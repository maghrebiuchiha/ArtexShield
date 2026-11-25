<?php
/**
 * Per-client scoring, sensors and fire control: a port of the Python
 * reference's core.py, held to the same decisions by spec/vectors.json.
 *
 * PHP keeps nothing between requests, so each call reads the client's track
 * and the block table from a Store and writes back what changed, holding the
 * client's lock meanwhile. Changes to the block table are replayed onto the
 * latest stored copy under its own lock, so concurrent workers do not undo
 * each other's blocks.
 */
declare(strict_types=1);

namespace ArtexShield;

use ArtexShield\Store\MemoryStore;
use ArtexShield\Store\Store;

final class Shield
{
    private const MISSING_MEMORY = 128;

    public array $cfg;
    public array $stats = ['requests' => 0, 'throttled' => 0, 'blocked' => 0, 'friendly' => 0, 'unidentified' => 0, 'refused' => 0];
    /** @var callable */
    private $clock;
    private Store $store;
    private array $trusted;
    private array $allowed;
    private array $canaries = [];
    private array $tlsDeny = [];
    private array $enumSkipExt = [];
    private array $engagements;
    private string $checkKey;
    private string $checkPath;
    private int $history;
    private int $trackTtl;
    // This request's view of the state.
    private array $tracks = [];
    private array $dirty = [];
    private ?array $blocks = null;           // network -> expiry
    private float $pruned = 0.0;
    private array $blockOps = [];

    /**
     * @param array $options settings (Config::DEFAULTS)
     * @param callable|null $clock returns Unix seconds; defaults to microtime(true)
     */
    public function __construct(array $options = [], ?Store $store = null, ?callable $clock = null)
    {
        $this->cfg = Config::make($options);
        $this->store = $store ?? new MemoryStore();
        $this->clock = $clock ?? static fn (): float => microtime(true);
        $nets = static fn (array $cidrs): array => array_map([Ip::class, 'network'], $cidrs);
        $this->trusted = $nets($this->cfg['trusted_proxies']);
        $this->allowed = $nets($this->cfg['allow_cidrs']);
        foreach ($this->cfg['canary_paths'] as $p) {
            $this->canaries[Util::normPath((string) $p)] = true;
        }
        foreach ($this->cfg['tls_denylist'] as $v) {
            $this->tlsDeny[Py::lower((string) $v)] = true;
        }
        foreach ($this->cfg['enum_ignore_extensions'] as $e) {
            $this->enumSkipExt[ltrim(Py::lower((string) $e), '.')] = true;
        }
        $this->engagements = array_map(static fn (array $e): array => $e + ['nets' => $nets($e['cidrs'])], $this->cfg['engagements']);
        $secret = $this->cfg['client_check_secret'];
        $this->checkKey = ($secret !== null && $secret !== '') ? (string) $secret : random_bytes(32);
        $this->checkPath = Util::prefixes([$this->cfg['client_check_path']], 'client_check_path')[0];
        $this->history = max($this->cfg['rate_limit'], $this->cfg['cadence_samples']);
        $this->trackTtl = (int) max(7 * 86400, 2 * $this->cfg['max_block_ttl'], 2 * $this->cfg['client_check_ttl']);
        $this->loadBlocks();                       // a new table is stamped as pruned now, as the reference does
    }

    private function now(): float
    {
        return (float) ($this->clock)();
    }

    // ---- client address ---------------------------------------------------------
    /** X-Forwarded-For is believed only from a trusted proxy. */
    public function clientIp(string $remoteAddr, ?string $forwardedFor = null): string
    {
        $remote = Py::strip($remoteAddr);
        $remote = $remote === '' ? '0.0.0.0' : $remote;
        if ($forwardedFor !== null && $forwardedFor !== '' && Ip::inNets($remote, $this->trusted)) {
            $hops = array_values(array_filter(array_map([Py::class, 'strip'], explode(',', $forwardedFor)), static fn ($h) => $h !== ''));
            foreach (array_reverse($hops) as $hop) {
                $addr = Ip::hopIp($hop);
                if ($addr === null) {
                    break;
                }
                if (!Ip::inNets($addr, $this->trusted)) {
                    return $addr;
                }
            }
        }
        return $remote;
    }

    public function identified(string $ip): bool
    {
        return Ip::usable($ip) && !Ip::inNets($ip, $this->trusted);
    }

    public function trustedPeer(string $ip): bool
    {
        return Ip::inNets($ip, $this->trusted);
    }

    // ---- before the site runs ---------------------------------------------------
    /** Decide on one request. $headers: name => value; $body: the start of the body, read only for honeytokens. */
    public function check(string $ip, string $method, string $path, string $query = '', array $headers = [], ?string $body = null): Decision
    {
        $key = Ip::trackKey($ip);
        $this->store->lock("t:$key");
        try {
            return $this->decide($ip, $key, $method, $path, $query, $headers, $body);
        } finally {
            $this->flush();
            $this->store->unlock("t:$key");
        }
    }

    private function decide(string $ip, string $key, string $method, string $path, string $query, array $headers, ?string $body): Decision
    {
        $cfg = $this->cfg;
        $now = $this->now();
        $h = [];
        foreach ($headers as $k => $v) {
            $h[Py::lower((string) $k)] = is_array($v) ? implode(', ', $v) : (string) $v;
        }
        $ua = $h['user-agent'] ?? '';
        $ref = bin2hex(random_bytes(4));
        $enforce = $cfg['mode'] === 'enforce';
        $npath = Util::normPath($path);
        $allowed = Ip::inNets($ip, $this->allowed);
        $exempt = !$allowed && Util::under($path, $cfg['exempt_paths']);
        $induced = !$cfg['score_induced'] && Util::induced($h);
        $sig = Signatures::get();
        $m = null;
        $assessment = Signatures::search($sig['assessment_ua'], $ua, $m);
        $hits = [];

        $this->stats['requests']++;
        // An allowlisted address is never scored. Nor is a request for an exempt
        // path, but a client blocked for what it did elsewhere stays blocked there too.
        if ($allowed) {
            return new Decision('pass', $enforce, 0.0, [], $ref, $ip);
        }
        if ($exempt) {
            if ($this->blocked($key, $now)) {
                return new Decision('block', $enforce, $cfg['block_score'], ['blocklist'], $ref, $ip);
            }
            return new Decision('pass', $enforce, 0.0, [], $ref, $ip);
        }
        if (!$this->identified($ip)) {
            $this->stats['unidentified']++;
            $labels = ['config:unidentified-client'];
            $warned = $this->store->get('unidentified');
            if ($warned === null || $now - (float) $warned >= $cfg['half_life']) {
                $this->store->set('unidentified', $now, (int) ceil($cfg['half_life']) + 60);
                $this->emit('unidentified', $ip, 0.0, $labels, $method, $path, $ua, $ref, $enforce);
            }
            return new Decision('pass', $enforce, 0.0, $labels, $ref, $ip);
        }
        if ($assessment) {
            $eref = $m[1] ?? '';
            foreach ($this->engagements as $e) {
                if ($e['reference'] === $eref && $e['start'] <= $now && $now < $e['end'] && Ip::inNets($ip, $e['nets'])) {
                    $this->stats['friendly']++;
                    $t = $this->track($key, $now);
                    if ($this->softDue($t, 'friendly', $now)) {
                        $this->emit('friendly', $ip, 0.0, ["iff:engagement=$eref"], $method, $path, $ua, $ref, $enforce);
                    }
                    return new Decision('pass', $enforce, 0.0, ["iff:engagement=$eref"], $ref, $ip, friendly: true);
                }
            }
            $hits[] = ['artex:unverified-assessment-label', 100.0, false];
        }
        if ($enforce && $this->blocked($key, $now)) {
            return new Decision('block', $enforce, $cfg['block_score'], ['blocklist'], $ref, $ip);
        }

        $seen = $this->scan($method, $npath, $query, $h, $ua);
        if ($cfg['honeytokens']) {
            $where = $this->honeytoken($npath, $query, $h, $body);
            if ($where !== null) {
                $seen[] = ["decoy:honeytoken-$where", max(100.0, $cfg['block_score']), false];
            }
        }
        $checked = $this->clientRequest($path, $h, $now);

        if ($this->blocked($key, $now)) {
            $all = array_merge($hits, $seen);
            $labels = array_merge(['blocklist'], array_column($all, 0));
            $loud = (bool) array_filter($all, static fn (array $x): bool => !$x[2]);
            if ($loud || $this->softDue($this->track($key, $now), 'blocked', $now)) {
                $this->emit('blocked', $ip, $cfg['block_score'], $labels, $method, $path, $ua, $ref, $enforce);
            }
            return new Decision('block', $enforce, $cfg['block_score'], $labels, $ref, $ip);
        }
        if ($induced) {
            $labels = array_column(array_filter(array_merge($hits, $seen), static fn (array $x): bool => !$x[2]), 0);
            if (!$labels) {
                return new Decision('pass', $enforce, 0.0, [], $ref, $ip, induced: true);
            }
            $this->stats['refused']++;
            $this->emit('refuse', $ip, 0.0, $labels, $method, $path, $ua, $ref, $enforce);
            return new Decision('refuse', $enforce, 0.0, $labels, $ref, $ip, induced: true);
        }
        $t = $this->track($key, $now);
        $this->decay($t, $now);
        $hits = array_merge($hits, $this->radar($t, $now, $seen), $this->clientHits($t, $now, $checked));
        Track::push($t->times, $now, $this->history);
        if ($enforce && $t->throttledUntil > $now) {
            $hits[] = ['behavior:ignored-retry-after', $cfg['ignored_throttle_points'], false];
        }
        $this->add($t, $hits);
        return $this->engage($t, $key, $ip, $now, array_column($hits, 0), $method, $path, $ua, $ref, $enforce);
    }

    // ---- after the site answered -----------------------------------------------------
    /** Feed back the status (and Content-Type) the site answered with. */
    public function observe(string $ip, string $path, int $status, bool $induced = false, string $contentType = ''): void
    {
        $key = Ip::trackKey($ip);
        $this->store->lock("t:$key");
        try {
            $this->observed($ip, $key, $path, $status, $induced, $contentType);
        } finally {
            $this->flush();
            $this->store->unlock("t:$key");
        }
    }

    private function observed(string $ip, string $key, string $path, int $status, bool $induced, string $contentType): void
    {
        $cfg = $this->cfg;
        if ($cfg['client_check'] && !$induced && $status >= 200 && $status < 300) {
            $type = Py::lower(Py::strip(explode(';', $contentType, 2)[0]));
            if ($type === 'text/html' || $type === 'application/xhtml+xml') {
                $this->clientPage($ip, $key);
            }
        }
        if ($status !== 404 || $induced) {
            return;
        }
        $now = $this->now();
        $npath = Util::normPath($path);
        if (Util::under($path, $cfg['exempt_paths']) || Ip::inNets($ip, $this->allowed)) {
            return;
        }
        $sig = Signatures::get();
        $hits = [];
        if (Signatures::search($sig['recon_paths'], $npath)) {
            $hits[] = ['recon:probe-404', 25.0, false];
        }
        if (Signatures::search($sig['missing_sensitive'], $npath) && !Signatures::search($sig['sensitive_paths'], $npath)) {
            $hits[] = ['decoy:sensitive-file-probe', 60.0, false];
        }
        $guess = !Util::under($path, $cfg['enum_ignore_prefixes']) && !isset($this->enumSkipExt[Util::extension($npath)]);
        $t = $this->existing($key);
        if ($t === null || $this->blocked($key, $now)) {
            return;
        }
        $this->decay($t, $now);
        $this->dirty[$key] = true;
        if ($guess && $this->newlyMissing($t, $npath, $now)) {
            Track::push($t->notFound, $now, 512);
            if ($cfg['slow_enum_budget']) {
                $max = max($cfg['slow_enum_budget'], 1);
                if (count($t->slow) === $max && $now - $t->slow[0] <= $cfg['slow_enum_window']) {
                    $hits[] = ['behavior:slow-enumeration', $cfg['slow_enum_points'], false];
                }
                Track::push($t->slow, $now, $max);
            }
        }
        while ($t->notFound && $now - $t->notFound[0] > $cfg['enum_window']) {
            array_shift($t->notFound);
        }
        if (count($t->notFound) >= $cfg['enum_404_threshold']) {
            $hits[] = ['behavior:path-enumeration', 40.0, false];
            $t->notFound = [];
        }
        if (!$hits) {
            return;
        }
        $this->add($t, $hits);
        $labels = array_column($hits, 0);
        $score = $t->score();
        if ($score >= $cfg['block_score']) {
            $this->block($t, $key, $now);
            $this->emit('block', $ip, $score, $labels, '-', $path, '', '-', $cfg['mode'] === 'enforce');
        } else {
            $this->emit('score', $ip, $t->score(), $labels, '-', $path, '', '-', $cfg['mode'] === 'enforce');
        }
    }

    private function newlyMissing(Track $t, string $npath, float $now): bool
    {
        $k = 'p' . substr(md5($npath), 0, 16);
        $last = $t->missing[$k] ?? null;
        unset($t->missing[$k]);
        $t->missing[$k] = $now;
        while (count($t->missing) > self::MISSING_MEMORY) {
            unset($t->missing[array_key_first($t->missing)]);
        }
        return $last === null || $now - $last > $this->cfg['half_life'];
    }

    // ---- honeytokens ------------------------------------------------------------------
    private function honeytoken(string $npath, string $query, array $h, ?string $body): ?string
    {
        $tokens = $this->cfg['honeytokens'];
        $has = static function (string $text) use ($tokens): bool {
            if ($text === '') {
                return false;
            }
            foreach ($tokens as $t) {
                if (str_contains($text, $t)) {
                    return true;
                }
            }
            $decoded = Util::decode($text);
            if ($decoded === $text) {
                return false;
            }
            foreach ($tokens as $t) {
                if (str_contains($decoded, $t)) {
                    return true;
                }
            }
            return false;
        };
        foreach ($h as $name => $raw) {
            $name = (string) $name;
            if ($name === 'referer') {
                continue;
            }
            $value = Py::slice($raw, 16384);
            if ($has($value)) {
                return $name === 'cookie' ? 'cookie' : 'header';
            }
            if (($name === 'authorization' || $name === 'proxy-authorization')
                && preg_match('~^[' . Py::SPACE . ']*basic[' . Py::SPACE . ']+([A-Za-z0-9+/_=-]{4,8192})~iu', $value, $m)) {
                $b64 = strpbrk($m[1], '-_') !== false ? strtr($m[1], '-_', '+/') : $m[1];
                try {
                    $decoded = Py::latin1(Py::b64decode($b64 . '==='));
                } catch (\InvalidArgumentException $e) {
                    $decoded = '';
                }
                if ($has($decoded)) {
                    return 'header';
                }
            }
        }
        if ($has(Py::slice($query, 65536))) {
            return 'query';
        }
        if ($has($npath)) {
            return 'path';
        }
        $limit = $this->cfg['honeytoken_body_limit'];
        if ($body !== null && $body !== '' && $limit && $has(Py::latin1(substr($body, 0, $limit)))) {
            return 'body';
        }
        return null;
    }

    // ---- client check (optional) ---------------------------------------------------------
    /** Answer the check script's call: ['status' => 204, 'headers' => [[name, value]], 'body' => '']. */
    public function clientCheckReply(string $ip, string $query, array $headers = [], bool $secure = false): array
    {
        $key = Ip::trackKey($ip);
        $this->store->lock("t:$key");
        try {
            $now = $this->now();
            $params = [];
            foreach (explode('&', $query) as $p) {
                if ($p === '') {
                    continue;
                }
                $eq = strpos($p, '=');
                $params[$eq === false ? $p : substr($p, 0, $eq)] = $eq === false ? '' : substr($p, $eq + 1);
            }
            $f = (string) ($params['f'] ?? '');
            $flags = Py::isDigits($f) && strlen($f) < 6 ? ((int) $f) & ClientCheck::FLAGS : 0;
            if ($this->identified($ip)) {
                $t = $this->track($key, $now);
                $t->checkedAt = $now;
                if ($flags) {
                    $t->automationAt = $now;
                }
            }
            $value = ClientCheck::sign($this->checkKey, (int) floor($now), $flags);
            $attrs = 'Path=/; Max-Age=' . (int) $this->cfg['client_check_ttl'] . '; HttpOnly; SameSite=Lax';
            return ['status' => 204, 'headers' => [
                ['Set-Cookie', $this->cfg['client_check_cookie'] . "=$value; $attrs" . ($secure ? '; Secure' : '')],
                ['Cache-Control', 'no-store'], ['Content-Length', '0']], 'body' => ''];
        } finally {
            $this->flush();
            $this->store->unlock("t:$key");
        }
    }

    /** The check script itself, served at client_check_path . ".js". */
    public function clientCheckAsset(): array
    {
        $body = ClientCheck::script($this->checkPath);
        return ['status' => 200, 'headers' => [['Content-Type', 'text/javascript; charset=utf-8'],
            ['Content-Length', (string) strlen($body)], ['Cache-Control', 'public, max-age=3600'],
            ['X-Content-Type-Options', 'nosniff']], 'body' => $body];
    }

    /** "check" or "script" for the client check's own endpoints, when it is on; else null. */
    public function clientCheckRoute(string $path): ?string
    {
        if (!$this->cfg['client_check']) {
            return null;
        }
        $npath = Util::normPath($path);
        return $npath === $this->checkPath ? 'check' : ($npath === $this->checkPath . '.js' ? 'script' : null);
    }

    public function clientCheckTag(): string
    {
        return ClientCheck::tag(rtrim($this->cfg['client_check_path'], '/'));
    }

    private function clientPage(string $ip, string $key): void
    {
        if (!$this->identified($ip)) {
            return;
        }
        $t = $this->existing($key);
        if ($t !== null && $t->pageAt === null) {
            $t->pageAt = $this->now();
            $this->dirty[$key] = true;
        }
    }

    private function clientRequest(string $path, array $h, float $now): ?array
    {
        if (!$this->cfg['client_check'] || !Util::under($path, $this->cfg['client_check_api_prefixes']) || !ClientCheck::scriptMade($h)) {
            return null;
        }
        $flags = ClientCheck::verify($this->checkKey, ClientCheck::cookie($h['cookie'] ?? '', $this->cfg['client_check_cookie']),
            $now, $this->cfg['client_check_ttl']);
        return [$flags !== null, $flags ?? 0];
    }

    private function clientHits(Track $t, float $now, ?array $checked): array
    {
        if ($checked === null) {
            return [];
        }
        $cfg = $this->cfg;
        [$valid, $flags] = $checked;
        $hits = [];
        $reported = $flags || ($t->automationAt !== null && $now - $t->automationAt < $cfg['client_check_ttl']);
        if ($reported && $this->softDue($t, 'client:automation-reported', $now)) {
            $hits[] = ['client:automation-reported', $cfg['client_check_points'], true];
        }
        if (!$valid && $t->checkedAt === null && $t->pageAt !== null && $now - $t->pageAt >= $cfg['client_check_grace']
            && $this->softDue($t, 'client:no-check', $now)) {
            $hits[] = ['client:no-check', $cfg['client_check_points'], true];
        }
        return $hits;
    }

    // ---- sensors -----------------------------------------------------------------------
    private function scan(string $method, string $npath, string $query, array $h, string $ua): array
    {
        $cfg = $this->cfg;
        $sig = Signatures::get();
        $hits = [];
        if (isset($this->canaries[$npath])) {
            $hits[] = ['decoy:canary-path', 100.0, false];
        } elseif (Signatures::search($sig['sensitive_paths'], $npath)) {
            $hits[] = ['decoy:sensitive-file-probe', 60.0, false];
        }
        $hard = null;
        foreach ($sig['hard_ua'] as [$rx, $points, $label]) {
            if (Signatures::search($rx, $ua)) {
                $hard = [$label, $points];
                break;
            }
        }
        if ($hard !== null) {
            $hits[] = [$hard[0], $hard[1], false];
        } else {
            foreach ($sig['soft_ua'] as [$rx, $points, $label]) {
                if (Signatures::search($rx, $ua)) {
                    $hits[] = [$label, $points, true];
                }
            }
            if (Py::strip($ua) === '') {
                $hits[] = ['ua:empty', 20.0, true];
            }
            if (Signatures::search($sig['browser_ua'], $ua) && !Signatures::search($sig['crawler_ua'], $ua) && ($h['accept-language'] ?? '') === '') {
                $hits[] = ['shape:browser-ua-without-browser-headers', 20.0, true];
            }
        }
        $verb = Py::upper($method);
        if (isset($sig['odd_methods'][$verb]) || isset($sig['soft_methods'][$verb])) {
            $hits[] = ["method:$verb", 30.0, isset($sig['soft_methods'][$verb])];
        }
        $target = Util::urlText($npath, $query);
        $plain = Util::stripSqlComments($target);
        $found = [];
        foreach (array_merge($sig['payloads'], $sig['oob']) as [$rx, $label]) {
            if (Signatures::search($rx, $target) || ($plain !== null && Signatures::search($rx, $plain))) {
                $found[] = $label;
            }
        }
        $headBlob = Util::decode(implode(' ', array_values($h)));
        foreach ($sig['oob'] as [$rx, $label]) {
            if (!in_array($label, $found, true) && Signatures::search($rx, $headBlob)) {
                $found[] = $label;
            }
        }
        foreach ($found as $label) {
            $hits[] = [$label, 50.0, false];
        }
        if ($cfg['tls_header'] && $this->tlsDeny) {
            $fp = Py::lower($h[Py::lower($cfg['tls_header'])] ?? '');
            if ($fp !== '' && isset($this->tlsDeny[$fp])) {
                $hits[] = ['tls:denylisted-fingerprint', 40.0, true];
            }
        }
        return $hits;
    }

    private function radar(Track $t, float $now, array $seen): array
    {
        $cfg = $this->cfg;
        $hits = array_values(array_filter($seen, fn (array $x): bool => !$x[2] || $this->softDue($t, $x[0], $now)));
        $recent = 0;
        foreach ($t->times as $x) {
            if ($now - $x <= $cfg['rate_window']) {
                $recent++;
            }
        }
        if ($recent + 1 > $cfg['rate_limit']) {
            $hits[] = ['behavior:request-flood', 30.0, false];
            $t->times = [];
        } elseif (count($t->times) >= $cfg['cadence_samples']) {
            $seq = array_merge(array_slice($t->times, -$cfg['cadence_samples']), [$now]);
            $gaps = [];
            for ($i = 1, $n = count($seq); $i < $n; $i++) {
                $gaps[] = $seq[$i] - $seq[$i - 1];
            }
            $count = count($gaps);
            $mean = Py::fsum($gaps) / $count;
            if ($cfg['cadence_min_mean'] <= $mean && $mean <= $cfg['cadence_max_mean']) {
                $devs = array_map(static fn (float $g): float => $g - $mean, $gaps);
                $ss = Py::fsum(array_map(static fn (float $d): float => $d * $d, $devs)) - Py::fsum($devs) ** 2 / $count;
                $cv = sqrt(max($ss, 0.0) / $count) / $mean;
                if ($cv <= $cfg['cadence_max_cv'] && $this->softDue($t, 'behavior:metronomic-cadence', $now)) {
                    $hits[] = ['behavior:metronomic-cadence', 20.0, true];
                }
            }
        }
        return $hits;
    }

    private function add(Track $t, array $hits): void
    {
        foreach ($hits as [, $points, $soft]) {
            if ($soft) {
                $t->softPoints = min($this->cfg['soft_cap'], $t->softPoints + $points);
            } else {
                $t->hard += $points;
            }
        }
    }

    // ---- fire control ----------------------------------------------------------------------
    private function engage(Track $t, string $key, string $ip, float $now, array $labels, string $method, string $path,
                            string $ua, string $ref, bool $enforce): Decision
    {
        $cfg = $this->cfg;
        $score = $t->score();
        if ($score >= $cfg['block_score']) {
            $this->block($t, $key, $now);
            $this->emit('block', $ip, $score, $labels, $method, $path, $ua, $ref, $enforce);
            return new Decision('block', $enforce, $score, $labels, $ref, $ip);
        }
        if ($score >= $cfg['throttle_score']) {
            $decay = $cfg['half_life'] * log($score / $cfg['throttle_score'], 2);
            $wait = (int) max($cfg['retry_after'], ceil($decay) + 1);
            $t->throttledUntil = $now + $wait;
            $this->stats['throttled']++;
            $this->emit('throttle', $ip, $score, $labels, $method, $path, $ua, $ref, $enforce);
            return new Decision('throttle', $enforce, $score, $labels, $ref, $ip, retryAfter: $wait);
        }
        $t->throttledUntil = 0.0;
        if ($labels) {
            $this->emit('score', $ip, $t->score(), $labels, $method, $path, $ua, $ref, $enforce);
        }
        return new Decision('pass', $enforce, $t->score(), $labels, $ref, $ip);
    }

    private function block(Track $t, string $key, float $now): void
    {
        $t->strikes++;
        $this->stats['blocked']++;
        $ttl = min($this->cfg['block_ttl'] * (2 ** ($t->strikes - 1)), $this->cfg['max_block_ttl']);
        if ($now - $this->pruned >= 60 || count($this->blocks) >= $this->cfg['max_blocks']) {
            $this->pruneBlocks($now);
        }
        $this->setBlock($key, $now + $ttl);
        $t->hard = 0.0;
        $t->softPoints = 0.0;
        $t->throttledUntil = 0.0;
        $t->notFound = [];
        $this->escalate($key, $now);
    }

    private function members(string $parent): int
    {
        $n = 0;
        foreach ($this->blocks as $k => $_) {
            if (Ip::wider((string) $k) === $parent) {
                $n++;
            }
        }
        return $n;
    }

    private function escalate(string $key, float $now): void
    {
        $need = $this->cfg['v6_escalate_after'];
        $parent = Ip::wider($key);
        while ($need && $parent !== null && $this->members($parent) >= $need) {
            foreach (array_keys($this->blocks) as $inside) {
                if (Ip::wider((string) $inside) === $parent) {
                    $this->dropBlock((string) $inside);
                }
            }
            $this->setBlock($parent, $now + $this->cfg['block_ttl']);
            $this->emit('block', $parent, $this->cfg['block_score'], ['behavior:network-rotation'], '-', '-', '', '-',
                $this->cfg['mode'] === 'enforce');
            $parent = Ip::wider($parent);
        }
    }

    private function setBlock(string $key, float $until): void
    {
        $this->blocks[$key] = $until;
        $this->blockOps[] = ['set', $key, $until];
    }

    private function dropBlock(string $key): bool
    {
        if (!array_key_exists($key, $this->blocks)) {
            return false;
        }
        unset($this->blocks[$key]);
        $this->blockOps[] = ['drop', $key];
        return true;
    }

    private function pruneBlocks(float $now): void
    {
        $this->pruned = $now;
        $this->blockOps[] = ['pruned', $now];
        foreach ($this->blocks as $k => $until) {
            if ($until <= $now) {
                $this->dropBlock((string) $k);
            }
        }
        $over = count($this->blocks) - $this->cfg['max_blocks'] + 1;
        if ($over > 0) {
            $nearest = $this->blocks;
            asort($nearest);                           // stable: ties keep their order
            foreach (array_slice(array_keys($nearest), 0, max($over, intdiv($this->cfg['max_blocks'], 10))) as $k) {
                $this->dropBlock((string) $k);
            }
        }
    }

    // ---- command post ----------------------------------------------------------------------
    /** Active blocks: network => expiry (Unix seconds). */
    public function blocklist(): array
    {
        $this->loadBlocks();
        $now = $this->now();
        foreach ($this->blocks as $k => $until) {
            if ($until <= $now) {
                $this->dropBlock((string) $k);
            }
        }
        $out = $this->blocks;
        $this->flush();
        return array_combine(array_map('strval', array_keys($out)), array_values($out)) ?: [];
    }

    /** Lift the block on $ip, including a wider IPv6 prefix that covers it. */
    public function unblock(string $ip): bool
    {
        $key = Ip::trackKey($ip);
        $this->store->lock("t:$key");
        try {
            $this->loadBlocks();
            unset($this->tracks[$key], $this->dirty[$key]);
            $this->store->delete("t:$key");
            $dropped = false;
            foreach ($this->covering($key, true) as $k) {
                $dropped = $this->dropBlock($k) || $dropped;
            }
            return $dropped;
        } finally {
            $this->flush();
            $this->store->unlock("t:$key");
        }
    }

    /** Recent events kept by the WordPress plugin go through here. */
    private function emit(string $action, string $ip, float $score, array $labels, string $method, string $path, string $ua,
                          string $ref, bool $enforced): void
    {
        $hook = $this->cfg['on_event'];
        if (!is_callable($hook)) {
            return;
        }
        $event = ['ts' => gmdate('Y-m-d\TH:i:s', (int) floor($this->now())) . '+00:00', 'action' => $action, 'enforced' => $enforced,
            'ip' => $ip, 'score' => round($score, 1), 'hits' => $labels, 'method' => $method, 'path' => Py::slice($path, 512),
            'ua' => Py::slice($ua, 256), 'ref' => $ref];
        try {
            $hook($event);
        } catch (\Throwable $e) {
            error_log('artex-shield: on_event failed: ' . $e->getMessage());
        }
    }

    // ---- state ------------------------------------------------------------------------------
    private function track(string $key, float $now): Track
    {
        $t = $this->existing($key);
        if ($t === null) {
            $t = new Track($now);
            $this->tracks[$key] = $t;
        }
        $this->dirty[$key] = true;
        return $t;
    }

    private function existing(string $key): ?Track
    {
        if (!array_key_exists($key, $this->tracks)) {
            $stored = $this->store->get("t:$key");
            $this->tracks[$key] = is_array($stored) ? Track::fromArray($stored) : null;
        }
        return $this->tracks[$key];
    }

    private function loadBlocks(): void
    {
        $stored = $this->store->get('blocks');
        if (is_array($stored)) {
            $this->blocks = array_map('floatval', $stored['b'] ?? []);
            $this->pruned = (float) ($stored['p'] ?? 0.0);
        } else {
            $this->blocks = [];
            $this->pruned = $this->now();
            $this->store->set('blocks', ['p' => $this->pruned, 'b' => []], 0);
        }
    }

    /** Write back this call's changes, and forget them: the next call reads fresh state. */
    private function flush(): void
    {
        $now = $this->now();
        foreach (array_keys($this->dirty) as $key) {
            $t = $this->tracks[$key] ?? null;
            if ($t !== null) {
                $this->store->set("t:$key", $t->toArray($now, $this->cfg['rate_window'], $this->cfg['cadence_samples']), $this->trackTtl);
            }
        }
        if ($this->blockOps) {
            $this->store->lock('blocks');
            try {
                $stored = $this->store->get('blocks');
                $blocks = is_array($stored) ? array_map('floatval', $stored['b'] ?? []) : [];
                $pruned = is_array($stored) ? (float) ($stored['p'] ?? 0.0) : 0.0;
                foreach ($this->blockOps as $op) {
                    if ($op[0] === 'set') {
                        $blocks[$op[1]] = $op[2];
                    } elseif ($op[0] === 'drop') {
                        unset($blocks[$op[1]]);
                    } else {
                        $pruned = $op[1];
                    }
                }
                $this->store->set('blocks', ['p' => $pruned, 'b' => $blocks], 0);
            } finally {
                $this->store->unlock('blocks');
            }
        }
        $this->tracks = [];
        $this->dirty = [];
        $this->blockOps = [];
        $this->loadBlocks();
    }

    private function covering(string $key, bool $wide = false): array
    {
        $keys = [$key];
        if (str_contains($key, ':')) {
            for ($k = Ip::wider($key); $k !== null; $k = Ip::wider($k)) {
                $keys[] = $k;
            }
        }
        return $keys;
    }

    private function blocked(string $key, float $now): bool
    {
        foreach ($this->covering($key) as $k) {
            if (!array_key_exists($k, $this->blocks)) {
                continue;
            }
            if ($this->blocks[$k] > $now) {
                return true;
            }
            $this->dropBlock($k);
        }
        return false;
    }

    private function decay(Track $t, float $now): void
    {
        $dt = $now - $t->updated;
        if ($dt > 0) {
            $factor = 0.5 ** ($dt / $this->cfg['half_life']);
            $t->hard *= $factor;
            $t->softPoints *= $factor;
            if ($t->score() < 0.5) {
                $t->hard = 0.0;
                $t->softPoints = 0.0;
            }
        }
        $t->updated = $now;
    }

    private function softDue(Track $t, string $label, float $now): bool
    {
        $last = $t->soft[$label] ?? null;
        if ($last !== null && $now - $last < $this->cfg['half_life']) {
            return false;
        }
        $t->soft[$label] = $now;
        return true;
    }
}
