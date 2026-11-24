<?php
/**
 * The PHP shield against spec/vectors.json, every case the Python reference
 * passes, replayed as spec/SPEC.md says a runner must.
 *
 *   php tests/vectors.php            # state in memory (stored as JSON, as on disk)
 *   php tests/vectors.php --files    # state in files, read back on every call
 *   php tests/vectors.php --cache    # state in the object cache (a stand-in that serialises, as Redis does)
 */
declare(strict_types=1);

use ArtexShield\ClientCheck;
use ArtexShield\Config;
use ArtexShield\Decoys;
use ArtexShield\Ip;
use ArtexShield\Shield;
use ArtexShield\Signatures;
use ArtexShield\Store\FileStore;
use ArtexShield\Store\MemoryStore;
use ArtexShield\Store\ObjectCacheStore;

require __DIR__ . '/../artex-shield/autoload.php';
require __DIR__ . '/check.php';

$spec = getenv('ARTEX_SPEC') ?: dirname(__DIR__, 3) . '/spec';
$data = json_decode((string) file_get_contents("$spec/vectors.json"), true, 512, JSON_THROW_ON_ERROR);
$files = in_array('--files', $argv, true);
$cache = in_array('--cache', $argv, true);
if ($cache) {
    $GLOBALS['__cache'] = [];
    function wp_cache_get(string $key, string $group = '', bool $force = false, ?bool &$found = null): mixed
    {
        $found = isset($GLOBALS['__cache']["$group:$key"]);
        return $found ? unserialize($GLOBALS['__cache']["$group:$key"]) : false;
    }
    function wp_cache_set(string $key, mixed $value, string $group = '', int $ttl = 0): bool
    {
        $GLOBALS['__cache']["$group:$key"] = serialize($value);
        return true;
    }
    function wp_cache_add(string $key, mixed $value, string $group = '', int $ttl = 0): bool
    {
        return isset($GLOBALS['__cache']["$group:$key"]) ? false : wp_cache_set($key, $value, $group, $ttl);
    }
    function wp_cache_delete(string $key, string $group = ''): bool
    {
        unset($GLOBALS['__cache']["$group:$key"]);
        return true;
    }
}
const TOLERANCE = 1e-6;

function options(?array $config, float $t0): array
{
    $out = [];
    foreach ($config ?? [] as $k => $v) {
        $out[$k] = $k === 'engagements'
            ? array_map(static fn (array $e): array => ['reference' => $e['reference'], 'cidrs' => $e['cidrs'],
                'start' => $t0 + $e['start'], 'end' => $t0 + $e['end']], $v)
            : $v;
    }
    return $out;
}

function body(array $r): ?string
{
    if (isset($r['body_base64'])) {
        return base64_decode($r['body_base64'], true);
    }
    return $r['body'] ?? null;
}

function fill(mixed $template, int $i): mixed
{
    if (is_string($template)) {
        return str_replace('{i}', (string) $i, $template);
    }
    if (is_array($template)) {
        return array_map(static fn ($v) => fill($v, $i), $template);
    }
    return $template;
}

final class Runner
{
    public array $failures = [];
    public float $now;
    private Shield $shield;

    public function __construct(private array $case, private float $t0, ?string $dir)
    {
        $this->now = $t0;
        if (function_exists('wp_cache_get')) {
            $GLOBALS['__cache'] = [];
        }
        $store = $dir !== null ? new FileStore($dir) : (function_exists('wp_cache_get') ? new ObjectCacheStore() : new MemoryStore());
        $this->shield = new Shield(options($case['config'] ?? null, $t0), $store, fn (): float => $this->now);
    }

    private function fail(string $where, string $message): void
    {
        $this->failures[] = "{$this->case['id']} step $where: $message";
    }

    private function compare(string $where, \ArtexShield\Decision $got, array $want, bool $full): void
    {
        $hits = $got->hits;
        sort($hits, SORT_STRING);
        if ($got->action !== $want['action']) {
            $this->fail($where, "action {$got->action}, expected {$want['action']} (hits " . implode(',', $hits) . ')');
        }
        if ($hits !== $want['hits']) {
            $this->fail($where, 'hits ' . json_encode($hits) . ', expected ' . json_encode($want['hits']));
        }
        if ($full && abs($got->score - $want['score']) > TOLERANCE) {
            $this->fail($where, "score {$got->score}, expected {$want['score']}");
        }
        if ($full && isset($want['retry_after']) && $got->retryAfter !== $want['retry_after']) {
            $this->fail($where, "retry_after {$got->retryAfter}, expected {$want['retry_after']}");
        }
    }

    private function step(string $where, array $step, mixed $expect, bool $full = true): void
    {
        $s = $this->shield;
        if (isset($step['request'])) {
            $r = $step['request'];
            $d = $s->check($r['ip'], $r['method'] ?? 'GET', $r['path'], $r['query'] ?? '', $r['headers'] ?? [], body($r));
            if ($expect !== null) {
                $this->compare($where, $d, $expect, $full);
            }
        } elseif (isset($step['observe'])) {
            $o = $step['observe'];
            $s->observe($o['ip'], $o['path'], $o['status'], (bool) ($o['induced'] ?? false), $o['content_type'] ?? '');
        } elseif (isset($step['client_check'])) {
            $c = $step['client_check'];
            $r = $s->clientCheckReply($c['ip'], $c['query'], $c['headers'] ?? [], (bool) ($c['secure'] ?? false));
            $got = ['status' => $r['status'], 'headers' => $r['headers']];
            if ($got !== $step['expect']) {
                $this->fail($where, 'client check answered ' . json_encode($got) . ', expected ' . json_encode($step['expect']));
            }
        } elseif (array_key_exists('unblock', $step)) {
            $got = $s->unblock($step['unblock']);
            if ($got !== $step['expect']) {
                $this->fail($where, 'unblock returned ' . json_encode($got) . ', expected ' . json_encode($step['expect']));
            }
        } elseif (array_key_exists('expect_blocklist', $step)) {
            $got = array_keys($s->blocklist());
            sort($got, SORT_STRING);
            if ($got !== $step['expect_blocklist']) {
                $this->fail($where, 'blocklist ' . json_encode($got) . ', expected ' . json_encode($step['expect_blocklist']));
            }
        } else {
            $this->fail($where, 'unknown step ' . implode(',', array_keys($step)));
        }
    }

    public function run(): array
    {
        foreach ($this->case['steps'] as $n => $step) {
            if (isset($step['repeat'])) {
                $t = $this->t0 + $step['at'];
                $started = false;
                $iteration = 0;
                foreach ($step['expect'] as $run) {
                    for ($k = 0; $k < $run['times']; $k++) {
                        $final = $k === $run['times'] - 1;
                        foreach ($step['steps'] as $j => $template) {
                            if ($started) {
                                $t += $step['dt'][$j];
                            }
                            $started = true;
                            $this->now = $t;
                            $this->step("$n (repeat $iteration, part $j)", fill($template, $step['i_from'] + $iteration),
                                ($final ? $run['last'] : $run['each'])[$j], $final);
                        }
                        $iteration++;
                    }
                }
                if ($iteration !== $step['repeat']) {
                    $this->fail((string) $n, "repeat block runs $iteration times, declares {$step['repeat']}");
                }
            } else {
                $this->now = $this->t0 + $step['at'];
                $this->step((string) $n, $step, $step['expect'] ?? null);
            }
        }
        return $this->failures;
    }
}

check('the file is the version this runner reads', fn () => same([2, 1800000000.0], [$data['version'], (float) $data['t0']]));

check('every case' . ($files ? ' (state in files)' : ($cache ? ' (state in the object cache)' : '')), function () use ($data, $files) {
    $failures = [];
    $root = $files ? sys_get_temp_dir() . '/artex-shield-vectors-' . getmypid() : null;
    foreach ($data['cases'] as $n => $case) {
        $dir = $root === null ? null : "$root/$n";
        array_push($failures, ...(new Runner($case, (float) $data['t0'], $dir))->run());
    }
    if ($root !== null) {
        exec('rm -rf ' . escapeshellarg($root));
    }
    same([], array_slice($failures, 0, 25), count($failures) . ' failures');
});

check('client addresses', function () use ($data) {
    foreach ($data['client_ip'] as $item) {
        $s = new Shield(['trusted_proxies' => $item['trusted_proxies']]);
        same($item['expect'], $s->clientIp($item['remote'], $item['forwarded_for']), json_encode($item));
    }
});

check('client check routes', function () use ($data) {
    foreach ($data['client_check_routes'] as $item) {
        $s = new Shield(options($item['config'], (float) $data['t0']));
        same($item['expect'], $s->clientCheckRoute($item['path']), json_encode($item));
    }
});

check('configs the reference refuses are refused', function () use ($data) {
    foreach ($data['config_errors'] as $item) {
        throws(fn () => Config::make(options($item['config'], (float) $data['t0'])), json_encode($item));
    }
});

check('canary and honeytoken derivations', function () use ($data) {
    foreach ($data['canaries'] as $item) {
        same($item['paths'], Decoys::canaries($item['secret'], $item['count']));
    }
    foreach ($data['honeytokens'] as $item) {
        $t = Decoys::honeytokens($item['secret'], $item['count']);
        same([$item['api_keys'], $item['users'], $item['passwords']], [$t['api_keys'], $t['users'], $t['passwords']]);
    }
});

check('the client check script', fn () => same(str_replace('PATH', '"/_artex/check"', $data['client_check_script']),
    ClientCheck::script('/_artex/check')));

check('every pattern reads the probe texts as Python does', function () use ($data) {
    $sig = Signatures::get();
    $table = [];
    foreach ($sig['hard_ua'] as [$rx, , $label]) {
        $table["hard_ua:$label"] = $rx;
    }
    foreach ($sig['soft_ua'] as [$rx, , $label]) {
        $table["soft_ua:$label"] = $rx;
    }
    foreach ($sig['payloads'] as [$rx, $label]) {
        $table["payloads:$label"] = $rx;
    }
    foreach ($sig['oob'] as [$rx, $label]) {
        $table["oob:$label"] = $rx;
    }
    foreach (['assessment_ua', 'browser_ua', 'crawler_ua', 'sensitive_paths', 'missing_sensitive', 'recon_paths'] as $name) {
        $table[$name] = $sig[$name];
    }
    $wrong = [];
    $texts = $data['pattern_probes']['texts'];
    foreach ($data['pattern_probes']['matches'] as $name => $want) {
        foreach ($texts as $i => $text) {
            $got = Signatures::search($table[$name], $text) ? '1' : '0';
            if ($got !== $want[$i]) {
                $wrong[] = "$name on " . json_encode($text) . ": $got, Python {$want[$i]}";
            }
        }
    }
    same([], $wrong);
});

check('the signature patterns are spec/patterns.json', fn () => same(
    file_get_contents("$spec/patterns.json"), file_get_contents(dirname(__DIR__) . '/artex-shield/patterns.json'),
    'copy spec/patterns.json to ports/php/artex-shield/patterns.json'));

check('patterns.php is patterns.json, translated (php build.php)', fn () => same(Signatures::fromJson(),
    require dirname(__DIR__) . '/artex-shield/patterns.php'));

check("addresses are read and written as Python's ipaddress does", function () {
    $cases = [['2001:db8:6:002::1', '2001:db8:6:2::/64'], ['::ffff:1.2.3.4', '1.2.3.4'], ['1.2.3.4', '1.2.3.4'],
        ['fe80::1%eth0', 'fe80::/64'], ['2001:0:0:1::1', '2001:0:0:1::/64'], ['::1', '::/64'], ['01.2.3.4', 'invalid'],
        ['1:2:3:4:5:6:7:8', '1:2:3:4::/64'], ['1::2:3:4:5:6:7', '1:0:2:3::/64'], ['::', '::/64'], ['1.2.3', 'invalid'],
        ['1:2:3:4:5:6:1.2.3.4', '1:2:3:4::/64'], [':1:2::', 'invalid'], ['1:::2', 'invalid']];
    foreach ($cases as [$addr, $key]) {
        same($key, Ip::trackKey($addr), $addr);
    }
    same('2001:db8:5::/56', Ip::wider('2001:db8:5:ff::/64'));
    same('2001:db8:5::/48', Ip::wider('2001:db8:5::/56'));
    same(null, Ip::wider('2001:db8::/48'));
    same('10.0.0.0/8', Ip::formatNetwork(Ip::network('10.1.2.3/255.0.0.0')));
});

exit(report());
