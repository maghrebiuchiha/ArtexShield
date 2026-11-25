<?php
/**
 * The WordPress plugin's own code: its request path under PHP's built-in
 * server, in front of the stand-in site in tests/wp/, and its settings
 * handling in the CLI.
 *
 *   php tests/plugin.php
 */
declare(strict_types=1);

require __DIR__ . '/check.php';
require_once dirname(__DIR__) . '/artex-shield/autoload.php';

const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36';
const BROWSER = ['User-Agent' => CHROME, 'Accept' => 'text/html', 'Accept-Language' => 'en-GB'];
const SCANNER = ['User-Agent' => 'sqlmap/1.8.4#stable'];
const SECRET = 'plugin-test-secret-0123456789';

$tmp = sys_get_temp_dir() . '/artex-plugin-test-' . getmypid();
@mkdir($tmp, 0700, true);
$optionsFile = "$tmp/options.json";
$content = "$tmp/wp-content";
@mkdir($content);
putenv("ARTEX_TEST_OPTIONS=$optionsFile");
putenv("ARTEX_TEST_CONTENT=$content");

/** Settings for the next requests, and a clean slate of scores and blocks. */
function site(array $settings = []): void
{
    global $optionsFile, $content;
    file_put_contents($optionsFile, json_encode(['artex_shield_settings' => $settings + ['secret' => SECRET]]));
    exec('rm -rf ' . escapeshellarg("$content/artex-shield-data"));
}

$probe = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($probe, false))[1];
fclose($probe);
$server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/wp/index.php'], [1 => ['file', "$tmp/server.log", 'a'],
    2 => ['file', "$tmp/server.log", 'a']], $pipes, null, ['ARTEX_TEST_OPTIONS' => $optionsFile, 'ARTEX_TEST_CONTENT' => $content]);
for ($i = 0; $i < 100 && !@fsockopen('127.0.0.1', $port); $i++) {
    usleep(50000);
}

/** One HTTP/1.1 request over a fresh connection: [status, headers (lower-case), body]. */
function http(string $method, string $path, array $headers = BROWSER, string $body = '', bool $chunked = false): array
{
    global $port;
    $sock = stream_socket_client("tcp://127.0.0.1:$port", $errno, $error, 5);
    $head = "$method $path HTTP/1.1\r\nHost: shop.example\r\nConnection: close\r\n";
    foreach ($headers as $k => $v) {
        $head .= "$k: $v\r\n";
    }
    if ($chunked) {
        $head .= "Transfer-Encoding: chunked\r\n";
        $body = dechex(strlen($body)) . "\r\n$body\r\n0\r\n\r\n";
    } elseif ($body !== '' || in_array($method, ['POST', 'PUT'], true)) {
        $head .= 'Content-Length: ' . strlen($body) . "\r\n";
    }
    fwrite($sock, "$head\r\n$body");
    $raw = stream_get_contents($sock);
    fclose($sock);
    [$top, $rest] = array_pad(explode("\r\n\r\n", (string) $raw, 2), 2, '');
    $lines = explode("\r\n", $top);
    $status = (int) (explode(' ', $lines[0])[1] ?? 0);
    $hs = [];
    foreach (array_slice($lines, 1) as $line) {
        [$k, $v] = array_pad(explode(':', $line, 2), 2, '');
        $hs[strtolower(trim($k))][] = trim($v);
    }
    return [$status, $hs, $rest];
}

check('monitor mode, the default, lets a scanner through and keeps the event', function () use ($content) {
    site();
    same(200, http('GET', '/', SCANNER)[0]);
    $events = glob("$content/artex-shield-data/*.php") ?: [];
    truthy(count($events) > 2, 'state was written');
    $log = implode('', array_map('file_get_contents', $events));
    truthy(str_contains($log, '"action":"block"') && str_contains($log, 'tool:sqlmap'), 'the block is in the recent events');
});

check('enforce mode blocks a scanner before the site, and its address stays blocked', function () {
    site(['mode' => 'enforce']);
    [$status, $headers, $body] = http('GET', '/', SCANNER);
    same(403, $status);
    truthy(str_starts_with($body, 'Request blocked. Reference: '), $body);
    same(['no-store'], $headers['cache-control'] ?? null);
    same(403, http('GET', '/')[0]);
});

check('a stopped HEAD request gets no body', function () {
    site(['mode' => 'enforce']);
    [$status, , $body] = http('HEAD', '/', SCANNER);
    same([403, ''], [$status, $body]);
});

check('a payload is throttled with Retry-After', function () {
    site(['mode' => 'enforce']);
    [$status, $headers] = http('GET', '/search?q=%3Cscript%3Ealert(1)%3C/script%3E');
    same(429, $status);
    truthy((int) ($headers['retry-after'][0] ?? 0) >= 120, 'Retry-After');
});

check('404s the site answers build a score', function () {
    site(['mode' => 'enforce']);
    same(404, http('GET', '/old-site-backup.sql')[0]);
    same(429, http('GET', '/')[0]);                       // 60 points for asking for a missing dump
});

check('the decoys are planted, and a canary blocks', function () {
    site(['mode' => 'enforce', 'client_check' => true]);
    [, , $robots] = http('GET', '/robots.txt');
    truthy(str_contains($robots, "Disallow: /wp-admin/\n") && preg_match('~Disallow: (/api/v1/internal/audit-[0-9a-f]{10})~', $robots, $m), $robots);
    [, , $page] = http('GET', '/');
    foreach (['rel="nofollow" tabindex="-1"', 'var __legacyApi', 'var __stagingConfig', 'TODO(ops): remove before release',
                 '<script src="/_artex/check.js" async></script>'] as $planted) {
        truthy(str_contains($page, $planted), $planted);
    }
    same(403, http('GET', $m[1])[0]);
});

check('decoys off plants nothing', function () {
    site(['decoys' => false]);
    [, , $page] = http('GET', '/');
    truthy(!str_contains($page, '__stagingConfig') && !str_contains($page, 'nofollow'), $page);
});

check('a login with a planted password is blocked before the site', function () {
    site(['mode' => 'enforce']);
    $tokens = ArtexShield\Decoys::honeytokens(SECRET);
    $form = http_build_query(['log' => 'admin-legacy', 'pwd' => $tokens['passwords'][1]]);
    [$status, , $body] = http('POST', '/wp-login.php', BROWSER + ['Content-Type' => 'application/x-www-form-urlencoded'], $form);
    same(403, $status, $body);
});

check('a planted key in a chunked JSON body, and in a multipart form, is blocked', function () {
    site(['mode' => 'enforce']);
    $tokens = ArtexShield\Decoys::honeytokens(SECRET);
    same(403, http('POST', '/echo', BROWSER + ['Content-Type' => 'application/json'], json_encode(['k' => $tokens['api_keys'][0]]), true)[0]);
    site(['mode' => 'enforce']);
    $form = "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{$tokens['api_keys'][1]}\r\n--b--\r\n";
    same(403, http('POST', '/echo', BROWSER + ['Content-Type' => 'multipart/form-data; boundary=b'], $form)[0]);
});

check('the site still reads every body whole', function () {
    site(['mode' => 'enforce']);
    foreach ([1, 70000, 300000] as $size) {
        $blob = random_bytes($size);
        [$status, , $body] = http('POST', '/echo', BROWSER + ['Content-Type' => 'application/octet-stream'], $blob);
        same([200, $size, hash('sha256', $blob)], [$status, json_decode($body, true)['input'] ?? null, json_decode($body, true)['sha'] ?? null]);
    }
    [, , $body] = http('POST', '/echo', BROWSER + ['Content-Type' => 'application/x-www-form-urlencoded'], 'a=1&b=2');
    same(2, json_decode($body, true)['post']);
});

check("the client check's script and endpoint are answered by the plugin", function () {
    site(['client_check' => true]);
    [$status, $headers, $body] = http('GET', '/_artex/check.js');
    same([200, ['text/javascript; charset=utf-8']], [$status, $headers['content-type'] ?? null]);
    truthy(str_contains($body, '"/_artex/check"'), $body);
    [$status, $headers] = http('GET', '/_artex/check?v=1&f=0');
    same(204, $status);
    truthy((bool) preg_match('/^artex_check=1\.\d+\.0\.[\w-]{22}; Path=\/; Max-Age=86400; HttpOnly; SameSite=Lax$/', $headers['set-cookie'][0] ?? ''),
        $headers['set-cookie'][0] ?? 'no cookie');
});

check('X-Forwarded-For is believed only from a trusted proxy', function () {
    site(['mode' => 'enforce', 'trusted_proxies' => ['127.0.0.1/32']]);
    same(403, http('GET', '/', SCANNER + ['X-Forwarded-For' => '203.0.113.7'])[0]);
    same(403, http('GET', '/', BROWSER + ['X-Forwarded-For' => '203.0.113.7'])[0]);
    same(200, http('GET', '/', BROWSER + ['X-Forwarded-For' => '198.51.100.9'])[0]);
    site(['mode' => 'enforce']);
    same(403, http('GET', '/', SCANNER + ['X-Forwarded-For' => '203.0.113.7'])[0]);
    same(403, http('GET', '/', BROWSER + ['X-Forwarded-For' => '198.51.100.9'])[0]);   // it was 127.0.0.1 all along
});

check('allowlisted addresses and exempt paths are never scored', function () {
    site(['mode' => 'enforce', 'exempt_paths' => ['/healthz']]);
    same(404, http('GET', '/healthz', SCANNER)[0]);
    site(['mode' => 'enforce', 'allow_cidrs' => ['127.0.0.0/8']]);
    same(200, http('GET', '/', SCANNER)[0]);
});

check('a broken setting leaves the site up', function () {
    site(['mode' => 'enforce', 'trusted_proxies' => ['not-a-network']]);
    same(200, http('GET', '/', SCANNER)[0]);
});

// ---- settings, in the CLI ----------------------------------------------------------
require __DIR__ . '/wp/stubs.php';
require dirname(__DIR__) . '/artex-shield/artex-shield.php';

check('the settings page keeps what is valid and refuses the rest', function () {
    site(['mode' => 'monitor', 'trusted_proxies' => ['10.0.0.0/8']]);
    $GLOBALS['__settings_errors'] = [];
    $out = ArtexShield\WordPress\Admin::sanitize(['mode' => 'enforce', 'secret' => 'short', 'decoys' => '1',
        'trusted_proxies' => "10.0.0.0/8\nnot-a-network", 'allow_cidrs' => "192.0.2.0/24  # monitoring\n\n2001:db8::/32",
        'exempt_paths' => "/healthz\n/status/", 'store' => 'files']);
    same('enforce', $out['mode']);
    same(SECRET, $out['secret']);                                  // too short: kept
    same(['10.0.0.0/8'], $out['trusted_proxies']);                 // one bad line: the old list kept
    same(['192.0.2.0/24', '2001:db8::/32'], $out['allow_cidrs']);
    same(['/healthz', '/status'], $out['exempt_paths']);
    same([true, false, false], [$out['decoys'], $out['honeytokens'], $out['client_check']]);
    same(['secret', 'trusted_proxies'], array_column($GLOBALS['__settings_errors'], 0));
    $bad = ArtexShield\WordPress\Admin::sanitize(['mode' => 'block-everyone', 'exempt_paths' => '/', 'store' => 'redis']);
    same(['monitor', [], 'auto'], [$bad['mode'], $bad['exempt_paths'], $bad['store']]);
    $GLOBALS['__settings_errors'] = [];
    ArtexShield\WordPress\Admin::sanitize(['secret' => SECRET, 'allow_cidrs' => '<img src=x onerror=alert(1)>']);
    same([['allow_cidrs', 'Allowlist: not a network: &lt;img src=x onerror=alert(1)&gt;. Not changed.']],
        $GLOBALS['__settings_errors'], 'WordPress prints messages as HTML: what was typed is escaped');
});

check('switching to enforce does not shut out the admin who saves it', function () {
    global $tmp;
    site(['mode' => 'monitor']);
    ini_set('error_log', "$tmp/cli.log");                                   // the events, out of the test's output
    $_SERVER['REMOTE_ADDR'] = '203.0.113.9';
    $shield = ArtexShield\WordPress\Plugin::shield();
    $shield->check('203.0.113.9', 'GET', '/', '', ['user-agent' => SCANNER['User-Agent']]);     // their own scan, in monitor mode
    $shield->check('198.51.100.7', 'GET', '/', '', ['user-agent' => SCANNER['User-Agent']]);    // somebody else's
    $blocked = array_keys($shield->blocklist());
    sort($blocked);
    same(['198.51.100.7', '203.0.113.9'], $blocked, 'both blocked');
    $GLOBALS['__settings_errors'] = [];
    ArtexShield\WordPress\Admin::sanitize(['mode' => 'monitor', 'secret' => SECRET]);
    truthy(isset($shield->blocklist()['203.0.113.9']), 'saving monitor mode changes nothing');
    ArtexShield\WordPress\Admin::sanitize(['mode' => 'enforce', 'secret' => SECRET]);
    same(['198.51.100.7'], array_keys($shield->blocklist()), 'only their own address is unblocked');
    same(['unblocked'], array_column($GLOBALS['__settings_errors'], 0));
    truthy(str_contains($GLOBALS['__settings_errors'][0][1], '203.0.113.9'), 'the notice names it');
    ArtexShield\WordPress\Admin::sanitize(['mode' => 'enforce', 'secret' => SECRET]);   // WordPress may sanitize twice
    same(1, count($GLOBALS['__settings_errors']), 'said once');
    unset($_SERVER['REMOTE_ADDR']);
});

proc_terminate($server);
proc_close($server);
exec('rm -rf ' . escapeshellarg($tmp));
exit(report());
