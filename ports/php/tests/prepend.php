<?php
/**
 * examples/prepend.php in front of a PHP site, as auto_prepend_file runs it:
 * PHP's built-in server, the stand-in site in tests/site/, and each request
 * the site served counted. Stops, the statuses fed back at shutdown, bodies,
 * the client check, monitor mode, the command line, a broken setting, and
 * examples/decoys.php.
 *
 *   php tests/prepend.php
 */
declare(strict_types=1);

require __DIR__ . '/check.php';
require_once dirname(__DIR__) . '/artex-shield/autoload.php';

const SECRET = 'prepend-test-secret-0123456789';
const BROWSER = ['User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
    'Accept' => 'text/html', 'Accept-Language' => 'en-GB'];

$root = dirname(__DIR__);
$tmp = sys_get_temp_dir() . '/artex-prepend-test-' . getmypid();
@mkdir($tmp, 0700, true);
$servers = [];

/**
 * A built-in server with these ARTEX_SHIELD_* settings: [port, site log, error log]. It serves
 * tests/site as its document root with examples/prepend.php as auto_prepend_file, or, with
 * $everyPath, sends every path to the front controller (tests/site/router.php).
 */
function server(string $name, array $env, bool $everyPath = false): array
{
    global $root, $tmp, $servers;
    $probe = stream_socket_server('tcp://127.0.0.1:0');
    $port = (int) explode(':', stream_socket_get_name($probe, false))[1];
    fclose($probe);
    $site = "$tmp/$name-site.log";
    $errors = "$tmp/$name-errors.log";
    $vars = ['SITE_LOG' => $site, 'ARTEX_SHIELD_DATA_DIR' => "$tmp/$name-data", 'PATH' => getenv('PATH')];
    foreach ($env as $k => $v) {
        $vars["ARTEX_SHIELD_$k"] = $v;
    }
    $command = $everyPath
        ? [PHP_BINARY, '-d', "error_log=$errors", '-S', "127.0.0.1:$port", "$root/tests/site/router.php"]
        : [PHP_BINARY, '-d', "auto_prepend_file=$root/examples/prepend.php", '-d', "error_log=$errors",
            '-S', "127.0.0.1:$port", '-t', "$root/tests/site"];
    $servers[] = proc_open($command,
        [1 => ['file', "$tmp/$name-server.log", 'a'], 2 => ['file', "$tmp/$name-server.log", 'a']], $pipes, null, $vars);
    for ($i = 0; $i < 100 && !@fsockopen('127.0.0.1', $port); $i++) {
        usleep(50000);
    }
    return [$port, $site, $errors];
}

/** One request on a new connection: [status, headers (lower-case), body]. */
function http(int $port, string $method, string $path, array $headers = BROWSER, string $body = ''): array
{
    $sock = stream_socket_client("tcp://127.0.0.1:$port", $errno, $error, 5);
    $head = "$method $path HTTP/1.1\r\nHost: shop.example\r\nConnection: close\r\n";
    foreach ($headers as $k => $v) {
        $head .= "$k: $v\r\n";
    }
    if ($body !== '' || $method === 'POST') {
        $head .= 'Content-Length: ' . strlen($body) . "\r\n";
    }
    fwrite($sock, "$head\r\n$body");
    $raw = stream_get_contents($sock);
    fclose($sock);
    [$top, $payload] = explode("\r\n\r\n", $raw, 2) + [1 => ''];
    $lines = explode("\r\n", $top);
    $out = [];
    foreach (array_slice($lines, 1) as $line) {
        [$k, $v] = explode(':', $line, 2) + [1 => ''];
        $out[strtolower(trim($k))] = trim($v);
    }
    return [(int) explode(' ', $lines[0])[1], $out, $payload];
}

function from(string $ip, array $headers = BROWSER): array
{
    return $headers + ['X-Forwarded-For' => $ip];
}

/** How many requests from $ip the site served. */
function served(string $log, string $ip): int
{
    return is_file($log) ? substr_count((string) file_get_contents($log), "$ip ") : 0;
}

[$port, $site, $errors] = server('enforce', ['MODE' => 'enforce', 'SECRET' => SECRET, 'TRUSTED_PROXIES' => '127.0.0.1/32',
    'CLIENT_CHECK' => '1']);

check('a page is served, and the site sees it', function () use ($port, $site) {
    [$status, , $body] = http($port, 'GET', '/', from('198.51.100.1'));
    same([200, '<html><body>page</body></html>', 1], [$status, $body, served($site, '198.51.100.1')]);
});

check('a scanner is blocked before the site runs, and stays blocked', function () use ($port, $site, $errors) {
    [$status, $headers, $body] = http($port, 'GET', '/', from('203.0.113.10', ['User-Agent' => 'sqlmap/1.8.4#stable']));
    same(403, $status);
    truthy(str_starts_with($body, 'Request blocked. Reference: '), $body);
    same('no-store', $headers['cache-control'] ?? null);
    [$status] = http($port, 'GET', '/', from('203.0.113.10'));
    same(403, $status, 'the next request, from another PHP process');
    same(0, served($site, '203.0.113.10'));
    usleep(100000);
    truthy(preg_match('~artex-shield: \{"ts":"[^"]+","action":"block".*"ip":"203\.0\.113\.10".*"tool:sqlmap"~',
        (string) @file_get_contents($errors)) === 1, 'the block is in the PHP error log');
});

check('statuses the site answered with are fed back when the script ends', function () use ($port) {
    foreach (['/missing/graphql', '/missing/actuator', '/missing/api-docs'] as $path) {
        same(404, http($port, 'GET', $path, from('203.0.113.20'))[0], $path);
    }
    [$status, $headers] = http($port, 'GET', '/', from('203.0.113.20'));
    same(429, $status, 'three recon 404s make 75 points: throttled');
    truthy((int) ($headers['retry-after'] ?? 0) >= 120, 'Retry-After');
});

check('a planted password in a form body is blocked', function () use ($port, $site) {
    $password = ArtexShield\Decoys::honeytokens(SECRET)['passwords'][1];
    $form = from('203.0.113.30', BROWSER + ['Content-Type' => 'application/x-www-form-urlencoded']);
    same(403, http($port, 'POST', '/login', $form, 'log=admin-legacy&pwd=' . rawurlencode($password))[0]);
    $boundary = 'artexboundary';
    $multipart = "--$boundary\r\nContent-Disposition: form-data; name=\"pwd\"\r\n\r\n$password\r\n--$boundary--\r\n";
    same(403, http($port, 'POST', '/login', from('203.0.113.31', BROWSER + ['Content-Type' => "multipart/form-data; boundary=$boundary"]),
        $multipart)[0], 'and in a multipart form, which PHP parses before any script runs');
    same(0, served($site, '203.0.113.30') + served($site, '203.0.113.31'));
});

check("the client check's script and endpoint are answered here", function () {
    // The script's path ends in .js: it reaches PHP where every path goes to the front controller.
    [$port, $site] = server('every-path', ['MODE' => 'enforce', 'SECRET' => SECRET, 'TRUSTED_PROXIES' => '127.0.0.1/32',
        'CLIENT_CHECK' => '1'], true);
    [$status, $headers, $body] = http($port, 'GET', '/_artex/check.js', from('198.51.100.40'));
    same([200, 'text/javascript; charset=utf-8'], [$status, $headers['content-type'] ?? null]);
    truthy(str_contains($body, '"/_artex/check"'), 'the script reports to the check');
    [$status, $headers] = http($port, 'GET', '/_artex/check?v=1&f=0', from('198.51.100.40'));
    same(204, $status);
    truthy(str_starts_with($headers['set-cookie'] ?? '', 'artex_check=1.'), $headers['set-cookie'] ?? 'no cookie');
    same(0, served($site, '198.51.100.40'));
});

check('monitor mode, the default, stops nothing', function () {
    [$port, $site] = server('monitor', ['TRUSTED_PROXIES' => '127.0.0.1/32']);
    same(200, http($port, 'GET', '/', from('203.0.113.50', ['User-Agent' => 'sqlmap/1.8.4#stable']))[0]);
    same(1, served($site, '203.0.113.50'));
});

check('a broken setting leaves the site up, and says why in the error log', function () {
    [$port, $site, $errors] = server('broken', ['EXEMPT_PATHS' => '/']);
    same(200, http($port, 'GET', '/', BROWSER)[0]);
    usleep(100000);
    truthy(str_contains((string) @file_get_contents($errors), 'artex-shield: exempt_paths'), 'the reason is logged');
});

check('the command line is left alone', function () use ($root) {
    $out = shell_exec(escapeshellarg(PHP_BINARY) . ' -d ' . escapeshellarg("auto_prepend_file=$root/examples/prepend.php")
        . " -r 'echo \"cli ok\";' 2>&1");
    same('cli ok', $out);
});

check('decoys.php prints what to plant, from the same secret', function () use ($root) {
    $out = (string) shell_exec('ARTEX_SHIELD_SECRET=' . escapeshellarg(SECRET) . ' ARTEX_SHIELD_CLIENT_CHECK=1 '
        . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("$root/examples/decoys.php"));
    $canaries = ArtexShield\Decoys::canaries(SECRET);
    $tokens = ArtexShield\Decoys::honeytokens(SECRET);
    truthy(str_contains($out, "Disallow: {$canaries[0]}\n"), 'robots.txt lines');
    truthy(str_contains($out, " / {$tokens['passwords'][1]} ;"), 'the HTML comment with a password');
    truthy(str_contains($out, '<script src="/_artex/check.js" async></script>'), 'the client check tag');
});

foreach ($servers as $s) {
    proc_terminate($s);
    proc_close($s);
}
exec('rm -rf ' . escapeshellarg($tmp));
exit(report());
