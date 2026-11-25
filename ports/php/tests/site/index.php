<?php
/**
 * A stand-in site for tests/prepend.php: one front controller, as most PHP
 * frameworks have, run by PHP's built-in server with examples/prepend.php
 * prepended. Pages under /missing are 404s; /api/... answers JSON; anything
 * else is an HTML page. Each request it serves is counted, so the test can
 * tell what reached the site.
 */
declare(strict_types=1);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$log = getenv('SITE_LOG');
if ($log) {
    file_put_contents($log, ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR']) . ' ' . $path . "\n", FILE_APPEND | LOCK_EX);
}
if (str_starts_with($path, '/missing')) {
    http_response_code(404);
    header('Content-Type: text/html; charset=utf-8');
    echo '<h1>Not found</h1>';
    return;
}
if (str_starts_with($path, '/api/')) {
    header('Content-Type: application/json');
    echo '{"ok":true}';
    return;
}
header('Content-Type: text/html; charset=utf-8');
echo '<html><body>page</body></html>';
