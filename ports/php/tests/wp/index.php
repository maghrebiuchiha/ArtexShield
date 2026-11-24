<?php
/**
 * The front controller for `php -S 127.0.0.1:PORT tests/wp/index.php`: loads
 * the plugin as WordPress would (which decides on the request at once), then
 * answers like a small site, calling the hooks WordPress calls.
 */
declare(strict_types=1);

require __DIR__ . '/stubs.php';
require dirname(__DIR__, 2) . '/artex-shield/artex-shield.php';

$path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
$input = (string) file_get_contents('php://input');

switch ($path) {
    case '/':
        header('Content-Type: text/html; charset=UTF-8');
        echo "<!doctype html><html><head><title>Shielded</title>\n";
        do_action('wp_head');
        echo "</head><body><h1>Shielded</h1>\n";
        do_action('wp_footer');
        echo "</body></html>\n";
        break;
    case '/robots.txt':
        header('Content-Type: text/plain; charset=utf-8');
        echo apply_filters('robots_txt', "User-agent: *\nDisallow: /wp-admin/\n", true);
        break;
    case '/wp-login.php':
    case '/echo':
        header('Content-Type: application/json');
        echo json_encode(['input' => strlen($input), 'sha' => hash('sha256', $input), 'post' => count($_POST)]);
        break;
    default:
        http_response_code(404);
        header('Content-Type: text/html; charset=UTF-8');
        echo '<p>Not found</p>';
}
