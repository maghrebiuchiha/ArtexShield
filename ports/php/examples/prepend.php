<?php
/**
 * artex-shield for any PHP site, run before every script by PHP's
 * auto_prepend_file. Nothing in the site changes.
 *
 *   php.ini, a .user.ini, or the PHP-FPM pool:
 *     auto_prepend_file = /opt/artex-shield/examples/prepend.php
 *     (PHP-FPM pool: php_admin_value[auto_prepend_file] = ...; Apache: php_value auto_prepend_file ...)
 *
 * Edit the settings below, or set them in the environment PHP runs with
 * (PHP-FPM passes it on with clear_env = no, or env[NAME] = value lines).
 * It starts in monitor mode: it logs what it would stop to the PHP error log
 * and stops nothing.
 *
 * It sees the requests PHP handles. With a front controller (Laravel,
 * Symfony, Drupal, most frameworks) that is every request; files the web
 * server serves itself never reach PHP, so their 404s are not counted.
 */
declare(strict_types=1);

if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
    return;                                        // cron jobs and command-line tools are not requests
}

require_once __DIR__ . '/../artex-shield/autoload.php';

(static function (): void {
    $env = static fn (string $name): string => (string) (getenv("ARTEX_SHIELD_$name") ?: '');
    $list = static fn (string $name): array => array_values(array_filter(preg_split('/[\s,]+/', $env($name)) ?: []));
    $secret = $env('SECRET');                      // a long random string you keep: decides the decoys
    $settings = [
        'mode' => $env('MODE') ?: 'monitor',
        'trusted_proxies' => $list('TRUSTED_PROXIES'),     // your load balancer or CDN, if any
        'allow_cidrs' => $list('ALLOW_CIDRS'),
        'exempt_paths' => $list('EXEMPT_PATHS'),           // e.g. /healthz
        'client_check' => in_array($env('CLIENT_CHECK'), ['1', 'true', 'yes', 'on'], true),
        // Each event, one JSON line in the PHP error log, as the WordPress plugin writes them.
        'on_event' => static fn (array $event) => error_log('artex-shield: ' . json_encode($event, JSON_UNESCAPED_SLASHES)),
    ];
    if ($secret !== '') {
        $settings['canary_paths'] = ArtexShield\Decoys::canaries($secret);
        $settings['honeytokens'] = ArtexShield\Decoys::honeytokens($secret);
        $settings['client_check_secret'] = hash_hmac('sha256', 'client-check', $secret);
    }
    // Scores and blocks, shared by every PHP worker. Keep it out of the document root.
    $dir = $env('DATA_DIR') ?: sys_get_temp_dir() . '/artex-shield';
    try {
        $store = new ArtexShield\Store\FileStore($dir);
        ArtexShield\Guard::protect(new ArtexShield\Shield($settings, $store));
        if (random_int(1, 1000) === 1) {
            register_shutdown_function([$store, 'prune']);     // now and then, remove expired entries
        }
    } catch (Throwable $e) {
        // A bad setting or an unwritable directory must not take the site down.
        error_log('artex-shield: ' . $e->getMessage());
    }
})();
