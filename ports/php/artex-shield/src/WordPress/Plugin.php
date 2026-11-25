<?php
/**
 * The WordPress side: settings in, a decision on every request as soon as
 * the plugin loads, the site's answer fed back at shutdown, and the decoys
 * planted on the site's pages.
 */
declare(strict_types=1);

namespace ArtexShield\WordPress;

use ArtexShield\Decision;
use ArtexShield\Decoys;
use ArtexShield\Guard;
use ArtexShield\Request;
use ArtexShield\Shield;
use ArtexShield\Store\FileStore;
use ArtexShield\Store\MemoryStore;
use ArtexShield\Store\ObjectCacheStore;
use ArtexShield\Store\Store;

final class Plugin
{
    public const OPTION = 'artex_shield_settings';
    public const DEFAULTS = [
        'mode' => 'monitor',            // log only; enforce once the log shows no visitor you would stop
        'secret' => '',                 // made on activation; decides canaries, honeytokens and the check's key
        'decoys' => true,               // plant canaries (and honeytokens, if on) on the site's pages
        'honeytokens' => true,
        'client_check' => false,
        'trusted_proxies' => [],
        'allow_cidrs' => [],
        'exempt_paths' => [],
        'store' => 'auto',              // auto: the object cache if it is persistent, else files
    ];
    private const EVENTS_KEPT = 50;

    private static ?Shield $shield = null;
    private static ?Store $store = null;
    private static ?string $problem = null;
    private static string $file = '';

    public static function boot(string $file): void
    {
        self::$file = $file;
        register_activation_hook($file, [self::class, 'activate']);
        register_deactivation_hook($file, [self::class, 'deactivate']);
        add_action('activated_plugin', [self::class, 'loadFirst']);
        add_action('artex_shield_prune', [self::class, 'prune']);
        if (is_admin()) {
            Admin::register($file);
        }
        if ((defined('WP_CLI') && WP_CLI) || PHP_SAPI === 'cli') {
            return;
        }
        try {
            self::guard();
        } catch (\Throwable $e) {
            // A broken setting or an unwritable store must not take the site down.
            self::$problem = $e->getMessage();
            error_log('artex-shield: ' . $e->getMessage());
        }
    }

    /** The settings, completed with defaults. */
    public static function settings(): array
    {
        $saved = get_option(self::OPTION, []);
        return array_merge(self::DEFAULTS, is_array($saved) ? $saved : []);
    }

    public static function problem(): ?string
    {
        return self::$problem;
    }

    /** The shield for these settings, built once per request. */
    public static function shield(): Shield
    {
        if (self::$shield !== null) {
            return self::$shield;
        }
        $s = self::settings();
        $secret = (string) $s['secret'];
        $options = [
            'mode' => $s['mode'] === 'enforce' ? 'enforce' : 'monitor',
            'trusted_proxies' => array_values((array) $s['trusted_proxies']),
            'allow_cidrs' => array_values((array) $s['allow_cidrs']),
            'exempt_paths' => array_values((array) $s['exempt_paths']),
            'on_event' => [self::class, 'record'],
        ];
        if ($secret !== '') {
            $options['canary_paths'] = Decoys::canaries($secret);
            if ($s['honeytokens']) {
                $options['honeytokens'] = Decoys::honeytokens($secret);
            }
            if ($s['client_check']) {
                $options['client_check'] = true;
                $options['client_check_secret'] = hash_hmac('sha256', 'client-check', $secret);
            }
        }
        return self::$shield = new Shield($options, self::store());
    }

    public static function store(): Store
    {
        if (self::$store !== null) {
            return self::$store;
        }
        $choice = self::settings()['store'];
        $cache = function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache();
        if ($choice === 'cache' || ($choice === 'auto' && $cache)) {
            return self::$store = new ObjectCacheStore();
        }
        try {
            return self::$store = new FileStore(self::dataDir());
        } catch (\RuntimeException $e) {
            self::$problem = $e->getMessage() . ': scores last one request only until this is fixed';
            return self::$store = new MemoryStore();
        }
    }

    public static function storeName(): string
    {
        $store = self::store();
        return $store instanceof ObjectCacheStore ? 'the object cache' : ($store instanceof FileStore ? 'files in ' . self::dataDir() : 'memory (one request)');
    }

    public static function dataDir(): string
    {
        return (defined('ARTEX_SHIELD_DATA_DIR') ? (string) constant('ARTEX_SHIELD_DATA_DIR') : WP_CONTENT_DIR . '/artex-shield-data');
    }

    /** The address the shield scores this request under, as guard() works it out, or null outside a web request. */
    public static function visitor(): ?string
    {
        if (!isset($_SERVER['REMOTE_ADDR'])) {
            return null;
        }
        $request = Request::fromGlobals($_SERVER);
        return self::shield()->clientIp($request->peer, $request->headers['x-forwarded-for'] ?? null);
    }

    /** Decide on this request before WordPress goes on (ArtexShield\Guard), and plant the decoys. */
    private static function guard(): void
    {
        Guard::protect(self::shield());
        self::plant();
    }

    /** What a stopped request gets: 403 or 429, plain text, a reference to quote. */
    public static function reply(Decision $d): array
    {
        return Guard::reply($d);
    }

    /** Canaries in robots.txt and the page, honeytokens in a comment and a script, the check's tag. */
    private static function plant(): void
    {
        $s = self::settings();
        $secret = (string) $s['secret'];
        if ($secret === '') {
            return;
        }
        if ($s['decoys']) {
            $canaries = Decoys::canaries($secret);
            add_filter('robots_txt', static fn ($out): string => rtrim((string) $out) . "\n\n" . Decoys::robotsTxtBlock($canaries), 99);
            add_action('wp_footer', static function () use ($canaries, $s, $secret): void {
                echo Decoys::htmlTrap($canaries[0]), "\n";
                $script = Decoys::jsTrap($canaries[1]);
                if ($s['honeytokens']) {
                    $tokens = Decoys::honeytokens($secret);
                    echo Decoys::honeytokenHtml($tokens), "\n";
                    $script .= "\n" . Decoys::honeytokenJs($tokens);
                }
                echo "<script>\n", $script, "\n</script>\n";
            }, 99);
        }
        if ($s['client_check']) {
            add_action('wp_head', static fn () => print(self::shield()->clientCheckTag() . "\n"), 1);
        }
    }

    /** Each event: the PHP error log, and the last few for the settings page. */
    public static function record(array $event): void
    {
        error_log('artex-shield: ' . json_encode($event, JSON_UNESCAPED_SLASHES));
        $store = self::store();
        $store->lock('events');
        try {
            $events = $store->get('events');
            $events = is_array($events) ? $events : [];
            $events[] = $event;
            $store->set('events', array_slice($events, -self::EVENTS_KEPT), 30 * 86400);
        } finally {
            $store->unlock('events');
        }
    }

    public static function events(): array
    {
        $events = self::store()->get('events');
        return is_array($events) ? array_reverse($events) : [];
    }

    public static function activate(): void
    {
        $s = self::settings();
        if ($s['secret'] === '') {
            $s['secret'] = bin2hex(random_bytes(32));
        }
        update_option(self::OPTION, $s, true);
        if (!wp_next_scheduled('artex_shield_prune')) {
            wp_schedule_event(time() + 3600, 'hourly', 'artex_shield_prune');
        }
    }

    public static function deactivate(): void
    {
        wp_clear_scheduled_hook('artex_shield_prune');
    }

    /** Load before other plugins, so the check runs before they do. */
    public static function loadFirst(string $plugin): void
    {
        $self = plugin_basename(self::$file);
        if ($plugin !== $self) {
            return;
        }
        $active = (array) get_option('active_plugins', []);
        $at = array_search($self, $active, true);
        if ($at !== false && $at !== 0) {
            unset($active[$at]);
            array_unshift($active, $self);
            update_option('active_plugins', array_values($active));
        }
    }

    public static function prune(): void
    {
        $store = self::store();
        if ($store instanceof FileStore) {
            $store->prune();
        }
    }
}
