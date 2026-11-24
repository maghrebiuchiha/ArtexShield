<?php
/**
 * A stand-in for the few WordPress functions the plugin calls, enough to run
 * its request path under PHP's built-in server and its settings code in the
 * CLI. Options live in a JSON file named by ARTEX_TEST_OPTIONS. CI runs the
 * plugin on real WordPress as well (ports/php/tests/wordpress/).
 */
declare(strict_types=1);

const ABSPATH = __DIR__ . '/';
define('WP_CONTENT_DIR', (string) (getenv('ARTEX_TEST_CONTENT') ?: sys_get_temp_dir() . '/artex-wp-content'));

$GLOBALS['__hooks'] = [];
$GLOBALS['__settings_errors'] = [];

function __options(): array
{
    $file = getenv('ARTEX_TEST_OPTIONS');
    return $file && is_file($file) ? (json_decode((string) file_get_contents($file), true) ?: []) : [];
}

function get_option(string $name, mixed $default = false): mixed
{
    return __options()[$name] ?? $default;
}

function update_option(string $name, mixed $value, mixed $autoload = null): bool
{
    $all = __options();
    $all[$name] = $value;
    file_put_contents((string) getenv('ARTEX_TEST_OPTIONS'), json_encode($all));
    return true;
}

function add_filter(string $hook, callable $fn, int $priority = 10, int $args = 1): bool
{
    $GLOBALS['__hooks'][$hook][$priority][] = [$fn, $args];
    return true;
}

function add_action(string $hook, callable $fn, int $priority = 10, int $args = 1): bool
{
    return add_filter($hook, $fn, $priority, $args);
}

function apply_filters(string $hook, mixed $value, mixed ...$more): mixed
{
    $byPriority = $GLOBALS['__hooks'][$hook] ?? [];
    ksort($byPriority);
    foreach ($byPriority as $fns) {
        foreach ($fns as [$fn, $args]) {
            $value = $fn(...array_slice(array_merge([$value], $more), 0, $args));
        }
    }
    return $value;
}

function do_action(string $hook, mixed ...$args): void
{
    apply_filters($hook, $args[0] ?? null, ...array_slice($args, 1));
}

function register_activation_hook(string $file, callable $fn): void
{
}

function register_deactivation_hook(string $file, callable $fn): void
{
}

function is_admin(): bool
{
    return false;
}

function wp_using_ext_object_cache(): bool
{
    return false;
}

function plugin_basename(string $file): string
{
    return 'artex-shield/artex-shield.php';
}

function wp_next_scheduled(string $hook): bool
{
    return false;
}

function wp_schedule_event(int $time, string $recurrence, string $hook): bool
{
    return true;
}

function wp_clear_scheduled_hook(string $hook): int
{
    return 0;
}

function add_settings_error(string $setting, string $code, string $message, string $type = 'error'): void
{
    $GLOBALS['__settings_errors'][] = [$code, $message];
}

function __(string $text, string $domain = 'default'): string
{
    return $text;
}
