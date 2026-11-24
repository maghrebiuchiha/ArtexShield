<?php
/** Settings → ARTEX Shield: mode, secret, decoys, allowlists, and what the shield has done. */
declare(strict_types=1);

namespace ArtexShield\WordPress;

use ArtexShield\Ip;
use ArtexShield\Util;

final class Admin
{
    private const PAGE = 'artex-shield';

    public static function register(string $file): void
    {
        add_action('admin_menu', static function (): void {
            add_options_page('ARTEX Shield', 'ARTEX Shield', 'manage_options', self::PAGE, [self::class, 'render']);
        });
        add_action('admin_init', static function (): void {
            register_setting(self::PAGE, Plugin::OPTION, ['type' => 'array', 'sanitize_callback' => [self::class, 'sanitize'],
                'default' => Plugin::DEFAULTS]);
        });
        add_action('admin_post_artex_shield_unblock', [self::class, 'unblock']);
        add_filter('plugin_action_links_' . plugin_basename($file), static function (array $links): array {
            array_unshift($links, '<a href="' . esc_url(admin_url('options-general.php?page=' . self::PAGE)) . '">'
                . esc_html__('Settings', 'artex-shield') . '</a>');
            return $links;
        });
        add_action('admin_notices', static function (): void {
            $problem = Plugin::problem();
            if ($problem !== null && current_user_can('manage_options')) {
                echo '<div class="notice notice-error"><p><strong>ARTEX Shield:</strong> ' . esc_html($problem) . '</p></div>';
            }
        });
    }

    /** One entry per line; blank lines and #comments ignored. An array (already
     * sanitized once, as WordPress sometimes does) is taken as it is. */
    private static function lines(mixed $text): array
    {
        $out = [];
        foreach (is_array($text) ? $text : (preg_split('/\R/', (string) $text) ?: []) as $line) {
            $line = (string) $line;
            $line = trim(explode('#', $line, 2)[0]);
            if ($line !== '') {
                $out[] = $line;
            }
        }
        return $out;
    }

    /** Check what was submitted; anything invalid keeps its old value and says why. */
    public static function sanitize(mixed $input): array
    {
        $old = Plugin::settings();
        $in = is_array($input) ? $input : [];
        $out = $old;
        $out['mode'] = in_array($in['mode'] ?? '', ['monitor', 'enforce'], true) ? $in['mode'] : $old['mode'];
        $secret = trim((string) ($in['secret'] ?? $old['secret']));
        if (strlen($secret) >= 16) {
            $out['secret'] = $secret;
        } else {
            add_settings_error(Plugin::OPTION, 'secret', __('The secret must be at least 16 characters; it was not changed.', 'artex-shield'));
        }
        foreach (['decoys', 'honeytokens', 'client_check'] as $flag) {
            $out[$flag] = !empty($in[$flag]);
        }
        foreach (['trusted_proxies' => 'Trusted proxies', 'allow_cidrs' => 'Allowlist'] as $name => $label) {
            $nets = self::lines($in[$name] ?? '');
            try {
                array_map([Ip::class, 'network'], $nets);
                $out[$name] = $nets;
            } catch (\InvalidArgumentException $e) {
                add_settings_error(Plugin::OPTION, $name, sprintf('%s: %s. %s', $label, $e->getMessage(), __('Not changed.', 'artex-shield')));
            }
        }
        $paths = self::lines($in['exempt_paths'] ?? '');
        try {
            $out['exempt_paths'] = Util::prefixes($paths, 'Exempt paths');
        } catch (\InvalidArgumentException $e) {
            add_settings_error(Plugin::OPTION, 'exempt_paths', $e->getMessage() . '. ' . __('Not changed.', 'artex-shield'));
        }
        $out['store'] = in_array($in['store'] ?? '', ['auto', 'files', 'cache'], true) ? $in['store'] : $old['store'];
        return $out;
    }

    public static function unblock(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Not allowed.', 'artex-shield'), 403);
        }
        check_admin_referer('artex_shield_unblock');
        $network = sanitize_text_field(wp_unslash($_POST['network'] ?? ''));
        $address = explode('/', $network)[0];
        $done = $address !== '' && Plugin::shield()->unblock($address);
        wp_safe_redirect(add_query_arg(['page' => self::PAGE, 'unblocked' => $done ? '1' : '0'], admin_url('options-general.php')));
        exit;
    }

    public static function render(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $s = Plugin::settings();
        $name = Plugin::OPTION;
        $checked = static fn (bool $on): string => $on ? ' checked' : '';
        echo '<div class="wrap"><h1>ARTEX Shield</h1>';
        if (isset($_GET['unblocked'])) {
            echo $_GET['unblocked'] === '1'
                ? '<div class="notice notice-success"><p>' . esc_html__('Unblocked.', 'artex-shield') . '</p></div>'
                : '<div class="notice notice-warning"><p>' . esc_html__('That network was not blocked.', 'artex-shield') . '</p></div>';
        }
        settings_errors($name);
        echo '<p>' . esc_html__('Detects and blocks ARTEX-style automated penetration testing before WordPress handles the request.', 'artex-shield') . '</p>';
        echo '<form method="post" action="options.php">';
        settings_fields(self::PAGE);
        echo '<table class="form-table" role="presentation">';
        echo '<tr><th scope="row">' . esc_html__('Mode', 'artex-shield') . '</th><td>';
        foreach (['monitor' => __('Monitor: log what would be stopped, stop nothing', 'artex-shield'),
                     'enforce' => __('Enforce: throttle and block', 'artex-shield')] as $value => $label) {
            echo '<label><input type="radio" name="' . esc_attr($name) . '[mode]" value="' . esc_attr($value) . '"'
                . $checked($s['mode'] === $value) . '> ' . esc_html($label) . '</label><br>';
        }
        echo '<p class="description">' . esc_html__('Start in monitor mode. Switch to enforce when a week of events below shows no visitor you would have stopped.', 'artex-shield') . '</p></td></tr>';
        echo '<tr><th scope="row"><label for="artex-secret">' . esc_html__('Secret', 'artex-shield') . '</label></th><td>'
            . '<input type="text" class="regular-text code" id="artex-secret" name="' . esc_attr($name) . '[secret]" value="' . esc_attr($s['secret']) . '" autocomplete="off">'
            . '<p class="description">' . esc_html__('Decides the canary paths, the fake credentials and the client check\'s key. Changing it changes all of them.', 'artex-shield') . '</p></td></tr>';
        echo '<tr><th scope="row">' . esc_html__('Decoys', 'artex-shield') . '</th><td>'
            . '<label><input type="checkbox" name="' . esc_attr($name) . '[decoys]" value="1"' . $checked((bool) $s['decoys']) . '> '
            . esc_html__('Plant canary paths in robots.txt, a hidden link and a script on every page', 'artex-shield') . '</label><br>'
            . '<label><input type="checkbox" name="' . esc_attr($name) . '[honeytokens]" value="1"' . $checked((bool) $s['honeytokens']) . '> '
            . esc_html__('Credential honeytokens: plant fake keys and passwords, and block whoever presents one', 'artex-shield') . '</label><br>'
            . '<label><input type="checkbox" name="' . esc_attr($name) . '[client_check]" value="1"' . $checked((bool) $s['client_check']) . '> '
            . esc_html__('Client check: a small script reports browser automation (soft evidence only; visitors without JavaScript are never affected)', 'artex-shield') . '</label></td></tr>';
        $area = static function (string $field, string $label, string $help) use ($s, $name): void {
            echo '<tr><th scope="row"><label for="artex-' . esc_attr($field) . '">' . esc_html($label) . '</label></th><td>'
                . '<textarea class="large-text code" rows="3" id="artex-' . esc_attr($field) . '" name="' . esc_attr($name) . '[' . esc_attr($field) . ']">'
                . esc_textarea(implode("\n", (array) $s[$field])) . '</textarea><p class="description">' . esc_html($help) . '</p></td></tr>';
        };
        $area('trusted_proxies', __('Trusted proxies', 'artex-shield'), __('Your own proxies, load balancer or CDN, one CIDR per line. X-Forwarded-For is believed from these and nobody else.', 'artex-shield'));
        $area('allow_cidrs', __('Allowlist', 'artex-shield'), __('Addresses never scored (monitoring, partners), one CIDR per line.', 'artex-shield'));
        $area('exempt_paths', __('Exempt paths', 'artex-shield'), __('Paths never scored, with everything under them, one per line, such as /healthz.', 'artex-shield'));
        echo '<tr><th scope="row">' . esc_html__('State', 'artex-shield') . '</th><td><select name="' . esc_attr($name) . '[store]">';
        foreach (['auto' => __('Automatic: the object cache if it is persistent, else files', 'artex-shield'),
                     'files' => __('Files', 'artex-shield'), 'cache' => __('The object cache', 'artex-shield')] as $value => $label) {
            echo '<option value="' . esc_attr($value) . '"' . ($s['store'] === $value ? ' selected' : '') . '>' . esc_html($label) . '</option>';
        }
        echo '</select><p class="description">' . esc_html(sprintf(__('Scores and blocks are kept in %s.', 'artex-shield'), Plugin::storeName())) . '</p></td></tr>';
        echo '</table>';
        submit_button();
        echo '</form>';

        echo '<h2>' . esc_html__('Blocked now', 'artex-shield') . '</h2>';
        $blocks = Plugin::shield()->blocklist();
        if (!$blocks) {
            echo '<p>' . esc_html__('Nothing is blocked.', 'artex-shield') . '</p>';
        } else {
            echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Network', 'artex-shield') . '</th><th>'
                . esc_html__('Until', 'artex-shield') . '</th><th></th></tr></thead><tbody>';
            foreach ($blocks as $network => $until) {
                echo '<tr><td><code>' . esc_html($network) . '</code></td><td>' . esc_html(gmdate('Y-m-d H:i', (int) $until)) . ' UTC</td><td>'
                    . '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">'
                    . '<input type="hidden" name="action" value="artex_shield_unblock"><input type="hidden" name="network" value="' . esc_attr($network) . '">';
                wp_nonce_field('artex_shield_unblock');
                echo '<button class="button">' . esc_html__('Unblock', 'artex-shield') . '</button></form></td></tr>';
            }
            echo '</tbody></table>';
        }
        echo '<h2>' . esc_html__('Recent events', 'artex-shield') . '</h2>';
        $events = Plugin::events();
        if (!$events) {
            echo '<p>' . esc_html__('None yet. Events also go to the PHP error log, one JSON line each.', 'artex-shield') . '</p>';
        } else {
            echo '<table class="widefat striped"><thead><tr><th>' . esc_html__('Time', 'artex-shield') . '</th><th>'
                . esc_html__('Action', 'artex-shield') . '</th><th>' . esc_html__('Address', 'artex-shield') . '</th><th>'
                . esc_html__('Request', 'artex-shield') . '</th><th>' . esc_html__('Signals', 'artex-shield') . '</th><th>'
                . esc_html__('Reference', 'artex-shield') . '</th></tr></thead><tbody>';
            foreach (array_slice($events, 0, 25) as $e) {
                echo '<tr><td>' . esc_html($e['ts'] ?? '') . '</td><td>' . esc_html(($e['action'] ?? '') . (empty($e['enforced']) ? ' (monitor)' : ''))
                    . '</td><td><code>' . esc_html($e['ip'] ?? '') . '</code></td><td>' . esc_html(($e['method'] ?? '') . ' ' . ($e['path'] ?? ''))
                    . '</td><td>' . esc_html(implode(', ', (array) ($e['hits'] ?? []))) . '</td><td><code>' . esc_html($e['ref'] ?? '') . '</code></td></tr>';
            }
            echo '</tbody></table>';
        }
        echo '</div>';
    }
}
