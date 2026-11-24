<?php
/** Removes the plugin's settings, its scheduled pruning and its stored state. */

defined('WP_UNINSTALL_PLUGIN') || exit;

require_once __DIR__ . '/autoload.php';

wp_clear_scheduled_hook('artex_shield_prune');
$dir = ArtexShield\WordPress\Plugin::dataDir();
delete_option(ArtexShield\WordPress\Plugin::OPTION);
if (is_dir($dir)) {
    foreach (scandir($dir) ?: [] as $name) {
        if (is_file("$dir/$name")) {
            @unlink("$dir/$name");
        }
    }
    @rmdir($dir);
}
