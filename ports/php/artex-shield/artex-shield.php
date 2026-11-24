<?php
/**
 * Plugin Name:       ARTEX Shield
 * Description:       Detects and blocks ARTEX-style automated penetration-testing traffic before WordPress handles the request. Monitor mode by default.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * License:           MIT
 * Text Domain:       artex-shield
 */

defined('ABSPATH') || exit;

if (PHP_VERSION_ID < 80100) {
    return;                       // WordPress will not activate it there either; see "Requires PHP"
}

require_once __DIR__ . '/autoload.php';

ArtexShield\WordPress\Plugin::boot(__FILE__);
