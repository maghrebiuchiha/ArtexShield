<?php
/**
 * For tests/prepend.php: a server that sends every path to the front
 * controller, as nginx's `try_files $uri $uri/ /index.php` or Apache's
 * rewrite to index.php does, with examples/prepend.php first. (PHP's built-in
 * server applies auto_prepend_file only to files under its document root,
 * and answers a missing path with an extension itself.)
 */
require dirname(__DIR__, 2) . '/examples/prepend.php';
require __DIR__ . '/index.php';
