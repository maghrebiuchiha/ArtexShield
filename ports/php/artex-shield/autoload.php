<?php
/** Loads ArtexShield\* classes from src/. No Composer needed. */
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'ArtexShield\\')) {
        $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen('ArtexShield\\'))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});
