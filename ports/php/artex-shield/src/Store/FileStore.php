<?php
declare(strict_types=1);

namespace ArtexShield\Store;

/**
 * State in files under one directory: one small file per key, written
 * atomically, with flock() on one of 64 lock files for the advisory locks.
 * Files are PHP that exits at once, so the web server cannot hand them out
 * even if the directory is reachable. prune() removes expired entries; the
 * WordPress plugin runs it hourly.
 */
final class FileStore implements Store
{
    private const GUARD = "<?php exit; ?>\n";
    private array $held = [];           // key -> stripe
    private array $stripes = [];        // stripe -> [handle, holders]

    public function __construct(private readonly string $dir)
    {
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException("cannot create $dir");
        }
        $deny = "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n  Deny from all\n</IfModule>\n";
        foreach (['index.php' => "<?php // Silence.\n", '.htaccess' => $deny] as $name => $text) {
            if (!file_exists("$dir/$name")) {
                @file_put_contents("$dir/$name", $text);
            }
        }
    }

    private function path(string $key): string
    {
        return $this->dir . '/' . md5($key) . '.php';
    }

    public function get(string $key): mixed
    {
        $text = @file_get_contents($this->path($key));
        if ($text === false || !str_starts_with($text, self::GUARD)) {
            return null;
        }
        $entry = json_decode(substr($text, strlen(self::GUARD)), true);
        if (!is_array($entry) || !array_key_exists('v', $entry)) {
            return null;
        }
        if ($entry['e'] !== 0 && $entry['e'] < time()) {
            @unlink($this->path($key));
            return null;
        }
        return $entry['v'];
    }

    public function set(string $key, mixed $value, int $ttl): void
    {
        $entry = ['e' => $ttl > 0 ? time() + $ttl : 0, 'v' => $value];
        $path = $this->path($key);
        $tmp = $path . '.' . getmypid() . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $json = json_encode($entry, JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
        if (@file_put_contents($tmp, self::GUARD . $json) === false || !@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot write $path");
        }
    }

    public function delete(string $key): void
    {
        @unlink($this->path($key));
    }

    public function lock(string $key): void
    {
        if (isset($this->held[$key])) {
            return;
        }
        // Keys share 64 lock files. flock() is per open file, so a second
        // lock on a stripe this process already holds would wait for itself:
        // count holders per stripe instead.
        $stripe = hexdec(substr(md5($key), 0, 2)) % 64;
        if (!isset($this->stripes[$stripe])) {
            $handle = @fopen($this->dir . "/lock-$stripe", 'c');
            if ($handle === false) {
                return;                               // no lock rather than no answer
            }
            flock($handle, LOCK_EX);
            $this->stripes[$stripe] = [$handle, 0];
        }
        $this->stripes[$stripe][1]++;
        $this->held[$key] = $stripe;
    }

    public function unlock(string $key): void
    {
        if (!isset($this->held[$key])) {
            return;
        }
        $stripe = $this->held[$key];
        unset($this->held[$key]);
        if (--$this->stripes[$stripe][1] === 0) {
            flock($this->stripes[$stripe][0], LOCK_UN);
            fclose($this->stripes[$stripe][0]);
            unset($this->stripes[$stripe]);
        }
    }

    /** Remove expired entries and stray temporary files. Returns how many went. */
    public function prune(): int
    {
        $gone = 0;
        foreach (glob($this->dir . '/*.php') ?: [] as $path) {
            if (basename($path) === 'index.php') {
                continue;
            }
            $head = @file_get_contents($path, false, null, 0, 64);
            if ($head !== false && preg_match('/"e":(\d+)/', $head, $m) && (int) $m[1] !== 0 && (int) $m[1] < time()) {
                $gone += (int) @unlink($path);
            }
        }
        foreach (glob($this->dir . '/*.tmp') ?: [] as $path) {
            if (@filemtime($path) < time() - 300) {
                $gone += (int) @unlink($path);
            }
        }
        return $gone;
    }
}
