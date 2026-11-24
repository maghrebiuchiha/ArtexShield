<?php
/** Paths, decoding and the "did a page make the browser send this" test, as util.py does them. */
declare(strict_types=1);

namespace ArtexShield;

final class Util
{
    /** Undo up to two layers of URL encoding (with + as a space). */
    public static function decode(string $text): string
    {
        for ($i = 0; $i < 2; $i++) {
            $next = Py::unquotePlus($text);
            if ($next === $text) {
                break;
            }
            $text = $next;
        }
        return $text;
    }

    /** The path as the shield compares it: percent-decoded, // collapsed, rooted. */
    public static function normPath(string $path): string
    {
        $p = Py::unquote($path === '' ? '/' : $path);
        $p = (string) preg_replace('~/{2,}~', '/', $p);
        return str_starts_with($p, '/') ? $p : '/' . $p;
    }

    /** Validate path prefixes and drop trailing slashes. */
    public static function prefixes(mixed $entries, string $field): array
    {
        if (is_string($entries)) {
            throw new \InvalidArgumentException("$field must be a list of paths, not one string");
        }
        $out = [];
        foreach ((array) $entries as $entry) {
            if (!is_string($entry) || !str_starts_with($entry, '/') || trim($entry, '/') === '') {
                throw new \InvalidArgumentException("$field: " . json_encode($entry) . " must start with '/' and name a path below it");
            }
            $out[] = rtrim((string) preg_replace('~/{2,}~', '/', $entry), '/');
        }
        return $out;
    }

    /** $path is one of $list or below one, by whole segments, never when it climbs with "..". */
    public static function under(string $path, array $list): bool
    {
        if (!$list) {
            return false;
        }
        $p = (string) preg_replace('~/{2,}~', '/', $path === '' ? '/' : $path);
        if (in_array('..', explode('/', str_replace('\\', '/', self::decode($p))), true)) {
            return false;
        }
        foreach ($list as $prefix) {
            if ($p === $prefix || str_starts_with($p, $prefix . '/')) {
                return true;
            }
        }
        return false;
    }

    /** Lower-case extension of the last path segment, without the dot. */
    public static function extension(string $path): string
    {
        $slash = strrpos($path, '/');
        $name = $slash === false ? $path : substr($path, $slash + 1);
        $dot = strrpos($name, '.');
        return $dot === false ? '' : Py::lower(substr($name, $dot + 1));
    }

    /** Did a web page, not the person, make the browser send this request? $h: lower-case names. */
    public static function induced(array $h): bool
    {
        $site = Py::lower(Py::strip($h['sec-fetch-site'] ?? ''));
        if ($site === 'cross-site' || $site === 'same-site') {
            return true;
        }
        if ($site === 'same-origin') {
            return !in_array(Py::lower(Py::strip($h['sec-fetch-dest'] ?? '')), ['', 'document', 'empty', 'websocket'], true);
        }
        if ($site !== '') {
            return false;
        }
        $referer = $h['referer'] ?? '';
        $host = Py::lower(Py::strip($h['host'] ?? ''));
        if ($referer === '' || $host === '') {
            return false;
        }
        try {
            $origin = Py::netloc(Py::strip($referer));
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        $at = strrpos($origin, '@');
        $origin = Py::lower($at === false ? $origin : substr($origin, $at + 1));
        return $origin !== '' && $origin !== $host;
    }

    /** UNION/**\/SELECT with comments turned into spaces; MySQL's /*!50000 ... *\/ keeps
     * its contents. Null when there is nothing to strip. */
    public static function stripSqlComments(string $text): ?string
    {
        if (strpos($text, '/*') === false) {
            return null;
        }
        $out = '';
        $i = 0;
        while (true) {
            $a = strpos($text, '/*', $i);
            if ($a === false) {
                $out .= substr($text, $i);
                break;
            }
            $out .= substr($text, $i, $a - $i) . ' ';
            $b = strpos($text, '*/', $a + 2);
            if ($b === false) {
                break;
            }
            if (substr($text, $a + 2, 1) === '!') {
                $out .= ltrim(substr($text, $a + 3, $b - $a - 3), '0123456789') . ' ';
            }
            $i = $b + 2;
        }
        return $out;
    }

    /** The decoded path, then each decoded query name and value, joined by NUL. */
    public static function urlText(string $path, string $query): string
    {
        $parts = [self::decode($path)];
        foreach (explode('&', $query) as $pair) {
            if ($pair === '') {
                continue;
            }
            $eq = strpos($pair, '=');
            $parts[] = self::decode($eq === false ? $pair : substr($pair, 0, $eq));
            $parts[] = self::decode($eq === false ? '' : substr($pair, $eq + 1));
        }
        return implode("\0", $parts);
    }
}
