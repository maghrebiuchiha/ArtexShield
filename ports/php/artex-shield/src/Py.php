<?php
/**
 * What the Python reference does with text, done the same way in PHP: its
 * whitespace, case mapping and code-point slicing, URL decoding, urlsplit's
 * netloc, base64 decoding and math.fsum. Every string here is UTF-8; the
 * WordPress adapter turns raw header bytes into UTF-8 first (as Latin-1,
 * the way Python's servers read them).
 */
declare(strict_types=1);

namespace ArtexShield;

final class Py
{
    /** Python's \s for str patterns, as a PCRE class body (UTF mode). */
    public const SPACE = '\t\n\x{0b}\f\r\x{1c}-\x{1f} \x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}';
    /** Python's \w for str patterns. */
    public const WORD = '\p{L}\p{N}_';

    /** str.strip() with no argument. */
    public static function strip(string $s): string
    {
        return (string) preg_replace('~^[' . self::SPACE . ']+|[' . self::SPACE . ']+$~u', '', $s);
    }

    /** Is any character of $s whitespace (str.isspace)? */
    public static function hasSpace(string $s): bool
    {
        return preg_match('~[' . self::SPACE . ']~u', $s) === 1;
    }

    /** len(s) in code points. */
    public static function length(string $s): int
    {
        return function_exists('mb_strlen') ? mb_strlen($s, 'UTF-8') : preg_match_all('~.~su', $s);
    }

    /** s[:n] by code point. */
    public static function slice(string $s, int $n): string
    {
        if (strlen($s) <= $n) {
            return $s;                       // n bytes hold at most n code points
        }
        if (function_exists('mb_substr')) {
            return mb_substr($s, 0, $n, 'UTF-8');
        }
        preg_match('~^.{0,' . $n . '}~su', $s, $m);
        return $m[0];
    }

    /** str.lower() / str.upper(): full Unicode case mapping. */
    public static function lower(string $s): string
    {
        return function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
    }

    public static function upper(string $s): string
    {
        return function_exists('mb_strtoupper') ? mb_strtoupper($s, 'UTF-8') : strtoupper($s);
    }

    /** Bytes read as Latin-1 (one character per byte), as UTF-8. */
    public static function latin1(string $bytes): string
    {
        if (!preg_match('/[\x80-\xff]/', $bytes)) {
            return $bytes;
        }
        return (string) preg_replace_callback('/[\x80-\xff]/', static function (array $m): string {
            $b = ord($m[0]);
            return chr(0xC0 | ($b >> 6)) . chr(0x80 | ($b & 0x3F));
        }, $bytes);
    }

    /** Bytes decoded as UTF-8 with U+FFFD for each maximal invalid subpart, as
     * Python's bytes.decode("utf-8", "replace") does. */
    public static function utf8(string $bytes): string
    {
        if (preg_match('//u', $bytes)) {
            return $bytes;                   // already valid
        }
        $out = '';
        $n = strlen($bytes);
        $i = 0;
        while ($i < $n) {
            $b = ord($bytes[$i]);
            if ($b < 0x80) {
                $out .= $bytes[$i++];
                continue;
            }
            if ($b >= 0xC2 && $b <= 0xDF) {
                $need = 1; $lo = 0x80; $hi = 0xBF;
            } elseif ($b === 0xE0) {
                $need = 2; $lo = 0xA0; $hi = 0xBF;
            } elseif (($b >= 0xE1 && $b <= 0xEC) || $b === 0xEE || $b === 0xEF) {
                $need = 2; $lo = 0x80; $hi = 0xBF;
            } elseif ($b === 0xED) {
                $need = 2; $lo = 0x80; $hi = 0x9F;
            } elseif ($b === 0xF0) {
                $need = 3; $lo = 0x90; $hi = 0xBF;
            } elseif ($b >= 0xF1 && $b <= 0xF3) {
                $need = 3; $lo = 0x80; $hi = 0xBF;
            } elseif ($b === 0xF4) {
                $need = 3; $lo = 0x80; $hi = 0x8F;
            } else {
                $out .= "\u{FFFD}";
                $i++;
                continue;
            }
            $k = 1;
            while ($k <= $need && $i + $k < $n) {
                $c = ord($bytes[$i + $k]);
                if ($c < ($k === 1 ? $lo : 0x80) || $c > ($k === 1 ? $hi : 0xBF)) {
                    break;
                }
                $k++;
            }
            if ($k === $need + 1) {
                $out .= substr($bytes, $i, $k);
            } else {
                $out .= "\u{FFFD}";
            }
            $i += $k;
        }
        return $out;
    }

    /** urllib.parse.unquote(s): %XX runs inside each stretch of ASCII text are
     * bytes decoded as UTF-8 (with replacement); other text is kept. */
    public static function unquote(string $s): string
    {
        if (strpos($s, '%') === false) {
            return $s;
        }
        return (string) preg_replace_callback('/[\x00-\x7f]+/', static function (array $m): string {
            $run = $m[0];
            if (strpos($run, '%') === false) {
                return $run;
            }
            $bytes = (string) preg_replace_callback('/%([0-9A-Fa-f]{2})/', static fn (array $h): string => chr(hexdec($h[1])), $run);
            return self::utf8($bytes);
        }, $s);
    }

    /** urllib.parse.unquote_plus(s). */
    public static function unquotePlus(string $s): string
    {
        return self::unquote(str_replace('+', ' ', $s));
    }

    /** urllib.parse.urlsplit(url).netloc; throws where urlsplit raises. */
    public static function netloc(string $url): string
    {
        $url = (string) preg_replace('/^[\x00-\x20]+/', '', $url);
        $url = str_replace(["\t", "\r", "\n"], '', $url);
        $i = strpos($url, ':');
        if ($i !== false && $i > 0 && preg_match('/^[A-Za-z]/', $url) && preg_match('/^[A-Za-z0-9+\-.]+$/', substr($url, 0, $i))) {
            $url = substr($url, $i + 1);
        }
        if (substr($url, 0, 2) !== '//') {
            return '';
        }
        $end = strlen($url);
        foreach (['/', '?', '#'] as $c) {
            $at = strpos($url, $c, 2);
            if ($at !== false) {
                $end = min($end, $at);
            }
        }
        $net = substr($url, 2, $end - 2);
        $open = strpos($net, '[') !== false;
        $close = strpos($net, ']') !== false;
        if ($open !== $close) {
            throw new \InvalidArgumentException('Invalid IPv6 URL');
        }
        if ($open) {
            $after = substr($net, strpos($net, '[') + 1);
            $cut = strpos($after, ']');
            self::checkBracketedHost($cut === false ? $after : substr($after, 0, $cut));
        }
        self::checkNetloc($net);
        return $net;
    }

    private static function checkBracketedHost(string $host): void
    {
        if (str_starts_with($host, 'v')) {
            if (!preg_match('/\Av[a-fA-F0-9]+\..+\z/u', $host)) {
                throw new \InvalidArgumentException('IPvFuture address is invalid');
            }
            return;
        }
        $ip = Ip::parse($host);
        if ($ip === null) {
            throw new \InvalidArgumentException('not an IP address');
        }
        if ($ip['version'] === 4) {
            throw new \InvalidArgumentException('An IPv4 address cannot be in brackets');
        }
    }

    private static function checkNetloc(string $net): void
    {
        if ($net === '' || !preg_match('/[\x80-\xff]/', $net) || !class_exists('Normalizer')) {
            return;
        }
        $n = str_replace(['@', ':', '#', '?'], '', $net);
        $normal = \Normalizer::normalize($n, \Normalizer::FORM_KC);
        if ($normal === false || $normal === $n) {
            return;
        }
        foreach (['/', '?', '#', '@', ':'] as $c) {
            if (strpos($normal, $c) !== false) {
                throw new \InvalidArgumentException('netloc contains invalid characters under NFKC normalization');
            }
        }
    }

    /** base64.b64decode(s) as binascii does it without validation. Throws on
     * an impossible length or missing padding. */
    public static function b64decode(string $s): string
    {
        static $table = null;
        if ($table === null) {
            $table = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'));
        }
        $out = '';
        $quad = 0;
        $left = 0;
        $pads = 0;
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $ch = $s[$i];
            if ($ch === '=') {
                if ($quad >= 2 && $quad + ++$pads >= 4) {
                    return $out;
                }
                continue;
            }
            if (!isset($table[$ch])) {
                continue;
            }
            $v = $table[$ch];
            $pads = 0;
            if ($quad === 0) {
                $quad = 1; $left = $v;
            } elseif ($quad === 1) {
                $quad = 2; $out .= chr((($left << 2) | ($v >> 4)) & 0xFF); $left = $v & 0x0F;
            } elseif ($quad === 2) {
                $quad = 3; $out .= chr((($left << 4) | ($v >> 2)) & 0xFF); $left = $v & 0x03;
            } else {
                $quad = 0; $out .= chr((($left << 6) | $v) & 0xFF); $left = 0;
            }
        }
        if ($quad !== 0) {
            throw new \InvalidArgumentException($quad === 1 ? 'invalid base64 length' : 'Incorrect padding');
        }
        return $out;
    }

    /** The correctly rounded sum of finite floats, as math.fsum. */
    public static function fsum(array $xs): float
    {
        $p = [];
        foreach ($xs as $x) {
            $x = (float) $x;
            $i = 0;
            $count = count($p);
            for ($j = 0; $j < $count; $j++) {
                $y = $p[$j];
                if (abs($x) < abs($y)) {
                    [$x, $y] = [$y, $x];
                }
                $hi = $x + $y;
                $lo = $y - ($hi - $x);
                if ($lo != 0.0) {
                    $p[$i++] = $lo;
                }
                $x = $hi;
            }
            $p = array_slice($p, 0, $i);
            if ($x != 0.0) {
                $p[] = $x;
            }
        }
        $n = count($p);
        $hi = 0.0;
        $lo = 0.0;
        if ($n > 0) {
            $hi = $p[--$n];
            while ($n > 0) {
                $x = $hi;
                $y = $p[--$n];
                $hi = $x + $y;
                $lo = $y - ($hi - $x);
                if ($lo != 0.0) {
                    break;
                }
            }
            if ($n > 0 && (($lo < 0.0 && $p[$n - 1] < 0.0) || ($lo > 0.0 && $p[$n - 1] > 0.0))) {
                $y = $lo * 2.0;
                $x = $hi + $y;
                if ($y == $x - $hi) {
                    $hi = $x;
                }
            }
        }
        return $hi;
    }

    /** json.dumps(str) as Python writes it (ensure_ascii). */
    public static function jsonString(string $s): string
    {
        $out = json_encode($s, JSON_UNESCAPED_SLASHES);
        return str_replace("\x7f", '\u007f', (string) $out);
    }

    /** str.isdigit() for ASCII digits; other scripts' digits count as not digits. */
    public static function isDigits(string $s): bool
    {
        return preg_match('/\A[0-9]+\z/', $s) === 1;
    }
}
