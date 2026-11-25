<?php
/**
 * IP addresses and networks as Python's ipaddress module reads and writes
 * them: strict IPv4, IPv6 with "::", an IPv4 tail and an optional %scope,
 * RFC 5952 text. IPv6 is held as eight 16-bit groups.
 */
declare(strict_types=1);

namespace ArtexShield;

final class Ip
{
    /** ['version' => 4, 'v4' => int] or ['version' => 6, 'v6' => int[8], 'scope' => ?string], or null. */
    public static function parse(string $s): ?array
    {
        $v4 = self::parseV4($s);
        if ($v4 !== null) {
            return ['version' => 4, 'v4' => $v4];
        }
        return self::parseV6($s);
    }

    private static function parseV4(string $s): ?int
    {
        $parts = explode('.', $s);
        if (count($parts) !== 4) {
            return null;
        }
        $value = 0;
        foreach ($parts as $part) {
            if (!preg_match('/^[0-9]{1,3}$/', $part) || ($part !== '0' && $part[0] === '0')) {
                return null;
            }
            $n = (int) $part;
            if ($n > 255) {
                return null;
            }
            $value = ($value << 8) | $n;
        }
        return $value;
    }

    private static function parseV6(string $s): ?array
    {
        $addr = $s;
        $scope = null;
        $pct = strpos($s, '%');
        if ($pct !== false) {
            $addr = substr($s, 0, $pct);
            $scope = substr($s, $pct + 1);
            if ($scope === '' || strpos($scope, '%') !== false) {
                return null;
            }
        }
        if ($addr === '') {
            return null;
        }
        $parts = explode(':', $addr);
        if (count($parts) < 3) {
            return null;
        }
        $last = $parts[count($parts) - 1];
        if (strpos($last, '.') !== false) {
            $v4 = self::parseV4(array_pop($parts));
            if ($v4 === null) {
                return null;
            }
            $parts[] = dechex(($v4 >> 16) & 0xFFFF);
            $parts[] = dechex($v4 & 0xFFFF);
        }
        $count = count($parts);
        if ($count > 9) {
            return null;
        }
        $skip = null;
        for ($i = 1; $i < $count - 1; $i++) {
            if ($parts[$i] === '') {
                if ($skip !== null) {
                    return null;
                }
                $skip = $i;
            }
        }
        if ($skip !== null) {
            $hi = $skip;
            $lo = $count - $skip - 1;
            if ($parts[0] === '') {
                if (--$hi) {
                    return null;
                }
            }
            if ($parts[$count - 1] === '') {
                if (--$lo) {
                    return null;
                }
            }
            $skipped = 8 - ($hi + $lo);
            if ($skipped < 1) {
                return null;
            }
        } else {
            if ($count !== 8 || $parts[0] === '' || $parts[$count - 1] === '') {
                return null;
            }
            $hi = $count;
            $lo = 0;
            $skipped = 0;
        }
        $groups = [];
        for ($i = 0; $i < $hi; $i++) {
            if (!preg_match('/^[0-9A-Fa-f]{1,4}$/', $parts[$i])) {
                return null;
            }
            $groups[] = hexdec($parts[$i]);
        }
        for ($i = 0; $i < $skipped; $i++) {
            $groups[] = 0;
        }
        for ($i = $count - $lo; $i < $count; $i++) {
            if (!preg_match('/^[0-9A-Fa-f]{1,4}$/', $parts[$i])) {
                return null;
            }
            $groups[] = hexdec($parts[$i]);
        }
        return ['version' => 6, 'v6' => array_map('intval', $groups), 'scope' => $scope];
    }

    /** The IPv4 address inside ::ffff:a.b.c.d, or the address itself. */
    private static function unmapped(array $a): array
    {
        if ($a['version'] === 6) {
            $g = $a['v6'];
            if ($g[0] === 0 && $g[1] === 0 && $g[2] === 0 && $g[3] === 0 && $g[4] === 0 && $g[5] === 0xFFFF) {
                return ['version' => 4, 'v4' => ($g[6] << 16) | $g[7]];
            }
        }
        return $a;
    }

    private static function formatV4(int $v): string
    {
        return implode('.', [($v >> 24) & 255, ($v >> 16) & 255, ($v >> 8) & 255, $v & 255]);
    }

    private static function formatV6(array $groups): string
    {
        $hex = array_map(static fn (int $g): string => dechex($g), $groups);
        $bestStart = -1;
        $bestLen = 0;
        $start = -1;
        $len = 0;
        foreach ($hex as $i => $h) {
            if ($h === '0') {
                $len++;
                if ($start === -1) {
                    $start = $i;
                }
                if ($len > $bestLen) {
                    $bestLen = $len;
                    $bestStart = $start;
                }
            } else {
                $len = 0;
                $start = -1;
            }
        }
        if ($bestLen > 1) {
            $end = $bestStart + $bestLen;
            if ($end === count($hex)) {
                $hex[] = '';
            }
            array_splice($hex, $bestStart, $bestLen, ['']);
            if ($bestStart === 0) {
                array_unshift($hex, '');
            }
        }
        return implode(':', $hex);
    }

    /** Address bits under a prefix: IPv4 as int, IPv6 as groups. */
    private static function masked(array $a, int $prefix): array
    {
        if ($a['version'] === 4) {
            $mask = $prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF);
            return ['version' => 4, 'v4' => $a['v4'] & $mask, 'prefix' => $prefix];
        }
        $groups = [];
        foreach ($a['v6'] as $i => $g) {
            $bits = max(0, min(16, $prefix - 16 * $i));
            $groups[] = $bits === 0 ? 0 : ($g & ((0xFFFF << (16 - $bits)) & 0xFFFF));
        }
        return ['version' => 6, 'v6' => $groups, 'prefix' => $prefix];
    }

    /** ip_network(text, strict=False). Throws on nonsense. */
    public static function network(string $text): array
    {
        $pieces = explode('/', $text);
        if (count($pieces) > 2) {
            throw new \InvalidArgumentException("not a network: $text");
        }
        $a = self::parse($pieces[0]);
        if ($a === null) {
            throw new \InvalidArgumentException("not a network: $text");
        }
        $max = $a['version'] === 4 ? 32 : 128;
        $prefix = $max;
        if (count($pieces) === 2) {
            $arg = $pieces[1];
            if (preg_match('/^[0-9]+$/', $arg) && (int) $arg <= $max) {
                $prefix = (int) $arg;
            } elseif ($a['version'] === 4 && ($m = self::parseV4($arg)) !== null) {
                $prefix = -1;
                foreach ([$m, $m ^ 0xFFFFFFFF] as $candidate) {
                    for ($p = 0; $p <= 32 && $prefix < 0; $p++) {
                        if (self::masked(['version' => 4, 'v4' => 0xFFFFFFFF], $p)['v4'] === $candidate) {
                            $prefix = $p;
                        }
                    }
                }
                if ($prefix < 0) {
                    throw new \InvalidArgumentException("bad netmask in $text");
                }
            } else {
                throw new \InvalidArgumentException("bad prefix in $text");
            }
        }
        return self::masked($a, $prefix);
    }

    public static function formatNetwork(array $n): string
    {
        return ($n['version'] === 4 ? self::formatV4($n['v4']) : self::formatV6($n['v6'])) . '/' . $n['prefix'];
    }

    /** Is $ip inside any of $nets (from network())? IPv4-mapped IPv6 counts as IPv4. */
    public static function inNets(string $ip, array $nets): bool
    {
        if (!$nets) {
            return false;
        }
        $parsed = self::parse($ip);
        if ($parsed === null) {
            return false;
        }
        $a = self::unmapped($parsed);
        foreach ($nets as $n) {
            if ($n['version'] === $a['version'] && self::masked($a, $n['prefix']) == $n) {
                return true;
            }
        }
        return false;
    }

    /** An address that can stand for one client: parseable and not unspecified. */
    public static function usable(string $ip): bool
    {
        $parsed = self::parse($ip);
        if ($parsed === null) {
            return false;
        }
        $a = self::unmapped($parsed);
        return $a['version'] === 4 ? $a['v4'] !== 0 : array_sum($a['v6']) !== 0;
    }

    /** One score per client: an IPv4 address, or an IPv6 /64. */
    public static function trackKey(string $ip): string
    {
        $parsed = self::parse($ip);
        if ($parsed === null) {
            return 'invalid';
        }
        $a = self::unmapped($parsed);
        if ($a['version'] === 4) {
            return self::formatV4($a['v4']);
        }
        return self::formatNetwork(self::masked($a, 64));
    }

    /** /64 -> /56 -> /48 for IPv6 block keys; null otherwise. */
    public static function wider(string $key): ?string
    {
        if (strpos($key, ':') === false) {
            return null;
        }
        $n = self::network($key);
        $step = [64 => 56, 56 => 48][$n['prefix']] ?? null;
        if ($step === null) {
            return null;
        }
        return self::formatNetwork(self::masked($n, $step));
    }

    /** The address in one X-Forwarded-For entry, or null. Ports are dropped. */
    public static function hopIp(string $hop): ?string
    {
        $h = trim(Py::strip($hop), '"');
        if (str_starts_with($h, '[')) {
            $end = strpos($h, ']');
            if ($end !== false && $end > 0) {
                $h = substr($h, 1, $end - 1);
            }
        } elseif (substr_count($h, ':') === 1) {
            $h = explode(':', $h)[0];
        }
        return self::parse($h) === null ? null : $h;
    }
}
