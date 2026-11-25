<?php
/** Canary paths and credential honeytokens, derived from a secret exactly as the Python reference does. */
declare(strict_types=1);

namespace ArtexShield;

final class Decoys
{
    private const SHAPES = ['/api/v1/internal/audit-{}', '/admin/legacy-{}/export', '/api/v2/debug/session-{}',
        '/backend/ops-{}/config', '/api/v1/staff/reports-{}'];
    private const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    private const USERS = ['svc-deploy', 'admin-legacy', 'ops-backup', 'staging-admin'];

    /** Stable, unguessable decoy paths derived from a secret. */
    public static function canaries(string $secret, int $count = 3): array
    {
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $tag = substr(hash_hmac('sha256', "canary-$i", $secret), 0, 10);
            $out[] = str_replace('{}', $tag, self::SHAPES[$i % count(self::SHAPES)]);
        }
        return $out;
    }

    /** Disallow lines for robots.txt. */
    public static function robotsTxtBlock(array $canaries): string
    {
        return "User-agent: *\n" . implode('', array_map(static fn (string $p): string => "Disallow: $p\n", $canaries));
    }

    /** A link no person can see or reach by keyboard. */
    public static function htmlTrap(string $canary): string
    {
        return '<a href="' . $canary . '" rel="nofollow" tabindex="-1" aria-hidden="true" style="position:absolute;left:-9999px">.</a>';
    }

    /** A dead constant for a JS bundle. */
    public static function jsTrap(string $canary, string $name = '__legacyApi'): string
    {
        return "var $name = \"$canary\";";
    }

    /** The bytes as a big-endian number, written as $length base-62 digits, least significant first. */
    private static function base62(string $bytes, int $length): string
    {
        $digits = array_values(unpack('C*', $bytes));
        $out = '';
        for ($k = 0; $k < $length; $k++) {
            $rem = 0;
            foreach ($digits as $i => $d) {                 // long division by 62
                $cur = ($rem << 8) | $d;
                $digits[$i] = intdiv($cur, 62);
                $rem = $cur % 62;
            }
            $out .= self::BASE62[$rem];
        }
        return $out;
    }

    /** Fake credentials from a secret: ['api_keys' => [], 'users' => [], 'passwords' => []]. */
    public static function honeytokens(string $secret, int $count = 2): array
    {
        if ($count < 1) {
            throw new \InvalidArgumentException('count must be at least 1');
        }
        $keys = $passwords = $users = [];
        for ($i = 0; $i < $count; $i++) {
            $keys[] = 'api_live_' . self::base62(hash_hmac('sha256', "honeytoken-key-$i", $secret, true), 32);
            $d = hash_hmac('sha256', "honeytoken-password-$i", $secret, true);
            $body = self::base62($d, 14);
            $at = ord($d[1]) % 14;
            $passwords[] = substr($body, 0, $at) . '!@#$*'[ord($d[0]) % 5] . substr($body, $at) . (ord($d[2]) % 10);
            $users[] = self::USERS[$i % count(self::USERS)];
        }
        return ['api_keys' => $keys, 'users' => $users, 'passwords' => $passwords];
    }

    /** The values the shield watches for: the API keys, then the passwords. */
    public static function watched(array $tokens): array
    {
        return array_merge($tokens['api_keys'], $tokens['passwords']);
    }

    /** A dead config object for a JS bundle, with a key and a login. */
    public static function honeytokenJs(array $tokens, int $index = 0, string $name = '__stagingConfig'): string
    {
        $i = $index % count($tokens['api_keys']);
        $fields = ['apiBase' => '/api/v1', 'apiKey' => $tokens['api_keys'][$i], 'adminUser' => $tokens['users'][$i],
            'adminPassword' => $tokens['passwords'][$i]];
        $pairs = [];
        foreach ($fields as $k => $v) {
            $pairs[] = Py::jsonString($k) . ': ' . Py::jsonString($v);
        }
        return "var $name = {" . implode(', ', $pairs) . '};';
    }

    /** An HTML comment with credentials someone meant to remove. */
    public static function honeytokenHtml(array $tokens, int $index = 1): string
    {
        $i = $index % count($tokens['api_keys']);
        return "<!-- TODO(ops): remove before release. Staging admin login {$tokens['users'][$i]} / {$tokens['passwords'][$i]} "
            . "; reporting API key {$tokens['api_keys'][$i]} -->";
    }
}
