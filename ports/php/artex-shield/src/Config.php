<?php
/**
 * Settings, with the defaults and checks of the Python reference's Config,
 * under the same snake_case names. See spec/SPEC.md for what each means.
 */
declare(strict_types=1);

namespace ArtexShield;

final class Config
{
    public const DEFAULTS = [
        'mode' => 'monitor',
        'throttle_score' => 50.0,
        'block_score' => 100.0,
        'half_life' => 600.0,
        'block_ttl' => 3600.0,
        'max_block_ttl' => 86400.0,
        'retry_after' => 120,
        'ignored_throttle_points' => 5.0,
        'trusted_proxies' => [],
        'allow_cidrs' => [],
        'exempt_paths' => [],
        'engagements' => [],
        'canary_paths' => [],
        'enum_404_threshold' => 15,
        'enum_window' => 60.0,
        'rate_limit' => 240,
        'rate_window' => 60.0,
        'cadence_samples' => 30,
        'cadence_min_mean' => 0.15,
        'cadence_max_mean' => 2.0,
        'cadence_max_cv' => 0.35,
        'tls_header' => null,
        'tls_denylist' => [],
        'max_tracks' => 50000,
        'soft_cap' => null,
        'enum_ignore_prefixes' => [],
        'enum_ignore_extensions' => ['js', 'mjs', 'css', 'map', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'avif', 'ico',
            'woff', 'woff2', 'ttf', 'otf', 'eot', 'mp3', 'mp4', 'webm'],
        'score_induced' => false,
        'max_blocks' => 100000,
        'v6_escalate_after' => 0,
        'slow_enum_budget' => 60,
        'slow_enum_window' => 3600.0,
        'slow_enum_points' => 10.0,
        'client_check' => false,
        'client_check_secret' => null,
        'client_check_path' => '/_artex/check',
        'client_check_cookie' => 'artex_check',
        'client_check_api_prefixes' => ['/api'],
        'client_check_grace' => 30.0,
        'client_check_ttl' => 86400.0,
        'client_check_points' => 20.0,
        'honeytokens' => [],
        'honeytoken_body_limit' => 65536,
        // Wiring, not behaviour: called with each event array.
        'on_event' => null,
    ];

    private const FLOATS = ['throttle_score', 'block_score', 'half_life', 'block_ttl', 'max_block_ttl', 'ignored_throttle_points',
        'enum_window', 'rate_window', 'cadence_min_mean', 'cadence_max_mean', 'cadence_max_cv', 'slow_enum_window',
        'slow_enum_points', 'client_check_grace', 'client_check_ttl', 'client_check_points'];
    private const INTS = ['retry_after', 'enum_404_threshold', 'rate_limit', 'cadence_samples', 'max_tracks', 'max_blocks',
        'v6_escalate_after', 'slow_enum_budget', 'honeytoken_body_limit'];

    /** A complete, checked config. Throws \InvalidArgumentException on anything the reference refuses. */
    public static function make(array $options = []): array
    {
        $unknown = array_diff(array_keys($options), array_keys(self::DEFAULTS));
        if ($unknown) {
            throw new \InvalidArgumentException('unknown settings: ' . implode(', ', $unknown));
        }
        $c = array_merge(self::DEFAULTS, $options);
        foreach (self::FLOATS as $k) {
            if (!is_int($c[$k]) && !is_float($c[$k])) {
                throw new \InvalidArgumentException("$k must be a number");
            }
            $c[$k] = (float) $c[$k];
        }
        foreach (self::INTS as $k) {
            if (!is_int($c[$k]) && !(is_float($c[$k]) && floor($c[$k]) === $c[$k])) {
                throw new \InvalidArgumentException("$k must be a whole number");
            }
            $c[$k] = (int) $c[$k];
        }
        if ($c['mode'] !== 'monitor' && $c['mode'] !== 'enforce') {
            throw new \InvalidArgumentException("mode must be 'monitor' or 'enforce'");
        }
        foreach (['rate_limit' => 1, 'cadence_samples' => 2, 'enum_404_threshold' => 1, 'max_tracks' => 1, 'max_blocks' => 1,
                     'v6_escalate_after' => 0, 'slow_enum_budget' => 0] as $name => $least) {
            if ($c[$name] < $least) {
                throw new \InvalidArgumentException("$name must be at least $least");
            }
        }
        if ($c['v6_escalate_after'] === 1) {
            throw new \InvalidArgumentException('v6_escalate_after must be 0 (off) or at least 2');
        }
        foreach (['half_life', 'rate_window', 'enum_window', 'slow_enum_window', 'block_ttl'] as $name) {
            if (!($c[$name] > 0)) {
                throw new \InvalidArgumentException("$name must be positive");
            }
        }
        $c['exempt_paths'] = Util::prefixes($c['exempt_paths'], 'exempt_paths');
        $c['enum_ignore_prefixes'] = Util::prefixes($c['enum_ignore_prefixes'], 'enum_ignore_prefixes');
        if (is_string($c['honeytokens'])) {
            throw new \InvalidArgumentException('honeytokens must be a list of values, not one string');
        }
        if (isset($c['honeytokens']['api_keys'])) {
            $c['honeytokens'] = Decoys::watched($c['honeytokens']);   // straight from Decoys::honeytokens()
        }
        $c['honeytokens'] = array_values(array_unique(array_map('strval', (array) $c['honeytokens'])));
        foreach ($c['honeytokens'] as $token) {
            if (Py::length($token) < 12 || Py::hasSpace($token)) {
                throw new \InvalidArgumentException('honeytoken ' . Py::slice($token, 4) . '... must be at least 12 characters '
                    . 'with no whitespace: anything shorter could turn up in ordinary requests');
            }
        }
        if ($c['honeytoken_body_limit'] < 0) {
            throw new \InvalidArgumentException('honeytoken_body_limit must not be negative');
        }
        $c['client_check_api_prefixes'] = Util::prefixes($c['client_check_api_prefixes'], 'client_check_api_prefixes');
        Util::prefixes([$c['client_check_path']], 'client_check_path');
        if (!is_string($c['client_check_cookie']) || !preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $c['client_check_cookie'])) {
            throw new \InvalidArgumentException('client_check_cookie must be 1 to 64 letters, digits, - or _');
        }
        foreach (['client_check_ttl', 'client_check_points'] as $name) {
            if (!($c[$name] > 0)) {
                throw new \InvalidArgumentException("$name must be positive");
            }
        }
        if ($c['client_check_grace'] < 0) {
            throw new \InvalidArgumentException('client_check_grace must not be negative');
        }
        if (!($c['throttle_score'] > 0 && $c['throttle_score'] <= $c['block_score'])) {
            throw new \InvalidArgumentException('need 0 < throttle_score <= block_score');
        }
        $c['soft_cap'] = $c['soft_cap'] === null ? 0.8 * $c['throttle_score'] : (float) $c['soft_cap'];
        if (!($c['soft_cap'] >= 0 && $c['soft_cap'] < $c['throttle_score'])) {
            throw new \InvalidArgumentException('need 0 <= soft_cap < throttle_score');
        }
        foreach (['trusted_proxies', 'allow_cidrs', 'canary_paths', 'tls_denylist', 'enum_ignore_extensions'] as $name) {
            if (is_string($c[$name])) {
                throw new \InvalidArgumentException("$name must be a list, not one string");
            }
            $c[$name] = array_values((array) $c[$name]);
        }
        $c['engagements'] = array_map(static function ($e): array {
            if (!is_array($e) || !isset($e['reference'], $e['cidrs'], $e['start'], $e['end'])) {
                throw new \InvalidArgumentException('an engagement needs reference, cidrs, start and end');
            }
            return ['reference' => (string) $e['reference'], 'cidrs' => array_values((array) $e['cidrs']),
                'start' => self::seconds($e['start']), 'end' => self::seconds($e['end'])];
        }, array_values((array) $c['engagements']));
        return $c;
    }

    /** Unix seconds from a number, a DateTimeInterface, or an ISO time with a timezone. */
    private static function seconds(mixed $v): float
    {
        if (is_int($v) || is_float($v)) {
            return (float) $v;
        }
        if ($v instanceof \DateTimeInterface) {
            return (float) $v->format('U.u');
        }
        if (is_string($v) && preg_match('/(?:Z|[+-]\d\d:?\d\d)$/i', trim($v))) {
            $t = strtotime($v);
            if ($t !== false) {
                return (float) $t;
            }
        }
        throw new \InvalidArgumentException('engagement times must be Unix seconds, a DateTime, or an ISO time with a timezone');
    }
}
