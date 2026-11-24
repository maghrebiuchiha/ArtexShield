<?php
/**
 * The shield reads attacker-controlled text on every request, so no input may
 * make that slow: the same budgets and hostile inputs as the Python
 * reference's Cost tests, for PCRE's own way of backtracking.
 */
declare(strict_types=1);

use ArtexShield\Shield;
use ArtexShield\Signatures;

require __DIR__ . '/../artex-shield/autoload.php';
require __DIR__ . '/check.php';

const BUDGET = 0.25;
const BROWSER = ['User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36',
    'Accept' => 'text/html', 'Accept-Language' => 'en-US'];

function timed(callable $fn): float
{
    $best = INF;
    for ($i = 0; $i < 2 && $best >= BUDGET; $i++) {          // best of two: ignore a scheduling hiccup
        $t0 = hrtime(true);
        $fn();
        $best = min($best, (hrtime(true) - $t0) / 1e9);
    }
    return $best;
}

check('every pattern scans in linear time, and none fails', function () {
    $sig = Signatures::get();
    $patterns = [];
    foreach ($sig['hard_ua'] as [$rx, , $label]) {
        $patterns["HARD_UA $label"] = $rx;
    }
    foreach ($sig['soft_ua'] as [$rx, , $label]) {
        $patterns["SOFT_UA $label"] = $rx;
    }
    foreach (array_merge($sig['payloads'], $sig['oob']) as [$rx, $label]) {
        $patterns[$label] = $rx;
    }
    foreach (['assessment_ua', 'browser_ua', 'crawler_ua', 'sensitive_paths', 'missing_sensitive', 'recon_paths'] as $name) {
        $patterns[$name] = $sig[$name];
    }
    truthy(count($patterns) >= 26, 'patterns');
    $atoms = ['a', 'db', 'a-', 'a.', '/', ' ', "\n", "\r\n ", '; ', ";\n", '/*', '/* a ', '*/', "' or ", '{{ ', ' on',
        ' onmouse', '#{1', '${T', '../', '..\\', 'javascript:', 'javascript: ', '<script>', '<script ',
        "' and '1", "' or 1 ", 'union select ', '1 union select ', 'sleep(', '<iframe ', '<x onclick=',
        '1', 'mozilla/5.0 ', 'ARTEX-Assessment/1 ', 'union ', 'union all ',
        "' ", "' or ", 'sleep ( ', '; ', '| cat ', '{{1 ', '${ ', '<%= 1', 'on', 'onload ', '<svg',
        'backup.', '/wp-config.php.a', '/swagger/', '/admin/', 'x.oast', '-.', 'curl/', 'é', 'ı', "\u{2028}"];
    $slow = [];
    foreach ($patterns as $name => $rx) {
        foreach ($atoms as $atom) {
            $text = str_repeat($atom, intdiv(30000, strlen($atom)));
            foreach ([$text, '/' . $text . '!'] as $subject) {
                $took = timed(static fn () => Signatures::search($rx, $subject));
                $python = preg_match($rx, $subject);
                if ($python === false && preg_last_error() !== PREG_JIT_STACKLIMIT_ERROR) {
                    $slow[] = "$name on " . json_encode($atom) . ': ' . preg_last_error_msg();
                } elseif ($took >= BUDGET) {
                    $slow[] = sprintf('%s on %s: %.2f s', $name, json_encode($atom), $took);
                }
            }
        }
    }
    same([], $slow);
});

check('oversized requests are checked quickly', function () {
    $s = new Shield(['mode' => 'enforce']);
    $padded = BROWSER;
    for ($i = 0; $i < 60; $i++) {
        $padded["X-Pad-$i"] = str_repeat('a', 8000);
    }
    $cases = [
        '60 padded headers' => fn () => $s->check('192.0.2.90', 'GET', '/', '', $padded),
        '8000-character path' => fn () => $s->check('192.0.2.91', 'GET', '/' . str_repeat('db', 4000) . '!', '', BROWSER),
        '60000-character query' => fn () => $s->check('192.0.2.92', 'GET', '/', str_repeat('a', 60000), BROWSER),
        '20000 query parameters' => fn () => $s->check('192.0.2.93', 'GET', '/', str_repeat('a=b&', 20000), BROWSER),
        '8000-character user agent' => fn () => $s->check('192.0.2.94', 'GET', '/', '', ['User-Agent' => str_repeat('Mozilla/5.0 ', 660)]),
        '8000-character referer' => fn () => $s->check('192.0.2.95', 'GET', '/', '', BROWSER + ['Host' => 'shop.example',
            'Referer' => 'https://' . str_repeat('a.', 4000)]),
        'a 64 KB body with honeytokens set' => fn () => (new Shield(['honeytokens' => ['api_live_0123456789abcdef']]))
            ->check('192.0.2.96', 'POST', '/', '', BROWSER, str_repeat('%', 65536)),
    ];
    foreach ($cases as $name => $fn) {
        $took = timed($fn);
        truthy($took < BUDGET, sprintf('%s: %.2f s', $name, $took));
    }
});

exit(report());
