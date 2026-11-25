<?php
/**
 * The signature patterns, from patterns.json: a copy of spec/patterns.json,
 * generated from the Python reference's signatures.py, translated here from
 * Python's regex dialect to PCRE.
 */
declare(strict_types=1);

namespace ArtexShield;

final class Signatures
{
    private static ?array $compiled = null;

    /** Every table, compiled: hard_ua and soft_ua as [regex, points, label], payloads and oob as
     * [regex, label], the rest as one regex, and the method lists. */
    public static function get(): array
    {
        if (self::$compiled !== null) {
            return self::$compiled;
        }
        $built = dirname(__DIR__) . '/patterns.php';             // see ports/php/build.php
        return self::$compiled = is_file($built) ? require $built : self::fromJson();
    }

    /** patterns.json, translated. */
    public static function fromJson(): array
    {
        $p = json_decode((string) file_get_contents(dirname(__DIR__) . '/patterns.json'), true, 512, JSON_THROW_ON_ERROR);
        $c = [];
        foreach (['hard_ua', 'soft_ua'] as $table) {
            $c[$table] = array_map(static fn (array $r): array => [self::compile($r[0]), (float) $r[1], $r[2]], $p[$table]);
        }
        foreach (['payloads', 'oob'] as $table) {
            $c[$table] = array_map(static fn (array $r): array => [self::compile($r[0]), $r[1]], $p[$table]);
        }
        foreach (['assessment_ua', 'browser_ua', 'crawler_ua', 'sensitive_paths', 'missing_sensitive', 'recon_paths'] as $name) {
            $c[$name] = self::compile($p[$name]);
        }
        $c['odd_methods'] = array_flip($p['odd_methods']);
        $c['soft_methods'] = array_flip($p['soft_methods']);
        return $c;
    }

    /** A Python pattern as a PCRE regex with delimiters and flags. Case-insensitive, as all of them are. */
    public static function compile(string $src): string
    {
        return '~(*LF)' . self::translate($src) . '~iu';
    }

    /** Does $regex match anywhere in $text? PCRE's JIT keeps its backtracking on
     * a small fixed stack, and a repeated group over a long text (a 30 KB
     * User-Agent, say) can run it out; then the same pattern runs again
     * without the JIT, which keeps backtracking on the heap. Any other PCRE
     * failure (the backtrack limit, say) is logged and counts as a match: as
     * no match, text built to exhaust PCRE would carry a payload past the
     * pattern. The patterns scan in linear time (tests/cost.php), so text a
     * visitor sends does not get here. */
    public static function search(string $regex, string $text, ?array &$m = null): bool
    {
        $found = preg_match($regex, $text, $m);
        if ($found === false && preg_last_error() === PREG_JIT_STACKLIMIT_ERROR) {
            $found = preg_match('~(*NO_JIT)' . substr($regex, 1), $text, $m);
        }
        if ($found === false) {
            error_log('artex-shield: pattern failed (' . preg_last_error_msg() . '), counted as a match: ' . substr($regex, 0, 60));
            $m = [];
            return true;
        }
        return $found === 1;
    }

    /**
     * Python `re` to PCRE in UTF mode with the meanings SPEC.md gives: \w \s
     * \d \b by Python's Unicode classes, and Python's one case equivalence
     * PCRE's folding lacks (i, I, dotless ı, dotted İ). PCRE already reads
     * (?P<name>), (?P=name), \A, $ and "." as Python does (with LF newlines).
     */
    public static function translate(string $src): string
    {
        $out = '';
        $n = strlen($src);
        $i = 0;
        while ($i < $n) {
            $c = $src[$i];
            if ($c === '\\') {
                [$piece] = self::escape($src, $i, false);
                $out .= $piece;
                $i += self::escapeLength($src, $i);
                continue;
            }
            if ($c === '[') {
                [$piece, $i] = self::charClass($src, $i);
                $out .= $piece;
                continue;
            }
            if ($c === '(' && (substr($src, $i, 4) === '(?P<' || substr($src, $i, 4) === '(?P=')) {
                $end = strcspn($src, '>)', $i + 4) + $i + 4;    // the group's name, copied as it is
                $out .= substr($src, $i, $end - $i + 1);
                $i = $end + 1;
                continue;
            }
            if ($c === 'i' || $c === 'I') {
                $out .= '[iI\x{131}\x{130}]';
            } elseif ($c === '~') {
                $out .= '\~';
            } else {
                $out .= $c;
            }
            $i++;
        }
        return $out;
    }

    private static function escapeLength(string $src, int $i): int
    {
        $n = $src[$i + 1] ?? '';
        return $n === 'x' ? 4 : ($n === 'u' ? 6 : 2);
    }

    /** One escape at $src[$i]: [piece] where piece is a string, or ['negated' => body] in a class. */
    private static function escape(string $src, int $i, bool $inClass): array
    {
        $n = $src[$i + 1] ?? '';
        $w = Py::WORD;
        $s = Py::SPACE;
        switch ($n) {
            case 'w': return [$inClass ? $w : "[$w]"];
            case 's': return [$inClass ? $s : "[$s]"];
            case 'd': return ['\p{Nd}'];
            case 'W': return [$inClass ? ['negated' => $w] : "[^$w]"];
            case 'S': return [$inClass ? ['negated' => $s] : "[^$s]"];
            case 'D': return [$inClass ? ['negated' => '\p{Nd}'] : '\P{Nd}'];
            case 'b': return [$inClass ? '\x{08}' : "(?:(?<=[$w])(?![$w])|(?<![$w])(?=[$w]))"];
            case 'B': return ["(?:(?<=[$w])(?=[$w])|(?<![$w])(?![$w]))"];
            case 'A': return ['\A'];
            case 'Z': return ['\z'];
            case 'x': return ['\x{' . substr($src, $i + 2, 2) . '}'];
            case 'u': return ['\x{' . substr($src, $i + 2, 4) . '}'];
            case 'v': return ['\x{0b}'];
            case 'n': case 'r': case 't': case 'f': return ['\\' . $n];
            case '':
                throw new \InvalidArgumentException('pattern ends in a backslash');
        }
        if (preg_match('/[A-Za-z0-9]/', $n)) {
            throw new \InvalidArgumentException("unsupported escape \\$n");
        }
        return ['\\' . $n];                    // a literal: \. \" \' \- and the like
    }

    /** A character class from $src[$i] ("["). One holding \S, \W or \D becomes an
     * alternation, as for the JavaScript port, so its meaning stays exact. */
    private static function charClass(string $src, int $i): array
    {
        $n = strlen($src);
        $j = $i + 1;
        $negate = false;
        if (($src[$j] ?? '') === '^') {
            $negate = true;
            $j++;
        }
        $items = '';
        $negated = [];
        $first = true;
        while ($j < $n) {
            $c = $src[$j];
            if ($c === ']' && !$first) {
                break;
            }
            $first = false;
            if ($c === '\\') {
                [$piece] = self::escape($src, $j, true);
                if (is_array($piece)) {
                    $negated[] = $piece['negated'];
                } else {
                    $items .= $piece;
                }
                $j += self::escapeLength($src, $j);
                continue;
            }
            $items .= ($c === '[' || $c === ']' || $c === '~') ? '\\' . $c : $c;
            $j++;
        }
        if (($src[$j] ?? '') !== ']') {
            throw new \InvalidArgumentException('unterminated character class');
        }
        if ($items !== '' && preg_match("~(*LF)[$items]~iu", 'i')) {
            if (preg_match('/(^|[^\\\\])-$/', $items)) {
                $items = substr($items, 0, -1) . '\-';      // a final "-" is literal; keep it so
            }
            $items .= '\x{131}\x{130}';
        }
        if (!$negated) {
            return ['[' . ($negate ? '^' : '') . $items . ']', $j + 1];
        }
        if ($negate) {
            throw new \InvalidArgumentException('a negated class holding \S, \W or \D is not supported');
        }
        $alternatives = $items !== '' ? ["[$items]"] : [];
        foreach ($negated as $body) {
            $alternatives[] = "[^$body]";
        }
        return ['(?:' . implode('|', $alternatives) . ')', $j + 1];
    }
}
