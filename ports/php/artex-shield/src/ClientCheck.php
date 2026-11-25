<?php
/** The optional client-side check: a script that reports browser automation, and a signed cookie. */
declare(strict_types=1);

namespace ArtexShield;

final class ClientCheck
{
    public const FLAGS = 7;

    // Must stay identical to client_check._SCRIPT; the vector test compares it with the spec.
    public const SCRIPT = <<<'JS'
(function () {
  try {
    var w = window, d = document, n = navigator, f = 0, k, keys;
    try { if (w.sessionStorage.getItem("artex_check")) return; w.sessionStorage.setItem("artex_check", "1"); } catch (e) {}
    if (n.webdriver === true) f |= 1;
    if (w.callPhantom || w._phantom || w.__nightmare || w.domAutomation || w.domAutomationController ||
        w.__playwright__binding__ || w.__pwInitScripts) f |= 2;
    var el = d.documentElement;
    if ((el && el.getAttribute("webdriver") !== null) || d.__selenium_unwrapped || d.__webdriver_evaluate ||
        d.__driver_evaluate || d.__webdriver_script_fn) f |= 4;
    try { keys = Object.keys(d); for (k = 0; k < keys.length; k++) { if (keys[k].indexOf("cdc_") >= 0) { f |= 4; break; } } } catch (e) {}
    var url = PATH + "?v=1&f=" + f;
    if (w.fetch) { w.fetch(url, {credentials: "same-origin", cache: "no-store"})["catch"](function () {}); }
    else { var x = new XMLHttpRequest(); x.open("GET", url, true); x.send(); }
  } catch (e) {}
})();

JS;

    /** The check script, reporting to $path. */
    public static function script(string $path): string
    {
        return str_replace('PATH', Py::jsonString($path), self::SCRIPT);
    }

    /** The <script> tag for every HTML page; the plugin serves $path . ".js". */
    public static function tag(string $path): string
    {
        return '<script src="' . $path . '.js" async></script>';
    }

    private static function mac(string $key, int $issued, int $flags): string
    {
        $raw = hash_hmac('sha256', "1.$issued.$flags", $key, true);
        return substr(rtrim(strtr(base64_encode($raw), '+/', '-_'), '='), 0, 22);
    }

    /** Cookie value: version, when issued, what was reported, signature. */
    public static function sign(string $key, int $issued, int $flags): string
    {
        return "1.$issued.$flags." . self::mac($key, $issued, $flags);
    }

    /** The flags of a valid, unexpired cookie this key signed; null otherwise. */
    public static function verify(string $key, ?string $value, float $now, float $ttl): ?int
    {
        if ($value === null || $value === '' || Py::length($value) > 100) {
            return null;
        }
        $parts = explode('.', $value);
        if (count($parts) !== 4 || $parts[0] !== '1' || !Py::isDigits($parts[1]) || !Py::isDigits($parts[2])) {
            return null;
        }
        if (strlen($parts[1]) > 18 || strlen($parts[2]) > 18) {
            return null;                         // far outside any valid time or flag value
        }
        $issued = (int) $parts[1];
        $flags = (int) $parts[2];
        if (!($now - $ttl <= $issued && $issued <= $now + 300) || $flags > self::FLAGS) {
            return null;
        }
        return hash_equals(self::mac($key, $issued, $flags), $parts[3]) ? $flags : null;
    }

    /** The value of cookie $name in a Cookie header, or null. */
    public static function cookie(string $header, string $name): ?string
    {
        foreach (explode(';', Py::slice($header, 16384)) as $part) {
            $piece = Py::strip($part);
            $eq = strpos($piece, '=');
            if ($eq !== false && substr($piece, 0, $eq) === $name) {
                return trim(Py::strip(substr($piece, $eq + 1)), '"');
            }
        }
        return null;
    }

    /** Did a page's script send this request (fetch or XHR)? $h: lower-case names. */
    public static function scriptMade(array $h): bool
    {
        $mode = Py::lower(Py::strip($h['sec-fetch-mode'] ?? ''));
        if ($mode !== '') {
            return ($mode === 'cors' || $mode === 'same-origin')
                && Py::lower(Py::strip($h['sec-fetch-dest'] ?? 'empty')) === 'empty';
        }
        if (Py::lower(Py::strip($h['x-requested-with'] ?? '')) === 'xmlhttprequest') {
            return true;
        }
        return !preg_match('~text/html|application/xhtml|image/|text/css|video/|audio/|font/~', Py::lower($h['accept'] ?? ''));
    }
}
