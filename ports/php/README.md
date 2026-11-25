# artex-shield for PHP and WordPress

`artex-shield/` is a WordPress plugin, and inside it a dependency-free PHP port of the shield (`src/`, namespace `ArtexShield`). It needs PHP 8.1 or newer. Any other PHP site can run the same shield before every script with `examples/prepend.php` (see "Any other PHP site").

This is a port of the Python package in this repository, which is the reference. Both are held to the same cases, `spec/vectors.json`, and the same rules, `spec/SPEC.md`. The main [README](../../README.md) explains what the shield looks for, how scoring works, and its limits. This page covers what is specific to PHP and WordPress.

## The WordPress plugin

Copy `artex-shield/` into `wp-content/plugins/`, or zip it and upload it under Plugins → Add New. Then activate it. Activation makes a random secret and puts the plugin first in the load order.

On every request, the plugin decides as soon as it is loaded, before themes and before most other plugins run:

- **Stopped requests.** A stopped request gets a 403 (blocked or refused) or a 429 with `Retry-After`, and WordPress never handles it. The plain-text body names a reference that is also logged.
- **Feedback from WordPress.** At shutdown, the status and `Content-Type` WordPress answered with go back to the shield. That is how 404s count as guessing, and how the client check knows who loaded pages.
- **Decoys.** The plugin plants them itself:
  - canary paths in `robots.txt`, a hidden link and a dead JS constant in the footer;
  - with honeytokens on, a fake staging login in an HTML comment and a fake API key in a script;
  - with the client check on, its `<script>` tag in the head.
- **The client check's endpoints** (`/_artex/check.js` and `/_artex/check`) are answered by the plugin.
- **Honeytokens in bodies.** With honeytokens on, the first 64 KiB of a request body is read for them. PHP keeps `php://input` readable, so WordPress still gets the whole body. A multipart form never reaches `php://input` (PHP parses it into `$_POST`), so its fields are read instead.

**Settings → ARTEX Shield** covers:

- the mode (monitor, the default, or enforce);
- the secret;
- the decoy, honeytoken and client-check switches;
- trusted proxies, the allowlist and exempt paths, one per line, each checked before it is saved;
- where state is kept.

The page also lists what is blocked now, with an Unblock button for each entry, and the last 25 events. Every event also goes to the PHP error log as one JSON line.

Leave it in monitor mode until a week of events shows no visitor you would have stopped.

Blocks recorded in monitor mode take effect when you switch to enforce. So that one on your own address (from trying a scanner on your own site, say) cannot shut you out, saving the settings in enforce mode unblocks the address you save them from, and says so.

### Where scores and blocks live

PHP forgets everything between requests, so the shield keeps each client's track and the block table in a store:

- **The object cache,** when WordPress has a persistent one (Redis, Memcached). This is the automatic choice when `wp_using_ext_object_cache()` is true.
- **Files** in `wp-content/artex-shield-data/` otherwise. Each key is one small file, written atomically, behind `flock()` on one of 64 lock files. Every file is PHP that exits at once, and the folder has an `.htaccess` refusing access. Set `ARTEX_SHIELD_DATA_DIR` in `wp-config.php` to keep them elsewhere. An hourly WP-Cron job removes expired entries.

Each client's track is read and written under that client's lock, so concurrent PHP workers do not lose each other's updates. Changes to the block table are replayed onto the latest stored copy under its own lock. Unlike several Python workers, every PHP worker therefore sees the same scores and blocks.

### What it costs

Measured on a 4-vCPU cloud container with PHP 8.3, for a first-seen visitor with browser headers:

| State | One request (check, then the status fed back) |
| --- | --- |
| Files | about 75 µs |
| Memory | about 25 µs |

The first request a PHP worker serves also compiles the patterns, about 2 ms. Run `build.php` after changing them, and OPcache keeps the translated patterns (`artex-shield/patterns.php`) in memory. Object cache cost depends on the backend: one get and one set per request.

## Any other PHP site

`examples/prepend.php` runs the shield before every script, through PHP's `auto_prepend_file`. The site's code does not change. Point the setting at it, in `php.ini`, a `.user.ini` in the document root, or the PHP-FPM pool:

```ini
auto_prepend_file = /opt/artex-shield/examples/prepend.php
; PHP-FPM pool:  php_admin_value[auto_prepend_file] = /opt/artex-shield/examples/prepend.php
; Apache:        php_value auto_prepend_file /opt/artex-shield/examples/prepend.php
```

**Settings.** It reads its settings from `ARTEX_SHIELD_*` environment variables, or you can edit the array at its top:

| Variable | Setting |
| --- | --- |
| `ARTEX_SHIELD_MODE` | `monitor` (the default) or `enforce` |
| `ARTEX_SHIELD_SECRET` | a long random string you keep; it decides the canaries, the fake credentials and the client check's key |
| `ARTEX_SHIELD_TRUSTED_PROXIES`, `ARTEX_SHIELD_ALLOW_CIDRS`, `ARTEX_SHIELD_EXEMPT_PATHS` | lists, separated by commas or spaces |
| `ARTEX_SHIELD_CLIENT_CHECK` | `1` to turn on the client check |
| `ARTEX_SHIELD_DATA_DIR` | where scores and blocks are kept, shared by every PHP worker; by default a directory in the system's temporary directory |

PHP-FPM passes the environment on with `clear_env = no`, or with an `env[ARTEX_SHIELD_MODE] = enforce` line per variable in the pool.

**What it does.** As the plugin does:

- It decides on each request before the site's code runs, and answers stopped ones itself.
- It feeds back the status the site answered with when the script ends, and answers the client check's own paths.
- A setting it cannot use goes to the PHP error log, and the site carries on. The command line (cron jobs, `artisan`, `drush`) is left alone.

**What it sees.** Only requests PHP handles:

- With a front controller (Laravel, Symfony, Drupal, most frameworks), that is every request. Files the web server serves itself never reach PHP, so their 404s are not counted.
- The client check's script ends in `.js`, so it needs a server that sends missing paths to the front controller, as `try_files $uri $uri/ /index.php` does.

**What to plant.** Print it with the same secret:

```bash
ARTEX_SHIELD_SECRET='...' php /opt/artex-shield/examples/decoys.php
```

`tests/prepend.php` runs all of this under PHP's built-in server, with `auto_prepend_file` set.

**From your own code.** `ArtexShield\Guard::protect($shield)` is what both the plugin and `prepend.php` call. To decide and answer yourself:

```php
require 'artex-shield/autoload.php';

$shield = new ArtexShield\Shield(['mode' => 'monitor', 'trusted_proxies' => ['10.0.0.0/8']],
    new ArtexShield\Store\FileStore('/var/lib/artex-shield'));
$request = ArtexShield\Request::fromGlobals($_SERVER);            // read as the plugin reads it
$ip = $shield->clientIp($request->peer, $request->headers['x-forwarded-for'] ?? null);
$d = $shield->check($ip, $request->method, $request->path, $request->query, $request->headers);   // ->action, ->stop(), ->hits, ->ref
// ... after the response: $shield->observe($ip, $request->path, $status, $d->induced, $contentType);
```

Settings use the reference's snake_case names (`throttle_score`, `exempt_paths`, ...); unknown names are refused.

## Tests

```bash
php tests/vectors.php            # spec/vectors.json, state in memory
php tests/vectors.php --files    # the same, every call reading its state back from files
php tests/vectors.php --cache    # the same, through the object-cache store
php tests/cost.php               # every pattern timed on hostile input
php tests/plugin.php             # the plugin's request path under php -S, and its settings
php tests/prepend.php            # examples/prepend.php as auto_prepend_file, in front of a stand-in site
```

`tests/plugin.php` runs the plugin in front of a stand-in for WordPress (`tests/wp/`) under PHP's built-in server: stops, 404 feedback, planted decoys, bodies, the client check, proxies and the settings sanitizer.

CI also runs the plugin on real WordPress 7, with PHP 8.2 and PHP 8.5 (`tests/wordpress/`). It checks the decoys on the page, the settings page saving and refusing values, a scanner blocked in enforce mode, and a planted password replayed from another address. CI runs the tests above on PHP 8.1, 8.3 and 8.5.

## Porting notes

- **Patterns.** They come from `spec/patterns.json` (copied to `artex-shield/patterns.json`) and are translated to PCRE by `src/Signatures.php`. PCRE already reads `(?P<name>)`, `$` and `.` as Python does. The translation supplies Python's `\s`, `\w` and `\b`, and its i/ı/İ case equivalence. When PCRE's JIT runs out of stack on a long input, the match is retried without the JIT.
- **Text.** Header values are read as Latin-1, then handled as UTF-8, as Python's servers do. `src/Py.php` reproduces urllib's unquote and urlsplit, binascii's base64, `math.fsum` and `str.strip`.
- **Addresses.** `src/Ip.php` reads and writes them as Python's ipaddress does.
