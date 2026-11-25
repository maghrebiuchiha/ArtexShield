# artex-shield decision spec

What every implementation (Python, the proxy, Node, PHP, OpenResty) must do with a request, and the format of `vectors.json`, the cases each one is checked against. The Python package in `src/artex_shield/` is the reference: where this text and the vectors disagree, the vectors win, and the disagreement is a bug in this text.

## Test vectors

`vectors.json` is exported from the Python test suite by `spec/export_vectors.py`: every decision the detection tests make (`test_shield.py`, `test_client_check.py`, `test_honeytokens.py`), recorded as it happened. Only the tests of Python-specific plumbing are left out (adapters, block file, locking, timing). `tests/test_vectors.py` replays them against the Python shield, `tests/test_proxy.py` sends every request in them through `artex-shield-proxy` over HTTP, `ports/node/test/vectors.test.js` replays them against the Node port, `ports/php/tests/vectors.php` against the PHP port (with its state kept in memory, in files, or in the object cache), `ports/openresty/tests/vectors.lua` against the OpenResty port (with its state in shared dicts), and `ports/openresty/tests/edge.py` sends every request in them through OpenResty over HTTP.

Each of these reads `vectors.json` (and `patterns.json`) from another directory when `ARTEX_SPEC` names one, so a set of cases made elsewhere, such as random ones with the reference's decisions as their expectations, can be run through every port. The HTTP runners skip cases with their own `trusted_proxies`, since they need to be the proxy the shield trusts.

```json
{"version": 2, "t0": 1800000000.0,
 "client_check_script": "(function () { ... PATH ... })();",
 "canaries":      [{"secret": "s", "count": 5, "paths": ["/api/v1/internal/audit-...", ...]}],
 "honeytokens":   [{"secret": "s", "count": 5, "api_keys": [...], "users": [...], "passwords": [...]}],
 "client_ip":     [{"trusted_proxies": [...], "remote": "10.0.0.2", "forwarded_for": "203.0.113.7:44321", "expect": "203.0.113.7"}],
 "client_check_routes": [{"config": {"client_check": true}, "path": "/_artex/check.js", "expect": "script"}],
 "config_errors": [{"config": {"exempt_paths": ["/"]}, "error": "..."}],
 "cases":         [{"id": "Behaviour/test_payloads#3", "config": {"mode": "enforce"}, "steps": [...]}]}
```

A case starts a fresh shield with the default config (below) overridden by `config`, and a clock reading `t0`. Engagement `start` and `end` are seconds after `t0`. Its steps run in order; each sets the clock to `t0 + at` first.

| Step | Do | Check |
| --- | --- | --- |
| `{"at", "request": {ip, method, path, query?, headers?, body?, body_base64?}, "expect"}` | decide on the request (`ip` is the client address, already resolved). `body` is UTF-8 text, `body_base64` any other bytes; only honeytokens read it | `action` equal; `hits` equal as a set (the file lists them sorted); `score` within 1e-6; `retry_after` equal when given |
| `{"at", "observe": {ip, path, status, induced?, content_type?}}` | feed back the status (and `Content-Type`) the app answered with | nothing |
| `{"at", "client_check": {ip, query, headers?, secure?}, "expect": {status, headers}}` | answer the client check endpoint (see "Client check") | `status` equal; `headers` equal, in order, as `[name, value]` pairs |
| `{"at", "unblock": ip, "expect": bool}` | lift the block on `ip` (and any wider IPv6 block over it) | whether one was lifted |
| `{"at", "expect_blocklist": [...]}` | list active blocks | the networks, sorted |
| `{"repeat": n, "at", "dt": [...], "i_from", "steps": [...], "expect": [...]}` | run `steps` `n` times; see below | as below |

A repeat block's iteration *k* (from 0) runs every template in `steps`, in order, with each `{i}` in a string replaced by `i_from + k`. The very first step runs at `t0 + at`. Every later step runs at the instant of the step before it **plus** `dt[j]`, where `j` is its place in the template (so `dt[0]` is the time from one iteration's last step to the next iteration's first). Accumulate in IEEE double precision, step by step; never compute an instant as `at + k * dt`. The tests moved their clock that way, and the result differs in the last bits. `expect` is a list of runs, `{"times": m, "each": [...], "last": [...]}`, one entry per template step (`null` for an observe):

- `each`: `action` and `hits` for each of the first `m - 1` iterations;
- `last`: the full decision for the run's final iteration.

`config_errors` must be refused at start-up, and `client_ip` is the address-resolution function on its own. `client_check_routes` says which paths are the client check's endpoints under a config (see "Client check"). `canaries` and `honeytokens` are the derivations below, which a port that takes a secret in its settings must reproduce exactly. `client_check_script` is the check script, with the word `PATH` standing for the check path written as a JSON string. `pattern_probes` gives, for every pattern in `patterns.json`, whether it matches each of a list of short texts chosen where regex dialects disagree: one `0` or `1` per text, in order.

Header names are case-insensitive. `query` is the raw query string, without the `?`.

## Configuration

Only the keys that change decisions. `soft_cap` defaults to 80% of `throttle_score`.

| Key | Default | Key | Default |
| --- | --- | --- | --- |
| `mode` | `"monitor"` | `enum_404_threshold` / `enum_window` | 15 / 60 s |
| `throttle_score` / `block_score` | 50 / 100 | `enum_ignore_prefixes` | `[]` |
| `half_life` | 600 s | `enum_ignore_extensions` | js mjs css map png jpg jpeg gif svg webp avif ico woff woff2 ttf otf eot mp3 mp4 webm |
| `block_ttl` / `max_block_ttl` | 3600 / 86400 s | `slow_enum_budget` / `slow_enum_window` / `slow_enum_points` | 60 / 3600 s / 10 |
| `retry_after` | 120 s | `rate_limit` / `rate_window` | 240 / 60 s |
| `ignored_throttle_points` | 5 | `cadence_samples` | 30 |
| `soft_cap` | 0.8 × `throttle_score` | `cadence_min_mean` / `cadence_max_mean` / `cadence_max_cv` | 0.15 s / 2.0 s / 0.35 |
| `trusted_proxies`, `allow_cidrs` | `[]` (CIDRs) | `tls_header`, `tls_denylist` | none |
| `exempt_paths`, `canary_paths` | `[]` | `score_induced` | false |
| `engagements` | `[]` | `v6_escalate_after` | 0 (off; 1 refused) |
| `honeytokens` | `[]` (each at least 12 characters, no whitespace) | `honeytoken_body_limit` | 65536 bytes |
| `client_check` | false | `client_check_secret` | none: a random key per process |
| `client_check_path` | `/_artex/check` | `client_check_cookie` | `artex_check` |
| `client_check_api_prefixes` | `["/api"]` | `client_check_grace` / `client_check_ttl` | 30 s / 86400 s |
| `client_check_points` | 20 | | |

## Who a client is

- **Client address.** `X-Forwarded-For` is read only when the direct peer is in `trusted_proxies`. Walk it from the right, skipping trusted addresses, and take the first untrusted one. An entry may carry a port: `1.2.3.4:5`, `[2001:db8::1]:443`. Stop at an entry that is not an address. With nothing usable, the peer itself, or `0.0.0.0` when there is no peer.
- **Unidentified.** An address that is missing, unspecified (`0.0.0.0`, `::`) or a trusted proxy is passed unscored, with hit `config:unidentified-client`.
- **Track key.** One score per client: an IPv4 address, or an IPv6 `/64` (IPv4-mapped IPv6 counts as IPv4).

## Deciding on a request

In this order; the first that applies decides.

1. **Allowlisted:** path under `exempt_paths` (whole segments, and never a path containing `..` at any decoding depth), or address in `allow_cidrs`. Pass, score 0, no hits.
2. **Unidentified:** see above.
3. **Assessment label:** a User-Agent with `ARTEX-Assessment/<version>`.
   - Matching an engagement's reference, source CIDR and time window: pass, `friendly`, hit `iff:engagement=<REF>`.
   - Otherwise: hit `artex:unverified-assessment-label` (100), and go on.
4. **Blocked**, in enforce mode: `block`, score = `block_score`, hits `["blocklist"]`.
5. **Read the request's signals** (table below), honeytokens included.
6. **Blocked**, in monitor mode: `block`, score = `block_score`, hits `blocklist` plus the signals. Nothing is stopped and the client's own score stays frozen until the block would have ended.
7. **Induced:** a web page made the browser send it.
   - Which requests count: `Sec-Fetch-Site` is `cross-site` or `same-site`; or it is `same-origin` and `Sec-Fetch-Dest` is something a page embeds (not `document`, `empty` or absent); or, without `Sec-Fetch-Site`, a `Referer` from another host than `Host`.
   - What happens: no score and no tracking. Pass if no hard signal fired; otherwise `refuse`, score 0, with the hard signals as hits.
   - `score_induced` turns this step off.
8. **Score the client.**
   - Decay the score (below).
   - Count each soft signal at most once per `half_life` per label; a repeat inside that window is dropped from the hits.
   - Add the volume and cadence signals, and the client check's (see "Client check").
   - In enforce mode only, add `behavior:ignored-retry-after` (5) if the client is still inside a `Retry-After` it was given.
   - Hard points add without limit; soft points add into a bucket capped at `soft_cap`. The score is hard + soft.
9. **Respond.**
   - **Score ≥ `block_score`:** `block`.
     - The block lasts `min(block_ttl × 2^(strikes−1), max_block_ttl)`, where `strikes` counts this client's blocks so far, this one included.
     - The score resets to 0.
   - **Score ≥ `throttle_score`:** `throttle`.
     - `retry_after = max(retry_after, ceil(half_life × log2(score / throttle_score)) + 1)`, and the client is "told to wait" until then.
   - **Otherwise:** `pass`, which clears any wait.

**After the app answers** (`observe`), only 404s count, apart from one thing: with the client check on, a 2xx answer whose `Content-Type` is `text/html` or `application/xhtml+xml` (parameters ignored, any case) to a request that was not induced notes the time of the client's first HTML page, if its address is identified and it already has a score track. 404s are skipped for induced requests, allowlisted paths and addresses, clients never seen, and blocked clients.

- `recon:probe-404` (25) and the missing dump or backup names (`decoy:sensitive-file-probe`, 60) score on every hit.
- A path counts toward enumeration only the first time it is missing for this client, and again after a `half_life` without asking for it. Paths under `enum_ignore_prefixes` or with `enum_ignore_extensions` never count. 15 counted paths within 60 s add `behavior:path-enumeration` (40) and reset the count.
- Each counted path beyond `slow_enum_budget` within `slow_enum_window` adds `behavior:slow-enumeration` (10).
- A score reaching `block_score` here blocks, as above.

**Decay:** `score × 0.5^(elapsed / half_life)`, applied to the hard and soft parts alike; a total under 0.5 becomes 0.

**IPv6 widening** is off unless `v6_escalate_after` is N ≥ 2. Then N blocked `/64`s inside one `/56` replace themselves with a block on the `/56`, and the same from `/56` to `/48`, each lasting `block_ttl`.

## Signals

Labels are part of the contract. Patterns are in `src/artex_shield/signatures.py`.

| Label | Points | Kind |
| --- | --- | --- |
| `decoy:canary-path` | 100 | hard |
| `artex:*`, `tool:*` (User-Agent signatures) | 100 | hard |
| `decoy:sensitive-file-probe` (dotfiles and keys on sight; dumps and backups on a 404) | 60 | hard |
| `payload:sqli` `payload:xss` `payload:traversal` `payload:cmdi` `payload:ssti` `payload:ssrf-metadata` | 50 each | hard, URL only |
| `payload:jndi` `payload:oob-callback` | 50 each | hard, URL and every header value |
| `decoy:honeytoken-header` `-cookie` `-query` `-path` `-body` | `max(100, block_score)` | hard |
| `ua:headless-browser` | 40 | soft |
| `tls:denylisted-fingerprint` | 40 | soft |
| `behavior:path-enumeration` | 40 | hard, from 404s |
| `behavior:request-flood` (more than `rate_limit` within `rate_window`; the history then empties) | 30 | hard |
| `method:TRACE` `method:TRACK` `method:CONNECT` `method:DEBUG` | 30 | hard |
| `method:PROPFIND` | 30 | soft |
| `recon:probe-404` | 25 | hard, from 404s |
| `behavior:metronomic-cadence` (the last `cadence_samples` gaps average 0.15–2 s with a coefficient of variation ≤ 0.35) | 20 | soft |
| `client:no-check` `client:automation-reported` | `client_check_points` (20) | soft |
| `shape:browser-ua-without-browser-headers` `ua:empty` | 20 each | soft |
| `ua:http-library` | 15 | soft |
| `behavior:slow-enumeration` | 10 | hard, from 404s |
| `behavior:ignored-retry-after` | 5 | hard |

Payload patterns read the decoded path and each query name and value, URL-decoded up to twice, joined by NUL. They are matched a second time with SQL comments turned into spaces. If a User-Agent signature fires, the soft User-Agent signals are not read.

## Honeytokens

A request carries a honeytoken when one of the configured values is a substring of one of these, looked at in this order; the first place found names the signal:

1. **Each header value** but `Referer`, in the order the headers came, its first 16384 characters: `cookie` for the `Cookie` header, `header` for any other. For `Authorization` and `Proxy-Authorization` of the form `Basic <base64>` (any case, base64 of 4 to 8192 characters, standard or URL-safe alphabet, padding optional), the decoded credentials too, read as Latin-1: `header`.
2. **The query string**, its first 65536 characters: `query`.
3. **The path**, percent-decoded with `//` runs collapsed: `path`.
4. **The body**, its first `honeytoken_body_limit` bytes read as Latin-1: `body`. Implementations that hand bodies on (adapters, proxies) read at most that much before deciding, and only when honeytokens are set.

Each text is searched as it is and, if different, after undoing up to two layers of URL encoding (`+` as a space). A hit is a hard signal worth `max(100, block_score)`, so it blocks on its own however `block_score` is set. Like any hard signal, on an induced request it refuses the request and blocks no one.

**Derivation** (`make_honeytokens(secret, count)`): for each `i` from 0, with `D(label) = HMAC-SHA256(secret, "honeytoken-" + label)` and `B62(bytes, n)` the bytes as a big-endian integer written as `n` base-62 digits (`0-9A-Za-z`), least significant first:

- API key `i`: `"api_live_" + B62(D("key-i"), 32)`.
- Password `i`: with `d = D("password-i")` and `b = B62(d, 14)`, insert `"!@#$*"[d[0] % 5]` into `b` at position `d[1] % 14`, then append the digit `d[2] % 10`.
- User `i`: `["svc-deploy", "admin-legacy", "ops-backup", "staging-admin"][i % 4]`. Users are decoration and are not watched for.

**Canaries** (`make_canaries(secret, count)`): for each `i`, the shape `i % 5` of `/api/v1/internal/audit-{}`, `/admin/legacy-{}/export`, `/api/v2/debug/session-{}`, `/backend/ops-{}/config`, `/api/v1/staff/reports-{}` with `{}` the first 10 hex digits of `HMAC-SHA256(secret, "canary-i")`.

## Client check

Optional, off unless `client_check` is true. It needs no state beyond the score tracks.

**Endpoints.** With the check on, a request whose path (percent-decoded, `//` collapsed) equals `client_check_path` (with any trailing `/` removed) is the check, and that path plus `.js` is the script. Both are answered by the shield's host, never passed to the app, and only after the request itself has been decided on and not stopped.

- **The script:** 200, `client_check_script` with `PATH` replaced, `Content-Type: text/javascript; charset=utf-8`, `Cache-Control: public, max-age=3600`, `X-Content-Type-Options: nosniff`.
- **The check:** 204 with an empty body. It reads `f` from the query (decimal, at most 5 digits; anything else is 0) and masks it to `7`. If the address is identified, it records on the client's track (creating it if need be) that it checked now, and, if `f` is not 0, that it reported automation now. Its headers, in this order: `Set-Cookie: <cookie>=<value>; Path=/; Max-Age=<ttl as an integer>; HttpOnly; SameSite=Lax`, with `; Secure` added when the visitor used HTTPS; `Cache-Control: no-store`; `Content-Length: 0`.

**The cookie value** is `1.<issued>.<flags>.<mac>`: `issued` the whole seconds of the clock, `mac` the first 22 characters of the URL-safe base64 of `HMAC-SHA256(client_check_secret, "1.<issued>.<flags>")`. It is valid when it has exactly those four parts, is at most 100 characters, has `issued` within `[now - client_check_ttl, now + 300]`, `flags` at most 7, and a matching `mac` (compare in constant time). It is read from the `Cookie` header's first 16384 characters: split on `;`, trim, first entry whose name equals `client_check_cookie`, value trimmed of spaces and `"`.

**Which requests are judged.** Only requests under `client_check_api_prefixes` that a page's script made. With a `Sec-Fetch-Mode` header, that means mode `cors` or `same-origin` with `Sec-Fetch-Dest` `empty` or absent. Without one, it means `X-Requested-With: XMLHttpRequest`, or an `Accept` that names none of `text/html`, `application/xhtml`, `image/`, `text/css`, `video/`, `audio/`, `font/`. Induced requests never get this far (step 7).

**Signals,** each at most once per `half_life`, soft:

- `client:automation-reported` when the request's valid cookie has flags, or the client's track noted an automation report less than `client_check_ttl` ago.
- `client:no-check` when the cookie is missing or invalid, the client never completed a check, and its first HTML page was served at least `client_check_grace` ago.

## Responses

In enforce mode, `block` and `refuse` answer 403 and `throttle` answers 429. All of them carry `Content-Type: text/plain; charset=utf-8`, `Cache-Control: no-store`, and a body naming a reference that is also logged:

- `Request blocked. Reference: <ref>`
- `Request refused. Reference: <ref>`
- `Too many requests. Reference: <ref>`, with `Retry-After: <retry_after>`

Monitor mode decides the same way but never stops a request.

## Porting notes

`spec/patterns.json` holds every pattern from `signatures.py`, generated with the vectors; translate it rather than copying patterns by hand. The patterns use Python `re` syntax on `str`: `(?P<q>...)` and `(?P=q)`, `\A`, lookbehind, `[\s\S]`, and case-insensitive matching throughout, with these meanings:

- `\w` is a Unicode letter, number or `_` (`[\p{L}\p{N}_]`); `\d` is a Unicode decimal digit (`\p{Nd}`); `\s` is `[\t\n\v\f\r\x1c-\x1f \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]`; `\b` is a boundary between `\w` and anything else.
- `$` (no multiline flag) matches at the end and also before a newline that ends the text.
- `.` matches anything but `\n`, `\r` and `\u2028` included.
- Case-insensitive matching folds case as Unicode simple case folding does: `ſ` matches `s`.

Notes per target:

- **JavaScript:** compile with the `u` and `i` flags; write `(?<q>...)` and `\k<q>`, `^` for `\A`, `(?=\n?$)` for `$`, `[^\n]` for `.`, and the classes above. JS's own `\w`, `\b` and `\d` are ASCII, so they must be replaced. `ports/node/lib/py.js` does all this.
- **PCRE (PHP, OpenResty's `ngx.re`):** `(?P<q>...)`, `(?P=q)` and `$` already mean the same. Use UTF mode with Unicode properties, then check `.`, the classes and case folding against `pattern_probes`.

`pattern_probes` in the vectors checks a translation on the texts where these differ.

Every pattern must run in linear time on hostile input. Before adding one, read the warning at the top of `signatures.py`.
