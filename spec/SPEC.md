# artex-shield decision spec

What every implementation (Python, the proxy, Node, PHP, OpenResty) must do with a request, and the format of `vectors.json`, the cases each one is checked against. The Python package in `src/artex_shield/` is the reference: where this text and the vectors disagree, the vectors win, and the disagreement is a bug in this text.

## Test vectors

`vectors.json` is exported from the Python test suite by `spec/export_vectors.py`: every decision the detection tests make, recorded as it happened. Only the tests of Python-specific plumbing are left out (adapters, block file, locking, timing). `tests/test_vectors.py` replays them against the Python shield, and `tests/test_proxy.py` sends every request in them through `artex-shield-proxy` over HTTP.

```json
{"version": 1, "t0": 1800000000.0,
 "client_ip":     [{"trusted_proxies": [...], "remote": "10.0.0.2", "forwarded_for": "203.0.113.7:44321", "expect": "203.0.113.7"}],
 "config_errors": [{"config": {"exempt_paths": ["/"]}, "error": "..."}],
 "cases":         [{"id": "Behaviour/test_payloads#3", "config": {"mode": "enforce"}, "steps": [...]}]}
```

A case starts a fresh shield with the default config (below) overridden by `config`, and a clock reading `t0`. Engagement `start` and `end` are seconds after `t0`. Its steps run in order; each sets the clock to `t0 + at` first.

| Step | Do | Check |
| --- | --- | --- |
| `{"at", "request": {ip, method, path, query?, headers?}, "expect"}` | decide on the request (`ip` is the client address, already resolved) | `action` equal; `hits` equal as a set (the file lists them sorted); `score` within 1e-6; `retry_after` equal when given |
| `{"at", "observe": {ip, path, status, induced?}}` | feed back the status the app answered with | nothing |
| `{"at", "unblock": ip, "expect": bool}` | lift the block on `ip` (and any wider IPv6 block over it) | whether one was lifted |
| `{"at", "expect_blocklist": [...]}` | list active blocks | the networks, sorted |
| `{"repeat": n, "at", "every", "i_from", "steps": [...], "expect": [...]}` | run `steps` `n` times; see below | as below |

A repeat block's iteration *k* (from 0) runs every template in `steps` with each `{i}` in a string replaced by `i_from + k`. All of an iteration's steps happen at one instant. The first iteration is at `t0 + at`, and each later one at the previous instant **plus** `every`, accumulated in IEEE double precision, never computed as `at + k * every`. The tests moved their clock that way, and the result differs in the last bits. `expect` is a list of runs, `{"times": m, "each": [...], "last": [...]}`, one entry per template step (`null` for an observe):

- `each`: `action` and `hits` for each of the first `m - 1` iterations;
- `last`: the full decision for the run's final iteration.

`config_errors` must be refused at start-up, and `client_ip` is the address-resolution function on its own.

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
5. **Read the request's signals** (table below).
6. **Blocked**, in monitor mode: `block`, score = `block_score`, hits `blocklist` plus the signals. Nothing is stopped and the client's own score stays frozen until the block would have ended.
7. **Induced:** a web page made the browser send it.
   - Which requests count: `Sec-Fetch-Site` is `cross-site` or `same-site`; or it is `same-origin` and `Sec-Fetch-Dest` is something a page embeds (not `document`, `empty` or absent); or, without `Sec-Fetch-Site`, a `Referer` from another host than `Host`.
   - What happens: no score and no tracking. Pass if no hard signal fired; otherwise `refuse`, score 0, with the hard signals as hits.
   - `score_induced` turns this step off.
8. **Score the client.**
   - Decay the score (below).
   - Count each soft signal at most once per `half_life` per label; a repeat inside that window is dropped from the hits.
   - Add the volume and cadence signals.
   - In enforce mode only, add `behavior:ignored-retry-after` (5) if the client is still inside a `Retry-After` it was given.
   - Hard points add without limit; soft points add into a bucket capped at `soft_cap`. The score is hard + soft.
9. **Respond.**
   - **Score ≥ `block_score`:** `block`.
     - The block lasts `min(block_ttl × 2^(strikes−1), max_block_ttl)`, where `strikes` counts this client's blocks so far, this one included.
     - The score resets to 0.
   - **Score ≥ `throttle_score`:** `throttle`.
     - `retry_after = max(retry_after, ceil(half_life × log2(score / throttle_score)) + 1)`, and the client is "told to wait" until then.
   - **Otherwise:** `pass`, which clears any wait.

**After the app answers** (`observe`), only 404s count. They are skipped for induced requests, allowlisted paths and addresses, clients never seen, and blocked clients.

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
| `ua:headless-browser` | 40 | soft |
| `tls:denylisted-fingerprint` | 40 | soft |
| `behavior:path-enumeration` | 40 | hard, from 404s |
| `behavior:request-flood` (more than `rate_limit` within `rate_window`; the history then empties) | 30 | hard |
| `method:TRACE` `method:TRACK` `method:CONNECT` `method:DEBUG` | 30 | hard |
| `method:PROPFIND` | 30 | soft |
| `recon:probe-404` | 25 | hard, from 404s |
| `behavior:metronomic-cadence` (the last `cadence_samples` gaps average 0.15–2 s with a coefficient of variation ≤ 0.35) | 20 | soft |
| `shape:browser-ua-without-browser-headers` `ua:empty` | 20 each | soft |
| `ua:http-library` | 15 | soft |
| `behavior:slow-enumeration` | 10 | hard, from 404s |
| `behavior:ignored-retry-after` | 5 | hard |

Payload patterns read the decoded path and each query name and value, URL-decoded up to twice, joined by NUL. They are matched a second time with SQL comments turned into spaces. If a User-Agent signature fires, the soft User-Agent signals are not read.

## Responses

In enforce mode, `block` and `refuse` answer 403 and `throttle` answers 429. All of them carry `Content-Type: text/plain; charset=utf-8`, `Cache-Control: no-store`, and a body naming a reference that is also logged:

- `Request blocked. Reference: <ref>`
- `Request refused. Reference: <ref>`
- `Too many requests. Reference: <ref>`, with `Retry-After: <retry_after>`

Monitor mode decides the same way but never stops a request.

## Porting notes

The patterns use Python `re` syntax: `(?P<q>...)` and `(?P=q)`, `\A`, lookbehind, `[\s\S]`, and case-insensitive matching throughout.

- **JavaScript and PCRE (PHP, OpenResty's `ngx.re`):** use `(?<q>...)` and `\k<q>`.
- **JavaScript:** has no `\A`; anchor with `^` and no multiline flag.

Every pattern must run in linear time on hostile input. Before adding one, read the warning at the top of `signatures.py`.
