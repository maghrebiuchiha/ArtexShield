# artex-shield for OpenResty (nginx)

`lib/` is the shield as an nginx module for [OpenResty](https://openresty.org): it decides on every request in the access phase, before nginx passes it to whatever is behind, so a scanner it blocks never reaches the site. That site can be anything nginx can serve or proxy: a static site, PHP, Node, Python, Java, or another server. Scores and blocks live in `lua_shared_dict`s, so every nginx worker sees the same ones. It is pure Lua with no dependencies beyond what OpenResty ships, and works with OpenResty 1.21.4 or newer.

This is a port of the Python package in this repository, which is the reference. Both are held to the same cases, `spec/vectors.json`, and the same rules, `spec/SPEC.md`. The main [README](../../README.md) explains what the shield looks for, how scoring works, and its limits. This page covers what is specific to nginx.

## Setting it up

Copy `lib/` to the server, say to `/opt/artex-shield/lib`, then:

```nginx
error_log logs/error.log warn;                  # the shield's events are logged at warn

http {
    lua_shared_dict artex_shield        64m;    # client scores
    lua_shared_dict artex_shield_blocks 16m;    # blocks and locks
    lua_package_path "/opt/artex-shield/lib/?.lua;;";

    init_by_lua_block {
        require("resty.artex_shield").configure({
            mode = "monitor",
            trusted_proxies = {"10.0.0.0/8"},       -- your load balancer or CDN, if any
            canary_secret = "a long random string you keep",
            honeytoken_secret = "another one",
        })
    }

    server {
        access_by_lua_block { require("resty.artex_shield").access() }
        log_by_lua_block    { require("resty.artex_shield").log() }

        location / {
            proxy_pass http://your-site;
            proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, never append, when nginx faces visitors
        }
    }
}
```

- **Mode.** `configure()` starts in monitor mode: it logs what it would stop and stops nothing. Leave it there until a week of events shows no visitor you would have stopped, then set `mode = "enforce"`.
- **Bad settings.** Anything the reference would refuse stops nginx from starting, with the reason in the error log.
- **Which locations are covered.** Every location in the server inherits the two phase handlers. A location with its own `access_by_lua` must call `require("resty.artex_shield").access()` first, or the shield does not run there.
- **Answers from the edge.** In enforce mode, a stopped request gets a 403, or a 429 with `Retry-After`. The plain-text body names a reference that is also logged. The client check's script and endpoint (`/_artex/check.js`, `/_artex/check`) are answered here too, never by the site.

**Settings.** The settings are the reference's, under the same snake_case names (`throttle_score`, `exempt_paths`, `client_check`, ...; see `spec/SPEC.md`). These are added, as for `artex-shield-proxy`:

| Setting | What it does |
| --- | --- |
| `canary_secret`, `canary_count` (3) | derive `canary_paths` from a secret |
| `honeytoken_secret`, `honeytoken_count` (2) | add fake credentials derived from a secret to `honeytokens` |
| `tracks_dict`, `blocks_dict` | name other shared dicts than `artex_shield` and `artex_shield_blocks` |
| `admin_token` | 16 characters or more: the admin location then answers 401 to a request without `Authorization: Bearer <admin_token>` |
| `on_event` | a function called with each event, instead of logging it |

**Events.** Each block, throttle and score is logged to nginx's error log at `warn`, one JSON line per event. nginx's default level is `error`, which hides them, so set `error_log ... warn` as above.

### What to plant

The canary paths and fake credentials work once they appear on the site. Print what to plant with the same settings:

```bash
resty --shdict 'artex_shield 1m' --shdict 'artex_shield_blocks 1m' -I /opt/artex-shield/lib -e '
    local edge = require "resty.artex_shield"
    edge.configure({canary_secret = "...", honeytoken_secret = "...", client_check = true})
    print(edge.decoys())'
```

It prints:

- the lines to add to `robots.txt`;
- a hidden link for your page template and a dead JS constant;
- fake credentials for a JS bundle and an HTML comment;
- the client check's `<script>` tag, when the check is on.

### Blocks, by hand

`require("resty.artex_shield").admin()` answers an admin location:

- `GET` lists the active blocks as JSON;
- `POST ip=<address>` lifts the block on that address.

Serve it from a server of its own that listens on loopback, never from the public one. Behind a TLS terminator, a load balancer or another proxy on the same host, every visitor reaches the public server from 127.0.0.1, so an `allow 127.0.0.1` there would let all of them list your blocks and lift their own. Set `admin_token` as well, and the location answers 401 to any request without `Authorization: Bearer <admin_token>` (compared in constant time). `examples/nginx.conf` does both, and `examples/artex_settings.lua` reads the token from `ARTEX_SHIELD_ADMIN_TOKEN`.

```nginx
server {
    listen 127.0.0.1:8081;                # loopback only, and not the port your proxy forwards to

    location = /_artex/admin {
        content_by_lua_block { require("resty.artex_shield").admin() }
    }
}
```

```bash
curl -H "Authorization: Bearer $ARTEX_SHIELD_ADMIN_TOKEN" http://127.0.0.1:8081/_artex/admin
```

From Lua, `require("resty.artex_shield").shield()` is the shield, with `blocklist()` and `unblock(ip)`.

### WordPress, in Docker

`examples/wordpress/docker-compose.yml` runs WordPress behind OpenResty with the shield, configured from environment variables (`examples/artex_settings.lua`). It is the same setup as the proxy's example, and CI runs it in enforce mode.

```bash
docker compose -f ports/openresty/examples/wordpress/docker-compose.yml up -d --wait
docker compose -f ports/openresty/examples/wordpress/docker-compose.yml run --rm --no-deps -T edge decoys
```

`examples/nginx.conf` is its configuration, and a starting point for your own.

### A static site

`examples/static.conf` serves a directory of files with the shield in front, and needs nothing behind nginx. nginx's own 404s for missing files go back to the shield, so a client guessing paths is scored as it would be in front of an app. Missing images, styles and scripts cost a visitor nothing, as everywhere. Install it as `nginx.conf` next to `mime.types`, with the site in `/var/www/site`. CI runs it in enforce mode with `tests/static.py`.

## What it does with a request

- **The request as sent.** The path comes from the request line the client sent, percent-decoded once, as the reference's servers decode it. nginx's own `$uri` has already resolved `..`, which would hide a traversal. The query is passed on as sent.
- **Headers.** Header bytes are read as Latin-1, and repeated headers are joined: Cookie with `; `, the rest with `, `. On HTTP/1 the order is the order they came in. nginx keeps no order for HTTP/2 and HTTP/3, so there they are read in sorted order; the order only decides which name a honeytoken found in two headers is reported under.
- **Bodies.** With honeytokens set, the first `honeytoken_body_limit` bytes of a request body are read before the request is decided on. nginx reads the whole body first (into memory, or a temporary file when it is larger than `client_body_buffer_size`), as it does anyway to pass it upstream with request buffering on.
- **Feedback from the site.** After the response, the status and `Content-Type` go back to the shield, as the reference's adapters do. That is how 404s count as guessing. Only a 404, or with the client check on a 2xx answer, can change anything, so nothing else is passed on. It runs in a zero-delay timer, because the log phase cannot wait for a lock.
- **Internal redirects.** `try_files`, `error_page` and the like run the access phase again. The shield decides on a request once, and feeds back its final status under the path the client asked for.
- **Long texts.** `configure()` raises PCRE's JIT stack from 32 KB to 1 MB (`ngx.re.opt`, which works only in `init_by_lua`). With that, every pattern gets through the 30 KB hostile inputs of `tests/cost.lua`, which nginx's own header buffers keep requests well under. A text too long even for that is matched again without the JIT on builds with PCRE2, such as the official 1.27 images. Builds with PCRE1 (1.21) log the pattern as failed and count it as a match instead, because PCRE1 without the JIT backtracks on the worker's C stack and can crash it. Any other failure, such as PCRE's match limit, also counts as a match, so text built to exhaust PCRE cannot carry a payload past a pattern.
- **Requests nginx refuses itself.** Requests that are malformed or not allowed (`TRACE`, a lower-case method, a path that climbs above `/`) are answered by nginx with 400 or 405 before any phase runs. The shield does not see them, and neither does the site.

## Where scores and blocks live

| Dict | Holds | When it is full |
| --- | --- | --- |
| `artex_shield` | one track per client (an IPv4 address or an IPv6 /64): 256 bytes after one request, 512 after ten, up to about 4.5 KB for a client with a full request history. 64 MB holds 120,000 to 250,000 | nginx drops the least recently seen; this is the reference's `max_tracks`, done by size |
| `artex_shield_blocks` | one entry per blocked network (128 bytes, about 8,000 per MB), and the locks. 16 MB holds the reference's `max_blocks`, 100,000 | never evicted. `max_blocks` prunes it as the reference does, and a dict too small for that drops the blocks nearest their end to make room, with a warning |

- **Locks.** A request holds its client's lock while it reads and writes that client's track. When two workers decide on one client at once, the second waits for the first, so neither undoes the other's update. A change to the block table takes the table's lock.
- **A stuck lock.** A lock expires after two seconds. A request that waited a second for one goes on without it, logging a warning: no lock rather than no answer.
- **After a reload.** Shared dicts survive `nginx -s reload`, so scores and blocks do too. A restart empties them.
- **The client check's key.** Without `client_check_secret`, the key the client check signs with is made once and kept in the blocks dict, so every worker agrees on it. A restart makes a new one, and cookies signed with the old one stop counting. Set `client_check_secret` to keep them.

## What it costs

Measured on a 4-vCPU cloud container with OpenResty 1.27.1.2, using `tests/nginx/bench.conf`: one nginx worker proxying to an origin that answers 1 KiB, driven by `wrk` with `tests/nginx/visitors.lua`. Every request comes from a new visitor address with a browser's headers, so each is scored in full. These are the ranges over three runs of six seconds.

| | Without the shield | With the shield |
| --- | --- | --- |
| One request at a time, p50 | 50–53 µs | 122–125 µs |
| One request at a time, p99 | 0.2–0.6 ms | 0.46–0.52 ms |
| Requests a second, one worker, 32 connections | 42,000–43,200 | 10,500–10,900 |

The shield adds about 70 µs of one core to a request. `worker_processes auto` gives every core that capacity. `tests/bench.lua` times the decision alone with `resty`:

| Call | Time |
| --- | --- |
| a first-seen visitor | about 40 µs |
| a visitor with 240 requests of history | about 60 µs |
| a blocked client | about 15 µs |
| a 404 fed back | about 60 µs |

## Tests

From `ports/openresty`, with OpenResty's `resty`. The `-fat` Docker images have it.

```bash
SHDICT="--shdict 'artex_shield 64m' --shdict 'artex_shield_blocks 8m' --shdict 'artex_shield_tiny 12k'"
eval resty $SHDICT -I lib -I tests tests/vectors.lua    # spec/vectors.json, state in shared dicts
eval resty $SHDICT -I lib -I tests tests/store.lua      # the shared dicts: tracks, blocks, pruning, locks
eval resty $SHDICT -I lib -I tests tests/adapter.lua    # configure(), decoys(), the stop answers
eval resty $SHDICT -I lib -I tests tests/cost.lua       # every pattern, and hostile text, on 30-64 KB inputs
python build.py --check                                 # patterns.lua and unicode.lua are up to date
```

`sh tests/run.sh` runs the four Lua suites the same way. On a build with PCRE1, `resty` cannot raise PCRE's JIT stack as `configure()` does in nginx, because `resty` keeps `init_by_lua` for itself. So `cost.lua` reports the searches that run out of it, and the smoke test runs the same matrix (`tests/patterns_matrix.lua`) inside nginx, where none may fail.

Two more suites run against real nginx, started with `openresty -c tests/nginx/<conf>`:

- **`tests/edge.py`, with `harness.conf`.** It sends every request in `spec/vectors.json` through OpenResty over HTTP. It checks what the shield was asked (address, method, path, query, headers, body), what it decided, the status the client got, and what was fed back afterwards. It also sends requests the vectors cannot carry: repeated headers, raw bytes, absolute-form targets, the client check's Secure flag.
- **`tests/smoke.py`, with `smoke.conf`.** It runs four workers in enforce mode in front of an origin that counts what reaches it:
  - a block every worker holds;
  - 40 requests from one client at once, of which only the first passes, so no update is lost;
  - 404s fed back to a block;
  - internal redirects decided on once;
  - bodies read from memory and from a temporary file;
  - the client check and the admin location;
  - hostile header text read in linear time;
  - every pattern on the 30 KB hostile inputs, inside nginx with the JIT stack `configure()` sets.

CI runs all of them on OpenResty 1.21.4.3 (PCRE1) and 1.27.1.2 (PCRE2), with `examples/static.conf` serving a static site (`tests/static.py`), and WordPress behind OpenResty (`examples/wordpress/`) in enforce mode on 1.27.

## Porting notes

- **Patterns.** `build.py` writes `lib/resty/artex_shield/patterns.lua` from `spec/patterns.json`. `signatures.lua` translates the patterns to PCRE for `ngx.re`, as the PHP port does. Python's `\s`, `\w` and `\b`, and its i/ı/İ equivalence, are spelled out; PCRE in UTF mode does the rest. When PCRE's JIT runs out of stack, the match is retried without the JIT.
- **Text.** Lua has no Unicode. `py.lua` reproduces urllib's unquote and urlsplit, binascii's base64, `math.fsum` and `str.strip`, and `str.lower()`/`str.upper()` from a table `build.py` takes from Python (`unicode.lua`). Every text reaches the patterns as valid UTF-8, since `ngx.re` refuses anything else. Trimming and splitting never use an end-anchored Lua pattern, because one such as `'"+$'` is quadratic on a long run.
- **Addresses.** `ip.lua` reads and writes them as Python's ipaddress does.
- **Numbers.** A track is stored as text, with times written to 17 digits. OpenResty's cjson keeps 16, and the cadence test needs every bit.
