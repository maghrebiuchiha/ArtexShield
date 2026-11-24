# artex-shield

Layered detection and blocking for [ARTEX](https://github.com/BaaRai/ARTEX)-style automated penetration-testing traffic. Drop-in middleware for Python web apps (Flask, Django, FastAPI, Starlette, any WSGI or ASGI app), Express and plain Node.js servers (`ports/node`), and a reverse proxy, `artex-shield-proxy`, for any other website: WordPress, PHP, a static site. No dependencies.

ARTEX is a self-hosted, LLM-driven pentest platform: a planner breaks a goal into intents and workers run real scanners against the target. It is meant for authorised testing, but nothing stops someone pointing it at a site they do not own. This project is built from a read of its source and targets what it actually does on the wire.

## The air-defence layout

| Layer | Role | In this project |
| --- | --- | --- |
| Radar | See everything, score what looks wrong | Sensors: signatures, header shape, payloads, 404 enumeration fast and slow, request cadence, optional TLS fingerprint |
| IFF | Tell friend from foe | Allowlists, plus authorised assessments verified by reference, source range and time window |
| Decoys | Draw fire away from real assets | Canary paths planted in `robots.txt`, hidden links and JS bundles |
| Tracking | Follow each contact | One decaying threat score per client (IPv4 address, IPv6 /64); optionally, a block widens to the /56 or /48 when one operator keeps changing /64 |
| Fire control | Respond in proportion | Pass, then throttle (429), then block (403) with doubling block times; refuse a single request (403) without touching the address |
| Command post | Share the picture | JSON event log, callback hook, one nginx deny file shared by all workers |

Soft signals cannot stop a request on their own, however many fire or however long a client runs. A block needs either one unambiguous signal (a canary hit, a scanner signature) or several weaker ones adding up.

## What ARTEX does, and how each habit is used

| ARTEX behaviour | Where in its source | Defence |
| --- | --- | --- |
| API-harvest scripts send `Mozilla/5.0 (spa-api-recon)` and `(spa-api-recon spider)` | `skills/api-recon/scripts/` | Blocked on sight |
| The harvester pulls quoted `/api…`, `/admin…`, `/v1…` strings out of JS bundles and requests them | `harvest_static.py` | `js_trap()` plants a dead constant in that exact shape; the first request to it is a block |
| Ships sqlmap, ffuf, nuclei, katana, httpx, dalfox, nmap | `Dockerfile` | Default User-Agents blocked on sight |
| Opt-in label `ARTEX-Assessment/1.0 (engagement=REF)` | `config/task_user_agents.go` | Friendly only if reference, source range and time window all match a record you configured; otherwise hostile |
| Noise profiles pace requests evenly at 2, 5 or 20 per second with at most 250 ms jitter | `egress/egress.go` | Cadence sensor (even spacing) and flood sensor |
| On 429 it honours `Retry-After`, and gives up when the wait exceeds 10, 30 or 60 s | `egress/egress.go` | Throttle replies always ask for at least 120 s; clients that keep coming anyway escalate to a block |
| Probes API docs, admin and debug routes | skills, prompts | Scored only when your app answers 404, so routes you really serve cost nobody anything |
| Browser disguise from Go and Python clients | recorded MITM proxy, scripts | Browser User-Agent without `Accept-Language` is flagged |

## Install

```bash
pip install .            # from this directory
python -m unittest discover -s tests
python examples/simulate.py
```

## Quick start

```python
from artex_shield import Shield, Config, ShieldWSGI, make_canaries

canaries = make_canaries("a-long-random-secret-you-keep")
shield = Shield(Config(
    mode="monitor",                      # log only; switch to "enforce" after a week of clean logs
    canary_paths=canaries,
    trusted_proxies=["10.0.0.0/8"],      # only if you sit behind your own proxy or load balancer
    exempt_paths=["/healthz"],
))

app.wsgi_app = ShieldWSGI(app.wsgi_app, shield)            # Flask
# application = ShieldWSGI(get_wsgi_application(), shield)  # Django, in wsgi.py
# app.add_middleware(ShieldASGI, shield=shield)              # FastAPI / Starlette
```

`ShieldASGI` checks WebSocket handshakes as well as HTTP requests: a blocked address cannot open a socket, and a handshake that would be stopped is closed before it is accepted. Messages sent over an open socket are not inspected.

Events go to the `artex_shield` logger as one JSON object per line. They are written, and your `on_event` callback is called, after the shield's lock is released, so a slow log handler or callback delays only its own request. Every stopped request carries a short reference, also shown to the client, so a wrongly blocked user can quote it to you.

### Behind a proxy

The shield scores one client per address, so it has to see the visitor's address and not your proxy's. List your proxies in `trusted_proxies`; `X-Forwarded-For` is then read from them and from nobody else. Entries with a port (`203.0.113.7:44321`, `[2001:db8::7]:443`) are understood.

A request is passed unscored when no address identifies its sender: the peer is one of your trusted proxies and the header names no client, or there is no peer address at all. Scoring it would put every visitor on one track, and one scanner would block them all. Each such request counts in `stats["unidentified"]`, and an `unidentified` event is logged once per half-life. If you see it, the shield is not protecting those requests, so fix the proxy configuration.

An app server bound to a unix socket reports no peer address. Add `"0.0.0.0/32"` to `trusted_proxies` to take `X-Forwarded-For` from that socket.

### Exempt paths

`exempt_paths` entries cover a path and everything under it, by whole segments: `"/static"` covers `/static` and `/static/app.js`, and not `/static-admin` or `/static/../api`. An entry must start with `/` and name something below the root; `""` and `"/"` are rejected because they would switch the shield off.

### Requests a page made the browser send

Canary paths are public by design: they sit in `robots.txt` and in your JavaScript. So anyone can put `<img src="https://your-site/that-canary">` on a page of their own, or in a forum post on yours, and every visitor's browser will request it. If that counted against the visitor, any stranger could have your visitors blocked. The same goes for attack-looking URLs, admin paths and piles of dead links.

Browsers say when a page, not the person, started a request (the `Sec-Fetch-*` headers; the `Referer` on browsers too old to send them). The shield treats a request as induced when it was started from another site, or is something a page of your own site embeds, such as an image or a frame. An induced request:

- is never held against the visitor: no score, no 404 counted, no block;
- is refused on its own, with a 403, if it trips a hard signal (a canary, a dotfile, a payload, a scanner User-Agent). It never reaches your app. The decision's action is `refuse`.

An address typed or bookmarked, a click inside your site, your site's own scripts, and any client that sends none of these headers are scored as before.

The cost: these headers are the client's word. A tool that marks its requests as induced keeps its address clean. It cannot get an attack request through that way, because every request that trips a hard signal is refused, but it can look for paths and send volume without being scored. Set `score_induced=True` to score these requests like any other; your visitors can then be blocked by a page they merely looked at.

If you call `check()` and `observe()` yourself, pass the decision's flag on: `shield.observe(ip, path, status, decision.induced)`.

### Monitor mode

Monitor mode reports what enforce mode would do, and stops nothing. Two details keep the report honest. A client over the throttle score is reported as `throttle` on each request, but is not scored for ignoring a wait nobody told it about. An address enforce mode would have blocked keeps its score frozen, as it would be, and its later requests are reported as `blocked` events: every one that carries a hard signal, and the rest once per half-life. A person who browses on normally while "blocked" is what a false positive looks like in the log.

### Client-side check (optional)

Off by default. When on, a small script on your HTML pages looks for the marks browser automation leaves, and the shield gives the browser a signed cookie saying the check ran:

- `navigator.webdriver`, which WebDriver, Playwright and Puppeteer set by default;
- the globals PhantomJS, Nightmare, Chrome automation and Playwright add;
- the properties Selenium and ChromeDriver leave on the document.

API calls then tell the shield something it cannot see otherwise:

- **`client:no-check`:** an API call that a page's script made, from a client that loaded your pages but never completed the check. Something is replaying what a browser would do without running your scripts.
- **`client:automation-reported`:** an API call from a client whose check reported automation.

Both are soft signals: 20 points, once per half-life, inside the soft cap, so they never throttle or block on their own. They add to hard evidence. In the simulation, a scraper replaying the API without running the page's script is let through until one probe for `/swagger.json` joins them.

```python
from artex_shield import Config, client_check_tag

config = Config(client_check=True,
                client_check_secret="another-long-random-secret",   # the same on every worker
                client_check_api_prefixes=["/api"])
client_check_tag(config)   # '<script src="/_artex/check.js" async></script>': put it on every HTML page
```

The middleware serves the script at `/_artex/check.js` and answers the check at `/_artex/check` itself; neither reaches your app. To inline the script instead (with a CSP nonce, say), put `artex_shield.client_check.script("/_artex/check")` inside your own `<script>` element. Pass the response's Content-Type to `observe()` if you call it yourself: the shield needs to know which clients were served HTML.

**Visitors without JavaScript are never affected.** Only API requests that a page's script made are judged: fetch and XHR calls, which browsers mark `Sec-Fetch-Mode: cors` with an empty destination. A browser with JavaScript off sends only navigations (links, forms, typed addresses) and subresource loads (images, stylesheets), and those are never judged, with or without the check. Browsers too old to send `Sec-Fetch-*` give themselves away by asking for HTML, images or CSS. The tests check this directly: a visitor without JavaScript gets the same decision on every request with the check on and off.

Also never judged:

- clients that never loaded an HTML page (API integrations);
- the first `client_check_grace` seconds (30) after a client's first page, so the page's own first calls are not judged before its script has run;
- requests another site's page made (see "Requests a page made the browser send").

The cookie is `HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS, signed with `client_check_secret`, and good for `client_check_ttl` (a day). It records when it was issued and what was reported; editing either breaks the signature. Without a secret, each worker makes its own, and a cookie then only counts on the worker that set it.

## In front of any website: `artex-shield-proxy`

For a site that is not a Python app, run the shield as a reverse proxy. Every request goes through the same checks as the middleware, and the ones it allows are forwarded to your site. The site's answers stream back, and their status codes feed the 404 sensors as the middleware's do.

```bash
pip install .
artex-shield-proxy --backend http://127.0.0.1:8000 --listen 0.0.0.0:8080
```

Then send your traffic to port 8080 instead of the site, and stop the site being reachable any other way. The proxy speaks plain HTTP/1.1. For HTTPS, keep your TLS terminator (Caddy, nginx, a load balancer, a CDN) in front of it and list its addresses in `trusted_proxies`, so the shield scores your visitors and not the terminator.

### WordPress, in Docker

```bash
docker compose -f examples/wordpress/docker-compose.yml up -d --build
```

This starts WordPress, MariaDB and the proxy, with only the proxy published, on port 8080. Open `http://localhost:8080` and run the WordPress installer through it. The official WordPress image already believes `X-Forwarded-For` from private addresses, so WordPress and its access log see each visitor's address. Watch the shield's decisions with `docker compose -f examples/wordpress/docker-compose.yml logs -f shield`. It starts in monitor mode; set `ARTEX_SHIELD_MODE=enforce` when a week of logs shows no visitor you would have stopped. CI installs WordPress through the proxy, then checks that a scanner, and a login with a planted honeytoken password, are both blocked before they reach WordPress.

The image alone: `docker build -t artex-shield-proxy .`, then `docker run -p 8080:8080 -e ARTEX_SHIELD_BACKEND=http://your-site:80 artex-shield-proxy`.

### Settings

Settings come from a TOML file (`--config`, or `ARTEX_SHIELD_CONFIG`; Python 3.11 or newer), then from environment variables, then from the command line (`--backend`, `--listen`, `--mode`), each overriding the one before. `examples/proxy.toml` lists them all. `artex-shield-proxy --check-config` prints what is in effect and exits.

Every setting has an environment variable named `ARTEX_SHIELD_` plus the setting in upper case. Lists are comma-separated, true or false is `1`/`0`, `true`/`false`, `yes`/`no` or `on`/`off`, and `ARTEX_SHIELD_ENGAGEMENTS` is a JSON list. An unknown `ARTEX_SHIELD_*` variable stops the proxy at start-up, so a typo cannot go unnoticed.

| `[proxy]` | Default | |
| --- | --- | --- |
| `backend` | none | The site: `http://host:port` or `https://host:port`, with no path |
| `listen` | `0.0.0.0:8080` | Also `[::]:8080`, or a bare port |
| `backend_host_header` | `preserve` | Pass the visitor's `Host` on, or `backend` to send the backend's own |
| `backend_tls_verify` | true | For an `https://` backend |
| `connect_timeout` / `read_timeout` | 10 / 60 s | `read_timeout` covers waiting on the backend, and on a visitor part-way through a request |
| `idle_timeout` | 75 s | A visitor's kept-alive connection between requests |
| `backend_idle_timeout` | 4 s | How long an idle backend connection is reused. Keep it below the backend's own keep-alive timeout |
| `max_idle_backend` | 32 | Idle backend connections kept open |
| `max_header_bytes` | 65536 | Larger request heads are answered 431 |
| `access_log` | false | One line per request on stderr |

Under `[shield]` goes any `Config` field from "Scoring" and the sections above (`mode`, `trusted_proxies`, `exempt_paths`, `allow_cidrs`, the thresholds, `client_check` and its settings, and the rest). Two more make decoys from a secret you keep: `canary_secret` (and `canary_count`, default 3) for canary paths, and `honeytoken_secret` (and `honeytoken_count`, default 2) for credential honeytokens. Authorised assessments are `[[shield.engagements]]` tables with `reference`, `cidrs`, `start` and `end`. Events go to stderr as JSON lines, as from the middleware.

A site behind the proxy may not be written in Python, so it cannot call the helpers that make the snippets to plant. `artex-shield-proxy --print-decoys` prints them for the settings in effect: the `robots.txt` lines, a hidden link and a JS constant for the canaries, the fake credentials for a JS bundle and an HTML comment, and the client check's `<script>` tag. Paste them into your theme or templates. On WordPress, a child theme's `footer.php` or a header-and-footer plugin will do.

### What it does with HTTP

- **Client addresses.** From an untrusted peer, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` and `Forwarded` are thrown away and replaced: the site receives the peer's address and `http`. From a peer in `trusted_proxies` they are kept, and the peer is appended to `X-Forwarded-For`.
- **Bodies stream both ways**, sized or chunked, and are never held whole in memory. There are two exceptions. An answer of 64 KiB or less with a `Content-Length` is sent out together with its head. With honeytokens set, the first `honeytoken_body_limit` bytes (64 KiB) of a request body are read before the shield decides; the rest then streams. `Expect: 100-continue` is answered by the proxy once the shield has allowed the request, or, with honeytokens set and a body coming, before reading it. Interim answers such as `103 Early Hints` are passed on.
- **The client check**, when on, is answered by the proxy: it serves the script at `/_artex/check.js` and the check at `/_artex/check`, and neither reaches the site. The cookie is marked `Secure` when a trusted proxy in front says the visitor used HTTPS. Each answer's `Content-Type` is passed to the shield, which is how it knows which clients were served HTML pages. Put the tag on your pages (see `--print-decoys`) and set `client_check_secret`, so cookies survive a restart.
- **Keep-alive.** Visitors' connections are kept open between requests, and pipelined requests are answered in order, each checked by the shield. Connections to the site are pooled. A `GET`, `HEAD` or other idempotent request without a body, sent on a pooled connection the site had just closed, is retried once on a new one. A `POST` never is.
- **WebSockets.** The handshake is checked like any other request. After the site answers `101`, bytes pass both ways untouched; messages on the socket are not inspected.
- **Hop-by-hop headers** (`Connection` and the headers it names, `Keep-Alive`, `TE`, `Trailer`, `Upgrade` outside a WebSocket handshake, `Proxy-Connection`, `Proxy-Authorization`, `Proxy-Authenticate`) stay on their own connection.
- **Requests that two servers could read differently are refused**, so nothing can ride past the shield inside another request's body. That covers `Content-Length` with `Transfer-Encoding`, lengths that disagree, codings other than `chunked` (501), malformed chunks, folded or malformed headers, control characters in a header, and two `Host` headers. These all answer 400 unless noted. An oversized head answers 431, and `CONNECT` 405.
- **Failures.** A site that cannot be reached answers 502. One that does not answer within `read_timeout` answers 504.
- **Shutting down.** On `SIGTERM` the proxy stops accepting, closes idle connections, and gives requests in flight 10 seconds.

### What it costs

Measured with `python examples/bench_proxy.py` on a 4-vCPU cloud container with Python 3.13: 20,000 requests per row, the range over nine runs. Each request carries a fresh visitor address, so it is scored in full. The origin answers 1 KiB.

| | Straight to the site, p50 | Through the proxy, p50 | Added, p50 | Through the proxy, p99 |
| --- | --- | --- | --- | --- |
| One request at a time | 0.09–0.10 ms | 0.45–0.56 ms | **0.36–0.45 ms** | 1.1–1.6 ms |
| 32 connections at once | 0.7–1.1 ms | 6.6–10 ms | 6–9 ms, queueing | 10–17 ms |

One proxy process handled 3,400–4,600 requests a second on that machine. Below that rate it adds about 0.4 ms to a request; above it, requests queue, as the 32-connection row shows. About 120 µs of each request is the shield's own decision, and the rest is HTTP handling in Python.

### Limits of the proxy

- **One process.** Scores and blocks live in that process's memory and are lost on restart. Set `blocklist_export_path` to keep blocks at your edge as well (see "Pushing blocks to the edge"). Several proxy processes would each keep their own scores; see "Limits".
- **HTTP/1.1 to the site.** The proxy does not terminate TLS and does not speak HTTP/2; the terminator in front of it does both.

## Node.js and Express

`ports/node` is the shield for Express, Connect and plain `http` servers. It has no dependencies and needs Node 20 or newer. It is a port of this package, and CI holds it to the same cases, `spec/vectors.json`, on Node 20, 22 and 24.

```js
const { Shield, artexShield, makeCanaries } = require("artex-shield");     // ports/node

const shield = new Shield({ mode: "monitor", canaryPaths: makeCanaries(process.env.ARTEX_SECRET) });
app.use(artexShield(shield));          // first, before body parsers
```

Settings are the ones above in camelCase (`throttleScore`, `trustedProxies`, `clientCheck`, `honeytokens`, ...), and the decoy helpers give the same values from the same secret. See [ports/node/README.md](ports/node/README.md) for the plain `http` wrapper, WebSocket upgrades, and what the middleware does with bodies.

## Plant the decoys

```python
from artex_shield import robots_txt_block, html_trap, js_trap

robots_txt_block(canaries)   # append to robots.txt
html_trap(canaries[1])       # paste into your base template
js_trap(canaries[0])         # paste into a JS file that ships in your bundle
```

Always list canaries in `robots.txt` so well-behaved crawlers stay out of them. Change the secret and the canaries change with it.

### Credential honeytokens

Fake API keys and passwords, derived from the same secret, planted where someone reading your source would find them. There is no account behind them, so the only way a request carries one is that someone harvested it and is trying it. Presenting one, anywhere, is a block on the first request.

```python
from artex_shield import Config, honeytoken_html, honeytoken_js, make_honeytokens

tokens = make_honeytokens("a-long-random-secret-you-keep")
Config(canary_paths=canaries, honeytokens=tokens)
honeytoken_js(tokens)     # paste into a JS file that ships in your bundle: a dead staging config object
honeytoken_html(tokens)   # paste into your base template: a "remove before release" comment with a login
```

The two helpers plant different pairs, so the log says which one was harvested. The keys look like `api_live_` plus 32 letters and digits. That deliberately matches no real provider's format, so planting them sets off no secret scanner and sends no false leak report to a provider. The passwords are 16 characters with a symbol. The usernames (`svc-deploy`, `admin-legacy`) are decoration: they could be someone's real account name, so they trigger nothing on their own.

Where the shield looks:

- every request header, with `Authorization: Basic` unpacked; the `Referer` is skipped, since it is only the browser repeating an address;
- cookies, the query string and the path;
- the first 64 KB of the body (`honeytoken_body_limit`).

Each place is searched as sent and URL-decoded, so a password typed into a login form is caught however it is encoded. The adapters read the body only when honeytokens are set, and hand it to your app unchanged. A WSGI body of unknown length is not read unless the server marks its end, since reading it could block.

Like canaries, honeytokens are public by design, so a hostile page could make a visitor's browser send one: `<img src="/api/items?api_key=...">`. That request is refused, and the visitor's address is not blocked (see "Requests a page made the browser send"). A request carrying one in a header or cookie cannot be forced that way, because another site's page cannot set them.

If you deploy by uploading your bundle through your own site, the upload carries the planted tokens: exempt that path (`exempt_paths`) or the deploy address (`allow_cidrs`).

## Authorised assessments

```python
from datetime import datetime, timezone
from artex_shield import Engagement

Config(engagements=[Engagement(
    reference="FS-17",
    cidrs=["198.51.100.24/32"],
    start=datetime(2026, 12, 1, 10, 0, tzinfo=timezone.utc),
    end=datetime(2026, 12, 1, 18, 0, tzinfo=timezone.utc),
)])
```

A User-Agent is self-declared, so the label alone is never trusted. ARTEX's own documentation says the same.

## Scoring

| Signal | Points | Repeats |
| --- | --- | --- |
| Canary path | 100 | every hit |
| Honeytoken (a planted fake API key or password) in a header, cookie, query, path or the first 64 KB of the body | the block score | every hit |
| ARTEX or scanner User-Agent, unverified assessment label | 100 | every hit |
| Dotfile or key probe (`/.env`, `/.git/`, `/id_rsa`) | 60 | every hit |
| Dump, backup or editor leftover by name (`db.sql`, `site-backup.zip`, `index.php.bak`) that returned 404 | 60 | every hit |
| Attack payload in the URL (SQL injection, XSS, traversal, command injection, template injection, cloud metadata address) | 50 each kind | every hit |
| JNDI lookup or callback domain in the URL or in any header, cookies included | 50 each kind | every hit |
| Headless browser User-Agent | 40 | once per half-life |
| Denylisted TLS fingerprint (from your edge) | 40 | once per half-life |
| 15 different missing paths (404) in 60 s | 40 | per 15 |
| More than 240 requests in 60 s | 30 | per window |
| TRACE, TRACK, CONNECT, DEBUG | 30 | every hit |
| PROPFIND | 30 | once per half-life |
| Recon path that returned 404 (`/admin` at the root; `swagger.json`, `openapi.json`, `graphql`, `actuator`, `wp-login.php` and the like at any depth) | 25 | every hit |
| Evenly spaced requests; browser User-Agent without browser headers; empty User-Agent | 20 each | once per half-life |
| HTTP library User-Agent | 15 | once per half-life |
| Optional client check: API call a page's script made, from a client that loaded pages but never completed the check, or whose check reported automation | 20 each | once per half-life |
| Each newly missing path after the first 60 in an hour | 10 | every hit |
| Request sent while told to wait (enforce mode only) | 5 | every hit |

Two things act without points:

| Situation | What happens |
| --- | --- |
| A request a web page made the browser send (see "Requests a page made the browser send") | Never scored. Refused with a 403 if the request itself carries a hard signal: a canary, a scanner User-Agent, a dotfile, a payload or an odd method. |
| Only with `v6_escalate_after` set (off by default): that many blocked IPv6 /64s inside one /56, or /56s inside one /48 | The whole prefix is blocked for the first-block time, and one entry replaces them. See "IPv6 block widening" before turning it on. |

Throttle at 50, block at 100. Scores halve every 10 minutes. First block lasts 1 hour and doubles per repeat, up to 24 hours. Everything is a `Config` field.

The signals that repeat once per half-life are the soft ones. Together they hold at most `soft_cap` points, 40 by default and always below the throttle score, so a headless monitor or a script polling on the second is never stopped for that alone. They still count beside hard evidence: a headless browser that also probes for `/swagger.json` is throttled.

A 404 counts toward enumeration once per path: polling one missing resource, reloading a page of dead links, or meeting the same broken image on every page adds nothing after the first time. 404s for page assets (`enum_ignore_extensions`: scripts, styles, source maps, images, fonts, media) do not count, since a stale page asking for files a deploy removed is not guessing. If a route of yours answers 404 to mean "no such item", list it in `enum_ignore_prefixes`. Recon paths and dump names that return 404 still score wherever they are.

A file name alone is not evidence: sites really do serve `employee-handbook.zip` and `release-notes.old`. Names that look like dumps or backups are scored only when your app answers 404, so a request for one that exists is served and costs nothing.

Guessing slower than 15 paths a minute is held to an allowance: 60 newly missing paths an hour (`slow_enum_budget`, `slow_enum_window`). Each one past that scores 10, so a client that keeps guessing is throttled within a handful more and blocked if it carries on. The allowance counts the same 404s as the fast sensor, with the same exceptions.

Payload patterns read the decoded path and each decoded query name and value. The `?`, `&` and `=` of the query string itself are not part of that text, so `?page=2&id=5` is four plain words. They are matched twice, the second time with SQL comments turned into spaces, so `UNION/**/SELECT` reads as `UNION SELECT`.

- **Command injection.** After a single `;`, `|`, `&` or line break, a short command name such as `id`, `cat` or `ls` counts only with an argument behind it (`;cat /etc/passwd`), because those characters also separate ordinary lists (`fields=name|id|price`). `whoami`, command substitution, `&&` and `||` count without one.
- **SQL injection.** Each keyword counts with the part of the attack that prose does not have, so a search box can take book titles, recipes and questions about SQL.
  - `UNION SELECT` followed by a select list (`NULL`, `1,2,3`, `@@version`, a call, a column then `FROM`), or straight after a quote, bracket or number. Not "student union select committee".
  - `SLEEP(5)` and `BENCHMARK(1000000,…)` written as MySQL needs them, with no space before the bracket and not as a method. Not "Why We Sleep (2017)", "sleep (8 hours)" or `time.sleep(5)`.
  - `WAITFOR DELAY '0:0:5'` with its quoted time, and `FROM information_schema`. Not "waitfor delay sql server example" or "information_schema.tables size".
  - After a quote, `OR`/`AND` with a comparison between literals (`'1'='1`, `1=1`, `'a' like 'a`), a comment, a function call, `TRUE`/`FALSE`, or a number left for the app's own quote to close (`' or '1`). Not quoted titles joined by "and" (`'Dune' and '1984'`), and not a filter with a column on the left (`status='open' and owner='sam'`).
  - A tautology after `OR` or `AND` anywhere: `or 1=1`, `'or'1'='1`.
- **XSS.** A tag or scheme counts with code behind it.
  - `<script` with a `src`, a call or assignment after it, or a closing `</script>`. Not "how to use <script tags" or "what does the <script> tag do".
  - `javascript:` followed by code (a call, backtick, `=`, `;` or `//`). Not "javascript: the good parts", and not `javascript:void(0)` alone.
  - An event handler with code after the `=`: the common ones anywhere but after a dot (`window.onload = …` is a script, not an attribute), any handler inside a tag or straight after a closing quote (`<details ontoggle=alert(1)>`, `" onpointerenter=…`). Not `?online=1`, "use onclick= in html" or "img onerror= fallback image".
  - `<iframe` with a `src` or `srcdoc`. A bare `<iframe>` or `<svg>` is a question about HTML.
- **Path traversal.** Three levels up, or up into a place worth reading (`/etc`, `windows`, `WEB-INF`, a dotfile), or two levels up to a server-side or config file (`../../config.php`). Two levels to a module (`cannot find module '../../utils'`) is how code imports things.
- **Template injection.** Arithmetic probes (`{{7*7}}`, `{{7*'7'}}`, `${7*7}`, `#{7*7}`) and the objects engines expose, bare or being dug into (`{{config}}`, `{{request.application…}}`). `{{email}}` from a mail merge that did not run is neither.

A search that pastes a whole payload, such as `' or 1=1--`, `<script>alert(1)</script>` or `../../../etc/passwd`, still scores: it is the attack, whoever typed it.

Headers are searched for JNDI lookups and callback domains only, in full and cookies included. They are not searched for the payload kinds above. A `Referer` or cookie repeats on every request, and a single-page app puts whatever the person typed into the address without asking the server, so one innocent match there would score a visitor again and again.

## IPv6 block widening

Off by default. An IPv6 client is tracked and blocked by its /64, the network one household or server is usually given. One operator can hold a whole /56 or /48 and move to a fresh /64 for every request, starting from zero each time. `v6_escalate_after` answers that: set it to N and, when N /64s inside one /56 are blocked at the same time, the whole /56 is blocked; N blocked /56s inside one /48 get the /48 blocked the same way.

```python
Config(v6_escalate_after=8)   # 0, the default, is off; 1 is refused
```

The risk is who else is in that prefix. A /56 is often one household's or one customer's allocation, but some providers, mobile networks and hosting platforms hand out /64s to many customers from a shared /56 or /48. Widening there blocks every customer in the pool together, for the first-block time (an hour by default), because of what a few neighbours did. `examples/simulate.py` shows it: 24 households sharing a /56 with 10 blocked scanners are untouched with widening off, and lose every request with `v6_escalate_after=8`.

Turn it on only if you know how your visitors' providers allocate addresses, or you are under a rotating-/64 attack and accept blocking neighbours. Watch the log for `behavior:network-rotation` events, which mark each widened block, and run in `monitor` mode first.

## Pushing blocks to the edge

Set `blocklist_export_path="/etc/nginx/artex-deny.conf"` and include that file in your nginx `server` block; see `examples/nginx.conf`. Reload nginx on a timer or with a file watcher.

- **All workers write one file.** Each worker merges its blocks with what the others wrote, so the file holds the union and this is the way to share blocks between workers. Expiry times are kept next to it in `artex-deny.conf.state`, and writers take turns on `artex-deny.conf.lock`. Both the file and its state are replaced atomically.
- **Entries leave when they expire.** The file is rewritten on each new block, on `unblock()`, and when its earliest entry expires. A timer does the last one, so it happens even if no request arrives; the timer is a daemon thread and exists only while an export path is set.
- **Only networks are written.** Anything else in the state file is dropped, so a damaged file cannot break `nginx -t`.
- **The block table is bounded.** At most `max_blocks` (100,000) are held; past that, the tenth nearest to expiry is dropped. Expired blocks are swept when a new block is added, at most once a minute, and whenever the list is read.

A file write happens after the shield's lock is released, so a slow disk delays only the request that caused it. `unblock()` lifts a block in the worker it is called in and removes it from the file; another worker that blocked the same address on its own will write it back.

For the TLS sensor, have your edge pass a JA3 or JA4 value in a header and set `tls_header` and `tls_denylist`. The denylist ships empty on purpose: fingerprints change with each Go and Python release, so capture your own from traffic you have already confirmed as hostile.

## Limits

- **There is no list of ARTEX addresses.** It is self-hosted, so it arrives from wherever its operator runs it. Addresses are blocked for behaviour, and an operator with fresh addresses starts each one from zero. On IPv6 that includes every fresh /64 inside one /56 or /48, unless you turn on block widening (`v6_escalate_after`, off by default; see "IPv6 block widening"). Even with it on, an operator with addresses in unrelated prefixes starts from zero in each.
- **Signatures are the weak layer.** Every User-Agent here can be changed with one flag. The decoys and behaviour sensors are what hold against a careful operator, and a patient one running slowly, with full browser headers, avoiding guesswork, can still get through. This reduces what automated tooling finds cheaply. It does not fix vulnerabilities.
- **`Sec-Fetch-Site` is the client's word.** A request is taken as induced, and so never scored, when its `Sec-Fetch-Site` header says `cross-site` or `same-site`, when it says `same-origin` and `Sec-Fetch-Dest` names something a page embeds, or, without those headers, when the `Referer` is from another host. Real browsers set these and a page cannot forge them, which is what protects your visitors from being blocked by a page they merely looked at. A tool can send them too. It gains nothing for an attack request, since every induced request that trips a hard signal is refused, but it can guess paths and send volume without its address being scored: the 404, recon, slow-guessing and flood sensors do not see it. `score_induced=True` closes that gap and reopens the other one.
- **A link someone is talked into opening** is not induced as far as the browser can tell if it is pasted or opened from a mail client (`Sec-Fetch-Site: none`), so a canary link sent by e-mail still blocks the person who opens it.
- **About 60 guessed paths an hour per address are still free**, and 14 a minute until that allowance is spent. Guessing values of one query parameter (`/item?id=1`, `?id=2`) is not counted at all, because the path is the same.
- **Payload patterns are a net, not a parser.** A bare `;id` or `|id` is not scored, because it reads the same as a list. Injection sent only in a `Referer`, cookie or other header is not scored, apart from JNDI lookups and callback domains. Encodings a pattern does not expect get through. To let search text through, some payload forms are not scored: a bare `<script>` tag with no code, a lone `<svg>` or `<iframe>`, a number left dangling after `OR` (`' or 1`), `UNION SELECT` after a plain word with a one-word list (`x union select a`), and two levels of `../` to a file with no server-side extension. And a search that is itself a payload (`sleep(5)`, `{{7*7}}`, `' or 1=1--`) still scores.
- **The client check is a speed bump, not a lock.** Anyone who reads this README can call `/_artex/check?f=0` and get a clean cookie, and a stealth plugin can hide `navigator.webdriver` (ARTEX ships none today; the weekly ARTEX check watches for one). It catches clients that do not know it is there, and only ever as soft evidence.
- **Request bodies are inspected only for honeytokens**, and only their first 64 KB; attack payloads in a body are not scored. Nor are messages on an open WebSocket inspected, by the middleware or the proxy, and nmap port scans never reach a web app at all. Keep your firewall and, if you have one, your WAF.
- **An exposed dump that really exists is served.** The shield cannot tell `db-backup.sql` from `employee-handbook.zip` until the app answers, so it waits for the 404.
- **Shared addresses.** Blocking an address also blocks everyone behind the same NAT, VPN or campus network. IPv6 block widening, if you turn it on, covers more: a /56 can be one household or, with some providers, hundreds of customers. This is why blocks expire and why `monitor` is the default mode.
- **Scores are per process.** With several workers each keeps its own scores, so thresholds are effectively multiplied, and a block made by one worker is enforced by the others only at the edge, through the shared deny file. Run one worker, or enforce the file in nginx, until a shared store is added. `artex-shield-proxy` is a single process, so it keeps one set of scores.
- **Search engines.** Crawlers that honour `robots.txt` will not touch canaries. Verified-bot checks by reverse DNS are not included; add crawler ranges to `allow_cidrs` if you see them scored. A crawler working through many dead links will also run into the hourly allowance.

## Layout

```
src/artex_shield/
  core.py         Config, Shield: tracking, sensors, fire control
  signatures.py   patterns for ARTEX and its toolchain
  decoys.py       canaries, credential honeytokens, and snippets to plant them
  middleware.py   WSGI and ASGI adapters
  proxy.py        artex-shield-proxy, the reverse proxy
  util.py         address and decoding helpers
  client_check.py the optional client-side check: script, signed cookie
tests/            231 tests, including every case in spec/vectors.json, run directly and through the proxy
examples/         Flask, FastAPI, nginx, WordPress in Docker, a proxy config and benchmark, and a campaign simulation
spec/             vectors.json, patterns.json and SPEC.md: the cases, patterns and rules every port is checked against
ports/node/       the Node.js / Express port
Dockerfile        the proxy's image
```
