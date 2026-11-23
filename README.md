# artex-shield

Layered detection and blocking for [ARTEX](https://github.com/BaaRai/ARTEX)-style automated penetration-testing traffic. Drop-in middleware for Python web apps (Flask, Django, FastAPI, Starlette, any WSGI or ASGI app). Standard library only.

ARTEX is a self-hosted, LLM-driven pentest platform: a planner breaks a goal into intents and workers run real scanners against the target. It is meant for authorised testing, but nothing stops someone pointing it at a site they do not own. This project is built from a read of its source and targets what it actually does on the wire.

## The air-defence layout

| Layer | Role | In this project |
| --- | --- | --- |
| Radar | See everything, score what looks wrong | Sensors: signatures, header shape, payloads, 404 enumeration, request cadence, optional TLS fingerprint |
| IFF | Tell friend from foe | Allowlists, plus authorised assessments verified by reference, source range and time window |
| Decoys | Draw fire away from real assets | Canary paths planted in `robots.txt`, hidden links and JS bundles |
| Tracking | Follow each contact | One decaying threat score per client (IPv4 address, IPv6 /64) |
| Fire control | Respond in proportion | Pass, then throttle (429), then block (403) with doubling block times; refuse a single request (403) without touching the address |
| Command post | Share the picture | JSON event log, callback hook, blocklist export for nginx |

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

Events go to the `artex_shield` logger as one JSON object per line. Every stopped request carries a short reference, also shown to the client, so a wrongly blocked user can quote it to you.

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

## Plant the decoys

```python
from artex_shield import robots_txt_block, html_trap, js_trap

robots_txt_block(canaries)   # append to robots.txt
html_trap(canaries[1])       # paste into your base template
js_trap(canaries[0])         # paste into a JS file that ships in your bundle
```

Always list canaries in `robots.txt` so well-behaved crawlers stay out of them. Change the secret and the canaries change with it.

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
| ARTEX or scanner User-Agent, unverified assessment label | 100 | every hit |
| Dotfile or key probe (`/.env`, `/.git/`, `/id_rsa`) | 60 | every hit |
| Dump, backup or editor leftover by name (`db.sql`, `site-backup.zip`, `index.php.bak`) that returned 404 | 60 | every hit |
| Attack payload in URL; JNDI or callback domain in URL or headers | 50 each | every hit |
| Headless browser User-Agent | 40 | once per half-life |
| Denylisted TLS fingerprint (from your edge) | 40 | once per half-life |
| 15 different missing paths (404) in 60 s | 40 | per 15 |
| More than 240 requests in 60 s | 30 | per window |
| TRACE, TRACK, CONNECT, DEBUG | 30 | every hit |
| PROPFIND | 30 | once per half-life |
| Recon path that returned 404 | 25 | every hit |
| Evenly spaced requests; browser User-Agent without browser headers; empty User-Agent | 20 each | once per half-life |
| HTTP library User-Agent | 15 | once per half-life |
| Request sent while told to wait | 5 | every hit |

Throttle at 50, block at 100. Scores halve every 10 minutes. First block lasts 1 hour and doubles per repeat, up to 24 hours. Everything is a `Config` field.

The signals that repeat once per half-life are the soft ones. Together they hold at most `soft_cap` points, 40 by default and always below the throttle score, so a headless monitor or a script polling on the second is never stopped for that alone. They still count beside hard evidence: a headless browser that also probes for `/swagger.json` is throttled.

A 404 counts toward enumeration once per path: polling one missing resource, reloading a page of dead links, or meeting the same broken image on every page adds nothing after the first time. 404s for page assets (`enum_ignore_extensions`: scripts, styles, source maps, images, fonts, media) do not count, since a stale page asking for files a deploy removed is not guessing. If a route of yours answers 404 to mean "no such item", list it in `enum_ignore_prefixes`. Recon paths and dump names that return 404 still score wherever they are.

A file name alone is not evidence: sites really do serve `employee-handbook.zip` and `release-notes.old`. Names that look like dumps or backups are scored only when your app answers 404, so a request for one that exists is served and costs nothing.

Payload patterns read the decoded path and each decoded query name and value. The `?`, `&` and `=` of the query string itself are not part of that text, so `?page=2&id=5` is four plain words. After a single `;`, `|` or `&`, a short command name such as `id` or `cat` counts only with an argument behind it (`;cat /etc/passwd`), because those characters also separate ordinary lists (`fields=name|id|price`). Command substitution, `&&` and `||` count without one.

## Pushing blocks to the edge

Set `blocklist_export_path="/etc/nginx/artex-deny.conf"` and include that file in your nginx `server` block; see `examples/nginx.conf`. The file is rewritten atomically on each new block. Reload nginx on a timer or with a file watcher.

For the TLS sensor, have your edge pass a JA3 or JA4 value in a header and set `tls_header` and `tls_denylist`. The denylist ships empty on purpose: fingerprints change with each Go and Python release, so capture your own from traffic you have already confirmed as hostile.

## Limits

- **There is no list of ARTEX addresses.** It is self-hosted, so it arrives from wherever its operator runs it. Addresses are blocked for behaviour, and an operator with fresh addresses starts each one from zero.
- **Signatures are the weak layer.** Every User-Agent here can be changed with one flag. The decoys and behaviour sensors are what hold against a careful operator, and a patient one running slowly, with full browser headers, avoiding guesswork, can still get through. This reduces what automated tooling finds cheaply. It does not fix vulnerabilities.
- **Shared addresses.** Blocking an address also blocks everyone behind the same NAT, VPN or campus network. This is why blocks expire and why `monitor` is the default mode.
- **State is per process.** With several workers each keeps its own scores, so thresholds are effectively multiplied. Use the nginx export to share blocks, or run one worker until a shared store is added.
- **Request bodies are not inspected**, and nmap port scans never reach a web app at all. Keep your firewall and, if you have one, your WAF.
- **Induced requests are taken at the browser's word.** See "Requests a page made the browser send": a tool can claim that context to avoid being scored for path guessing and volume. It was a choice between that and letting any web page get your visitors blocked.
- **A link someone is talked into opening** is not induced as far as the browser can tell if it is pasted or opened from a mail client, so a canary link sent by e-mail still blocks the person who opens it.
- **An exposed dump that really exists is served.** The shield used to stop the first request for anything named like a backup. It cannot tell `db-backup.sql` from `employee-handbook.zip` until the app answers, so it now waits for the 404.
- **Search engines.** Crawlers that honour `robots.txt` will not touch canaries. Verified-bot checks by reverse DNS are not included; add crawler ranges to `allow_cidrs` if you see them scored.

## Layout

```
src/artex_shield/
  core.py         Config, Shield: tracking, sensors, fire control
  signatures.py   patterns for ARTEX and its toolchain
  decoys.py       canary generation and trap snippets
  middleware.py   WSGI and ASGI adapters
  util.py         address and decoding helpers
tests/            70 tests on simulated traffic
examples/         Flask, FastAPI, nginx, and a campaign simulation
```
