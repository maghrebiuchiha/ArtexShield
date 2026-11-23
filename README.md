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
| Fire control | Respond in proportion | Pass, then throttle (429), then block (403) with doubling block times |
| Command post | Share the picture | JSON event log, callback hook, blocklist export for nginx |

No single soft signal can stop a request. A block needs either one unambiguous signal (a canary hit, a scanner signature) or several weaker ones adding up.

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
| Sensitive file probe (`/.env`, `/.git/`, dumps, backups) | 60 | every hit |
| Attack payload in URL; JNDI or callback domain in URL or headers | 50 each | every hit |
| Headless browser User-Agent | 40 | once per half-life |
| Denylisted TLS fingerprint (from your edge) | 40 | once per half-life |
| 15 or more 404s in 60 s | 40 | per 15 |
| More than 240 requests in 60 s | 30 | per window |
| TRACE, TRACK, CONNECT, DEBUG, PROPFIND | 30 | every hit |
| Recon path that returned 404 | 25 | every hit |
| Evenly spaced requests; browser User-Agent without browser headers; empty User-Agent | 20 each | once per half-life |
| HTTP library User-Agent | 15 | once per half-life |
| Request sent while told to wait | 5 | every hit |

Throttle at 50, block at 100. Scores halve every 10 minutes. First block lasts 1 hour and doubles per repeat, up to 24 hours. Everything is a `Config` field.

## Pushing blocks to the edge

Set `blocklist_export_path="/etc/nginx/artex-deny.conf"` and include that file in your nginx `server` block; see `examples/nginx.conf`. The file is rewritten atomically on each new block. Reload nginx on a timer or with a file watcher.

For the TLS sensor, have your edge pass a JA3 or JA4 value in a header and set `tls_header` and `tls_denylist`. The denylist ships empty on purpose: fingerprints change with each Go and Python release, so capture your own from traffic you have already confirmed as hostile.

## Limits

- **There is no list of ARTEX addresses.** It is self-hosted, so it arrives from wherever its operator runs it. Addresses are blocked for behaviour, and an operator with fresh addresses starts each one from zero.
- **Signatures are the weak layer.** Every User-Agent here can be changed with one flag. The decoys and behaviour sensors are what hold against a careful operator, and a patient one running slowly, with full browser headers, avoiding guesswork, can still get through. This reduces what automated tooling finds cheaply. It does not fix vulnerabilities.
- **Shared addresses.** Blocking an address also blocks everyone behind the same NAT, VPN or campus network. This is why blocks expire and why `monitor` is the default mode.
- **State is per process.** With several workers each keeps its own scores, so thresholds are effectively multiplied. Use the nginx export to share blocks, or run one worker until a shared store is added.
- **Request bodies are not inspected**, and nmap port scans never reach a web app at all. Keep your firewall and, if you have one, your WAF.
- **Search engines.** Crawlers that honour `robots.txt` will not touch canaries. Verified-bot checks by reverse DNS are not included; add crawler ranges to `allow_cidrs` if you see them scored.

## Layout

```
src/artex_shield/
  core.py         Config, Shield: tracking, sensors, fire control
  signatures.py   patterns for ARTEX and its toolchain
  decoys.py       canary generation and trap snippets
  middleware.py   WSGI and ASGI adapters
  util.py         address and decoding helpers
tests/            31 tests on simulated traffic
examples/         Flask, FastAPI, nginx, and a campaign simulation
```
