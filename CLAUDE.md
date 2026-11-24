# artex-shield

Python middleware that detects and blocks ARTEX-style automated pentest traffic
(https://github.com/BaaRai/ARTEX). Standard library only, Python 3.9+.

## Layout
- `src/artex_shield/core.py` - Config, Shield: per-client scoring, sensors, throttle/block logic
- `src/artex_shield/signatures.py` - User-Agent, path and payload patterns
- `src/artex_shield/decoys.py` - canary paths, credential honeytokens, and snippets to plant them
- `src/artex_shield/middleware.py` - WSGI and ASGI adapters
- `src/artex_shield/client_check.py` - optional client-side check: automation-reporting script, signed cookie
- `src/artex_shield/proxy.py` - `artex-shield-proxy`, the asyncio reverse proxy for non-Python sites; `Dockerfile`,
  `examples/wordpress/` (compose file and CI smoke test), `examples/proxy.toml`
- `tests/test_shield.py` - simulated traffic, fake clock, no network
- `tests/test_proxy.py` - the proxy against a local origin on 127.0.0.1, and spec/vectors.json replayed through it
- `spec/vectors.json`, `spec/patterns.json`, `spec/SPEC.md` - the cases, signature patterns and rules every port must
  match; `tests/test_vectors.py` runs them
- `ports/node/` - the Node.js / Express port (no dependencies); `lib/patterns.json` is a copy of `spec/patterns.json`
- `ports/php/artex-shield/` - the WordPress plugin and PHP port (PHP 8.1+, no dependencies); `patterns.json` is a copy of
  `spec/patterns.json`, `patterns.php` its translation (`php ports/php/build.php`)
- `examples/simulate.py` - campaign vs. legitimate-traffic soak; exits 1 if any legit request is stopped

## Commands
- Tests: `python -W error -m unittest discover -s tests`
- Simulation: `python examples/simulate.py`
- Proxy latency: `python examples/bench_proxy.py`; update the numbers in README.md ("What it costs") if the proxy changes
- Vectors: `python spec/export_vectors.py` after a deliberate behaviour change (review the diff: it binds every port);
  CI runs `--check`. If signatures.py changed, also `cd ports/node && npm run sync-patterns`, and copy
  spec/patterns.json to ports/php/artex-shield/ and run `php ports/php/build.php`
- Node port: `cd ports/node && npm test` (the Express example runs when `npm install --no-save express` is done)
- PHP port: `cd ports/php && php tests/vectors.php && php tests/vectors.php --files && php tests/vectors.php --cache
  && php tests/cost.php && php tests/plugin.php`; real WordPress runs in CI only (`tests/wordpress/`)

## Rules
- No runtime dependencies. Optional integrations (e.g. Redis) go behind an extra.
- Every new sensor needs a test that it fires on hostile traffic AND a check that
  `examples/simulate.py` still reports 0 legitimate requests stopped.
- Soft signals must not be able to throttle on their own.
- Default mode stays `monitor`.
- Every port passes every case in spec/vectors.json; change the reference and the ports together.

## Roadmap
1. Shared state (Redis) so scores and blocks hold across workers
2. Score request bodies (POST payloads)
3. Node/Express port
