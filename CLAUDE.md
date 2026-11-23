# artex-shield

Python middleware that detects and blocks ARTEX-style automated pentest traffic
(https://github.com/BaaRai/ARTEX). Standard library only, Python 3.9+.

## Layout
- `src/artex_shield/core.py` - Config, Shield: per-client scoring, sensors, throttle/block logic
- `src/artex_shield/signatures.py` - User-Agent, path and payload patterns
- `src/artex_shield/decoys.py` - canary paths and trap snippets
- `src/artex_shield/middleware.py` - WSGI and ASGI adapters
- `tests/test_shield.py` - simulated traffic, fake clock, no network
- `examples/simulate.py` - campaign vs. legitimate-traffic soak; exits 1 if any legit request is stopped

## Commands
- Tests: `python -W error -m unittest discover -s tests`
- Simulation: `python examples/simulate.py`

## Rules
- No runtime dependencies. Optional integrations (e.g. Redis) go behind an extra.
- Every new sensor needs a test that it fires on hostile traffic AND a check that
  `examples/simulate.py` still reports 0 legitimate requests stopped.
- Soft signals must not be able to throttle on their own.
- Default mode stays `monitor`.

## Roadmap
1. Shared state (Redis) so scores and blocks hold across workers
2. Score request bodies (POST payloads)
3. Node/Express port
