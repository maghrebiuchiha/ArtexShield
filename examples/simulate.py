"""Replay an ARTEX-style campaign and ordinary visitors against the shield.

Nothing leaves this process: requests are plain function calls on a fake
clock. Run it to see the engagement sequence and to sanity-check tuning.

    python examples/simulate.py
"""
import logging
import random

from artex_shield import Config, Shield, make_canaries

logging.getLogger("artex_shield").addHandler(logging.NullHandler())
logging.getLogger("artex_shield").propagate = False

CHROME = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/131.0.0.0 Safari/537.36")
BROWSER = {"User-Agent": CHROME, "Accept": "text/html", "Accept-Language": "en-US"}
SITE = {"/", "/products", "/about", "/api/items", "/login", "/static/app.js"}


class Clock:
    t = 1_800_000_000.0

    def __call__(self):
        return self.t


def send(shield, clock, ip, path, headers, query="", gap=0.0, log=None, who=""):
    clock.t += gap
    d = shield.check(ip, "GET", path, query, headers)
    status = {"block": 403, "throttle": 429}.get(d.action) if d.stop else (200 if path in SITE else 404)
    if not d.stop:
        shield.observe(ip, path, status)
    if log is not None:
        log.append((who, path + ("?" + query if query else ""), status, int(d.score), ",".join(d.hits)))
    return status


def campaign(shield, clock, canaries):
    """One operator, three addresses, the phases an ARTEX run goes through."""
    log, rng = [], random.Random(7)

    # Phase 1 - static API harvest with the bundled script's own User-Agent.
    send(shield, clock, "203.0.113.10", "/", {"User-Agent": "Mozilla/5.0 (spa-api-recon)"}, log=log, who="harvester")

    # Phase 2 - new address, browser disguise, "quiet" noise profile (2 req/s + jitter).
    # It requests what the harvest pulled out of the JS bundle, canary included.
    ip, disguise = "203.0.113.11", {"User-Agent": CHROME}
    for path in ["/", "/static/app.js", "/api/items", "/swagger.json", "/openapi.json", canaries[0], "/api/items"]:
        send(shield, clock, ip, path, disguise, gap=0.5 + rng.uniform(0, 0.25), log=log, who="paced recon")

    # Phase 3 - third address, a paced fuzzing and injection run.
    ip = "203.0.113.12"
    for i in range(40):
        status = send(shield, clock, ip, f"/{rng.choice(['backup', 'old', 'test', 'dev', 'tmp'])}{i}", disguise,
                      gap=0.2, log=log, who="fuzz")
        if status == 403:
            break
    for q in ["id=1' UNION SELECT null--", "id=1 AND SLEEP(5)"]:
        send(shield, clock, ip, "/api/items", disguise, query=q, gap=0.2, log=log, who="injection")
    return log


def visitors(shield, clock, n=300):
    """People, a polling dashboard and an API script. None should be stopped."""
    rng, stopped = random.Random(11), 0
    for u in range(n):
        ip = f"198.18.{u // 250}.{u % 250 + 1}"
        kind = u % 10
        if kind == 0:        # dashboard polling every second, browser headers
            for _ in range(120):
                stopped += send(shield, clock, ip, "/api/items", BROWSER, gap=1.0) in (403, 429)
        elif kind == 1:      # integration script, irregular
            for _ in range(60):
                stopped += send(shield, clock, ip, "/api/items", {"User-Agent": "python-requests/2.32"},
                                gap=rng.uniform(2, 30)) in (403, 429)
        else:                # browsing: pause, then a burst of assets, the odd dead link
            for _ in range(rng.randint(3, 25)):
                clock.t += rng.uniform(2, 60)
                for _ in range(rng.randint(2, 30)):
                    path = rng.choice(sorted(SITE)) if rng.random() > 0.03 else f"/dead-{rng.randint(0, 99)}"
                    stopped += send(shield, clock, ip, path, BROWSER, gap=rng.uniform(0.001, 0.1)) in (403, 429)
    return stopped


def main():
    clock = Clock()
    canaries = make_canaries("demo-secret")
    shield = Shield(Config(mode="enforce", canary_paths=canaries), clock=clock)

    print(f"{'actor':<12} {'request':<44} {'resp':>4} {'score':>5}  signals")
    for who, req, status, score, hits in campaign(shield, clock, canaries):
        print(f"{who:<12} {req[:44]:<44} {status:>4} {score:>5}  {hits}")

    print(f"\nactive blocks: {sorted(shield.blocklist())}")
    before = shield.stats["requests"]
    stopped = visitors(shield, clock)
    print(f"legitimate traffic: {shield.stats['requests'] - before} requests from 300 clients, {stopped} stopped")
    return stopped


if __name__ == "__main__":
    raise SystemExit(1 if main() else 0)
