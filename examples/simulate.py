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
SCRIPT = {"User-Agent": "python-requests/2.32"}
# A synthetic-monitoring browser: headless, and it sends no Accept-Language.
HEADLESS = {"User-Agent": CHROME.replace("Chrome/", "HeadlessChrome/"), "Accept": "text/html"}
CRON = {"User-Agent": "curl/8.5.0", "Accept": "*/*"}

PAGES = ["/", "/products", "/about", "/api/items", "/login", "/static/app.js", "/search", "/blog"]
DOWNLOADS = ["/downloads/price-list.pdf", "/downloads/brochure-2026.pdf", "/downloads/user-guide.zip",
             "/downloads/installer-2.4.1.zip", "/downloads/terms.docx"]
SITE = set(PAGES) | set(DOWNLOADS)
# Query strings real sites see every day: paging, ids, categories, tracking
# tags, pipe- and semicolon-separated lists, an encoded return URL.
QUERIES = {
    "/products": ["page=2&id=5", "cat=3&id=17", "id=42&utm_source=newsletter&utm_medium=email",
                  "tags=dog|cat", "sort=price|name&dir=asc", "color=red;size=m&id=8", "page=3&sh=1&nc=0"],
    "/blog": ["p=1&cat=3", "year=2026&month=11&id=204", "author=kim&cat=news"],
    "/search": ["q=red+shoes&page=2", "q=o%27reilly+books&id=9", "q=cat+food&sort=price",
                "q=caf%C3%A9+near+me", "q=R%26D+jobs&uname=sam", "q=bash+scripting+course&cat=7"],
    "/api/items": ["page=2&id=5", "fields=name|id|price", "ids=1,2,3&expand=owner",
                   "since=2026-11-23T10:00:00Z&limit=50&id=3"],
    "/login": ["next=%2Fproducts%3Fpage%3D2%26id%3D5"],
    "/": ["utm_source=mail&utm_campaign=autumn&id=77", "ref=partner&curl=0"],
}


class Clock:
    t = 1_800_000_000.0

    def __call__(self):
        return self.t


class Tally:
    """Requests and stops per kind of legitimate client."""

    def __init__(self):
        self.rows = {}

    def client(self, kind):
        self.rows.setdefault(kind, [0, 0, 0])[0] += 1

    def count(self, kind, status):
        row = self.rows[kind]
        row[1] += 1
        row[2] += status in (403, 429)

    def total(self, column):
        return sum(row[column] for row in self.rows.values())


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


def browse(shield, clock, tally, kind, ip, rng, sessions, pause):
    """Page views: a pause, then a burst of pages and assets. Some carry a
    query string, some are downloads, the odd one is a dead link."""
    for _ in range(sessions):
        clock.t += rng.uniform(*pause)
        for _ in range(rng.randint(2, 30)):
            roll, query = rng.random(), ""
            if roll < 0.03:
                path = f"/dead-{rng.randint(0, 99)}"
            elif roll < 0.08:
                path = rng.choice(DOWNLOADS)
            else:
                path = rng.choice(PAGES)
                if path in QUERIES and rng.random() < 0.5:
                    query = rng.choice(QUERIES[path])
            tally.count(kind, send(shield, clock, ip, path, BROWSER, query=query, gap=rng.uniform(0.001, 0.1)))


def poll(shield, clock, tally, kind, ip, headers, paths, every, hours, rng=None):
    """One request per tick for `hours`; `every` is seconds, or a (low, high) range."""
    end, i = clock.t + hours * 3600, 0
    while clock.t < end:
        path, _, query = paths[i % len(paths)].partition("?")
        gap = rng.uniform(*every) if rng else every
        tally.count(kind, send(shield, clock, ip, path, headers, query=query, gap=gap))
        i += 1


def visitors(shield, clock, n=300):
    """People, polling dashboards, API scripts, monitors and downloads, some of
    them running for hours. None should be stopped."""
    rng, tally = random.Random(11), Tally()
    for u in range(n):
        ip = f"198.18.{u // 250}.{u % 250 + 1}"
        kind = u % 10
        if kind == 0:        # dashboard polling every second, browser headers
            tally.client("dashboard, 2 min")
            for _ in range(120):
                tally.count("dashboard, 2 min", send(shield, clock, ip, "/api/items", BROWSER,
                                                     query="page=1&id=7", gap=1.0))
        elif kind == 1:      # integration script, irregular
            tally.client("api script, irregular")
            for i in range(60):
                tally.count("api script, irregular", send(shield, clock, ip, "/api/items", SCRIPT,
                                                          query=QUERIES["/api/items"][i % 4], gap=rng.uniform(2, 30)))
        else:                # browsing
            tally.client("browsing")
            browse(shield, clock, tally, "browsing", ip, rng, sessions=rng.randint(3, 25), pause=(2, 60))

    # Clients that stay for hours. A score halves every 10 minutes, so anything
    # that builds up over several half-lives only shows on runs this long.
    long_runs = [
        ("dashboard, 3 h at 1/s", BROWSER, ["/api/items?page=1&id=7"], 1.0, 3, None),
        ("api script, 3 h at 1/s", SCRIPT, ["/api/items?since=2026-11-23T10:00:00Z&limit=50&id=3"], 1.0, 3, None),
        ("api script, 6 h at 2/min", SCRIPT, ["/api/items?fields=name|id|price", "/api/items?page=2&id=5"],
         (20, 40), 6, rng),
        ("headless monitor, 6 h", HEADLESS, ["/", "/products?page=1&id=5", "/login", "/search?q=cat+food&sort=price"],
         75.0, 6, None),
        ("cron download, 4 h", CRON, DOWNLOADS, 600.0, 4, None),
    ]
    for net, (kind, headers, paths, every, hours, jitter) in enumerate(long_runs):
        for copy in range(2):
            tally.client(kind)
            poll(shield, clock, tally, kind, f"198.19.{net}.{copy + 1}", headers, paths, every, hours, jitter)
    for copy in range(4):    # a tab left open all working day
        tally.client("browsing, 8 h")
        browse(shield, clock, tally, "browsing, 8 h", f"198.19.9.{copy + 1}", rng, sessions=110, pause=(60, 480))
    return tally


def main():
    clock = Clock()
    canaries = make_canaries("demo-secret")
    shield = Shield(Config(mode="enforce", canary_paths=canaries), clock=clock)

    print(f"{'actor':<12} {'request':<44} {'resp':>4} {'score':>5}  signals")
    for who, req, status, score, hits in campaign(shield, clock, canaries):
        print(f"{who:<12} {req[:44]:<44} {status:>4} {score:>5}  {hits}")

    print(f"\nactive blocks: {sorted(shield.blocklist())}")
    tally = visitors(shield, clock)
    print(f"\n{'legitimate client':<26} {'clients':>7} {'requests':>9} {'stopped':>8}")
    for kind, (clients, requests, stopped) in tally.rows.items():
        print(f"{kind:<26} {clients:>7} {requests:>9} {stopped:>8}")
    stopped = tally.total(2)
    print(f"\nlegitimate traffic: {tally.total(1)} requests from {tally.total(0)} clients, {stopped} stopped")
    return stopped


if __name__ == "__main__":
    raise SystemExit(1 if main() else 0)
