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
# The same browser with the cookies a real session carries, including one
# that remembers a search and one that holds a pipe-separated cart.
SIGNED_IN = dict(BROWSER, Cookie="sid=4f9c2a71; _ga=GA1.2.1234.5678; consent=%7B%22ads%22%3Afalse%7D; "
                                 "last=%2Fsearch%3Fq%3Dcat%2Bfood%26sort%3Dprice; cart=3|17|42; lang=en-US")
SCRIPT = {"User-Agent": "python-requests/2.32"}
# A synthetic-monitoring browser: headless, and it sends no Accept-Language.
HEADLESS = {"User-Agent": CHROME.replace("Chrome/", "HeadlessChrome/"), "Accept": "text/html"}
CRON = {"User-Agent": "curl/8.5.0", "Accept": "*/*"}
# Windows asks about a link by WebDAV before the browser opens it.
WEBDAV = {"User-Agent": "Microsoft-WebDAV-MiniRedir/10.0.19045", "Accept-Language": "en-US"}
# What a browser adds when another site's page, not the person, made it send the request.
FORCED = dict(BROWSER, **{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image",
                          "Referer": "https://forum.example/thread/9", "Host": "shop.example"})

PAGES = ["/", "/products", "/about", "/api/items", "/login", "/static/app.js", "/search", "/blog"]
# Several of these have names a backup-hunting scanner would also try. The site
# really serves them, so asking for them is not a probe.
DOWNLOADS = ["/downloads/price-list.pdf", "/downloads/brochure-2026.pdf", "/downloads/user-guide.zip",
             "/downloads/installer-2.4.1.zip", "/downloads/terms.docx", "/downloads/employee-handbook.zip",
             "/downloads/feedback-form-2026.zip", "/exports/customer-database.zip", "/downloads/release-notes.old",
             "/downloads/site-backup-tool.tar"]
SITE = set(PAGES) | set(DOWNLOADS)
# Query strings real sites see every day: paging, ids, categories, tracking
# tags, pipe- and semicolon-separated lists, an encoded return URL.
QUERIES = {
    "/products": ["page=2&id=5", "cat=3&id=17", "id=42&utm_source=newsletter&utm_medium=email",
                  "tags=dog|cat", "sort=price|name&dir=asc", "color=red;size=m&id=8", "page=3&sh=1&nc=0",
                  "note=gift%0Awrap+please&id=5", "filter=price%3D10+or+price%3D20"],
    "/blog": ["p=1&cat=3", "year=2026&month=11&id=204", "author=kim&cat=news"],
    "/search": ["q=red+shoes&page=2", "q=o%27reilly+books&id=9", "q=cat+food&sort=price",
                "q=caf%C3%A9+near+me", "q=R%26D+jobs&uname=sam", "q=bash+scripting+course&cat=7",
                "q=cats+and+dogs&page=2", "q=1+or+2+bedrooms", "q=what+does+%60ls%60+do", "q=use+onclick%3D+in+html"],
    "/api/items": ["page=2&id=5", "fields=name|id|price", "ids=1,2,3&expand=owner",
                   "since=2026-11-23T10:00:00Z&limit=50&id=3"],
    "/login": ["next=%2Fproducts%3Fpage%3D2%26id%3D5", "next=%2Flist%3Fonline%3D1%26onsale%3Dtrue"],
    "/": ["utm_source=mail&utm_campaign=autumn&id=77", "ref=partner&curl=0",
          "email=%7B%7Bemail%7D%7D&utm_source=newsletter"],      # a mail merge that did not run
}


class Clock:
    t = 1_800_000_000.0

    def __call__(self):
        return self.t


class Tally:
    """Requests and stops per kind of legitimate client."""

    def __init__(self):
        self.rows = {}
        self.forced = [0, 0]         # requests a hostile page made visitors' browsers send: sent, refused

    def client(self, kind):
        self.rows.setdefault(kind, [0, 0, 0])[0] += 1

    def count(self, kind, status):
        row = self.rows[kind]
        row[1] += 1
        row[2] += status in (403, 429)

    def total(self, column):
        return sum(row[column] for row in self.rows.values())


def send(shield, clock, ip, path, headers, query="", gap=0.0, log=None, who="", method="GET"):
    clock.t += gap
    d = shield.check(ip, method, path, query, headers)
    status = {"throttle": 429}.get(d.action, 403) if d.stop else (200 if path in SITE else 404)
    if not d.stop:
        shield.observe(ip, path, status, d.induced)
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


def slow_guessing(shield, clock, ip="203.0.113.13", per_minute=12, hours=3):
    """Phase 4 - a fourth address guesses paths slowly enough to stay under the
    per-minute limit. Returns (sent, answered by the app, first request stopped)."""
    sent = answered = 0
    first_stop = None
    for i in range(per_minute * 60 * hours):
        status = send(shield, clock, ip, f"/guess-{i}", BROWSER, gap=60 / per_minute)
        sent += 1
        answered += status == 404
        if first_stop is None and status in (403, 429):
            first_stop = sent
    return sent, answered, first_stop


def browse(shield, clock, tally, kind, ip, rng, sessions, pause, headers=BROWSER):
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
            tally.count(kind, send(shield, clock, ip, path, headers, query=query, gap=rng.uniform(0.001, 0.1)))


def poll(shield, clock, tally, kind, ip, headers, paths, every, hours, rng=None):
    """One request per tick for `hours`; `every` is seconds, or a (low, high) range."""
    end, i = clock.t + hours * 3600, 0
    while clock.t < end:
        path, _, query = paths[i % len(paths)].partition("?")
        gap = rng.uniform(*every) if rng else every
        tally.count(kind, send(shield, clock, ip, path, headers, query=query, gap=gap))
        i += 1


def awkward(shield, clock, tally, canaries, rng):
    """Honest clients that look bad at a glance: 404s that are not guesses,
    WebDAV discovery, and visitors whose browser a hostile page is driving."""
    for copy in range(3):    # waiting for a job that is not ready: the same 404 every 2 s for 10 minutes
        kind, ip = "job poller, 404 every 2 s", f"198.19.20.{copy + 1}"
        tally.client(kind)
        poll(shield, clock, tally, kind, ip, BROWSER, ["/api/jobs/42/result"], 2.0, 1 / 6)
        tally.count(kind, send(shield, clock, ip, "/products", BROWSER, query="page=2&id=5", gap=1.0))

    for copy in range(3):    # a cached page asking for 30 script and style chunks a deploy removed, reloaded twice
        kind, ip = "stale page, 30 dead assets", f"198.19.21.{copy + 1}"
        tally.client(kind)
        for reload in range(3):
            tally.count(kind, send(shield, clock, ip, "/", BROWSER, gap=rng.uniform(60, 240)))
            for i in range(30):
                asset = f"/static/chunk-{copy}{i:02d}." + ("js", "css", "js.map")[i % 3]
                tally.count(kind, send(shield, clock, ip, asset, BROWSER, gap=rng.uniform(0.005, 0.05)))

    for copy in range(3):    # links opened from Word: Windows probes by WebDAV, then the browser fetches
        kind, ip = "office link, WebDAV probe", f"198.19.22.{copy + 1}"
        tally.client(kind)
        for _ in range(6):
            clock.t += rng.uniform(120, 900)
            for method in ("OPTIONS", "PROPFIND", "PROPFIND", "PROPFIND", "PROPFIND"):
                tally.count(kind, send(shield, clock, ip, "/downloads", WEBDAV, gap=0.2, method=method))
            tally.count(kind, send(shield, clock, ip, "/downloads/terms.docx", BROWSER, gap=0.5))

    for copy in range(2):    # a site full of old links: 45 different dead pages an hour, for three hours
        kind, ip = "45 dead links an hour", f"198.19.24.{copy + 1}"
        tally.client(kind)
        for i in range(135):
            tally.count(kind, send(shield, clock, ip, f"/archive/{copy}/{i}", BROWSER, gap=80.0))
            tally.count(kind, send(shield, clock, ip, "/products", BROWSER, query="page=2&id=5", gap=1.0))

    # An IPv6 street: twenty-four households in one /56, each with its own /64.
    # Five more networks in the same /56 are scanners and get blocked; that is
    # too few for the /56 to be taken as one operator, so the street is left alone.
    for bad in range(5):
        send(shield, clock, f"2001:db8:40:{0xe0 + bad:x}::1", "/", {"User-Agent": "sqlmap/1.9"}, gap=1.0)
    for house in range(24):
        kind, ip = "IPv6 neighbours of scanners", f"2001:db8:40:{house:x}::{house + 1:x}"
        tally.client(kind)
        browse(shield, clock, tally, kind, ip, rng, sessions=3, pause=(5, 60), headers=SIGNED_IN)

    # A hostile page shows visitors image tags that point here: at a canary, a
    # dotfile, attack URLs, admin paths, a pile of dead links. Their browsers
    # send those. Those requests are not legitimate and may be refused; the
    # visitors' own browsing, before and after, must not be touched.
    bait = [(canaries[0], ""), (canaries[1], ""), ("/.env", ""), ("/search", "q=<script>alert(1)</script>"),
            ("/api/items", "id=1' UNION SELECT null--"), ("/db-backup.sql", ""),
            ("/admin", ""), ("/wp-login.php", ""), ("/phpmyadmin/", ""), ("/actuator/env", "")]
    bait += [(f"/x-{i}", "") for i in range(40)]
    for copy in range(5):
        kind, ip = "visitor on a hostile page", f"198.19.23.{copy + 1}"
        tally.client(kind)
        browse(shield, clock, tally, kind, ip, rng, sessions=4, pause=(5, 60))
        for round_ in range(3):
            for path, query in bait:
                status = send(shield, clock, ip, path, FORCED, query=query, gap=0.01)
                tally.forced[0] += 1
                tally.forced[1] += status in (403, 429)
            browse(shield, clock, tally, kind, ip, rng, sessions=4, pause=(5, 60))


def visitors(shield, clock, canaries, n=300):
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
            browse(shield, clock, tally, "browsing", ip, rng, sessions=rng.randint(3, 25), pause=(2, 60),
                   headers=SIGNED_IN if u % 2 else BROWSER)

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
    awkward(shield, clock, tally, canaries, rng)
    return tally


def main():
    clock = Clock()
    canaries = make_canaries("demo-secret")
    shield = Shield(Config(mode="enforce", canary_paths=canaries), clock=clock)

    print(f"{'actor':<12} {'request':<44} {'resp':>4} {'score':>5}  signals")
    for who, req, status, score, hits in campaign(shield, clock, canaries):
        print(f"{who:<12} {req[:44]:<44} {status:>4} {score:>5}  {hits}")

    print(f"\nactive blocks: {sorted(shield.blocklist())}")
    sent, answered, first_stop = slow_guessing(shield, clock)
    print(f"slow guessing from a fourth address, 12 paths a minute for 3 hours: {sent} sent, {answered} answered, "
          f"stopped from request {first_stop}")
    tally = visitors(shield, clock, canaries)
    print(f"\n{'legitimate client':<26} {'clients':>7} {'requests':>9} {'stopped':>8}")
    for kind, (clients, requests, stopped) in tally.rows.items():
        print(f"{kind:<26} {clients:>7} {requests:>9} {stopped:>8}")
    stopped = tally.total(2)
    print(f"\nforced on visitors by a hostile page: {tally.forced[0]} requests, {tally.forced[1]} refused, "
          f"{sum(net.startswith('198.') for net in shield.blocklist())} visitors blocked")
    print(f"legitimate traffic: {tally.total(1)} requests from {tally.total(0)} clients, {stopped} stopped")
    return stopped


if __name__ == "__main__":
    raise SystemExit(1 if main() else 0)
