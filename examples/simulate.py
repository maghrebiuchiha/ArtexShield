"""Replay an ARTEX-style campaign and ordinary visitors against the shield.

Nothing leaves this process: requests are plain function calls on a fake
clock. Run it to see the engagement sequence and to sanity-check tuning.

    python examples/simulate.py
"""
import logging
import random
import urllib.parse

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
HTML = {"/", "/products", "/about", "/login", "/search", "/blog"}
# The optional client check is on in this simulation. What a browser sends for
# a call its page's script makes, and for things it loads without any script.
FETCH = {"User-Agent": CHROME, "Accept": "application/json", "Accept-Language": "en-US",
         "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}
NAVIGATE = dict(BROWSER, **{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"})
IMAGE = {"User-Agent": CHROME, "Accept": "image/avif,image/webp,*/*", "Accept-Language": "en-US",
         "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}
OLD_BROWSER = {"User-Agent": "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/15.6 Safari/605.1.15",
               "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en-US"}
# Several of these have names a backup-hunting scanner would also try. The site
# really serves them, so asking for them is not a probe.
DOWNLOADS = ["/downloads/price-list.pdf", "/downloads/brochure-2026.pdf", "/downloads/user-guide.zip",
             "/downloads/installer-2.4.1.zip", "/downloads/terms.docx", "/downloads/employee-handbook.zip",
             "/downloads/feedback-form-2026.zip", "/exports/customer-database.zip", "/downloads/release-notes.old",
             "/downloads/site-backup-tool.tar"]
SITE = set(PAGES) | set(DOWNLOADS)
# What people type into a search box: books with colons, years and quoted
# titles, recipes with apostrophes and brackets, programming questions that
# mention <script>, sleep(), UNION SELECT or ../../. tests/test_shield.py
# checks the same phrases one by one.
SEARCHES = [
    "javascript: the good parts", "JavaScript: The Definitive Guide (7th edition)",
    "javascript: understanding the weird parts (course)", "Why We Sleep (2017) Matthew Walker",
    "'Salem's Lot", "'Dune' and '1984'", "'The Road' or 'Blood Meridian'", '"Catch-22" and "Slaughterhouse-Five"',
    "Harry Potter and the Philosopher's Stone", "The Hitchhiker's Guide to the Galaxy", "'Tis: A Memoir",
    "Charlotte's Web or Stuart Little", '"Pride and Prejudice" or "Emma"', "Don't Make Me Think (2nd edition)",
    "O'Reilly 'Learning Python' or 'Fluent Python'", "Tolkien 'The Hobbit' and 3 other books",
    "'Night Shift' or 'Skeleton Crew' stephen king", "Rock 'n' Roll: A Social History",
    "'Dune' or true crime", "'It' and 'Carrie' (1976 film)",
    "chicken tikka masala (serves 4)", "mac 'n' cheese", "grandma's apple pie", "salt & pepper squid",
    "bake at 350°F (175°C) for 25-30 min", "1/2 cup sugar; 2 eggs; 1 tsp vanilla", "slow cooker chili | easy | 8 hours",
    "shepherd's pie or cottage pie", "meal plan for 3 kids' and 2 adults", "fish 'n' chips", "s'mores without a campfire",
    "'no knead' bread or focaccia", "eggs benedict & hollandaise (blender)", "sourdough starter (day 1)",
    "'salt' and 'pepper' to taste", "brownies 9x13 (serves 12-16)", "2 eggs or 1 banana as substitute",
    "sleep (8 hours)", "how much sleep (7-9 hours) do adults need", "benchmark (2024) gpu",
    "student union select committee", "credit union select checking account",
    "how to use <script tags in html", "<script async vs defer", "what does the <script> tag do",
    "python time.sleep(5) not working", "how to sleep 5 seconds in bash", "sql union select example",
    "sql union all select vs union", "mysql information_schema.tables size", "waitfor delay sql server example",
    "window.onload = function vs DOMContentLoaded", "img onerror= fallback image", "<iframe> embed youtube responsive",
    '<svg viewBox="0 0 24 24"> icon size', "jest cannot find module '../../utils'", "import styles from '../../theme.css'",
    "difference between == and === in javascript", "rust Option<T> unwrap vs expect", "c++ std::vector<int> push_back",
    "regex lookahead (?=...) example", "bash if [ -f file ]; then echo exists", "git log --oneline && git status",
    'href="javascript:void(0)" meaning', "jinja2 {{ variable|default('none') }}", "flask {{ config.SECRET_KEY }} in template",
    "find . -name '*.py' | xargs grep TODO", "python f'{name!r}' formatting", "sql where 1=1 meaning",
    "kubectl get pods -o wide | grep Running", "node fetch('/api').then(res => res.json())", "css :not(.active) selector",
    "powershell Get-ChildItem | Select-Object Name", "typescript Record<string, number>", "cron */5 * * * * every 5 minutes",
    "geekbench cpu benchmark(single core)", "<button onclick= not working", "sleep sort algorithm (joke)",
]
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
QUERIES["/search"] += ["q=" + urllib.parse.quote_plus(text) for text in SEARCHES]


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
        kind = "text/html" if path in HTML else "application/json" if path.startswith("/api") else "text/plain"
        shield.observe(ip, path, status, d.induced, kind)
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


def run_check(shield, clock, ip, headers, flags=0, gap=0.3):
    """The page's check script, running in the browser: it calls the check
    endpoint and the browser keeps the cookie. Returns headers carrying it."""
    clock.t += gap
    d = shield.check(ip, "GET", "/_artex/check", f"v=1&f={flags}", FETCH)
    if d.stop:
        return headers
    _, hdrs, _ = shield.client_check_reply(ip, f"v=1&f={flags}", {})
    return dict(headers, Cookie=dict(hdrs)["Set-Cookie"].split(";", 1)[0])


def script_clients(shield, clock, tally, rng):
    """Clients the client check is about, all honest. None may be stopped."""
    for copy in range(10):   # a web app: pages run their script, then call the API every few seconds for an hour
        kind, ip = "browser running page JS", f"198.19.30.{copy + 1}"
        tally.client(kind)
        tally.count(kind, send(shield, clock, ip, "/", NAVIGATE, gap=rng.uniform(1, 30)))
        api = run_check(shield, clock, ip, FETCH)
        end = clock.t + 3600
        while clock.t < end:
            tally.count(kind, send(shield, clock, ip, "/api/items", api, query="page=1&id=5", gap=rng.uniform(2, 30)))
            if rng.random() < 0.05:
                tally.count(kind, send(shield, clock, ip, "/products", NAVIGATE, gap=1.0))
                api = run_check(shield, clock, ip, api)

    for copy in range(10):   # JavaScript off: pages, links into /api, images served from /api. Old browsers too.
        kind, ip = "browser, JavaScript off", f"198.19.31.{copy + 1}"
        page, image = (NAVIGATE, IMAGE) if copy % 2 else (OLD_BROWSER, dict(OLD_BROWSER, Accept="image/webp,image/*"))
        tally.client(kind)
        for _ in range(40):
            tally.count(kind, send(shield, clock, ip, rng.choice(sorted(HTML)), page, gap=rng.uniform(5, 60)))
            tally.count(kind, send(shield, clock, ip, "/api/items", page, query="format=html", gap=rng.uniform(2, 20)))
            tally.count(kind, send(shield, clock, ip, "/api/items", image, query="avatar=7", gap=0.05))

    for copy in range(2):    # a QA suite driving a real browser with WebDriver, every second for two hours
        kind, ip = "QA suite (WebDriver)", f"198.19.32.{copy + 1}"
        tally.client(kind)
        tally.count(kind, send(shield, clock, ip, "/", NAVIGATE, gap=5))
        api = run_check(shield, clock, ip, FETCH, flags=1)
        for _ in range(7200):
            tally.count(kind, send(shield, clock, ip, "/api/items", api, query="page=1&id=5", gap=1.0))

    for copy in range(4):    # an ad blocker that blocks the check script: pages and API calls, no check ever
        kind, ip = "check script blocked", f"198.19.33.{copy + 1}"
        tally.client(kind)
        for _ in range(30):
            tally.count(kind, send(shield, clock, ip, rng.choice(sorted(HTML)), NAVIGATE, gap=rng.uniform(5, 90)))
            for _ in range(rng.randint(1, 6)):
                tally.count(kind, send(shield, clock, ip, "/api/items", FETCH, query="page=2&id=5",
                                       gap=rng.uniform(1, 10)))


def api_replay(shield, clock):
    """Campaign, last phase: a fifth address loads the home page like a browser
    would, never runs its script, then replays the site's API at ARTEX's quiet
    pace. Returns the client-check signals it raised and when it was stopped."""
    ip, replay = "203.0.113.14", {"User-Agent": CHROME, "Accept": "*/*", "Accept-Language": "en-US"}
    send(shield, clock, ip, "/", replay, gap=1.0)
    signals, stopped = set(), None
    for i in range(600):
        d = shield.check(ip, "GET", "/api/items", f"page={i}&id=5", replay)
        clock.t += 0.5 + random.Random(i).uniform(0, 0.25)
        signals |= {h for h in d.hits if h.startswith(("client:", "behavior:metronomic"))}
        if i == 300:                                        # halfway, one probe for API docs
            shield.observe(ip, "/swagger.json", 404)
        if d.stop and stopped is None:
            stopped = i + 1
    return sorted(signals), stopped


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

    for copy in range(6):    # the search box: book titles, recipes, programming questions, one after another
        kind, ip = "search box, 78 phrases", f"198.19.25.{copy + 1}"
        tally.client(kind)
        for text in rng.sample(SEARCHES, len(SEARCHES)):
            tally.count(kind, send(shield, clock, ip, "/search", SIGNED_IN if copy % 2 else BROWSER,
                                   query="q=" + urllib.parse.quote_plus(text), gap=rng.uniform(5, 45)))

    ipv6_street(shield, clock, tally, rng)
    script_clients(shield, clock, tally, rng)

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


def ipv6_street(shield, clock, tally, rng, kind="IPv6 neighbours of scanners"):
    """Twenty-four households in one /56, each with its own /64, and ten more
    networks in the same /56 that are scanners and get blocked. Ten is past the
    point where block widening (v6_escalate_after=8) would take the whole /56
    for one operator. Widening is off by default, so the street is left alone."""
    for bad in range(10):
        send(shield, clock, f"2001:db8:40:{0xe0 + bad:x}::1", "/", {"User-Agent": "sqlmap/1.9"}, gap=1.0)
    for house in range(24):
        tally.client(kind)
        browse(shield, clock, tally, kind, f"2001:db8:40:{house:x}::{house + 1:x}", rng, sessions=3, pause=(5, 60),
               headers=SIGNED_IN)


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
    shield = Shield(Config(mode="enforce", canary_paths=canaries, client_check=True,
                           client_check_secret="demo-secret"), clock=clock)

    print(f"{'actor':<12} {'request':<44} {'resp':>4} {'score':>5}  signals")
    for who, req, status, score, hits in campaign(shield, clock, canaries):
        print(f"{who:<12} {req[:44]:<44} {status:>4} {score:>5}  {hits}")

    print(f"\nactive blocks: {sorted(shield.blocklist())}")
    sent, answered, first_stop = slow_guessing(shield, clock)
    print(f"slow guessing from a fourth address, 12 paths a minute for 3 hours: {sent} sent, {answered} answered, "
          f"stopped from request {first_stop}")
    signals, stopped = api_replay(shield, clock)
    print(f"API replay from a fifth address, no page script run: signals {', '.join(signals)}; soft alone, so it "
          f"is let through until a /swagger.json probe adds hard evidence; stopped from request {stopped}")
    tally = visitors(shield, clock, canaries)
    print(f"\n{'legitimate client':<26} {'clients':>7} {'requests':>9} {'stopped':>8}")
    for kind, (clients, requests, stopped) in tally.rows.items():
        print(f"{kind:<26} {clients:>7} {requests:>9} {stopped:>8}")
    stopped = tally.total(2)
    print(f"\nforced on visitors by a hostile page: {tally.forced[0]} requests, {tally.forced[1]} refused, "
          f"{sum(net.startswith('198.') for net in shield.blocklist())} visitors blocked")
    # The same street on a shield with block widening switched on: not part of
    # the count above, a picture of what the option costs.
    wide_clock, wide_tally = Clock(), Tally()
    ipv6_street(Shield(Config(mode="enforce", v6_escalate_after=8), clock=wide_clock), wide_clock, wide_tally,
                random.Random(11))
    _, sent, lost = wide_tally.rows["IPv6 neighbours of scanners"]
    print(f"the same IPv6 street with block widening on (v6_escalate_after=8): {lost} of {sent} requests stopped")
    print(f"legitimate traffic: {tally.total(1)} requests from {tally.total(0)} clients, {stopped} stopped")
    return stopped


if __name__ == "__main__":
    raise SystemExit(1 if main() else 0)
