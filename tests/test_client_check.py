"""The optional client-side check: a script that reports automation, a signed cookie."""
import asyncio
import io
import logging
import time
import unittest

from artex_shield import Config, Shield, ShieldASGI, ShieldWSGI, client_check_tag
from artex_shield import client_check as cc

T0 = 1_800_000_000.0
logging.getLogger("artex_shield").disabled = True
CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/131.0.0.0 Safari/537.36")
# What a browser sends, by kind of request.
PAGE = {"User-Agent": CHROME, "Accept": "text/html,application/xhtml+xml", "Accept-Language": "en",
        "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
LINK = dict(PAGE, **{"Sec-Fetch-Site": "same-origin"})                          # a click inside the site
FETCH = {"User-Agent": CHROME, "Accept": "application/json", "Accept-Language": "en",
         "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}
IMAGE = {"User-Agent": CHROME, "Accept": "image/avif,image/webp,*/*", "Accept-Language": "en",
         "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}
# A browser too old to send Sec-Fetch-*, with JavaScript off: navigations and images only.
OLD_LINK = {"User-Agent": "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/15.6 Safari/605.1.15",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en"}
OLD_IMAGE = dict(OLD_LINK, Accept="image/webp,image/png,image/*;q=0.8,*/*;q=0.5")
# An HTTP library dressed as a browser, replaying what pages would ask for.
REPLAY = {"User-Agent": CHROME, "Accept": "*/*", "Accept-Language": "en"}


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


def shield(**kw):
    c = Clock()
    kw.setdefault("mode", "enforce")
    kw.setdefault("client_check", True)
    kw.setdefault("client_check_secret", "test-secret")
    return Shield(Config(**kw), clock=c), c


class Visitor:
    """One client, with a cookie jar, talking to the shield the way the adapters do."""

    def __init__(self, s, c, ip="192.0.2.10"):
        self.s, self.c, self.ip, self.jar = s, c, ip, {}

    def get(self, path, headers, query="", gap=1.0, html=None):
        self.c.t += gap
        h = dict(headers)
        if self.jar and not h.get("Cookie"):
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.jar.items())
        d = self.s.check(self.ip, "GET", path, query, h)
        if d.stop:
            return d
        route = self.s.client_check_route(path)
        if route == "check":
            _, hdrs, _ = self.s.client_check_reply(self.ip, query, {k.lower(): v for k, v in h.items()})
            name, _, rest = dict(hdrs)["Set-Cookie"].partition("=")
            self.jar[name] = rest.split(";", 1)[0]
        elif route is None:
            html = path in ("/", "/products", "/about") if html is None else html
            self.s.observe(self.ip, path, 200, d.induced, "text/html; charset=utf-8" if html else "application/json")
        return d

    def page_with_script(self, path="/", flags=0, gap=1.0):
        """A page, then its check script running in the browser."""
        self.get(path, PAGE, gap=gap)
        return self.get("/_artex/check", FETCH, query=f"v=1&f={flags}", gap=0.3)


def client_hits(d):
    return [h for h in d.hits if h.startswith("client:")]


class Off(unittest.TestCase):
    def test_off_by_default_and_nothing_changes(self):
        self.assertFalse(Config().client_check)
        self.assertEqual(Config().mode, "monitor")
        s, c = shield(client_check=False)
        v = Visitor(s, c)
        v.get("/", PAGE)
        self.assertIsNone(s.client_check_route("/_artex/check"))
        for _ in range(50):
            self.assertEqual(client_hits(v.get("/api/items", REPLAY, gap=60)), [])


class Fires(unittest.TestCase):
    def test_a_client_that_loads_pages_but_never_runs_the_check(self):
        s, c = shield()
        v = Visitor(s, c, "203.0.113.20")
        v.get("/", REPLAY)                         # gets the HTML, never runs its script
        hits = []
        for _ in range(30):
            hits += client_hits(v.get("/api/items", REPLAY, gap=2))
        self.assertEqual(hits, ["client:no-check"])               # once per half-life
        self.assertLess(s._tracks["203.0.113.20"].score, s.cfg.throttle_score)

    def test_a_browser_that_reports_automation(self):
        for flag in (cc.FLAG_WEBDRIVER, cc.FLAG_DRIVER_GLOBALS, cc.FLAG_DRIVER_TRACES):
            s, c = shield()
            v = Visitor(s, c, "203.0.113.21")
            v.page_with_script(flags=flag)
            hits = []
            for _ in range(20):
                hits += client_hits(v.get("/api/items", FETCH, gap=3))
            self.assertEqual(hits, ["client:automation-reported"], flag)

    def test_the_grace_period_runs_from_the_first_page(self):
        s, c = shield(client_check_grace=30)
        v = Visitor(s, c, "192.0.2.40")
        v.get("/", PAGE)
        v.get("/products", PAGE, gap=25)              # more pages do not start it again
        self.assertIn("client:no-check", client_hits(v.get("/api/items", FETCH, gap=6)))

    def test_the_report_holds_even_if_the_cookie_is_thrown_away(self):
        s, c = shield()
        v = Visitor(s, c, "203.0.113.22")
        v.page_with_script(flags=cc.FLAG_WEBDRIVER)
        v.jar.clear()
        self.assertEqual(client_hits(v.get("/api/items", FETCH, gap=5)), ["client:automation-reported"])

    def test_signals_are_soft_however_long_it_goes_on(self):
        s, c = shield()
        bot = dict(FETCH, **{"User-Agent": CHROME.replace("Chrome/", "HeadlessChrome/") + " python-requests/2"})
        v = Visitor(s, c, "203.0.113.23")
        v.page_with_script(flags=cc.FLAGS)        # every automation mark there is
        other = Visitor(s, c, "203.0.113.24")
        other.get("/", REPLAY)
        for _ in range(3600):
            for who, headers in ((v, bot), (other, REPLAY)):
                d = who.get("/api/items", headers, gap=0.5)
                self.assertEqual(d.action, "pass", d.hits)
        for ip in ("203.0.113.23", "203.0.113.24"):
            self.assertEqual(s._tracks[ip].hard, 0)
            self.assertLessEqual(s._tracks[ip].soft_points, s.cfg.soft_cap)

    def test_they_add_to_hard_evidence(self):
        # 30 hard points (a TRACE request) pass on their own. With the automation
        # report beside them they reach the throttle score; from a browser whose
        # check came back clean, the same 30 points still pass.
        actions = {}
        for flags in (cc.FLAG_WEBDRIVER, 0):
            s, c = shield()
            v = Visitor(s, c, "203.0.113.25")
            v.page_with_script(flags=flags)
            self.assertEqual(s.check(v.ip, "TRACE", "/", "", FETCH).action, "pass")
            actions[flags] = v.get("/api/items", FETCH, gap=0).action     # no time to decay: 30 + 20 = 50
        self.assertEqual(actions, {cc.FLAG_WEBDRIVER: "throttle", 0: "pass"})


class Spares(unittest.TestCase):
    def test_a_real_browser_running_the_script(self):
        s, c = shield()
        v = Visitor(s, c)
        v.page_with_script()
        self.assertIn("artex_check", v.jar)
        for i in range(2 * 3600 // 5):
            if i % 100 == 0:
                v.page_with_script("/products", gap=1)
            self.assertEqual(client_hits(v.get("/api/items", FETCH, gap=5)), [])
        self.assertEqual(s._tracks["192.0.2.10"].score, 0)

    def test_visitors_without_javascript_are_never_affected(self):
        # Everything a browser sends without running script, with the check on
        # and off: every decision must be the same, hits and all.
        session = [("/", PAGE), ("/products", LINK), ("/api/items", LINK), ("/api/report.pdf", LINK),
                   ("/api/avatar/7", IMAGE), ("/swagger.json", LINK), ("/api/items", LINK),
                   ("/", OLD_LINK), ("/api/items", OLD_LINK), ("/api/avatar/8", OLD_IMAGE)] * 40
        outcomes = []
        for on in (True, False):
            s, c = shield(client_check=on)
            v, seen = Visitor(s, c, "192.0.2.30"), []
            for path, headers in session:
                d = v.get(path, headers, gap=7, html=headers in (PAGE, LINK, OLD_LINK) and not path.startswith("/api"))
                if path == "/swagger.json":
                    s.observe(v.ip, path, 404)
                seen.append((d.action, round(d.score, 6), d.hits))
            outcomes.append(seen)
        self.assertEqual(outcomes[0], outcomes[1])
        self.assertFalse(any(h.startswith("client:") for _, _, hits in outcomes[0] for h in hits))

    def test_requests_a_browser_makes_without_script_are_never_script_made(self):
        for headers in (PAGE, LINK, IMAGE, OLD_LINK, OLD_IMAGE,
                        dict(IMAGE, **{"Sec-Fetch-Dest": "style", "Accept": "text/css"}),
                        dict(LINK, **{"Sec-Fetch-Mode": "websocket", "Sec-Fetch-Dest": "websocket"})):
            self.assertFalse(cc.script_made({k.lower(): v for k, v in headers.items()}), headers)
        for headers in (FETCH, REPLAY, {"Accept": "application/json"}, {},
                        dict(OLD_LINK, **{"X-Requested-With": "XMLHttpRequest"})):
            self.assertTrue(cc.script_made({k.lower(): v for k, v in headers.items()}), headers)

    def test_the_first_calls_after_a_page_have_time(self):
        s, c = shield(client_check_grace=30)
        v = Visitor(s, c)
        v.get("/", PAGE)
        for _ in range(9):                          # the page's own calls, before its script has finished
            self.assertEqual(client_hits(v.get("/api/items", FETCH, gap=3)), [])

    def test_clients_that_never_load_a_page_are_not_judged(self):
        s, c = shield()
        v = Visitor(s, c, "198.51.100.40")
        for _ in range(200):                        # an API integration: no pages, no script, by design
            self.assertEqual(client_hits(v.get("/api/items", {"User-Agent": "acme-sync/2.1"}, gap=20)), [])

    def test_only_api_paths_are_judged(self):
        s, c = shield()
        v = Visitor(s, c, "203.0.113.41")
        v.get("/", REPLAY)
        for path in ("/search", "/products", "/static/app.js", "/apix"):
            self.assertEqual(client_hits(v.get(path, REPLAY, gap=60)), [], path)
        self.assertEqual(client_hits(v.get("/api/items", REPLAY, gap=60)), ["client:no-check"])

    def test_a_request_another_page_made_is_not_judged(self):
        s, c = shield()
        v = Visitor(s, c, "192.0.2.50")
        v.get("/", REPLAY)
        forced = dict(FETCH, **{"Sec-Fetch-Site": "cross-site", "Origin": "https://elsewhere.example"})
        for _ in range(20):
            self.assertEqual(client_hits(v.get("/api/items", forced, gap=60)), [])


class Cookie(unittest.TestCase):
    KEY = b"test-secret"

    def test_round_trip_and_tampering(self):
        value = cc.sign(self.KEY, int(T0), cc.FLAG_WEBDRIVER)
        self.assertEqual(cc.verify(self.KEY, value, T0, 86400), cc.FLAG_WEBDRIVER)
        v, issued, flags, mac = value.split(".")
        for forged in (f"{v}.{issued}.0.{mac}",                       # "no automation" with the old signature
                       f"{v}.{int(T0) + 999}.{flags}.{mac}", value[:-1] + ("A" if value[-1] != "A" else "B"),
                       "1.x.0.abc", "", "garbage", value + ".extra", "2" + value[1:], "1." + "9" * 200 + ".0.x"):
            self.assertIsNone(cc.verify(self.KEY, forged, T0, 86400), forged)
        self.assertIsNone(cc.verify(b"other-secret", value, T0, 86400))
        self.assertIsNone(cc.verify(self.KEY, value, T0 + 86401, 86400))      # expired
        self.assertIsNone(cc.verify(self.KEY, cc.sign(self.KEY, int(T0) + 3600, 0), T0, 86400))  # from the future

    def test_a_forged_or_foreign_cookie_counts_as_none(self):
        s, c = shield()
        v = Visitor(s, c, "203.0.113.60")
        v.get("/", REPLAY)
        for value in ("1.1800000000.0.AAAAAAAAAAAAAAAAAAAAAA", cc.sign(b"someone-else", int(T0), 0)):
            v.jar = {"artex_check": value}
            self.assertEqual(client_hits(v.get("/api/items", REPLAY, gap=601)), ["client:no-check"], value)

    def test_numbers_are_ascii_digits_only(self):
        # str.isdigit() also takes "²", which int() refuses, and "٣", which int() reads as 3.
        for digit in ("²", "٣"):
            for value in (f"1.{digit}.0.AAAAAAAAAAAAAAAAAAAAAA", f"1.{int(T0)}.{digit}.AAAAAAAAAAAAAAAAAAAAAA"):
                self.assertIsNone(cc.verify(self.KEY, value, T0, 86400), value)
        s, c = shield()
        v = Visitor(s, c, "203.0.113.61")
        v.get("/", REPLAY)
        for value in ("1.².0.x", f"1.{int(T0)}.٣.x"):
            v.jar = {"artex_check": value}
            self.assertEqual(client_hits(v.get("/api/items", REPLAY, gap=601)), ["client:no-check"], value)
        for flags in ("²", "٣", "¹²"):
            _, hdrs, _ = s.client_check_reply("203.0.113.62", f"v=1&f={flags}", {})
            value = dict(hdrs)["Set-Cookie"].split("=", 1)[1].split(";")[0]
            self.assertEqual(cc.verify(self.KEY, value, c.t, 86400), 0, flags)     # not an automation report

    def test_workers_with_the_same_secret_accept_each_others_cookies(self):
        a, ca = shield()
        b, cb = shield()
        v = Visitor(a, ca)
        v.page_with_script()
        w = Visitor(b, cb)
        w.jar = dict(v.jar)
        w.get("/", PAGE)
        for _ in range(30):
            self.assertEqual(client_hits(w.get("/api/items", FETCH, gap=30)), [])

    def test_cookie_attributes(self):
        s, _ = shield()
        _, hdrs, _ = s.client_check_reply("192.0.2.10", "v=1&f=0", {}, secure=True)
        set_cookie = dict(hdrs)["Set-Cookie"]
        self.assertTrue(set_cookie.startswith("artex_check=1."))
        for attr in ("Path=/", "Max-Age=86400", "HttpOnly", "SameSite=Lax", "Secure"):
            self.assertIn(attr, set_cookie)
        _, hdrs, _ = s.client_check_reply("192.0.2.10", "v=1&f=0", {}, secure=False)
        self.assertNotIn("Secure", dict(hdrs)["Set-Cookie"])
        _, hdrs, _ = s.client_check_reply("192.0.2.10", "f=99999999&junk", {})
        flags = cc.verify(b"test-secret", dict(hdrs)["Set-Cookie"].split("=", 1)[1].split(";")[0], T0, 86400)
        self.assertEqual(flags, 0)                  # nonsense is not an automation report

    def test_parsing_a_huge_cookie_header_is_quick(self):
        s, c = shield()
        h = dict(FETCH, Cookie="; ".join(f"c{i}={'x' * 50}" for i in range(20000)))
        t0 = time.perf_counter()
        s.check("192.0.2.11", "GET", "/api/items", "", h)
        self.assertLess(time.perf_counter() - t0, 0.25)

    def test_config_is_validated(self):
        for bad in ({"client_check_path": "check"}, {"client_check_path": "/"}, {"client_check_cookie": "a b"},
                    {"client_check_api_prefixes": ["api"]}, {"client_check_ttl": 0}, {"client_check_grace": -1}):
            with self.assertRaises(ValueError, msg=bad):
                Config(**bad)


class Adapters(unittest.TestCase):
    def test_wsgi(self):
        seen = []

        def app(environ, start_response):
            seen.append(environ["PATH_INFO"])
            html = not environ["PATH_INFO"].startswith("/api")
            start_response("200 OK", [("Content-Type", "text/html; charset=utf-8" if html else "application/json")])
            return [b"ok"]

        s, c = shield()
        wrapped = ShieldWSGI(app, s)

        def call(path, query="", headers=PAGE, cookie="", scheme="https"):
            c.t += 40
            env = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": query, "REMOTE_ADDR": "192.0.2.70",
                   "wsgi.url_scheme": scheme, "wsgi.input": io.BytesIO()}
            for k, v in headers.items():
                env["HTTP_" + k.upper().replace("-", "_")] = v
            if cookie:
                env["HTTP_COOKIE"] = cookie
            out = {}
            body = b"".join(wrapped(env, lambda st, h, e=None: out.update(status=st, headers=h)))
            return out["status"], out["headers"], body

        status, headers, body = call("/_artex/check.js")
        self.assertEqual(status, "200 OK")
        self.assertIn(("Content-Type", "text/javascript; charset=utf-8"), headers)
        self.assertIn(b"navigator", body)
        self.assertIn(b'"/_artex/check"', body)
        call("/")                                   # an HTML page, noted through observe()
        self.assertIsNotNone(s._tracks["192.0.2.70"].page_at)
        status, headers, _ = call("/_artex/check", "v=1&f=1", FETCH)
        self.assertEqual(status, "204 No Content")
        set_cookie = dict(headers)["Set-Cookie"]
        self.assertIn("Secure", set_cookie)
        self.assertEqual(seen, ["/"])               # the check's own endpoints never reach the app
        cookie = set_cookie.split(";", 1)[0]
        self.assertEqual(call("/api/items", headers=FETCH, cookie=cookie)[0], "200 OK")
        self.assertEqual(s._tracks["192.0.2.70"].soft_points, s.cfg.client_check_points)

    def test_asgi(self):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"text/html")]})
            await send({"type": "http.response.body", "body": b"ok"})

        s, c = shield()
        wrapped = ShieldASGI(app, s)

        async def call(path, query=b"", extra=()):
            sent = []
            scope = {"type": "http", "method": "GET", "path": path, "query_string": query, "scheme": "http",
                     "client": ("192.0.2.71", 5555),
                     "headers": [(b"user-agent", CHROME.encode()), (b"accept-language", b"en")] + list(extra)}

            async def send(m):
                sent.append(m)

            await wrapped(scope, None, send)
            return sent

        sent = asyncio.run(call("/_artex/check.js"))
        self.assertEqual(sent[0]["status"], 200)
        asyncio.run(call("/"))
        self.assertIsNotNone(s._tracks["192.0.2.71"].page_at)
        sent = asyncio.run(call("/_artex/check", b"v=1&f=0"))
        self.assertEqual(sent[0]["status"], 204)
        cookie = dict(sent[0]["headers"])[b"set-cookie"].decode()
        self.assertNotIn("Secure", cookie)          # plain http, no trusted proxy saying otherwise

    def test_tag(self):
        self.assertEqual(client_check_tag(Config()), '<script src="/_artex/check.js" async></script>')
        self.assertIn('"/x/c"', cc.script("/x/c"))


if __name__ == "__main__":
    unittest.main()
