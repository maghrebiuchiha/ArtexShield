"""Credential honeytokens: fake API keys and passwords that block whoever presents one."""
import asyncio
import base64
import io
import json
import logging
import re
import time
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone

from artex_shield import (Config, Engagement, Shield, ShieldASGI, ShieldWSGI, honeytoken_html, honeytoken_js,
                          make_canaries, make_honeytokens)

T0 = 1_800_000_000.0
logging.getLogger("artex_shield").disabled = True
CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/131.0.0.0 Safari/537.36")
BROWSER = {"User-Agent": CHROME, "Accept": "text/html", "Accept-Language": "en-US"}
TOKENS = make_honeytokens("site-secret")
KEY, PASSWORD, USER = TOKENS.api_keys[0], TOKENS.passwords[1], TOKENS.users[1]


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


def shield(**kw):
    c = Clock()
    kw.setdefault("mode", "enforce")
    kw.setdefault("honeytokens", TOKENS)
    return Shield(Config(**kw), clock=c), c


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class Making(unittest.TestCase):
    def test_tokens_are_stable_and_belong_to_the_secret(self):
        self.assertEqual(make_honeytokens("site-secret"), TOKENS)
        other = make_honeytokens("another-secret")
        self.assertFalse(set(TOKENS) & set(other))
        self.assertEqual(len(make_honeytokens("s", 5).api_keys), 5)
        everything = list(TOKENS) + make_canaries("site-secret", 5)
        self.assertEqual(len(everything), len(set(everything)))
        with self.assertRaises(ValueError):
            make_honeytokens("s", 0)

    def test_they_look_like_credentials_but_no_real_provider_s(self):
        for key in TOKENS.api_keys:
            self.assertRegex(key, r"^api_live_[0-9A-Za-z]{32}$")
            self.assertNotRegex(key, r"^(sk_live_|pk_live_|rk_live_|AKIA|ASIA|ghp_|gho_|github_pat_|xox[abprs]-|AIza|"
                                     r"SG\.|glpat-|npm_|sq0|EAAC)")
        for password in TOKENS.passwords:
            self.assertRegex(password, r"^[0-9A-Za-z!@#$*]{16}$")
            self.assertRegex(password, r"[!@#$*]")
            self.assertRegex(password, r"\d$")
        self.assertEqual(list(TOKENS), list(TOKENS.api_keys + TOKENS.passwords))     # usernames are not watched

    def test_planting_helpers(self):
        js = honeytoken_js(TOKENS)
        config = json.loads(re.fullmatch(r"var __stagingConfig = (\{.*\});", js).group(1))
        self.assertEqual((config["apiKey"], config["adminUser"], config["adminPassword"]),
                         (TOKENS.api_keys[0], TOKENS.users[0], TOKENS.passwords[0]))
        html = honeytoken_html(TOKENS)
        self.assertTrue(html.startswith("<!--") and html.endswith("-->"))
        inner = html[4:-3]
        self.assertNotIn("--", inner)                   # would end or break the comment
        self.assertNotIn(">", inner)
        for value in (TOKENS.users[1], TOKENS.passwords[1], TOKENS.api_keys[1]):
            self.assertIn(value, html)
        self.assertNotIn(TOKENS.api_keys[0], html)      # a different pair from the bundle's, so the log says which


class Presented(unittest.TestCase):
    """Every way a harvested credential comes back, each blocked on the first request."""

    def assertBlockedAt(self, where, query="", extra=None, body=None, path="/api/items", method="GET"):
        s, c = shield()
        d = s.check("203.0.113.50", method, path, query, dict(BROWSER, **(extra or {})), body)
        self.assertEqual((d.action, d.stop), ("block", True), (where, d.hits))
        self.assertIn(f"decoy:honeytoken-{where}", d.hits)
        c.t += 5                                        # and the address stays blocked, however clean it looks
        self.assertEqual(s.check("203.0.113.50", "GET", "/", "", BROWSER).action, "block")

    def test_headers(self):
        self.assertBlockedAt("header", extra={"Authorization": f"Bearer {KEY}"})
        self.assertBlockedAt("header", extra={"X-API-Key": KEY})
        self.assertBlockedAt("header", extra={"X-Auth-Token": f"token={KEY}"})
        self.assertBlockedAt("header", extra={"X-Password": urllib.parse.quote(PASSWORD)})

    def test_basic_auth_at_every_padding_length(self):
        for user in ("a", "ab", "abc", USER, "x" * 37):
            self.assertBlockedAt("header", extra={"Authorization": basic(user, PASSWORD)})
        self.assertBlockedAt("header", extra={"Authorization": basic(KEY, "")})
        url_safe = base64.urlsafe_b64encode(f"{USER}:{PASSWORD}".encode()).decode().rstrip("=")
        self.assertBlockedAt("header", extra={"Proxy-Authorization": "basic " + url_safe})

    def test_cookies(self):
        self.assertBlockedAt("cookie", extra={"Cookie": f"sid=abc; api_key={KEY}; theme=dark"})
        self.assertBlockedAt("cookie", extra={"Cookie": "creds=" + urllib.parse.quote(f"{USER}:{PASSWORD}")})

    def test_query_and_path(self):
        self.assertBlockedAt("query", query=f"api_key={KEY}&page=2")
        self.assertBlockedAt("query", query="password=" + urllib.parse.quote(PASSWORD))
        self.assertBlockedAt("query", query="p=" + urllib.parse.quote(urllib.parse.quote(PASSWORD)))  # double-encoded
        self.assertBlockedAt("path", path=f"/api/keys/{KEY}/rotate")

    def test_bodies(self):
        self.assertBlockedAt("body", method="POST", body=json.dumps({"apiKey": KEY, "q": "x"}).encode())
        self.assertBlockedAt("body", method="POST",
                             body=urllib.parse.urlencode({"username": USER, "password": PASSWORD}).encode())
        multipart = (b"--b\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + PASSWORD.encode() +
                     b"\r\n--b--\r\n")
        self.assertBlockedAt("body", method="POST", body=multipart)
        self.assertBlockedAt("body", method="PUT", body=b"x" * 60000 + KEY.encode())   # inside the first 64 KB

    def test_every_token_counts(self):
        for token in TOKENS:
            self.assertBlockedAt("query", query="v=" + urllib.parse.quote(token))


class Spared(unittest.TestCase):
    def test_near_misses_and_ordinary_traffic_pass(self):
        s, c = shield()
        near = [KEY[:-1], KEY[:-1] + ("A" if KEY[-1] != "A" else "B"), KEY.upper(), PASSWORD[:-2],
                "api_live_", USER, f"Bearer {make_honeytokens('another-secret').api_keys[0]}"]
        for i, value in enumerate(near):
            c.t += 60
            for d in (s.check(f"192.0.2.{i + 1}", "GET", "/api/items", "q=" + urllib.parse.quote(value), BROWSER),
                      s.check(f"192.0.2.{i + 1}", "POST", "/login", "", dict(BROWSER, Authorization=value),
                              f"username={USER}&password=hunter2".encode())):
                self.assertEqual(d.action, "pass", (value, d.hits))

    def test_the_referer_is_not_a_presentation(self):
        s, _ = shield()
        d = s.check("192.0.2.30", "GET", "/", "", dict(BROWSER, Referer=f"https://shop.example/search?q={KEY}"))
        self.assertEqual(d.action, "pass")

    def test_past_the_body_limit_is_not_read(self):
        s, _ = shield(honeytoken_body_limit=1024)
        self.assertEqual(s.check("192.0.2.31", "POST", "/upload", "", BROWSER, b"x" * 2000 + KEY.encode()).action,
                         "pass")

    def test_a_page_that_makes_the_browser_send_one_does_not_get_the_visitor_blocked(self):
        # Honeytokens are public by design, like canaries: anyone can put
        # <img src="/api/items?api_key=..."> on a page. That request is refused;
        # the visitor's address is not blocked.
        forced = dict(BROWSER, **{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors",
                                  "Sec-Fetch-Dest": "image", "Referer": "https://forum.example/"})
        s, c = shield()
        d = s.check("192.0.2.32", "GET", "/api/items", f"api_key={KEY}", forced)
        self.assertEqual((d.action, d.stop), ("refuse", True))
        c.t += 1
        self.assertEqual(s.check("192.0.2.32", "GET", "/", "", BROWSER).action, "pass")
        self.assertEqual(s.blocklist(), {})
        s2, _ = shield(score_induced=True)
        self.assertEqual(s2.check("192.0.2.32", "GET", "/api/items", f"api_key={KEY}", forced).action, "block")

    def test_monitor_mode_reports_and_stops_nothing(self):
        events = []
        s, _ = shield(mode="monitor", on_event=events.append)
        d = s.check("203.0.113.51", "GET", "/api/items", "", dict(BROWSER, Authorization=f"Bearer {KEY}"))
        self.assertEqual((d.action, d.stop), ("block", False))
        self.assertEqual(events[0]["hits"], ["decoy:honeytoken-header"])

    def test_still_an_instant_block_with_a_higher_block_score(self):
        s, _ = shield(block_score=250, throttle_score=120)
        self.assertEqual(s.check("203.0.113.52", "GET", "/", f"k={KEY}", BROWSER).action, "block")

    def test_allowlists_and_verified_engagements_come_first(self):
        now = datetime.fromtimestamp(T0, timezone.utc)
        eng = Engagement("FS-17", ["198.51.100.0/24"], now - timedelta(hours=1), now + timedelta(hours=1))
        s, _ = shield(allow_cidrs=["10.0.0.0/8"], exempt_paths=["/healthz"], engagements=[eng])
        self.assertEqual(s.check("10.1.2.3", "GET", "/", f"k={KEY}", BROWSER).action, "pass")
        self.assertEqual(s.check("203.0.113.53", "GET", "/healthz", f"k={KEY}", BROWSER).action, "pass")
        tester = dict(BROWSER, **{"User-Agent": "ARTEX-Assessment/1.0 (engagement=FS-17)"})
        self.assertTrue(s.check("198.51.100.24", "GET", "/", f"k={KEY}", tester).friendly)

    def test_config(self):
        self.assertEqual(Config().honeytokens, ())
        self.assertEqual(Config().mode, "monitor")
        for bad in (["short"], ["has a space in it"], "api_live_xxxxxxxxxxxxxxxx"):
            with self.assertRaises(ValueError, msg=bad):
                Config(honeytokens=bad)
        with self.assertRaises(ValueError):
            Config(honeytoken_body_limit=-1)
        self.assertEqual(Config(honeytokens=[KEY, KEY]).honeytokens, (KEY,))

    def test_checking_a_large_request_is_quick(self):
        s, _ = shield()
        headers = dict(BROWSER, **{f"X-Pad-{i}": "a" * 8000 for i in range(60)},
                       Cookie="; ".join(f"c{i}={'x' * 40}" for i in range(400)), Authorization="Basic " + "QUFB" * 2000)
        t0 = time.perf_counter()
        s.check("192.0.2.40", "POST", "/upload", "a=" + "b" * 60000, headers, b"%41" * 21845)
        self.assertLess(time.perf_counter() - t0, 0.25)


class Adapters(unittest.TestCase):
    def wsgi(self, s):
        received = []

        def app(environ, start_response):
            stream = environ["wsgi.input"]
            how = environ.get("HTTP_X_READ", "read")
            if how == "read":
                data = stream.read()
            elif how == "chunks":
                data = b""
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    data += chunk
            elif how == "lines":
                data = b"".join(stream)
            else:
                length = int(environ.get("CONTENT_LENGTH") or 0)
                data = stream.read(length)
            received.append(data)
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        wrapped = ShieldWSGI(app, s)

        def call(body=b"", headers=None, length=True, terminated=False, ip="192.0.2.60"):
            env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/upload", "QUERY_STRING": "", "REMOTE_ADDR": ip,
                   "wsgi.input": io.BytesIO(body)}
            if length:
                env["CONTENT_LENGTH"] = str(len(body))
            if terminated:
                env["wsgi.input_terminated"] = True
            for k, v in dict(BROWSER, **(headers or {})).items():
                env["HTTP_" + k.upper().replace("-", "_")] = v
            out = {}
            b"".join(wrapped(env, lambda st, h, e=None: out.update(status=st)))
            return out["status"]

        return call, received

    def test_wsgi_blocks_before_the_app_and_otherwise_hands_it_the_body_untouched(self):
        s, _ = shield()
        call, received = self.wsgi(s)
        self.assertEqual(call(json.dumps({"apiKey": KEY}).encode(), ip="203.0.113.60"), "403 Forbidden")
        self.assertEqual(received, [])
        big = bytes(range(256)) * 800 + b"\nline two\nline three"      # 200 KB, past the read limit
        for how in ("read", "chunks", "lines", "length"):
            received.clear()
            self.assertEqual(call(big, {"X-Read": how}), "200 OK", how)
            self.assertEqual(received, [big], how)
        received.clear()                                # chunked: no length, but the server marks the end
        self.assertEqual(call(big, {"X-Read": "read"}, length=False, terminated=True), "200 OK")
        self.assertEqual(received, [big])
        received.clear()                                # no length and no end marker: not read, still delivered
        self.assertEqual(call(KEY.encode(), {"X-Read": "read"}, length=False), "200 OK")
        self.assertEqual(received, [KEY.encode()])

    def test_wsgi_without_honeytokens_does_not_touch_the_body(self):
        s, _ = shield(honeytokens=())
        call, received = self.wsgi(s)
        self.assertEqual(call(KEY.encode()), "200 OK")
        self.assertEqual(received, [KEY.encode()])

    def asgi(self, s):
        got = []

        async def app(scope, receive, send):
            body, messages = b"", []
            while True:
                m = await receive()
                messages.append(m)
                body += m.get("body", b"")
                if not m.get("more_body"):
                    break
            got.append((body, [m.get("more_body", False) for m in messages]))
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        wrapped = ShieldASGI(app, s)

        def call(chunks, ip="192.0.2.61", length=True):
            sent, queue, pulls = [], list(chunks), []

            async def receive():
                pulls.append(1)
                chunk = queue.pop(0)
                return {"type": "http.request", "body": chunk, "more_body": bool(queue)}

            async def send(m):
                sent.append(m)

            headers = [(b"user-agent", CHROME.encode()), (b"accept-language", b"en")]
            headers.append((b"content-length", str(sum(map(len, chunks))).encode()) if length else
                           (b"transfer-encoding", b"chunked"))
            scope = {"type": "http", "method": "POST", "path": "/upload", "query_string": b"",
                     "client": (ip, 5555), "headers": headers}
            asyncio.run(wrapped(scope, receive, send))
            return sent[0]["status"], len(pulls)

        return call, got

    def test_asgi_blocks_before_the_app_and_otherwise_replays_every_message(self):
        s, _ = shield()
        call, got = self.asgi(s)
        status, _ = call([b"x" * 1000, b'{"password": "' + PASSWORD.encode() + b'"}'], ip="203.0.113.61")
        self.assertEqual((status, got), (403, []))
        chunks = [bytes([i]) * 30000 for i in range(5)]  # 150 KB in five messages, past the read limit
        status, _ = call(chunks)
        self.assertEqual(status, 200)
        self.assertEqual(got, [(b"".join(chunks), [True, True, True, True, False])])
        got.clear()
        status, _ = call([b"abc", b"def"], length=False)
        self.assertEqual((status, got), (200, [(b"abcdef", [True, False])]))

    def test_asgi_without_a_body_or_honeytokens_reads_nothing_early(self):
        s, _ = shield(honeytokens=())
        call, got = self.asgi(s)
        status, pulls = call([KEY.encode()])
        self.assertEqual((status, pulls, got[0][0]), (200, 1, KEY.encode()))


if __name__ == "__main__":
    unittest.main()
