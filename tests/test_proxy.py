"""artex-shield-proxy, against a small origin server written apart from it.

Everything runs on 127.0.0.1 with ephemeral ports; nothing leaves the machine.
The last class replays spec/vectors.json through the proxy over real sockets.
"""
import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

from unittest import mock

import artex_shield
from artex_shield import Config, Shield, make_honeytokens
from artex_shield.proxy import Proxy, Settings, _host_port, load_settings, main

from test_vectors import Runner, body as vector_body, load

logging.getLogger("artex_shield").disabled = True      # the shield's event log; proxy errors still show
BROWSER = (b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
           b"Chrome/131.0 Safari/537.36\r\nAccept: text/html,*/*\r\nAccept-Language: en-GB,en;q=0.9\r\n")
SCANNER = b"User-Agent: sqlmap/1.8.4#stable (https://sqlmap.org)\r\n"
WAIT = 5.0          # anything that should happen at once, given this long before the test fails


# ---- an origin server ---------------------------------------------------------------
class Request:
    def __init__(self, head: bytes):
        lines = head[:-4].decode("latin-1").split("\r\n")
        self.method, self.target, self.version = lines[0].split(" ")
        self.headers = [tuple(x.strip() for x in line.split(":", 1)) for line in lines[1:]]
        self.body = b""

    def get(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def one(self, name):
        got = self.get(name)
        return got[0] if len(got) == 1 else None


async def read_body(headers, reader):
    """A request or response body by Content-Length or chunked; headers is a list of (name, value)."""
    h = {k.lower(): v for k, v in headers}
    if h.get("transfer-encoding", "").lower() == "chunked":
        out = b""
        while True:
            size = int((await reader.readuntil(b"\r\n")).split(b";")[0], 16)
            if size == 0:
                while await reader.readuntil(b"\r\n") != b"\r\n":
                    pass
                return out
            out += await reader.readexactly(size)
            await reader.readexactly(2)
    return await reader.readexactly(int(h.get("content-length", "0")))


class Origin:
    """A small HTTP/1.1 server. By default it reads the body and answers with
    JSON describing what it received; a test can set `handler` instead."""

    def __init__(self):
        self.seen = []
        self.connections = 0
        self.status = 200
        self.content_type = "application/json"
        self.handler = None
        self.writers = set()

    async def start(self):
        self.server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.url = "http://127.0.0.1:%d" % self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self):
        self.server.close()
        for w in list(self.writers):
            w.close()
        await self.server.wait_closed()

    async def _serve(self, reader, writer):
        self.connections += 1
        self.writers.add(writer)
        try:
            while True:
                try:
                    req = Request(await reader.readuntil(b"\r\n\r\n"))
                except (asyncio.IncompleteReadError, ConnectionError):
                    return
                self.seen.append(req)
                if self.handler is not None:
                    if not await self.handler(req, reader, writer):
                        return
                    continue
                req.body = await read_body(req.headers, reader)
                body = json.dumps({"method": req.method, "target": req.target, "headers": req.headers,
                                   "body": hashlib.sha256(req.body).hexdigest(), "length": len(req.body)}).encode()
                writer.write(b"HTTP/1.1 %d Whatever\r\nContent-Type: %s\r\nX-Origin: yes\r\n"
                             b"Content-Length: %d\r\n\r\n%s" % (self.status, self.content_type.encode(), len(body), body))
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self.writers.discard(writer)
            writer.close()


# ---- a client ----------------------------------------------------------------------------
class Response:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def get(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def one(self, name):
        got = self.get(name)
        return got[0] if got else None

    def json(self):
        return json.loads(self.body)


async def read_response(reader, method="GET"):
    head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), WAIT)
    lines = head[:-4].decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers = [tuple(x.strip() for x in line.split(":", 1)) for line in lines[1:]]
    h = {k.lower(): v for k, v in headers}
    if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
        body = b""
    elif "transfer-encoding" in h or "content-length" in h:
        body = await asyncio.wait_for(read_body(headers, reader), WAIT)
    else:
        body = await asyncio.wait_for(reader.read(), WAIT)
    return Response(status, headers, body)


class Client:
    def __init__(self, port):
        self.port = port

    async def __aenter__(self):
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", self.port)
        return self

    async def __aexit__(self, *exc):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except ConnectionError:
            pass

    async def send(self, raw: bytes):
        self.writer.write(raw)
        await self.writer.drain()

    async def ask(self, raw: bytes, method="GET"):
        await self.send(raw)
        return await read_response(self.reader, method)

    async def closed(self):
        """True when the proxy has closed the connection."""
        return await asyncio.wait_for(self.reader.read(1), WAIT) == b""


def get(path="/", extra=b"", method=b"GET", version=b"HTTP/1.1"):
    return b"%s %s %s\r\nHost: shop.example\r\n%s%s\r\n" % (method, path.encode(), version, BROWSER, extra)


class ProxyTest(unittest.IsolatedAsyncioTestCase):
    config = {}         # the shield's
    settings = {}       # the proxy's

    async def asyncSetUp(self):
        self.origin = await Origin().start()
        self.shield = Shield(Config(**self.config))
        self.proxy = Proxy(Settings(backend=self.origin.url, listen="127.0.0.1:0", **self.settings), self.shield)
        await self.proxy.start()
        self.decisions, self.observed, self.content_types = [], [], []
        check, observe = self.shield.check, self.shield.observe

        self.asked_headers = []

        self.asked_bodies = []

        def checking(ip, method, path, query="", headers=None, body=None):
            d = check(ip, method, path, query, headers, body)
            self.decisions.append((ip, method, path, query, d))
            self.asked_headers.append(dict(headers or {}))
            self.asked_bodies.append(body)
            return d

        def observing(ip, path, status, induced=False, content_type=""):
            self.observed.append((ip, path, status, induced))
            self.content_types.append(content_type)
            return observe(ip, path, status, induced, content_type)

        self.shield.check, self.shield.observe = checking, observing

    async def asyncTearDown(self):
        await self.proxy.stop(grace=1.0)
        await self.origin.stop()

    def client(self):
        return Client(self.proxy.port)

    async def fetch(self, raw, method="GET"):
        async with self.client() as c:
            return await c.ask(raw, method)


# ---- forwarding -----------------------------------------------------------------------
class Forwarding(ProxyTest):
    async def test_a_request_and_its_answer_pass_through(self):
        r = await self.fetch(b"POST /cart/add?item=5&qty=2 HTTP/1.1\r\nHost: shop.example\r\n" + BROWSER +
                             b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nitem=5&qty2")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.one("X-Origin"), "yes")
        seen = self.origin.seen[0]
        self.assertEqual((seen.method, seen.target, seen.one("Host"), seen.one("Content-Length")),
                         ("POST", "/cart/add?item=5&qty=2", "shop.example", "11"))
        self.assertEqual(r.json()["body"], hashlib.sha256(b"item=5&qty2").hexdigest())
        self.assertEqual(self.decisions[0][1:4], ("POST", "/cart/add", "item=5&qty=2"))

    async def test_the_backends_host_can_be_sent_instead(self):
        self.proxy.settings.backend_host_header = "backend"
        await self.fetch(get())
        self.assertEqual(self.origin.seen[0].one("Host"), self.origin.url[len("http://"):])
        self.assertEqual(self.origin.seen[0].one("X-Forwarded-Host"), "shop.example")

    async def test_x_forwarded_headers_from_an_untrusted_client_are_replaced(self):
        await self.fetch(get(extra=b"X-Forwarded-For: 6.6.6.6\r\nX-Forwarded-Proto: https\r\n"
                                   b"X-Forwarded-Host: evil.example\r\nForwarded: for=6.6.6.6\r\n"))
        seen = self.origin.seen[0]
        self.assertEqual(seen.get("X-Forwarded-For"), ["127.0.0.1"])
        self.assertEqual(seen.get("X-Forwarded-Proto"), ["http"])
        self.assertEqual(seen.get("X-Forwarded-Host"), ["shop.example"])
        self.assertEqual(seen.get("Forwarded"), [])
        self.assertEqual(self.decisions[0][0], "127.0.0.1")

    async def test_hop_by_hop_headers_stay_on_their_own_connection(self):
        async def handler(req, reader, writer):
            writer.write(b"HTTP/1.1 200 OK\r\nConnection: X-Internal\r\nX-Internal: secret\r\nKeep-Alive: timeout=1\r\n"
                         b"Proxy-Authenticate: Basic\r\nX-Kept: 1\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            return True
        self.origin.handler = handler
        r = await self.fetch(get(extra=b"Connection: keep-alive, X-Hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\n"
                                       b"TE: trailers\r\nProxy-Authorization: Basic eDp5\r\nUpgrade: h2c\r\n"
                                       b"Proxy-Connection: keep-alive\r\nX-Kept: 1\r\n"))
        seen = {k.lower() for k, _ in self.origin.seen[0].headers}
        self.assertFalse(seen & {"x-hop", "keep-alive", "te", "proxy-authorization", "upgrade", "proxy-connection"})
        self.assertIn("x-kept", seen)
        self.assertEqual(self.origin.seen[0].get("Connection"), ["keep-alive"])
        got = {k.lower() for k, _ in r.headers}
        self.assertFalse(got & {"x-internal", "keep-alive", "proxy-authenticate"})
        self.assertEqual(r.get("Connection"), ["keep-alive"])
        self.assertEqual((r.one("X-Kept"), r.body), ("1", b"ok"))

    async def test_the_shield_reads_the_decoded_path_and_the_backend_gets_it_as_sent(self):
        await self.fetch(get("/caf%C3%A9/a%20b/%2e%2e/x?q=a%20b"))
        self.assertEqual(self.decisions[0][2:4], ("/café/a b/../x", "q=a%20b"))
        self.assertEqual(self.origin.seen[0].target, "/caf%C3%A9/a%20b/%2e%2e/x?q=a%20b")

    async def test_repeated_headers_reach_the_shield_joined(self):
        await self.fetch(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\naccept: */*\r\n"
                         b"Cookie: a=1\r\nCookie: b=2\r\n\r\n")
        seen = self.asked_headers[0]
        self.assertEqual((seen["accept"], seen["cookie"]), ("text/html, */*", "a=1; b=2"))
        self.assertEqual(self.origin.seen[0].get("Cookie"), ["a=1", "b=2"])     # sent on as they came

    async def test_an_absolute_url_is_sent_on_as_a_path_with_its_host(self):
        await self.fetch(b"GET http://shop.example/a?b=1 HTTP/1.1\r\nHost: other.example\r\n" + BROWSER + b"\r\n")
        self.assertEqual((self.origin.seen[0].target, self.origin.seen[0].get("Host")), ("/a?b=1", ["shop.example"]))
        self.assertEqual(self.decisions[0][2:4], ("/a", "b=1"))

    async def test_connect_is_refused(self):
        r = await self.fetch(b"CONNECT /x HTTP/1.1\r\nHost: shop.example\r\n" + BROWSER + b"\r\n")
        self.assertEqual(r.status, 405)
        self.assertEqual(self.origin.seen, [])

    async def test_every_pipelined_request_goes_through_the_shield(self):
        async with self.client() as c:
            await c.send(b"POST /a HTTP/1.1\r\nHost: x\r\n" + BROWSER + b"Content-Length: 0\r\n\r\n" + get("/b") + get("/c"))
            answers = [await read_response(c.reader) for _ in range(3)]
        self.assertEqual([a.json()["target"] for a in answers], ["/a", "/b", "/c"])
        self.assertEqual([d[2] for d in self.decisions], ["/a", "/b", "/c"])


class TrustedPeer(ProxyTest):
    config = {"trusted_proxies": ["127.0.0.0/8"]}

    async def test_x_forwarded_for_from_a_trusted_proxy_is_kept_and_extended(self):
        await self.fetch(get(extra=b"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: https\r\n"
                                   b"X-Forwarded-Host: www.example\r\n"))
        seen = self.origin.seen[0]
        self.assertEqual(seen.get("X-Forwarded-For"), ["203.0.113.7, 127.0.0.1"])
        self.assertEqual(seen.get("X-Forwarded-Proto"), ["https"])
        self.assertEqual(seen.get("X-Forwarded-Host"), ["www.example"])
        self.assertEqual(self.decisions[0][0], "203.0.113.7")

    async def test_the_client_behind_the_proxy_is_the_one_scored(self):
        self.shield.cfg.mode = "enforce"
        self.assertEqual((await self.fetch(get(extra=b"X-Forwarded-For: 203.0.113.7\r\n" + SCANNER))).status, 403)
        self.assertEqual((await self.fetch(get(extra=b"X-Forwarded-For: 203.0.113.7\r\n"))).status, 403)
        self.assertEqual((await self.fetch(get(extra=b"X-Forwarded-For: 198.51.100.9\r\n"))).status, 200)


# ---- what the shield decides -----------------------------------------------------------------
class Enforce(ProxyTest):
    config = {"mode": "enforce"}

    async def test_a_scanner_is_blocked_and_never_reaches_the_site(self):
        r = await self.fetch(get(extra=SCANNER))
        self.assertEqual(r.status, 403)
        self.assertRegex(r.body.decode(), r"^Request blocked\. Reference: [0-9a-f]{8}\n$")
        self.assertEqual((r.one("Content-Type"), r.one("Cache-Control")), ("text/plain; charset=utf-8", "no-store"))
        self.assertEqual((await self.fetch(get("/about"))).status, 403)        # the address stays blocked
        self.assertEqual(self.origin.seen, [])

    async def test_a_payload_is_throttled_with_retry_after(self):
        r = await self.fetch(get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E"))
        self.assertEqual(r.status, 429)
        self.assertRegex(r.body.decode(), r"^Too many requests\. Reference: [0-9a-f]{8}\n$")
        self.assertEqual(r.one("Retry-After"), str(self.decisions[0][4].retry_after))
        self.assertEqual(self.origin.seen, [])

    async def test_a_stopped_request_keeps_the_connection_unless_it_had_a_body(self):
        async with self.client() as c:
            self.assertEqual((await c.ask(get(extra=SCANNER))).one("Connection"), "keep-alive")
            r = await c.ask(get("/x", method=b"HEAD"), "HEAD")
            self.assertEqual((r.status, r.body), (403, b""))
            r = await c.ask(b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
            self.assertEqual((r.status, r.one("Connection")), (403, "close"))
            self.assertTrue(await c.closed())

    async def test_a_stopped_request_gets_no_100_continue(self):
        async with self.client() as c:
            r = await c.ask(get("/upload", method=b"PUT", extra=SCANNER + b"Expect: 100-continue\r\nContent-Length: 4\r\n"))
            self.assertEqual((r.status, r.one("Connection")), (403, "close"))
            self.assertTrue(await c.closed())
        self.assertEqual(self.origin.seen, [])

    async def test_a_websocket_handshake_is_checked_like_any_request(self):
        r = await self.fetch(get("/ws", extra=SCANNER + b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
                                                         b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                                         b"Sec-WebSocket-Version: 13\r\n"))
        self.assertEqual(r.status, 403)
        self.assertEqual(self.origin.seen, [])

    async def test_an_encoded_traversal_is_caught(self):
        r = await self.fetch(get("/static/..%2f..%2f..%2fetc%2fpasswd"))
        self.assertIn(r.status, (403, 429))
        self.assertIn("payload:traversal", self.decisions[0][4].hits)
        self.assertEqual(self.origin.seen, [])

    async def test_missing_files_the_backend_reports_build_a_score(self):
        self.origin.status = 404
        r = await self.fetch(get("/old-site-backup.sql"))
        self.assertEqual(r.status, 404)
        self.assertEqual(self.observed, [("127.0.0.1", "/old-site-backup.sql", 404, False)])
        self.origin.status = 200
        r = await self.fetch(get("/"))
        self.assertEqual(r.status, 429)                    # 60 points for asking for a dump that is not there
        self.assertAlmostEqual(self.decisions[1][4].score, 60.0, delta=0.1)     # less a moment's decay


class Monitor(ProxyTest):
    async def test_monitor_mode_decides_but_lets_everything_through(self):
        r = await self.fetch(get(extra=SCANNER))
        self.assertEqual(r.status, 200)
        d = self.decisions[0][4]
        self.assertEqual((d.action, d.enforced), ("block", False))
        self.assertEqual(len(self.origin.seen), 1)

    async def test_the_backends_status_and_the_induced_flag_reach_the_shield(self):
        self.origin.status = 404
        await self.fetch(get("/gone"))
        await self.fetch(get("/logo.png", extra=b"Sec-Fetch-Site: cross-site\r\nSec-Fetch-Dest: image\r\n"))
        self.assertEqual(self.observed, [("127.0.0.1", "/gone", 404, False), ("127.0.0.1", "/logo.png", 404, True)])


# ---- connections --------------------------------------------------------------------------------
class Connections(ProxyTest):
    async def test_one_client_connection_carries_many_requests_over_one_backend_connection(self):
        async with self.client() as c:
            for n in range(5):
                r = await c.ask(get(f"/page/{n}"))
                self.assertEqual((r.status, r.json()["target"], r.one("Connection")), (200, f"/page/{n}", "keep-alive"))
        self.assertEqual((self.origin.connections, self.proxy.backend.opened), (1, 1))

    async def test_connection_close_is_honoured(self):
        async with self.client() as c:
            r = await c.ask(get(extra=b"Connection: close\r\n"))
            self.assertEqual((r.status, r.one("Connection")), (200, "close"))
            self.assertTrue(await c.closed())

    async def test_http_1_0_closes_unless_it_asks_for_keep_alive(self):
        async with self.client() as c:
            r = await c.ask(get(version=b"HTTP/1.0"))
            self.assertEqual((r.status, r.one("Connection")), (200, "close"))
            self.assertTrue(await c.closed())
        async with self.client() as c:
            for _ in range(2):
                r = await c.ask(get(version=b"HTTP/1.0", extra=b"Connection: keep-alive\r\n"))
                self.assertEqual((r.status, r.one("Connection")), (200, "keep-alive"))

    async def test_an_idle_client_connection_is_closed(self):
        self.proxy.settings.idle_timeout = 0.2
        async with self.client() as c:
            await c.ask(get())
            self.assertTrue(await c.closed())

    def closes_on_the_second_request(self):
        """An origin that drops a kept-alive connection just as the next
        request arrives: the race every pool loses now and then."""
        counts = {}

        async def handler(req, reader, writer):
            counts[writer] = counts.get(writer, 0) + 1
            if counts[writer] == 2:
                return False
            await read_body(req.headers, reader)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            return True
        self.origin.handler = handler

    async def test_a_get_is_retried_once_when_the_pooled_connection_had_been_closed(self):
        self.closes_on_the_second_request()
        async with self.client() as c:
            self.assertEqual((await c.ask(get())).status, 200)
            self.assertEqual((await c.ask(get("/again"))).status, 200)
        self.assertEqual(self.origin.connections, 2)
        self.assertEqual([r.target for r in self.origin.seen], ["/", "/again", "/again"])

    async def test_a_post_is_never_sent_twice(self):
        self.closes_on_the_second_request()
        async with self.client() as c:
            self.assertEqual((await c.ask(get())).status, 200)
            r = await c.ask(b"POST /pay HTTP/1.1\r\nHost: x\r\n" + BROWSER + b"Content-Length: 2\r\n\r\n{}")
            self.assertEqual(r.status, 502)
        self.assertEqual([r.target for r in self.origin.seen], ["/", "/pay"])

    async def test_a_pooled_connection_is_dropped_before_the_backend_would_drop_it(self):
        self.proxy.settings.backend_idle_timeout = 0.1
        async with self.client() as c:
            await c.ask(get())
            await asyncio.sleep(0.2)
            r = await c.ask(b"POST /order HTTP/1.1\r\nHost: x\r\n" + BROWSER + b"Content-Length: 1\r\n\r\n1")
            self.assertEqual(r.status, 200)
        self.assertEqual(self.proxy.backend.opened, 2)

    async def test_stop_closes_idle_connections_at_once(self):
        async with self.client() as c:
            await c.ask(get())
            started = time.monotonic()
            await self.proxy.stop(grace=5.0)
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertTrue(await c.closed())


# ---- bodies ---------------------------------------------------------------------------------------
class Streaming(ProxyTest):
    async def test_a_chunked_upload_reaches_the_backend_while_the_client_is_still_sending(self):
        first = asyncio.Event()

        async def handler(req, reader, writer):
            size = int((await reader.readuntil(b"\r\n")).split(b";")[0], 16)
            data = await reader.readexactly(size)
            first.set()                                    # the client only sends the rest after this
            await reader.readexactly(2)
            data += await read_body([("transfer-encoding", "chunked")], reader)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(data), data))
            await writer.drain()
            return True
        self.origin.handler = handler
        async with self.client() as c:
            await c.send(b"POST /upload HTTP/1.1\r\nHost: x\r\n" + BROWSER + b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
            await asyncio.wait_for(first.wait(), WAIT)     # a proxy that buffered the body would hang here
            r = await c.ask(b"6\r\n world\r\n0\r\n\r\n")
        self.assertEqual(r.body, b"hello world")
        self.assertEqual(self.origin.seen[0].get("Transfer-Encoding"), ["chunked"])

    async def test_a_sized_upload_streams_too(self):
        half = asyncio.Event()

        async def handler(req, reader, writer):
            data = await reader.readexactly(5)
            half.set()
            data += await reader.readexactly(5)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(data), data))
            await writer.drain()
            return True
        self.origin.handler = handler
        async with self.client() as c:
            await c.send(b"PUT /f HTTP/1.1\r\nHost: x\r\n" + BROWSER + b"Content-Length: 10\r\n\r\nhello")
            await asyncio.wait_for(half.wait(), WAIT)
            r = await c.ask(b"world")
        self.assertEqual(r.body, b"helloworld")

    async def test_a_response_reaches_the_client_while_the_backend_is_still_sending(self):
        got_first = asyncio.Event()

        async def handler(req, reader, writer):
            writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n")
            await writer.drain()
            await asyncio.wait_for(got_first.wait(), WAIT)
            writer.write(b"6\r\nsecond\r\n0\r\n\r\n")
            await writer.drain()
            return True
        self.origin.handler = handler
        async with self.client() as c:
            await c.send(get("/events"))
            head = await asyncio.wait_for(c.reader.readuntil(b"\r\n\r\n"), WAIT)
            self.assertIn(b"Transfer-Encoding: chunked", head)
            buf = b""
            while b"first" not in buf:
                buf += await asyncio.wait_for(c.reader.read(100), WAIT)
            got_first.set()
            while not buf.endswith(b"0\r\n\r\n"):
                buf += await asyncio.wait_for(c.reader.read(100), WAIT)
        self.assertIn(b"second", buf)

    async def test_a_large_body_arrives_intact_both_ways(self):
        blob = os.urandom(3 * 1024 * 1024)

        async def handler(req, reader, writer):
            data = await read_body(req.headers, reader)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(data), data[::-1]))
            await writer.drain()
            return True
        self.origin.handler = handler
        r = await self.fetch(b"POST /big HTTP/1.1\r\nHost: x\r\n" + BROWSER + b"Content-Length: %d\r\n\r\n" % len(blob) + blob)
        self.assertEqual(hashlib.sha256(r.body).digest(), hashlib.sha256(blob[::-1]).digest())

    async def test_a_response_without_a_length_runs_to_the_close_and_is_chunked_on(self):
        async def handler(req, reader, writer):
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"x" * 100000)
            await writer.drain()
            return False
        self.origin.handler = handler
        async with self.client() as c:
            r = await c.ask(get())
            self.assertEqual((r.status, r.one("Transfer-Encoding"), len(r.body)), (200, "chunked", 100000))
            self.assertEqual((await c.ask(get())).status, 200)          # the client's connection lives on
        self.assertEqual(self.origin.connections, 2)                   # the backend's did not

    async def test_head_204_and_304_answers_carry_no_body(self):
        async def handler(req, reader, writer):
            status = {"/head": 200, "/none": 204, "/same": 304}[req.target]
            writer.write(b"HTTP/1.1 %d X\r\nContent-Length: 50\r\nETag: \"v1\"\r\n\r\n" % status
                         if status != 204 else b"HTTP/1.1 204 No Content\r\n\r\n")
            await writer.drain()
            return True
        self.origin.handler = handler
        async with self.client() as c:
            self.assertEqual((await c.ask(get("/head", method=b"HEAD"), "HEAD")).status, 200)
            self.assertEqual((await c.ask(get("/none"))).status, 204)
            self.assertEqual((await c.ask(get("/same"))).status, 304)
            self.assertEqual((await c.ask(get("/head", method=b"HEAD"), "HEAD")).status, 200)   # nothing left over
        self.assertEqual(self.origin.connections, 1)

    async def test_100_continue_lets_the_client_send_its_body(self):
        async with self.client() as c:
            await c.send(b"PUT /f HTTP/1.1\r\nHost: x\r\n" + BROWSER + b"Expect: 100-continue\r\nContent-Length: 5\r\n\r\n")
            interim = await read_response(c.reader)
            self.assertEqual(interim.status, 100)
            r = await c.ask(b"hello")
        self.assertEqual((r.status, r.json()["length"]), (200, 5))
        self.assertEqual(self.origin.seen[0].get("Expect"), [])

    async def test_early_hints_are_passed_on(self):
        async def handler(req, reader, writer):
            writer.write(b"HTTP/1.1 103 Early Hints\r\nLink: </app.css>; rel=preload\r\n\r\n"
                         b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            return True
        self.origin.handler = handler
        async with self.client() as c:
            await c.send(get())
            hint, final = await read_response(c.reader), await read_response(c.reader)
        self.assertEqual((hint.status, hint.one("Link"), final.status, final.body), (103, "</app.css>; rel=preload", 200, b"ok"))


# ---- honeytokens and the client check -----------------------------------------------------------------
TOKENS = make_honeytokens("proxy-test-secret")


class Honeytokens(ProxyTest):
    config = {"mode": "enforce", "honeytokens": TOKENS}

    async def test_a_planted_key_in_a_body_is_blocked_before_the_site(self):
        payload = json.dumps({"apiKey": TOKENS.api_keys[0], "q": "x"}).encode()
        r = await self.fetch(b"POST /api/report HTTP/1.1\r\nHost: x\r\n" + BROWSER +
                             b"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (len(payload), payload))
        self.assertEqual((r.status, r.one("Connection")), (403, "close"))
        self.assertIn("decoy:honeytoken-body", self.decisions[0][4].hits)
        self.assertEqual(self.origin.seen, [])

    async def test_a_planted_password_in_a_chunked_form_is_blocked(self):
        form = urllib.parse.urlencode({"log": TOKENS.users[1], "pwd": TOKENS.passwords[1]}).encode()
        r = await self.fetch(b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\n" + BROWSER +
                             b"Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n" % (len(form), form))
        self.assertEqual(r.status, 403)
        self.assertEqual(self.origin.seen, [])

    async def test_a_planted_key_in_a_header_is_blocked(self):
        r = await self.fetch(get("/api/items", extra=b"Authorization: Bearer %s\r\n" % TOKENS.api_keys[1].encode()))
        self.assertEqual(r.status, 403)
        self.assertIn("decoy:honeytoken-header", self.decisions[0][4].hits)

    async def test_100_continue_comes_first_so_the_body_can_be_read(self):
        payload = b"key=" + TOKENS.api_keys[0].encode()
        async with self.client() as c:
            await c.send(b"POST /x HTTP/1.1\r\nHost: x\r\n" + BROWSER +
                         b"Expect: 100-continue\r\nContent-Length: %d\r\n\r\n" % len(payload))
            self.assertEqual((await read_response(c.reader)).status, 100)
            self.assertEqual((await c.ask(payload)).status, 403)

    async def test_ordinary_bodies_reach_the_site_whole(self):
        blob = os.urandom(200 * 1024)                     # well past what is read ahead
        r = await self.fetch(b"POST /upload HTTP/1.1\r\nHost: x\r\n" + BROWSER +
                             b"Content-Length: %d\r\n\r\n" % len(blob) + blob)
        self.assertEqual((r.status, r.json()["body"]), (200, hashlib.sha256(blob).hexdigest()))
        self.assertEqual(self.asked_bodies[0], blob[:65536])
        chunks = b"".join(b"%x\r\n%s\r\n" % (len(p), p) for p in (blob[:1000], blob[1000:90000], blob[90000:]))
        r = await self.fetch(b"PUT /upload HTTP/1.1\r\nHost: x\r\n" + BROWSER + b"Transfer-Encoding: chunked\r\n\r\n" +
                             chunks + b"0\r\n\r\n")
        self.assertEqual((r.status, r.json()["body"]), (200, hashlib.sha256(blob).hexdigest()))

    async def test_a_key_past_the_limit_is_not_read_as_the_shield_would_not(self):
        payload = b"x" * 70000 + TOKENS.api_keys[0].encode()
        r = await self.fetch(b"POST /upload HTTP/1.1\r\nHost: x\r\n" + BROWSER +
                             b"Content-Length: %d\r\n\r\n" % len(payload) + payload)
        self.assertEqual((r.status, r.json()["length"]), (200, len(payload)))

    async def test_without_honeytokens_bodies_are_not_read_ahead(self):
        self.shield.cfg.honeytokens = ()
        await self.fetch(b"POST /x HTTP/1.1\r\nHost: x\r\n" + BROWSER + b"Content-Length: 5\r\n\r\nhello")
        self.assertEqual(self.asked_bodies, [None])


class ClientCheck(ProxyTest):
    config = {"mode": "enforce", "client_check": True, "client_check_secret": "s", "client_check_grace": 0,
              "trusted_proxies": ["127.0.0.0/8"]}
    PAGE = b"Sec-Fetch-Site: none\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n"
    FETCH = b"Sec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\n"

    async def test_the_proxy_serves_the_script_and_answers_the_check_itself(self):
        r = await self.fetch(get("/_artex/check.js"))
        self.assertEqual((r.status, r.one("Content-Type")), (200, "text/javascript; charset=utf-8"))
        self.assertIn(b'"/_artex/check"', r.body)
        r = await self.fetch(get("/_artex/check?v=1&f=0", extra=self.FETCH))
        self.assertEqual(r.status, 204)
        self.assertRegex(r.one("Set-Cookie"), r"^artex_check=1\.\d+\.0\.[\w-]{22}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax$")
        r = await self.fetch(get("/_artex/check?v=1&f=0", extra=self.FETCH + b"X-Forwarded-Proto: https\r\n"))
        self.assertTrue(r.one("Set-Cookie").endswith("; Secure"))
        self.assertEqual(self.origin.seen, [])

    async def test_an_api_client_that_loads_pages_but_never_checks_is_noted(self):
        self.origin.content_type = "text/html; charset=utf-8"
        await self.fetch(get("/", extra=self.PAGE + b"X-Forwarded-For: 198.51.100.1\r\n"))
        self.assertEqual(self.content_types, ["text/html; charset=utf-8"])
        self.origin.content_type = "application/json"
        await self.fetch(get("/api/items", extra=self.FETCH + b"X-Forwarded-For: 198.51.100.1\r\n"))
        self.assertIn("client:no-check", self.decisions[-1][4].hits)

    async def test_a_browser_that_ran_the_check_is_not(self):
        self.origin.content_type = "text/html; charset=utf-8"
        async with self.client() as c:
            who = b"X-Forwarded-For: 198.51.100.2\r\n"
            await c.ask(get("/", extra=self.PAGE + who))
            cookie = (await c.ask(get("/_artex/check?v=1&f=0", extra=self.FETCH + who))).one("Set-Cookie").split(";")[0]
            await c.ask(get("/api/items", extra=self.FETCH + who + b"Cookie: %s\r\n" % cookie.encode()))
        self.assertEqual([h for h in self.decisions[-1][4].hits if h.startswith("client:")], [])


# ---- WebSockets ---------------------------------------------------------------------------------------
def ws_frame(text: str, mask: bool) -> bytes:
    data = text.encode()
    if not mask:
        return bytes([0x81, len(data)]) + data
    key = os.urandom(4)
    return bytes([0x81, 0x80 | len(data)]) + key + bytes(b ^ key[i % 4] for i, b in enumerate(data))


async def ws_read(reader) -> str:
    b0, b1 = await reader.readexactly(2)
    n = b1 & 0x7F
    key = await reader.readexactly(4) if b1 & 0x80 else b"\0\0\0\0"
    data = await reader.readexactly(n)
    return bytes(b ^ key[i % 4] for i, b in enumerate(data)).decode()


class WebSockets(ProxyTest):
    KEY = "dGhlIHNhbXBsZSBub25jZQ=="

    async def ws_origin(self, req, reader, writer):
        if req.one("Upgrade") != "websocket":
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return True
        accept = base64.b64encode(hashlib.sha1((req.one("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                                               .encode()).digest())
        writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     b"Sec-WebSocket-Accept: %s\r\n\r\n" % accept)
        writer.write(ws_frame("welcome", mask=False))      # the server speaks first: both directions are open
        await writer.drain()
        try:
            while True:
                writer.write(ws_frame("echo: " + await ws_read(reader), mask=False))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            return False

    def handshake(self, upgrade=b"websocket"):
        return get("/socket", extra=b"Connection: keep-alive, Upgrade\r\nUpgrade: %s\r\nSec-WebSocket-Key: %s\r\n"
                                    b"Sec-WebSocket-Version: 13\r\n" % (upgrade, self.KEY.encode()))

    async def test_a_websocket_is_tunnelled_after_the_handshake(self):
        self.origin.handler = self.ws_origin
        async with self.client() as c:
            r = await c.ask(self.handshake())
            self.assertEqual((r.status, r.one("Upgrade"), r.one("Connection")), (101, "websocket", "Upgrade"))
            self.assertEqual(r.one("Sec-WebSocket-Accept"), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
            self.assertEqual(await asyncio.wait_for(ws_read(c.reader), WAIT), "welcome")
            for text in ("hello", "again"):
                await c.send(ws_frame(text, mask=True))
                self.assertEqual(await asyncio.wait_for(ws_read(c.reader), WAIT), "echo: " + text)
        seen = self.origin.seen[0]
        self.assertEqual((seen.one("Upgrade"), seen.one("Connection"), seen.one("Sec-WebSocket-Key")),
                         ("websocket", "Upgrade", self.KEY))
        self.assertEqual(self.decisions[0][2], "/socket")
        self.assertEqual(self.observed, [("127.0.0.1", "/socket", 101, False)])

    async def test_an_upgrade_to_anything_but_a_websocket_is_not_passed_on(self):
        self.origin.handler = self.ws_origin
        r = await self.fetch(self.handshake(upgrade=b"h2c"))
        self.assertEqual(r.status, 400)                                 # the origin's answer to a plain GET here
        self.assertEqual(self.origin.seen[0].get("Upgrade"), [])        # Upgrade is hop-by-hop

    async def test_a_websocket_the_backend_turns_down_is_answered_and_closed(self):
        async def refuse(req, reader, writer):
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno")
            await writer.drain()
            return True
        self.origin.handler = refuse
        async with self.client() as c:
            r = await c.ask(self.handshake())
            self.assertEqual((r.status, r.body, r.one("Connection")), (403, b"no", "close"))
            self.assertTrue(await c.closed())


# ---- failures ---------------------------------------------------------------------------------------------
class BackendFailures(ProxyTest):
    async def test_502_when_the_backend_is_down(self):
        await self.origin.stop()
        self.origin.stop = lambda: asyncio.sleep(0)
        r = await self.fetch(get())
        self.assertEqual((r.status, r.one("Connection")), (502, "close"))

    async def test_504_when_the_backend_is_too_slow(self):
        self.proxy.settings.read_timeout = 0.2

        async def slow(req, reader, writer):
            await asyncio.sleep(3)
            return False
        self.origin.handler = slow
        self.assertEqual((await self.fetch(get())).status, 504)

    async def test_502_when_the_backend_answers_nonsense(self):
        async def nonsense(req, reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.9\r\n\r\n")
            await writer.drain()
            return False
        self.origin.handler = nonsense
        self.assertEqual((await self.fetch(get())).status, 502)


class Smuggling(ProxyTest):
    """Requests whose framing two servers could read differently are refused,
    so nothing can ride past the shield inside another request's body."""
    HIDDEN = b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"

    async def refused(self, raw, status=400):
        async with self.client() as c:
            r = await c.ask(raw)
            self.assertEqual((r.status, r.one("Connection")), (status, "close"), raw)
            self.assertTrue(await c.closed())
        self.assertNotIn("/admin", [d[2] for d in self.decisions])

    async def test_content_length_with_transfer_encoding(self):
        await self.refused(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
                           b"0\r\n\r\n" + self.HIDDEN)
        self.assertEqual(self.origin.seen, [])

    async def test_conflicting_or_malformed_lengths(self):
        for cl in (b"Content-Length: 5\r\nContent-Length: 6\r\n", b"Content-Length: 5, 6\r\n",
                   b"Content-Length: -1\r\n", b"Content-Length: +5\r\n", b"Content-Length: 0x5\r\n",
                   b"Content-Length: 99999999999999999999\r\n"):
            await self.refused(b"POST / HTTP/1.1\r\nHost: x\r\n" + cl + b"\r\nhello" + self.HIDDEN)
        self.assertEqual(self.origin.seen, [])

    async def test_codings_other_than_chunked(self):
        for te in (b"chunked, gzip", b"gzip", b"xchunked", b"chunked, chunked"):
            await self.refused(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: %s\r\n\r\n0\r\n\r\n" % te + self.HIDDEN,
                               status=501)
        await self.refused(b"POST / HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + self.HIDDEN)

    async def test_malformed_chunks(self):
        for body in (b"zz\r\nhello\r\n0\r\n\r\n", b"5\r\nhelloXX0\r\n\r\n", b"-5\r\nhello\r\n0\r\n\r\n",
                     b"5 5\r\nhello\r\n0\r\n\r\n"):
            await self.refused(b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + body + self.HIDDEN)

    async def test_malformed_heads(self):
        for raw in (b"GET / HTTP/1.1\r\nHost: x\r\n folded: on\r\n\r\n",
                    b"GET / HTTP/1.1\r\nHost : x\r\n\r\n",
                    b"GET / HTTP/1.1\r\nNo-Colon\r\n\r\n",
                    b"GET / HTTP/1.1\r\nX: a\nTransfer-Encoding: chunked\r\n\r\n",
                    b"GET / HTTP/1.1\r\nX: a\rb\r\n\r\n",
                    b"GET / HTTP/1.1\r\nX: a\x00b\r\n\r\n",
                    b"GET  / HTTP/1.1\r\n\r\n",
                    b"GET /a b HTTP/1.1\r\n\r\n",
                    b"G(T / HTTP/1.1\r\n\r\n",
                    b"GET example.com HTTP/1.1\r\n\r\n",
                    b"GET * HTTP/1.1\r\n\r\n",
                    b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n"):
            await self.refused(raw)
        await self.refused(b"GET / HTTP/2.0\r\n\r\n", status=505)
        self.assertEqual(self.origin.seen, [])

    async def test_an_oversized_head(self):
        await self.refused(b"GET / HTTP/1.1\r\nX-Big: " + b"a" * 70000 + b"\r\n\r\n", status=431)


# ---- settings -----------------------------------------------------------------------------------------------
class Configuration(unittest.TestCase):
    def test_environment_variables(self):
        env = {"ARTEX_SHIELD_BACKEND": "http://wordpress:80", "ARTEX_SHIELD_LISTEN": "8081",
               "ARTEX_SHIELD_MODE": "enforce", "ARTEX_SHIELD_TRUSTED_PROXIES": "10.0.0.0/8, 172.16.0.0/12",
               "ARTEX_SHIELD_SCORE_INDUCED": "yes", "ARTEX_SHIELD_HALF_LIFE": "300", "ARTEX_SHIELD_RETRY_AFTER": "60",
               "ARTEX_SHIELD_TLS_HEADER": "X-JA4", "ARTEX_SHIELD_READ_TIMEOUT": "5", "ARTEX_SHIELD_ACCESS_LOG": "on",
               "ARTEX_SHIELD_CANARY_SECRET": "s3cret", "ARTEX_SHIELD_CANARY_COUNT": "2",
               "ARTEX_SHIELD_ENGAGEMENTS": json.dumps([{"reference": "ENG-1", "cidrs": ["198.51.100.0/24"],
                                                        "start": "2026-01-01T00:00:00Z", "end": "2026-02-01T00:00:00Z"}]),
               "HOME": "/root"}
        s = load_settings(env=env)
        c = s.shield
        self.assertEqual((s.backend, s.listen_host, s.listen_port, s.read_timeout, s.access_log),
                         ("http://wordpress:80", "0.0.0.0", 8081, 5.0, True))
        self.assertEqual((c.mode, c.trusted_proxies, c.score_induced, c.half_life, c.retry_after, c.tls_header),
                         ("enforce", ["10.0.0.0/8", "172.16.0.0/12"], True, 300.0, 60, "X-JA4"))
        self.assertEqual(len(c.canary_paths), 2)
        self.assertEqual(c.engagements[0].reference, "ENG-1")

    def test_honeytokens_from_a_secret(self):
        s = load_settings(env={"ARTEX_SHIELD_BACKEND": "http://a:1", "ARTEX_SHIELD_HONEYTOKEN_SECRET": "hs",
                               "ARTEX_SHIELD_HONEYTOKEN_COUNT": "3"})
        self.assertEqual(s.shield.honeytokens, tuple(make_honeytokens("hs", 3)))

    def test_print_decoys(self):
        from contextlib import redirect_stdout
        from io import StringIO
        env = {"ARTEX_SHIELD_BACKEND": "http://a:1", "ARTEX_SHIELD_CANARY_SECRET": "cs",
               "ARTEX_SHIELD_HONEYTOKEN_SECRET": "hs", "ARTEX_SHIELD_CLIENT_CHECK": "on"}
        out = StringIO()
        root = logging.getLogger()
        handlers, level = root.handlers[:], root.level
        try:
            with mock.patch.dict(os.environ, env), redirect_stdout(out):
                self.assertEqual(main(["--print-decoys"]), 0)
        finally:
            root.handlers[:], root.level = handlers, level
        text = out.getvalue()
        tokens = make_honeytokens("hs")
        for snippet in ("Disallow: /api/v1/internal/audit-", tokens.api_keys[0], tokens.passwords[1],
                        '<script src="/_artex/check.js" async></script>'):
            self.assertIn(snippet, text)

    def test_the_command_line_wins(self):
        s = load_settings(env={"ARTEX_SHIELD_BACKEND": "http://a:1", "ARTEX_SHIELD_MODE": "enforce"},
                          overrides={"backend": "http://b:2", "mode": "monitor", "listen": None})
        self.assertEqual((s.backend, s.shield.mode, s.listen), ("http://b:2", "monitor", "0.0.0.0:8080"))

    def test_mistakes_are_refused(self):
        for env in ({}, {"ARTEX_SHIELD_BACKEND": "ftp://x"}, {"ARTEX_SHIELD_BACKEND": "http://x/wp"},
                    {"ARTEX_SHIELD_BACKEND": "http://x", "ARTEX_SHIELD_MODEE": "enforce"},
                    {"ARTEX_SHIELD_BACKEND": "http://x", "ARTEX_SHIELD_SCORE_INDUCED": "maybe"},
                    {"ARTEX_SHIELD_BACKEND": "http://x", "ARTEX_SHIELD_HALF_LIFE": "soon"},
                    {"ARTEX_SHIELD_BACKEND": "http://x", "ARTEX_SHIELD_MODE": "block-everyone"},
                    {"ARTEX_SHIELD_BACKEND": "http://x", "ARTEX_SHIELD_LISTEN": "localhost"},
                    {"ARTEX_SHIELD_BACKEND": "http://x", "ARTEX_SHIELD_ENGAGEMENTS": "[{"},
                    {"ARTEX_SHIELD_BACKEND": "http://x", "ARTEX_SHIELD_ENGAGEMENTS": '[{"reference": "E"}]'},
                    {"ARTEX_SHIELD_BACKEND": "http://x", "ARTEX_SHIELD_ENGAGEMENTS": json.dumps(
                        [{"reference": "E", "cidrs": [], "start": "2026-01-01T00:00:00", "end": "2026-01-02T00:00:00"}])}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                load_settings(env=env)

    def test_listen_addresses(self):
        self.assertEqual(_host_port("8080"), ("0.0.0.0", 8080))
        self.assertEqual(_host_port("127.0.0.1:80"), ("127.0.0.1", 80))
        self.assertEqual(_host_port("[::1]:8443"), ("::1", 8443))
        self.assertEqual(_host_port(":9000"), ("0.0.0.0", 9000))

    @unittest.skipIf(sys.version_info < (3, 11), "TOML needs Python 3.11")
    def test_a_toml_file_then_the_environment(self):
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write('[proxy]\nbackend = "http://127.0.0.1:8000"\nlisten = "127.0.0.1:8080"\nidle_timeout = 30\n\n'
                    '[shield]\nmode = "enforce"\ntrusted_proxies = ["10.0.0.0/8"]\ncanary_secret = "s3cret"\n\n'
                    '[[shield.engagements]]\nreference = "ENG-7"\ncidrs = ["198.51.100.0/24"]\n'
                    'start = 2026-03-01T00:00:00Z\nend = 2026-03-15T00:00:00+01:00\n')
        try:
            s = load_settings(f.name, env={"ARTEX_SHIELD_MODE": "monitor"})
            self.assertEqual((s.backend, s.listen_port, s.idle_timeout), ("http://127.0.0.1:8000", 8080, 30))
            self.assertEqual((s.shield.mode, s.shield.trusted_proxies, len(s.shield.canary_paths)),
                             ("monitor", ["10.0.0.0/8"], 3))
            self.assertEqual(s.shield.engagements[0].reference, "ENG-7")
            with open(f.name, "a") as g:
                g.write('\n[extra]\nx = 1\n')
            with self.assertRaises(ValueError):
                load_settings(f.name, env={})
        finally:
            os.unlink(f.name)

    @unittest.skipIf(sys.version_info >= (3, 11), "only before Python 3.11")
    def test_toml_before_3_11_says_what_to_do(self):
        with self.assertRaisesRegex(SystemExit, "ARTEX_SHIELD_"):
            load_settings("/nonexistent.toml", env={})

    def test_check_config(self):
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO
        out, err = StringIO(), StringIO()
        root = logging.getLogger()
        handlers, level = root.handlers[:], root.level          # main() sets up logging; put it back
        try:
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(main(["--backend", "http://127.0.0.1:9", "--mode", "enforce", "--check-config"]), 0)
                self.assertEqual(main(["--check-config", "--backend", "nowhere"]), 2)
        finally:
            root.handlers[:], root.level = handlers, level
        shown = json.loads(out.getvalue())
        self.assertEqual((shown["backend"], shown["shield"]["mode"]), ("http://127.0.0.1:9", "enforce"))
        self.assertIn("backend must be", err.getvalue())


class Command(unittest.IsolatedAsyncioTestCase):
    async def test_the_command_serves_and_stops_cleanly_on_sigterm(self):
        if not hasattr(signal, "SIGTERM") or sys.platform == "win32":
            self.skipTest("POSIX signals")
        origin = await Origin().start()
        env = dict(os.environ, PYTHONPATH=os.path.dirname(os.path.dirname(artex_shield.__file__)),
                   ARTEX_SHIELD_MODE="enforce")
        proc = await asyncio.create_subprocess_exec(sys.executable, "-m", "artex_shield.proxy", "--backend", origin.url,
                                                    "--listen", "127.0.0.1:0", env=env,
                                                    stderr=asyncio.subprocess.PIPE)
        try:
            line = (await asyncio.wait_for(proc.stderr.readline(), 20)).decode()
            port = int(re.search(r"listening on 127\.0\.0\.1:(\d+)", line).group(1))
            async with Client(port) as c:
                self.assertEqual((await c.ask(get())).status, 200)
                self.assertEqual((await c.ask(get(extra=SCANNER))).status, 403)
            proc.send_signal(signal.SIGTERM)
            self.assertEqual(await asyncio.wait_for(proc.wait(), 20), 0)
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            await proc.stderr.read()
            await origin.stop()


# ---- spec/vectors.json through the proxy ------------------------------------------------------------------------
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_CTL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_FRAMING = {"x-forwarded-for", "content-length", "transfer-encoding", "expect", "connection", "upgrade"}


class Harness:
    """The proxy and a bare origin on a loop in another thread; the vectors
    are sent from this one over a plain socket, one request at a time."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self.status, self.content_type, self.writers = 200, "", set()
        self.call(self._start())
        self.sock = self.rfile = None
        self.proxied = self.direct = 0

    def call(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(30)

    async def _start(self):
        self.origin = await asyncio.start_server(self._origin, "127.0.0.1", 0)
        backend = "http://127.0.0.1:%d" % self.origin.sockets[0].getsockname()[1]
        self.proxy = Proxy(Settings(backend=backend, listen="127.0.0.1:0"), Shield())
        await self.proxy.start()

    async def _origin(self, reader, writer):
        self.writers.add(writer)
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                length = re.search(rb"(?i)\r\ncontent-length: *(\d+)", head)
                await reader.readexactly(int(length.group(1)) if length else 0)
                ctype = b"Content-Type: %s\r\n" % self.content_type.encode("latin-1") if self.content_type else b""
                writer.write(b"HTTP/1.1 %d X\r\n%sContent-Length: 0\r\n\r\n" % (self.status, ctype))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self.writers.discard(writer)
            writer.close()

    async def _stop(self):
        await self.proxy.stop(grace=1.0)
        self.origin.close()
        for w in list(self.writers):
            w.close()
        await self.origin.wait_closed()

    def close(self):
        self.hang_up()
        self.call(self._stop())
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)
        self.loop.close()

    def hang_up(self):
        if self.sock is not None:
            self.rfile.close()
            self.sock.close()
            self.sock = self.rfile = None

    def sendable(self, r):
        """Whether a vector request can go over HTTP unchanged, as the shield would see it."""
        try:
            addr = ipaddress.ip_address(r["ip"])
        except ValueError:
            return False
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        if addr.version == 4 and addr in _LOOPBACK or not r["path"].startswith("/"):
            return False
        if not _TOKEN.fullmatch(r.get("method", "GET")):
            return False
        names = [k.lower() for k in r.get("headers", {})]
        if len(set(names)) != len(names) or set(names) & _FRAMING:
            return False
        for k, v in r.get("headers", {}).items():
            if not _TOKEN.fullmatch(k) or _CTL.search(v) or v != v.strip(" \t") or max(map(ord, v), default=0) > 255:
                return False
        return True

    def request(self, r, status, content_type=""):
        """Send one vector request; return (HTTP status, headers)."""
        self.status, self.content_type = status, content_type
        method = r.get("method", "GET")
        target = urllib.parse.quote(r["path"], safe="/")     # encoded more than a browser would, on purpose
        self.query = re.sub(r"[^\x21-\x7e]", lambda m: urllib.parse.quote(m.group()), r.get("query", ""))
        if self.query:
            target += "?" + self.query
        head = [f"{method} {target} HTTP/1.1", f"X-Forwarded-For: {r['ip']}"]
        head += [f"{k}: {v}" for k, v in r.get("headers", {}).items()]
        payload = vector_body(r)
        if payload is not None:
            head.append(f"Content-Length: {len(payload)}")
        raw = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + (payload or b"")
        if self.sock is None:
            self.sock = socket.create_connection(("127.0.0.1", self.proxy.port))
            self.rfile = self.sock.makefile("rb")
        self.sock.sendall(raw)
        code = int(self.rfile.readline().split()[1])
        headers = {}
        while True:
            line = self.rfile.readline()
            if line in (b"\r\n", b""):
                break
            k, _, v = line.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()
        if method != "HEAD":
            self.rfile.read(int(headers.get("content-length", "0")))
        if headers.get("connection", "").lower() == "close":
            self.hang_up()
        return code, headers


class ProxyRunner(Runner):
    """test_vectors.Runner with each request sent through the proxy. The
    shield trusts the proxy's peer, 127.0.0.1, and the vector's client address
    travels in X-Forwarded-For.

    observe() is the one call the proxy makes on its own, after the backend
    answers. The proxy's calls are checked and recorded here, not passed on:
    the runner feeds the vector's own observe steps, so the shield ends up in
    exactly the state the reference reached, even where a test fed back a
    status the proxy would not have seen. A request followed at the same
    instant by an observe step for the same address and path is sent with the
    backend answering that status, and the proxy's report has to match it.
    client_check_reply() is held back the same way: the proxy answers a
    request to the check's own path, which records the client as checked,
    where the vector's request step only asks check()."""

    def __init__(self, case, t0, harness):
        case = dict(case, config=dict(case.get("config", {}), trusted_proxies=["127.0.0.1/32"]))
        super().__init__(case, t0)
        self.h, self.pending, self.reported, self.last = harness, None, [], None
        check = self.shield.check

        def checking(ip, method, path, query="", headers=None, body=None):
            self.asked = (ip, method, path, query, {k.lower(): v for k, v in (headers or {}).items()}, body)
            self.last = check(ip, method, path, query, headers, body)
            return self.last
        self.shield.check = checking
        self.shield.observe = lambda ip, path, status, induced=False, content_type="": self.reported.append(
            (ip, path, status, induced, content_type))
        self.observe = type(self.shield).observe.__get__(self.shield)
        self.replied = []
        harness.proxy.shield = self.shield

    def held_reply(self, ip, query, headers=None, secure=False):
        self.replied.append((ip, query))
        return 204, [("Cache-Control", "no-store"), ("Content-Length", "0")], b""

    def step(self, where, step, expect=None, full=True):
        if self.pending is not None:
            p_where, p_step, p_expect, p_full, p_t = self.pending
            self.pending = None
            r, o = p_step["request"], step.get("observe")
            if o is not None and self.clock.t == p_t and (o["ip"], o["path"]) == (r["ip"], r["path"]):
                return self.send(p_where, r, p_expect, p_full, o)
            now, self.clock.t = self.clock.t, p_t
            self.send(p_where, r, p_expect, p_full)
            self.clock.t = now
        if "request" in step and self.h.sendable(step["request"]):
            self.pending = (where, step, expect, full, self.clock.t)
        elif "observe" in step:
            o = step["observe"]
            self.observe(o["ip"], o["path"], o["status"], o.get("induced", False), o.get("content_type", ""))
            self.h.direct += 1
        else:
            if "request" in step:
                self.h.direct += 1
            super().step(where, step, expect, full)

    def send(self, where, r, expect, full, observe=None):
        status = observe["status"] if observe else 200
        ctype = observe.get("content_type", "") if observe else ""
        self.last, self.reported, self.replied = None, [], []
        self.shield.client_check_reply = self.held_reply      # the proxy's call only; the vector's steps make theirs
        try:
            code, headers = self.h.request(r, status, ctype)
        finally:
            del self.shield.client_check_reply
        self.h.proxied += 1
        d = self.last
        if d is None:
            return self.fail(where, f"the proxy answered {code} without asking the shield")
        headers_sent = {k.lower(): v for k, v in r.get("headers", {}).items()}
        headers_sent["x-forwarded-for"] = r["ip"]
        payload, cfg = vector_body(r), self.shield.cfg
        if payload is not None:
            headers_sent["content-length"] = str(len(payload))
        read_ahead = payload[:cfg.honeytoken_body_limit] if payload and cfg.honeytokens and cfg.honeytoken_body_limit \
            else None
        if self.asked != (r["ip"], r.get("method", "GET"), r["path"], self.h.query, headers_sent, read_ahead):
            self.fail(where, f"the shield was asked about {str(self.asked)[:300]}")
        if expect is not None:
            self.compare(where, d, expect, full)
        method = r.get("method", "GET")
        route = type(self.shield).client_check_route(self.shield, r["path"])
        forwarded = not d.stop and not route and method != "CONNECT"
        want = ((403 if d.action in ("block", "refuse") else 429) if d.stop else
                {"script": 200, "check": 204}[route] if route else 405 if not forwarded else status)
        if code != want:
            self.fail(where, f"HTTP {code}, expected {want} for {d.action} (enforced {d.enforced})")
        if d.stop and d.action == "throttle" and headers.get("retry-after") != str(d.retry_after):
            self.fail(where, f"Retry-After {headers.get('retry-after')}, expected {d.retry_after}")
        sent = ctype.strip(" \t")             # what HTTP carries of it: a header value loses its outer spaces
        if self.reported != ([(r["ip"], r["path"], status, d.induced, sent)] if forwarded else []):
            self.fail(where, f"the proxy reported {self.reported} to observe()")
        if self.replied != ([(r["ip"], self.h.query)] if route == "check" and not d.stop else []):
            self.fail(where, f"the proxy replied {self.replied} for the client check")
        if observe is not None:
            self.observe(observe["ip"], observe["path"], observe["status"], observe.get("induced", False), ctype)

    def run(self):
        super().run()
        if self.pending is not None:
            where, step, expect, full, t = self.pending
            self.pending, self.clock.t = None, t
            self.send(where, step["request"], expect, full)
        return self.failures


class VectorsThroughTheProxy(unittest.TestCase):
    def test_every_case(self):
        data = load()
        h = Harness()
        skipped, failures = [], []
        try:
            for case in data["cases"]:
                if "trusted_proxies" in case.get("config", {}):
                    skipped.append(case["id"])            # their own proxies: the harness needs to be the one
                    continue
                failures += ProxyRunner(case, data["t0"], h).run()
        finally:
            h.close()
        self.assertEqual(failures[:20], [])
        self.assertLessEqual(len(skipped), 2)
        self.assertGreater(h.proxied, 0.95 * (h.proxied + h.direct), (h.proxied, h.direct))
        if os.environ.get("VECTORS_VERBOSE"):
            print(f"\n{h.proxied} requests through the proxy, {h.direct} steps direct, cases skipped: {skipped}")


if __name__ == "__main__":
    unittest.main()
