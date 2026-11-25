"""spec/vectors.json through OpenResty over HTTP, as tests/test_proxy.py
replays it through artex-shield-proxy.

    python3 ports/openresty/tests/edge.py [http://127.0.0.1:8399]

The server is tests/nginx/harness.conf: the edge module in front of a bare
origin, with test hooks. Each request step goes over HTTP with the vector's
client address in X-Forwarded-For (the shield trusts 127.0.0.1), and the
hooks report what the shield was asked: the address, method, path, query,
headers and body prefix must be exactly what the vector says. Then the
decision, the HTTP status the client got and what the edge passed back to
observe() are checked. Steps that are not requests (observe, unblock,
blocklist, the client check) run on the shield directly, as in the proxy's
test, so the shield ends up in the state the reference reached.

nginx itself refuses some requests before any phase runs (TRACE, methods in
lower case, a path that climbs above /): the shield is never asked, and no
app sees them. Those steps run directly instead, and are counted.

Standard library only; exits 1 on any failure.
"""
import base64
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.environ.get("ARTEX_SPEC") or os.path.join(HERE, "..", "..", "..", "spec")
TOLERANCE = 1e-6
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_METHOD = re.compile(r"[A-Z]+")
_CTL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_FRAMING = {"x-forwarded-for", "content-length", "transfer-encoding", "expect", "connection", "upgrade", "te",
            "keep-alive", "trailer"}


def body(r):
    if "body_base64" in r:
        return base64.b64decode(r["body_base64"])
    return r["body"].encode("utf-8") if "body" in r else None


def fill(template, i):
    if isinstance(template, str):
        return template.replace("{i}", str(i))
    if isinstance(template, dict):
        return {k: fill(v, i) for k, v in template.items()}
    if isinstance(template, list):
        return [fill(v, i) for v in template]
    return template


class Connection:
    """One keep-alive connection to the server, reopened when it closes."""

    def __init__(self, host, port):
        self.host, self.port, self.sock, self.rfile = host, port, None, None

    def close(self):
        if self.sock is not None:
            self.rfile.close()
            self.sock.close()
            self.sock = self.rfile = None

    def exchange(self, raw, method):
        if self.sock is None:
            self.sock = socket.create_connection((self.host, self.port), timeout=30)
            self.rfile = self.sock.makefile("rb")
        self.sock.sendall(raw)
        status_line = self.rfile.readline()
        if not status_line:
            raise ConnectionError("the server closed the connection")
        code = int(status_line.split()[1])
        headers = {}
        while True:
            line = self.rfile.readline()
            if line in (b"\r\n", b""):
                break
            k, _, v = line.decode("latin-1").partition(":")
            headers[k.strip().lower()] = v.strip()
        payload = b""
        if method != "HEAD" and code not in (204, 304) and code >= 200:
            if headers.get("transfer-encoding", "").lower() == "chunked":
                while True:
                    size = int(self.rfile.readline().split(b";")[0], 16)
                    chunk = self.rfile.read(size + 2)
                    if size == 0:
                        break
                    payload += chunk[:-2]
            else:
                payload = self.rfile.read(int(headers.get("content-length", "0")))
        if headers.get("connection", "").lower() == "close":
            self.close()
        return code, headers, payload

    def control(self, path, value=None):
        data = json.dumps(value).encode() if value is not None else b""
        raw = (f"{'POST' if value is not None else 'GET'} {path} HTTP/1.1\r\nHost: harness\r\n"
               f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data
        code, _, payload = self.exchange(raw, "POST")
        if code != 200:
            raise RuntimeError(f"{path} answered {code}: {payload[:300]!r}")
        return json.loads(payload)


def sendable(r):
    """Whether a vector request can go over HTTP unchanged, as the shield would see it."""
    try:
        addr = ipaddress.ip_address(r["ip"])
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    if addr.version == 4 and addr in _LOOPBACK or not r["path"].startswith("/"):
        return False
    method = r.get("method", "GET")
    if not _METHOD.fullmatch(method) or method in ("TRACE", "CONNECT"):
        return False                                     # nginx answers these itself
    names = [k.lower() for k in r.get("headers", {})]
    if len(set(names)) != len(names) or set(names) & _FRAMING or any(n.startswith("x-test-") for n in names):
        return False
    for k, v in r.get("headers", {}).items():
        if not _TOKEN.fullmatch(k) or _CTL.search(v) or v != v.strip(" \t") or max(map(ord, v), default=0) > 255:
            return False
    return True


class Stats:
    def __init__(self):
        self.proxied = self.direct = self.refused = 0


class EdgeRunner:
    def __init__(self, case, t0, conn, stats):
        self.case, self.t0, self.conn, self.stats = case, t0, conn, stats
        self.failures, self.pending, self.now = [], None, t0
        cfg = dict(case.get("config", {}), trusted_proxies=["127.0.0.1/32"])
        if "engagements" in cfg:
            cfg["engagements"] = [dict(e, start=t0 + e["start"], end=t0 + e["end"]) for e in cfg["engagements"]]
        self.cfg = cfg
        made = conn.control("/__test/case", {"config": cfg, "now": t0})
        if not made["ok"]:
            raise RuntimeError(f"{case['id']}: the edge refused the config: {made.get('error')}")

    def fail(self, where, message):
        self.failures.append(f"{self.case['id']} step {where}: {message}")

    def compare(self, where, got, want, full):
        hits = sorted(got["hits"])
        if got["action"] != want["action"]:
            self.fail(where, f"action {got['action']!r}, expected {want['action']!r} (hits {hits})")
        if hits != want["hits"]:
            self.fail(where, f"hits {hits}, expected {want['hits']}")
        if full and abs(got["score"] - want["score"]) > TOLERANCE:
            self.fail(where, f"score {got['score']}, expected {want['score']}")
        if full and "retry_after" in want and got["retry_after"] != want["retry_after"]:
            self.fail(where, f"retry_after {got['retry_after']}, expected {want['retry_after']}")

    def direct(self, where, step, expect, full, now):
        self.stats.direct += 1
        out = self.conn.control("/__test/step", {"now": now, "step": step})
        if "request" in step:
            if expect is not None:
                self.compare(where, out, expect, full)
        elif "client_check" in step:
            if out != step["expect"]:
                self.fail(where, f"client check answered {out}, expected {step['expect']}")
        elif "unblock" in step:
            if out["unblocked"] != step["expect"]:
                self.fail(where, f"unblock returned {out['unblocked']}, expected {step['expect']}")
        elif "expect_blocklist" in step:
            if out["blocklist"] != step["expect_blocklist"]:
                self.fail(where, f"blocklist {out['blocklist']}, expected {step['expect_blocklist']}")

    def step(self, where, step, expect=None, full=True):
        if self.pending is not None:
            p_where, p_step, p_expect, p_full, p_t = self.pending
            self.pending = None
            r, o = p_step["request"], step.get("observe")
            if o is not None and self.now == p_t and (o["ip"], o["path"]) == (r["ip"], r["path"]):
                return self.send(p_where, r, p_expect, p_full, p_t, o)
            self.send(p_where, r, p_expect, p_full, p_t)
        if "request" in step and sendable(step["request"]):
            self.pending = (where, step, expect, full, self.now)
        else:
            self.direct(where, step, expect, full, self.now)

    def send(self, where, r, expect, full, t, observe=None):
        status = observe["status"] if observe else 200
        ctype = observe.get("content_type", "") if observe else ""
        method = r.get("method", "GET")
        target = urllib.parse.quote(r["path"], safe="/")     # encoded more than a browser would, on purpose
        query = re.sub(r"[^\x21-\x7e]", lambda m: urllib.parse.quote(m.group()), r.get("query", ""))
        if query:
            target += "?" + query
        vector_headers = r.get("headers", {})
        head = [f"{method} {target} HTTP/1.1", f"X-Test-Clock: {t!r}", f"X-Test-Status: {status}",
                f"X-Forwarded-For: {r['ip']}"]
        if ctype:
            head.append(f"X-Test-Type: {ctype}")
        if not any(k.lower() == "host" for k in vector_headers):
            head += ["Host: harness", "X-Test-Host: drop"]
        head += [f"{k}: {v}" for k, v in vector_headers.items()]
        payload = body(r)
        if payload is not None:
            head.append(f"Content-Length: {len(payload)}")
        raw = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + (payload or b"")
        code, headers, _ = self.conn.exchange(raw, method)
        report = self.conn.control("/__test/report")
        d, asked = report["decision"], report["asked"]
        if d is None:
            # nginx answered without a phase running: run the step on the shield instead
            if code not in (400, 405, 414):
                self.fail(where, f"HTTP {code} without the shield being asked")
            self.stats.refused += 1
            self.direct(where, {"request": r}, expect, full, t)
        else:
            self.stats.proxied += 1
            self.check_sent(where, r, query, payload, asked)
            if expect is not None:
                self.compare(where, d, expect, full)
            route = None
            if self.cfg.get("client_check"):
                route = self.conn.control("/__test/step", {"now": t, "step": {"route": r["path"]}})["route"]
            forwarded = not d["stop"] and not route
            want = ((403 if d["action"] in ("block", "refuse") else 429) if d["stop"] else
                    {"script": 200, "check": 204}[route] if route else status)
            if code != want:
                self.fail(where, f"HTTP {code}, expected {want} for {d['action']} (enforced {d['enforced']})")
            if d["stop"] and d["action"] == "throttle" and headers.get("retry-after") != str(d["retry_after"]):
                self.fail(where, f"Retry-After {headers.get('retry-after')}, expected {d['retry_after']}")
            # Only what observe() can act on is passed on: a 404, or a 2xx page with the client check on.
            matters = status == 404 or (bool(self.cfg.get("client_check")) and 200 <= status < 300)
            want_reported = [[r["ip"], r["path"], status, d["induced"], ctype]] if forwarded and matters else []
            if report["reported"] != want_reported:
                self.fail(where, f"the edge passed on {report['reported']}, expected {want_reported}")
        if observe is not None:
            self.direct(where, {"observe": observe}, None, True, t)

    def check_sent(self, where, r, query, payload, asked):
        headers = {k.lower(): v for k, v in r.get("headers", {}).items()}
        headers["x-forwarded-for"] = r["ip"]
        if payload is not None:
            headers["content-length"] = str(len(payload))
        limit = self.cfg.get("honeytoken_body_limit", 65536)
        prefix = payload[:limit] if payload and self.cfg.get("honeytokens") and limit else None
        got_headers = dict((k, v) for k, v in asked[4])
        want = [r["ip"], r.get("method", "GET"), r["path"], query, headers,
                base64.b64encode(prefix).decode() if prefix is not None else False]
        got = asked[:4] + [got_headers, asked[5]]
        if got != want or len(asked[4]) != len(got_headers):
            self.fail(where, f"the shield was asked about {str(got)[:300]}, expected {str(want)[:300]}")

    def run(self):
        for n, step in enumerate(self.case["steps"]):
            if "repeat" in step:
                t, started, iteration = self.t0 + step["at"], False, 0
                for run in step["expect"]:
                    for k in range(run["times"]):
                        final = k == run["times"] - 1
                        for j, template in enumerate(step["steps"]):
                            if started:
                                t += step["dt"][j]
                            started = True
                            self.now = t
                            want = (run["last"] if final else run["each"])[j]
                            self.step(f"{n} (repeat {iteration}, part {j})", fill(template, step["i_from"] + iteration),
                                      want, final)
                        iteration += 1
            else:
                self.now = self.t0 + step["at"]
                self.step(n, step, step.get("expect"))
        if self.pending is not None:
            where, step, expect, full, t = self.pending
            self.pending = None
            self.send(where, step["request"], expect, full, t)
        return self.failures


def plumbing(conn):
    """How the edge reads requests the vectors cannot carry: repeated headers,
    raw bytes, absolute-form targets, the client check's Secure flag."""
    failures = []
    t0 = 1800000000.0

    def case(config):
        made = conn.control("/__test/case", {"config": config, "now": t0})
        assert made["ok"], made

    def ask(head, body=b""):
        raw = "\r\n".join(head).encode("latin-1") + b"\r\n\r\n" + body
        method = head[0].split()[0]
        code, headers, payload = conn.exchange(raw, method)
        return code, headers, payload, conn.control("/__test/report")

    def expect(what, ok, detail=""):
        if not ok:
            failures.append(f"plumbing: {what}: {str(detail)[:300]}")

    case({"trusted_proxies": ["127.0.0.1/32"]})
    _, _, _, rep = ask(["GET /x HTTP/1.1", "Host: shop.example", "X-Forwarded-For: 198.51.100.1", "Cookie: a=1",
                        "X-Thing: one", "cookie: b=2", "Accept: text/html", "X-THING: two"])
    names = [n for n, _ in rep["asked"][4]]
    got = dict(rep["asked"][4])
    expect("repeated headers are joined, Cookie with '; ', in the order they first came",
           names == ["host", "x-forwarded-for", "cookie", "x-thing", "accept"]
           and got["cookie"] == "a=1; b=2" and got["x-thing"] == "one, two", rep["asked"])

    code, _, _, rep = ask(["GET /caf\xe9/a%2520b/caf%C3%A9?q=%41+b&r=caf\xe9 HTTP/1.1", "Host: shop.example",
                           "X-Forwarded-For: 198.51.100.2", "X-Name: caf\xe9"])
    asked = rep["asked"] or [None] * 6
    expect("raw bytes read as Latin-1, the path decoded once, the query as sent",
           asked[2] == "/caf\u00e9/a%20b/caf\u00e9" and asked[3] == "q=%41+b&r=caf\u00e9"
           and dict(asked[4]).get("x-name") == "caf\u00e9", (code, asked))

    _, _, _, rep = ask(["GET http://other.example/abs/path?y=1 HTTP/1.1", "Host: shop.example",
                        "X-Forwarded-For: 198.51.100.3"])
    expect("an absolute-form target is read as its path and query", rep["asked"][2:4] == ["/abs/path", "y=1"],
           rep["asked"])

    _, _, _, rep = ask(["POST /form HTTP/1.1", "Host: shop.example", "X-Forwarded-For: 198.51.100.4",
                        "Content-Length: 5"], b"a=b&c")
    expect("without honeytokens the body is not read", rep["asked"][5] is False, rep["asked"])
    case({"trusted_proxies": ["127.0.0.1/32"], "honeytokens": ["api_live_plumbing_0123"], "honeytoken_body_limit": 4})
    _, _, _, rep = ask(["POST /form HTTP/1.1", "Host: shop.example", "X-Forwarded-For: 198.51.100.5",
                        "Content-Length: 5"], b"a=b&c")
    expect("with them, the first honeytoken_body_limit bytes are", rep["asked"][5] == base64.b64encode(b"a=b&").decode(),
           rep["asked"])
    code, headers, payload, rep = ask(["HEAD / HTTP/1.1", "Host: shop.example", "X-Forwarded-For: 198.51.100.6",
                                       "User-Agent: sqlmap/1.8"])
    expect("a HEAD is decided on like a GET, and its 403 has no body",
           rep["decision"]["action"] == "block" and payload == b"", (code, rep["decision"]))

    for trusted, secure in ((["127.0.0.1/32"], True), ([], False)):
        case({"trusted_proxies": trusted, "client_check": True, "client_check_secret": "plumbing secret"})
        code, headers, _, _ = ask(["GET /_artex/check?v=1&f=0 HTTP/1.1", "Host: shop.example",
                                   "X-Forwarded-Proto: https", "X-Forwarded-For: 198.51.100.7"])
        cookie = headers.get("set-cookie", "")
        expect(f"X-Forwarded-Proto is believed {'from a trusted peer' if trusted else 'from no one else'}",
               code == 204 and cookie.endswith("; Secure") == secure, cookie)
    return failures


def main(argv):
    url = urllib.parse.urlsplit(argv[1] if len(argv) > 1 else "http://127.0.0.1:8399")
    with open(os.path.join(SPEC, "vectors.json"), encoding="utf-8") as f:
        data = json.load(f)
    conn, stats, failures, skipped = Connection(url.hostname, url.port or 80), Stats(), [], []
    for case in data["cases"]:
        if "trusted_proxies" in case.get("config", {}):
            skipped.append(case["id"])                   # their own proxies: the harness needs to be the one
            continue
        failures += EdgeRunner(case, data["t0"], conn, stats).run()
    failures += plumbing(conn)
    conn.close()
    total = stats.proxied + stats.refused
    print(f"{len(data['cases']) - len(skipped)} cases: {stats.proxied} requests through OpenResty, "
          f"{stats.refused} refused by nginx itself, {stats.direct - stats.refused} steps run directly; "
          f"skipped: {skipped}")
    for f in failures[:25]:
        print("FAIL ", f)
    ok = not failures and len(skipped) <= 2 and stats.proxied > 0.9 * total
    print("all good" if ok else f"{len(failures)} failures")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
