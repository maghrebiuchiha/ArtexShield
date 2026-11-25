"""The edge module in real nginx, as a site runs it: tests/nginx/smoke.conf,
four workers in enforce mode in front of an origin that counts what reaches
it. What the vector harness cannot show: blocks shared by every worker, the
statuses fed back after the response (in a timer) building a block, internal
redirects decided on once, bodies read from memory and from a temporary file,
the client check's endpoints and the admin location.

    python3 ports/openresty/tests/smoke.py [http://127.0.0.1:8499]

Each request goes on a new connection, so the four workers share the work.
Standard library only; exits 1 on any failure.
"""
import json
import socket
import sys
import time
import urllib.parse

URL = urllib.parse.urlsplit(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8499")
BROWSER = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
           "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en-GB,en;q=0.7"}
TOKEN = "api_live_smoke0123456789"
failures = []


def expect(what, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        failures.append(what)
        if detail:
            print("      " + str(detail)[:400])


def raw(request: bytes, host=None, port=None):
    """Send one request on a new connection; (status, headers, body)."""
    with socket.create_connection((host or URL.hostname, port or URL.port), timeout=10) as s:
        s.sendall(request)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers.setdefault(k.strip().lower(), []).append(v.strip())
    if "chunked" in headers.get("transfer-encoding", []):
        plain = b""
        while True:
            size, _, rest = body.partition(b"\r\n")
            size = int(size.split(b";")[0], 16)
            if size == 0:
                break
            plain, body = plain + rest[:size], rest[size + 2:]
        body = plain
    return int(lines[0].split()[1]), {k: v[0] if len(v) == 1 else v for k, v in headers.items()}, body


def fetch(path, ip, headers=BROWSER, method="GET", body=None, target=None):
    lines = [f"{method} {target or path} HTTP/1.1", "Host: shop.example", f"X-Forwarded-For: {ip}", "Connection: close"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    return raw(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + (body or b""))


def events():
    status, _, body = raw(b"GET /__events HTTP/1.1\r\nHost: shop.example\r\nConnection: close\r\n\r\n")
    return json.loads(body) if status == 200 else []


def origin_saw(ip):
    _, _, body = raw(f"GET /__origin/seen?ip={ip} HTTP/1.1\r\nHost: o\r\nConnection: close\r\n\r\n".encode(),
                     port=8498)
    return int(body or b"0")


def settle():
    time.sleep(0.2)                     # the statuses go back to the shield in a timer after each response


# ---- a visitor --------------------------------------------------------------------------------
status, headers, body = fetch("/", "198.51.100.1")
expect(f"a page is served through the edge ({status})", status == 200 and b"page" in body)
expect("the origin saw it", origin_saw("198.51.100.1") == 1)

# ---- a scanner, and the block every worker holds ------------------------------------------------
status, _, body = fetch("/", "203.0.113.10", {"User-Agent": "sqlmap/1.8.4#stable"})
expect(f"a scanner is blocked ({status})", status == 403 and body.startswith(b"Request blocked. Reference: "), body)
workers, codes = set(), set()
for _ in range(40):
    status, headers, _ = fetch("/", "203.0.113.10")
    codes.add(status)
    workers.add(headers.get("x-worker"))
expect(f"its address stays blocked on every later request ({sorted(codes)})", codes == {403})
expect(f"by every worker that answered ({len(workers)} of 4)", len(workers) >= 3, workers)
expect("none of it reached the origin", origin_saw("203.0.113.10") == 0)
status, headers, body = fetch("/", "203.0.113.10", method="HEAD")
expect(f"a HEAD from it is blocked too, without a body ({status})", status == 403 and body == b"")

# ---- one client, many workers at once: no update is lost -------------------------------------------
import threading
barrier, results = threading.Barrier(40), []


def hit():
    barrier.wait()
    results.append(fetch("/", "203.0.113.70", target="/item?id=1%27%20or%20%271%27%3D%271")[0])


threads = [threading.Thread(target=hit) for _ in range(40)]
for th in threads:
    th.start()
for th in threads:
    th.join()
expect(f"40 payloads at once from one address: only the first passes ({sorted(set(results))}, "
       f"{results.count(200)} passed)", results.count(200) == 1 and len(results) == 40)

# ---- hostile header text costs no more than any other -------------------------------------------
started = time.perf_counter()
status, _, _ = fetch("/", "198.51.100.80", {**BROWSER, "X-Pad": "a" + " " * 7000 + "x",
                                            "Cookie": "artex_check=a" + '"' * 7000 + "x"})
took = time.perf_counter() - started
expect(f"7 KB runs of spaces and quotes in headers are read in linear time ({status}, {took * 1000:.0f} ms)",
       status == 200 and took < 0.1)

started = time.perf_counter()
codes = [fetch("/", f"198.51.100.{90 + i}", {**BROWSER, "User-Agent": atom * (30000 // len(atom))},
               target="/search?q=" + urllib.parse.quote(atom * (20000 // len(atom))))[0]   # 64 KB once encoded
         for i, atom in enumerate(("a", "mozilla/5.0 ", "' or "))]
took = time.perf_counter() - started
expect(f"30 KB of hostile text in a header, and 20 KB in the URL, are decided on ({codes}, {took * 1000:.0f} ms)",
       all(c in (200, 403, 429) for c in codes) and took < 1)

status, _, body = raw(b"GET /__patterns HTTP/1.1\r\nHost: shop.example\r\nConnection: close\r\n\r\n")
matrix = json.loads(body) if status == 200 else {}
expect(f"in nginx, every pattern gets through the hostile 30 KB inputs on the JIT stack configure() sets "
       f"({matrix.get('count')} patterns, {matrix.get('jit_stack')} out of stack)",
       matrix.get("jit_stack") == 0 and matrix.get("failed") in ([], {}) and matrix.get("slow") in ([], {}), matrix)

# ---- 404s fed back after the response build a block --------------------------------------------
codes = [fetch(f"/missing/guess-{i}", "203.0.113.20")[0] for i in range(10)]
settle()
status, _, _ = fetch("/", "203.0.113.20")
seen = [e for e in events() if e["ip"] == "203.0.113.20"]
expect(f"ten missing paths, fed back after each response, get the client throttled ({status})",
       codes == [404] * 10 and status == 429
       and [e["hits"] for e in seen[:2]] == [["behavior:path-enumeration"]] * 2, seen)
codes = []
while len(codes) < 10 and (not codes or codes[-1] == 429):
    codes.append(fetch("/", "203.0.113.20")[0])
# 85 now, +5 for each request inside its Retry-After, less a little decay: a block on the fourth or fifth
expect(f"asking again while told to wait ends in a block ({codes})", codes[-1] == 403 and 4 <= len(codes) <= 5)

# ---- the path as sent, not as nginx resolved it --------------------------------------------------
status, _, _ = fetch("/", "203.0.113.30", target="/a/b/../../etc/passwd")
seen = [e for e in events() if e["ip"] == "203.0.113.30"]
expect("a traversal nginx would resolve away is still seen",
       any("payload:traversal" in e["hits"] for e in seen), seen)
status, _, _ = fetch("/", "203.0.113.31", target="http://other.example/.git/config")
seen = [e for e in events() if e["ip"] == "203.0.113.31"]
expect(f"an absolute-form request is read by its path ({status})",
       any("decoy:sensitive-file-probe" in e["hits"] for e in seen), seen)

# ---- internal redirects: decided on once ---------------------------------------------------------
for where, ip in (("/named/", "203.0.113.40"), ("/uri/", "203.0.113.41")):
    status, _, _ = fetch("/", ip, target=where + "item?id=1%27%20or%20%271%27%3D%271")
    seen = [e for e in events() if e["ip"] == ip]
    expect(f"a request redirected inside nginx ({where}) is decided on once ({status}, {len(seen)} event)",
           status == 200 and len(seen) == 1 and "payload:sqli" in seen[0]["hits"], seen)
for where, ip in (("/named/", "203.0.113.42"), ("/uri/", "203.0.113.43")):
    codes = {fetch("/", ip, target=f"{where}missing/guess-{i}")[0] for i in range(5)}
    settle()
    seen = [e for e in events() if e["ip"] == ip]
    expect(f"404s after a redirect inside nginx ({where}) are fed back under the paths asked for ({sorted(codes)})",
           codes == {404} and len(seen) == 1 and "behavior:path-enumeration" in seen[0]["hits"]
           and seen[0]["path"] == f"{where}missing/guess-4", seen)

# ---- honeytokens in bodies, from memory and from a temporary file ---------------------------------
form = {"Content-Type": "application/x-www-form-urlencoded", **BROWSER}
status, _, _ = fetch("/login", "203.0.113.50", form, "POST", f"user=a&key={TOKEN}".encode())
expect(f"a planted key in a small body is blocked ({status})", status == 403)
big = b"x" * 1000 + TOKEN.encode() + b"y" * 99000
status, _, _ = fetch("/upload", "203.0.113.51", form, "POST", big)
expect(f"in a 100 KB body nginx kept in a file, too ({status})", status == 403)
late = b"x" * 70000 + TOKEN.encode()
status, _, _ = fetch("/upload", "203.0.113.52", form, "POST", late)
expect(f"past the first 64 KiB it is not looked for, as the reference does ({status})", status == 200)
expect("blocked bodies never reached the origin", origin_saw("203.0.113.50") + origin_saw("203.0.113.51") == 0)

# ---- the client check, answered by the edge ---------------------------------------------------------
status, headers, body = fetch("/_artex/check.js", "198.51.100.60")
expect(f"the check script is served ({status})", status == 200 and b'"/_artex/check"' in body
       and headers.get("content-type", "").startswith("text/javascript"))
status, headers, _ = fetch("/_artex/check", "198.51.100.60", target="/_artex/check?v=1&f=0")
cookie = headers.get("set-cookie", "")
expect(f"the check answers 204 with a signed cookie ({status})",
       status == 204 and cookie.startswith("artex_check=1.") and "HttpOnly" in cookie, cookie)
expect("the origin saw neither", origin_saw("198.51.100.60") == 0)

# ---- the admin location ----------------------------------------------------------------------------
status, _, body = raw(b"GET /_artex/admin HTTP/1.1\r\nHost: shop.example\r\nConnection: close\r\n\r\n")
listed = [b["network"] for b in json.loads(body).get("blocks", [])] if status == 200 else []
expect(f"the admin location lists the blocks ({status})", "203.0.113.10" in listed and "203.0.113.20" in listed, body)
form_body = b"ip=203.0.113.10"
status, _, body = raw(b"POST /_artex/admin HTTP/1.1\r\nHost: shop.example\r\nConnection: close\r\n"
                      b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s"
                      % (len(form_body), form_body))
expect(f"and unblocks one ({status})", status == 200 and json.loads(body).get("unblocked") is True, body)
status, _, _ = fetch("/", "203.0.113.10")
expect(f"which every worker then lets through ({status})", status == 200)

print("all good" if not failures else f"{len(failures)} failed")
sys.exit(1 if failures else 0)
