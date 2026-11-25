"""examples/static.conf as a site would run it: OpenResty serving the files in
tests/static-site, with the shield in enforce mode. nginx's own 404s for
missing files must reach the shield as an app's would.

    docker run -d --name static -p 8085:8080 \\
      -e ARTEX_SHIELD_MODE=enforce -e ARTEX_SHIELD_CANARY_SECRET=ci-only-canary-secret \\
      -e ARTEX_SHIELD_TRUSTED_PROXIES=172.16.0.0/12 \\
      -v "$PWD/ports/openresty/lib:/opt/artex-shield/lib:ro" \\
      -v "$PWD/ports/openresty/examples/artex_settings.lua:/opt/artex-shield/artex_settings.lua:ro" \\
      -v "$PWD/ports/openresty/examples/static.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro" \\
      -v "$PWD/ports/openresty/tests/static-site:/var/www/site:ro" openresty/openresty:1.27.1.2-bookworm-fat
    ARTEX_SHIELD_CANARY_SECRET=ci-only-canary-secret python3 ports/openresty/tests/static.py http://127.0.0.1:8085

Visitors' addresses travel in X-Forwarded-For from Docker's bridge, which
the container trusts. Standard library only; the canary paths come from the
Python reference in src/. Exits 1 on any failure.
"""
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "src"))
from artex_shield import make_canaries  # noqa: E402

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8085").rstrip("/")
SECRET = os.environ.get("ARTEX_SHIELD_CANARY_SECRET", "")
BROWSER = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
           "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en-GB,en;q=0.7"}
failures = []


def expect(what, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        failures.append(what)
        if detail:
            print("      " + str(detail)[:300])


def fetch(path, ip, headers=BROWSER, method="GET"):
    req = urllib.request.Request(BASE + path, headers={**headers, "X-Forwarded-For": ip}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read().decode("utf-8", "replace")


status, ctype, body = fetch("/", "198.51.100.1")
expect(f"the site's page is served ({status})", status == 200 and "A static site" in body and ctype.startswith("text/html"))
status, ctype, _ = fetch("/robots.txt", "198.51.100.1")
expect(f"and its robots.txt ({status})", status == 200 and ctype.startswith("text/plain"))
status, _, _ = fetch("/_artex/health", "198.51.100.1")
expect(f"the health check answers before the shield ({status})", status == 204)

codes = {fetch(f"/assets/photo-{i}.png", "198.51.100.2")[0] for i in range(25)}
status, _, _ = fetch("/", "198.51.100.2")
expect(f"25 missing images cost a visitor nothing ({sorted(codes)}, then {status})", codes == {404} and status == 200)

codes = {fetch(f"/backup-{i}", "203.0.113.20")[0] for i in range(30)}
status, headers_type, body = fetch("/", "203.0.113.20")
expect(f"30 guessed paths, answered by nginx's own 404s, get the guesser throttled ({sorted(codes)}, then {status})",
       codes == {404} and status == 429 and body.startswith("Too many requests. Reference: "), body)

canaries = make_canaries(SECRET) if SECRET else []
expect("a canary secret was given", bool(canaries))
if canaries:
    status, _, body = fetch(canaries[0], "203.0.113.30")
    expect(f"a canary path is a block ({status})", status == 403 and body.startswith("Request blocked. Reference: "))
    status, _, body = fetch("/", "203.0.113.30")
    expect(f"and the page is not served to that address again ({status})", status == 403 and "A static site" not in body)

status, _, body = fetch("/", "203.0.113.40", {"User-Agent": "sqlmap/1.8.4#stable"})
expect(f"a scanner gets no page ({status})", status == 403 and "A static site" not in body)
status, _, _ = fetch("/", "203.0.113.40", method="HEAD")
expect(f"nor a HEAD of one ({status})", status == 403)

print("all good" if not failures else f"{len(failures)} failed")
sys.exit(1 if failures else 0)
