"""End-to-end check of examples/wordpress/docker-compose.yml, run by CI.

    ARTEX_SHIELD_MODE=enforce docker compose -f examples/wordpress/docker-compose.yml up -d --build --wait
    python examples/wordpress/smoke.py http://localhost:8080
    python examples/wordpress/smoke.py http://localhost:8080 --replay PASSWORD

Installs WordPress through the proxy (a form POST, redirects, cookies), reads
pages as a visitor, then sends one scanner request and checks that it and
everything after it from the same address is blocked. With --replay, instead
logs in with a planted honeytoken password (from --print-decoys) and checks
that the login is blocked before WordPress sees it. Exits 1 on failure.
Standard library only.
"""
import http.cookiejar
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")
REPLAY = sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == "--replay" else None
BROWSER = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
           "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en-GB,en;q=0.7"}
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def fetch(path, data=None, headers=BROWSER):
    req = urllib.request.Request(BASE + path, data=urllib.parse.urlencode(data).encode() if data else None,
                                 headers=headers)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def expect(what, ok):
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        sys.exit(1)


if REPLAY is not None:
    expect("a honeytoken password was given", bool(REPLAY))
    status, body = fetch("/wp-login.php", data={"log": "admin-legacy", "pwd": REPLAY, "wp-submit": "Log In"})
    expect(f"a login with the planted password is blocked ({status})",
           status == 403 and body.startswith("Request blocked. Reference: "))
    status, _ = fetch("/")
    expect(f"its address stays blocked ({status})", status == 403)
    print("all good")
    sys.exit(0)

deadline = time.time() + 180
while True:
    try:
        status, body = fetch("/")
        if status == 200:
            break
    except OSError as e:
        status = e
    if time.time() > deadline:
        expect(f"WordPress answers through the proxy (last: {status})", False)
    time.sleep(2)

expect("the installer is served through the proxy", "wp-admin/install.php" in body or "WordPress" in body)
status, body = fetch("/wp-admin/install.php?step=2", data={
    "weblog_title": "Shielded", "user_name": "admin", "admin_password": "smoke-Test-0nly!",
    "admin_password2": "smoke-Test-0nly!", "pw_weak": "1", "admin_email": "admin@example.com",
    "blog_public": "0", "language": ""})
expect(f"a form POST installs WordPress ({status})", status == 200 and "wp-login.php" in body)
status, body = fetch("/")
expect(f"the home page is served ({status})", status == 200 and "Shielded" in body)
status, body = fetch("/?p=1")
expect(f"a post is served ({status})", status == 200 and "Hello world" in body)
status, _ = fetch("/wp-login.php")
expect(f"the login page is served ({status})", status == 200)
status, _ = fetch("/no-such-page-here/")
expect(f"WordPress's own 404 comes back ({status})", status == 404)

status, body = fetch("/", headers={"User-Agent": "sqlmap/1.8.4#stable (https://sqlmap.org)"})
expect(f"a scanner is blocked ({status})", status == 403 and body.startswith("Request blocked. Reference: "))
status, _ = fetch("/")
expect(f"its address stays blocked ({status})", status == 403)
print("all good")
