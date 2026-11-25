"""End-to-end check of the plugin on real WordPress (docker-compose.yml here), run by CI.

    python3 smoke.py admin http://localhost:8090 PASSWORD     # monitor mode, the settings page, switch to enforce
    python3 smoke.py visitor http://localhost:8090            # in enforce mode: pages, decoys, a scanner
    python3 smoke.py replay http://wordpress HONEYTOKEN       # from another address: a planted password

Each part prints what it checks and exits 1 on the first failure. Standard library only.
"""
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

PART, BASE = sys.argv[1], sys.argv[2].rstrip("/")
ARG = sys.argv[3] if len(sys.argv) > 3 else ""
BROWSER = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
           "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en-GB,en;q=0.7"}
jar = http.cookiejar.CookieJar()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)


def fetch(path, data=None, headers=BROWSER):
    body = urllib.parse.urlencode(data).encode() if isinstance(data, dict) else data
    req = urllib.request.Request(BASE + path, data=body, headers=headers)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def expect(what, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        print("      " + str(detail)[:2000])
        sys.exit(1)


def no_php_errors(page, where):
    m = re.search(r"<b>(?:Warning|Notice|Deprecated|Fatal error)</b>:.*?(?:<br|$)", page)
    expect(f"no PHP warnings on {where}", m is None, m.group(0) if m else "")


if PART == "admin":
    status, _, page = fetch("/")
    expect(f"the home page is served in monitor mode ({status})", status == 200, page[:500])
    no_php_errors(page, "the home page")
    for planted in ('rel="nofollow" tabindex="-1"', "var __legacyApi", "var __stagingConfig", "TODO(ops): remove before release"):
        expect(f"planted on the page: {planted}", planted in page)
    status, _, robots = fetch("/robots.txt")
    expect(f"robots.txt names a canary ({status})", status == 200 and "Disallow: /api/v1/internal/audit-" in robots, robots)
    status, _, page = fetch("/", headers={"User-Agent": "sqlmap/1.8.4#stable"})
    expect(f"monitor mode lets a scanner through ({status})", status == 200)

    fetch("/wp-login.php")                                     # sets WordPress's test cookie
    status, headers, page = fetch("/wp-login.php", {"log": "admin", "pwd": ARG, "wp-submit": "Log In",
                                                     "redirect_to": BASE + "/wp-admin/", "testcookie": "1"})
    expect(f"the admin logs in ({status})", status == 302 and "wp-admin" in headers.get("Location", ""), page[:500])
    status, _, page = fetch("/wp-admin/options-general.php?page=artex-shield")
    expect(f"the settings page opens ({status})", status == 200 and "ARTEX Shield" in page, page[:500])
    no_php_errors(page, "the settings page")
    expect("it shows the mode, the secret and the allowlists",
           all(f'name="artex_shield_settings[{f}]"' in page for f in ("mode", "secret", "trusted_proxies", "allow_cidrs", "exempt_paths")))
    expect("it lists the scanner's event", "tool:sqlmap" in page)
    settings_form = page.split('action="options.php"', 1)[-1].split("</form>", 1)[0]     # not the unblock forms below it
    form = dict(re.findall(r"""<input type=["']hidden["'] (?:id=["'][^"']*["'] )?name=["']([^"']+)["'] value=["']([^"']*)["']""",
                           settings_form))
    expect("the form carries a nonce", "_wpnonce" in form and form.get("option_page") == "artex-shield", form)
    secret = re.search(r'name="artex_shield_settings\[secret\]" value="([^"]+)"', page).group(1)
    form.update({"artex_shield_settings[mode]": "enforce", "artex_shield_settings[secret]": secret,
                 "artex_shield_settings[decoys]": "1", "artex_shield_settings[honeytokens]": "1",
                 "artex_shield_settings[trusted_proxies]": "not-a-network", "artex_shield_settings[allow_cidrs]": "",
                 "artex_shield_settings[exempt_paths]": "/healthz", "artex_shield_settings[store]": "auto"})
    status, headers, page = fetch("/wp-admin/options.php", form)
    expect(f"the settings are saved ({status})", status == 302 and "settings-updated=true" in headers.get("Location", ""), page[:500])
    # The scanner above came from this address too, so monitor mode put it on the block list. Saving
    # enforce mode must not shut the admin out with it.
    status, _, page = fetch("/wp-admin/options-general.php?page=artex-shield&settings-updated=true")
    expect(f"the admin is not shut out by switching to enforce ({status})", status == 200, page[:300])
    expect("they are told their own address was unblocked", page.count("was on the block list") == 1, page[:300])
    expect("an invalid proxy is refused with a reason, once",
           page.count("Trusted proxies: not a network: not-a-network") == 1, page[:300])
    expect("enforce mode is now chosen", re.search(r'value="enforce"\s+checked', page) is not None)
    no_php_errors(page, "the saved settings page")

elif PART == "visitor":
    status, _, page = fetch("/")
    expect(f"the home page is served in enforce mode ({status})", status == 200, page[:500])
    status, _, page = fetch("/no-such-page/")
    expect(f"WordPress's own 404 comes back ({status})", status == 404)
    status, _, body = fetch("/", headers={"User-Agent": "sqlmap/1.8.4#stable"})
    expect(f"a scanner is blocked ({status})", status == 403 and body.startswith("Request blocked. Reference: "), body[:300])
    status, _, _ = fetch("/")
    expect(f"its address stays blocked ({status})", status == 403)

elif PART == "replay":
    expect("a honeytoken password was given", bool(ARG))
    status, _, body = fetch("/wp-login.php", {"log": "admin-legacy", "pwd": ARG, "wp-submit": "Log In"})
    expect(f"a login with the planted password is blocked ({status})", status == 403 and body.startswith("Request blocked."), body[:300])
    status, _, _ = fetch("/")
    expect(f"its address stays blocked ({status})", status == 403)

print("all good")
