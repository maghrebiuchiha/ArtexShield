"""Optional client-side check: a small script that reports browser automation,
and a signed cookie that says the check ran.

The script runs in the visitor's browser on your HTML pages. It looks for the
marks that browser automation leaves (navigator.webdriver, the globals and
document properties that PhantomJS, Nightmare, Playwright, Puppeteer and
ChromeDriver add) and calls the check endpoint with what it found. The answer
sets a cookie, signed so it cannot be made up or edited: when it was issued
and what was reported.

What this can tell the shield is narrow, and only ever soft evidence:

- An API request that a page's script made (fetch or XHR), from a client that
  loaded your pages but never completed the check, comes from something that
  runs no script of yours: an HTTP library replaying what a browser would do.
- One that carries an automation report comes from a driven browser.

Requests a browser sends without running any script, navigations and
subresource loads such as images, are never judged here, so a visitor with
JavaScript turned off is never affected.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Dict, Optional

FLAG_WEBDRIVER = 1          # navigator.webdriver is true: WebDriver, Playwright, Puppeteer by default
FLAG_DRIVER_GLOBALS = 2     # window globals left by PhantomJS, Nightmare, Chrome automation, Playwright
FLAG_DRIVER_TRACES = 4      # document properties left by Selenium and ChromeDriver
FLAGS = FLAG_WEBDRIVER | FLAG_DRIVER_GLOBALS | FLAG_DRIVER_TRACES

_SCRIPT = """(function () {
  try {
    var w = window, d = document, n = navigator, f = 0, k, keys;
    try { if (w.sessionStorage.getItem("artex_check")) return; w.sessionStorage.setItem("artex_check", "1"); } catch (e) {}
    if (n.webdriver === true) f |= 1;
    if (w.callPhantom || w._phantom || w.__nightmare || w.domAutomation || w.domAutomationController ||
        w.__playwright__binding__ || w.__pwInitScripts) f |= 2;
    var el = d.documentElement;
    if ((el && el.getAttribute("webdriver") !== null) || d.__selenium_unwrapped || d.__webdriver_evaluate ||
        d.__driver_evaluate || d.__webdriver_script_fn) f |= 4;
    try { keys = Object.keys(d); for (k = 0; k < keys.length; k++) { if (keys[k].indexOf("cdc_") >= 0) { f |= 4; break; } } } catch (e) {}
    var url = PATH + "?v=1&f=" + f;
    if (w.fetch) { w.fetch(url, {credentials: "same-origin", cache: "no-store"})["catch"](function () {}); }
    else { var x = new XMLHttpRequest(); x.open("GET", url, true); x.send(); }
  } catch (e) {}
})();
"""


def script(path: str) -> str:
    """The check script, reporting to `path` (Config.client_check_path)."""
    return _SCRIPT.replace("PATH", json.dumps(path))


def tag(path: str) -> str:
    """The <script> tag to put on every HTML page. The middleware serves the
    file itself at `path` + ".js"; to inline it instead (for a CSP nonce, say),
    put script(path) inside your own <script> element."""
    return f'<script src="{path}.js" async></script>'


def _mac(key: bytes, issued: int, flags: int) -> str:
    digest = hmac.new(key, f"1.{issued}.{flags}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode()[:22]


def sign(key: bytes, issued: int, flags: int) -> str:
    """Cookie value: version, when issued, what was reported, signature."""
    return f"1.{issued}.{flags}.{_mac(key, issued, flags)}"


def digits(text: str) -> bool:
    """ASCII digits only: str.isdigit() also takes "²", which int() refuses,
    and "٣", which int() reads as 3."""
    return text.isascii() and text.isdigit()


def verify(key: bytes, value: Optional[str], now: float, ttl: float) -> Optional[int]:
    """The reported flags if `value` is a cookie this key signed that has not
    expired; None for anything else."""
    if not value or len(value) > 100:
        return None
    parts = value.split(".")
    if len(parts) != 4 or parts[0] != "1" or not digits(parts[1]) or not digits(parts[2]):
        return None
    issued, flags = int(parts[1]), int(parts[2])
    if not now - ttl <= issued <= now + 300 or flags > FLAGS:
        return None
    if not hmac.compare_digest(parts[3], _mac(key, issued, flags)):
        return None
    return flags


def cookie(header: str, name: str) -> Optional[str]:
    """The value of cookie `name` in a Cookie header, or None."""
    for part in header[:16384].split(";"):
        k, sep, v = part.strip().partition("=")
        if sep and k == name:
            return v.strip().strip('"')
    return None


def script_made(h: Dict[str, str]) -> bool:
    """True when a page's script sent this request (fetch or XMLHttpRequest).

    Browsers mark that themselves: Sec-Fetch-Mode is cors or same-origin and
    the destination is empty, where a navigation says navigate and an image or
    stylesheet says no-cors with its own destination. Browsers too old to send
    those headers ask for HTML when they navigate and for images or CSS when
    they load them. Anything else, the shape HTTP libraries and scripts send,
    counts as script-made. A browser with JavaScript off sends no request
    this returns True for."""
    mode = h.get("sec-fetch-mode", "").strip().lower()
    if mode:
        return mode in ("cors", "same-origin") and h.get("sec-fetch-dest", "empty").strip().lower() == "empty"
    if h.get("x-requested-with", "").strip().lower() == "xmlhttprequest":
        return True
    accept = h.get("accept", "").lower()
    return not re.search(r"text/html|application/xhtml|image/|text/css|video/|audio/|font/", accept)
