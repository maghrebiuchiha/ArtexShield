"use strict";
// The optional client-side check: a script that reports browser automation,
// and a signed cookie saying the check ran. See client_check.py and SPEC.md.
const crypto = require("crypto");
const py = require("./py");

const FLAGS = 7;      // 1 navigator.webdriver, 2 driver globals, 4 driver traces on the document

// Must stay identical to client_check._SCRIPT; test/vectors.test.js compares it with the spec.
const SCRIPT = `(function () {
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
`;

/** The check script, reporting to `path`. */
function script(path) {
  return SCRIPT.split("PATH").join(py.jsonString(path));
}

/** The <script> tag for every HTML page; the middleware serves `path` + ".js". */
function tag(path) {
  return `<script src="${path}.js" async></script>`;
}

function mac(key, issued, flags) {
  return crypto.createHmac("sha256", key).update(`1.${issued}.${flags}`).digest("base64url").slice(0, 22);
}

/** Cookie value: version, when issued, what was reported, signature. */
function sign(key, issued, flags) {
  return `1.${issued}.${flags}.${mac(key, issued, flags)}`;
}

/** The flags of a valid, unexpired cookie this key signed; null otherwise. */
function verify(key, value, now, ttl) {
  if (!value || py.cpLength(value) > 100) return null;
  const parts = value.split(".");
  if (parts.length !== 4 || parts[0] !== "1" || !py.isAsciiDigits(parts[1]) || !py.isAsciiDigits(parts[2])) return null;
  const issued = Number(parts[1]);
  const flags = Number(parts[2]);
  if (!(now - ttl <= issued && issued <= now + 300) || flags > FLAGS) return null;
  const want = Buffer.from(mac(key, String(issued), String(flags)));
  const got = Buffer.from(parts[3]);
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return null;
  return flags;
}

/** The value of cookie `name` in a Cookie header, or null. */
function cookie(header, name) {
  for (const part of py.cpSlice(header, 16384).split(";")) {
    const piece = py.strip(part);
    const eq = piece.indexOf("=");
    if (eq >= 0 && piece.slice(0, eq) === name) return py.strip(piece.slice(eq + 1)).replace(/^"+|"+$/g, "");
  }
  return null;
}

const ASSETS = /text\/html|application\/xhtml|image\/|text\/css|video\/|audio\/|font\//;

/** Did a page's script send this request (fetch or XHR)? `h`: lower-case header Map. */
function scriptMade(h) {
  const mode = py.strip(h.get("sec-fetch-mode") || "").toLowerCase();
  if (mode) {
    return (mode === "cors" || mode === "same-origin") &&
      py.strip(h.has("sec-fetch-dest") ? h.get("sec-fetch-dest") : "empty").toLowerCase() === "empty";
  }
  if (py.strip(h.get("x-requested-with") || "").toLowerCase() === "xmlhttprequest") return true;
  return !ASSETS.test((h.get("accept") || "").toLowerCase());
}

module.exports = { FLAGS, SCRIPT, script, tag, sign, verify, cookie, scriptMade };
