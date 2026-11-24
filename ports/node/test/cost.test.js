"use strict";
// The shield reads attacker-controlled text on every request, so no input may
// make that slow. The same budgets and hostile inputs as the Python reference's
// Cost tests, since JavaScript's regex engine backtracks in its own way.
const test = require("node:test");
const assert = require("node:assert");
const S = require("../lib/signatures");
const { Shield } = require("../lib");

const BUDGET = 0.25;
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";
const BROWSER = { "User-Agent": CHROME, Accept: "text/html", "Accept-Language": "en-US" };

function timed(fn) {
  let best = Infinity;
  for (let i = 0; i < 2 && best >= BUDGET; i += 1) {         // best of two: ignore a scheduling hiccup
    const t0 = process.hrtime.bigint();
    fn();
    best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e9);
  }
  return best;
}

test("every pattern scans in linear time", () => {
  const patterns = [];
  for (const [rx, , label] of S.HARD_UA) patterns.push([`HARD_UA ${label}`, rx]);
  for (const [rx, , label] of S.SOFT_UA) patterns.push([`SOFT_UA ${label}`, rx]);
  for (const [rx, label] of S.PAYLOADS.concat(S.OOB)) patterns.push([label, rx]);
  for (const name of ["ASSESSMENT_UA", "BROWSER_UA", "CRAWLER_UA", "SENSITIVE_PATHS", "MISSING_SENSITIVE", "RECON_PATHS"]) {
    patterns.push([name, S[name]]);
  }
  assert.ok(patterns.length >= 26);
  const atoms = ["a", "db", "a-", "a.", "/", " ", "\n", "\r\n ", "; ", ";\n", "/*", "/* a ", "*/", "' or ", "{{ ", " on",
    " onmouse", "#{1", "${T", "../", "..\\", "javascript:", "javascript: ", "<script>", "<script ",
    "' and '1", "' or 1 ", "union select ", "1 union select ", "sleep(", "<iframe ", "<x onclick=",
    "1", "mozilla/5.0 ", "ARTEX-Assessment/1 ", "union ", "union all ",
    "' ", "' or ", "sleep ( ", "; ", "| cat ", "{{1 ", "${ ", "<%= 1", "on", "onload ", "<svg",
    "backup.", "/wp-config.php.a", "/swagger/", "/admin/", "x.oast", "-.", "curl/", "é", "ı", " "];
  const slow = [];
  for (const [name, rx] of patterns) {
    for (const atom of atoms) {
      const text = atom.repeat(Math.floor(30000 / atom.length));
      for (const subject of [text, "/" + text + "!"]) {
        const took = timed(() => rx.test(subject));
        if (took >= BUDGET) slow.push(`${name} on ${JSON.stringify(atom)}: ${took.toFixed(2)} s`);
      }
    }
  }
  assert.deepStrictEqual(slow, []);
});

test("oversized requests are checked quickly", () => {
  const s = new Shield({ mode: "enforce", logger: null });
  const padded = { ...BROWSER };
  for (let i = 0; i < 60; i += 1) padded[`X-Pad-${i}`] = "a".repeat(8000);
  const cases = {
    "60 padded headers": () => s.check("192.0.2.90", "GET", "/", "", padded),
    "8000-character path": () => s.check("192.0.2.91", "GET", "/" + "db".repeat(4000) + "!", "", BROWSER),
    "60000-character query": () => s.check("192.0.2.92", "GET", "/", "a".repeat(60000), BROWSER),
    "20000 query parameters": () => s.check("192.0.2.93", "GET", "/", "a=b&".repeat(20000), BROWSER),
    "8000-character user agent": () => s.check("192.0.2.94", "GET", "/", "", { "User-Agent": "Mozilla/5.0 ".repeat(660) }),
    "8000-character referer": () => s.check("192.0.2.95", "GET", "/", "", { ...BROWSER, Host: "shop.example",
      Referer: "https://" + "a.".repeat(4000) }),
    "a 64 KB body with honeytokens set": () => new Shield({ honeytokens: ["api_live_0123456789abcdef"], logger: null })
      .check("192.0.2.96", "POST", "/", "", BROWSER, Buffer.alloc(65536, "%")),
  };
  for (const [name, fn] of Object.entries(cases)) assert.ok(timed(fn) < BUDGET, name);
});
