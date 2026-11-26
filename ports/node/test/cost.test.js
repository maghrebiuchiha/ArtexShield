"use strict";
// The shield reads attacker-controlled text on every request, so no input may
// make that slow. The same budgets and hostile inputs as the Python reference's
// Cost tests, since JavaScript's regex engine backtracks in its own way.
const test = require("node:test");
const assert = require("node:assert");
const S = require("../lib/signatures");
const { Shield } = require("../lib");

const BUDGET = 0.25;
// Starts of SQL, markup and paths a pattern can almost match, and runs to
// follow them: the same lists as the reference's (tests/test_shield.py).
const LEADS = ["'", '"', "' or", "' or 1", "' or true", "' or '", "' )", "' ) or", "' or (", "union select a", "union select 1",
  "or", "1", "<script", "javascript:", "../", "${", "{{"];
const RUNS = [" ", "\t", "\n", ")", ") ", " )", "(", "1", "'"];
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
    // Something a pattern almost matches, then one long run: a run that two
    // quantifiers can share (\s*\)?\s*) is retried split every way.
    for (const lead of LEADS) {
      for (const run of RUNS) {
        const subject = lead + run.repeat(Math.floor(30000 / run.length)) + "!";
        const took = timed(() => rx.test(subject));
        if (took >= BUDGET) slow.push(`${name} on ${JSON.stringify(lead)} + ${JSON.stringify(run)}: ${took.toFixed(2)} s`);
      }
    }
  }
  assert.deepStrictEqual(slow, []);
});

test("a client's track stays small however long the paths it asks for", () => {
  // The 404s a client has been told about are remembered by digest, not by
  // path: 128 paths of 15 KB each must not make its track hold megabytes.
  const s = new Shield({ enum404Threshold: 1e6, slowEnumBudget: 0, logger: null });    // guessing is not scored here
  s.check("198.51.100.1", "GET", "/", "", BROWSER);
  for (let j = 0; j < 200; j += 1) s.observe("198.51.100.1", "/" + String(j).padStart(4, "0") + "a".repeat(15000), 404);
  const t = s.tracks.get("198.51.100.1");
  assert.strictEqual(t.missing.size, 128);
  const held = [...t.missing.keys()].reduce((n, k) => n + k.length, 0);
  assert.ok(held <= 128 * 16, `${held} characters of keys`);
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
    "a quote, then 60000 spaces": () => s.check("192.0.2.97", "GET", "/", "q='+or" + "+".repeat(60000), BROWSER),
    "8000-character user agent": () => s.check("192.0.2.94", "GET", "/", "", { "User-Agent": "Mozilla/5.0 ".repeat(660) }),
    "8000-character referer": () => s.check("192.0.2.95", "GET", "/", "", { ...BROWSER, Host: "shop.example",
      Referer: "https://" + "a.".repeat(4000) }),
    "a 64 KB body with honeytokens set": () => new Shield({ honeytokens: ["api_live_0123456789abcdef"], logger: null })
      .check("192.0.2.96", "POST", "/", "", BROWSER, Buffer.alloc(65536, "%")),
  };
  for (const [name, fn] of Object.entries(cases)) assert.ok(timed(fn) < BUDGET, name);
});
