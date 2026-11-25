"use strict";
// The Node shield against spec/vectors.json: every case the Python reference
// passes, replayed as spec/SPEC.md says a runner must.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { Shield, makeConfig, makeCanaries, makeHoneytokens, clientCheckScript } = require("../lib");
const ip = require("../lib/ip");

const SPEC = process.env.ARTEX_SPEC || path.join(__dirname, "..", "..", "..", "spec");     // ARTEX_SPEC: another spec/ directory
const data = JSON.parse(fs.readFileSync(path.join(SPEC, "vectors.json"), "utf8"));
const TOLERANCE = 1e-6;

/** snake_case vector settings to the camelCase this port takes. */
function options(spec, t0) {
  const out = { logger: null };
  for (const [k, v] of Object.entries(spec || {})) {
    const name = k.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
    out[name] = name === "engagements"
      ? v.map((e) => ({ reference: e.reference, cidrs: e.cidrs, start: t0 + e.start, end: t0 + e.end }))
      : v;
  }
  return out;
}

function body(r) {
  if ("body_base64" in r) return Buffer.from(r.body_base64, "base64");
  return "body" in r ? Buffer.from(r.body, "utf8") : null;
}

function fill(template, i) {
  if (typeof template === "string") return template.split("{i}").join(String(i));
  if (Array.isArray(template)) return template.map((v) => fill(v, i));
  if (template && typeof template === "object") {
    return Object.fromEntries(Object.entries(template).map(([k, v]) => [k, fill(v, i)]));
  }
  return template;
}

class Runner {
  constructor(c, t0) {
    this.case = c;
    this.t0 = t0;
    this.failures = [];
    this.now = t0;
    this.shield = new Shield(options(c.config, t0), () => this.now);
  }

  fail(where, message) {
    this.failures.push(`${this.case.id} step ${where}: ${message}`);
  }

  compare(where, got, want, full) {
    const hits = [...got.hits].sort();
    if (got.action !== want.action) this.fail(where, `action ${got.action}, expected ${want.action} (hits ${hits})`);
    if (JSON.stringify(hits) !== JSON.stringify(want.hits)) this.fail(where, `hits ${JSON.stringify(hits)}, expected ${JSON.stringify(want.hits)}`);
    if (full && Math.abs(got.score - want.score) > TOLERANCE) this.fail(where, `score ${got.score}, expected ${want.score}`);
    if (full && "retry_after" in want && got.retryAfter !== want.retry_after) {
      this.fail(where, `retry_after ${got.retryAfter}, expected ${want.retry_after}`);
    }
  }

  step(where, step, expect, full = true) {
    const s = this.shield;
    if (step.request) {
      const r = step.request;
      const d = s.check(r.ip, r.method || "GET", r.path, r.query || "", r.headers || {}, body(r));
      if (expect != null) this.compare(where, d, expect, full);
    } else if (step.observe) {
      const o = step.observe;
      s.observe(o.ip, o.path, o.status, Boolean(o.induced), o.content_type || "");
    } else if (step.client_check) {
      const c = step.client_check;
      const r = s.clientCheckReply(c.ip, c.query, c.headers || {}, Boolean(c.secure));
      const got = { status: r.status, headers: r.headers };
      if (JSON.stringify(got) !== JSON.stringify(step.expect)) {
        this.fail(where, `client check answered ${JSON.stringify(got)}, expected ${JSON.stringify(step.expect)}`);
      }
    } else if ("unblock" in step) {
      const got = s.unblock(step.unblock);
      if (got !== step.expect) this.fail(where, `unblock returned ${got}, expected ${step.expect}`);
    } else if ("expect_blocklist" in step) {
      const got = Object.keys(s.blocklist()).sort();
      if (JSON.stringify(got) !== JSON.stringify(step.expect_blocklist)) {
        this.fail(where, `blocklist ${JSON.stringify(got)}, expected ${JSON.stringify(step.expect_blocklist)}`);
      }
    } else {
      this.fail(where, `unknown step ${Object.keys(step)}`);
    }
  }

  run() {
    this.case.steps.forEach((step, n) => {
      if ("repeat" in step) {
        let t = this.t0 + step.at;
        let started = false;
        let iteration = 0;
        for (const run of step.expect) {
          for (let k = 0; k < run.times; k += 1) {
            const final = k === run.times - 1;
            step.steps.forEach((template, j) => {
              if (started) t += step.dt[j];
              started = true;
              this.now = t;
              this.step(`${n} (repeat ${iteration}, part ${j})`, fill(template, step.i_from + iteration),
                (final ? run.last : run.each)[j], final);
            });
            iteration += 1;
          }
        }
        if (iteration !== step.repeat) this.fail(n, `repeat block runs ${iteration} times, declares ${step.repeat}`);
      } else {
        this.now = this.t0 + step.at;
        this.step(n, step, step.expect);
      }
    });
    return this.failures;
  }
}

test("the file is the version this runner reads", () => {
  assert.deepStrictEqual([data.version, data.t0], [2, 1800000000.0]);
  if (!process.env.ARTEX_SPEC) assert.ok(data.cases.length > 500);    // the repository's own spec, read whole
});

test("every case", () => {
  const failures = [];
  for (const c of data.cases) failures.push(...new Runner(c, data.t0).run());
  assert.deepStrictEqual(failures.slice(0, 25), [], `${failures.length} failures`);
});

test("client addresses", () => {
  for (const item of data.client_ip) {
    const s = new Shield({ trustedProxies: item.trusted_proxies, logger: null });
    assert.strictEqual(s.clientIp(item.remote, item.forwarded_for), item.expect, JSON.stringify(item));
  }
});

test("client check routes", () => {
  for (const item of data.client_check_routes) {
    const s = new Shield(options(item.config, data.t0));
    assert.strictEqual(s.clientCheckRoute(item.path), item.expect, JSON.stringify(item));
  }
});

test("configs the reference refuses are refused", () => {
  for (const item of data.config_errors) {
    assert.throws(() => makeConfig(options(item.config, data.t0)), Error, JSON.stringify(item));
  }
});

test("canary and honeytoken derivations", () => {
  for (const item of data.canaries) assert.deepStrictEqual(makeCanaries(item.secret, item.count), item.paths);
  for (const item of data.honeytokens) {
    const t = makeHoneytokens(item.secret, item.count);
    assert.deepStrictEqual([t.apiKeys, t.users, t.passwords], [item.api_keys, item.users, item.passwords]);
  }
});

test("every pattern reads the probe texts as Python does", () => {
  const S = require("../lib/signatures");
  const table = {};
  for (const [rx, , label] of S.HARD_UA) table[`hard_ua:${label}`] = rx;
  for (const [rx, , label] of S.SOFT_UA) table[`soft_ua:${label}`] = rx;
  for (const [rx, label] of S.PAYLOADS) table[`payloads:${label}`] = rx;
  for (const [rx, label] of S.OOB) table[`oob:${label}`] = rx;
  for (const name of ["assessment_ua", "browser_ua", "crawler_ua", "sensitive_paths", "missing_sensitive", "recon_paths"]) {
    table[name] = S[name.toUpperCase()];
  }
  const { texts, matches } = data.pattern_probes;
  const wrong = [];
  for (const [name, want] of Object.entries(matches)) {
    const got = texts.map((t) => (table[name].test(t) ? "1" : "0")).join("");
    for (let i = 0; i < texts.length; i += 1) {
      if (got[i] !== want[i]) wrong.push(`${name} on ${JSON.stringify(texts[i])}: ${got[i]}, Python ${want[i]}`);
    }
  }
  assert.deepStrictEqual(wrong, []);
});

test("the client check script", () => {
  assert.strictEqual(clientCheckScript("/_artex/check"), data.client_check_script.split("PATH").join('"/_artex/check"'));
});

test("the signature patterns are spec/patterns.json", () => {
  const ours = fs.readFileSync(path.join(__dirname, "..", "lib", "patterns.json"), "utf8");
  const spec = fs.readFileSync(path.join(SPEC, "patterns.json"), "utf8");
  assert.strictEqual(ours, spec, "copy spec/patterns.json to ports/node/lib/patterns.json");
});

test("addresses are read and written as Python's ipaddress does", () => {
  const cases = [["2001:db8:6:002::1", "2001:db8:6:2::/64"], ["::ffff:1.2.3.4", "1.2.3.4"], ["1.2.3.4", "1.2.3.4"],
    ["fe80::1%eth0", "fe80::/64"], ["2001:0:0:1::1", "2001:0:0:1::/64"], ["::1", "::/64"], ["01.2.3.4", "invalid"],
    ["1:2:3:4:5:6:7:8", "1:2:3:4::/64"], ["1::2:3:4:5:6:7", "1:0:2:3::/64"], ["::", "::/64"], ["1.2.3", "invalid"],
    ["1:2:3:4:5:6:1.2.3.4", "1:2:3:4::/64"], [":1:2::", "invalid"], ["1:::2", "invalid"]];
  for (const [addr, key] of cases) assert.strictEqual(ip.trackKey(addr), key, addr);
  assert.strictEqual(ip.wider("2001:db8:5:ff::/64"), "2001:db8:5::/56");
  assert.strictEqual(ip.wider("2001:db8:5::/56"), "2001:db8:5::/48");
  assert.strictEqual(ip.wider("2001:db8::/48"), null);
});

module.exports = { Runner, options, body, fill, data };
