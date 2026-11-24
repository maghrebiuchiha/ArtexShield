"use strict";
// The middleware and the http wrapper on a real server on 127.0.0.1.
const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const net = require("net");
const crypto = require("crypto");
const { Shield, handler, artexShield, upgradeGuard, makeHoneytokens } = require("../lib");

const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";
const BROWSER = { "User-Agent": CHROME, Accept: "text/html", "Accept-Language": "en-GB" };
const SCANNER = { "User-Agent": "sqlmap/1.8.4#stable" };
const TOKENS = makeHoneytokens("node-test-secret");

/** A server running `shield` in front of an app that records what reached it. */
async function site(options, app) {
  const shield = new Shield({ logger: null, ...options });
  const reached = [];
  const observed = [];
  const observe = shield.observe.bind(shield);
  shield.observe = (...args) => { observed.push(args); return observe(...args); };
  const inner = app || ((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      reached.push({ method: req.method, url: req.url, body });
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ length: body.length, sha: crypto.createHash("sha256").update(body).digest("hex") }));
    });
  });
  const server = http.createServer(handler(shield, inner));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { shield, server, reached, observed, port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

/** One request; resolves {status, headers, body}. `body` may be a Buffer or an array of chunks. */
function request(port, { method = "GET", path = "/", headers = BROWSER, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers, agent: false }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", reject);
    if (Array.isArray(body)) {
      body.forEach((c) => req.write(c));
      req.end();
    } else {
      req.end(body);
    }
  });
}

test("a request passes through to the app", async () => {
  const s = await site({ mode: "enforce" });
  const r = await request(s.port, { path: "/products?page=2&id=5" });
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(s.reached.map((x) => x.url), ["/products?page=2&id=5"]);
  await s.close();
});

test("enforce mode blocks a scanner before the app and keeps the address blocked", async () => {
  const s = await site({ mode: "enforce" });
  const r = await request(s.port, { headers: SCANNER });
  assert.strictEqual(r.status, 403);
  assert.match(r.body, /^Request blocked\. Reference: [0-9a-f]{8}\n$/);
  assert.strictEqual(r.headers["cache-control"], "no-store");
  assert.strictEqual((await request(s.port)).status, 403);
  assert.deepStrictEqual(s.reached, []);
  await s.close();
});

test("a payload is throttled with Retry-After", async () => {
  const s = await site({ mode: "enforce" });
  const r = await request(s.port, { path: "/search?q=%3Cscript%3Ealert(1)%3C/script%3E" });
  assert.strictEqual(r.status, 429);
  assert.ok(Number(r.headers["retry-after"]) >= 120);
  assert.match(r.body, /^Too many requests\. Reference: /);
  await s.close();
});

test("monitor mode decides but lets everything through", async () => {
  const s = await site({});
  assert.strictEqual((await request(s.port, { headers: SCANNER })).status, 200);
  assert.strictEqual(s.reached.length, 1);
  await s.close();
});

test("the app's status and content type reach the shield, however it sets them", async () => {
  const s = await site({}, (req, res) => {
    if (req.url === "/gone") { res.writeHead(404, { "Content-Type": "text/html" }); return res.end("no"); }
    if (req.url === "/page") { res.statusCode = 200; res.setHeader("content-type", "text/html; charset=utf-8"); return res.end("<p>"); }
    res.writeHead(204, [["X-A", "1"], ["Content-Type", "application/json"]]);
    return res.end();
  });
  await request(s.port, { path: "/gone" });
  await request(s.port, { path: "/page" });
  await request(s.port, { path: "/raw" });
  assert.deepStrictEqual(s.observed.map(([, path, status, , type]) => [path, status, type]),
    [["/gone", 404, "text/html"], ["/page", 200, "text/html; charset=utf-8"], ["/raw", 204, "application/json"]]);
  await s.close();
});

test("404s from the app build a score", async () => {
  const s = await site({ mode: "enforce" }, (req, res) => { res.statusCode = req.url === "/" ? 200 : 404; res.end(); });
  assert.strictEqual((await request(s.port, { path: "/old-site-backup.sql" })).status, 404);
  assert.strictEqual((await request(s.port, { path: "/" })).status, 429);       // 60 points for a missing dump
  await s.close();
});

test("X-Forwarded-For is believed only from a trusted proxy", async () => {
  const untrusted = await site({});
  await request(untrusted.port, { headers: { ...BROWSER, "X-Forwarded-For": "203.0.113.7" } });
  assert.strictEqual(untrusted.observed[0][0], "127.0.0.1");
  await untrusted.close();
  const trusted = await site({ trustedProxies: ["127.0.0.1/32"], mode: "enforce" });
  await request(trusted.port, { headers: { ...SCANNER, "X-Forwarded-For": "203.0.113.7" } });
  assert.strictEqual((await request(trusted.port, { headers: { ...BROWSER, "X-Forwarded-For": "203.0.113.7" } })).status, 403);
  assert.strictEqual((await request(trusted.port, { headers: { ...BROWSER, "X-Forwarded-For": "198.51.100.9" } })).status, 200);
  await trusted.close();
});

test("the path is decoded for the shield and repeated headers are joined", async () => {
  const s = await site({});
  const seen = [];
  const check = s.shield.check.bind(s.shield);
  s.shield.check = (...args) => { seen.push(args); return check(...args); };
  await request(s.port, { path: "/caf%C3%A9/a%20b?q=a%20b", headers: [["Host", "x"], ["User-Agent", CHROME], ["Accept", "text/html"],
    ["accept", "*/*"], ["Cookie", "a=1"], ["Cookie", "b=2"], ["Accept-Language", "en"]].flat() });
  const [, , path, query, headers] = seen[0];
  assert.deepStrictEqual([path, query], ["/café/a b", "q=a%20b"]);
  assert.strictEqual(headers.get("accept"), "text/html, */*");
  assert.strictEqual(headers.get("cookie"), "a=1; b=2");
  await s.close();
});

test("honeytokens: a planted key in a body is blocked before the app", async () => {
  const s = await site({ mode: "enforce", honeytokens: TOKENS });
  const body = JSON.stringify({ apiKey: TOKENS.apiKeys[0] });
  const r = await request(s.port, { method: "POST", path: "/api/report", body,
    headers: { ...BROWSER, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } });
  assert.strictEqual(r.status, 403);
  assert.deepStrictEqual(s.reached, []);
  await s.close();
});

test("honeytokens: in a chunked form, and in a header", async () => {
  const s = await site({ mode: "enforce", honeytokens: TOKENS });
  const form = `log=admin-legacy&pwd=${encodeURIComponent(TOKENS.passwords[1])}`;
  const r = await request(s.port, { method: "POST", path: "/wp-login.php", body: [form.slice(0, 9), form.slice(9)],
    headers: { ...BROWSER, "Transfer-Encoding": "chunked" } });
  assert.strictEqual(r.status, 403);
  const s2 = await site({ mode: "enforce", honeytokens: TOKENS });
  const h = await request(s2.port, { headers: { ...BROWSER, Authorization: `Bearer ${TOKENS.apiKeys[1]}` } });
  assert.strictEqual(h.status, 403);
  await s.close();
  await s2.close();
});

test("honeytokens: the app still reads every body whole, of any size and framing", async () => {
  const s = await site({ mode: "enforce", honeytokens: TOKENS });
  const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
  for (const size of [0, 1, 1000, 65535, 65536, 65537, 300000]) {
    const blob = crypto.randomBytes(size);
    const sized = await request(s.port, { method: "POST", path: "/up", body: blob,
      headers: { ...BROWSER, "Content-Length": size } });
    assert.deepStrictEqual(JSON.parse(sized.body), { length: size, sha: sha(blob) }, `sized ${size}`);
    const parts = size ? [blob.subarray(0, Math.floor(size / 3)), blob.subarray(Math.floor(size / 3))] : [];
    const chunked = await request(s.port, { method: "PUT", path: "/up", body: parts,
      headers: { ...BROWSER, "Transfer-Encoding": "chunked" } });
    assert.deepStrictEqual(JSON.parse(chunked.body), { length: size, sha: sha(blob) }, `chunked ${size}`);
  }
  await s.close();
});

test("honeytokens: a key past the first 64 KiB is not read, as the reference does not", async () => {
  const s = await site({ mode: "enforce", honeytokens: TOKENS });
  const body = Buffer.concat([Buffer.alloc(70000, "x"), Buffer.from(TOKENS.apiKeys[0])]);
  const r = await request(s.port, { method: "POST", path: "/up", body, headers: { ...BROWSER, "Content-Length": body.length } });
  assert.strictEqual(r.status, 200);
  await s.close();
});

test("the client check's script and endpoint are answered here", async () => {
  const s = await site({ clientCheck: true, clientCheckSecret: "s", trustedProxies: ["127.0.0.1/32"] });
  const script = await request(s.port, { path: "/_artex/check.js" });
  assert.strictEqual(script.status, 200);
  assert.strictEqual(script.headers["content-type"], "text/javascript; charset=utf-8");
  assert.ok(script.body.includes('"/_artex/check"'));
  const fetchHeaders = { "User-Agent": CHROME, Accept: "*/*", "Accept-Language": "en", "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty" };
  const check = await request(s.port, { path: "/_artex/check?v=1&f=0", headers: fetchHeaders });
  assert.strictEqual(check.status, 204);
  assert.match(check.headers["set-cookie"][0], /^artex_check=1\.\d+\.0\.[\w-]{22}; Path=\/; Max-Age=86400; HttpOnly; SameSite=Lax$/);
  const secure = await request(s.port, { path: "/_artex/check?v=1&f=0", headers: { ...fetchHeaders, "X-Forwarded-Proto": "https" } });
  assert.ok(secure.headers["set-cookie"][0].endsWith("; Secure"));
  assert.deepStrictEqual(s.reached, []);
  await s.close();
});

test("Express-style mounting reads the original URL", async () => {
  const shield = new Shield({ mode: "enforce", logger: null });
  const mw = artexShield(shield);
  const server = http.createServer((req, res) => {
    req.originalUrl = req.url;
    req.url = req.url.replace(/^\/mounted/, "") || "/";   // what a mounted router does
    mw(req, res, () => res.end("ok"));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  assert.strictEqual((await request(port, { path: "/mounted/.env" })).status, 429);     // the full path was read
  await new Promise((r) => server.close(r));
});

test("a WebSocket handshake is checked like any request", async () => {
  const shield = new Shield({ mode: "enforce", logger: null });
  const guard = upgradeGuard(shield);
  const accepted = [];
  const server = http.createServer((req, res) => res.end());
  server.on("upgrade", (req, socket) => {
    if (!guard(req, socket)) return;
    accepted.push(req.url);
    socket.end("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const handshake = (ua) => new Promise((resolve) => {
    const sock = net.connect(server.address().port, "127.0.0.1", () => {
      sock.write(`GET /socket HTTP/1.1\r\nHost: x\r\nUser-Agent: ${ua}\r\nAccept-Language: en\r\nConnection: Upgrade\r\n` +
        "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n");
    });
    let data = "";
    sock.on("data", (d) => { data += d; });
    sock.on("end", () => resolve(data));
    sock.on("error", () => resolve(data));
  });
  assert.match(await handshake(CHROME), /^HTTP\/1\.1 101 /);
  assert.match(await handshake("sqlmap/1.8"), /^HTTP\/1\.1 403 Forbidden\r\n[\s\S]*Request blocked/);
  assert.deepStrictEqual(accepted, ["/socket"]);
  await new Promise((r) => server.close(r));
});
