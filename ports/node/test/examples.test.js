"use strict";
// The two examples, run for real. Express is not a dependency: CI installs it
// (npm install --no-save express) and this file skips the Express example without it.
const test = require("node:test");
const assert = require("node:assert");
const http = require("http");

process.env.ARTEX_MODE = "enforce";
process.env.ARTEX_SECRET = "examples-test-secret";
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";
const BROWSER = { "User-Agent": CHROME, Accept: "text/html", "Accept-Language": "en-GB" };

function request(port, { method = "GET", path = "/", headers = BROWSER, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers, agent: false }, (res) => {
      let data = "";
      res.on("data", (c) => { data += c; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function listening(server) {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return server.address().port;
}

test("the plain http example", async () => {
  const { server, shield } = require("../examples/http");
  shield.cfg = { ...shield.cfg, logger: null };
  const port = await listening(server);
  assert.strictEqual((await request(port)).status, 200);
  assert.match((await request(port, { path: "/robots.txt" })).body, /^User-agent: \*\nDisallow: \/api\/v1\/internal\/audit-/);
  assert.strictEqual((await request(port, { headers: { "User-Agent": "sqlmap/1.8" } })).status, 403);
  await new Promise((r) => server.close(r));
});

let express = null;
try {
  express = require.resolve("express");
} catch {
  express = null;
}

test("the Express example: decoys planted, bodies parsed after the read-ahead, honeytokens blocked",
  { skip: express ? false : "express is not installed (npm install --no-save express)" }, async () => {
    const { app, shield, tokens } = require("../examples/express");
    shield.cfg = { ...shield.cfg, logger: null };
    const server = http.createServer(app);
    const port = await listening(server);
    const home = await request(port);
    assert.strictEqual(home.status, 200);
    for (const planted of [tokens.passwords[1], '<script src="/_artex/check.js" async></script>', 'rel="nofollow"']) {
      assert.ok(home.body.includes(planted), planted);
    }
    const json = { order: 7, note: "x".repeat(70000) };              // past the read-ahead, to the parser whole
    const echoed = await request(port, { method: "POST", path: "/api/echo", body: JSON.stringify(json),
      headers: { ...BROWSER, "Content-Type": "application/json" } });
    assert.strictEqual(echoed.status, 200);
    assert.deepStrictEqual(JSON.parse(echoed.body).got, json);
    assert.strictEqual((await request(port, { path: "/_artex/check?v=1&f=0" })).status, 204);
    const replay = await request(port, { method: "POST", path: "/api/echo", body: JSON.stringify({ key: tokens.apiKeys[0] }),
      headers: { ...BROWSER, "Content-Type": "application/json" } });
    assert.strictEqual(replay.status, 403);
    assert.strictEqual((await request(port)).status, 403);           // and the address stays blocked
    await new Promise((r) => server.close(r));
  });
