"use strict";
// A plain Node `http` server behind artex-shield, WebSocket upgrades included.
//
//   ARTEX_SECRET=a-long-random-secret node examples/http.js
//   curl -i localhost:3000/            # 200
//   curl -i -A sqlmap/1.8 localhost:3000/   # 403 with ARTEX_MODE=enforce; logged either way
//
// Outside this repository, require("artex-shield") instead of "../lib".
const http = require("http");
const { Shield, handler, upgradeGuard, makeCanaries, robotsTxtBlock, htmlTrap } = require("../lib");

const secret = process.env.ARTEX_SECRET || "change-me-to-a-long-random-secret";
const canaries = makeCanaries(secret);
const shield = new Shield({
  mode: process.env.ARTEX_MODE || "monitor",     // log only; "enforce" once the logs show no visitor you would stop
  canaryPaths: canaries,
  // trustedProxies: ["10.0.0.0/8"],             // only behind your own proxy or load balancer
});

function app(req, res) {
  if (req.url === "/robots.txt") {
    res.setHeader("Content-Type", "text/plain");
    return res.end(robotsTxtBlock(canaries));
  }
  if (req.url === "/") {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.end(`<!doctype html><title>Hello</title><h1>Hello</h1>${htmlTrap(canaries[0])}`);
  }
  res.statusCode = 404;                          // the shield sees the 404s your app answers
  return res.end("Not found\n");
}

const server = http.createServer(handler(shield, app));
const guard = upgradeGuard(shield);
server.on("upgrade", (req, socket) => {
  if (!guard(req, socket)) return;               // a blocked client never opens a socket
  socket.end("HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n");   // your WebSocket server goes here
});

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  server.listen(port, () => console.log(`listening on http://localhost:${port}, mode ${shield.cfg.mode}`));
}
module.exports = { server, shield };
