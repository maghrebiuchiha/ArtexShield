"use strict";
// Express behind artex-shield, with every decoy planted.
//
//   npm install express
//   ARTEX_SECRET=a-long-random-secret node examples/express.js
//
// Outside this repository, require("artex-shield") instead of "../lib".
const express = require("express");
const {
  Shield, artexShield, makeCanaries, makeHoneytokens, robotsTxtBlock, htmlTrap, jsTrap, honeytokenHtml, honeytokenJs,
  clientCheckTag,
} = require("../lib");

const secret = process.env.ARTEX_SECRET || "change-me-to-a-long-random-secret";
const canaries = makeCanaries(secret);
const tokens = makeHoneytokens(secret);
const shield = new Shield({
  mode: process.env.ARTEX_MODE || "monitor",     // log only; "enforce" once the logs show no visitor you would stop
  canaryPaths: canaries,
  honeytokens: tokens,                           // fake credentials: whoever presents one is blocked on sight
  clientCheck: true,                             // optional: the page script below reports browser automation
  clientCheckSecret: `${secret}/client-check`,
  // trustedProxies: ["10.0.0.0/8"],             // only behind your own proxy or load balancer
});

const app = express();
app.use(artexShield(shield));                    // first: before body parsers, routers and static files
app.use(express.json());

app.get("/robots.txt", (req, res) => res.type("text/plain").send(robotsTxtBlock(canaries)));
app.get("/app.js", (req, res) => res.type("text/javascript").send(`${jsTrap(canaries[1])}\n${honeytokenJs(tokens)}\n`));
app.get("/", (req, res) => res.type("html").send(
  `<!doctype html><title>Shop</title><h1>Shop</h1>${htmlTrap(canaries[0])}${honeytokenHtml(tokens)}` +
  `<script src="/app.js"></script>${clientCheckTag(shield)}`));
app.post("/api/echo", (req, res) => res.json({ got: req.body }));

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => console.log(`listening on http://localhost:${port}, mode ${shield.cfg.mode}`));
}
module.exports = { app, shield, tokens };
