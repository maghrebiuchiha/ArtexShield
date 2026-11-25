# artex-shield for Node.js

Detection and blocking of [ARTEX](https://github.com/BaaRai/ARTEX)-style automated penetration-testing traffic, for Express, Connect and plain `http` servers. No dependencies; Node 20 or newer.

This is a port of the Python package in this repository, which is the reference. Both are held to the same cases, `spec/vectors.json`, and the same rules, `spec/SPEC.md`. The main [README](../../README.md) explains what the shield looks for, how scoring works, and its limits. This page covers what is specific to Node.

It is not on npm. Install it from a copy of this repository: `npm install /path/to/ArtexShield/ports/node`. That gives your app `require("artex-shield")`.

## Express

```js
const express = require("express");
const { Shield, artexShield, makeCanaries } = require("artex-shield");

const canaries = makeCanaries(process.env.ARTEX_SECRET);        // a long random string you keep
const shield = new Shield({
  mode: "monitor",                       // log only; "enforce" once a week of logs shows no visitor you would stop
  canaryPaths: canaries,
  trustedProxies: ["10.0.0.0/8"],        // only if you sit behind your own proxy or load balancer
});

const app = express();
app.use(artexShield(shield));            // first: before body parsers, routers and static files
```

`examples/express.js` plants every decoy: canaries in `robots.txt`, a hidden link and a JS bundle, honeytokens, and the client check.

## Plain `http`

```js
const http = require("http");
const { Shield, handler, upgradeGuard } = require("artex-shield");

const shield = new Shield({ mode: "monitor" });
const server = http.createServer(handler(shield, app));      // app(req, res) is your handler

const guard = upgradeGuard(shield);                            // WebSocket handshakes are checked too
server.on("upgrade", (req, socket, head) => {
  if (!guard(req, socket)) return;                             // it answered 403 or 429 and closed the socket
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
});
```

See `examples/http.js`.

## What the middleware does

- **Client address.** It reads `req.socket.remoteAddress`, and reads `X-Forwarded-For` only from an address in `trustedProxies`. Express's `trust proxy` setting plays no part.
- **Path and query.** The path is taken from `req.originalUrl` (or `req.url`) and percent-decoded as UTF-8; the query is used as sent. Headers come from `req.rawHeaders`, in order, with repeats joined.
- **Stopped requests.** A blocked or refused request gets a 403, and a throttled one a 429 with `Retry-After`. The body names a reference that is also logged. Monitor mode never stops a request.
- **Feedback from your app.** The status code and `Content-Type` your app answers with go back to the shield, whether it calls `res.writeHead` or sets `res.statusCode`. That is how 404s count as guessing, and how the client check knows who loaded pages.
- **Honeytokens in bodies.** With honeytokens set, the first `honeytokenBodyLimit` bytes (64 KiB) of a request body are read before the shield decides. They are then handed back to the request stream in order, so `express.json()`, `multer` or your own reader gets the whole body as sent. Without honeytokens, bodies are not touched.
- **The client check**, when on, is answered by the middleware: it serves the script at `/_artex/check.js` and the check at `/_artex/check`. Neither reaches your app. Put `clientCheckTag(shield)` on every HTML page.

## Settings

The same as the Python `Config`, in camelCase: `throttleScore` for `throttle_score`, `clientCheckSecret` for `client_check_secret`, and so on. Defaults and meanings are in `spec/SPEC.md` and `lib/config.js`. Unknown names are refused, so a typo cannot go unnoticed.

Engagement windows take a `Date`, Unix seconds, or an ISO string with a timezone:

```js
engagements: [{ reference: "ENG-2026-014", cidrs: ["198.51.100.0/24"], start: "2026-03-01T09:00:00Z", end: "2026-03-14T18:00:00Z" }]
```

Two settings are Node's own:

- **`logger`** receives each event as one JSON line through `.warn()`. It defaults to `console`; `null` silences it.
- **`onEvent(event)`** is called with each event object.

## The decoy helpers

`makeCanaries`, `robotsTxtBlock`, `htmlTrap`, `jsTrap`, `makeHoneytokens`, `honeytokenJs`, `honeytokenHtml` and `clientCheckTag` produce the same values and snippets as the Python helpers, from the same secret.

## Using the shield directly

```js
const d = shield.check(ip, method, path, query, headers, bodyStart);  // d.action, d.stop, d.hits, d.score, d.retryAfter, d.ref
shield.observe(ip, path, status, d.induced, contentType);
shield.blocklist();   // {network: expiry in Unix seconds}
shield.unblock(ip);
```

## Tests

```bash
npm test        # spec/vectors.json, the middleware on a real server, pattern cost, the examples
```

- **The shared vectors:** every case runs through this port, along with each signature pattern's verdict on texts where regex dialects differ.
- **Pattern cost:** each pattern is timed on the same hostile inputs as the Python suite.
- **The Express example** runs when Express is installed. CI runs it with Express 4 and 5: `npm install --no-save express`.

The signature patterns are not copied by hand. `lib/patterns.json` is `spec/patterns.json`, which is generated from the Python reference's `signatures.py`, and `lib/py.js` translates Python's regex dialect to JavaScript's. After the reference's patterns change, run `npm run sync-patterns`; a test fails until you do.

## Cost

One decision takes about 14 µs on a 4-vCPU cloud container with Node 22: a first-seen visitor, browser headers, a path and a query.

## Limits of this port

- **Scores are per process.** Under `cluster` or several instances, each keeps its own scores and blocks, as with several Python workers.
- **No block file yet.** The Python package can write its blocks to an nginx deny file (`blocklist_export_path`); this port does not. Use `onEvent` to act on `block` events.
- **Mount the middleware first.** A body parser that runs before it consumes the body, and honeytokens in bodies are then not seen.
