"use strict";
// Express / Connect middleware, a wrapper for plain `http` handlers, and a
// guard for WebSocket upgrades. Each reads the request the way
// artex-shield-proxy does, so all three decide alike.
const { strip } = require("./py");
const { unquote } = require("./py");

/** Lower-case header names in arrival order; repeats joined (cookies with "; "). */
function rawHeaderMap(rawHeaders) {
  const h = new Map();
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const k = rawHeaders[i].toLowerCase();
    const v = rawHeaders[i + 1];
    h.set(k, h.has(k) ? h.get(k) + (k === "cookie" ? "; " : ", ") + v : v);
  }
  return h;
}

/** {path, query}: the path percent-decoded (UTF-8), the query as sent. */
function splitTarget(target) {
  let raw = target || "/";
  if (/^https?:\/\//i.test(raw)) {
    const rest = raw.replace(/^https?:\/\/[^/?#]*/i, "");
    raw = rest.startsWith("/") ? rest : "/" + rest;
  }
  raw = raw.split("#")[0];
  const q = raw.indexOf("?");
  const path = q < 0 ? raw : raw.slice(0, q);
  return { path: unquote(path), query: q < 0 ? "" : raw.slice(q + 1) };
}

function requestFacts(shield, req) {
  const peer = (req.socket && req.socket.remoteAddress) || "";
  const headers = rawHeaderMap(req.rawHeaders || []);
  const { path, query } = splitTarget(req.originalUrl || req.url);
  return { peer, headers, path, query, ip: shield.clientIp(peer, headers.get("x-forwarded-for") || null) };
}

/** The status line, headers and body a stopped request gets. */
function reply(d) {
  if (d.action === "block" || d.action === "refuse") {
    const body = Buffer.from(`Request ${d.action === "block" ? "blocked" : "refused"}. Reference: ${d.ref}\n`);
    return { status: 403, reason: "Forbidden", body, headers: [["Content-Type", "text/plain; charset=utf-8"],
      ["Content-Length", String(body.length)], ["Cache-Control", "no-store"]] };
  }
  const body = Buffer.from(`Too many requests. Reference: ${d.ref}\n`);
  return { status: 429, reason: "Too Many Requests", body, headers: [["Content-Type", "text/plain; charset=utf-8"],
    ["Content-Length", String(body.length)], ["Retry-After", String(d.retryAfter)], ["Cache-Control", "no-store"]] };
}

function send(res, status, headers, body) {
  for (const [k, v] of headers) res.setHeader(k, v);
  res.statusCode = status;
  res.end(body);
}

/** Did the visitor use HTTPS? Behind your own proxy, believe its X-Forwarded-Proto. */
function https(shield, req, peer, headers) {
  if (req.socket && req.socket.encrypted) return true;
  const proto = strip((headers.get("x-forwarded-proto") || "").split(",")[0]).toLowerCase();
  return proto === "https" && shield.trusted.length > 0 && require("./ip").inNets(peer, shield.trusted);
}

/** Has the request a body to read? */
function hasBody(headers) {
  const length = strip(headers.get("content-length") || "");
  return (length !== "" && length !== "0") || headers.has("transfer-encoding");
}

/** Read the start of the body (up to `limit` bytes) for the honeytoken check
 * and leave the stream as it was, so the app and its body parsers read the
 * whole body as sent. Resolves with what was read.
 *
 * The stream's own events cannot be used for this: a "readable" listener
 * reads ahead by itself and, on a short body, ends the stream before the
 * app is listening. So what is already buffered is taken out exactly
 * (which never ends a stream), and what arrives next is caught at push(),
 * where the HTTP parser hands it over. When enough has arrived, all of it
 * goes back in order, followed by the end if that came too. */
function readAhead(req, limit) {
  return new Promise((resolve, reject) => {
    const held = [];
    let size = 0;
    let settled = false;
    const ended = req.complete;                     // the end is in the stream already
    if (req.readableLength > 0) {
      const chunk = req.read(req.readableLength);
      if (chunk) { held.push(chunk); size += chunk.length; }
    }
    const own = Object.prototype.hasOwnProperty.call(req, "push") ? req.push : null;
    const push = req.push;
    const restore = () => {
      if (own) req.push = own; else delete req.push;
      req.removeListener("aborted", onAbort);
      req.removeListener("error", onAbort);
    };
    const finish = (eof) => {
      settled = true;
      restore();
      const all = Buffer.concat(held);
      let more = true;
      if (ended) {
        if (all.length) req.unshift(all);
      } else {
        if (all.length) more = push.call(req, all);
        if (eof) push.call(req, null);
      }
      resolve(all.subarray(0, limit));
      return more;
    };
    function onAbort(err) {
      if (settled) return;
      settled = true;
      restore();
      reject(err instanceof Error ? err : new Error("request aborted"));
    }
    if (ended || size >= limit) return finish(false);
    req.once("aborted", onAbort);
    req.once("error", onAbort);
    req.push = function (chunk, encoding) {
      if (settled) return push.call(req, chunk, encoding);
      if (chunk === null) return finish(true) && false;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
      held.push(buf);
      size += buf.length;
      return size >= limit ? finish(false) : true;
    };
    return undefined;
  });
}

/** Call `fn(status, contentType)` when the response's head is written. */
function watch(res, fn) {
  const writeHead = res.writeHead;
  let seen = false;
  res.writeHead = function (statusCode, ...rest) {
    if (!seen) {
      seen = true;
      let type = "";
      const given = rest.find((x) => x && typeof x === "object");
      if (Array.isArray(given)) {
        const flat = given.length && Array.isArray(given[0]) ? given.flat() : given;
        for (let i = 0; i + 1 < flat.length; i += 2) if (String(flat[i]).toLowerCase() === "content-type") type = String(flat[i + 1]);
      } else if (given) {
        for (const [k, v] of Object.entries(given)) if (k.toLowerCase() === "content-type") type = String(v);
      }
      if (!type) type = String(res.getHeader("content-type") || "");
      try {
        fn(Number(statusCode), type);
      } catch (e) {
        if (console && console.error) console.error("artex-shield: observe failed", e);
      }
    }
    return writeHead.call(this, statusCode, ...rest);
  };
}

/** The shield as Express / Connect middleware: app.use(artexShield(shield)). Mount it first. */
function artexShield(shield) {
  return function artexShieldMiddleware(req, res, next) {
    const facts = requestFacts(shield, req);
    const { headers, path, query, ip, peer } = facts;
    const limit = shield.cfg.honeytokenBodyLimit;
    const reading = shield.cfg.honeytokens.length && limit && hasBody(headers) ? readAhead(req, limit) : null;
    const decide = (body) => {
      const d = shield.check(ip, req.method, path, query, headers, body);
      if (d.stop) {
        const r = reply(d);
        return send(res, r.status, r.headers, r.body);
      }
      const route = shield.clientCheckRoute(path);
      if (route) {
        const r = route === "script" ? shield.clientCheckAsset()
          : shield.clientCheckReply(ip, query, headers, https(shield, req, peer, headers));
        return send(res, r.status, r.headers, r.body);
      }
      watch(res, (status, type) => shield.observe(ip, path, status, d.induced, type));
      return next();
    };
    if (reading === null) return decide(null);
    return reading.then(decide, () => {
      if (!res.headersSent) send(res, 400, [["Content-Type", "text/plain; charset=utf-8"]], "Bad request\n");
    });
  };
}

/** Wrap a plain request handler: http.createServer(handler(shield, app)). */
function handler(shield, app) {
  const mw = artexShield(shield);
  return function artexShieldHandler(req, res) {
    return mw(req, res, () => app(req, res));
  };
}

/** For server.on("upgrade"): checks a WebSocket handshake like any request.
 * Returns true to go ahead; otherwise it has answered and closed the socket.
 *
 *   server.on("upgrade", (req, socket, head) => {
 *     if (guard(req, socket)) wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
 *   });
 */
function upgradeGuard(shield) {
  return function artexShieldUpgrade(req, socket) {
    const { headers, path, query, ip } = requestFacts(shield, req);
    const d = shield.check(ip, req.method, path, query, headers, null);
    if (!d.stop) return true;
    const r = reply(d);
    const head = r.headers.map(([k, v]) => `${k}: ${v}\r\n`).join("");
    socket.end(`HTTP/1.1 ${r.status} ${r.reason}\r\n${head}Connection: close\r\n\r\n` + r.body.toString());
    return false;
  };
}

module.exports = { artexShield, handler, upgradeGuard, reply, splitTarget, rawHeaderMap, readAhead };
