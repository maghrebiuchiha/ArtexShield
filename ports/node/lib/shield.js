"use strict";
// Per-client scoring, sensors and fire control: a port of the Python
// reference's core.py, held to the same decisions by spec/vectors.json.
const crypto = require("crypto");
const cc = require("./clientCheck");
const ip = require("./ip");
const py = require("./py");
const S = require("./signatures");
const { makeConfig, nets } = require("./config");
const { decode, normPath, prefixes, under, extension, induced: isInduced, stripSqlComments, urlText } = require("./util");

const MISSING_MEMORY = 128;
const BASIC = new RegExp(`^[${py.SPACE}]*basic[${py.SPACE}]+([A-Za-z0-9+/_=-]{4,8192})`, "iu");

class Decision {
  constructor(action, enforced, score, hits, ref, ipAddr, extra = {}) {
    this.action = action;            // "pass" | "throttle" | "block" | "refuse"
    this.enforced = enforced;        // false in monitor mode
    this.score = score;
    this.hits = hits;
    this.ref = ref;                  // incident reference shown to the client
    this.ip = ipAddr;
    this.retryAfter = extra.retryAfter || 0;
    this.friendly = Boolean(extra.friendly);
    this.induced = Boolean(extra.induced);   // a page made the browser send it; pass on to observe()
  }

  /** True when the request must not reach the app. */
  get stop() {
    return this.enforced && this.action !== "pass";
  }
}

/** A queue with a length limit, dropping from the front, like deque(maxlen=n). */
class Ring {
  constructor(max) {
    this.max = max;
    this.items = [];
  }

  push(x) {
    this.items.push(x);
    if (this.items.length > this.max) this.items.shift();
  }

  get length() { return this.items.length; }
}

class Track {
  constructor(now, history, slowBudget) {
    this.hard = 0;
    this.softPoints = 0;
    this.updated = now;
    this.times = new Ring(history);
    this.notFound = new Ring(512);
    this.slow = new Ring(Math.max(slowBudget, 1));
    this.missing = new Map();       // missing paths already counted -> last asked for
    this.soft = new Map();          // soft label -> when it last counted
    this.strikes = 0;
    this.throttledUntil = 0;
    this.pageAt = null;             // first HTML page served (client check)
    this.checkedAt = null;          // last completed client check
    this.automationAt = null;       // last check that reported automation
  }

  get score() { return this.hard + this.softPoints; }
}

/** Header names lower-cased, in the order they came; a Map, an object or [name, value] pairs. */
function headerMap(headers) {
  const h = new Map();
  if (!headers) return h;
  const entries = headers instanceof Map || Array.isArray(headers) ? headers : Object.entries(headers);
  for (const [k, v] of entries) h.set(String(k).toLowerCase(), Array.isArray(v) ? v.join(", ") : String(v));
  return h;
}

function isoSeconds(t) {
  return new Date(Math.floor(t) * 1000).toISOString().replace(/\.\d{3}Z$/, "+00:00");
}

class Shield {
  /** `options`: settings (see config.js). `clock`: returns Unix seconds. */
  constructor(options = {}, clock = () => Date.now() / 1000) {
    this.cfg = makeConfig(options);
    this.clock = clock;
    this.tracks = new Map();
    this.history = Math.max(this.cfg.rateLimit, this.cfg.cadenceSamples);
    this.blocks = new Map();        // network -> expiry
    this.members = new Map();       // wider IPv6 prefix -> Set of blocked networks inside it
    this.wide = 0;
    this.pruned = this.clock();
    this.trusted = nets(this.cfg.trustedProxies);
    this.allowed = nets(this.cfg.allowCidrs);
    this.exempt = this.cfg.exemptPaths;
    this.enumSkip = this.cfg.enumIgnorePrefixes;
    this.enumSkipExt = new Set(this.cfg.enumIgnoreExtensions.map((e) => String(e).toLowerCase().replace(/^\.+/, "")));
    this.canaries = new Set(this.cfg.canaryPaths.map(normPath));
    this.tlsDeny = new Set(this.cfg.tlsDenylist.map((v) => String(v).toLowerCase()));
    this.engagements = this.cfg.engagements.map((e) => ({ ...e, nets: nets(e.cidrs) }));
    const secret = this.cfg.clientCheckSecret;
    this.checkKey = secret ? Buffer.from(String(secret), "utf8") : crypto.randomBytes(32);
    this.checkPath = prefixes([this.cfg.clientCheckPath], "clientCheckPath")[0];
    this.checkApi = this.cfg.clientCheckApiPrefixes;
    this.stats = { requests: 0, throttled: 0, blocked: 0, friendly: 0, unidentified: 0, refused: 0 };
    this.unidentifiedWarned = null;
  }

  // ---- client address --------------------------------------------------------------
  /** X-Forwarded-For is believed only from a trusted proxy. */
  clientIp(remoteAddr, forwardedFor = null) {
    const remote = py.strip(remoteAddr || "") || "0.0.0.0";
    if (forwardedFor && ip.inNets(remote, this.trusted)) {
      const hops = forwardedFor.split(",").map(py.strip).filter(Boolean).reverse();
      for (const hop of hops) {
        const addr = ip.hopIp(hop);
        if (addr === null) break;
        if (!ip.inNets(addr, this.trusted)) return addr;
      }
    }
    return remote;
  }

  identified(addr) {
    return ip.usable(addr) && !ip.inNets(addr, this.trusted);
  }

  // ---- before the app runs ---------------------------------------------------------
  /** Decide on one request. `headers`: object, Map or pairs. `body`: the
   * start of the request body (Buffer), read only for honeytokens. */
  check(clientIp, method, path, query = "", headers = null, body = null) {
    const cfg = this.cfg;
    const now = this.clock();
    const h = headerMap(headers);
    const ua = h.get("user-agent") || "";
    const key = ip.trackKey(clientIp);
    const ref = crypto.randomBytes(4).toString("hex");
    const enforce = cfg.mode === "enforce";
    const npath = normPath(path);
    const exempt = under(path, this.exempt) || ip.inNets(clientIp, this.allowed);
    const induced = !cfg.scoreInduced && isInduced(h);
    const m = S.ASSESSMENT_UA.exec(ua);
    const hits = [];
    query = query || "";

    this.stats.requests += 1;
    if (exempt) return new Decision("pass", enforce, 0, [], ref, clientIp);
    if (!this.identified(clientIp)) {
      this.stats.unidentified += 1;
      const labels = ["config:unidentified-client"];
      if (this.unidentifiedWarned === null || now - this.unidentifiedWarned >= cfg.halfLife) {
        this.unidentifiedWarned = now;
        this.emit("unidentified", clientIp, 0, labels, method, path, ua, ref, enforce);
      }
      return new Decision("pass", enforce, 0, labels, ref, clientIp);
    }
    if (m) {
      const eref = m[1] || "";
      if (this.engagements.some((e) => e.reference === eref && e.start <= now && now < e.end &&
          ip.inNets(clientIp, e.nets))) {
        this.stats.friendly += 1;
        const t = this.track(key, now);
        if (this.softDue(t, "friendly", now)) {
          this.emit("friendly", clientIp, 0, [`iff:engagement=${eref}`], method, path, ua, ref, enforce);
        }
        return new Decision("pass", enforce, 0, [`iff:engagement=${eref}`], ref, clientIp, { friendly: true });
      }
      hits.push(["artex:unverified-assessment-label", 100, false]);
    }
    if (enforce && this.blocked(key, now)) return new Decision("block", enforce, cfg.blockScore, ["blocklist"], ref, clientIp);

    const seen = this.scan(method, npath, query, h, ua);
    if (cfg.honeytokens.length) {
      const where = this.honeytoken(npath, query, h, body);
      if (where) seen.push([`decoy:honeytoken-${where}`, Math.max(100, cfg.blockScore), false]);
    }
    const checked = this.clientRequest(path, h, now);

    if (this.blocked(key, now)) {
      const all = hits.concat(seen);
      const labels = ["blocklist"].concat(all.map(([l]) => l));
      const loud = all.some(([, , soft]) => !soft);
      if (loud || this.softDue(this.track(key, now), "blocked", now)) {
        this.emit("blocked", clientIp, cfg.blockScore, labels, method, path, ua, ref, enforce);
      }
      return new Decision("block", enforce, cfg.blockScore, labels, ref, clientIp);
    }
    if (induced) {
      const labels = hits.concat(seen).filter(([, , soft]) => !soft).map(([l]) => l);
      if (!labels.length) return new Decision("pass", enforce, 0, [], ref, clientIp, { induced: true });
      this.stats.refused += 1;
      this.emit("refuse", clientIp, 0, labels, method, path, ua, ref, enforce);
      return new Decision("refuse", enforce, 0, labels, ref, clientIp, { induced: true });
    }
    const t = this.track(key, now);
    this.decay(t, now);
    hits.push(...this.radar(t, now, seen), ...this.clientHits(t, now, checked));
    t.times.push(now);
    if (enforce && t.throttledUntil > now) hits.push(["behavior:ignored-retry-after", cfg.ignoredThrottlePoints, false]);
    this.add(t, hits);
    return this.engage(t, key, clientIp, now, hits.map(([l]) => l), method, path, ua, ref, enforce);
  }

  // ---- after the app answered ------------------------------------------------------
  /** Feed back the status (and Content-Type) the app answered with. */
  observe(clientIp, path, status, induced = false, contentType = "") {
    const cfg = this.cfg;
    if (cfg.clientCheck && !induced && status >= 200 && status < 300) {
      const type = py.strip((contentType || "").split(";")[0]).toLowerCase();
      if (type === "text/html" || type === "application/xhtml+xml") this.clientPage(clientIp);
    }
    if (status !== 404 || induced) return;
    const now = this.clock();
    const npath = normPath(path);
    if (under(path, this.exempt) || ip.inNets(clientIp, this.allowed)) return;
    const key = ip.trackKey(clientIp);
    const hits = [];
    if (S.RECON_PATHS.test(npath)) hits.push(["recon:probe-404", 25, false]);
    if (S.MISSING_SENSITIVE.test(npath) && !S.SENSITIVE_PATHS.test(npath)) hits.push(["decoy:sensitive-file-probe", 60, false]);
    const guess = !under(path, this.enumSkip) && !this.enumSkipExt.has(extension(npath));
    const t = this.tracks.get(key);
    if (t === undefined || this.blocked(key, now)) return;
    this.decay(t, now);
    if (guess && this.newlyMissing(t, npath, now)) {
      t.notFound.push(now);
      if (cfg.slowEnumBudget) {
        if (t.slow.length === t.slow.max && now - t.slow.items[0] <= cfg.slowEnumWindow) {
          hits.push(["behavior:slow-enumeration", cfg.slowEnumPoints, false]);
        }
        t.slow.push(now);
      }
    }
    while (t.notFound.length && now - t.notFound.items[0] > cfg.enumWindow) t.notFound.items.shift();
    if (t.notFound.length >= cfg.enum404Threshold) {
      hits.push(["behavior:path-enumeration", 40, false]);
      t.notFound.items.length = 0;
    }
    if (!hits.length) return;
    this.add(t, hits);
    const labels = hits.map(([l]) => l);
    const score = t.score;
    if (score >= cfg.blockScore) {
      this.block(t, key, now);
      this.emit("block", clientIp, score, labels, "-", path, "", "-", cfg.mode === "enforce");
    } else {
      this.emit("score", clientIp, t.score, labels, "-", path, "", "-", cfg.mode === "enforce");
    }
  }

  newlyMissing(t, npath, now) {
    const last = t.missing.get(npath);
    t.missing.delete(npath);
    t.missing.set(npath, now);
    while (t.missing.size > MISSING_MEMORY) t.missing.delete(t.missing.keys().next().value);
    return last === undefined || now - last > this.cfg.halfLife;
  }

  // ---- honeytokens -----------------------------------------------------------------
  honeytoken(npath, query, h, body) {
    const tokens = this.cfg.honeytokens;
    const has = (text) => {
      if (!text) return false;
      if (tokens.some((t) => text.includes(t))) return true;
      const decoded = decode(text);
      return decoded !== text && tokens.some((t) => decoded.includes(t));
    };
    for (const [name, raw] of h) {
      if (name === "referer") continue;
      const value = py.cpSlice(raw, 16384);
      if (has(value)) return name === "cookie" ? "cookie" : "header";
      if (name === "authorization" || name === "proxy-authorization") {
        const m = BASIC.exec(value);
        if (m) {
          const b64 = /[-_]/.test(m[1]) ? m[1].replace(/-/g, "+").replace(/_/g, "/") : m[1];
          let decoded = "";
          try {
            decoded = py.b64decode(b64 + "===").toString("latin1");
          } catch (e) {
            decoded = "";
          }
          if (has(decoded)) return "header";
        }
      }
    }
    if (has(py.cpSlice(query, 65536))) return "query";
    if (has(npath)) return "path";
    const limit = this.cfg.honeytokenBodyLimit;
    if (body && body.length && limit && has(Buffer.from(body).subarray(0, limit).toString("latin1"))) return "body";
    return null;
  }

  // ---- client check (optional) -------------------------------------------------------
  /** Answer the check script's call: {status, headers: [[name, value]], body}. */
  clientCheckReply(clientIp, query, headers = null, secure = false) {
    const now = this.clock();
    const params = new Map();
    for (const p of (query || "").split("&")) {
      if (!p) continue;
      const eq = p.indexOf("=");
      params.set(eq < 0 ? p : p.slice(0, eq), eq < 0 ? "" : p.slice(eq + 1));
    }
    const f = params.get("f") || "";
    const flags = py.isAsciiDigits(f) && f.length < 6 ? Number(f) & cc.FLAGS : 0;
    if (this.identified(clientIp)) {
      const t = this.track(ip.trackKey(clientIp), now);
      t.checkedAt = now;
      if (flags) t.automationAt = now;
    }
    const value = cc.sign(this.checkKey, Math.floor(now), flags);
    const attrs = `Path=/; Max-Age=${Math.trunc(this.cfg.clientCheckTtl)}; HttpOnly; SameSite=Lax`;
    return {
      status: 204,
      headers: [["Set-Cookie", `${this.cfg.clientCheckCookie}=${value}; ${attrs}` + (secure ? "; Secure" : "")],
        ["Cache-Control", "no-store"], ["Content-Length", "0"]],
      body: Buffer.alloc(0),
    };
  }

  /** The check script itself, served at clientCheckPath + ".js". */
  clientCheckAsset() {
    const body = Buffer.from(cc.script(this.checkPath), "utf8");
    return {
      status: 200,
      headers: [["Content-Type", "text/javascript; charset=utf-8"], ["Content-Length", String(body.length)],
        ["Cache-Control", "public, max-age=3600"], ["X-Content-Type-Options", "nosniff"]],
      body,
    };
  }

  /** "check" or "script" for the client check's own endpoints, when it is on; else null. */
  clientCheckRoute(path) {
    if (!this.cfg.clientCheck) return null;
    const npath = normPath(path);
    return npath === this.checkPath ? "check" : npath === this.checkPath + ".js" ? "script" : null;
  }

  clientPage(clientIp) {
    if (!this.identified(clientIp)) return;
    const t = this.tracks.get(ip.trackKey(clientIp));
    if (t !== undefined && t.pageAt === null) t.pageAt = this.clock();
  }

  clientRequest(path, h, now) {
    if (!this.cfg.clientCheck || !under(path, this.checkApi) || !cc.scriptMade(h)) return null;
    const flags = cc.verify(this.checkKey, cc.cookie(h.get("cookie") || "", this.cfg.clientCheckCookie), now,
      this.cfg.clientCheckTtl);
    return [flags !== null, flags || 0];
  }

  clientHits(t, now, checked) {
    if (checked === null) return [];
    const cfg = this.cfg;
    const [valid, flags] = checked;
    const hits = [];
    const reported = flags || (t.automationAt !== null && now - t.automationAt < cfg.clientCheckTtl);
    if (reported && this.softDue(t, "client:automation-reported", now)) {
      hits.push(["client:automation-reported", cfg.clientCheckPoints, true]);
    }
    if (!valid && t.checkedAt === null && t.pageAt !== null && now - t.pageAt >= cfg.clientCheckGrace &&
        this.softDue(t, "client:no-check", now)) {
      hits.push(["client:no-check", cfg.clientCheckPoints, true]);
    }
    return hits;
  }

  // ---- sensors -----------------------------------------------------------------------
  scan(method, npath, query, h, ua) {
    const cfg = this.cfg;
    const hits = [];
    if (this.canaries.has(npath)) hits.push(["decoy:canary-path", 100, false]);
    else if (S.SENSITIVE_PATHS.test(npath)) hits.push(["decoy:sensitive-file-probe", 60, false]);

    const hard = S.HARD_UA.find(([rx]) => rx.test(ua));
    if (hard) {
      hits.push([hard[2], hard[1], false]);
    } else {
      for (const [rx, points, label] of S.SOFT_UA) if (rx.test(ua)) hits.push([label, points, true]);
      if (!py.strip(ua)) hits.push(["ua:empty", 20, true]);
      if (S.BROWSER_UA.test(ua) && !S.CRAWLER_UA.test(ua) && !h.get("accept-language")) {
        hits.push(["shape:browser-ua-without-browser-headers", 20, true]);
      }
    }
    const verb = method.toUpperCase();
    if (S.ODD_METHODS.has(verb) || S.SOFT_METHODS.has(verb)) hits.push([`method:${verb}`, 30, S.SOFT_METHODS.has(verb)]);

    const target = urlText(npath, query);
    const plain = stripSqlComments(target);
    const found = [];
    for (const [rx, label] of S.PAYLOADS.concat(S.OOB)) {
      if (rx.test(target) || (plain !== null && rx.test(plain))) found.push(label);
    }
    const headBlob = decode(Array.from(h.values()).join(" "));
    for (const [rx, label] of S.OOB) if (!found.includes(label) && rx.test(headBlob)) found.push(label);
    for (const label of found) hits.push([label, 50, false]);

    if (cfg.tlsHeader && this.tlsDeny.size) {
      const fp = (h.get(cfg.tlsHeader.toLowerCase()) || "").toLowerCase();
      if (fp && this.tlsDeny.has(fp)) hits.push(["tls:denylisted-fingerprint", 40, true]);
    }
    return hits;
  }

  radar(t, now, seen) {
    const cfg = this.cfg;
    const hits = seen.filter((hit) => !hit[2] || this.softDue(t, hit[0], now));
    const recent = t.times.items.filter((x) => now - x <= cfg.rateWindow).length;
    if (recent + 1 > cfg.rateLimit) {
      hits.push(["behavior:request-flood", 30, false]);
      t.times.items.length = 0;
    } else if (t.times.length >= cfg.cadenceSamples) {
      const seq = t.times.items.slice(-cfg.cadenceSamples).concat([now]);
      const gaps = [];
      for (let i = 1; i < seq.length; i += 1) gaps.push(seq[i] - seq[i - 1]);
      const mean = py.fsum(gaps) / gaps.length;
      if (cfg.cadenceMinMean <= mean && mean <= cfg.cadenceMaxMean) {
        const devs = gaps.map((g) => g - mean);
        const ss = py.fsum(devs.map((d) => d * d)) - py.fsum(devs) ** 2 / gaps.length;
        const cv = Math.sqrt(Math.max(ss, 0) / gaps.length) / mean;
        if (cv <= cfg.cadenceMaxCv && this.softDue(t, "behavior:metronomic-cadence", now)) {
          hits.push(["behavior:metronomic-cadence", 20, true]);
        }
      }
    }
    return hits;
  }

  add(t, hits) {
    for (const [, points, soft] of hits) {
      if (soft) t.softPoints = Math.min(this.cfg.softCap, t.softPoints + points);
      else t.hard += points;
    }
  }

  // ---- fire control ------------------------------------------------------------------
  engage(t, key, clientIp, now, labels, method, path, ua, ref, enforce) {
    const cfg = this.cfg;
    const score = t.score;
    if (score >= cfg.blockScore) {
      this.block(t, key, now);
      this.emit("block", clientIp, score, labels, method, path, ua, ref, enforce);
      return new Decision("block", enforce, score, labels, ref, clientIp);
    }
    if (score >= cfg.throttleScore) {
      const decay = cfg.halfLife * Math.log2(score / cfg.throttleScore);
      const wait = Math.max(cfg.retryAfter, Math.ceil(decay) + 1);
      t.throttledUntil = now + wait;
      this.stats.throttled += 1;
      this.emit("throttle", clientIp, score, labels, method, path, ua, ref, enforce);
      return new Decision("throttle", enforce, score, labels, ref, clientIp, { retryAfter: wait });
    }
    t.throttledUntil = 0;
    if (labels.length) this.emit("score", clientIp, t.score, labels, method, path, ua, ref, enforce);
    return new Decision("pass", enforce, t.score, labels, ref, clientIp);
  }

  block(t, key, now) {
    t.strikes += 1;
    this.stats.blocked += 1;
    const ttl = Math.min(this.cfg.blockTtl * 2 ** (t.strikes - 1), this.cfg.maxBlockTtl);
    if (now - this.pruned >= 60 || this.blocks.size >= this.cfg.maxBlocks) this.pruneBlocks(now);
    this.setBlock(key, now + ttl);
    t.hard = 0;
    t.softPoints = 0;
    t.throttledUntil = 0;
    t.notFound.items.length = 0;
    this.escalate(key, now);
  }

  escalate(key, now) {
    const need = this.cfg.v6EscalateAfter;
    let parent = ip.wider(key);
    while (need && parent && (this.members.get(parent) || new Set()).size >= need) {
      for (const inside of Array.from(this.members.get(parent))) this.dropBlock(inside);
      this.setBlock(parent, now + this.cfg.blockTtl);
      this.emit("block", parent, this.cfg.blockScore, ["behavior:network-rotation"], "-", "-", "", "-",
        this.cfg.mode === "enforce");
      parent = ip.wider(parent);
    }
  }

  setBlock(key, until) {
    if (!this.blocks.has(key)) {
      const parent = ip.wider(key);
      if (parent) {
        if (!this.members.has(parent)) this.members.set(parent, new Set());
        this.members.get(parent).add(key);
      }
      if (!key.endsWith("/64") && key.includes(":")) this.wide += 1;
    }
    this.blocks.set(key, until);
  }

  dropBlock(key) {
    if (!this.blocks.has(key)) return false;
    this.blocks.delete(key);
    const parent = ip.wider(key);
    const inside = parent ? this.members.get(parent) : undefined;
    if (inside !== undefined) {
      inside.delete(key);
      if (!inside.size) this.members.delete(parent);
    }
    if (!key.endsWith("/64") && key.includes(":")) this.wide -= 1;
    return true;
  }

  pruneBlocks(now) {
    this.pruned = now;
    for (const [key, until] of Array.from(this.blocks)) if (until <= now) this.dropBlock(key);
    const over = this.blocks.size - this.cfg.maxBlocks + 1;
    if (over > 0) {
      const nearest = Array.from(this.blocks).sort((a, b) => a[1] - b[1]);
      for (const [key] of nearest.slice(0, Math.max(over, Math.floor(this.cfg.maxBlocks / 10)))) this.dropBlock(key);
    }
  }

  // ---- command post --------------------------------------------------------------------
  /** Active blocks: {network: expiry in Unix seconds}. */
  blocklist() {
    const now = this.clock();
    for (const [key, until] of Array.from(this.blocks)) if (until <= now) this.dropBlock(key);
    return Object.fromEntries(this.blocks);
  }

  /** Lift the block on `addr`, including a wider IPv6 prefix that covers it. */
  unblock(addr) {
    const key = ip.trackKey(addr);
    this.tracks.delete(key);
    return this.covering(key, true).filter((k) => this.dropBlock(k)).length > 0;
  }

  emit(action, clientIp, score, labels, method, path, ua, ref, enforced) {
    const { logger, onEvent } = this.cfg;
    if (!logger && !onEvent) return;
    const event = {
      ts: isoSeconds(this.clock()), action, enforced, ip: clientIp, score: Math.round(score * 10) / 10, hits: labels,
      method, path: py.cpSlice(path, 512), ua: py.cpSlice(ua, 256), ref,
    };
    if (logger) logger.warn(JSON.stringify(event));
    if (onEvent) {
      try {
        onEvent(event);
      } catch (e) {
        if (logger) logger.warn(`artex-shield: onEvent callback failed: ${e && e.stack ? e.stack : e}`);
      }
    }
  }

  // ---- tracking ------------------------------------------------------------------------
  track(key, now) {
    let t = this.tracks.get(key);
    if (t === undefined) {
      t = new Track(now, this.history, this.cfg.slowEnumBudget);
      this.tracks.set(key, t);
      while (this.tracks.size > this.cfg.maxTracks) this.tracks.delete(this.tracks.keys().next().value);
    } else {
      this.tracks.delete(key);
      this.tracks.set(key, t);
    }
    return t;
  }

  covering(key, wide = false) {
    const keys = [key];
    if (key.includes(":") && (wide || this.wide)) {
      for (let k = ip.wider(key); k; k = ip.wider(k)) keys.push(k);
    }
    return keys;
  }

  blocked(key, now) {
    for (const k of this.covering(key)) {
      const until = this.blocks.get(k);
      if (until === undefined) continue;
      if (until > now) return true;
      this.dropBlock(k);
    }
    return false;
  }

  decay(t, now) {
    const dt = now - t.updated;
    if (dt > 0) {
      const factor = 0.5 ** (dt / this.cfg.halfLife);
      t.hard *= factor;
      t.softPoints *= factor;
      if (t.score < 0.5) {
        t.hard = 0;
        t.softPoints = 0;
      }
    }
    t.updated = now;
  }

  softDue(t, label, now) {
    const last = t.soft.get(label);
    if (last !== undefined && now - last < this.cfg.halfLife) return false;
    t.soft.set(label, now);
    return true;
  }
}

module.exports = { Shield, Decision, headerMap };
