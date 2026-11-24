"use strict";
// Settings, with the defaults and checks of the Python reference's Config.
// Names are camelCase here (throttleScore for throttle_score); SPEC.md has
// what each one means.
const ip = require("./ip");
const py = require("./py");
const { prefixes } = require("./util");

const DEFAULTS = {
  mode: "monitor",
  throttleScore: 50,
  blockScore: 100,
  halfLife: 600,
  blockTtl: 3600,
  maxBlockTtl: 86400,
  retryAfter: 120,
  ignoredThrottlePoints: 5,
  trustedProxies: [],
  allowCidrs: [],
  exemptPaths: [],
  engagements: [],
  canaryPaths: [],
  enum404Threshold: 15,
  enumWindow: 60,
  rateLimit: 240,
  rateWindow: 60,
  cadenceSamples: 30,
  cadenceMinMean: 0.15,
  cadenceMaxMean: 2.0,
  cadenceMaxCv: 0.35,
  tlsHeader: null,
  tlsDenylist: [],
  maxTracks: 50000,
  softCap: null,
  enumIgnorePrefixes: [],
  enumIgnoreExtensions: ["js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "woff",
    "woff2", "ttf", "otf", "eot", "mp3", "mp4", "webm"],
  scoreInduced: false,
  maxBlocks: 100000,
  v6EscalateAfter: 0,
  slowEnumBudget: 60,
  slowEnumWindow: 3600,
  slowEnumPoints: 10,
  clientCheck: false,
  clientCheckSecret: null,
  clientCheckPath: "/_artex/check",
  clientCheckCookie: "artex_check",
  clientCheckApiPrefixes: ["/api"],
  clientCheckGrace: 30,
  clientCheckTtl: 86400,
  clientCheckPoints: 20,
  honeytokens: [],
  honeytokenBodyLimit: 65536,
  // Wiring, not behaviour.
  logger: console,          // anything with .warn(line); null for silence
  onEvent: null,            // called with each event object
};

/** Seconds since the epoch from a Date, an ISO string with a zone, or a number of seconds. */
function seconds(value, what) {
  if (value instanceof Date) return value.getTime() / 1000;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && /(?:Z|[+-]\d\d:?\d\d)$/i.test(value.trim()) && !Number.isNaN(Date.parse(value))) {
    return Date.parse(value) / 1000;
  }
  throw new Error(`engagement ${what} must be a Date, Unix seconds, or an ISO time with a timezone`);
}

function list(value, name) {
  if (value == null) return [];
  if (typeof value === "string") throw new Error(`${name} must be a list, not one string`);
  return Array.from(value);
}

/** A complete, checked config from `options`. Throws on anything the
 * reference refuses, and on names it does not know. */
function makeConfig(options = {}) {
  const unknown = Object.keys(options).filter((k) => !(k in DEFAULTS));
  if (unknown.length) throw new Error(`unknown settings: ${unknown.join(", ")}`);
  const c = { ...DEFAULTS, ...options };
  if (c.mode !== "monitor" && c.mode !== "enforce") throw new Error("mode must be 'monitor' or 'enforce'");
  for (const [name, least] of [["rateLimit", 1], ["cadenceSamples", 2], ["enum404Threshold", 1], ["maxTracks", 1],
    ["maxBlocks", 1], ["v6EscalateAfter", 0], ["slowEnumBudget", 0]]) {
    if (!(c[name] >= least)) throw new Error(`${name} must be at least ${least}`);
  }
  if (c.v6EscalateAfter === 1) throw new Error("v6EscalateAfter must be 0 (off) or at least 2");
  for (const name of ["halfLife", "rateWindow", "enumWindow", "slowEnumWindow", "blockTtl"]) {
    if (!(c[name] > 0)) throw new Error(`${name} must be positive`);
  }
  c.exemptPaths = prefixes(c.exemptPaths, "exemptPaths");
  c.enumIgnorePrefixes = prefixes(c.enumIgnorePrefixes, "enumIgnorePrefixes");
  if (typeof c.honeytokens === "string") {
    throw new Error("honeytokens must be a list of values (or makeHoneytokens(...)), not one string");
  }
  c.honeytokens = [...new Set(Array.from(c.honeytokens || [], String))];
  for (const token of c.honeytokens) {
    if (py.cpLength(token) < 12 || py.hasSpace(token)) {
      throw new Error(`honeytoken ${token.slice(0, 4)}... must be at least 12 characters with no whitespace: ` +
        "anything shorter could turn up in ordinary requests");
    }
  }
  if (!(c.honeytokenBodyLimit >= 0)) throw new Error("honeytokenBodyLimit must not be negative");
  c.clientCheckApiPrefixes = prefixes(c.clientCheckApiPrefixes, "clientCheckApiPrefixes");
  prefixes([c.clientCheckPath], "clientCheckPath");
  if (typeof c.clientCheckCookie !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(c.clientCheckCookie)) {
    throw new Error("clientCheckCookie must be 1 to 64 letters, digits, - or _");
  }
  for (const name of ["clientCheckTtl", "clientCheckPoints"]) {
    if (!(c[name] > 0)) throw new Error(`${name} must be positive`);
  }
  if (!(c.clientCheckGrace >= 0)) throw new Error("clientCheckGrace must not be negative");
  if (!(c.throttleScore > 0 && c.throttleScore <= c.blockScore)) throw new Error("need 0 < throttleScore <= blockScore");
  if (c.softCap == null) c.softCap = 0.8 * c.throttleScore;
  if (!(c.softCap >= 0 && c.softCap < c.throttleScore)) throw new Error("need 0 <= softCap < throttleScore");
  c.trustedProxies = list(c.trustedProxies, "trustedProxies");
  c.allowCidrs = list(c.allowCidrs, "allowCidrs");
  c.canaryPaths = list(c.canaryPaths, "canaryPaths");
  c.tlsDenylist = list(c.tlsDenylist, "tlsDenylist");
  c.enumIgnoreExtensions = list(c.enumIgnoreExtensions, "enumIgnoreExtensions");
  c.engagements = list(c.engagements, "engagements").map((e) => {
    if (!e || typeof e.reference !== "string" || !e.cidrs) throw new Error("an engagement needs reference, cidrs, start and end");
    return { reference: e.reference, cidrs: list(e.cidrs, "cidrs"), start: seconds(e.start, "start"), end: seconds(e.end, "end") };
  });
  return Object.freeze(c);
}

/** Networks from CIDR text; throws on anything that is not one. */
function nets(cidrs) {
  return cidrs.map((c) => ip.network(c));
}

module.exports = { DEFAULTS, makeConfig, nets };
