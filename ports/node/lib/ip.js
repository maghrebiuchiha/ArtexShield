"use strict";
// IP addresses and networks as Python's ipaddress module reads and writes
// them: strict IPv4 (four decimal octets, no leading zeros), IPv6 with "::",
// an embedded IPv4 tail and an optional %scope, and RFC 5952 text out.

/** {version, value: BigInt, scope} or null when `s` is not an address. */
function parse(s) {
  if (typeof s !== "string") return null;
  const v4 = parseV4(s);
  if (v4 !== null) return { version: 4, value: v4, scope: null };
  return parseV6(s);
}

function parseV4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^[0-9]{1,3}$/.test(part)) return null;
    if (part !== "0" && part[0] === "0") return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

function parseHextet(h) {
  if (!/^[0-9A-Fa-f]{1,4}$/.test(h)) throw new Error("bad hextet");
  return BigInt(parseInt(h, 16));
}

function parseV6(s) {
  let addr = s;
  let scope = null;
  const pct = s.indexOf("%");
  if (pct >= 0) {
    addr = s.slice(0, pct);
    scope = s.slice(pct + 1);
    if (!scope || scope.includes("%")) return null;
  }
  if (!addr) return null;
  const parts = addr.split(":");
  if (parts.length < 3) return null;
  if (parts[parts.length - 1].includes(".")) {
    const v4 = parseV4(parts.pop());
    if (v4 === null) return null;
    parts.push(((v4 >> 16n) & 0xffffn).toString(16), (v4 & 0xffffn).toString(16));
  }
  if (parts.length > 9) return null;
  let skip = null;
  for (let i = 1; i < parts.length - 1; i += 1) {
    if (!parts[i]) {
      if (skip !== null) return null;
      skip = i;
    }
  }
  let hi;
  let lo;
  let skipped;
  if (skip !== null) {
    hi = skip;
    lo = parts.length - skip - 1;
    if (!parts[0]) { hi -= 1; if (hi) return null; }
    if (!parts[parts.length - 1]) { lo -= 1; if (lo) return null; }
    skipped = 8 - (hi + lo);
    if (skipped < 1) return null;
  } else {
    if (parts.length !== 8 || !parts[0] || !parts[parts.length - 1]) return null;
    hi = parts.length;
    lo = 0;
    skipped = 0;
  }
  try {
    let value = 0n;
    for (let i = 0; i < hi; i += 1) value = (value << 16n) | parseHextet(parts[i]);
    value <<= 16n * BigInt(skipped);
    for (let i = parts.length - lo; i < parts.length; i += 1) value = (value << 16n) | parseHextet(parts[i]);
    return { version: 6, value, scope };
  } catch {
    return null;
  }
}

/** The IPv4 address inside ::ffff:a.b.c.d, or the address itself. */
function unmapped(a) {
  if (a.version === 6 && (a.value >> 32n) === 0xffffn) return { version: 4, value: a.value & 0xffffffffn, scope: null };
  return a;
}

function formatV4(value) {
  return [24n, 16n, 8n, 0n].map((shift) => ((value >> shift) & 0xffn).toString()).join(".");
}

function formatV6(value) {
  let hextets = [];
  for (let i = 0; i < 8; i += 1) hextets.push(((value >> BigInt(112 - 16 * i)) & 0xffffn).toString(16));
  let bestStart = -1;
  let bestLen = 0;
  let start = -1;
  let len = 0;
  hextets.forEach((h, i) => {
    if (h === "0") {
      len += 1;
      if (start === -1) start = i;
      if (len > bestLen) { bestLen = len; bestStart = start; }
    } else {
      len = 0;
      start = -1;
    }
  });
  if (bestLen > 1) {
    const end = bestStart + bestLen;
    if (end === hextets.length) hextets.push("");
    hextets.splice(bestStart, bestLen, "");
    if (bestStart === 0) hextets = [""].concat(hextets);
  }
  return hextets.join(":");
}

/** str(address), as Python writes it (an IPv6 scope kept). */
function format(a) {
  if (a.version === 4) return formatV4(a.value);
  return formatV6(a.value) + (a.scope ? "%" + a.scope : "");
}

function bits(version) {
  return version === 4 ? 32 : 128;
}

function maskOf(version, prefix) {
  const all = (1n << BigInt(bits(version))) - 1n;
  return (all << BigInt(bits(version) - prefix)) & all;
}

/** ip_network(text, strict=False): {version, value, prefix}. Throws on nonsense. */
function network(text) {
  if (typeof text !== "string") throw new Error(`not a network: ${text}`);
  const pieces = text.split("/");
  if (pieces.length > 2) throw new Error(`not a network: ${text}`);
  const a = parse(pieces[0]);
  if (a === null) throw new Error(`not a network: ${text}`);
  let prefix = bits(a.version);
  if (pieces.length === 2) prefix = prefixOf(a.version, pieces[1], text);
  return { version: a.version, value: a.value & maskOf(a.version, prefix), prefix };
}

function prefixOf(version, arg, text) {
  if (/^[0-9]+$/.test(arg)) {
    const n = Number(arg);
    if (n > bits(version)) throw new Error(`bad prefix in ${text}`);
    return n;
  }
  if (version === 4) {
    const m = parseV4(arg);                         // a netmask, or a hostmask
    if (m !== null) {
      for (const candidate of [m, m ^ 0xffffffffn]) {
        for (let p = 0; p <= 32; p += 1) if (maskOf(4, p) === candidate) return p;
      }
    }
  }
  throw new Error(`bad prefix in ${text}`);
}

function formatNetwork(n) {
  return (n.version === 4 ? formatV4(n.value) : formatV6(n.value)) + "/" + n.prefix;
}

/** Is `ip` (text) inside any of `nets`? IPv4-mapped IPv6 counts as IPv4. */
function inNets(ip, nets) {
  if (!nets.length) return false;
  const parsed = parse(ip);
  if (parsed === null) return false;
  const a = unmapped(parsed);
  return nets.some((n) => n.version === a.version && (a.value & maskOf(n.version, n.prefix)) === n.value);
}

/** An address that can stand for one client: parseable and not unspecified. */
function usable(ip) {
  const parsed = parse(ip);
  return parsed !== null && unmapped(parsed).value !== 0n;
}

/** One score per client: an IPv4 address, or an IPv6 /64. */
function trackKey(ip) {
  const parsed = parse(ip);
  if (parsed === null) return "invalid";
  const a = unmapped(parsed);
  if (a.version === 4) return formatV4(a.value);
  return formatNetwork({ version: 6, value: a.value & maskOf(6, 64), prefix: 64 });
}

/** /64 -> /56 -> /48 for IPv6 block keys; null otherwise. */
function wider(key) {
  if (!key.includes(":")) return null;
  const n = network(key);
  const step = { 64: 56, 56: 48 }[n.prefix];
  if (!step) return null;
  return formatNetwork({ version: 6, value: n.value & maskOf(6, step), prefix: step });
}

/** The address in one X-Forwarded-For entry, or null. Ports are dropped. */
function hopIp(hop) {
  const { strip } = require("./py");
  let h = strip(hop).replace(/^"+|"+$/g, "");
  if (h.startsWith("[")) {
    const end = h.indexOf("]");
    if (end > 0) h = h.slice(1, end);
  } else if (h.split(":").length === 2) {
    h = h.split(":")[0];
  }
  return parse(h) === null ? null : h;
}

module.exports = { parse, format, network, inNets, usable, trackKey, wider, hopIp, formatNetwork };
