"use strict";
// What the Python reference does with text, done the same way in JavaScript:
// its regular expressions, whitespace, slicing by code point, URL decoding,
// urlsplit's netloc, base64 decoding and math.fsum. The shield's decisions
// depend on each of these down to the edge cases, and spec/vectors.json checks them.

// ---- character classes ----------------------------------------------------------
// Python's \s for str patterns (str.isspace) and \w (str.isalnum or "_"), as JS
// Unicode classes. They agree on every code point Python's Unicode tables know.
const SPACE = "\\t\\n\\v\\f\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const WORD = "\\p{L}\\p{N}_";
const SPACE_RX = new RegExp(`[${SPACE}]`, "u");
const STRIP_RX = new RegExp(`^[${SPACE}]+|[${SPACE}]+$`, "gu");

// ---- Python re -> JS RegExp ---------------------------------------------------------
const SYNTAX = new Set("^$\\.*+?()[]{}|/");

/** Translate a Python `re` pattern into a JS RegExp source with the same
 * meaning under the "u" flag: Unicode \w \s \d \b, Python's `$` (end, or
 * before a final newline), `.` that only refuses "\n", \A, (?P<name>) and
 * (?P=name). With `ignoreCase`, also Python's one case equivalence that
 * Unicode case folding lacks: i, I, dotless ı and dotted İ all match each
 * other. Covers what signatures.py uses; anything else throws rather than
 * being guessed at. */
function translate(src, ignoreCase = false) {
  let out = "";
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === "\\") {
      const [piece, next] = escape(src, i, false);
      out += piece;
      i = next;
      continue;
    }
    if (c === "[") {
      const [piece, next] = charClass(src, i, ignoreCase);
      out += piece;
      i = next;
      continue;
    }
    if (c === "(" && src.startsWith("(?P<", i)) {
      out += "(?<";
      i += 4;
      continue;
    }
    if (c === "(" && src.startsWith("(?P=", i)) {
      const end = src.indexOf(")", i);
      out += `\\k<${src.slice(i + 4, end)}>`;
      i = end + 1;
      continue;
    }
    if (ignoreCase && (c === "i" || c === "I")) out += "[iI\\u0131\\u0130]";
    else if (c === ".") out += "[^\\n]";
    else if (c === "$") out += "(?=\\n?$)";
    else out += c;
    i += 1;
  }
  return out;
}

/** One escape at src[i]. Inside a class, returns the class items; a negated
 * class escape (\S \W \D) comes back as {negated: "..."} for charClass. */
function escape(src, i, inClass) {
  const n = src[i + 1];
  const next = i + 2;
  if (n === undefined) throw new Error("pattern ends in a backslash");
  if (n === "w") return [inClass ? WORD : `[${WORD}]`, next];
  if (n === "s") return [inClass ? SPACE : `[${SPACE}]`, next];
  if (n === "d") return ["\\p{Nd}", next];
  if (n === "W") return [inClass ? { negated: WORD } : `[^${WORD}]`, next];
  if (n === "S") return [inClass ? { negated: SPACE } : `[^${SPACE}]`, next];
  if (n === "D") return [inClass ? { negated: "\\p{Nd}" } : "\\P{Nd}", next];
  if (n === "b") return [inClass ? "\\x08" : `(?:(?<=[${WORD}])(?![${WORD}])|(?<![${WORD}])(?=[${WORD}]))`, next];
  if (inClass && (n === "A" || n === "Z" || n === "B")) throw new Error(`\\${n} inside a character class`);
  if (n === "B") return [`(?:(?<=[${WORD}])(?=[${WORD}])|(?<![${WORD}])(?![${WORD}]))`, next];
  if (n === "A") return ["^", next];
  if (n === "Z") return ["$", next];
  if (n === "x") return ["\\x" + src.slice(next, next + 2), next + 2];
  if (n === "u") return ["\\u" + src.slice(next, next + 4), next + 4];
  if ("nrtfv".includes(n)) return ["\\" + n, next];
  if (/[0-9]/.test(n)) throw new Error("numbered escapes are not supported");
  if (SYNTAX.has(n)) return ["\\" + n, next];
  if (n === "-") return [inClass ? "\\-" : "-", next];
  return [n, next];                                    // an identity escape such as \" or \'
}

/** A character class from src[i] ("["). One that holds \S, \W or \D cannot
 * be written as a single JS class in "u" mode, so it becomes an alternation. */
function charClass(src, i, ignoreCase) {
  let j = i + 1;
  let negate = false;
  if (src[j] === "^") { negate = true; j += 1; }
  let items = "";
  const negatedParts = [];
  let first = true;
  while (j < src.length) {
    const c = src[j];
    if (c === "]" && !first) break;
    first = false;
    if (c === "\\") {
      const [piece, next] = escape(src, j, true);
      if (typeof piece === "object") negatedParts.push(piece.negated);
      else items += piece;
      j = next;
      continue;
    }
    items += c === "[" || c === "]" ? "\\" + c : c;
    j += 1;
  }
  if (src[j] !== "]") throw new Error("unterminated character class");
  if (ignoreCase && items && new RegExp(`[${items}]`, "iu").test("i")) {
    if (/(^|[^\\])-$/.test(items)) items = items.slice(0, -1) + "\\-";     // a final "-" is literal; keep it so
    items += "\\u0131\\u0130";
  }
  if (!negatedParts.length) return [`[${negate ? "^" : ""}${items}]`, j + 1];
  if (negate) throw new Error("a negated class holding \\S, \\W or \\D is not supported");
  const alternatives = (items ? [`[${items}]`] : []).concat(negatedParts.map((p) => `[^${p}]`));
  return [`(?:${alternatives.join("|")})`, j + 1];
}

/** A Python pattern compiled for JS. `ignoreCase` as re.IGNORECASE. */
function compile(src, ignoreCase = true) {
  return new RegExp(translate(src, ignoreCase), ignoreCase ? "iu" : "u");
}

// ---- strings ----------------------------------------------------------------------
/** str.strip() with no argument. */
function strip(s) {
  return s.replace(STRIP_RX, "");
}

/** str.isspace() for any character of `s`. */
function hasSpace(s) {
  return SPACE_RX.test(s);
}

/** len(s): code points, not UTF-16 units. */
function cpLength(s) {
  let n = 0;
  for (const _ of s) n += 1;           // eslint-disable-line no-unused-vars
  return n;
}

/** s[:n] by code point. */
function cpSlice(s, n) {
  if (s.length <= n) return s;          // n UTF-16 units hold at most n code points
  let count = 0;
  let i = 0;
  for (const ch of s) {
    if (count === n) break;
    count += 1;
    i += ch.length;
  }
  return s.slice(0, i);
}

/** str.isdigit() for ASCII-only inputs; other digits count as not digits. */
function isAsciiDigits(s) {
  return /^[0-9]+$/.test(s);
}

/** json.dumps(str) with ensure_ascii, as Python writes it. */
function jsonString(s) {
  return JSON.stringify(s).replace(/[\u007f-￿]/g, (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
}

// ---- urllib.parse -------------------------------------------------------------------
const HEX = /^[0-9A-Fa-f]{2}$/;
const utf8 = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

/** urllib.parse.unquote(s): %XX runs inside each stretch of ASCII text are
 * bytes decoded as UTF-8, with U+FFFD for what is not; other text is kept. */
function unquote(s) {
  if (!s.includes("%")) return s;
  let out = "";
  let i = 0;
  while (i < s.length) {
    let j = i;
    while (j < s.length && s.charCodeAt(j) < 0x80) j += 1;
    if (j > i) {
      const run = s.slice(i, j);
      out += run.includes("%") ? asciiRun(run) : run;
    }
    let k = j;
    while (k < s.length && s.charCodeAt(k) >= 0x80) k += 1;
    out += s.slice(j, k);
    i = k;
  }
  return out;
}

function asciiRun(run) {
  const bytes = [];
  for (let i = 0; i < run.length; i += 1) {
    if (run[i] === "%" && HEX.test(run.slice(i + 1, i + 3))) {
      bytes.push(parseInt(run.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(run.charCodeAt(i));
    }
  }
  return utf8.decode(Uint8Array.from(bytes));
}

/** urllib.parse.unquote_plus(s). */
function unquotePlus(s) {
  return unquote(s.replace(/\+/g, " "));
}

const SCHEME_CHARS = /^[A-Za-z0-9+\-.]+$/;
const C0_OR_SPACE = /^[\x00-\x20]+/;

/** urllib.parse.urlsplit(url).netloc, raising (throwing) where it does. */
function netloc(url) {
  url = url.replace(C0_OR_SPACE, "").replace(/[\t\r\n]/g, "");
  const i = url.indexOf(":");
  if (i > 0 && /^[A-Za-z]$/.test(url[0]) && SCHEME_CHARS.test(url.slice(0, i))) url = url.slice(i + 1);
  if (url.slice(0, 2) !== "//") return "";
  let end = url.length;
  for (const c of "/?#") {
    const at = url.indexOf(c, 2);
    if (at >= 0) end = Math.min(end, at);
  }
  const net = url.slice(2, end);
  if ((net.includes("[") && !net.includes("]")) || (net.includes("]") && !net.includes("["))) {
    throw new Error("Invalid IPv6 URL");
  }
  if (net.includes("[") && net.includes("]")) {
    const after = net.slice(net.indexOf("[") + 1);               // netloc.partition('[')[2].partition(']')[0]
    checkBracketedHost(after.includes("]") ? after.slice(0, after.indexOf("]")) : after);
  }
  checkNetloc(net);
  return net;
}

function checkBracketedHost(host) {
  const ip = require("./ip");
  if (host.startsWith("v")) {
    if (!/^v[a-fA-F0-9]+\.[^\n]+$/.test(host)) throw new Error("IPvFuture address is invalid");
    return;
  }
  const parsed = ip.parse(host);
  if (parsed === null) throw new Error("not an IP address");
  if (parsed.version === 4) throw new Error("An IPv4 address cannot be in brackets");
}

function checkNetloc(net) {
  if (!net || /^[\x00-\x7f]*$/.test(net)) return;
  const n = net.replace(/[@:#?]/g, "");
  const normal = n.normalize("NFKC");
  if (n === normal) return;
  for (const c of "/?#@:") {
    if (normal.includes(c)) throw new Error("netloc contains invalid characters under NFKC normalization");
  }
}

// ---- base64.b64decode, non-strict --------------------------------------------------
const B64 = new Map([..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"].map((c, i) => [c, i]));

/** base64.b64decode(s) as binascii does it without validation: characters
 * outside the alphabet are skipped, enough padding ends the input, and an
 * impossible length throws. */
function b64decode(s) {
  const out = [];
  let quad = 0;
  let left = 0;
  let pads = 0;
  for (const ch of s) {
    if (ch === "=") {
      if (quad >= 2 && quad + ++pads >= 4) return Buffer.from(out);
      continue;
    }
    const v = B64.get(ch);
    if (v === undefined) continue;
    pads = 0;
    if (quad === 0) { quad = 1; left = v; }
    else if (quad === 1) { quad = 2; out.push(((left << 2) | (v >> 4)) & 0xff); left = v & 0x0f; }
    else if (quad === 2) { quad = 3; out.push(((left << 4) | (v >> 2)) & 0xff); left = v & 0x03; }
    else { quad = 0; out.push(((left << 6) | v) & 0xff); left = 0; }
  }
  if (quad !== 0) throw new Error(quad === 1 ? "invalid base64 length" : "Incorrect padding");
  return Buffer.from(out);
}

// ---- math.fsum ----------------------------------------------------------------------
/** The correctly rounded sum of `xs` (finite values), as math.fsum. */
function fsum(xs) {
  const p = [];
  for (let x of xs) {
    let i = 0;
    for (let j = 0; j < p.length; j += 1) {
      let y = p[j];
      if (Math.abs(x) < Math.abs(y)) { const t = x; x = y; y = t; }
      const hi = x + y;
      const lo = y - (hi - x);
      if (lo !== 0) p[i++] = lo;
      x = hi;
    }
    p.length = i;
    if (x !== 0) p.push(x);
  }
  let n = p.length;
  let hi = 0;
  let lo = 0;
  if (n > 0) {
    hi = p[--n];
    while (n > 0) {
      const x = hi;
      const y = p[--n];
      hi = x + y;
      lo = y - (hi - x);
      if (lo !== 0) break;
    }
    if (n > 0 && ((lo < 0 && p[n - 1] < 0) || (lo > 0 && p[n - 1] > 0))) {
      const y = lo * 2;
      const x = hi + y;
      if (y === x - hi) hi = x;
    }
  }
  return hi;
}

module.exports = {
  SPACE, WORD, translate, compile, strip, hasSpace, cpLength, cpSlice, isAsciiDigits, jsonString,
  unquote, unquotePlus, netloc, b64decode, fsum,
};
