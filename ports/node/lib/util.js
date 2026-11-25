"use strict";
// Paths, decoding and the "did a page make the browser send this" test, as
// util.py does them.
const py = require("./py");

/** Undo up to two layers of URL encoding (with + as a space). */
function decode(text) {
  for (let i = 0; i < 2; i += 1) {
    const next = py.unquotePlus(text);
    if (next === text) break;
    text = next;
  }
  return text;
}

/** The path as the shield compares it: percent-decoded, // collapsed, rooted. */
function normPath(path) {
  let p = py.unquote(path || "/");
  p = p.replace(/\/{2,}/g, "/");
  return p.startsWith("/") ? p : "/" + p;
}

/** Validate path prefixes and drop trailing slashes. */
function prefixes(entries, field) {
  if (typeof entries === "string") throw new Error(`${field} must be a list of paths, not one string`);
  const out = [];
  for (const entry of entries) {
    if (typeof entry !== "string" || !entry.startsWith("/") || !entry.replace(/^\/+|\/+$/g, "")) {
      throw new Error(`${field}: ${JSON.stringify(entry)} must start with '/' and name a path below it`);
    }
    out.push(entry.replace(/\/{2,}/g, "/").replace(/\/+$/, ""));
  }
  return out;
}

/** `path` is one of `prefixes` or below one, by whole segments, and never
 * when it climbs with ".." at any depth of encoding. */
function under(path, list) {
  if (!list.length) return false;
  const p = (path || "/").replace(/\/{2,}/g, "/");
  if (decode(p).replace(/\\/g, "/").split("/").includes("..")) return false;
  return list.some((prefix) => p === prefix || p.startsWith(prefix + "/"));
}

/** Lower-case extension of the last path segment, without the dot. */
function extension(path) {
  const name = path.slice(path.lastIndexOf("/") + 1);
  return name.includes(".") ? name.slice(name.lastIndexOf(".") + 1).toLowerCase() : "";
}

/** Did a web page, not the person, make the browser send this request? */
function induced(h) {
  const site = py.strip(h.get("sec-fetch-site") || "").toLowerCase();
  if (site === "cross-site" || site === "same-site") return true;
  if (site === "same-origin") {
    return !["", "document", "empty", "websocket"].includes(py.strip(h.get("sec-fetch-dest") || "").toLowerCase());
  }
  if (site) return false;
  const referer = h.get("referer") || "";
  const host = py.strip(h.get("host") || "").toLowerCase();
  if (!referer || !host) return false;
  let origin;
  try {
    origin = py.netloc(py.strip(referer));
  } catch {
    return false;
  }
  origin = origin.slice(origin.lastIndexOf("@") + 1).toLowerCase();
  return Boolean(origin) && origin !== host;
}

/** UNION/**\/SELECT with the comments turned into spaces; MySQL's
 * /*!50000 ... *\/ keeps its contents. Returns null when there is nothing to strip. */
function stripSqlComments(text) {
  if (!text.includes("/*")) return null;
  const out = [];
  let i = 0;
  for (;;) {
    const a = text.indexOf("/*", i);
    if (a < 0) {
      out.push(text.slice(i));
      break;
    }
    out.push(text.slice(i, a), " ");
    const b = text.indexOf("*/", a + 2);
    if (b < 0) break;
    if (text.startsWith("!", a + 2)) out.push(text.slice(a + 3, b).replace(/^[0-9]+/, ""), " ");
    i = b + 2;
  }
  return out.join("");
}

/** The decoded path, then each decoded query name and value, joined by NUL. */
function urlText(path, query) {
  const parts = [decode(path)];
  for (const pair of query.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    parts.push(decode(eq < 0 ? pair : pair.slice(0, eq)), decode(eq < 0 ? "" : pair.slice(eq + 1)));
  }
  return parts.join("\x00");
}

module.exports = { decode, normPath, prefixes, under, extension, induced, stripSqlComments, urlText };
