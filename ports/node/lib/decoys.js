"use strict";
// Decoy kit: canary paths and credential honeytokens, derived from a secret
// you keep exactly as the Python reference derives them (SPEC.md).
const crypto = require("crypto");
const py = require("./py");

const SHAPES = ["/api/v1/internal/audit-{}", "/admin/legacy-{}/export", "/api/v2/debug/session-{}",
  "/backend/ops-{}/config", "/api/v1/staff/reports-{}"];

function hmac(secret, label) {
  return crypto.createHmac("sha256", Buffer.from(String(secret), "utf8")).update(label).digest();
}

/** Stable, unguessable decoy paths derived from a secret. */
function makeCanaries(secret, count = 3) {
  const out = [];
  for (let i = 0; i < count; i += 1) {
    const tag = hmac(secret, `canary-${i}`).toString("hex").slice(0, 10);
    out.push(SHAPES[i % SHAPES.length].replace("{}", tag));
  }
  return out;
}

/** Disallow lines for robots.txt. */
function robotsTxtBlock(canaries) {
  return "User-agent: *\n" + canaries.map((p) => `Disallow: ${p}\n`).join("");
}

/** A link no person can see or reach by keyboard. */
function htmlTrap(canary) {
  return `<a href="${canary}" rel="nofollow" tabindex="-1" aria-hidden="true" style="position:absolute;left:-9999px">.</a>`;
}

/** A dead constant for your JS bundle. */
function jsTrap(canary, name = "__legacyApi") {
  return `var ${name} = "${canary}";`;
}

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const USERS = ["svc-deploy", "admin-legacy", "ops-backup", "staging-admin"];

function base62(bytes, length) {
  let n = BigInt("0x" + bytes.toString("hex"));
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out += BASE62[Number(n % 62n)];
    n /= 62n;
  }
  return out;
}

/** Fake credentials from a secret: {apiKeys, users, passwords}. Iterating
 * gives the values the shield watches for, so it can go straight into
 * the `honeytokens` setting. */
function makeHoneytokens(secret, count = 2) {
  if (count < 1) throw new Error("count must be at least 1");
  const apiKeys = [];
  const passwords = [];
  for (let i = 0; i < count; i += 1) {
    apiKeys.push("api_live_" + base62(hmac(secret, `honeytoken-key-${i}`), 32));
    const d = hmac(secret, `honeytoken-password-${i}`);
    const body = base62(d, 14);
    const at = d[1] % 14;
    passwords.push(body.slice(0, at) + "!@#$*"[d[0] % 5] + body.slice(at) + String(d[2] % 10));
  }
  const users = apiKeys.map((_, i) => USERS[i % USERS.length]);
  return {
    apiKeys, users, passwords,
    [Symbol.iterator]() { return apiKeys.concat(passwords)[Symbol.iterator](); },
  };
}

/** A dead config object for your JS bundle, with a key and a login. */
function honeytokenJs(tokens, index = 0, name = "__stagingConfig") {
  const i = index % tokens.apiKeys.length;
  const fields = [["apiBase", "/api/v1"], ["apiKey", tokens.apiKeys[i]], ["adminUser", tokens.users[i]],
    ["adminPassword", tokens.passwords[i]]];
  return `var ${name} = {${fields.map(([k, v]) => `${py.jsonString(k)}: ${py.jsonString(v)}`).join(", ")}};`;
}

/** An HTML comment with credentials someone meant to remove. */
function honeytokenHtml(tokens, index = 1) {
  const i = index % tokens.apiKeys.length;
  return `<!-- TODO(ops): remove before release. Staging admin login ${tokens.users[i]} / ${tokens.passwords[i]} ` +
    `; reporting API key ${tokens.apiKeys[i]} -->`;
}

module.exports = { makeCanaries, robotsTxtBlock, htmlTrap, jsTrap, makeHoneytokens, honeytokenJs, honeytokenHtml };
