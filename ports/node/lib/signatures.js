"use strict";
// The signature patterns, compiled from patterns.json: a copy of
// spec/patterns.json, which is generated from the Python reference's
// signatures.py. Every pattern runs on text a client chose, on every request,
// and test/cost.test.js times each one against hostile input.
const { compile } = require("./py");
const P = require("./patterns.json");

module.exports = {
  HARD_UA: P.hard_ua.map(([src, points, label]) => [compile(src), points, label]),
  SOFT_UA: P.soft_ua.map(([src, points, label]) => [compile(src), points, label]),
  ASSESSMENT_UA: compile(P.assessment_ua),
  BROWSER_UA: compile(P.browser_ua),
  CRAWLER_UA: compile(P.crawler_ua),
  SENSITIVE_PATHS: compile(P.sensitive_paths),
  MISSING_SENSITIVE: compile(P.missing_sensitive),
  RECON_PATHS: compile(P.recon_paths),
  PAYLOADS: P.payloads.map(([src, label]) => [compile(src), label]),
  OOB: P.oob.map(([src, label]) => [compile(src), label]),
  ODD_METHODS: new Set(P.odd_methods),
  SOFT_METHODS: new Set(P.soft_methods),
};
