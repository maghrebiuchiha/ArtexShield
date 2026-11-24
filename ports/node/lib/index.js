"use strict";
/**
 * artex-shield for Node.js: detection and blocking of ARTEX-style automated
 * penetration-testing traffic, as Express / Connect middleware or around any
 * `http` handler. No dependencies. A port of the Python reference, held to
 * the same decisions by spec/vectors.json.
 *
 *   const { Shield, artexShield, makeCanaries } = require("artex-shield");
 *   const shield = new Shield({ mode: "monitor", canaryPaths: makeCanaries(process.env.CANARY_SECRET) });
 *   app.use(artexShield(shield));
 */
const { Shield, Decision } = require("./shield");
const { makeConfig, DEFAULTS } = require("./config");
const decoys = require("./decoys");
const clientCheck = require("./clientCheck");
const { artexShield, handler, upgradeGuard } = require("./middleware");

/** The <script> tag for the optional client check, for every HTML page. */
function clientCheckTag(shieldOrOptions = {}) {
  const cfg = shieldOrOptions instanceof Shield ? shieldOrOptions.cfg : makeConfig(shieldOrOptions);
  return clientCheck.tag(cfg.clientCheckPath.replace(/\/+$/, ""));
}

module.exports = {
  Shield, Decision, makeConfig, DEFAULTS,
  artexShield, handler, upgradeGuard,
  makeCanaries: decoys.makeCanaries, robotsTxtBlock: decoys.robotsTxtBlock, htmlTrap: decoys.htmlTrap, jsTrap: decoys.jsTrap,
  makeHoneytokens: decoys.makeHoneytokens, honeytokenJs: decoys.honeytokenJs, honeytokenHtml: decoys.honeytokenHtml,
  clientCheckTag, clientCheckScript: clientCheck.script,
};
