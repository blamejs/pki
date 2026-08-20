// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- sign-scheme.mldsaDigestSuitable: the RFC 9882 sec. 3.3 digest-strength
 * policy, asked as one question by both the signer and the CMS verifier so the two
 * cannot drift. Pins that the answer comes from the table's OWN entries: the gate
 * rejects on a falsy lookup, so a digest name planted on Object.prototype would
 * otherwise answer for every name a parameter set's row omits and a below-strength
 * digest would pass the strength check on both paths.
 *
 * The planted name is installed and removed inside each vector, never left on the
 * prototype across the suite.
 */

var helpers = require("../helpers");
var check = helpers.check;
var signScheme = require("../../lib/sign-scheme");

var suitable = signScheme.mldsaDigestSuitable;

// Install `name` on Object.prototype for the duration of `fn`, then remove it.
function withPlanted(name, fn) {
  Object.prototype[name] = true;
  try { return fn(); }
  finally { delete Object.prototype[name]; }
}

function run() {
  // ==== the policy itself (RFC 9882 sec. 3.3) ====
  check("1. ML-DSA-44 accepts sha256", suitable("ML-DSA-44", "sha256") === true);
  check("2. ML-DSA-65 refuses sha256 as below its strength", suitable("ML-DSA-65", "sha256") === false);
  check("3. ML-DSA-87 accepts sha512", suitable("ML-DSA-87", "sha512") === true);
  check("4. ML-DSA-87 refuses sha256 and sha384", suitable("ML-DSA-87", "sha256") === false && suitable("ML-DSA-87", "sha384") === false);
  check("5. an unknown parameter set is refused rather than defaulted", suitable("ML-DSA-99", "sha512") === false);
  check("6. an unknown digest name is refused", suitable("ML-DSA-44", "md5") === false);

  // ==== the defense: the answer comes from own entries, not the prototype chain ====
  check("7. a digest planted on Object.prototype does not become suitable for ML-DSA-87",
    withPlanted("sha256", function () { return suitable("ML-DSA-87", "sha256"); }) === false);
  check("8. ...nor for ML-DSA-65, whose row also omits it",
    withPlanted("sha256", function () { return suitable("ML-DSA-65", "sha256"); }) === false);
  check("9. a parameter set planted on Object.prototype does not become a known set",
    withPlanted("ML-DSA-99", function () { return suitable("ML-DSA-99", "sha512"); }) === false);
  check("10. a planted name does not disturb a genuine acceptance",
    withPlanted("sha256", function () { return suitable("ML-DSA-44", "sha256"); }) === true);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
