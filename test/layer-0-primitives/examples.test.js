// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the runnable example programs the tarball ships.
 *
 * An example an operator can run is a claim about the library, and a claim with nothing behind it
 * goes stale the first time a verb changes shape. These run each program as a CHILD PROCESS, the way
 * a reader runs it, and assert the lines it printed rather than only its exit code: a program that
 * still exits 0 while printing `valid: false` has stopped demonstrating what it says it does.
 *
 * The program set is READ FROM DISK rather than listed here, so an example added to examples/ is
 * covered without an edit, and one that ships without an expectation here fails rather than being
 * silently uncovered.
 */

var helpers = require("../helpers");
var check = helpers.check;
var path = require("node:path");
var fs = require("node:fs");
var spawnSync = require("node:child_process").spawnSync;
var pkg = require("../../package.json");

var EXAMPLES_DIR = path.join(__dirname, "..", "..", "examples");

/** What each program must print. A line here is a substring the output must contain, so a value
 *  that changes meaning fails even though the program still runs. */
var EXPECTED = {
  "issue-a-certificate.js": [
    "ca subject:   CN=Example CA, O=Example",
    "leaf subject: CN=host.example",
    "leaf issuer:  CN=Example CA, O=Example",
    "leaf serial:  20 bytes of entropy",
    "path valid:   true",
    "after expiry: false",
  ],
  "read-a-certificate.js": [
    "subject:      CN=host.example, O=Example",
    "algorithm:    Ed25519",
    "lint worst:   pass",
    "lint findings: 0",
    "cons: SEQUENCE",
  ],
  "sign-and-verify-cms.js": [
    "verified:     true",
    "signers:      1",
    "verified true",
    "altered:      rejected",
  ],
  "post-quantum.js": [
    "signed with id-ml-dsa-65",
    "signed with id-slh-dsa-sha2-128s",
    "signed with Ed25519",
    "path validates with a post-quantum anchor: true",
    "both sides agree: true",
  ],
  "revoke-and-check.js": [
    "before crl:   true",
    "crl entries:  1, next update in 7 days",
    "after crl:    false",
    "refused for:  path/revoked",
  ],
};

function exampleFiles() {
  return fs.readdirSync(EXAMPLES_DIR).filter(function (name) {
    return name.length > 3 && name.slice(-3) === ".js" &&
      fs.statSync(path.join(EXAMPLES_DIR, name)).isFile();
  }).sort();
}

function run() {
  var files = exampleFiles();
  check("examples/ holds runnable programs", files.length >= 5);

  /* Every program on disk must have an expectation, and every expectation must name a program on
   * disk. Without both directions a new example ships uncovered, or a deleted one leaves a rule
   * asserting nothing. */
  var expectedNames = Object.keys(EXPECTED).sort();
  check("every example program has stated results here, and every statement names a program: " +
    "on disk [" + files.join(", ") + "] vs stated [" + expectedNames.join(", ") + "]",
  files.join(",") === expectedNames.join(","));

  files.forEach(function (name) {
    var r = spawnSync(process.execPath, [path.join(EXAMPLES_DIR, name)], { encoding: "utf8" });
    var out = (r.stdout || "") + (r.stderr || "");
    check("examples/" + name + " exits 0: " + (r.status === 0 ? "" : out.slice(0, 200)),
      r.status === 0);
    var missing = (EXPECTED[name] || []).filter(function (line) { return out.indexOf(line) === -1; });
    check("examples/" + name + " prints what it claims (" + (EXPECTED[name] || []).length +
      " statements): missing " + JSON.stringify(missing.slice(0, 3)),
    missing.length === 0);
  });

  /* A program the tarball does not carry is not runnable by the operator who installed the package,
   * and the examples/wiki application is a separate app that must NOT ship. */
  var shipped = pkg.files || [];
  check("package.json ships the example programs", shipped.some(function (f) {
    return f.indexOf("examples/") === 0;
  }));
  check("package.json does not ship the wiki application", !shipped.some(function (f) {
    return f === "examples" || f === "examples/";
  }));

  /* The require line a reader copies is the one the program runs: Node resolves a package's own
   * name inside it, so `require("@blamejs/pki")` works both after an install and in this tree. An
   * example reaching for a relative path would run here and be wrong everywhere else. */
  var relative = files.filter(function (name) {
    var src = fs.readFileSync(path.join(EXAMPLES_DIR, name), "utf8");
    return src.indexOf('require("' + pkg.name + '")') === -1;
  });
  check("every example requires the package by name, as a reader would: " + relative.join(", "),
    relative.length === 0);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
