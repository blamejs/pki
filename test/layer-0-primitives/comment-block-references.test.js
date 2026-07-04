// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — @spec / @defends comment-block references.
 * Oracle: the standards-body reference grammar + canonical URLs + the
 * required-on-every-primitive doc gate. The wiki validator/generator are
 * dependency-free, so this runs without an examples/wiki npm install.
 */

var os   = require("node:os");
var fs   = require("node:fs");
var path = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;

var WIKI_LIB   = path.resolve(__dirname, "../../examples/wiki/lib");
var validator  = require(path.join(WIKI_LIB, "source-comment-block-validator"));
var parser     = require(path.join(WIKI_LIB, "source-doc-parser"));
var generator  = require(path.join(WIKI_LIB, "page-generator"));

// --- @spec grammar (every recognized standards body + rejects) -------------

function testSpecGrammar() {
  var valid = [
    "FIPS 186-5", "FIPS 203", "FIPS 140-3", "FIPS 186-5 (DSS)",
    "SP 800-38D", "NIST SP 800-56C Rev. 2",
    "RFC 5280", "RFC 5280 §4.1.2.5.2", "RFC 8017",
    "X.690", "X.690 §8.3.2", "X.690 (2021) §8.3.2", "X.509",
    "ISO/IEC 8825", "ISO/IEC 80000-13", "IEC 80000-13",
    "SEC 1", "SEC 2", "ANSI X9.62",
    "W3C WebCrypto §ecdsa", "PKCS#1", "CA/Browser Forum BR",
    "semver.org 2.0.0", "SemVer 2.0.0",
    "internal", "internal (design: scale helper)",
  ];
  valid.forEach(function (r) { check("@spec valid: " + r, validator.isValidSpecRef(r) === true); });

  var invalid = ["FIPS", "RFC", "X.", "SP 800", "just prose here",
                 "X.690 extra words", "", "rfc 5280", "FIPS abc"];
  invalid.forEach(function (r) { check("@spec invalid: " + JSON.stringify(r), validator.isValidSpecRef(r) === false); });
}

// --- @defends grammar (CVE / CWE / named class) ----------------------------

function testDefendsGrammar() {
  var valid = ["CVE-2014-1568", "CWE-400", "ASN.1-parser-DoS",
               "ASN.1-parser-DoS (CWE-400)", "non-minimal-DER-forgery (CVE-2014-1568)",
               "timing-side-channel"];
  valid.forEach(function (r) { check("@defends valid: " + r, validator.isValidDefendsRef(r) === true); });

  var invalid = ["CVE-14-1568", "CWE-", "CVE-2014", "cve-2014-1568"];
  invalid.forEach(function (r) { check("@defends invalid: " + r, validator.isValidDefendsRef(r) === false); });
}

// --- wiki reference URL mapping --------------------------------------------

function testSpecUrls() {
  var linked = [
    ["RFC 5280 §4.1.2.5.2", "https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.2"],
    ["RFC 5280",            "https://datatracker.ietf.org/doc/html/rfc5280"],
    ["FIPS 186-5",          "https://csrc.nist.gov/pubs/fips/186-5/final"],
    ["X.690 §8.3.2",        "https://www.itu.int/rec/T-REC-X.690"],
    ["W3C WebCrypto §ecdsa","https://www.w3.org/TR/WebCryptoAPI/"],
    ["CVE-2014-1568",       "https://www.cve.org/CVERecord?id=CVE-2014-1568"],
    ["CWE-400",             "https://cwe.mitre.org/data/definitions/400.html"],
    ["SEC 1",               "https://www.secg.org/sec1-v2.pdf"],
  ];
  linked.forEach(function (c) { check("specUrl " + c[0], generator.specUrl(c[0]) === c[1]); });

  // No stable deep link -> rendered as plain code, not a broken href.
  ["ISO/IEC 8825", "ANSI X9.62", "internal (design: x)", "semver.org 2.0.0",
   "PKCS#1", "CA/Browser Forum BR"].forEach(function (r) {
    check("specUrl null for " + r, generator.specUrl(r) === null);
  });
}

// --- required-on-every-primitive gate (config.requireSpec) -----------------

var _fixN = 0;
function _fixtureSource(specLine) {
  return [
    "/**", " * @module pki.fixture", " * @nav Core", " * @title Fixture", " */",
    "/**",
    " * @primitive pki.fixture.thing",
    " * @signature pki.fixture.thing(x) -> y",
    " * @since 0.1.0",
    " * @status stable",
    specLine ? (" * " + specLine) : null,
    " *",
    " * A fixture primitive with sufficient descriptive prose to pass checks.",
    " *",
    " * @example",
    " *   pki.fixture.thing(1);",
    " */",
    "function thing(x) { return x; }",
    "module.exports = { thing: thing };",
    "",
  ].filter(function (l) { return l !== null; }).join("\n");
}
function _validateFixture(specLine, requireSpec) {
  var dir = path.join(os.tmpdir(), "pki-spec-fix-" + process.pid + "-" + (_fixN++));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "fixture.js"), _fixtureSource(specLine));
  var findings;
  try { findings = validator.validate({ libDir: dir, parser: parser, requireSpec: requireSpec }); }
  finally { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {} }
  return findings || [];
}
function _has(findings, re) { return findings.some(function (f) { return re.test(f.msg); }); }

function testRequiredGate() {
  check("requireSpec flags a primitive missing @spec",
    _has(_validateFixture(null, true), /missing @spec/));
  check("requireSpec passes a primitive with a valid @spec",
    !_has(_validateFixture("@spec X.690 §8.3.2, RFC 5280 §4.1.2.2", true), /@spec/));
  check("@spec internal (design: ...) satisfies the requirement",
    !_has(_validateFixture("@spec internal (design: fixture helper)", true), /missing @spec/));
  check("an invalid @spec reference is flagged",
    _has(_validateFixture("@spec NotAStandard 99", true), /not a recognized normative reference/));
  check("an invalid @defends reference is flagged",
    _has(_validateFixture("@spec RFC 5280\n * @defends CVE-14-1568", true), /@defends `CVE-14-1568`/));
  // Default (requireSpec off) must NOT flag missing @spec — the gate stays
  // green until @spec is backfilled onto every primitive.
  check("requireSpec off does not flag a missing @spec",
    !_has(_validateFixture(null, false), /missing @spec/));
}

function run() {
  testSpecGrammar();
  testDefendsGrammar();
  testSpecUrls();
  testRequiredGate();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
