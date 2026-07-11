// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-name (@internal): fail-closed DN name integrity.
 * Oracle: the RFC 5280 sec. 7.1 canonical comparison (case-fold + internal-
 * whitespace collapse), the multiset RDN rule, and the CVE-2009-2408 control-byte
 * reject. The DN comparison is the shared primitive pki.path.validate name
 * chaining, revocation issuer / OCSP responder matching, and name constraints
 * compose -- it is exercised end-to-end there; these pin its contract directly.
 */

var name = require("../../lib/guard-name");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError");
// defineClass subclasses take (code, message).
function E(code, message) { return new TestError(code, message); }
function rdn() { var a = []; for (var i = 0; i < arguments.length; i += 2) a.push({ type: arguments[i], value: arguments[i + 1] }); return a; }
var CN = "2.5.4.3", O = "2.5.4.10";
var NUL = String.fromCharCode(0), SOH = String.fromCharCode(1);
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testDnEqual() {
  check("identical DNs equal", name.dnEqual([rdn(CN, "Root")], [rdn(CN, "Root")], E, "x/n", "dn") === true);
  check("case-folded equal (Root == root)", name.dnEqual([rdn(CN, "Root")], [rdn(CN, "root")], E, "x/n", "dn") === true);
  check("internal whitespace collapsed", name.dnEqual([rdn(CN, "Root  CA")], [rdn(CN, "Root CA")], E, "x/n", "dn") === true);
  check("leading/trailing whitespace trimmed", name.dnEqual([rdn(CN, "  Root  ")], [rdn(CN, "Root")], E, "x/n", "dn") === true);
  check("genuinely different not equal", name.dnEqual([rdn(CN, "Root")], [rdn(CN, "Evil")], E, "x/n", "dn") === false);
  check("different RDN count not equal", name.dnEqual([rdn(CN, "Root")], [rdn(CN, "Root"), rdn(O, "Org")], E, "x/n", "dn") === false);
  check("different attribute type not equal", name.dnEqual([rdn(CN, "Root")], [rdn(O, "Root")], E, "x/n", "dn") === false);
}

function testRdnMultiset() {
  // An RDN is an unordered SET: order within the RDN must not matter.
  check("multi-value RDN order-independent", name.rdnEqual(rdn(CN, "Root", O, "Org"), rdn(O, "Org", CN, "Root"), E, "x/n", "dn") === true);
  check("multi-value RDN mismatch", name.rdnEqual(rdn(CN, "Root", O, "Org"), rdn(CN, "Root", O, "Other"), E, "x/n", "dn") === false);
}

function testControlByteReject() {
  // CVE-2009-2408: an embedded NUL / C0 control byte throws the caller's typed error
  // so a truncation name never compares equal. TAB (0x09) is exempt (collapsed).
  check("embedded NUL throws the typed code", codeOf(function () { name.dnEqual([rdn(CN, "Root" + NUL + ".evil")], [rdn(CN, "Root")], E, "x/name", "dn"); }) === "x/name");
  check("C0 control byte throws the typed code", codeOf(function () { name.dnEqual([rdn(CN, "Ro" + SOH + "ot")], [rdn(CN, "Root")], E, "x/name", "dn"); }) === "x/name");
  check("TAB is exempt and collapsed to a space", name.dnEqual([rdn(CN, "Root\tCA")], [rdn(CN, "Root CA")], E, "x/name", "dn") === true);
}

function run() {
  testDnEqual();
  testRdnMultiset();
  testControlByteReject();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
