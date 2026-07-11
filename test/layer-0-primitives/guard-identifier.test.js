// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-identifier (@internal): fail-closed canonicalization of the
 * structured-identifier strings the toolkit compares and encodes.
 * Oracle: X.660 -- a canonical dotted-decimal OID has two or more arcs, no
 * leading-zero component, the root arc 0..2, and the second arc 0..39 under roots
 * 0 and 1. The string-OID contract is the shared primitive pki.oid name/arc
 * resolution, pki.asn1 build.oid, and pki.path.validate EKU / policy key checking
 * compose -- exercised end-to-end there; these pin its contract directly.
 */

var identifier = require("../../lib/guard-identifier");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError");
function E(code, message) { return new TestError(code, message); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testAcceptsCanonical() {
  check("a plain OID is returned unchanged", identifier.assertCanonicalOid("1.2.840.113549", E, "x/bad", "oid") === "1.2.840.113549");
  check("a two-arc OID is accepted", identifier.assertCanonicalOid("2.5", E, "x/bad", "oid") === "2.5");
  check("a zero arc is canonical (no leading zero)", identifier.assertCanonicalOid("2.5.29.0", E, "x/bad", "oid") === "2.5.29.0");
  check("root 2 lifts the second-arc bound", identifier.assertCanonicalOid("2.999.1", E, "x/bad", "oid", "x/bounds") === "2.999.1");
  // A UUID-based arc exceeds 2^53 -- it must survive as a BigInt without precision loss.
  check("a huge arc beyond 2^53 is accepted", identifier.assertCanonicalOid("2.25.329800735698586629295641978511506172918", E, "x/bad", "oid") === "2.25.329800735698586629295641978511506172918");
}

function testSyntaxRejects() {
  check("a leading-zero arc throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("2.05.29.15", E, "x/bad", "oid"); }) === "x/bad");
  check("a single arc throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("2", E, "x/bad", "oid"); }) === "x/bad");
  check("a non-string throws the syntax code", codeOf(function () { identifier.assertCanonicalOid(1.2, E, "x/bad", "oid"); }) === "x/bad");
  check("a trailing dot throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("1.2.", E, "x/bad", "oid"); }) === "x/bad");
  check("a non-numeric arc throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("1.2.x", E, "x/bad", "oid"); }) === "x/bad");
}

function testBoundsRejects() {
  // The X.660 arc bounds throw the SEPARATE boundsCode when one is supplied.
  check("root arc above 2 throws the bounds code", codeOf(function () { identifier.assertCanonicalOid("9.9.9", E, "x/bad", "oid", "x/bounds"); }) === "x/bounds");
  check("second arc 40 under root 1 throws the bounds code", codeOf(function () { identifier.assertCanonicalOid("1.40.1", E, "x/bad", "oid", "x/bounds"); }) === "x/bounds");
  // With no boundsCode, an out-of-range arc falls back to the syntax code.
  check("bounds fault falls back to the syntax code by default", codeOf(function () { identifier.assertCanonicalOid("9.9.9", E, "x/bad", "oid"); }) === "x/bad");
}

function testBoundsWaived() {
  // boundsCode === null waives the arc-bound check (a LOOKUP key): a well-formed
  // but non-encodable OID passes syntax so the caller can treat it as a miss.
  check("boundsCode null accepts an out-of-bounds well-formed OID", identifier.assertCanonicalOid("9.9.9", E, "x/bad", "oid", null) === "9.9.9");
  // Syntax is still enforced even when bounds are waived.
  check("boundsCode null still rejects a leading-zero arc", codeOf(function () { identifier.assertCanonicalOid("2.05.1", E, "x/bad", "oid", null); }) === "x/bad");
}

function run() {
  testAcceptsCanonical();
  testSyntaxRejects();
  testBoundsRejects();
  testBoundsWaived();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
