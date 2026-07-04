// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.oid (OID ↔ name registry).
 * Oracle: known RFC / NIST names + hand-computed arc conversions.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var vectors = helpers.vectors;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testRegistry() {
  check("name(commonName)", pki.oid.name("2.5.4.3") === "commonName");
  check("name(sha256WithRSA)", pki.oid.name("1.2.840.113549.1.1.11") === "sha256WithRSAEncryption");
  check("name(ecPublicKey)", pki.oid.name("1.2.840.10045.2.1") === "ecPublicKey");
  check("name(Ed25519)", pki.oid.name("1.3.101.112") === "Ed25519");
  check("name(ML-DSA-87)", pki.oid.name("2.16.840.1.101.3.4.3.19") === "id-ml-dsa-87");
  check("name(ML-KEM-1024)", pki.oid.name("2.16.840.1.101.3.4.4.3") === "id-ml-kem-1024");
  check("name(basicConstraints)", pki.oid.name("2.5.29.19") === "basicConstraints");
  check("unregistered returns undefined", pki.oid.name("1.3.6.1.4.1.99999.7") === undefined);
  check("byName reverse lookup", pki.oid.byName("commonName") === "2.5.4.3");
  check("has()", pki.oid.has("2.5.4.3") === true && pki.oid.has("9.9.9") === false);
}

function testRegister() {
  pki.oid.register("1.3.6.1.4.1.99999.1", "acmeWidgetPolicy");
  check("register forward", pki.oid.name("1.3.6.1.4.1.99999.1") === "acmeWidgetPolicy");
  check("register reverse", pki.oid.byName("acmeWidgetPolicy") === "1.3.6.1.4.1.99999.1");
  check("register rejects bad oid", code(function () { pki.oid.register("nope", "x"); }) === "oid/bad-input");
}

function testArcs() {
  check("toArcs", JSON.stringify(pki.oid.toArcs("2.5.4.3")) === JSON.stringify([2, 5, 4, 3]));
  check("fromArcs", pki.oid.fromArcs([1, 2, 840, 113549]) === "1.2.840.113549");
  check("arc round-trip", pki.oid.fromArcs(pki.oid.toArcs("2.16.840.1.101.3.4.2.1")) === "2.16.840.1.101.3.4.2.1");
  check("fromArcs rejects short", code(function () { pki.oid.fromArcs([1]); }) === "oid/bad-input");
  check("fromArcs rejects negative bigint arc", code(function () { pki.oid.fromArcs([2n, -5n, 1n]); }) === "oid/bad-arc");
}

function testDer() {
  vectors.OID_CONTENT.forEach(function (t) {
    var full = pki.oid.toDER(t[0]);
    check("toDER/fromDER round-trip " + t[0], pki.oid.fromDER(full) === t[0]);
  });
}

function run() {
  testRegistry();
  testRegister();
  testArcs();
  testDer();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
