// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- validator-attcert (@internal): the WebAuthn attestation-certificate profile
 * (sec. 8.2.1 packed + sec. 8.3.1 TPM AIK + the id-fido-gen-ce-aaguid extension). The
 * `@enforced-by behavioral` contract is that the MUST-reject vectors ARE the guard, so this
 * drives each function directly with a duck-typed certificate + a stub extension accessor
 * for every rejection, exactly as the cose/tpm/sig validators are pinned.
 *
 * The validator reads only cert.version, cert.subject.rdns, and the caller's
 * `exts` { find(cert, name) -> rawExt|null, decode(cert, name) -> {critical, value}|null }
 * accessor, so a plain object stands in for a parsed certificate with no DER to craft.
 */

var attcert = require("../../lib/validator-attcert");
var oid = require("../../lib/oid");
var asn1 = require("../../lib/asn1-der");
var b = asn1.build;
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError", { withCause: true });
function E(code, message, cause) { return new TestError(code, message, cause); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

var C = oid.byName("countryName"), O = oid.byName("organizationName");
var OU = oid.byName("organizationalUnitName"), CN = oid.byName("commonName");

// A stub extension accessor: decodeMap[name] answers exts.decode, findMap[name] answers
// exts.find. An absent key returns null (the "extension not present" case).
function exts(decodeMap, findMap) {
  return {
    decode: function (cert, name) { return (decodeMap && decodeMap[name]) || null; },
    find: function (cert, name) { return (findMap && findMap[name]) || null; },
  };
}
// A subject built from [type, value] pairs, one attribute per RDN (the shape the validator
// flattens: cert.subject.rdns is an array of RDNs, each an array of { type, value }).
function subject(pairs) { return { rdns: (pairs || []).map(function (p) { return [{ type: p[0], value: p[1] }]; }) }; }
var NOT_CA = { basicConstraints: { value: { cA: false } } };
var PACKED_SUBJECT = [[C, "US"], [O, "Yubico"], [OU, "Authenticator Attestation"], [CN, "yk"]];

function run() {
  // --- requireV3 -----------------------------------------------------------------
  check("requireV3 rejects a non-v3 attestation leaf",
    code(function () { attcert.requireV3({ version: 1 }, E, "att/bad"); }) === "att/bad");
  check("requireV3 accepts a v3 leaf",
    code(function () { attcert.requireV3({ version: 3 }, E, "att/bad"); }) === "NO-THROW");

  // --- assertNotCa ---------------------------------------------------------------
  check("assertNotCa rejects a leaf missing basicConstraints",
    code(function () { attcert.assertNotCa({}, exts({}), E, "att/bad"); }) === "att/bad");
  check("assertNotCa rejects a CA-asserting leaf (cA=true)",
    code(function () { attcert.assertNotCa({}, exts({ basicConstraints: { value: { cA: true } } }), E, "att/bad"); }) === "att/bad");
  check("assertNotCa accepts a leaf with basicConstraints cA=FALSE",
    code(function () { attcert.assertNotCa({}, exts(NOT_CA), E, "att/bad"); }) === "NO-THROW");

  // --- packedCert (WebAuthn 8.2.1) ----------------------------------------------
  check("packedCert accepts a complete packed leaf",
    code(function () { attcert.packedCert({ version: 3, subject: subject(PACKED_SUBJECT) }, exts(NOT_CA), E, "att/bad"); }) === "NO-THROW");
  check("packedCert rejects a non-v3 packed leaf (via requireV3)",
    code(function () { attcert.packedCert({ version: 1, subject: subject(PACKED_SUBJECT) }, exts(NOT_CA), E, "att/bad"); }) === "att/bad");
  check("packedCert rejects a CA packed leaf (via assertNotCa)",
    code(function () { attcert.packedCert({ version: 3, subject: subject(PACKED_SUBJECT) }, exts({ basicConstraints: { value: { cA: true } } }), E, "att/bad"); }) === "att/bad");
  check("packedCert rejects a subject missing countryName",
    code(function () { attcert.packedCert({ version: 3, subject: subject([[O, "Yubico"], [OU, "Authenticator Attestation"], [CN, "yk"]]) }, exts(NOT_CA), E, "att/bad"); }) === "att/bad");
  check("packedCert rejects a subject missing organizationName",
    code(function () { attcert.packedCert({ version: 3, subject: subject([[C, "US"], [OU, "Authenticator Attestation"], [CN, "yk"]]) }, exts(NOT_CA), E, "att/bad"); }) === "att/bad");
  check("packedCert rejects a subject missing commonName",
    code(function () { attcert.packedCert({ version: 3, subject: subject([[C, "US"], [O, "Yubico"], [OU, "Authenticator Attestation"]]) }, exts(NOT_CA), E, "att/bad"); }) === "att/bad");
  check("packedCert rejects a subject whose OU is not \"Authenticator Attestation\"",
    code(function () { attcert.packedCert({ version: 3, subject: subject([[C, "US"], [O, "Yubico"], [OU, "Wrong"], [CN, "yk"]]) }, exts(NOT_CA), E, "att/bad"); }) === "att/bad");
  check("packedCert tolerates a subject with no rdns array",
    code(function () { attcert.packedCert({ version: 3, subject: {} }, exts(NOT_CA), E, "att/bad"); }) === "att/bad");

  // --- aikCert (WebAuthn 8.3.1) --------------------------------------------------
  var AIK_EKU = { extKeyUsage: { value: [oid.byName("tcgKpAikCertificate")] } };
  var AIK_SAN = { subjectAltName: { value: { names: [{ tagNumber: 4, value: { rdns: [
    [{ type: oid.byName("tpmManufacturer"), value: "id:FFFFF1D0" }],
    [{ type: oid.byName("tpmModel"), value: "m" }],
    [{ type: oid.byName("tpmVersion"), value: "v" }],
  ] } }] } } };
  function aikExts(over) {
    var d = { basicConstraints: { value: { cA: false } } };
    d.extKeyUsage = AIK_EKU.extKeyUsage; d.subjectAltName = AIK_SAN.subjectAltName;
    if (over) Object.keys(over).forEach(function (k) { d[k] = over[k]; });
    return exts(d);
  }
  check("aikCert accepts a complete AIK leaf",
    code(function () { attcert.aikCert({ version: 3, subject: subject([]) }, aikExts(), E, "att/bad"); }) === "NO-THROW");
  check("aikCert accepts a leaf whose subject has no rdns array (empty subject)",
    code(function () { attcert.aikCert({ version: 3, subject: {} }, aikExts(), E, "att/bad"); }) === "NO-THROW");
  check("aikCert rejects an AIK leaf with a non-empty subject",
    code(function () { attcert.aikCert({ version: 3, subject: subject([[CN, "x"]]) }, aikExts(), E, "att/bad"); }) === "att/bad");
  check("aikCert rejects an AIK leaf missing the tcg-kp-AIKCertificate EKU",
    code(function () { attcert.aikCert({ version: 3, subject: subject([]) }, aikExts({ extKeyUsage: { value: [oid.byName("serverAuth")] } }), E, "att/bad"); }) === "att/bad");
  check("aikCert rejects an AIK leaf with no extKeyUsage at all",
    code(function () { attcert.aikCert({ version: 3, subject: subject([]) }, aikExts({ extKeyUsage: null }), E, "att/bad"); }) === "att/bad");
  check("aikCert rejects an AIK leaf whose SAN lacks the tcg attributes",
    code(function () { attcert.aikCert({ version: 3, subject: subject([]) }, aikExts({ subjectAltName: { value: { names: [{ tagNumber: 4, value: { rdns: [] } }] } } }), E, "att/bad"); }) === "att/bad");
  check("aikCert rejects an AIK leaf with no directoryName SAN",
    code(function () { attcert.aikCert({ version: 3, subject: subject([]) }, aikExts({ subjectAltName: { value: { names: [{ tagNumber: 2, value: "dns.example" }] } } }), E, "att/bad"); }) === "att/bad");

  // --- aaguidExt (id-fido-gen-ce-aaguid) -----------------------------------------
  var aaguid = Buffer.alloc(16, 0xab);
  var goodExtVal = b.octetString(aaguid);        // OCTET STRING wrapping the 16-byte aaguid
  check("aaguidExt tolerates an absent extension",
    code(function () { attcert.aaguidExt({}, aaguid, exts({}, {}), E, "att/bad", "att/mismatch"); }) === "NO-THROW");
  check("aaguidExt accepts a matching extension",
    code(function () { attcert.aaguidExt({}, aaguid, exts({}, { idFidoGenCeAaguid: { critical: false, value: goodExtVal } }), E, "att/bad", "att/mismatch"); }) === "NO-THROW");
  check("aaguidExt rejects a critical extension",
    code(function () { attcert.aaguidExt({}, aaguid, exts({}, { idFidoGenCeAaguid: { critical: true, value: goodExtVal } }), E, "att/bad", "att/mismatch"); }) === "att/bad");
  check("aaguidExt rejects a malformed (non-OCTET-STRING) extension value",
    code(function () { attcert.aaguidExt({}, aaguid, exts({}, { idFidoGenCeAaguid: { critical: false, value: b.integer(1n) } }), E, "att/bad", "att/mismatch"); }) === "att/bad");
  check("aaguidExt rejects a non-matching aaguid with the mismatch code",
    code(function () { attcert.aaguidExt({}, aaguid, exts({}, { idFidoGenCeAaguid: { critical: false, value: b.octetString(Buffer.alloc(16, 0x01)) } }), E, "att/bad", "att/mismatch"); }) === "att/mismatch");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
