// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.x509 (certificate parsing).
 * Oracle: a real OpenSSL-generated self-signed P-256 certificate whose
 * fields were read out independently with `openssl x509 -noout -text`.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var vectors = helpers.vectors;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

var EXPECT = vectors.CERT_EC_EXPECT;

function testParseFields() {
  var cert = pki.x509.parse(vectors.CERT_EC_PEM);
  check("version is 3", cert.version === EXPECT.version);
  check("serial hex matches", cert.serialNumberHex.toLowerCase() === EXPECT.serialHex);
  check("serial is a BigInt", typeof cert.serialNumber === "bigint");
  check("subject DN", cert.subject.dn === EXPECT.subjectDn);
  check("issuer DN", cert.issuer.dn === EXPECT.issuerDn);
  check("notBefore", cert.validity.notBefore.toISOString() === EXPECT.notBeforeIso);
  check("notAfter", cert.validity.notAfter.toISOString() === EXPECT.notAfterIso);
  check("signature algorithm OID", cert.signatureAlgorithm.oid === EXPECT.sigAlgOid);
  check("signature algorithm name", cert.signatureAlgorithm.name === EXPECT.sigAlgName);
  check("outer/tbs sig algs agree", cert.signatureAlgorithm.oid === cert.tbsSignatureAlgorithm.oid);
  check("SPKI algorithm OID", cert.subjectPublicKeyInfo.algorithm.oid === EXPECT.spkiAlgOid);
  check("SPKI algorithm name", cert.subjectPublicKeyInfo.algorithm.name === EXPECT.spkiAlgName);
  check("public key bytes present", cert.subjectPublicKeyInfo.publicKey.bytes.length > 0);
  check("tbsBytes is a non-empty Buffer", Buffer.isBuffer(cert.tbsBytes) && cert.tbsBytes.length > 0);
  check("signature value present", cert.signatureValue.bytes.length > 0);
}

function testExtensions() {
  var cert = pki.x509.parse(vectors.CERT_EC_PEM);
  var oids = cert.extensions.map(function (e) { return e.oid; });
  EXPECT.extnOids.forEach(function (o) {
    check("has extension " + o, oids.indexOf(o) !== -1);
  });
  var bc = cert.extensions.filter(function (e) { return e.oid === "2.5.29.19"; })[0];
  check("basicConstraints is critical", bc && bc.critical === true);
  check("basicConstraints named", bc && bc.name === "basicConstraints");
  check("extension value is a Buffer", bc && Buffer.isBuffer(bc.value));
}

function testPem() {
  var der = pki.x509.pemDecode(vectors.CERT_EC_PEM, "CERTIFICATE");
  check("pemDecode yields DER", Buffer.isBuffer(der) && der[0] === 0x30);
  var reencoded = pki.x509.pemEncode(der, "CERTIFICATE");
  check("PEM round-trips to same DER", pki.x509.pemDecode(reencoded, "CERTIFICATE").equals(der));
  check("parse(DER) === parse(PEM)", (function () {
    var a = pki.x509.parse(der);
    var b = pki.x509.parse(vectors.CERT_EC_PEM);
    return a.subject.dn === b.subject.dn && a.serialNumberHex === b.serialNumberHex;
  })());
  check("pemDecode rejects wrong label", code(function () { pki.x509.pemDecode(vectors.CERT_EC_PEM, "PRIVATE KEY"); }) === "pem/label-mismatch");
}

function testRejects() {
  check("rejects empty SEQUENCE", code(function () { pki.x509.parse(Buffer.from("3000", "hex")); }) === "x509/not-a-certificate");
  check("rejects non-buffer input", code(function () { pki.x509.parse(42); }) === "x509/bad-input");
  check("rejects garbage DER", code(function () { pki.x509.parse(Buffer.from("ffffffff", "hex")); }) !== "NO-THROW");
}

function run() {
  testParseFields();
  testExtensions();
  testPem();
  testRejects();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
