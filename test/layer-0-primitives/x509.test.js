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

// ---- synthetic-certificate builders (hand-built canonical DER) --------
// Composed from the strict DER builders so each malformed shape is exact.

var build = pki.asn1.build;

function _algId(oidStr) { return build.sequence([build.oid(oidStr)]); }

function _atv(typeOid, value) { return build.sequence([build.oid(typeOid), build.utf8(value)]); }

// A one-RDN Name; extraRdns lets a test add legally-repeated attribute types.
function _name(cn, extraRdns) {
  var rdns = [build.set([_atv("2.5.4.3", cn)])];
  if (extraRdns) for (var i = 0; i < extraRdns.length; i++) rdns.push(extraRdns[i]);
  return build.sequence(rdns);
}

function _validity() {
  return build.sequence([
    build.utcTime(new Date("2026-01-01T00:00:00Z")),
    build.utcTime(new Date("2030-01-01T00:00:00Z")),
  ]);
}

function _spki() {
  return build.sequence([
    build.sequence([build.oid("1.2.840.10045.2.1"), build.oid("1.2.840.10045.3.1.7")]),
    build.bitString(Buffer.from([0x04, 0x01, 0x02, 0x03]), 0),
  ]);
}

function _ext(oidStr) {
  return build.sequence([build.oid(oidStr), build.octetString(Buffer.from([0x04, 0x02, 0xaa, 0xbb]))]);
}

// Assemble a Certificate SEQUENCE from an array of already-built tbs children.
function _cert(tbsChildren) {
  var tbs = build.sequence(tbsChildren);
  return build.sequence([tbs, _algId("1.2.840.10045.4.3.2"), build.bitString(Buffer.from([0x30, 0x03]), 0)]);
}

// FIX 9 — a tbs with an explicit version [0] but only six children (SPKI
// omitted): 6 children survive a bare `< 6` guard, then the positional SPKI
// read is `undefined` and `.children` throws a raw TypeError (no `.code`).
function testShortTbsWithVersion() {
  var cert = _cert([
    build.explicit(0, build.integer(2n)), // version v3
    build.integer(1n),                    // serial
    _algId("1.2.840.10045.4.3.2"),        // signature alg
    _name("issuer"),                      // issuer
    _validity(),                          // validity
    _name("subject"),                     // subject — SPKI intentionally omitted
  ]);
  var c = code(function () { pki.x509.parse(cert); });
  check("short tbs (version + 6 children) throws a CertificateError, not a raw TypeError",
    typeof c === "string" && c.indexOf("x509/") === 0);
}

// FIX 10 — two identical subjectKeyIdentifier extensions must be refused.
function testDuplicateExtension() {
  var cert = _cert([
    build.explicit(0, build.integer(2n)),
    build.integer(1n),
    _algId("1.2.840.10045.4.3.2"),
    _name("issuer"),
    _validity(),
    _name("subject"),
    _spki(),
    build.explicit(3, build.sequence([_ext("2.5.29.14"), _ext("2.5.29.14")])),
  ]);
  check("duplicate extension rejected", code(function () { pki.x509.parse(cert); }) === "x509/duplicate-extension");

  // Guard the anti-regression: repeated RDN attribute types are LEGAL.
  var multiOu = _cert([
    build.explicit(0, build.integer(2n)),
    build.integer(1n),
    _algId("1.2.840.10045.4.3.2"),
    _name("issuer", [build.set([_atv("2.5.4.11", "Eng")]), build.set([_atv("2.5.4.11", "Ops")])]),
    _validity(),
    _name("subject"),
    _spki(),
  ]);
  check("repeated RDN attribute types (multiple OU) still parse",
    code(function () { pki.x509.parse(multiOu); }) === "NO-THROW");
}

// FIX 11 — the certificate version is validated against the RFC 5280 set.
function testVersionValidation() {
  function withVersion(vInt) {
    return _cert([
      build.explicit(0, build.integer(vInt)),
      build.integer(1n),
      _algId("1.2.840.10045.4.3.2"),
      _name("issuer"),
      _validity(),
      _name("subject"),
      _spki(),
    ]);
  }
  check("explicit version 41 rejected", code(function () { pki.x509.parse(withVersion(41n)); }) === "x509/bad-version");
  check("explicit version -1 rejected", code(function () { pki.x509.parse(withVersion(-1n)); }) === "x509/bad-version");
  check("explicitly-encoded default v1 rejected", code(function () { pki.x509.parse(withVersion(0n)); }) === "x509/bad-version");

  // No version field parses as v1.
  var v1 = _cert([
    build.integer(1n),
    _algId("1.2.840.10045.4.3.2"),
    _name("issuer"),
    _validity(),
    _name("subject"),
    _spki(),
  ]);
  check("no version field parses as v1", (function () {
    var cert = pki.x509.parse(v1);
    return cert.version === 1;
  })());

  // Extensions with a non-v3 version are rejected.
  var v1WithExts = _cert([
    build.integer(1n),
    _algId("1.2.840.10045.4.3.2"),
    _name("issuer"),
    _validity(),
    _name("subject"),
    _spki(),
    build.explicit(3, build.sequence([_ext("2.5.29.14")])),
  ]);
  check("extensions on a v1 cert rejected", code(function () { pki.x509.parse(v1WithExts); }) === "x509/bad-version");
}

// A malformed KNOWN string type in a DN (invalid UTF-8 CN) must fail the
// certificate closed — _attrValueToString must not hex-encode it away and
// silently bypass the decoder's strict string validation. An ANY-typed value
// (a non-string tag) still legitimately falls back to a hex #-string.
function testMalformedDnStringRejected() {
  function certWithDnValue(valueNode) {
    var atv = build.sequence([build.oid("2.5.4.3"), valueNode]);
    var subject = build.sequence([build.set([atv])]);
    return _cert([
      build.explicit(0, build.integer(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
      _name("issuer"), _validity(), subject, _spki(),
    ]);
  }
  function dnOf(cert) { try { return pki.x509.parse(cert).subject.dn; } catch (_e) { return null; } }

  // A malformed KNOWN string type (invalid UTF-8 UTF8String) must fail the
  // certificate closed — not hex-encode the invalid bytes away.
  var badCert = certWithDnValue(pki.asn1.encode(0x00, false, pki.asn1.TAGS.UTF8_STRING, Buffer.from([0xFF, 0xFE])));
  check("x509.parse rejects a malformed UTF8String in a DN (fails closed, not hex)",
    code(function () { pki.x509.parse(badCert); }) === "x509/bad-atv");

  // An ANY-typed non-string value (INTEGER 5 = DER 02 01 05) is rendered as its
  // FULL DER encoding per RFC 4514 §2.4 — tag + length + content, not content-only.
  check("x509.parse hex-renders an ANY-typed DN value as full DER (#020105)",
    (dnOf(certWithDnValue(build.integer(5n))) || "").indexOf("#020105") !== -1);

  // A CONSTRUCTED ANY value (SEQUENCE{INTEGER 1} = DER 30 03 02 01 01) must NOT
  // reject the certificate: read.string throws asn1/expected-primitive, which is
  // a representable ANY value (RFC 4514 §2.4), not a malformed string.
  check("x509.parse hex-renders a constructed ANY DN value (does not reject)",
    (dnOf(certWithDnValue(build.sequence([build.integer(1n)]))) || "").indexOf("#3003020101") !== -1);
}

function run() {
  testParseFields();
  testExtensions();
  testPem();
  testRejects();
  testShortTbsWithVersion();
  testDuplicateExtension();
  testVersionValidation();
  testMalformedDnStringRejected();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
