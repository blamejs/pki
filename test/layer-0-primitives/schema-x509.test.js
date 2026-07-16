// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.x509 (certificate parsing).
 * Oracle: a real OpenSSL-generated self-signed P-256 certificate whose
 * fields were read out independently with `openssl x509 -noout -text`.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var vectors = helpers.vectors;
var pkix = require("../../lib/schema-pkix");
var oidReg = require("../../lib/oid");
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

var EXPECT = vectors.CERT_EC_EXPECT;

function testParseFields() {
  var cert = pki.schema.x509.parse(vectors.CERT_EC_PEM);
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
  // tbsBytes is the exact signed region an external verifier hashes — it must
  // be the tbsCertificate TLV byte-for-byte off the wire, never re-serialized.
  var wireDer = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM, "CERTIFICATE");
  check("tbsBytes byte-identical to the tbsCertificate TLV on the wire",
    cert.tbsBytes.equals(pki.asn1.decode(wireDer).children[0].bytes));
  check("signature value present", cert.signatureValue.bytes.length > 0);
}

function testExtensions() {
  var cert = pki.schema.x509.parse(vectors.CERT_EC_PEM);
  var oids = cert.extensions.map(function (e) { return e.oid; });
  EXPECT.extnOids.forEach(function (o) {
    check("has extension " + o, oids.indexOf(o) !== -1);
  });
  var bc = cert.extensions.filter(function (e) { return e.oid === "2.5.29.19"; })[0];
  check("basicConstraints is critical", bc && bc.critical === true);
  check("basicConstraints named", bc && bc.name === "basicConstraints");
  check("extension value is a Buffer", bc && Buffer.isBuffer(bc.value));

  // Known-answer SAN decode against the openssl oracle: drive the RFC 5280
  // sec. 4.2.1.6 subjectAltName decoder (the same OID-keyed registry
  // certification-path validation uses on attacker-supplied bytes) over the
  // real certificate's extension value and compare the dNSName entries to
  // the independently-read expectation.
  var sanOid = oidReg.byName("subjectAltName");
  var sanExt = cert.extensions.filter(function (e) { return e.oid === sanOid; })[0];
  check("subjectAltName extension present", Boolean(sanExt));
  var NS = pkix.makeNS("path", pki.errors.PathError, oidReg);
  var san = pkix.certExtensionDecoders(NS).byOid[sanOid](sanExt.value);
  var dns = san.names
    .filter(function (nm) { return nm.tagClass === "context" && nm.tagNumber === 2; })
    .map(function (nm) { return nm.value; });
  check("SAN dNSName entries match the openssl-read expectation",
    dns.length === EXPECT.sanDnsNames.length &&
    dns.every(function (d, i) { return d === EXPECT.sanDnsNames[i]; }));
}

function testPem() {
  var der = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM, "CERTIFICATE");
  check("pemDecode yields DER", Buffer.isBuffer(der) && der[0] === 0x30);
  var reencoded = pki.schema.x509.pemEncode(der, "CERTIFICATE");
  check("PEM round-trips to same DER", pki.schema.x509.pemDecode(reencoded, "CERTIFICATE").equals(der));
  check("parse(DER) === parse(PEM)", (function () {
    var a = pki.schema.x509.parse(der);
    var b = pki.schema.x509.parse(vectors.CERT_EC_PEM);
    return a.subject.dn === b.subject.dn && a.serialNumberHex === b.serialNumberHex;
  })());
  check("pemDecode rejects wrong label", code(function () { pki.schema.x509.pemDecode(vectors.CERT_EC_PEM, "PRIVATE KEY"); }) === "pem/label-mismatch");
  // The format's canonical RFC 7468 label (CERTIFICATE) is the default, matching
  // every sibling format: called label-less on text whose first block is a
  // foreign type, pemDecode refuses rather than returning the first block of
  // anything; an explicit null label opts into the any-block behavior.
  check("label-less pemDecode enforces the CERTIFICATE label", pki.schema.x509.pemDecode(vectors.CERT_EC_PEM).equals(der));
  var bundle = pki.schema.x509.pemEncode(Buffer.from([0x30, 0x00]), "PRIVATE KEY") + vectors.CERT_EC_PEM;
  check("label-less pemDecode rejects a foreign first block", code(function () { pki.schema.x509.pemDecode(bundle); }) === "pem/label-mismatch");
  check("pemDecode(text, null) takes the first block of any type", pki.schema.x509.pemDecode(bundle, null).equals(Buffer.from([0x30, 0x00])));
  // A detached-backed PEM Buffer must fail closed as a typed PemError, not a raw
  // TypeError -- the text guard re-views through the byte guard, which threads
  // the raw failure as the cause (PemError carries withCause).
  check("pemDecode rejects a detached-backed Buffer", code(function () {
    var ab = new ArrayBuffer(8); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] });
    pki.schema.x509.pemDecode(b);
  }) === "pem/bad-input");
}

function testRejects() {
  check("rejects empty SEQUENCE", code(function () { pki.schema.x509.parse(Buffer.from("3000", "hex")); }) === "x509/not-a-certificate");
  check("rejects non-buffer input", code(function () { pki.schema.x509.parse(42); }) === "x509/bad-input");
  // A detached-backed input fails closed via the shared coerceToDer byte guard --
  // the defence propagates to every DER format that composes it, not per-format.
  check("rejects a detached-backed Buffer", code(function () {
    var ab = new ArrayBuffer(4); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] });
    pki.schema.x509.parse(b);
  }) === "x509/bad-input");
  check("rejects garbage DER", code(function () { pki.schema.x509.parse(Buffer.from("ffffffff", "hex")); }) !== "NO-THROW");
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

// a tbs with an explicit version [0] but only six children (SPKI
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
  var c = code(function () { pki.schema.x509.parse(cert); });
  check("short tbs (version + 6 children) throws a CertificateError, not a raw TypeError",
    typeof c === "string" && c.indexOf("x509/") === 0);
}

// two identical subjectKeyIdentifier extensions must be refused.
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
  check("duplicate extension rejected", code(function () { pki.schema.x509.parse(cert); }) === "x509/duplicate-extension");

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
    code(function () { pki.schema.x509.parse(multiOu); }) === "NO-THROW");
}

// the certificate version is validated against the RFC 5280 set.
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
  check("explicit version 41 rejected", code(function () { pki.schema.x509.parse(withVersion(41n)); }) === "x509/bad-version");
  check("explicit version -1 rejected", code(function () { pki.schema.x509.parse(withVersion(-1n)); }) === "x509/bad-version");
  check("explicitly-encoded default v1 rejected", code(function () { pki.schema.x509.parse(withVersion(0n)); }) === "x509/bad-version");

  // ENUMERATED shares INTEGER's content encoding but is a distinct universal type.
  // version and serialNumber are INTEGER-pinned, so an ENUMERATED at either
  // position is a type mismatch, rejected fail-closed (never coerced).
  var enumVersion = _cert([
    build.explicit(0, build.enumerated(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
    _name("issuer"), _validity(), _name("subject"), _spki(),
  ]);
  var ev = code(function () { pki.schema.x509.parse(enumVersion); });
  check("cert version encoded as ENUMERATED rejected", typeof ev === "string" && (ev.indexOf("x509/") === 0 || ev.indexOf("asn1/") === 0));
  var enumSerial = _cert([
    build.explicit(0, build.integer(2n)), build.enumerated(5n), _algId("1.2.840.10045.4.3.2"),
    _name("issuer"), _validity(), _name("subject"), _spki(),
  ]);
  var es = code(function () { pki.schema.x509.parse(enumSerial); });
  check("cert serialNumber encoded as ENUMERATED rejected", typeof es === "string" && (es.indexOf("x509/") === 0 || es.indexOf("asn1/") === 0));

  // SubjectPublicKeyInfo MUST be a universal SEQUENCE — a [0]-constructed node
  // carrying the right children is not a SEQUENCE and must be rejected.
  var ctxSpki = build.contextConstructed(0, Buffer.concat([_algId("1.2.840.10045.2.1"), build.bitString(Buffer.from([0x04, 1, 2, 3]), 0)]));
  var certCtxSpki = _cert([
    build.explicit(0, build.integer(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
    _name("issuer"), _validity(), _name("subject"), ctxSpki,
  ]);
  check("cert subjectPublicKeyInfo as [0]-constructed (non-SEQUENCE) rejected", code(function () { pki.schema.x509.parse(certCtxSpki); }) === "x509/bad-spki");

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
    var cert = pki.schema.x509.parse(v1);
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
  check("extensions on a v1 cert rejected", code(function () { pki.schema.x509.parse(v1WithExts); }) === "x509/bad-version");
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
  // No try/catch: these certs are built to parse; a regression that made one
  // throw should surface the real parse error, not be hidden behind a null.
  function dnOf(cert) { return pki.schema.x509.parse(cert).subject.dn; }

  // A malformed KNOWN string type (invalid UTF-8 UTF8String) must fail the
  // certificate closed — not hex-encode the invalid bytes away.
  var badCert = certWithDnValue(pki.asn1.encode(0x00, false, pki.asn1.TAGS.UTF8_STRING, Buffer.from([0xFF, 0xFE])));
  check("x509.parse rejects a malformed UTF8String in a DN (fails closed, not hex)",
    code(function () { pki.schema.x509.parse(badCert); }) === "x509/bad-atv");

  // A CONSTRUCTED encoding of a known string type is DER-illegal and must fail
  // the certificate closed at decode — it must NOT reach the RFC 4514 hex
  // fallback (which would bypass the restricted-string content checks). Only a
  // genuinely non-string constructed value (a SEQUENCE) takes the # fallback.
  check("x509.parse rejects a constructed string type in a DN (DER-illegal)",
    code(function () { pki.schema.x509.parse(certWithDnValue(pki.asn1.encode(0x00, true, pki.asn1.TAGS.UTF8_STRING, build.utf8("x")))); }) === "x509/bad-der");

  // An ANY-typed non-string value (INTEGER 5 = DER 02 01 05) is rendered as its
  // FULL DER encoding per RFC 4514 §2.4 — tag + length + content, not content-only.
  check("x509.parse hex-renders an ANY-typed DN value as full DER (#020105)",
    (dnOf(certWithDnValue(build.integer(5n))) || "").indexOf("#020105") !== -1);

  // A CONSTRUCTED ANY value (SEQUENCE{INTEGER 1} = DER 30 03 02 01 01) must NOT
  // reject the certificate: read.string throws asn1/expected-primitive, which is
  // a representable ANY value (RFC 4514 §2.4), not a malformed string.
  check("x509.parse hex-renders a constructed ANY DN value (does not reject)",
    (dnOf(certWithDnValue(build.sequence([build.integer(1n)]))) || "").indexOf("#3003020101") !== -1);

  // RFC 4514 sec. 2.4 escapes — a literal '#'-leading string is surfaced and
  // rendered escaped ('\#...'), so it cannot collide with the '#'+hex form the
  // non-string fallback emits; leading/trailing spaces and NUL are escaped too.
  check("x509.parse renders a literal '#'-leading string escaped, distinct from the hex form",
    dnOf(certWithDnValue(build.utf8("#0500"))) === "CN=\\#0500");
  check("literal '#'-leading value surfaced escaped in rdns",
    pki.schema.x509.parse(certWithDnValue(build.utf8("#0500"))).subject.rdns[0][0].value === "\\#0500");
  check("x509.parse escapes leading/trailing spaces in a DN value",
    dnOf(certWithDnValue(build.utf8(" padded "))) === "CN=\\ padded\\ ");
  check("x509.parse escapes NUL in a DN value",
    dnOf(certWithDnValue(build.utf8("a\u0000b"))) === "CN=a\\00b");
}

// RFC 5280 §4.1 — the optional trailing tbs fields (issuerUniqueID [1],
// subjectUniqueID [2], extensions [3]) each appear at most once, in strictly
// increasing tag order. A second [3] would otherwise overwrite the first and
// split duplicate extension OIDs across two wrappers past the per-sequence
// duplicate-extension check.
function testTbsTrailingFieldGrammar() {
  function tbs(trailing) {
    return _cert([
      build.explicit(0, build.integer(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
      _name("issuer"), _validity(), _name("subject"), _spki(),
    ].concat(trailing));
  }
  var exts = build.explicit(3, build.sequence([_ext("2.5.29.14")]));
  // [1] IMPLICIT BIT STRING (RFC 5280 sec. 4.1.2.8): context PRIMITIVE,
  // content = unusedBits octet + bits.
  var uid1 = build.contextPrimitive(1, Buffer.from([0x00, 0x01]));
  check("two [3] extension wrappers rejected",
    code(function () { pki.schema.x509.parse(tbs([exts, build.explicit(3, build.sequence([_ext("2.5.29.15")]))])); }) === "x509/bad-tbs");
  check("out-of-order trailing fields ([3] before [1]) rejected",
    code(function () { pki.schema.x509.parse(tbs([exts, uid1])); }) === "x509/bad-tbs");
  check("unknown trailing context tag [4] rejected",
    code(function () { pki.schema.x509.parse(tbs([build.explicit(4, build.integer(1n))])); }) === "x509/bad-tbs");
  check("a single extensions [3] still parses",
    code(function () { pki.schema.x509.parse(tbs([exts])); }) === "NO-THROW");
  check("ordered issuerUniqueID [1] then extensions [3] still parses",
    code(function () { pki.schema.x509.parse(tbs([uid1, exts])); }) === "NO-THROW");
}

// RFC 5280 sec. 4.1.2.8 — issuerUniqueID / subjectUniqueID MUST NOT appear
// when the version is 1; they require a v2 or v3 certificate.
function testUniqueIdVersionCoupling() {
  var uid1 = build.contextPrimitive(1, Buffer.from([0x00, 0x01]));
  var uid2 = build.contextPrimitive(2, Buffer.from([0x00, 0x01]));
  function v1Cert(trailing) {
    return _cert([
      build.integer(1n), _algId("1.2.840.10045.4.3.2"),
      _name("issuer"), _validity(), _name("subject"), _spki(),
    ].concat(trailing));
  }
  check("v1 cert with issuerUniqueID [1] rejected",
    code(function () { pki.schema.x509.parse(v1Cert([uid1])); }) === "x509/bad-version");
  check("v1 cert with subjectUniqueID [2] rejected",
    code(function () { pki.schema.x509.parse(v1Cert([uid2])); }) === "x509/bad-version");
  // v2 is the minimum version for the unique identifiers. RFC 5280 sec. 4.1.2.8:
  // the field is [1] IMPLICIT BIT STRING -- a context PRIMITIVE whose content
  // is unusedBits + bits, never an EXPLICIT wrap around a universal BIT STRING.
  function v2Cert(trailing) {
    return _cert([
      build.explicit(0, build.integer(1n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
      _name("issuer"), _validity(), _name("subject"), _spki(),
    ].concat(trailing));
  }
  var v2WithUid = v2Cert([build.contextPrimitive(1, Buffer.from([0x00, 0xAF]))]);
  check("v2 cert with IMPLICIT issuerUniqueID [1] parses",
    code(function () { pki.schema.x509.parse(v2WithUid); }) === "NO-THROW");
  check("constructed (EXPLICIT-wrapped) issuerUniqueID rejected",
    code(function () { pki.schema.x509.parse(v2Cert([build.explicit(1, build.bitString(Buffer.from([0x01]), 0))])); }) !== "NO-THROW");
  check("subjectUniqueID with unusedBits above 7 rejected",
    code(function () { pki.schema.x509.parse(v2Cert([build.contextPrimitive(2, Buffer.from([0x09, 0x01]))])); }) !== "NO-THROW");
}

// RFC 5280 sec. 4.1 -- Validity, TBSCertificate, and AttributeTypeAndValue are
// SEQUENCEs in the normative ASN.1; a SET-tagged (0x31) body is a different
// type a conforming decoder cannot decode, even though it is constructed.
function testSequenceTagEnforcement() {
  function setTag(der) { var c = Buffer.from(der); c[0] = 0x31; return c; }
  var sig = "1.2.840.10045.4.3.2";
  var tbsChildren = [build.integer(1n), _algId(sig), _name("issuer"), _validity(), _name("subject"), _spki()];
  var certSetTbs = build.sequence([setTag(build.sequence(tbsChildren)), _algId(sig), build.bitString(Buffer.from([0x30, 0x03]), 0)]);
  check("SET-tagged tbsCertificate rejected",
    code(function () { pki.schema.x509.parse(certSetTbs); }) === "x509/bad-tbs");
  var certSetValidity = _cert([build.integer(1n), _algId(sig), _name("issuer"), setTag(_validity()), _name("subject"), _spki()]);
  check("SET-tagged Validity rejected",
    code(function () { pki.schema.x509.parse(certSetValidity); }) === "x509/bad-validity");
  var badRdnName = build.sequence([build.set([setTag(_atv("2.5.4.3", "x"))])]);
  var certSetAtv = _cert([build.integer(1n), _algId(sig), badRdnName, _validity(), _name("subject"), _spki()]);
  check("SET-tagged AttributeTypeAndValue rejected",
    code(function () { pki.schema.x509.parse(certSetAtv); }) === "x509/bad-atv");
}

// RFC 5280 sec. 4.1.2.5 — validity dates through the year 2049 MUST be
// encoded as UTCTime; GeneralizedTime is reserved for 2050 or later.
function testValidityTimeEncodingCutover() {
  function certWithValidity(validityNode) {
    return _cert([
      build.explicit(0, build.integer(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
      _name("issuer"), validityNode, _name("subject"), _spki(),
    ]);
  }
  var genPre2050 = build.sequence([
    build.generalizedTime(new Date("2020-01-01T00:00:00Z")),
    build.utcTime(new Date("2030-01-01T00:00:00Z")),
  ]);
  check("notBefore as GeneralizedTime 2020 rejected (must be UTCTime through 2049)",
    code(function () { pki.schema.x509.parse(certWithValidity(genPre2050)); }) === "x509/bad-time");
  var genPost2050 = build.sequence([
    build.utcTime(new Date("2026-01-01T00:00:00Z")),
    build.generalizedTime(new Date("2050-01-01T00:00:00Z")),
  ]);
  check("notAfter as GeneralizedTime 2050 parses",
    code(function () { pki.schema.x509.parse(certWithValidity(genPost2050)); }) === "NO-THROW");
}

// Additional RFC 5280 tbsCertificate conformance MUSTs.
function testRfc5280Conformance() {
  // §4.1.1.2 — outer signatureAlgorithm MUST equal tbsCertificate.signature.
  function certSig(innerOid, outerOid) {
    var tbs = build.sequence([
      build.explicit(0, build.integer(2n)), build.integer(1n), _algId(innerOid),
      _name("issuer"), _validity(), _name("subject"), _spki(),
    ]);
    return build.sequence([tbs, _algId(outerOid), build.bitString(Buffer.from([0x30, 0x03]), 0)]);
  }
  check("mismatched outer/inner signatureAlgorithm rejected (algorithm substitution)",
    code(function () { pki.schema.x509.parse(certSig("1.2.840.10045.4.3.2", "1.2.840.10045.4.3.4")); }) === "x509/bad-signature-algorithm");
  check("matching signatureAlgorithm parses",
    code(function () { pki.schema.x509.parse(certSig("1.2.840.10045.4.3.2", "1.2.840.10045.4.3.2")); }) === "NO-THROW");

  // §4.1.2.9 — Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension.
  function certExt(extNode) {
    return _cert([
      build.explicit(0, build.integer(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
      _name("issuer"), _validity(), _name("subject"), _spki(), build.explicit(3, extNode),
    ]);
  }
  check("empty extensions SEQUENCE rejected",
    code(function () { pki.schema.x509.parse(certExt(build.sequence([]))); }) === "x509/bad-extensions");
  check("non-SEQUENCE extensions wrapper rejected (CertificateError, not a raw TypeError)",
    code(function () { pki.schema.x509.parse(certExt(build.integer(5n))); }) === "x509/bad-extensions");

  // §4.1.2.4 — issuer MUST be non-empty; §4.1.2.6 — empty subject is permitted.
  function certNames(issuerNode, subjectNode) {
    return _cert([
      build.explicit(0, build.integer(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
      issuerNode, _validity(), subjectNode, _spki(),
    ]);
  }
  check("empty issuer distinguished name rejected",
    code(function () { pki.schema.x509.parse(certNames(build.sequence([]), _name("subject"))); }) === "x509/bad-issuer");
  check("empty subject distinguished name permitted (subjectAltName case)",
    code(function () { pki.schema.x509.parse(certNames(_name("issuer"), build.sequence([]))); }) === "NO-THROW");
}

// A certificate is validated as a whole structure before the cross-field
// checks (signatureAlgorithm agreement §4.1.1.2, non-empty issuer §4.1.2.4,
// extension uniqueness §4.2) run, so which typed error a MULTIPLY-malformed
// certificate reports first is precedence-dependent and deliberately not
// pinned. The invariant that must hold for every such combination is that it
// stays fail-closed: rejected with a typed x509/* or asn1/* error, never
// accepted and never a raw crash.
function testMultiDefectFailClosed() {
  function rejected(label, cert) {
    var c = code(function () { pki.schema.x509.parse(cert); });
    check(label, c !== "NO-THROW" && c.indexOf("RAW:") !== 0);
  }
  var badValidity = build.sequence([build.utcTime(new Date("2026-01-01T00:00:00Z"))]); // 1 child, not 2
  rejected("multi-defect: sig-alg mismatch + malformed validity stays fail-closed", _cert([
    build.explicit(0, build.integer(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.4"),
    _name("issuer"), badValidity, _name("subject"), _spki(),
  ]));
  rejected("multi-defect: empty issuer + malformed validity stays fail-closed", _cert([
    build.explicit(0, build.integer(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
    build.sequence([]), badValidity, _name("subject"), _spki(),
  ]));
  var dupExts = build.explicit(3, build.sequence([
    _ext("2.5.29.14"),
    build.sequence([build.oid("2.5.29.14"), build.integer(5n)]), // dup OID, value is INTEGER not OCTET STRING
  ]));
  rejected("multi-defect: duplicate extension OID + malformed value stays fail-closed", _cert([
    build.explicit(0, build.integer(2n)), build.integer(1n), _algId("1.2.840.10045.4.3.2"),
    _name("issuer"), _validity(), _name("subject"), _spki(), dupExts,
  ]));
}

// RFC 3739 sec. 3.2.6 + ETSI EN 319 412-5 qualified-certificate statements (the id-pe-qcStatements
// extension decoder registered in certExtensionDecoders, surfaced via x509.parse -> byOid).
function testQcStatements() {
  var NS = pkix.makeNS("path", pki.errors.PathError, oidReg);
  var qcOid = oidReg.byName("qcStatements");
  var dec = pkix.certExtensionDecoders(NS).byOid[qcOid];
  var C = oidReg.byName("qcCompliance"), L = oidReg.byName("qcLimitValue"), SSCD = oidReg.byName("qcSSCD");
  var T = oidReg.byName("qcType"), Tesign = oidReg.byName("qctEsign"), Tweb = oidReg.byName("qctWeb");
  var V1 = oidReg.byName("qcsPkixQCSyntaxV1");

  // 1. QcCompliance (info-absent) accepts; info === null.
  var r1 = dec(build.sequence([build.sequence([build.oid(C)])]));
  check("qc: QcCompliance decodes info-absent", r1.length === 1 && r1[0].statementId === C && r1[0].name === "qcCompliance" && r1[0].info === null);
  // 2. QcType (SEQUENCE OF OID) -> types + typeNames.
  var r2 = dec(build.sequence([build.sequence([build.oid(T), build.sequence([build.oid(Tesign), build.oid(Tweb)])])]));
  check("qc: QcType decodes the purpose OIDs + names", r2[0].name === "qcType" && r2[0].info.types.join(",") === Tesign + "," + Tweb && r2[0].info.typeNames.join(",") === "qctEsign,qctWeb");
  // 3. QcLimitValue MonetaryValue (alphabetic currency), uint31/int-narrowed to Numbers.
  var r3 = dec(build.sequence([build.sequence([build.oid(L), build.sequence([build.printable("EUR"), build.integer(100000n), build.integer(2n)])])]));
  check("qc: QcLimitValue decodes currency/amount/exponent", r3[0].info.currency === "EUR" && r3[0].info.amount === 100000 && r3[0].info.exponent === 2);
  // 4. Unknown statementId preserved OPAQUE (no throw), raw statementInfo TLV byte-identical.
  var infoTlv = build.utf8("whatever");
  var r4 = dec(build.sequence([build.sequence([build.oid("1.3.6.1.4.1.99999.1"), infoTlv])]));
  check("qc: unknown statementId preserved opaque", r4[0].name === null && r4[0].info.opaque === true && Buffer.isBuffer(r4[0].info.bytes) && r4[0].info.bytes.equals(infoTlv));
  // 5-8. Structural rejects.
  check("qc: not a SEQUENCE -> bad-qc-statements", code(function () { dec(build.integer(5n)); }) === "path/bad-qc-statements");
  check("qc: non-OID statementId -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.integer(1n), build.nullValue()])])); }) === "path/bad-qc-statement");
  // RFC 3739 defines QCStatements as a SEQUENCE OF QCStatement with no uniqueness constraint, so a
  // repeated statementId is valid on the wire -- every statement decodes in order (a linter may flag the
  // repeat; the decoder must not drop it and make the extension undecodable for inspect / lint).
  var rDup = dec(build.sequence([build.sequence([build.oid(C)]), build.sequence([build.oid(C)])]));
  check("qc: a repeated statementId decodes in wire order (no uniqueness constraint)", rDup.length === 2 && rDup[0].name === "qcCompliance" && rDup[1].name === "qcCompliance");
  check("qc: empty SEQUENCE OF -> bad-qc-statements", code(function () { dec(build.sequence([])); }) === "path/bad-qc-statements");
  // 9. A presence-only statement carrying statementInfo rejects.
  check("qc: QcCompliance with statementInfo -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(C), build.nullValue()])])); }) === "path/bad-qc-statement");
  check("qc: QcSSCD with statementInfo -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(SSCD), build.nullValue()])])); }) === "path/bad-qc-statement");
  // 10. QcType shape violations.
  check("qc: QcType member not an OID -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(T), build.sequence([build.integer(1n)])])])); }) === "path/bad-qc-statement");
  check("qc: QcType empty inner -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(T), build.sequence([])])])); }) === "path/bad-qc-statement");
  check("qc: QcType statementInfo absent -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(T)])])); }) === "path/bad-qc-statement");
  // 11. QcLimitValue currency arms.
  check("qc: QcLimitValue bad alphabetic currency length -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(L), build.sequence([build.printable("EU"), build.integer(1n), build.integer(0n)])])])); }) === "path/bad-qc-statement");
  var rNum = dec(build.sequence([build.sequence([build.oid(L), build.sequence([build.integer(978n), build.integer(1n), build.integer(0n)])])]));
  check("qc: QcLimitValue numeric currency accepts", rNum[0].info.currency === 978);
  check("qc: QcLimitValue numeric currency out of range -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(L), build.sequence([build.integer(1000n), build.integer(1n), build.integer(0n)])])])); }) === "path/bad-qc-statement");
  // 12. Mixed statements: wire order preserved, known + unknown coexist.
  var r12 = dec(build.sequence([build.sequence([build.oid(C)]), build.sequence([build.oid(T), build.sequence([build.oid(Tesign)])]), build.sequence([build.oid("1.3.6.1.4.1.99999.2"), build.printable("x")])]));
  check("qc: mixed statements preserve order + known/unknown", r12.length === 3 && r12[0].info === null && r12[1].info.types[0] === Tesign && r12[2].info.opaque === true && r12[2].name === null);
  // 16. SemanticsInformation (v1): at least one field; empty rejects.
  var r16 = dec(build.sequence([build.sequence([build.oid(V1), build.sequence([build.oid("1.3.6.1.4.1.99999.9")])])]));
  check("qc: SemanticsInformation decodes semanticsIdentifier", r16[0].info.semanticsIdentifier === "1.3.6.1.4.1.99999.9" && r16[0].info.nameRegistrationAuthorities.length === 0);
  check("qc: empty SemanticsInformation -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(V1), build.sequence([])])])); }) === "path/bad-qc-statement");
  // SemanticsInformation with nameRegistrationAuthorities (a SEQUENCE OF GeneralName); a QCStatement of >2 children.
  var rSem = dec(build.sequence([build.sequence([build.oid(V1), build.sequence([build.oid("1.2.3.4"), build.sequence([build.contextPrimitive(6, Buffer.from("https://ra", "ascii"))])])])]));
  check("qc: SemanticsInformation decodes nameRegistrationAuthorities", rSem[0].info.semanticsIdentifier === "1.2.3.4" && rSem[0].info.nameRegistrationAuthorities.length === 1);
  check("qc: a nameRegistrationAuthority that is not a GeneralName -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(V1), build.sequence([build.oid("1.2.3"), build.sequence([build.integer(5n)])])])])); }) === "path/bad-qc-statement");
  check("qc: a QCStatement of more than two elements -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(C), build.nullValue(), build.nullValue()])])); }) === "path/bad-qc-statement");
  // ETSI V2.5.1 additions: QcIdentMethod (SEQUENCE OF OID) + QcQSCDlegislation (SEQUENCE OF CountryName).
  var IM = oidReg.byName("qcIdentMethod"), QSCDL = oidReg.byName("qcQSCDlegislation");
  check("qc: QcIdentMethod decodes its method OIDs", dec(build.sequence([build.sequence([build.oid(IM), build.sequence([build.oid("1.2.3.4")])])]))[0].info.methods[0] === "1.2.3.4");
  check("qc: QcQSCDlegislation decodes its country codes", dec(build.sequence([build.sequence([build.oid(QSCDL), build.sequence([build.printable("DE")])])]))[0].info.countries[0] === "DE");
  // Remaining ETSI statement decoders + the signed MonetaryValue exponent.
  var RP = oidReg.byName("qcRetentionPeriod"), PDS = oidReg.byName("qcPDS"), CCL = oidReg.byName("qcCClegislation");
  check("qc: QcRetentionPeriod decodes the year count", dec(build.sequence([build.sequence([build.oid(RP), build.integer(10n)])]))[0].info.years === 10);
  var rPds = dec(build.sequence([build.sequence([build.oid(PDS), build.sequence([build.sequence([build.ia5("https://x/pds"), build.printable("en")])])])]));
  check("qc: QcPDS decodes url + language", rPds[0].info.locations[0].url === "https://x/pds" && rPds[0].info.locations[0].language === "en");
  check("qc: QcPDS bad language length -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(PDS), build.sequence([build.sequence([build.ia5("u"), build.printable("eng")])])])])); }) === "path/bad-qc-statement");
  // ETSI EN 319 412-5 Annex B: PdsLocation ::= SEQUENCE { url IA5String, language PrintableString (SIZE(2)) }
  // -- language is mandatory (no OPTIONAL) in every version V1.1.1..V2.5.1; a location missing it is
  // non-conformant and fails closed (inspect degrades to opaque bytes). Do not loosen to accept one child.
  check("qc: QcPDS language-less location -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(PDS), build.sequence([build.sequence([build.ia5("https://x/pds")])])])])); }) === "path/bad-qc-statement");
  var rCcl = dec(build.sequence([build.sequence([build.oid(CCL), build.sequence([build.printable("US"), build.printable("CA")])])]));
  check("qc: QcCClegislation decodes the country codes", rCcl[0].info.countries.join(",") === "US,CA");
  check("qc: QcCClegislation bad country length -> bad-qc-statement", code(function () { dec(build.sequence([build.sequence([build.oid(CCL), build.sequence([build.printable("USA")])])])); }) === "path/bad-qc-statement");
  var rNeg = dec(build.sequence([build.sequence([build.oid(L), build.sequence([build.printable("USD"), build.integer(100n), build.integer(-2n)])])]));
  check("qc: QcLimitValue decodes a negative (fractional) exponent", rNeg[0].info.exponent === -2);
  var rBig = dec(build.sequence([build.sequence([build.oid(L), build.sequence([build.printable("JPY"), build.integer(5000000000n), build.integer(0n)])])]));
  check("qc: QcLimitValue accepts a large amount beyond uint31", rBig[0].info.amount === 5000000000);
  var rExp = dec(build.sequence([build.sequence([build.oid(L), build.sequence([build.printable("USD"), build.integer(1n), build.integer(1000n)])])]));
  check("qc: QcLimitValue accepts an exponent beyond a small window", rExp[0].info.exponent === 1000);
  // A PrintableString currency carrying a disallowed byte (0x40 '@', not in the PrintableString set)
  // decodes structurally but fails the leaf read; the decoder must surface its own typed
  // bad-qc-statement, not leak asn1/bad-printable-string. Raw TLV: 13 03 'U' 'S' '@'.
  check("qc: QcLimitValue currency with a disallowed byte -> bad-qc-statement (typed, not asn1/*)", code(function () { dec(build.sequence([build.sequence([build.oid(L), build.sequence([build.raw(Buffer.from([0x13, 0x03, 0x55, 0x53, 0x40])), build.integer(1n), build.integer(0n)])])])); }) === "path/bad-qc-statement");

  // 13. Orchestrator: the SHIPPED consumer path (x509.parse -> extensions -> byOid).
  function _certWithQc(critical, qcVal) {
    var ext = [build.oid(qcOid)];
    if (critical) ext.push(build.boolean(true));
    ext.push(build.octetString(qcVal));
    return _cert([build.explicit(0, build.integer(2n)), build.integer(2n), _algId("1.2.840.10045.4.3.2"),
      _name("issuer"), _validity(), _name("subj"), _spki(), build.explicit(3, build.sequence([build.sequence(ext)]))]);
  }
  var qcVal = build.sequence([build.sequence([build.oid(C)]), build.sequence([build.oid(T), build.sequence([build.oid(Tweb)])]), build.sequence([build.oid("1.3.6.1.4.1.99999.3"), build.printable("z")])]);
  var certDer = _certWithQc(false, qcVal);
  var parsed = pki.schema.x509.parse(certDer);
  var qcExt = parsed.extensions.filter(function (e) { return e.oid === qcOid; })[0];
  check("qc: x509.parse surfaces the qcStatements extension (name + raw value)", qcExt && qcExt.name === "qcStatements" && Buffer.isBuffer(qcExt.value));
  var decoded = pkix.certExtensionDecoders(NS).byOid[qcExt.oid](qcExt.value);
  check("qc: orchestrator parse -> extensions -> byOid decodes end to end", decoded[0].name === "qcCompliance" && decoded[1].info.typeNames[0] === "qctWeb");

  // 14. inspect renders the decoded statements AND their decoded values (not just the name, not raw
  // bytes): the cert carries a QcType(web), so the rendered purpose value must appear.
  var rendered = pki.inspect.certificate(certDer);
  check("qc: inspect renders the decoded qcStatement names", /qcCompliance|qcType/i.test(rendered));
  check("qc: inspect renders the decoded qcStatement values (QcType purpose)", /qctWeb/i.test(rendered));
  // Exercise every value-bearing renderer branch (QcLimitValue amount, QcRetentionPeriod years, QcPDS
  // location, legislation countries) so a statement's decoded payload -- not just its name -- is shown.
  // IM (qcIdentMethod) is already in scope from the decode vectors above.
  var richQc = build.sequence([
    build.sequence([build.oid(L), build.sequence([build.printable("USD"), build.integer(100000n), build.integer(0n)])]),
    build.sequence([build.oid(RP), build.integer(10n)]),
    build.sequence([build.oid(PDS), build.sequence([build.sequence([build.ia5("https://x/pds"), build.printable("en")])])]),
    build.sequence([build.oid(CCL), build.sequence([build.printable("DE"), build.printable("FR")])]),
    build.sequence([build.oid(IM), build.sequence([build.oid("0.4.0.1862.1.8.1")])]),
    build.sequence([build.oid(V1), build.sequence([build.oid("1.2.3.4")])]),   // SemanticsInformation (id-qcs)
    build.sequence([build.oid("1.2.3.99")])]);                                 // unknown statementId -> opaque
  var richRendered = pki.inspect.certificate(_certWithQc(false, richQc));
  check("qc: inspect renders a QcLimitValue amount", /100000 USD/.test(richRendered));
  check("qc: inspect renders a QcRetentionPeriod", /10 years/.test(richRendered));
  check("qc: inspect renders a QcPDS location", /https:\/\/x\/pds \(en\)/.test(richRendered));
  check("qc: inspect renders QcCClegislation countries", /DE, FR/.test(richRendered));
  check("qc: inspect renders a SemanticsInformation identifier", /1\.2\.3\.4/.test(richRendered));
  check("qc: inspect renders an unknown statement as opaque", /1\.2\.3\.99 \(opaque\)/.test(richRendered));

  // 15. A CRITICAL qcStatements IS flagged unknown-critical: its qualified-certificate semantics are
  // not processed here (path-validate rejects a critical instance for the same reason), so the linter
  // must surface it. Findings expose the rule id as .id (not .code) and the extension via .context.
  var critCertDer = _certWithQc(true, build.sequence([build.sequence([build.oid(C)])]));
  var lintFindings = pki.lint.certificate(critCertDer).findings;
  check("qc: a critical qcStatements is flagged unknown-critical", lintFindings.some(function (f) { return f.id === "lint/rfc5280/unknown-critical-extension" && f.context && f.context.name === "qcStatements"; }));
}

// [MS-WCCE] / [MS-CRTD] Microsoft enterprise CA certificate extensions -- the five
// certExtensionDecoders rows (certificate template v2, v1 enroll cert-type name, CA version,
// previous-CA-cert hash, application policies) surfaced via x509.parse -> byOid + pki.inspect.
function testMsCaExtensions() {
  var NS = pkix.makeNS("path", pki.errors.PathError, oidReg);
  var byOid = pkix.certExtensionDecoders(NS).byOid;
  var TPL = oidReg.byName("msCertificateTemplate"), ECT = oidReg.byName("msEnrollCertType");
  var CAV = oidReg.byName("msCaVersion"), PCH = oidReg.byName("msPreviousCertHash");
  var AP = oidReg.byName("msApplicationPolicies"), CP = oidReg.byName("certificatePolicies");
  var tpl = byOid[TPL], ect = byOid[ECT], cav = byOid[CAV], pch = byOid[PCH];
  function _certWithExt(extOid, critical, valBytes) {
    var ext = [build.oid(extOid)];
    if (critical) ext.push(build.boolean(true));
    ext.push(build.octetString(valBytes));
    return _cert([build.explicit(0, build.integer(2n)), build.integer(2n), _algId("1.2.840.10045.4.3.2"),
      _name("issuer"), _validity(), _name("subj"), _spki(), build.explicit(3, build.sequence([build.sequence(ext)]))]);
  }

  // --- 1. msCertificateTemplate (CertificateTemplateOID) ---
  var t1 = tpl(build.sequence([build.oid("1.2.3"), build.integer(100n), build.integer(0n)]));
  check("ms: template full -> {id, major, minor}", t1.templateID === "1.2.3" && t1.templateMajorVersion === 100 && t1.templateMinorVersion === 0);
  var t2 = tpl(build.sequence([build.oid("1.2.3")]));
  check("ms: template OID-only -> both versions null", t2.templateMajorVersion === null && t2.templateMinorVersion === null);
  var t3 = tpl(build.sequence([build.oid("1.2.3"), build.integer(100n)]));
  check("ms: template major-only -> minor null", t3.templateMajorVersion === 100 && t3.templateMinorVersion === null);
  var t4 = tpl(build.sequence([build.oid("1.2.3"), build.integer(2147483649n)]));   // 0x80000001, a DWORD > 2^31-1
  check("ms: template major accepts a DWORD beyond uint31", t4.templateMajorVersion === 2147483649);
  check("ms: template missing templateID -> bad-ms-certificate-template", code(function () { tpl(build.sequence([])); }) === "path/bad-ms-certificate-template");
  check("ms: template non-OID first child -> reject", code(function () { tpl(build.sequence([build.integer(100n)])); }) === "path/bad-ms-certificate-template");
  check("ms: template trailing 4th field -> reject", code(function () { tpl(build.sequence([build.oid("1.2.3"), build.integer(1n), build.integer(0n), build.integer(1n)])); }) === "path/bad-ms-certificate-template");
  check("ms: template non-minimal major INTEGER -> reject", code(function () { tpl(build.sequence([build.oid("1.2.3"), build.raw(Buffer.from([0x02, 0x02, 0x00, 0x64]))])); }) === "path/bad-ms-certificate-template");

  // --- 2. msEnrollCertType (bare BMPString "User" = 1e 08 00 55 00 73 00 65 00 72) ---
  check("ms: enroll cert-type BMPString decodes", ect(build.raw(Buffer.from([0x1e, 0x08, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72]))) === "User");
  check("ms: enroll cert-type empty BMPString -> ''", ect(build.raw(Buffer.from([0x1e, 0x00]))) === "");
  check("ms: enroll cert-type wrong string type (UTF8) -> reject", code(function () { ect(build.utf8("User")); }) === "path/bad-ms-enroll-cert-type");
  check("ms: enroll cert-type odd BMP length -> reject", code(function () { ect(build.raw(Buffer.from([0x1e, 0x03, 0x00, 0x55, 0x00]))); }) === "path/bad-ms-enroll-cert-type");

  // --- 3. msCaVersion (INTEGER, keyIndex<<16 | certIndex) ---
  var v1 = cav(build.integer(65541n));   // 0x00010005
  check("ms: CA version splits keyIndex/certIndex", v1.caVersion === 65541 && v1.caKeyIndex === 1 && v1.certIndex === 5);
  var v2 = cav(build.integer(2147483648n));   // 0x80000000, high bit set
  check("ms: CA version high-bit DWORD (not uint31)", v2.caKeyIndex === 32768 && v2.certIndex === 0);
  var v3 = cav(build.integer(4294967295n));   // 0xFFFFFFFF
  check("ms: CA version max DWORD splits", v3.caKeyIndex === 65535 && v3.certIndex === 65535);
  check("ms: CA version negative -> reject", code(function () { cav(build.integer(-1n)); }) === "path/bad-ms-ca-version");
  check("ms: CA version over DWORD -> reject", code(function () { cav(build.integer(4294967296n)); }) === "path/bad-ms-ca-version");
  check("ms: CA version wrong tag (OCTET STRING) -> reject", code(function () { cav(build.octetString(Buffer.from([0, 1, 0, 5]))); }) === "path/bad-ms-ca-version");

  // --- 4. msPreviousCertHash (the SHA-1 thumbprint of the prior CA cert -- exactly 20 octets) ---
  check("ms: previous-cert-hash SHA-1 (20) -> Buffer(20)", pch(build.octetString(Buffer.alloc(20, 0xab))).length === 20);
  check("ms: previous-cert-hash SHA-256 length (32) -> reject (not a SHA-1 thumbprint)", code(function () { pch(build.octetString(Buffer.alloc(32, 0xcd))); }) === "path/bad-ms-previous-cert-hash");
  check("ms: previous-cert-hash empty -> reject", code(function () { pch(build.octetString(Buffer.alloc(0))); }) === "path/bad-ms-previous-cert-hash");
  check("ms: previous-cert-hash 19 octets -> reject (off-by-one)", code(function () { pch(build.octetString(Buffer.alloc(19, 0x01))); }) === "path/bad-ms-previous-cert-hash");
  check("ms: previous-cert-hash wrong tag (INTEGER) -> reject", code(function () { pch(build.integer(0n)); }) === "path/bad-ms-previous-cert-hash");

  // --- 5. msApplicationPolicies (= RFC 5280 certificatePolicies, reuse not re-impl) ---
  check("ms: application-policies reuses the certificatePolicies closure (identity)", byOid[AP] === byOid[CP]);
  var ap = byOid[AP](build.sequence([build.sequence([build.oid("2.5")])]));
  check("ms: application-policies decodes a PolicyInformation", ap[0].policyIdentifier === "2.5");
  check("ms: application-policies empty SEQUENCE -> reject", code(function () { byOid[AP](build.sequence([])); }) !== "NO-THROW");

  // --- strict-DER: trailing bytes after the TLV and constructed strings fail closed with the typed code ---
  check("ms: CA version with trailing bytes -> reject", code(function () { cav(Buffer.concat([build.integer(65541n), Buffer.from([0xff, 0xff])])); }) === "path/bad-ms-ca-version");
  check("ms: CA version non-minimal INTEGER -> reject", code(function () { cav(build.raw(Buffer.from([0x02, 0x02, 0x00, 0x05]))); }) === "path/bad-ms-ca-version");
  check("ms: template with trailing bytes -> reject", code(function () { tpl(Buffer.concat([build.sequence([build.oid("1.2.3")]), Buffer.from([0x00])])); }) === "path/bad-ms-certificate-template");
  check("ms: constructed BMPString enroll cert-type -> reject", code(function () { ect(build.raw(Buffer.from([0x3e, 0x04, 0x1e, 0x02, 0x00, 0x55]))); }) === "path/bad-ms-enroll-cert-type");
  check("ms: constructed OCTET STRING previous-cert-hash -> reject", code(function () { pch(build.raw(Buffer.from([0x24, 0x04, 0x04, 0x02, 0xab, 0xcd]))); }) === "path/bad-ms-previous-cert-hash");

  // --- orchestrator: x509.parse -> extensions -> byOid, per extension ---
  var certDer = _certWithExt(TPL, false, build.sequence([build.oid("1.2.3"), build.integer(5n), build.integer(2n)]));
  var parsed = pki.schema.x509.parse(certDer);
  var extNode = parsed.extensions.filter(function (e) { return e.oid === TPL; })[0];
  check("ms: orchestrator surfaces msCertificateTemplate on x509.parse", !!extNode && byOid[TPL](extNode.value).templateMajorVersion === 5);

  // --- inspect renders each extension's decoded values ---
  var rTpl = pki.inspect.certificate(certDer);
  check("ms: inspect renders the template id + version", /1\.2\.3/.test(rTpl) && /v5\.2|5\.2/.test(rTpl));
  var rCav = pki.inspect.certificate(_certWithExt(CAV, false, build.integer(65541n)));
  check("ms: inspect renders the CA version", /1\.5/.test(rCav));
  var rPch = pki.inspect.certificate(_certWithExt(PCH, false, build.octetString(Buffer.from("deadbeef".repeat(5), "hex"))));
  check("ms: inspect renders the previous-cert-hash upper-hex", /DE:AD:BE:EF/.test(rPch));
  var rEct = pki.inspect.certificate(_certWithExt(ECT, false, build.raw(Buffer.from([0x1e, 0x08, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72]))));
  check("ms: inspect renders the enroll cert-type name", /User/.test(rEct));
  var rTplOid = pki.inspect.certificate(_certWithExt(TPL, false, build.sequence([build.oid("1.4.9")])));
  check("ms: inspect renders an OID-only template (no version suffix)", /Template: 1\.4\.9/.test(rTplOid) && !/1\.4\.9 v/.test(rTplOid));
  var rTplMaj = pki.inspect.certificate(_certWithExt(TPL, false, build.sequence([build.oid("1.4.9"), build.integer(5n)])));
  check("ms: inspect renders a major-only template (minor defaults to 0)", /1\.4\.9 v5\.0/.test(rTplMaj));
}

function run() {
  testParseFields();
  testExtensions();
  testQcStatements();
  testMsCaExtensions();
  testPem();
  testRejects();
  testShortTbsWithVersion();
  testDuplicateExtension();
  testVersionValidation();
  testMalformedDnStringRejected();
  testTbsTrailingFieldGrammar();
  testUniqueIdVersionCoupling();
  testSequenceTagEnforcement();
  testValidityTimeEncodingCutover();
  testRfc5280Conformance();
  testMultiDefectFailClosed();
  testMlKemCertificates();
}

// ML-KEM certificates (RFC 9935): the parse acceptance surface for all three parameter
// sets -- OID resolution both directions, ABSENT parameters (the shared algorithmIdentifier
// choke point rejects NULL/present), the raw ek surfaced byte-exact, orchestrator routing,
// and the published App C.3 certificates. Parse stays size-agnostic (house precedent:
// sizes enforce in lint + at the import boundary).
function testMlKemCertificates() {
  var fs = require("fs");
  var path = require("path");
  var FIX = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "mlkem", "rfc9935-appc.json"), "utf8")).vectors;
  function fx(n) { return Buffer.from(FIX[n].derHex, "hex"); }
  var b = pki.asn1.build;
  var EK_LEN = { 512: 800, 768: 1184, 1024: 1568 };
  [512, 768, 1024].forEach(function (set) {
    var certDer = fx("cert-" + set);
    var c = pki.schema.x509.parse(certDer);
    check("ML-KEM-" + set + " published cert (RFC 9935 C.3) parses with the id-ml-kem OID resolved",
      c.subjectPublicKeyInfo.algorithm.name === "id-ml-kem-" + set &&
      c.subjectPublicKeyInfo.algorithm.oid === oidReg.byName("id-ml-kem-" + set));
    check("ML-KEM-" + set + " SPKI parameters are absent (RFC 9935 sec. 3)",
      c.subjectPublicKeyInfo.algorithm.parameters === null);
    check("ML-KEM-" + set + " raw ek surfaced at its exact FIPS 203 size",
      c.subjectPublicKeyInfo.publicKey.bytes.length === EK_LEN[set]);
    check("ML-KEM-" + set + " orchestrator routes to x509", (function () { var r = pki.schema.parse(certDer); return r.tbsBytes !== undefined && r.subjectPublicKeyInfo.algorithm.name === "id-ml-kem-" + set; })());
  });
  // The shared algorithmIdentifier choke point: NULL parameters on an ML-KEM SPKI reject.
  var good = pki.asn1.decode(fx("cert-768"));
  var tbs = good.children[0];
  var ek = pki.asn1.read.bitString(tbs.children[6].children[1]).bytes;
  var badSpki = b.sequence([b.sequence([b.oid(oidReg.byName("id-ml-kem-768")), b.nullValue()]), b.bitString(ek, 0)]);
  var kids = tbs.children.map(function (ch) { return ch.bytes; });
  kids[6] = badSpki;
  var badCert = b.sequence([b.sequence(kids), good.children[1].bytes, good.children[2].bytes]);
  check("ML-KEM SPKI with NULL parameters -> rejected by the shared algorithmIdentifier choke point",
    code(function () { pki.schema.x509.parse(badCert); }) !== "NO-THROW");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
