// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.x509
 * @nav        Schema
 * @title      X.509
 * @order      100
 * @featured   true
 * @slug       x509
 *
 * @intro
 *   X.509 certificate handling per RFC 5280. The seed surface is
 *   `parse` — turn a DER or PEM certificate into a structured,
 *   fully-decoded object: version, serial, signature algorithm, issuer
 *   and subject distinguished names, validity window (as real `Date`s),
 *   subject public-key info, and the extension list. The parser composes
 *   the strict DER codec and the OID registry, so every field is
 *   validated on the way in and every algorithm / attribute / extension
 *   is named where the registry knows it.
 *
 *   The raw `tbsCertificate` bytes are returned alongside the parsed
 *   fields so a signature-verification layer can hash exactly the bytes
 *   that were signed rather than re-encoding and hoping for round-trip
 *   fidelity.
 *
 * @card
 *   Parse DER / PEM X.509 certificates into structured, validated fields
 *   with named algorithms, extensions, and real-`Date` validity windows.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var pkix = require("./schema-pkix");

var CertificateError = frameworkError.CertificateError;
var PemError = frameworkError.PemError;

// ---- PEM -------------------------------------------------------------

/**
 * @primitive  pki.schema.x509.pemDecode
 * @signature  pki.schema.x509.pemDecode(text, label?) -> Buffer
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.schema.x509.pemEncode
 *
 * Extract the DER bytes from a PEM block. With `label` given (e.g.
 * `"CERTIFICATE"`) the block type must match; without it, the first block
 * is taken. Throws `PemError` on a missing / mismatched envelope or a
 * non-base64 body.
 *
 * @example
 *   var der = pki.schema.x509.pemDecode(pemText, "CERTIFICATE");
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label, PemError); }

/**
 * @primitive  pki.schema.x509.pemEncode
 * @signature  pki.schema.x509.pemEncode(der, label) -> string
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 7468, RFC 5280
 * @related    pki.schema.x509.pemDecode
 *
 * Wrap DER bytes in a PEM envelope with 64-column base64 lines.
 *
 * @example
 *   var pem = pki.schema.x509.pemEncode(der, "CERTIFICATE");
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label, PemError); }

// ---- helpers ---------------------------------------------------------

// The x509 error namespace the schema engine walks under: prefix names the
// error family and E constructs the typed CertificateError. The shared PKIX
// sub-schemas (AlgorithmIdentifier, Name, Extension) live in lib/pkix-schema.js
// as ns-parameterized factories so crl.js / cms.js reuse them while emitting
// their own crl/*, cms/* codes; here they are instantiated under this NS.
var NS = { prefix: "x509", E: function (code, message) { return new CertificateError(code, message); }, oid: oid };

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var NAME = pkix.name(NS);

// Validity ::= SEQUENCE { notBefore Time, notAfter Time }. The historical guard
// checked only children.length===2 (not the SEQUENCE tag) -> assert "constructed".
var VALIDITY = schema.seq([
  schema.field("notBefore", schema.time(NS)),
  schema.field("notAfter", schema.time(NS)),
], {
  assert: "constructed", arity: { exact: 2 }, code: "x509/bad-validity", what: "Validity",
  build: function (m) { return { notBefore: m.fields.notBefore.value, notAfter: m.fields.notAfter.value }; },
});

// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
var SPKI = schema.seq([
  schema.field("algorithm", ALGORITHM_IDENTIFIER),
  schema.field("subjectPublicKey", schema.bitString()),
], {
  assert: "constructed", arity: { exact: 2 }, code: "x509/bad-spki", what: "SubjectPublicKeyInfo",
  build: function (m) {
    return {
      algorithm: m.fields.algorithm.value.result, // algorithm field = ALGORITHM_IDENTIFIER seq-match; .value = its build
      publicKey: { unusedBits: m.fields.subjectPublicKey.value.unusedBits, bytes: m.fields.subjectPublicKey.value.bytes },
      bytes: m.node.bytes,
    };
  },
});

var EXTENSIONS = pkix.extensions(NS);

// Version ::= INTEGER { v1(0), v2(1), v3(2) }, [0] EXPLICIT DEFAULT v1. Read as a
// BigInt so an out-of-range value can't coerce to a float; reject an explicitly-
// encoded v1 (DER forbids encoding the DEFAULT).
function readVersion(ns) {
  return schema.decode(function (n) {
    var v = asn1.read.integer(n);
    if (v === 0n) throw ns.E(ns.prefix + "/bad-version", "DER forbids explicitly encoding the default version v1");
    if (v === 1n) return 2;
    if (v === 2n) return 3;
    throw ns.E(ns.prefix + "/bad-version", "unsupported certificate version " + v.toString());
  });
}

// TBSCertificate ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1, serialNumber
// INTEGER, signature AlgorithmIdentifier, issuer Name, validity Validity,
// subject Name, subjectPublicKeyInfo SubjectPublicKeyInfo, issuerUniqueID [1]
// IMPLICIT OPTIONAL, subjectUniqueID [2] IMPLICIT OPTIONAL, extensions [3]
// EXPLICIT OPTIONAL }. The trailing fields are at-most-once, in increasing tag
// order (the engine enforces it); only extensions are surfaced.
var CERTIFICATE_TBS = schema.seq([
  schema.optional("version", readVersion(NS), { tag: 0, explicit: true, emptyCode: "x509/bad-version", default: 1 }),
  schema.field("serialNumber", schema.integerLeaf()),
  schema.field("signature", ALGORITHM_IDENTIFIER),
  schema.field("issuer", NAME),
  schema.field("validity", VALIDITY),
  schema.field("subject", NAME),
  schema.field("subjectPublicKeyInfo", SPKI),
  schema.trailing([
    { tag: 1, name: "issuerUniqueID", schema: schema.any() },
    { tag: 2, name: "subjectUniqueID", schema: schema.any() },
    { tag: 3, name: "extensions", schema: EXTENSIONS, explicit: true, emptyCode: "x509/bad-extensions" },
  ], { minTag: 1, maxTag: 3, unexpectedCode: "x509/bad-tbs", orderCode: "x509/bad-tbs" }),
], { assert: "constructed", code: "x509/bad-tbs", what: "tbsCertificate" });

// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue
// BIT STRING }. The build runs the RFC 5280 cross-field checks (§4.1.1.2 sig-alg
// agreement, §4.1.2.4 non-empty issuer, §4.1.2.9 extensions-only-in-v3) after the
// structural walk, then assembles the public parse result. Raw-byte accessors
// (serialNumberHex, tbsBytes, sig-alg agreement) read off the match-tree nodes.
var CERTIFICATE = schema.seq([
  schema.field("tbsCertificate", CERTIFICATE_TBS),
  schema.field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("signatureValue", schema.bitString()),
], {
  assert: "sequence", arity: { exact: 3 }, code: "x509/not-a-certificate", what: "Certificate",
  build: function (m, ctx) {
    var tbs = m.fields.tbsCertificate.value; // CERTIFICATE_TBS seq-match (no build)

    // RFC 5280 §4.1.1.2 — outer signatureAlgorithm MUST equal tbsCertificate.signature.
    if (!m.fields.signatureAlgorithm.node.bytes.equals(tbs.fields.signature.node.bytes)) {
      throw ctx.E("x509/bad-signature-algorithm", "signatureAlgorithm must match tbsCertificate.signature (RFC 5280 §4.1.1.2)");
    }

    var version = tbs.fields.version.value; // 1 (default) | 2 | 3
    var issuer = tbs.fields.issuer.value.result;
    // RFC 5280 §4.1.2.4 — issuer MUST be non-empty (an empty subject is permitted, §4.1.2.6).
    if (!issuer.rdns.length) {
      throw ctx.E("x509/bad-issuer", "issuer must be a non-empty distinguished name");
    }

    var extField = tbs.fields.extensions;
    var hasExtensions = !!(extField && extField.present);
    // RFC 5280 §4.1.2.9 — extensions appear only in a v3 certificate.
    if (hasExtensions && version !== 3) {
      throw ctx.E("x509/bad-version", "extensions are only permitted in a v3 certificate");
    }

    var serialNode = tbs.fields.serialNumber.node;
    var sigBits = m.fields.signatureValue.value; // { unusedBits, bytes }
    return {
      version:               version,
      serialNumber:          tbs.fields.serialNumber.value,
      serialNumberHex:       serialNode.content.toString("hex"),
      signatureAlgorithm:    m.fields.signatureAlgorithm.value.result,
      tbsSignatureAlgorithm: tbs.fields.signature.value.result,
      issuer:                issuer,
      subject:               tbs.fields.subject.value.result,
      validity:              tbs.fields.validity.value.result,
      subjectPublicKeyInfo:  tbs.fields.subjectPublicKeyInfo.value.result,
      extensions:            hasExtensions ? extField.value.result : [],
      tbsBytes:              tbs.node.bytes,
      signatureValue:        { unusedBits: sigBits.unusedBits, bytes: sigBits.bytes },
    };
  },
});

// ---- parse -----------------------------------------------------------

/**
 * @primitive  pki.schema.x509.parse
 * @signature  pki.schema.x509.parse(input) -> certificate
 * @since      0.1.7
 * @status     stable
 * @spec       RFC 5280, X.509
 * @defends    malformed-certificate-parse (CWE-20)
 * @related    pki.asn1.decode, pki.oid.name
 *
 * Parse a DER `Buffer` or a PEM string/Buffer into a structured
 * certificate: `{ version, serialNumber, serialNumberHex,
 * signatureAlgorithm, issuer, subject, validity, subjectPublicKeyInfo,
 * extensions, tbsBytes, signatureValue }`. Distinguished names come back
 * both as a rendered `dn` string and as structured `rdns`; the validity
 * window is real `Date`s; `tbsBytes` is the exact signed byte range for a
 * downstream verifier.
 *
 * Throws `CertificateError` when the bytes are not a well-formed
 * certificate and `Asn1Error` when the underlying DER is malformed.
 *
 * @example
 *   var cert = pki.schema.x509.parse(pemString);
 *   cert.subject.dn;                 // "CN=example.com, O=Example"
 *   cert.validity.notAfter;          // Date
 *   cert.signatureAlgorithm.name;    // "sha256WithRSAEncryption"
 */
function parse(input) {
  return pkix.runParse(input, { pemLabel: "CERTIFICATE", PemError: PemError, ErrorClass: CertificateError, prefix: "x509", what: "certificate", topSchema: CERTIFICATE, ns: NS });
}

module.exports = {
  parse:     parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
};
