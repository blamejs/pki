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
 *   `parse` -- turn a DER or PEM certificate into a structured,
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
 * Extract the DER bytes from a PEM block (default label `CERTIFICATE`, the
 * RFC 7468 sec. 5 armor -- the canonical-label default every sibling format
 * applies). Pass a `label` to enforce a different block type, or an explicit
 * `null` to take the first block of any type. Throws `PemError` on a
 * missing / mismatched envelope or a non-base64 body.
 *
 * @example
 *   var der = pki.schema.x509.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label === null ? null : (label || "CERTIFICATE"), PemError); }

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
var NS = pkix.makeNS("x509", CertificateError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var NAME = pkix.name(NS);

// Validity ::= SEQUENCE { notBefore Time, notAfter Time } -- the outer tag is
// asserted (a SET-tagged body is a different ASN.1 type, not a Validity).
// pkix.time enforces the RFC 5280 sec. 4.1.2.5 encoding cutover on decode: a
// validity date through 2049 must be UTCTime, GeneralizedTime is 2050 onward.
var VALIDITY = schema.seq([
  schema.field("notBefore", pkix.time(NS)),
  schema.field("notAfter", pkix.time(NS)),
], {
  assert: "sequence", arity: { exact: 2 }, code: "x509/bad-validity", what: "Validity",
  build: function (m) { return { notBefore: m.fields.notBefore.value, notAfter: m.fields.notAfter.value }; },
});

// SubjectPublicKeyInfo -- the shared pkix.spki factory under the x509 NS.
var SPKI = pkix.spki(NS);

var EXTENSIONS = pkix.extensions(NS);

// Version ::= INTEGER { v1(0), v2(1), v3(2) }, [0] EXPLICIT DEFAULT v1. Read as a
// BigInt so an out-of-range value can't coerce to a float; reject an explicitly-
// encoded v1 (DER forbids encoding the DEFAULT).
// version ::= INTEGER { v1(0), v2(1), v3(2) } inside a [0] EXPLICIT DEFAULT v1 --
// DER forbids encoding the default, so 0 is rejected; 1->v2, 2->v3.
var CERTIFICATE_VERSION = pkix.versionReader(NS, { "1": 2, "2": 3 });

// TBSCertificate ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1, serialNumber
// INTEGER, signature AlgorithmIdentifier, issuer Name, validity Validity,
// subject Name, subjectPublicKeyInfo SubjectPublicKeyInfo, issuerUniqueID [1]
// IMPLICIT OPTIONAL, subjectUniqueID [2] IMPLICIT OPTIONAL, extensions [3]
// EXPLICIT OPTIONAL }. The trailing fields are at-most-once, in increasing tag
// order (the engine enforces it); only extensions are surfaced.
var CERTIFICATE_TBS = schema.seq([
  schema.optional("version", CERTIFICATE_VERSION, { tag: 0, explicit: true, emptyCode: "x509/bad-version", default: 1 }),
  schema.field("serialNumber", schema.integerLeaf()),
  schema.field("signature", ALGORITHM_IDENTIFIER),
  schema.field("issuer", NAME),
  schema.field("validity", VALIDITY),
  schema.field("subject", NAME),
  schema.field("subjectPublicKeyInfo", SPKI),
  schema.trailing([
    // RFC 5280 sec. 4.1.2.8 -- the unique identifiers are [n] IMPLICIT BIT
    // STRING (context PRIMITIVE, unusedBits validated), never an EXPLICIT wrap.
    { tag: 1, name: "issuerUniqueID", schema: schema.implicitBitString(1) },
    { tag: 2, name: "subjectUniqueID", schema: schema.implicitBitString(2) },
    { tag: 3, name: "extensions", schema: EXTENSIONS, explicit: true, emptyCode: "x509/bad-extensions" },
  ], { minTag: 1, maxTag: 3, unexpectedCode: "x509/bad-tbs", orderCode: "x509/bad-tbs" }),
], { assert: "sequence", code: "x509/bad-tbs", what: "tbsCertificate" });

// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue
// BIT STRING }. The build runs the RFC 5280 cross-field checks (sec. 4.1.1.2 sig-alg
// agreement, sec. 4.1.2.4 non-empty issuer, sec. 4.1.2.9 extensions-only-in-v3) after the
// structural walk, then assembles the public parse result. Raw-byte accessors
// (serialNumberHex, tbsBytes, sig-alg agreement) read off the match-tree nodes.
// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
// -- the shared SIGNED envelope. The certificate-specific invariants (outer==inner
// signatureAlgorithm agreement, non-empty issuer, v3-only extensions) live in the
// build; the envelope owns the SEQUENCE-of-3 shape and signature extraction.
var CERTIFICATE = pkix.signedEnvelope(NS, CERTIFICATE_TBS, {
  code: "x509/not-a-certificate", what: "Certificate",
  build: function (e, ctx) {
    var tbs = e.tbsMatch; // CERTIFICATE_TBS seq-match (no build)

    // RFC 5280 sec. 4.1.1.2 -- outer signatureAlgorithm MUST equal tbsCertificate.signature.
    if (!e.outerSignatureAlgorithmBytes.equals(tbs.fields.signature.node.bytes)) {
      throw ctx.E("x509/bad-signature-algorithm", "signatureAlgorithm must match tbsCertificate.signature (RFC 5280 sec. 4.1.1.2)");
    }

    var version = tbs.fields.version.value; // 1 (default) | 2 | 3
    var issuer = tbs.fields.issuer.value.result;
    // RFC 5280 sec. 4.1.2.4 -- issuer MUST be non-empty (an empty subject is permitted, sec. 4.1.2.6).
    if (!issuer.rdns.length) {
      throw ctx.E("x509/bad-issuer", "issuer must be a non-empty distinguished name");
    }

    var extField = tbs.fields.extensions;
    var hasExtensions = !!(extField && extField.present);
    // RFC 5280 sec. 4.1.2.9 -- extensions appear only in a v3 certificate.
    if (hasExtensions && version !== 3) {
      throw ctx.E("x509/bad-version", "extensions are only permitted in a v3 certificate");
    }

    // RFC 5280 sec. 4.1.2.8 -- issuerUniqueID / subjectUniqueID MUST NOT
    // appear when the version is 1; they require a v2 or v3 certificate.
    if ((tbs.fields.issuerUniqueID.present || tbs.fields.subjectUniqueID.present) && version < 2) {
      throw ctx.E("x509/bad-version", "issuerUniqueID/subjectUniqueID require a v2 or v3 certificate (RFC 5280 sec. 4.1.2.8)");
    }

    var serialNode = tbs.fields.serialNumber.node;
    return {
      version:               version,
      serialNumber:          tbs.fields.serialNumber.value,
      serialNumberHex:       serialNode.content.toString("hex"),
      signatureAlgorithm:    e.signatureAlgorithm,
      tbsSignatureAlgorithm: tbs.fields.signature.value.result,
      issuer:                issuer,
      subject:               tbs.fields.subject.value.result,
      validity:              tbs.fields.validity.value.result,
      subjectPublicKeyInfo:  tbs.fields.subjectPublicKeyInfo.value.result,
      extensions:            hasExtensions ? extField.value.result : [],
      tbsBytes:              e.tbsBytes,
      signatureValue:        e.signatureValue,
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
var parse = pkix.makeParser({ pemLabel: "CERTIFICATE", PemError: PemError, ErrorClass: CertificateError, prefix: "x509", what: "certificate", topSchema: CERTIFICATE, ns: NS });

// matches(root): does the decoded DER look like a Certificate? A CSR and a CRL
// share the outer SEQUENCE-of-3 envelope, so the discriminator is inside the
// tbs: a certificate has a Validity -- a SEQUENCE of exactly two Time values -- at
// position [serial, signature, issuer, VALIDITY] after the optional [0] version.
// A CSR's certificationRequestInfo has subjectPublicKeyInfo there (no Validity),
// and a CRL leads with a bare Time; neither matches. Used by the orchestrator.
function matches(root) {
  var TAGS = asn1.TAGS;
  var tbs = pkix.signedEnvelopeTbs(root);
  if (!tbs) return false;
  var kids = tbs.children;
  var i = schema.isContext(kids[0], 0) ? 1 : 0; // optional [0] version
  var validity = kids[i + 3]; // serial(i), signature(i+1), issuer(i+2), validity(i+3)
  return schema.isUniversal(validity, TAGS.SEQUENCE) &&
    !!validity.children && validity.children.length === 2 &&
    validity.children.every(function (t) {
      return schema.isUniversalOneOf(t, [TAGS.UTC_TIME, TAGS.GENERALIZED_TIME]);
    });
}

module.exports = {
  parse:     parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches:   matches,
};
