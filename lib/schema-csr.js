// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.csr
 * @nav        Schema
 * @title      CSR
 * @order      130
 * @slug       csr
 *
 * @intro
 *   PKCS#10 certification request handling per RFC 2986. `parse` turns a DER or
 *   PEM CSR into a structured object: version, subject distinguished name,
 *   subject public-key info, the requested attributes (each with its raw values),
 *   and the signature over the CertificationRequestInfo. It composes the same
 *   schema engine and shared PKIX sub-schemas (AlgorithmIdentifier, Name,
 *   SubjectPublicKeyInfo) the certificate parser uses, so the request inherits the
 *   identical fail-closed structural rules, and the raw
 *   `certificationRequestInfoBytes` are returned for signature checking.
 *
 *   A CSR is self-signed only in the sense that the requester proves possession of
 *   the private key; unlike a certificate or CRL there is no inner signature
 *   algorithm to agree with, the subject MAY be empty, and the attribute set has
 *   no uniqueness constraint — the parser deliberately omits those three
 *   certificate/CRL guards.
 *
 * @card
 *   Parse DER / PEM PKCS#10 CSRs into structured, validated fields — subject DN,
 *   public key, requested attributes, signature, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var CsrError = frameworkError.CsrError;
var PemError = frameworkError.PemError;

// The csr error namespace the schema engine walks under. Shared PKIX sub-schemas
// are instantiated here under csr/* so a structural fault reports a csr code.
var NS = pkix.makeNS("csr", CsrError, oid);

var NAME = pkix.name(NS);
var SPKI = pkix.spki(NS);

// CertificationRequestInfo version ::= INTEGER { v1(0) } (RFC 2986 §4.1). A BARE
// mandatory INTEGER whose ONLY legal value is 0 — the inverse of the cert/CRL
// readers, which reject 0 as the DER-forbidden default. Surface v1 as 1. A
// cert-shaped [0] EXPLICIT wrapper at this position makes asn1.read.integer throw
// asn1/* (fail-closed).
var CSR_VERSION = pkix.versionReader(NS, { "0": 1 });

// Attribute ::= SEQUENCE { type OID, values SET OF ANY } — the shared pkix factory
// under the csr NS (values raw DER, SET SIZE(1..MAX), no uniqueness). The same
// factory serves the PKCS#8 private-key attributes.
var ATTRIBUTE = pkix.attribute(NS);

// CertificationRequestInfo ::= SEQUENCE { version, subject Name,
//   subjectPKInfo SubjectPublicKeyInfo, attributes [0] IMPLICIT SET OF Attribute }.
// attributes is a REQUIRED field (a CRI omitting [0] is a missing-required-field
// fault, not silently accepted) modeled as an IMPLICIT [0] SET OF with min:0 (an
// empty attributes SET is legal). subject MAY be empty — no non-empty-DN guard.
var CERTIFICATION_REQUEST_INFO = schema.seq([
  schema.field("version", CSR_VERSION),
  schema.field("subject", NAME),
  schema.field("subjectPKInfo", SPKI),
  schema.field("attributes", schema.implicitSetOf(0, ATTRIBUTE, { min: 0, code: "csr/bad-attributes", what: "attributes" })),
], {
  assert: "sequence", code: "csr/bad-cri", what: "certificationRequestInfo",
  build: function (m) {
    return {
      version: m.fields.version.value,
      subject: m.fields.subject.value.result, // Name is a seqOf → field.value is the match; .result is the {rdns, dn} build
      subjectPublicKeyInfo: m.fields.subjectPKInfo.value.result,
      attributes: m.fields.attributes.value.items.map(function (it) { return it.value.result; }),
    };
  },
});

// CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm,
//   signature BIT STRING } — the shared SIGNED envelope. DIVERGENCE from the
// cert/CRL builders: OMIT the outer-vs-inner signatureAlgorithm agreement check
// (the CRI has no inner signature AlgorithmIdentifier) and the non-empty-subject
// guard (a CSR subject MAY be empty). The omission is structural — this build
// simply never references the agreement bytes.
var CERTIFICATION_REQUEST = pkix.signedEnvelope(NS, CERTIFICATION_REQUEST_INFO, {
  code: "csr/not-a-certification-request", what: "CertificationRequest",
  build: function (e) {
    var cri = e.tbsMatch.result;
    return {
      version: cri.version,
      subject: cri.subject,
      subjectPublicKeyInfo: cri.subjectPublicKeyInfo,
      attributes: cri.attributes,
      certificationRequestInfoBytes: e.tbsBytes,
      tbsBytes: e.tbsBytes,
      signatureAlgorithm: e.signatureAlgorithm,
      signatureValue: e.signatureValue,
    };
  },
});

/**
 * @primitive  pki.schema.csr.parse
 * @signature  pki.schema.csr.parse(input) -> csr
 * @since      0.1.8
 * @status     experimental
 * @spec       RFC 2986
 * @related    pki.schema.x509.parse, pki.schema.parse
 *
 * Parse a DER `Buffer` or a PEM (`CERTIFICATE REQUEST`) string into a structured
 * PKCS#10 request: `{ version, subject, subjectPublicKeyInfo, attributes,
 * certificationRequestInfoBytes, tbsBytes, signatureAlgorithm, signatureValue }`.
 * Every field is validated on the way in; a malformed CertificationRequest /
 * CertificationRequestInfo throws a typed `CsrError` (`csr/*`) and a leaf-level
 * codec fault surfaces as `asn1/*`. Attribute values are returned as raw DER
 * buffers so an unrecognized attribute type never fails the parse.
 *
 * @example
 *   var csr = pki.schema.csr.parse(der);
 *   csr.subject.dn;             // → "CN=req.example"
 *   csr.attributes[0].type;     // → "1.2.840.113549.1.9.14"
 */
var parse = pkix.makeParser({ pemLabel: "CERTIFICATE REQUEST", PemError: PemError, ErrorClass: CsrError, prefix: "csr", what: "certification request", topSchema: CERTIFICATION_REQUEST, ns: NS });

/**
 * @primitive  pki.schema.csr.pemDecode
 * @signature  pki.schema.csr.pemDecode(text, label?) -> Buffer
 * @since      0.1.8
 * @status     experimental
 * @spec       RFC 7468, RFC 2986
 * @related    pki.schema.csr.parse
 *
 * Extract the DER bytes from a PEM CSR block (default label `CERTIFICATE
 * REQUEST`). Throws `PemError` on a missing / mismatched envelope or a non-base64
 * body.
 *
 * @example
 *   var der = pki.schema.csr.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "CERTIFICATE REQUEST", PemError); }

/**
 * @primitive  pki.schema.csr.pemEncode
 * @signature  pki.schema.csr.pemEncode(der, label?) -> string
 * @since      0.1.8
 * @status     experimental
 * @spec       RFC 7468
 * @related    pki.schema.csr.pemDecode
 *
 * Wrap DER bytes in a PEM CSR envelope (default label `CERTIFICATE REQUEST`).
 *
 * @example
 *   var pem = pki.schema.csr.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "CERTIFICATE REQUEST", PemError); }

// A CertificationRequest shares the outer SEQUENCE-of-3 shape with a certificate
// and a CRL; a CSR is distinguished by its CertificationRequestInfo — a SEQUENCE
// of EXACTLY four children {version INTEGER, subject SEQUENCE, subjectPKInfo
// SEQUENCE, attributes [0]}. The mandatory trailing context-[0] attributes
// element is what a cert (whose tbs leads with [0] EXPLICIT version or an INTEGER
// serial and never ends the leading run this way) and a CRL (whose tbs reaches a
// bare Time at the validity position) never present, so the three detectors are
// mutually exclusive.
function matches(root) {
  var TAGS = asn1.TAGS;
  var cri = pkix.signedEnvelopeTbs(root);
  if (!cri) return false;
  var k = cri.children;
  if (k.length !== 4) return false;
  return k[0].tagClass === "universal" && k[0].tagNumber === TAGS.INTEGER &&
    k[1].tagClass === "universal" && k[1].tagNumber === TAGS.SEQUENCE &&
    k[2].tagClass === "universal" && k[2].tagNumber === TAGS.SEQUENCE &&
    k[3].tagClass === "context" && k[3].tagNumber === 0;
}

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
};
