// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema
 * @nav        Schema
 * @title      Schema
 * @order      10
 * @featured   true
 * @slug       schema
 *
 * @intro
 *   The schema family: a declarative ASN.1 structure-schema engine and the
 *   per-format parsers built on it. Every format (X.509 certificates, CRLs,
 *   PKCS#10 certification requests, PKCS#8 private keys, and CMS SignedData) is a
 *   member that COMPOSES the
 *   shared engine and the shared PKIX sub-schemas (AlgorithmIdentifier, Name,
 *   Extension), so a structural rule — bounds-checked positional reads,
 *   optional / tagged field ordering, SET-OF uniqueness, fail-closed typed
 *   errors — is defined once in the engine and no format can reintroduce the
 *   class of bug it prevents.
 *
 *   `parse` is the orchestrator: hand it DER (or PEM) and it detects which
 *   format the bytes encode and routes to that member's parser. Each member is
 *   also reachable directly (`pki.schema.x509.parse`, `pki.schema.crl.parse`),
 *   and `all()` enumerates the registered formats.
 *
 * @card
 *   One declarative schema engine; every PKI format (X.509, CRL, …) is a
 *   member composed on it. Detect-and-parse DER, or call a format directly.
 */

var engine = require("./schema-engine");
var pkix = require("./schema-pkix");
var x509 = require("./schema-x509");
var crl = require("./schema-crl");
var csr = require("./schema-csr");
var pkcs8 = require("./schema-pkcs8");
var cms = require("./schema-cms");
var ocsp = require("./schema-ocsp");
var frameworkError = require("./framework-error");

var SchemaError = frameworkError.SchemaError;
var PemError = frameworkError.PemError;

// The shared parse-entry opts for the orchestrator: label-agnostic PEM unwrap
// (any block type routes), the schema/* error family. Detection needs DER, so
// the coerced DER is what gets routed to the matched format.
var ENTRY = { pemLabel: null, PemError: PemError, ErrorClass: SchemaError, prefix: "schema", what: "input" };

// REGISTRY — each format is declarative data: a name, a `detect(root)` that
// recognizes the decoded DER root as this format's outer structure, and the
// member's own `parse`. Adding a format is a table entry, not new dispatch
// logic. Order matters: the most specific detector wins, so a new member is
// inserted ahead of any more-permissive one.
var FORMATS = [
  {
    // CMS ContentInfo (RFC 5652 §3) — the only registered root that leads with an
    // OBJECT IDENTIFIER child (a SEQUENCE of exactly 2: contentType OID + a
    // context [0] EXPLICIT content wrapper). Disjoint from the INTEGER-first pkcs8
    // and the tbs-SEQUENCE-first signed-envelope trio, so it detects unambiguously.
    // A non-SignedData content type routes here and gets a precise
    // cms/unsupported-content-type rather than schema/unknown-format.
    name: "cms",
    module: cms,
    detect: cms.matches,
    parse: function (input) { return cms.parse(input); },
  },
  {
    // OCSPRequest ::= SEQUENCE { tbsRequest SEQUENCE, optionalSignature [0] EXPLICIT
    // OPTIONAL } — a SEQUENCE of 1-2 whose first child is the tbsRequest SEQUENCE.
    // Leads with a SEQUENCE like the signed-envelope trio, but is excluded by arity
    // (the trio is EXACTLY 3 children; an OCSPRequest is 1-2), so it detects
    // unambiguously regardless of registry order (RFC 6960 §4.1.1).
    name: "ocsp-request",
    module: ocsp,
    detect: ocsp.matchesRequest,
    parse: function (input) { return ocsp.parseRequest(input); },
  },
  {
    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0]
    // EXPLICIT OPTIONAL } — the only registered root that leads with an ENUMERATED
    // child, so it is disjoint from every other format (RFC 6960 §4.2.1).
    name: "ocsp-response",
    module: ocsp,
    detect: ocsp.matchesResponse,
    parse: function (input) { return ocsp.parseResponse(input); },
  },
  {
    // PKCS#8 PrivateKeyInfo / OneAsymmetricKey — SEQUENCE whose first child is an
    // INTEGER (version) and third an OCTET STRING (privateKey); disjoint from the
    // signed-envelope trio. (EncryptedPrivateKeyInfo is deliberately NOT
    // auto-routed: its SEQUENCE{SEQUENCE, OCTET STRING} shape is ambiguous — a
    // PKCS#1 DigestInfo is identical — so structural detection cannot classify it
    // without a validated encryption-algorithm discriminator, which arrives with
    // the PBES layer. It is reached explicitly via pki.schema.pkcs8.parseEncrypted.)
    name: "pkcs8",
    module: pkcs8,
    detect: pkcs8.matches,
    parse: function (input) { return pkcs8.parse(input); },
  },
  {
    // CertificationRequest ::= SEQUENCE { certificationRequestInfo,
    // signatureAlgorithm, signature } — the same outer 3-element shape,
    // distinguished by a CertificationRequestInfo of EXACTLY four children
    // ending in the IMPLICIT [0] attributes element. Checked first because that
    // detector is the most specific and mutually exclusive with the others.
    name: "csr",
    module: csr,
    detect: csr.matches,
    parse: function (input) { return csr.parse(input); },
  },
  {
    // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
    // signatureValue } — the same outer shape as a certificate, distinguished
    // by its tbsCertList (a bare Time at the certificate's Validity position).
    name: "crl",
    module: crl,
    detect: crl.matches,
    parse: function (input) { return crl.parse(input); },
  },
  {
    name: "x509",
    module: x509,
    // Certificate — identified by a Validity (SEQUENCE of two Times) inside the
    // tbs, so a CSR / other 3-element signed envelope is NOT misclassified as a
    // certificate (it falls through to schema/unknown-format).
    detect: x509.matches,
    parse: function (input) { return x509.parse(input); },
  },
];

/**
 * @primitive  pki.schema.all
 * @signature  pki.schema.all() -> string[]
 * @since      0.1.7
 * @status     experimental
 * @spec       RFC 5280
 * @related    pki.schema.parse
 *
 * The names of every registered format, in detection order.
 *
 * @example
 *   pki.schema.all();  // → ["cms", "ocsp-request", "ocsp-response", "pkcs8", "csr", "crl", "x509"]
 */
function all() { return FORMATS.map(function (f) { return f.name; }); }

/**
 * @primitive  pki.schema.parse
 * @signature  pki.schema.parse(input) -> parsed
 * @since      0.1.7
 * @status     experimental
 * @spec       RFC 5280
 * @related    pki.schema.x509, pki.schema.all
 *
 * Detect which PKI format `input` (a DER `Buffer` or a PEM string) encodes and
 * route to that format's parser, returning the same structured object the
 * format's own `parse` returns. Throws `SchemaError("schema/unknown-format")` when
 * the bytes match no registered format; the underlying decode / structural
 * errors of the matched format propagate unchanged.
 *
 * @example
 *   var parsed = pki.schema.parse(der);  // cert → the pki.schema.x509 shape
 */
function parse(input) {
  // Coerce + decode via the shared parse-entry, then route the COERCED DER (a
  // PEM string/Buffer is already unwrapped, so the matched format parses DER
  // directly and never re-treats the armor as DER).
  var der = pkix.coerceToDer(input, ENTRY);
  var root = pkix.decodeRoot(der, ENTRY);
  for (var i = 0; i < FORMATS.length; i++) {
    if (FORMATS[i].detect(root)) return FORMATS[i].parse(der);
  }
  throw new SchemaError("schema/unknown-format", "input does not match any registered PKI format (" + all().join(", ") + ")");
}

// Curated public surface: each format exposes only its operator primitives. The
// `matches` detector is internal dispatch infrastructure (used by FORMATS above),
// not an operator API, so it is NOT re-exported here.
module.exports = {
  engine: engine,
  x509: { parse: x509.parse, pemDecode: x509.pemDecode, pemEncode: x509.pemEncode },
  crl:  { parse: crl.parse,  pemDecode: crl.pemDecode },
  csr:  { parse: csr.parse,  pemDecode: csr.pemDecode, pemEncode: csr.pemEncode },
  pkcs8: { parse: pkcs8.parse, parseEncrypted: pkcs8.parseEncrypted, pemDecode: pkcs8.pemDecode, pemEncode: pkcs8.pemEncode },
  cms:  { parse: cms.parse, pemDecode: cms.pemDecode, pemEncode: cms.pemEncode },
  ocsp: { parseRequest: ocsp.parseRequest, parseResponse: ocsp.parseResponse, pemDecode: ocsp.pemDecode },
  all: all,
  parse: parse,
};
