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
 *   per-format parsers built on it. Every format -- from X.509 certificates
 *   and CRLs through CMS, OCSP, timestamps, and PKCS#12 stores; `all()`
 *   enumerates the registered set -- is a member that COMPOSES the
 *   shared engine and the shared PKIX sub-schemas (AlgorithmIdentifier, Name,
 *   Extension), so a structural rule -- bounds-checked positional reads,
 *   optional / tagged field ordering, SET-OF uniqueness, fail-closed typed
 *   errors -- is defined once in the engine and no format can reintroduce the
 *   class of bug it prevents.
 *
 *   `parse` is the orchestrator: hand it DER (or PEM) and it detects which
 *   format the bytes encode and routes to that member's parser. Each member is
 *   also reachable directly (`pki.schema.x509.parse`, `pki.schema.crl.parse`),
 *   and `all()` enumerates the registered formats.
 *
 * @card
 *   One declarative schema engine; every PKI format (X.509, CRL, ...) is a
 *   member composed on it. Detect-and-parse DER, or call a format directly.
 */

var engine = require("./schema-engine");
var pkix = require("./schema-pkix");
var x509 = require("./schema-x509");
var crl = require("./schema-crl");
var csr = require("./schema-csr");
var pkcs8 = require("./schema-pkcs8");
var pkcs12 = require("./schema-pkcs12");
var cms = require("./schema-cms");
var ocsp = require("./schema-ocsp");
var tsp = require("./schema-tsp");
var crmf = require("./schema-crmf");
var cmp = require("./schema-cmp");
var csrattrs = require("./schema-csrattrs");
var attrcert = require("./schema-attrcert");
// smime is a COMPANION decoder for CMS signed-attribute values, NOT a top-level
// format -- it has no self-describing DER root (an ESS attribute value is a bare
// SEQUENCE) so it is deliberately absent from FORMATS / the detect-and-route
// `parse`; it is reached only by explicit OID dispatch on a CMS attribute.
var smime = require("./schema-smime");
var frameworkError = require("./framework-error");

var SchemaError = frameworkError.SchemaError;
var PemError = frameworkError.PemError;

// The shared parse-entry opts for the orchestrator: label-agnostic PEM unwrap
// (any block type routes), the schema/* error family. Detection needs a decoded
// root, so the coerced bytes are what gets routed to the matched format. The
// ber mode lets a BER-encoded PFX (the dominant real-world .p12 shape) decode
// far enough to detect; a BER input matching a strict-DER-only format still
// fails typed inside that format's own parse.
var ENTRY = { pemLabel: null, PemError: PemError, ErrorClass: SchemaError, prefix: "schema", what: "input", ber: true };

// REGISTRY -- each format is declarative data: a name, a `detect(root)` that
// recognizes the decoded DER root as this format's outer structure, and the
// member's own `parse`. Adding a format is a table entry, not new dispatch
// logic. Order matters: the most specific detector wins, so a new member is
// inserted ahead of any more-permissive one.
var FORMATS = [
  {
    // CMS ContentInfo (RFC 5652 sec. 3) -- the only registered root that leads with an
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
    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL } --
    // a SEQUENCE of 1-2 whose first child is a PKIStatusInfo SEQUENCE whose own first
    // child is an INTEGER status. This detector is a strict REFINEMENT of the
    // ocsp-request one (both are SEQUENCE-of-1-2 with a SEQUENCE first child), so it
    // MUST be checked first: a tokenless TimeStampResp (a bare PKIStatusInfo) would
    // otherwise be shadowed by ocsp-request, whereas an OCSPRequest's tbsRequest never
    // leads with a universal INTEGER and so never matches here (RFC 3161 sec. 2.4.2). A
    // bare timestamp token is a CMS ContentInfo and routes to cms; a bare TSTInfo is
    // an internal payload (reached via pki.schema.tsp.parseTstInfo).
    name: "tsp",
    module: tsp,
    detect: tsp.matches,
    parse: function (input) { return tsp.parse(input); },
  },
  {
    // CertReqMessages ::= SEQUENCE SIZE(1..MAX) OF CertReqMsg (RFC 4211 sec. 3) -- a
    // SEQUENCE whose first CertReqMsg's CertRequest leads with a universal INTEGER
    // (certReqId) then a universal SEQUENCE (certTemplate). Leads with a SEQUENCE
    // like the signed-envelope trio and the ocsp-request, but the INTEGER-then-
    // SEQUENCE pair at that depth is disjoint from both. Registered AHEAD of
    // ocsp-request: a single-message CertReqMessages is the only remaining overlap
    // with the ocsp-request detector, and crmf's deeper probe is the more specific.
    name: "crmf",
    module: crmf,
    detect: crmf.matches,
    parse: function (input) { return crmf.parse(input); },
  },
  {
    // PKIMessage ::= SEQUENCE { header PKIHeader, body PKIBody [0..26],
    // protection [0]?, extraCerts [1]? } (RFC 9810 sec. 5.1) -- a SEQUENCE of 2-4
    // whose first child is a >=3-child SEQUENCE leading with a bare INTEGER
    // (pvno) and whose second child is context-constructed [0..26]. ORDER IS
    // LOAD-BEARING here: a 2-child PKIMessage whose body is ir [0] also
    // satisfies the shallow ocsp-request probe below (k[0] SEQUENCE +
    // k[1] context-[0]), while no OCSPRequest satisfies this detector (its
    // tbsRequest never leads with a bare INTEGER) -- so cmp MUST sit ahead of
    // ocsp-request for the pair to dispatch deterministically.
    name: "cmp",
    module: cmp,
    detect: cmp.matches,
    parse: function (input) { return cmp.parse(input); },
  },
  {
    // CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID (RFC 8951 sec. 3.5) -- a
    // SEQUENCE whose every child is a bare universal OID or an Attribute (a
    // universal SEQUENCE of exactly 2: OID + SET). A 1-2-element all-Attribute
    // CsrAttrs satisfies the permissive ocsp-request probe below (SEQUENCE +
    // constructed first child), and the empty 30 00 is a CsrAttrs no other root
    // accepts -- so csrattrs is the strict refinement and MUST sit ahead of
    // ocsp-request, the same resolution tsp / cmp use. Disjoint from cmp (whose
    // body child is context-[0..26], never a universal OID/Attribute).
    name: "csrattrs",
    module: csrattrs,
    detect: csrattrs.matches,
    parse: function (input) { return csrattrs.parse(input); },
  },
  {
    // OCSPRequest ::= SEQUENCE { tbsRequest SEQUENCE, optionalSignature [0] EXPLICIT
    // OPTIONAL } -- a SEQUENCE of 1-2 whose first child is the tbsRequest SEQUENCE.
    // Leads with a SEQUENCE like the signed-envelope trio, but is excluded by arity
    // (the trio is EXACTLY 3 children; an OCSPRequest is 1-2). Checked AFTER tsp,
    // whose detector is a strict refinement (RFC 6960 sec. 4.1.1), and AFTER cmp,
    // whose 2-child ir-body shape this probe would otherwise shadow.
    name: "ocsp-request",
    module: ocsp,
    detect: ocsp.matchesRequest,
    parse: function (input) { return ocsp.parseRequest(input); },
  },
  {
    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0]
    // EXPLICIT OPTIONAL } -- the only registered root that leads with an ENUMERATED
    // child, so it is disjoint from every other format (RFC 6960 sec. 4.2.1).
    name: "ocsp-response",
    module: ocsp,
    detect: ocsp.matchesResponse,
    parse: function (input) { return ocsp.parseResponse(input); },
  },
  {
    // PKCS#12 PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData
    // OPTIONAL } -- INTEGER-first like pkcs8, so the discriminators are deeper:
    // children[1] is a ContentInfo (SEQUENCE of exactly 2: OID + [0] constructed --
    // a shape a PrivateKeyInfo's AlgorithmIdentifier never presents) and
    // children[2] is a MacData SEQUENCE or absent (pkcs8 requires an OCTET STRING
    // there). Shape-disjoint from pkcs8, and registered ahead of it as the more
    // specific probe (RFC 7292 sec. 4). A BER-encoded PFX detects through the
    // orchestrator's BER decode fallback and routes here.
    name: "pkcs12",
    module: pkcs12,
    detect: pkcs12.matches,
    parse: function (input) { return pkcs12.parse(input); },
  },
  {
    // PKCS#8 PrivateKeyInfo / OneAsymmetricKey -- SEQUENCE whose first child is an
    // INTEGER (version) and third an OCTET STRING (privateKey); disjoint from the
    // signed-envelope trio. (EncryptedPrivateKeyInfo is deliberately NOT
    // auto-routed: its SEQUENCE{SEQUENCE, OCTET STRING} shape is ambiguous -- a
    // PKCS#1 DigestInfo is identical -- so structural detection cannot classify it
    // without a validated encryption-algorithm discriminator, which arrives with
    // the PBES layer. It is reached explicitly via pki.schema.pkcs8.parseEncrypted.)
    name: "pkcs8",
    module: pkcs8,
    detect: pkcs8.matches,
    parse: function (input) { return pkcs8.parse(input); },
  },
  {
    // CertificationRequest ::= SEQUENCE { certificationRequestInfo,
    // signatureAlgorithm, signature } -- the same outer 3-element shape,
    // distinguished by a CertificationRequestInfo of EXACTLY four children
    // ending in the IMPLICIT [0] attributes element. Checked first because that
    // detector is the most specific and mutually exclusive with the others.
    name: "csr",
    module: csr,
    detect: csr.matches,
    parse: function (input) { return csr.parse(input); },
  },
  {
    // AttributeCertificate ::= SEQUENCE { acinfo, signatureAlgorithm, signatureValue }
    // -- the signed-envelope trio, recognized by an acinfo that LEADS WITH a bare
    // INTEGER version and carries a 2-GeneralizedTime attrCertValidityPeriod at
    // children[5] (RFC 5755, section 4.1). Order-independent versus crl / x509 / csr:
    // a v2 acinfo puts the AlgorithmIdentifier at the position where their probes
    // require a bare Time / a 2-Time Validity / a 4-child CRI, and none of their tbs
    // shapes carry the 2-GeneralizedTime marker at children[5].
    name: "attrcert",
    module: attrcert,
    detect: attrcert.matches,
    parse: function (input) { return attrcert.parse(input); },
  },
  {
    // AttributeCertificateV1 (X.509-1997, RFC 5652, section 10.2) -- the obsolete
    // predecessor whose acInfo LEADS WITH the subject CHOICE (context [0]/[1]).
    // Recognized and deferred with a precise attrcert/legacy-v1-not-supported rather
    // than routed to a wrong format. ORDER IS LOAD-BEARING against x509: a [0]-subject
    // v1 AC ALSO satisfies x509.matches (the [0] child reads as the certificate's
    // EXPLICIT version marker, putting the 2-GeneralizedTime attrCertValidityPeriod at
    // the Validity probe offset), so this entry MUST sit ahead of x509 for first-match
    // dispatch to defer it here. children[1] == SEQUENCE keeps a v3 certificate (whose
    // [0] version is followed by an INTEGER serialNumber) from matching in the other
    // direction.
    name: "attrcert-v1",
    module: attrcert,
    detect: attrcert.matchesV1,
    parse: function (input) { return attrcert.parseV1(input); },
  },
  {
    // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm,
    // signatureValue } -- the same outer shape as a certificate, distinguished
    // by its tbsCertList (a bare Time at the certificate's Validity position).
    name: "crl",
    module: crl,
    detect: crl.matches,
    parse: function (input) { return crl.parse(input); },
  },
  {
    name: "x509",
    module: x509,
    // Certificate -- identified by a Validity (SEQUENCE of two Times) inside the
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
 *   pki.schema.all();  // -> ["cms", "tsp", "crmf", "cmp", "ocsp-request", "ocsp-response", "pkcs12", "pkcs8", "csr", "attrcert", "attrcert-v1", "crl", "x509"]
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
 *   var parsed = pki.schema.parse(der);  // cert -> the pki.schema.x509 shape
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
  crl:  { parse: crl.parse,  pemDecode: crl.pemDecode, pemEncode: crl.pemEncode },
  csr:  { parse: csr.parse,  pemDecode: csr.pemDecode, pemEncode: csr.pemEncode },
  pkcs8: { parse: pkcs8.parse, parseEncrypted: pkcs8.parseEncrypted, pemDecode: pkcs8.pemDecode, pemEncode: pkcs8.pemEncode },
  pkcs12: { parse: pkcs12.parse, pemDecode: pkcs12.pemDecode, pemEncode: pkcs12.pemEncode },
  cms:  { parse: cms.parse, pemDecode: cms.pemDecode, pemEncode: cms.pemEncode },
  ocsp: { parseRequest: ocsp.parseRequest, parseResponse: ocsp.parseResponse, pemDecode: ocsp.pemDecode, pemEncode: ocsp.pemEncode },
  tsp: { parse: tsp.parse, parseTstInfo: tsp.parseTstInfo, parseToken: tsp.parseToken, pemDecode: tsp.pemDecode, pemEncode: tsp.pemEncode },
  crmf: { parse: crmf.parse, pemDecode: crmf.pemDecode, pemEncode: crmf.pemEncode },
  cmp: { parse: cmp.parse, pemDecode: cmp.pemDecode, pemEncode: cmp.pemEncode },
  csrattrs: { parse: csrattrs.parse },
  attrcert: { parse: attrcert.parse, pemDecode: attrcert.pemDecode, pemEncode: attrcert.pemEncode },
  smime: { parseSigningCertificate: smime.parseSigningCertificate, parseSigningCertificateV2: smime.parseSigningCertificateV2, parseSmimeCapabilities: smime.parseSmimeCapabilities, decodeAttribute: smime.decodeAttribute },
  all: all,
  parse: parse,
};
