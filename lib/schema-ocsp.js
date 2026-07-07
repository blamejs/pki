// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.ocsp
 * @nav        Schema
 * @title      OCSP
 * @order      150
 * @slug       ocsp
 *
 * @intro
 *   OCSP request and response handling per RFC 6960 (§4.1 OCSPRequest, §4.2
 *   OCSPResponse). Two entry points — `parseRequest` and `parseResponse` — turn a
 *   DER or PEM message into a structured object. A response is a two-stage
 *   OID-dispatch: `OCSPResponse` carries an ENUMERATED `responseStatus` and an
 *   OPTIONAL `responseBytes`; when the `responseType` is `id-pkix-ocsp-basic` its
 *   `response` OCTET STRING content is a fresh DER `BasicOCSPResponse` that is
 *   decoded and walked, so the per-certificate statuses surface structurally.
 *
 *   OCSP is a signed protocol: the bytes an external verifier must hash are surfaced
 *   RAW and never re-serialized. `tbsRequestBytes` and `tbsResponseDataBytes` are the
 *   exact on-wire `tbsRequest` / `ResponseData` TLVs; each `CertID` surfaces its
 *   `issuerNameHash` / `issuerKeyHash` as raw octets, and the responder's `byKey`
 *   hash and the raw `signature` bytes are left for the caller to verify. Embedded
 *   certificates are surfaced as raw DER, so an unknown alternative never fails the
 *   parse. DER-only, fail-closed.
 *
 * @card
 *   Parse DER / PEM OCSP requests and responses (RFC 6960) into structured,
 *   validated fields — per-certificate status, responder identity, raw tbs bytes for
 *   external verification, certificates kept raw, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var OcspError = frameworkError.OcspError;
var PemError = frameworkError.PemError;

// The ocsp error namespace the schema engine walks under.
var NS = pkix.makeNS("ocsp", OcspError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var NAME = pkix.name(NS);
var EXTENSIONS = pkix.extensions(NS);

// Version ::= INTEGER { v1(0) }. OCSP defines only v1(0), which DER forbids
// encoding (it is the DEFAULT), so ANY explicitly-encoded version is a fault; the
// empty accept map rejects every value and absence yields the default 1.
var VERSION = pkix.versionReader(NS, {});

// id-pkix-ocsp-basic is the one ResponseBytes.responseType this build decodes; any
// other is recognized-and-deferred. Resolved from the registry, never a literal.
var OID_OCSP_BASIC = oid.byName("ocspBasic");

// OCSPResponseStatus ::= ENUMERATED — value 4 is "not used" and >= 7 is undefined,
// so both are rejected (RFC 6960 §4.2.1).
var STATUS_NAMES = { "0": "successful", "1": "malformedRequest", "2": "internalError", "3": "tryLater", "5": "sigRequired", "6": "unauthorized" };

// CRLReason ::= ENUMERATED — value 7 is "not used"; the rest are RFC 5280 §5.3.1.
var CRL_REASONS = { "0": "unspecified", "1": "keyCompromise", "2": "cACompromise", "3": "affiliationChanged", "4": "superseded", "5": "cessationOfOperation", "6": "certificateHold", "8": "removeFromCRL", "9": "privilegeWithdrawn", "10": "aACompromise" };

// ---- shared leaves ---------------------------------------------------

// A GeneralizedTime-only leaf. OCSP times (producedAt / thisUpdate / nextUpdate /
// revocationTime) are GeneralizedTime, never UTCTime (RFC 6960); assert the tag
// before the codec reads it so a UTCTime is rejected ocsp/bad-time.
var GENERALIZED_TIME = schema.decode(function (n, ctx) {
  if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.GENERALIZED_TIME) {
    throw ctx.E("ocsp/bad-time", "OCSP time must be a GeneralizedTime (RFC 6960)");
  }
  return asn1.read.time(n);
});

// OCSPResponseStatus decode-and-whitelist leaf. read.enumerated is tag-checked, so
// an INTEGER-encoded status is rejected at the leaf (asn1/unexpected-tag).
var OCSP_RESPONSE_STATUS = schema.decode(function (n, ctx) {
  var v = asn1.read.enumerated(n);
  var key = v.toString();
  if (!Object.prototype.hasOwnProperty.call(STATUS_NAMES, key)) throw ctx.E("ocsp/bad-response-status", "undefined OCSPResponseStatus " + key + " (RFC 6960 §4.2.1)");
  return { code: Number(v), name: STATUS_NAMES[key] };
});

// CRLReason decode-and-whitelist leaf.
var CRL_REASON = schema.decode(function (n, ctx) {
  var v = asn1.read.enumerated(n);
  var key = v.toString();
  if (!Object.prototype.hasOwnProperty.call(CRL_REASONS, key)) throw ctx.E("ocsp/bad-revocation-reason", "undefined CRLReason " + key + " (RFC 5280 §5.3.1)");
  return CRL_REASONS[key];
});

// A certs [0] SEQUENCE OF Certificate element. Unlike the CMS CertificateChoices
// (a tagged CHOICE), an OCSP certs element is a plain Certificate — a universal
// SEQUENCE (RFC 5280 §4.1) — so assert that shape before surfacing its raw DER, and
// reject a non-SEQUENCE element rather than reporting arbitrary bytes as a cert.
function certificateBytes() {
  return schema.decode(function (n, ctx) {
    if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.SEQUENCE || !n.children) {
      throw ctx.E("ocsp/bad-certs", "each certs element must be a Certificate (a SEQUENCE) (RFC 6960 §4.1.1/§4.2.1)");
    }
    return n.bytes;
  });
}

// requestorName [1] EXPLICIT GeneralName (RFC 6960 §4.1.1) — validated + surfaced raw
// via the shared pkix.generalName primitive (RFC 5280 §4.2.1.6), so a malformed
// GeneralName fails closed and the OCSP + TSP parsers cannot drift on this grammar.
var GENERAL_NAME_RAW = pkix.generalName(NS, { code: "ocsp/bad-requestor-name" });

// An OCSP signature BIT STRING is a byte string handed to a cryptographic verifier,
// so it MUST be octet-aligned (0 unused bits); a non-octet-aligned signature is
// malformed. Shared by the request Signature and the BasicOCSPResponse.
function _rawSignature(field) {
  var sig = field.value;
  if (sig.unusedBits !== 0) throw NS.E("ocsp/bad-signature", "an OCSP signature BIT STRING must be octet-aligned (0 unused bits)");
  return sig.bytes;
}

// certs [0] EXPLICIT SEQUENCE OF Certificate — each element raw. Shared by the
// request Signature and the BasicOCSPResponse.
var CERTS = schema.seqOf(certificateBytes(), { assert: "sequence", code: "ocsp/bad-certs", what: "certs" });

// ---- CertID (shared request + response) ------------------------------

// CertID ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, issuerNameHash OCTET
// STRING, issuerKeyHash OCTET STRING, serialNumber CertificateSerialNumber }
// (RFC 6960 §4.1.1). The two hashes are surfaced raw for the caller to verify.
var CERT_ID = schema.seq([
  schema.field("hashAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("issuerNameHash", schema.octetString()),
  schema.field("issuerKeyHash", schema.octetString()),
  schema.field("serialNumber", schema.integerLeaf()),
], {
  assert: "sequence", arity: { exact: 4 }, code: "ocsp/bad-cert-id", what: "CertID",
  build: function (m) {
    return {
      hashAlgorithm: m.fields.hashAlgorithm.value.result,
      issuerNameHash: m.fields.issuerNameHash.value,
      issuerKeyHash: m.fields.issuerKeyHash.value,
      serialNumber: m.fields.serialNumber.value,
      serialNumberHex: m.fields.serialNumber.node.content.toString("hex"),
    };
  },
});

// ---- response tree ---------------------------------------------------

// RevokedInfo ::= SEQUENCE { revocationTime GeneralizedTime, revocationReason [0]
// EXPLICIT CRLReason OPTIONAL } (RFC 6960 §4.2.1). Walked on the [1] IMPLICIT node,
// so assert:"constructed" (the context tag replaced the universal SEQUENCE tag).
var REVOKED_INFO = schema.seq([
  schema.field("revocationTime", GENERALIZED_TIME),
  schema.trailing([
    { tag: 0, name: "revocationReason", schema: CRL_REASON, explicit: true, emptyCode: "ocsp/bad-revoked-info" },
  ], { minTag: 0, maxTag: 0, unexpectedCode: "ocsp/bad-revoked-info", orderCode: "ocsp/bad-revoked-info" }),
], {
  assert: "constructed", code: "ocsp/bad-revoked-info", what: "RevokedInfo",
  build: function (m) {
    return {
      revocationTime: m.fields.revocationTime.value,
      revocationReason: m.fields.revocationReason.present ? m.fields.revocationReason.value : null,
    };
  },
});

// CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo,
// unknown [2] IMPLICIT NULL } (RFC 6960 §4.2.1). good/unknown are primitive empty
// context nodes; revoked is a constructed context [1] whose body is RevokedInfo.
var CERT_STATUS = schema.choice([
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitNull(0) },
  { when: { tagClass: "context", tagNumber: 1 }, schema: REVOKED_INFO },
  { when: { tagClass: "context", tagNumber: 2 }, schema: schema.implicitNull(2) },
], { code: "ocsp/bad-cert-status", what: "CertStatus" });

function _shapeCertStatus(field) {
  var t = field.node.tagNumber;
  if (t === 0) return { type: "good" };
  if (t === 2) return { type: "unknown" };
  var ri = field.value.result;
  return { type: "revoked", revocationTime: ri.revocationTime, revocationReason: ri.revocationReason };
}

// SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate GeneralizedTime,
// nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL, singleExtensions [1] EXPLICIT
// Extensions OPTIONAL } (RFC 6960 §4.2.1). certStatus is consumed positionally
// (before thisUpdate), so its context [0] good arm cannot be confused with the
// trailing nextUpdate [0].
var SINGLE_RESPONSE = schema.seq([
  schema.field("certID", CERT_ID),
  schema.field("certStatus", CERT_STATUS),
  schema.field("thisUpdate", GENERALIZED_TIME),
  schema.trailing([
    { tag: 0, name: "nextUpdate", schema: GENERALIZED_TIME, explicit: true, emptyCode: "ocsp/bad-single-response" },
    { tag: 1, name: "singleExtensions", schema: EXTENSIONS, explicit: true, emptyCode: "ocsp/bad-single-response" },
  ], { minTag: 0, maxTag: 1, unexpectedCode: "ocsp/bad-single-response", orderCode: "ocsp/bad-single-response" }),
], {
  assert: "sequence", code: "ocsp/bad-single-response", what: "SingleResponse",
  build: function (m) {
    return {
      certID: m.fields.certID.value.result,
      certStatus: _shapeCertStatus(m.fields.certStatus),
      thisUpdate: m.fields.thisUpdate.value,
      nextUpdate: m.fields.nextUpdate.present ? m.fields.nextUpdate.value : null,
      singleExtensions: m.fields.singleExtensions.present ? m.fields.singleExtensions.value.result : null,
    };
  },
});

// ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash } (RFC 6960 §4.2.1) —
// both EXPLICIT (the module is EXPLICIT TAGS). byKey is an EXPLICIT-wrapped universal
// OCTET STRING (0xA2 04 ...), NOT an IMPLICIT primitive [2].
var RESPONDER_ID = schema.choice([
  { when: { tagClass: "context", tagNumber: 1 }, schema: schema.explicit(1, NAME, { code: "ocsp/bad-responder-id" }) },
  { when: { tagClass: "context", tagNumber: 2 }, schema: schema.explicit(2, schema.octetString(), { code: "ocsp/bad-responder-id" }) },
], { code: "ocsp/bad-responder-id", what: "ResponderID" });

function _shapeResponderID(field) {
  if (field.node.tagNumber === 1) return { byName: field.value.result };
  // RFC 6960 §4.2.1 — KeyHash is the SHA-1 hash of the responder's public key, so a
  // conformant byKey ResponderID is exactly 20 octets; reject any other length.
  var keyHash = field.value;
  if (keyHash.length !== 20) throw NS.E("ocsp/bad-responder-id", "ResponderID byKey (KeyHash) must be a 20-byte SHA-1 hash (RFC 6960 §4.2.1)");
  return { byKey: keyHash };
}

// ResponseData ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1, responderID,
// producedAt GeneralizedTime, responses SEQUENCE OF SingleResponse,
// responseExtensions [1] EXPLICIT Extensions OPTIONAL } (RFC 6960 §4.2.1).
var RESPONSE_DATA = schema.seq([
  schema.optional("version", VERSION, { tag: 0, explicit: true, default: 1, emptyCode: "ocsp/bad-version" }),
  schema.field("responderID", RESPONDER_ID),
  schema.field("producedAt", GENERALIZED_TIME),
  schema.field("responses", schema.seqOf(SINGLE_RESPONSE, { assert: "sequence", min: 1, code: "ocsp/bad-responses", what: "responses" })),
  schema.trailing([
    { tag: 1, name: "responseExtensions", schema: EXTENSIONS, explicit: true, emptyCode: "ocsp/bad-response-data" },
  ], { minTag: 1, maxTag: 1, unexpectedCode: "ocsp/bad-response-data", orderCode: "ocsp/bad-response-data" }),
], {
  assert: "sequence", code: "ocsp/bad-response-data", what: "ResponseData",
  build: function (m) {
    return {
      version: m.fields.version.value,
      responderID: _shapeResponderID(m.fields.responderID),
      producedAt: m.fields.producedAt.value,
      responses: m.fields.responses.value.items.map(function (it) { return it.value.result; }),
      responseExtensions: m.fields.responseExtensions.present ? m.fields.responseExtensions.value.result : null,
    };
  },
});

// BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData, signatureAlgorithm
// AlgorithmIdentifier, signature BIT STRING, certs [0] EXPLICIT SEQUENCE OF
// Certificate OPTIONAL } (RFC 6960 §4.2.1). tbsResponseData.node.bytes is the exact
// signed region (no CMS-style re-tag divergence — the clean case).
var BASIC_OCSP_RESPONSE = schema.seq([
  schema.field("tbsResponseData", RESPONSE_DATA),
  schema.field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("signature", schema.bitString()),
  schema.trailing([
    { tag: 0, name: "certs", schema: CERTS, explicit: true, emptyCode: "ocsp/bad-basic-response" },
  ], { minTag: 0, maxTag: 0, unexpectedCode: "ocsp/bad-basic-response", orderCode: "ocsp/bad-basic-response" }),
], {
  assert: "sequence", code: "ocsp/bad-basic-response", what: "BasicOCSPResponse",
  build: function (m) {
    var tbs = m.fields.tbsResponseData.value.result;
    return {
      tbsResponseDataBytes: m.fields.tbsResponseData.node.bytes,
      version: tbs.version,
      responderID: tbs.responderID,
      producedAt: tbs.producedAt,
      responses: tbs.responses,
      responseExtensions: tbs.responseExtensions,
      signatureAlgorithm: m.fields.signatureAlgorithm.value.result,
      signature: _rawSignature(m.fields.signature),
      certs: m.fields.certs.present ? m.fields.certs.value.items.map(function (it) { return it.value; }) : [],
    };
  },
});

// ResponseBytes ::= SEQUENCE { responseType OBJECT IDENTIFIER, response OCTET STRING }
// (RFC 6960 §4.2.1). For id-pkix-ocsp-basic the response OCTET STRING content is a
// fresh DER BasicOCSPResponse (decoded + walked); an unknown responseType is
// recognized-and-deferred with a precise ocsp/unsupported-response-type.
var RESPONSE_BYTES = schema.seq([
  schema.field("responseType", schema.oidLeaf()),
  schema.field("response", schema.octetString()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "ocsp/bad-response-bytes", what: "ResponseBytes",
  build: function (m, ctx) {
    var responseType = m.fields.responseType.value;
    var raw = m.fields.response.value;
    if (responseType !== OID_OCSP_BASIC) {
      throw NS.E("ocsp/unsupported-response-type", (ctx.oid.name(responseType) || responseType) + " is not id-pkix-ocsp-basic (RFC 6960 §4.2.1)");
    }
    var inner;
    try { inner = asn1.decode(raw); }
    catch (e) { throw NS.E("ocsp/bad-der", "BasicOCSPResponse DER did not decode: " + ((e && e.message) || String(e)), e); }
    return {
      responseType: responseType,
      responseTypeName: ctx.oid.name(responseType) || null,
      response: raw,
      basicResponse: schema.walk(BASIC_OCSP_RESPONSE, inner, ctx).result,
    };
  },
});

// OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus, responseBytes [0]
// EXPLICIT ResponseBytes OPTIONAL } (RFC 6960 §4.2.1). The status <-> responseBytes
// biconditional (successful iff responseBytes present) is the OCSP-specific
// cross-field guard.
var OCSP_RESPONSE = schema.seq([
  schema.field("responseStatus", OCSP_RESPONSE_STATUS),
  schema.optional("responseBytes", RESPONSE_BYTES, { tag: 0, explicit: true, emptyCode: "ocsp/bad-ocsp-response" }),
], {
  assert: "sequence", arity: { min: 1 }, code: "ocsp/bad-ocsp-response", what: "OCSPResponse",
  build: function (m) {
    var status = m.fields.responseStatus.value;
    var present = m.fields.responseBytes.present;
    // RFC 6960 §4.2.1 — a successful response MUST carry responseBytes; any other
    // status MUST NOT (there is nothing to convey but the status).
    if (status.code === 0 && !present) throw NS.E("ocsp/bad-response-bytes", "a successful OCSPResponse must carry responseBytes (RFC 6960 §4.2.1)");
    if (status.code !== 0 && present) throw NS.E("ocsp/bad-response-bytes", "a non-successful OCSPResponse must not carry responseBytes (RFC 6960 §4.2.1)");
    var rb = present ? m.fields.responseBytes.value.result : null;
    return {
      responseStatus: status,
      responseBytes: rb ? { responseType: rb.responseType, responseTypeName: rb.responseTypeName, response: rb.response } : null,
      basicResponse: rb ? rb.basicResponse : null,
    };
  },
});

// ---- request tree ----------------------------------------------------

// Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0] EXPLICIT
// Extensions OPTIONAL } (RFC 6960 §4.1.1).
var REQUEST = schema.seq([
  schema.field("reqCert", CERT_ID),
  schema.trailing([
    { tag: 0, name: "singleRequestExtensions", schema: EXTENSIONS, explicit: true, emptyCode: "ocsp/bad-request" },
  ], { minTag: 0, maxTag: 0, unexpectedCode: "ocsp/bad-request", orderCode: "ocsp/bad-request" }),
], {
  assert: "sequence", code: "ocsp/bad-request", what: "Request",
  build: function (m) {
    return {
      certID: m.fields.reqCert.value.result,
      singleRequestExtensions: m.fields.singleRequestExtensions.present ? m.fields.singleRequestExtensions.value.result : null,
    };
  },
});

// Signature ::= SEQUENCE { signatureAlgorithm AlgorithmIdentifier, signature BIT
// STRING, certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL } (RFC 6960 §4.1.1).
var SIGNATURE = schema.seq([
  schema.field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("signature", schema.bitString()),
  schema.trailing([
    { tag: 0, name: "certs", schema: CERTS, explicit: true, emptyCode: "ocsp/bad-signature" },
  ], { minTag: 0, maxTag: 0, unexpectedCode: "ocsp/bad-signature", orderCode: "ocsp/bad-signature" }),
], {
  assert: "sequence", code: "ocsp/bad-signature", what: "Signature",
  build: function (m) {
    return {
      signatureAlgorithm: m.fields.signatureAlgorithm.value.result,
      signature: _rawSignature(m.fields.signature),
      certs: m.fields.certs.present ? m.fields.certs.value.items.map(function (it) { return it.value; }) : [],
    };
  },
});

// TBSRequest ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1, requestorName [1]
// EXPLICIT GeneralName OPTIONAL, requestList SEQUENCE OF Request, requestExtensions
// [2] EXPLICIT Extensions OPTIONAL } (RFC 6960 §4.1.1). requestorName is surfaced
// raw (GeneralName is a wide CHOICE with no factory yet).
var TBS_REQUEST = schema.seq([
  schema.optional("version", VERSION, { tag: 0, explicit: true, default: 1, emptyCode: "ocsp/bad-version" }),
  schema.optional("requestorName", GENERAL_NAME_RAW, { tag: 1, explicit: true, emptyCode: "ocsp/bad-requestor-name" }),
  schema.field("requestList", schema.seqOf(REQUEST, { assert: "sequence", min: 1, code: "ocsp/bad-request-list", what: "requestList" })),
  schema.trailing([
    { tag: 2, name: "requestExtensions", schema: EXTENSIONS, explicit: true, emptyCode: "ocsp/bad-tbs-request" },
  ], { minTag: 2, maxTag: 2, unexpectedCode: "ocsp/bad-tbs-request", orderCode: "ocsp/bad-tbs-request" }),
], {
  assert: "sequence", code: "ocsp/bad-tbs-request", what: "TBSRequest",
  build: function (m) {
    var rn = m.fields.requestorName;
    return {
      version: m.fields.version.value,
      requestorName: rn.present ? { bytes: rn.value.bytes, tagClass: rn.value.tagClass, tagNumber: rn.value.tagNumber } : null,
      requestList: m.fields.requestList.value.items.map(function (it) { return it.value.result; }),
      requestExtensions: m.fields.requestExtensions.present ? m.fields.requestExtensions.value.result : null,
    };
  },
});

// OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0] EXPLICIT
// Signature OPTIONAL } (RFC 6960 §4.1.1). tbsRequest.node.bytes is the raw signed
// region for external verification.
var OCSP_REQUEST = schema.seq([
  schema.field("tbsRequest", TBS_REQUEST),
  schema.optional("optionalSignature", SIGNATURE, { tag: 0, explicit: true, emptyCode: "ocsp/not-a-request" }),
], {
  assert: "sequence", arity: { min: 1 }, code: "ocsp/not-a-request", what: "OCSPRequest",
  build: function (m) {
    var tbs = m.fields.tbsRequest.value.result;
    var optionalSignature = m.fields.optionalSignature.present ? m.fields.optionalSignature.value.result : null;
    // RFC 6960 §4.1.2 — if the request is signed, the requestor SHALL specify its
    // name in requestorName (the identity the signature binds to). A signed request
    // without it is internally inconsistent; reject fail-closed.
    if (optionalSignature && tbs.requestorName === null) {
      throw NS.E("ocsp/missing-requestor-name", "a signed OCSPRequest must specify requestorName (RFC 6960 §4.1.2)");
    }
    return {
      tbsRequestBytes: m.fields.tbsRequest.node.bytes,
      version: tbs.version,
      requestorName: tbs.requestorName,
      requestList: tbs.requestList,
      requestExtensions: tbs.requestExtensions,
      optionalSignature: optionalSignature,
    };
  },
});

/**
 * @primitive  pki.schema.ocsp.parseRequest
 * @signature  pki.schema.ocsp.parseRequest(input) -> ocspRequest
 * @since      0.1.11
 * @status     stable
 * @spec       RFC 6960
 * @related    pki.schema.ocsp.parseResponse, pki.schema.parse
 *
 * Parse a DER `Buffer` or a PEM (`OCSP REQUEST`) string into a structured
 * OCSPRequest: `{ tbsRequestBytes, version, requestorName, requestList,
 * requestExtensions, optionalSignature }`. `tbsRequestBytes` is the exact on-wire
 * `tbsRequest` TLV for external signature verification; each `requestList` entry
 * carries its `CertID` (with the two issuer hashes raw). A malformed structure
 * throws a typed `OcspError` (`ocsp/*`) and a leaf-level codec fault surfaces as
 * `asn1/*`.
 *
 * @example
 *   var req = pki.schema.ocsp.parseRequest(der);
 *   req.requestList[0].certID.serialNumberHex;   // -> "1332"
 */
var parseRequest = pkix.makeParser({ pemLabel: "OCSP REQUEST", PemError: PemError, ErrorClass: OcspError, prefix: "ocsp", what: "OCSP request", topSchema: OCSP_REQUEST, ns: NS });

/**
 * @primitive  pki.schema.ocsp.parseResponse
 * @signature  pki.schema.ocsp.parseResponse(input) -> ocspResponse
 * @since      0.1.11
 * @status     stable
 * @spec       RFC 6960
 * @related    pki.schema.ocsp.parseRequest, pki.schema.parse
 *
 * Parse a DER `Buffer` or a PEM (`OCSP RESPONSE`) string into a structured
 * OCSPResponse: `{ responseStatus, responseBytes, basicResponse }`. For a successful
 * basic response, `basicResponse` carries `{ tbsResponseDataBytes, responderID,
 * producedAt, responses, signatureAlgorithm, signature, certs }`; each
 * `responses[i].certStatus` is `{ type: "good" | "revoked" | "unknown" }`. A
 * non-successful status carries no `responseBytes`. A malformed structure throws a
 * typed `OcspError` (`ocsp/*`); an unsupported `responseType` throws
 * `ocsp/unsupported-response-type`.
 *
 * @example
 *   var res = pki.schema.ocsp.parseResponse(der);
 *   res.responseStatus.name;                       // -> "successful"
 *   res.basicResponse.responses[0].certStatus.type; // -> "good" | "revoked" | "unknown"
 */
var parseResponse = pkix.makeParser({ pemLabel: "OCSP RESPONSE", PemError: PemError, ErrorClass: OcspError, prefix: "ocsp", what: "OCSP response", topSchema: OCSP_RESPONSE, ns: NS });

/**
 * @primitive  pki.schema.ocsp.pemDecode
 * @signature  pki.schema.ocsp.pemDecode(text, label?) -> Buffer
 * @since      0.1.11
 * @status     stable
 * @spec       RFC 7468, RFC 6960
 * @related    pki.schema.ocsp.parseResponse
 *
 * Extract the DER bytes from a PEM OCSP block (default label `OCSP RESPONSE`; pass
 * `"OCSP REQUEST"` for a request). Throws `PemError` on a missing / mismatched
 * envelope or a non-base64 body.
 *
 * @example
 *   var der = pki.schema.ocsp.pemDecode(pemText, "OCSP REQUEST");
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "OCSP RESPONSE", PemError); }

// An OCSPResponse root is the only registered structure that leads with an
// ENUMERATED child (a SEQUENCE of 1-2: responseStatus + an optional context [0]
// responseBytes). Every other root leads with a SEQUENCE (x509/crl/csr/ocsp-request),
// an OBJECT IDENTIFIER (cms), or an INTEGER (pkcs8), so the detector is
// unconditionally exclusive.
function matchesResponse(root) {
  var T = asn1.TAGS;
  if (!root || root.tagClass !== "universal" || root.tagNumber !== T.SEQUENCE || !root.children) return false;
  var k = root.children;
  if (k.length < 1 || k.length > 2) return false;
  if (!(k[0].tagClass === "universal" && k[0].tagNumber === T.ENUMERATED)) return false;
  if (k.length === 2 && !(k[1].tagClass === "context" && k[1].tagNumber === 0 && k[1].children)) return false;
  return true;
}

// An OCSPRequest root is a SEQUENCE of 1-2 whose first child is the tbsRequest
// SEQUENCE (optionally followed by a context [0] EXPLICIT signature). It leads with
// a SEQUENCE like x509/crl/csr, but those require EXACTLY 3 children (the
// signed-envelope trio), while an OCSPRequest is 1-2 — so it is excluded by arity.
function matchesRequest(root) {
  var T = asn1.TAGS;
  if (!root || root.tagClass !== "universal" || root.tagNumber !== T.SEQUENCE || !root.children) return false;
  var k = root.children;
  if (k.length < 1 || k.length > 2) return false;
  if (!(k[0].tagClass === "universal" && k[0].tagNumber === T.SEQUENCE && k[0].children)) return false;
  if (k.length === 2 && !(k[1].tagClass === "context" && k[1].tagNumber === 0 && k[1].children)) return false;
  return true;
}

module.exports = {
  parseRequest: parseRequest,
  parseResponse: parseResponse,
  pemDecode: pemDecode,
  matchesRequest: matchesRequest,
  matchesResponse: matchesResponse,
};
