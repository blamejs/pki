// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.ocsp (OCSP request + response parser, RFC 6960 §4).
 * Spec-first conformance vectors, RED-first: every valid OCSPRequest / OCSPResponse
 * parses to the documented shape; every malformed structure is rejected fail-closed
 * with a typed ocsp/* (or leaf-level asn1/*) error. Two entry points in one module —
 * parseRequest / parseResponse — mirroring the two-top-schema shape of PKCS#8.
 *
 * The response parser is a two-stage OID-dispatch: OCSPResponse carries an
 * ENUMERATED responseStatus + an OPTIONAL [0] EXPLICIT ResponseBytes; when
 * responseType == id-pkix-ocsp-basic its response OCTET STRING content is a fresh
 * DER BasicOCSPResponse that is decoded and walked. tbsRequest / tbsResponseData are
 * surfaced RAW (node.bytes) for external signature verification.
 *
 * RED baseline: pki.schema.ocsp.parseRequest / parseResponse are undefined until the
 * parser lands, so every vector throws — the suite drives the build to GREEN.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

// ---- OIDs (dotted literals are fine in TEST fixtures) ----------------
var SHA1                = "1.3.14.3.2.26";
var ID_PKIX_OCSP_BASIC  = "1.3.6.1.5.5.7.48.1.1";
var ID_PKIX_OCSP_NONCE  = "1.3.6.1.5.5.7.48.1.2";
var CN                  = "2.5.4.3";
var SIG_ALG             = "1.2.840.113549.1.1.11"; // sha256WithRSAEncryption

// ---- fixture builders (compose pki.asn1.build) -----------------------
function algId(o) { return b.sequence([b.oid(o)]); }
function name(cn) { return b.sequence([b.set([b.sequence([b.oid(CN), b.utf8(cn)])])]); }
function gen(iso) { return b.generalizedTime(new Date(iso)); }
function utc(iso) { return b.utcTime(new Date(iso)); }

// CertID { hashAlgorithm, issuerNameHash OCTET STRING, issuerKeyHash OCTET STRING, serialNumber INTEGER }
function certID(o) {
  o = o || {};
  var c = [
    o.hashAlg || algId(o.hashOid || SHA1),
    o.nameHash || b.octetString(Buffer.alloc(20, 0x11)),
    o.keyHash || b.octetString(Buffer.alloc(20, 0x22)),
  ];
  if (o.serial !== false) c.push(o.serialNode || b.integer(BigInt(o.serial === undefined ? 4919 : o.serial)));
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}

// CertStatus CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo, unknown [2] IMPLICIT NULL }
function statusGood()    { return b.contextPrimitive(0, Buffer.alloc(0)); }
function statusUnknown() { return b.contextPrimitive(2, Buffer.alloc(0)); }
function statusRevoked(iso, reason) {
  var fields = [gen(iso)];
  if (reason !== undefined && reason !== null) fields.push(b.explicit(0, b.enumerated(reason)));
  return b.contextConstructed(1, Buffer.concat(fields));
}

// ResponderID CHOICE { byName [1] EXPLICIT Name, byKey [2] EXPLICIT KeyHash }
function responderByName(cn) { return b.explicit(1, name(cn)); }
function responderByKey(buf) { return b.explicit(2, b.octetString(buf)); }

// GeneralName rfc822Name [2] IA5String — a valid GeneralName CHOICE alternative
// (context tags [0]..[8]); requestorName [1] EXPLICIT wraps one of these.
function rfc822(s) { return b.contextPrimitive(2, Buffer.from(s, "latin1")); }

// Extension { extnID, critical DEFAULT FALSE, extnValue OCTET STRING } — nonce
// extnValue wraps a DER OCTET STRING carrying the nonce bytes (RFC 6960 §4.4.1).
function nonceExt(nonceBytes) { return b.sequence([b.oid(ID_PKIX_OCSP_NONCE), b.octetString(b.octetString(Buffer.from(nonceBytes)))]); }
function extensions(list) { return b.sequence(list); }

// SingleResponse { certID, certStatus, thisUpdate, nextUpdate [0] EXPLICIT OPT, singleExtensions [1] EXPLICIT OPT }
function singleResponse(o) {
  var c = [o.certID || certID({}), o.status || statusGood(), o.thisUpdate || gen("2026-01-01T00:00:00Z")];
  if (o.nextUpdate) c.push(b.explicit(0, o.nextUpdate));
  if (o.singleExtensions) c.push(b.explicit(1, o.singleExtensions));
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}

// ResponseData { version [0] EXPLICIT DEFAULT v1, responderID, producedAt, responses SEQ OF, responseExtensions [1] EXPLICIT OPT }
function responseData(o) {
  o = o || {};
  var c = [];
  if (o.version !== undefined) c.push(b.explicit(0, b.integer(BigInt(o.version))));
  c.push(o.responderID || responderByKey(Buffer.alloc(20, 0xAB)));
  c.push(o.producedAt || gen("2026-01-02T00:00:00Z"));
  c.push(b.sequence(o.responses || [singleResponse({})]));
  if (o.responseExtensions) c.push(b.explicit(1, o.responseExtensions));
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}

// BasicOCSPResponse { tbsResponseData, signatureAlgorithm, signature BIT STRING, certs [0] EXPLICIT SEQ OF Certificate OPT }
function basicResponse(o) {
  o = o || {};
  var tbs = o.tbs || responseData({});
  var c = [tbs, o.sigAlg || algId(SIG_ALG), o.sig || b.bitString(Buffer.from([0xBE, 0xEF]))];
  if (o.certs) c.push(b.explicit(0, b.sequence(o.certs)));
  return { der: b.sequence(c), tbs: tbs };
}

// ResponseBytes { responseType OID, response OCTET STRING }
function responseBytes(typeOid, innerDer) { return b.sequence([b.oid(typeOid), b.octetString(innerDer)]); }

// OCSPResponse { responseStatus ENUMERATED, responseBytes [0] EXPLICIT OPT }
function ocspResponse(o) {
  o = o || {};
  var c = [b.enumerated(o.status === undefined ? 0 : o.status)];
  if (o.responseBytes) c.push(b.explicit(0, o.responseBytes));
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}
// A basic successful OCSPResponse wrapping the given BasicOCSPResponse der.
function basicOcspResponse(basic) { return ocspResponse({ status: 0, responseBytes: responseBytes(ID_PKIX_OCSP_BASIC, basic.der) }); }

// Request { reqCert CertID, singleRequestExtensions [0] EXPLICIT OPT }
function request(o) {
  o = o || {};
  var c = [o.certID || certID({})];
  if (o.singleRequestExtensions) c.push(b.explicit(0, o.singleRequestExtensions));
  return b.sequence(c);
}
// Signature { signatureAlgorithm, signature BIT STRING, certs [0] EXPLICIT SEQ OF Certificate OPT }
function signature(o) {
  o = o || {};
  var c = [o.sigAlg || algId(SIG_ALG), o.sig || b.bitString(Buffer.from([0x51, 0x67]))];
  if (o.certs) c.push(b.explicit(0, b.sequence(o.certs)));
  return b.sequence(c);
}
// TBSRequest { version [0] EXPLICIT DEFAULT v1, requestorName [1] EXPLICIT OPT, requestList SEQ OF, requestExtensions [2] EXPLICIT OPT }
function tbsRequest(o) {
  o = o || {};
  var c = [];
  if (o.version !== undefined) c.push(b.explicit(0, b.integer(BigInt(o.version))));
  if (o.requestorName) c.push(b.explicit(1, o.requestorName));
  c.push(b.sequence(o.requestList || [request({})]));
  if (o.requestExtensions) c.push(b.explicit(2, o.requestExtensions));
  if (o.children) return b.sequence(o.children);
  return b.sequence(c);
}
// OCSPRequest { tbsRequest, optionalSignature [0] EXPLICIT Signature OPT }
function ocspRequest(o) {
  o = o || {};
  var tbs = o.tbs || tbsRequest({});
  var c = [tbs];
  if (o.optionalSignature) c.push(b.explicit(0, o.optionalSignature));
  if (o.children) return b.sequence(o.children);
  return { der: b.sequence(c), tbs: tbs };
}

// A cert-shaped raw element for certs [0] (surfaced raw, never parsed here).
function rawCert() { return b.sequence([b.oid("1.2.3"), b.integer(1n)]); }

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseReqCode(der) { return code(function () { pki.schema.ocsp.parseRequest(der); }); }
function parseRespCode(der) { return code(function () { pki.schema.ocsp.parseResponse(der); }); }
function parseReq(der) { return pki.schema.ocsp.parseRequest(der); }
function parseResp(der) { return pki.schema.ocsp.parseResponse(der); }

// ---- ACCEPT — request ------------------------------------------------
function testAcceptRequest() {
  // 2. minimal request: one Request { CertID(SHA-1) }, no version / requestorName / exts / signature.
  var req = ocspRequest({});
  var m = parseReq(req.der);
  check("2. minimal request: tbsRequestBytes are the raw tbsRequest TLV", Buffer.isBuffer(m.tbsRequestBytes) && m.tbsRequestBytes.equals(req.tbs));
  check("2. minimal request: version defaults to 1", m.version === 1);
  check("2. minimal request: one Request", Array.isArray(m.requestList) && m.requestList.length === 1);
  check("2. minimal request: CertID hashAlgorithm sha1", m.requestList[0].certID.hashAlgorithm.name === "sha1");
  check("2. minimal request: CertID serialNumberHex", typeof m.requestList[0].certID.serialNumberHex === "string");
  check("2. minimal request: issuerNameHash raw octets", Buffer.isBuffer(m.requestList[0].certID.issuerNameHash) && m.requestList[0].certID.issuerNameHash.length === 20);
  check("2. minimal request: no optionalSignature", m.optionalSignature === null);
  check("2. minimal request: no requestorName", m.requestorName === null);

  // 3. signed request: optionalSignature [0] { sigAlg, BIT STRING sig, certs [0] one
  //    raw cert }. A signed request SHALL carry requestorName (RFC 6960 §4.1.2).
  var sigBytes = Buffer.from([0x51, 0x67]);
  var sreq = ocspRequest({ tbs: tbsRequest({ requestorName: rfc822("ocsp@ca.example") }), optionalSignature: signature({ sig: b.bitString(sigBytes), certs: [rawCert()] }) });
  var ms = parseReq(sreq.der);
  check("3. signed request: signatureAlgorithm surfaced", ms.optionalSignature && ms.optionalSignature.signatureAlgorithm.oid === SIG_ALG);
  check("3. signed request: raw signature bytes", Buffer.isBuffer(ms.optionalSignature.signature) && ms.optionalSignature.signature.equals(sigBytes));
  check("3. signed request: one raw cert", Array.isArray(ms.optionalSignature.certs) && ms.optionalSignature.certs.length === 1 && Buffer.isBuffer(ms.optionalSignature.certs[0]));
  // 3b. signed request WITHOUT requestorName -> reject (RFC 6960 §4.1.2 SHALL).
  check("3b. signed request without requestorName rejected",
    parseReqCode(ocspRequest({ optionalSignature: signature({}) }).der) === "ocsp/missing-requestor-name");
  // 3c. empty requestList -> reject; requestList is one-or-more (RFC 6960 §4.1.1).
  check("3c. empty requestList rejected",
    parseReqCode(ocspRequest({ tbs: tbsRequest({ requestList: [] }) }).der) === "ocsp/bad-request-list");

  // 4. request with requestorName [1] EXPLICIT GeneralName + requestExtensions [2] (a nonce).
  var nreq = ocspRequest({ tbs: tbsRequest({ requestorName: rfc822("ocsp@ca.example"), requestExtensions: extensions([nonceExt([1, 2, 3, 4, 5])]) }) });
  var mn = parseReq(nreq.der);
  check("4. requestorName surfaced raw", mn.requestorName && Buffer.isBuffer(mn.requestorName.bytes) && mn.requestorName.tagNumber === 2);
  check("4. requestExtensions nonce named", Array.isArray(mn.requestExtensions) && mn.requestExtensions[0].name === "ocspNonce");
  check("4. requestExtensions nonce value raw", Buffer.isBuffer(mn.requestExtensions[0].value));
  // 4b. requestorName whose inner value is not a GeneralName ([1] EXPLICIT INTEGER) -> reject.
  check("4b. non-GeneralName requestorName rejected",
    parseReqCode(ocspRequest({ tbs: tbsRequest({ requestorName: b.integer(5n) }) }).der) === "ocsp/bad-requestor-name");
  // 4f. requestorName as directoryName [4] EXPLICIT Name (a valid constructed GeneralName) -> accept.
  check("4f. directoryName requestorName accepted",
    parseReqCode(ocspRequest({ tbs: tbsRequest({ requestorName: b.explicit(4, name("Requestor CA")) }), optionalSignature: signature({}) }).der) === "NO-THROW");
}

// ---- ACCEPT — response -----------------------------------------------
function testAcceptResponse() {
  // 5. successful basic response, one SingleResponse { good }, byKey responderID.
  var basic = basicResponse({ tbs: responseData({ responderID: responderByKey(Buffer.alloc(20, 0xAB)), responses: [singleResponse({ status: statusGood() })] }) });
  var m = parseResp(basicOcspResponse(basic));
  check("5. responseStatus successful", m.responseStatus.code === 0 && m.responseStatus.name === "successful");
  check("5. tbsResponseDataBytes are the raw ResponseData TLV", Buffer.isBuffer(m.basicResponse.tbsResponseDataBytes) && m.basicResponse.tbsResponseDataBytes.equals(basic.tbs));
  check("5. responderID byKey raw 20-byte hash", m.basicResponse.responderID.byKey && m.basicResponse.responderID.byKey.length === 20);
  check("5. certStatus good", m.basicResponse.responses[0].certStatus.type === "good");
  check("5. producedAt is a Date", m.basicResponse.producedAt instanceof Date);

  // 6. revoked status with revocationTime + revocationReason [0] EXPLICIT keyCompromise(1).
  var rev = basicResponse({ tbs: responseData({ responses: [singleResponse({ status: statusRevoked("2025-06-01T00:00:00Z", 1) })] }) });
  var mr = parseResp(basicOcspResponse(rev));
  check("6. certStatus revoked", mr.basicResponse.responses[0].certStatus.type === "revoked");
  check("6. revocationTime Date", mr.basicResponse.responses[0].certStatus.revocationTime instanceof Date);
  check("6. revocationReason keyCompromise", mr.basicResponse.responses[0].certStatus.revocationReason === "keyCompromise");

  // 7. unknown status.
  var unk = basicResponse({ tbs: responseData({ responses: [singleResponse({ status: statusUnknown() })] }) });
  check("7. certStatus unknown", parseResp(basicOcspResponse(unk)).basicResponse.responses[0].certStatus.type === "unknown");

  // 8. byName responderID (Name/RDNSequence).
  var byn = basicResponse({ tbs: responseData({ responderID: responderByName("Responder CA") }) });
  var mb = parseResp(basicOcspResponse(byn));
  check("8. responderID byName dn rendered", mb.basicResponse.responderID.byName && /Responder CA/.test(mb.basicResponse.responderID.byName.dn));

  // 9. nextUpdate [0] EXPLICIT + singleExtensions [1] EXPLICIT present.
  var full = basicResponse({ tbs: responseData({ responses: [singleResponse({ nextUpdate: gen("2026-02-01T00:00:00Z"), singleExtensions: extensions([nonceExt([9])]) })] }) });
  var mf = parseResp(basicOcspResponse(full));
  check("9. nextUpdate decoded", mf.basicResponse.responses[0].nextUpdate instanceof Date);
  check("9. singleExtensions decoded", Array.isArray(mf.basicResponse.responses[0].singleExtensions) && mf.basicResponse.responses[0].singleExtensions.length === 1);

  // 10. non-successful status (tryLater(3)) with NO responseBytes.
  var tl = parseResp(ocspResponse({ status: 3 }));
  check("10. tryLater status name", tl.responseStatus.name === "tryLater");
  check("10. no responseBytes", tl.responseBytes === null && tl.basicResponse === null);

  // 11. RAW EXACTNESS: tbsResponseDataBytes + signature never a re-encode.
  var sigBytes = Buffer.from([0xBE, 0xEF]);
  var raw = basicResponse({ tbs: responseData({}), sig: b.bitString(sigBytes) });
  var mx = parseResp(basicOcspResponse(raw));
  check("11. tbsResponseDataBytes exact", mx.basicResponse.tbsResponseDataBytes.equals(raw.tbs));
  check("11. signature bytes exact", mx.basicResponse.signature.equals(sigBytes));
}

// ---- REJECT — envelope / DER -----------------------------------------
function testRejectEnvelope() {
  // 12/13. responseStatus 4 (unused) / >= 7 -> ocsp/bad-response-status.
  check("12. responseStatus 4 (unused) rejected", parseRespCode(ocspResponse({ status: 4 })) === "ocsp/bad-response-status");
  check("13. responseStatus 7 (>=7) rejected", parseRespCode(ocspResponse({ status: 7 })) === "ocsp/bad-response-status");
  // 14. responseStatus encoded INTEGER not ENUMERATED -> leaf asn1/unexpected-tag.
  check("14. responseStatus INTEGER not ENUMERATED", parseRespCode(b.sequence([b.integer(0n)])) === "asn1/unexpected-tag");
  // 15. explicitly-encoded version [0] INTEGER 0 -> ocsp/bad-version (empty accept map).
  check("15a. request explicit version rejected", parseReqCode(ocspRequest({ tbs: tbsRequest({ version: 0 }) }).der) === "ocsp/bad-version");
  check("15b. response explicit version rejected", parseRespCode(basicOcspResponse(basicResponse({ tbs: responseData({ version: 0 }) }))) === "ocsp/bad-version");
  // 16. non-successful status carrying responseBytes -> ocsp/bad-response-bytes.
  check("16. non-successful + responseBytes rejected", parseRespCode(ocspResponse({ status: 1, responseBytes: responseBytes(ID_PKIX_OCSP_BASIC, basicResponse({}).der) })) === "ocsp/bad-response-bytes");
  // 17. successful with NO responseBytes -> ocsp/bad-response-bytes.
  check("17. successful without responseBytes rejected", parseRespCode(ocspResponse({ status: 0 })) === "ocsp/bad-response-bytes");
  // 18. trailing garbage after the outer SEQUENCE -> ocsp/bad-der.
  var goodResp = basicOcspResponse(basicResponse({}));
  check("18. trailing byte rejected", parseRespCode(Buffer.concat([goodResp, Buffer.from([0x00])])) === "ocsp/bad-der");
  // 20. indefinite-length outer SEQUENCE -> ocsp/bad-der.
  check("20. indefinite length rejected", parseRespCode(Buffer.from([0x30, 0x80, 0x00, 0x00])) === "ocsp/bad-der");
  // 21. non-minimal length -> ocsp/bad-der.
  check("21. non-minimal length rejected", parseRespCode(Buffer.from([0x30, 0x81, 0x03, 0x0a, 0x01, 0x00])) === "ocsp/bad-der");
}

// ---- REJECT — ResponderID / CertStatus tag traps ---------------------
function testRejectResponderCertStatus() {
  // 22. ResponderID byKey encoded IMPLICIT (0x82 hash) instead of EXPLICIT (0xA2 04 hash).
  var implicitByKey = b.contextPrimitive(2, Buffer.alloc(20, 0xCC));
  var badRid = basicResponse({ tbs: responseData({ responderID: implicitByKey }) });
  check("22. byKey IMPLICIT instead of EXPLICIT rejected", parseRespCode(basicOcspResponse(badRid)) !== "NO-THROW");
  // 22b. byKey KeyHash not 20 bytes (not a SHA-1 hash) -> ocsp/bad-responder-id.
  var shortKeyHash = basicResponse({ tbs: responseData({ responderID: responderByKey(Buffer.alloc(10, 0xAB)) }) });
  check("22b. byKey KeyHash wrong length rejected", parseRespCode(basicOcspResponse(shortKeyHash)) === "ocsp/bad-responder-id");
  // 23. ResponderID as a bare universal type / unknown context tag -> no CHOICE arm.
  var badRid2 = basicResponse({ tbs: responseData({ responderID: b.contextConstructed(3, name("X")) }) });
  check("23. responderID unknown arm rejected", parseRespCode(basicOcspResponse(badRid2)) === "ocsp/bad-responder-id");
  // 24. CertStatus good as 0xA0 00 (constructed) -> leaf asn1/expected-primitive (implicit-NULL leaf).
  var goodConstructed = basicResponse({ tbs: responseData({ responses: [singleResponse({ status: b.contextConstructed(0, Buffer.alloc(0)) })] }) });
  check("24. good constructed rejected", parseRespCode(basicOcspResponse(goodConstructed)) === "asn1/expected-primitive");
  // 25. CertStatus good as 0x80 01 00 (non-zero length) -> leaf asn1/bad-null.
  var goodNonEmpty = basicResponse({ tbs: responseData({ responses: [singleResponse({ status: b.contextPrimitive(0, Buffer.from([0x00])) })] }) });
  check("25. good non-empty rejected", parseRespCode(basicOcspResponse(goodNonEmpty)) === "asn1/bad-null");
  // 26. CertStatus revoked as PRIMITIVE 0x81 ... -> ocsp/bad-revoked-info (assert:"constructed").
  var revPrimitive = basicResponse({ tbs: responseData({ responses: [singleResponse({ status: b.contextPrimitive(1, gen("2025-01-01T00:00:00Z")) })] }) });
  check("26. revoked primitive rejected", parseRespCode(basicOcspResponse(revPrimitive)) === "ocsp/bad-revoked-info");
  // 27. CertStatus context [3] (no arm) -> ocsp/bad-cert-status.
  var certStatus3 = basicResponse({ tbs: responseData({ responses: [singleResponse({ status: b.contextPrimitive(3, Buffer.alloc(0)) })] }) });
  check("27. certStatus unknown arm rejected", parseRespCode(basicOcspResponse(certStatus3)) === "ocsp/bad-cert-status");
}

// ---- REJECT — time / CertID / extensions -----------------------------
function testRejectTimeCertIdExt() {
  // 29. producedAt as UTCTime where GeneralizedTime is required -> ocsp/bad-time.
  var utcProduced = basicResponse({ tbs: responseData({ producedAt: utc("2026-01-02T00:00:00Z") }) });
  check("29. producedAt UTCTime rejected", parseRespCode(basicOcspResponse(utcProduced)) === "ocsp/bad-time");
  // 31. CertID with only 3 fields (missing serialNumber) -> ocsp/bad-cert-id (arity).
  var certID3 = certID({ children: [algId(SHA1), b.octetString(Buffer.alloc(20, 1)), b.octetString(Buffer.alloc(20, 2))] });
  var req3 = ocspRequest({ tbs: tbsRequest({ requestList: [request({ certID: certID3 })] }) });
  check("31. CertID missing serialNumber rejected", parseReqCode(req3.der) === "ocsp/bad-cert-id");
  // 32. CertID.serialNumber non-minimal INTEGER -> leaf asn1/non-minimal-integer.
  var badSerial = Buffer.from([0x02, 0x02, 0x00, 0x01]); // redundant leading 0x00
  var certIDbadSerial = certID({ children: [algId(SHA1), b.octetString(Buffer.alloc(20, 1)), b.octetString(Buffer.alloc(20, 2)), badSerial] });
  var reqBadSerial = ocspRequest({ tbs: tbsRequest({ requestList: [request({ certID: certIDbadSerial })] }) });
  check("32. non-minimal serialNumber rejected", parseReqCode(reqBadSerial.der) === "asn1/non-minimal-integer");
  // 35. empty Extensions SEQUENCE when the OPTIONAL wrapper is present -> ocsp/bad-extensions.
  var emptyExtReq = ocspRequest({ tbs: tbsRequest({ requestExtensions: extensions([]) }) });
  check("35. empty Extensions rejected", parseReqCode(emptyExtReq.der) === "ocsp/bad-extensions");
}

// ---- REJECT — response re-dispatch -----------------------------------
function testRejectRedispatch() {
  // 36. responseType != id-pkix-ocsp-basic -> ocsp/unsupported-response-type.
  var other = ocspResponse({ status: 0, responseBytes: responseBytes("1.2.3.4.5", basicResponse({}).der) });
  check("36. unsupported responseType rejected", parseRespCode(other) === "ocsp/unsupported-response-type");
  // 37. basic but response OCTET STRING has trailing bytes after BasicOCSPResponse -> ocsp/bad-der.
  var withTrailer = ocspResponse({ status: 0, responseBytes: responseBytes(ID_PKIX_OCSP_BASIC, Buffer.concat([basicResponse({}).der, Buffer.from([0x00])])) });
  check("37. inner trailing bytes rejected", parseRespCode(withTrailer) === "ocsp/bad-der");
  // 38. revocationReason value 7 (not used) -> ocsp/bad-revocation-reason.
  var badReason = basicResponse({ tbs: responseData({ responses: [singleResponse({ status: statusRevoked("2025-01-01T00:00:00Z", 7) })] }) });
  check("38. revocationReason 7 rejected", parseRespCode(basicOcspResponse(badReason)) === "ocsp/bad-revocation-reason");
}

// ---- DISPATCH + coercion ---------------------------------------------
function testDispatch() {
  // 39. a built OCSP response routes to ocsp-response.
  var resp = basicOcspResponse(basicResponse({}));
  var rr = pki.schema.parse(resp);
  check("39. response routes to ocsp-response", rr && rr.responseStatus && rr.basicResponse);
  check("39. all() lists ocsp-response", pki.schema.all().indexOf("ocsp-response") !== -1);
  // 40. a built OCSP request routes to ocsp-request (children[0] SEQUENCE, arity 1-2), not x509/crl/csr.
  var req = ocspRequest({}).der;
  var qr = pki.schema.parse(req);
  check("40. request routes to ocsp-request", qr && qr.requestList && qr.tbsRequestBytes);
  check("40. all() lists ocsp-request", pki.schema.all().indexOf("ocsp-request") !== -1);
  // 41. a CMS message (OID-first) still routes to cms, never misclassified as ocsp.
  var cms = b.sequence([b.oid("1.2.840.113549.1.7.2"), b.explicit(0, b.sequence([b.integer(1n), b.set([]), b.sequence([b.oid("1.2.840.113549.1.7.1")]), b.set([])]))]);
  check("41. cms routes to cms, not ocsp", pki.schema.parse(cms).signerInfos !== undefined);
  // 42. INPUT COERCION via the shared parse-entry.
  check("42a. non-buffer input -> ocsp/bad-input", parseRespCode(42) === "ocsp/bad-input");
  check("42b. Uint8Array input parses", (function () { var u = Uint8Array.from(resp); return code(function () { pki.schema.ocsp.parseResponse(u); }) === "NO-THROW"; })());
  // 43. MULTI-DEFECT fail-closed: never NO-THROW, never a raw TypeError.
  var multi = ocspResponse({ status: 4, responseBytes: responseBytes(ID_PKIX_OCSP_BASIC, basicResponse({ tbs: responseData({ responderID: b.contextConstructed(3, name("X")) }) }).der) });
  var c43 = parseRespCode(multi);
  check("43. multi-defect fail-closed (typed reject)", c43 !== "NO-THROW" && c43.indexOf("RAW:") !== 0);
}

// ---- REJECT — EXPLICIT-wrapper / position / codec-leaf edges ---------
function testRejectExtras() {
  // 19. trailing bytes INSIDE an EXPLICIT wrapper: responseBytes [0] with two inner
  //     TLVs -> the _explicitInner "exactly one value" reject (field's code).
  var twoInner = b.contextConstructed(0, Buffer.concat([responseBytes(ID_PKIX_OCSP_BASIC, basicResponse({}).der), b.integer(1n)]));
  check("19. explicit wrapper with two inner TLVs rejected", parseRespCode(b.sequence([b.enumerated(0), twoInner])) === "ocsp/bad-ocsp-response");
  // 28. position confusion: a [0] EXPLICIT (nextUpdate shape) where certStatus [0] is
  //     expected -> the CHOICE consumes it as good, the implicit-NULL leaf rejects the
  //     constructed form -> a typed reject, never NO-THROW.
  var confused = b.sequence([certID({}), b.explicit(0, gen("2026-01-01T00:00:00Z")), gen("2026-01-01T00:00:00Z")]);
  var badSR = basicResponse({ tbs: responseData({ responses: [confused] }) });
  var c28 = parseRespCode(basicOcspResponse(badSR));
  check("28. certStatus/nextUpdate position confusion rejected", c28 !== "NO-THROW" && c28.indexOf("RAW:") !== 0);
  // 30. producedAt GeneralizedTime with fractional seconds -> leaf asn1/* fault.
  var badTime = Buffer.concat([Buffer.from([0x18, 0x11]), Buffer.from("20260101000000.5Z", "latin1")]);
  var badTimeResp = basicResponse({ tbs: responseData({ producedAt: badTime }) });
  check("30. malformed GeneralizedTime -> leaf asn1 fault", parseRespCode(basicOcspResponse(badTimeResp)).indexOf("asn1/") === 0);
  // 33. Signature.signature BIT STRING with unused low bits set -> leaf asn1/bad-bit-string.
  var badBitString = Buffer.from([0x03, 0x02, 0x01, 0xFF]); // unusedBits=1, low bit set (non-canonical)
  var badSig = basicResponse({ sig: badBitString });
  check("33. non-canonical BIT STRING signature rejected", parseRespCode(basicOcspResponse(badSig)) === "asn1/bad-bit-string");
  // 34. critical BOOLEAN present-and-FALSE in an extension -> ocsp/bad-extension.
  var falseCritical = b.sequence([b.oid(ID_PKIX_OCSP_NONCE), b.boolean(false), b.octetString(b.octetString(Buffer.from([1])))]);
  var badExtReq = ocspRequest({ tbs: tbsRequest({ requestExtensions: extensions([falseCritical]) }) });
  check("34. explicit critical FALSE extension rejected", parseReqCode(badExtReq.der) === "ocsp/bad-extension");
  // 35b. non-octet-aligned signature BIT STRING (unusedBits > 0) is malformed for a
  //      byte-string signature -> ocsp/bad-signature, on BOTH the response and request.
  var unalignedResp = basicResponse({ sig: b.bitString(Buffer.from([0xFE]), 1) });
  check("35b. non-octet-aligned response signature rejected", parseRespCode(basicOcspResponse(unalignedResp)) === "ocsp/bad-signature");
  var unalignedReq = ocspRequest({ tbs: tbsRequest({ requestorName: rfc822("ocsp@ca.example") }), optionalSignature: signature({ sig: b.bitString(Buffer.from([0xFE]), 1) }) });
  check("35c. non-octet-aligned request signature rejected", parseReqCode(unalignedReq.der) === "ocsp/bad-signature");
  // 35d/35e. a certs element that is not a Certificate (a SEQUENCE) -> ocsp/bad-certs,
  //          on both the response BasicOCSPResponse and the request Signature.
  check("35d. non-SEQUENCE response certs element rejected",
    parseRespCode(basicOcspResponse(basicResponse({ certs: [b.integer(1n)] }))) === "ocsp/bad-certs");
  var badCertsReq = ocspRequest({ tbs: tbsRequest({ requestorName: rfc822("ocsp@ca.example") }), optionalSignature: signature({ certs: [b.integer(1n)] }) });
  check("35e. non-SEQUENCE request certs element rejected", parseReqCode(badCertsReq.der) === "ocsp/bad-certs");
  // 4c. requestorName directoryName [4] encoded PRIMITIVE (must be constructed) -> reject.
  check("4c. primitive directoryName requestorName rejected",
    parseReqCode(ocspRequest({ tbs: tbsRequest({ requestorName: b.contextPrimitive(4, Buffer.from([1, 2, 3])) }) }).der) === "ocsp/bad-requestor-name");
  // 4d. requestorName rfc822Name [1] with a non-IA5 (high) byte -> reject.
  check("4d. non-IA5 rfc822Name requestorName rejected",
    parseReqCode(ocspRequest({ tbs: tbsRequest({ requestorName: b.contextPrimitive(1, Buffer.from([0x80])) }) }).der) === "ocsp/bad-requestor-name");
  // 4e. requestorName iPAddress [7] with an invalid length -> reject.
  check("4e. bad-length iPAddress requestorName rejected",
    parseReqCode(ocspRequest({ tbs: tbsRequest({ requestorName: b.contextPrimitive(7, Buffer.from([1, 2, 3])) }) }).der) === "ocsp/bad-requestor-name");
  // 4g. empty otherName [0] (a constructed GeneralName with no body) -> reject.
  check("4g. empty otherName requestorName rejected",
    parseReqCode(ocspRequest({ tbs: tbsRequest({ requestorName: b.contextConstructed(0, Buffer.alloc(0)) }) }).der) === "ocsp/bad-requestor-name");
  // 4h. incomplete otherName [0] with only type-id (missing the value [0]) -> reject.
  check("4h. incomplete otherName requestorName rejected",
    parseReqCode(ocspRequest({ tbs: tbsRequest({ requestorName: b.contextConstructed(0, b.oid("1.2.3.4")) }) }).der) === "ocsp/bad-requestor-name");
  // 4i. complete otherName [0] { type-id, value [0] EXPLICIT } -> accept (signed request).
  var otherName = b.contextConstructed(0, Buffer.concat([b.oid("1.2.3.4"), b.explicit(0, b.utf8("upn@ca.example"))]));
  check("4i. complete otherName requestorName accepted",
    parseReqCode(ocspRequest({ tbs: tbsRequest({ requestorName: otherName }), optionalSignature: signature({}) }).der) === "NO-THROW");
  // 5d. empty ResponseData.responses -> reject; responses is one-or-more (RFC 6960 §4.2.1).
  check("5d. empty responses rejected",
    parseRespCode(basicOcspResponse(basicResponse({ tbs: responseData({ responses: [] }) }))) === "ocsp/bad-responses");
}

function run() {
  testAcceptRequest();
  testAcceptResponse();
  testRejectEnvelope();
  testRejectResponderCertStatus();
  testRejectTimeCertIdExt();
  testRejectRedispatch();
  testRejectExtras();
  testDispatch();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
