// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.schema.cmc (RFC 5272 / 5273 / 5274 as updated by RFC 6402):
 * the CMC message layer carried inside a CMS SignedData whose encapsulated
 * content type is id-cct-PKIData (a Full PKI Request) or id-cct-PKIResponse
 * (a Full PKI Response).
 *
 * Spec-first conformance vectors, RED-first: pki.schema.cmc.parse is undefined
 * until the module lands, so every vector throws and the suite drives it GREEN.
 *
 * The fragile cells this file exists to pin, each a place where the spec is
 * ambiguous or self-contradictory and a decoder could plausibly guess:
 *   - PD2/PR6: all four (three) sequences are MANDATORY though each may be
 *     EMPTY. A dropped-but-empty field is malformed, not absent.
 *   - PD8: BodyPartID uniqueness spans the WHOLE message, not one sequence;
 *     0 is reserved as "the current PKIData" and is not an element's identity.
 *   - ST3: OtherStatusInfo is a CHOICE whose `extendedFailInfo` arm is UNTAGGED
 *     in the 1988 module and [1] in the 2008 module, colliding with `pendInfo`.
 *     Both encodings occur; the decoder disambiguates on the first child's tag
 *     and REFUSES anything it cannot tell apart.
 *   - IP1: the reqSequence byte range is surfaced RAW, tag and length included,
 *     because the Identity Proof V2 witness is computed over exactly those bytes.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

// ---- OIDs (dotted literals are fine in TEST fixtures) ----------------
var ID_CCT_PKI_DATA      = "1.3.6.1.5.5.7.12.2";
var ID_CCT_PKI_RESPONSE  = "1.3.6.1.5.5.7.12.3";
var ID_DATA              = "1.2.840.113549.1.7.1";
var ID_SIGNED_DATA       = "1.2.840.113549.1.7.2";
var ID_CMC_STATUS_INFO   = "1.3.6.1.5.5.7.7.1";
var ID_CMC_IDENTIFICATION = "1.3.6.1.5.5.7.7.2";
var ID_CMC_TRANSACTION_ID = "1.3.6.1.5.5.7.7.5";
var ID_CMC_STATUS_INFO_V2 = "1.3.6.1.5.5.7.7.25";
var ID_CMC_RESPONSE_BODY  = "1.3.6.1.5.5.7.7.37";
var ID_CMC_RA_IDENTITY_WITNESS = "1.3.6.1.5.5.7.7.35";
var SHA256               = "2.16.840.1.101.3.4.2.1";

function code(fn) {
  try { var r = fn(); if (r && typeof r.then === "function") return "ASYNC"; return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); }
}

// ---- fixture builders ------------------------------------------------

// A minimal SignedData wrapper carrying `eContent` under `eContentType`. The CMC
// layer only reads the encapsulated content, so one empty signerInfos SET is
// enough structure for the parser under test.
//
// CMSVersion follows RFC 5652 sec. 5.1, which the shipped CMS parser enforces: a
// content type other than id-data forces v3, and id-data takes v1. Hard-coding
// one version here would fail in the CMS layer for reasons that have nothing to
// do with CMC.
function signedData(eContentType, eContentDer, opts) {
  opts = opts || {};
  var encap = eContentDer === null
    ? b.sequence([b.oid(eContentType)])
    : b.sequence([b.oid(eContentType), b.explicit(0, b.octetString(eContentDer))]);
  var version = eContentType === ID_DATA ? 1n : 3n;
  var sd = b.sequence([
    b.integer(version),
    b.set([b.sequence([b.oid(SHA256), b.nullValue()])]),
    encap,
    b.set([]),
  ]);
  return b.sequence([b.oid(opts.outerType || ID_SIGNED_DATA), b.explicit(0, sd)]);
}

// PKIData ::= SEQUENCE { controlSequence, reqSequence, cmsSequence, otherMsgSequence }
function pkiData(controls, reqs, cmsSeq, otherMsgs) {
  return b.sequence([
    b.sequence(controls || []),
    b.sequence(reqs || []),
    b.sequence(cmsSeq || []),
    b.sequence(otherMsgs || []),
  ]);
}

// PKIResponse ::= SEQUENCE { controlSequence, cmsSequence, otherMsgSequence }
function pkiResponse(controls, cmsSeq, otherMsgs) {
  return b.sequence([
    b.sequence(controls || []),
    b.sequence(cmsSeq || []),
    b.sequence(otherMsgs || []),
  ]);
}

// TaggedAttribute ::= SEQUENCE { bodyPartID, attrType, attrValues SET OF ANY }
function taggedAttr(bodyPartID, attrType, values) {
  return b.sequence([b.integer(BigInt(bodyPartID)), b.oid(attrType), b.set(values || [])]);
}

// TaggedCertificationRequest ::= SEQUENCE { bodyPartID, certificationRequest }
// carried in the tcr [0] IMPLICIT arm of TaggedRequest.
function tcr(bodyPartID, csrDer) {
  return b.contextConstructed(0, Buffer.concat([b.integer(BigInt(bodyPartID)), csrDer]));
}

// A structurally valid CertificationRequest whose subject is the given RDNSequence.
function csr(subjectDer) {
  var spki = b.sequence([b.sequence([b.oid("1.2.840.10045.2.1"), b.oid("1.2.840.10045.3.1.7")]),
    b.bitString(Buffer.from([4, 1, 2]), 0)]);
  var cri = b.sequence([b.integer(0n), subjectDer, spki, b.contextConstructed(0, Buffer.alloc(0))]);
  return b.sequence([cri, b.sequence([b.oid(SHA256)]), b.bitString(Buffer.from([0]), 0)]);
}
function dn(cn) {
  return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]);
}

// crm [1] IMPLICIT CertReqMsg. The module is IMPLICIT TAGS, so the [1] node's
// children ARE the CertReqMsg fields:
//   CertReqMsg  ::= SEQUENCE { certReq CertRequest, popo OPTIONAL, regInfo OPTIONAL }
//   CertRequest ::= SEQUENCE { certReqId INTEGER, certTemplate CertTemplate, ... }
// so certReqId sits at certReq.children[0] -- which RFC 5272 sec. 3.2.2 makes
// this request's body part identifier.
// The CertTemplate comes from the shipped builder rather than hand-rolled tags:
// CertTemplate mixes IMPLICIT and (for the CHOICE-typed Name fields, which ASN.1
// forces back to EXPLICIT) explicit tagging, and getting that wrong in a fixture
// produces a template the CRMF parser rightly refuses, which would read as a bug
// in the code under test.
function crm(certReqId, cn) {
  var spki = b.sequence([b.sequence([b.oid("1.2.840.10045.2.1"), b.oid("1.2.840.10045.3.1.7")]),
    b.bitString(Buffer.from([4, 1, 2]), 0)]);
  var certTemplate = pki.crmf.buildCertTemplate({ subject: cn, publicKey: spki });
  var certReq = b.sequence([b.integer(BigInt(certReqId)), certTemplate]);
  return b.contextConstructed(1, certReq);
}

// TaggedContentInfo ::= SEQUENCE { bodyPartID, contentInfo } -- RFC 5272 sec.
// 3.2.1.3. The inner ContentInfo is an id-data wrapper here; this decoder does
// not interpret it, but the bodyPartID is still a body part identity.
function taggedContentInfo(bodyPartID) {
  var contentInfo = b.sequence([b.oid(ID_DATA), b.explicit(0, b.octetString(Buffer.from([1, 2, 3])))]);
  return b.sequence([b.integer(BigInt(bodyPartID)), contentInfo]);
}

// OtherMsg ::= SEQUENCE { bodyPartID, otherMsgType, otherMsgValue } -- sec. 3.2.1.4.
function otherMsg(bodyPartID) {
  return b.sequence([b.integer(BigInt(bodyPartID)), b.oid("1.3.6.1.4.1.99999.3"),
    b.octetString(Buffer.from([9]))]);
}

// CMCStatusInfoV2 ::= SEQUENCE { cMCStatus, bodyList SEQUENCE SIZE(1..MAX) OF
//   BodyPartReference, statusString UTF8String OPTIONAL, otherInfo OPTIONAL }
function statusInfoV2(bodyPartID, status, bodyList, otherInfo, statusString) {
  var fields = [b.integer(BigInt(status)), b.sequence(bodyList)];
  if (statusString != null) fields.push(b.utf8(statusString));
  if (otherInfo != null) fields.push(otherInfo);
  return taggedAttr(bodyPartID, ID_CMC_STATUS_INFO_V2, [b.sequence(fields)]);
}

async function run() {
  var cmc = pki.schema.cmc;

  // =====================================================================
  // A. PKIData / PKIResponse structure
  // =====================================================================

  // A1 -- all four sequences present and EMPTY is the minimal legal PKIData.
  var a1 = cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [], [], [])));
  check("A1. an all-empty PKIData parses as kind pkiData (PD2: mandatory-though-empty)",
    a1.kind === "pkiData" && a1.controls.length === 0 && a1.requests.length === 0 &&
    a1.cmsSequence.length === 0 && a1.otherMsgs.length === 0);

  // A2 -- PKIResponse has THREE sequences (no reqSequence).
  var a2 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([], [], [])));
  check("A2. an all-empty PKIResponse parses as kind pkiResponse (PR6: three fields)",
    a2.kind === "pkiResponse" && a2.controls.length === 0 &&
    a2.cmsSequence.length === 0 && a2.otherMsgs.length === 0);

  // A4 -- id-data is a CMS message, not a CMC one.
  check("A4. an id-data eContentType is refused as not-CMC",
    code(function () { return cmc.parse(signedData(ID_DATA, b.sequence([]))); }) === "cmc/not-cmc");

  // A4b -- the CARRIER matters, not just the encapsulated content type. RFC 5272
  // sec. 3.2 / 4.2 admit a SignedData or an AuthenticatedData; another CMS type
  // that happens to expose an encapContentInfo (CompressedData does) is not a
  // Full PKI message, and accepting it because the inner OID matches would let an
  // unsigned, unauthenticated wrapper deliver a "request".
  var compressed = b.sequence([b.oid("1.2.840.113549.1.9.16.1.9"), b.explicit(0, b.sequence([
    b.integer(0n),
    b.sequence([b.oid("1.2.840.113549.1.9.16.3.8")]),
    b.sequence([b.oid(ID_CCT_PKI_DATA), b.explicit(0, b.octetString(pkiData([], [], [], [])))]),
  ]))]);
  check("A4b. a CompressedData carrying id-cct-PKIData is refused (the carrier must be SignedData / AuthenticatedData)",
    code(function () { return cmc.parse(compressed); }) === "cmc/not-cmc");

  // A5 -- a PKIData missing otherMsgSequence: the field is mandatory though it
  // may be empty, so three children is malformed rather than "absent optional".
  var a5 = b.sequence([b.sequence([]), b.sequence([]), b.sequence([])]);
  check("A5. a PKIData with only three children is refused (PD2)",
    code(function () { return cmc.parse(signedData(ID_CCT_PKI_DATA, a5)); }) === "cmc/bad-pkidata");

  // A6 -- a PKIResponse must NOT carry a reqSequence.
  var a6 = b.sequence([b.sequence([]), b.sequence([]), b.sequence([]), b.sequence([])]);
  check("A6. a PKIResponse with four children is refused (PR6)",
    code(function () { return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, a6)); }) === "cmc/bad-pkiresponse");

  // A7 -- a detached SignedData carries no content to interpret.
  check("A7. a detached SignedData (no eContent) is refused",
    code(function () { return cmc.parse(signedData(ID_CCT_PKI_DATA, null)); }) === "cmc/no-content");

  // A8 -- the reqSequence byte range is surfaced RAW, tag and length included,
  // because the Identity Proof V2 witness is computed over exactly those bytes
  // "encoded exactly as it appears in the Full PKI Request including the
  // sequence type and length" (RFC 5272 sec. 6.2.1). Assert against a hand
  // slice of the input, never against a re-encode -- a re-encode would agree
  // with a re-serializing implementation and hide the bug the rule exists for.
  var reqDer = tcr(1, csr(dn("a8.example")));
  var innerA8 = pkiData([], [reqDer], [], []);
  var a8 = cmc.parse(signedData(ID_CCT_PKI_DATA, innerA8));
  var wantReqSeq = b.sequence([reqDer]);
  check("A8. reqSequenceBytes is the raw TLV, tag+length included (IP1)",
    Buffer.isBuffer(a8.reqSequenceBytes) && Buffer.compare(a8.reqSequenceBytes, wantReqSeq) === 0);
  check("A8b. reqSequenceBytes is a slice of the encapsulated content, not a re-encode",
    innerA8.includes(a8.reqSequenceBytes));

  // A9 -- trailing bytes after the PKIData SEQUENCE.
  check("A9. trailing bytes after the PKIData are refused by the DER codec",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, Buffer.concat([pkiData([], [], [], []), Buffer.from([0])])));
    }) === "asn1/trailing-bytes");

  // =====================================================================
  // B. Body part identity -- PD8 / PD9
  // =====================================================================

  check("B1. two TaggedAttributes sharing a bodyPartID are refused",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [taggedAttr(7, ID_CMC_IDENTIFICATION, [b.utf8("a")]),
         taggedAttr(7, ID_CMC_TRANSACTION_ID, [b.integer(1n)])], [], [], [])));
    }) === "cmc/duplicate-body-part-id");

  // B2 -- uniqueness spans the WHOLE PKIData, not one sequence. A decoder that
  // checked each sequence independently would accept this.
  check("B2. a TaggedAttribute and a TaggedRequest sharing a bodyPartID are refused (whole-message uniqueness)",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [taggedAttr(4, ID_CMC_IDENTIFICATION, [b.utf8("a")])],
        [tcr(4, csr(dn("b2.example")))], [], [])));
    }) === "cmc/duplicate-body-part-id");

  // B2b/B2c -- RFC 5272 sec. 3.2.2 says "Each element of a PKIData or PKIResponse
  // has an associated body part identifier" and it "MUST be unique within a
  // single PKIData or PKIResponse". FOUR element kinds carry one: TaggedAttribute
  // (controls), TaggedRequest (tcr bodyPartID / crm certReqId / orm bodyPartID),
  // TaggedContentInfo (cmsSequence, sec. 3.2.1.3) and OtherMsg (otherMsgSequence,
  // sec. 3.2.1.4). Checking only some of them is the whole bug -- these two pin
  // the sequences a structure-only reader is most likely to pass over as opaque.
  check("B2b. a TaggedContentInfo colliding with a control is refused (cmsSequence carries identities too)",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [taggedAttr(9, ID_CMC_IDENTIFICATION, [b.utf8("a")])], [],
        [taggedContentInfo(9)], [])));
    }) === "cmc/duplicate-body-part-id");

  check("B2c. an OtherMsg colliding with a TaggedContentInfo is refused",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [], [], [taggedContentInfo(12)], [otherMsg(12)])));
    }) === "cmc/duplicate-body-part-id");

  check("B2d. distinct identities across all four element kinds parse",
    cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
      [taggedAttr(1, ID_CMC_IDENTIFICATION, [b.utf8("a")])],
      [tcr(2, csr(dn("b2d.example")))],
      [taggedContentInfo(3)], [otherMsg(4)]))).cmsSequence.length === 1);

  check("B3. a bodyPartID above 4294967295 is refused",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [taggedAttr(4294967296, ID_CMC_IDENTIFICATION, [b.utf8("a")])], [], [], [])));
    }) === "cmc/bad-body-part-id");

  check("B4. a negative bodyPartID is refused",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [b.sequence([b.integer(-1n), b.oid(ID_CMC_IDENTIFICATION), b.set([b.utf8("a")])])], [], [], [])));
    }) === "cmc/bad-body-part-id");

  // B5 -- 0 is reserved for "the current PKIData"; it is a legal REFERENCE but
  // never an element's own identity.
  check("B5. bodyPartID 0 as an element identity is refused (reserved)",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [taggedAttr(0, ID_CMC_IDENTIFICATION, [b.utf8("a")])], [], [], [])));
    }) === "cmc/reserved-body-part-id");
  var b5 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse(
    [statusInfoV2(1, 0, [b.sequence([b.integer(0n)])])], [], [])));
  check("B5b. bodyPartID 0 INSIDE a BodyPartPath is accepted (a reference to the current PKIData)",
    b5.controls.length === 1);

  // B6 / B7 -- SIZE(1..MAX) on both BodyPartPath and bodyList.
  check("B6. an empty BodyPartPath is refused (SIZE(1..MAX))",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse(
        [statusInfoV2(1, 0, [b.sequence([])])], [], [])));
    }) === "cmc/bad-body-part-path");

  check("B7. an empty bodyList in CMCStatusInfoV2 is refused (SIZE(1..MAX))",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse(
        [statusInfoV2(1, 0, [])], [], [])));
    }) === "cmc/bad-status-info");

  // =====================================================================
  // C. TaggedRequest arms -- PD10 / PD11
  // =====================================================================

  var c1 = cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [tcr(1, csr(dn("c1.example")))], [], [])));
  check("C1. the tcr [0] arm decodes and the inner CSR round-trips through pki.schema.csr",
    c1.requests[0].arm === "tcr" && c1.requests[0].bodyPartID === 1 &&
    pki.schema.csr.parse(c1.requests[0].certificationRequestBytes).subject.dn === "CN=c1.example");

  // C3 -- an `orm` arm with an unrecognized message type is surfaced RAW, never
  // a fault: PD7's rule is that a consumer does not hard-fail on what it does
  // not recognize.
  var ormDer = b.contextConstructed(2, Buffer.concat([
    b.integer(9n), b.oid("1.3.6.1.4.1.99999.7"), b.octetString(Buffer.from([1, 2, 3]))]));
  var c3 = cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [ormDer], [], [])));
  check("C3. an orm [2] arm with an unknown type OID is surfaced raw rather than refused",
    c3.requests[0].arm === "orm" && c3.requests[0].requestMessageType === "1.3.6.1.4.1.99999.7" &&
    Buffer.isBuffer(c3.requests[0].requestMessageValueBytes));

  // C2 -- the crm [1] arm. RFC 5272 sec. 3.2.2 is explicit that the body part
  // identifier for a CertReqMsg is its certReqId, NOT a separate field: "Body
  // part identifiers are encoded in the certReqIds field for CertReqMsg objects
  // (in a TaggedRequest) or in the bodyPartID field of the other objects." So the
  // crm arm carries an identity, and it is bound by the same whole-message
  // uniqueness rule as every other body part.
  var c2 = cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [crm(11, "c2.example")], [], [])));
  check("C2. the crm [1] arm decodes and its certReqId is the body part identity (RFC 5272 sec. 3.2.2)",
    c2.requests[0].arm === "crm" && c2.requests[0].bodyPartID === 11);
  check("C2b. the crm arm's certReqMsgBytes is a universal SEQUENCE the CRMF parser can consume",
    pki.schema.crmf.parse(b.sequence([c2.requests[0].certReqMsgBytes]))
      .messages[0].certReq.certTemplate.subject.dn === "CN=c2.example");

  check("C2c. a crm arm colliding with a control's bodyPartID is refused (the rule binds every arm)",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [taggedAttr(11, ID_CMC_IDENTIFICATION, [b.utf8("a")])], [crm(11, "c2c.example")], [], [])));
    }) === "cmc/duplicate-body-part-id");

  check("C2d. two crm arms sharing a certReqId are refused",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [], [crm(5, "one.example"), crm(5, "two.example")], [], [])));
    }) === "cmc/duplicate-body-part-id");

  check("C2e. an empty crm [1] arm is refused rather than accepted as a request with no identity",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [b.contextConstructed(1, Buffer.alloc(0))], [], [])));
    }) === "cmc/bad-tagged-request");

  check("C4. an unknown TaggedRequest tag [3] is refused",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [b.contextConstructed(3, b.integer(1n))], [], [])));
    }) === "cmc/bad-tagged-request");

  // C5 -- the CMC module is IMPLICIT TAGS, so an EXPLICIT-encoded tcr (a [0]
  // wrapping a SEQUENCE wrapping the pair) is a different, invalid encoding.
  check("C5. an EXPLICIT-encoded tcr arm is refused (the module is IMPLICIT TAGS)",
    code(function () {
      var inner = b.sequence([b.integer(1n), csr(dn("c5.example"))]);
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [b.contextConstructed(0, inner)], [], [])));
    }) === "cmc/bad-tagged-request");

  // C6 -- "the subject field in a CertificationRequest MAY be NULL, but MUST be
  // present". Erratum 8027 (Verified) reads NULL as a zero-length RDNSequence,
  // NOT an ASN.1 NULL -- so an empty SEQUENCE is legal here.
  var c6 = cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [tcr(1, csr(b.sequence([])))], [], [])));
  check("C6. a tcr whose CSR subject is a zero-length RDNSequence parses (PD11 + erratum 8027)",
    c6.requests[0].arm === "tcr");

  // =====================================================================
  // D. Status controls -- the ST3 ambiguity set
  // =====================================================================

  // D1 -- ABSENCE of a status control means success. A parser that required one
  // would be wrong (ST5), and this is the vector most easily left out.
  var d1 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([], [], [])));
  check("D1. a PKIResponse with NO status control at all parses (ST5: success is assumed)",
    d1.kind === "pkiResponse" && d1.statuses.length === 0);

  // D2 -- multiple status controls are a LIST of verdicts, in order (ST1).
  var d2 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
    statusInfoV2(1, 0, [b.sequence([b.integer(1n)])]),
    statusInfoV2(2, 3, [b.sequence([b.integer(2n)])],
      b.sequence([b.octetString(Buffer.from("tok")), b.generalizedTime(new Date("2026-03-01T00:00:00Z"))])),
  ], [], [])));
  check("D2. two statusInfoV2 controls are both surfaced, in order (ST1)",
    d2.statuses.length === 2 && d2.statuses[0].status === "success" && d2.statuses[1].status === "pending");

  // D3 -- otherInfo as a universal INTEGER is failInfo.
  var d3 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
    statusInfoV2(1, 2, [b.sequence([b.integer(1n)])], b.integer(9n))], [], [])));
  check("D3. otherInfo INTEGER 9 with status failed decodes as failInfo popFailed",
    d3.statuses[0].failInfo === 9 && d3.statuses[0].failInfoName === "popFailed");

  // D4 / D5 -- the 1988-module collision: BOTH pendInfo and extendedFailInfo are
  // untagged SEQUENCEs. Disambiguate on the FIRST CHILD's tag.
  var d4 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
    statusInfoV2(1, 3, [b.sequence([b.integer(1n)])],
      b.sequence([b.octetString(Buffer.from("tok")), b.generalizedTime(new Date("2026-03-01T00:00:00Z"))]))], [], [])));
  check("D4. an untagged SEQUENCE whose first child is an OCTET STRING is pendInfo (ST3, 1988 module)",
    d4.statuses[0].pendInfo !== null && d4.statuses[0].pendInfo.pendToken.toString() === "tok" &&
    d4.statuses[0].pendInfo.pendTime.toISOString() === "2026-03-01T00:00:00.000Z");

  var d5 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
    statusInfoV2(1, 2, [b.sequence([b.integer(1n)])],
      b.sequence([b.oid("1.3.6.1.4.1.99999.9"), b.octetString(Buffer.from([1]))]))], [], [])));
  check("D5. an untagged SEQUENCE whose first child is an OID is extendedFailInfo (ST3, 1988 module)",
    d5.statuses[0].extendedFailInfo !== null &&
    d5.statuses[0].extendedFailInfo.failInfoOID === "1.3.6.1.4.1.99999.9");

  // D5b / D5c -- the extendedFailInfo arm belongs to CMCStatusInfoV2 alone. RFC
  // 5272 sec. 6.1.1 gives the v1 otherInfo exactly two arms, failInfo and
  // pendInfo, so a v1 control carrying the extended shape in either encoding is
  // expressing something v1 cannot say -- and reading a failure verdict out of it
  // would treat a malformed control as a valid rejection.
  function statusInfoV1(bodyPartID, status, bodyList, otherInfo) {
    var fields = [b.integer(BigInt(status)), b.sequence(bodyList)];
    if (otherInfo != null) fields.push(otherInfo);
    return taggedAttr(bodyPartID, ID_CMC_STATUS_INFO, [b.sequence(fields)]);
  }

  check("D5b. a v1 status control cannot carry the untagged extendedFailInfo shape",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
        statusInfoV1(1, 2, [b.integer(1n)],
          b.sequence([b.oid("1.3.6.1.4.1.99999.9"), b.octetString(Buffer.from([1]))]))], [], [])));
    }) === "cmc/bad-status-info");

  check("D5c. nor the [1] IMPLICIT one",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
        statusInfoV1(1, 2, [b.integer(1n)],
          b.contextConstructed(1, Buffer.concat([b.oid("1.3.6.1.4.1.99999.9"), b.octetString(Buffer.from([1]))])))], [], [])));
    }) === "cmc/bad-status-info");

  check("D5d. the two arms v1 DOES define still work",
    // The rejection above must be about the extended arm, not about v1 controls.
    cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
      statusInfoV1(1, 2, [b.integer(1n)], b.integer(9n))], [], []))).statuses[0].failInfo === 9);

  // C9 -- a TaggedContentInfo's payload is surfaced RAW, but it must still BE a
  // ContentInfo. Not decoding a content type this layer may not know is one
  // thing; handing back an INTEGER as a "CMS message" no CMS reader will accept
  // is another.
  check("C9. a cmsSequence element whose payload cannot be a ContentInfo is refused",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [],
        [b.sequence([b.integer(1n), b.integer(9n)])], [])));
    }) === "cmc/bad-cms-sequence");

  check("C9b. nor one whose content field is not the [0] EXPLICIT content",
    // The leading OID alone is not enough: `SEQUENCE { OID, INTEGER }` would be
    // surfaced as a content info that no CMS reader accepts.
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [],
        [b.sequence([b.integer(1n), b.sequence([b.oid("1.2.840.113549.1.7.1"), b.integer(9n)])])], [])));
    }) === "cmc/bad-cms-sequence");

  check("C9c. a bare contentType with no content is accepted (the field is OPTIONAL)",
    cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData([], [],
      [b.sequence([b.integer(1n), b.sequence([b.oid("1.2.840.113549.1.7.1")])])], []))).cmsSequence.length === 1);

  // D6 -- the 2008 module tags the same arm [1]. Both encodings appear on the
  // wire; supporting only one is the partial-rule trap.
  var d6 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
    statusInfoV2(1, 2, [b.sequence([b.integer(1n)])],
      b.contextConstructed(1, Buffer.concat([b.oid("1.3.6.1.4.1.99999.9"), b.octetString(Buffer.from([1]))])))], [], [])));
  check("D6. a [1] IMPLICIT SEQUENCE is extendedFailInfo (ST3, RFC 6402 2008 module)",
    d6.statuses[0].extendedFailInfo !== null &&
    d6.statuses[0].extendedFailInfo.failInfoOID === "1.3.6.1.4.1.99999.9");

  // D7 -- anything the two rules cannot tell apart is REFUSED, never guessed.
  check("D7. an untagged SEQUENCE whose first child is a BOOLEAN is refused as ambiguous",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
        statusInfoV2(1, 2, [b.sequence([b.integer(1n)])],
          b.sequence([b.boolean(true), b.octetString(Buffer.from([1]))]))], [], [])));
    }) === "cmc/ambiguous-status-info");

  // D8 / D9 -- the cross-field coupling (ST4).
  check("D8. status failed carrying a pendInfo is refused (ST4)",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
        statusInfoV2(1, 2, [b.sequence([b.integer(1n)])],
          b.sequence([b.octetString(Buffer.from("tok")), b.generalizedTime(new Date("2026-03-01T00:00:00Z"))]))], [], [])));
    }) === "cmc/status-info-mismatch");

  check("D9. status pending with otherInfo ABSENT is refused (ST4: pendInfo MUST be populated)",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
        statusInfoV2(1, 3, [b.sequence([b.integer(1n)])])], [], [])));
    }) === "cmc/status-info-mismatch");

  // D7b -- ASN.1 SEQUENCE ordering: the OPTIONAL statusString precedes the
  // OPTIONAL otherInfo. A decoder that just looks for "the first UTF8String"
  // and "the other one" accepts them reversed, which is a different encoding of
  // a structure DER admits exactly one encoding of.
  check("D7b. a statusString placed AFTER otherInfo is refused (SEQUENCE field order)",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
        taggedAttr(1, ID_CMC_STATUS_INFO_V2, [b.sequence([
          b.integer(2n), b.sequence([b.integer(1n)]), b.integer(9n), b.utf8("late")])])], [], [])));
    }) === "cmc/bad-status-info");

  // D10 / D11 -- 1 is RESERVED and 8 is unassigned; an unknown status is not a
  // verdict in either direction.
  check("D10. cMCStatus 1 (reserved) is refused",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
        statusInfoV2(1, 1, [b.sequence([b.integer(1n)])])], [], [])));
    }) === "cmc/bad-status");
  check("D11. cMCStatus 8 (unassigned) is refused",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
        statusInfoV2(1, 8, [b.sequence([b.integer(1n)])])], [], [])));
    }) === "cmc/bad-status");

  // D12 -- 1000..1999 is a legal private failInfo range (ST7): surfaced
  // numerically with no name, never refused.
  var d12 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
    statusInfoV2(1, 2, [b.sequence([b.integer(1n)])], b.integer(1500n))], [], [])));
  check("D12. failInfo 1500 (the private range) is surfaced numerically with a null name (ST7)",
    d12.statuses[0].failInfo === 1500 && d12.statuses[0].failInfoName === null);

  // D13 -- an unrecognized extended failInfoOID is surfaced raw; internalCAError
  // is a MAY, and synthesizing it would invent a reason the server never sent.
  check("D13. an unrecognized failInfoOID is not synthesized into a failInfo (ST8)",
    d5.statuses[0].failInfo === null && d5.statuses[0].failInfoName === null);

  // D14 -- a v1 statusInfo alongside the V2 control: both are surfaced (ST1).
  var d14 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse([
    taggedAttr(1, ID_CMC_STATUS_INFO, [b.sequence([b.integer(0n), b.sequence([b.integer(1n)])])]),
    statusInfoV2(2, 0, [b.sequence([b.integer(1n)])]),
  ], [], [])));
  check("D14. a v1 statusInfo and a V2 control are both surfaced (ST1)",
    d14.statuses.length === 2 && d14.statuses[0].version === 1 && d14.statuses[1].version === 2);

  // =====================================================================
  // E (parse half). Control placement -- RFC 6402 sec. 2.5 / 2.6
  // =====================================================================

  check("E8. id-cmc-responseBody in a PKIData is refused (RFC 6402 sec. 2.6)",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_DATA, pkiData(
        [taggedAttr(1, ID_CMC_RESPONSE_BODY, [b.octetString(Buffer.from([1]))])], [], [], [])));
    }) === "cmc/control-misplaced");

  check("E9. id-cmc-raIdentityWitness in a PKIResponse is refused (RFC 6402 sec. 2.5)",
    code(function () {
      return cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse(
        [taggedAttr(1, ID_CMC_RA_IDENTITY_WITNESS, [b.octetString(Buffer.from([1]))])], [], [])));
    }) === "cmc/control-misplaced");

  // =====================================================================
  // The bare-body entry points, driven by their own full paths. A caller who
  // already holds the encapsulated content (an eContentType dispatch of their
  // own) decodes it without re-wrapping it in a CMS envelope.
  // =====================================================================

  var bare = pki.schema.cmc.parsePkiData(pkiData([taggedAttr(1, ID_CMC_TRANSACTION_ID, [b.integer(42n)])], [], [], []));
  check("F1. pki.schema.cmc.parsePkiData decodes a bare PKIData body",
    bare.kind === "pkiData" && bare.controls[0].attrName === "id-cmc-transactionId" &&
    Buffer.compare(bare.reqSequenceBytes, b.sequence([])) === 0);

  var bareResp = pki.schema.cmc.parsePkiResponse(pkiResponse([statusInfoV2(1, 0, [b.sequence([b.integer(1n)])])], [], []));
  check("F2. pki.schema.cmc.parsePkiResponse decodes a bare PKIResponse body",
    bareResp.kind === "pkiResponse" && bareResp.statuses[0].status === "success" &&
    bareResp.reqSequenceBytes === null);

  // The four-vs-three arity is what distinguishes the two bodies, so each entry
  // point must refuse the OTHER body rather than decode it by position.
  check("F3. parsePkiData refuses a PKIResponse body (four fields vs three)",
    code(function () { return pki.schema.cmc.parsePkiData(pkiResponse([], [], [])); }) === "cmc/bad-pkidata");
  check("F4. parsePkiResponse refuses a PKIData body",
    code(function () { return pki.schema.cmc.parsePkiResponse(pkiData([], [], [], [])); }) === "cmc/bad-pkiresponse");

  // E10 -- an entirely unknown control OID is surfaced, never a fault (PD7).
  var e10 = cmc.parse(signedData(ID_CCT_PKI_RESPONSE, pkiResponse(
    [taggedAttr(1, "1.3.6.1.4.1.99999.42", [b.octetString(Buffer.from([1]))])], [], [])));
  check("E10. an unknown control OID is surfaced on unhandled rather than refused (PD7)",
    e10.unhandled.length === 1 && e10.unhandled[0].attrType === "1.3.6.1.4.1.99999.42" &&
    Buffer.isBuffer(e10.unhandled[0].values[0]));

  // F5 -- the input dispatch decides "already-parsed CMS" vs "bytes to parse".
  // A typed array IS bytes, and deciding on `typeof x === "object"` alone puts it
  // on the parsed-object branch, where it has no content type and gets refused as
  // not-CMC. Every byte form the codec accepts must reach the same verdict.
  var f5der = signedData(ID_CCT_PKI_DATA, pkiData([], [], [], []));
  check("F5. DER supplied as a Uint8Array parses identically to the same bytes as a Buffer",
    cmc.parse(new Uint8Array(f5der)).kind === cmc.parse(f5der).kind);

  check("F5b. a genuinely already-parsed CMS structure still routes to the parsed branch",
    cmc.parse(pki.schema.cms.parse(f5der)).kind === "pkiData");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error((e && e.stack) || e); process.exit(1); });
}
