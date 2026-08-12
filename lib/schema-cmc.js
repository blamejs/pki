// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.cmc
 * @nav        Schema
 * @title      CMC
 * @order      185
 * @slug       cmc
 *
 * @intro
 *   RFC 5272 CMC message-layer decoding, as updated by RFC 6402. A Full PKI
 *   Request (`PKIData`) and a Full PKI Response (`PKIResponse`) both ride inside
 *   a CMS SignedData (or AuthenticatedData) as the encapsulated content, named by
 *   the eContentType `id-cct-PKIData` / `id-cct-PKIResponse` -- so `parse` peels
 *   the CMS layer, dispatches on that content type, and decodes the message.
 *
 *   Every body part carries a `BodyPartID`, and the identifier MUST be unique
 *   across the WHOLE message rather than within one sequence; 0 is reserved as
 *   the reference to the enclosing PKIData and is never an element's own
 *   identity. Controls are surfaced as an ordered list with their values RAW: an
 *   unrecognized control is DATA, not a fault, because the rule that a server
 *   fails an unrecognized control binds the server, not the client reading a
 *   response. The status controls (`CMCStatusInfo` v1 and `CMCStatusInfoV2`) are
 *   collected in wire order -- a response may carry several verdicts, and the
 *   ABSENCE of one means success.
 *
 *   The `reqSequence` byte range is surfaced exactly as it appeared on the wire,
 *   tag and length included, because the Identity Proof V2 witness is computed
 *   over those bytes and a re-serialization would silently differ.
 *
 * @spec RFC 5272, RFC 5273, RFC 5274, RFC 6402
 * @card
 *   Decode RFC 5272 CMC Full PKI Requests and Responses inside CMS -- controls
 *   with raw values, tagged requests (PKCS#10 / CRMF / other), ordered status
 *   verdicts with the RFC 6402 two-module OtherStatusInfo ambiguity resolved,
 *   whole-message body-part identity, raw reqSequence bytes, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var cms = require("./schema-cms");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");

var CmcError = frameworkError.CmcError;

var NS = pkix.makeNS("cmc", CmcError, oid);
var TAGS = asn1.TAGS;

function E(code, message, cause) { return new CmcError(code, message, cause); }
function O(name) { return oid.byName(name); }

// Registry constants -- never a dotted literal in a format module.
var OID_PKI_DATA = O("id-cct-PKIData");
var OID_PKI_RESPONSE = O("id-cct-PKIResponse");
var OID_STATUS_INFO = O("id-cmc-statusInfo");
var OID_STATUS_INFO_V2 = O("id-cmc-statusInfoV2");
var OID_RESPONSE_BODY = O("id-cmc-responseBody");
var OID_RA_IDENTITY_WITNESS = O("id-cmc-raIdentityWitness");

// BodyPartID ::= INTEGER (0..4294967295) -- RFC 5272 sec. 3.2.2.
var BODY_PART_MAX = 4294967295n;

// CMCStatus ::= INTEGER { success(0), failed(2), pending(3), noSupport(4),
// confirmRequired(5), popRequired(6), partial(7) } -- RFC 5272 sec. 6.1.3.
// 1 is RESERVED: it is neither a success nor a failure, so it is refused rather
// than folded into either.
var STATUS_BY_VALUE = {
  0: "success", 2: "failed", 3: "pending", 4: "noSupport",
  5: "confirmRequired", 6: "popRequired", 7: "partial",
};

// CMCFailInfo ::= INTEGER { ... } -- RFC 5272 sec. 6.1.4. Values outside this set
// are surfaced numerically rather than refused: sec. 6.1.4 reserves 1000..1999
// for private extended reasons, so an unknown number is legal data.
var FAIL_INFO_BY_VALUE = {
  0: "badAlg", 1: "badMessageCheck", 2: "badRequest", 3: "badTime", 4: "badCertId",
  5: "unsupportedExt", 6: "mustArchiveKeys", 7: "badIdentity", 8: "popRequired",
  9: "popFailed", 10: "noKeyReuse", 11: "internalCAError", 12: "tryLater",
  13: "authDataFail",
};

// The CMS content types a Full PKI Request / Response may ride in -- RFC 5272
// sec. 3.2 ("encapsulated in either a SignedData or an AuthenticatedData") and
// sec. 4.2, which says the same of the response.
// The names are the OID REGISTRY's, read off `oid.name(...)` rather than the
// spec's prose: RFC 5652 calls the type AuthenticatedData, the registry row is
// `authData`, and hard-coding the prose spelling would reject every conforming
// AuthenticatedData response while looking correct.
var CMC_CARRIERS = { signedData: 1, authData: 1 };

// Control PLACEMENT -- RFC 6402 sec. 2.5 / 2.6 give two MUSTs about where a
// control may appear. An OID-keyed table states them once, in the shape of the
// shipped CMS attribute-placement registry, so a new placement rule is a row.
var CONTROL_PLACEMENT = {};
CONTROL_PLACEMENT[OID_RESPONSE_BODY] = "pkiResponse";      // sec. 2.6: never in a PKIData
CONTROL_PLACEMENT[OID_RA_IDENTITY_WITNESS] = "pkiData";    // sec. 2.5: never in a PKIResponse

// ---- leaves ----------------------------------------------------------

// A BodyPartID read + bounded + narrowed atomically. `guard.range.int` takes
// BigInt bounds and returns a Number only when the value is inside them, so an
// out-of-range identifier can never reach the caller as a silently-truncated int.
function readBodyPartId(node, label) {
  var v = asn1.read.integer(node);
  return guard.range.int(v, 0n, BODY_PART_MAX, E, "cmc/bad-body-part-id", label || "a BodyPartID");
}

// The identity of an element, where 0 is reserved (RFC 5272 sec. 3.2.2: "The
// bodyPartID value of 0 is reserved for use as the reference to the current
// PKIData object"). A REFERENCE may be 0; an identity may not.
function readBodyPartIdentity(node) {
  var id = readBodyPartId(node, "a body part identity");
  if (id === 0) {
    throw E("cmc/reserved-body-part-id",
      "bodyPartID 0 is reserved as the reference to the current PKIData and cannot identify a body part (RFC 5272 sec. 3.2.2)");
  }
  return id;
}

// ---- controls --------------------------------------------------------

// TaggedAttribute ::= SEQUENCE { bodyPartID BodyPartID, attrType OBJECT
// IDENTIFIER, attrValues SET OF AttributeValue } -- RFC 5272 sec. 3.2.1.1.
// attrValues are surfaced RAW: this decoder does not know every control, and
// PD7's "fail on an unrecognized control" binds the SERVER, not a client reading
// a response, so an unknown value is data to hand on rather than a fault.
//
// The placement rule is NOT checked here: it depends on which message the control
// sits in, which the enclosing walk knows and this shape does not.
var TAGGED_ATTRIBUTE = schema.seq([
  schema.field("bodyPartID", schema.decode(readBodyPartIdentity)),
  schema.field("attrType", schema.oidLeaf()),
  schema.field("attrValues", schema.setOf(schema.any(),
    { code: "cmc/bad-control", what: "TaggedAttribute attrValues", build: rawList })),
], {
  assert: "sequence", arity: { exact: 3 }, code: "cmc/bad-control", what: "a TaggedAttribute",
  build: function (m) {
    var attrType = m.fields.attrType.value;
    return {
      bodyPartID: m.fields.bodyPartID.value,
      attrType: attrType,
      attrName: oid.name(attrType) || null,
      values: m.fields.attrValues.value.result,
    };
  },
});

// RFC 6402 sec. 2.5 / 2.6 give two MUSTs about WHERE a control may appear, and
// both are one-directional. Applied against the enclosing message kind.
function assertControlPlacement(control, where) {
  var placement = CONTROL_PLACEMENT[control.attrType];
  if (placement && placement !== where) {
    throw E("cmc/control-misplaced",
      "the control " + (control.attrName || control.attrType) + " may appear only in the control sequence of a " +
      placement + " (RFC 6402 sec. 2.5 / 2.6)");
  }
}

// ---- status controls -------------------------------------------------

// BodyPartReference ::= CHOICE { bodyPartID BodyPartID, bodyPartPath BodyPartPath }
// -- an INTEGER and a SEQUENCE, so the arms are tag-disjoint. BodyPartPath is
// SEQUENCE SIZE(1..MAX), so an empty one is malformed rather than "no path".
function parseBodyPartReference(node) {
  if (node.tagClass === "universal" && node.tagNumber === TAGS.INTEGER) {
    return { bodyPartID: readBodyPartId(node), bodyPartPath: null };
  }
  if (node.tagClass === "universal" && node.tagNumber === TAGS.SEQUENCE && node.constructed) {
    if (node.children.length < 1) {
      throw E("cmc/bad-body-part-path", "a BodyPartPath is SEQUENCE SIZE(1..MAX) and cannot be empty (RFC 5272 sec. 3.2.2)");
    }
    return { bodyPartID: null, bodyPartPath: node.children.map(function (c) { return readBodyPartId(c); }) };
  }
  throw E("cmc/bad-status-info", "a BodyPartReference must be a BodyPartID INTEGER or a BodyPartPath SEQUENCE");
}

/**
 * OtherStatusInfo ::= CHOICE { failInfo CMCFailInfo, pendInfo PendInfo,
 *                              extendedFailInfo SEQUENCE { ... } }
 *
 * The load-bearing ambiguity. RFC 5272 App A and RFC 6402 App A.1 (the 1988
 * module) leave `extendedFailInfo` UNTAGGED, so it collides with `pendInfo` --
 * both are a bare SEQUENCE. RFC 6402 App A.2 (the 2008 module) tags it `[1]`.
 * Both encodings occur on the wire, so both are decoded:
 *
 *   universal INTEGER   -> failInfo
 *   context [1]         -> extendedFailInfo (2008 module)
 *   universal SEQUENCE  -> disambiguate on the FIRST child's tag:
 *                            OCTET STRING -> pendInfo  (PendInfo ::= SEQUENCE
 *                              { pendToken OCTET STRING, pendTime GeneralizedTime })
 *                            OBJECT IDENTIFIER -> extendedFailInfo
 *   anything else       -> refuse
 *
 * The final arm is the point: a shape that matches neither rule is REFUSED, not
 * guessed at. Guessing here would attach a failure reason, or a pending token,
 * that the responder never sent.
 */
function parseOtherStatusInfo(node, version) {
  // The extendedFailInfo arm belongs to CMCStatusInfoV2 alone. RFC 5272 sec. 6.1.1
  // gives the v1 otherInfo exactly two arms -- `CHOICE { failInfo CMCFailInfo,
  // pendInfo PendInfo }` -- so accepting the third here would read a failure
  // verdict out of a v1 control that cannot legally express one, and the
  // disambiguation below would be answering a question v1 never asks.
  var extendedAllowed = version !== 1;
  if (node.tagClass === "universal" && node.tagNumber === TAGS.INTEGER) {
    var v = asn1.read.integer(node);
    var n = guard.range.int(v, 0n, 0xFFFFFFFFn, E, "cmc/bad-status-info", "a CMCFailInfo");
    return { failInfo: n, failInfoName: FAIL_INFO_BY_VALUE[n] || null, pendInfo: null, extendedFailInfo: null };
  }
  if (node.tagClass === "context" && node.tagNumber === 1) {
    if (!extendedAllowed) {
      throw E("cmc/bad-status-info",
        "a v1 CMCStatusInfo otherInfo is failInfo or pendInfo only; the [1] extendedFailInfo arm is CMCStatusInfoV2's (RFC 5272 sec. 6.1.1)");
    }
    // IMPLICIT, so the [1] REPLACES the SEQUENCE tag and its children are the
    // failInfoOID / failInfoValue directly -- there is no inner SEQUENCE to
    // unwrap. Both RFC 6402 modules are IMPLICIT: A.1 (rfc6402.txt:805) and A.2
    // (rfc6402.txt:1314) each open `DEFINITIONS IMPLICIT TAGS ::=`, and the
    // EXPLICIT-override rule does not apply here because the tagged type is a
    // plain SEQUENCE rather than a CHOICE or an open type. Reading this arm as
    // EXPLICIT would reject every conforming 2008-module response.
    return { failInfo: null, failInfoName: null, pendInfo: null, extendedFailInfo: readExtendedFailInfo(node.children, "[1] extendedFailInfo") };
  }
  if (node.tagClass === "universal" && node.tagNumber === TAGS.SEQUENCE && node.constructed) {
    var first = node.children[0];
    if (!first) throw E("cmc/ambiguous-status-info", "an empty OtherStatusInfo SEQUENCE matches neither pendInfo nor extendedFailInfo");
    if (first.tagClass === "universal" && first.tagNumber === TAGS.OCTET_STRING) {
      if (node.children.length !== 2) throw E("cmc/bad-status-info", "PendInfo must be { pendToken, pendTime }");
      // pendTime is a GeneralizedTime specifically, so assert the tag rather than
      // accept either time form -- a UTCTime here is a different encoding, and
      // reading it anyway would let a two-digit year through the retry clock.
      var timeNode = node.children[1];
      if (timeNode.tagClass !== "universal" || timeNode.tagNumber !== TAGS.GENERALIZED_TIME) {
        throw E("cmc/bad-status-info", "PendInfo pendTime must be a GeneralizedTime (RFC 5272 sec. 6.1.1)");
      }
      return {
        failInfo: null, failInfoName: null, extendedFailInfo: null,
        pendInfo: { pendToken: asn1.read.octetString(first), pendTime: asn1.read.time(timeNode) },
      };
    }
    if (first.tagClass === "universal" && first.tagNumber === TAGS.OBJECT_IDENTIFIER) {
      if (!extendedAllowed) {
        throw E("cmc/bad-status-info",
          "a v1 CMCStatusInfo otherInfo SEQUENCE is pendInfo; this one leads with an OBJECT IDENTIFIER, which is the extendedFailInfo shape CMCStatusInfoV2 introduced (RFC 5272 sec. 6.1.1)");
      }
      return { failInfo: null, failInfoName: null, pendInfo: null, extendedFailInfo: readExtendedFailInfo(node.children, "extendedFailInfo") };
    }
    throw E("cmc/ambiguous-status-info",
      "an untagged OtherStatusInfo SEQUENCE is pendInfo or extendedFailInfo depending on its first element, and this one is neither an OCTET STRING nor an OBJECT IDENTIFIER (RFC 5272 App A vs RFC 6402 App A.1/A.2)");
  }
  throw E("cmc/bad-status-info", "OtherStatusInfo must be a CMCFailInfo INTEGER, a PendInfo SEQUENCE, or an extendedFailInfo");
}

// ExtendedFailInfo ::= SEQUENCE { failInfoOID OBJECT IDENTIFIER, failInfoValue ANY }
// The OID is surfaced raw and NEVER mapped onto a CMCFailInfo: RFC 5272 sec.
// 6.1.1 makes internalCAError only a MAY for an unrecognized extended error, and
// synthesizing it would report a reason the responder did not send.
function readExtendedFailInfo(children, what) {
  if (!children || children.length !== 2) {
    throw E("cmc/bad-status-info", what + " must be SEQUENCE { failInfoOID, failInfoValue }");
  }
  return { failInfoOID: asn1.read.oid(children[0]), failInfoValueBytes: children[1].bytes };
}

// CMCStatusInfoV2 ::= SEQUENCE { cMCStatus, bodyList SEQUENCE SIZE(1..MAX) OF
//   BodyPartReference, statusString UTF8String OPTIONAL, otherInfo OPTIONAL }
// The v1 CMCStatusInfo is the same shape with a SEQUENCE OF BodyPartID bodyList
// and no extendedFailInfo arm; both are decoded into one surface so a caller
// reads one ordered list of verdicts (RFC 5272 sec. 6.1: a client MUST cope with
// several status controls).
function parseStatusInfo(valueDer, version, bodyPartID) {
  var root = asn1.decode(valueDer);
  if (root.tagClass !== "universal" || root.tagNumber !== TAGS.SEQUENCE || !root.constructed) {
    throw E("cmc/bad-status-info", "a CMCStatusInfo value must be a SEQUENCE");
  }
  var kids = root.children;
  if (kids.length < 2) throw E("cmc/bad-status-info", "a CMCStatusInfo needs at least cMCStatus and bodyList");

  var statusValue = asn1.read.integer(kids[0]);
  var statusNum = guard.range.int(statusValue, 0n, 0xFFFFFFFFn, E, "cmc/bad-status", "a CMCStatus");
  var statusName = STATUS_BY_VALUE[statusNum];
  if (!statusName) {
    // 1 is reserved and everything above 7 is unassigned. An unknown status is
    // not a verdict in either direction, so it is refused rather than mapped.
    throw E("cmc/bad-status", "unknown CMCStatus " + statusNum + " (1 is reserved; RFC 5272 sec. 6.1.3)");
  }

  var listNode = kids[1];
  if (listNode.tagClass !== "universal" || listNode.tagNumber !== TAGS.SEQUENCE || !listNode.constructed) {
    throw E("cmc/bad-status-info", "the CMCStatusInfo bodyList must be a SEQUENCE");
  }
  if (listNode.children.length < 1) {
    throw E("cmc/bad-status-info", "the CMCStatusInfo bodyList is SEQUENCE SIZE(1..MAX) and cannot be empty (RFC 5272 sec. 6.1.1)");
  }
  var bodyList = listNode.children.map(function (c) {
    return version === 2 ? parseBodyPartReference(c) : { bodyPartID: readBodyPartId(c), bodyPartPath: null };
  });

  // The two OPTIONAL tail fields are ORDERED by the ASN.1: statusString precedes
  // otherInfo. Tracking only "have I seen a statusString yet" would accept them
  // reversed -- a second encoding of a structure DER admits exactly one encoding
  // of -- so the walk refuses anything once otherInfo has been consumed.
  var statusString = null, other = null, sawOther = false;
  for (var i = 2; i < kids.length; i++) {
    var k = kids[i];
    if (k.tagClass === "universal" && k.tagNumber === TAGS.UTF8_STRING && statusString === null && !sawOther) {
      // read.string, not a per-type reader: the codec exposes one strict text reader
      // for the DirectoryString family and there is no `read.utf8`. The tag is
      // already asserted UTF8String above, so this decodes exactly that.
      statusString = asn1.read.string(k);
      continue;
    }
    if (sawOther) {
      throw E("cmc/bad-status-info",
        "a CMCStatusInfo carries at most one OtherStatusInfo, and the OPTIONAL statusString precedes it (RFC 5272 sec. 6.1.1)");
    }
    other = parseOtherStatusInfo(k, version);
    sawOther = true;
  }

  var out = {
    version: version, bodyPartID: bodyPartID, status: statusName, statusValue: statusNum,
    bodyList: bodyList, statusString: statusString,
    failInfo: other ? other.failInfo : null,
    failInfoName: other ? other.failInfoName : null,
    pendInfo: other ? other.pendInfo : null,
    extendedFailInfo: other ? other.extendedFailInfo : null,
  };
  _assertStatusCoherent(out);
  return out;
}

// The cross-field coupling (RFC 5272 sec. 6.1.1 / 6.1.2): failInfo and
// extendedFailInfo are "present only if cMCStatus contains the value failed",
// and pendInfo "MUST be populated for a cMCStatus value of pending or partial".
// A message whose status and detail disagree is refused rather than reconciled --
// the two halves would otherwise let a caller read a verdict neither field states.
function _assertStatusCoherent(s) {
  var isFailed = s.status === "failed";
  var isPending = s.status === "pending" || s.status === "partial";
  if ((s.failInfo !== null || s.extendedFailInfo !== null) && !isFailed) {
    throw E("cmc/status-info-mismatch",
      "a failInfo / extendedFailInfo is present only when cMCStatus is failed, got " + s.status + " (RFC 5272 sec. 6.1.1)");
  }
  if (s.pendInfo !== null && !isPending) {
    throw E("cmc/status-info-mismatch",
      "a pendInfo is present only when cMCStatus is pending or partial, got " + s.status + " (RFC 5272 sec. 6.1.1)");
  }
  if (isPending && s.pendInfo === null) {
    throw E("cmc/status-info-mismatch",
      "the pendInfo field MUST be populated for a cMCStatus of " + s.status + " (RFC 5272 sec. 6.1.2)");
  }
}

// ---- tagged requests -------------------------------------------------

// TaggedRequest ::= CHOICE { tcr [0] TaggedCertificationRequest,
//                           crm [1] CertReqMsg,
//                           orm [2] SEQUENCE { bodyPartID, requestMessageType,
//                                              requestMessageValue } }
// The CMC module is IMPLICIT TAGS, so each context tag REPLACES the arm's own
// universal tag -- the [0] node's direct children are the TaggedCertificationRequest
// fields, NOT a nested SEQUENCE. An EXPLICIT encoding is therefore a different
// (and invalid) message, which is what C5 pins.
// An IMPLICIT context-tagged constructed node re-encoded under the universal
// SEQUENCE tag it stands in for. IMPLICIT tagging REPLACES the tag and leaves the
// content untouched, so restoring it is exactly a re-headering of the same bytes.
function _asUniversalSequence(node) {
  var headerLen = node.header.end - node.header.start;
  return asn1.encode(0x00, true, TAGS.SEQUENCE, node.bytes.subarray(headerLen));
}

function parseTaggedRequest(node) {
  if (node.tagClass !== "context" || !node.constructed) {
    throw E("cmc/bad-tagged-request", "a TaggedRequest must be a context-tagged constructed CHOICE arm (RFC 5272 sec. 3.2.1.2)");
  }
  if (node.tagNumber === 0) {
    // TaggedCertificationRequest ::= SEQUENCE { bodyPartID, certificationRequest }
    if (node.children.length !== 2) {
      throw E("cmc/bad-tagged-request", "a tcr arm is [0] IMPLICIT { bodyPartID, certificationRequest }; the module is IMPLICIT TAGS, so an EXPLICIT wrapper is not this arm");
    }
    var csrNode = node.children[1];
    if (csrNode.tagClass !== "universal" || csrNode.tagNumber !== TAGS.SEQUENCE || !csrNode.constructed) {
      throw E("cmc/bad-tagged-request", "the tcr certificationRequest must be a CertificationRequest SEQUENCE");
    }
    return {
      arm: "tcr", bodyPartID: readBodyPartIdentity(node.children[0]),
      certificationRequestBytes: csrNode.bytes, certReqMsgBytes: null,
      requestMessageType: null, requestMessageValueBytes: null,
    };
  }
  if (node.tagNumber === 1) {
    // crm [1] IMPLICIT CertReqMsg.
    //
    // This arm still has a body part IDENTITY, and it is not a separate field:
    // RFC 5272 sec. 3.2.2 says "Body part identifiers are encoded in the
    // certReqIds field for CertReqMsg objects (in a TaggedRequest) or in the
    // bodyPartID field of the other objects", and sec. 6.5.2 repeats it
    // ("... either the bodyPartID of a TaggedCertificationRequest (PKCS #10) or
    // the certReqId of the CertRequest within a CertReqMsg (CRMF)"). So the
    // certReqId is read here and carried into the SAME whole-message uniqueness
    // check every other body part is bound by -- returning null would silently
    // exempt this arm from it.
    //
    //   CertReqMsg  ::= SEQUENCE { certReq CertRequest, popo OPTIONAL, regInfo OPTIONAL }
    //   CertRequest ::= SEQUENCE { certReqId INTEGER, certTemplate CertTemplate, ... }
    //
    // Only the identity is decoded here; the CertReqMsg's own conformance is
    // pki.schema.crmf's to enforce, and duplicating it would fork the rules.
    var certReq = node.children[0];
    if (!certReq || certReq.tagClass !== "universal" || certReq.tagNumber !== TAGS.SEQUENCE || !certReq.constructed) {
      throw E("cmc/bad-tagged-request", "a crm arm is [1] IMPLICIT CertReqMsg, whose first element is a CertRequest SEQUENCE");
    }
    if (!certReq.children.length) {
      throw E("cmc/bad-tagged-request", "a CertRequest must lead with its certReqId INTEGER (RFC 4211 sec. 5)");
    }
    return {
      arm: "crm", bodyPartID: readBodyPartIdentity(certReq.children[0]),
      certificationRequestBytes: null,
      // Re-tagged from the IMPLICIT [1] back to the universal SEQUENCE the CRMF
      // parser expects: handing back the context-tagged bytes would produce a
      // structure no CertReqMsg reader accepts.
      certReqMsgBytes: _asUniversalSequence(node),
      requestMessageType: null, requestMessageValueBytes: null,
    };
  }
  if (node.tagNumber === 2) {
    if (node.children.length !== 3) {
      throw E("cmc/bad-tagged-request", "an orm arm is [2] IMPLICIT { bodyPartID, requestMessageType, requestMessageValue }");
    }
    return {
      arm: "orm", bodyPartID: readBodyPartIdentity(node.children[0]),
      certificationRequestBytes: null, certReqMsgBytes: null,
      requestMessageType: asn1.read.oid(node.children[1]),
      requestMessageValueBytes: node.children[2].bytes,
    };
  }
  throw E("cmc/bad-tagged-request", "unknown TaggedRequest alternative [" + node.tagNumber + "] (RFC 5272 sec. 3.2.1.2)");
}

// ---- body-part identity ----------------------------------------------

// RFC 5272 sec. 3.2.2: "The body part identifier MUST be unique within a single
// PKIData or PKIResponse." The scope is the WHOLE message -- a checker that ran
// per-sequence would accept a control and a request that collide, which is
// exactly the shape B2 pins.
function assertUniqueBodyPartIds(ids) {
  var seen = Object.create(null);
  for (var i = 0; i < ids.length; i++) {
    if (ids[i] === null) continue;
    if (seen[ids[i]]) {
      throw E("cmc/duplicate-body-part-id",
        "bodyPartID " + ids[i] + " appears more than once; it MUST be unique within a single PKIData or PKIResponse (RFC 5272 sec. 3.2.2)");
    }
    seen[ids[i]] = true;
  }
}

// ---- the two message bodies ------------------------------------------

// The two message bodies as engine schemas. Declaring them means the engine owns
// the positional reads, the field arity and the SET-OF ordering -- the bug class
// a hand-rolled cursor keeps reintroducing -- while the rules that genuinely span
// fields (whole-message body-part uniqueness, control placement, the status
// cross-checks) run in the build / the caller, which is where they can see
// everything they need.
// A repeat's walk result is the match object `{ node, items: [{ node, value }] }`,
// so each of these carries a `build` that flattens it to the plain list the
// enclosing build wants. The three differ by what an item's `value` IS, which is
// decided by the item schema:
//   - a `seq` item walks to its own MATCH, so its build output is at .value.result
//   - a `decode` leaf walks straight to whatever its function returned
//   - an `any` item walks to the node, whose .bytes is the raw TLV
function builtList(match) { return match.items.map(function (i) { return i.value.result; }); }
function decodedList(match) { return match.items.map(function (i) { return i.value; }); }
function rawList(match) { return match.items.map(function (i) { return i.node.bytes; }); }

var CONTROL_SEQUENCE = schema.seqOf(TAGGED_ATTRIBUTE,
  { code: "cmc/bad-control", what: "a control sequence", build: builtList });
var REQ_SEQUENCE = schema.seqOf(schema.decode(parseTaggedRequest),
  { code: "cmc/bad-tagged-request", what: "a reqSequence", build: decodedList });

// TaggedContentInfo ::= SEQUENCE { bodyPartID, contentInfo } (RFC 5272 sec.
// 3.2.1.3) and OtherMsg ::= SEQUENCE { bodyPartID, otherMsgType, otherMsgValue }
// (sec. 3.2.1.4). Neither payload is interpreted here -- the ContentInfo is a
// CMS object the caller decodes, the OtherMsg value is by definition arbitrary --
// but BOTH carry a body part identity, and sec. 3.2.2's uniqueness rule covers
// "each element of a PKIData or PKIResponse". Decoding just the identifier is
// what lets that rule cover them without this layer claiming to understand the
// payload.
var TAGGED_CONTENT_INFO = schema.seq([
  schema.field("bodyPartID", schema.decode(readBodyPartIdentity)),
  schema.field("contentInfo", schema.any()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "cmc/bad-cms-sequence", what: "a TaggedContentInfo",
  build: function (m) {
    // The payload stays RAW -- this layer does not decode a content type it may
    // not know -- but it must still BE a ContentInfo: SEQUENCE { contentType
    // OBJECT IDENTIFIER, content [0] EXPLICIT ANY OPTIONAL } (RFC 5652 sec. 3).
    // Surfacing an INTEGER, or anything else that cannot be one, as a content
    // info would hand the caller a "CMS message" no CMS reader will accept, which
    // is not the same thing as a content type this decoder happens not to handle.
    var ci = m.fields.contentInfo.value;
    var kids = ci.children || [];
    var lead = kids[0];
    if (!(ci.tagClass === "universal" && ci.tagNumber === TAGS.SEQUENCE && ci.constructed) || !lead) {
      throw E("cmc/bad-cms-sequence",
        "a TaggedContentInfo carries a CMS ContentInfo, which leads with its contentType OBJECT IDENTIFIER (RFC 5652 sec. 3)");
    }
    // READ the contentType rather than inspecting its tag. An OBJECT IDENTIFIER
    // TLV can carry content no OID reader will accept -- empty, or a subidentifier
    // padded to a non-minimal encoding -- and a tag check waves both through. The
    // toolkit's own CMS parser refuses them, so accepting them here would let the
    // builder sign a "CMS message" pki.schema.cms.parse will not read back. The
    // VALUE is still not interpreted: this layer only establishes that there is a
    // content type to interpret.
    try { asn1.read.oid(lead); }
    catch (e) {
      throw E("cmc/bad-cms-sequence",
        "a TaggedContentInfo carries a CMS ContentInfo, whose contentType must be a readable OBJECT IDENTIFIER (RFC 5652 sec. 3)", e);
    }
    // The WHOLE envelope, not just its first field: content is `[0] EXPLICIT ANY
    // DEFINED BY contentType OPTIONAL`, so at most one more element and it is that
    // tag. An INTEGER sitting where the content belongs, or a third field, is not
    // a ContentInfo any CMS reader will take -- and stopping at the leading OID
    // would surface it as one.
    if (kids.length > 2) {
      throw E("cmc/bad-cms-sequence",
        "a CMS ContentInfo is { contentType, [0] EXPLICIT content OPTIONAL }; this carries " +
        kids.length + " fields (RFC 5652 sec. 3)");
    }
    if (kids.length === 2) {
      var content = kids[1];
      if (content.tagClass !== "context" || content.tagNumber !== 0 || !content.constructed) {
        throw E("cmc/bad-cms-sequence",
          "a CMS ContentInfo's second field is the [0] EXPLICIT content (RFC 5652 sec. 3)");
      }
      // EXPLICIT wraps EXACTLY ONE value (X.690 sec. 8.14). Checking the tag alone
      // would let an EMPTY wrapper, or one holding several values, read as a content
      // info -- shapes pki.schema.cms.parse refuses as cms/not-a-content-info, so the
      // builder's readback would pass a message its own CMS reader will not accept.
      if (!content.children || content.children.length !== 1) {
        throw E("cmc/bad-cms-sequence",
          "a ContentInfo's [0] EXPLICIT content wraps exactly one value, got " +
          ((content.children && content.children.length) || 0) + " (X.690 sec. 8.14)");
      }
    }
    return { bodyPartID: m.fields.bodyPartID.value, contentInfoBytes: ci.bytes };
  },
});

var OTHER_MSG = schema.seq([
  schema.field("bodyPartID", schema.decode(readBodyPartIdentity)),
  schema.field("otherMsgType", schema.oidLeaf()),
  schema.field("otherMsgValue", schema.any()),
], {
  assert: "sequence", arity: { exact: 3 }, code: "cmc/bad-other-msg", what: "an OtherMsg",
  build: function (m) {
    return {
      bodyPartID: m.fields.bodyPartID.value,
      otherMsgType: m.fields.otherMsgType.value,
      otherMsgValueBytes: m.fields.otherMsgValue.value.bytes,
    };
  },
});

// PKIData ::= SEQUENCE { controlSequence, reqSequence, cmsSequence,
//   otherMsgSequence } -- RFC 5272 sec. 3.2.1. All FOUR are mandatory though each
// may be empty, so `arity: { exact: 4 }` is the rule, not a convenience.
var PKI_DATA = schema.seq([
  schema.field("controlSequence", CONTROL_SEQUENCE),
  schema.field("reqSequence", REQ_SEQUENCE),
  schema.field("cmsSequence", schema.seqOf(TAGGED_CONTENT_INFO,
    { code: "cmc/bad-cms-sequence", what: "the PKIData cmsSequence", build: builtList })),
  schema.field("otherMsgSequence", schema.seqOf(OTHER_MSG,
    { code: "cmc/bad-other-msg", what: "the PKIData otherMsgSequence", build: builtList })),
], {
  assert: "sequence", arity: { exact: 4 }, code: "cmc/bad-pkidata",
  what: "a PKIData (SEQUENCE { controlSequence, reqSequence, cmsSequence, otherMsgSequence }, all four mandatory though each may be empty -- RFC 5272 sec. 3.2.1)",
  build: function (m) {
    return {
      kind: "pkiData",
      controls: m.fields.controlSequence.value.result,
      requests: m.fields.reqSequence.value.result,
      cmsSequence: m.fields.cmsSequence.value.result,
      otherMsgs: m.fields.otherMsgSequence.value.result,
      // The raw reqSequence TLV, tag and length included: the Identity Proof V2
      // witness is computed over exactly these bytes "encoded exactly as it
      // appears in the Full PKI Request" (RFC 5272 sec. 6.2.1), so it is taken
      // off the matched NODE rather than re-encoded from the decoded requests.
      reqSequenceBytes: m.fields.reqSequence.node.bytes,
    };
  },
});

// PKIResponse ::= SEQUENCE { controlSequence, cmsSequence, otherMsgSequence } --
// RFC 5272 sec. 4.2.1. THREE fields: there is no reqSequence in a response.
var PKI_RESPONSE = schema.seq([
  schema.field("controlSequence", CONTROL_SEQUENCE),
  schema.field("cmsSequence", schema.seqOf(TAGGED_CONTENT_INFO,
    { code: "cmc/bad-cms-sequence", what: "the PKIResponse cmsSequence", build: builtList })),
  schema.field("otherMsgSequence", schema.seqOf(OTHER_MSG,
    { code: "cmc/bad-other-msg", what: "the PKIResponse otherMsgSequence", build: builtList })),
], {
  assert: "sequence", arity: { exact: 3 }, code: "cmc/bad-pkiresponse",
  what: "a PKIResponse (SEQUENCE { controlSequence, cmsSequence, otherMsgSequence } -- three fields, all mandatory though each may be empty -- RFC 5272 sec. 4.2.1)",
  build: function (m) {
    return {
      kind: "pkiResponse",
      controls: m.fields.controlSequence.value.result,
      requests: [],
      cmsSequence: m.fields.cmsSequence.value.result,
      otherMsgs: m.fields.otherMsgSequence.value.result,
      reqSequenceBytes: null,
    };
  },
});

// Collect the status controls out of an already-parsed control list, in wire
// order. Absence is NOT an error: RFC 5272 sec. 6.1.2 says "If no status exists
// for a Simple or Full PKI Request, then the value of success is assumed", so a
// response with no status control is a successful one.
function _collectStatuses(controls) {
  var out = [];
  for (var i = 0; i < controls.length; i++) {
    var c = controls[i];
    var version = c.attrType === OID_STATUS_INFO_V2 ? 2 : (c.attrType === OID_STATUS_INFO ? 1 : 0);
    if (!version) continue;
    if (c.values.length !== 1) {
      throw E("cmc/bad-status-info", "a CMC status control carries exactly one AttributeValue, got " + c.values.length);
    }
    out.push(parseStatusInfo(c.values[0], version, c.bodyPartID));
  }
  return out;
}

// The cross-cutting rules that a per-field walk cannot see: where each control is
// allowed to appear, which of them are status verdicts, which are unrecognized
// (surfaced, never a fault), and the whole-message body-part uniqueness.
function _finishBody(body, where) {
  for (var i = 0; i < body.controls.length; i++) assertControlPlacement(body.controls[i], where);
  body.statuses = _collectStatuses(body.controls);
  body.unhandled = body.controls.filter(function (c) {
    return c.attrType !== OID_STATUS_INFO && c.attrType !== OID_STATUS_INFO_V2 && c.attrName === null;
  });
  // RFC 5272 sec. 3.2.2 scopes uniqueness to "each element of a PKIData or
  // PKIResponse", and FOUR element kinds carry an identity. Enumerated here in
  // one place so the rule cannot hold for some of them and quietly lapse for the
  // rest: controls (sec. 3.2.1.1), requests (sec. 3.2.1.2 -- the tcr/orm
  // bodyPartID and the crm arm's certReqId), content infos (sec. 3.2.1.3) and
  // other messages (sec. 3.2.1.4).
  var ids = [];
  function collect(list) { for (var j = 0; j < list.length; j++) ids.push(list[j].bodyPartID); }
  collect(body.controls);
  collect(body.requests);
  collect(body.cmsSequence);
  collect(body.otherMsgs);
  assertUniqueBodyPartIds(ids);
  return body;
}

/**
 * @primitive  pki.schema.cmc.parsePkiData
 * @signature  pki.schema.cmc.parsePkiData(der) -> parsed
 * @since      0.4.16
 * @status     experimental
 * @spec       RFC 5272 sec. 3.2.1
 * @related    pki.schema.cmc.parse, pki.schema.cmc.parsePkiResponse
 *
 * Decode a bare `PKIData` body (the encapsulated content of a Full PKI Request),
 * without the CMS layer. All FOUR sequences are mandatory though each may be
 * empty, so a message that simply omits a trailing empty one is malformed rather
 * than shorthand. `reqSequenceBytes` is the raw `reqSequence` TLV, tag and length
 * included, because the Identity Proof V2 witness is computed over exactly those
 * bytes (RFC 5272 sec. 6.2.1).
 *
 * @example
 *   var b = pki.asn1.build;
 *   var der = b.sequence([b.sequence([]), b.sequence([]), b.sequence([]), b.sequence([])]);
 *   var d = pki.schema.cmc.parsePkiData(der);
 *   d.controls.length;   // 0 -- present and empty, which is legal
 */
function parsePkiData(input) {
  var root = asn1.decode(Buffer.isBuffer(input) ? input : Buffer.from(input));
  var body = schema.walk(PKI_DATA, root, NS).result;
  body.bytes = root.bytes;
  return _finishBody(body, "pkiData");
}

/**
 * @primitive  pki.schema.cmc.parsePkiResponse
 * @signature  pki.schema.cmc.parsePkiResponse(der) -> parsed
 * @since      0.4.16
 * @status     experimental
 * @spec       RFC 5272 sec. 4.2.1
 * @related    pki.schema.cmc.parse, pki.schema.cmc.parsePkiData
 *
 * Decode a bare `PKIResponse` body. A PKIResponse has THREE sequences -- there is
 * no `reqSequence` -- and all three are mandatory though each may be empty. The
 * status controls are collected in wire order; a response may legitimately carry
 * several, and carrying NONE means success (RFC 5272 sec. 6.1.2).
 *
 * @example
 *   var b = pki.asn1.build;
 *   var der = b.sequence([b.sequence([]), b.sequence([]), b.sequence([])]);
 *   var r = pki.schema.cmc.parsePkiResponse(der);
 *   r.statuses.length;   // 0 -- no status control means success is assumed
 */
function parsePkiResponse(input) {
  var root = asn1.decode(Buffer.isBuffer(input) ? input : Buffer.from(input));
  var body = schema.walk(PKI_RESPONSE, root, NS).result;
  body.bytes = root.bytes;
  return _finishBody(body, "pkiResponse");
}

/**
 * @primitive  pki.schema.cmc.parse
 * @signature  pki.schema.cmc.parse(input) -> parsed
 * @since      0.4.16
 * @status     experimental
 * @spec       RFC 5272, RFC 6402
 * @defends    cmc-status-confusion (CWE-20)
 * @related    pki.schema.cmc.parsePkiData, pki.schema.cmc.parsePkiResponse, pki.cms.verify
 *
 * Decode a CMC Full PKI Request or Full PKI Response from its CMS carrier. `input`
 * is DER, a PEM `CMS` block, or an already-parsed `pki.schema.cms` object. The CMS
 * layer is peeled, the encapsulated content type selects the body
 * (`id-cct-PKIData` -> a request, `id-cct-PKIResponse` -> a response), and any
 * other content type is refused as not-CMC rather than guessed at.
 *
 * The parsed CMS is returned on `cms` so a caller can verify the signature -- this
 * decoder never does: reading a message and trusting it are separate steps, and
 * RFC 5272 sec. 3.2.1.3.4 makes the signature check the caller's obligation.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var body = b.sequence([b.sequence([]), b.sequence([]), b.sequence([]), b.sequence([])]);
 *   var encap = b.sequence([b.oid(pki.oid.byName("id-cct-PKIData")), b.explicit(0, b.octetString(body))]);
 *   var sd = b.sequence([b.integer(3n), b.set([]), encap, b.set([])]);
 *   var der = b.sequence([b.oid("1.2.840.113549.1.7.2"), b.explicit(0, sd)]);
 *   pki.schema.cmc.parse(der).kind;   // "pkiData"
 */
function parse(input) {
  // Bytes or an already-parsed CMS? Decided by a POSITIVE marker of the parsed
  // shape, never by "it is an object" -- a Uint8Array is an object too, so the
  // looser test routes perfectly good DER to the parsed branch, where it has no
  // content type and is refused as not-CMC while the identical Buffer parses.
  // encapContentInfo is the field this function goes on to read, so requiring it
  // is the same question the code below already asks.
  var parsedCms = (input && typeof input === "object" && !ArrayBuffer.isView(input) &&
    !(input instanceof ArrayBuffer) && input.encapContentInfo != null)
    ? input : cms.parse(input);
  // The CARRIER is part of the identity, not just the encapsulated content type.
  // RFC 5272 sec. 3.2 / 4.2 admit a SignedData or an AuthenticatedData; other CMS
  // types also expose an encapContentInfo (CompressedData does), and dispatching
  // on the inner OID alone would accept an unsigned, unauthenticated wrapper as a
  // Full PKI message.
  if (CMC_CARRIERS[parsedCms.contentTypeName] !== 1) {
    throw E("cmc/not-cmc",
      "a Full PKI Request / Response is carried in a CMS SignedData or AuthenticatedData, got " +
      (parsedCms.contentTypeName || "an unnamed content type") + " (RFC 5272 sec. 3.2 / 4.2)");
  }
  var encap = parsedCms.encapContentInfo;
  if (!encap) throw E("cmc/not-cmc", "a CMC message is carried in a CMS SignedData or AuthenticatedData");
  var eContentType = encap.eContentType;
  if (eContentType !== OID_PKI_DATA && eContentType !== OID_PKI_RESPONSE) {
    throw E("cmc/not-cmc",
      "the encapsulated content type is " + (oid.name(eContentType) || eContentType) +
      ", not id-cct-PKIData or id-cct-PKIResponse (RFC 5272 sec. 3.2 / 4.2)");
  }
  if (encap.eContent == null) {
    throw E("cmc/no-content",
      "a Full PKI Request / Response carries its body as the encapsulated content; this SignedData is detached (RFC 5272 sec. 3.2)");
  }
  var body = eContentType === OID_PKI_DATA ? parsePkiData(encap.eContent) : parsePkiResponse(encap.eContent);
  body.cms = parsedCms;
  body.eContentType = eContentType;
  return body;
}

module.exports = {
  parse: parse,
  parsePkiData: parsePkiData,
  parsePkiResponse: parsePkiResponse,
  STATUS_BY_VALUE: STATUS_BY_VALUE,
  FAIL_INFO_BY_VALUE: FAIL_INFO_BY_VALUE,
};
