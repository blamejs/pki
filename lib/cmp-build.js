// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.cmp
 * @nav        Signing
 * @title      Certificate management protocol messages
 * @fullname   CMP (Certificate Management Protocol, RFC 4210)
 * @intro The RFC 9810 Certificate Management Protocol producing side. `pki.cmp.build` assembles a
 *   `PKIMessage` -- a `PKIHeader` (sender / recipient / transaction metadata), a `PKIBody` carrying one
 *   request or transaction (an `ir` / `cr` / `kur` certificate request via `pki.crmf.build`, a `p10cr`
 *   PKCS#10 via `pki.csr.sign`, or a `certConf` / `pollReq` / `genm` / `rr`), and an optional
 *   `PKIProtection` computed over the message. Protection is a signature under the sender key (any
 *   registry algorithm) or a PBMAC1 shared-secret MAC. The emitted message round-trips through
 *   `pki.schema.cmp.parse` and its protection verifies. `pki.cmp.transfer` carries a message to a CMP
 *   endpoint (RFC 9811), `pki.cmp.verify` checks an incoming message's protection, and `pki.cmp.session`
 *   drives a full enrollment transaction end to end over these. Parsing lives at `pki.schema.cmp.parse`.
 * @spec RFC 9810
 * @card Build a CMP PKIMessage with signature or PBMAC1 protection.
 */
//
// RFC 9810 Appendix A is DEFINITIONS EXPLICIT TAGS: every context tag in the PKIMessage envelope
// (each PKIHeader [0..8] optional, every PKIBody [n] arm, protection [0], extraCerts [1]) is an EXPLICIT
// wrapper (asn1.build.explicit), the exact inverse of the RFC 4211 CRMF interior (IMPLICIT TAGS). The two
// IMPLICIT islands are foreign imports produced wholesale by pki.crmf.build (the CertReqMessages /
// CertTemplate interior) and embedded verbatim, never re-encoded here. Protection is computed over the
// byte-exact DER of the virtual ProtectedPart ::= SEQUENCE { header, body }, built from the same header
// and body TLVs placed in the envelope. The signature scheme resolves from the sender key through the
// shared sign-scheme registry; the Name / GeneralName / SPKI encoders and the post-sign self-check are the
// shared lib/pki-build primitives, bound to the cmp namespace.

var asn1 = require("./asn1-der");
var oid = require("./oid");
var cmp = require("./schema-cmp");
var crmf = require("./crmf-sign");
var schemaCrmf = require("./schema-crmf");
var intrinsic = require("./guard-intrinsic");
// Own-key membership through an operation taken at load: it decides which proof-of-possession
// methods couple the message to a protocol version, and an inherited name is one no RFC defined.
var _hasOwn = intrinsic.hasOwn;
// The same load-bound treatment for the operations that shape a revocation request and a support
// message: each decides what reaches the wire, so a replaced built-in must not get a say.
var _isArray = intrinsic.isArray;
var _isBuffer = intrinsic.isBuffer;
var _bufferConcat = intrinsic.bufferConcat;
var _map = intrinsic.map;
var _keys = intrinsic.keys;
var _forEach = intrinsic.forEach;
var _push = intrinsic.push;
var _stringify = intrinsic.stringify;
var _bigInt = intrinsic.BigInt;
// The constructor taken at load: re-materializing an instant that is about to be encoded must not
// go through a Date a caller could have replaced after this module was read.
var _Date = intrinsic.Date;
var csr = require("./schema-csr");
var crl = require("./schema-crl");
var x509 = require("./schema-x509");
var signScheme = require("./sign-scheme");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var webcrypto = require("./webcrypto");
var pbes2 = require("./pbes2");
var constants = require("./constants");
var guard = require("./guard-all");
var httpTransport = require("./http-transport");
var frameworkError = require("./framework-error");

var CmpError = frameworkError.CmpError;
var b = asn1.build;
function _err(code, message, cause) { return new CmpError(code, message, cause); }
function _signE(kind, message, cause) { return new CmpError("cmp/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var NS = pkix.makeNS("cmp", CmpError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var _b = pkiBuild.makeBuilder({
  ErrorClass: CmpError, prefix: "cmp", O: O, NS: NS,
  NAME_SCHEMA: pkix.name(NS), SPKI_SCHEMA: pkix.spki(NS), EXT_DECODERS: EXT_DECODERS,
});

var KNOWN_HEADER_KEYS = {
  sender: 1, recipient: 1, pvno: 1, messageTime: 1, senderKID: 1, recipKID: 1,
  transactionID: 1, senderNonce: 1, recipNonce: 1, freeText: 1, generalInfo: 1,
};
var KNOWN_BODY_KEYS = {
  ir: 1, cr: 1, kur: 1, p10cr: 1, certConf: 1, pollReq: 1, genm: 1, rr: 1,   // request-side
  ip: 1, cp: 1, kup: 1, ccp: 1, krp: 1, rp: 1, genp: 1, error: 1, pollRep: 1, pkiconf: 1,   // CA/responder-side
};
// The PKIBody arm -> its EXPLICIT context tag number (schema-cmp.js BODY_ARMS). rr is [11], not [15].
var BODY_TAG = {
  ir: 0, cr: 2, p10cr: 4, kur: 7, rr: 11, genm: 21, certConf: 24, pollReq: 25,
  ip: 1, cp: 3, kup: 8, krp: 10, rp: 12, ccp: 14, pkiconf: 19, genp: 22, error: 23, pollRep: 26,
};
var CRMF_BODY = { ir: 1, cr: 1, kur: 1 };   // arms whose content is a CertReqMessages via pki.crmf.build
var CERT_REP_ARM = { ip: 1, cp: 1, kup: 1, ccp: 1 };   // arms carrying a CertRepMessage
// Protection has two mutually exclusive forms, and the signature parameters are read only by the
// signature one: under PBMAC1 a requested pss or digestAlgorithm selects nothing and the message
// goes out MAC'd under the default PRF, byte-identical to the call that never named them. The union
// stays in force where the form is ambiguous, so _resolveProtection keeps its both/neither verdicts.
var KNOWN_OPTS_KEYS = { key: 1, cert: 1, mac: 1, extraCerts: 1, pem: 1, pss: 1, digestAlgorithm: 1 };
var KNOWN_OPTS_SIG_KEYS = { key: 1, cert: 1, extraCerts: 1, pem: 1, pss: 1, digestAlgorithm: 1 };
var KNOWN_OPTS_MAC_KEYS = { mac: 1, extraCerts: 1, pem: 1 };
var KNOWN_MESSAGE_KEYS = { header: 1, body: 1 };
var KNOWN_MAC_KEYS = { secret: 1, salt: 1, iterationCount: 1, prf: 1, keyLength: 1, algorithm: 1 };

var PBMAC1_DEFAULT_ITER = 100000;
var PBMAC1_DEFAULT_SALT_BYTES = 16;
var PBMAC1_MIN_SALT = 8;          // octets -- RFC 8018 sec. 4.1 (64-bit) floor; matches the pki.cmp.verify verifier floor
var PBMAC1_DEFAULT_KEYLEN = 32;   // bytes -- HMAC-SHA256 key
var PBMAC1_MIN_KEYLEN = 20;       // bytes -- RFC 9579 sec. 9 floor (matches the pki.cmp.verify verifier floor)
var PBMAC1_MAX_KEYLEN = 1024;     // bytes -- an HMAC key beyond a hash block is pointless; bound the work
var PBMAC1_MIN_ITER = 1000;       // RFC 8018 sec. 4.2 recommended minimum -- reject a trivially weak count
var PBMAC1_PRF = { "SHA-256": "hmacWithSHA256", "SHA-384": "hmacWithSHA384", "SHA-512": "hmacWithSHA512" };
var PBMAC1_MAC_OID = { "SHA-256": "hmacWithSHA256", "SHA-384": "hmacWithSHA384", "SHA-512": "hmacWithSHA512" };
var PBMAC1_PRF_HLEN = { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 };   // PBKDF2 PRF output length (one derived block)
// PKIFailureInfo named bits (RFC 9810 sec. 5.2.3), position = bit index, mirroring schema-cmp's decode list;
// the build -> parse round-trip cross-checks the positions against the parser.
var FAIL_INFO_NAMES = ["badAlg", "badMessageCheck", "badRequest", "badTime", "badCertId", "badDataFormat",
  "wrongAuthority", "incorrectData", "missingTimeStamp", "badPOP", "certRevoked", "certConfirmed",
  "wrongIntegrity", "badRecipientNonce", "timeNotAvailable", "unacceptedPolicy", "unacceptedExtension",
  "addInfoNotAvailable", "badSenderNonce", "badCertTemplate", "signerNotTrusted", "transactionIdInUse",
  "unsupportedVersion", "notAuthorized", "systemUnavail", "systemFailure", "duplicateCertReq"];
var FAIL_INFO_INDEX = {};
FAIL_INFO_NAMES.forEach(function (n, i) { FAIL_INFO_INDEX[n] = i; });
// CertStatus.hashAlg names the hash used to compute certHash, restricted to hash algorithms and not any OID.
var CERT_CONF_HASH_ALGS = { sha1: 1, sha256: 1, sha384: 1, sha512: 1, "sha3-256": 1, "sha3-512": 1 };

// ---- small shared encoders (byte-exact inverses of schema-cmp.js readers) ----

function _reqOctets(v, what) {
  var buf = _b.reqDer(v, what);
  return b.octetString(buf);
}

// PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String: non-empty, every element UTF8String.
function _encodePkiFreeText(strings, code, what) {
  if (!Array.isArray(strings) || !strings.length) throw _err(code, what + " must be a non-empty array of strings");
  return b.sequence(strings.map(function (s) {
    if (typeof s !== "string") throw _err(code, what + " entries must be strings");
    return b.utf8(s);
  }));
}

// A recognized fixed-syntax id-it value (RFC 9810 sec. 5.1.1.1/.2/.4): implicitConfirm -> NULL,
// confirmWaitTime -> GeneralizedTime, certProfile -> non-empty SEQUENCE OF UTF8String. An unknown id-it
// carries a pre-encoded infoValue DER (or none).
function _encodeInfoValue(itav) {
  var name = itav.infoType;
  if (name === "implicitConfirm") {
    if (itav.infoValue != null) throw _err("cmp/bad-info-value", "implicitConfirm carries a NULL infoValue");
    return b.nullValue();
  }
  if (name === "confirmWaitTime") {
    guard.time.assertValid(itav.infoValue, _err, "cmp/bad-info-value", "confirmWaitTime infoValue");   // reject a non-Date / Invalid Date
    return b.generalizedTime(itav.infoValue);
  }
  if (name === "certProfile") {
    return _encodePkiFreeText(itav.infoValue, "cmp/bad-info-value", "certProfile");
  }
  if (itav.infoValue == null) return null;
  return b.raw(_b.reqDer(itav.infoValue, "infoValue (a pre-encoded DER value)"));
}

// InfoTypeAndValue ::= SEQUENCE { infoType OID, infoValue ANY DEFINED BY infoType OPTIONAL }.
function _encodeInfoTypeAndValue(itav) {
  if (!itav || typeof itav !== "object" || Buffer.isBuffer(itav)) throw _err("cmp/bad-info-value", "an InfoTypeAndValue must be an object { infoType, infoValue? }");
  if (typeof itav.infoType !== "string" || O(itav.infoType) == null) throw _err("cmp/bad-name", "unknown infoType " + JSON.stringify(itav.infoType));
  var children = [b.oid(O(itav.infoType))];
  var val = _encodeInfoValue(itav);
  if (val != null) children.push(val);
  return b.sequence(children);
}

// generalInfo [8] / genm content: SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue.
function _encodeGeneralInfo(itavs, code, what) {
  if (!Array.isArray(itavs) || !itavs.length) throw _err(code, what + " must be a non-empty array of InfoTypeAndValue");
  return b.sequence(itavs.map(_encodeInfoTypeAndValue));
}

// ---- PKIHeader ----

// An AlgorithmIdentifier { algorithm OID, parameters ANY OPTIONAL } for a bare/absent-params digest.
function _algIdNoParams(name) { return b.sequence([b.oid(O(name))]); }

// PKIHeader ::= SEQUENCE { pvno INTEGER, sender GeneralName, recipient GeneralName, EXPLICIT [0..8] }.
// protectionAlgDer is the DERIVED AlgorithmIdentifier ([1]), present iff the message is protected. Returns
// the exact headerTLV, built ONCE and reused in both the envelope and the ProtectedPart (RFC 9810 5.1.3).
function _encodeHeader(headerSpec, protectionAlgDer, pvno) {
  if (!headerSpec || typeof headerSpec !== "object" || Buffer.isBuffer(headerSpec)) throw _err("cmp/bad-input", "message.header must be an object");
  guard.identifier.assertKnownKeys(headerSpec, KNOWN_HEADER_KEYS, _err, "cmp/bad-input", "unknown header field ");
  if (headerSpec.sender == null) throw _err("cmp/bad-input", "message.header.sender is required (GeneralName)");
  if (headerSpec.recipient == null) throw _err("cmp/bad-input", "message.header.recipient is required (GeneralName)");

  var children = [
    b.integer(BigInt(pvno)),
    _b.encodeGeneralName(headerSpec.sender),
    _b.encodeGeneralName(headerSpec.recipient),
  ];
  // EXPLICIT [0..8] optionals, ascending, at most once each.
  if (headerSpec.messageTime != null) {
    guard.time.assertValid(headerSpec.messageTime, _err, "cmp/bad-input", "header.messageTime");   // reject a non-Date / Invalid Date
    children.push(b.explicit(0, b.generalizedTime(headerSpec.messageTime)));   // GeneralizedTime ONLY (never UTCTime)
  }
  if (protectionAlgDer != null) children.push(b.explicit(1, b.raw(protectionAlgDer)));
  if (headerSpec.senderKID != null) children.push(b.explicit(2, _reqOctets(headerSpec.senderKID, "header.senderKID")));
  if (headerSpec.recipKID != null) children.push(b.explicit(3, _reqOctets(headerSpec.recipKID, "header.recipKID")));
  if (headerSpec.transactionID != null) children.push(b.explicit(4, _reqOctets(headerSpec.transactionID, "header.transactionID")));
  if (headerSpec.senderNonce != null) children.push(b.explicit(5, _reqOctets(headerSpec.senderNonce, "header.senderNonce")));
  if (headerSpec.recipNonce != null) children.push(b.explicit(6, _reqOctets(headerSpec.recipNonce, "header.recipNonce")));
  if (headerSpec.freeText != null) children.push(b.explicit(7, _encodePkiFreeText(headerSpec.freeText, "cmp/bad-freetext", "header.freeText")));
  if (headerSpec.generalInfo != null) children.push(b.explicit(8, _encodeGeneralInfo(headerSpec.generalInfo, "cmp/bad-general-info", "header.generalInfo")));
  return b.sequence(children);
}

// ---- PKIBody arm content encoders ----

// A certReqId is an UNBOUNDED INTEGER (RFC 9483 -1 sentinel, no upper bound): accept a safe-integer number
// or a bigint (a large value beyond 2^53), reject a non-integer / other type. Returns a BigInt for b.integer.
function _reqIdInt(v, code, what) { return guard.range.authoredInteger(v, _err, code, what); }

// PKIFailureInfo ::= BIT STRING (named bits, RFC 9810 sec. 5.2.3): a minimal NamedBitList from bit names.
function _encodeFailInfo(names, code) {
  if (!Array.isArray(names)) throw _err(code, "statusInfo.failInfo must be an array of PKIFailureInfo bit names");
  return b.namedBitString(names.map(function (n) {
    if (typeof n !== "string" || FAIL_INFO_INDEX[n] === undefined) throw _err(code, "unknown PKIFailureInfo bit " + JSON.stringify(n));
    return FAIL_INFO_INDEX[n];
  }));
}

// PKIStatusInfo ::= SEQUENCE { status PKIStatus INTEGER, statusString PKIFreeText OPTIONAL, failInfo BIT STRING
// OPTIONAL }. `code` is the caller's typed error (default cmp/bad-status-info; certConf passes cmp/bad-cert-status).
function _encodePkiStatusInfo(si, code) {
  code = code || "cmp/bad-status-info";
  if (!si || typeof si !== "object" || Buffer.isBuffer(si)) throw _err(code, "a PKIStatusInfo must be an object { status, statusString?, failInfo? }");
  if (typeof si.status !== "number" || !Number.isInteger(si.status) || si.status < 0 || si.status > 6) throw _err(code, "statusInfo.status must be a PKIStatus 0..6 (RFC 9810 sec. 5.2.3)");
  var children = [b.integer(BigInt(si.status))];
  if (si.statusString != null) children.push(_encodePkiFreeText(si.statusString, code, "statusInfo.statusString"));
  if (si.failInfo != null) children.push(_encodeFailInfo(si.failInfo, code));   // strict order: status -> statusString -> failInfo (both optionals untagged)
  return b.sequence(children);
}

// CertStatus ::= SEQUENCE { certHash OCTET STRING, certReqId INTEGER, statusInfo PKIStatusInfo OPTIONAL,
//   hashAlg [0] EXPLICIT AlgorithmIdentifier OPTIONAL }. hashAlg present => cmp2021 (pvno bump).
function _encodeCertStatus(cs, state) {
  if (!cs || typeof cs !== "object" || Buffer.isBuffer(cs)) throw _err("cmp/bad-cert-status", "each CertStatus must be an object");
  var children = [
    _reqOctets(cs.certHash, "certConf certHash"),
    b.integer(_reqIdInt(cs.certReqId, "cmp/bad-cert-status", "CertStatus certReqId")),   // signed, -1 legal, unbounded
  ];
  if (cs.statusInfo != null) children.push(_encodePkiStatusInfo(cs.statusInfo, "cmp/bad-cert-status"));
  if (cs.hashAlg != null) {
    if (typeof cs.hashAlg !== "string" || !CERT_CONF_HASH_ALGS[cs.hashAlg]) throw _err("cmp/bad-name", "certConf hashAlg must be a hash algorithm (sha256 / sha384 / sha512 / sha3-256 / sha3-512 / sha1); got " + JSON.stringify(cs.hashAlg));
    children.push(b.explicit(0, _algIdNoParams(cs.hashAlg)));
    state.usesCmp2021 = true;
  }
  return b.sequence(children);
}

// CertConfirmContent ::= SEQUENCE OF CertStatus (empty legal, no SIZE floor).
function _encodeCertConfirmContent(list, state) {
  if (!Array.isArray(list)) throw _err("cmp/bad-cert-status", "certConf must be an array of CertStatus");
  return b.sequence(list.map(function (cs) { return _encodeCertStatus(cs, state); }));
}

// PollReqContent ::= SEQUENCE OF SEQUENCE { certReqId INTEGER } (-1 legal).
function _encodePollReqContent(list) {
  if (!Array.isArray(list)) throw _err("cmp/bad-poll-req", "pollReq must be an array of { certReqId }");
  return b.sequence(list.map(function (pr) {
    if (!pr || typeof pr !== "object" || Buffer.isBuffer(pr)) throw _err("cmp/bad-poll-req", "each pollReq entry must be { certReqId: <integer> }");
    return b.sequence([b.integer(_reqIdInt(pr.certReqId, "cmp/bad-poll-req", "pollReq certReqId"))]);
  }));
}

// GenMsgContent ::= SEQUENCE OF InfoTypeAndValue (empty legal).
function _encodeGenMsgContent(list) {
  if (!Array.isArray(list)) throw _err("cmp/bad-info-type-and-value", "genm must be an array of InfoTypeAndValue");
  return b.sequence(list.map(_encodeInfoTypeAndValue));
}

// RevReqContent ::= SEQUENCE OF RevDetails { certDetails CertTemplate, crlEntryDetails Extensions OPTIONAL }.
function _encodeRevDetails(rd) {
  if (!rd || typeof rd !== "object" || Buffer.isBuffer(rd)) throw _err("cmp/bad-rev-req", "each RevDetails must be an object { certDetails, crlEntryDetails? }");
  guard.identifier.assertKnownKeys(rd, KNOWN_REV_DETAILS_KEYS, _err, "cmp/bad-rev-req", "unknown RevDetails field ");
  if (rd.certDetails == null) throw _err("cmp/bad-rev-req", "RevDetails.certDetails (a CertTemplate) is required");
  var certDetails;
  if (Buffer.isBuffer(rd.certDetails) || rd.certDetails instanceof Uint8Array) {
    certDetails = b.raw(_b.reqDer(rd.certDetails, "RevDetails.certDetails (a pre-encoded CertTemplate DER)"));
  } else {
    // A revocation must identify the certificate to revoke by issuer + serialNumber (RFC 9810 App. D sec.
    // 5.3.2); the pre-encoded-CertTemplate hatch above is the escape for an advanced identification.
    if (rd.certDetails.issuer == null || rd.certDetails.serialNumber == null) throw _err("cmp/bad-rev-req", "a revocation certDetails must identify the certificate by issuer and serialNumber");
    certDetails = b.raw(crmf.buildCertTemplate(rd.certDetails));
  }
  var children = [certDetails];
  if (rd.crlEntryDetails != null) children.push(b.raw(_encodeCrlEntryDetails(rd.crlEntryDetails)));
  return b.sequence(children);
}

// crlEntryDetails ::= Extensions. A revocation request states WHY, so the structured form
// { reason } encodes the single reasonCode extension RFC 9483 sec. 4.2 requires. A caller
// needing another entry extension passes a pre-encoded Extensions DER instead.
//
// The reasonCode is emitted even at unspecified(0). RFC 5280 sec. 5.3.1 omits that value from a
// CRL entry, where absence and unspecified carry the same meaning; sec. 4.2 governs a different
// structure and says the field is REQUIRED and "MUST be 0 (unspecified)" when the reason is
// unknown or is not to be published, so the omit-on-zero rule does not travel here.
var KNOWN_REV_DETAILS_KEYS = { certDetails: 1, crlEntryDetails: 1 };
var KNOWN_CRL_ENTRY_DETAIL_KEYS = { reason: 1 };
var CRL_REASON_BY_NAME = intrinsic.create(null);
_forEach(_keys(constants.NAMES.CRL_REASON), function (v) { CRL_REASON_BY_NAME[constants.NAMES.CRL_REASON[v]] = intrinsic.Number(v); });
function _encodeCrlEntryDetails(spec) {
  if (_isBuffer(spec) || intrinsic.types.isTypedArray(spec)) return _b.reqDer(spec, "RevDetails.crlEntryDetails (a pre-encoded Extensions DER)");
  if (typeof spec !== "object") throw _err("cmp/bad-rev-req", "RevDetails.crlEntryDetails must be { reason } or a pre-encoded Extensions DER");
  guard.identifier.assertKnownKeys(spec, KNOWN_CRL_ENTRY_DETAIL_KEYS, _err, "cmp/bad-rev-req", "unknown crlEntryDetails field ");
  var code = spec.reason == null ? 0 : CRL_REASON_BY_NAME[spec.reason];
  if (spec.reason != null && (typeof spec.reason !== "string" || !_hasOwn(CRL_REASON_BY_NAME, spec.reason))) {
    throw _err("cmp/bad-rev-req", "unknown CRLReason " + _stringify(spec.reason) + " (RFC 5280 sec. 5.3.1)");
  }
  return b.sequence([_b.ext(O("reasonCode"), false, b.enumerated(_bigInt(code)))]);
}

// ---- support-message request values (RFC 9480 sec. 2.17, profiled by RFC 9483 sec. 4.3.4) ----
//
// CRLSource ::= CHOICE { dpn [0] DistributionPointName, issuer [1] GeneralNames }
// CRLStatus ::= SEQUENCE { source CRLSource, thisUpdate Time OPTIONAL }
// CRLStatusListValue ::= SEQUENCE SIZE (1..MAX) OF CRLStatus
//
// The CMP module is EXPLICIT TAGS, so CRLSource's own [0] / [1] wrap their alternative. The
// DistributionPointName inside the dpn arm keeps the IMPLICIT tagging of the module it is
// imported from, which is why its fullName [0] is a bare context-constructed GeneralNames.
var KNOWN_CRL_STATUS_KEYS = { dpn: 1, issuer: 1, thisUpdate: 1 };
var KNOWN_DPN_KEYS = { fullName: 1 };
function buildCrlStatusList(spec) {
  if (!spec || typeof spec !== "object" || _isBuffer(spec)) throw _err("cmp/bad-input", "a crlUpdate request must be an object { dpn | issuer, thisUpdate? }");
  guard.identifier.assertKnownKeys(spec, KNOWN_CRL_STATUS_KEYS, _err, "cmp/bad-input", "unknown crlUpdate field ");
  if ((spec.dpn == null) === (spec.issuer == null)) {
    throw _err("cmp/bad-input", "a crlUpdate identifies the requested CRL by EXACTLY ONE of dpn (a distribution point name) or issuer (the CA that issues it) -- CRLSource is a CHOICE (RFC 9483 sec. 4.3.4)");
  }
  var source, issuerNameDer = null;
  if (spec.dpn != null) {
    if (!spec.dpn || typeof spec.dpn !== "object" || _isBuffer(spec.dpn)) throw _err("cmp/bad-input", "crlUpdate.dpn must be { fullName: [<GeneralName>...] }");
    guard.identifier.assertKnownKeys(spec.dpn, KNOWN_DPN_KEYS, _err, "cmp/bad-input", "unknown crlUpdate.dpn field ");
    // The nameRelativeToCRLIssuer arm of DistributionPointName is not built, matching the same
    // decision in pki.crl.sign for issuingDistributionPoint and freshestCRL. Re-open it in all
    // three together, since a partial relative-name surface would encode names one verb can
    // produce and its sibling cannot.
    if (spec.dpn.fullName == null) throw _err("cmp/bad-input", "crlUpdate.dpn requires fullName (the nameRelativeToCRLIssuer arm is not built; pki.crl.sign draws the same line for issuingDistributionPoint)");
    var entries = _isArray(spec.dpn.fullName) ? spec.dpn.fullName : [spec.dpn.fullName];
    if (!entries.length) throw _err("cmp/bad-input", "crlUpdate.dpn.fullName must carry at least one GeneralName");
    source = b.explicit(0, b.contextConstructed(0, _bufferConcat(_map(entries, function (e) { return _b.encodeGeneralName(e); }))));
  } else {
    // sec. 4.3.4: the issuer choice "MUST contain the issuer DN in the directoryName field of a
    // GeneralName element", so a name spec is wrapped as directoryName rather than passed through
    // encodeGeneralName, where a bare string would resolve to some other GeneralName arm.
    // The encoded Name is kept as well: a caller who names an issuer is asking for THAT issuer's
    // CRL, and pki.cmp.session compares the returned one against it. Taking it from here means the
    // comparison reads the name that went on the wire rather than re-interpreting the spec.
    issuerNameDer = _b.encodeName(spec.issuer);
    source = b.explicit(1, b.sequence([_b.encodeGeneralName({ directoryName: spec.issuer })]));
  }
  // Read ONCE. A caller's thisUpdate can be an accessor, so encoding from one read and validating
  // against a second could judge the answer against a cutoff the request never carried. The instant
  // that went on the wire is returned with the bytes, and it is that value the response is held to.
  var status = [source], askedInstant = null, asked = spec.thisUpdate;
  if (asked != null) {
    askedInstant = guard.time.instantOf(asked, _err, "cmp/bad-input", "crlUpdate.thisUpdate");
    _push(status, b.raw(_b.timeDer(new _Date(askedInstant), "crlUpdate.thisUpdate")));
  }
  return { der: b.sequence([b.sequence(status)]), issuerName: issuerNameDer, thisUpdate: askedInstant };
}

function _encodeRevReqContent(list) {
  if (!Array.isArray(list) || !list.length) throw _err("cmp/bad-rev-req", "rr must be a non-empty array of RevDetails");
  return b.sequence(list.map(_encodeRevDetails));
}

// ---- response-side (CA/responder) PKIBody arm content encoders ----

// CertOrEncCert ::= CHOICE { certificate [0] EXPLICIT CMPCertificate, encryptedCert [1] EXPLICIT EncryptedKey }.
function _encodeCertOrEncCert(coec, state) {
  if (!coec || typeof coec !== "object" || Buffer.isBuffer(coec)) throw _err("cmp/bad-cert-response", "certifiedKeyPair must carry certificate or encryptedCert");
  if (coec.certificate != null && coec.encryptedCert != null) throw _err("cmp/bad-cert-response", "certOrEncCert is a CHOICE: supply exactly one of certificate or encryptedCert, not both");
  if (coec.certificate != null) {
    var certDer = _b.reqDer(coec.certificate, "certifiedKeyPair.certificate (a Certificate DER)");
    try { x509.parse(certDer); } catch (e) { if (e instanceof CmpError) throw e; throw _err("cmp/bad-cert-response", "certifiedKeyPair.certificate is not a valid X.509 certificate", e); }
    return b.explicit(0, b.raw(certDer));   // certificate [0] EXPLICIT
  }
  if (coec.encryptedCert != null) {
    // encryptedCert [1] wraps an EncryptedKey (pre-encoded DER hatch in v1). Like the privateKey, only the
    // EnvelopedData [0] form is cmp2021; the deprecated EncryptedValue (a universal SEQUENCE) is cmp2000.
    var ec = _b.reqDer(coec.encryptedCert, "certifiedKeyPair.encryptedCert (a pre-encoded EncryptedKey DER)");
    var ecNode;
    try { ecNode = asn1.decode(ec); } catch (e) { throw _err("cmp/bad-cert-response", "certifiedKeyPair.encryptedCert is not valid DER", e); }
    if (ecNode.tagClass === "context" && ecNode.tagNumber === 0) state.usesCmp2021 = true;
    return b.explicit(1, b.raw(ec));
  }
  throw _err("cmp/bad-cert-response", "certifiedKeyPair must carry certificate or encryptedCert");
}

// CertifiedKeyPair ::= SEQUENCE { certOrEncCert, privateKey [0] EXPLICIT OPTIONAL, publicationInfo [1] EXPLICIT OPTIONAL }.
function _encodeCertifiedKeyPair(ckp, state) {
  if (!ckp || typeof ckp !== "object" || Buffer.isBuffer(ckp)) throw _err("cmp/bad-cert-response", "certifiedKeyPair must be an object");
  var children = [_encodeCertOrEncCert(ckp, state)];   // certificate / encryptedCert are direct keys (the parse-result shape)
  if (ckp.privateKey != null) {
    var pk = _b.reqDer(ckp.privateKey, "certifiedKeyPair.privateKey (a pre-encoded EncryptedKey DER)");
    children.push(b.explicit(0, b.raw(pk)));
    // EncryptedKey ::= CHOICE { encryptedValue EncryptedValue (a universal SEQUENCE, the deprecated cmp2000
    // form), envelopedData [0] (a cmp2021 feature). Only the envelopedData form bumps pvno to cmp2021(3).
    var pkNode;
    try { pkNode = asn1.decode(pk); } catch (e) { throw _err("cmp/bad-cert-response", "certifiedKeyPair.privateKey is not valid DER", e); }
    if (pkNode.tagClass === "context" && pkNode.tagNumber === 0) state.usesCmp2021 = true;
  }
  if (ckp.publicationInfo != null) children.push(b.explicit(1, b.raw(_b.reqDer(ckp.publicationInfo, "certifiedKeyPair.publicationInfo (a pre-encoded DER)"))));
  return b.sequence(children);
}

// CertResponse ::= SEQUENCE { certReqId INTEGER, status PKIStatusInfo, certifiedKeyPair OPTIONAL, rspInfo OCTET STRING OPTIONAL }.
function _encodeCertResponse(cr, state) {
  if (!cr || typeof cr !== "object" || Buffer.isBuffer(cr)) throw _err("cmp/bad-cert-response", "each CertResponse must be an object");
  if (cr.status == null) throw _err("cmp/bad-cert-response", "CertResponse.status (a PKIStatusInfo) is required");
  var hasCkp = cr.certifiedKeyPair != null;
  // RFC 9810 sec. 5.3.4: failInfo XOR certifiedKeyPair; a certifiedKeyPair is allowed only under a granting
  // status (accepted 0 / grantedWithMods 1).
  if (hasCkp && cr.status.failInfo != null) throw _err("cmp/bad-cert-response", "a CertResponse must not carry both failInfo and certifiedKeyPair");
  if (hasCkp && cr.status.status !== 0 && cr.status.status !== 1) throw _err("cmp/bad-cert-response", "a CertResponse certifiedKeyPair is allowed only under a granting status (accepted / grantedWithMods)");
  var children = [b.integer(_reqIdInt(cr.certReqId, "cmp/bad-cert-response", "CertResponse certReqId")), _encodePkiStatusInfo(cr.status, "cmp/bad-cert-response")];
  if (hasCkp) children.push(_encodeCertifiedKeyPair(cr.certifiedKeyPair, state));
  if (cr.rspInfo != null) children.push(_reqOctets(cr.rspInfo, "CertResponse.rspInfo"));
  return b.sequence(children);
}

// CertRepMessage ::= SEQUENCE { caPubs [1] EXPLICIT SEQUENCE OF CMPCertificate OPTIONAL, response SEQUENCE OF CertResponse }.
function _encodeCertRepMessage(spec, state, arm) {
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("cmp/bad-cert-rep", arm + " must be an object { caPubs?, response }");
  if (!Array.isArray(spec.response)) throw _err("cmp/bad-cert-rep", arm + ".response must be an array of CertResponse");
  if (arm === "ccp" && spec.response.length !== 1) throw _err("cmp/bad-cert-rep", "a ccp CertRepMessage carries exactly one CertResponse (RFC 9810 App. D)");
  var children = [];
  if (spec.caPubs != null) {   // caPubs [1] PRECEDES response (the optional-first x509-version shape)
    if (!Array.isArray(spec.caPubs) || !spec.caPubs.length) throw _err("cmp/bad-cert-rep", arm + ".caPubs must be a non-empty array of certificate DERs");
    children.push(b.explicit(1, b.sequence(spec.caPubs.map(function (c) { return _certRaw(c, "cmp/bad-cert-rep", "a caPubs entry"); }))));
  }
  children.push(b.sequence(spec.response.map(function (cr) { return _encodeCertResponse(cr, state); })));
  return b.sequence(children);
}

// A raw Certificate DER, validated via the real parser before it is embedded.
function _certRaw(c, code, what) {
  var der = _b.reqDer(c, what + " (a Certificate DER)");
  try { x509.parse(der); } catch (e) { if (e instanceof CmpError) throw e; throw _err(code, what + " is not a valid X.509 certificate", e); }
  return b.raw(der);
}

// RevRepContent ::= SEQUENCE { status SEQ OF PKIStatusInfo (min 1), revCerts [0] EXPLICIT SEQ OF CertId OPTIONAL, crls [1] EXPLICIT SEQ OF CertificateList OPTIONAL }.
function _encodeCertIdRr(cid) {
  if (!cid || typeof cid !== "object" || Buffer.isBuffer(cid) || cid.issuer == null || cid.serialNumber == null) throw _err("cmp/bad-rev-rep", "each revCerts CertId must be { issuer, serialNumber }");
  return b.sequence([_b.encodeGeneralName(cid.issuer), b.integer(_reqIdInt(cid.serialNumber, "cmp/bad-rev-rep", "CertId serialNumber"))]);
}
function _encodeRevRepContent(spec) {
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("cmp/bad-rev-rep", "rp must be an object { status, revCerts?, crls? }");
  if (!Array.isArray(spec.status) || !spec.status.length) throw _err("cmp/bad-rev-rep", "rp.status must be a non-empty array of PKIStatusInfo");
  var children = [b.sequence(spec.status.map(function (si) { return _encodePkiStatusInfo(si, "cmp/bad-rev-rep"); }))];
  if (spec.revCerts != null) {
    if (!Array.isArray(spec.revCerts) || !spec.revCerts.length) throw _err("cmp/bad-rev-rep", "rp.revCerts must be a non-empty array of CertId");
    children.push(b.explicit(0, b.sequence(spec.revCerts.map(_encodeCertIdRr))));
  }
  if (spec.crls != null) {
    if (!Array.isArray(spec.crls) || !spec.crls.length) throw _err("cmp/bad-rev-rep", "rp.crls must be a non-empty array of CertificateList DERs");
    children.push(b.explicit(1, b.sequence(spec.crls.map(function (c) {
      var der = _b.reqDer(c, "crls entry (a CertificateList DER)");
      try { crl.parse(der); }   // each crls entry MUST be a valid X.509 CRL (CertificateList)
      catch (e) { if (e instanceof CmpError) throw e; throw _err("cmp/bad-rev-rep", "a crls entry is not a valid CRL (CertificateList)", e); }
      return b.raw(der);
    }))));
  }
  return b.sequence(children);
}

// ErrorMsgContent ::= SEQUENCE { pKIStatusInfo, errorCode INTEGER OPTIONAL, errorDetails PKIFreeText OPTIONAL }.
function _encodeErrorMsgContent(spec) {
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("cmp/bad-error", "error must be an object { pKIStatusInfo, errorCode?, errorDetails? }");
  if (spec.pKIStatusInfo == null) throw _err("cmp/bad-error", "error.pKIStatusInfo is required");
  var children = [_encodePkiStatusInfo(spec.pKIStatusInfo, "cmp/bad-error")];
  if (spec.errorCode != null) children.push(b.integer(_reqIdInt(spec.errorCode, "cmp/bad-error", "error.errorCode")));
  if (spec.errorDetails != null) children.push(_encodePkiFreeText(spec.errorDetails, "cmp/bad-error", "error.errorDetails"));
  return b.sequence(children);
}

// PollRepContent ::= SEQUENCE OF SEQUENCE { certReqId INTEGER, checkAfter INTEGER (seconds, >= 0), reason PKIFreeText OPTIONAL }.
function _encodePollRepContent(list) {
  if (!Array.isArray(list) || !list.length) throw _err("cmp/bad-poll-rep", "pollRep must be a non-empty array of { certReqId, checkAfter, reason? }");
  return b.sequence(list.map(function (pr) {
    if (!pr || typeof pr !== "object" || Buffer.isBuffer(pr)) throw _err("cmp/bad-poll-rep", "each pollRep entry must be an object");
    if (typeof pr.checkAfter !== "number" || !Number.isInteger(pr.checkAfter) || pr.checkAfter < 0 || pr.checkAfter > 0x7fffffff) throw _err("cmp/bad-poll-rep", "pollRep checkAfter must be a non-negative uint31 delay in seconds (RFC 9810 sec. 5.3.22)");
    var kids = [b.integer(_reqIdInt(pr.certReqId, "cmp/bad-poll-rep", "pollRep certReqId")), b.integer(BigInt(pr.checkAfter))];
    if (pr.reason != null) kids.push(_encodePkiFreeText(pr.reason, "cmp/bad-poll-rep", "pollRep reason"));
    return b.sequence(kids);
  }));
}

// KeyRecRepContent ::= SEQUENCE { status PKIStatusInfo, newSigCert [0] EXPLICIT CMPCertificate OPTIONAL, caCerts [1] EXPLICIT SEQ OF CMPCertificate OPTIONAL, keyPairHist [2] EXPLICIT SEQ OF CertifiedKeyPair OPTIONAL }.
function _encodeKeyRecRepContent(spec, state) {
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("cmp/bad-key-rec-rep", "krp must be an object { status, newSigCert?, caCerts?, keyPairHist? }");
  if (spec.status == null) throw _err("cmp/bad-key-rec-rep", "krp.status is required");
  var children = [_encodePkiStatusInfo(spec.status, "cmp/bad-key-rec-rep")];
  if (spec.newSigCert != null) children.push(b.explicit(0, _certRaw(spec.newSigCert, "cmp/bad-key-rec-rep", "krp.newSigCert")));
  if (spec.caCerts != null) {
    if (!Array.isArray(spec.caCerts) || !spec.caCerts.length) throw _err("cmp/bad-key-rec-rep", "krp.caCerts must be a non-empty array of certificate DERs");
    children.push(b.explicit(1, b.sequence(spec.caCerts.map(function (c) { return _certRaw(c, "cmp/bad-key-rec-rep", "a krp.caCerts entry"); }))));
  }
  if (spec.keyPairHist != null) {
    if (!Array.isArray(spec.keyPairHist) || !spec.keyPairHist.length) throw _err("cmp/bad-key-rec-rep", "krp.keyPairHist must be a non-empty array of CertifiedKeyPair");
    children.push(b.explicit(2, b.sequence(spec.keyPairHist.map(function (ckp) { return _encodeCertifiedKeyPair(ckp, state); }))));
  }
  return b.sequence(children);
}

// Does a built CertReqMessages carry a proof of possession that RFC 9810 sec. 5.2.8.3 couples to
// cmp2021(3)? Stated over the RFC's pair rather than over the arms this toolkit happens to emit, so
// the coupling still holds if agreeMAC is built later.
var CMP2021_POP_METHODS = { agreeMAC: 1, encryptedKey: 1 };
function _popNeedsCmp2021(crmfDer) {
  var messages;
  // Re-reading a CertReqMessages this process just produced. A fault here is an internal
  // inconsistency, not a caller error, so it is named in this module's namespace: a crmf/* parse code
  // surfacing from cmp.build would send the operator looking at a request they wrote correctly. A
  // CRMF fault raised while BUILDING that body still passes through untranslated, where it does name
  // the caller's own input.
  try { messages = schemaCrmf.parse(crmfDer).messages; }
  catch (e) {
    throw _err("cmp/bad-body", "the certificate request body this message just built did not parse back: " +
      ((e && e.message) || e), e);
  }
  for (var i = 0; i < messages.length; i++) {
    var popo = messages[i].popo;
    if (popo && popo.method && _hasOwn(CMP2021_POP_METHODS, popo.method)) return true;
  }
  return false;
}

// Dispatch the single-key body object to its EXPLICIT-tagged arm. Returns { bodyTLV, usesCmp2021 }.
function _encodeBody(bodySpec, key, opts) {
  if (!bodySpec || typeof bodySpec !== "object" || Buffer.isBuffer(bodySpec)) throw _err("cmp/bad-input", "message.body must be a single-key object");
  var keys = Object.keys(bodySpec);
  if (keys.length !== 1) throw _err("cmp/bad-input", "message.body must have exactly one arm, got " + keys.length);
  var arm = keys[0];
  if (!KNOWN_BODY_KEYS[arm]) throw _err("cmp/bad-input", "unknown body arm " + JSON.stringify(arm));
  var tag = BODY_TAG[arm], state = { usesCmp2021: false };

  if (CRMF_BODY[arm]) {
    // The CRMF proof of possession is signed with the REQUESTED key's private half, which is distinct from
    // the message-protection key. Take it from a `key` field on the request spec; default to the protection
    // key only for a self-request (the client certifying the very key it protects with).
    var reqSpec = bodySpec[arm], popKey = key;
    if (reqSpec && typeof reqSpec === "object" && !Buffer.isBuffer(reqSpec) && "key" in reqSpec) {
      popKey = reqSpec.key;
      reqSpec = Object.assign({}, reqSpec);
      delete reqSpec.key;
    }
    return crmf.build(reqSpec, popKey, {}).then(function (crmfDer) {
      // RFC 9810 sec. 5.2.8.3: "When using agreeMAC or encryptedKey choices, the pvno cmp2021(3)
      // MUST be used." Read off the message that was actually emitted rather than off the spec that
      // asked for it, so the announced version answers for the bytes on the wire. The parser
      // enforces the same rule on the way in, and before this the two disagreed: a request carrying
      // an encryptedKey proof went out announcing cmp2000(2), and this toolkit's own reader refused
      // the message this toolkit had just built.
      return { bodyTLV: b.explicit(tag, b.raw(crmfDer)), usesCmp2021: _popNeedsCmp2021(crmfDer) };
    });
  }
  var inner;
  if (arm === "p10cr") {
    var csrDer = _b.reqDer(bodySpec.p10cr, "p10cr (a CertificationRequest DER)");
    try { csr.parse(csrDer); }   // validate the embedded PKCS#10 via the real parser (fail-closed on a non-CSR)
    catch (e) { if (e instanceof CmpError) throw e; throw _err("cmp/bad-input", "p10cr is not a valid PKCS#10 CertificationRequest", e); }
    inner = b.raw(csrDer);
  } else if (arm === "certConf") {
    inner = _encodeCertConfirmContent(bodySpec.certConf, state);
  } else if (arm === "pollReq") {
    inner = _encodePollReqContent(bodySpec.pollReq);
  } else if (arm === "genm") {
    inner = _encodeGenMsgContent(bodySpec.genm);
  } else if (arm === "rr") {
    inner = _encodeRevReqContent(bodySpec.rr);
  } else if (CERT_REP_ARM[arm]) {   // ip / cp / kup / ccp -- CertRepMessage
    inner = _encodeCertRepMessage(bodySpec[arm], state, arm);
  } else if (arm === "rp") {
    inner = _encodeRevRepContent(bodySpec.rp);
  } else if (arm === "genp") {   // GenRepContent == GenMsgContent
    inner = _encodeGenMsgContent(bodySpec.genp);
  } else if (arm === "error") {
    inner = _encodeErrorMsgContent(bodySpec.error);
  } else if (arm === "pollRep") {
    inner = _encodePollRepContent(bodySpec.pollRep);
  } else if (arm === "krp") {
    inner = _encodeKeyRecRepContent(bodySpec.krp, state);
  } else {   // pkiconf -- PKIConfirmContent ::= NULL
    if (bodySpec.pkiconf !== null && bodySpec.pkiconf !== true) throw _err("cmp/bad-input", "pkiconf takes null or true (PKIConfirmContent is NULL)");
    inner = b.nullValue();
  }
  return Promise.resolve({ bodyTLV: b.explicit(tag, inner), usesCmp2021: state.usesCmp2021 });
}

// ---- protection ----


// Resolve the protection selector to { protectionAlgDer, computeBits(protectedPartDer)->Promise<Buffer> },
// senderSpki, senderScheme } before the header is built (protectionAlg is opts-derived, not header-derived).
function _resolveProtection(opts) {
  var hasSig = opts.key != null || opts.cert != null;
  var hasMac = opts.mac != null;
  if (hasSig && hasMac) throw _err("cmp/bad-input", "supply exactly one of { key, cert } (signature) or { mac } (PBMAC1), not both");
  if (!hasSig && !hasMac) throw _err("cmp/bad-input", "a PKIMessage requires protection: supply { key, cert } for a signature or { mac } for PBMAC1");

  if (hasSig) {
    if (opts.key == null || opts.cert == null) throw _err("cmp/bad-input", "signature protection requires both opts.key (the private key) and opts.cert (the signer certificate)");
    var certDer = _b.reqDer(opts.cert, "opts.cert (the signer certificate DER)");
    var senderSpki;
    try { senderSpki = x509.parse(certDer).subjectPublicKeyInfo.bytes; }
    catch (e) { throw _err("cmp/bad-input", "opts.cert is not a valid X.509 certificate", e); }
    _b.assertValidSpki(senderSpki, "the sender certificate SPKI");
    var scheme = signScheme.resolveSignScheme(_b.certLikeFromSpki(senderSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);
    return {
      protectionAlgDer: scheme.sigAlgId,
      certDer: certDer,
      computeBits: function (protectedPartDer) {
        return Promise.resolve(signScheme.signOverTbs(scheme, opts.key, protectedPartDer, _signE)).then(function (sig) {
          return Promise.resolve(_b.assertSignatureVerifies(protectedPartDer, sig, senderSpki, scheme)).then(function () {
            return b.bitString(sig, 0);
          });
        });
      },
    };
  }

  // PBMAC1
  var m = opts.mac;
  if (!m || typeof m !== "object" || Buffer.isBuffer(m)) throw _err("cmp/bad-input", "opts.mac must be an object { secret, salt?, iterationCount?, prf?, keyLength? }");
  guard.identifier.assertKnownKeys(m, KNOWN_MAC_KEYS, _err, "cmp/bad-input", "unknown opts.mac field ");
  if (m.algorithm != null && m.algorithm !== "pbmac1") throw _err("cmp/unsupported-algorithm", "opts.mac.algorithm " + JSON.stringify(m.algorithm) + " is not supported (v1 ships pbmac1; passwordBasedMac is deferred)");
  var secret = m.secret;
  if (typeof secret !== "string" || !secret) {
    if (!Buffer.isBuffer(secret) || !secret.length) throw _err("cmp/bad-input", "opts.mac.secret must be a non-empty string or Buffer");
  }
  var secretBuf = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, "utf8");
  var prf = m.prf || "SHA-256";
  if (!PBMAC1_PRF[prf]) throw _err("cmp/bad-input", "opts.mac.prf must be SHA-256 / SHA-384 / SHA-512");
  var iterationCount = m.iterationCount != null ? m.iterationCount : PBMAC1_DEFAULT_ITER;
  if (typeof iterationCount !== "number" || !Number.isInteger(iterationCount) || iterationCount < PBMAC1_MIN_ITER) throw _err("cmp/bad-input", "opts.mac.iterationCount must be at least " + PBMAC1_MIN_ITER + " (RFC 8018 sec. 4.2)");
  // Bound the PBKDF2 work factors before deriving: a huge iterationCount or keyLength is self-inflicted work.
  if (iterationCount > constants.LIMITS.PBKDF2_MAX_ITERATIONS) throw _err("cmp/bad-input", "opts.mac.iterationCount exceeds the PBKDF2 work-factor cap " + constants.LIMITS.PBKDF2_MAX_ITERATIONS);
  var keyLength = m.keyLength != null ? m.keyLength : PBMAC1_DEFAULT_KEYLEN;
  // RFC 9579 sec. 9 floor (>= 20 bytes): produce only messages the verifier (pki.cmp.verify, same floor) can
  // accept, so a shorter derived key is refused at production time and never emitted as an unverifiable message.
  if (typeof keyLength !== "number" || !Number.isInteger(keyLength) || keyLength < PBMAC1_MIN_KEYLEN) throw _err("cmp/bad-input", "opts.mac.keyLength must be an integer >= " + PBMAC1_MIN_KEYLEN + " bytes (RFC 9579 sec. 9)");
  if (keyLength > PBMAC1_MAX_KEYLEN) throw _err("cmp/bad-input", "opts.mac.keyLength exceeds the cap " + PBMAC1_MAX_KEYLEN + " bytes");
  // Bound the COMBINED work: a keyLength spanning multiple PRF blocks costs iterationCount HMACs per block, so
  // the product can exceed the per-block iteration cap. Cap it against the same ceiling pki.cmp.verify enforces,
  // so build never emits a message its verify-inverse would refuse as over-budget (RFC 8018 sec. 5.2).
  var blocks = Math.ceil(keyLength / PBMAC1_PRF_HLEN[prf]);
  if (iterationCount * blocks > constants.LIMITS.PBKDF2_MAX_ITERATIONS) throw _err("cmp/bad-input", "opts.mac combined work (iterationCount " + iterationCount + " x " + blocks + " derived blocks) exceeds the PBKDF2 work-factor cap " + constants.LIMITS.PBKDF2_MAX_ITERATIONS);
  var salt = m.salt != null ? _b.reqDer(m.salt, "opts.mac.salt") : Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(PBMAC1_DEFAULT_SALT_BYTES)));
  // RFC 8018 sec. 4.1 (64-bit) floor: an empty or short salt loses precomputation resistance, so produce only
  // messages pki.cmp.verify (same floor) accepts, refusing a below-minimum salt at construction time.
  if (salt.length < PBMAC1_MIN_SALT) throw _err("cmp/bad-input", "opts.mac.salt must be at least " + PBMAC1_MIN_SALT + " octets (RFC 8018 sec. 4.1)");
  if (salt.length > constants.LIMITS.PBKDF2_MAX_SALT) throw _err("cmp/bad-input", "opts.mac.salt exceeds " + constants.LIMITS.PBKDF2_MAX_SALT + " bytes");
  var macDesc = { salt: salt, iterationCount: iterationCount, keyLength: keyLength, prfName: PBMAC1_PRF[prf], macName: PBMAC1_MAC_OID[prf] };

  return {
    protectionAlgDer: pbes2.pbmac1AlgId(macDesc),
    certDer: null,
    computeBits: function (protectedPartDer) {
      return pbes2.pbmac1(secretBuf, salt, iterationCount, keyLength, prf, prf, protectedPartDer).then(function (mac) {
        return b.bitString(mac, 0);
      });
    },
  };
}

// ---- orchestrator ----

function build(message, opts) {
  // Every caller-owned argument copied at entry and released when the call settles; see the note
  // on the same call in x509-sign. `opts.mac.secret` is why the copy has to be deep: it sits a
  // level below the options object and is read by the PBMAC1 derivation after the first turn.
  return guard.bytes.fixedCall(CmpError, "cmp/bad-input", [
    [message, "the PKIMessage spec"], [opts, "pki.cmp.build options"],
  ], _build);
}

function _build(message, opts) {
  opts = opts || {};
  if (!message || typeof message !== "object" || Buffer.isBuffer(message)) throw _err("cmp/bad-input", "the PKIMessage spec must be an object { header, body }");
  guard.identifier.assertKnownKeys(message, KNOWN_MESSAGE_KEYS, _err, "cmp/bad-input", function (k) {
    return "unknown message field " + JSON.stringify(k) + " (a message carries only header + body)";
  });
  var sigForm = opts.key != null || opts.cert != null, macForm = opts.mac != null;
  guard.identifier.assertKnownKeys(opts,
    sigForm === macForm ? KNOWN_OPTS_KEYS : sigForm ? KNOWN_OPTS_SIG_KEYS : KNOWN_OPTS_MAC_KEYS,
    _err, "cmp/bad-input", function (k) {
      return "unknown opts field " + JSON.stringify(k) +
        (macForm && (k === "pss" || k === "digestAlgorithm")
          ? " for MAC protection; the signature parameters are read only by the { key, cert } form"
          : "");
    });
  if (message.header == null) throw _err("cmp/bad-input", "message.header is required");
  if (message.body == null) throw _err("cmp/bad-input", "message.body is required");

  var prot = _resolveProtection(opts);
  var senderKey = opts.key;

  return Promise.resolve(_encodeBody(message.body, senderKey, opts)).then(function (bodyResult) {
    var bodyTLV = bodyResult.bodyTLV;
    var pvno = message.header.pvno != null ? message.header.pvno : 2;
    if (typeof pvno !== "number" || !Number.isInteger(pvno)) throw _err("cmp/bad-input", "header.pvno must be an integer");
    if (bodyResult.usesCmp2021 && pvno < 3) pvno = 3;   // a certConf hashAlg forces cmp2021(3)

    var headerTLV = _encodeHeader(message.header, prot.protectionAlgDer, pvno);   // built ONCE
    var protectedPartDer = b.sequence([headerTLV, bodyTLV]);   // virtual ProtectedPart ::= SEQUENCE { header, body }

    return prot.computeBits(protectedPartDer).then(function (protectionBits) {
      var msgChildren = [headerTLV, bodyTLV, b.explicit(0, protectionBits)];   // reuse the SAME header/body TLVs
      var extraCertsDers = _collectExtraCerts(opts, prot.certDer);
      if (extraCertsDers.length) msgChildren.push(b.explicit(1, b.sequence(extraCertsDers)));
      var der = b.sequence(msgChildren);

      cmp.parse(der);   // round-trip re-validation: the emitted message MUST parse (protection<=>protectionAlg, pvno, freeText, etc.)
      if (opts.pem != null) {
        if (opts.pem === true) return cmp.pemEncode(der, "CMP");
        if (typeof opts.pem !== "string" || !opts.pem) throw _err("cmp/bad-input", "opts.pem must be true or a non-empty PEM label string");
        return cmp.pemEncode(der, opts.pem);
      }
      return der;
    });
  });
}

function _collectExtraCerts(opts, protCertDer) {
  var out = [];
  if (protCertDer != null) out.push(b.raw(protCertDer));
  if (opts.extraCerts != null) {
    if (!Array.isArray(opts.extraCerts)) throw _err("cmp/bad-extra-certs", "opts.extraCerts must be an array of certificate DERs");
    opts.extraCerts.forEach(function (c) {
      var der = _b.reqDer(c, "extraCerts entry (a Certificate DER)");
      try { x509.parse(der); }   // each extraCerts entry MUST be a valid X.509 certificate (RFC 9810 sec. 5.1)
      catch (e) { if (e instanceof CmpError) throw e; throw _err("cmp/bad-extra-certs", "an extraCerts entry is not a valid X.509 certificate", e); }
      out.push(b.raw(der));
    });
  }
  return out;
}

/**
 * @primitive  pki.cmp.build
 * @signature  pki.cmp.build(message, opts?) -> Promise<Buffer|string>
 * @since      0.3.5
 * @status     stable
 * @spec       RFC 9810, RFC 9481, RFC 9579
 * @related    pki.schema.cmp.parse
 *
 * Build an RFC 9810 CMP `PKIMessage` -- the producing-side inverse of `pki.schema.cmp.parse`. `message` is
 * `{ header, body }`: `header` carries the `sender` / `recipient` GeneralNames plus optional transaction
 * metadata (`transactionID`, `senderNonce`, `messageTime`, `freeText`, `generalInfo`, ...); `body` is a
 * single-key object naming the arm. Request-side: `{ ir }` / `{ cr }` / `{ kur }` (a `CertReqMessages` spec
 * delegated to `pki.crmf.build`; the proof-of-possession key is `key` on the arm spec), `{ p10cr }` (a PKCS#10
 * CertificationRequest DER), `{ certConf }`, `{ pollReq }`, `{ genm }`, `{ rr }`. CA/responder-side: `{ ip }` /
 * `{ cp }` / `{ kup }` / `{ ccp }` (a `CertRepMessage`: `caPubs` plus `response` of `CertResponse` each with a
 * `PKIStatusInfo` and, under a granting status, a `certifiedKeyPair`), `{ rp }` (`RevRepContent`), `{ genp }`,
 * `{ error }` (`ErrorMsgContent`), `{ pollRep }`, `{ krp }` (`KeyRecRepContent`), `{ pkiconf }` (NULL). The
 * message is protected: `opts` carries exactly
 * one of `{ key, cert }` (a signature under the sender key over the message, using any registry algorithm: RSA
 * / ECDSA / EdDSA / ML-DSA / SLH-DSA / composite, resolved from the certificate) or `{ mac }` (a PBMAC1
 * shared-secret MAC). The protection is computed over the exact DER of the virtual
 * `ProtectedPart ::= SEQUENCE { header, body }` and self-verified before the message is returned. The
 * emitted PKIMessage round-trips byte-identically through `pki.schema.cmp.parse`.
 *
 * @opts
 *   - `key` (Buffer|CryptoKey) + `cert` (Buffer): signature protection under the sender key; `cert` is
 *     the signer certificate (its SPKI resolves the algorithm) and is placed in `extraCerts`.
 *   - `mac` ({ secret, salt?, iterationCount?, prf?, keyLength? }): PBMAC1 protection from a shared secret.
 *   - `extraCerts` (array of Buffer): additional certificates to carry in `extraCerts [1]`.
 *   - `pem` (boolean|string): return a PEM `CMP` block instead of DER.
 *   - `pss` (boolean) / `digestAlgorithm` (string): signature-protection algorithm options.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "client", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var csrDer = await pki.csr.sign({ subject: "client", subjectPublicKey: await pki.key.export(pair.publicKey) },
 *     { key: signerKeyPkcs8 });
 *   var der = await pki.cmp.build(
 *     { header: { sender: { directoryName: "CN=client" }, recipient: { directoryName: "CN=CA" } },
 *       body: { p10cr: csrDer } },
 *     { key: signerKeyPkcs8, cert: signerCertDer });
 *   pki.schema.cmp.parse(der).body.arm;   // "p10cr"
 */

// ---- the thin RFC 9811 HTTP transfer verb: POST a DER PKIMessage over the shared pki.transport ----
//
// RFC 9811 defines exactly ONE client operation -- POST a DER PKIMessage, receive a DER PKIMessage -- so
// every CMP exchange (ir / p10cr / certConf / pollReq / rr / genm ...) rides this single stateless verb;
// the caller builds+protects the message upstream with pki.cmp.build and hands the finished bytes here,
// which are POSTed VERBATIM (the protection covers them). No socket is opened by this codec -- the verb
// composes pki.schema.cmp.parse over pki.transport, exactly as pki.est / pki.acme wire their message layers.

var DEFAULT_TRANSFER_TIMEOUT = constants.TIME.seconds(30);
var MAX_TRANSFER_TIMEOUT = constants.TIME.seconds(600);
var PKIXCMP = "application/pkixcmp";
var PKIXCMP_POLL = "application/pkixcmp-poll";   // the legacy type handled "like application/pkixcmp" (RFC 9811 sec. 4)
var KNOWN_TRANSFER_OPTS = { transport: 1, tls: 1, headers: 1, timeout: 1, maxResponseBytes: 1 };

// The DER of a caller-supplied PKIMessage: a DER Buffer / Uint8Array re-viewed through guard.bytes.view
// (sent VERBATIM -- protection covers these exact bytes), a PEM "CMP" string decoded, else a config-time
// cmp/bad-input before the wire. The re-view fails a DETACHED backing buffer (a transferred / structuredClone'd
// view reads as zero-length) as cmp/bad-input rather than silently POSTing an empty body in its place.
function _cmpMessageDer(input) {
  var der;
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) der = guard.bytes.view(input, CmpError, "cmp/bad-input", "the CMP message DER");
  else if (typeof input === "string") {
    // Normalize a PEM decode failure (no block, wrong armor label, malformed base64) to the stable
    // cmp/bad-input at this input boundary, rather than leaking the PEM layer's PemError to the caller.
    try { der = cmp.pemDecode(input); }
    catch (e) { throw _err("cmp/bad-input", "the CMP message is not a valid PEM CMP block", e); }
  } else throw _err("cmp/bad-input", "a CMP message must be a DER Buffer/Uint8Array or a PEM CMP string");
  // Validate the bytes ARE a PKIMessage before the wire (transfer accepts a DER PKIMessage), so malformed
  // input fails locally as cmp/bad-input rather than crossing the network seam. parse validates only -- the
  // ORIGINAL der is returned for the verbatim POST (protection covers the exact bytes; nothing re-serialized).
  try { cmp.parse(der); }
  catch (e) { throw _err("cmp/bad-input", "the CMP message is not a valid PKIMessage", e); }
  return der;
}

// Map opts.tls (operator-facing) to the transport request.tls shape. rejectUnauthorized is NOT here --
// the transport forces it on unconditionally; the verb never disables server verification.
function _tlsForTransfer(opts) {
  var t = opts.tls || {};
  return { anchors: t.anchors, useSystemStore: t.useSystemStore, cert: t.cert, key: t.key, minVersion: t.minVersion, servername: t.servername, checkServerIdentity: t.checkServerIdentity };
}

// The response content-type token (before any ;-parameters), lowercased; is it a CMP media type?
function _ctypeToken(headers) { return String((headers || {})["content-type"] || "").split(";")[0].trim().toLowerCase(); }
function _isPkixcmp(headers) { var t = _ctypeToken(headers); return t === PKIXCMP || t === PKIXCMP_POLL; }

// Classify the CMP HTTP response (RFC 9811 sec. 3.1/3.2/4). 200 + a pkixcmp body -> parse + resolve;
// another 2xx -> reject (a request response MUST be 200, sec. 3.1); 3xx -> not followed (sec. 3.1/5);
// 4xx/5xx WITH a well-formed CMP body -> FORWARD the integrity-protected verdict (sec. 1.2/3.1), else
// cmp/http-error. The HTTP status is surfaced as DATA, never used to set the transaction verdict (sec. 5).
// `body` is always a Buffer (the verb normalizes it before the size cap).
function _classifyCmpResponse(status, headers, body, tls) {
  var ctype = _ctypeToken(headers);
  if (status === 200) {
    if (!_isPkixcmp(headers)) throw _err("cmp/bad-content-type", "a 200 CMP response must be application/pkixcmp (RFC 9811 sec. 3.2), got " + JSON.stringify(ctype || null));
    if (body.length === 0) throw _err("cmp/empty-response", "a 200 CMP response carried an empty body (RFC 9811 sec. 3.3)");
    return { response: cmp.parse(body), responseBytes: body, status: 200, contentType: ctype, tls: tls };   // a malformed body surfaces the parser's fail-closed cmp/* verdict
  }
  // Below 200, every branch requires a valid HTTP status INTEGER -- a missing / non-numeric / out-of-range
  // status from an injected transport must not fall through to the forward branch as if it were a 4xx/5xx.
  var httpStatus = (typeof status === "number" && Number.isSafeInteger(status) && status >= 100 && status <= 599) ? status : null;
  if (httpStatus !== null && httpStatus >= 300 && httpStatus < 400) throw _err("cmp/redirect-not-followed", "a CMP " + httpStatus + " redirect is not followed (RFC 9811 sec. 3.1, sec. 5); reconfigure the endpoint URL");
  if (httpStatus !== null && httpStatus >= 400 && httpStatus <= 599) {
    if (_isPkixcmp(headers) && body.length > 0) {
      var forwarded;
      try { forwarded = cmp.parse(body); }
      catch (e) { throw _err("cmp/http-error", "the CMP server returned HTTP " + httpStatus + " with an undecodable body", e); }
      // Only a CMP `error` message is a coherent verdict to forward on an HTTP failure. A 4xx/5xx carrying a
      // non-error arm (a granting `ip`, a `pkiconf`) is contradictory -- the HTTP layer says failure while the
      // CMP body says success -- so it is NOT accepted as a usable response; the HTTP failure stands.
      if (forwarded.body.arm !== "error") throw _err("cmp/http-error", "the CMP server returned HTTP " + httpStatus + " with a non-error '" + forwarded.body.arm + "' body; an HTTP failure forwards only a CMP error message (RFC 9811 sec. 1.2/3.1)");
      return { response: forwarded, responseBytes: body, status: httpStatus, contentType: ctype, tls: tls };
    }
    throw _err("cmp/http-error", "the CMP server returned HTTP " + httpStatus + " with no forwardable CMP error body");
  }
  // Any other status -- a non-200 2xx, a 1xx informational, or a non-numeric / out-of-range value.
  throw _err("cmp/unexpected-status", "a CMP response must be HTTP 200 (or a 4xx/5xx carrying a CMP error), not " + JSON.stringify(status) + " (RFC 9811 sec. 3.1)");
}

function transfer(url, message, opts) {
  return guard.async.deferred(function () { return _transfer(url, message, opts); });
}

function _transfer(url, message, opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, KNOWN_TRANSFER_OPTS, _err, "cmp/bad-input", "unknown opts field ");
  var der = _cmpMessageDer(message);   // config gate: before any transport call
  var parsedUrl;
  try { parsedUrl = new URL(String(url)); }   // parse only -- NO client scheme gate (the transport owns socket security)
  catch (e) { throw _err("cmp/bad-url", "the CMP URL did not parse: " + String(url), e); }
  var transport = opts.transport;
  if (!transport) {
    var t = opts.tls || {};
    var hasAnchors = t.anchors !== undefined && t.anchors !== null && !(Array.isArray(t.anchors) && t.anchors.length === 0);
    if (!hasAnchors && t.useSystemStore !== true) throw _err("cmp/no-trust-anchors", "no explicit trust anchor and tls.useSystemStore not set to true -- refusing an unpinned server (RFC 9811 sec. 5)");
    transport = httpTransport.https({ E: _err, errPrefix: "cmp" });
  }
  var timeout = guard.limits.cap(opts.timeout, "timeout", DEFAULT_TRANSFER_TIMEOUT, { E: _err, code: "cmp/bad-input", min: 1, max: MAX_TRANSFER_TIMEOUT });
  var maxResponseBytes = guard.limits.cap(opts.maxResponseBytes, "maxResponseBytes", constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, { E: _err, code: "cmp/bad-input", min: 1, max: constants.LIMITS.HTTP_MAX_RESPONSE_BYTES });
  // Build the request headers: forward custom opts.headers but STRIP the request-framing headers
  // (content-length, transfer-encoding) and ANY content-type case variant -- the verb sets the content-type
  // and the transport computes Content-Length from the exact body, so a caller cannot desync the request
  // framing (HTTP request smuggling via a short/long content-length) or override the media type through
  // header-name casing (a "Content-Type" that Object.assign would keep alongside the lowercase one).
  var headers = {};
  Object.keys(opts.headers || {}).forEach(function (k) {
    var lk = k.toLowerCase();
    if (lk !== "content-length" && lk !== "transfer-encoding" && lk !== "content-type") headers[k] = opts.headers[k];
  });
  headers["content-type"] = PKIXCMP;
  var tls = _tlsForTransfer(opts);
  return Promise.resolve(transport({ method: "POST", url: parsedUrl.href, headers: headers, body: der, tls: tls, timeout: timeout, maxResponseBytes: maxResponseBytes })).then(function (res) {
    res = res || {};
    var h = {};
    Object.keys(res.headers || {}).forEach(function (k) { h[k.toLowerCase()] = res.headers[k]; });
    // Normalize the response body to a Buffer preserving its exact bytes: a binary view (Buffer / Uint8Array
    // from an injected transport) is re-viewed through the byte guard, as the request path does; only a
    // genuine string body falls back to a UTF-8 encode (the width a real socket already counts) so the size
    // cap and the parser see the same bytes -- a typed array is not stringified to "48,130,..." garbage.
    var body = (Buffer.isBuffer(res.body) || res.body instanceof Uint8Array)
      ? guard.bytes.view(res.body, CmpError, "cmp/bad-response", "the CMP response body")
      : Buffer.from(String(res.body == null ? "" : res.body), "utf8");
    if (body.length > maxResponseBytes) throw _err("cmp/response-too-large", "the response body (" + body.length + " bytes) exceeds the " + maxResponseBytes + "-byte cap");
    return _classifyCmpResponse(res.status, h, body, res.tls || null);
  });
}

// A single safe path segment for a well-known URI: no separator, dot-segment, or reserved/space char that
// would retarget the resource; percent-encoded on the way out. Fails closed (guards never guess a value).
function _wellKnownSeg(v, name) {
  var s = String(v);
  if (s === "" || s === "." || s === ".." || /[/?#\s\\]/.test(s)) throw _err("cmp/bad-url", "the CMP " + name + " must be a single safe path segment (no '/', dot-segment, or reserved char): " + JSON.stringify(s));
  // encodeURIComponent throws a raw URIError (no .code) on an unpaired UTF-16 surrogate; normalize it to the
  // helper's cmp/bad-url contract so a malformed-config segment never escapes as an untyped error.
  try { return encodeURIComponent(s); }
  catch (e) { throw _err("cmp/bad-url", "the CMP " + name + " is not encodable (e.g. an unpaired surrogate): " + JSON.stringify(s), e); }
}

var KNOWN_WELLKNOWN_OPTS = { label: 1, operation: 1 };

function wellKnownUrl(base, opts) {
  opts = opts || {};
  // Reject an unknown option key (a typo like { lable } / { operaton }), as build/transfer do -- a silently
  // ignored option would build the DEFAULT endpoint and send the request to a different CA/profile.
  guard.identifier.assertKnownKeys(opts, KNOWN_WELLKNOWN_OPTS, _err, "cmp/bad-input", function (k) {
    return "unknown wellKnownUrl option " + JSON.stringify(k) + " (expected label / operation)";
  });
  var u;
  try { u = new URL(String(base)); }
  catch (e) { throw _err("cmp/bad-url", "the CMP base URL did not parse: " + String(base), e); }
  // Require an http(s) authority: a non-HTTP scheme (file:, data:, a custom scheme) has an opaque origin
  // ("null"), which would build a nonsensical "null/.well-known/cmp". A well-known URI is an HTTP concept
  // (RFC 8615); https vs http is left to the transport (Build decision 6), but the scheme must be one of them.
  if (u.protocol !== "https:" && u.protocol !== "http:") throw _err("cmp/bad-url", "the CMP base URL must be http or https (a well-known URI is authority-rooted over HTTP), got " + u.protocol + ": " + JSON.stringify(String(base)));
  if (u.search || u.hash) throw _err("cmp/bad-url", "the CMP base URL must not carry a query or fragment component (RFC 9811 sec. 3.4)");
  // A backslash has no place in an http(s) authority: WHATWG rewrites it to a path separator (so
  // `https://ca.example\tenant` is really the path `/tenant`), but the raw-path regex below excludes only
  // `/?#` and would swallow it as authority, slipping a supplied path past the check. Reject it outright.
  if (/\\/.test(String(base))) throw _err("cmp/bad-url", "the CMP base URL must not contain a backslash (WHATWG rewrites it to a path separator): " + JSON.stringify(String(base)));
  // An RFC 8615 well-known URI is AUTHORITY-ROOTED (/.well-known/...), so a base carrying ANY path is
  // rejected fail-closed -- an operator whose CMP endpoint sits under a path passes that full operation URL
  // to transfer() directly. Inspect the RAW path in the source string, NOT url.pathname: WHATWG normalizes
  // dot-segments (`/tenant/..`, `/%2e`) to "/" before the parse, which would slip a supplied path past a
  // pathname check and silently target the authority-root profile instead of reporting the misconfiguration.
  var rawBasePath = String(base).replace(/^[a-z]+:\/\/[^/?#]*/i, "").split(/[?#]/)[0];
  if (rawBasePath !== "" && rawBasePath !== "/") throw _err("cmp/bad-url", "an RFC 8615 well-known URI is authority-rooted; the CMP base URL must have no path component (pass a full operation URL to transfer instead): " + JSON.stringify(String(base)));
  var segs = [".well-known", "cmp"];
  if (opts.label != null) { segs.push("p"); segs.push(_wellKnownSeg(opts.label, "label")); }
  if (opts.operation != null) segs.push(_wellKnownSeg(opts.operation, "operation"));
  return u.origin + "/" + segs.join("/");
}

/**
 * @primitive  pki.cmp.transfer
 * @signature  pki.cmp.transfer(url, message, opts?) -> Promise<{ response, responseBytes, status, contentType, tls }>
 * @since      0.3.19
 * @status     experimental
 * @spec       RFC 9811, RFC 9810
 * @related    pki.cmp.build, pki.cmp.wellKnownUrl, pki.schema.cmp.parse, pki.transport.https
 *
 * POST a DER `PKIMessage` to a CMP endpoint and return the parsed response `PKIMessage`, over the shared
 * `pki.transport`. RFC 9811 transfers every CMP exchange identically, as one HTTP POST of a DER PKIMessage
 * and one response PKIMessage, so a single stateless verb carries `ir` / `cr` / `kur` / `p10cr` / `certConf`
 * / `pollReq` / `rr` / `genm` and their responses; the caller builds and protects the message upstream with
 * `pki.cmp.build` and hands the finished bytes here. `message` is a DER `Buffer`/`Uint8Array` or a PEM `CMP`
 * string, sent verbatim (the message-layer protection covers these exact bytes; they are never re-encoded).
 * The response is classified fail-closed: HTTP 200 carrying an `application/pkixcmp` body is parsed and
 * resolved; another 2xx is `cmp/unexpected-status` (RFC 9811 requires 200); a 3xx is `cmp/redirect-not-followed`
 * (never auto-followed, sec. 3.1/5); a 4xx/5xx carrying a well-formed CMP `error` PKIMessage FORWARDS that
 * integrity-protected verdict (sec. 1.2/3.1) with the HTTP status surfaced as data, while a 4xx/5xx that is
 * not a CMP `error` message (no body, an undecodable body, or a non-error arm) is `cmp/http-error`.
 * Protection is surfaced, not verified: the client confers no trust, and the
 * caller (or a future `pki.cmp.verify`) checks the response protection using the raw `headerBytes`/`bodyBytes`.
 * By default the transport is https-only and requires an explicit trust anchor; there is no client scheme
 * gate, so an operator who injects an http-capable transport reaches the RFC-9811-permitted plain-HTTP path.
 *
 * @opts
 *   - `transport` -- an injectable `transport(request) -> Promise<{status,headers,body}>` (default
 *     `pki.transport.https`, which fail-closes on a non-https URL and an unpinned server).
 *   - `tls` -- `{ anchors, useSystemStore, cert, key, minVersion, servername, checkServerIdentity }` for the
 *     default transport (mutual-TLS `cert`/`key` is common for CMP in addition to message protection).
 *   - `headers` -- extra request headers. The `content-type: application/pkixcmp` is always set and not
 *     overridable (any casing), and the request-framing headers (`content-length`, `transfer-encoding`) are
 *     stripped -- the transport computes Content-Length from the exact body, so a caller cannot desync framing.
 *   - `timeout` -- ms (default 30s); `maxResponseBytes` -- streaming cap, tightenable downward only.
 * @example
 *   var reqDer = await pki.cmp.build(
 *     { header: { sender: { directoryName: "CN=client" }, recipient: { directoryName: "CN=CA" } },
 *       body: { p10cr: csrDer } },
 *     { key: signerKeyPkcs8, cert: signerCertDer });
 *   var url = pki.cmp.wellKnownUrl("https://ca.example", { operation: "p10cr" });
 *   var res = await pki.cmp.transfer(url, reqDer, { transport: transport });
 *   res.response.body.arm;   // "ip" | "cp" | "error"
 */

/**
 * @primitive  pki.cmp.wellKnownUrl
 * @signature  pki.cmp.wellKnownUrl(base, opts?) -> string
 * @since      0.3.19
 * @status     experimental
 * @spec       RFC 9811, RFC 8615
 * @related    pki.cmp.transfer
 *
 * Build an RFC 9811 sec. 3.4 CMP request-URI under the `/.well-known/cmp` prefix (RFC 8615). The four forms:
 * `<base>/.well-known/cmp`, `.../<operation>`, `.../p/<label>`, and `.../p/<label>/<operation>`. A pure string
 * builder over an authority-rooted well-known path (RFC 8615) -- https vs http is left to the transport (both
 * forms are accepted, RFC 9811 sec. 3.4), but the `base` MUST be an http(s) URL. It rejects (`cmp/bad-url`) an
 * unparseable `base`, a non-http(s) scheme (`file:`/`data:`/a custom scheme has an opaque origin), a `base`
 * carrying a path / query / fragment (a well-known URI is authority-rooted; a path would capture it), and a
 * `label`/`operation` that is empty, a dot-segment, or contains a `/` or other reserved char (never silently
 * retarget the resource). The `operation` label is a caller-supplied string, not validated against a profile
 * vocabulary (RFC 9483 is out of scope).
 *
 * @opts
 *   - `label` -- an optional CA/RA name inserted as `.../p/<label>` (a single percent-encoded path segment).
 *   - `operation` -- an optional operation label appended as the final path segment.
 * @example
 *   pki.cmp.wellKnownUrl("https://ca.example");                          // "https://ca.example/.well-known/cmp"
 *   pki.cmp.wellKnownUrl("https://ca.example", { label: "myca", operation: "cr" });
 *   //                                                                   // ".../.well-known/cmp/p/myca/cr"
 */
module.exports = {
  build: build, transfer: transfer, wellKnownUrl: wellKnownUrl,
  buildCrlStatusList: buildCrlStatusList,   // @internal -- pki.cmp.session composes it for a crlUpdate support message
  // @internal -- one key, several legal SPKI encodings (a compressed EC point among them), so the
  // session compares root-rollover keys through the same definition the builders already use.
  samePublicKey: function (a, b) { return _b.samePublicKey(a, b); },
};
