// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.cmp
 * @nav        Signing
 * @title      Certificate management protocol messages
 * @intro The RFC 9810 Certificate Management Protocol producing side. `pki.cmp.build` assembles a
 *   `PKIMessage` -- a `PKIHeader` (sender / recipient / transaction metadata), a `PKIBody` carrying one
 *   request or transaction (an `ir` / `cr` / `kur` certificate request via `pki.crmf.build`, a `p10cr`
 *   PKCS#10 via `pki.csr.sign`, or a `certConf` / `pollReq` / `genm` / `rr`), and an optional
 *   `PKIProtection` computed over the message. Protection is a signature under the sender key (any
 *   registry algorithm) or a PBMAC1 shared-secret MAC. The emitted message round-trips through
 *   `pki.schema.cmp.parse` and its protection verifies. Parsing lives at `pki.schema.cmp.parse`.
 * @spec RFC 9810
 * @card Build a CMP PKIMessage with signature or PBMAC1 protection.
 */
//
// RFC 9810 Appendix A is DEFINITIONS EXPLICIT TAGS: every context tag in the PKIMessage envelope --
// each PKIHeader [0..8] optional, every PKIBody [n] arm, protection [0], extraCerts [1] -- is an EXPLICIT
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
var csr = require("./schema-csr");
var crl = require("./schema-crl");
var x509 = require("./schema-x509");
var signScheme = require("./sign-scheme");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var webcrypto = require("./webcrypto");
var constants = require("./constants");
var guard = require("./guard-all");
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
// The PKIBody arm -> its EXPLICIT context tag number (schema-cmp.js BODY_ARMS). rr is [11], NOT [15].
var BODY_TAG = {
  ir: 0, cr: 2, p10cr: 4, kur: 7, rr: 11, genm: 21, certConf: 24, pollReq: 25,
  ip: 1, cp: 3, kup: 8, krp: 10, rp: 12, ccp: 14, pkiconf: 19, genp: 22, error: 23, pollRep: 26,
};
var CRMF_BODY = { ir: 1, cr: 1, kur: 1 };   // arms whose content is a CertReqMessages via pki.crmf.build
var CERT_REP_ARM = { ip: 1, cp: 1, kup: 1, ccp: 1 };   // arms carrying a CertRepMessage
var KNOWN_OPTS_KEYS = { key: 1, cert: 1, mac: 1, extraCerts: 1, pem: 1, pss: 1, digestAlgorithm: 1 };
var KNOWN_MAC_KEYS = { secret: 1, salt: 1, iterationCount: 1, prf: 1, keyLength: 1, algorithm: 1 };

var PBMAC1_DEFAULT_ITER = 100000;
var PBMAC1_DEFAULT_SALT_BYTES = 16;
var PBMAC1_DEFAULT_KEYLEN = 32;   // bytes -- HMAC-SHA256 key
var PBMAC1_MAX_KEYLEN = 1024;     // bytes -- an HMAC key beyond a hash block is pointless; bound the work
var PBMAC1_MIN_ITER = 1000;       // RFC 8018 sec. 4.2 recommended minimum -- reject a trivially weak count
var PBMAC1_PRF = { "SHA-256": "hmacWithSHA256", "SHA-384": "hmacWithSHA384", "SHA-512": "hmacWithSHA512" };
var PBMAC1_MAC_OID = { "SHA-256": "hmacWithSHA256", "SHA-384": "hmacWithSHA384", "SHA-512": "hmacWithSHA512" };
// PKIFailureInfo named bits (RFC 9810 sec. 5.2.3), position = bit index -- mirrors schema-cmp's decode list;
// the build -> parse round-trip cross-checks the positions against the parser.
var FAIL_INFO_NAMES = ["badAlg", "badMessageCheck", "badRequest", "badTime", "badCertId", "badDataFormat",
  "wrongAuthority", "incorrectData", "missingTimeStamp", "badPOP", "certRevoked", "certConfirmed",
  "wrongIntegrity", "badRecipientNonce", "timeNotAvailable", "unacceptedPolicy", "unacceptedExtension",
  "addInfoNotAvailable", "badSenderNonce", "badCertTemplate", "signerNotTrusted", "transactionIdInUse",
  "unsupportedVersion", "notAuthorized", "systemUnavail", "systemFailure", "duplicateCertReq"];
var FAIL_INFO_INDEX = {};
FAIL_INFO_NAMES.forEach(function (n, i) { FAIL_INFO_INDEX[n] = i; });
// CertStatus.hashAlg names the hash used to compute certHash -- restrict it to hash algorithms, not any OID.
var CERT_CONF_HASH_ALGS = { sha1: 1, sha256: 1, sha384: 1, sha512: 1, "sha3-256": 1, "sha3-512": 1 };

// ---- small shared encoders (byte-exact inverses of schema-cmp.js readers) ----

function _reqOctets(v, what) {
  var buf = _b.reqDer(v, what);
  return b.octetString(buf);
}

// PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String -- non-empty, every element UTF8String.
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
// An HMAC AlgorithmIdentifier carries NULL parameters (RFC 8018 App. B.1.1 / RFC 4231), unlike a bare SHA-2
// digest algId (ABSENT parameters, RFC 5754 sec. 2). Used for the PBMAC1 prf + messageAuthScheme.
function _hmacAlgId(name) { return b.sequence([b.oid(O(name)), b.nullValue()]); }

// PKIHeader ::= SEQUENCE { pvno INTEGER, sender GeneralName, recipient GeneralName, EXPLICIT [0..8] }.
// protectionAlgDer is the DERIVED AlgorithmIdentifier ([1]), present iff the message is protected. Returns
// the exact headerTLV, built ONCE and reused in both the envelope and the ProtectedPart (RFC 9810 5.1.3).
function _encodeHeader(headerSpec, protectionAlgDer, pvno) {
  if (!headerSpec || typeof headerSpec !== "object" || Buffer.isBuffer(headerSpec)) throw _err("cmp/bad-input", "message.header must be an object");
  Object.keys(headerSpec).forEach(function (k) { if (!KNOWN_HEADER_KEYS[k]) throw _err("cmp/bad-input", "unknown header field " + JSON.stringify(k)); });
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
function _reqIdInt(v, code, what) {
  if (typeof v === "bigint") return v;
  // Number.isSafeInteger (not isInteger): a value above 2^53 is imprecise as a Number, so it MUST be a bigint.
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  throw _err(code, what + " must be an integer (a safe-integer number, or a bigint for a large value)");
}

// PKIFailureInfo ::= BIT STRING (named bits, RFC 9810 sec. 5.2.3) -- a minimal NamedBitList from bit names.
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
  if (rd.crlEntryDetails != null) children.push(b.raw(_b.reqDer(rd.crlEntryDetails, "RevDetails.crlEntryDetails (a pre-encoded Extensions DER)")));
  return b.sequence(children);
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
    // EnvelopedData [0] form is cmp2021 -- the deprecated EncryptedValue (a universal SEQUENCE) is cmp2000.
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
      return { bodyTLV: b.explicit(tag, b.raw(crmfDer)), usesCmp2021: false };
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

// PBMAC1 protectionAlg: id-PBMAC1 with PBMAC1-params { keyDerivationFunc PBKDF2{salt,iter,keyLength,prf},
// messageAuthScheme HMAC } -- the byte-exact inverse of schema-pkcs12.js PBMAC1_PARAMS / PBKDF2_PARAMS.
function _encodePbmac1AlgId(pd) {
  var pbkdf2Params = [b.octetString(pd.salt), b.integer(BigInt(pd.iterationCount)), b.integer(BigInt(pd.keyLength))];
  // prf: omit iff the DEFAULT algid-hmacWithSHA1; else the prf AlgorithmIdentifier with ABSENT params.
  // nosemgrep: pki-non-constant-time-secret-compare -- prfName is a PRF algorithm name, not a secret
  if (pd.prfName !== "hmacWithSHA1") pbkdf2Params.push(_hmacAlgId(pd.prfName));
  var pbkdf2AlgId = b.sequence([b.oid(O("pbkdf2")), b.sequence(pbkdf2Params)]);
  var pbmac1Params = b.sequence([pbkdf2AlgId, _hmacAlgId(pd.macName)]);
  return b.sequence([b.oid(O("pbmac1")), pbmac1Params]);
}

// Resolve the protection selector to { protectionAlgDer, computeBits(protectedPartDer)->Promise<Buffer> },
// senderSpki, senderScheme } BEFORE the header is built (protectionAlg is opts-derived, not header-derived).
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
  Object.keys(m).forEach(function (k) { if (!KNOWN_MAC_KEYS[k]) throw _err("cmp/bad-input", "unknown opts.mac field " + JSON.stringify(k)); });
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
  // Bound the PBKDF2 work factors BEFORE deriving -- a huge iterationCount / keyLength is self-inflicted work.
  if (iterationCount > constants.LIMITS.PBKDF2_MAX_ITERATIONS) throw _err("cmp/bad-input", "opts.mac.iterationCount exceeds the PBKDF2 work-factor cap " + constants.LIMITS.PBKDF2_MAX_ITERATIONS);
  var keyLength = m.keyLength != null ? m.keyLength : PBMAC1_DEFAULT_KEYLEN;
  if (typeof keyLength !== "number" || !Number.isInteger(keyLength) || keyLength < 1) throw _err("cmp/bad-input", "opts.mac.keyLength must be a positive integer (bytes)");
  if (keyLength > PBMAC1_MAX_KEYLEN) throw _err("cmp/bad-input", "opts.mac.keyLength exceeds the cap " + PBMAC1_MAX_KEYLEN + " bytes");
  var salt = m.salt != null ? _b.reqDer(m.salt, "opts.mac.salt") : Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(PBMAC1_DEFAULT_SALT_BYTES)));
  if (salt.length > constants.LIMITS.PBKDF2_MAX_SALT) throw _err("cmp/bad-input", "opts.mac.salt exceeds " + constants.LIMITS.PBKDF2_MAX_SALT + " bytes");
  var macDesc = { salt: salt, iterationCount: iterationCount, keyLength: keyLength, prfName: PBMAC1_PRF[prf], macName: PBMAC1_MAC_OID[prf] };

  return {
    protectionAlgDer: _encodePbmac1AlgId(macDesc),
    certDer: null,
    computeBits: function (protectedPartDer) {
      return _pbmac1(secretBuf, salt, iterationCount, keyLength, prf, protectedPartDer).then(function (mac) {
        return b.bitString(mac, 0);
      });
    },
  };
}

// PBKDF2-derive an HMAC key from the shared secret, then HMAC the ProtectedPart (both via the engine).
function _pbmac1(secretBuf, salt, iterationCount, keyLength, prf, message) {
  var subtle = webcrypto.webcrypto.subtle;
  return subtle.importKey("raw", secretBuf, { name: "PBKDF2" }, false, ["deriveBits"]).then(function (baseKey) {
    return subtle.deriveBits({ name: "PBKDF2", salt: salt, iterations: iterationCount, hash: prf }, baseKey, keyLength * 8);
  }).then(function (bits) {
    return subtle.importKey("raw", Buffer.from(bits), { name: "HMAC", hash: prf }, false, ["sign"]).then(function (hmacKey) {
      return subtle.sign({ name: "HMAC" }, hmacKey, message);
    });
  }).then(function (sig) { return Buffer.from(sig); });
}

// ---- orchestrator ----

function build(message, opts) {
  return Promise.resolve().then(function () { return _build(message, opts); });
}

function _build(message, opts) {
  opts = opts || {};
  if (!message || typeof message !== "object" || Buffer.isBuffer(message)) throw _err("cmp/bad-input", "the PKIMessage spec must be an object { header, body }");
  Object.keys(message).forEach(function (k) { if (k !== "header" && k !== "body") throw _err("cmp/bad-input", "unknown message field " + JSON.stringify(k) + " (a message carries only header + body)"); });
  Object.keys(opts).forEach(function (k) { if (!KNOWN_OPTS_KEYS[k]) throw _err("cmp/bad-input", "unknown opts field " + JSON.stringify(k)); });
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
 * @status     experimental
 * @spec       RFC 9810, RFC 9481, RFC 9579
 * @related    pki.schema.cmp.parse
 *
 * Build an RFC 9810 CMP `PKIMessage` -- the producing-side inverse of `pki.schema.cmp.parse`. `message` is
 * `{ header, body }`: `header` carries the `sender` / `recipient` GeneralNames plus optional transaction
 * metadata (`transactionID`, `senderNonce`, `messageTime`, `freeText`, `generalInfo`, ...); `body` is a
 * single-key object naming the arm. Request-side: `{ ir }` / `{ cr }` / `{ kur }` (a `CertReqMessages` spec
 * delegated to `pki.crmf.build`; the proof-of-possession key is `key` on the arm spec), `{ p10cr }` (a PKCS#10
 * CertificationRequest DER), `{ certConf }`, `{ pollReq }`, `{ genm }`, `{ rr }`. CA/responder-side: `{ ip }` /
 * `{ cp }` / `{ kup }` / `{ ccp }` (a `CertRepMessage` -- `caPubs` + `response` of `CertResponse` each with a
 * `PKIStatusInfo` and, under a granting status, a `certifiedKeyPair`), `{ rp }` (`RevRepContent`), `{ genp }`,
 * `{ error }` (`ErrorMsgContent`), `{ pollRep }`, `{ krp }` (`KeyRecRepContent`), `{ pkiconf }` (NULL). The
 * message is protected: `opts` carries EXACTLY
 * ONE of `{ key, cert }` (a signature under the sender key over the message -- any registry algorithm, RSA
 * / ECDSA / EdDSA / ML-DSA / SLH-DSA / composite, resolved from the certificate) or `{ mac }` (a PBMAC1
 * shared-secret MAC). The protection is computed over the exact DER of the virtual
 * `ProtectedPart ::= SEQUENCE { header, body }` and self-verified before the message is returned. The
 * emitted PKIMessage round-trips byte-identically through `pki.schema.cmp.parse`.
 *
 * @opts
 *   - `key` (Buffer|CryptoKey) + `cert` (Buffer) -- signature protection under the sender key; `cert` is
 *     the signer certificate (its SPKI resolves the algorithm) and is placed in `extraCerts`.
 *   - `mac` ({ secret, salt?, iterationCount?, prf?, keyLength? }) -- PBMAC1 protection from a shared secret.
 *   - `extraCerts` (array of Buffer) -- additional certificates to carry in `extraCerts [1]`.
 *   - `pem` (boolean|string) -- return a PEM `CMP` block instead of DER.
 *   - `pss` (boolean) / `digestAlgorithm` (string) -- signature-protection algorithm options.
 *
 * @example
 *   var der = await pki.cmp.build(
 *     { header: { sender: { directoryName: "CN=client" }, recipient: { directoryName: "CN=CA" } },
 *       body: { p10cr: csrDer } },
 *     { key: signerKeyPkcs8, cert: signerCertDer });
 *   pki.schema.cmp.parse(der).body.arm;   // "p10cr"
 */
module.exports = { build: build };
