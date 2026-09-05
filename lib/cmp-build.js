// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.cmp
 * @nav        Signing
 * @title      Certificate management protocol messages
 * @fullname   CMP (Certificate Management Protocol, RFC 4210)
 * @intro The RFC 9810 Certificate Management Protocol producing side. `pki.cmp.build` assembles a
 *   `PKIMessage`: a `PKIHeader` (sender / recipient / transaction metadata), a `PKIBody` carrying one
 *   request or transaction (an `ir` / `cr` / `kur` certificate request via `pki.crmf.build`, a `p10cr`
 *   PKCS#10 via `pki.csr.sign`, a `certConf` / `pollReq` / `genm` / `rr`, or a `nested` wrapper of other
 *   PKIMessages an RA forwards), and an optional
 *   `PKIProtection` computed over the message. Protection is a signature under the sender key (any
 *   registry algorithm) or a PBMAC1 shared-secret MAC. The emitted message round-trips through
 *   `pki.schema.cmp.parse` and its protection verifies. `pki.cmp.transfer` carries a message to a CMP
 *   endpoint (RFC 9811), `pki.cmp.verify` checks an incoming message's protection, and `pki.cmp.session`
 *   drives a full enrollment transaction end to end over these. Parsing lives at `pki.schema.cmp.parse`.
 * @spec RFC 9810
 * @card Build a CMP PKIMessage with signature or PBMAC1 protection.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var oid = require("./oid");
var cmp = require("./schema-cmp");
var crmf = require("./crmf-sign");
var schemaCrmf = require("./schema-crmf");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var _isArray = intrinsic.isArray;
var _isBuffer = intrinsic.isBuffer;
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _strIndexOf = intrinsic.uncurry(String.prototype.indexOf);
var _bufferConcat = intrinsic.bufferConcat;
var _map = intrinsic.map;
var _keys = intrinsic.keys;
var _forEach = intrinsic.forEach;
var _push = intrinsic.push;
var _stringify = intrinsic.stringify;
var _bigInt = intrinsic.BigInt;
var _Date = intrinsic.Date;
var csr = require("./schema-csr");
require("./path-validate");
var csrVerify = require("./csr-verify");
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

var KNOWN_HEADER_KEYS = intrinsic.assign(intrinsic.create(null), {
  sender: 1, recipient: 1, pvno: 1, messageTime: 1, senderKID: 1, recipKID: 1,
  transactionID: 1, senderNonce: 1, recipNonce: 1, freeText: 1, generalInfo: 1,
});
var KNOWN_BODY_KEYS = intrinsic.assign(intrinsic.create(null), {
  ir: 1, cr: 1, kur: 1, krr: 1, ccr: 1, p10cr: 1, certConf: 1, pollReq: 1, genm: 1, rr: 1,
  ip: 1, cp: 1, kup: 1, ccp: 1, krp: 1, rp: 1, genp: 1, error: 1, pollRep: 1, pkiconf: 1,
  nested: 1,
});
var BODY_TAG = intrinsic.assign(intrinsic.create(null), {
  ir: 0, cr: 2, p10cr: 4, kur: 7, krr: 9, ccr: 13, rr: 11, genm: 21, certConf: 24, pollReq: 25,
  ip: 1, cp: 3, kup: 8, krp: 10, rp: 12, ccp: 14, pkiconf: 19, genp: 22, error: 23, pollRep: 26,
  nested: 20,
});
var CRMF_BODY = intrinsic.assign(intrinsic.create(null), { ir: 1, cr: 1, kur: 1, krr: 1, ccr: 1 });
var CERT_REP_ARM = intrinsic.assign(intrinsic.create(null), { ip: 1, cp: 1, kup: 1, ccp: 1 });
var KNOWN_OPTS_KEYS = intrinsic.assign(intrinsic.create(null), { key: 1, cert: 1, mac: 1, extraCerts: 1, pem: 1, pss: 1, digestAlgorithm: 1 });
var KNOWN_OPTS_SIG_KEYS = intrinsic.assign(intrinsic.create(null), { key: 1, cert: 1, extraCerts: 1, pem: 1, pss: 1, digestAlgorithm: 1 });
var KNOWN_OPTS_MAC_KEYS = intrinsic.assign(intrinsic.create(null), { mac: 1, extraCerts: 1, pem: 1 });
var KNOWN_MESSAGE_KEYS = intrinsic.assign(intrinsic.create(null), { header: 1, body: 1 });
var KNOWN_MAC_KEYS = intrinsic.assign(intrinsic.create(null), { secret: 1, salt: 1, iterationCount: 1, prf: 1, keyLength: 1, algorithm: 1 });

var PBMAC1_DEFAULT_ITER = 100000;
var PBMAC1_DEFAULT_SALT_BYTES = 16;
var PBMAC1_MIN_SALT = 8;
var PBMAC1_DEFAULT_KEYLEN = 32;
var PBMAC1_MIN_KEYLEN = 20;
var PBMAC1_MAX_KEYLEN = 1024;
var PBMAC1_MIN_ITER = 1000;
var PBMAC1_PRF = intrinsic.assign(intrinsic.create(null), { "SHA-256": "hmacWithSHA256", "SHA-384": "hmacWithSHA384", "SHA-512": "hmacWithSHA512" });
var PBMAC1_MAC_OID = intrinsic.assign(intrinsic.create(null), { "SHA-256": "hmacWithSHA256", "SHA-384": "hmacWithSHA384", "SHA-512": "hmacWithSHA512" });
var PBMAC1_PRF_HLEN = intrinsic.assign(intrinsic.create(null), { "SHA-256": 32, "SHA-384": 48, "SHA-512": 64 });
var FAIL_INFO_NAMES = ["badAlg", "badMessageCheck", "badRequest", "badTime", "badCertId", "badDataFormat",
  "wrongAuthority", "incorrectData", "missingTimeStamp", "badPOP", "certRevoked", "certConfirmed",
  "wrongIntegrity", "badRecipientNonce", "timeNotAvailable", "unacceptedPolicy", "unacceptedExtension",
  "addInfoNotAvailable", "badSenderNonce", "badCertTemplate", "signerNotTrusted", "transactionIdInUse",
  "unsupportedVersion", "notAuthorized", "systemUnavail", "systemFailure", "duplicateCertReq"];
var FAIL_INFO_INDEX = intrinsic.create(null);
FAIL_INFO_NAMES.forEach(function (n, i) { FAIL_INFO_INDEX[n] = i; });
var CERT_CONF_HASH_ALGS = intrinsic.assign(intrinsic.create(null), { sha1: 1, sha256: 1, sha384: 1, sha512: 1, "sha3-256": 1, "sha3-512": 1 });


function _reqOctets(v, what) {
  var buf = _b.reqDer(v, what);
  return b.octetString(buf);
}

function _encodePkiFreeText(strings, code, what) {
  if (!Array.isArray(strings) || !strings.length) throw _err(code, what + " must be a non-empty array of strings");
  return b.sequence(strings.map(function (s) {
    if (typeof s !== "string") throw _err(code, what + " entries must be strings");
    return b.utf8(s);
  }));
}

function _encodeInfoValue(itav) {
  var name = itav.infoType;
  if (name === "implicitConfirm") {
    if (itav.infoValue != null) throw _err("cmp/bad-info-value", "implicitConfirm carries a NULL infoValue");
    return b.nullValue();
  }
  if (name === "confirmWaitTime") {
    guard.time.assertValid(itav.infoValue, _err, "cmp/bad-info-value", "confirmWaitTime infoValue");
    return b.generalizedTime(itav.infoValue);
  }
  if (name === "certProfile") {
    return _encodePkiFreeText(itav.infoValue, "cmp/bad-info-value", "certProfile");
  }
  if (itav.infoValue == null) return null;
  return b.raw(_b.reqDer(itav.infoValue, "infoValue (a pre-encoded DER value)"));
}

function _encodeInfoTypeAndValue(itav) {
  if (!itav || typeof itav !== "object" || Buffer.isBuffer(itav)) throw _err("cmp/bad-info-value", "an InfoTypeAndValue must be an object { infoType, infoValue? }");
  if (typeof itav.infoType !== "string" || O(itav.infoType) == null) throw _err("cmp/bad-name", "unknown infoType " + guard.text.showValue(itav.infoType));
  var children = [b.oid(O(itav.infoType))];
  var val = _encodeInfoValue(itav);
  if (val != null) children.push(val);
  return b.sequence(children);
}

function _encodeGeneralInfo(itavs, code, what) {
  if (!Array.isArray(itavs) || !itavs.length) throw _err(code, what + " must be a non-empty array of InfoTypeAndValue");
  return b.sequence(itavs.map(_encodeInfoTypeAndValue));
}


function _algIdNoParams(name) { return b.sequence([b.oid(O(name))]); }

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
  if (headerSpec.messageTime != null) {
    guard.time.assertValid(headerSpec.messageTime, _err, "cmp/bad-input", "header.messageTime");
    children.push(b.explicit(0, b.generalizedTime(headerSpec.messageTime)));
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


function _reqIdInt(v, code, what) { return guard.range.authoredInteger(v, _err, code, what); }

function _encodeFailInfo(names, code) {
  if (!Array.isArray(names)) throw _err(code, "statusInfo.failInfo must be an array of PKIFailureInfo bit names");
  return b.namedBitString(names.map(function (n) {
    if (typeof n !== "string" || FAIL_INFO_INDEX[n] === undefined) throw _err(code, "unknown PKIFailureInfo bit " + guard.text.showValue(n));
    return FAIL_INFO_INDEX[n];
  }));
}

function _encodePkiStatusInfo(si, code) {
  code = code || "cmp/bad-status-info";
  if (!si || typeof si !== "object" || Buffer.isBuffer(si)) throw _err(code, "a PKIStatusInfo must be an object { status, statusString?, failInfo? }");
  if (typeof si.status !== "number" || !Number.isInteger(si.status) || si.status < 0 || si.status > 6) throw _err(code, "statusInfo.status must be a PKIStatus 0..6 (RFC 9810 sec. 5.2.3)");
  var children = [b.integer(BigInt(si.status))];
  if (si.statusString != null) children.push(_encodePkiFreeText(si.statusString, code, "statusInfo.statusString"));
  if (si.failInfo != null) children.push(_encodeFailInfo(si.failInfo, code));
  return b.sequence(children);
}

function _encodeCertStatus(cs, state) {
  if (!cs || typeof cs !== "object" || Buffer.isBuffer(cs)) throw _err("cmp/bad-cert-status", "each CertStatus must be an object");
  var children = [
    _reqOctets(cs.certHash, "certConf certHash"),
    b.integer(_reqIdInt(cs.certReqId, "cmp/bad-cert-status", "CertStatus certReqId")),
  ];
  if (cs.statusInfo != null) children.push(_encodePkiStatusInfo(cs.statusInfo, "cmp/bad-cert-status"));
  if (cs.hashAlg != null) {
    if (typeof cs.hashAlg !== "string" || !CERT_CONF_HASH_ALGS[cs.hashAlg]) throw _err("cmp/bad-name", "certConf hashAlg must be a hash algorithm (sha256 / sha384 / sha512 / sha3-256 / sha3-512 / sha1); got " + guard.text.showValue(cs.hashAlg));
    children.push(b.explicit(0, _algIdNoParams(cs.hashAlg)));
    state.usesCmp2021 = true;
  }
  return b.sequence(children);
}

function _encodeCertConfirmContent(list, state) {
  if (!Array.isArray(list)) throw _err("cmp/bad-cert-status", "certConf must be an array of CertStatus");
  return b.sequence(list.map(function (cs) { return _encodeCertStatus(cs, state); }));
}

function _encodePollReqContent(list) {
  if (!Array.isArray(list)) throw _err("cmp/bad-poll-req", "pollReq must be an array of { certReqId }");
  return b.sequence(list.map(function (pr) {
    if (!pr || typeof pr !== "object" || Buffer.isBuffer(pr)) throw _err("cmp/bad-poll-req", "each pollReq entry must be { certReqId: <integer> }");
    return b.sequence([b.integer(_reqIdInt(pr.certReqId, "cmp/bad-poll-req", "pollReq certReqId"))]);
  }));
}

function _encodeGenMsgContent(list) {
  if (!Array.isArray(list)) throw _err("cmp/bad-info-type-and-value", "genm must be an array of InfoTypeAndValue");
  return b.sequence(list.map(_encodeInfoTypeAndValue));
}

function _encodeRevDetails(rd) {
  if (!rd || typeof rd !== "object" || Buffer.isBuffer(rd)) throw _err("cmp/bad-rev-req", "each RevDetails must be an object { certDetails, crlEntryDetails? }");
  guard.identifier.assertKnownKeys(rd, KNOWN_REV_DETAILS_KEYS, _err, "cmp/bad-rev-req", "unknown RevDetails field ");
  if (rd.certDetails == null) throw _err("cmp/bad-rev-req", "RevDetails.certDetails (a CertTemplate) is required");
  var certDetails;
  if (guard.bytes.isByteSource(rd.certDetails)) {
    certDetails = b.raw(guard.bytes.snapshotSource(rd.certDetails, CmpError, "cmp/bad-rev-req", "RevDetails.certDetails (a pre-encoded CertTemplate DER)"));
  } else {
    if (rd.certDetails.issuer == null || rd.certDetails.serialNumber == null) throw _err("cmp/bad-rev-req", "a revocation certDetails must identify the certificate by issuer and serialNumber");
    certDetails = b.raw(crmf.buildCertTemplate(rd.certDetails));
  }
  var children = [certDetails];
  if (rd.crlEntryDetails != null) children.push(b.raw(_encodeCrlEntryDetails(rd.crlEntryDetails)));
  return b.sequence(children);
}

var KNOWN_REV_DETAILS_KEYS = intrinsic.assign(intrinsic.create(null), { certDetails: 1, crlEntryDetails: 1 });
var KNOWN_CRL_ENTRY_DETAIL_KEYS = intrinsic.assign(intrinsic.create(null), { reason: 1 });
var CRL_REASON_BY_NAME = intrinsic.create(null);
_forEach(_keys(constants.NAMES.CRL_REASON), function (v) { CRL_REASON_BY_NAME[constants.NAMES.CRL_REASON[v]] = intrinsic.Number(v); });
function _encodeCrlEntryDetails(spec) {
  if (guard.bytes.isByteSource(spec)) return guard.bytes.snapshotSource(spec, CmpError, "cmp/bad-rev-req", "RevDetails.crlEntryDetails (a pre-encoded Extensions DER)");
  guard.identifier.assertPlainRecord(spec, _err, "cmp/bad-rev-req", "RevDetails.crlEntryDetails ({ reason } or a pre-encoded Extensions DER)");
  guard.identifier.assertKnownKeys(spec, KNOWN_CRL_ENTRY_DETAIL_KEYS, _err, "cmp/bad-rev-req", "unknown crlEntryDetails field ");
  var reason = spec.reason;
  if (reason != null && (typeof reason !== "string" || !_hasOwn(CRL_REASON_BY_NAME, reason))) {
    throw _err("cmp/bad-rev-req", "unknown CRLReason " + guard.text.showValue(reason) + " (RFC 5280 sec. 5.3.1)");
  }
  var code = reason == null ? 0 : CRL_REASON_BY_NAME[reason];
  return b.sequence([_b.ext(O("reasonCode"), false, b.enumerated(_bigInt(code)))]);
}

var KNOWN_CRL_STATUS_KEYS = intrinsic.assign(intrinsic.create(null), { dpn: 1, issuer: 1, thisUpdate: 1 });
var KNOWN_DPN_KEYS = intrinsic.assign(intrinsic.create(null), { fullName: 1 });
function buildCrlStatusList(spec) {
  if (!spec || typeof spec !== "object" || _isBuffer(spec)) throw _err("cmp/bad-input", "a crlUpdate request must be an object { dpn | issuer, thisUpdate? }");
  guard.identifier.assertKnownKeys(spec, KNOWN_CRL_STATUS_KEYS, _err, "cmp/bad-input", "unknown crlUpdate field ");
  var dpnSpec = spec.dpn, issuerSpec = spec.issuer;
  if (dpnSpec == null && issuerSpec == null) {
    throw _err("cmp/bad-input", "a crlUpdate identifies the requested CRL by a dpn (a distribution point name), an issuer (the CA that issues it), or both (RFC 9483 sec. 4.3.4)");
  }
  if (dpnSpec != null && issuerSpec == null) {
    throw _err("cmp/bad-input", "a crlUpdate naming a dpn must also name the issuer whose CRL is acceptable: a distribution point name alone leaves the response unbound, since a complete CRL states no scope to compare it against (RFC 9483 sec. 4.3.4, RFC 5280 sec. 5.2.5). Drive an unbound request with pki.cmp.build + pki.cmp.transfer.");
  }
  var source, issuerNameDer = null, dpnNames = null;
  if (issuerSpec != null) issuerNameDer = _b.encodeName(issuerSpec);
  if (dpnSpec != null) {
    if (typeof dpnSpec !== "object" || _isBuffer(dpnSpec)) throw _err("cmp/bad-input", "crlUpdate.dpn must be { fullName: [<GeneralName>...] }");
    guard.identifier.assertKnownKeys(dpnSpec, KNOWN_DPN_KEYS, _err, "cmp/bad-input", "unknown crlUpdate.dpn field ");
    var fullName = dpnSpec.fullName;
    if (fullName == null) throw _err("cmp/bad-input", "crlUpdate.dpn requires fullName (the nameRelativeToCRLIssuer arm is not built; pki.crl.sign draws the same line for issuingDistributionPoint)");
    var entries = _isArray(fullName) ? fullName : [fullName];
    if (!entries.length) throw _err("cmp/bad-input", "crlUpdate.dpn.fullName must carry at least one GeneralName");
    dpnNames = _map(entries, function (e) { return _b.encodeGeneralName(e); });
    source = b.explicit(0, b.contextConstructed(0, _bufferConcat(dpnNames)));
  } else {
    source = b.explicit(1, b.sequence([b.explicit(4, b.raw(issuerNameDer))]));
  }
  var status = [source], askedInstant = null, asked = spec.thisUpdate;
  if (asked != null) {
    guard.time.assertValid(asked, _err, "cmp/bad-input", "crlUpdate.thisUpdate");
    askedInstant = guard.time.instantOf(asked);
    _push(status, b.raw(_b.timeDer(new _Date(askedInstant), "crlUpdate.thisUpdate")));
  }
  return {
    der: b.sequence([b.sequence(status)]),
    issuerName: issuerNameDer,
    thisUpdate: askedInstant,
    dpn: dpnNames === null ? null : { kind: "fullName", names: dpnNames },
  };
}

var IDP_SCHEMA = pkix.issuingDistributionPoint("cmp/bad-info-value");
function decodeIdpDistributionPoint(valueBytes) {
  var m;
  try { m = schema.walk(IDP_SCHEMA, asn1.decode(valueBytes), NS); }
  catch (e) { throw _err("cmp/bad-info-value", "the returned CRL carries a malformed issuingDistributionPoint extension (RFC 5280 sec. 5.2.5)", e); }
  if (!m.fields.distributionPoint.present) return null;
  var wrap = m.fields.distributionPoint.node;
  if (!wrap.children || wrap.children.length !== 1) {
    throw _err("cmp/bad-info-value", "an issuingDistributionPoint distributionPoint [0] must wrap exactly one DistributionPointName (RFC 5280 sec. 5.2.5)");
  }
  return pkix.distributionPointName(NS, wrap.children[0], "cmp/bad-info-value");
}

function _encodeRevReqContent(list) {
  if (!Array.isArray(list) || !list.length) throw _err("cmp/bad-rev-req", "rr must be a non-empty array of RevDetails");
  return b.sequence(list.map(_encodeRevDetails));
}


function _encodeCertOrEncCert(coec, state) {
  if (!coec || typeof coec !== "object" || Buffer.isBuffer(coec)) throw _err("cmp/bad-cert-response", "certifiedKeyPair must carry certificate or encryptedCert");
  if (coec.certificate != null && coec.encryptedCert != null) throw _err("cmp/bad-cert-response", "certOrEncCert is a CHOICE: supply exactly one of certificate or encryptedCert, not both");
  if (coec.certificate != null) {
    var certDer = _b.reqDerSequence(coec.certificate, "certifiedKeyPair.certificate (a Certificate DER)");
    try { x509.parse(certDer); } catch (e) { if (e instanceof CmpError) throw e; throw _err("cmp/bad-cert-response", "certifiedKeyPair.certificate is not a valid X.509 certificate", e); }
    return b.explicit(0, b.raw(certDer));
  }
  if (coec.encryptedCert != null) {
    var ec = _b.reqDer(coec.encryptedCert, "certifiedKeyPair.encryptedCert (a pre-encoded EncryptedKey DER)");
    var ecNode;
    try { ecNode = asn1.decode(ec); } catch (e) { throw _err("cmp/bad-cert-response", "certifiedKeyPair.encryptedCert is not valid DER", e); }
    if (ecNode.tagClass === "context" && ecNode.tagNumber === 0) state.usesCmp2021 = true;
    return b.explicit(1, b.raw(ec));
  }
  throw _err("cmp/bad-cert-response", "certifiedKeyPair must carry certificate or encryptedCert");
}

function _encodeCertifiedKeyPair(ckp, state) {
  if (!ckp || typeof ckp !== "object" || Buffer.isBuffer(ckp)) throw _err("cmp/bad-cert-response", "certifiedKeyPair must be an object");
  var children = [_encodeCertOrEncCert(ckp, state)];
  if (ckp.privateKey != null) {
    var pk = _b.reqDer(ckp.privateKey, "certifiedKeyPair.privateKey (a pre-encoded EncryptedKey DER)");
    children.push(b.explicit(0, b.raw(pk)));
    var pkNode;
    try { pkNode = asn1.decode(pk); } catch (e) { throw _err("cmp/bad-cert-response", "certifiedKeyPair.privateKey is not valid DER", e); }
    if (pkNode.tagClass === "context" && pkNode.tagNumber === 0) state.usesCmp2021 = true;
  }
  if (ckp.publicationInfo != null) children.push(b.explicit(1, b.raw(_b.reqDer(ckp.publicationInfo, "certifiedKeyPair.publicationInfo (a pre-encoded DER)"))));
  return b.sequence(children);
}

function _encodeCertResponse(cr, state) {
  if (!cr || typeof cr !== "object" || Buffer.isBuffer(cr)) throw _err("cmp/bad-cert-response", "each CertResponse must be an object");
  if (cr.status == null) throw _err("cmp/bad-cert-response", "CertResponse.status (a PKIStatusInfo) is required");
  var hasCkp = cr.certifiedKeyPair != null;
  if (hasCkp && cr.status.failInfo != null) throw _err("cmp/bad-cert-response", "a CertResponse must not carry both failInfo and certifiedKeyPair");
  if (hasCkp && cr.status.status !== 0 && cr.status.status !== 1) throw _err("cmp/bad-cert-response", "a CertResponse certifiedKeyPair is allowed only under a granting status (accepted / grantedWithMods)");
  var children = [b.integer(_reqIdInt(cr.certReqId, "cmp/bad-cert-response", "CertResponse certReqId")), _encodePkiStatusInfo(cr.status, "cmp/bad-cert-response")];
  if (hasCkp) children.push(_encodeCertifiedKeyPair(cr.certifiedKeyPair, state));
  if (cr.rspInfo != null) children.push(_reqOctets(cr.rspInfo, "CertResponse.rspInfo"));
  return b.sequence(children);
}

function _encodeCertRepMessage(spec, state, arm) {
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("cmp/bad-cert-rep", arm + " must be an object { caPubs?, response }");
  if (!Array.isArray(spec.response)) throw _err("cmp/bad-cert-rep", arm + ".response must be an array of CertResponse");
  var children = [];
  if (spec.caPubs != null) {
    if (!Array.isArray(spec.caPubs) || !spec.caPubs.length) throw _err("cmp/bad-cert-rep", arm + ".caPubs must be a non-empty array of certificate DERs");
    children.push(b.explicit(1, b.sequence(spec.caPubs.map(function (c) { return _certRaw(c, "cmp/bad-cert-rep", "a caPubs entry"); }))));
  }
  children.push(b.sequence(spec.response.map(function (cr) { return _encodeCertResponse(cr, state); })));
  return b.sequence(children);
}

function _certRaw(c, code, what) {
  var der = _b.reqDerSequence(c, what + " (a Certificate DER)");
  try { x509.parse(der); } catch (e) { if (e instanceof CmpError) throw e; throw _err(code, what + " is not a valid X.509 certificate", e); }
  return b.raw(der);
}

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
      var der = _b.reqDerSequence(c, "crls entry (a CertificateList DER)");
      try { crl.parse(der); }
      catch (e) { if (e instanceof CmpError) throw e; throw _err("cmp/bad-rev-rep", "a crls entry is not a valid CRL (CertificateList)", e); }
      return b.raw(der);
    }))));
  }
  return b.sequence(children);
}

function _encodeErrorMsgContent(spec) {
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("cmp/bad-error", "error must be an object { pKIStatusInfo, errorCode?, errorDetails? }");
  if (spec.pKIStatusInfo == null) throw _err("cmp/bad-error", "error.pKIStatusInfo is required");
  var children = [_encodePkiStatusInfo(spec.pKIStatusInfo, "cmp/bad-error")];
  if (spec.errorCode != null) children.push(b.integer(_reqIdInt(spec.errorCode, "cmp/bad-error", "error.errorCode")));
  if (spec.errorDetails != null) children.push(_encodePkiFreeText(spec.errorDetails, "cmp/bad-error", "error.errorDetails"));
  return b.sequence(children);
}

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

var CMP2021_POP_METHODS = intrinsic.assign(intrinsic.create(null), { agreeMAC: 1, encryptedKey: 1 });
function _popNeedsCmp2021(crmfDer) {
  var messages;
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

function _encodeNestedContent(list) {
  if (!intrinsic.isArray(list) || list.length === 0) {
    throw _err("cmp/bad-input", "nested must be a non-empty array of PKIMessage DER (RFC 9810 sec. 5.1.3.5 PKIMessages is SIZE (1..MAX))");
  }
  return b.sequence(intrinsic.map(_b.reqDenseArray(list, "nested"), function (m, i) {
    var der = _b.reqDerSequence(m, "nested[" + i + "] (a PKIMessage DER)");
    try { cmp.parse(der); }
    catch (e) { throw _err("cmp/bad-input", "nested[" + i + "] does not parse as a PKIMessage", e); }
    return b.raw(der);
  }));
}

function _encodeBody(bodySpec, key, opts) {
  if (!bodySpec || typeof bodySpec !== "object" || Buffer.isBuffer(bodySpec)) throw _err("cmp/bad-input", "message.body must be a single-key object");
  var keys = Object.keys(bodySpec);
  if (keys.length !== 1) throw _err("cmp/bad-input", "message.body must have exactly one arm, got " + keys.length);
  var arm = keys[0];
  if (!KNOWN_BODY_KEYS[guard.text.keyOf(arm)]) throw _err("cmp/bad-input", "unknown body arm " + guard.text.showValue(arm));
  var tag = BODY_TAG[arm], state = { usesCmp2021: false };

  if (CRMF_BODY[arm]) {
    var reqSpec = bodySpec[arm], popKey = key;
    if (reqSpec && typeof reqSpec === "object" && !Buffer.isBuffer(reqSpec) && "key" in reqSpec) {
      popKey = reqSpec.key;
      reqSpec = Object.assign({}, reqSpec);
      delete reqSpec.key;
    }
    return crmf.build(reqSpec, popKey, {}).then(function (crmfDer) {
      return { bodyTLV: b.explicit(tag, b.raw(crmfDer)), usesCmp2021: _popNeedsCmp2021(crmfDer) };
    });
  }
  var inner;
  if (arm === "p10cr") {
    var csrDer = _b.reqDerSequence(bodySpec.p10cr, "p10cr (a CertificationRequest DER)");
    var parsedCsr;
    try { parsedCsr = csr.parse(csrDer); }
    catch (e) { if (e instanceof CmpError) throw e; throw _err("cmp/bad-input", "p10cr is not a valid PKCS#10 CertificationRequest", e); }
    return _p10crBody(csrDer, parsedCsr, tag, state);
  }
  if (arm === "certConf") {
    inner = _encodeCertConfirmContent(bodySpec.certConf, state);
  } else if (arm === "pollReq") {
    inner = _encodePollReqContent(bodySpec.pollReq);
  } else if (arm === "genm") {
    inner = _encodeGenMsgContent(bodySpec.genm);
  } else if (arm === "rr") {
    inner = _encodeRevReqContent(bodySpec.rr);
  } else if (CERT_REP_ARM[arm]) {
    inner = _encodeCertRepMessage(bodySpec[arm], state, arm);
  } else if (arm === "rp") {
    inner = _encodeRevRepContent(bodySpec.rp);
  } else if (arm === "genp") {
    inner = _encodeGenMsgContent(bodySpec.genp);
  } else if (arm === "error") {
    inner = _encodeErrorMsgContent(bodySpec.error);
  } else if (arm === "pollRep") {
    inner = _encodePollRepContent(bodySpec.pollRep);
  } else if (arm === "krp") {
    inner = _encodeKeyRecRepContent(bodySpec.krp, state);
  } else if (arm === "nested") {
    inner = _encodeNestedContent(bodySpec.nested);
  } else {
    if (bodySpec.pkiconf !== null && bodySpec.pkiconf !== true) throw _err("cmp/bad-input", "pkiconf takes null or true (PKIConfirmContent is NULL)");
    inner = b.nullValue();
  }
  return Promise.resolve({ bodyTLV: b.explicit(tag, inner), usesCmp2021: state.usesCmp2021 });
}

async function _p10crBody(csrDer, parsedCsr, tag, state) {
  if (!(await csrVerify.verifyCsrSignature(parsedCsr))) {
    throw _err("cmp/bad-popo", "the p10cr CertificationRequest failed its proof-of-possession: its PKCS#10 signature does not verify under its own subject public key, so a CA would reject it");
  }
  return { bodyTLV: b.explicit(tag, b.raw(csrDer)), usesCmp2021: state.usesCmp2021 };
}



function _resolveProtection(opts) {
  var hasSig = opts.key != null || opts.cert != null;
  var hasMac = opts.mac != null;
  if (hasSig && hasMac) throw _err("cmp/bad-input", "supply exactly one of { key, cert } (signature) or { mac } (PBMAC1), not both");
  if (!hasSig && !hasMac) throw _err("cmp/bad-input", "a PKIMessage requires protection: supply { key, cert } for a signature or { mac } for PBMAC1");

  if (hasSig) {
    if (opts.key == null || opts.cert == null) throw _err("cmp/bad-input", "signature protection requires both opts.key (the private key) and opts.cert (the signer certificate)");
    var certDer = _b.reqDerSequence(opts.cert, "opts.cert (the signer certificate DER)");
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

  var m = opts.mac;
  if (!m || typeof m !== "object" || Buffer.isBuffer(m)) throw _err("cmp/bad-input", "opts.mac must be an object { secret, salt?, iterationCount?, prf?, keyLength? }");
  guard.identifier.assertKnownKeys(m, KNOWN_MAC_KEYS, _err, "cmp/bad-input", "unknown opts.mac field ");
  if (m.algorithm != null && m.algorithm !== "pbmac1") throw _err("cmp/unsupported-algorithm", "opts.mac.algorithm " + guard.text.showValue(m.algorithm) + " is not supported (v1 ships pbmac1; passwordBasedMac is deferred)");
  var secret = m.secret;
  if (typeof secret !== "string" || !secret) {
    if (!Buffer.isBuffer(secret) || !secret.length) throw _err("cmp/bad-input", "opts.mac.secret must be a non-empty string or Buffer");
  }
  var secretBuf = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, "utf8");
  var prf = m.prf != null ? m.prf : "SHA-256";
  if (!PBMAC1_PRF[prf]) throw _err("cmp/bad-input", "opts.mac.prf must be SHA-256 / SHA-384 / SHA-512");
  var iterationCount = m.iterationCount != null ? m.iterationCount : PBMAC1_DEFAULT_ITER;
  if (typeof iterationCount !== "number" || !Number.isInteger(iterationCount) || iterationCount < PBMAC1_MIN_ITER) throw _err("cmp/bad-input", "opts.mac.iterationCount must be at least " + PBMAC1_MIN_ITER + " (RFC 8018 sec. 4.2)");
  if (iterationCount > constants.LIMITS.PBKDF2_MAX_ITERATIONS) throw _err("cmp/bad-input", "opts.mac.iterationCount exceeds the PBKDF2 work-factor cap " + constants.LIMITS.PBKDF2_MAX_ITERATIONS);
  var keyLength = m.keyLength != null ? m.keyLength : PBMAC1_DEFAULT_KEYLEN;
  if (typeof keyLength !== "number" || !Number.isInteger(keyLength) || keyLength < PBMAC1_MIN_KEYLEN) throw _err("cmp/bad-input", "opts.mac.keyLength must be an integer >= " + PBMAC1_MIN_KEYLEN + " bytes (RFC 9579 sec. 9)");
  if (keyLength > PBMAC1_MAX_KEYLEN) throw _err("cmp/bad-input", "opts.mac.keyLength exceeds the cap " + PBMAC1_MAX_KEYLEN + " bytes");
  var blocks = Math.ceil(keyLength / PBMAC1_PRF_HLEN[prf]);
  if (iterationCount * blocks > constants.LIMITS.PBKDF2_MAX_ITERATIONS) throw _err("cmp/bad-input", "opts.mac combined work (iterationCount " + iterationCount + " x " + blocks + " derived blocks) exceeds the PBKDF2 work-factor cap " + constants.LIMITS.PBKDF2_MAX_ITERATIONS);
  var salt = m.salt != null ? _b.reqDer(m.salt, "opts.mac.salt") : Buffer.from(webcrypto.webcrypto.getRandomValues(new Uint8Array(PBMAC1_DEFAULT_SALT_BYTES)));
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


function build(message, opts) {
  return guard.bytes.fixedCall(CmpError, "cmp/bad-input", [
    [message, "the PKIMessage spec"], [opts, "pki.cmp.build options"],
  ], _build);
}

async function _build(message, opts) {
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

  var bodyResult = await _encodeBody(message.body, senderKey, opts);
  var bodyTLV = bodyResult.bodyTLV;
  var pvno = message.header.pvno != null ? message.header.pvno : 2;
  if (typeof pvno !== "number" || !Number.isInteger(pvno)) throw _err("cmp/bad-input", "header.pvno must be an integer");
  if (bodyResult.usesCmp2021 && pvno < 3) pvno = 3;

  var headerTLV = _encodeHeader(message.header, prot.protectionAlgDer, pvno);
  var protectedPartDer = b.sequence([headerTLV, bodyTLV]);

  var protectionBits = await prot.computeBits(protectedPartDer);
  var msgChildren = [headerTLV, bodyTLV, b.explicit(0, protectionBits)];
  var extraCertsDers = _collectExtraCerts(opts, prot.certDer);
  if (extraCertsDers.length) msgChildren.push(b.explicit(1, b.sequence(extraCertsDers)));
  var der = b.sequence(msgChildren);

  cmp.parse(der);
  if (opts.pem != null) {
    if (opts.pem === true) return cmp.pemEncode(der, "CMP");
    if (typeof opts.pem !== "string" || !opts.pem) throw _err("cmp/bad-input", "opts.pem must be true or a non-empty PEM label string");
    return cmp.pemEncode(der, opts.pem);
  }
  return der;
}

function _collectExtraCerts(opts, protCertDer) {
  var out = [];
  if (protCertDer != null) out.push(b.raw(protCertDer));
  if (opts.extraCerts != null) {
    if (!Array.isArray(opts.extraCerts)) throw _err("cmp/bad-extra-certs", "opts.extraCerts must be an array of certificate DERs");
    opts.extraCerts.forEach(function (c) {
      var der = _b.reqDerSequence(c, "extraCerts entry (a Certificate DER)");
      try { x509.parse(der); }
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
 * Build an RFC 9810 CMP `PKIMessage`, the producing-side inverse of `pki.schema.cmp.parse`. `message` is
 * `{ header, body }`: `header` carries the `sender` / `recipient` GeneralNames plus optional transaction
 * metadata (`transactionID`, `senderNonce`, `messageTime`, `freeText`, `generalInfo`, ...); `body` is a
 * single-key object naming the arm. Request-side: `{ ir }` / `{ cr }` / `{ kur }` / `{ krr }` (key recovery,
 * RFC 9810 sec. 5.3.7) / `{ ccr }` (cross-certification, RFC 9810 sec. 5.3.11: the requesting CA keeps its
 * private key, so a ccr carrying the private-key-transport encryptedKey proof-of-possession is refused; a
 * ccr is a CertReqMessages at the normative floor and the optional App. D.6 single-request cardinality is
 * not enforced); each
 * a `CertReqMessages` spec
 * delegated to `pki.crmf.build`; the proof-of-possession key is `key` on the arm spec), `{ p10cr }` (a PKCS#10
 * CertificationRequest DER), `{ certConf }`, `{ pollReq }`, `{ genm }`, `{ rr }`. CA/responder-side: `{ ip }` /
 * `{ cp }` / `{ kup }` / `{ ccp }` (a `CertRepMessage`: `caPubs` plus `response` of `CertResponse` each with a
 * `PKIStatusInfo` and, under a granting status, a `certifiedKeyPair`), `{ rp }` (`RevRepContent`), `{ genp }`,
 * `{ error }` (`ErrorMsgContent`), `{ pollRep }`, `{ krp }` (`KeyRecRepContent`), `{ pkiconf }` (NULL).
 * Registration-authority: `{ nested }` (an array of complete PKIMessage DER, each forwarded unchanged and
 * wrapped as `NestedMessageContent`, RFC 9810 sec. 5.1.3.5; each entry is checked to parse as a PKIMessage
 * before it is wrapped, and an empty array or an entry that does not parse is refused). The
 * message is protected: `opts` carries exactly
 * one of `{ key, cert }` (a signature under the sender key over the message, using any registry algorithm: RSA
 * / ECDSA / EdDSA / ML-DSA / SLH-DSA / composite, resolved from the certificate) or `{ mac }` (a PBMAC1
 * shared-secret MAC). The protection is computed over the exact DER of the virtual
 * `ProtectedPart ::= SEQUENCE { header, body }` and self-verified before the message is returned. An
 * embedded `p10cr` request is checked against its own proof-of-possession first: a PKCS#10 whose
 * self-signature does not verify under its subject public key is refused (`cmp/bad-popo`) rather than
 * protected and sent. The emitted PKIMessage round-trips byte-identically through `pki.schema.cmp.parse`.
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


var DEFAULT_TRANSFER_TIMEOUT = constants.TIME.seconds(30);
var MAX_TRANSFER_TIMEOUT = constants.TIME.seconds(600);
var PKIXCMP = "application/pkixcmp";
var PKIXCMP_POLL = "application/pkixcmp-poll";
var KNOWN_TRANSFER_OPTS = intrinsic.assign(intrinsic.create(null), { transport: 1, tls: 1, headers: 1, timeout: 1, maxResponseBytes: 1, proxy: 1 });

function _cmpMessageDer(input) {
  var der;
  if (guard.bytes.isByteSource(input)) der = guard.bytes.source(input, CmpError, "cmp/bad-input", "the CMP message DER");
  else if (typeof input === "string") {
    try { der = cmp.pemDecode(input); }
    catch (e) { throw _err("cmp/bad-input", "the CMP message is not a valid PEM CMP block", e); }
  } else throw _err("cmp/bad-input", "a CMP message must be a DER Buffer/Uint8Array or a PEM CMP string");
  try { cmp.parse(der); }
  catch (e) { throw _err("cmp/bad-input", "the CMP message is not a valid PKIMessage", e); }
  return der;
}

function _tlsForTransfer(opts) {
  var t = opts.tls || {};
  return { anchors: t.anchors, useSystemStore: t.useSystemStore, cert: t.cert, key: t.key, minVersion: t.minVersion, servername: t.servername, checkServerIdentity: t.checkServerIdentity };
}

function _ctypeToken(headers) { return String((headers || {})["content-type"] || "").split(";")[0].trim().toLowerCase(); }
function _isPkixcmp(headers) { var t = _ctypeToken(headers); return t === PKIXCMP || t === PKIXCMP_POLL; }

function _classifyCmpResponse(status, headers, body, tls) {
  var ctype = _ctypeToken(headers);
  if (status === 200) {
    if (!_isPkixcmp(headers)) throw _err("cmp/bad-content-type", "a 200 CMP response must be application/pkixcmp (RFC 9811 sec. 3.2), got " + JSON.stringify(ctype || null));
    if (body.length === 0) throw _err("cmp/empty-response", "a 200 CMP response carried an empty body (RFC 9811 sec. 3.3)");
    return { response: cmp.parse(body), responseBytes: body, status: 200, contentType: ctype, tls: tls };
  }
  var httpStatus = (typeof status === "number" && Number.isSafeInteger(status) && status >= 100 && status <= 599) ? status : null;
  if (httpStatus !== null && httpStatus >= 300 && httpStatus < 400) throw _err("cmp/redirect-not-followed", "a CMP " + httpStatus + " redirect is not followed (RFC 9811 sec. 3.1, sec. 5); reconfigure the endpoint URL");
  if (httpStatus !== null && httpStatus >= 400 && httpStatus <= 599) {
    if (_isPkixcmp(headers) && body.length > 0) {
      var forwarded;
      try { forwarded = cmp.parse(body); }
      catch (e) { throw _err("cmp/http-error", "the CMP server returned HTTP " + httpStatus + " with an undecodable body", e); }
      if (forwarded.body.arm !== "error") throw _err("cmp/http-error", "the CMP server returned HTTP " + httpStatus + " with a non-error '" + forwarded.body.arm + "' body; an HTTP failure forwards only a CMP error message (RFC 9811 sec. 1.2/3.1)");
      return { response: forwarded, responseBytes: body, status: httpStatus, contentType: ctype, tls: tls };
    }
    throw _err("cmp/http-error", "the CMP server returned HTTP " + httpStatus + " with no forwardable CMP error body");
  }
  throw _err("cmp/unexpected-status", "a CMP response must be HTTP 200 (or a 4xx/5xx carrying a CMP error), not " + JSON.stringify(status) + " (RFC 9811 sec. 3.1)");
}

function transfer(url, message, opts) {
  return guard.async.deferred(function () { return _transfer(url, message, opts); });
}

/** @internal Refused at the door and again where the value is used. The checked value is RETURNED
 * and it is that one the caller uses: reading the option again would ask a second time, and an
 * accessor can answer differently on each read. */
function _assertTransport(opts) {
  return guard.identifier.assertCallableOption(opts, "transport", _err, "cmp/bad-input", "opts.transport",
    "(request) => Promise<{ status, headers, body }>");
}

function _transfer(url, message, opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, KNOWN_TRANSFER_OPTS, _err, "cmp/bad-input", "unknown opts field ");
  _assertTransport(opts);
  var der = _cmpMessageDer(message);
  var parsedUrl;
  try { parsedUrl = new URL(String(url)); }
  catch (e) { throw _err("cmp/bad-url", "the CMP URL did not parse: " + guard.text.showValue(url), e); }
  var transport = _assertTransport(opts);
  if (!transport) {
    var t = opts.tls || {};
    var hasAnchors = t.anchors !== undefined && t.anchors !== null && !(Array.isArray(t.anchors) && t.anchors.length === 0);
    if (!hasAnchors && t.useSystemStore !== true) throw _err("cmp/no-trust-anchors", "no explicit trust anchor and tls.useSystemStore not set to true -- refusing an unpinned server (RFC 9811 sec. 5)");
    transport = httpTransport.https({ E: _err, errPrefix: "cmp" });
  }
  var timeout = guard.limits.cap(opts.timeout, "timeout", DEFAULT_TRANSFER_TIMEOUT, { E: _err, code: "cmp/bad-input", min: 1, max: MAX_TRANSFER_TIMEOUT });
  var maxResponseBytes = guard.limits.cap(opts.maxResponseBytes, "maxResponseBytes", constants.LIMITS.HTTP_MAX_RESPONSE_BYTES, { E: _err, code: "cmp/bad-input", min: 1, max: constants.LIMITS.HTTP_MAX_RESPONSE_BYTES });
  var proxy;
  try { proxy = httpTransport.snapshotProxy(opts.proxy); }
  catch (e) { throw _err("cmp/bad-input", "the options object could not be read", e); }
  var headers = intrinsic.create(null);
  Object.keys(opts.headers || {}).forEach(function (k) {
    var lk = k.toLowerCase();
    if (lk !== "content-length" && lk !== "transfer-encoding" && lk !== "content-type") headers[k] = opts.headers[k];
  });
  headers["content-type"] = PKIXCMP;
  var tls = _tlsForTransfer(opts);
  return guard.async.invoked(transport, [{ method: "POST", url: parsedUrl.href, headers: headers, body: der, tls: tls, proxy: proxy, timeout: timeout, maxResponseBytes: maxResponseBytes }], _err, "cmp/bad-input", "opts.transport").then(function (res) {
    res = res || {};
    var h = intrinsic.create(null);
    Object.keys(res.headers || {}).forEach(function (k) { h[k.toLowerCase()] = res.headers[k]; });
    var body = guard.bytes.isByteSource(res.body)
      ? guard.bytes.source(res.body, CmpError, "cmp/bad-response", "the CMP response body")
      : Buffer.from(String(res.body == null ? "" : res.body), "utf8");
    if (body.length > maxResponseBytes) throw _err("cmp/response-too-large", "the response body (" + body.length + " bytes) exceeds the " + maxResponseBytes + "-byte cap");
    return _classifyCmpResponse(res.status, h, body, res.tls || null);
  });
}

function _hasUnsafeSegChar(s) {
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    if (c === 0x2f || c === 0x3f || c === 0x23 || c === 0x5c || pkix.isJsWhitespace(c)) return true;
  }
  return false;
}
function _wellKnownSeg(v, name) {
  var s = String(v);
  if (s === "" || s === "." || s === ".." || _hasUnsafeSegChar(s)) throw _err("cmp/bad-url", "the CMP " + name + " must be a single safe path segment (no '/', dot-segment, or reserved char): " + JSON.stringify(s));
  try { return encodeURIComponent(s); }
  catch (e) { throw _err("cmp/bad-url", "the CMP " + name + " is not encodable (e.g. an unpaired surrogate): " + JSON.stringify(s), e); }
}

var KNOWN_WELLKNOWN_OPTS = intrinsic.assign(intrinsic.create(null), { label: 1, operation: 1 });

function _isAsciiLetter(ch) { return (ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z"); }
function _stripSchemeAuthority(s) {
  var p = 0, n = s.length;
  while (p < n && _isAsciiLetter(_charAt(s, p))) p += 1;
  if (p === 0 || _strSlice(s, p, p + 3) !== "://") return s;
  p += 3;
  while (p < n) { var ch = _charAt(s, p); if (ch === "/" || ch === "?" || ch === "#") break; p += 1; }
  return _strSlice(s, p);
}
function _beforeQueryOrFragment(s) {
  for (var i = 0; i < s.length; i++) { var ch = _charAt(s, i); if (ch === "?" || ch === "#") return _strSlice(s, 0, i); }
  return s;
}

function wellKnownUrl(base, opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, KNOWN_WELLKNOWN_OPTS, _err, "cmp/bad-input", function (k) {
    return "unknown wellKnownUrl option " + JSON.stringify(k) + " (expected label / operation)";
  });
  var u;
  try { u = new URL(String(base)); }
  catch (e) { throw _err("cmp/bad-url", "the CMP base URL did not parse: " + guard.text.showValue(base), e); }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw _err("cmp/bad-url", "the CMP base URL must be http or https (a well-known URI is authority-rooted over HTTP), got " + u.protocol + ": " + JSON.stringify(String(base)));
  if (u.search || u.hash) throw _err("cmp/bad-url", "the CMP base URL must not carry a query or fragment component (RFC 9811 sec. 3.4)");
  if (_strIndexOf(String(base), "\\") !== -1) throw _err("cmp/bad-url", "the CMP base URL must not contain a backslash (WHATWG rewrites it to a path separator): " + JSON.stringify(String(base)));
  var rawBasePath = _beforeQueryOrFragment(_stripSchemeAuthority(String(base)));
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
 * @status     stable
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
 *   - `proxy` -- reach the CA through a forward HTTP proxy (`{ url, auth?, tls? }`; see pki.transport).
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
 * @status     stable
 * @spec       RFC 9811, RFC 8615
 * @related    pki.cmp.transfer
 *
 * Build an RFC 9811 sec. 3.4 CMP request-URI under the `/.well-known/cmp` prefix (RFC 8615). The four forms:
 * `<base>/.well-known/cmp`, `.../<operation>`, `.../p/<label>`, and `.../p/<label>/<operation>`. A pure string
 * builder over an authority-rooted well-known path (RFC 8615): https vs http is left to the transport (both
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
  buildCrlStatusList: buildCrlStatusList,   // @internal
  // @internal
  samePublicKey: function (a, b) { return _b.samePublicKey(a, b); },
  // @internal
  decodeCertExtension: function (dottedOid, valueBytes) {
    var dec = EXT_DECODERS[dottedOid];
    return dec ? dec(valueBytes) : null;
  },
  // @internal
  decodeIdpDistributionPoint: decodeIdpDistributionPoint,
};
