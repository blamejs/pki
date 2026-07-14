// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.tsp
 * @nav        Signing
 * @title      Timestamps
 * @intro Create an RFC 3161 timestamp token. A TimeStampToken IS a CMS SignedData whose
 *   encapsulated content is a `TSTInfo` (the timestamped message imprint + trusted time), so
 *   `sign(messageImprint, tsa, opts)` builds the `TSTInfo`, attaches the RFC 3161 sec. 2.4.2
 *   signing-certificate attribute that binds the token to the TSA certificate, and signs it
 *   through `pki.cms.sign`. It is the producing side of `pki.schema.tsp.parseToken`.
 * @spec RFC 3161
 * @card Create an RFC 3161 timestamp token (a CMS SignedData over a TSTInfo).
 */

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var cmsSign = require("./cms-sign");
var cmsVerify = require("./cms-verify");
var pathValidate = require("./path-validate");
var pkiX509 = require("./schema-x509");
var smime = require("./schema-smime");
var schemaTsp = require("./schema-tsp");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");

var TspError = frameworkError.TspError;
var b = asn1.build;
function _err(code, message, cause) { return new TspError(code, message, cause); }
function O(name) { return oid.byName(name); }

// Digest names whose imprint / certHash this producer supports (the SHA-2 family).
var NODE_DIGEST = { sha256: "sha256", sha384: "sha384", sha512: "sha512" };
// The message-imprint hash MUST be exactly the digest algorithm's output length (RFC 3161 sec.
// 2.4.1 -- hashedMessage is "the hash of the datum to be time-stamped").
var HASH_LEN = { sha256: 32, sha384: 48, sha512: 64 };

// A hash AlgorithmIdentifier { OID, NULL } -- messageImprint and ESSCertIDv2 hash algorithms
// carry an explicit NULL parameter (the form RFC 3161 / RFC 5035 producers emit).
function _hashAlgId(name) {
  if (!NODE_DIGEST[name]) throw _err("tsp/unsupported-algorithm", "unsupported hash algorithm " + JSON.stringify(name));
  return b.sequence([b.oid(O(name)), b.nullValue()]);
}
// A policy identifier: an OID name or a dotted-decimal string.
function _policy(p) {
  if (typeof p !== "string") throw _err("tsp/bad-input", "the timestamp policy must be an OID name or dotted string");
  return /^\d+(\.\d+)+$/.test(p) ? b.oid(p) : b.oid(O(p));
}
// The signer certificate DER (DER Buffer / PEM string / Uint8Array) -- for the ESSCertIDv2 hash.
function _certDer(c) {
  if (c == null) throw _err("tsp/bad-input", "the TSA signer requires a certificate (cert)");
  if (c instanceof Uint8Array && !Buffer.isBuffer(c)) c = Buffer.from(c);          // a Uint8Array -> Buffer
  if (Buffer.isBuffer(c)) { if (c[0] === 0x30) return c; c = c.toString("latin1"); }   // DER as-is, else decode as PEM
  if (typeof c !== "string") throw _err("tsp/bad-input", "the TSA certificate must be a DER Buffer or a PEM string");
  var m = c.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  if (!m) throw _err("tsp/bad-input", "the TSA certificate PEM is not a CERTIFICATE block");
  return Buffer.from(m[1].replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
}

// The RFC 5035 SigningCertificateV2 signed-attribute value binding the token to the TSA cert:
// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }, ESSCertIDv2 ::= SEQUENCE {
// hashAlgorithm DEFAULT sha256, certHash OCTET STRING, issuerSerial OPTIONAL }. The default
// sha256 hashAlgorithm is omitted; certHash is the digest of the certificate.
function _signingCertV2(certDer, hashName) {
  var certHash = nodeCrypto.createHash(NODE_DIGEST[hashName]).update(certDer).digest();
  var essCertId = hashName === "sha256"
    ? b.sequence([b.octetString(certHash)])                       // hashAlgorithm DEFAULT sha256 omitted
    : b.sequence([_hashAlgId(hashName), b.octetString(certHash)]);
  return b.sequence([b.sequence([essCertId])]);
}

/**
 * @primitive  pki.tsp.sign
 * @signature  pki.tsp.sign(messageImprint, tsa, opts) -> Promise<Buffer|string>
 * @since      0.2.15
 * @status     experimental
 * @spec       RFC 3161
 * @related    pki.schema.tsp.parseToken, pki.cms.sign
 *
 * Create an RFC 3161 TimeStampToken over `messageImprint` (`{ hashAlgorithm, hashedMessage }`
 * -- the hash of the data being timestamped, computed by the requester). `tsa` is the
 * timestamp authority's `{ cert, key }` (as `pki.cms.sign` takes them). The token is a CMS
 * SignedData whose content is a `TSTInfo` carrying the imprint, the TSA policy, a serial
 * number, and `genTime`; the RFC 3161 sec. 2.4.2 signing-certificate attribute binding the
 * token to the TSA certificate is attached automatically.
 *
 * @opts  policy        REQUIRED -- the TSA policy identifier (an OID name or dotted string).
 * @opts  serialNumber  REQUIRED -- a unique token serial number (a number or BigInt).
 * @opts  genTime       The trusted time (a `Date`). Default: now.
 * @opts  nonce         The request nonce to echo (a number or BigInt), for replay protection.
 * @opts  accuracy      `{ seconds?, millis?, micros? }` -- the genTime +/- accuracy.
 * @opts  ordering      Whether tokens from this TSA are strictly ordered in time (boolean).
 * @opts  certHashAlgorithm  The ESSCertIDv2 hash algorithm name. Default `sha256`.
 * @opts  sid / pem     Passed through to `pki.cms.sign` (signer identifier, PEM output).
 * @example
 *   var imprint = { hashAlgorithm: "sha256", hashedMessage: sha256Digest };
 *   var token = await pki.tsp.sign(imprint, { cert: signerCertDer, key: signerKeyPkcs8 }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   (await pki.cms.verify(token)).valid;   // true
 */
function sign(messageImprint, tsa, opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("tsp/bad-input", "pki.tsp.sign options must be an object");
  var mi = messageImprint || {};
  if (!mi.hashAlgorithm || !NODE_DIGEST[mi.hashAlgorithm]) throw _err("tsp/unsupported-algorithm", "messageImprint.hashAlgorithm must be a supported hash name");
  if (!Buffer.isBuffer(mi.hashedMessage) && !(mi.hashedMessage instanceof Uint8Array)) throw _err("tsp/bad-input", "messageImprint.hashedMessage must be a Buffer");
  if (mi.hashedMessage.length !== HASH_LEN[mi.hashAlgorithm]) throw _err("tsp/bad-input", "messageImprint.hashedMessage length (" + mi.hashedMessage.length + ") does not match the " + mi.hashAlgorithm + " digest length (" + HASH_LEN[mi.hashAlgorithm] + ")");
  if (!opts.policy) throw _err("tsp/bad-input", "a timestamp token requires a policy identifier (opts.policy)");
  if (opts.serialNumber == null) throw _err("tsp/bad-input", "a timestamp token requires a serialNumber (opts.serialNumber)");

  var certDer = _certDer(tsa && tsa.cert);
  var certHashAlg = opts.certHashAlgorithm || "sha256";
  if (!NODE_DIGEST[certHashAlg]) throw _err("tsp/unsupported-algorithm", "unsupported certHashAlgorithm " + JSON.stringify(certHashAlg));

  // TSTInfo (RFC 3161 sec. 2.4.2): version(1), policy, messageImprint, serialNumber, genTime,
  // then the OPTIONAL accuracy / ordering / nonce in ascending order.
  var imprint = b.sequence([_hashAlgId(mi.hashAlgorithm), b.octetString(Buffer.from(mi.hashedMessage))]);
  // genTime defaults to now; a supplied value MUST be a valid Date (never a silently-ignored
  // non-Date or an Invalid Date that would encode a garbage GeneralizedTime).
  if (opts.genTime != null && (!(opts.genTime instanceof Date) || isNaN(opts.genTime.getTime()))) {
    throw _err("tsp/bad-input", "genTime must be a valid Date");
  }
  var genTime = opts.genTime instanceof Date ? opts.genTime : new Date();
  var fields = [b.integer(1n), _policy(opts.policy), imprint, b.integer(BigInt(opts.serialNumber)), b.generalizedTime(genTime)];
  if (opts.accuracy) fields.push(_accuracy(opts.accuracy));
  if (opts.ordering === true) fields.push(b.boolean(true));
  if (opts.nonce != null) fields.push(b.integer(BigInt(opts.nonce)));
  var tstInfo = b.sequence(fields);

  var signCert = { type: "signingCertificateV2", values: [_signingCertV2(certDer, certHashAlg)] };
  var extra = [signCert].concat(opts.additionalSignedAttributes || []);
  var signer = { cert: certDer, key: tsa && tsa.key, digestAlgorithm: opts.digestAlgorithm, pss: opts.pss };
  return cmsSign.sign(tstInfo, signer, {
    eContentType: "tSTInfo",
    additionalSignedAttributes: extra,
    sid: opts.sid,
    pem: opts.pem,
  });
}

// Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER (1..999) OPTIONAL,
// micros [1] INTEGER (1..999) OPTIONAL } (RFC 3161 sec. 2.4.2). seconds is a non-negative
// integer; millis and micros MUST each be in 1..999 -- enforced before encoding.
function _accuracy(a) {
  var f = [];
  if (a.seconds != null) {
    var s = Number(a.seconds);
    if (!Number.isInteger(s) || s < 0 || s > 0x7fffffff) throw _err("tsp/bad-input", "Accuracy seconds must be a non-negative integer");
    f.push(b.integer(BigInt(s)));
  }
  if (a.millis != null) f.push(b.contextPrimitive(0, _subMilliBytes(a.millis, "millis")));
  if (a.micros != null) f.push(b.contextPrimitive(1, _subMilliBytes(a.micros, "micros")));
  return b.sequence(f);
}
// The content octets of an Accuracy millis/micros field: an INTEGER in 1..999 (RFC 3161 sec.
// 2.4.2), without the universal INTEGER tag (the field is IMPLICIT [0]/[1]).
function _subMilliBytes(n, label) {
  var v = Number(n);
  if (!Number.isInteger(v) || v < 1 || v > 999) throw _err("tsp/bad-input", "Accuracy " + label + " must be an integer in 1..999 (RFC 3161 sec. 2.4.2)");
  return b.integer(BigInt(v)).subarray(2);               // strip the universal INTEGER tag+length
}

// Coverage residual -- `_hashAlgId`'s unsupported-hash throw is unreachable through the shipped
// path: both callers (the messageImprint hash and the ESSCertIDv2 certHashAlgorithm) validate
// the name against NODE_DIGEST before `_hashAlgId` runs, so the guard is belt-and-suspenders.

// PKIFailureInfo name -> NamedBitList bit index (RFC 3161 sec. 2.4.2; the reverse of the
// schema-tsp FAILURE_BITS decode map). Build maps names -> bits; an unknown name fails closed.
var FAILINFO_BIT = { badAlg: 0, badRequest: 2, badDataFormat: 5, timeNotAvailable: 14, unacceptedPolicy: 15, unacceptedExtension: 16, addInfoNotAvailable: 17, systemFailure: 25 };

// Encode a PKIFailureInfo as a minimal DER NamedBitList BIT STRING from a set of names: set each
// named bit (bit 0 = MSB of byte 0), strip trailing zero octets, and place unusedBits exactly
// below the lowest set bit (X.690 sec. 11.2.2).
function _failInfoBits(names) {
  if (!Array.isArray(names)) throw _err("tsp/bad-input", "failInfo must be an array of PKIFailureInfo names");
  var idxs = names.map(function (n) {
    var i = FAILINFO_BIT[n];
    if (i == null) throw _err("tsp/bad-input", "unknown PKIFailureInfo name " + JSON.stringify(n) + " (RFC 3161 sec. 2.4.2)");
    return i;
  });
  if (!idxs.length) return b.bitString(Buffer.alloc(0), 0);          // no bits -> empty BIT STRING
  // buf is sized to the highest set bit, so its last octet always carries that bit (non-zero) --
  // there is never a trailing zero octet to strip; only the trailing zero BITS of the last octet
  // are removed, via the DER unusedBits count (X.690 sec. 11.2.2).
  var buf = Buffer.alloc((Math.max.apply(null, idxs) >> 3) + 1);
  idxs.forEach(function (i) { buf[i >> 3] |= 0x80 >> (i & 7); });
  var unused = 0, last = buf[buf.length - 1];
  while (unused < 7 && ((last >> unused) & 1) === 0) unused++;       // unusedBits below the lowest set bit
  return b.bitString(buf, unused);
}

// Coerce a timeStampToken (a CMS ContentInfo the token producer emits) to DER for embedding in a
// TimeStampResp -- a DER Buffer as-is, a Uint8Array copied, or a PEM string de-armored.
function _tokenDer(t) {
  if (Buffer.isBuffer(t) && t[0] === 0x30) return t;
  if (t instanceof Uint8Array && !Buffer.isBuffer(t)) { var u = Buffer.from(t); if (u[0] === 0x30) return u; }
  if (typeof t === "string") return schemaTsp.pemDecode(t);
  throw _err("tsp/bad-input", "the timeStampToken must be a DER Buffer or a PEM string");
}

function _assertImprint(mi) {
  if (!mi.hashAlgorithm || !NODE_DIGEST[mi.hashAlgorithm]) throw _err("tsp/unsupported-algorithm", "messageImprint.hashAlgorithm must be a supported hash name");
  if (!Buffer.isBuffer(mi.hashedMessage) && !(mi.hashedMessage instanceof Uint8Array)) throw _err("tsp/bad-input", "messageImprint.hashedMessage must be a Buffer");
  if (mi.hashedMessage.length !== HASH_LEN[mi.hashAlgorithm]) throw _err("tsp/bad-input", "messageImprint.hashedMessage length (" + mi.hashedMessage.length + ") does not match the " + mi.hashAlgorithm + " digest length (" + HASH_LEN[mi.hashAlgorithm] + ")");
}

/**
 * @primitive  pki.tsp.request
 * @signature  pki.tsp.request(messageImprint, opts) -> Buffer|string
 * @since      0.2.19
 * @status     experimental
 * @spec       RFC 3161
 * @related    pki.tsp.parseRequest, pki.tsp.sign
 *
 * Build an RFC 3161 `TimeStampReq` (sec. 2.4.1) over `messageImprint`
 * (`{ hashAlgorithm, hashedMessage }` -- the same shape `pki.tsp.sign` takes). `version` is 1;
 * `certReq` is BOOLEAN DEFAULT FALSE, so it is emitted only when explicitly `true`. Returns DER
 * (or PEM when `opts.pem`).
 *
 * @opts  reqPolicy   The requested TSA policy (an OID name or dotted string).
 * @opts  nonce       A large random nonce (number/BigInt) the client checks the token echoes.
 * @opts  certReq     Whether the TSA should include its certificate in the token (boolean).
 * @opts  extensions  An array of encoded Extension DER buffers ([0] IMPLICIT Extensions).
 * @opts  pem         Return a PEM "TIMESTAMP REQUEST" string instead of DER (boolean).
 * @example
 *   var req = pki.tsp.request({ hashAlgorithm: "sha256", hashedMessage: sha256Digest }, { nonce: 0x0102030405060708n, certReq: true });
 */
function request(messageImprint, opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("tsp/bad-input", "pki.tsp.request options must be an object");
  var mi = messageImprint || {};
  _assertImprint(mi);
  var imprint = b.sequence([_hashAlgId(mi.hashAlgorithm), b.octetString(Buffer.from(mi.hashedMessage))]);
  // TimeStampReq: version(1), messageImprint, then OPTIONAL reqPolicy / nonce / certReq /
  // extensions in schema order. certReq DEFAULT FALSE -> only an explicit TRUE is encoded (DER).
  var fields = [b.integer(1n), imprint];
  if (opts.reqPolicy != null) fields.push(_policy(opts.reqPolicy));
  if (opts.nonce != null) fields.push(b.integer(BigInt(opts.nonce)));
  if (opts.certReq != null && typeof opts.certReq !== "boolean") throw _err("tsp/bad-input", "certReq must be a boolean");
  if (opts.certReq === true) fields.push(b.boolean(true));
  if (opts.extensions != null) {
    if (!Array.isArray(opts.extensions) || !opts.extensions.every(function (e) { return Buffer.isBuffer(e) || e instanceof Uint8Array; })) throw _err("tsp/bad-input", "extensions must be an array of encoded Extension DER buffers");
    if (opts.extensions.length) fields.push(b.contextConstructed(0, Buffer.concat(opts.extensions.map(function (e) { return Buffer.from(e); }))));
  }
  var der = b.sequence(fields);
  return opts.pem ? schemaTsp.pemEncode(der, "TIMESTAMP REQUEST") : der;
}

/**
 * @primitive  pki.tsp.parseRequest
 * @signature  pki.tsp.parseRequest(input) -> timeStampReq
 * @since      0.2.19
 * @status     experimental
 * @spec       RFC 3161
 * @related    pki.tsp.request, pki.schema.tsp.parseRequest
 *
 * Parse a `TimeStampReq` (DER `Buffer` or PEM) -- the `pki.schema.tsp.parseRequest` decoder on the
 * `pki.tsp` namespace. Returns `{ version, messageImprint, reqPolicy, reqPolicyName, nonce,
 * nonceHex, certReq, extensions }`; a malformed structure throws a typed `TspError`.
 *
 * @example
 *   var req = pki.tsp.parseRequest(der);
 *   req.certReq;   // -> boolean
 */
function parseRequest(input) { return schemaTsp.parseRequest(input); }

/**
 * @primitive  pki.tsp.response
 * @signature  pki.tsp.response(token, opts) -> Buffer|string
 * @since      0.2.19
 * @status     experimental
 * @spec       RFC 3161
 * @related    pki.tsp.parseResponse, pki.tsp.sign
 *
 * Build an RFC 3161 `TimeStampResp` (sec. 2.4.2): a `PKIStatusInfo` and, on success, the
 * `timeStampToken`. Pass a `token` (the CMS ContentInfo `pki.tsp.sign` produces) with the default
 * granted status, or build a rejection with `response(null, { status, failInfo, statusString })`.
 * The status-to-token coupling is enforced (granted 0/1 carries a token, any other status must not),
 * mirroring the parse-side gate. Returns DER (or PEM when `opts.pem`).
 *
 * @opts  status        PKIStatus 0..5 (default 0 granted). granted(0)/grantedWithMods(1) carry a token.
 * @opts  failInfo      Array of PKIFailureInfo names (only on rejection(2)): e.g. ["badAlg"].
 * @opts  statusString  Human-readable PKIFreeText (string or array of strings).
 * @opts  pem           Return a PEM "TIMESTAMP RESPONSE" string instead of DER (boolean).
 * @example
 *   var resp = pki.tsp.response(token, {});                                  // granted
 *   var rej  = pki.tsp.response(null, { status: 2, failInfo: ["badAlg"] });  // rejection
 */
function response(token, opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("tsp/bad-input", "pki.tsp.response options must be an object");
  var status = opts.status == null ? 0 : Number(opts.status);
  if (!Number.isInteger(status) || status < 0 || status > 5) throw _err("tsp/bad-input", "PKIStatus must be an integer in 0..5 (RFC 3161 sec. 2.4.2)");
  var granted = status === 0 || status === 1;
  if (granted && token == null) throw _err("tsp/missing-token", "a granted TimeStampResp requires a timeStampToken (RFC 3161 sec. 2.4.2)");
  if (!granted && token != null) throw _err("tsp/unexpected-token", "a non-granted TimeStampResp must not carry a timeStampToken (RFC 3161 sec. 2.4.2)");
  var siFields = [b.integer(BigInt(status))];
  if (opts.statusString != null) {
    var texts = Array.isArray(opts.statusString) ? opts.statusString : [opts.statusString];
    // PKIFreeText is SEQUENCE SIZE (1..MAX) OF UTF8String -- an empty statusString would build an
    // empty SEQUENCE the parser (seqOf min:1) rejects, so reject it at the builder instead.
    if (!texts.length) throw _err("tsp/bad-input", "statusString must carry at least one PKIFreeText element (RFC 4210 SEQUENCE SIZE 1..MAX)");
    siFields.push(b.sequence(texts.map(function (t) { return b.utf8(String(t)); })));
  }
  if (opts.failInfo != null) {
    if (status !== 2) throw _err("tsp/unexpected-failinfo", "failInfo is present only when the status is rejection(2) (RFC 3161 sec. 2.4.2)");
    siFields.push(_failInfoBits(opts.failInfo));
  }
  var respFields = [b.sequence(siFields)];
  if (token != null) respFields.push(b.raw(_tokenDer(token)));
  var der = b.sequence(respFields);
  return opts.pem ? schemaTsp.pemEncode(der, "TIMESTAMP RESPONSE") : der;
}

/**
 * @primitive  pki.tsp.parseResponse
 * @signature  pki.tsp.parseResponse(input) -> timeStampResp
 * @since      0.2.19
 * @status     experimental
 * @spec       RFC 3161
 * @related    pki.tsp.response, pki.schema.tsp.parse
 *
 * Parse a `TimeStampResp` (DER `Buffer` or PEM) -- the shipped `pki.schema.tsp.parse` decoder on
 * the `pki.tsp` namespace. Returns `{ status, statusString, failInfo, timeStampToken }` with the
 * status-to-token coupling enforced; a granted response's token is decoded via `parseToken`.
 *
 * @example
 *   var resp = pki.tsp.parseResponse(der);
 *   resp.timeStampToken.tstInfo.genTime;   // -> Date (on a granted response)
 */
function parseResponse(input) { return schemaTsp.parse(input); }

// Coverage residual -- the null-guards and decode/parse catches in the verify helpers below are
// belt-and-suspenders on values already guaranteed upstream, so their failure arms are unreachable
// through the shipped path: parseToken has already proven the token is a single-signer SignedData
// carrying a signing-certificate attribute, so `signerInfo`/`signedAttrs`/the signing-cert attr are
// present; cms.verify returns a parsed, matched signer certificate, so `tsaCertDer` is set and
// re-parsing it (or decoding its extensions) cannot fail here; decodeAttribute yields at least one
// ESSCertID (an empty SEQUENCE OF is rejected at decode -> the `!essCert` guard is defensive); and
// path.validate returns a fail-closed verdict for a bad anchor rather than throwing, so its catch
// is defensive. Likewise, in the out-of-path chain step, `parsed.certificates` is always an array
// (empty when absent), the embedded certs the chain walk parses are the X.509 (universal) choices,
// and guard.name.dnEqual's control-byte reject is defensive on a cert x509.parse already accepted --
// so the `|| []`, the non-universal filter arm, and that throw are unreachable through the shipped
// path. A malformed ESS value IS reachable (a signed-but-broken attribute) and IS covered; the
// reachable verdicts (unsupported hash, EKU shape/wrapper, keyUsage, imprint/nonce/policy/binding
// mismatch, untrusted TSA, embedded-chain ordering) are each driven by a RED conformance vector.

// The imprint / ESSCertID hash algorithms a verifier can recompute: the SHA-2 family, plus SHA-1
// for MATCHING a legacy token's imprint (a verify-side digest, never a signing choice). An unknown
// or weak (e.g. MD5) algorithm cannot be recomputed, so the check fails closed rather than assume.
var _VERIFY_DIGEST = { sha256: "sha256", sha384: "sha384", sha512: "sha512", sha1: "sha1" };

// M10 -- recompute the imprint over `data` under the token's messageImprint hash algorithm (read
// from the verified eContent) and compare to hashedMessage. `data` is raw bytes (hashed) or a
// precomputed { hashAlgorithm, hashedMessage } (algorithm-exact + byte-exact). Returns true or a
// tsp/* verdict code; a config-shape error throws (the caller's contract).
function _imprintMatches(mi, data) {
  var name = mi.hashAlgorithm && mi.hashAlgorithm.name;
  var nodeAlg = name && _VERIFY_DIGEST[name];
  if (!nodeAlg) return "tsp/unsupported-algorithm";   // cannot recompute -> never assume a match
  var actual;
  if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
    actual = nodeCrypto.createHash(nodeAlg).update(Buffer.from(data)).digest();
  } else if (data && typeof data === "object" && (Buffer.isBuffer(data.hashedMessage) || data.hashedMessage instanceof Uint8Array)) {
    if (data.hashAlgorithm !== name) return "tsp/imprint-mismatch";   // a precomputed imprint under a different algorithm
    actual = Buffer.from(data.hashedMessage);
  } else {
    throw _err("tsp/bad-input", "pki.tsp.verify data must be a Buffer or a { hashAlgorithm, hashedMessage } imprint");
  }
  return Buffer.compare(actual, Buffer.from(mi.hashedMessage)) === 0 ? true : "tsp/imprint-mismatch";
}

// M13 -- the token MUST be bound to the exact signer certificate via the ESS SigningCertificate(V2)
// signed attribute (RFC 3161 sec. 2.4.2 / RFC 5816): recompute hash(tsaCertDer) under the
// ESSCertID(V2) hashAlgorithm (v1 implies SHA-1, v2 defaults SHA-256) and compare to certHash.
function _checkCertBinding(signerInfo, tsaCertDer) {
  var attrs = (signerInfo && signerInfo.signedAttrs) || [];
  var sc = null;
  for (var i = 0; i < attrs.length; i++) {
    if (attrs[i].type === O("signingCertificateV2") || attrs[i].type === O("signingCertificate")) { sc = attrs[i]; break; }
  }
  if (!sc) return "tsp/missing-signing-certificate";   // parseToken guarantees presence; belt-and-suspenders
  var decoded;
  try { decoded = smime.decodeAttribute(sc); }
  catch (_e) { return "tsp/bad-signing-certificate"; }
  var essCert = decoded.certs && decoded.certs[0];
  if (!essCert) return "tsp/bad-signing-certificate";
  var nodeAlg = essCert.hashAlgorithm && _VERIFY_DIGEST[essCert.hashAlgorithm.name];
  if (!nodeAlg) return "tsp/unsupported-algorithm";
  var actual = nodeCrypto.createHash(nodeAlg).update(tsaCertDer).digest();
  if (Buffer.compare(actual, Buffer.from(essCert.certHash)) !== 0) return "tsp/cert-binding-mismatch";
  // RFC 5035 sec. 5: if the ESSCertID(V2) carries the OPTIONAL issuerSerial, it MUST identify the
  // signer certificate -- confirm its serialNumber. The certHash already pins the exact cert
  // cryptographically; the serialNumber is that cert's unambiguous identity field.
  if (essCert.issuerSerial) {
    var signerCert;
    try { signerCert = pkiX509.parse(tsaCertDer); }
    catch (_e) { return "tsp/bad-signing-certificate"; }
    if (essCert.issuerSerial.serialNumber !== signerCert.serialNumber) return "tsp/cert-binding-mismatch";
  }
  return true;
}

// M11 -- RFC 3161 sec. 2.3: the TSA certificate MUST contain exactly ONE extendedKeyUsage instance
// whose sole KeyPurposeID is id-kp-timeStamping, and that extension MUST be CRITICAL. path.validate's
// requiredEku only checks the purpose is ASSERTED (an absent EKU is unrestricted), so this
// single-purpose + critical gate is layered on top -- the OCSP-delegate precedent for a format gate
// above the path checks. Additionally (RFC 5280 sec. 4.2.1.3) a keyUsage extension, if present, MUST
// permit signing for the cert to sign the token. Returns true or a tsp/* code.
function _checkTsaCertUsage(tsaCertDer) {
  var cert;
  try { cert = pkiX509.parse(tsaCertDer); }
  catch (_e) { return "tsp/bad-tsa-certificate"; }
  var exts = (cert.extensions || []).filter(function (e) { return e.oid === O("extKeyUsage"); });
  if (exts.length !== 1) return "tsp/bad-eku";   // absent, or a duplicate extension (RFC 5280 -- one instance)
  if (!exts[0].critical) return "tsp/eku-not-critical";
  var purposes, ekuNode;
  try { ekuNode = asn1.decode(exts[0].value); }
  catch (_e) { return "tsp/bad-eku"; }
  // the extnValue MUST be a universal SEQUENCE OF KeyPurposeId -- a non-SEQUENCE constructed wrapper
  // (e.g. a SET) carrying OID children would otherwise slip through the bare children walk.
  if (ekuNode.tagClass !== "universal" || ekuNode.tagNumber !== asn1.TAGS.SEQUENCE || !ekuNode.children) return "tsp/bad-eku";
  try { purposes = ekuNode.children.map(function (c) { return asn1.read.oid(c); }); }
  catch (_e) { return "tsp/bad-eku"; }
  if (purposes.length !== 1 || purposes[0] !== O("timeStamping")) return "tsp/eku-not-exclusive";
  // A keyUsage that forbids signing cannot mint a token (RFC 5280 sec. 4.2.1.3); an absent keyUsage
  // is unrestricted. Require digitalSignature (bit 0) or nonRepudiation/contentCommitment (bit 1) --
  // the signing bits, the TSA analogue of the OCSP-responder keyUsage gate.
  var kuExts = (cert.extensions || []).filter(function (e) { return e.oid === O("keyUsage"); });
  if (kuExts.length) {
    var ku;
    try { ku = asn1.read.bitString(asn1.decode(kuExts[0].value)); }
    catch (_e) { return "tsp/bad-key-usage"; }
    var byte0 = ku.bytes.length ? ku.bytes[0] : 0;
    if (!((byte0 >> 7) & 1) && !((byte0 >> 6) & 1)) return "tsp/bad-key-usage";   // no digitalSignature / nonRepudiation
  }
  return true;
}

// Build the ordered certification path for path.validate from the token's embedded certificates:
// walk from the TSA leaf up through each issuer found among the embedded certs (its subject DN
// equals the working issuer DN) to the top embedded cert -- the trust anchor validates that one --
// then return the path in RFC 5280 sec. 6.1 order (anchor-issued cert first, the leaf last). A cert
// is never chained to itself (the serialNumberHex guard); the walk is bounded by the pool size.
// Token-local ordering only; full path building from a trust store is pki.path's separate concern.
function _orderTsaChain(leaf, pool) {
  var chain = [leaf], used = [], current = leaf;
  for (var depth = 0; depth < pool.length; depth++) {
    var next = -1;
    for (var i = 0; i < pool.length; i++) {
      if (used[i] || pool[i].serialNumberHex === current.serialNumberHex) continue;
      if (guard.name.dnEqual(pool[i].subject.rdns, current.issuer.rdns, TspError, "tsp/bad-tsa-certificate")) { next = i; break; }
    }
    if (next < 0) break;
    used[next] = true; current = pool[next]; chain.push(current);
  }
  return chain.reverse();   // path.validate takes the path anchor-down: highest issuer first, leaf last
}

/**
 * @primitive  pki.tsp.verify
 * @signature  pki.tsp.verify(token, data, opts) -> Promise<result>
 * @since      0.2.19
 * @status     experimental
 * @spec       RFC 3161, RFC 5816
 * @related    pki.tsp.sign, pki.cms.verify, pki.path.validate
 *
 * Verify an RFC 3161 TimeStampToken against the data it should cover. `token` is the token DER /
 * PEM (never a parsed object -- every checked field is read from the CMS-verified eContent, so a
 * mutated parsed structure cannot desynchronize the checks from the signed bytes). `data` is the
 * original bytes (hashed under the token's messageImprint algorithm) or a precomputed
 * `{ hashAlgorithm, hashedMessage }`. Returns `{ valid, genTime, accuracy, serialNumber,
 * serialNumberHex, policy, nonce, tsa, tstInfo, signer, code?, reason? }`. `valid` is true only
 * when the CMS signature, the imprint match, the eContentType, the ESSCertID(V2) binding, the
 * RFC 3161 sec. 2.3 critical single-`timeStamping` extendedKeyUsage rule, the requested nonce (when
 * supplied), and -- when a `trustAnchor` is supplied -- the full out-of-path TSA-cert path
 * validation all pass. A conformance / trust failure of a well-formed token is a
 * `{ valid:false, code }` verdict; malformed or config input throws a typed `TspError`.
 *
 * @opts  trustAnchor   Anchor `{ name, publicKey, algorithm }` -- runs `pki.path.validate` on the
 *                       TSA certificate chain ordered from the token's embedded certificates
 *                       (validity at genTime, requiredEku timeStamping, revocation), so a TSA under
 *                       an intermediate CA validates, not only one directly under the anchor. Omit
 *                       to verify signature + imprint + binding + EKU only and anchor the cert yourself.
 * @opts  nonce         Require the token's TSTInfo.nonce to equal this (a number/BigInt).
 * @opts  reqPolicy     Require the token's policy to equal this (an OID name or dotted string).
 * @opts  revocationChecker  Passed through to `pki.path.validate`.
 * @example
 *   var imprint = { hashAlgorithm: "sha256", hashedMessage: sha256Digest };
 *   var token = await pki.tsp.sign(imprint, { cert: signerCertDer, key: signerKeyPkcs8 }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   var res = await pki.tsp.verify(token, Buffer.from("hello"), {});
 *   res.valid;     // boolean; pass opts.trustAnchor to also chain the TSA cert to a root
 *   res.genTime;   // Date, read from the verified eContent
 */
async function verify(token, data, opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("tsp/bad-input", "pki.tsp.verify options must be an object");
  var tokenDer = _tokenDer(token);   // DER Buffer / PEM -> DER; a non-token input throws tsp/bad-input
  // M7 -- parseToken enforces the SignedData + id-ct-TSTInfo + single-signer + signing-cert-present
  // structure and decodes the TSTInfo FROM the raw eContent; a structural defect throws.
  var parsed = schemaTsp.parseToken(tokenDer);
  var tst = parsed.tstInfo;
  function fail(code, reason) {
    return { valid: false, code: code, reason: reason || null, genTime: tst.genTime, accuracy: tst.accuracy, serialNumber: tst.serialNumber, serialNumberHex: tst.serialNumberHex, policy: tst.policy, nonce: tst.nonce, tsa: tst.tsa, tstInfo: tst, signer: null };
  }
  // M12 -- the CMS signature over the exact RFC 5652 sec. 5.4 preimage (message-digest bound to the
  // authenticated eContent). cms.verify re-parses the same bytes; a failure is a fail-closed verdict.
  var cmsRes = await cmsVerify.verify(tokenDer);
  var signer = cmsRes.signers[0];
  if (!cmsRes.valid) return fail("tsp/bad-signature", signer && (signer.code || signer.message));
  var tsaCertDer = signer && signer.cert;
  if (!tsaCertDer) return fail("tsp/bad-signature", "the TSA signer certificate was not found");
  // M10 -- what was timestamped MUST correspond to the data (imprint recompute + match).
  var mi = _imprintMatches(tst.messageImprint, data);
  if (mi !== true) return fail(mi);
  // M14 -- if a request nonce is supplied, the token MUST echo it (BigInt-exact).
  if (opts.nonce != null) {
    var wantNonce = BigInt(opts.nonce);
    if (tst.nonce == null || tst.nonce !== wantNonce) return fail("tsp/nonce-mismatch");
  }
  // M15 -- if the requested policy is supplied, the token's policy MUST equal it.
  if (opts.reqPolicy != null) {
    var wantPolicy = /^\d+(\.\d+)+$/.test(opts.reqPolicy) ? opts.reqPolicy : O(opts.reqPolicy);
    if (tst.policy !== wantPolicy) return fail("tsp/policy-mismatch");
  }
  // M13 -- the ESSCertID(V2) binding: the verifying cert MUST be the one the signer identified.
  var bind = _checkCertBinding(parsed.signerInfo, tsaCertDer);
  if (bind !== true) return fail(bind);
  // M11 -- the RFC 3161 sec. 2.3 critical single-timeStamping EKU gate + the keyUsage-permits-signing check.
  var usage = _checkTsaCertUsage(tsaCertDer);
  if (usage !== true) return fail(usage);
  // M18 -- full out-of-path TSA-cert validation (issuer-sig, validity at genTime, unknown-critical,
  // key-param inheritance, requiredEku, optional revocation), only when a trustAnchor is supplied.
  // The path is ordered from the token's embedded certificates (leaf + any intermediates), so a TSA
  // issued under an intermediate CA -- not just directly under the anchor -- validates.
  if (opts.trustAnchor) {
    var pathRes;
    try {
      // parseToken surfaces each embedded cert as { bytes, tagClass, ... }; take the X.509 certs
      // (universal SEQUENCE), skipping any attribute-certificate choices, and parse their raw bytes.
      var pool = (parsed.certificates || []).filter(function (c) { return c.tagClass === "universal"; }).map(function (c) { return pkiX509.parse(c.bytes); });
      pathRes = await pathValidate.validate(_orderTsaChain(pkiX509.parse(tsaCertDer), pool), {
        time: tst.genTime, trustAnchor: opts.trustAnchor, requiredEku: ["timeStamping"], revocationChecker: opts.revocationChecker,
      });
    } catch (e) { return fail("tsp/untrusted-tsa", (e && e.message) || String(e)); }
    if (!pathRes.valid) return fail("tsp/untrusted-tsa", "the TSA certificate did not validate to the trust anchor at genTime");
  }
  return {
    valid: true, genTime: tst.genTime, accuracy: tst.accuracy,
    serialNumber: tst.serialNumber, serialNumberHex: tst.serialNumberHex,
    policy: tst.policy, policyName: tst.policyName, nonce: tst.nonce, tsa: tst.tsa,
    tstInfo: tst, signer: { cert: tsaCertDer, sid: signer.sid },
  };
}

module.exports = { sign: sign, request: request, parseRequest: parseRequest, response: response, parseResponse: parseResponse, verify: verify };
