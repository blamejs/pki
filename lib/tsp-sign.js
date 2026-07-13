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
  if (Buffer.isBuffer(c)) { if (c[0] === 0x30) return c; c = c.toString("latin1"); }
  else if (c instanceof Uint8Array) return Buffer.from(c);
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
module.exports = { sign: sign };
