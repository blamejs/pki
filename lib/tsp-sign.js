// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.tsp
 * @nav        Signing
 * @title      Timestamps
 * @fullname   RFC 3161 trusted timestamps: request, sign and verify
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
var intrinsic = require("./guard-intrinsic");
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var frameworkError = require("./framework-error");

var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var TspError = frameworkError.TspError;
var _NS = pkix.makeNS("tsp", TspError, oid);
var b = asn1.build;
function _err(code, message, cause) { return new TspError(code, message, cause); }

function _hasNonZeroDigit(s) {
  for (var i = 0; i < s.length; i++) { var c = _charCodeAt(s, i); if (c >= 49 && c <= 57) return true; }
  return false;
}
function O(name) { return oid.byName(name); }

var _b = pkiBuild.makeBuilder({
  ErrorClass: TspError, prefix: "tsp", O: O, NS: _NS,
  NAME_SCHEMA: pkix.name(_NS), SPKI_SCHEMA: pkix.spki(_NS),
});

var NODE_DIGEST = intrinsic.assign(intrinsic.create(null), { sha256: "sha256", sha384: "sha384", sha512: "sha512" });
var HASH_LEN = { sha256: 32, sha384: 48, sha512: 64 };

var _REVOCATION_RANK = { "false": 0, "undetermined": 1, "waived": 2, "determined": 3 };
function _rankRevocation(v) {
  var r = _REVOCATION_RANK[String(v)];
  return r === undefined ? 0 : r;
}
function _moreEstablished(candidate, current) {
  return _rankRevocation(candidate) > _rankRevocation(current);
}

function _hashAlgId(name) {
  if (!NODE_DIGEST[name]) throw _err("tsp/unsupported-algorithm", "unsupported hash algorithm " + guard.text.showValue(name));
  return b.sequence([b.oid(O(name)), b.nullValue()]);
}
function _policy(p) {
  if (typeof p !== "string") throw _err("tsp/bad-input", "the timestamp policy must be an OID name or dotted string");
  return oid.isDottedDecimal(p) ? b.oid(p) : b.oid(O(p));
}
function _certDer(c) {
  if (c == null) throw _err("tsp/bad-input", "the TSA signer requires a certificate (cert)");
  if (guard.bytes.isByteSource(c)) {
    var buf = guard.bytes.source(c, TspError, "tsp/bad-input", "the TSA certificate");
    if (buf[0] === 0x30) return buf;
    c = buf.toString("latin1");
  }
  if (typeof c !== "string") throw _err("tsp/bad-input", "the TSA certificate must be a DER BufferSource or a PEM string");
  var der = pkix.pemDecodeLenient(c, "CERTIFICATE");
  if (der === null) throw _err("tsp/bad-input", "the TSA certificate PEM is not a CERTIFICATE block");
  return der;
}

function _signingCertV2(certDer, hashName) {
  var certHash = nodeCrypto.createHash(NODE_DIGEST[hashName]).update(certDer).digest();
  var essCertId = hashName === "sha256"
    ? b.sequence([b.octetString(certHash)])
    : b.sequence([_hashAlgId(hashName), b.octetString(certHash)]);
  return b.sequence([b.sequence([essCertId])]);
}

/**
 * @primitive  pki.tsp.sign
 * @signature  pki.tsp.sign(messageImprint, tsa, opts) -> Promise<Buffer|string>
 * @since      0.2.15
 * @status     stable
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
 * @opts  accuracy      The genTime +/- accuracy, as `{ seconds?, millis?, micros? }`.
 * @opts  ordering      Whether tokens from this TSA are strictly ordered in time (boolean).
 * @opts  certHashAlgorithm  The ESSCertIDv2 hash algorithm name. Default `sha256`.
 * @opts  sid / pem     Passed through to `pki.cms.sign` (signer identifier, PEM output).
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Example TSA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     // RFC 3161 sec. 2.3: a TSA certificate's extendedKeyUsage MUST be critical
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
 *     { key: signerKeyPkcs8 });
 *   var sha256Digest = Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello")));
 *   var imprint = { hashAlgorithm: "sha256", hashedMessage: sha256Digest };
 *   var token = await pki.tsp.sign(imprint, { cert: signerCertDer, key: signerKeyPkcs8 }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   (await pki.cms.verify(token)).valid;   // true
 */
function sign(messageImprint, tsa, opts) {
  return guard.bytes.fixedCall(TspError, "tsp/bad-input", [
    [messageImprint, "the messageImprint"], [tsa, "the TSA"], [opts, "pki.tsp.sign options"],
  ], _sign);
}

var _TSA_KEYS = { cert: 1, key: 1 };
var _IMPRINT_KEYS = { hashAlgorithm: 1, hashedMessage: 1 };
var _SIGN_OPTS = {
  policy: 1, serialNumber: 1, genTime: 1, nonce: 1, accuracy: 1, ordering: 1, sid: 1,
  digestAlgorithm: 1, certHashAlgorithm: 1, additionalSignedAttributes: 1, pss: 1, pem: 1,
};

function _sign(messageImprint, tsa, opts) {
  opts = opts || {};
  if (messageImprint && typeof messageImprint === "object" && !Buffer.isBuffer(messageImprint)) {
    guard.identifier.assertKnownKeys(messageImprint, _IMPRINT_KEYS, _err, "tsp/bad-input", function (k) {
      return "unknown messageImprint field " + JSON.stringify(k) + " (the imprint is { hashAlgorithm, hashedMessage })";
    });
  }
  guard.identifier.assertKnownKeys(opts, _SIGN_OPTS, _err, "tsp/bad-input", "pki.tsp.sign has an unknown option ");
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("tsp/bad-input", "pki.tsp.sign options must be an object");
  if (tsa && typeof tsa === "object" && !Buffer.isBuffer(tsa)) {
    guard.identifier.assertKnownKeys(tsa, _TSA_KEYS, _err, "tsp/bad-input", function (k) {
      return "unknown TSA field " + JSON.stringify(k) +
        " (the TSA is { cert, key }; a signing option belongs in the third argument)";
    });
  }
  var mi = messageImprint || {};
  if (!mi.hashAlgorithm || !NODE_DIGEST[mi.hashAlgorithm]) throw _err("tsp/unsupported-algorithm", "messageImprint.hashAlgorithm must be a supported hash name");
  if (!guard.bytes.isByteSource(mi.hashedMessage)) throw _err("tsp/bad-input", "messageImprint.hashedMessage must be a BufferSource");
  var _signHmLen = guard.bytes.source(mi.hashedMessage, TspError, "tsp/bad-input", "messageImprint.hashedMessage").length;
  if (_signHmLen !== HASH_LEN[mi.hashAlgorithm]) throw _err("tsp/bad-input", "messageImprint.hashedMessage length (" + _signHmLen + ") does not match the " + mi.hashAlgorithm + " digest length (" + HASH_LEN[mi.hashAlgorithm] + ")");
  if (!opts.policy) throw _err("tsp/bad-input", "a timestamp token requires a policy identifier (opts.policy)");
  if (opts.serialNumber == null) throw _err("tsp/bad-input", "a timestamp token requires a serialNumber (opts.serialNumber)");

  var certDer = _certDer(tsa && tsa.cert);
  var certHashAlg = opts.certHashAlgorithm || "sha256";
  if (!NODE_DIGEST[certHashAlg]) throw _err("tsp/unsupported-algorithm", "unsupported certHashAlgorithm " + guard.text.showValue(certHashAlg));

  var imprint = b.sequence([_hashAlgId(mi.hashAlgorithm), b.octetString(guard.bytes.source(mi.hashedMessage, TspError, "tsp/bad-input", "messageImprint.hashedMessage"))]);
  if (opts.genTime != null) guard.time.assertValid(opts.genTime, _err, "tsp/bad-input", "genTime");
  var genTime = guard.time.isDate(opts.genTime) ? opts.genTime : new Date();
  var serial = guard.range.authoredInteger(opts.serialNumber, _err, "tsp/bad-input", "serialNumber");
  var fields = [b.integer(1n), _policy(opts.policy), imprint, b.integer(serial), b.generalizedTime(genTime)];
  if (opts.accuracy) fields.push(_accuracy(opts.accuracy));
  if (opts.ordering === true) fields.push(b.boolean(true));
  if (opts.nonce != null) fields.push(b.integer(guard.range.authoredInteger(opts.nonce, _err, "tsp/bad-input", "nonce")));
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

var _ACCURACY_KEYS = { seconds: 1, millis: 1, micros: 1 };

function _accuracy(a) {
  guard.identifier.assertKnownKeys(a, _ACCURACY_KEYS, _err, "tsp/bad-input", function (k) {
    return "unknown accuracy field " + JSON.stringify(k) + "; Accuracy is { seconds?, millis?, micros? }";
  });
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
function _subMilliBytes(n, label) {
  var v = Number(n);
  if (!Number.isInteger(v) || v < 1 || v > 999) throw _err("tsp/bad-input", "Accuracy " + label + " must be an integer in 1..999 (RFC 3161 sec. 2.4.2)");
  return b.integer(BigInt(v)).subarray(2);
}


var FAILINFO_BIT = { badAlg: 0, badRequest: 2, badDataFormat: 5, timeNotAvailable: 14, unacceptedPolicy: 15, unacceptedExtension: 16, addInfoNotAvailable: 17, systemFailure: 25 };

function _failInfoBits(names) {
  if (!Array.isArray(names)) throw _err("tsp/bad-input", "failInfo must be an array of PKIFailureInfo names");
  var idxs = names.map(function (n) {
    var i = FAILINFO_BIT[n];
    if (i == null) throw _err("tsp/bad-input", "unknown PKIFailureInfo name " + guard.text.showValue(n) + " (RFC 3161 sec. 2.4.2)");
    return i;
  });
  return b.namedBitString(idxs);
}

function _tokenDer(t) {
  if (guard.bytes.isByteSource(t)) { var u = guard.bytes.source(t, TspError, "tsp/bad-input", "the timeStampToken"); if (u[0] === 0x30) return u; }
  if (typeof t === "string") return schemaTsp.pemDecode(t);
  throw _err("tsp/bad-input", "the timeStampToken must be a DER BufferSource or a PEM string");
}

function _assertImprint(mi) {
  if (!mi.hashAlgorithm || !NODE_DIGEST[mi.hashAlgorithm]) throw _err("tsp/unsupported-algorithm", "messageImprint.hashAlgorithm must be a supported hash name");
  if (!guard.bytes.isByteSource(mi.hashedMessage)) throw _err("tsp/bad-input", "messageImprint.hashedMessage must be a BufferSource");
  var hmLen = guard.bytes.source(mi.hashedMessage, TspError, "tsp/bad-input", "messageImprint.hashedMessage").length;
  if (hmLen !== HASH_LEN[mi.hashAlgorithm]) throw _err("tsp/bad-input", "messageImprint.hashedMessage length (" + hmLen + ") does not match the " + mi.hashAlgorithm + " digest length (" + HASH_LEN[mi.hashAlgorithm] + ")");
}

/**
 * @primitive  pki.tsp.request
 * @signature  pki.tsp.request(messageImprint, opts) -> Buffer|string
 * @since      0.2.19
 * @status     stable
 * @spec       RFC 3161
 * @related    pki.tsp.parseRequest, pki.tsp.sign
 *
 * Build an RFC 3161 `TimeStampReq` (sec. 2.4.1) over `messageImprint`
 * (`{ hashAlgorithm, hashedMessage }`, the same shape `pki.tsp.sign` takes). `version` is 1;
 * `certReq` is BOOLEAN DEFAULT FALSE, so it is emitted only when explicitly `true`. Returns DER
 * (or PEM when `opts.pem`).
 *
 * @opts  reqPolicy   The requested TSA policy (an OID name or dotted string).
 * @opts  nonce       A large random nonce (number/BigInt) the client checks the token echoes.
 * @opts  certReq     Whether the TSA should include its certificate in the token (boolean).
 * @opts  extensions  An array of encoded Extension DER buffers ([0] IMPLICIT Extensions).
 * @opts  pem         Return a PEM "TIMESTAMP REQUEST" string instead of DER (boolean).
 * @example
 *   var sha256Digest = Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello")));
 *   var req = pki.tsp.request({ hashAlgorithm: "sha256", hashedMessage: sha256Digest }, { nonce: 0x0102030405060708n, certReq: true });
 */
var _REQUEST_OPTS = { reqPolicy: 1, nonce: 1, certReq: 1, extensions: 1, pem: 1 };

function request(messageImprint, opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("tsp/bad-input", "pki.tsp.request options must be an object");
  guard.identifier.assertKnownKeys(opts, _REQUEST_OPTS, _err, "tsp/bad-input", "pki.tsp.request has an unknown option ");
  var mi = messageImprint || {};
  if (mi && typeof mi === "object" && !Buffer.isBuffer(mi)) {
    guard.identifier.assertKnownKeys(mi, _IMPRINT_KEYS, _err, "tsp/bad-input", function (k) {
      return "unknown messageImprint field " + JSON.stringify(k) +
        " (the imprint is { hashAlgorithm, hashedMessage }; a request option belongs in the second argument)";
    });
  }
  _assertImprint(mi);
  var imprint = b.sequence([_hashAlgId(mi.hashAlgorithm), b.octetString(guard.bytes.source(mi.hashedMessage, TspError, "tsp/bad-input", "messageImprint.hashedMessage"))]);
  var fields = [b.integer(1n), imprint];
  if (opts.reqPolicy != null) fields.push(_policy(opts.reqPolicy));
  if (opts.nonce != null) fields.push(b.integer(guard.range.authoredInteger(opts.nonce, _err, "tsp/bad-input", "nonce")));
  if (opts.certReq != null && typeof opts.certReq !== "boolean") throw _err("tsp/bad-input", "certReq must be a boolean");
  if (opts.certReq === true) fields.push(b.boolean(true));
  if (opts.extensions != null) {
    if (!Array.isArray(opts.extensions) || !guard.list.allMatch(opts.extensions, function (e) { return guard.bytes.isByteSource(e); })) throw _err("tsp/bad-input", "extensions must be an array of encoded Extension DER buffers");
    var seenExt = {};
    var encoded = opts.extensions.map(function (e, i) {
      var der = guard.bytes.source(e, TspError, "tsp/bad-input", "an extension");
      _b.assertValidExtension(der, i);
      var extnId = asn1.read.oid(asn1.decode(der).children[0]);
      if (seenExt[extnId]) throw _err("tsp/bad-input", "duplicate request extension " + extnId + " (RFC 5280 sec. 4.2)");
      seenExt[extnId] = true;
      return der;
    });
    if (encoded.length) fields.push(b.contextConstructed(0, Buffer.concat(encoded)));
  }
  var der = b.sequence(fields);
  return opts.pem ? schemaTsp.pemEncode(der, "TIMESTAMP REQUEST") : der;
}

/**
 * @primitive  pki.tsp.parseRequest
 * @signature  pki.tsp.parseRequest(input) -> timeStampReq
 * @since      0.2.19
 * @status     stable
 * @spec       RFC 3161
 * @related    pki.tsp.request, pki.schema.tsp.parseRequest
 *
 * Parse a `TimeStampReq` (DER `Buffer` or PEM) -- the `pki.schema.tsp.parseRequest` decoder on the
 * `pki.tsp` namespace. Returns `{ version, messageImprint, reqPolicy, reqPolicyName, nonce,
 * nonceHex, certReq, extensions }`; a malformed structure throws a typed `TspError`.
 *
 * @example
 *   var der = pki.tsp.request({ hashAlgorithm: "sha256", hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello"))) },
 *     { certReq: true });
 *   var req = pki.tsp.parseRequest(der);
 *   req.certReq;   // -> boolean
 */
function parseRequest(input) { return schemaTsp.parseRequest(input); }

/**
 * @primitive  pki.tsp.response
 * @signature  pki.tsp.response(token, opts) -> Buffer|string
 * @since      0.2.19
 * @status     stable
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
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Example TSA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
 *     { key: key });
 *   var token = await pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello"))) },
 *     { cert: cert, key: key }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   var resp = pki.tsp.response(token, {});                                  // granted
 *   var rej  = pki.tsp.response(null, { status: 2, failInfo: ["badAlg"] });  // rejection
 */
var _RESPONSE_OPTS = { status: 1, statusString: 1, failInfo: 1, pem: 1 };

function response(token, opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("tsp/bad-input", "pki.tsp.response options must be an object");
  guard.identifier.assertKnownKeys(opts, _RESPONSE_OPTS, _err, "tsp/bad-input", "pki.tsp.response has an unknown option ");
  var status = opts.status == null ? 0 : Number(opts.status);
  if (!Number.isInteger(status) || status < 0 || status > 5) throw _err("tsp/bad-input", "PKIStatus must be an integer in 0..5 (RFC 3161 sec. 2.4.2)");
  var granted = status === 0 || status === 1;
  if (granted && token == null) throw _err("tsp/missing-token", "a granted TimeStampResp requires a timeStampToken (RFC 3161 sec. 2.4.2)");
  if (!granted && token != null) throw _err("tsp/unexpected-token", "a non-granted TimeStampResp must not carry a timeStampToken (RFC 3161 sec. 2.4.2)");
  var siFields = [b.integer(BigInt(status))];
  if (opts.statusString != null) {
    var texts = Array.isArray(opts.statusString) ? opts.statusString : [opts.statusString];
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
 * @status     stable
 * @spec       RFC 3161
 * @related    pki.tsp.response, pki.schema.tsp.parse
 *
 * Parse a `TimeStampResp` (DER `Buffer` or PEM) -- the shipped `pki.schema.tsp.parse` decoder on
 * the `pki.tsp` namespace. Returns `{ status, statusString, failInfo, timeStampToken }` with the
 * status-to-token coupling enforced; a granted response's token is decoded via `parseToken`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Example TSA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
 *     { key: key });
 *   var token = await pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello"))) },
 *     { cert: cert, key: key }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   var der = pki.tsp.response(token, {});
 *   var resp = pki.tsp.parseResponse(der);
 *   resp.timeStampToken.tstInfo.genTime;   // -> Date (on a granted response)
 */
function parseResponse(input) { return schemaTsp.parse(input); }


var _VERIFY_DIGEST = intrinsic.assign(intrinsic.create(null), { sha256: "sha256", sha384: "sha384", sha512: "sha512", sha1: "sha1" });
var _VERIFY_DIGEST_LEN = intrinsic.assign(intrinsic.create(null), { sha1: 20, sha256: 32, sha384: 48, sha512: 64 });
var _BIND_DIGEST = intrinsic.assign(intrinsic.create(null), { sha256: "sha256", sha384: "sha384", sha512: "sha512" });

function _imprintMatches(mi, data) {
  var name = mi.hashAlgorithm && mi.hashAlgorithm.name;
  var nodeAlg = (name && intrinsic.hasOwn(_VERIFY_DIGEST, name)) ? _VERIFY_DIGEST[name] : null;
  if (!nodeAlg) return "tsp/unsupported-algorithm";
  var wantLen = _VERIFY_DIGEST_LEN[name];
  if (mi.hashedMessage.length !== wantLen) return "tsp/imprint-mismatch";
  var actual;
  if (guard.bytes.isByteSource(data)) {
    actual = nodeCrypto.createHash(nodeAlg).update(guard.bytes.source(data, TspError, "tsp/bad-input", "data")).digest();
  } else if (data && typeof data === "object" && guard.bytes.isByteSource(data.hashedMessage)) {
    if (data.hashAlgorithm !== name) return "tsp/imprint-mismatch";
    var dhmLen = guard.bytes.source(data.hashedMessage, TspError, "tsp/bad-input", "precomputed imprint hashedMessage").length;
    if (dhmLen !== wantLen) throw _err("tsp/bad-input", "precomputed imprint hashedMessage length (" + dhmLen + ") does not match the " + name + " digest length (" + wantLen + ")");
    actual = guard.bytes.source(data.hashedMessage, TspError, "tsp/bad-input", "precomputed imprint hashedMessage");
  } else {
    throw _err("tsp/bad-input", "pki.tsp.verify data must be a Buffer or a { hashAlgorithm, hashedMessage } imprint");
  }
  return Buffer.compare(actual, Buffer.from(mi.hashedMessage)) === 0 ? true : "tsp/imprint-mismatch";
}

function _checkCertBinding(signerInfo, tsaCertDer) {
  var attrs = (signerInfo && signerInfo.signedAttrs) || [];
  var sc = null, scV1 = null;
  for (var i = 0; i < attrs.length; i++) {
    if (attrs[i].type === O("signingCertificateV2")) { sc = attrs[i]; break; }
    if (attrs[i].type === O("signingCertificate") && !scV1) scV1 = attrs[i];
  }
  if (!sc) sc = scV1;
  if (!sc) return "tsp/missing-signing-certificate";
  var decoded;
  try { decoded = smime.decodeAttribute(sc); }
  catch (_e) { return "tsp/bad-signing-certificate"; }
  var essCert = decoded.certs && decoded.certs[0];
  if (!essCert) return "tsp/bad-signing-certificate";
  var nodeAlg = essCert.hashAlgorithm && _BIND_DIGEST[essCert.hashAlgorithm.name];
  if (!nodeAlg) return "tsp/unsupported-algorithm";
  var actual = nodeCrypto.createHash(nodeAlg).update(tsaCertDer).digest();
  if (Buffer.compare(actual, Buffer.from(essCert.certHash)) !== 0) return "tsp/cert-binding-mismatch";
  if (essCert.issuerSerial) {
    var signerCert;
    try { signerCert = pkiX509.parse(tsaCertDer); }
    catch (_e) { return "tsp/bad-signing-certificate"; }
    if (essCert.issuerSerial.serialNumber !== signerCert.serialNumber) return "tsp/cert-binding-mismatch";
    var names = essCert.issuerSerial.issuer.names || [];
    var gn = null;
    try { if (names.length === 1) gn = schemaTsp.decodeGeneralName(names[0].bytes); }
    catch (_e) { return "tsp/cert-binding-mismatch"; }
    if (!gn || gn.tagNumber !== 4 || !gn.value || !guard.name.dnEqual(gn.value.rdns, signerCert.issuer.rdns, _err, "tsp/cert-binding-mismatch", "the ESSCertID issuer")) {
      return "tsp/cert-binding-mismatch";
    }
  }
  return true;
}

function _checkTsaCertUsage(tsaCertDer) {
  var cert;
  try { cert = pkiX509.parse(tsaCertDer); }
  catch (_e) { return "tsp/bad-tsa-certificate"; }
  var exts = (cert.extensions || []).filter(function (e) { return e.oid === O("extKeyUsage"); });
  if (exts.length !== 1) return "tsp/bad-eku";
  if (!exts[0].critical) return "tsp/eku-not-critical";
  var purposes, ekuNode;
  try { ekuNode = asn1.decode(exts[0].value); }
  catch (_e) { return "tsp/bad-eku"; }
  if (ekuNode.tagClass !== "universal" || ekuNode.tagNumber !== asn1.TAGS.SEQUENCE || !ekuNode.children) return "tsp/bad-eku";
  try { purposes = ekuNode.children.map(function (c) { return asn1.read.oid(c); }); }
  catch (_e) { return "tsp/bad-eku"; }
  if (purposes.length !== 1 || purposes[0] !== O("timeStamping")) return "tsp/eku-not-exclusive";
  var ku;
  try { ku = pkix.keyUsageOf(_NS, cert, _err, "tsp/bad-key-usage", "TSA certificate"); }
  catch (_e) { return "tsp/bad-key-usage"; }
  if (ku && !ku.digitalSignature && !ku.nonRepudiation) return "tsp/bad-key-usage";
  return true;
}

function _tsaMatchesCert(tsaBytes, signerCert) {
  var gn;
  try { gn = schemaTsp.decodeGeneralName(tsaBytes); }
  catch (_e) { return false; }
  if (gn.tagNumber === 4 && gn.value && guard.name.dnEqual(gn.value.rdns, signerCert.subject.rdns, _err, "tsp/tsa-mismatch", "the TSA subject")) return true;
  var sanExt = (signerCert.extensions || []).filter(function (e) { return e.oid === O("subjectAltName"); })[0];
  if (sanExt) {
    var san;
    try { san = asn1.decode(sanExt.value); }
    catch (_e) { return false; }
    if (san.tagClass === "universal" && san.tagNumber === asn1.TAGS.SEQUENCE && san.children) {
      for (var i = 0; i < san.children.length; i++) {
        if (san.children[i].bytes.equals(tsaBytes)) return true;
      }
    }
  }
  return false;
}

var MAX_TSA_CHAINS = 32;

function _buildTsaChains(leaf, pool) {
  var chains = [];
  function dfs(current, acc, used) {
    if (chains.length >= MAX_TSA_CHAINS) return;
    chains.push(acc.slice());
    for (var i = 0; i < pool.length && chains.length < MAX_TSA_CHAINS; i++) {
      if (used[i]) continue;
      if (pool[i].serialNumberHex === current.serialNumberHex && guard.name.dnEqual(pool[i].issuer.rdns, current.issuer.rdns, _err, "tsp/bad-tsa-certificate", "the TSA certificate issuer")) continue;
      if (guard.name.dnEqual(pool[i].subject.rdns, current.issuer.rdns, _err, "tsp/bad-tsa-certificate", "the TSA certificate subject")) {
        used[i] = true; acc.push(pool[i]);
        dfs(pool[i], acc, used);
        acc.pop(); used[i] = false;
      }
    }
  }
  dfs(leaf, [leaf], []);
  return chains.map(function (c) { return c.slice().reverse(); }).sort(function (a, b) { return b.length - a.length; });
}

/**
 * @primitive  pki.tsp.verify
 * @signature  pki.tsp.verify(token, data, opts) -> Promise<result>
 * @since      0.2.19
 * @status     stable
 * @spec       RFC 3161, RFC 5816
 * @related    pki.tsp.sign, pki.cms.verify, pki.path.validate
 *
 * Verify an RFC 3161 TimeStampToken against the data it should cover. `token` is the token DER /
 * PEM, never a parsed object: every checked field is read from the CMS-verified eContent, so a
 * mutated parsed structure cannot desynchronize the checks from the signed bytes. `data` is the
 * original bytes (hashed under the token's messageImprint algorithm) or a precomputed
 * `{ hashAlgorithm, hashedMessage }`. Returns `{ valid, trusted, revocationChecked,
 * anchorConstraints, genTime, accuracy, serialNumber,
 * serialNumberHex, policy, nonce, tsa, tstInfo, signer, code?, reason? }`. `valid` is true only
 * when the CMS signature, the imprint match, the eContentType, the ESSCertID(V2) binding, the
 * RFC 3161 sec. 2.3 critical single-`timeStamping` extendedKeyUsage rule, the requested nonce (when
 * supplied), and, when `trustAnchors` is supplied, the full out-of-path TSA-cert path
 * validation all pass. A conformance / trust failure of a well-formed token is a
 * `{ valid:false, code }` verdict; malformed or config input throws a typed `TspError`.
 *
 * `trusted` is the second claim and is kept apart from the first. `valid` says the token's
 * signature and structural bindings hold; `trusted` says the timestamp authority chained to an
 * anchor this caller named. Without `trustAnchors` there is nothing to chain to and `trusted` is
 * `false`: every branch, refusing and accepting alike, carries the field with a definite
 * value. A timestamp is archived precisely to be re-read years later, and one boolean
 * cannot answer both questions then.
 *
 * `revocationChecked` is the third claim, for the same reason. Revocation runs only when a
 * `revocationChecker` is supplied. Without a field naming which happened, a `trusted` token whose
 * TSA was never checked against a CRL or an OCSP responder reads identically to one established
 * un-revoked. It is `false` whenever no path ran at all. `anchorConstraints` carries whatever the anchor
 * itself constrained, from `pki.path.validate`.
 *
 * @opts  trustAnchors  Anchor `{ name, publicKey, algorithm }`, or a non-empty array of them. Runs
 *                       `pki.path.validate` on the TSA certificate chain from the token's certificates
 *                       (validity at genTime, requiredEku timeStamping, and revocation when a
 *                       `revocationChecker` is supplied, with `revocationChecked` reporting which),
 *                       so a TSA under an intermediate CA validates, not only one directly under
 *                       the anchor. Omit to verify signature + imprint + binding + EKU only and
 *                       anchor the cert yourself.
 * @opts  nonce         Require the token's TSTInfo.nonce to equal this (a number/BigInt).
 * @opts  reqPolicy     Require the token's policy to equal this (an OID name or dotted string).
 * @opts  certs         Out-of-band TSA certificates (an array of DER `Buffer`s) added to the signer
 *                      candidates and the path pool, so a cert-less token (the TSA omits its
 *                      certificate when `certReq` was false) and an intermediate absent from the
 *                      token can still verify and chain.
 * @opts  revocationChecker  Passed through to `pki.path.validate`.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Example TSA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
 *     { key: signerKeyPkcs8 });
 *   var sha256Digest = Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", Buffer.from("hello")));
 *   var imprint = { hashAlgorithm: "sha256", hashedMessage: sha256Digest };
 *   var token = await pki.tsp.sign(imprint, { cert: signerCertDer, key: signerKeyPkcs8 }, { policy: "1.3.6.1.4.1.1", serialNumber: 1 });
 *   var res = await pki.tsp.verify(token, Buffer.from("hello"), {});
 *   res.valid;     // boolean; pass opts.trustAnchors to also chain the TSA cert to a root
 *   res.genTime;   // Date, read from the verified eContent
 */
var _VERIFY_OPTS = { certs: 1, trustAnchors: 1, nonce: 1, reqPolicy: 1, revocationChecker: 1 };

function _anyCritical(extensions) {
  return guard.list.anyMatches(extensions, function (e) { return !!e && !!e.critical; });
}

async function verify(token, data, opts) {
  opts = opts || {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw _err("tsp/bad-input", "pki.tsp.verify options must be an object");
  guard.identifier.assertKnownKeys(opts, _VERIFY_OPTS, _err, "tsp/bad-input",
    "pki.tsp.verify has an unknown option (the anchor option is `trustAnchors`) ");
  if (opts.certs != null && (!Array.isArray(opts.certs) || !guard.list.allMatch(opts.certs, function (c) { return guard.bytes.isByteSource(c); }))) {
    throw _err("tsp/bad-input", "pki.tsp.verify opts.certs must be an array of DER certificate Buffers");
  }
  var tokenDer = _tokenDer(token);
  var parsed = schemaTsp.parseToken(tokenDer);
  var tst = parsed.tstInfo;
  var revocationChecked = false;
  var anchorConstraints = null;
  function fail(code, reason) {
    return { valid: false, trusted: false, revocationChecked: revocationChecked, anchorConstraints: anchorConstraints, code: code, reason: reason || null, genTime: tst.genTime, accuracy: tst.accuracy, serialNumber: tst.serialNumber, serialNumberHex: tst.serialNumberHex, policy: tst.policy, nonce: tst.nonce, tsa: tst.tsa, tstInfo: tst, signer: null };
  }
  var cmsRes = await cmsVerify.verify(tokenDer, { certs: opts.certs });
  var signer = cmsRes.signers[0];
  if (!cmsRes.valid) return fail("tsp/bad-signature", signer && (signer.code || signer.message));
  var tsaCertDer = signer && signer.cert;
  if (!tsaCertDer) return fail("tsp/bad-signature", "the TSA signer certificate was not found");
  var mi = _imprintMatches(tst.messageImprint, data);
  if (mi !== true) return fail(mi);
  if (opts.nonce != null) {
    var wantNonce = guard.range.authoredInteger(opts.nonce, _err, "tsp/bad-input", "opts.nonce");
    if (tst.nonce == null || tst.nonce !== wantNonce) return fail("tsp/nonce-mismatch");
  }
  if (opts.reqPolicy != null) {
    var wantPolicy = oid.isDottedDecimal(opts.reqPolicy) ? opts.reqPolicy : O(opts.reqPolicy);
    if (tst.policy !== wantPolicy) return fail("tsp/policy-mismatch");
  }
  if (tst.extensions && _anyCritical(tst.extensions)) {
    return fail("tsp/unknown-critical-extension");
  }
  var bind = _checkCertBinding(parsed.signerInfo, tsaCertDer);
  if (bind !== true) return fail(bind);
  var usage = _checkTsaCertUsage(tsaCertDer);
  if (usage !== true) return fail(usage);
  if (tst.tsa) {
    var sc;
    try { sc = pkiX509.parse(tsaCertDer); }
    catch (_e) { return fail("tsp/bad-tsa-certificate"); }
    if (!_tsaMatchesCert(tst.tsa.bytes, sc)) return fail("tsp/tsa-mismatch");
  }
  var trusted = false;
  if (opts.trustAnchors) {
    var pathRes = null;
    var floorT = tst.genTime;
    var ceilT = (tst.genTimeFraction != null && _hasNonZeroDigit(tst.genTimeFraction.slice(3))) ? new Date(guard.time.instantOf(floorT) + 1) : floorT;
    try {
      var pool = (parsed.certificates || []).filter(function (c) { return c.tagClass === "universal"; }).map(function (c) { return pkiX509.parse(c.bytes); });
      (opts.certs || []).forEach(function (c) { pool.push(pkiX509.parse(c)); });
      async function validateAt(chain, when) {
        var res = await pathValidate.validate(chain, {
          time: when, trustAnchors: opts.trustAnchors, requiredEku: ["timeStamping"], checkPurpose: "timeStamping", revocationChecker: opts.revocationChecker,
        });
        if (_moreEstablished(res.revocationChecked, revocationChecked)) revocationChecked = res.revocationChecked;
        if (anchorConstraints == null && res.anchorConstraints != null) anchorConstraints = res.anchorConstraints;
        return res;
      }
      var chains = _buildTsaChains(pkiX509.parse(tsaCertDer), pool);
      for (var ci = 0; ci < chains.length && !(pathRes && pathRes.valid); ci++) {
        pathRes = await validateAt(chains[ci], floorT);
        if (pathRes.valid && ceilT !== floorT) pathRes = await validateAt(chains[ci], ceilT);
      }
    } catch (e) { return fail("tsp/untrusted-tsa", (e && e.message) || String(e)); }
    if (!pathRes || !pathRes.valid) return fail("tsp/untrusted-tsa", "the TSA certificate did not validate to the trust anchor at genTime");
    revocationChecked = pathRes.revocationChecked;
    anchorConstraints = pathRes.anchorConstraints;
    trusted = true;
  }
  return {
    valid: true, trusted: trusted, revocationChecked: revocationChecked, anchorConstraints: anchorConstraints,
    genTime: tst.genTime, accuracy: tst.accuracy,
    serialNumber: tst.serialNumber, serialNumberHex: tst.serialNumberHex,
    policy: tst.policy, policyName: tst.policyName, nonce: tst.nonce, tsa: tst.tsa,
    tstInfo: tst, signer: { cert: tsaCertDer, sid: signer.sid },
  };
}

module.exports = { sign: sign, request: request, parseRequest: parseRequest, response: response, parseResponse: parseResponse, verify: verify };
