// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.ocsp
 * @nav        Revocation
 * @title      OCSP
 * @fullname   OCSP (Online Certificate Status Protocol) revocation checking
 * @intro The producing + client-facing half of RFC 6960 Online Certificate Status Protocol:
 *   build a status request over a certificate (`pki.ocsp.buildRequest`), build and sign a status
 *   response as an authorized responder (`pki.ocsp.sign`), emit an unsigned error response
 *   (`pki.ocsp.buildErrorResponse`), and verify a returned response as a relying party
 *   (`pki.ocsp.verify`). Parsing lives in `pki.schema.ocsp`; revocation during path validation is
 *   `pki.path.ocspChecker`. Signing rides the shared sign-scheme registry (the same classical +
 *   post-quantum set `pki.cms.sign` uses), so a response is signed under RSA / ECDSA / EdDSA /
 *   ML-DSA / SLH-DSA per the responder key. Verification composes the same hardened responder-
 *   authorization, signature and currency gates `pki.path.ocspChecker` runs; there is no weaker
 *   second verify path. Fail-closed: `verify` returns a `"unknown"` verdict (never a silent accept)
 *   for any unmet gate, with one scoped exception: a request-nonce mismatch downgrades only a
 *   `good` to `"unknown"`, leaving a signed, current, authorized `revoked` reported as `revoked`
 *   with `nonceMatched: false` (see `verify`). Malformed input throws a typed `OcspError`.
 * @spec RFC 6960, RFC 9654, RFC 5019
 * @card Build, sign, and verify RFC 6960 OCSP requests + responses (a responder + a relying party).
 */

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var pkiBuild = require("./pki-build");
var oid = require("./oid");
var x509 = require("./schema-x509");
var ocspSchema = require("./schema-ocsp");
var crlSchema = require("./schema-crl");
var pathValidate = require("./path-validate");
var signScheme = require("./sign-scheme");
var ocspVerify = require("./ocsp-verify");
var ocspRequestVerify = require("./ocsp-request-verify");
var webcrypto = require("./webcrypto");
var subtle = webcrypto.webcrypto.subtle;
var guard = require("./guard-all");
var constants = require("./constants");
var frameworkError = require("./framework-error");

var OcspError = frameworkError.OcspError;
var b = asn1.build;
function O(name) { return oid.byName(name); }
function _err(code, message, cause) { return new OcspError(code, message, cause); }
function _signE(kind, message, cause) { return new OcspError("ocsp/" + kind, message, cause); }

var HASH_WC = Object.assign(Object.create(null), { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" });
var REASON_CODE = Object.create(null);
Object.keys(constants.NAMES.CRL_REASON).forEach(function (k) { REASON_CODE[constants.NAMES.CRL_REASON[k]] = parseInt(k, 10); });
var OID_OCSP_NONCE = O("ocspNonce");
var OID_OCSP_BASIC = O("ocspBasic");
var OID_EXTENDED_REVOKE = O("ocspExtendedRevoke");
var OID_OCSP_CRL = O("ocspCrl");
var EXTENSION_PLACEMENT = ocspSchema.extensionPlacement(oid);
var ENTRY_EXTENSION_CRITICALITY = crlSchema.entryExtensionCriticality(oid);
var CERTIFICATE_HOLD = REASON_CODE.certificateHold, REMOVE_FROM_CRL = REASON_CODE.removeFromCRL;
var OID_REASON_CODE = O("reasonCode");

function _digest(wcHash, buf) { return subtle.digest(wcHash, buf).then(function (h) { return Buffer.from(h); }); }
function _certOf(arg, what) {
  var label = what || "a certificate";
  return guard.parsed.acceptDerived(arg, "certificate", function (bytes) {
    var der = bytes;
    if (typeof bytes === "string") {
      try { der = x509.pemDecode(bytes); } catch (e) { throw _err("ocsp/bad-input", label + " PEM could not be decoded", e); }
    }
    try { return x509.parse(der); } catch (e) { throw _err("ocsp/bad-input", label + " is not a well-formed X.509 certificate", e); }
  }, _err, "ocsp/bad-input", label);
}
var _RESPONSE_CLAIM = ["responseStatus", "basicResponse", "tbsResponseDataBytes"];
function _responseFromBytes(response) {
  return guard.parsed.fromTrustedSource(response, "ocspResponse", _RESPONSE_CLAIM, function (bytes) {
    return ocspSchema.parseResponse(_toDer(bytes, "the OCSP response"));
  }, _err, "ocsp/bad-input",
  "the OCSP response must be its DER bytes, a PEM string, or an unmodified pki.schema.ocsp.parseResponse result: the signature, the algorithm that verifies it and the bytes it covers are separate properties of a parsed object, so a REBUILT response (Object.assign, spread, a JSON round-trip) could have the three describe different responses and is refused");
}

function _toDer(input, what) {
  if (guard.bytes.isByteSource(input)) return guard.bytes.snapshotSource(input, OcspError, "ocsp/bad-input", what || "input");
  if (typeof input === "string") { try { return ocspSchema.pemDecode(input); } catch (e) { throw _err("ocsp/bad-input", (what || "input") + " PEM could not be decoded", e); } }
  throw _err("ocsp/bad-input", (what || "input") + " must be a DER Buffer, Uint8Array, or PEM string");
}
function _keyValue(spkiDer) { return ocspVerify.ocspKeyValue(spkiDer); }
function _nonceExt(nonceBytes) { return b.sequence([b.oid(OID_OCSP_NONCE), b.octetString(b.octetString(nonceBytes))]); }
/** @internal RFC 9654 sec. 2.1 bounds a nonce at 1..128 octets, and adds for the requester: "An OCSP
 *  requester that implements the extension in this document MUST use a minimum length of 32
 *  octets". A responder echoes what it was sent, so its floor stays at the section's 1. */
function _assertNonce(nonceBytes, floor) {
  if (!Buffer.isBuffer(nonceBytes) || nonceBytes.length < floor || nonceBytes.length > 128) {
    throw _err("ocsp/bad-input", "a nonce must be a Buffer of " + floor + "..128 octets (RFC 9654 sec. 2.1)");
  }
}
var REQUESTER_NONCE_FLOOR = 32, RESPONDER_NONCE_FLOOR = 1;
function _buildCertID(cert, issuer, hashName) {
  var wc = HASH_WC[guard.text.keyOf(hashName)];
  if (!wc) throw _err("ocsp/bad-input", "unsupported CertID hashAlgorithm " + guard.text.showValue(hashName) + " (sha1 / sha256 / sha384 / sha512)");
  return Promise.all([
    _digest(wc, issuer.subject.bytes),
    _digest(wc, _keyValue(issuer.subjectPublicKeyInfo.bytes)),
  ]).then(function (hashes) {
    var hashAlgId = hashName === "sha1" ? b.sequence([b.oid(O(hashName)), b.nullValue()]) : b.sequence([b.oid(O(hashName))]);
    return b.sequence([
      hashAlgId,
      b.octetString(hashes[0]),
      b.octetString(hashes[1]),
      b.integer(cert.serialNumber),
    ]);
  });
}

/**
 * @primitive pki.ocsp.buildRequest
 * @signature pki.ocsp.buildRequest(query, opts?) -> Buffer | string
 * @since 0.2.22
 * @status stable
 * @spec RFC 6960, RFC 9654, RFC 5019
 * @related pki.ocsp.verify, pki.schema.ocsp.parseRequest
 *
 * Build an OCSPRequest for the status of one or more certificates. `query` is a `{ cert, issuer }`
 * pair (or an array of them), each certificate given parsed or as DER/PEM; the CertID is derived by
 * hashing the issuer name and key under `opts.hashAlgorithm` (SHA-1 by default, the RFC 5019 interop
 * choice). The version DEFAULT (v1) is omitted from the DER. Returns the request DER, or PEM when
 * `opts.pem` is set.
 *
 * @opts
 *   hashAlgorithm  `"sha1"` (default) / `"sha256"` / `"sha384"` / `"sha512"`; the CertID identity hash.
 *   nonce          `true` for a fresh 32-octet CSPRNG nonce (RFC 9654), or a caller Buffer of 32..128
 *                  octets (RFC 9654 sec. 2.1: a requester MUST use at least 32).
 *   requestorName  a Name (DER `BufferSource`, or a parsed Name) placed in the [1] requestorName as a
 *                  directoryName. With `signer`, the signer certificate's subject is taken when none
 *                  is stated (RFC 6960 sec. 4.1.2: a requestor that signs SHALL specify its name).
 *   signer         `{ cert, key }` to sign the request.
 *   profile        `"lightweight"`: one Request, SHA-1 CertID, nonce-only extensions (RFC 5019).
 *   pem            emit a PEM `OCSP REQUEST` string instead of DER.
 * @example
 *   var ca = await pki.key.generate("Ed25519");
 *   var caKey = await pki.key.export(ca.privateKey);
 *   var caDer = await pki.x509.sign({ subject: "Example CA", subjectPublicKey: await pki.key.export(ca.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } }, { key: caKey });
 *   var leaf = await pki.key.generate("Ed25519");
 *   var leafDer = await pki.x509.sign({ subject: "leaf.example", subjectPublicKey: await pki.key.export(leaf.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { cert: caDer, key: caKey });
 *   var der = await pki.ocsp.buildRequest({ cert: leafDer, issuer: caDer }, { nonce: true });
 */
function buildRequest(query, opts) {
  return guard.bytes.fixedCall(OcspError, "ocsp/bad-input", [
    [query, "the OCSP request query"], [opts, "pki.ocsp.buildRequest options"],
  ], _buildRequest);
}

var _BUILD_REQUEST_OPTS = Object.assign(Object.create(null), {
  hashAlgorithm: 1, nonce: 1, pem: 1, profile: 1, requestorName: 1, signer: 1
});
var _QUERY_KEYS = Object.assign(Object.create(null), { cert: 1, issuer: 1, singleRequestExtensions: 1 });
var _REQUEST_SIGNER_KEYS = Object.assign(Object.create(null), { cert: 1, key: 1 });

function _buildRequest(query, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "ocsp/bad-input", "pki.ocsp.buildRequest options");
  guard.identifier.assertKnownKeys(opts, _BUILD_REQUEST_OPTS, _err, "ocsp/bad-input",
    "pki.ocsp.buildRequest has an unknown option (the anti-replay nonce is `nonce`): ");
  var lightweight = opts.profile === "lightweight";
  var hashName = opts.hashAlgorithm || "sha1";
  if (lightweight && hashName !== "sha1") throw _err("ocsp/bad-input", "the lightweight profile requires a SHA-1 CertID (RFC 5019 sec. 2.1.1)");
  var queries = Array.isArray(query) ? pkiBuild.reqDenseArray(query, "queries", _err, "ocsp/bad-input") : [query];
  if (!queries.length) throw _err("ocsp/bad-input", "buildRequest needs at least one { cert, issuer } query");
  if (lightweight && queries.length !== 1) throw _err("ocsp/bad-input", "the lightweight profile permits exactly one Request (RFC 5019 sec. 2.1.1)");
  var signerCertDer = null, signerCert = null;
  if (opts.signer) {
    guard.identifier.assertKnownKeys(opts.signer, _REQUEST_SIGNER_KEYS, _err, "ocsp/bad-input", "unknown request signer field (the signer is { cert, key }): ");
    signerCertDer = _normCertDer(opts.signer.cert, "the request signer certificate");
    signerCert = _certOf(signerCertDer, "the request signer certificate");
  }
  /** @internal Sec. 4.1.2: "If the request is signed, the requestor SHALL specify its name in the
   *  requestorName field." The signer certificate names the requestor, so its subject is the name
   *  when none is stated. A certificate with an empty subject names its holder in a critical
   *  subjectAltName (RFC 5280 sec. 4.1.2.6); an empty Name names nobody, so it is not derived. */
  var requestorNameDer = null;
  if (opts.requestorName != null) requestorNameDer = _nameDer(opts.requestorName);
  else if (signerCert !== null) {
    if (!signerCert.subject.rdns.length) throw _err("ocsp/bad-input", "the request signer certificate has an empty subject, so no requestorName can be taken from it; state requestorName (RFC 6960 sec. 4.1.2)");
    requestorNameDer = signerCert.subject.bytes;
  }

  return Promise.all(queries.map(function (q) {
    if (!q || typeof q !== "object") throw _err("ocsp/bad-input", "each query must be { cert, issuer }");
    guard.identifier.assertKnownKeys(q, _QUERY_KEYS, _err, "ocsp/bad-input", "unknown query field (a query is { cert, issuer, singleRequestExtensions? }): ");
    if (q.cert == null || q.issuer == null) throw _err("ocsp/bad-input", "each query must be { cert, issuer }");
    var cert = _certOf(q.cert, "the query certificate");
    var issuer = _certOf(q.issuer, "the issuer certificate");
    return _buildCertID(cert, issuer, hashName).then(function (certID) {
      var reqChildren = [certID];
      if (q.singleRequestExtensions && q.singleRequestExtensions.length) {
        if (lightweight) throw _err("ocsp/bad-input", "the lightweight profile permits no singleRequestExtensions (RFC 5019 sec. 2.1.1)");
        reqChildren.push(b.explicit(0, b.sequence(q.singleRequestExtensions)));
      }
      return b.sequence(reqChildren);
    });
  })).then(function (requests) {
    var tbsChildren = [];
    if (requestorNameDer !== null) tbsChildren.push(b.explicit(1, b.contextConstructed(4, requestorNameDer)));
    tbsChildren.push(b.sequence(requests));
    var reqExts = [];
    if (opts.nonce) {
      var nonceBytes = opts.nonce === true ? nodeCrypto.randomBytes(32) : opts.nonce;
      _assertNonce(nonceBytes, REQUESTER_NONCE_FLOOR);
      reqExts.push(_nonceExt(nonceBytes));
    }
    if (reqExts.length) tbsChildren.push(b.explicit(2, b.sequence(reqExts)));
    var tbsRequest = b.sequence(tbsChildren);
    if (signerCert === null) return _emitReq(b.sequence([tbsRequest]), opts);
    var scheme = signScheme.resolveSignScheme(signerCert, { combinedRsaSig: true }, true, _signE);
    return signScheme.signOverTbs(scheme, opts.signer.key, tbsRequest, _signE).then(function (sig) {
      var optionalSignature = b.sequence([scheme.sigAlgId, b.bitString(sig, 0), b.explicit(0, b.sequence([b.raw(signerCertDer)]))]);
      return _emitReq(b.sequence([tbsRequest, b.explicit(0, optionalSignature)]), opts);
    });
  });
}
function _emitReq(der, opts) { return opts.pem ? ocspSchema.pemEncode(der, "OCSP REQUEST") : der; }
function _nameDer(name) {
  if (guard.bytes.isByteSource(name)) return guard.bytes.snapshotSource(name, OcspError, "ocsp/bad-input", "requestorName");
  if (name && name.bytes) return name.bytes;
  throw _err("ocsp/bad-input", "requestorName must be a DER Name BufferSource or a parsed Name");
}
function _normCertDer(cert, what) {
  if (guard.bytes.isByteSource(cert)) return guard.bytes.snapshotSource(cert, OcspError, "ocsp/bad-input", what || "a certificate");
  if (typeof cert === "string") { try { return x509.pemDecode(cert); } catch (e) { throw _err("ocsp/bad-input", (what || "a certificate") + " PEM could not be decoded", e); } }
  if (cert && cert.tbsBytes && cert.subjectPublicKeyInfo) {
    throw _err("ocsp/bad-input", (what || "a certificate") + " to embed must be supplied as DER bytes or a PEM string, not a parsed certificate (the parser does not retain the full DER encoding needed to embed it verbatim)");
  }
  throw _err("ocsp/bad-input", (what || "a certificate") + " must be a DER Buffer, Uint8Array, or PEM string");
}

/**
 * @primitive pki.ocsp.sign
 * @signature pki.ocsp.sign(responseData, responder, opts?) -> Promise<Buffer | string>
 * @since 0.2.22
 * @status stable
 * @spec RFC 6960, RFC 9654
 * @related pki.ocsp.verify, pki.ocsp.buildErrorResponse
 *
 * Build and sign a `successful` OCSPResponse wrapping a BasicOCSPResponse. `responseData` names the
 * responderID, an optional producedAt, and one or more per-certificate responses; `responder` is the
 * `{ cert, key }` signing the response (the issuing CA directly, or a CA-issued delegate bearing
 * id-kp-OCSPSigning + id-pkix-ocsp-nocheck). The signature is computed over the exact ResponseData
 * DER (RFC 6960 sec. 4.2.1: no CMS wrapper, no signed attributes). The responder certificate is
 * embedded in `certs [0]` so a relying party can find it. Returns the response DER, or PEM.
 *
 * Each response may carry `singleExtensions`, as an object or as an array of pre-encoded Extension
 * DER. The object form takes `archiveCutoff`, the Date before which the responder no longer holds
 * status (RFC 6960 sec. 4.4.4), and `crlReferences`, a `{ crlUrl, crlNum, crlTime }` naming the CRL
 * the status was drawn from (sec. 4.4.2), any subset of the three. A pre-encoded entry is read with
 * the parser's own singleExtensions reader before it is emitted, so a response this verb signs is
 * one `pki.schema.ocsp.parseResponse` reads back, and a malformed archiveCutoff or CrlID is refused
 * here with the code the parser would have raised. A pre-encoded entry is also held to where RFC
 * 6960 places it: the request-only extensions (sec. 4.4.3, 4.4.6, 4.4.7) and the two a response
 * carries in responseExtensions alone (the extended revoked definition, sec. 4.4.8, and the RFC 9654
 * nonce) are refused in singleExtensions, and a CRL entry extension carried here (sec. 4.4.5) keeps
 * the criticality RFC 5280 sec. 5.3 fixes for it.
 *
 * A "revoked" status for a non-issued certificate (revocationReason certificateHold at
 * 1970-01-01T00:00:00Z, sec. 2.2) places the extended revoked definition in responseExtensions
 * whether or not `opts.extendedRevoke` names it, refuses `extendedRevoke: false`, and refuses CRL
 * references or any CRL entry extension on that SingleResponse.
 *
 * @opts
 *   nonce           a request nonce Buffer to echo back in responseExtensions (RFC 9654).
 *   extendedRevoke  emit the id-pkix-ocsp-extended-revoke extension (RFC 6960 sec. 4.4.8); implied
 *                   by a non-issued response, where `false` is refused.
 *   embedCert       `false` to omit certs [0] (a direct-CA response the client already trusts).
 *   pem             emit a PEM `OCSP RESPONSE` string instead of DER.
 * @example
 *   var ca = await pki.key.generate("Ed25519");
 *   var responderPkcs8 = await pki.key.export(ca.privateKey);
 *   // the issuing CA responds directly here, so its own certificate is the responder's
 *   var caDer = await pki.x509.sign({ subject: "Example CA", subjectPublicKey: await pki.key.export(ca.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } },
 *     { key: responderPkcs8 });
 *   var responderCertDer = caDer;
 *   var leaf = await pki.key.generate("Ed25519");
 *   var leafDer = await pki.x509.sign({ subject: "leaf.example", subjectPublicKey: await pki.key.export(leaf.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { cert: caDer, key: responderPkcs8 });
 *   var resp = await pki.ocsp.sign(
 *     { responderID: "byName", responses: [{ cert: leafDer, issuer: caDer, status: "good" }] },
 *     { cert: responderCertDer, key: responderPkcs8 });
 */
function sign(responseData, responder, opts) {
  return guard.bytes.fixedCall(OcspError, "ocsp/bad-input", [
    [responseData, "the OCSP responseData"], [responder, "the responder"], [opts, "pki.ocsp.sign options"],
  ], _sign);
}

var _SIGN_OPTS = Object.assign(Object.create(null), { embedCert: 1, extendedRevoke: 1, nonce: 1, pem: 1 });
var _RESPONSE_DATA_KEYS = Object.assign(Object.create(null), { responderID: 1, responses: 1, producedAt: 1 });
var _SINGLE_RESPONSE_KEYS = Object.assign(Object.create(null), { cert: 1, issuer: 1, certID: 1, hashAlgorithm: 1, status: 1, thisUpdate: 1, nextUpdate: 1, singleExtensions: 1 });
var _RESPONDER_KEYS = Object.assign(Object.create(null), { cert: 1, key: 1 });
var _STATUS_KEYS = Object.assign(Object.create(null), { revoked: 1, revocationReason: 1 });

function _sign(responseData, responder, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "ocsp/bad-input", "pki.ocsp.sign options");
  guard.identifier.assertKnownKeys(opts, _SIGN_OPTS, _err, "ocsp/bad-input",
    "pki.ocsp.sign has an unknown option (the nonce to echo back is `nonce`): ");
  responseData = responseData || {};
  if (typeof responseData !== "object") throw _err("ocsp/bad-input", "the responseData must be an object { responderID, responses, producedAt? }");
  guard.identifier.assertKnownKeys(responseData, _RESPONSE_DATA_KEYS, _err, "ocsp/bad-input", "unknown responseData field (accepted: responderID, responses, producedAt): ");
  if (!responder || typeof responder !== "object") throw _err("ocsp/bad-input", "a responder must be { cert, key }");
  guard.identifier.assertKnownKeys(responder, _RESPONDER_KEYS, _err, "ocsp/bad-input", "unknown responder field (the responder is { cert, key }; a signing option belongs in the third argument): ");
  if (responder.cert == null || responder.key == null) throw _err("ocsp/bad-input", "a responder must be { cert, key }");
  var respCertDer = _normCertDer(responder.cert, "the responder certificate");
  var respCert = _certOf(respCertDer, "the responder certificate");
  var ownedKeyBytes = [];
  var responderKey = _snapshotSignerKey(responder.key, ownedKeyBytes);
  function _wipeOwnedKey() {
    if (ownedKeyBytes.length) guard.secret.zeroizeAll(ownedKeyBytes, OcspError, "ocsp/bad-input", "the responder key copy");
    ownedKeyBytes.length = 0;
  }
  var pending;
  try {
    pending = _signResponse(responseData, responder, respCert, respCertDer, responderKey, opts);
  } catch (e) { _wipeOwnedKey(); throw e; }
  return pending.then(function (out) { _wipeOwnedKey(); return out; },
    function (e) { _wipeOwnedKey(); throw e; });
}

function _signResponse(responseData, responder, respCert, respCertDer, responderKey, opts) {
  var responses = responseData.responses != null ? pkiBuild.reqDenseArray(responseData.responses, "responses", _err, "ocsp/bad-input") : [];
  if (!responses.length) throw _err("ocsp/bad-input", "a response MUST include at least one SingleResponse (RFC 6960 sec. 4.2.1)");

  return _responderID(responseData.responderID, respCert).then(function (ridNode) {
    return Promise.all(responses.map(function (r) { return _buildSingleResponse(r, opts); })).then(function (built) {
      var srNodes = built.map(function (x) { return x.node; });
      var anyNonIssued = built.some(function (x) { return x.nonIssued; });
      /** @internal Sec. 2.2 and 4.4.8: a "revoked" answer for a non-issued certificate MUST carry the
       *  extended revoked definition in responseExtensions, so the shape itself places it there,
       *  and a caller declining it is refused rather than left with a response the section forbids. */
      if (anyNonIssued && opts.extendedRevoke === false) {
        throw _err("ocsp/bad-input", "a revoked response for a non-issued certificate MUST carry the extended-revoke response extension, so extendedRevoke: false is refused here (RFC 6960 sec. 2.2 / 4.4.8)");
      }
      var rdChildren = [ridNode, b.generalizedTime(_asEncodableDate(responseData.producedAt, "producedAt") || new Date()), b.sequence(srNodes)];
      var respExts = [];
      if (opts.nonce != null) { _assertNonce(opts.nonce, RESPONDER_NONCE_FLOOR); respExts.push(_nonceExt(opts.nonce)); }
      if (opts.extendedRevoke || anyNonIssued) respExts.push(b.sequence([b.oid(OID_EXTENDED_REVOKE), b.octetString(b.nullValue())]));
      if (respExts.length) rdChildren.push(b.explicit(1, b.sequence(respExts)));
      var responseDataDer = b.sequence(rdChildren);
      var scheme = signScheme.resolveSignScheme(respCert, { combinedRsaSig: true }, true, _signE);
      return signScheme.signOverTbs(scheme, responderKey, responseDataDer, _signE).then(function (sig) {
        var basicChildren = [responseDataDer, scheme.sigAlgId, b.bitString(sig, 0)];
        if (opts.embedCert !== false) basicChildren.push(b.explicit(0, b.sequence([b.raw(respCertDer)])));
        var responseBytes = b.sequence([b.oid(OID_OCSP_BASIC), b.octetString(b.sequence(basicChildren))]);
        var der = b.sequence([b.enumerated(0n), b.explicit(0, responseBytes)]);
        return opts.pem ? ocspSchema.pemEncode(der, "OCSP RESPONSE") : der;
      });
    });
  });
}
function _asDate(d) {
  if (d == null) return null;
  var dt = guard.time.toDate(d);
  if (isNaN(guard.time.instantOf(dt))) throw _err("ocsp/bad-input", "an invalid date value " + guard.text.showValue(d));
  return dt;
}
/** @internal `_asDate` for a Date this verb WRITES as a GeneralizedTime (producedAt, thisUpdate,
 *  nextUpdate, a revocation time): the encodable year range is held here so the fault stays in this
 *  verb's domain. The verify clock is only compared and stays on `_asDate`. */
function _asEncodableDate(d, which) {
  var dt = _asDate(d);
  return dt === null ? null : guard.time.assertEncodable(dt, _err, "ocsp/bad-input", which);
}
function _snapshotSignerKey(key, owned) {
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {   // allow:byte-source-narrow -- responder private key on the key-ownership contract (Buffer / Uint8Array / PEM / CryptoKey); widening keys is a separate root decision
    var copy = guard.bytes.snapshot(key, OcspError, "ocsp/bad-input", "the responder key");
    owned.push(copy);
    return copy;
  }
  if (key && typeof key === "object" && (key.mldsa != null || key.trad != null)) {
    return Object.assign({}, key, { mldsa: _snapshotSignerKey(key.mldsa, owned), trad: _snapshotSignerKey(key.trad, owned) });
  }
  return key;
}

function _responderID(rid, respCert) {
  if (rid == null || rid === "byName") return Promise.resolve(b.explicit(1, b.raw(respCert.subject.bytes)));
  if (rid === "byKey") return _digest("SHA-1", _keyValue(respCert.subjectPublicKeyInfo.bytes)).then(function (kh) { return b.explicit(2, b.octetString(kh)); });
  throw _err("ocsp/bad-input", "responderID must be \"byName\" or \"byKey\"");
}
function _buildSingleResponse(r, opts) {
  r = r || {};
  var certIdP;
  if (typeof r !== "object") return Promise.reject(_err("ocsp/bad-input", "each response entry must be an object"));
  try { guard.identifier.assertKnownKeys(r, _SINGLE_RESPONSE_KEYS, _err, "ocsp/bad-input", "unknown response entry field (accepted: cert, issuer, certID, hashAlgorithm, status, thisUpdate, nextUpdate, singleExtensions): "); }
  catch (e) { return Promise.reject(e); }
  if (r.certID != null) certIdP = Promise.resolve(b.raw(guard.bytes.view(r.certID, OcspError, "ocsp/bad-input", "a response entry's certID")));
  else if (r.cert != null && r.issuer != null) certIdP = _buildCertID(_certOf(r.cert, "a response certificate"), _certOf(r.issuer, "a response issuer"), r.hashAlgorithm || "sha1");
  else return Promise.reject(_err("ocsp/bad-input", "each response entry needs { certID } or { cert, issuer }"));
  /** @internal Every per-entry refusal stays INSIDE this chain. These entries are built through a
   * map into Promise.all, so a synchronous throw here would abort the map before Promise.all
   * attached handlers, and an earlier entry's rejection would be orphaned: the caller catches
   * sign()'s failure and the process still sees an unhandled rejection. */
  return certIdP.then(function (certID) {
    var thisUpdate = _asEncodableDate(r.thisUpdate, "thisUpdate") || new Date();
    var nextUpdate = r.nextUpdate === null ? null : (_asEncodableDate(r.nextUpdate, "nextUpdate") || _defaultNextUpdate());
    /** @internal RFC 6960 sec. 4.2.2.1 makes thisUpdate and nextUpdate a validity interval, and says
     * it corresponds to the {thisUpdate, nextUpdate} interval in CRLs. An interval whose end
     * precedes its start states a status window that closed before it opened, and pki.ocsp.verify
     * reports such a response unknown, so signing one emits what nothing can act on. pki.x509.sign,
     * pki.crl.sign, pki.attrcert.sign and pki.crmf.build each refuse their own reversed window; this
     * is that rule in the one place it was missing. The RESOLVED values are compared rather than the
     * caller's, since a defaulted nextUpdate reaches a relying party the same way a supplied one
     * does. An equal pair is left alone, as it is for a CRL: a zero-length window is not forbidden.
     *
     * The CALLER's instants are compared, at their full precision, which is what the four sibling
     * verbs do. Two instants inside one second encode to the same whole-second GeneralizedTime, so
     * comparing the encoded values instead would accept a descending pair and quietly emit the
     * zero-length window it truncates to. A caller naming a later thisUpdate than nextUpdate has
     * stated a reversed one whatever the seconds round to, and hears so here. */
    if (nextUpdate !== null && guard.time.instantOf(thisUpdate) > guard.time.instantOf(nextUpdate)) {
      throw _err("ocsp/bad-input", "thisUpdate must not be after nextUpdate (RFC 6960 sec. 4.2.2.1)");
    }
    var statusNode = _certStatusNode(r.status, opts);
    var nonIssued = _isNonIssuedStatus(r.status);
    var srChildren = [certID, statusNode, b.generalizedTime(thisUpdate)];
    if (nextUpdate !== null) srChildren.push(b.explicit(0, b.generalizedTime(nextUpdate)));
    if (r.singleExtensions != null) {
      var singleDer = _singleExtensionsDer(r.singleExtensions, nonIssued);
      if (singleDer.length) srChildren.push(b.explicit(1, b.sequence(singleDer)));
    }
    return { node: b.sequence(srChildren), nonIssued: nonIssued };
  });
}
/** @internal Sec. 2.2 defines the non-issued shape by its two fields: revocationReason
 *  certificateHold and revocationTime 1970-01-01T00:00:00Z. The time is judged as it is ENCODED: a
 *  GeneralizedTime carries whole seconds, so any instant inside the first second of 1970 reaches
 *  the relying party as that value. */
function _isNonIssuedStatus(status) {
  if (!status || typeof status !== "object" || status.revoked == null || status.revocationReason == null) return false;
  var code = typeof status.revocationReason === "number" ? status.revocationReason : REASON_CODE[guard.text.keyOf(status.revocationReason)];
  if (code !== CERTIFICATE_HOLD) return false;
  var instant = guard.time.instantOf(_asEncodableDate(status.revoked, "the revocation time"));
  return instant >= 0 && instant < constants.TIME.seconds(1);
}
var NON_ISSUED_FORBIDDEN = "a revoked response for a non-issued certificate MUST NOT carry CRL references or any CRL entry extension (RFC 6960 sec. 2.2)";
/** @internal What a pre-encoded singleExtension may be, beyond decoding: not one of the extensions
 *  RFC 6960 defines for requests alone, not one a response carries in responseExtensions alone, with
 *  the criticality RFC 5280 sec. 5.3 fixes for a CRL entry extension carried here (sec. 4.4.5), and
 *  not a CRL reference or entry extension on the non-issued shape (sec. 2.2). */
function _assertSingleExtensionPlacement(e, nonIssued) {
  var label = "pre-encoded singleExtension " + (e.name || e.oid);
  /** @internal The three tables have a null prototype, so an absent OID reads as undefined. */
  var requestClause = EXTENSION_PLACEMENT.requestOnly[e.oid], responseClause = EXTENSION_PLACEMENT.responseOnly[e.oid];
  if (requestClause !== undefined) throw _err("ocsp/bad-input", label + " is a request extension and does not belong in a response (" + requestClause + ")");
  if (responseClause !== undefined) throw _err("ocsp/bad-input", label + " belongs in responseExtensions, not in singleExtensions (" + responseClause + ")");
  var entry = ENTRY_EXTENSION_CRITICALITY[e.oid];
  if (entry !== undefined && (e.critical === true) !== entry.critical) {
    throw _err("ocsp/bad-input", label + " must be marked " + (entry.critical ? "critical" : "non-critical") + " (" + entry.citation + ", carried by RFC 6960 sec. 4.4.5)");
  }
  if (nonIssued && (entry !== undefined || e.oid === OID_OCSP_CRL)) throw _err("ocsp/bad-input", NON_ISSUED_FORBIDDEN);
  if (entry !== undefined) {
    /** @internal Sec. 4.4.5 carries the CRL entry extensions as they are, so the CRL parser's own
     *  reader decides whether the value reads, and RFC 5280 sec. 5.3.1 keeps removeFromCRL(8) to a
     *  delta CRL, which a SingleResponse is not. */
    var read;
    try { read = crlSchema.readEntryExtension(e); }
    catch (err) { throw _err("ocsp/bad-input", label + " value is malformed (" + entry.citation + ")", err); }
    if (e.oid === OID_REASON_CODE && read.value === REMOVE_FROM_CRL) {
      throw _err("ocsp/bad-input", label + " removeFromCRL(8) appears only in a delta CRL (RFC 5280 sec. 5.3.1), never in an OCSP response");
    }
  }
}
function _defaultNextUpdate() { return new Date(Date.now() + constants.TIME.days(7)); }
var _SINGLE_EXT_KEYS = Object.assign(Object.create(null), { archiveCutoff: 1, crlReferences: 1 });
var _CRL_ID_KEYS = Object.assign(Object.create(null), { crlUrl: 1, crlNum: 1, crlTime: 1 });

/** @internal RFC 6960 sec. 4.4.2 and sec. 4.4.4 put archiveCutoff and the CRL references in a
 *  SingleResponse's singleExtensions. The object form names them as fields; the array form carries
 *  pre-encoded Extension DER, and each entry is run through the parser's own singleExtensions reader
 *  first, so this verb never emits an entry pki.schema.ocsp.parseResponse would refuse. */
function _singleExtensionsDer(spec, nonIssued) {
  if (Array.isArray(spec)) {
    var dense = pkiBuild.reqDenseArray(spec, "singleExtensions", _err, "ocsp/bad-input");
    var ders = dense.map(function (d, i) {
      return guard.bytes.snapshotSource(d, OcspError, "ocsp/bad-input", "singleExtensions[" + i + "]");
    });
    if (ders.length) {
      var parsed = ocspSchema.readSingleExtensionsDer(ders);
      parsed.forEach(function (e) { _assertSingleExtensionPlacement(e, nonIssued); });
    }
    return ders;
  }
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) {
    throw _err("ocsp/bad-input", "singleExtensions must be an object { archiveCutoff?, crlReferences? } or an array of pre-encoded Extension DER");
  }
  guard.identifier.assertKnownKeys(spec, _SINGLE_EXT_KEYS, _err, "ocsp/bad-input", function (k) {
    return "unknown singleExtensions field " + guard.text.showValue(k) + " (accepted: archiveCutoff, crlReferences)";
  });
  var out = [];
  if (spec.archiveCutoff != null) {
    guard.time.assertEncodable(spec.archiveCutoff, _err, "ocsp/bad-input", "singleExtensions archiveCutoff");
    out.push(b.sequence([b.oid(oid.byName("ocspArchiveCutoff")), b.octetString(b.generalizedTime(spec.archiveCutoff))]));
  }
  if (spec.crlReferences != null) {
    if (nonIssued) throw _err("ocsp/bad-input", NON_ISSUED_FORBIDDEN);
    var c = spec.crlReferences;
    if (!c || typeof c !== "object" || Array.isArray(c) || Buffer.isBuffer(c)) {
      throw _err("ocsp/bad-input", "singleExtensions crlReferences must be an object { crlUrl?, crlNum?, crlTime? }");
    }
    guard.identifier.assertKnownKeys(c, _CRL_ID_KEYS, _err, "ocsp/bad-input", function (k) {
      return "unknown crlReferences field " + guard.text.showValue(k) + " (accepted: crlUrl, crlNum, crlTime)";
    });
    var fields = [];
    if (c.crlUrl != null) {
      if (typeof c.crlUrl !== "string" || !c.crlUrl.length) throw _err("ocsp/bad-input", "crlReferences crlUrl must be a non-empty string");
      for (var j = 0; j < c.crlUrl.length; j++) {
        if (c.crlUrl.charCodeAt(j) > 0x7f) throw _err("ocsp/bad-input", "crlReferences crlUrl must be 7-bit ASCII (an IA5String, RFC 6960 sec. 4.4.2)");
      }
      fields.push(b.explicit(0, b.ia5(c.crlUrl)));
    }
    if (c.crlNum != null) {
      var num = guard.range.authoredInteger(c.crlNum, _err, "ocsp/bad-input", "crlReferences crlNum");
      if (num < 0n) throw _err("ocsp/bad-input", "crlReferences crlNum must be non-negative (it is a cRLNumber, RFC 5280 sec. 5.2.3)");
      fields.push(b.explicit(1, b.integer(num)));
    }
    if (c.crlTime != null) {
      guard.time.assertEncodable(c.crlTime, _err, "ocsp/bad-input", "crlReferences crlTime");
      fields.push(b.explicit(2, b.generalizedTime(c.crlTime)));
    }
    out.push(b.sequence([b.oid(oid.byName("ocspCrl")), b.octetString(b.sequence(fields))]));
  }
  return out;
}

function _certStatusNode(status, opts) {
  if (status == null || status === "good") return b.contextPrimitive(0, Buffer.alloc(0));
  if (status === "unknown") return b.contextPrimitive(2, Buffer.alloc(0));
  if (typeof status === "object" && status.revoked != null) {
    guard.identifier.assertKnownKeys(status, _STATUS_KEYS, _err, "ocsp/bad-input", "unknown revoked status field (a revoked status is { revoked, revocationReason? }): ");
    var ri = [b.generalizedTime(_asEncodableDate(status.revoked, "the revocation time"))];
    if (status.revocationReason != null) {
      var code = typeof status.revocationReason === "number" ? status.revocationReason : REASON_CODE[guard.text.keyOf(status.revocationReason)];
      if (code == null) throw _err("ocsp/bad-input", "unknown revocationReason " + guard.text.showValue(status.revocationReason));
      ri.push(b.explicit(0, b.enumerated(BigInt(code))));
    }
    return b.contextConstructed(1, Buffer.concat(ri));
  }
  throw _err("ocsp/bad-input", "a response status must be \"good\", \"unknown\", or { revoked: <Date>, revocationReason? }");
}

/**
 * @primitive pki.ocsp.buildErrorResponse
 * @signature pki.ocsp.buildErrorResponse(status) -> Buffer
 * @since 0.2.22
 * @status stable
 * @spec RFC 6960
 * @related pki.ocsp.sign
 *
 * Build an UNSIGNED error OCSPResponse, one of `malformedRequest` / `internalError` / `tryLater` /
 * `sigRequired` / `unauthorized`, carrying only the responseStatus and no responseBytes (RFC 6960
 * sec. 2.3: an error message conveys no certificate status and is not signed).
 *
 * @example
 *   var der = pki.ocsp.buildErrorResponse("tryLater");
 */
var ERROR_STATUS = Object.assign(Object.create(null), { malformedRequest: 1, internalError: 2, tryLater: 3, sigRequired: 5, unauthorized: 6 });
function buildErrorResponse(status) {
  var code = ERROR_STATUS[guard.text.keyOf(status)];
  if (code == null) throw _err("ocsp/bad-input", "an error responseStatus must be one of " + Object.keys(ERROR_STATUS).join(" / "));
  return b.sequence([b.enumerated(BigInt(code))]);
}

/**
 * @primitive pki.ocsp.verify
 * @signature pki.ocsp.verify(response, opts) -> Promise<{ valid, status, responderAuthorized, signatureValid, matched, thisUpdate, nextUpdate, revocationReason?, revocationTime?, nonceMatched?, reason }>
 * @since 0.2.22
 * @status stable
 * @spec RFC 6960, RFC 9654, RFC 5019
 * @related pki.path.ocspChecker, pki.ocsp.buildRequest
 *
 * Verify a returned OCSP response as a relying party (RFC 6960 sec. 3.2 client acceptance). Resolves
 * an AUTHORIZED responder (the issuing CA directly, or a CA-issued delegate bearing id-kp-OCSPSigning
 * + id-pkix-ocsp-nocheck), verifies the signature over `tbsResponseData`, matches the CertID triple
 * to the target certificate under the CertID's own hashAlgorithm, checks currency
 * (`thisUpdate`/`nextUpdate`), and, when `opts.requestNonce` is supplied, confirms the response
 * nonce echoes it. This runs the same hardened gates `pki.path.ocspChecker` does. Fail-closed: an
 * unauthorized, stale, or CertID-mismatched response is a `"unknown"` verdict (never a silent
 * accept); a malformed response's parse fault surfaces as the parser's `ocsp/*` / `asn1/*`.
 *
 * `valid` is the toolkit-wide verdict alias the other verify verbs carry, and it is true only when
 * `status` is `"good"`. Because every failure this verb detects already collapses to `"unknown"`,
 * `valid` states exactly what `status === "good"` does and hides no unrun check. A revoked
 * certificate is `valid: false`; which of the two it was stays in `status`.
 *
 * The request-nonce check is reported, and downgrades `good` alone. Every verdict carries
 * `nonceMatched` (true / false / null when the client sent no nonce). An unmatched nonce turns a
 * `good` into `"unknown"`, because a response that is not an answer to this request cannot be relied
 * on to say the certificate is still fine. It does not touch `revoked`: revocation does not go stale
 * the way non-revocation does, so discarding a signed, current, authorized `revoked` because it was
 * replayed would hand a soft-failing caller the very certificate the responder refused. A replayed
 * `revoked` is therefore reported as `revoked` with `nonceMatched: false`.
 *
 * @opts
 *   cert            the target certificate (parsed, DER, or PEM) -- REQUIRED.
 *   issuer          its issuer certificate (parsed, DER, or PEM) -- REQUIRED.
 *   time            the validation instant (default: now).
 *   requestNonce    the nonce the client sent; when given, the response MUST echo it (constant-time).
 *   historicalMode  defer a strictly-future revocation (report good) instead of revoking on skew.
 * @example
 *   var ca = await pki.key.generate("Ed25519");
 *   var caKey = await pki.key.export(ca.privateKey);
 *   var caDer = await pki.x509.sign({ subject: "Example CA", subjectPublicKey: await pki.key.export(ca.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } },
 *     { key: caKey });
 *   var leaf = await pki.key.generate("Ed25519");
 *   var leafDer = await pki.x509.sign({ subject: "leaf.example", subjectPublicKey: await pki.key.export(leaf.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { cert: caDer, key: caKey });
 *   var responseDer = await pki.ocsp.sign(
 *     { responderID: "byName", responses: [{ cert: leafDer, issuer: caDer, status: "good" }] },
 *     { cert: caDer, key: caKey });
 *   var res = await pki.ocsp.verify(responseDer, { cert: leafDer, issuer: caDer });
 *   res.status;   // "good" | "revoked" | "unknown"
 */
var _VERIFY_OPTS = Object.assign(Object.create(null), { cert: 1, historicalMode: 1, issuer: 1, requestNonce: 1, time: 1 });

function verify(response, opts) {
  try {
    opts = guard.identifier.optionsObject(opts, _err, "ocsp/bad-input", "pki.ocsp.verify options");
    guard.identifier.assertKnownKeys(opts, _VERIFY_OPTS, _err, "ocsp/bad-input",
      "pki.ocsp.verify has an unknown option (the request nonce to bind against is `requestNonce`): ");
  } catch (e) { return Promise.reject(e); }
  if (opts.cert == null || opts.issuer == null) return Promise.reject(_err("ocsp/bad-input", "verify requires opts.cert and opts.issuer"));
  var parsed, cert, issuerCert, time;
  try {
    parsed = _responseFromBytes(response);
    cert = _certOf(opts.cert, "the target certificate");
    issuerCert = _certOf(opts.issuer, "the issuer certificate");
    time = opts.time == null ? new Date() : _asDate(opts.time);
  } catch (e) { return Promise.reject(e); }
  return pathValidate.verifyOcspResponse(parsed, cert, issuerCert, time, { historicalMode: opts.historicalMode === true }).then(function (verdict) {
    var out;
    if (opts.requestNonce == null) {
      out = guard.verdict.of(verdict, { nonceMatched: null });
    } else {
      var respNonce = _responseNonce(parsed);
      var reqNonce = guard.bytes.isByteSource(opts.requestNonce)
        ? guard.bytes.snapshotSource(opts.requestNonce, OcspError, "ocsp/bad-input", "opts.requestNonce") : null;
      var matched = respNonce != null && reqNonce != null && guard.crypto.constantTimeEqual(respNonce, reqNonce);
      out = guard.verdict.of(verdict, { nonceMatched: matched });
      if (!matched && out.status === "good") {
        out = guard.verdict.of(out, { status: "unknown", reason: "the OCSP response nonce does not echo the request nonce (RFC 9654)" });
      }
    }
    return guard.verdict.of(out, { valid: out.status === "good" });
  });
}
function _responseNonce(parsed) {
  var br = parsed && parsed.basicResponse;
  var exts = (br && br.responseExtensions) || [];
  for (var i = 0; i < exts.length; i++) if (exts[i].oid === OID_OCSP_NONCE) return exts[i].nonce || null;
  return null;
}

var _VERIFY_REQUEST_OPTS = Object.assign(Object.create(null), { certs: 1 });
function _requestFromBytes(request) {
  if (guard.bytes.isByteSource(request)) request = guard.bytes.snapshotSource(request, OcspError, "ocsp/bad-input", "the OCSP request");
  return ocspSchema.parseRequest(request);
}
function _reqVerdict(parsed, extra) {
  return guard.verdict.of({
    valid: extra.signed === true && extra.signatureValid === true && extra.requestorNamed === true,
    signed: extra.signed, signatureValid: extra.signatureValid, requestorNamed: extra.requestorNamed === true,
    signerCert: extra.signerCert != null ? extra.signerCert : null,
    signerCerts: extra.signerCerts != null ? extra.signerCerts : [],
    certs: extra.certs != null ? extra.certs : [],
    signerSubject: extra.signerSubject != null ? extra.signerSubject : null,
    requestorName: parsed.requestorName, requestList: parsed.requestList,
    requestExtensions: parsed.requestExtensions, version: parsed.version,
    reason: extra.reason != null ? extra.reason : null,
  });
}
async function _findRequestSigners(candidates, strict, parsed, sig, sigBits) {
  var parsedList = [];
  for (var i = 0; i < candidates.length; i++) {
    try { parsedList.push({ der: candidates[i], cert: x509.parse(candidates[i]) }); }
    catch (e) { if (strict) throw _err("ocsp/bad-signer-cert", "an opts.certs entry does not parse as an X.509 certificate", e); }
  }
  var parseable = parsedList.map(function (p) { return p.der; });
  var matches = [];
  for (var j = 0; j < parsedList.length; j++) {
    if (await ocspRequestVerify.verifyRequestSignature(sig.signatureAlgorithm, sigBits, parsedList[j].cert.subjectPublicKeyInfo.bytes, parsed.tbsRequestBytes)) {
      matches.push({ der: parsedList[j].der, subject: parsedList[j].cert.subject });
    }
  }
  return { matches: matches, parseable: parseable };
}
/** @internal RFC 6960 sec. 4.1.2: "If the request is signed, the requestor SHALL specify its name
 *  in the requestorName field." The requestor is whoever holds the key that signed, so the name is
 *  held to the subject of a certificate that verified the signature, compared as a distinguished
 *  name (RFC 5280 sec. 7.1). The parser refuses a signed request that names nobody
 *  (ocsp/missing-requestor-name); one naming its requestor by a GeneralName form other than
 *  directoryName leaves the check unperformed and never a pass. */
function _requestorNamed(parsed, matches) {
  var rn = parsed.requestorName;
  if (rn.tagNumber !== 4) {
    return { named: [], reason: "the signed OCSP request names its requestor by a GeneralName form [" + rn.tagNumber + "] this responder does not compare to a certificate subject; a directoryName is compared (RFC 6960 sec. 4.1.2)" };
  }
  if (!rn.value.rdns.length) return { named: [], reason: "the signed OCSP request's requestorName is an empty distinguished name, which names nobody (RFC 6960 sec. 4.1.2)" };
  var named = [];
  for (var i = 0; i < matches.length; i++) {
    if (guard.name.dnEqual(matches[i].subject.rdns, rn.value.rdns, _err, "ocsp/bad-input", "the requestorName")) named.push(matches[i]);
  }
  if (named.length) return { named: named, reason: null };
  return { named: [], reason: "the requestorName " + guard.text.showValue(rn.value.dn) + " is not the subject of a certificate that signed the request (RFC 6960 sec. 4.1.2)" };
}
/** @internal Several certificates can carry the signing key (a renewal beside the certificate it
 *  replaced), and one of them may carry another subject. The signer the verdict names, and the set
 *  the responder builds its trusted path from, are the certificates that both verified the signature
 *  AND carry the name the request states; a same-key certificate under another name is not the
 *  requestor, whatever order the request embeds them in. */
function _signerVerdict(parsed, found, failReason) {
  if (!found.matches.length) return _reqVerdict(parsed, { signed: true, signatureValid: false, certs: found.parseable, reason: failReason });
  var bound = _requestorNamed(parsed, found.matches);
  var signers = bound.named.length ? bound.named : found.matches;
  return _reqVerdict(parsed, {
    signed: true, signatureValid: true, requestorNamed: bound.reason === null, signerCert: signers[0].der,
    signerCerts: signers.map(function (m) { return m.der; }), certs: found.parseable,
    signerSubject: { dn: signers[0].subject.dn, rdns: signers[0].subject.rdns }, reason: bound.reason,
  });
}

/**
 * @primitive  pki.ocsp.verifyRequest
 * @signature  pki.ocsp.verifyRequest(request, opts?) -> Promise<{ valid, signed, signatureValid, requestorNamed, signerCert, signerCerts, certs, signerSubject, requestorName, requestList, requestExtensions, version, reason }>
 * @since      0.6.0
 * @status     stable
 * @spec       RFC 6960
 * @related    pki.ocsp.buildRequest, pki.ocsp.verify, pki.schema.ocsp.parseRequest, pki.csr.verify
 *
 * The responder-side counterpart to `pki.ocsp.buildRequest`: verify a client's signed OCSP request
 * (RFC 6960 sec. 4.1.1). Signing a request is OPTIONAL, so an unsigned request is not an error; it is
 * reported with `signed: false` and authenticates no requestor. For a signed request the requestor's
 * signature over the exact `tbsRequest` is checked under the public key of the requestor certificate
 * the request carries, through the same certification-path signature engine `pki.ocsp.verify` uses
 * for a response (with its EdDSA low-order-point and algorithm-confusion gates). `request` is DER
 * `Buffer` / `Uint8Array` or a PEM `OCSP REQUEST` string, parsed from bytes so the signature, its
 * algorithm and the covered `tbsRequest` are one byte string and cannot be split.
 *
 * `signatureValid` means only that a certificate's key made this signature over this request. It
 * says nothing about whether that certificate is trusted: `signerCerts` is every certificate the
 * request carries whose key verified the signature AND whose subject is the `requestorName` the
 * request states (RFC 6960 sec. 4.1.1 certs is unordered, and a key may appear under an expired
 * certificate beside its renewal; a same-key certificate under another name is not the requestor),
 * so the responder builds a trusted path to one of them rather than depend on ordering. `signerCert`
 * and the decoded `signerSubject` are the first of those, the common single-signer case; when no
 * verifying certificate carries the name, they fall back to the verifying ones and `valid` is
 * false. `certs` is every parseable certificate the
 * request carried (or opts.certs supplied), including intermediates that do not sign and so are absent
 * from `signerCerts`: the responder passes it as the `opts.candidates` pool to `pki.path.build`, which
 * discovers and validates the ordered path from a `signerCerts` entry (leaf) up to a trust anchor.
 * The responder then confirms that certificate is authorized to sign the request: its `keyUsage`,
 * where present, must assert `digitalSignature` (RFC 5280 sec. 4.2.1.3, since the certificate signed
 * the request). The `requestorName` a signed request carries (RFC 6960 sec. 4.1.2: a requestor that
 * signs SHALL specify its name) is held to the subject of a certificate that verified the signature,
 * compared as a distinguished name (RFC 5280 sec. 7.1): `requestorNamed` is true when it is, `valid`
 * requires it, and a name given as a GeneralName form other than directoryName is not compared and
 * never passes. The decoded `requestorName` (with its `value` for a directoryName), `requestList`,
 * `requestExtensions` and `version` are returned so the CertIDs being asked about need no re-parse.
 *
 * @opts
 *   - `certs`  An array of certificates (DER `Buffer` / `Uint8Array` or PEM strings) supplying the
 *              requestor certificate when the request omits its own `certs` (RFC 6960 lets them
 *              travel out of band); every entry whose key verifies is surfaced in `signerCerts`,
 *              and is ignored when the request embeds its own certificates.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey), spki = await pki.key.export(pair.publicKey);
 *   var caDer = await pki.x509.sign({ subject: "OCSP CA", subjectPublicKey: spki,
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z") }, { key: key });
 *   var request = await pki.ocsp.buildRequest({ cert: caDer, issuer: caDer },
 *     { signer: { cert: caDer, key: key }, requestorName: pki.schema.x509.parse(caDer).subject.bytes });
 *   var v = await pki.ocsp.verifyRequest(request);
 *   // v.signed && v.signatureValid -> for a signerCerts entry, pki.path.build(entry, { candidates:
 *   // v.certs, trustAnchors, time }) discovers and validates the path (several signerCerts may share
 *   // the key, e.g. an expired one beside its renewal); confirm that entry's keyUsage asserts
 *   // digitalSignature, then bind its subject to the requestor you expect before honoring v.requestList.
 */
async function verifyRequest(request, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "ocsp/bad-input", "pki.ocsp.verifyRequest options");
  guard.identifier.assertKnownKeys(opts, _VERIFY_REQUEST_OPTS, _err, "ocsp/bad-input",
    "pki.ocsp.verifyRequest has an unknown option (out-of-band requestor certificates are `certs`): ");
  var parsed = _requestFromBytes(request);
  var sig = parsed.optionalSignature;
  if (sig == null) {
    return _reqVerdict(parsed, { signed: false, signatureValid: false,
      reason: "the OCSP request is unsigned (RFC 6960 sec. 4.1.1 makes optionalSignature OPTIONAL); no requestor is authenticated" });
  }
  var sigBits = { unusedBits: 0, bytes: sig.signature };
  if (sig.certs.length) {
    return _signerVerdict(parsed, await _findRequestSigners(sig.certs, false, parsed, sig, sigBits),
      "the OCSP request signature does not verify over tbsRequest under any certificate the request carries (RFC 6960 sec. 4.1.1)");
  }
  var suppliedCerts = [];
  if (opts.certs != null) {
    var list = pkiBuild.reqDenseArray(opts.certs, "opts.certs", _err, "ocsp/bad-input");
    for (var i = 0; i < list.length; i++) suppliedCerts.push(_normCertDer(list[i], "an opts.certs entry"));
  }
  if (!suppliedCerts.length) {
    return _reqVerdict(parsed, { signed: true, signatureValid: false,
      reason: "the signed OCSP request carries no certificate and opts.certs was not supplied, so its signature cannot be verified" });
  }
  return _signerVerdict(parsed, await _findRequestSigners(suppliedCerts, true, parsed, sig, sigBits),
    "the OCSP request signature does not verify over tbsRequest under any opts.certs entry");
}

module.exports = {
  buildRequest: buildRequest,
  sign: sign,
  buildErrorResponse: buildErrorResponse,
  verify: verify,
  verifyRequest: verifyRequest,
};
