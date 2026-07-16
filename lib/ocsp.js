// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.ocsp
 * @nav        Revocation
 * @title      OCSP
 * @intro The producing + client-facing half of RFC 6960 Online Certificate Status Protocol:
 *   build a status request over a certificate (`pki.ocsp.buildRequest`), build and sign a status
 *   response as an authorized responder (`pki.ocsp.sign`), emit an unsigned error response
 *   (`pki.ocsp.buildErrorResponse`), and verify a returned response as a relying party
 *   (`pki.ocsp.verify`). Parsing lives in `pki.schema.ocsp`; revocation during path validation is
 *   `pki.path.ocspChecker`. Signing rides the shared sign-scheme registry (the same classical +
 *   post-quantum set `pki.cms.sign` uses), so a response is signed under RSA / ECDSA / EdDSA /
 *   ML-DSA / SLH-DSA per the responder key. Verification composes the SAME hardened responder-
 *   authorization + signature + currency gates `pki.path.ocspChecker` runs -- there is no weaker
 *   second verify path. Fail-closed: `verify` returns a `"unknown"` verdict (never a silent accept)
 *   for any unmet gate; malformed input throws a typed `OcspError`.
 * @spec RFC 6960, RFC 9654, RFC 5019
 * @card Build, sign, and verify RFC 6960 OCSP requests + responses (a responder + a relying party).
 */

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var ocspSchema = require("./schema-ocsp");
var pathValidate = require("./path-validate");
var signScheme = require("./sign-scheme");
var ocspVerify = require("./ocsp-verify");
var webcrypto = require("./webcrypto");
var subtle = webcrypto.webcrypto.subtle;
var guard = require("./guard-all");
var constants = require("./constants");
var frameworkError = require("./framework-error");

var OcspError = frameworkError.OcspError;
var b = asn1.build;
function O(name) { return oid.byName(name); }
function _err(code, message, cause) { return new OcspError(code, message, cause); }
// The domain error factory the shared sign-scheme resolver/signer throws through (kind ->
// ocsp/<kind>), so its faults keep the ocsp/* codes.
function _signE(kind, message, cause) { return new OcspError("ocsp/" + kind, message, cause); }

// CertID / responder-ID hash algorithm name -> WebCrypto digest name. SHA-1 is the RFC 5019 interop
// default for the CertID IDENTITY hash (not a signature; collision resistance is irrelevant to the
// lookup, so SHAttered does not bar it -- the deliberate split path-validate makes too).
var HASH_WC = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
// A CRLReason name -> its enumerated value (RFC 5280 sec. 5.3.1), reverse of pki.C.NAMES.CRL_REASON.
var REASON_CODE = {};
Object.keys(constants.NAMES.CRL_REASON).forEach(function (k) { REASON_CODE[constants.NAMES.CRL_REASON[k]] = parseInt(k, 10); });
var OID_OCSP_NONCE = O("ocspNonce");
var OID_OCSP_BASIC = O("ocspBasic");
var OID_EXTENDED_REVOKE = O("ocspExtendedRevoke");

function _digest(wcHash, buf) { return subtle.digest(wcHash, buf).then(function (h) { return Buffer.from(h); }); }
function _certOf(arg, what) {
  if (arg && arg.subjectPublicKeyInfo && arg.tbsBytes) return arg;   // already parsed
  var der;
  if (Buffer.isBuffer(arg)) der = arg;
  else if (arg instanceof Uint8Array) der = Buffer.from(arg);
  else if (typeof arg === "string") { try { der = x509.pemDecode(arg); } catch (e) { throw _err("ocsp/bad-input", (what || "a certificate") + " PEM could not be decoded", e); } }
  else throw _err("ocsp/bad-input", (what || "a certificate") + " must be a parsed certificate, a DER Buffer, or a PEM string");
  try { return x509.parse(der); } catch (e) { throw _err("ocsp/bad-input", (what || "a certificate") + " is not a well-formed X.509 certificate", e); }
}
function _toDer(input, what) {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input);
  if (typeof input === "string") { try { return ocspSchema.pemDecode(input); } catch (e) { throw _err("ocsp/bad-input", (what || "input") + " PEM could not be decoded", e); } }
  throw _err("ocsp/bad-input", (what || "input") + " must be a DER Buffer, Uint8Array, or PEM string");
}
// The subjectPublicKey BIT STRING value an issuerKeyHash / byKey KeyHash hashes over.
function _keyValue(spkiDer) { return ocspVerify.ocspKeyValue(spkiDer); }
// A non-critical id-pkix-ocsp-nonce Extension carrying the raw nonce (RFC 9654): the extnValue
// OCTET STRING wraps the Nonce ::= OCTET STRING.
function _nonceExt(nonceBytes) { return b.sequence([b.oid(OID_OCSP_NONCE), b.octetString(b.octetString(nonceBytes))]); }
function _assertNonce(nonceBytes) {
  if (!Buffer.isBuffer(nonceBytes) || nonceBytes.length < 1 || nonceBytes.length > 128) {
    throw _err("ocsp/bad-input", "a nonce must be a Buffer of 1..128 octets (RFC 9654 sec. 2.1)");
  }
}
// The CertID SEQUENCE for target `cert` under `issuer`, hashing under `hashName` (RFC 6960 sec. 4.1.1).
function _buildCertID(cert, issuer, hashName) {
  var wc = HASH_WC[hashName];
  if (!wc) throw _err("ocsp/bad-input", "unsupported CertID hashAlgorithm " + JSON.stringify(hashName) + " (sha1 / sha256 / sha384 / sha512)");
  return Promise.all([
    _digest(wc, issuer.subject.bytes),
    _digest(wc, _keyValue(issuer.subjectPublicKeyInfo.bytes)),
  ]).then(function (hashes) {
    // SHA-1 carries NULL parameters (RFC 3279); a SHA-2 digest AlgorithmIdentifier omits them
    // (RFC 5754 sec. 2). The CertID matcher keys on the OID and ignores parameters either way.
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
 * @status experimental
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
 *   hashAlgorithm  `"sha1"` (default) / `"sha256"` / `"sha384"` / `"sha512"` -- the CertID identity hash.
 *   nonce          `true` for a fresh 32-octet CSPRNG nonce (RFC 9654), or a caller Buffer (1..128 octets).
 *   requestorName  a Name (RDN array) placed in the [1] requestorName as a directoryName.
 *   signer         `{ cert, key }` to sign the request (requires requestorName).
 *   profile        `"lightweight"` -- one Request, SHA-1 CertID, nonce-only extensions (RFC 5019).
 *   pem            emit a PEM `OCSP REQUEST` string instead of DER.
 * @example
 *   var der = await pki.ocsp.buildRequest({ cert: leafDer, issuer: caDer }, { nonce: true });
 */
function buildRequest(query, opts) {
  opts = opts || {};
  var lightweight = opts.profile === "lightweight";
  var hashName = opts.hashAlgorithm || "sha1";
  if (lightweight && hashName !== "sha1") throw _err("ocsp/bad-input", "the lightweight profile requires a SHA-1 CertID (RFC 5019 sec. 2.1.1)");
  var queries = Array.isArray(query) ? query : [query];
  if (!queries.length) throw _err("ocsp/bad-input", "buildRequest needs at least one { cert, issuer } query");
  if (lightweight && queries.length !== 1) throw _err("ocsp/bad-input", "the lightweight profile permits exactly one Request (RFC 5019 sec. 2.1.1)");
  if (opts.signer && !opts.requestorName) throw _err("ocsp/bad-input", "a signed OCSP request MUST carry requestorName (RFC 6960 sec. 4.1.2)");

  return Promise.all(queries.map(function (q) {
    if (!q || q.cert == null || q.issuer == null) throw _err("ocsp/bad-input", "each query must be { cert, issuer }");
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
    if (opts.requestorName) {
      // requestorName [1] EXPLICIT GeneralName; a Name is carried as directoryName [4].
      var nameDer = _nameDer(opts.requestorName);
      tbsChildren.push(b.explicit(1, b.contextConstructed(4, nameDer)));
    }
    tbsChildren.push(b.sequence(requests));
    var reqExts = [];
    if (opts.nonce) {
      var nonceBytes = opts.nonce === true ? nodeCrypto.randomBytes(32) : opts.nonce;   // >= 32 octets, CSPRNG (RFC 9654 sec. 2.1)
      _assertNonce(nonceBytes);
      reqExts.push(_nonceExt(nonceBytes));
    }
    if (reqExts.length) tbsChildren.push(b.explicit(2, b.sequence(reqExts)));
    var tbsRequest = b.sequence(tbsChildren);
    if (!opts.signer) return _emitReq(b.sequence([tbsRequest]), opts);
    var signerCertDer = _normCertDer(opts.signer.cert, "the request signer certificate");
    var signerCert = _certOf(signerCertDer, "the request signer certificate");
    var scheme = signScheme.resolveSignScheme(signerCert, { combinedRsaSig: true }, true, _signE);
    return signScheme.signOverTbs(scheme, opts.signer.key, tbsRequest, _signE).then(function (sig) {
      var optionalSignature = b.sequence([scheme.sigAlgId, b.bitString(sig, 0), b.explicit(0, b.sequence([b.raw(signerCertDer)]))]);
      return _emitReq(b.sequence([tbsRequest, b.explicit(0, optionalSignature)]), opts);
    });
  });
}
function _emitReq(der, opts) { return opts.pem ? ocspSchema.pemEncode(der, "OCSP REQUEST") : der; }
function _nameDer(name) {
  if (Buffer.isBuffer(name)) return name;
  if (name && name.bytes) return name.bytes;   // a parsed Name
  throw _err("ocsp/bad-input", "requestorName must be a DER Name Buffer or a parsed Name");
}
// The RAW DER of a certificate that will be embedded verbatim (the responder cert in a
// BasicOCSPResponse, the signer cert in a signed OCSPRequest). It must be supplied as bytes:
// a parsed certificate does not retain its full DER encoding, and re-encoding it would risk
// byte drift from the signed original, so a parsed cert is rejected rather than reconstructed.
function _normCertDer(cert, what) {
  if (Buffer.isBuffer(cert)) return cert;
  if (cert instanceof Uint8Array) return Buffer.from(cert);
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
 * @status experimental
 * @spec RFC 6960, RFC 9654
 * @related pki.ocsp.verify, pki.ocsp.buildErrorResponse
 *
 * Build and sign a `successful` OCSPResponse wrapping a BasicOCSPResponse. `responseData` names the
 * responderID, an optional producedAt, and one or more per-certificate responses; `responder` is the
 * `{ cert, key }` signing the response (the issuing CA directly, or a CA-issued delegate bearing
 * id-kp-OCSPSigning + id-pkix-ocsp-nocheck). The signature is computed over the exact ResponseData
 * DER (RFC 6960 sec. 4.2.1 -- no CMS wrapper, no signed attributes). The responder certificate is
 * embedded in `certs [0]` so a relying party can find it. Returns the response DER, or PEM.
 *
 * @opts
 *   nonce           a request nonce Buffer to echo back in responseExtensions (RFC 9654).
 *   extendedRevoke  emit the id-pkix-ocsp-extended-revoke extension (RFC 6960 sec. 4.4.8).
 *   embedCert       `false` to omit certs [0] (a direct-CA response the client already trusts).
 *   pem             emit a PEM `OCSP RESPONSE` string instead of DER.
 * @example
 *   var resp = await pki.ocsp.sign(
 *     { responderID: "byName", responses: [{ cert: leafDer, issuer: caDer, status: "good" }] },
 *     { cert: responderCertDer, key: responderPkcs8 });
 */
function sign(responseData, responder, opts) {
  opts = opts || {};
  responseData = responseData || {};
  if (!responder || responder.cert == null || responder.key == null) throw _err("ocsp/bad-input", "a responder must be { cert, key }");
  var respCertDer = _normCertDer(responder.cert, "the responder certificate");
  var respCert = _certOf(respCertDer, "the responder certificate");
  var responses = responseData.responses || [];
  if (!responses.length) throw _err("ocsp/bad-input", "a response MUST include at least one SingleResponse (RFC 6960 sec. 4.2.1)");

  return _responderID(responseData.responderID, respCert).then(function (ridNode) {
    return Promise.all(responses.map(function (r) { return _buildSingleResponse(r, opts); })).then(function (srNodes) {
      var rdChildren = [ridNode, b.generalizedTime(_asDate(responseData.producedAt) || new Date()), b.sequence(srNodes)];
      var respExts = [];
      if (opts.nonce != null) { _assertNonce(opts.nonce); respExts.push(_nonceExt(opts.nonce)); }
      if (opts.extendedRevoke) respExts.push(b.sequence([b.oid(OID_EXTENDED_REVOKE), b.octetString(b.nullValue())]));
      if (respExts.length) rdChildren.push(b.explicit(1, b.sequence(respExts)));
      var responseDataDer = b.sequence(rdChildren);
      var scheme = signScheme.resolveSignScheme(respCert, { combinedRsaSig: true }, true, _signE);
      return signScheme.signOverTbs(scheme, responder.key, responseDataDer, _signE).then(function (sig) {
        var basicChildren = [responseDataDer, scheme.sigAlgId, b.bitString(sig, 0)];
        if (opts.embedCert !== false) basicChildren.push(b.explicit(0, b.sequence([b.raw(respCertDer)])));
        var responseBytes = b.sequence([b.oid(OID_OCSP_BASIC), b.octetString(b.sequence(basicChildren))]);
        var der = b.sequence([b.enumerated(0n), b.explicit(0, responseBytes)]);
        return opts.pem ? ocspSchema.pemEncode(der, "OCSP RESPONSE") : der;
      });
    });
  });
}
// A date value -> Date, or null when absent (the caller defaults). An unparseable value is a
// config-time error, not a silently-emitted Invalid Date: a NaN date would encode as a malformed
// GeneralizedTime in a SIGNED response, and compare false against every currency bound on verify.
function _asDate(d) {
  if (d == null) return null;
  var dt = d instanceof Date ? d : new Date(d);
  if (isNaN(dt.getTime())) throw _err("ocsp/bad-input", "an invalid date value " + JSON.stringify(d));
  return dt;
}
function _responderID(rid, respCert) {
  if (rid == null || rid === "byName") return Promise.resolve(b.explicit(1, b.raw(respCert.subject.bytes)));   // byName [1] EXPLICIT Name
  if (rid === "byKey") return _digest("SHA-1", _keyValue(respCert.subjectPublicKeyInfo.bytes)).then(function (kh) { return b.explicit(2, b.octetString(kh)); });
  throw _err("ocsp/bad-input", "responderID must be \"byName\" or \"byKey\"");
}
function _buildSingleResponse(r, opts) {
  r = r || {};
  var certIdP;
  if (r.certID != null) certIdP = Promise.resolve(b.raw(Buffer.isBuffer(r.certID) ? r.certID : Buffer.from(r.certID)));
  else if (r.cert != null && r.issuer != null) certIdP = _buildCertID(_certOf(r.cert, "a response certificate"), _certOf(r.issuer, "a response issuer"), r.hashAlgorithm || "sha1");
  else return Promise.reject(_err("ocsp/bad-input", "each response entry needs { certID } or { cert, issuer }"));
  return certIdP.then(function (certID) {
    var statusNode = _certStatusNode(r.status, opts);
    var srChildren = [certID, statusNode, b.generalizedTime(_asDate(r.thisUpdate) || new Date())];
    if (r.nextUpdate !== null) srChildren.push(b.explicit(0, b.generalizedTime(_asDate(r.nextUpdate) || _defaultNextUpdate())));
    if (r.singleExtensions && r.singleExtensions.length) srChildren.push(b.explicit(1, b.sequence(r.singleExtensions)));
    return b.sequence(srChildren);
  });
}
function _defaultNextUpdate() { return new Date(Date.now() + constants.TIME.days(7)); }
function _certStatusNode(status, opts) {
  if (status == null || status === "good") return b.contextPrimitive(0, Buffer.alloc(0));   // good [0] IMPLICIT NULL
  if (status === "unknown") return b.contextPrimitive(2, Buffer.alloc(0));                   // unknown [2] IMPLICIT NULL
  if (typeof status === "object" && status.revoked != null) {
    var ri = [b.generalizedTime(_asDate(status.revoked))];   // revoked != null is guaranteed above
    if (status.revocationReason != null) {
      var code = typeof status.revocationReason === "number" ? status.revocationReason : REASON_CODE[status.revocationReason];
      if (code == null) throw _err("ocsp/bad-input", "unknown revocationReason " + JSON.stringify(status.revocationReason));
      ri.push(b.explicit(0, b.enumerated(BigInt(code))));   // revocationReason [0] EXPLICIT CRLReason
    }
    return b.contextConstructed(1, Buffer.concat(ri));       // revoked [1] IMPLICIT RevokedInfo
  }
  throw _err("ocsp/bad-input", "a response status must be \"good\", \"unknown\", or { revoked: <Date>, revocationReason? }");
}

/**
 * @primitive pki.ocsp.buildErrorResponse
 * @signature pki.ocsp.buildErrorResponse(status) -> Buffer | string
 * @since 0.2.22
 * @status experimental
 * @spec RFC 6960
 * @related pki.ocsp.sign
 *
 * Build an UNSIGNED error OCSPResponse -- `malformedRequest` / `internalError` / `tryLater` /
 * `sigRequired` / `unauthorized` -- carrying only the responseStatus and no responseBytes (RFC 6960
 * sec. 2.3: an error message conveys no certificate status and is not signed).
 *
 * @example
 *   var der = pki.ocsp.buildErrorResponse("tryLater");
 */
var ERROR_STATUS = { malformedRequest: 1, internalError: 2, tryLater: 3, sigRequired: 5, unauthorized: 6 };
function buildErrorResponse(status) {
  var code = ERROR_STATUS[status];
  if (code == null) throw _err("ocsp/bad-input", "an error responseStatus must be one of " + Object.keys(ERROR_STATUS).join(" / "));
  return b.sequence([b.enumerated(BigInt(code))]);
}

/**
 * @primitive pki.ocsp.verify
 * @signature pki.ocsp.verify(response, opts) -> Promise<{ status, responderAuthorized, signatureValid, thisUpdate, nextUpdate, revocationReason?, nonceMatched?, reason }>
 * @since 0.2.22
 * @status experimental
 * @spec RFC 6960, RFC 9654, RFC 5019
 * @related pki.path.ocspChecker, pki.ocsp.buildRequest
 *
 * Verify a returned OCSP response as a relying party (RFC 6960 sec. 3.2 client acceptance). Resolves
 * an AUTHORIZED responder (the issuing CA directly, or a CA-issued delegate bearing id-kp-OCSPSigning
 * + id-pkix-ocsp-nocheck), verifies the signature over `tbsResponseData`, matches the CertID triple
 * to the target certificate under the CertID's own hashAlgorithm, checks currency
 * (`thisUpdate`/`nextUpdate`), and -- when `opts.requestNonce` is supplied -- confirms the response
 * nonce echoes it. This runs the SAME hardened gates `pki.path.ocspChecker` does. Fail-closed: an
 * unauthorized, stale, mismatched, or nonce-mismatched response is a `"unknown"` verdict (never a
 * silent accept); a malformed response's parse fault surfaces as the parser's `ocsp/*` / `asn1/*`.
 *
 * @opts
 *   cert            the target certificate (parsed, DER, or PEM) -- REQUIRED.
 *   issuer          its issuer certificate (parsed, DER, or PEM) -- REQUIRED.
 *   time            the validation instant (default: now).
 *   requestNonce    the nonce the client sent; when given, the response MUST echo it (constant-time).
 *   historicalMode  defer a strictly-future revocation (report good) instead of revoking on skew.
 * @example
 *   var res = await pki.ocsp.verify(responseDer, { cert: leafDer, issuer: caDer });
 *   res.status;   // "good" | "revoked" | "unknown"
 */
function verify(response, opts) {
  opts = opts || {};
  if (opts.cert == null || opts.issuer == null) return Promise.reject(_err("ocsp/bad-input", "verify requires opts.cert and opts.issuer"));
  var parsed, cert, issuerCert, time;
  try {
    parsed = (response && response.responseStatus) ? response : ocspSchema.parseResponse(_toDer(response, "the OCSP response"));
    cert = _certOf(opts.cert, "the target certificate");
    issuerCert = _certOf(opts.issuer, "the issuer certificate");
    // The time drives the currency + responder-cert validity windows; an invalid Date fails closed
    // via _asDate (a NaN compares false against every bound, silently disabling both), never defaults.
    time = opts.time == null ? new Date() : _asDate(opts.time);
  } catch (e) { return Promise.reject(e); }
  return pathValidate.verifyOcspResponse(parsed, cert, issuerCert, time, { historicalMode: opts.historicalMode === true }).then(function (verdict) {
    if (opts.requestNonce == null) return verdict;
    // A client that sent a nonce binds it (RFC 9654 / RFC 5019 sec. 4): a missing or mismatched
    // response nonce fails the verdict closed, even if the status/signature were otherwise good.
    var respNonce = _responseNonce(parsed);
    var reqNonce = Buffer.isBuffer(opts.requestNonce) ? opts.requestNonce : (opts.requestNonce instanceof Uint8Array ? Buffer.from(opts.requestNonce) : null);
    var matched = respNonce != null && reqNonce != null && guard.crypto.constantTimeEqual(respNonce, reqNonce);
    var out = Object.assign({}, verdict, { nonceMatched: matched });
    if (!matched && verdict.status !== "unknown") {
      return Object.assign(out, { status: "unknown", reason: "the OCSP response nonce does not echo the request nonce (RFC 9654)" });
    }
    return out;
  });
}
function _responseNonce(parsed) {
  var br = parsed && parsed.basicResponse;
  var exts = (br && br.responseExtensions) || [];
  for (var i = 0; i < exts.length; i++) if (exts[i].oid === OID_OCSP_NONCE) return exts[i].nonce || null;
  return null;
}

module.exports = {
  buildRequest: buildRequest,
  sign: sign,
  buildErrorResponse: buildErrorResponse,
  verify: verify,
};
