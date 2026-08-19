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
// default for the CertID identity hash (not a signature; collision resistance is irrelevant to the
// lookup, so SHAttered does not bar it, the same deliberate split path-validate makes).
var HASH_WC = { sha1: "SHA-1", sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
// A CRLReason name -> its enumerated value (RFC 5280 sec. 5.3.1), reverse of pki.C.NAMES.CRL_REASON.
var REASON_CODE = {};
Object.keys(constants.NAMES.CRL_REASON).forEach(function (k) { REASON_CODE[constants.NAMES.CRL_REASON[k]] = parseInt(k, 10); });
var OID_OCSP_NONCE = O("ocspNonce");
var OID_OCSP_BASIC = O("ocspBasic");
var OID_EXTENDED_REVOKE = O("ocspExtendedRevoke");

function _digest(wcHash, buf) { return subtle.digest(wcHash, buf).then(function (h) { return Buffer.from(h); }); }
function _certOf(arg, what) {
  var label = what || "a certificate";
  // Re-derived from the bytes its parser read, like every other certificate door. A CertID is an
  // IDENTITY -- the issuer's name and key hashed, plus the serial -- so a certificate that names one
  // identity while carrying another's signed bytes would have this verb ask about, or answer for,
  // a certificate nobody issued.
  return guard.parsed.acceptDerived(arg, "certificate", function (bytes) {
    var der = bytes;
    if (typeof bytes === "string") {
      try { der = x509.pemDecode(bytes); } catch (e) { throw _err("ocsp/bad-input", label + " PEM could not be decoded", e); }
    }
    try { return x509.parse(der); } catch (e) { throw _err("ocsp/bad-input", label + " is not a well-formed X.509 certificate", e); }
  }, _err, "ocsp/bad-input", label);
}
// The response, always parsed from the bytes the caller handed over. See verify's own comment for
// why an object cannot be accepted here: the three parts of a signature check would come from three
// independently-chosen properties. The claim is detected on any of the parsed-response fields, so a
// caller who passes one is told what happened, never given a byte-parse fault about its type.
var _RESPONSE_CLAIM = ["responseStatus", "basicResponse", "tbsResponseDataBytes"];
function _responseFromBytes(response) {
  return guard.parsed.fromTrustedSource(response, "ocspResponse", _RESPONSE_CLAIM, function (bytes) {
    return ocspSchema.parseResponse(_toDer(bytes, "the OCSP response"));
  }, _err, "ocsp/bad-input",
  "the OCSP response must be its DER bytes, a PEM string, or an unmodified pki.schema.ocsp.parseResponse result: the signature, the algorithm that verifies it and the bytes it covers are separate properties of a parsed object, so a REBUILT response (Object.assign, spread, a JSON round-trip) could have the three describe different responses and is refused");
}

function _toDer(input, what) {
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) return guard.bytes.snapshot(input, OcspError, "ocsp/bad-input", what || "input");
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
 *   nonce          `true` for a fresh 32-octet CSPRNG nonce (RFC 9654), or a caller Buffer (1..128 octets).
 *   requestorName  a Name (RDN array) placed in the [1] requestorName as a directoryName.
 *   signer         `{ cert, key }` to sign the request (requires requestorName).
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
  // Both arguments copied at entry and released when the call settles -- see the note on the same
  // call in x509-sign. The request is assembled across several promise turns (each CertID is a
  // hash), and opts carries byte fields -- the nonce and requestorName -- that reach the encoding.
  return guard.bytes.fixedCall(OcspError, "ocsp/bad-input", [
    [query, "the OCSP request query"], [opts, "pki.ocsp.buildRequest options"],
  ], _buildRequest);
}

// Every option pki.ocsp.buildRequest reads. `nonce` earns the named refusal: it is the
// anti-replay binding, and a misspelling ships a request with no nonce at all, which the
// responder answers happily and the caller cannot later bind to.
// Taken from this verb's own @opts block, which is the published contract; a grep of the
// function body misses `pem`, read by the shared emitter rather than here.
var _BUILD_REQUEST_OPTS = {
  hashAlgorithm: 1, nonce: 1, pem: 1, profile: 1, requestorName: 1, signer: 1
};

function _buildRequest(query, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "ocsp/bad-input", "pki.ocsp.buildRequest options");
  guard.identifier.assertKnownKeys(opts, _BUILD_REQUEST_OPTS, _err, "ocsp/bad-input",
    "pki.ocsp.buildRequest has an unknown option (the anti-replay nonce is `nonce`): ");
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
  if (Buffer.isBuffer(name)) return guard.bytes.snapshot(name, OcspError, "ocsp/bad-input", "requestorName");
  if (name && name.bytes) return name.bytes;   // a parsed Name
  throw _err("ocsp/bad-input", "requestorName must be a DER Name Buffer or a parsed Name");
}
// The RAW DER of a certificate that will be embedded verbatim (the responder cert in a
// BasicOCSPResponse, the signer cert in a signed OCSPRequest). It must be supplied as bytes:
// a parsed certificate does not retain its full DER encoding, and re-encoding it would risk
// byte drift from the signed original, so a parsed cert is rejected rather than reconstructed.
function _normCertDer(cert, what) {
  if (Buffer.isBuffer(cert) || cert instanceof Uint8Array) return guard.bytes.snapshot(cert, OcspError, "ocsp/bad-input", what || "a certificate");
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
 * @opts
 *   nonce           a request nonce Buffer to echo back in responseExtensions (RFC 9654).
 *   extendedRevoke  emit the id-pkix-ocsp-extended-revoke extension (RFC 6960 sec. 4.4.8).
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
// Documented `-> Promise`, so a fault leaves as a REJECTION (guard-async); the checks stay
// synchronous because they read the responder's mutable cert and key.
function sign(responseData, responder, opts) {
  // Every caller-owned argument copied at entry and released when the call settles -- see the note
  // on the same call in x509-sign.
  return guard.bytes.fixedCall(OcspError, "ocsp/bad-input", [
    [responseData, "the OCSP responseData"], [responder, "the responder"], [opts, "pki.ocsp.sign options"],
  ], _sign);
}

// Every option pki.ocsp.sign reads. `nonce` here is the request nonce this response echoes back.
// A misspelling emits a response that answers nobody's request, and the client that sent a nonce
// then reads it as unbound.
var _SIGN_OPTS = { embedCert: 1, extendedRevoke: 1, nonce: 1, pem: 1 };

function _sign(responseData, responder, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "ocsp/bad-input", "pki.ocsp.sign options");
  guard.identifier.assertKnownKeys(opts, _SIGN_OPTS, _err, "ocsp/bad-input",
    "pki.ocsp.sign has an unknown option (the nonce to echo back is `nonce`): ");
  responseData = responseData || {};
  if (!responder || responder.cert == null || responder.key == null) throw _err("ocsp/bad-input", "a responder must be { cert, key }");
  var respCertDer = _normCertDer(responder.cert, "the responder certificate");
  var respCert = _certOf(respCertDer, "the responder certificate");
  // Read with the certificate, not after the awaits below. The ResponderID and the
  // embedded certificate are both fixed from `respCert` here; the signature is made
  // several promise turns later, so a `responder` whose key was replaced in between
  // would produce a response naming one responder and signed by another key.
  //
  // Capturing the REFERENCE only closes half of that: it stops `responder.key = other`,
  // but PKCS#8 arrives as caller-owned BYTES and a composite key as a caller-owned
  // { mldsa, trad } object, either of which can be rewritten in place across the same
  // gap with the same result -- a response carrying this responder's ID and certificate
  // over a signature made by a different key, which no relying party can verify. So the
  // material itself is snapshotted here, not just the binding to it. A CryptoKey is
  // opaque and a PEM string is immutable, so both are already safe by reference.
  var ownedKeyBytes = [];
  var responderKey = _snapshotSignerKey(responder.key, ownedKeyBytes);
  // The copy is cleared on the failing path as well as the succeeding one -- a wrong or
  // malformed key is the case an attacker can force, so a success-only wipe would keep the
  // secret exactly when it matters. The wipe covers the WHOLE window the copy exists, not
  // just the signing call: the copy is taken before the response list, the responder ID, the
  // SingleResponses, the dates, the nonce and the signature scheme are validated, and every
  // one of those can fail. Attaching cleanup to signing alone leaves the secret in the heap
  // on each of those earlier exits, which are the easiest ones for a caller to reach.
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

// Everything from the key snapshot onward, so a single cleanup in the caller covers every
// exit -- sync throw and async rejection alike -- rather than each fallible step needing to
// remember. `responderKey` is the private copy; it is never the caller's object.
function _signResponse(responseData, responder, respCert, respCertDer, responderKey, opts) {
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
// A date value -> Date, or null when absent (the caller defaults). An unparseable value is a
// config-time error, not a silently-emitted Invalid Date: a NaN date would encode as a malformed
// GeneralizedTime in a SIGNED response, and compare false against every currency bound on verify.
function _asDate(d) {
  if (d == null) return null;
  var dt = guard.time.isDate(d) ? d : new Date(d);
  if (isNaN(guard.time.instantOf(dt))) throw _err("ocsp/bad-input", "an invalid date value " + JSON.stringify(d));
  return dt;
}
// A private copy of whatever signer-key material the caller owns, taken at the entry
// point because signing happens several promise turns later (see `sign`). Bytes are
// copied; a composite { mldsa, trad } is rebuilt with each component copied, since
// rewriting a component is the same attack one level down. Anything else -- a CryptoKey,
// a PEM string -- is not caller-mutable in a way that changes the key, so it rides as-is
// rather than being coerced into a shape this function does not understand.
// `owned` collects every buffer THIS function allocated, so the caller can clear them once
// signing is done. A copy of a private key is a second copy of a secret, which is precisely
// what this project's secret-lifetime discipline exists to avoid -- so the copy that closes
// the aliasing window is wiped rather than left to the garbage collector. Only our own
// allocations are listed: the caller's key is never written to.
function _snapshotSignerKey(key, owned) {
  if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
    var copy = guard.bytes.snapshot(key, OcspError, "ocsp/bad-input", "the responder key");
    owned.push(copy);
    return copy;
  }
  // The test is "is this a composite DESCRIPTOR", not "does it currently hold bytes". A
  // composite whose components are both PEM strings carries nothing mutable inside it, but
  // the OBJECT is still the caller's: reassigning `key.mldsa` after the call reaches the
  // deferred signing operation just as rewriting a buffer would, and yields a response whose
  // responder ID and embedded certificate describe one responder over a signature made by
  // another key. So the container is always rebuilt, and each component is snapshotted by
  // its own type -- bytes copied, an immutable PEM string passed through.
  if (key && typeof key === "object" && (key.mldsa != null || key.trad != null)) {
    return Object.assign({}, key, { mldsa: _snapshotSignerKey(key.mldsa, owned), trad: _snapshotSignerKey(key.trad, owned) });
  }
  return key;
}

function _responderID(rid, respCert) {
  if (rid == null || rid === "byName") return Promise.resolve(b.explicit(1, b.raw(respCert.subject.bytes)));   // byName [1] EXPLICIT Name
  if (rid === "byKey") return _digest("SHA-1", _keyValue(respCert.subjectPublicKeyInfo.bytes)).then(function (kh) { return b.explicit(2, b.octetString(kh)); });
  throw _err("ocsp/bad-input", "responderID must be \"byName\" or \"byKey\"");
}
function _buildSingleResponse(r, opts) {
  r = r || {};
  var certIdP;
  // A pre-encoded CertID is spliced in RAW, so its type is checked rather than coerced:
  // Buffer.from(20) would allocate twenty zero octets and emit a structurally broken
  // CertID inside a response this responder then SIGNS.
  if (r.certID != null) certIdP = Promise.resolve(b.raw(guard.bytes.view(r.certID, OcspError, "ocsp/bad-input", "a response entry's certID")));
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
 * @status stable
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
// Every option pki.ocsp.verify reads. `requestNonce` is the one worth refusing by name: it is
// what binds the response to this request. A misspelling leaves nonceMatched null on a call
// that did ask, and null is the value meaning "the client never asked".
var _VERIFY_OPTS = { cert: 1, historicalMode: 1, issuer: 1, requestNonce: 1, time: 1 };

function verify(response, opts) {
  // This verb reports faults by rejecting, not throwing, so both entry guards run inside the
  // same try and surface as a rejection like every other fault on this path.
  try {
    opts = guard.identifier.optionsObject(opts, _err, "ocsp/bad-input", "pki.ocsp.verify options");
    guard.identifier.assertKnownKeys(opts, _VERIFY_OPTS, _err, "ocsp/bad-input",
      "pki.ocsp.verify has an unknown option (the request nonce to bind against is `requestNonce`): ");
  } catch (e) { return Promise.reject(e); }
  if (opts.cert == null || opts.issuer == null) return Promise.reject(_err("ocsp/bad-input", "verify requires opts.cert and opts.issuer"));
  var parsed, cert, issuerCert, time;
  try {
    // The response is parsed from BYTES, always. A claimed-parsed response carries the signature,
    // the algorithm that verifies it and the byte range it covers as three independent properties,
    // so an object could pair one structure's tbsResponseDataBytes with another's signature -- and a
    // signature the issuing CA made over a certificate it issued would verify as a ResponseData
    // signature, returning status "good" for a certificate the responder never spoke about.
    // Parsing here binds all three to one byte string. pki.schema.ocsp.parseResponse remains the
    // parse-only route for a caller who wants the structure without a verdict.
    parsed = _responseFromBytes(response);
    cert = _certOf(opts.cert, "the target certificate");
    issuerCert = _certOf(opts.issuer, "the issuer certificate");
    // The time drives the currency + responder-cert validity windows; an invalid Date fails closed
    // via _asDate (a NaN compares false against every bound, silently disabling both), never defaults.
    time = opts.time == null ? new Date() : _asDate(opts.time);
  } catch (e) { return Promise.reject(e); }
  // The object parsed HERE goes to the verdict verb, not the caller's argument again. It carries the
  // parser's record, so the verdict verb re-derives from the same recorded bytes -- one snapshot,
  // read by both. Passing the caller's argument a second time would take a SECOND snapshot of it,
  // and a shared-memory view can differ between the two: the nonce compared below would belong to
  // one response and the signature verified to another, which is the split this whole mechanism
  // exists to close.
  return pathValidate.verifyOcspResponse(parsed, cert, issuerCert, time, { historicalMode: opts.historicalMode === true }).then(function (verdict) {
    // A client that sent no nonce still gets the field, as null. Leaving it absent would make
    // "not requested" indistinguishable from "the field is not there yet" for a consumer reading
    // res.nonceMatched, and the three-state contract is the whole point: true bound, false not
    // bound, null never asked. The verdict is copied rather than mutated, since it is the lower
    // primitive's object and this layer does not own it.
    if (opts.requestNonce == null) return Object.assign({}, verdict, { nonceMatched: null });
    // A client that sent a nonce binds it (RFC 9654 / RFC 5019 sec. 4): a missing or mismatched
    // response nonce fails the verdict closed, even if the status/signature were otherwise good.
    var respNonce = _responseNonce(parsed);
    var reqNonce = (Buffer.isBuffer(opts.requestNonce) || opts.requestNonce instanceof Uint8Array)
      ? guard.bytes.snapshot(opts.requestNonce, OcspError, "ocsp/bad-input", "opts.requestNonce") : null;
    var matched = respNonce != null && reqNonce != null && guard.crypto.constantTimeEqual(respNonce, reqNonce);
    var out = Object.assign({}, verdict, { nonceMatched: matched });
    // The downgrade applies to `good` ONLY. `unknown` is the closed direction for a
    // response claiming the certificate is fine, because an unmatched nonce means
    // this is not an answer to this request and the "fine" may be stale. It is NOT
    // the closed direction for `revoked`: revocation does not expire the way
    // non-revocation does, so discarding a signed, current, authorized revoked
    // verdict because it was replayed would hand a soft-fail caller the certificate
    // the responder just refused -- turning the anti-replay defense into the thing
    // that accepts a revoked certificate. `nonceMatched: false` still reports that
    // this response was not bound to this request.
    if (!matched && verdict.status === "good") {
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
