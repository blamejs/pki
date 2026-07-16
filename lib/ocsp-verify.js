// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surfaces are pki.path.ocspChecker
// (revocation during path validation) and pki.ocsp.verify (standalone RFC 6960 sec. 3.2 client
// acceptance), which BOTH compose this ONE verify core. There is deliberately no second, weaker
// OCSP response-verification path: a standalone verify that re-derived the responder-authorization
// gates would be the exact fail-open the out-of-path-signer-cert-full-validation discipline exists
// to prevent.
//
// The core is a factory over an INJECTED `deps` seam so it has no back-edge into path-validate:
// the signature engine (`verifyWithSpki`) and the RFC 5280 cert-profile gates
// (`decodeExt`/`findExt`/`unrecognizedCriticalExtension`/`validateCriticalExtensionStructure`/
// `compositeKeyUsageCheck`/`isNullOrAbsentParams`/`spliceSpkiParameters`/`dnEqual`) are supplied by
// the caller that owns them; everything OCSP-specific (CertID hash binding, responder
// authorization, currency, status) lives here.
//
// Rule set (gap-checked verbatim against RFC 6960 sec. 3.2 / 4.1.1 / 4.2.2.2 / 4.2.2.2.1):
//   - authorizeResponder: the issuing CA directly (responderID identifies the issuer) OR a
//     CA-issued delegate valid at `time` bearing id-kp-OCSPSigning (anyEKU / absent EKU do NOT
//     authorize), keyUsage-permits-signing, no unknown/malformed critical extension, and
//     id-pkix-ocsp-nocheck (a transport-free verify cannot otherwise confirm the responder is
//     unrevoked); the delegate's own issuance signature is verified under the issuer key.
//   - certIdMatches: serial + issuerNameHash + issuerKeyHash under the CertID's OWN hashAlgorithm
//     (a serial-only match is a cross-CA substitution and is rejected).
//   - currency: thisUpdate <= time and a bounded nextUpdate > time (a nextUpdate-less response is
//     unusable per the lightweight profile).

var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var compositeSig = require("./composite-sig");
var webcrypto = require("./webcrypto");
var subtle = webcrypto.webcrypto.subtle;

// CertID identity-hash algorithms (RFC 6960 sec. 4.1.1). SEPARATE from the signature HASH set
// (which omits SHA-1, SHAttered): a CertID hash is an identity binding of an already-known issuer,
// not a signature, so RFC 6960's default SHA-1 CertID MUST interoperate. A hash outside this set
// cannot be reproduced -> no CertID match (fail closed).
var OCSP_CERTID_HASHES = {};
OCSP_CERTID_HASHES[oid.byName("sha1")] = "SHA-1";
OCSP_CERTID_HASHES[oid.byName("sha256")] = "SHA-256";
OCSP_CERTID_HASHES[oid.byName("sha384")] = "SHA-384";
OCSP_CERTID_HASHES[oid.byName("sha512")] = "SHA-512";
var OID_OCSP_SIGNING = oid.byName("ocspSigning");
var OID_OCSP_NOCHECK = oid.byName("ocspNoCheck");
var OID_EKU = oid.byName("extKeyUsage");
var OID_KEY_USAGE = oid.byName("keyUsage");

function ocspDigest(alg, buf) { return subtle.digest(alg, buf).then(function (h) { return Buffer.from(h); }); }

// The subjectPublicKey BIT STRING VALUE (past the unused-bits octet) of an SPKI DER -- the exact
// bytes an OCSP CertID issuerKeyHash / byKey KeyHash hash over (RFC 6960 sec. 4.1.1). Throws on a
// malformed SPKI; the caller fails closed.
function ocspKeyValue(spkiDer) {
  return asn1.read.bitString(asn1.decode(spkiDer).children[1]).bytes;
}

// makeOcspVerify(deps) -> the bound OCSP verify core. deps = { verifyWithSpki, decodeExt, findExt,
// unrecognizedCriticalExtension, validateCriticalExtensionStructure, compositeKeyUsageCheck,
// isNullOrAbsentParams, spliceSpkiParameters, dnEqual } -- the signature engine + RFC 5280
// cert-profile gates owned by the caller.
function makeOcspVerify(deps) {
  var verifyWithSpki = deps.verifyWithSpki;
  var decodeExt = deps.decodeExt;
  var findExt = deps.findExt;
  var unrecognizedCriticalExtension = deps.unrecognizedCriticalExtension;
  var validateCriticalExtensionStructure = deps.validateCriticalExtensionStructure;
  var compositeKeyUsageCheck = deps.compositeKeyUsageCheck;
  var isNullOrAbsentParams = deps.isNullOrAbsentParams;
  var spliceSpkiParameters = deps.spliceSpkiParameters;
  var dnEqual = deps.dnEqual;

  // The delegate responder's importable SPKI, splicing the issuer's algorithm parameters in when
  // the delegate key inherits them (an EC SPKI that omits the namedCurve, RFC 5280 sec. 4.1.2.7).
  function ocspResponderSpki(rc, issuer) {
    var keyAlg = rc.subjectPublicKeyInfo.algorithm;
    if (!isNullOrAbsentParams(keyAlg.parameters)) return rc.subjectPublicKeyInfo.bytes;
    var issuerOid, issuerParams;
    // Coverage residual -- the catch is unreachable: this runs only after the delegate's signature
    // verified under issuer.workingPublicKey, so that SPKI already imported and decodes cleanly.
    try {
      var alg = asn1.decode(issuer.workingPublicKey).children[0];
      issuerOid = asn1.read.oid(alg.children[0]);
      issuerParams = alg.children[1] ? alg.children[1].bytes : null;
    } catch (_e) { return rc.subjectPublicKeyInfo.bytes; }
    if (issuerOid === keyAlg.oid && !isNullOrAbsentParams(issuerParams)) {
      return spliceSpkiParameters(rc.subjectPublicKeyInfo, keyAlg.oid, issuerParams);
    }
    return rc.subjectPublicKeyInfo.bytes;
  }

  // Returns true if `extList` carries any critical extension (this code processes no OCSP
  // response/single extension semantics, so a critical one makes the response unusable).
  function ocspHasCriticalExtension(extList) {
    if (!extList) return false;
    for (var i = 0; i < extList.length; i++) if (extList[i].critical) return true;
    return false;
  }

  // A SingleResponse's CertID names the target cert IFF serial AND issuerNameHash + issuerKeyHash
  // (under the CertID's OWN hashAlgorithm) match the issuer. `issuerNameCandidates` is every RFC
  // 5280 sec. 7.1-equal byte encoding of the validated issuer DN to try.
  async function ocspCertIdMatches(certID, cert, issuerNameCandidates, issuerKeyBits) {
    if (certID.serialNumberHex !== cert.serialNumberHex) return false;
    var hashName = OCSP_CERTID_HASHES[certID.hashAlgorithm.oid];
    if (!hashName) return false;
    var keyHash = await ocspDigest(hashName, issuerKeyBits);
    if (!certID.issuerKeyHash.equals(keyHash)) return false;
    for (var i = 0; i < issuerNameCandidates.length; i++) {
      if (certID.issuerNameHash.equals(await ocspDigest(hashName, issuerNameCandidates[i]))) return true;
    }
    return false;
  }

  // Resolve the signer of a BasicOCSPResponse to an AUTHORIZED responder SPKI DER, or null. Two
  // models: the issuing CA directly, or a CA-delegated responder (RFC 6960 sec. 4.2.2.2). Fails
  // closed at every branch.
  async function ocspAuthorizeResponder(basicResponse, cert, issuer, issuerKeyBits, time) {
    var rid = basicResponse.responderID;
    var matchesIssuer = false;
    try {
      if (rid.byName) matchesIssuer = dnEqual(rid.byName.rdns, cert.issuer.rdns);
      else if (rid.byKey) matchesIssuer = rid.byKey.equals(await ocspDigest("SHA-1", issuerKeyBits));
    } catch (_e) { matchesIssuer = false; }
    if (matchesIssuer) return issuer.workingPublicKey;

    for (var i = 0; i < basicResponse.certs.length; i++) {
      var rc;
      try { rc = x509.parse(basicResponse.certs[i]); }
      catch (_e) { continue; }
      var identifies = false;
      try {
        if (rid.byName) identifies = dnEqual(rid.byName.rdns, rc.subject.rdns);
        else if (rid.byKey) identifies = rid.byKey.equals(await ocspDigest("SHA-1", ocspKeyValue(rc.subjectPublicKeyInfo.bytes)));
      } catch (_e) { identifies = false; }
      if (!identifies) continue;
      // The delegate MUST be issued directly by the CA that issued the target.
      var issuedByCa;
      try { issuedByCa = dnEqual(rc.issuer.rdns, cert.issuer.rdns); }
      catch (_e) { continue; }
      if (!issuedByCa) continue;
      if (!isOctetAligned(rc.signatureValue)) continue;
      if (!(await verifyWithSpki(rc.signatureAlgorithm, rc.signatureValue.bytes, issuer.workingPublicKey, rc.tbsBytes))) continue;
      // The delegate cert MUST itself be valid at the validation instant.
      if (time < rc.validity.notBefore || time > rc.validity.notAfter) continue;
      // The delegate MUST assert id-kp-OCSPSigning; anyEKU / an absent EKU do not.
      var eku;
      try { eku = decodeExt(rc, OID_EKU); }
      catch (_e) { continue; }
      if (!eku || eku.value.indexOf(OID_OCSP_SIGNING) === -1) continue;
      // A delegate asserting keyUsage MUST permit digitalSignature; an absent keyUsage is
      // unrestricted, an unreadable one is not authoritative.
      var ku;
      try { ku = decodeExt(rc, OID_KEY_USAGE); }
      catch (_e) { continue; }
      if (ku && ku.value.digitalSignature !== true) continue;
      // An unknown critical extension (or a recognized-but-malformed one) makes the delegate
      // unusable, the same fail-closed rule the path validator applies.
      if (unrecognizedCriticalExtension(rc, false)) continue;
      if (validateCriticalExtensionStructure(rc)) continue;
      // The delegate MUST carry id-pkix-ocsp-nocheck (RFC 6960 sec. 4.2.2.2.1): a transport-free
      // checker cannot otherwise confirm the responder cert is unrevoked.
      if (!findExt(rc, OID_OCSP_NOCHECK)) continue;
      // A composite-keyed delegate gets the same composite keyUsage gate the path certs do.
      if (compositeSig.COMPOSITE_ALGS[rc.subjectPublicKeyInfo.algorithm.oid] && !compositeKeyUsageCheck(rc).ok) continue;
      return ocspResponderSpki(rc, issuer);
    }
    return null;
  }

  // A BIT STRING is octet-aligned iff its unused-bits count is 0 -- reused from the caller's
  // guard so a non-octet-aligned responder signature is never verified.
  function isOctetAligned(bitString) { return !!bitString && bitString.unusedBits === 0; }

  // evaluateResponse(resp, cert, issuer, issuerKeyBits, issuerNameCandidates, time, historical) ->
  // a granular per-response SUMMARY for ONE parsed OCSPResponse, aggregating over ALL of its
  // matching SingleResponses (a revoked SingleResponse shadows a good one WITHIN the response, the
  // same fail-closed law the multi-response aggregator applies). Never throws (fail-closed):
  //   { applicable, responderAuthorized, signatureValid, matched, revoked:{reason,revocationReason}?,
  //     sawGood, sawUnknownStatus, thisUpdate?, nextUpdate?, reason }
  async function evaluateResponse(resp, cert, issuer, issuerKeyBits, issuerNameCandidates, time, historical) {
    if (resp.responseStatus.code !== 0) return { applicable: false, matched: false, reason: "non-successful OCSP responseStatus (" + resp.responseStatus.code + ")" };
    var br = resp.basicResponse;
    // Coverage residual -- unreachable for a parsed response (schema-ocsp enforces the
    // successful<->responseBytes biconditional); backstop for a hand-built object.
    if (!br) return { applicable: false, matched: false, reason: "successful OCSP response carries no BasicOCSPResponse" };
    var signerSpki = await ocspAuthorizeResponder(br, cert, issuer, issuerKeyBits, time);
    if (!signerSpki) return { applicable: true, matched: false, responderAuthorized: false, reason: "no authorized OCSP responder signs this response (RFC 6960 sec. 4.2.2.2)" };
    if (!(await verifyWithSpki(br.signatureAlgorithm, br.signature, signerSpki, br.tbsResponseDataBytes))) {
      return { applicable: true, matched: false, responderAuthorized: true, signatureValid: false, reason: "the OCSP response signature does not verify over tbsResponseData" };
    }
    if (ocspHasCriticalExtension(br.responseExtensions)) {
      return { applicable: true, matched: false, responderAuthorized: true, signatureValid: true, reason: "the OCSP response carries an unrecognized critical extension" };
    }
    var out = { applicable: true, matched: false, responderAuthorized: true, signatureValid: true, revoked: null, sawGood: false, sawUnknownStatus: false, reason: "no current SingleResponse names this certificate" };
    for (var s = 0; s < br.responses.length; s++) {
      var sr = br.responses[s];
      if (!(await ocspCertIdMatches(sr.certID, cert, issuerNameCandidates, issuerKeyBits))) continue;
      if (ocspHasCriticalExtension(sr.singleExtensions)) continue;
      if (sr.thisUpdate > time) continue;
      if (!sr.nextUpdate || sr.nextUpdate < time) continue;
      out.matched = true; out.thisUpdate = sr.thisUpdate; out.nextUpdate = sr.nextUpdate;
      var st = sr.certStatus;
      if (st.type === "revoked") {
        // Present-time validation revokes regardless of a future revocationTime (skew/post-dating);
        // only explicit historical validation defers a strictly-future revocation (reports good).
        if (historical && st.revocationTime instanceof Date && st.revocationTime.getTime() > time.getTime()) { out.sawGood = true; }
        else if (!out.revoked) { out.revoked = { revocationReason: st.revocationReason || null, reason: "certificate reported revoked by an authorized OCSP responder" + (st.revocationReason ? " (" + st.revocationReason + ")" : "") }; }
      } else if (st.type === "good") { out.sawGood = true; }
      else { out.sawUnknownStatus = true; }
    }
    return out;
  }

  return {
    evaluateResponse: evaluateResponse,
    authorizeResponder: ocspAuthorizeResponder,
    certIdMatches: ocspCertIdMatches,
    hasCriticalExtension: ocspHasCriticalExtension,
    responderSpki: ocspResponderSpki,
  };
}

module.exports = { makeOcspVerify: makeOcspVerify, ocspKeyValue: ocspKeyValue, ocspDigest: ocspDigest, OCSP_CERTID_HASHES: OCSP_CERTID_HASHES };
