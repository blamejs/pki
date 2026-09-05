// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var asn1 = require("./asn1-der");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var oid = require("./oid");
var x509 = require("./schema-x509");
var compositeSig = require("./composite-sig");
var webcrypto = require("./webcrypto");
var subtle = webcrypto.webcrypto.subtle;

var OCSP_CERTID_HASHES = {};
OCSP_CERTID_HASHES[oid.byName("sha1")] = "SHA-1";
OCSP_CERTID_HASHES[oid.byName("sha256")] = "SHA-256";
OCSP_CERTID_HASHES[oid.byName("sha384")] = "SHA-384";
OCSP_CERTID_HASHES[oid.byName("sha512")] = "SHA-512";
var OID_OCSP_SIGNING = oid.byName("ocspSigning");
var _asserts = guard.list.contains;
var _bufferFrom = intrinsic.bufferFrom;
var _bytesEqual = intrinsic.bufferEquals;
var OID_OCSP_NOCHECK = oid.byName("ocspNoCheck");
var OID_EKU = oid.byName("extKeyUsage");
var OID_KEY_USAGE = oid.byName("keyUsage");

function ocspDigest(alg, buf) { return subtle.digest(alg, buf).then(function (h) { return _bufferFrom(h); }); }

function ocspKeyValue(spkiDer) {
  return asn1.read.bitString(asn1.decode(spkiDer).children[1]).bytes;
}

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

  function ocspResponderSpki(rc, issuer) {
    var keyAlg = rc.subjectPublicKeyInfo.algorithm;
    if (!isNullOrAbsentParams(keyAlg.parameters)) return rc.subjectPublicKeyInfo.bytes;
    var issuerOid, issuerParams;
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

  function ocspHasCriticalExtension(extList) {
    if (!extList) return false;
    for (var i = 0; i < extList.length; i++) if (extList[i].critical) return true;
    return false;
  }

  async function ocspCertIdMatches(certID, cert, issuerNameCandidates, issuerKeyBits) {
    if (certID.serialNumberHex !== cert.serialNumberHex) return false;
    var hashName = intrinsic.hasOwn(OCSP_CERTID_HASHES, certID.hashAlgorithm.oid) ? OCSP_CERTID_HASHES[certID.hashAlgorithm.oid] : null;
    if (!hashName) return false;
    var keyHash = await ocspDigest(hashName, issuerKeyBits);
    if (!_bytesEqual(certID.issuerKeyHash, keyHash)) return false;
    for (var i = 0; i < issuerNameCandidates.length; i++) {
      if (_bytesEqual(certID.issuerNameHash, await ocspDigest(hashName, issuerNameCandidates[i]))) return true;
    }
    return false;
  }

  async function ocspAuthorizeResponder(basicResponse, cert, issuer, issuerKeyBits, time) {
    var rid = basicResponse.responderID;
    var matchesIssuer = false;
    try {
      if (rid.byName) matchesIssuer = dnEqual(rid.byName.rdns, cert.issuer.rdns);
      else if (rid.byKey) matchesIssuer = _bytesEqual(rid.byKey, await ocspDigest("SHA-1", issuerKeyBits));
    } catch (_e) { matchesIssuer = false; }
    if (matchesIssuer) return issuer.workingPublicKey;

    for (var i = 0; i < basicResponse.certs.length; i++) {
      var rc;
      try { rc = x509.parse(basicResponse.certs[i]); }
      catch (_e) { continue; }
      var identifies = false;
      try {
        if (rid.byName) identifies = dnEqual(rid.byName.rdns, rc.subject.rdns);
        else if (rid.byKey) identifies = _bytesEqual(rid.byKey, await ocspDigest("SHA-1", ocspKeyValue(rc.subjectPublicKeyInfo.bytes)));
      } catch (_e) { identifies = false; }
      if (!identifies) continue;
      var issuedByCa;
      try { issuedByCa = dnEqual(rc.issuer.rdns, cert.issuer.rdns); }
      catch (_e) { continue; }
      if (!issuedByCa) continue;
      if (!isOctetAligned(rc.signatureValue)) continue;
      if (!(await verifyWithSpki(rc.signatureAlgorithm, rc.signatureValue.bytes, issuer.workingPublicKey, rc.tbsBytes))) continue;
      if (guard.time.instantOf(time) < guard.time.instantOf(rc.validity.notBefore) ||
        guard.time.instantOf(time) > guard.time.instantOf(rc.validity.notAfter)) continue;
      var eku;
      try { eku = decodeExt(rc, OID_EKU); }
      catch (_e) { continue; }
      if (!eku || !_asserts(eku.value, OID_OCSP_SIGNING)) continue;
      var ku;
      try { ku = decodeExt(rc, OID_KEY_USAGE); }
      catch (_e) { continue; }
      if (ku && ku.value.digitalSignature !== true) continue;
      if (unrecognizedCriticalExtension(rc, false)) continue;
      if (validateCriticalExtensionStructure(rc)) continue;
      if (!findExt(rc, OID_OCSP_NOCHECK)) continue;
      if (compositeSig.COMPOSITE_ALGS[rc.subjectPublicKeyInfo.algorithm.oid] && !compositeKeyUsageCheck(rc).ok) continue;
      return ocspResponderSpki(rc, issuer);
    }
    return null;
  }

  function isOctetAligned(bitString) { return !!bitString && bitString.unusedBits === 0; }

  /**
   * @internal Every field the callers decide on is present on every return, so a field an early
   * return would have left absent is read from the response that was evaluated rather than from
   * whatever a polluted Object.prototype answers: a rejected response would otherwise be able to
   * report `sawGood`, and a certificate with no authoritative response would read as good.
   */
  function _evaluation(extras) {
    return guard.verdict.of({
      applicable: false, matched: false, responderAuthorized: false, signatureValid: false,
      revoked: null, sawGood: false, sawUnknownStatus: false,
      thisUpdate: null, nextUpdate: null, reason: "",
    }, extras);
  }

  async function evaluateResponse(resp, cert, issuer, issuerKeyBits, issuerNameCandidates, time, historical) {
    if (resp.responseStatus.code !== 0) return _evaluation({ reason: "non-successful OCSP responseStatus (" + resp.responseStatus.code + ")" });
    var br = resp.basicResponse;
    if (!br) return _evaluation({ reason: "successful OCSP response carries no BasicOCSPResponse" });
    var signerSpki = await ocspAuthorizeResponder(br, cert, issuer, issuerKeyBits, time);
    if (!signerSpki) return _evaluation({ applicable: true, reason: "no authorized OCSP responder signs this response (RFC 6960 sec. 4.2.2.2)" });
    if (!(await verifyWithSpki(br.signatureAlgorithm, br.signature, signerSpki, br.tbsResponseDataBytes))) {
      return _evaluation({ applicable: true, responderAuthorized: true, reason: "the OCSP response signature does not verify over tbsResponseData" });
    }
    if (ocspHasCriticalExtension(br.responseExtensions)) {
      return _evaluation({ applicable: true, responderAuthorized: true, signatureValid: true, reason: "the OCSP response carries an unrecognized critical extension" });
    }
    var out = _evaluation({ applicable: true, responderAuthorized: true, signatureValid: true, reason: "no current SingleResponse names this certificate" });
    for (var s = 0; s < br.responses.length; s++) {
      var sr = br.responses[s];
      if (!(await ocspCertIdMatches(sr.certID, cert, issuerNameCandidates, issuerKeyBits))) continue;
      if (ocspHasCriticalExtension(sr.singleExtensions)) continue;
      if (guard.time.instantOf(sr.thisUpdate) > guard.time.instantOf(time)) continue;
      if (!sr.nextUpdate || guard.time.instantOf(sr.nextUpdate) < guard.time.instantOf(time)) continue;
      out.matched = true; out.thisUpdate = sr.thisUpdate; out.nextUpdate = sr.nextUpdate;
      var st = sr.certStatus;
      if (st.type === "revoked") {
        // allow:nan-date-comparison-unguarded -- revocationTime is codec-parsed (NaN-rejected); a NaN check time makes this FAIL CLOSED (sawGood stays unset -> not treated good), and `time` is validated at the pki.ocsp.verify / path.verifyOcspResponse entry points.
        if (historical && guard.time.isDate(st.revocationTime) &&
          guard.time.instantOf(st.revocationTime) > guard.time.instantOf(time)) { out.sawGood = true; }
        else if (!out.revoked) { out.revoked = { revocationReason: st.revocationReason || null, revocationTime: guard.time.isDate(st.revocationTime) ? st.revocationTime : null, reason: "certificate reported revoked by an authorized OCSP responder" + (st.revocationReason ? " (" + st.revocationReason + ")" : "") }; }
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
