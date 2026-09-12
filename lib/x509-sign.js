// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.x509
 * @nav        Signing
 * @title      Certificates
 * @fullname   X.509 certificates: parse, sign and inspect
 * @intro The X.509 certificate-issuance producing side. `pki.x509.sign` builds a `TBSCertificate`,
 *   signs it, and emits a `Certificate` (RFC 5280 sec. 4) that `pki.schema.x509.parse`,
 *   `pki.path.validate`, and OpenSSL all accept, self-signed or CA-signed, over any signature
 *   algorithm the toolkit registry resolves: RSA (PKCS#1 v1.5 / PSS), ECDSA, EdDSA, ML-DSA, SLH-DSA,
 *   and the composite (hybrid) arms. Parsing lives at `pki.schema.x509.parse`.
 * @spec RFC 5280
 * @card Build and sign an X.509 certificate, self-signed or CA-signed, over any registry algorithm.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _isArray = intrinsic.isArray, _bufferEquals = intrinsic.bufferEquals;
var frameworkError = require("./framework-error");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var ct = require("./ct");

var CertificateError = frameworkError.CertificateError;
var NS = pkix.makeNS("x509", CertificateError, oid);
var NAME_SCHEMA = pkix.name(NS);
var SPKI_SCHEMA = pkix.spki(NS);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var b = asn1.build;
function _err(code, message, cause) { return new CertificateError(code, message, cause); }
function _signE(kind, message, cause) { return new CertificateError("x509/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var KNOWN_SPEC_KEYS = intrinsic.assign(intrinsic.create(null), {
  subject: 1, subjectPublicKey: 1, notBefore: 1, notAfter: 1, serialNumber: 1, extensions: 1,
});
var KNOWN_ISSUER_CERT_KEYS = intrinsic.assign(intrinsic.create(null), { key: 1, cert: 1 });
var KNOWN_ISSUER_EXPLICIT_KEYS = intrinsic.assign(intrinsic.create(null), { key: 1, name: 1, publicKey: 1 });
var KNOWN_SIGN_OPTS = intrinsic.assign(intrinsic.create(null), { digestAlgorithm: 1, pem: 1, pss: 1 });

var KNOWN_EXT_KEYS = intrinsic.assign(intrinsic.create(null), {
  subjectKeyIdentifier: 1, authorityKeyIdentifier: 1, keyUsage: 1, keyUsageCritical: 1,
  extendedKeyUsage: 1, extendedKeyUsageCritical: 1, basicConstraints: 1, subjectAltName: 1,
  certificatePolicies: 1, certificatePoliciesCritical: 1, nameConstraints: 1,
  authorityInfoAccess: 1, cRLDistributionPoints: 1, freshestCRL: 1,
  policyConstraints: 1, inhibitAnyPolicy: 1, policyMappings: 1, policyMappingsCritical: 1,
  issuerAltName: 1, qcStatements: 1, qcStatementsCritical: 1,
  precertificatePoison: 1, signedCertificateTimestampList: 1,
  msCertificateTemplate: 1, msEnrollCertType: 1, msCaVersion: 1, msPreviousCertHash: 1,
  msApplicationPolicies: 1,
  subjectInfoAccess: 1, subjectDirectoryAttributes: 1, ocspNoCheck: 1,
});

var _b = pkiBuild.makeBuilder({ ErrorClass: CertificateError, prefix: "x509", O: O, NS: NS, NAME_SCHEMA: NAME_SCHEMA, SPKI_SCHEMA: SPKI_SCHEMA, EXT_DECODERS: EXT_DECODERS });
var _encodeName = _b.encodeName, _isEmptyName = _b.isEmptyName, _reqDer = _b.reqDer,
  _assertValidSpki = _b.assertValidSpki, _assertValidExtension = _b.assertValidExtension,
  _assertCertCriticality = _b.assertCertCriticality,
  _certLikeFromSpki = _b.certLikeFromSpki, _assertCertVerifies = _b.assertSignatureVerifies,
  _ext = _b.ext, _extBasicConstraints = _b.extBasicConstraints, _validateBcSpec = _b.validateBcSpec,
  _extKeyUsage = _b.extKeyUsage, _extExtKeyUsage = _b.extExtKeyUsage, _extSki = _b.extSki,
  _extNameConstraints = _b.extNameConstraints, _extAia = _b.extAuthorityInfoAccess,
  _extCrlDp = _b.extCrlDistributionPoints, _extPolicyConstraints = _b.extPolicyConstraints,
  _extInhibitAnyPolicy = _b.extInhibitAnyPolicy, _extPolicyMappings = _b.extPolicyMappings,
  _encodeGeneralNames = _b.encodeGeneralNames, _reqDenseArray = _b.reqDenseArray,
  _extQcStatements = _b.extQcStatements,
  _extAki = _b.extAki, _extSan = _b.extSan, _extCertPolicies = _b.extCertPolicies,
  _skiKeyId = _b.skiKeyId, _spkiKeyId = _b.spkiKeyId, _serialInteger = _b.serialInteger;


function _akiKeyId(val, ctx) {
  var issuerSki = ctx.issuerCert ? _b.skiValueOf(ctx.issuerCert) : null;
  if (guard.bytes.isByteSource(val)) {
    var given = guard.bytes.snapshotSource(val, CertificateError, "x509/bad-input", "the authorityKeyIdentifier keyIdentifier");
    /** @internal Sec. 4.2.1.2: the issuer certificate's subjectKeyIdentifier MUST be the value
     *  placed in the authorityKeyIdentifier of what it issues, so a stated value is held to it. */
    if (issuerSki && !_bufferEquals(given, issuerSki)) {
      throw _err("x509/bad-input", "the authorityKeyIdentifier keyIdentifier must equal the issuer certificate's subjectKeyIdentifier (RFC 5280 sec. 4.2.1.2); omit it to take that value");
    }
    return given;
  }
  if (val === true) return issuerSki || _spkiKeyId(ctx.issuerSpki);
  throw _err("x509/bad-input", "authorityKeyIdentifier must be true (auto-derive from the issuer) or a Buffer key id");
}

/** @internal The extension also names the issuing certificate directly (RFC 5280 sec. 4.2.1.1), so
 *  the spec takes the object form beside the `true` and key-id shorthands. The key id is resolved
 *  here because only this verb knows the issuer being signed under. */
function _akiFields(val, ctx) {
  if (val === true || guard.bytes.isByteSource(val)) return [_akiKeyId(val, ctx), null, null];
  if (typeof val !== "object" || _isArray(val)) {
    throw _err("x509/bad-input", "authorityKeyIdentifier must be true, a Buffer key id, or an object { keyIdentifier, authorityCertIssuer, authorityCertSerialNumber }");
  }
  guard.identifier.assertKnownKeys(val, _b.AKI_KEYS, _err, "x509/bad-input", function (k) {
    return "unknown authorityKeyIdentifier field " + guard.text.showValue(k) + " (accepted: keyIdentifier, authorityCertIssuer, authorityCertSerialNumber)";
  });
  /** @internal The pair identifies the certificate whose key signed this one, so when that
   *  certificate is the issuer being signed under, `true` takes its issuer name and serial from it.
   *  A caller that states the values itself keeps them, since an issuer given as a bare name and key
   *  carries no certificate to read them from. */
  var issuerName = val.authorityCertIssuer, serial = val.authorityCertSerialNumber;
  if (issuerName === true || serial === true) {
    if (!ctx.issuerCert) {
      throw _err("x509/bad-input", "authorityCertIssuer and authorityCertSerialNumber derive from the issuing certificate, so they are named directly when the issuer is given as a name and key");
    }
    if (issuerName === true) issuerName = [{ directoryName: ctx.issuerCert.issuer.bytes }];
    if (serial === true) serial = "0x" + ctx.issuerCert.serialNumberHex;
  }
  /** @internal Sec. 4.2.1.1: the keyIdentifier field MUST be included in every certificate a
   *  conforming CA generates, self-signed ones excepted, so the object form carries it unless
   *  declined, and declining it is refused where the section allows no omission. */
  var keyId = val.keyIdentifier == null ? true : val.keyIdentifier;
  if (keyId === false) {
    if (!ctx.selfSigned) throw _err("x509/bad-input", "the authorityKeyIdentifier keyIdentifier MUST be included in every certificate a CA generates other than a self-signed one, so keyIdentifier: false is refused here (RFC 5280 sec. 4.2.1.1)");
    keyId = null;
  } else {
    keyId = _akiKeyId(keyId, ctx);
  }
  return [keyId, issuerName == null ? null : issuerName, serial == null ? null : serial];
}

function _buildExtensions(extSpec, ctx) {
  if (extSpec == null) extSpec = {};
  if (_isArray(extSpec)) {
    var seenExt = intrinsic.create(null), arrCa = false, arrKeyCertSign = false, arrPathLen = false, arrNameConstraints = false;
    var oidBc = O("basicConstraints"), oidKu = O("keyUsage"), oidNc = O("nameConstraints");
    var arr = extSpec.map(function (e, i) {
      var der = _reqDer(e, "extension");
      _assertValidExtension(der, i, EXT_DECODERS);
      var n = asn1.decode(der);
      var extnId = asn1.read.oid(n.children[0]);
      if (seenExt[extnId]) throw _err("x509/bad-input", "duplicate extension " + extnId + " in the extensions array (RFC 5280 sec. 4.2 -- at most one instance of an extension)");
      seenExt[extnId] = true;
      if (extnId === oidNc) arrNameConstraints = true;
      _assertCertCriticality(extnId, n.children.length === 3, "pre-encoded");
      var dec = EXT_DECODERS[extnId];
      if (dec) {
        var decoded;
        try { decoded = dec(asn1.read.octetString(n.children[n.children.length - 1])); }
        catch (e) {
          if (e instanceof CertificateError) throw e;
          throw _err("x509/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension value is malformed", e);
        }
        if (extnId === oidBc) {
          arrCa = decoded.cA === true; arrPathLen = decoded.pathLenConstraint != null;
          if (arrCa && n.children.length !== 3) throw _err("x509/bad-input", "a CA certificate's basicConstraints MUST be critical (RFC 5280 sec. 4.2.1.9)");
        }
        else if (extnId === oidKu) { arrKeyCertSign = decoded.keyCertSign === true; }
      }
      return b.raw(der);
    });
    if (arrKeyCertSign && !arrCa) throw _err("x509/bad-input", "keyUsage keyCertSign requires basicConstraints cA=TRUE (RFC 5280 sec. 4.2.1.3)");
    if (arrPathLen && (!arrCa || !arrKeyCertSign)) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires cA=TRUE and keyUsage keyCertSign (RFC 5280 sec. 4.2.1.9)");
    if (arrNameConstraints && !arrCa) throw _err("x509/bad-input", "nameConstraints appears only in a CA certificate, so it requires basicConstraints cA=TRUE (RFC 5280 sec. 4.2.1.10)");
    _assertCtStagesExclusive(!!seenExt[O("precertificatePoison")], !!seenExt[O("signedCertificateTimestampList")]);
    return arr;
  }
  if (typeof extSpec !== "object") throw _err("x509/bad-input", "extensions must be an object or an array of pre-encoded Extension DER");
  guard.identifier.assertKnownKeys(extSpec, KNOWN_EXT_KEYS, _err, "x509/bad-input", function (k) {
    return "unknown extension " + JSON.stringify(k) + " in the extensions spec; pass a pre-encoded Extension DER via the array form for a custom extension";
  });

  var bc = extSpec.basicConstraints;
  if (bc != null) _validateBcSpec(bc);
  var caTrue = !!(bc && bc.cA === true);
  var ku = extSpec.keyUsage;
  var assertsKeyCertSign = _isArray(ku) && ku.indexOf("keyCertSign") >= 0;
  if (assertsKeyCertSign && !caTrue) throw _err("x509/bad-input", "keyUsage keyCertSign requires basicConstraints cA=TRUE (RFC 5280 sec. 4.2.1.3)");
  if (bc && bc.pathLen != null) {
    if (!caTrue) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires cA=TRUE (RFC 5280 sec. 4.2.1.9)");
    if (!assertsKeyCertSign) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires keyUsage keyCertSign (RFC 5280 sec. 4.2.1.9)");
  }

  var out = [];
  /** @internal Sec. 4.2.1.2: the SKI MUST appear in every CA certificate and SHOULD in every end
   *  entity, so it is emitted unless declined, and declining is refused on a CA. Sec. 4.2.1.1: the
   *  AKI keyIdentifier MUST be included in every certificate a conforming CA generates, the one
   *  exception being a self-signed certificate, so the same shape applies with that exception. */
  var skiVal = extSpec.subjectKeyIdentifier == null ? true : extSpec.subjectKeyIdentifier;
  if (skiVal === false) {
    if (caTrue) throw _err("x509/bad-input", "a CA certificate MUST carry a subjectKeyIdentifier, so subjectKeyIdentifier: false is refused when basicConstraints cA is TRUE (RFC 5280 sec. 4.2.1.2)");
  } else {
    out.push(_ext(O("subjectKeyIdentifier"), false, _extSki(_skiKeyId(skiVal, ctx.spki))));
  }
  var akiVal = extSpec.authorityKeyIdentifier == null ? !ctx.selfSigned : extSpec.authorityKeyIdentifier;
  if (akiVal === false) {
    if (!ctx.selfSigned) throw _err("x509/bad-input", "the authorityKeyIdentifier keyIdentifier MUST be included in every certificate a CA generates other than a self-signed one, so authorityKeyIdentifier: false is refused here (RFC 5280 sec. 4.2.1.1)");
  } else {
    var akiF = _akiFields(akiVal, ctx);
    out.push(_ext(O("authorityKeyIdentifier"), false, _extAki(akiF[0], akiF[1], akiF[2])));
  }
  if (ku != null) out.push(_ext(O("keyUsage"), extSpec.keyUsageCritical !== false, _extKeyUsage(ku)));
  if (extSpec.extendedKeyUsage != null) out.push(_ext(O("extKeyUsage"), !!extSpec.extendedKeyUsageCritical, _extExtKeyUsage(extSpec.extendedKeyUsage)));
  if (bc != null) {
    if (bc.cA === true && bc.critical === false) throw _err("x509/bad-input", "a CA certificate's basicConstraints MUST be critical (RFC 5280 sec. 4.2.1.9)");
    out.push(_ext(O("basicConstraints"), bc.critical !== false, _extBasicConstraints(bc)));
  }
  if (extSpec.subjectAltName != null) out.push(_ext(O("subjectAltName"), ctx.subjectEmpty, _extSan(extSpec.subjectAltName)));
  if (extSpec.certificatePolicies != null) out.push(_ext(O("certificatePolicies"), !!extSpec.certificatePoliciesCritical, _extCertPolicies(extSpec.certificatePolicies)));
  /** @internal Sections 4.2.2.1 and 4.2.1.15 fix these non-critical; sec. 4.2.1.13 states a SHOULD
   *  and the toolkit issues the conforming form. */
  if (extSpec.authorityInfoAccess != null) guard.list.append(out, _ext(O("authorityInfoAccess"), false, _extAia(extSpec.authorityInfoAccess)));
  if (extSpec.cRLDistributionPoints != null) guard.list.append(out, _ext(O("cRLDistributionPoints"), false, _extCrlDp(extSpec.cRLDistributionPoints, "cRLDistributionPoints")));
  if (extSpec.freshestCRL != null) guard.list.append(out, _ext(O("freshestCRL"), false, _extCrlDp(extSpec.freshestCRL, "freshestCRL")));
  /** @internal Sections 4.2.1.11 and 4.2.1.14 fix these critical; sec. 4.2.1.5 states a SHOULD for
   *  policyMappings and sec. 4.2.1.7 a SHOULD for issuerAltName, and the toolkit issues the
   *  conforming form of each. */
  if (extSpec.policyConstraints != null) guard.list.append(out, _ext(O("policyConstraints"), true, _extPolicyConstraints(extSpec.policyConstraints)));
  if (extSpec.inhibitAnyPolicy != null) guard.list.append(out, _ext(O("inhibitAnyPolicy"), true, _extInhibitAnyPolicy(extSpec.inhibitAnyPolicy)));
  /** @internal Sec. 4.2.1.5 states a SHOULD for marking policyMappings critical, and pki.path.validate
   *  does not process the extension, so a critical one is a certificate this toolkit's own validator
   *  must reject and pki.lint.certificate grades `unknown-critical-extension`. The default is the
   *  usable form and the knob reaches the SHOULD-conforming one, as certificatePolicies does. */
  if (extSpec.policyMappings != null) guard.list.append(out, _ext(O("policyMappings"), !!extSpec.policyMappingsCritical, _extPolicyMappings(extSpec.policyMappings)));
  if (extSpec.issuerAltName != null) guard.list.append(out, _ext(O("issuerAltName"), false, _encodeGeneralNames(_reqDenseArray(extSpec.issuerAltName, "issuerAltName"))));
  /** @internal pki.path.validate does not process qcStatements, so a critical one is rejected as an
   *  unrecognized critical extension; the default is the form that validates and the knob reaches
   *  the other, as policyMappings and certificatePolicies do. */
  if (extSpec.qcStatements != null) guard.list.append(out, _ext(O("qcStatements"), !!extSpec.qcStatementsCritical, _extQcStatements(extSpec.qcStatements)));
  if (extSpec.nameConstraints != null) {
    if (!caTrue) throw _err("x509/bad-input", "nameConstraints appears only in a CA certificate, so it requires basicConstraints cA=TRUE (RFC 5280 sec. 4.2.1.10)");
    guard.list.append(out, _ext(O("nameConstraints"), true, _extNameConstraints(extSpec.nameConstraints)));
  }
  _assertCtStagesExclusive(extSpec.precertificatePoison != null, extSpec.signedCertificateTimestampList != null);
  /** @internal Sec. 3.1 fixes the poison critical and its extnValue to ASN.1 NULL: a standard X.509v3
   *  client must refuse the precertificate rather than accept it as an issued certificate. */
  if (extSpec.precertificatePoison != null) {
    if (extSpec.precertificatePoison !== true) throw _err("x509/bad-input", "precertificatePoison is a flag, so it is true or omitted");
    guard.list.append(out, _ext(O("precertificatePoison"), true, asn1.build.nullValue()));
  }
  /** @internal RFC 6962 states no criticality for this extension, and the clients it exists to serve
   *  reconstruct the entry from a certificate they already accepted. A critical one is refused by
   *  every client that does not recognize the OID, this toolkit's own validator included, so no knob
   *  reaches that form; a caller who needs it supplies the Extension pre-encoded. */
  if (extSpec.signedCertificateTimestampList != null) {
    guard.list.append(out, _ext(O("signedCertificateTimestampList"), false,
      _encodeSctList(extSpec.signedCertificateTimestampList)));
  }
  /** @internal The Active Directory Certificate Services enrollment extensions. Neither
   *  pki.path.validate nor pki.lint processes them, so a critical instance is refused as an
   *  unrecognized critical extension by this toolkit's own readers; they are emitted non-critical and
   *  no knob reaches the other form. msApplicationPolicies is read with the certificate-policies
   *  rules, so it takes that spec and shares its encoder. */
  if (extSpec.msCertificateTemplate != null) guard.list.append(out, _ext(O("msCertificateTemplate"), false, _b.extMsCertificateTemplate(extSpec.msCertificateTemplate)));
  if (extSpec.msEnrollCertType != null) guard.list.append(out, _ext(O("msEnrollCertType"), false, _b.extMsEnrollCertType(extSpec.msEnrollCertType)));
  if (extSpec.msCaVersion != null) guard.list.append(out, _ext(O("msCaVersion"), false, _b.extMsCaVersion(extSpec.msCaVersion)));
  if (extSpec.msPreviousCertHash != null) guard.list.append(out, _ext(O("msPreviousCertHash"), false, _b.extMsPreviousCertHash(extSpec.msPreviousCertHash)));
  if (extSpec.msApplicationPolicies != null) guard.list.append(out, _ext(O("msApplicationPolicies"), false, _extCertPolicies(extSpec.msApplicationPolicies)));
  /** @internal Sections 4.2.2.2 and 4.2.1.8 both require a conforming CA to mark these non-critical,
   *  which `assertCertCriticality` also holds the pre-encoded form to. */
  if (extSpec.subjectInfoAccess != null) guard.list.append(out, _ext(O("subjectInfoAccess"), false, _b.extSubjectInfoAccess(extSpec.subjectInfoAccess)));
  if (extSpec.subjectDirectoryAttributes != null) guard.list.append(out, _ext(O("subjectDirectoryAttributes"), false, _b.extSubjectDirectoryAttributes(extSpec.subjectDirectoryAttributes)));
  /** @internal RFC 6960 sec. 4.2.2.2.1 marks an OCSP responder certificate so a client does not ask
   *  about its revocation: the value SHALL be NULL, and the section says it should be non-critical. */
  if (extSpec.ocspNoCheck != null) {
    if (extSpec.ocspNoCheck !== true) throw _err("x509/bad-input", "ocspNoCheck is a flag, so it is true or omitted");
    guard.list.append(out, _ext(O("ocspNoCheck"), false, asn1.build.nullValue()));
  }
  return out;
}


/** @internal RFC 6962 sec. 3.1 and sec. 3.2 put these at the two ends of one exchange: the poison
 *  names the precertificate submitted to a log, and the SCT list names the certificate issued once
 *  the log answers, reconstructed from the other by removing this extension. A certificate carrying
 *  both names no stage of that exchange, and the SCTs in it could never verify. Both the typed spec
 *  and the pre-encoded array reach the same certificate, so both are held to it here. */
function _assertCtStagesExclusive(hasPoison, hasSctList) {
  if (hasPoison && hasSctList) {
    throw _err("x509/bad-input", "precertificatePoison names a precertificate and signedCertificateTimestampList names the certificate issued after it, so a certificate carries one or the other (RFC 6962 sec. 3.2)");
  }
}

/** @internal The SCT list is named as fields in a TYPED spec, so a fault in it is this verb's to
 *  report: pki.ct owns the RFC 6962 sec. 3.3 encoding and raises its own ct/* codes, which name a
 *  module the caller of pki.x509.sign never addressed. */
function _encodeSctList(scts) {
  if (!_isArray(scts)) throw _err("x509/bad-input", "signedCertificateTimestampList must be an array of signed certificate timestamps (RFC 6962 sec. 3.3)");
  try { return ct.encodeSctList(scts); }
  catch (e) {
    if (e instanceof CertificateError) throw e;
    throw _err("x509/bad-input", "signedCertificateTimestampList could not be encoded: " + (e && e.message), e);
  }
}

function _timeDer(date, which) { return _b.timeDer(date, "certificate " + which); }
function _assertIssuerIsCa(issuerCert) {
  var exts = issuerCert.extensions || [];
  function ext(name) { return exts.filter(function (x) { return x.oid === O(name); })[0] || null; }
  var bcExt = ext("basicConstraints");
  if (!bcExt) throw _err("x509/bad-input", "the issuer certificate is not a CA -- it has no basicConstraints extension (RFC 5280 sec. 4.2.1.9)");
  if (bcExt.critical !== true) throw _err("x509/bad-input", "the issuer certificate basicConstraints is not marked critical (RFC 5280 sec. 4.2.1.9 requires it on a CA)");
  var bc;
  try { bc = EXT_DECODERS[O("basicConstraints")](bcExt.value); }
  catch (e) { if (e instanceof CertificateError) throw e; throw _err("x509/bad-input", "the issuer certificate basicConstraints is malformed", e); }
  if (bc.cA !== true) throw _err("x509/bad-input", "the issuer certificate is not a CA (basicConstraints cA is not TRUE)");
  var kuExt = ext("keyUsage");
  if (kuExt) {
    var ku;
    try { ku = EXT_DECODERS[O("keyUsage")](kuExt.value); }
    catch (e) { if (e instanceof CertificateError) throw e; throw _err("x509/bad-input", "the issuer certificate keyUsage is malformed", e); }
    if (ku.keyCertSign !== true) throw _err("x509/bad-input", "the issuer certificate keyUsage does not assert keyCertSign -- it cannot sign certificates (RFC 5280 sec. 4.2.1.3)");
  }
  return bc.pathLenConstraint;
}
function _issuedCaInfo(extSpec) {
  if (extSpec == null) return { cA: false, pathLen: null };
  if (!_isArray(extSpec)) {
    var bc = extSpec.basicConstraints;
    return { cA: !!(bc && bc.cA === true), pathLen: bc && bc.pathLen != null ? Number(bc.pathLen) : null };
  }
  for (var i = 0; i < extSpec.length; i++) {
    var n = asn1.decode(_reqDer(extSpec[i], "extension"));
    if (asn1.read.oid(n.children[0]) !== O("basicConstraints")) continue;
    var dec = EXT_DECODERS[O("basicConstraints")](asn1.read.octetString(n.children[n.children.length - 1]));
    return { cA: dec.cA === true, pathLen: dec.pathLenConstraint != null ? Number(dec.pathLenConstraint) : null };
  }
  return { cA: false, pathLen: null };
}
function _hasCriticalSan(extSpec) {
  if (extSpec == null) return false;
  if (!_isArray(extSpec)) return !!extSpec.subjectAltName;
  var sanOid = O("subjectAltName");
  for (var i = 0; i < extSpec.length; i++) {
    var n = asn1.decode(_reqDer(extSpec[i], "extension"));
    if (n.children.length === 3 && asn1.read.oid(n.children[0]) === sanOid && asn1.read.boolean(n.children[1]) === true) return true;
  }
  return false;
}


/**
 * @primitive pki.x509.sign
 * @signature pki.x509.sign(spec, issuer, opts?) -> Promise<Buffer|string>
 * @since 0.3.0
 * @status stable
 * @spec RFC 5280 sec. 4, RFC 9909, RFC 9814
 * @defends forged-certificate-issuance (CWE-347)
 * @related pki.schema.x509.parse, pki.path.validate, pki.cms.sign
 *
 * Build, sign, and DER-encode an X.509 certificate. `spec` describes the certificate to issue:
 * `subject` (a string CN, an array of RDNs, or raw Name DER), `subjectPublicKey` (the SPKI DER of the
 * key being certified), `notBefore` / `notAfter` (`Date`s), an optional `serialNumber`, and an optional
 * `extensions` object. `issuer` is the signing side: `{ key }` alone issues a self-signed certificate
 * (issuer = subject, signed with the subject's own key); `{ name, publicKey, key }` or `{ cert, key }`
 * issues a CA-signed one. The signing key `key` is a WebCrypto `CryptoKey` (a `pki.key.generate`
 * private key passed directly, without exporting) or a PKCS#8 private key as DER (`Buffer`) or PEM
 * (`string`); a public or secret CryptoKey, or a `node:crypto` KeyObject, is refused. A `subjectAltName`
 * (or any `GeneralName`) entry may be a form object (`{ dNSName: "..." }`) or a bare string classified
 * fail-closed into its form (`"host.example"`, `"a@b.example"`, `"10.0.0.1"`, `"https://host.example/"`).
 * The signature algorithm is resolved from the signing key: RSA (PKCS#1 v1.5
 * or PSS via `opts.pss`), ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm, so every algorithm the
 * toolkit signs with is available here without a per-algorithm branch.
 *
 * The version is derived from the field set (v3 when extensions are present, else v1). Two
 * extensions are emitted without being named, because RFC 5280 places them on the issuing CA: a
 * `subjectKeyIdentifier` derived from the subject key by method (1), and, unless the certificate is
 * self-signed (the subject's own key signs it and the names agree), an `authorityKeyIdentifier`
 * whose keyIdentifier is the issuer certificate's SKI or, without one, the issuer key's method (1)
 * value. `subjectKeyIdentifier: false` omits the first on an end entity (sec. 4.2.1.2 states a
 * SHOULD there) and is refused on a CA (a MUST); `authorityKeyIdentifier: false` is honored on a
 * self-signed certificate (sec. 4.2.1.1 allows the omission there) and refused on any other. The
 * pre-encoded array form of `extensions` emits exactly what it is given. Serial bounds
 * (positive, <= 20 octets), the validity UTCTime/GeneralizedTime cutover, the DER DEFAULT omissions
 * (v1 tag, `critical=FALSE`, `cA=FALSE`), and the CA cross-field rules (keyCertSign and
 * pathLenConstraint require cA=TRUE) are all enforced; a violation throws a typed `CertificateError`.
 * Where the spec carries raw DER (a `Name` Buffer, a pre-encoded `Extension`, an issuer `publicKey`
 * SPKI), a structural fault throws `CertificateError`, while a malformed leaf inside those bytes
 * throws `Asn1Error`, the same two-error contract the parsers present.
 *
 * `extensions.nameConstraints` restricts what the CA being issued may itself issue, as
 * `{ permitted: [...], excluded: [...] }` with at least one side present. Each entry names one
 * GeneralName form: `{ dNSName: ".example.com" }`, `{ rfc822Name: "example.com" }`,
 * `{ uniformResourceIdentifier: ".example.com" }`, `{ directoryName: [{ commonName: "Sub" }] }`, or
 * `{ iPAddress: buf }` where `buf` is an address followed by its mask, 8 octets for IPv4 and 32 for
 * IPv6. A base names a namespace rather than a subject, so it may carry a leading dot and is held to
 * the rule for a constraint base. A bare string is refused here, since the name form decides which
 * namespace is constrained. The extension is emitted critical, which RFC 5280 sec. 4.2.1.10 requires,
 * and it appears only on a certificate whose `basicConstraints` sets `cA: true`.
 *
 * `extensions.authorityInfoAccess` names where to reach the issuer, as a list of
 * `{ accessMethod, accessLocation }`. The method is a registered name (`"ocsp"`, `"caIssuers"`) or a
 * dotted OID; the location is a `GeneralName` in either accepted form.
 * `extensions.cRLDistributionPoints` names where to fetch the CRL, and `extensions.freshestCRL` the
 * delta CRL, which RFC 5280 sec. 4.2.1.15 gives the same syntax. Each takes a list whose entries are
 * either a `GeneralName` standing for a single `fullName`, or
 * `{ fullName, reasons, cRLIssuer }` for the full form; `reasons` names RFC 5280 sec. 4.2.1.13
 * ReasonFlags bits, whose numbering differs from the CRLReason values `pki.crl.sign` takes. A
 * distribution point naming only `reasons` is refused, which that clause requires. All three are
 * emitted non-critical.
 *
 * The policy machinery certification-path validation acts on is available the same way.
 * `extensions.policyConstraints` takes `{ requireExplicitPolicy, inhibitPolicyMapping }` skip counts,
 * at least one of which RFC 5280 sec. 4.2.1.11 requires; `extensions.inhibitAnyPolicy` takes a bare
 * skip count (sec. 4.2.1.14); both are emitted critical, which those clauses require.
 * `extensions.policyMappings` takes a list of `{ issuerDomainPolicy, subjectDomainPolicy }` naming
 * registered policies or dotted OIDs, and refuses a mapping to or from `anyPolicy`, which sec.
 * 4.2.1.5 forbids, the same rule `pki.path.validate` applies at sec. 6.1.4(a). That clause states a
 * SHOULD for marking it critical. The validator processes the extension on an intermediate
 * certificate, where sec. 6.1.4 applies the mappings to the policy tree, and treats a critical one on
 * the TARGET certificate as unprocessed, rejecting it; `pki.lint.certificate` grades that case
 * `unknown-critical-extension`. It is emitted non-critical unless `policyMappingsCritical` is set.
 * `extensions.issuerAltName` takes the `GeneralName` forms `subjectAltName` takes and is emitted
 * non-critical (sec. 4.2.1.7).
 *
 * `extensions.certificatePolicies` takes a policy as a registered name, a dotted OID, or an entry
 * object `{ oid, cps, userNotice }` carrying the RFC 5280 sec. 4.2.1.4 qualifiers: `cps` is the
 * certification-practice-statement URI, and `userNotice` takes `{ noticeRef, explicitText }`, either
 * or both, where `noticeRef` is `{ organization, noticeNumbers }`. Every DisplayText is emitted as a
 * UTF8String, the encoding the section names for a conforming CA, and is held to its SIZE (1..200)
 * bound counted in characters.
 *
 * `extensions.authorityKeyIdentifier` takes `true` to derive the key id from the issuer, a
 * `BufferSource` key id, or an object `{ keyIdentifier, authorityCertIssuer, authorityCertSerialNumber }`
 * naming the issuing certificate directly (RFC 5280 sec. 4.2.1.1). The issuer name and the serial are
 * both present or both absent, which is the rule the reader applies. Each of the two also takes
 * `true`, which reads it from the issuing certificate, so the pair identifies the certificate that
 * actually signed this one; `true` requires an issuer given as a certificate. The object form
 * carries the `keyIdentifier` whether or not it is named (`keyIdentifier: false` omits it on a
 * self-signed certificate only), and a stated key id is held to the issuer certificate's
 * subjectKeyIdentifier when the issuer is given as a certificate carrying one (sec. 4.2.1.2).
 *
 * `extensions.qcStatements` builds the RFC 3739 sec. 3.2.6 qualified-certificate statements, as a
 * list of `{ statementId, info? }`. A statement the toolkit knows encodes its own value syntax:
 * `qcCompliance` and `qcSSCD` carry no `info` at all; `qcType` and `qcIdentMethod` take
 * `{ types }` / `{ methods }` of object identifiers, including the registered ETSI names `qctEsign`,
 * `qctEseal` and `qctWeb`; `qcCClegislation` and `qcQSCDlegislation` take `{ countries }` of
 * two-letter codes; `qcRetentionPeriod` takes `{ years }`; `qcLimitValue` takes
 * `{ currency, amount, exponent }` with an alphabetic or numeric ISO 4217 currency; `qcPDS` takes
 * `{ locations: [{ url, language }] }`; and `qcsPkixQCSyntaxV1` / `V2` take
 * `{ semanticsIdentifier, nameRegistrationAuthorities }`, at least one of the two. Each typed `info`
 * accepts only the fields its own statement defines, so a misspelled key is refused rather than
 * dropped. Any other statement id takes `info` as pre-encoded DER, or omits `info` for a
 * presence-only statement, since `statementInfo` is optional on every statement and nothing here can
 * know an unknown syntax. `pki.path.validate` does not process this extension, so it is emitted
 * non-critical unless `qcStatementsCritical` is set.
 *
 * `extensions.subjectInfoAccess` takes the same `{ accessMethod, accessLocation }` list
 * `authorityInfoAccess` takes, since RFC 5280 sec. 4.2.2.2 gives it sec. 4.2.2.1's syntax; the two
 * access methods that section defines are the registered names `id-ad-caRepository` and
 * `id-ad-timeStamping`, the latter being a different OID from the extended-key-usage `timeStamping`.
 * `extensions.subjectDirectoryAttributes` takes a list of `{ type, values }` with each value as
 * pre-encoded DER, the form its reader surfaces (sec. 4.2.1.8). Both are emitted non-critical, which
 * those sections require. `extensions.ocspNoCheck: true` marks an OCSP responder certificate so a
 * client does not ask about its revocation (RFC 6960 sec. 4.2.2.2.1): the value is NULL, as that
 * section requires, and it is emitted non-critical, which the section says it should be.
 *
 * The Active Directory Certificate Services enrollment extensions are written from the same spec.
 * `extensions.msCertificateTemplate` takes `{ templateID, templateMajorVersion, templateMinorVersion }`,
 * the versions optional and each a DWORD, a minor version requiring a major one;
 * `extensions.msEnrollCertType` takes the legacy v1 template name as a BMPString;
 * `extensions.msCaVersion` takes `{ caKeyIndex, certIndex }` or the composed DWORD;
 * `extensions.msPreviousCertHash` takes the 20-octet SHA-1 thumbprint of the previous CA certificate;
 * and `extensions.msApplicationPolicies` takes the `certificatePolicies` spec, which is what its
 * reader applies. All five are emitted non-critical, since neither `pki.path.validate` nor
 * `pki.lint.certificate` processes them and a critical instance is refused as unrecognized.
 *
 * `extensions.precertificatePoison: true` issues an RFC 6962 sec. 3.1 precertificate: the poison is
 * emitted critical with an ASN.1 NULL value, which is what stops a standard X.509v3 client from
 * validating the precertificate as an issued certificate. `extensions.signedCertificateTimestampList`
 * takes the SCTs a log returned, in the shape `pki.ct.signSct` and `pki.ct.parseSctList` use, and
 * embeds them in the certificate issued after the log answers (sec. 3.3, at least one). It is always
 * emitted non-critical, since a client that does not recognize the OID refuses a certificate that
 * marks it critical. The two name opposite ends of one exchange, so a spec naming both is refused. A
 * client recovers the signed entry from the issued certificate with `pki.ct.x509CertEntry`.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `CERTIFICATE` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS instead of PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerSpki = await pki.key.export(pair.publicKey);
 *   var root = await pki.x509.sign(
 *     { subject: "Example Root CA", subjectPublicKey: signerSpki,
 *       notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *       extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } },
 *     { key: pair.privateKey });   // a WebCrypto CryptoKey signs directly (or pass a PKCS#8 DER Buffer / PEM string)
 *   pki.schema.x509.parse(root).subject.dn;   // "CN=Example Root CA"
 */
function sign(spec, issuer, opts) {
  return guard.bytes.fixedCall(CertificateError, "x509/bad-input", [
    [spec, "the certificate spec"], [issuer, "the issuer"], [opts, "pki.x509.sign options"],
  ], _sign);
}

function _sign(spec, issuer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("x509/bad-input", "the certificate spec must be an object");
  issuer = issuer || {};
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, _err, "x509/bad-input", function (k) {
    return "unknown certificate spec field " + JSON.stringify(k) +
      (k === "issuer" ? "; the issuer is the SECOND argument to pki.x509.sign, not a spec field" : "") +
      (k === "extension" ? "; the extensions spec field is `extensions`" : "");
  });
  var byCert = issuer.cert != null;
  guard.identifier.assertKnownKeys(issuer, byCert ? KNOWN_ISSUER_CERT_KEYS : KNOWN_ISSUER_EXPLICIT_KEYS,
    _err, "x509/bad-input", function (k) {
      return "unknown issuer field " + JSON.stringify(k) + " for the " + (byCert
        ? "certificate form; issuer.cert supplies the name and the public key, so they are not read here"
        : "explicit form; the issuer takes { key, name, publicKey }, or { key, cert } to take both from a certificate");
    });
  guard.identifier.assertKnownKeys(opts, KNOWN_SIGN_OPTS, _err, "x509/bad-input", "pki.x509.sign has an unknown option ");
  if (issuer.key == null) throw _err("x509/bad-input", "a signing key (issuer.key, a WebCrypto CryptoKey or a PKCS#8 private key DER/PEM) is required");

  var spki = _reqDer(spec.subjectPublicKey, "spec.subjectPublicKey (the SPKI DER of the certified key)");
  _assertValidSpki(spki, "spec.subjectPublicKey");
  var subjectDer = _encodeName(spec.subject == null ? [] : spec.subject);
  var subjectEmpty = _isEmptyName(subjectDer);

  var issuerDer, issuerSpki, issuerCert = null, issuerPathLen = null;
  var selfSigned = issuer.name == null && issuer.cert == null && issuer.publicKey == null;
  if (selfSigned) {
    issuerDer = subjectDer;
    issuerSpki = spki;
  } else if (issuer.cert != null) {
    issuerCert = guard.parsed.acceptDerived(issuer.cert, "certificate", x509.parse, _err, "x509/bad-input", "issuer.cert");
    issuerPathLen = _assertIssuerIsCa(issuerCert);
    issuerDer = pkiBuild.tbsNameField(issuerCert, "subject");
    issuerSpki = issuerCert.subjectPublicKeyInfo.bytes;
  } else {
    issuerDer = _encodeName(issuer.name == null ? [] : issuer.name);
    issuerSpki = _reqDer(issuer.publicKey, "issuer.publicKey (the issuer SPKI DER)");
    _assertValidSpki(issuerSpki, "issuer.publicKey");
  }
  if (_isEmptyName(issuerDer)) throw _err("x509/bad-issuer", "issuer must be a non-empty distinguished name");

  var scheme = signScheme.resolveSignScheme(_certLikeFromSpki(issuerSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  var serialTlv = _serialInteger(spec.serialNumber);
  guard.time.assertEncodable(spec.notBefore, _err, "x509/bad-input", "notBefore");
  guard.time.assertEncodable(spec.notAfter, _err, "x509/bad-input", "notAfter");
  // allow:nan-date-comparison-unguarded -- both operands are guard.time.assertEncodable'd on the two lines above (an Invalid Date throws before this comparison).
  if (guard.time.instantOf(spec.notBefore) > guard.time.instantOf(spec.notAfter)) throw _err("x509/bad-input", "notBefore must not be after notAfter (RFC 5280 sec. 4.1.2.5)");
  var validityDer = b.sequence([_timeDer(spec.notBefore, "notBefore"), _timeDer(spec.notAfter, "notAfter")]);

  /** @internal Sec. 4.2.1.1 defines the self-signed exception by the signature: it is generated
   *  with the private key of the certificate's own subject public key. The bare `{ key }` issuer
   *  form is that by construction; an explicit issuer is measured, key and name both, and the key
   *  is compared as a key rather than as an encoding, since one EC key has two point encodings. */
  var selfIssued = guard.name.dnEqual(
    schema.walk(NAME_SCHEMA, asn1.decode(subjectDer), NS).result.rdns,
    schema.walk(NAME_SCHEMA, asn1.decode(issuerDer), NS).result.rdns,
    _err, "x509/bad-input", "issuer/subject DN");
  var selfSignedCert = selfIssued && _b.samePublicKey(issuerSpki, spki);
  var extSpec = spec.extensions;
  var exts = _buildExtensions(extSpec, { spki: spki, issuerSpki: issuerSpki, issuerCert: issuerCert, subjectEmpty: subjectEmpty, selfSigned: selfSignedCert });
  if (subjectEmpty && !_hasCriticalSan(extSpec)) {
    throw _err("x509/bad-input", "an empty subject requires a critical subjectAltName (RFC 5280 sec. 4.1.2.6)");
  }
  if (issuerPathLen != null) {
    var issued = _issuedCaInfo(extSpec);
    if (issued.cA && !selfIssued) {
      if (issuerPathLen < 1) throw _err("x509/bad-input", "the issuer certificate pathLenConstraint (0) forbids issuing a non-self-issued CA certificate below it (RFC 5280 sec. 4.2.1.9)");
      if (issued.pathLen != null && issued.pathLen > issuerPathLen - 1) throw _err("x509/bad-input", "the issued CA certificate pathLenConstraint exceeds the issuer's remaining path length (RFC 5280 sec. 4.2.1.9)");
    }
  }
  var version = exts.length ? 3 : 1;

  var tbsChildren = [];
  if (version !== 1) tbsChildren.push(b.explicit(0, b.integer(BigInt(version - 1))));
  tbsChildren.push(serialTlv);
  tbsChildren.push(scheme.sigAlgId);
  tbsChildren.push(issuerDer);
  tbsChildren.push(validityDer);
  tbsChildren.push(subjectDer);
  tbsChildren.push(b.raw(spki));
  if (exts.length) tbsChildren.push(b.explicit(3, b.sequence(exts)));
  var tbsDer = b.sequence(tbsChildren);

  return signScheme.signOverTbs(scheme, issuer.key, tbsDer, _signE).then(function (sig) {
    return Promise.resolve(_assertCertVerifies(tbsDer, sig, issuerSpki, scheme)).then(function () {
      var certDer = b.sequence([tbsDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? x509.pemEncode(certDer, "CERTIFICATE") : certDer;
    });
  }, function (e) {
    if (e instanceof CertificateError) throw e;
    throw _err("x509/bad-input", "signing the certificate failed -- the signing key does not match the resolved algorithm or is invalid", e);
  });
}

/**
 * @primitive pki.x509.randomSerial
 * @signature pki.x509.randomSerial() -> BigInt
 * @since 0.7.12
 * @status stable
 * @spec RFC 5280 sec. 4.1.2.2
 * @related pki.x509.sign
 *
 * Draw a certificate serial number: 20 octets from the platform CSPRNG read as a positive integer.
 * This is the same draw `pki.x509.sign` makes when `spec.serialNumber` is omitted, so an issuer that
 * has to record a serial before the certificate exists gets it without re-implementing the draw and
 * without signing first. The value satisfies the section 4.1.2.2 profile a signer enforces: positive,
 * and at most 20 octets.
 *
 * The top bit is cleared so the DER INTEGER carries no sign octet, and a zero top byte is redrawn, so
 * every value the top byte can take is equally likely.
 *
 * @example
 *   var serial = pki.x509.randomSerial();            // record this before the certificate exists
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign(
 *     { subject: "leaf.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *       notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
 *       serialNumber: serial },
 *     { key: pair.privateKey });
 *   pki.schema.x509.parse(der).serialNumber === serial;   // true: the issued serial is the drawn one
 */
function randomSerial() { return pkiBuild.randomSerial(); }

/** @internal One row per extension the object form of `spec.extensions` encodes, for the standalone
 *  encoder: the registry OID name, the value encoder, and how the criticality is decided. `fixed`
 *  is the value the RFC or the toolkit's posture emits, refused if a knob disagrees; `knob` marks
 *  the extensions whose criticality is the issuer's choice (or, for subjectAltName, follows a
 *  subject this encoder does not hold); `flag` marks a NULL-valued marker given as `true`. The two
 *  key identifiers take only their explicit forms here: deriving one needs the subject key or the
 *  issuer, which live in the assembled spec. */
function _flagValue(name, v) {
  if (v !== true) throw _err("x509/bad-input", name + " is a flag, so it is true or omitted");
  return asn1.build.nullValue();
}
function _standaloneSki(v) {
  if (v === true) throw _err("x509/bad-input", "subjectKeyIdentifier: true derives the key id from the subject key, which this encoder does not hold; pass the key id bytes, or name it in spec.extensions");
  return _extSki(_skiKeyId(v, null));
}
function _standaloneAki(v) {
  if (v === true) throw _err("x509/bad-input", "authorityKeyIdentifier: true derives the key id from the issuer, which this encoder does not hold; pass { keyIdentifier } bytes, or name it in spec.extensions");
  if (guard.bytes.isByteSource(v)) return _extAki(_akiKeyId(v, {}), null, null);
  if (typeof v !== "object" || _isArray(v) || v === null) throw _err("x509/bad-input", "authorityKeyIdentifier must be a Buffer key id or an object { keyIdentifier, authorityCertIssuer, authorityCertSerialNumber }");
  if (!guard.bytes.isByteSource(v.keyIdentifier)) {
    throw _err("x509/bad-input", "authorityKeyIdentifier keyIdentifier must be the key id bytes here (RFC 5280 sec. 4.2.1.1 requires the field, and deriving it needs the issuer); name it in spec.extensions to derive it");
  }
  var f = _akiFields(v, { selfSigned: false });
  return _extAki(f[0], f[1], f[2]);
}
var EXTENSION_ROWS = [
  ["subjectKeyIdentifier", "subjectKeyIdentifier", { fixed: false, cite: "RFC 5280 sec. 4.2.1.2" }, _standaloneSki],
  ["authorityKeyIdentifier", "authorityKeyIdentifier", { fixed: false, cite: "RFC 5280 sec. 4.2.1.1" }, _standaloneAki],
  ["keyUsage", "keyUsage", { knob: true, dflt: true }, function (v) { return _extKeyUsage(v); }],
  ["extendedKeyUsage", "extKeyUsage", { knob: true, dflt: false }, function (v) { return _extExtKeyUsage(v); }],
  ["basicConstraints", "basicConstraints", { inValue: true }, function (v) {
    _validateBcSpec(v);
    if (v.cA === true && v.critical === false) throw _err("x509/bad-input", "a CA certificate's basicConstraints MUST be critical (RFC 5280 sec. 4.2.1.9)");
    if (v.pathLen != null && v.cA !== true) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires cA=TRUE (RFC 5280 sec. 4.2.1.9)");
    return _extBasicConstraints(v);
  }],
  ["subjectAltName", "subjectAltName", { knob: true, dflt: false }, function (v) { return _extSan(v); }],
  ["issuerAltName", "issuerAltName", { fixed: false, cite: "RFC 5280 sec. 4.2.1.7" }, function (v) { return _encodeGeneralNames(_reqDenseArray(v, "issuerAltName")); }],
  ["certificatePolicies", "certificatePolicies", { knob: true, dflt: false }, function (v) { return _extCertPolicies(v); }],
  ["nameConstraints", "nameConstraints", { fixed: true, cite: "RFC 5280 sec. 4.2.1.10" }, function (v) { return _extNameConstraints(v); }],
  ["policyConstraints", "policyConstraints", { fixed: true, cite: "RFC 5280 sec. 4.2.1.11" }, function (v) { return _extPolicyConstraints(v); }],
  ["inhibitAnyPolicy", "inhibitAnyPolicy", { fixed: true, cite: "RFC 5280 sec. 4.2.1.14" }, function (v) { return _extInhibitAnyPolicy(v); }],
  ["policyMappings", "policyMappings", { knob: true, dflt: false }, function (v) { return _extPolicyMappings(v); }],
  ["authorityInfoAccess", "authorityInfoAccess", { fixed: false, cite: "RFC 5280 sec. 4.2.2.1" }, function (v) { return _extAia(v); }],
  ["subjectInfoAccess", "subjectInfoAccess", { fixed: false, cite: "RFC 5280 sec. 4.2.2.2" }, function (v) { return _b.extSubjectInfoAccess(v); }],
  ["cRLDistributionPoints", "cRLDistributionPoints", { fixed: false, cite: "RFC 5280 sec. 4.2.1.13" }, function (v) { return _extCrlDp(v, "cRLDistributionPoints"); }],
  ["freshestCRL", "freshestCRL", { fixed: false, cite: "RFC 5280 sec. 4.2.1.15" }, function (v) { return _extCrlDp(v, "freshestCRL"); }],
  ["qcStatements", "qcStatements", { knob: true, dflt: false }, function (v) { return _extQcStatements(v); }],
  ["subjectDirectoryAttributes", "subjectDirectoryAttributes", { fixed: false, cite: "RFC 5280 sec. 4.2.1.8" }, function (v) { return _b.extSubjectDirectoryAttributes(v); }],
  ["msCertificateTemplate", "msCertificateTemplate", { fixed: false, cite: "the toolkit issues the form its readers accept" }, function (v) { return _b.extMsCertificateTemplate(v); }],
  ["msEnrollCertType", "msEnrollCertType", { fixed: false, cite: "the toolkit issues the form its readers accept" }, function (v) { return _b.extMsEnrollCertType(v); }],
  ["msCaVersion", "msCaVersion", { fixed: false, cite: "the toolkit issues the form its readers accept" }, function (v) { return _b.extMsCaVersion(v); }],
  ["msPreviousCertHash", "msPreviousCertHash", { fixed: false, cite: "the toolkit issues the form its readers accept" }, function (v) { return _b.extMsPreviousCertHash(v); }],
  ["msApplicationPolicies", "msApplicationPolicies", { fixed: false, cite: "the toolkit issues the form its readers accept" }, function (v) { return _extCertPolicies(v); }],
  ["ocspNoCheck", "ocspNoCheck", { fixed: false, cite: "RFC 6960 sec. 4.2.2.2.1" }, function (v) { return _flagValue("ocspNoCheck", v); }],
  ["precertificatePoison", "precertificatePoison", { fixed: true, cite: "RFC 6962 sec. 3.1" }, function (v) { return _flagValue("precertificatePoison", v); }],
  ["signedCertificateTimestampList", "signedCertificateTimestampList", { fixed: false, cite: "RFC 6962 sec. 3.3" }, function (v) { return _encodeSctList(v); }],
];
var EXTENSION_BY_NAME = intrinsic.create(null), EXTENSION_BY_OID = intrinsic.create(null);
intrinsic.forEach(EXTENSION_ROWS, function (r) {
  var row = { name: r[0], oid: O(r[1]), rule: r[2], encode: r[3] };
  EXTENSION_BY_NAME[r[0]] = row;
  EXTENSION_BY_OID[row.oid] = row;
});
var KNOWN_EXTENSION_OPTS = intrinsic.assign(intrinsic.create(null), { critical: 1 });

function _extensionRow(name) {
  if (typeof name !== "string") throw _err("x509/bad-input", "the extension name must be a registered extension name or a dotted OID string, got " + guard.text.showValue(name));
  if (intrinsic.hasOwn(EXTENSION_BY_NAME, name)) return EXTENSION_BY_NAME[name];
  if (oid.isDottedDecimal(name)) return intrinsic.hasOwn(EXTENSION_BY_OID, name) ? EXTENSION_BY_OID[name] : null;
  throw _err("x509/bad-input", "unknown extension " + guard.text.showValue(name) + "; the names spec.extensions takes are accepted, and any other extension is named by its dotted OID with its extnValue pre-encoded");
}
function _extensionCritical(row, opts) {
  var rule = row.rule, stated = opts.critical;
  if (rule.inValue) {
    if (stated !== undefined) throw _err("x509/bad-input", row.name + " carries its criticality in the value ({ cA, pathLen, critical }), so opts.critical does not apply");
    return null;
  }
  if (rule.knob) return stated === undefined ? rule.dflt : stated;
  if (stated !== undefined && stated !== rule.fixed) {
    throw _err("x509/bad-input", row.name + " is emitted " + (rule.fixed ? "critical" : "non-critical") + " (" + rule.cite + "), so opts.critical cannot say otherwise");
  }
  return rule.fixed;
}

/**
 * @primitive pki.x509.extension
 * @signature pki.x509.extension(name, value, opts?) -> Buffer
 * @since 0.7.33
 * @status stable
 * @spec RFC 5280 sec. 4.2
 * @related pki.x509.sign, pki.csr.sign, pki.crl.sign
 *
 * Encode one X.509 `Extension` as DER, ready for the pre-encoded array form of `extensions` on
 * `pki.x509.sign`, `pki.csr.sign`, or `pki.crl.sign`. `name` is one of the extension names
 * `spec.extensions` takes, or a dotted OID string. For a name (or the dotted OID of one), `value`
 * is the same plain form `spec.extensions` takes for it: the key-usage and purpose name lists, the
 * `{ cA, pathLen, critical }` object, the GeneralName lists, the policy, constraint, access, and
 * distribution-point objects, the statement and template objects, `true` for the NULL-valued
 * markers, and for the two key identifiers their explicit forms (the key id bytes for
 * `subjectKeyIdentifier`; bytes or `{ keyIdentifier, authorityCertIssuer, authorityCertSerialNumber }`
 * with the key id present for `authorityKeyIdentifier`). The forms that derive a value from the
 * subject key or the issuer (`true`) are refused here, since only the assembled spec holds those.
 * For any other dotted OID, `value` is a `BufferSource` holding the already-encoded `extnValue`.
 *
 * The criticality follows what the signer emits for the object form. Where RFC 5280 fixes it
 * (the key identifiers, the constraint and policy-constraint extensions, the access and
 * distribution extensions), or the toolkit issues one form only, `opts.critical` may only restate
 * that value. `keyUsage` (default critical), `extendedKeyUsage`, `certificatePolicies`,
 * `policyMappings`, `qcStatements` (default non-critical), and `subjectAltName` (critical exactly
 * when the subject is empty, which the caller knows) take `opts.critical`; `basicConstraints`
 * carries `critical` inside its value. An unregistered OID takes `opts.critical` as stated.
 *
 * @opts
 *   - `critical` (boolean) -- the criticality, where the extension admits a choice.
 *
 * @example
 *   var ku = pki.x509.extension("keyUsage", ["digitalSignature"]);
 *   var san = pki.x509.extension("subjectAltName", ["leaf.example"]);
 *   var custom = pki.x509.extension("1.3.6.1.4.1.99999.7", pki.asn1.build.utf8("v1"), { critical: false });
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign(
 *     { subject: "leaf.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *       notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
 *       extensions: [ku, san, custom] },
 *     { key: pair.privateKey });
 *   pki.schema.x509.parse(der).extensions.length;   // 3
 */
function extension(name, value, opts) {
  var fixed = guard.bytes.fixArguments(CertificateError, "x509/bad-input", [
    [value, "the extension value"], [opts, "pki.x509.extension options"],
  ]);
  try { return _extension(name, fixed.values[0], fixed.values[1]); }
  finally { fixed.release(); }
}
function _extension(name, value, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "x509/bad-input", "pki.x509.extension options");
  guard.identifier.assertKnownKeys(opts, KNOWN_EXTENSION_OPTS, _err, "x509/bad-input", "pki.x509.extension has an unknown option ");
  if (opts.critical !== undefined && typeof opts.critical !== "boolean") throw _err("x509/bad-input", "opts.critical must be a boolean");
  if (value === undefined || value === null) throw _err("x509/bad-input", "the extension value is required");
  var row = _extensionRow(name);
  if (row === null) {
    if (!guard.bytes.isByteSource(value)) throw _err("x509/bad-input", "an extension named by a dotted OID takes its extnValue as pre-encoded bytes");
    var raw = guard.bytes.snapshotSource(value, CertificateError, "x509/bad-input", "the pre-encoded extnValue");
    _b.assertExtnValueIsDer(raw, "the " + name + " extension");
    try { return _ext(name, opts.critical === true, raw); }
    catch (e) {
      if (e instanceof CertificateError) throw e;
      throw _err("x509/bad-input", "the extension name " + guard.text.showValue(name) + " is not a valid OBJECT IDENTIFIER", e);
    }
  }
  if (guard.bytes.isByteSource(value) && !(row.name === "subjectKeyIdentifier" || row.name === "authorityKeyIdentifier" || row.name === "msPreviousCertHash")) {
    throw _err("x509/bad-input", row.name + " takes the plain form spec.extensions takes, not pre-encoded bytes; name the extension by a dotted OID that is not registered to pass raw bytes");
  }
  var critical = _extensionCritical(row, opts);
  var valueDer = row.encode(value);
  if (critical === null) critical = value.critical !== false;
  return _ext(row.oid, critical, valueDer);
}

module.exports = { sign: sign, randomSerial: randomSerial, extension: extension };
