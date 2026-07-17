// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.csr
 * @nav        Signing
 * @title      Certification requests
 * @intro The PKCS#10 certification-request producing side. `pki.csr.sign` builds a
 *   `CertificationRequestInfo`, signs it with the SUBJECT's own private key (proof of possession -- a
 *   CSR has no issuer), and emits a `CertificationRequest` (RFC 2986) that `pki.schema.csr.parse`,
 *   OpenSSL, and a CA enrollment pipeline all accept. Requested v3 extensions ride in a PKCS#9
 *   `extensionRequest` attribute (RFC 2985) a CA copies into the issued certificate. Parsing lives at
 *   `pki.schema.csr.parse`.
 * @spec RFC 2986
 * @card Build and sign a PKCS#10 certification request (proof of possession by the subject key).
 */
//
// The signature algorithm resolves from the SUBJECT public key through the shared sign-scheme registry
// (RSA / ECDSA / EdDSA / ML-DSA / SLH-DSA / composite), so there is no per-algorithm branch here. The
// distinguished-name / extension / SPKI encoders + the post-sign self-check are the shared lib/pki-build
// primitives (the same ones pki.x509.sign composes), bound to the csr namespace.

var asn1 = require("./asn1-der");
var oid = require("./oid");
var csr = require("./schema-csr");
var signScheme = require("./sign-scheme");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var frameworkError = require("./framework-error");

var CsrError = frameworkError.CsrError;
var b = asn1.build;
function _err(code, message, cause) { return new CsrError(code, message, cause); }
function _signE(kind, message, cause) { return new CsrError("csr/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var NS = pkix.makeNS("csr", CsrError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var _b = pkiBuild.makeBuilder({
  ErrorClass: CsrError, prefix: "csr", O: O, NS: NS,
  NAME_SCHEMA: pkix.name(NS), SPKI_SCHEMA: pkix.spki(NS), EXT_DECODERS: EXT_DECODERS,
});

// The requested-extension object keys (a CSR REQUESTS extensions; it does NOT enforce issuance policy,
// so there are no CA cross-field gates and no authorityKeyIdentifier auto-derivation).
var KNOWN_REQ_EXT_KEYS = {
  subjectAltName: 1, keyUsage: 1, keyUsageCritical: 1, extendedKeyUsage: 1, extendedKeyUsageCritical: 1,
  basicConstraints: 1, certificatePolicies: 1, certificatePoliciesCritical: 1, subjectKeyIdentifier: 1,
};
// challengePassword DirectoryString charset (PrintableString set); anything else uses UTF8String.
var PRINTABLE_RE = /^[A-Za-z0-9 '()+,\-./:=?]*$/;

// attributes ::= [0] IMPLICIT SET OF Attribute (RFC 2986). The IMPLICIT tag replaces the universal SET,
// so it is a context-constructed [0] whose DER-sorted members ARE the SET-OF; empty -> A0 00.
function _implicitSetOf0(members) {
  return b.contextConstructed(0, Buffer.concat(members.slice().sort(Buffer.compare)));
}

// The requested v3 Extensions (a bare SEQUENCE OF Extension, RFC 2985 sec. 5.4.2) from the object form,
// or an array of pre-encoded Extension DER. Reuses the shared extension-value encoders; no CA gates.
function _buildRequestedExtensions(extSpec, subjectSpki) {
  if (Array.isArray(extSpec)) {
    if (!extSpec.length) throw _err("csr/bad-input", "extensionRequest must carry at least one extension");
    var seen = {};
    return b.sequence(extSpec.map(function (e, i) {
      var der = _b.reqDer(e, "extension");
      _b.assertValidExtension(der, i);
      var n = asn1.decode(der);
      var extnId = asn1.read.oid(n.children[0]);
      if (seen[extnId]) throw _err("csr/bad-input", "duplicate extension " + extnId + " in extensionRequest (RFC 5280 sec. 4.2)");
      seen[extnId] = true;
      // Fully validate a RECOGNIZED extension via its real RFC 5280 sec. 4.2.1 value decoder (a malformed
      // value fails closed with the decoder's typed code); an unrecognized extension stays opaque.
      var dec = EXT_DECODERS[extnId];
      if (dec) {
        try { dec(asn1.read.octetString(n.children[n.children.length - 1])); }
        catch (err) { if (err instanceof CsrError) throw err; throw _err("csr/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension value is malformed", err); }
      }
      return b.raw(der);
    }));
  }
  if (!extSpec || typeof extSpec !== "object") throw _err("csr/bad-input", "extensionRequest must be an object or an array of pre-encoded Extension DER");
  Object.keys(extSpec).forEach(function (k) {
    if (!KNOWN_REQ_EXT_KEYS[k]) throw _err("csr/bad-input", "unknown extensionRequest extension " + JSON.stringify(k) + "; pass a pre-encoded Extension DER via the array form for a custom extension");
  });
  var out = [];
  if (extSpec.subjectKeyIdentifier != null) out.push(_b.ext(O("subjectKeyIdentifier"), false, _b.extSki(_b.skiKeyId(extSpec.subjectKeyIdentifier, subjectSpki))));
  if (extSpec.keyUsage != null) out.push(_b.ext(O("keyUsage"), extSpec.keyUsageCritical !== false, _b.extKeyUsage(extSpec.keyUsage)));
  if (extSpec.extendedKeyUsage != null) out.push(_b.ext(O("extKeyUsage"), !!extSpec.extendedKeyUsageCritical, _b.extExtKeyUsage(extSpec.extendedKeyUsage)));
  if (extSpec.basicConstraints != null) { _b.validateBcSpec(extSpec.basicConstraints); out.push(_b.ext(O("basicConstraints"), extSpec.basicConstraints.critical !== false, _b.extBasicConstraints(extSpec.basicConstraints))); }
  if (extSpec.subjectAltName != null) out.push(_b.ext(O("subjectAltName"), false, _b.extSan(extSpec.subjectAltName)));
  if (extSpec.certificatePolicies != null) out.push(_b.ext(O("certificatePolicies"), !!extSpec.certificatePoliciesCritical, _b.extCertPolicies(extSpec.certificatePolicies)));
  if (!out.length) throw _err("csr/bad-input", "extensionRequest must request at least one extension");
  return b.sequence(out);
}

// challengePassword ::= DirectoryString bounded 1..255 (RFC 2985 sec. 5.4.1). PrintableString when the
// value is in that charset, else UTF8String; never a Teletex/BMP/Universal string for a new value.
function _challengePassword(pw) {
  if (typeof pw !== "string" || pw.length < 1 || pw.length > 255) throw _err("csr/bad-input", "challengePassword must be a 1..255 character string (RFC 2985 sec. 5.4.1)");
  return PRINTABLE_RE.test(pw) ? b.printable(pw) : b.utf8(pw);
}

/**
 * @primitive pki.csr.sign
 * @signature pki.csr.sign(spec, key, opts?) -> Promise<Buffer|string>
 * @since 0.3.1
 * @status stable
 * @spec RFC 2986, RFC 2985
 * @defends forged-certification-request (CWE-347)
 * @related pki.schema.csr.parse, pki.x509.sign
 *
 * Build, sign, and DER-encode a PKCS#10 certification request. `spec` describes the request -- `subject`
 * (a common-name string, an array of RDNs, or raw Name DER; MAY be empty), `subjectPublicKey` (the SPKI
 * DER of the key being certified), and optional `extensionRequest` (requested v3 extensions -- an object
 * of subjectAltName / keyUsage / extendedKeyUsage / basicConstraints / certificatePolicies /
 * subjectKeyIdentifier, or an array of pre-encoded Extension DER) and `challengePassword`. `key` (or
 * `{ key }`) is the SUBJECT's own PKCS#8 private key / WebCrypto CryptoKey -- the request is self-signed
 * to prove possession of the private half of `subjectPublicKey`, and that proof is verified before the
 * request is returned. The signature algorithm is resolved from the subject key (RSA PKCS#1 v1.5 or PSS,
 * ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm). Returns DER, or a PEM `CERTIFICATE REQUEST` with
 * `opts.pem`. Malformed input throws a typed `CsrError`. Certificate-request parsing is `pki.schema.csr.parse`.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `CERTIFICATE REQUEST` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS rather than PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var req = await pki.csr.sign(
 *     { subject: "req.example.com", subjectPublicKey: signerSpki,
 *       extensionRequest: { subjectAltName: [{ dNSName: "req.example.com" }] } },
 *     { key: signerKeyPkcs8 });
 *   pki.schema.csr.parse(req).subject.dn;   // "CN=req.example.com"
 */
function sign(spec, key, opts) {
  return Promise.resolve().then(function () { return _sign(spec, key, opts); });
}

function _sign(spec, key, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("csr/bad-input", "the certification-request spec must be an object");
  // Reject a typo'd spec field at config-time rather than silently dropping it (a misspelled `subjcet`
  // would otherwise yield an empty-subject request).
  Object.keys(spec).forEach(function (k) {
    if (k !== "subject" && k !== "subjectPublicKey" && k !== "extensionRequest" && k !== "challengePassword" && k !== "attributes") throw _err("csr/bad-input", "unknown spec field " + JSON.stringify(k));
  });
  // The signing key is the second argument (a PKCS#8 key / CryptoKey / composite key pair), or { key }.
  var signingKey = (key && typeof key === "object" && !Buffer.isBuffer(key) && !(key instanceof Uint8Array) && key.type == null && "key" in key) ? key.key : key;
  if (signingKey == null) throw _err("csr/bad-input", "a signing key (the subject's private key) is required");

  var subjectSpki = _b.reqDer(spec.subjectPublicKey, "spec.subjectPublicKey (the SPKI DER of the requested key)");
  _b.assertValidSpki(subjectSpki, "spec.subjectPublicKey");
  var subjectDer = _b.encodeName(spec.subject == null ? [] : spec.subject);

  // attributes: extensionRequest + challengePassword + pre-encoded opaque Attribute DER (the escape
  // hatch). A recognized attribute may appear at most once (RFC 2985 SINGLE VALUE + producer hygiene).
  var attrs = [], seenAttr = {};
  function addAttr(attrType, valueTlv) {
    if (seenAttr[attrType]) throw _err("csr/bad-input", "duplicate " + (oid.name(attrType) || attrType) + " attribute");
    seenAttr[attrType] = true;
    attrs.push(b.sequence([b.oid(attrType), b.set([valueTlv])]));   // Attribute ::= SEQUENCE { type, SET OF value }
  }
  if (spec.extensionRequest != null) addAttr(O("extensionRequest"), _buildRequestedExtensions(spec.extensionRequest, subjectSpki));
  if (spec.challengePassword != null) addAttr(O("challengePassword"), _challengePassword(spec.challengePassword));
  if (spec.attributes != null) {
    if (!Array.isArray(spec.attributes)) throw _err("csr/bad-input", "spec.attributes must be an array of pre-encoded Attribute DER");
    spec.attributes.forEach(function (a, i) {
      var der = _b.reqDer(a, "attribute [" + i + "]");
      var n;
      try { n = asn1.decode(der); }
      catch (e) { throw _err("csr/bad-input", "pre-encoded attribute [" + i + "] is not valid DER", e); }
      if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length !== 2 || n.children[1].tagNumber !== asn1.TAGS.SET) throw _err("csr/bad-input", "pre-encoded attribute [" + i + "] must be an Attribute SEQUENCE { type OID, SET OF value }");
      var at;
      try { at = asn1.read.oid(n.children[0]); }
      catch (e) { throw _err("csr/bad-input", "pre-encoded attribute [" + i + "] type is not an OBJECT IDENTIFIER", e); }
      if (seenAttr[at]) throw _err("csr/bad-input", "duplicate " + (oid.name(at) || at) + " attribute");
      seenAttr[at] = true;
      attrs.push(b.raw(der));
    });
  }

  // Resolve the signature scheme from the SUBJECT public key (the request proves possession of its private half).
  var scheme = signScheme.resolveSignScheme(_b.certLikeFromSpki(subjectSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  // CertificationRequestInfo ::= SEQUENCE { version INTEGER(0), subject, subjectPKInfo, attributes [0] }.
  var criDer = b.sequence([b.integer(0n), subjectDer, b.raw(subjectSpki), _implicitSetOf0(attrs)]);

  return signScheme.signOverTbs(scheme, signingKey, criDer, _signE).then(function (sig) {
    // Proof of possession: the signature MUST verify under the subject public key (what openssl req -verify checks).
    return Promise.resolve(_b.assertSignatureVerifies(criDer, sig, subjectSpki, scheme)).then(function () {
      var der = b.sequence([criDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? csr.pemEncode(der, "CERTIFICATE REQUEST") : der;
    });
  }, function (e) {
    if (e instanceof CsrError) throw e;
    throw _err("csr/bad-input", "signing the certification request failed -- the signing key does not match the subject public key or is invalid", e);
  });
}

module.exports = { sign: sign };
