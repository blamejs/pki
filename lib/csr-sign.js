// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.csr
 * @nav        Signing
 * @title      Certification requests
 * @fullname   CSRs (PKCS#10 certification requests): build, sign and verify
 * @intro The PKCS#10 certification-request producing side. `pki.csr.sign` builds a
 *   `CertificationRequestInfo`, signs it with the subject's own private key (proof of possession, since
 *   a CSR has no issuer), and emits a `CertificationRequest` (RFC 2986) that `pki.schema.csr.parse`,
 *   OpenSSL, and a CA enrollment pipeline all accept. Requested v3 extensions ride in a PKCS#9
 *   `extensionRequest` attribute (RFC 2985) a CA copies into the issued certificate. Parsing lives at
 *   `pki.schema.csr.parse`.
 * @spec RFC 2986
 * @card Build and sign a PKCS#10 certification request (proof of possession by the subject key).
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var csr = require("./schema-csr");
var signScheme = require("./sign-scheme");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
require("./path-validate");
var csrVerify = require("./csr-verify");

var CsrError = frameworkError.CsrError;
var KNOWN_SPEC_KEYS = { subject: 1, subjectPublicKey: 1, extensionRequest: 1, challengePassword: 1, attributes: 1 };
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

function _implicitSetOf0(members) {
  return b.contextConstructed(0, Buffer.concat(members.slice().sort(Buffer.compare)));
}

function _buildRequestedExtensions(extSpec, subjectSpki) { return _b.requestedExtensions(extSpec, subjectSpki); }

function _challengePassword(pw) {
  if (typeof pw !== "string" || pw.length < 1 || pw.length > 255) throw _err("csr/bad-input", "challengePassword must be a 1..255 character string (RFC 2985 sec. 5.4.1)");
  return asn1.isPrintableString(pw) ? b.printable(pw) : b.utf8(pw);
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
 * Build, sign, and DER-encode a PKCS#10 certification request. `spec` describes the request: `subject`
 * (a common-name string, an array of RDNs, or raw Name DER; MAY be empty), `subjectPublicKey` (the SPKI
 * DER of the key being certified), and optional `extensionRequest` (requested v3 extensions, as an object
 * of subjectAltName / keyUsage / extendedKeyUsage / basicConstraints / certificatePolicies /
 * subjectKeyIdentifier, or an array of pre-encoded Extension DER) and `challengePassword`. `key` (or
 * `{ key }`) is the subject's own PKCS#8 private key / WebCrypto CryptoKey, so the request is self-signed
 * to prove possession of the private half of `subjectPublicKey`, and that proof is verified before the
 * request is returned. The signature algorithm is resolved from the subject key (RSA PKCS#1 v1.5 or PSS,
 * ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm). Returns DER, or a PEM `CERTIFICATE REQUEST` with
 * `opts.pem`. Malformed input throws a typed `CsrError`; where the spec carries raw DER (a `Name`
 * Buffer, a pre-encoded requested `Extension` or `Attribute`) a malformed leaf inside those bytes
 * throws `Asn1Error` instead. Certificate-request parsing is `pki.schema.csr.parse`.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `CERTIFICATE REQUEST` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS instead of PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerSpki = await pki.key.export(pair.publicKey);
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var req = await pki.csr.sign(
 *     { subject: "req.example.com", subjectPublicKey: signerSpki,
 *       extensionRequest: { subjectAltName: [{ dNSName: "req.example.com" }] } },
 *     { key: signerKeyPkcs8 });
 *   pki.schema.csr.parse(req).subject.dn;   // "CN=req.example.com"
 */
function sign(spec, key, opts) {
  return guard.bytes.fixedCall(CsrError, "csr/bad-input", [
    [spec, "the certification-request spec"], [key, "the signing key"], [opts, "pki.csr.sign options"],
  ], _sign);
}

function _sign(spec, key, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("csr/bad-input", "the certification-request spec must be an object");
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, _err, "csr/bad-input", "unknown spec field ");
  var signingKey = (key && typeof key === "object" && !Buffer.isBuffer(key) && !(key instanceof Uint8Array) && key.type == null && "key" in key) ? key.key : key;
  if (signingKey == null) throw _err("csr/bad-input", "a signing key (the subject's private key) is required");

  var subjectSpki = _b.reqDer(spec.subjectPublicKey, "spec.subjectPublicKey (the SPKI DER of the requested key)");
  _b.assertValidSpki(subjectSpki, "spec.subjectPublicKey");
  var subjectDer = _b.encodeName(spec.subject == null ? [] : spec.subject);

  var attrs = [], seenAttr = {};
  function addAttr(attrType, valueTlv) {
    if (seenAttr[attrType]) throw _err("csr/bad-input", "duplicate " + (oid.name(attrType) || attrType) + " attribute");
    seenAttr[attrType] = true;
    attrs.push(b.sequence([b.oid(attrType), b.set([valueTlv])]));
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
      if (at === O("extensionRequest")) throw _err("csr/bad-input", "pass requested extensions via spec.extensionRequest, not a pre-encoded extensionRequest attribute");
      if (at === O("challengePassword")) throw _err("csr/bad-input", "pass the challenge password via spec.challengePassword, not a pre-encoded challengePassword attribute");
      if (!n.children[1].children || n.children[1].children.length === 0) throw _err("csr/bad-input", "pre-encoded attribute [" + i + "] value SET must contain at least one value (RFC 2986 SET SIZE(1..MAX))");
      if (seenAttr[at]) throw _err("csr/bad-input", "duplicate " + (oid.name(at) || at) + " attribute");
      seenAttr[at] = true;
      attrs.push(b.raw(der));
    });
  }

  var scheme = signScheme.resolveSignScheme(_b.certLikeFromSpki(subjectSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  var criDer = b.sequence([b.integer(0n), subjectDer, b.raw(subjectSpki), _implicitSetOf0(attrs)]);

  return signScheme.signOverTbs(scheme, signingKey, criDer, _signE).then(function (sig) {
    return Promise.resolve(_b.assertSignatureVerifies(criDer, sig, subjectSpki, scheme)).then(function () {
      var der = b.sequence([criDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? csr.pemEncode(der, "CERTIFICATE REQUEST") : der;
    });
  }, function (e) {
    if (e instanceof CsrError) throw e;
    throw _err("csr/bad-input", "signing the certification request failed -- the signing key does not match the subject public key or is invalid", e);
  });
}

function _coerceCsr(request) {
  return guard.parsed.acceptDerived(request, "csr", csr.parse, _err, "csr/bad-input", "the certification request");
}

/**
 * @primitive pki.csr.verify
 * @signature pki.csr.verify(request) -> Promise<{ valid, verified, subject, subjectPublicKeyInfo, attributes, certificationRequestInfoBytes }>
 * @since 0.5.13
 * @status stable
 * @spec RFC 2986 sec. 4.2
 * @defends csr-proof-of-possession-bypass (CWE-347)
 * @related pki.csr.sign, pki.schema.csr.parse, pki.x509.sign
 *
 * Verify a certification request's signature over its exact parsed `certificationRequestInfo` bytes.
 * `request` is a DER `Buffer`, a PEM string, or a parsed request. A CSR carries no issuer: the
 * verifying key is the `subjectPKInfo` inside the signed preimage, so this is the proof of
 * possession `openssl req -verify` checks, and a CA that issues without it certifies a key the
 * requester may not hold.
 *
 * The result carries `verified` alongside the `subject`, `subjectPublicKeyInfo`, `attributes` and
 * `certificationRequestInfoBytes` that were verified, all re-derived from the request's own bytes.
 * Issue from those rather than from the argument: a request normalized in place before verifying
 * leaves the caller holding edited fields, and a bare boolean would answer about the signed bytes
 * while the certificate got built from the edits.
 *
 * What `true` establishes is bounded, and the bound is the point. It says the producer held the
 * private half of the key inside this request, over bytes that include the subject name and every
 * requested extension, so none of them were altered after signing. It says nothing about who the
 * producer is: the key is self-asserted, the name is self-asserted, and a requester free to choose
 * both can prove possession of a key they generated a moment ago under any name they like. Binding
 * that name to an identity is the enrollment protocol's job -- `pki.est`, `pki.cmc`, `pki.cmp`, or
 * an out-of-band check -- and remains one after this returns `true`.
 *
 * Verification composes the one path-validation signature engine, with the same algorithm-confusion
 * (RFC 9814 sec. 4 key-OID == sig-OID) and EdDSA low-order-point gates, rather than the self-check
 * this module's signing side runs over a key the caller already controls. It fails closed to
 * `false` on any import or verification fault; malformed input throws a typed `CsrError`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spki = await pki.key.export(pair.publicKey);
 *   var pkcs8 = await pki.key.export(pair.privateKey);
 *   // A bare string is the commonName VALUE, so this asks for CN=device-42.
 *   var req = await pki.csr.sign({ subject: "device-42", subjectPublicKey: spki }, { key: pkcs8 });
 *   var r = await pki.csr.verify(req);
 *   // Issue from r.subject / r.subjectPublicKeyInfo / r.attributes, which are the verified fields.
 *   var issued = r.verified
 *     ? await pki.x509.sign({ subject: r.subject.dn, subjectPublicKey: r.subjectPublicKeyInfo.bytes,
 *         notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z") },
 *       { key: pkcs8 })
 *     : null;
 */
function verify(request) { return guard.async.deferred(function () { return _verify(request); }); }
function _verify(request) {
  var parsed = _coerceCsr(request);
  return Promise.resolve(csrVerify.verifyCsrSignature(parsed)).then(function (ok) {
    return {
      valid: ok === true,
      verified: ok === true,
      subject: parsed.subject,
      subjectPublicKeyInfo: parsed.subjectPublicKeyInfo,
      attributes: parsed.attributes,
      certificationRequestInfoBytes: parsed.certificationRequestInfoBytes,
    };
  });
}

module.exports = { sign: sign, verify: verify };
