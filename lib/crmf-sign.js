// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.crmf
 * @nav        Signing
 * @title      Certificate request messages
 * @intro The RFC 4211 certificate-request-message producing side. `pki.crmf.build` assembles a
 *   `CertReqMessages` -- one or more `CertReqMsg`, each a `CertRequest` (a `CertTemplate` of the requested
 *   certificate fields plus optional controls) paired with a proof of possession. The common proof is a
 *   `POPOSigningKey` signature over the `CertRequest`, made with the private half of the key being
 *   certified (the requester proves possession, exactly as a PKCS#10 CSR does). The message drops into a
 *   CMP (RFC 9810) or EST enrollment body. Parsing lives at `pki.schema.crmf.parse`.
 * @spec RFC 4211
 * @card Build a CRMF CertReqMessages with a signature proof of possession.
 */
//
// RFC 4211 App. B / RFC 5912 sec. 10 are DEFINITIONS IMPLICIT TAGS: a CertTemplate [0]..[9] field tag
// REPLACES the base universal tag (built via asn1.build.implicit, preserving the primitive/constructed
// bit); the shipped parser encodes issuer [3] / subject [5] Name IMPLICITLY (the dominant CMP/EST wire
// form), so the builder does too. The two EXPLICIT exceptions are the OptionalValidity notBefore [0] /
// notAfter [1] Time (a genuine UTCTime/GeneralizedTime CHOICE). The signature scheme resolves from the
// requested publicKey through the shared sign-scheme registry; the Name / extension / SPKI encoders and
// the post-sign self-check are the shared lib/pki-build primitives, bound to the crmf namespace.

var asn1 = require("./asn1-der");
var oid = require("./oid");
var crmf = require("./schema-crmf");
var signScheme = require("./sign-scheme");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var frameworkError = require("./framework-error");

var CrmfError = frameworkError.CrmfError;
var b = asn1.build;
function _err(code, message, cause) { return new CrmfError(code, message, cause); }
function _signE(kind, message, cause) { return new CrmfError("crmf/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var NS = pkix.makeNS("crmf", CrmfError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var _b = pkiBuild.makeBuilder({
  ErrorClass: CrmfError, prefix: "crmf", O: O, NS: NS,
  NAME_SCHEMA: pkix.name(NS), SPKI_SCHEMA: pkix.spki(NS), EXT_DECODERS: EXT_DECODERS,
});

var KNOWN_SPEC_KEYS = { certReqId: 1, certTemplate: 1, controls: 1, regInfo: 1, pop: 1 };
var KNOWN_TEMPLATE_KEYS = { version: 1, subject: 1, publicKey: 1, validity: 1, extensions: 1, issuer: 1 };
// object key -> the registered OID name of the control / regInfo AttributeTypeAndValue it emits, and the
// value encoder. regToken/authenticator/utf8Pairs are UTF8String (RFC 4211 sec. 6.1/6.2/7.1); oldCertID
// is a CertId SEQUENCE; protocolEncrKey is a validated SPKI.
var CONTROL_UTF8 = { regToken: "regToken", authenticator: "authenticator", utf8Pairs: "utf8Pairs" };

// ---- CertTemplate + POP structural encoders (byte-exact inverses of schema-crmf.js) ----

// OptionalValidity [4] IMPLICIT SEQUENCE { notBefore [0] EXPLICIT Time, notAfter [1] EXPLICIT Time } --
// at least one present (RFC 4211 sec. 5). Time is a CHOICE so [0]/[1] are EXPLICIT.
function _encodeOptionalValidity(validity) {
  if (!validity || typeof validity !== "object" || Buffer.isBuffer(validity)) throw _err("crmf/bad-validity", "validity must be an object { notBefore?, notAfter? }");
  var nb = validity.notBefore, na = validity.notAfter;
  if (nb == null && na == null) throw _err("crmf/bad-validity", "validity must contain notBefore or notAfter (RFC 4211 sec. 5)");
  var parts = [];
  // timeDer validates each instant (guard.time.assertValid throws on an Invalid Date) BEFORE the
  // inverted-window comparison, so getTime() below cannot be NaN.
  if (nb != null) parts.push(b.explicit(0, _b.timeDer(nb, "validity notBefore")));
  if (na != null) parts.push(b.explicit(1, _b.timeDer(na, "validity notAfter")));
  // allow:nan-date-comparison-unguarded -- both instants passed timeDer's guard.time.assertValid above.
  if (nb != null && na != null && nb.getTime() > na.getTime()) throw _err("crmf/bad-validity", "notBefore must not be after notAfter");
  return b.implicit(4, b.sequence(parts));
}
// CertTemplate ::= SEQUENCE { [0..9] all IMPLICIT OPTIONAL }. A REQUEST omits serialNumber [1] / signingAlg
// [2] / issuerUID [7] / subjectUID [8] (CA-assigned or deprecated, RFC 4211 sec. 5) -- the builder never
// emits them. Fields are emitted in ascending tag order.
function _encodeCertTemplate(tpl) {
  if (!tpl || typeof tpl !== "object" || Buffer.isBuffer(tpl)) throw _err("crmf/bad-cert-template", "certTemplate must be an object");
  Object.keys(tpl).forEach(function (k) { if (!KNOWN_TEMPLATE_KEYS[k]) throw _err("crmf/bad-input", "unknown certTemplate field " + JSON.stringify(k)); });
  var fields = [];
  if (tpl.version != null) {
    if (tpl.version !== 2) throw _err("crmf/bad-version", "certTemplate version MUST be 2 (v3) if supplied (RFC 4211 sec. 5)");
    fields.push(b.implicit(0, b.integer(2n)));                                  // version [0]
  }
  if (tpl.issuer != null) fields.push(b.implicit(3, _b.encodeName(tpl.issuer)));   // issuer [3] (IMPLICIT, parser's encode form)
  if (tpl.validity != null) fields.push(_encodeOptionalValidity(tpl.validity));    // validity [4]
  if (tpl.subject != null) fields.push(b.implicit(5, _b.encodeName(tpl.subject))); // subject [5]
  var spki = null;
  if (tpl.publicKey != null) {
    spki = _b.reqDer(tpl.publicKey, "certTemplate.publicKey (the SPKI DER of the requested key)");
    _b.assertValidSpki(spki, "certTemplate.publicKey");
    fields.push(b.implicit(6, spki));                                             // publicKey [6]
  }
  if (tpl.extensions != null) fields.push(b.implicit(9, _b.requestedExtensions(tpl.extensions, spki)));   // extensions [9]
  return { der: b.sequence(fields), spki: spki, complete: tpl.subject != null && tpl.publicKey != null };
}

// Controls / regInfo ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue { type OID, value ANY }. Object
// form maps recognized names to typed value encoders; any other (or a pre-encoded AttributeTypeAndValue
// DER array) rides the escape hatch, shape-validated.
function _buildAttrTypeAndValues(spec, code, label) {
  if (Array.isArray(spec)) {
    if (!spec.length) throw _err(code, label + " must carry at least one entry");
    var seenA = {};
    return b.sequence(spec.map(function (e, i) {
      var der = _b.reqDer(e, label + " [" + i + "]");
      var n;
      try { n = asn1.decode(der); } catch (err) { throw _err("crmf/bad-input", "pre-encoded " + label + " [" + i + "] is not valid DER", err); }
      if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length !== 2) throw _err("crmf/bad-input", "pre-encoded " + label + " [" + i + "] must be a SEQUENCE { type OID, value }");
      var t;
      try { t = asn1.read.oid(n.children[0]); } catch (err) { throw _err("crmf/bad-input", "pre-encoded " + label + " [" + i + "] type is not an OBJECT IDENTIFIER", err); }
      if (seenA[t]) throw _err(code, "duplicate " + label + " type " + (oid.name(t) || t));
      seenA[t] = true;
      return b.raw(der);
    }));
  }
  if (!spec || typeof spec !== "object") throw _err("crmf/bad-input", label + " must be an object or an array of pre-encoded AttributeTypeAndValue DER");
  var out = [], seen = {};
  Object.keys(spec).forEach(function (k) {
    var typeOid, valueTlv;
    if (CONTROL_UTF8[k]) { typeOid = O(CONTROL_UTF8[k]); valueTlv = b.utf8(String(spec[k])); }
    else if (k === "oldCertID") { typeOid = O("oldCertID"); valueTlv = _encodeCertId(spec[k]); }
    else if (k === "protocolEncrKey") {
      typeOid = O("protocolEncrKey");
      var key = _b.reqDer(spec[k], "controls.protocolEncrKey (an SPKI DER)");
      _b.assertValidSpki(key, "controls.protocolEncrKey");
      valueTlv = b.raw(key);
    } else {
      throw _err("crmf/bad-input", "unknown " + label + " " + JSON.stringify(k) + "; pass a pre-encoded AttributeTypeAndValue DER via the array form for a custom control");
    }
    if (seen[typeOid]) throw _err(code, "duplicate " + label + " type " + k);
    seen[typeOid] = true;
    out.push(b.sequence([b.oid(typeOid), valueTlv]));
  });
  if (!out.length) throw _err(code, label + " must carry at least one entry");
  return b.sequence(out);
}
// certReqId is a signed INTEGER, value UNCONSTRAINED (the RFC 9483 -1 sentinel and 0 are both legal). A
// number must be a safe integer (a fractional or > 2^53 number loses precision through BigInt); a BigInt
// or a decimal / 0x-hex string carries an arbitrary value.
function _certReqId(v) {
  if (v == null) return 0n;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw _err("crmf/bad-input", "certReqId number must be a safe integer (pass a BigInt or a string for a larger value)"); return BigInt(v); }
  if (typeof v === "string") { try { return BigInt(v); } catch (e) { throw _err("crmf/bad-input", "certReqId string must be a decimal or 0x-hex integer", e); } }
  throw _err("crmf/bad-input", "certReqId must be a BigInt, a safe integer, or a string");
}
// CertId ::= SEQUENCE { issuer GeneralName, serialNumber INTEGER } (RFC 4211 sec. 6.4, oldCertID value).
function _encodeCertId(id) {
  if (!id || typeof id !== "object" || id.issuer == null || id.serialNumber == null) throw _err("crmf/bad-input", "oldCertID must be { issuer: GeneralName, serialNumber }");
  return b.sequence([_b.encodeGeneralName(id.issuer), _b.serialInteger(id.serialNumber)]);
}

// ProofOfPossession. The signature arm (the default when a key is given): when the template carries BOTH
// subject and publicKey (complete), sign the CertRequest DER and OMIT poposkInput; otherwise build a
// POPOSigningKeyInput (authInfo sender [0] GeneralName + the requested publicKey), sign its SEQUENCE, and
// carry it as poposkInput [0] (RFC 4211 sec. 4.1). raVerified is emitted only on an explicit opt-in.
function _buildProofOfPossession(pop, certReqDer, template, signingKey, opts) {
  var mode = (pop && pop.type) || (signingKey != null ? "signature" : null);
  if (mode == null) return null;   // no POP requested and no key -> omit popo (an RA supplies it out of band)
  if (mode === "raVerified") {
    if (!(pop && pop.raVerified === true)) throw _err("crmf/bad-popo", "raVerified must be explicitly opted into (pop: { type: 'raVerified', raVerified: true }) -- a requester does not normally assert it (RFC 4211 sec. 4)");
    return b.implicit(0, b.nullValue());   // raVerified [0] IMPLICIT NULL
  }
  if (mode !== "signature") throw _err("crmf/bad-popo", "unsupported proof-of-possession type " + JSON.stringify(mode) + " (supported: 'signature', 'raVerified')");
  if (signingKey == null) throw _err("crmf/bad-input", "a signature proof of possession requires the requester's private key");
  if (template.spki == null) throw _err("crmf/bad-input", "a signature proof of possession requires certTemplate.publicKey");
  var scheme = signScheme.resolveSignScheme(_b.certLikeFromSpki(template.spki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);
  var signedRegion, poposkInputField = null;
  if (template.complete) {
    signedRegion = certReqDer;   // sec. 4.1: complete template -> sign the CertRequest, poposkInput omitted
  } else {
    // POPOSigningKeyInput ::= SEQUENCE { authInfo CHOICE { sender [0] GeneralName, publicKeyMAC }, publicKey }.
    var sender = pop && pop.sender;
    if (sender == null) throw _err("crmf/bad-popo", "an incomplete template (missing subject or publicKey) requires pop.sender (a GeneralName) for the POPOSigningKeyInput authInfo (RFC 4211 sec. 4.1)");
    var poposkSeq = b.sequence([b.explicit(0, _b.encodeGeneralName(sender)), b.raw(template.spki)]);
    signedRegion = poposkSeq;
    poposkInputField = b.implicit(0, poposkSeq);   // poposkInput [0] IMPLICIT POPOSigningKeyInput
  }
  return signScheme.signOverTbs(scheme, signingKey, signedRegion, _signE).then(function (sig) {
    return Promise.resolve(_b.assertSignatureVerifies(signedRegion, sig, template.spki, scheme)).then(function () {
      var popoChildren = [];
      if (poposkInputField) popoChildren.push(poposkInputField);
      popoChildren.push(scheme.sigAlgId);
      popoChildren.push(b.bitString(sig, 0));
      return b.implicit(1, b.sequence(popoChildren));   // signature [1] IMPLICIT POPOSigningKey
    });
  }, function (e) {
    if (e instanceof CrmfError) throw e;
    throw _err("crmf/bad-input", "signing the proof of possession failed -- the key does not match the requested public key or is invalid", e);
  });
}

/**
 * @primitive pki.crmf.build
 * @signature pki.crmf.build(spec, key?, opts?) -> Promise<Buffer|string>
 * @since 0.3.3
 * @status experimental
 * @spec RFC 4211
 * @defends forged-certificate-request (CWE-347)
 * @related pki.schema.crmf.parse, pki.csr.sign
 *
 * Build and DER-encode an RFC 4211 `CertReqMessages`. `spec` describes one certificate request message (or
 * pass `spec.messages` -- an array of specs -- for a batch): `certReqId` (an integer, default 0; the RFC
 * 9483 `-1` sentinel is allowed), `certTemplate` (the requested certificate fields -- `subject`, `publicKey`
 * (the SPKI DER of the key being certified), `validity` ({ notBefore, notAfter } Dates), `extensions` (an
 * object of subjectAltName / keyUsage / extendedKeyUsage / basicConstraints / certificatePolicies /
 * subjectKeyIdentifier, or pre-encoded Extension DER), and an optional `version` (2)), optional `controls`
 * and `regInfo` (an object of regToken / authenticator / utf8Pairs / oldCertID / protocolEncrKey, or
 * pre-encoded AttributeTypeAndValue DER), and an optional `pop` selector. `key` (or `{ key }`) is the
 * REQUESTER's private key -- the private half of `certTemplate.publicKey`; the message carries a
 * `POPOSigningKey` proof of possession signed with it (verified before the message is returned), exactly
 * as a PKCS#10 CSR proves possession. The signature algorithm is resolved from the requested public key
 * (RSA PKCS#1 v1.5 / PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm). `key` is optional -- omit it
 * for a `raVerified` proof (opt in with `pop: { type: 'raVerified', raVerified: true }`). Returns DER, or a
 * PEM block with `opts.pem` (the label is required). Malformed input throws a typed `CrmfError`.
 * Certificate-request-message parsing is `pki.schema.crmf.parse`.
 *
 * @opts
 *   - `pem` (string) -- return a PEM block with this label instead of DER (e.g. "CERTIFICATE REQUEST MESSAGE").
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS rather than PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var msg = await pki.crmf.build(
 *     { certReqId: 0, certTemplate: { subject: "device-42", publicKey: signerSpki } },
 *     { key: signerKeyPkcs8 });
 *   pki.schema.crmf.parse(msg).messages[0].certReq.certTemplate.subject.dn;   // "CN=device-42"
 */
function build(spec, key, opts) {
  return Promise.resolve().then(function () { return _build(spec, key, opts); });
}

function _buildCertReqMsg(spec, key, opts) {
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("crmf/bad-input", "each certificate-request-message spec must be an object");
  Object.keys(spec).forEach(function (k) { if (!KNOWN_SPEC_KEYS[k]) throw _err("crmf/bad-input", "unknown spec field " + JSON.stringify(k)); });
  if (spec.certTemplate == null) throw _err("crmf/bad-input", "spec.certTemplate is required");

  var signingKey = (key && typeof key === "object" && !Buffer.isBuffer(key) && !(key instanceof Uint8Array) && key.type == null && "key" in key) ? key.key : key;
  var template = _encodeCertTemplate(spec.certTemplate);
  var certReqChildren = [b.integer(_certReqId(spec.certReqId)), template.der];
  if (spec.controls != null) certReqChildren.push(_buildAttrTypeAndValues(spec.controls, "crmf/bad-controls", "controls"));
  var certReqDer = b.sequence(certReqChildren);

  return Promise.resolve(_buildProofOfPossession(spec.pop, certReqDer, template, signingKey, opts)).then(function (popoDer) {
    var msgChildren = [certReqDer];
    if (popoDer) msgChildren.push(popoDer);
    if (spec.regInfo != null) msgChildren.push(_buildAttrTypeAndValues(spec.regInfo, "crmf/bad-reg-info", "regInfo"));
    return b.sequence(msgChildren);   // CertReqMsg
  });
}

function _build(spec, key, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("crmf/bad-input", "the certificate-request-message spec must be an object");
  var specs;
  if (spec.messages != null) {
    // Batch form: the envelope carries ONLY `messages` -- reject a stray field so a request spec written at
    // the wrong nesting level (e.g. certTemplate alongside messages) is not silently dropped.
    if (!Array.isArray(spec.messages)) throw _err("crmf/bad-input", "spec.messages must be an array of certificate-request-message specs");
    Object.keys(spec).forEach(function (k) { if (k !== "messages") throw _err("crmf/bad-input", "unknown batch-envelope field " + JSON.stringify(k) + " -- a batch spec carries only 'messages'"); });
    specs = spec.messages;
  } else {
    specs = [spec];
  }
  if (!specs.length) throw _err("crmf/bad-input", "at least one certificate request message is required (RFC 4211 sec. 3)");
  return Promise.all(specs.map(function (s) { return _buildCertReqMsg(s, key, opts); })).then(function (msgs) {
    var der = b.sequence(msgs);   // CertReqMessages ::= SEQUENCE SIZE(1..MAX) OF CertReqMsg
    if (opts.pem != null) {
      if (typeof opts.pem !== "string" || !opts.pem) throw _err("crmf/bad-input", "opts.pem must be a non-empty PEM label string");
      return crmf.pemEncode(der, opts.pem);
    }
    return der;
  });
}

module.exports = { build: build };
