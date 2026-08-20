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
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
require("./path-validate");   // side-effect: path-validate injects its signature engine into crmf-verify at load
var crmfVerify = require("./crmf-verify");

// The runtime operations this module builds and verifies with, bound at load. Each is an ordinary
// writable property of a global until it is captured, so one replaced afterwards decides whether a
// byte check runs, which entries a spec is held to, and what a verdict reports.
var _keys = intrinsic.keys;
var _assign = intrinsic.assign;
var _stringify = intrinsic.stringify;
var _isArray = intrinsic.isArray;
var _isBuffer = intrinsic.isBuffer;
var _isSafeInteger = intrinsic.isSafeInteger;
var _map = intrinsic.map;
var _every = intrinsic.every;
var _push = intrinsic.uncurry(Array.prototype.push);
var _String = intrinsic.String;
var _BigInt = intrinsic.BigInt;
var _Promise = Promise;
var _promiseResolve = intrinsic.uncurry(intrinsic.promiseResolve);

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
var KNOWN_BATCH_KEYS = { messages: 1 };
var KNOWN_TEMPLATE_KEYS = { version: 1, subject: 1, publicKey: 1, validity: 1, extensions: 1, issuer: 1 };
var REVOCATION_TEMPLATE_KEYS = { version: 1, subject: 1, publicKey: 1, validity: 1, extensions: 1, issuer: 1, serialNumber: 1 };
// The controls (RFC 4211 sec. 6) and regInfo (sec. 7) are disjoint AttributeTypeAndValue namespaces:
// regToken/authenticator/oldCertID/protocolEncrKey are controls and utf8Pairs is regInfo, so the object
// form validates each key against its own field's registry (a control name is not a valid regInfo, and
// vice versa). The key name equals the registered OID name; complex values (pkiPublicationInfo, certReq)
// ride the pre-encoded escape hatch. Each entry is the value encoder for that OID.
function _ctlUtf8(v) { return b.utf8(_String(v)); }
function _ctlSpki(v) { var k = _b.reqDer(v, "protocolEncrKey (an SPKI DER)"); _b.assertValidSpki(k, "protocolEncrKey"); return b.raw(k); }
var CONTROL_VALUE = { regToken: _ctlUtf8, authenticator: _ctlUtf8, oldCertID: function (v) { return _encodeCertId(v); }, protocolEncrKey: _ctlSpki };
var REGINFO_VALUE = { utf8Pairs: _ctlUtf8 };

// ---- CertTemplate + POP structural encoders (byte-exact inverses of schema-crmf.js) ----

// OptionalValidity [4] IMPLICIT SEQUENCE { notBefore [0] EXPLICIT Time, notAfter [1] EXPLICIT Time } --
// at least one present (RFC 4211 sec. 5). Time is a CHOICE so [0]/[1] are EXPLICIT.
function _encodeOptionalValidity(validity) {
  if (!validity || typeof validity !== "object" || _isBuffer(validity)) throw _err("crmf/bad-validity", "validity must be an object { notBefore?, notAfter? }");
  var nb = validity.notBefore, na = validity.notAfter;
  if (nb == null && na == null) throw _err("crmf/bad-validity", "validity must contain notBefore or notAfter (RFC 4211 sec. 5)");
  var parts = [];
  // timeDer validates each instant (guard.time.assertValid throws on an Invalid Date) before the
  // inverted-window comparison, so getTime() below cannot be NaN.
  if (nb != null) _push(parts, b.explicit(0, _b.timeDer(nb, "validity notBefore")));
  if (na != null) _push(parts, b.explicit(1, _b.timeDer(na, "validity notAfter")));
  // allow:nan-date-comparison-unguarded -- both instants passed timeDer's guard.time.assertValid above.
  if (nb != null && na != null && guard.time.instantOf(nb) > guard.time.instantOf(na)) throw _err("crmf/bad-validity", "notBefore must not be after notAfter");
  return b.implicit(4, b.sequence(parts));
}
// CertTemplate ::= SEQUENCE { [0..9] all IMPLICIT OPTIONAL }. A request omits serialNumber [1] / signingAlg
// [2] / issuerUID [7] / subjectUID [8] (CA-assigned or deprecated, RFC 4211 sec. 5), and the builder never
// emits them. Fields are emitted in ascending tag order.
function _encodeCertTemplate(tpl, opts) {
  if (!tpl || typeof tpl !== "object" || _isBuffer(tpl)) throw _err("crmf/bad-cert-template", "certTemplate must be an object");
  // A request template omits serialNumber (CA-assigned, RFC 4211 sec. 5); a revocation template (CMP rr,
  // RFC 9810 sec. 5.3.9) carries serialNumber [1] to name the certificate to revoke, allowed only then.
  var allowed = (opts && opts.revocation) ? REVOCATION_TEMPLATE_KEYS : KNOWN_TEMPLATE_KEYS;
  guard.identifier.assertKnownKeys(tpl, allowed, _err, "crmf/bad-input", "unknown certTemplate field ");
  var fields = [];
  if (tpl.version != null) {
    if (tpl.version !== 2) throw _err("crmf/bad-version", "certTemplate version MUST be 2 (v3) if supplied (RFC 4211 sec. 5)");
    _push(fields, b.implicit(0, b.integer(2n)));                                  // version [0]
  }
  if (tpl.serialNumber != null) _push(fields, b.implicit(1, _b.serialInteger(tpl.serialNumber)));   // serialNumber [1] (revocation only)
  // issuer [3] / subject [5] are EXPLICIT: Name is a CHOICE, and X.680 sec. 31.2.7 forces a context tag on
  // a CHOICE to EXPLICIT even under the module's IMPLICIT TAGS default (the [3]/[5] wraps the RDNSequence
  // SEQUENCE, it does not replace its tag). The parser accepts both forms; this is the conformant one.
  if (tpl.issuer != null) _push(fields, b.explicit(3, _b.encodeName(tpl.issuer)));    // issuer [3] EXPLICIT
  if (tpl.validity != null) _push(fields, _encodeOptionalValidity(tpl.validity));     // validity [4] IMPLICIT
  if (tpl.subject != null) _push(fields, b.explicit(5, _b.encodeName(tpl.subject)));  // subject [5] EXPLICIT
  var spki = null;
  if (tpl.publicKey != null) {
    spki = _b.reqDer(tpl.publicKey, "certTemplate.publicKey (the SPKI DER of the requested key)");
    _b.assertValidSpki(spki, "certTemplate.publicKey");
    _push(fields, b.implicit(6, spki));                                             // publicKey [6]
  }
  if (tpl.extensions != null) _push(fields, b.implicit(9, _b.requestedExtensions(tpl.extensions, spki)));   // extensions [9]
  return { der: b.sequence(fields), spki: spki, complete: tpl.subject != null && tpl.publicKey != null };
}

// Controls / regInfo ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue { type OID, value ANY }. Object
// form maps recognized names to typed value encoders; any other (or a pre-encoded AttributeTypeAndValue
// DER array) rides the escape hatch, shape-validated.
function _buildAttrTypeAndValues(spec, code, label, valueMap) {
  if (_isArray(spec)) {
    if (!spec.length) throw _err(code, label + " must carry at least one entry");
    var seenA = {};
    return b.sequence(_map(spec, function (e, i) {
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
  guard.identifier.assertKnownKeys(spec, valueMap, _err, "crmf/bad-input", function (k) {
    return "unknown " + label + " " + _stringify(k) + "; pass a pre-encoded AttributeTypeAndValue DER via the array form for a " + label + " entry outside " + _keys(valueMap).join("/");
  });
  _keys(spec).forEach(function (k) {
    var enc = valueMap[k];
    var typeOid = O(k);
    if (seen[typeOid]) throw _err(code, "duplicate " + label + " type " + k);
    seen[typeOid] = true;
    _push(out, b.sequence([b.oid(typeOid), enc(spec[k])]));
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
  if (typeof v === "number") { if (!_isSafeInteger(v)) throw _err("crmf/bad-input", "certReqId number must be a safe integer (pass a BigInt or a string for a larger value)"); return _BigInt(v); }
  if (typeof v === "string") { try { return _BigInt(v); } catch (e) { throw _err("crmf/bad-input", "certReqId string must be a decimal or 0x-hex integer", e); } }
  throw _err("crmf/bad-input", "certReqId must be a BigInt, a safe integer, or a string");
}
// CertId ::= SEQUENCE { issuer GeneralName, serialNumber INTEGER } (RFC 4211 sec. 6.4, oldCertID value).
function _encodeCertId(id) {
  if (!id || typeof id !== "object" || id.issuer == null || id.serialNumber == null) throw _err("crmf/bad-input", "oldCertID must be { issuer: GeneralName, serialNumber }");
  return b.sequence([_b.encodeGeneralName(id.issuer), _b.serialInteger(id.serialNumber)]);
}

// ProofOfPossession. The signature arm (the default when a key is given): when the template carries both
// subject and publicKey (complete), sign the CertRequest DER and omit poposkInput; otherwise build a
// POPOSigningKeyInput (authInfo sender [0] GeneralName + the requested publicKey), sign its SEQUENCE, and
// carry it as poposkInput [0] (RFC 4211 sec. 4.1). raVerified is emitted only on an explicit opt-in.
function _buildProofOfPossession(pop, certReqDer, template, signingKey, opts) {
  if (pop != null && (typeof pop !== "object" || _isBuffer(pop))) throw _err("crmf/bad-input", "spec.pop must be an object (e.g. { type: 'signature' } or { type: 'raVerified', raVerified: true })");
  var mode = (pop && pop.type) || (signingKey != null ? "signature" : null);
  if (mode == null) return null;   // no POP requested and no key -> omit popo (an RA supplies it out of band)
  if (mode === "raVerified") {
    if (!(pop && pop.raVerified === true)) throw _err("crmf/bad-popo", "raVerified must be explicitly opted into (pop: { type: 'raVerified', raVerified: true }) -- a requester does not normally assert it (RFC 4211 sec. 4)");
    return b.implicit(0, b.nullValue());   // raVerified [0] IMPLICIT NULL
  }
  if (mode !== "signature") throw _err("crmf/bad-popo", "unsupported proof-of-possession type " + _stringify(mode) + " (supported: 'signature', 'raVerified')");
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
    return _promiseResolve(_Promise, _b.assertSignatureVerifies(signedRegion, sig, template.spki, scheme)).then(function () {
      var popoChildren = [];
      if (poposkInputField) _push(popoChildren, poposkInputField);
      _push(popoChildren, scheme.sigAlgId);
      _push(popoChildren, b.bitString(sig, 0));
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
 * @status stable
 * @spec RFC 4211
 * @defends forged-certificate-request (CWE-347)
 * @related pki.schema.crmf.parse, pki.csr.sign
 *
 * Build and DER-encode an RFC 4211 `CertReqMessages`. `spec` describes one certificate request message (or
 * pass `spec.messages`, an array of specs, for a batch): `certReqId` (an integer, default 0; the RFC
 * 9483 `-1` sentinel is allowed), `certTemplate` (the requested certificate fields: `subject`, `publicKey`
 * (the SPKI DER of the key being certified), `validity` ({ notBefore, notAfter } Dates), `extensions` (an
 * object of subjectAltName / keyUsage / extendedKeyUsage / basicConstraints / certificatePolicies /
 * subjectKeyIdentifier, or pre-encoded Extension DER), and an optional `version` (2)), optional `controls`
 * and `regInfo` (an object of regToken / authenticator / utf8Pairs / oldCertID / protocolEncrKey, or
 * pre-encoded AttributeTypeAndValue DER), and an optional `pop` selector. `key` (or `{ key }`) is the
 * REQUESTER's private key -- the private half of `certTemplate.publicKey`; the message carries a
 * `POPOSigningKey` proof of possession signed with it (verified before the message is returned), exactly
 * as a PKCS#10 CSR proves possession. The signature algorithm is resolved from the requested public key
 * (RSA PKCS#1 v1.5 / PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm). `key` is optional: omit it
 * for a `raVerified` proof (opt in with `pop: { type: 'raVerified', raVerified: true }`). Returns DER, or a
 * PEM block with `opts.pem` (the label is required). Malformed input throws a typed `CrmfError`.
 * Certificate-request-message parsing is `pki.schema.crmf.parse`.
 *
 * @opts
 *   - `pem` (string) -- return a PEM block with this label instead of DER (e.g. "CERTIFICATE REQUEST MESSAGE").
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS instead of PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerSpki = await pki.key.export(pair.publicKey);
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var msg = await pki.crmf.build(
 *     { certReqId: 0, certTemplate: { subject: "device-42", publicKey: signerSpki } },
 *     { key: signerKeyPkcs8 });
 *   pki.schema.crmf.parse(msg).messages[0].certReq.certTemplate.subject.dn;   // "CN=device-42"
 */
function build(spec, key, opts) {
  // Every caller-owned argument copied at entry and released when the call settles -- see the note
  // on the same call in x509-sign.
  return guard.bytes.fixedCall(CrmfError, "crmf/bad-input", [
    [spec, "the certificate-request-message spec"], [key, "the signing key"], [opts, "pki.crmf.build options"],
  ], _build);
}

function _buildCertReqMsg(spec, key, opts) {
  if (!spec || typeof spec !== "object" || _isBuffer(spec)) throw _err("crmf/bad-input", "each certificate-request-message spec must be an object");
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, _err, "crmf/bad-input", "unknown spec field ");
  if (spec.certTemplate == null) throw _err("crmf/bad-input", "spec.certTemplate is required");

  var signingKey = (key && typeof key === "object" && !_isBuffer(key) && !(key instanceof Uint8Array) && key.type == null && "key" in key) ? key.key : key;
  var template = _encodeCertTemplate(spec.certTemplate);
  var certReqChildren = [b.integer(_certReqId(spec.certReqId)), template.der];
  if (spec.controls != null) _push(certReqChildren, _buildAttrTypeAndValues(spec.controls, "crmf/bad-controls", "controls", CONTROL_VALUE));
  var certReqDer = b.sequence(certReqChildren);

  return _promiseResolve(_Promise, _buildProofOfPossession(spec.pop, certReqDer, template, signingKey, opts)).then(function (popoDer) {
    var msgChildren = [certReqDer];
    if (popoDer) _push(msgChildren, popoDer);
    if (spec.regInfo != null) _push(msgChildren, _buildAttrTypeAndValues(spec.regInfo, "crmf/bad-reg-info", "regInfo", REGINFO_VALUE));
    return b.sequence(msgChildren);   // CertReqMsg
  });
}

function _build(spec, key, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || _isBuffer(spec)) throw _err("crmf/bad-input", "the certificate-request-message spec must be an object");
  var specs;
  if (spec.messages != null) {
    // Batch form: the envelope carries ONLY `messages` -- reject a stray field so a request spec written at
    // the wrong nesting level (e.g. certTemplate alongside messages) is not silently dropped.
    if (!_isArray(spec.messages)) throw _err("crmf/bad-input", "spec.messages must be an array of certificate-request-message specs");
    guard.identifier.assertKnownKeys(spec, KNOWN_BATCH_KEYS, _err, "crmf/bad-input", function (k) {
      return "unknown batch-envelope field " + _stringify(k) + " -- a batch spec carries only 'messages'";
    });
    specs = spec.messages;
  } else {
    specs = [spec];
  }
  if (!specs.length) throw _err("crmf/bad-input", "at least one certificate request message is required (RFC 4211 sec. 3)");
  return Promise.all(_map(specs, function (s) { return _buildCertReqMsg(s, key, opts); })).then(function (msgs) {
    var der = b.sequence(msgs);   // CertReqMessages ::= SEQUENCE SIZE(1..MAX) OF CertReqMsg
    if (opts.pem != null) {
      if (typeof opts.pem !== "string" || !opts.pem) throw _err("crmf/bad-input", "opts.pem must be a non-empty PEM label string");
      return crmf.pemEncode(der, opts.pem);
    }
    return der;
  });
}

/**
 * @primitive  pki.crmf.buildCertTemplate
 * @signature  pki.crmf.buildCertTemplate(template) -> Buffer
 * @since      0.3.5
 * @status     stable
 * @spec       RFC 4211
 * @related    pki.crmf.build
 *
 * Encode a bare RFC 4211 `CertTemplate` (the requested-certificate fields: `subject`, `publicKey`,
 * `validity`, requested `extensions`, an optional `version` 2, `issuer`) to canonical DER. This is the
 * `certTemplate` interior of `pki.crmf.build`, exposed for the RFC 9810 CMP `rr` (revocation request) body,
 * whose `RevDetails.certDetails` carries a `CertTemplate` naming the certificate to revoke. Returns the DER
 * `Buffer`; a malformed template throws a typed `CrmfError`.
 *
 * @example
 *   var tpl = pki.crmf.buildCertTemplate({ serialNumber: 42n, issuer: "CN=CA" });
 *   pki.asn1.decode(tpl).tagNumber === pki.asn1.TAGS.SEQUENCE;   // the CertTemplate SEQUENCE
 */
function buildCertTemplate(template) { return _encodeCertTemplate(template, { revocation: true }).der; }

function _coerceMessages(input) {
  return guard.parsed.acceptDerived(input, "crmf", crmf.parse, _err, "crmf/bad-input", "the certificate request messages");
}

// One CertReqMsg's proof of possession, reduced to a verdict. Every return names a method and
// reports the requested identity, so a refusal is as informative as an acceptance.
function _verifyOne(msg) {
  var t = msg.certReq && msg.certReq.certTemplate;
  var base = {
    certReqId: msg.certReq && msg.certReq.certReqId,
    subject: (t && t.subject) || null,
    subjectBound: false,
    publicKey: (t && t.publicKey && t.publicKey.bytes) || null,
  };
  function settle(extra) { return _promiseResolve(_Promise, _assign({}, base, extra)); }

  var popo = msg.popo;
  if (popo == null) {
    return settle({ verified: false, method: null, cryptographicallyVerified: false,
      reason: "the request carries no proof of possession" });
  }
  if (popo.type === "raVerified") {
    // sec. 4: an assertion by the RA that it checked possession out of band. It is not a proof and
    // must not read as one; a caller that trusts its RA opts in by reading `method`.
    return settle({ verified: false, method: "raVerified", cryptographicallyVerified: false,
      reason: "raVerified asserts the RA checked possession out of band -- this is not a proof and cannot be verified from the message" });
  }
  if (popo.type !== "signature") {
    // keyEncipherment / keyAgreement complete over a later protocol exchange (a challenge the
    // verifier does not hold) or need the CA's decryption key, so no verdict is available here.
    return settle({ verified: false, method: popo.type, cryptographicallyVerified: false,
      reason: "a " + popo.type + " proof of possession completes over an exchange this verifier does not hold (RFC 4211 sec. 4.2, 4.3)" });
  }

  // Which bytes the signature covers is fixed by whether poposkInput is present: the DER of
  // poposkInput when it is, the DER of certReq when it is not (RFC 4211 sec. 4.1, and the ASN.1
  // module on p.33 -- sec. 4.1's case-3 prose says "certificate template" where the field
  // definition and the module both say certReq).
  //
  // The three conformance rules that decide which of those is legitimate are enforced ONE layer
  // down, at parse: poposkInput MUST be omitted exactly when the template carries both subject and
  // publicKey, and poposkInput.publicKey MUST equal the template's (schema-crmf.js, the CertReqMsg
  // build). A message breaking either never reaches this function, and re-checking here would add
  // a branch no input can take while implying the parser might let one through.
  var pin = popo.poposkInput;
  var preimage = pin ? pin.signedBytes : msg.certReq.certReqBytes;
  // The key possession is proven for is the one inside the preimage. With poposkInput that is its
  // own publicKey; sec. 4.1 requires the template to carry the same value, and the parser enforces
  // that whenever the template has one at all. A template that omits it entirely still parses (the
  // equality rule has nothing to compare), so reading the template here would report null for a key
  // whose possession was just proven.
  var spki = pin ? pin.publicKey : base.publicKey;
  // Which fields the verdict may report follows from which bytes were signed. The certReq preimage
  // is the whole CertRequest, so the template's subject rides with it. The poposkInput preimage
  // covers the key and the authInfo sender and never the template, so a subject sitting in the
  // message alongside it is unsigned: reporting it beside `verified: true` would let a CA issue a
  // name the requester proved nothing about. It is withheld, and `subjectBound` says so rather than
  // leaving the absence to look like a request that named no subject.
  var bound = !pin;
  return crmfVerify.verifyPopSignature(popo, spki, preimage).then(function (ok) {
    return _assign({}, base, {
      verified: ok === true, method: "signature", cryptographicallyVerified: ok === true,
      subject: bound ? base.subject : null,
      subjectBound: bound,
      publicKey: spki || null,
      reason: ok === true ? undefined : "the proof-of-possession signature does not verify under the requested public key",
    });
  });
}

/**
 * @primitive pki.crmf.verifyPop
 * @signature pki.crmf.verifyPop(messages) -> Promise<{ verified, messages: [{ verified, method, cryptographicallyVerified, certReqId, subject, subjectBound, publicKey, reason }] }>
 * @since 0.5.14
 * @status stable
 * @spec RFC 4211 sec. 4.1
 * @defends crmf-proof-of-possession-bypass (CWE-347)
 * @related pki.crmf.build, pki.csr.verify, pki.schema.crmf.parse
 *
 * Verify the proof of possession on each `CertReqMsg` in a `CertReqMessages`. `messages` is a DER
 * `Buffer` or a parsed result. A CA or RA that issues without this certifies a key the requester
 * may not hold. One verdict is returned per message, in order, and the top-level `verified` is true
 * only when every message carried a proof that verified.
 *
 * For the `signature` proof the covered bytes are the ones RFC 4211 names: the DER of `poposkInput`
 * when that field is present, and the DER of `certReq` when it is absent. Two conformance rules ride
 * with it, both refusals rather than warnings, because each lets a certificate be issued for
 * something nobody signed: `poposkInput` MUST be omitted exactly when the template carries both
 * subject and public key (its preimage covers the key and the sender, never the subject), and
 * `poposkInput.publicKey` MUST be exactly the template's public key (sec. 4.1). Verification
 * composes the one path-validation signature engine, with the same algorithm-confusion (RFC 9814
 * sec. 4) and EdDSA low-order-point gates.
 *
 * The other proofs are reported, never guessed. `raVerified` is an RA's out-of-band assertion, so it
 * returns `verified: false` with `method: "raVerified"` and a caller who trusts that RA opts in by
 * reading `method`. `keyEncipherment` and `keyAgreement` complete over a later protocol exchange, or
 * need the CA's decryption key, so they return `verified: false` naming the arm.
 *
 * Each verdict carries what the verified preimage covers, so a CA issues from what was checked.
 * `publicKey` is the key possession was proven for. `subject` is the requested name when the
 * preimage was the `certReq`, which covers the whole template; when the preimage was `poposkInput`
 * it covers the key and the sender alone, so any subject in the message is unsigned and is withheld
 * with `subjectBound: false`. Bind the name by other means before issuing in that case.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spki = await pki.key.export(pair.publicKey);
 *   var pkcs8 = await pki.key.export(pair.privateKey);
 *   var req = await pki.crmf.build({ certReqId: 1n,
 *     certTemplate: { subject: "device-42", publicKey: spki } }, { key: pkcs8 });   // a bare string is the commonName VALUE
 *   var r = await pki.crmf.verifyPop(req);
 *   r.verified;                    // true
 *   r.messages[0].method;          // "signature"
 */
function verifyPop(messages) { return guard.async.deferred(function () { return _verifyPop(messages); }); }
function _verifyPop(messages) {
  var parsed = _coerceMessages(messages);
  return Promise.all(_map(parsed.messages, _verifyOne)).then(function (out) {
    return { verified: out.length > 0 && _every(out, function (m) { return m.verified === true; }), messages: out };
  });
}

module.exports = { build: build, buildCertTemplate: buildCertTemplate, verifyPop: verifyPop };
