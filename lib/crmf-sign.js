// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.crmf
 * @nav        Signing
 * @title      Certificate request messages
 * @fullname   CRMF (Certificate Request Message Format, RFC 4211)
 * @intro The RFC 4211 certificate-request-message producing side. `pki.crmf.build` assembles a
 *   `CertReqMessages`: one or more `CertReqMsg`, each a `CertRequest` (a `CertTemplate` of the requested
 *   certificate fields plus optional controls) paired with a proof of possession. The common proof is a
 *   `POPOSigningKey` signature over the `CertRequest`, made with the private half of the key being
 *   certified (the requester proves possession, exactly as a PKCS#10 CSR does). The message drops into a
 *   CMP (RFC 9810) or EST enrollment body. Parsing lives at `pki.schema.crmf.parse`.
 * @spec RFC 4211
 * @card Build a CRMF CertReqMessages with a signature proof of possession.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var crmf = require("./schema-crmf");
var signScheme = require("./sign-scheme");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var _stringify = intrinsic.stringify;
var cms = require("./schema-cms");
var cmsEncrypt = require("./cms-encrypt");
var key = require("./key");
require("./path-validate");
var crmfVerify = require("./crmf-verify");

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
var POP_KEYS_BY_ARM = {
  raVerified: { type: 1, raVerified: 1 },
  signature: { type: 1, sender: 1 },
  subsequentMessage: { type: 1, method: 1, subsequentMessage: 1 },
  encryptedKey: {
    type: 1, method: 1, privateKey: 1, identifier: 1, recipients: 1, archive: 1,
    contentEncryptionAlgorithm: 1,
  },
  agreeMAC: { type: 1, method: 1 },
  thisMessage: { type: 1, method: 1 },
  dhMAC: { type: 1, method: 1 },
};
var KNOWN_BATCH_KEYS = { messages: 1 };
var KNOWN_TEMPLATE_KEYS = { version: 1, subject: 1, publicKey: 1, validity: 1, extensions: 1, issuer: 1 };
var REVOCATION_TEMPLATE_KEYS = { version: 1, subject: 1, publicKey: 1, validity: 1, extensions: 1, issuer: 1, serialNumber: 1 };
function _ctlUtf8(v) { return b.utf8(String(v)); }
function _ctlSpki(v) { var k = _b.reqDer(v, "protocolEncrKey (an SPKI DER)"); _b.assertValidSpki(k, "protocolEncrKey"); return b.raw(k); }
var CONTROL_VALUE = { regToken: _ctlUtf8, authenticator: _ctlUtf8, oldCertID: function (v) { return _encodeCertId(v); }, protocolEncrKey: _ctlSpki };
var REGINFO_VALUE = { utf8Pairs: _ctlUtf8 };


function _encodeOptionalValidity(validity) {
  if (!validity || typeof validity !== "object" || Buffer.isBuffer(validity)) throw _err("crmf/bad-validity", "validity must be an object { notBefore?, notAfter? }");
  var nb = validity.notBefore, na = validity.notAfter;
  if (nb == null && na == null) throw _err("crmf/bad-validity", "validity must contain notBefore or notAfter (RFC 4211 sec. 5)");
  var parts = [];
  if (nb != null) parts.push(b.explicit(0, _b.timeDer(nb, "validity notBefore")));
  if (na != null) parts.push(b.explicit(1, _b.timeDer(na, "validity notAfter")));
  // allow:nan-date-comparison-unguarded -- both instants passed timeDer's guard.time.assertValid above.
  if (nb != null && na != null && guard.time.instantOf(nb) > guard.time.instantOf(na)) throw _err("crmf/bad-validity", "notBefore must not be after notAfter");
  return b.implicit(4, b.sequence(parts));
}
function _encodeCertTemplate(tpl, opts) {
  if (!tpl || typeof tpl !== "object" || Buffer.isBuffer(tpl)) throw _err("crmf/bad-cert-template", "certTemplate must be an object");
  var allowed = (opts && opts.revocation) ? REVOCATION_TEMPLATE_KEYS : KNOWN_TEMPLATE_KEYS;
  guard.identifier.assertKnownKeys(tpl, allowed, _err, "crmf/bad-input", "unknown certTemplate field ");
  var fields = [];
  if (tpl.version != null) {
    if (tpl.version !== 2) throw _err("crmf/bad-version", "certTemplate version MUST be 2 (v3) if supplied (RFC 4211 sec. 5)");
    fields.push(b.implicit(0, b.integer(2n)));
  }
  if (tpl.serialNumber != null) fields.push(b.implicit(1, _b.serialInteger(tpl.serialNumber)));
  if (tpl.issuer != null) fields.push(b.explicit(3, _b.encodeName(tpl.issuer)));
  if (tpl.validity != null) fields.push(_encodeOptionalValidity(tpl.validity));
  if (tpl.subject != null) fields.push(b.explicit(5, _b.encodeName(tpl.subject)));
  var spki = null;
  if (tpl.publicKey != null) {
    spki = _b.reqDer(tpl.publicKey, "certTemplate.publicKey (the SPKI DER of the requested key)");
    _b.assertValidSpki(spki, "certTemplate.publicKey");
    fields.push(b.implicit(6, spki));
  }
  if (tpl.extensions != null) fields.push(b.implicit(9, _b.requestedExtensions(tpl.extensions, spki)));
  return { der: b.sequence(fields), spki: spki, complete: tpl.subject != null && tpl.publicKey != null };
}

function _buildAttrTypeAndValues(spec, code, label, valueMap) {
  if (Array.isArray(spec)) {
    if (!spec.length) throw _err(code, label + " must carry at least one entry");
    var seenA = {};
    return b.sequence(pkiBuild.reqDenseArray(spec, label, _err, code).map(function (e, i) {
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
    return "unknown " + label + " " + JSON.stringify(k) + "; pass a pre-encoded AttributeTypeAndValue DER via the array form for a " + label + " entry outside " + Object.keys(valueMap).join("/");
  });
  Object.keys(spec).forEach(function (k) {
    var enc = valueMap[k];
    var typeOid = O(k);
    if (seen[typeOid]) throw _err(code, "duplicate " + label + " type " + k);
    seen[typeOid] = true;
    out.push(b.sequence([b.oid(typeOid), enc(spec[k])]));
  });
  if (!out.length) throw _err(code, label + " must carry at least one entry");
  return b.sequence(out);
}
function _certReqId(v) {
  if (v == null) return 0n;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw _err("crmf/bad-input", "certReqId number must be a safe integer (pass a BigInt or a string for a larger value)"); return BigInt(v); }
  if (typeof v === "string") { try { return BigInt(v); } catch (e) { throw _err("crmf/bad-input", "certReqId string must be a decimal or 0x-hex integer", e); } }
  throw _err("crmf/bad-input", "certReqId must be a BigInt, a safe integer, or a string");
}
function _encodeCertId(id) {
  if (!id || typeof id !== "object" || id.issuer == null || id.serialNumber == null) throw _err("crmf/bad-input", "oldCertID must be { issuer: GeneralName, serialNumber }");
  return b.sequence([_b.encodeGeneralName(id.issuer), _b.serialInteger(id.serialNumber)]);
}

var POPO_PRIVKEY_TAGS = intrinsic.assign(intrinsic.create(null), { keyEncipherment: 2, keyAgreement: 3 });
var SUBSEQUENT_MESSAGE = { encrCert: 0n, challengeResp: 1n };
var DEPRECATED_POPO_METHOD = intrinsic.assign(intrinsic.create(null), { thisMessage: "encryptedKey", dhMAC: "agreeMAC" });

function _encKeyWithID(privateKeyDer, identifier) {
  var idNode;
  if (typeof identifier === "string") idNode = b.utf8(identifier);
  else idNode = _b.encodeGeneralName(identifier);
  return b.sequence([b.raw(privateKeyDer), idNode]);
}

function _buildPopoPrivKey(pop, mode, template) {
  var outerTag = POPO_PRIVKEY_TAGS[guard.text.keyOf(mode)];
  var method = pop && pop.method;
  if (typeof method !== "string") {
    throw _err("crmf/bad-popo", "a " + mode + " proof of possession requires pop.method ('subsequentMessage' or 'encryptedKey')");
  }
  if (_hasOwn(DEPRECATED_POPO_METHOD, guard.text.keyOf(method))) {
    throw _err("crmf/bad-popo", "the " + method + " proof of possession is deprecated by RFC 4211 sec. 4.2 in favor of " +
      DEPRECATED_POPO_METHOD[method] + "; a reader still accepts it, a new message should not carry it");
  }
  if (method === "agreeMAC" && mode === "keyEncipherment") {
    throw _err("crmf/bad-popo", "keyEncipherment proof of possession cannot use the agreeMAC alternative -- " +
      "it is defined for keyAgreement only (RFC 4211 sec. 4.2, sec. 4.3)");
  }
  if (method === "agreeMAC") {
    throw _err("crmf/unsupported-popo", "the agreeMAC proof of possession is not built by this toolkit: it requires " +
      "the RFC 2875 static Diffie-Hellman shared secret between the requester's key and a CA certificate it " +
      "already holds. Use 'subsequentMessage' (encrCert or challengeResp), which every key type can produce");
  }
  if (method === "subsequentMessage") {
    var which = pop.subsequentMessage;
    if (typeof which !== "string" || !_hasOwn(SUBSEQUENT_MESSAGE, which)) {
      throw _err("crmf/bad-popo", "pop.subsequentMessage must be 'encrCert' or 'challengeResp' -- " +
        "SubsequentMessage ::= INTEGER { encrCert (0), challengeResp (1) } has no other value (RFC 4211 sec. 4.2)");
    }
    return b.explicit(outerTag, b.implicit(1, b.integer(SUBSEQUENT_MESSAGE[which])));
  }
  if (method !== "encryptedKey") {
    throw _err("crmf/bad-popo", "unsupported POPOPrivKey method " + guard.text.showValue(method) +
      " (supported: 'subsequentMessage', 'encryptedKey')");
  }
  return _buildEncryptedKeyPop(pop, outerTag, template);
}

function _buildEncryptedKeyPop(pop, outerTag, template) {
  if (pop.archive !== true) {
    throw _err("crmf/bad-popo", "an encryptedKey proof of possession sends the requester's private key to the CA, " +
      "and RFC 9810 sec. 5.2.8.3.1 permits it only where archival is intended -- opt in with pop.archive: true");
  }
  if (pop.identifier == null) {
    throw _err("crmf/bad-popo", "an encryptedKey proof of possession requires pop.identifier (a string or a GeneralName): " +
      "RFC 4211 sec. 4.2.1 makes EncKeyWithID.identifier mandatory when the purpose is proving possession, so a " +
      "decrypting agent knows whose key it holds");
  }
  var privateKeyDer = guard.bytes.snapshot(pop.privateKey, CrmfError, "crmf/bad-input", "pop.privateKey");
  var encKeyWithIdDer = null;
  function wipe() { guard.secret.zeroizeAll([privateKeyDer, encKeyWithIdDer], CrmfError, "crmf/bad-input", "the enclosed private key"); }
  try {
    return _encryptedKeyPopBody();
  } catch (e) { wipe(); throw e; }

  function _encryptedKeyPopBody() {
  if (!privateKeyDer.length) throw _err("crmf/bad-input", "pop.privateKey must be the requester's PrivateKeyInfo (PKCS#8) DER");
  var pkiKids, pkiVersion;
  try { pkiKids = pkix.rootSequenceChildren(asn1.decode(privateKeyDer), 3); }
  catch (e) { throw _err("crmf/bad-input", "pop.privateKey must be a PrivateKeyInfo (PKCS#8) SEQUENCE", e); }
  if (!pkiKids) throw _err("crmf/bad-input", "pop.privateKey must be a PrivateKeyInfo (PKCS#8) SEQUENCE of at least three fields");
  try { pkiVersion = asn1.read.integer(pkiKids[0]); }
  catch (e) { throw _err("crmf/bad-input", "PrivateKeyInfo.version must be an INTEGER (RFC 4211 sec. 4.2.1)", e); }
  if (pkiVersion !== 0n) {
    throw _err("crmf/bad-input", "EncKeyWithID.privateKey must be a PrivateKeyInfo with version 0, got " + pkiVersion + " (RFC 4211 sec. 4.2.1)");
  }
  var recipients = pop.recipients;
  if (!intrinsic.isArray(recipients) || recipients.length === 0) {
    throw _err("crmf/bad-input", "an encryptedKey proof of possession requires pop.recipients (the CA or archive agents to envelope the key to)");
  }
  var cea = pop.contentEncryptionAlgorithm || "aes-256-cbc";
  if (typeof cea !== "string") throw _err("crmf/bad-input", "pop.contentEncryptionAlgorithm must be an algorithm name");
  var _ceaLc = intrinsic.toLowerCase(cea);
  if (intrinsic.stringIndexOf(_ceaLc, "gcm") !== -1 || intrinsic.stringIndexOf(_ceaLc, "ccm") !== -1 || intrinsic.stringIndexOf(_ceaLc, "chacha") !== -1) {
    throw _err("crmf/bad-popo", "encryptedKey is typed EnvelopedData, and the AEAD algorithm " + cea +
      " produces an AuthEnvelopedData instead (RFC 5083) -- choose a CBC content-encryption algorithm");
  }
  if (template.spki == null) {
    throw _err("crmf/bad-input", "an encryptedKey proof of possession requires certTemplate.publicKey -- " +
      "the proof is that the enclosed private key is the one being certified (RFC 4211 sec. 4.2)");
  }
  encKeyWithIdDer = _encKeyWithID(privateKeyDer, pop.identifier);
  return _assertEnclosedKeyMatches(privateKeyDer, template.spki).then(function () {
    return cmsEncrypt.encrypt(encKeyWithIdDer, recipients, { contentType: "encKeyWithID", contentEncryptionAlgorithm: cea })
      .then(null, function (e) {
        if (e instanceof CrmfError) throw e;
        throw _err("crmf/bad-input", "the encryptedKey proof of possession could not envelope the private key to " +
          "pop.recipients: " + ((e && e.message) || e), e);
      });
  })
    .then(function (contentInfo) {
      var inner = _bareEnvelopedData(contentInfo);
      return b.explicit(outerTag, b.implicit(4, inner));
    })
    .then(function (out) { wipe(); return out; }, function (e) { wipe(); throw e; });
  }
}

function _assertEnclosedKeyMatches(privateKeyDer, templateSpki) {
  return Promise.resolve()
    .then(function () { return key.publicFromPrivate(privateKeyDer); })
    .then(function (derivedSpki) {
      var derived = guard.bytes.view(derivedSpki, CrmfError, "crmf/bad-input", "the derived public key");
      var wanted = guard.bytes.view(templateSpki, CrmfError, "crmf/bad-input", "certTemplate.publicKey");
      if (!_b.samePublicKey(derived, wanted)) {
        throw _err("crmf/bad-popo", "the private key enclosed in the encryptedKey proof of possession is not the " +
          "private half of certTemplate.publicKey, so it proves possession of a key this request does not ask to " +
          "have certified (RFC 4211 sec. 4.2)");
      }
    }, function (e) {
      if (e instanceof CrmfError) throw e;
      throw _err("crmf/bad-input", "pop.privateKey could not be read as a private key to check against " +
        "certTemplate.publicKey: " + ((e && e.message) || e), e);
    });
}

function _bareEnvelopedData(contentInfoDer) {
  try {
    var kids = pkix.rootSequenceChildren(asn1.decode(contentInfoDer), 2, 2);
    var wrapper = kids && kids[1];
    if (!wrapper || wrapper.tagClass !== "context" || wrapper.tagNumber !== 0 || !wrapper.children || wrapper.children.length !== 1) {
      throw _err("crmf/bad-popo", "the enveloped private key is not a ContentInfo carrying one [0] EXPLICIT content");
    }
    var env = wrapper.children[0];
    cms.walkEnvelopedData(env);
    return b.raw(env.bytes);
  } catch (e) {
    if (e instanceof CrmfError) throw e;
    throw _err("crmf/bad-popo", "the enveloped private key could not be read back as an EnvelopedData: " +
      ((e && e.message) || e), e);
  }
}

function _assertPopArmKeys(pop, mode) {
  var arm = _hasOwn(POPO_PRIVKEY_TAGS, guard.text.keyOf(mode)) ? pop.method : mode;
  var allowed = (typeof arm === "string" && _hasOwn(POP_KEYS_BY_ARM, arm))
    ? POP_KEYS_BY_ARM[arm]
    : { type: 1, method: 1 };
  guard.identifier.assertKnownKeys(pop, allowed, _err, "crmf/bad-input", function (k) {
    return "spec.pop field " + _stringify(k) + " is not read by a " +
      (typeof arm === "string" ? arm : "proof") + " proof of possession";
  });
}

function _buildProofOfPossession(pop, certReqDer, template, signingKey, opts) {
  if (pop != null && (typeof pop !== "object" || Buffer.isBuffer(pop))) throw _err("crmf/bad-input", "spec.pop must be an object (e.g. { type: 'signature' } or { type: 'raVerified', raVerified: true })");
  var mode = (pop && pop.type) || (signingKey != null ? "signature" : null);
  if (pop != null) _assertPopArmKeys(pop, mode);
  if (mode == null) return null;
  if (mode === "raVerified") {
    if (!(pop && pop.raVerified === true)) throw _err("crmf/bad-popo", "raVerified must be explicitly opted into (pop: { type: 'raVerified', raVerified: true }) -- a requester does not normally assert it (RFC 4211 sec. 4)");
    return b.implicit(0, b.nullValue());
  }
  if (_hasOwn(POPO_PRIVKEY_TAGS, guard.text.keyOf(mode))) return _buildPopoPrivKey(pop, mode, template);
  if (mode !== "signature") {
    throw _err("crmf/bad-popo", "unsupported proof-of-possession type " + guard.text.showValue(mode) +
      " (supported: 'signature', 'raVerified', 'keyEncipherment', 'keyAgreement')");
  }
  if (signingKey == null) throw _err("crmf/bad-input", "a signature proof of possession requires the requester's private key");
  if (template.spki == null) throw _err("crmf/bad-input", "a signature proof of possession requires certTemplate.publicKey");
  var scheme = signScheme.resolveSignScheme(_b.certLikeFromSpki(template.spki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);
  var signedRegion, poposkInputField = null;
  if (template.complete) {
    signedRegion = certReqDer;
  } else {
    var sender = pop && pop.sender;
    if (sender == null) throw _err("crmf/bad-popo", "an incomplete template (missing subject or publicKey) requires pop.sender (a GeneralName) for the POPOSigningKeyInput authInfo (RFC 4211 sec. 4.1)");
    var poposkSeq = b.sequence([b.explicit(0, _b.encodeGeneralName(sender)), b.raw(template.spki)]);
    signedRegion = poposkSeq;
    poposkInputField = b.implicit(0, poposkSeq);
  }
  return signScheme.signOverTbs(scheme, signingKey, signedRegion, _signE).then(function (sig) {
    return Promise.resolve(_b.assertSignatureVerifies(signedRegion, sig, template.spki, scheme)).then(function () {
      var popoChildren = [];
      if (poposkInputField) popoChildren.push(poposkInputField);
      popoChildren.push(scheme.sigAlgId);
      popoChildren.push(b.bitString(sig, 0));
      return b.implicit(1, b.sequence(popoChildren));
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
 * REQUESTER's private key, the private half of `certTemplate.publicKey`; the message carries a
 * `POPOSigningKey` proof of possession signed with it (verified before the message is returned), exactly
 * as a PKCS#10 CSR proves possession. The signature algorithm is resolved from the requested public key
 * (RSA PKCS#1 v1.5 / PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm). `key` is optional: omit it
 * for a `raVerified` proof (opt in with `pop: { type: 'raVerified', raVerified: true }`). Returns DER, or a
 * PEM block with `opts.pem` (the label is required). Malformed input throws a typed `CrmfError`.
 * Certificate-request-message parsing is `pki.schema.crmf.parse`.
 *
 * A key that cannot sign proves possession another way (RFC 4211 sec. 4.2, 4.3), which is the case an
 * ML-KEM enrollment is in. Set `pop.type` to `keyEncipherment` or `keyAgreement` and pick a `pop.method`:
 *
 * - `subsequentMessage` with `pop.subsequentMessage` of `encrCert` or `challengeResp`. The proof completes
 *   over the enrolling protocol's next exchange (RFC 9810 sec. 5.2.8.3.2 / .3), so this message only
 *   declares which one. No key material leaves the requester, and every key type can produce it.
 * - `encryptedKey`, which sends the requester's private key to the CA inside a CMS `EnvelopedData` whose
 *   content type is `id-ct-encKeyWithID`. RFC 9810 sec. 5.2.8.3.1 permits it only where archival is
 *   intended, so it takes `pop.archive: true`; `pop.privateKey` is the PKCS#8 DER, `pop.recipients` the CMS
 *   recipients to envelope it to, and `pop.identifier` (a string or GeneralName) is required, because
 *   sec. 4.2.1 makes it mandatory whenever the purpose is proving possession: without it a decrypting
 *   agent cannot tell whose key it holds. `pop.contentEncryptionAlgorithm` defaults to `aes-256-cbc`; an
 *   AEAD algorithm is refused, since it would produce an `AuthEnvelopedData` this field cannot carry.
 *
 * The two alternatives the specification deprecates in the same breath as defining them, `thisMessage` and
 * `dhMAC`, are refused with their successors named; `pki.schema.crmf.parse` still reads both, since a peer
 * may send one. `agreeMAC` is not built: it needs the RFC 2875 static Diffie-Hellman shared secret between
 * the requester's key and a CA certificate it already holds. Building an `encryptedKey` or `agreeMAC` proof
 * inside `pki.cmp.build` raises the announced protocol version to cmp2021(3), which RFC 9810 sec. 5.2.8.3
 * requires.
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
  return guard.bytes.fixedCall(CrmfError, "crmf/bad-input", [
    [spec, "the certificate-request-message spec"], [key, "the signing key"], [opts, "pki.crmf.build options"],
  ], _build);
}

function _buildCertReqMsg(spec, key, opts) {
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("crmf/bad-input", "each certificate-request-message spec must be an object");
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, _err, "crmf/bad-input", "unknown spec field ");
  if (spec.certTemplate == null) throw _err("crmf/bad-input", "spec.certTemplate is required");

  var signingKey = (key && typeof key === "object" && !Buffer.isBuffer(key) && !(key instanceof Uint8Array) && key.type == null && "key" in key) ? key.key : key;
  var template = _encodeCertTemplate(spec.certTemplate);
  var certReqChildren = [b.integer(_certReqId(spec.certReqId)), template.der];
  if (spec.controls != null) certReqChildren.push(_buildAttrTypeAndValues(spec.controls, "crmf/bad-controls", "controls", CONTROL_VALUE));
  var certReqDer = b.sequence(certReqChildren);

  return Promise.resolve(_buildProofOfPossession(spec.pop, certReqDer, template, signingKey, opts)).then(function (popoDer) {
    var msgChildren = [certReqDer];
    if (popoDer) msgChildren.push(popoDer);
    if (spec.regInfo != null) msgChildren.push(_buildAttrTypeAndValues(spec.regInfo, "crmf/bad-reg-info", "regInfo", REGINFO_VALUE));
    return b.sequence(msgChildren);
  });
}

function _build(spec, key, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("crmf/bad-input", "the certificate-request-message spec must be an object");
  var specs;
  if (spec.messages != null) {
    if (!Array.isArray(spec.messages)) throw _err("crmf/bad-input", "spec.messages must be an array of certificate-request-message specs");
    guard.identifier.assertKnownKeys(spec, KNOWN_BATCH_KEYS, _err, "crmf/bad-input", function (k) {
      return "unknown batch-envelope field " + JSON.stringify(k) + " -- a batch spec carries only 'messages'";
    });
    specs = spec.messages;
  } else {
    specs = [spec];
  }
  if (!specs.length) throw _err("crmf/bad-input", "at least one certificate request message is required (RFC 4211 sec. 3)");
  return Promise.all(specs.map(function (s) { return _buildCertReqMsg(s, key, opts); })).then(function (msgs) {
    var der = b.sequence(msgs);
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

function _verifyOne(msg) {
  var t = msg.certReq && msg.certReq.certTemplate;
  var base = {
    certReqId: msg.certReq && msg.certReq.certReqId,
    subject: (t && t.subject) || null,
    subjectBound: false,
    publicKey: (t && t.publicKey && t.publicKey.bytes) || null,
  };
  function settle(extra) {
    var v = guard.verdict.of(base, extra);
    return Promise.resolve(guard.verdict.of(v, { valid: v.verified === true }));
  }

  var popo = msg.popo;
  if (popo == null) {
    return settle({ verified: false, method: null, cryptographicallyVerified: false,
      reason: "the request carries no proof of possession" });
  }
  if (popo.type === "raVerified") {
    return settle({ verified: false, method: "raVerified", cryptographicallyVerified: false,
      reason: "raVerified asserts the RA checked possession out of band -- this is not a proof and cannot be verified from the message" });
  }
  if (popo.type !== "signature") {
    return settle({ verified: false, method: popo.type, cryptographicallyVerified: false,
      reason: "a " + popo.type + " proof of possession completes over an exchange this verifier does not hold (RFC 4211 sec. 4.2, 4.3)" });
  }

  var pin = popo.poposkInput;
  var preimage = pin ? pin.signedBytes : msg.certReq.certReqBytes;
  var spki = pin ? pin.publicKey : base.publicKey;
  var bound = !pin;
  return crmfVerify.verifyPopSignature(popo, spki, preimage).then(function (ok) {
    return guard.verdict.of(base, {
      valid: ok === true, verified: ok === true, method: "signature", cryptographicallyVerified: ok === true,
      subject: bound ? base.subject : null,
      subjectBound: bound,
      publicKey: spki || null,
      reason: ok === true ? undefined : "the proof-of-possession signature does not verify under the requested public key",
    });
  });
}

/**
 * @primitive pki.crmf.verifyPop
 * @signature pki.crmf.verifyPop(messages) -> Promise<{ valid, verified, messages: [{ valid, verified, method, cryptographicallyVerified, certReqId, subject, subjectBound, publicKey, reason }] }>
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
  return Promise.all(parsed.messages.map(_verifyOne)).then(function (out) {
    var allVerified = out.length > 0 && out.every(function (m) { return m.verified === true; });
    return { valid: allVerified, verified: allVerified, messages: out };
  });
}

module.exports = { build: build, buildCertTemplate: buildCertTemplate, verifyPop: verifyPop };
