// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.crmf
 * @nav        Signing
 * @title      Certificate request messages
 * @fullname   CRMF (Certificate Request Message Format, RFC 4211)
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
// Own-key membership through an operation taken at load: it decides which proof-of-possession
// alternative a request carries, and a name reached from the prototype is one the RFC never defined.
var _hasOwn = intrinsic.hasOwn;
var _stringify = intrinsic.stringify;
var cms = require("./schema-cms");
var cmsEncrypt = require("./cms-encrypt");
var key = require("./key");
require("./path-validate");   // side-effect: path-validate injects its signature engine into crmf-verify at load
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
// spec.pop across all four ProofOfPossession arms: `type` picks the arm; `raVerified` and `sender`
// belong to the raVerified / signature arms; the rest to POPOPrivKey (RFC 4211 sec. 4.2, 4.3).
// spec.pop is a CHOICE, so the accepted key set is per ARM rather than a union of all of them. A
// single flat list would accept `{ type: 'keyEncipherment', method: 'subsequentMessage', privateKey,
// recipients, archive: true }`: a caller who believed they were sending the key that way gets a
// message that declares a later exchange instead, with the three fields they supplied read by
// nothing. `type` and `method` are what pick the arm, so they are read first and the rest is checked
// against the arm the caller chose.
var POP_KEYS_BY_ARM = {
  raVerified: { type: 1, raVerified: 1 },
  signature: { type: 1, sender: 1 },
  subsequentMessage: { type: 1, method: 1, subsequentMessage: 1 },
  encryptedKey: {
    type: 1, method: 1, privateKey: 1, identifier: 1, recipients: 1, archive: 1,
    contentEncryptionAlgorithm: 1,
  },
  // The arms that refuse before they read anything else still need a set, so the refusal a caller
  // sees names the method rather than an unknown field alongside it.
  agreeMAC: { type: 1, method: 1 },
  thisMessage: { type: 1, method: 1 },
  dhMAC: { type: 1, method: 1 },
};
var KNOWN_BATCH_KEYS = { messages: 1 };
var KNOWN_TEMPLATE_KEYS = { version: 1, subject: 1, publicKey: 1, validity: 1, extensions: 1, issuer: 1 };
var REVOCATION_TEMPLATE_KEYS = { version: 1, subject: 1, publicKey: 1, validity: 1, extensions: 1, issuer: 1, serialNumber: 1 };
// The controls (RFC 4211 sec. 6) and regInfo (sec. 7) are disjoint AttributeTypeAndValue namespaces:
// regToken/authenticator/oldCertID/protocolEncrKey are controls and utf8Pairs is regInfo, so the object
// form validates each key against its own field's registry (a control name is not a valid regInfo, and
// vice versa). The key name equals the registered OID name; complex values (pkiPublicationInfo, certReq)
// ride the pre-encoded escape hatch. Each entry is the value encoder for that OID.
function _ctlUtf8(v) { return b.utf8(String(v)); }
function _ctlSpki(v) { var k = _b.reqDer(v, "protocolEncrKey (an SPKI DER)"); _b.assertValidSpki(k, "protocolEncrKey"); return b.raw(k); }
var CONTROL_VALUE = { regToken: _ctlUtf8, authenticator: _ctlUtf8, oldCertID: function (v) { return _encodeCertId(v); }, protocolEncrKey: _ctlSpki };
var REGINFO_VALUE = { utf8Pairs: _ctlUtf8 };

// ---- CertTemplate + POP structural encoders (byte-exact inverses of schema-crmf.js) ----

// OptionalValidity [4] IMPLICIT SEQUENCE { notBefore [0] EXPLICIT Time, notAfter [1] EXPLICIT Time } --
// at least one present (RFC 4211 sec. 5). Time is a CHOICE so [0]/[1] are EXPLICIT.
function _encodeOptionalValidity(validity) {
  if (!validity || typeof validity !== "object" || Buffer.isBuffer(validity)) throw _err("crmf/bad-validity", "validity must be an object { notBefore?, notAfter? }");
  var nb = validity.notBefore, na = validity.notAfter;
  if (nb == null && na == null) throw _err("crmf/bad-validity", "validity must contain notBefore or notAfter (RFC 4211 sec. 5)");
  var parts = [];
  // timeDer validates each instant (guard.time.assertValid throws on an Invalid Date) before the
  // inverted-window comparison, so getTime() below cannot be NaN.
  if (nb != null) parts.push(b.explicit(0, _b.timeDer(nb, "validity notBefore")));
  if (na != null) parts.push(b.explicit(1, _b.timeDer(na, "validity notAfter")));
  // allow:nan-date-comparison-unguarded -- both instants passed timeDer's guard.time.assertValid above.
  if (nb != null && na != null && guard.time.instantOf(nb) > guard.time.instantOf(na)) throw _err("crmf/bad-validity", "notBefore must not be after notAfter");
  return b.implicit(4, b.sequence(parts));
}
// CertTemplate ::= SEQUENCE { [0..9] all IMPLICIT OPTIONAL }. A request omits serialNumber [1] / signingAlg
// [2] / issuerUID [7] / subjectUID [8] (CA-assigned or deprecated, RFC 4211 sec. 5), and the builder never
// emits them. Fields are emitted in ascending tag order.
function _encodeCertTemplate(tpl, opts) {
  if (!tpl || typeof tpl !== "object" || Buffer.isBuffer(tpl)) throw _err("crmf/bad-cert-template", "certTemplate must be an object");
  // A request template omits serialNumber (CA-assigned, RFC 4211 sec. 5); a revocation template (CMP rr,
  // RFC 9810 sec. 5.3.9) carries serialNumber [1] to name the certificate to revoke, allowed only then.
  var allowed = (opts && opts.revocation) ? REVOCATION_TEMPLATE_KEYS : KNOWN_TEMPLATE_KEYS;
  guard.identifier.assertKnownKeys(tpl, allowed, _err, "crmf/bad-input", "unknown certTemplate field ");
  var fields = [];
  if (tpl.version != null) {
    if (tpl.version !== 2) throw _err("crmf/bad-version", "certTemplate version MUST be 2 (v3) if supplied (RFC 4211 sec. 5)");
    fields.push(b.implicit(0, b.integer(2n)));                                  // version [0]
  }
  if (tpl.serialNumber != null) fields.push(b.implicit(1, _b.serialInteger(tpl.serialNumber)));   // serialNumber [1] (revocation only)
  // issuer [3] / subject [5] are EXPLICIT: Name is a CHOICE, and X.680 sec. 31.2.7 forces a context tag on
  // a CHOICE to EXPLICIT even under the module's IMPLICIT TAGS default (the [3]/[5] wraps the RDNSequence
  // SEQUENCE, it does not replace its tag). The parser accepts both forms; this is the conformant one.
  if (tpl.issuer != null) fields.push(b.explicit(3, _b.encodeName(tpl.issuer)));    // issuer [3] EXPLICIT
  if (tpl.validity != null) fields.push(_encodeOptionalValidity(tpl.validity));     // validity [4] IMPLICIT
  if (tpl.subject != null) fields.push(b.explicit(5, _b.encodeName(tpl.subject)));  // subject [5] EXPLICIT
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
function _buildAttrTypeAndValues(spec, code, label, valueMap) {
  if (Array.isArray(spec)) {
    if (!spec.length) throw _err(code, label + " must carry at least one entry");
    var seenA = {};
    // Density before the map, which would otherwise skip a hole into b.sequence as a native error.
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

// The two ProofOfPossession arms a key that cannot sign has to use: keyEncipherment [2] and
// keyAgreement [3], each carrying a POPOPrivKey. Both field tags are EXPLICIT, because POPOPrivKey is
// itself a CHOICE and X.680 sec. 31.2.7 forbids implicit tagging of one. The parser states and
// enforces the same rule (schema-crmf.js), so an implicit emission here would disagree with the
// module's own reader.
var POPO_PRIVKEY_TAGS = { keyEncipherment: 2, keyAgreement: 3 };
// SubsequentMessage ::= INTEGER { encrCert (0), challengeResp (1) } (RFC 4211 sec. 4.2).
var SUBSEQUENT_MESSAGE = { encrCert: 0n, challengeResp: 1n };
// The specification deprecates two of the five alternatives in the same breath as defining them:
// thisMessage "has been deprecated in favor of encryptedKey", dhMAC "is deprecated in favor of the
// agreeMAC field" (sec. 4.2), and RFC 9810 sec. 5.2.8.3 restates both as `-- deprecated`. A reader
// still has to accept them, since a peer may send one; a producer choosing to emit one today is
// choosing the superseded encoding, so the builder names the successor instead of emitting it.
var DEPRECATED_POPO_METHOD = { thisMessage: "encryptedKey", dhMAC: "agreeMAC" };

// EncKeyWithID ::= SEQUENCE { privateKey PrivateKeyInfo,
//                             identifier CHOICE { string UTF8String, generalName GeneralName } OPTIONAL }
// (RFC 4211 sec. 4.2.1). `identifier` is marked OPTIONAL in the module and then made mandatory by the
// prose for this use: "This field MUST be present if the purpose is to prove possession of the private
// key." The reason is stated there too. Without it an escrow agent decrypts a key without knowing
// whose it is, so an attacker can wrap someone else's intercepted key in a request of their own and
// then ask for it back. Building a POP is that first purpose, so the caller supplies one.
function _encKeyWithID(privateKeyDer, identifier) {
  var idNode;
  if (typeof identifier === "string") idNode = b.utf8(identifier);
  else idNode = _b.encodeGeneralName(identifier);   // the GeneralName alternative of the CHOICE
  return b.sequence([b.raw(privateKeyDer), idNode]);
}

// POPOPrivKey, the proof an encryption or key-agreement key gives instead of a signature (RFC 4211
// sec. 4.2 / 4.3). A key that cannot sign has no POPOSigningKey available, so without these arms the
// only reachable alternative is raVerified, an RA's assertion and not a proof at all. For a toolkit
// whose signature story is PQC-first that gap lands exactly on ML-KEM enrollment.
//
// `subsequentMessage` carries no cryptography: it declares which follow-up exchange will complete the
// proof, and the completion happens in the enrolling protocol (RFC 9810 sec. 5.2.8.3.2 / .3), not here.
// `encryptedKey` carries the private key itself to the CA, which is why it is gated twice below.
function _buildPopoPrivKey(pop, mode, template) {
  var outerTag = POPO_PRIVKEY_TAGS[mode];
  var method = pop && pop.method;
  if (typeof method !== "string") {
    throw _err("crmf/bad-popo", "a " + mode + " proof of possession requires pop.method ('subsequentMessage' or 'encryptedKey')");
  }
  if (_hasOwn(DEPRECATED_POPO_METHOD, method)) {
    throw _err("crmf/bad-popo", "the " + method + " proof of possession is deprecated by RFC 4211 sec. 4.2 in favor of " +
      DEPRECATED_POPO_METHOD[method] + "; a reader still accepts it, a new message should not carry it");
  }
  // sec. 4.2 lists exactly three methods for an encipherment key (the private key provided, a
  // decrypted challenge, an encrypted certificate) and introduces the MAC alternatives only in
  // sec. 4.3, "for keyAgreement (only)". The parser refuses a MAC arm under keyEncipherment; the
  // builder refuses to produce one, so the two directions agree about the same message.
  if (method === "agreeMAC" && mode === "keyEncipherment") {
    throw _err("crmf/bad-popo", "keyEncipherment proof of possession cannot use the agreeMAC alternative -- " +
      "it is defined for keyAgreement only (RFC 4211 sec. 4.2, sec. 4.3)");
  }
  if (method === "agreeMAC") {
    // Conforming, and not built here. It needs the static Diffie-Hellman shared secret of RFC 2875
    // sec. 3, derived between the requester's private key and a CA certificate the requester already
    // holds, a classical key-agreement primitive this toolkit does not otherwise carry. It is
    // reported, not approximated: verifyPop already names an inbound agreeMAC as unverified, and an
    // emitted one nothing here can check would be worse than none.
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
    // subsequentMessage [1] IMPLICIT SubsequentMessage, inside the EXPLICIT [2]/[3] wrapper.
    return b.explicit(outerTag, b.implicit(1, b.integer(SUBSEQUENT_MESSAGE[which])));
  }
  if (method !== "encryptedKey") {
    throw _err("crmf/bad-popo", "unsupported POPOPrivKey method " + JSON.stringify(method) +
      " (supported: 'subsequentMessage', 'encryptedKey')");
  }
  // encryptedKey is legal under BOTH outer arms, and the asymmetry with agreeMAC above is the
  // specification's own. RFC 4211 sec. 4.3: key-agreement POP "is accomplished by one of four
  // different methods. The first three are identical to those presented above for key encryption
  // keys" -- and the first of sec. 4.2's three is "The private key can be provided to the CA/RA",
  // which is this alternative. Only the fourth, the MAC, is agreement-only. The parser reads
  // encryptedKey under both arms for the same reason, so gating it to keyEncipherment here would put
  // the producer and the reader back into disagreement about one message.
  return _buildEncryptedKeyPop(pop, outerTag, template);
}

// encryptedKey [4] EnvelopedData. RFC 9810 sec. 5.2.8.3.1: "This method SHALL only be used if archival
// of the private key is desired." Nothing in a builder can confirm that intent, so it is an explicit
// opt-in on the raVerified precedent: handing your private key to the CA should take a sentence that
// says so, not a mistyped method name.
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
  // From here the function owns a plaintext copy of the caller's private key, so every exit clears it.
  // The checks below reject a malformed PKCS#8, an empty recipient list, an AEAD algorithm and a
  // template with no key, and each of those throws synchronously: cleanup attached only to the
  // promise would run on none of them, leaving the copy readable exactly on the paths a caller hits
  // by getting the call wrong. `wipe` tolerates the second buffer not existing yet.
  var privateKeyDer = guard.bytes.snapshot(pop.privateKey, CrmfError, "crmf/bad-input", "pop.privateKey");
  var encKeyWithIdDer = null;
  function wipe() { guard.secret.zeroizeAll([privateKeyDer, encKeyWithIdDer], CrmfError, "crmf/bad-input", "the enclosed private key"); }
  try {
    return _encryptedKeyPopBody();
  } catch (e) { wipe(); throw e; }

  function _encryptedKeyPopBody() {
  if (!privateKeyDer.length) throw _err("crmf/bad-input", "pop.privateKey must be the requester's PrivateKeyInfo (PKCS#8) DER");
  // PrivateKeyInfo.version MUST be 0 (sec. 4.2.1). These are caller bytes, so the value is read rather
  // than assumed; a v1 OneAsymmetricKey carries a public key the CA did not ask to be told.
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
  // The field is typed EnvelopedData, so the content-encryption algorithm has to be one that produces
  // one. An AEAD algorithm yields an AuthEnvelopedData (RFC 5083), a different structure this field
  // cannot carry and the parser will not read. It is refused by name, not emitted for a peer to
  // reject. CBC is the default here for that reason, not as a preference between the two.
  var cea = pop.contentEncryptionAlgorithm || "aes-256-cbc";
  if (typeof cea !== "string") throw _err("crmf/bad-input", "pop.contentEncryptionAlgorithm must be an algorithm name");
  var _ceaLc = intrinsic.toLowerCase(cea);   // /gcm|ccm|chacha/i (ASCII algorithm name)
  if (intrinsic.stringIndexOf(_ceaLc, "gcm") !== -1 || intrinsic.stringIndexOf(_ceaLc, "ccm") !== -1 || intrinsic.stringIndexOf(_ceaLc, "chacha") !== -1) {
    throw _err("crmf/bad-popo", "encryptedKey is typed EnvelopedData, and the AEAD algorithm " + cea +
      " produces an AuthEnvelopedData instead (RFC 5083) -- choose a CBC content-encryption algorithm");
  }
  // RFC 4211 sec. 4.2: encryptedKey "contains the encrypted private key MATCHING THE PUBLIC KEY for
  // which the certificate is to be issued". Without this the arm proves nothing it claims to: a
  // requester could ask for a certificate over one key while enclosing an unrelated private key, and
  // the CA would issue on a proof of possession of something it never certified. The signature arm
  // self-verifies before returning for the same reason; this is that check for this arm.
  if (template.spki == null) {
    throw _err("crmf/bad-input", "an encryptedKey proof of possession requires certTemplate.publicKey -- " +
      "the proof is that the enclosed private key is the one being certified (RFC 4211 sec. 4.2)");
  }
  // The second plaintext copy: the EncKeyWithID that carries the key into the message. This arm is
  // the one place in the toolkit that deliberately holds a caller's private key in the clear, so both
  // copies are cleared on every exit. The caller's own buffer stays intact, since it was copied.
  encKeyWithIdDer = _encKeyWithID(privateKeyDer, pop.identifier);
  // Composed, never hand-rolled: the one CMS producer emits the RecipientInfos, and the content type is
  // the id-ct-encKeyWithID sec. 4.2 requires -- the same OID the parser independently checks for.
  return _assertEnclosedKeyMatches(privateKeyDer, template.spki).then(function () {
    // The CMS producer raises its own cms/* faults for a malformed recipient or an algorithm it does
    // not carry. Those are this module's inputs, reached through a composition the caller cannot see,
    // so they are re-raised in this module's namespace with the original kept as the cause -- the
    // same translation the CRMF parser performs where it composes the CMS reader.
    return cmsEncrypt.encrypt(encKeyWithIdDer, recipients, { contentType: "encKeyWithID", contentEncryptionAlgorithm: cea })
      .then(null, function (e) {
        if (e instanceof CrmfError) throw e;
        throw _err("crmf/bad-input", "the encryptedKey proof of possession could not envelope the private key to " +
          "pop.recipients: " + ((e && e.message) || e), e);
      });
  })
    .then(function (contentInfo) {
      // cms.encrypt returns a ContentInfo wrapping the EnvelopedData; the field carries the bare
      // structure. Read back through the shipped walker rather than indexing into our own output, so a
      // change in what encrypt emits is a typed error here and not a malformed message on the wire.
      var inner = _bareEnvelopedData(contentInfo);
      return b.explicit(outerTag, b.implicit(4, inner));
    })
    .then(function (out) { wipe(); return out; }, function (e) { wipe(); throw e; });
  }
}

// Is the private key about to be enclosed the one the template asks to have certified? Derived through
// the toolkit's own key engine, not a second re-implementation, so every algorithm it drives (RSA, EC,
// the Edwards curves, ML-KEM, ML-DSA) answers the same way. Both values are public, so this is an
// ordinary comparison and not a secret one.
// nosemgrep: pki-non-constant-time-secret-compare
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

// The EnvelopedData SEQUENCE inside the ContentInfo cms.encrypt returns, validated on the way out.
// Every fault here comes from re-reading a composition the caller never sees. The codec's decode and
// the CMS walker each raise in their own namespace, so the whole body is translated, not the one call
// that happens to be likeliest. `pki.crmf.build` promises a typed CrmfError, and a promise with an
// exception for the paths nobody expected to take is the shape that makes it untrue exactly once.
function _bareEnvelopedData(contentInfoDer) {
  try {
    var kids = pkix.rootSequenceChildren(asn1.decode(contentInfoDer), 2, 2);
    var wrapper = kids && kids[1];
    if (!wrapper || wrapper.tagClass !== "context" || wrapper.tagNumber !== 0 || !wrapper.children || wrapper.children.length !== 1) {
      throw _err("crmf/bad-popo", "the enveloped private key is not a ContentInfo carrying one [0] EXPLICIT content");
    }
    var env = wrapper.children[0];
    cms.walkEnvelopedData(env);   // typed cms/* on anything that is not a well-formed EnvelopedData
    return b.raw(env.bytes);
  } catch (e) {
    if (e instanceof CrmfError) throw e;
    throw _err("crmf/bad-popo", "the enveloped private key could not be read back as an EnvelopedData: " +
      ((e && e.message) || e), e);
  }
}

// Check spec.pop against the arm the caller selected, never against every arm's fields at once. Every
// opt-in below is a refusal a caller turns off by naming it, so a field that belongs to a different
// arm must not read as one this arm accepted and ignored: the caller believes they asked for
// something the message does not say. An unrecognized arm falls through with only the selector
// fields allowed, so the error names the arm rather than a field beside it.
function _assertPopArmKeys(pop, mode) {
  var arm = _hasOwn(POPO_PRIVKEY_TAGS, mode) ? pop.method : mode;
  var allowed = (typeof arm === "string" && _hasOwn(POP_KEYS_BY_ARM, arm))
    ? POP_KEYS_BY_ARM[arm]
    : { type: 1, method: 1 };
  guard.identifier.assertKnownKeys(pop, allowed, _err, "crmf/bad-input", function (k) {
    return "spec.pop field " + _stringify(k) + " is not read by a " +
      (typeof arm === "string" ? arm : "proof") + " proof of possession";
  });
}

// ProofOfPossession. The signature arm (the default when a key is given): when the template carries both
// subject and publicKey (complete), sign the CertRequest DER and omit poposkInput; otherwise build a
// POPOSigningKeyInput (authInfo sender [0] GeneralName + the requested publicKey), sign its SEQUENCE, and
// carry it as poposkInput [0] (RFC 4211 sec. 4.1). raVerified is emitted only on an explicit opt-in.
function _buildProofOfPossession(pop, certReqDer, template, signingKey, opts) {
  if (pop != null && (typeof pop !== "object" || Buffer.isBuffer(pop))) throw _err("crmf/bad-input", "spec.pop must be an object (e.g. { type: 'signature' } or { type: 'raVerified', raVerified: true })");
  // Every opt-in below is a refusal a caller turns off by naming it, so a misspelled key must not
  // read as an omitted one: `archve: true` silently withholding the archival consent, or `identifer`
  // silently omitting the field RFC 4211 sec. 4.2.1 makes mandatory, would each be a message built
  // on the opposite of what the caller asked for.
  // The arm is resolved BEFORE its fields are checked, because `type` is not the only thing that
  // picks one: a spec that supplies a key and omits `type` selects the signature arm, and checking
  // against an unresolved arm would refuse the `pop.sender` that arm reads.
  var mode = (pop && pop.type) || (signingKey != null ? "signature" : null);
  if (pop != null) _assertPopArmKeys(pop, mode);
  if (mode == null) return null;   // no POP requested and no key -> omit popo (an RA supplies it out of band)
  if (mode === "raVerified") {
    if (!(pop && pop.raVerified === true)) throw _err("crmf/bad-popo", "raVerified must be explicitly opted into (pop: { type: 'raVerified', raVerified: true }) -- a requester does not normally assert it (RFC 4211 sec. 4)");
    return b.implicit(0, b.nullValue());   // raVerified [0] IMPLICIT NULL
  }
  if (_hasOwn(POPO_PRIVKEY_TAGS, mode)) return _buildPopoPrivKey(pop, mode, template);
  if (mode !== "signature") {
    throw _err("crmf/bad-popo", "unsupported proof-of-possession type " + JSON.stringify(mode) +
      " (supported: 'signature', 'raVerified', 'keyEncipherment', 'keyAgreement')");
  }
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
 *   sec. 4.2.1 makes it mandatory whenever the purpose is proving possession -- without it a decrypting
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
  // Every caller-owned argument copied at entry and released when the call settles -- see the note
  // on the same call in x509-sign.
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
    guard.identifier.assertKnownKeys(spec, KNOWN_BATCH_KEYS, _err, "crmf/bad-input", function (k) {
      return "unknown batch-envelope field " + JSON.stringify(k) + " -- a batch spec carries only 'messages'";
    });
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
  function settle(extra) { return Promise.resolve(Object.assign({}, base, extra)); }

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
    return Object.assign({}, base, {
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
  return Promise.all(parsed.messages.map(_verifyOne)).then(function (out) {
    return { verified: out.length > 0 && out.every(function (m) { return m.verified === true; }), messages: out };
  });
}

module.exports = { build: build, buildCertTemplate: buildCertTemplate, verifyPop: verifyPop };
