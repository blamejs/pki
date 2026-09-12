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

var nodeCrypto = require("node:crypto");
/** @internal Bound at module load, like every other capture here: the proof below decides what it
 * agrees and what it hashes, so a replacement swapped in afterwards must not be able to steer it. */
var _createHash = nodeCrypto.createHash;
var _createHmac = nodeCrypto.createHmac;
var _diffieHellman = nodeCrypto.diffieHellman;
var _createPublicKey = nodeCrypto.createPublicKey;
var _createPrivateKey = nodeCrypto.createPrivateKey;
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var crmf = require("./schema-crmf");
var signScheme = require("./sign-scheme");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
var pkiBuild = require("./pki-build");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var constants = require("./constants");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var _isBuffer = intrinsic.isBuffer;
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

var KNOWN_SPEC_KEYS = intrinsic.assign(intrinsic.create(null), { certReqId: 1, certTemplate: 1, controls: 1, regInfo: 1, pop: 1 });
var POP_KEYS_BY_ARM = intrinsic.assign(intrinsic.create(null), {
  raVerified: { type: 1, raVerified: 1 },
  signature: { type: 1, sender: 1 },
  subsequentMessage: { type: 1, method: 1, subsequentMessage: 1 },
  encryptedKey: {
    type: 1, method: 1, privateKey: 1, identifier: 1, recipients: 1, archive: 1,
    contentEncryptionAlgorithm: 1,
  },
  agreeMAC: { type: 1, method: 1, key: 1, caCert: 1 },
  thisMessage: { type: 1, method: 1 },
  dhMAC: { type: 1, method: 1 },
});
var KNOWN_BATCH_KEYS = intrinsic.assign(intrinsic.create(null), { messages: 1 });
var KNOWN_TEMPLATE_KEYS = intrinsic.assign(intrinsic.create(null), { version: 1, subject: 1, publicKey: 1, validity: 1, extensions: 1, issuer: 1 });
var REVOCATION_TEMPLATE_KEYS = intrinsic.assign(intrinsic.create(null), { version: 1, subject: 1, publicKey: 1, validity: 1, extensions: 1, issuer: 1, serialNumber: 1 });
function _ctlUtf8(v) { return b.utf8(String(v)); }
function _ctlSpki(v) { var k = _b.reqDer(v, "protocolEncrKey (an SPKI DER)"); _b.assertValidSpki(k, "protocolEncrKey"); return b.raw(k); }
var CONTROL_VALUE = intrinsic.assign(intrinsic.create(null), { regToken: _ctlUtf8, authenticator: _ctlUtf8, oldCertID: function (v) { return _encodeCertId(v); }, protocolEncrKey: _ctlSpki });
var REGINFO_VALUE = intrinsic.assign(intrinsic.create(null), { utf8Pairs: _ctlUtf8 });


function _encodeOptionalValidity(validity) {
  if (!validity || typeof validity !== "object" || _isBuffer(validity)) throw _err("crmf/bad-validity", "validity must be an object { notBefore?, notAfter? }");
  var nb = validity.notBefore, na = validity.notAfter;
  if (nb == null && na == null) throw _err("crmf/bad-validity", "validity must contain notBefore or notAfter (RFC 4211 sec. 5)");
  var parts = [];
  if (nb != null) parts.push(b.explicit(0, _b.timeDer(nb, "validity notBefore")));
  if (na != null) parts.push(b.explicit(1, _b.timeDer(na, "validity notAfter")));
  // allow:nan-date-comparison-unguarded -- both instants passed timeDer's guard.time.assertEncodable above.
  if (nb != null && na != null && guard.time.instantOf(nb) > guard.time.instantOf(na)) throw _err("crmf/bad-validity", "notBefore must not be after notAfter");
  return b.implicit(4, b.sequence(parts));
}
function _encodeCertTemplate(tpl, opts) {
  if (!tpl || typeof tpl !== "object" || _isBuffer(tpl)) throw _err("crmf/bad-cert-template", "certTemplate must be an object");
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
    var seenA = intrinsic.create(null);
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
  var out = [], seen = intrinsic.create(null);
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
var SUBSEQUENT_MESSAGE = intrinsic.assign(intrinsic.create(null), { encrCert: 0n, challengeResp: 1n });
var DEPRECATED_POPO_METHOD = intrinsic.assign(intrinsic.create(null), { thisMessage: "encryptedKey", dhMAC: "agreeMAC" });

function _encKeyWithID(privateKeyDer, identifier) {
  var idNode;
  if (typeof identifier === "string") idNode = b.utf8(identifier);
  else idNode = _b.encodeGeneralName(identifier);
  return b.sequence([b.raw(privateKeyDer), idNode]);
}

/** @internal The digest each static Diffie-Hellman proof algorithm is defined over, keyed by the OID
 * that names it. RFC 2875 sec. 4.4 registers one, `id-dhPop-static-HMAC-SHA1`, and its digest is part
 * of what that OID means: the derivation and the MAC are SHA-1 because the identifier on the wire says
 * so, not because this side chose it. A second algorithm would be a row here, as it is for the CMC
 * challenge's own witness and MAC tables. */
var DH_POP_DIGEST = intrinsic.create(null);
DH_POP_DIGEST[O("id-dhPop-static-HMAC-SHA1")] = "sha1";

/** @internal The RFC 2875 sec. 3 static Diffie-Hellman proof of possession, which RFC 4211 sec. 4.3
 * requires every DH implementation to support. The requester holds a certificate for the authority, and
 * a key on the authority's own group; the secret they agree keys a MAC over the request, so producing
 * it demonstrates possession of the private half without signing anything.
 *
 * The MAC covers the DER `certReq`, which the ASN.1 comment on POPOPrivKey states and the prose does
 * not: "a MAC (over the DER-encoded value of the certReq parameter in CertReqMsg, which must include
 * both subject and publicKey)". The `PKMACValue` field description names the DER-encoded public key
 * instead, and that describes the OTHER place that structure is used, the `publicKeyMAC` of
 * POPOSigningKeyInput. */
function _buildAgreeMac(pop, outerTag, certReqDer, template) {
  /** @internal The POPOPrivKey comment states what the prose does not: the MAC covers a certReq "which
   * must include both subject and publicKey". A request naming neither identifies nothing the proof
   * could be about, so it is refused rather than MACed as it stands. */
  if (!template || !template.complete) {
    throw _err("crmf/bad-popo", "an agreeMAC proof of possession covers a certReq that must include both the subject and the publicKey (RFC 4211 sec. 4.3), and this template names only one of them");
  }
  if (pop.key == null) throw _err("crmf/bad-popo", "an agreeMAC proof of possession needs pop.key, the requester's Diffie-Hellman private key, to agree the secret with the authority (RFC 2875 sec. 3)");
  if (pop.caCert == null) throw _err("crmf/bad-popo", "an agreeMAC proof of possession needs pop.caCert, the authority's certificate the requester already holds, for its Diffie-Hellman public key and its names (RFC 4211 sec. 4.3)");

  var caCertDer;
  try {
    caCertDer = guard.bytes.snapshotSource(pkix.coerceToDer(pop.caCert, {
      pemLabel: "CERTIFICATE", PemError: frameworkError.PemError, ErrorClass: CrmfError, prefix: "crmf",
    }), CrmfError, "crmf/bad-popo", "the authority certificate");
  } catch (e) {
    if (e instanceof CrmfError && e.code === "crmf/bad-popo") throw e;
    throw _err("crmf/bad-popo", "pop.caCert is not a certificate this runtime can read", e);
  }
  var parsedCa;
  try { parsedCa = x509.parse(caCertDer); }
  catch (e) { throw _err("crmf/bad-popo", "pop.caCert is not a well-formed certificate", e); }

  /** @internal RFC 4211 sec. 4.3: "If either the subject or issuer name in the CA certificate is empty,
   * then the alternative name should be used in its place." An empty name with no alternative leaves the
   * derivation with nothing to bind, so it is refused rather than derived from an empty string.
   * Only the subject half is reachable: RFC 5280 sec. 4.1.2.4 requires a non-empty issuer, and the
   * certificate parser pop.caCert passes through enforces it with x509/bad-issuer, so an authority
   * certificate carrying an empty issuer never reaches this derivation. */
  var leading = _nameOrAlternative(parsedCa, "subject", "subjectAltName");
  var trailing = _nameOrAlternative(parsedCa, "issuer", "issuerAltName");

  /** @internal RFC 5280 sec. 4.2.1.3: a keyUsage extension restricts the certified key to the
   * purposes it asserts, and this proof uses the authority's key to agree a secret. A certificate
   * that states its purposes and does not state this one is refused rather than used for it. A
   * certificate carrying no keyUsage asserts no restriction and is left alone. */
  var caKu = pkix.keyUsageOf(NS, parsedCa, _err, "crmf/bad-popo", "authority certificate's");
  if (caKu && caKu.keyAgreement !== true) {
    throw _err("crmf/bad-popo", "the authority certificate's keyUsage does not assert keyAgreement, so its key is not certified for the agreement this proof performs (RFC 5280 sec. 4.2.1.3)");
  }

  var caPub, eePriv;
  /** @internal A finite-field key reaches a certificate in two encodings, and the group is checked
   * whichever one carried it. The X9.42 form is rewritten into the form this runtime classifies, and
   * that rewrite checks the group on the way; the PKCS#3 form needs no rewrite, so it is checked
   * here instead of arriving unexamined because it happened to need no conversion. */
  var caX942 = _x942ToPkcs3(parsedCa.subjectPublicKeyInfo.bytes, "the authority certificate's");
  var caSpkiBytes;
  if (caX942 !== null) {
    _assertDhGroup(caX942.p, caX942.g, caX942.y, caX942.q, caX942.j, true, "the authority certificate's");
    _assertAgreementExponent(caX942, "the authority certificate's key");
    caSpkiBytes = caX942.der;
  } else {
    caSpkiBytes = parsedCa.subjectPublicKeyInfo.bytes;
    var pkcs3 = _pkcs3Params(caSpkiBytes, "the authority certificate's");
    if (pkcs3 !== null) {
      _assertDhGroup(pkcs3.p, pkcs3.g, pkcs3.y, null, null, true, "the authority certificate's");
      _assertAgreementExponent(pkcs3, "the authority certificate's key");
    }
  }
  try { caPub = _createPublicKey({ key: caSpkiBytes, format: "der", type: "spki" }); }
  catch (e) { throw _err("crmf/bad-popo", "the authority certificate does not carry a key this runtime can agree with", e); }
  /** @internal The snapshot of the caller's key is this function's own copy of private material, so it
   * is registered for the wipe below rather than left to the argument boundary, which clears what it
   * was handed and not what this made from it. */
  var keySnapshot = null;
  var translated = null;
  var zz = null, k = null;
  try {
    /** @internal Inside the cleanup scope, because the import can throw AFTER the snapshot exists: a
     * catch that returned from out here would leave that copy of private material behind. */
    try {
      if (pop.key && typeof pop.key === "object" && pop.key.asymmetricKeyType != null) {
        eePriv = pop.key;
      } else if (pop.key && typeof pop.key === "object" && pop.key.type === "private" &&
                 typeof pop.key.export === "function") {
        /** @internal A key object the runtime holds without classifying, which is what it makes of an
         * X9.42 key. It reads its own encoding back, so the same rewrite the serialized forms take
         * applies here: supporting the encoding for a caller holding bytes and refusing the caller
         * holding the key those bytes import to would be the same key admitted one way. The export
         * is this function's own copy of private material and is cleared with the rest. */
        keySnapshot = pop.key.export({ format: "der", type: "pkcs8" });
        translated = _x942PrivToPkcs3(keySnapshot);
        eePriv = translated !== null
          ? _createPrivateKey({ key: translated, format: "der", type: "pkcs8" })
          : pop.key;
      } else if (guard.bytes.isByteSource(pop.key)) {
        keySnapshot = guard.bytes.snapshotSource(pop.key, CrmfError, "crmf/bad-popo", "the requester's private key");
        /** @internal Assigned to the outer name, not a local one: the rewrite is this function's own
         * copy of the private value, and an import that throws after it exists must not leave it
         * behind. The wipe below clears whatever was made, on every way out. */
        translated = _x942PrivToPkcs3(keySnapshot);
        eePriv = _createPrivateKey({ key: translated || keySnapshot, format: "der", type: "pkcs8" });
      } else {
        /** @internal A PEM key reaches the same conversion: it is the same key in the same encoding
         * with an armor around it, so admitting one form and not the other would support X9.42 for a
         * caller holding DER and refuse the caller holding the identical bytes in PEM. */
        var pemDer = _pemPrivateKeyDer(pop.key);
        if (pemDer !== null) {
          keySnapshot = pemDer;
          translated = _x942PrivToPkcs3(keySnapshot);
          eePriv = _createPrivateKey({ key: translated || keySnapshot, format: "der", type: "pkcs8" });
        } else {
          eePriv = _createPrivateKey(pop.key);
        }
      }
    } catch (e) {
      if (e instanceof CrmfError) throw e;
      throw _err("crmf/bad-popo", "pop.key is not a private key this runtime can read", e);
    }
    /** @internal The proof is about the key being certified, so the key that agrees the secret has to
     * be the private half of the one the template asks for. The authority derives its side from the
     * template's public key, so a private key from another pair agrees a secret with the authority
     * perfectly well and produces a MAC the authority cannot reproduce: a proof of possession of
     * something this request never asked to have certified. The encryptedKey arm holds its enclosed
     * key to the same rule. */
    var eeSpki;
    try { eeSpki = _createPublicKey(eePriv).export({ format: "der", type: "spki" }); }
    catch (e) { throw _err("crmf/bad-popo", "the public half of pop.key could not be derived to check it against the requested key", e); }
    /** @internal Compared as keys, not as bytes. A PKCS#3 DHParameter carries an optional
     * privateValueLength, so one finite-field key has more than one valid SubjectPublicKeyInfo and a
     * byte comparison refuses a request that names the very key it was made with. */
    /** @internal The requested key is read in both encodings too. A template naming the key in the
     * X9.42 form and a pop.key holding its PKCS#3 private half are the same key, and comparing the
     * two encodings through the runtime answers false, so the template is brought to the one form
     * before the comparison. Its own subgroup is checked on the way, as the authority's is. */
    /** @internal The requested key is read in both encodings on the same footing. The X9.42 form is
     * brought to the one the runtime classifies, and the PKCS#3 form is read in place so the shape
     * this comparison rests on is checked either way: the request carries the caller's own encoding,
     * so a malformed one it never read would travel under a MAC covering it. */
    /** @internal The requested key is brought to the one encoding so the comparison is about keys,
     * and its shape is read either way. Its p and g are the authority's, which the runtime requires
     * this key to share and which the agreement's own floors already answered for; its q and j are
     * not, since the caller states those here and the conversion drops them. They are held to the
     * key they describe, so the request cannot carry a subgroup order its own key does not have. */
    var templateSpki = template.spki;
    if (templateSpki) {
      var converted = _x942ToPkcs3(templateSpki, "certTemplate.publicKey's");
      if (converted !== null) {
        _assertDhGroup(converted.p, converted.g, converted.y, converted.q, converted.j, false, "certTemplate.publicKey's");
        templateSpki = converted.der;
      } else {
        var tPkcs3 = _pkcs3Params(templateSpki, "certTemplate.publicKey's");
        if (tPkcs3 !== null) _assertDhGroup(tPkcs3.p, tPkcs3.g, tPkcs3.y, null, null, false, "certTemplate.publicKey's");
      }
    }
    if (!templateSpki || !_b.samePublicKey(eeSpki, templateSpki)) {
      throw _err("crmf/bad-popo", "pop.key is not the private half of certTemplate.publicKey; the authority derives its side of the agreement from the requested key, so a proof made with any other key demonstrates possession of something this request does not ask to have certified (RFC 4211 sec. 4.3)");
    }
    /** @internal The exponent this key agrees with has to be one the authority cannot work out.
     * RFC 2631 sec. 2.2 states X9.42's own requirement: "X9.42 requires that the private key x be in
     * the interval [2, (q - 2)]." The three exponents outside it agree a secret that follows from the
     * authority's certificate alone: x = 0 agrees one, x = 1 agrees the authority's public value
     * itself, and x = q-1 agrees the inverse of that value. A MAC keyed from any of them demonstrates
     * possession of nothing, since whoever holds the certificate can compute the same key.
     * The exponent is read off the public value rather than out of the key: g^x is 1, g and g inverse
     * exactly at those three, so the test needs no copy of private material and no stated order.
     * After the comparison above, which the requested key reached only through the size bound its own
     * parameters were held to, so the inversion below runs on a modulus that was measured first. */
    _assertAgreementExponent(_pkcs3Params(eeSpki, "pop.key's"), "pop.key");
    /** @internal Finite-field Diffie-Hellman only. RFC 2875 sec. 3 defines this algorithm over a group
     * with parameters g and p, agreeing `g^xy mod p`. An elliptic-curve or montgomery pair agrees a
     * secret through the same call and would be emitted under the same OID, which names an operation
     * the recipient would not be performing. */
    if (eePriv.asymmetricKeyType !== "dh" || caPub.asymmetricKeyType !== "dh") {
      /** @internal A key this runtime imported but did not classify reports no asymmetricKeyType, which
       * is what an X9.42 dhpublicnumber SubjectPublicKeyInfo does here where the PKCS#3 dhKeyAgreement
       * form is classified. The agreement refuses such a key on its own, so naming the unrecognized
       * side is the whole of the difference between the two messages. */
      throw _err("crmf/bad-popo", "the static Diffie-Hellman proof of possession is defined over a finite-field group (RFC 2875 sec. 3), and " +
        _keyTypeLabel("pop.key", eePriv) + " against " + _keyTypeLabel("the authority certificate's key", caPub));
    }
    /** @internal The agreement's own Buffer, not a copy of it: wrapping it would leave the original
     * holding the secret with nothing to clear it. */
    try { zz = _diffieHellman({ privateKey: eePriv, publicKey: caPub }); }
    catch (e) { throw _err("crmf/bad-popo", "the requester's key and the authority's key did not agree a secret; this proof needs a key on the authority's own parameters (RFC 4211 sec. 4.3)", e); }
    /** @internal K = SHA1(LeadingInfo | ZZ | TrailingInfo) (RFC 2875 sec. 3, step 3c), under the
     * digest the proof's own algorithm identifier names. */
    var popAlgOid = O("id-dhPop-static-HMAC-SHA1");
    var digest = DH_POP_DIGEST[popAlgOid];
    k = _createHash(digest).update(leading).update(zz).update(trailing).digest();
    /** @internal Ordinary HMAC-SHA1. RFC 2875 sec. 3(d) writes the construction correctly and then
     * labels its pads the wrong way round, calling 0x36 the outer pad and 0x5C the inner one, which is
     * the reverse of RFC 2104; the same sentence says the MAC is computed "as per [RFC2104]". */
    var mac = _createHmac(digest, k).update(certReqDer).digest();
    /** @internal The BIT STRING carries the DhPopStatic SEQUENCE, not the raw MAC. RFC 2875 sec. 3
     * says so after the computation: "DhPopStatic is encoded as a BIT STRING and is the signature
     * value (i.e. encodes the above sequence instead of the raw output from 3d)". `issuerAndSerial`
     * names the certificate the public key came from, and is "omitted if the public key did not come
     * from a certificate"; here it always does, since the caller supplies it. */
    var dhPopStatic = b.sequence([
      b.sequence([b.raw(parsedCa.issuer.bytes), b.integer(parsedCa.serialNumber)]),
      b.octetString(mac),
    ]);
    return b.explicit(outerTag, b.implicit(3, b.sequence([
      b.sequence([b.oid(popAlgOid)]),
      b.bitString(dhPopStatic, 0),
    ])));
  } finally {
    var made = [];
    if (zz) guard.list.append(made, zz);
    if (k) guard.list.append(made, k);
    if (keySnapshot) guard.list.append(made, keySnapshot);
    if (translated) guard.list.append(made, translated);
    if (made.length) guard.secret.zeroizeAll(made, CrmfError, "crmf/bad-popo", "the agreed proof-of-possession secret");
  }
}

/** @internal The distinguished name a derivation binds to, or the alternative name when the certificate
 * leaves it empty (RFC 4211 sec. 4.3). A certificate carrying neither cannot key this proof. */
/** @internal The group and the public value a certificate states, checked once for both encodings a
 * finite-field key is written in. q is the subgroup order where the encoding states one and null
 * where it does not, which is the whole difference between the X9.42 and PKCS#3 forms.
 *
 * The sizes come first because every test after them raises one operand to the power of another and
 * proves a modulus prime, and the DER reader admits an INTEGER far wider than any group. The bound
 * is 4096 bits, which covers every MODP group a certificate carries; proving a modulus of that width
 * prime costs about a second, and the width the reader would otherwise allow costs tens of seconds.
 *
 * y is bounded to the group whichever encoding carried it. A value of 1 or p-1 has order 1 or 2, so
 * the secret it agrees exposes the requester's private exponent modulo that order; those are the
 * only small orders a safe prime has, which is what the range test alone answers for. Where q is
 * stated the subgroup test answers for the rest, and it means something only because q is proven
 * prime: y^q = 1 otherwise bounds the order of y to a divisor of q rather than to q. */
/** @internal Whether a public value in this agreement states an exponent the other side could work
 * out. Both halves are held to it: an agreement has two exponents and either one outside the interval
 * makes the secret public, so a rule stated for the requester alone would leave the authority free to
 * carry the same key. Takes the PKCS#3 parameters of a key that agrees, or null when the key is not a
 * finite-field one, in which case there is no exponent of this kind to test.
 * The inverse of g is computed as g^(p-2), which is the inverse when p is prime. Each caller runs the
 * group's own checks first, so p is proven prime and bounded before this exponentiates with it.
 * The excluded values are the ones whose secret follows with NO search: an exponent of 0, 1 or -1
 * agrees one, the other side's public value, and its inverse. A safe prime also has elements of
 * order 2q, and the PKCS#3 form states no order, so such a generator is admitted and its square root
 * of one, p-1, reflects each of those values: the exponent q+1 produces p-g and q-1 produces p minus
 * the inverse of g, and each agrees the negation of a secret that already follows. The reflections
 * are excluded with the values they reflect, since reading the two alone would hold a group with a
 * full-order generator to half the rule.
 * What is excluded is the set the GROUP determines: five values, fixed by p and g, that an exponent
 * lands on without anybody choosing it. An exponent a reader could instead GUESS, whether small like
 * 2 or structured like (q+1)/2, is a different matter and is not tested here. Recognizing one means
 * raising g to that candidate and comparing, so refusing a family of them is a search with a bound,
 * and any bound this picked would refuse keys RFC 2631 sec. 2.2 admits while a reader used the next
 * candidate past it. Whether an exponent is unpredictable is a property of how the key was
 * generated, which no specification asks a request builder to verify and which the public value does
 * not carry. */
function _assertAgreementExponent(parts, what) {
  if (parts === null) return;
  var gInv = _modPow(parts.g, parts.p - 2n, parts.p);
  if (parts.y === 1n || parts.y === parts.g || parts.y === gInv ||
      parts.y === parts.p - parts.g || parts.y === parts.p - gInv) {
    throw _err("crmf/bad-popo", what + " states a private exponent outside the interval [2, q-2] that X9.42 " +
      "requires (RFC 2631 sec. 2.2), so the secret agreed with it follows from values the request and the " +
      "authority certificate already carry, and the proof would demonstrate possession of nothing");
  }
}

/** @internal Whether a stated order and cofactor describe the p and g stated beside them: the key
 * module's tests, a comparison, a multiplication and a modulo, which every path that reads these
 * parameters can afford. The archival arm reads a key without bounding its size, and the tests it
 * leaves to the certifying authority are the ones whose cost grows with it, a modular exponentiation
 * and two primality proofs. */
function _assertDhParamsCoherent(p, g, q, j, what) {
  key.assertDhDomainCoherent(p, g, q, j, CrmfError, "crmf/bad-popo", what);
}

function _assertDhGroup(p, g, y, q, j, forAgreement, what) {
  key.assertDhOperandsWithin([p, g, y, q, j], CrmfError, "crmf/bad-popo", what);
  _assertDhParamsCoherent(p, g, q, j, what);
  /** @internal A PrivateKeyInfo states the group without stating a public value in it, so the two
   * tests that hold a value to these parameters have nothing to run against and the rest still do.
   * The private half's own p and g are the ones its public half is compared against, and that public
   * half is held to the subgroup where it is read. */
  if (y !== null && (y <= 1n || y >= p - 1n)) {
    throw _err("crmf/bad-popo", what + " Diffie-Hellman public value is outside the group (RFC 2875 sec. 3)");
  }
  /** @internal A stated order is held against g before anything is proven prime. Both tests below
   * cost seconds on a large modulus and this one costs a modular exponentiation, so a set of
   * parameters that cannot be a group is turned away at the cheaper of the two. The rest of that
   * question was already answered above, without exponentiating. */
  if (q !== null) key.assertDhGeneratorOrder(p, g, q, CrmfError, "crmf/bad-popo", what);
  key.assertDhModulusPrime(p, CrmfError, "crmf/bad-popo", what);
  /** @internal With no stated subgroup order there is nothing to test y against, so the group itself
   * has to be one whose only small orders the range above already excluded. That is a safe prime:
   * p = 2r+1 with r prime has element orders 1, 2, r and 2r alone, and y = 1 and y = p-1 are the only
   * values of the first two. A prime p is not enough on its own, since p-1 may carry small factors
   * and then an order-3 value sits inside the range and the secret it agrees exposes the requester's
   * private exponent modulo 3. */
  var order;
  if (q === null) {
    /** @internal Nothing was stated, so there is nothing to hold the parameters to; only a key this
     * proof will agree in has to be a group whose orders the range above already bounded. */
    if (!forAgreement) return;
    order = (p - 1n) / 2n;
    if (!_isPrime(order)) {
      throw _err("crmf/bad-popo", what + " parameters state no subgroup order and its modulus is not a safe prime, so nothing bounds the order of its public value (RFC 2875 sec. 3)");
    }
  } else {
    key.assertDhOrderPrime(q, CrmfError, "crmf/bad-popo", what);
    order = q;
    /** @internal The public value has to lie in the subgroup the parameters name. This is what the
     * stated order says about the key, so it is checked wherever the parameters are read and not
     * only where a secret is agreed: a request carries these parameters to whoever reads it next. */
    if (y !== null) key.assertDhValueInSubgroup(p, q, y, CrmfError, "crmf/bad-popo", what);
  }
  /** @internal Everything above answers whether the parameters describe the key they carry, which is
   * asked of any key this reads. What follows is the strength the AGREEMENT needs, and a key being
   * archived rather than agreed with is not held to it. */
  if (!forAgreement) return;
  /** @internal Whichever way the encoding stated it, the order has to be large. Proving it prime
   * makes the order of y exactly that value rather than a divisor of it, which is worth nothing when
   * the value itself is small: 3 is prime and divides p-1 for a great many p, and 7 is a safe prime
   * whose own subgroup has order 3. Either way the secret exposes the requester's private exponent
   * modulo a number small enough to search. The floor is the smallest subgroup order NIST SP 800-56A
   * states for a finite-field group, so every real one clears it. */
  if (order < _DH_MIN_Q) {
    throw _err("crmf/bad-popo", what + " parameters state a subgroup too small to hide a private exponent (under " +
      constants.LIMITS.DH_MIN_SUBGROUP_BYTES + " bytes)");
  }
  /** @internal A large subgroup says the public value is hard to take a discrete log of INSIDE the
   * group; it says nothing about the group itself, which index calculus attacks through the modulus.
   * A 512-bit safe prime has a 255-bit subgroup and clears the floor above while the secret agreed
   * in it is recoverable. The floor is the one the toolkit's own linter names for a public key. */
  if (p < _DH_MIN_P) {
    throw _err("crmf/bad-popo", what + " Diffie-Hellman modulus is under " +
      constants.LIMITS.DH_MIN_MODULUS_BYTES + " bytes, which is too small to agree a secret in");
  }
}

/** @internal The DER inside a PEM PRIVATE KEY block, or null when the value is not one. A caller
 * holding a key in PEM holds the same bytes under an armor, so the conversion below has to see it. */
function _pemPrivateKeyDer(value) {
  if (typeof value !== "string") return null;
  /** @internal The decoder's own buffer is returned rather than a copy of it. Copying would leave
   * the original holding the private key with nothing registered to clear it, which is the shape
   * that puts a second copy of a secret beyond the reach of the wipe. */
  try {
    return pkix.pemDecode(value, "PRIVATE KEY", frameworkError.PemError);
  } catch (_e) { return null; } // allow:swallow-unverified a value that is not a PEM private key is left to the import below to refuse
}

/** @internal A PKCS#8 private key in the X9.42 form, rewritten into the PKCS#3 one this runtime
 * classifies, or null when it is not in that form. PrivateKeyInfo is SEQUENCE { version,
 * privateKeyAlgorithm, privateKey OCTET STRING, attributes [0] OPTIONAL } (RFC 5958), and only the
 * algorithm changes: the private value the OCTET STRING wraps is the same INTEGER either way. The
 * public halves of this key are already read in both encodings, so leaving the private half in one
 * of them would support the encoding for a requester holding somebody else's key and not their own. */
function _x942PrivToPkcs3(pkcs8Bytes) {
  var node;
  try { node = asn1.decode(pkcs8Bytes); } catch (_e) { return null; } // allow:swallow-unverified a key the runtime cannot read is refused by the import this stands before
  if (!_isUniversal(node, 16) || !node.children || node.children.length < 3) return null;
  var alg = node.children[1];
  if (!_isUniversal(alg, 16) || !alg.children || alg.children.length !== 2) return null;
  var algOid;
  try { algOid = asn1.read.oid(alg.children[0]); } catch (_e2) { return null; } // allow:swallow-unverified an algorithm field with no OID is refused by that same import
  if (algOid !== O("dhpublicnumber")) return null;
  var dom;
  try {
    dom = _x942Domain(alg.children[1], "pop.key's");
  } catch (e) {
    if (e instanceof CrmfError) throw e;
    throw _err("crmf/bad-popo", "pop.key states X9.42 domain parameters that could not be read", e);
  }
  /** @internal The order and cofactor this key states are held to the p and g it states them about,
   * for the same reason the requested key's are: the PKCS#3 form carries neither, so this conversion
   * is the last place either is looked at. The floors the agreement needs are not applied twice. This
   * key's p and g are the requested key's, which the comparison below requires it to share and which
   * the agreement already answered for. */
  _assertDhGroup(dom.p, dom.g, null, dom.q, dom.j, false, "pop.key's");
  var fields = [b.raw(node.children[0].bytes),
    b.sequence([b.oid(O("dhKeyAgreement")), b.sequence([b.integer(dom.p), b.integer(dom.g)])]),
    b.raw(node.children[2].bytes)];
  for (var i = 3; i < node.children.length; i++) guard.list.append(fields, b.raw(node.children[i].bytes));
  /** @internal The builder's own buffer, not a copy of it: a copy would leave the rewritten private
   * key behind with nothing registered to clear it. */
  return b.sequence(fields);
}

/** @internal The algorithm and the two fields a SubjectPublicKeyInfo is made of, or null when the
 * bytes are not one. Both finite-field encodings read the same outer shape, so they read it here
 * rather than each carrying a copy of the checks the other already made. */
function _spkiParts(spkiBytes) {
  var node;
  try { node = asn1.decode(spkiBytes); } catch (_e) { return null; } // allow:swallow-unverified both callers hand this DER a reader has already decoded once
  if (!_isUniversal(node, 16) || !node.children || node.children.length !== 2) return null;
  var alg = node.children[0];
  if (!_isUniversal(alg, 16) || !alg.children || alg.children.length !== 2) return null;
  var algOid;
  try { algOid = asn1.read.oid(alg.children[0]); } catch (_e2) { return null; } // allow:swallow-unverified the reader the caller's key passes first refuses an algorithm field with no OID
  return { node: node, algOid: algOid, params: alg.children[1] };
}

/** @internal The p, g and public value of a PKCS#3 dhKeyAgreement SubjectPublicKeyInfo, or null when
 * the key is not in that form: the key module's reader, which is the only thing that looks at these
 * bytes before the request travels under a MAC covering them, with this module's errors. A structure
 * this module's own outer reader does not recognize as a key is not in that form either. */
function _pkcs3Params(spkiBytes, what) {
  var parts = _spkiParts(spkiBytes);
  if (parts === null || parts.algOid !== O("dhKeyAgreement")) return null;
  return key.pkcs3Params(spkiBytes, CrmfError, "crmf/bad-popo", what);
}

/** @internal A container is read for the tag it carries and not for merely having children: a
 * context-specific constructed value holds children too, and converting one would rewrite a key the
 * recipient's own reader refuses into a PKCS#3 key that imports, so the request would carry a public
 * key nothing else can read. The predicate itself is the engine's. */
var _isUniversal = schema.isUniversal;

/** @internal The p, g, q and cofactor an X9.42 DomainParameters states, read by the key module,
 * which owns the structure and the conversion that drops its last three fields; the errors are this
 * module's. Both halves of a finite-field key carry this structure and both take that conversion,
 * so both read it in that one place. */
function _x942Domain(paramsNode, what) {
  return key.x942Domain(paramsNode, CrmfError, "crmf/bad-popo", what);
}

/** @internal Two raised to a count of BITS, so a bound states the width it is named for: a value is
 * at least n bits wide exactly when it is not below 2^(n-1), and at most n bits wide exactly when it
 * is below 2^n. Counting in bytes and shifting by eight per byte lands a whole byte short of that. */
function _pow2(bits) {
  var v = 1n;
  for (var i = 0; i < bits; i++) v <<= 1n;
  return v;
}

/** @internal The smallest modulus a group may be agreed in, and the smallest order a q may name. */
var _DH_MIN_P = _pow2(8 * constants.LIMITS.DH_MIN_MODULUS_BYTES - 1);
var _DH_MIN_Q = _pow2(8 * constants.LIMITS.DH_MIN_SUBGROUP_BYTES - 1);

/** @internal Whether a value is prime: the key module's test, remembered there across calls, since
 * an enrollment run asks the same question of the same group every time. */
var _isPrime = key.isPrime;

/** @internal b^e mod m, the key module's. The exponent is a public domain parameter and the base a
 * public key, so no operand here is secret and the loop is not written to hide one. */
var _modPow = key.modPow;

/** @internal An X.509 Diffie-Hellman certificate names dhpublicnumber and carries X9.42
 * DomainParameters (RFC 3279 sec. 2.3.3), where this runtime classifies only the PKCS#3 DHParameter
 * form. The agreement needs p and g, so the key is rewritten into the form the runtime reads.
 * DomainParameters also states q, the order of the subgroup the key is supposed to live in, which
 * the PKCS#3 form cannot carry: it is checked HERE, before the parameter that states it is dropped.
 * Without that check a key outside the subgroup would be agreed with, and the shared secret it
 * produces leaks the private exponent modulo the small order it does have. */
function _x942ToPkcs3(spkiBytes, what) {
  var parts = _spkiParts(spkiBytes);
  if (parts === null || parts.algOid !== O("dhpublicnumber")) return null;
  var node = parts.node;

  var dom, y;
  try {
    dom = _x942Domain(parts.params, what);
    /** @internal The public key BIT STRING holds whole octets. The codec admits a nonzero unused-bit
     * count whose padding bits are zero, which spells one key two ways, and the conversion carries
     * this BIT STRING through unchanged, so the second spelling would be re-emitted rather than
     * normalized. */
    var pub = asn1.read.bitString(node.children[1]);
    if (!guard.crypto.isOctetAligned(pub)) {
      throw _err("crmf/bad-popo", what + " Diffie-Hellman public key BIT STRING must be octet-aligned (0 unused bits)");
    }
    y = asn1.read.integer(asn1.decode(pub.bytes));
  } catch (e3) {
    if (e3 instanceof CrmfError) throw e3;
    throw _err("crmf/bad-popo", what + " X9.42 Diffie-Hellman key could not be read", e3);
  }
  return {
    p: dom.p, g: dom.g, y: y, q: dom.q, j: dom.j,
    der: intrinsic.bufferFrom(b.sequence([
      b.sequence([b.oid(O("dhKeyAgreement")), b.sequence([b.integer(dom.p), b.integer(dom.g)])]),
      b.raw(node.children[1].bytes),
    ])),
  };
}

/** @internal How a key reads in the refusal above. A key the runtime imported without classifying
 * carries no asymmetricKeyType, and reporting that as a type name says nothing an operator can act on. */
function _keyTypeLabel(what, key) {
  var type = key && key.asymmetricKeyType;
  if (typeof type !== "string" || type === "") {
    return what + " carries an algorithm this runtime does not recognize as a key it can agree with";
  }
  return what + " is " + guard.text.showValue(type);
}

/** @internal Whether a decoded alternative-name extension names anybody. GeneralNames is a SEQUENCE
 * of at least one GeneralName, and a GeneralName is a CHOICE whose every arm carries a
 * context-specific tag from 0 to 8 (RFC 5280 sec. 4.2.1.6). The certificate parser surfaces an
 * extension's bytes without running the decoder registered for it, so a list that is empty, or that
 * holds something no arm of that CHOICE covers, reaches here carrying a length and naming nobody. */
function _namesSomebody(node) {
  if (!_isUniversal(node, 16) || !node.children || node.children.length === 0) return false;
  try { schema.walk(pkix.generalNames(NS, { code: "crmf/bad-popo" }), node, NS); }
  catch (_e) { return false; } // allow:swallow-unverified a list the shared reader refuses names nobody, which the caller's refusal states
  /** @internal The shared reader answers for the SHAPE of every arm, including ediPartyName [5] and
   * the ORAddress opening of x400Address [3]. What remains here is the separate question this
   * derivation asks, which is whether the arm names SOMEBODY rather than whether it is well formed:
   * a Name with no RDNs and an ORAddress whose components are all empty are both conforming and
   * neither identifies a subject. Splitting it this way keeps a naming-strength rule out of a
   * structural reader every other consumer shares. */
  for (var i = 0; i < node.children.length; i++) {
    var arm = node.children[i];
    if (arm.tagNumber === 3 && !_isOrAddress(arm)) return false;
    if (arm.tagNumber === 4 && !_isNonEmptyName(arm)) return false;
  }
  return true;
}

/** @internal Whether a [3] arm is an ORAddress that names somebody. It opens with the
 * BuiltInStandardAttributes SEQUENCE (X.411), so an arm carrying that tag over some other value is
 * not an address. Every field of those attributes is optional, and the domain-defined and extension
 * attributes that may follow carry naming data of their own, so the address names somebody when ANY
 * of its components does: an empty first component is a conforming address when a later one is not.
 * What the components hold is an X.400 structure this does not read, which the derivation can afford
 * because it hashes these bytes rather than interpreting them; what it cannot afford is hashing an
 * address whose every component is empty, which names nobody at all. */
function _isOrAddress(node) {
  var kids = node.children;
  if (!kids || kids.length === 0 || !schema.isUniversal(kids[0], 16)) return false;
  for (var i = 0; i < kids.length; i++) {
    if (kids[i].children && kids[i].children.length > 0) return true;
  }
  return false;
}

/** @internal Whether a [4] arm names a directory entry. Name is a SEQUENCE OF RelativeDistinguished
 * Name and permits none at all, which is the very thing the subject field carried when this fallback
 * was reached: an empty name substituted for an empty name still names nobody. */
function _isNonEmptyName(node) {
  var kids = node.children;
  if (!kids || kids.length !== 1) return false;
  var dn = kids[0];
  return schema.isUniversal(dn, 16) && !!dn.children && dn.children.length > 0;
}


function _nameOrAlternative(parsed, nameField, altExtension) {
  var name = parsed[nameField];
  if (name && name.bytes && name.rdns && name.rdns.length > 0) return intrinsic.bufferFrom(name.bytes);
  var exts = parsed.extensions;
  for (var i = 0; exts && i < exts.length; i++) {
    var ext = exts[i];
    if (ext && ext.name === altExtension && ext.value != null) {
      var alt = _b.reqDer(ext.value, "the authority certificate's " + altExtension);
      /** @internal Read through the GeneralNames schema, not measured. The certificate parser
       * surfaces an extension's bytes without running the decoder registered for it, so a
       * present-but-empty list carries a length while naming nobody, and a SEQUENCE holding
       * something that is not a GeneralName names nobody either. Keying the derivation from bytes
       * like those is the case this refusal exists for. */
      var altNames;
      try { altNames = asn1.decode(alt); } catch (_e) { altNames = null; } // allow:swallow-unverified a list this cannot read names nobody, which the refusal below states
      if (_namesSomebody(altNames)) {
        return intrinsic.bufferFrom(alt);
      }
    }
  }
  throw _err("crmf/bad-popo", "the authority certificate's " + nameField +
    " name is empty and it carries no " + altExtension + " to use in its place (RFC 4211 sec. 4.3)");
}

function _buildPopoPrivKey(pop, mode, template, certReqDer) {
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
  if (method === "agreeMAC") return _buildAgreeMac(pop, outerTag, certReqDer, template);
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

async function _assertEnclosedKeyCorresponds(privateKeyDer, templateSpki) {
  var pair;
  try {
    pair = await key.correspondsTo(privateKeyDer, templateSpki);
  } catch (e) {
    if (e instanceof CrmfError) throw e;
    /** @internal A key the key module cannot read at all is bad input; one it reads and cannot
     * exercise together with the template's key proves possession of nothing, which is the proof
     * failing, not the input. */
    if (e && e.isPkiError === true && e.code === "key/bad-input") {
      throw _err("crmf/bad-input", "pop.privateKey could not be read as a private key to check against " +
        "certTemplate.publicKey: " + (e.message || e), e);
    }
    throw _err("crmf/bad-popo", "the private key enclosed in the encryptedKey proof of possession could not be " +
      "exercised with certTemplate.publicKey, so it cannot be shown to be that key's private half (RFC 4211 sec. 4.2)", e);
  }
  if (pair !== true) {
    throw _err("crmf/bad-popo", "the private key enclosed in the encryptedKey proof of possession is not the " +
      "private half of certTemplate.publicKey, so it proves possession of a key this request does not ask to " +
      "have certified (RFC 4211 sec. 4.2)");
  }
}

function _assertEnclosedKeyMatches(privateKeyDer, templateSpki) {
  /** @internal Which proof the enclosed key takes depends on what its structure can carry. A
   * finite-field PrivateKeyInfo carries the exponent alone, so the public value derived from it IS
   * the proof, and this arm keeps that derivation at any width, with the cheap tests below. Every
   * other family's private structure carries public components of its own (RFC 5958 sec. 2,
   * RFC 5915, PKCS #1), which a caller could set to the template's beside private material that
   * cannot use it, so those are proven by USING the key against the template. */
  var enclosedAlg = key.algorithmOidAt(privateKeyDer, 1);
  if (enclosedAlg !== null && !key.isDhOid(enclosedAlg)) return _assertEnclosedKeyCorresponds(privateKeyDer, templateSpki);
  return Promise.resolve()
    .then(function () { return key.publicFromPrivate(privateKeyDer); })
    .then(function (derivedSpki) {
      var derived = guard.bytes.view(derivedSpki, CrmfError, "crmf/bad-input", "the derived public key");
      var wanted = guard.bytes.view(templateSpki, CrmfError, "crmf/bad-input", "certTemplate.publicKey");
      /** @internal A finite-field key names itself in either encoding here too, and an enclosed key
       * derives its public half in the PKCS#3 form, so a template naming the X9.42 form is brought to
       * the one form rather than read as a different key, and one already in the PKCS#3 form is read
       * where it stands. Both are held to describing the key they carry, since the request travels
       * with them. Neither is held to the floors the AGREEMENT needs: this arm sends a private key to
       * be archived and agrees nothing, so those would refuse a legacy key it exists to enroll. */
      /** @internal Both encodings are read for their SHAPE, so a request does not travel carrying
       * DER nothing checked, and the X9.42 form is brought to the one the runtime classifies so the
       * comparison is about keys. This arm asks one question, which RFC 4211 sec. 4.2 states: is the
       * enclosed key the private half of the requested one. Whether that key sits in a good group is
       * the certifying authority's policy, and answering it here would mean proving a modulus prime,
       * which costs seconds and forces an upper bound on the size, so a key too large to prove would
       * become a key too large to archive.
       * What a stated order and cofactor say about the p and g beside them is a different question,
       * and it is answered: the conversion drops both, the request travels carrying the caller's own
       * encoding of them, and the tests take a multiplication and a modulo rather than the
       * exponentiation and the primality proofs the size bound exists for. */
      var wantedX942 = _x942ToPkcs3(wanted, "certTemplate.publicKey's");
      if (wantedX942 !== null) {
        _assertDhParamsCoherent(wantedX942.p, wantedX942.g, wantedX942.q, wantedX942.j, "certTemplate.publicKey's");
        wanted = wantedX942.der;
      } else _pkcs3Params(wanted, "certTemplate.publicKey's");
      /** @internal Both sides, not one. An enclosed key in the X9.42 form derives its public half in
       * that same form, so converting only the template would compare one encoding against the other
       * and refuse a pair that matches. The order and cofactor this side states are the enclosed
       * private key's own, and they reach the archive with it, so the same conversion drops them under
       * the same tests rather than only where the caller wrote the parameters by hand. */
      var derivedX942 = _x942ToPkcs3(derived, "the enclosed private key's");
      if (derivedX942 !== null) {
        _assertDhParamsCoherent(derivedX942.p, derivedX942.g, derivedX942.q, derivedX942.j, "the enclosed private key's");
        derived = derivedX942.der;
      }
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
  if (pop != null && (typeof pop !== "object" || _isBuffer(pop))) throw _err("crmf/bad-input", "spec.pop must be an object (e.g. { type: 'signature' } or { type: 'raVerified', raVerified: true })");
  var mode = (pop && pop.type) || (signingKey != null ? "signature" : null);
  if (pop != null) _assertPopArmKeys(pop, mode);
  if (mode == null) return null;
  if (mode === "raVerified") {
    if (!(pop && pop.raVerified === true)) throw _err("crmf/bad-popo", "raVerified must be explicitly opted into (pop: { type: 'raVerified', raVerified: true }) -- a requester does not normally assert it (RFC 4211 sec. 4)");
    return b.implicit(0, b.nullValue());
  }
  if (_hasOwn(POPO_PRIVKEY_TAGS, guard.text.keyOf(mode))) return _buildPopoPrivKey(pop, mode, template, certReqDer);
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
 *   agent cannot tell whose key it holds. The enclosed key is proven the private half of
 *   `certTemplate.publicKey` with the key itself (`crmf/bad-popo` when it is not), not by the public
 *   components its structure states. `pop.contentEncryptionAlgorithm` defaults to `aes-256-cbc`; an
 *   AEAD algorithm is refused, since it would produce an `AuthEnvelopedData` this field cannot carry.
 * - `agreeMAC`, which agrees a secret with the authority and MACs the request under a key derived from it,
 *   so nothing is signed (RFC 4211 sec. 4.3, RFC 2875 sec. 3). `pop.key` is the requester's finite-field
 *   Diffie-Hellman private key, as a PKCS#8 DER, a PEM `PRIVATE KEY` block, or a `KeyObject`, and
 *   `pop.caCert` is the authority's certificate the requester already holds, as DER or a PEM
 *   `CERTIFICATE` block. Either key may name its group in the PKCS#3 or the X9.42 encoding.
 *   `pop.key` must be the private half of `certTemplate.publicKey`,
 *   which the authority derives its own side of the agreement from, and the template must name both a
 *   subject and a public key, which the MAC covers. An elliptic-curve or montgomery pair is refused, as is
 *   a key on parameters other than the authority's.
 *
 * The two alternatives the specification deprecates in the same breath as defining them, `thisMessage` and
 * `dhMAC`, are refused with their successors named; `pki.schema.crmf.parse` still reads both, since a peer
 * may send one. Building an `encryptedKey` or `agreeMAC` proof inside `pki.cmp.build` raises the announced
 * protocol version to cmp2021(3), which RFC 9810 sec. 5.2.8.3 requires.
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
  if (!spec || typeof spec !== "object" || _isBuffer(spec)) throw _err("crmf/bad-input", "each certificate-request-message spec must be an object");
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, _err, "crmf/bad-input", "unknown spec field ");
  if (spec.certTemplate == null) throw _err("crmf/bad-input", "spec.certTemplate is required");

  var signingKey = (key && typeof key === "object" && !_isBuffer(key) && !(key instanceof Uint8Array) && key.type == null && "key" in key) ? key.key : key;
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
  if (!spec || typeof spec !== "object" || _isBuffer(spec)) throw _err("crmf/bad-input", "the certificate-request-message spec must be an object");
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
    return guard.verdict.of({ valid: allVerified, verified: allVerified, messages: out });
  });
}

module.exports = { build: build, buildCertTemplate: buildCertTemplate, verifyPop: verifyPop };
