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
var _checkPrimeSync = nodeCrypto.checkPrimeSync;
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var crmf = require("./schema-crmf");
var signScheme = require("./sign-scheme");
var pkix = require("./schema-pkix");
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
  // allow:nan-date-comparison-unguarded -- both instants passed timeDer's guard.time.assertValid above.
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
  var caSpkiBytes = _x942ToPkcs3(parsedCa.subjectPublicKeyInfo.bytes);
  if (caSpkiBytes === null) {
    caSpkiBytes = parsedCa.subjectPublicKeyInfo.bytes;
    var pkcs3 = _pkcs3Params(caSpkiBytes);
    if (pkcs3 !== null) _assertDhGroup(pkcs3.p, pkcs3.g, pkcs3.y, null, null);
  }
  try { caPub = _createPublicKey({ key: caSpkiBytes, format: "der", type: "spki" }); }
  catch (e) { throw _err("crmf/bad-popo", "the authority certificate does not carry a key this runtime can agree with", e); }
  /** @internal The snapshot of the caller's key is this function's own copy of private material, so it
   * is registered for the wipe below rather than left to the argument boundary, which clears what it
   * was handed and not what this made from it. */
  var keySnapshot = null;
  var zz = null, k = null;
  try {
    /** @internal Inside the cleanup scope, because the import can throw AFTER the snapshot exists: a
     * catch that returned from out here would leave that copy of private material behind. */
    try {
      if (pop.key && typeof pop.key === "object" && pop.key.asymmetricKeyType != null) {
        eePriv = pop.key;
      } else if (guard.bytes.isByteSource(pop.key)) {
        keySnapshot = guard.bytes.snapshotSource(pop.key, CrmfError, "crmf/bad-popo", "the requester's private key");
        eePriv = _createPrivateKey({ key: keySnapshot, format: "der", type: "pkcs8" });
      } else {
        eePriv = _createPrivateKey(pop.key);
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
    var templateSpki = template.spki && (_x942ToPkcs3(template.spki) || template.spki);
    if (!templateSpki || !_b.samePublicKey(eeSpki, templateSpki)) {
      throw _err("crmf/bad-popo", "pop.key is not the private half of certTemplate.publicKey; the authority derives its side of the agreement from the requested key, so a proof made with any other key demonstrates possession of something this request does not ask to have certified (RFC 4211 sec. 4.3)");
    }
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
function _assertDhGroup(p, g, y, q, j) {
  if (p >= _DH_MAX || g >= _DH_MAX || y >= _DH_MAX ||
      (q !== null && q >= _DH_MAX) || (j !== null && j >= _DH_MAX)) {
    throw _err("crmf/bad-popo", "the authority certificate's parameters are larger than any Diffie-Hellman group this toolkit agrees over (" +
      constants.LIMITS.DH_MAX_MODULUS_BYTES + " bytes)");
  }
  if (p <= 2n || g <= 1n || g >= p - 1n) {
    throw _err("crmf/bad-popo", "the authority certificate's parameters are not a Diffie-Hellman group");
  }
  if (y <= 1n || y >= p - 1n) {
    throw _err("crmf/bad-popo", "the authority certificate's Diffie-Hellman public value is outside the group (RFC 2875 sec. 3)");
  }
  /** @internal The cofactor states (p-1)/q, so it is answered for here, after the sizes that bound
   * the multiplication and before the group is measured. */
  if (j !== null && j * q !== p - 1n) {
    throw _err("crmf/bad-popo", "the authority certificate's X9.42 cofactor does not match its own p and q");
  }
  if (!_checkPrimeSync(_bigToBuf(p))) {
    throw _err("crmf/bad-popo", "the authority certificate's Diffie-Hellman modulus is not prime, so the group its parameters describe does not exist");
  }
  /** @internal With no stated subgroup order there is nothing to test y against, so the group itself
   * has to be one whose only small orders the range above already excluded. That is a safe prime:
   * p = 2r+1 with r prime has element orders 1, 2, r and 2r alone, and y = 1 and y = p-1 are the only
   * values of the first two. A prime p is not enough on its own, since p-1 may carry small factors
   * and then an order-3 value sits inside the range and the secret it agrees exposes the requester's
   * private exponent modulo 3. */
  var order;
  if (q === null) {
    order = (p - 1n) / 2n;
    if (!_checkPrimeSync(_bigToBuf(order))) {
      throw _err("crmf/bad-popo", "the authority certificate states no subgroup order and its modulus is not a safe prime, so nothing bounds the order of its public value (RFC 2875 sec. 3)");
    }
  } else {
    if (q <= 1n || (p - 1n) % q !== 0n || _modPow(g, q, p) !== 1n) {
      throw _err("crmf/bad-popo", "the authority certificate's X9.42 domain parameters state a subgroup order its own p and g do not have");
    }
    if (!_checkPrimeSync(_bigToBuf(q))) {
      throw _err("crmf/bad-popo", "the authority certificate's X9.42 domain parameters state a subgroup order that is not prime, so a public value in it need not have that order");
    }
    order = q;
  }
  /** @internal Whichever way the encoding stated it, the order has to be large. Proving it prime
   * makes the order of y exactly that value rather than a divisor of it, which is worth nothing when
   * the value itself is small: 3 is prime and divides p-1 for a great many p, and 7 is a safe prime
   * whose own subgroup has order 3. Either way the secret exposes the requester's private exponent
   * modulo a number small enough to search. The floor is the smallest subgroup order NIST SP 800-56A
   * states for a finite-field group, so every real one clears it. */
  if (order < _DH_MIN_Q) {
    throw _err("crmf/bad-popo", "the authority certificate states a subgroup too small to hide a private exponent (under " +
      constants.LIMITS.DH_MIN_SUBGROUP_BYTES + " bytes)");
  }
  if (q !== null && _modPow(y, q, p) !== 1n) {
    throw _err("crmf/bad-popo", "the authority certificate's Diffie-Hellman public value is not in the subgroup its own domain parameters state, so agreeing with it would expose the requester's private exponent");
  }
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
 * the key is not in that form. DHParameter is SEQUENCE { prime, base, privateValueLength OPTIONAL }
 * (PKCS#3 sec. 9), and it states no subgroup order, so the group it describes is checked without one. */
function _pkcs3Params(spkiBytes) {
  var parts = _spkiParts(spkiBytes);
  if (parts === null || parts.algOid !== O("dhKeyAgreement")) return null;
  var node = parts.node;
  try {
    var prm = asn1.decode(parts.params.bytes);
    if (!_isUniversal(prm, 16) || !prm.children || prm.children.length < 2 || prm.children.length > 3) {
      throw _err("crmf/bad-popo", "the authority certificate's PKCS#3 Diffie-Hellman parameters are not a DHParameter SEQUENCE");
    }
    var pub = asn1.read.bitString(node.children[1]);
    if (!guard.crypto.isOctetAligned(pub)) {
      throw _err("crmf/bad-popo", "the authority certificate's Diffie-Hellman public key BIT STRING must be octet-aligned (0 unused bits)");
    }
    return {
      p: asn1.read.integer(prm.children[0]),
      g: asn1.read.integer(prm.children[1]),
      y: asn1.read.integer(asn1.decode(pub.bytes)),
    };
  } catch (e) {
    if (e instanceof CrmfError) throw e;
    throw _err("crmf/bad-popo", "the authority certificate's PKCS#3 Diffie-Hellman key could not be read", e);
  }
}

/** @internal Whether a decoded node is a universal tag of this number. A container is read for the
 * tag it carries and not for merely having children: a context-specific constructed value holds
 * children too, and converting one would rewrite a key the recipient's own reader refuses into a
 * PKCS#3 key that imports, so the request would carry a public key nothing else can read. */
function _isUniversal(node, tagNumber) {
  return !!node && node.tagClass === "universal" && node.tagNumber === tagNumber;
}

/** @internal ValidationParms is SEQUENCE { seed BIT STRING, pgenCounter INTEGER } (RFC 3279
 * sec. 2.3.3). The conversion drops it, so reading it is the only thing that answers for it: a
 * certificate whose parameters do not hold the two fields is malformed rather than merely carrying
 * something this does not need. */
function _assertValidationParms(node) {
  var kids = node.children;
  if (!_isUniversal(node, 16) || !kids || kids.length !== 2 ||
      !_isUniversal(kids[0], 3) || !_isUniversal(kids[1], 2)) {
    throw _err("crmf/bad-popo", "the authority certificate's X9.42 validationParms is not a seed BIT STRING with a pgenCounter INTEGER");
  }
  asn1.read.bitString(kids[0]);
  asn1.read.integer(kids[1]);
}

/** @internal One past the largest Diffie-Hellman operand this module computes with, built once. */
var _DH_MAX = (function () {
  var v = 1n;
  for (var i = 0; i < constants.LIMITS.DH_MAX_MODULUS_BYTES; i++) v <<= 8n;
  return v;
}());

/** @internal The smallest subgroup order a stated q may name, built the same way. */
var _DH_MIN_Q = (function () {
  var v = 1n;
  for (var i = 1; i < constants.LIMITS.DH_MIN_SUBGROUP_BYTES; i++) v <<= 8n;
  return v;
}());

/** @internal A non-negative BigInt as the big-endian bytes the runtime's primality test reads. */
function _bigToBuf(n) {
  var len = 0, v = n;
  while (v > 0n) { len++; v >>= 8n; }
  if (len === 0) len = 1;
  var buf = intrinsic.bufferAlloc(len);
  v = n;
  for (var i = len - 1; i >= 0; i--) { buf[i] = Number(v & 0xffn); v >>= 8n; }
  return buf;
}

/** @internal b^e mod m by square and multiply. The exponent is a public domain parameter and the
 * base a public key, so no operand here is secret and the loop is not written to hide one. */
function _modPow(base, exp, mod) {
  var result = 1n, b = base % mod, e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

/** @internal An X.509 Diffie-Hellman certificate names dhpublicnumber and carries X9.42
 * DomainParameters (RFC 3279 sec. 2.3.3), where this runtime classifies only the PKCS#3 DHParameter
 * form. The agreement needs p and g, so the key is rewritten into the form the runtime reads.
 * DomainParameters also states q, the order of the subgroup the key is supposed to live in, which
 * the PKCS#3 form cannot carry: it is checked HERE, before the parameter that states it is dropped.
 * Without that check a key outside the subgroup would be agreed with, and the shared secret it
 * produces leaks the private exponent modulo the small order it does have. */
function _x942ToPkcs3(spkiBytes) {
  var parts = _spkiParts(spkiBytes);
  if (parts === null || parts.algOid !== O("dhpublicnumber")) return null;
  var node = parts.node;

  var domain, p, g, q, j = null, y;
  try {
    domain = asn1.decode(parts.params.bytes);
    /** @internal DomainParameters is SEQUENCE { p, g, q, j OPTIONAL, validationParms OPTIONAL }
     * (RFC 3279 sec. 2.3.3). The two optional fields are read to be checked, not skipped: a field
     * this does not read is a field the conversion would drop without anyone having looked at it. */
    if (!_isUniversal(domain, 16) || !domain.children ||
        domain.children.length < 3 || domain.children.length > 5) return null;
    p = asn1.read.integer(domain.children[0]);
    g = asn1.read.integer(domain.children[1]);
    q = asn1.read.integer(domain.children[2]);
    /** @internal j and validationParms are independently optional, so a fourth field is told apart
     * by its tag rather than by its position: an INTEGER is the cofactor and a SEQUENCE is the
     * validation parameters, which may appear with no cofactor before them. */
    if (domain.children.length >= 4) {
      var opt = domain.children[3];
      if (_isUniversal(opt, 2)) {
        j = asn1.read.integer(opt);
        if (domain.children.length === 5) _assertValidationParms(domain.children[4]);
      } else if (_isUniversal(opt, 16)) {
        if (domain.children.length === 5) {
          throw _err("crmf/bad-popo", "the authority certificate's X9.42 domain parameters carry a field after validationParms");
        }
        _assertValidationParms(opt);
      } else {
        throw _err("crmf/bad-popo", "the authority certificate's X9.42 domain parameters carry a fourth field that is neither a cofactor nor validationParms");
      }
    }
    /** @internal The public key BIT STRING holds whole octets. The codec admits a nonzero unused-bit
     * count whose padding bits are zero, which spells one key two ways, and the conversion carries
     * this BIT STRING through unchanged, so the second spelling would be re-emitted rather than
     * normalized. */
    var pub = asn1.read.bitString(node.children[1]);
    if (!guard.crypto.isOctetAligned(pub)) {
      throw _err("crmf/bad-popo", "the authority certificate's Diffie-Hellman public key BIT STRING must be octet-aligned (0 unused bits)");
    }
    y = asn1.read.integer(asn1.decode(pub.bytes));
  } catch (e3) {
    if (e3 instanceof CrmfError) throw e3;
    throw _err("crmf/bad-popo", "the authority certificate's X9.42 Diffie-Hellman key could not be read", e3);
  }
  _assertDhGroup(p, g, y, q, j);
  return intrinsic.bufferFrom(b.sequence([
    b.sequence([b.oid(O("dhKeyAgreement")), b.sequence([b.integer(p), b.integer(g)])]),
    b.raw(node.children[1].bytes),
  ]));
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

function _nameOrAlternative(parsed, nameField, altExtension) {
  var name = parsed[nameField];
  if (name && name.bytes && name.rdns && name.rdns.length > 0) return intrinsic.bufferFrom(name.bytes);
  var exts = parsed.extensions;
  for (var i = 0; exts && i < exts.length; i++) {
    var ext = exts[i];
    if (ext && ext.name === altExtension && ext.value != null) {
      var alt = _b.reqDer(ext.value, "the authority certificate's " + altExtension);
      if (alt.length > 0) return intrinsic.bufferFrom(alt);
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

function _assertEnclosedKeyMatches(privateKeyDer, templateSpki) {
  return Promise.resolve()
    .then(function () { return key.publicFromPrivate(privateKeyDer); })
    .then(function (derivedSpki) {
      var derived = guard.bytes.view(derivedSpki, CrmfError, "crmf/bad-input", "the derived public key");
      var wanted = guard.bytes.view(templateSpki, CrmfError, "crmf/bad-input", "certTemplate.publicKey");
      /** @internal A finite-field key names itself in either encoding here too, and an enclosed key
       * derives its public half in the PKCS#3 form, so a template naming the X9.42 form is brought to
       * the one form rather than read as a different key. */
      wanted = _x942ToPkcs3(wanted) || wanted;
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
 *   agent cannot tell whose key it holds. `pop.contentEncryptionAlgorithm` defaults to `aes-256-cbc`; an
 *   AEAD algorithm is refused, since it would produce an `AuthEnvelopedData` this field cannot carry.
 * - `agreeMAC`, which agrees a secret with the authority and MACs the request under a key derived from it,
 *   so nothing is signed (RFC 4211 sec. 4.3, RFC 2875 sec. 3). `pop.key` is the requester's finite-field
 *   Diffie-Hellman private key and `pop.caCert` is the authority's certificate the requester already holds,
 *   as DER or a PEM `CERTIFICATE` block. `pop.key` must be the private half of `certTemplate.publicKey`,
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
