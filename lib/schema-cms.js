// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.cms
 * @nav        Schema
 * @title      CMS
 * @order      160
 * @slug       cms
 *
 * @intro
 *   CMS handling per RFC 5652 (sec. 3 ContentInfo envelope). `parse` turns a DER or PEM
 *   (`CMS`) message into a structured object and is an OID-dispatch envelope --
 *   ContentInfo reads its `contentType` and structurally decodes SignedData (sec. 5),
 *   EnvelopedData (sec. 6, with all five RecipientInfo kinds: key-transport,
 *   key-agreement per RFC 5753, KEK, password, and other, including the RFC 9629
 *   KEMRecipientInfo carried under `id-ori-kem` with ML-KEM per RFC 9936),
 *   EncryptedData (sec. 8), AuthenticatedData (sec. 9), and AuthEnvelopedData (RFC 5083,
 *   with RFC 5084 AES-GCM/CCM parameter validation); the remaining PKCS#7 content
 *   types are recognized and rejected with a precise `cms/unsupported-content-type`
 *   in place of a generic unknown-format error. A SignedData surfaces its version,
 *   digest algorithms, encapsulated content, certificate / CRL sets, and signer
 *   infos; an EnvelopedData its recipient infos and encrypted content info; an
 *   EncryptedData its encrypted content info; an AuthenticatedData its MAC
 *   algorithm, optional digest algorithm, authenticated / unauthenticated
 *   attributes, and raw `mac`; an AuthEnvelopedData its recipient infos, encrypted
 *   content, validated AEAD parameters, and raw `mac`.
 *
 *   CMS is a signed container: the bytes an external verifier must hash are
 *   surfaced raw and never re-serialized. `encapContentInfo.eContent` is the raw
 *   content (or `null` for a detached signature); each SignerInfo's `signature` is
 *   raw, and `signedAttrsBytes` is the on-wire `[0]` SignedAttributes TLV so a
 *   verifier can re-tag it to the universal SET the signature is computed over
 *   (sec. 5.4); `authAttrsBytes` plays the same role for the sec. 9.2 MAC input and the
 *   RFC 5083 sec. 2.2 AAD. Embedded certificates and CRLs are surfaced as raw DER +
 *   their outer tag, validated against the closed CertificateChoices /
 *   RevocationInfoChoice tag sets, so an obsolete alternative never fails the
 *   parse but an out-of-set element does. DER-only, fail-closed.
 *
 * @card
 *   Parse DER / PEM CMS (RFC 5652 / 5083 / 9629) into structured, validated fields
 *   -- signed, enveloped, encrypted, authenticated, and auth-enveloped content;
 *   raw attribute bytes for external verification; certificates/CRLs kept raw,
 *   fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var guard = require("./guard-all");
var oid = require("./oid");
var frameworkError = require("./framework-error");
var schemaX509 = require("./schema-x509");
var schemaCrl = require("./schema-crl");

var CmsError = frameworkError.CmsError;
var PemError = frameworkError.PemError;

var NS = pkix.makeNS("cms", CmsError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var ATTRIBUTE = pkix.attribute(NS);
var NAME = pkix.name(NS);

var SIGNED_DATA_VERSION = pkix.versionReader(NS, { "1": 1, "3": 3, "4": 4, "5": 5 });
var SIGNER_VERSION = pkix.versionReader(NS, { "1": 1, "3": 3 });
var ENVELOPED_DATA_VERSION = pkix.versionReader(NS, { "0": 0, "2": 2, "3": 3, "4": 4 });
var ENCRYPTED_DATA_VERSION = pkix.versionReader(NS, { "0": 0, "2": 2 });
var KTRI_VERSION = pkix.versionReader(NS, { "0": 0, "2": 2 });
var KARI_VERSION = pkix.versionReader(NS, { "3": 3 });
var KEKRI_VERSION = pkix.versionReader(NS, { "4": 4 });
var PWRI_VERSION = pkix.versionReader(NS, { "0": 0 });
var AUTHDATA_VERSION = pkix.versionReader(NS, { "0": 0, "1": 1, "3": 3 });
var COMPRESSED_DATA_VERSION = pkix.versionReader(NS, { "0": 0 });
var AUTHENV_VERSION = pkix.versionReader(NS, { "0": 0 });
var KEMRI_VERSION = pkix.versionReader(NS, { "0": 0 });

var OID_SIGNED_DATA = oid.byName("signedData");
var OID_ENVELOPED_DATA = oid.byName("envelopedData");
var OID_ENCRYPTED_DATA = oid.byName("encryptedData");
var OID_AUTH_DATA = oid.byName("authData");
var OID_AUTH_ENVELOPED_DATA = oid.byName("authEnvelopedData");
var OID_COMPRESSED_DATA = oid.byName("compressedData");
var OID_DATA = oid.byName("data");
var OID_ORI_KEM = oid.byName("kem");

var WRAP_KEK_LENGTHS = {};
WRAP_KEK_LENGTHS[oid.byName("aes128-wrap")] = 16;
WRAP_KEK_LENGTHS[oid.byName("aes192-wrap")] = 24;
WRAP_KEK_LENGTHS[oid.byName("aes256-wrap")] = 32;

var KEM_CT_LENGTHS = {};
["id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024"].forEach(function (n) { KEM_CT_LENGTHS[oid.byName(n)] = oid.kemParams(n).ct; });

var AEAD_GCM_ICVLENS = new Set([12, 13, 14, 15, 16]);
var AEAD_CCM_ICVLENS = new Set([4, 6, 8, 10, 12, 14, 16]);
var AEAD_ALGS = {};
["aes128-GCM", "aes192-GCM", "aes256-GCM"].forEach(function (n) { AEAD_ALGS[oid.byName(n)] = "gcm"; });
["aes128-CCM", "aes192-CCM", "aes256-CCM"].forEach(function (n) { AEAD_ALGS[oid.byName(n)] = "ccm"; });

var DEFERRED = new Set([
  oid.byName("data"), oid.byName("signedAndEnvelopedData"),
  oid.byName("digestedData"),
]);
var OID_CONTENT_TYPE = oid.byName("contentType");
var OID_MESSAGE_DIGEST = oid.byName("messageDigest");
var OID_SIGNING_TIME = oid.byName("signingTime");
var OID_COUNTERSIGNATURE = oid.byName("countersignature");

var ATTR_FORBIDDEN_IN = {};
ATTR_FORBIDDEN_IN[OID_CONTENT_TYPE] = { unsigned: true, unauth: true, unprotected: true };
ATTR_FORBIDDEN_IN[OID_MESSAGE_DIGEST] = { unsigned: true, unauth: true, unprotected: true };
ATTR_FORBIDDEN_IN[OID_SIGNING_TIME] = { unsigned: true, unauth: true, unprotected: true };
ATTR_FORBIDDEN_IN[OID_COUNTERSIGNATURE] = { signed: true, auth: true, unauth: true, unprotected: true };
var ATTR_PLACE_LABELS = {
  signed: "a signed attribute", unsigned: "an unsigned attribute", auth: "an authenticated attribute",
  unauth: "an unauthenticated attribute", unprotected: "an unprotected attribute",
};

function _checkAttrPlacement(attrs, place) {
  for (var i = 0; i < attrs.length; i++) {
    var row = ATTR_FORBIDDEN_IN[attrs[i].type];
    if (row && row[place]) {
      throw NS.E("cms/misplaced-attr", "the " + (oid.name(attrs[i].type) || attrs[i].type) +
        " attribute must not be " + ATTR_PLACE_LABELS[place] + " (RFC 5652 sec. 11)");
    }
  }
}

function _checkContentBindingAttrs(attrs, mode) {
  var ct = 0, md = 0, seen = Object.create(null);
  for (var i = 0; i < attrs.length; i++) {
    var a = attrs[i];
    if (seen[a.type]) {
      if (a.type === OID_CONTENT_TYPE) throw NS.E("cms/duplicate-content-type", "the attribute set must not repeat the content-type attribute");
      if (a.type === OID_MESSAGE_DIGEST) throw NS.E("cms/duplicate-message-digest", "the attribute set must not repeat the message-digest attribute");
      throw NS.E("cms/duplicate-signed-attr", "the attribute set must not include multiple instances of the same attribute type (" + a.type + ")");
    }
    seen[a.type] = true;
    if (a.type === OID_CONTENT_TYPE) {
      ct += 1;
      if (mode === "countersig") throw NS.E("cms/misplaced-attr", "a countersignature's signedAttrs must not carry a content-type attribute (RFC 5652 sec. 11.4)");
      if (a.values.length !== 1) throw NS.E("cms/bad-content-type-attr", "the content-type attribute must be single-valued");
      try { asn1.read.oid(asn1.decode(a.values[0])); }
      catch (e) { throw NS.E("cms/bad-content-type-attr", "the content-type attribute value must be a valid OBJECT IDENTIFIER", e); }
    } else if (a.type === OID_MESSAGE_DIGEST) {
      md += 1;
      if (a.values.length !== 1) throw NS.E("cms/bad-message-digest-attr", "the message-digest attribute must be single-valued");
      try { asn1.read.octetString(asn1.decode(a.values[0])); }
      catch (e) { throw NS.E("cms/bad-message-digest-attr", "the message-digest attribute value must be an OCTET STRING", e); }
    } else if (a.type === OID_SIGNING_TIME) {
      if (a.values.length !== 1) throw NS.E("cms/bad-signing-time-attr", "the signing-time attribute must be single-valued (RFC 5652 sec. 11.3)");
      try { asn1.read.time(asn1.decode(a.values[0])); }
      catch (e) { throw NS.E("cms/bad-signing-time-attr", "the signing-time attribute value must be a Time (RFC 5652 sec. 11.3)", e); }
    }
  }
  if (mode !== "countersig" && ct === 0) throw NS.E("cms/missing-content-type", "the attribute set must contain a content-type attribute (RFC 5652 sec. 11.1)");
  if (md === 0) throw NS.E("cms/missing-message-digest", "the attribute set must contain a message-digest attribute (RFC 5652 sec. 11.2)");
}

function _readsAs(vals, tagNumber, reader) {
  if (vals.length !== 1 || !schema.isUniversal(vals[0], tagNumber)) return false;
  var reads = true;
  try { reader(vals[0]); }
  catch (_e) {
    reads = false;
  }
  return reads;
}
function _readsAsTime(vals) {
  if (vals.length !== 1) return false;
  var reads = true;
  try { asn1.read.time(vals[0]); }
  catch (_e) {
    reads = false;
  }
  return reads;
}

function _ascendingDer(nodes) {
  for (var i = 1; i < nodes.length; i++) {
    if (Buffer.compare(nodes[i - 1].bytes, nodes[i].bytes) > 0) return false;
  }
  return true;
}

function looksLikeSignedAttributes(bytes) {
  if (!bytes || !bytes.length) return false;
  var node;
  try { node = asn1.decode(bytes); }
  catch (_e) { return false; }
  if (!schema.isUniversal(node, asn1.TAGS.SET) || !node.constructed) return false;
  var kids = node.children || [];
  if (!kids.length) return false;
  if (!_ascendingDer(kids)) return false;
  var sawContentType = false, sawMessageDigest = false, seenTypes = Object.create(null);
  for (var i = 0; i < kids.length; i++) {
    var a = kids[i];
    if (!schema.isUniversal(a, asn1.TAGS.SEQUENCE)) return false;
    if (!a.children || a.children.length !== 2) return false;
    var t = a.children[0], vs = a.children[1];
    if (!schema.isUniversal(t, asn1.TAGS.OBJECT_IDENTIFIER)) return false;
    if (!schema.isUniversal(vs, asn1.TAGS.SET)) return false;
    var attrOid;
    try { attrOid = asn1.read.oid(t); }
    catch (_e2) { return false; }
    if (seenTypes[attrOid]) return false;
    seenTypes[attrOid] = true;
    var placement = ATTR_FORBIDDEN_IN[attrOid];
    if (placement && placement.signed) return false;
    var n = (vs.children || []).length;
    if (n < 1) return false;
    if (!_ascendingDer(vs.children || [])) return false;
    var vals = vs.children || [];
    if (attrOid === OID_CONTENT_TYPE) {
      if (!_readsAs(vals, asn1.TAGS.OBJECT_IDENTIFIER, asn1.read.oid)) return false;
      sawContentType = true;
    } else if (attrOid === OID_MESSAGE_DIGEST) {
      if (!_readsAs(vals, asn1.TAGS.OCTET_STRING, asn1.read.octetString)) return false;
      sawMessageDigest = true;
    } else if (attrOid === OID_SIGNING_TIME) {
      if (!_readsAsTime(vals)) return false;
    }
  }
  return sawContentType && sawMessageDigest;
}

function _assertContentTypeMatchesAttrs(attrs, eContentType) {
  for (var i = 0; i < attrs.length; i++) {
    if (attrs[i].type !== OID_CONTENT_TYPE) continue;
    if (attrs[i].values.length !== 1) throw NS.E("cms/bad-content-type-attr", "the content-type attribute must be single-valued (RFC 5652 sec. 11.1)");
    var ctv;
    try { ctv = asn1.read.oid(asn1.decode(attrs[i].values[0])); }
    catch (e) { throw NS.E("cms/bad-content-type-attr", "the content-type attribute value must be a valid OBJECT IDENTIFIER", e); }
    if (ctv !== eContentType) throw NS.E("cms/content-type-mismatch", "the content-type attribute (" + ctv + ") must equal the eContentType (" + eContentType + ") (RFC 5652 sec. 5.3)");
  }
}

function _checkNoDuplicateAttrs(attrs) {
  var seen = Object.create(null);
  for (var i = 0; i < attrs.length; i++) {
    if (seen[attrs[i].type]) throw NS.E("cms/duplicate-attr", "an attribute set must not include multiple instances of the same attribute type (" + attrs[i].type + ", RFC 5652 sec. 5.3)");
    seen[attrs[i].type] = true;
  }
}

function _validateAeadParams(alg, macLen) {
  var kind = AEAD_ALGS[alg.oid];
  if (!kind) return null;
  var K = kind.toUpperCase();
  if (alg.parameters === null) throw NS.E("cms/bad-aead-params", "an AES-" + K + " content-encryption algorithm MUST carry its parameters (RFC 5084 sec. 3." + (kind === "gcm" ? "2" : "1") + ")");
  var node;
  try { node = asn1.decode(alg.parameters); }
  catch (e) { throw NS.E("cms/bad-aead-params", "malformed AES-" + K + " parameters", e); }
  if (node.tagClass !== "universal" || node.tagNumber !== T.SEQUENCE || !node.children || node.children.length < 1 || node.children.length > 2) {
    throw NS.E("cms/bad-aead-params", "AES-" + K + " parameters must be a SEQUENCE { aes-nonce, aes-ICVlen DEFAULT 12 } (RFC 5084)");
  }
  var nonce;
  try { nonce = asn1.read.octetString(node.children[0]); }
  catch (e) { throw NS.E("cms/bad-aead-params", "the AEAD aes-nonce must be an OCTET STRING", e); }
  if (kind === "ccm" && (nonce.length < 7 || nonce.length > 13)) throw NS.E("cms/bad-aead-params", "the AES-CCM aes-nonce must be 7..13 octets (RFC 5084 sec. 3.1)");
  if (nonce.length < 1) throw NS.E("cms/bad-aead-params", "the AEAD aes-nonce must be non-empty");
  var icvLen = 12, icvEncoded = false;
  if (node.children.length === 2) {
    var iv;
    try { iv = asn1.read.integer(node.children[1]); }
    catch (e) { throw NS.E("cms/bad-aead-params", "the AEAD aes-ICVlen must be an INTEGER", e); }
    if (iv < 0n || iv > 16n) throw NS.E("cms/bad-aead-params", "the AEAD aes-ICVlen is out of range");
    icvLen = Number(iv); icvEncoded = true;
  }
  var legal = kind === "gcm" ? AEAD_GCM_ICVLENS : AEAD_CCM_ICVLENS;
  if (!legal.has(icvLen)) throw NS.E("cms/bad-aead-params", "the AES-" + K + " aes-ICVlen " + icvLen + " is not an allowed value (RFC 5084)");
  if (icvEncoded && icvLen === 12) throw NS.E("cms/non-canonical-default", "the AEAD aes-ICVlen equal to the DEFAULT 12 MUST be omitted (X.690 sec. 11.5)");
  if (macLen != null && icvLen !== macLen) throw NS.E("cms/mac-length-mismatch", "the AEAD aes-ICVlen " + icvLen + " must equal the mac length " + macLen + " (RFC 5084)");
  return { kind: kind, nonce: nonce, icvLen: icvLen };
}

function _assertDerEncodedAttrs(node, code) {
  try { asn1.decode(node.bytes); }
  catch (e) { throw NS.E(code, "the attribute set must be DER encoded even inside a BER envelope (RFC 5652 sec. 5.3)", e); }
}

function rawElement(item) {
  return { bytes: item.node.bytes, tagClass: item.node.tagClass, tagNumber: item.node.tagNumber };
}

var CERT_CHOICE_TAGS = { universal: {}, context: { 0: true, 1: true, 2: true, 3: true } };
var CRL_CHOICE_TAGS = { universal: {}, context: { 1: true } };
CERT_CHOICE_TAGS.universal[asn1.TAGS.SEQUENCE] = true;
CRL_CHOICE_TAGS.universal[asn1.TAGS.SEQUENCE] = true;
function rawChoiceElement(allowed, code, what) {
  return function (item) {
    var n = item.node;
    var byClass = allowed[n.tagClass];
    if (!n.constructed || !byClass || byClass[n.tagNumber] !== true) {
      throw NS.E(code, what + " element tag is outside the closed CHOICE set (RFC 5652 sec. 10.2.1-sec. 10.2.2)");
    }
    return rawElement(item);
  };
}

function _expectedSignedDataVersion(certificates, crls, signerInfos, eContentType) {
  var otherCert = certificates.some(function (c) { return schema.isContext(c, 3); });
  var otherCrl = crls.some(function (c) { return schema.isContext(c, 1); });
  if (otherCert || otherCrl) return 5;
  if (certificates.some(function (c) { return schema.isContext(c, 2); })) return 4;
  if (certificates.some(function (c) { return schema.isContext(c, 1); }) ||
      signerInfos.some(function (si) { return si.version === 3; }) ||
      eContentType !== OID_DATA) return 3;
  return 1;
}

var ENCAP_CONTENT_INFO = schema.seq([
  schema.field("eContentType", schema.oidLeaf()),
  schema.optional("eContent", schema.octetString(), { tag: 0, explicit: true, emptyCode: "cms/bad-econtent" }),
], {
  assert: "sequence", arity: { min: 1, max: 2 }, code: "cms/bad-encap-content-info", what: "EncapsulatedContentInfo",
  build: function (m) {
    return {
      eContentType: m.fields.eContentType.value,
      eContent: m.fields.eContent.present ? m.fields.eContent.value : null,
    };
  },
});

var ISSUER_AND_SERIAL = schema.seq([
  schema.field("issuer", NAME),
  schema.field("serialNumber", schema.integerLeaf()),
], {
  assert: "sequence", arity: { exact: 2 }, code: "cms/bad-issuer-and-serial", what: "IssuerAndSerialNumber",
  build: function (m) {
    return {
      issuer: m.fields.issuer.value.result,
      serialNumber: m.fields.serialNumber.value,
      serialNumberHex: m.fields.serialNumber.node.content.toString("hex"),
    };
  },
});

var SIGNER_IDENTIFIER = schema.choice([
  { when: { tagClass: "universal", tagNumber: asn1.TAGS.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitOctetString(0) },
], { code: "cms/bad-signer-identifier", what: "SignerIdentifier" });

function makeSignerInfo(mode) {
  return schema.seq([
    schema.field("version", SIGNER_VERSION),
    schema.field("sid", SIGNER_IDENTIFIER),
    schema.field("digestAlgorithm", ALGORITHM_IDENTIFIER),
    schema.optional("signedAttrs", schema.implicitSetOf(0, ATTRIBUTE, { min: 1, code: "cms/bad-signed-attrs", what: "signedAttrs" }), { tag: 0 }),
    schema.field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
    schema.field("signature", schema.octetString()),
    schema.optional("unsignedAttrs", schema.implicitSetOf(1, ATTRIBUTE, { min: 1, code: "cms/bad-unsigned-attrs", what: "unsignedAttrs" }), { tag: 1 }),
  ], {
    assert: "sequence", code: "cms/bad-signer-info", what: "SignerInfo",
    build: function (m, ctx) {
      var version = m.fields.version.value;
      var sidNode = m.fields.sid.node;
      var isSkid = sidNode.tagClass === "context" && sidNode.tagNumber === 0;
      var sid;
      if (isSkid) {
        if (version !== 3) throw NS.E("cms/bad-signer-version", "a subjectKeyIdentifier signer identifier requires SignerInfo version 3");
        sid = { subjectKeyIdentifier: m.fields.sid.value };
      } else {
        if (version !== 1) throw NS.E("cms/bad-signer-version", "an issuerAndSerialNumber signer identifier requires SignerInfo version 1");
        sid = m.fields.sid.value.result;
      }
      var signedAttrs = null, signedAttrsBytes = null;
      if (m.fields.signedAttrs.present) {
        _assertDerEncodedAttrs(m.fields.signedAttrs.node, "cms/bad-signed-attrs");
        signedAttrs = m.fields.signedAttrs.value.items.map(function (it) { return it.value.result; });
        _checkAttrPlacement(signedAttrs, "signed");
        _checkContentBindingAttrs(signedAttrs, mode);
        signedAttrsBytes = m.fields.signedAttrs.node.bytes;
      }
      var unsignedAttrs = null;
      if (m.fields.unsignedAttrs.present) {
        unsignedAttrs = m.fields.unsignedAttrs.value.items.map(function (it) { return it.value.result; });
        _checkAttrPlacement(unsignedAttrs, "unsigned");
        for (var u = 0; u < unsignedAttrs.length; u++) {
          if (unsignedAttrs[u].type !== OID_COUNTERSIGNATURE) continue;
          for (var v = 0; v < unsignedAttrs[u].values.length; v++) {
            var csNode;
            try { csNode = asn1.decode(unsignedAttrs[u].values[v]); }
            catch (e) { throw NS.E("cms/bad-countersignature", "a countersignature attribute value must be DER (RFC 5652 sec. 11.4)", e); }
            schema.walk(COUNTERSIGNATURE_SIGNER_INFO, csNode, ctx);
          }
        }
      }
      return {
        version: version,
        sid: sid,
        digestAlgorithm: m.fields.digestAlgorithm.value.result,
        signedAttrs: signedAttrs,
        signedAttrsBytes: signedAttrsBytes,
        signatureAlgorithm: m.fields.signatureAlgorithm.value.result,
        signature: m.fields.signature.value,
        unsignedAttrs: unsignedAttrs,
      };
    },
  });
}
var SIGNER_INFO = makeSignerInfo("content");
var COUNTERSIGNATURE_SIGNER_INFO = makeSignerInfo("countersig");

var SIGNED_DATA = schema.seq([
  schema.field("version", SIGNED_DATA_VERSION),
  schema.field("digestAlgorithms", schema.setOf(ALGORITHM_IDENTIFIER, { min: 0, code: "cms/bad-digest-algorithms", what: "digestAlgorithms" })),
  schema.field("encapContentInfo", ENCAP_CONTENT_INFO),
  schema.optional("certificates", schema.implicitSetOf(0, schema.any(), { min: 1, code: "cms/bad-certificates", what: "certificates" }), { tag: 0 }),
  schema.optional("crls", schema.implicitSetOf(1, schema.any(), { min: 1, code: "cms/bad-crls", what: "crls" }), { tag: 1 }),
  schema.field("signerInfos", schema.setOf(SIGNER_INFO, { min: 0, code: "cms/bad-signer-infos", what: "signerInfos" })),
], {
  assert: "sequence", code: "cms/bad-signed-data", what: "SignedData",
  build: function (m) {
    var version = m.fields.version.value;
    var encapContentInfo = m.fields.encapContentInfo.value.result;
    var certificates = m.fields.certificates.present ? m.fields.certificates.value.items.map(rawChoiceElement(CERT_CHOICE_TAGS, "cms/bad-certificates", "certificates")) : [];
    var crls = m.fields.crls.present ? m.fields.crls.value.items.map(rawChoiceElement(CRL_CHOICE_TAGS, "cms/bad-crls", "crls")) : [];
    var signerInfos = m.fields.signerInfos.value.items.map(function (it) { return it.value.result; });

    if (encapContentInfo.eContentType !== OID_DATA) {
      for (var s = 0; s < signerInfos.length; s++) {
        if (signerInfos[s].signedAttrs === null) throw NS.E("cms/missing-signed-attrs", "a SignerInfo must carry signedAttrs when the content type is not id-data (RFC 5652 sec. 5.3)");
      }
    }

    for (var si = 0; si < signerInfos.length; si++) {
      if (signerInfos[si].signedAttrs) _assertContentTypeMatchesAttrs(signerInfos[si].signedAttrs, encapContentInfo.eContentType);
    }

    var expected = _expectedSignedDataVersion(certificates, crls, signerInfos, encapContentInfo.eContentType);
    if (version !== expected) throw NS.E("cms/bad-version", "SignedData version " + version + " does not match its contents (RFC 5652 sec. 5.1 requires v" + expected + ")");

    return {
      version: version,
      digestAlgorithms: m.fields.digestAlgorithms.value.items.map(function (it) { return it.value.result; }),
      encapContentInfo: encapContentInfo,
      certificates: certificates,
      crls: crls,
      signerInfos: signerInfos,
    };
  },
});

var T = asn1.TAGS;

var ENCRYPTED_CONTENT_INFO = schema.seq([
  schema.field("contentType", schema.oidLeaf()),
  schema.field("contentEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.optional("encryptedContent", schema.implicitOctetString(0), { tag: 0 }),
], {
  assert: "sequence", arity: { min: 2, max: 3 }, code: "cms/bad-encrypted-content-info", what: "EncryptedContentInfo",
  build: function (m) {
    return {
      contentType: m.fields.contentType.value,
      contentEncryptionAlgorithm: m.fields.contentEncryptionAlgorithm.value.result,
      encryptedContent: m.fields.encryptedContent.present ? m.fields.encryptedContent.value : null,
    };
  },
});

var RECIPIENT_IDENTIFIER = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitOctetString(0) },
], { code: "cms/bad-recipient-identifier", what: "RecipientIdentifier" });

var KEY_TRANS_RECIPIENT_INFO = schema.seq([
  schema.field("version", KTRI_VERSION),
  schema.field("rid", RECIPIENT_IDENTIFIER),
  schema.field("keyEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "sequence", code: "cms/bad-ktri", what: "KeyTransRecipientInfo",
  build: function (m) {
    var version = m.fields.version.value;
    var ridNode = m.fields.rid.node;
    var isSkid = ridNode.tagClass === "context" && ridNode.tagNumber === 0;
    if (isSkid && version !== 2) throw NS.E("cms/bad-recipient-version", "a subjectKeyIdentifier recipient identifier requires KeyTransRecipientInfo version 2 (RFC 5652 sec. 6.2.1)");
    if (!isSkid && version !== 0) throw NS.E("cms/bad-recipient-version", "an issuerAndSerialNumber recipient identifier requires KeyTransRecipientInfo version 0 (RFC 5652 sec. 6.2.1)");
    return {
      type: "ktri", version: version,
      rid: isSkid ? { subjectKeyIdentifier: m.fields.rid.value } : m.fields.rid.value.result,
      ridType: isSkid ? "subjectKeyIdentifier" : "issuerAndSerialNumber",
      keyEncryptionAlgorithm: m.fields.keyEncryptionAlgorithm.value.result,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

var ORIGINATOR_PUBLIC_KEY = schema.seq([
  schema.field("algorithm", ALGORITHM_IDENTIFIER),
  schema.field("publicKey", schema.bitString()),
], {
  assert: "constructed", code: "cms/bad-originator-public-key", what: "OriginatorPublicKey",
  build: function (m) { return { algorithm: m.fields.algorithm.value.result, publicKey: m.fields.publicKey.value }; },
});

var ORIGINATOR_IDENTIFIER_OR_KEY = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitOctetString(0) },
  { when: { tagClass: "context", tagNumber: 1 }, schema: ORIGINATOR_PUBLIC_KEY },
], { code: "cms/bad-originator-identifier", what: "OriginatorIdentifierOrKey" });

function keyIdentifierSchema(keyIdName, assert, code, what) {
  return schema.seq([
    schema.field(keyIdName, schema.octetString()),
    schema.optional("date", schema.time(NS), { whenUniversal: [T.GENERALIZED_TIME] }),
    schema.optional("other", schema.any(), { whenUniversal: [T.SEQUENCE] }),
  ], {
    assert: assert, code: code, what: what,
    build: function (m) {
      var out = {};
      out[keyIdName] = m.fields[keyIdName].value;
      out.date = m.fields.date.present ? m.fields.date.value : null;
      out.other = m.fields.other.present ? m.fields.other.node.bytes : null;
      return out;
    },
  });
}

var RECIPIENT_KEY_IDENTIFIER = keyIdentifierSchema("subjectKeyIdentifier",
  "constructed", "cms/bad-recipient-key-identifier", "RecipientKeyIdentifier");

var KEY_AGREE_RECIPIENT_IDENTIFIER = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: RECIPIENT_KEY_IDENTIFIER },
], { code: "cms/bad-kari-identifier", what: "KeyAgreeRecipientIdentifier" });

var RECIPIENT_ENCRYPTED_KEY = schema.seq([
  schema.field("rid", KEY_AGREE_RECIPIENT_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "sequence", code: "cms/bad-recipient-encrypted-key", what: "RecipientEncryptedKey",
  build: function (m) {
    var ridNode = m.fields.rid.node;
    var isRkid = ridNode.tagClass === "context" && ridNode.tagNumber === 0;
    return {
      rid: m.fields.rid.value.result,
      ridType: isRkid ? "rKeyId" : "issuerAndSerialNumber",
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

var KEY_AGREE_RECIPIENT_INFO = schema.seq([
  schema.field("version", KARI_VERSION),
  schema.field("originator", schema.explicit(0, ORIGINATOR_IDENTIFIER_OR_KEY, { code: "cms/bad-kari" })),
  schema.optional("ukm", schema.octetString(), { tag: 1, explicit: true, emptyCode: "cms/bad-kari" }),
  schema.field("keyEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("recipientEncryptedKeys", schema.seqOf(RECIPIENT_ENCRYPTED_KEY, { code: "cms/bad-recipient-encrypted-keys", what: "recipientEncryptedKeys" })),
], {
  assert: "constructed", code: "cms/bad-kari", what: "KeyAgreeRecipientInfo",
  build: function (m) {
    var origNode = m.fields.originator.node.children[0];
    var origForm = origNode.tagClass === "context" ? (origNode.tagNumber === 0 ? "subjectKeyIdentifier" : "originatorKey") : "issuerAndSerialNumber";
    var origVal = m.fields.originator.value;
    return {
      type: "kari", version: m.fields.version.value,
      originator: { form: origForm, value: origForm === "subjectKeyIdentifier" ? origVal : origVal.result },
      ukm: m.fields.ukm.present ? m.fields.ukm.value : null,
      keyEncryptionAlgorithm: m.fields.keyEncryptionAlgorithm.value.result,
      recipientEncryptedKeys: m.fields.recipientEncryptedKeys.value.items.map(function (it) { return it.value.result; }),
    };
  },
});

var KEK_IDENTIFIER = keyIdentifierSchema("keyIdentifier",
  "sequence", "cms/bad-kek-identifier", "KEKIdentifier");
var KEK_RECIPIENT_INFO = schema.seq([
  schema.field("version", KEKRI_VERSION),
  schema.field("kekid", KEK_IDENTIFIER),
  schema.field("keyEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "constructed", code: "cms/bad-kekri", what: "KEKRecipientInfo",
  build: function (m) {
    return {
      type: "kekri", version: m.fields.version.value,
      kekid: m.fields.kekid.value.result,
      keyEncryptionAlgorithm: m.fields.keyEncryptionAlgorithm.value.result,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

var PASSWORD_RECIPIENT_INFO = schema.seq([
  schema.field("version", PWRI_VERSION),
  schema.optional("keyDerivationAlgorithm", pkix.algorithmIdentifier(NS, { implicitTag: 0 }), { tag: 0 }),
  schema.field("keyEncryptionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "constructed", code: "cms/bad-pwri", what: "PasswordRecipientInfo",
  build: function (m) {
    return {
      type: "pwri", version: m.fields.version.value,
      keyDerivationAlgorithm: m.fields.keyDerivationAlgorithm.present ? m.fields.keyDerivationAlgorithm.value.result : null,
      keyEncryptionAlgorithm: m.fields.keyEncryptionAlgorithm.value.result,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

var KEM_RECIPIENT_INFO = schema.seq([
  schema.field("version", KEMRI_VERSION),
  schema.field("rid", RECIPIENT_IDENTIFIER),
  schema.field("kem", ALGORITHM_IDENTIFIER),
  schema.field("kemct", schema.octetString()),
  schema.field("kdf", ALGORITHM_IDENTIFIER),
  schema.field("kekLength", schema.integerLeaf()),
  schema.optional("ukm", schema.octetString(), { tag: 0, explicit: true, emptyCode: "cms/bad-kem-recipient-info" }),
  schema.field("wrap", ALGORITHM_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "sequence", code: "cms/bad-kem-recipient-info", what: "KEMRecipientInfo",
  build: function (m) {
    var ridNode = m.fields.rid.node;
    var isSkid = ridNode.tagClass === "context" && ridNode.tagNumber === 0;
    var kem = m.fields.kem.value.result;
    var kemct = m.fields.kemct.value;
    var wrap = m.fields.wrap.value.result;
    var kl = m.fields.kekLength.value;
    if (kl < 1n || kl > 65535n) throw NS.E("cms/bad-kek-length", "KEMRecipientInfo kekLength must be 1..65535 (RFC 9629 sec. 3)");
    var kekLength = Number(kl);
    var wrapLen = WRAP_KEK_LENGTHS[wrap.oid];
    if (wrapLen !== undefined && kekLength !== wrapLen) {
      throw NS.E("cms/kek-length-mismatch", "kekLength " + kekLength + " does not match the " + (oid.name(wrap.oid) || wrap.oid) + " KEK size " + wrapLen + " (RFC 9629 sec. 3)");
    }
    var ctLen = KEM_CT_LENGTHS[kem.oid];
    if (ctLen !== undefined && kemct.length !== ctLen) {
      throw NS.E("cms/bad-kem-ciphertext", "the " + (oid.name(kem.oid) || kem.oid) + " kemct must be exactly " + ctLen + " octets (FIPS 203)");
    }
    return {
      version: m.fields.version.value,
      rid: isSkid ? { subjectKeyIdentifier: m.fields.rid.value } : m.fields.rid.value.result,
      ridType: isSkid ? "subjectKeyIdentifier" : "issuerAndSerialNumber",
      kem: kem,
      kemct: kemct,
      kdf: m.fields.kdf.value.result,
      kekLength: kekLength,
      ukm: m.fields.ukm.present ? m.fields.ukm.value : null,
      wrap: wrap,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

var OTHER_RECIPIENT_INFO = schema.seq([
  schema.field("oriType", schema.oidLeaf()),
  schema.field("oriValue", schema.any()),
], {
  assert: "constructed", code: "cms/bad-ori", what: "OtherRecipientInfo",
  build: function (m, ctx) {
    var oriType = m.fields.oriType.value;
    var raw = m.fields.oriValue.node.bytes;
    if (oriType === OID_ORI_KEM) {
      var kemri = schema.walk(KEM_RECIPIENT_INFO, m.fields.oriValue.node, ctx).result;
      return { type: "ori", oriType: oriType, oriValue: raw, kemri: kemri };
    }
    return { type: "ori", oriType: oriType, oriValue: raw, kemri: null };
  },
});

var RECIPIENT_INFO = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: KEY_TRANS_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 1 }, schema: KEY_AGREE_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 2 }, schema: KEK_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 3 }, schema: PASSWORD_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 4 }, schema: OTHER_RECIPIENT_INFO },
], { code: "cms/bad-recipient-info", what: "RecipientInfo" });

var ORIGINATOR_INFO = schema.seq([
  schema.optional("certs", schema.implicitSetOf(0, schema.any(), { min: 1, code: "cms/bad-originator-certs", what: "certs" }), { tag: 0 }),
  schema.optional("crls", schema.implicitSetOf(1, schema.any(), { min: 1, code: "cms/bad-originator-crls", what: "crls" }), { tag: 1 }),
], {
  assert: "constructed", code: "cms/bad-originator-info", what: "OriginatorInfo",
  build: function (m) {
    return {
      certs: m.fields.certs.present ? m.fields.certs.value.items.map(rawChoiceElement(CERT_CHOICE_TAGS, "cms/bad-originator-certs", "OriginatorInfo certs")) : [],
      crls: m.fields.crls.present ? m.fields.crls.value.items.map(rawChoiceElement(CRL_CHOICE_TAGS, "cms/bad-originator-crls", "OriginatorInfo crls")) : [],
    };
  },
});

function _expectedEnvelopedDataVersion(originatorInfo, recipientInfos, hasUnprotectedAttrs) {
  var hasOrig = !!originatorInfo;
  var certs = hasOrig ? originatorInfo.certs : [];
  var crls = hasOrig ? originatorInfo.crls : [];
  if (hasOrig && (certs.some(function (c) { return schema.isContext(c, 3); }) || crls.some(function (c) { return schema.isContext(c, 1); }))) return 4;
  if ((hasOrig && certs.some(function (c) { return schema.isContext(c, 2); })) ||
      recipientInfos.some(function (r) { return r.type === "pwri" || r.type === "ori"; })) return 3;
  if (!hasOrig && !hasUnprotectedAttrs &&
      recipientInfos.every(function (r) { return r.type === "ktri" && r.ridType === "issuerAndSerialNumber"; })) return 0;
  return 2;
}

function _expectedAuthDataVersion(originatorInfo) {
  if (!originatorInfo) return 0;
  var certs = originatorInfo.certs, crls = originatorInfo.crls;
  if (certs.some(function (c) { return schema.isContext(c, 3); }) || crls.some(function (c) { return schema.isContext(c, 1); })) return 3;
  if (certs.some(function (c) { return schema.isContext(c, 2); })) return 1;
  return 0;
}

var ENVELOPED_DATA = schema.seq([
  schema.field("version", ENVELOPED_DATA_VERSION),
  schema.optional("originatorInfo", ORIGINATOR_INFO, { tag: 0 }),
  schema.field("recipientInfos", schema.setOf(RECIPIENT_INFO, { min: 1, code: "cms/bad-recipient-infos", what: "recipientInfos" })),
  schema.field("encryptedContentInfo", ENCRYPTED_CONTENT_INFO),
  schema.optional("unprotectedAttrs", schema.implicitSetOf(1, ATTRIBUTE, { min: 1, code: "cms/bad-unprotected-attrs", what: "unprotectedAttrs" }), { tag: 1 }),
], {
  assert: "sequence", code: "cms/bad-enveloped-data", what: "EnvelopedData",
  build: function (m) {
    var version = m.fields.version.value;
    var originatorInfo = m.fields.originatorInfo.present ? m.fields.originatorInfo.value.result : null;
    var recipientInfos = m.fields.recipientInfos.value.items.map(function (it) { return it.value.result; });
    var hasUnprotectedAttrs = m.fields.unprotectedAttrs.present;
    var expected = _expectedEnvelopedDataVersion(originatorInfo, recipientInfos, hasUnprotectedAttrs);
    if (version !== expected) throw NS.E("cms/bad-version", "EnvelopedData version " + version + " does not match its contents (RFC 5652 sec. 6.1 requires v" + expected + ")");
    var unprotectedAttrs = hasUnprotectedAttrs ? m.fields.unprotectedAttrs.value.items.map(function (it) { return it.value.result; }) : null;
    if (unprotectedAttrs) _checkAttrPlacement(unprotectedAttrs, "unprotected");
    return {
      version: version,
      originatorInfo: originatorInfo,
      recipientInfos: recipientInfos,
      encryptedContentInfo: m.fields.encryptedContentInfo.value.result,
      unprotectedAttrs: unprotectedAttrs,
    };
  },
});

var ENCRYPTED_DATA = schema.seq([
  schema.field("version", ENCRYPTED_DATA_VERSION),
  schema.field("encryptedContentInfo", ENCRYPTED_CONTENT_INFO),
  schema.optional("unprotectedAttrs", schema.implicitSetOf(1, ATTRIBUTE, { min: 1, code: "cms/bad-unprotected-attrs", what: "unprotectedAttrs" }), { tag: 1 }),
], {
  assert: "sequence", code: "cms/bad-encrypted-data", what: "EncryptedData",
  build: function (m) {
    var version = m.fields.version.value;
    var hasUnprotectedAttrs = m.fields.unprotectedAttrs.present;
    var expected = hasUnprotectedAttrs ? 2 : 0;
    if (version !== expected) throw NS.E("cms/bad-version", "EncryptedData version " + version + " does not match its contents (RFC 5652 sec. 8 requires v" + expected + ")");
    var unprotectedAttrs = hasUnprotectedAttrs ? m.fields.unprotectedAttrs.value.items.map(function (it) { return it.value.result; }) : null;
    if (unprotectedAttrs) _checkAttrPlacement(unprotectedAttrs, "unprotected");
    return {
      version: version,
      encryptedContentInfo: m.fields.encryptedContentInfo.value.result,
      unprotectedAttrs: unprotectedAttrs,
    };
  },
});

var AUTHENTICATED_DATA = schema.seq([
  schema.field("version", AUTHDATA_VERSION),
  schema.optional("originatorInfo", ORIGINATOR_INFO, { tag: 0 }),
  schema.field("recipientInfos", schema.setOf(RECIPIENT_INFO, { min: 1, code: "cms/bad-recipient-infos", what: "recipientInfos" })),
  schema.field("macAlgorithm", ALGORITHM_IDENTIFIER),
  schema.optional("digestAlgorithm", pkix.algorithmIdentifier(NS, { implicitTag: 1 }), { tag: 1 }),
  schema.field("encapContentInfo", ENCAP_CONTENT_INFO),
  schema.optional("authAttrs", schema.implicitSetOf(2, ATTRIBUTE, { min: 1, code: "cms/bad-auth-attrs", what: "authAttrs" }), { tag: 2 }),
  schema.field("mac", schema.octetString()),
  schema.optional("unauthAttrs", schema.implicitSetOf(3, ATTRIBUTE, { min: 1, code: "cms/bad-unauth-attrs", what: "unauthAttrs" }), { tag: 3 }),
], {
  assert: "sequence", code: "cms/bad-auth-data", what: "AuthenticatedData",
  build: function (m) {
    var version = m.fields.version.value;
    var originatorInfo = m.fields.originatorInfo.present ? m.fields.originatorInfo.value.result : null;
    var encapContentInfo = m.fields.encapContentInfo.value.result;
    var hasDigestAlg = m.fields.digestAlgorithm.present;
    var hasAuthAttrs = m.fields.authAttrs.present;

    var expected = _expectedAuthDataVersion(originatorInfo);
    if (version !== expected) throw NS.E("cms/bad-version", "AuthenticatedData version " + version + " does not match its contents (RFC 5652 sec. 9.1 requires v" + expected + ")");

    if (!hasAuthAttrs && encapContentInfo.eContentType !== OID_DATA) {
      throw NS.E("cms/missing-auth-attrs", "AuthenticatedData must carry authAttrs when the content type is not id-data (RFC 5652 sec. 9.1)");
    }
    if (hasDigestAlg && !hasAuthAttrs) throw NS.E("cms/missing-auth-attrs", "a digestAlgorithm requires authAttrs (RFC 5652 sec. 9.1)");
    if (hasAuthAttrs && !hasDigestAlg) throw NS.E("cms/missing-digest-algorithm", "authAttrs require a digestAlgorithm (RFC 5652 sec. 9.1)");

    var authAttrs = null, authAttrsBytes = null;
    if (hasAuthAttrs) {
      _assertDerEncodedAttrs(m.fields.authAttrs.node, "cms/bad-auth-attrs");
      authAttrs = m.fields.authAttrs.value.items.map(function (it) { return it.value.result; });
      _checkAttrPlacement(authAttrs, "auth");
      _checkContentBindingAttrs(authAttrs, "content");
      _assertContentTypeMatchesAttrs(authAttrs, encapContentInfo.eContentType);
      authAttrsBytes = m.fields.authAttrs.node.bytes;
    }
    var unauthAttrs = null;
    if (m.fields.unauthAttrs.present) {
      unauthAttrs = m.fields.unauthAttrs.value.items.map(function (it) { return it.value.result; });
      _checkAttrPlacement(unauthAttrs, "unauth");
    }
    return {
      version: version,
      originatorInfo: originatorInfo,
      recipientInfos: m.fields.recipientInfos.value.items.map(function (it) { return it.value.result; }),
      macAlgorithm: m.fields.macAlgorithm.value.result,
      digestAlgorithm: hasDigestAlg ? m.fields.digestAlgorithm.value.result : null,
      encapContentInfo: encapContentInfo,
      authAttrs: authAttrs,
      authAttrsBytes: authAttrsBytes,
      mac: m.fields.mac.value,
      unauthAttrs: unauthAttrs,
    };
  },
});

var AUTH_ENVELOPED_DATA = schema.seq([
  schema.field("version", AUTHENV_VERSION),
  schema.optional("originatorInfo", ORIGINATOR_INFO, { tag: 0 }),
  schema.field("recipientInfos", schema.setOf(RECIPIENT_INFO, { min: 1, code: "cms/bad-recipient-infos", what: "recipientInfos" })),
  schema.field("authEncryptedContentInfo", ENCRYPTED_CONTENT_INFO),
  schema.optional("authAttrs", schema.implicitSetOf(1, ATTRIBUTE, { min: 1, code: "cms/bad-auth-attrs", what: "authAttrs" }), { tag: 1 }),
  schema.field("mac", schema.octetString()),
  schema.optional("unauthAttrs", schema.implicitSetOf(2, ATTRIBUTE, { min: 1, code: "cms/bad-unauth-attrs", what: "unauthAttrs" }), { tag: 2 }),
], {
  assert: "sequence", code: "cms/bad-auth-enveloped-data", what: "AuthEnvelopedData",
  build: function (m) {
    var encryptedContentInfo = m.fields.authEncryptedContentInfo.value.result;
    var mac = m.fields.mac.value;
    var aead = _validateAeadParams(encryptedContentInfo.contentEncryptionAlgorithm, mac.length);

    var hasAuthAttrs = m.fields.authAttrs.present;
    if (!hasAuthAttrs && encryptedContentInfo.contentType !== OID_DATA) {
      throw NS.E("cms/missing-auth-attrs", "AuthEnvelopedData must carry authAttrs when the content type is not id-data (RFC 5083 sec. 2.1)");
    }
    var authAttrs = null, authAttrsBytes = null;
    if (hasAuthAttrs) {
      _assertDerEncodedAttrs(m.fields.authAttrs.node, "cms/bad-auth-attrs");
      authAttrs = m.fields.authAttrs.value.items.map(function (it) { return it.value.result; });
      _checkAttrPlacement(authAttrs, "auth");
      _checkNoDuplicateAttrs(authAttrs);
      _assertContentTypeMatchesAttrs(authAttrs, encryptedContentInfo.contentType);
      authAttrsBytes = m.fields.authAttrs.node.bytes;
    }
    var unauthAttrs = null;
    if (m.fields.unauthAttrs.present) {
      unauthAttrs = m.fields.unauthAttrs.value.items.map(function (it) { return it.value.result; });
      _checkAttrPlacement(unauthAttrs, "unauth");
    }
    return {
      version: m.fields.version.value,
      originatorInfo: m.fields.originatorInfo.present ? m.fields.originatorInfo.value.result : null,
      recipientInfos: m.fields.recipientInfos.value.items.map(function (it) { return it.value.result; }),
      encryptedContentInfo: encryptedContentInfo,
      aead: aead,
      authAttrs: authAttrs,
      authAttrsBytes: authAttrsBytes,
      mac: mac,
      unauthAttrs: unauthAttrs,
    };
  },
});

var COMPRESSED_DATA = schema.seq([
  schema.field("version", COMPRESSED_DATA_VERSION),
  schema.field("compressionAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("encapContentInfo", ENCAP_CONTENT_INFO),
], {
  assert: "sequence", code: "cms/bad-compressed-data", what: "CompressedData",
  build: function (m) {
    return {
      version: m.fields.version.value,
      compressionAlgorithm: m.fields.compressionAlgorithm.value.result,
      encapContentInfo: m.fields.encapContentInfo.value.result,
    };
  },
});

var CONTENT_INFO = schema.seq([
  schema.field("contentType", schema.oidLeaf()),
  schema.field("content", schema.explicit(0, schema.any(), { code: "cms/not-a-content-info" })),
], {
  assert: "sequence", arity: { exact: 2 }, code: "cms/not-a-content-info", what: "ContentInfo",
  build: function (m, ctx) {
    var ct = m.fields.contentType.value;
    var inner = null;
    if (ct === OID_SIGNED_DATA) inner = SIGNED_DATA;
    else if (ct === OID_ENVELOPED_DATA) inner = ENVELOPED_DATA;
    else if (ct === OID_ENCRYPTED_DATA) inner = ENCRYPTED_DATA;
    else if (ct === OID_AUTH_DATA) inner = AUTHENTICATED_DATA;
    else if (ct === OID_AUTH_ENVELOPED_DATA) inner = AUTH_ENVELOPED_DATA;
    else if (ct === OID_COMPRESSED_DATA) inner = COMPRESSED_DATA;
    if (inner === null) {
      if (DEFERRED.has(ct)) {
        throw NS.E("cms/unsupported-content-type", (ctx.oid.name(ct) || ct) + " is recognized but not parsed by this build");
      }
      throw NS.E("cms/unknown-content-type", "unrecognized ContentInfo content type " + ct);
    }
    var result = schema.walk(inner, m.fields.content.value, ctx).result;
    result.contentType = ct;
    result.contentTypeName = ctx.oid.name(ct) || null;
    return result;
  },
});

/**
 * @primitive  pki.schema.cms.parse
 * @signature  pki.schema.cms.parse(input) -> content
 * @since      0.1.10
 * @status     stable
 * @spec       RFC 5652, RFC 5083, RFC 9629
 * @related    pki.schema.parse, pki.schema.x509.parse
 *
 * Parse a DER `Buffer` or a PEM (`CMS`) string into the structured content the
 * ContentInfo carries, dispatched by its content type. `id-signedData` returns
 * `{ version, digestAlgorithms, encapContentInfo, certificates, crls,
 * signerInfos }`; `id-envelopedData` returns `{ version, originatorInfo,
 * recipientInfos, encryptedContentInfo, unprotectedAttrs }`; `id-encryptedData`
 * returns `{ version, encryptedContentInfo, unprotectedAttrs }`; `id-ct-authData`
 * returns `{ version, originatorInfo, recipientInfos, macAlgorithm,
 * digestAlgorithm, encapContentInfo, authAttrs, authAttrsBytes, mac,
 * unauthAttrs }`; `id-ct-authEnvelopedData` returns `{ version, originatorInfo,
 * recipientInfos, encryptedContentInfo, aead, authAttrs, authAttrsBytes, mac,
 * unauthAttrs }` (`aead` holds the validated AES-GCM/CCM nonce + ICV length, or
 * `null` for an unrecognized algorithm). A KEM recipient (RFC 9629) surfaces as
 * `{ type: "ori", oriType, oriValue, kemri }` with the parsed KEMRecipientInfo in
 * `kemri`. Every result additionally carries `contentType` (the dotted OID) and
 * `contentTypeName` (its registry name) naming which of the five shapes was
 * dispatched. The raw byte ranges an external verifier hashes (`eContent`,
 * `signature`, `signedAttrsBytes`, `authAttrsBytes`, `mac`) are surfaced
 * exactly as on the wire. The remaining PKCS#7 types throw `cms/unsupported-content-type`; an
 * unrecognized OID throws `cms/unknown-content-type`; a malformed structure
 * throws a typed `CmsError` (`cms/*`) and a leaf-level codec fault surfaces as
 * `asn1/*`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     serialNumber: 0x0a1bn, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: key });
 *   var der = await pki.cms.sign(Buffer.from("hello"), { cert: cert, key: key });
 *   var cms = pki.schema.cms.parse(der);
 *   cms.signerInfos[0].sid.serialNumberHex;   // -> "0a1b"
 *   cms.encapContentInfo.eContent;            // -> Buffer | null (detached)
 */
var parse = pkix.makeRecordingParser({ pemLabel: "CMS", PemError: PemError, ErrorClass: CmsError, prefix: "cms", what: "CMS ContentInfo", topSchema: CONTENT_INFO, ns: NS }, "cms");

/**
 * @primitive  pki.schema.cms.pemDecode
 * @signature  pki.schema.cms.pemDecode(text, label?) -> Buffer
 * @since      0.1.10
 * @status     stable
 * @spec       RFC 7468, RFC 5652
 * @related    pki.schema.cms.parse
 *
 * Extract the DER bytes from a PEM CMS block (default label `CMS`). Throws
 * `PemError` on a missing / mismatched envelope or a non-base64 body.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var pemText = await pki.cms.sign(Buffer.from("hello"), { cert: cert, key: key }, { pem: true });
 *   var der = pki.schema.cms.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label || "CMS", PemError); }

/**
 * @primitive  pki.schema.cms.pemEncode
 * @signature  pki.schema.cms.pemEncode(der, label?) -> string
 * @since      0.1.10
 * @status     stable
 * @spec       RFC 7468
 * @related    pki.schema.cms.pemDecode
 *
 * Wrap DER bytes in a PEM CMS envelope (default label `CMS`).
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var der = await pki.cms.sign(Buffer.from("hello"), { cert: cert, key: key });
 *   var pem = pki.schema.cms.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "CMS", PemError); }

function matches(root) {
  var TAGS = asn1.TAGS;
  var k = pkix.rootSequenceChildren(root, 2, 2);
  if (!k) return false;
  if (!schema.isUniversal(k[0], TAGS.OBJECT_IDENTIFIER)) return false;
  if (!(schema.isContext(k[1], 0) && k[1].children)) return false;
  return true;
}

function walkEnvelopedData(node) { return schema.walk(ENVELOPED_DATA, node, NS).result; }

var walkSignedData = guard.parsed.recordingWalker("cms", function (node) {
  return schema.walk(SIGNED_DATA, node, NS).result;
}, function (der) { return asn1.decode(der, { ber: true }); });
function walkEncryptedData(node) { return schema.walk(ENCRYPTED_DATA, node, NS).result; }
function walkCountersignature(node) { return schema.walk(COUNTERSIGNATURE_SIGNER_INFO, node, NS).result; }

function assertAttachedCiphertext(eci, E, code, label) {
  if (!eci || eci.encryptedContent === null || eci.encryptedContent.length === 0) {
    throw E(code, (label || "encrypted content") + " must carry a non-empty attached ciphertext (RFC 5652 sec. 6.1), not be detached or empty");
  }
  return eci;
}

function parseCertsOnly(der, E, prefix, maxCerts, requireCert) {
  var needCert = requireCert !== false;
  var r;
  try { r = parse(der); }
  catch (e) { throw E(prefix + "/bad-response", "a certs-only response did not decode as CMS: " + ((e && e.message) || String(e)), e); }
  if (r.contentTypeName !== "signedData") throw E(prefix + "/not-certs-only", "a certs-only response must be a CMS SignedData (RFC 5272 sec. 4.1)");
  if (r.encapContentInfo.eContentType !== OID_DATA || r.encapContentInfo.eContent !== null) {
    throw E(prefix + "/not-certs-only", "a certs-only Simple PKI Response must carry id-data with no eContent (RFC 5272 sec. 4.1)");
  }
  if (r.signerInfos.length !== 0) throw E(prefix + "/not-certs-only", "a certs-only Simple PKI Response must have empty signerInfos (RFC 5272 sec. 4.1)");
  var allCerts = r.certificates;
  var allCrls = r.crls;
  if (needCert) {
    if (allCerts.length === 0) throw E(prefix + "/no-certificates", "a certs-only response must contain at least one certificate (RFC 5272 sec. 4.1)");
  } else if (allCerts.length === 0 && allCrls.length === 0) {
    throw E(prefix + "/no-certificates", "a certs-only message must contain at least one certificate or CRL (RFC 8551 sec. 3.8)");
  }
  var certs = (maxCerts != null && allCerts.length > maxCerts) ? allCerts.slice(0, maxCerts) : allCerts;
  for (var i = 0; i < certs.length; i++) {
    if (certs[i].tagClass !== "universal") throw E(prefix + "/bad-certificate-choice", "a certs-only response exchanges plain X.509 certificates; a tagged CertificateChoices alternative is not permitted (RFC 5272)");
    try { schemaX509.parse(certs[i].bytes); }
    catch (e) { throw E(prefix + "/bad-certificate", "a certs-only response carried a non-certificate in its certificates field (RFC 5272 sec. 4.1)", e); }
  }
  var crlCap = maxCerts != null ? (maxCerts - certs.length) : null;
  var crls = (crlCap != null && allCrls.length > crlCap) ? allCrls.slice(0, crlCap) : allCrls;
  for (var j = 0; j < crls.length; j++) {
    if (crls[j].tagClass !== "universal") throw E(prefix + "/bad-crl", "a certs-only response CRL must be a plain X.509 CertificateList, not a tagged otherRevInfo alternative (RFC 5652 sec. 10.2.1)");
    try { schemaCrl.parse(crls[j].bytes); }
    catch (e) { throw E(prefix + "/bad-crl", "a certs-only response carried a non-CRL in its crls field", e); }
  }
  return {
    certificates: certs.map(function (c) { return c.bytes; }),
    crls: crls.map(function (c) { return c.bytes; }),
  };
}

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  parseCertsOnly: parseCertsOnly,
  walkEnvelopedData: walkEnvelopedData,
  walkSignedData: walkSignedData,
  walkEncryptedData: walkEncryptedData,
  walkCountersignature: walkCountersignature,
  looksLikeSignedAttributes: looksLikeSignedAttributes,
  assertAttachedCiphertext: assertAttachedCiphertext,
  WRAP_KEK_LENGTHS: WRAP_KEK_LENGTHS,
  KEM_CT_LENGTHS: KEM_CT_LENGTHS,
  AEAD_ALGS: AEAD_ALGS,
  AEAD_GCM_ICVLENS: AEAD_GCM_ICVLENS,
  AEAD_CCM_ICVLENS: AEAD_CCM_ICVLENS,
};
