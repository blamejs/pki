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
 *   CMS handling per RFC 5652 (§3 ContentInfo envelope). `parse` turns a DER or PEM
 *   (`CMS`) message into a structured object and is an OID-dispatch envelope —
 *   ContentInfo reads its `contentType` and structurally decodes SignedData (§5),
 *   EnvelopedData (§6, with all five RecipientInfo kinds — key-transport,
 *   key-agreement per RFC 5753, KEK, password, and other), and EncryptedData (§8);
 *   the remaining PKCS#7 content types are recognized and rejected with a precise
 *   `cms/unsupported-content-type` rather than a generic unknown-format error. A
 *   SignedData surfaces its version, digest algorithms, encapsulated content,
 *   certificate / CRL sets, and signer infos; an EnvelopedData its recipient infos
 *   and encrypted content info; an EncryptedData its encrypted content info.
 *
 *   CMS is a signed container: the bytes an external verifier must hash are
 *   surfaced RAW and never re-serialized. `encapContentInfo.eContent` is the raw
 *   content (or `null` for a detached signature); each SignerInfo's `signature` is
 *   raw, and `signedAttrsBytes` is the on-wire `[0]` SignedAttributes TLV so a
 *   verifier can re-tag it to the universal SET the signature is computed over
 *   (§5.4). Embedded certificates and CRLs are surfaced as raw DER + their outer
 *   tag, so an obsolete or unknown alternative never fails the parse. DER-only,
 *   fail-closed.
 *
 * @card
 *   Parse DER / PEM CMS SignedData (RFC 5652) into structured, validated fields —
 *   encapsulated content, signer infos, raw signed-attribute bytes for external
 *   verification, certificates/CRLs kept raw, fail-closed.
 */

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var frameworkError = require("./framework-error");

var CmsError = frameworkError.CmsError;
var PemError = frameworkError.PemError;

// The cms error namespace the schema engine walks under.
var NS = pkix.makeNS("cms", CmsError, oid);

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var ATTRIBUTE = pkix.attribute(NS);
var NAME = pkix.name(NS);

// CMSVersion ::= INTEGER — the SignedData version is {1,3,4,5} and the SignerInfo
// version is {1,3} (RFC 5652 §5.1, §5.3). Wider accept maps than any other format.
var SIGNED_DATA_VERSION = pkix.versionReader(NS, { "1": 1, "3": 3, "4": 4, "5": 5 });
var SIGNER_VERSION = pkix.versionReader(NS, { "1": 1, "3": 3 });
// EnvelopedData §6.1 (0/2/3/4), EncryptedData §8 (0/2), and the per-RecipientInfo
// versions (RFC 5652 §6.2.1-§6.2.4): ktri {0,2}, kari {3}, kekri {4}, pwri {0}.
var ENVELOPED_DATA_VERSION = pkix.versionReader(NS, { "0": 0, "2": 2, "3": 3, "4": 4 });
var ENCRYPTED_DATA_VERSION = pkix.versionReader(NS, { "0": 0, "2": 2 });
var KTRI_VERSION = pkix.versionReader(NS, { "0": 0, "2": 2 });
var KARI_VERSION = pkix.versionReader(NS, { "3": 3 });
var KEKRI_VERSION = pkix.versionReader(NS, { "4": 4 });
var PWRI_VERSION = pkix.versionReader(NS, { "0": 0 });

// id-signedData / id-envelopedData / id-encryptedData are the content types this
// build structurally decodes; the rest are recognized-and-deferred (a precise
// diagnostic, not a silent unknown-format). OIDs resolve from the registry (pkcs7 /
// smimeCt families), never dotted literals.
var OID_SIGNED_DATA = oid.byName("signedData");
var OID_ENVELOPED_DATA = oid.byName("envelopedData");
var OID_ENCRYPTED_DATA = oid.byName("encryptedData");
var OID_DATA = oid.byName("data");
var DEFERRED = new Set([
  oid.byName("data"), oid.byName("signedAndEnvelopedData"),
  oid.byName("digestedData"), oid.byName("authData"),
]);
// The two mandatory signed-attribute types (RFC 5652 §5.3, §11.1/§11.2).
var OID_CONTENT_TYPE = oid.byName("contentType");
var OID_MESSAGE_DIGEST = oid.byName("messageDigest");

// Enforce the SignedAttributes value constraints (RFC 5652 §5.3, §11) — if
// signedAttrs is present it MUST contain exactly one content-type attribute and
// exactly one message-digest attribute, each single-valued. The content-type value
// == eContentType and messageDigest == the actual content hash are §5.6
// VERIFICATION concerns (surfaced, checked by the verifier), not structural-parse
// concerns.
function _checkSignedAttrs(attrs) {
  var ct = 0, md = 0, seen = Object.create(null);
  for (var i = 0; i < attrs.length; i++) {
    var a = attrs[i];
    // RFC 5652 §5.3 — a signerInfo MUST NOT include multiple instances of the
    // same signed-attribute type (specific codes for the two mandatory types).
    if (seen[a.type]) {
      if (a.type === OID_CONTENT_TYPE) throw NS.E("cms/duplicate-content-type", "signedAttrs must not repeat the content-type attribute");
      if (a.type === OID_MESSAGE_DIGEST) throw NS.E("cms/duplicate-message-digest", "signedAttrs must not repeat the message-digest attribute");
      throw NS.E("cms/duplicate-signed-attr", "signedAttrs must not include multiple instances of the same attribute type (" + a.type + ")");
    }
    seen[a.type] = true;
    if (a.type === OID_CONTENT_TYPE) {
      ct += 1;
      if (a.values.length !== 1) throw NS.E("cms/bad-content-type-attr", "the content-type signed attribute must be single-valued");
      // ContentType ::= OBJECT IDENTIFIER (RFC 5652 §11.1) — validate the value's
      // full syntax (tag AND minimal base-128 OID content), not just the tag, so a
      // truncated / non-minimal subidentifier is rejected here, not at verify time.
      try { asn1.read.oid(asn1.decode(a.values[0])); }
      catch (e) { throw NS.E("cms/bad-content-type-attr", "the content-type signed attribute value must be a valid OBJECT IDENTIFIER", e); }
    } else if (a.type === OID_MESSAGE_DIGEST) {
      md += 1;
      if (a.values.length !== 1) throw NS.E("cms/bad-message-digest-attr", "the message-digest signed attribute must be single-valued");
      // MessageDigest ::= OCTET STRING (RFC 5652 §11.2) — validate the full syntax.
      try { asn1.read.octetString(asn1.decode(a.values[0])); }
      catch (e) { throw NS.E("cms/bad-message-digest-attr", "the message-digest signed attribute value must be an OCTET STRING", e); }
    }
  }
  // Duplicates are rejected in the loop (the seen-set); here only presence.
  if (ct === 0) throw NS.E("cms/missing-content-type", "signedAttrs must contain a content-type attribute (RFC 5652 §11.1)");
  if (md === 0) throw NS.E("cms/missing-message-digest", "signedAttrs must contain a message-digest attribute (RFC 5652 §11.2)");
}

// A CertificateChoices / RevocationInfoChoice element, surfaced RAW (its DER +
// outer tag) rather than recursively parsed — the obsolete CHOICE alternatives
// (extendedCertificate, attribute certs, otherRevocationInfo) never fail the
// parse, and a caller re-parses a `certificate`/`CertificateList` element itself.
function rawElement(item) {
  return { bytes: item.node.bytes, tagClass: item.node.tagClass, tagNumber: item.node.tagNumber };
}

// RFC 5652 §5.1 — the exact SignedData CMSVersion, computed from the raw
// CertificateChoices / RevocationInfoChoice outer tags (a certificate `other` is
// [3], a v2AttrCert [2], a v1AttrCert [1]; a RevocationInfoChoice `other` is [1]),
// the SignerInfo versions, and whether the content type is id-data.
function _expectedSignedDataVersion(certificates, crls, signerInfos, eContentType) {
  function ctx(el, n) { return el.tagClass === "context" && el.tagNumber === n; }
  var otherCert = certificates.some(function (c) { return ctx(c, 3); });
  var otherCrl = crls.some(function (c) { return ctx(c, 1); });
  if (otherCert || otherCrl) return 5;
  if (certificates.some(function (c) { return ctx(c, 2); })) return 4;   // v2AttrCert [2]
  if (certificates.some(function (c) { return ctx(c, 1); }) ||           // v1AttrCert [1]
      signerInfos.some(function (si) { return si.version === 3; }) ||
      eContentType !== OID_DATA) return 3;
  return 1;
}

// EncapsulatedContentInfo ::= SEQUENCE { eContentType OID,
//   eContent [0] EXPLICIT OCTET STRING OPTIONAL } (RFC 5652 §5.2). Absent eContent
// is a detached signature (surfaced as null); present is the raw content bytes.
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

// IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
// (RFC 5652 §10.2.4). serialNumberHex preserves the DER sign padding.
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

// SignerIdentifier ::= CHOICE { issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] IMPLICIT OCTET STRING } (RFC 5652 §5.3) — the arm is
// disambiguated by tag (universal SEQUENCE vs context [0]).
var SIGNER_IDENTIFIER = schema.choice([
  { when: { tagClass: "universal", tagNumber: asn1.TAGS.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitOctetString(0) },
], { code: "cms/bad-signer-identifier", what: "SignerIdentifier" });

// SignerInfo ::= SEQUENCE { version, sid SignerIdentifier, digestAlgorithm,
//   signedAttrs [0] IMPLICIT OPTIONAL, signatureAlgorithm, signature OCTET STRING,
//   unsignedAttrs [1] IMPLICIT OPTIONAL } (RFC 5652 §5.3). signedAttrs/unsignedAttrs
// are positional optionals (a required signatureAlgorithm sits between them, so
// they cannot be a trailing block).
var SIGNER_INFO = schema.seq([
  schema.field("version", SIGNER_VERSION),
  schema.field("sid", SIGNER_IDENTIFIER),
  schema.field("digestAlgorithm", ALGORITHM_IDENTIFIER),
  schema.optional("signedAttrs", schema.implicitSetOf(0, ATTRIBUTE, { min: 1, code: "cms/bad-signed-attrs", what: "signedAttrs" }), { tag: 0 }),
  schema.field("signatureAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("signature", schema.octetString()),
  schema.optional("unsignedAttrs", schema.implicitSetOf(1, ATTRIBUTE, { min: 1, code: "cms/bad-unsigned-attrs", what: "unsignedAttrs" }), { tag: 1 }),
], {
  assert: "sequence", code: "cms/bad-signer-info", what: "SignerInfo",
  build: function (m) {
    var version = m.fields.version.value;
    var sidNode = m.fields.sid.node;
    var isSkid = sidNode.tagClass === "context" && sidNode.tagNumber === 0;
    var sid;
    if (isSkid) {
      // RFC 5652 §5.3 — a subjectKeyIdentifier sid forces SignerInfo version 3.
      if (version !== 3) throw NS.E("cms/bad-signer-version", "a subjectKeyIdentifier signer identifier requires SignerInfo version 3");
      sid = { subjectKeyIdentifier: m.fields.sid.value };
    } else {
      // RFC 5652 §5.3 — an issuerAndSerialNumber sid forces SignerInfo version 1.
      if (version !== 1) throw NS.E("cms/bad-signer-version", "an issuerAndSerialNumber signer identifier requires SignerInfo version 1");
      sid = m.fields.sid.value.result;
    }
    var signedAttrs = null, signedAttrsBytes = null;
    if (m.fields.signedAttrs.present) {
      signedAttrs = m.fields.signedAttrs.value.items.map(function (it) { return it.value.result; });
      _checkSignedAttrs(signedAttrs);
      // The raw on-wire signedAttrs bytes (leading 0xA0) so a verifier can re-tag to
      // a universal SET and reproduce the signed hash (RFC 5652 §5.4).
      signedAttrsBytes = m.fields.signedAttrs.node.bytes;
    }
    return {
      version: version,
      sid: sid,
      digestAlgorithm: m.fields.digestAlgorithm.value.result,
      signedAttrs: signedAttrs,
      signedAttrsBytes: signedAttrsBytes,
      signatureAlgorithm: m.fields.signatureAlgorithm.value.result,
      signature: m.fields.signature.value,
      unsignedAttrs: m.fields.unsignedAttrs.present ? m.fields.unsignedAttrs.value.items.map(function (it) { return it.value.result; }) : null,
    };
  },
});

// SignedData ::= SEQUENCE { version CMSVersion, digestAlgorithms SET OF,
//   encapContentInfo, certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT
//   OPTIONAL, signerInfos SET OF } (RFC 5652 §5.1). digestAlgorithms and
//   signerInfos are min:0 — a degenerate certs-only SignedData carries neither.
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
    var certificates = m.fields.certificates.present ? m.fields.certificates.value.items.map(rawElement) : [];
    var crls = m.fields.crls.present ? m.fields.crls.value.items.map(rawElement) : [];
    var signerInfos = m.fields.signerInfos.value.items.map(function (it) { return it.value.result; });

    // RFC 5652 §5.3 — signedAttrs MAY be omitted only when the content type is
    // id-data; any other eContentType requires each SignerInfo to carry signedAttrs
    // (so the content-type + message-digest attributes bind the signature).
    if (encapContentInfo.eContentType !== OID_DATA) {
      for (var s = 0; s < signerInfos.length; s++) {
        if (signerInfos[s].signedAttrs === null) throw NS.E("cms/missing-signed-attrs", "a SignerInfo must carry signedAttrs when the content type is not id-data (RFC 5652 §5.3)");
      }
    }

    // RFC 5652 §5.3 — when signedAttrs are present, the content-type attribute's
    // value MUST equal the eContentType (a cross-field consistency both parsed
    // here; a mismatch is an internally-inconsistent SignedData).
    for (var si = 0; si < signerInfos.length; si++) {
      var sa = signerInfos[si].signedAttrs;
      if (!sa) continue;
      for (var ai = 0; ai < sa.length; ai++) {
        if (sa[ai].type !== OID_CONTENT_TYPE) continue;
        var ctv = asn1.read.oid(asn1.decode(sa[ai].values[0]));
        if (ctv !== encapContentInfo.eContentType) throw NS.E("cms/content-type-mismatch", "the content-type signed attribute (" + ctv + ") must equal the eContentType (" + encapContentInfo.eContentType + ") (RFC 5652 §5.3)");
      }
    }

    // RFC 5652 §5.1 — the SignedData CMSVersion is determined by its contents.
    var expected = _expectedSignedDataVersion(certificates, crls, signerInfos, encapContentInfo.eContentType);
    if (version !== expected) throw NS.E("cms/bad-version", "SignedData version " + version + " does not match its contents (RFC 5652 §5.1 requires v" + expected + ")");

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

// ==== EnvelopedData / EncryptedData (RFC 5652 §6/§8, RFC 5753) ========
var T = asn1.TAGS;

// EncryptedContentInfo ::= SEQUENCE { contentType OID, contentEncryptionAlgorithm
//   AlgorithmIdentifier, encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL } (RFC
//   5652 §6.1). encryptedContent is [0] IMPLICIT (context PRIMITIVE) — its content
//   octets ARE the ciphertext directly, so it reads through implicitOctetString(0),
//   NOT the [0] EXPLICIT shape ENCAP_CONTENT_INFO uses (which would double-strip a
//   length header). The ciphertext + algorithm parameters are surfaced RAW.
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

// RecipientIdentifier ::= CHOICE { issuerAndSerialNumber, subjectKeyIdentifier [0]
//   IMPLICIT OCTET STRING } (RFC 5652 §6.2.1) — structurally identical to
//   SignerIdentifier; reuse ISSUER_AND_SERIAL + the implicitOctetString(0) leaf.
var RECIPIENT_IDENTIFIER = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitOctetString(0) },
], { code: "cms/bad-recipient-identifier", what: "RecipientIdentifier" });

// KeyTransRecipientInfo ::= SEQUENCE { version(0|2), rid RecipientIdentifier,
//   keyEncryptionAlgorithm, encryptedKey OCTET STRING } (RFC 5652 §6.2.1).
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
    // RFC 5652 §6.2.1 — rid ⇔ version: issuerAndSerialNumber ⇒ 0, subjectKeyIdentifier ⇒ 2.
    if (isSkid && version !== 2) throw NS.E("cms/bad-recipient-version", "a subjectKeyIdentifier recipient identifier requires KeyTransRecipientInfo version 2 (RFC 5652 §6.2.1)");
    if (!isSkid && version !== 0) throw NS.E("cms/bad-recipient-version", "an issuerAndSerialNumber recipient identifier requires KeyTransRecipientInfo version 0 (RFC 5652 §6.2.1)");
    return {
      type: "ktri", version: version,
      rid: isSkid ? { subjectKeyIdentifier: m.fields.rid.value } : m.fields.rid.value.result,
      ridType: isSkid ? "subjectKeyIdentifier" : "issuerAndSerialNumber",
      keyEncryptionAlgorithm: m.fields.keyEncryptionAlgorithm.value.result,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

// OriginatorPublicKey ::= SEQUENCE { algorithm, publicKey BIT STRING } (RFC 5753
//   §3.1.1), reached as originatorKey [1] IMPLICIT — SPKI-shaped but cannot reuse
//   pkix.spki (which asserts a universal SEQUENCE), so assert:"constructed".
var ORIGINATOR_PUBLIC_KEY = schema.seq([
  schema.field("algorithm", ALGORITHM_IDENTIFIER),
  schema.field("publicKey", schema.bitString()),
], {
  assert: "constructed", code: "cms/bad-originator-public-key", what: "OriginatorPublicKey",
  build: function (m) { return { algorithm: m.fields.algorithm.value.result, publicKey: m.fields.publicKey.value }; },
});

// OriginatorIdentifierOrKey ::= CHOICE { issuerAndSerialNumber, subjectKeyIdentifier
//   [0] IMPLICIT OCTET STRING, originatorKey [1] IMPLICIT OriginatorPublicKey }.
var ORIGINATOR_IDENTIFIER_OR_KEY = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: schema.implicitOctetString(0) },
  { when: { tagClass: "context", tagNumber: 1 }, schema: ORIGINATOR_PUBLIC_KEY },
], { code: "cms/bad-originator-identifier", what: "OriginatorIdentifierOrKey" });

// RecipientKeyIdentifier (RFC 5652 §6.2.2) and KEKIdentifier (§6.2.3) are one
//   shape — { <keyId> OCTET STRING, date GeneralizedTime OPTIONAL, other
//   OtherKeyAttribute OPTIONAL } — differing only in the key-id field's name and
//   the enclosing tag form. One factory defines both so the OPTIONAL handling
//   (date and the raw-surfaced OtherKeyAttribute) cannot diverge between them.
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

// Reached as rKeyId [0] IMPLICIT (a SEQUENCE — constructed, unlike ktri's [0] leaf).
var RECIPIENT_KEY_IDENTIFIER = keyIdentifierSchema("subjectKeyIdentifier",
  "constructed", "cms/bad-recipient-key-identifier", "RecipientKeyIdentifier");

// KeyAgreeRecipientIdentifier ::= CHOICE { issuerAndSerialNumber, rKeyId [0] IMPLICIT
//   RecipientKeyIdentifier } (RFC 5652 §6.2.2).
var KEY_AGREE_RECIPIENT_IDENTIFIER = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: ISSUER_AND_SERIAL },
  { when: { tagClass: "context", tagNumber: 0 }, schema: RECIPIENT_KEY_IDENTIFIER },
], { code: "cms/bad-kari-identifier", what: "KeyAgreeRecipientIdentifier" });

// RecipientEncryptedKey ::= SEQUENCE { rid KeyAgreeRecipientIdentifier, encryptedKey
//   OCTET STRING } (RFC 5652 §6.2.2).
var RECIPIENT_ENCRYPTED_KEY = schema.seq([
  schema.field("rid", KEY_AGREE_RECIPIENT_IDENTIFIER),
  schema.field("encryptedKey", schema.octetString()),
], {
  assert: "sequence", code: "cms/bad-recipient-encrypted-key", what: "RecipientEncryptedKey",
  build: function (m) {
    var ridNode = m.fields.rid.node;
    var isRkid = ridNode.tagClass === "context" && ridNode.tagNumber === 0;
    return {
      rid: isRkid ? m.fields.rid.value.result : m.fields.rid.value.result,
      encryptedKey: m.fields.encryptedKey.value,
    };
  },
});

// KeyAgreeRecipientInfo ::= [1] IMPLICIT SEQUENCE { version(3), originator [0]
//   EXPLICIT OriginatorIdentifierOrKey, ukm [1] EXPLICIT OPTIONAL,
//   keyEncryptionAlgorithm, recipientEncryptedKeys SEQUENCE OF } (RFC 5652 §6.2.2 +
//   RFC 5753 §3.1.1). originator [0] is EXPLICIT (wraps a CHOICE).
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

// KEKRecipientInfo ::= [2] IMPLICIT SEQUENCE { version(4), kekid KEKIdentifier,
//   keyEncryptionAlgorithm, encryptedKey } (RFC 5652 §6.2.3).
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

// PasswordRecipientInfo ::= [3] IMPLICIT SEQUENCE { version(0), keyDerivationAlgorithm
//   [0] IMPLICIT AlgorithmIdentifier OPTIONAL, keyEncryptionAlgorithm, encryptedKey }
//   (RFC 5652 §6.2.4). keyDerivationAlgorithm [0] IMPLICIT is the one field needing
//   the implicitTag AlgorithmIdentifier; present iff the first post-version node is [0].
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

// OtherRecipientInfo ::= [4] IMPLICIT SEQUENCE { oriType OID, oriValue ANY } (RFC
//   5652 §6.2.5) — oriValue opaque, surfaced RAW (the shipped encoder routes
//   KEMRecipientInfo through here).
var OTHER_RECIPIENT_INFO = schema.seq([
  schema.field("oriType", schema.oidLeaf()),
  schema.field("oriValue", schema.any()),
], {
  assert: "constructed", code: "cms/bad-ori", what: "OtherRecipientInfo",
  build: function (m) { return { type: "ori", oriType: m.fields.oriType.value, oriValue: m.fields.oriValue.node.bytes }; },
});

// RecipientInfo ::= CHOICE { ktri KeyTransRecipientInfo, kari [1], kekri [2], pwri
//   [3], ori [4] } (RFC 5652 §6.2). A bare universal SEQUENCE is ktri (the untagged
//   alternative). An unknown context tag → no arm → cms/bad-recipient-info.
var RECIPIENT_INFO = schema.choice([
  { when: { tagClass: "universal", tagNumber: T.SEQUENCE }, schema: KEY_TRANS_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 1 }, schema: KEY_AGREE_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 2 }, schema: KEK_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 3 }, schema: PASSWORD_RECIPIENT_INFO },
  { when: { tagClass: "context", tagNumber: 4 }, schema: OTHER_RECIPIENT_INFO },
], { code: "cms/bad-recipient-info", what: "RecipientInfo" });

// OriginatorInfo ::= [0] IMPLICIT SEQUENCE { certs [0] IMPLICIT OPTIONAL, crls [1]
//   IMPLICIT OPTIONAL } (RFC 5652 §6.1). Members surfaced RAW (their outer tag feeds
//   the version rule).
var ORIGINATOR_INFO = schema.seq([
  schema.optional("certs", schema.implicitSetOf(0, schema.any(), { min: 1, code: "cms/bad-originator-certs", what: "certs" }), { tag: 0 }),
  schema.optional("crls", schema.implicitSetOf(1, schema.any(), { min: 1, code: "cms/bad-originator-crls", what: "crls" }), { tag: 1 }),
], {
  assert: "constructed", code: "cms/bad-originator-info", what: "OriginatorInfo",
  build: function (m) {
    return {
      certs: m.fields.certs.present ? m.fields.certs.value.items.map(rawElement) : [],
      crls: m.fields.crls.present ? m.fields.crls.value.items.map(rawElement) : [],
    };
  },
});

// RFC 5652 §6.1 — the exact EnvelopedData CMSVersion, from originatorInfo's raw
// cert/crl outer tags and the recipient arms (a cert `other` is [3], a v2AttrCert
// [2]; a crl `other` is [1]; a pwri or ori forces v3; all-ktri-IAS with no
// originatorInfo/unprotectedAttrs is v0; everything else v2).
function _expectedEnvelopedDataVersion(originatorInfo, recipientInfos, hasUnprotectedAttrs) {
  function ctx(el, n) { return el.tagClass === "context" && el.tagNumber === n; }
  var hasOrig = !!originatorInfo;
  var certs = hasOrig ? originatorInfo.certs : [];
  var crls = hasOrig ? originatorInfo.crls : [];
  if (hasOrig && (certs.some(function (c) { return ctx(c, 3); }) || crls.some(function (c) { return ctx(c, 1); }))) return 4;
  if ((hasOrig && certs.some(function (c) { return ctx(c, 2); })) ||
      recipientInfos.some(function (r) { return r.type === "pwri" || r.type === "ori"; })) return 3;
  if (!hasOrig && !hasUnprotectedAttrs &&
      recipientInfos.every(function (r) { return r.type === "ktri" && r.ridType === "issuerAndSerialNumber"; })) return 0;
  return 2;
}

// EnvelopedData ::= SEQUENCE { version, originatorInfo [0] IMPLICIT OPTIONAL,
//   recipientInfos RecipientInfos (SET SIZE 1..MAX), encryptedContentInfo,
//   unprotectedAttrs [1] IMPLICIT OPTIONAL } (RFC 5652 §6.1). recipientInfos is
//   min:1 (an empty SET is non-conformant — the INVERSE of SignedData's degenerate
//   signerInfos).
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
    if (version !== expected) throw NS.E("cms/bad-version", "EnvelopedData version " + version + " does not match its contents (RFC 5652 §6.1 requires v" + expected + ")");
    return {
      version: version,
      originatorInfo: originatorInfo,
      recipientInfos: recipientInfos,
      encryptedContentInfo: m.fields.encryptedContentInfo.value.result,
      unprotectedAttrs: hasUnprotectedAttrs ? m.fields.unprotectedAttrs.value.items.map(function (it) { return it.value.result; }) : null,
    };
  },
});

// EncryptedData ::= SEQUENCE { version, encryptedContentInfo, unprotectedAttrs [1]
//   IMPLICIT OPTIONAL } (RFC 5652 §8) — no recipients, no originatorInfo; the CEK is
//   distributed out of band. version is 0, or 2 iff unprotectedAttrs are present.
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
    if (version !== expected) throw NS.E("cms/bad-version", "EncryptedData version " + version + " does not match its contents (RFC 5652 §8 requires v" + expected + ")");
    return {
      version: version,
      encryptedContentInfo: m.fields.encryptedContentInfo.value.result,
      unprotectedAttrs: hasUnprotectedAttrs ? m.fields.unprotectedAttrs.value.items.map(function (it) { return it.value.result; }) : null,
    };
  },
});

// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY DEFINED BY
//   contentType } (RFC 5652 §3). The content is captured raw (explicit(0, any()))
//   and re-dispatched by contentType inside the build: id-signedData walks
//   SIGNED_DATA, id-envelopedData / id-encryptedData walk their schemas, the other
//   PKCS#7 types are recognized-and-deferred, unknown OIDs are rejected.
var CONTENT_INFO = schema.seq([
  schema.field("contentType", schema.oidLeaf()),
  schema.field("content", schema.explicit(0, schema.any(), { code: "cms/not-a-content-info" })),
], {
  assert: "sequence", arity: { exact: 2 }, code: "cms/not-a-content-info", what: "ContentInfo",
  build: function (m, ctx) {
    var ct = m.fields.contentType.value;
    if (ct === OID_SIGNED_DATA) return schema.walk(SIGNED_DATA, m.fields.content.value, ctx).result;
    if (ct === OID_ENVELOPED_DATA) return schema.walk(ENVELOPED_DATA, m.fields.content.value, ctx).result;
    if (ct === OID_ENCRYPTED_DATA) return schema.walk(ENCRYPTED_DATA, m.fields.content.value, ctx).result;
    if (DEFERRED.has(ct)) {
      throw NS.E("cms/unsupported-content-type", (ctx.oid.name(ct) || ct) + " is recognized but not parsed by this build");
    }
    throw NS.E("cms/unknown-content-type", "unrecognized ContentInfo content type " + ct);
  },
});

/**
 * @primitive  pki.schema.cms.parse
 * @signature  pki.schema.cms.parse(input) -> signedData
 * @since      0.1.10
 * @status     stable
 * @spec       RFC 5652
 * @related    pki.schema.parse, pki.schema.x509.parse
 *
 * Parse a DER `Buffer` or a PEM (`CMS`) string into a structured CMS SignedData:
 * `{ version, digestAlgorithms, encapContentInfo, certificates, crls,
 * signerInfos }`. `encapContentInfo.eContent` is the raw content (or `null` when
 * detached); each SignerInfo carries its raw `signature` and, when present, the
 * on-wire `signedAttrsBytes` for external verification. A ContentInfo whose type
 * is not `id-signedData` throws `cms/unsupported-content-type` (a recognized
 * PKCS#7 type) or `cms/unknown-content-type`; a malformed structure throws a typed
 * `CmsError` (`cms/*`) and a leaf-level codec fault surfaces as `asn1/*`.
 *
 * @example
 *   var cms = pki.schema.cms.parse(der);
 *   cms.signerInfos[0].sid.serialNumberHex;   // -> "0a1b..."
 *   cms.encapContentInfo.eContent;            // -> Buffer | null (detached)
 */
var parse = pkix.makeParser({ pemLabel: "CMS", PemError: PemError, ErrorClass: CmsError, prefix: "cms", what: "CMS ContentInfo", topSchema: CONTENT_INFO, ns: NS });

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
 *   var pem = pki.schema.cms.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "CMS", PemError); }

// A CMS ContentInfo root is the only registered structure whose root leads with an
// OBJECT IDENTIFIER child: a SEQUENCE of exactly 2 whose first child is an OID and
// second a context [0] constructed wrapper. x509/crl/csr lead with a tbs SEQUENCE
// and pkcs8 with an INTEGER, so the detectors are mutually exclusive regardless of
// registry order.
function matches(root) {
  var TAGS = asn1.TAGS;
  if (!root || root.tagClass !== "universal" || root.tagNumber !== TAGS.SEQUENCE) return false;
  var k = root.children;
  if (!k || k.length !== 2) return false;
  if (!(k[0].tagClass === "universal" && k[0].tagNumber === TAGS.OBJECT_IDENTIFIER)) return false;
  if (!(k[1].tagClass === "context" && k[1].tagNumber === 0 && k[1].children)) return false;
  return true;
}

module.exports = {
  parse: parse,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
};
