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
 *   CMS SignedData handling per RFC 5652 (§3 ContentInfo envelope, §5 SignedData).
 *   `parse` turns a DER or PEM (`CMS`) message into a structured object: the
 *   SignedData version, the digest algorithms, the encapsulated content, the
 *   certificate / CRL sets, and the signer infos. It is an OID-dispatch envelope —
 *   ContentInfo reads its `contentType` and structurally decodes only
 *   `id-signedData`; the other PKCS#7 content types (EnvelopedData, EncryptedData,
 *   …) are recognized and rejected with a precise `cms/unsupported-content-type`
 *   rather than a generic unknown-format error.
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

// id-signedData is the one content type this build structurally decodes; the rest
// are recognized-and-deferred (a precise diagnostic, not a silent unknown-format).
// OIDs resolve from the registry (pkcs7 / smimeCt families), never dotted literals.
var OID_SIGNED_DATA = oid.byName("signedData");
var DEFERRED = new Set([
  oid.byName("data"), oid.byName("envelopedData"), oid.byName("signedAndEnvelopedData"),
  oid.byName("digestedData"), oid.byName("encryptedData"), oid.byName("authData"),
]);
// The two mandatory signed-attribute types (RFC 5652 §5.3, §11.1/§11.2).
var OID_CONTENT_TYPE = oid.byName("contentType");
var OID_MESSAGE_DIGEST = oid.byName("messageDigest");

// Enforce the SignedAttributes value constraints (RFC 5652 §5.3, §11) — the
// content-type attribute is single-valued and appears once, and the message-digest
// appears once. The content-type value == eContentType and messageDigest == the
// actual content hash are §5.6 VERIFICATION concerns (surfaced, checked by the
// verifier), not structural-parse concerns.
function _checkSignedAttrs(attrs) {
  var ct = 0, md = 0;
  for (var i = 0; i < attrs.length; i++) {
    var a = attrs[i];
    if (a.type === OID_CONTENT_TYPE) {
      ct += 1;
      if (a.values.length !== 1) throw NS.E("cms/bad-content-type-attr", "the content-type signed attribute must be single-valued");
    } else if (a.type === OID_MESSAGE_DIGEST) {
      md += 1;
      if (a.values.length !== 1) throw NS.E("cms/bad-message-digest-attr", "the message-digest signed attribute must be single-valued");
    }
  }
  if (ct > 1) throw NS.E("cms/duplicate-content-type", "signedAttrs must not repeat the content-type attribute");
  if (md > 1) throw NS.E("cms/duplicate-message-digest", "signedAttrs must not repeat the message-digest attribute");
}

// A CertificateChoices / RevocationInfoChoice element, surfaced RAW (its DER +
// outer tag) rather than recursively parsed — the obsolete CHOICE alternatives
// (extendedCertificate, attribute certs, otherRevocationInfo) never fail the
// parse, and a caller re-parses a `certificate`/`CertificateList` element itself.
function rawElement(item) {
  return { bytes: item.node.bytes, tagClass: item.node.tagClass, tagNumber: item.node.tagNumber };
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
    return {
      version: m.fields.version.value,
      digestAlgorithms: m.fields.digestAlgorithms.value.items.map(function (it) { return it.value.result; }),
      encapContentInfo: m.fields.encapContentInfo.value.result,
      certificates: m.fields.certificates.present ? m.fields.certificates.value.items.map(rawElement) : [],
      crls: m.fields.crls.present ? m.fields.crls.value.items.map(rawElement) : [],
      signerInfos: m.fields.signerInfos.value.items.map(function (it) { return it.value.result; }),
    };
  },
});

// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY DEFINED BY
//   contentType } (RFC 5652 §3). The content is captured raw (explicit(0, any()))
//   and re-dispatched by contentType inside the build: id-signedData walks
//   SIGNED_DATA, the other PKCS#7 types are recognized-and-deferred, unknown OIDs
//   are rejected.
var CONTENT_INFO = schema.seq([
  schema.field("contentType", schema.oidLeaf()),
  schema.field("content", schema.explicit(0, schema.any(), { code: "cms/not-a-content-info" })),
], {
  assert: "sequence", arity: { exact: 2 }, code: "cms/not-a-content-info", what: "ContentInfo",
  build: function (m, ctx) {
    var ct = m.fields.contentType.value;
    if (ct === OID_SIGNED_DATA) return schema.walk(SIGNED_DATA, m.fields.content.value, ctx).result;
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
 * @status     experimental
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
 * @status     experimental
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
 * @status     experimental
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
