// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.schema.attrcert
 * @nav        Schema
 * @title      Attribute Cert
 * @order      175
 * @slug       attrcert
 *
 * @intro
 *   X.509 Attribute Certificate handling per RFC 5755. An attribute certificate
 *   binds a holder to a set of privilege attributes (role, group, clearance)
 *   without carrying a public key -- the authorization counterpart to an identity
 *   certificate. `parse` decodes a v2 `AttributeCertificate` into its holder,
 *   issuer, validity window (real `Date`s), attributes, and extensions, reusing
 *   the shared signed-envelope so the raw `tbsBytes` (the exact signed region) and
 *   the `signatureValue` are surfaced for a downstream verifier.
 *
 *   The holder and issuer identities are `GeneralName`s, validated on the way in
 *   (each alternative's form and content per RFC 5280 sec. 4.2.1.6) and surfaced with
 *   their raw bytes. The RFC 5755 sec. 4.2.3 issuer profile is enforced at parse: the
 *   issuer is `v2Form` (never `v1Form`) carrying exactly one non-empty
 *   `directoryName` in `issuerName`, with `baseCertificateID` / `objectDigestInfo`
 *   absent. The MUSTs above parse altitude (the holder-to-PKC binding, targeting
 *   and revocation) remain verification-layer concerns. The obsolete X.509-1997
 *   `AttributeCertificateV1` is recognized and deferred, not parsed. DER-only,
 *   fail-closed.
 *
 * @card
 *   Parse DER / PEM RFC 5755 attribute certificates into holder, issuer,
 *   validity, attributes, and extensions -- validated GeneralNames, raw verifier
 *   inputs, legacy v1 recognize-and-defer, fail-closed.
 */

var asn1 = require("./asn1-der");
var constants = require("./constants");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");

var AttrCertError = frameworkError.AttrCertError;
var PemError = frameworkError.PemError;

var NS = pkix.makeNS("attrcert", AttrCertError, oid);

var TAGS = asn1.TAGS;

var ALGORITHM_IDENTIFIER = pkix.algorithmIdentifier(NS);
var EXTENSIONS = pkix.extensions(NS);

// AttCertVersion ::= INTEGER { v2(1) } -- a bare, mandatory INTEGER (not the x509
// [0] EXPLICIT DEFAULT shape). The only legal value is v2, surfaced as 2.
var VERSION = pkix.versionReader(NS, { "1": 2 });

// ---- shared leaves ---------------------------------------------------

// AttCertValidityPeriod times are GeneralizedTime (RFC 5755 sec. 4.2.6) -- a UTCTime is
// rejected. Non-fractional YYYYMMDDHHMMSSZ is enforced by the codec.
var GENERALIZED_TIME = pkix.generalizedTime(NS, { code: "attrcert/bad-time", message: "AttCertValidityPeriod times must be GeneralizedTime (RFC 5755 sec. 4.2.6)" });

// digestedObjectType ::= ENUMERATED { publicKey(0), publicKeyCert(1),
// otherObjectTypes(2) } (RFC 5755 sec. 4.1) -- an undefined value is rejected; a
// non-ENUMERATED tag fails at the codec (asn1/*).
// objectDigestInfo digested-object-type names -- single source pki.C.NAMES.OBJECT_DIGEST_TYPE.
var ODT_NAMES = constants.NAMES.OBJECT_DIGEST_TYPE;
var DIGESTED_OBJECT_TYPE = schema.decode(function (n, ctx) {
  var v = asn1.read.enumerated(n);
  var k = v.toString();
  if (!Object.prototype.hasOwnProperty.call(ODT_NAMES, k)) {
    throw ctx.E("attrcert/bad-digested-object-type", "digestedObjectType " + k + " is not a defined value (RFC 5755 sec. 4.1)");
  }
  // RFC 5755 sec. 7.3 -- a conformant AC MUST NOT use otherObjectTypes(2); the digested
  // object is limited to a public key or a public-key certificate, so reject it
  // fail-closed rather than parse a digest whose object type is unidentifiable.
  if (k === "2") {
    throw ctx.E("attrcert/bad-digested-object-type", "otherObjectTypes(2) MUST NOT be used (RFC 5755 sec. 7.3)");
  }
  return { code: Number(v), name: ODT_NAMES[k] };
});

// ---- IssuerSerial / ObjectDigestInfo ---------------------------------

// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serial CertificateSerialNumber,
// issuerUID UniqueIdentifier OPTIONAL } (RFC 5755 sec. 4.1). Reached as an IMPLICIT
// [n] node (Holder [0] / V2Form [0]) whose tag replaces the SEQUENCE tag, so the
// shape assertion is "constructed" (the tag is pinned by the enclosing trailing);
// a context [n] PRIMITIVE node has no children and fails closed here.
var ISSUER_SERIAL = schema.seq([
  schema.field("issuer", pkix.generalNames(NS, { code: "attrcert/bad-issuer-serial" })),
  schema.field("serial", schema.integerLeaf()),
  schema.optional("issuerUID", schema.bitString(), { whenUniversal: [TAGS.BIT_STRING] }),
], {
  assert: "constructed", code: "attrcert/bad-issuer-serial", what: "IssuerSerial",
  build: function (m) {
    return {
      issuer: m.fields.issuer.value.result,
      serial: m.fields.serial.value,
      serialHex: m.fields.serial.node.content.toString("hex"),
      issuerUID: m.fields.issuerUID.present ? m.fields.issuerUID.value : null,
    };
  },
});

// ObjectDigestInfo ::= SEQUENCE { digestedObjectType ENUMERATED, otherObjectTypeID
// OBJECT IDENTIFIER OPTIONAL, digestAlgorithm AlgorithmIdentifier, objectDigest BIT
// STRING } (RFC 5755 sec. 4.1). otherObjectTypeID is present only for otherObjectTypes(2).
var OBJECT_DIGEST_INFO = schema.seq([
  schema.field("digestedObjectType", DIGESTED_OBJECT_TYPE),
  schema.optional("otherObjectTypeID", schema.oidLeaf(), { whenUniversal: [TAGS.OBJECT_IDENTIFIER] }),
  schema.field("digestAlgorithm", ALGORITHM_IDENTIFIER),
  schema.field("objectDigest", schema.bitString()),
], {
  assert: "constructed", code: "attrcert/bad-object-digest-info", what: "ObjectDigestInfo",
  build: function (m, ctx) {
    var t = m.fields.digestedObjectType.value;
    // otherObjectTypeID identifies a non-certificate object type, meaningful only with
    // otherObjectTypes(2) -- which RFC 5755 sec. 7.3 forbids (rejected at the leaf above) --
    // so a present otherObjectTypeID is never valid here and is rejected fail-closed.
    if (m.fields.otherObjectTypeID.present) {
      throw ctx.E("attrcert/bad-object-digest-info", "otherObjectTypeID is only valid with otherObjectTypes(2), which RFC 5755 sec. 7.3 forbids");
    }
    // The objectDigest is a whole-octet digest over the identified object; a
    // non-octet-aligned BIT STRING is malformed (RFC 5755 sec. 4.1) and has no
    // in-tree verify layer to catch it later, so reject it at parse.
    guard.crypto.assertOctetAligned(m.fields.objectDigest.value, ctx.E, "attrcert/bad-object-digest-info", "objectDigest");
    return {
      digestedObjectType: t,
      otherObjectTypeID: null,
      digestAlgorithm: m.fields.digestAlgorithm.value.result,
      objectDigest: m.fields.objectDigest.value,
    };
  },
});

// ---- Holder / AttCertIssuer / V2Form ---------------------------------

// Holder ::= SEQUENCE { baseCertificateID [0] IMPLICIT IssuerSerial OPTIONAL,
// entityName [1] IMPLICIT GeneralNames OPTIONAL, objectDigestInfo [2] IMPLICIT
// ObjectDigestInfo OPTIONAL } (RFC 5755 sec. 4.1). All three are IMPLICIT + OPTIONAL;
// the profile RECOMMENDS exactly one, but the parser surfaces all three (null when
// absent) and does not enforce the cardinality.
var HOLDER = schema.seq([
  schema.trailing([
    { tag: 0, name: "baseCertificateID", schema: ISSUER_SERIAL },
    { tag: 1, name: "entityName", schema: pkix.generalNames(NS, { implicitTag: 1, code: "attrcert/bad-entity-name" }) },
    { tag: 2, name: "objectDigestInfo", schema: OBJECT_DIGEST_INFO },
  ], { minTag: 0, maxTag: 2, unexpectedCode: "attrcert/bad-holder", orderCode: "attrcert/bad-holder" }),
], {
  assert: "sequence", code: "attrcert/bad-holder", what: "Holder",
  build: function (m) {
    return {
      baseCertificateID: m.fields.baseCertificateID.present ? m.fields.baseCertificateID.value.result : null,
      entityName: m.fields.entityName.present ? m.fields.entityName.value.result : null,
      objectDigestInfo: m.fields.objectDigestInfo.present ? m.fields.objectDigestInfo.value.result : null,
    };
  },
});

// V2Form ::= SEQUENCE { issuerName GeneralNames OPTIONAL, baseCertificateID [0]
// IMPLICIT IssuerSerial OPTIONAL, objectDigestInfo [1] IMPLICIT ObjectDigestInfo
// OPTIONAL } (RFC 5755 sec. 4.1). Reached via the AttCertIssuer CHOICE on a context [0]
// node, so the shape is "constructed". The build enforces the sec. 4.2.3 issuer
// profile MUSTs: every field is syntactically OPTIONAL, but a conformant AC's
// issuerName is present with one and only one GeneralName -- a non-empty
// directoryName -- and baseCertificateID / objectDigestInfo are absent.
var V2_FORM = schema.seq([
  schema.optional("issuerName", pkix.generalNames(NS, { code: "attrcert/bad-issuer-name" }), { whenUniversal: [TAGS.SEQUENCE] }),
  schema.trailing([
    { tag: 0, name: "baseCertificateID", schema: ISSUER_SERIAL },
    { tag: 1, name: "objectDigestInfo", schema: OBJECT_DIGEST_INFO },
  ], { minTag: 0, maxTag: 1, unexpectedCode: "attrcert/bad-v2form", orderCode: "attrcert/bad-v2form" }),
], {
  assert: "constructed", code: "attrcert/bad-v2form", what: "V2Form",
  build: function (m, ctx) {
    if (!m.fields.issuerName.present) {
      throw ctx.E("attrcert/bad-issuer-name", "v2Form must contain issuerName (RFC 5755 sec. 4.2.3)");
    }
    var issuerName = m.fields.issuerName.value.result;
    if (issuerName.names.length !== 1) {
      throw ctx.E("attrcert/bad-issuer-name", "issuerName must contain one and only one GeneralName (RFC 5755 sec. 4.2.3)");
    }
    if (issuerName.names[0].tagNumber !== 4) {
      throw ctx.E("attrcert/bad-issuer-name", "the issuerName GeneralName must be a directoryName [4] (RFC 5755 sec. 4.2.3)");
    }
    // directoryName [4] EXPLICIT wraps exactly one Name (the shared GeneralName
    // grammar validated that); a zero-RDN Name is an empty DN identifying no
    // issuer, which sec. 4.2.3 forbids.
    var dirName = asn1.decode(issuerName.names[0].bytes).children[0];
    if (!dirName.children || dirName.children.length < 1) {
      throw ctx.E("attrcert/bad-issuer-name", "the issuerName directoryName must be a non-empty distinguished name (RFC 5755 sec. 4.2.3)");
    }
    if (m.fields.baseCertificateID.present || m.fields.objectDigestInfo.present) {
      throw ctx.E("attrcert/bad-v2form", "baseCertificateID and objectDigestInfo must not be present in v2Form (RFC 5755 sec. 4.2.3)");
    }
    return { issuerName: issuerName, baseCertificateID: null, objectDigestInfo: null };
  },
});

// AttCertIssuer ::= CHOICE { v1Form GeneralNames, v2Form [0] IMPLICIT V2Form } (RFC
// 5755 sec. 4.1). A universal SEQUENCE is the (obsolete but structurally recognizable)
// v1Form, which a conformant AC MUST NOT use (sec. 4.2.3) -- the arm is recognized and
// rejected with a precise verdict rather than mis-dispatched; a context [0] is v2Form.
var ATT_CERT_ISSUER = schema.choice([
  { when: { tagClass: "universal", tagNumber: TAGS.SEQUENCE },
    schema: schema.decode(function (n, ctx) {
      throw ctx.E("attrcert/bad-issuer", "AttCertIssuer must use v2Form -- v1Form MUST NOT be used (RFC 5755 sec. 4.2.3)");
    }) },
  { when: { tagClass: "context", tagNumber: 0 }, schema: V2_FORM },
], { code: "attrcert/bad-issuer" });

// ---- validity + attributes -------------------------------------------

// AttCertValidityPeriod ::= SEQUENCE { notBeforeTime GeneralizedTime, notAfterTime
// GeneralizedTime } (RFC 5755 sec. 4.2.6).
var VALIDITY = schema.seq([
  schema.field("notBeforeTime", GENERALIZED_TIME),
  schema.field("notAfterTime", GENERALIZED_TIME),
], {
  assert: "sequence", arity: { exact: 2 }, code: "attrcert/bad-validity", what: "AttCertValidityPeriod",
  build: function (m) { return { notBeforeTime: m.fields.notBeforeTime.value, notAfterTime: m.fields.notAfterTime.value }; },
});

// attributes ::= SEQUENCE OF Attribute (RFC 5755 sec. 4.2.7) -- MUST be non-empty and
// each AttributeType OID unique. Order-preserving (SEQUENCE OF, not SET OF).
var ATTRIBUTES = schema.seqOf(pkix.attribute(NS), {
  assert: "sequence", min: 1, code: "attrcert/bad-attributes", what: "attributes",
  unique: function (it) { return it.value.result.type; }, dupCode: "attrcert/duplicate-attribute",
  build: function (m) { return m.items.map(function (it) { return it.value.result; }); },
});

// ---- AttributeCertificateInfo / AttributeCertificate -----------------

// AttributeCertificateInfo ::= SEQUENCE { version, holder, issuer, signature
// AlgorithmIdentifier, serialNumber, attrCertValidityPeriod, attributes,
// issuerUniqueID OPTIONAL, extensions OPTIONAL } (RFC 5755 sec. 4.1). The tbs body the
// signed envelope wraps; the cross-field invariants live in the envelope build.
var ACINFO = schema.seq([
  schema.field("version", VERSION),
  schema.field("holder", HOLDER),
  schema.field("issuer", ATT_CERT_ISSUER),
  schema.field("signature", ALGORITHM_IDENTIFIER),
  schema.field("serialNumber", schema.integerLeaf()),
  schema.field("attrCertValidityPeriod", VALIDITY),
  schema.field("attributes", ATTRIBUTES),
  schema.optional("issuerUniqueID", schema.bitString(), { whenUniversal: [TAGS.BIT_STRING] }),
  schema.optional("extensions", EXTENSIONS, { whenUniversal: [TAGS.SEQUENCE] }),
], { assert: "sequence", code: "attrcert/bad-acinfo", what: "AttributeCertificateInfo" });

// AttributeCertificate ::= SEQUENCE { acinfo, signatureAlgorithm, signatureValue
// BIT STRING } -- the shared SIGNED envelope (RFC 5755 sec. 4.1). The AC-specific
// invariants (sec. 4.2.4 sig-alg agreement, sec. 4.2.5 positive-and-<=20-octet serialNumber)
// run in the build; the envelope owns the SEQUENCE-of-3 shape + signature extraction.
var ATTRIBUTE_CERTIFICATE = pkix.signedEnvelope(NS, ACINFO, {
  code: "attrcert/not-an-attribute-certificate", what: "AttributeCertificate",
  build: function (e, ctx) {
    var acinfo = e.tbsMatch;

    // RFC 5755 sec. 4.2.4 -- the outer signatureAlgorithm MUST equal acinfo.signature.
    if (!e.outerSignatureAlgorithmBytes.equals(acinfo.fields.signature.node.bytes)) {
      throw ctx.E("attrcert/bad-signature-algorithm", "signatureAlgorithm must match AttributeCertificateInfo.signature (RFC 5755 sec. 4.2.4)");
    }

    // RFC 5755 sec. 4.2.5 -- serialNumber MUST be a positive INTEGER of at most 20 content
    // octets. Positive excludes both a negative (DER sign bit set) and zero (a minimal
    // INTEGER 0 is a single 0x00 octet -- the codec already rejected any non-minimal
    // zero). Surface it lossless (BigInt) + as hex.
    var serialNode = acinfo.fields.serialNumber.node;
    var sc = serialNode.content;
    if (sc.length === 0 || (sc[0] & 0x80) !== 0 || (sc.length === 1 && sc[0] === 0)) {
      throw ctx.E("attrcert/bad-serial-number", "serialNumber must be a positive INTEGER (RFC 5755 sec. 4.2.5)");
    }
    if (sc.length > 20) {
      throw ctx.E("attrcert/bad-serial-number", "serialNumber must not exceed 20 content octets (RFC 5755 sec. 4.2.5)");
    }

    // AttCertIssuer is a CHOICE whose v1Form arm rejects at the leaf (sec. 4.2.3), so
    // the surviving arm is always v2Form. The { form, v2Form, v1Form } shape is
    // kept stable for consumers keying off `form`.
    var issuer = { form: "v2Form", v2Form: acinfo.fields.issuer.value.result, v1Form: null };

    // RFC 5755 sec. 4.4 -- decode each attribute's value(s) additively: a recognized attribute type
    // gains `decoded` (parallel to `values`); an unrecognized type falls back to { opaque, bytes } so
    // the parse never fails on an unknown attribute, and a recognized-but-malformed value fails closed.
    var attributes = acinfo.fields.attributes.value.result;
    attributes.forEach(function (a) {
      var dec = _ATTR_VALUE_DECODERS[a.type];
      a.decoded = a.values.map(function (v) { return dec ? dec(v) : { opaque: true, bytes: v }; });
    });

    // RFC 5755 sec. 4.3 -- decode each AC extension additively (extensions[i].decoded), same opaque
    // fallback + fail-closed-on-malformed contract as the attributes above.
    var extField = acinfo.fields.extensions;
    var extensions = (extField && extField.present) ? extField.value.result : [];
    extensions.forEach(function (x) {
      var dec = _AC_EXT_DECODERS[x.oid];
      x.decoded = dec ? dec(x.value) : { opaque: true, bytes: x.value };
    });

    return {
      version:               acinfo.fields.version.value,     // 2
      holder:                acinfo.fields.holder.value.result,
      issuer:                issuer,
      signatureAlgorithm:    e.signatureAlgorithm,
      tbsSignatureAlgorithm: acinfo.fields.signature.value.result,
      serialNumber:          acinfo.fields.serialNumber.value,
      serialNumberHex:       sc.toString("hex"),
      validity:              acinfo.fields.attrCertValidityPeriod.value.result,
      attributes:            attributes,
      issuerUniqueID:        acinfo.fields.issuerUniqueID.present ? acinfo.fields.issuerUniqueID.value : null,
      extensions:            extensions,
      tbsBytes:              e.tbsBytes,
      signatureValue:        e.signatureValue,
    };
  },
});

// ---- parse -----------------------------------------------------------

/**
 * @primitive  pki.schema.attrcert.parse
 * @signature  pki.schema.attrcert.parse(input) -> attributeCertificate
 * @since      0.1.14
 * @status     stable
 * @spec       RFC 5755, X.509
 * @related    pki.schema.parse, pki.schema.x509.parse
 *
 * Parse a DER `Buffer` or a PEM string/Buffer (label `ATTRIBUTE CERTIFICATE`,
 * the OpenSSL armor) into a structured v2 attribute
 * certificate: `{ version, holder, issuer, signatureAlgorithm, serialNumber,
 * serialNumberHex, validity, attributes, issuerUniqueID, extensions, tbsBytes,
 * signatureValue }`. The holder / issuer identities come back as validated
 * `GeneralName`s (each element `{ bytes, tagClass, tagNumber }`); the validity
 * window is real `Date`s; `tbsBytes` is the exact signed byte range for a verifier.
 *
 * Throws `AttrCertError` when the bytes are not a well-formed attribute certificate
 * (an obsolete `AttributeCertificateV1` throws `attrcert/legacy-v1-not-supported`)
 * and `Asn1Error` when the underlying DER is malformed.
 *
 * @example
 *   var ac = pki.schema.attrcert.parse(der);
 *   ac.attributes[0].name;   // "role"
 *   ac.validity.notAfterTime;// Date
 */
var PARSE_OPTS = { pemLabel: "ATTRIBUTE CERTIFICATE", PemError: PemError, ErrorClass: AttrCertError, prefix: "attrcert", what: "attribute certificate" };

function _legacyV1Error() {
  return new AttrCertError("attrcert/legacy-v1-not-supported", "AttributeCertificateV1 (X.509-1997) is obsolete and not parsed by this build (RFC 5755 sec. 1)");
}

function parse(input) {
  var root = pkix.decodeRoot(pkix.coerceToDer(input, PARSE_OPTS), PARSE_OPTS);
  // A well-formed legacy AttributeCertificateV1 gets the advertised, stable
  // attrcert/legacy-v1-not-supported on the DIRECT path too -- not a low-level asn1/*
  // tag error from attempting the v2 walk -- so a direct caller of this entry sees the
  // same error family for the recognized-but-deferred form as the orchestrator does.
  if (matchesV1(root)) throw _legacyV1Error();
  return schema.walk(ATTRIBUTE_CERTIFICATE, root, NS).result;
}

// The obsolete X.509-1997 AttributeCertificateV1 (RFC 5652 sec. 10.2) is recognized and
// deferred: decode the envelope (so a malformed input still fails as bad DER), then
// throw the precise diagnostic rather than routing it to a wrong format.
function parseV1(input) {
  pkix.decodeRoot(pkix.coerceToDer(input, PARSE_OPTS), PARSE_OPTS);
  throw _legacyV1Error();
}

/**
 * @primitive  pki.schema.attrcert.pemDecode
 * @signature  pki.schema.attrcert.pemDecode(text, label?) -> Buffer
 * @since      0.1.14
 * @status     stable
 * @spec       RFC 7468, RFC 5755
 * @related    pki.schema.attrcert.parse
 *
 * Extract the DER bytes from a PEM block (default label
 * `ATTRIBUTE CERTIFICATE`, the OpenSSL armor -- the canonical-label default
 * every sibling format applies). Pass a `label` to enforce a different block
 * type, or an explicit `null` to take the first block of any type. Throws
 * `PemError` on a missing / mismatched envelope or a non-base64 body.
 *
 * @example
 *   var der = pki.schema.attrcert.pemDecode(pemText);
 */
function pemDecode(text, label) { return pkix.pemDecode(text, label === null ? null : (label || "ATTRIBUTE CERTIFICATE"), PemError); }

/**
 * @primitive  pki.schema.attrcert.pemEncode
 * @signature  pki.schema.attrcert.pemEncode(der, label?) -> string
 * @since      0.1.23
 * @status     stable
 * @spec       RFC 7468, RFC 5755
 * @related    pki.schema.attrcert.pemDecode
 *
 * Wrap DER bytes in a PEM envelope (default label `ATTRIBUTE CERTIFICATE`, the
 * same default `pemDecode` reads). Throws `PemError` on a malformed label.
 *
 * @example
 *   var pem = pki.schema.attrcert.pemEncode(der);
 */
function pemEncode(der, label) { return pkix.pemEncode(der, label || "ATTRIBUTE CERTIFICATE", PemError); }

// matches(root): a v2 AttributeCertificate is the signed-envelope trio whose acinfo
// LEADS WITH a bare universal INTEGER version (== v2 = 1, NOT the x509 [0] EXPLICIT
// wrapper) and whose attrCertValidityPeriod at children[5] is a SEQUENCE of exactly
// two GeneralizedTime (RFC 5755 sec. 4.2.6 forbids UTCTime) -- a marker no cert / CRL /
// CSR presents at that position. Disjoint from matchesV1 by the children[0] tag class.
function matches(root) {
  var acinfo = pkix.signedEnvelopeTbs(root);
  if (!acinfo) return false;
  var k = acinfo.children;
  if (!k || k.length < 7) return false;
  if (!schema.isUniversal(k[0], TAGS.INTEGER)) return false;
  if (!(schema.isUniversal(k[1], TAGS.SEQUENCE) && k[1].children)) return false;
  var v = k[5];
  if (!(schema.isUniversal(v, TAGS.SEQUENCE) && v.children && v.children.length === 2)) return false;
  return v.children.every(function (t) { return schema.isUniversal(t, TAGS.GENERALIZED_TIME); });
}

// matchesV1(root): the obsolete AttributeCertificateV1 -- its acInfo (version DEFAULT
// v1 OMITTED) LEADS WITH the subject CHOICE (a context [0]/[1]), and its children[1]
// is the issuer GeneralNames (a universal SEQUENCE). The children[1] == SEQUENCE test
// keeps it disjoint from a v3 certificate (whose [0] EXPLICIT version is followed by
// an INTEGER serialNumber), so v1-vs-cert dispatch is order-independent.
function matchesV1(root) {
  var acinfo = pkix.signedEnvelopeTbs(root);
  if (!acinfo) return false;
  var k = acinfo.children;
  if (!k || k.length < 6) return false;
  if (!(schema.isContextOneOf(k[0], [0, 1]) && k[0].children)) return false;
  return schema.isUniversal(k[1], TAGS.SEQUENCE);
}

// ---- RFC 5755 sec. 4.4 attribute-value decoders ----------------------
// A per-attribute-type decoder table (mirroring pkix.certExtensionDecoders): each takes the raw
// AttributeValue TLV Buffer and returns a structured value, throwing a typed attrcert/bad-* error on
// any non-conformant shape. Composes pkix's shared imperative helpers + generalName/generalNames.
// A single GeneralName decodes as the walk OBJECT itself (gn.tagNumber / gn.value); generalNames
// (plural) returns { names:[...] } on .result.
var _AV = pkix._decodeHelpers(NS);
var _decodeTop = _AV.decodeTop, _seqChildren = _AV.seqChildren, _readInt = _AV.readInt, _Oav = _AV.O;
var _GN = pkix.generalName(NS, { decodeValue: true, code: "attrcert/bad-general-name" });
var _GNS_0 = pkix.generalNames(NS, { implicitTag: 0, decodeValue: true, code: "attrcert/bad-general-names" });
function _isCtx(node, n) { return node && node.tagClass === "context" && node.tagNumber === n; }
function _isU(node, tag) { return node && node.tagClass === "universal" && node.tagNumber === tag; }
function _oneGN(node, code) {
  if (!_isCtx(node, 0) && !_isCtx(node, 1) && !_isCtx(node, 2) && !_isCtx(node, 3) &&
      !_isCtx(node, 4) && !_isCtx(node, 5) && !_isCtx(node, 6) && !_isCtx(node, 7) && !_isCtx(node, 8)) {
    throw NS.E(code, "a GeneralName must be a context-tagged [0]..[8] CHOICE alternative");
  }
  var gn = schema.walk(_GN, node, NS);
  return { tagNumber: gn.tagNumber, value: gn.value };
}

// SvceAuthInfo ::= SEQUENCE { service GeneralName, ident GeneralName, authInfo OCTET STRING OPTIONAL }
// -- authenticationInfo (sec. 4.4.1) allows authInfo; accessIdentity (sec. 4.4.2) MUST omit it.
function _svceAuthInfo(authInfoAllowed, code) {
  return function (buf) {
    var kids = _seqChildren(buf, code, "SvceAuthInfo");
    if (kids.length < 2 || kids.length > 3) throw NS.E(code, "SvceAuthInfo must be a SEQUENCE { service, ident, authInfo? }");
    var service = _oneGN(kids[0], code);
    var ident = _oneGN(kids[1], code);
    var authInfo = null;
    if (kids.length === 3) {
      if (!authInfoAllowed) throw NS.E(code, "this attribute must not carry authInfo (RFC 5755 sec. 4.4.2)");
      if (!_isU(kids[2], TAGS.OCTET_STRING)) throw NS.E(code, "SvceAuthInfo authInfo must be an OCTET STRING");
      authInfo = Buffer.concat([asn1.read.octetString(kids[2])]);
    }
    return { service: service, ident: ident, authInfo: authInfo };
  };
}

// IetfAttrSyntax ::= SEQUENCE { policyAuthority [0] IMPLICIT GeneralNames OPTIONAL,
//   values SEQUENCE OF CHOICE { octets OCTET STRING, oid OBJECT IDENTIFIER, string UTF8String } }
function _ietfAttrSyntax(buf) {
  var C = "attrcert/bad-ietf-attr";
  var kids = _seqChildren(buf, C, "IetfAttrSyntax");
  if (!kids.length || kids.length > 2) throw NS.E(C, "IetfAttrSyntax must be a SEQUENCE { policyAuthority [0]?, values }");
  var policyAuthority = null, i = 0;
  if (_isCtx(kids[0], 0)) { policyAuthority = schema.walk(_GNS_0, kids[0], NS).result; i = 1; }
  var valuesNode = kids[i];
  if (!valuesNode || !_isU(valuesNode, TAGS.SEQUENCE) || !valuesNode.children || !valuesNode.children.length) {
    throw NS.E(C, "IetfAttrSyntax values must be a non-empty SEQUENCE OF value");
  }
  if (i + 1 !== kids.length) throw NS.E(C, "IetfAttrSyntax has unexpected trailing fields (a [0] must precede values)");
  var kinds = {};
  var values = valuesNode.children.map(function (v) {
    if (_isU(v, TAGS.OCTET_STRING)) { kinds.octets = true; return { kind: "octets", value: Buffer.concat([asn1.read.octetString(v)]) }; }
    if (_isU(v, TAGS.OBJECT_IDENTIFIER)) { kinds.oid = true; return { kind: "oid", value: asn1.read.oid(v) }; }
    if (_isU(v, TAGS.UTF8_STRING)) { kinds.string = true; return { kind: "string", value: asn1.read.string(v) }; }
    throw NS.E(C, "IetfAttrSyntax value must be an OCTET STRING, OBJECT IDENTIFIER, or UTF8String");
  });
  return { policyAuthority: policyAuthority, values: values, homogeneous: Object.keys(kinds).length === 1 };
}

// RoleSyntax ::= SEQUENCE { roleAuthority [0] IMPLICIT GeneralNames OPTIONAL, roleName [1] EXPLICIT GeneralName }
function _role(buf) {
  var C = "attrcert/bad-role";
  var kids = _seqChildren(buf, C, "RoleSyntax");
  if (!kids.length || kids.length > 2) throw NS.E(C, "RoleSyntax must be a SEQUENCE { roleAuthority [0]?, roleName [1] }");
  var roleAuthority = null, i = 0;
  if (_isCtx(kids[0], 0)) { roleAuthority = schema.walk(_GNS_0, kids[0], NS).result; i = 1; }
  var rn = kids[i];
  if (!_isCtx(rn, 1) || !rn.children || rn.children.length !== 1) throw NS.E(C, "RoleSyntax roleName must be an EXPLICIT [1] wrapping exactly one GeneralName");
  if (i + 1 !== kids.length) throw NS.E(C, "RoleSyntax has unexpected trailing fields");
  return { roleAuthority: roleAuthority, roleName: _oneGN(rn.children[0], C) };
}

// Clearance ::= SEQUENCE { policyId OBJECT IDENTIFIER, classList ClassList DEFAULT {unclassified},
//   securityCategories SET OF SecurityCategory OPTIONAL }.
// ClassList ::= BIT STRING { unmarked(0), unclassified(1), restricted(2), confidential(3), secret(4), topSecret(5) }.
var _CLASSLIST_NAMES = ["unmarked", "unclassified", "restricted", "confidential", "secret", "topSecret"];
function _decodeClassList(node, C) {
  var bs;
  try { bs = asn1.read.bitString(node); } catch (e) { throw NS.E(C, "Clearance classList must be a BIT STRING", e); }
  schema.assertMinimalNamedBits(bs.unusedBits, bs.bytes, function (m) { throw NS.E(C, m); });
  var names = [], flags = {}, reserved = [];
  var total = bs.bytes.length * 8 - bs.unusedBits;
  for (var bit = 0; bit < total; bit++) {
    if ((bs.bytes[bit >> 3] & (0x80 >> (bit & 7))) === 0) continue;
    if (bit < _CLASSLIST_NAMES.length) { names.push(_CLASSLIST_NAMES[bit]); flags[_CLASSLIST_NAMES[bit]] = true; }
    else reserved.push(bit);
  }
  return { names: names, flags: flags, reservedBits: reserved };
}
// SecurityCategory ::= SEQUENCE { type [0] IMPLICIT OBJECT IDENTIFIER, value [1] EXPLICIT ANY }.
function _securityCategory(node, C) {
  if (!_isU(node, TAGS.SEQUENCE) || !node.children || node.children.length !== 2) throw NS.E(C, "a SecurityCategory must be a SEQUENCE of a type and a value");
  var typeNode = node.children[0], valueNode = node.children[1];
  if (!_isCtx(typeNode, 0) || typeNode.children) throw NS.E(C, "SecurityCategory type must be a primitive [0] IMPLICIT OBJECT IDENTIFIER");
  var type; try { type = asn1.decodeOidContent(typeNode.content); } catch (e) { throw NS.E(C, "SecurityCategory type is not a valid OBJECT IDENTIFIER", e); }
  if (!_isCtx(valueNode, 1) || !valueNode.children || valueNode.children.length !== 1) throw NS.E(C, "SecurityCategory value must be an EXPLICIT [1] wrapping one element");
  return { type: type, valueBytes: Buffer.concat([valueNode.children[0].bytes]) };
}
function _clearance(buf) {
  var C = "attrcert/bad-clearance";
  var kids = _seqChildren(buf, C, "Clearance");
  if (!kids.length || kids.length > 3) throw NS.E(C, "Clearance must be a SEQUENCE { policyId, classList?, securityCategories? }");
  if (!_isU(kids[0], TAGS.OBJECT_IDENTIFIER)) throw NS.E(C, "Clearance policyId must be an OBJECT IDENTIFIER");
  var policyId; try { policyId = asn1.read.oid(kids[0]); } catch (e) { throw NS.E(C, "Clearance policyId must be an OBJECT IDENTIFIER", e); }
  var classList = { names: ["unclassified"], flags: { unclassified: true }, reservedBits: [] }, i = 1;   // DEFAULT {unclassified}
  if (kids[i] && _isU(kids[i], TAGS.BIT_STRING)) {
    classList = _decodeClassList(kids[i], C);
    if (classList.names.length === 1 && classList.flags.unclassified && !classList.reservedBits.length) {
      throw NS.E(C, "Clearance classList equal to the DEFAULT {unclassified} must be omitted (non-canonical DER)");
    }
    i++;
  }
  var securityCategories = null;
  if (kids[i]) {
    var setNode = kids[i];
    if (!_isU(setNode, TAGS.SET) || !setNode.children || !setNode.children.length) throw NS.E(C, "Clearance securityCategories must be a non-empty SET OF SecurityCategory");
    securityCategories = setNode.children.map(function (categoryNode) { return _securityCategory(categoryNode, C); });
    i++;
  }
  if (i !== kids.length) throw NS.E(C, "Clearance has fields out of order or unexpected trailing fields");
  return { policyId: policyId, classList: classList, securityCategories: securityCategories };
}

var _ATTR_VALUE_DECODERS = {};
_ATTR_VALUE_DECODERS[_Oav("role")] = _role;
_ATTR_VALUE_DECODERS[_Oav("clearance")] = _clearance;
// RFC 5755 sec. 4.4.6 requires decoding the legacy RFC 3281 id-at-clearance too (the X.501
// selected-attribute-types arc, an alias of "clearance" -- built from arcs, never a dotted literal).
_ATTR_VALUE_DECODERS[oid.fromArcs([2, 5, 1, 5, 55])] = _clearance;
_ATTR_VALUE_DECODERS[_Oav("authenticationInfo")] = _svceAuthInfo(true, "attrcert/bad-svce-auth-info");
_ATTR_VALUE_DECODERS[_Oav("accessIdentity")] = _svceAuthInfo(false, "attrcert/bad-access-identity");
_ATTR_VALUE_DECODERS[_Oav("chargingIdentity")] = _ietfAttrSyntax;
_ATTR_VALUE_DECODERS[_Oav("group")] = _ietfAttrSyntax;

// ---- RFC 5755 sec. 4.3 AC-extension decoders -------------------------
// A per-extension-OID decoder table for the AC-specific extensions (kept in the AC domain, not the
// shared cert-extension table, because Targets/TargetCert reuse the local IssuerSerial). Each takes
// the raw extnValue content Buffer and returns a structured value, fail-closed with a typed error.

// AuditIdentity ::= OCTET STRING (sec. 4.3.1) -- an opaque audit tag, unconstrained (no SIZE), so an
// empty OCTET STRING (04 00) is valid; only the OCTET STRING type is enforced.
function _acAuditIdentity(buf) {
  var C = "attrcert/bad-audit-identity";
  var n = _decodeTop(buf, C, "AuditIdentity");
  if (!_isU(n, TAGS.OCTET_STRING)) throw NS.E(C, "AuditIdentity must be an OCTET STRING");
  return Buffer.concat([asn1.read.octetString(n)]);
}

// NoRevAvail syntax is NULL (sec. 4.3.6: '0500'H is the DER encoding) -- the extnValue OCTET STRING
// contains a DER NULL. An empty or any-other-shape value is malformed and fails closed.
function _noRevAvail(buf) {
  var C = "attrcert/bad-no-rev-avail";
  var n = _decodeTop(buf, C, "NoRevAvail");
  try { asn1.read.nullValue(n); } catch (e) { throw NS.E(C, "NoRevAvail must be a DER NULL (RFC 5755 sec. 4.3.6)", e); }
  return { noRevAvail: true };
}

// Target ::= CHOICE { targetName [0] GeneralName, targetGroup [1] GeneralName, targetCert [2] TargetCert }.
// [0]/[1] wrap a GeneralName CHOICE (EXPLICIT); [2] is an IMPLICIT TargetCert SEQUENCE.
function _acTargetCert(node, C) {
  if (!node.children || !node.children.length) throw NS.E(C, "a targetCert [2] must be a non-empty TargetCert SEQUENCE");
  var out = { kind: "targetCert", targetCertificate: null, targetName: null, certDigestInfo: null }, i = 0;
  out.targetCertificate = schema.walk(ISSUER_SERIAL, node.children[i++], NS).result;
  if (node.children[i] && node.children[i].tagClass === "context") out.targetName = _oneGN(node.children[i++], C);
  if (node.children[i] && _isU(node.children[i], TAGS.SEQUENCE)) out.certDigestInfo = schema.walk(OBJECT_DIGEST_INFO, node.children[i++], NS).result;
  if (i !== node.children.length) throw NS.E(C, "a targetCert has unexpected trailing fields");
  return out;
}
function _acTarget(node, C, allowTargetCert) {
  if (_isCtx(node, 0) || _isCtx(node, 1)) {
    if (!node.children || node.children.length !== 1) throw NS.E(C, "a Target name must be an EXPLICIT [0]/[1] wrapping one GeneralName");
    return { kind: node.tagNumber === 0 ? "targetName" : "targetGroup", name: _oneGN(node.children[0], C) };
  }
  if (_isCtx(node, 2)) {
    if (!allowTargetCert) throw NS.E(C, "the targetCert [2] CHOICE MUST NOT be used in proxying information (RFC 5755 sec. 7.4)");
    return _acTargetCert(node, C);
  }
  throw NS.E(C, "a Target must be [0] targetName, [1] targetGroup, or [2] targetCert");
}
// Targets ::= SEQUENCE OF Target -- decode a Targets SEQUENCE node into an array of Target.
function _acDecodeTargets(node, C, allowTargetCert) {
  if (!_isU(node, TAGS.SEQUENCE) || !node.children || !node.children.length) throw NS.E(C, "Targets must be a non-empty SEQUENCE OF Target");
  return node.children.map(function (t) { return _acTarget(t, C, allowTargetCert); });
}
// Both targetInformation (sec. 4.3.2) and ProxyInfo (sec. 7.4) are SEQUENCE OF Targets -- an outer
// SEQUENCE whose every element is itself a Targets (SEQUENCE OF Target). A conforming issuer emits one
// Targets, but users MUST accept several. proxying additionally forbids the targetCert [2] alternative.
function _seqOfTargets(buf, C, allowTargetCert) {
  var kids = _seqChildren(buf, C, "SEQUENCE OF Targets");
  if (!kids.length) throw NS.E(C, "a SEQUENCE OF Targets must be non-empty");
  return kids.map(function (targetsNode) { return _acDecodeTargets(targetsNode, C, allowTargetCert); });
}
function _targetInformation(buf) { return _seqOfTargets(buf, "attrcert/bad-targets", true); }
function _acProxying(buf) { return _seqOfTargets(buf, "attrcert/bad-proxy-info", false); }

// AAControls ::= SEQUENCE { pathLenConstraint INTEGER (0..MAX) OPTIONAL, permittedAttrs [0] AttrSpec
//   OPTIONAL, excludedAttrs [1] AttrSpec OPTIONAL, permitUnSpecified BOOLEAN DEFAULT TRUE }.
// AttrSpec ::= SEQUENCE OF OBJECT IDENTIFIER (the [0]/[1] IMPLICIT tag replaces the SEQUENCE tag).
function _acAttrSpec(node, C) {
  if (!node.children) throw NS.E(C, "an AttrSpec must be a SEQUENCE OF OBJECT IDENTIFIER");
  return node.children.map(function (o) {
    if (!_isU(o, TAGS.OBJECT_IDENTIFIER)) throw NS.E(C, "an AttrSpec element must be an OBJECT IDENTIFIER");
    try { return asn1.read.oid(o); } catch (e) { throw NS.E(C, "an AttrSpec element must be an OBJECT IDENTIFIER", e); }
  });
}
function _aaControls(buf) {
  var C = "attrcert/bad-aa-controls";
  var kids = _seqChildren(buf, C, "AAControls");
  if (kids.length > 4) throw NS.E(C, "AAControls has too many fields");
  var out = { pathLenConstraint: null, permittedAttrs: null, excludedAttrs: null, permitUnSpecified: true }, i = 0;
  if (kids[i] && _isU(kids[i], TAGS.INTEGER)) { out.pathLenConstraint = guard.range.uint31(_readInt(kids[i], C, "pathLenConstraint"), NS.E, C, "AAControls pathLenConstraint"); i++; }
  if (kids[i] && _isCtx(kids[i], 0)) { out.permittedAttrs = _acAttrSpec(kids[i], C); i++; }
  if (kids[i] && _isCtx(kids[i], 1)) { out.excludedAttrs = _acAttrSpec(kids[i], C); i++; }
  if (kids[i] && _isU(kids[i], TAGS.BOOLEAN)) {
    var v = asn1.read.boolean(kids[i]);
    if (v === true) throw NS.E(C, "AAControls permitUnSpecified TRUE equals the DEFAULT and must be omitted (non-canonical DER)");
    out.permitUnSpecified = v; i++;
  }
  if (i !== kids.length) throw NS.E(C, "AAControls has fields out of order or unexpected trailing fields");
  return out;
}

var _AC_EXT_DECODERS = {};
_AC_EXT_DECODERS[_Oav("acAuditIdentity")] = _acAuditIdentity;
_AC_EXT_DECODERS[_Oav("targetInformation")] = _targetInformation;
_AC_EXT_DECODERS[_Oav("noRevAvail")] = _noRevAvail;
_AC_EXT_DECODERS[_Oav("aaControls")] = _aaControls;
_AC_EXT_DECODERS[_Oav("acProxying")] = _acProxying;

// @internal -- validate a pre-encoded AC attribute value / AC extension value against the SAME decoder
// the parser runs, so the attrcert-sign escape hatches (a caller's pre-encoded Attribute / Extension DER)
// cannot embed a structurally-malformed recognized value the strict parser would then reject. `type` /
// `extnOid` are dotted-OID strings; `valueDer` / `extnValueDer` are the raw AttributeValue / extnValue
// content Buffers (exactly what the parse loop passes). An unrecognized type returns null (stays opaque,
// no validation); a recognized-but-malformed value throws the frozen attrcert/bad-* code.
function validateAttributeValue(type, valueDer) {
  var dec = _ATTR_VALUE_DECODERS[type];
  return dec ? dec(valueDer) : null;
}
function validateExtensionValue(extnOid, extnValueDer) {
  var dec = _AC_EXT_DECODERS[extnOid];
  return dec ? dec(extnValueDer) : null;
}

module.exports = {
  parse: parse,
  parseV1: parseV1,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  matchesV1: matchesV1,
  validateAttributeValue: validateAttributeValue,
  validateExtensionValue: validateExtensionValue,
};
