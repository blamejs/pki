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
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");
var oid = require("./oid");
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
var ODT_NAMES = { "0": "publicKey", "1": "publicKeyCert", "2": "otherObjectTypes" };
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

    var extField = acinfo.fields.extensions;
    return {
      version:               acinfo.fields.version.value,     // 2
      holder:                acinfo.fields.holder.value.result,
      issuer:                issuer,
      signatureAlgorithm:    e.signatureAlgorithm,
      tbsSignatureAlgorithm: acinfo.fields.signature.value.result,
      serialNumber:          acinfo.fields.serialNumber.value,
      serialNumberHex:       sc.toString("hex"),
      validity:              acinfo.fields.attrCertValidityPeriod.value.result,
      attributes:            acinfo.fields.attributes.value.result,
      issuerUniqueID:        acinfo.fields.issuerUniqueID.present ? acinfo.fields.issuerUniqueID.value : null,
      extensions:            (extField && extField.present) ? extField.value.result : [],
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
 * @status     experimental
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
 * @status     experimental
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
 * @status     experimental
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

module.exports = {
  parse: parse,
  parseV1: parseV1,
  pemDecode: pemDecode,
  pemEncode: pemEncode,
  matches: matches,
  matchesV1: matchesV1,
};
