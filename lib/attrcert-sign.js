// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.attrcert
 * @nav        Signing
 * @title      Attribute certificates
 * @intro The RFC 5755 attribute-certificate producing side. `pki.attrcert.sign` builds an
 *   `AttributeCertificateInfo` binding a Holder to a set of privilege attributes (role, clearance,
 *   group, ...) over a validity window, signs it with an Attribute Authority's private key, and emits an
 *   `AttributeCertificate` that `pki.schema.attrcert.parse` accepts and re-validates byte for byte.
 *   Unlike a public-key certificate an attribute certificate is never self-signed: the holder has no
 *   key, so the issuing AA is always a distinct signer. Parsing lives at `pki.schema.attrcert.parse`.
 * @spec RFC 5755
 * @card Build and sign an RFC 5755 attribute certificate as an Attribute Authority.
 */
//
// RFC 5755 is DEFINITIONS IMPLICIT TAGS (App. B): a context [n] on a non-CHOICE component replaces the
// underlying tag (its children are the component's fields: Holder [0]/[1]/[2], AttCertIssuer v2Form [0],
// RoleSyntax roleAuthority [0], IetfAttrSyntax policyAuthority [0], AAControls [0]/[1]), built with
// b.contextConstructed(n, ...); a context [n] wrapping a GeneralName CHOICE (roleName [1], Target [0]/[1])
// is EXPLICIT, built with b.explicit(n, ...). The signature algorithm resolves from the AA public key
// through the shared sign-scheme registry (RSA / ECDSA / EdDSA / ML-DSA / SLH-DSA / composite). The name /
// GeneralName / extension / SPKI encoders + the post-sign self-check are the shared lib/pki-build
// primitives; the AC-specific structures are the byte-exact inverse of the schema-attrcert.js readers,
// which re-validate every emitted structure on the round trip.

var asn1 = require("./asn1-der");
var oid = require("./oid");
var attrcert = require("./schema-attrcert");
var x509 = require("./schema-x509");
var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
require("./path-validate");   // side-effect: path-validate injects its signature engine into attrcert-verify at load
var attrcertVerify = require("./attrcert-verify");
var pkiBuild = require("./pki-build");
var frameworkError = require("./framework-error");

var AttrCertError = frameworkError.AttrCertError;
var b = asn1.build;
function _err(code, message, cause) { return new AttrCertError(code, message, cause); }
function _signE(kind, message, cause) { return new AttrCertError("attrcert/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var NS = pkix.makeNS("attrcert", AttrCertError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var _b = pkiBuild.makeBuilder({
  ErrorClass: AttrCertError, prefix: "attrcert", O: O, NS: NS,
  NAME_SCHEMA: pkix.name(NS), SPKI_SCHEMA: pkix.spki(NS), EXT_DECODERS: EXT_DECODERS,
});

// The recognized spec keys; an unknown key is a typo and throws at config-time (a custom attribute /
// extension is passed as pre-encoded DER via the array form).
var KNOWN_SPEC_KEYS = { holder: 1, notBeforeTime: 1, notAfterTime: 1, serialNumber: 1, attributes: 1, extensions: 1 };
var KNOWN_HOLDER_KEYS = { entityName: 1, baseCertificateID: 1, fromCertificate: 1, objectDigestInfo: 1 };
// object key -> the registered OID name of the AC attribute type it emits.
var ATTR_OID_NAME = {
  role: "role", clearance: "clearance", group: "group", chargingIdentity: "chargingIdentity",
  accessIdentity: "accessIdentity", authenticationInfo: "authenticationInfo",
};
// object key -> { oid name, critical } of the AC / AA extension it emits, with the RFC 5755 criticality:
// auditIdentity MUST be critical (sec. 4.3.1), targetInformation MUST be critical (sec. 4.3.2), proxying
// MUST be critical (sec. 7.2), noRevAvail MUST be non-critical (sec. 4.3.6), authorityKeyIdentifier MUST
// be non-critical (sec. 4.3.3); AAControls MAY be critical (sec. 7.4) and is emitted critical as the safer
// default for a delegation-constraint extension (a verifier that cannot process it MUST reject the AC).
var EXT_META = {
  auditIdentity:          { name: "acAuditIdentity",       critical: true },
  targetInformation:      { name: "targetInformation",     critical: true },
  noRevAvail:             { name: "noRevAvail",            critical: false },
  aaControls:             { name: "aaControls",            critical: true },
  acProxying:             { name: "acProxying",            critical: true },
  authorityKeyIdentifier: { name: "authorityKeyIdentifier", critical: false },
};
// The RFC 5755-mandated criticality per extension OID (from EXT_META), enforced on the pre-encoded array
// hatch so an escape-hatch extension cannot ship with a criticality the profile forbids.
var REQUIRED_CRITICALITY = {};
Object.keys(EXT_META).forEach(function (k) { REQUIRED_CRITICALITY[O(EXT_META[k].name)] = EXT_META[k].critical; });
// ClassList ::= BIT STRING { unmarked(0) .. topSecret(5) } (RFC 5755 sec. 4.4.4), the encode inverse of
// the schema-attrcert.js _CLASSLIST_NAMES decode array; DEFAULT {unclassified} (bit 1) is omitted.
var CLASSLIST_BIT = { unmarked: 0, unclassified: 1, restricted: 2, confidential: 3, secret: 4, topSecret: 5 };

var _tbsNameBytes = pkiBuild.tbsNameField;   // the AA issuerName / holder baseCertificateID chain exactly to a cert's DN
// Parse a certificate DER/PEM (or accept a parsed certificate), re-typing a raw x509/* parse fault to the
// attrcert domain so a malformed AA cert / holder cert surfaces attrcert/*, not a foreign CertificateError.
function _parseCert(cert, what) {
  // Re-derived from the bytes its parser read. Issuer and serial together ARE the Holder's identity,
  // so a certificate assembled from parts could bind an attribute certificate to a holder that no
  // issuer ever named.
  return guard.parsed.acceptDerived(cert, "certificate", function (bytes) {
    try { return x509.parse(bytes); }
    catch (e) { if (e instanceof AttrCertError) throw e; throw _err("attrcert/bad-input", what + " is not a well-formed certificate", e); }
  }, _err, "attrcert/bad-input", what);
}
// The raw content octets of an OBJECT IDENTIFIER (past its own tag+len): the body of a [0] IMPLICIT OID.
function _oidContent(name) {
  var dotted = O(name) || name;
  var enc;
  try { enc = b.oid(dotted); } catch (e) { throw _err("attrcert/bad-input", "not a valid object identifier: " + JSON.stringify(name), e); }
  return asn1.decode(enc).content;
}
// A GeneralNames spec (a single GeneralName object or an array of them) -> the member list.
function _gnList(spec) {
  if (Array.isArray(spec)) return spec;
  return [spec];
}

// ---- structural encoders (byte-exact inverses of the schema-attrcert.js readers) ----

// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serial CertificateSerialNumber, issuerUID BIT STRING
// OPTIONAL }. Returns the content (concatenated field TLVs) so a [n] IMPLICIT caller wraps it directly.
function _issuerSerialContent(is) {
  if (!is || typeof is !== "object" || Buffer.isBuffer(is)) throw _err("attrcert/bad-input", "baseCertificateID must be an object { issuer, serial, issuerUID? }");
  if (is.issuer == null) throw _err("attrcert/bad-input", "baseCertificateID.issuer (a GeneralNames) is required");
  var parts = [_b.encodeGeneralNames(_gnList(is.issuer)), _b.serialInteger(is.serial)];
  if (is.issuerUID != null) {
    if (!Buffer.isBuffer(is.issuerUID)) throw _err("attrcert/bad-input", "baseCertificateID.issuerUID must be a Buffer");
    parts.push(b.bitString(is.issuerUID, 0));
  }
  return Buffer.concat(parts);
}
// ObjectDigestInfo ::= SEQUENCE { digestedObjectType ENUMERATED, otherObjectTypeID OID OPTIONAL,
// digestAlgorithm AlgorithmIdentifier, objectDigest BIT STRING }. otherObjectTypes(2) is forbidden (sec.
// 7.3), so otherObjectTypeID is never emitted. Returns the content for a [n] IMPLICIT caller.
var ODT_CODE = { publicKey: 0, publicKeyCert: 1 };
function _objectDigestInfoContent(odi) {
  if (!odi || typeof odi !== "object" || Buffer.isBuffer(odi)) throw _err("attrcert/bad-input", "objectDigestInfo must be an object");
  var code = ODT_CODE[odi.digestedObjectType];
  if (code == null) throw _err("attrcert/bad-input", "objectDigestInfo.digestedObjectType must be 'publicKey' or 'publicKeyCert' (otherObjectTypes is forbidden, RFC 5755 sec. 7.3)");
  if (!Buffer.isBuffer(odi.objectDigest)) throw _err("attrcert/bad-input", "objectDigestInfo.objectDigest must be a Buffer (the whole-octet digest)");
  var algName = odi.digestAlgorithm;
  var algOid = O(algName) || algName;
  var algTlv;
  try { algTlv = b.sequence([b.oid(algOid)]); } catch (e) { throw _err("attrcert/bad-input", "objectDigestInfo.digestAlgorithm is not a valid algorithm identifier", e); }
  return Buffer.concat([b.enumerated(BigInt(code)), algTlv, b.bitString(odi.objectDigest, 0)]);
}
// Holder ::= SEQUENCE { baseCertificateID [0] IMPLICIT IssuerSerial, entityName [1] IMPLICIT GeneralNames,
// objectDigestInfo [2] IMPLICIT ObjectDigestInfo }, exactly one form (the profile binds a real holder).
function _encodeHolder(holder) {
  if (!holder || typeof holder !== "object" || Buffer.isBuffer(holder)) throw _err("attrcert/bad-input", "holder must be an object with exactly one form");
  guard.identifier.assertKnownKeys(holder, KNOWN_HOLDER_KEYS, _err, "attrcert/bad-input", "unknown holder form ");
  var forms = Object.keys(holder).filter(function (k) { return holder[k] != null; });
  if (forms.length !== 1) throw _err("attrcert/bad-input", "holder must carry exactly one form (entityName, baseCertificateID, fromCertificate, or objectDigestInfo), got " + forms.length);
  if (holder.entityName != null) {
    // entityName [1] IMPLICIT GeneralNames -> the [1] node's children ARE the GeneralName members.
    return b.sequence([_b.encodeGeneralNames(_gnList(holder.entityName), 1)]);
  }
  if (holder.baseCertificateID != null) {
    return b.sequence([b.contextConstructed(0, _issuerSerialContent(holder.baseCertificateID))]);
  }
  if (holder.fromCertificate != null) {
    // Bind to a public-key certificate's identity: baseCertificateID = { issuer = the PKC's issuer DN as a
    // directoryName, serial = the PKC serialNumber } (RFC 5755 sec. 4.1 / 7.3).
    // Both halves come from the signed bytes. issuer and serial together are the identity, so deriving
    // the issuer from tbsBytes while reading the serial off the object let the two name different
    // certificates: a Holder with a genuine issuer DN and whatever serial the caller wrote.
    var pkc = _parseCert(holder.fromCertificate, "holder.fromCertificate");
    var content = _issuerSerialContent({ issuer: [{ directoryName: _tbsNameBytes(pkc, "issuer") }], serial: pkiBuild.tbsSerialNumber(pkc) });
    return b.sequence([b.contextConstructed(0, content)]);
  }
  // objectDigestInfo [2] IMPLICIT ObjectDigestInfo.
  return b.sequence([b.contextConstructed(2, _objectDigestInfoContent(holder.objectDigestInfo))]);
}

// AttCertIssuer v2Form [0] IMPLICIT V2Form { issuerName GeneralNames }, where issuerName is exactly one
// directoryName [4] over a non-empty DN (RFC 5755 sec. 4.2.3). The [0] replaces the V2Form SEQUENCE tag.
function _encodeV2FormIssuer(dnSpec) {
  var dnDer = _b.encodeName(dnSpec == null ? [] : dnSpec);
  if (_b.isEmptyName(dnDer)) throw _err("attrcert/bad-issuer-name", "the AA issuerName must be a non-empty distinguished name (RFC 5755 sec. 4.2.3)");
  var issuerNameGns = _b.encodeGeneralNames([{ directoryName: dnDer }]);   // a universal SEQUENCE OF one directoryName
  return b.contextConstructed(0, issuerNameGns);
}
// AttCertValidityPeriod ::= SEQUENCE { notBeforeTime GeneralizedTime, notAfterTime GeneralizedTime }
// (RFC 5755 sec. 4.2.6): always GeneralizedTime, never UTCTime; reject an inverted window.
function _encodeValidity(notBefore, notAfter) {
  guard.time.assertValid(notBefore, _err, "attrcert/bad-input", "notBeforeTime");
  guard.time.assertValid(notAfter, _err, "attrcert/bad-input", "notAfterTime");
  // allow:nan-date-comparison-unguarded -- both operands are guard.time.assertValid'd above.
  if (guard.time.instantOf(notBefore) > guard.time.instantOf(notAfter)) throw _err("attrcert/bad-input", "notBeforeTime must not be after notAfterTime (RFC 5755 sec. 4.2.6)");
  return b.sequence([b.generalizedTime(notBefore), b.generalizedTime(notAfter)]);
}

// ---- attribute-value encoders (sec. 4.4) ----

// RoleSyntax ::= SEQUENCE { roleAuthority [0] IMPLICIT GeneralNames OPTIONAL, roleName [1] EXPLICIT
// GeneralName }. roleName is a GeneralName CHOICE -> EXPLICIT; roleAuthority a GeneralNames -> IMPLICIT [0].
function _encodeRole(role) {
  if (!role || typeof role !== "object" || role.roleName == null) throw _err("attrcert/bad-input", "role must be an object with a roleName GeneralName");
  var parts = [];
  if (role.roleAuthority != null) parts.push(_b.encodeGeneralNames(_gnList(role.roleAuthority), 0));
  parts.push(b.explicit(1, _b.encodeGeneralName(role.roleName)));
  return b.sequence(parts);
}
// Clearance ::= SEQUENCE { policyId OID, classList BIT STRING DEFAULT {unclassified}, securityCategories
// SET OF SecurityCategory OPTIONAL } (RFC 5755 sec. 4.4.4). A classList equal to the DEFAULT is omitted.
function _encodeClearance(cl) {
  if (!cl || typeof cl !== "object" || cl.policyId == null) throw _err("attrcert/bad-input", "clearance must be an object with a policyId OID");
  var parts;
  try { parts = [b.oid(O(cl.policyId) || cl.policyId)]; } catch (e) { throw _err("attrcert/bad-input", "clearance.policyId is not a valid object identifier", e); }
  if (cl.classList != null) {
    if (!Array.isArray(cl.classList)) throw _err("attrcert/bad-input", "clearance.classList must be an array of class names");
    var positions = cl.classList.map(function (n) {
      var pos = CLASSLIST_BIT[n];
      if (pos == null) throw _err("attrcert/bad-input", "unknown clearance class " + JSON.stringify(n));
      return pos;
    });
    // A present classList equal to the DEFAULT {unclassified} is non-canonical DER (the parser rejects it).
    var isDefault = positions.length === 1 && positions[0] === CLASSLIST_BIT.unclassified;
    if (!isDefault) parts.push(b.namedBitString(positions));
  }
  if (cl.securityCategories != null) {
    if (!Array.isArray(cl.securityCategories) || !cl.securityCategories.length) throw _err("attrcert/bad-input", "clearance.securityCategories must be a non-empty array");
    parts.push(b.set(cl.securityCategories.map(_encodeSecurityCategory)));
  }
  return b.sequence(parts);
}
// SecurityCategory ::= SEQUENCE { type [0] IMPLICIT OBJECT IDENTIFIER, value [1] EXPLICIT ANY }. The
// value is one element the parser EXPLICIT [1] wrapper carries verbatim, so it MUST be a single
// well-formed DER TLV -- validate it (no malformed / multi-element / trailing bytes) before signing.
function _encodeSecurityCategory(sc) {
  if (!sc || typeof sc !== "object" || sc.type == null || !Buffer.isBuffer(sc.value)) throw _err("attrcert/bad-input", "each securityCategory must be { type: OID, value: DER Buffer }");
  var node;
  try { node = asn1.decode(sc.value); } catch (e) { throw _err("attrcert/bad-input", "securityCategory value must be a single well-formed DER element", e); }
  if (node.bytes.length !== sc.value.length) throw _err("attrcert/bad-input", "securityCategory value must be exactly one DER element (no trailing bytes)");
  return b.sequence([b.contextPrimitive(0, _oidContent(sc.type)), b.explicit(1, sc.value)]);
}
// IetfAttrSyntax ::= SEQUENCE { policyAuthority [0] IMPLICIT GeneralNames OPTIONAL, values SEQUENCE OF
// CHOICE { octets OCTET STRING, oid OBJECT IDENTIFIER, string UTF8String } } (group / chargingIdentity).
function _encodeIetfAttrSyntax(ia) {
  if (!ia || typeof ia !== "object" || !Array.isArray(ia.values) || !ia.values.length) throw _err("attrcert/bad-input", "an IetfAttrSyntax attribute must be an object with a non-empty values array");
  var parts = [];
  if (ia.policyAuthority != null) parts.push(_b.encodeGeneralNames(_gnList(ia.policyAuthority), 0));
  parts.push(b.sequence(ia.values.map(function (v) {
    if (v == null || typeof v !== "object") throw _err("attrcert/bad-input", "each IetfAttrSyntax value must be { octets }, { oid }, or { string }");
    if (v.octets != null) { if (!Buffer.isBuffer(v.octets)) throw _err("attrcert/bad-input", "IetfAttrSyntax octets must be a Buffer"); return b.octetString(v.octets); }
    if (v.oid != null) { try { return b.oid(O(v.oid) || v.oid); } catch (e) { throw _err("attrcert/bad-input", "IetfAttrSyntax oid is not a valid object identifier", e); } }
    if (v.string != null) return b.utf8(String(v.string));
    throw _err("attrcert/bad-input", "each IetfAttrSyntax value must be { octets }, { oid }, or { string }");
  })));
  return b.sequence(parts);
}
// SvceAuthInfo ::= SEQUENCE { service GeneralName, ident GeneralName, authInfo OCTET STRING OPTIONAL }.
// authenticationInfo (sec. 4.4.1) permits authInfo; accessIdentity (sec. 4.4.2) MUST omit it.
function _encodeSvceAuthInfo(sai, authInfoAllowed, label) {
  if (!sai || typeof sai !== "object" || sai.service == null || sai.ident == null) throw _err("attrcert/bad-input", label + " must be an object with a service and an ident GeneralName");
  var parts = [_b.encodeGeneralName(sai.service), _b.encodeGeneralName(sai.ident)];
  if (sai.authInfo != null) {
    if (!authInfoAllowed) throw _err("attrcert/bad-input", "accessIdentity must not carry authInfo (RFC 5755 sec. 4.4.2)");
    if (!Buffer.isBuffer(sai.authInfo)) throw _err("attrcert/bad-input", label + " authInfo must be a Buffer");
    parts.push(b.octetString(sai.authInfo));
  }
  return b.sequence(parts);
}

var ATTR_VALUE_ENCODER = {
  role:               function (v) { return _encodeRole(v); },
  clearance:          function (v) { return _encodeClearance(v); },
  group:              function (v) { return _encodeIetfAttrSyntax(v); },
  chargingIdentity:   function (v) { return _encodeIetfAttrSyntax(v); },
  authenticationInfo: function (v) { return _encodeSvceAuthInfo(v, true, "authenticationInfo"); },
  accessIdentity:     function (v) { return _encodeSvceAuthInfo(v, false, "accessIdentity"); },
};

// ---- extension-value encoders (sec. 4.3 / 7.4) ----

// Target ::= CHOICE { targetName [0] EXPLICIT GeneralName, targetGroup [1] EXPLICIT GeneralName }
// (targetCert [2] is out of v1 scope; use a pre-encoded Extension DER for a targetCert-bearing value).
function _encodeTarget(t) {
  if (!t || typeof t !== "object") throw _err("attrcert/bad-input", "each target must be { targetName } or { targetGroup }");
  if (t.targetName != null) return b.explicit(0, _b.encodeGeneralName(t.targetName));
  if (t.targetGroup != null) return b.explicit(1, _b.encodeGeneralName(t.targetGroup));
  throw _err("attrcert/bad-input", "each target must be { targetName } or { targetGroup }");
}
// targetInformation / acProxying value ::= SEQUENCE OF Targets, Targets ::= SEQUENCE OF Target. A
// conformant issuer emits exactly one Targets.
function _encodeSeqOfTargets(targets) {
  if (!Array.isArray(targets) || !targets.length) throw _err("attrcert/bad-input", "a targets value must be a non-empty array of targets");
  return b.sequence([b.sequence(targets.map(_encodeTarget))]);
}
// AAControls ::= SEQUENCE { pathLenConstraint INTEGER OPTIONAL, permittedAttrs [0] IMPLICIT AttrSpec
// OPTIONAL, excludedAttrs [1] IMPLICIT AttrSpec OPTIONAL, permitUnSpecified BOOLEAN DEFAULT TRUE }.
// AttrSpec ::= SEQUENCE OF OID (the [0]/[1] IMPLICIT tag replaces the SEQUENCE tag).
function _attrSpec(names, tag, label) {
  if (!Array.isArray(names)) throw _err("attrcert/bad-input", "aaControls." + label + " must be an array of attribute-type OIDs");
  var oids = names.map(function (n) {
    try { return b.oid(O(n) || n); } catch (e) { throw _err("attrcert/bad-input", "aaControls." + label + " contains an invalid object identifier " + JSON.stringify(n), e); }
  });
  return b.contextConstructed(tag, Buffer.concat(oids));
}
function _encodeAAControls(aac) {
  if (!aac || typeof aac !== "object" || Buffer.isBuffer(aac)) throw _err("attrcert/bad-input", "aaControls must be an object");
  var parts = [];
  if (aac.pathLenConstraint != null) {
    // The parser narrows pathLenConstraint through guard.range.uint31 (0..2^31-1), so a larger value the
    // builder emits would fail the round trip, so bound it to the same range at build time.
    if (typeof aac.pathLenConstraint !== "number" || !Number.isInteger(aac.pathLenConstraint) || aac.pathLenConstraint < 0 || aac.pathLenConstraint > 0x7fffffff) throw _err("attrcert/bad-input", "aaControls.pathLenConstraint must be an integer in 0..2147483647 (RFC 5755 sec. 7.4)");
    parts.push(b.integer(BigInt(aac.pathLenConstraint)));
  }
  if (aac.permittedAttrs != null) parts.push(_attrSpec(aac.permittedAttrs, 0, "permittedAttrs"));
  if (aac.excludedAttrs != null) parts.push(_attrSpec(aac.excludedAttrs, 1, "excludedAttrs"));
  // permitUnSpecified DEFAULT TRUE -- a TRUE value equals the DEFAULT and is omitted (non-canonical DER).
  if (aac.permitUnSpecified === false) parts.push(b.boolean(false));
  else if (aac.permitUnSpecified != null && aac.permitUnSpecified !== true) throw _err("attrcert/bad-input", "aaControls.permitUnSpecified must be a boolean");
  return b.sequence(parts);
}
// Emit a single AC / AA extension's value DER from its object-form spec.
function _extensionValue(key, val, aaSpki) {
  switch (key) {
    case "auditIdentity":
      if (!Buffer.isBuffer(val)) throw _err("attrcert/bad-input", "auditIdentity must be a Buffer (an OCTET STRING audit tag)");
      return b.octetString(val);
    case "targetInformation": return _encodeSeqOfTargets(val);
    case "acProxying": return _encodeSeqOfTargets(val);
    case "noRevAvail": return b.nullValue();
    case "aaControls": return _encodeAAControls(val);
    case "authorityKeyIdentifier": return _b.extAki(_b.skiKeyId(val, aaSpki));
    default: throw _err("attrcert/bad-input", "unknown extension " + JSON.stringify(key));
  }
}

// ---- attributes / extensions assembly ----

// attributes ::= SEQUENCE OF Attribute (RFC 5755 sec. 4.2.7): non-empty, each AttributeType OID unique;
// or an array of pre-encoded Attribute DER (validated in shape AND value). Each Attribute value SET is
// DER-sorted.
function _buildAttributes(attrSpec) {
  var attrs = [], seen = {};
  function add(type, valueTlv) {
    if (seen[type]) throw _err("attrcert/duplicate-attribute", "duplicate " + (oid.name(type) || type) + " attribute (RFC 5755 sec. 4.2.7)");
    seen[type] = true;
    attrs.push(b.sequence([b.oid(type), b.set([valueTlv])]));
  }
  if (Array.isArray(attrSpec)) {
    attrSpec.forEach(function (a, i) {
      var der = _b.reqDer(a, "attribute [" + i + "]");
      var n;
      try { n = asn1.decode(der); } catch (e) { throw _err("attrcert/bad-input", "pre-encoded attribute [" + i + "] is not valid DER", e); }
      if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length !== 2 || n.children[1].tagNumber !== asn1.TAGS.SET) throw _err("attrcert/bad-input", "pre-encoded attribute [" + i + "] must be an Attribute SEQUENCE { type OID, SET OF value }");
      var at;
      try { at = asn1.read.oid(n.children[0]); } catch (e) { throw _err("attrcert/bad-input", "pre-encoded attribute [" + i + "] type is not an OBJECT IDENTIFIER", e); }
      if (!n.children[1].children || !n.children[1].children.length) throw _err("attrcert/bad-input", "pre-encoded attribute [" + i + "] value SET must contain at least one value");
      if (seen[at]) throw _err("attrcert/duplicate-attribute", "duplicate " + (oid.name(at) || at) + " attribute (RFC 5755 sec. 4.2.7)");
      seen[at] = true;
      // A recognized AC attribute type is validated against its real sec. 4.4 value decoder; an
      // unrecognized type stays opaque (the parser also leaves it opaque).
      n.children[1].children.forEach(function (valNode) {
        try { attrcert.validateAttributeValue(at, valNode.bytes); }
        catch (err) { if (err instanceof AttrCertError) throw err; throw _err("attrcert/bad-input", "pre-encoded " + (oid.name(at) || at) + " attribute value is malformed", err); }
      });
      attrs.push(b.raw(der));
    });
    if (!attrs.length) throw _err("attrcert/bad-attributes", "attributes must carry at least one Attribute (RFC 5755 sec. 4.2.7)");
    return b.sequence(attrs);
  }
  if (!attrSpec || typeof attrSpec !== "object") throw _err("attrcert/bad-input", "attributes must be an object or an array of pre-encoded Attribute DER");
  guard.identifier.assertKnownKeys(attrSpec, ATTR_VALUE_ENCODER, _err, "attrcert/bad-input", function (k) {
    return "unknown attribute " + JSON.stringify(k) + "; pass a pre-encoded Attribute DER via the array form for a custom attribute";
  });
  Object.keys(attrSpec).forEach(function (k) {
    add(O(ATTR_OID_NAME[k]), ATTR_VALUE_ENCODER[k](attrSpec[k]));
  });
  if (!attrs.length) throw _err("attrcert/bad-attributes", "attributes must carry at least one Attribute (RFC 5755 sec. 4.2.7)");
  return b.sequence(attrs);
}

// extensions ::= SEQUENCE OF Extension (RFC 5755 sec. 4.2.9): the recognized object form, or an array
// of pre-encoded Extension DER. At most one instance of a particular extension OID. Returns a universal
// SEQUENCE OF Extension, or null when none are requested.
function _buildExtensions(extSpec, aaSpki) {
  if (extSpec == null) return null;
  if (Array.isArray(extSpec)) {
    if (!extSpec.length) return null;
    var seenA = {};
    var exts = extSpec.map(function (e, i) {
      var der = _b.reqDer(e, "extension");
      _b.assertValidExtension(der, i);
      var n = asn1.decode(der);
      var extnId = asn1.read.oid(n.children[0]);
      if (seenA[extnId]) throw _err("attrcert/bad-input", "duplicate extension " + extnId + " (RFC 5755 sec. 4.2.9)");
      seenA[extnId] = true;
      // A recognized RFC 5755-profiled extension MUST carry its mandated criticality even via the escape
      // hatch (assertValidExtension already rejected an explicit critical=FALSE, so 3 children == critical).
      var required = REQUIRED_CRITICALITY[extnId];
      if (required != null && (n.children.length === 3) !== required) {
        throw _err("attrcert/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension must be marked " + (required ? "critical" : "non-critical") + " (RFC 5755)");
      }
      // Validate a recognized value against its real decoder: a cert-style AA extension (AKI / CRLDP /
      // AIA) through the RFC 5280 sec. 4.2.1 table, an AC-specific extension through the sec. 4.3 table.
      var extnValue = asn1.read.octetString(n.children[n.children.length - 1]);
      try {
        if (EXT_DECODERS[extnId]) EXT_DECODERS[extnId](extnValue);
        else attrcert.validateExtensionValue(extnId, extnValue);
      } catch (err) { if (err instanceof AttrCertError) throw err; throw _err("attrcert/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension value is malformed", err); }
      return b.raw(der);
    });
    return b.sequence(exts);
  }
  if (typeof extSpec !== "object") throw _err("attrcert/bad-input", "extensions must be an object or an array of pre-encoded Extension DER");
  guard.identifier.assertKnownKeys(extSpec, EXT_META, _err, "attrcert/bad-input", function (k) {
    return "unknown extension " + JSON.stringify(k) + "; pass a pre-encoded Extension DER via the array form for a custom extension";
  });
  var out = [], seen = {};
  Object.keys(extSpec).forEach(function (k) {
    if (extSpec[k] == null) return;   // a null/omitted extension is not requested (matches the attribute form)
    var meta = EXT_META[k], eOid = O(meta.name);
    if (seen[eOid]) throw _err("attrcert/bad-input", "duplicate extension " + JSON.stringify(k) + " (RFC 5755 sec. 4.2.9)");
    seen[eOid] = true;
    out.push(_b.ext(eOid, meta.critical, _extensionValue(k, extSpec[k], aaSpki)));
  });
  if (!out.length) return null;
  return b.sequence(out);
}

/**
 * @primitive pki.attrcert.sign
 * @signature pki.attrcert.sign(spec, issuer, opts?) -> Promise<Buffer|string>
 * @since 0.3.2
 * @status stable
 * @spec RFC 5755
 * @defends forged-attribute-certificate (CWE-347)
 * @related pki.schema.attrcert.parse, pki.x509.sign
 *
 * Build, sign, and DER-encode an RFC 5755 attribute certificate as an Attribute Authority. `spec`
 * describes the certificate -- `holder` (exactly one form: `entityName`, `baseCertificateID`,
 * `fromCertificate` to bind a public-key certificate's identity, or `objectDigestInfo`), `notBeforeTime`
 * / `notAfterTime` (`Date`s -> GeneralizedTime), an optional `serialNumber` (positive, <= 20 octets;
 * a random 20-octet serial is generated when omitted), `attributes` (an object of the sec. 4.4 privilege
 * syntaxes -- role / clearance / group / chargingIdentity / accessIdentity / authenticationInfo -- or an
 * array of pre-encoded Attribute DER), and optional `extensions` (an object of auditIdentity /
 * targetInformation / noRevAvail / aaControls / acProxying / authorityKeyIdentifier, or an array of
 * pre-encoded Extension DER). `issuer` is the signing AA: `{ cert, key }` (the AA certificate DER/PEM
 * and its private key) or `{ name, publicKey, key }` (an explicit issuer DN, AA SPKI DER, and key); an
 * attribute certificate is never self-signed. The signature algorithm is resolved from the AA key (RSA
 * PKCS#1 v1.5 or PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm), and the signature is verified
 * under the AA public key before the certificate is returned. Returns DER, or a PEM `ATTRIBUTE
 * CERTIFICATE` with `opts.pem`. Malformed input throws a typed `AttrCertError`; where the spec carries
 * raw DER (a holder or issuer `Name` Buffer, a pre-encoded `Extension`) a malformed leaf inside
 * those bytes throws `Asn1Error`. The AA certificate's own
 * profile (RFC 5755 sec. 4.5) and validity are a verification-layer concern, so validate the AA
 * certificate with `pki.path.validate` before trusting the attribute certificate. Parsing is
 * `pki.schema.attrcert.parse`.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `ATTRIBUTE CERTIFICATE` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS instead of PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Attribute Authority", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var ac = await pki.attrcert.sign(
 *     { holder: { entityName: { directoryName: "CN=Alice" } },
 *       notBeforeTime: new Date("2026-01-01T00:00:00Z"), notAfterTime: new Date("2027-01-01T00:00:00Z"),
 *       attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } } },
 *     { cert: signerCertDer, key: signerKeyPkcs8 });
 *   pki.schema.attrcert.parse(ac).attributes[0].type;   // the role attribute OID
 */
function sign(spec, issuer, opts) {
  // Every caller-owned argument copied at entry and released when the call settles -- see the note
  // on the same call in x509-sign.
  return guard.bytes.fixedCall(AttrCertError, "attrcert/bad-input", [
    [spec, "the attribute-certificate spec"], [issuer, "the issuer"], [opts, "pki.attrcert.sign options"],
  ], _sign);
}

function _sign(spec, issuer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("attrcert/bad-input", "the attribute-certificate spec must be an object");
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, _err, "attrcert/bad-input", "unknown spec field ");
  issuer = issuer || {};
  if (issuer.key == null) throw _err("attrcert/bad-input", "a signing key (issuer.key, the AA's PKCS#8 private key) is required");

  // Resolve the AA issuer DN + signing-key SPKI. An attribute certificate is NEVER self-signed. No CA
  // gate on issuer.cert -- an AA is NOT a certificate authority (its PKC MUST NOT assert keyCertSign,
  // RFC 5755 sec. 4.5), so requiring cA/keyCertSign would reject every conformant AA certificate.
  var issuerDnSpec, aaSpki;
  if (issuer.cert != null) {
    var aaCert = _parseCert(issuer.cert, "issuer.cert");
    issuerDnSpec = _tbsNameBytes(aaCert, "subject");
    aaSpki = aaCert.subjectPublicKeyInfo.bytes;
  } else if (issuer.name != null && issuer.publicKey != null) {
    issuerDnSpec = issuer.name;
    aaSpki = _b.reqDer(issuer.publicKey, "issuer.publicKey (the AA SPKI DER)");
    _b.assertValidSpki(aaSpki, "issuer.publicKey");
  } else {
    throw _err("attrcert/bad-input", "issuer must be { cert, key } or { name, publicKey, key } (an attribute certificate is never self-signed)");
  }

  var issuerDer = _encodeV2FormIssuer(issuerDnSpec);
  var holderDer = _encodeHolder(spec.holder);
  var validityDer = _encodeValidity(spec.notBeforeTime, spec.notAfterTime);
  var attributesDer = _buildAttributes(spec.attributes);
  var extsDer = _buildExtensions(spec.extensions, aaSpki);

  // Resolve the signature scheme from the AA (signing) key's SPKI -- the whole registry, for free.
  var scheme = signScheme.resolveSignScheme(_b.certLikeFromSpki(aaSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  // AttributeCertificateInfo ::= SEQUENCE { version(bare INTEGER 1), holder, issuer, signature
  // AlgorithmIdentifier, serialNumber, attrCertValidityPeriod, attributes, [issuerUniqueID], [extensions] }.
  // signature == the outer signatureAlgorithm (RFC 5755 sec. 4.2.4), single source scheme.sigAlgId.
  var acinfoChildren = [
    b.integer(1n), holderDer, issuerDer, scheme.sigAlgId,
    _b.serialInteger(spec.serialNumber), validityDer, attributesDer,
  ];
  if (extsDer) acinfoChildren.push(extsDer);   // issuerUniqueID omitted (sec. 4.2.8); extensions is a bare universal SEQUENCE
  var acinfoDer = b.sequence(acinfoChildren);

  return signScheme.signOverTbs(scheme, issuer.key, acinfoDer, _signE).then(function (sig) {
    // The signature MUST verify under the AA public key (the AA proof); composite verifies both arms.
    return Promise.resolve(_b.assertSignatureVerifies(acinfoDer, sig, aaSpki, scheme)).then(function () {
      var acDer = b.sequence([acinfoDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? attrcert.pemEncode(acDer, "ATTRIBUTE CERTIFICATE") : acDer;
    });
  }, function (e) {
    if (e instanceof AttrCertError) throw e;
    throw _err("attrcert/bad-input", "signing the attribute certificate failed -- the signing key does not match the resolved algorithm or is invalid", e);
  });
}

var KNOWN_VERIFY_OPTS = { time: 1, target: 1 };
var _NAME_SCHEMA = pkix.name(NS);

// A Name DER, read through the one Name reader, so every distinguished name this verb compares is
// in the shape guard.name.dnEqual takes.
function _readName(der, what) {
  try { return schema.walk(_NAME_SCHEMA, asn1.decode(der), NS).result; }
  catch (e) {
    if (e instanceof AttrCertError) throw e;
    throw _err("attrcert/bad-input", what + " is not a readable distinguished name", e);
  }
}

// The AC issuer's distinguished name. The parser has already established that issuerName holds
// exactly one non-empty directoryName [4] (RFC 5755 sec. 4.2.3) and surfaces it as a raw node, so
// the DN itself is one EXPLICIT unwrap away.
function _acIssuerName(parsed) {
  var node = asn1.decode(parsed.issuer.v2Form.issuerName.names[0].bytes);
  if (!node.children || node.children.length !== 1) {
    throw _err("attrcert/bad-issuer-name", "the AC issuerName directoryName does not wrap exactly one Name");
  }
  return _readName(node.children[0].bytes, "the AC issuer name");
}

function _coerceAc(input) {
  return guard.parsed.acceptDerived(input, "attributeCertificate", attrcert.parse, _err,
    "attrcert/bad-input", "the attribute certificate");
}

// The AC issuer this caller directly trusts as an AC issuer (RFC 5755 sec. 5, item 4). That is a
// configuration decision the certificate cannot make for itself, so it is an argument, and an
// argument this verb refuses to infer.
function _resolveIssuer(issuer) {
  if (issuer == null || typeof issuer !== "object" || Buffer.isBuffer(issuer)) {
    throw _err("attrcert/bad-input", "an issuer { name, publicKey } is required -- RFC 5755 sec. 5 item 4 makes trusting an AC issuer the verifier's own configuration");
  }
  guard.identifier.assertKnownKeys(issuer, { name: 1, publicKey: 1 }, _err, "attrcert/bad-input",
    "the issuer has an unknown key ");
  if (issuer.publicKey == null) throw _err("attrcert/bad-input", "issuer.publicKey (the AC issuer's SubjectPublicKeyInfo DER) is required");
  if (typeof issuer.name !== "string" || issuer.name === "") {
    throw _err("attrcert/bad-input", "issuer.name (the distinguished name this verifier trusts as an AC issuer) is required");
  }
  // The trusted name is compared as a distinguished name, never as a string: RFC 5280 sec. 7.1
  // identity is not string equality, and guard.name owns that comparison. Encoding the caller's
  // name and reading it back through the SAME Name reader the parser used puts both sides in the
  // one shape dnEqual takes.
  return {
    name: issuer.name, rdns: _readName(_b.encodeName(issuer.name), "issuer.name").rdns,
    spki: guard.bytes.view(issuer.publicKey, AttrCertError, "attrcert/bad-input", "issuer.publicKey"),
  };
}

// RFC 5755 sec. 4.3.2: a targeted AC is valid only at the servers it names, and "servers not named
// MUST reject the AC". An absent extension means untargeted, so there is nothing to check.
//
// Only the decoded targetName and targetGroup alternatives are compared. Searching the extension's
// raw bytes for the caller's encoded GeneralName would also match a name nested inside a targetCert,
// where it identifies the TARGET CERTIFICATE'S ISSUER rather than a target, and would then accept an
// AC at a server it never named. A match against a targetGroup does count: sec. 4.3.2 targets "named
// targets or groups", so a verifier presenting its group name is naming itself among them.
//
// The caller's GeneralName goes through the shared builder, then back through the SAME GeneralName
// reader the parser used, so both sides of every comparison are the one decoded shape. Reading it
// back rather than dereferencing a context node's `content` also keeps this off a field that is
// null whenever the node is constructed.
function _callerTarget(target) {
  return attrcert.readGeneralName(_b.encodeGeneralName(target), "attrcert/bad-input");
}

// RFC 5280 sec. 7.5: two mailboxes match when the local-part is an exact match AND the host-part
// matches case-insensitively. The split is on the LAST "@", since a quoted local-part may contain
// one; a value with no "@" has no host-part to fold and compares exactly.
function _mailboxEqual(a, bx) {
  var i = a.lastIndexOf("@"), j = bx.lastIndexOf("@");
  if (i < 0 || j < 0) return a === bx;
  return a.slice(0, i) === bx.slice(0, j) &&
    a.slice(i + 1).toLowerCase() === bx.slice(j + 1).toLowerCase();
}

// Whether a target the AC names is this verifier, under the matching rule each GeneralName form
// defines. A form whose rule this build does not implement compares exactly, which can refuse a
// name a fuller comparison would accept and can never accept one it would refuse.
function _generalNameMatches(entry, want) {
  if (!entry || entry.tagNumber !== want.tagNumber) return false;
  switch (entry.tagNumber) {
    // RFC 5280 sec. 7.2: "When comparing DNS names for equality, conforming implementations MUST
    // perform a case-insensitive exact match on the entire DNS name."
    case 2: return String(entry.value).toLowerCase() === String(want.value).toLowerCase();
    // sec. 7.5, as above.
    case 1: return _mailboxEqual(String(entry.value), String(want.value));
    // A directoryName is a distinguished name, and sec. 7.1 identity is not string equality, so it
    // goes through the one DN comparator rather than comparing the printed form.
    case 4:
      return !!(entry.value && want.value) &&
        guard.name.dnEqual(entry.value.rdns, want.value.rdns, _err, "attrcert/bad-input", "the target name");
    // sec. 7.4 makes a URI comparison a full RFC 3987 normalization: percent-encoding, path
    // segments and scheme-based rules, not merely lowercasing the scheme and host. A partial
    // normalization would be a guess that could match a URI it should not, so the encoded value is
    // compared as it stands. Re-open condition: an RFC 3987 normalizer in the toolkit.
    default:
      if (Buffer.isBuffer(entry.value) && Buffer.isBuffer(want.value)) return entry.value.equals(want.value);
      if (typeof entry.value === "string" && typeof want.value === "string") return entry.value === want.value;
      // A form whose decoded value is neither (otherName, ediPartyName, x400Address) has no
      // comparison here; the caller is told so rather than given a silent mismatch.
      return null;
  }
}

function _checkTargeting(ac, target) {
  var ext = null;
  for (var i = 0; i < ac.extensions.length; i++) {
    if (ac.extensions[i].name === "targetInformation") ext = ac.extensions[i];
  }
  if (!ext) return { checked: true, ok: true };
  if (target === undefined) {
    return { checked: false, ok: false,
      reason: "this attribute certificate is targeted, and no opts.target names this verifier (RFC 5755 sec. 4.3.2)" };
  }
  var want = _callerTarget(target);
  // The extension's syntax is a SEQUENCE OF Targets, and its groups are FLATTENED rather than
  // required one by one. RFC 5755 sec. 4.3.2: "If more than one Targets element is found in an AC,
  // the extension MUST be treated as if all Target elements had been found within one Targets
  // element." An issuer conforming to the same paragraph produces only one group anyway, so the
  // nesting carries no meaning to honour; requiring a match in every group would refuse ACs the
  // paragraph says to accept.
  var groups = ext.decoded || [];
  var uncomparable = null;
  for (var g = 0; g < groups.length; g++) {
    for (var t = 0; t < groups[g].length; t++) {
      var entry = groups[g][t];
      // targetCert is the third Target arm; the names inside it identify a certificate, not a target.
      if (entry.kind !== "targetName" && entry.kind !== "targetGroup") continue;
      var m = _generalNameMatches(entry.name, want);
      if (m === true) return { checked: true, ok: true };
      if (m === null) uncomparable = entry.name && entry.name.tagNumber;
    }
  }
  // A target this build cannot compare leaves the check unperformed, which cannot read as a pass.
  if (uncomparable !== null) {
    return { checked: false, ok: false,
      reason: "this attribute certificate names a target in a GeneralName form ([" + uncomparable +
        "]) this verifier does not compare, so the RFC 5755 sec. 4.3.2 check did not run" };
  }
  return { checked: true, ok: false,
    reason: "this attribute certificate does not name this verifier among its targets (RFC 5755 sec. 4.3.2)" };
}

// The critical extensions this verb SUPPORTS, by OID. RFC 5755 sec. 5 defines support in two parts:
// the verifier must be able to parse the value, AND "where the extension value causes the AC to be
// rejected, the AC verifier MUST reject the AC". Parsing alone satisfies only the first, so an
// extension whose constraints this verb never evaluates cannot be called supported however cleanly
// it decodes.
//
//   targetInformation -- evaluated, by the sec. 4.3.2 check below.
//   acAuditIdentity   -- sec. 4.3.1 is an audit/logging identity and states no rule that rejects an
//                        AC, so there is no second part to satisfy. It rides out on the verdict's
//                        `extensions` for the logging the section asks for.
//
// Everything else critical is refused, including extensions this build parses but does not act on:
// aaControls (sec. 7.4) constrains what an AA may delegate and acProxying (sec. 7.2) constrains
// proxy use, and an unevaluated constraint is exactly what item 7 exists to stop. A critical
// extension defined in future defaults to refused, which is the safe direction.
var SUPPORTED_CRITICAL = {};
SUPPORTED_CRITICAL[O("targetInformation")] = 1;
SUPPORTED_CRITICAL[O("acAuditIdentity")] = 1;

function _unsupportedCritical(ac) {
  for (var i = 0; i < ac.extensions.length; i++) {
    var e = ac.extensions[i];
    if (e.critical !== true) continue;
    // Own-property membership, so an extension OID that happens to name something on Object.prototype
    // cannot read as supported.
    if (!Object.prototype.hasOwnProperty.call(SUPPORTED_CRITICAL, e.oid)) return e.oid;
    // A supported OID whose value this build could not interpret is still unusable.
    if (e.decoded === null || e.decoded === undefined || e.decoded.opaque === true) return e.oid;
  }
  return null;
}

/**
 * @primitive pki.attrcert.verify
 * @signature pki.attrcert.verify(ac, issuer, opts) -> Promise<{ verified, signatureValid, validityChecked, targetingChecked, holderBindingChecked, issuerPathChecked, holder, issuer, attributes, extensions, notBefore, notAfter, serialNumberHex, reason }>
 * @since 0.5.15
 * @status stable
 * @spec RFC 5755 sec. 5
 * @defends attribute-certificate-forgery (CWE-347)
 * @related pki.attrcert.sign, pki.path.validate, pki.schema.attrcert.parse
 *
 * Verify an RFC 5755 attribute certificate. An AC carries privilege attributes -- a role, a group, a
 * clearance -- so a consumer that reads them without this grants privileges on unauthenticated
 * input. `ac` is a DER `Buffer`, a PEM string, or a parsed attribute certificate; `issuer` is
 * `{ name, publicKey }`, the AC issuer this verifier trusts as an AC issuer, which section 5 item 4
 * makes the verifier's own configuration and this verb therefore refuses to infer from the AC.
 *
 * The checks it performs are section 5's items 2, 4, 5, 6 and 7: the signature over the exact
 * `AttributeCertificateInfo` bytes through the one path-validation signature engine; the issuer
 * being the one named; the evaluation instant lying within the validity, where equality with either
 * bound succeeds as the section states; the targeting rule of section 4.3.2, where an AC naming
 * targets is refused at a verifier it does not name; and rejection of any critical extension this
 * verb does not process. Section 5 defines support as parsing the value AND rejecting where the
 * value would reject, so an extension parsed but never evaluated is not supported: targeting is
 * processed and an audit identity states no rule that rejects, while `aaControls` and `acProxying`
 * carry constraints this verb does not evaluate, so a critical one is refused. A critical extension
 * defined in future defaults to refused. The verdict carries `extensions` so an audit identity
 * reaches the caller for the logging section 4.3.1 asks for.
 *
 * Targeting compares `opts.target` against the `targetName` and `targetGroup` alternatives only,
 * under each GeneralName form's own matching rule: a dNSName folds case across the whole name
 * (RFC 5280 sec. 7.2), a mailbox matches its local-part exactly and its host-part case-insensitively
 * (sec. 7.5), and a directoryName goes through the same distinguished-name comparison the rest of
 * the toolkit uses (sec. 7.1). A URI compares as encoded, because sec. 7.4 makes URI equality a full
 * RFC 3987 normalization -- percent-encoding, path segments and scheme-based rules -- and a partial
 * one could match a URI it should not. A form with no comparison here (otherName, ediPartyName,
 * x400Address) leaves `targetingChecked: false` and never a pass. Every one of those limits can
 * refuse a target a fuller comparison would accept, and none can accept one it would refuse.
 * Re-open condition: an RFC 3987 normalizer, at which point URIs compare under sec. 7.4.
 *
 * Items 1 and 3, and the issuer path in item 2, need certificates this verb is not given: the
 * holder's own public-key certificate and its chain, the AC issuer's chain, and the section 4.5
 * profile of the issuer's certificate. Run those through `pki.path.validate` with the certificates
 * you hold. The verdict reports them as `holderBindingChecked: false` and `issuerPathChecked:
 * false` rather than leaving their absence to read as a pass, and `verified` never means more than
 * the checks whose slots are true. Re-open condition: when a caller can pass the holder and issuer
 * certificates, both become checks this verb performs and both slots follow the arguments.
 *
 * @opts
 *   time    the instant to evaluate the AC at. Omitting it leaves section 5 item 5 unasked, which
 *           reports `validityChecked: false` and never `verified: true`.
 *   target  a GeneralName naming this verifier, for the section 4.3.2 targeting check.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var aaSpki = await pki.key.export(pair.publicKey);
 *   var aaKey = await pki.key.export(pair.privateKey);
 *   var acDer = await pki.attrcert.sign({
 *     holder: { entityName: { directoryName: "CN=Alice" } },
 *     notBeforeTime: new Date("2026-01-01T00:00:00Z"),
 *     notAfterTime: new Date("2027-01-01T00:00:00Z"),
 *     attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } },
 *   }, { name: "CN=Example AA", publicKey: aaSpki, key: aaKey });
 *   var r = await pki.attrcert.verify(acDer, { name: "CN=Example AA", publicKey: aaSpki },
 *     { time: new Date("2026-06-01T00:00:00Z") });
 *   r.verified;      // true when every check whose slot is true passed
 *   r.attributes;    // the privileges, re-derived from the signed bytes
 */
function verify(ac, issuer, opts) {
  return guard.async.deferred(function () { return _verify(ac, issuer, opts); });
}
function _verify(ac, issuer, opts) {
  var o = guard.identifier.optionsObject(opts, _err, "attrcert/bad-input", "pki.attrcert.verify options");
  guard.identifier.assertKnownKeys(o, KNOWN_VERIFY_OPTS, _err, "attrcert/bad-input",
    "pki.attrcert.verify has an unknown option ");
  var parsed = _coerceAc(ac);
  var trust = _resolveIssuer(issuer);

  var acIssuer = _acIssuerName(parsed);
  var result = {
    holder: parsed.holder,
    issuer: acIssuer,
    attributes: parsed.attributes,
    // Carried so a caller can act on what rode along: sec. 4.3.1 asks that an audit identity be
    // used for audit and logging, which it cannot be if the verdict drops it.
    extensions: parsed.extensions,
    notBefore: parsed.validity.notBeforeTime,
    notAfter: parsed.validity.notAfterTime,
    serialNumberHex: parsed.serialNumberHex,
    signatureValid: false,
    validityChecked: false,
    targetingChecked: false,
    holderBindingChecked: false,   // item 1 needs the holder's certificate, which this verb is not given
    issuerPathChecked: false,      // items 2 and 3 need the issuer's chain, likewise
    verified: false,
    reason: undefined,
  };

  // The signature runs first so `signatureValid` is answered even when a later gate refuses: an
  // operator reading an out-of-window verdict still learns whether the bytes were authentic.
  return Promise.resolve(attrcertVerify.verifyAcSignature(parsed, trust.spki)).then(function (sigOk) {
    result.signatureValid = sigOk === true;
    var fail = function (reason) { result.reason = reason; return result; };
    if (!result.signatureValid) return fail("the signature does not verify under the issuer public key");

    // Item 4: the caller trusts a named AC issuer, and this AC must be the one they named.
    if (!guard.name.dnEqual(acIssuer.rdns, trust.rdns, _err,
      "attrcert/bad-input", "the AC issuer")) {
      return fail("this attribute certificate names issuer " + JSON.stringify(acIssuer.dn) +
        ", which is not the AC issuer this verifier trusts");
    }

    // Item 7, before the fields are read: an unsupported critical extension makes the whole AC
    // unusable, so a caller must not act on attributes carried beside one.
    var badExt = _unsupportedCritical(parsed);
    if (badExt) return fail("this attribute certificate carries an unsupported critical extension (" + badExt + "), which RFC 5755 sec. 5 item 7 requires be rejected");

    // Item 6.
    var targeting = _checkTargeting(parsed, o.target);
    result.targetingChecked = targeting.checked;
    if (!targeting.ok) return fail(targeting.reason);

    // Item 5. An absent instant asks nothing, which cannot read as a pass.
    if (o.time === undefined) {
      return fail("no opts.time was supplied, so RFC 5755 sec. 5 item 5 (the evaluation instant lies within the validity) went unasked");
    }
    guard.time.assertValid(o.time, _err, "attrcert/bad-input", "pki.attrcert.verify opts.time");
    var at = guard.time.instantOf(o.time);
    result.validityChecked = true;
    // "If the evaluation time is equal to either notBeforeTime or notAfterTime, then the AC is
    // timely and this check succeeds" -- both bounds are inclusive.
    if (at < guard.time.instantOf(result.notBefore) || at > guard.time.instantOf(result.notAfter)) {
      return fail("the evaluation instant lies outside this attribute certificate's validity");
    }

    result.verified = true;
    return result;
  });
}

module.exports = { sign: sign, verify: verify };
