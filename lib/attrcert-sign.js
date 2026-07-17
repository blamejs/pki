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
 *   Unlike a public-key certificate an attribute certificate is never self-signed -- the holder has no
 *   key, so the issuing AA is always a distinct signer. Parsing lives at `pki.schema.attrcert.parse`.
 * @spec RFC 5755
 * @card Build and sign an RFC 5755 attribute certificate as an Attribute Authority.
 */
//
// RFC 5755 is DEFINITIONS IMPLICIT TAGS (App. B): a context [n] on a non-CHOICE component REPLACES the
// underlying tag (its children ARE the component's fields -- Holder [0]/[1]/[2], AttCertIssuer v2Form [0],
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
// ClassList ::= BIT STRING { unmarked(0) .. topSecret(5) } (RFC 5755 sec. 4.4.4) -- the encode inverse of
// the schema-attrcert.js _CLASSLIST_NAMES decode array; DEFAULT {unclassified} (bit 1) is omitted.
var CLASSLIST_BIT = { unmarked: 0, unclassified: 1, restricted: 2, confidential: 3, secret: 4, topSecret: 5 };

var _tbsNameBytes = pkiBuild.tbsNameField;   // the AA issuerName / holder baseCertificateID chain exactly to a cert's DN
// Parse a certificate DER/PEM (or accept a parsed certificate), re-typing a raw x509/* parse fault to the
// attrcert domain so a malformed AA cert / holder cert surfaces attrcert/*, not a foreign CertificateError.
function _parseCert(cert, what) {
  if (!Buffer.isBuffer(cert) && typeof cert !== "string") {
    if (!cert || !cert.tbsBytes) throw _err("attrcert/bad-input", what + " must be a certificate DER/PEM or a parsed certificate");
    return cert;
  }
  try { return x509.parse(cert); }
  catch (e) { if (e instanceof AttrCertError) throw e; throw _err("attrcert/bad-input", what + " is not a well-formed certificate", e); }
}
// The raw content octets of an OBJECT IDENTIFIER (past its own tag+len) -- the body of a [0] IMPLICIT OID.
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
// OPTIONAL }. Returns the CONTENT (concatenated field TLVs) so a [n] IMPLICIT caller wraps it directly.
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
// 7.3), so otherObjectTypeID is never emitted. Returns the CONTENT for a [n] IMPLICIT caller.
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
// objectDigestInfo [2] IMPLICIT ObjectDigestInfo } -- exactly one form (the profile binds a real holder).
function _encodeHolder(holder) {
  if (!holder || typeof holder !== "object" || Buffer.isBuffer(holder)) throw _err("attrcert/bad-input", "holder must be an object with exactly one form");
  Object.keys(holder).forEach(function (k) { if (!KNOWN_HOLDER_KEYS[k]) throw _err("attrcert/bad-input", "unknown holder form " + JSON.stringify(k)); });
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
    var pkc = _parseCert(holder.fromCertificate, "holder.fromCertificate");
    var content = _issuerSerialContent({ issuer: [{ directoryName: _tbsNameBytes(pkc, "issuer") }], serial: pkc.serialNumber });
    return b.sequence([b.contextConstructed(0, content)]);
  }
  // objectDigestInfo [2] IMPLICIT ObjectDigestInfo.
  return b.sequence([b.contextConstructed(2, _objectDigestInfoContent(holder.objectDigestInfo))]);
}

// AttCertIssuer v2Form [0] IMPLICIT V2Form { issuerName GeneralNames } -- issuerName is exactly one
// directoryName [4] over a non-empty DN (RFC 5755 sec. 4.2.3). The [0] replaces the V2Form SEQUENCE tag.
function _encodeV2FormIssuer(dnSpec) {
  var dnDer = _b.encodeName(dnSpec == null ? [] : dnSpec);
  if (_b.isEmptyName(dnDer)) throw _err("attrcert/bad-issuer-name", "the AA issuerName must be a non-empty distinguished name (RFC 5755 sec. 4.2.3)");
  var issuerNameGns = _b.encodeGeneralNames([{ directoryName: dnDer }]);   // a universal SEQUENCE OF one directoryName
  return b.contextConstructed(0, issuerNameGns);
}
// AttCertValidityPeriod ::= SEQUENCE { notBeforeTime GeneralizedTime, notAfterTime GeneralizedTime }
// (RFC 5755 sec. 4.2.6) -- ALWAYS GeneralizedTime, never UTCTime; reject an inverted window.
function _encodeValidity(notBefore, notAfter) {
  guard.time.assertValid(notBefore, _err, "attrcert/bad-input", "notBeforeTime");
  guard.time.assertValid(notAfter, _err, "attrcert/bad-input", "notAfterTime");
  // allow:nan-date-comparison-unguarded -- both operands are guard.time.assertValid'd above.
  if (notBefore.getTime() > notAfter.getTime()) throw _err("attrcert/bad-input", "notBeforeTime must not be after notAfterTime (RFC 5755 sec. 4.2.6)");
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
// (targetCert [2] is out of v1 scope -- use a pre-encoded Extension DER for a targetCert-bearing value).
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
    // builder emits would fail the round trip -- bound it to the same range at build time.
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

// attributes ::= SEQUENCE OF Attribute (RFC 5755 sec. 4.2.7) -- non-empty, each AttributeType OID unique;
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
  Object.keys(attrSpec).forEach(function (k) {
    if (!ATTR_VALUE_ENCODER[k]) throw _err("attrcert/bad-input", "unknown attribute " + JSON.stringify(k) + "; pass a pre-encoded Attribute DER via the array form for a custom attribute");
    add(O(ATTR_OID_NAME[k]), ATTR_VALUE_ENCODER[k](attrSpec[k]));
  });
  if (!attrs.length) throw _err("attrcert/bad-attributes", "attributes must carry at least one Attribute (RFC 5755 sec. 4.2.7)");
  return b.sequence(attrs);
}

// extensions ::= SEQUENCE OF Extension (RFC 5755 sec. 4.2.9) -- the recognized object form, or an array
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
  Object.keys(extSpec).forEach(function (k) {
    if (!EXT_META[k]) throw _err("attrcert/bad-input", "unknown extension " + JSON.stringify(k) + "; pass a pre-encoded Extension DER via the array form for a custom extension");
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
 * @status experimental
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
 * pre-encoded Extension DER). `issuer` is the signing AA -- `{ cert, key }` (the AA certificate DER/PEM
 * and its private key) or `{ name, publicKey, key }` (an explicit issuer DN, AA SPKI DER, and key); an
 * attribute certificate is never self-signed. The signature algorithm is resolved from the AA key (RSA
 * PKCS#1 v1.5 or PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm), and the signature is verified
 * under the AA public key before the certificate is returned. Returns DER, or a PEM `ATTRIBUTE
 * CERTIFICATE` with `opts.pem`. Malformed input throws a typed `AttrCertError`. The AA certificate's own
 * profile (RFC 5755 sec. 4.5) and validity are a verification-layer concern -- validate the AA
 * certificate with `pki.path.validate` before trusting the attribute certificate. Parsing is
 * `pki.schema.attrcert.parse`.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `ATTRIBUTE CERTIFICATE` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS rather than PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var ac = await pki.attrcert.sign(
 *     { holder: { entityName: { directoryName: "CN=Alice" } },
 *       notBeforeTime: new Date("2026-01-01T00:00:00Z"), notAfterTime: new Date("2027-01-01T00:00:00Z"),
 *       attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } } },
 *     { cert: signerCertDer, key: signerKeyPkcs8 });
 *   pki.schema.attrcert.parse(ac).attributes[0].type;   // the role attribute OID
 */
function sign(spec, issuer, opts) {
  return Promise.resolve().then(function () { return _sign(spec, issuer, opts); });
}

function _sign(spec, issuer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("attrcert/bad-input", "the attribute-certificate spec must be an object");
  Object.keys(spec).forEach(function (k) { if (!KNOWN_SPEC_KEYS[k]) throw _err("attrcert/bad-input", "unknown spec field " + JSON.stringify(k)); });
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

module.exports = { sign: sign };
