// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.attrcert
 * @nav        Signing
 * @title      Attribute certificates
 * @fullname   X.509 attribute certificates (RFC 5755)
 * @intro The RFC 5755 attribute-certificate producing side. `pki.attrcert.sign` builds an
 *   `AttributeCertificateInfo` binding a Holder to a set of privilege attributes (role, clearance,
 *   group, ...) over a validity window, signs it with an Attribute Authority's private key, and emits an
 *   `AttributeCertificate` that `pki.schema.attrcert.parse` accepts and re-validates byte for byte.
 *   Unlike a public-key certificate an attribute certificate is never self-signed: the holder has no
 *   key, so the issuing AA is always a distinct signer. Parsing lives at `pki.schema.attrcert.parse`.
 * @spec RFC 5755
 * @card Build and sign an RFC 5755 attribute certificate as an Attribute Authority.
 */

var asn1 = require("./asn1-der");
var oid = require("./oid");
var attrcert = require("./schema-attrcert");
var x509 = require("./schema-x509");
var signScheme = require("./sign-scheme");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
require("./path-validate");
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

var KNOWN_SPEC_KEYS = { holder: 1, notBeforeTime: 1, notAfterTime: 1, serialNumber: 1, attributes: 1, extensions: 1 };
var KNOWN_HOLDER_KEYS = { entityName: 1, baseCertificateID: 1, fromCertificate: 1, objectDigestInfo: 1 };
var ATTR_OID_NAME = intrinsic.assign(intrinsic.create(null), {
  role: "role", clearance: "clearance", group: "group", chargingIdentity: "chargingIdentity",
  accessIdentity: "accessIdentity", authenticationInfo: "authenticationInfo",
});
var EXT_META = intrinsic.assign(intrinsic.create(null), {
  auditIdentity:          { name: "acAuditIdentity",       critical: true },
  targetInformation:      { name: "targetInformation",     critical: true },
  noRevAvail:             { name: "noRevAvail",            critical: false },
  aaControls:             { name: "aaControls",            critical: true },
  acProxying:             { name: "acProxying",            critical: true },
  authorityKeyIdentifier: { name: "authorityKeyIdentifier", critical: false },
});
var REQUIRED_CRITICALITY = intrinsic.create(null);
Object.keys(EXT_META).forEach(function (k) { REQUIRED_CRITICALITY[O(EXT_META[k].name)] = EXT_META[k].critical; });
var CLASSLIST_BIT = intrinsic.assign(intrinsic.create(null), { unmarked: 0, unclassified: 1, restricted: 2, confidential: 3, secret: 4, topSecret: 5 });

var _tbsNameBytes = pkiBuild.tbsNameField;
function _parseCert(cert, what) {
  return guard.parsed.acceptDerived(cert, "certificate", function (bytes) {
    try { return x509.parse(bytes); }
    catch (e) { if (e instanceof AttrCertError) throw e; throw _err("attrcert/bad-input", what + " is not a well-formed certificate", e); }
  }, _err, "attrcert/bad-input", what);
}
function _oidContent(name) {
  var dotted = O(name) || name;
  var enc;
  try { enc = b.oid(dotted); } catch (e) { throw _err("attrcert/bad-input", "not a valid object identifier: " + JSON.stringify(name), e); }
  return asn1.decode(enc).content;
}
function _gnList(spec) {
  if (Array.isArray(spec)) return spec;
  return [spec];
}


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
var ODT_CODE = intrinsic.assign(intrinsic.create(null), { publicKey: 0, publicKeyCert: 1 });
function _objectDigestInfoContent(odi) {
  if (!odi || typeof odi !== "object" || Buffer.isBuffer(odi)) throw _err("attrcert/bad-input", "objectDigestInfo must be an object");
  var code = ODT_CODE[guard.text.keyOf(odi.digestedObjectType)];
  if (code == null) throw _err("attrcert/bad-input", "objectDigestInfo.digestedObjectType must be 'publicKey' or 'publicKeyCert' (otherObjectTypes is forbidden, RFC 5755 sec. 7.3)");
  if (!Buffer.isBuffer(odi.objectDigest)) throw _err("attrcert/bad-input", "objectDigestInfo.objectDigest must be a Buffer (the whole-octet digest)");
  var algName = odi.digestAlgorithm;
  var algOid = O(algName) || algName;
  var algTlv;
  try { algTlv = b.sequence([b.oid(algOid)]); } catch (e) { throw _err("attrcert/bad-input", "objectDigestInfo.digestAlgorithm is not a valid algorithm identifier", e); }
  return Buffer.concat([b.enumerated(BigInt(code)), algTlv, b.bitString(odi.objectDigest, 0)]);
}
function _encodeHolder(holder) {
  if (!holder || typeof holder !== "object" || Buffer.isBuffer(holder)) throw _err("attrcert/bad-input", "holder must be an object with exactly one form");
  guard.identifier.assertKnownKeys(holder, KNOWN_HOLDER_KEYS, _err, "attrcert/bad-input", "unknown holder form ");
  var forms = Object.keys(holder).filter(function (k) { return holder[k] != null; });
  if (forms.length !== 1) throw _err("attrcert/bad-input", "holder must carry exactly one form (entityName, baseCertificateID, fromCertificate, or objectDigestInfo), got " + forms.length);
  if (holder.entityName != null) {
    return b.sequence([_b.encodeGeneralNames(_gnList(holder.entityName), 1)]);
  }
  if (holder.baseCertificateID != null) {
    return b.sequence([b.contextConstructed(0, _issuerSerialContent(holder.baseCertificateID))]);
  }
  if (holder.fromCertificate != null) {
    var pkc = _parseCert(holder.fromCertificate, "holder.fromCertificate");
    var content = _issuerSerialContent({ issuer: [{ directoryName: _tbsNameBytes(pkc, "issuer") }], serial: pkiBuild.tbsSerialNumber(pkc) });
    return b.sequence([b.contextConstructed(0, content)]);
  }
  return b.sequence([b.contextConstructed(2, _objectDigestInfoContent(holder.objectDigestInfo))]);
}

function _encodeV2FormIssuer(dnSpec) {
  var dnDer = _b.encodeName(dnSpec == null ? [] : dnSpec);
  if (_b.isEmptyName(dnDer)) throw _err("attrcert/bad-issuer-name", "the AA issuerName must be a non-empty distinguished name (RFC 5755 sec. 4.2.3)");
  var issuerNameGns = _b.encodeGeneralNames([{ directoryName: dnDer }]);
  return b.contextConstructed(0, issuerNameGns);
}
function _encodeValidity(notBefore, notAfter) {
  guard.time.assertValid(notBefore, _err, "attrcert/bad-input", "notBeforeTime");
  guard.time.assertValid(notAfter, _err, "attrcert/bad-input", "notAfterTime");
  // allow:nan-date-comparison-unguarded -- both operands are guard.time.assertValid'd above.
  if (guard.time.instantOf(notBefore) > guard.time.instantOf(notAfter)) throw _err("attrcert/bad-input", "notBeforeTime must not be after notAfterTime (RFC 5755 sec. 4.2.6)");
  return b.sequence([b.generalizedTime(notBefore), b.generalizedTime(notAfter)]);
}


function _encodeRole(role) {
  if (!role || typeof role !== "object" || role.roleName == null) throw _err("attrcert/bad-input", "role must be an object with a roleName GeneralName");
  var parts = [];
  if (role.roleAuthority != null) parts.push(_b.encodeGeneralNames(_gnList(role.roleAuthority), 0));
  parts.push(b.explicit(1, _b.encodeGeneralName(role.roleName)));
  return b.sequence(parts);
}
function _encodeClearance(cl) {
  if (!cl || typeof cl !== "object" || cl.policyId == null) throw _err("attrcert/bad-input", "clearance must be an object with a policyId OID");
  var parts;
  try { parts = [b.oid(O(cl.policyId) || cl.policyId)]; } catch (e) { throw _err("attrcert/bad-input", "clearance.policyId is not a valid object identifier", e); }
  if (cl.classList != null) {
    if (!Array.isArray(cl.classList)) throw _err("attrcert/bad-input", "clearance.classList must be an array of class names");
    var positions = cl.classList.map(function (n) {
      var pos = CLASSLIST_BIT[guard.text.keyOf(n)];
      if (pos == null) throw _err("attrcert/bad-input", "unknown clearance class " + guard.text.showValue(n));
      return pos;
    });
    var isDefault = positions.length === 1 && positions[0] === CLASSLIST_BIT.unclassified;
    if (!isDefault) parts.push(b.namedBitString(positions));
  }
  if (cl.securityCategories != null) {
    if (!Array.isArray(cl.securityCategories) || !cl.securityCategories.length) throw _err("attrcert/bad-input", "clearance.securityCategories must be a non-empty array");
    parts.push(b.set(cl.securityCategories.map(_encodeSecurityCategory)));
  }
  return b.sequence(parts);
}
function _encodeSecurityCategory(sc) {
  if (!sc || typeof sc !== "object" || sc.type == null || !Buffer.isBuffer(sc.value)) throw _err("attrcert/bad-input", "each securityCategory must be { type: OID, value: DER Buffer }");
  var node;
  try { node = asn1.decode(sc.value); } catch (e) { throw _err("attrcert/bad-input", "securityCategory value must be a single well-formed DER element", e); }
  if (node.bytes.length !== sc.value.length) throw _err("attrcert/bad-input", "securityCategory value must be exactly one DER element (no trailing bytes)");
  return b.sequence([b.contextPrimitive(0, _oidContent(sc.type)), b.explicit(1, sc.value)]);
}
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

var ATTR_VALUE_ENCODER = intrinsic.assign(intrinsic.create(null), {
  role:               function (v) { return _encodeRole(v); },
  clearance:          function (v) { return _encodeClearance(v); },
  group:              function (v) { return _encodeIetfAttrSyntax(v); },
  chargingIdentity:   function (v) { return _encodeIetfAttrSyntax(v); },
  authenticationInfo: function (v) { return _encodeSvceAuthInfo(v, true, "authenticationInfo"); },
  accessIdentity:     function (v) { return _encodeSvceAuthInfo(v, false, "accessIdentity"); },
});


function _encodeTarget(t) {
  if (!t || typeof t !== "object") throw _err("attrcert/bad-input", "each target must be { targetName } or { targetGroup }");
  if (t.targetName != null) return b.explicit(0, _b.encodeGeneralName(t.targetName));
  if (t.targetGroup != null) return b.explicit(1, _b.encodeGeneralName(t.targetGroup));
  throw _err("attrcert/bad-input", "each target must be { targetName } or { targetGroup }");
}
function _encodeSeqOfTargets(targets) {
  if (!Array.isArray(targets) || !targets.length) throw _err("attrcert/bad-input", "a targets value must be a non-empty array of targets");
  return b.sequence([b.sequence(targets.map(_encodeTarget))]);
}
function _attrSpec(names, tag, label) {
  if (!Array.isArray(names)) throw _err("attrcert/bad-input", "aaControls." + label + " must be an array of attribute-type OIDs");
  var oids = names.map(function (n) {
    try { return b.oid(O(n) || n); } catch (e) { throw _err("attrcert/bad-input", "aaControls." + label + " contains an invalid object identifier " + guard.text.showValue(n), e); }
  });
  return b.contextConstructed(tag, Buffer.concat(oids));
}
function _encodeAAControls(aac) {
  if (!aac || typeof aac !== "object" || Buffer.isBuffer(aac)) throw _err("attrcert/bad-input", "aaControls must be an object");
  var parts = [];
  if (aac.pathLenConstraint != null) {
    if (typeof aac.pathLenConstraint !== "number" || !Number.isInteger(aac.pathLenConstraint) || aac.pathLenConstraint < 0 || aac.pathLenConstraint > 0x7fffffff) throw _err("attrcert/bad-input", "aaControls.pathLenConstraint must be an integer in 0..2147483647 (RFC 5755 sec. 7.4)");
    parts.push(b.integer(BigInt(aac.pathLenConstraint)));
  }
  if (aac.permittedAttrs != null) parts.push(_attrSpec(aac.permittedAttrs, 0, "permittedAttrs"));
  if (aac.excludedAttrs != null) parts.push(_attrSpec(aac.excludedAttrs, 1, "excludedAttrs"));
  if (aac.permitUnSpecified === false) parts.push(b.boolean(false));
  else if (aac.permitUnSpecified != null && aac.permitUnSpecified !== true) throw _err("attrcert/bad-input", "aaControls.permitUnSpecified must be a boolean");
  return b.sequence(parts);
}
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

function _assertRevocationSchemesExclusive(seen) {
  if (!_hasOwn(seen, O("noRevAvail"))) return;
  var names = Object.keys(REVOCATION_POINTERS);
  for (var i = 0; i < names.length; i++) {
    if (_hasOwn(seen, names[i])) {
      throw _err("attrcert/bad-input", "an attribute certificate must not carry both noRevAvail and a " +
        REVOCATION_POINTERS[names[i]] + " revocation pointer (RFC 5755 sec. 6)");
    }
  }
}

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
      var required = REQUIRED_CRITICALITY[extnId];
      if (required != null && (n.children.length === 3) !== required) {
        throw _err("attrcert/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension must be marked " + (required ? "critical" : "non-critical") + " (RFC 5755)");
      }
      var extnValue = asn1.read.octetString(n.children[n.children.length - 1]);
      try {
        if (EXT_DECODERS[extnId]) EXT_DECODERS[extnId](extnValue);
        else attrcert.validateExtensionValue(extnId, extnValue);
      } catch (err) { if (err instanceof AttrCertError) throw err; throw _err("attrcert/bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension value is malformed", err); }
      return b.raw(der);
    });
    _assertRevocationSchemesExclusive(seenA);
    return b.sequence(exts);
  }
  if (typeof extSpec !== "object") throw _err("attrcert/bad-input", "extensions must be an object or an array of pre-encoded Extension DER");
  guard.identifier.assertKnownKeys(extSpec, EXT_META, _err, "attrcert/bad-input", function (k) {
    return "unknown extension " + JSON.stringify(k) + "; pass a pre-encoded Extension DER via the array form for a custom extension";
  });
  var out = [], seen = {};
  Object.keys(extSpec).forEach(function (k) {
    if (extSpec[k] == null) return;
    var meta = EXT_META[k], eOid = O(meta.name);
    if (seen[eOid]) throw _err("attrcert/bad-input", "duplicate extension " + JSON.stringify(k) + " (RFC 5755 sec. 4.2.9)");
    seen[eOid] = true;
    out.push(_b.ext(eOid, meta.critical, _extensionValue(k, extSpec[k], aaSpki)));
  });
  _assertRevocationSchemesExclusive(seen);
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
 * describes the certificate: `holder` (exactly one form: `entityName`, `baseCertificateID`,
 * `fromCertificate` to bind a public-key certificate's identity, or `objectDigestInfo`), `notBeforeTime`
 * / `notAfterTime` (`Date`s -> GeneralizedTime), an optional `serialNumber` (positive, <= 20 octets;
 * a random 20-octet serial is generated when omitted), `attributes` (an object of the sec. 4.4 privilege
 * syntaxes (role / clearance / group / chargingIdentity / accessIdentity / authenticationInfo), or an
 * array of pre-encoded Attribute DER), and optional `extensions` (an object of auditIdentity /
 * targetInformation / noRevAvail / aaControls / acProxying / authorityKeyIdentifier, or an array of
 * pre-encoded Extension DER). `issuer` is the signing AA: `{ cert, key }` (the AA certificate DER/PEM
 * and its private key) or `{ name, publicKey, key }` (an explicit issuer DN, AA SPKI DER, and key); an
 * attribute certificate is never self-signed. RFC 5755 section 6 defines two revocation schemes and
 * makes them exclusive ("An AC MUST NOT contain both a noRevAvail extension and a 'pointer in AC'"),
 * so `noRevAvail` beside a `crlDistributionPoints` or `authorityInfoAccess` extension is refused,
 * in the named form and the pre-encoded form alike. The signature algorithm is resolved from the AA key (RSA
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
  return guard.bytes.fixedCall(AttrCertError, "attrcert/bad-input", [
    [spec, "the attribute-certificate spec"], [issuer, "the issuer"], [opts, "pki.attrcert.sign options"],
  ], _sign);
}

function _sign(spec, issuer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("attrcert/bad-input", "the attribute-certificate spec must be an object");
  guard.identifier.assertKnownKeys(spec, KNOWN_SPEC_KEYS, _err, "attrcert/bad-input", "unknown spec field ");
  issuer = issuer || {};
  if (issuer.key == null) throw _err("attrcert/bad-input", "a signing key (issuer.key, the AA's WebCrypto CryptoKey or PKCS#8 private key DER/PEM) is required");

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

  var scheme = signScheme.resolveSignScheme(_b.certLikeFromSpki(aaSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  var acinfoChildren = [
    b.integer(1n), holderDer, issuerDer, scheme.sigAlgId,
    _b.serialInteger(spec.serialNumber), validityDer, attributesDer,
  ];
  if (extsDer) acinfoChildren.push(extsDer);
  var acinfoDer = b.sequence(acinfoChildren);

  return signScheme.signOverTbs(scheme, issuer.key, acinfoDer, _signE).then(function (sig) {
    return Promise.resolve(_b.assertSignatureVerifies(acinfoDer, sig, aaSpki, scheme)).then(function () {
      var acDer = b.sequence([acinfoDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? attrcert.pemEncode(acDer, "ATTRIBUTE CERTIFICATE") : acDer;
    });
  }, function (e) {
    if (e instanceof AttrCertError) throw e;
    throw _err("attrcert/bad-input", "signing the attribute certificate failed -- the signing key does not match the resolved algorithm or is invalid", e);
  });
}

var KNOWN_VERIFY_OPTS = { time: 1, target: 1, revocationStatus: 1 };
var REVOCATION_STATUS = Object.create(null);
REVOCATION_STATUS.notRevoked = 1;
REVOCATION_STATUS.revoked = 1;
var _NAME_SCHEMA = pkix.name(NS);

function _readName(der, what) {
  try { return schema.walk(_NAME_SCHEMA, asn1.decode(der), NS).result; }
  catch (e) {
    if (e instanceof AttrCertError) throw e;
    throw _err("attrcert/bad-input", what + " is not a readable distinguished name", e);
  }
}

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

function _resolveIssuer(issuer) {
  if (issuer == null || typeof issuer !== "object" || Buffer.isBuffer(issuer)) {
    throw _err("attrcert/bad-input", "an issuer { name, publicKey } is required -- RFC 5755 sec. 5 item 4 makes trusting an AC issuer the verifier's own configuration");
  }
  guard.identifier.assertKnownKeys(issuer, { name: 1, publicKey: 1 }, _err, "attrcert/bad-input",
    "the issuer has an unknown key ");
  if (issuer.publicKey == null) throw _err("attrcert/bad-input", "issuer.publicKey (the AC issuer's SubjectPublicKeyInfo DER) is required");
  if (issuer.name == null) {
    throw _err("attrcert/bad-input", "issuer.name (the distinguished name this verifier trusts as an AC issuer) is required");
  }
  var trustedDer;
  try { trustedDer = _b.encodeName(issuer.name); }
  catch (e) {
    if (e instanceof AttrCertError) throw e;
    throw _err("attrcert/bad-input", "issuer.name is not a distinguished name", e);
  }
  var rdns = _readName(trustedDer, "issuer.name").rdns;
  if (!rdns.length) {
    throw _err("attrcert/bad-input", "issuer.name is an empty distinguished name, which names no AC issuer (RFC 5755 sec. 4.2.3)");
  }
  return {
    rdns: rdns,
    spki: guard.bytes.snapshot(issuer.publicKey, AttrCertError, "attrcert/bad-input", "issuer.publicKey"),
  };
}

function _callerTarget(target) {
  return attrcert.readGeneralName(_b.encodeGeneralName(target), "attrcert/bad-input");
}

function _mailboxEqual(a, bx) {
  var i = a.lastIndexOf("@"), j = bx.lastIndexOf("@");
  if (i < 0 || j < 0) return a === bx;
  return a.slice(0, i) === bx.slice(0, j) &&
    a.slice(i + 1).toLowerCase() === bx.slice(j + 1).toLowerCase();
}

function _generalNameMatches(entry, want) {
  if (!entry || entry.tagNumber !== want.tagNumber) return false;
  switch (entry.tagNumber) {
    case 2: return String(entry.value).toLowerCase() === String(want.value).toLowerCase();
    case 1: return _mailboxEqual(String(entry.value), String(want.value));
    case 4:
      return !!(entry.value && want.value) &&
        guard.name.dnEqual(entry.value.rdns, want.value.rdns, _err, "attrcert/bad-input", "the target name");
    default:
      if (Buffer.isBuffer(entry.value) && Buffer.isBuffer(want.value)) return entry.value.equals(want.value);
      if (typeof entry.value === "string" && typeof want.value === "string") return entry.value === want.value;
      return null;
  }
}

function _checkTargeting(ac, want) {
  var ext = null;
  for (var i = 0; i < ac.extensions.length; i++) {
    if (ac.extensions[i].name === "targetInformation") ext = ac.extensions[i];
  }
  if (!ext) return { checked: true, ok: true };
  if (want === undefined) {
    return { checked: false, ok: false,
      reason: "this attribute certificate is targeted, and no opts.target names this verifier (RFC 5755 sec. 4.3.2)" };
  }
  var groups = ext.decoded || [];
  for (var g0 = 0; g0 < groups.length; g0++) {
    for (var t0 = 0; t0 < groups[g0].length; t0++) {
      if (groups[g0][t0].kind !== "targetCert") continue;
      return { checked: false, ok: false,
        reason: "this attribute certificate carries a targetCert target, which RFC 5755 sec. 4.3.2 says MUST NOT be used, so the targeting check did not run" };
    }
  }

  var uncomparable = null;
  for (var g = 0; g < groups.length; g++) {
    for (var t = 0; t < groups[g].length; t++) {
      var entry = groups[g][t];
      if (entry.kind !== "targetName" && entry.kind !== "targetGroup") continue;
      var m = _generalNameMatches(entry.name, want);
      if (m === true) return { checked: true, ok: true };
      if (m === null) uncomparable = entry.name && entry.name.tagNumber;
    }
  }
  if (uncomparable !== null) {
    return { checked: false, ok: false,
      reason: "this attribute certificate names a target in a GeneralName form ([" + uncomparable +
        "]) this verifier does not compare, so the RFC 5755 sec. 4.3.2 check did not run" };
  }
  return { checked: true, ok: false,
    reason: "this attribute certificate does not name this verifier among its targets (RFC 5755 sec. 4.3.2)" };
}

var SUPPORTED_CRITICAL = {};
SUPPORTED_CRITICAL[O("targetInformation")] = 1;
SUPPORTED_CRITICAL[O("acAuditIdentity")] = 1;

function _unsupportedCritical(ac) {
  for (var i = 0; i < ac.extensions.length; i++) {
    var e = ac.extensions[i];
    if (e.critical !== true) continue;
    if (!_hasOwn(SUPPORTED_CRITICAL, e.oid)) return e.oid;
    if (e.decoded === null || e.decoded === undefined || e.decoded.opaque === true) return e.oid;
  }
  return null;
}

/**
 * @primitive pki.attrcert.verify
 * @signature pki.attrcert.verify(ac, issuer, opts) -> Promise<{ valid, verified, signatureValid, validityChecked, targetingChecked, revocationChecked, noRevAvail, holderBindingChecked, issuerPathChecked, holder, issuer, attributes, extensions, notBefore, notAfter, serialNumberHex, reason }>
 * @since 0.5.15
 * @status stable
 * @spec RFC 5755 sec. 5
 * @defends attribute-certificate-forgery (CWE-347)
 * @related pki.attrcert.sign, pki.path.validate, pki.schema.attrcert.parse
 *
 * Verify an RFC 5755 attribute certificate. An AC carries privilege attributes (a role, a group, a
 * clearance), so a consumer that reads them without this grants privileges on unauthenticated
 * input. `ac` is a DER `Buffer`, a PEM string, or a parsed attribute certificate; `issuer` is
 * `{ name, publicKey }`, the AC issuer this verifier trusts as an AC issuer, which section 5 item 4
 * makes the verifier's own configuration and this verb therefore refuses to infer from the AC.
 * `issuer.name` takes every form `pki.attrcert.sign` accepts for the issuing AA (a string, an
 * array of RDNs, or raw `Name` DER) and is compared as a distinguished name (RFC 5280 section
 * 7.1), so an AC issued under a multi-RDN authority name is verifiable under that same name.
 *
 * Both options are read at the call, before signature verification suspends it, so a caller that
 * reuses or rewrites its options object (including calling `setTime` on the `Date` it passed in)
 * cannot change the verdict that call returns.
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
 * RFC 3987 normalization (percent-encoding, path segments and scheme-based rules) and a partial
 * one could match a URI it should not. A form with no comparison here (otherName, ediPartyName,
 * x400Address) leaves `targetingChecked: false` and never a pass. Every one of those limits can
 * refuse a target a fuller comparison would accept, and none can accept one it would refuse.
 * Re-open condition: an RFC 3987 normalizer, at which point URIs compare under sec. 7.4.
 *
 * The third `Target` alternative, `targetCert`, is one section 4.3.2 says "MUST NOT be used", so an
 * attribute certificate carrying one is refused before any match is considered, with
 * `targetingChecked: false`. A match on some other entry does not rescue it: the issuer broke a MUST
 * NOT of its own profile, and letting the verdict turn on which entries rode alongside the forbidden
 * one would leave the outcome to whoever assembled the certificate.
 *
 * Revocation is section 6, outside the seven. This verb implements that section's "never revoke"
 * scheme, which AC users MUST support: it holds no revocation evidence and follows no pointer out
 * of the certificate. The section states the consequence, "If only the 'never revoke' scheme is
 * supported, then all ACs that do not contain a noRevAvail extension, MUST be rejected", because
 * an issuer that omits noRevAvail is stating that revocation status checks are supported, and a
 * verdict that skipped one would grant privileges the issuer expected to be able to withdraw. So an
 * AC carrying `noRevAvail` verifies with `revocationChecked: true` and `noRevAvail: true`, and one
 * without it is refused unless the caller supplies `opts.revocationStatus`. A caller running the
 * section's "pointer in AC" scheme reads the certificate's own `crlDistributionPoints` /
 * `authorityInfoAccess` from the verdict's `extensions`, establishes the status, and passes it back.
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
 *   revocationStatus
 *           `"notRevoked"` or `"revoked"`, the status the caller established for this AC through
 *           the section 6 "pointer in AC" scheme. Supplying it answers section 6 for an AC that
 *           carries no `noRevAvail`; omitting it leaves such an AC refused.
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
 *     // RFC 5755 sec. 6: the issuer states no revocation information will exist for this AC.
 *     extensions: { noRevAvail: true },
 *   }, { name: "CN=Example AA", publicKey: aaSpki, key: aaKey });
 *   var r = await pki.attrcert.verify(acDer, { name: "CN=Example AA", publicKey: aaSpki },
 *     { time: new Date("2026-06-01T00:00:00Z") });
 *   r.verified;      // true when every check whose slot is true passed
 *   r.attributes;    // the privileges, re-derived from the signed bytes
 */
function verify(ac, issuer, opts) {
  return guard.async.deferred(function () { return _verify(ac, issuer, opts); });
}
function _fixVerifyOptions(opts) {
  var o = guard.identifier.optionsObject(opts, _err, "attrcert/bad-input", "pki.attrcert.verify options");
  guard.identifier.assertKnownKeys(o, KNOWN_VERIFY_OPTS, _err, "attrcert/bad-input",
    "pki.attrcert.verify has an unknown option ");
  var at = null;
  if (o.time !== undefined) {
    guard.time.assertValid(o.time, _err, "attrcert/bad-input", "pki.attrcert.verify opts.time");
    at = guard.time.instantOf(o.time);
  }
  var revocationStatus = null;
  if (o.revocationStatus !== undefined) {
    if (typeof o.revocationStatus !== "string" ||
      !_hasOwn(REVOCATION_STATUS, o.revocationStatus)) {
      throw _err("attrcert/bad-input", 'pki.attrcert.verify opts.revocationStatus must be "notRevoked" or "revoked"');
    }
    revocationStatus = o.revocationStatus;
  }
  return {
    at: at, revocationStatus: revocationStatus,
    target: o.target === undefined ? undefined : _callerTarget(o.target),
  };
}

var REVOCATION_POINTERS = Object.create(null);
REVOCATION_POINTERS[O("cRLDistributionPoints")] = "crlDistributionPoints";
REVOCATION_POINTERS[O("authorityInfoAccess")] = "authorityInfoAccess";

function _revocationScheme(ac) {
  var out = { noRevAvail: false, pointer: null };
  for (var i = 0; i < ac.extensions.length; i++) {
    var e = ac.extensions[i];
    if (e.name === "noRevAvail") out.noRevAvail = true;
    var p = REVOCATION_POINTERS[e.oid];
    if (p !== undefined && _hasOwn(REVOCATION_POINTERS, e.oid)) out.pointer = p;
  }
  return out;
}

function _verify(ac, issuer, opts) {
  var fixed = _fixVerifyOptions(opts);
  var parsed = _coerceAc(ac);
  var trust = _resolveIssuer(issuer);

  var acIssuer = _acIssuerName(parsed);
  var result = guard.verdict.of({
    holder: parsed.holder,
    issuer: acIssuer,
    attributes: parsed.attributes,
    extensions: parsed.extensions,
    notBefore: parsed.validity.notBeforeTime,
    notAfter: parsed.validity.notAfterTime,
    serialNumberHex: parsed.serialNumberHex,
    signatureValid: false,
    validityChecked: false,
    targetingChecked: false,
    revocationChecked: false,
    noRevAvail: false,
    holderBindingChecked: false,
    issuerPathChecked: false,
    valid: false,
    verified: false,
    reason: undefined,
  });

  return Promise.resolve(attrcertVerify.verifyAcSignature(parsed, trust.spki)).then(function (sigOk) {
    result.signatureValid = sigOk === true;
    var fail = function (reason) { result.reason = reason; return result; };
    if (!result.signatureValid) return fail("the signature does not verify under the issuer public key");

    if (!guard.name.dnEqual(acIssuer.rdns, trust.rdns, _err,
      "attrcert/bad-input", "the AC issuer")) {
      return fail("this attribute certificate names issuer " + JSON.stringify(acIssuer.dn) +
        ", which is not the AC issuer this verifier trusts");
    }

    var badExt = _unsupportedCritical(parsed);
    if (badExt) return fail("this attribute certificate carries an unsupported critical extension (" + badExt + "), which RFC 5755 sec. 5 item 7 requires be rejected");

    var targeting = _checkTargeting(parsed, fixed.target);
    result.targetingChecked = targeting.checked;
    if (!targeting.ok) return fail(targeting.reason);

    if (fixed.at === null) {
      return fail("no opts.time was supplied, so RFC 5755 sec. 5 item 5 (the evaluation instant lies within the validity) went unasked");
    }
    result.validityChecked = true;
    if (fixed.at < guard.time.instantOf(result.notBefore) || fixed.at > guard.time.instantOf(result.notAfter)) {
      return fail("the evaluation instant lies outside this attribute certificate's validity");
    }

    var scheme = _revocationScheme(parsed);
    result.noRevAvail = scheme.noRevAvail;
    if (scheme.noRevAvail && scheme.pointer) {
      return fail("this attribute certificate carries both noRevAvail and a " + scheme.pointer +
        " revocation pointer, which RFC 5755 sec. 6 says an AC MUST NOT do");
    }
    if (fixed.revocationStatus !== null) {
      result.revocationChecked = true;
      if (fixed.revocationStatus === "revoked") {
        return fail("this attribute certificate is revoked, as opts.revocationStatus reports");
      }
    } else if (result.noRevAvail) {
      result.revocationChecked = true;
    } else {
      return fail("this attribute certificate carries no noRevAvail extension, so its issuer supports revocation status checks and RFC 5755 sec. 6 requires one; establish the status from the certificate's own pointers and pass it as opts.revocationStatus");
    }

    result.verified = true;
    result.valid = true;
    return result;
  });
}

module.exports = { sign: sign, verify: verify };
