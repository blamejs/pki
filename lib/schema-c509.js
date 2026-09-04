// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.schema.c509
 * @nav    Schema
 * @title  C509
 * @fullname   C509 compact certificates (CBOR-encoded X.509)
 * @intro  C509 CBOR-encoded certificates (draft-ietf-cose-cbor-encoded-cert). A compact CBOR
 *   re-encoding of an X.509 v3 certificate: a deterministic-CBOR array of exactly 11 elements
 *   (10 TBS fields + the issuer signature). Two modes: c509CertificateType 2 is a natively-signed
 *   C509, and 3 is a CBOR re-encoding of a DER X.509 certificate that inverts byte-for-byte to the
 *   original DER (so the original signature still verifies). It decodes CBOR, not DER, so it is
 *   reached by an explicit pki.schema.c509.parse call and is never auto-routed by pki.schema.parse.
 * @card  Composes the shipped pki.cbor codec (core-deterministic, fail-closed) + the X.509 model.
 */

var cbor = require("./cbor-det");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
var guard = require("./guard-all");
var constants = require("./constants");
var frameworkError = require("./framework-error");
var validator = require("./validator-all");
var webcrypto = require("./webcrypto");

var b = asn1.build;

var C = constants;
var C509Error = frameworkError.C509Error;
function _err(code, message, cause) { return new C509Error(code, message, cause); }
var MAX_EPOCH_SECONDS = 8640000000000n;
var NO_EXPIRY_SECONDS = 253402300799n;

function _name(n) { var d = oid.byName(n); if (!d) { throw new Error("schema-c509: unregistered OID name " + JSON.stringify(n)); } return n; }

var SIG_ALG_BY_INT = {
  0: _name("ecdsaWithSHA256"),
  1: _name("ecdsaWithSHA384"),
  2: _name("ecdsaWithSHA512"),
};
var PK_ALG_BY_INT = {
  0: { alg: _name("rsaEncryption") },
  1: { alg: _name("ecPublicKey"), curve: _name("prime256v1") },
  2: { alg: _name("ecPublicKey"), curve: _name("secp384r1") },
  3: { alg: _name("ecPublicKey"), curve: _name("secp521r1") },
};
var EC_FIELD_BYTES = Object.assign(Object.create(null), { "prime256v1": 32, "secp384r1": 48, "secp521r1": 66 });

var ATTR_BY_INT = {
  0: _name("emailAddress"),
  1: _name("commonName"),
  2: _name("surname"),
  3: _name("serialNumber"),
  4: _name("countryName"),
  5: _name("localityName"),
  6: _name("stateOrProvinceName"),
  7: _name("streetAddress"),
  8: _name("organizationName"),
  9: _name("organizationalUnitName"),
  10: _name("title"),
};
var EXT_BY_INT = {
  1: _name("subjectKeyIdentifier"),
  2: _name("keyUsage"),
  3: _name("subjectAltName"),
  4: _name("basicConstraints"),
  5: _name("cRLDistributionPoints"),
  6: _name("certificatePolicies"),
  7: _name("authorityKeyIdentifier"),
  8: _name("extKeyUsage"),
  9: _name("authorityInfoAccess"),
  24: _name("subjectDirectoryAttributes"),
  25: _name("issuerAltName"),
  26: _name("nameConstraints"),
  27: _name("policyMappings"),
  28: _name("policyConstraints"),
  29: _name("freshestCRL"),
  30: _name("inhibitAnyPolicy"),
  31: _name("subjectInfoAccess"),
  32: _name("ipAddrBlocks"),
  33: _name("autonomousSysIds"),
  34: _name("ipAddrBlocksV2"),
  35: _name("autonomousSysIdsV2"),
  36: _name("ocspNoCheck"),
  38: _name("tlsFeature"),
};
var EXT_COMPACT = Object.assign(Object.create(null), {
  subjectKeyIdentifier: 1, keyUsage: 1, basicConstraints: 1, authorityKeyIdentifier: 1,
  extKeyUsage: 1, inhibitAnyPolicy: 1, ocspNoCheck: 1, tlsFeature: 1,
  subjectAltName: 1, issuerAltName: 1, nameConstraints: 1, cRLDistributionPoints: 1,
  freshestCRL: 1, authorityInfoAccess: 1, subjectInfoAccess: 1, certificatePolicies: 1,
  policyMappings: 1, policyConstraints: 1, subjectDirectoryAttributes: 1,
  ipAddrBlocks: 1, autonomousSysIds: 1, ipAddrBlocksV2: 1, autonomousSysIdsV2: 1,
});
var EKU_BY_INT = {
  0: _name("anyExtendedKeyUsage"), 1: _name("serverAuth"), 2: _name("clientAuth"),
  3: _name("codeSigning"), 4: _name("emailProtection"), 8: _name("timeStamping"), 9: _name("ocspSigning"),
  10: _name("pkinitClientAuth"), 11: _name("pkinitKdc"), 12: _name("secureShellClient"), 13: _name("secureShellServer"),
  14: _name("bundleSecurity"), 15: _name("cmcCA"), 16: _name("cmcRA"), 17: _name("cmcArchive"), 18: _name("cmKGA"),
  20: _name("fanDevice"),
};
var EKU_TO_INT = {};
Object.keys(EKU_BY_INT).forEach(function (k) { EKU_TO_INT[oid.byName(EKU_BY_INT[k])] = Number(k); });

var NS = pkix.makeNS("c509", C509Error, oid);
var GN_LEAF = pkix.generalName(NS, { decodeValue: true });
var GN_LEAF_SUBTREE = pkix.generalName(NS, { decodeValue: true, subtreeBase: true });

var ON_NAME_BY_INT = { "-1": _name("hardwareModuleName"), "-2": _name("smtpUtf8Mailbox"), "-3": _name("macAddress") };
var ON_INT_BY_OID = {};
Object.keys(ON_NAME_BY_INT).forEach(function (k) { ON_INT_BY_OID[oid.byName(ON_NAME_BY_INT[k])] = Number(k); });
var IA_BY_INT = {
  1: _name("ocsp"), 2: _name("caIssuers"), 3: _name("id-ad-timeStamping"), 5: _name("id-ad-caRepository"),
  10: _name("id-ad-rpkiManifest"), 11: _name("id-ad-signedObject"), 13: _name("id-ad-rpkiNotify"),
};
var IA_TO_INT = {};
Object.keys(IA_BY_INT).forEach(function (k) { IA_TO_INT[oid.byName(IA_BY_INT[k])] = Number(k); });

var CP_BY_INT = {
  0: _name("anyPolicy"), 1: _name("domain-validated"), 2: _name("organization-validated"),
  3: _name("individual-validated"), 4: _name("ev-guidelines"),
  7: _name("id-cp-ipAddr-asNumber"), 8: _name("id-cp-ipAddr-asNumber-v2"),
  24: _name("id-rspRole-ci"), 25: _name("id-rspRole-euicc-v2"), 26: _name("id-rspRole-euicc"),
  27: _name("id-rspRole-eum-v2"), 28: _name("id-rspRole-eum"),
  29: _name("id-rspRole-dp-tls-v2"), 30: _name("id-rspRole-dp-tls"),
  31: _name("id-rspRole-dp-auth-v2"), 32: _name("id-rspRole-dp-auth"),
  33: _name("id-rspRole-dp-pb-v2"), 34: _name("id-rspRole-dp-pb"),
  35: _name("id-rspRole-ds-tls-v2"), 36: _name("id-rspRole-ds-tls"),
  37: _name("id-rspRole-ds-auth-v2"), 38: _name("id-rspRole-ds-auth"),
};
var CP_TO_INT = {};
Object.keys(CP_BY_INT).forEach(function (k) { CP_TO_INT[oid.byName(CP_BY_INT[k])] = Number(k); });
var PQ_BY_INT = { 1: _name("cps"), 2: _name("unotice") };
var PQ_TO_INT = {};
Object.keys(PQ_BY_INT).forEach(function (k) { PQ_TO_INT[oid.byName(PQ_BY_INT[k])] = Number(k); });


function _biguint(node, code, label) {
  if (!node || node.majorType !== 2) throw _err(code, label + " must be an unwrapped CBOR byte string (~biguint)");
  var b = node.content;
  if (b.length > C.LIMITS.CBOR_MAX_BIGUINT_BYTES) throw _err(code, label + " exceeds the ~biguint byte cap");
  if (b.length > 0 && b[0] === 0x00) throw _err("c509/non-minimal-serial", label + " has a redundant leading 0x00 (~biguint omits the sign octet)");
  return b.length ? BigInt("0x" + b.toString("hex")) : 0n;
}

function _hexBytes(s, code, label) {
  if (typeof s !== "string") throw _err(code, label + " must be a hexadecimal string");
  if ((s.length % 2) !== 0) throw _err(code, label + " must have an even number of hexadecimal digits");
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70))) {
      throw _err(code, label + " must be hexadecimal");
    }
  }
  return Buffer.from(s, "hex");
}

function _time(node, allowNull, label) {
  if (allowNull && node.majorType === 7 && node.ai === 22) return null;
  if (node.majorType !== 0) throw _err("c509/bad-validity", label + " must be an unwrapped CBOR epoch integer (~time)");
  var secs = node.argument;
  if (allowNull && secs === NO_EXPIRY_SECONDS) {
    throw _err("c509/bad-validity", label + " of 99991231235959Z is encoded as the CBOR simple value null (draft sec. 3.1.5), not as the epoch " + NO_EXPIRY_SECONDS);
  }
  if (secs > MAX_EPOCH_SECONDS) throw _err("c509/bad-validity", label + " is outside the representable Date range");
  return new Date(C.TIME.seconds(Number(secs)));
}

function _oidName(node, code, label) {
  if (!node || node.majorType !== 2) throw _err(code, label + " must be an unwrapped CBOR byte string (~oid)");
  var dotted;
  try { dotted = asn1.decodeOidContent(node.content); }
  catch (e) { throw _err(code, label + " is not a valid BER OID content encoding", e); }
  return { oid: dotted, name: oid.name(dotted) || dotted };
}

function _algorithm(node, byInt, code, label) {
  if (node.majorType === 0 || node.majorType === 1) {
    var i = Number(cbor.read.int(node));
    var mapped = byInt[i];
    if (mapped === undefined) throw _err("c509/unknown-algorithm", label + " integer " + i + " has no C509 registry row");
    if (typeof mapped === "string") return { name: mapped, oid: oid.byName(mapped) };
    return { name: mapped.alg, oid: oid.byName(mapped.alg), curve: mapped.curve || null };
  }
  if (node.majorType === 2) { var r = _oidName(node, code, label); return { name: r.name, oid: r.oid }; }
  if (node.majorType === 4 && node.children && node.children.length === 2) {
    var a = _oidName(node.children[0], code, label);
    if (node.children[1].majorType !== 2) throw _err(code, label + " algorithm parameters must be a CBOR byte string");
    if (node.children[1].content.length === 0) throw _err(code, label + " algorithm parameters must not be an empty byte string; omit them with the bare ~oid form (draft sec. 3.1.3)");
    return { name: a.name, oid: a.oid, parameters: node.children[1].content };
  }
  throw _err(code, label + " is not a C509 AlgorithmIdentifier (int / ~oid / [~oid, params])");
}

function _specialText(node) {
  if (node.majorType === 3) return { text: cbor.read.textString(node) };
  if (node.majorType === 2) return { hex: node.content.toString("hex") };
  if (node.majorType === 6 && Number(node.argument) === 48) {
    if (!node.children || !node.children[0] || node.children[0].majorType !== 2) {
      throw _err("c509/bad-name", "a tag-48 MAC-address value must wrap a CBOR byte string");
    }
    var euiBytes = node.children[0].content;
    if (euiBytes.length !== 6 && euiBytes.length !== 8) throw _err("c509/bad-name", "a tag-48 MAC address must be 6 (EUI-48) or 8 (EUI-64) bytes");
    return { eui64: euiBytes };
  }
  throw _err("c509/bad-name", "an attribute value is not a C509 SpecialText (text / bytes / tag-48)");
}

function _isEvenHexLower(s) {
  var n = s.length;
  if (n < 2 || (n & 1) !== 0) return false;
  for (var i = 0; i < n; i++) {
    var c = s.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102))) return false;
  }
  return true;
}
function _isEui64Text(s) {
  if (s.length !== 23) return false;
  for (var i = 0; i < 23; i++) {
    if ((i % 3) === 2) { if (s.charCodeAt(i) !== 45) return false; }
    else {
      var c = s.charCodeAt(i);
      if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 70))) return false;
    }
  }
  return true;
}
function _assertCanonicalSpecialText(node, isNative, E) {
  if (isNative) return;
  if (node.majorType === 3) {
    var t = cbor.read.textString(node);
    if (t.length >= 2 && _isEvenHexLower(t)) {
      throw _err(E, "a text attribute value of even-length hex characters must be encoded as a CBOR byte string (draft sec. 3.1.4)");
    }
    if (_isEui64Text(t)) {
      throw _err(E, "a text attribute value in EUI-64 form must be encoded as a CBOR tag-48 MAC address (draft sec. 3.1.4)");
    }
    return;
  }
  if (node.majorType === 2) {
    if (node.content.length === 0) throw _err(E, "an empty attribute value must be encoded as a CBOR text string (draft sec. 3.1.4)");
    return;
  }
  var eui = node.children[0].content;
  if (eui.length === 8 && eui[3] === 0xff && eui[4] === 0xfe) {
    throw _err(E, "an EUI-64 of the form HH-HH-HH-FF-FE-HH-HH-HH must be encoded as a 48-bit MAC address (draft sec. 3.1.4)");
  }
}

function _assertAttrValue(rdn) {
  try { _reconAttrValue(rdn); }
  catch (e) {
    if (e instanceof C509Error) throw e;
    throw _err("c509/bad-name", "the " + rdn.type + " value is not valid for the string type its attribute integer declares", e);
  }
}

function _name509(node, isSubject, isNative) {
  if (!isSubject && node.majorType === 7 && node.ai === 22) return null;
  if (node.majorType === 3 || node.majorType === 2 || node.majorType === 6) {
    var sv = _specialText(node);
    _assertCanonicalSpecialText(node, isNative, "c509/bad-name");
    if (sv.eui64) return { rdns: [{ type: "commonName", eui64: sv.eui64 }], eui64: sv.eui64, dn: "CN=" + _macToEui64String(sv.eui64) };
    var val = sv.text !== undefined ? sv.text : sv.hex;
    var bareRdn = { type: "commonName", value: val };
    _assertAttrValue(bareRdn);
    return { rdns: [bareRdn], dn: "CN=" + guard.name.escapeDnValue(val) };
  }
  if (node.majorType !== 4) throw _err("c509/bad-name", "a C509 Name must be null, a SpecialText, or an array of RDN attributes");
  var rdns = [];
  var parts = [];
  var kids = node.children || [];
  if (kids.length % 2 !== 0) throw _err("c509/bad-name", "a C509 Name array must be attribute-type/value pairs (dangling attribute type)");
  if (kids.length === 0 && !isSubject) throw _err("c509/bad-name", "the issuer Name must not be empty (RFC 5280 sec. 4.1.2.4)");
  for (var i = 0; i + 1 < kids.length; i += 2) {
    if (kids[i].majorType !== 0 && kids[i].majorType !== 1) throw _err("c509/bad-name", "a C509 Name attribute type must be a CBOR integer");
    var ti = Number(cbor.read.int(kids[i]));
    if (isNative && ti < 0) throw _err("c509/bad-name", "a natively signed C509 Name attribute type integer must be non-negative (draft sec. 3.1.4), got " + ti);
    var tname = ATTR_BY_INT[Math.abs(ti)];
    if (tname === undefined) throw _err("c509/bad-name", "attribute type integer " + ti + " has no C509 registry row");
    var v = _specialText(kids[i + 1]);
    _assertCanonicalSpecialText(kids[i + 1], isNative, "c509/bad-name");
    var vv = v.text !== undefined ? v.text : (v.hex !== undefined ? v.hex : _macToEui64String(v.eui64));
    var rdn = { type: tname, value: vv, printable: ti < 0 };
    _assertAttrValue(rdn);
    rdns.push(rdn);
    parts.push(_shortName(tname) + "=" + guard.name.escapeDnValue(vv));
  }
  if (!isNative && rdns.length === 1 && rdns[0].type === "commonName" && !rdns[0].printable) {
    throw _err("c509/bad-name", "a Name holding a single +1 commonName must be encoded as a bare SpecialText, not an array (draft sec. 3.1.4)");
  }
  return { rdns: rdns, dn: parts.join(", ") };
}
function _shortName(n) { return (n && constants.NAMES.DN_SHORT[n]) || n; }


function _cborUint(node, label) {
  if (node.majorType !== 0) throw _err("c509/bad-extensions", "a " + label + " value must be a CBOR unsigned integer");
  return cbor.read.int(node);
}
function _cborIntVal(node, label) {
  if (node.majorType !== 0 && node.majorType !== 1) throw _err("c509/bad-extensions", "a " + label + " value must be a CBOR integer");
  return cbor.read.int(node);
}
function _boundCount(value, label) {
  return guard.range.uint31(value, _err, "c509/bad-extensions", label + " (0..2^31-1)");
}
function _ekuPurposeOid(node) {
  if (node.majorType === 0 || node.majorType === 1) {
    var i = Number(cbor.read.int(node));
    var nm = EKU_BY_INT[i];
    if (nm === undefined) throw _err("c509/bad-extensions", "an extKeyUsage int " + i + " has no C509 registry row");
    return oid.byName(nm);
  }
  return _oidName(node, "c509/bad-extensions", "an extKeyUsage KeyPurposeId").oid;
}


function _oidCbor(dotted) { return cbor.build.byteString(asn1.encodeOidContent(dotted)); }
function _isCborNull(node) { return node.majorType === 7 && node.ai === 22; }

function _ia5Bytes(node, tag) {
  if (node.majorType !== 3) throw _err("c509/bad-extensions", "a GeneralName [" + tag + "] value must be a CBOR text string (IA5String)");
  var s = cbor.read.textString(node);
  if (s.length === 0) throw _err("c509/bad-extensions", "a GeneralName [" + tag + "] IA5String must be non-empty");
  for (var i = 0; i < s.length; i++) { if (s.charCodeAt(i) > 0x7f) throw _err("c509/bad-extensions", "a GeneralName [" + tag + "] IA5String has a non-ASCII code point"); }
  var buf = Buffer.from(s, "latin1");
  guard.name.assertPrintableIa5(buf, _err, "c509/bad-extensions", "GeneralName [" + tag + "]");
  return buf;
}

function _namedBitsToContent(value) {
  if (!Number.isInteger(value) || value <= 0 || value > 0x1ff) return null;
  var hi = 0; for (var t = value; t; t >>= 1) hi++; hi -= 1;
  var buf = Buffer.alloc((hi >> 3) + 1);
  for (var bit = 0; bit <= hi; bit++) { if (value & (1 << bit)) buf[bit >> 3] |= 0x80 >> (bit & 7); }
  return { unusedBits: 7 - (hi & 7), bytes: buf };
}
function _namedBitsFromContent(bytes, unusedBits) {
  var total = bytes.length * 8 - unusedBits, value = 0;
  for (var bit = 0; bit < total && bit < 31; bit++) { if (bytes[bit >> 3] & (0x80 >> (bit & 7))) value |= (1 << bit); }
  return value > 0 && value <= 0x1ff ? value : null;
}

function _generalNameToDer(intVal, valueNode, ipMode, isNative) {
  if (intVal === 1 || intVal === 2 || intVal === 6) return b.contextPrimitive(intVal, _ia5Bytes(valueNode, intVal));
  if (intVal === 4) return b.explicit(4, _reconName(_name509(valueNode, true, isNative)));
  if (intVal === 7) return b.contextPrimitive(7, ipMode ? _ncIpToDer(valueNode) : _sanIpBytes(valueNode));
  if (intVal === 8) return b.contextPrimitive(8, asn1.encodeOidContent(_oidName(valueNode, "c509/bad-extensions", "a registeredID [8]").oid));
  if (intVal === 0 || intVal === -1 || intVal === -2 || intVal === -3) return _otherNameToDer(valueNode, intVal);
  throw _err("c509/bad-extensions", "GeneralName int " + intVal + " has no C509 sec. 8.13 registry row");
}
function _generalNameFromDer(gn, ipMode) {
  var t = gn.tagNumber;
  if (t === 1 || t === 2 || t === 6) return [cbor.build.int(BigInt(t)), cbor.build.textString(gn.value)];
  if (t === 4) { var nm = _dirNameToCbor(gn.bytes); return nm == null ? null : [cbor.build.int(4n), nm]; }
  if (t === 7) {
    if (!ipMode) return [cbor.build.int(7n), cbor.build.byteString(gn.value)];
    var ip = _ncIpFromDer(gn.value); return ip == null ? null : [cbor.build.int(7n), cbor.build.byteString(ip)];
  }
  if (t === 8) return [cbor.build.int(8n), _oidCbor(gn.value)];
  if (t === 0) return _otherNameFromDer(gn.value);
  return null;
}

function _generalNamesToDer(node, isNative) {
  if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "a GeneralNames value must be a CBOR array");
  var kids = node.children;
  if (kids.length === 0 || kids.length % 2 !== 0) throw _err("c509/bad-extensions", "a GeneralNames array must be non-empty (int, value) pairs (sec. 3.3)");
  var out = [];
  for (var i = 0; i + 1 < kids.length; i += 2) out.push(_generalNameToDer(Number(_cborIntVal(kids[i], "a GeneralName type")), kids[i + 1], false, isNative));
  return out;
}
function _generalNamesFromDer(gnNodes) {
  var out = [];
  for (var i = 0; i < gnNodes.length; i++) {
    var pair = _generalNameFromDer(schema.walk(GN_LEAF, gnNodes[i], NS), false);
    if (pair == null) return null;
    out.push(pair[0]); out.push(pair[1]);
  }
  return out;
}

function _otherNameToDer(node, intVal) {
  var typeId, inner;
  if (intVal === 0) {
    if (node.majorType !== 4 || !node.children || node.children.length !== 2) throw _err("c509/bad-extensions", "a generic otherName value must be a CBOR [ ~oid, bytes ] pair");
    typeId = _oidName(node.children[0], "c509/bad-extensions", "an otherName type-id").oid;
    if (node.children[1].majorType !== 2) throw _err("c509/bad-extensions", "an otherName value must be a CBOR byte string (the [0] EXPLICIT inner TLV)");
    inner = _requireStrictDerTlv(node.children[1].content, "c509/bad-extensions", "an otherName value");
  } else if (intVal === -1) {
    if (node.majorType !== 4 || !node.children || node.children.length !== 2) throw _err("c509/bad-extensions", "an id-on-hardwareModuleName value must be a CBOR [ ~oid, bytes ] pair");
    if (node.children[1].majorType !== 2) throw _err("c509/bad-extensions", "a hardwareModuleName hwSerialNum must be a CBOR byte string");
    typeId = oid.byName("hardwareModuleName");
    inner = b.sequence([b.oid(_oidName(node.children[0], "c509/bad-extensions", "a hardwareModuleName hwType").oid), b.octetString(node.children[1].content)]);
  } else if (intVal === -2) {
    if (node.majorType !== 3) throw _err("c509/bad-extensions", "an id-on-SmtpUTF8Mailbox value must be a CBOR text string");
    var smtp = cbor.read.textString(node);
    if (smtp.length === 0) throw _err("c509/bad-extensions", "an id-on-SmtpUTF8Mailbox value must be non-empty (RFC 9598 SIZE (1..MAX))");
    typeId = oid.byName("smtpUtf8Mailbox");
    inner = b.utf8(smtp);
  } else {
    if (node.majorType !== 2) throw _err("c509/bad-extensions", "an id-on-MACAddress value must be a CBOR byte string");
    if (node.content.length !== 6 && node.content.length !== 8) throw _err("c509/bad-extensions", "an id-on-MACAddress value must be 6 (EUI-48) or 8 (EUI-64) octets");
    typeId = oid.byName("macAddress");
    inner = b.octetString(node.content);
  }
  return b.contextConstructed(0, Buffer.concat([b.oid(typeId), b.explicit(0, inner)]));
}
function _otherNameFromDer(v) {
  var onInt = ON_INT_BY_OID[v.typeId];
  if (onInt === undefined) return [cbor.build.int(0n), cbor.build.array([_oidCbor(v.typeId), cbor.build.byteString(v.valueBytes)])];
  var inner;
  try { inner = asn1.decode(v.valueBytes); } catch (_e) { return null; }   // allow:swallow-unverified -- a malformed otherName value yields null, so the extension does not compact and is carried in C509 general form (raw bytes)
  if (onInt === -1) {
    if (inner.tagClass !== "universal" || inner.tagNumber !== asn1.TAGS.SEQUENCE || !inner.children || inner.children.length !== 2) return null;
    var hwType, hwSerial;
    try { hwType = asn1.read.oid(inner.children[0]); hwSerial = asn1.read.octetString(inner.children[1]); } catch (_e2) { return null; }   // allow:swallow-unverified -- a malformed hardwareModuleName yields null, so the extension is carried in C509 general form instead
    return [cbor.build.int(-1n), cbor.build.array([_oidCbor(hwType), cbor.build.byteString(hwSerial)])];
  }
  if (onInt === -2) {
    if (inner.tagClass !== "universal" || inner.tagNumber !== asn1.TAGS.UTF8_STRING) return null;
    var txt; try { txt = asn1.read.string(inner); } catch (_e3) { return null; }   // allow:swallow-unverified -- a non-UTF8String otherName yields null, so the extension is carried in C509 general form instead
    return [cbor.build.int(-2n), cbor.build.textString(txt)];
  }
  if (inner.tagClass !== "universal" || inner.tagNumber !== asn1.TAGS.OCTET_STRING) return null;
  var mac; try { mac = asn1.read.octetString(inner); } catch (_e4) { return null; }   // allow:swallow-unverified -- a malformed octet-string otherName value yields null, so the extension is carried in C509 general form instead
  if (mac.length !== 6 && mac.length !== 8) return null;
  return [cbor.build.int(-3n), cbor.build.byteString(mac)];
}

function _dirNameToCbor(gnBytes) {
  var node = asn1.decode(gnBytes);
  if (!node.children || node.children.length !== 1) return null;
  var name;
  try { name = _c509NameFromDer(node.children[0].bytes); } catch (_e) { return null; }   // allow:swallow-unverified -- a malformed directoryName yields null, so the extension is carried in C509 general form instead
  try { return _encName(name, true); } catch (_e2) { return null; }   // allow:swallow-unverified -- a directoryName that does not re-encode yields null, so the extension is carried in C509 general form instead
}

function _sanIpBytes(node) {
  if (node.majorType !== 2) throw _err("c509/bad-extensions", "an iPAddress value must be a CBOR byte string");
  if (node.content.length !== 4 && node.content.length !== 16) throw _err("c509/bad-extensions", "an iPAddress must be 4 (IPv4) or 16 (IPv6) octets");
  return node.content;
}
function _ncIpToDer(node) {
  if (node.majorType !== 2) throw _err("c509/bad-extensions", "a name-constraints iPAddress value must be a CBOR byte string");
  var buf = node.content, addrLen;
  if (buf.length === 5) addrLen = 4; else if (buf.length === 17) addrLen = 16;
  else throw _err("c509/bad-extensions", "a name-constraints iPAddress must be 5 (IPv4) or 17 (IPv6) octets (address + prefix length; RFC 9549 sec. 2.2)");
  var prefixLen = buf[addrLen], maxBits = addrLen * 8;
  if (prefixLen > maxBits) throw _err("c509/bad-extensions", "a name-constraints iPAddress prefix length " + prefixLen + " exceeds " + maxBits);
  var mask = Buffer.alloc(addrLen);
  for (var bit = 0; bit < prefixLen; bit++) mask[bit >> 3] |= 0x80 >> (bit & 7);
  return Buffer.concat([buf.subarray(0, addrLen), mask]);
}
function _ncIpFromDer(buf) {
  var addrLen = buf.length >> 1, mask = buf.subarray(addrLen), prefixLen = 0, seenZero = false;
  for (var i = 0; i < mask.length; i++) {
    for (var bit = 0; bit < 8; bit++) {
      if (mask[i] & (0x80 >> bit)) { if (seenZero) return null; prefixLen++; }
      else seenZero = true;
    }
  }
  return Buffer.concat([buf.subarray(0, addrLen), Buffer.from([prefixLen])]);
}


function _isUniversal(n, tagNumber) { return !!n && n.tagClass === "universal" && n.tagNumber === tagNumber; }

function _ipSeqToInt(seq) {
  if (!seq.length || seq[0] > 7) return null;
  var head = Buffer.from([seq[0] + 1]);
  return BigInt("0x" + Buffer.concat([head, seq.subarray(1)]).toString("hex"));
}
function _ipIntToSeq(n) {
  if (n < 1n) return null;
  var out = [];
  for (var v = n; v > 0n; v >>= 8n) out.unshift(Number(v & 0xffn));
  if (out.length > 9 || out[0] < 1 || out[0] > 8) return null;
  out[0] -= 1;
  return Buffer.from(out);
}
var _IP_WIDTH = { 1: 4, 2: 16 };

function _ipLow(seq, width) {
  var v = Buffer.alloc(width);
  seq.subarray(1).copy(v);
  return v;
}
function _ipHigh(seq, width) {
  var v = _ipLow(seq, width);
  var bits = (seq.length - 1) * 8 - seq[0];
  for (var i = bits; i < width * 8; i++) v[i >> 3] |= 0x80 >> (i & 7);
  return v;
}
function _ipOctCmp(a, b) {
  for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return 0;
}
function _ipIsSuccessor(a, b) {
  var carry = 1, inc = Buffer.from(a);
  for (var i = inc.length - 1; i >= 0 && carry; i--) { var s = inc[i] + carry; inc[i] = s & 0xff; carry = s >> 8; }
  if (carry) return false;
  return _ipOctCmp(inc, b) === 0;
}

function _ipRangeIsPrefix(lo, hi) {
  var bits = lo.length * 8, n = 0;
  while (n < bits) {
    var byteAt = n >> 3, mask = 0x80 >> (n & 7);
    if ((lo[byteAt] & mask) !== (hi[byteAt] & mask)) break;
    n++;
  }
  for (var i = n; i < bits; i++) {
    var bt = i >> 3, mk = 0x80 >> (i & 7);
    if ((lo[bt] & mk) !== 0) return false;
    if ((hi[bt] & mk) === 0) return false;
  }
  return true;
}

function _famOctCmp(a, b) {
  var n = Math.min(a.length, b.length);
  for (var i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return a.length - b.length;
}

function _ipSeqBitsClear(seq) {
  var unused = seq[0], value = seq.subarray(1);
  if (!value.length) return unused === 0;
  if (unused === 0) return true;
  return (value[value.length - 1] & ((1 << unused) - 1)) === 0;
}

function _ipRangesCanonical(bounds) {
  for (var i = 1; i < bounds.length; i++) {
    var prev = bounds[i - 1], cur = bounds[i];
    if (_ipOctCmp(cur.lo, prev.hi) <= 0) return false;
    if (_ipIsSuccessor(prev.hi, cur.lo)) return false;
  }
  return true;
}

function _ipChoiceToDer(items, afi) {
  var out = [], prev = null, sawBytes = false, sawInt = false, seqs = [];
  var width = _IP_WIDTH[afi];
  if (!width) throw _err("c509/bad-extensions", "address family " + afi + " has no known address width, so its addresses cannot be checked (RFC 3779 sec. 2.2.3.3)");
  function widthOk(seq) { return seq.length - 1 <= width; }
  function absolute(node) {
    var seq;
    if (node.majorType === 2) {
      sawBytes = true;
      if (node.content.length === 0) throw _err("c509/bad-extensions", "an IPAddress byte sequence must be non-empty");
      if (node.content[0] > 7) throw _err("c509/bad-extensions", "an IPAddress unused-bit count must be 0..7 (DER)");
      seq = node.content;
    } else {
      sawInt = true;
      var d = _cborIntVal(node, "an IPAddress");
      var abs = prev === null ? d : prev + d;
      prev = abs;
      guard.range.uint64(abs, _err, "c509/bad-extensions", "an IPAddress");
      seq = _ipIntToSeq(abs);
      if (!seq) throw _err("c509/bad-extensions", "an IPAddress integer does not encode a DER BIT STRING (sec. 3.3)");
    }
    if (!widthOk(seq)) {
      throw _err("c509/bad-extensions", "an IPAddress is wider than address family " + afi + " permits (RFC 3779 sec. 2.2.3.8)");
    }
    if (!_ipSeqBitsClear(seq)) {
      throw _err("c509/bad-extensions", "an IPAddress must leave its declared unused bits zero (RFC 3779 sec. 2.2.3.8)");
    }
    return seq;
  }
  var bounds = [];
  for (var i = 0; i < items.length; i++) {
    var it = items[i];
    if (it.majorType === 4) {
      if (!it.children || it.children.length !== 2) throw _err("c509/bad-extensions", "an IPAddress range must be exactly [min, max]");
      var lo = absolute(it.children[0]), hi = absolute(it.children[1]);
      seqs.push(lo); seqs.push(hi);
      var rlo = _ipLow(lo, width), rhi = _ipHigh(hi, width);
      {
        if (_ipRangeIsPrefix(rlo, rhi)) throw _err("c509/bad-extensions", "an address range that is exactly a prefix must use the prefix form (RFC 3779 sec. 2.2.3.7)");
        bounds.push({ lo: rlo, hi: rhi });
      }
      out.push(b.sequence([b.bitString(lo.subarray(1), lo[0]), b.bitString(hi.subarray(1), hi[0])]));
    } else {
      var pfx = absolute(it);
      seqs.push(pfx);
      bounds.push({ lo: _ipLow(pfx, width), hi: _ipHigh(pfx, width) });
      out.push(b.bitString(pfx.subarray(1), pfx[0]));
    }
  }
  if (sawBytes && sawInt) throw _err("c509/bad-extensions", "an IPAddressFamily must use one address form throughout (sec. 3.3)");
  if (sawBytes && !seqs.some(function (s) { return s.length > 8; })) {
    throw _err("c509/bad-extensions", "an IPAddressFamily whose addresses all fit 8 octets must use the integer form (sec. 3.3)");
  }
  for (var r = 0; r < bounds.length; r++) {
    if (_ipOctCmp(bounds[r].lo, bounds[r].hi) > 0) throw _err("c509/bad-extensions", "an IPAddress range must not end below its start (RFC 3779 sec. 2.2.3.9)");
  }
  if (!_ipRangesCanonical(bounds)) {
    throw _err("c509/bad-extensions", "an IPAddressFamily must be sorted, non-overlapping and maximally merged (RFC 3779 sec. 2.2.3.6)");
  }
  return out;
}

function _ipChoiceFromDer(ch, afi) {
  if (!_isUniversal(ch, asn1.TAGS.SEQUENCE) || !ch.children || ch.children.length === 0) return null;
  var groups = [], flat = [];
  for (var i = 0; i < ch.children.length; i++) {
    var el = ch.children[i], pair;
    if (_isUniversal(el, asn1.TAGS.BIT_STRING)) {
      var bs = asn1.read.bitString(el);
      pair = [Buffer.concat([Buffer.from([bs.unusedBits]), bs.bytes])];
    } else if (_isUniversal(el, asn1.TAGS.SEQUENCE) && el.children && el.children.length === 2 &&
               _isUniversal(el.children[0], asn1.TAGS.BIT_STRING) && _isUniversal(el.children[1], asn1.TAGS.BIT_STRING)) {
      var lo = asn1.read.bitString(el.children[0]), hi = asn1.read.bitString(el.children[1]);
      pair = [Buffer.concat([Buffer.from([lo.unusedBits]), lo.bytes]),
              Buffer.concat([Buffer.from([hi.unusedBits]), hi.bytes])];
    } else return null;
    groups.push(pair);
    for (var k = 0; k < pair.length; k++) flat.push(pair[k]);
  }
  var width = _IP_WIDTH[afi];
  if (!width) return null;
  var bounds = [];
  for (var g = 0; g < groups.length; g++) {
    var bg = groups[g];
    if (bg[0].length - 1 > width || bg[bg.length - 1].length - 1 > width) return null;
    var blo = _ipLow(bg[0], width), bhi = _ipHigh(bg[bg.length - 1], width);
    if (bg.length === 2 && _ipRangeIsPrefix(blo, bhi)) return null;
    bounds.push({ lo: blo, hi: bhi });
  }
  for (var r = 0; r < bounds.length; r++) {
    if (_ipOctCmp(bounds[r].lo, bounds[r].hi) > 0) return null;
  }
  if (!_ipRangesCanonical(bounds)) return null;
  var useBytes = flat.some(function (s) { return s.length > 8; });
  var out = [];
  if (useBytes) {
    groups.forEach(function (p) {
      out.push(p.length === 1 ? cbor.build.byteString(p[0])
        : cbor.build.array([cbor.build.byteString(p[0]), cbor.build.byteString(p[1])]));
    });
    return cbor.build.array(out);
  }
  var prev = null;
  function delta(seq) {
    var n = _ipSeqToInt(seq);
    if (n === null) return null;
    var d = prev === null ? n : n - prev;
    prev = n;
    return cbor.build.int(d);
  }
  for (var gi = 0; gi < groups.length; gi++) {
    var grp = groups[gi];
    if (grp.length === 1) {
      var one = delta(grp[0]);
      if (!one) return null;
      out.push(one);
    } else {
      var dlo = delta(grp[0]);
      var dhi = dlo ? delta(grp[1]) : null;
      if (!dlo || !dhi) return null;
      out.push(cbor.build.array([dlo, dhi]));
    }
  }
  return cbor.build.array(out);
}

function _asDelta(node, prev) {
  var d = _cborIntVal(node, "an ASIdentifier");
  var abs = prev === null ? d : prev + d;
  guard.range.int(abs, 0n, 4294967295n, _err, "c509/bad-extensions", "an ASIdentifier");
  return abs;
}

function _subtreesToDer(node, isNative) {
  if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "a GeneralSubtrees value must be a CBOR array");
  var kids = node.children;
  if (kids.length === 0 || kids.length % 2 !== 0) throw _err("c509/bad-extensions", "a GeneralSubtrees array must be non-empty (int, value) pairs");
  var out = [];
  for (var i = 0; i + 1 < kids.length; i += 2) out.push(b.sequence([_generalNameToDer(Number(_cborIntVal(kids[i], "a GeneralSubtree base type")), kids[i + 1], true, isNative)]));
  return Buffer.concat(out);
}
function _subtreesFromDer(subtreeNodes) {
  if (!subtreeNodes.length) return null;
  var out = [];
  for (var i = 0; i < subtreeNodes.length; i++) {
    var st = subtreeNodes[i];
    if (st.tagClass !== "universal" || st.tagNumber !== asn1.TAGS.SEQUENCE || !st.children || st.children.length !== 1) return null;
    var pair = _generalNameFromDer(schema.walk(GN_LEAF_SUBTREE, st.children[0], NS), true);
    if (pair == null) return null;
    out.push(pair[0]); out.push(pair[1]);
  }
  return out;
}

function _accessMethodOid(node) {
  if (node.majorType === 0 || node.majorType === 1) {
    var i = Number(cbor.read.int(node)), nm = IA_BY_INT[i];
    if (nm === undefined) throw _err("c509/bad-extensions", "an accessMethod int " + i + " has no C509 sec. 8.11 registry row");
    return oid.byName(nm);
  }
  return _oidName(node, "c509/bad-extensions", "an accessMethod").oid;
}
function _reasonsBitsToDer(value) {
  if ((value & 1) !== 0) throw _err("c509/bad-extensions", "a cRLDistributionPoints reasons value must not set the reserved unused ReasonFlags bit 0 (RFC 5280 sec. 4.2.1.13)");
  var c = _namedBitsToContent(value);
  if (c == null) throw _err("c509/bad-extensions", "a cRLDistributionPoints reasons value must be within the 9 defined ReasonFlags bits");
  return b.contextPrimitive(1, Buffer.concat([Buffer.from([c.unusedBits]), c.bytes]));
}
function _serialIntContent(node) {
  var mag = _minBytes(_biguint(node, "c509/bad-extensions", "an authorityKeyIdentifier serial"));
  if (mag.length === 0) return Buffer.from([0x00]);
  return (mag[0] & 0x80) ? Buffer.concat([Buffer.from([0x00]), mag]) : mag;
}

function _ia5Universal(text, label) {
  if (text.length === 0) throw _err("c509/bad-extensions", label + " must be non-empty");
  for (var i = 0; i < text.length; i++) { if (text.charCodeAt(i) > 0x7f) throw _err("c509/bad-extensions", label + " must be a 7-bit IA5String"); }
  guard.name.assertPrintableIa5(Buffer.from(text, "latin1"), _err, "c509/bad-extensions", label);
  return b.ia5(text);
}
function _policyIdToDerOid(node) {
  if (node.majorType === 0 || node.majorType === 1) {
    var i = Number(cbor.read.int(node)), nm = CP_BY_INT[i];
    if (nm === undefined) throw _err("c509/bad-extensions", "a certificatePolicies policy int " + i + " has no C509 sec. 8.9 registry row");
    return oid.byName(nm);
  }
  return _oidName(node, "c509/bad-extensions", "a certificatePolicies policyIdentifier").oid;
}
function _policyIdFromDer(dotted) {
  var i = CP_TO_INT[dotted];
  return i !== undefined ? cbor.build.int(BigInt(i)) : _oidCbor(dotted);
}
function _qualifierToDer(qidNode, qtextNode) {
  if (qidNode.majorType !== 0 && qidNode.majorType !== 1) throw _err("c509/bad-extensions", "a policyQualifierId must be a C509 sec. 8.10 int (a ~oid qualifier is not compact-representable)");
  var qi = Number(cbor.read.int(qidNode)), nm = PQ_BY_INT[qi];
  if (nm === undefined) throw _err("c509/bad-extensions", "a policyQualifierId int " + qi + " has no C509 sec. 8.10 registry row");
  if (qtextNode.majorType !== 3) throw _err("c509/bad-extensions", "a policyQualifier value must be a CBOR text string");
  var text = cbor.read.textString(qtextNode);
  if (qi === 1) return b.sequence([b.oid(oid.byName("cps")), _ia5Universal(text, "a CPSuri")]);
  if (text.length === 0) throw _err("c509/bad-extensions", "a UserNotice explicitText must be non-empty (DisplayText SIZE 1..200)");
  return b.sequence([b.oid(oid.byName("unotice")), b.sequence([b.utf8(text)])]);
}
function _qualifierFromDer(pq) {
  var qid = asn1.read.oid(pq.children[0]), qi = PQ_TO_INT[qid];
  if (qi === undefined) return null;
  var q = pq.children[1];
  if (qi === 1) {
    if (q.tagClass !== "universal" || q.tagNumber !== asn1.TAGS.IA5_STRING) return null;
    var uri; try { uri = asn1.read.string(q); } catch (_e) { return null; }   // allow:swallow-unverified -- a malformed URI policy qualifier yields null, so the extension is carried in C509 general form instead
    return [cbor.build.int(1n), cbor.build.textString(uri)];
  }
  if (q.tagClass !== "universal" || q.tagNumber !== asn1.TAGS.SEQUENCE || !q.children || q.children.length !== 1) return null;
  var dt = q.children[0];
  if (dt.tagClass !== "universal" || dt.tagNumber !== asn1.TAGS.UTF8_STRING) return null;
  var txt; try { txt = asn1.read.string(dt); } catch (_e2) { return null; }   // allow:swallow-unverified -- a malformed displayText qualifier yields null, so the extension is carried in C509 general form instead
  return [cbor.build.int(2n), cbor.build.textString(txt)];
}

function _dpToDer(dpNode, isNative) {
  if (dpNode.majorType !== 4 || !dpNode.children || dpNode.children.length !== 3) throw _err("c509/bad-extensions", "a DistributionPoint must be a CBOR [ fullName, reasons, cRLIssuer ] array");
  var fullName = dpNode.children[0], reasons = dpNode.children[1], crlIssuer = dpNode.children[2];
  var uris;
  if (fullName.majorType === 3) uris = [b.contextPrimitive(6, _ia5Bytes(fullName, 6))];
  else if (fullName.majorType === 4 && fullName.children) {
    if (fullName.children.length < 2) throw _err("c509/bad-extensions", "a DistributionPoint fullName array must hold 2 or more URIs (a single URI is a bare text; sec. 3.3)");
    uris = fullName.children.map(function (u) { return b.contextPrimitive(6, _ia5Bytes(u, 6)); });
  } else throw _err("c509/bad-extensions", "a DistributionPoint fullName must be a URI text or an array of URIs");
  var fields = [b.explicit(0, b.contextConstructed(0, Buffer.concat(uris)))];
  if (!_isCborNull(reasons)) fields.push(_reasonsBitsToDer(Number(_cborUint(reasons, "cRLDistributionPoints reasons"))));
  if (!_isCborNull(crlIssuer)) fields.push(b.contextConstructed(2, b.explicit(4, _reconName(_name509(crlIssuer, true, isNative)))));
  return b.sequence(fields);
}
function _dpFromDer(dp) {
  if (dp.tagClass !== "universal" || dp.tagNumber !== asn1.TAGS.SEQUENCE || !dp.children) return null;
  var fullNameUris = null, reasonsVal = null, crlIssuerCbor = null, lastTag = -1;
  for (var i = 0; i < dp.children.length; i++) {
    var f = dp.children[i];
    if (f.tagClass !== "context" || f.tagNumber <= lastTag) return null;
    lastTag = f.tagNumber;
    if (f.tagNumber === 0) {
      if (!f.children || f.children.length !== 1) return null;
      var dpn = f.children[0];
      if (dpn.tagClass !== "context" || dpn.tagNumber !== 0 || !dpn.children || !dpn.children.length) return null;
      fullNameUris = [];
      for (var j = 0; j < dpn.children.length; j++) {
        var mm = dpn.children[j];
        if (mm.tagClass !== "context" || mm.tagNumber !== 6) return null;
        fullNameUris.push(schema.walk(GN_LEAF, mm, NS).value);
      }
    } else if (f.tagNumber === 1) {
      var bs;
      try { bs = asn1.read.bitStringImplicit(f, 1); } catch (_e) { return null; }   // allow:swallow-unverified -- a malformed reason-flags bit string yields null, so the distributionPoint does not compact and is carried in C509 general form
      reasonsVal = _namedBitsFromContent(bs.bytes, bs.unusedBits);
      if (reasonsVal == null) return null;
    } else if (f.tagNumber === 2) {
      if (!f.children || f.children.length !== 1) return null;
      var ci = f.children[0];
      if (ci.tagClass !== "context" || ci.tagNumber !== 4 || !ci.children || ci.children.length !== 1) return null;
      try { crlIssuerCbor = _encName(_c509NameFromDer(ci.children[0].bytes), true); } catch (_e2) { return null; }   // allow:swallow-unverified -- a malformed CRL-issuer name yields null, so the distributionPoint is carried in C509 general form instead
    } else return null;
  }
  if (fullNameUris == null) return null;
  var oneUri = fullNameUris.length === 1 ? fullNameUris[0] : null;
  var fnCbor = oneUri != null ? cbor.build.textString(oneUri) : cbor.build.array(fullNameUris.map(function (u) { return cbor.build.textString(u); }));
  return {
    triple: cbor.build.array([fnCbor, reasonsVal == null ? cbor.build.nullValue() : cbor.build.uint(BigInt(reasonsVal)), crlIssuerCbor == null ? cbor.build.nullValue() : crlIssuerCbor]),
    oneUri: oneUri, noReasons: reasonsVal == null, noIssuer: crlIssuerCbor == null,
  };
}

function _extValueToDer(name, node, isNative) {
  switch (name) {
    case "subjectKeyIdentifier":
      if (node.majorType !== 2) throw _err("c509/bad-extensions", "a subjectKeyIdentifier value must be a CBOR byte string");
      return b.octetString(node.content);
    case "keyUsage":
      return _reconKeyUsageBits(Number(_cborUint(node, "keyUsage")));
    case "basicConstraints": {
      var iv = _cborIntVal(node, "basicConstraints");
      if (iv === -2n) return b.sequence([]);
      if (iv === -1n) return b.sequence([b.boolean(true)]);
      if (iv >= 0n) return b.sequence([b.boolean(true), b.integer(_boundCount(iv, "a basicConstraints pathLenConstraint"))]);
      throw _err("c509/bad-extensions", "a basicConstraints int " + iv + " is outside the -2/-1/pathLen range");
    }
    case "authorityKeyIdentifier":
      if (node.majorType === 2) return b.sequence([b.contextPrimitive(0, node.content)]);
      if (node.majorType === 4 && node.children && node.children.length === 3) {
        if (node.children[0].majorType !== 2) throw _err("c509/bad-extensions", "an authorityKeyIdentifier keyIdentifier must be a CBOR byte string");
        return b.sequence([
          b.contextPrimitive(0, node.children[0].content),
          b.contextConstructed(1, Buffer.concat(_generalNamesToDer(node.children[1], isNative))),
          b.contextPrimitive(2, _serialIntContent(node.children[2])),
        ]);
      }
      throw _err("c509/bad-extensions", "an authorityKeyIdentifier value must be a keyId byte string or the [ keyId, authorityCertIssuer, serial ] array (sec. 3.3)");
    case "extKeyUsage": {
      var items;
      if (node.majorType === 4) {
        items = node.children || [];
        if (items.length < 2) throw _err("c509/bad-extensions", "an extKeyUsage array must hold 2 or more KeyPurposeIds; a single purpose omits the array (draft-20 sec. 3.3)");
      } else {
        items = [node];
      }
      return b.sequence(items.map(function (it) { return b.oid(_ekuPurposeOid(it)); }));
    }
    case "inhibitAnyPolicy":
      return b.integer(_boundCount(_cborUint(node, "inhibitAnyPolicy"), "an inhibitAnyPolicy SkipCerts"));
    case "ocspNoCheck":
      if (node.majorType !== 7 || !(Buffer.isBuffer(node.bytes) && node.bytes.length === 1 && node.bytes[0] === 0xf6)) throw _err("c509/bad-extensions", "an ocspNoCheck value must be the CBOR simple value null");
      return b.nullValue();
    case "tlsFeature": {
      if (node.majorType !== 4) throw _err("c509/bad-extensions", "a tlsFeature value must be a CBOR array");
      return b.sequence((node.children || []).map(function (f) { return b.integer(_cborUint(f, "tlsFeature feature")); }));
    }
    case "subjectAltName":
    case "issuerAltName":
      if (node.majorType === 3) return b.sequence([b.contextPrimitive(2, _ia5Bytes(node, 2))]);
      if (!isNative && node.majorType === 4 && node.children && node.children.length === 2 &&
          node.children[0].majorType === 0 && Number(cbor.read.int(node.children[0])) === 2 &&
          node.children[1].majorType === 3) {
        throw _err("c509/bad-extensions", "a " + name + " holding exactly one dNSName must be encoded as a bare CBOR text string, not an array (draft sec. 3.3)");
      }
      return b.sequence(_generalNamesToDer(node, isNative));
    case "nameConstraints": {
      if (node.majorType !== 4 || !node.children || node.children.length !== 2) throw _err("c509/bad-extensions", "a nameConstraints value must be a 2-element CBOR array [ permitted, excluded ] (sec. 3.3)");
      var ncFields = [];
      if (!_isCborNull(node.children[0])) ncFields.push(b.contextConstructed(0, _subtreesToDer(node.children[0], isNative)));
      if (!_isCborNull(node.children[1])) ncFields.push(b.contextConstructed(1, _subtreesToDer(node.children[1], isNative)));
      if (ncFields.length === 0) throw _err("c509/bad-extensions", "nameConstraints must contain permittedSubtrees or excludedSubtrees (RFC 5280 sec. 4.2.1.10)");
      return b.sequence(ncFields);
    }
    case "authorityInfoAccess":
    case "subjectInfoAccess": {
      if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "an " + name + " value must be a CBOR array");
      var aiaKids = node.children;
      if (aiaKids.length === 0 || aiaKids.length % 2 !== 0) throw _err("c509/bad-extensions", "an " + name + " array must be non-empty (accessMethod, uri) pairs (sec. 3.3)");
      var descs = [];
      for (var ai = 0; ai + 1 < aiaKids.length; ai += 2) descs.push(b.sequence([b.oid(_accessMethodOid(aiaKids[ai])), b.contextPrimitive(6, _ia5Bytes(aiaKids[ai + 1], 6))]));
      return b.sequence(descs);
    }
    case "cRLDistributionPoints":
    case "freshestCRL":
      if (node.majorType === 3) return b.sequence([b.sequence([b.explicit(0, b.contextConstructed(0, b.contextPrimitive(6, _ia5Bytes(node, 6))))])]);
      if (node.majorType !== 4 || !node.children || node.children.length < 1) throw _err("c509/bad-extensions", "a " + name + " value must be a CBOR array of DistributionPoints or a bare URI text (sec. 3.3)");
      return b.sequence(node.children.map(function (dp) { return _dpToDer(dp, isNative); }));
    case "ipAddrBlocks":
    case "ipAddrBlocksV2": {
      if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "an IPAddrBlocks value must be a CBOR array");
      var ipKids = node.children;
      if (ipKids.length === 0 || ipKids.length % 3 !== 0) throw _err("c509/bad-extensions", "an IPAddrBlocks array must be non-empty (AFI, SAFI, addresses) triples (sec. 3.3)");
      var families = [], prevFam = null;
      for (var fi = 0; fi + 2 < ipKids.length; fi += 3) {
        var afi = _cborUint(ipKids[fi], "an IPAddrBlocks AFI");
        if (afi > 0xffffn) throw _err("c509/bad-extensions", "an IPAddrBlocks AFI must fit two octets (RFC 3779 sec. 2.2.3.3)");
        var safiNode = ipKids[fi + 1], famBytes = [Number(afi >> 8n) & 0xff, Number(afi & 0xffn)];
        if (!_isCborNull(safiNode)) {
          var safi = _cborUint(safiNode, "an IPAddrBlocks SAFI");
          if (safi > 0xffn) throw _err("c509/bad-extensions", "an IPAddrBlocks SAFI must fit one octet (RFC 3779 sec. 2.2.3.3)");
          famBytes.push(Number(safi));
        }
        var famOct = Buffer.from(famBytes);
        if (prevFam !== null && _famOctCmp(prevFam, famOct) >= 0) {
          throw _err("c509/bad-extensions", "IPAddrBlocks address families must be unique and in ascending addressFamily order (RFC 3779 sec. 2.2.3.3)");
        }
        prevFam = famOct;
        var choice = ipKids[fi + 2], famFields = [b.octetString(famOct)];
        if (_isCborNull(choice)) {
          famFields.push(b.nullValue());
        } else {
          if (choice.majorType !== 4 || !choice.children || choice.children.length === 0) {
            throw _err("c509/bad-extensions", "an IPAddrBlocks address choice must be null (inherit) or a non-empty CBOR array");
          }
          famFields.push(b.sequence(_ipChoiceToDer(choice.children, Number(afi))));
        }
        families.push(b.sequence(famFields));
      }
      return b.sequence(families);
    }
    case "autonomousSysIds":
    case "autonomousSysIdsV2": {
      if (_isCborNull(node)) return b.sequence([b.explicit(0, b.nullValue())]);
      if (node.majorType !== 4 || !node.children || node.children.length === 0) {
        throw _err("c509/bad-extensions", "an ASIdentifiers value must be null (inherit) or a non-empty CBOR array");
      }
      var asKids = node.children, asDers = [], asPrev = null, asPrevHigh = null;
      for (var asi2 = 0; asi2 < asKids.length; asi2++) {
        var it = asKids[asi2];
        if (it.majorType === 4) {
          if (!it.children || it.children.length !== 2) throw _err("c509/bad-extensions", "an ASIdentifiers range must be exactly [min, max]");
          var amin = _asDelta(it.children[0], asPrev), amax = _asDelta(it.children[1], amin);
          if (amax <= amin) throw _err("c509/bad-extensions", "an ASIdentifiers range must be ascending (RFC 3779 sec. 3.2.3.6)");
          if (asPrevHigh !== null && amin <= asPrevHigh + 1n) throw _err("c509/bad-extensions", "ASIdentifiers must be sorted, non-overlapping and maximally merged (RFC 3779 sec. 3.2.3.4)");
          asDers.push(b.sequence([b.integer(amin), b.integer(amax)]));
          asPrev = amax;
          asPrevHigh = amax;
        } else {
          var aid = _asDelta(it, asPrev);
          if (asPrevHigh !== null && aid <= asPrevHigh + 1n) throw _err("c509/bad-extensions", "ASIdentifiers must be sorted, non-overlapping and maximally merged (RFC 3779 sec. 3.2.3.4)");
          asDers.push(b.integer(aid));
          asPrev = aid;
          asPrevHigh = aid;
        }
      }
      return b.sequence([b.explicit(0, b.sequence(asDers))]);
    }
    case "certificatePolicies": {
      if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "a certificatePolicies value must be a CBOR array");
      var cpKids = node.children;
      if (cpKids.length === 0 || cpKids.length % 2 !== 0) throw _err("c509/bad-extensions", "a certificatePolicies array must be non-empty (policyIdentifier, qualifiers) pairs (sec. 3.3)");
      var polInfos = [], seenPolicy = {};
      for (var cpi = 0; cpi + 1 < cpKids.length; cpi += 2) {
        var quals = cpKids[cpi + 1];
        if (quals.majorType !== 4 || !quals.children) throw _err("c509/bad-extensions", "a certificatePolicies qualifiers slot must be a CBOR array");
        var policyOid = _policyIdToDerOid(cpKids[cpi]);
        if (seenPolicy[policyOid]) throw _err("c509/bad-extensions", "a certificatePolicies policy OID must not appear more than once (RFC 5280 sec. 4.2.1.4)");
        seenPolicy[policyOid] = true;
        var polFields = [b.oid(policyOid)];
        if (quals.children.length) {
          if (quals.children.length % 2 !== 0) throw _err("c509/bad-extensions", "a policyQualifiers array must be (policyQualifierId, qualifier) pairs");
          var pqDers = [];
          for (var qk = 0; qk + 1 < quals.children.length; qk += 2) pqDers.push(_qualifierToDer(quals.children[qk], quals.children[qk + 1]));
          polFields.push(b.sequence(pqDers));
        }
        polInfos.push(b.sequence(polFields));
      }
      return b.sequence(polInfos);
    }
    case "policyMappings": {
      if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "a policyMappings value must be a CBOR array");
      var pmKids = node.children;
      if (pmKids.length === 0 || pmKids.length % 2 !== 0) throw _err("c509/bad-extensions", "a policyMappings array must be non-empty (issuerDomainPolicy, subjectDomainPolicy) pairs (sec. 3.3)");
      var maps = [];
      for (var mi = 0; mi + 1 < pmKids.length; mi += 2) maps.push(b.sequence([b.oid(_policyIdToDerOid(pmKids[mi])), b.oid(_policyIdToDerOid(pmKids[mi + 1]))]));
      return b.sequence(maps);
    }
    case "policyConstraints": {
      if (node.majorType !== 4 || !node.children || node.children.length !== 2) throw _err("c509/bad-extensions", "a policyConstraints value must be a 2-element CBOR array [ requireExplicitPolicy, inhibitPolicyMapping ] (sec. 3.3)");
      var pcFields = [], repN = node.children[0], ipmN = node.children[1];
      if (!_isCborNull(repN)) pcFields.push(b.implicit(0, b.integer(_boundCount(_cborUint(repN, "a policyConstraints requireExplicitPolicy"), "a policyConstraints requireExplicitPolicy"))));
      if (!_isCborNull(ipmN)) pcFields.push(b.implicit(1, b.integer(_boundCount(_cborUint(ipmN, "a policyConstraints inhibitPolicyMapping"), "a policyConstraints inhibitPolicyMapping"))));
      if (pcFields.length === 0) throw _err("c509/bad-extensions", "policyConstraints must contain requireExplicitPolicy or inhibitPolicyMapping (RFC 5280 sec. 4.2.1.11)");
      return b.sequence(pcFields);
    }
    case "subjectDirectoryAttributes":
      return _sdaToDer(node, isNative);
    default:
      throw _err("c509/bad-extensions", "extension " + name + " has no compact value decoder");
  }
}

function _extValueFromDer(name, der) {
  var node;
  try {
  node = asn1.decode(der);
  switch (name) {
    case "subjectKeyIdentifier":
      return cbor.build.byteString(asn1.read.octetString(node));
    case "keyUsage": {
      var bits = _keyUsageBitsFromDer(der);
      return bits == null ? null : cbor.build.uint(BigInt(bits));
    }
    case "basicConstraints": {
      var kids = node.children || [];
      if (kids.length === 0) return cbor.build.int(-2n);
      if (asn1.read.boolean(kids[0]) !== true) return null;
      if (kids.length === 1) return cbor.build.int(-1n);
      if (kids.length !== 2) return null;
      return cbor.build.uint(asn1.read.integer(kids[1]));
    }
    case "authorityKeyIdentifier": {
      var akids = node.children || [];
      if (akids.length === 1 && akids[0].tagClass === "context" && akids[0].tagNumber === 0) {
        return cbor.build.byteString(asn1.read.octetStringImplicit(akids[0], 0));
      }
      if (akids.length === 3 && akids[0].tagClass === "context" && akids[0].tagNumber === 0 &&
          akids[1].tagClass === "context" && akids[1].tagNumber === 1 && akids[1].children &&
          akids[2].tagClass === "context" && akids[2].tagNumber === 2) {
        var akiIssuer = _generalNamesFromDer(akids[1].children);
        if (akiIssuer == null) return null;
        var akiSerial = asn1.read.integerImplicit(akids[2], 2);
        if (akiSerial < 0n) return null;
        return cbor.build.array([cbor.build.byteString(asn1.read.octetStringImplicit(akids[0], 0)), cbor.build.array(akiIssuer), cbor.build.byteString(_minBytes(akiSerial))]);
      }
      return null;
    }
    case "extKeyUsage": {
      var purposes = node.children || [];
      if (!purposes.length) return null;
      var out = purposes.map(function (p) {
        var dotted = asn1.read.oid(p), pint = EKU_TO_INT[dotted];
        return pint !== undefined ? cbor.build.int(BigInt(pint)) : cbor.build.byteString(asn1.encodeOidContent(dotted));
      });
      return out.length === 1 ? out[0] : cbor.build.array(out);
    }
    case "inhibitAnyPolicy":
      return cbor.build.uint(asn1.read.integer(node));
    case "ocspNoCheck":
      asn1.read.nullValue(node);
      return cbor.build.nullValue();
    case "tlsFeature":
      return cbor.build.array((node.children || []).map(function (f) { return cbor.build.uint(asn1.read.integer(f)); }));
    case "subjectAltName":
    case "issuerAltName": {
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1) return null;
      var sanMembers = node.children;
      if (sanMembers.length === 1 && sanMembers[0].tagClass === "context" && sanMembers[0].tagNumber === 2) {
        return cbor.build.textString(schema.walk(GN_LEAF, sanMembers[0], NS).value);
      }
      var sanItems = _generalNamesFromDer(sanMembers);
      return sanItems == null ? null : cbor.build.array(sanItems);
    }
    case "nameConstraints": {
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1) return null;
      var permCbor = cbor.build.nullValue(), exclCbor = cbor.build.nullValue(), sawNc = false, ncLast = -1;
      for (var nci = 0; nci < node.children.length; nci++) {
        var ncf = node.children[nci];
        if (ncf.tagClass !== "context" || ncf.tagNumber <= ncLast) return null;
        ncLast = ncf.tagNumber;
        var subItems = _subtreesFromDer(ncf.children || []);
        if (subItems == null) return null;
        if (ncf.tagNumber === 0) { permCbor = cbor.build.array(subItems); sawNc = true; }
        else if (ncf.tagNumber === 1) { exclCbor = cbor.build.array(subItems); sawNc = true; }
        else return null;
      }
      return sawNc ? cbor.build.array([permCbor, exclCbor]) : null;
    }
    case "authorityInfoAccess":
    case "subjectInfoAccess": {
      var aiaDescs = node.children || [];
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || aiaDescs.length < 1) return null;
      var aiaOut = [];
      for (var adi = 0; adi < aiaDescs.length; adi++) {
        var d = aiaDescs[adi];
        if (d.tagClass !== "universal" || d.tagNumber !== asn1.TAGS.SEQUENCE || !d.children || d.children.length !== 2) return null;
        var aiaLoc = d.children[1];
        if (aiaLoc.tagClass !== "context" || aiaLoc.tagNumber !== 6) return null;
        var methodDotted = asn1.read.oid(d.children[0]), mint = IA_TO_INT[methodDotted];
        aiaOut.push(mint !== undefined ? cbor.build.int(BigInt(mint)) : _oidCbor(methodDotted));
        aiaOut.push(cbor.build.textString(schema.walk(GN_LEAF, aiaLoc, NS).value));
      }
      return cbor.build.array(aiaOut);
    }
    case "cRLDistributionPoints":
    case "freshestCRL": {
      var dps = node.children || [];
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || dps.length < 1) return null;
      var dpResults = [];
      for (var dpi = 0; dpi < dps.length; dpi++) { var dpr = _dpFromDer(dps[dpi]); if (dpr == null) return null; dpResults.push(dpr); }
      if (dpResults.length === 1 && dpResults[0].oneUri != null && dpResults[0].noReasons && dpResults[0].noIssuer) return cbor.build.textString(dpResults[0].oneUri);
      return cbor.build.array(dpResults.map(function (r) { return r.triple; }));
    }
    case "ipAddrBlocks":
    case "ipAddrBlocksV2": {
      if (!_isUniversal(node, asn1.TAGS.SEQUENCE) || !node.children || node.children.length === 0) return null;
      var ipOut = [], prevFamOct = null;
      for (var ifi = 0; ifi < node.children.length; ifi++) {
        var fam = node.children[ifi];
        if (!_isUniversal(fam, asn1.TAGS.SEQUENCE) || !fam.children || fam.children.length !== 2) return null;
        var famOct = asn1.read.octetString(fam.children[0]);
        if (famOct.length !== 2 && famOct.length !== 3) return null;
        if (prevFamOct !== null && _famOctCmp(prevFamOct, famOct) >= 0) return null;
        prevFamOct = famOct;
        var afiVal = (famOct[0] << 8) | famOct[1];
        ipOut.push(cbor.build.uint(BigInt(afiVal)));
        ipOut.push(famOct.length === 3 ? cbor.build.uint(BigInt(famOct[2])) : cbor.build.nullValue());
        var ch = fam.children[1];
        if (_isUniversal(ch, asn1.TAGS.NULL)) { ipOut.push(cbor.build.nullValue()); continue; }
        var chOut = _ipChoiceFromDer(ch, afiVal);
        if (!chOut) return null;
        ipOut.push(chOut);
      }
      return cbor.build.array(ipOut);
    }
    case "autonomousSysIds":
    case "autonomousSysIdsV2": {
      if (!_isUniversal(node, asn1.TAGS.SEQUENCE) || !node.children || node.children.length !== 1) return null;
      var asnum = node.children[0];
      if (asnum.tagClass !== "context" || asnum.tagNumber !== 0 || !asnum.children || asnum.children.length !== 1) return null;
      var inner = asnum.children[0];
      if (_isUniversal(inner, asn1.TAGS.NULL)) return cbor.build.nullValue();
      if (!_isUniversal(inner, asn1.TAGS.SEQUENCE) || !inner.children || inner.children.length === 0) return null;
      var asOut = [], asPrevOut = null, asPrevHigh = null;
      for (var aoi = 0; aoi < inner.children.length; aoi++) {
        var el = inner.children[aoi], elLo, elHi;
        if (_isUniversal(el, asn1.TAGS.INTEGER)) {
          elLo = asn1.read.integer(el);
          elHi = elLo;
          if (elLo < 0n || elLo > 4294967295n) return null;
        } else if (_isUniversal(el, asn1.TAGS.SEQUENCE) && el.children && el.children.length === 2) {
          elLo = asn1.read.integer(el.children[0]);
          elHi = asn1.read.integer(el.children[1]);
          if (elLo < 0n || elHi > 4294967295n || elHi <= elLo) return null;
        } else return null;
        if (asPrevHigh !== null && elLo <= asPrevHigh + 1n) return null;
        if (el.tagNumber === asn1.TAGS.INTEGER) {
          asOut.push(cbor.build.int(asPrevOut === null ? elLo : elLo - asPrevOut));
          asPrevOut = elLo;
        } else {
          asOut.push(cbor.build.array([
            cbor.build.int(asPrevOut === null ? elLo : elLo - asPrevOut),
            cbor.build.int(elHi - elLo),
          ]));
          asPrevOut = elHi;
        }
        asPrevHigh = elHi;
      }
      return cbor.build.array(asOut);
    }
    case "certificatePolicies": {
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1) return null;
      var cpOut = [];
      for (var pli = 0; pli < node.children.length; pli++) {
        var pol = node.children[pli];
        if (pol.tagClass !== "universal" || pol.tagNumber !== asn1.TAGS.SEQUENCE || !pol.children || pol.children.length < 1 || pol.children.length > 2) return null;
        cpOut.push(_policyIdFromDer(asn1.read.oid(pol.children[0])));
        var qArr = [];
        if (pol.children.length === 2) {
          var qseq = pol.children[1];
          if (qseq.tagClass !== "universal" || qseq.tagNumber !== asn1.TAGS.SEQUENCE || !qseq.children || !qseq.children.length) return null;
          for (var qj = 0; qj < qseq.children.length; qj++) {
            var pq = qseq.children[qj];
            if (pq.tagClass !== "universal" || pq.tagNumber !== asn1.TAGS.SEQUENCE || !pq.children || pq.children.length !== 2) return null;
            var qpair = _qualifierFromDer(pq);
            if (qpair == null) return null;
            qArr.push(qpair[0]); qArr.push(qpair[1]);
          }
        }
        cpOut.push(cbor.build.array(qArr));
      }
      return cbor.build.array(cpOut);
    }
    case "policyMappings": {
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1) return null;
      var pmOut = [];
      for (var pm = 0; pm < node.children.length; pm++) {
        var mp = node.children[pm];
        if (mp.tagClass !== "universal" || mp.tagNumber !== asn1.TAGS.SEQUENCE || !mp.children || mp.children.length !== 2) return null;
        pmOut.push(_policyIdFromDer(asn1.read.oid(mp.children[0])));
        pmOut.push(_policyIdFromDer(asn1.read.oid(mp.children[1])));
      }
      return cbor.build.array(pmOut);
    }
    case "policyConstraints": {
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1 || node.children.length > 2) return null;
      var repC = cbor.build.nullValue(), ipmC = cbor.build.nullValue(), pcLast = -1;
      for (var pci = 0; pci < node.children.length; pci++) {
        var f = node.children[pci];
        if (f.tagClass !== "context" || f.tagNumber <= pcLast) return null;
        pcLast = f.tagNumber;
        var sv = asn1.read.integerImplicit(f, f.tagNumber);
        if (sv < 0n) return null;
        if (f.tagNumber === 0) repC = cbor.build.uint(sv);
        else if (f.tagNumber === 1) ipmC = cbor.build.uint(sv);
        else return null;
      }
      return cbor.build.array([repC, ipmC]);
    }
    case "subjectDirectoryAttributes":
      return _sdaFromDer(node);
    default:
      return null;
  }
  } catch (_e) {
    return null;
  }
}






function _requireStrictDerTlv(content, code, label) {
  return guard.der.tlv(content, _err, code, label);
}

function _derSetInDeclaredOrder(vals) {
  for (var i = 1; i < vals.length; i++) {
    if (Buffer.compare(vals[i - 1], vals[i]) > 0) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes attributeValue list must be in DER ascending order (X.690 sec. 11.6)");
  }
  return b.set(vals);
}

function _sdaToDer(node, isNative) {
  if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes value must be a CBOR array");
  var kids = node.children;
  if (kids.length === 0 || kids.length % 2 !== 0) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes array must be non-empty (attributeType, attributeValue) pairs (sec. 3.3)");
  var attrs = [];
  for (var i = 0; i + 1 < kids.length; i += 2) {
    var typeNode = kids[i], valuesNode = kids[i + 1];
    if (valuesNode.majorType !== 4 || !valuesNode.children || valuesNode.children.length < 1) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes attributeValue must be a non-empty CBOR array (SET OF, SIZE 1..MAX, RFC 5280 sec. 4.2.1.8)");
    var vals = [];
    if (typeNode.majorType === 0 || typeNode.majorType === 1) {
      var ti = Number(cbor.read.int(typeNode));
      if (isNative && ti < 0) throw _err("c509/bad-extensions", "a natively signed C509 subjectDirectoryAttributes attribute type integer must be non-negative (draft sec. 3.1.4), got " + ti);
      var tname = ATTR_BY_INT[Math.abs(ti)];
      if (tname === undefined) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes attribute type int " + ti + " has no C509 sec. 8.6 registry row");
      for (var vi = 0; vi < valuesNode.children.length; vi++) {
        var vn = valuesNode.children[vi];
        if (vn.majorType !== 3) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes int-form attribute value must be a CBOR text string (a non-string value requires the ~oid form)");
        try { vals.push(_reconAttrValue({ type: tname, value: cbor.read.textString(vn), printable: ti < 0 })); }
        catch (e) { throw _err("c509/bad-extensions", "a subjectDirectoryAttributes " + tname + " value is not valid for its string type", e); }
      }
      attrs.push(b.sequence([b.oid(oid.byName(tname)), _derSetInDeclaredOrder(vals)]));
    } else if (typeNode.majorType === 2) {
      var dotted = _oidName(typeNode, "c509/bad-extensions", "a subjectDirectoryAttributes attribute type").oid;
      for (var vj = 0; vj < valuesNode.children.length; vj++) {
        var vb = valuesNode.children[vj];
        if (vb.majorType !== 2) throw _err("c509/bad-extensions", "a ~oid-form subjectDirectoryAttributes value must be a CBOR byte string (a raw DER AttributeValue)");
        vals.push(b.raw(_requireStrictDerTlv(vb.content, "c509/bad-extensions", "a ~oid-form subjectDirectoryAttributes AttributeValue")));
      }
      attrs.push(b.sequence([b.oid(dotted), _derSetInDeclaredOrder(vals)]));
    } else {
      throw _err("c509/bad-extensions", "a subjectDirectoryAttributes attribute type must be a CBOR integer (sec. 8.6) or a ~oid");
    }
  }
  return b.sequence(attrs);
}

function _sdaTryIntForm(tint, name, valueNodes) {
  if (tint === undefined) return null;
  var i;
  if (name === "emailAddress") {
    var mails = [];
    for (i = 0; i < valueNodes.length; i++) {
      if (valueNodes[i].tagClass !== "universal" || valueNodes[i].tagNumber !== asn1.TAGS.IA5_STRING) return null;
      mails.push(cbor.build.textString(asn1.read.string(valueNodes[i])));
    }
    return { sign: 1, values: mails };
  }
  var sign = 0, out = [];
  for (i = 0; i < valueNodes.length; i++) {
    var vn = valueNodes[i], s;
    if (vn.tagClass === "universal" && vn.tagNumber === asn1.TAGS.UTF8_STRING) s = 1;
    else if (vn.tagClass === "universal" && vn.tagNumber === asn1.TAGS.PRINTABLE_STRING) s = -1;
    else return null;
    if (sign === 0) sign = s;
    else if (sign !== s) return null;
    out.push(cbor.build.textString(asn1.read.string(vn)));
  }
  return { sign: sign, values: out };
}

function _sdaFromDer(node) {
  if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1) return null;
  var out = [];
  for (var ai = 0; ai < node.children.length; ai++) {
    var attr = node.children[ai];
    if (attr.tagClass !== "universal" || attr.tagNumber !== asn1.TAGS.SEQUENCE || !attr.children || attr.children.length !== 2) return null;
    var setNode = attr.children[1];
    if (setNode.tagClass !== "universal" || setNode.tagNumber !== asn1.TAGS.SET || !setNode.children || setNode.children.length < 1) return null;
    var dotted = asn1.read.oid(attr.children[0]);
    var nm = oid.name(dotted), tint = nm != null ? ATTR_TO_INT[nm] : undefined;
    var intForm = _sdaTryIntForm(tint, nm, setNode.children);
    if (intForm != null) {
      out.push(cbor.build.int(BigInt(intForm.sign < 0 ? -tint : tint)));
      out.push(cbor.build.array(intForm.values));
    } else {
      out.push(_oidCbor(dotted));
      out.push(cbor.build.array(setNode.children.map(function (v) { return cbor.build.byteString(v.bytes); })));
    }
  }
  return cbor.build.array(out);
}

function _tryCompactExtValue(name, der) {
  var compact = _extValueFromDer(name, der);
  if (compact == null) return null;
  var recon;
  try {
    recon = _extValueToDer(name, cbor.decode(compact));
  } catch (_e) {
    return null;
  }
  return recon.equals(der) ? compact : null;
}

function _extensions(node, isNative) {
  if (node.majorType === 0 || node.majorType === 1) {
    var iv = Number(cbor.read.int(node));
    return [{ name: "keyUsage", oid: oid.byName("keyUsage"), critical: iv < 0, keyUsageBits: Math.abs(iv) }];
  }
  if (node.majorType !== 4) throw _err("c509/bad-extensions", "C509 extensions must be an array or a keyUsage int shortcut");
  var out = [];
  var kids = node.children || [];
  if (kids.length % 2 !== 0) throw _err("c509/bad-extensions", "a C509 extensions array must be id/value pairs (dangling extension identifier)");
  if (!isNative && kids.length === 2 &&
      (kids[0].majorType === 0 || kids[0].majorType === 1) && (kids[1].majorType === 0 || kids[1].majorType === 1) &&
      Math.abs(Number(cbor.read.int(kids[0]))) === 2) {
    throw _err("c509/bad-extensions", "an extensions field holding only keyUsage must be encoded as a single CBOR int, not an array (draft sec. 3.1.10)");
  }
  for (var i = 0; i + 1 < kids.length; i += 2) {
    var idNode = kids[i], valNode = kids[i + 1];
    var name, extOid, critical, valContent;
    if (idNode.majorType === 0 || idNode.majorType === 1) {
      var ei = Number(cbor.read.int(idNode));
      name = EXT_BY_INT[Math.abs(ei)];
      if (name === undefined) throw _err("c509/bad-extensions", "extension type integer " + ei + " has no C509 registry row");
      extOid = oid.byName(name); critical = ei < 0;
      if (EXT_COMPACT[name]) {
        valContent = _extValueToDer(name, valNode, isNative);
      } else if (valNode.majorType === 2) {
        valContent = valNode.content;
      } else {
        throw _err("c509/bad-extensions", "extension " + name + " has no compact value codec; its int-form value must be a byte string (draft-20 sec. 3.3)");
      }
    } else {
      var r = _oidName(idNode, "c509/bad-extensions", "an extension id");
      name = r.name; extOid = r.oid;
      critical = valNode.majorType === 4;
      if (critical) {
        if (!valNode.children || valNode.children.length !== 1 || valNode.children[0].majorType !== 2) {
          throw _err("c509/bad-extensions", "a critical ~oid extension value must wrap a single byte string");
        }
        valContent = valNode.children[0].content;
      } else {
        if (valNode.majorType !== 2) throw _err("c509/bad-extensions", "a non-critical ~oid extension value must be a byte string");
        valContent = valNode.content;
      }
    }
    out.push({ name: name, oid: extOid, critical: critical, value: valContent || null });
  }
  return out;
}


function _macToEui64String(buf) {
  var bytes = buf.length === 6 ? Buffer.concat([buf.subarray(0, 3), Buffer.from([0xff, 0xfe]), buf.subarray(3)]) : buf;
  var s = [];
  for (var i = 0; i < bytes.length; i++) { var h = bytes[i].toString(16).toUpperCase(); if (h.length < 2) h = "0" + h; s.push(h); }
  return s.join("-");
}

function _reconAttrValue(rdn) {
  if (rdn.eui64) return b.utf8(_macToEui64String(rdn.eui64));
  var s = String(rdn.value);
  if (s.length === 0) throw _err("c509/bad-name", "a " + rdn.type + " value must be non-empty (SIZE (1..MAX))");
  if (rdn.type === "countryName" && s.length !== 2) throw _err("c509/bad-name", "a countryName value must have length 2 (draft sec. 3.1.4)");
  if (rdn.type === "emailAddress") return b.ia5(s);
  if (!rdn.printable && (rdn.type === "countryName" || rdn.type === "serialNumber")) b.printable(s);
  return rdn.printable ? b.printable(s) : b.utf8(s);
}

function _reconName(name) {
  return b.sequence(name.rdns.map(function (rdn) {
    return b.set([b.sequence([b.oid(oid.byName(rdn.type)), _reconAttrValue(rdn)])]);
  }));
}

function _reconTime(date) {
  if (date === null) return b.generalizedTime(new Date(Date.UTC(9999, 11, 31, 23, 59, 59)));
  return date.getUTCFullYear() < 2050 ? b.utcTime(date) : b.generalizedTime(date);
}

function _reconSpki(spkAlg, keyBytes, rsaKey) {
  if (spkAlg.name === "ecPublicKey") {
    var fieldSize = EC_FIELD_BYTES[spkAlg.curve];
    if (!fieldSize) throw _err("c509/non-invertible", "unsupported EC curve " + spkAlg.curve);
    if (!keyBytes || keyBytes.length === 0) throw _err("c509/non-invertible", "the EC subjectPublicKey byte string is empty");
    var head = keyBytes[0], point;
    if (head === 0x04) {
      if (keyBytes.length !== 1 + 2 * fieldSize) throw _err("c509/non-invertible", "uncompressed EC point length " + keyBytes.length + " does not match " + spkAlg.curve);
      point = keyBytes;
    } else if (head === 0x02 || head === 0x03) {
      if (keyBytes.length !== 1 + fieldSize) throw _err("c509/non-invertible", "compressed EC point length " + keyBytes.length + " does not match " + spkAlg.curve);
      point = keyBytes;
    } else if (head === 0xfe || head === 0xfd) {
      if (keyBytes.length !== 1 + fieldSize) throw _err("c509/non-invertible", "C509-marked EC point length " + keyBytes.length + " does not match " + spkAlg.curve);
      var sec1 = Buffer.concat([Buffer.from([head === 0xfe ? 0x02 : 0x03]), keyBytes.subarray(1)]);
      point = webcrypto.decompressEcPoint(sec1, spkAlg.curve, _err, "c509/non-invertible");
    } else throw _err("c509/non-invertible", "unrecognized EC point encoding 0x" + head.toString(16));
    return b.sequence([b.sequence([b.oid(oid.byName("ecPublicKey")), b.oid(oid.byName(spkAlg.curve))]), b.bitString(point, 0)]);
  }
  if (spkAlg.name === "rsaEncryption") {
    var rsaPk = b.sequence([b.integer(rsaKey.modulus), b.integer(rsaKey.exponent)]);
    return b.sequence([b.sequence([b.oid(oid.byName("rsaEncryption")), b.nullValue()]), b.bitString(rsaPk, 0)]);
  }
  throw _err("c509/non-invertible", "subjectPublicKey algorithm " + spkAlg.name + " is not in the type-3 reconstruction covered set");
}

function _reconKeyUsageBits(value) {
  var c = _namedBitsToContent(value);
  if (c == null) throw _err("c509/non-invertible", "a keyUsage value must be a positive integer within the 9 defined bits");
  return b.bitString(c.bytes, c.unusedBits);
}

function _reconExtensions(exts) {
  var items = exts.map(function (ext) {
    var extnValue;
    if (ext.name === "keyUsage" && typeof ext.keyUsageBits === "number") extnValue = _reconKeyUsageBits(ext.keyUsageBits);
    else if (Buffer.isBuffer(ext.value)) extnValue = ext.value;
    else throw _err("c509/non-invertible", "extension " + ext.name + " has no reconstructable value in the covered set");
    var fields = [b.oid(ext.oid || oid.byName(ext.name))];
    if (ext.critical) fields.push(b.boolean(true));
    fields.push(b.octetString(extnValue));
    return b.sequence(fields);
  });
  return b.explicit(3, b.sequence(items));
}

function _reconAlgId(alg) {
  var fields = [b.oid(alg.oid)];
  if (alg.parameters && alg.parameters.length) {
    fields.push(b.raw(_requireStrictDerTlv(alg.parameters, "c509/non-invertible", "algorithm parameters")));
  }
  return b.sequence(fields);
}

function _reconstructDer(r, sigNode) {
  var sigAlgSeq = _reconAlgId(r.signatureAlgorithm);
  var subjectName = _reconName(r.subject);
  var spelledIssuer = r.issuer && r.issuer.rdns ? _reconName(r.issuer) : null;
  if (spelledIssuer !== null && spelledIssuer.equals(subjectName)) {
    throw _err("c509/bad-name", "an issuer identical to the subject must be encoded as the CBOR simple value null (draft sec. 3.1.4)");
  }
  var tbsFields = [
    b.explicit(0, b.integer(2n)),
    b.integer(r.serialNumber),
    sigAlgSeq,
    spelledIssuer === null ? subjectName : spelledIssuer,
    b.sequence([_reconTime(r.validity.notBefore), _reconTime(r.validity.notAfter)]),
    subjectName,
    _reconSpki(r.subjectPublicKeyAlgorithm, r.subjectPublicKey, r.rsaPublicKey),
  ];
  if (r.extensions.length) tbsFields.push(_reconExtensions(r.extensions));
  var tbs = b.sequence(tbsFields);
  if (String(r.signatureAlgorithm.name || "").toLowerCase().indexOf("ecdsa") !== 0) {
    throw _err("c509/non-invertible", "type-3 signature reconstruction covers only ECDSA; got " + r.signatureAlgorithm.name);
  }
  var coordLen = r.signatureValue.length / 2;
  if (coordLen !== 32 && coordLen !== 48 && coordLen !== 66) {
    throw _err("c509/bad-signature", "the type-3 ECDSA signature width " + r.signatureValue.length + " is not a valid fixed-width r||s (expected 64/96/132 for P-256/384/521)");
  }
  var sigValue = validator.sig.rawToEcdsaDer(r.signatureValue, coordLen);
  return b.sequence([tbs, sigAlgSeq, b.bitString(sigValue, 0)]);
}


/**
 * @primitive  pki.schema.c509.parse
 * @signature  pki.schema.c509.parse(bytes) -> { certificateType, serialNumber, serialNumberHex, ... }
 * @since      0.2.30
 * @status     stable
 * @spec       draft-ietf-cose-cbor-encoded-cert, RFC 8949, RFC 9090, RFC 5280
 *
 * Decode a C509 certificate (draft-ietf-cose-cbor-encoded-cert) from its deterministic-CBOR bytes.
 * Returns the decoded fields (c509CertificateType 2 native or 3 re-encoded); a malformed shape throws a
 * typed C509Error carrying the inner cbor/asn1 fault as .cause. It decodes CBOR, not DER, so it is
 * reached by an explicit call and is not auto-routed by pki.schema.parse. The type-2 signedData and the
 * raw signature are surfaced as-is (a native verifier hashes them without re-serialization).
 *
 * @example
 *   // the RFC 7925 profiled certificate from draft-ietf-cose-cbor-encoded-cert Appendix A.1 (type 3)
 *   var bytes = Buffer.from(
 *     "8b03" + "4301f50d" + "00" + "6b52464320746573742043" + "41" + "1a63b0cd00" + "1a6955b900" +
 *     "d830460123456789ab" + "01" + "5821feb1216ab96e5b3b3340f5bdf02e693f16213a04525ed44450b1019c2dfd3838ab" +
 *     "01" + "5840d4320b1d6849e309219d30037e138166f2508247dddae76ccceea55053c108e90d551f6d60106f1abb484cfbe6256c178e4ac3314ea19191e8b607da5ae3bda16",
 *     "hex");
 *   var c = pki.schema.c509.parse(bytes);
 *   c.certificateType; // 3
 */
function parse(input) {
  var root;
  try { root = cbor.decode(input); }
  catch (e) { throw _err("c509/not-a-certificate", "the input is not well-formed deterministic CBOR", e); }
  if (root.majorType !== 4 || !root.children) throw _err("c509/not-a-certificate", "a C509 certificate must be a CBOR array");
  var f = root.children;
  if (f.length !== 11) throw _err("c509/bad-tbs", "a C509 certificate must be an array of exactly 11 elements, got " + f.length);

  if (f[0].majorType !== 0 && f[0].majorType !== 1) throw _err("c509/bad-certificate-type", "c509CertificateType must be a CBOR integer");
  var type = Number(cbor.read.int(f[0]));
  if (type !== 2 && type !== 3) throw _err("c509/bad-certificate-type", "c509CertificateType must be 2 (native) or 3 (re-encoded), got " + type);

  var serialBytes = f[1];
  var serial = _biguint(serialBytes, "c509/bad-serial", "certificateSerialNumber");
  var sHex = serialBytes.content.toString("hex");

  var sigAlg = _algorithm(f[2], SIG_ALG_BY_INT, "c509/unknown-algorithm", "issuerSignatureAlgorithm");
  var issuer = _name509(f[3], false, type === 2);
  var notBefore = _time(f[4], false, "validityNotBefore");
  var notAfter = _time(f[5], true, "validityNotAfter");
  var subject = _name509(f[6], true, type === 2);
  if (issuer === null && (!subject || !subject.rdns || subject.rdns.length === 0)) {
    throw _err("c509/bad-name", "a self-signed C509 (issuer == subject) requires a non-empty subject, since it is also the issuer (RFC 5280 sec. 4.1.2.4)");
  }
  var spkAlg = _algorithm(f[7], PK_ALG_BY_INT, "c509/unknown-algorithm", "subjectPublicKeyAlgorithm");
  var subjectPublicKey = null, rsaKey = null;
  if (spkAlg.name === "rsaEncryption") {
    if (f[8].majorType === 2) rsaKey = { modulus: _biguint(f[8], "c509/bad-spki", "RSA modulus"), exponent: 65537n };
    else if (f[8].majorType === 4 && f[8].children && f[8].children.length === 2) {
      rsaKey = { modulus: _biguint(f[8].children[0], "c509/bad-spki", "RSA modulus"), exponent: _biguint(f[8].children[1], "c509/bad-spki", "RSA exponent") };
      if (rsaKey.exponent === 65537n) throw _err("c509/bad-spki", "an RSA subjectPublicKey with exponent 65537 omits the array and the exponent (sec. 3.1.9)");
    } else throw _err("c509/bad-spki", "an RSA subjectPublicKey must be a ~biguint modulus or [modulus, exponent]");
    if (rsaKey.modulus < 1n || rsaKey.exponent < 1n) throw _err("c509/bad-spki", "an RSA modulus and public exponent must be positive");
  } else {
    if (f[8].majorType !== 2) throw _err("c509/bad-spki", "subjectPublicKey must be a CBOR byte string");
    subjectPublicKey = f[8].content;
  }
  var extensions = _extensions(f[9], type === 2);
  if (f[10].majorType !== 2) throw _err("c509/bad-signature", "issuerSignatureValue must be a CBOR byte string");
  var signatureValue = f[10].content;

  var result = {
    certificateType: type,
    serialNumber: serial,
    serialNumberHex: sHex,
    signatureAlgorithm: sigAlg,
    issuer: issuer,
    validity: { notBefore: notBefore, notAfter: notAfter },
    subject: subject,
    subjectPublicKeyAlgorithm: spkAlg,
    subjectPublicKey: subjectPublicKey,
    rsaPublicKey: rsaKey,
    extensions: extensions,
    signatureValue: signatureValue,
  };

  result._fieldBytes = root.bytes.subarray(1, root.bytes.length - f[10].bytes.length);
  if (type === 2) result.signedData = result._fieldBytes;

  if (type === 3) result.reconstructedDer = _reconstructDer(result, f[10]);

  return result;
}

function matches(node) {
  return !!node && node.majorType === 4 && !!node.children && node.children.length === 11 &&
    (node.children[0].majorType === 0 || node.children[0].majorType === 1) &&
    (Number(node.children[0].argument) === 2 || Number(node.children[0].argument) === 3);
}


var SIG_ALG_TO_INT = Object.assign(Object.create(null), { ecdsaWithSHA256: 0, ecdsaWithSHA384: 1, ecdsaWithSHA512: 2 });
var PK_ALG_TO_INT = Object.assign(Object.create(null), { rsaEncryption: 0, "ecPublicKey|prime256v1": 1, "ecPublicKey|secp384r1": 2, "ecPublicKey|secp521r1": 3 });
var ATTR_TO_INT = Object.create(null);
Object.keys(ATTR_BY_INT).forEach(function (k) { ATTR_TO_INT[ATTR_BY_INT[k]] = Number(k); });
var EXT_TO_INT = Object.create(null);
Object.keys(EXT_BY_INT).forEach(function (k) { if (EXT_COMPACT[EXT_BY_INT[k]]) EXT_TO_INT[EXT_BY_INT[k]] = Number(k); });

function _minBytes(n) {
  if (n < 0n) throw _err("c509/bad-serial", "a ~biguint value must be non-negative");
  if (n === 0n) return Buffer.alloc(0);
  var hex = n.toString(16); if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}
function _encAlgorithm(alg, toInt, key) {
  var i = toInt[key];
  if (i !== undefined && !(alg.parameters && alg.parameters.length)) return cbor.build.int(BigInt(i));
  var oidBytes = cbor.build.byteString(asn1.encodeOidContent(alg.oid));
  if (alg.parameters && alg.parameters.length) return cbor.build.array([oidBytes, cbor.build.byteString(alg.parameters)]);
  return oidBytes;
}
function _encSpecialText(rdn) {
  if (rdn.eui64) return cbor.build.tag(48, cbor.build.byteString(rdn.eui64));
  var v = String(rdn.value);
  if (v.length >= 2 && _isEvenHexLower(v)) return cbor.build.byteString(Buffer.from(v, "hex"));
  return cbor.build.textString(v);
}
function _encName(name, isSubject) {
  if (name === null || name === undefined) {
    if (!isSubject) return cbor.build.nullValue();
    throw _err("c509/bad-name", "the subject Name is required");
  }
  var rdns = name.rdns || [];
  if (rdns.length === 1 && rdns[0].type === "commonName" && !rdns[0].printable) return _encSpecialText(rdns[0]);
  var items = [];
  rdns.forEach(function (rdn) {
    var ai = ATTR_TO_INT[rdn.type];
    if (ai === undefined) throw _err("c509/bad-name", "attribute type " + rdn.type + " has no C509 registry int");
    items.push(cbor.build.int(BigInt(rdn.printable ? -ai : ai)));
    items.push(_encSpecialText(rdn));
  });
  return cbor.build.array(items);
}
function _encSpk(r) {
  if (r.rsaPublicKey) {
    var mod = cbor.build.byteString(_minBytes(r.rsaPublicKey.modulus));
    if (r.rsaPublicKey.exponent === 65537n) return mod;
    return cbor.build.array([mod, cbor.build.byteString(_minBytes(r.rsaPublicKey.exponent))]);
  }
  if (!Buffer.isBuffer(r.subjectPublicKey)) throw _err("c509/bad-spki", "the subjectPublicKey bytes are missing");
  return cbor.build.byteString(r.subjectPublicKey);
}
function _encExtensions(exts) {
  if (exts.length === 1 && exts[0].name === "keyUsage" && typeof exts[0].keyUsageBits === "number") {
    return cbor.build.int(BigInt(exts[0].critical ? -exts[0].keyUsageBits : exts[0].keyUsageBits));
  }
  var items = [];
  exts.forEach(function (ext) {
    var ei = EXT_TO_INT[ext.name];
    var compact = (ei !== undefined && Buffer.isBuffer(ext.value)) ? _tryCompactExtValue(ext.name, ext.value) : null;
    if (compact != null) {
      items.push(cbor.build.int(BigInt(ext.critical ? -ei : ei)));
      items.push(compact);
    } else {
      items.push(cbor.build.byteString(asn1.encodeOidContent(ext.oid || oid.byName(ext.name))));
      if (!Buffer.isBuffer(ext.value)) throw _err("c509/non-invertible", "extension " + (ext.oid || ext.name) + " has no byte-string value to encode");
      var bs = cbor.build.byteString(ext.value);
      items.push(ext.critical ? cbor.build.array([bs]) : bs);
    }
  });
  return cbor.build.array(items);
}
var _derToType3;
function _requireResultShape(r) {
  if (r.certificateType == null) throw _err("c509/bad-input", "a C509 result must carry certificateType");
  if (r.serialNumber == null && r.serialNumberHex == null) throw _err("c509/bad-input", "a C509 result must carry serialNumber or serialNumberHex");
  if (!r.signatureAlgorithm || typeof r.signatureAlgorithm.name !== "string") throw _err("c509/bad-input", "a C509 result must carry signatureAlgorithm.name");
  if (!r.subjectPublicKeyAlgorithm || typeof r.subjectPublicKeyAlgorithm.name !== "string") throw _err("c509/bad-input", "a C509 result must carry subjectPublicKeyAlgorithm.name");
  if (!r.validity || !guard.time.isDate(r.validity.notBefore) || (r.validity.notAfter !== null && !guard.time.isDate(r.validity.notAfter))) throw _err("c509/bad-input", "a C509 result must carry validity.notBefore (Date) and notAfter (Date or null)");
  if (!Array.isArray(r.extensions)) throw _err("c509/bad-input", "a C509 result must carry an extensions array");
  if (!Buffer.isBuffer(r.signatureValue)) throw _err("c509/bad-input", "a C509 result must carry a Buffer signatureValue");
}
function _validityUint(date, label) {
  var secs = Math.floor(guard.time.instantOf(date) / 1000);
  if (!isFinite(secs) || secs < 0) throw _err("c509/bad-validity", label + " is before the Unix epoch or not a valid date; C509 ~time is a non-negative CBOR epoch");
  return cbor.build.uint(BigInt(secs));
}
function _encodeC509Array(r) {
  if (Buffer.isBuffer(r._fieldBytes)) {
    if (!Buffer.isBuffer(r.signatureValue)) throw _err("c509/bad-input", "a re-emitted certificate must carry a Buffer signatureValue");
    if (r.serialNumberHex != null) _hexBytes(r.serialNumberHex, "c509/bad-serial", "serialNumberHex");
    var out = Buffer.concat([Buffer.from([0x8b]), r._fieldBytes, cbor.build.byteString(r.signatureValue)]);
    parse(out);
    return out;
  }
  _requireResultShape(r);
  var pkKey = r.subjectPublicKeyAlgorithm.curve ? r.subjectPublicKeyAlgorithm.name + "|" + r.subjectPublicKeyAlgorithm.curve : r.subjectPublicKeyAlgorithm.name;
  var arr = cbor.build.array([
    cbor.build.int(BigInt(r.certificateType)),
    cbor.build.byteString(r.serialNumberHex != null ? _hexBytes(r.serialNumberHex, "c509/bad-serial", "serialNumberHex") : _minBytes(r.serialNumber)),
    _encAlgorithm(r.signatureAlgorithm, SIG_ALG_TO_INT, r.signatureAlgorithm.name),
    _encName(r.issuer, false),
    _validityUint(r.validity.notBefore, "validityNotBefore"),
    r.validity.notAfter === null ? cbor.build.nullValue() : _validityUint(r.validity.notAfter, "validityNotAfter"),
    _encName(r.subject, true),
    _encAlgorithm(r.subjectPublicKeyAlgorithm, PK_ALG_TO_INT, pkKey),
    _encSpk(r),
    _encExtensions(r.extensions),
    cbor.build.byteString(r.signatureValue),
  ]);
  parse(arr);
  return arr;
}

/**
 * @primitive  pki.schema.c509.encode
 * @signature  pki.schema.c509.encode(input[, opts]) -> Buffer
 * @since      0.3.4
 * @status     stable
 * @spec       draft-ietf-cose-cbor-encoded-cert, RFC 8949, RFC 9090
 * @related    pki.schema.c509.parse
 *
 * Encode a C509 certificate to its deterministic-CBOR bytes. This is the producing-side inverse of
 * `pki.schema.c509.parse`. `input` is either a DER X.509 v3 certificate (a Buffer or PEM string), which is
 * forward-transformed to a **type-3** C509 (a compact CBOR re-encoding whose signature is copied from the
 * source and re-expressed as a fixed-width r||s, so `parse(encode(der)).reconstructedDer` reproduces the
 * original DER byte for byte and the original signature still verifies), or a `pki.schema.c509.parse`
 * result object, which is re-emitted to its native deterministic-CBOR array. The emission is canonical
 * deterministic CBOR (RFC 8949 sec. 4.2): shortest-form heads, definite lengths, sorted map keys, and the
 * registry integer shorthand for every registered algorithm / attribute / extension. It is signing-free (a
 * byte transform, like `pki.ct.encodeSctList`); a shape outside the covered set throws a typed `C509Error`.
 *
 * The fixed-width ECDSA r||s is sized by the ISSUER's signing curve, which a leaf certificate does not
 * carry. It is resolved authoritatively (never a magnitude guess, and matching issuer/subject Names are not
 * taken as proof of self-signing): from `opts.issuerCurve`, or from the RFC 5480 standard digest<->curve
 * pairing the signature algorithm implies. A certificate signed with a non-standard digest/curve pairing
 * (its r/s wider than the digest's standard curve) fails closed; supply the issuer curve via
 * `opts.issuerCurve`.
 *
 * @opts
 *   - `issuerCurve` (string) -- the ISSUER's ECDSA signing curve "P-256" / "P-384" / "P-521" (or the OID
 *     names prime256v1 / secp384r1 / secp521r1); authoritative, overrides the resolution above. Consulted
 *     only for the DER -> type-3 path; ignored when re-emitting a parse result.
 *
 * @example
 *   // the type-3 (natively signed) encoding covers ECDSA-signed X.509 v3 certificates
 *   var pair = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
 *   var signerCertDer = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"] } },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var cbor = pki.schema.c509.encode(signerCertDer);   // a DER cert -> a compact type-3 C509
 *   pki.schema.c509.parse(cbor).certificateType;        // 3
 */
function _stripHyphens(s) {
  var out = "";
  for (var i = 0; i < s.length; i++) { var ch = s.charAt(i); if (ch !== "-") out += ch; }
  return out;
}
function _euiFromCn(value) {
  if (!_isEui64Text(value)) return null;
  var bytes = Buffer.from(_stripHyphens(value), "hex");
  if (bytes[3] === 0xff && bytes[4] === 0xfe) return Buffer.concat([bytes.subarray(0, 3), bytes.subarray(5)]);
  return bytes;
}
function _c509NameFromDer(nameBytes) {
  var node = asn1.decode(nameBytes);
  var rdns = [];
  (node.children || []).forEach(function (rdnSet) {
    if (!rdnSet.children || rdnSet.children.length !== 1) throw _err("c509/non-invertible", "a C509 Name requires single-attribute RDNs");
    var attr = rdnSet.children[0];
    var attrName = oid.name(asn1.read.oid(attr.children[0]));
    if (attrName == null || ATTR_TO_INT[attrName] === undefined) throw _err("c509/non-invertible", "attribute type " + attrName + " has no C509 registry integer");
    var valNode = attr.children[1];
    var value;
    try { value = asn1.read.string(valNode); }
    catch (e) { throw _err("c509/non-invertible", "attribute " + attrName + " carries a value whose string type the C509 sec. 8.6 int form cannot represent", e); }
    var isIa5 = valNode.tagClass === "universal" && valNode.tagNumber === asn1.TAGS.IA5_STRING;
    if ((attrName === "emailAddress") !== isIa5) throw _err("c509/non-invertible", "attribute " + attrName + " carries a " + (isIa5 ? "IA5String" : "non-IA5String") + " value the C509 sec. 8.6 int form cannot represent");
    var eui = attrName === "commonName" ? _euiFromCn(value) : null;
    if (eui) rdns.push({ type: attrName, value: value, eui64: eui });
    else rdns.push({ type: attrName, value: value, printable: valNode.tagNumber === asn1.TAGS.PRINTABLE_STRING });
  });
  return { rdns: rdns };
}
function _keyUsageBitsFromDer(extnValue) {
  var bs;
  try {
    bs = asn1.read.bitString(asn1.decode(extnValue));
  } catch (_e) {
    return null;
  }
  return _namedBitsFromContent(bs.bytes, bs.unusedBits);
}
var _NO_EXPIRY = C.TIME.seconds(Number(NO_EXPIRY_SECONDS));
var NODE_TO_WEBCRYPTO = Object.assign(Object.create(null), { "prime256v1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521" });
var WEBCRYPTO_FIELD_BYTES = Object.assign(Object.create(null), { "P-256": 32, "P-384": 48, "P-521": 66 });
var SIG_ALG_TO_CURVE = Object.assign(Object.create(null), { "ecdsaWithSHA256": "P-256", "ecdsaWithSHA384": "P-384", "ecdsaWithSHA512": "P-521" });
function _magBytes(intNode) {
  var c = intNode.content, i = 0;
  while (i < c.length - 1 && c[i] === 0x00) i++;
  return c.length - i;
}
function _sigMagWidth(derSig) {
  var n;
  try { n = asn1.decode(derSig); } catch (e) { throw _err("c509/bad-signature", "the ECDSA issuer signature is not valid DER", e); }
  if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length !== 2) throw _err("c509/bad-signature", "the ECDSA issuer signature must be a SEQUENCE of two INTEGERs");
  for (var i = 0; i < 2; i++) {
    var ch = n.children[i];
    if (ch.tagNumber !== asn1.TAGS.INTEGER || ch.tagClass !== "universal" || ch.constructed) throw _err("c509/bad-signature", "the ECDSA issuer signature r and s must be universal INTEGERs");
  }
  return Math.max(_magBytes(n.children[0]), _magBytes(n.children[1]));
}
var CURVE_ORDER = ["P-256", "P-384", "P-521"];
function _minCurveForMag(mag) {
  for (var i = 0; i < CURVE_ORDER.length; i++) { if (mag <= WEBCRYPTO_FIELD_BYTES[CURVE_ORDER[i]]) return CURVE_ORDER[i]; }
  return null;
}
function _resolveIssuerSigCurve(c, opts) {
  var mag = _sigMagWidth(c.signatureValue.bytes), curve;
  if (opts && opts.issuerCurve != null) {
    curve = String(opts.issuerCurve);
    if (NODE_TO_WEBCRYPTO[curve]) curve = NODE_TO_WEBCRYPTO[curve];
    if (!WEBCRYPTO_FIELD_BYTES[curve]) throw _err("c509/bad-input", "opts.issuerCurve must be P-256 / P-384 / P-521 (or prime256v1 / secp384r1 / secp521r1); got " + opts.issuerCurve);
  } else {
    curve = SIG_ALG_TO_CURVE[c.signatureAlgorithm.name];
    if (!curve) throw _err("c509/non-invertible", "cannot resolve the issuer signing curve for signature algorithm " + c.signatureAlgorithm.name);
    var minCurve = _minCurveForMag(mag);
    if (!minCurve) throw _err("c509/non-invertible", "the ECDSA signature r/s width " + mag + " exceeds every supported curve field");
    if (WEBCRYPTO_FIELD_BYTES[curve] < mag) throw _err("c509/non-invertible", "the issuer signed with a non-standard digest/curve pairing (r/s width " + mag + " exceeds the " + curve + " field implied by " + c.signatureAlgorithm.name + "); pass opts.issuerCurve (P-256 / P-384 / P-521)");
    if (WEBCRYPTO_FIELD_BYTES[curve] > WEBCRYPTO_FIELD_BYTES[minCurve]) throw _err("c509/non-invertible", "signature algorithm " + c.signatureAlgorithm.name + " does not uniquely determine the issuer curve (r/s width " + mag + " also fits " + minCurve + "); pass opts.issuerCurve (P-256 / P-384 / P-521)");
  }
  if (mag > WEBCRYPTO_FIELD_BYTES[curve]) throw _err("c509/non-invertible", "the ECDSA signature r/s width " + mag + " does not fit the resolved " + curve + " field");
  return curve;
}
function _compressEcPoint(point, coordLen) {
  if (!point.length || point[0] !== 0x04) return point;
  if (point.length !== 1 + 2 * coordLen) throw _err("c509/non-invertible", "uncompressed EC point length " + point.length + " does not match the curve field size");
  var x = point.subarray(1, 1 + coordLen), y = point.subarray(1 + coordLen);
  return Buffer.concat([Buffer.from([(y[y.length - 1] & 1) ? 0xfd : 0xfe]), x]);
}
_derToType3 = function (input, opts) {
  var c;
  try { c = x509.parse(input); } catch (e) { throw _err("c509/bad-input", "the input is not a valid X.509 certificate", e); }
  if (c.version !== 3) throw _err("c509/non-invertible", "C509 covers X.509 v3 certificates; got v" + c.version);
  if (String(c.signatureAlgorithm.name || "").toLowerCase().indexOf("ecdsa") !== 0) throw _err("c509/non-invertible", "type-3 C509 encoding covers only ECDSA-signed certificates; got " + (c.signatureAlgorithm.name || "an unregistered algorithm"));
  if (c.subjectPublicKeyInfo.algorithm.name !== "ecPublicKey") throw _err("c509/non-invertible", "type-3 C509 encoding covers only EC (ecPublicKey) certificates in v1; got " + (c.subjectPublicKeyInfo.algorithm.name || "an unregistered algorithm"));
  var curveOid = asn1.read.oid(asn1.decode(c.subjectPublicKeyInfo.algorithm.parameters));
  var curve = oid.name(curveOid);
  var coordLen = EC_FIELD_BYTES[curve];
  if (!coordLen) throw _err("c509/non-invertible", "unsupported EC subject curve " + (curve || curveOid));
  var sigCurve = _resolveIssuerSigCurve(c, opts);
  var spkiNode = asn1.decode(c.subjectPublicKeyInfo.bytes);
  return {
    certificateType: 3,
    serialNumber: c.serialNumber,
    signatureAlgorithm: { name: c.signatureAlgorithm.name, oid: c.signatureAlgorithm.oid },
    issuer: c.issuer.bytes.equals(c.subject.bytes) ? null : _c509NameFromDer(c.issuer.bytes),
    validity: { notBefore: c.validity.notBefore, notAfter: guard.time.instantOf(c.validity.notAfter) === _NO_EXPIRY ? null : c.validity.notAfter },
    subject: _c509NameFromDer(c.subject.bytes),
    subjectPublicKeyAlgorithm: { name: "ecPublicKey", oid: c.subjectPublicKeyInfo.algorithm.oid, curve: curve },
    subjectPublicKey: _compressEcPoint(asn1.read.bitString(spkiNode.children[1]).bytes, coordLen),
    rsaPublicKey: null,
    extensions: (c.extensions || []).map(function (e) {
      var ext = { name: e.name, oid: e.oid, critical: !!e.critical, value: e.value };
      if (e.name === "keyUsage") { var bits = _keyUsageBitsFromDer(e.value); if (bits != null) ext.keyUsageBits = bits; }
      return ext;
    }),
    signatureValue: validator.sig.ecdsaDerToP1363(c.signatureValue.bytes, sigCurve, C509Error, "c509/bad-signature"),
  };
};

function encode(input, opts) {
  if (input && typeof input === "object" && !Buffer.isBuffer(input) && input.certificateType != null) {
    return _encodeC509Array(input);
  }
  if (!Buffer.isBuffer(input) && typeof input !== "string") throw _err("c509/bad-input", "encode input must be a DER/PEM X.509 certificate or a c509.parse result");
  var origDer = pkix.coerceToDer(input, { pemLabel: "CERTIFICATE", PemError: frameworkError.PemError, ErrorClass: C509Error, prefix: "c509" });
  var encoded = _encodeC509Array(_derToType3(origDer, opts));
  var recon = parse(encoded).reconstructedDer;
  if (!recon || Buffer.compare(recon, origDer) !== 0) throw _err("c509/non-invertible", "the type-3 C509 does not reconstruct the source certificate byte-for-byte");
  return encoded;
}

module.exports = { parse: parse, matches: matches, encode: encode };
