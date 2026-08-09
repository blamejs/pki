// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.schema.c509
 * @nav    Schema
 * @title  C509
 * @intro  C509 CBOR-encoded certificates (draft-ietf-cose-cbor-encoded-cert). A compact CBOR
 *   re-encoding of an X.509 v3 certificate: a deterministic-CBOR array of exactly 11 elements
 *   (10 TBS fields + the issuer signature). Two modes -- c509CertificateType 2 = natively-signed
 *   C509, 3 = a CBOR re-encoding of a DER X.509 certificate that inverts byte-for-byte to the
 *   original DER (so the original signature still verifies). It decodes CBOR, not DER, so it is
 *   reached by an explicit pki.schema.c509.parse call and is NOT auto-routed by pki.schema.parse.
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
// The ECMAScript Date window is +/- 8.64e15 ms = +/- 8.64e12 seconds; a C509 ~time is an unsigned
// epoch-seconds value, so only the upper bound can be exceeded (mirrors cbor-det read.time).
var MAX_EPOCH_SECONDS = 8640000000000n;

// The C509 integer registries (draft-20 sec. 8.6/sec. 8.8/sec. 8.14/sec. 8.15): a C509 int is a compact ALIAS of an
// OID, resolved to the SAME name oid.byName returns for the DER form. Declared as int -> registered
// OID NAME (never a dotted-decimal literal -- the oid-dotted-decimal-literal gate); oid.byName then
// yields the dotted string. A row whose target name is not registered fails closed at module load.
function _name(n) { var d = oid.byName(n); if (!d) { throw new Error("schema-c509: unregistered OID name " + JSON.stringify(n)); } return n; }

// sec. 8.14 issuerSignatureAlgorithm / signature (the subset v1 covers; negative = legacy SHA-1 values).
var SIG_ALG_BY_INT = {
  0: _name("ecdsaWithSHA256"),
  1: _name("ecdsaWithSHA384"),
  2: _name("ecdsaWithSHA512"),
};
// sec. 8.15 subjectPublicKeyAlgorithm (int -> {alg, curve?} so the reconstruction can rebuild the SPKI).
var PK_ALG_BY_INT = {
  0: { alg: _name("rsaEncryption") },
  1: { alg: _name("ecPublicKey"), curve: _name("prime256v1") },
  2: { alg: _name("ecPublicKey"), curve: _name("secp384r1") },
  3: { alg: _name("ecPublicKey"), curve: _name("secp521r1") },
};
// EC curve -> field size in bytes (the SEC1 coordinate width), for point-length validation.
var EC_FIELD_BYTES = { "prime256v1": 32, "secp384r1": 48, "secp521r1": 66 };

// sec. 8.6 RDN attribute types (abs(int) -> name; the sign selects the X.509 string type: positive utf8String,
// negative printableString). An attribute whose value is ALWAYS an IA5String is instead "unambiguously
// represented using a non-negative int" (draft sec. 3.1.4) -- emailAddress is int 0, so its value reconstructs
// as an IA5String and its sign carries no string-type meaning.
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
// sec. 8.8 extension types (abs(int) -> name; the sign selects criticality). The general-name-bearing
// extensions (subjectAltName / issuerAltName / nameConstraints / cRLDistributionPoints / freshestCRL /
// authorityInfoAccess / subjectInfoAccess) ride the shared sec. 8.13 GeneralNames value codec below; each
// carries a specific CBOR value form and falls back to ~oid + byte-string only when a member is outside
// the sec. 8.13 registry (an x400Address / ediPartyName general name, a non-URI access location, ...).
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
  // RFC 3779 resource-delegation extensions, and their RFC 8360 "v2" twins, which the draft
  // encodes "exactly like" the originals -- same two codecs, four registry rows (sec. 8.8).
  32: _name("ipAddrBlocks"),
  33: _name("autonomousSysIds"),
  34: _name("ipAddrBlocksV2"),
  35: _name("autonomousSysIdsV2"),
  36: _name("ocspNoCheck"),
  38: _name("tlsFeature"),
};
// The extensions whose compact CBOR value form (sec. 3.3) is invertible to/from the DER extnValue.
// A registered extension NOT in this set carries its value as the ~oid + byte-string form (sec. 3.7).
var EXT_COMPACT = {
  subjectKeyIdentifier: 1, keyUsage: 1, basicConstraints: 1, authorityKeyIdentifier: 1,
  extKeyUsage: 1, inhibitAnyPolicy: 1, ocspNoCheck: 1, tlsFeature: 1,
  subjectAltName: 1, issuerAltName: 1, nameConstraints: 1, cRLDistributionPoints: 1,
  freshestCRL: 1, authorityInfoAccess: 1, subjectInfoAccess: 1, certificatePolicies: 1,
  policyMappings: 1, policyConstraints: 1, subjectDirectoryAttributes: 1,
  ipAddrBlocks: 1, autonomousSysIds: 1, ipAddrBlocksV2: 1, autonomousSysIdsV2: 1,
};
// sec. 8.12 Extended Key Usages registry (C509 int -> registered id-kp purpose name). A KeyPurposeId
// outside this set encodes as an unwrapped ~oid; a C509 int outside it fails closed on decode.
var EKU_BY_INT = {
  0: _name("anyExtendedKeyUsage"), 1: _name("serverAuth"), 2: _name("clientAuth"),
  3: _name("codeSigning"), 4: _name("emailProtection"), 8: _name("timeStamping"), 9: _name("ocspSigning"),
  10: _name("pkinitClientAuth"), 11: _name("pkinitKdc"), 12: _name("secureShellClient"), 13: _name("secureShellServer"),
  14: _name("bundleSecurity"), 15: _name("cmcCA"), 16: _name("cmcRA"), 17: _name("cmcArchive"), 18: _name("cmKGA"),
  20: _name("fanDevice"),
};
var EKU_TO_INT = {};   // dotted OID -> C509 int (the encode inverse; keyed on the resolved OID)
Object.keys(EKU_BY_INT).forEach(function (k) { EKU_TO_INT[oid.byName(EKU_BY_INT[k])] = Number(k); });

// The shared pkix namespace + GeneralName leaves the general-name value codec composes for the DER ->
// CBOR direction (the CVE-2009-2408 IA5 control-byte guard, the otherName/directoryName shape, the
// iPAddress length and RFC 9549 subtree-base length are all enforced there -- never re-validated by hand).
var NS = pkix.makeNS("c509", C509Error, oid);
var GN_LEAF = pkix.generalName(NS, { decodeValue: true });                       // SAN-form GeneralName leaf
var GN_LEAF_SUBTREE = pkix.generalName(NS, { decodeValue: true, subtreeBase: true }); // name-constraints subtree base

// sec. 8.13 C509 General Names registry: for the standard forms the C509 int == the RFC 5280 sec. 4.2.1.6
// GeneralName CHOICE context tag (1 rfc822Name, 2 dNSName, 4 directoryName, 6 URI, 7 iPAddress, 8
// registeredID); the _generalNameToDer / _generalNameFromDer switches carry that mapping directly.
// x400Address [3] and ediPartyName [5] have no registry row -- a GeneralNames carrying either is not
// compact-encodable (the enclosing extension falls back to ~oid + byte-string).
// The id-on otherName specials get their own negative C509 ints (sec. 8.13 / sec. 3.3): int -> the id-on
// type-id OID name; the derived inverse keys on the resolved OID so a decode selects the negative int.
var ON_NAME_BY_INT = { "-1": _name("hardwareModuleName"), "-2": _name("smtpUtf8Mailbox"), "-3": _name("macAddress") };
var ON_INT_BY_OID = {};
Object.keys(ON_NAME_BY_INT).forEach(function (k) { ON_INT_BY_OID[oid.byName(ON_NAME_BY_INT[k])] = Number(k); });
// sec. 8.11 C509 Information Access registry (int -> registered access-method OID name; the id-ad methods
// keep the id-ad- prefix, see oid.js). A method OID outside the table encodes as ~oid; a C509 method int
// outside it fails closed. IA_TO_INT is the derived encode inverse, keyed on the resolved OID.
var IA_BY_INT = {
  1: _name("ocsp"), 2: _name("caIssuers"), 3: _name("id-ad-timeStamping"), 5: _name("id-ad-caRepository"),
  10: _name("id-ad-rpkiManifest"), 11: _name("id-ad-signedObject"), 13: _name("id-ad-rpkiNotify"),
};
var IA_TO_INT = {};
Object.keys(IA_BY_INT).forEach(function (k) { IA_TO_INT[oid.byName(IA_BY_INT[k])] = Number(k); });

// sec. 8.9 C509 Certificate Policies registry (int -> registered policy OID name; the CA/Browser Forum
// levels, the RFC 3779 id-cp-ipAddr policies, and the GSMA SGP.22 id-rspRole roles). A policy OID outside
// this set encodes as ~oid; a C509 policy int outside it fails closed. CP_TO_INT is the derived inverse.
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
// sec. 8.10 C509 Policies Qualifiers registry (int -> id-qt qualifier OID name; the derived inverse).
var PQ_BY_INT = { 1: _name("cps"), 2: _name("unotice") };
var PQ_TO_INT = {};
Object.keys(PQ_BY_INT).forEach(function (k) { PQ_TO_INT[oid.byName(PQ_BY_INT[k])] = Number(k); });

// ---- field readers (the unwrapped ~biguint / ~time / ~oid contracts; draft-20 sec. 3.1) ----

// ~biguint (sec. 3.1.2): a BARE byte string (major type 2), big-endian magnitude, the non-negative
// leading 0x00 OMITTED. NOT the shipped read.biguint (which requires the tag-2 wrapper and rejects
// <= 8-byte content). A leading 0x00 is non-minimal; content over the cap is rejected.
function _biguint(node, code, label) {
  if (!node || node.majorType !== 2) throw _err(code, label + " must be an unwrapped CBOR byte string (~biguint)");
  var b = node.content;
  if (b.length > C.LIMITS.CBOR_MAX_BIGUINT_BYTES) throw _err(code, label + " exceeds the ~biguint byte cap");
  if (b.length > 1 && b[0] === 0x00) throw _err("c509/non-minimal-serial", label + " has a redundant leading 0x00 (~biguint omits the sign octet)");
  return b.length ? BigInt("0x" + b.toString("hex")) : 0n;
}

// ~time (sec. 3.1.5): a BARE unsigned integer (major type 0), epoch seconds. A major-type-1 / tag / float
// MUST reject. Bound to the Date window; the CBOR simple null (permitted only for notAfter) -> null.
function _time(node, allowNull, label) {
  if (allowNull && node.majorType === 7 && node.ai === 22) return null;   // CBOR simple null (0xF6)
  if (node.majorType !== 0) throw _err("c509/bad-validity", label + " must be an unwrapped CBOR epoch integer (~time)");
  var secs = node.argument;
  if (secs > MAX_EPOCH_SECONDS) throw _err("c509/bad-validity", label + " is outside the representable Date range");
  return new Date(C.TIME.seconds(Number(secs)));
}

// ~oid (sec. 3.1.3 etc.): a BARE byte string carrying the BER OID content octets (RFC 9090), no tag-111
// head. Compose asn1.decodeOidContent -> dotted -> oid.name (the same the tag reader does internally).
function _oidName(node, code, label) {
  if (!node || node.majorType !== 2) throw _err(code, label + " must be an unwrapped CBOR byte string (~oid)");
  var dotted;
  try { dotted = asn1.decodeOidContent(node.content); }
  catch (e) { throw _err(code, label + " is not a valid BER OID content encoding", e); }
  return { oid: dotted, name: oid.name(dotted) || dotted };
}

// AlgorithmIdentifier (sec. 3.1.3/sec. 3.1.7): int (registry) | ~oid (bare bytes) | [ ~oid, params ].
function _algorithm(node, byInt, code, label) {
  if (node.majorType === 0 || node.majorType === 1) {
    var i = Number(cbor.read.int(node));
    var mapped = byInt[i];   // registry keyed by the signed int (negatives are legacy SHA-1 rows)
    if (mapped === undefined) throw _err("c509/unknown-algorithm", label + " integer " + i + " has no C509 registry row");
    if (typeof mapped === "string") return { name: mapped, oid: oid.byName(mapped) };
    return { name: mapped.alg, oid: oid.byName(mapped.alg), curve: mapped.curve || null };
  }
  if (node.majorType === 2) { var r = _oidName(node, code, label); return { name: r.name, oid: r.oid }; }
  if (node.majorType === 4 && node.children && node.children.length === 2) {
    var a = _oidName(node.children[0], code, label);
    // The [~oid, params] form carries the DER parameters as a CBOR byte string; a non-byte-string here
    // is malformed and cannot be reconstructed (b.raw would append garbage) -- fail closed.
    if (node.children[1].majorType !== 2) throw _err(code, label + " algorithm parameters must be a CBOR byte string");
    // The parameters carry ONE complete DER element spliced into the reconstruction. An empty byte
    // string is no element at all: it rebuilds the same AlgorithmIdentifier as the bare ~oid form,
    // which is how the CDDL already spells "no parameters" -- so accepting it would give one
    // algorithm two encodings, and one X.509 signature would cover both.
    if (node.children[1].content.length === 0) throw _err(code, label + " algorithm parameters must not be an empty byte string; omit them with the bare ~oid form (draft sec. 3.1.3)");
    return { name: a.name, oid: a.oid, parameters: node.children[1].content };
  }
  throw _err(code, label + " is not a C509 AlgorithmIdentifier (int / ~oid / [~oid, params])");
}

// SpecialText attribute value (sec. 3.1.4/sec. 3.1.6): text | bytes (even-length-hex optimization) | tag-48
// (a MAC address, RFC 9542). v1 surfaces the value; the DN string uses the text form.
function _specialText(node) {
  if (node.majorType === 3) return { text: cbor.read.textString(node) };
  if (node.majorType === 2) return { hex: node.content.toString("hex") };
  if (node.majorType === 6 && Number(node.argument) === 48) {
    // A tag-48 MAC address (RFC 9542) MUST wrap a CBOR byte string of 6 (EUI-48/MAC-48) or 8 (EUI-64)
    // bytes; anything else is malformed and cannot reconstruct a well-formed EUI-64 commonName.
    if (!node.children || !node.children[0] || node.children[0].majorType !== 2) {
      throw _err("c509/bad-name", "a tag-48 MAC-address value must wrap a CBOR byte string");
    }
    var euiBytes = node.children[0].content;
    if (euiBytes.length !== 6 && euiBytes.length !== 8) throw _err("c509/bad-name", "a tag-48 MAC address must be 6 (EUI-48) or 8 (EUI-64) bytes");
    return { eui64: euiBytes };
  }
  throw _err("c509/bad-name", "an attribute value is not a C509 SpecialText (text / bytes / tag-48)");
}

// draft sec. 3.1.4 fixes WHICH of the three SpecialText spellings a value takes -- the choice belongs to
// the specification, not the sender. A text string of an even length >= 2 drawn only from '0'-'9'/'a'-'f'
// is encoded as a byte string; a text string of the form "HH-HH-HH-HH-HH-HH-HH-HH" is encoded as a tag-48
// MAC address, 48-bit when it matches "HH-HH-HH-FF-FE-HH-HH-HH" and 64-bit otherwise; anything else is a
// text string. Accepting a second spelling of one value would give the reconstructed certificate more than
// one C509 encoding, so a single X.509 signature would cover them all and two distinct byte strings would
// name one certificate. NOT enforced for a natively signed certificate: sec. 3.1.4 says bytes and tag 48
// there "do not correspond to any predefined text string encoding and may also be used for other attribute
// types", so no canonical text spelling exists to hold one to.
var _HEX_OPTIMIZED = /^(?:[0-9a-f]{2})+$/;
var _EUI64_TEXT = /^(?:[0-9A-F]{2}-){7}[0-9A-F]{2}$/;
function _assertCanonicalSpecialText(node, isNative, E) {
  if (isNative) return;
  if (node.majorType === 3) {
    var t = cbor.read.textString(node);
    if (t.length >= 2 && _HEX_OPTIMIZED.test(t)) {
      throw _err(E, "a text attribute value of even-length hex characters must be encoded as a CBOR byte string (draft sec. 3.1.4)");
    }
    if (_EUI64_TEXT.test(t)) {
      throw _err(E, "a text attribute value in EUI-64 form must be encoded as a CBOR tag-48 MAC address (draft sec. 3.1.4)");
    }
    return;
  }
  if (node.majorType === 2) {
    // An empty byte string renders as the empty text, whose canonical spelling is a text string.
    if (node.content.length === 0) throw _err(E, "an empty attribute value must be encoded as a CBOR text string (draft sec. 3.1.4)");
    return;
  }
  var eui = node.children[0].content;
  if (eui.length === 8 && eui[3] === 0xff && eui[4] === 0xfe) {
    throw _err(E, "an EUI-64 of the form HH-HH-HH-FF-FE-HH-HH-HH must be encoded as a 48-bit MAC address (draft sec. 3.1.4)");
  }
}

// A single Name (sec. 3.1.4/sec. 3.1.6): the CBOR simple null (issuer only) | a bare SpecialText single
// commonName | an array of RDNAttributes. Surfaces { dn, rdns, eui64? } shape-compatible with x509.
// An rdn's (attribute type, sign) pair DECLARES an X.509 string type, so its text must be valid for that type --
// a printableString sign over a non-PrintableString character, a non-ASCII emailAddress (IA5String-only), or a
// value outside the type's SIZE. Assert it by running the SAME builder the reconstruction uses, so a Name this
// parse accepts is always one it can rebuild, and a natively-signed certificate (which never reconstructs) is
// held to the identical rule. Applied to BOTH Name forms -- the array form and the bare single-commonName form.
// The builder's asn1/* fault is re-thrown in this module's domain rather than leaking onto the parse surface.
function _assertAttrValue(rdn) {
  try { _reconAttrValue(rdn); }
  catch (e) {
    if (e instanceof C509Error) throw e;
    throw _err("c509/bad-name", "the " + rdn.type + " value is not valid for the string type its attribute integer declares", e);
  }
}

function _name509(node, isSubject, isNative) {
  if (!isSubject && node.majorType === 7 && node.ai === 22) return null;   // issuer == subject (self-signed)
  // A bare SpecialText (not an array) is a single commonName attribute (attributeType == +1).
  if (node.majorType === 3 || node.majorType === 2 || node.majorType === 6) {
    var sv = _specialText(node);
    _assertCanonicalSpecialText(node, isNative, "c509/bad-name");
    // The bare form is a single commonName -- hold its value to the SAME rules the array form applies, so a
    // natively-signed certificate (which never reconstructs) cannot carry a value the reconstruction would refuse.
    // A tag-48 MAC renders to a fixed 17-character EUI-64 string that satisfies every value rule by
    // construction, and _reconAttrValue short-circuits on eui64 before any of them -- so asserting here would
    // be a no-op. The rules bind on the TEXT forms below.
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
  // Each RDN attribute is an (attributeType, attributeValue) pair; an odd-length array is a dangling
  // attribute type with no value -- reject rather than silently drop the trailing element.
  if (kids.length % 2 !== 0) throw _err("c509/bad-name", "a C509 Name array must be attribute-type/value pairs (dangling attribute type)");
  // RFC 5280 sec. 4.1.2.4 -- the issuer MUST be a non-empty distinguished name (only the SUBJECT may be empty,
  // for the subjectAltName case). An empty issuer array would reconstruct a certificate this toolkit's OWN
  // x509.parse refuses to load (x509/bad-issuer), so the codec must not produce one.
  if (kids.length === 0 && !isSubject) throw _err("c509/bad-name", "the issuer Name must not be empty (RFC 5280 sec. 4.1.2.4)");
  for (var i = 0; i + 1 < kids.length; i += 2) {
    // The attributeType slot must be a CBOR integer (major type 0/1). Guard the major type BEFORE the read
    // so a non-integer type slot fails in this module's own domain (c509/bad-name), matching the value slot,
    // rather than leaking cbor.read.int's cbor/unexpected-major fault onto the parse surface. Reached with
    // attacker-controlled bytes via the sec. 8.13 directoryName general name (subjectAltName, authorityKey-
    // Identifier issuer, cRLDistributionPoints cRLIssuer, nameConstraints subtree base) and the top-level Name.
    if (kids[i].majorType !== 0 && kids[i].majorType !== 1) throw _err("c509/bad-name", "a C509 Name attribute type must be a CBOR integer");
    var ti = Number(cbor.read.int(kids[i]));
    // draft sec. 3.1.4: "in natively signed C509 certificates all CBOR ints SHALL be non-negative." The sign
    // exists ONLY to reproduce the string type of an original X.509 DER, which a native certificate does not
    // have -- so a negative attributeType there is an encoding no conformant producer emits, and accepting it
    // would let this parser read a natively-signed name a conformant peer must reject.
    if (isNative && ti < 0) throw _err("c509/bad-name", "a natively signed C509 Name attribute type integer must be non-negative (draft sec. 3.1.4), got " + ti);
    var tname = ATTR_BY_INT[Math.abs(ti)];
    if (tname === undefined) throw _err("c509/bad-name", "attribute type integer " + ti + " has no C509 registry row");
    var v = _specialText(kids[i + 1]);
    _assertCanonicalSpecialText(kids[i + 1], isNative, "c509/bad-name");
    var vv = v.text !== undefined ? v.text : (v.hex !== undefined ? v.hex : _macToEui64String(v.eui64));
    // The RENDERED text is what carries into the rdn -- deliberately NOT the raw eui64, because the EUI shortcut
    // in _reconAttrValue is unconditional and would take precedence over the attribute's declared string type,
    // rebuilding a tag-48 emailAddress or countryName as a UTF8String. Only the bare-SpecialText form above is
    // always a commonName and may carry it; here the value is held to whatever type the attribute integer declares.
    var rdn = { type: tname, value: vv, printable: ti < 0 };
    _assertAttrValue(rdn);
    rdns.push(rdn);
    parts.push(_shortName(tname) + "=" + guard.name.escapeDnValue(vv));
  }
  // sec. 3.1.4: "If Name contains a single 'common name' attribute with attributeType = +1, it is for
  // compactness encoded as just the SpecialText containing the single attribute value." The array
  // spelling of that one case is therefore a second encoding of a name that already has a canonical
  // one. Only +1 has a bare form -- a negative (printableString) commonName keeps the array.
  if (!isNative && rdns.length === 1 && rdns[0].type === "commonName" && !rdns[0].printable) {
    throw _err("c509/bad-name", "a Name holding a single +1 commonName must be encoded as a bare SpecialText, not an array (draft sec. 3.1.4)");
  }
  return { rdns: rdns, dn: parts.join(", ") };
}
// The rendered dn uses the SAME spelling as every other name renderer here (schema-pkix): the RDNs in
// certificate order joined by ", ", which is what `openssl x509 -subject` prints -- so one certificate
// has one dn string whichever parser read it, and the interop gate can pin both against openssl. It is
// deliberately not the RFC 4514 / LDAP distinguishedName (which reverses the RDNs and drops the space).
// What IS taken from RFC 4514 is sec. 2.4 value escaping, through the shared guard: raw concatenation
// would let a single attribute whose value contains a comma render identically to a genuine multi-RDN
// name (a spoofable identity string, and the ONLY name surface a natively signed certificate has, since
// it never reconstructs DER), and would carry control bytes into logs.
// The SAME label table schema-pkix renders with (pki.C.NAMES.DN_SHORT), not a local list: a hand-rolled
// one covers whichever attributes it was written for and silently renders the rest by their long name,
// so the same certificate would still read differently depending on which parser produced the string.
function _shortName(n) { return (n && constants.NAMES.DN_SHORT[n]) || n; }

// ---- compact per-extension value codec (draft-20 sec. 3.3) -------------------
// Each registered extension in EXT_COMPACT has a specific CBOR encoding of its value that is invertible
// to/from the DER extnValue inner content (the bytes _reconExtensions wraps in an OCTET STRING). Native
// C509 MUST use the specific form (sec. 3.7); the decode side reconstructs the DER, the encode side emits
// the compact form only when it round-trips byte-for-byte (else the ~oid + byte-string fallback).

// A CBOR unsigned integer node -> its BigInt value (major type 0 guarantees non-negative). Arbitrary
// precision: a DER INTEGER holds any width, so no cap -- the round-trip guard verifies the reconstruction.
function _cborUint(node, label) {
  if (node.majorType !== 0) throw _err("c509/bad-extensions", "a " + label + " value must be a CBOR unsigned integer");
  return cbor.read.int(node);
}
// A CBOR integer node (either sign) -> its BigInt value (basicConstraints uses -2/-1/pathLen).
function _cborIntVal(node, label) {
  if (node.majorType !== 0 && node.majorType !== 1) throw _err("c509/bad-extensions", "a " + label + " value must be a CBOR integer");
  return cbor.read.int(node);
}
// A non-negative reconstruct-side count (a policyConstraints / inhibitAnyPolicy SkipCerts, a basicConstraints
// pathLenConstraint) narrowed to [0, 2^31-1] via the SAME guard.range.uint31 the toolkit's own DER decoders
// (schema-pkix) bound these INTEGER (0..MAX) counts through. A native CBOR value past 2^31-1 fails closed here
// rather than reconstructing a DER the toolkit's own decoder would then reject -- the reconstruct path must
// produce nothing that decoder rejects. Returns a Number; b.integer narrows it to the minimal DER INTEGER.
function _boundCount(value, label) {
  return guard.range.uint31(value, _err, "c509/bad-extensions", label + " (0..2^31-1)");
}
// A C509 KeyPurposeId (int registry alias OR unwrapped ~oid) -> the dotted extended-key-usage OID.
function _ekuPurposeOid(node) {
  if (node.majorType === 0 || node.majorType === 1) {
    var i = Number(cbor.read.int(node));
    var nm = EKU_BY_INT[i];
    if (nm === undefined) throw _err("c509/bad-extensions", "an extKeyUsage int " + i + " has no C509 registry row");
    return oid.byName(nm);
  }
  // A ~oid KeyPurposeId routes through _oidName, which validates the BER OID content and remaps an oid/*
  // fault to c509/bad-extensions (fault preserved as .cause) -- a non-byte-string node fails closed there too.
  return _oidName(node, "c509/bad-extensions", "an extKeyUsage KeyPurposeId").oid;
}

// ---- the shared C509 GeneralNames value codec (draft-20 sec. 3.3 / sec. 8.13) ------------------
// One int <-> DER-context-tag pair (_generalNameToDer / _generalNameFromDer) drives every general-name-
// bearing extension (subjectAltName, nameConstraints, authorityKeyIdentifier, cRLDistributionPoints,
// authorityInfoAccess, ...), so a tag/int mapping bug cannot diverge across them. The DER -> CBOR side
// composes the shared pkix.generalName leaf; the CBOR -> DER side builds directly with asn1.build.*, the
// exact inverse. Every encode stays behind the extension-level byte-exact round-trip guard
// (_tryCompactExtValue), so a member the codec cannot invert byte-for-byte falls the WHOLE extension back
// to the conformant ~oid + byte-string form (sec. 3.7) -- never a partial GeneralNames.

// The unwrapped ~oid CBOR form (a bare byte string of the BER OID content octets; RFC 9090).
function _oidCbor(dotted) { return cbor.build.byteString(asn1.encodeOidContent(dotted)); }
// The CBOR simple value null (0xF6): the omitted permitted / excluded / reasons / cRLIssuer field.
function _isCborNull(node) { return node.majorType === 7 && node.ai === 22; }

// A CBOR text node -> the IA5String content octets of an IMPLICIT [n] GeneralName (rfc822Name/dNSName/URI).
// IA5String is 7-bit ASCII, so a code point > 0x7f cannot be one; a control byte (C0/DEL) is an injection
// vector (CVE-2009-2408) the shared name guard rejects -- matching the pkix.generalName decode side, so a
// value it rejects also fails the reconstruction direction (no round-trip guard runs on decode).
function _ia5Bytes(node, tag) {
  if (node.majorType !== 3) throw _err("c509/bad-extensions", "a GeneralName [" + tag + "] value must be a CBOR text string (IA5String)");
  var s = cbor.read.textString(node);
  // An empty IA5 GeneralName is rejected by the shared pkix.generalName leaf (a non-empty rfc822Name /
  // dNSName / URI), so reject it on the reconstruction side too rather than emit an empty [n] IA5String.
  if (s.length === 0) throw _err("c509/bad-extensions", "a GeneralName [" + tag + "] IA5String must be non-empty");
  for (var i = 0; i < s.length; i++) { if (s.charCodeAt(i) > 0x7f) throw _err("c509/bad-extensions", "a GeneralName [" + tag + "] IA5String has a non-ASCII code point"); }
  var buf = Buffer.from(s, "latin1");
  guard.name.assertPrintableIa5(buf, _err, "c509/bad-extensions", "GeneralName [" + tag + "]");
  return buf;
}

// A named-bit-list value (bit i -> named bit i, MSB-first; the 9-bit keyUsage / ReasonFlags range) -> the
// DER BIT STRING content { unusedBits, bytes }, or null when the value is outside the 9 defined bits.
function _namedBitsToContent(value) {
  if (!Number.isInteger(value) || value <= 0 || value > 0x1ff) return null;
  var hi = 0; for (var t = value; t; t >>= 1) hi++; hi -= 1;   // highest set bit index
  var buf = Buffer.alloc((hi >> 3) + 1);
  for (var bit = 0; bit <= hi; bit++) { if (value & (1 << bit)) buf[bit >> 3] |= 0x80 >> (bit & 7); }
  return { unusedBits: 7 - (hi & 7), bytes: buf };
}
// The inverse: a DER BIT STRING content -> the named-bit value (bit i -> 2^i), or null when out of range.
function _namedBitsFromContent(bytes, unusedBits) {
  var total = bytes.length * 8 - unusedBits, value = 0;
  for (var bit = 0; bit < total && bit < 31; bit++) { if (bytes[bit >> 3] & (0x80 >> (bit & 7))) value |= (1 << bit); }
  return value > 0 && value <= 0x1ff ? value : null;
}

// One C509 (int, value) general name -> one DER GeneralName TLV. `ipMode` (name-constraints subtree base)
// only changes the iPAddress arm: SAN is a bare 4/16-octet address, a subtree base is the RFC 9549 form.
function _generalNameToDer(intVal, valueNode, ipMode, isNative) {
  if (intVal === 1 || intVal === 2 || intVal === 6) return b.contextPrimitive(intVal, _ia5Bytes(valueNode, intVal));   // IMPLICIT IA5String
  if (intVal === 4) return b.explicit(4, _reconName(_name509(valueNode, true, isNative)));                                       // directoryName [4] EXPLICIT Name
  if (intVal === 7) return b.contextPrimitive(7, ipMode ? _ncIpToDer(valueNode) : _sanIpBytes(valueNode));             // iPAddress [7] IMPLICIT OCTET STRING
  if (intVal === 8) return b.contextPrimitive(8, asn1.encodeOidContent(_oidName(valueNode, "c509/bad-extensions", "a registeredID [8]").oid));  // registeredID [8] IMPLICIT OID
  if (intVal === 0 || intVal === -1 || intVal === -2 || intVal === -3) return _otherNameToDer(valueNode, intVal);      // otherName [0]
  throw _err("c509/bad-extensions", "GeneralName int " + intVal + " has no C509 sec. 8.13 registry row");
}
// The DER GeneralName leaf result { tagNumber, value, bytes } -> a [intCbor, valueCbor] pair, or null when
// the name is not compact-representable (x400Address [3] / ediPartyName [5], a directoryName the compact
// Name codec cannot hold, a non-canonical name-constraints IP mask).
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
  return null;   // tags 3 / 5 (x400Address / ediPartyName) -- no sec. 8.13 registry row
}

// A flat CBOR array [int, value, int, value, ...] -> the list of DER GeneralName TLVs (the caller wraps
// them: a universal SEQUENCE for SAN/IAN, an implicit [n] for AKI issuer / DP cRLIssuer). These are always
// SAN-form (the RFC 9549 subtree-base iPAddress form is name-constraints-only and routes through
// _subtreesToDer / _subtreesFromDer, which call the singular codec with ipMode directly).
function _generalNamesToDer(node, isNative) {
  if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "a GeneralNames value must be a CBOR array");
  var kids = node.children;
  if (kids.length === 0 || kids.length % 2 !== 0) throw _err("c509/bad-extensions", "a GeneralNames array must be non-empty (int, value) pairs (sec. 3.3)");
  var out = [];
  for (var i = 0; i + 1 < kids.length; i += 2) out.push(_generalNameToDer(Number(_cborIntVal(kids[i], "a GeneralName type")), kids[i + 1], false, isNative));
  return out;
}
// The inverse: a list of DER GeneralName nodes -> the flat CBOR items, or null if ANY member is not
// compact-representable (the whole enclosing extension then falls back -- never a partial GeneralNames).
function _generalNamesFromDer(gnNodes) {
  var out = [];
  for (var i = 0; i < gnNodes.length; i++) {
    var pair = _generalNameFromDer(schema.walk(GN_LEAF, gnNodes[i], NS), false);
    if (pair == null) return null;
    out.push(pair[0]); out.push(pair[1]);
  }
  return out;
}

// otherName [0] IMPLICIT SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY } -- the context tag
// REPLACES the SEQUENCE tag (RFC 5280 IMPLICIT tagging), so the [0] node holds type-id then value directly
// (no inner universal SEQUENCE). The generic form (C509 int 0) carries [ ~oid(type-id), bytes(the [0]
// EXPLICIT inner value's raw TLV) ]; the id-on specials (-1/-2/-3) carry the RFC 4108 / RFC 9598 /
// lamps-macaddress value shapes and reconstruct the full OtherName.
function _otherNameToDer(node, intVal) {
  var typeId, inner;
  if (intVal === 0) {
    if (node.majorType !== 4 || !node.children || node.children.length !== 2) throw _err("c509/bad-extensions", "a generic otherName value must be a CBOR [ ~oid, bytes ] pair");
    typeId = _oidName(node.children[0], "c509/bad-extensions", "an otherName type-id").oid;
    if (node.children[1].majorType !== 2) throw _err("c509/bad-extensions", "an otherName value must be a CBOR byte string (the [0] EXPLICIT inner TLV)");
    // The [0] EXPLICIT inner TLV is an ANY spliced verbatim -- strict-validate it, not just its framing.
    inner = _requireStrictDerTlv(node.children[1].content, "c509/bad-extensions", "an otherName value");
  } else if (intVal === -1) {   // id-on-hardwareModuleName: [ ~oid(hwType), bytes(hwSerialNum) ] -> HardwareModuleName
    if (node.majorType !== 4 || !node.children || node.children.length !== 2) throw _err("c509/bad-extensions", "an id-on-hardwareModuleName value must be a CBOR [ ~oid, bytes ] pair");
    if (node.children[1].majorType !== 2) throw _err("c509/bad-extensions", "a hardwareModuleName hwSerialNum must be a CBOR byte string");
    typeId = oid.byName("hardwareModuleName");
    inner = b.sequence([b.oid(_oidName(node.children[0], "c509/bad-extensions", "a hardwareModuleName hwType").oid), b.octetString(node.children[1].content)]);
  } else if (intVal === -2) {   // id-on-SmtpUTF8Mailbox: text -> UTF8String (RFC 9598 SIZE (1..MAX))
    if (node.majorType !== 3) throw _err("c509/bad-extensions", "an id-on-SmtpUTF8Mailbox value must be a CBOR text string");
    var smtp = cbor.read.textString(node);
    if (smtp.length === 0) throw _err("c509/bad-extensions", "an id-on-SmtpUTF8Mailbox value must be non-empty (RFC 9598 SIZE (1..MAX))");
    typeId = oid.byName("smtpUtf8Mailbox");
    inner = b.utf8(smtp);
  } else {   // intVal === -3, id-on-MACAddress: bytes (6 = EUI-48, 8 = EUI-64) -> OCTET STRING
    if (node.majorType !== 2) throw _err("c509/bad-extensions", "an id-on-MACAddress value must be a CBOR byte string");
    if (node.content.length !== 6 && node.content.length !== 8) throw _err("c509/bad-extensions", "an id-on-MACAddress value must be 6 (EUI-48) or 8 (EUI-64) octets");
    typeId = oid.byName("macAddress");
    inner = b.octetString(node.content);
  }
  return b.contextConstructed(0, Buffer.concat([b.oid(typeId), b.explicit(0, inner)]));   // [0] IMPLICIT SEQUENCE
}
// The inverse: the pkix.generalName otherName value { typeId, valueBytes } -> a [intCbor, valueCbor] pair,
// or null when an id-on special's inner value is not its RFC-defined shape (the extension then falls back).
function _otherNameFromDer(v) {
  var onInt = ON_INT_BY_OID[v.typeId];
  if (onInt === undefined) return [cbor.build.int(0n), cbor.build.array([_oidCbor(v.typeId), cbor.build.byteString(v.valueBytes)])];
  var inner;
  try { inner = asn1.decode(v.valueBytes); } catch (_e) { return null; }
  if (onInt === -1) {   // HardwareModuleName ::= SEQUENCE { hwType OID, hwSerialNum OCTET STRING } (RFC 4108)
    if (inner.tagClass !== "universal" || inner.tagNumber !== asn1.TAGS.SEQUENCE || !inner.children || inner.children.length !== 2) return null;
    var hwType, hwSerial;
    try { hwType = asn1.read.oid(inner.children[0]); hwSerial = asn1.read.octetString(inner.children[1]); } catch (_e2) { return null; }
    return [cbor.build.int(-1n), cbor.build.array([_oidCbor(hwType), cbor.build.byteString(hwSerial)])];
  }
  if (onInt === -2) {   // SmtpUTF8Mailbox ::= UTF8String (RFC 9598)
    if (inner.tagClass !== "universal" || inner.tagNumber !== asn1.TAGS.UTF8_STRING) return null;
    var txt; try { txt = asn1.read.string(inner); } catch (_e3) { return null; }
    return [cbor.build.int(-2n), cbor.build.textString(txt)];
  }
  if (inner.tagClass !== "universal" || inner.tagNumber !== asn1.TAGS.OCTET_STRING) return null;   // onInt === -3: MACAddress ::= OCTET STRING
  var mac; try { mac = asn1.read.octetString(inner); } catch (_e4) { return null; }
  // nosemgrep: pki-non-constant-time-secret-compare -- mac is a PUBLIC hardware MAC address (an EUI-48/64
  // identifier, RFC 9542 / lamps-macaddress), not a MAC / HMAC / auth tag / secret; this is a length check.
  if (mac.length !== 6 && mac.length !== 8) return null;
  return [cbor.build.int(-3n), cbor.build.byteString(mac)];
}

// directoryName [4] EXPLICIT Name (a CHOICE, hence EXPLICIT) <-> the C509 compact Name. Reuses the file's
// Name codecs; a Name the compact form cannot hold (a multi-value RDN, an attribute outside sec. 8.6)
// returns null so the whole extension falls back to ~oid + byte-string.
function _dirNameToCbor(gnBytes) {
  var node = asn1.decode(gnBytes);   // the [4]-tagged EXPLICIT wrapper
  if (!node.children || node.children.length !== 1) return null;
  var name;
  try { name = _c509NameFromDer(node.children[0].bytes); } catch (_e) { return null; }
  try { return _encName(name, true); } catch (_e2) { return null; }
}

// iPAddress [7] (SAN form): a bare 4-octet (IPv4) or 16-octet (IPv6) address, CBOR bytes <-> DER content.
function _sanIpBytes(node) {
  if (node.majorType !== 2) throw _err("c509/bad-extensions", "an iPAddress value must be a CBOR byte string");
  if (node.content.length !== 4 && node.content.length !== 16) throw _err("c509/bad-extensions", "an iPAddress must be 4 (IPv4) or 16 (IPv6) octets");
  return node.content;
}
// iPAddress [7] (name-constraints subtree base): RFC 9549 sec. 2.2. CBOR is address || prefix-length (5 or
// 17 octets, the last octet the prefix bit count); DER is address || mask (8 or 32 octets). CBOR -> DER
// expands the prefix length to a contiguous mask.
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
// DER -> CBOR: address || mask (8/32) -> address || prefix-length (5/17). The mask MUST be a canonical
// contiguous prefix mask (N leading 1-bits then all 0-bits); a non-prefix mask (host bits set,
// non-contiguous) is not representable in the prefix form -> null (the extension falls back, losing no bits).
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

// ---- RFC 3779 IPAddrBlocks / ASIdentifiers (draft sec. 3.3, ext ints 32-35) -----------------
//
// An RFC 3779 IPAddress is a BIT STRING whose unused-bit count carries the prefix length, so the
// draft maps it to the byte sequence `unusedBits || value`, which "preserves the exact information
// contained in the ASN.1 BIT STRING" -- lossless even for a prefix ending in zero bits. Per
// IPAddressFamily the draft then picks ONE of two forms and makes the choice a SHALL: if any of the
// family's byte sequences exceeds 8 octets the whole family uses the bytes form, otherwise the int
// form. Accepting the wrong one would give one DER two CBOR encodings, so decode enforces it.
//
// The int form is the big-endian integer of `(unusedBits + 1) || value` -- the +1 guarantees a
// non-zero leading octet, which is what makes the minimal big-endian representation unambiguous --
// and every IPAddress after the first is stored as the DIFFERENCE from its predecessor. The chain
// runs flat over each address in order (a range contributes min then max) and RESETS at each
// family, so a family always opens with an absolute value.
//
// These integers reach 2^64-1: an IPv6 /48 already exceeds 2^53, and the draft's own A.5 vector
// lands there. Everything below is BigInt end to end and bounds through guard.range.uint64 (the
// BigInt-preserving guard) -- never the uint31 counter bound, which would reject a valid prefix.

// An asn1 node exposes tagClass + tagNumber (never a combined `.tag`), so a universal-type test
// has to check both -- a context-tagged [16] must not read as a SEQUENCE.
function _isUniversal(n, tagNumber) { return !!n && n.tagClass === "universal" && n.tagNumber === tagNumber; }

// `unusedBits || value` -> the (unusedBits+1)||value integer. Returns null if the sequence cannot
// be one (empty, or an unused-bit count DER would not accept).
function _ipSeqToInt(seq) {
  if (!seq.length || seq[0] > 7) return null;
  // One-shot base-256 parse of (unusedBits+1)||value. A per-byte shift-accumulate is quadratic in
  // the operand width, so the toolkit builds a BigInt from its hex in a single call instead.
  var head = Buffer.from([seq[0] + 1]);
  return BigInt("0x" + Buffer.concat([head, seq.subarray(1)]).toString("hex"));
}
// The inverse: the minimal big-endian octets of `n`, with the leading octet decremented back to the
// unused-bit count. Returns null when `n` cannot be an encoded IPAddress -- a leading octet outside
// 1..8 is not a DER unused-bit count, and past 8 octets the family was required to use the bytes form.
function _ipIntToSeq(n) {
  if (n < 1n) return null;
  var out = [];
  for (var v = n; v > 0n; v >>= 8n) out.unshift(Number(v & 0xffn));
  if (out.length > 9 || out[0] < 1 || out[0] > 8) return null;
  out[0] -= 1;
  return Buffer.from(out);
}
// The address width in octets of an address family, from its AFI (RFC 3779 sec. 2.2.3.3). Only a
// family whose width is known can have its canonical form checked, so an unrecognized AFI yields
// null and the caller declines to compact rather than compacting something it cannot verify.
var _IP_WIDTH = { 1: 4, 2: 16 };

// The lowest address an `unusedBits || value` sequence denotes, as `width` big-endian octets. DER
// forces the unused bits to zero, so the value IS its own lowest address once zero-extended.
function _ipLow(seq, width) {
  var v = Buffer.alloc(width);
  seq.subarray(1).copy(v);
  return v;
}
// The highest address it denotes: the same prefix with every host bit set (RFC 3779 sec. 2.2.3.8 --
// a range's max is likewise the prefix with its trailing bits taken as ones).
function _ipHigh(seq, width) {
  var v = _ipLow(seq, width);
  var bits = (seq.length - 1) * 8 - seq[0];
  for (var i = bits; i < width * 8; i++) v[i >> 3] |= 0x80 >> (i & 7);
  return v;
}
// Big-endian octet-string compare, and "is `b` the immediate successor of `a`" -- the test that
// distinguishes a legal gap from a contiguous pair the RFC requires be merged.
function _ipOctCmp(a, b) {
  for (var i = 0; i < a.length; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return 0;
}
function _ipIsSuccessor(a, b) {
  var carry = 1, inc = Buffer.from(a);
  for (var i = inc.length - 1; i >= 0 && carry; i--) { var s = inc[i] + carry; inc[i] = s & 0xff; carry = s >> 8; }
  if (carry) return false;                    // `a` was already the maximum address
  return _ipOctCmp(inc, b) === 0;
}

// RFC 3779 sec. 2.2.3.7: "any range of addresses that can be encoded as a prefix MUST be encoded
// using an IPAddress element", with the choice fixed by the spec's own pseudocode -- let N be the
// count of matching leading bits of the low and high addresses; if every remaining bit of the low
// is zero AND every remaining bit of the high is one, the span IS the N-bit prefix and the range
// form is forbidden. Two encodings of one address span would otherwise both be legal.
function _ipRangeIsPrefix(lo, hi) {
  var bits = lo.length * 8, n = 0;
  while (n < bits) {
    var byteAt = n >> 3, mask = 0x80 >> (n & 7);
    if ((lo[byteAt] & mask) !== (hi[byteAt] & mask)) break;
    n++;
  }
  for (var i = n; i < bits; i++) {
    var bt = i >> 3, mk = 0x80 >> (i & 7);
    if ((lo[bt] & mk) !== 0) return false;        // a low-address host bit is set
    if ((hi[bt] & mk) === 0) return false;        // a high-address host bit is clear
  }
  return true;
}

// RFC 3779 sec. 2.2.3.3 orders the families themselves: "There MUST be only one IPAddressFamily
// SEQUENCE per unique combination of AFI and SAFI. Each SEQUENCE MUST be ordered by ascending
// addressFamily values (treating the octets as unsigned quantities). An addressFamily without a
// SAFI MUST precede one that contains an SAFI." A plain unsigned octet-string compare gives all
// three at once, because a two-octet family is a PREFIX of the three-octet one sharing its AFI and
// a prefix sorts first. Returns < 0, 0 or > 0; 0 means the same AFI/SAFI appeared twice.
function _famOctCmp(a, b) {
  var n = Math.min(a.length, b.length);
  for (var i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return a.length - b.length;
}

// Is `unusedBits || value` a sequence DER would accept as a BIT STRING? The declared unused low
// bits MUST be zero (RFC 3779 sec. 2.2.3.8 restates the DER rule), and a value with no octets can
// only declare zero unused bits. Checked HERE rather than left to the BIT STRING builder, because
// the builder's fault is an asn1/* error surfacing out of a CBOR-layer decode -- a caller handed a
// malformed compact value should see this module's own verdict, not the ASN.1 layer's.
function _ipSeqBitsClear(seq) {
  var unused = seq[0], value = seq.subarray(1);
  if (!value.length) return unused === 0;
  if (unused === 0) return true;
  return (value[value.length - 1] & ((1 << unused) - 1)) === 0;
}

// RFC 3779 sec. 2.2.3.6 fixes the canonical form of an address list: entries sorted on
// `<lowest address> | <prefix length>` (which is neither the DER byte order nor the compact integer
// order -- the RFC warns about the first and the second sorts the same wrong way), no pair
// overlapping, and any contiguous pair combined into one entry. All three bind together: a list
// violating any of them is not the one canonical encoding of its address set, so this codec
// declines to compact it and the extension keeps its original bytes.
// Two comparisons carry all three rules. `cur.lo > prev.hi` is the no-overlap rule AND the sort
// rule at once: entries are already known to have lo <= hi, so an entry that started at or before
// its predecessor's low address would also start at or before its high one. A separate ascending
// test would therefore be a branch nothing can reach.
function _ipRangesCanonical(bounds) {
  for (var i = 1; i < bounds.length; i++) {
    var prev = bounds[i - 1], cur = bounds[i];
    if (_ipOctCmp(cur.lo, prev.hi) <= 0) return false;        // out of order, or overlapping
    if (_ipIsSuccessor(prev.hi, cur.lo)) return false;        // contiguous: MUST have been merged
  }
  return true;
}

// One family's IntIPAddressChoice / IPAddressChoice -> the DER IPAddressOrRange SEQUENCE list.
// The int form stores each address after the first as a DIFFERENCE from its predecessor, flat over
// every address in order (a range contributes min then max); the chain resets at each family, which
// is why `prev` starts null here rather than being threaded across families. The reconstructed
// ABSOLUTE is what gets bounded -- the delta itself is an arbitrary CBOR int and bounding it would
// miss a chain that walks out of range in steps.
function _ipChoiceToDer(items, afi) {
  var out = [], prev = null, sawBytes = false, sawInt = false, seqs = [];
  // An address may not be wider than its family: RFC 3779 sec. 2.2.3.8 sizes an IPAddress by the
  // family, so a 5-octet address under AFI 1 is not an IPv4 address at all. Without this, a native
  // C509 would reconstruct into a DER carrying an over-wide address -- one the RFC forbids and an
  // independent validator refuses -- from CBOR this codec had accepted. The mirror check lives on
  // the encode side; both directions have to hold or the pair is not a bijection.
  // Without the family's address width none of the RFC 3779 rules below can be evaluated: the
  // width bound has nothing to compare against, and the low/high bounds that drive the order,
  // overlap, adjacency and endpoint checks cannot be computed at all. Accepting such a family
  // would therefore wave every one of those checks through -- so a family this codec cannot
  // measure is refused outright, matching the encode side, which declines to compact it. An
  // `inherit` family is unaffected: it carries no addresses and never reaches here.
  var width = _IP_WIDTH[afi];
  if (!width) throw _err("c509/bad-extensions", "address family " + afi + " has no known address width, so its addresses cannot be checked (RFC 3779 sec. 2.2.3.3)");
  function widthOk(seq) { return seq.length - 1 <= width; }
  function absolute(node) {
    var seq;
    if (node.majorType === 2) {                              // bytes form: the sequence verbatim
      sawBytes = true;
      if (node.content.length === 0) throw _err("c509/bad-extensions", "an IPAddress byte sequence must be non-empty");
      if (node.content[0] > 7) throw _err("c509/bad-extensions", "an IPAddress unused-bit count must be 0..7 (DER)");
      seq = node.content;
    } else {
      sawInt = true;
      var d = _cborIntVal(node, "an IPAddress");
      var abs = prev === null ? d : prev + d;
      prev = abs;
      // Bound the reconstructed absolute through the BigInt-preserving guard: this domain reaches
      // 2^64-1, so narrowing to Number would corrupt the value being guarded.
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
    if (it.majorType === 4) {                                 // [min, max] -> an addressRange
      if (!it.children || it.children.length !== 2) throw _err("c509/bad-extensions", "an IPAddress range must be exactly [min, max]");
      var lo = absolute(it.children[0]), hi = absolute(it.children[1]);
      seqs.push(lo); seqs.push(hi);
      var rlo = _ipLow(lo, width), rhi = _ipHigh(hi, width);
      {
        // A span expressible as a prefix MUST use the prefix form (RFC 3779 sec. 2.2.3.7), or one
        // address span would have two legal encodings.
        if (_ipRangeIsPrefix(rlo, rhi)) throw _err("c509/bad-extensions", "an address range that is exactly a prefix must use the prefix form (RFC 3779 sec. 2.2.3.7)");
        bounds.push({ lo: rlo, hi: rhi });
      }
      out.push(b.sequence([b.bitString(lo.subarray(1), lo[0]), b.bitString(hi.subarray(1), hi[0])]));
    } else {                                                  // a single addressPrefix
      var pfx = absolute(it);
      seqs.push(pfx);
      bounds.push({ lo: _ipLow(pfx, width), hi: _ipHigh(pfx, width) });
      out.push(b.bitString(pfx.subarray(1), pfx[0]));
    }
  }
  // The form choice is a SHALL, so the wrong one would give one DER two CBOR encodings. A family
  // mixing the two arms is not a choice either admits; a bytes-form family whose every sequence
  // fits 8 octets was required to use the int form.
  if (sawBytes && sawInt) throw _err("c509/bad-extensions", "an IPAddressFamily must use one address form throughout (sec. 3.3)");
  if (sawBytes && !seqs.some(function (s) { return s.length > 8; })) {
    throw _err("c509/bad-extensions", "an IPAddressFamily whose addresses all fit 8 octets must use the integer form (sec. 3.3)");
  }
  // The SAME RFC 3779 sec. 2.2.3.6 canonical form the encode side requires, enforced here too.
  // draft sec. 3.3 says "The limitations specified in [RFC3779] apply here as well", so a compact
  // list that is unsorted, overlapping, or unmerged is malformed C509 -- and reconstructing it
  // would emit a certificate an independent validator refuses, from CBOR this codec had accepted.
  // Both directions must hold or the pair is not a bijection.
  for (var r = 0; r < bounds.length; r++) {
    if (_ipOctCmp(bounds[r].lo, bounds[r].hi) > 0) throw _err("c509/bad-extensions", "an IPAddress range must not end below its start (RFC 3779 sec. 2.2.3.9)");
  }
  if (!_ipRangesCanonical(bounds)) {
    throw _err("c509/bad-extensions", "an IPAddressFamily must be sorted, non-overlapping and maximally merged (RFC 3779 sec. 2.2.3.6)");
  }
  return out;
}

// DER IPAddressChoice (a SEQUENCE of BIT STRING / SEQUENCE-of-two-BIT-STRING) -> the compact CBOR
// array. The form is chosen per family and is a SHALL: the bytes form applies to the WHOLE family
// as soon as any one sequence exceeds 8 octets, otherwise every member takes the delta-coded int
// form. Returns null on any shape the compact form cannot carry exactly.
function _ipChoiceFromDer(ch, afi) {
  if (!_isUniversal(ch, asn1.TAGS.SEQUENCE) || !ch.children || ch.children.length === 0) return null;
  // Collect each address as its `unusedBits || value` sequence, keeping the range grouping.
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
  // The list must be in RFC 3779 sec. 2.2.3.6 canonical form -- sorted, non-overlapping, and with
  // every contiguous pair already merged. A list that is not is not the one canonical encoding of
  // its address set, so it is NOT re-encoded into a conforming one: this returns null and the
  // extension rides the byte-string form, keeping its exact bytes and leaving the defect visible to
  // a validator. Checking overlap and adjacency needs the family's address width, so a family whose
  // AFI this codec does not know declines too, rather than compacting what it cannot verify.
  // Defense-in-depth, and deliberately explicit: without the width the bound arithmetic below would
  // fault and the caller's catch would produce the same fallback, so this line changes no observable
  // verdict and no vector can isolate it. It stays because a fallback that depends on an exception
  // being raised somewhere downstream is one refactor away from becoming an accepted value.
  var width = _IP_WIDTH[afi];
  if (!width) return null;
  var bounds = [];
  for (var g = 0; g < groups.length; g++) {
    var bg = groups[g];
    if (bg[0].length - 1 > width || bg[bg.length - 1].length - 1 > width) return null;   // longer than the family's addresses
    var blo = _ipLow(bg[0], width), bhi = _ipHigh(bg[bg.length - 1], width);
    // The mirror of the decode-side rule: a range that is exactly a prefix had to be written as one.
    // No vector can isolate this line today, because the encode path's round-trip self-verify
    // re-parses what it produced and the decode rule rejects it there, yielding the same fallback.
    // It stays explicit because that makes encode's correctness depend on decode continuing to
    // throw -- soften the decode rule and this path would silently start compacting again.
    if (bg.length === 2 && _ipRangeIsPrefix(blo, bhi)) return null;
    bounds.push({ lo: blo, hi: bhi });
  }
  // A range's own endpoints must ascend too, which a single-entry list has no chance to violate.
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

// One ASId in the delta chain -> its absolute value, bounded to the RFC 3779 32-bit ASId domain.
// Safe to narrow here (2^32-1 < 2^53), unlike the IP domain.
function _asDelta(node, prev) {
  var d = _cborIntVal(node, "an ASIdentifier");
  var abs = prev === null ? d : prev + d;
  // Bound only -- the narrowed Number the guard returns is deliberately discarded, because the
  // chain's next step adds a BigInt delta to this value and mixing the two throws.
  guard.range.int(abs, 0n, 4294967295n, _err, "c509/bad-extensions", "an ASIdentifier");
  return abs;
}

// GeneralSubtrees = [ + GeneralName ] (the flat int/value array) <-> the concatenated GeneralSubtree
// SEQUENCEs (RFC 5280 sec. 4.2.1.10: SEQUENCE { base, minimum [0] DEFAULT 0, maximum [1] OPTIONAL }); the
// C509 profile omits minimum/maximum, so each GeneralSubtree is base-only.
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
    if (st.tagClass !== "universal" || st.tagNumber !== asn1.TAGS.SEQUENCE || !st.children || st.children.length !== 1) return null;   // base only (minimum/maximum omitted)
    var pair = _generalNameFromDer(schema.walk(GN_LEAF_SUBTREE, st.children[0], NS), true);
    if (pair == null) return null;
    out.push(pair[0]); out.push(pair[1]);
  }
  return out;
}

// A CBOR accessMethod (int, sec. 8.11 registry, or ~oid) -> the dotted access-method OID.
function _accessMethodOid(node) {
  if (node.majorType === 0 || node.majorType === 1) {
    var i = Number(cbor.read.int(node)), nm = IA_BY_INT[i];
    if (nm === undefined) throw _err("c509/bad-extensions", "an accessMethod int " + i + " has no C509 sec. 8.11 registry row");
    return oid.byName(nm);
  }
  return _oidName(node, "c509/bad-extensions", "an accessMethod").oid;
}
// A reasons uint (bit i -> named ReasonFlags bit i) -> the [1] IMPLICIT ReasonFlags BIT STRING TLV.
function _reasonsBitsToDer(value) {
  // ReasonFlags bit 0 is reserved "unused" (RFC 5280 sec. 4.2.1.13; the reason bits are 1..8), so a value
  // that sets it is not a valid ReasonFlags even though the shared 9-bit range check would accept it. Bit 0
  // is a legitimate keyUsage bit (digitalSignature), so this reason-specific reject lives here, not in the
  // shared named-bit helper -- a malformed native C509 reasons value fails closed rather than reconstructing
  // a semantically invalid X.509 ReasonFlags.
  if ((value & 1) !== 0) throw _err("c509/bad-extensions", "a cRLDistributionPoints reasons value must not set the reserved unused ReasonFlags bit 0 (RFC 5280 sec. 4.2.1.13)");
  var c = _namedBitsToContent(value);
  if (c == null) throw _err("c509/bad-extensions", "a cRLDistributionPoints reasons value must be within the 9 defined ReasonFlags bits");
  return b.contextPrimitive(1, Buffer.concat([Buffer.from([c.unusedBits]), c.bytes]));
}
// A CBOR ~biguint serial node -> the DER INTEGER content octets (minimal two's-complement of the
// non-negative serial): the bare magnitude, prefixed with a 0x00 sign octet when its top bit is set.
function _serialIntContent(node) {
  var mag = _minBytes(_biguint(node, "c509/bad-extensions", "an authorityKeyIdentifier serial"));
  if (mag.length === 0) return Buffer.from([0x00]);                                     // serial 0
  return (mag[0] & 0x80) ? Buffer.concat([Buffer.from([0x00]), mag]) : mag;
}

// ---- certificatePolicies (draft-20 sec. 3.3 / sec. 8.9 / sec. 8.10; RFC 5280 sec. 4.2.1.4) ----
// A CBOR text -> a UNIVERSAL IA5String TLV, running the same 7-bit + CVE-2009-2408 control-byte guard the
// general-name IA5 arms use (never the bare b.ia5, which permits control bytes). Non-empty (the general-name
// IA5 arms reject empty too; a CPSuri parity tightening -- RFC 5280 sets no SIZE floor on CPSuri).
function _ia5Universal(text, label) {
  if (text.length === 0) throw _err("c509/bad-extensions", label + " must be non-empty");
  for (var i = 0; i < text.length; i++) { if (text.charCodeAt(i) > 0x7f) throw _err("c509/bad-extensions", label + " must be a 7-bit IA5String"); }
  guard.name.assertPrintableIa5(Buffer.from(text, "latin1"), _err, "c509/bad-extensions", label);
  return b.ia5(text);
}
// A CBOR policyIdentifier (a sec. 8.9 registry int, or an unwrapped ~oid) -> the dotted policy OID.
function _policyIdToDerOid(node) {
  if (node.majorType === 0 || node.majorType === 1) {
    var i = Number(cbor.read.int(node)), nm = CP_BY_INT[i];
    if (nm === undefined) throw _err("c509/bad-extensions", "a certificatePolicies policy int " + i + " has no C509 sec. 8.9 registry row");
    return oid.byName(nm);
  }
  return _oidName(node, "c509/bad-extensions", "a certificatePolicies policyIdentifier").oid;
}
// The inverse: a dotted policy OID -> CBOR (a sec. 8.9 int if registered, else an unwrapped ~oid).
function _policyIdFromDer(dotted) {
  var i = CP_TO_INT[dotted];
  return i !== undefined ? cbor.build.int(BigInt(i)) : _oidCbor(dotted);
}
// (qualifierId CBOR, qualifier-text CBOR) -> one DER PolicyQualifierInfo SEQUENCE { policyQualifierId OID,
// qualifier ANY DEFINED BY }. The qualifierId resolves to a sec. 8.10 int ONLY: a ~oid / unregistered
// qualifierId has no defined qualifier:text semantics, so it is not compact-representable (fail closed, never
// guess the ANY type). id-qt-cps -> CPSuri IA5String; id-qt-unotice -> UserNotice { explicitText utf8String }.
function _qualifierToDer(qidNode, qtextNode) {
  if (qidNode.majorType !== 0 && qidNode.majorType !== 1) throw _err("c509/bad-extensions", "a policyQualifierId must be a C509 sec. 8.10 int (a ~oid qualifier is not compact-representable)");
  var qi = Number(cbor.read.int(qidNode)), nm = PQ_BY_INT[qi];
  if (nm === undefined) throw _err("c509/bad-extensions", "a policyQualifierId int " + qi + " has no C509 sec. 8.10 registry row");
  if (qtextNode.majorType !== 3) throw _err("c509/bad-extensions", "a policyQualifier value must be a CBOR text string");
  var text = cbor.read.textString(qtextNode);
  if (qi === 1) return b.sequence([b.oid(oid.byName("cps")), _ia5Universal(text, "a CPSuri")]);   // CPSuri ::= IA5String
  // id-qt-unotice: UserNotice ::= SEQUENCE { explicitText utf8String } -- noticeRef omitted. Only the SIZE
  // (1..200) FLOOR is enforced: an empty explicitText is a degenerate value no encoder can have produced,
  // while RFC 5280 sec. 4.2.1.4 directs certificate users to gracefully handle a notice ABOVE 200
  // characters, and draft-20 sec. 3.3's compact predicate is SIZE-silent -- so an over-long notice
  // transcodes rather than being refused.
  if (text.length === 0) throw _err("c509/bad-extensions", "a UserNotice explicitText must be non-empty (DisplayText SIZE 1..200)");
  return b.sequence([b.oid(oid.byName("unotice")), b.sequence([b.utf8(text)])]);
}
// One DER PolicyQualifierInfo node -> [ qidCbor, qtextCbor ], or null when not compact-representable: an
// unregistered qualifierId, a cps qualifier whose value is not a plain IA5String, or a UserNotice that is
// anything but SEQUENCE { explicitText utf8String } (a noticeRef, a non-UTF8String DisplayText arm, or more
// than the one explicitText child) -> whole-extension ~oid fallback.
function _qualifierFromDer(pq) {
  var qid = asn1.read.oid(pq.children[0]), qi = PQ_TO_INT[qid];
  if (qi === undefined) return null;
  var q = pq.children[1];
  if (qi === 1) {                                                      // CPSuri ::= IA5String
    if (q.tagClass !== "universal" || q.tagNumber !== asn1.TAGS.IA5_STRING) return null;
    var uri; try { uri = asn1.read.string(q); } catch (_e) { return null; }
    return [cbor.build.int(1n), cbor.build.textString(uri)];
  }
  // id-qt-unotice: SEQUENCE { explicitText utf8String } ONLY (noticeRef absent).
  if (q.tagClass !== "universal" || q.tagNumber !== asn1.TAGS.SEQUENCE || !q.children || q.children.length !== 1) return null;
  var dt = q.children[0];
  if (dt.tagClass !== "universal" || dt.tagNumber !== asn1.TAGS.UTF8_STRING) return null;
  var txt; try { txt = asn1.read.string(dt); } catch (_e2) { return null; }
  return [cbor.build.int(2n), cbor.build.textString(txt)];
}

// One CBOR DistributionPointName [ fullName, reasons, cRLIssuer ] -> one DER DistributionPoint SEQUENCE.
// distributionPoint [0] is EXPLICIT (it wraps the DistributionPointName CHOICE); fullName [0], reasons [1],
// cRLIssuer [2] are IMPLICIT (RFC 5280 sec. 4.2.1.13) -- mixing these is the classic byte-exactness trap.
function _dpToDer(dpNode, isNative) {
  if (dpNode.majorType !== 4 || !dpNode.children || dpNode.children.length !== 3) throw _err("c509/bad-extensions", "a DistributionPoint must be a CBOR [ fullName, reasons, cRLIssuer ] array");
  var fullName = dpNode.children[0], reasons = dpNode.children[1], crlIssuer = dpNode.children[2];
  var uris;
  if (fullName.majorType === 3) uris = [b.contextPrimitive(6, _ia5Bytes(fullName, 6))];
  else if (fullName.majorType === 4 && fullName.children) {
    if (fullName.children.length < 2) throw _err("c509/bad-extensions", "a DistributionPoint fullName array must hold 2 or more URIs (a single URI is a bare text; sec. 3.3)");
    uris = fullName.children.map(function (u) { return b.contextPrimitive(6, _ia5Bytes(u, 6)); });
  } else throw _err("c509/bad-extensions", "a DistributionPoint fullName must be a URI text or an array of URIs");
  var fields = [b.explicit(0, b.contextConstructed(0, Buffer.concat(uris)))];   // distributionPoint [0] EXPLICIT { fullName [0] IMPLICIT GeneralNames }
  if (!_isCborNull(reasons)) fields.push(_reasonsBitsToDer(Number(_cborUint(reasons, "cRLDistributionPoints reasons"))));
  if (!_isCborNull(crlIssuer)) fields.push(b.contextConstructed(2, b.explicit(4, _reconName(_name509(crlIssuer, true, isNative)))));   // cRLIssuer [2] { [4] directoryName }
  return b.sequence(fields);
}
// One DER DistributionPoint SEQUENCE -> the pieces for the CBOR DistributionPointName, or null when the DP
// is not compact-representable (no fullName, a non-URI fullName member, a nameRelativeToCRLIssuer, or a
// cRLIssuer that is not a single directoryName). oneUri is set when fullName is exactly one URI, so the
// whole-extension bare-text shortcut can fire.
function _dpFromDer(dp) {
  if (dp.tagClass !== "universal" || dp.tagNumber !== asn1.TAGS.SEQUENCE || !dp.children) return null;
  var fullNameUris = null, reasonsVal = null, crlIssuerCbor = null, lastTag = -1;
  for (var i = 0; i < dp.children.length; i++) {
    var f = dp.children[i];
    if (f.tagClass !== "context" || f.tagNumber <= lastTag) return null;   // DER: unique + ascending
    lastTag = f.tagNumber;
    if (f.tagNumber === 0) {
      if (!f.children || f.children.length !== 1) return null;
      var dpn = f.children[0];
      if (dpn.tagClass !== "context" || dpn.tagNumber !== 0 || !dpn.children || !dpn.children.length) return null;   // fullName [0] only
      fullNameUris = [];
      for (var j = 0; j < dpn.children.length; j++) {
        var mm = dpn.children[j];
        if (mm.tagClass !== "context" || mm.tagNumber !== 6) return null;   // non-URI fullName member
        fullNameUris.push(schema.walk(GN_LEAF, mm, NS).value);
      }
    } else if (f.tagNumber === 1) {
      var bs;
      try { bs = asn1.read.bitStringImplicit(f, 1); } catch (_e) { return null; }
      reasonsVal = _namedBitsFromContent(bs.bytes, bs.unusedBits);
      if (reasonsVal == null) return null;
    } else if (f.tagNumber === 2) {
      if (!f.children || f.children.length !== 1) return null;
      var ci = f.children[0];
      if (ci.tagClass !== "context" || ci.tagNumber !== 4 || !ci.children || ci.children.length !== 1) return null;   // one directoryName
      try { crlIssuerCbor = _encName(_c509NameFromDer(ci.children[0].bytes), true); } catch (_e2) { return null; }
    } else return null;
  }
  if (fullNameUris == null) return null;   // C509 requires the fullName distributionPoint
  var oneUri = fullNameUris.length === 1 ? fullNameUris[0] : null;
  var fnCbor = oneUri != null ? cbor.build.textString(oneUri) : cbor.build.array(fullNameUris.map(function (u) { return cbor.build.textString(u); }));
  return {
    triple: cbor.build.array([fnCbor, reasonsVal == null ? cbor.build.nullValue() : cbor.build.uint(BigInt(reasonsVal)), crlIssuerCbor == null ? cbor.build.nullValue() : crlIssuerCbor]),
    oneUri: oneUri, noReasons: reasonsVal == null, noIssuer: crlIssuerCbor == null,
  };
}

// Decode a compact extension value (a decoded CBOR node) to the DER extnValue inner content. Fails closed
// (c509/bad-extensions) on a CBOR shape the named extension does not define.
function _extValueToDer(name, node, isNative) {
  switch (name) {
    case "subjectKeyIdentifier":   // KeyIdentifier = bytes -> OCTET STRING(keyid)
      if (node.majorType !== 2) throw _err("c509/bad-extensions", "a subjectKeyIdentifier value must be a CBOR byte string");
      return b.octetString(node.content);
    case "keyUsage":               // uint -> KeyUsage BIT STRING (a value past the 9 named bits fails closed)
      return _reconKeyUsageBits(Number(_cborUint(node, "keyUsage")));
    case "basicConstraints": {     // int -> SEQUENCE { cA?, pathLen? }
      var iv = _cborIntVal(node, "basicConstraints");
      if (iv === -2n) return b.sequence([]);                                  // cA false (omitted)
      if (iv === -1n) return b.sequence([b.boolean(true)]);                   // cA true, no pathLen
      if (iv >= 0n) return b.sequence([b.boolean(true), b.integer(_boundCount(iv, "a basicConstraints pathLenConstraint"))]);   // cA true, pathLen (0..2^31-1, as the DER decoder bounds it)
      throw _err("c509/bad-extensions", "a basicConstraints int " + iv + " is outside the -2/-1/pathLen range");
    }
    case "authorityKeyIdentifier":   // keyId-only bytes, or [ keyId, authorityCertIssuer, serial ] (sec. 3.3)
      if (node.majorType === 2) return b.sequence([b.contextPrimitive(0, node.content)]);
      if (node.majorType === 4 && node.children && node.children.length === 3) {
        if (node.children[0].majorType !== 2) throw _err("c509/bad-extensions", "an authorityKeyIdentifier keyIdentifier must be a CBOR byte string");
        return b.sequence([
          b.contextPrimitive(0, node.children[0].content),                                           // keyIdentifier [0] IMPLICIT OCTET STRING
          b.contextConstructed(1, Buffer.concat(_generalNamesToDer(node.children[1], isNative))),       // authorityCertIssuer [1] IMPLICIT GeneralNames
          b.contextPrimitive(2, _serialIntContent(node.children[2])),                                // authorityCertSerialNumber [2] IMPLICIT INTEGER
        ]);
      }
      throw _err("c509/bad-extensions", "an authorityKeyIdentifier value must be a keyId byte string or the [ keyId, authorityCertIssuer, serial ] array (sec. 3.3)");
    case "extKeyUsage": {          // [2* KeyPurposeId] / KeyPurposeId -> SEQUENCE OF OID (draft-20 sec. 3.3)
      var items;
      if (node.majorType === 4) {
        items = node.children || [];
        if (items.length < 2) throw _err("c509/bad-extensions", "an extKeyUsage array must hold 2 or more KeyPurposeIds; a single purpose omits the array (draft-20 sec. 3.3)");
      } else {
        items = [node];
      }
      return b.sequence(items.map(function (it) { return b.oid(_ekuPurposeOid(it)); }));
    }
    case "inhibitAnyPolicy":       // uint -> INTEGER SkipCerts (0..2^31-1, as the DER decoder bounds it)
      return b.integer(_boundCount(_cborUint(node, "inhibitAnyPolicy"), "an inhibitAnyPolicy SkipCerts"));
    case "ocspNoCheck":            // null -> NULL
      if (node.majorType !== 7 || !(Buffer.isBuffer(node.bytes) && node.bytes.length === 1 && node.bytes[0] === 0xf6)) throw _err("c509/bad-extensions", "an ocspNoCheck value must be the CBOR simple value null");
      return b.nullValue();
    case "tlsFeature": {           // [uint ...] -> SEQUENCE OF INTEGER
      if (node.majorType !== 4) throw _err("c509/bad-extensions", "a tlsFeature value must be a CBOR array");
      return b.sequence((node.children || []).map(function (f) { return b.integer(_cborUint(f, "tlsFeature feature")); }));
    }
    case "subjectAltName":
    case "issuerAltName":          // SubjectAltName = GeneralNames / text (exactly one dNSName -> bare text)
      if (node.majorType === 3) return b.sequence([b.contextPrimitive(2, _ia5Bytes(node, 2))]);
      // sec. 3.3: "If subjectAltName contains exactly one dNSName, the array and the int are omitted and
      // extensionValue is the dNSName encoded as a CBOR text string." The array spelling of that one case
      // is a second encoding of the same extension value.
      if (!isNative && node.majorType === 4 && node.children && node.children.length === 2 &&
          node.children[0].majorType === 0 && Number(cbor.read.int(node.children[0])) === 2 &&
          node.children[1].majorType === 3) {
        throw _err("c509/bad-extensions", "a " + name + " holding exactly one dNSName must be encoded as a bare CBOR text string, not an array (draft sec. 3.3)");
      }
      return b.sequence(_generalNamesToDer(node, isNative));
    case "nameConstraints": {      // [ permittedSubtrees / null, excludedSubtrees / null ]
      if (node.majorType !== 4 || !node.children || node.children.length !== 2) throw _err("c509/bad-extensions", "a nameConstraints value must be a 2-element CBOR array [ permitted, excluded ] (sec. 3.3)");
      var ncFields = [];
      if (!_isCborNull(node.children[0])) ncFields.push(b.contextConstructed(0, _subtreesToDer(node.children[0], isNative)));   // permittedSubtrees [0]
      if (!_isCborNull(node.children[1])) ncFields.push(b.contextConstructed(1, _subtreesToDer(node.children[1], isNative)));   // excludedSubtrees [1]
      if (ncFields.length === 0) throw _err("c509/bad-extensions", "nameConstraints must contain permittedSubtrees or excludedSubtrees (RFC 5280 sec. 4.2.1.10)");
      return b.sequence(ncFields);
    }
    case "authorityInfoAccess":
    case "subjectInfoAccess": {    // [ accessMethod, uri, ... ] -> SEQUENCE OF AccessDescription { OID, [6] URI }
      if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "an " + name + " value must be a CBOR array");
      var aiaKids = node.children;
      if (aiaKids.length === 0 || aiaKids.length % 2 !== 0) throw _err("c509/bad-extensions", "an " + name + " array must be non-empty (accessMethod, uri) pairs (sec. 3.3)");
      var descs = [];
      for (var ai = 0; ai + 1 < aiaKids.length; ai += 2) descs.push(b.sequence([b.oid(_accessMethodOid(aiaKids[ai])), b.contextPrimitive(6, _ia5Bytes(aiaKids[ai + 1], 6))]));
      return b.sequence(descs);
    }
    case "cRLDistributionPoints":
    case "freshestCRL":            // [ + DistributionPointName ] / text (one DP, one-URI fullName -> bare text)
      if (node.majorType === 3) return b.sequence([b.sequence([b.explicit(0, b.contextConstructed(0, b.contextPrimitive(6, _ia5Bytes(node, 6))))])]);
      if (node.majorType !== 4 || !node.children || node.children.length < 1) throw _err("c509/bad-extensions", "a " + name + " value must be a CBOR array of DistributionPoints or a bare URI text (sec. 3.3)");
      return b.sequence(node.children.map(function (dp) { return _dpToDer(dp, isNative); }));
    // IPAddrBlocks (and its RFC 8360 v2 twin): a FLAT array of (AFI, SAFI, choice) triples --
    // IPAddressFamily is a parenthesized CDDL group, so it splices rather than nesting.
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
        // The families themselves are ordered and unique (RFC 3779 sec. 2.2.3.3), the same way the
        // addresses inside one are. Without this a value could name AFI 2 before AFI 1, or repeat a
        // family, and reconstruct a certificate an independent validator refuses.
        var famOct = Buffer.from(famBytes);
        if (prevFam !== null && _famOctCmp(prevFam, famOct) >= 0) {
          throw _err("c509/bad-extensions", "IPAddrBlocks address families must be unique and in ascending addressFamily order (RFC 3779 sec. 2.2.3.3)");
        }
        prevFam = famOct;
        var choice = ipKids[fi + 2], famFields = [b.octetString(famOct)];
        if (_isCborNull(choice)) {                          // null -> inherit
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
    // ASIdentifiers (and its v2 twin): null = inherit, else a flat array of uint / [min,max].
    // Only the asnum field is representable -- a present rdi has no compact form (sec. 3.3), so a
    // certificate carrying one rides the ~oid byte-string form and never reaches this arm.
    case "autonomousSysIds":
    case "autonomousSysIdsV2": {
      if (_isCborNull(node)) return b.sequence([b.explicit(0, b.nullValue())]);   // asnum inherit
      if (node.majorType !== 4 || !node.children || node.children.length === 0) {
        throw _err("c509/bad-extensions", "an ASIdentifiers value must be null (inherit) or a non-empty CBOR array");
      }
      // The deltas are `uint` in the draft's CDDL precisely because RFC 3779 sec. 3.2.3.4 sorts AS
      // ids by increasing value: a negative delta would walk the chain backwards. That section also
      // forbids a pair overlapping and requires a contiguous series to be one range -- the same
      // three rules the encode side applies, tracked here across members through `asPrevHigh`.
      // A negative delta needs no separate test: on the first entry it drives the absolute below
      // zero and the range guard refuses it, and on any later entry it lands at or below the
      // previous high, which the canonical test already refuses. A separate uint check would be a
      // branch nothing can reach.
      var asKids = node.children, asDers = [], asPrev = null, asPrevHigh = null;
      for (var asi2 = 0; asi2 < asKids.length; asi2++) {
        var it = asKids[asi2];
        if (it.majorType === 4) {                            // [min, max] -> ASRange
          if (!it.children || it.children.length !== 2) throw _err("c509/bad-extensions", "an ASIdentifiers range must be exactly [min, max]");
          var amin = _asDelta(it.children[0], asPrev), amax = _asDelta(it.children[1], amin);
          if (amax <= amin) throw _err("c509/bad-extensions", "an ASIdentifiers range must be ascending (RFC 3779 sec. 3.2.3.6)");
          if (asPrevHigh !== null && amin <= asPrevHigh + 1n) throw _err("c509/bad-extensions", "ASIdentifiers must be sorted, non-overlapping and maximally merged (RFC 3779 sec. 3.2.3.4)");
          asDers.push(b.sequence([b.integer(amin), b.integer(amax)]));
          asPrev = amax;
          asPrevHigh = amax;
        } else {                                             // uint -> ASId
          var aid = _asDelta(it, asPrev);
          if (asPrevHigh !== null && aid <= asPrevHigh + 1n) throw _err("c509/bad-extensions", "ASIdentifiers must be sorted, non-overlapping and maximally merged (RFC 3779 sec. 3.2.3.4)");
          asDers.push(b.integer(aid));
          asPrev = aid;
          asPrevHigh = aid;
        }
      }
      return b.sequence([b.explicit(0, b.sequence(asDers))]);
    }
    case "certificatePolicies": {   // [ pid, [ *(qid, qtext) ], ... ] -> SEQUENCE OF PolicyInformation
      if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "a certificatePolicies value must be a CBOR array");
      var cpKids = node.children;
      if (cpKids.length === 0 || cpKids.length % 2 !== 0) throw _err("c509/bad-extensions", "a certificatePolicies array must be non-empty (policyIdentifier, qualifiers) pairs (sec. 3.3)");
      var polInfos = [], seenPolicy = {};
      for (var cpi = 0; cpi + 1 < cpKids.length; cpi += 2) {
        var quals = cpKids[cpi + 1];
        if (quals.majorType !== 4 || !quals.children) throw _err("c509/bad-extensions", "a certificatePolicies qualifiers slot must be a CBOR array");
        // A policy OID MUST NOT appear more than once (RFC 5280 sec. 4.2.1.4); the toolkit's own DER decoder
        // rejects a duplicate (schema-pkix certExtensionDecoders), so reconstruct fails closed rather than
        // producing a certificatePolicies extension that decoder would reject.
        var policyOid = _policyIdToDerOid(cpKids[cpi]);
        if (seenPolicy[policyOid]) throw _err("c509/bad-extensions", "a certificatePolicies policy OID must not appear more than once (RFC 5280 sec. 4.2.1.4)");
        seenPolicy[policyOid] = true;
        var polFields = [b.oid(policyOid)];
        if (quals.children.length) {
          if (quals.children.length % 2 !== 0) throw _err("c509/bad-extensions", "a policyQualifiers array must be (policyQualifierId, qualifier) pairs");
          var pqDers = [];
          for (var qk = 0; qk + 1 < quals.children.length; qk += 2) pqDers.push(_qualifierToDer(quals.children[qk], quals.children[qk + 1]));
          polFields.push(b.sequence(pqDers));   // policyQualifiers SEQUENCE OF PolicyQualifierInfo
        }
        polInfos.push(b.sequence(polFields));
      }
      return b.sequence(polInfos);
    }
    case "policyMappings": {        // [ idp, sdp, idp, sdp, ... ] -> SEQUENCE OF SEQUENCE { OID, OID } (sec. 3.3)
      if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "a policyMappings value must be a CBOR array");
      var pmKids = node.children;
      if (pmKids.length === 0 || pmKids.length % 2 !== 0) throw _err("c509/bad-extensions", "a policyMappings array must be non-empty (issuerDomainPolicy, subjectDomainPolicy) pairs (sec. 3.3)");
      var maps = [];
      // each member is a CertPolicyId -- the same sec. 8.9 int/~oid policy space as certificatePolicies (an int
      // outside sec. 8.9 fails closed in _policyIdToDerOid). anyPolicy is accepted: RFC 5280 sec. 4.2.1.5's
      // "MUST NOT map to/from anyPolicy" is a generation rule the toolkit's own DER decoder does not reject.
      for (var mi = 0; mi + 1 < pmKids.length; mi += 2) maps.push(b.sequence([b.oid(_policyIdToDerOid(pmKids[mi])), b.oid(_policyIdToDerOid(pmKids[mi + 1]))]));
      return b.sequence(maps);
    }
    case "policyConstraints": {      // [ requireExplicitPolicy: uint/null, inhibitPolicyMapping: uint/null ] -> SEQUENCE { [0]?, [1]? }
      if (node.majorType !== 4 || !node.children || node.children.length !== 2) throw _err("c509/bad-extensions", "a policyConstraints value must be a 2-element CBOR array [ requireExplicitPolicy, inhibitPolicyMapping ] (sec. 3.3)");
      var pcFields = [], repN = node.children[0], ipmN = node.children[1];
      if (!_isCborNull(repN)) pcFields.push(b.implicit(0, b.integer(_boundCount(_cborUint(repN, "a policyConstraints requireExplicitPolicy"), "a policyConstraints requireExplicitPolicy"))));   // requireExplicitPolicy [0] IMPLICIT SkipCerts
      if (!_isCborNull(ipmN)) pcFields.push(b.implicit(1, b.integer(_boundCount(_cborUint(ipmN, "a policyConstraints inhibitPolicyMapping"), "a policyConstraints inhibitPolicyMapping"))));   // inhibitPolicyMapping [1] IMPLICIT SkipCerts
      // both-null is the empty-SEQUENCE case RFC 5280 sec. 4.2.1.11 forbids ("either ... MUST be present"); the
      // toolkit's own DER decoder rejects the empty PolicyConstraints, so the reconstruct fails closed too.
      if (pcFields.length === 0) throw _err("c509/bad-extensions", "policyConstraints must contain requireExplicitPolicy or inhibitPolicyMapping (RFC 5280 sec. 4.2.1.11)");
      return b.sequence(pcFields);   // positional slot -> tag makes [0] < [1] unique + ascending by construction
    }
    case "subjectDirectoryAttributes":   // [ type, values, type, values, ... ] -> SEQUENCE OF Attribute (sec. 3.3)
      return _sdaToDer(node, isNative);
    default:
      throw _err("c509/bad-extensions", "extension " + name + " has no compact value decoder");
  }
}

// Encode a DER extnValue inner content to its compact CBOR value bytes, or null when the DER is not the
// canonical form the compact encoding covers (the caller then emits the ~oid + byte-string fallback).
function _extValueFromDer(name, der) {
  var node;
  // A malformed DER extnValue (an ill-formed OID/INTEGER child, a truncated SEQUENCE) is simply not
  // compact-encodable; any decode/read fault surfaces as null so the caller emits the ~oid byte-string form.
  // Wrong-type children throw from asn1.read.* / cbor.build.uint (a negative value) and surface as the null
  // fallback; the encode-side round-trip guard is the final net, so only the structural dispatch is inline.
  try {
  node = asn1.decode(der);
  switch (name) {
    case "subjectKeyIdentifier":                                      // OCTET STRING(keyid) -> the bare key id
      return cbor.build.byteString(asn1.read.octetString(node));
    case "keyUsage": {                                               // BIT STRING -> uint
      var bits = _keyUsageBitsFromDer(der);
      return bits == null ? null : cbor.build.uint(BigInt(bits));
    }
    case "basicConstraints": {                                      // SEQUENCE { cA?, pathLen? } -> int
      var kids = node.children || [];
      if (kids.length === 0) return cbor.build.int(-2n);            // cA absent (a non-SEQUENCE falls back via the guard)
      if (asn1.read.boolean(kids[0]) !== true) return null;        // explicit cA=false is non-canonical -> fall back
      if (kids.length === 1) return cbor.build.int(-1n);
      if (kids.length !== 2) return null;
      return cbor.build.uint(asn1.read.integer(kids[1]));           // pathLen (>= 0; a negative INTEGER throws -> fall back)
    }
    case "authorityKeyIdentifier": {                               // SEQUENCE { [0] keyId } or the 3-tuple form
      var akids = node.children || [];
      if (akids.length === 1 && akids[0].tagClass === "context" && akids[0].tagNumber === 0) {
        return cbor.build.byteString(asn1.read.octetStringImplicit(akids[0], 0));   // keyId-only
      }
      // the [ keyIdentifier [0], authorityCertIssuer [1], authorityCertSerialNumber [2] ] all-three form.
      if (akids.length === 3 && akids[0].tagClass === "context" && akids[0].tagNumber === 0 &&
          akids[1].tagClass === "context" && akids[1].tagNumber === 1 && akids[1].children &&
          akids[2].tagClass === "context" && akids[2].tagNumber === 2) {
        var akiIssuer = _generalNamesFromDer(akids[1].children);
        if (akiIssuer == null) return null;
        var akiSerial = asn1.read.integerImplicit(akids[2], 2);
        if (akiSerial < 0n) return null;   // C509 authorityCertSerialNumber is a non-negative ~biguint
        return cbor.build.array([cbor.build.byteString(asn1.read.octetStringImplicit(akids[0], 0)), cbor.build.array(akiIssuer), cbor.build.byteString(_minBytes(akiSerial))]);
      }
      return null;   // keyId+serial-without-issuer / issuer-only / other combinations fall back to ~oid
    }
    case "extKeyUsage": {                                          // SEQUENCE OF OID -> [int/~oid ...] / single
      var purposes = node.children || [];
      if (!purposes.length) return null;
      var out = purposes.map(function (p) {
        var dotted = asn1.read.oid(p), pint = EKU_TO_INT[dotted];
        return pint !== undefined ? cbor.build.int(BigInt(pint)) : cbor.build.byteString(asn1.encodeOidContent(dotted));
      });
      return out.length === 1 ? out[0] : cbor.build.array(out);
    }
    case "inhibitAnyPolicy":                                       // INTEGER -> uint
      return cbor.build.uint(asn1.read.integer(node));
    case "ocspNoCheck":                                            // NULL -> null
      asn1.read.nullValue(node);
      return cbor.build.nullValue();
    case "tlsFeature":                                             // SEQUENCE OF INTEGER -> [uint ...]
      return cbor.build.array((node.children || []).map(function (f) { return cbor.build.uint(asn1.read.integer(f)); }));
    case "subjectAltName":
    case "issuerAltName": {                                        // SEQUENCE OF GeneralName -> flat array / dNSName text
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1) return null;
      var sanMembers = node.children;
      if (sanMembers.length === 1 && sanMembers[0].tagClass === "context" && sanMembers[0].tagNumber === 2) {
        return cbor.build.textString(schema.walk(GN_LEAF, sanMembers[0], NS).value);   // exactly one dNSName -> bare text
      }
      var sanItems = _generalNamesFromDer(sanMembers);
      return sanItems == null ? null : cbor.build.array(sanItems);
    }
    case "nameConstraints": {                                      // SEQUENCE { [0] permitted?, [1] excluded? } -> [perm, excl]
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1) return null;
      var permCbor = cbor.build.nullValue(), exclCbor = cbor.build.nullValue(), sawNc = false, ncLast = -1;
      for (var nci = 0; nci < node.children.length; nci++) {
        var ncf = node.children[nci];
        if (ncf.tagClass !== "context" || ncf.tagNumber <= ncLast) return null;   // DER: unique + ascending
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
    case "subjectInfoAccess": {                                    // SEQUENCE OF AccessDescription -> [method, uri, ...]
      var aiaDescs = node.children || [];
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || aiaDescs.length < 1) return null;
      var aiaOut = [];
      for (var adi = 0; adi < aiaDescs.length; adi++) {
        var d = aiaDescs[adi];
        if (d.tagClass !== "universal" || d.tagNumber !== asn1.TAGS.SEQUENCE || !d.children || d.children.length !== 2) return null;
        var aiaLoc = d.children[1];
        if (aiaLoc.tagClass !== "context" || aiaLoc.tagNumber !== 6) return null;   // the compact form is URI-only
        var methodDotted = asn1.read.oid(d.children[0]), mint = IA_TO_INT[methodDotted];
        aiaOut.push(mint !== undefined ? cbor.build.int(BigInt(mint)) : _oidCbor(methodDotted));
        aiaOut.push(cbor.build.textString(schema.walk(GN_LEAF, aiaLoc, NS).value));
      }
      return cbor.build.array(aiaOut);
    }
    case "cRLDistributionPoints":
    case "freshestCRL": {                                          // SEQUENCE OF DistributionPoint -> array / bare URI text
      var dps = node.children || [];
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || dps.length < 1) return null;
      var dpResults = [];
      for (var dpi = 0; dpi < dps.length; dpi++) { var dpr = _dpFromDer(dps[dpi]); if (dpr == null) return null; dpResults.push(dpr); }
      if (dpResults.length === 1 && dpResults[0].oneUri != null && dpResults[0].noReasons && dpResults[0].noIssuer) return cbor.build.textString(dpResults[0].oneUri);
      return cbor.build.array(dpResults.map(function (r) { return r.triple; }));
    }
    // IPAddrBlocks -> the flat (AFI, SAFI, choice) array. Any shape the compact form cannot
    // represent exactly returns null, so the extension rides the ~oid byte-string form intact.
    case "ipAddrBlocks":
    case "ipAddrBlocksV2": {
      if (!_isUniversal(node, asn1.TAGS.SEQUENCE) || !node.children || node.children.length === 0) return null;
      var ipOut = [], prevFamOct = null;
      for (var ifi = 0; ifi < node.children.length; ifi++) {
        var fam = node.children[ifi];
        if (!_isUniversal(fam, asn1.TAGS.SEQUENCE) || !fam.children || fam.children.length !== 2) return null;
        var famOct = asn1.read.octetString(fam.children[0]);
        if (famOct.length !== 2 && famOct.length !== 3) return null;   // OCTET STRING (SIZE (2..3))
        // Families ordered and unique (RFC 3779 sec. 2.2.3.3) -- the mirror of the decode side.
        if (prevFamOct !== null && _famOctCmp(prevFamOct, famOct) >= 0) return null;
        prevFamOct = famOct;
        var afiVal = (famOct[0] << 8) | famOct[1];
        ipOut.push(cbor.build.uint(BigInt(afiVal)));
        ipOut.push(famOct.length === 3 ? cbor.build.uint(BigInt(famOct[2])) : cbor.build.nullValue());
        var ch = fam.children[1];
        if (_isUniversal(ch, asn1.TAGS.NULL)) { ipOut.push(cbor.build.nullValue()); continue; }   // inherit
        var chOut = _ipChoiceFromDer(ch, afiVal);
        if (!chOut) return null;
        ipOut.push(chOut);
      }
      return cbor.build.array(ipOut);
    }
    // ASIdentifiers -> null (inherit) or the flat delta array. Only asnum is representable: a
    // present rdi has no compact form (sec. 3.3), so such a certificate returns null here.
    case "autonomousSysIds":
    case "autonomousSysIdsV2": {
      if (!_isUniversal(node, asn1.TAGS.SEQUENCE) || !node.children || node.children.length !== 1) return null;
      var asnum = node.children[0];
      if (asnum.tagClass !== "context" || asnum.tagNumber !== 0 || !asnum.children || asnum.children.length !== 1) return null;
      var inner = asnum.children[0];
      if (_isUniversal(inner, asn1.TAGS.NULL)) return cbor.build.nullValue();          // asnum inherit
      if (!_isUniversal(inner, asn1.TAGS.SEQUENCE) || !inner.children || inner.children.length === 0) return null;
      // RFC 3779 sec. 3.2.3.4 fixes the canonical form the same way sec. 2.2.3.6 does for addresses:
      // sorted by increasing value, no pair overlapping, and any contiguous series already merged
      // into one range. `asPrevHigh` carries the previous entry's upper bound so all three hold
      // ACROSS members -- checking only within a range would let a descending or adjacent pair
      // through. A list that is not canonical is left uncompacted with its bytes intact.
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
        if (asPrevHigh !== null && elLo <= asPrevHigh + 1n) return null;   // descending, overlapping, or contiguous
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
    case "certificatePolicies": {                                  // SEQUENCE OF PolicyInformation -> [ pid, [ *(qid, qtext) ], ... ]
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1) return null;
      var cpOut = [];
      for (var pli = 0; pli < node.children.length; pli++) {
        var pol = node.children[pli];
        if (pol.tagClass !== "universal" || pol.tagNumber !== asn1.TAGS.SEQUENCE || !pol.children || pol.children.length < 1 || pol.children.length > 2) return null;
        cpOut.push(_policyIdFromDer(asn1.read.oid(pol.children[0])));
        var qArr = [];
        if (pol.children.length === 2) {
          var qseq = pol.children[1];
          if (qseq.tagClass !== "universal" || qseq.tagNumber !== asn1.TAGS.SEQUENCE || !qseq.children || !qseq.children.length) return null;   // policyQualifiers SIZE 1..MAX
          for (var qj = 0; qj < qseq.children.length; qj++) {
            var pq = qseq.children[qj];
            if (pq.tagClass !== "universal" || pq.tagNumber !== asn1.TAGS.SEQUENCE || !pq.children || pq.children.length !== 2) return null;
            var qpair = _qualifierFromDer(pq);
            if (qpair == null) return null;                        // any non-cps/unotice qualifier -> whole-ext fallback
            qArr.push(qpair[0]); qArr.push(qpair[1]);
          }
        }
        cpOut.push(cbor.build.array(qArr));                        // empty [] when policyQualifiers absent
      }
      return cbor.build.array(cpOut);
    }
    case "policyMappings": {                                        // SEQUENCE OF SEQUENCE { OID, OID } -> [ idp, sdp, ... ]
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
    case "policyConstraints": {                                     // SEQUENCE { [0] rep?, [1] ipm? } -> [ rep/null, ipm/null ]
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1 || node.children.length > 2) return null;
      var repC = cbor.build.nullValue(), ipmC = cbor.build.nullValue(), pcLast = -1;
      for (var pci = 0; pci < node.children.length; pci++) {
        var f = node.children[pci];
        if (f.tagClass !== "context" || f.tagNumber <= pcLast) return null;   // DER: unique + ascending [0] < [1]
        pcLast = f.tagNumber;
        var sv = asn1.read.integerImplicit(f, f.tagNumber);
        if (sv < 0n) return null;                                             // SkipCerts (0..MAX) -- a negative is non-compact
        if (f.tagNumber === 0) repC = cbor.build.uint(sv);
        else if (f.tagNumber === 1) ipmC = cbor.build.uint(sv);
        else return null;
      }
      return cbor.build.array([repC, ipmC]);
    }
    case "subjectDirectoryAttributes":                              // SEQUENCE OF Attribute -> [ type, values, ... ]
      return _sdaFromDer(node);
    default:
      return null;
  }
  } catch (_e) {
    return null;
  }
}

// ---- subjectDirectoryAttributes compact value codec (draft-20 sec. 3.3 / 8.6 / 8.8, RFC 5280 sec. 4.2.1.8) ----
// SubjectDirectoryAttributes ::= SEQUENCE SIZE(1..MAX) OF Attribute ::= SEQUENCE { type, values SET OF value }.
// The compact form is a flat CBOR array [ type1, values1, ... ] where each values slot is ITSELF a non-empty
// CBOR array -- an Attribute's SET may hold more than one value, unlike a Name's single-value RDN. type is a
// sec. 8.6 registry int (the sign selects the string type) with text values, or an unwrapped ~oid with raw DER
// value bytes (an unregistered type stays compact via its own ~oid form, never dropping the whole extension).
// The extension-level _tryCompactExtValue round-trip guard is the byte-exactness net.

// A ~oid-form attributeValue must be exactly ONE non-empty, well-formed DER AttributeValue TLV. An empty byte
// string would build a SET OF SIZE 0 (RFC 5280 sec. 4.2.1.8 requires at least one value); a byte string carrying
// more than one TLV would fan one declared value into several SET members (draft-20 sec. 3.3: one `bytes` is one
// AttributeValue). There is no downstream DER decoder to catch either (SDA ships c509-only), so the reconstruct
// arm self-enforces the single-TLV shape rather than splice a degenerate or invalid Attribute.
// ---- the shared strict-DER gate for a raw-spliced ANY value --------------------------------------
// Several reconstruct sites splice CALLER/ATTACKER-supplied bytes into the rebuilt certificate verbatim (an
// AlgorithmIdentifier's `parameters`, a generic otherName's `value [0] EXPLICIT ANY`, a subjectDirectoryAttributes
// `~oid`-form AttributeValue). asn1.decode validates TLV FRAMING ONLY -- it rejects truncation, trailing bytes and
// non-minimal lengths, and enforces the DER primitive/constructed rules, but it does NOT check per-type CONTENT:
// it frames an empty INTEGER, the reserved end-of-contents tag 0, and an out-of-alphabet string quite happily.
// Splicing those produces a certificate an independent decoder refuses to load, and one this toolkit's OWN readers
// reject -- so every such site routes through the one gate below instead of a bare asn1.decode.

// Every universal PRIMITIVE tag whose content this toolkit can strictly validate, mapped to its reader. A
// universal primitive OUTSIDE this map has no strict content validator here, so it is REJECTED rather than
// spliced unchecked. The documented residual: a value whose type this toolkit cannot yet strictly validate is
// not compact-representable -- VideotexString / GraphicString / GeneralString / ObjectDescriptor / REAL (no
// content reader in this toolkit), and a fractional-seconds GeneralizedTime (the X.690 sec. 11.7 relaxation is deliberately scoped to the codec
// and RFC 3161 timestamping, and must not creep into a third consumer). On the ENCODE path such a value simply
// degrades to the byte-exact ~oid + byte-string form, losing nothing; on the DECODE path it is a fail-closed
// verdict rather than a guess.
var _ANY_VALUE_READERS = (function () {
  var m = {}, R = asn1.read, T = asn1.TAGS;
  m[T.BOOLEAN] = R.boolean; m[T.INTEGER] = R.integer; m[T.ENUMERATED] = R.enumerated;
  m[T.BIT_STRING] = R.bitString; m[T.OCTET_STRING] = R.octetString; m[T.NULL] = R.nullValue;
  m[T.OBJECT_IDENTIFIER] = R.oid; m[T.UTC_TIME] = R.time; m[T.GENERALIZED_TIME] = R.time;
  // NumericString reads through its OWN reader: it is not a DirectoryString type, and routing it through
  // read.string would fold it into the RFC 5280 sec. 7.1 name-comparison identity class (see asn1-der.js).
  m[T.NUMERIC_STRING] = R.numericString;
  [T.UTF8_STRING, T.PRINTABLE_STRING, T.IA5_STRING, T.TELETEX_STRING, T.VISIBLE_STRING, T.BMP_STRING, T.UNIVERSAL_STRING].forEach(function (t) { m[t] = R.string; });
  return m;
})();

// A universal SET's required member order depends on a type the ANY does not carry: X.690 sec. 11.6 orders a
// SET OF by the members' full encodings, while a structured SET is ordered by TAG (X.680 sec. 8.6) -- and the two
// differ whenever the constructed bit does (a SEQUENCE member, tag 16, sorts BEFORE a PrintableString, tag 19, by
// tag but AFTER it by octets). A structured SET cannot repeat a tag, so a repeated tag proves SET OF and the
// octet rule binds; with all-distinct tags either reading is possible, so accept a value that satisfies EITHER
// (rejecting only what is non-canonical under BOTH readings -- sound in both directions, never a guess).
var _TAG_CLASS_RANK = { universal: 0, application: 1, context: 2, private: 3 };
function _setOrderOk(kids) {
  var i, dup = false, seen = {};
  for (i = 0; i < kids.length; i++) {
    var key = kids[i].tagClass + ":" + kids[i].tagNumber;
    if (seen[key]) { dup = true; break; }
    seen[key] = true;
  }
  var octetAsc = true, tagAsc = true;
  for (i = 1; i < kids.length; i++) {
    if (Buffer.compare(kids[i - 1].bytes, kids[i].bytes) > 0) octetAsc = false;
    // Tag order ranks by CLASS first (universal < application < context < private, X.680 sec. 8.6), then by tag
    // number -- compare the class's NUMBER, never its name (the names do not sort in class order).
    var pc = _TAG_CLASS_RANK[kids[i - 1].tagClass], cc = _TAG_CLASS_RANK[kids[i].tagClass];
    if (pc !== cc ? pc > cc : kids[i - 1].tagNumber > kids[i].tagNumber) tagAsc = false;
  }
  return dup ? octetAsc : (octetAsc || tagAsc);
}

// Strict-validate a decoded DER element at ANY depth, in the caller's error domain. Rejects the reserved EOC tag
// 0; runs a universal primitive through its strict content reader (or rejects a type with none); recurses into a
// constructed element's children; and holds a universal SET to a canonical order. Only SEQUENCE and SET are
// accepted as universal CONSTRUCTED types -- an EXTERNAL / EMBEDDED PDV / CHARACTER STRING has mandatory
// components this gate cannot verify (the degenerate empty form is not a valid encoding of any of them), so it is
// refused for the same reason an unvalidatable primitive is. A NON-universal element (a legitimately context- or
// application-tagged ANY) passes on its framing, but its constructed children are still walked.
function _strictDerElement(node, code, label) {
  if (node.tagClass === "universal" && node.tagNumber === 0) throw _err(code, label + " must not use the reserved end-of-contents encoding (tag 0)");
  if (node.constructed) {
    if (node.tagClass === "universal" && node.tagNumber !== asn1.TAGS.SEQUENCE && node.tagNumber !== asn1.TAGS.SET) {
      throw _err(code, label + " of universal constructed type " + node.tagNumber + " has no strict DER structure validator here");
    }
    var kids = node.children;   // asn1.decode always sets a (possibly empty) children array on a constructed node
    for (var i = 0; i < kids.length; i++) _strictDerElement(kids[i], code, label);
    if (node.tagClass === "universal" && node.tagNumber === asn1.TAGS.SET && !_setOrderOk(kids)) {
      throw _err(code, label + " has a SET whose members are in no canonical DER order (X.690 sec. 11.6 / X.680 sec. 8.6)");
    }
    return;
  }
  if (node.tagClass === "universal") {
    // Validate-or-reject: a universal primitive with no strict content reader is NOT accepted on framing alone
    // (asn1.decode frames a malformed NumericString "12 01 40" happily), so the map is exhaustive by refusal.
    var reader = _ANY_VALUE_READERS[node.tagNumber];
    if (!reader) throw _err(code, label + " of universal type " + node.tagNumber + " has no strict DER content validator here");
    try { reader(node); } catch (e) { throw _err(code, label + " is not a valid DER element for its type", e); }
  }
}
// Raw ANY bytes about to be spliced verbatim must be exactly ONE non-empty, well-formed AND strictly-valid DER
// element: framing + no-trailing-data via asn1.decode, then content / structure / SET order via
// _strictDerElement, both reported in the CALLER's error domain. Returns the bytes so a call site can wrap a
// splice inline. Used by every reconstruct site that emits caller-supplied ANY bytes verbatim.
function _requireStrictDerTlv(content, code, label) {
  if (content.length === 0) throw _err(code, label + " must be a non-empty DER element");
  var node;
  try { node = asn1.decode(content); } catch (e) { throw _err(code, label + " must be exactly one well-formed DER element (no trailing data)", e); }
  _strictDerElement(node, code, label);
  return content;
}

// asn1.build.set SORTS its members, so handing it a non-canonically-ordered values list would SILENTLY rewrite
// the declared order -- many distinct C509 encodings would reconstruct one and the same certificate. Require the
// declared order to already BE canonical, so the compact form maps one-to-one onto the DER it rebuilds.
function _derSetInDeclaredOrder(vals) {
  for (var i = 1; i < vals.length; i++) {
    if (Buffer.compare(vals[i - 1], vals[i]) > 0) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes attributeValue list must be in DER ascending order (X.690 sec. 11.6)");
  }
  return b.set(vals);
}

// [ type1, values1, ... ] -> the DER SubjectDirectoryAttributes. A malformed native value fails closed
// (c509/bad-extensions); on the encode path the same throw is a round-trip mismatch -> whole-ext ~oid fallback.
function _sdaToDer(node, isNative) {
  if (node.majorType !== 4 || !node.children) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes value must be a CBOR array");
  var kids = node.children;
  if (kids.length === 0 || kids.length % 2 !== 0) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes array must be non-empty (attributeType, attributeValue) pairs (sec. 3.3)");
  var attrs = [];
  for (var i = 0; i + 1 < kids.length; i += 2) {
    var typeNode = kids[i], valuesNode = kids[i + 1];
    if (valuesNode.majorType !== 4 || !valuesNode.children || valuesNode.children.length < 1) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes attributeValue must be a non-empty CBOR array (SET OF, SIZE 1..MAX, RFC 5280 sec. 4.2.1.8)");
    var vals = [];
    if (typeNode.majorType === 0 || typeNode.majorType === 1) {          // int form: a sec. 8.6 registry alias, text values
      var ti = Number(cbor.read.int(typeNode));
      // draft sec. 3.1.4 applies to EVERY int in a natively signed certificate, not just the top-level Name's.
      if (isNative && ti < 0) throw _err("c509/bad-extensions", "a natively signed C509 subjectDirectoryAttributes attribute type integer must be non-negative (draft sec. 3.1.4), got " + ti);
      var tname = ATTR_BY_INT[Math.abs(ti)];
      if (tname === undefined) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes attribute type int " + ti + " has no C509 sec. 8.6 registry row");
      // countryName / serialNumber carry a CHARACTER restriction (draft sec. 3.1.4 "SHALL contain only
      // characters from the 74-character ASCII subset permitted by PrintableString"), NOT a sign override --
      // _reconAttrValue asserts the charset and honours the declared string type. Requiring the negative sign
      // here would also make these attributes unrepresentable in a NATIVE certificate, whose ints SHALL all be
      // non-negative (same sec.), so the rule is the charset, not the sign.
      for (var vi = 0; vi < valuesNode.children.length; vi++) {
        var vn = valuesNode.children[vi];
        if (vn.majorType !== 3) throw _err("c509/bad-extensions", "a subjectDirectoryAttributes int-form attribute value must be a CBOR text string (a non-string value requires the ~oid form)");
        // _reconAttrValue -> b.printable / b.utf8 throws only an Asn1Error for a value outside its string type's
        // alphabet (a printableString sign over non-PrintableString characters); remap it to this module's
        // domain so attacker-controlled native input fails closed as c509/bad-extensions, not a leaked asn1/*.
        try { vals.push(_reconAttrValue({ type: tname, value: cbor.read.textString(vn), printable: ti < 0 })); }
        catch (e) { throw _err("c509/bad-extensions", "a subjectDirectoryAttributes " + tname + " value is not valid for its string type", e); }
      }
      attrs.push(b.sequence([b.oid(oid.byName(tname)), _derSetInDeclaredOrder(vals)]));
    } else if (typeNode.majorType === 2) {                              // ~oid form: raw AttributeValue TLVs
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

// One DER Attribute's SET members -> the int-form { sign, values:[CBOR text] }, or null when the int form is
// not confidently byte-exact (an unregistered type, a non-utf8/printable value, or a SET mixing utf8String and
// printableString -- one sign cannot express it). A null routes that ONE attribute to the always-byte-exact
// ~oid + raw-bytes form (a still-compact sec. 3.3 SDA form); the extension round-trip guard is the ultimate net.
function _sdaTryIntForm(tint, name, valueNodes) {
  if (tint === undefined) return null;
  var i;
  // An IA5String-only attribute (emailAddress) rides its non-negative int with IA5String values -- its type,
  // not a sign, fixes the string type, so it is matched separately from the utf8/printable sign convention.
  if (name === "emailAddress") {
    var mails = [];
    for (i = 0; i < valueNodes.length; i++) {
      if (valueNodes[i].tagClass !== "universal" || valueNodes[i].tagNumber !== asn1.TAGS.IA5_STRING) return null;
      mails.push(cbor.build.textString(asn1.read.string(valueNodes[i])));
    }
    return { sign: 1, values: mails };
  }
  var sign = 0, out = [];   // sign: -1 printableString, +1 utf8String
  for (i = 0; i < valueNodes.length; i++) {
    var vn = valueNodes[i], s;
    if (vn.tagClass === "universal" && vn.tagNumber === asn1.TAGS.UTF8_STRING) s = 1;
    else if (vn.tagClass === "universal" && vn.tagNumber === asn1.TAGS.PRINTABLE_STRING) s = -1;
    else return null;                                  // any other value tag -> the ~oid form preserves it exactly
    if (sign === 0) sign = s;
    else if (sign !== s) return null;                  // a mixed utf8/printable SET -- the headline trap
    out.push(cbor.build.textString(asn1.read.string(vn)));
  }
  return { sign: sign, values: out };
}

// The DER SubjectDirectoryAttributes -> the flat compact CBOR array, or null (whole-ext ~oid fallback). Per
// attribute: the int form when the type is sec. 8.6-registered AND every value is a single-signed utf8/
// printable string, else the ~oid + raw-bytes form (always byte-exact).
function _sdaFromDer(node) {
  if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length < 1) return null;
  var out = [];
  for (var ai = 0; ai < node.children.length; ai++) {
    var attr = node.children[ai];
    if (attr.tagClass !== "universal" || attr.tagNumber !== asn1.TAGS.SEQUENCE || !attr.children || attr.children.length !== 2) return null;
    var setNode = attr.children[1];
    if (setNode.tagClass !== "universal" || setNode.tagNumber !== asn1.TAGS.SET || !setNode.children || setNode.children.length < 1) return null;   // SET OF, non-empty
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

// Encode-side guard: emit the compact value only when it decodes back to the EXACT DER extnValue, so a
// non-canonical or unrepresentable value can never produce a lossy compact form (it falls back to ~oid).
// A value _extValueFromDer produced but _extValueToDer cannot reconstruct -- an empty GeneralNames the DER
// builder rejects (an AKI authorityCertIssuer [1] with no members), or any future codec asymmetry -- is
// NOT compact-representable: the round-trip reconstruction throwing is treated identically to a byte
// mismatch, so encode() falls back to the ~oid form rather than raising on a certificate x509.parse
// accepts. The final encode() self-verify still gates byte-exactness end to end.
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

// extensions (sec. 3.1.10/sec. 3.3/sec. 8.8): [ * Extension ] | a single keyUsage int-shortcut.
function _extensions(node, isNative) {
  // The keyUsage int-shortcut (sec. 3.1.10): a bare int -> one keyUsage extension, criticality from the
  // sign, value = abs(int) (Appendix A.1.1: the single int 1 -> non-critical keyUsage digitalSignature).
  if (node.majorType === 0 || node.majorType === 1) {
    var iv = Number(cbor.read.int(node));
    return [{ name: "keyUsage", oid: oid.byName("keyUsage"), critical: iv < 0, keyUsageBits: Math.abs(iv) }];
  }
  if (node.majorType !== 4) throw _err("c509/bad-extensions", "C509 extensions must be an array or a keyUsage int shortcut");
  var out = [];
  var kids = node.children || [];
  // Each extension is an (extensionID, extensionValue) pair; an odd-length array is a dangling
  // extension identifier with no value -- reject rather than silently drop the trailing element.
  if (kids.length % 2 !== 0) throw _err("c509/bad-extensions", "a C509 extensions array must be id/value pairs (dangling extension identifier)");
  // sec. 3.1.10: "If the CBOR array contains exactly two ints and the absolute value of the first int is
  // 2 (corresponding to keyUsage), the CBOR array is omitted and the 'extensions' field is encoded as a
  // single CBOR int." The array spelling of that one case is a second encoding of the same extensions.
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
      // A registered extension with a compact value form (sec. 3.3) decodes its specific CBOR value to the
      // DER extnValue inner content. A registered extension WITHOUT one (subjectAltName, until the general-
      // name value codec lands) can only reconstruct a byte-string value (the raw DER extnValue); a
      // non-byte-string value there is an unsupported compact form and MUST fail closed -- a text/array value
      // is NOT raw DER, and copying its bytes would reconstruct a structurally invalid extension.
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
      // ~oid extension (sec. 3.1.10): the extnValue is a byte string -- BARE (non-critical) or wrapped in a
      // single-element array (critical). Validate the shape so a malformed value fails closed at decode.
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

// ---- type-3 DER reconstruction (byte-exact inversion; draft-20 sec. 3 / sec. 5) ----
// Type 3 is an INVERTIBLE transform: the reconstruction reproduces the ORIGINAL DER Certificate
// byte-for-byte (so the original signature verifies). A field outside the covered set fails closed
// (c509/non-invertible) -- never a partial or best-effort DER.

// A C509 tag-48 MAC (RFC 9542) reconstructs to the commonName EUI-64 string: a 6-byte value is a 48-bit
// MAC expanded to the EUI-64 HH-HH-HH-FF-FE-HH-HH-HH by inserting FF-FE; an 8-byte value is the EUI-64.
function _macToEui64String(buf) {
  var bytes = buf.length === 6 ? Buffer.concat([buf.subarray(0, 3), Buffer.from([0xff, 0xfe]), buf.subarray(3)]) : buf;
  var s = [];
  for (var i = 0; i < bytes.length; i++) { var h = bytes[i].toString(16).toUpperCase(); if (h.length < 2) h = "0" + h; s.push(h); }
  return s.join("-");
}

// One RDN attribute value -> its DER string. The C509 sign convention: a positive attribute int ->
// utf8String, a negative -> printableString; countryName / serialNumber are PrintableString-restricted.
function _reconAttrValue(rdn) {
  if (rdn.eui64) return b.utf8(_macToEui64String(rdn.eui64));   // the bare-form commonName MAC (a fixed 17 chars)
  var s = String(rdn.value);
  // The attribute's registered ASN.1 type carries a SIZE constraint as well as an alphabet, and a value outside
  // it is not a valid encoding of that type: every DirectoryString-valued attribute is SIZE (1..MAX) and
  // emailAddress is IA5String SIZE (1..MAX) (RFC 5280 App. A.1), so an empty value is never valid; countryName
  // "SHALL have length 2" (draft sec. 3.1.4, X.520 SIZE (2)). Enforced HERE, the single place the value is built
  // for its declared type, so the decode, reconstruct and subject-directory-attributes paths cannot disagree.
  if (s.length === 0) throw _err("c509/bad-name", "a " + rdn.type + " value must be non-empty (SIZE (1..MAX))");
  if (rdn.type === "countryName" && s.length !== 2) throw _err("c509/bad-name", "a countryName value must have length 2 (draft sec. 3.1.4)");
  // emailAddress is an IA5String-only attribute (draft sec. 3.1.4): its type, not the int's sign, fixes the
  // string type, so it reconstructs as an IA5String whichever way the non-negative int was written.
  if (rdn.type === "emailAddress") return b.ia5(s);
  // serialNumber / countryName carry a CHARACTER restriction, not a string-type override: draft sec. 3.1.4
  // "SHALL contain only characters from the 74-character ASCII subset permitted by PrintableString". Enforce
  // that on the CHARACTERS and still honour the sign for the string type -- coercing them to PrintableString
  // regardless of sign would make the +N and -N encodings of one value reconstruct IDENTICAL DER, so a single
  // X.509 signature would cover two distinct C509 encodings (a malleability window in the type-3 transform).
  // b.printable IS the PrintableString charset authority -- run it for the assert even when the sign selects
  // utf8String, so the restriction binds on the characters without overriding the declared string type.
  if (!rdn.printable && (rdn.type === "countryName" || rdn.type === "serialNumber")) b.printable(s);
  return rdn.printable ? b.printable(s) : b.utf8(s);
}

// A Name -> the DER RDNSequence (SEQUENCE OF SET OF SEQUENCE{ type, value }); one attribute per RDN.
function _reconName(name) {
  return b.sequence(name.rdns.map(function (rdn) {
    return b.set([b.sequence([b.oid(oid.byName(rdn.type)), _reconAttrValue(rdn)])]);
  }));
}

// A validity instant -> UTCTime (RFC 5280 sec. 4.1.2.5: year < 2050) or GeneralizedTime. A null notAfter
// -> the no-well-defined-expiry sentinel 99991231235959Z.
function _reconTime(date) {
  if (date === null) return b.generalizedTime(new Date(Date.UTC(9999, 11, 31, 23, 59, 59)));
  return date.getUTCFullYear() < 2050 ? b.utcTime(date) : b.generalizedTime(date);
}

// subjectPublicKeyInfo -> DER. EC: rebuild AlgorithmIdentifier{ ecPublicKey, namedCurve } + the BIT
// STRING point, de-compressing a C509 0xFE/0xFD marker back to the original uncompressed 0x04||X||Y.
function _reconSpki(spkAlg, keyBytes, rsaKey) {
  if (spkAlg.name === "ecPublicKey") {
    var fieldSize = EC_FIELD_BYTES[spkAlg.curve];
    if (!fieldSize) throw _err("c509/non-invertible", "unsupported EC curve " + spkAlg.curve);
    if (!keyBytes || keyBytes.length === 0) throw _err("c509/non-invertible", "the EC subjectPublicKey byte string is empty");
    var head = keyBytes[0], point;
    // The point length must match the curve field size for its encoding -- an uncompressed 0x04 point is
    // 1 + 2*fieldSize, a compressed 0x02/0x03/0xFE/0xFD point is 1 + fieldSize -- so a truncated / padded
    // point cannot be re-emitted as a valid (or byte-exact) SubjectPublicKeyInfo.
    if (head === 0x04) {
      if (keyBytes.length !== 1 + 2 * fieldSize) throw _err("c509/non-invertible", "uncompressed EC point length " + keyBytes.length + " does not match " + spkAlg.curve);
      point = keyBytes;
    } else if (head === 0x02 || head === 0x03) {
      if (keyBytes.length !== 1 + fieldSize) throw _err("c509/non-invertible", "compressed EC point length " + keyBytes.length + " does not match " + spkAlg.curve);
      point = keyBytes;
    } else if (head === 0xfe || head === 0xfd) {                                // C509 marker -> de-compress
      if (keyBytes.length !== 1 + fieldSize) throw _err("c509/non-invertible", "C509-marked EC point length " + keyBytes.length + " does not match " + spkAlg.curve);
      var sec1 = Buffer.concat([Buffer.from([head === 0xfe ? 0x02 : 0x03]), keyBytes.subarray(1)]);
      point = webcrypto.decompressEcPoint(sec1, spkAlg.curve, _err, "c509/non-invertible");
    } else throw _err("c509/non-invertible", "unrecognized EC point encoding 0x" + head.toString(16));
    return b.sequence([b.sequence([b.oid(oid.byName("ecPublicKey")), b.oid(oid.byName(spkAlg.curve))]), b.bitString(point, 0)]);
  }
  if (spkAlg.name === "rsaEncryption") {
    // draft-20 sec. 3.2.1: the RSA key is [modulus, exponent] ~biguints, OR just the modulus ~biguint
    // when the exponent is 65537 (parse has already resolved rsaKey to { modulus, exponent }). Reconstruct
    // AlgorithmIdentifier{ rsaEncryption, NULL } + the BIT STRING wrapping RSAPublicKey ::= SEQUENCE {
    // modulus INTEGER, publicExponent INTEGER }.
    var rsaPk = b.sequence([b.integer(rsaKey.modulus), b.integer(rsaKey.exponent)]);
    return b.sequence([b.sequence([b.oid(oid.byName("rsaEncryption")), b.nullValue()]), b.bitString(rsaPk, 0)]);
  }
  throw _err("c509/non-invertible", "subjectPublicKey algorithm " + spkAlg.name + " is not in the type-3 reconstruction covered set");
}

// The keyUsage int value -> the DER KeyUsage BIT STRING (RFC 5280 sec. 4.2.1.3): bit i of the value ->
// BIT STRING named bit i (bit 0 = digitalSignature = the MSB of the first content octet). Composes the
// shared named-bit content builder (also used by the cRLDistributionPoints reasons transform); a
// non-positive, non-integer, or > 0x1FF value is not a valid KeyUsage and fails closed.
function _reconKeyUsageBits(value) {
  var c = _namedBitsToContent(value);
  if (c == null) throw _err("c509/non-invertible", "a keyUsage value must be a positive integer within the 9 defined bits");
  return b.bitString(c.bytes, c.unusedBits);
}

// extensions -> the [3] EXPLICIT SEQUENCE OF Extension DER.
function _reconExtensions(exts) {
  var items = exts.map(function (ext) {
    var extnValue;
    if (ext.name === "keyUsage" && typeof ext.keyUsageBits === "number") extnValue = _reconKeyUsageBits(ext.keyUsageBits);
    else if (Buffer.isBuffer(ext.value)) extnValue = ext.value;   // raw DER extnValue bytes
    else throw _err("c509/non-invertible", "extension " + ext.name + " has no reconstructable value in the covered set");
    var fields = [b.oid(ext.oid || oid.byName(ext.name))];
    if (ext.critical) fields.push(b.boolean(true));
    fields.push(b.octetString(extnValue));
    return b.sequence(fields);
  });
  return b.explicit(3, b.sequence(items));
}

// An AlgorithmIdentifier -> DER SEQUENCE { algorithm OID, parameters? }. A C509 [~oid, params]
// algorithm carries its DER parameters bytes, which MUST be reproduced so the reconstruction inverts
// byte-exact (silently dropping them would change the signed bytes); the int / ~oid forms carry no
// parameters (ecdsaWith* and the like omit them).
function _reconAlgId(alg) {
  var fields = [b.oid(alg.oid)];
  if (alg.parameters && alg.parameters.length) {
    // AlgorithmIdentifier.parameters is ANY, spliced verbatim -- so it gets the SAME strict gate as every other
    // raw-ANY splice, not just a framing check. Framing alone admits an empty INTEGER / reserved tag 0 / a
    // non-minimal INTEGER, each of which reconstructs an AlgorithmIdentifier that an independent X.509 decoder
    // refuses to load and that this toolkit's own readers reject.
    fields.push(b.raw(_requireStrictDerTlv(alg.parameters, "c509/non-invertible", "algorithm parameters")));
  }
  return b.sequence(fields);
}

// The full type-3 -> DER Certificate reconstruction, byte-for-byte.
function _reconstructDer(r, sigNode) {
  var sigAlgSeq = _reconAlgId(r.signatureAlgorithm);
  var subjectName = _reconName(r.subject);
  var spelledIssuer = r.issuer && r.issuer.rdns ? _reconName(r.issuer) : null;
  // sec. 3.1.4: an issuer identical to the subject MUST be the CBOR simple value null. Spelling it
  // out instead rebuilds the same DER, so one certificate would have two C509 encodings and the one
  // X.509 signature over that DER would cover both.
  if (spelledIssuer !== null && spelledIssuer.equals(subjectName)) {
    throw _err("c509/bad-name", "an issuer identical to the subject must be encoded as the CBOR simple value null (draft sec. 3.1.4)");
  }
  var tbsFields = [
    b.explicit(0, b.integer(2n)),                                  // version v3 (type-3 is X.509 v3)
    b.integer(r.serialNumber),
    sigAlgSeq,
    spelledIssuer === null ? subjectName : spelledIssuer,          // null issuer -> issuer == subject
    b.sequence([_reconTime(r.validity.notBefore), _reconTime(r.validity.notAfter)]),
    subjectName,
    _reconSpki(r.subjectPublicKeyAlgorithm, r.subjectPublicKey, r.rsaPublicKey),
  ];
  // RFC 5280 sec. 4.1: the [3] extensions field is OPTIONAL and, when present, SHALL contain at least one
  // extension -- an empty C509 extensions array reconstructs to an OMITTED field, not an empty SEQUENCE.
  if (r.extensions.length) tbsFields.push(_reconExtensions(r.extensions));
  var tbs = b.sequence(tbsFields);
  // The signature is re-wrapped as a DER ECDSA-Sig-Value from the fixed-width r||s, so only an ECDSA
  // signature algorithm is in the type-3 reconstruction covered set (an RSA/EdDSA signature is raw bytes,
  // not r||s -- rejected rather than mis-wrapped). A wrong-length r||s surfaces the caller's typed code.
  if (!/^ecdsa/i.test(r.signatureAlgorithm.name || "")) {
    throw _err("c509/non-invertible", "type-3 signature reconstruction covers only ECDSA; got " + r.signatureAlgorithm.name);
  }
  // The fixed-width r||s must split at a real curve field width -- P-256/384/521 = 64/96/132 bytes
  // (RFC 9053 sec. 2.1). A width that is not 2x a supported field size is not a valid ECDSA signature and
  // cannot be re-wrapped byte-exact; surface the caller's typed code rather than split at a bogus offset.
  var coordLen = r.signatureValue.length / 2;
  if (coordLen !== 32 && coordLen !== 48 && coordLen !== 66) {
    throw _err("c509/bad-signature", "the type-3 ECDSA signature width " + r.signatureValue.length + " is not a valid fixed-width r||s (expected 64/96/132 for P-256/384/521)");
  }
  var sigValue = validator.sig.rawToEcdsaDer(r.signatureValue, coordLen);
  return b.sequence([tbs, sigAlgSeq, b.bitString(sigValue, 0)]);
}

// ---- the parse ----

/**
 * @primitive  pki.schema.c509.parse
 * @signature  pki.schema.c509.parse(bytes) -> { certificateType, serialNumber, serialNumberHex, ... }
 * @since      0.2.30
 * @status     experimental
 * @spec       draft-ietf-cose-cbor-encoded-cert, RFC 8949, RFC 9090, RFC 5280
 *
 * Decode a C509 certificate (draft-ietf-cose-cbor-encoded-cert) from its deterministic-CBOR bytes.
 * Returns the decoded fields (c509CertificateType 2 native or 3 re-encoded); a malformed shape throws a
 * typed C509Error carrying the inner cbor/asn1 fault as .cause. It decodes CBOR, not DER, so it is
 * reached by an explicit call and is not auto-routed by pki.schema.parse. The type-2 signedData and the
 * raw signature are surfaced RAW (a native verifier hashes them without re-serialization).
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

  // The type slot must be a CBOR integer -- guard the major type here so a text/array/byte-string field 0 fails
  // in this module's domain rather than leaking cbor.read.int's cbor/unexpected-major fault to the caller.
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
  // A CBOR-null issuer means issuer == subject (self-signed), so the EFFECTIVE issuer is the subject -- and it
  // must still satisfy RFC 5280 sec. 4.1.2.4. Checking only the array form would let the null form rebuild the
  // very empty issuer the array form is refused for.
  if (issuer === null && (!subject || !subject.rdns || subject.rdns.length === 0)) {
    throw _err("c509/bad-name", "a self-signed C509 (issuer == subject) requires a non-empty subject, since it is also the issuer (RFC 5280 sec. 4.1.2.4)");
  }
  var spkAlg = _algorithm(f[7], PK_ALG_BY_INT, "c509/unknown-algorithm", "subjectPublicKeyAlgorithm");
  var subjectPublicKey = null, rsaKey = null;
  if (spkAlg.name === "rsaEncryption") {
    // draft-20 sec. 3.2.1: [modulus, exponent] ~biguints, OR a bare modulus ~biguint (exponent = 65537).
    if (f[8].majorType === 2) rsaKey = { modulus: _biguint(f[8], "c509/bad-spki", "RSA modulus"), exponent: 65537n };
    else if (f[8].majorType === 4 && f[8].children && f[8].children.length === 2) {
      rsaKey = { modulus: _biguint(f[8].children[0], "c509/bad-spki", "RSA modulus"), exponent: _biguint(f[8].children[1], "c509/bad-spki", "RSA exponent") };
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

  // The RAW bytes of CBOR-array elements 0..9 (NOT the outer array head, NOT the signature) -- a zero-copy
  // subarray. For a native (type-2) certificate this is the signed region a verifier hashes (sec. 3.1.12);
  // surfaced as `_fieldBytes` for BOTH types so encode() re-emits a parsed certificate byte-for-byte (a
  // re-derivation from the decoded values could differ on a canonical-equivalent form, breaking a type-2
  // signature or a type-3 DER reconstruction). `signedData` keeps its type-2-only signed-region meaning.
  // From the DECODED root's own bytes (root.bytes == array head + all 11 elements), not offset arithmetic
  // on `input` (which breaks when input is a Uint8Array the codec normalized to a different buffer): the
  // fields region is root.bytes minus the 1-byte array(11) head and minus the trailing signatureValue.
  result._fieldBytes = root.bytes.subarray(1, root.bytes.length - f[10].bytes.length);
  if (type === 2) result.signedData = result._fieldBytes;

  // Type-3 is an invertible re-encoding of a DER X.509 certificate: reconstruct the original DER
  // byte-for-byte so the original signature verifies and x509.parse recovers the certificate.
  if (type === 3) result.reconstructedDer = _reconstructDer(result, f[10]);

  return result;
}

// matches(node) -- a STRUCTURAL probe over a DECODED CBOR node: an array of 11 whose first element is
// a major-type-0/1 int equal to 2 or 3. Not wired into the DER orchestrator (C509 is CBOR, not DER).
function matches(node) {
  return !!node && node.majorType === 4 && !!node.children && node.children.length === 11 &&
    (node.children[0].majorType === 0 || node.children[0].majorType === 1) &&
    (Number(node.children[0].argument) === 2 || Number(node.children[0].argument) === 3);
}

// ---- the encode (the producing side; draft-20 sec. 3) -----------------------
// The byte-exact inverse of parse/reconstruct: emit the 11-element deterministic-CBOR C509 array via the
// cbor.build.* emitter. Two inputs, dispatched structurally: a DER X.509 certificate (Buffer/PEM) -> the
// FLAGSHIP type-3 forward transform (parse(encode(der)).reconstructedDer == der, so the original signature
// verifies); a c509.parse result -> re-emit its native array. Signing-free (mirrors ct.encodeSctList).

// The registry INVERSE tables (name -> canonical int). The RDN-attribute and extension inverses are
// DERIVED from the *_BY_INT decode tables so the two directions cannot drift apart (a hand-kept inverse
// once carried a stale pre-draft-20 numbering); the extension inverse keeps only the compact-encodable
// rows, so a registered extension without a value codec (subjectAltName) routes to the ~oid form.
var SIG_ALG_TO_INT = { ecdsaWithSHA256: 0, ecdsaWithSHA384: 1, ecdsaWithSHA512: 2 };
var PK_ALG_TO_INT = { rsaEncryption: 0, "ecPublicKey|prime256v1": 1, "ecPublicKey|secp384r1": 2, "ecPublicKey|secp521r1": 3 };
var ATTR_TO_INT = {};
Object.keys(ATTR_BY_INT).forEach(function (k) { ATTR_TO_INT[ATTR_BY_INT[k]] = Number(k); });
var EXT_TO_INT = {};
Object.keys(EXT_BY_INT).forEach(function (k) { if (EXT_COMPACT[EXT_BY_INT[k]]) EXT_TO_INT[EXT_BY_INT[k]] = Number(k); });

// A non-negative BigInt -> its minimal big-endian ~biguint bytes (the leading 0x00 sign octet omitted).
function _minBytes(n) {
  if (n < 0n) throw _err("c509/bad-serial", "a ~biguint value must be non-negative");
  if (n === 0n) return Buffer.alloc(0);
  var hex = n.toString(16); if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}
// A C509 AlgorithmIdentifier -> int (registry) | ~oid (bare bytes) | [~oid, params]. `key` selects the row.
// The bare-~oid arm is unreachable from either call site as the type-3 encoder stands, and is kept as
// the honest fallback rather than an assumption: the signature slot refuses every non-ECDSA algorithm
// before this runs, and every curve the subjectPublicKey slot accepts (prime256v1 / secp384r1 /
// secp521r1) carries an ecPublicKey registry row. Adding a curve without its row would reach it.
function _encAlgorithm(alg, toInt, key) {
  var i = toInt[key];
  if (i !== undefined && !(alg.parameters && alg.parameters.length)) return cbor.build.int(BigInt(i));
  var oidBytes = cbor.build.byteString(asn1.encodeOidContent(alg.oid));   // ~oid: bare BER OID content
  if (alg.parameters && alg.parameters.length) return cbor.build.array([oidBytes, cbor.build.byteString(alg.parameters)]);
  return oidBytes;
}
// A SpecialText attribute value -> CBOR, walking the sec. 3.1.4 cascade: an EUI-64 is a tag-48 MAC
// address, a text string of even length >= 2 drawn only from '0'-'9'/'a'-'f' is a byte string, and
// anything else is a text string. The decoder holds an incoming certificate to exactly this cascade,
// so the encoder walks it too -- a spelling chosen here that the decoder refuses would make this
// encoder emit certificates its own parser rejects.
function _encSpecialText(rdn) {
  if (rdn.eui64) return cbor.build.tag(48, cbor.build.byteString(rdn.eui64));
  var v = String(rdn.value);
  if (v.length >= 2 && _HEX_OPTIMIZED.test(v)) return cbor.build.byteString(Buffer.from(v, "hex"));
  return cbor.build.textString(v);
}
// A Name -> CBOR: null (issuer only) | a bare SpecialText single utf8 commonName | an array of RDN pairs.
function _encName(name, isSubject) {
  if (name === null || name === undefined) {
    if (!isSubject) return cbor.build.nullValue();   // issuer == subject (self-signed)
    throw _err("c509/bad-name", "the subject Name is required");
  }
  var rdns = name.rdns || [];
  if (rdns.length === 1 && rdns[0].type === "commonName" && !rdns[0].printable) return _encSpecialText(rdns[0]);
  var items = [];
  rdns.forEach(function (rdn) {
    var ai = ATTR_TO_INT[rdn.type];
    if (ai === undefined) throw _err("c509/bad-name", "attribute type " + rdn.type + " has no C509 registry int");
    items.push(cbor.build.int(BigInt(rdn.printable ? -ai : ai)));   // sign selects printableString
    items.push(_encSpecialText(rdn));
  });
  return cbor.build.array(items);
}
// subjectPublicKey -> CBOR: EC point byte string, or an RSA ~biguint modulus ([modulus, exponent] when e != 65537).
function _encSpk(r) {
  if (r.rsaPublicKey) {
    var mod = cbor.build.byteString(_minBytes(r.rsaPublicKey.modulus));
    if (r.rsaPublicKey.exponent === 65537n) return mod;
    return cbor.build.array([mod, cbor.build.byteString(_minBytes(r.rsaPublicKey.exponent))]);
  }
  if (!Buffer.isBuffer(r.subjectPublicKey)) throw _err("c509/bad-spki", "the subjectPublicKey bytes are missing");
  return cbor.build.byteString(r.subjectPublicKey);
}
// extensions -> CBOR: the keyUsage int-shortcut (a lone keyUsage), else an array of [extID, extValue] pairs.
function _encExtensions(exts) {
  if (exts.length === 1 && exts[0].name === "keyUsage" && typeof exts[0].keyUsageBits === "number") {
    return cbor.build.int(BigInt(exts[0].critical ? -exts[0].keyUsageBits : exts[0].keyUsageBits));
  }
  var items = [];
  exts.forEach(function (ext) {
    var ei = EXT_TO_INT[ext.name];
    // A registered extension with a compact value form emits int extID + the specific CBOR value, but
    // only when that value inverts to the EXACT DER extnValue (the round-trip guard); otherwise it falls
    // through to the conformant ~oid + byte-string form (sec. 3.7) -- never a lossy compact encoding.
    var compact = (ei !== undefined && Buffer.isBuffer(ext.value)) ? _tryCompactExtValue(ext.name, ext.value) : null;
    if (compact != null) {
      items.push(cbor.build.int(BigInt(ext.critical ? -ei : ei)));
      items.push(compact);
    } else {
      items.push(cbor.build.byteString(asn1.encodeOidContent(ext.oid || oid.byName(ext.name))));   // ~oid extension id
      if (!Buffer.isBuffer(ext.value)) throw _err("c509/non-invertible", "extension " + (ext.oid || ext.name) + " has no byte-string value to encode");
      var bs = cbor.build.byteString(ext.value);
      items.push(ext.critical ? cbor.build.array([bs]) : bs);              // critical ~oid value wraps in a 1-element array
    }
  });
  return cbor.build.array(items);
}
// forward-declared below; the DER X.509 -> type-3 C509 structured result.
var _derToType3;
// A hand-built (no _fieldBytes) result must carry the structured fields the encode below reads; a missing or
// wrong-typed field fails closed with a typed verdict rather than a raw property-access crash.
function _requireResultShape(r) {
  if (r.certificateType == null) throw _err("c509/bad-input", "a C509 result must carry certificateType");
  if (r.serialNumber == null && r.serialNumberHex == null) throw _err("c509/bad-input", "a C509 result must carry serialNumber or serialNumberHex");
  if (!r.signatureAlgorithm || typeof r.signatureAlgorithm.name !== "string") throw _err("c509/bad-input", "a C509 result must carry signatureAlgorithm.name");
  if (!r.subjectPublicKeyAlgorithm || typeof r.subjectPublicKeyAlgorithm.name !== "string") throw _err("c509/bad-input", "a C509 result must carry subjectPublicKeyAlgorithm.name");
  if (!r.validity || !(r.validity.notBefore instanceof Date) || (r.validity.notAfter !== null && !(r.validity.notAfter instanceof Date))) throw _err("c509/bad-input", "a C509 result must carry validity.notBefore (Date) and notAfter (Date or null)");
  if (!Array.isArray(r.extensions)) throw _err("c509/bad-input", "a C509 result must carry an extensions array");
  if (!Buffer.isBuffer(r.signatureValue)) throw _err("c509/bad-input", "a C509 result must carry a Buffer signatureValue");
}
// A validity Date -> its C509 ~time (a non-negative CBOR epoch uint). A pre-epoch date cannot be
// represented (the parser accepts only an unwrapped major-type-0 integer) and fails closed here.
function _validityUint(date, label) {
  var secs = Math.floor(date.getTime() / 1000);
  if (!isFinite(secs) || secs < 0) throw _err("c509/bad-validity", label + " is before the Unix epoch or not a valid date; C509 ~time is a non-negative CBOR epoch");
  return cbor.build.uint(BigInt(secs));
}
// A structured C509 result -> the 11-element deterministic-CBOR array.
function _encodeC509Array(r) {
  // Re-emit a PARSED certificate's raw fields (elements 0..9) VERBATIM -- re-deriving from the decoded
  // values could differ on a canonical-equivalent form (a byte-string attribute value, a registry alias)
  // and break a type-2 native signature (which covers these bytes) or a type-3 DER reconstruction (which
  // depends on the field values). Both types preserve the exact bytes; only a hand-built result (no
  // _fieldBytes) re-derives from the structured values below.
  if (Buffer.isBuffer(r._fieldBytes)) {
    if (!Buffer.isBuffer(r.signatureValue)) throw _err("c509/bad-input", "a re-emitted certificate must carry a Buffer signatureValue");
    var out = Buffer.concat([Buffer.from([0x8b]), r._fieldBytes, cbor.build.byteString(r.signatureValue)]);   // array(11) head + fields 0..9 + signatureValue
    parse(out);   // fail closed: a caller-mutated _fieldBytes must still re-parse as a valid C509, else parse throws a typed c509/* verdict
    return out;
  }
  _requireResultShape(r);
  var pkKey = r.subjectPublicKeyAlgorithm.curve ? r.subjectPublicKeyAlgorithm.name + "|" + r.subjectPublicKeyAlgorithm.curve : r.subjectPublicKeyAlgorithm.name;
  var arr = cbor.build.array([
    cbor.build.int(BigInt(r.certificateType)),
    cbor.build.byteString(r.serialNumberHex != null ? Buffer.from(r.serialNumberHex, "hex") : _minBytes(r.serialNumber)),
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
  parse(arr);   // fail closed: a hand-built result must re-parse as a valid C509 (as the verbatim path checks), else parse throws a typed c509/* verdict
  return arr;
}

/**
 * @primitive  pki.schema.c509.encode
 * @signature  pki.schema.c509.encode(input[, opts]) -> Buffer
 * @since      0.3.4
 * @status     experimental
 * @spec       draft-ietf-cose-cbor-encoded-cert, RFC 8949, RFC 9090
 * @related    pki.schema.c509.parse
 *
 * Encode a C509 certificate to its deterministic-CBOR bytes -- the producing-side inverse of
 * `pki.schema.c509.parse`. `input` is either a DER X.509 v3 certificate (a Buffer or PEM string), which is
 * forward-transformed to a **type-3** C509 (a compact CBOR re-encoding whose signature is copied from the
 * source and re-expressed as a fixed-width r||s, so `parse(encode(der)).reconstructedDer` reproduces the
 * original DER byte for byte and the original signature still verifies), or a `pki.schema.c509.parse`
 * result object, which is re-emitted to its native deterministic-CBOR array. The emission is canonical
 * deterministic CBOR (RFC 8949 sec. 4.2) -- shortest-form heads, definite lengths, sorted map keys, and the
 * registry integer shorthand for every registered algorithm / attribute / extension. It is signing-free (a
 * byte transform, like `pki.ct.encodeSctList`); a shape outside the covered set throws a typed `C509Error`.
 *
 * The fixed-width ECDSA r||s is sized by the ISSUER's signing curve, which a leaf certificate does not
 * carry. It is resolved authoritatively (never a magnitude guess, and matching issuer/subject Names are not
 * taken as proof of self-signing): from `opts.issuerCurve`, or from the RFC 5480 standard digest<->curve
 * pairing the signature algorithm implies. A certificate signed with a non-standard digest/curve pairing
 * (its r/s wider than the digest's standard curve) fails closed -- supply the issuer curve via
 * `opts.issuerCurve`.
 *
 * @opts
 *   - `issuerCurve` (string) -- the ISSUER's ECDSA signing curve "P-256" / "P-384" / "P-521" (or the OID
 *     names prime256v1 / secp384r1 / secp521r1); authoritative, overrides the resolution above. Consulted
 *     only for the DER -> type-3 path; ignored when re-emitting a parse result.
 *
 * @example
 *   var cbor = pki.schema.c509.encode(signerCertDer);   // a DER cert -> a compact type-3 C509
 *   pki.schema.c509.parse(cbor).certificateType;        // 3
 */
// A commonName string that is a MAC / EUI address ("HH-HH-HH-FF-FE-HH-HH-HH") -> the C509 tag-48 byte
// value (draft-20 sec. 3.2.3): an FF-FE-in-the-middle EUI-64 collapses to its 6-byte EUI-48, else the
// 8-byte EUI-64 verbatim. A non-MAC commonName returns null (encoded as text). The exact inverse of
// _macToEui64String, so the reconstruction rebuilds the identical DER commonName string.
function _euiFromCn(value) {
  if (!/^[0-9A-F]{2}(-[0-9A-F]{2}){7}$/.test(value)) return null;
  var bytes = Buffer.from(value.replace(/-/g, ""), "hex");
  if (bytes[3] === 0xff && bytes[4] === 0xfe) return Buffer.concat([bytes.subarray(0, 3), bytes.subarray(5)]);
  return bytes;
}
// A DER Name -> the C509 structured rdns, decoding each attribute's string type (PrintableString ->
// printable, UTF8String -> utf8; the C509 int sign carries this). Single-attribute RDNs only (v1).
function _c509NameFromDer(nameBytes) {
  var node = asn1.decode(nameBytes);
  var rdns = [];
  (node.children || []).forEach(function (rdnSet) {
    if (!rdnSet.children || rdnSet.children.length !== 1) throw _err("c509/non-invertible", "a C509 Name requires single-attribute RDNs");
    var attr = rdnSet.children[0];
    var attrName = oid.name(asn1.read.oid(attr.children[0]));
    if (attrName == null || ATTR_TO_INT[attrName] === undefined) throw _err("c509/non-invertible", "attribute type " + attrName + " has no C509 registry integer");
    var valNode = attr.children[1];
    // A value whose string type this codec cannot represent (NumericString and the other non-DirectoryString
    // types read.string declines) is NOT compact-representable -- report that in THIS module's domain rather
    // than leaking the codec's own asn1/* fault out of encode(), which is what every sibling shape does.
    var value;
    try { value = asn1.read.string(valNode); }
    catch (e) { throw _err("c509/non-invertible", "attribute " + attrName + " carries a value whose string type the C509 sec. 8.6 int form cannot represent", e); }
    // The IA5String type belongs ONLY to an IA5-only attribute (emailAddress, draft sec. 3.1.4), whose value
    // reconstructs from its type rather than the int's sign. Refuse either mismatch here with a precise verdict
    // instead of emitting an int form whose reconstruction would differ from the source bytes.
    var isIa5 = valNode.tagClass === "universal" && valNode.tagNumber === asn1.TAGS.IA5_STRING;
    if ((attrName === "emailAddress") !== isIa5) throw _err("c509/non-invertible", "attribute " + attrName + " carries a " + (isIa5 ? "IA5String" : "non-IA5String") + " value the C509 sec. 8.6 int form cannot represent");
    var eui = attrName === "commonName" ? _euiFromCn(value) : null;
    if (eui) rdns.push({ type: attrName, value: value, eui64: eui });                            // tag-48 MAC commonName
    else rdns.push({ type: attrName, value: value, printable: valNode.tagNumber === asn1.TAGS.PRINTABLE_STRING });
  });
  return { rdns: rdns };
}
// A keyUsage extnValue (a DER KeyUsage BIT STRING) -> the C509 integer whose bit i is the named bit i.
// Composes the shared named-bit reader (also used by the cRLDistributionPoints reasons transform).
function _keyUsageBitsFromDer(extnValue) {
  var bs;
  try {
    bs = asn1.read.bitString(asn1.decode(extnValue));
  } catch (_e) {
    return null;   // a malformed keyUsage BIT STRING cannot take the int shortcut -> encode it as a raw extension
  }
  return _namedBitsFromContent(bs.bytes, bs.unusedBits);
}
var _NO_EXPIRY = Date.UTC(9999, 11, 31, 23, 59, 59);
// The C509 (OID/node) curve names <-> the WebCrypto namedCurve the P1363 converter expects, and the
// RFC 5480 standard digest<->curve pairing an ECDSA signature algorithm implies.
var NODE_TO_WEBCRYPTO = { "prime256v1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521" };
var WEBCRYPTO_FIELD_BYTES = { "P-256": 32, "P-384": 48, "P-521": 66 };
var SIG_ALG_TO_CURVE = { "ecdsaWithSHA256": "P-256", "ecdsaWithSHA384": "P-384", "ecdsaWithSHA512": "P-521" };
// A DER INTEGER magnitude byte length: the content past any leading sign/pad octet.
function _magBytes(intNode) {
  var c = intNode.content, i = 0;
  while (i < c.length - 1 && c[i] === 0x00) i++;
  return c.length - i;
}
// The max r/s magnitude width of a DER ECDSA signature (validating its two-INTEGER shape).
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
var CURVE_ORDER = ["P-256", "P-384", "P-521"];   // ascending field size
// The smallest supported curve whose field holds a magnitude, or null if none does.
function _minCurveForMag(mag) {
  for (var i = 0; i < CURVE_ORDER.length; i++) { if (mag <= WEBCRYPTO_FIELD_BYTES[CURVE_ORDER[i]]) return CURVE_ORDER[i]; }
  return null;
}
// The ISSUER signature's fixed-width r||s is sized by the ISSUER's signing curve. The DER ECDSA signature
// does NOT carry the curve and the r/s magnitudes are only a lower bound (a P-384 signature with small r/s
// is byte-indistinguishable from a P-256 one), so the curve is resolved from an AUTHORITATIVE source, never
// a guess: (1) an explicit opts.issuerCurve, or (2) the RFC 5480 standard digest<->curve pairing the
// signature algorithm implies -- and ONLY when that pairing is the smallest curve the magnitude admits.
// Matching issuer/subject Names are NOT treated as proof of self-signing (a self-issued certificate may be
// cross-signed by a different key on a different curve). A signature whose r/s exceed the digest's standard
// curve (a larger key) OR whose magnitude also fits a SMALLER curve (a smaller key signing with a larger
// digest) leaves the curve undetermined: it fails closed and directs the caller to opts.issuerCurve.
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
// Compress an uncompressed SEC1 EC point (0x04||X||Y) to the C509 marker form (draft-20 sec. 3.2.2): the
// sign-of-Y marker 0xFE (Y even) / 0xFD (Y odd) followed by X. The inverse of webcrypto.decompressEcPoint,
// so the type-3 reconstruction recovers the exact original point. A non-0x04 point is kept verbatim.
function _compressEcPoint(point, coordLen) {
  if (!point.length || point[0] !== 0x04) return point;
  if (point.length !== 1 + 2 * coordLen) throw _err("c509/non-invertible", "uncompressed EC point length " + point.length + " does not match the curve field size");
  var x = point.subarray(1, 1 + coordLen), y = point.subarray(1 + coordLen);
  return Buffer.concat([Buffer.from([(y[y.length - 1] & 1) ? 0xfd : 0xfe]), x]);
}
// A DER X.509 v3 certificate -> the type-3 C509 structured result (the inverse of _reconstructDer). Only
// the reconstruction's covered set is invertible; encode() self-verifies the byte-exact round trip.
_derToType3 = function (input, opts) {
  var c;
  try { c = x509.parse(input); } catch (e) { throw _err("c509/bad-input", "the input is not a valid X.509 certificate", e); }
  // Both C509 certificate types are defined over X.509 v3 (draft-ietf-cose-cbor-encoded-cert
  // sec. 1), and the encoding carries no version field -- reconstruction always emits v3. So a v1
  // or v2 certificate is outside the format, not a codec limitation, and saying so here keeps it
  // from falling through to the byte-compare below, whose "does not reconstruct byte-for-byte"
  // reads as a defect in this encoder rather than a certificate the format does not cover.
  // (A v3 certificate with the extensions field OMITTED is fully supported: sec. 3.1.10 encodes
  // an omitted 'extensions' field as an empty CBOR array.)
  if (c.version !== 3) throw _err("c509/non-invertible", "C509 covers X.509 v3 certificates; got v" + c.version);
  if (!/^ecdsa/i.test(c.signatureAlgorithm.name || "")) throw _err("c509/non-invertible", "type-3 C509 encoding covers only ECDSA-signed certificates; got " + (c.signatureAlgorithm.name || "an unregistered algorithm"));
  if (c.subjectPublicKeyInfo.algorithm.name !== "ecPublicKey") throw _err("c509/non-invertible", "type-3 C509 encoding covers only EC (ecPublicKey) certificates in v1; got " + (c.subjectPublicKeyInfo.algorithm.name || "an unregistered algorithm"));
  var curveOid = asn1.read.oid(asn1.decode(c.subjectPublicKeyInfo.algorithm.parameters));
  var curve = oid.name(curveOid);
  var coordLen = EC_FIELD_BYTES[curve];
  if (!coordLen) throw _err("c509/non-invertible", "unsupported EC subject curve " + (curve || curveOid));
  var sigCurve = _resolveIssuerSigCurve(c, opts);   // the ISSUER signing curve, resolved authoritatively (opts / digest pairing)
  var spkiNode = asn1.decode(c.subjectPublicKeyInfo.bytes);
  return {
    certificateType: 3,
    serialNumber: c.serialNumber,          // no serialNumberHex -> the encoder uses the minimal ~biguint magnitude
    signatureAlgorithm: { name: c.signatureAlgorithm.name, oid: c.signatureAlgorithm.oid },
    // sec. 3.1.4: "If the 'issuer' field is identical to the 'subject' field, e.g., in case of
    // self-signed certificates, then the 'issuer' field MUST be encoded as the CBOR simple value
    // null." Compared on the RAW DER bytes, not on a canonicalized name: the reconstruction rebuilds
    // a null issuer FROM the subject, so two names that merely compare equal (a PrintableString
    // against a UTF8String of the same characters) would rebuild different bytes and break the
    // signature that covers them. Byte-identical is exactly the condition under which that is safe.
    issuer: c.issuer.bytes.equals(c.subject.bytes) ? null : _c509NameFromDer(c.issuer.bytes),
    validity: { notBefore: c.validity.notBefore, notAfter: c.validity.notAfter.getTime() === _NO_EXPIRY ? null : c.validity.notAfter },
    subject: _c509NameFromDer(c.subject.bytes),
    subjectPublicKeyAlgorithm: { name: "ecPublicKey", oid: c.subjectPublicKeyInfo.algorithm.oid, curve: curve },
    subjectPublicKey: _compressEcPoint(asn1.read.bitString(spkiNode.children[1]).bytes, coordLen),   // 0x04||X||Y -> C509 compressed marker
    rsaPublicKey: null,
    extensions: (c.extensions || []).map(function (e) {
      var ext = { name: e.name, oid: e.oid, critical: !!e.critical, value: e.value };
      if (e.name === "keyUsage") { var bits = _keyUsageBitsFromDer(e.value); if (bits != null) ext.keyUsageBits = bits; }   // enable the int-shortcut
      return ext;
    }),
    signatureValue: validator.sig.ecdsaDerToP1363(c.signatureValue.bytes, sigCurve, C509Error, "c509/bad-signature"),
  };
};

function encode(input, opts) {
  if (input && typeof input === "object" && !Buffer.isBuffer(input) && input.certificateType != null) {
    return _encodeC509Array(input);   // a parse result -> re-emit its native array
  }
  if (!Buffer.isBuffer(input) && typeof input !== "string") throw _err("c509/bad-input", "encode input must be a DER/PEM X.509 certificate or a c509.parse result");
  // Normalize input to DER through the SAME shared coercion x509.parse uses (a PEM string, a PEM-armored
  // Buffer, or raw DER all collapse to the certificate DER), so the self-verify compares against exactly the
  // bytes _derToType3 processed -- never a Buffer of PEM text.
  var origDer = pkix.coerceToDer(input, { pemLabel: "CERTIFICATE", PemError: frameworkError.PemError, ErrorClass: C509Error, prefix: "c509" });
  var encoded = _encodeC509Array(_derToType3(origDer, opts));
  // The type-3 transform MUST invert back to the original DER byte-for-byte (so the original signature
  // verifies) -- self-verify it, failing closed on any edge the reconstruction cannot reproduce.
  var recon = parse(encoded).reconstructedDer;
  if (!recon || Buffer.compare(recon, origDer) !== 0) throw _err("c509/non-invertible", "the type-3 C509 does not reconstruct the source certificate byte-for-byte");
  return encoded;
}

module.exports = { parse: parse, matches: matches, encode: encode };
