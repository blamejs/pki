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

// sec. 8.6 attribute types (abs(int) -> name; the sign selects the X.509 string type).
var ATTR_BY_INT = {
  1: _name("commonName"),
  2: _name("surname"),
  3: _name("serialNumber"),
  4: _name("countryName"),
  6: _name("localityName"),
  7: _name("stateOrProvinceName"),
  8: _name("organizationName"),
  9: _name("organizationalUnitName"),
  10: _name("title"),
};
// sec. 8.8 extension types (abs(int) -> name; the sign selects criticality).
var EXT_BY_INT = {
  1: _name("subjectKeyIdentifier"),
  2: _name("keyUsage"),
  3: _name("subjectAltName"),
  4: _name("basicConstraints"),
  7: _name("keyUsage"),
  10: _name("authorityKeyIdentifier"),
};

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
  if (!node || node.majorType !== 0) throw _err("c509/bad-validity", label + " must be an unwrapped CBOR epoch integer (~time)");
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
    var mac = node.children[0].content;
    if (mac.length !== 6 && mac.length !== 8) throw _err("c509/bad-name", "a tag-48 MAC address must be 6 (EUI-48) or 8 (EUI-64) bytes");
    return { eui64: mac };
  }
  throw _err("c509/bad-name", "an attribute value is not a C509 SpecialText (text / bytes / tag-48)");
}

// A single Name (sec. 3.1.4/sec. 3.1.6): the CBOR simple null (issuer only) | a bare SpecialText single
// commonName | an array of RDNAttributes. Surfaces { dn, rdns, eui64? } shape-compatible with x509.
function _name509(node, isSubject) {
  if (!isSubject && node.majorType === 7 && node.ai === 22) return null;   // issuer == subject (self-signed)
  // A bare SpecialText (not an array) is a single commonName attribute (attributeType == +1).
  if (node.majorType === 3 || node.majorType === 2 || node.majorType === 6) {
    var sv = _specialText(node);
    if (sv.eui64) return { rdns: [{ type: "commonName", eui64: sv.eui64 }], eui64: sv.eui64, dn: "CN=" + _macToEui64String(sv.eui64) };
    var val = sv.text !== undefined ? sv.text : sv.hex;
    return { rdns: [{ type: "commonName", value: val }], dn: "CN=" + val };
  }
  if (node.majorType !== 4) throw _err("c509/bad-name", "a C509 Name must be null, a SpecialText, or an array of RDN attributes");
  var rdns = [];
  var parts = [];
  var kids = node.children || [];
  // Each RDN attribute is an (attributeType, attributeValue) pair; an odd-length array is a dangling
  // attribute type with no value -- reject rather than silently drop the trailing element.
  if (kids.length % 2 !== 0) throw _err("c509/bad-name", "a C509 Name array must be attribute-type/value pairs (dangling attribute type)");
  for (var i = 0; i + 1 < kids.length; i += 2) {
    var ti = Number(cbor.read.int(kids[i]));
    var tname = ATTR_BY_INT[Math.abs(ti)];
    if (tname === undefined) throw _err("c509/bad-name", "attribute type integer " + ti + " has no C509 registry row");
    var v = _specialText(kids[i + 1]);
    var vv = v.text !== undefined ? v.text : (v.hex !== undefined ? v.hex : _macToEui64String(v.eui64));
    rdns.push({ type: tname, value: vv, printable: ti < 0 });
    parts.push(_shortName(tname) + "=" + vv);
  }
  return { rdns: rdns, dn: parts.join(",") };
}
function _shortName(n) { return n === "commonName" ? "CN" : n === "countryName" ? "C" : n === "organizationName" ? "O" : n === "organizationalUnitName" ? "OU" : n === "localityName" ? "L" : n === "stateOrProvinceName" ? "ST" : n; }

// extensions (sec. 3.1.10/sec. 3.3/sec. 8.8): [ * Extension ] | a single keyUsage int-shortcut.
function _extensions(node) {
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
  for (var i = 0; i + 1 < kids.length; i += 2) {
    var idNode = kids[i], valNode = kids[i + 1];
    var name, extOid, critical;
    if (idNode.majorType === 0 || idNode.majorType === 1) {
      var ei = Number(cbor.read.int(idNode));
      name = EXT_BY_INT[Math.abs(ei)];
      if (name === undefined) throw _err("c509/bad-extensions", "extension type integer " + ei + " has no C509 registry row");
      extOid = oid.byName(name); critical = ei < 0;
    } else {
      var r = _oidName(idNode, "c509/bad-extensions", "an extension id");
      name = r.name; extOid = r.oid;
      // ~oid extension: bare bytes -> non-critical, [ bytes ] -> critical (sec. 3.1.10).
      critical = valNode.majorType === 4;
    }
    // A critical ~oid extension wraps its extnValue byte string in a single-element array, so the raw
    // value is the inner byte string; otherwise it is the node's own byte-string content.
    var valContent = (critical && valNode.majorType === 4 && valNode.children && valNode.children[0]) ? valNode.children[0].content : valNode.content;
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
  if (rdn.eui64) return b.utf8(_macToEui64String(rdn.eui64));
  if (rdn.type === "countryName" || rdn.type === "serialNumber") return b.printable(String(rdn.value));
  return rdn.printable ? b.printable(String(rdn.value)) : b.utf8(String(rdn.value));
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
// BIT STRING named bit i (bit 0 = digitalSignature = the MSB of the first content octet).
function _reconKeyUsageBits(value) {
  // The keyUsage value indexes the 9 named bits of RFC 5280 sec. 4.2.1.3 (digitalSignature..decipherOnly);
  // a non-positive, non-integer, or > 0x1FF value is not a valid KeyUsage and would also corrupt the
  // 32-bit bitwise re-encoding below (a value past 2^31 wraps). Fail closed before the bit walk.
  if (!Number.isInteger(value) || value <= 0 || value > 0x1ff) throw _err("c509/non-invertible", "a keyUsage value must be a positive integer within the 9 defined bits");
  var hi = 0; for (var t = value; t; t >>= 1) hi++;   // number of significant bits
  hi -= 1;                                             // highest set bit index
  var nbytes = (hi >> 3) + 1;
  var buf = Buffer.alloc(nbytes);
  for (var bit = 0; bit <= hi; bit++) { if (value & (1 << bit)) buf[bit >> 3] |= 0x80 >> (bit & 7); }
  return b.bitString(buf, 7 - (hi & 7));
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
    // AlgorithmIdentifier.parameters is ANY -- exactly one well-formed DER element. Validate the supplied
    // bytes decode as a single element (the strict decoder rejects trailing bytes / malformed encodings)
    // before re-emitting them, so a malformed or multi-element parameter blob fails closed rather than
    // producing an invalid reconstructed AlgorithmIdentifier.
    try { asn1.decode(alg.parameters); }
    catch (e) { throw _err("c509/non-invertible", "algorithm parameters are not a single well-formed DER element", e); }
    fields.push(b.raw(alg.parameters));
  }
  return b.sequence(fields);
}

// The full type-3 -> DER Certificate reconstruction, byte-for-byte.
function _reconstructDer(r, sigNode) {
  var sigAlgSeq = _reconAlgId(r.signatureAlgorithm);
  var tbsFields = [
    b.explicit(0, b.integer(2n)),                                  // version v3 (type-3 is X.509 v3)
    b.integer(r.serialNumber),
    sigAlgSeq,
    _reconName(r.issuer && r.issuer.rdns ? r.issuer : r.subject),  // null issuer -> issuer == subject
    b.sequence([_reconTime(r.validity.notBefore), _reconTime(r.validity.notAfter)]),
    _reconName(r.subject),
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

  var type = Number(cbor.read.int(f[0]));
  if (type !== 2 && type !== 3) throw _err("c509/bad-certificate-type", "c509CertificateType must be 2 (native) or 3 (re-encoded), got " + type);

  var serialBytes = f[1];
  var serial = _biguint(serialBytes, "c509/bad-serial", "certificateSerialNumber");
  var sHex = serialBytes.content.toString("hex");

  var sigAlg = _algorithm(f[2], SIG_ALG_BY_INT, "c509/unknown-algorithm", "issuerSignatureAlgorithm");
  var issuer = _name509(f[3], false);
  var notBefore = _time(f[4], false, "validityNotBefore");
  var notAfter = _time(f[5], true, "validityNotAfter");
  var subject = _name509(f[6], true);
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
  var extensions = _extensions(f[9]);
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

  // Native (type-2) signed region (sec. 3.1.12): the RAW bytes of the CBOR-sequence elements 0..9 (NOT
  // the outer array head, NOT the signature) -- a zero-copy subarray a native verifier hashes.
  if (type === 2) {
    var b0 = f[0].bytes, b9 = f[9].bytes;
    var start = b0.byteOffset - input.byteOffset;
    var end = b9.byteOffset - input.byteOffset + b9.length;
    result.signedData = input.subarray(start, end);
  }

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

module.exports = { parse: parse, matches: matches };
