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
    var euiBytes = node.children[0].content;
    if (euiBytes.length !== 6 && euiBytes.length !== 8) throw _err("c509/bad-name", "a tag-48 MAC address must be 6 (EUI-48) or 8 (EUI-64) bytes");
    return { eui64: euiBytes };
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
    var name, extOid, critical, valContent;
    if (idNode.majorType === 0 || idNode.majorType === 1) {
      var ei = Number(cbor.read.int(idNode));
      name = EXT_BY_INT[Math.abs(ei)];
      if (name === undefined) throw _err("c509/bad-extensions", "extension type integer " + ei + " has no C509 registry row");
      extOid = oid.byName(name); critical = ei < 0;
      // An int extension value is a Defined CBOR item; v1 reconstructs only a byte-string value (a
      // non-byte-string value surfaces as null and fails closed at the type-3 reconstruction).
      valContent = valNode.content;
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

// The registry INVERSE tables -- the canonical int per name (the lossy forward map is resolved to ONE
// choice: EXT_BY_INT maps both 2 and 7 to keyUsage, so keyUsage encodes to the canonical draft int 2).
var SIG_ALG_TO_INT = { ecdsaWithSHA256: 0, ecdsaWithSHA384: 1, ecdsaWithSHA512: 2 };
var PK_ALG_TO_INT = { rsaEncryption: 0, "ecPublicKey|prime256v1": 1, "ecPublicKey|secp384r1": 2, "ecPublicKey|secp521r1": 3 };
var ATTR_TO_INT = { commonName: 1, surname: 2, serialNumber: 3, countryName: 4, localityName: 6, stateOrProvinceName: 7, organizationName: 8, organizationalUnitName: 9, title: 10 };
var EXT_TO_INT = { subjectKeyIdentifier: 1, keyUsage: 2, subjectAltName: 3, basicConstraints: 4, authorityKeyIdentifier: 10 };

// A non-negative BigInt -> its minimal big-endian ~biguint bytes (the leading 0x00 sign octet omitted).
function _minBytes(n) {
  if (n < 0n) throw _err("c509/bad-serial", "a ~biguint value must be non-negative");
  if (n === 0n) return Buffer.alloc(0);
  var hex = n.toString(16); if (hex.length % 2) hex = "0" + hex;
  return Buffer.from(hex, "hex");
}
// A C509 AlgorithmIdentifier -> int (registry) | ~oid (bare bytes) | [~oid, params]. `key` selects the row.
function _encAlgorithm(alg, toInt, key) {
  var i = toInt[key];
  if (i !== undefined && !(alg.parameters && alg.parameters.length)) return cbor.build.int(BigInt(i));
  var oidBytes = cbor.build.byteString(asn1.encodeOidContent(alg.oid));   // ~oid: bare BER OID content
  if (alg.parameters && alg.parameters.length) return cbor.build.array([oidBytes, cbor.build.byteString(alg.parameters)]);
  return oidBytes;
}
// A SpecialText attribute value -> CBOR (text | tag-48 EUI). v1 encodes the text + eui64 forms.
function _encSpecialText(rdn) {
  if (rdn.eui64) return cbor.build.tag(48, cbor.build.byteString(rdn.eui64));
  return cbor.build.textString(String(rdn.value));
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
    if (ei !== undefined) {
      items.push(cbor.build.int(BigInt(ext.critical ? -ei : ei)));
      // a registered-int extension carries its extnValue DER bytes as a bare byte string.
      if (!Buffer.isBuffer(ext.value)) throw _err("c509/non-invertible", "extension " + ext.name + " has no byte-string value to encode");
      items.push(cbor.build.byteString(ext.value));
    } else {
      items.push(cbor.build.byteString(asn1.encodeOidContent(ext.oid)));   // ~oid extension id
      if (!Buffer.isBuffer(ext.value)) throw _err("c509/non-invertible", "extension " + (ext.oid || ext.name) + " has no byte-string value to encode");
      var bs = cbor.build.byteString(ext.value);
      items.push(ext.critical ? cbor.build.array([bs]) : bs);              // critical ~oid value wraps in a 1-element array
    }
  });
  return cbor.build.array(items);
}
// forward-declared below; the DER X.509 -> type-3 C509 structured result.
var _derToType3;
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
  var pkKey = r.subjectPublicKeyAlgorithm.curve ? r.subjectPublicKeyAlgorithm.name + "|" + r.subjectPublicKeyAlgorithm.curve : r.subjectPublicKeyAlgorithm.name;
  return cbor.build.array([
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
    var value = asn1.read.string(valNode);
    var eui = attrName === "commonName" ? _euiFromCn(value) : null;
    if (eui) rdns.push({ type: attrName, value: value, eui64: eui });                            // tag-48 MAC commonName
    else rdns.push({ type: attrName, value: value, printable: valNode.tagNumber === asn1.TAGS.PRINTABLE_STRING });
  });
  return { rdns: rdns };
}
// A keyUsage extnValue (a DER KeyUsage BIT STRING) -> the C509 integer whose bit i is the named bit i.
function _keyUsageBitsFromDer(extnValue) {
  var bs;
  try { bs = asn1.read.bitString(asn1.decode(extnValue)); } catch (_e) { return null; }
  var total = bs.bytes.length * 8 - bs.unusedBits, value = 0;
  for (var bit = 0; bit < total && bit < 31; bit++) { if (bs.bytes[bit >> 3] & (0x80 >> (bit & 7))) value |= (1 << bit); }
  return value > 0 && value <= 0x1ff ? value : null;
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
  return Math.max(_magBytes(n.children[0]), _magBytes(n.children[1]));
}
// The ISSUER signature's fixed-width r||s is sized by the ISSUER's signing curve. The DER ECDSA signature
// does NOT carry the curve and the r/s magnitudes are only a lower bound (a P-384 signature with small r/s
// is byte-indistinguishable from a P-256 one), so the curve is resolved from an AUTHORITATIVE source, never
// a guess: (1) an explicit opts.issuerCurve, or (2) the RFC 5480 standard digest<->curve pairing the
// signature algorithm implies. Matching issuer/subject Names are NOT treated as proof of self-signing -- a
// self-issued certificate may be cross-signed by a different key on a different curve, so the Names cannot
// size the r||s. A signature whose r/s magnitudes exceed the digest's standard curve was made with a
// non-standard digest/curve pairing that cannot be inferred: it fails closed and directs the caller to
// opts.issuerCurve.
function _resolveIssuerSigCurve(c, opts) {
  var mag = _sigMagWidth(c.signatureValue.bytes), curve;
  if (opts && opts.issuerCurve != null) {
    curve = String(opts.issuerCurve);
    if (NODE_TO_WEBCRYPTO[curve]) curve = NODE_TO_WEBCRYPTO[curve];
    if (!WEBCRYPTO_FIELD_BYTES[curve]) throw _err("c509/bad-input", "opts.issuerCurve must be P-256 / P-384 / P-521 (or prime256v1 / secp384r1 / secp521r1); got " + opts.issuerCurve);
  } else {
    curve = SIG_ALG_TO_CURVE[c.signatureAlgorithm.name];
    if (!curve) throw _err("c509/non-invertible", "cannot resolve the issuer signing curve for signature algorithm " + c.signatureAlgorithm.name);
    if (mag > WEBCRYPTO_FIELD_BYTES[curve]) throw _err("c509/non-invertible", "the issuer signed with a non-standard digest/curve pairing (r/s width " + mag + " exceeds the " + curve + " field implied by " + c.signatureAlgorithm.name + "); pass opts.issuerCurve (P-256 / P-384 / P-521)");
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
    issuer: _c509NameFromDer(c.issuer.bytes),
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
  var encoded = _encodeC509Array(_derToType3(input, opts));
  // The type-3 transform MUST invert back to the original DER byte-for-byte (so the original signature
  // verifies) -- self-verify it, failing closed on any edge the reconstruction cannot reproduce.
  var recon = parse(encoded).reconstructedDer;
  var origDer = Buffer.isBuffer(input) ? input : x509.pemDecode(input);
  if (!recon || Buffer.compare(recon, origDer) !== 0) throw _err("c509/non-invertible", "the type-3 C509 does not reconstruct the source certificate byte-for-byte");
  return encoded;
}

module.exports = { parse: parse, matches: matches, encode: encode };
