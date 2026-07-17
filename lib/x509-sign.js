// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

/**
 * @module     pki.x509
 * @nav        Signing
 * @title      Certificates
 * @intro The X.509 certificate-issuance producing side. `pki.x509.sign` builds a `TBSCertificate`,
 *   signs it, and emits a `Certificate` (RFC 5280 sec. 4) that `pki.schema.x509.parse`,
 *   `pki.path.validate`, and OpenSSL all accept -- self-signed or CA-signed, over any signature
 *   algorithm the toolkit registry resolves: RSA (PKCS#1 v1.5 / PSS), ECDSA, EdDSA, ML-DSA, SLH-DSA,
 *   and the composite (hybrid) arms. Parsing lives at `pki.schema.x509.parse`.
 * @spec RFC 5280
 * @card Build and sign an X.509 certificate -- self-signed or CA-signed, over any registry algorithm.
 */
//
// The whole algorithm matrix comes from the shared sign-scheme resolver (the same registry
// pki.cms.sign / pki.tsp.sign drive), so a new algorithm is a registry row, never a branch here. The
// TBS + extension DER is hand-assembled through the canonical asn1.build.* layer (the shipped
// cms/tsp/ocsp producing pattern); the strict schema-x509 decoder round-trips it, and that round-trip
// -- plus OpenSSL interop -- is the divergence guard.

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var signScheme = require("./sign-scheme");
var compositeSig = require("./composite-sig");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");
var schema = require("./schema-engine");
var pkix = require("./schema-pkix");

var CertificateError = frameworkError.CertificateError;
// The x509 schema namespace + Name parser -- the SAME RDNSequence parser pki.schema.x509.parse uses, so
// a raw Name DER is validated fully (structure, DirectoryString types) with the frozen x509/* codes.
var NS = pkix.makeNS("x509", CertificateError, oid);
var NAME_SCHEMA = pkix.name(NS);
var b = asn1.build;
// Two error factories (cms-sign.js pattern): `_err` takes a full x509/* code; `_signE` prepends the
// domain so the shared sign-scheme resolver/signer faults keep the x509/* codes. Both are FACTORIES
// -- guard.time.assertValid and resolveSignScheme invoke them as `E(code, msg)` with no `new`.
function _err(code, message, cause) { return new CertificateError(code, message, cause); }
function _signE(kind, message, cause) { return new CertificateError("x509/" + kind, message, cause); }
function O(n) { return oid.byName(n); }

var OID_SKI = O("subjectKeyIdentifier");

// The recognized keys of the `extensions` spec object; an unknown key is a typo and throws at
// config-time (a custom extension is passed as pre-encoded DER via the array form).
var KNOWN_EXT_KEYS = {
  subjectKeyIdentifier: 1, authorityKeyIdentifier: 1, keyUsage: 1, keyUsageCritical: 1,
  extendedKeyUsage: 1, extendedKeyUsageCritical: 1, basicConstraints: 1, subjectAltName: 1,
  certificatePolicies: 1, certificatePoliciesCritical: 1,
};

// KeyUsage named-bit positions (RFC 5280 sec. 4.2.1.3); contentCommitment is the RFC 5280 rename of
// the X.509 nonRepudiation bit (1).
var KU_BIT = {
  digitalSignature: 0, nonRepudiation: 1, contentCommitment: 1, keyEncipherment: 2,
  dataEncipherment: 3, keyAgreement: 4, keyCertSign: 5, cRLSign: 6, encipherOnly: 7, decipherOnly: 8,
};

// ---- distinguished name encoding (RFC 5280 sec. 4.1.2.4) -------------------

// countryName is a PrintableString, emailAddress an IA5String; every other new-certificate attribute
// is a UTF8String (Teletex/BMP/Universal are backward-compat only and never emitted).
function _atvString(attrName, value) {
  if (attrName === "countryName") {
    // countryName is a PrintableString SIZE(2) -- the two-letter ISO 3166 alpha-2 code (RFC 5280 /
    // X.520). Reject any other length at config-time.
    if (String(value).length !== 2) throw _err("x509/bad-name", "countryName must be a two-letter ISO 3166 code (PrintableString SIZE(2))");
    return b.printable(value);
  }
  if (attrName === "emailAddress") return b.ia5(value);
  return b.utf8(value);
}
function _encodeAtv(attrName, value) {
  if (value == null || value === "") throw _err("x509/bad-name", "the " + attrName + " attribute value must be a non-empty string");
  var typeOid;
  try { typeOid = O(attrName); }
  catch (e) { throw _err("x509/bad-name", "unknown distinguished-name attribute " + JSON.stringify(attrName), e); }
  return b.sequence([b.oid(typeOid), _atvString(attrName, value)]);
}
function _encodeRdn(rdnSpec) {
  if (!rdnSpec || typeof rdnSpec !== "object" || Buffer.isBuffer(rdnSpec)) throw _err("x509/bad-name", "each RDN must be an object of { attributeName: value }");
  var keys = Object.keys(rdnSpec);
  if (!keys.length) throw _err("x509/bad-name", "an RDN must carry at least one attribute");
  // build.set DER-sorts the AttributeTypeAndValue members (X.690 SET-OF ordering) for a multi-valued RDN.
  return b.set(keys.map(function (k) { return _encodeAtv(k, rdnSpec[k]); }));
}
// A DN spec -> RDNSequence DER. A string is shorthand for a single commonName RDN; a Buffer is raw
// pre-encoded Name DER (the escape hatch). An empty array yields an empty RDNSequence (a subject MAY
// be empty with a critical SAN; the issuer non-empty rule is enforced by the caller).
function _encodeName(spec) {
  if (Buffer.isBuffer(spec)) { _assertValidNameDer(spec); return spec; }
  if (typeof spec === "string") spec = [{ commonName: spec }];
  if (!Array.isArray(spec)) throw _err("x509/bad-name", "a name must be a string, an array of RDNs, or raw Name DER");
  return b.sequence(spec.map(_encodeRdn));
}
// A raw Name DER is embedded verbatim, so validate it is a well-formed RDNSequence -- a SEQUENCE OF
// RelativeDistinguishedName, each a non-empty SET OF AttributeTypeAndValue{ type OID, value } -- before
// it is embedded. An empty RDNSequence is permitted (an empty subject; the issuer non-empty rule is
// enforced separately). asn1.decode already rejects trailing bytes.
function _assertValidNameDer(der) {
  var node;
  try { node = asn1.decode(der); }
  catch (e) { throw _err("x509/bad-name", "the raw Name DER is not valid DER", e); }
  // Full validation: walk the raw Name through the exact RDNSequence parser the certificate parser
  // uses (the SET-OF structure, the AttributeTypeAndValue arity, the DirectoryString value types),
  // not a partial hand-rolled shape check -- so an embedded raw Name is exactly what parses back.
  try { schema.walk(NAME_SCHEMA, node, NS); }
  catch (e) {
    if (e instanceof CertificateError || (e && e.name === "Asn1Error")) throw e;
    throw _err("x509/bad-name", "the raw Name DER is not a well-formed distinguished name", e);
  }
}
function _isEmptyName(nameDer) { return asn1.decode(nameDer).children.length === 0; }

// ---- GeneralName encoding (RFC 5280 sec. 4.2.1.6) --------------------------

function _ia5Content(s) {
  s = String(s);
  for (var i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 0x7F) throw _err("x509/bad-input", "value requires 7-bit ASCII (IA5String): " + JSON.stringify(s));
  }
  return Buffer.from(s, "latin1");
}
function _encodeGeneralName(entry) {
  if (!entry || typeof entry !== "object" || Buffer.isBuffer(entry)) throw _err("x509/bad-input", "a GeneralName must be an object with exactly one name form");
  var keys = Object.keys(entry);
  if (keys.length !== 1) throw _err("x509/bad-input", "a GeneralName entry must have exactly one form, got " + keys.length);
  var k = keys[0], v = entry[k];
  if (v == null || v === "") throw _err("x509/bad-input", "an empty GeneralName value is not permitted (RFC 5280 sec. 4.2.1.6)");
  switch (k) {
    // IMPLICIT [1]/[2]/[6] IA5String -- context-primitive over the raw ASCII content.
    case "rfc822Name": return b.contextPrimitive(1, _ia5Content(v));
    case "dNSName": return b.contextPrimitive(2, _ia5Content(v));
    case "uniformResourceIdentifier": case "uri": return b.contextPrimitive(6, _ia5Content(v));
    // IMPLICIT [7] OCTET STRING -- 4 octets (IPv4) or 16 (IPv6).
    case "iPAddress":
      if (!Buffer.isBuffer(v) || (v.length !== 4 && v.length !== 16)) throw _err("x509/bad-input", "iPAddress must be a 4- or 16-octet Buffer");
      return b.contextPrimitive(7, v);
    // [4] Name -- Name is a CHOICE, so the context tag is necessarily EXPLICIT.
    case "directoryName": return b.explicit(4, _encodeName(v));
    default: throw _err("x509/bad-input", "unsupported GeneralName form " + JSON.stringify(k) + " (supported: rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, directoryName)");
  }
}

// ---- extension-value encoders (the inverse of certExtensionDecoders) -------

function _extKeyUsage(names) {
  if (!Array.isArray(names) || !names.length) throw _err("x509/bad-input", "keyUsage must assert at least one bit (RFC 5280 sec. 4.2.1.3)");
  var positions = names.map(function (n) {
    var pos = KU_BIT[n];
    if (pos == null) throw _err("x509/bad-input", "unknown keyUsage bit " + JSON.stringify(n));
    return pos;
  });
  return b.namedBitString(positions);   // minimal NamedBitList DER (X.690 sec. 11.2.2)
}
function _extExtKeyUsage(names) {
  if (!Array.isArray(names) || !names.length) throw _err("x509/bad-input", "extendedKeyUsage must list at least one KeyPurposeId");
  return b.sequence(names.map(function (n) {
    var purposeOid;
    try { purposeOid = O(n); }
    catch (e) { throw _err("x509/bad-input", "unknown extendedKeyUsage purpose " + JSON.stringify(n), e); }
    return b.oid(purposeOid);
  }));
}
function _extBasicConstraints(spec) {
  var children = [];
  if (spec.cA === true) children.push(b.boolean(true));   // cA=FALSE omitted (DER DEFAULT)
  if (spec.pathLen != null) children.push(b.integer(_pathLen(spec.pathLen)));
  return b.sequence(children);
}
function _pathLen(v) {
  if (typeof v !== "number" || !isFinite(v) || v < 0 || (v | 0) !== v) throw _err("x509/bad-input", "basicConstraints pathLenConstraint must be a non-negative integer");
  return BigInt(v);
}
function _extSki(keyid) { return b.octetString(keyid); }
function _extAki(keyid) { return b.sequence([b.contextPrimitive(0, keyid)]); }   // keyIdentifier [0] IMPLICIT OCTET STRING
function _extSan(entries) {
  if (!Array.isArray(entries) || !entries.length) throw _err("x509/bad-input", "subjectAltName must carry at least one GeneralName");
  return b.sequence(entries.map(_encodeGeneralName));
}
function _extCertPolicies(names) {
  if (!Array.isArray(names) || !names.length) throw _err("x509/bad-input", "certificatePolicies must list at least one policy OID");
  var seen = {};
  return b.sequence(names.map(function (n) {
    var pOid;
    try { pOid = O(n); }
    catch (e) { throw _err("x509/bad-input", "unknown certificate policy " + JSON.stringify(n), e); }
    if (seen[pOid]) throw _err("x509/bad-input", "duplicate certificate policy " + JSON.stringify(n) + " (RFC 5280 sec. 4.2.1.4)");
    seen[pOid] = true;
    return b.sequence([b.oid(pOid)]);   // PolicyInformation ::= SEQUENCE { policyIdentifier OID }
  }));
}
// Wrap an encoded extension value in Extension ::= SEQUENCE { extnID, critical?, extnValue }. A
// FALSE critical bit is omitted (DER DEFAULT), so the boolean appears only when the extension is critical.
function _ext(oidStr, critical, valueDer) {
  var children = [b.oid(oidStr)];
  if (critical) children.push(b.boolean(true));
  children.push(b.octetString(valueDer));
  return b.sequence(children);
}

// The SHA-1 subjectKeyIdentifier (RFC 5280 sec. 4.2.1.2 method 1): the hash of the subjectPublicKey
// BIT STRING CONTENT (past the unused-bits octet), NOT the whole SPKI or the whole BIT STRING TLV.
function _spkiKeyId(spkiDer) {
  var keyBytes = asn1.read.bitString(asn1.decode(spkiDer).children[1]).bytes;
  // nosemgrep: pki-weak-hash-md5-sha1 -- RFC 5280 sec. 4.2.1.2 method 1 DEFINES the subjectKeyIdentifier
  // as the SHA-1 of the subjectPublicKey; this is a key identifier, not a signature or a
  // collision-resistance use, and the algorithm is fixed by the standard.
  return nodeCrypto.createHash("sha1").update(keyBytes).digest();
}
function _skiValueOf(caCert) {
  var ext = (caCert.extensions || []).filter(function (e) { return e.oid === OID_SKI; })[0];
  if (ext) { try { return asn1.read.octetString(asn1.decode(ext.value)); } catch (_e) { /* fall through to re-derive from the issuer SPKI */ } }
  return null;
}
function _skiKeyId(val, spkiDer) {
  if (Buffer.isBuffer(val)) return val;
  if (val === true) return _spkiKeyId(spkiDer);
  throw _err("x509/bad-input", "subjectKeyIdentifier must be true (auto-derive) or a Buffer key id");
}
function _akiKeyId(val, ctx) {
  if (Buffer.isBuffer(val)) return val;
  if (val === true) {
    if (ctx.issuerCert) { var ski = _skiValueOf(ctx.issuerCert); if (ski) return ski; }
    return _spkiKeyId(ctx.issuerSpki);
  }
  throw _err("x509/bad-input", "authorityKeyIdentifier must be true (auto-derive from the issuer) or a Buffer key id");
}

// Build the extensions [3] block from the spec object (or pass through an array of pre-encoded
// Extension DER buffers). Enforces the RFC 5280 CA cross-field gates, then emits a deterministic order.
function _buildExtensions(extSpec, ctx) {
  if (extSpec == null) return [];
  if (Array.isArray(extSpec)) {
    // Validate each pre-encoded extension, reject a duplicate extnID (RFC 5280 sec. 4.2 -- at most one
    // instance of an extension), and decode basicConstraints + keyUsage to apply the same CA
    // cross-field rules the object form enforces (below), so the array escape hatch cannot bypass them.
    var seenExt = {}, arrCa = false, arrKeyCertSign = false, arrPathLen = false;
    var oidBc = O("basicConstraints"), oidKu = O("keyUsage");
    var arr = extSpec.map(function (e, i) {
      var der = _reqDer(e, "extension");
      _assertValidExtension(der, i);
      var n = asn1.decode(der);
      var extnId = asn1.read.oid(n.children[0]);
      if (seenExt[extnId]) throw _err("x509/bad-input", "duplicate extension " + extnId + " in the extensions array (RFC 5280 sec. 4.2 -- at most one instance of an extension)");
      seenExt[extnId] = true;
      if (extnId === oidBc || extnId === oidKu) {
        // Decode the recognized value for the coherence check; a malformed value is re-typed to a
        // CertificateError rather than leaking a raw asn1/* read error from this boundary.
        try {
          var val = asn1.decode(asn1.read.octetString(n.children[n.children.length - 1]));
          if (extnId === oidBc) {
            if (val.children[0] && val.children[0].tagNumber === asn1.TAGS.BOOLEAN && val.children[0].tagClass === "universal") arrCa = asn1.read.boolean(val.children[0]);
            arrPathLen = val.children.some(function (c) { return c.tagNumber === asn1.TAGS.INTEGER && c.tagClass === "universal"; });
          } else {
            var bits = asn1.read.bitString(val);
            arrKeyCertSign = bits.bytes.length > 0 && (bits.bytes[0] & 0x04) !== 0;   // keyCertSign is bit 5 (0x80 >> 5)
          }
        } catch (e) {
          if (e instanceof CertificateError) throw e;
          throw _err("x509/bad-input", "pre-encoded " + (extnId === oidBc ? "basicConstraints" : "keyUsage") + " extension value is malformed", e);
        }
      }
      return b.raw(der);
    });
    if (arrKeyCertSign && !arrCa) throw _err("x509/bad-input", "keyUsage keyCertSign requires basicConstraints cA=TRUE (RFC 5280 sec. 4.2.1.3)");
    if (arrPathLen && (!arrCa || !arrKeyCertSign)) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires cA=TRUE and keyUsage keyCertSign (RFC 5280 sec. 4.2.1.9)");
    return arr;
  }
  if (typeof extSpec !== "object") throw _err("x509/bad-input", "extensions must be an object or an array of pre-encoded Extension DER");
  // Reject a typo'd / unsupported extension key at config-time rather than silently dropping it (a
  // misspelled `keyUsag` would otherwise omit keyUsage). A custom extension goes in the array form.
  Object.keys(extSpec).forEach(function (k) {
    if (!KNOWN_EXT_KEYS[k]) throw _err("x509/bad-input", "unknown extension " + JSON.stringify(k) + " in the extensions spec; pass a pre-encoded Extension DER via the array form for a custom extension");
  });

  var bc = extSpec.basicConstraints;
  var caTrue = !!(bc && bc.cA === true);
  var ku = extSpec.keyUsage;
  var assertsKeyCertSign = Array.isArray(ku) && ku.indexOf("keyCertSign") >= 0;
  // RFC 5280 sec. 4.2.1.3 -- keyCertSign requires basicConstraints cA=TRUE.
  if (assertsKeyCertSign && !caTrue) throw _err("x509/bad-input", "keyUsage keyCertSign requires basicConstraints cA=TRUE (RFC 5280 sec. 4.2.1.3)");
  // RFC 5280 sec. 4.2.1.9 -- pathLenConstraint requires cA=TRUE AND keyCertSign.
  if (bc && bc.pathLen != null) {
    if (!caTrue) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires cA=TRUE (RFC 5280 sec. 4.2.1.9)");
    if (!assertsKeyCertSign) throw _err("x509/bad-input", "basicConstraints pathLenConstraint requires keyUsage keyCertSign (RFC 5280 sec. 4.2.1.9)");
  }

  var out = [];
  if (extSpec.subjectKeyIdentifier != null) out.push(_ext(O("subjectKeyIdentifier"), false, _extSki(_skiKeyId(extSpec.subjectKeyIdentifier, ctx.spki))));
  if (extSpec.authorityKeyIdentifier != null) out.push(_ext(O("authorityKeyIdentifier"), false, _extAki(_akiKeyId(extSpec.authorityKeyIdentifier, ctx))));
  if (ku != null) out.push(_ext(O("keyUsage"), extSpec.keyUsageCritical !== false, _extKeyUsage(ku)));
  if (extSpec.extendedKeyUsage != null) out.push(_ext(O("extKeyUsage"), !!extSpec.extendedKeyUsageCritical, _extExtKeyUsage(extSpec.extendedKeyUsage)));
  if (bc != null) out.push(_ext(O("basicConstraints"), bc.critical !== false, _extBasicConstraints(bc)));
  if (extSpec.subjectAltName != null) out.push(_ext(O("subjectAltName"), ctx.subjectEmpty, _extSan(extSpec.subjectAltName)));
  if (extSpec.certificatePolicies != null) out.push(_ext(O("certificatePolicies"), !!extSpec.certificatePoliciesCritical, _extCertPolicies(extSpec.certificatePolicies)));
  return out;
}

// ---- serial + validity + key plumbing --------------------------------------

// RFC 5280 sec. 4.1.2.2 -- a positive, non-zero INTEGER of at most 20 content octets. A random
// 20-octet positive serial is generated when none is supplied.
function _serialInteger(serial) {
  var v;
  if (serial == null) {
    var rnd = nodeCrypto.randomBytes(20);
    rnd[0] &= 0x7f;                      // keep the top bit clear so the magnitude stays <= 20 octets and positive
    if (rnd[0] === 0) rnd[0] = 0x01;     // never all-zero leading -> non-zero and no redundant sign octet
    v = BigInt("0x" + rnd.toString("hex"));
  } else if (typeof serial === "bigint") { v = serial; }
  else if (typeof serial === "number") { if (!Number.isInteger(serial)) throw _err("x509/bad-serial", "serialNumber must be an integer"); v = BigInt(serial); }
  else if (typeof serial === "string") { try { v = BigInt(serial); } catch (e) { throw _err("x509/bad-serial", "serialNumber string must be a decimal or 0x-hex integer", e); } }
  else if (Buffer.isBuffer(serial)) { v = serial.length ? BigInt("0x" + serial.toString("hex")) : 0n; }
  else { throw _err("x509/bad-serial", "serialNumber must be a BigInt, integer, hex string, or Buffer"); }
  if (v <= 0n) throw _err("x509/bad-serial", "serialNumber must be a positive integer (RFC 5280 sec. 4.1.2.2)");
  var tlv = b.integer(v);
  if (asn1.decode(tlv).content.length > 20) throw _err("x509/bad-serial", "serialNumber must not exceed 20 octets (RFC 5280 sec. 4.1.2.2)");
  return tlv;
}
// RFC 5280 sec. 4.1.2.5 -- UTCTime for 1950..2049, GeneralizedTime otherwise. UTCTime's two-digit year
// only represents 1950..2049 (sec. 4.1.2.5.1), so a pre-1950 date MUST use GeneralizedTime (the same
// arm as a date from 2050 on); using UTCTime for a pre-1950 year would be unrepresentable.
function _timeDer(date, which) {
  guard.time.assertValid(date, _err, "x509/bad-input", "certificate " + which);
  var y = date.getUTCFullYear();
  return (y >= 1950 && y <= 2049) ? b.utcTime(date) : b.generalizedTime(date);
}
function _reqDer(v, what) {
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v);
  throw _err("x509/bad-input", what + " must be a DER Buffer");
}
// A well-formed SubjectPublicKeyInfo is a SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey
// BIT STRING }. The subject key is embedded verbatim (b.raw), so reject a malformed one AT ISSUANCE
// rather than emitting a certificate that fails to parse. (asn1.decode already rejects trailing bytes.)
function _assertValidSpki(spkiDer, what) {
  var n;
  try { n = asn1.decode(spkiDer); }
  catch (e) { throw _err("x509/bad-input", what + " is not valid DER", e); }
  if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length !== 2) throw _err("x509/bad-input", what + " must be a SubjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey }");
  var alg = n.children[0], key = n.children[1];
  if (alg.tagNumber !== asn1.TAGS.SEQUENCE || alg.tagClass !== "universal" || !alg.children || !alg.children.length) throw _err("x509/bad-input", what + " algorithm must be an AlgorithmIdentifier SEQUENCE");
  try { asn1.read.oid(alg.children[0]); }
  catch (e) { throw _err("x509/bad-input", what + " algorithm identifier is not an OBJECT IDENTIFIER", e); }
  if (key.tagNumber !== asn1.TAGS.BIT_STRING || key.tagClass !== "universal") throw _err("x509/bad-input", what + " subjectPublicKey must be a BIT STRING");
}
// A well-formed Extension is a SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET
// STRING }. A pre-encoded (array-form) extension is embedded verbatim, so validate its shape here.
function _assertValidExtension(der, idx) {
  var n;
  try { n = asn1.decode(der); }
  catch (e) { throw _err("x509/bad-input", "pre-encoded extension [" + idx + "] is not valid DER", e); }
  if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length < 2 || n.children.length > 3) throw _err("x509/bad-input", "pre-encoded extension [" + idx + "] must be an Extension SEQUENCE { extnID, critical?, extnValue }");
  try { asn1.read.oid(n.children[0]); }
  catch (e) { throw _err("x509/bad-input", "pre-encoded extension [" + idx + "] extnID is not an OBJECT IDENTIFIER", e); }
  if (n.children.length === 3) {
    var crit;
    try { crit = asn1.read.boolean(n.children[1]); }
    catch (e) { throw _err("x509/bad-input", "pre-encoded extension [" + idx + "] critical must be a BOOLEAN", e); }
    // DER DEFAULT: a FALSE criticality MUST be omitted, so an explicitly-encoded critical=FALSE is
    // non-canonical (RFC 5280 sec. 4.2 / X.690 sec. 11.5).
    if (crit !== true) throw _err("x509/bad-input", "pre-encoded extension [" + idx + "] critical=FALSE must be omitted (DER DEFAULT)");
  }
  var last = n.children[n.children.length - 1];
  if (last.tagNumber !== asn1.TAGS.OCTET_STRING || last.tagClass !== "universal") throw _err("x509/bad-input", "pre-encoded extension [" + idx + "] extnValue must be an OCTET STRING");
}
// Synthesize the parsed-cert shape resolveSignScheme reads (it only needs subjectPublicKeyInfo.algorithm)
// from a raw SPKI DER: { algorithm: { oid, parameters } }. `parameters` is the raw params TLV (or undefined).
function _certLikeFromSpki(spkiDer) {
  var spki = asn1.decode(spkiDer);
  if (!spki.children || !spki.children.length) throw _err("x509/bad-input", "the signing key SPKI is not a SubjectPublicKeyInfo");
  var alg = spki.children[0];
  var keyOid;
  try { keyOid = asn1.read.oid(alg.children[0]); }
  catch (e) { throw _err("x509/bad-input", "the signing key SPKI algorithm is not an OID", e); }
  return { subjectPublicKeyInfo: { algorithm: { oid: keyOid, parameters: alg.children.length > 1 ? alg.children[1].bytes : undefined } } };
}
// The raw subject Name TLV of a parsed CA certificate (byte-identical, so the child issuer chains to
// the CA subject exactly). The subject follows the optional version [0], serial, signature, issuer,
// and validity in the tbsCertificate.
function _caSubjectBytes(caCert) {
  var tbs = asn1.decode(caCert.tbsBytes);
  var hasVersion = tbs.children[0].tagClass === "context" && tbs.children[0].tagNumber === 0;
  return tbs.children[(hasVersion ? 1 : 0) + 4].bytes;   // [version?] serial(0) sig(1) issuer(2) validity(3) SUBJECT(4)
}
// Confirm the produced signature verifies under the ISSUER public key, so a signing key that does not
// correspond to it cannot silently yield a certificate that fails to chain. Verifying the actual
// signature is key-type-agnostic -- it holds for a PKCS#8 key, a WebCrypto CryptoKey, or any signer --
// where deriving-and-comparing the public key cannot (a non-extractable CryptoKey has no exportable
// public half). A composite {mldsa, trad} arm is the caller's to pair and is skipped here.
function _assertCertVerifies(tbsDer, sig, issuerSpki, scheme) {
  if (scheme.composite) {
    // Verify BOTH composite component signatures against the composite public key.
    return compositeSig.compositeVerify(issuerSpki, sig, tbsDer, scheme.composite, CertificateError, "x509/unsupported-algorithm", "x509/bad-input").then(function (r) {
      if (!r.ok) throw _err("x509/bad-input", "the composite signing key does not correspond to the issuer public key -- the certificate would not chain");
    });
  }
  var pub;
  try { pub = nodeCrypto.createPublicKey({ key: issuerSpki, format: "der", type: "spki" }); }
  catch (e) { throw _err("x509/bad-input", "the issuer public key could not be imported for the chain self-check", e); }
  var s = scheme.sign, ok;
  try {
    if (s.name === "ECDSA") ok = nodeCrypto.verify(scheme.digest, tbsDer, { key: pub, dsaEncoding: "der" }, sig);
    else if (s.name === "RSA-PSS") ok = nodeCrypto.verify(scheme.digest, tbsDer, { key: pub, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: s.saltLength }, sig);
    else if (s.name === "RSASSA-PKCS1-v1_5") ok = nodeCrypto.verify(scheme.digest, tbsDer, pub, sig);
    // allow:eddsa-verify-without-loworder-gate -- this is a self-check that OUR just-produced signature
    // verifies under the issuer key the caller controls, not a security verify of an untrusted EdDSA
    // signature, so the low-order-point gate (a forged-signature defense) does not apply.
    else ok = nodeCrypto.verify(null, tbsDer, pub, sig);   // Ed25519 / Ed448 / ML-DSA / SLH-DSA
  } catch (e) { throw _err("x509/bad-input", "the chain self-check could not run against the issuer public key", e); }
  if (!ok) throw _err("x509/bad-input", "the signing key does not correspond to the issuer public key -- the certificate would not chain");
}
// Does the extensions spec carry a subjectAltName that will be emitted critical? The object form forces
// SAN critical when the subject is empty (so any subjectAltName qualifies); the pre-encoded array form
// is decoded to look for an Extension whose extnID is subjectAltName with a TRUE critical flag.
function _hasCriticalSan(extSpec) {
  if (extSpec == null) return false;
  if (!Array.isArray(extSpec)) return !!extSpec.subjectAltName;
  var sanOid = O("subjectAltName");
  for (var i = 0; i < extSpec.length; i++) {
    var n = asn1.decode(_reqDer(extSpec[i], "extension"));
    if (n.children.length === 3 && asn1.read.oid(n.children[0]) === sanOid && asn1.read.boolean(n.children[1]) === true) return true;
  }
  return false;
}

// ---- the primitive ---------------------------------------------------------

/**
 * @primitive pki.x509.sign
 * @signature pki.x509.sign(spec, issuer, opts?) -> Promise<Buffer|string>
 * @since 0.3.0
 * @status stable
 * @spec RFC 5280 sec. 4, RFC 9909, RFC 9814
 * @defends forged-certificate-issuance (CWE-347)
 * @related pki.schema.x509.parse, pki.path.validate, pki.cms.sign
 *
 * Build, sign, and DER-encode an X.509 certificate. `spec` describes the certificate to issue --
 * `subject` (a string CN, an array of RDNs, or raw Name DER), `subjectPublicKey` (the SPKI DER of the
 * key being certified), `notBefore` / `notAfter` (`Date`s), an optional `serialNumber`, and an optional
 * `extensions` object. `issuer` is the signing side: `{ key }` alone issues a self-signed certificate
 * (issuer = subject, signed with the subject's own key); `{ name, publicKey, key }` or `{ cert, key }`
 * issues a CA-signed one. The signature algorithm is resolved from the signing key -- RSA (PKCS#1 v1.5
 * or PSS via `opts.pss`), ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm -- so every algorithm the
 * toolkit signs with is available here without a per-algorithm branch.
 *
 * The version is derived from the field set (v3 when extensions are present, else v1). Serial bounds
 * (positive, <= 20 octets), the validity UTCTime/GeneralizedTime cutover, the DER DEFAULT omissions
 * (v1 tag, `critical=FALSE`, `cA=FALSE`), and the CA cross-field rules (keyCertSign and
 * pathLenConstraint require cA=TRUE) are all enforced; a violation throws a typed `CertificateError`.
 *
 * @opts
 *   - `pem` (boolean) -- return a PEM `CERTIFICATE` string instead of DER.
 *   - `pss` (boolean) -- sign an RSA key with RSASSA-PSS rather than PKCS#1 v1.5.
 *   - `digestAlgorithm` (string) -- override the message digest where the algorithm permits a choice.
 * @example
 *   var root = await pki.x509.sign(
 *     { subject: "Example Root CA", subjectPublicKey: signerSpki,
 *       notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *       extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } },
 *     { key: signerKeyPkcs8 });
 *   pki.schema.x509.parse(root).subject.dn;   // "CN=Example Root CA"
 */
function sign(spec, issuer, opts) {
  return Promise.resolve().then(function () { return _sign(spec, issuer, opts); });
}

function _sign(spec, issuer, opts) {
  opts = opts || {};
  if (!spec || typeof spec !== "object" || Buffer.isBuffer(spec)) throw _err("x509/bad-input", "the certificate spec must be an object");
  issuer = issuer || {};
  if (issuer.key == null) throw _err("x509/bad-input", "a signing key (issuer.key, a PKCS#8 private key) is required");

  var spki = _reqDer(spec.subjectPublicKey, "spec.subjectPublicKey (the SPKI DER of the certified key)");
  _assertValidSpki(spki, "spec.subjectPublicKey");
  var subjectDer = _encodeName(spec.subject == null ? [] : spec.subject);
  var subjectEmpty = _isEmptyName(subjectDer);

  // Resolve the issuer name + signing-key SPKI. `{ key }` alone -> self-signed.
  var issuerDer, issuerSpki, issuerCert = null;
  var selfSigned = issuer.name == null && issuer.cert == null && issuer.publicKey == null;
  if (selfSigned) {
    issuerDer = subjectDer;
    issuerSpki = spki;
  } else if (issuer.cert != null) {
    issuerCert = (Buffer.isBuffer(issuer.cert) || typeof issuer.cert === "string") ? x509.parse(issuer.cert) : issuer.cert;
    if (!issuerCert || !issuerCert.tbsBytes) throw _err("x509/bad-input", "issuer.cert must be a certificate DER/PEM or a parsed certificate");
    issuerDer = _caSubjectBytes(issuerCert);
    issuerSpki = issuerCert.subjectPublicKeyInfo.bytes;
  } else {
    issuerDer = _encodeName(issuer.name == null ? [] : issuer.name);
    issuerSpki = _reqDer(issuer.publicKey, "issuer.publicKey (the issuer SPKI DER)");
  }
  // RFC 5280 sec. 4.1.2.4 -- the issuer MUST be a non-empty distinguished name.
  if (_isEmptyName(issuerDer)) throw _err("x509/bad-issuer", "issuer must be a non-empty distinguished name");

  // Resolve the signature scheme from the SIGNING key's SPKI algorithm (the whole registry, for free).
  var scheme = signScheme.resolveSignScheme(_certLikeFromSpki(issuerSpki), { combinedRsaSig: true, pss: opts.pss, digestAlgorithm: opts.digestAlgorithm }, true, _signE);

  var serialTlv = _serialInteger(spec.serialNumber);
  // Validate both instants, then reject an inverted window before encoding (a notBefore after notAfter
  // is a nonsensical validity period, RFC 5280 sec. 4.1.2.5).
  guard.time.assertValid(spec.notBefore, _err, "x509/bad-input", "notBefore");
  guard.time.assertValid(spec.notAfter, _err, "x509/bad-input", "notAfter");
  // allow:nan-date-comparison-unguarded -- both operands are guard.time.assertValid'd on the two lines above (an Invalid Date throws before this comparison).
  if (spec.notBefore.getTime() > spec.notAfter.getTime()) throw _err("x509/bad-input", "notBefore must not be after notAfter (RFC 5280 sec. 4.1.2.5)");
  var validityDer = b.sequence([_timeDer(spec.notBefore, "notBefore"), _timeDer(spec.notAfter, "notAfter")]);

  var exts = _buildExtensions(spec.extensions, { spki: spki, issuerSpki: issuerSpki, issuerCert: issuerCert, subjectEmpty: subjectEmpty });
  // RFC 5280 sec. 4.1.2.6 -- an empty subject requires a critical subjectAltName (recognized in both the
  // object form and a pre-encoded array-form extension).
  if (subjectEmpty && !_hasCriticalSan(spec.extensions)) {
    throw _err("x509/bad-input", "an empty subject requires a critical subjectAltName (RFC 5280 sec. 4.1.2.6)");
  }
  // Version is derived from the emitted field set (RFC 5280 sec. 4.1.2.1); the builder never emits
  // unique identifiers, so extensions => v3, otherwise v1 (the [0] tag is omitted under DER DEFAULT).
  var version = exts.length ? 3 : 1;

  var tbsChildren = [];
  if (version !== 1) tbsChildren.push(b.explicit(0, b.integer(BigInt(version - 1))));   // v2->INTEGER 1, v3->INTEGER 2
  tbsChildren.push(serialTlv);
  tbsChildren.push(scheme.sigAlgId);   // signature == signatureAlgorithm (RFC 5280 sec. 4.1.1.2), single source
  tbsChildren.push(issuerDer);
  tbsChildren.push(validityDer);
  tbsChildren.push(subjectDer);
  tbsChildren.push(b.raw(spki));
  if (exts.length) tbsChildren.push(b.explicit(3, b.sequence(exts)));
  var tbsDer = b.sequence(tbsChildren);

  return signScheme.signOverTbs(scheme, issuer.key, tbsDer, _signE).then(function (sig) {
    // The signature MUST verify under the issuer public key, or the certificate would not chain (the
    // composite arm returns a promise; the classical/PQC path throws synchronously on a mismatch).
    return Promise.resolve(_assertCertVerifies(tbsDer, sig, issuerSpki, scheme)).then(function () {
      var certDer = b.sequence([tbsDer, scheme.sigAlgId, b.bitString(sig, 0)]);
      return opts.pem ? x509.pemEncode(certDer, "CERTIFICATE") : certDer;
    });
  }, function (e) {
    // A signing failure at a well-formed tbs is a bad signing key or a key/algorithm mismatch; keep a
    // typed CertificateError (composite key-shape faults already are), and re-type a raw WebCrypto
    // rejection to x509/bad-input rather than leaking a DOMException from the boundary.
    if (e instanceof CertificateError) throw e;
    throw _err("x509/bad-input", "signing the certificate failed -- the signing key does not match the resolved algorithm or is invalid", e);
  });
}

module.exports = { sign: sign };
