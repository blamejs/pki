// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the ENCODE-direction sibling of schema-pkix.js (which is decode-only). `makeBuilder(ctx)`
// binds a domain namespace once and returns the shared PKIX producing primitives every signer module
// composes: the distinguished-name encoder, the GeneralName + RFC 5280 sec. 4.2.1 extension-value
// encoders, the embedded-input validators (a raw Name / a SubjectPublicKeyInfo / a pre-encoded Extension
// run through the SAME parser the decoder uses), the sign-scheme bridge, and the post-sign signature
// self-check (the key-match / proof-of-possession verify). Each is parameterized on the CALLER's error
// class + code prefix, so pki.x509.sign keeps x509/* codes and pki.csr.sign keeps csr/*.

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var compositeSig = require("./composite-sig");
var nodeCrypto = require("crypto");

var b = asn1.build;

// KeyUsage named-bit positions (RFC 5280 sec. 4.2.1.3); contentCommitment is the RFC 5280 rename of the
// X.509 nonRepudiation bit (1).
var KU_BIT = {
  digitalSignature: 0, nonRepudiation: 1, contentCommitment: 1, keyEncipherment: 2,
  dataEncipherment: 3, keyAgreement: 4, keyCertSign: 5, cRLSign: 6, encipherOnly: 7, decipherOnly: 8,
};

// makeBuilder(ctx) -> the bound producing primitives. ctx = { ErrorClass, prefix, O, NS, NAME_SCHEMA,
// SPKI_SCHEMA, EXT_DECODERS }. `E(kind, msg, cause)` builds a `<prefix>/<kind>` typed error.
function makeBuilder(ctx) {
  var ErrorClass = ctx.ErrorClass, O = ctx.O, NS = ctx.NS;
  var NAME_SCHEMA = ctx.NAME_SCHEMA, SPKI_SCHEMA = ctx.SPKI_SCHEMA;
  function E(kind, message, cause) { return new ErrorClass(ctx.prefix + "/" + kind, message, cause); }
  function code(kind) { return ctx.prefix + "/" + kind; }

  // ---- distinguished name encoding (RFC 5280 sec. 4.1.2.4) ----
  // countryName is a PrintableString SIZE(2), emailAddress an IA5String; every other new-name attribute
  // is a UTF8String (Teletex/BMP/Universal are backward-compat only and never emitted).
  function atvString(attrName, value) {
    if (attrName === "countryName") {
      if (String(value).length !== 2) throw E("bad-name", "countryName must be a two-letter ISO 3166 code (PrintableString SIZE(2))");
      return b.printable(value);
    }
    if (attrName === "emailAddress") return b.ia5(value);
    return b.utf8(value);
  }
  function encodeAtv(attrName, value) {
    if (value == null || value === "") throw E("bad-name", "the " + attrName + " attribute value must be a non-empty string");
    // oid.byName returns undefined (does not throw) for an unrecognized name -- reject it explicitly.
    var typeOid = O(attrName);
    if (typeOid == null) throw E("bad-name", "unknown distinguished-name attribute " + JSON.stringify(attrName));
    var valueTlv;
    try { valueTlv = atvString(attrName, value); }
    catch (e) { if (e instanceof ErrorClass) throw e; throw E("bad-name", "the " + attrName + " value has characters invalid for its string type", e); }
    return b.sequence([b.oid(typeOid), valueTlv]);
  }
  function encodeRdn(rdnSpec) {
    if (!rdnSpec || typeof rdnSpec !== "object" || Buffer.isBuffer(rdnSpec)) throw E("bad-name", "each RDN must be an object of { attributeName: value }");
    var keys = Object.keys(rdnSpec);
    if (!keys.length) throw E("bad-name", "an RDN must carry at least one attribute");
    return b.set(keys.map(function (k) { return encodeAtv(k, rdnSpec[k]); }));
  }
  // A DN spec -> RDNSequence DER. A string is shorthand for a single commonName RDN; a Buffer is raw
  // pre-encoded Name DER (validated through the parser). An empty array yields an empty RDNSequence.
  function encodeName(spec) {
    if (Buffer.isBuffer(spec)) { assertValidNameDer(spec); return spec; }
    if (typeof spec === "string") spec = [{ commonName: spec }];
    if (!Array.isArray(spec)) throw E("bad-name", "a name must be a string, an array of RDNs, or raw Name DER");
    return b.sequence(spec.map(encodeRdn));
  }
  // Full validation of a raw Name DER: walk it through the exact RDNSequence parser the decoder uses.
  function assertValidNameDer(der) {
    var node;
    try { node = asn1.decode(der); }
    catch (e) { throw E("bad-name", "the raw Name DER is not valid DER", e); }
    try { schema.walk(NAME_SCHEMA, node, NS); }
    catch (e) {
      if (e instanceof ErrorClass || (e && e.name === "Asn1Error")) throw e;
      throw E("bad-name", "the raw Name DER is not a well-formed distinguished name", e);
    }
  }
  function isEmptyName(nameDer) { return asn1.decode(nameDer).children.length === 0; }

  // ---- GeneralName encoding (RFC 5280 sec. 4.2.1.6) ----
  function ia5Content(s) {
    s = String(s);
    for (var i = 0; i < s.length; i++) {
      if (s.charCodeAt(i) > 0x7F) throw E("bad-input", "value requires 7-bit ASCII (IA5String): " + JSON.stringify(s));
    }
    return Buffer.from(s, "latin1");
  }
  function encodeGeneralName(entry) {
    if (!entry || typeof entry !== "object" || Buffer.isBuffer(entry)) throw E("bad-input", "a GeneralName must be an object with exactly one name form");
    var keys = Object.keys(entry);
    if (keys.length !== 1) throw E("bad-input", "a GeneralName entry must have exactly one form, got " + keys.length);
    var k = keys[0], v = entry[k];
    if (v == null || v === "") throw E("bad-input", "an empty GeneralName value is not permitted (RFC 5280 sec. 4.2.1.6)");
    switch (k) {
      case "rfc822Name": return b.contextPrimitive(1, ia5Content(v));
      case "dNSName": return b.contextPrimitive(2, ia5Content(v));
      case "uniformResourceIdentifier": case "uri": return b.contextPrimitive(6, ia5Content(v));
      case "iPAddress":
        if (!Buffer.isBuffer(v) || (v.length !== 4 && v.length !== 16)) throw E("bad-input", "iPAddress must be a 4- or 16-octet Buffer");
        return b.contextPrimitive(7, v);
      case "directoryName": return b.explicit(4, encodeName(v));   // Name is a CHOICE -> the context tag is EXPLICIT
      default: throw E("bad-input", "unsupported GeneralName form " + JSON.stringify(k) + " (supported: rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, directoryName)");
    }
  }

  // ---- extension-value encoders (the inverse of certExtensionDecoders) ----
  function extKeyUsage(names) {
    if (!Array.isArray(names) || !names.length) throw E("bad-input", "keyUsage must assert at least one bit (RFC 5280 sec. 4.2.1.3)");
    var positions = names.map(function (n) {
      var pos = KU_BIT[n];
      if (pos == null) throw E("bad-input", "unknown keyUsage bit " + JSON.stringify(n));
      return pos;
    });
    return b.namedBitString(positions);
  }
  function extExtKeyUsage(names) {
    if (!Array.isArray(names) || !names.length) throw E("bad-input", "extendedKeyUsage must list at least one KeyPurposeId");
    return b.sequence(names.map(function (n) {
      var purposeOid = O(n);
      if (purposeOid == null) throw E("bad-input", "unknown extendedKeyUsage purpose " + JSON.stringify(n));
      return b.oid(purposeOid);
    }));
  }
  function validateBcSpec(bc) {
    if (bc.cA != null && typeof bc.cA !== "boolean") throw E("bad-input", "basicConstraints cA must be a boolean");
    if (bc.critical != null && typeof bc.critical !== "boolean") throw E("bad-input", "basicConstraints critical must be a boolean");
    if (bc.pathLen != null) pathLen(bc.pathLen);
    Object.keys(bc).forEach(function (k) {
      if (k !== "cA" && k !== "pathLen" && k !== "critical") throw E("bad-input", "unknown basicConstraints field " + JSON.stringify(k));
    });
  }
  function extBasicConstraints(spec) {
    var children = [];
    if (spec.cA === true) children.push(b.boolean(true));   // cA=FALSE omitted (DER DEFAULT)
    if (spec.pathLen != null) children.push(b.integer(pathLen(spec.pathLen)));
    return b.sequence(children);
  }
  function pathLen(v) {
    if (typeof v !== "number" || !isFinite(v) || v < 0 || (v | 0) !== v) throw E("bad-input", "basicConstraints pathLenConstraint must be a non-negative integer");
    return BigInt(v);
  }
  function extSki(keyid) { return b.octetString(keyid); }
  function extAki(keyid) { return b.sequence([b.contextPrimitive(0, keyid)]); }   // keyIdentifier [0] IMPLICIT OCTET STRING
  function extSan(entries) {
    if (!Array.isArray(entries) || !entries.length) throw E("bad-input", "subjectAltName must carry at least one GeneralName");
    return b.sequence(entries.map(encodeGeneralName));
  }
  function extCertPolicies(names) {
    if (!Array.isArray(names) || !names.length) throw E("bad-input", "certificatePolicies must list at least one policy OID");
    var seen = {};
    return b.sequence(names.map(function (n) {
      var pOid = O(n);
      if (pOid == null) throw E("bad-input", "unknown certificate policy " + JSON.stringify(n));
      if (seen[pOid]) throw E("bad-input", "duplicate certificate policy " + JSON.stringify(n) + " (RFC 5280 sec. 4.2.1.4)");
      seen[pOid] = true;
      return b.sequence([b.oid(pOid)]);
    }));
  }
  // Wrap a value in Extension ::= SEQUENCE { extnID, critical?, extnValue }; a FALSE critical is omitted.
  function ext(oidStr, critical, valueDer) {
    var children = [b.oid(oidStr)];
    if (critical) children.push(b.boolean(true));
    children.push(b.octetString(valueDer));
    return b.sequence(children);
  }

  // The SHA-1 subjectKeyIdentifier (RFC 5280 sec. 4.2.1.2 method 1): SHA-1 of the subjectPublicKey BIT
  // STRING CONTENT (past the unused-bits octet), NOT the whole SPKI or the BIT STRING TLV.
  function spkiKeyId(spkiDer) {
    var keyBytes = asn1.read.bitString(asn1.decode(spkiDer).children[1]).bytes;
    // nosemgrep: pki-weak-hash-md5-sha1 -- RFC 5280 sec. 4.2.1.2 method 1 DEFINES the subjectKeyIdentifier
    // as the SHA-1 of the subjectPublicKey; this is a key identifier, not a signature or a
    // collision-resistance use, and the algorithm is fixed by the standard.
    return nodeCrypto.createHash("sha1").update(keyBytes).digest();
  }
  function skiKeyId(val, spkiDer) {
    if (Buffer.isBuffer(val)) return val;
    if (val === true) return spkiKeyId(spkiDer);
    throw E("bad-input", "subjectKeyIdentifier must be true (auto-derive) or a Buffer key id");
  }

  // ---- embedded-input validators ----
  function reqDer(v, what) {
    if (Buffer.isBuffer(v)) return v;
    if (v instanceof Uint8Array) return Buffer.from(v);
    throw E("bad-input", what + " must be a DER Buffer");
  }
  // Full validation of an embedded SubjectPublicKeyInfo via the SAME parser the decoder uses.
  function assertValidSpki(spkiDer, what) {
    var node;
    try { node = asn1.decode(spkiDer); }
    catch (e) { throw E("bad-input", what + " is not valid DER", e); }
    try { schema.walk(SPKI_SCHEMA, node, NS); }
    catch (e) {
      if (e instanceof ErrorClass || (e && e.name === "Asn1Error")) throw e;
      throw E("bad-input", what + " is not a well-formed SubjectPublicKeyInfo", e);
    }
  }
  // A pre-encoded Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING };
  // an explicit critical=FALSE is non-canonical (DER DEFAULT) and rejected.
  function assertValidExtension(der, idx) {
    var n;
    try { n = asn1.decode(der); }
    catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] is not valid DER", e); }
    if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length < 2 || n.children.length > 3) throw E("bad-input", "pre-encoded extension [" + idx + "] must be an Extension SEQUENCE { extnID, critical?, extnValue }");
    try { asn1.read.oid(n.children[0]); }
    catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] extnID is not an OBJECT IDENTIFIER", e); }
    if (n.children.length === 3) {
      var crit;
      try { crit = asn1.read.boolean(n.children[1]); }
      catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] critical must be a BOOLEAN", e); }
      if (crit !== true) throw E("bad-input", "pre-encoded extension [" + idx + "] critical=FALSE must be omitted (DER DEFAULT)");
    }
    var last = n.children[n.children.length - 1];
    if (last.tagNumber !== asn1.TAGS.OCTET_STRING || last.tagClass !== "universal") throw E("bad-input", "pre-encoded extension [" + idx + "] extnValue must be an OCTET STRING");
  }
  // Synthesize the parsed-cert shape resolveSignScheme reads (subjectPublicKeyInfo.algorithm) from a raw SPKI.
  function certLikeFromSpki(spkiDer) {
    var spki = asn1.decode(spkiDer);
    if (!spki.children || !spki.children.length) throw E("bad-input", "the signing key SPKI is not a SubjectPublicKeyInfo");
    var alg = spki.children[0];
    var keyOid;
    try { keyOid = asn1.read.oid(alg.children[0]); }
    catch (e) { throw E("bad-input", "the signing key SPKI algorithm is not an OID", e); }
    return { subjectPublicKeyInfo: { algorithm: { oid: keyOid, parameters: alg.children.length > 1 ? alg.children[1].bytes : undefined } } };
  }

  // Confirm the produced signature verifies under `spki` -- key-type-agnostic (a PKCS#8 key, a WebCrypto
  // CryptoKey, or any signer), where deriving-and-comparing the public key cannot (a non-extractable
  // CryptoKey has no exportable public half). This is the x509 chain self-check AND the CSR proof of
  // possession. Composite verifies both components. Returns a promise for composite, sync-throws for classical.
  function assertSignatureVerifies(preimage, sig, spki, scheme) {
    if (scheme.composite) {
      return compositeSig.compositeVerify(spki, sig, preimage, scheme.composite, ErrorClass, code("unsupported-algorithm"), code("bad-input")).then(function (r) {
        if (!r.ok) throw E("bad-input", "the composite signing key does not correspond to the public key -- the signature would not verify");
      });
    }
    var pub;
    try { pub = nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" }); }
    catch (e) { throw E("bad-input", "the public key could not be imported for the signature self-check", e); }
    var s = scheme.sign, ok;
    try {
      if (s.name === "ECDSA") ok = nodeCrypto.verify(scheme.digest, preimage, { key: pub, dsaEncoding: "der" }, sig);
      else if (s.name === "RSA-PSS") ok = nodeCrypto.verify(scheme.digest, preimage, { key: pub, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: s.saltLength }, sig);
      else if (s.name === "RSASSA-PKCS1-v1_5") ok = nodeCrypto.verify(scheme.digest, preimage, pub, sig);
      // allow:eddsa-verify-without-loworder-gate -- a self-check that OUR just-produced signature verifies
      // under the key the caller controls, not a security verify of an untrusted EdDSA signature, so the
      // low-order-point gate (a forged-signature defense) does not apply.
      else ok = nodeCrypto.verify(null, preimage, pub, sig);   // Ed25519 / Ed448 / ML-DSA / SLH-DSA
    } catch (e) { throw E("bad-input", "the signature self-check could not run against the public key", e); }
    if (!ok) throw E("bad-input", "the signing key does not correspond to the public key -- the signature would not verify");
  }

  return {
    E: E, code: code, KU_BIT: KU_BIT,
    encodeName: encodeName, isEmptyName: isEmptyName, encodeGeneralName: encodeGeneralName,
    extKeyUsage: extKeyUsage, extExtKeyUsage: extExtKeyUsage, validateBcSpec: validateBcSpec,
    extBasicConstraints: extBasicConstraints, pathLen: pathLen, extSki: extSki, extAki: extAki,
    extSan: extSan, extCertPolicies: extCertPolicies, ext: ext,
    spkiKeyId: spkiKeyId, skiKeyId: skiKeyId,
    reqDer: reqDer, assertValidSpki: assertValidSpki, assertValidExtension: assertValidExtension,
    certLikeFromSpki: certLikeFromSpki, assertSignatureVerifies: assertSignatureVerifies,
  };
}

module.exports = { makeBuilder: makeBuilder, KU_BIT: KU_BIT };
