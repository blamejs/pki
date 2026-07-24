// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the pki.cms.encrypt implementation. The operator-facing @module pki.cms + the
// @primitive pki.cms.encrypt block live in cms-verify.js, which re-exports this function (the
// cms-sign.js model).
//
// CMS EnvelopedData / AuthEnvelopedData / EncryptedData production (RFC 5652/5083/5084/3560/5753/
// 8418/9629/9936/3211/8018), the producing side of pki.cms.decrypt. It is the crypto layer over
// the shipped strict parser (schema-cms.js): one fresh content-encryption key is wrapped for
// every recipient (RFC 5652 sec. 6.1), each RecipientInfo arm dispatched off the recipient's key
// material (RSA -> ktri OAEP; EC -> kari stdDH; X25519/X448 -> kari HKDF; ML-KEM -> ori/KEMRI;
// password -> pwri; symmetric KEK -> kekri) through the OID-keyed registry, never a hardcoded
// switch. AEAD (AES-GCM) content is the default and yields AuthEnvelopedData; CBC yields
// EnvelopedData. PKCS#1 v1.5 is NEVER emitted.

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var schemaCms = require("./schema-cms");
var webcrypto = require("./webcrypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var pbes2 = require("./pbes2");
var b = asn1.build;
var subtle = webcrypto.webcrypto.subtle;
var CmsError = frameworkError.CmsError;
var WRAP_KEK_LENGTHS = schemaCms.WRAP_KEK_LENGTHS;

function O(n) { return oid.byName(n); }
function _err(code, message, cause) { return new CmsError(code, message, cause); }

// An AlgorithmIdentifier { OID } (absent params) or { OID, NULL }.
function _algId(name, shape) { return shape === "null" ? b.sequence([b.oid(O(name)), b.nullValue()]) : b.sequence([b.oid(O(name))]); }

// A certificate descriptor -> raw DER (the recipient cert is parsed for dispatch + rid; the caller
// supplies bytes, not a re-encoded parse).
function _normCertDer(cert, what) {
  if (Buffer.isBuffer(cert)) return cert;
  if (cert instanceof Uint8Array) return Buffer.from(cert);
  if (typeof cert === "string") { try { return x509.pemDecode(cert); } catch (e) { throw _err("cms/bad-input", (what || "a certificate") + " PEM could not be decoded", e); } }
  throw _err("cms/bad-input", (what || "a certificate") + " must be a DER Buffer, Uint8Array, or PEM string");
}

// ---- content-encryption algorithms (registry, not switch) ------------------
// name -> { oid, keyBits, aead }. AEAD (GCM) -> AuthEnvelopedData; CBC -> EnvelopedData.
var CONTENT_ALGS = {
  "aes-128-gcm": { oid: "aes128-GCM", keyBits: 128, aead: true },
  "aes-192-gcm": { oid: "aes192-GCM", keyBits: 192, aead: true },
  "aes-256-gcm": { oid: "aes256-GCM", keyBits: 256, aead: true },
  "aes-128-cbc": { oid: "aes128-CBC", keyBits: 128, aead: false },
  "aes-192-cbc": { oid: "aes192-CBC", keyBits: 192, aead: false },
  "aes-256-cbc": { oid: "aes256-CBC", keyBits: 256, aead: false },
};

// The AES key-wrap OID for a KEK of `keyBytes` octets (16/24/32 -> aes128/192/256-wrap).
function _wrapOidForKek(keyBytes) {
  if (keyBytes === 16) return "aes128-wrap";
  if (keyBytes === 24) return "aes192-wrap";
  if (keyBytes === 32) return "aes256-wrap";
  // Coverage residual: unreachable via the API -- a KEK/CEK is always an AES key size (16/24/32);
  // a defensive throw for a future caller that hands an off-size key.
  throw _err("cms/bad-input", "no AES key-wrap algorithm for a " + keyBytes + "-octet key-encryption key");
}

// GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING, aes-ICVlen INTEGER DEFAULT 12 } -- the
// DEFAULT 12 is OMITTED on emit (RFC 5084 sec. 3.2 / canonical DER).
function _gcmParams(nonce, icvLen) {
  var kids = [b.octetString(nonce)];
  if (icvLen !== 12) kids.push(b.integer(BigInt(icvLen)));
  return b.sequence(kids);
}

// The keyIdentifier option selects the RecipientIdentifier form. "issuerAndSerial" is the documented
// default (its RFC name issuerAndSerialNumber is accepted too); reject anything else rather than
// silently emitting issuerAndSerialNumber, so a typo surfaces instead of a rid the caller never asked for.
function _assertKeyIdentifier(form) {
  if (form != null && form !== "issuerAndSerial" && form !== "issuerAndSerialNumber" && form !== "subjectKeyIdentifier") {
    throw _err("cms/bad-input", "unsupported keyIdentifier " + JSON.stringify(form) + " (use \"issuerAndSerial\" or \"subjectKeyIdentifier\")");
  }
}
// The RecipientIdentifier (rid) for a parsed cert: issuerAndSerialNumber (default) or
// subjectKeyIdentifier [0] IMPLICIT. Both forms per RFC 5652 sec. 6.2.1.
function _rid(cert, form) {
  _assertKeyIdentifier(form);
  if (form === "subjectKeyIdentifier") {
    var ski = _skiOf(cert);
    if (!ski) throw _err("cms/bad-input", "keyIdentifier: \"subjectKeyIdentifier\" requires the recipient certificate to carry a subjectKeyIdentifier extension");
    return { node: b.contextPrimitive(0, ski), riVersion: 2 };
  }
  return { node: b.sequence([b.raw(cert.issuer.bytes), b.integer(cert.serialNumber)]), riVersion: 0 };
}
// Coverage residual (the malformed-extension catch arms in _skiOf + _assertKeyUsage, and the
// unsupported-curve / low-order / unsupported-KEM-cert throws further below): these validate the
// CALLER's own recipient certificate at config time (tier-1 THROW). They fire only when a caller
// supplies a certificate whose SKI/keyUsage extension is malformed, or whose key is an unsupported
// curve / a low-order Montgomery point / an unsupported KEM -- inputs the toolkit never produces.
function _skiOf(cert) {
  var exts = cert.extensions || [];
  for (var i = 0; i < exts.length; i++) if (exts[i].name === "subjectKeyIdentifier" && exts[i].value != null) {
    try { return asn1.read.octetString(asn1.decode(exts[i].value)); } catch (e) { throw _err("cms/bad-input", "the certificate's subjectKeyIdentifier extension is malformed", e); }
  }
  return null;
}

// keyUsage bit assertion (M9/M15): a recipient cert WITH a keyUsage extension MUST assert `bitName`.
var KU_BIT = { digitalSignature: 0, keyEncipherment: 2, dataEncipherment: 3, keyAgreement: 4 };
function _assertKeyUsage(cert, bitName, arm) {
  var exts = cert.extensions || [];
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].name === "keyUsage" && exts[i].value != null) {
      var ku;
      try { ku = asn1.read.bitString(asn1.decode(exts[i].value)); } catch (e) { throw _err("cms/bad-input", "the recipient certificate's keyUsage extension is malformed", e); }
      var idx = KU_BIT[bitName], byteI = idx >> 3, mask = 0x80 >> (idx & 7);
      if (byteI >= ku.bytes.length || (ku.bytes[byteI] & mask) === 0) throw _err("cms/bad-key-usage", "the " + arm + " recipient certificate's keyUsage does not assert " + bitName);
      return;
    }
  }
}

// ---- ktri (RSA) : RSAES-OAEP, SHA-256 default (v1.5 never emitted) ---------
var OAEP_HASH = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
function _oaepParams(hashName) {
  var hAlg = _algId(hashName, "null");
  var mgf = b.sequence([b.oid(O("mgf1")), hAlg]);
  // pSourceAlgorithm [2] DEFAULT pSpecifiedEmpty -- the empty-label default MUST be omitted (X.690).
  return b.sequence([b.explicit(0, hAlg), b.explicit(1, mgf)]);
}
async function _buildKtri(cek, cert, opts) {
  _assertKeyUsage(cert, "keyEncipherment", "ktri");
  var hashName = opts.oaepHash || "sha256";
  if (!OAEP_HASH[hashName]) throw _err("cms/bad-input", "unsupported oaepHash " + JSON.stringify(hashName));
  var pub = await subtle.importKey("spki", cert.subjectPublicKeyInfo.bytes, { name: "RSA-OAEP", hash: OAEP_HASH[hashName] }, false, ["encrypt"]);
  var encryptedKey = Buffer.from(await subtle.encrypt({ name: "RSA-OAEP" }, pub, cek));
  var rid = _rid(cert, opts.keyIdentifier);
  var keyEncAlg = b.sequence([b.oid(O("rsaesOaep")), _oaepParams(hashName)]);
  return { tag: null, _riVersion: rid.riVersion, node: b.sequence([b.integer(BigInt(rid.riVersion)), rid.node, keyEncAlg, b.octetString(encryptedKey)]) };
}

// ---- kari (EC / X25519 / X448) : ephemeral-static ECDH ---------------------
var EC_KA = {}; // recipient-curve OID -> { curve, x963: {hash, scheme}, coordLen }
EC_KA[O("prime256v1")] = { curve: "P-256", hash: "SHA-256", scheme: "dhSinglePass-stdDH-sha256kdf-scheme" };
EC_KA[O("secp384r1")] = { curve: "P-384", hash: "SHA-384", scheme: "dhSinglePass-stdDH-sha384kdf-scheme" };
EC_KA[O("secp521r1")] = { curve: "P-521", hash: "SHA-512", scheme: "dhSinglePass-stdDH-sha512kdf-scheme" };
var MONT_KA = {}; // X25519/X448 key OID -> { name, hkdf, scheme }
MONT_KA[O("X25519")] = { name: "X25519", hkdf: "SHA-256", scheme: "dhSinglePass-stdDH-hkdf-sha256-scheme" };
MONT_KA[O("X448")] = { name: "X448", hkdf: "SHA-512", scheme: "dhSinglePass-stdDH-hkdf-sha512-scheme" };

// ECC-CMS-SharedInfo ::= SEQUENCE { keyInfo AlgorithmIdentifier (the wrap, params ABSENT),
//   entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL, suppPubInfo [2] EXPLICIT OCTET STRING } --
// suppPubInfo = the KEK length in BITS, 4-octet big-endian (RFC 5753 sec. 7.2). ONE builder,
// shared by encrypt + decrypt so the two sides cannot diverge.
function _eccSharedInfo(wrapName, ukm, kekBytes) {
  var kids = [_algId(wrapName, "absent")];
  if (ukm) kids.push(b.explicit(0, b.octetString(ukm)));
  var supp = Buffer.alloc(4); supp.writeUInt32BE(kekBytes * 8, 0);
  kids.push(b.explicit(2, b.octetString(supp)));
  return b.sequence(kids);
}
async function _buildKari(cek, cert, opts) {
  _assertKeyUsage(cert, "keyAgreement", "kari");
  var keyAlg = cert.subjectPublicKeyInfo.algorithm;
  var wrapName = _wrapOidForKek(cek.length);
  var ukm = opts.ukm ? guard.bytes.view(opts.ukm, CmsError, "cms/bad-input", "ukm") : null;
  var ecdhPub, origKeyAlgId, kek;
  if (keyAlg.oid === O("ecPublicKey")) {
    var curveOid = asn1.read.oid(asn1.decode(keyAlg.parameters));
    var ka = EC_KA[curveOid];
    if (!ka) throw _err("cms/unsupported-algorithm", "unsupported recipient EC curve for kari");
    var recipPub = await subtle.importKey("spki", cert.subjectPublicKeyInfo.bytes, { name: "ECDH", namedCurve: ka.curve }, false, []);
    var eph = await subtle.generateKey({ name: "ECDH", namedCurve: ka.curve }, true, ["deriveBits"]);
    origKeyAlgId = { spki: Buffer.from(await subtle.exportKey("spki", eph.publicKey)), scheme: ka.scheme };
    var z = Buffer.from(await subtle.deriveBits({ name: "ECDH", public: recipPub }, eph.privateKey, null));
    var zKey = await subtle.importKey("raw", z, { name: "X963KDF" }, false, ["deriveBits"]);
    var sharedInfo = _eccSharedInfo(wrapName, ukm, cek.length);
    kek = Buffer.from(await subtle.deriveBits({ name: "X963KDF", hash: ka.hash, info: sharedInfo }, zKey, cek.length * 8));
    void ecdhPub;
  } else if (MONT_KA[keyAlg.oid]) {
    var mka = MONT_KA[keyAlg.oid];
    var rPub = await subtle.importKey("spki", cert.subjectPublicKeyInfo.bytes, { name: mka.name }, false, []);
    var meph = await subtle.generateKey({ name: mka.name }, true, ["deriveBits"]);
    origKeyAlgId = { spki: Buffer.from(await subtle.exportKey("spki", meph.publicKey)), scheme: mka.scheme };
    var mz = Buffer.from(await subtle.deriveBits({ name: mka.name, public: rPub }, meph.privateKey, null));
    if (mz.every(function (x) { return x === 0; })) throw _err("cms/bad-input", "the X25519/X448 shared secret is all-zero (low-order point)");
    var mzKey = await subtle.importKey("raw", mz, { name: "HKDF" }, false, ["deriveBits"]);
    // RFC 8418 sec. 2.2: when a ukm is present it is used BOTH as the HKDF salt AND as the
    // ECC-CMS-SharedInfo entityUInfo (the HKDF info) -- omitting it from the info diverges the KEK
    // from any conformant peer that reads the transmitted ukm.
    kek = Buffer.from(await subtle.deriveBits({ name: "HKDF", hash: mka.hkdf, salt: ukm || Buffer.alloc(0), info: _eccSharedInfo(wrapName, ukm, cek.length) }, mzKey, cek.length * 8));
  } else {
    // Coverage residual: unreachable -- _buildRecipient routes only ecPublicKey / X25519 / X448
    // keys into _buildKari; a defensive throw against a future dispatch change.
    throw _err("cms/unsupported-algorithm", "unsupported recipient key algorithm for kari");
  }
  var encryptedKey = await _aesKwWrap(kek, cek);
  // originatorKey [1] IMPLICIT OriginatorPublicKey { algorithm, publicKey BIT STRING }.
  var origSpki = asn1.decode(origKeyAlgId.spki);
  var origPubBits = origSpki.children[1]; // BIT STRING node
  var originatorKey = b.contextConstructed(1, Buffer.concat([origSpki.children[0].bytes, origPubBits.bytes]));
  // KeyAgreeRecipientIdentifier CHOICE { issuerAndSerialNumber, rKeyId [0] IMPLICIT
  // RecipientKeyIdentifier } -- the SKI form here wraps a SEQUENCE (rKeyId), unlike ktri's bare
  // subjectKeyIdentifier [0] IMPLICIT OCTET STRING.
  var ridNode;
  _assertKeyIdentifier(opts.keyIdentifier);
  if (opts.keyIdentifier === "subjectKeyIdentifier") {
    var ski = _skiOf(cert);
    if (!ski) throw _err("cms/bad-input", "keyIdentifier: \"subjectKeyIdentifier\" requires the recipient certificate to carry a subjectKeyIdentifier extension");
    ridNode = b.contextConstructed(0, b.octetString(ski));
  } else {
    ridNode = b.sequence([b.raw(cert.issuer.bytes), b.integer(cert.serialNumber)]);
  }
  var rek = b.sequence([b.sequence([ridNode, b.octetString(encryptedKey)])]); // RecipientEncryptedKeys SEQ OF { rid, encKey }
  var kekAlg = b.sequence([b.oid(O(origKeyAlgId.scheme)), _algId(wrapName, "absent")]);
  var kariKids = [b.integer(3n), b.explicit(0, originatorKey)];
  if (ukm) kariKids.push(b.explicit(1, b.octetString(ukm)));
  kariKids.push(kekAlg, rek);
  return { tag: 1, node: b.sequence(kariKids) };
}

// ---- kekri (symmetric KEK) : AES-KW --------------------------------------
async function _buildKekri(cek, desc) {
  var kek = guard.bytes.view(desc.kek, CmsError, "cms/bad-input", "kek");
  if (desc.kekId == null) throw _err("cms/bad-input", "a kek recipient needs a kekId");
  var wrapName = _wrapOidForKek(kek.length);
  var encryptedKey = await _aesKwWrap(kek, cek);
  var kekid = b.sequence([b.octetString(guard.bytes.view(desc.kekId, CmsError, "cms/bad-input", "kekId"))]);
  return { tag: 2, node: b.sequence([b.integer(4n), kekid, _algId(wrapName, "absent"), b.octetString(encryptedKey)]) };
}

// A PBKDF2 iterationCount MUST be a positive integer within the same cap the decryptor enforces -- a
// ---- pwri (password) : PBKDF2 + RFC 3211 double-CBC PWRI-KEK ---------------
async function _buildPwri(cek, desc) {
  var password = pbes2.passwordBytes(desc.password, _err, "cms");
  var iterations = pbes2.assertIterations(desc.iterations == null ? 600000 : desc.iterations, _err, "cms");
  var salt = desc.salt ? pbes2.assertSalt(guard.bytes.view(desc.salt, CmsError, "cms/bad-input", "salt"), _err, "cms") : nodeCrypto.randomBytes(16);
  var prf = desc.prf || "hmacWithSHA256";
  var innerKeyBytes = 32; // AES-256-CBC inner
  var kekKey = await subtle.importKey("raw", password, { name: "PBKDF2" }, false, ["deriveBits"]);
  var kek = Buffer.from(await subtle.deriveBits({ name: "PBKDF2", hash: _prfHash(prf), salt: salt, iterations: iterations }, kekKey, innerKeyBytes * 8));
  // The RFC 3211 double-CBC wrap under an inner AES-256-CBC whose IV is carried in the
  // keyEncryptionAlgorithm parameter (id-alg-PWRI-KEK parameter = the inner cipher AlgorithmIdentifier).
  var iv = nodeCrypto.randomBytes(16);
  var encryptedKey = _pwriWrapIv(kek, cek, iv);
  // PBKDF2-params as keyDerivationAlgorithm [0] IMPLICIT.
  var kdfParams = pbes2.pbkdf2ParamsSeq(salt, iterations, prf);
  var kdfAlg = b.contextConstructed(0, Buffer.concat([b.oid(O("pbkdf2")), kdfParams]));
  var keyEncAlg = b.sequence([b.oid(O("id-alg-PWRI-KEK")), b.sequence([b.oid(O("aes256-CBC")), b.octetString(iv)])]);
  return { tag: 3, node: b.sequence([b.integer(0n), kdfAlg, keyEncAlg, b.octetString(encryptedKey)]) };
}

// ---- kemri (ML-KEM ori) : RFC 9629 + 9936 ---------------------------------
var KEM_WRAP = {}; // ML-KEM OID -> wrap name (RFC 9936 sec. 2.2.1)
KEM_WRAP[O("id-ml-kem-512")] = "aes128-wrap";
KEM_WRAP[O("id-ml-kem-768")] = "aes256-wrap";
KEM_WRAP[O("id-ml-kem-1024")] = "aes256-wrap";
var KEM_WC = {}; KEM_WC[O("id-ml-kem-512")] = "ML-KEM-512"; KEM_WC[O("id-ml-kem-768")] = "ML-KEM-768"; KEM_WC[O("id-ml-kem-1024")] = "ML-KEM-1024";

// CMSORIforKEMOtherInfo ::= SEQUENCE { wrap AlgorithmIdentifier, kekLength INTEGER,
//   ukm [0] EXPLICIT OCTET STRING OPTIONAL } -- the RFC 9629 sec. 5 KDF info, one builder both sides.
function _kemOtherInfo(wrapName, kekBytes, ukm) {
  var kids = [_algId(wrapName, "absent"), b.integer(BigInt(kekBytes))];
  if (ukm) kids.push(b.explicit(0, b.octetString(ukm)));
  return b.sequence(kids);
}
async function _buildKemri(cek, cert, opts) {
  _assertKeyUsage(cert, "keyEncipherment", "kemri");
  var keyOid = cert.subjectPublicKeyInfo.algorithm.oid;
  var wcName = KEM_WC[keyOid];
  if (!wcName) throw _err("cms/unsupported-algorithm", "unsupported KEM recipient key algorithm");
  var wrapName = KEM_WRAP[keyOid];
  var kekBytes = WRAP_KEK_LENGTHS[O(wrapName)];
  var ukm = opts.ukm ? guard.bytes.view(opts.ukm, CmsError, "cms/bad-input", "ukm") : null;
  var pub = await subtle.importKey("spki", cert.subjectPublicKeyInfo.bytes, { name: wcName }, false, ["encapsulateBits"]);
  var kem = await subtle.encapsulateBits({ name: wcName }, pub);
  var ss = Buffer.from(kem.sharedKey), kemct = Buffer.from(kem.ciphertext);
  var ssKey = await subtle.importKey("raw", ss, { name: "HKDF" }, false, ["deriveBits"]);
  var kek = Buffer.from(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: Buffer.alloc(0), info: _kemOtherInfo(wrapName, kekBytes, ukm) }, ssKey, kekBytes * 8));
  var encryptedKey = await _aesKwWrap(kek, cek);
  var rid = _rid(cert, opts.keyIdentifier);
  var kemriKids = [b.integer(0n), rid.node, _algId(oid.name(keyOid), "absent"), b.octetString(kemct), _algId("hkdfWithSha256", "absent"), b.integer(BigInt(kekBytes))];
  if (ukm) kemriKids.push(b.explicit(0, b.octetString(ukm)));
  kemriKids.push(_algId(wrapName, "absent"), b.octetString(encryptedKey));
  var kemri = b.sequence(kemriKids);
  return { tag: 4, node: b.sequence([b.oid(O("kem")), kemri]) };
}

// AES-KW wrap of the CEK under a raw KEK.
async function _aesKwWrap(kek, cek) {
  var kekKey = await subtle.importKey("raw", kek, { name: "AES-KW" }, false, ["wrapKey"]);
  var cekKey = await subtle.importKey("raw", cek, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);
  return Buffer.from(await subtle.wrapKey("raw", cekKey, kekKey, { name: "AES-KW" }));
}

// RFC 3211 sec. 2.3.1 wrap formatting + double-CBC (sec. 2.3.2).
function _pwriFormat(cek) {
  var count = cek.length;
  // Coverage residual: for the AES CEK sizes the toolkit produces (16/24/32), `count` is always in
  // range, `body` (4 + count) is never a 16-octet multiple, and `body + padLen` always reaches the
  // 2-block minimum -- so the out-of-range throw and the two zero/underflow pad arms never fire.
  if (count < 1 || count > 255) throw _err("cms/bad-input", "the CEK length is out of the RFC 3211 range");
  var check = Buffer.from([count, cek[0] ^ 0xff, cek[1] ^ 0xff, cek[2] ^ 0xff]);
  var body = Buffer.concat([check, cek]);
  var blk = 16;
  var padLen = body.length % blk === 0 ? 0 : blk - (body.length % blk);
  if (body.length + padLen < 2 * blk) padLen += (2 * blk - (body.length + padLen));
  return Buffer.concat([body, nodeCrypto.randomBytes(padLen)]);
}
function _pwriWrapIv(kek, cek, iv) {
  var wk = _pwriFormat(cek);
  var c1 = nodeCrypto.createCipheriv("aes-256-cbc", kek, iv); c1.setAutoPadding(false);
  var pass1 = Buffer.concat([c1.update(wk), c1.final()]);
  var iv2 = pass1.subarray(pass1.length - 16);
  var c2 = nodeCrypto.createCipheriv("aes-256-cbc", kek, iv2); c2.setAutoPadding(false);
  return Buffer.concat([c2.update(pass1), c2.final()]);
}

var PRF_HASH = { hmacWithSHA1: "SHA-1", hmacWithSHA256: "SHA-256", hmacWithSHA384: "SHA-384", hmacWithSHA512: "SHA-512" };
function _prfHash(prf) { if (!PRF_HASH[prf]) throw _err("cms/bad-input", "unsupported pwri prf " + JSON.stringify(prf)); return PRF_HASH[prf]; }

// ---- recipient dispatch ----------------------------------------------------
async function _buildRecipient(cek, desc, opts) {
  if (desc == null || typeof desc !== "object") throw _err("cms/bad-input", "each recipient must be a descriptor object");
  if (desc.password != null) return _buildPwri(cek, desc);
  if (desc.kek != null) return _buildKekri(cek, desc);
  if (desc.cert != null) {
    var cert = x509.parse(_normCertDer(desc.cert, "a recipient certificate"));
    var keyOid = cert.subjectPublicKeyInfo.algorithm.oid;
    if (keyOid === O("rsaEncryption") || keyOid === O("rsassaPss")) return _buildKtri(cek, cert, mergeOpts(opts, desc));
    if (keyOid === O("ecPublicKey") || MONT_KA[keyOid]) return _buildKari(cek, cert, mergeOpts(opts, desc));
    if (KEM_WC[keyOid]) return _buildKemri(cek, cert, mergeOpts(opts, desc));
    throw _err("cms/unsupported-algorithm", "unsupported recipient certificate key algorithm " + keyOid);
  }
  throw _err("cms/bad-input", "a recipient needs { cert }, { password }, or { kek, kekId }");
}
function mergeOpts(opts, desc) {
  return { oaepHash: desc.oaepHash || opts.oaepHash, keyIdentifier: desc.keyIdentifier || opts.keyIdentifier, ukm: desc.ukm != null ? desc.ukm : opts.ukm };
}
// RecipientInfo CHOICE: ktri untagged; kari [1], kekri [2], pwri [3], ori [4] -- all IMPLICIT,
// so the arm's SEQUENCE tag is replaced by the context tag.
function _taggedRecipient(r) {
  if (r.tag == null) return r.node;
  return b.contextConstructed(r.tag, r.node.subarray(_tlvHeaderLen(r.node)));
}

// EnvelopedData version (RFC 5652 sec. 6.1): any pwri/ori -> 3; else any ri v2 or a kari/kekri
// (v3/v4) -> 2; else 0. We never emit originatorInfo/unprotectedAttrs by default.
function _envelopedVersion(recips, hasUnprotected) {
  var anyOri = recips.some(function (r) { return r.tag === 4 || r.tag === 3; }); // pwri(3)/ori(4)
  if (anyOri) return 3;
  var forcesTwo = hasUnprotected || recips.some(function (r) { return r.tag === 1 || r.tag === 2 || (r.tag == null && r._riVersion === 2); });
  return forcesTwo ? 2 : 0;
}

async function encrypt(content, recipients, opts) {
  opts = opts || {};
  var contentBytes = guard.bytes.view(content, CmsError, "cms/bad-input", "content");
  var algName = opts.contentEncryptionAlgorithm || "aes-256-gcm";
  var ca = CONTENT_ALGS[algName];
  if (!ca) throw _err("cms/bad-input", "unsupported contentEncryptionAlgorithm " + JSON.stringify(algName));
  var contentType = opts.contentType || "data";
  var cek = nodeCrypto.randomBytes(ca.keyBits / 8);

  // EncryptedData: a single non-array { cek } or { password } descriptor, no RecipientInfos.
  if (!Array.isArray(recipients)) return _encryptedData(contentBytes, recipients, ca, contentType, opts, cek);

  if (!recipients.length) throw _err("cms/bad-input", "at least one recipient is required (RFC 5652 sec. 6.1)");
  var recips = [];
  for (var i = 0; i < recipients.length; i++) recips.push(await _buildRecipient(cek, recipients[i], opts));
  var riNodes = recips.map(_taggedRecipient);

  if (ca.aead) return _emit(_authEnvelopedData(contentBytes, cek, ca, contentType, opts, riNodes, recips), "authEnvelopedData", opts);
  return _emit(_envelopedData(contentBytes, cek, ca, contentType, riNodes, recips), "envelopedData", opts);
}

function _emit(inner, ctName, opts) {
  var ci = b.sequence([b.oid(O(ctName)), b.explicit(0, inner)]);
  return opts.pem ? schemaCms.pemEncode(ci, "CMS") : ci;
}

function _envelopedData(contentBytes, cek, ca, contentType, riNodes, recips) {
  var iv = nodeCrypto.randomBytes(16);
  var enc = pbes2.cbcEncrypt(cek, iv, contentBytes, ca.keyBits);
  var eci = b.sequence([b.oid(O(contentType)), b.sequence([b.oid(O(ca.oid)), b.octetString(iv)]), b.contextPrimitive(0, enc)]);
  return b.sequence([b.integer(BigInt(_envelopedVersion(recips, false))), b.setOf(riNodes), eci]);
}

function _authEnvelopedData(contentBytes, cek, ca, contentType, opts, riNodes, recips) {
  var nonce = nodeCrypto.randomBytes(12);
  var authAttrsDer = null, aad = Buffer.alloc(0);
  // RFC 5083 sec. 2.1: authAttrs MUST be present when the content type is not id-data. Emitting an
  // AuthEnvelopedData without them for a non-data type produces a message our own strict parser rejects.
  if (contentType !== "data" && !(opts.authAttrs && opts.authAttrs.length)) {
    throw _err("cms/bad-input", "AuthEnvelopedData with a non-data contentType requires authAttrs (RFC 5083 sec. 2.1)");
  }
  if (opts.authAttrs && opts.authAttrs.length) {
    // authAttrs are transmitted [1] IMPLICIT but MACed under the EXPLICIT SET OF tag (RFC 5083 sec. 2.2).
    var setOf = b.setOf(opts.authAttrs);
    aad = setOf; authAttrsDer = b.contextConstructed(1, setOf.subarray(_tlvHeaderLen(setOf)));
  }
  // A 16-octet (128-bit) GCM tag -- the strongest ICV and what OpenSSL emits, so the message
  // interops across OpenSSL 3.5 / 4.x. The aes-ICVlen (16) is carried explicitly (RFC 5084 sec. 3.2
  // omits it ONLY when it equals the DEFAULT 12); it MUST equal the mac octet length (M42).
  var g = _gcmEncrypt(cek, nonce, contentBytes, aad, ca.keyBits, 16);
  var eci = b.sequence([b.oid(O(contentType)), b.sequence([b.oid(O(ca.oid)), _gcmParams(nonce, 16)]), b.contextPrimitive(0, g.ct)]);
  var kids = [b.integer(0n), b.setOf(riNodes), eci];
  if (authAttrsDer) kids.push(authAttrsDer);
  kids.push(b.octetString(g.tag));
  void recips;
  return b.sequence(kids);
}

function _encryptedData(contentBytes, desc, ca, contentType, opts, cek) {
  if (ca.aead) throw _err("cms/bad-input", "EncryptedData supports only CBC content encryption");
  var iv = nodeCrypto.randomBytes(16);
  var contentAlgNode, encKey;
  if (desc && desc.cek != null) {
    encKey = guard.bytes.view(desc.cek, CmsError, "cms/bad-input", "cek");
    if (encKey.length !== ca.keyBits / 8) throw _err("cms/bad-input", "the supplied cek length does not match " + opts.contentEncryptionAlgorithm);
    contentAlgNode = b.sequence([b.oid(O(ca.oid)), b.octetString(iv)]);
  } else if (desc && desc.password != null) {
    return _encryptedDataPbes2(contentBytes, desc, ca, contentType, iv, opts);
  } else {
    throw _err("cms/bad-input", "EncryptedData needs a single { cek } or { password } descriptor");
  }
  var enc = pbes2.cbcEncrypt(encKey, iv, contentBytes, ca.keyBits);
  var eci = b.sequence([b.oid(O(contentType)), contentAlgNode, b.contextPrimitive(0, enc)]);
  var inner = b.sequence([b.integer(0n), eci]);
  return _emit(inner, "encryptedData", opts);
}

function _encryptedDataPbes2(contentBytes, desc, ca, contentType, iv, opts) {
  var password = pbes2.passwordBytes(desc.password, _err, "cms");
  var iterations = pbes2.assertIterations(desc.iterations == null ? 600000 : desc.iterations, _err, "cms");
  var salt = desc.salt ? pbes2.assertSalt(guard.bytes.view(desc.salt, CmsError, "cms/bad-input", "salt"), _err, "cms") : nodeCrypto.randomBytes(16);
  var prf = desc.prf || "hmacWithSHA256";
  var key = nodeCrypto.pbkdf2Sync(password, salt, iterations, ca.keyBits / 8, pbes2.prfNodeByName(prf, _err, "cms"));
  var enc = pbes2.cbcEncrypt(key, iv, contentBytes, ca.keyBits);
  var contentAlg = pbes2.pbes2AlgId(salt, iterations, prf, ca.oid, iv);
  var eci = b.sequence([b.oid(O(contentType)), contentAlg, b.contextPrimitive(0, enc)]);
  var inner = b.sequence([b.integer(0n), eci]);
  return _emit(inner, "encryptedData", { pem: opts && opts.pem != null ? opts.pem : desc.pem });
}

// ---- content-encryption primitives ----------------------------------------
function _gcmEncrypt(key, nonce, plaintext, aad, keyBits, tagLen) {
  var c = nodeCrypto.createCipheriv("aes-" + keyBits + "-gcm", key, nonce, { authTagLength: tagLen });
  if (aad && aad.length) c.setAAD(aad);
  var ct = Buffer.concat([c.update(plaintext), c.final()]);
  return { ct: ct, tag: c.getAuthTag() };
}

// The length of a DER TLV's tag+length header (so the SET OF re-tag drops the tag byte(s)).
function _tlvHeaderLen(der) {
  var lenByte = der[1];
  if (lenByte < 0x80) return 2;
  return 2 + (lenByte & 0x7f);
}

// ---- pki.cms.authenticate (RFC 5652 sec. 9 AuthenticatedData) ---------------
// AuthenticatedData carries CLEARTEXT content plus a MAC (no content encryption). A single fresh HMAC
// key is minted, wrapped for every recipient with the EXACT RecipientInfo model EnvelopedData uses for
// the CEK, and the MAC (HMAC-SHA-2) covers either the re-tagged [2] authAttrs SET OF (default) or the
// eContent value octets directly. Homes here (not a new module) so the recipient-wrap helpers are
// module-local; the verify half folds into pki.cms.decrypt.

// The macAlgorithm registry: an OID name + the WebCrypto/node hashes (data-driven, not a switch).
var MAC_ALGS = {
  "hmac-sha256": { oid: "hmacWithSHA256", wc: "SHA-256", node: "sha256" },
  "hmac-sha384": { oid: "hmacWithSHA384", wc: "SHA-384", node: "sha384" },
  "hmac-sha512": { oid: "hmacWithSHA512", wc: "SHA-512", node: "sha512" },
};
// The fresh MAC key length: 32 octets is AES-KW-compatible (16/24/32), so it wraps through every
// recipient arm (kari/kekri/kemri import the wrapped key as AES-CBC) with no codec change, and a
// 32-octet conveyed key is a valid HMAC key for SHA-256/384/512 (RFC 2104).
var MAC_KEY_OCTETS = 32;
// The message-digest hashes the AuthenticatedData verify path (cms-decrypt DIGEST_WC) can consume --
// the producer never emits a digestAlgorithm its own verifier cannot recompute (the no-orphan rule).
var SUPPORTED_DIGEST = { sha256: 1, sha384: 1, sha512: 1 };

async function authenticate(content, recipients, opts) {
  opts = opts || {};
  var contentBytes = guard.bytes.view(content, CmsError, "cms/bad-input", "content");
  var macName = opts.macAlgorithm || "hmac-sha256";
  var mac = MAC_ALGS[macName];
  if (!mac) throw _err("cms/bad-input", "unsupported macAlgorithm " + JSON.stringify(macName) + " (hmac-sha256/384/512)");
  if (!Array.isArray(recipients) || !recipients.length) throw _err("cms/bad-input", "at least one recipient is required (RFC 5652 sec. 9.1)");
  var contentType = opts.contentType || "data";
  var withAttrs = opts.authenticatedAttributes !== false;
  // RFC 5652 sec. 9.1: authAttrs MUST be present when the eContentType is not id-data.
  if (contentType !== "data" && !withAttrs) throw _err("cms/bad-input", "AuthenticatedData with a non-data contentType requires authenticated attributes (RFC 5652 sec. 9.1)");

  var macKey = nodeCrypto.randomBytes(MAC_KEY_OCTETS);
  var recips = [];
  for (var i = 0; i < recipients.length; i++) recips.push(await _buildRecipient(macKey, recipients[i], opts));
  var riNodes = recips.map(_taggedRecipient);

  var digestName = opts.digestAlgorithm || mac.node;
  var digestAlgTagged = null, authAttrsDer = null, preimage;
  if (withAttrs) {
    if (!SUPPORTED_DIGEST[digestName]) throw _err("cms/bad-input", "unsupported digestAlgorithm " + JSON.stringify(digestName) + " (sha256/384/512)");
    // sec. 9.2: content-type (== eContentType) + message-digest (== digest(content)) attributes,
    // SET-OF-sorted, MACed under the EXPLICIT SET OF tag (0x31) but transmitted [2] IMPLICIT (0xA2).
    var mdDigest = nodeCrypto.createHash(digestName).update(contentBytes).digest();
    var pairs = [
      b.sequence([b.oid(O("contentType")), b.setOf([b.oid(O(contentType))])]),
      b.sequence([b.oid(O("messageDigest")), b.setOf([b.octetString(mdDigest)])]),
    ];
    if (opts.authAttrs && opts.authAttrs.length) pairs = pairs.concat(opts.authAttrs);
    // Every authAttr (auto-built or caller-supplied) MUST be a well-formed Attribute SEQUENCE
    // { type OBJECT IDENTIFIER, values SET OF } and each type appears at most once (RFC 5652) -- so a
    // malformed or duplicate caller attribute is rejected BEFORE it is MACed and emitted, never left to
    // fail an operator's parser downstream.
    var seenTypes = {};
    pairs.forEach(function (p) {
      var node;
      try { node = asn1.decode(p); } catch (e) { throw _err("cms/bad-input", "an authenticated attribute is not well-formed DER", e); }
      if (node.tagClass !== "universal" || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children || node.children.length !== 2 ||
        node.children[1].tagClass !== "universal" || node.children[1].tagNumber !== asn1.TAGS.SET ||
        !node.children[1].children || node.children[1].children.length < 1) {
        throw _err("cms/bad-input", "an authenticated attribute must be an Attribute SEQUENCE { type, non-empty SET OF value } (RFC 5652)");
      }
      var t;
      try { t = asn1.read.oid(node.children[0]); } catch (e) { throw _err("cms/bad-input", "an authenticated attribute type is not an OBJECT IDENTIFIER", e); }
      if (seenTypes[t]) throw _err("cms/bad-input", "authenticated attributes must not repeat an attribute type (RFC 5652): " + t);
      seenTypes[t] = 1;
    });
    var setOf = b.setOf(pairs);
    preimage = setOf;                                                            // MAC over the 0x31 SET OF
    authAttrsDer = b.contextConstructed(2, setOf.subarray(_tlvHeaderLen(setOf)));   // [2] IMPLICIT on the wire
    digestAlgTagged = b.contextConstructed(1, b.oid(O(digestName)));             // [1] IMPLICIT DigestAlgorithmIdentifier
  } else {
    preimage = contentBytes;                                                    // MAC over the eContent value octets
  }

  var hmacKey = await subtle.importKey("raw", macKey, { name: "HMAC", hash: mac.wc }, false, ["sign"]);
  var macValue = Buffer.from(await subtle.sign({ name: "HMAC" }, hmacKey, preimage));

  var eci = b.sequence([b.oid(O(contentType)), b.explicit(0, b.octetString(contentBytes))]);
  var kids = [b.integer(0n), b.setOf(riNodes), _algId(mac.oid)];
  if (digestAlgTagged) kids.push(digestAlgTagged);
  kids.push(eci);
  if (authAttrsDer) kids.push(authAttrsDer);
  kids.push(b.octetString(macValue));
  return _emit(b.sequence(kids), "authData", opts);
}

module.exports = { encrypt: encrypt, authenticate: authenticate };
