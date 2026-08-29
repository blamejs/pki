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
// EnvelopedData. PKCS#1 v1.5 is never emitted.

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var schemaCms = require("./schema-cms");
var webcrypto = require("./webcrypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var pbes2 = require("./pbes2");
var b = asn1.build;
var subtle = webcrypto.webcrypto.subtle;
var pkix = require("./schema-pkix");
var CmsError = frameworkError.CmsError;
var _KU_NS = pkix.makeNS("cms", CmsError, oid);
var WRAP_KEK_LENGTHS = schemaCms.WRAP_KEK_LENGTHS;

function O(n) { return oid.byName(n); }
function _err(code, message, cause) { return new CmsError(code, message, cause); }

// An AlgorithmIdentifier { OID } (absent params) or { OID, NULL }.
function _algId(name, shape) { return shape === "null" ? b.sequence([b.oid(O(name)), b.nullValue()]) : b.sequence([b.oid(O(name))]); }

// A certificate descriptor -> raw DER (the recipient cert is parsed for dispatch + rid; the caller
// supplies bytes, not a re-encoded parse).
function _normCertDer(cert, what) {
  if (guard.bytes.isByteSource(cert)) return guard.bytes.snapshotSource(cert, CmsError, "cms/bad-input", what || "a certificate");
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
  // Coverage residual: unreachable via the API, since a KEK/CEK is always an AES key size (16/24/32);
  // a defensive throw for a future caller that hands an off-size key.
  throw _err("cms/bad-input", "no AES key-wrap algorithm for a " + keyBytes + "-octet key-encryption key");
}

// GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING, aes-ICVlen INTEGER DEFAULT 12 }, where the
// DEFAULT 12 is omitted on emit (RFC 5084 sec. 3.2 / canonical DER).
function _gcmParams(nonce, icvLen) {
  var kids = [b.octetString(nonce)];
  if (icvLen !== 12) kids.push(b.integer(BigInt(icvLen)));
  return b.sequence(kids);
}

// The keyIdentifier option selects the RecipientIdentifier form. "issuerAndSerial" is the documented
// default (its RFC name issuerAndSerialNumber is accepted too); reject anything else instead of
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
// curve, a low-order Montgomery point, or an unsupported KEM: inputs the toolkit never produces.
function _skiOf(cert) {
  var exts = cert.extensions || [];
  for (var i = 0; i < exts.length; i++) if (exts[i].name === "subjectKeyIdentifier" && exts[i].value != null) {
    try { return asn1.read.octetString(asn1.decode(exts[i].value)); } catch (e) { throw _err("cms/bad-input", "the certificate's subjectKeyIdentifier extension is malformed", e); }
  }
  return null;
}

// keyUsage bit assertion (M9/M15): a recipient cert WITH a keyUsage extension MUST assert `bitName`.
// Through the shared reader, which applies the NamedBitList rules a local bit test does not: DER
// drops trailing zero bits (X.690 sec. 11.2.2) and sec. 4.2.1.3 requires at least one bit set, so
// reading the bits here would accept as a recipient a certificate the issuing side calls malformed.
function _assertKeyUsage(cert, bitName, arm) {
  var ku = pkix.keyUsageOf(_KU_NS, cert, _err, "cms/bad-input", "recipient certificate's");
  if (ku && ku[bitName] !== true) throw _err("cms/bad-key-usage", "the " + arm + " recipient certificate's keyUsage does not assert " + bitName);
}

// ---- ktri (RSA) : RSAES-OAEP, SHA-256 default (v1.5 never emitted) ---------
var OAEP_HASH = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };
function _oaepParams(hashName) {
  var hAlg = _algId(hashName, "null");
  var mgf = b.sequence([b.oid(O("mgf1")), hAlg]);
  // pSourceAlgorithm [2] DEFAULT pSpecifiedEmpty: the empty-label default MUST be omitted (X.690).
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
//   entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL, suppPubInfo [2] EXPLICIT OCTET STRING }, where
// suppPubInfo is the KEK length in bits, 4-octet big-endian (RFC 5753 sec. 7.2). One builder,
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
  // z / mz (the raw agreement secret) and the derived kek are all allocated here and all secret.
  // Declared together so one `finally` clears whichever the chosen branch produced, including when
  // a later encoding step throws (RFC 9629 sec. 7 asks the same of the KEM builder below).
  var ecdhPub, origKeyAlgId, kek, z, mz;
  try {
    if (keyAlg.oid === O("ecPublicKey")) {
      var curveOid = asn1.read.oid(asn1.decode(keyAlg.parameters));
      var ka = EC_KA[curveOid];
      if (!ka) throw _err("cms/unsupported-algorithm", "unsupported recipient EC curve for kari");
      var recipPub = await subtle.importKey("spki", cert.subjectPublicKeyInfo.bytes, { name: "ECDH", namedCurve: ka.curve }, false, []);
      var eph = await subtle.generateKey({ name: "ECDH", namedCurve: ka.curve }, true, ["deriveBits"]);
      origKeyAlgId = { spki: Buffer.from(await subtle.exportKey("spki", eph.publicKey)), scheme: ka.scheme };
      z = Buffer.from(await subtle.deriveBits({ name: "ECDH", public: recipPub }, eph.privateKey, null));
      var zKey = await subtle.importKey("raw", z, { name: "X963KDF" }, false, ["deriveBits"]);
      var sharedInfo = _eccSharedInfo(wrapName, ukm, cek.length);
      kek = Buffer.from(await subtle.deriveBits({ name: "X963KDF", hash: ka.hash, info: sharedInfo }, zKey, cek.length * 8));
      void ecdhPub;
    } else if (MONT_KA[keyAlg.oid]) {
      var mka = MONT_KA[keyAlg.oid];
      var rPub = await subtle.importKey("spki", cert.subjectPublicKeyInfo.bytes, { name: mka.name }, false, []);
      var meph = await subtle.generateKey({ name: mka.name }, true, ["deriveBits"]);
      origKeyAlgId = { spki: Buffer.from(await subtle.exportKey("spki", meph.publicKey)), scheme: mka.scheme };
      mz = Buffer.from(await subtle.deriveBits({ name: mka.name, public: rPub }, meph.privateKey, null));
      if (mz.every(function (x) { return x === 0; })) throw _err("cms/bad-input", "the X25519/X448 shared secret is all-zero (low-order point)");
      var mzKey = await subtle.importKey("raw", mz, { name: "HKDF" }, false, ["deriveBits"]);
      // RFC 8418 sec. 2.2: when a ukm is present it is used as both the HKDF salt and the
      // ECC-CMS-SharedInfo entityUInfo (the HKDF info). Omitting it from the info diverges the KEK
      // from any conformant peer that reads the transmitted ukm.
      kek = Buffer.from(await subtle.deriveBits({ name: "HKDF", hash: mka.hkdf, salt: ukm || Buffer.alloc(0), info: _eccSharedInfo(wrapName, ukm, cek.length) }, mzKey, cek.length * 8));
    } else {
      // Coverage residual: unreachable, since _buildRecipient routes only ecPublicKey / X25519 / X448
      // keys into _buildKari; a defensive throw against a future dispatch change.
      throw _err("cms/unsupported-algorithm", "unsupported recipient key algorithm for kari");
    }
    var encryptedKey = await _aesKwWrap(kek, cek);
    // originatorKey [1] IMPLICIT OriginatorPublicKey { algorithm, publicKey BIT STRING }.
    var origSpki = asn1.decode(origKeyAlgId.spki);
    var origPubBits = origSpki.children[1]; // BIT STRING node
    var originatorKey = b.contextConstructed(1, Buffer.concat([origSpki.children[0].bytes, origPubBits.bytes]));
    // KeyAgreeRecipientIdentifier CHOICE { issuerAndSerialNumber, rKeyId [0] IMPLICIT
    // RecipientKeyIdentifier }, where the SKI form wraps a SEQUENCE (rKeyId), unlike ktri's bare
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
  } finally {
    // Buffer.from(arrayBuffer) is a VIEW over the engine's returned buffer, so clearing z / mz
    // clears that allocation too. The CEK belongs to the caller (the message, not this recipient)
    // and is wiped once at the end of encrypt; the ephemeral PUBLIC key is not secret.
    guard.secret.zeroizeAll([z, mz, kek], CmsError, "cms/bad-input", "the key-agreement shared secret");
  }
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

// A PBKDF2 iterationCount MUST be a positive integer within the same cap the decryptor enforces, so a
// ---- pwri (password) : PBKDF2 + RFC 3211 double-CBC PWRI-KEK ---------------
async function _buildPwri(cek, desc) {
  // A string / Uint8Array password is encoded into a buffer this toolkit allocated, a credential
  // copy, so it is cleared once the derivation has consumed it. A caller-supplied Buffer is
  // borrowed and left intact.
  // The option validation runs before the password is encoded: a rejected iteration count or salt
  // would otherwise abandon an owned credential copy on the way out.
  var iterations = pbes2.assertIterations(desc.iterations == null ? 600000 : desc.iterations, _err, "cms");
  var salt = desc.salt ? pbes2.assertSalt(guard.bytes.view(desc.salt, CmsError, "cms/bad-input", "salt"), _err, "cms") : nodeCrypto.randomBytes(16);
  var prf = desc.prf || "hmacWithSHA256";
  _prfHash(prf);   // reject an unsupported prf HERE, before a credential copy exists to abandon
  var innerKeyBytes = 32; // AES-256-CBC inner
  var pwOwn = pbes2.passwordBytesOwned(desc.password, _err, "cms");
  var password = pwOwn.bytes;
  var kekKey = await subtle.importKey("raw", password, { name: "PBKDF2" }, false, ["deriveBits"]);
  // The derived KEK is this function's allocation and is cleared below. `password` is not: when the
  // caller passes a Buffer, passwordBytes hands back that very buffer, so wiping it would destroy
  // the caller's own memory, the one failure this rule must never cause.
  var kek = Buffer.from(await subtle.deriveBits({ name: "PBKDF2", hash: _prfHash(prf), salt: salt, iterations: iterations }, kekKey, innerKeyBytes * 8));
  if (pwOwn.owned) guard.secret.zeroize(password, CmsError, "cms/bad-input", "the password encoding");
  try {
    // The RFC 3211 double-CBC wrap under an inner AES-256-CBC whose IV is carried in the
    // keyEncryptionAlgorithm parameter (id-alg-PWRI-KEK parameter = the inner cipher AlgorithmIdentifier).
    var iv = nodeCrypto.randomBytes(16);
    var encryptedKey = _pwriWrapIv(kek, cek, iv);
    // PBKDF2-params as keyDerivationAlgorithm [0] IMPLICIT.
    var kdfParams = pbes2.pbkdf2ParamsSeq(salt, iterations, prf);
    var kdfAlg = b.contextConstructed(0, Buffer.concat([b.oid(O("pbkdf2")), kdfParams]));
    var keyEncAlg = b.sequence([b.oid(O("id-alg-PWRI-KEK")), b.sequence([b.oid(O("aes256-CBC")), b.octetString(iv)])]);
    return { tag: 3, node: b.sequence([b.integer(0n), kdfAlg, keyEncAlg, b.octetString(encryptedKey)]) };
  } finally {
    guard.secret.zeroize(kek, CmsError, "cms/bad-input", "the password-derived key-encryption key");
  }
}

// ---- kemri (ML-KEM ori) : RFC 9629 + 9936 ---------------------------------
var KEM_WRAP = {}; // ML-KEM OID -> wrap name (RFC 9936 sec. 2.2.1)
KEM_WRAP[O("id-ml-kem-512")] = "aes128-wrap";
KEM_WRAP[O("id-ml-kem-768")] = "aes256-wrap";
KEM_WRAP[O("id-ml-kem-1024")] = "aes256-wrap";
var KEM_WC = {}; KEM_WC[O("id-ml-kem-512")] = "ML-KEM-512"; KEM_WC[O("id-ml-kem-768")] = "ML-KEM-768"; KEM_WC[O("id-ml-kem-1024")] = "ML-KEM-1024";

// CMSORIforKEMOtherInfo ::= SEQUENCE { wrap AlgorithmIdentifier, kekLength INTEGER,
//   ukm [0] EXPLICIT OCTET STRING OPTIONAL }, the RFC 9629 sec. 5 KDF info, one builder both sides.
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
  var kek = null, kekAb = null;
  try {
    var ssKey = await subtle.importKey("raw", ss, { name: "HKDF" }, false, ["deriveBits"]);
    kekAb = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: Buffer.alloc(0), info: _kemOtherInfo(wrapName, kekBytes, ukm) }, ssKey, kekBytes * 8);
    kek = Buffer.from(kekAb);
    var encryptedKey = await _aesKwWrap(kek, cek);
    var rid = _rid(cert, opts.keyIdentifier);
    var kemriKids = [b.integer(0n), rid.node, _algId(oid.name(keyOid), "absent"), b.octetString(kemct), _algId("hkdfWithSha256", "absent"), b.integer(BigInt(kekBytes))];
    if (ukm) kemriKids.push(b.explicit(0, b.octetString(ukm)));
    kemriKids.push(_algId(wrapName, "absent"), b.octetString(encryptedKey));
    var kemri = b.sequence(kemriKids);
    return { tag: 4, node: b.sequence([b.oid(O("kem")), kemri]) };
  } finally {
    // RFC 9629 sec. 7 asks the SENDER to discard the shared secret and KEK once the recipient entry
    // is built, and to use a fresh secret per recipient, so this runs per call and not once at
    // the end of a multi-recipient message. In a `finally`, so a wrap or encoding failure does not
    // leave them behind. The CEK is the caller's and is wiped by no one here; kemct is public.
    // kem.sharedKey is the ArrayBuffer the engine returned and ss is this function's copy of it;
    // both hold the secret, so both are cleared. A Uint8Array view aliases the buffer's bytes, so
    // wiping the view wipes the buffer itself. kem.ciphertext is public and stays.
    guard.secret.zeroizeAll([ss, kek, kem.sharedKey ? new Uint8Array(kem.sharedKey) : null, kekAb ? new Uint8Array(kekAb) : null],
      CmsError, "cms/bad-input", "the KEM shared secret");
  }
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
  //  and  each hold a plaintext copy of the CEK; only the padded result is returned, so
  // the intermediates are cleared here and never abandoned.
  var wrapped = Buffer.concat([body, nodeCrypto.randomBytes(padLen)]);
  guard.secret.zeroizeAll([check, body], CmsError, "cms/bad-input", "a PWRI formatting intermediate");
  return wrapped;
}
function _pwriWrapIv(kek, cek, iv) {
  // wk is the formatted plaintext -- a complete copy of the CEK -- and is cleared once the first
  // encryption pass has consumed it. pass1 is already ciphertext.
  var wk = _pwriFormat(cek);
  try {
    var c1 = nodeCrypto.createCipheriv("aes-256-cbc", kek, iv); c1.setAutoPadding(false);
    var pass1 = guard.secret.cipherFinish(c1, wk, CmsError, "cms/bad-input", "the PWRI first-pass ciphertext");
    var iv2 = pass1.subarray(pass1.length - 16);
    var c2 = nodeCrypto.createCipheriv("aes-256-cbc", kek, iv2); c2.setAutoPadding(false);
    return guard.secret.cipherFinish(c2, pass1, CmsError, "cms/bad-input", "the PWRI wrapped key");
  } finally {
    guard.secret.zeroize(wk, CmsError, "cms/bad-input", "the PWRI plaintext block");
  }
}

var PRF_HASH = { hmacWithSHA1: "SHA-1", hmacWithSHA256: "SHA-256", hmacWithSHA384: "SHA-384", hmacWithSHA512: "SHA-512" };
function _prfHash(prf) { if (!PRF_HASH[prf]) throw _err("cms/bad-input", "unsupported pwri prf " + JSON.stringify(prf)); return PRF_HASH[prf]; }

// ---- recipient dispatch ----------------------------------------------------
// The fields a recipient descriptor carries, PER ARM. Each arm reads a disjoint set, and every
// field beyond the selector is optional with a default, so an unrecognized name is missed by
// nothing and the recipient is built with the shipped parameters instead: `oaepHsh` for `oaepHash`
// encrypts the content key under the default SHA-256 OAEP, and a misspelled `iterations`, `salt`
// or `prf` on a password recipient derives the key at the default work factor. A union table would
// admit another arm's fields, which the chosen arm never reads.
var _PWRI_KEYS = { password: 1, iterations: 1, prf: 1, salt: 1 };
var _KEKRI_KEYS = { kek: 1, kekId: 1 };
// A certificate recipient dispatches on the certificate's KEY ALGORITHM, and the arms read
// different fields: ktri (RSA) reads oaepHash and never ukm; kari (ECDH / X25519 / X448) and kemri
// (ML-KEM) read ukm and never oaepHash. One table across all three accepted `oaepHash` on an EC
// certificate, where nothing reads it, so the content key was wrapped under the arm's own defaults
// while the caller had named a hash. Checked after the key algorithm resolves, since that is what
// selects the arm.
var _KTRI_RECIPIENT_KEYS = { cert: 1, oaepHash: 1, keyIdentifier: 1 };
var _AGREE_RECIPIENT_KEYS = { cert: 1, keyIdentifier: 1, ukm: 1 };

// The three top-level options that are per-recipient DEFAULTS rather than message-wide settings.
// Which of them any given message actually consumes depends on the recipient arms it selects, so
// they are checked against the arms after those resolve, not against a fixed list.
var _RECIPIENT_DEFAULTS = ["oaepHash", "keyIdentifier", "ukm"];

function _assertRecipientKeys(desc, known, arm) {
  guard.identifier.assertKnownKeys(desc, known, _err, "cms/bad-input", function (k) {
    return "unknown field " + JSON.stringify(k) + " on a " + arm +
      " recipient; that field is not read for this recipient type";
  });
}

// A default no selected recipient reads is discarded exactly as a misspelling would be: `oaepHash`
// on a message whose only recipient is a password recipient names a wrapping the message does not
// perform. Run after every recipient's arm has resolved and BEFORE anything is emitted.
function _assertDefaultsConsumed(opts, consumed) {
  for (var i = 0; i < _RECIPIENT_DEFAULTS.length; i++) {
    var name = _RECIPIENT_DEFAULTS[i];
    if (opts[name] != null && !consumed[name]) {
      throw _err("cms/bad-input", "opts." + name + " is a per-recipient default and no recipient of this message reads it" +
        (name === "oaepHash" ? " (only an RSA certificate recipient does)"
          : name === "ukm" ? " (only a key-agreement or KEM certificate recipient does)"
            : " (only a certificate recipient does)"));
    }
  }
}

async function _buildRecipient(cek, desc, opts, consumed) {
  if (desc == null || typeof desc !== "object") throw _err("cms/bad-input", "each recipient must be a descriptor object");
  // Checked per arm, on the same selector the dispatch below uses, so the table that runs is the
  // one belonging to the arm that will build. `consumed` records which top-level defaults the
  // selected arms read, so a default no recipient consumes can be refused once they all resolve.
  if (desc.password != null) { _assertRecipientKeys(desc, _PWRI_KEYS, "password"); return _buildPwri(cek, desc); }
  if (desc.kek != null) { _assertRecipientKeys(desc, _KEKRI_KEYS, "KEK"); return _buildKekri(cek, desc); }
  if (desc.cert != null) {
    var cert = x509.parse(_normCertDer(desc.cert, "a recipient certificate"));
    var keyOid = cert.subjectPublicKeyInfo.algorithm.oid;
    if (keyOid === O("rsaEncryption") || keyOid === O("rsassaPss")) {
      _assertRecipientKeys(desc, _KTRI_RECIPIENT_KEYS, "RSA certificate");
      return _buildKtri(cek, cert, mergeOpts(opts, desc, _KTRI_RECIPIENT_KEYS, consumed));
    }
    if (keyOid === O("ecPublicKey") || MONT_KA[keyOid]) {
      _assertRecipientKeys(desc, _AGREE_RECIPIENT_KEYS, "key-agreement certificate");
      return _buildKari(cek, cert, mergeOpts(opts, desc, _AGREE_RECIPIENT_KEYS, consumed));
    }
    if (KEM_WC[keyOid]) {
      _assertRecipientKeys(desc, _AGREE_RECIPIENT_KEYS, "KEM certificate");
      return _buildKemri(cek, cert, mergeOpts(opts, desc, _AGREE_RECIPIENT_KEYS, consumed));
    }
    throw _err("cms/unsupported-algorithm", "unsupported recipient certificate key algorithm " + keyOid);
  }
  throw _err("cms/bad-input", "a recipient needs { cert }, { password }, or { kek, kekId }");
}
// Each default is taken from the descriptor when it supplies one and from the top-level options
// otherwise. That one choice is also the record of which top-level defaults the recipient CONSUMED:
// an arm that does not read the name never consumes it, and neither does one whose descriptor
// overrode it, so recording it from the arm's table alone would accept a value nothing read.
function _pickDefault(desc, opts, name, known, consumed, nullish) {
  var supplied = desc[name], fromDesc = nullish ? supplied != null : !!supplied;
  if (!fromDesc && known[name] && consumed && opts[name] != null) consumed[name] = 1;
  return fromDesc ? supplied : opts[name];
}
function mergeOpts(opts, desc, known, consumed) {
  return {
    oaepHash: _pickDefault(desc, opts, "oaepHash", known, consumed, false),
    keyIdentifier: _pickDefault(desc, opts, "keyIdentifier", known, consumed, false),
    ukm: _pickDefault(desc, opts, "ukm", known, consumed, true),
  };
}
// RecipientInfo CHOICE: ktri untagged; kari [1], kekri [2], pwri [3], ori [4], all IMPLICIT,
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

// The two exported verbs have DISJOINT option sets, so they get separate tables: one shared table
// would admit every other verb's keys, which is the hole rather than the door. Each is the union of
// what the verb reads THROUGH ITS DELEGATIONS -- encrypt never names oaepHash, keyIdentifier or ukm
// itself, but hands opts to the per-recipient builders that do, and to _emit for pem.
// Authenticated attributes live in an AuthEnvelopedData, which only an AEAD content algorithm
// produces: a CBC algorithm selects EnvelopedData, which has no field for them and is not handed
// opts at all. Requested there, they named a protection the message does not carry.
var _ENCRYPT_OPTS_AEAD = {
  contentEncryptionAlgorithm: 1, contentType: 1, authAttrs: 1, oaepHash: 1, keyIdentifier: 1,
  ukm: 1, pem: 1,
};
var _ENCRYPT_OPTS_CBC = {
  contentEncryptionAlgorithm: 1, contentType: 1, oaepHash: 1, keyIdentifier: 1, ukm: 1, pem: 1,
};
// authenticatedAttributes: false MACs the content octets directly, and the attribute set is what
// carries the digest: neither the digest algorithm nor any extra attribute is read on that branch.
var _AUTHENTICATE_OPTS_ATTRS = {
  macAlgorithm: 1, digestAlgorithm: 1, authenticatedAttributes: 1, authAttrs: 1, contentType: 1,
  keyIdentifier: 1, oaepHash: 1, ukm: 1, pem: 1,
};
var _AUTHENTICATE_OPTS_BARE = {
  macAlgorithm: 1, authenticatedAttributes: 1, contentType: 1,
  keyIdentifier: 1, oaepHash: 1, ukm: 1, pem: 1,
};

async function encrypt(content, recipients, opts) {
  opts = opts || {};
  // The content algorithm selects the structure, so it is resolved before the door and the table
  // that runs is the one belonging to the structure this call will emit.
  var algName = opts.contentEncryptionAlgorithm || "aes-256-gcm";
  var ca = CONTENT_ALGS[algName];
  if (!ca) throw _err("cms/bad-input", "unsupported contentEncryptionAlgorithm " + JSON.stringify(algName));
  guard.identifier.assertKnownKeys(opts, ca.aead ? _ENCRYPT_OPTS_AEAD : _ENCRYPT_OPTS_CBC, _err, "cms/bad-input",
    function (k) {
      return "pki.cms.encrypt has an unknown option " + JSON.stringify(k) +
        (!ca.aead && k === "authAttrs"
          ? " for a CBC content algorithm; authenticated attributes are carried only by an AuthEnvelopedData, which an AEAD algorithm produces"
          : "");
    });
  // An async-iterable content streams the plaintext through the cipher without buffering it whole; a byte
  // source takes the one-shot path. asyncStreamOf reads Symbol.asyncIterator once and wins only when the
  // value is not already a byte source, so a Buffer with a stray asyncIterator stays a Buffer.
  var contentStream = guard.bytes.asyncStreamOf(content);
  var contentBytes = contentStream ? null : guard.bytes.view(content, CmsError, "cms/bad-input", "content");
  var contentType = opts.contentType || "data";
  var cek = nodeCrypto.randomBytes(ca.keyBits / 8);

  // The CEK protects the content for every recipient, so unlike a per-recipient shared secret it is
  // cleared once, after the last recipient entry is built and the content is encrypted. Wiping it
  // inside the recipient loop would destroy the key the remaining recipients must be given.
  try {
    // EncryptedData: a single non-array { cek } or { password } descriptor, no RecipientInfos.
    if (!Array.isArray(recipients)) return await _encryptedData(contentBytes, contentStream, recipients, ca, contentType, opts, cek);

    if (!recipients.length) throw _err("cms/bad-input", "at least one recipient is required (RFC 5652 sec. 6.1)");
    var recips = [];
    var consumed = {};
    for (var i = 0; i < recipients.length; i++) recips.push(await _buildRecipient(cek, recipients[i], opts, consumed));
    _assertDefaultsConsumed(opts, consumed);
    var riNodes = recips.map(_taggedRecipient);

    if (ca.aead) return _emit(await _authEnvelopedData(contentBytes, contentStream, cek, ca, contentType, opts, riNodes, recips), "authEnvelopedData", opts);
    return _emit(await _envelopedData(contentBytes, contentStream, cek, ca, contentType, riNodes, recips), "envelopedData", opts);
  } finally {
    guard.secret.zeroize(cek, CmsError, "cms/bad-input", "the content-encryption key");
  }
}

function _emit(inner, ctName, opts) {
  var ci = b.sequence([b.oid(O(ctName)), b.explicit(0, inner)]);
  return opts.pem ? schemaCms.pemEncode(ci, "CMS") : ci;
}

// Run a streamed plaintext through the content cipher, translating the engine's malformed-streamed-content
// domain into this verb's cms/bad-input via the shared guard, so pki.cms.encrypt keeps its typed CmsError
// contract (the streamed sign/verify paths translate the same way).
async function _encStream(spec, stream) {
  try {
    return await subtle.encryptStream(spec, stream);
  } catch (e) {
    guard.bytes.translateStreamError(e, _err, "cms/bad-input");
  }
}

async function _envelopedData(contentBytes, contentStream, cek, ca, contentType, riNodes, recips) {
  var iv = nodeCrypto.randomBytes(16);
  // A streamed plaintext runs through the CBC cipher incrementally (assembling only the ciphertext, whose
  // length the encryptedContent OCTET STRING needs); a Buffer takes the one-shot path. Both produce the
  // same wire bytes for the same plaintext, so the emitted DER is identical to the buffered form.
  var enc = contentStream
    ? (await _encStream({ algNode: "aes-" + ca.keyBits + "-cbc", key: cek, iv: iv }, contentStream)).ciphertext
    : pbes2.cbcEncrypt(cek, iv, contentBytes, ca.keyBits, CmsError, "cms/bad-input");
  var eci = b.sequence([b.oid(O(contentType)), b.sequence([b.oid(O(ca.oid)), b.octetString(iv)]), b.contextPrimitive(0, enc)]);
  return b.sequence([b.integer(BigInt(_envelopedVersion(recips, false))), b.setOf(riNodes), eci]);
}

// Every authenticated attribute this module MACs -- auto-built or caller-supplied, in either content
// type that carries them -- MUST be a well-formed Attribute SEQUENCE { type OBJECT IDENTIFIER,
// non-empty SET OF value } with no repeated type (RFC 5652 sec. 5.3). Rejecting here means a
// malformed attribute never reaches the wire; leaving it to the wire means the operator learns from
// a peer's parser that the message they built is unreadable, with the MAC already computed over it.
//
// `forbidden` names an attribute type this particular content type must not emit, with the clause
// that says so. It is a parameter rather than a constant because the same attribute is required in
// one content type and discouraged in the other: AuthenticatedData MACs its own message-digest by
// design (RFC 5652 sec. 9.2), while for AuthEnvelopedData that value is the unencrypted hash of a
// plaintext the message exists to conceal (RFC 5083 sec. 2.1 / sec. 5).
function _assertAuthAttrs(pairs, forbidden) {
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
    if (intrinsic.hasOwn(seenTypes, t)) throw _err("cms/bad-input", "authenticated attributes must not repeat an attribute type (RFC 5652): " + t);
    seenTypes[t] = 1;
    if (forbidden && t === forbidden.oid) throw _err("cms/bad-input", forbidden.why);
  });
}

// The one attribute AuthEnvelopedData declines to emit. Its value is the unencrypted one-way hash of
// the plaintext, so disclosing it enables content tracking and confirms a guessed plaintext against
// a message that was encrypted to prevent exactly that.
var AUTH_ENVELOPED_FORBIDDEN = {
  oid: O("messageDigest"),
  why: "authAttrs must not carry the message-digest attribute in an AuthEnvelopedData: its value is the unencrypted hash of the plaintext, which enables content tracking and confirmation of a guessed plaintext (RFC 5083 sec. 2.1, sec. 5)",
};

async function _authEnvelopedData(contentBytes, contentStream, cek, ca, contentType, opts, riNodes, recips) {
  var nonce = nodeCrypto.randomBytes(12);
  var authAttrsDer = null, aad = Buffer.alloc(0);
  // RFC 5083 sec. 2.1: authAttrs MUST be present when the content type is not id-data. Emitting an
  // AuthEnvelopedData without them for a non-data type produces a message our own strict parser rejects.
  if (contentType !== "data" && !(opts.authAttrs && opts.authAttrs.length)) {
    throw _err("cms/bad-input", "AuthEnvelopedData with a non-data contentType requires authAttrs (RFC 5083 sec. 2.1)");
  }
  if (opts.authAttrs && opts.authAttrs.length) {
    _assertAuthAttrs(opts.authAttrs, AUTH_ENVELOPED_FORBIDDEN);
    // authAttrs are transmitted [1] IMPLICIT but MACed under the EXPLICIT SET OF tag (RFC 5083 sec. 2.2).
    var setOf = b.setOf(opts.authAttrs);
    aad = setOf; authAttrsDer = b.contextConstructed(1, setOf.subarray(_tlvHeaderLen(setOf)));
  }
  // A 16-octet (128-bit) GCM tag, the strongest ICV and what OpenSSL emits, so the message
  // interops across OpenSSL 3.5 / 4.x. The aes-ICVlen (16) is carried explicitly (RFC 5084 sec. 3.2
  // omits it only when it equals the DEFAULT 12); it MUST equal the mac octet length (M42).
  // A streamed plaintext runs through the GCM cipher incrementally; the tag is produced at final() over the
  // same bytes, so the ciphertext + tag equal the one-shot form for the same plaintext and AAD.
  var g;
  if (contentStream) {
    var r = await _encStream({ algNode: "aes-" + ca.keyBits + "-gcm", key: cek, iv: nonce, aad: aad, authTagLength: 16 }, contentStream);
    g = { ct: r.ciphertext, tag: r.tag };
  } else {
    g = _gcmEncrypt(cek, nonce, contentBytes, aad, ca.keyBits, 16);
  }
  var eci = b.sequence([b.oid(O(contentType)), b.sequence([b.oid(O(ca.oid)), _gcmParams(nonce, 16)]), b.contextPrimitive(0, g.ct)]);
  var kids = [b.integer(0n), b.setOf(riNodes), eci];
  if (authAttrsDer) kids.push(authAttrsDer);
  kids.push(b.octetString(g.tag));
  void recips;
  return b.sequence(kids);
}

// The single descriptor an EncryptedData takes, PER ARM. `cek` and `password` select the arm and
// the arms read disjoint sets, so a union would admit the other arm's fields: `{ cek, iterations }`
// supplies a work factor to a branch that derives nothing, and the caller's parameter is discarded
// exactly as a misspelling would be. `pem` is read after both arms, so it belongs to each.
// pem selects the output encoding of the whole call and is an OPTION, the third argument, on every
// other verb here. A second spelling on the descriptor was read by the password arm alone, so the
// cek arm accepted it and returned DER; there is now one place to ask for PEM.
var _ENCRYPTED_DATA_CEK_KEYS = { cek: 1 };
var _ENCRYPTED_DATA_PW_KEYS = { password: 1, iterations: 1, salt: 1, prf: 1 };

async function _encryptedData(contentBytes, contentStream, desc, ca, contentType, opts, cek) {
  if (ca.aead) throw _err("cms/bad-input", "EncryptedData supports only CBC content encryption");
  // An EncryptedData carries no RecipientInfos at all, so nothing here reads a per-recipient
  // default. This branch returns before the recipient loop, so it answers for them itself.
  _assertDefaultsConsumed(opts, {});
  // Checked per arm, on the same selector the dispatch below uses, so the table that runs belongs
  // to the branch that will encrypt.
  if (desc != null && typeof desc === "object") {
    var edKeys = desc.cek != null ? _ENCRYPTED_DATA_CEK_KEYS : _ENCRYPTED_DATA_PW_KEYS;
    var edArm = desc.cek != null ? "cek" : "password";
    guard.identifier.assertKnownKeys(desc, edKeys, _err, "cms/bad-input", function (k) {
      return "unknown field " + JSON.stringify(k) + " on a " + edArm +
        " EncryptedData descriptor; that field is not read for this arm";
    });
  }
  var iv = nodeCrypto.randomBytes(16);
  var contentAlgNode, encKey;
  if (desc && desc.cek != null) {
    encKey = guard.bytes.view(desc.cek, CmsError, "cms/bad-input", "cek");
    if (encKey.length !== ca.keyBits / 8) throw _err("cms/bad-input", "the supplied cek length does not match " + opts.contentEncryptionAlgorithm);
    contentAlgNode = b.sequence([b.oid(O(ca.oid)), b.octetString(iv)]);
  } else if (desc && desc.password != null) {
    return _encryptedDataPbes2(contentBytes, contentStream, desc, ca, contentType, iv, opts);
  } else {
    throw _err("cms/bad-input", "EncryptedData needs a single { cek } or { password } descriptor");
  }
  var enc = contentStream
    ? (await _encStream({ algNode: "aes-" + ca.keyBits + "-cbc", key: encKey, iv: iv }, contentStream)).ciphertext
    : pbes2.cbcEncrypt(encKey, iv, contentBytes, ca.keyBits, CmsError, "cms/bad-input");
  var eci = b.sequence([b.oid(O(contentType)), contentAlgNode, b.contextPrimitive(0, enc)]);
  var inner = b.sequence([b.integer(0n), eci]);
  return _emit(inner, "encryptedData", opts);
}

async function _encryptedDataPbes2(contentBytes, contentStream, desc, ca, contentType, iv, opts) {
  // A string / Uint8Array password is encoded into a buffer this toolkit allocated, a credential
  // copy, so it is cleared once the derivation has consumed it. A caller-supplied Buffer is
  // borrowed and left intact.
  var pwOwn2 = pbes2.passwordBytesOwned(desc.password, _err, "cms");
  var password = pwOwn2.bytes;
  var iterations = pbes2.assertIterations(desc.iterations == null ? 600000 : desc.iterations, _err, "cms");
  var salt = desc.salt ? pbes2.assertSalt(guard.bytes.view(desc.salt, CmsError, "cms/bad-input", "salt"), _err, "cms") : nodeCrypto.randomBytes(16);
  var prf = desc.prf || "hmacWithSHA256";
  // The password-derived content key is this function's allocation; `password` may be the caller's
  // own buffer (passwordBytes passes a Buffer straight through) and is left alone.
  var key = nodeCrypto.pbkdf2Sync(password, salt, iterations, ca.keyBits / 8, pbes2.prfNodeByName(prf, _err, "cms"));
  if (pwOwn2.owned) guard.secret.zeroize(password, CmsError, "cms/bad-input", "the password encoding");
  try {
    var enc = contentStream
      ? (await _encStream({ algNode: "aes-" + ca.keyBits + "-cbc", key: key, iv: iv }, contentStream)).ciphertext
      : pbes2.cbcEncrypt(key, iv, contentBytes, ca.keyBits, CmsError, "cms/bad-input");
    var contentAlg = pbes2.pbes2AlgId(salt, iterations, prf, ca.oid, iv);
    var eci = b.sequence([b.oid(O(contentType)), contentAlg, b.contextPrimitive(0, enc)]);
    var inner = b.sequence([b.integer(0n), eci]);
    return _emit(inner, "encryptedData", opts);
  } finally {
    guard.secret.zeroize(key, CmsError, "cms/bad-input", "the password-derived content-encryption key");
  }
}

// ---- content-encryption primitives ----------------------------------------
function _gcmEncrypt(key, nonce, plaintext, aad, keyBits, tagLen) {
  var c = nodeCrypto.createCipheriv("aes-" + keyBits + "-gcm", key, nonce, { authTagLength: tagLen });
  if (aad && aad.length) c.setAAD(aad);
  var ct = guard.secret.cipherFinish(c, plaintext, CmsError, "cms/bad-input", "a content-encryption intermediate");
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
  // The attribute branch is selected once, and the door and the MAC below both act on that one
  // decision, so the table that runs belongs to the branch that will compute the MAC.
  var withAttrs = opts.authenticatedAttributes !== false;
  guard.identifier.assertKnownKeys(opts, withAttrs ? _AUTHENTICATE_OPTS_ATTRS : _AUTHENTICATE_OPTS_BARE,
    _err, "cms/bad-input", function (k) {
      return "pki.cms.authenticate has an unknown option " + JSON.stringify(k) +
        (!withAttrs && (k === "digestAlgorithm" || k === "authAttrs")
          ? " with authenticatedAttributes: false; the MAC then covers the content octets directly and no attribute set is built"
          : "");
    });
  var contentBytes = guard.bytes.view(content, CmsError, "cms/bad-input", "content");
  var macName = opts.macAlgorithm || "hmac-sha256";
  var mac = MAC_ALGS[macName];
  if (!mac) throw _err("cms/bad-input", "unsupported macAlgorithm " + JSON.stringify(macName) + " (hmac-sha256/384/512)");
  if (!Array.isArray(recipients) || !recipients.length) throw _err("cms/bad-input", "at least one recipient is required (RFC 5652 sec. 9.1)");
  var contentType = opts.contentType || "data";
  // RFC 5652 sec. 9.1: authAttrs MUST be present when the eContentType is not id-data.
  if (contentType !== "data" && !withAttrs) throw _err("cms/bad-input", "AuthenticatedData with a non-data contentType requires authenticated attributes (RFC 5652 sec. 9.1)");

  // The MAC key is this path's content-encryption key: every recipient is given it, so it is cleared
  // once at the end and not per recipient, and only after the MAC has been computed over it.
  var macKey = nodeCrypto.randomBytes(MAC_KEY_OCTETS);
  try {
    var recips = [];
    var consumedAuth = {};
    for (var i = 0; i < recipients.length; i++) recips.push(await _buildRecipient(macKey, recipients[i], opts, consumedAuth));
    _assertDefaultsConsumed(opts, consumedAuth);
    var riNodes = recips.map(_taggedRecipient);

    var digestAlgTagged = null, authAttrsDer = null, preimage;
    if (withAttrs) {
      // Inside the branch that uses it: the attribute set is what carries the digest, so on the
      // other branch there is no digest to name and opts.digestAlgorithm is refused at the door.
      var digestName = opts.digestAlgorithm || mac.node;
      if (!SUPPORTED_DIGEST[digestName]) throw _err("cms/bad-input", "unsupported digestAlgorithm " + JSON.stringify(digestName) + " (sha256/384/512)");
      // sec. 9.2: content-type (== eContentType) + message-digest (== digest(content)) attributes,
      // SET-OF-sorted, MACed under the EXPLICIT SET OF tag (0x31) but transmitted [2] IMPLICIT (0xA2).
      var mdDigest = nodeCrypto.createHash(digestName).update(contentBytes).digest();
      var pairs = [
        b.sequence([b.oid(O("contentType")), b.setOf([b.oid(O(contentType))])]),
        b.sequence([b.oid(O("messageDigest")), b.setOf([b.octetString(mdDigest)])]),
      ];
      if (opts.authAttrs && opts.authAttrs.length) pairs = pairs.concat(opts.authAttrs);
      _assertAuthAttrs(pairs, null);
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
    var ci = b.sequence([b.oid(O("authData")), b.explicit(0, b.sequence(kids))]);
    // Self-verify: the emitted AuthenticatedData MUST re-parse clean through the strict parser, so a
    // caller-supplied authenticated attribute with a recognized type but extra RFC 5652 constraints (a
    // misplaced type, a signing-time whose value is not a Time) is rejected HERE at build time rather
    // than by the recipient's parser after the fact.
    try { schemaCms.parse(ci); } catch (e) { throw (e instanceof CmsError) ? e : _err("cms/bad-input", "the supplied authenticated attributes produced an invalid AuthenticatedData", e); }
    return opts.pem ? schemaCms.pemEncode(ci, "CMS") : ci;
  } finally {
    guard.secret.zeroize(macKey, CmsError, "cms/bad-input", "the message-authentication key");
  }
}

module.exports = { encrypt: encrypt, authenticate: authenticate };
