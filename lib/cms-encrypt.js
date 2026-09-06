// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
// @primitive pki.cms.encrypt block live in cms-verify.js, which re-exports this function (the

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var pkiBuild = require("./pki-build");
var oid = require("./oid");
var x509 = require("./schema-x509");
var schemaCms = require("./schema-cms");
var webcrypto = require("./webcrypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var pbes2 = require("./pbes2");
var compositeKem = require("./composite-kem");
var b = asn1.build;
var subtle = webcrypto.webcrypto.subtle;
var pkix = require("./schema-pkix");
var CmsError = frameworkError.CmsError;
var _KU_NS = pkix.makeNS("cms", CmsError, oid);
var WRAP_KEK_LENGTHS = schemaCms.WRAP_KEK_LENGTHS;

function O(n) { return oid.byName(n); }
function _err(code, message, cause) { return new CmsError(code, message, cause); }

function _algId(name, shape) { return shape === "null" ? b.sequence([b.oid(O(name)), b.nullValue()]) : b.sequence([b.oid(O(name))]); }

function _normCertDer(cert, what) {
  if (guard.bytes.isByteSource(cert)) return guard.bytes.snapshotSource(cert, CmsError, "cms/bad-input", what || "a certificate");
  if (typeof cert === "string") { try { return x509.pemDecode(cert); } catch (e) { throw _err("cms/bad-input", (what || "a certificate") + " PEM could not be decoded", e); } }
  throw _err("cms/bad-input", (what || "a certificate") + " must be a DER Buffer, Uint8Array, or PEM string");
}

var CONTENT_ALGS = intrinsic.assign(intrinsic.create(null), {
  "aes-128-gcm": { oid: "aes128-GCM", keyBits: 128, aead: true },
  "aes-192-gcm": { oid: "aes192-GCM", keyBits: 192, aead: true },
  "aes-256-gcm": { oid: "aes256-GCM", keyBits: 256, aead: true },
  "aes-128-cbc": { oid: "aes128-CBC", keyBits: 128, aead: false },
  "aes-192-cbc": { oid: "aes192-CBC", keyBits: 192, aead: false },
  "aes-256-cbc": { oid: "aes256-CBC", keyBits: 256, aead: false },
});

function _wrapOidForKek(keyBytes) {
  if (keyBytes === 16) return "aes128-wrap";
  if (keyBytes === 24) return "aes192-wrap";
  if (keyBytes === 32) return "aes256-wrap";
  throw _err("cms/bad-input", "no AES key-wrap algorithm for a " + keyBytes + "-octet key-encryption key");
}

function _gcmParams(nonce, icvLen) {
  var kids = [b.octetString(nonce)];
  if (icvLen !== 12) kids.push(b.integer(BigInt(icvLen)));
  return b.sequence(kids);
}

function _assertKeyIdentifier(form) {
  if (form != null && form !== "issuerAndSerial" && form !== "issuerAndSerialNumber" && form !== "subjectKeyIdentifier") {
    throw _err("cms/bad-input", "unsupported keyIdentifier " + guard.text.showValue(form) + " (use \"issuerAndSerial\" or \"subjectKeyIdentifier\")");
  }
}
function _rid(cert, form) {
  _assertKeyIdentifier(form);
  if (form === "subjectKeyIdentifier") {
    var ski = _skiOf(cert);
    if (!ski) throw _err("cms/bad-input", "keyIdentifier: \"subjectKeyIdentifier\" requires the recipient certificate to carry a subjectKeyIdentifier extension");
    return { node: b.contextPrimitive(0, ski), riVersion: 2 };
  }
  return { node: b.sequence([b.raw(cert.issuer.bytes), b.integer(cert.serialNumber)]), riVersion: 0 };
}
function _skiOf(cert) {
  var exts = cert.extensions || [];
  for (var i = 0; i < exts.length; i++) if (exts[i].name === "subjectKeyIdentifier" && exts[i].value != null) {
    try { return asn1.read.octetString(asn1.decode(exts[i].value)); } catch (e) { throw _err("cms/bad-input", "the certificate's subjectKeyIdentifier extension is malformed", e); }
  }
  return null;
}

function _assertKeyUsage(cert, bitName, arm) {
  var ku = pkix.keyUsageOf(_KU_NS, cert, _err, "cms/bad-input", "recipient certificate's");
  if (ku && ku[bitName] !== true) throw _err("cms/bad-key-usage", "the " + arm + " recipient certificate's keyUsage does not assert " + bitName);
}

var OAEP_HASH = intrinsic.assign(intrinsic.create(null), { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" });
function _oaepParams(hashName) {
  var hAlg = _algId(hashName, "null");
  var mgf = b.sequence([b.oid(O("mgf1")), hAlg]);
  return b.sequence([b.explicit(0, hAlg), b.explicit(1, mgf)]);
}
async function _buildKtri(cek, cert, opts) {
  _assertKeyUsage(cert, "keyEncipherment", "ktri");
  var hashName = opts.oaepHash || "sha256";
  if (!OAEP_HASH[guard.text.keyOf(hashName)]) throw _err("cms/bad-input", "unsupported oaepHash " + guard.text.showValue(hashName));
  var pub = await subtle.importKey("spki", cert.subjectPublicKeyInfo.bytes, { name: "RSA-OAEP", hash: OAEP_HASH[hashName] }, false, ["encrypt"]);
  var encryptedKey = Buffer.from(await subtle.encrypt({ name: "RSA-OAEP" }, pub, cek));
  var rid = _rid(cert, opts.keyIdentifier);
  var keyEncAlg = b.sequence([b.oid(O("rsaesOaep")), _oaepParams(hashName)]);
  return { tag: null, _riVersion: rid.riVersion, node: b.sequence([b.integer(BigInt(rid.riVersion)), rid.node, keyEncAlg, b.octetString(encryptedKey)]) };
}

var EC_KA = intrinsic.create(null);
EC_KA[O("prime256v1")] = { curve: "P-256", hash: "SHA-256", scheme: "dhSinglePass-stdDH-sha256kdf-scheme" };
EC_KA[O("secp384r1")] = { curve: "P-384", hash: "SHA-384", scheme: "dhSinglePass-stdDH-sha384kdf-scheme" };
EC_KA[O("secp521r1")] = { curve: "P-521", hash: "SHA-512", scheme: "dhSinglePass-stdDH-sha512kdf-scheme" };
var MONT_KA = intrinsic.create(null);
MONT_KA[O("X25519")] = { name: "X25519", hkdf: "SHA-256", scheme: "dhSinglePass-stdDH-hkdf-sha256-scheme" };
MONT_KA[O("X448")] = { name: "X448", hkdf: "SHA-512", scheme: "dhSinglePass-stdDH-hkdf-sha512-scheme" };

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
      kek = Buffer.from(await subtle.deriveBits({ name: "HKDF", hash: mka.hkdf, salt: ukm || Buffer.alloc(0), info: _eccSharedInfo(wrapName, ukm, cek.length) }, mzKey, cek.length * 8));
    } else {
      throw _err("cms/unsupported-algorithm", "unsupported recipient key algorithm for kari");
    }
    var encryptedKey = await _aesKwWrap(kek, cek);
    var origSpki = asn1.decode(origKeyAlgId.spki);
    var origPubBits = origSpki.children[1];
    var originatorKey = b.contextConstructed(1, Buffer.concat([origSpki.children[0].bytes, origPubBits.bytes]));
    var ridNode;
    _assertKeyIdentifier(opts.keyIdentifier);
    if (opts.keyIdentifier === "subjectKeyIdentifier") {
      var ski = _skiOf(cert);
      if (!ski) throw _err("cms/bad-input", "keyIdentifier: \"subjectKeyIdentifier\" requires the recipient certificate to carry a subjectKeyIdentifier extension");
      ridNode = b.contextConstructed(0, b.octetString(ski));
    } else {
      ridNode = b.sequence([b.raw(cert.issuer.bytes), b.integer(cert.serialNumber)]);
    }
    var rek = b.sequence([b.sequence([ridNode, b.octetString(encryptedKey)])]);
    var kekAlg = b.sequence([b.oid(O(origKeyAlgId.scheme)), _algId(wrapName, "absent")]);
    var kariKids = [b.integer(3n), b.explicit(0, originatorKey)];
    if (ukm) kariKids.push(b.explicit(1, b.octetString(ukm)));
    kariKids.push(kekAlg, rek);
    return { tag: 1, node: b.sequence(kariKids) };
  } finally {
    guard.secret.zeroizeAll([z, mz, kek], CmsError, "cms/bad-input", "the key-agreement shared secret");
  }
}

async function _buildKekri(cek, desc) {
  var kek = guard.bytes.view(desc.kek, CmsError, "cms/bad-input", "kek");
  if (desc.kekId == null) throw _err("cms/bad-input", "a kek recipient needs a kekId");
  var wrapName = _wrapOidForKek(kek.length);
  var encryptedKey = await _aesKwWrap(kek, cek);
  var kekid = b.sequence([b.octetString(guard.bytes.view(desc.kekId, CmsError, "cms/bad-input", "kekId"))]);
  return { tag: 2, node: b.sequence([b.integer(4n), kekid, _algId(wrapName, "absent"), b.octetString(encryptedKey)]) };
}

async function _buildPwri(cek, desc) {
  var iterations = pbes2.assertIterations(desc.iterations == null ? 600000 : desc.iterations, _err, "cms");
  var salt = desc.salt ? pbes2.assertSalt(guard.bytes.view(desc.salt, CmsError, "cms/bad-input", "salt"), _err, "cms") : nodeCrypto.randomBytes(16);
  var prf = desc.prf || "hmacWithSHA256";
  _prfHash(prf);
  var innerKeyBytes = 32;
  var pwOwn = pbes2.passwordBytesOwned(desc.password, _err, "cms");
  var password = pwOwn.bytes;
  var kekKey = await subtle.importKey("raw", password, { name: "PBKDF2" }, false, ["deriveBits"]);
  var kek = Buffer.from(await subtle.deriveBits({ name: "PBKDF2", hash: _prfHash(prf), salt: salt, iterations: iterations }, kekKey, innerKeyBytes * 8));
  if (pwOwn.owned) guard.secret.zeroize(password, CmsError, "cms/bad-input", "the password encoding");
  try {
    var iv = nodeCrypto.randomBytes(16);
    var encryptedKey = _pwriWrapIv(kek, cek, iv);
    var kdfParams = pbes2.pbkdf2ParamsSeq(salt, iterations, prf);
    var kdfAlg = b.contextConstructed(0, Buffer.concat([b.oid(O("pbkdf2")), kdfParams]));
    var keyEncAlg = b.sequence([b.oid(O("id-alg-PWRI-KEK")), b.sequence([b.oid(O("aes256-CBC")), b.octetString(iv)])]);
    return { tag: 3, node: b.sequence([b.integer(0n), kdfAlg, keyEncAlg, b.octetString(encryptedKey)]) };
  } finally {
    guard.secret.zeroize(kek, CmsError, "cms/bad-input", "the password-derived key-encryption key");
  }
}

var KEM_WRAP = intrinsic.create(null);
KEM_WRAP[O("id-ml-kem-512")] = "aes128-wrap";
KEM_WRAP[O("id-ml-kem-768")] = "aes256-wrap";
KEM_WRAP[O("id-ml-kem-1024")] = "aes256-wrap";
var KEM_WC = intrinsic.create(null); KEM_WC[O("id-ml-kem-512")] = "ML-KEM-512"; KEM_WC[O("id-ml-kem-768")] = "ML-KEM-768"; KEM_WC[O("id-ml-kem-1024")] = "ML-KEM-1024";

function _kemOtherInfo(wrapName, kekBytes, ukm) {
  var kids = [_algId(wrapName, "absent"), b.integer(BigInt(kekBytes))];
  if (ukm) kids.push(b.explicit(0, b.octetString(ukm)));
  return b.sequence(kids);
}
async function _kemEncapsulate(keyOid, cert) {
  if (KEM_WC[keyOid]) {
    var pub = await subtle.importKey("spki", cert.subjectPublicKeyInfo.bytes, { name: KEM_WC[keyOid] }, false, ["encapsulateBits"]);
    var kem = await subtle.encapsulateBits({ name: KEM_WC[keyOid] }, pub);
    return { ss: Buffer.from(kem.sharedKey), kemct: Buffer.from(kem.ciphertext), wrapName: KEM_WRAP[keyOid], raw: kem.sharedKey };
  }
  if (compositeKem.isCompositeKem(keyOid)) {
    var out = await compositeKem.encapsulate(cert.subjectPublicKeyInfo.bytes);
    return { ss: out.sharedSecret, kemct: out.ciphertext, wrapName: "aes256-wrap", raw: null };
  }
  throw _err("cms/unsupported-algorithm", "unsupported KEM recipient key algorithm");
}
async function _buildKemri(cek, cert, opts) {
  _assertKeyUsage(cert, "keyEncipherment", "kemri");
  var keyOid = cert.subjectPublicKeyInfo.algorithm.oid;
  var ukm = opts.ukm ? guard.bytes.view(opts.ukm, CmsError, "cms/bad-input", "ukm") : null;
  var enc = await _kemEncapsulate(keyOid, cert);
  var wrapName = enc.wrapName;
  var kekBytes = WRAP_KEK_LENGTHS[O(wrapName)];
  var ss = enc.ss, kemct = enc.kemct;
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
    guard.secret.zeroizeAll([ss, kek, enc.raw ? new Uint8Array(enc.raw) : null, kekAb ? new Uint8Array(kekAb) : null],
      CmsError, "cms/bad-input", "the KEM shared secret");
  }
}

async function _aesKwWrap(kek, cek) {
  var kekKey = await subtle.importKey("raw", kek, { name: "AES-KW" }, false, ["wrapKey"]);
  var cekKey = await subtle.importKey("raw", cek, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);
  return Buffer.from(await subtle.wrapKey("raw", cekKey, kekKey, { name: "AES-KW" }));
}

function _pwriFormat(cek) {
  var count = cek.length;
  if (count < 1 || count > 255) throw _err("cms/bad-input", "the CEK length is out of the RFC 3211 range");
  var check = Buffer.from([count, cek[0] ^ 0xff, cek[1] ^ 0xff, cek[2] ^ 0xff]);
  var body = Buffer.concat([check, cek]);
  var blk = 16;
  var padLen = body.length % blk === 0 ? 0 : blk - (body.length % blk);
  if (body.length + padLen < 2 * blk) padLen += (2 * blk - (body.length + padLen));
  var wrapped = Buffer.concat([body, nodeCrypto.randomBytes(padLen)]);
  guard.secret.zeroizeAll([check, body], CmsError, "cms/bad-input", "a PWRI formatting intermediate");
  return wrapped;
}
function _pwriWrapIv(kek, cek, iv) {
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

var PRF_HASH = intrinsic.assign(intrinsic.create(null), { hmacWithSHA1: "SHA-1", hmacWithSHA256: "SHA-256", hmacWithSHA384: "SHA-384", hmacWithSHA512: "SHA-512" });
function _prfHash(prf) { if (!PRF_HASH[guard.text.keyOf(prf)]) throw _err("cms/bad-input", "unsupported pwri prf " + guard.text.showValue(prf)); return PRF_HASH[guard.text.keyOf(prf)]; }

var _PWRI_KEYS = intrinsic.assign(intrinsic.create(null), { password: 1, iterations: 1, prf: 1, salt: 1 });
var _KEKRI_KEYS = intrinsic.assign(intrinsic.create(null), { kek: 1, kekId: 1 });
var _KTRI_RECIPIENT_KEYS = intrinsic.assign(intrinsic.create(null), { cert: 1, oaepHash: 1, keyIdentifier: 1 });
var _AGREE_RECIPIENT_KEYS = intrinsic.assign(intrinsic.create(null), { cert: 1, keyIdentifier: 1, ukm: 1 });

var _RECIPIENT_DEFAULTS = ["oaepHash", "keyIdentifier", "ukm"];

function _assertRecipientKeys(desc, known, arm) {
  guard.identifier.assertKnownKeys(desc, known, _err, "cms/bad-input", function (k) {
    return "unknown field " + JSON.stringify(k) + " on a " + arm +
      " recipient; that field is not read for this recipient type";
  });
}

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
    if (KEM_WC[keyOid] || compositeKem.isCompositeKem(keyOid)) {
      _assertRecipientKeys(desc, _AGREE_RECIPIENT_KEYS, "KEM certificate");
      return _buildKemri(cek, cert, mergeOpts(opts, desc, _AGREE_RECIPIENT_KEYS, consumed));
    }
    throw _err("cms/unsupported-algorithm", "unsupported recipient certificate key algorithm " + keyOid);
  }
  throw _err("cms/bad-input", "a recipient needs { cert }, { password }, or { kek, kekId }");
}
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
function _taggedRecipient(r) {
  if (r.tag == null) return r.node;
  return b.contextConstructed(r.tag, r.node.subarray(_tlvHeaderLen(r.node)));
}

function _envelopedVersion(recips, hasUnprotected) {
  var anyOri = recips.some(function (r) { return r.tag === 4 || r.tag === 3; });
  if (anyOri) return 3;
  var forcesTwo = hasUnprotected || recips.some(function (r) { return r.tag === 1 || r.tag === 2 || (r.tag == null && r._riVersion === 2); });
  return forcesTwo ? 2 : 0;
}

var _ENCRYPT_OPTS_AEAD = intrinsic.assign(intrinsic.create(null), {
  contentEncryptionAlgorithm: 1, contentType: 1, authAttrs: 1, oaepHash: 1, keyIdentifier: 1,
  ukm: 1, pem: 1,
});
var _ENCRYPT_OPTS_CBC = intrinsic.assign(intrinsic.create(null), {
  contentEncryptionAlgorithm: 1, contentType: 1, oaepHash: 1, keyIdentifier: 1, ukm: 1, pem: 1,
});
var _AUTHENTICATE_OPTS_ATTRS = intrinsic.assign(intrinsic.create(null), {
  macAlgorithm: 1, digestAlgorithm: 1, authenticatedAttributes: 1, authAttrs: 1, contentType: 1,
  keyIdentifier: 1, oaepHash: 1, ukm: 1, pem: 1,
});
var _AUTHENTICATE_OPTS_BARE = intrinsic.assign(intrinsic.create(null), {
  macAlgorithm: 1, authenticatedAttributes: 1, contentType: 1,
  keyIdentifier: 1, oaepHash: 1, ukm: 1, pem: 1,
});

function encrypt(content, recipients, opts) {
  return guard.bytes.fixedCall(CmsError, "cms/bad-input", [
    [recipients, "recipients"], [opts, "pki.cms.encrypt options"],
  ], function (recipientsCopy, optsCopy) {
    return _encryptImpl(content, recipientsCopy, optsCopy);
  });
}

async function _encryptImpl(content, recipients, opts) {
  opts = opts || {};
  var algName = opts.contentEncryptionAlgorithm || "aes-256-gcm";
  var ca = CONTENT_ALGS[guard.text.keyOf(algName)];
  if (!ca) throw _err("cms/bad-input", "unsupported contentEncryptionAlgorithm " + guard.text.showValue(algName));
  guard.identifier.assertKnownKeys(opts, ca.aead ? _ENCRYPT_OPTS_AEAD : _ENCRYPT_OPTS_CBC, _err, "cms/bad-input",
    function (k) {
      return "pki.cms.encrypt has an unknown option " + JSON.stringify(k) +
        (!ca.aead && k === "authAttrs"
          ? " for a CBC content algorithm; authenticated attributes are carried only by an AuthEnvelopedData, which an AEAD algorithm produces"
          : "");
    });
  var contentStream = guard.bytes.asyncStreamOf(content);
  var contentBytes = contentStream ? null : guard.bytes.view(content, CmsError, "cms/bad-input", "content");
  var contentType = opts.contentType || "data";
  var cek = nodeCrypto.randomBytes(ca.keyBits / 8);

  try {
    if (!Array.isArray(recipients)) return await _encryptedData(contentBytes, contentStream, recipients, ca, contentType, opts, cek);

    if (!recipients.length) throw _err("cms/bad-input", "at least one recipient is required (RFC 5652 sec. 6.1)");
    var recips = [];
    var consumed = intrinsic.create(null);
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

async function _encStream(spec, stream) {
  try {
    return await subtle.encryptStream(spec, stream);
  } catch (e) {
    guard.bytes.translateStreamError(e, _err, "cms/bad-input");
  }
}

async function _envelopedData(contentBytes, contentStream, cek, ca, contentType, riNodes, recips) {
  var iv = nodeCrypto.randomBytes(16);
  var enc = contentStream
    ? (await _encStream({ algNode: "aes-" + ca.keyBits + "-cbc", key: cek, iv: iv }, contentStream)).ciphertext
    : pbes2.cbcEncrypt(cek, iv, contentBytes, ca.keyBits, CmsError, "cms/bad-input");
  var eci = b.sequence([b.oid(O(contentType)), b.sequence([b.oid(O(ca.oid)), b.octetString(iv)]), b.contextPrimitive(0, enc)]);
  return b.sequence([b.integer(BigInt(_envelopedVersion(recips, false))), b.setOf(riNodes), eci]);
}

function _assertAuthAttrs(pairs, forbidden) {
  var dense = pkiBuild.reqDenseArray(pairs, "authAttrs", _err, "cms/bad-input");
  var seenTypes = intrinsic.create(null);
  dense.forEach(function (p) {
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
  return dense;
}

var AUTH_ENVELOPED_FORBIDDEN = intrinsic.assign(intrinsic.create(null), {
  oid: O("messageDigest"),
  why: "authAttrs must not carry the message-digest attribute in an AuthEnvelopedData: its value is the unencrypted hash of the plaintext, which enables content tracking and confirmation of a guessed plaintext (RFC 5083 sec. 2.1, sec. 5)",
});

async function _authEnvelopedData(contentBytes, contentStream, cek, ca, contentType, opts, riNodes, recips) {
  var nonce = nodeCrypto.randomBytes(12);
  var authAttrsDer = null, aad = Buffer.alloc(0);
  if (contentType !== "data" && !(opts.authAttrs && opts.authAttrs.length)) {
    throw _err("cms/bad-input", "AuthEnvelopedData with a non-data contentType requires authAttrs (RFC 5083 sec. 2.1)");
  }
  if (opts.authAttrs && opts.authAttrs.length) {
    var denseAttrs = _assertAuthAttrs(opts.authAttrs, AUTH_ENVELOPED_FORBIDDEN);
    var setOf = b.setOf(denseAttrs);
    aad = setOf; authAttrsDer = b.contextConstructed(1, setOf.subarray(_tlvHeaderLen(setOf)));
  }
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

var _ENCRYPTED_DATA_CEK_KEYS = intrinsic.assign(intrinsic.create(null), { cek: 1 });
var _ENCRYPTED_DATA_PW_KEYS = intrinsic.assign(intrinsic.create(null), { password: 1, iterations: 1, salt: 1, prf: 1 });

async function _encryptedData(contentBytes, contentStream, desc, ca, contentType, opts, cek) {
  if (ca.aead) throw _err("cms/bad-input", "EncryptedData supports only CBC content encryption");
  _assertDefaultsConsumed(opts, {});
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
  var pwOwn2 = pbes2.passwordBytesOwned(desc.password, _err, "cms");
  var password = pwOwn2.bytes;
  var iterations = pbes2.assertIterations(desc.iterations == null ? 600000 : desc.iterations, _err, "cms");
  var salt = desc.salt ? pbes2.assertSalt(guard.bytes.view(desc.salt, CmsError, "cms/bad-input", "salt"), _err, "cms") : nodeCrypto.randomBytes(16);
  var prf = desc.prf || "hmacWithSHA256";
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

function _gcmEncrypt(key, nonce, plaintext, aad, keyBits, tagLen) {
  var c = nodeCrypto.createCipheriv("aes-" + keyBits + "-gcm", key, nonce, { authTagLength: tagLen });
  if (aad && aad.length) c.setAAD(aad);
  var ct = guard.secret.cipherFinish(c, plaintext, CmsError, "cms/bad-input", "a content-encryption intermediate");
  return { ct: ct, tag: c.getAuthTag() };
}

function _tlvHeaderLen(der) {
  var lenByte = der[1];
  if (lenByte < 0x80) return 2;
  return 2 + (lenByte & 0x7f);
}


var MAC_ALGS = intrinsic.assign(intrinsic.create(null), {
  "hmac-sha256": { oid: "hmacWithSHA256", wc: "SHA-256", node: "sha256" },
  "hmac-sha384": { oid: "hmacWithSHA384", wc: "SHA-384", node: "sha384" },
  "hmac-sha512": { oid: "hmacWithSHA512", wc: "SHA-512", node: "sha512" },
});
var MAC_KEY_OCTETS = 32;
var SUPPORTED_DIGEST = intrinsic.assign(intrinsic.create(null), { sha256: 1, sha384: 1, sha512: 1 });

async function authenticate(content, recipients, opts) {
  opts = opts || {};
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
  var mac = MAC_ALGS[guard.text.keyOf(macName)];
  if (!mac) throw _err("cms/bad-input", "unsupported macAlgorithm " + guard.text.showValue(macName) + " (hmac-sha256/384/512)");
  if (!Array.isArray(recipients) || !recipients.length) throw _err("cms/bad-input", "at least one recipient is required (RFC 5652 sec. 9.1)");
  var contentType = opts.contentType || "data";
  if (contentType !== "data" && !withAttrs) throw _err("cms/bad-input", "AuthenticatedData with a non-data contentType requires authenticated attributes (RFC 5652 sec. 9.1)");

  var macKey = nodeCrypto.randomBytes(MAC_KEY_OCTETS);
  try {
    var recips = [];
    var consumedAuth = {};
    for (var i = 0; i < recipients.length; i++) recips.push(await _buildRecipient(macKey, recipients[i], opts, consumedAuth));
    _assertDefaultsConsumed(opts, consumedAuth);
    var riNodes = recips.map(_taggedRecipient);

    var digestAlgTagged = null, authAttrsDer = null, preimage;
    if (withAttrs) {
      var digestName = opts.digestAlgorithm || mac.node;
      if (!SUPPORTED_DIGEST[guard.text.keyOf(digestName)]) throw _err("cms/bad-input", "unsupported digestAlgorithm " + guard.text.showValue(digestName) + " (sha256/384/512)");
      var mdDigest = nodeCrypto.createHash(digestName).update(contentBytes).digest();
      var pairs = [
        b.sequence([b.oid(O("contentType")), b.setOf([b.oid(O(contentType))])]),
        b.sequence([b.oid(O("messageDigest")), b.setOf([b.octetString(mdDigest)])]),
      ];
      if (opts.authAttrs && opts.authAttrs.length) pairs = pairs.concat(opts.authAttrs);
      pairs = _assertAuthAttrs(pairs, null);
      var setOf = b.setOf(pairs);
      preimage = setOf;
      authAttrsDer = b.contextConstructed(2, setOf.subarray(_tlvHeaderLen(setOf)));
      digestAlgTagged = b.contextConstructed(1, b.oid(O(digestName)));
    } else {
      preimage = contentBytes;
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
    try { schemaCms.parse(ci); } catch (e) { throw (e instanceof CmsError) ? e : _err("cms/bad-input", "the supplied authenticated attributes produced an invalid AuthenticatedData", e); }
    return opts.pem ? schemaCms.pemEncode(ci, "CMS") : ci;
  } finally {
    guard.secret.zeroize(macKey, CmsError, "cms/bad-input", "the message-authentication key");
  }
}

module.exports = { encrypt: encrypt, authenticate: authenticate };
