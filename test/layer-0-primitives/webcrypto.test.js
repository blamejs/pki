// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.webcrypto (W3C SubtleCrypto engine).
 * Oracle: SHA known-answer vectors; sign/verify round-trips across the
 * classical AND post-quantum algorithm set; cross-verification with
 * Node's native crypto (an independent implementation path).
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var nodeCrypto = require("node:crypto");
function code(fn) { return fn().then(function () { return "NO-THROW"; }, function (e) { return e.code; }); }
function hex(ab) { return Buffer.from(ab).toString("hex"); }

var subtle = pki.webcrypto.subtle;

async function testRandom() {
  var a = new Uint8Array(16);
  var r = pki.webcrypto.getRandomValues(a);
  check("getRandomValues returns the same array", r === a);
  check("getRandomValues filled (not all-zero)", a.some(function (x) { return x !== 0; }));
  check("randomUUID shape", /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(pki.webcrypto.randomUUID()));
  check("getRandomValues rejects >64KiB", (await code(async function () { pki.webcrypto.getRandomValues(new Uint8Array(65537)); })) === "webcrypto/data");
  check("getRandomValues rejects Float64Array", (await code(async function () { pki.webcrypto.getRandomValues(new Float64Array(4)); })) === "webcrypto/data");
  // A detached-backed view must fail closed as a typed error, not a raw TypeError.
  check("getRandomValues rejects a detached-backed view", (await code(async function () {
    var u = new Uint8Array(8); structuredClone(u.buffer, { transfer: [u.buffer] });
    pki.webcrypto.getRandomValues(u);
  })) === "webcrypto/data");
}

async function testDigest() {
  var abc = Buffer.from("abc");
  check("SHA-256(abc)", hex(await subtle.digest("SHA-256", abc)) === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  check("SHA-1(abc) [legacy compat]", hex(await subtle.digest("SHA-1", abc)) === "a9993e364706816aba3e25717850c26c9cd0d89d");
  check("SHA-512(abc) length", (await subtle.digest("SHA-512", abc)).byteLength === 64);
  check("SHA3-256(abc)", hex(await subtle.digest("SHA3-256", abc)) === "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
  // _toBuf must surface a detached-backed BufferSource as a typed webcrypto/data
  // error, not a raw TypeError from Buffer.from -- for both a view and a raw
  // ArrayBuffer whose backing store was transferred away.
  check("digest rejects a detached-backed view", (await code(async function () {
    var u = new Uint8Array(8); structuredClone(u.buffer, { transfer: [u.buffer] });
    await subtle.digest("SHA-256", u);
  })) === "webcrypto/data");
  check("digest rejects a detached ArrayBuffer", (await code(async function () {
    var ab = new ArrayBuffer(8); structuredClone(ab, { transfer: [ab] });
    await subtle.digest("SHA-256", ab);
  })) === "webcrypto/data");
  // A detached-backed BUFFER reads as zero-length: without the guard, digest
  // would silently hash EMPTY (a fail-OPEN, not a throw). It must fail closed.
  check("digest rejects a detached Buffer (fail-open guard)", (await code(async function () {
    var ab = new ArrayBuffer(8); var b = Buffer.from(ab); structuredClone(ab, { transfer: [ab] });
    await subtle.digest("SHA-256", b);
  })) === "webcrypto/data");
}

async function _signVerify(genAlg, signAlg, usages) {
  var kp = await subtle.generateKey(genAlg, true, usages || ["sign", "verify"]);
  var data = Buffer.from("the bytes that were signed");
  var sig = await subtle.sign(signAlg || genAlg, kp.privateKey, data);
  var ok = await subtle.verify(signAlg || genAlg, kp.publicKey, sig, data);
  var tampered = await subtle.verify(signAlg || genAlg, kp.publicKey, sig, Buffer.from("different bytes entirely!!"));
  return { kp: kp, sig: sig, ok: ok, tampered: tampered, data: data };
}

async function testClassicalSign() {
  var ec = await _signVerify({ name: "ECDSA", namedCurve: "P-256" }, { name: "ECDSA", hash: "SHA-256" });
  check("ECDSA P-256 verifies", ec.ok === true);
  check("ECDSA P-256 rejects tamper", ec.tampered === false);
  // Cross-verify with Node native (independent path): export SPKI, verify P1363 sig.
  var spki = await subtle.exportKey("spki", ec.kp.publicKey);
  var nativeKey = nodeCrypto.createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
  check("ECDSA sig cross-verifies with node native", nodeCrypto.verify("sha256", ec.data, { key: nativeKey, dsaEncoding: "ieee-p1363" }, Buffer.from(ec.sig)));

  var ed = await _signVerify({ name: "Ed25519" });
  check("Ed25519 verifies + rejects tamper", ed.ok === true && ed.tampered === false);

  var pss = await _signVerify({ name: "RSA-PSS", modulusLength: 2048, hash: "SHA-256" }, { name: "RSA-PSS", saltLength: 32 });
  check("RSA-PSS verifies + rejects tamper", pss.ok === true && pss.tampered === false);

  var pkcs1 = await _signVerify({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  check("RSASSA-PKCS1-v1_5 verifies + rejects tamper", pkcs1.ok === true && pkcs1.tampered === false);
}

async function testPqcSign() {
  for (var lvl of ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F", "SLH-DSA-SHAKE-256F"]) {
    var r = await _signVerify({ name: lvl });
    check(lvl + " verifies + rejects tamper (PQC)", r.ok === true && r.tampered === false);
  }
  // ML-KEM: key generation + SPKI export ship today (KEM encapsulation
  // follows once Node exposes it).
  var kem = await subtle.generateKey({ name: "ML-KEM-768" }, true, []);
  check("ML-KEM-768 key generation + SPKI export", (await subtle.exportKey("spki", kem.publicKey)).byteLength > 0);
}

async function testImportExport() {
  var kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
  var spki = await subtle.exportKey("spki", kp.publicKey);
  var pub2 = await subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-384" }, true, ["verify"]);
  var data = Buffer.from("round-trip");
  var sig = await subtle.sign({ name: "ECDSA", hash: "SHA-384" }, kp.privateKey, data);
  check("SPKI export/import round-trips (verify)", await subtle.verify({ name: "ECDSA", hash: "SHA-384" }, pub2, sig, data));

  var pkcs8 = await subtle.exportKey("pkcs8", kp.privateKey);
  var priv2 = await subtle.importKey("pkcs8", pkcs8, { name: "ECDSA", namedCurve: "P-384" }, true, ["sign"]);
  check("PKCS8 export/import round-trips (sign)", (await subtle.sign({ name: "ECDSA", hash: "SHA-384" }, priv2, data)).byteLength > 0);

  var jwk = await subtle.exportKey("jwk", kp.publicKey);
  check("JWK export has EC coords", jwk.kty === "EC" && !!jwk.x && !!jwk.y);
  var pub3 = await subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-384" }, true, ["verify"]);
  check("JWK export/import round-trips (verify)", await subtle.verify({ name: "ECDSA", hash: "SHA-384" }, pub3, sig, data));

  var raw = await subtle.exportKey("raw", kp.publicKey);
  check("raw EC point is uncompressed", new Uint8Array(raw)[0] === 0x04);
  var pub4 = await subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-384" }, true, ["verify"]);
  check("raw export/import round-trips (verify)", await subtle.verify({ name: "ECDSA", hash: "SHA-384" }, pub4, sig, data));

  check("non-extractable export throws", (await code(async function () {
    var k = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    await subtle.exportKey("pkcs8", k.privateKey);
  })) === "webcrypto/invalid-access");
}

// W3C WebCrypto §ECDSA/ECDH "import key" — the imported EC key's curve is taken
// from the KEY material; it MUST equal the requested namedCurve (else DataError)
// and MUST be a supported curve (else NotSupportedError), across spki, pkcs8 and
// jwk. generateKey already enforces this (webcrypto.js:194); importKey must not
// be more lenient — a mismatch mislabels the CryptoKey (algorithm confusion) and
// an unsupported curve smuggles a non-approved curve past the P-256/384/521 set.
async function testEcImportCurveValidation() {
  function ecDer(nodeCurve) {
    var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: nodeCurve });
    return {
      spki:   kp.publicKey.export({ format: "der", type: "spki" }),
      pkcs8:  kp.privateKey.export({ format: "der", type: "pkcs8" }),
      pubJwk: kp.publicKey.export({ format: "jwk" }),
    };
  }
  var p256 = ecDer("prime256v1");
  var p384 = ecDer("secp384r1");
  var k256 = ecDer("secp256k1"); // not in the framework's CURVE_NODE set

  // Unsupported curve → NotSupportedError, on every parse-based format.
  check("spki import of an unsupported curve (secp256k1) rejects (not-supported)",
    (await code(async function () { await subtle.importKey("spki", k256.spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]); })) === "webcrypto/not-supported");
  check("pkcs8 import of an unsupported curve rejects (not-supported)",
    (await code(async function () { await subtle.importKey("pkcs8", k256.pkcs8, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]); })) === "webcrypto/not-supported");
  check("jwk import of an unsupported curve rejects (not-supported)",
    (await code(async function () { await subtle.importKey("jwk", k256.pubJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]); })) === "webcrypto/not-supported");

  // Curve mismatch: a real P-384 key claimed as P-256 → DataError.
  check("spki import with namedCurve != key curve rejects (data)",
    (await code(async function () { await subtle.importKey("spki", p384.spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]); })) === "webcrypto/data");
  check("pkcs8 import with namedCurve != key curve rejects (data)",
    (await code(async function () { await subtle.importKey("pkcs8", p384.pkcs8, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]); })) === "webcrypto/data");
  check("jwk import with jwk.crv != namedCurve rejects (data)",
    (await code(async function () { await subtle.importKey("jwk", p384.pubJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]); })) === "webcrypto/data");

  // ECDH routes through the same path.
  check("ECDH import with namedCurve != key curve rejects (data)",
    (await code(async function () { await subtle.importKey("spki", p384.spki, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]); })) === "webcrypto/data");

  // Matching + supported succeeds, and algorithm.namedCurve is taken from the key.
  check("spki import with matching P-256 succeeds, namedCurve from key",
    (await (async function () { var k = await subtle.importKey("spki", p256.spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]); return k.algorithm.namedCurve; })()) === "P-256");
  check("pkcs8 import with matching P-384 succeeds, namedCurve from key",
    (await (async function () { var k = await subtle.importKey("pkcs8", p384.pkcs8, { name: "ECDSA", namedCurve: "P-384" }, true, ["sign"]); return k.algorithm.namedCurve; })()) === "P-384");
}

async function testEncrypt() {
  // AES-GCM round-trip with AAD.
  var key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  var iv = pki.webcrypto.getRandomValues(new Uint8Array(12));
  var pt = Buffer.from("secret payload");
  var ct = await subtle.encrypt({ name: "AES-GCM", iv: iv, additionalData: Buffer.from("hdr") }, key, pt);
  var back = await subtle.decrypt({ name: "AES-GCM", iv: iv, additionalData: Buffer.from("hdr") }, key, ct);
  check("AES-GCM round-trips", Buffer.from(back).toString() === "secret payload");
  check("AES-GCM rejects wrong AAD", (await code(async function () {
    await subtle.decrypt({ name: "AES-GCM", iv: iv, additionalData: Buffer.from("WRONG") }, key, ct);
  })) !== "NO-THROW");

  // RSA-OAEP round-trip.
  var rkp = await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
  var enc = await subtle.encrypt({ name: "RSA-OAEP" }, rkp.publicKey, Buffer.from("key material"));
  var dec = await subtle.decrypt({ name: "RSA-OAEP" }, rkp.privateKey, enc);
  check("RSA-OAEP round-trips", Buffer.from(dec).toString() === "key material");
}

async function testDerive() {
  // ECDH agreement: two parties derive the same secret.
  var a = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  var b = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  var sa = await subtle.deriveBits({ name: "ECDH", public: b.publicKey }, a.privateKey, 256);
  var sb = await subtle.deriveBits({ name: "ECDH", public: a.publicKey }, b.privateKey, 256);
  check("ECDH derives a shared secret", hex(sa) === hex(sb) && hex(sa).length === 64);

  // HKDF + PBKDF2 determinism.
  var ikm = await subtle.importKey("raw", Buffer.from("input key material"), { name: "HKDF" }, false, ["deriveBits"]);
  var h1 = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: Buffer.from("salt"), info: Buffer.from("ctx") }, ikm, 256);
  var h2 = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: Buffer.from("salt"), info: Buffer.from("ctx") }, ikm, 256);
  check("HKDF is deterministic + 32 bytes", hex(h1) === hex(h2) && h1.byteLength === 32);

  var pw = await subtle.importKey("raw", Buffer.from("password"), { name: "PBKDF2" }, false, ["deriveBits"]);
  var p1 = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: Buffer.from("NaCl"), iterations: 1000 }, pw, 256);
  check("PBKDF2 derives 32 bytes deterministically", p1.byteLength === 32);
}

async function testWrap() {
  var kek = await subtle.generateKey({ name: "AES-KW", length: 256 }, true, ["wrapKey", "unwrapKey"]);
  var target = await subtle.generateKey({ name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
  var wrapped = await subtle.wrapKey("raw", target, kek, { name: "AES-KW" });
  var unwrapped = await subtle.unwrapKey("raw", wrapped, kek, { name: "AES-KW" }, { name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
  var origRaw = await subtle.exportKey("raw", target);
  var unwrappedRaw = await subtle.exportKey("raw", unwrapped);
  check("AES-KW wrap/unwrap round-trips the key", hex(origRaw) === hex(unwrappedRaw));
}

async function testUnwrapKeyUsage() {
  // unwrapKey must enforce the "unwrapKey" usage on BOTH the AES-KW path and
  // the delegated (RSA-OAEP) path — the latter previously fell open because
  // it only ever checked "decrypt" on an internally-cloned key.
  var rkp = await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256" }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
  var target = await subtle.generateKey({ name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
  var wrapped = await subtle.wrapKey("raw", target, rkp.publicKey, { name: "RSA-OAEP" });
  // A private key holding "decrypt" but NOT "unwrapKey" must be refused.
  var pkcs8 = await subtle.exportKey("pkcs8", rkp.privateKey);
  var privNoUnwrap = await subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
  check("unwrapKey (RSA-OAEP) enforces 'unwrapKey' usage", (await code(async function () {
    await subtle.unwrapKey("raw", wrapped, privNoUnwrap, { name: "RSA-OAEP" }, { name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
  })) === "webcrypto/invalid-access");
  // With the usage present it round-trips.
  var privUnwrap = await subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt", "unwrapKey"]);
  var unwrapped = await subtle.unwrapKey("raw", wrapped, privUnwrap, { name: "RSA-OAEP" }, { name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
  check("unwrapKey (RSA-OAEP) round-trips with the usage present",
    hex(await subtle.exportKey("raw", target)) === hex(await subtle.exportKey("raw", unwrapped)));
}

async function testDeriveKeyUsage() {
  // deriveKey requires the "deriveKey" usage — not "deriveBits".
  var pubB = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
  var withDeriveKey = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
  var derived = await subtle.deriveKey({ name: "ECDH", public: pubB.publicKey }, withDeriveKey.privateKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  check("deriveKey accepts a ['deriveKey'] base key", derived.type === "secret" && derived.algorithm.length === 256);
  // A ['deriveBits']-only key must NOT be usable for deriveKey (fail closed).
  var deriveBitsOnly = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  check("deriveKey rejects a ['deriveBits']-only base key", (await code(async function () {
    await subtle.deriveKey({ name: "ECDH", public: pubB.publicKey }, deriveBitsOnly.privateKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  })) === "webcrypto/invalid-access");
  // deriveBits still enforces its own "deriveBits" usage.
  check("deriveBits still rejects a ['deriveKey']-only base key", (await code(async function () {
    await subtle.deriveBits({ name: "ECDH", public: pubB.publicKey }, withDeriveKey.privateKey, 256);
  })) === "webcrypto/invalid-access");
}

async function testHmacVerifyLength() {
  var hkey = await subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"]);
  var data = Buffer.from("authenticated message");
  var goodSig = await subtle.sign({ name: "HMAC" }, hkey, data);
  check("HMAC valid signature verifies", (await subtle.verify({ name: "HMAC" }, hkey, goodSig, data)) === true);
  // A wrong-length signature must RESOLVE false, not throw RangeError.
  var threw = false, result;
  try { result = await subtle.verify({ name: "HMAC" }, hkey, new Uint8Array(5), data); } catch (_e) { threw = true; }
  check("HMAC verify resolves false for a wrong-length signature", threw === false && result === false);
}

async function testAesCtrLength() {
  var ctrKey = await subtle.generateKey({ name: "AES-CTR", length: 256 }, true, ["encrypt", "decrypt"]);
  var counter = pki.webcrypto.getRandomValues(new Uint8Array(16));
  // node cannot honor a counter width < 128, so any non-128 length is refused.
  check("AES-CTR encrypt rejects length != 128", (await code(async function () {
    await subtle.encrypt({ name: "AES-CTR", counter: counter, length: 64 }, ctrKey, Buffer.from("x"));
  })) === "webcrypto/not-supported");
  check("AES-CTR decrypt rejects length != 128", (await code(async function () {
    await subtle.decrypt({ name: "AES-CTR", counter: counter, length: 64 }, ctrKey, Buffer.from("x"));
  })) === "webcrypto/not-supported");
  // length:128 round-trips.
  var ct = await subtle.encrypt({ name: "AES-CTR", counter: counter, length: 128 }, ctrKey, Buffer.from("ctr payload"));
  var back = await subtle.decrypt({ name: "AES-CTR", counter: counter, length: 128 }, ctrKey, ct);
  check("AES-CTR length:128 round-trips", Buffer.from(back).toString() === "ctr payload");
}

// W3C WebCrypto sign/verify/encrypt/decrypt/deriveBits/deriveKey/wrapKey/
// unwrapKey: when the requested algorithm's name differs from the key's own
// algorithm name the operation MUST throw an InvalidAccessError. The binding
// is load-bearing for the one-shot families (EdDSA / ML-DSA / SLH-DSA), where
// node derives the algorithm from the KEY handle and the requested name would
// otherwise be silently ignored -- verify({name:"Ed25519"}, mlDsaKey, ...)
// must not report an ML-DSA verification as an Ed25519 one.
async function testAlgorithmKeyBinding() {
  var data = Buffer.from("bound to the key's own algorithm");
  var ml = await subtle.generateKey({ name: "ML-DSA-44" }, true, ["sign", "verify"]);
  var mlSig = await subtle.sign({ name: "ML-DSA-44" }, ml.privateKey, data);
  check("verify binds the name to the key (Ed25519 name on an ML-DSA key)",
    (await code(async function () { await subtle.verify({ name: "Ed25519" }, ml.publicKey, mlSig, data); })) === "webcrypto/invalid-access");
  check("verify binds the name across PQC families (SLH-DSA name on an ML-DSA key)",
    (await code(async function () { await subtle.verify({ name: "SLH-DSA-SHA2-128S" }, ml.publicKey, mlSig, data); })) === "webcrypto/invalid-access");
  check("sign binds the name to the key (Ed448 name on an ML-DSA key)",
    (await code(async function () { await subtle.sign({ name: "Ed448" }, ml.privateKey, data); })) === "webcrypto/invalid-access");

  // RSA: PKCS#1 v1.5 and PSS are distinct algorithms; a key labeled for one
  // must not sign or verify under the other.
  var pkcs1 = await subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" }, true, ["sign", "verify"]);
  var pkcs1Sig = await subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, pkcs1.privateKey, data);
  check("an RSASSA-PKCS1-v1_5 key cannot sign under RSA-PSS",
    (await code(async function () { await subtle.sign({ name: "RSA-PSS", saltLength: 32 }, pkcs1.privateKey, data); })) === "webcrypto/invalid-access");
  check("an RSASSA-PKCS1-v1_5 key cannot verify under RSA-PSS",
    (await code(async function () { await subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pkcs1.publicKey, pkcs1Sig, data); })) === "webcrypto/invalid-access");

  var gcm = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  var iv = pki.webcrypto.getRandomValues(new Uint8Array(16));
  check("an AES-GCM key cannot encrypt under AES-CBC",
    (await code(async function () { await subtle.encrypt({ name: "AES-CBC", iv: iv }, gcm, data); })) === "webcrypto/invalid-access");
  check("an AES-GCM key cannot decrypt under AES-CBC",
    (await code(async function () { await subtle.decrypt({ name: "AES-CBC", iv: iv }, gcm, Buffer.alloc(16)); })) === "webcrypto/invalid-access");

  var ec = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits", "deriveKey"]);
  var xk = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  check("deriveBits binds the name to the base key",
    (await code(async function () { await subtle.deriveBits({ name: "X25519", public: xk.publicKey }, ec.privateKey, 256); })) === "webcrypto/invalid-access");
  check("deriveBits binds the name to the peer public key",
    (await code(async function () { await subtle.deriveBits({ name: "ECDH", public: xk.publicKey }, ec.privateKey, 256); })) === "webcrypto/invalid-access");
  check("deriveKey binds the name to the base key",
    (await code(async function () { await subtle.deriveKey({ name: "X25519", public: xk.publicKey }, ec.privateKey, { name: "AES-GCM", length: 256 }, true, ["encrypt"]); })) === "webcrypto/invalid-access");

  var kw = await subtle.generateKey({ name: "AES-KW", length: 256 }, true, ["wrapKey", "unwrapKey"]);
  var target = await subtle.generateKey({ name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
  check("wrapKey binds the name to the wrapping key",
    (await code(async function () { await subtle.wrapKey("raw", target, kw, { name: "AES-GCM", iv: iv }); })) === "webcrypto/invalid-access");
  check("unwrapKey binds the name to the unwrapping key",
    (await code(async function () { await subtle.unwrapKey("raw", Buffer.alloc(24), kw, { name: "AES-GCM", iv: iv }, { name: "AES-GCM", length: 128 }, true, ["encrypt"]); })) === "webcrypto/invalid-access");

  // An unrecognized name still reports not-supported: algorithm recognition
  // precedes the name/key binding in the W3C error ordering.
  check("an unrecognized name still reports not-supported, not invalid-access",
    (await code(async function () { await subtle.verify({ name: "NOPE" }, ml.publicKey, mlSig, data); })) === "webcrypto/not-supported");
}

// exportKey("raw") / importKey("raw") for the OKP families: an EdDSA public
// key round-trips through the raw point form, keeps its canonical algorithm
// label, and still verifies.
async function testRawOkpImportExport() {
  var data = Buffer.from("okp raw round-trip");
  var kp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var sig = await subtle.sign({ name: "Ed25519" }, kp.privateKey, data);
  var raw = await subtle.exportKey("raw", kp.publicKey);
  check("raw Ed25519 public export is the 32-byte point", raw.byteLength === 32);
  var pub2 = await subtle.importKey("raw", raw, { name: "Ed25519" }, true, ["verify"]);
  check("raw Ed25519 import is labeled Ed25519", pub2.algorithm.name === "Ed25519");
  check("raw Ed25519 import verifies the original signature", (await subtle.verify({ name: "Ed25519" }, pub2, sig, data)) === true);

  var kp8 = await subtle.generateKey({ name: "Ed448" }, true, ["sign", "verify"]);
  var sig8 = await subtle.sign({ name: "Ed448" }, kp8.privateKey, data);
  var raw8 = await subtle.exportKey("raw", kp8.publicKey);
  var pub8 = await subtle.importKey("raw", raw8, { name: "Ed448" }, true, ["verify"]);
  check("raw Ed448 import is labeled Ed448 and verifies",
    pub8.algorithm.name === "Ed448" && (await subtle.verify({ name: "Ed448" }, pub8, sig8, data)) === true);
}

// W3C deriveBits: a request the derivation cannot satisfy MUST throw an
// OperationError. Buffer.subarray clamps at the end of the secret, so an
// unchecked over-request would silently hand back fewer bytes of key material
// than the caller believes it received; a non-multiple-of-8 length would
// silently truncate to a byte boundary.
async function testDeriveBitsLength() {
  var a = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  var b = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  check("deriveBits rejects a request beyond the ECDH shared-secret size",
    (await code(async function () { await subtle.deriveBits({ name: "ECDH", public: b.publicKey }, a.privateKey, 4096); })) === "webcrypto/operation");
  check("deriveBits rejects a non-multiple-of-8 length",
    (await code(async function () { await subtle.deriveBits({ name: "ECDH", public: b.publicKey }, a.privateKey, 250); })) === "webcrypto/operation");
  check("deriveBits rejects a zero length",
    (await code(async function () { await subtle.deriveBits({ name: "ECDH", public: b.publicKey }, a.privateKey, 0); })) === "webcrypto/operation");
  var full = await subtle.deriveBits({ name: "ECDH", public: b.publicKey }, a.privateKey, null);
  check("deriveBits with a null length returns the full shared secret", full.byteLength === 32);

  var ikm = await subtle.importKey("raw", Buffer.from("input key material"), { name: "HKDF" }, false, ["deriveBits"]);
  check("HKDF deriveBits rejects a non-multiple-of-8 length",
    (await code(async function () { await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: Buffer.from("s"), info: Buffer.from("i") }, ikm, 129); })) === "webcrypto/operation");
  var pw = await subtle.importKey("raw", Buffer.from("password"), { name: "PBKDF2" }, false, ["deriveBits"]);
  check("PBKDF2 deriveBits rejects a non-multiple-of-8 length",
    (await code(async function () { await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: Buffer.from("NaCl"), iterations: 1000 }, pw, 129); })) === "webcrypto/operation");
}

// W3C get-key-length for AES: an AES derivedKeyType carries a REQUIRED length
// of 128/192/256. Deriving without one must fail as a syntax error rather
// than silently sizing the key from the raw agreement secret (a curve-sized
// "AES" key is unusable and wrong).
async function testDeriveKeyAesLength() {
  var a = await subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, true, ["deriveKey"]);
  var b = await subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, true, ["deriveKey"]);
  check("deriveKey rejects an AES derivedKeyType with no length",
    (await code(async function () { await subtle.deriveKey({ name: "ECDH", public: b.publicKey }, a.privateKey, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]); })) === "webcrypto/syntax");
  check("deriveKey rejects an AES derivedKeyType with an off-size length",
    (await code(async function () { await subtle.deriveKey({ name: "ECDH", public: b.publicKey }, a.privateKey, { name: "AES-GCM", length: 384 }, true, ["encrypt", "decrypt"]); })) === "webcrypto/syntax");
  // An explicit 128 over a P-384 secret derives a working 128-bit key.
  var k = await subtle.deriveKey({ name: "ECDH", public: b.publicKey }, a.privateKey, { name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
  var iv = pki.webcrypto.getRandomValues(new Uint8Array(12));
  var ct = await subtle.encrypt({ name: "AES-GCM", iv: iv }, k, Buffer.from("derived"));
  check("deriveKey with an explicit AES length yields a working key",
    Buffer.from(await subtle.decrypt({ name: "AES-GCM", iv: iv }, k, ct)).toString() === "derived" && k.algorithm.length === 128);
}

// W3C HMAC get-key-length: an omitted length defaults to the BLOCK size of
// the hash (the HMAC key-pad width -- 512 bits for SHA-256, 1024 for
// SHA-384), NOT the digest size. A digest-size default would mint key
// material no conforming WebCrypto engine agrees with for identical inputs,
// so MACs keyed through this engine would fail to verify elsewhere.
async function testHmacDefaultLength() {
  var g = await subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"]);
  check("generateKey HMAC defaults to the SHA-256 block size (512 bits)", g.algorithm.length === 512);
  var g384 = await subtle.generateKey({ name: "HMAC", hash: "SHA-384" }, true, ["sign"]);
  check("generateKey HMAC defaults to the SHA-384 block size (1024 bits)", g384.algorithm.length === 1024);
  // A fractional byte count cannot be minted exactly -- typed rejection, not
  // a raw RangeError out of randomBytes.
  check("generateKey HMAC rejects a non-multiple-of-8 length",
    (await code(async function () { await subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 100 }, true, ["sign"]); })) === "webcrypto/syntax");

  // deriveKey inherits the same default: the defaulted derivation must equal
  // an explicit block-size derivation of the same agreement secret.
  var a = await subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey"]);
  var b = await subtle.generateKey({ name: "ECDH", namedCurve: "P-521" }, true, ["deriveKey"]);
  var hk = await subtle.deriveKey({ name: "ECDH", public: b.publicKey }, a.privateKey, { name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
  var hkExplicit = await subtle.deriveKey({ name: "ECDH", public: b.publicKey }, a.privateKey, { name: "HMAC", hash: "SHA-256", length: 512 }, true, ["sign"]);
  var r1 = Buffer.from(await subtle.exportKey("raw", hk));
  var r2 = Buffer.from(await subtle.exportKey("raw", hkExplicit));
  check("deriveKey HMAC without length derives the block-size key",
    hk.algorithm.length === 512 && r1.length === 64 && r1.equals(r2));

  // An HKDF derivedKeyType has no intrinsic size (W3C get-key-length is
  // null): the FULL agreement secret becomes the input keying material --
  // not a silently truncated 256-bit prefix of it.
  var ikm = await subtle.deriveKey({ name: "ECDH", public: b.publicKey }, a.privateKey, { name: "HKDF" }, false, ["deriveBits"]);
  check("deriveKey to an HKDF base key carries the full agreement secret", ikm.algorithm.length === 528);

  // A KDF base has no implicit output size: deriving a length-less KDF type
  // from it must fail closed with the module's typed code, never feed an
  // undefined length into the KDF.
  var kdfBase = await subtle.importKey("raw", Buffer.from("input key material"), { name: "HKDF" }, false, ["deriveKey"]);
  check("deriveKey to a length-less KDF type over a KDF base fails closed",
    (await code(async function () { await subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: Buffer.from("s"), info: Buffer.from("i") }, kdfBase, { name: "HKDF" }, false, ["deriveBits"]); })) === "webcrypto/operation");
}

// W3C RsaKeyGenParams.publicExponent is a BigInteger octet string that the
// engine narrows through Number() for node:crypto. An empty buffer has no
// integer value (BigInt("0x") is a raw SyntaxError), and a value above
// 2^32-1 is outside the interoperable WebCrypto exponent range and heads
// toward Number's exact-integer limit, where the narrowing would silently
// hand node a DIFFERENT exponent than requested. Both must reject typed at
// the entry point, before any narrowing.
async function testRsaPublicExponentValidation() {
  check("generateKey RSA: empty publicExponent rejects typed",
    (await code(async function () {
      await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256", publicExponent: new Uint8Array(0) }, true, ["encrypt", "decrypt"]);
    })) === "webcrypto/syntax");
  check("generateKey RSA: publicExponent above 2^32-1 rejects typed",
    (await code(async function () {
      // 2^56 + 1 -- odd on the wire, but Number(BigInt(2^56+1)) rounds to the
      // even 2^56, so without the bound node would be handed a changed value.
      await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 0, 0, 0, 0, 0, 1]) }, true, ["encrypt", "decrypt"]);
    })) === "webcrypto/syntax");
  check("generateKey RSA: explicit 65537 publicExponent still accepted",
    (await code(async function () {
      await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]) }, true, ["encrypt", "decrypt"]);
    })) === "NO-THROW");
}

// unwrapKey (jwk) under a NON-authenticating algorithm (AES-CBC / AES-CTR)
// "successfully" decrypts tampered bytes; the JSON.parse of that plaintext
// is the first point that can notice, and its failure must surface as the
// module's typed error (W3C: DataError) -- never a raw SyntaxError escaping
// the public API.
async function testUnwrapJwkNotJson() {
  var kek = await subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
  var iv = pki.webcrypto.getRandomValues(new Uint8Array(16));
  var notJwk = await subtle.encrypt({ name: "AES-CBC", iv: iv }, kek, Buffer.from("not a jwk"));
  var err = null;
  try { await subtle.unwrapKey("jwk", notJwk, kek, { name: "AES-CBC", iv: iv }, { name: "AES-GCM", length: 128 }, true, ["encrypt"]); }
  catch (e) { err = e; }
  check("unwrapKey (jwk) surfaces non-JSON plaintext as typed webcrypto/data",
    err instanceof pki.errors.PkiError && err.code === "webcrypto/data");
}

async function testUnwrapJwkDuplicateMember() {
  // The unwrapped JWK must be parsed STRICTLY: a smuggled duplicate member (which
  // bare JSON.parse resolves last-wins) must reject, not import a JWK that differs
  // from what a producer/verifier saw (the JSON parser-differential class).
  var kek = await subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
  var iv = pki.webcrypto.getRandomValues(new Uint8Array(16));
  var validK = Buffer.alloc(16, 3).toString("base64url");
  var dupJwk = '{"kty":"oct","k":"' + validK + '","k":"' + Buffer.alloc(16, 9).toString("base64url") + '"}';
  var wrapped = await subtle.encrypt({ name: "AES-CBC", iv: iv }, kek, Buffer.from(dupJwk));
  var err = null;
  try { await subtle.unwrapKey("jwk", wrapped, kek, { name: "AES-CBC", iv: iv }, { name: "HMAC", hash: "SHA-256" }, true, ["sign"]); }
  catch (e) { err = e; }
  check("unwrapKey (jwk) rejects a smuggled duplicate member", err instanceof pki.errors.PkiError && err.code === "webcrypto/data");
}

async function testSurface() {
  check("pki.webcrypto is a Crypto instance", pki.webcrypto instanceof pki.webcrypto.Crypto);
  check("pki.webcrypto.subtle is a SubtleCrypto", pki.webcrypto.subtle instanceof pki.webcrypto.SubtleCrypto);
  check("WebCryptoError is a PkiError", new pki.webcrypto.WebCryptoError("webcrypto/syntax", "y") instanceof pki.errors.PkiError);
  check("the WebCrypto classes are reachable under pki.webcrypto", typeof pki.webcrypto.CryptoKey === "function" && pki.WebCrypto === undefined);
  var k = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  check("unsupported algorithm throws not-supported", (await code(async function () { await subtle.sign({ name: "NOPE" }, k.privateKey, Buffer.from("x")); })) === "webcrypto/not-supported");
}

async function testJwkOctStrict() {
  // JWK oct key material must decode STRICTLY: a missing / non-canonical / non-
  // alphabet `k` must reject, never silently import WRONG key material (the lenient
  // Buffer.from(String(undefined),"base64url") imported a bogus 6-byte key).
  var hmacAlg = { name: "HMAC", hash: "SHA-256" };
  var validK = Buffer.alloc(32, 7).toString("base64url");   // canonical unpadded base64url
  check("jwk oct: canonical k imports", (await code(function () { return subtle.importKey("jwk", { kty: "oct", k: validK }, hmacAlg, false, ["sign"]); })) === "NO-THROW");
  check("jwk oct: missing k rejects", (await code(function () { return subtle.importKey("jwk", { kty: "oct" }, hmacAlg, false, ["sign"]); })) === "webcrypto/data");
  check("jwk oct: non-canonical k rejects", (await code(function () { return subtle.importKey("jwk", { kty: "oct", k: "QR" }, hmacAlg, false, ["sign"]); })) === "webcrypto/data");
  check("jwk oct: padded/non-alphabet k rejects", (await code(function () { return subtle.importKey("jwk", { kty: "oct", k: "AAAA=" }, hmacAlg, false, ["sign"]); })) === "webcrypto/data");
}

// generateKey edge + malformed descriptors: an omitted keyUsages defaults to an
// empty usage set; a bad AES length / unsupported HMAC hash / unsupported curve /
// unrecognized algorithm each fail closed with the module's typed code; an object
// hash is accepted; an omitted RSA modulusLength defaults to 2048.
async function testGenerateKeyEdges() {
  var k = await subtle.generateKey({ name: "Ed25519" }, true);
  check("generateKey with no keyUsages yields empty usage sets", k.privateKey.usages.length === 0 && k.publicKey.usages.length === 0);
  check("generateKey AES with an off-size length rejects (syntax)",
    (await code(function () { return subtle.generateKey({ name: "AES-GCM", length: 200 }, true, ["encrypt"]); })) === "webcrypto/syntax");
  check("generateKey HMAC with an unsupported hash rejects (not-supported)",
    (await code(function () { return subtle.generateKey({ name: "HMAC", hash: "SHA-999" }, true, ["sign"]); })) === "webcrypto/not-supported");
  var hk = await subtle.generateKey({ name: "HMAC", hash: { name: "SHA-384" } }, true, ["sign", "verify"]);
  check("generateKey HMAC accepts an object hash and defaults to its block size", hk.algorithm.length === 1024 && hk.algorithm.hash.name === "SHA-384");
  var rk = await subtle.generateKey({ name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
  check("generateKey RSA with no modulusLength defaults to 2048", rk.publicKey.algorithm.modulusLength === 2048);
  check("generateKey ECDSA with an unsupported curve rejects (not-supported)",
    (await code(function () { return subtle.generateKey({ name: "ECDSA", namedCurve: "P-999" }, true, ["sign"]); })) === "webcrypto/not-supported");
  check("generateKey with an unrecognized algorithm rejects (not-supported)",
    (await code(function () { return subtle.generateKey({ name: "FOO" }, true, ["sign"]); })) === "webcrypto/not-supported");
}

// _normalizeAlg entry-point validation + digest hash resolution: a null / no-name
// algorithm descriptor is a syntax error; an unsupported digest name is
// not-supported.
async function testNormalizeAndDigestEdges() {
  check("digest with a null algorithm rejects (syntax)",
    (await code(function () { return subtle.digest(null, Buffer.from("x")); })) === "webcrypto/syntax");
  check("digest with a nameless algorithm object rejects (syntax)",
    (await code(function () { return subtle.digest({ foo: 1 }, Buffer.from("x")); })) === "webcrypto/syntax");
  check("digest with an unsupported hash rejects (not-supported)",
    (await code(function () { return subtle.digest("SHA-999", Buffer.from("x")); })) === "webcrypto/not-supported");
}

// RSA-PSS with no explicit saltLength signs + verifies via the digest-length
// default (RSA_PSS_SALTLEN_DIGEST) on both the sign and verify branches.
async function testRsaPssDefaultSalt() {
  var pss = await subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, hash: "SHA-256" }, true, ["sign", "verify"]);
  var data = Buffer.from("pss default salt");
  var sig = await subtle.sign({ name: "RSA-PSS" }, pss.privateKey, data);
  check("RSA-PSS with no saltLength signs + verifies (digest-length default)",
    (await subtle.verify({ name: "RSA-PSS" }, pss.publicKey, sig, data)) === true);
}

// RSA-OAEP with an explicit label round-trips through the label-present branch of
// both encrypt and decrypt; the same label must be supplied to decrypt.
async function testRsaOaepLabel() {
  var oaep = await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
  var label = Buffer.from("oaep-label");
  var ct = await subtle.encrypt({ name: "RSA-OAEP", label: label }, oaep.publicKey, Buffer.from("secret"));
  var pt = await subtle.decrypt({ name: "RSA-OAEP", label: label }, oaep.privateKey, ct);
  check("RSA-OAEP with an explicit label round-trips", Buffer.from(pt).toString() === "secret");
}

// encrypt / decrypt with an algorithm the key is permitted for (usage present)
// but that is not a recognized encrypt/decrypt algorithm fails not-supported.
async function testEncryptDecryptUnsupported() {
  var aes = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  check("encrypt with an unrecognized algorithm rejects (not-supported)",
    (await code(function () { return subtle.encrypt({ name: "HMAC" }, aes, Buffer.from("x")); })) === "webcrypto/not-supported");
  check("decrypt with an unrecognized algorithm rejects (not-supported)",
    (await code(function () { return subtle.decrypt({ name: "HMAC" }, aes, Buffer.from("x")); })) === "webcrypto/not-supported");
}

// deriveBits / deriveKey with the correct usage but an unrecognized derivation
// algorithm fails not-supported (the name check follows the usage check).
async function testDeriveUnsupportedAlg() {
  var ecdh = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits", "deriveKey"]);
  check("deriveBits with an unrecognized algorithm rejects (not-supported)",
    (await code(function () { return subtle.deriveBits({ name: "FOO" }, ecdh.privateKey, 128); })) === "webcrypto/not-supported");
  check("deriveKey with an unrecognized algorithm rejects (not-supported)",
    (await code(function () { return subtle.deriveKey({ name: "FOO" }, ecdh.privateKey, { name: "AES-GCM", length: 128 }, true, ["encrypt"]); })) === "webcrypto/not-supported");
}

// wrapKey / unwrapKey: an unrecognized wrap algorithm fails not-supported; the
// "jwk" wrap format serializes the exported JWK before content encryption and
// round-trips through a content-encryption (AES-GCM) wrapping key.
async function testWrapUnsupportedAndJwk() {
  var kek = await subtle.generateKey({ name: "AES-KW", length: 256 }, true, ["wrapKey", "unwrapKey"]);
  var target = await subtle.generateKey({ name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
  check("wrapKey with an unrecognized algorithm rejects (not-supported)",
    (await code(function () { return subtle.wrapKey("raw", target, kek, { name: "HMAC" }); })) === "webcrypto/not-supported");
  check("unwrapKey with an unrecognized algorithm rejects (not-supported)",
    (await code(function () { return subtle.unwrapKey("raw", Buffer.alloc(24), kek, { name: "HMAC" }, { name: "AES-GCM", length: 128 }, true, ["encrypt"]); })) === "webcrypto/not-supported");

  var gcmKek = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["wrapKey", "unwrapKey"]);
  var iv = pki.webcrypto.getRandomValues(new Uint8Array(12));
  var wrapped = await subtle.wrapKey("jwk", target, gcmKek, { name: "AES-GCM", iv: iv });
  var unwrapped = await subtle.unwrapKey("jwk", wrapped, gcmKek, { name: "AES-GCM", iv: iv }, { name: "AES-GCM", length: 128 }, true, ["encrypt", "decrypt"]);
  check("wrapKey/unwrapKey with the 'jwk' format round-trips the key",
    hex(await subtle.exportKey("raw", target)) === hex(await subtle.exportKey("raw", unwrapped)) && unwrapped.type === "secret");
}

// importKey format + descriptor edges: an omitted keyUsages defaults to []; a
// non-HMAC oct JWK, a private JWK, a raw OKP (X25519) public key, and an spki
// EdDSA public key each import with the right shape; a bogus format, a malformed
// raw EC point, and a raw RSA request each fail closed; an RSA import with no
// hash carries an undefined algorithm.hash.
async function testImportKeyEdges() {
  var ecdh = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  var spki = await subtle.exportKey("spki", ecdh.publicKey);
  var noUsages = await subtle.importKey("spki", spki, { name: "ECDH", namedCurve: "P-256" }, true);
  check("importKey with no keyUsages defaults to an empty usage set", noUsages.usages.length === 0);

  var kbuf = Buffer.alloc(16, 5);
  var aesImp = await subtle.importKey("jwk", { kty: "oct", k: kbuf.toString("base64url") }, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
  check("importKey jwk oct (non-HMAC) imports an AES key of the raw length",
    aesImp.algorithm.name === "AES-GCM" && aesImp.algorithm.length === 128 && hex(await subtle.exportKey("raw", aesImp)) === hex(kbuf));

  var edkp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var privJwk = await subtle.exportKey("jwk", edkp.privateKey);
  var privImp = await subtle.importKey("jwk", privJwk, { name: "Ed25519" }, true, ["sign"]);
  var edData = Buffer.from("jwk private import");
  var edSig = await subtle.sign({ name: "Ed25519" }, privImp, edData);
  check("importKey jwk with a 'd' member imports a private key that signs",
    privImp.type === "private" && (await subtle.verify({ name: "Ed25519" }, edkp.publicKey, edSig, edData)) === true);

  var x2 = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  var xraw = await subtle.exportKey("raw", x2.publicKey);
  var xpub = await subtle.importKey("raw", xraw, { name: "X25519" }, true, []);
  var x1 = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  check("importKey raw X25519 public derives the same secret as the original peer key",
    xpub.algorithm.name === "X25519" &&
    hex(await subtle.deriveBits({ name: "X25519", public: xpub }, x1.privateKey, 256)) ===
    hex(await subtle.deriveBits({ name: "X25519", public: x2.publicKey }, x1.privateKey, 256)));

  var edspki = await subtle.exportKey("spki", edkp.publicKey);
  var edPub = await subtle.importKey("spki", edspki, { name: "Ed25519" }, true, ["verify"]);
  check("importKey spki Ed25519 keeps the canonical label and verifies",
    edPub.algorithm.name === "Ed25519" && (await subtle.verify({ name: "Ed25519" }, edPub, edSig, edData)) === true);
  var ed448 = await subtle.generateKey({ name: "Ed448" }, true, ["sign", "verify"]);
  var ed448spki = await subtle.exportKey("spki", ed448.publicKey);
  var ed448Pub = await subtle.importKey("spki", ed448spki, { name: "Ed448" }, true, ["verify"]);
  check("importKey spki Ed448 keeps the canonical label", ed448Pub.algorithm.name === "Ed448");

  var rsa = await subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, hash: "SHA-256" }, true, ["sign", "verify"]);
  var rsaSpki = await subtle.exportKey("spki", rsa.publicKey);
  var rsaNoHash = await subtle.importKey("spki", rsaSpki, { name: "RSA-PSS" }, true, ["verify"]);
  check("importKey spki RSA with no hash carries an undefined algorithm.hash",
    rsaNoHash.algorithm.name === "RSA-PSS" && rsaNoHash.algorithm.hash === undefined);

  check("importKey with an unsupported format rejects (not-supported)",
    (await code(function () { return subtle.importKey("bogus", Buffer.alloc(4), { name: "AES-GCM" }, true, ["encrypt"]); })) === "webcrypto/not-supported");
  check("importKey raw EC with a malformed point rejects (data)",
    (await code(function () { return subtle.importKey("raw", Buffer.from([1, 2, 3]), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]); })) === "webcrypto/data");
  check("importKey raw for a public-key algorithm with no raw form rejects (not-supported)",
    (await code(function () { return subtle.importKey("raw", Buffer.alloc(10), { name: "RSA-OAEP" }, true, ["encrypt"]); })) === "webcrypto/not-supported");
}

// exportKey edges: a secret key rejects the asymmetric 'spki' format; an
// unsupported format is not-supported; a public-key algorithm with no raw point
// form (RSA) rejects raw export.
async function testExportKeyEdges() {
  var hmacKey = await subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
  check("exportKey of a secret key to 'spki' rejects (not-supported)",
    (await code(function () { return subtle.exportKey("spki", hmacKey); })) === "webcrypto/not-supported");
  var ecdh = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  check("exportKey with an unsupported format rejects (not-supported)",
    (await code(function () { return subtle.exportKey("bogus", ecdh.publicKey); })) === "webcrypto/not-supported");
  var rsa = await subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
  check("exportKey raw of an RSA public key rejects (not-supported)",
    (await code(function () { return subtle.exportKey("raw", rsa.publicKey); })) === "webcrypto/not-supported");
}

// HKDF deriveBits with no info uses an empty-info default; deriveKey to a KDF
// derived type that carries an explicit length narrows the agreement secret to
// that length before importing the KDF key.
async function testHkdfInfoAndDeriveKeyKdfLength() {
  var ikm = await subtle.importKey("raw", Buffer.from("input key material"), { name: "HKDF" }, false, ["deriveBits"]);
  var out = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: Buffer.from("salt") }, ikm, 256);
  check("HKDF deriveBits with no info derives 32 bytes (empty-info default)", out.byteLength === 32);

  var a = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
  var b = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
  var kdfKey = await subtle.deriveKey({ name: "ECDH", public: b.publicKey }, a.privateKey, { name: "HKDF", length: 256 }, false, ["deriveBits"]);
  check("deriveKey to a KDF type with an explicit length imports a KDF key of that length",
    kdfKey.type === "secret" && kdfKey.algorithm.name === "HKDF" && kdfKey.algorithm.length === 256);
}

// A node:crypto fault crossing the public webcrypto surface MUST be a typed WebCryptoError,
// never a raw node Error; and an imported key whose TYPE disagrees with the requested
// algorithm is a DataError, not a mislabeled CryptoKey (algorithm confusion).
async function testNodeErrorTyping() {
  // Import key-type vs algorithm-name mismatch -> DataError (fail-open otherwise: an RSA key
  // labelled Ed25519 would then "sign" under the wrong scheme).
  var rsaPkcs8 = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ format: "der", type: "pkcs8" });
  check("importKey: RSA pkcs8 under {name:Ed25519} rejected (webcrypto/data)",
    (await code(async function () { await subtle.importKey("pkcs8", rsaPkcs8, { name: "Ed25519" }, true, ["sign"]); })) === "webcrypto/data");
  var rsaSpki = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "der", type: "spki" });
  check("importKey: RSA spki under {name:ECDSA,P-256} rejected (webcrypto/data)",
    (await code(async function () { await subtle.importKey("spki", rsaSpki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]); })) === "webcrypto/data");
  var edPkcs8 = nodeCrypto.generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" });
  check("importKey: an Ed25519 pkcs8 under {name:RSA-PSS} rejected (webcrypto/data)",
    (await code(async function () { await subtle.importKey("pkcs8", edPkcs8, { name: "RSA-PSS", hash: "SHA-256" }, true, ["sign"]); })) === "webcrypto/data");
  // The PQC families import the same key-is-authority rule: an RSA key under a PQC name
  // (ML-DSA / SLH-DSA) is a DataError, not a mislabeled PQC key that would then run RSA.
  check("importKey: an RSA pkcs8 under {name:ML-DSA-44} rejected (webcrypto/data)",
    (await code(async function () { await subtle.importKey("pkcs8", rsaPkcs8, { name: "ML-DSA-44" }, true, ["sign"]); })) === "webcrypto/data");
  check("importKey: an RSA spki under {name:SLH-DSA-SHA2-128s} rejected (webcrypto/data)",
    (await code(async function () { await subtle.importKey("spki", rsaSpki, { name: "SLH-DSA-SHA2-128s" }, true, ["verify"]); })) === "webcrypto/data");

  // AES-KW wrap/unwrap of a non-8-multiple length -> typed OperationError, not a raw throw.
  var kwKey = await subtle.importKey("raw", new Uint8Array(16), { name: "AES-KW" }, false, ["wrapKey", "unwrapKey"]);
  var gcmKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  check("wrapKey: AES-KW over a jwk (non-8-multiple) -> webcrypto/operation, not a raw throw",
    (await code(async function () { await subtle.wrapKey("jwk", gcmKey, kwKey, { name: "AES-KW" }); })) === "webcrypto/operation");
  check("unwrapKey: AES-KW wrapped input of a non-8-multiple length -> webcrypto/operation",
    (await code(async function () { await subtle.unwrapKey("raw", new Uint8Array(20), kwKey, { name: "AES-KW" }, { name: "AES-GCM", length: 256 }, true, ["encrypt"]); })) === "webcrypto/operation");

  // A tampered AES-GCM ciphertext (bad auth tag) -> typed OperationError, never a raw fault.
  var iv = nodeCrypto.randomBytes(12);
  var ctBuf = Buffer.from(await subtle.encrypt({ name: "AES-GCM", iv: iv }, gcmKey, Buffer.from("secret")));
  ctBuf[ctBuf.length - 1] = ctBuf[ctBuf.length - 1] ^ 0xff;
  check("decrypt: a tampered AES-GCM ciphertext (bad tag) -> webcrypto/operation, not a raw throw",
    (await code(async function () { await subtle.decrypt({ name: "AES-GCM", iv: iv }, gcmKey, ctBuf); })) === "webcrypto/operation");
}

async function run() {
  await testSurface();
  await testNodeErrorTyping();
  await testRandom();
  await testDigest();
  await testClassicalSign();
  await testPqcSign();
  await testImportExport();
  await testEcImportCurveValidation();
  await testEncrypt();
  await testDerive();
  await testWrap();
  await testUnwrapKeyUsage();
  await testDeriveKeyUsage();
  await testHmacVerifyLength();
  await testAesCtrLength();
  await testAlgorithmKeyBinding();
  await testRawOkpImportExport();
  await testDeriveBitsLength();
  await testDeriveKeyAesLength();
  await testHmacDefaultLength();
  await testRsaPublicExponentValidation();
  await testUnwrapJwkNotJson();
  await testUnwrapJwkDuplicateMember();
  await testJwkOctStrict();
  await testGenerateKeyEdges();
  await testNormalizeAndDigestEdges();
  await testRsaPssDefaultSalt();
  await testRsaOaepLabel();
  await testEncryptDecryptUnsupported();
  await testDeriveUnsupportedAlg();
  await testWrapUnsupportedAndJwk();
  await testImportKeyEdges();
  await testExportKeyEdges();
  await testHkdfInfoAndDeriveKeyKdfLength();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
