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
}

async function testDigest() {
  var abc = Buffer.from("abc");
  check("SHA-256(abc)", hex(await subtle.digest("SHA-256", abc)) === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  check("SHA-1(abc) [legacy compat]", hex(await subtle.digest("SHA-1", abc)) === "a9993e364706816aba3e25717850c26c9cd0d89d");
  check("SHA-512(abc) length", (await subtle.digest("SHA-512", abc)).byteLength === 64);
  check("SHA3-256(abc)", hex(await subtle.digest("SHA3-256", abc)) === "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
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

async function testSurface() {
  check("pki.webcrypto is a Crypto instance", pki.webcrypto instanceof pki.webcrypto.Crypto);
  check("pki.webcrypto.subtle is a SubtleCrypto", pki.webcrypto.subtle instanceof pki.webcrypto.SubtleCrypto);
  check("WebCryptoError is a PkiError", new pki.webcrypto.WebCryptoError("x", "y") instanceof pki.errors.PkiError);
  check("the WebCrypto classes are reachable under pki.webcrypto", typeof pki.webcrypto.CryptoKey === "function" && pki.WebCrypto === undefined);
  var k = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  check("unsupported algorithm throws not-supported", (await code(async function () { await subtle.sign({ name: "NOPE" }, k.privateKey, Buffer.from("x")); })) === "webcrypto/not-supported");
}

async function run() {
  await testSurface();
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
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
