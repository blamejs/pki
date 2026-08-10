// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- secret lifetime: every key-establishment secret the toolkit ALLOCATES is
 * wiped at the moment it stops being needed (NIST SP 800-227 RS5 / sec. 4.2, RFC 9629
 * sec. 7), and no buffer the CALLER owns is ever wiped.
 *
 * The wipes themselves live in lib/webcrypto.js and lib/cms-*.js, which compose
 * guard-secret. guard-secret.test.js pins that guard's own contract -- given a buffer,
 * it clears exactly that buffer -- but a contract test cannot show that the shipped
 * code still CALLS it: delete every `finally` in the engine and those checks stay green.
 * These vectors close that gap by driving the real consumer paths and reading the
 * provider's own buffer afterwards.
 *
 * Method: tap node:crypto where a secret is BORN -- decapsulate/encapsulate (the KEM
 * shared secret), diffieHellman (the ECDH z / X25519 mz), and KeyObject.export (the
 * copy a KDF makes of its input key material). Each capture keeps the buffer AND a
 * snapshot taken the instant the provider returned it, so "wiped" is asserted against a
 * value that was demonstrably non-zero -- an all-zero assertion on a buffer that was
 * always all-zero proves nothing.
 *
 * Scope honesty, matching guard-secret's own docstring: this pins that the toolkit
 * clears the buffers it allocates. It is not a claim that no copy of a secret survives
 * anywhere -- the runtime makes copies no JS can reach.
 */

var nodeCrypto = require("node:crypto");
var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var signing = require("../helpers/signing");
var makeRecipient = signing.makeRecipient;
var subtle = pki.webcrypto.subtle;

var MSG = Buffer.from("secret-lifetime round-trip payload");

// ---- the tap ----------------------------------------------------------------
// Wraps the three points where a provider hands back secret bytes. Returns a handle
// whose restore() MUST run in a finally: leaving node:crypto patched would corrupt
// every later suite in the same process.
function tap() {
  var caps = [];
  var real = {
    encapsulate: nodeCrypto.encapsulate,
    decapsulate: nodeCrypto.decapsulate,
    diffieHellman: nodeCrypto.diffieHellman,
    createSecretKey: nodeCrypto.createSecretKey,
  };
  function grab(label, buf) {
    if (Buffer.isBuffer(buf) || ArrayBuffer.isView(buf)) {
      caps.push({
        label: label,
        buf: buf,
        snap: Buffer.from(Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength)),
      });
    }
    return buf;
  }
  nodeCrypto.encapsulate = function () {
    var r = real.encapsulate.apply(this, arguments);
    if (r && r.sharedKey) grab("kem.encap", r.sharedKey);
    return r;
  };
  nodeCrypto.decapsulate = function () { return grab("kem.decap", real.decapsulate.apply(this, arguments)); };
  nodeCrypto.diffieHellman = function () { return grab("dh.z", real.diffieHellman.apply(this, arguments)); };
  // A cipher or KDF copies its key material out of the KeyObject via export(); that copy is
  // toolkit-owned and owes the same wipe as a shared secret. Wrapping export on the
  // instance catches it wherever the key was created, including keys the CMS paths build
  // internally and a test could not otherwise reach.
  nodeCrypto.createSecretKey = function () {
    var ko = real.createSecretKey.apply(this, arguments);
    var realExport = ko.export.bind(ko);
    ko.export = function () { return grab("key.export", realExport.apply(null, arguments)); };
    return ko;
  };
  // pbkdf2Sync returns the password-derived KEK / content key the CMS layer holds directly.
  real.pbkdf2Sync = nodeCrypto.pbkdf2Sync;
  nodeCrypto.pbkdf2Sync = function () { return grab("pbkdf2.kek", real.pbkdf2Sync.apply(this, arguments)); };
  // randomBytes is how the CEK is born; IVs, nonces and salts come from it too, so captures are
  // labelled by length and the CEK assertions select the content-key size explicitly.
  real.randomBytes = nodeCrypto.randomBytes;
  nodeCrypto.randomBytes = function (n) { return grab("random." + n, real.randomBytes.apply(this, arguments)); };
  // A KEK the CMS layer derives is Buffer.from(<the ArrayBuffer deriveBits returned>) -- a VIEW, so
  // wiping the CMS-side Buffer clears this ArrayBuffer and the capture observes it. Nothing at the
  // node:crypto layer sees these, which is why the engine tap alone cannot cover the CMS wipes.
  var hadOwnDerive = Object.prototype.hasOwnProperty.call(subtle, "deriveBits");
  var realDerive = subtle.deriveBits;
  subtle.deriveBits = async function () {
    var ab = await realDerive.apply(this, arguments);
    grab("derived.bits", new Uint8Array(ab));
    return ab;
  };
  real._restoreDerive = function () {
    if (hadOwnDerive) subtle.deriveBits = realDerive; else delete subtle.deriveBits;
  };
  return {
    caps: caps,
    of: function (label) { return caps.filter(function (c) { return c.label === label; }); },
    restore: function () {
      nodeCrypto.encapsulate = real.encapsulate;
      nodeCrypto.decapsulate = real.decapsulate;
      nodeCrypto.diffieHellman = real.diffieHellman;
      nodeCrypto.createSecretKey = real.createSecretKey;
      nodeCrypto.pbkdf2Sync = real.pbkdf2Sync;
      nodeCrypto.randomBytes = real.randomBytes;
      real._restoreDerive();
    },
  };
}

function allZero(b) { return b.length > 0 && Buffer.from(b).every(function (x) { return x === 0; }); }
function anyNonZero(b) { return Buffer.from(b).some(function (x) { return x !== 0; }); }

// Same contract as wiped() below, for a label whose count depends on how many derivations a flow
// performs (a KEK derivation count is an implementation detail; that every one is cleared is not).
function wipedAll(t, label, what) {
  var got = t.of(label);
  check(what + ": at least one secret buffer was captured", got.length > 0);
  check(what + ": every captured buffer held real secret material", got.length > 0 && got.every(function (c) { return anyNonZero(c.snap); }));
  check(what + ": every captured buffer is zeroed", got.length > 0 && got.every(function (c) { return allZero(c.buf); }));
}

function wiped(t, label, want, what) {
  var got = t.of(label);
  check(what + ": the provider allocated " + want + " secret buffer(s)", got.length === want);
  check(what + ": every captured buffer held real secret material", got.length > 0 && got.every(function (c) { return anyNonZero(c.snap); }));
  check(what + ": every captured buffer is zeroed after the operation", got.length > 0 && got.every(function (c) { return allZero(c.buf); }));
}

async function run() {
  // ============================================================================
  // A. KEM -- both directions, success and failure
  // ============================================================================
  var t = tap();
  try {
    var kp = await subtle.generateKey({ name: "ML-KEM-768" }, true, ["encapsulateBits", "decapsulateBits"]);
    var enc = await subtle.encapsulateBits({ name: "ML-KEM-768" }, kp.publicKey);
    wiped(t, "kem.encap", 1, "encapsulateBits wipes the provider's shared secret");

    var ss = await subtle.decapsulateBits({ name: "ML-KEM-768" }, kp.privateKey, enc.ciphertext);
    wiped(t, "kem.decap", 1, "decapsulateBits wipes the provider's shared secret");
    // The wipe must not corrupt what the caller receives -- the failure mode of wiping a
    // buffer that is ALIASED by the return value rather than copied from it.
    check("the wipe leaves both returned shared secrets intact and in agreement",
      Buffer.compare(Buffer.from(ss), Buffer.from(enc.sharedKey)) === 0 && anyNonZero(Buffer.from(ss)));
  } finally { t.restore(); }

  // A tampered same-length ciphertext must still wipe: FIPS 203 sec. 6.3 implicit
  // rejection returns a pseudo-random secret rather than throwing, so the secret IS
  // allocated on this path and a wipe placed only on the success branch would miss it.
  t = tap();
  try {
    var kp2 = await subtle.generateKey({ name: "ML-KEM-768" }, true, ["encapsulateBits", "decapsulateBits"]);
    var e2 = await subtle.encapsulateBits({ name: "ML-KEM-768" }, kp2.publicKey);
    var bad = Buffer.from(e2.ciphertext); bad[0] ^= 0xff;
    await subtle.decapsulateBits({ name: "ML-KEM-768" }, kp2.privateKey, bad);
    wiped(t, "kem.decap", 1, "decapsulateBits under implicit rejection still wipes");
  } finally { t.restore(); }

  // ============================================================================
  // B. Non-KEM key establishment -- the same duty, the same engine
  // ============================================================================
  // ECDH: nodeCrypto.diffieHellman returns z in a buffer this module owns. Every exit
  // from the branch owes the wipe, including the length==null shortcut that returns the
  // whole secret.
  t = tap();
  try {
    var a = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    var bkey = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    var z1 = await subtle.deriveBits({ name: "ECDH", public: bkey.publicKey }, a.privateKey, 256);
    wiped(t, "dh.z", 1, "ECDH deriveBits wipes the raw shared secret");
    check("ECDH still derives usable bits after the wipe", anyNonZero(Buffer.from(z1)) && z1.byteLength === 32);
  } finally { t.restore(); }

  t = tap();
  try {
    var c1 = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    var c2 = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    var zFull = await subtle.deriveBits({ name: "ECDH", public: c2.publicKey }, c1.privateKey, null);
    wiped(t, "dh.z", 1, "ECDH deriveBits(length=null) wipes on the full-secret exit too");
    check("ECDH full-length derivation still returns the secret", anyNonZero(Buffer.from(zFull)));
  } finally { t.restore(); }

  // X25519 / X448: the same branch, a different curve family -- the montgomery shared
  // secret mz is allocated identically and is equally secret.
  for (var mont of ["X25519", "X448"]) {
    t = tap();
    try {
      var m1 = await subtle.generateKey({ name: mont }, true, ["deriveBits"]);
      var m2 = await subtle.generateKey({ name: mont }, true, ["deriveBits"]);
      var mz = await subtle.deriveBits({ name: mont, public: m2.publicKey }, m1.privateKey, null);
      wiped(t, "dh.z", 1, mont + " deriveBits wipes the raw shared secret");
      check(mont + " still derives usable bits after the wipe", anyNonZero(Buffer.from(mz)));
    } finally { t.restore(); }
  }

  // The three KDF arms each export their input key material into a toolkit-owned copy.
  // HKDF has wiped it since the KEM work; X963KDF and PBKDF2 sit on the same dispatch
  // and owe the same duty -- X963KDF's base key IS the ECDH z of an RFC 5753 kari.
  var kdfCases = [
    { name: "HKDF", alg: { name: "HKDF", hash: "SHA-256", salt: Buffer.alloc(8), info: Buffer.alloc(0) } },
    { name: "X963KDF", alg: { name: "X963KDF", hash: "SHA-256", info: Buffer.alloc(0) } },
    { name: "PBKDF2", alg: { name: "PBKDF2", hash: "SHA-256", salt: Buffer.from("salt"), iterations: 1000 } },
  ];
  for (var kc of kdfCases) {
    t = tap();
    var out, callerKeyMaterial;
    try {
      // A caller-owned buffer: the wipe must clear the toolkit's EXPORT of this material,
      // never the caller's own memory. Destroying a caller's key material would be a worse
      // defect than leaving a copy readable, and it is the failure this rule reaches for first.
      callerKeyMaterial = Buffer.alloc(32, 0x5a);
      var kk = await subtle.importKey("raw", callerKeyMaterial, { name: kc.name }, false, ["deriveBits"]);
      out = await subtle.deriveBits(kc.alg, kk, 256);
      wiped(t, "key.export", 1, kc.name + " wipes its exported input key material");
      check(kc.name + " leaves the CALLER's key material untouched",
        callerKeyMaterial.every(function (x) { return x === 0x5a; }));
      check(kc.name + " still derives the correct-length output after the wipe", out.byteLength === 32);
    } finally { t.restore(); }
    // "output is non-empty" would still pass if the key had been wiped BEFORE the derivation
    // consumed it, so it cannot show the real material was used. Deriving from an all-zero key of
    // the same length yields exactly what a wiped buffer would; the two outputs must differ.
    //
    // Scope: this does NOT detect an eager wipe on the asynchronous arm. Node copies a job's
    // inputs when it queues them, so PBKDF2 derives correctly either way -- the deferred wipe
    // there is defence against a provider that does not, not a fix for a live fault.
    var zeroKey = await subtle.importKey("raw", Buffer.alloc(32), { name: kc.name }, false, ["deriveBits"]);
    var zeroOut = await subtle.deriveBits(kc.alg, zeroKey, 256);
    check(kc.name + " derived from the real key material, not from an all-zero buffer",
      Buffer.compare(Buffer.from(out), Buffer.from(zeroOut)) !== 0);
  }

  // The AES content-encryption key is exported on EVERY encrypt and decrypt. In a CMS message
  // that key is the CEK protecting the content for every recipient, so an unwiped export leaves
  // the whole message's key readable for the process lifetime.
  for (var aes of [
    { name: "AES-GCM", alg: { name: "AES-GCM", iv: Buffer.alloc(12, 1) } },
    { name: "AES-CBC", alg: { name: "AES-CBC", iv: Buffer.alloc(16, 2) } },
    { name: "AES-CTR", alg: { name: "AES-CTR", counter: Buffer.alloc(16, 3), length: 128 } },
  ]) {
    var ct;
    t = tap();
    try {
      var ak = await subtle.generateKey({ name: aes.name, length: 256 }, true, ["encrypt", "decrypt"]);
      ct = await subtle.encrypt(aes.alg, ak, MSG);
      wiped(t, "key.export", 1, aes.name + " encrypt wipes the exported content key");
      var back = await subtle.decrypt(aes.alg, ak, ct);
      check(aes.name + " round-trips correctly despite the wipe", Buffer.compare(Buffer.from(back), MSG) === 0);
      wiped(t, "key.export", 2, aes.name + " decrypt wipes its exported content key too");
    } finally { t.restore(); }
  }

  // ============================================================================
  // C. The CMS consumer paths -- where an operator actually meets these secrets
  // ============================================================================
  // kemri: encrypt allocates one shared secret per recipient, decrypt one for the
  // recipient it resolves.
  var mkem = makeRecipient("ml-kem-768");
  t = tap();
  try {
    await pki.cms.encrypt(MSG, [{ cert: mkem.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
    wiped(t, "kem.encap", 1, "pki.cms.encrypt wipes the KEM shared secret it sends under");
  } finally { t.restore(); }

  var kemEnv2 = await pki.cms.encrypt(MSG, [{ cert: mkem.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  t = tap();
  try {
    var d = await pki.cms.decrypt(kemEnv2, { key: mkem.key, cert: mkem.cert });
    wiped(t, "kem.decap", 1, "pki.cms.decrypt wipes the KEM shared secret it recovers under");
    check("the content still decrypts correctly alongside the wipe", Buffer.compare(d.content, MSG) === 0);
  } finally { t.restore(); }

  // The failure path owes the wipe too: a wrong decapsulation key yields a shared secret
  // (implicit rejection) that unwraps to garbage, and the throw must not skip the cleanup.
  var otherKem = makeRecipient("ml-kem-768");
  t = tap();
  try {
    var threw = null;
    try { await pki.cms.decrypt(kemEnv2, { key: otherKem.key, cert: mkem.cert }); }
    catch (e) { threw = e; }
    check("a wrong KEM key still fails closed with the uniform verdict", threw !== null && threw.code === "cms/decrypt-failed");
    wiped(t, "kem.decap", 1, "pki.cms.decrypt wipes the KEM shared secret on the FAILURE path");
  } finally { t.restore(); }

  // kari: the ECDH/montgomery shared secret behind an RFC 5753 key-agreement recipient.
  for (var kariKind of ["ec-p256", "x25519"]) {
    var rec = makeRecipient(kariKind);
    t = tap();
    try {
      await pki.cms.encrypt(MSG, [{ cert: rec.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
      wiped(t, "dh.z", 1, "pki.cms.encrypt wipes the " + kariKind + " agreement secret");
    } finally { t.restore(); }

    var kEnv2 = await pki.cms.encrypt(MSG, [{ cert: rec.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
    t = tap();
    try {
      var kd = await pki.cms.decrypt(kEnv2, { key: rec.key, cert: rec.cert });
      wiped(t, "dh.z", 1, "pki.cms.decrypt wipes the " + kariKind + " agreement secret");
      check("the " + kariKind + " content still decrypts correctly alongside the wipe", Buffer.compare(kd.content, MSG) === 0);
    } finally { t.restore(); }
  }

  // ============================================================================
  // D. The secrets the CMS layer holds itself -- the CEK, and the KEKs it derives
  // ============================================================================
  // The CEK is the message's key, wrapped for every recipient, so unlike a per-recipient secret it
  // must survive the whole recipient loop and be cleared exactly once at the end. A per-recipient
  // wipe would break every recipient after the first, so this runs with TWO recipients.
  var r1 = makeRecipient("rsa"), r2 = makeRecipient("ec-p256");
  t = tap();
  try {
    var twoEnv = await pki.cms.encrypt(MSG, [{ cert: r1.cert }, { cert: r2.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
    wiped(t, "random.32", 1, "pki.cms.encrypt wipes the content-encryption key");
    // Both recipients must still open the message: proof the single wipe landed after the loop and
    // not inside it. A CEK cleared per recipient would leave the second entry wrapping zeros.
    var o1 = await pki.cms.decrypt(twoEnv, { key: r1.key, cert: r1.cert });
    var o2 = await pki.cms.decrypt(twoEnv, { key: r2.key, cert: r2.cert });
    check("both recipients still recover the content (the CEK wipe is once, after the loop)",
      Buffer.compare(o1.content, MSG) === 0 && Buffer.compare(o2.content, MSG) === 0);
  } finally { t.restore(); }

  // A password recipient derives its KEK with PBKDF2 on both sides -- but through DIFFERENT
  // primitives: the producer goes through the engine's async deriveBits, the consumer through
  // node's pbkdf2Sync directly. Each is observed where that side's secret actually lives.
  t = tap();
  try {
    await pki.cms.encrypt(MSG, [{ password: "pw", iterations: 1000 }], { contentEncryptionAlgorithm: "aes-256-cbc" });
    wipedAll(t, "derived.bits", "pki.cms.encrypt wipes the password-derived key-encryption key");
  } finally { t.restore(); }

  var pwEnv2 = await pki.cms.encrypt(MSG, [{ password: "pw", iterations: 1000 }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  t = tap();
  try {
    var pwOut = await pki.cms.decrypt(pwEnv2, { password: "pw" });
    wiped(t, "pbkdf2.kek", 1, "pki.cms.decrypt wipes the password-derived key-encryption key");
    check("the password-recipient content still decrypts", Buffer.compare(pwOut.content, MSG) === 0);
  } finally { t.restore(); }

  // A wrong password must clear it too -- that is the path an attacker drives repeatedly.
  t = tap();
  try {
    var pwThrew = null;
    try { await pki.cms.decrypt(pwEnv2, { password: "wrong" }); } catch (e) { pwThrew = e; }
    check("a wrong password fails closed with the uniform verdict", pwThrew !== null && pwThrew.code === "cms/decrypt-failed");
    wiped(t, "pbkdf2.kek", 1, "pki.cms.decrypt wipes the password-derived KEK on the FAILURE path");
  } finally { t.restore(); }

  // The kari KEK the CMS layer derives -- observed through the ArrayBuffer deriveBits returned,
  // which the CMS-side Buffer is a view over.
  t = tap();
  try {
    var kariRec = makeRecipient("ec-p256");
    var kariEnv = await pki.cms.encrypt(MSG, [{ cert: kariRec.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
    wipedAll(t, "derived.bits", "pki.cms.encrypt wipes every key-agreement KEK it derived");
    var kariOut = await pki.cms.decrypt(kariEnv, { key: kariRec.key, cert: kariRec.cert });
    wipedAll(t, "derived.bits", "pki.cms.decrypt wipes every key-agreement KEK it derived");
    check("the key-agreement content still decrypts", Buffer.compare(kariOut.content, MSG) === 0);
  } finally { t.restore(); }

  // A caller-supplied KEK is the caller's memory and must come back untouched -- the kekri arm
  // views desc.kek directly rather than copying it.
  var callerKek = Buffer.alloc(32, 0x3c);
  var kekEnv = await pki.cms.encrypt(MSG, [{ kek: callerKek, kekId: Buffer.from("k1") }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  var kekOut = await pki.cms.decrypt(kekEnv, { kek: callerKek, kekId: Buffer.from("k1") });
  check("a caller-supplied KEK is never wiped by encrypt or decrypt",
    callerKek.every(function (x) { return x === 0x3c; }) && Buffer.compare(kekOut.content, MSG) === 0);

  // A password-protected EncryptedData derives the CONTENT key straight from the password (no
  // recipient wrapping), and must clear it when the password is wrong as well as when it is right.
  // CBC is unauthenticated, so a wrong password does not reliably throw -- PKCS#7 padding is
  // coincidentally valid about 1 in 256 times -- and the deterministic property is therefore "never
  // returns the plaintext". Several wrong passwords are tried so the throwing path is exercised.
  var edEnv = await pki.cms.encrypt(MSG, { password: "pw", iterations: 1000 }, { contentEncryptionAlgorithm: "aes-256-cbc" });
  var threwUniform = 0, leaked = 0;
  t = tap();
  try {
    for (var w = 0; w < 12; w++) {
      try {
        var bad = await pki.cms.decrypt(edEnv, { password: "wrong-" + w, iterations: 1000 });
        if (Buffer.isBuffer(bad.content) && Buffer.compare(bad.content, MSG) === 0) leaked++;
      } catch (e) {
        if (e.code === "cms/decrypt-failed") threwUniform++; else throw e;
      }
    }
    check("a wrong EncryptedData password never yields the plaintext", leaked === 0);
    check("a wrong EncryptedData password reports the uniform verdict when it fails closed", threwUniform > 0);
    wipedAll(t, "pbkdf2.kek", "pki.cms.decrypt wipes the password-derived content key on the FAILURE path");
  } finally { t.restore(); }

  var edOut = await pki.cms.decrypt(edEnv, { password: "pw", iterations: 1000 });
  check("the password-protected EncryptedData still opens with the right password", Buffer.compare(edOut.content, MSG) === 0);

  // Same contract for a caller-supplied password buffer: passwordBytes hands a Buffer straight
  // through, so a wipe placed on it would destroy the caller's credential.
  var callerPw = Buffer.from("hunter2-hunter2-");
  var pwBufEnv = await pki.cms.encrypt(MSG, [{ password: callerPw, iterations: 1000 }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  var pwBufOut = await pki.cms.decrypt(pwBufEnv, { password: callerPw });
  check("a caller-supplied password Buffer is never wiped",
    Buffer.compare(callerPw, Buffer.from("hunter2-hunter2-")) === 0 && Buffer.compare(pwBufOut.content, MSG) === 0);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
