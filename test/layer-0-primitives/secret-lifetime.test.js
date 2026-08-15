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
var bld = pki.asn1.build;

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
  // The classic PKCS#12 KDF (RFC 7292 App. B) is a JS loop, not a node primitive, so the only view
  // of the key it derives is the moment it is handed to a cipher or HMAC.
  real.createHmac = nodeCrypto.createHmac;
  nodeCrypto.createHmac = function (alg, key) { grab("hmac.key", key); return real.createHmac.apply(this, arguments); };
  real.createDecipheriv = nodeCrypto.createDecipheriv;
  nodeCrypto.createDecipheriv = function (alg, key) { grab("cipher.key", key); return real.createDecipheriv.apply(this, arguments); };
  // pbkdf2Sync returns the password-derived KEK / content key the CMS layer holds directly.
  real.pbkdf2Sync = nodeCrypto.pbkdf2Sync;
  nodeCrypto.pbkdf2Sync = function (pw) { grab("pbkdf2.pw", pw); return grab("pbkdf2.kek", real.pbkdf2Sync.apply(this, arguments)); };
  // randomBytes is how the CEK is born; IVs, nonces and salts come from it too, so captures are
  // labelled by length and the CEK assertions select the content-key size explicitly.
  real.randomBytes = nodeCrypto.randomBytes;
  nodeCrypto.randomBytes = function (n) { return grab("random." + n, real.randomBytes.apply(this, arguments)); };
  // A KEK the CMS layer derives is Buffer.from(<the ArrayBuffer deriveBits returned>) -- a VIEW, so
  // wiping the CMS-side Buffer clears this ArrayBuffer and the capture observes it. Nothing at the
  // node:crypto layer sees these, which is why the engine tap alone cannot cover the CMS wipes.
  // A key the CMS layer recovered is handed to the engine as RAW bytes. HMAC verify uses the key
  // handle directly and never exports it, so an import-time capture is the only view of a recovered
  // MAC key. Captures here include CALLER-owned material too (a caller may import its own raw key),
  // so assertions on this label name the specific buffer they mean.
  var realImport = subtle.importKey;
  var hadOwnImport = Object.prototype.hasOwnProperty.call(subtle, "importKey");
  // A PKCS#8 import is the only view of the private-key buffer the engine decoded for a caller who
  // passed a Uint8Array or a PEM string: that buffer is allocated inside lib/ and handed straight to
  // importKey, so capturing the argument here IS holding the toolkit's own copy.
  subtle.importKey = function (format, keyData) {
    if (format === "raw") grab("import.raw", keyData);
    if (format === "pkcs8") grab("import.pkcs8", keyData);
    return realImport.apply(this, arguments);
  };
  // A key-transport unwrap yields the recovered key as the RSA decryption output. When that key is
  // rejected as too short it is never imported, so this is the only place it can be observed.
  var realDecrypt = subtle.decrypt;
  var hadOwnDecrypt = Object.prototype.hasOwnProperty.call(subtle, "decrypt");
  subtle.decrypt = async function () {
    var out = await realDecrypt.apply(this, arguments);
    if (out instanceof ArrayBuffer) grab("decrypt.out", new Uint8Array(out));
    return out;
  };
  var hadOwnDerive = Object.prototype.hasOwnProperty.call(subtle, "deriveBits");
  var realDerive = subtle.deriveBits;
  subtle.deriveBits = async function () {
    var ab = await realDerive.apply(this, arguments);
    grab("derived.bits", new Uint8Array(ab));
    return ab;
  };
  real._restoreDerive = function () {
    if (hadOwnDerive) subtle.deriveBits = realDerive; else delete subtle.deriveBits;
    if (hadOwnImport) subtle.importKey = realImport; else delete subtle.importKey;
    if (hadOwnDecrypt) subtle.decrypt = realDecrypt; else delete subtle.decrypt;
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
      nodeCrypto.createHmac = real.createHmac;
      nodeCrypto.createDecipheriv = real.createDecipheriv;
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

// The raw-import captures of a given length: used where the only view of a recovered key is the
// moment it is handed to the engine.
function wipedRaw(t, len, what) {
  var got = t.of("import.raw").filter(function (c) { return c.buf.length === len; });
  check(what + ": a " + len + "-octet key was imported", got.length > 0);
  check(what + ": it held real key material", got.length > 0 && got.every(function (c) { return anyNonZero(c.snap); }));
  check(what + ": it is zeroed afterwards", got.length > 0 && got.every(function (c) { return allZero(c.buf); }));
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
        var wrongOut = await pki.cms.decrypt(edEnv, { password: "wrong-" + w, iterations: 1000 });
        if (Buffer.isBuffer(wrongOut.content) && Buffer.compare(wrongOut.content, MSG) === 0) leaked++;
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

  // When a key-transport unwrap fails, the decryptor substitutes a FRESH RANDOM content key and
  // decrypts with it, so the failure emerges from the content stage like every other bad-key path
  // (RFC 3218 implicit rejection). That substitute is allocated inside the content stage, so it is
  // that stage's to clear -- a wipe placed only where the recovered key lives would clear the null
  // it replaced and leave the substitute behind, on precisely the path an attacker drives.
  // The substitution is the PKCS#1 v1.5 arm, which this library never EMITS (v1.5 is decrypt-only),
  // so the message is built by hand -- a hostile message is exactly the case that reaches it. A
  // wrong-length RSA ciphertext is a decode fault, which is what triggers the substitution.
  var rsaA = makeRecipient("rsa");
  var v15Ktri = bld.sequence([bld.integer(0n), bld.sequence([bld.sequence([]), bld.integer(1n)]),
    bld.sequence([bld.oid(pki.oid.byName("rsaEncryption")), bld.nullValue()]), bld.octetString(Buffer.alloc(128))]);
  var v15Eci = bld.sequence([bld.oid(pki.oid.byName("data")),
    bld.sequence([bld.oid(pki.oid.byName("aes256-CBC")), bld.octetString(Buffer.alloc(16))]),
    bld.contextPrimitive(0, Buffer.alloc(16))]);
  var v15Env = bld.sequence([bld.oid(pki.oid.byName("envelopedData")),
    bld.explicit(0, bld.sequence([bld.integer(0n), bld.setOf([v15Ktri]), v15Eci]))]);
  t = tap();
  try {
    // The substitute key is random and the content is unauthenticated CBC, so this does not reliably
    // throw -- the deterministic property is that it never yields plaintext. Either way the
    // substitute must be cleared.
    var leakedV15 = false;
    try {
      var v15Out = await pki.cms.decrypt(v15Env, { key: rsaA.key, cert: rsaA.cert }, { recipientIndex: 0 });
      leakedV15 = Buffer.isBuffer(v15Out.content) && Buffer.compare(v15Out.content, MSG) === 0;
    } catch (e) {
      if (e.code !== "cms/decrypt-failed") throw e;
    }
    check("a v1.5 decode fault never yields plaintext (implicit rejection, no oracle)", leakedV15 === false);
    wipedAll(t, "random.32", "pki.cms.decrypt wipes the implicit-rejection substitute content key");
  } finally { t.restore(); }

  // AuthenticatedData is the sibling of the enveloped path: its MAC key plays the CEK's role -- it is
  // generated once, wrapped for every recipient, and recovered by one. It owes the identical duty on
  // both sides, and on the failing path.
  var authRec = makeRecipient("rsa");
  t = tap();
  try {
    await pki.cms.authenticate(MSG, [{ cert: authRec.cert }]);
    wiped(t, "random.32", 1, "pki.cms.authenticate wipes the message-authentication key it generated");
  } finally { t.restore(); }

  var authMsg = await pki.cms.authenticate(MSG, [{ cert: authRec.cert }]);
  t = tap();
  try {
    var authOut = await pki.cms.decrypt(authMsg, { key: authRec.key, cert: authRec.cert });
    check("the authenticated content still verifies and is returned", Buffer.compare(authOut.content, MSG) === 0 && authOut.authenticated === true);
    wipedRaw(t, 32, "pki.cms.decrypt wipes the message-authentication key it recovered");
  } finally { t.restore(); }

  // The reachable failure here is a TAMPERED message, not a wrong key: a wrong key fails while
  // recovering the MAC key, before one exists to clear. Flipping a byte of the content leaves the
  // structure and the MAC over the authenticated attributes intact, so the key IS recovered and the
  // recomputed message-digest is what rejects (RFC 5652 sec. 9.3) -- the key must be cleared there.
  var tampered = Buffer.from(authMsg);
  var at = tampered.indexOf(MSG);
  check("the authenticated content was located for tampering", at > 0);
  tampered[at] ^= 0xff;
  t = tap();
  try {
    var authThrew = null;
    try { await pki.cms.decrypt(tampered, { key: authRec.key, cert: authRec.cert }); } catch (e) { authThrew = e; }
    check("a tampered AuthenticatedData fails closed with the uniform verdict",
      authThrew !== null && authThrew.code === "cms/decrypt-failed");
    wipedRaw(t, 32, "pki.cms.decrypt wipes the message-authentication key on the FAILURE path");
  } finally { t.restore(); }

  // Password-based private-key protection derives a key that guards a PRIVATE KEY -- the most
  // sensitive thing this library encrypts. Both directions clear it.
  var pkRec = makeRecipient("ec-p256");
  var pkDer = pkRec.key;   // an unencrypted PKCS#8 private key, as DER
  {
    t = tap();
    try {
      var encPk = await pki.key.encrypt(pkDer, "pw-for-the-private-key", { iterations: 1000 });
      wipedAll(t, "pbkdf2.kek", "pki.key.encrypt wipes the password-derived key protecting a private key");
      t.restore(); t = tap();
      var backPk = await pki.key.decrypt(encPk, "pw-for-the-private-key");
      check("the private key still decrypts to the same DER", Buffer.compare(Buffer.from(backPk), Buffer.from(pkDer)) === 0);
      wipedAll(t, "pbkdf2.kek", "pki.key.decrypt wipes the password-derived key protecting a private key");
      t.restore(); t = tap();
      var pkThrew = null;
      try { await pki.key.decrypt(encPk, "the-wrong-password"); } catch (e) { pkThrew = e; }
      check("a wrong private-key password fails closed", pkThrew !== null);
      wipedAll(t, "pbkdf2.kek", "pki.key.decrypt wipes the derived key on the FAILURE path");
    } finally { t.restore(); }
  }

  // PKCS#12 integrity: the classic MAC key comes from the RFC 7292 App. B KDF, not from PBKDF2, so
  // it is observed where it is handed to the HMAC. Both sides -- the store's producer and the
  // verifier -- derive it, and both must clear it.
  var p12Rec = makeRecipient("ec-p256");
  t = tap();
  try {
    var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: p12Rec.cert }] }] },
      { password: "1234", mac: { algorithm: "hmac", hash: "sha256", iterations: 2048 } });
    wipedAll(t, "hmac.key", "pki.pkcs12.build wipes the password-derived MAC key");
    t.restore(); t = tap();
    var opened = await pki.pkcs12.open(p12, "1234");
    check("the PKCS#12 store still opens and its integrity verifies", opened != null);
    wipedAll(t, "hmac.key", "pki.pkcs12.open wipes the password-derived MAC key it recomputed");
  } finally { t.restore(); }

  // HPKE reaches the same raw Diffie-Hellman output the WebCrypto path does, through its own code,
  // so the KEM shared secret is cleared on every DHKEM arm rather than only where the engine sees it.
  var S = pki.hpke.suites;
  var hpkeIds = { kem: S.KEM.DHKEM_X25519_HKDF_SHA256, kdf: S.KDF.HKDF_SHA256, aead: S.AEAD.AES_256_GCM };
  var hkp = nodeCrypto.generateKeyPairSync("x25519");
  t = tap();
  try {
    var sealed = pki.hpke.seal(hpkeIds, hkp.publicKey, {}, Buffer.from("aad"), MSG);
    wipedAll(t, "dh.z", "pki.hpke.seal wipes the raw key-agreement secret");
    t.restore(); t = tap();
    var openedHpke = pki.hpke.open(hpkeIds, sealed.enc, hkp.privateKey, {}, Buffer.from("aad"), sealed.ct);
    check("the HPKE payload still opens after the wipe", Buffer.compare(Buffer.from(openedHpke), MSG) === 0);
    wipedAll(t, "dh.z", "pki.hpke.open wipes the raw key-agreement secret");
  } finally { t.restore(); }

  // The single-shot entry points build a context, use it once and drop it, so the context's own key
  // material is theirs to clear. The multi-message API hands the context to the caller instead, and
  // must NOT clear it -- the caller is still using it.
  var oneShot = pki.hpke.seal(hpkeIds, hkp.publicKey, {}, Buffer.from("aad"), MSG);
  check("the single-shot payload round-trips after its context is cleared",
    Buffer.compare(Buffer.from(pki.hpke.open(hpkeIds, oneShot.enc, hkp.privateKey, {}, Buffer.from("aad"), oneShot.ct)), MSG) === 0);

  // A caller-held context must NOT be cleared: its lifetime belongs to the caller, and clearing it
  // would break the second and later messages of a multi-message exchange.
  var ctxS = pki.hpke.setupS(hpkeIds, hkp.publicKey, {});
  var hm1 = ctxS.context.seal(Buffer.from("aad"), Buffer.from("first"));
  var hm2 = ctxS.context.seal(Buffer.from("aad"), Buffer.from("second"));
  var ctxR = pki.hpke.setupR(hpkeIds, ctxS.enc, hkp.privateKey, {});
  var got1 = Buffer.from(ctxR.open(Buffer.from("aad"), hm1));
  var got2 = Buffer.from(ctxR.open(Buffer.from("aad"), hm2));
  check("a caller-held context still seals and opens a SECOND message (its lifetime is the caller's)",
    got1.toString() === "first" && got2.toString() === "second");

  // A hostile AuthenticatedData whose recipient unwraps to a key that is merely TOO SHORT is the
  // case where a substitute must not be assigned over the recovered key: doing so drops the only
  // reference to a real recovered secret and clears the random replacement instead. The message is
  // built by hand -- this library never emits a short MAC key -- by OAEP-encrypting 8 octets under
  // the recipient's own public key and splicing that in as the encrypted key.
  var shortRec = makeRecipient("rsa");
  var realAuth = await pki.cms.authenticate(MSG, [{ cert: shortRec.cert }], { authenticatedAttributes: false });
  var adRoot = pki.asn1.decode(realAuth);
  var adSeq = adRoot.children[1].children[0];             // [0] EXPLICIT -> AuthenticatedData
  var ktri = adSeq.children[1].children[0];               // SET OF RecipientInfo -> ktri
  var shortPub = await subtle.importKey("spki", pki.schema.x509.parse(shortRec.cert).subjectPublicKeyInfo.bytes,
    { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]);
  var shortWrapped = Buffer.from(await subtle.encrypt({ name: "RSA-OAEP" }, shortPub, Buffer.alloc(8, 0x9c)));
  var spliced = bld.sequence([bld.oid(pki.oid.byName("authData")), bld.explicit(0, bld.sequence([
    bld.raw(adSeq.children[0].bytes),
    bld.setOf([bld.sequence([bld.raw(ktri.children[0].bytes), bld.raw(ktri.children[1].bytes),
      bld.raw(ktri.children[2].bytes), bld.octetString(shortWrapped)])]),
    bld.raw(adSeq.children[2].bytes), bld.raw(adSeq.children[3].bytes), bld.raw(adSeq.children[4].bytes),
  ]))]);
  t = tap();
  try {
    var shortThrew = null;
    try { await pki.cms.decrypt(spliced, { key: shortRec.key, cert: shortRec.cert }); } catch (e) { shortThrew = e; }
    check("a short recovered MAC key fails closed with the uniform verdict",
      shortThrew !== null && shortThrew.code === "cms/decrypt-failed");
    // BOTH must be cleared: the 8-octet key that WAS recovered, and the 16-octet substitute. The
    // substitute's presence is itself the proof this branch ran -- nothing else allocates 16 random
    // octets here -- and the recovered key is observed as the RSA decryption output, because the
    // whole point of the fix is that it is no longer imported.
    var recovered = t.of("decrypt.out").filter(function (c) { return c.buf.length === 8; });
    check("the recovered MAC key was 8 octets, so the short-key branch ran", recovered.length === 1);
    check("the recovered short MAC key held real material", recovered.length === 1 && anyNonZero(recovered[0].snap));
    check("the recovered short MAC key is cleared, not just the substitute",
      recovered.length === 1 && allZero(recovered[0].buf));
    wipedAll(t, "random.16", "the substitute MAC key is cleared when the recovered key is too short");
  } finally { t.restore(); }

  // A derived key handed back as a VIEW over a larger allocation is the subtle form of this bug:
  // clearing what the caller received leaves the rest of the final digest block -- password-derived
  // material -- readable behind it. A legacy PKCS#12 store uses key sizes that are NOT a multiple of
  // the digest length (RC2 wants 5 octets of a 20-octet SHA-1 block), so the whole backing buffer
  // must be observed, not just the returned window.
  var viewLeak = [];
  t = tap();
  try {
    var legacy = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: p12Rec.cert }] }] },
      { password: "1234", mac: { algorithm: "hmac", hash: "sha1", iterations: 1024 } });
    check("a SHA-1-MAC PKCS#12 store still builds", Buffer.isBuffer(legacy) || typeof legacy === "string");
    t.of("hmac.key").forEach(function (c) {
      // Look past the caller's window at the ENTIRE backing allocation.
      var whole = Buffer.from(c.buf.buffer, 0, c.buf.buffer.byteLength);
      if (anyNonZero(whole)) viewLeak.push(c.buf.length + "/" + whole.length);
    });
    check("no password-derived material survives behind the returned key window",
      viewLeak.length === 0);
  } finally { t.restore(); }

  // A key-transport recipient's content key arrives as the RSA decryption output. The engine clears
  // the provider's buffer once it has copied it out, and the CMS layer clears the copy once the
  // content is open -- so nothing along that chain is left holding the recovered key.
  var ktRec = makeRecipient("rsa");
  var ktEnv2 = await pki.cms.encrypt(MSG, [{ cert: ktRec.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  t = tap();
  try {
    var ktOut = await pki.cms.decrypt(ktEnv2, { key: ktRec.key, cert: ktRec.cert });
    check("the key-transport content decrypts correctly", Buffer.compare(ktOut.content, MSG) === 0);
    wipedAll(t, "decrypt.out", "pki.cms.decrypt wipes the key-transport content key it recovered");
  } finally { t.restore(); }

  // Ownership decides whether a password ENCODING may be cleared. A string password is encoded into
  // a buffer this library allocated -- the common case, and a credential copy it must clear -- while
  // a caller-supplied Buffer is borrowed and must survive. Both are checked, because getting this
  // wrong in either direction is a defect: leaving the encoding readable, or destroying the
  // caller's credential.
  var strPwEnv = await pki.cms.encrypt(MSG, [{ password: "a-string-password", iterations: 1000 }],
    { contentEncryptionAlgorithm: "aes-256-cbc" });
  t = tap();
  try {
    var strPwOut = await pki.cms.decrypt(strPwEnv, { password: "a-string-password" });
    check("a string password still round-trips after its encoding is cleared",
      Buffer.compare(strPwOut.content, MSG) === 0);
    wipedAll(t, "pbkdf2.pw", "a string password's encoding is cleared once the derivation consumed it");
  } finally { t.restore(); }

  var bufPw = Buffer.from("a-buffer-password");
  var bufPwCopy = Buffer.from(bufPw);
  var bufPwEnv = await pki.cms.encrypt(MSG, [{ password: bufPw, iterations: 1000 }],
    { contentEncryptionAlgorithm: "aes-256-cbc" });
  t = tap();
  try {
    var bufPwOut = await pki.cms.decrypt(bufPwEnv, { password: bufPw });
    check("a caller-supplied password Buffer survives both directions intact",
      Buffer.compare(bufPw, bufPwCopy) === 0 && Buffer.compare(bufPwOut.content, MSG) === 0);
    // The mirror assertion: this one must NOT be cleared, because it is the caller's.
    var pwCaps = t.of("pbkdf2.pw");
    check("the caller's password Buffer reached the derivation and was left readable",
      pwCaps.length > 0 && pwCaps.every(function (c) { return anyNonZero(c.buf); }));
  } finally { t.restore(); }

  // PKCS#12 takes its password through a DIFFERENT encoder than the CMS paths (RFC 7292 App. B
  // BMPString rather than UTF-8), and that encoder also returns a caller-supplied Buffer as-is. So
  // the ownership rule has to hold there independently -- clearing what looks like "the encoding"
  // would destroy the caller's credential.
  var p12BufPw = Buffer.from("p12-buffer-password");
  var p12BufCopy = Buffer.from(p12BufPw);
  var p12BufStore = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: p12Rec.cert }] }] },
    { password: p12BufPw, mac: { algorithm: "hmac", hash: "sha256", iterations: 1024 } });
  var p12BufOpened = await pki.pkcs12.open(p12BufStore, p12BufPw);
  check("a caller-supplied PKCS#12 password Buffer survives build and open intact",
    Buffer.compare(p12BufPw, p12BufCopy) === 0 && p12BufOpened != null);

  // Same contract for a caller-supplied password buffer: passwordBytes hands a Buffer straight
  // through, so a wipe placed on it would destroy the caller's credential.
  var callerPw = Buffer.from("hunter2-hunter2-");
  var pwBufEnv = await pki.cms.encrypt(MSG, [{ password: callerPw, iterations: 1000 }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  var pwBufOut = await pki.cms.decrypt(pwBufEnv, { password: callerPw });
  check("a caller-supplied password Buffer is never wiped",
    Buffer.compare(callerPw, Buffer.from("hunter2-hunter2-")) === 0 && Buffer.compare(pwBufOut.content, MSG) === 0);

  // ---- the PRIVATE-KEY copies the engine makes to import a key --------------------
  // A signer or recipient key arrives as a Buffer, a Uint8Array, or a PEM string. The first is the
  // caller's own memory and is passed through; the other two are decoded into a NEW buffer here,
  // and that buffer is a second copy of a private key which nothing outside this process can reach.
  // Both directions are asserted, because they fail in opposite ways: an un-wiped copy leaves the
  // key readable, and a wrongly-wiped caller buffer destroys the key they still hold.
  var pkSigner = signing.makeSigner("ec-p256");
  var pkPem = pki.schema.pkcs8.pemEncode(pkSigner.key);
  var pkU8 = new Uint8Array(Buffer.from(pkSigner.key));
  var pkU8Snapshot = Buffer.from(pkU8);
  check("the Uint8Array signer key is non-zero to begin with", pkU8Snapshot.some(function (x) { return x !== 0; }));

  // Driving pki.x509.sign is the shipped consumer path for sign-scheme's key import. The tap holds
  // the buffer the engine received, which for these two forms is the copy lib/ made.
  var pkSpec = { subject: "Key Copy", subjectPublicKey: pkSigner.spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") };
  var certFromU8, certFromPem;
  t = tap();
  try {
    certFromU8 = await pki.x509.sign(pkSpec, { key: pkU8 });
    wipedAll(t, "import.pkcs8", "a Uint8Array signer key: the copy handed to the engine");
  } finally { t.restore(); }
  check("a certificate still signs from a Uint8Array key", Buffer.isBuffer(certFromU8));
  check("...and the caller's Uint8Array is untouched (it is theirs)",
    Buffer.compare(Buffer.from(pkU8), pkU8Snapshot) === 0);
  t = tap();
  try {
    certFromPem = await pki.x509.sign(pkSpec, { key: pkPem });
    wipedAll(t, "import.pkcs8", "a PEM signer key: the decoded copy");
  } finally { t.restore(); }
  check("a certificate still signs from a PEM key", Buffer.isBuffer(certFromPem));

  var callerKeyBuf = Buffer.from(pkSigner.key);
  var callerKeySnapshot = Buffer.from(callerKeyBuf);
  await pki.x509.sign(pkSpec, { key: callerKeyBuf });
  check("a caller-supplied signer key Buffer is never wiped",
    Buffer.compare(callerKeyBuf, callerKeySnapshot) === 0);

  // The recipient side of the same rule, through pki.cms.decrypt.
  var pkRecip = await makeRecipient("rsa");
  var recipEnv = await pki.cms.encrypt(MSG, [{ cert: pkRecip.cert }]);
  var recipKeyBuf = Buffer.from(pkRecip.key);
  var recipKeySnapshot = Buffer.from(recipKeyBuf);
  var recipOut = await pki.cms.decrypt(recipEnv, { key: recipKeyBuf, cert: pkRecip.cert });
  check("a caller-supplied recipient key Buffer is never wiped, and still decrypts",
    Buffer.compare(recipKeyBuf, recipKeySnapshot) === 0 && Buffer.compare(recipOut.content, MSG) === 0);
  var recipU8 = new Uint8Array(Buffer.from(pkRecip.key));
  var recipU8Snapshot = Buffer.from(recipU8);
  var recipOut2;
  t = tap();
  try {
    recipOut2 = await pki.cms.decrypt(recipEnv, { key: recipU8, cert: pkRecip.cert });
    wipedAll(t, "import.pkcs8", "a Uint8Array ktri recipient key: the copy handed to the engine");
  } finally { t.restore(); }
  check("a Uint8Array recipient key still decrypts, and the caller's array is untouched",
    Buffer.compare(recipOut2.content, MSG) === 0 && Buffer.compare(Buffer.from(recipU8), recipU8Snapshot) === 0);

  // The rule holds per recipient KIND, not just for the one that happened to be tested: the key
  // reaches a different unwrap on each, and each takes its own copy.
  var kariCopyRecip = await makeRecipient("ec-p256");
  var kariCopyEnv = await pki.cms.encrypt(MSG, [{ cert: kariCopyRecip.cert }]);
  var kariCopyPem = pki.schema.pkcs8.pemEncode(kariCopyRecip.key);
  var kariCopyOut;
  t = tap();
  try {
    kariCopyOut = await pki.cms.decrypt(kariCopyEnv, { key: kariCopyPem, cert: kariCopyRecip.cert });
    wipedAll(t, "import.pkcs8", "a PEM kari recipient key: the decoded copy");
  } finally { t.restore(); }
  check("a PEM kari recipient key still decrypts", Buffer.compare(kariCopyOut.content, MSG) === 0);

  // The FAILURE path, which is the one an attacker chooses. Between taking the key copy and the
  // unwrap sit several reads of attacker-supplied structure -- the wrap algorithm, the originator's
  // key, the recipient match -- and each throws on malformed input. A message crafted to fail there
  // must leave no more behind than one that decrypts, so the copy is asserted on a run that throws.
  var badKari = Buffer.from(kariCopyEnv);
  var kariParsed = pki.schema.cms.parse(kariCopyEnv);
  check("the kari fixture parses (the tampering below targets a real structure)", kariParsed != null);
  // Corrupt the ephemeral originator key so the agreement cannot be reconstructed.
  var origIdx = badKari.indexOf(Buffer.from([0x03, 0x42, 0x00, 0x04]));
  check("the originator public key was located for tampering", origIdx > 0);
  badKari[origIdx + 8] ^= 0xff;
  var tamperThrew = false;
  t = tap();
  try {
    try { await pki.cms.decrypt(badKari, { key: kariCopyPem, cert: kariCopyRecip.cert }); }
    catch (_e) { tamperThrew = true; }
    check("a tampered kari message is refused", tamperThrew === true);
    wipedAll(t, "import.pkcs8", "a kari failure: the key copy is still cleared");
  } finally { t.restore(); }

  // The tampered message above fails at the unwrap, which is inside the protected region either way.
  // This one fails INSIDE THE SETUP WINDOW -- parsing the recipient certificate, between taking the
  // key copy and reaching the agreement -- which is the window that was unprotected. The engine has
  // already been handed the copy by then, so the tap holds it and can say whether it was cleared.
  // On this path the key is never handed to the engine at all -- the setup throws first -- so the
  // import tap sees nothing and cannot answer. The copy is observed where it is BORN instead, at the
  // PEM decode the toolkit runs to produce it: that returned buffer IS the copy, and holding it is
  // the only way to ask whether an early throw leaves it readable.
  var pkcs8Mod = require("../../lib/schema-pkcs8");
  var realPemDecode = pkcs8Mod.pemDecode;
  var decoded = [];
  pkcs8Mod.pemDecode = function () {
    var out = realPemDecode.apply(this, arguments);
    if (Buffer.isBuffer(out)) decoded.push({ buf: out, snap: Buffer.from(out) });
    return out;
  };
  // The trigger is an unknown key-WRAP OID inside the agreement parameters. That is read one step
  // after the key copy is taken and before any agreement happens, so the refusal comes from exactly
  // the region that used to sit outside the protected block. (An unknown key-AGREEMENT OID looks
  // similar but is rejected later, from inside the block, so it would not test this.)
  var kariKea = pki.schema.cms.parse(kariCopyEnv).recipientInfos[0].keyEncryptionAlgorithm;
  var wrapOid = pki.asn1.read.oid(pki.asn1.decode(kariKea.parameters).children[0]);
  var wrapDer = pki.asn1.build.oid(wrapOid);
  var wrapAt = kariCopyEnv.indexOf(wrapDer);
  check("the kari key-wrap OID was located for tampering", wrapAt > 0);
  var unknownWrap = Buffer.from(kariCopyEnv);
  unknownWrap[wrapAt + wrapDer.length - 1] ^= 0x40;
  var windowCode = null;
  try {
    try { await pki.cms.decrypt(unknownWrap, { key: kariCopyPem, cert: kariCopyRecip.cert }); }
    catch (e) { windowCode = e.code; }
  } finally { pkcs8Mod.pemDecode = realPemDecode; }
  check("an unknown kari key-wrap is refused from inside the setup window",
    windowCode === "cms/unsupported-algorithm");
  check("the PEM decode produced a key copy to observe", decoded.length > 0);
  check("...it held real key material", decoded.length > 0 && decoded.every(function (c) { return anyNonZero(c.snap); }));
  check("...and it is cleared even though the throw came from the setup, not the unwrap",
    decoded.length > 0 && decoded.every(function (c) { return allZero(c.buf); }));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
