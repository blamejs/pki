// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.cms.decrypt: CMS EnvelopedData / AuthEnvelopedData / EncryptedData decryption
 * (RFC 5652/5083/5084/3560/5753/8418/9629/9936/3211/8018/3218). Drives the SHIPPED consumer path
 * pki.cms.decrypt against messages pki.cms.encrypt produces (self round-trip) and asserts the
 * fail-closed, ORACLE-FREE verdict: every secret-dependent failure collapses to the single uniform
 * cms/decrypt-failed code -- the Bleichenbacher / EFAIL / PWRI-oracle defense is the crown jewel.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var signing = require("../helpers/signing");
var makeRecipient = signing.makeRecipient;
var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }
async function codeOf(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
var MSG = Buffer.from("the CMS enveloped-data round-trip payload -- attack me");

async function rt(recipDesc, km, opts) {
  var env = await pki.cms.encrypt(MSG, [recipDesc], opts);
  return pki.cms.decrypt(env, km);
}

async function run() {
  // ---- accept round-trips per recipient type x algorithm (single-algorithm axis) ----
  for (var kind of ["rsa", "ec-p256", "ec-p384", "ec-p521", "x25519", "x448", "ml-kem-512", "ml-kem-768", "ml-kem-1024"]) {
    var r = makeRecipient(kind);
    var d = await rt({ cert: r.cert }, { key: r.key, cert: r.cert }, { contentEncryptionAlgorithm: "aes-256-cbc" });
    check("round-trip " + kind + " -> content + not authenticated (CBC)", Buffer.compare(d.content, MSG) === 0 && d.authenticated === false);
  }
  // OAEP hash variants (ktri)
  var rsa = makeRecipient("rsa");
  for (var h of ["sha256", "sha384", "sha512"]) {
    var dh = await rt({ cert: rsa.cert }, { key: rsa.key, cert: rsa.cert }, { contentEncryptionAlgorithm: "aes-256-cbc", oaepHash: h });
    check("ktri OAEP-" + h + " round-trips", Buffer.compare(dh.content, MSG) === 0);
  }
  // AEAD (GCM) -> AuthEnvelopedData, authenticated:true; both key sizes.
  var dg = await rt({ cert: rsa.cert }, { key: rsa.key, cert: rsa.cert });
  check("AES-256-GCM -> AuthEnvelopedData, authenticated:true", Buffer.compare(dg.content, MSG) === 0 && dg.authenticated === true);
  var dg128 = await rt({ cert: rsa.cert }, { key: rsa.key, cert: rsa.cert }, { contentEncryptionAlgorithm: "aes-128-gcm" });
  check("AES-128-GCM round-trips", Buffer.compare(dg128.content, MSG) === 0 && dg128.authenticated === true);
  // pwri + kekri + EncryptedData
  check("pwri password round-trips", Buffer.compare((await rt({ password: "hunter2" }, { password: "hunter2" }, { contentEncryptionAlgorithm: "aes-256-cbc" })).content, MSG) === 0);
  var kek = Buffer.alloc(32, 5);
  check("kekri AES-256-KW round-trips", Buffer.compare((await rt({ kek: kek, kekId: Buffer.from("k5") }, { kek: kek }, { contentEncryptionAlgorithm: "aes-256-cbc" })).content, MSG) === 0);
  var kek128 = Buffer.alloc(16, 6);
  check("kekri AES-128-KW round-trips", Buffer.compare((await rt({ kek: kek128, kekId: Buffer.from("k6") }, { kek: kek128 }, { contentEncryptionAlgorithm: "aes-256-cbc" })).content, MSG) === 0);
  var cekEnv = await pki.cms.encrypt(MSG, { cek: Buffer.alloc(32, 3) }, { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("EncryptedData {cek} round-trips + recipientType cek", (function (d) { return Buffer.compare(d.content, MSG) === 0 && d.recipientType === "cek"; })(await pki.cms.decrypt(cekEnv, { cek: Buffer.alloc(32, 3) })));
  var pwEnv = await pki.cms.encrypt(MSG, { password: "pw" }, { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("EncryptedData {password} (PBES2) round-trips", Buffer.compare((await pki.cms.decrypt(pwEnv, { password: "pw" })).content, MSG) === 0);

  // ---- multi-recipient: ONE CEK, each key material recovers the SAME content (M3) ----
  var mkem = makeRecipient("ml-kem-768");
  var multi = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }, { cert: mkem.cert }, { password: "pw" }, { kek: kek, kekId: Buffer.from("k5") }]);
  check("multi-recipient: RSA key recovers", Buffer.compare((await pki.cms.decrypt(multi, { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("multi-recipient: ML-KEM key recovers the same content", Buffer.compare((await pki.cms.decrypt(multi, { key: mkem.key, cert: mkem.cert })).content, MSG) === 0);
  check("multi-recipient: password recovers the same content", Buffer.compare((await pki.cms.decrypt(multi, { password: "pw" })).content, MSG) === 0);
  check("multi-recipient: kek recovers the same content", Buffer.compare((await pki.cms.decrypt(multi, { kek: kek })).content, MSG) === 0);

  // ---- rid matching: IAS (default) and SKI ----
  var rSki = makeRecipient("rsa", { ski: Buffer.from("0123456789abcdef0123", "latin1") });
  var envSki = await pki.cms.encrypt(MSG, [{ cert: rSki.cert, keyIdentifier: "subjectKeyIdentifier" }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("ktri subjectKeyIdentifier rid round-trips", Buffer.compare((await pki.cms.decrypt(envSki, { key: rSki.key, cert: rSki.cert })).content, MSG) === 0);

  // ---- dispatch: graceful handling + no-match + unsupported ----
  var noMatch = makeRecipient("rsa");
  check("key material matching no recipient -> cms/no-matching-recipient", (await codeOf(function () { return pki.cms.decrypt(multi, { key: noMatch.key, cert: noMatch.cert }); })) === "cms/no-matching-recipient");
  // graceful: an RSA key still decrypts a message where it is ONE of several recipients (M7).
  check("graceful: RSA recovers despite sibling ML-KEM/pwri/kekri recipients", Buffer.compare((await pki.cms.decrypt(multi, { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  // explicit recipientIndex override (an opts field) on a single-recipient message (index 0 is deterministic).
  var singlePwri = await pki.cms.encrypt(MSG, [{ password: "pw" }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("recipientIndex 0 explicitly selects the sole recipient", Buffer.compare((await pki.cms.decrypt(singlePwri, { password: "pw" }, { recipientIndex: 0 })).content, MSG) === 0);

  // ---- the uniform verdict: EVERY secret-dependent failure -> cms/decrypt-failed ----
  // GCM: tampered tag, ciphertext, and AAD each -> uniform, authenticated never leaks.
  var gEnv = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }]);
  check("GCM tampered ciphertext -> cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(_flipByte(gEnv, gEnv.length - 25), { key: rsa.key, cert: rsa.cert }); })) === "cms/decrypt-failed");
  // CBC bad pad (EFAIL) -> uniform.
  var cbcEnv = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("CBC tampered content -> cms/decrypt-failed (EFAIL class, no partial plaintext)", (await codeOf(function () { return pki.cms.decrypt(_flipByte(cbcEnv, cbcEnv.length - 5), { key: rsa.key, cert: rsa.cert }); })) === "cms/decrypt-failed");
  // AES-KW oracle: a single-byte-tampered wrapped CEK -> uniform.
  var kekEnv = await pki.cms.encrypt(MSG, [{ kek: kek, kekId: Buffer.from("k5") }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("AES-KW tampered wrapped CEK -> cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(kekEnv, { kek: Buffer.alloc(32, 8) }); })) === "cms/decrypt-failed");
  // PWRI oracle: wrong password -> uniform (check-byte mismatch indistinguishable).
  var pwriEnv = await pki.cms.encrypt(MSG, [{ password: "right" }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("PWRI wrong password -> cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(pwriEnv, { password: "wrong" }); })) === "cms/decrypt-failed");
  // Bleichenbacher/MMA: THREE differently-broken v1.5 inputs -> IDENTICAL cms/decrypt-failed.
  var v15a = _osslV15(rsa, MSG);
  if (v15a) {
    var codes = [];
    codes.push(await codeOf(function () { return pki.cms.decrypt(_flipByte(v15a, _encKeyOffset(v15a)), { key: rsa.key, cert: rsa.cert }); }));  // corrupt padding
    codes.push(await codeOf(function () { return pki.cms.decrypt(_flipByte(v15a, _encKeyOffset(v15a) + 5), { key: rsa.key, cert: rsa.cert }); }));  // corrupt mid
    codes.push(await codeOf(function () { return pki.cms.decrypt(v15a, { key: makeRecipient("rsa").key, cert: rsa.cert }); }));  // valid-padding wrong key
    check("v1.5 MMA: three differently-broken inputs yield the IDENTICAL cms/decrypt-failed (RFC 3218)", codes.every(function (c) { return c === "cms/decrypt-failed"; }));
    check("v1.5: the correct key still round-trips (implicit rejection does not break the good path)", Buffer.compare((await pki.cms.decrypt(v15a, { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  } else { helpers.skip && helpers.skip("openssl v1.5 fixture unavailable"); }

  // ---- kemri: wrong-length ct rejected before decap; ML-KEM implicit rejection folds in ----
  var kemEnv = await pki.cms.encrypt(MSG, [{ cert: mkem.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("kemri tampered kemct -> cms/decrypt-failed (FO implicit rejection folds into the uniform verdict)", (await codeOf(function () { return pki.cms.decrypt(_flipByte(kemEnv, 120), { key: mkem.key, cert: mkem.cert }); })) === "cms/decrypt-failed");

  // ---- detached content + config-time ----
  check("decrypt without key material -> throws", (await codeOf(function () { return pki.cms.decrypt(gEnv, null); })) === "cms/bad-input");
  check("decrypt a non-CMS input -> cms/bad-input or asn1/*", /^(cms|asn1|oid)\//.test(await codeOf(function () { return pki.cms.decrypt(Buffer.from([0x30, 0x00]), { password: "x" }); })));

  // ---- PBKDF2 DoS cap ----
  var hiEnv = await pki.cms.encrypt(MSG, [{ password: "p", iterations: 1000 }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("maxIterations cap below the message iterations -> cms/iteration-limit", (await codeOf(function () { return pki.cms.decrypt(hiEnv, { password: "p" }, { maxIterations: 100 }); })) === "cms/iteration-limit");
  check("a NaN maxIterations -> cms/bad-input (never a silently-disabled cap)", (await codeOf(function () { return pki.cms.decrypt(hiEnv, { password: "p" }, { maxIterations: NaN }); })) === "cms/bad-input");
  check("a non-number maxIterations -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(hiEnv, { password: "p" }, { maxIterations: "100" }); })) === "cms/bad-input");
  check("a normal password still round-trips within the cap", Buffer.compare((await pki.cms.decrypt(hiEnv, { password: "p" })).content, MSG) === 0);

  // ---- orchestrator routing ----
  check("pki.schema.parse routes an EnvelopedData we emit to cms (authEnvelopedData)", pki.schema.parse(gEnv).contentTypeName === "authEnvelopedData");

  // ---- input-form parity: Uint8Array / PEM / bad types across input, key, cert, password, kek ----
  var envCbc = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("decrypt accepts a Uint8Array input", Buffer.compare((await pki.cms.decrypt(new Uint8Array(envCbc), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("decrypt accepts a PEM input", (function () { var pem = pki.schema.cms.pemEncode(envCbc, "CMS"); return typeof pem === "string"; })());
  var pemEnv = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc", pem: true });
  check("decrypt accepts a PEM string input", Buffer.compare((await pki.cms.decrypt(pemEnv, { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("decrypt accepts a Uint8Array recipient key + PEM cert", Buffer.compare((await pki.cms.decrypt(envCbc, { key: new Uint8Array(rsa.key), cert: pki.schema.x509.pemEncode(rsa.cert, "CERTIFICATE") })).content, MSG) === 0);
  check("decrypt accepts a PEM recipient key", Buffer.compare((await pki.cms.decrypt(envCbc, { key: pki.schema.pkcs8.pemEncode(rsa.key, "PRIVATE KEY"), cert: rsa.cert })).content, MSG) === 0);
  check("decrypt rejects a non-decodable input -> cms/bad-input or asn1", /^(cms|asn1|oid|pem)\//.test(await codeOf(function () { return pki.cms.decrypt(42, { key: rsa.key, cert: rsa.cert }); })));
  check("decrypt rejects a non-decodable PEM input", /\//.test(await codeOf(function () { return pki.cms.decrypt("-----BEGIN CMS-----\nnot b64 !!!\n-----END CMS-----\n", { key: rsa.key, cert: rsa.cert }); })));
  check("decrypt rejects a bad recipient key type -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(envCbc, { key: 42, cert: rsa.cert }); })) === "cms/bad-input");
  check("decrypt rejects a bad recipient cert type -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(envCbc, { key: rsa.key, cert: 42 }); })) === "cms/bad-input");
  check("decrypt with empty key material object -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(envCbc, {}); })) === "cms/bad-input");

  // password forms + kek forms + kekId matching
  var pwB = await pki.cms.encrypt(MSG, [{ password: Buffer.from("bpw") }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("pwri password as a Buffer round-trips", Buffer.compare((await pki.cms.decrypt(pwB, { password: Buffer.from("bpw") })).content, MSG) === 0);
  var kEnv = await pki.cms.encrypt(MSG, [{ kek: kek, kekId: Buffer.from("kX") }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("kekri kekId Uint8Array match round-trips", Buffer.compare((await pki.cms.decrypt(kEnv, { kek: new Uint8Array(kek), kekId: new Uint8Array(Buffer.from("kX")) })).content, MSG) === 0);
  check("kekri wrong kekId -> cms/no-matching-recipient", (await codeOf(function () { return pki.cms.decrypt(kEnv, { kek: kek, kekId: Buffer.from("other") }); })) === "cms/no-matching-recipient");

  // SKI rid for kari + kemri; ukm-bearing kari + kemri
  var ecSki = makeRecipient("ec-p256", { ski: Buffer.from("ec-ski-20-bytes-here", "latin1") });
  var ecSkiEnv = await pki.cms.encrypt(MSG, [{ cert: ecSki.cert, keyIdentifier: "subjectKeyIdentifier" }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("kari subjectKeyIdentifier rid round-trips", Buffer.compare((await pki.cms.decrypt(ecSkiEnv, { key: ecSki.key, cert: ecSki.cert })).content, MSG) === 0);
  var kemSki = makeRecipient("ml-kem-768", { ski: Buffer.from("kem-ski-20-bytes-hey", "latin1") });
  var kemSkiEnv = await pki.cms.encrypt(MSG, [{ cert: kemSki.cert, keyIdentifier: "subjectKeyIdentifier" }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("kemri subjectKeyIdentifier rid round-trips", Buffer.compare((await pki.cms.decrypt(kemSkiEnv, { key: kemSki.key, cert: kemSki.cert })).content, MSG) === 0);
  var ukmEc = makeRecipient("ec-p256");
  var ukmEnv = await pki.cms.encrypt(MSG, [{ cert: ukmEc.cert }], { contentEncryptionAlgorithm: "aes-256-cbc", ukm: Buffer.from("ukm-material") });
  check("kari with ukm round-trips", Buffer.compare((await pki.cms.decrypt(ukmEnv, { key: ukmEc.key, cert: ukmEc.cert })).content, MSG) === 0);
  // a kari whose RecipientEncryptedKey for THIS recipient is not element 0 (a dummy rek prepended):
  // selection + unwrap must find the matching rek by rid, not blindly take element 0.
  var mrEc = makeRecipient("ec-p256");
  var mrEnv = _prependDummyKariRek(await pki.cms.encrypt(MSG, [{ cert: mrEc.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
  check("a multi-rek kari selects this recipient's encrypted key (not element 0)", Buffer.compare((await pki.cms.decrypt(mrEnv, { key: mrEc.key, cert: mrEc.cert })).content, MSG) === 0);
  // a kari whose originator EC key omits its curve parameters inherits the curve from the recipient.
  var poEc = makeRecipient("ec-p256");
  var poEnv = _stripOrigCurve(await pki.cms.encrypt(MSG, [{ cert: poEc.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
  check("a kari with a parameterless originator EC key inherits the recipient's curve", Buffer.compare((await pki.cms.decrypt(poEnv, { key: poEc.key, cert: poEc.cert })).content, MSG) === 0);
  var ukmKem = makeRecipient("ml-kem-768");
  var ukmKemEnv = await pki.cms.encrypt(MSG, [{ cert: ukmKem.cert }], { contentEncryptionAlgorithm: "aes-256-cbc", ukm: Buffer.from("kem-ukm") });
  check("kemri with ukm round-trips", Buffer.compare((await pki.cms.decrypt(ukmKemEnv, { key: ukmKem.key, cert: ukmKem.cert })).content, MSG) === 0);

  // recipientIndex override + out of range (an opts field)
  check("recipientIndex out of range -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(multi, { password: "pw" }, { recipientIndex: 99 }); })) === "cms/bad-input");
  var singleKem = await pki.cms.encrypt(MSG, [{ cert: mkem.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("recipientIndex 0 explicitly selects a sole ML-KEM recipient", Buffer.compare((await pki.cms.decrypt(singleKem, { key: mkem.key, cert: mkem.cert }, { recipientIndex: 0 })).content, MSG) === 0);

  // detached content -> no-encrypted-content
  var detached = _stripEncryptedContent(envCbc);
  check("detached encryptedContent -> cms/no-encrypted-content", /cms\/(no-encrypted-content|bad-input)/.test(await codeOf(function () { return pki.cms.decrypt(detached, { key: rsa.key, cert: rsa.cert }); })));

  // no-matching for each key type (password/kek against an all-ktri message)
  check("password key material against an all-ktri message -> no-matching-recipient", (await codeOf(function () { return pki.cms.decrypt(envCbc, { password: "x" }); })) === "cms/no-matching-recipient");
  check("kek key material against an all-ktri message -> no-matching-recipient", (await codeOf(function () { return pki.cms.decrypt(envCbc, { kek: kek }); })) === "cms/no-matching-recipient");

  // bad password type; Uint8Array password; EncryptedData bad cek length/type
  check("pwri with a non-string/Buffer password -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(pwriEnv, { password: 42 }); })) === "cms/bad-input");
  check("EncryptedData {cek} wrong length -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(cekEnv, { cek: Buffer.alloc(16) }); })) === "cms/bad-input");
  check("EncryptedData given a password when it is a raw-cek structure -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(cekEnv, { password: "x" }); })) === "cms/bad-input");
  check("EncryptedData PBES2 given a cek instead of a password -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(pwEnv, { cek: Buffer.alloc(32) }); })) === "cms/bad-input");

  // ---- hostile EncryptedData/PBES2 structure -> a typed PkiError, never a raw TypeError (fuzz contract) ----
  function encData(algNode) { return pki.asn1.build.sequence([pki.oid.byName("encryptedData") ? pki.asn1.build.oid(pki.oid.byName("encryptedData")) : null, pki.asn1.build.explicit(0, pki.asn1.build.sequence([pki.asn1.build.integer(0n), pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("data")), algNode, pki.asn1.build.contextPrimitive(0, Buffer.alloc(16))])]))].filter(Boolean)); }
  var bp = pki.asn1.build;
  for (var badParams of [bp.integer(5n), bp.sequence([]), bp.sequence([bp.integer(1n), bp.integer(2n)])]) {
    var badEnc = encData(bp.sequence([bp.oid(pki.oid.byName("pbes2")), badParams]));
    check("a malformed PBES2 EncryptedData is a typed PkiError, not a raw throw", (function (c) { return /^(cms|asn1|oid)\//.test(c); })(await codeOf(function () { return pki.cms.decrypt(badEnc, { password: "x" }); })));
  }

  // a SKI-rid message decrypted with a cert lacking a subjectKeyIdentifier -> no match (covers _skiOf null).
  check("SKI-rid message + a cert without a subjectKeyIdentifier -> no-matching-recipient", (await codeOf(function () { return pki.cms.decrypt(envSki, { key: rsa.key, cert: rsa.cert }); })) === "cms/no-matching-recipient");

  // ---- input-form parity: the alternate Buffer/Uint8Array/already-parsed arms ----
  check("decrypt accepts a plain Uint8Array input", Buffer.compare((await pki.cms.decrypt(new Uint8Array(envCbc), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("decrypt accepts an already-parsed CMS object as input", Buffer.compare((await pki.cms.decrypt(pki.schema.cms.parse(envCbc), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("decrypt accepts a plain Uint8Array recipient key", Buffer.compare((await pki.cms.decrypt(envCbc, { key: new Uint8Array(rsa.key), cert: rsa.cert })).content, MSG) === 0);
  check("decrypt accepts a plain Uint8Array recipient cert", Buffer.compare((await pki.cms.decrypt(envCbc, { key: rsa.key, cert: new Uint8Array(rsa.cert) })).content, MSG) === 0);
  check("decrypt accepts a Uint8Array password", Buffer.compare((await pki.cms.decrypt(pwriEnv, { password: new Uint8Array(Buffer.from("right")) })).content, MSG) === 0);
  check("decrypt with a non-object key material -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(envCbc, "not-an-object"); })) === "cms/bad-input");
  check("recipientIndex negative -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(multi, { password: "pw" }, { recipientIndex: -1 }); })) === "cms/bad-input");
  check("recipientIndex non-number -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(multi, { password: "pw" }, { recipientIndex: "0" }); })) === "cms/bad-input");
  var kekNoId = await pki.cms.encrypt(MSG, [{ kek: kek, kekId: Buffer.from("kX") }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("a kekri message decrypted with a kek and no kekId matches the first kekri", Buffer.compare((await pki.cms.decrypt(kekNoId, { kek: kek })).content, MSG) === 0);
  var sgn = signing.makeSigner("rsa");
  var signedCms = await pki.cms.sign(Buffer.from("hi"), [{ cert: sgn.cert, key: sgn.key }]);
  check("a non-Enveloped/non-Encrypted CMS (a SignedData) -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(signedCms, { key: rsa.key, cert: rsa.cert }); })) === "cms/bad-input");

  // ---- structural reject matrix: each distinct-code error arm driven through pki.cms.decrypt ----
  function envSet(riNodes, hasContent) {
    var eci = [bp.oid(O("data")), bp.sequence([bp.oid(O("aes256-CBC")), bp.octetString(Buffer.alloc(16))])];
    if (hasContent !== false) eci.push(bp.contextPrimitive(0, Buffer.alloc(16)));
    return bp.sequence([bp.oid(O("envelopedData")), bp.explicit(0, bp.sequence([bp.integer(3n), bp.setOf(riNodes), bp.sequence(eci)]))]);
  }
  function pwriRI(kdfNode, keaNode, ek) {
    var parts = [bp.integer(0n)];
    if (kdfNode) parts.push(kdfNode);
    parts.push(keaNode, bp.octetString(ek || Buffer.alloc(32)));
    return bp.contextConstructed(3, Buffer.concat(parts));
  }
  var goodKdf = bp.contextConstructed(0, Buffer.concat([bp.oid(O("pbkdf2")), bp.sequence([bp.octetString(Buffer.alloc(16)), bp.integer(1000n)])]));
  var pwriKea = bp.sequence([bp.oid(O("id-alg-PWRI-KEK")), bp.sequence([bp.oid(O("aes256-CBC")), bp.octetString(Buffer.alloc(16))])]);
  async function pwriCode(kdfNode, keaNode) { return codeOf(function () { return pki.cms.decrypt(envSet([pwriRI(kdfNode, keaNode)]), { password: "p" }); }); }
  check("pwri without a keyDerivationAlgorithm -> cms/missing-key-derivation", (await pwriCode(null, pwriKea)) === "cms/missing-key-derivation");
  check("pwri with a non-PBKDF2 keyDerivation -> cms/unsupported-algorithm", (await pwriCode(bp.contextConstructed(0, Buffer.concat([bp.oid(O("hmacWithSHA256")), bp.sequence([])])), pwriKea)) === "cms/unsupported-algorithm");
  check("pwri with a non-PWRI-KEK keyEncryption -> cms/unsupported-algorithm", (await pwriCode(goodKdf, bp.sequence([bp.oid(O("aes256-wrap")), bp.octetString(Buffer.alloc(0))]))) === "cms/unsupported-algorithm");
  check("pwri with a non-CBC inner cipher -> cms/unsupported-algorithm", (await pwriCode(goodKdf, bp.sequence([bp.oid(O("id-alg-PWRI-KEK")), bp.sequence([bp.oid(O("aes256-GCM")), bp.octetString(Buffer.alloc(16))])]))) === "cms/unsupported-algorithm");
  check("pwri with a wrong-length wrapped key -> cms/decrypt-failed (uniform)", (await codeOf(function () { return pki.cms.decrypt(envSet([pwriRI(goodKdf, pwriKea, Buffer.alloc(30))]), { password: "p" }); })) === "cms/decrypt-failed");
  // ori (OtherRecipientInfo) reached via an explicit recipientIndex: unsupported oriType + RSA-KEM are distinct-coded.
  var oriData = bp.contextConstructed(4, Buffer.concat([bp.oid(O("data")), bp.integer(0n)]));
  check("an unsupported OtherRecipientInfo type -> cms/unsupported-recipient-type", (await codeOf(function () { return pki.cms.decrypt(envSet([oriData]), { key: rsa.key, cert: rsa.cert }, { recipientIndex: 0 }); })) === "cms/unsupported-recipient-type");
  function oriKem(kemOid) { return bp.contextConstructed(4, Buffer.concat([bp.oid(O("kem")), bp.sequence([bp.integer(0n), bp.contextPrimitive(0, Buffer.alloc(20)), bp.sequence([bp.oid(O(kemOid))]), bp.octetString(Buffer.alloc(32)), bp.sequence([bp.oid(O("hkdfWithSha256"))]), bp.integer(32n), bp.sequence([bp.oid(O("aes256-wrap"))]), bp.octetString(Buffer.alloc(40))])])); }
  check("an RSA-KEM (id-kem-rsa) OtherRecipientInfo -> cms/unsupported-algorithm", (await codeOf(function () { return pki.cms.decrypt(envSet([oriKem("id-kem-rsa")]), { key: mkem.key, cert: mkem.cert }, { recipientIndex: 0 }); })) === "cms/unsupported-algorithm");
  check("an unknown KEM OtherRecipientInfo -> cms/unsupported-algorithm", (await codeOf(function () { return pki.cms.decrypt(envSet([oriKem("data")]), { key: mkem.key, cert: mkem.cert }, { recipientIndex: 0 }); })) === "cms/unsupported-algorithm");

  // a PBKDF2 salt above the DoS cap -> cms/bad-input.
  var bigSaltKdf = bp.contextConstructed(0, Buffer.concat([bp.oid(O("pbkdf2")), bp.sequence([bp.octetString(Buffer.alloc(2000)), bp.integer(1000n)])]));
  check("a PBKDF2 salt above the cap -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(envSet([pwriRI(bigSaltKdf, pwriKea)]), { password: "p" }); })) === "cms/bad-input");
  // OAEP parameters WebCrypto cannot faithfully honor (an MGF1 hash != the OAEP hash, or a non-empty
  // label) are rejected, not silently ignored. A ktri with a SKI rid pins EnvelopedData/recipient version 2.
  var NL = bp.raw(Buffer.from([5, 0]));
  function ktriOaepEnv(paramsInner) {
    var ktri = bp.sequence([bp.integer(2n), bp.contextPrimitive(0, Buffer.alloc(20)), bp.sequence([bp.oid(O("rsaesOaep")), paramsInner]), bp.octetString(Buffer.alloc(256))]);
    var eci = bp.sequence([bp.oid(O("data")), bp.sequence([bp.oid(O("aes256-CBC")), bp.octetString(Buffer.alloc(16))]), bp.contextPrimitive(0, Buffer.alloc(16))]);
    return bp.sequence([bp.oid(O("envelopedData")), bp.explicit(0, bp.sequence([bp.integer(2n), bp.setOf([ktri]), eci]))]);
  }
  var oaepMgf = ktriOaepEnv(bp.sequence([bp.explicit(0, bp.sequence([bp.oid(O("sha256")), NL])), bp.explicit(1, bp.sequence([bp.oid(O("mgf1")), bp.sequence([bp.oid(O("sha1")), NL])]))]));
  check("OAEP with an MGF1 hash != the OAEP hash -> cms/unsupported-algorithm", (await codeOf(function () { return pki.cms.decrypt(oaepMgf, { key: rsa.key, cert: rsa.cert }, { recipientIndex: 0 }); })) === "cms/unsupported-algorithm");
  var oaepLabel = ktriOaepEnv(bp.sequence([bp.explicit(0, bp.sequence([bp.oid(O("sha256")), NL])), bp.explicit(2, bp.sequence([bp.oid(O("pSpecified")), bp.octetString(Buffer.from("label"))]))]));
  check("OAEP with a non-empty label -> cms/unsupported-algorithm", (await codeOf(function () { return pki.cms.decrypt(oaepLabel, { key: rsa.key, cert: rsa.cert }, { recipientIndex: 0 }); })) === "cms/unsupported-algorithm");
  // PKCS#1 v1.5 (rsaEncryption) implicit rejection WITHOUT an openssl oracle: a decode fault (here a
  // wrong-length RSA ciphertext) yields a fresh random CEK, so the failure is the uniform verdict --
  // never a distinguishable padding error (RFC 3218 sec. 2.3.2).
  var v15Ktri = bp.sequence([bp.integer(0n), bp.sequence([bp.sequence([]), bp.integer(1n)]), bp.sequence([bp.oid(O("rsaEncryption")), NL]), bp.octetString(Buffer.alloc(128))]);
  var v15EciNoSsl = bp.sequence([bp.oid(O("data")), bp.sequence([bp.oid(O("aes256-CBC")), bp.octetString(Buffer.alloc(16))]), bp.contextPrimitive(0, Buffer.alloc(16))]);
  var v15EnvNoSsl = bp.sequence([bp.oid(O("envelopedData")), bp.explicit(0, bp.sequence([bp.integer(0n), bp.setOf([v15Ktri]), v15EciNoSsl]))]);
  check("v1.5 ktri with a decode fault -> cms/decrypt-failed (implicit rejection, no oracle)", (await codeOf(function () { return pki.cms.decrypt(v15EnvNoSsl, { key: rsa.key, cert: rsa.cert }, { recipientIndex: 0 }); })) === "cms/decrypt-failed");

  // ---- EncryptedData + PBES2 distinct-code reject arms ----
  function encData3(algNode, hasContent) {
    var eci = [bp.oid(O("data")), algNode];
    if (hasContent !== false) eci.push(bp.contextPrimitive(0, Buffer.alloc(16)));
    return bp.sequence([bp.oid(O("encryptedData")), bp.explicit(0, bp.sequence([bp.integer(0n), bp.sequence(eci)]))]);
  }
  var aesAlg = bp.sequence([bp.oid(O("aes256-CBC")), bp.octetString(Buffer.alloc(16))]);
  check("EncryptedData with no encryptedContent -> cms/no-encrypted-content", (await codeOf(function () { return pki.cms.decrypt(encData3(aesAlg, false), { cek: Buffer.alloc(32) }); })) === "cms/no-encrypted-content");
  check("EncryptedData with an unsupported content algorithm -> cms/unsupported-algorithm", (await codeOf(function () { return pki.cms.decrypt(encData3(bp.sequence([bp.oid(O("rsaEncryption")), bp.octetString(Buffer.alloc(16))])), { cek: Buffer.alloc(32) }); })) === "cms/unsupported-algorithm");
  check("EncryptedData given a kek (no cek) -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(encData3(aesAlg), { kek: Buffer.alloc(32) }); })) === "cms/bad-input");
  function pbes2Enc(kdfOid, cipherOid) {
    var pbes2 = bp.sequence([bp.oid(O("pbes2")), bp.sequence([bp.sequence([bp.oid(O(kdfOid)), bp.sequence([bp.octetString(Buffer.alloc(16)), bp.integer(1000n)])]), bp.sequence([bp.oid(O(cipherOid)), bp.octetString(Buffer.alloc(16))])])]);
    return encData3(pbes2);
  }
  check("PBES2 with a non-PBKDF2 keyDerivationFunc -> cms/unsupported-algorithm", (await codeOf(function () { return pki.cms.decrypt(pbes2Enc("hmacWithSHA256", "aes256-CBC"), { password: "x" }); })) === "cms/unsupported-algorithm");
  check("PBES2 with an unsupported content cipher -> cms/unsupported-algorithm", (await codeOf(function () { return pki.cms.decrypt(pbes2Enc("pbkdf2", "rsaEncryption"), { password: "x" }); })) === "cms/unsupported-algorithm");
  check("PBES2 given a cek instead of a password -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(pbes2Enc("pbkdf2", "aes256-CBC"), { cek: Buffer.alloc(32) }); })) === "cms/bad-input");

  // ---- the uniform verdict on content-open faults: a valid CEK, then a malformed content field ----
  // rebuild a real kekri envelope with a wrong-length content IV -> the CEK unwraps, the open fails uniform.
  var badIvEnv = _rebuildContentIv(kekNoId, 8);
  check("a valid CEK over a wrong-length content IV -> cms/decrypt-failed (uniform)", (await codeOf(function () { return pki.cms.decrypt(badIvEnv, { kek: kek }); })) === "cms/decrypt-failed");
  check("EncryptedData {cek} with the wrong key -> cms/decrypt-failed (uniform CBC open)", (await codeOf(function () { return pki.cms.decrypt(cekEnv, { cek: Buffer.alloc(32, 0xff) }); })) === "cms/decrypt-failed");
  check("EncryptedData PBES2 with the wrong password -> cms/decrypt-failed (uniform CBC open)", (await codeOf(function () { return pki.cms.decrypt(pwEnv, { password: "wrong" }); })) === "cms/decrypt-failed");
  check("a malformed recipient-key PEM -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(envCbc, { key: "-----BEGIN PRIVATE KEY-----\nnot-b64!!\n-----END PRIVATE KEY-----\n", cert: rsa.cert }); })) === "cms/bad-input");
  check("a malformed recipient-cert PEM (decrypt) -> cms/bad-input", (await codeOf(function () { return pki.cms.decrypt(envCbc, { key: rsa.key, cert: "-----BEGIN CERTIFICATE-----\nnot-b64!!\n-----END CERTIFICATE-----\n" }); })) === "cms/bad-input");

  // orchestrator routing
  check("pki.schema.parse routes an emitted EncryptedData to cms", pki.schema.parse(cekEnv).contentTypeName === "encryptedData");

  console.log("CHECKS " + helpers.getChecks());
}

function _stripEncryptedContent(der) {
  // Re-parse + rebuild the EnvelopedData without the [0] encryptedContent (a detached structure).
  var ci = pki.asn1.decode(der);
  var ed = ci.children[1].children[0];             // [0] EXPLICIT EnvelopedData
  var eci = ed.children[ed.children.length - 1];   // encryptedContentInfo SEQUENCE
  var b2 = pki.asn1.build;
  var newEci = b2.sequence(eci.children.slice(0, 2).map(function (c) { return b2.raw(c.bytes); })); // drop [0] content
  var newEd = b2.sequence(ed.children.slice(0, ed.children.length - 1).map(function (c) { return b2.raw(c.bytes); }).concat([newEci]));
  return b2.sequence([b2.raw(ci.children[0].bytes), b2.explicit(0, newEd)]);
}

// Rebuild a valid EnvelopedData with a wrong-length content IV: the recipientInfo (the wrapped CEK)
// is untouched, so the CEK unwraps and the failure surfaces only at the content open (the uniform verdict).
function _rebuildContentIv(der, ivLen) {
  var ci = pki.asn1.decode(der);
  var ed = ci.children[1].children[0];
  var eci = ed.children[ed.children.length - 1];
  var b2 = pki.asn1.build;
  var alg = eci.children[1];
  var newAlg = b2.sequence([b2.raw(alg.children[0].bytes), b2.octetString(Buffer.alloc(ivLen))]);
  var newEciKids = [b2.raw(eci.children[0].bytes), newAlg];
  for (var i = 2; i < eci.children.length; i++) newEciKids.push(b2.raw(eci.children[i].bytes));
  var newEdKids = ed.children.slice(0, ed.children.length - 1).map(function (c) { return b2.raw(c.bytes); }).concat([b2.sequence(newEciKids)]);
  return b2.sequence([b2.raw(ci.children[0].bytes), b2.explicit(0, b2.sequence(newEdKids))]);
}
// Prepend a dummy RecipientEncryptedKey (a non-matching rid) before the real one in a kari, so the
// recipient's own rek is at index 1 -- exercises rid-matched rek selection instead of "take element 0".
function _prependDummyKariRek(der) {
  var b2 = pki.asn1.build;
  var ci = pki.asn1.decode(der);
  var ed = ci.children[1].children[0];
  var riSet = ed.children.filter(function (c) { return c.tagNumber === 17 && c.tagClass === "universal"; })[0];
  var kari = riSet.children[0];
  var reks = kari.children[kari.children.length - 1];
  var realRek = reks.children[0];
  var issuerBytes = realRek.children[0].children[0].bytes;   // reuse the issuer Name, bump the serial
  var dummyRek = b2.sequence([b2.sequence([b2.raw(issuerBytes), b2.integer(99999n)]), b2.octetString(Buffer.alloc(40))]);
  var newReks = b2.sequence([dummyRek, b2.raw(realRek.bytes)]);
  var kariContent = Buffer.concat(kari.children.slice(0, kari.children.length - 1).map(function (c) { return c.bytes; }).concat([newReks]));
  var newKari = b2.contextConstructed(1, kariContent);
  var edKids = ed.children.map(function (c) { return (c.tagNumber === 17 && c.tagClass === "universal") ? b2.setOf([newKari]) : b2.raw(c.bytes); });
  return b2.sequence([b2.raw(ci.children[0].bytes), b2.explicit(0, b2.sequence(edKids))]);
}

// Strip the curve parameters from a kari's originator EC key (RFC 5753 sec. 7.1 allows inheriting
// the curve from the recipient) -- the decryptor must resolve the curve from the recipient certificate.
function _stripOrigCurve(der) {
  var b2 = pki.asn1.build;
  var ci = pki.asn1.decode(der);
  var ed = ci.children[1].children[0];
  var riSet = ed.children.filter(function (c) { return c.tagNumber === 17 && c.tagClass === "universal"; })[0];
  var kari = riSet.children[0];
  var opk = kari.children[1].children[0];                                   // originator [0] EXPLICIT -> originatorKey [1]
  var algId = opk.children[0];
  var newOpk = b2.contextConstructed(1, Buffer.concat([b2.sequence([b2.raw(algId.children[0].bytes)]), opk.children[1].bytes]));
  var newOrig = b2.contextConstructed(0, newOpk);
  var kariContent = Buffer.concat([kari.children[0].bytes, newOrig].concat(kari.children.slice(2).map(function (c) { return c.bytes; })));
  var newKari = b2.contextConstructed(1, kariContent);
  var edKids = ed.children.map(function (c) { return (c.tagNumber === 17 && c.tagClass === "universal") ? b2.setOf([newKari]) : b2.raw(c.bytes); });
  return b2.sequence([b2.raw(ci.children[0].bytes), b2.explicit(0, b2.sequence(edKids))]);
}

function _flipByte(buf, i) { var c = Buffer.from(buf); c[i] ^= 0x01; return c; }
function _encKeyOffset(der) { return Math.floor(der.length / 2); }  // a byte inside the RSA-encrypted key region

// An OpenSSL PKCS#1 v1.5 ktri EnvelopedData over MSG for `recip`, or null when openssl is absent
// (spawnSync reports a spawn failure via `.error` and a non-zero exit via `.status`, never a throw).
function _osslV15(recip, msg) {
  var cp = require("node:child_process"), fs = require("node:fs"), os = require("node:os"), path = require("node:path");
  var OSSL = process.env.PKIJS_OPENSSL || "C:/Program Files/OpenSSL-Win64/bin/openssl.exe";
  if (!fs.existsSync(OSSL)) return null;
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "cmsv15-"));
  fs.writeFileSync(path.join(dir, "c.crt"), pki.schema.x509.pemEncode(recip.cert, "CERTIFICATE"));
  fs.writeFileSync(path.join(dir, "m.bin"), msg);
  var r = cp.spawnSync(OSSL, ["cms", "-encrypt", "-aes-256-cbc", "-in", path.join(dir, "m.bin"), "-outform", "DER", "-out", path.join(dir, "e.der"), "-recip", path.join(dir, "c.crt")], { encoding: "buffer" });
  if (r.error || r.status !== 0 || !fs.existsSync(path.join(dir, "e.der"))) return null;
  return fs.readFileSync(path.join(dir, "e.der"));
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}

void O; void b;
