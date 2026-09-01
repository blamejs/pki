// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- composite ML-KEM in CMS KEMRecipientInfo (RFC 9629 kemri + RFC 9936 conventions +
 * draft-lamps-pq-composite-kem). Drives the SHIPPED consumer path: pki.cms.encrypt to a recipient
 * whose certificate carries a composite ML-KEM key (e.g. id-MLKEM768-ECDH-P256-SHA3-256), then
 * pki.cms.decrypt with the composite PKCS#8 key. Encaps is randomized, so this is a genuine
 * round-trip, not a KAT match; the App. G decaps KAT already covers the engine in composite-kem.test.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var surgery = require("../helpers/der-surgery");
var b = pki.asn1.build;
var kat = require("../fixtures/composite-kem/kat.json");
function O(n) { return pki.oid.byName(n); }
async function codeOf(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
var MSG = Buffer.from("composite ML-KEM CMS enveloped-data round-trip -- attack me");

var COMPOSITE = kat.tests.filter(function (t) { return t.tcId.indexOf("id-MLKEM") === 0; });
function arm(t) { return { cert: Buffer.from(t.x5c, "base64"), key: Buffer.from(t.dk_pkcs8, "base64"), tcId: t.tcId }; }

async function run() {
  var supported = [];
  for (var i = 0; i < COMPOSITE.length; i++) {
    var a = arm(COMPOSITE[i]);
    var spki = pki.schema.x509.parse(a.cert).subjectPublicKeyInfo.bytes;
    try { await pki.kem.encapsulate(spki); }
    catch (e) { console.log("SKIP " + a.tcId + " -- engine curve unsupported on this host: " + (e.code || e.message)); continue; }
    var env = await pki.cms.encrypt(MSG, [{ cert: a.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
    var d = await pki.cms.decrypt(env, { key: a.key, cert: a.cert });
    check("composite kemri round-trip " + a.tcId + " -> content recovered, not authenticated (CBC)", Buffer.compare(d.content, MSG) === 0 && d.authenticated === false);
    supported.push(a);
  }
  check("composite kemri: every host-supported composite arm was exercised (>= 10 of 12)", supported.length >= 10);

  var one = supported[0];

  // AEAD (GCM) -> AuthEnvelopedData, authenticated:true
  var g = await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: one.cert }]), { key: one.key, cert: one.cert });
  check("composite kemri AES-256-GCM -> AuthEnvelopedData authenticated:true", Buffer.compare(g.content, MSG) === 0 && g.authenticated === true);

  // Shape: the emitted recipient carries the composite kem OID, hkdf-sha256, aes256-wrap, kekLength 32.
  var shapeEnv = await pki.cms.encrypt(MSG, [{ cert: one.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  var kemOidDer = b.oid(O(one.tcId));
  var wrapOidDer = b.oid(O("aes256-wrap"));
  var kdfOidDer = b.oid(O("hkdfWithSha256"));
  check("composite kemri emits the composite kem OID", shapeEnv.indexOf(kemOidDer) !== -1);
  check("composite kemri emits hkdf-sha256 as the kdf", shapeEnv.indexOf(kdfOidDer) !== -1);
  check("composite kemri emits aes256-wrap as the wrap", shapeEnv.indexOf(wrapOidDer) !== -1);

  // Reject: wrong recipient key -> the uniform oracle-free cms/decrypt-failed verdict.
  var two = supported[1] || supported[0];
  var envA = await pki.cms.encrypt(MSG, [{ cert: one.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  // A matching rid (one.cert) with the WRONG private key (two.key) reaches decaps and MUST collapse to the
  // single uniform verdict -- the composite's explicit RSA-OAEP rejection must not leak as a distinguishing oracle.
  check("composite kemri matching rid + wrong key -> cms/decrypt-failed (oracle-free)", (await codeOf(function () { return pki.cms.decrypt(envA, { key: two.key, cert: one.cert }); })) === "cms/decrypt-failed");

  // Reject: a tampered composite ciphertext -> the uniform verdict. The env midpoint lands deep in the kemct
  // (the largest component, >= 1120 bytes for every arm), so the ML-KEM half implicit-rejects to a wrong shared
  // secret and the AES-KW unwrap fails, collapsing to the single cms/decrypt-failed verdict.
  var envT = Buffer.from(await pki.cms.encrypt(MSG, [{ cert: one.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
  envT[Math.floor(envT.length / 2)] ^= 0x40;
  check("composite kemri tampered kemct -> cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(envT, { key: one.key, cert: one.cert }); })) === "cms/decrypt-failed");

  // Multi-recipient: composite KEM alongside RSA, each recovers the SAME content.
  var rsa = require("../helpers/signing").makeRecipient("rsa");
  var multi = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }, { cert: one.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("multi-recipient: composite KEM recovers", Buffer.compare((await pki.cms.decrypt(multi, { key: one.key, cert: one.cert })).content, MSG) === 0);
  check("multi-recipient: the RSA sibling recovers the same content", Buffer.compare((await pki.cms.decrypt(multi, { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);

  // Reject: a composite kem AlgorithmIdentifier carrying PRESENT parameters is refused (params MUST be absent).
  var goodKemOid = b.oid(O(one.tcId));
  var absentAlg = b.sequence([goodKemOid]);
  var paramsAlg = b.sequence([goodKemOid, Buffer.from([0x05, 0x00])]);
  var withParams = surgery.replaceTlv(Buffer.from(envA), absentAlg, paramsAlg);
  check("composite kemri with present kem parameters -> cms/bad-algorithm-parameters (params MUST be absent)", withParams.count === 1 && (await codeOf(function () { return pki.cms.decrypt(withParams.der, { key: one.key, cert: one.cert }); })) === "cms/bad-algorithm-parameters");

  // An invalid ukm is rejected at the door -- validated BEFORE any KEM secret is generated, so a rejected
  // input never leaves fresh secret material unwiped (the shared kemri builder validates ukm first).
  check("composite kemri: an invalid ukm is refused with cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: one.cert, ukm: 123 }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");

  // Algorithm binding: the advertised kem OID MUST match the recipient key's algorithm. P-256 (59) and
  // brainpoolP256r1 (61) share the ML-KEM-768 + 65-octet ciphertext layout, so swapping the encoded OID leaves a
  // structurally valid kemri that the P-256 key could otherwise still decapsulate -- an algorithm-confusion vector.
  var p256 = COMPOSITE.filter(function (t) { return t.tcId === "id-MLKEM768-ECDH-P256-SHA3-256"; })[0];
  if (p256) {
    var p256arm = arm(p256);
    var envP = Buffer.from(await pki.cms.encrypt(MSG, [{ cert: p256arm.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
    var swapped = surgery.replaceTlv(envP, b.oid(O("id-MLKEM768-ECDH-P256-SHA3-256")), b.oid(O("id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256")));
    check("composite kemri: an advertised kem OID not matching the recipient key -> cms/decrypt-failed", swapped.count === 1 && (await codeOf(function () { return pki.cms.decrypt(swapped.der, { key: p256arm.key, cert: p256arm.cert }); })) === "cms/decrypt-failed");
  }

  console.log("CHECKS " + helpers.getChecks());
}

run().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
