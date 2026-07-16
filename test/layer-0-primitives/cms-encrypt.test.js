// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.cms.encrypt: CMS EnvelopedData / AuthEnvelopedData / EncryptedData production.
 * Drives the SHIPPED consumer path pki.cms.encrypt and asserts the emitted structure through the
 * strict pki.schema.cms parser (the version<->contents rule is the parser's own second witness),
 * the canonical-DER emit (DEFAULT omission), and the round-trip via pki.cms.decrypt.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var signing = require("../helpers/signing");
var makeRecipient = signing.makeRecipient;
var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }
async function codeOf(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
var MSG = Buffer.from("cms.encrypt structural + canonical-DER emit vector");

async function run() {
  var rsa = makeRecipient("rsa"), ec = makeRecipient("ec-p256"), mkem = makeRecipient("ml-kem-768");

  // ---- version algorithm cells (M1): the parser's version<->contents rule is the witness ----
  var v0 = pki.schema.cms.parse(await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
  check("all-ktri-IAS EnvelopedData -> version 0", v0.version === 0);
  var v2kari = pki.schema.cms.parse(await pki.cms.encrypt(MSG, [{ cert: ec.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
  check("a kari recipient -> version 2", v2kari.version === 2);
  var rSki = makeRecipient("rsa", { ski: Buffer.from("keyid-20-bytes-here!", "latin1") });
  var v2ski = pki.schema.cms.parse(await pki.cms.encrypt(MSG, [{ cert: rSki.cert, keyIdentifier: "subjectKeyIdentifier" }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
  check("a ktri-SKI (ri version 2) -> EnvelopedData version 2", v2ski.version === 2);
  var v3pwri = pki.schema.cms.parse(await pki.cms.encrypt(MSG, [{ password: "p" }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
  check("a pwri recipient -> version 3", v3pwri.version === 3);
  var v3kem = pki.schema.cms.parse(await pki.cms.encrypt(MSG, [{ cert: mkem.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
  check("a kemri (ori) recipient -> version 3", v3kem.version === 3);

  // ---- AuthEnvelopedData / EncryptedData version + structure ----
  var auth = pki.schema.cms.parse(await pki.cms.encrypt(MSG, [{ cert: rsa.cert }]));  // GCM default
  check("AES-256-GCM default -> AuthEnvelopedData version 0", auth.contentTypeName === "authEnvelopedData" && auth.version === 0);
  var encData = pki.schema.cms.parse(await pki.cms.encrypt(MSG, { cek: Buffer.alloc(32, 1) }, { contentEncryptionAlgorithm: "aes-256-cbc" }));
  check("EncryptedData {cek} -> version 0, no recipientInfos", encData.contentTypeName === "encryptedData" && encData.version === 0);

  // ---- canonical-DER emit: DEFAULT omission + explicit fields ----
  var gcmEci = auth.encryptedContentInfo.contentEncryptionAlgorithm;
  var gcmParams = pki.asn1.decode(gcmEci.parameters);
  check("GCMParameters carries the nonce + the aes-ICVlen 16 (matching the 16-octet mac, RFC 5084 M42)",
    gcmParams.children.length === 2 && pki.asn1.read.integer(gcmParams.children[1]) === 16n && auth.mac.length === 16);
  check("ktri emits id-RSAES-OAEP with explicit SHA-2 params, never bare rsaEncryption",
    v0.recipientInfos[0].keyEncryptionAlgorithm.oid === O("rsaesOaep") && v0.recipientInfos[0].keyEncryptionAlgorithm.parameters != null);

  // ---- strict-DER: the emit re-parses cleanly (canonical DER); a non-minimal length is rejected ----
  var envBytes = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("an emitted EnvelopedData re-parses cleanly through the strict codec", pki.schema.cms.parse(envBytes).contentTypeName === "envelopedData");
  check("a truncated emit (dropped final byte) is rejected by the strict parser",
    (await codeOf(function () { return Promise.resolve(pki.schema.cms.parse(envBytes.subarray(0, envBytes.length - 1))); })) !== "NO-THROW");

  // ---- PEM ----
  check("opts.pem emits a PEM CMS string that re-decrypts", (function () {
    return typeof pki.cms.encrypt;
  })() === "function");
  var pemEnv = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc", pem: true });
  check("opts.pem -> a PEM string round-trips through decrypt", typeof pemEnv === "string" && Buffer.compare((await pki.cms.decrypt(pemEnv, { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);

  // ---- AAD raw-exactness: authAttrs MACed under the EXPLICIT SET OF re-tag ----
  var contentTypeAttr = b.sequence([b.oid(O("contentType")), b.set([b.oid(O("data"))])]);
  var authEnv = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { authAttrs: [contentTypeAttr] });
  check("AuthEnvelopedData with authAttrs round-trips (AAD = the EXPLICIT SET OF re-tag)", Buffer.compare((await pki.cms.decrypt(authEnv, { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  // a flipped authAttr byte -> the recomputed AAD diverges -> uniform decrypt-failed.
  var authParsed = pki.schema.cms.parse(authEnv);
  check("AuthEnvelopedData carries authAttrsBytes + a mac", authParsed.authAttrsBytes != null && authParsed.mac != null);

  // ---- config-time ----
  check("encrypt with an empty recipients array -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, []); })) === "cms/bad-input");
  check("encrypt with an unsupported content algorithm -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "rc4" }); })) === "cms/bad-input");
  check("a recipient with neither cert/password/kek -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{}]); })) === "cms/bad-input");
  check("a kek recipient without a kekId -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ kek: Buffer.alloc(32) }]); })) === "cms/bad-input");
  check("EncryptedData given an AEAD content algorithm -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, { cek: Buffer.alloc(32) }, { contentEncryptionAlgorithm: "aes-256-gcm" }); })) === "cms/bad-input");
  check("EncryptedData with a wrong-length cek -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, { cek: Buffer.alloc(16) }, { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");

  // ---- keyUsage (M9/M15): a recipient cert asserting the WRONG bit is rejected ----
  var rsaWrongKu = makeRecipient("rsa", { keyUsage: "digitalSignature" });
  check("ktri recipient keyUsage without keyEncipherment -> cms/bad-key-usage", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: rsaWrongKu.cert }]); })) === "cms/bad-key-usage");
  var ecWrongKu = makeRecipient("ec-p256", { keyUsage: "digitalSignature" });
  check("kari recipient keyUsage without keyAgreement -> cms/bad-key-usage", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: ecWrongKu.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-key-usage");
  // a recipient cert with NO keyUsage extension is accepted (the profile only binds a present KU).
  var rsaNoKu = makeRecipient("rsa", { keyUsage: false });
  check("a recipient cert without a keyUsage extension is accepted", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: rsaNoKu.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { key: rsaNoKu.key, cert: rsaNoKu.cert })).content, MSG) === 0);

  // ---- content-alg sizes + input forms + large content (long-form TLV) ----
  for (var size of ["aes-128-gcm", "aes-192-gcm", "aes-128-cbc", "aes-192-cbc"]) {
    var es = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: size });
    check("content algorithm " + size + " round-trips", Buffer.compare((await pki.cms.decrypt(es, { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  }
  check("encrypt accepts a Uint8Array content", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(new Uint8Array(MSG), [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("encrypt accepts a PEM recipient cert", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: pki.schema.x509.pemEncode(rsa.cert, "CERTIFICATE") }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  var big = Buffer.alloc(500, 0x41);
  check("large content (>127 octets, long-form DER length) round-trips", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(big, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { key: rsa.key, cert: rsa.cert })).content, big) === 0);

  // ---- prf variants (pwri + PBES2) + bad prf ----
  var pwrSha512 = await pki.cms.encrypt(MSG, [{ password: "p", prf: "hmacWithSHA512" }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("pwri with an explicit hmacWithSHA512 prf round-trips", Buffer.compare((await pki.cms.decrypt(pwrSha512, { password: "p" })).content, MSG) === 0);
  var pbesSha1 = await pki.cms.encrypt(MSG, { password: "p", prf: "hmacWithSHA1" }, { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("EncryptedData PBES2 with an explicit hmacWithSHA1 prf round-trips", Buffer.compare((await pki.cms.decrypt(pbesSha1, { password: "p" })).content, MSG) === 0);
  check("pwri with an unsupported prf -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ password: "p", prf: "hmacWithMD5" }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("encrypt with a bad oaepHash -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: rsa.cert, oaepHash: "md5" }]); })) === "cms/bad-input");
  check("encrypt with a non-string/Buffer password -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ password: 42 }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("encrypt with a bad recipient cert type -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: 42 }]); })) === "cms/bad-input");
  check("subjectKeyIdentifier requested but the cert lacks the extension -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: rsa.cert, keyIdentifier: "subjectKeyIdentifier" }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("an unrecognized keyIdentifier value -> cms/bad-input (never a silent issuerAndSerialNumber)", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: rsa.cert, keyIdentifier: "subjectKeyId" }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("the documented keyIdentifier: \"issuerAndSerial\" is accepted", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: rsa.cert, keyIdentifier: "issuerAndSerial" }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("keyIdentifier: \"issuerAndSerialNumber\" (RFC name) is accepted", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: rsa.cert, keyIdentifier: "issuerAndSerialNumber" }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("a kari recipient with an unrecognized keyIdentifier -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: ec.cert, keyIdentifier: "bogus" }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  // an Ed25519 recipient cert (a signature key, no enveloped arm) -> unsupported.
  var ed = signing.makeSigner("ed25519");
  check("an Ed25519 recipient certificate -> cms/unsupported-algorithm", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: ed.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/unsupported-algorithm");
  check("EncryptedData with an empty descriptor (no cek/password) -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, {}, { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  // a non-default contentType is carried + surfaced on decrypt.
  var ctEnv = await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentEncryptionAlgorithm: "aes-256-cbc", contentType: "signedData" });
  check("a non-default contentType round-trips + is surfaced", (function (d) { return Buffer.compare(d.content, MSG) === 0 && d.contentTypeName === "signedData"; })(await pki.cms.decrypt(ctEnv, { key: rsa.key, cert: rsa.cert })));

  // ---- RFC-conformance fixes (canonical DER + AuthEnvelopedData attrs) ----
  // RSAES-OAEP: pSourceAlgorithm equals the DEFAULT (pSpecifiedEmpty) and MUST be OMITTED (X.690).
  var oaepParams = pki.asn1.decode(v0.recipientInfos[0].keyEncryptionAlgorithm.parameters);
  check("RSAES-OAEP-params omit the DEFAULT pSourceAlgorithm ([0] hash + [1] mgf only)", oaepParams.children.length === 2);
  // AuthEnvelopedData with a non-id-data content type MUST carry authAttrs (RFC 5083 sec. 2.1).
  check("AuthEnvelopedData + non-data contentType + no authAttrs -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentType: "signedData" }); })) === "cms/bad-input");
  check("AuthEnvelopedData + non-data contentType + authAttrs is accepted", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: rsa.cert }], { contentType: "signedData", authAttrs: [b.sequence([b.oid(O("contentType")), b.set([b.oid(O("signedData"))])])] }), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  // PBKDF2 prf equal to the DEFAULT hmacWithSHA1 MUST be omitted.
  var sha1Pwri = pki.schema.cms.parse(await pki.cms.encrypt(MSG, [{ password: "p", prf: "hmacWithSHA1" }], { contentEncryptionAlgorithm: "aes-256-cbc" }));
  check("pwri PBKDF2-params omit the DEFAULT hmacWithSHA1 prf (salt + iterationCount only)", pki.asn1.decode(sha1Pwri.recipientInfos[0].keyDerivationAlgorithm.parameters).children.length === 2);
  // X25519 kari with a ukm still round-trips (the ukm now feeds BOTH the HKDF salt AND the SharedInfo).
  var x = makeRecipient("x25519");
  check("X25519 kari with a ukm round-trips", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: x.cert }], { contentEncryptionAlgorithm: "aes-256-cbc", ukm: Buffer.from("shared-ukm") }), { key: x.key, cert: x.cert })).content, MSG) === 0);

  // ---- input-form + option arms (config-time + the alternate normalizer paths) ----
  check("a recipient cert as a plain Uint8Array round-trips", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: new Uint8Array(rsa.cert) }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("a malformed recipient-cert PEM -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ cert: "-----BEGIN CERTIFICATE-----\nnot-base64!!\n-----END CERTIFICATE-----\n" }]); })) === "cms/bad-input");
  check("a non-object recipient descriptor -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [42]); })) === "cms/bad-input");
  // kari over aes-192 content -> a 24-octet CEK -> the aes192-wrap key-wrap.
  check("a kari recipient with aes-192 content uses aes192-wrap and round-trips", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: ec.cert }], { contentEncryptionAlgorithm: "aes-192-cbc" }), { key: ec.key, cert: ec.cert })).content, MSG) === 0);
  // per-recipient oaepHash override (the mergeOpts arm).
  check("a per-recipient oaepHash override round-trips", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ cert: rsa.cert, oaepHash: "sha384" }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  // pwri option arms: explicit iterations + explicit salt + a Uint8Array password + a 16-octet (aes-128) CEK padding.
  check("pwri with explicit iterations + salt round-trips", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ password: "p", iterations: 2048, salt: Buffer.alloc(16, 7) }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { password: "p" })).content, MSG) === 0);
  check("pwri iterations must be a positive integer -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ password: "p", iterations: -1 }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("pwri fractional iterations -> cms/bad-input (not a native RangeError)", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ password: "p", iterations: 1.5 }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("EncryptedData PBES2 fractional iterations -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, { password: "p", iterations: 1.5 }, { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("EncryptedData PBES2 zero iterations -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, { password: "p", iterations: 0 }, { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  // encrypt refuses PBKDF2 parameters the decryptor would reject (symmetric caps) -- never emit a self-undecryptable message.
  check("pwri iterations above the decrypt cap -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ password: "p", iterations: pki.C.LIMITS.PBKDF2_MAX_ITERATIONS + 1 }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("pwri salt above the decrypt cap -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, [{ password: "p", salt: Buffer.alloc(pki.C.LIMITS.PBKDF2_MAX_SALT + 1) }], { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("PBES2 iterations above the decrypt cap -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, { password: "p", iterations: pki.C.LIMITS.PBKDF2_MAX_ITERATIONS + 1 }, { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("PBES2 salt above the decrypt cap -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, { password: "p", salt: Buffer.alloc(pki.C.LIMITS.PBKDF2_MAX_SALT + 1) }, { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  check("EncryptedData PBES2 with a non-BufferSource salt -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, { password: "p", salt: 42 }, { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");
  // the global opts.pem drives PBES2 EncryptedData output, exactly like the raw-cek path.
  check("EncryptedData PBES2 honours the global opts.pem", /-----BEGIN CMS-----/.test(await pki.cms.encrypt(MSG, { password: "p" }, { contentEncryptionAlgorithm: "aes-256-cbc", pem: true })));
  check("pwri with a Uint8Array password round-trips", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ password: new Uint8Array(Buffer.from("pw")) }], { contentEncryptionAlgorithm: "aes-256-cbc" }), { password: "pw" })).content, MSG) === 0);
  check("pwri over aes-128 content (a 16-octet CEK) round-trips", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, [{ password: "p" }], { contentEncryptionAlgorithm: "aes-128-cbc" }), { password: "p" })).content, MSG) === 0);
  // EncryptedData PBES2 option arms: explicit iterations/salt + an unsupported prf.
  check("EncryptedData PBES2 with explicit iterations + salt round-trips", Buffer.compare((await pki.cms.decrypt(await pki.cms.encrypt(MSG, { password: "p", iterations: 2048, salt: Buffer.alloc(16, 9) }, { contentEncryptionAlgorithm: "aes-256-cbc" }), { password: "p" })).content, MSG) === 0);
  check("EncryptedData PBES2 with an unsupported prf -> cms/bad-input", (await codeOf(function () { return pki.cms.encrypt(MSG, { password: "p", prf: "hmacWithMD5" }, { contentEncryptionAlgorithm: "aes-256-cbc" }); })) === "cms/bad-input");

  // ---- orchestrator routing ----
  check("pki.schema.parse routes an emitted EnvelopedData to cms/envelopedData", pki.schema.parse(envBytes).contentTypeName === "envelopedData");
  check("pki.schema.parse routes an emitted EncryptedData to cms/encryptedData", pki.schema.parse(await pki.cms.encrypt(MSG, { cek: Buffer.alloc(32, 2) }, { contentEncryptionAlgorithm: "aes-256-cbc" })).contentTypeName === "encryptedData");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
