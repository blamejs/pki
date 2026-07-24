// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for pki.pkcs12.open -- the PKCS#12 (.p12/.pfx) reading + decryption side (RFC 7292 sec.
// 5.1, RFC 9579, RFC 8018). Every vector drives the shipped consumer and asserts the recovered bytes against
// the originals, the MAC-verify-BEFORE-decrypt ordering, the fail-closed policies (MAC-less, public-key,
// legacy PBE), and the uniform decrypt verdict. Cross-implementation open (OpenSSL/NSS-produced stores) lives
// in test/integration/pkcs12-build-openssl-interop.test.js.
//
// MAC-before-decrypt (RFC 7292 sec. 5.1): a store whose password MAC fails returns NOTHING -- the wrong-password
// verdict is the MAC gate (pkcs12/mac-mismatch), never a per-bag decrypt error. The PBES2 bag password is UTF-8
// (the pinned interop convention), the classic MAC password BMPString+NULL.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;

async function codeOf(promise) { try { await promise; return null; } catch (e) { return e && e.code; } }

var SIGNER = null;
function signer() { if (!SIGNER) SIGNER = makeSigner("rsa"); return SIGNER; }

// ---- #1 / #4 / #5 / #13 build -> open round-trip (classic HMAC) -------------
async function testClassicRoundTrip() {
  var s = signer();
  var crl = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"), revoked: [] }, { cert: pki.schema.x509.parse(s.cert), key: s.key });
  var lki = Buffer.from([0xaa, 0xbb]);
  var p12 = await pki.pkcs12.build({ safeContents: [
    { encrypt: { password: "1234" }, bags: [{ type: "cert", cert: s.cert, friendlyName: "my cert", localKeyId: lki }] },   // #4 encrypted cert safe
    { bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234" }, localKeyId: lki }, { type: "crl", crl: crl }] } ] },
    { password: "1234", mac: { algorithm: "hmac", hash: "sha256" } });
  var o = await pki.pkcs12.open(p12, "1234");
  check("#1 macVerified is true", o.macVerified === true);
  check("#1 integrityMode is password", o.integrityMode === "password");
  check("#1 recovers one key + one cert + one crl", o.keys.length === 1 && o.certs.length === 1 && o.crls.length === 1);
  check("#5 shrouded key decrypts to the exact PrivateKeyInfo DER", Buffer.compare(o.keys[0].pkcs8, s.key) === 0);
  check("#5 the recovered key re-parses as PKCS#8", pki.schema.pkcs8.parse(o.keys[0].pkcs8) != null);
  check("#1 keys[0].encrypted is true", o.keys[0].encrypted === true);
  check("#4 the cert is recovered from the encrypted safe", Buffer.compare(o.certs[0].cert, s.cert) === 0);
  check("#1 the crl is recovered", Buffer.compare(o.crls[0].crl, crl) === 0);
  check("#13 friendlyName round-trips (BMPString)", o.certs[0].friendlyName === "my cert");
  check("#13 localKeyId pairs the key and cert", Buffer.isBuffer(o.keys[0].localKeyId) && o.keys[0].localKeyId.equals(o.certs[0].localKeyId));
}

// ---- #2 PBMAC1 round-trip; a plaintext keyBag surfaces raw DER -------------
async function testPbmac1AndPlainKey() {
  var s = signer();
  var pb = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }, { type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] },
    { password: "1234", mac: { algorithm: "pbmac1", hash: "sha256" } });
  var ob = await pki.pkcs12.open(pb, "1234");
  check("#2 PBMAC1 store opens (MAC gate verified) + key round-trips", ob.macVerified === true && Buffer.compare(ob.keys[0].pkcs8, s.key) === 0);
  // a plaintext keyBag returns the raw PrivateKeyInfo DER with encrypted:false.
  var pk = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "key", key: s.key }] }] }, { password: "1234" });
  var ok = await pki.pkcs12.open(pk, "1234");
  check("a plaintext keyBag surfaces the raw PrivateKeyInfo DER (encrypted:false)", ok.keys[0].encrypted === false && Buffer.compare(ok.keys[0].pkcs8, s.key) === 0);
}

// ---- #3 wrong password fails at the MAC gate before any decrypt -----------
async function testWrongPassword() {
  var s = signer();
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] }, { password: "1234" });
  check("#3 wrong password -> pkcs12/mac-mismatch (MAC gate, no partial bundle)", (await codeOf(pki.pkcs12.open(p12, "wrong"))) === "pkcs12/mac-mismatch");
}

// ---- #6 post-MAC bag decrypt failure -> uniform pkcs12/decrypt-failed ------
async function testUniformDecryptFail() {
  var s = signer();
  // the shrouded key is encrypted under a DIFFERENT password than the MAC -> the MAC (macpw) verifies, then
  // the bag decrypt with macpw fails (the bag is under bagpw): a UNIFORM pkcs12/decrypt-failed, no oracle.
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "bagpw" } }] }] }, { password: "macpw" });
  check("#6 a post-MAC shrouded-key decrypt failure -> uniform pkcs12/decrypt-failed", (await codeOf(pki.pkcs12.open(p12, "macpw"))) === "pkcs12/decrypt-failed");
  // an encrypted SAFE under a different password than the MAC: the walkSafeContents re-parse failure is
  // collapsed to the SAME uniform verdict (no distinguishable structural code -- no padding oracle).
  var p12safe = await pki.pkcs12.build({ safeContents: [{ encrypt: { password: "safepw" }, bags: [{ type: "cert", cert: s.cert }] }] }, { password: "macpw" });
  check("#6 an encrypted safe under a differing password -> uniform pkcs12/decrypt-failed", (await codeOf(pki.pkcs12.open(p12safe, "macpw"))) === "pkcs12/decrypt-failed");
}

// ---- #7 MAC-less store: refuse by default, opt-in allowed ------------------
async function testMacLessPolicy() {
  var s = signer();
  var pn = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { mac: false });
  check("#7 a MAC-less store -> pkcs12/no-integrity by default", (await codeOf(pki.pkcs12.open(pn, "1234"))) === "pkcs12/no-integrity");
  var on = await pki.pkcs12.open(pn, "1234", { allowUnauthenticated: true });
  check("#7 allowUnauthenticated opens it with macVerified:false", on.macVerified === false && on.integrityMode === "none" && on.certs.length === 1);
}

// ---- #10 attacker-controlled bag KDF iteration cap ------------------------
async function testBagDosCap() {
  var s = signer();
  // MAC iterations 500 (cheap), the PBES2 bag at 4096; open with maxIterations 1000 -> the MAC passes the cap
  // but the bag KDF exceeds it, refused BEFORE deriving.
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234", iterations: 4096 } }] }] },
    { password: "1234", mac: { algorithm: "hmac", hash: "sha256", iterations: 500 } });
  check("#10 a bag KDF over opts.maxIterations -> pkcs12/iteration-limit", (await codeOf(pki.pkcs12.open(p12, "1234", { maxIterations: 1000 }))) === "pkcs12/iteration-limit");
  check("#10 a non-integer maxIterations -> pkcs12/bad-input", (await codeOf(pki.pkcs12.open(p12, "1234", { maxIterations: NaN }))) === "pkcs12/bad-input");
}

// ---- #14 keys:"crypto" imports; ambiguous RSA/EC fails closed -------------
async function testKeysCrypto() {
  var ed = await pki.key.generate("Ed25519");
  var pe = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: await pki.key.export(ed.privateKey), encrypt: { password: "1234" } }] }] }, { password: "1234" });
  var oe = await pki.pkcs12.open(pe, "1234", { keys: "crypto" });
  check("#14 keys:crypto imports an unambiguous key to a CryptoKey", oe.keys[0].key && oe.keys[0].key.type === "private" && oe.keys[0].key.algorithm.name === "Ed25519");
  // an RSA key without importAlgorithm fails closed (the key.import ambiguity).
  var s = signer();
  var pr = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] }, { password: "1234" });
  check("#14 keys:crypto with an ambiguous RSA key + no importAlgorithm -> fail closed", typeof (await codeOf(pki.pkcs12.open(pr, "1234", { keys: "crypto" }))) === "string");
  var or = await pki.pkcs12.open(pr, "1234", { keys: "crypto", importAlgorithm: { name: "RSA-PSS", hash: "SHA-256" } });
  check("#14 keys:crypto with importAlgorithm imports the RSA key", or.keys[0].key.type === "private");
}

// ---- #15 nested safeContentsBag recursion + input polymorphism ------------
async function testNestedAndInputs() {
  var s = signer();
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "safeContents", nested: [{ type: "cert", cert: s.cert }, { type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] }] }, { password: "1234" });
  var o = await pki.pkcs12.open(p12, "1234");
  check("#15 a nested safeContentsBag's bags are recovered", o.certs.length === 1 && o.keys.length === 1 && Buffer.compare(o.certs[0].cert, s.cert) === 0);
  // a secret bag round-trips through open.
  var ps = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "secret", secretTypeId: "data", secretValue: pki.asn1.build.octetString(Buffer.from("shh")) }] }] }, { password: "1234" });
  var os = await pki.pkcs12.open(ps, "1234");
  check("a secret bag is recovered by open", os.secrets.length === 1 && os.secrets[0].secretTypeName === "data" && Buffer.isBuffer(os.secrets[0].secretValue));
  // open accepts DER, PEM, and a pre-parsed result.
  var pem = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234", pem: true });
  check("open accepts a PEM string", (await pki.pkcs12.open(pem, "1234")).certs.length === 1);
  check("open accepts a parse-result object", (await pki.pkcs12.open(pki.schema.pkcs12.parse(await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234" })), "1234")).certs.length === 1);
}

async function main() {
  await testClassicRoundTrip();
  await testPbmac1AndPlainKey();
  await testWrongPassword();
  await testUniformDecryptFail();
  await testMacLessPolicy();
  await testBagDosCap();
  await testKeysCrypto();
  await testNestedAndInputs();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
