// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for PKCS#12 public-key integrity (RFC 7292 sec. 4): pki.pkcs12.build with
// opts.integrity { mode: "public-key", signer } wraps the AuthenticatedSafe as an id-signedData authSafe
// (a CMS SignedData over the exact serialized AuthenticatedSafe, NO MacData), and pki.pkcs12.open verifies
// that SignedData signature FIRST (the integrity gate, exactly as the MAC is for password mode) BEFORE
// decrypting any bag. Privacy (PBES2 bag encryption) is INDEPENDENT of integrity, so the caller password
// still decrypts the bags; the signer is surfaced as a per-signer verdict, never trust-chained (the caller's
// pki.path.validate step). Cross-implementation verification (openssl cms over our authSafe) lives in
// test/integration/pkcs12-public-key-openssl-interop.test.js.
//
// RED baseline: build throws pkcs12/unsupported-algorithm and open throws pkcs12/bad-integrity-mode for a
// public-key store until the signedData mode lands.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
async function codeOf(promise) { try { await promise; return null; } catch (e) { return e && e.code; } }

var SIGNER = null;
function signer() { if (!SIGNER) SIGNER = makeSigner("rsa"); return SIGNER; }

// Build a public-key-integrity store: a cert bag + a PBES2 shrouded key bag, signed by `sgn`.
async function buildStore(sgn, opts) {
  opts = opts || {};
  var s = signer();
  var bagCert = opts.bagCert || s.cert;
  var integrity = { mode: "public-key" };
  if (opts.signers) integrity.signers = opts.signers; else integrity.signer = sgn || { cert: s.cert, key: s.key };
  if (opts.certificates === false) integrity.certificates = false;
  return pki.pkcs12.build(
    { safeContents: [{ bags: [{ type: "cert", cert: bagCert }, { type: "shroudedKey", key: s.key, encrypt: { password: opts.password || "P" } }] }] },
    Object.assign({ integrity: integrity, password: opts.password || "P" }, opts.buildOpts || {}));
}
function flipRegion(der, region) {
  var i = der.indexOf(region);
  if (i < 0) throw new Error("flipRegion: region not found");
  var out = Buffer.from(der); out[i + region.length - 1] ^= 0xff; return out;
}

// ---- 1 / 5 build -> open round-trip -----------------------------------------
async function testRoundTrip() {
  var pfx = await buildStore();
  var o = await pki.pkcs12.open(pfx, "P");
  check("#1 integrityMode is public-key", o.integrityMode === "public-key");
  check("#1 macVerified is false (integrity is the signature, not a MAC)", o.macVerified === false);
  check("#1 the signer verdict is surfaced ok", o.signers && o.signers.length === 1 && o.signers[0].ok === true);
  check("#1 the signer cert is surfaced", Buffer.isBuffer(o.signers[0].cert));
  check("#1 the shrouded key re-validates as PKCS#8", o.keys.length === 1 && pki.schema.pkcs8.parse(o.keys[0].pkcs8) != null);
  check("#1 the cert bag is recovered", o.certs.length === 1);
  // #5 no-MacData-required: open SUCCEEDS without allowUnauthenticated + never throws pkcs12/no-integrity.
  check("#5 a public-key store opens without opts.allowUnauthenticated", (await pki.pkcs12.open(pfx, "P")).integrityMode === "public-key");
}

// ---- 2 build -> schema.parse (no MacData, authSafeSigned) --------------------
async function testParse() {
  var pfx = await buildStore();
  var m = pki.schema.pkcs12.parse(pfx);
  check("#2 parse integrityMode public-key", m.integrityMode === "public-key");
  check("#2 authSafeSigned non-null with >=1 SignerInfo", m.authSafeSigned != null && m.authSafeSigned.signerInfos.length >= 1);
  check("#2 mac + macedBytes are null (no MacData)", m.mac === null && m.macedBytes === null);
  check("#2 the top PFX SEQUENCE has exactly 2 children (version + authSafe, NO MacData)", pki.asn1.decode(pfx).children.length === 2);
}

// ---- 3 independent cms.verify -----------------------------------------------
async function testIndependentVerify() {
  var pfx = await buildStore();
  var res = await pki.cms.verify(pki.schema.pkcs12.parse(pfx).authSafeSigned);
  check("#3 the SignedData authSafe verifies through the separate cms verb", res.valid === true);
}

// ---- 4 / 11 tamper-negative (the integrity gate) ----------------------------
async function testTamper() {
  var bag = makeSigner("ec-p256", { serial: 0x5a1, cn: "Bag Cert" });   // distinct from the RSA signer
  var pfx = await buildStore(null, { bagCert: bag.cert });
  // flip a byte inside the eContent (the bag cert DER) so the pfx still parses but the signature fails.
  var tampered = flipRegion(pfx, bag.cert);
  check("#4 a tampered authSafe -> open throws pkcs12/signature-invalid", (await codeOf(pki.pkcs12.open(tampered, "P"))) === "pkcs12/signature-invalid");
  check("#4 and the independent cms.verify reports invalid", (await pki.cms.verify(pki.schema.pkcs12.parse(tampered).authSafeSigned)).valid === false);
}

// ---- 6 signer surfaced, not trust-chained -----------------------------------
async function testSignerNotChained() {
  // the signer cert is a minimal self-issued cert with a dummy signature (un-anchored); open still returns
  // ok:true for a valid SignedData signature -- integrity, not trust. Trust is the caller's path.validate.
  var pfx = await buildStore();
  var o = await pki.pkcs12.open(pfx, "P");
  check("#6 open returns ok:true for a valid signature from an un-anchored signer (integrity != trust)", o.signers[0].ok === true);
}

// ---- 7 bag password independent of the integrity keypair --------------------
async function testBagPasswordIndependent() {
  var pfx = await buildStore();   // signer key != the bag password "P"
  check("#7 the bag password recovers the bags", (await pki.pkcs12.open(pfx, "P")).keys.length === 1);
  // a wrong BAG password with a VALID signature -> uniform pkcs12/decrypt-failed (no MAC to catch it first).
  check("#7 a wrong bag password -> pkcs12/decrypt-failed (NOT pkcs12/mac-mismatch)", (await codeOf(pki.pkcs12.open(pfx, "wrong"))) === "pkcs12/decrypt-failed");
}

// ---- 8 verifyMac still rejects a public-key store ---------------------------
async function testVerifyMacRejects() {
  var pfx = await buildStore();
  check("#8 verifyMac still rejects a public-key store -> pkcs12/bad-input", (await codeOf(pki.pkcs12.verifyMac(pfx, "P"))) === "pkcs12/bad-input");
}

// ---- 9 build rejects mac + public-key / no-signer ---------------------------
async function testBuildConfigRejects() {
  var s = signer();
  check("#9 mac + public-key integrity -> pkcs12/bad-integrity-mode", (await codeOf(buildStore(null, { buildOpts: { mac: { algorithm: "hmac" } } }))) === "pkcs12/bad-integrity-mode");
  check("#9 public-key integrity with no signer -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { integrity: { mode: "public-key" }, password: "P" }))) === "pkcs12/bad-input");
}

// ---- 10 PQC signer arm ------------------------------------------------------
async function testPqcSigner() {
  var ml = makeSigner("ml-dsa-65");
  var pfx = await buildStore({ cert: ml.cert, key: ml.key });
  check("#10 an ML-DSA-65 signer round-trips (every cms.sign algorithm ships)", (await pki.pkcs12.open(pfx, "P")).signers[0].ok === true);
}

// ---- 11 multi-signer (all must verify) --------------------------------------
async function testMultiSigner() {
  var s = signer(), ec = makeSigner("ec-p256", { serial: 0x9c, cn: "Second Signer" });
  var pfx = await buildStore(null, { signers: [{ cert: s.cert, key: s.key }, { cert: ec.cert, key: ec.key }] });
  var o = await pki.pkcs12.open(pfx, "P");
  check("#11 both signers verify (all-must-verify)", o.signers.length === 2 && o.signers.every(function (x) { return x.ok === true; }));
}

// ---- 12 cert-less store + opts.signerCerts ----------------------------------
async function testCertLess() {
  var s = signer();
  var pfx = await buildStore(null, { certificates: false });
  check("#12 a cert-less store without opts.signerCerts fails closed", (await codeOf(pki.pkcs12.open(pfx, "P"))) != null);
  var o = await pki.pkcs12.open(pfx, "P", { signerCerts: [s.cert] });
  check("#12 with opts.signerCerts the signature verifies", o.signers[0].ok === true);
}

// ---- 13 PBES2 privacy safe + shrouded key both decrypt ----------------------
async function testEncryptedPrivacySafe() {
  var s = signer();
  var pfx = await pki.pkcs12.build(
    { safeContents: [{ encrypt: { password: "P" }, bags: [{ type: "cert", cert: s.cert }] }, { bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "P" } }] }] },
    { integrity: { mode: "public-key", signer: { cert: s.cert, key: s.key } }, password: "P" });
  var o = await pki.pkcs12.open(pfx, "P");
  check("#13 an encrypted privacy safe (cert) + a shrouded key both decrypt under public-key integrity", o.certs.length === 1 && o.keys.length === 1);
}

// ---- 15 DER / PEM I/O -------------------------------------------------------
async function testIo() {
  var pfx = await buildStore(null, { buildOpts: { pem: true } });
  check("#15 build opts.pem returns a PKCS12 PEM string", typeof pfx === "string" && pfx.indexOf("-----BEGIN PKCS12-----") === 0);
  check("#15 the PEM round-trips through open", (await pki.pkcs12.open(pfx, "P")).signers[0].ok === true);
}

async function main() {
  await testRoundTrip();
  await testParse();
  await testIndependentVerify();
  await testTamper();
  await testSignerNotChained();
  await testBagPasswordIndependent();
  await testVerifyMacRejects();
  await testBuildConfigRejects();
  await testPqcSigner();
  await testMultiSigner();
  await testCertLess();
  await testEncryptedPrivacySafe();
  await testIo();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
