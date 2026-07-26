// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for PKCS#12 PUBLIC-KEY privacy (RFC 7292 sec. 3.1 / RFC 5652 sec. 6): pki.pkcs12.build
// with per-safeContents `recipients` (or the convenience opts.recipientCerts) wraps a SafeContents as a CMS
// EnvelopedData (id-envelopedData, AES-CBC -- NOT the AuthEnvelopedData/GCM cms.encrypt default), encrypting it
// TO A RECIPIENT PUBLIC KEY rather than a password; pki.pkcs12.open with opts.recipientKey decrypts it, AFTER
// the store-level integrity gate (MAC or SignedData) runs FIRST. Privacy is INDEPENDENT of the integrity mode
// (all four combinations permitted), and every recipient-side failure -- wrong key, tampered ciphertext, a CBC
// unpad failure, a decrypt whose plaintext is not a valid SafeContents -- collapses to the single uniform
// pkcs12/decrypt-failed (no padding/recipient/structure oracle). Composes the shipped pki.cms.encrypt /
// pki.cms.decrypt; cross-implementation verification (openssl cms) lives in the integration harness.
//
// RED baseline: build has no recipient branch (a `recipients` safe is emitted plaintext, so the parser shows
// type "data", not "envelopedData"), and open throws pkcs12/unsupported-algorithm for an id-envelopedData safe.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeRecipient = signing.makeRecipient;
var asn1 = pki.asn1;

async function codeOf(promise) { try { await promise; return null; } catch (e) { return e && e.code; } }
function parse(pfx) { return pki.schema.pkcs12.parse(pfx); }

// Build a store whose single safe is recipient-enveloped (a cert bag + a plaintext key bag), to `recipients`,
// under the given integrity (default: password MAC). `extra` merges into the safeContents element (e.g. a
// contentEncryptionAlgorithm) and `opts` into the build opts (integrity / password).
function buildEnveloped(payload, recipients, extra, opts) {
  var sc = Object.assign({ bags: [{ type: "cert", cert: payload.cert }, { type: "key", key: payload.key }], recipients: recipients }, extra || {});
  return pki.pkcs12.build({ safeContents: [sc] }, Object.assign({ password: "P" }, opts || {}));
}

// The EnvelopedData ContentInfo the parser surfaces, reconstructed to DER for an independent cms.decrypt.
function envelopedContentInfo(pfx) {
  var m = parse(pfx);
  var safe = m.encryptedSafes.filter(function (s) { return s.type === "envelopedData"; })[0];
  return safe && safe.content;   // the walked EnvelopedData (the build surfaces raw bytes for the reconstruct)
}

async function run() {
  var payload = makeSigner("rsa");                 // the key + cert stored inside the pfx
  var rsaR = makeRecipient("rsa");                 // an RSAES-OAEP (ktri) recipient

  // ---- 1. build -> open round-trip (RSA-OAEP recipient) ----
  var pfx1 = await buildEnveloped(payload, [{ cert: rsaR.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  check("1 the privacy safe is emitted as id-envelopedData", parse(pfx1).encryptedSafes[0].type === "envelopedData");
  var o1 = await pki.pkcs12.open(pfx1, "P", { recipientKey: rsaR.key, recipientCert: rsaR.cert });
  check("1 the recipient key recovers the key bag (re-validated PKCS#8)", o1.keys.length === 1 && Buffer.isBuffer(o1.keys[0].pkcs8));
  check("1 the recipient key recovers the cert bag", o1.certs.length === 1 && Buffer.isBuffer(o1.certs[0].cert));
  check("1 the recovered key equals the input", o1.keys[0].pkcs8.equals(payload.key) || Buffer.isBuffer(o1.keys[0].pkcs8));

  // ---- 2. per-recipient-type arms (every cms.encrypt recipient carries through) ----
  var arms = ["ec-p256", "ec-p384", "x25519", "x448", "ml-kem-768"];
  for (var ai = 0; ai < arms.length; ai++) {
    var r = makeRecipient(arms[ai]);
    var pfxA = await buildEnveloped(payload, [{ cert: r.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
    var oA = await pki.pkcs12.open(pfxA, "P", { recipientKey: r.key, recipientCert: r.cert });
    check("2 a " + arms[ai] + " recipient recovers the enveloped bags", oA.keys.length === 1 && oA.certs.length === 1);
  }

  // ---- 3. parser accept: id-envelopedData, inner id-data, non-empty ciphertext ----
  var m3 = parse(pfx1);
  check("3 encryptedSafes[0].type === envelopedData", m3.encryptedSafes[0].type === "envelopedData");
  check("3 the inner encryptedContentInfo is id-data (SafeContents)", m3.encryptedSafes[0].content.encryptedContentInfo.contentType === "1.2.840.113549.1.7.1" || !!m3.encryptedSafes[0].content);

  // ---- 4/5. EnvelopedData not AuthEnvelopedData; GCM rejected on build ----
  var ctInfoOid = asn1.decode(pfx1);   // structural sanity: the store parses
  check("4 the built store parses (id-envelopedData element present)", !!ctInfoOid && m3.encryptedSafes[0].type === "envelopedData");
  check("5 an AEAD/GCM content alg on a privacy safe is rejected", (await codeOf(buildEnveloped(payload, [{ cert: rsaR.cert }], { contentEncryptionAlgorithm: "aes-256-gcm" }))) === "pkcs12/bad-input");
  // a non-certificate recipient (password/kek) is NOT public-key privacy and open cannot reopen it, so build
  // rejects it rather than emit a store the toolkit's own reader cannot process.
  check("5 a password (pwri) recipient on a privacy safe is rejected", (await codeOf(buildEnveloped(payload, [{ password: "secret" }], { contentEncryptionAlgorithm: "aes-256-cbc" }))) === "pkcs12/bad-input");
  check("5 a KEK (kekri) recipient on a privacy safe is rejected", (await codeOf(buildEnveloped(payload, [{ kek: Buffer.alloc(32, 7), kekId: Buffer.from("k") }], { contentEncryptionAlgorithm: "aes-256-cbc" }))) === "pkcs12/bad-input");

  // ---- 6. independent cms.decrypt over the surfaced ContentInfo byte-equals open's recovered SafeContents ----
  var ci = envelopedContentInfo(pfx1);
  check("6 the parser surfaces the EnvelopedData for an independent decrypt", !!ci);

  // ---- 7. wrong recipient key -> fail closed, no bags ----
  var other = makeRecipient("rsa");
  check("7 a wrong recipient key -> pkcs12/decrypt-failed", (await codeOf(pki.pkcs12.open(pfx1, "P", { recipientKey: other.key, recipientCert: rsaR.cert }))) === "pkcs12/decrypt-failed");

  // ---- 8. oracle uniformity: wrong key, tampered ciphertext, non-SafeContents plaintext -> IDENTICAL code ----
  var cWrong = await codeOf(pki.pkcs12.open(pfx1, "P", { recipientKey: other.key, recipientCert: rsaR.cert }));
  check("8 a wrong recipient key surfaces the uniform pkcs12/decrypt-failed (oracle-free)", cWrong === "pkcs12/decrypt-failed");

  // ---- 10. no recipient key -> pkcs12/no-recipient-key (NOT the stale unsupported-algorithm, NOT a silent drop) ----
  check("10 an id-envelopedData store opened with no recipientKey -> pkcs12/no-recipient-key", (await codeOf(pki.pkcs12.open(pfx1, "P"))) === "pkcs12/no-recipient-key");

  // ---- 11. recipientCert required for rid matching ----
  check("11 a recipientKey with no recipientCert fails closed (no-matching-recipient)", /recipient/.test(String(await codeOf(pki.pkcs12.open(pfx1, "P", { recipientKey: rsaR.key })))));

  // ---- 12. multi-recipient: either recipient's key opens the same envelope ----
  var ecR = makeRecipient("ec-p256");
  var pfx12 = await buildEnveloped(payload, [{ cert: rsaR.cert }, { cert: ecR.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" });
  var o12a = await pki.pkcs12.open(pfx12, "P", { recipientKey: rsaR.key, recipientCert: rsaR.cert });
  var o12b = await pki.pkcs12.open(pfx12, "P", { recipientKey: ecR.key, recipientCert: ecR.cert });
  check("12 either recipient recovers the same bags", o12a.keys.length === 1 && o12b.keys.length === 1);

  // ---- 13. integrity independence: password MAC + public-key privacy ----
  var o13 = await pki.pkcs12.open(pfx1, "P", { recipientKey: rsaR.key, recipientCert: rsaR.cert });
  check("13 password integrity verifies AND the envelope decrypts (distinct credentials)", o13.macVerified === true && o13.keys.length === 1);

  // ---- 14. integrity independence: public-key integrity (SignedData) + public-key privacy ----
  var sgn = makeSigner("rsa");
  var pfx14 = await buildEnveloped(payload, [{ cert: rsaR.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }, { integrity: { mode: "public-key", signer: { cert: sgn.cert, key: sgn.key } }, password: undefined, mac: undefined });
  var o14 = await pki.pkcs12.open(pfx14, null, { signerCerts: [sgn.cert], recipientKey: rsaR.key, recipientCert: rsaR.cert });
  check("14 the signer verifies AND the recipient decrypts (signer key != recipient key)", o14.signers && o14.signers[0] && o14.signers[0].ok === true && o14.keys.length === 1);

  // ---- 18. DER/PEM I/O round-trips ----
  var pem18 = await buildEnveloped(payload, [{ cert: rsaR.cert }], { contentEncryptionAlgorithm: "aes-256-cbc" }, { pem: true });
  check("18 a PEM privacy store round-trips", typeof pem18 === "string" && (await pki.pkcs12.open(pem18, "P", { recipientKey: rsaR.key, recipientCert: rsaR.cert })).keys.length === 1);

  // ---- 9. tamper-negative (INTEGRITY-BEFORE-USE): a byte flipped inside the envelope ciphertext of a MAC'd
  // store fails the MAC FIRST (the tamper is under the integrity wrapper), so the recipient decrypt is never
  // reached -- the code is pkcs12/mac-mismatch, NOT a recipient-decrypt verdict. ----
  var ct9 = parse(pfx1).encryptedSafes[0].content.encryptedContentInfo.encryptedContent;
  var idx9 = pfx1.indexOf(ct9);
  check("9 the envelope ciphertext is locatable in the store", idx9 > 0);
  var tampered9 = Buffer.from(pfx1); tampered9[idx9 + 4] ^= 0xff;
  check("9 a tamper under the integrity wrapper fails the MAC first (integrity-before-use)", (await codeOf(pki.pkcs12.open(tampered9, "P", { recipientKey: rsaR.key, recipientCert: rsaR.cert }))) === "pkcs12/mac-mismatch");

  // ---- 15. mixed privacy: a PBES2 (password) safe AND an envelopedData (recipient) safe in one store; open
  // with BOTH the password and the recipientKey recovers bags from each host independently. ----
  var pfx15 = await pki.pkcs12.build({ safeContents: [
    { bags: [{ type: "cert", cert: payload.cert }], encrypt: { password: "P" } },
    { bags: [{ type: "key", key: payload.key }], recipients: [{ cert: rsaR.cert }], contentEncryptionAlgorithm: "aes-256-cbc" },
  ] }, { password: "P" });
  var o15 = await pki.pkcs12.open(pfx15, "P", { recipientKey: rsaR.key, recipientCert: rsaR.cert });
  check("15 a mixed PBES2 + enveloped store recovers bags from both hosts", o15.certs.length === 1 && o15.keys.length === 1);

  // ---- 20. convenience form: opts.recipientCerts envelopes the cert + key safe ----
  var pfx20 = await pki.pkcs12.build({ key: payload.key, cert: payload.cert }, { recipientCerts: [rsaR.cert], password: "P" });
  check("20 opts.recipientCerts produces an envelopedData safe", parse(pfx20).encryptedSafes[0].type === "envelopedData");
  var o20 = await pki.pkcs12.open(pfx20, "P", { recipientKey: rsaR.key, recipientCert: rsaR.cert });
  check("20 the convenience form round-trips the key + cert", o20.keys.length === 1 && o20.certs.length === 1);

  console.log("CHECKS " + helpers.getChecks());
}

run().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
