// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.ct.verifyLogListSignature: verify the detached signature Google publishes over the CT
 * log-list JSON (log_list.sig over log_list.json, RFC-6962-ecosystem). The scheme is empirically confirmed
 * RSASSA-PKCS1-v1.5 / SHA-256 over the RAW JSON bytes against a caller-pinned RSA SubjectPublicKeyInfo
 * (an EC P-256 arm is future-proofing). Composes the shipped verifySct RSA/EC verify path. A cryptographic
 * mismatch (wrong key, tampered json/sig, PSS padding) resolves false (a verdict); a structural / forgery
 * -defense failure (e<3 RSA, sub-2048 RSA, unsupported key, non-conformant ECDSA DER, malformed input)
 * throws a typed CtError. Fixtures are cryptographically real (self-round-trip: a generated key signs a
 * sample log-list byte-blob, and the primitive verifies it).
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");

async function code(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
async function vres(fn) { try { return await fn(); } catch (e) { return (e && e.code) || String(e); } }

// A sample log-list JSON byte blob -- any bytes work for a self-round-trip; the real format is irrelevant
// to the signature (it is over raw bytes).
var JSON_BLOB = Buffer.from(JSON.stringify({ version: "3", log_list_timestamp: "2026-07-16T00:00:00Z", operators: [{ name: "Op", logs: [], tiled_logs: [] }] }));

async function run() {
  // ==== Accept / self-round-trip (RSA + EC) ========================================================
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaSpki = rsa.publicKey.export({ format: "der", type: "spki" });
  var rsaSig = crypto.sign("sha256", JSON_BLOB, rsa.privateKey);   // RSASSA-PKCS1-v1.5 by default for an RSA key
  check("1. an RSA-2048 PKCS1-v1.5/SHA-256 self-round-trip verifies true", (await vres(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, rsaSig, rsaSpki); })) === true);
  var ec = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var ecSpki = ec.publicKey.export({ format: "der", type: "spki" });
  var ecSig = crypto.sign("sha256", JSON_BLOB, ec.privateKey);     // DER ECDSA-Sig-Value
  check("2. an EC P-256 self-round-trip verifies true (the future-proof arm)", (await vres(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, ecSig, ecSpki); })) === true);
  // a string json coerces to its UTF-8 bytes (the caller may pass the fetched text)
  check("2a. a string json verifies (coerced to its UTF-8 bytes)", (await vres(function () { return pki.ct.verifyLogListSignature(JSON_BLOB.toString("utf8"), rsaSig, rsaSpki); })) === true);

  // ==== Tamper / mismatch -> false (a verdict, not a throw) =========================================
  var flippedJson = Buffer.from(JSON_BLOB); flippedJson[10] ^= 0x01;
  check("3. one flipped JSON byte -> false", (await vres(function () { return pki.ct.verifyLogListSignature(flippedJson, rsaSig, rsaSpki); })) === false);
  check("4. a trailing newline appended to the JSON -> false (raw-bytes, no canonicalization)", (await vres(function () { return pki.ct.verifyLogListSignature(Buffer.concat([JSON_BLOB, Buffer.from("\n")]), rsaSig, rsaSpki); })) === false);
  var flippedSig = Buffer.from(rsaSig); flippedSig[flippedSig.length - 1] ^= 0x01;
  check("5. one flipped signature byte -> false", (await vres(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, flippedSig, rsaSpki); })) === false);
  var rsa2 = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  check("6. a different well-formed RSA key (wrong key) -> false (a verdict, not a throw)", (await vres(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, rsaSig, rsa2.publicKey.export({ format: "der", type: "spki" })); })) === false);

  // ==== Scheme / padding pinning (PKCS#1 v1.5, not PSS) =============================================
  var pssSig = crypto.sign("sha256", JSON_BLOB, { key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING });
  check("7. a PSS signature over the same message + key -> false (padding pinned to PKCS#1 v1.5)", (await vres(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, pssSig, rsaSpki); })) === false);

  // ==== Forgery / key-hardening defenses ============================================================
  // e = 1 RSA SPKI (a v1.5 e=1 "signature" is just the DigestInfo -> would forge true) -> ct/bad-input at _spkiAlg.
  var b = pki.asn1.build, O = function (n) { return pki.oid.byName(n); };
  var bigMod = (1n << 2047n) | 1n;   // a ~2048-bit odd positive modulus (its value is irrelevant -- the e=1 gate fires first)
  var e1Rsa = b.sequence([b.integer(bigMod), b.integer(1n)]);
  var e1Spki = b.sequence([b.sequence([b.oid(O("rsaEncryption")), b.nullValue()]), b.bitString(e1Rsa, 0)]);
  check("8. an RSA SPKI with e = 1 -> ct/bad-input (the e>=3 gate fires before verify)", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, rsaSig, e1Spki); })) === "ct/bad-input");
  var rsa1024 = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
  check("9. a 1024-bit RSA key -> ct/unsupported-algorithm (below the 2048 minimum)", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, crypto.sign("sha256", JSON_BLOB, rsa1024.privateKey), rsa1024.publicKey.export({ format: "der", type: "spki" })); })) === "ct/unsupported-algorithm");
  var ed = crypto.generateKeyPairSync("ed25519");
  check("10. an Ed25519 key -> ct/unsupported-algorithm", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, Buffer.alloc(64), ed.publicKey.export({ format: "der", type: "spki" })); })) === "ct/unsupported-algorithm");
  var p384 = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  check("11. a P-384 EC key -> ct/unsupported-algorithm (only P-256)", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, crypto.sign("sha384", JSON_BLOB, p384.privateKey), p384.publicKey.export({ format: "der", type: "spki" })); })) === "ct/unsupported-algorithm");
  // a non-conformant DER ECDSA-Sig-Value (r = s = 0, CVE-2022-21449) -> ct/bad-signature, never true.
  var zeroSig = b.sequence([b.integer(0n), b.integer(0n)]);
  check("12. an r=s=0 ECDSA Sig-Value -> ct/bad-signature (never true, CVE-2022-21449)", /^(ct\/bad-signature|false)$/.test(String(await vres(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, zeroSig, ecSpki); }))));
  // an ECDSA component >= the curve order n (in [n, 2^256)) passes a field-SIZE check but violates the
  // FIPS 186-5 sec. 6.4.2 order bound; the order-aware gate rejects it BEFORE verify (not just r=s=0).
  var P256_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
  var rEqualsN = b.sequence([b.integer(P256_N), b.integer(1n)]);
  check("12a. an ECDSA r == the curve order n -> ct/bad-signature (FIPS 186-5 order bound)", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, rEqualsN, ecSpki); })) === "ct/bad-signature");
  // a non-minimal DER s INTEGER (redundant 00 sign octet) -> ct/bad-signature (the s-position read gate).
  var nonMinimalS = Buffer.from([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01]);
  check("12b. a non-minimal DER s INTEGER -> ct/bad-signature", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, nonMinimalS, ecSpki); })) === "ct/bad-signature");

  // ==== Config-time misuse -> ct/bad-input ==========================================================
  check("13. a non-Buffer/string json -> ct/bad-input", (await code(function () { return pki.ct.verifyLogListSignature(123, rsaSig, rsaSpki); })) === "ct/bad-input");
  check("14. a non-Buffer signature -> ct/bad-input", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, {}, rsaSpki); })) === "ct/bad-input");
  check("15. a non-SPKI publicKey -> ct/bad-input", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, rsaSig, Buffer.from([1, 2, 3])); })) === "ct/bad-input");
  check("16. no publicKey (null) -> ct/bad-input (no baked-in-key fallback)", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, rsaSig, null); })) === "ct/bad-input");
  // a structurally well-formed EC SPKI (passes _spkiAlg) whose point is NOT on P-256 -> subtle.importKey
  // rejects it -> the fail-closed ct/verify-error catch (not a false verdict).
  var offCurve = b.sequence([b.sequence([b.oid(O("ecPublicKey")), b.oid(O("prime256v1"))]), b.bitString(Buffer.concat([Buffer.from([0x04]), Buffer.alloc(64, 0xff)]), 0)]);
  check("17. an EC SPKI with an off-curve point -> ct/verify-error (unimportable key, fail-closed)", (await code(function () { return pki.ct.verifyLogListSignature(JSON_BLOB, ecSig, offCurve); })) === "ct/verify-error");
  // the signed message is bounded before the digest/verify (a hostile caller cannot force unbounded work).
  var over = Buffer.alloc(pki.C.LIMITS.CT_LOG_LIST_MAX_BYTES + 1, 0x20);
  check("18. a json message over the CT_LOG_LIST_MAX_BYTES cap -> ct/too-large (bounded before verify)", (await code(function () { return pki.ct.verifyLogListSignature(over, rsaSig, rsaSpki); })) === "ct/too-large");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
