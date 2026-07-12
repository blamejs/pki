// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.shbs: stateful hash-based signature VERIFICATION (HSS/LMS,
 * RFC 8554, profiled by NIST SP 800-208).
 * Oracle: two independent authoritative KAT sources -- RFC 8554 Appendix F (the
 * two HSS L=2 test cases) and the 320 NIST ACVP LMS-sigVer vectors (every
 * SP 800-208 parameter set: SHA-256/SHAKE x M32/M24 x W1..W8 x H5..H25, with
 * both accept and reject cases). A verify engine with no cross-implementation
 * KAT is untested; these are the correctness spine.
 */

var readFixture = function (n) { return require("../fixtures/shbs/" + n); };
var pki = require("../../index.js");
var helpers = require("../helpers");
var check = helpers.check;

function hx(s) { return Buffer.from(s, "hex"); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

// -- RFC 8554 Appendix F: HSS L=2 known-answer accept ------------------------
function testRfcAppendixF() {
  var kat = readFixture("rfc8554-appF.json");
  kat.forEach(function (tc) {
    check("RFC 8554 App F [" + tc.name.replace(/\s*\(.*/, "") + "] verifies true",
      pki.shbs.verify(hx(tc.publicKeyHex), hx(tc.messageHex), hx(tc.signatureHex)) === tc.expected);
  });
  // A single-bit flip in the message must break the HSS verify.
  var tc0 = kat[0];
  var badMsg = hx(tc0.messageHex); badMsg[0] ^= 0x01;
  check("RFC App F: a flipped message byte -> false", pki.shbs.verify(hx(tc0.publicKeyHex), badMsg, hx(tc0.signatureHex)) === false);
  // A flip in the signature (a Winternitz chain value) must break it.
  var badSig = hx(tc0.signatureHex); badSig[badSig.length - 1] ^= 0x01;
  check("RFC App F: a flipped signature byte -> false", pki.shbs.verify(hx(tc0.publicKeyHex), hx(tc0.messageHex), badSig) === false);
}

// -- NIST ACVP LMS-sigVer: the full 320-vector suite, every parameter set ----
function testAcvpLmsSigVer() {
  var v = readFixture("acvp-lms-sigver.json");
  var fails = [], byMode = {};
  v.forEach(function (t) {
    var got;
    try { got = pki.shbs.verifyLms(hx(t.publicKey), hx(t.message), hx(t.signature)); }
    catch (e) { got = "THREW:" + (e.code || e.message); }
    var ok = got === t.testPassed;
    var mode = t.lmsMode + "/" + t.lmOtsMode;
    if (!byMode[mode]) byMode[mode] = { pass: 0, fail: 0 };
    byMode[mode][ok ? "pass" : "fail"] += 1;
    if (!ok && fails.length < 6) fails.push("tc" + t.tcId + " " + mode + " expected=" + t.testPassed + " got=" + got);
  });
  var modes = Object.keys(byMode);
  check("ACVP: every parameter-set combination exercised", modes.length === 80);
  check("ACVP: all 320 LMS-sigVer vectors match NIST testPassed" + (fails.length ? " -- first fails: " + fails.join("; ") : ""),
    fails.length === 0 && v.length === 320);
}

// -- malformed blobs -> typed ShbsError (not false, not a raw throw) ----------
function testMalformed() {
  var v = readFixture("acvp-lms-sigver.json");
  var good = v.filter(function (t) { return t.testPassed; })[0];
  var pub = hx(good.publicKey), msg = hx(good.message), sig = hx(good.signature);
  // Truncated signature (short by one byte) -> shbs/bad-signature.
  check("truncated LMS signature -> shbs/bad-signature",
    codeOf(function () { pki.shbs.verifyLms(pub, msg, sig.subarray(0, sig.length - 1)); }) === "shbs/bad-signature");
  // Trailing byte on an otherwise-valid signature -> shbs/bad-signature.
  check("trailing-byte LMS signature -> shbs/bad-signature",
    codeOf(function () { pki.shbs.verifyLms(pub, msg, Buffer.concat([sig, Buffer.from([0])])); }) === "shbs/bad-signature");
  // Unknown LMS typecode in the public key -> shbs/unsupported-parameter-set.
  var badTypePub = Buffer.from(pub); badTypePub.writeUInt32BE(0x000000FF, 0);
  check("unknown LMS typecode -> shbs/unsupported-parameter-set",
    codeOf(function () { pki.shbs.verifyLms(badTypePub, msg, sig); }) === "shbs/unsupported-parameter-set");
  // Signature OTS typecode disagreeing with the public key is a verification
  // FAILURE (false), not a structural error -- RFC 8554 Algorithm 6a step 2c
  // returns INVALID; the public key is the authority (downgrade defense).
  var badOtsSig = Buffer.from(sig); badOtsSig.writeUInt32BE(badOtsSig.readUInt32BE(4) === 4 ? 3 : 4, 4);
  check("signature/public-key typecode mismatch -> false",
    pki.shbs.verifyLms(pub, msg, badOtsSig) === false);
  // A non-buffer input -> shbs/bad-input.
  check("non-buffer public key -> shbs/bad-input", codeOf(function () { pki.shbs.verifyLms(42, msg, sig); }) === "shbs/bad-input");
  // HSS level-count gate: App F Test Case 1 signature under a truncated L.
  var kat = readFixture("rfc8554-appF.json")[0];
  var hssPub = hx(kat.publicKeyHex); var badL = Buffer.from(hssPub); badL.writeUInt32BE(3, 0);
  check("HSS Nspk+1 != L -> shbs/bad-signature",
    codeOf(function () { pki.shbs.verify(badL, hx(kat.messageHex), hx(kat.signatureHex)); }) === "shbs/bad-signature");
  // A 4-7 byte HSS public key (valid L, absent/truncated top LMS key) must fail
  // closed TYPED, never a raw RangeError from an unbounded direct read.
  [4, 5, 6, 7].forEach(function (len) {
    var tiny = Buffer.alloc(len); tiny.writeUInt32BE(1, 0);   // L=1, then <4 remaining bytes
    var got = codeOf(function () { pki.shbs.verify(tiny, msg, hx("00000000")); });
    check("tiny HSS public key (len " + len + ") -> typed shbs/*", typeof got === "string" && got.indexOf("shbs/") === 0);
  });
  // An exact-length LMS signature whose leaf index q >= 2^h is a verification
  // FAILURE (false), not a structural error -- RFC 8554 Algorithm 6a step 2i
  // (return INVALID). Take a valid signature and set q past the tree height.
  var badQ = Buffer.from(sig); badQ.writeUInt32BE(0xFFFFFFFF, 0);
  check("exact-length signature with q >= 2^h -> false", pki.shbs.verifyLms(pub, msg, badQ) === false);
  // RFC 8554 Algorithm 6a step 2c: the typecode is checked BEFORE the length, so
  // a mismatched OTS typecode is INVALID (false) even for an 8-byte blob too
  // short to be a complete signature -- never re-sized by the mismatched typecode
  // (which would reject a legitimate typecode-mutation vector as malformed).
  var sigOts = sig.readUInt32BE(4);
  var tinyMismatch = Buffer.alloc(8); tinyMismatch.writeUInt32BE(0, 0); tinyMismatch.writeUInt32BE(sigOts === 4 ? 3 : 4, 4);
  check("8-byte blob with a mismatched OTS typecode -> false (RFC Alg 6a step 2c)", pki.shbs.verifyLms(pub, msg, tinyMismatch) === false);
}

// -- OID registry + params-absent seed ---------------------------------------
function testOid() {
  check("id-alg-hss-lms-hashsig round-trips", pki.oid.byName("id-alg-hss-lms-hashsig") === "1.2.840.113549.1.9.16.3.17"
    && pki.oid.name("1.2.840.113549.1.9.16.3.17") === "id-alg-hss-lms-hashsig");
  check("id-alg-xmss-hashsig round-trips", pki.oid.byName("id-alg-xmss-hashsig") === "1.3.6.1.5.5.7.6.34");
  check("id-alg-xmssmt-hashsig round-trips", pki.oid.byName("id-alg-xmssmt-hashsig") === "1.3.6.1.5.5.7.6.35");
  check("HSS/LMS params MUST be absent", pki.oid.paramsMustBeAbsent(pki.oid.byName("id-alg-hss-lms-hashsig")) === true);
  check("XMSS params MUST be absent", pki.oid.paramsMustBeAbsent(pki.oid.byName("id-alg-xmss-hashsig")) === true);
}

function run() {
  testOid();
  testRfcAppendixF();
  testAcvpLmsSigVer();
  testMalformed();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
