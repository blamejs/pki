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
  // HSS consistency: an LMS signature inside an HSS blob whose typecode is
  // mutated must be a verification FAILURE (false), exactly as verifyLms treats
  // it -- NOT a throw. The HSS parser sizes each level's signature by the
  // AUTHORITATIVE public key, so a mismatch reaches _lmsVerify's step-2c check.
  var hss = readFixture("rfc8554-appF.json")[0];
  var hp = hx(hss.publicKeyHex), hm = hx(hss.messageHex), hs = Buffer.from(hx(hss.signatureHex));
  hs.writeUInt32BE(hs.readUInt32BE(8) === 4 ? 3 : 4, 8);   // sig[0] OTS typecode (bytes 8-11)
  check("HSS signature with a mutated inner LMS typecode -> false", pki.shbs.verify(hp, hm, hs) === false);
}

// -- structural bounds: each fail-closed length/typecode guard reached on the
//    SHIPPED consumer path, asserting the typed verdict (never a raw throw) ----
function testStructuralBounds() {
  var v = readFixture("acvp-lms-sigver.json");
  var good = v.filter(function (t) { return t.testPassed; })[0];
  var pub = hx(good.publicKey), msg = hx(good.message), sig = hx(good.signature);

  // A valid LMS typecode paired with an UNKNOWN LM-OTS typecode (bytes 4..7):
  // the OTS typecode is a second registry authority, so an unrecognized value is
  // shbs/unsupported-parameter-set -- resolved AFTER the LMS typecode, so this
  // is a distinct guard from the unknown-LMS-typecode case above.
  var badOtsPub = Buffer.from(pub); badOtsPub.writeUInt32BE(0x000000FF, 4);
  check("LMS public key with unknown LM-OTS typecode -> shbs/unsupported-parameter-set",
    codeOf(function () { pki.shbs.verifyLms(badOtsPub, msg, sig); }) === "shbs/unsupported-parameter-set");

  // Valid typecodes but a wrong TOTAL length (one byte short of the exact 24+m):
  // the LMS public-key exact-length gate -> shbs/bad-public-key.
  var shortPub = pub.subarray(0, pub.length - 1);
  check("LMS public key of wrong exact length -> shbs/bad-public-key",
    codeOf(function () { pki.shbs.verifyLms(shortPub, msg, sig); }) === "shbs/bad-public-key");

  // An LMS signature shorter than 8 bytes cannot hold q + the OTS typecode; the
  // length precheck fails closed -> shbs/bad-signature (before any field read).
  check("LMS signature shorter than 8 bytes -> shbs/bad-signature",
    codeOf(function () { pki.shbs.verifyLms(pub, msg, sig.subarray(0, 4)); }) === "shbs/bad-signature");

  // An HSS public key shorter than 4 bytes cannot hold the level count L; the
  // top-level HSS precheck fails closed -> shbs/bad-public-key.
  check("HSS public key shorter than 4 bytes -> shbs/bad-public-key",
    codeOf(function () { pki.shbs.verify(Buffer.alloc(3), msg, sig); }) === "shbs/bad-public-key");

  // A multi-level HSS (L=2) whose top LMS key is under 8 bytes: the per-level
  // signature-length computation fails closed -> shbs/bad-public-key, never a
  // raw RangeError from an unbounded read of a truncated inner key. Nspk+1 == L
  // clears the level-count gate so control reaches the length computation.
  var pubL2 = Buffer.alloc(8); pubL2.writeUInt32BE(2, 0);   // L=2, then a 4-byte top LMS key
  var sigN1 = Buffer.alloc(4); sigN1.writeUInt32BE(1, 0);   // Nspk=1 (Nspk+1 == L)
  check("HSS top-level LMS key under 8 bytes -> shbs/bad-public-key",
    codeOf(function () { pki.shbs.verify(pubL2, msg, sigN1); }) === "shbs/bad-public-key");
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

// -- RFC 9802 Appendix A: an HSS-signed certificate through pki.path.validate ------------------
// The published example is self-signed, so the certificate is its own issuer and validating it
// checks the signature under the key it carries. That is the end-to-end proof the raw-blob verify
// cannot give: it exercises the certificate parse, the algorithm dispatch, and the verdict.
async function testHssCertificatePath() {
  var fx = readFixture("rfc9802-appA-hss-cert.json");
  var pem = fx.pem.join("\n");
  var parsed = pki.schema.x509.parse(pem);
  var T = new Date("2030-01-01T00:00:00Z");

  check("HSS-1 the RFC 9802 certificate names id-alg-hss-lms-hashsig for both its signature and its key",
    parsed.signatureAlgorithm.oid === pki.oid.byName("id-alg-hss-lms-hashsig") &&
    parsed.subjectPublicKeyInfo.algorithm.oid === pki.oid.byName("id-alg-hss-lms-hashsig"));

  var r = await pki.path.validate([parsed], { time: T, trustAnchors: [pem] });
  check("HSS-2 pki.path.validate accepts the self-signed HSS certificate", r.valid === true);

  // The signature is over the whole tbsCertificate, not a digest of it (RFC 9802 sec. 7.1), so a
  // single changed byte anywhere in it must fail. der-surgery is not needed: the anchor carries the
  // key, and flipping a byte of the signature is the same falsification.
  var der = pki.schema.x509.pemDecode(pem);
  var tampered = Buffer.from(der);
  tampered[tampered.length - 1] ^= 0x01;
  var rBad = await pki.path.validate([pki.schema.x509.parse(tampered)], { time: T, trustAnchors: [pem] });
  var badCodes = [];
  (rBad.results || []).forEach(function (res) { (res.checks || []).forEach(function (c) { if (c.ok === false) badCodes.push(c.code); }); });
  check("HSS-3 a tampered signature is refused, not accepted",
    rBad.valid === false && badCodes.indexOf("path/bad-signature") !== -1);

  // The advertised algorithm is bound to the key: the certificate's own subject public key must be
  // the HSS key the signature algorithm names (RFC 9802 sec. 5.1 / sec. 7.1, PARAMS ARE absent).
  check("HSS-4 the signature algorithm carries no parameters", parsed.signatureAlgorithm.parameters === null);

  // An anchor may be given as a tuple rather than a certificate, so its public key is whatever bytes the
  // caller passed. Bytes that are not a SubjectPublicKeyInfo never reach the signature engine: the anchor
  // door refuses them, which is why the engine's own read guard cannot be driven from here.
  var junkErr = null;
  try {
    await pki.path.validate([parsed], { time: T, trustAnchors: [{
      name: parsed.issuer, algorithm: pki.oid.byName("id-alg-hss-lms-hashsig"), publicKey: Buffer.from([0x30, 0x00]),
    }] });
  } catch (e) { junkErr = e; }
  check("HSS-6 an anchor public key that is not a SubjectPublicKeyInfo is refused at the door",
    !!junkErr && junkErr.code === "path/bad-input");

  // A SubjectPublicKeyInfo the door accepts can still carry key material the engine cannot read. The
  // engine's refusal is a verdict on the signature, never a pass.
  var spki = Buffer.from(pki.asn1.decode(der).children[0].children[6].bytes);
  var keyAt = spki.indexOf(Buffer.from("000000010000000500000004", "hex"));
  var brokenSpki = Buffer.from(spki);
  brokenSpki[keyAt + 3] = 0x7f;   // an HSS level count no parameter set defines
  var rBrokenKey = await pki.path.validate([parsed], { time: T, trustAnchors: [{
    name: parsed.issuer, algorithm: pki.oid.byName("id-alg-hss-lms-hashsig"), publicKey: brokenSpki,
  }] });
  var brokenCodes = [];
  (rBrokenKey.results || []).forEach(function (res) { (res.checks || []).forEach(function (c) { if (c.ok === false) brokenCodes.push(c.code); }); });
  check("HSS-7 an unreadable HSS public key is a signature refusal, not a pass",
    rBrokenKey.valid === false && brokenCodes.indexOf("path/bad-signature") !== -1);

  // The codec accepts a BIT STRING that declares unused bits as long as they are zero, so a key would
  // otherwise admit a second encoding of itself. An RFC 8554 public key is a whole number of octets.
  var alignKey = Buffer.from(parsed.subjectPublicKeyInfo.publicKey.bytes);
  alignKey[alignKey.length - 1] &= 0xF0;
  var unalignedSpki = pki.asn1.build.sequence([
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("id-alg-hss-lms-hashsig"))]),
    pki.asn1.build.bitString(alignKey, 4),
  ]);
  var rUnaligned = await pki.path.validate([parsed], { time: T, trustAnchors: [{
    name: parsed.issuer, algorithm: pki.oid.byName("id-alg-hss-lms-hashsig"), publicKey: unalignedSpki,
  }] });
  var alignCodes = [];
  (rUnaligned.results || []).forEach(function (res) { (res.checks || []).forEach(function (c) { if (c.ok === false) alignCodes.push(c.code); }); });
  check("HSS-9 a subjectPublicKey declaring unused bits is refused, not read as the whole-octet key",
    rUnaligned.valid === false && alignCodes.indexOf("path/bad-signature") !== -1);

  // RFC 9802 sec. 6 names the CertificateList beside the Certificate, so a revocation list claiming the
  // algorithm reaches the same engine and is answered with a signature verdict. There is no published
  // HSS-signed CRL to accept, and the toolkit does not sign stateful keys, so what is pinned here is the
  // route and the refusal.
  var bld = pki.asn1.build;
  var hssAlgId = bld.sequence([bld.oid(pki.oid.byName("id-alg-hss-lms-hashsig"))]);
  var tbsCertList = bld.sequence([
    bld.integer(1n), hssAlgId, bld.raw(Buffer.from(parsed.subject.bytes)),
    bld.utcTime(new Date("2027-01-01T00:00:00Z")),
  ]);
  var crlDer = bld.sequence([tbsCertList, hssAlgId, bld.bitString(Buffer.alloc(64), 0)]);
  var crlVerdict = await pki.crl.verify(crlDer, { cert: pem });
  check("HSS-8 a CertificateList naming the HSS algorithm is answered with a signature verdict",
    crlVerdict.valid === false && crlVerdict.signatureValid === false && crlVerdict.issuerMaySign === true);

  // Outside the validity window the verdict is the ordinary one, so the new dispatch did not become
  // a way around the rest of section 6.1.
  var rExpired = await pki.path.validate([parsed], { time: new Date("2040-01-01T00:00:00Z"), trustAnchors: [pem] });
  check("HSS-5 an expired HSS certificate is refused like any other", rExpired.valid === false);
}

async function run() {
  testOid();
  testRfcAppendixF();
  testAcvpLmsSigVer();
  testMalformed();
  testStructuralBounds();
  await testHssCertificatePath();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
