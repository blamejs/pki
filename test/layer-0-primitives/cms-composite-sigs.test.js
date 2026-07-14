// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- composite ML-DSA SignerInfo in CMS (draft-ietf-lamps-cms-composite-sigs, over the
 * composite construction of draft-ietf-lamps-pq-composite-sigs). Drives the shipped consumer paths
 * pki.cms.sign(...) / pki.cms.verify(...); the s>=n and bad-split rejects drive the shared composite
 * engine (lib/composite-sig.js) directly, since those hostile signatures cannot be produced by the
 * signer. A composite signature pairs a post-quantum ML-DSA with a traditional RSA/ECDSA/EdDSA and
 * is accepted IFF BOTH components verify (never an AND->OR downgrade).
 *
 * Covers: per-family round-trip (accept) with the arm's Table-1 digestAlgorithm; attached/detached;
 * multi-signer coexistence with the classical schemes; and the fail-closed rejects -- AND-downgrade,
 * the CVE-2022-21449 [1,n-1] ECDSA bound (s>=n), bad split length, the sec. 3.4 digest-coherence
 * gate, params-present defense-in-depth, key<->sig OID mismatch, messageDigest desync, the
 * unsupported arms, and the sign-side config-time throws.
 */

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var compositeSig = require("../../lib/composite-sig");
var pki = helpers.pki;
var check = helpers.check;
var makeCompositeSigner = signing.makeCompositeSigner;
var makeSigner = signing.makeSigner;
var b = pki.asn1.build;
var CmsError = pki.errors.CmsError;

var CONTENT = Buffer.from("composite ML-DSA CMS SignedData content");
// The NIST P-256 group order n; a valid ECDSA signature has r, s in [1, n-1] (CVE-2022-21449).
var N_P256 = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

async function rejects(label, fn, code) {
  var e = null;
  try { await fn(); } catch (err) { e = err; }
  check(label + " throws", e !== null);
  check(label + " code=" + code, e && e.code === code);
}

// ---- accept: per-family round-trip, with the arm's Table-1 digestAlgorithm (M8) ----
async function testRoundTrip() {
  var arms = [
    "id-MLDSA44-ECDSA-P256-SHA256",   // ECDSA + SHA-256 pre-hash
    "id-MLDSA44-RSA2048-PKCS15-SHA256",   // RSA PKCS#1 v1.5 + SHA-256
    "id-MLDSA65-ECDSA-P256-SHA512",   // the draft Appendix B arm
    "id-MLDSA65-Ed25519-SHA512",      // EdDSA
    "id-MLDSA65-RSA3072-PSS-SHA512",  // RSA-PSS
    "id-MLDSA87-ECDSA-P521-SHA512",   // the largest ML-DSA + P-521
  ];
  for (var i = 0; i < arms.length; i++) {
    var s = makeCompositeSigner(arms[i]);
    var p7 = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key });
    var res = await pki.cms.verify(p7, { certs: [s.cert] });
    check(arms[i] + " signs -> verifies", res.valid === true && res.signers[0].ok === true);
    var parsed = pki.schema.cms.parse(p7);
    check(arms[i] + " digestAlgorithm == arm pre-hash (" + s.comp.phCms + ")", parsed.signerInfos[0].digestAlgorithm.name === s.comp.phCms);
    check(arms[i] + " signatureAlgorithm is the composite OID", parsed.signerInfos[0].signatureAlgorithm.oid === pki.oid.byName(arms[i]));
  }
}

// ---- accept: detached content ----
async function testDetached() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var p7 = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key }, { detached: true });
  var res = await pki.cms.verify(p7, { content: CONTENT, certs: [s.cert] });
  check("detached composite verifies", res.valid === true);
  // wrong detached content -> the message-digest attribute cannot match (RFC 5652 sec. 5.4)
  var bad = await pki.cms.verify(p7, { content: Buffer.from("different content"), certs: [s.cert] });
  check("detached wrong content -> message-digest-mismatch", bad.valid === false && bad.signers[0].code === "cms/message-digest-mismatch");
}

// ---- accept: a composite SignerInfo coexists with a classical one ----
async function testMultiSigner() {
  var comp = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var classic = makeSigner("ec-p256");
  var p7 = await pki.cms.sign(CONTENT, [{ cert: comp.cert, key: comp.key }, { cert: classic.cert, key: classic.key }]);
  var res = await pki.cms.verify(p7, { certs: [comp.cert, classic.cert] });
  check("multi-signer composite + classical: both verify", res.valid === true && res.signers.length === 2 && res.signers.every(function (x) { return x.ok === true; }));
}

// ---- reject: AND-downgrade -- corrupting EITHER component fails the whole signature (M5) ----
async function testAndDowngrade() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var p7 = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key });
  var okRes = await pki.cms.verify(p7, { certs: [s.cert] });
  check("AND base: both components valid -> true", okRes.valid === true);
  var sig = pki.schema.cms.parse(p7).signerInfos[0].signature;   // mldsaSig || tradSig
  var at = p7.indexOf(sig);
  check("locate the composite signature in the DER", at >= 0);
  // flip a byte in the ML-DSA half (valid trad, broken ML-DSA) -> false
  var tM = Buffer.from(p7); tM[at + 8] ^= 0xff;
  var rM = await pki.cms.verify(tM, { certs: [s.cert] });
  check("ML-DSA component corrupted -> valid:false", rM.valid === false);
  // flip a byte in the traditional half (valid ML-DSA, broken trad) -> false
  var tT = Buffer.from(p7); tT[at + sig.length - 3] ^= 0xff;
  var rT = await pki.cms.verify(tT, { certs: [s.cert] });
  check("traditional component corrupted -> valid:false", rT.valid === false);
}

// ---- reject: the CVE-2022-21449 [1, n-1] ECDSA bound survived the engine relocation ----
// A composite ECDSA arm whose traditional s == n (the curve order) MUST be rejected by the shared
// order-aware DER->P1363 gate (validator.sig.ecdsaDerToP1363), never passed to WebCrypto verify.
async function testEcdsaOrderBound() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var d = s.comp;
  var msg = Buffer.from("preimage for the composite ECDSA order-bound vector");
  var sig = await compositeSig.compositeSign(d, s.key, msg);
  // Sanity: the untampered composite signature verifies.
  var good = await compositeSig.compositeVerify(s.spki, sig, msg, d, CmsError, "cms/unsupported-algorithm", "cms/bad-signature");
  check("order-bound base: valid composite verifies", good.ok === true);
  // Rebuild the traditional ECDSA half with s = n (out of [1, n-1]); keep r and the ML-DSA half.
  var tradDer = sig.subarray(d.mldsaSig);
  var node = pki.asn1.decode(tradDer);
  var r = pki.asn1.read.integer(node.children[0]);
  var forged = Buffer.concat([sig.subarray(0, d.mldsaSig), b.sequence([b.integer(r), b.integer(N_P256)])]);
  var res = await compositeSig.compositeVerify(s.spki, forged, msg, d, CmsError, "cms/unsupported-algorithm", "cms/bad-signature");
  check("ECDSA s == n (order) -> rejected", res.ok === false);
  check("ECDSA s == n -> cms/bad-signature (the [1,n-1] belt)", res.code === "cms/bad-signature");
}

// ---- reject: a low-order EdDSA traditional component (the CVE class every other EdDSA verify
// path in the toolkit already gates -- cms.verify, path.validate). node/OpenSSL imports an
// all-zeroes (on-curve, low-order) Ed25519 key without complaint and it can verify a forged
// component; leaving that unchecked collapses the composite AND to ML-DSA-only. The shared
// edwards-point.validate gate must reject the point before verify, exactly as the ECDSA
// order-bound belt above surfaces a coded fault rather than a silent false.
async function testEddsaLowOrder() {
  var s = makeCompositeSigner("id-MLDSA65-Ed25519-SHA512");
  var d = s.comp;
  var msg = Buffer.from("preimage for the composite EdDSA low-order vector");
  var sig = await compositeSig.compositeSign(d, s.key, msg);
  // Sanity: the untampered composite (full-order Ed25519 component) verifies.
  var good = await compositeSig.compositeVerify(s.spki, sig, msg, d, CmsError, "cms/unsupported-algorithm", "cms/bad-signature");
  check("eddsa low-order base: valid composite verifies", good.ok === true);
  // Forge the SPKI: keep the ML-DSA half, replace the 32-byte Ed25519 traditional half with an
  // all-zeroes low-order point. The ML-DSA component still verifies, isolating the trad gate.
  var rawKey = pki.asn1.read.bitString(pki.asn1.decode(s.spki).children[1]).bytes;
  var mldsaPK = Buffer.from(rawKey.subarray(0, d.mldsaPk));
  var forgedSpki = b.sequence([b.sequence([b.oid(pki.oid.byName("id-MLDSA65-Ed25519-SHA512"))]),
    b.bitString(Buffer.concat([mldsaPK, Buffer.alloc(32)]), 0)]);
  var res = await compositeSig.compositeVerify(forgedSpki, sig, msg, d, CmsError, "cms/unsupported-algorithm", "cms/bad-signature");
  check("composite EdDSA low-order point -> rejected", res.ok === false);
  check("composite EdDSA low-order point -> cms/bad-signature (rejected before verify)", res.code === "cms/bad-signature");
}

// ---- reject: a composite key/signature shorter than the fixed ML-DSA component ----
async function testBadSplitLength() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var d = s.comp;
  var msg = Buffer.from("preimage");
  // A signature exactly mldsaSig long leaves the traditional half empty -> fail closed.
  var res = await compositeSig.compositeVerify(s.spki, Buffer.alloc(d.mldsaSig), msg, d, CmsError, "cms/unsupported-algorithm", "cms/bad-signature");
  check("signature with no trad component -> rejected", res.ok === false && res.code === "cms/bad-signature");
}

// ---- reject: the sec. 3.4 digestAlgorithm-coherence gate (M11) ----
// A composite SignerInfo whose digestAlgorithm is not the arm's Table-1 pre-hash is rejected
// (the sec. 5 SHOULD-reject taken fail-closed), never verified under the wrong digest.
async function testDigestCoherence() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");   // pre-hash SHA-512
  var p7 = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key });
  // Rewrite every id-sha512 OID (2.16.840.1.101.3.4.2.3) to id-sha256 (...2.1): identical length,
  // so the DER stays well-formed but the SignerInfo digestAlgorithm now disagrees with the arm.
  var sha512 = Buffer.from(b.oid(pki.oid.byName("sha512")));
  var sha256 = Buffer.from(b.oid(pki.oid.byName("sha256")));
  var mutated = _replaceAll(p7, sha512, sha256);
  check("digest OID rewrite changed the DER", !mutated.equals(p7));
  var res = await pki.cms.verify(mutated, { certs: [s.cert] });
  check("wrong digestAlgorithm -> valid:false", res.valid === false);
  check("wrong digestAlgorithm -> cms/unsupported-algorithm", res.signers[0].code === "cms/unsupported-algorithm");
}

// ---- reject: params present on the composite signatureAlgorithm (defense-in-depth) ----
async function testParamsPresent() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var p7 = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key });
  var parsed = pki.schema.cms.parse(p7);
  parsed.signerInfos[0].signatureAlgorithm.parameters = Buffer.from([0x05, 0x00]);   // a DER NULL
  var res = await pki.cms.verify(parsed, { certs: [s.cert] });
  check("composite sigAlg params present -> valid:false", res.valid === false);
  check("composite sigAlg params present -> cms/unsupported-algorithm", res.signers[0].code === "cms/unsupported-algorithm");
}

// ---- reject: signer cert SPKI composite OID != SignerInfo signatureAlgorithm OID (M6) ----
async function testKeySigOidMismatch() {
  var signer = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512", { cn: "Dup", serial: 0x99 });
  var other = makeCompositeSigner("id-MLDSA65-Ed25519-SHA512", { cn: "Dup", serial: 0x99 });   // same sid, different arm
  // Do not embed the signer cert; verify sees only the mismatched-arm cert (same issuer+serial).
  var p7 = await pki.cms.sign(CONTENT, { cert: signer.cert, key: signer.key }, { certificates: false });
  var res = await pki.cms.verify(p7, { certs: [other.cert] });
  check("key<->sig OID mismatch -> valid:false", res.valid === false);
  check("key<->sig OID mismatch -> cms/unsupported-algorithm", res.signers[0].code === "cms/unsupported-algorithm");
}

// ---- reject: sign-side config-time throws (the two input/scope gates) ----
async function testSignConfigThrows() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  await rejects("missing traditional component key", function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: { mldsa: s.key.mldsa } }); }, "cms/bad-input");
  await rejects("missing ML-DSA component key", function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: { trad: s.key.trad } }); }, "cms/bad-input");
  await rejects("a single (non-split) key for a composite cert", function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: s.key.mldsa }); }, "cms/bad-input");
  await rejects("digestAlgorithm conflicting with the arm pre-hash", function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: s.key, digestAlgorithm: "sha256" }); }, "cms/bad-input");
}

// ---- reject: an unsupported arm fails closed on sign (never a single-component signature) ----
async function testUnsupportedArm() {
  // Build a minimal cert whose SPKI carries an unsupported composite OID (brainpool); the sign
  // path must refuse it at config time before touching a key.
  var arm = "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512";
  var spki = b.sequence([b.sequence([b.oid(pki.oid.byName(arm))]), b.bitString(Buffer.alloc(64), 0)]);
  var cert = signing.minimalCert(spki, {});
  await rejects("sign an unsupported composite arm", function () {
    return pki.cms.sign(CONTENT, { cert: cert, key: { mldsa: Buffer.alloc(4), trad: Buffer.alloc(4) } });
  }, "cms/unsupported-algorithm");
}

// ---- reject: an unsupported arm fails closed on VERIFY too (a CMS carrying one cannot be signed,
// so drive it through the parsed-object input path with an unsupported composite OID) ----
async function testUnsupportedArmVerify() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var p7 = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key });
  var parsed = pki.schema.cms.parse(p7);
  parsed.signerInfos[0].signatureAlgorithm.oid = pki.oid.byName("id-MLDSA65-ECDSA-brainpoolP256r1-SHA512");
  var res = await pki.cms.verify(parsed, { certs: [s.cert] });
  check("verify unsupported arm -> valid:false", res.valid === false);
  check("verify unsupported arm -> cms/unsupported-algorithm", res.signers[0].code === "cms/unsupported-algorithm");
}

// ---- reject: a present non-NULL digestAlgorithm parameter (RFC 5754 sec. 2) ----
async function testDigestParamsPresent() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var p7 = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key });
  var parsed = pki.schema.cms.parse(p7);
  parsed.signerInfos[0].digestAlgorithm.parameters = Buffer.from([0x04, 0x01, 0x00]);   // an OCTET STRING, not NULL
  var res = await pki.cms.verify(parsed, { certs: [s.cert] });
  check("present non-NULL digest params -> valid:false", res.valid === false);
  check("present non-NULL digest params -> cms/unsupported-algorithm", res.signers[0].code === "cms/unsupported-algorithm");
  // draft sec. 3.4: the composite digestAlgorithm parameters MUST be OMITTED -- a present DER NULL
  // (which the generic RFC 5754 rule accepts for a SHA-2 digest, and which the classical/ML-DSA
  // paths accept) is non-conformant for a composite SignerInfo and is likewise rejected.
  var pNull = pki.schema.cms.parse(p7);
  pNull.signerInfos[0].digestAlgorithm.parameters = Buffer.from([0x05, 0x00]);   // DER NULL -- must be omitted for composite
  var resNull = await pki.cms.verify(pNull, { certs: [s.cert] });
  check("present DER NULL digest params -> valid:false", resNull.valid === false);
  check("present DER NULL digest params -> cms/unsupported-algorithm", resNull.signers[0].code === "cms/unsupported-algorithm");
}

// ---- reject: malformed composite public key / RSA component -> a fail-closed verdict, never a throw ----
async function testMalformedComposite() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var msg = Buffer.from("malformed-composite preimage");
  var sig = await compositeSig.compositeSign(s.comp, s.key, msg);
  // A SubjectPublicKeyInfo whose second field is not a BIT STRING cannot be read.
  var badSpki = b.sequence([b.sequence([b.oid(pki.oid.byName("id-MLDSA65-ECDSA-P256-SHA512"))]), b.nullValue()]);
  var r1 = await compositeSig.compositeVerify(badSpki, sig, msg, s.comp, CmsError, "cms/unsupported-algorithm", "cms/bad-signature");
  check("malformed composite SPKI -> rejected (verdict, not throw)", r1.ok === false && typeof r1.code === "string");
  // A composite RSA arm whose RSAPublicKey component does not decode -> the traditional half fails.
  var rs = makeCompositeSigner("id-MLDSA65-RSA3072-PSS-SHA512");
  var rmsg = Buffer.from("malformed-rsa preimage");
  var rsig = await compositeSig.compositeSign(rs.comp, rs.key, rmsg);
  var rawKey = pki.asn1.read.bitString(pki.asn1.decode(rs.spki).children[1]).bytes;
  var mldsaPK = rawKey.subarray(0, rs.comp.mldsaPk);
  var badRsaSpki = b.sequence([b.sequence([b.oid(pki.oid.byName("id-MLDSA65-RSA3072-PSS-SHA512"))]), b.bitString(Buffer.concat([mldsaPK, Buffer.from([0xff, 0xff, 0xff, 0xff])]), 0)]);
  var r2 = await compositeSig.compositeVerify(badRsaSpki, rsig, rmsg, rs.comp, CmsError, "cms/unsupported-algorithm", "cms/bad-signature");
  check("malformed composite RSA component -> rejected", r2.ok === false);
}

// ---- accept: the two component keys as Uint8Array and PKCS#8 PEM; a bad-type component rejected ----
async function testKeyInputForms() {
  var s = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var u8 = { mldsa: new Uint8Array(s.key.mldsa), trad: new Uint8Array(s.key.trad) };
  check("composite keys as Uint8Array round-trip", (await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: s.cert, key: u8 }), { certs: [s.cert] })).valid === true);
  var pem = { mldsa: _pkcs8Pem(s.key.mldsa), trad: _pkcs8Pem(s.key.trad) };
  check("composite keys as PKCS#8 PEM round-trip", (await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: s.cert, key: pem }), { certs: [s.cert] })).valid === true);
  await rejects("a bad-type component key", function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: { mldsa: 123, trad: s.key.trad } }); }, "cms/bad-input");
  await rejects("a malformed-PEM component key", function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: { mldsa: "-----BEGIN PRIVATE KEY-----\nnot-base64!!!\n-----END PRIVATE KEY-----\n", trad: s.key.trad } }); }, "cms/bad-input");
}
function _pkcs8Pem(der) { return "-----BEGIN PRIVATE KEY-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END PRIVATE KEY-----\n"; }

// Replace every occurrence of `find` in `buf` with `repl` (equal length assumed).
function _replaceAll(buf, find, repl) {
  var out = Buffer.from(buf), i = 0;
  while ((i = out.indexOf(find, i)) >= 0) { repl.copy(out, i); i += repl.length; }
  return out;
}

async function run() {
  await testRoundTrip();
  await testDetached();
  await testMultiSigner();
  await testAndDowngrade();
  await testEcdsaOrderBound();
  await testEddsaLowOrder();
  await testBadSplitLength();
  await testDigestCoherence();
  await testParamsPresent();
  await testKeySigOidMismatch();
  await testSignConfigThrows();
  await testUnsupportedArm();
  await testUnsupportedArmVerify();
  await testDigestParamsPresent();
  await testMalformedComposite();
  await testKeyInputForms();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
