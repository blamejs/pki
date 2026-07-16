// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- validator-sig (@internal): the ORDER-aware DER ECDSA-Sig-Value conformance
 * gate (ecdsaDerToP1363) + its raw r||s conversion (RFC 3279 sec. 2.2.3 + X.690 sec. 8.3
 * strict-DER + SEC1 + FIPS 186-5 sec. 6.4.2). Oracle: a hand-crafted set of malformed
 * ECDSA-Sig-Value encodings, each of which MUST fail closed with the caller's typed error
 * -- a non-minimal, negative, zero, over-size, or out-of-[1,n-1] r/s is rejected, never
 * normalized-and-accepted (the strict-DER + CVE-2022-21449 promise).
 */

var sig = require("../../lib/validator-sig");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;
var bld = helpers.pki.asn1.build;
// The NIST P-256 group order n; a valid ECDSA signature has r, s in [1, n-1] (CVE-2022-21449).
var N_P256 = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

// The caller's error class threads a cause (as WebauthnError does), so define with withCause.
var TestError = errors.defineClass("TestError", { withCause: true });
function E(code, message, cause) { return new TestError(code, message, cause); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
function H(hex) { return Buffer.from(hex, "hex"); }

function run() {
  var CODE = "sig/bad";
  // A well-formed 2x32-byte ECDSA-Sig-Value converts to raw r||s (64 bytes). Both coordinates
  // are in [1, n-1] (r = 0x7f.., s = 0x01.. are far below the P-256 order n = 0xffffffff00..).
  var rHex = "7f" + "ab".repeat(31), sHex = "01" + "cd".repeat(31);
  var valid = H("3044" + "0220" + rHex + "0220" + sHex);
  var raw = sig.ecdsaDerToP1363(valid, "P-256", E, CODE);
  check("valid ECDSA-Sig-Value -> 64-byte raw r||s", raw.length === 64);
  check("valid: r coordinate preserved (left position)", raw.subarray(0, 32).toString("hex") === rHex);
  check("valid: s coordinate preserved (right position)", raw.subarray(32).toString("hex") === sHex);
  // A short coordinate is left-padded to the curve field width (r = 5 -> 31 zero bytes then 0x05).
  var shortSig = H("3006" + "0201" + "05" + "0201" + "06");
  var shortRaw = sig.ecdsaDerToP1363(shortSig, "P-256", E, CODE);
  check("short r is left-padded to the curve width", shortRaw.length === 64 && shortRaw[31] === 0x05 && shortRaw[30] === 0x00);

  // --- strict-DER conformance rejects (all -> the caller's typed code) ---
  // Non-minimal r (leading 0x00 with the next byte's high bit clear): X.690 sec. 8.3.2.
  check("non-minimal r (redundant 0x00 sign octet) -> rejected", code(function () { sig.ecdsaDerToP1363(H("3007" + "0202007f" + "020105"), "P-256", E, CODE); }) === CODE);
  // Negative r (top bit set, no leading sign octet).
  check("negative r -> rejected", code(function () { sig.ecdsaDerToP1363(H("3006" + "0201ff" + "020105"), "P-256", E, CODE); }) === CODE);
  // Zero r (r MUST be >= 1).
  check("zero r -> rejected", code(function () { sig.ecdsaDerToP1363(H("3006" + "020100" + "020105"), "P-256", E, CODE); }) === CODE);
  // r magnitude at/above the curve order n (33-byte 0x01<<256 = 2^256 > n) -> out of [1, n-1].
  check("over-size r (>= order n) -> rejected", code(function () { sig.ecdsaDerToP1363(H("3026" + "022101" + "00".repeat(32) + "020105"), "P-256", E, CODE); }) === CODE);
  // Non-minimal / negative / zero also enforced on s.
  check("zero s -> rejected", code(function () { sig.ecdsaDerToP1363(H("3006" + "020105" + "020100"), "P-256", E, CODE); }) === CODE);
  check("negative s -> rejected", code(function () { sig.ecdsaDerToP1363(H("3006" + "020105" + "0201ff"), "P-256", E, CODE); }) === CODE);

  // --- structural rejects ---
  check("not a SEQUENCE -> rejected", code(function () { sig.ecdsaDerToP1363(H("020105"), "P-256", E, CODE); }) === CODE);
  check("SEQUENCE with one child -> rejected", code(function () { sig.ecdsaDerToP1363(H("3003020105"), "P-256", E, CODE); }) === CODE);
  check("SEQUENCE with three children -> rejected", code(function () { sig.ecdsaDerToP1363(H("3009020101020102020103"), "P-256", E, CODE); }) === CODE);
  // A constructed r (an empty SEQUENCE where a primitive INTEGER is required) is rejected.
  check("constructed r (SEQUENCE in r's slot) -> rejected", code(function () { sig.ecdsaDerToP1363(H("3006" + "3000" + "020105"), "P-256", E, CODE); }) === CODE);
  check("empty input -> rejected", code(function () { sig.ecdsaDerToP1363(H(""), "P-256", E, CODE); }) === CODE);

  // --- rawToEcdsaDer: the inverse (raw r||s -> canonical DER), round-trip identity through the gate ---
  var rawIn = Buffer.concat([H(rHex), H(sHex)]);   // 64-byte raw r||s, both in [1, n-1]
  var derOut = sig.rawToEcdsaDer(rawIn, 32);
  check("rawToEcdsaDer emits a DER SEQUENCE", derOut[0] === 0x30);
  check("rawToEcdsaDer -> ecdsaDerToP1363 round-trips to identity", Buffer.compare(sig.ecdsaDerToP1363(derOut, "P-256", E, CODE), rawIn) === 0);
  // A coordinate whose high bit is set gets a leading 0x00 in DER and is stripped back on read.
  // r = 0xff00..00 is < n (n's 2nd byte is 0xff, r's is 0x00), so it stays in [1, n-1].
  var hi = Buffer.concat([H("ff" + "00".repeat(31)), H("80" + "11".repeat(31))]);
  check("rawToEcdsaDer round-trips a high-bit coordinate", Buffer.compare(sig.ecdsaDerToP1363(sig.rawToEcdsaDer(hi, 32), "P-256", E, CODE), hi) === 0);
  // config-time TypeError on a mis-sized / non-Buffer raw signature.
  var t1 = false; try { sig.rawToEcdsaDer(rawIn, 48); } catch (e) { t1 = e instanceof TypeError; }
  check("rawToEcdsaDer rejects a wrong-length raw sig (TypeError)", t1);
  var t2 = false; try { sig.rawToEcdsaDer("notbuf", 32); } catch (e) { t2 = e instanceof TypeError; }
  check("rawToEcdsaDer rejects a non-Buffer raw sig (TypeError)", t2);

  // --- ecdsaDerToP1363: the ORDER-aware [1, n-1] gate (CVE-2022-21449) -- the single home the
  // composite-signature, certification-path, CMS, CT, and webauthn ECDSA components share. ---
  var okDer = bld.sequence([bld.integer(1n), bld.integer(2n)]);
  check("ecdsaDerToP1363 valid (r,s in [1,n-1]) -> 64-byte raw", sig.ecdsaDerToP1363(okDer, "P-256", E, CODE).length === 64);
  check("ecdsaDerToP1363 unsupported curve -> rejected", code(function () { sig.ecdsaDerToP1363(okDer, "P-999", E, CODE); }) === CODE);
  check("ecdsaDerToP1363 s == 0 -> out of range", code(function () { sig.ecdsaDerToP1363(bld.sequence([bld.integer(1n), bld.integer(0n)]), "P-256", E, CODE); }) === CODE);
  check("ecdsaDerToP1363 s == n (order) -> out of range (CVE-2022-21449 upper bound)", code(function () { sig.ecdsaDerToP1363(bld.sequence([bld.integer(1n), bld.integer(N_P256)]), "P-256", E, CODE); }) === CODE);
  check("ecdsaDerToP1363 r == n (order) -> out of range", code(function () { sig.ecdsaDerToP1363(bld.sequence([bld.integer(N_P256), bld.integer(1n)]), "P-256", E, CODE); }) === CODE);
  check("ecdsaDerToP1363 not a SEQUENCE(r,s) -> rejected", code(function () { sig.ecdsaDerToP1363(bld.sequence([bld.integer(1n)]), "P-256", E, CODE); }) === CODE);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
