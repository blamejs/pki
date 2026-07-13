// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- validator-sig (@internal): the DER ECDSA-Sig-Value conformance gate +
 * raw r||s conversion (RFC 3279 sec. 2.2.3 + X.690 sec. 8.3 strict-DER + SEC1).
 * Oracle: a hand-crafted set of malformed ECDSA-Sig-Value encodings, each of which
 * MUST fail closed with the caller's typed error -- a non-minimal, negative, zero, or
 * over-size r/s is rejected, never normalized-and-accepted (the strict-DER promise).
 */

var sig = require("../../lib/validator-sig");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

// The caller's error class threads a cause (as WebauthnError does), so define with withCause.
var TestError = errors.defineClass("TestError", { withCause: true });
function E(code, message, cause) { return new TestError(code, message, cause); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
function H(hex) { return Buffer.from(hex, "hex"); }

function run() {
  var CODE = "sig/bad";
  // A well-formed 2x32-byte ECDSA-Sig-Value converts to raw r||s (64 bytes).
  var rHex = "7f" + "ab".repeat(31), sHex = "01" + "cd".repeat(31);
  var valid = H("3044" + "0220" + rHex + "0220" + sHex);
  var raw = sig.ecdsaSigToRaw(valid, 32, E, CODE);
  check("valid ECDSA-Sig-Value -> 64-byte raw r||s", raw.length === 64);
  check("valid: r coordinate preserved (left position)", raw.subarray(0, 32).toString("hex") === rHex);
  check("valid: s coordinate preserved (right position)", raw.subarray(32).toString("hex") === sHex);
  // A short coordinate is left-padded to coordLen (r = 5 -> 31 zero bytes then 0x05).
  var shortSig = H("3006" + "0201" + "05" + "0201" + "06");
  var shortRaw = sig.ecdsaSigToRaw(shortSig, 32, E, CODE);
  check("short r is left-padded to coordLen", shortRaw.length === 64 && shortRaw[31] === 0x05 && shortRaw[30] === 0x00);

  // --- strict-DER conformance rejects (all -> the caller's typed code) ---
  // Non-minimal r (leading 0x00 with the next byte's high bit clear): X.690 sec. 8.3.2.
  check("non-minimal r (redundant 0x00 sign octet) -> rejected", code(function () { sig.ecdsaSigToRaw(H("3007" + "0202007f" + "020105"), 32, E, CODE); }) === CODE);
  // Negative r (top bit set, no leading sign octet).
  check("negative r -> rejected", code(function () { sig.ecdsaSigToRaw(H("3006" + "0201ff" + "020105"), 32, E, CODE); }) === CODE);
  // Zero r (r MUST be >= 1).
  check("zero r -> rejected", code(function () { sig.ecdsaSigToRaw(H("3006" + "020100" + "020105"), 32, E, CODE); }) === CODE);
  // r magnitude wider than the curve field size (33 bytes vs coordLen 32).
  check("over-size r (exceeds field) -> rejected", code(function () { sig.ecdsaSigToRaw(H("3026" + "022101" + "00".repeat(32) + "020105"), 32, E, CODE); }) === CODE);
  // Non-minimal / negative / zero also enforced on s.
  check("zero s -> rejected", code(function () { sig.ecdsaSigToRaw(H("3006" + "020105" + "020100"), 32, E, CODE); }) === CODE);
  check("negative s -> rejected", code(function () { sig.ecdsaSigToRaw(H("3006" + "020105" + "0201ff"), 32, E, CODE); }) === CODE);

  // --- structural rejects ---
  check("not a SEQUENCE -> rejected", code(function () { sig.ecdsaSigToRaw(H("020105"), 32, E, CODE); }) === CODE);
  check("SEQUENCE with one child -> rejected", code(function () { sig.ecdsaSigToRaw(H("3003020105"), 32, E, CODE); }) === CODE);
  check("SEQUENCE with three children -> rejected", code(function () { sig.ecdsaSigToRaw(H("3009020101020102020103"), 32, E, CODE); }) === CODE);
  // A constructed r (an empty SEQUENCE where a primitive INTEGER is required) is rejected.
  check("constructed r (SEQUENCE in r's slot) -> rejected", code(function () { sig.ecdsaSigToRaw(H("3006" + "3000" + "020105"), 32, E, CODE); }) === CODE);
  check("empty input -> rejected", code(function () { sig.ecdsaSigToRaw(H(""), 32, E, CODE); }) === CODE);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
