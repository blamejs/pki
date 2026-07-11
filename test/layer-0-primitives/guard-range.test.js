// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-range (@internal): fail-closed bound + atomic narrow of an
 * untrusted DECODED ASN.1 INTEGER before it becomes a JS Number.
 * Oracle: the safe-integer band [-(2^53-1), 2^53-1] and the [min,max] contract.
 *
 * Two tiers are exercised: the config-time AUTHORING guard (a developer wiring
 * a range wider than the safe-narrow band gets a TypeError -- BOTH ends), and
 * the parse-time REJECT (out-of-range decoded content throws the caller's typed
 * PkiError). The authoring guard is unreachable through any parser call site
 * (no format wires a min below the floor), so a direct unit vector is the only
 * place it can be pinned.
 */

var range = require("../../lib/guard-range");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError");
// The (code, message) typed-error factory a caller injects as guard-range's E
// (defineClass subclasses take (code, message)).
function E(code, message) { return new TestError(code, message); }

var SAFE_MAX = 9007199254740991n;   // 2^53 - 1
var SAFE_MIN = -9007199254740991n;  // -(2^53 - 1)

function typeErr(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e instanceof TypeError ? "TYPE" : (e.code || "OTHER"); } }
function pkiCode(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testAuthoringBounds() {
  // Upper end: a max past the safe ceiling is a wiring error -> TypeError.
  check("int: max > 2^53-1 throws TypeError",
    typeErr(function () { range.int(0n, 0n, SAFE_MAX + 1n, E, "x/bad", "f"); }) === "TYPE");
  // Lower end (the symmetric guard): a min below the safe FLOOR narrows lossy
  // exactly as a too-high max does, so it must throw at authoring time too.
  check("int: min < -(2^53-1) throws TypeError",
    typeErr(function () { range.int(0n, SAFE_MIN - 1n, 100n, E, "x/bad", "f"); }) === "TYPE");
  // The band edges themselves are lossless -> authorable, and narrow exactly.
  check("int: max == 2^53-1 is authorable + narrows exactly",
    range.int(SAFE_MAX, 0n, SAFE_MAX, E, "x/bad", "f") === Number(SAFE_MAX));
  check("int: min == -(2^53-1) is authorable + narrows exactly",
    range.int(SAFE_MIN, SAFE_MIN, 0n, E, "x/bad", "f") === Number(SAFE_MIN));
  // Non-BigInt bounds are an authoring fault: a NaN min/max compares false
  // against every BigInt, silently disabling the range -- the guard would
  // narrow ANY value. Reject at authoring time like the band checks above.
  check("int: NaN bounds throw TypeError",
    typeErr(function () { range.int(5n, NaN, NaN, E, "x/bad", "f"); }) === "TYPE");
  check("int: Number bounds throw TypeError",
    typeErr(function () { range.int(5n, 0, 10, E, "x/bad", "f"); }) === "TYPE");
}

function testParseReject() {
  // Parse-time: out-of-range decoded content -> the caller's typed PkiError.
  check("int: value above max -> typed code", pkiCode(function () { range.int(50n, 0n, 10n, E, "x/oob", "f"); }) === "x/oob");
  check("int: value below min -> typed code", pkiCode(function () { range.int(-1n, 0n, 10n, E, "x/oob", "f"); }) === "x/oob");
  check("int: non-bigint value -> typed code", pkiCode(function () { range.int(5, 0n, 10n, E, "x/oob", "f"); }) === "x/oob");
  check("int: in-range value narrows exactly", range.int(7n, 0n, 10n, E, "x/oob", "f") === 7);
}

function testShapes() {
  check("uint31: 0 accepted", range.uint31(0n, E, "x/oob", "f") === 0);
  check("uint31: 2^31-1 accepted", range.uint31(2147483647n, E, "x/oob", "f") === 2147483647);
  check("uint31: 2^31 rejected", pkiCode(function () { range.uint31(2147483648n, E, "x/oob", "f"); }) === "x/oob");
  check("uint31: -1 rejected", pkiCode(function () { range.uint31(-1n, E, "x/oob", "f"); }) === "x/oob");
  check("positiveInt31: 0 rejected (count of at least one)", pkiCode(function () { range.positiveInt31(0n, E, "x/oob", "f"); }) === "x/oob");
  check("positiveInt31: 1 accepted", range.positiveInt31(1n, E, "x/oob", "f") === 1);
}

function testUint64() {
  var U64_MAX = 18446744073709551615n;   // 2^64 - 1
  // BigInt in range is returned unchanged (never narrowed to a lossy Number).
  check("uint64: a BigInt in range is returned as a BigInt", range.uint64(U64_MAX, E, "x/oob", "f") === U64_MAX);
  check("uint64: zero accepted", range.uint64(0n, E, "x/oob", "f") === 0n);
  // A non-negative safe-integer Number is widened to a BigInt.
  check("uint64: a safe-integer Number widens to BigInt", range.uint64(42, E, "x/oob", "f") === 42n);
  // Out of range / wrong kind -> the caller's typed PkiError.
  check("uint64: 2^64 rejected", pkiCode(function () { range.uint64(U64_MAX + 1n, E, "x/oob", "f"); }) === "x/oob");
  check("uint64: negative rejected", pkiCode(function () { range.uint64(-1n, E, "x/oob", "f"); }) === "x/oob");
  check("uint64: a Number past 2^53 rejected (precision already lost)", pkiCode(function () { range.uint64(Number.MAX_SAFE_INTEGER + 2, E, "x/oob", "f"); }) === "x/oob");
  check("uint64: a fractional Number rejected", pkiCode(function () { range.uint64(1.5, E, "x/oob", "f"); }) === "x/oob");
  check("uint64: a string rejected", pkiCode(function () { range.uint64("1", E, "x/oob", "f"); }) === "x/oob");
}

function run() {
  testAuthoringBounds();
  testParseReject();
  testShapes();
  testUint64();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
