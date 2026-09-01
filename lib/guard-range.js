// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var _isSafeInteger = require("./guard-intrinsic").isSafeInteger;
var _freeze = require("./guard-intrinsic").freeze;
var _Number = require("./guard-intrinsic").Number;
var _BigInt = require("./guard-intrinsic").BigInt;

var UINT31_MAX = 2147483647n;
var SAFE_MAX   = 9007199254740991n;
var SAFE_MIN   = -9007199254740991n;
// (both spellings are flagged as a re-inline; see uint64's @guard-shape lines).
var UINT64_MAX = 18446744073709551615n;

// @enforced-by guard-shape-reinlined
// @guard-shape 2147483647n
function int(value, min, max, E, code, label) {
  if (typeof min !== "bigint" || typeof max !== "bigint") {
    throw new TypeError("guard.range.int: the min/max bounds must be BigInt");
  }
  if (max > SAFE_MAX) {
    throw new TypeError("guard.range.int: max " + max + " exceeds the safe-integer ceiling; use a BigInt-preserving guard");
  }
  if (min < SAFE_MIN) {
    throw new TypeError("guard.range.int: min " + min + " is below the safe-integer floor; use a BigInt-preserving guard");
  }
  if (typeof value !== "bigint" || value < min || value > max) {
    throw E(code, label + " must be an integer within " + min + ".." + max);
  }
  return _Number(value);
}

// @enforced-by guard-shape-reinlined  (shares the 2147483647n shape declared on int)
function uint31(value, E, code, label) { return int(value, 0n, UINT31_MAX, E, code, label); }

// @enforced-by guard-shape-reinlined  (shares the 2147483647n shape declared on int)
function positiveInt31(value, E, code, label) { return int(value, 1n, UINT31_MAX, E, code, label); }

// @enforced-by guard-shape-reinlined
// @guard-shape 18446744073709551615n
// @guard-shape 0xffffffffffffffffn
function uint64(value, E, code, label) {
  var v;
  if (typeof value === "bigint") {
    v = value;
  } else if (typeof value === "number" && _isSafeInteger(value) && value >= 0) {
    v = _BigInt(value);
  } else {
    throw E(code, label + " must be a non-negative safe-integer Number or a BigInt (a uint64)");
  }
  if (v < 0n || v > UINT64_MAX) {
    throw E(code, label + " must be a uint64 in [0, 2^64)");
  }
  return v;
}

// @enforced-by guard-shape-reinlined
// @guard-shape Number\.isSafeInteger\(\s*[A-Za-z_$][\w$]*\s*\)\s*\)\s*return BigInt
function authoredInteger(value, E, code, label) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && _isSafeInteger(value)) return _BigInt(value);
  throw E(code, label + " must be an integer (a safe-integer number, or a bigint for a large value)");
}

module.exports = _freeze({
  int: int, uint31: uint31, positiveInt31: positiveInt31, uint64: uint64,
  authoredInteger: authoredInteger,
});
