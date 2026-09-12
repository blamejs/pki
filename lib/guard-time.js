// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var _create = require("./guard-intrinsic").create;
var _assign = require("./guard-intrinsic").assign;
var util = _assign(_create(null), { types: require("./guard-intrinsic").types });
var _freeze = require("./guard-intrinsic").freeze;
var _isNaN = Number.isNaN;
var _Date = Date;

var _dateGetTime = require("./guard-intrinsic").uncurry(Date.prototype.getTime);
var _dateGetUTCFullYear = require("./guard-intrinsic").uncurry(Date.prototype.getUTCFullYear);
/** @internal A DER GeneralizedTime carries a four-digit year and a UTCTime a narrower one, so a Date
 *  outside 0000..9999 has no PKI encoding. It is refused where the Date is validated, in the caller's
 *  own domain, rather than reaching the codec and surfacing as an asn1/* error out of a typed spec. */
var DER_YEAR_MIN = 0, DER_YEAR_MAX = 9999;

// @enforced-by guard-shape-reinlined
// @guard-shape \.getTime\s*\(
function instantOf(value) { return _dateGetTime(value); }

// @enforced-by nan-date-comparison-unguarded
function assertValid(value, E, code, label) {
  if (!util.types.isDate(value) || _isNaN(instantOf(value))) {
    throw E(code, (label || "value") + " must be a valid Date");
  }
  var year = _dateGetUTCFullYear(value);
  if (year < DER_YEAR_MIN || year > DER_YEAR_MAX) {
    throw E(code, (label || "value") + " year " + year + " is outside " + DER_YEAR_MIN + ".." + DER_YEAR_MAX + ", the range a DER time can carry");
  }
  return value;
}

// @enforced-by nan-date-comparison-unguarded
function within(instant, lower, upper, E, code, label, opts) {
  assertValid(instant, E, code, label);
  assertValid(lower, E, code, (label || "window") + " lower bound");
  assertValid(upper, E, code, (label || "window") + " upper bound");
  var t = instantOf(instant);
  var lo = instantOf(lower);
  var hi = instantOf(upper);
  return t >= lo && (opts && opts.upperInclusive ? t <= hi : t < hi);
}

// @enforced-by behavioral -- a prototype test in place of a slot test has no rename-proof code
function isDate(value) {
  return util.types.isDate(value);
}

// @enforced-by behavioral -- a coercion-safe Date converter has no rename-proof code shape; the RED vector (a caller value with no numeric or string form, a BigInt or a throwing Symbol.toPrimitive, becomes an invalid Date the downstream isNaN check rejects, never a native TypeError out of the Date constructor) is the guard.
function toDate(value) {
  if (util.types.isDate(value)) return value;
  if (typeof value === "string" || typeof value === "number") return new _Date(value);
  return new _Date(NaN);
}

module.exports = _freeze({
  assertValid: assertValid,
  instantOf: instantOf,
  isDate: isDate,
  toDate: toDate,
  within: within,
});
