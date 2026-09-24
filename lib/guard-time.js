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
var _dateGetUTCMonth = require("./guard-intrinsic").uncurry(Date.prototype.getUTCMonth);
var _dateGetUTCDate = require("./guard-intrinsic").uncurry(Date.prototype.getUTCDate);
var _dateGetUTCHours = require("./guard-intrinsic").uncurry(Date.prototype.getUTCHours);
var _dateGetUTCMinutes = require("./guard-intrinsic").uncurry(Date.prototype.getUTCMinutes);
var _dateGetUTCSeconds = require("./guard-intrinsic").uncurry(Date.prototype.getUTCSeconds);
var _dateGetUTCMilliseconds = require("./guard-intrinsic").uncurry(Date.prototype.getUTCMilliseconds);
var _dateSetUTCFullYear = require("./guard-intrinsic").uncurry(Date.prototype.setUTCFullYear);
var _dateUTC = Date.UTC;
var _floor = Math.floor;
var _ceil = Math.ceil;
/** @internal A DER GeneralizedTime carries a four-digit year and a UTCTime a narrower one, so a Date
 *  outside 0000..9999 has no PKI encoding. */
var DER_YEAR_MIN = 0, DER_YEAR_MAX = 9999;

// @enforced-by guard-shape-reinlined
// @guard-shape \.getTime\s*\(
function instantOf(value) { return _dateGetTime(value); }

// @enforced-by nan-date-comparison-unguarded
function assertValid(value, E, code, label) {
  if (!util.types.isDate(value) || _isNaN(instantOf(value))) {
    throw E(code, (label || "value") + " must be a valid Date");
  }
  return value;
}

// @enforced-by behavioral -- the year bound has no rename-proof code shape; a RED vector per producer route is the guard
/** @internal The guard for a Date a verb WRITES as a DER time: `assertValid`, then the year is held
 *  to DER_YEAR_MIN..DER_YEAR_MAX so the refusal carries the caller's code before the codec sees the
 *  value. Each producer route has a vector that a year-10000 Date reports the verb's own bad-input
 *  code, never asn1/bad-generalizedtime. A Date a verb only compares against (a verification clock)
 *  passes `assertValid` alone, and has a vector that the same Date is accepted and compared. */
function assertEncodable(value, E, code, label) {
  assertValid(value, E, code, label);
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

// @enforced-by behavioral -- reading a month and adding to it is also how a date renderer prints one, so the arithmetic has no rename-proof shape a detector can tell from `getUTCMonth() + 1`; the clamping and year-borrow vectors in guard-time.test.js are the guard
/** @internal The instant `months` calendar months after a valid Date, clamped to the last day of
 *  the target month where that month is shorter, so 31 January plus one month gives 28 or 29
 *  February. A ceiling stated in months has no reading in days, since how many days 39 months hold
 *  depends on which 39. Time of day is carried through unchanged. */
function addMonths(value, months, E, code, label) {
  assertValid(value, E, code, label);
  var year = _dateGetUTCFullYear(value);
  var month = _dateGetUTCMonth(value) + months;
  var day = _dateGetUTCDate(value);
  var carry = _floorDiv(month, 12);
  var targetYear = year + carry;
  var targetMonth = month - carry * 12;
  var lastDay = _daysInMonth(targetYear, targetMonth);
  /** @internal Date.UTC reads a year of 0..99 as 1900..1999, and a DER time carries 0000..9999, so
   * the date is built at a safe year and the real one is set with the month and day together. One
   * call sets all three, where setting the year alone would roll 29 February out of a leap year the
   * remap had landed on. */
  var out = new _Date(_dateUTC(2000, 0, 1,
    _dateGetUTCHours(value), _dateGetUTCMinutes(value), _dateGetUTCSeconds(value),
    _dateGetUTCMilliseconds(value)));
  _dateSetUTCFullYear(out, targetYear, targetMonth, day < lastDay ? day : lastDay);
  return out;
}
var _MONTH_DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
/** @internal The proleptic Gregorian leap rule the Date object follows, so year 0 is a leap year
 *  and year 1900 is not. */
function _daysInMonth(year, month) {
  if (month !== 1) return _MONTH_DAYS[month];
  return ((year % 4 === 0 && year % 100 !== 0) || year % 400 === 0) ? 29 : 28;
}
/** @internal Integer division that rounds toward negative infinity, so a month index before
 *  January of the starting year borrows a year rather than truncating toward zero. */
function _floorDiv(a, b) {
  var q = a / b;
  var f = q < 0 ? -_ceil(-q) : _floor(q);
  return f;
}

// @enforced-by behavioral -- a coercion-safe Date converter has no rename-proof code shape; the RED vector (a caller value with no numeric or string form, a BigInt or a throwing Symbol.toPrimitive, becomes an invalid Date the downstream isNaN check rejects, never a native TypeError out of the Date constructor) is the guard.
function toDate(value) {
  if (util.types.isDate(value)) return value;
  if (typeof value === "string" || typeof value === "number") return new _Date(value);
  return new _Date(NaN);
}

module.exports = _freeze({
  assertValid: assertValid,
  assertEncodable: assertEncodable,
  addMonths: addMonths,
  instantOf: instantOf,
  isDate: isDate,
  toDate: toDate,
  within: within,
});
