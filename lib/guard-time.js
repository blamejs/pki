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
var _dateToISOString = require("./guard-intrinsic").uncurry(Date.prototype.toISOString);
var _charCodeAt = require("./guard-intrinsic").uncurry(String.prototype.charCodeAt);
var _Number = require("./guard-intrinsic").Number;
var constants = require("./constants");
/** @internal RFC 3161 clause 2.4.2 states an Accuracy's third field in microseconds, which no
 *  `C.TIME` scale names because no PKI structure carries a microsecond duration anywhere else. */
var MICROS_PER_MILLISECOND = 1000;
var _dateUTC = Date.UTC;
var _floor = Math.floor;
var _ceil = Math.ceil;
/** @internal A DER GeneralizedTime carries a four-digit year and a UTCTime a narrower one, so a Date
 *  outside 0000..9999 has no PKI encoding. */
var DER_YEAR_MIN = 0, DER_YEAR_MAX = 9999;

// @enforced-by guard-shape-reinlined
// @guard-shape \.getTime\s*\(
function instantOf(value) { return _dateGetTime(value); }

/** The instant an error message or a verdict names, rendered through the operation captured at load.
 *  A replaced `toISOString` chooses the time a refusal reports, which is what an operator reads when
 *  deciding whether the refusal was right, so the rendering is taken from the same place every other
 *  read of a Date is.
 *
 * @enforced-by behavioral -- the live-read budget each module declares is what holds a call-time
 * `toISOString` out of a converted file; a `@guard-shape` here would name the read in every module
 * that renders a date and the budget already answers for those.
 */
function isoOf(value) { return _dateToISOString(value); }

/** The instant a DER GeneralizedTime names, rounded UP to the next whole millisecond where its
 *  fractional seconds carry a digit a `Date` cannot hold. `fraction` is the fraction's digit string;
 *  the first three digits ARE the milliseconds, so a nonzero digit after them puts the real instant
 *  strictly between `value` and `value + 1ms`.
 *
 *  An upper bound is decided against this rather than against the Date, because the Date truncates:
 *  a time stamped at `...000000.000001Z` reads as `...000000.000Z`, which compares equal to a bound
 *  of `...000000Z` and so passes an "after the bound" test it is on the wrong side of. The two
 *  consumers are the timestamp verifier's own check of the authority's certificate window and the
 *  signature-timestamp row's check of the signing certificate's expiry.
 *
 * @enforced-by behavioral -- a truncating comparison has no rename-proof shape; the RED vector is a
 * token minted with a sub-millisecond fraction one tick past a certificate's notAfter.
 */
function ceilInstantOf(value, fraction) { return latestInstantOf(value, fraction, null); }

/** @internal The part of a DER GeneralizedTime's fractional seconds a `Date` cannot hold, in whole
 *  microseconds. The first three digits ARE the milliseconds; the next three are microseconds, and
 *  anything finer than a microsecond counts as one, since a bound is only a bound if it is not
 *  exceeded. Read digit by digit through the captured accessor: a fraction is caller bytes. */
function _fractionMicros(fraction) {
  if (typeof fraction !== "string" || fraction.length <= 3) return 0;
  var micros = 0;
  var finer = false;
  for (var i = 3; i < fraction.length; i++) {
    var c = _charCodeAt(fraction, i);
    if (c < 48 || c > 57) break;
    var digit = c - 48;
    if (i === 3) micros += digit * 100;
    else if (i === 4) micros += digit * 10;
    else if (i === 5) micros += digit;
    else if (digit > 0) finer = true;
  }
  return finer ? micros + 1 : micros;
}

/** The LATEST instant a timestamp could have been created at: its `genTime` ceiling plus the
 *  accuracy the token states. RFC 3161 clause 2.4.2 defines accuracy as the bound on the difference
 *  between the stated time and the real one, so a token saying it is accurate to two seconds places
 *  its creation anywhere in a four-second window, and an upper bound that reads only `genTime`
 *  concludes something the token does not establish. `accuracy` is the parsed `{ seconds, millis,
 *  micros }` or null; `seconds` arrives as a BigInt, the other two as numbers, and a micros
 *  remainder rounds up because a bound is only a bound if it is not exceeded.
 *
 * @enforced-by behavioral -- a bound that ignores a field has no rename-proof shape; the RED vector
 * is a token whose genTime precedes a certificate's notAfter while its accuracy window does not.
 */
function latestInstantOf(value, fraction, accuracy) {
  var at = instantOf(value);
  var ms = 0;
  /** @internal The sub-millisecond parts are summed and rounded ONCE. Rounding the genTime fraction
   *  and the accuracy up separately overstates the bound by a millisecond when both carry one, which
   *  refuses a token whose real window ends before the instant it is compared against. */
  var micros = _fractionMicros(fraction);
  if (accuracy !== null && typeof accuracy === "object") {
    if (typeof accuracy.seconds === "bigint") ms += constants.TIME.seconds(_Number(accuracy.seconds));
    else if (typeof accuracy.seconds === "number") ms += constants.TIME.seconds(accuracy.seconds);
    if (typeof accuracy.millis === "number") ms += constants.TIME.milliseconds(accuracy.millis);
    if (typeof accuracy.micros === "number") micros += accuracy.micros;
  }
  if (micros > 0) ms += _ceil(micros / MICROS_PER_MILLISECOND);
  return ms > 0 ? at + ms : at;
}

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
  isoOf: isoOf,
  ceilInstantOf: ceilInstantOf,
  latestInstantOf: latestInstantOf,
  isDate: isDate,
  toDate: toDate,
  within: within,
});
