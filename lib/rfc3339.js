// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @internal
 * lib/rfc3339.js -- RFC 3339 date-time parsing + validation, a fail-closed engine primitive shared by
 * pki.acme (a boolean field-validator over server-supplied JSON) and pki.ct (parse a CT log-list
 * timestamp / temporal-interval bound to a comparable Date). Beyond the grammar it enforces CALENDAR
 * validity -- a syntactically well-formed but impossible instant (month 13, February 30, hour 25, a
 * :60 leap second, a +25:00 offset) is rejected, so a downstream expiry / window comparison never runs
 * on a value JS `Date` would silently roll over or `Date.parse` would NaN. Like the byte-reader / guard
 * family, `parse` takes the caller's `(code, message) -> error` factory so every consumer keeps its own
 * domain fault code.
 */

// Exactly `count` ASCII digits at `start`, as an integer, or null on any non-digit or short read.
// The grammar is decided character by character (no regex, whose match protocol re-dispatches through
// a replaceable `exec`); `\d` in the original is ASCII [0-9] only, matched here as 48..57.
function _digitsAt(v, start, count) {
  if (start + count > v.length) return null;
  var val = 0;
  for (var i = 0; i < count; i++) {
    var c = v.charCodeAt(start + i);
    if (c < 48 || c > 57) return null;
    val = val * 10 + (c - 48);
  }
  return val;
}

// RFC 3339 date-time scanned into its components, or null on any grammar violation:
// YYYY "-" MM "-" DD [Tt] HH ":" MM ":" SS, an optional "." + one-or-more fraction digits, then a
// zone -- [Zz] or ([+-]) OFFHH ":" OFFMM -- with nothing after. Calendar validity is checked by the
// caller. `offset` carries the numeric-offset hours/minutes when present, else null.
function _scanDateTime(v) {
  var n = v.length, p = 0;
  var year = _digitsAt(v, p, 4); if (year === null) return null; p += 4;
  if (v.charAt(p) !== "-") return null; p += 1;
  var month = _digitsAt(v, p, 2); if (month === null) return null; p += 2;
  if (v.charAt(p) !== "-") return null; p += 1;
  var day = _digitsAt(v, p, 2); if (day === null) return null; p += 2;
  var t = v.charAt(p); if (t !== "T" && t !== "t") return null; p += 1;
  var hour = _digitsAt(v, p, 2); if (hour === null) return null; p += 2;
  if (v.charAt(p) !== ":") return null; p += 1;
  var min = _digitsAt(v, p, 2); if (min === null) return null; p += 2;
  if (v.charAt(p) !== ":") return null; p += 1;
  var sec = _digitsAt(v, p, 2); if (sec === null) return null; p += 2;
  if (v.charAt(p) === ".") {   // optional fractional second: "." + one or more digits
    p += 1;
    var fracStart = p;
    while (p < n) { var fc = v.charCodeAt(p); if (fc < 48 || fc > 57) break; p += 1; }
    if (p === fracStart) return null;
  }
  var z = v.charAt(p), offset = null;
  if (z === "Z" || z === "z") {
    p += 1;
  } else if (z === "+" || z === "-") {
    p += 1;
    var offHour = _digitsAt(v, p, 2); if (offHour === null) return null; p += 2;
    if (v.charAt(p) !== ":") return null; p += 1;
    var offMin = _digitsAt(v, p, 2); if (offMin === null) return null; p += 2;
    offset = { hour: offHour, min: offMin };
  } else {
    return null;   // a zone is required
  }
  if (p !== n) return null;   // no trailing characters
  return { year: year, month: month, day: day, hour: hour, min: min, sec: sec, offset: offset };
}

// isValid(v) -> boolean: v is a syntactically well-formed AND calendar-valid RFC 3339 date-time string.
function isValid(v) {
  if (typeof v !== "string") return false;
  var t = _scanDateTime(v);
  if (!t) return false;
  if (t.month < 1 || t.month > 12) return false;
  // Reject a :60 leap second (Node's Date.parse returns NaN for it, so a comparison on such a value
  // would silently pass) and any hour/minute/second out of range.
  if (t.hour > 23 || t.min > 59 || t.sec > 59) return false;
  var leap = (t.year % 4 === 0 && t.year % 100 !== 0) || t.year % 400 === 0;
  var daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (t.day < 1 || t.day > daysInMonth[t.month - 1]) return false;
  if (t.offset) { if (t.offset.hour > 23 || t.offset.min > 59) return false; }   // a numeric zone offset must itself be valid
  return true;
}

// parse(v, E, code, label) -> Date: a calendar-valid RFC 3339 date-time as a comparable Date; otherwise
// throws E(code, message) (the caller's (code, message) factory). isValid guarantees `new Date(v)` is a
// real instant (never NaN), so a returned Date is always safe to compare.
function parse(v, E, code, label) {
  if (!isValid(v)) throw E(code, (label || "the value") + " is not a valid RFC 3339 date-time");
  return new Date(v);
}

// RFC 3339 sec. 5.6 `full-date`: a calendar date with no time component. A distinct production from
// the date-time above, and deliberately a separate pair of functions instead of a flag: a consumer
// that expects one and is handed the other has a malformed value, not a permissible variant.
// RFC 3339 full-date scanned into its components (YYYY "-" MM "-" DD, nothing after), or null.
function _scanFullDate(v) {
  var p = 0;
  var year = _digitsAt(v, p, 4); if (year === null) return null; p += 4;
  if (v.charAt(p) !== "-") return null; p += 1;
  var month = _digitsAt(v, p, 2); if (month === null) return null; p += 2;
  if (v.charAt(p) !== "-") return null; p += 1;
  var day = _digitsAt(v, p, 2); if (day === null) return null; p += 2;
  if (p !== v.length) return null;
  return { year: year, month: month, day: day };
}

// isValidDate(v) -> boolean: v is a syntactically well-formed AND calendar-valid RFC 3339 full-date.
// Calendar validity matters as much as shape: "2021-02-30" parses as a Date in JS by rolling over
// into March, so a shape-only check would silently accept a day that does not exist.
function isValidDate(v) {
  if (typeof v !== "string") return false;
  var t = _scanFullDate(v);
  if (!t) return false;
  if (t.month < 1 || t.month > 12) return false;
  var leap = (t.year % 4 === 0 && t.year % 100 !== 0) || t.year % 400 === 0;
  var daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return t.day >= 1 && t.day <= daysInMonth[t.month - 1];
}

// parseDate(v, E, code, label) -> Date at UTC midnight. Anchored explicitly at UTC ("T00:00:00Z")
// instead of left to `new Date("YYYY-MM-DD")`, so the instant does not shift with the host time
// zone. A freshness or rollback comparison must not depend on where it runs.
function parseDate(v, E, code, label) {
  if (!isValidDate(v)) throw E(code, (label || "the value") + " is not a valid RFC 3339 full-date (YYYY-MM-DD)");
  return new Date(v + "T00:00:00Z");
}

module.exports = { isValid: isValid, parse: parse, isValidDate: isValidDate, parseDate: parseDate };
