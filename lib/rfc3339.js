// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @internal
 * lib/rfc3339.js: RFC 3339 date-time parsing + validation, a fail-closed engine primitive shared by
 * pki.acme (a boolean field-validator over server-supplied JSON) and pki.ct (parse a CT log-list
 * timestamp / temporal-interval bound to a comparable Date). Beyond the grammar it enforces CALENDAR
 * validity: a syntactically well-formed but impossible instant (month 13, February 30, hour 25, a
 * :60 leap second, a +25:00 offset) is rejected, so a downstream expiry / window comparison never runs
 * on a value JS `Date` would silently roll over or `Date.parse` would NaN. Like the byte-reader / guard
 * family, `parse` takes the caller's `(code, message) -> error` factory so every consumer keeps its own
 * domain fault code.
 */

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
  if (v.charAt(p) === ".") {
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
    return null;
  }
  if (p !== n) return null;
  return { year: year, month: month, day: day, hour: hour, min: min, sec: sec, offset: offset };
}

function isValid(v) {
  if (typeof v !== "string") return false;
  var t = _scanDateTime(v);
  if (!t) return false;
  if (t.month < 1 || t.month > 12) return false;
  if (t.hour > 23 || t.min > 59 || t.sec > 59) return false;
  var leap = (t.year % 4 === 0 && t.year % 100 !== 0) || t.year % 400 === 0;
  var daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (t.day < 1 || t.day > daysInMonth[t.month - 1]) return false;
  if (t.offset) { if (t.offset.hour > 23 || t.offset.min > 59) return false; }
  return true;
}

function parse(v, E, code, label) {
  if (!isValid(v)) throw E(code, (label || "the value") + " is not a valid RFC 3339 date-time");
  return new Date(v);
}

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

function isValidDate(v) {
  if (typeof v !== "string") return false;
  var t = _scanFullDate(v);
  if (!t) return false;
  if (t.month < 1 || t.month > 12) return false;
  var leap = (t.year % 4 === 0 && t.year % 100 !== 0) || t.year % 400 === 0;
  var daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return t.day >= 1 && t.day <= daysInMonth[t.month - 1];
}

function parseDate(v, E, code, label) {
  if (!isValidDate(v)) throw E(code, (label || "the value") + " is not a valid RFC 3339 full-date (YYYY-MM-DD)");
  return new Date(v + "T00:00:00Z");
}

module.exports = { isValid: isValid, parse: parse, isValidDate: isValidDate, parseDate: parseDate };
