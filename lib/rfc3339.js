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

// date "T" time with a zone (Z or a numeric offset); an optional fractional second.
var RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/;

// isValid(v) -> boolean: v is a syntactically well-formed AND calendar-valid RFC 3339 date-time string.
function isValid(v) {
  if (typeof v !== "string") return false;
  var m = RFC3339_RE.exec(v);
  if (!m) return false;
  var year = +m[1], month = +m[2], day = +m[3], hour = +m[4], min = +m[5], sec = +m[6];
  if (month < 1 || month > 12) return false;
  // Reject a :60 leap second (Node's Date.parse returns NaN for it, so a comparison on such a value
  // would silently pass) and any hour/minute/second out of range.
  if (hour > 23 || min > 59 || sec > 59) return false;
  var leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  var daysInMonth = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day < 1 || day > daysInMonth[month - 1]) return false;
  if (m[7]) { if (+m[8] > 23 || +m[9] > 59) return false; }   // a numeric zone offset must itself be valid
  return true;
}

// parse(v, E, code, label) -> Date: a calendar-valid RFC 3339 date-time as a comparable Date; otherwise
// throws E(code, message) (the caller's (code, message) factory). isValid guarantees `new Date(v)` is a
// real instant (never NaN), so a returned Date is always safe to compare.
function parse(v, E, code, label) {
  if (!isValid(v)) throw E(code, (label || "the value") + " is not a valid RFC 3339 date-time");
  return new Date(v);
}

module.exports = { isValid: isValid, parse: parse };
