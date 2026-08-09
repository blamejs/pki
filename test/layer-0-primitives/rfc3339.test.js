// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for lib/rfc3339.js -- the shared RFC 3339 date reader every consumer that
// compares an expiry, a freshness window or a rollback counter parses through. Two productions,
// deliberately separate: sec. 5.6 `date-time` (a date, a time and a zone) and sec. 5.6 `full-date`
// (a calendar date alone). A consumer handed the wrong one has a malformed value, not a variant.
//
// The vectors that matter most are the ones JS would silently accept: `new Date("2021-02-30")`
// rolls over into March rather than failing, and `Date.parse` returns NaN for a :60 leap second --
// so a shape-only check would hand a downstream comparison a value that is wrong or not a number.

var rfc3339 = require("../../lib/rfc3339");
var helpers = require("../helpers");
var check = helpers.check;

function E(code, message) { var e = new Error(message); e.code = code; return e; }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

function run() {
  // ---- date-time (sec. 5.6) ----
  check("date-time: a UTC instant is valid", rfc3339.isValid("2026-08-09T12:00:00Z"));
  check("date-time: a numeric offset is valid", rfc3339.isValid("2026-08-09T12:00:00+02:00"));
  check("date-time: a fractional second is valid", rfc3339.isValid("2026-08-09T12:00:00.250Z"));
  check("date-time: lower-case t and z are valid", rfc3339.isValid("2026-08-09t12:00:00z"));
  check("date-time: a missing zone is refused", !rfc3339.isValid("2026-08-09T12:00:00"));
  check("date-time: a bare date is refused by the date-time reader", !rfc3339.isValid("2026-08-09"));
  // A :60 leap second is where Date.parse returns NaN, so accepting it would poison a comparison.
  check("date-time: a :60 leap second is refused", !rfc3339.isValid("2026-12-31T23:59:60Z"));
  check("date-time: an out-of-range hour is refused", !rfc3339.isValid("2026-08-09T24:00:00Z"));
  check("date-time: an out-of-range zone offset is refused", !rfc3339.isValid("2026-08-09T12:00:00+25:00"));
  check("date-time: a non-string is refused", !rfc3339.isValid(20260809));
  check("date-time: parse yields a comparable instant",
    rfc3339.parse("2026-08-09T12:00:00Z", E, "x/bad", "t").getTime() === Date.UTC(2026, 7, 9, 12, 0, 0));
  check("date-time: parse throws the caller's code", code(function () { rfc3339.parse("nope", E, "x/bad", "t"); }) === "x/bad");

  // ---- full-date (sec. 5.6) ----
  check("full-date: a calendar date is valid", rfc3339.isValidDate("2026-08-09"));
  check("full-date: a date-time is refused by the full-date reader", !rfc3339.isValidDate("2026-08-09T12:00:00Z"));
  check("full-date: a non-string is refused", !rfc3339.isValidDate(20260809));
  check("full-date: a short year is refused", !rfc3339.isValidDate("226-08-09"));
  check("full-date: month 00 and 13 are refused", !rfc3339.isValidDate("2026-00-09") && !rfc3339.isValidDate("2026-13-09"));
  check("full-date: day 00 is refused", !rfc3339.isValidDate("2026-08-00"));
  // The headline case: JS would roll this into 2 March rather than reject it.
  check("full-date: 2021-02-30 is refused rather than rolled over", !rfc3339.isValidDate("2021-02-30"));
  check("full-date: 2026-04-31 is refused (April has 30 days)", !rfc3339.isValidDate("2026-04-31"));
  // Leap-year arithmetic, including the century rules both ways.
  check("full-date: 2024-02-29 is valid (a leap year)", rfc3339.isValidDate("2024-02-29"));
  check("full-date: 2023-02-29 is refused (not a leap year)", !rfc3339.isValidDate("2023-02-29"));
  check("full-date: 2000-02-29 is valid (a 400-year leap year)", rfc3339.isValidDate("2000-02-29"));
  check("full-date: 1900-02-29 is refused (a 100-year non-leap year)", !rfc3339.isValidDate("1900-02-29"));
  // Anchored at UTC explicitly, so the instant does not shift with the host time zone -- a freshness
  // comparison must not depend on where it runs.
  check("full-date: parseDate anchors at UTC midnight",
    rfc3339.parseDate("2026-08-09", E, "x/bad", "d").getTime() === Date.UTC(2026, 7, 9, 0, 0, 0));
  check("full-date: parseDate throws the caller's code",
    code(function () { rfc3339.parseDate("2021-02-30", E, "x/bad", "d"); }) === "x/bad");
  check("full-date: parseDate refuses a date-time",
    code(function () { rfc3339.parseDate("2026-08-09T00:00:00Z", E, "x/bad", "d"); }) === "x/bad");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
