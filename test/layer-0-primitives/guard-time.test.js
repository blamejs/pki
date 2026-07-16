// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard.time: fail-closed Date-instant validation before a temporal
 * comparison (the NaN-Date fail-open defence). Pins the guard's own contract: a
 * malformed Date is rejected via the caller's typed-error FACTORY BEFORE it can
 * reach a getTime() comparison (where its NaN would compare false and silently
 * accept), and within() throws on a malformed operand while returning a boolean
 * for in/out-of-window. An Invalid Date is built at runtime (new Date("x")) so the
 * source stays pure ASCII with no NaN literal.
 */

var helpers = require("../helpers");
var check = helpers.check;
var guard = require("../../lib/guard-all").time;

// A (code, message, cause) FACTORY -- the tier-appropriate currency guard.time takes
// (NEVER a defineClass class, which would crash `cannot be invoked without new`).
function E(code, message, cause) { var e = new Error(message); e.code = code; e.cause = cause; return e; }
function threw(fn) { try { fn(); return null; } catch (e) { return e.code || e.name; } }

function run() {
  var valid = new Date("2026-01-01T00:00:00Z");
  var invalid = new Date("not-a-date");   // Invalid Date: instanceof Date, NaN time
  var lower = new Date("2025-01-01T00:00:00Z");
  var upper = new Date("2027-01-01T00:00:00Z");

  // ==== assertValid ====
  check("1. assertValid returns the same Date for a valid Date", guard.assertValid(valid, E, "x/bad", "t") === valid);
  check("2. assertValid rejects an Invalid Date via the factory (not a silent pass)", threw(function () { guard.assertValid(invalid, E, "x/bad-time", "t"); }) === "x/bad-time");
  check("3. assertValid rejects a non-Date string", threw(function () { guard.assertValid("2026-01-01", E, "x/bad-time", "t"); }) === "x/bad-time");
  check("4. assertValid rejects a number", threw(function () { guard.assertValid(1735689600000, E, "x/bad-time", "t"); }) === "x/bad-time");
  check("5. assertValid rejects null and undefined", threw(function () { guard.assertValid(null, E, "x/bad-time", "t"); }) === "x/bad-time" && threw(function () { guard.assertValid(undefined, E, "x/bad-time", "t"); }) === "x/bad-time");

  // ==== within -- containment is a BOOLEAN, malformed is a THROW ====
  var mid = new Date("2026-06-01T00:00:00Z");
  check("6. within returns true for an in-window instant (half-open)", guard.within(mid, lower, upper, E, "x/bad", "t") === true);
  check("7. within returns false for an out-of-window instant", guard.within(new Date("2030-01-01T00:00:00Z"), lower, upper, E, "x/bad", "t") === false);
  // half-open [lower, upper): lower is IN, upper is OUT.
  check("8. within half-open: instant == lower -> true", guard.within(lower, lower, upper, E, "x/bad", "t") === true);
  check("9. within half-open: instant == upper -> false", guard.within(upper, lower, upper, E, "x/bad", "t") === false);
  // upperInclusive [lower, upper]: upper is IN (the certificate-validity shape).
  check("10. within upperInclusive: instant == upper -> true", guard.within(upper, lower, upper, E, "x/bad", "t", { upperInclusive: true }) === true);

  // within THROWS (not silently-false) on any malformed operand -- the fail-open the
  // guard exists to prevent: a NaN instant/bound must never read as out-of-window.
  check("11. within THROWS on a NaN instant (not a silent false)", threw(function () { guard.within(invalid, lower, upper, E, "x/bad-time", "t"); }) === "x/bad-time");
  check("12. within THROWS on a NaN lower bound", threw(function () { guard.within(mid, invalid, upper, E, "x/bad-time", "t"); }) === "x/bad-time");
  check("13. within THROWS on a NaN upper bound", threw(function () { guard.within(mid, lower, invalid, E, "x/bad-time", "t"); }) === "x/bad-time");
  // instant BEFORE the window -> false (the t >= lower branch is false).
  check("14. within returns false for an instant before the lower bound", guard.within(new Date("2020-01-01T00:00:00Z"), lower, upper, E, "x/bad", "t") === false);
  // opts present but WITHOUT upperInclusive -> half-open (opts truthy, upperInclusive falsy branch).
  check("15. within with opts={} is half-open: instant == upper -> false", guard.within(upper, lower, upper, E, "x/bad", "t", {}) === false);
  // no label supplied -> the (label || default) fallbacks are exercised.
  check("16. assertValid rejects with the default label when none is given", threw(function () { guard.assertValid(invalid, E, "x/bad-time"); }) === "x/bad-time");
  // A valid no-label call reaches the lower/upper assertValid lines so their (label || "window")
  // default is exercised; an invalid instant would throw before those lines.
  check("17. within with all-valid operands and no label returns a boolean", guard.within(mid, lower, upper, E, "x/bad") === true);
  // no-label throw path (the instant assertValid default label).
  check("18. within throws with the default label on a bad instant and no label", threw(function () { guard.within(invalid, lower, upper, E, "x/bad-time"); }) === "x/bad-time");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
