// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard.time: fail-closed Date-instant validation before a temporal
 * comparison (the NaN-Date fail-open defense). Pins the guard's own contract: a
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

  // A value that inherits from Date.prototype and holds no instant. `instanceof Date` says yes
  // to it, so a guard keyed on that runs `getTime()` on it and the raw TypeError that method
  // throws escapes as itself, out of a boundary whose contract is a typed error.
  var lookalike = Object.create(Date.prototype);
  check("19. a Date lookalike passes instanceof, which is why that test is not the one used",
        lookalike instanceof Date === true);
  check("20. isDate reads the slot, so it says no to one", guard.isDate(lookalike) === false);
  check("21. and yes to a real Date, valid or invalid",
        guard.isDate(valid) === true && guard.isDate(invalid) === true);
  check("22. assertValid refuses a lookalike with the caller's code, not a raw TypeError",
        threw(function () { guard.assertValid(lookalike, E, "x/bad-time", "t"); }) === "x/bad-time");
  check("23. within refuses one as an instant", threw(function () { guard.within(lookalike, lower, upper, E, "x/bad-time", "t"); }) === "x/bad-time");
  check("24. and as either bound",
        threw(function () { guard.within(mid, lookalike, upper, E, "x/bad-time", "t"); }) === "x/bad-time" &&
        threw(function () { guard.within(mid, lower, lookalike, E, "x/bad-time", "t"); }) === "x/bad-time");
  // A Date built in another realm has that realm's prototype, so the same identity-shaped test
  // misses it in the other direction and calls a real instant no Date at all.
  var foreignDate = require("vm").runInNewContext("new Date(0)");
  check("25. a Date from another realm fails instanceof", foreignDate instanceof Date === false);
  check("26. isDate accepts it, because the slot is what holds the instant",
        guard.isDate(foreignDate) === true && guard.assertValid(foreignDate, E, "x/bad", "t") === foreignDate);

  // The instant is read from the slot, never through the value's `getTime`. That is an ordinary
  // method on Date.prototype, so a subclass or an own property answers it: one that threw left
  // this guard through the caller's own exception, and one that answered differently on each call
  // made the instant validated and the instant compared two different reads of one argument.
  var Throwing = class extends Date { getTime() { throw new RangeError("planted"); } };
  check("27. assertValid accepts a Date whose getTime override throws",
        guard.assertValid(new Throwing(1000), E, "x/bad", "t") instanceof Throwing);
  check("28. and refuses one holding no instant however its override answers",
        threw(function () {
          var Lying = class extends Date { getTime() { return 1000; } };
          guard.assertValid(new Lying("not-a-date"), E, "x/bad-time", "t");
        }) === "x/bad-time");
  var reads = 0;
  var Drifting = class extends Date { getTime() { reads++; return reads === 1 ? 1000 : 9e15; } };
  check("29. within compares the instant the value holds, not the one its override reports",
        guard.within(new Drifting(1000), new Date(0), new Date(2000), E, "x/bad", "t") === true);
  check("30. and the override was never called", reads === 0);
  check("31. instantOf reads the slot through the intrinsic",
        guard.instantOf(new Drifting(1234)) === 1234);

  // ==== toDate -- coercion-safe conversion: never invokes the Date constructor on a
  // value it would throw on, so a pathological caller option becomes an Invalid Date
  // the downstream isNaN(instantOf(...)) check refuses with the caller's typed error.
  var invalidInstant = function (dt) { return Number.isNaN(guard.instantOf(dt)); };
  check("32. toDate returns the same Date for a real Date", guard.toDate(valid) === valid);
  check("33. toDate converts a numeric timestamp to a valid Date", guard.instantOf(guard.toDate(0)) === 0);
  check("34. toDate converts an ISO string to a valid Date", guard.instantOf(guard.toDate("2026-01-01T00:00:00Z")) === guard.instantOf(valid));
  check("35. toDate yields an Invalid Date (not a throw) for a BigInt", invalidInstant(guard.toDate(1n)));
  check("36. toDate yields an Invalid Date for an Object.create(null)", invalidInstant(guard.toDate(Object.create(null))));
  check("37. toDate yields an Invalid Date for a symbol", invalidInstant(guard.toDate(Symbol("t"))));
  // A value whose Symbol.toPrimitive throws must never be coerced; toDate never touches it.
  var hostileSym = 0; var poison = {};
  Object.defineProperty(poison, Symbol.toPrimitive, { value: function () { hostileSym = 1; throw new RangeError("poison"); } });
  check("38. toDate yields an Invalid Date for a throwing-toPrimitive value without invoking it",
        invalidInstant(guard.toDate(poison)) && hostileSym === 0);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
