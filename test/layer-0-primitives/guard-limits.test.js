// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-limits (@internal): config-time resource-cap validation +
 * the parse-time item counter. The decode-rejects-a-bad-cap contract is
 * exercised behaviorally through the composing decoders (asn1 / cbor / the
 * path-validate entry points); these pin the guard's OWN authoring edges: a
 * malformed bound handed to the guard must throw a config-time TypeError, never
 * silently disable the check it configures.
 */

var limits = require("../../lib/guard-limits");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;

var TestError = errors.defineClass("TestError");
function E(code, message) { return new TestError(code, message); }
function typeErr(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e instanceof TypeError ? "TYPE" : (e.code || "OTHER"); } }

function testCap() {
  check("undefined value returns the default", limits.cap(undefined, "k", 7) === 7);
  check("valid value passes", limits.cap(5, "k", 7) === 5);
  check("negative value throws TypeError", typeErr(function () { limits.cap(-1, "k", 7); }) === "TYPE");
  check("fractional value throws TypeError", typeErr(function () { limits.cap(1.5, "k", 7); }) === "TYPE");
  // opts bounds + typed-error currency.
  check("opts.min binds", typeErr(function () { limits.cap(0, "k", 7, { E: E, code: "x/oob", min: 1 }); }) === "x/oob");
  check("opts.max binds", typeErr(function () { limits.cap(8, "k", 7, { E: E, code: "x/oob", min: 0, max: 7 }); }) === "x/oob");
  // The bound is read ONCE, into the value both the integer check and the comparison use. Read
  // twice, the check saw one bound and the comparison another, so an `opts` whose `max` answers a
  // valid small integer to the type check and a large one to the comparison configured a cap that
  // admitted a value above the bound it had just been validated against. Every call site in lib/
  // passes an inline literal, so this was not reachable through any shipped verb; the guard is the
  // thing that has to hold for the next call site.
  var maxReads = 0;
  var steerable = { E: E, code: "x/oob", min: 0 };
  Object.defineProperty(steerable, "max", {
    enumerable: true,
    get: function () { maxReads += 1; return maxReads === 1 ? 7 : 1e9; },
  });
  check("a steerable opts.max cannot admit a value above the validated bound",
    typeErr(function () { limits.cap(8, "k", 7, steerable); }) === "x/oob");
  check("and the bound was read once (" + maxReads + ")", maxReads === 1);
  var minReads = 0;
  var steerableMin = { E: E, code: "x/oob", max: 1000 };
  Object.defineProperty(steerableMin, "min", {
    enumerable: true,
    get: function () { minReads += 1; return minReads === 1 ? 0 : 1e9; },
  });
  check("a steerable opts.min cannot refuse a value the validated bound admits",
    limits.cap(5, "k", 7, steerableMin) === 5);
  check("in-bounds value passes with opts", limits.cap(3, "k", 7, { E: E, code: "x/oob", min: 1, max: 7 }) === 3);
}

function testCapAuthoringBounds() {
  // The bounds themselves are authoring inputs: a NaN / fractional min or max
  // silently disables the comparison (value < NaN is false) -- and a NaN min
  // REPLACES the default >= 0 floor, so it is strictly worse than no opts.
  // A malformed bound throws a config-time TypeError regardless of opts.E.
  check("NaN min throws TypeError", typeErr(function () { limits.cap(-5, "k", 0, { min: NaN }); }) === "TYPE");
  check("NaN max throws TypeError", typeErr(function () { limits.cap(99, "k", 0, { min: 0, max: NaN }); }) === "TYPE");
  check("fractional min throws TypeError", typeErr(function () { limits.cap(5, "k", 0, { min: 1.5 }); }) === "TYPE");
  check("NaN min throws TypeError even with opts.E", typeErr(function () { limits.cap(-5, "k", 0, { E: E, code: "x/oob", min: NaN }); }) === "TYPE");
}

function testCounter() {
  var c = limits.counter(2, E, "x/many", "item");
  check("counter count() starts at 0", c.count() === 0);
  c.tick(); c.tick();
  check("counter count() reports the ticks so far", c.count() === 2);
  check("counter throws past the cap", typeErr(function () { c.tick(); }) === "x/many");
  check("counter count() reflects the tick that overran the cap", c.count() === 3);
  // The ceiling is an authoring input: an undefined / NaN / fractional max
  // builds a counter that NEVER fires (n > NaN is false) -- a dead fanout
  // defense. Reject at construction with a config-time TypeError.
  check("undefined max throws TypeError", typeErr(function () { limits.counter(undefined, E, "x/many", "item"); }) === "TYPE");
  check("NaN max throws TypeError", typeErr(function () { limits.counter(NaN, E, "x/many", "item"); }) === "TYPE");
  check("fractional max throws TypeError", typeErr(function () { limits.counter(1.5, E, "x/many", "item"); }) === "TYPE");
  check("negative max throws TypeError", typeErr(function () { limits.counter(-1, E, "x/many", "item"); }) === "TYPE");
  // no label -> the (label || "decoded item") default is exercised.
  var c2 = limits.counter(0, E, "x/many");
  check("counter with no label uses the default label", typeErr(function () { c2.tick(); }) === "x/many");
}

function testByteCap() {
  var buf = Buffer.alloc(10);
  check("byteCap returns the buffer when within the cap", limits.byteCap(buf, 16, E, "x/too-large", "blob") === buf);
  check("byteCap returns the buffer at exactly the cap", limits.byteCap(buf, 10, E, "x/too-large", "blob") === buf);
  check("byteCap throws the typed error one byte over the cap", typeErr(function () { limits.byteCap(buf, 9, E, "x/too-large", "blob"); }) === "x/too-large");
  // The ceiling is an authoring input: an undefined / NaN / fractional / negative max
  // makes `length > max` never fire -- a dead size defense. Config-time TypeError.
  check("byteCap undefined max throws TypeError", typeErr(function () { limits.byteCap(buf, undefined, E, "x/too-large", "blob"); }) === "TYPE");
  check("byteCap NaN max throws TypeError", typeErr(function () { limits.byteCap(buf, NaN, E, "x/too-large", "blob"); }) === "TYPE");
  check("byteCap fractional max throws TypeError", typeErr(function () { limits.byteCap(buf, 1.5, E, "x/too-large", "blob"); }) === "TYPE");
  check("byteCap negative max throws TypeError", typeErr(function () { limits.byteCap(buf, -1, E, "x/too-large", "blob"); }) === "TYPE");
  // no label -> the (label || "input") default is exercised.
  check("byteCap over-cap with no label uses the default label", typeErr(function () { limits.byteCap(buf, 9, E, "x/too-large"); }) === "x/too-large");
}

// The budget a parse spends against. Its reason for existing is narrow and worth stating: a
// resource failure must not be convertible into a semantic answer. There are roughly 230
// swallowing catches in lib/, and auditing all of them is the approach that failed; latching
// the exhaustion on an object the swallow cannot reach is the approach that does not need to.
function testBudget() {
  var b = limits.budget({ maxBytes: 100 });
  check("a fresh budget is not exhausted", b.exhausted() === false);
  check("it reports its maximum", b.max() === 100);
  check("spending under the maximum returns what was spent", b.spend(40, "a value") === 40);
  check("and accumulates", b.spent() === 40 && b.remaining() === 60);
  check("spending up to exactly the maximum is allowed", b.spend(60, "the rest") === 60);
  check("which leaves nothing remaining", b.remaining() === 0 && b.exhausted() === false);

  var threw = null;
  try { b.spend(1, "one byte too many"); } catch (e) { threw = e; }
  check("spending past the maximum throws", threw !== null);
  check("the throw is a budget exhaustion", limits.isBudgetExceeded(threw) === true);
  check("and names what overran it", String(threw.message).indexOf("one byte too many") !== -1);

  // The property the whole design rests on: catching the throw does not undo the exhaustion.
  check("the budget stays exhausted after the throw was caught", b.exhausted() === true);
  var again = null;
  try { b.spend(0, "nothing at all"); } catch (e) { again = e; }
  check("and a later zero-cost spend still reports exhausted", b.exhausted() === true);
  void again;

  // A budget exhaustion is NOT a PkiError, so the re-throw shape every domain uses passes it
  // through rather than reading it as a decode verdict.
  check("a budget exhaustion is not a PkiError", (threw instanceof pki.errors.PkiError) === false);
  check("so the common re-throw guard lets it past", (function () {
    try {
      try { limits.budget({ maxBytes: 1 }).spend(2, "x"); }
      catch (e) { if (e instanceof pki.errors.PkiError) return "absorbed"; throw e; }
    } catch (outer) { return limits.isBudgetExceeded(outer) ? "rethrown" : "other"; }
    return "fell-through";
  })() === "rethrown");

  // trip() is the same latch for a limit that is not counted in bytes.
  var t = limits.budget({ maxBytes: 10 });
  var tripped = null;
  try { t.trip("a nesting depth"); } catch (e) { tripped = e; }
  check("trip throws a budget exhaustion", limits.isBudgetExceeded(tripped) === true);
  check("trip latches the same way", t.exhausted() === true);
  check("trip names what overran", String(tripped.message).indexOf("a nesting depth") !== -1);

  // The budget is frozen, so a caller holding one cannot clear the latch by writing over it.
  var f = limits.budget({ maxBytes: 5 });
  try { f.spend(9, "over"); } catch (_e) { /* expected */ }
  try { f.exhausted = function () { return false; }; } catch (_e2) { /* frozen in strict mode */ }
  check("the latch cannot be replaced on the budget object", f.exhausted() === true);

  // Authoring-time refusals: a bad maximum or a bad spend is a TypeError at the boundary.
  check("a non-integer maximum throws TypeError", typeErr(function () { limits.budget({ maxBytes: 1.5 }); }) === "TYPE");
  check("a negative maximum throws TypeError", typeErr(function () { limits.budget({ maxBytes: -1 }); }) === "TYPE");
  check("a negative spend throws TypeError", typeErr(function () { limits.budget({ maxBytes: 10 }).spend(-1, "x"); }) === "TYPE");
  check("a non-integer spend throws TypeError", typeErr(function () { limits.budget({ maxBytes: 10 }).spend(1.5, "x"); }) === "TYPE");
  check("no maximum falls back to the DER byte cap", limits.budget().max() === pki.C.LIMITS.DER_MAX_BYTES);
  check("isBudgetExceeded says no to an ordinary error", limits.isBudgetExceeded(new Error("x")) === false);
  check("isBudgetExceeded says no to null", limits.isBudgetExceeded(null) === false);
}

// A per-operation timeout bounds each operation and nothing bounds their sum: six distribution
// points at a 30-second transport default is a three-minute validation. The deadline is that
// outer bound, read from a monotonic clock so a wall clock stepping backward cannot extend it,
// with the clock injectable so a vector drives the bound without waiting for it.
function testDeadline() {
  function threw(fn) { try { fn(); return null; } catch (e) { return e.constructor.name; } }
  var t = 0;
  function clock() { return t; }
  var d = limits.deadline(100, { now: clock });

  check("40. a fresh deadline has its whole budget and has not expired",
    d.remaining() === 100 && d.expired() === false && d.elapsed() === 0 && d.total() === 100);
  t = 60;
  check("41. time spent comes off the budget", d.remaining() === 40 && d.elapsed() === 60 && d.expired() === false);
  t = 100;
  check("42. the budget reaching zero is expiry", d.remaining() === 0 && d.expired() === true);
  t = 5000;
  check("43. ...and it stays expired, with the remainder never going below zero",
    d.remaining() === 0 && d.expired() === true);
  t = -500;
  check("44. a clock that steps backward does not hand the budget back",
    d.elapsed() === 0 && d.remaining() === 100);

  check("45. a zero deadline is expired from the start", (function () {
    var z = limits.deadline(0, { now: clock });
    return z.expired() === true && z.remaining() === 0;
  })());
  check("46. the default clock is monotonic and the budget is bounded by it", (function () {
    var real = limits.deadline(50);
    return real.remaining() <= 50 && real.remaining() >= 0 && real.expired() === false;
  })());
  check("47. a negative or non-integer total is a configuration fault",
    threw(function () { limits.deadline(-1); }) === "TypeError" &&
    threw(function () { limits.deadline(1.5); }) === "TypeError" &&
    threw(function () { limits.deadline("100"); }) === "TypeError");
  check("48. a clock that does not return a finite number is a configuration fault",
    threw(function () { limits.deadline(10, { now: function () { return "x"; } }); }) === "TypeError" &&
    threw(function () { limits.deadline(10, { now: function () { return NaN; } }); }) === "TypeError");
  check("49. the deadline is frozen, so a caller cannot move it",
    Object.isFrozen(d) && (function () {
      try { d.remaining = function () { return 999; }; } catch (_e) { /* frozen */ }
      return d.remaining() === 100;
    })());
}

function run() {
  testCap();
  testCapAuthoringBounds();
  testCounter();
  testByteCap();
  testBudget();
  testDeadline();
  testAnOmittedOptionsRecordReadsNoInheritedField();
}

/* A record defaulted with `{}` has `Object.prototype`, so every field the caller omitted is read off
   the prototype chain. These two read a CLOCK and a BOUND out of a record their callers routinely
   omit, and neither sits behind an options door: `pki.path.fetchingChecker` reaches
   `guard.limits.deadline(cfg.totalDeadlineMs)` with no second argument at all. An inherited `now`
   therefore decided when a revocation deadline expires, which is either a deadline that never
   expires or one already expired before the first fetch, and an inherited `max` decided the bound a
   decoded value is held to. The defaults have no prototype, so there is nothing to inherit. */
function testAnOmittedOptionsRecordReadsNoInheritedField() {
  var proto = Object.prototype;
  var had = Object.prototype.hasOwnProperty.call(proto, "now");
  var hadMax = Object.prototype.hasOwnProperty.call(proto, "max");
  var realNow = proto.now, realMax = proto.max;
  var clockCalls = 0;
  var d, capped = null, capThrew = null;
  try {
    // A clock whose every reading is a billion milliseconds later, so a deadline measured against it
    // is expired before anything runs.
    Object.defineProperty(proto, "now", {
      value: function () { clockCalls += 1; return clockCalls * 1e9; },
      writable: true, configurable: true, enumerable: false,
    });
    // A bound of zero, so a value held to it would be refused whatever it is.
    Object.defineProperty(proto, "max", { value: 0, writable: true, configurable: true, enumerable: false });
    d = limits.deadline(5000);
    try { capped = limits.cap(4096, "maxBytes", 4096); } catch (e) { capThrew = (e && e.code) || "throw"; }
  } finally {
    if (had) Object.defineProperty(proto, "now", { value: realNow, writable: true, configurable: true, enumerable: false });
    else delete proto.now;
    if (hadMax) Object.defineProperty(proto, "max", { value: realMax, writable: true, configurable: true, enumerable: false });
    else delete proto.max;
  }
  // CONTROL: the pollution has to be the shape the guard would actually use, or the arm proves only
  // that an unusable value was ignored. `now` is used when it is callable and `max` when it is a
  // number, and both were.
  check("CONTROL the inherited clock is callable and the inherited bound is a number, which is what " +
    "these fields are read as", typeof realNow === "undefined" && typeof realMax === "undefined");
  check("CONTROL an inherited `now` is reachable on a plain object literal, which is the shape the " +
    "default used to have", (function () {
    var seen;
    try {
      Object.defineProperty(proto, "now", { value: 42, writable: true, configurable: true, enumerable: false });
      seen = {}.now;
    } finally { delete proto.now; }
    return seen === 42;
  })());
  check("a deadline built with its options omitted is not expired by an inherited clock (" +
    clockCalls + " inherited clock call(s), remaining " + (d && d.remaining()) + " ms)",
  d !== null && clockCalls === 0 && d.expired() === false && d.remaining() > 0);
  check("a cap built with its options omitted is not bounded by an inherited max (" +
    (capThrew === null ? "returned " + capped : "threw " + capThrew) + ")",
  capThrew === null && capped === 4096);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
