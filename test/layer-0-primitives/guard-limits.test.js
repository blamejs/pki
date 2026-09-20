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

function run() {
  testCap();
  testCapAuthoringBounds();
  testCounter();
  testByteCap();
  testBudget();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
