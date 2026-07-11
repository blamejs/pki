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
  c.tick(); c.tick();
  check("counter throws past the cap", typeErr(function () { c.tick(); }) === "x/many");
  // The ceiling is an authoring input: an undefined / NaN / fractional max
  // builds a counter that NEVER fires (n > NaN is false) -- a dead fanout
  // defence. Reject at construction with a config-time TypeError.
  check("undefined max throws TypeError", typeErr(function () { limits.counter(undefined, E, "x/many", "item"); }) === "TYPE");
  check("NaN max throws TypeError", typeErr(function () { limits.counter(NaN, E, "x/many", "item"); }) === "TYPE");
  check("fractional max throws TypeError", typeErr(function () { limits.counter(1.5, E, "x/many", "item"); }) === "TYPE");
  check("negative max throws TypeError", typeErr(function () { limits.counter(-1, E, "x/many", "item"); }) === "TYPE");
}

function run() {
  testCap();
  testCapAuthoringBounds();
  testCounter();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
