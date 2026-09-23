// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-async (@internal): the await boundary around caller code. A
 * producer that is not callable, does not return a thenable, throws where it
 * was expected to reject, or never settles at all is each a fault of the
 * caller's operation, and each has to reach the composing verb as that verb's
 * own typed error rather than as a raw throw or as a wait with no end. The
 * composing verbs (pki.path.fetchingChecker, the EST and ACME clients) drive
 * these behaviorally; these pin the guard's own contract.
 */

var async = require("../../lib/guard-async");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError");
function E(code, message) { return new TestError(code, message); }

// `invoked` and `awaited` refuse synchronously, so the call is made inside the try rather than
// before it: passing the result of the call would let a synchronous throw escape uncaught.
async function codeOf(p) {
  try { await (typeof p === "function" ? p() : p); return "NO-THROW"; }
  catch (e) { return e instanceof TestError ? e.code : ("OTHER:" + (e && e.name)); }
}

async function testInvoked() {
  check("a producer returning a thenable resolves to its value",
    (await async.invoked(function () { return Promise.resolve(7); }, [], E, "t/bad", "op")) === 7);
  check("a producer returning a non-thenable is the boundary's error",
    (await codeOf(function () { return async.invoked(function () { return 7; }, [], E, "t/bad", "op"); })) === "t/bad");
  check("a producer returning null is the boundary's error",
    (await codeOf(function () { return async.invoked(function () { return null; }, [], E, "t/bad", "op"); })) === "t/bad");
  check("a producer that throws synchronously is the boundary's error",
    (await codeOf(function () { return async.invoked(function () { throw new Error("boom"); }, [], E, "t/bad", "op"); })) === "t/bad");
  // A bound class constructor passes a callability check and throws when called.
  var Bound = (class X { }).bind(null);
  check("a bound class constructor is the boundary's error, not a raw TypeError",
    (await codeOf(function () { return async.invoked(Bound, [], E, "t/bad", "op"); })) === "t/bad");
  check("a rejecting producer passes its own rejection through",
    (await codeOf(function () { return async.invoked(function () { return Promise.reject(new Error("no")); }, [], E, "t/bad", "op"); })) === "OTHER:Error");
}

async function testBounded() {
  check("a value settling inside the bound is returned",
    (await async.bounded(Promise.resolve(3), 1000, E, "t/slow", "op")) === 3);
  check("a rejection inside the bound passes through",
    (await codeOf(async.bounded(Promise.reject(new Error("no")), 1000, E, "t/slow", "op"))) === "OTHER:Error");
  check("an operation that never settles is refused at the bound",
    (await codeOf(async.bounded(new Promise(function () { }), 20, E, "t/slow", "op"))) === "t/slow");
  check("a bound of zero refuses without awaiting",
    (await codeOf(async.bounded(new Promise(function () { }), 0, E, "t/slow", "op"))) === "t/slow");
  check("a negative bound refuses the same way",
    (await codeOf(async.bounded(new Promise(function () { }), -1, E, "t/slow", "op"))) === "t/slow");

  // The refusal names the bound it passed, so an operator reading it can tell a slow source from
  // a source that answered with a fault.
  var msg = null;
  try { await async.bounded(new Promise(function () { }), 15, E, "t/slow", "the CRL fetch"); }
  catch (e) { msg = e.message; }
  check("the refusal names the operation and the bound",
    typeof msg === "string" && msg.indexOf("the CRL fetch") === 0 && msg.indexOf("15ms") !== -1);

  // The timer holds the event loop while a bound is in flight. An unreferenced one lets a process
  // with nothing else pending exit while the await is outstanding, which reads as a clean run that
  // simply stopped. Proven by the clock: the bound below is still the last thing keeping this
  // suite alive when it fires.
  var startedAt = Date.now();
  await codeOf(async.bounded(new Promise(function () { }), 40, E, "t/slow", "op"));
  var waited = Date.now() - startedAt;
  check("the bound is actually awaited rather than abandoned (" + waited + "ms)", waited >= 35);

  // A settled operation clears the timer, so a bound far in the future does not hold anything.
  var quick = Date.now();
  await async.bounded(Promise.resolve(1), 3600000, E, "t/slow", "op");
  check("a value that settles early does not wait out its bound", (Date.now() - quick) < 1000);
}

async function testAwaited() {
  check("a thenable is adopted through its own then",
    (await async.awaited({ then: function (res) { res(11); } }, E, "t/bad", "op")) === 11);
  check("a value whose then throws on read is the boundary's error",
    (await codeOf(function () {
      return async.awaited(Object.defineProperty({}, "then", {
        get: function () { throw new Error("trap"); },
      }), E, "t/bad", "op");
    })) === "t/bad");
  check("undefined is the boundary's error",
    (await codeOf(function () { return async.awaited(undefined, E, "t/bad", "op"); })) === "t/bad");
}

async function testDeferred() {
  check("a body returning a value resolves to it",
    (await async.deferred(function () { return 5; })) === 5);
  check("a body that throws becomes a rejection rather than a synchronous throw",
    (await codeOf(async.deferred(function () { throw new Error("sync"); }))) === "OTHER:Error");
}

async function run() {
  await testInvoked();
  await testAwaited();
  await testDeferred();
  await testBounded();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
