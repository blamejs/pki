// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-intrinsic (@internal): invoke a captured method against a receiver without
 * reading any property of the captured function.
 *
 * Capturing a method at module load freezes WHICH function a guard runs, so a later
 * `Uint8Array.prototype.fill = noop` changes nothing. It does not freeze HOW that function is
 * invoked: `_fill.call(view, 0)` reads `call` off the captured function, and the function is the
 * one still sitting on the prototype. An own `call` assigned to it shadows
 * `Function.prototype.call`, and the guard runs the caller's replacement with the same result the
 * un-captured code had -- with every check around it still running and still passing.
 *
 * The first group pins the primitive's own contract. The second drives the five guards that
 * compose it through their shipped entry points with every relevant intrinsic poisoned at once,
 * which is where the property has to hold.
 */

var intrinsic = require("../../lib/guard-intrinsic");
var guard = require("../../lib/guard-all");
var name = require("../../lib/guard-name");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError", { withCause: true });
function F(code, message) { var e = new Error(message); e.code = code; return e; }
function rdn(type, value) { return [{ type: type, value: value }]; }
var CN = "2.5.4.3";

function testUncurryContract() {
  var f = intrinsic.uncurry(String.prototype.toUpperCase);
  check("uncurried method applies to the receiver passed first", f("abc") === "ABC");

  var slice = intrinsic.uncurry(String.prototype.slice);
  check("uncurried method forwards its remaining arguments", slice("abcdef", 1, 3) === "bc");

  var getTime = intrinsic.uncurry(Date.prototype.getTime);
  check("uncurried getter-style method reaches the internal slot", getTime(new Date(1234)) === 1234);

  // A receiver with no slot behind it is refused by the intrinsic itself, which is the fail-closed
  // direction and the reason these are reached through the intrinsic rather than the value.
  var threw = false;
  try { getTime({}); } catch (_e) { threw = true; }
  check("uncurried method still refuses a receiver with no slot", threw === true);

  // Authoring input, held to the same rule a guard taking a bound holds it to: a non-function
  // silently produces something uncallable, and the failure would surface far from the mistake.
  var badArg = false;
  try { intrinsic.uncurry(undefined); } catch (e) { badArg = e instanceof TypeError; }
  check("uncurry refuses a non-function at the point of the mistake", badArg === true);

  // The returned function is a fresh object, so poisoning the source method's `call` afterwards
  // cannot reach it. This is the whole point, stated as a property of the primitive.
  var real = String.prototype.toUpperCase.call;
  var poisoned;
  try {
    String.prototype.toUpperCase.call = function () { return "POISONED"; };
    poisoned = f("abc");
  } finally {
    if (real === undefined) delete String.prototype.toUpperCase.call;
    else String.prototype.toUpperCase.call = real;
  }
  check("an own `call` on the source method does not reach the uncurried form", poisoned === "ABC");
}

// Every guard that performs its work with a captured intrinsic, driven with the own-`call`
// property set on each of those intrinsics at once. Each assertion names the guard whose contract
// would otherwise be answered by the caller.
function testEveryComposingGuardHolds() {
  // The byte-source getters are reachable the same way guard-bytes reaches them, so they are
  // poisoned alongside the ordinary methods; leaving them out would make the guard-bytes assertion
  // below hold whatever the module did.
  var taProto = Object.getPrototypeOf(Uint8Array.prototype);
  function getterOf(proto, key) { return Object.getOwnPropertyDescriptor(proto, key).get; }
  var poisons = [
    [String.prototype.toLowerCase, function () { return "same"; }],
    [String.prototype.charAt, function () { return "s"; }],
    [String.prototype.charCodeAt, function () { return 0x20; }],
    [Uint8Array.prototype.fill, function () { return this; }],
    [Buffer.prototype.toString, function () { return "SUBSTITUTED"; }],
    [TextDecoder.prototype.decode, function () { return "SUBSTITUTED"; }],
    [Date.prototype.getTime, function () { return 0; }],
    [getterOf(taProto, "buffer"), function () { return new ArrayBuffer(64); }],
    [getterOf(taProto, "byteOffset"), function () { return 0; }],
    [getterOf(taProto, "byteLength"), function () { return 64; }],
    [getterOf(DataView.prototype, "buffer"), function () { return new ArrayBuffer(64); }],
    [getterOf(DataView.prototype, "byteOffset"), function () { return 0; }],
    [getterOf(DataView.prototype, "byteLength"), function () { return 64; }],
  ];
  var had = [];
  var dnEqual, wiped, decoded, instant, viewLen;
  // Each guard is driven inside its own catch, so one arm failing reports as its own check rather
  // than escaping the suite and hiding the arms behind it.
  function attempt(fn) { try { return fn(); } catch (e) { return "threw " + (e.code || e.message); } }
  try {
    for (var i = 0; i < poisons.length; i++) {
      had.push(Object.prototype.hasOwnProperty.call(poisons[i][0], "call"));
      poisons[i][0].call = poisons[i][1];
    }

    dnEqual = attempt(function () {
      return name.rdnEqual(rdn(CN, "alice"), rdn(CN, "bobby"), F, "x/bad", "the name");
    });

    wiped = attempt(function () {
      var secret = Buffer.from("hunter2hunter2hu", "utf8");
      guard.secret.zeroize(secret, TestError, "x/bad", "the secret");
      return Array.prototype.every.call(secret, function (b) { return b === 0; });
    });

    decoded = attempt(function () {
      return guard.text.decode(Buffer.from("abc"), 16, TestError,
        { tooLarge: "x/too-large", badInput: "x/bad-input", label: "the text" });
    });

    instant = attempt(function () { return guard.time.instantOf(new Date(1700000000000)); });

    viewLen = attempt(function () {
      return guard.bytes.view(Buffer.from([1, 2, 3]), TestError, "x/bad", "the bytes").length;
    });
  } finally {
    for (var j = 0; j < poisons.length; j++) {
      if (had[j]) continue;
      delete poisons[j][0].call;
    }
  }

  check("guard-name still refuses two different distinguished names", dnEqual === false);
  check("guard-secret still clears the buffer it was given", wiped === true);
  check("guard-text still returns the bytes it decoded", decoded === "abc");
  check("guard-time still reads the instant the Date holds", instant === 1700000000000);
  // Reverting the byte getters makes this read 64 rather than 3, since a poisoned byteLength is
  // what `_reView` builds the Buffer from. It also fails the guard-text arm above, which re-views
  // through this same guard and then measures the result against its cap -- so in-suite the two
  // arms go red together, with guard-text reporting first.
  check("guard-bytes still measures the view it was given", viewLen === 3);
}

// The other half of what a guard reads from the runtime: `util.types` is an ordinary object on an
// ordinary module export, and the global `isNaN` is a writable binding. Neither is a method on a
// prototype, so the capture-and-uncurry above does not cover them and they need their own answer.
// These are the questions a lookalike cannot lie about, which is exactly why they are worth
// replacing: a caller who answers them has replaced the toolkit's only reliable test of what a
// value IS.
function testRuntimeReadsAreSnapshotted() {
  var utilTypes = require("util").types;
  var realIsDate = utilTypes.isDate, realIsNaN = globalThis.isNaN;
  var saidDate, acceptedInvalid;
  try {
    utilTypes.isDate = function () { return true; };
    globalThis.isNaN = function () { return false; };
    saidDate = guard.time.isDate({});
    try {
      guard.time.assertValid(new Date(NaN), F, "x/bad", "the time");
      acceptedInvalid = true;
    } catch (_e) { acceptedInvalid = false; }
  } finally {
    utilTypes.isDate = realIsDate;
    globalThis.isNaN = realIsNaN;
  }
  // The re-view a wipe performs turns a backing store back into something writable, and it does
  // that through `Buffer.from`. One returning a buffer over DIFFERENT memory hands the wipe a
  // decoy: the fill runs, the decoy is zeroed, the call returns normally, and the plaintext it was
  // aimed at is still readable. Every check between the two is satisfied.
  var realFrom = Buffer.from;
  var plaintext = realFrom.call(Buffer, "hunter2hunter2hu", "utf8");
  var decoy = Buffer.alloc(16, 0xAA);
  try {
    Buffer.from = function () { return decoy; };
    guard.secret.zeroize(plaintext, TestError, "x/bad", "the secret");
  } finally {
    Buffer.from = realFrom;
  }
  check("a replaced Buffer.from cannot redirect the wipe onto a decoy buffer",
    Array.prototype.every.call(plaintext, function (b) { return b === 0; }));

  check("a replaced util.types.isDate cannot make a plain object answer as a Date", saidDate === false);
  check("a replaced global isNaN cannot make an invalid Date pass the validity check",
    acceptedInvalid === false);
}

function run() {
  testUncurryContract();
  testEveryComposingGuardHolds();
  testRuntimeReadsAreSnapshotted();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
