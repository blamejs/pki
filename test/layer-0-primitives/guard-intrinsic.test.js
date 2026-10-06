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
var encoding = require("../../lib/guard-encoding");
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
// A proof of possession turns on whether two public keys are the same key. A replaced
// KeyObject.prototype.equals answering true would make one key stand in for another, so the capture
// is taken at load and the replacement never reaches the comparison.
function testKeyEqualsIsSnapshotted() {
  var nodeCrypto = require("crypto");
  var a = nodeCrypto.createPublicKey(nodeCrypto.generateKeyPairSync("ec",
    { namedCurve: "prime256v1" }).privateKey);
  var b = nodeCrypto.createPublicKey(nodeCrypto.generateKeyPairSync("ec",
    { namedCurve: "prime256v1" }).privateKey);
  var real = nodeCrypto.KeyObject.prototype.equals;
  var saidEqual, saidUnequal;
  try {
    nodeCrypto.KeyObject.prototype.equals = function () { return true; };
    saidEqual = intrinsic.keyEquals(a, b);
    nodeCrypto.KeyObject.prototype.equals = function () { return false; };
    saidUnequal = intrinsic.keyEquals(a, a);
  } finally {
    nodeCrypto.KeyObject.prototype.equals = real;
  }
  check("a replaced KeyObject.equals cannot make two different keys answer as one", saidEqual === false);
  check("a replaced KeyObject.equals cannot make one key answer as two", saidUnequal === true);
}

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

  // Canonicality is decided by decoding the text and re-encoding the result, so BOTH halves of
  // that round trip settle the answer. Capturing the decoder and leaving the re-encoder live keeps
  // the hole open from the other side: a `toString` returning the input makes every non-canonical
  // encoding compare equal to its own re-encoding. `AB` decodes to 0x00, whose canonical form is
  // `AA`, so it must be refused.
  var realToStr = Buffer.prototype.toString, encOutcome;
  try {
    Buffer.prototype.toString = function () { return "AB"; };
    try {
      encoding.base64url("AB", 100, F, "x/bad", "the value");
      encOutcome = "accepted";
    } catch (e) { encOutcome = e.code; }
  } finally {
    Buffer.prototype.toString = realToStr;
  }
  check("a replaced Buffer.prototype.toString cannot make a non-canonical encoding canonical",
    encOutcome === "x/bad");

  // On a typed array `length` is a configurable accessor on the prototype, and the Buffer arm's
  // cap comparison reads it. One returning 0 admits a buffer of any size and then decodes it in
  // full, which is the allocation the cap exists to bound.
  var taProto = Object.getPrototypeOf(Uint8Array.prototype);
  var realLenDesc = Object.getOwnPropertyDescriptor(taProto, "length");
  var capOutcome;
  try {
    Object.defineProperty(taProto, "length", { get: function () { return 0; }, configurable: true });
    try {
      guard.text.decode(Buffer.alloc(4096), 16, TestError,
        { tooLarge: "x/too-large", badInput: "x/bad-input", label: "the text" });
      capOutcome = "accepted";
    } catch (e) { capOutcome = e.code || "OTHER"; }
  } finally {
    Object.defineProperty(taProto, "length", realLenDesc);
  }
  check("a replaced typed-array length getter cannot admit an over-cap Buffer",
    capOutcome === "x/too-large");

  // The same accessor against the size cap every bounded byte input in the toolkit runs through.
  // A getter answering 0 makes `size > max` false for a buffer of any size, so the cap is not
  // raised or widened, it is gone.
  var byteCapOutcome;
  try {
    Object.defineProperty(taProto, "length", { get: function () { return 0; }, configurable: true });
    try {
      guard.limits.byteCap(Buffer.alloc(4096), 16, F, "x/too-large", "the input");
      byteCapOutcome = "accepted";
    } catch (e) { byteCapOutcome = e.code || "OTHER"; }
  } finally {
    Object.defineProperty(taProto, "length", realLenDesc);
  }
  check("a replaced typed-array length getter cannot admit an over-cap byteCap input",
    byteCapOutcome === "x/too-large");

  // And against the control-byte scan that defends the name-truncation class. The accessor is the
  // loop's end, so one answering 0 runs the loop zero times: the name still carries the control
  // byte, and the walk that would have found it reports nothing.
  var ia5 = Buffer.from([0x61, 0x00, 0x62]);   // "a", NUL, "b" -- built as bytes, source stays ASCII
  var ia5Outcome;
  try {
    Object.defineProperty(taProto, "length", { get: function () { return 0; }, configurable: true });
    try {
      guard.name.assertPrintableIa5(ia5, F, "x/bad-name", "the name");
      ia5Outcome = "accepted";
    } catch (e) { ia5Outcome = e.code || "OTHER"; }
  } finally {
    Object.defineProperty(taProto, "length", realLenDesc);
  }
  check("a replaced typed-array length getter cannot skip the control-byte scan",
    ia5Outcome === "x/bad-name");

  // The same accessor against the argument copy, where the consequence is a secret rather than a
  // refusal. The copy's size decides how large the private store is, how much of it the caller gets
  // back, and how much of it goes on the wipe list. An accessor answering short leaves `release`
  // clearing the front of a copy that still holds the rest of the secret. The replacement below
  // shrinks only 16-byte views, so every other buffer in the process still reports its true size
  // and the surrounding machinery is undisturbed.
  var secretLen = 16;
  var copiedLen;
  try {
    Object.defineProperty(taProto, "length", {
      get: function () {
        var real = realLenDesc.get.call(this);
        return real === secretLen ? 4 : real;
      },
      configurable: true,
    });
    var held = Buffer.from("hunter2hunter2hu", "utf8");
    var kept = guard.bytes.snapshotDeep(held, TestError, "x/bad", "the secret", { collect: [] });
    // Measured through the real accessor, so the assertion is not itself answered by the
    // replacement it is testing.
    Object.defineProperty(taProto, "length", realLenDesc);
    copiedLen = realLenDesc.get.call(kept);
  } finally {
    Object.defineProperty(taProto, "length", realLenDesc);
  }
  check("a replaced typed-array length getter cannot short the copy of a secret",
    copiedLen === secretLen);

  // Which own names count as array indices is `String(Number(k)) === k`, and both halves are
  // ordinary writable properties of globalThis. "00" is numeric but not the canonical spelling of
  // its number, so it is not an index and the position it sits at stays a hole. A `String` that
  // answers "00" for 0 makes it count, and a list with a hole then reports itself as dense.
  var holed = [];
  holed.length = 1;
  holed["00"] = "not-an-element";
  var realString = globalThis.String;
  var reported;
  try {
    globalThis.String = function (x) { return x === 0 ? "00" : realString(x); };
    reported = guard.identifier.readableIndices(holed, F, "x/bad", "the list");
  } finally {
    globalThis.String = realString;
  }
  check("a replaced global String cannot make a non-index name count as an index",
    Array.isArray(reported) && reported.length === 0);

  check("a replaced util.types.isDate cannot make a plain object answer as a Date", saidDate === false);
  check("a replaced global isNaN cannot make an invalid Date pass the validity check",
    acceptedInvalid === false);
}

// The whole class at once. The vectors above each poison one reference and drive one guard, which
// is how they stay diagnostic; this poisons every global the guard family used to read live and
// drives all of them together, which is the property an operator actually depends on. A guard swept
// later inherits this without a new vector being written for it.
function testWholeFamilyUnderFullPoisoning() {
  var utilTypes = require("util").types;
  var real = {
    toLowerCase: String.prototype.toLowerCase, charAt: String.prototype.charAt,
    charCodeAt: String.prototype.charCodeAt, fill: Uint8Array.prototype.fill,
    bufToString: Buffer.prototype.toString, decode: TextDecoder.prototype.decode,
    getTime: Date.prototype.getTime, isBuffer: Buffer.isBuffer, byteLength: Buffer.byteLength,
    isView: ArrayBuffer.isView, isArray: Array.isArray, isInteger: Number.isInteger,
    isNaN: globalThis.isNaN, isDate: utilTypes.isDate,
    gopd: Object.getOwnPropertyDescriptor, ownKeys: Reflect.ownKeys,
    // The array operations a guard walks its OWN arrays with. A `forEach` no-op makes a scan over
    // real keys report nothing, and whatever is keyed on that scan then passes vacuously.
    arrForEach: Array.prototype.forEach, arrEvery: Array.prototype.every,
    arrIndexOf: Array.prototype.indexOf, arrPush: Array.prototype.push,
    arrFilter: Array.prototype.filter, arrMap: Array.prototype.map,
    arrSort: Array.prototype.sort,
  };
  var bufferFrom = Buffer.from;
  var secret = bufferFrom.call(Buffer, "hunter2hunter2hu", "utf8");
  var r = {};
  try {
    String.prototype.toLowerCase = function () { return "same"; };
    String.prototype.charAt = function () { return "s"; };
    String.prototype.charCodeAt = function () { return 0x20; };
    Uint8Array.prototype.fill = function () { return this; };
    Buffer.prototype.toString = function () { return "SUBSTITUTED"; };
    TextDecoder.prototype.decode = function () { return "SUBSTITUTED"; };
    Date.prototype.getTime = function () { return 0; };
    Buffer.isBuffer = function () { return false; };
    Buffer.byteLength = function () { return 0; };
    ArrayBuffer.isView = function () { return false; };
    Array.isArray = function () { return false; };
    Number.isInteger = function () { return true; };
    globalThis.isNaN = function () { return false; };
    utilTypes.isDate = function () { return true; };
    Object.getOwnPropertyDescriptor = function () { return { value: 1, writable: true }; };
    Reflect.ownKeys = function () { return []; };
    Array.prototype.forEach = function () { };
    Array.prototype.every = function () { return true; };
    Array.prototype.indexOf = function () { return -1; };
    Array.prototype.push = function () { return 0; };
    Array.prototype.filter = function () { return []; };
    Array.prototype.map = function () { return []; };
    Array.prototype.sort = function () { return this; };

    r.dn = name.rdnEqual(rdn(CN, "alice"), rdn(CN, "bobby"), F, "x/bad", "the name");
    guard.secret.zeroize(secret, TestError, "x/bad", "the secret");
    r.wiped = Array.prototype.every.call(secret, function (b) { return b === 0; });
    r.text = guard.text.decode(bufferFrom.call(Buffer, "abc"), 16, TestError,
      { tooLarge: "x/too-large", badInput: "x/bad-input", label: "the text" });
    r.instant = guard.time.instantOf(new Date(1700000000000));
    r.notADate = guard.time.isDate({});
    r.viewLen = guard.bytes.view(bufferFrom.call(Buffer, [1, 2, 3]), TestError, "x/bad", "b").length;
    try { encoding.base64url("AB", 100, F, "x/bad", "v"); r.enc = "accepted"; }
    catch (e) { r.enc = e.code; }
  } finally {
    String.prototype.toLowerCase = real.toLowerCase; String.prototype.charAt = real.charAt;
    String.prototype.charCodeAt = real.charCodeAt; Uint8Array.prototype.fill = real.fill;
    Buffer.prototype.toString = real.bufToString; TextDecoder.prototype.decode = real.decode;
    Date.prototype.getTime = real.getTime; Buffer.isBuffer = real.isBuffer;
    Buffer.byteLength = real.byteLength; ArrayBuffer.isView = real.isView;
    Array.isArray = real.isArray; Number.isInteger = real.isInteger;
    globalThis.isNaN = real.isNaN; utilTypes.isDate = real.isDate;
    Object.getOwnPropertyDescriptor = real.gopd; Reflect.ownKeys = real.ownKeys;
    Array.prototype.forEach = real.arrForEach; Array.prototype.every = real.arrEvery;
    Array.prototype.indexOf = real.arrIndexOf; Array.prototype.push = real.arrPush;
    Array.prototype.filter = real.arrFilter; Array.prototype.map = real.arrMap;
    Array.prototype.sort = real.arrSort;
  }

  check("under full poisoning, guard-name keeps two different names apart", r.dn === false);
  check("under full poisoning, guard-secret still clears the buffer", r.wiped === true);
  check("under full poisoning, guard-text returns the bytes it decoded", r.text === "abc");
  check("under full poisoning, guard-time reads the instant the Date holds", r.instant === 1700000000000);
  check("under full poisoning, guard-time still refuses a plain object as a Date", r.notADate === false);
  check("under full poisoning, guard-bytes measures the view it was given", r.viewLen === 3);
  check("under full poisoning, guard-encoding still refuses a non-canonical value", r.enc === "x/bad");
}

function run() {
  testUncurryContract();
  testEveryComposingGuardHolds();
  testRuntimeReadsAreSnapshotted();
  testKeyEqualsIsSnapshotted();
  testWholeFamilyUnderFullPoisoning();
  testSelectionsConsultNoConstructionProtocol();
}

// A capture closes the METHOD and leaves the PROTOCOL the method consults open. `filter` and `map`
// build their result through ArraySpeciesCreate, which reads `constructor` off the receiver and
// `Symbol.species` off that, and `subarray` runs the typed-array form of the same thing. The species
// descriptor is configurable, so a replacement decides what the operation hands back: one returning
// `{ length: 0 }` collects every match as an indexed property while the length stays zero, and the
// result reads EMPTY. Empty is rarely inert -- an empty subject-alternative-name selection sends a
// hostname check to its common-name fallback, an empty permitted-subtree list reads as "constrains no
// name of that form" and skips the check -- so a refusal must not be reached through one.
//
// These three primitives exist for that, and this pins the difference: the captured operations are
// shown to be steerable in the same breath, so the vector cannot pass by the protocol being
// unreachable.
function testSelectionsConsultNoConstructionProtocol() {
  var realSpecies = Object.getOwnPropertyDescriptor(Array, Symbol.species);
  var src = [1, 2, 3, 4];
  var buf = Buffer.from([9, 8, 7, 6, 5]);
  var captured, safe, capturedMap, safeMap, capturedSlice, safeSlice;
  try {
    Object.defineProperty(Array, Symbol.species, {
      value: function () { return { length: 0 }; }, configurable: true,
    });
    captured = intrinsic.filter(src, function (x) { return x % 2 === 0; }).length;
    safe = intrinsic.selectList(src, function (x) { return x % 2 === 0; }).length;
    capturedMap = intrinsic.map(src, function (x) { return x; }).length;
    safeMap = intrinsic.mapList(src, function (x) { return x; }).length;
  } finally {
    Object.defineProperty(Array, Symbol.species, realSpecies);
  }
  check("intrinsic: a hostile Array species empties a captured filter", captured === 0);
  check("intrinsic: selectList is unaffected by a hostile Array species", safe === 2);
  check("intrinsic: a hostile Array species empties a captured map", capturedMap === 0);
  check("intrinsic: mapList is unaffected by a hostile Array species", safeMap === 4);

  // The typed-array form. `subarray` reads `constructor` off the receiver, so a Buffer whose
  // constructor carries a hostile species hands back whatever that species built: answering with the
  // expected RP ID hash for a 32-byte slice made an assertion produced for another relying party
  // satisfy expectedRpId while the signature was verified over the original bytes.
  var hostile = function (len) { return new Uint8Array(len === undefined ? 0 : len); };
  hostile[Symbol.species] = function () { return new Uint8Array([0, 0, 0]); };
  var poisoned = Buffer.from([9, 8, 7, 6, 5]);
  Object.defineProperty(poisoned, "constructor", { value: hostile, configurable: true });
  capturedSlice = intrinsic.bufToString(intrinsic.subarray(poisoned, 1, 4), "hex");
  safeSlice = intrinsic.bufToString(intrinsic.byteSlice(poisoned, 1, 4), "hex");
  check("intrinsic: a hostile typed-array species steers a captured subarray", capturedSlice === "000000");
  check("intrinsic: byteSlice is unaffected by a hostile typed-array species", safeSlice === "080706");
  check("intrinsic: byteSlice matches subarray on an ordinary buffer",
    intrinsic.bufToString(intrinsic.byteSlice(buf, 1, 4), "hex") ===
    intrinsic.bufToString(intrinsic.subarray(buf, 1, 4), "hex"));

  // `slice` runs the same species create, and its result object receives both the elements and the
  // length write, so a species that discards them leaves an empty copy. An empty copy of a
  // certificate chain reads as "nothing left to validate" where a self-presented anchor has just
  // been stripped, and the chain reports trusted with no path validated at all.
  var capturedCopy, safeCopy;
  try {
    Object.defineProperty(Array, Symbol.species, {
      value: function () { return { length: 0 }; }, configurable: true,
    });
    capturedCopy = intrinsic.arraySlice(src);
    safeCopy = intrinsic.copyList(src);
  } finally {
    Object.defineProperty(Array, Symbol.species, realSpecies);
  }
  check("intrinsic: a hostile Array species makes a captured slice return a non-array",
    Array.isArray(capturedCopy) === false);
  check("intrinsic: copyList is unaffected by a hostile Array species",
    Array.isArray(safeCopy) && safeCopy.length === 4 && safeCopy[0] === 1);
  check("intrinsic: copyList honors a start offset like slice does",
    intrinsic.copyList(src, 2).length === 2 && intrinsic.copyList(src, 2)[0] === 3);

  // The join is the fourth form. `concat` reads a spreadability flag off each operand AND builds
  // through the species, so a hostile species hands back a non-array holding the elements, and a
  // `false` flag leaves the operands nested inside the result. A join that drops an excluded-subtree
  // list loses the exclusion, and one that drops a chain element shortens the path that is validated.
  var capturedJoin, safeJoin, nestedJoin, safeNested;
  try {
    Object.defineProperty(Array, Symbol.species, {
      value: function () { return { length: 0 }; }, configurable: true,
    });
    capturedJoin = intrinsic.concat([1, 2], [3]);
    safeJoin = intrinsic.concatList([1, 2], [3]);
  } finally {
    Object.defineProperty(Array, Symbol.species, realSpecies);
  }
  check("intrinsic: a hostile Array species makes a captured concat return a non-array",
    Array.isArray(capturedJoin) === false);
  check("intrinsic: concatList is unaffected by a hostile Array species",
    Array.isArray(safeJoin) && safeJoin.length === 3 && safeJoin[2] === 3);
  try {
    Array.prototype[Symbol.isConcatSpreadable] = false;
    nestedJoin = intrinsic.concat([1, 2], [3]);
    safeNested = intrinsic.concatList([1, 2], [3]);
  } finally {
    delete Array.prototype[Symbol.isConcatSpreadable];
  }
  check("intrinsic: a false isConcatSpreadable nests the operands of a captured concat",
    nestedJoin.length === 2 && Array.isArray(nestedJoin[0]));
  check("intrinsic: concatList ignores isConcatSpreadable",
    safeNested.length === 3 && safeNested[0] === 1);

  // Appending is the other half. `push` writes through Set, which WALKS THE PROTOTYPE for a numeric
  // setter: an accessor installed at `Array.prototype[0]` takes the value, no own property lands on
  // the array, and the index reads back as whatever its getter answers. That is enough to substitute
  // a quality-of-protection token into a Digest credential, so the appends these build with define
  // an own property instead.
  // The accumulator is a counter, not an array: writing index 0 of an array would re-enter the very
  // setter being installed.
  var taken = 0;
  var pushRes, appendRes, selRes;
  try {
    Object.defineProperty(Array.prototype, "0", {
      set: function () { taken += 1; },
      get: function () { return "SUBSTITUTED"; },
      configurable: true,
    });
    var viaPush = [];
    intrinsic.push(viaPush, "auth-int");
    pushRes = viaPush[0];
    var viaAppend = [];
    intrinsic.append(viaAppend, "auth-int");
    appendRes = viaAppend[0];
    selRes = intrinsic.selectList(["auth-int"], function () { return true; })[0];
  } finally {
    delete Array.prototype["0"];
  }
  check("intrinsic: an Array.prototype numeric setter intercepts a captured push",
    pushRes === "SUBSTITUTED" && taken >= 1);
  check("intrinsic: append writes an own property the setter cannot intercept", appendRes === "auth-int");
  check("intrinsic: selectList writes own properties the setter cannot intercept", selRes === "auth-int");

  // The element count is read off the receiver, so the four list verbs take a real array and nothing
  // else. An array's `length` is an own data property and consults nothing; a typed array answers
  // from an accessor on `%TypedArray%.prototype` that a caller can redefine to report zero, which
  // would empty every result, and `append` would then overwrite index 0 rather than extend.
  var taLenProto = Object.getPrototypeOf(Uint8Array.prototype);
  var realTaLen = Object.getOwnPropertyDescriptor(taLenProto, "length");
  var refused = 0;
  try {
    Object.defineProperty(taLenProto, "length", { get: function () { return 0; }, configurable: true });
    ["mapList", "selectList", "copyList"].forEach(function (k) {
      try { intrinsic[k](new Uint8Array([1, 2, 3]), function (x) { return x; }); } catch (_e) { refused += 1; }
    });
    try { intrinsic.append(new Uint8Array([1, 2, 3]), 9); } catch (_e) { refused += 1; }
  } finally {
    Object.defineProperty(taLenProto, "length", realTaLen);
  }
  check("intrinsic: the list verbs refuse a receiver whose length is read from a prototype accessor",
    refused === 4);
  check("intrinsic: the list verbs still accept an ordinary array",
    intrinsic.mapList([1, 2], function (x) { return x * 3; })[1] === 6);

  // `isArray` is satisfied by a PROXY over an array, and its `length` trap can hand back an OBJECT
  // whose `valueOf` answers differently on each coercion. A loop that re-reads the length per
  // iteration then visits fewer elements than the first read promised, which silently drops the
  // tail: MEASURED through `pki.path.validate`, a proxied two-certificate path whose length shrank
  // that way reported valid with the second certificate never checked. The count is read once and
  // type-checked, the way `guard.list` does it.
  function shrinkingProxy(arr) {
    var reads = 0;
    var len = { valueOf: function () { reads += 1; return reads === 1 ? arr.length : arr.length - 1; } };
    return new Proxy(arr, { get: function (t, k) { return k === "length" ? len : t[k]; } });
  }
  check("intrinsic: a proxy whose length is an object is still seen as an array",
    Array.isArray(shrinkingProxy([1, 2])) === true);
  ["mapList", "selectList", "copyList"].forEach(function (verb) {
    var refused = false;
    try { intrinsic[verb](shrinkingProxy([1, 2]), function (x) { return x; }); } catch (_e) { refused = true; }
    check("intrinsic: " + verb + " refuses a receiver whose length is not a plain integer", refused === true);
  });
  var appendRefused = false;
  try { intrinsic.append(shrinkingProxy([1, 2]), 3); } catch (_e) { appendRefused = true; }
  check("intrinsic: append refuses one too", appendRefused === true);

  // `String.prototype.split` is SPECIFIED to look the separator's `Symbol.split` method up and call
  // it (ES2015 21.1.3.19 step 2), so the separator's prototype chain is part of the operation and
  // capturing `split` does not close it. Hard rule 11 bans `split` in lib/ for that reason.
  //
  // Whether a captured `split` ACTUALLY performs that lookup is a property of the engine, not of
  // this code: Node 24.21, the supported runtime, dispatches to the hook, and Node 26.9 fast-paths
  // a primitive-string separator past it. So nothing here asserts what `split` does -- an assertion
  // about that is an assertion about the RUNNER, and one written that way failed on CI while passing
  // locally. What is asserted is the subject: `splitChar` consults nothing, on every runtime.
  var hookedScan, hookedObjSep;
  try {
    Object.defineProperty(String.prototype, Symbol.split, {
      value: function () { return ["HOOKED"]; }, configurable: true,
    });
    hookedScan = intrinsic.splitChar("127.0.0.1", 46);
  } finally {
    delete String.prototype[Symbol.split];
  }
  // The dispatch mechanism is live in every engine for an OBJECT separator, which is what makes the
  // string-separator fast path an optimisation rather than a guarantee.
  hookedObjSep = "127.0.0.1".split({ [Symbol.split]: function () { return ["HOOKED"]; } });
  check("intrinsic: an object separator carrying @@split IS dispatched to, so the protocol is live",
    hookedObjSep.length === 1 && hookedObjSep[0] === "HOOKED");
  check("intrinsic: splitChar does not consult a separator prototype at all",
    hookedScan.length === 4 && hookedScan[0] === "127" && hookedScan[3] === "1");
  check("intrinsic: splitChar matches split on the delimiter cases these parsers use",
    JSON.stringify(intrinsic.splitChar("a..b", 46)) === JSON.stringify("a..b".split(".")) &&
    JSON.stringify(intrinsic.splitChar("", 46)) === JSON.stringify("".split(".")) &&
    JSON.stringify(intrinsic.splitChar("Websites;Email", 59)) === JSON.stringify("Websites;Email".split(";")));
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
