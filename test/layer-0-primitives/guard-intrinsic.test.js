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

async function run() {
  testUncurryContract();
  testEveryComposingGuardHolds();
  testRuntimeReadsAreSnapshotted();
  testKeyEqualsIsSnapshotted();
  testWholeFamilyUnderFullPoisoning();
  await testSelectionsConsultNoConstructionProtocol();
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
async function testSelectionsConsultNoConstructionProtocol() {
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

  // Each ELEMENT is read once, so the value a predicate decides on is the value that is kept. Read
  // twice, an element with a getter answers the test with one value and supplies another, which is
  // the shape where a selection that gates a refusal admits the very thing the refusal examined.
  var twoFaced = [];
  var faceReads = 0;
  Object.defineProperty(twoFaced, "0", {
    get: function () { faceReads += 1; return faceReads === 1 ? "SAFE" : "EVIL"; },
    enumerable: true, configurable: true,
  });
  twoFaced.length = 1;
  var selected = intrinsic.selectList(twoFaced, function (v) { return v === "SAFE"; });
  check("intrinsic: selectList keeps the value its predicate judged, not a second read of the slot",
    selected.length === 1 && selected[0] === "SAFE" && faceReads === 1);

  // Each BOUND is coerced once. Read repeatedly by the clamping arithmetic, an object-valued bound
  // answers differently per read and the window copied is not the one any single read describes.
  var boundReads = 0;
  var movingBound = { valueOf: function () { boundReads += 1; return boundReads === 1 ? 1 : 2; } };
  var copied = intrinsic.copyList([1, 2, 3], movingBound);
  check("intrinsic: copyList coerces a bound once", boundReads === 1 && copied.length === 2 && copied[0] === 2);
  check("intrinsic: copyList still matches slice on negative and clamped bounds",
    JSON.stringify(intrinsic.copyList([1, 2, 3, 4, 5], -2)) === JSON.stringify([1, 2, 3, 4, 5].slice(-2)) &&
    JSON.stringify(intrinsic.copyList([1, 2, 3], 1, 99)) === JSON.stringify([1, 2, 3].slice(1, 99)));

  // The offset the second operand lands at comes from the COPY. Taken by re-reading the first
  // operand, an element getter that ran during the copy could have changed that length in between,
  // so the second operand would overwrite copied entries or leave holes.
  var shrinkOnRead = [];
  Object.defineProperty(shrinkOnRead, "0", {
    get: function () { shrinkOnRead.length = 1; return "a"; }, enumerable: true, configurable: true,
  });
  Object.defineProperty(shrinkOnRead, "1", { value: "b", enumerable: true, configurable: true, writable: true });
  // The copy captured a length of 2 before the getter ran, so it holds two slots; taking the offset
  // from the shrunken first operand instead puts `z` at index 1, on top of one of them.
  var joined = intrinsic.concatList(shrinkOnRead, ["z"]);
  check("intrinsic: concatList places the second operand after what it actually copied",
    joined.length === 3 && joined[0] === "a" && joined[2] === "z");

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

  // `charCodeAt` and `slice` each convert their receiver, so a receiver that is not already a string
  // is scanned as one value and sliced as another: one answering "a.b" for the first two reads and
  // "XYZ" afterwards returned the fields of a string the delimiter scan never saw. The delimiter has
  // the mirror of that problem: `===` against a character code never coerces, so an object delimiter
  // matches nothing and the whole input comes back as one field, which every caller reads as "this
  // value carries no delimiter". Both are refused rather than answered.
  var movingRecv = { length: 3, toString: function () { return movingRecv.n++ < 2 ? "a.b" : "XYZ"; }, n: 0 };
  check("intrinsic: splitChar refuses a receiver that is not a string",
    typeOf(function () { return intrinsic.splitChar(movingRecv, 46); }) === "TypeError");
  check("intrinsic: splitChar refuses a delimiter that is not a character code",
    typeOf(function () { return intrinsic.splitChar("a.b", { valueOf: function () { return 46; } }); }) === "TypeError" &&
    typeOf(function () { return intrinsic.splitChar("a.b", "."); }) === "TypeError");

  // The clamping arithmetic reads a bound two or three times, and every relational comparison
  // coerces an object afresh. The same fix `copyList` took has to hold for the byte window: a start
  // answering 1 for the comparisons and 0 afterwards was compared as 1 and sliced from 0, so the
  // view returned covered a byte the bound excluded.
  var byteReads = 0;
  var movingStart = { valueOf: function () { byteReads += 1; return byteReads <= 3 ? 1 : 0; } };
  var window40 = intrinsic.byteSlice(Buffer.from([10, 20, 30, 40]), movingStart, 3);
  var stable40 = intrinsic.byteSlice(Buffer.from([10, 20, 30, 40]), 1, 3);
  check("intrinsic: byteSlice coerces a bound once, so the view is the window one read describes",
    byteReads === 1 && window40.length === 2 && window40[0] === 20 && window40[1] === 30 &&
    stable40.length === 2 && stable40[0] === 20);
  check("intrinsic: byteSlice still clamps and defaults the way subarray does",
    intrinsic.byteSlice(Buffer.from([1, 2, 3])).length === 3 &&
    intrinsic.byteSlice(Buffer.from([1, 2, 3]), 2, 99).length === 1 &&
    intrinsic.byteSlice(Buffer.from([1, 2, 3]), 3, 1).length === 0);
  // A fractional bound finds no slot: `list[0.5]` is absent, so the result carries its full length
  // with nothing in it, which reads as a window of absent values rather than as the bad argument.
  // The continuation primitive invokes its captured method through the uncurried form, so it consults
  // neither `Promise.prototype.then` nor `Function.prototype.call`. Invoking a capture as
  // `captured.call(receiver, ...)` reads `call` off the function at that moment, which is one
  // replaceable operation standing between the capture and its use.
  var callReplaced = false;
  var realCall = Function.prototype.call;
  var seven = Promise.resolve(7);
  var chained;
  try {
    Function.prototype.call = function () { callReplaced = true; throw new Error("call was consulted"); };
    chained = intrinsic.chain(seven, function (v) { return v + 1; });
  } finally { Function.prototype.call = realCall; }
  var chainedValue = await chained;
  check("intrinsic: chain invokes its capture without reading Function.prototype.call",
    chainedValue === 8 && callReplaced === false);
  var thenReplaced = false;
  var realThenDesc = Object.getOwnPropertyDescriptor(Promise.prototype, "then");
  var real = Promise.resolve("real");
  var hooked = Promise.resolve("HOOKED");
  var chained2;
  try {
    Object.defineProperty(Promise.prototype, "then", {
      value: function () { thenReplaced = true; return hooked; },
      writable: true, configurable: true,
    });
    chained2 = intrinsic.chain(real, function (v) { return v; });
  } finally { Object.defineProperty(Promise.prototype, "then", realThenDesc); }
  check("intrinsic: chain does not consult a replaced Promise.prototype.then",
    (await chained2) === "real" && thenReplaced === false);

  // Native `then` builds the promise it RETURNS through SpeciesConstructor, which reads `constructor`
  // off the promise and `Symbol.species` off that, and that descriptor is configurable. A species
  // whose executor drops its resolve function and answers with a promise of its own hands the caller
  // a verdict nothing computed. The promise `chain` returns is built from the captured constructor,
  // and whatever `then` returns is discarded.
  var realPromiseSpecies = Object.getOwnPropertyDescriptor(Promise, Symbol.species);
  function HostileSpecies(executor) { executor(function () {}, function () {}); return Promise.resolve({ valid: true }); }
  var speciesChained;
  try {
    Object.defineProperty(Promise, Symbol.species, { value: HostileSpecies, configurable: true });
    speciesChained = intrinsic.chain(Promise.resolve("real"), function (v) { return v; });
  } finally { Object.defineProperty(Promise, Symbol.species, realPromiseSpecies); }
  check("intrinsic: a hostile promise species cannot substitute the promise chain hands back",
    (await speciesChained) === "real");

  // Resolving a promise with a thenable is specified to read `then` off that thenable and call it, so
  // a callback that RETURNS a promise is adopted through the live method even when the continuation
  // itself was captured. A real promise is adopted through the capture instead; the hook must not be
  // consulted at all, and the value must be the one the inner promise actually carried.
  // The adoption happens in a MICROTASK after `chain` returns, so the replacement has to stay
  // installed across the drain: restoring it in a `finally` removes it first and the vector then
  // passes against the live method too. The result is observed through a captured continuation
  // rather than by awaiting, since awaiting would be the caller's own boundary and not this one.
  var adoptionHookCalls = 0;
  var realThenDesc2 = Object.getOwnPropertyDescriptor(Promise.prototype, "then");
  var fabricated = Promise.resolve({ valid: true, fabricated: true });
  var adopted = null;
  try {
    Object.defineProperty(Promise.prototype, "then", {
      value: function (ok, fail) { adoptionHookCalls += 1; return realThenDesc2.value.call(fabricated, ok, fail); },
      writable: true, configurable: true,
    });
    var adoptionChained = intrinsic.chain(Promise.resolve(1), function () { return Promise.resolve("inner-real"); });
    intrinsic.chain(adoptionChained, function (v) { adopted = { value: v }; },
      function (e) { adopted = { error: (e && e.message) || String(e) }; });
    await helpers.waitUntil(function () { return adopted !== null; },
      { timeoutMs: 2000, label: "the chained promise settles under a replaced Promise.prototype.then" });
  } finally { Object.defineProperty(Promise.prototype, "then", realThenDesc2); }
  check("intrinsic: a promise returned from a callback is adopted through the capture (calls=" +
    adoptionHookCalls + ")", adopted.value === "inner-real" && adoptionHookCalls === 0);

  // A replacement that steers the chain has to be prevented without the verb drifting away from the
  // method it stands in for, so the two are compared over the cases a caller can produce: a handler
  // omitted, supplied as null, as a number and as an object; a rejection with and without a handler;
  // a handler that throws; a recovery that returns and one that throws; a returned rejected promise;
  // a returned thenable that settles more than once and then throws; and a returned object whose
  // `then` getter throws. All sixteen outcomes must read the same both ways.
  var rawThen = Object.getOwnPropertyDescriptor(Promise.prototype, "then").value;
  function observe(p) {
    return new Promise(function (r) {
      rawThen.call(p, function (v) { r(["ok", v]); },
        function (e) { r(["err", e instanceof Error ? e.name + ": " + e.message : e]); });
    });
  }
  async function outcomes(viaChain) {
    function go(p, a, b) { return viaChain ? intrinsic.chain(p, a, b) : p.then(a, b); }
    var rows = [];
    var handlers = [undefined, null, 17, {}];
    for (var hi = 0; hi < handlers.length; hi++) {
      rows.push(await observe(go(Promise.resolve(7), handlers[hi], handlers[hi])));
      rows.push(await observe(go(Promise.reject("bad"), handlers[hi], handlers[hi])));
    }
    rows.push(await observe(go(Promise.resolve(1), function () { throw new Error("boom"); }, function () { return "wrong"; })));
    rows.push(await observe(go(Promise.reject("bad"), undefined, function (e) { return "recovered:" + e; })));
    rows.push(await observe(go(Promise.reject("bad"), undefined, function () { throw new Error("fail-throw"); })));
    rows.push(await observe(go(Promise.resolve(), function () { return Promise.reject("inner-bad"); })));
    rows.push(await observe(go(Promise.resolve(), function () {
      return { then: function (res, rej) { res(8); rej("late"); res(9); throw new Error("late"); } };
    })));
    rows.push(await observe(go(Promise.resolve(), function () { return { get then() { throw new Error("getter"); } }; })));
    // A `then` getter answering a non-function and then a function: the specified procedure reads it
    // ONCE, so the first answer decides. Testing it here before settling would read it twice and the
    // second answer would settle what the first had already ruled out.
    var reads = 0;
    rows.push(await observe(go(Promise.resolve(), function () {
      return { get then() { return ++reads === 1 ? undefined : function (ok) { ok("forged"); }; } };
    })));
    // And a microtask between the handler returning a thenable and that thenable settling: the job is
    // queued, not run in place, so the value it reads is the one current when it runs.
    var flag = "before";
    rows.push(await observe(go(Promise.resolve(), function () {
      queueMicrotask(function () { flag = "after"; });
      return { then: function (ok) { ok(flag); } };
    })));
    return JSON.stringify(rows);
  }
  var nativeOutcomes = await outcomes(false);
  var chainOutcomes = await outcomes(true);
  check("intrinsic: chain settles exactly as the method it stands in for, over eighteen outcomes",
    nativeOutcomes === chainOutcomes);
  // A thenable is accepted in the receiver position, which is what the method it replaces does, and a
  // value that is no kind of promise is the same TypeError that method raises.
  var fromThenable = await intrinsic.chain({ then: function (ok) { ok(3); } }, function (v) { return v + 1; });
  check("intrinsic: chain takes a thenable receiver and refuses a value that is neither",
    fromThenable === 4 && typeOf(function () { return intrinsic.chain({}, function (v) { return v; }); }) === "TypeError");
  // A handler that returns the promise its own call hands back is a cycle. The method it replaces
  // rejects it; waiting on it would leave a verify that never settles and so never refuses.
  var cyclic;
  cyclic = intrinsic.chain(Promise.resolve(1), function () { return cyclic; });
  var cyclicOutcome = await observe(cyclic);
  check("intrinsic: a handler returning its own result promise is refused rather than waited on",
    cyclicOutcome[0] === "err" && String(cyclicOutcome[1]).indexOf("TypeError") === 0);
  // The species is read off the promise's `constructor`, so a getter that throws is the one way a
  // REAL promise makes the captured call fail. Treating that as "not a promise" and settling through
  // the resolve function would adopt the promise's own `then` instead, which is the substitution the
  // capture exists to prevent: the failure is a refusal.
  var trapped = Promise.resolve("real");
  Object.defineProperty(trapped, "constructor", { get: function () { throw new Error("species trap"); } });
  Object.defineProperty(trapped, "then", { value: function (ok) { ok("forged"); }, configurable: true });
  var trappedOutcome = await observe(intrinsic.chain(Promise.resolve(1), function () { return trapped; }));
  check("intrinsic: a promise whose constructor read throws is refused, not adopted through its own then",
    trappedOutcome[0] === "err" && trappedOutcome[1] === "Error: species trap");
  // An object carrying the promise prototype without a promise's state is refused for the same
  // reason, where the method it replaces would settle with the object. Both deviations are refusals,
  // which is the direction a verdict path may deviate in.
  var protoOnly = Object.create(Promise.prototype, { then: { value: undefined } });
  var protoOutcome = await observe(intrinsic.chain(Promise.resolve(1), function () { return protoOnly; }));
  check("intrinsic: an object carrying the promise prototype without its state is refused",
    protoOutcome[0] === "err" && String(protoOutcome[1]).indexOf("TypeError") === 0);
  // The classification runs inside the refusal as well. This step is reached from inside a
  // continuation, so a value whose prototype cannot even be read would otherwise leave the verb
  // pending with an unhandled rejection beside it, and a verify that never settles never refuses.
  var trapOutcome = null;
  var trapChain = intrinsic.chain(Promise.resolve(1), function () {
    return new Proxy({}, { getPrototypeOf: function () { throw new Error("prototype trap"); } });
  });
  intrinsic.chain(trapChain, function (v) { trapOutcome = ["ok", v]; },
    function (e) { trapOutcome = ["err", (e && e.message) || String(e)]; });
  await helpers.waitUntil(function () { return trapOutcome !== null; },
    { timeoutMs: 2000, label: "the chain settles for a value whose prototype read throws" });
  check("intrinsic: a value whose prototype cannot be read is refused rather than left pending",
    trapOutcome[0] === "err" && trapOutcome[1] === "prototype trap");

  // A value that is NOT a promise is still handed to the resolve function, because a caller's own
  // thenable is the thing to call rather than a mechanism to route around.
  var ownThenableCalled = false;
  var viaOwnThenable = intrinsic.chain(Promise.resolve(1), function () {
    return { then: function (res) { ownThenableCalled = true; res("from the caller's thenable"); } };
  });
  check("intrinsic: a caller's own thenable is still called",
    (await viaOwnThenable) === "from the caller's thenable" && ownThenableCalled === true);
  // And the handler contract is unchanged: a throw rejects, a rejection without a handler passes
  // through, and a handler that returns settles the chain with its value.
  var threw = await intrinsic.chain(Promise.resolve(1), function () { throw new Error("boom"); },
    undefined).then(function () { return "NO-THROW"; }, function (e) { return e.message; });
  var recovered = await intrinsic.chain(Promise.reject(new Error("nope")), undefined,
    function (e) { return "recovered: " + e.message; });
  var passedThrough = await intrinsic.chain(Promise.reject(new Error("unhandled")), function (v) { return v; })
    .then(function () { return "NO-THROW"; }, function (e) { return e.message; });
  check("intrinsic: chain keeps the handler contract of the method it replaces",
    threw === "boom" && recovered === "recovered: nope" && passedThrough === "unhandled");

  // `indexOf` and `every` are specified in terms of HasProperty, so both consult the prototype at an
  // index the list has a HOLE at: membership finds a value the list does not hold, and the universal
  // test SKIPS the hole and so answers true for a list with no elements of its own. Together that is
  // an allow-list a caller left empty admitting a value installed on the prototype.
  var realIndexZero = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  var ownResult, nativeResult, copyResult;
  try {
    Array.prototype[0] = "https://evil.example";
    var sparse = new Array(1);
    ownResult = [intrinsic.ownIndexOf(sparse, "https://evil.example"),
      intrinsic.everyOwn(sparse, function (o) { return typeof o === "string"; })];
    nativeResult = [sparse.indexOf("https://evil.example"),
      sparse.every(function (o) { return typeof o === "string"; })];
    copyResult = intrinsic.copyList(sparse)[0];
  } finally {
    if (realIndexZero) Object.defineProperty(Array.prototype, "0", realIndexZero);
    else delete Array.prototype[0];
  }
  check("intrinsic: a hole does not read as an inherited member (native answers " +
    JSON.stringify(nativeResult) + ")",
  ownResult[0] === -1 && ownResult[1] === false && nativeResult[0] === 0 && nativeResult[1] === true);
  check("intrinsic: and a copy of a sparse list carries nothing from the prototype",
    copyResult === undefined);

  // Capturing `Promise.all` is not enough: it performs GetPromiseResolve on the constructor at EACH
  // call, so a replaced `Promise.resolve` hands the aggregate its own values and no component is
  // awaited at all. `allOf` subscribes to each member through the captured continuation instead.
  var realResolve = Promise.resolve;
  var allUncurried = intrinsic.uncurry(intrinsic.promiseAll);
  var falseA = realResolve.call(Promise, false), falseB = realResolve.call(Promise, false);
  var viaAll, viaAllOf;
  try {
    Promise.resolve = function () { return realResolve.call(Promise, true); };
    viaAll = allUncurried(Promise, [falseA, falseB]);
    viaAllOf = intrinsic.allOf([falseA, falseB]);
  } finally { Promise.resolve = realResolve; }
  var allValues = await viaAll;
  var allOfValues = await viaAllOf;
  check("intrinsic: allOf awaits its members where a captured Promise.all takes a replaced resolve " +
    "(" + JSON.stringify(allValues) + " vs " + JSON.stringify(allOfValues) + ")",
  allValues[0] === true && allValues[1] === true && allOfValues[0] === false && allOfValues[1] === false);
  // Settling a promise with a value reads `then` off that value and calls it when it is callable, so
  // a `then` installed on `Array.prototype` makes every ordinary array a thenable and the aggregate
  // settles with whatever that replacement answers instead of its result list. The list handed back
  // inherits nothing, so there is no `then` to find; every consumer reads it through verbs that take
  // the receiver rather than calling a method on it.
  // The replacement has to stay installed across the microtask drain, since the settlement that
  // would read it happens after the call returns. The outcomes are observed through the captured
  // continuation rather than by awaiting, so the observation is not the thing under test.
  var realArrayThen = Object.getOwnPropertyDescriptor(Array.prototype, "then");
  var aggAllValue = null, aggSettledValue = null;
  try {
    Array.prototype.then = function (res) { res("forged"); };
    intrinsic.chain(intrinsic.allOf([Promise.resolve(1)]), function (v) { aggAllValue = v; });
    intrinsic.chain(intrinsic.settledOf([Promise.resolve(2)]), function (v) { aggSettledValue = v; });
    await helpers.waitUntil(function () { return aggAllValue !== null && aggSettledValue !== null; },
      { timeoutMs: 2000, label: "both aggregates settle under an inherited Array.prototype.then" });
  } finally {
    if (realArrayThen) Object.defineProperty(Array.prototype, "then", realArrayThen);
    else delete Array.prototype.then;
  }
  check("intrinsic: an inherited `then` cannot replace an aggregate's result list",
    aggAllValue.length === 1 && aggAllValue[0] === 1 &&
    aggSettledValue.length === 1 && aggSettledValue[0].status === "fulfilled" && aggSettledValue[0].value === 2);

  // Asking whether an index is the list's own and then reading it are two operations, and a proxy
  // whose descriptor trap reports the element and deletes it answers the first yes and the second
  // from the prototype. Existence and value come from one descriptor read.
  var realIndexZeroB = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  var trapResult;
  try {
    Array.prototype[0] = "inherited";
    var base = ["real"];
    var vanishing = new Proxy(base, {
      getOwnPropertyDescriptor: function (t, k) {
        var d = Reflect.getOwnPropertyDescriptor(t, k);
        if (k === "0") delete t[0];
        return d;
      },
    });
    trapResult = [intrinsic.ownIndexOf(vanishing, "inherited"),
      intrinsic.everyOwn(vanishing, function (v) { return v === "inherited"; })];
  } finally {
    if (realIndexZeroB) Object.defineProperty(Array.prototype, "0", realIndexZeroB);
    else delete Array.prototype[0];
  }
  check("intrinsic: an element that vanishes between the ownership answer and the read is not taken " +
    "from the prototype", trapResult[0] === -1 && trapResult[1] === false);

  check("intrinsic: allOf keeps member order and rejects on the first rejection",
    JSON.stringify(await intrinsic.allOf([Promise.resolve(1), Promise.resolve(2), Promise.resolve(3)])) === "[1,2,3]" &&
    JSON.stringify(await intrinsic.allOf([])) === "[]" &&
    (await intrinsic.chain(intrinsic.allOf([Promise.resolve(1), Promise.reject(new Error("first"))]),
      function () { return "NO-THROW"; }, function (e) { return e.message; })) === "first");

  check("intrinsic: a fractional bound is refused by both windowing verbs",
    typeOf(function () { return intrinsic.copyList([10, 20, 30], 0.5, 2); }) === "TypeError" &&
    typeOf(function () { return intrinsic.byteSlice(Buffer.from([1, 2, 3]), 0.5); }) === "TypeError" &&
    typeOf(function () { return intrinsic.copyList([10, 20, 30], NaN); }) === "TypeError");
}

function typeOf(fn) {
  try { fn(); return "NO-THROW"; } catch (e) { return e.constructor.name; }
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
