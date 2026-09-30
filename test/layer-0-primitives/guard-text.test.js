// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-text (@internal): bounded byte-source -> string decode, cap
 * BEFORE copy. The cap-before-copy and detached-buffer contracts are exercised
 * behaviorally through the composing boundaries (PEM decode, EST transfer,
 * guard-json); these pin the guard's own contract directly, including the
 * authoring edge: a malformed maxBytes must throw a config-time TypeError,
 * never silently disable the size cap.
 */

var text = require("../../lib/guard-text");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError", { withCause: true });
var SPEC = { tooLarge: "x/too-large", badInput: "x/bad-input", label: "the text" };
var FATAL = { charset: "utf-8", fatal: true, tooLarge: "x/too-large", badDecode: "x/bad-utf8", badInput: "x/bad-input", label: "the text" };
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e instanceof TypeError ? "TYPE" : (e.code || "OTHER"); } }

function testDecode() {
  check("Buffer decodes latin1 by default", text.decode(Buffer.from("abc"), 16, TestError, SPEC) === "abc");
  check("string passes through", text.decode("abc", 16, TestError, SPEC) === "abc");
  check("over-cap Buffer rejected", codeOf(function () { text.decode(Buffer.alloc(17), 16, TestError, SPEC); }) === "x/too-large");
  check("over-cap string rejected", codeOf(function () { text.decode(new Array(18).join("x"), 16, TestError, SPEC); }) === "x/too-large");
  // Any byte source decodes, not only a Node Buffer (a caller-injected transport may return a Uint8Array, a
  // DataView, or a raw ArrayBuffer); each is re-viewed through the byte guard, capped, then decoded.
  check("Uint8Array decodes (a byte source, not only a Buffer)", text.decode(new Uint8Array([0x61, 0x62, 0x63]), 16, TestError, SPEC) === "abc");
  check("DataView decodes (a byte source)", text.decode(new DataView(Uint8Array.from([0x61, 0x62, 0x63]).buffer), 16, TestError, SPEC) === "abc");
  check("raw ArrayBuffer decodes (the full BufferSource contract)", text.decode(Uint8Array.from([0x61, 0x62, 0x63]).buffer, 16, TestError, SPEC) === "abc");
  check("over-cap Uint8Array rejected (cap-before-copy applies to every byte source)", codeOf(function () { text.decode(new Uint8Array(17), 16, TestError, SPEC); }) === "x/too-large");
  check("non-byte-source/non-string rejected", codeOf(function () { text.decode(42, 16, TestError, SPEC); }) === "x/bad-input");
  check("fatal utf-8 rejects an invalid sequence", codeOf(function () { text.decode(Buffer.from([0xC3]), 16, TestError, FATAL); }) === "x/bad-utf8");
  check("fatal utf-8 decodes a valid sequence", text.decode(Buffer.from([0xC3, 0xA9]), 16, TestError, FATAL) === String.fromCharCode(0xE9));
}

function testAuthoringBounds() {
  // maxBytes is an authoring input: an undefined / NaN / fractional cap makes
  // `length > maxBytes` always false -- the size cap silently disabled on the
  // guard whose contract is cap-BEFORE-copy. Config-time TypeError instead.
  check("undefined maxBytes throws TypeError", codeOf(function () { text.decode(Buffer.from("a"), undefined, TestError, SPEC); }) === "TYPE");
  check("NaN maxBytes throws TypeError", codeOf(function () { text.decode(Buffer.from("a"), NaN, TestError, SPEC); }) === "TYPE");
  check("fractional maxBytes throws TypeError", codeOf(function () { text.decode(Buffer.from("a"), 1.5, TestError, SPEC); }) === "TYPE");
}

// The decode does not dispatch through a property a caller can replace. `Buffer.prototype.toString`
// is writable, and on the Buffer arm it produces the guard's entire output: replaced with a function
// returning a constant, the cap still runs, the detached-view refusal still runs, the fatal-UTF-8
// rule still runs, and every one of them passes -- while what a PEM header, a JOSE segment or a DN
// attribute is read from is a string the caller chose.
function testDecodeNotCallerReplaceable() {
  var realToString = Buffer.prototype.toString;
  var latin1, fatalUtf8;
  try {
    Buffer.prototype.toString = function () { return "SUBSTITUTED"; };
    latin1 = text.decode(Buffer.from("abc"), 16, TestError, SPEC);
    fatalUtf8 = text.decode(Buffer.from([0xC3, 0xA9]), 16, TestError, FATAL);
  } finally {
    Buffer.prototype.toString = realToString;
  }
  check("a replaced Buffer.prototype.toString cannot substitute the decoded latin1 text", latin1 === "abc");
  check("a replaced Buffer.prototype.toString cannot substitute the fatal utf-8 text",
    fatalUtf8 === String.fromCharCode(0xE9));

  // The fatal arm produces its output through TextDecoder rather than through the Buffer method
  // above, so it needs its own answer to the same question -- covering one arm and leaving the
  // other reading a live property is how this defect gets half-fixed.
  var realDecode = TextDecoder.prototype.decode, fatalOut;
  try {
    TextDecoder.prototype.decode = function () { return "SUBSTITUTED"; };
    fatalOut = text.decode(Buffer.from([0xC3, 0xA9]), 16, TestError, FATAL);
  } finally {
    TextDecoder.prototype.decode = realDecode;
  }
  check("a replaced TextDecoder.prototype.decode cannot substitute the fatal utf-8 text",
    fatalOut === String.fromCharCode(0xE9));

  // The string arm is measured against the cap with Buffer.byteLength, so a replacement returning
  // a small number admits a string of any size -- which is the allocation the cap exists to bound.
  var realByteLength = Buffer.byteLength, bigCode;
  try {
    Buffer.byteLength = function () { return 1; };
    bigCode = codeOf(function () {
      text.decode(new Array(200).join("é"), 16, TestError,
        { charset: "utf-8", tooLarge: "x/too-large", badInput: "x/bad-input", label: "the text" });
    });
  } finally {
    Buffer.byteLength = realByteLength;
  }
  check("a replaced Buffer.byteLength cannot admit an over-cap string", bigCode === "x/too-large");

  // The cap check itself, and the test that decides which arm an input takes.
  var realIsInteger = Number.isInteger, capCode;
  try {
    Number.isInteger = function () { return true; };
    capCode = codeOf(function () { text.decode(Buffer.from("a"), NaN, TestError, SPEC); });
  } finally {
    Number.isInteger = realIsInteger;
  }
  check("a replaced Number.isInteger cannot disable the cap check", capCode === "TYPE");

  // Caught inside the swap so the failure reports as this check rather than escaping the suite as
  // an unnamed throw. Without the capture a Buffer takes neither arm and the decode refuses it.
  var realIsBuffer = Buffer.isBuffer, armOut;
  try {
    Buffer.isBuffer = function () { return false; };
    try { armOut = text.decode(Buffer.from("abc"), 16, TestError, SPEC); }
    catch (e) { armOut = "threw " + (e.code || "OTHER"); }
  } finally {
    Buffer.isBuffer = realIsBuffer;
  }
  check("a replaced Buffer.isBuffer cannot route a Buffer down the string arm", armOut === "abc");
}

function testShowValue() {
  check("showValue quotes a string", text.showValue("pem") === "\"pem\"");
  check("showValue prints a number", text.showValue(42) === "42");
  check("showValue prints a bigint without throwing", text.showValue(1n) === "1");
  check("showValue prints a boolean", text.showValue(true) === "true");
  check("showValue names null", text.showValue(null) === "null");
  check("showValue names a plain object by type", text.showValue({ a: 1 }) === "a value of type object");
  var cyclic = {}; cyclic.self = cyclic;
  check("showValue never throws on a cyclic object", text.showValue(cyclic) === "a value of type object");
  var throwsToJson = { toJSON: function () { throw new Error("boom"); } };
  check("showValue does not invoke a caller toJSON", text.showValue(throwsToJson) === "a value of type object");
  check("showValue names a symbol by type", text.showValue(Symbol("s")) === "a value of type symbol");
  check("showValue names a function by type", text.showValue(function () {}) === "a value of type function");
  check("showValue names undefined by type", text.showValue(undefined) === "a value of type undefined");
}

function testKeyOf() {
  check("keyOf passes a string through", text.keyOf("aes-256-cbc") === "aes-256-cbc");
  check("keyOf passes a number through", text.keyOf(1) === 1);
  check("keyOf maps an object with no primitive coercion to undefined", text.keyOf(Object.create(null)) === undefined);
  check("keyOf maps an object whose Symbol.toPrimitive throws to undefined", text.keyOf({ [Symbol.toPrimitive]: function () { throw new Error("x"); } }) === undefined);
  check("keyOf maps a plain object to undefined", text.keyOf({ a: 1 }) === undefined);
  check("keyOf maps a bigint to undefined", text.keyOf(1n) === undefined);
  check("keyOf maps null to undefined", text.keyOf(null) === undefined);
  var MAP = { "aes-256-cbc": 1 };
  var patho = Object.create(null);
  var safe = true;
  try { void MAP[text.keyOf(patho)]; } catch (_e) { safe = false; }
  check("a table indexed by keyOf(a coercion-unsafe object) misses without throwing", safe && MAP[text.keyOf(patho)] === undefined);
  check("a table indexed by keyOf(a valid key) still hits", MAP[text.keyOf("aes-256-cbc")] === 1);
}

// assertWellFormedUtf16: the guard's own contract. An unpaired UTF-16 surrogate has no UTF-8 encoding
// and every conversion in the platform substitutes U+FFFD for it rather than failing, so two strings
// differing only in that code unit convert to the SAME bytes. Wherever those bytes are signed or hashed
// that is a collision. The surrogate halves are built with String.fromCharCode so this source stays
// pure ASCII; a literal would put a lone surrogate in the file.
var HI = String.fromCharCode(0xd800), HI_MAX = String.fromCharCode(0xdbff);
var LO = String.fromCharCode(0xdc00), LO_MAX = String.fromCharCode(0xdfff);
// U+FFFD is built the same way: written as an escape, the file on disk ends up holding the character's
// raw UTF-8 bytes, and this source stays ASCII.
var REPLACEMENT = String.fromCharCode(0xfffd);
function wf(s) { return text.assertWellFormedUtf16(s, TestError, "x/bad-utf16", "the value"); }

function testWellFormedUtf16() {
  // The collision the guard exists to prevent, measured rather than asserted from memory: without a
  // check, these two distinct strings convert to identical bytes.
  check("the premise: a lone surrogate and U+FFFD convert to the same UTF-8 bytes",
    Buffer.from(HI, "utf8").equals(Buffer.from(REPLACEMENT, "utf8")));

  check("a lone high surrogate is refused", codeOf(function () { wf(HI); }) === "x/bad-utf16");
  check("the top of the high range is refused", codeOf(function () { wf(HI_MAX); }) === "x/bad-utf16");
  check("a lone low surrogate is refused", codeOf(function () { wf(LO); }) === "x/bad-utf16");
  check("the top of the low range is refused", codeOf(function () { wf(LO_MAX); }) === "x/bad-utf16");
  check("a reversed pair is refused, the low half coming first",
    codeOf(function () { wf(LO + HI); }) === "x/bad-utf16");
  check("a high surrogate at the very end is refused, there being no next unit",
    codeOf(function () { wf("ab" + HI); }) === "x/bad-utf16");
  check("a high surrogate followed by an ordinary character is refused",
    codeOf(function () { wf(HI + "a"); }) === "x/bad-utf16");
  check("a high surrogate followed by another high surrogate is refused",
    codeOf(function () { wf(HI + HI + LO); }) === "x/bad-utf16");

  // Every well-formed pair passes, including both corners of the range, or the guard would be refusing
  // ordinary characters above the BMP rather than the malformed ones.
  [[HI, LO], [HI, LO_MAX], [HI_MAX, LO], [HI_MAX, LO_MAX]].forEach(function (p, i) {
    check("CONTROL well-formed pair " + i + " passes", codeOf(function () { wf(p[0] + p[1]); }) === "NO-THROW");
  });
  check("CONTROL a pair between ordinary characters passes, the scan resuming after it",
    codeOf(function () { wf("a" + HI + LO + "b" + HI_MAX + LO_MAX + "c"); }) === "NO-THROW");
  check("CONTROL the empty string and plain ASCII pass",
    codeOf(function () { wf(""); }) === "NO-THROW" && codeOf(function () { wf("plain"); }) === "NO-THROW");
  check("CONTROL U+FFFD itself passes, being an ordinary code point",
    codeOf(function () { wf(REPLACEMENT); }) === "NO-THROW");
  check("the string is returned, so the guard can wrap a value in place",
    wf("ok") === "ok");

  // The caller's own class and code carry the fault, so each boundary keeps its domain/reason.
  var e = null;
  try { wf(HI); } catch (err) { e = err; }
  check("the fault is the caller's error class and code",
    e instanceof TestError && e.code === "x/bad-utf16");
  check("and it names the value and the index",
    e.message.indexOf("the value") === 0 && e.message.indexOf("index 0") !== -1);
}

function run() {
  testDecode();
  testAuthoringBounds();
  testDecodeNotCallerReplaceable();
  testShowValue();
  testKeyOf();
  testWellFormedUtf16();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
