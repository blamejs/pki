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
  check("non-string/Buffer rejected", codeOf(function () { text.decode(42, 16, TestError, SPEC); }) === "x/bad-input");
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

function run() {
  testDecode();
  testAuthoringBounds();
  testDecodeNotCallerReplaceable();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
