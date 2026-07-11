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

function run() {
  testDecode();
  testAuthoringBounds();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
