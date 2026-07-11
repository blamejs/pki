// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-json (@internal): strict bounded JSON parse of untrusted bytes.
 * Oracle: RFC 8259 grammar + the duplicate-member / __proto__ / depth / size
 * fail-closed contract that JSON.parse does not provide. The consumers (pki.jose
 * message parsing, pki.webcrypto JWK unwrap) are exercised end-to-end in their own
 * suites; these pin the guard's contract directly.
 */

var json = require("../../lib/guard-json");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError", { withCause: true });
var SPEC = {
  maxBytes: 4096, maxDepth: 8,
  badJson: "x/bad-json", tooDeep: "x/too-deep", duplicateMember: "x/dup",
  tooLarge: "x/too-large", badInput: "x/bad-input", label: "the document",
};
function p(input) { return json.parse(input, TestError, SPEC); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testParse() {
  check("object parses", p('{"a":1,"b":[2,3]}').b[1] === 3);
  check("Buffer input parses", p(Buffer.from('{"x":true}')).x === true);
  check("nested + strings + escapes", p('{"s":"a\\nb","n":-1.5e2}').n === -150);
  check("empty object / array", p("{}").constructor === Object && p("[]").length === 0);
}

function testStrict() {
  check("duplicate member rejected", codeOf(function () { p('{"a":1,"a":2}'); }) === "x/dup");
  check("duplicate member at depth rejected", codeOf(function () { p('{"o":{"k":1,"k":2}}'); }) === "x/dup");
  // A repeated __proto__ must still trip the duplicate gate (own-property assignment).
  check("duplicate __proto__ rejected", codeOf(function () { p('{"__proto__":1,"__proto__":2}'); }) === "x/dup");
  // A single __proto__ member is a normal own property, not a prototype mutation.
  check("__proto__ is an own member, prototype intact", (function () {
    var o = p('{"__proto__":{"polluted":true}}');
    return Object.prototype.hasOwnProperty.call(o, "__proto__") && ({}).polluted === undefined;
  })());
  check("leading zero rejected", codeOf(function () { p("01"); }) === "x/bad-json");
  check("bare minus rejected", codeOf(function () { p("-"); }) === "x/bad-json");
  check("trailing content rejected", codeOf(function () { p('{"a":1} x'); }) === "x/bad-json");
  check("control char in string rejected", codeOf(function () { p('"a' + String.fromCharCode(1) + 'b"'); }) === "x/bad-json");
}

function testBounds() {
  check("over-depth rejected", codeOf(function () { p("[[[[[[[[[[1]]]]]]]]]]"); }) === "x/too-deep");
  check("over-size rejected before parse", codeOf(function () {
    json.parse('{"a":"' + new Array(5000).join("x") + '"}', TestError, SPEC);
  }) === "x/too-large");
}

function testAuthoringBounds() {
  // The caps are Tier-1 authoring inputs: an omitted / NaN / fractional cap is
  // a wiring bug that must throw a config-time TypeError -- never silently
  // disable the bound (a depth-uncapped parse escapes as a raw stack-overflow
  // RangeError; a size-uncapped parse allocates without limit).
  function typeErr(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e instanceof TypeError ? "TYPE" : (e.code || "OTHER"); } }
  function spec(over) { var s = {}; Object.keys(SPEC).forEach(function (k) { s[k] = SPEC[k]; }); Object.keys(over).forEach(function (k) { s[k] = over[k]; }); return s; }
  check("omitted maxDepth throws TypeError", typeErr(function () { json.parse("[1]", TestError, spec({ maxDepth: undefined })); }) === "TYPE");
  check("NaN maxDepth throws TypeError", typeErr(function () { json.parse("[1]", TestError, spec({ maxDepth: NaN })); }) === "TYPE");
  check("omitted maxBytes throws TypeError", typeErr(function () { json.parse("[1]", TestError, spec({ maxBytes: undefined })); }) === "TYPE");
  check("fractional maxBytes throws TypeError", typeErr(function () { json.parse("[1]", TestError, spec({ maxBytes: 10.5 })); }) === "TYPE");
  // The stack-safe ceiling binds the depth cap itself (the asn1/cbor model): a
  // maxDepth past it cannot drive the recursive descent into a raw RangeError.
  check("maxDepth above the stack-safe ceiling throws TypeError", typeErr(function () { json.parse("[1]", TestError, spec({ maxDepth: 100000 })); }) === "TYPE");
}

function run() {
  testParse();
  testStrict();
  testBounds();
  testAuthoringBounds();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
