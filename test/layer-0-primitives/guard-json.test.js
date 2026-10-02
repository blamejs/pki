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
var BS = String.fromCharCode(92); // JSON escape lead-in, built at runtime to keep source ASCII-clean

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

function testGrammarErrors() {
  // value() reaching end-of-input: an empty or whitespace-only document has no
  // value token and must be rejected, not silently return undefined.
  check("empty input rejected", codeOf(function () { p(""); }) === "x/bad-json");
  check("whitespace-only input rejected", codeOf(function () { p("   "); }) === "x/bad-json");
  // An object key must be a quoted string.
  check("numeric object key rejected", codeOf(function () { p("{1:2}"); }) === "x/bad-json");
  check("unquoted object key rejected", codeOf(function () { p("{a:1}"); }) === "x/bad-json");
  // The key/value separator must be ':'.
  check("missing ':' after key rejected", codeOf(function () { p('{"a" 1}'); }) === "x/bad-json");
  // A member must be followed by ',' or '}'.
  check("missing ',' between members rejected", codeOf(function () { p('{"a":1 "b":2}'); }) === "x/bad-json");
  // An array element must be followed by ',' or ']'.
  check("missing ',' between elements rejected", codeOf(function () { p("[1 2]"); }) === "x/bad-json");
  // A string with no closing quote.
  check("unterminated string rejected", codeOf(function () { p(String.fromCharCode(34) + "abc"); }) === "x/bad-json");
  // A backslash as the final byte (dangling escape) must not read past the end.
  check("dangling escape rejected", codeOf(function () { p(String.fromCharCode(34) + "abc" + BS); }) === "x/bad-json");
}

function testStringEscapes() {
  // Each RFC 8259 two-character escape decodes to its single control/literal char.
  check("escaped quote decodes", p('"' + BS + '""') === String.fromCharCode(34));
  check("escaped backslash decodes", p('"' + BS + BS + '"') === BS);
  check("escaped solidus decodes", p('"' + BS + '/"') === "/");
  check("escaped backspace decodes", p('"' + BS + 'b"').charCodeAt(0) === 8);
  check("escaped formfeed decodes", p('"' + BS + 'f"').charCodeAt(0) === 12);
  check("escaped carriage-return decodes", p('"' + BS + 'r"').charCodeAt(0) === 13);
  check("escaped tab decodes", p('"' + BS + 't"').charCodeAt(0) === 9);
}

function testNumberOverflow() {
  // A token that satisfies the RFC 8259 number grammar but overflows IEEE-754 to
  // Infinity must fail closed -- never be returned as a non-finite value.
  check("overflow exponent rejected", codeOf(function () { p("1e400"); }) === "x/bad-json");
  check("negative overflow exponent rejected", codeOf(function () { p("-1e400"); }) === "x/bad-json");
}

function run() {
  testParse();
  testStrict();
  testBounds();
  testAuthoringBounds();
  testGrammarErrors();
  testStringEscapes();
  testNumberOverflow();
  testExactIntegers();
}

// A format can forbid floating point outright, and `integersOnly` refuses any token carrying a `.` or an
// exponent for it. Ordinary JSON formats do not: RFC 6962, protobuf-JSON and the WebAuthn metadata
// statement all permit `1e3`, so refusing exponent form there would refuse a document a conforming
// producer emitted.
//
// What those formats DO need is that a value they will treat as an integer is the integer the producer
// wrote. `1.0000000000000001` converts to the Number 1, so an `isInteger` check AFTER conversion sees a
// conforming document and the value the client goes on to report is not the spelling the server sent. For
// CT that value is folded into a reconstructed binary preimage, so the rounding spelling verifies.
//
// `exactIntegers` is that rule, applied to the TOKEN while it is still text: the token must denote an
// integer, and one a double represents exactly. It accepts everything a producer may legally write for an
// integer and refuses every spelling whose value is not exactly its own integer.
function testExactIntegers() {
  var EXACT = { maxBytes: 4096, maxDepth: 8, exactIntegers: true,
    badJson: "x/bad-json", tooDeep: "x/too-deep", duplicateMember: "x/dup",
    tooLarge: "x/too-large", badInput: "x/bad-input", label: "the document" };
  function pe(input) { return json.parse(input, TestError, EXACT); }
  function codeE(s) { try { pe(s); return "NO-THROW"; } catch (e) { return e.code; } }

  // ACCEPTED: every legal spelling of an exact integer.
  var ok = [
    ['{"v":1}', 1],
    ['{"v":0}', 0],
    ['{"v":-7}', -7],
    ['{"v":1e3}', 1000],
    ['{"v":1E3}', 1000],
    ['{"v":1e+3}', 1000],
    ['{"v":1.0}', 1],
    ['{"v":1.000}', 1],
    ['{"v":15.0e2}', 1500],
    ['{"v":1500e-2}', 15],
    ['{"v":-1.0e1}', -10],
    ['{"v":9007199254740991}', 9007199254740991],
  ];
  var okFails = [];
  ok.forEach(function (c) {
    var got;
    try { got = pe(c[0]).v; } catch (e) { got = "threw " + e.code; }
    if (got !== c[1]) okFails.push(c[0] + " -> " + got + " (wanted " + c[1] + ")");
  });
  check("EI1: every legal spelling of an exact integer is accepted and read as that integer" +
    (okFails.length ? " (failed: " + okFails.join("; ") + ")" : ""),
    okFails.length === 0);

  // REFUSED: a token whose value is not exactly its own integer. The first is the one that matters: it
  // converts to the Number 1, so a check made after conversion cannot see it.
  var bad = ['{"v":1.0000000000000001}', '{"v":1.5}', '{"v":0.1}', '{"v":-2.5}',
    '{"v":1e-3}', '{"v":1.05e1}', '{"v":123456789012345678901}'];
  var badOk = [];
  bad.forEach(function (s) { if (codeE(s) !== "x/bad-json") badOk.push(s + " -> " + codeE(s)); });
  check("EI2: a token whose value is not exactly its own integer is refused" +
    (badOk.length ? " (accepted: " + badOk.join("; ") + ")" : ""),
    badOk.length === 0);

  // The one that names the whole point: it is indistinguishable from 1 after conversion.
  check("EI3: 1.0000000000000001 converts to the Number 1, so the refusal has to happen on the token",
    Number("1.0000000000000001") === 1 && codeE('{"v":1.0000000000000001}') === "x/bad-json");

  // An integer too large for a double to represent exactly is refused, because the value read back would
  // not be the value written: 2^53 + 1 converts to 2^53.
  check("EI4: an integer beyond exact double representation is refused",
    Number("9007199254740993") === 9007199254740992 &&
    codeE('{"v":9007199254740993}') === "x/bad-json");

  // CONTROLS. `exactIntegers` must not become `integersOnly`: exponent form stays legal, which is the
  // whole reason this policy exists separately.
  check("EI5: CONTROL exponent form is still accepted here, unlike under integersOnly",
    pe('{"v":1e3}').v === 1000 &&
    codeOf(function () {
      return json.parse('{"v":1e3}', TestError,
        { maxBytes: 4096, maxDepth: 8, integersOnly: true, badJson: "x/bad-json", tooDeep: "x/too-deep",
          duplicateMember: "x/dup", tooLarge: "x/too-large", badInput: "x/bad-input", label: "d" });
    }) === "x/bad-json");
  // CONTROL: without the policy, nothing changes, so no existing consumer is newly strict.
  check("EI6: CONTROL with no policy asked for, a fractional number is still read as before",
    p('{"v":1.0000000000000001}').v === 1 && p('{"v":1.5}').v === 1.5);
  // CONTROL: the policy applies at every depth, not only at the top level.
  check("EI7: CONTROL the rule applies to a nested value and inside an array",
    pe('{"a":{"b":[1e3,2]}}').a.b[0] === 1000 &&
    codeE('{"a":{"b":[1.5]}}') === "x/bad-json");

  /* EI8. The rule must COST a bounded amount, decided before any arithmetic. A token is
     `digits x 10^scale`, and computing that value to find out whether it is an integer means expanding
     the power: `0e999999` is a million-digit expansion that then multiplies by a zero mantissa, so it
     passes and can be repeated for every token the size cap admits. Measured at 1566 ms for a 907-byte
     document before the fix, and a larger permitted response scales from there.
     The decision is taken from the DIGIT COUNT and the scale instead, so nothing wide is ever built.
     A whole-input budget is asserted rather than a per-token ratio, which is the only form that catches
     an input made of many cheap-looking tokens. */
  var manyZeroExp = [];
  for (var zi = 0; zi < 200; zi++) manyZeroExp.push("0e999999");
  var zeroExpDoc = '{"v":[' + manyZeroExp.join(",") + "]}";
  var t0 = process.hrtime.bigint();
  var zeroExpOutcome = codeE(zeroExpDoc);
  var zeroExpMs = Number(process.hrtime.bigint() - t0) / 1e6;
  check("EI8: 200 zero-mantissa huge-exponent tokens cost a bounded time (" +
    zeroExpMs.toFixed(0) + " ms for " + zeroExpDoc.length + " bytes, outcome " + zeroExpOutcome + ")",
    zeroExpMs < 250);
  /* And the same for a NON-zero mantissa, which is the other half: `1e999999` must be refused for being
     outside the exact range without expanding it either. */
  var manyBigExp = [];
  for (var bi = 0; bi < 200; bi++) manyBigExp.push("1e999999");
  var bigExpDoc = '{"v":[' + manyBigExp.join(",") + "]}";
  var t1 = process.hrtime.bigint();
  var bigExpOutcome = codeE(bigExpDoc);
  var bigExpMs = Number(process.hrtime.bigint() - t1) / 1e6;
  check("EI8a: and 200 huge-exponent tokens with a non-zero mantissa are refused as cheaply (" +
    bigExpMs.toFixed(0) + " ms, outcome " + bigExpOutcome + ")",
    bigExpMs < 250 && bigExpOutcome === "x/bad-json");
  /* A long run of digits scaled back to a small integer is the third shape: 400 digits with an exponent
     that cancels them. It denotes an integer, so it must be decided without building the 400-digit value
     when the result is out of range anyway. */
  var longDigits = "1" + new Array(400).join("0");
  var t2 = process.hrtime.bigint();
  var longOutcome = codeE('{"v":' + longDigits + "e-398}");
  var longMs = Number(process.hrtime.bigint() - t2) / 1e6;
  check("EI8b: a 400-digit mantissa scaled back to a small integer is decided cheaply (" +
    longMs.toFixed(0) + " ms, outcome " + longOutcome + ")",
    longMs < 250);
  /* CONTROL: zero is still read, in every spelling, since special-casing it is part of the fix and a
     fix that refused zero would pass the budget checks above for the wrong reason. */
  check("EI8c: CONTROL zero is still accepted and read as zero, however it is spelled",
    pe('{"v":0}').v === 0 && pe('{"v":0e999999}').v === 0 &&
    pe('{"v":0.000}').v === 0 && pe('{"v":-0.0e5}').v === 0);
  /* EI8d. Bounding the cost must not bound the SPELLING. A first attempt capped the exponent at six
     characters, which refuses `1e0000000`, a perfectly ordinary way to write 1, and refused it for every
     caller rather than only those asking for an integer policy. The cost is bounded by deciding from
     digit counts instead, so no limit on how the exponent is written is needed. */
  check("EI8d: a long but harmless exponent spelling is still read, under the policy and without it",
    pe('{"v":1e0000000}').v === 1 && pe('{"v":0e1000000}').v === 0 &&
    p('{"v":1e0000000}').v === 1 && p('{"v":1.5e0000000}').v === 1.5);

  /* EI9. A format can be ordinary JSON, where a fractional number is legal somewhere in it, and still
     read ONE member as an integer. `exactIntegerMembers` names those members, and nothing else in the
     document is constrained. This is the form the real consumers use, because a document-wide rule is a
     bet that no field anywhere is fractional: the FIDO catalogue carries biometric rates and an in-toto
     predicate is arbitrary JSON by specification, so that bet loses. */
  var MEMBERS = { maxBytes: 4096, maxDepth: 8,
    exactIntegerMembers: Object.assign(Object.create(null), { no: 1, logIndex: 1 }),
    badJson: "x/bad-json", tooDeep: "x/too-deep", duplicateMember: "x/dup",
    tooLarge: "x/too-large", badInput: "x/bad-input", label: "the document" };
  function pm(s) { return json.parse(s, TestError, MEMBERS); }
  function codeM(s) { try { pm(s); return "NO-THROW"; } catch (e) { return e.code; } }
  check("EI9: a named member is held to the rule and an unnamed one is not",
    codeM('{"no":1.0000000000000001}') === "x/bad-json" &&
    pm('{"score":0.5}').score === 0.5 &&
    pm('{"no":42e0,"score":0.001}').no === 42);
  check("EI9a: the rule follows the member name at any depth, and an array element is not a member",
    codeM('{"a":{"b":{"logIndex":1.0000000000000001}}}') === "x/bad-json" &&
    pm('{"a":{"b":{"other":1.0000000000000001}}}').a.b.other === 1 &&
    pm('{"no":[1.5]}').no[0] === 1.5);
  check("EI9b: CONTROL naming no members constrains nothing",
    p('{"no":1.0000000000000001}').no === 1);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
