// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.asn1.schema (the L2 structure-schema engine).
 * Oracle: hand-built canonical DER walked against declarative schemas; each
 * combinator's shape assertion, arity, optional / trailing ordering, SET-OF
 * uniqueness, and error mapping is exercised directly (the x509 parser is the
 * integration oracle; this is the unit oracle).
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var S = pki.asn1.schema;
var b = pki.asn1.build;
var TAGS = pki.asn1.TAGS;

function E(code, msg) { var e = new Error(msg); e.code = code; return e; }
var NS = { prefix: "t", E: E, oid: pki.oid };
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + e.constructor.name); } }
function walk(schema, der) { return S.walk(schema, pki.asn1.decode(der), NS); }

function testLeaves() {
  check("oidLeaf reads the dotted OID", walk(S.oidLeaf(), b.oid("1.2.840.10045.4.3.2")) === "1.2.840.10045.4.3.2");
  check("integerLeaf reads a BigInt", walk(S.integerLeaf(), b.integer(255n)) === 255n);
  check("boolean reads true", walk(S.boolean(), b.boolean(true)) === true);
  check("octetString reads bytes", walk(S.octetString(), b.octetString(Buffer.from([1, 2, 3]))).equals(Buffer.from([1, 2, 3])));
  check("bitString reads {unusedBits,bytes}", (function () { var r = walk(S.bitString(), b.bitString(Buffer.from([0xaa]), 0)); return r.unusedBits === 0 && r.bytes.equals(Buffer.from([0xaa])); })());
  check("any yields the node itself", walk(S.any(), b.integer(5n)).tagNumber === TAGS.INTEGER);
  check("decode runs the fn", walk(S.decode(function (n) { return "seen:" + n.tagNumber; }), b.integer(5n)) === "seen:" + TAGS.INTEGER);
  check("time reads UTCTime", walk(S.time(NS), b.utcTime(new Date("2026-01-01T00:00:00Z"))).toISOString() === "2026-01-01T00:00:00.000Z");
  check("time rejects a non-time tag (t/bad-time)", code(function () { walk(S.time(NS), b.integer(5n)); }) === "t/bad-time");
}

function testSeqAssertAndArity() {
  var seqExact2 = S.seq([S.field("a", S.integerLeaf()), S.field("b", S.integerLeaf())],
    { assert: "sequence", arity: { exact: 2 }, code: "t/bad-seq", build: function (m) { return [m.fields.a.value, m.fields.b.value]; } });
  check("seq(sequence) builds .result", (function () { var r = walk(seqExact2, b.sequence([b.integer(1n), b.integer(2n)])).result; return r[0] === 1n && r[1] === 2n; })());
  check("seq(sequence) rejects a SET (t/bad-seq)", code(function () { walk(seqExact2, b.set([b.integer(1n), b.integer(2n)])); }) === "t/bad-seq");
  check("seq arity exact rejects a 3-element SEQUENCE", code(function () { walk(seqExact2, b.sequence([b.integer(1n), b.integer(2n), b.integer(3n)])); }) === "t/bad-seq");
  check("seq missing required field throws the seq code", code(function () { walk(seqExact2, b.sequence([b.integer(1n)])); }) === "t/bad-seq");

  // assert:"constructed" accepts a SET (children only, no SEQUENCE-tag check).
  var conAny = S.seq([S.field("a", S.integerLeaf())], { assert: "constructed", arity: { min: 1 }, code: "t/bad-con" });
  check("seq(constructed) accepts a SET-tagged node", code(function () { walk(conAny, b.set([b.integer(1n)])); }) === "NO-THROW");
  check("seq(constructed) min-arity rejects empty", code(function () { walk(conAny, b.sequence([])); }) === "t/bad-con");
}

function testOptional() {
  // version-like: optional [0] EXPLICIT INTEGER, default 1.
  var spec = S.seq([
    S.optional("v", S.integerLeaf(), { tag: 0, explicit: true, emptyCode: "t/bad-v", default: 1n }),
    S.field("n", S.integerLeaf()),
  ], { assert: "sequence", code: "t/bad", build: function (m) { return { v: m.fields.v.value, present: m.fields.v.present, n: m.fields.n.value }; } });
  check("optional present ([0] EXPLICIT) is read", (function () { var r = walk(spec, b.sequence([b.explicit(0, b.integer(2n)), b.integer(9n)])).result; return r.v === 2n && r.present === true && r.n === 9n; })());
  check("optional absent binds the default", (function () { var r = walk(spec, b.sequence([b.integer(9n)])).result; return r.v === 1n && r.present === false && r.n === 9n; })());
  check("optional [0] EXPLICIT with an empty wrapper throws emptyCode",
    code(function () { walk(spec, b.sequence([b.contextConstructed(0, Buffer.alloc(0)), b.integer(9n)])); }) === "t/bad-v");
}

function testTrailing() {
  var spec = S.seq([
    S.field("head", S.integerLeaf()),
    S.trailing([
      { tag: 1, name: "one", schema: S.any() },
      { tag: 2, name: "two", schema: S.any() },
      { tag: 3, name: "three", schema: S.integerLeaf(), explicit: true, emptyCode: "t/bad-three" },
    ], { minTag: 1, maxTag: 3, unexpectedCode: "t/bad-trailing", orderCode: "t/bad-order" }),
  ], { assert: "sequence", code: "t/bad", build: function (m) { return m.fields; } });
  check("trailing in-order ([1] then [3]) parses", code(function () { walk(spec, b.sequence([b.integer(0n), b.contextPrimitive(1, Buffer.from([1])), b.explicit(3, b.integer(7n))])); }) === "NO-THROW");
  check("trailing out-of-order ([3] then [1]) rejected (order code)", code(function () { walk(spec, b.sequence([b.integer(0n), b.explicit(3, b.integer(7n)), b.contextPrimitive(1, Buffer.from([1]))])); }) === "t/bad-order");
  check("trailing repeated tag rejected (order code)", code(function () { walk(spec, b.sequence([b.integer(0n), b.contextPrimitive(1, Buffer.from([1])), b.contextPrimitive(1, Buffer.from([2]))])); }) === "t/bad-order");
  check("trailing unknown tag [4] rejected (unexpected code)", code(function () { walk(spec, b.sequence([b.integer(0n), b.contextPrimitive(4, Buffer.from([1]))])); }) === "t/bad-trailing");
  check("trailing explicit [3] value is read", (function () { var m = walk(spec, b.sequence([b.integer(0n), b.explicit(3, b.integer(7n))])).result; return m.three.present === true && m.three.value === 7n; })());
  check("absent trailing member binds present:false", (function () { var m = walk(spec, b.sequence([b.integer(0n)])).result; return m.three.present === false; })());
}

function testTrailingNoMinTag() {
  // Regression (Codex PR #9): a trailing block that OMITS minTag with a member
  // at tag [0] must accept a leading [0] field. The monotonic-order sentinel
  // starts BELOW the lowest accepted tag; a fallback of 0 rejected the first
  // [0] field as "repeated or out of order". x509's tbs always passes minTag:1,
  // so only the general combinator exercised the minTag-absent path.
  var spec = S.seq([
    S.field("head", S.integerLeaf()),
    S.trailing([
      { tag: 0, name: "zero", schema: S.any() },
      { tag: 2, name: "two", schema: S.integerLeaf(), explicit: true, emptyCode: "t/bad-two" },
    ], { unexpectedCode: "t/bad-trailing", orderCode: "t/bad-order" }),
  ], { assert: "sequence", code: "t/bad", build: function (m) { return m.fields; } });
  check("trailing without minTag accepts a leading [0] field",
    code(function () { walk(spec, b.sequence([b.integer(0n), b.contextPrimitive(0, Buffer.from([1]))])); }) === "NO-THROW");
  check("trailing without minTag reads [0] then [2] in tag order", (function () {
    // No try/catch: a regression that rejects the [0] field should surface the
    // real order-error here, not be swallowed into a bare `false`.
    var m = walk(spec, b.sequence([b.integer(0n), b.contextPrimitive(0, Buffer.from([1])), b.explicit(2, b.integer(7n))])).result;
    return m.zero.present === true && m.two.present === true && m.two.value === 7n;
  })());
  check("trailing without minTag still rejects out-of-order ([2] then [0])",
    code(function () { walk(spec, b.sequence([b.integer(0n), b.explicit(2, b.integer(7n)), b.contextPrimitive(0, Buffer.from([1]))])); }) === "t/bad-order");
}

function testRepeatUniqueness() {
  var uniq = S.setOfUnique(S.seq([S.field("k", S.oidLeaf())], { assert: "sequence", code: "t/bad-item", build: function (m) { return m.fields.k.value; } }),
    function (item) { return item.value.result; }, { assert: "set", code: "t/bad-set", dupCode: "t/dup" });
  var distinct = b.set([b.sequence([b.oid("2.5.4.3")]), b.sequence([b.oid("2.5.4.6")])]);
  var dup = b.set([b.sequence([b.oid("2.5.4.3")]), b.sequence([b.oid("2.5.4.3")])]);
  check("setOfUnique accepts distinct keys", code(function () { walk(uniq, distinct); }) === "NO-THROW");
  check("setOfUnique rejects a duplicate key (dupCode)", code(function () { walk(uniq, dup); }) === "t/dup");
  var min1 = S.seqOf(S.integerLeaf(), { assert: "sequence", min: 1, code: "t/bad-seqof" });
  check("seqOf min:1 rejects empty", code(function () { walk(min1, b.sequence([])); }) === "t/bad-seqof");
}

function testChoiceAndExplicit() {
  var timeChoice = S.choice([
    { when: { tagClass: "universal", tagNumber: TAGS.UTC_TIME }, schema: S.decode(function () { return "utc"; }) },
    { when: { tagClass: "universal", tagNumber: TAGS.GENERALIZED_TIME }, schema: S.decode(function () { return "gen"; }) },
  ], { code: "t/bad-choice" });
  check("choice matches UTCTime alternative", walk(timeChoice, b.utcTime(new Date("2026-01-01T00:00:00Z"))) === "utc");
  check("choice with no matching alternative throws code", code(function () { walk(timeChoice, b.integer(5n)); }) === "t/bad-choice");

  var exp = S.explicit(0, S.integerLeaf(), { emptyCode: "t/bad-exp" });
  check("explicit [0] unwraps + reads the inner value", walk(exp, b.explicit(0, b.integer(42n))) === 42n);
  check("explicit [0] on a wrong tag throws", code(function () { walk(exp, b.explicit(1, b.integer(42n))); }) === "t/bad-exp");
}

function run() {
  testLeaves();
  testSeqAssertAndArity();
  testOptional();
  testTrailing();
  testTrailingNoMinTag();
  testRepeatUniqueness();
  testChoiceAndExplicit();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
