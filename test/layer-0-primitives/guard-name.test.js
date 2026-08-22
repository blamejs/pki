// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-name (@internal): fail-closed DN name integrity.
 * Oracle: the RFC 5280 sec. 7.1 canonical comparison (case-fold + internal-
 * whitespace collapse), the multiset RDN rule, and the CVE-2009-2408 control-byte
 * reject. The DN comparison is the shared primitive pki.path.validate name
 * chaining, revocation issuer / OCSP responder matching, and name constraints
 * compose -- it is exercised end-to-end there; these pin its contract directly.
 */

var name = require("../../lib/guard-name");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError");
// defineClass subclasses take (code, message).
function E(code, message) { return new TestError(code, message); }
function rdn() { var a = []; for (var i = 0; i < arguments.length; i += 2) a.push({ type: arguments[i], value: arguments[i + 1] }); return a; }
var CN = "2.5.4.3", O = "2.5.4.10";
var NUL = String.fromCharCode(0), SOH = String.fromCharCode(1);
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testDnEqual() {
  check("identical DNs equal", name.dnEqual([rdn(CN, "Root")], [rdn(CN, "Root")], E, "x/n", "dn") === true);
  check("case-folded equal (Root == root)", name.dnEqual([rdn(CN, "Root")], [rdn(CN, "root")], E, "x/n", "dn") === true);
  check("internal whitespace collapsed", name.dnEqual([rdn(CN, "Root  CA")], [rdn(CN, "Root CA")], E, "x/n", "dn") === true);
  check("leading/trailing whitespace trimmed", name.dnEqual([rdn(CN, "  Root  ")], [rdn(CN, "Root")], E, "x/n", "dn") === true);
  check("genuinely different not equal", name.dnEqual([rdn(CN, "Root")], [rdn(CN, "Evil")], E, "x/n", "dn") === false);
  check("different RDN count not equal", name.dnEqual([rdn(CN, "Root")], [rdn(CN, "Root"), rdn(O, "Org")], E, "x/n", "dn") === false);
  check("different attribute type not equal", name.dnEqual([rdn(CN, "Root")], [rdn(O, "Root")], E, "x/n", "dn") === false);

  // A parsed Name carries its RDN sequence in `.rdns`; the Name itself has no `length`. Handed one,
  // the length comparison is undefined-against-undefined, the loop never runs, and this returns a
  // fabricated TRUE for two unrelated names -- an identity guard answering "equal" because it was
  // handed the wrong shape. It refuses instead, so the mistake surfaces at the call site.
  var parsedRoot = { rdns: [rdn(CN, "Root")], dn: "CN=Root" };
  var parsedEvil = { rdns: [rdn(CN, "Evil")], dn: "CN=Evil" };
  check("a parsed Name is refused, never compared as though equal",
    codeOf(function () { name.dnEqual(parsedRoot, parsedEvil, E, "x/name", "dn"); }) === "x/name");
  check("...in either position", codeOf(function () { name.dnEqual([rdn(CN, "Root")], parsedEvil, E, "x/name", "dn"); }) === "x/name");
  check("...and rdnEqual refuses it too",
    codeOf(function () { name.rdnEqual(parsedRoot, parsedEvil, E, "x/name", "dn"); }) === "x/name");
  // The correct call on the same values still decides them apart.
  check("the RDN sequence of those same names is not equal",
    name.dnEqual(parsedRoot.rdns, parsedEvil.rdns, E, "x/name", "dn") === false);
}

function testRdnMultiset() {
  // An RDN is an unordered SET: order within the RDN must not matter.
  check("multi-value RDN order-independent", name.rdnEqual(rdn(CN, "Root", O, "Org"), rdn(O, "Org", CN, "Root"), E, "x/n", "dn") === true);
  check("multi-value RDN mismatch", name.rdnEqual(rdn(CN, "Root", O, "Org"), rdn(CN, "Root", O, "Other"), E, "x/n", "dn") === false);
}

function testControlByteReject() {
  // CVE-2009-2408: an embedded NUL / C0 control byte throws the caller's typed error
  // so a truncation name never compares equal. TAB (0x09) is exempt (collapsed).
  check("embedded NUL throws the typed code", codeOf(function () { name.dnEqual([rdn(CN, "Root" + NUL + ".evil")], [rdn(CN, "Root")], E, "x/name", "dn"); }) === "x/name");
  check("C0 control byte throws the typed code", codeOf(function () { name.dnEqual([rdn(CN, "Ro" + SOH + "ot")], [rdn(CN, "Root")], E, "x/name", "dn"); }) === "x/name");
  check("TAB is exempt and collapsed to a space", name.dnEqual([rdn(CN, "Root\tCA")], [rdn(CN, "Root CA")], E, "x/name", "dn") === true);
}

function testRenderEscaping() {
  // escapeControlBytes: the render-side sibling -- a control byte a display must still
  // show becomes \xHH (never a raw CR/LF/NUL that forges a report line); printable
  // ASCII passes through unchanged.
  check("control byte -> \\xHH (NUL, LF)", name.escapeControlBytes("a" + NUL + "b" + String.fromCharCode(10)) === "a\\x00b\\x0A");
  check("printable ASCII passes through", name.escapeControlBytes("plain.text-123 (x)") === "plain.text-123 (x)");
  check("DEL 0x7f is escaped", name.escapeControlBytes(String.fromCharCode(0x7f)) === "\\x7F");
  // escapeDnValue (this IS the behavioral guard): RFC 4514 -- a separator inside a DN
  // value is backslash-escaped so it cannot read as a second RDN in the report.
  check("DN comma escaped, not a forged RDN", name.escapeDnValue("foo, CN=admin") === "foo\\, CN=admin");
  check("DN plus escaped", name.escapeDnValue("a+b") === "a\\+b");
  check("DN leading '#' escaped", name.escapeDnValue("#x") === "\\#x");
  check("DN leading + trailing space escaped", name.escapeDnValue(" x ") === "\\ x\\ ");
  // RFC 4514 sec. 2.4 hex form: a NUL / control octet is '\' + two hex digits, so an
  // embedded CR / LF in a DN value cannot forge a report line when the dn is displayed.
  check("DN NUL -> \\00 (RFC 4514 hex)", name.escapeDnValue("a" + NUL + "b") === "a\\00b");
  check("DN LF -> \\0A (RFC 4514 hex, no forged line)", name.escapeDnValue("a" + String.fromCharCode(10) + "b") === "a\\0Ab");
  check("clean DN value untouched", name.escapeDnValue("pkijs.com") === "pkijs.com");
}

// Every operation this guard is built out of is taken from the prototypes at module load, so a
// caller who rewrites one afterwards changes nothing here. Each value compared is a primitive
// string, so `"x".toLowerCase()` reaches whatever `String.prototype` holds at the moment it runs,
// and those are ordinary writable properties. A `toLowerCase` returning a constant answers the
// whole of this guard's job on the caller's behalf: every DN compares equal to every other, so
// chaining accepts an unrelated issuer, a revocation entry matches a certificate it was never
// written for, and a name constraint stops excluding anything.
//
// Three structurally different members of the class are exercised, since the claim quantifies over
// String.prototype and not over one method: the case fold, the character read the canonical walk is
// built on, and the character-code read the control-byte reject is built on.
function testNotCallerReplaceable() {
  // Equal-length values, so a replacement that answers the same character for every position
  // produces the same canonical form on both sides. Two different lengths would stay different
  // whatever the replacement returns, and the vector would pass without the guard holding.
  var A = rdn(CN, "alice"), B = rdn(CN, "bobby");
  var swaps = [
    // The case fold, answered as one constant for every input.
    ["toLowerCase", function () { return "same"; }],
    // The character read the canonical walk builds its output from.
    ["charAt", function () { return "s"; }],
    // The character-code read the whitespace collapse consults. Answering SPACE for every position
    // drops every character, so each value canonicalizes to the empty string.
    ["charCodeAt", function () { return 0x20; }]
  ];
  for (var i = 0; i < swaps.length; i++) {
    var key = swaps[i][0], real = String.prototype[key], equal;
    try {
      String.prototype[key] = swaps[i][1];
      equal = name.rdnEqual(A, B, E, "x/bad", "the name");
    } finally {
      String.prototype[key] = real;
    }
    check("a replaced String.prototype." + key + " cannot make two different DNs compare equal",
      equal === false);
  }
  // The control-byte reject reads character codes too, and it is the CVE-2009-2408 defense: a
  // charCodeAt that never reports a control byte lets `good.example.com\0.evil.com` through the
  // one check standing between it and a comparison or a display.
  var realCharCodeAt = String.prototype.charCodeAt, nulCode;
  try {
    String.prototype.charCodeAt = function () { return 0x61; };
    nulCode = codeOf(function () {
      name.assertNoControlBytes("good.example.com" + NUL + ".evil.com", E, "x/bad", "the name");
    });
  } finally {
    String.prototype.charCodeAt = realCharCodeAt;
  }
  check("a replaced String.prototype.charCodeAt cannot hide an embedded control byte",
    nulCode === "x/bad");
  // The escaping side of the same class: a replaced charAt decides what a report line says a
  // subject was, which is the display-confusion half of what this module defends.
  var realCharAt = String.prototype.charAt, escaped;
  try {
    String.prototype.charAt = function () { return "s"; };
    escaped = name.escapeDnValue("foo, CN=admin");
  } finally {
    String.prototype.charAt = realCharAt;
  }
  check("a replaced String.prototype.charAt cannot rewrite an escaped DN value",
    escaped === "foo\\, CN=admin");

  // The shape test that decides whether a comparison can happen at all. Replacing it points the
  // wrong way -- comparisons become refusals rather than false matches -- so this pins the
  // capture, and it does so on the refusal side, where a caller could otherwise deny service to
  // every name comparison the toolkit makes.
  var realIsArray = Array.isArray, sameDn;
  try {
    Array.isArray = function () { return false; };
    // Caught inside the swap so the failure reports as this check rather than escaping the suite.
    try { sameDn = name.rdnEqual(rdn(CN, "alice"), rdn(CN, "alice"), E, "x/bad", "the name"); }
    catch (e) { sameDn = "threw " + (e.code || "OTHER"); }
  } finally {
    Array.isArray = realIsArray;
  }
  check("a replaced Array.isArray cannot turn a valid comparison into a refusal", sameDn === true);
}

function run() {
  testDnEqual();
  testRdnMultiset();
  testControlByteReject();
  testRenderEscaping();
  testEmailEqual();
  testDpnCorresponds();
  testNotCallerReplaceable();
}

// RFC 5280 sec. 6.3.3(b)(2)(i) correspondence, whose comparison key sec. 5.2.5 pins to the
// identical encoding. Two properties carry the rule and pull in opposite directions: sharing ONE
// name is enough (a point published under several names would otherwise reject its own CRL), and
// the shared name must be the same BYTES (a canonical comparison would accept a CRL scoped to a
// point the reference never named). The third is that a form this comparison cannot decide answers
// no rather than guessing.
function testDpnCorresponds() {
  var eq = name.dpnCorresponds;
  function full() { var n = []; for (var i = 0; i < arguments.length; i++) n.push(Buffer.from(arguments[i], "utf8")); return { kind: "fullName", names: n }; }
  function rel(s) { return { kind: "rdn", bytes: Buffer.from(s, "utf8") }; }
  check("one name in common corresponds", eq(full("a", "b"), full("c", "b"), E, "x/d", "dp") === true);
  check("no name in common does not correspond", eq(full("a"), full("b"), E, "x/d", "dp") === false);
  check("a single shared name is enough, not whole-set equality", eq(full("a"), full("a", "b", "c"), E, "x/d", "dp") === true);
  // The bytes decide. A name that differs only in its encoding is a different distribution point
  // here, which is the opposite of the sec. 7.1 rule dnEqual applies to a DN.
  check("a name differing only in case does NOT correspond", eq(full("Point"), full("point"), E, "x/d", "dp") === false);
  check("a name differing by whitespace does NOT correspond", eq(full("a b"), full("a  b"), E, "x/d", "dp") === false);
  check("an empty name list corresponds with nothing", eq(full(), full("a"), E, "x/d", "dp") === false);
  check("identical nameRelativeToCRLIssuer bytes correspond", eq(rel("ou=1"), rel("ou=1"), E, "x/d", "dp") === true);
  check("different nameRelativeToCRLIssuer bytes do not", eq(rel("ou=1"), rel("ou=2"), E, "x/d", "dp") === false);
  check("mixed forms never correspond", eq(full("a"), rel("a"), E, "x/d", "dp") === false);

  // A comparison handed the wrong shape refuses at the call site. Answering false would read as a
  // clean refusal of a CRL while nothing was compared, which is the failure dnEqual's own shape
  // check exists to prevent.
  check("a missing comparand refuses", codeOf(function () { eq(null, full("a"), E, "x/d", "dp"); }) === "x/d");
  check("an unknown kind refuses", codeOf(function () { eq({ kind: "other", names: [] }, full("a"), E, "x/d", "dp"); }) === "x/d");
  check("a fullName with no names array refuses", codeOf(function () { eq({ kind: "fullName" }, full("a"), E, "x/d", "dp"); }) === "x/d");
  check("a sparse names array refuses", codeOf(function () { var s = full("a"); s.names[3] = Buffer.from("b"); delete s.names[1]; eq(s, full("a"), E, "x/d", "dp"); }) === "x/d");
  // A name that is not bytes cannot be compared as bytes. An object supplying its own `equals` or
  // `length` would be answering the question asked of it.
  check("a non-buffer name refuses", codeOf(function () { eq({ kind: "fullName", names: [{ equals: function () { return true; } }] }, full("a"), E, "x/d", "dp"); }) === "x/d");
  check("an rdn form with no bytes refuses", codeOf(function () { eq({ kind: "rdn" }, rel("a"), E, "x/d", "dp"); }) === "x/d");

  // A field read twice is two values: an accessor can present the name that passes the shape check
  // and a different one to the comparison, so the bytes that decided the answer would be bytes
  // nothing validated. Each field is taken from its own property descriptor, once, which refuses
  // the accessor outright rather than racing it.
  var flip = 0;
  var moving = { get kind() { return "fullName"; }, get names() { flip += 1; return [Buffer.from(flip === 1 ? "checked" : "swapped", "utf8")]; } };
  check("an accessor-backed comparand refuses rather than being read twice",
    codeOf(function () { eq(moving, full("swapped"), E, "x/d", "dp"); }) === "x/d");
  check("the refused accessor was never invoked", flip === 0);
  check("an accessor-backed names element refuses", codeOf(function () {
    var arr = []; Object.defineProperty(arr, 0, { get: function () { return Buffer.from("a"); }, enumerable: true });
    eq({ kind: "fullName", names: arr }, full("a"), E, "x/d", "dp");
  }) === "x/d");
  // An inherited kind, names or bytes is a shape the decoder never produces: the fields are its own.
  check("an inherited kind refuses", codeOf(function () { eq(Object.create({ kind: "fullName", names: [Buffer.from("a")] }), full("a"), E, "x/d", "dp"); }) === "x/d");
  check("an inherited names refuses", codeOf(function () { eq(Object.create({ names: [Buffer.from("a")] }, { kind: { value: "fullName" } }), full("a"), E, "x/d", "dp"); }) === "x/d");
  check("an inherited bytes refuses", codeOf(function () { eq(Object.create({ bytes: Buffer.from("a") }, { kind: { value: "rdn" } }), rel("a"), E, "x/d", "dp"); }) === "x/d");
  check("an inherited names ELEMENT refuses rather than being taken off Array.prototype", codeOf(function () {
    var arr = [Buffer.from("a")]; arr.length = 2;
    try { Object.defineProperty(Array.prototype, "1", { value: Buffer.from("b"), configurable: true });
      eq({ kind: "fullName", names: arr }, full("b"), E, "x/d", "dp");
    } finally { delete Array.prototype[1]; }
  }) === "x/d");
  // A Proxy answers the own-descriptor query and the ordinary read from different places. Taking
  // the value out of the descriptor leaves one answer, so the two cannot disagree.
  check("a Proxy whose descriptor and read disagree cannot smuggle an inherited value", (function () {
    var target = Object.create({ kind: "rdn", bytes: Buffer.from("a", "utf8") });
    var lying = new Proxy(target, {
      getOwnPropertyDescriptor: function (t, k) { return { value: t[k], writable: true, enumerable: true, configurable: true }; },
    });
    // Either it refuses, or it answers from the value the descriptor reported, which is "a" -- so a
    // comparison against "b" is false. What it must never do is report a match.
    try { return eq(lying, rel("b"), E, "x/d", "dp") === false; }
    catch (e) { return e.code === "x/d"; }
  })());
}

// RFC 5280 sec. 7.5 decides the match; RFC 8398 sec. 5 decides what may not be
// transformed on the way. The third state is the load-bearing one: an address this
// toolkit cannot canonicalize must report that, because "no-match" is an answer and
// the comparison never happened.
function testEmailEqual() {
  var eq = name.emailEqual;
  // Built at runtime, so this file stays pure ASCII: a raw Cyrillic host in the source
  // is the kind of byte a later editor silently normalizes.
  var cyrillicHost = "a@" + String.fromCharCode(0x43f, 0x440, 0x438, 0x43c, 0x435, 0x440) + ".example";
  check("an identical address matches", eq("a@example.com", "a@example.com") === "match");
  check("the host-part compares case-insensitively", eq("a@EXAMPLE.COM", "a@example.com") === "match");
  // The rule most likely to be "simplified" into a full lowercase, which would let
  // Alice@ open mail addressed to a different mailbox at the same domain.
  check("the local-part compares case-SENSITIVELY", eq("Alice@example.com", "alice@example.com") === "no-match");
  check("a different host does not match", eq("a@example.com", "a@other.com") === "no-match");
  // RFC 8398 sec. 5: "implementations MUST NOT interpret any characters as wildcards".
  check("a wildcard in the certificate is a literal, matching nothing else",
    eq("*@example.com", "bob@example.com") === "no-match");
  check("...and matching only itself", eq("*@example.com", "*@example.com") === "match");
  // A quoted local-part may legally contain @; splitting on the first would compare a
  // fragment of the mailbox against the wrong host.
  check("the split is on the LAST @, so a quoted local-part survives",
    eq("\"x@y\"@example.com", "\"x@y\"@example.com") === "match");
  // Two hosts already in A-label form are the same encoding, so no IDNA transform is
  // needed and the ordinary ASCII rule decides. Refusing them would make every certificate
  // with an internationalized domain unusable for sender binding, including one whose
  // address matches exactly. The case that DOES need a transform is an A-label against a
  // U-label, and the U-label side is non-ASCII, which is refused below.
  check("two A-label hosts compare under the ordinary ASCII rule",
    eq("a@xn--e1afmkfd.example", "a@XN--E1AFMKFD.EXAMPLE") === "match");
  check("an A-label host does not match a different A-label host",
    eq("a@xn--e1afmkfd.example", "a@xn--bcher-kva.example") === "no-match");
  check("a non-ASCII host is not comparable",
    eq(cyrillicHost, "a@x.example") === "not-comparable");
  // sec. 7.5 authorizes a case-insensitive ASCII fold and no more. A Unicode-aware
  // toLowerCase() maps U+212A KELVIN SIGN onto ASCII "k", so "ban<U+212A>.com" and
  // "bank.com" -- different byte strings, separately registrable -- would collapse into
  // one identity. The fold must never reach outside A-Z.
  var kelvinHost = "a@ban" + String.fromCharCode(0x212a) + ".com";
  check("a Unicode letter that case-folds onto ASCII never collides with the ASCII host",
    eq(kelvinHost, "a@bank.com") !== "match");
  check("an address with no @ is not comparable", eq("noatsign", "a@b.com") === "not-comparable");
  check("an empty host is not comparable", eq("a@", "a@b.com") === "not-comparable");
  check("an empty local-part is not comparable", eq("@b.com", "a@b.com") === "not-comparable");
  check("a non-string is not comparable, never a throw", eq(null, "a@b.com") === "not-comparable");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
