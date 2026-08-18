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

function run() {
  testDnEqual();
  testRdnMultiset();
  testControlByteReject();
  testRenderEscaping();
  testEmailEqual();
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
