// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// consumers whose name-string integrity composes this guard (pki.path.validate
// DN chaining, pki.schema.x509 GeneralName / SAN decode).
//
// guard-name -- fail-closed name integrity: reject an embedded control byte in a
// distinguished-name / SAN string, and compare two distinguished names by their
// RFC 5280 sec. 7.1 canonical identity, never their raw bytes.
//
// Defends the name-truncation / display-confusion class (CVE-2009-2408): a NUL
// or control byte embedded in a decoded name lets an attacker make two different
// names compare equal (or a UI truncate at the NUL), so a cert issued for
// "good.example.com\0.evil.com" is treated as "good.example.com". CWE-158
// (improper neutralization of null byte) / CWE-20. The reject is at decode, so a
// truncation name never reaches a comparison or a display.
//
// Defends the DN identity-vs-bytes class (CWE-706): a distinguished name has many
// RFC 5280 sec. 7.1-equal DER encodings (case, whitespace, PrintableString vs
// UTF8String). Binding identity to raw bytes (a byte compare, or hashing
// name.bytes as a lookup key) silently treats two equal names as different, so
// certificate chaining breaks, a revocation issuer / OCSP responder fails to
// match, or (the mirror risk) a name constraint is escaped. Every DN identity
// decision routes through the one canonical comparison here.

var intrinsic = require("./guard-intrinsic");

// The string operations this module is built out of, taken from the prototypes at module load and
// uncurried so no call site reads a property of them. Every value compared here is a primitive
// string, so each call below would otherwise dispatch to whatever `String.prototype` holds at the
// moment it runs, and those are ordinary writable properties. A `toLowerCase` that returns a
// constant makes every DN compare equal to every other, which is the whole of this guard's job
// answered by the caller: chaining accepts an unrelated issuer, a revocation entry matches a
// certificate it was never written for, and a name constraint stops excluding anything. The same
// reasoning covers the escaping helpers, where a replaced `charAt` decides what a report line says
// a subject was. See guard-intrinsic for why the capture alone is not enough.
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var _toLowerCase = intrinsic.uncurry(String.prototype.toLowerCase);
var _toUpperCase = intrinsic.uncurry(String.prototype.toUpperCase);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _lastIndexOf = intrinsic.uncurry(String.prototype.lastIndexOf);
var _numToString = intrinsic.uncurry(Number.prototype.toString);
var _create = intrinsic.create;
var _hasOwn = intrinsic.hasOwn;
// Already a plain function rather than a method, so it is invoked directly and has no receiver.
var _fromCharCode = String.fromCharCode;
var _String = String;
// The shape test that decides whether a comparison can be performed at all. Refusing is the
// fail-closed direction, so replacing this turns comparisons into refusals rather than into false
// matches, and it is captured for the same reason as the rest: what a guard does is settled before
// a caller runs, or it is settled by the caller.
var _isArray = Array.isArray;

// assertNoControlBytes(str, E, code, label) -> str | throws E(code, ...)
// DirectoryString policy (a DN attribute value): reject NUL and C0 control bytes
// in a DECODED name string. TAB (0x09) is exempt; printable non-ASCII (a
// UTF8String CN carries accented / CJK characters) is allowed. `str` is assumed a
// string (the caller guards typeof). E is the (code, message) typed-error factory.
// @enforced-by behavioral -- the control-byte reject has no rename-proof code
//   shape distinct from the ASN.1 charset readers; the CVE-2009-2408 RED vectors
//   (a DN string with an embedded NUL / control byte rejects) are the guard.
function assertNoControlBytes(str, E, code, label) {
  for (var i = 0; i < str.length; i++) {
    var c = _charCodeAt(str, i);
    if (c === 0 || (c < 0x20 && c !== 0x09)) {
      throw E(code, label + " contains an embedded control byte (CVE-2009-2408)");
    }
  }
  return str;
}

// assertPrintableIa5(buf, E, code, label) -> buf | throws E(code, ...)
// IA5String policy (a dNSName / rfc822Name / URI GeneralName): every byte must be
// printable 7-bit ASCII [0x20, 0x7e], since an embedded NUL or control byte enables the
// same name-truncation bypass downstream. `buf` is the raw GeneralName content.
// @enforced-by behavioral -- the printable-IA5 byte-range reject has no rename-proof
//   code shape distinct from the ASN.1 IA5 reader; the CVE-2009-2408 RED vectors
//   (a SAN with a control byte rejects) are the guard.
function assertPrintableIa5(buf, E, code, label) {
  // The scan end comes from the slot, not from `buf.length`. A shorter answer stops the walk before
  // the control byte, which is the whole defense skipped on a name that still carries it.
  var n = intrinsic.sizeOf(buf);
  for (var i = 0; i < n; i++) {
    if (buf[i] < 0x20 || buf[i] > 0x7e) {
      throw E(code, label + " must be a printable IA5String (no control bytes)");
    }
  }
  return buf;
}

// Canonical form of a single DN attribute value (RFC 5280 sec. 7.1): reject an
// embedded control byte (CVE-2009-2408) then case-fold and collapse internal
// whitespace. Every standard X.520 attribute uses caseIgnoreMatch, and this form
// matches OpenSSL's X509_NAME_cmp, so a chain OpenSSL accepts is not rejected. This
// canonicalization is the shape the guard-shape-reinlined detector keys on
// (declared on dnEqual): a boundary hand-rolling it is re-implementing DN identity.
// The collapse is a single walk, not a pattern replace. This runs on every
// attribute value of every name the toolkit compares, a certificate an attacker
// supplies included, and one pass with a running "was the last character a space"
// flag costs exactly the length. It also spells out which characters count as
// whitespace: RFC 5280 sec. 7.1 defers to X.520's caseIgnoreMatch, whose SPACE is
// the ASCII space, and a pattern's \s silently also folds VT, FF, NBSP and every
// Unicode space separator, which would equate two names X.520 keeps distinct.
function _isSpace(c) { return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d; }
function _canonAttrValue(v, E, code, label) {
  if (typeof v !== "string") return v;
  assertNoControlBytes(v, E, code, label);
  var out = "", lastWasSpace = true;   // true so leading whitespace is dropped
  for (var i = 0; i < v.length; i++) {
    if (_isSpace(_charCodeAt(v, i))) { lastWasSpace = true; continue; }
    if (lastWasSpace && out.length) out += " ";
    lastWasSpace = false;
    out += _charAt(v, i);
  }
  return _toLowerCase(out);
}
// rdnEqual(a, b, E, code, label) -> boolean. Canonical comparison of a single
// RelativeDistinguishedName (an unordered SET of type/value pairs, compared as a
// multiset). The RDN-level primitive a name-constraint directoryName prefix match
// composes; dnEqual composes it over the RDN sequence. Comparing an RDN by raw DER
// would treat two RFC 5280-equal names as different (or let a truncation name
// compare equal).
// Both comparands must be the RDN SEQUENCE, not the parsed Name object that carries one. This is
// not a style check: a parsed Name has no `length`, so `a.length !== b.length` compares undefined
// with undefined, the loop over `i < undefined` never runs, and the comparison returns TRUE for two
// unrelated names. An identity comparison that answers "equal" because it was handed the wrong
// shape is the worst possible failure of this guard: it is the one place a DN identity is
// decided, and every caller reads a true from it as proof. So a comparison that cannot be
// performed refuses, and the caller learns at the call site instead of trusting a fabricated
// match. (A caller holding a parsed Name passes its `.rdns`.)
function _assertSequence(a, b, E, code, label, what) {
  if (!_isArray(a) || !_isArray(b)) {
    throw E(code, "cannot compare " + label + ": " + what + " comparison requires the RDN sequence on both sides (pass name.rdns, not the parsed Name)");
  }
  // A hole is refused here rather than read below. Indexing a sparse array walks to
  // `Array.prototype`, so a numeric property planted there supplies an attribute at the missing
  // index and the comparison decides identity on a value the name does not carry. A real RDN
  // sequence has no holes, so refusing costs nothing and there is no value to guess at.
  if (_hasHole(a) || _hasHole(b)) {
    throw E(code, "cannot compare " + label + ": " + what + " comparison requires a dense sequence on both sides");
  }
}

function _hasHole(arr) {
  for (var i = 0; i < arr.length; i++) { if (!_hasOwn(arr, i)) return true; }
  return false;
}
// @enforced-by guard-shape-reinlined  (shares the canonicalization shape declared on dnEqual)
function rdnEqual(a, b, E, code, label) {
  _assertSequence(a, b, E, code, label, "an RDN");
  if (a.length !== b.length) return false;
  // A null-prototype accumulator rather than an array: a numeric property planted on
  // `Array.prototype` reads back as "already matched" for an index nothing has matched, which skips
  // a candidate attribute and reports two equal RDNs as different.
  var used = _create(null);
  for (var i = 0; i < a.length; i++) {
    var found = false;
    for (var j = 0; j < b.length; j++) {
      if (used[j]) continue;
      if (a[i].type === b[j].type && _canonAttrValue(a[i].value, E, code, label) === _canonAttrValue(b[j].value, E, code, label)) {
        used[j] = true; found = true; break;
      }
    }
    if (!found) return false;
  }
  return true;
}
// dnEqual(rdnsA, rdnsB, E, code, label) -> boolean. RFC 5280 sec. 7.1 canonical
// distinguished-name comparison over the RDN sequence, the single place a DN identity
// is decided, so no caller binds identity to raw DER (a byte compare, or hashing
// name.bytes, would treat two RFC 5280-equal names as different, breaking a chain or
// a revocation match, or, the mirror risk, escaping a name constraint). The
// per-RDN canonicalization + control-byte reject is in rdnEqual / _canonAttrValue.
// @enforced-by guard-shape-reinlined
// @guard-shape replace\(/\\s\+/g,
function dnEqual(rdnsA, rdnsB, E, code, label) {
  _assertSequence(rdnsA, rdnsB, E, code, label, "a distinguished-name");
  if (rdnsA.length !== rdnsB.length) return false;
  for (var i = 0; i < rdnsA.length; i++) {
    if (!rdnEqual(rdnsA[i], rdnsB[i], E, code, label)) return false;
  }
  return true;
}

// escapeControlBytes(str) -> str. The render-side sibling of assertNoControlBytes:
// where a name string must still be DISPLAYED best-effort (a human-readable report,
// a log line) instead of rejected, neutralize every C0 control byte and DEL by
// rendering it as \xHH. A bare CR / LF / NUL in a decoded dNSName or DN value would
// otherwise forge or overwrite report lines in a terminal or log (CWE-117 output-log
// injection / CWE-116 improper output encoding). Non-control bytes pass through.
// Written as a charCodeAt scan, not a /[\x00-\x1f]/ regex: eslint's no-control-regex
// (correctly) refuses control characters in a regex literal, and the control-byte
// range test is the rename-proof shape the detector keys on regardless.
// @enforced-by guard-shape-reinlined
// @guard-shape < 0x20 \|\| \w+ === 0x7f
function escapeControlBytes(str) {
  var s = _String(str), out = "";
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    out += (c < 0x20 || c === 0x7f)
      ? "\\x" + (c < 16 ? "0" : "") + _toUpperCase(_numToString(c, 16))
      : _charAt(s, i);
  }
  return out;
}

// escapeDnValue(v) -> str. RFC 4514 sec. 2.4 string-representation escaping of a DN
// attribute value (the input is the already-unwrapped semantic string): backslash-
// escape the always-specials , + " \ < > ; and a NUL (as \00), then the positional
// rules -- a trailing space as '\ ' and a leading '#' or space as '\#' / '\ '. Without
// this a value like `foo, CN=admin` renders as two RDNs, and a literal `#05` collides
// with the hexstring form, so the report misstates a subject/issuer name (CWE-116).
// The one place a DN attribute value is made display-safe; pki.schema.pkix's DN
// rendering composes it, and pki.inspect reuses that parser output (name.dn).
var DN_SPECIAL = { 0x2c: 1, 0x2b: 1, 0x22: 1, 0x5c: 1, 0x3c: 1, 0x3e: 1, 0x3b: 1 };   // , + " \ < > ;
// RFC 4514 sec. 2.4's special set is the TABLE above and the walk is a single pass.
// The separator escape used to be a pattern replace feeding a second loop, which
// meant two passes over an attacker-supplied value and a character class holding a
// quote and a backslash inside a regex literal, the form most easily misread by a
// human and, as it happened, by the codebase-patterns literal-stripper.
//
// @enforced-by behavioral -- the escaping has no rename-proof code shape distinct
//   from ordinary string building; the guard-name RED vectors + the schema-pkix DN
//   round-trip vectors (a comma / plus / leading '#' renders backslash-escaped) are the guard.
function escapeDnValue(v) {
  var s = _String(v), out = "";
  // A NUL / control octet becomes '\' + two hex digits, so an embedded CR / LF / NUL
  // in a decoded DN value can never forge a report line when displayed.
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    if (c < 0x20 || c === 0x7f) out += "\\" + (c < 16 ? "0" : "") + _toUpperCase(_numToString(c, 16));
    else if (DN_SPECIAL[c] === 1) out += "\\" + _charAt(s, i);
    else out += _charAt(s, i);
  }
  if (out.length && _charAt(out, out.length - 1) === " ") out = _strSlice(out, 0, -1) + "\\ ";
  if (_charAt(out, 0) === "#" || _charAt(out, 0) === " ") out = "\\" + out;
  return out;
}

// emailEqual(a, b) -> "match" | "no-match" | "not-comparable". The RFC 5280 sec. 7.5
// sibling of dnEqual: two email addresses match iff their local-parts are an exact match
// AND their host-parts match under a case-insensitive ASCII comparison. The local-part is
// NEVER case-folded -- RFC 8398 sec. 5 states it "MUST NOT be transformed in any way, such
// as by doing case folding or normalization of any kind", because Alice@ and alice@ are
// permitted to be different mailboxes.
//
// The result is three-valued on purpose. An internationalized host-part (an `xn--` A-label
// or any non-ASCII octet) needs an IDNA2008 A-label/U-label transform this toolkit does not
// carry, so the rule cannot be applied. Returning "no-match" there would answer a question
// that was never asked, and a caller acting on it would reject a legitimate sender; the
// honest verdict is that the comparison was unavailable. A guard that cannot decide says so
// instead of guessing (the value is fail-CLOSED at the call site: no caller may read
// "not-comparable" as a pass).
//
// RFC 8398 sec. 5 also forbids wildcards outright -- "implementations MUST NOT interpret
// any characters as wildcards" -- so no character here is ever special. A certificate
// carrying `*@example.com` matches that literal string and nothing else. Name-CONSTRAINT
// processing (RFC 5280 sec. 4.2.1.10 as extended by RFC 8398 sec. 6), where a bare domain
// legitimately covers a whole subtree, is a different rule and stays in path-validate.
//
// @enforced-by guard-shape-reinlined
// @guard-shape lastIndexOf\("@"\)
function emailEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return "not-comparable";
  // Split on the LAST "@": a quoted local-part may legally contain one, and taking the
  // first would move part of the mailbox into the domain and compare the wrong halves.
  var ai = _lastIndexOf(a, "@"), bi = _lastIndexOf(b, "@");
  if (ai <= 0 || bi <= 0 || ai === a.length - 1 || bi === b.length - 1) return "not-comparable";
  var aLocal = _strSlice(a, 0, ai), bLocal = _strSlice(b, 0, bi);
  var aHost = _strSlice(a, ai + 1), bHost = _strSlice(b, bi + 1);
  if (!_asciiHost(aHost) || !_asciiHost(bHost)) return "not-comparable";
  if (aLocal !== bLocal) return "no-match";
  return lowerAscii(aHost) === lowerAscii(bHost) ? "match" : "no-match";
}

// A host-part this comparison can decide: ASCII, and carrying no A-label. Anything else
// needs the IDNA transform named above, so it is reported as undecidable rather than
// compared as raw bytes -- `xn--e1afmkfd.example` and its Unicode form are one host, and
// treating them as different would be a wrong answer rather than an absent one.
function _asciiHost(h) {
  if (h.length === 0) return false;
  // ASCII is the whole test, and an A-label is ASCII. Two hosts already in A-label form
  // need no transformation to be compared -- they are the same encoding -- so rejecting
  // them for carrying `xn--` would make sender binding unusable for every certificate with
  // an internationalized domain, including one whose address matches exactly. The case an
  // IDNA transform WOULD be needed for is an A-label against a U-label, and the U-label
  // side is non-ASCII, so it is refused here anyway.
  for (var i = 0; i < h.length; i++) if (_charCodeAt(h, i) > 0x7f) return false;
  return true;
}

// lowerAscii(s) -> string
// ASCII-only lowercase. String.toLowerCase() is Unicode-aware and would fold characters
// outside ASCII (the Kelvin sign lowercases to "k"), which is precisely the mapping a
// name comparison does not authorize: a name folded that way is one the certificate or
// message does not carry, and comparing it equal to a name that was asked for is the
// defect. Every case-insensitive name comparison in the toolkit -- a host part, a CMP
// domain, an ACME identifier set -- folds through this one definition, so none of them can
// disagree about which characters case-fold.
//
// @enforced-by guard-shape-reinlined
// @guard-shape 0x41\s*&&\s*[A-Za-z_$][\w$]*\s*<=\s*0x5[aA]\s*\)\s*\?[^:]*\+\s*(?:32|0x20)\s*\)
function lowerAscii(s) {
  var out = "";
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    out += (c >= 0x41 && c <= 0x5a) ? _fromCharCode(c + 32) : _charAt(s, i);
  }
  return out;
}

// Frozen for the reason the family header gives: a boundary reads its guard off this object at the
// call, so a writable export would let a caller replace the check rather than pass it.
module.exports = intrinsic.freeze({
  assertNoControlBytes: assertNoControlBytes, assertPrintableIa5: assertPrintableIa5,
  dnEqual: dnEqual, rdnEqual: rdnEqual, emailEqual: emailEqual,
  escapeControlBytes: escapeControlBytes, escapeDnValue: escapeDnValue,
  lowerAscii: lowerAscii,
});
