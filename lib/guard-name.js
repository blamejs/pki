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
// RFC 5280 sec. 7.1 canonical identity rather than their raw bytes.
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
// UTF8String). Binding identity to raw bytes -- a byte compare, or hashing
// name.bytes as a lookup key -- silently treats two equal names as different, so
// certificate chaining breaks, a revocation issuer / OCSP responder fails to
// match, or (the mirror risk) a name constraint is escaped. Every DN identity
// decision routes through the one canonical comparison here.

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
    var c = str.charCodeAt(i);
    if (c === 0 || (c < 0x20 && c !== 0x09)) {
      throw E(code, label + " contains an embedded control byte (CVE-2009-2408)");
    }
  }
  return str;
}

// assertPrintableIa5(buf, E, code, label) -> buf | throws E(code, ...)
// IA5String policy (a dNSName / rfc822Name / URI GeneralName): every byte must be
// printable 7-bit ASCII [0x20, 0x7e] -- an embedded NUL / control byte enables the
// same name-truncation bypass downstream. `buf` is the raw GeneralName content.
// @enforced-by behavioral -- the printable-IA5 byte-range reject has no rename-proof
//   code shape distinct from the ASN.1 IA5 reader; the CVE-2009-2408 RED vectors
//   (a SAN with a control byte rejects) are the guard.
function assertPrintableIa5(buf, E, code, label) {
  for (var i = 0; i < buf.length; i++) {
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
function _canonAttrValue(v, E, code, label) {
  if (typeof v !== "string") return v;
  assertNoControlBytes(v, E, code, label);
  return v.trim().replace(/\s+/g, " ").toLowerCase();
}
// rdnEqual(a, b, E, code, label) -> boolean. Canonical comparison of a single
// RelativeDistinguishedName (an unordered SET of type/value pairs, compared as a
// multiset). The RDN-level primitive a name-constraint directoryName prefix match
// composes; dnEqual composes it over the RDN sequence. Comparing an RDN by raw DER
// would treat two RFC 5280-equal names as different (or let a truncation name
// compare equal).
// @enforced-by guard-shape-reinlined  (shares the canonicalization shape declared on dnEqual)
function rdnEqual(a, b, E, code, label) {
  if (a.length !== b.length) return false;
  var used = [];
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
// distinguished-name comparison over the RDN sequence -- the ONE place a DN identity
// is decided, so no caller binds identity to raw DER (a byte compare, or hashing
// name.bytes, would treat two RFC 5280-equal names as different, breaking a chain /
// a revocation match, or -- the mirror risk -- escaping a name constraint). The
// per-RDN canonicalization + control-byte reject is in rdnEqual / _canonAttrValue.
// @enforced-by guard-shape-reinlined
// @guard-shape replace\(/\\s\+/g,
function dnEqual(rdnsA, rdnsB, E, code, label) {
  if (rdnsA.length !== rdnsB.length) return false;
  for (var i = 0; i < rdnsA.length; i++) {
    if (!rdnEqual(rdnsA[i], rdnsB[i], E, code, label)) return false;
  }
  return true;
}

// escapeControlBytes(str) -> str. The render-side sibling of assertNoControlBytes:
// where a name string must still be DISPLAYED best-effort (a human-readable report,
// a log line) rather than rejected, neutralize every C0 control byte and DEL by
// rendering it as \xHH. A bare CR / LF / NUL in a decoded dNSName or DN value would
// otherwise forge or overwrite report lines in a terminal or log (CWE-117 output-log
// injection / CWE-116 improper output encoding). Non-control bytes pass through.
// Written as a charCodeAt scan, not a /[\x00-\x1f]/ regex: eslint's no-control-regex
// (correctly) refuses control characters in a regex literal, and the control-byte
// range test is the rename-proof shape the detector keys on regardless.
// @enforced-by guard-shape-reinlined
// @guard-shape < 0x20 \|\| \w+ === 0x7f
function escapeControlBytes(str) {
  var s = String(str), out = "";
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    out += (c < 0x20 || c === 0x7f) ? "\\x" + (c < 16 ? "0" : "") + c.toString(16).toUpperCase() : s.charAt(i);
  }
  return out;
}

// escapeDnValue(str) -> str. RFC 4514 sec. 2.4 string-representation escaping of a
// DN attribute value: backslash-escape the structural separators (" + , ; < > \) and
// a leading '#' / a leading-or-trailing space, THEN neutralize control bytes. Without
// this a value like `foo, CN=admin` renders as `CN=foo, CN=admin` and reads as two
// RDNs, so an attacker-controlled subject/issuer name masquerades as extra attributes
// in the report (CWE-116). The one place a DN value is made display-safe.
// @enforced-by behavioral -- the RFC 4514 separator class carries a quote inside a
//   regex literal, which the codebase-patterns literal-stripper mis-tokenizes, so no
//   rename-proof shape is detectable; the guard-name RED vectors (a comma / plus in a
//   DN value renders backslash-escaped, and does NOT read as a second RDN) are the guard.
function escapeDnValue(str) {
  var s = String(str).replace(/([\\"+,;<>])/g, "\\$1").replace(/^#/, "\\#").replace(/^ | $/g, "\\ ");
  return escapeControlBytes(s);
}

module.exports = {
  assertNoControlBytes: assertNoControlBytes, assertPrintableIa5: assertPrintableIa5,
  dnEqual: dnEqual, rdnEqual: rdnEqual,
  escapeControlBytes: escapeControlBytes, escapeDnValue: escapeDnValue,
};
