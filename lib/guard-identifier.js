// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// consumers whose identifier-string integrity composes this guard (pki.oid
// name/arc resolution, pki.asn1 OID encoding, pki.path.validate requiredEku /
// userInitialPolicySet key checking).
//
// guard-identifier -- fail-closed canonicalization of the structured-identifier
// STRINGS the toolkit compares and encodes. An identifier used as a lookup /
// comparison key must be in one canonical form, or the string form and the
// decoded form of the same identifier silently disagree.
//
// Defends the canonicalization-divergence class (CWE-20): a dotted-decimal OID
// with a leading-zero arc ("2.05.29.15") round-trips to a DIFFERENT OID
// ("2.5.29.15"), and an arc outside the X.660 bounds can never DER-encode at all.
// A hand-rolled string check that accepts either lets `build.oid` emit bytes that
// decode to a different OID than the string names, or lets a non-canonical policy /
// EKU key compare unequal to the canonical decoder output it is matched against (a
// silent false-reject). Every string-form identifier check routes through here so
// the string and DER forms cannot diverge.

// assertCanonicalOid(str, E, code, label, boundsCode) -> str | throws
// A canonical dotted-decimal object identifier string: two or more arcs, each a
// non-negative decimal integer with no leading zero (the SYNTAX), and -- unless
// bounds are waived -- the root arc 0..2 with the second arc 0..39 under roots 0
// and 1 (the X.660 ENCODABILITY bounds: the first two arcs pack into a single
// sub-identifier as 40*root+second). E is the (code, message) typed-error factory:
//   - a syntax fault always throws E(code, ...).
//   - boundsCode === null waives the arc-bound check -- for a LOOKUP key (oid.name
//     / oid.has), where a well-formed but non-encodable OID is simply not
//     registered (a miss), not an error.
//   - otherwise an out-of-range arc throws E(boundsCode, ...) (boundsCode defaults
//     to code), so a caller distinguishing the two reasons (oid.js: oid/bad-input
//     syntax vs oid/bad-arc bounds) keeps both codes.
// @enforced-by behavioral -- string-form OID canonicalization has no rename-proof
//   code shape distinct from the arc-based bounds check oid.js legitimately keeps
//   for the arc path; the divergence RED vectors (build.oid / oid.toArcs / requiredEku
//   reject a non-canonical OID) driving the composing consumers are the guard.
function assertCanonicalOid(str, E, code, label, boundsCode) {
  var who = label || "OID";
  if (typeof str !== "string" || !/^(0|[1-9]\d*)(\.(0|[1-9]\d*))+$/.test(str)) {
    throw E(code, who + " must be a canonical dotted-decimal OID string of two or more arcs with no leading-zero component");
  }
  if (boundsCode === null) return str;
  var bcode = boundsCode === undefined ? code : boundsCode;
  var parts = str.split(".");
  var root = BigInt(parts[0]);
  var second = BigInt(parts[1]);
  if (root > 2n) throw E(bcode, who + " root arc must be 0, 1, or 2 (X.660)");
  if (root < 2n && second > 39n) throw E(bcode, who + " second arc must be 0..39 under roots 0 and 1 (X.660)");
  return str;
}

module.exports = { assertCanonicalOid: assertCanonicalOid };
