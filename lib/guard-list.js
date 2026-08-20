// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal, so no operator-facing namespace. The documented surface is every verdict whose rule
// composes this guard: pki.path.validate (requiredEku, the policy tree), pki.cms.verify (the
// message trust verdict), the OCSP delegated-responder check, the TPM AIK purpose check, and the
// timestamp unknown-critical-extension gate.
//
// guard-list, membership decided by comparison and never by a prototype method.
//
// Defends the intrinsic-substitution class (CWE-349 / CWE-693: a control the caller can neutralize).
// Written `list.indexOf(v) !== -1` or `list.some(fn)`, a membership test asks the runtime, at the
// moment of the call, which function `indexOf` or `some` is. A caller who receives control after
// this package loads, through an option accessor or a `toJSON` or while a verb is suspended on an
// await, can replace it. The answer becomes whatever they chose, while every check around it still
// runs and still passes.
//
// The distinction that matters is what the answer IS. A scan over a local accumulator produces a
// value. A scan that decides whether a certificate carries a purpose, whether a policy is expected,
// or whether every signer is trusted IS the rule. Measured on the tree before this guard existed:
// with `Array.prototype.indexOf` replaced to report every value present, a certificate restricted
// to emailProtection satisfied a requiredEku of serverAuth, and pki.path.validate went from
// valid:false to valid:true.
//
// Capturing the method at load (guard-intrinsic) is the other half of the same defense, and is what
// a module already inside that discipline uses. This guard is for the rule sites themselves. A loop
// over `===` has nothing to replace, so it holds whatever the prototype says, in a module that has
// been swept and in one that has not.

// contains(list, value) -> boolean. Strict-equality membership, the `indexOf(v) !== -1` rule.
// A null / undefined list is honestly empty, never a throw: these run on verdict paths.
// @enforced-by behavioral -- `.indexOf(x) !== -1` has no rename-proof form that separates a
//   membership RULE from its legitimate siblings: the identical token is a substring search
//   (`authority.indexOf(":")`, `addr.indexOf("@")`) and a local index lookup, and a shape matching
//   all of them fired on 37 sites of which most were strings. What makes a site this guard's is
//   what the answer IS -- a decision about a certificate, a policy or a signer -- and that is a
//   judgment no regex makes. The RED vectors are the guard: a codeSigning-only certificate still
//   fails a serverAuth requiredEku, and an unauthorized responder is still refused, each with
//   Array.prototype.indexOf replaced after load.
function contains(list, value) {
  if (!list) return false;
  for (var i = 0, n = list.length; i < n; i++) if (list[i] === value) return true;
  return false;
}

// containsAll(list, values) -> boolean. Every one of `values` present in `list` -- the shape a
// "these purposes are all required" rule needs. No `values` is vacuously satisfied.
// @enforced-by behavioral -- the composition of contains() has no rename-proof shape of its own;
//   the RED vectors (a codeSigning-only certificate still fails a serverAuth requiredEku with
//   Array.prototype.indexOf replaced) are the guard.
function containsAll(list, values) {
  if (!values) return true;
  for (var i = 0, n = values.length; i < n; i++) if (!contains(list, values[i])) return false;
  return true;
}

// anyMatches(list, predicate) -> boolean. The `some(fn)` rule: does any member satisfy it? The
// predicate is the caller's own function, so what this guard removes is the DISPATCH, not the test.
// @enforced-by behavioral -- `.some(` has legitimate non-rule siblings (building a list, reporting
//   a count), so a blanket detector would false-fire; the RED vectors (a critical extension is
//   still seen, an untrusted signer still reported) are the guard.
function anyMatches(list, predicate) {
  if (!list) return false;
  for (var i = 0, n = list.length; i < n; i++) if (predicate(list[i], i)) return true;
  return false;
}

// allMatch(list, predicate) -> boolean. The `every(fn)` rule, same reasoning as anyMatches. An
// empty list is vacuously true, matching Array.prototype.every -- a caller that needs "non-empty
// AND all" tests the length itself, as pki.cms.verify does for the trust verdict.
// @enforced-by behavioral -- see anyMatches; the RED vector (an untrusted signer keeps
// trusted:false with Array.prototype.every replaced) is the guard.
function allMatch(list, predicate) {
  if (!list) return true;
  for (var i = 0, n = list.length; i < n; i++) if (!predicate(list[i], i)) return false;
  return true;
}

module.exports = {
  contains: contains,
  containsAll: containsAll,
  anyMatches: anyMatches,
  allMatch: allMatch,
};
