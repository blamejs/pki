// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// verifiers whose validity / currency / temporal gates compose this guard
// (pki.path.validate, pki.ocsp.verify, pki.tsp.*, pki.ct.*, pki.cms.sign).
//
// guard-time -- fail-closed Date-instant validation before a temporal comparison.
//
// Defends the NaN-Date fail-open class (CWE-20 improper input validation feeding
// a silent security-gate bypass). An Invalid Date is still `instanceof Date`, and
// EVERY relational comparison against its NaN getTime() (NaN < x, NaN >= x) is
// false -- so a validity / not-before / not-after / currency window built on an
// unvalidated Date silently ACCEPTS when it should reject. The class recurred at
// three independent boundaries (TSP genTime, OCSP producedAt/thisUpdate, CT
// temporal-interval) before it was centralized here; the sibling
// nan-date-comparison-unguarded codebase-patterns detector flags any lib function
// that re-inlines a `.getTime()` comparison WITHOUT first rejecting a NaN, so a
// new boundary is routed to this guard rather than re-growing the bug.
//
// Tier split: `value instanceof Date` with a NaN time is malformed CALLER input
// (a config-time / entry-point Date -- an operator-supplied distrustAfter, a
// caller `opts.time`), so assertValid throws the caller's typed error rather than
// returning a silent default. within() is the fail-closed window primitive: it
// THROWS on a malformed operand but RETURNS a boolean for in/out-of-window, so the
// OCSP / CRL currency callers that treat out-of-window as a `continue` skip keep
// their control flow while a NaN operand can never slip through as a false.

// assertValid(value, E, code, label) -> the same Date, once proven valid.
//   value : a Date (or an alleged one) from a caller boundary.
//   E     : the (code, message[, cause]) typed-error FACTORY in scope at the call
//           site (ns.E / the module-local _err) -- NEVER a defineClass class, which
//           would crash `class cannot be invoked without new` on the error path.
//   code  : the frozen domain/reason code this boundary rejects malformed time under.
//   label : field phrase for the message.
// @enforced-by nan-date-comparison-unguarded
function assertValid(value, E, code, label) {
  if (!(value instanceof Date) || isNaN(value.getTime())) {
    throw E(code, (label || "value") + " must be a valid Date");
  }
  return value;
}

// within(instant, lower, upper, E, code, label, opts) -> boolean (instant in window).
//   Rejects a malformed instant / lower / upper by THROWING (assertValid), then
//   answers containment as a boolean. Half-open [lower, upper) by default (a CT
//   temporal-interval / an OCSP-CRL currency window); pass opts.upperInclusive for
//   the closed [notBefore, notAfter] certificate-validity shape.
// @enforced-by nan-date-comparison-unguarded
function within(instant, lower, upper, E, code, label, opts) {
  // assertValid rejects a non-Date / Invalid Date operand up front, so t/lo/hi below are
  // guaranteed non-NaN -- the containment comparisons can never be a silent NaN-false. The
  // getTime() results are bound to locals (not compared inline), so this home carries no
  // unguarded `.getTime()`-in-a-comparison shape for the nan-date-comparison-unguarded detector.
  assertValid(instant, E, code, label);
  assertValid(lower, E, code, (label || "window") + " lower bound");
  assertValid(upper, E, code, (label || "window") + " upper bound");
  var t = instant.getTime();
  var lo = lower.getTime();
  var hi = upper.getTime();
  return t >= lo && (opts && opts.upperInclusive ? t <= hi : t < hi);
}

module.exports = {
  assertValid: assertValid,
  within: within,
};
