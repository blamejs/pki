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
// every relational comparison against its NaN getTime() (NaN < x, NaN >= x) is
// false, so a validity / not-before / not-after / currency window built on an
// unvalidated Date silently accepts when it should reject. The class recurred at
// three independent boundaries (TSP genTime, OCSP producedAt/thisUpdate, CT
// temporal-interval) before it was centralized here; the sibling
// nan-date-comparison-unguarded codebase-patterns detector flags any lib function
// that re-inlines a `.getTime()` comparison without first rejecting a NaN, so a
// new boundary is routed to this guard instead of re-growing the bug.
//
// Tier split: `value instanceof Date` with a NaN time is malformed caller input
// (a config-time or entry-point Date, such as an operator-supplied distrustAfter
// or a caller `opts.time`), so assertValid throws the caller's typed error instead
// of returning a silent default. within() is the fail-closed window primitive: it
// THROWS on a malformed operand but RETURNS a boolean for in/out-of-window, so the
// OCSP / CRL currency callers that treat out-of-window as a `continue` skip keep
// their control flow while a NaN operand can never slip through as a false.

var util = require("util");

// assertValid(value, E, code, label) -> the same Date, once proven valid.
//   value : a Date (or an alleged one) from a caller boundary.
//   E     : the (code, message[, cause]) typed-error FACTORY in scope at the call
//           site (ns.E / the module-local _err), never a defineClass class, which
//           would crash `class cannot be invoked without new` on the error path.
//   code  : the frozen domain/reason code this boundary rejects malformed time under.
//   label : field phrase for the message.
// @enforced-by nan-date-comparison-unguarded
function assertValid(value, E, code, label) {
  // The slot, never the prototype. `instanceof Date` asks what a value inherits from, and
  // `Object.create(Date.prototype)` inherits everything while holding no instant, so it passes
  // that test and `getTime()` then throws a raw TypeError out of this guard. `util.types.isDate`
  // reads the internal slot, which a caller cannot fake and which answers the same across realms.
  if (!util.types.isDate(value) || isNaN(value.getTime())) {
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

// isDate(value) -> boolean: does this value actually hold an instant?
//
// The predicate half of assertValid, for the boundaries that choose a default rather than refuse
// (`opts.genTime instanceof Date ? opts.genTime : new Date()`). `instanceof` asks what a value
// inherits from, so `Object.create(Date.prototype)` passes it while holding no instant, and the
// `.getTime()` that follows throws a raw TypeError out of a verb whose contract is a typed error.
// A caller who supplied one and got the default instead would be worse served still: the value
// they passed would have been silently replaced. This reads the slot, which cannot be faked and
// answers the same for a Date built in another realm.
//
// An Invalid Date has the slot and a NaN instant, so this says yes to one. A boundary that
// compares instants wants assertValid, which rejects both shapes.
// @enforced-by behavioral -- a prototype test in place of a slot test has no rename-proof code
// shape; the RED vectors (a slot-less Date lookalike at cms.verify / cms.sign / tsp.sign) are
// the guard.
function isDate(value) {
  return util.types.isDate(value);
}

module.exports = {
  assertValid: assertValid,
  isDate: isDate,
  within: within,
};
