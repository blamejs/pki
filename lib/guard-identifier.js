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

// The dotted-decimal grammar, walked instead of matched. `(0|[1-9]\d*)(\.(0|[1-9]\d*))+`
// nests a quantified group inside a quantified group with an alternation in each,
// which is the shape whose cost on a rejecting string is a property of the pattern
// and not of the length, and this guard's whole job is to be handed strings that
// reject. Walking the string is one pass, one comparison per character, and it
// states the two rules plainly: an arc is one or more digits, and an arc longer than
// one digit does not start with zero (the leading-zero form round-trips to a
// DIFFERENT OID, which is the divergence this guard exists to stop).
function _isDottedDecimal(str) {
  if (str.length === 0) return false;
  var arcs = 0, digits = 0, leadingZero = false;
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c === 0x2e) {                                   // "."
      if (digits === 0 || leadingZero) return false;    // empty arc, or "01"
      arcs++; digits = 0; leadingZero = false;
      continue;
    }
    if (c < 0x30 || c > 0x39) return false;             // not a digit
    if (digits === 1 && str.charCodeAt(i - 1) === 0x30) leadingZero = true;
    digits++;
  }
  if (digits === 0 || leadingZero) return false;        // trailing "." or a final "01"
  return arcs >= 1;                                     // two or more arcs
}

// assertCanonicalOid(str, E, code, label, boundsCode) -> str | throws
// A canonical dotted-decimal object identifier string: two or more arcs, each a
// non-negative decimal integer with no leading zero (the syntax), and, unless
// bounds are waived, the root arc 0..2 with the second arc 0..39 under roots 0
// and 1 (the X.660 encodability bounds: the first two arcs pack into a single
// sub-identifier as 40*root+second). E is the (code, message) typed-error factory:
//   - a syntax fault always throws E(code, ...).
//   - boundsCode === null waives the arc-bound check, for a lookup key (oid.name
//     / oid.has), where a well-formed but non-encodable OID is simply not
//     registered (a miss) and not an error.
//   - otherwise an out-of-range arc throws E(boundsCode, ...) (boundsCode defaults
//     to code), so a caller distinguishing the two reasons (oid.js: oid/bad-input
//     syntax vs oid/bad-arc bounds) keeps both codes.
// @enforced-by behavioral -- string-form OID canonicalization has no rename-proof
//   code shape distinct from the arc-based bounds check oid.js legitimately keeps
//   for the arc path; the divergence RED vectors (build.oid / oid.toArcs / requiredEku
//   reject a non-canonical OID) driving the composing consumers are the guard.
function assertCanonicalOid(str, E, code, label, boundsCode) {
  var who = label || "OID";
  if (typeof str !== "string" || !_isDottedDecimal(str)) {
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

// assertKnownKeys(obj, known, E, code, label): every own key of `obj` must appear in `known`.
//
// The shape this replaces was hand-written in a dozen callers, and it is worth one home because
// getting it wrong fails open in the quietest possible way: an options object whose key is
// misspelled silently carries the default, so a caller who asked for a stricter check gets the
// looser behavior and no error. Two details are easy to lose in a re-inline and are fixed here.
// `known` is consulted with hasOwnProperty and not a truthiness test, so an inherited Object
// member ("constructor", "toString") cannot read as a recognized key; and the walk is over own
// enumerable keys, so a `__proto__` arriving from JSON is inspected instead of skipped.
//
// @enforced-by behavioral -- an options-shape walk has no rename-proof code shape; the RED vectors
// (an unknown key, an inherited name, a JSON-borne __proto__) are the guard.
//
// `message` is the caller's own wording, so routing an existing check through this guard changes
// what is checked, never what the operator reads: a string is the prefix the quoted key is appended
// to, and a function (key) -> string builds the whole sentence, for the many callers that name the
// key mid-sentence and follow it with the hint that says what to pass instead.
//
// @enforced-by guard-shape-reinlined
// The shape requires the throw: an identical walk whose body filters on the same table (copying the
// recognized keys onward instead of rejecting the unrecognized ones) is a different operation with
// no fail-open risk, and must not be dragged through a guard that only knows how to reject.
// @guard-shape Object\.keys\(\w+(?:\.\w+)*\)\.forEach\(function \((\w+)\) \{\s*if \(![\w.]+\[\1\]\) (?:\{\s*)?throw
function assertKnownKeys(obj, known, E, code, message) {
  var describe = typeof message === "function" ? message : function (k) { return message + JSON.stringify(k); };
  _readableNames(obj).forEach(function (k) {
    if (!Object.prototype.hasOwnProperty.call(known, k)) throw E(code, describe(k));
  });
}

// Every name a later `obj.foo` can resolve, which is what the caller is really being asked
// about -- not the subset `Object.keys` reports.
//
// `Object.keys` lists own ENUMERABLE names only, so two ordinary JavaScript objects walked
// straight past the check while still answering the lookup: `Object.create({ password: "pw" })`
// puts the value on the prototype, and `Object.defineProperty(o, "password", { enumerable:
// false })` puts it on the object where the enumeration cannot see it. Either one meant
// `pki.key.export` accepted the bag, ignored the password it could read, and returned the
// private key in the clear -- the exact case the refusal exists to prevent, reached by a
// different object shape.
//
// @enforced-by behavioral -- a property-surface walk has no rename-proof code shape; the RED
// vectors ARE the guard, and they are the shapes that got past it in turn: a prototype data
// property, a non-enumerable own property, a class getter, and a prototype method that must
// still be allowed through.
//
// Every name that can SUPPLY A VALUE to a later `obj.foo`, which is the question being asked.
// Enumerability is not the line -- three shapes in a row got through a rule that used it:
// a prototype data property, a non-enumerable own property, and then a class getter, which
// class syntax also defines non-enumerable. Each answered the lookup while the enumeration
// showed nothing, and each meant pki.key.export returned an unprotected private key.
//
// So the walk covers the whole chain and skips exactly one thing: a name INHERITED as a DATA
// property whose value is a FUNCTION -- a method, including `constructor`. A method is
// behavior the bag's class defines, not a value its caller supplied, and this repository has
// settled that an instance of a caller's own class is a legitimate options bag
// (guard.bytes.snapshotDeep copies one and keeps its prototype so its methods resolve), so
// flagging them would reject calls that work today.
//
// Enumerability deliberately plays no part in that test. It records how a method was WRITTEN,
// not what it means: class syntax defines methods non-enumerable while `Proto.m = fn` defines
// them enumerable, and a rule keyed on it accepted one style and rejected the other. An
// ACCESSOR is never skipped whichever way it was written: a getter exists to answer with a
// value, which is exactly what an option does.
//
// Residual, and stated rather than hidden: an UNKNOWN option supplied as an inherited method is
// not reported. Its value would be a function; the function-valued options here
// (revocationChecker, verifier, transport) are passed as own properties, so the hole needs a
// caller to both misspell one AND place it on a prototype. That is the case this rule trades
// away to keep class instances usable.
function _readableNames(obj) {
  var seen = Object.create(null);
  var out = [];
  var o = obj;
  var own = true;
  while (o && o !== Object.prototype) {
    Object.getOwnPropertyNames(o).forEach(function (k) {
      if (seen[k]) return;
      if (!own) {
        var d = Object.getOwnPropertyDescriptor(o, k);
        // A method: inherited, a data property, holding a function. Written either way.
        if (d && !d.get && !d.set && typeof d.value === "function") return;
      }
      seen[k] = 1;
      out.push(k);
    });
    o = Object.getPrototypeOf(o);
    own = false;
  }
  return out;
}

// Normalize a verb's options argument, and RETURN it, because the order matters and returning
// is the only way to make the safe order the easy one.
//
// The idiom this replaces was `opts = opts || {}` followed by a type check. That reads as though
// it validates, and does not: `||` treats `false`, `0`, `""` and `NaN` as absent too, so those
// four were rewritten to `{}` before the check could see them and sailed through as valid
// options. Every entry point that reached for the idiom inherited the hole, including three that
// had shipped with it.
//
// Only `null` and `undefined` mean "no options given". Anything else non-object is a caller
// error and says so. A Buffer is excluded because it is an object and is never an options bag --
// passing one is an argument-order mistake, which is worth naming rather than treating as empty.
//
// @enforced-by behavioral -- the defect is an ORDERING, which has no rename-proof code shape; the
// RED vector (a verb handed `false` accepting it as `{}`) is the guard.
function optionsObject(opts, E, code, label) {
  if (opts === null || opts === undefined) return {};
  if (typeof opts !== "object" || Buffer.isBuffer(opts)) throw E(code, label + " must be an object");
  return opts;
}

module.exports = {
  assertCanonicalOid: assertCanonicalOid,
  assertKnownKeys: assertKnownKeys,
  optionsObject: optionsObject,
  // Exported so a caller that FORWARDS an options bag copies the same surface this module
  // accepts. Anything narrower -- `Object.keys`, say -- admits a name here and then drops it
  // on the way, which is worse than refusing it: the option is reported valid and silently
  // does nothing at the place it was meant to act.
  readableNames: _readableNames
};
