// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var util = require("util");
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
  _refuseUnenumerable(obj, E, code, "the options");
  var describe = typeof message === "function" ? message : function (k) { return message + JSON.stringify(k); };
  _readableNames(obj).forEach(function (k) {
    if (!Object.prototype.hasOwnProperty.call(known, k)) throw E(code, describe(k));
  });
}

// The names Object.prototype carries in a clean runtime, captured while this module loads, which
// is before application code has run and so before anything could have added to it. Comparing
// against the captured set skips the built-ins by identity and still reports any name added
// afterwards. Stopping the walk at Object.prototype instead excludes the whole object, so a runtime
// whose prototype carries `Object.prototype.password = "pw"` answers `opts.password` on a plain
// `{}` and `pki.key.export` hands back an unprotected key for a bag holding nothing.
//
// A name planted before this module loads is baked into the snapshot and cannot be distinguished
// from a built-in; require order is the limit of what this can see.
var _PRISTINE_OBJECT_PROTO = (function () {
  var s = Object.create(null);
  Object.getOwnPropertyNames(Object.prototype).forEach(function (k) { s[k] = 1; });
  return s;
})();

// Can this object be asked honestly what it holds?
//
// A Proxy answers `ownKeys` and `get` from two independent traps, so the two need not agree. One
// reporting no keys while its `get` returns "pw" for `password` presents an object that every
// enumeration calls empty and every read calls populated. No walk can close that: the readable
// names are whatever the trap decides at the moment it is asked, and asking again may differ.
// So the enumeration is not made more thorough, the object is refused. That is the same rule
// guard-bytes states for a value it cannot copy: there are two honest outcomes for a caller's
// argument, and "read it and hope the enumeration was truthful" is not one of them.
//
// The check is by identity through `util.types.isProxy`, never by behavior. Probing traps to
// catch a liar is a race a liar wins: it can answer consistently until the check is over.
function _refuseUnenumerable(v, E, code, label) {
  if (v !== null && typeof v === "object" && util.types.isProxy(v)) {
    throw E(code, label + " is a Proxy, whose reported keys need not match what it answers, so " +
      "an option it holds cannot be found; pass a plain object");
  }
}

// Does the prototype chain above `from` supply `k` as a data property holding `fn`? That is what
// makes `k` a method. Asking it by value identity is what makes the answer survive
// guard.bytes.snapshotDeep.
//
// The snapshot copies every readable name onto the copy and keeps the prototype, so a class's
// method arrives as an own property while the identical function is still reachable above it. A
// rule that asks "is this name own?" therefore calls the same method an option on the copy and
// behavior on the original, and every check running after a snapshot refuses an options bag that
// is an instance of the caller's own class.
//
// The walk stops at an object already seen, since a prototype chain is finite only while it is
// acyclic and a Proxy can make it otherwise. See the note on _readableNames.
function _isMethodOf(from, k, fn) {
  var visited = new Set();
  for (var o = from; o && !visited.has(o); o = Object.getPrototypeOf(o)) {
    visited.add(o);
    var d = Object.getOwnPropertyDescriptor(o, k);
    if (!d) continue;
    return !d.get && !d.set && d.value === fn;
  }
  return false;
}

// Every name that can supply a value to a later `obj.foo`. `Object.keys` reports a subset of
// those: own enumerable names only. Four ordinary object shapes answer the lookup while showing
// that enumeration nothing. A value on the prototype (`Object.create({ password: "pw" })`). A
// non-enumerable own value (`Object.defineProperty(o, "password", { enumerable: false })`). A
// class getter, which class syntax also defines non-enumerable. And a polluted
// `Object.prototype`. On each of them `pki.key.export` accepts the bag, ignores the password it
// can read, and returns the private key in the clear, which is the case the refusal exists to
// prevent.
//
// @enforced-by behavioral -- a property-surface walk has no rename-proof code shape. The RED
// vectors are the guard, and they are the shapes that got past it in turn: a prototype data
// property, a non-enumerable own property, a class getter, a polluted Object.prototype, and a
// prototype method that must still be allowed through.
//
// So the walk covers the whole chain and skips one thing: a method, meaning a data property
// holding a function that the chain above it also supplies under that name. A method is behavior
// the bag's class defines. This repository has settled that an instance of a caller's own class
// is a legitimate options bag, since guard.bytes.snapshotDeep copies one and keeps its prototype
// so its methods resolve, and flagging them would reject calls that work today.
//
// Neither enumerability nor ownness decides that test. Each records how the name arrived, which
// is a different question from what it means. Enumerability records how a method was written,
// and the two ways differ: class syntax defines methods non-enumerable while `Proto.m = fn`
// defines them enumerable, so a rule keyed on it accepts one style and rejects the other.
// Ownness records whether the object has been through a snapshot, which flips the same method
// from inherited to own, so a rule keyed on it calls that method behavior at one check site and
// an unknown option at the next. Value identity against the chain above answers the same on both
// sides, which is what lets a check sit before or after a snapshot and reach one verdict.
//
// An accessor is never a method, whichever way it was written. A getter exists to answer with a
// value, which is exactly what an option does.
//
// One case is traded away, and it is written down here rather than left implicit. An unknown
// option supplied as a method is not reported: its value would have to be a function, and the
// prototype chain would have to supply that same function under that name. The function-valued
// options here (revocationChecker, verifier, transport) are passed as own properties, so reaching
// the hole needs a caller to misspell one and also define it as a method. That is the price of
// keeping class instances usable.
function _readableNames(obj) {
  var seen = Object.create(null);
  var out = [];
  var o = obj;
  // A prototype chain is finite only while it is acyclic, and a Proxy can make it otherwise.
  // While its target stays extensible a `getPrototypeOf` trap may return the proxy itself. The
  // walk therefore stops at an object it has already visited. A second lap over the same objects
  // yields no name the first did not, so the reported names stay complete. Without the test a
  // caller's argument hangs the verb before a single option has been read.
  var visited = new Set();
  while (o && !visited.has(o)) {
    visited.add(o);
    var atObjectProto = (o === Object.prototype);
    var inherited = (o !== obj);
    var above = Object.getPrototypeOf(o);
    Object.getOwnPropertyNames(o).forEach(function (k) {
      if (seen[k]) return;
      if (atObjectProto && _PRISTINE_OBJECT_PROTO[k]) return;   // a built-in, not a supplied option
      var d = Object.getOwnPropertyDescriptor(o, k);
      // A method: a data property holding a function that is either inherited, where a class
      // defines one, or also supplied under that name by the chain above, where a snapshot has
      // copied one down onto the object. Both readings are needed. The first alone calls a
      // promoted method an option. The second alone misses a method at the level that defines
      // it, where nothing above carries the same function. An accessor is never a method,
      // whichever way it was written, since a getter exists to answer with a value.
      if (d && !d.get && !d.set && typeof d.value === "function" &&
          (inherited || _isMethodOf(above, k, d.value))) return;
      seen[k] = 1;
      out.push(k);
    });
    o = above;
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
  _refuseUnenumerable(opts, E, code, label);
  return opts;
}

module.exports = {
  assertCanonicalOid: assertCanonicalOid,
  assertKnownKeys: assertKnownKeys,
  optionsObject: optionsObject,
  // Exported so a caller that FORWARDS an options bag copies the same surface this module
  // accepts. A narrower enumeration such as `Object.keys` admits a name here and then drops
  // it on the way, which is worse than refusing it. The option is reported valid and then
  // does nothing at the place it was meant to act.
  readableNames: _readableNames
};
