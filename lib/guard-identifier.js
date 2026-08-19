// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// The slot predicates, snapshotted at load. `util.types` is an ordinary object, and this module
// asks it whether a value is a Proxy -- the question that decides whether an options bag can be
// asked honestly what it holds at all.
var intrinsic = require("./guard-intrinsic");
var util = { types: intrinsic.types };
// The array test, taken at load. It decides whether a value is walked as a list at all, so one
// answering `false` makes the index scan report nothing -- and every index rule keyed on what that
// scan found then applies to nothing, which is how an accessor under index 0 reaches a copy loop
// that the refusal was supposed to have turned the whole call away for.
var _isArray = intrinsic.isArray;
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
// `known` and `message` are the module's own, and `obj` is the only argument here that a caller
// supplies. Questions asked of `obj` are typed, since a caller can answer them with a trap or a
// getter that throws; questions asked of the other two are not, because a table or a wording that
// throws is this toolkit's own wiring mistake. Handing either one a value off a caller would put
// an untyped exception on a boundary that promises a typed one, so neither takes one.
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
    if (Object.prototype.hasOwnProperty.call(known, k)) return;
    // A Symbol reaches the message as its description, before either form of `message` sees it.
    // JSON.stringify returns undefined for one, so a caller's own builder (which stringifies the
    // key itself) would name the refused option "undefined" and leave nothing to search for.
    // Normalizing here rather than in the default builder keeps both forms reading the same.
    throw E(code, describe(typeof k === "symbol" ? String(k) : k));
  });
}

// What Object.prototype carries, per ECMA-262, written out rather than read from the runtime.
//
// Stopping the walk at Object.prototype excludes the whole object, so a runtime whose prototype
// carries `Object.prototype.password = "pw"` answers `opts.password` on a plain `{}` and
// `pki.key.export` hands back an unprotected key for a bag holding nothing. Naming the members
// instead reports anything else there.
//
// Reading the names off the live Object.prototype at load looks equivalent and is not: it is the
// runtime under attack answering the question, so a name planted before this module loads is
// captured as a built-in and is thereafter invisible. The spec list holds whoever loaded first.
// A guard-identifier test asserts it against the live object, so an engine that adds a member
// fails there rather than silently reporting it to every caller as an unknown option.
//
// The residual is a planted function REPLACING one of these twelve. No verb reads `opts.toString`
// as an option, so that smuggles nothing; it breaks the runtime at large, not this check.
var _PRISTINE_OBJECT_PROTO = (function () {
  var s = Object.create(null);
  ["constructor", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
    "toString", "valueOf", "__defineGetter__", "__defineSetter__", "__lookupGetter__",
    "__lookupSetter__", "__proto__"].forEach(function (k) { s[k] = 1; });
  return s;
})();

// Is this descriptor shaped like a member of Object.prototype rather than a planted value? Every
// real one is a data property holding a function, or the `__proto__` accessor. Nothing there is a
// data property holding a string, a number or an object, so a planted `password: "pw"` fails this
// test whatever the snapshot above says about its name.
function _looksBuiltIn(d) {
  return !!d && (!!d.get || !!d.set || typeof d.value === "function");
}

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
// The WHOLE chain, not the object. `obj.password` resolves through every prototype above it, so a
// plain object inheriting from a lying Proxy answers the read while enumerating empty and is not
// itself a Proxy. Testing only the object handed in leaves that one line of indirection open.
// The error factory is validated before it is needed, for the same reason a guard taking a bound
// validates the bound: the one moment it is called is the moment something has already gone
// wrong, and a factory that is not one turns the refusal into a TypeError from inside the guard.
// This is a caller's wiring mistake rather than untrusted input, so it throws plainly.
function _requireFactory(E) {
  if (typeof E !== "function") {
    throw new TypeError("guard.identifier needs an error factory called as E(code, message); " +
      "a class is not one, so adapt it at the call site");
  }
}

function _refuseUnenumerable(v, E, code, label) {
  _requireFactory(E);
  if (v === null || typeof v !== "object") return;
  var visited = new Set();
  for (var o = v; o && !visited.has(o); o = Object.getPrototypeOf(o)) {
    visited.add(o);
    if (!util.types.isProxy(o)) continue;
    throw E(code, label + (o === v ? " is" : " inherits from") + " a Proxy, whose reported keys " +
      "need not match what it answers, so an option it holds cannot be found; pass a plain object");
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
// prototype chain would have to supply that same function under that name. So `class Options {
// typo() {} }` passes, and `opts.typo` does resolve. The function-valued options here
// (revocationChecker, verifier, transport) are passed as own properties, so reaching the hole
// needs a caller to misspell one AND define it as a method rather than assign it. That is the
// price of keeping class instances usable, which this repository has settled, and it is the one
// gap in "every name a later obj.foo can resolve is reported".
// Is this string an array index, as the language defines one: an integer in [0, 2^32 - 2] whose
// canonical decimal spelling is the string itself?
//
// `String(Number(k)) === k` looks like that test and is not. It also admits "-1", "1.5", "NaN",
// "Infinity" and "4294967295" (one past the last index), every one of which is an ordinary named
// property on an array rather than an element. Treating them as structure means an unknown option
// under one of those names is passed over here and dropped by the copy in guard-bytes, so it
// reaches neither the check nor the verb. A leading zero is excluded by the same comparison,
// since "01" is a named property too.
function _isArrayIndex(k) {
  var n = Number(k);
  return Number.isInteger(n) && n >= 0 && n < 4294967295 && String(n) === k;
}

// Is this value one whose own `length` and indices are structure rather than supplied names?
//
// The value itself, never anything it inherits from. An object merely sitting over an array is a
// plain object: a `0` or a `length` of its own is a field its caller wrote, and reading the kind
// off the chain suppressed exactly those. What such a bag inherits from the array beneath it is a
// separate question, answered by the level test in the walk.
//
// A DataView is a byte view and is not one of these. It reads its bytes through methods and has no
// integer-indexed elements and no `length`, so `dv.length = 9` and `dv[0] = "x"` are ordinary
// properties that stay set and answer on a later read. Counting it as indexed drops both from the
// names reported and from the copy the verb is handed.
function _isIndexedKind(v) {
  return _isArray(v) || (ArrayBuffer.isView(v) && !util.types.isDataView(v));
}

// The names the built-in collection kinds define on their prototypes, written out rather than
// read from the runtime, for the same reason the root's twelve are: reading a prototype to learn
// what belongs on it asks the polluted object to vouch for itself.
//
// One set covering every kind, because a LEVEL is what gets read and a level's kind cannot be
// established without asking a prototype who it is. `Object.create(Map.prototype)` holds no map
// and inherits `size`; a foreign array's prototype is not this realm's. Both are answered by
// asking whether the NAME is one a kind defines, which no realm and no lookalike changes.
//
// Being on the list is not enough on its own: the member also has to be shaped like one, so a
// planted `Array.prototype.password` is reported while `Array.prototype.length` is not.
// One list per prototype, holding exactly what THAT prototype defines. Sharing a list across
// kinds that merely resemble each other exempts a name its holder never had, which is a caller's
// option passed over in silence: a weak collection counts nothing and has no `size`, a
// SharedArrayBuffer is `growable` where an ArrayBuffer is `resizable` and `detached`, a DataView
// has no `length`, and `BYTES_PER_ELEMENT` belongs to a concrete typed array rather than the
// prototype they share.
var _ARRAY_PROTO_MEMBERS = ["length", Symbol.unscopables];
var _REGEXP_PROTO_MEMBERS = ["source", "flags", "global", "ignoreCase", "multiline",
  "dotAll", "unicode", "unicodeSets", "sticky", "hasIndices"];
var _SIZED_PROTO_MEMBERS = ["size", Symbol.toStringTag];
var _WEAK_PROTO_MEMBERS = [Symbol.toStringTag];
var _ARRAYBUFFER_PROTO_MEMBERS = ["byteLength", "maxByteLength", "resizable", "detached",
  Symbol.toStringTag];
var _SHARED_PROTO_MEMBERS = ["byteLength", "maxByteLength", "growable", Symbol.toStringTag];
var _DATAVIEW_PROTO_MEMBERS = ["buffer", "byteLength", "byteOffset", Symbol.toStringTag];
var _TYPED_PROTO_MEMBERS = ["buffer", "byteLength", "byteOffset", "length", Symbol.toStringTag];
var _CONCRETE_TYPED_MEMBERS = ["BYTES_PER_ELEMENT"];
// Node puts these two on Buffer.prototype, beneath the ECMAScript typed-array prototype.
var _BUFFER_PROTO_MEMBERS = ["parent", "offset"];

// What a whole kind carries, as against what one prototype defines. This is what answers for a
// value whose chain holds no prototype of this realm, where the level cannot be recognized and
// the kind read from the value's own slot is all there is.
// A kind carries what its own prototypes hold and nothing a neighboring kind holds. Answering a
// buffer with both buffer kinds' members exempts `growable` on an ArrayBuffer and `detached` on a
// SharedArrayBuffer, neither of which the language defines there, so a caller's getter under
// either name is passed over.
var _ARRAY_MEMBERS = _ARRAY_PROTO_MEMBERS;
var _REGEXP_MEMBERS = ["lastIndex"].concat(_REGEXP_PROTO_MEMBERS);
var _VIEW_MEMBERS = _TYPED_PROTO_MEMBERS.concat(_CONCRETE_TYPED_MEMBERS);
var _BUFFER_KIND_MEMBERS = _VIEW_MEMBERS.concat(_BUFFER_PROTO_MEMBERS);
var _DATAVIEW_MEMBERS = _DATAVIEW_PROTO_MEMBERS;
var _ARRAYBUFFER_MEMBERS = _ARRAYBUFFER_PROTO_MEMBERS;
var _SHARED_MEMBERS = _SHARED_PROTO_MEMBERS;

// Which of those a value carries, taken from its internal slot.
//
// The value's own kind, not the union, because a name belongs to a kind and a caller's accessor
// can borrow one that a different kind defines. `class Opts extends Array { get buffer() {} }` is
// an array, `buffer` is a byte view's member and not an array's, so that getter is the caller's
// option and gets reported.
//
// A value with no collection slot answers with nothing. `Object.create(Map.prototype)` holds no
// map and still inherits `size`, and that is settled by the level test in the walk, which reads
// the members off the prototype the name was found on.
// The prototypes this realm installs a kind's members on. A level that IS one carries the
// language's members whatever the value in front of it turns out to be, which is how
// `Object.create(Map.prototype)` keeps `size` while holding no map.
//
// Typed arrays are recognized through the prototype they all share rather than by naming each
// constructor, so a kind the list never mentioned is covered: `Float16Array` arrived on Node 24
// and an enumeration would have gone on reporting its `BYTES_PER_ELEMENT` as a caller's option.
// Each one paired with the members IT defines, never the union of every kind's. A level carries
// only its own: `size` on `Array.prototype` is nothing the language put there, so exempting it
// because some other kind has a member by that name hands back the hole this walk exists to
// close, for anyone who plants it in a shape that reads as built-in.
var _TYPED_ARRAY_PROTO = Object.getPrototypeOf(Uint8Array.prototype);
var _INTRINSIC_HOLDERS = (function () {
  var m = new Map([[_TYPED_ARRAY_PROTO, _TYPED_PROTO_MEMBERS]]);
  function pair(ctor, members) { if (ctor && ctor.prototype) m.set(ctor.prototype, members); }
  pair(Array, _ARRAY_PROTO_MEMBERS);
  pair(RegExp, _REGEXP_PROTO_MEMBERS);
  [Map, Set].forEach(function (c) { pair(c, _SIZED_PROTO_MEMBERS); });
  [WeakMap, WeakSet].forEach(function (c) { pair(c, _WEAK_PROTO_MEMBERS); });
  pair(ArrayBuffer, _ARRAYBUFFER_PROTO_MEMBERS);
  pair(typeof SharedArrayBuffer === "function" ? SharedArrayBuffer : null, _SHARED_PROTO_MEMBERS);
  pair(DataView, _DATAVIEW_PROTO_MEMBERS);
  pair(Buffer, _BUFFER_PROTO_MEMBERS);
  // Every concrete typed-array kind the runtime actually provides, found by asking it rather than
  // by naming them, so a kind added later is covered the day it lands -- Float16Array was.
  //
  // Registered as identities. Recognizing them by their PARENT instead admitted anything a caller
  // built over `%TypedArray%.prototype`, and a bag inheriting `BYTES_PER_ELEMENT` from such an
  // object then read as an intrinsic member rather than as the unknown option it was.
  //
  // Reading a global can run a getter, and a deprecated one can throw; a fault here would break
  // this module's load over a name it does not need.
  Object.getOwnPropertyNames(globalThis).forEach(function (n) {
    var C;
    try { C = globalThis[n]; }
    catch (_e) { /* allow:swallow-unverified this runs once at load over whatever globals the host defines, and no global in a supported runtime throws on read, so no test drives it; it is here so an embedder's throwing accessor cannot stop this module loading over a name it does not need */ return; }
    if (typeof C !== "function" || typeof C.BYTES_PER_ELEMENT !== "number") return;
    if (!C.prototype || Object.getPrototypeOf(C.prototype) !== _TYPED_ARRAY_PROTO) return;
    m.set(C.prototype, _CONCRETE_TYPED_MEMBERS);
  });
  return m;
})();

// The members a chain level defines, or null where the level is not one the language installs
// members on. Membership is by identity: every prototype the language installs members on is in
// the table above, the concrete typed-array ones included, so an object that merely sits over one
// of them is a caller's and its names are theirs.
function _holderMembers(o) {
  return _INTRINSIC_HOLDERS.has(o) ? _INTRINSIC_HOLDERS.get(o) : null;
}

// Is this one of Node's Buffers? A byte view whose chain reaches `Buffer.prototype`, asked by
// walking it rather than through `Buffer.isBuffer`.
//
// `Buffer.isBuffer` is an `instanceof`, and `Buffer` is an ordinary extensible function, so
// defining `Buffer[Symbol.hasInstance]` on it hands the answer to whoever did. That is the same
// pollution this walk exists to survive on `Object.prototype` and `Array.prototype`, and it can
// throw as well as lie: a caller's argument then leaves a door whose contract is a typed error
// carrying somebody else's exception. A prototype identity is not writable from outside.
function _isNodeBuffer(v) {
  if (!util.types.isUint8Array(v)) return false;
  var visited = new Set();
  for (var o = v; o && !visited.has(o); o = Object.getPrototypeOf(o)) {
    visited.add(o);
    if (o === Buffer.prototype) return true;
  }
  return false;
}

function _kindMembers(v) {
  // The value's own slot, never a kind it merely inherits from. Whatever a real intrinsic
  // prototype in the chain supplies is handled by the level test at the walk; a name that only
  // looks like a member, on a class of the caller's, is the option they wrote.
  if (v === null || v === undefined) return [];
  if (_isArray(v)) return _ARRAY_MEMBERS;
  if (_isNodeBuffer(v)) return _BUFFER_KIND_MEMBERS;
  if (util.types.isDataView(v)) return _DATAVIEW_MEMBERS;
  if (ArrayBuffer.isView(v)) return _VIEW_MEMBERS;
  if (util.types.isArrayBuffer(v)) return _ARRAYBUFFER_MEMBERS;
  if (util.types.isSharedArrayBuffer(v)) return _SHARED_MEMBERS;
  if (util.types.isRegExp(v)) return _REGEXP_MEMBERS;
  if (util.types.isWeakMap(v) || util.types.isWeakSet(v)) return _WEAK_PROTO_MEMBERS;
  if (util.types.isMap(v) || util.types.isSet(v)) return _SIZED_PROTO_MEMBERS;
  return [];
}

// The names a kind puts on the value itself rather than on its prototype, which are structure the
// same way an array's `length` is: `opts.lastIndex` on a RegExp answers with the match position
// whatever a caller meant by it, so no option can be supplied under that name.
function _isOwnStructuralName(v, k) {
  return util.types.isRegExp(v) && k === "lastIndex";
}

// The shape a member the language put there has, and a planted one does not: an accessor, a
// function, or a data property the language pinned. `Symbol.toStringTag` and `BYTES_PER_ELEMENT`
// are non-writable; `Array.prototype.length` is writable and non-configurable. A name added by
// assignment or by an ordinary defineProperty is neither, so it stays reported.
function _looksIntrinsic(d) {
  return !!d && (!!d.get || !!d.set || typeof d.value === "function" ||
                 d.writable === false || d.configurable === false);
}

// The member descriptors this realm's collection prototypes actually carry, taken at load and
// keyed by the accessor or value they hold.
//
// The name and the shape together are not enough on their own: a caller's class can extend a
// collection and define one of its own members over the top, and
// `class Opts extends Map { get size() {} }` is then an accessor named `size` on a value that is
// a Map. What tells the two apart is where the name sits, and that answers in any realm: the
// language installs a member once, so an intrinsic one is the only level of the chain carrying
// that name, while an override shadows the intrinsic still sitting above it. A name found twice
// is a caller's.
//
// Reading it that way also settles a kind this list would have to be extended for. `Float16Array`
// is on Node 24 and was not among the constructors named here, and the moment a typed array of an
// unlisted kind arrived its `BYTES_PER_ELEMENT` read as an option its caller never wrote.
function _shadowsAnother(v, k, holder) {
  var visited = new Set();
  var past = false;
  for (var o = v; o !== null && o !== undefined && !visited.has(o); o = Object.getPrototypeOf(o)) {
    visited.add(o);
    if (o === holder) { past = true; continue; }
    if (past && Object.getOwnPropertyDescriptor(o, k)) return true;
  }
  return false;
}

function _readableNames(obj) {
  var seen = Object.create(null);
  var out = [];
  // A primitive supplies no option names, and `Reflect.ownKeys` refuses one outright. The walk
  // starts above it rather than on it, so a caller who hands a number or a string where an
  // options bag belongs gets their own verb's refusal for the wrong type from the door that
  // checks types, instead of a raw TypeError from in here about a reflection method they never
  // called. `null` and `undefined` have no chain at all and stop immediately.
  var o = (obj === null || obj === undefined) ? null : Object(obj);
  // Whether the value's own `length` and indices are structure. That is true of an array and a
  // byte view and of nothing else: a Map, a Set and an ArrayBuffer have no own `length`, so
  // skipping the name there would discard one the caller had put on themselves.
  //
  // A verb reads an option by name whatever the argument's type, and `opts = []; opts.pem = true`
  // is an options bag as far as `opts.pem` is concerned, so these kinds have to work. Their
  // prototypes carry names the caller did not supply, and the per-level test below is what
  // handles those. Refusing to read the chain at all leaves a bag whose chain holds nothing
  // intrinsic unread.
  var indexedSelf = _isIndexedKind(o);
  var members = _kindMembers(o);
  // A prototype chain is finite only while it is acyclic, and a Proxy can make it otherwise.
  // While its target stays extensible a `getPrototypeOf` trap may return the proxy itself. The
  // walk therefore stops at an object it has already visited. A second lap over the same objects
  // yields no name the first did not, so the reported names stay complete. Without the test a
  // caller's argument hangs the verb before a single option has been read.
  var visited = new Set();
  while (o && !visited.has(o)) {
    visited.add(o);
    var inherited = (o !== obj);
    var above = Object.getPrototypeOf(o);
    // The root of the chain is the last level before null, which is what `Object.prototype` is.
    // Its position holds in every realm. A value built in a `vm` context or a worker thread
    // carries that realm's root above it, so an identity test against the local object misses it
    // and the foreign `__proto__` accessor reads as a name the caller supplied.
    //
    // The level has to be an inherited one. A caller's own `Object.create(null)` has no prototype
    // either, and treating the bag itself as a root skips the names they set on it.
    var atObjectProto = inherited && above === null;
    // A kind's own prototype gets no exemption as a level. Passing one over whole hides anything
    // added to it, and `Array.prototype.password = "pw"` is then invisible while `opts.password`
    // resolves, which handed `pki.key.export` an unprotected private key for `[]` as the bag.
    // Object.prototype was already read for that reason; every level is now read the same way,
    // and what a kind puts on its prototype is passed over by name below.
    //
    // Reflect.ownKeys, because Object.getOwnPropertyNames never returns a Symbol key and a
    // caller can write one. Such a name cannot answer `opts.password`, so it reaches no verb,
    // but it is still an option supplied and not read, which is the whole thing being refused.
    Reflect.ownKeys(o).forEach(function (k) {
      if (seen[k]) return;
      // The indices of an array or a byte view are its structure, whichever level they are read
      // from. Both kinds answer an integer-keyed read from their elements before any prototype is
      // consulted, so no caller can supply an option under such a name.
      if (indexedSelf && typeof k === "string" && _isArrayIndex(k)) return;
      // `length` is structure only where the language puts it on the value itself, which an array
      // does and a byte view does not. On an array it is an own non-configurable property that no
      // prototype can shadow, so `opts.length` is always the count. A byte view carries it as a
      // prototype accessor, and `class Opts extends Uint8Array { get length() {} }` shadows that
      // one: `opts.length` then answers with what the caller wrote, so it is an option they
      // supplied. Passing the name over for both kinds hid exactly that. Left to the level test
      // below, which exempts the accessor where the language installed it and reports an override.
      if (indexedSelf && k === "length" && !inherited) return;
      if (_isOwnStructuralName(obj, k)) return;
      var d = Object.getOwnPropertyDescriptor(o, k);
      // A name a built-in kind defines, on a level above the value and shaped the way the
      // language leaves it. Own is deliberately excluded: an own `detached` on a buffer shadows
      // the intrinsic getter, so `opts.detached` answers with what the caller wrote, and
      // pki.cms.sign reads an option under exactly that name.
      // A member of the value's own kind, or one sitting on a prototype the language installs
      // members on. The second is what carries `Object.create(Map.prototype)`, which holds no map
      // and inherits `size` all the same. Neither alone is enough: without the level test a class
      // of the caller's could name a getter after any kind's member and have it passed over.
      var here = _holderMembers(o);
      if (inherited && _looksIntrinsic(d) && !_shadowsAnother(obj, k, o) &&
          (here === null ? members.indexOf(k) !== -1 : here.indexOf(k) !== -1)) return;
      // Object.prototype is decided here and nowhere else. A member is one of the twelve the spec
      // names, still shaped like one: a data property holding a function, or the `__proto__`
      // accessor. Anything else on it was planted and is reported.
      //
      // The method rule below must not run on it. That rule exempts an inherited function so a
      // caller's class keeps its methods, and a planted `password` function is inherited and a
      // function, so the rule would rescue exactly the value this check exists to find. A class
      // defines its methods on its own prototype, and nothing legitimate puts one on the root.
      if (atObjectProto) {
        if (_PRISTINE_OBJECT_PROTO[k] && _looksBuiltIn(d)) return;
        seen[k] = 1;
        out.push(k);
        return;
      }
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

// The exported form of the property walk, which takes the caller's error factory like every
// other guard function.
//
// The internal walk reads the prototype chain, and reading a chain runs a `getPrototypeOf` trap,
// so a hostile one throws its own raw error out of a module whose whole contract is a typed one.
// `assertKnownKeys` and `optionsObject` refuse a Proxy before they walk; this door has to do the
// same, because a caller reaching for the names directly is exactly the caller who has not
// already checked. Taking `(E, code, label)` is what makes that possible, and it puts the one
// guard function that did not follow the family convention back inside it.
//
// @enforced-by behavioral -- a missing refusal has no rename-proof code shape; the RED vector
// (a hostile trap escaping as its own Error from this door) is the guard.
function readableNames(obj, E, code, label) {
  _refuseUnenumerable(obj, E, code, label);
  return _readableNames(obj);
}

// The indices an ordinary read on an array resolves, ascending, own and inherited.
//
// The name walk above drops every index of an indexed kind, since an index is structure rather
// than a name a caller supplied. Something still has to answer which indices there ARE, and the
// answer is not `Reflect.ownKeys`: an array consults its prototype chain for a hole, so
// `Object.setPrototypeOf([,], {0: signer})` reads `[signer]` to a `for` loop, to `forEach`, and to
// every consumer of the value, while its own keys report an empty array. A copy built from the own
// keys alone holds a hole where the original answers, which is the same divergence between the
// value checked and the value used that this family exists to close - here it silently shortens a
// signer list rather than lengthening it.
//
// Arrays only. A typed array answers a canonical index from its elements and never consults the
// chain, in bounds or out, so its indices are exactly its own. A DataView is an ordinary object
// whose numeric keys ARE caller-supplied names, and the name walk above already reports them.
//
// `length` is read off the own descriptor, which for an array is the non-configurable count the
// language maintains and no prototype can shadow. Inherited indices at or above it are left out:
// a read past `length` resolves, but no length-bounded traversal reaches it, and carrying one
// across would lengthen the copy past what the caller passed.
//
// The work stays bounded by what the value and its chain actually hold, so a caller who writes
// `a.length = 4e9` costs what a sparse array costs and not four billion steps. The walk stops at
// an object already visited for the reason the name walk does: a `getPrototypeOf` trap can hand
// back a fresh proxy forever, and a chain that never ends hangs the verb.
//
// @enforced-by behavioral -- an enumeration gap has no rename-proof code shape; the RED vector
// (a length-one array holding its only element on its prototype, copied to a hole) is the guard.
function readableIndices(obj, E, code, label) {
  _refuseUnenumerable(obj, E, code, label);
  if (!_isArray(obj)) return [];
  var own = Object.getOwnPropertyDescriptor(obj, "length");
  var limit = own ? own.value : 0;
  var seen = Object.create(null);
  var out = [];
  var visited = new Set();
  for (var o = obj; o && !visited.has(o); o = Object.getPrototypeOf(o)) {
    visited.add(o);
    Reflect.ownKeys(o).forEach(function (k) {
      if (typeof k !== "string" || !_isArrayIndex(k) || seen[k]) return;
      if (Number(k) >= limit) return;
      seen[k] = 1;
      out.push(k);
    });
  }
  return out.sort(function (a, b) { return Number(a) - Number(b); });
}

// The object kinds that are never an options bag, named so the refusal says which mistake was
// made. Buffer is handled beside the type check, being the argument-order slip.
//
// A boxed primitive is the one that has to be here rather than left to the unknown-option check.
// `new Number(0)` and `new Boolean(false)` carry no readable name at all, so nothing is reported
// and they pass as a bag with no options in it: the same silence `0` and `false` used to buy,
// one wrapper away. The rest carry names the language installed, so each is refused already; what
// they gain is a message that names the argument rather than one of the engine's own fields.
//
// Every one read off the value's slot, so a lookalike built over the prototype does not answer for
// one, a real one from a `vm` context or a worker thread does, and the value is asked nothing.
//
// That last part is the reason none of these is a type tag. `Object.prototype.toString` reads
// `Symbol.toStringTag`, which a caller can back with a getter that throws, so classifying a bag
// that way put the caller's own exception on a boundary whose contract is a typed error, and a
// caller could name any object an arguments object by writing the tag themselves.
function _notAnOptionsBag(v) {
  if (util.types.isBoxedPrimitive(v)) return "a boxed primitive";
  if (util.types.isNativeError(v)) return "an Error";
  if (util.types.isPromise(v)) return "a Promise";
  if (util.types.isArgumentsObject(v)) return "an arguments object";
  return null;
}

// Normalize a verb's options argument and return it. The order of the two steps decides whether
// the check runs on the caller's value, and returning is what makes the safe order the easy one.
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
// @enforced-by behavioral -- the defect is an ordering, which has no rename-proof code shape; the
// RED vector (a verb handed `false` accepting it as `{}`) is the guard.
function optionsObject(opts, E, code, label) {
  // No options supplied gets a bag with NO prototype, so it inherits nothing. A plain `{}` here
  // would inherit whatever Object.prototype carries, and on a runtime where that has been
  // polluted the caller is then refused for a name they never wrote. A caller who does pass `{}`
  // is a different case and keeps the refusal: `opts.password` answers on their object, so the
  // option is readable and unread, which is exactly what is being refused.
  if (opts === null || opts === undefined) return Object.create(null);
  // `typeof` asks the value nothing, so it is safe on any argument. Every question after it comes
  // once the value has been refused as a Proxy, because each one walks the prototype chain and so
  // runs a `getPrototypeOf` trap, which took this door out through the caller's own exception
  // rather than the typed one it promises.
  if (typeof opts !== "object") throw E(code, label + " must be an object");
  _refuseUnenumerable(opts, E, code, label);
  if (_isNodeBuffer(opts)) throw E(code, label + " must be an object");
  var wrong = _notAnOptionsBag(opts);
  if (wrong) throw E(code, label + ": " + wrong + " is not an options bag; pass a plain object");
  return _settle(opts, E, code, label);
}

// The caller's bag, once its option names have been shown to hold still while they are read.
//
// Reading an option can run a caller's getter, and a getter can add a name to the bag it was read
// from. `{ get format() { this.password = "pw"; return "der"; } }` shows only `format` while the
// unknown-option check runs, and grows `password` when the verb reads `format` afterwards, so the
// names that were checked are not the names the verb ends up carrying. `pki.key.export` took such
// a bag and returned a private key in the clear, which is the case the check exists to prevent.
//
// Every readable name is therefore read here, before anything is checked, and the names are taken
// again afterwards. A bag that grew or dropped one is refused, because a bag that rewrites itself
// as it is read has no set of names that can be checked at all.
//
// The bag itself is handed back, never a copy of it. Which names a caller supplied is decided by
// where they sit: own is theirs, inherited is machinery unless the chain says otherwise. Copying
// the readable ones onto a new object destroys exactly that, and every attempt to keep it turned
// into its own defect: a bare copy dropped `pki.path.build`'s inherited `transport` and sent the
// verb to the network the caller meant to replace, and a copy built over the original inherited
// native accessors onto a receiver with no slot behind them, so an `ArrayBuffer` options bag
// raised a raw TypeError from `opts.detached`.
//
// An accessor cannot be one, and that is the whole rule: a getter answers a different question
// every time it is asked, so a name checked once says nothing about what the verb reads next.
//
// Every narrower attempt to keep them was measured and each carried its own defect. Reading once
// and re-taking the names catches a getter that mutates immediately and misses one that waits for
// a later read. Freezing the bag closes that and then throws a raw TypeError on a non-empty typed
// array, which cannot be frozen at all, while still leaving a mutable PROTOTYPE for an inherited
// getter to grow. Copying the bag instead loses which names were the caller's own, drops an
// inherited option a verb reads, and leaves a native accessor on a receiver with no slot for it.
//
// Refusing is the one rule with nothing behind it. A plain object, a class instance with methods,
// a collection, a bag from another realm are all still options bags; what is asked is that the
// options themselves be values. The names are read once even so, since an accessor can hide on a
// prototype and this is where that gets found.
// The descriptor a name resolves to, from wherever on the chain it is found. Only the first
// level carrying it matters, since that is the one a read reaches.
function _descriptorHolder(v, k) {
  var visited = new Set();
  for (var o = v; o !== null && o !== undefined && !visited.has(o); o = Object.getPrototypeOf(o)) {
    visited.add(o);
    var d = Object.getOwnPropertyDescriptor(o, k);
    if (d) return d;
  }
  return null;
}

// refuseAccessorFields(obj, names, E, code, label) -> undefined | throws E(code, msg)
//
// Every door that decides what a caller supplied asks this, because a door that reads an accessor
// before another door checks for one leaves nothing behind to find: guard.bytes.snapshotDeep runs
// a spec's getters while copying and writes what they returned as plain data, so the option check
// that follows sees values and cannot tell there was ever an accessor there.
//
// @enforced-by behavioral -- reading an accessor before it is refused has no rename-proof code
// shape; the RED vectors (a getter on an options bag and on a signing spec) are the guard.
function refuseAccessorFields(obj, names, E, code, label) {
  for (var i = 0; i < names.length; i++) {
    var holder = _descriptorHolder(obj, names[i]);
    if (holder && (holder.get || holder.set)) {
      throw E(code, label + " supplies " +
        JSON.stringify(typeof names[i] === "symbol" ? String(names[i]) : names[i]) +
        " through an accessor, whose value can differ between the check and the read; pass an " +
        "object whose fields are plain values");
    }
  }
}

function _settle(opts, E, code, label) {
  // A caller's accessor can throw, and that fault gets this boundary's typed code rather than
  // escaping as itself from a verb the caller called for something else.
  function readAll(names) {
    for (var i = 0; i < names.length; i++) {
      try { void opts[names[i]]; }
      catch (_e) {
        throw E(code, label + ": reading " +
          JSON.stringify(typeof names[i] === "symbol" ? String(names[i]) : names[i]) + " threw");
      }
    }
  }
  var before = _readableNames(opts);
  refuseAccessorFields(opts, before, E, code, label);
  readAll(before);
  var after = _readableNames(opts);
  var same = after.length === before.length;
  for (var j = 0; same && j < after.length; j++) same = before.indexOf(after[j]) !== -1;
  if (!same) {
    throw E(code, label + " changes which options it carries while they are read, so no set of " +
      "them can be checked; pass an object whose properties are plain values");
  }
  return opts;
}

module.exports = {
  assertCanonicalOid: assertCanonicalOid,
  assertKnownKeys: assertKnownKeys,
  optionsObject: optionsObject,
  refuseAccessorFields: refuseAccessorFields,
  // Exported so a caller that forwards an options bag copies the same surface this module
  // accepts. A narrower enumeration such as `Object.keys` admits a name here and then drops
  // it on the way, which is worse than refusing it. The option is reported valid and then
  // does nothing at the place it was meant to act.
  readableNames: readableNames,
  // Exported for the same reason as its sibling: a caller copying an array has to reach the
  // elements a read reaches, and the own keys are not that set.
  readableIndices: readableIndices
};
