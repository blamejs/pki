// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is every guard that composes
// this one, which is every guard that performs its work with a captured intrinsic: guard-bytes
// (the byte-source door), guard-time (the evaluation instant), guard-name (distinguished-name
// identity), guard-text (the byte-to-string decode), guard-secret (the wipe).
//
// guard-intrinsic -- invoke a captured method against a receiver without reading any property of
// the captured function.
//
// Capturing a method at module load closes half of the hole. `var _fill =
// Uint8Array.prototype.fill` freezes which function the guard will run, so a later
// `Uint8Array.prototype.fill = noop` changes nothing. Then `_fill.call(view, 0)` reads `call` off
// that function object, and the object is the one still sitting on the prototype where any caller
// can reach it. Assigning `Uint8Array.prototype.fill.call = function () {}` installs an own
// property that shadows `Function.prototype.call`, and the guard runs the caller's function with
// the same result the un-captured code had. The wipe clears nothing. A distinguished name compares
// equal to an unrelated one. A decode returns a string the caller chose. Every check around it
// still runs and still passes.
//
// The uncurried form performs no property read at the call site. `_fill(view, 0)` invokes a
// function object no caller holds a reference to, so nothing on it is left to poison. The binding
// happens here, at load, while `Function.prototype.call` and `.bind` are still the language's own.
//
// The scope of the defense is replacement that happens after this module loads. Code running
// before it is already inside the trust boundary and can reach further than any single method, so
// there is no defense here to add for that case. What capture-then-uncurry buys is that a caller
// who receives control later, through an option accessor or while a verb is suspended on an await,
// cannot change what a guard does.

var _utilTypes = require("util").types;

var _call = Function.prototype.call;
var _bind = Function.prototype.bind;
// The invocation primitive `uncurry` itself is built out of. Binding as `_bind.call(_call, fn)`
// would read `call` off the captured bind function, which is the very shape this module exists to
// remove -- and `uncurry` is exported, so it can run long after load, while another guard
// initializes. `Reflect.apply` is invoked directly, so no property of it is consulted either.
var _reflectApply = Reflect.apply;

// isArray -- the array test, snapshotted for the same reason as the predicates below. It decides
// whether a value is walked as a list at all, so one answering `false` makes an index scan report
// nothing and every rule keyed on what that scan found silently applies to nothing.
var _isArray = Array.isArray;

// The Buffer constructors, snapshotted for the same reason. `Buffer.from` is a writable property
// of the `Buffer` global and it is how this toolkit turns a backing store into something it can
// read or clear; one returning a buffer over DIFFERENT memory hands every later step a decoy, so a
// wipe zeroes the decoy while the plaintext it was aimed at stays readable.
var _bufferFrom = Buffer.from;
var _bufferAlloc = Buffer.alloc;
var _bufferConcat = Buffer.concat;
var _bufferIsBuffer = Buffer.isBuffer;
var _bufferByteLength = Buffer.byteLength;
var _bufferCompare = Buffer.compare;
// `Buffer.prototype.equals` is the byte-identity test a binding decides on: an OCSP CertID says the
// response is about this issuer, a responder ID says this key signed it. Dispatched live, one
// answering true makes a response about a DIFFERENT certificate match the one being asked about.
var _bufferEquals = uncurry(Buffer.prototype.equals);

// The rest of what a guard reads from the runtime while it is deciding something. These are
// grouped here rather than captured file by file so the set is enumerable in one place and a guard
// added later inherits it: a reader asking "what can a caller still reach" has one list to read.
//
// The reflective operations are the load-bearing ones. `getOwnPropertyDescriptor` is how the
// identifier guard learns whether a field is an accessor, `getPrototypeOf` and `ownKeys` are how it
// walks a chain honestly, and `isView` is how the byte guard recognizes the shape whose backing
// store it must refuse when shared. A replacement for any of them answers the question the guard
// asked on the caller's behalf.
var _isView = ArrayBuffer.isView;
var _isInteger = Number.isInteger;
var _isSafeInteger = Number.isSafeInteger;
var _fromCharCode = String.fromCharCode;
var _objectCreate = Object.create;
var _getPrototypeOf = Object.getPrototypeOf;
var _setPrototypeOf = Object.setPrototypeOf;
var _getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var _getOwnPropertyNames = Object.getOwnPropertyNames;
var _defineProperty = Object.defineProperty;
var _objectKeys = Object.keys;
var _objectAssign = Object.assign;
var _objectFreeze = Object.freeze;
var _isExtensible = Object.isExtensible;
var _ownKeys = Reflect.ownKeys;
var _jsonStringify = JSON.stringify;
var _mathFloor = Math.floor;
var _mathCeil = Math.ceil;
var _mathMin = Math.min;
var _mathMax = Math.max;
// A numeric parse a bound is then compared against: one answering a larger value widens the bound
// the comparison was written to enforce.
var _parseInt = parseInt;
var _promiseResolve = Promise.resolve;
var _promiseReject = Promise.reject;

// The array operations, uncurried at load. These run on arrays the TOOLKIT owns -- an `ownKeys`
// result, a local accumulator -- so the receiver is never a caller's object; what is caller-
// reachable is `Array.prototype` itself. A `forEach` replaced with a no-op makes a scan over
// perfectly real keys report nothing, and a check keyed on what that scan found then passes
// vacuously, which is the same fail-open shape as an index test that answers `false`.
var _arrForEach = uncurry(Array.prototype.forEach);
var _arrMap = uncurry(Array.prototype.map);
var _arrFilter = uncurry(Array.prototype.filter);
var _arrEvery = uncurry(Array.prototype.every);
var _arrSome = uncurry(Array.prototype.some);
var _arrIndexOf = uncurry(Array.prototype.indexOf);
var _arrSort = uncurry(Array.prototype.sort);
var _arrConcat = uncurry(Array.prototype.concat);
var _arrSlice = uncurry(Array.prototype.slice);
var _arrJoin = uncurry(Array.prototype.join);
var _arrPush = uncurry(Array.prototype.push);

// The string and byte-view operations a decision is then made on. A `toUpperCase` or `toLowerCase`
// replaced after load changes which registry row an algorithm name resolves to; a `subarray`
// returning a different window hands the next step bytes from somewhere else in the same buffer;
// and a radix conversion is how a key's own numbers are read back before they are compared.
var _strToUpperCase = uncurry(String.prototype.toUpperCase);
var _strToLowerCase = uncurry(String.prototype.toLowerCase);
var _strIndexOf = uncurry(String.prototype.indexOf);
var _taSubarray = uncurry(Uint8Array.prototype.subarray);
var _abSlice = uncurry(ArrayBuffer.prototype.slice);
var _numToString = uncurry(Number.prototype.toString);
var _bigIntToString = uncurry(BigInt.prototype.toString);

// The collection operations, uncurried. A guard's cycle-safe chain walk is a `Set` it owns, and
// `has` is what stops it: one answering `true` ends the walk at the first prototype, so a scan that
// should have found an accessor two levels up reports nothing and the rule keyed on it passes. The
// registry lookups are the same shape from the other side -- a `get` that answers for a key never
// stored hands a guard a member list for an object it has never seen.
var _setAdd = uncurry(Set.prototype.add);
var _setHas = uncurry(Set.prototype.has);
var _mapGet = uncurry(Map.prototype.get);
var _mapSet = uncurry(Map.prototype.set);
var _mapHas = uncurry(Map.prototype.has);
var _weakGet = uncurry(WeakMap.prototype.get);
var _weakSet = uncurry(WeakMap.prototype.set);
var _weakHas = uncurry(WeakMap.prototype.has);
var _taSet = uncurry(Uint8Array.prototype.set);
// Own-membership, which is how this toolkit asks whether a key is really in a table rather than
// inherited from a prototype somebody extended. Spelled `Object.prototype.hasOwnProperty.call(t, k)`
// it reads two replaceable properties to answer one question, and either of them answering yes puts
// a name into an allowlist that never contained it.
var _hasOwn = uncurry(Object.prototype.hasOwnProperty);
// The conversions, which are globals and so ordinary writable properties of globalThis. They read
// like language rather than like code, which is why they were the last of these to be noticed: an
// index test is `String(Number(k)) === k`, a narrow is `Number(v)`, and a header value is
// `String(value)` before it is scanned for injection. A replacement decides all three.
var _String = String;
var _Number = Number;
var _Boolean = Boolean;
var _BigInt = BigInt;
var _Date = Date;
var _isFinite = globalThis.isFinite;
// The byte-view constructors, for the same reason: a private copy is only private if the store and
// the view over it are the ones this code asked for. A replaced constructor hands back a view over
// storage of its own choosing, while the cleanup still tracks the store that was allocated.
var _ArrayBuffer = ArrayBuffer;
var _Uint8Array = Uint8Array;
var _DataView = DataView;
// Boxing a primitive, which decides what a reflection scan then sees.
var _ObjectFn = Object;
// The prototype OBJECTS, used as identity sentinels: "is this a plain object", "is this a Buffer",
// "has the chain walk reached the top". Each is reached as a property of a replaceable global, so
// after a replacement the sentinel is a different object and every comparison against it is false.
var _ObjectProto = Object.prototype;
var _BufferProto = Buffer.prototype;
var _ArrayProto = Array.prototype;
var _Set = Set;
var _Map = Map;
var _WeakMap = WeakMap;

// types -- the slot predicates, snapshotted at load.
//
// `util.types` is an ordinary object on an ordinary module export, so `util.types.isDate = () =>
// true` reaches every guard that asks it at call time. These predicates are how this toolkit
// answers "what IS this value", in preference to a prototype test a caller can satisfy, so a
// caller who gets to answer them instead has replaced the one question a lookalike cannot lie
// about. Every own function property is carried across rather than a written-out list, because a
// list is a thing to get wrong and a predicate added by a later runtime would silently be missing
// from it.
var _types = Object.create(null);
var _typeNames = Object.getOwnPropertyNames(_utilTypes);
for (var _i = 0; _i < _typeNames.length; _i++) {
  if (typeof _utilTypes[_typeNames[_i]] === "function") {
    _types[_typeNames[_i]] = _utilTypes[_typeNames[_i]];
  }
}
Object.freeze(_types);

// uncurry(fn) -> function (receiver, ...args) { return fn.call(receiver, ...args); }
//   fn : the intrinsic captured from a prototype, or an intrinsic getter function.
//
// The returned function is private to whichever module called `uncurry`, so no property of it is
// reachable from outside.
//
// A `.call` on a captured intrinsic is the shape this replaces. It reads as safe while being as
// reachable as the un-captured method was, so it is flagged anywhere in lib/, including a guard
// not yet written. The safe spelling is also the tripwire for the next one.
// @enforced-by guard-shape-reinlined
// @guard-shape \b_[A-Za-z][A-Za-z0-9_$]*\.(?:call|apply)\s*\(
function uncurry(fn) {
  if (typeof fn !== "function") {
    throw new TypeError("guard.intrinsic.uncurry: expects the captured function, got " + typeof fn);
  }
  return _reflectApply(_bind, _call, [fn]);
}

// getter(proto, name, who) -> the prototype's own accessor, uncurried.
//   proto : the intrinsic prototype the accessor lives on.
//   name  : the accessor's property name.
//   who   : how the prototype is named in the refusal, for a runtime that has no such accessor.
//
// A view's size, offset and backing store are accessors on a prototype, which means they are
// replaceable, which means every rule keyed on one is answerable by whoever replaced it. Taking the
// descriptor's `get` at load and uncurrying it reads the value's own slot and consults nothing.
// A runtime without the accessor is refused rather than fallen back from: a fallback here would be
// the value's own `length`, which is the property this exists to stop reading.
// @enforced-by behavioral -- reading a descriptor's `get` is not distinguishable from testing one
//   for presence (`!!d.get`, which four guards do legitimately), so a lexical detector would
//   false-fire on every accessor-shape check in the tree; the vectors that replace an accessor and
//   drive the composing guard are the guard. The `.call` half of the shape is covered by uncurry's
//   guard-shape-reinlined detector.
function getter(proto, name, who) {
  var d = _getOwnPropertyDescriptor(proto, name);
  if (!d || typeof d.get !== "function") {
    throw new TypeError("guard.intrinsic.getter: this runtime has no intrinsic " + who + "." +
      name + " accessor, so the value's own would have to be invoked instead");
  }
  return uncurry(d.get);
}

var _taByteLength = getter(_getPrototypeOf(Uint8Array.prototype), "byteLength", "%TypedArray%.prototype");
var _dvByteLength = getter(DataView.prototype, "byteLength", "DataView.prototype");

// sizeOf(value) -> how large the value is: a string's character count, a view's byte count.
//
// The size of an input decides a cap, a bound, an emptiness gate and a loop end all over this
// toolkit, and `value.length` asks the prototype for it. On a view that property is a replaceable
// accessor: one reporting a small number for a large buffer disables every size cap at once, and
// one reporting a positive number for an empty buffer passes an empty secret, an empty DER element
// and an empty name through the gates that exist to refuse them. So a view is measured from its
// slot, and a DataView carries its own accessor rather than the typed-array one.
//
// A primitive string's `length` is a data property the language maintains and no code can redefine,
// so the string arm reads it directly. The two arms are one function because a size comparison
// should have one spelling: a second way to measure is a second thing to get wrong, and the arm
// that gets skipped is the one that was replaceable. Anything that is neither is refused rather
// than measured, since its `length` would be whatever its author wrote.
// @enforced-by behavioral -- `x.length` on a byte view is the same three tokens as on a string or
//   an array, where the read is safe and ubiquitous, and the receiver's kind is not knowable
//   statically in this codebase's style; a detector would flag every array bound in the tree. The
//   over-cap and control-byte vectors under a replaced accessor are the guard.
function sizeOf(value) {
  if (typeof value === "string") return value.length;
  if (_types.isDataView(value)) return _dvByteLength(value);
  if (_types.isTypedArray(value)) return _taByteLength(value);
  throw new TypeError("guard.intrinsic.sizeOf: expects a string or a byte view, got " +
    (value === null ? "null" : typeof value));
}

// Frozen, and that is what makes the capture worth taking. A consumer binds these at load, but it
// also reads several of them as `intrinsic.<name>(...)` at the call itself, and the module registry
// hands every caller this same object: assigning one property would redirect that call in every
// module at once, which is the substitution the captures exist to refuse. Freezing costs nothing
// here because nothing writes to it after load.
module.exports = Object.freeze({
  uncurry: uncurry,
  getter: getter,
  sizeOf: sizeOf,
  types: _types,
  isArray: _isArray,
  bufferFrom: _bufferFrom,
  bufferAlloc: _bufferAlloc,
  bufferConcat: _bufferConcat,
  isBuffer: _bufferIsBuffer,
  byteLength: _bufferByteLength,
  compare: _bufferCompare,
  bufferEquals: _bufferEquals,
  isView: _isView,
  isInteger: _isInteger,
  isSafeInteger: _isSafeInteger,
  fromCharCode: _fromCharCode,
  create: _objectCreate,
  getPrototypeOf: _getPrototypeOf,
  setPrototypeOf: _setPrototypeOf,
  getOwnPropertyDescriptor: _getOwnPropertyDescriptor,
  getOwnPropertyNames: _getOwnPropertyNames,
  defineProperty: _defineProperty,
  keys: _objectKeys,
  assign: _objectAssign,
  freeze: _objectFreeze,
  isExtensible: _isExtensible,
  ownKeys: _ownKeys,
  stringify: _jsonStringify,
  floor: _mathFloor,
  ceil: _mathCeil,
  min: _mathMin,
  max: _mathMax,
  parseInt: _parseInt,
  push: _arrPush,
  toUpperCase: _strToUpperCase,
  toLowerCase: _strToLowerCase,
  stringIndexOf: _strIndexOf,
  subarray: _taSubarray,
  arrayBufferSlice: _abSlice,
  numberToString: _numToString,
  bigIntToString: _bigIntToString,
  promiseResolve: _promiseResolve,
  promiseReject: _promiseReject,
  forEach: _arrForEach,
  map: _arrMap,
  filter: _arrFilter,
  every: _arrEvery,
  some: _arrSome,
  indexOf: _arrIndexOf,
  sort: _arrSort,
  concat: _arrConcat,
  arraySlice: _arrSlice,
  join: _arrJoin,
  hasOwn: _hasOwn,
  // Invocation itself. `fn.apply(...)` reads `apply` off Function.prototype, so a replacement
  // decides whether a verb's body runs at all and what it appears to return; `Reflect.apply` is
  // invoked directly and consults no property of the function.
  apply: _reflectApply,
  // And the cleanup half of a promise chain: `.finally` is where a copied secret is released, so a
  // replacement that drops its callback leaves the plaintext copy alive for the process's lifetime.
  promiseFinally: uncurry(Promise.prototype["finally"]),
  String: _String,
  Number: _Number,
  Boolean: _Boolean,
  BigInt: _BigInt,
  Date: _Date,
  isFinite: _isFinite,
  ArrayBuffer: _ArrayBuffer,
  Uint8Array: _Uint8Array,
  DataView: _DataView,
  Object: _ObjectFn,
  ObjectProto: _ObjectProto,
  BufferProto: _BufferProto,
  ArrayProto: _ArrayProto,
  setAdd: _setAdd,
  setHas: _setHas,
  mapGet: _mapGet,
  mapSet: _mapSet,
  mapHas: _mapHas,
  weakGet: _weakGet,
  weakSet: _weakSet,
  weakHas: _weakHas,
  typedArraySet: _taSet,
  Set: _Set,
  Map: _Map,
  WeakMap: _WeakMap,
});
