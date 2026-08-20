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

module.exports = {
  uncurry: uncurry,
  types: _types,
  isArray: _isArray,
  bufferFrom: _bufferFrom,
  bufferAlloc: _bufferAlloc,
  bufferConcat: _bufferConcat,
  isBuffer: _bufferIsBuffer,
  byteLength: _bufferByteLength,
  compare: _bufferCompare,
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
};
