// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var _utilTypes = require("util").types;
var _nodeCrypto = require("node:crypto");

var _call = Function.prototype.call;
var _bind = Function.prototype.bind;
var _reflectApply = Reflect.apply;

var _isArray = Array.isArray;

var _bufferFrom = Buffer.from;
var _bufferAlloc = Buffer.alloc;
var _bufferConcat = Buffer.concat;
var _bufferIsBuffer = Buffer.isBuffer;
var _bufferByteLength = Buffer.byteLength;
var _bufferCompare = Buffer.compare;
var _bufferEquals = uncurry(Buffer.prototype.equals);
var _bufferToString = uncurry(Buffer.prototype.toString);
/** @internal Key identity, taken off the KeyObject prototype at load. A caller that replaced this
 * method could make two different keys answer as one, which is the question a proof of possession
 * turns on. */
var _keyEquals = uncurry(_nodeCrypto.KeyObject.prototype.equals);

var _isView = ArrayBuffer.isView;
var _isInteger = Number.isInteger;
var _isSafeInteger = Number.isSafeInteger;
var _numberIsFinite = Number.isFinite;
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
var _parseInt = parseInt;
/** @internal The promise constructor itself, captured at load. `Promise.resolve` and `Promise.reject`
 *  are captured below, but they build their promise from the RECEIVER they are called on, so reading
 *  the global binding at the call hands the construction to whatever that binding holds. A verdict
 *  returned as `Promise.resolve(false)` from a hostile constructor is not a refusal. */
var _Promise = Promise;
var _promiseResolve = Promise.resolve;
var _promiseReject = Promise.reject;
/** @internal The aggregators, captured alongside them. `all` is what assembles a verdict out of
 *  component results, so a replacement that resolves a fabricated array never awaits the components
 *  and hands its own values to the caller as the verdict. All four are captured together: a member
 *  with no captured form is a member that stays live. */
var _promiseAll = Promise.all;
var _promiseAllSettled = Promise.allSettled;
var _promiseRace = Promise.race;
var _promiseAny = Promise.any;
/** @internal The factory methods, captured for the same reason. `withResolvers` hands back the resolve
 *  and reject capability for a promise it built, and `try` decides whether the callback runs at all, so
 *  a replacement of either chooses what the caller goes on to settle or never settles. Both are
 *  present on the supported runtime floor. */
var _promiseTry = Promise["try"];
var _promiseWithResolvers = Promise.withResolvers;
/** @internal The URL parser, captured for the reason the promise constructor is: what it returns names
 *  the host a request is sent to. A replacement installed while a call is in flight answers with a
 *  genuine URL of its own, and an endpoint built from that answer reaches a host the caller never
 *  wrote while the url the caller passed is still the one the call reports. `canParse` is captured
 *  beside it because a module that decides a form with it is deciding from the same binding. */
var _URL = URL;
var _urlCanParse = URL.canParse;
/** @internal And its accessors, because capturing a constructor does not capture the prototype the
 *  value it returns reads through. MEASURED: with the constructor captured, a header getter that
 *  redefined `URL.prototype.href` had every request go to the host its own getter named while the url
 *  the caller passed was still the one the call reported. The parts of a destination are read through
 *  these, and the two that build an endpoint are written through the captured setters. */
var _urlHref = getter(URL.prototype, "href", "URL.prototype");
var _urlOrigin = getter(URL.prototype, "origin", "URL.prototype");
var _urlProtocol = getter(URL.prototype, "protocol", "URL.prototype");
var _urlPathname = getter(URL.prototype, "pathname", "URL.prototype");
var _urlSearch = getter(URL.prototype, "search", "URL.prototype");
var _urlHostname = getter(URL.prototype, "hostname", "URL.prototype");
var _urlPort = getter(URL.prototype, "port", "URL.prototype");
var _urlUsername = getter(URL.prototype, "username", "URL.prototype");
var _urlPassword = getter(URL.prototype, "password", "URL.prototype");
var _urlSearchParams = getter(URL.prototype, "searchParams", "URL.prototype");
var _urlSetPathname = setter(URL.prototype, "pathname", "URL.prototype");
var _urlSetSearch = setter(URL.prototype, "search", "URL.prototype");
var _asyncIterator = Symbol.asyncIterator;

var _arrForEach = uncurry(Array.prototype.forEach);
var _arrMap = uncurry(Array.prototype.map);
var _arrFilter = uncurry(Array.prototype.filter);
var _arrEvery = uncurry(Array.prototype.every);
var _arrSome = uncurry(Array.prototype.some);
var _arrIndexOf = uncurry(Array.prototype.indexOf);
/** @internal The in-place sort, captured at load. A DER SET OF is ordered by its encoded bytes, so the
 *  sort decides the bytes emitted: MEASURED, a replaced `slice` or `sort` made an attribute set encode a
 *  member other than the one that was validated, on a path whose output is then signed. */
var _arrSort = uncurry(Array.prototype.sort);
var _arrConcat = uncurry(Array.prototype.concat);
var _arrSlice = uncurry(Array.prototype.slice);
var _arrJoin = uncurry(Array.prototype.join);
var _arrPush = uncurry(Array.prototype.push);
/** @internal The mutators. A list is what a rule is enforced over, so an operation that drops or moves
 *  an element decides whether the rule reaches it: a replaced `pop` that popped twice took a signed
 *  note's last signature line away with the empty tail element, and the forged signature on that line
 *  was never checked. */
var _arrPop = uncurry(Array.prototype.pop);
var _arrShift = uncurry(Array.prototype.shift);
var _arrUnshift = uncurry(Array.prototype.unshift);
var _arrSplice = uncurry(Array.prototype.splice);
var _arrReverse = uncurry(Array.prototype.reverse);

var _strToUpperCase = uncurry(String.prototype.toUpperCase);
var _strToLowerCase = uncurry(String.prototype.toLowerCase);
var _strIndexOf = uncurry(String.prototype.indexOf);
var _taSubarray = uncurry(Uint8Array.prototype.subarray);
var _abSlice = uncurry(ArrayBuffer.prototype.slice);
var _numToString = uncurry(Number.prototype.toString);
var _bigIntToString = uncurry(BigInt.prototype.toString);

var _setAdd = uncurry(Set.prototype.add);
var _setHas = uncurry(Set.prototype.has);
var _mapGet = uncurry(Map.prototype.get);
var _mapSet = uncurry(Map.prototype.set);
var _mapHas = uncurry(Map.prototype.has);
var _weakGet = uncurry(WeakMap.prototype.get);
var _weakSet = uncurry(WeakMap.prototype.set);
var _weakHas = uncurry(WeakMap.prototype.has);
var _taSet = uncurry(Uint8Array.prototype.set);
var _hasOwn = uncurry(Object.prototype.hasOwnProperty);
var _String = String;
var _Number = Number;
var _Boolean = Boolean;
var _BigInt = BigInt;
var _Date = Date;
var _dateParse = Date.parse;
var _numberIsNaN = Number.isNaN;
var _isFinite = globalThis.isFinite;
var _ArrayBuffer = ArrayBuffer;
var _Uint8Array = Uint8Array;
var _DataView = DataView;
var _ObjectFn = Object;
var _ObjectProto = Object.prototype;
var _BufferProto = Buffer.prototype;
var _ArrayProto = Array.prototype;
var _FunctionProto = Function.prototype;
var _Set = Set;
var _Map = Map;
var _WeakMap = WeakMap;

var _types = Object.create(null);
var _typeNames = Object.getOwnPropertyNames(_utilTypes);
for (var _i = 0; _i < _typeNames.length; _i++) {
  if (typeof _utilTypes[_typeNames[_i]] === "function") {
    _types[_typeNames[_i]] = _utilTypes[_typeNames[_i]];
  }
}
Object.freeze(_types);

// @enforced-by guard-shape-reinlined
// @guard-shape \b_[A-Za-z][A-Za-z0-9_$]*\.(?:call|apply)\s*\(
function uncurry(fn) {
  if (typeof fn !== "function") {
    throw new TypeError("guard.intrinsic.uncurry: expects the captured function, got " + typeof fn);
  }
  return _reflectApply(_bind, _call, [fn]);
}

// @enforced-by behavioral -- reading a descriptor's `get` is not distinguishable from testing one
function getter(proto, name, who) {
  var d = _getOwnPropertyDescriptor(proto, name);
  if (!d || typeof d.get !== "function") {
    throw new TypeError("guard.intrinsic.getter: this runtime has no intrinsic " + who + "." +
      name + " accessor, so the value's own would have to be invoked instead");
  }
  return uncurry(d.get);
}

/** @internal The write half of the same question: a replaced setter can drop the write and leave the
 *  value it was given to change unchanged. */
// @enforced-by behavioral -- reading a descriptor's `set` is not distinguishable from testing one
function setter(proto, name, who) {
  var d = _getOwnPropertyDescriptor(proto, name);
  if (!d || typeof d.set !== "function") {
    throw new TypeError("guard.intrinsic.setter: this runtime has no intrinsic " + who + "." +
      name + " accessor, so the value's own would have to be invoked instead");
  }
  return uncurry(d.set);
}

var _taByteLength = getter(_getPrototypeOf(Uint8Array.prototype), "byteLength", "%TypedArray%.prototype");
var _dvByteLength = getter(DataView.prototype, "byteLength", "DataView.prototype");

// @enforced-by behavioral -- `x.length` on a byte view is the same three tokens as on a string or
function sizeOf(value) {
  if (typeof value === "string") return value.length;
  if (_types.isDataView(value)) return _dvByteLength(value);
  if (_types.isTypedArray(value)) return _taByteLength(value);
  throw new TypeError("guard.intrinsic.sizeOf: expects a string or a byte view, got " +
    (value === null ? "null" : typeof value));
}

module.exports = Object.freeze({
  uncurry: uncurry,
  getter: getter,
  sizeOf: sizeOf,
  types: _types,
  isArray: _isArray,
  bufferFrom: _bufferFrom,
  bufferAlloc: _bufferAlloc,
  bufferConcat: _bufferConcat,
  bufToString: _bufferToString,
  isBuffer: _bufferIsBuffer,
  byteLength: _bufferByteLength,
  compare: _bufferCompare,
  bufferEquals: _bufferEquals,
  keyEquals: _keyEquals,
  isView: _isView,
  isInteger: _isInteger,
  isSafeInteger: _isSafeInteger,
  numberIsFinite: _numberIsFinite,
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
  pop: _arrPop,
  shift: _arrShift,
  unshift: _arrUnshift,
  splice: _arrSplice,
  reverse: _arrReverse,
  toUpperCase: _strToUpperCase,
  toLowerCase: _strToLowerCase,
  stringIndexOf: _strIndexOf,
  subarray: _taSubarray,
  arrayBufferSlice: _abSlice,
  numberToString: _numToString,
  bigIntToString: _bigIntToString,
  Promise: _Promise,
  promiseResolve: _promiseResolve,
  promiseReject: _promiseReject,
  promiseAll: _promiseAll,
  promiseAllSettled: _promiseAllSettled,
  promiseRace: _promiseRace,
  promiseAny: _promiseAny,
  promiseTry: _promiseTry,
  promiseWithResolvers: _promiseWithResolvers,
  setter: setter,
  URL: _URL,
  urlCanParse: _urlCanParse,
  urlHref: _urlHref,
  urlOrigin: _urlOrigin,
  urlProtocol: _urlProtocol,
  urlPathname: _urlPathname,
  urlSearch: _urlSearch,
  urlHostname: _urlHostname,
  urlPort: _urlPort,
  urlUsername: _urlUsername,
  urlPassword: _urlPassword,
  urlSearchParams: _urlSearchParams,
  urlSetPathname: _urlSetPathname,
  urlSetSearch: _urlSetSearch,
  asyncIterator: _asyncIterator,
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
  apply: _reflectApply,
  promiseFinally: uncurry(Promise.prototype["finally"]),
  String: _String,
  Number: _Number,
  Boolean: _Boolean,
  BigInt: _BigInt,
  Date: _Date,
  dateParse: _dateParse,
  numberIsNaN: _numberIsNaN,
  isFinite: _isFinite,
  ArrayBuffer: _ArrayBuffer,
  Uint8Array: _Uint8Array,
  DataView: _DataView,
  Object: _ObjectFn,
  ObjectProto: _ObjectProto,
  BufferProto: _BufferProto,
  ArrayProto: _ArrayProto,
  FunctionProto: _FunctionProto,
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
