// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var _utilTypes = require("util").types;

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
var _parseInt = parseInt;
var _promiseResolve = Promise.resolve;
var _promiseReject = Promise.reject;
var _asyncIterator = Symbol.asyncIterator;

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
var _isFinite = globalThis.isFinite;
var _ArrayBuffer = ArrayBuffer;
var _Uint8Array = Uint8Array;
var _DataView = DataView;
var _ObjectFn = Object;
var _ObjectProto = Object.prototype;
var _BufferProto = Buffer.prototype;
var _ArrayProto = Array.prototype;
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
