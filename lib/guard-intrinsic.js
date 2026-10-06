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
/** @internal The big-endian integer readers, captured at load. A length or a counter read out of a
 *  wire structure is what the bounds check and the slice after it are computed from, so a replaced
 *  reader decides which bytes a check runs over and which value a monotonicity rule compares. */
var _readUInt8 = uncurry(Buffer.prototype.readUInt8);
var _readUInt16BE = uncurry(Buffer.prototype.readUInt16BE);
var _readUInt32BE = uncurry(Buffer.prototype.readUInt32BE);
var _readUIntBE = uncurry(Buffer.prototype.readUIntBE);
var _writeUInt16BE = uncurry(Buffer.prototype.writeUInt16BE);
var _writeUInt32BE = uncurry(Buffer.prototype.writeUInt32BE);
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
var _isFrozen = Object.isFrozen;
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
var _urlHash = getter(URL.prototype, "hash", "URL.prototype");
var _urlHostname = getter(URL.prototype, "hostname", "URL.prototype");
var _urlPort = getter(URL.prototype, "port", "URL.prototype");
var _urlUsername = getter(URL.prototype, "username", "URL.prototype");
var _urlPassword = getter(URL.prototype, "password", "URL.prototype");
var _urlSearchParams = getter(URL.prototype, "searchParams", "URL.prototype");
var _urlSetPathname = setter(URL.prototype, "pathname", "URL.prototype");
var _urlSetSearch = setter(URL.prototype, "search", "URL.prototype");
var _urlSetHash = setter(URL.prototype, "hash", "URL.prototype");
var _asyncIterator = Symbol.asyncIterator;

var _arrForEach = uncurry(Array.prototype.forEach);
var _arrMap = uncurry(Array.prototype.map);
var _arrFilter = uncurry(Array.prototype.filter);
var _arrEvery = uncurry(Array.prototype.every);
var _arrSome = uncurry(Array.prototype.some);
var _arrIndexOf = uncurry(Array.prototype.indexOf);
/** @internal The fold, captured at load. A fold is how a sequence of checks is chained into one verdict,
 *  so a replacement that returns its seed without visiting an element answers for a sequence it never
 *  walked. */
var _arrReduce = uncurry(Array.prototype.reduce);
/** @internal The append these three build with. `push` is not usable for it: it writes through Set,
 *  which WALKS THE PROTOTYPE for a numeric setter, so an accessor installed at `Array.prototype[0]`
 *  takes the value and leaves no own property on the array at all, and the index then reads back as
 *  whatever its getter answers. MEASURED: a fresh literal appended to with `push` held no own index
 *  `0` and read as the getter's value. `defineProperty` consults no setter, which is the same reason
 *  `guard.list.append` is written this way. */
function _appendOwn(out, i, value) {
  _defineProperty(out, i, { value: value, writable: true, enumerable: true, configurable: true });
}
var _strCharCodeAt = uncurry(String.prototype.charCodeAt);
var _strSliceOwn = uncurry(String.prototype.slice);
/** @internal A split on ONE delimiter character, scanned rather than dispatched.
 *  `String.prototype.split` is specified to look the separator's `Symbol.split` method up and call
 *  it (ES2015 21.1.3.19 step 2), so the separator's prototype chain is part of the operation and a
 *  capture of `split` does not close it. Hard rule 11 bans `split` in `lib/` for exactly that
 *  reason. MEASURED on Node 26: V8 fast-paths a primitive-string separator and does NOT perform
 *  that lookup, so none of `String.prototype[Symbol.split]`, `Object.prototype[Symbol.split]` or a
 *  replaced `String.prototype.split` changes what the captured call returns. This scan does not
 *  depend on that optimisation holding. `charCodeAt` and `slice` carry no such protocol.
 *  The delimiter is a CHARACTER CODE, not a string, so there is no separator object to consult. */
// @enforced-by behavioral -- vectors pin the delimiter cases and record the runtime's fast path
function splitChar(s, code) {
  var out = [];
  var n = s.length, start = 0, k = 0;
  for (var i = 0; i < n; i++) {
    if (_strCharCodeAt(s, i) === code) { _appendOwn(out, k++, _strSliceOwn(s, start, i)); start = i + 1; }
  }
  _appendOwn(out, k, _strSliceOwn(s, start, n));
  return out;
}
/** @internal The element count, refusing anything but a real array. An array's `length` is an OWN
 *  data property, so reading it consults nothing; an array-LIKE answers from wherever its own
 *  descriptor says, and a typed array answers from an accessor on `%TypedArray%.prototype` that a
 *  caller can redefine, which would report zero and empty every result below. The four verbs are for
 *  lists, so the narrow argument is the honest contract rather than a length read taken on trust;
 *  `guard.list.append` refuses a non-array for the same reason. */
function _ownLength(list, who) {
  if (!_isArray(list)) throw new TypeError("intrinsic." + who + ": the receiver must be an array");
  return list.length;
}
// @enforced-by behavioral -- a RED vector installs an Array.prototype numeric setter and pins that
/** @internal The same append, for a module that holds a list and adds to its end. `guard.list.append`
 *  is the orchestrated form of this and is preferred where `guard` is in scope; this exists for the
 *  modules that take only the intrinsic captures. */
function append(list, value) {
  _appendOwn(list, _ownLength(list, "append"), value);
  return list;
}
/** @internal A selection and a projection that consult NO construction protocol. Capturing
 *  `Array.prototype.filter` and `map` is not sufficient on its own: both build their result through
 *  ArraySpeciesCreate, which reads `constructor` off the receiver and `Symbol.species` off that, and
 *  the species descriptor is configurable. A species returning `{ length: 0 }` takes every match as
 *  an indexed property while the length stays zero, so the result reads as EMPTY, and empty is rarely
 *  inert: an empty subject-alternative-name selection sends a hostname check to its common-name
 *  fallback, an empty permitted-subtree list reads as "this issuer constrains no name of that form"
 *  and skips the check, and an empty quality-of-protection list reads as a challenge offering none.
 *  A species returning a longer object substitutes the elements instead, which is how a fabricated
 *  certificate chain or anchor set reaches a verify. These append into an array literal, which is
 *  created through no protocol. Use them wherever the result feeds a refusal.
 *
 *  There is no rename-proof code shape to detect, because `intrinsic.map` stays the right spelling
 *  wherever the result only feeds a report and is wrong only where it feeds a refusal, so a lexical
 *  detector on the call would fire across most of the tree. The guard is the conformance vector in
 *  `guard-intrinsic.test.js`, which installs a hostile `Array[Symbol.species]` and asserts in the
 *  same run that the captured operation IS steered and these are not. */
// @enforced-by behavioral -- a RED vector installs a hostile Array species and pins both outcomes
function mapList(list, fn) {
  var out = [];
  var n = _ownLength(list, "mapList");
  for (var i = 0; i < n; i++) _appendOwn(out, i, fn(list[i], i, list));
  return out;
}
// @enforced-by behavioral -- the same RED vector pins the selection form
function selectList(list, pred) {
  var out = [];
  var n = _ownLength(list, "selectList"), k = 0;
  for (var i = 0; i < n; i++) { if (pred(list[i], i, list)) _appendOwn(out, k++, list[i]); }
  return out;
}
/** @internal A copy that consults no construction protocol. `Array.prototype.slice` runs
 *  ArraySpeciesCreate like the selections above, so a species answering with an object of its own
 *  receives the elements and the length write: a copy of a certificate chain that discards them left
 *  an empty path, and an empty path reads as "nothing left to validate" where a self-presented anchor
 *  had just been stripped, so the chain reported trusted with no path validated at all. */
/** @internal A join that consults no construction protocol. `concat` reads
 *  `Symbol.isConcatSpreadable` off each operand and builds its result through ArraySpeciesCreate, so
 *  a `false` there leaves an operand NESTED inside the result where a per-element field test finds
 *  nothing to recognize, and a hostile species discards the elements outright. A join that drops an
 *  excluded-subtree list loses the exclusion, and one that drops a chain element shortens the path
 *  that gets validated. */
// @enforced-by behavioral -- the same RED vector pins the join form
function concatList(a, b) {
  var out = copyList(a);
  var k = _ownLength(a, "concatList");
  var n = _ownLength(b, "concatList");
  for (var i = 0; i < n; i++) _appendOwn(out, k + i, b[i]);
  return out;
}
// @enforced-by behavioral -- the same RED vector pins the copy form
function copyList(list, start, end) {
  var n = _ownLength(list, "copyList");
  var s = start === undefined ? 0 : (start < 0 ? (n + start < 0 ? 0 : n + start) : (start > n ? n : start));
  var e = end === undefined ? n : (end < 0 ? (n + end < 0 ? 0 : n + end) : (end > n ? n : end));
  var out = [];
  var k = 0;
  for (var i = s; i < e; i++) _appendOwn(out, k++, list[i]);
  return out;
}
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
/** @internal A WeakSet's own pair. `WeakMap.prototype.has` throws on a WeakSet receiver, so a module
 *  marking objects in a WeakSet needs these rather than the WeakMap captures above. A marker read
 *  this way is what says an object came from a verifying producer rather than from a caller. */
var _weakSetAdd = uncurry(WeakSet.prototype.add);
var _weakSetHas = uncurry(WeakSet.prototype.has);
var _taSet = uncurry(Uint8Array.prototype.set);
/** @internal The three accessors a byte view is described by, taken off `%TypedArray%.prototype`
 *  itself so none of them is read through a replaceable property at the call. */
var _taProto = _getPrototypeOf(Uint8Array.prototype);
var _taBuffer = getter(_taProto, "buffer", "%TypedArray%.prototype");
var _taByteOffset = getter(_taProto, "byteOffset", "%TypedArray%.prototype");
var _taLength = getter(_taProto, "length", "%TypedArray%.prototype");
/** @internal A byte slice that consults NO construction protocol. `subarray` runs
 *  TypedArraySpeciesCreate, which reads `constructor` off the receiver and then `Symbol.species` off
 *  that, so a hostile species returns a fabricated object in place of the slice: answering with the
 *  expected RP ID hash for a 32-byte slice made an assertion produced for another relying party
 *  satisfy `expectedRpId`, while the signature was still verified over the original bytes. This
 *  builds the view from the buffer and offset directly, which is what `subarray` would have produced
 *  and shares the same memory, so it is a drop-in for it.
 *
 *  `intrinsic.subarray` stays correct wherever the slice only feeds a length or a copy, so no
 *  rename-proof shape separates the two uses. The guard is the conformance vector in
 *  `guard-intrinsic.test.js`, which poisons a buffer's own `constructor` with a hostile species and
 *  asserts in the same run that `subarray` IS steered and this one is not. */
// @enforced-by behavioral -- a RED vector poisons a buffer's constructor and pins both outcomes
function byteSlice(buf, start, end) {
  var len = _taLength(buf);
  var s = start === undefined ? 0 : (start < 0 ? 0 : start);
  var e = end === undefined ? len : (end > len ? len : end);
  if (s > len) s = len;
  if (e < s) e = s;
  return _bufferFrom(_taBuffer(buf), _taByteOffset(buf) + s, e - s);
}
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
  readUInt8: _readUInt8,
  readUInt16BE: _readUInt16BE,
  readUInt32BE: _readUInt32BE,
  readUIntBE: _readUIntBE,
  writeUInt16BE: _writeUInt16BE,
  writeUInt32BE: _writeUInt32BE,
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
  isFrozen: _isFrozen,
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
  urlHash: _urlHash,
  urlHostname: _urlHostname,
  urlPort: _urlPort,
  urlUsername: _urlUsername,
  urlPassword: _urlPassword,
  urlSearchParams: _urlSearchParams,
  urlSetPathname: _urlSetPathname,
  urlSetSearch: _urlSetSearch,
  urlSetHash: _urlSetHash,
  asyncIterator: _asyncIterator,
  forEach: _arrForEach,
  map: _arrMap,
  filter: _arrFilter,
  every: _arrEvery,
  some: _arrSome,
  indexOf: _arrIndexOf,
  reduce: _arrReduce,
  mapList: mapList,
  selectList: selectList,
  copyList: copyList,
  concatList: concatList,
  splitChar: splitChar,
  append: append,
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
  weakSetAdd: _weakSetAdd,
  weakSetHas: _weakSetHas,
  typedArraySet: _taSet,
  byteSlice: byteSlice,
  Set: _Set,
  Map: _Map,
  WeakMap: _WeakMap,
});
