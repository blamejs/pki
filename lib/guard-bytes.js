// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
var async = require("./guard-async");
var identifier = require("./guard-identifier");
var time = require("./guard-time");
var intrinsic = require("./guard-intrinsic");
var util = intrinsic.assign(intrinsic.create(null), { types: intrinsic.types });
var _isArray = intrinsic.isArray;
var _bufferFrom = intrinsic.bufferFrom;
var _isView = intrinsic.isView;
var _isBuffer = intrinsic.isBuffer;
var _asyncIterator = intrinsic.asyncIterator;
var _NO_ARGS = intrinsic.freeze([]);
var _create = intrinsic.create;
var _getPrototypeOf = intrinsic.getPrototypeOf;
var _getOwnPropertyDescriptor = intrinsic.getOwnPropertyDescriptor;
var _defineProperty = intrinsic.defineProperty;
var _objectKeys = intrinsic.keys;
var _isExtensible = intrinsic.isExtensible;
var _ownKeys = intrinsic.ownKeys;
var _stringify = intrinsic.stringify;
var _forEach = intrinsic.forEach;
var _map = intrinsic.map;
var _filter = intrinsic.filter;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _setForEach = intrinsic.uncurry(Set.prototype.forEach);
var _mapForEach = intrinsic.uncurry(Map.prototype.forEach);
var _String = intrinsic.String;
var _Date = intrinsic.Date;
var _apply = intrinsic.apply;
var _promiseFinally = intrinsic.promiseFinally;
var _ArrayBuffer = intrinsic.ArrayBuffer;
var _Uint8Array = intrinsic.Uint8Array;
var _DataView = intrinsic.DataView;
var _ObjectProto = intrinsic.ObjectProto;
var _setAdd = intrinsic.setAdd;
var _setHas = intrinsic.setHas;
var _mapSet = intrinsic.mapSet;
var _taSet = intrinsic.typedArraySet;
var _Set = intrinsic.Set;
var _Map = intrinsic.Map;
var _append = require("./guard-list").append;

function _ownArrayIndices(v, n) {
  var keys = _ownKeys(v);
  var out = [];
  for (var j = 0; j < keys.length; j++) {
    var k = keys[j];
    if (typeof k !== "string") continue;
    var ix = k >>> 0;
    if (_String(ix) === k && ix !== 0xFFFFFFFF && ix < n) _append(out, k);
  }
  return out;
}

// @enforced-by behavioral -- a narrowed restatement of a list has no rename-proof code shape;
function isByteSource(x) {
  return _isBuffer(x) || _isView(x) || _isArrayBuffer(x);
}

// @enforced-by behavioral -- a lazy stream wrapper has no rename-proof code shape; the RED vectors (a
function asyncStreamOf(x) {
  if (isByteSource(x) || x == null || (typeof x !== "object" && typeof x !== "function")) return null;
  var acquire = x[_asyncIterator];
  if (typeof acquire !== "function") return null;
  var stream = {};
  stream[_asyncIterator] = function () { return _apply(acquire, x, _NO_ARGS); };
  return stream;
}

function translateStreamError(e, E, code) {
  if (e && e.code === "webcrypto/data") throw E(code, "a streamed content chunk is not a byte source", e);
  if (e && e.code === "webcrypto/syntax") throw E(code, "the streamed content is not a valid async iterable of byte chunks", e);
  throw e;
}

function _isArrayBuffer(v) {
  return util.types.isArrayBuffer(v);
}

var _TYPED_ARRAY_PROTO = _getPrototypeOf(Uint8Array.prototype);

var _uncurriedGetter = intrinsic.getter;
var _taBuffer     = _uncurriedGetter(_TYPED_ARRAY_PROTO, "buffer", "%TypedArray%.prototype");
var _taByteOffset = _uncurriedGetter(_TYPED_ARRAY_PROTO, "byteOffset", "%TypedArray%.prototype");
var _dvBuffer     = _uncurriedGetter(DataView.prototype, "buffer", "DataView.prototype");
var _dvByteOffset = _uncurriedGetter(DataView.prototype, "byteOffset", "DataView.prototype");

function _storeOf(v)  { return util.types.isDataView(v) ? _dvBuffer(v) : _taBuffer(v); }
function _offsetOf(v) { return util.types.isDataView(v) ? _dvByteOffset(v) : _taByteOffset(v); }
function _lengthOf(v) { return intrinsic.sizeOf(v); }

function _reView(v) {
  return _bufferFrom(_storeOf(v), _offsetOf(v), _lengthOf(v));
}

function _isTypedArrayPredName(name) {
  var n = name.length;
  if (n < 8) return false;
  if (_charCodeAt(name, 0) !== 105 || _charCodeAt(name, 1) !== 115) return false;
  var tail = "Array";
  for (var k = 0; k < 5; k++) { if (_charCodeAt(name, n - 5 + k) !== _charCodeAt(tail, k)) return false; }
  for (var i = 2; i < n - 5; i++) {
    var c = _charCodeAt(name, i);
    if (!((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122))) return false;
  }
  return true;
}

var _CONCRETE_KINDS = _filter(
  _map(
    // allow:guard-reads-runtime-live -- module-init, see above
    _filter(_objectKeys(util.types), function (name) { return _isTypedArrayPredName(name); }),
    // allow:guard-reads-runtime-live -- module-init, see above
    function (name) { return [util.types[name], globalThis[name.slice(2)]]; }
  ),
  function (row) {
    return typeof row[0] === "function" && typeof row[1] === "function" &&
           typeof row[1].BYTES_PER_ELEMENT === "number" && row[1].BYTES_PER_ELEMENT > 0;
  }
);

function _concreteKindOf(v) {
  for (var i = 0; i < _CONCRETE_KINDS.length; i++) {
    if (_CONCRETE_KINDS[i][0](v)) return _CONCRETE_KINDS[i][1];
  }
  return null;
}

var _NAMED_KINDS = _filter([
  ["isNativeError", "Error"], ["isRegExp", "RegExp"], ["isPromise", "Promise"],
  ["isWeakMap", "WeakMap"], ["isWeakSet", "WeakSet"], ["isMap", "Map"], ["isSet", "Set"],
  ["isDate", "Date"], ["isProxy", "Proxy"]
], function (row) { return typeof util.types[row[0]] === "function"; });

function _kindName(v) {
  for (var i = 0; i < _NAMED_KINDS.length; i++) {
    if (util.types[_NAMED_KINDS[i][0]](v)) return _NAMED_KINDS[i][1];
  }
  return typeof v === "function" ? "function" : "value";
}

function _article(name) {
  var c = name.length > 0 ? _charCodeAt(name, 0) : 0;
  var vowel = c === 65 || c === 69 || c === 73 || c === 79 || c === 85 ||
              c === 97 || c === 101 || c === 105 || c === 111 || c === 117;
  return vowel ? "an" : "a";
}

// @enforced-by behavioral -- an input door reaching for this instead of `view` has no rename-proof
function outputView(input, ErrorClass, code, label) {
  if (!util.types.isUint8Array(input) && !_isView(input)) {
    throw _raise(ErrorClass, code, label + ": expected a Buffer / TypedArray to write into");
  }
  try {
    return _reView(input);
  } catch (e) {
    throw _raise(ErrorClass, code, label + ": output is not a usable byte view (detached backing buffer?)", e);
  }
}

// @enforced-by behavioral -- `x.length` is the ordinary spelling wherever the value is this
function lengthOf(view) {
  return _lengthOf(view);
}

function _refuseShared(v, ErrorClass, code, label) {
  if (util.types.isSharedArrayBuffer(v) ||
      (_isView(v) && util.types.isSharedArrayBuffer(_storeOf(v)))) {
    throw _raise(ErrorClass, code, label + ": shared memory cannot be used here, because another " +
      "thread can rewrite it after it has been checked; pass a Buffer or a Uint8Array over " +
      "memory this process owns");
  }
}



var _ErrorProto = Error.prototype;
function _isErrorClass(E) {
  if (typeof E !== "function") return false;
  var seen = new _Set();
  for (var p = E.prototype; p !== null && typeof p === "object"; p = _getPrototypeOf(p)) {
    if (p === _ErrorProto) return true;
    if (_setHas(seen, p)) return false;
    _setAdd(seen, p);
  }
  return false;
}

function _raise(E, code, message, cause) {
  return _isErrorClass(E) ? new E(code, message, cause) : E(code, message, cause);
}

// @enforced-by guard-shape-reinlined
// @guard-shape (?:Buffer\.from|new\s+[A-Za-z_$][\w$]*Array)\(\s*(?:new\s+[A-Za-z_$][\w$]*Array\(\s*)?([A-Za-z_$][\w$]*)\.buffer\s*,\s*\1\.byteOffset
function view(input, ErrorClass, code, label) {
  _refuseShared(input, ErrorClass, code, label);
  if (util.types.isUint8Array(input)) {
    try {
      return _reView(input);
    } catch (e) {
      throw _raise(ErrorClass, code, label + ": input is not a usable byte view (detached backing buffer?)", e);
    }
  }
  throw _raise(ErrorClass, code, label + ": expected a Buffer / Uint8Array");
}

// @enforced-by guard-shape-reinlined  (the re-view shape is declared on view above)
function source(input, ErrorClass, code, label) {
  _refuseShared(input, ErrorClass, code, label);
  var isAb = _isArrayBuffer(input);
  if (isAb || _isView(input)) {
    try {
      return isAb ? _bufferFrom(input) : _reView(input);
    } catch (e) {
      throw _raise(ErrorClass, code, label + ": input is not a usable byte source (detached backing buffer?)", e);
    }
  }
  throw _raise(ErrorClass, code, label + ": expected a BufferSource (ArrayBuffer / TypedArray / Buffer)");
}

// @enforced-by behavioral -- a copy has no rename-proof code shape to detect (any
function snapshot(input, ErrorClass, code, label) {
  return _bufferFrom(view(input, ErrorClass, code, label));
}

// @enforced-by behavioral -- a copy has no rename-proof shape to detect; the guard
function snapshotSource(input, ErrorClass, code, label) {
  return _bufferFrom(source(input, ErrorClass, code, label));
}

// @enforced-by behavioral -- a copy has no rename-proof code shape to detect (any `Buffer.from(x)`
function snapshotDeep(value, ErrorClass, code, label, opts) {
  var o = opts || {};
  var cap = o.maxDepth == null ? 64 : o.maxDepth;
  return _deep(value, ErrorClass, code, label, cap, 0, o.collect || null);
}

function _surface(names) {
  var t = _create(null);
  _forEach(names, function (n) { t[n] = 1; });
  t[Symbol.toStringTag] = 1;
  return t;
}
var _CRYPTO_KEY_SURFACE = _surface(["type", "extractable", "algorithm", "usages",
  "asymmetricKeyType", "asymmetricKeyDetails", "_handle"]);
var _ERROR_SURFACE = _surface(["message", "stack", "name", "cause"]);
var _REGEXP_SURFACE = _surface(["lastIndex", "source", "flags", "global", "ignoreCase", "multiline",
  "sticky", "unicode", "unicodeSets", "hasIndices", "dotAll"]);
var _THENABLE_SURFACE = _surface(["then", "catch", "finally"]);

function _opaqueSurface(v, ErrorClass, code, label) {
  var proto = _getPrototypeOf(v);
  if (proto === _ObjectProto || proto === null) return null;
  if (util.types.isWeakMap(v) || util.types.isWeakSet(v)) return _create(null);
  if (util.types.isNativeError(v)) return _ERROR_SURFACE;
  if (util.types.isRegExp(v)) return _REGEXP_SURFACE;
  if (util.types.isKeyObject(v)) return _CRYPTO_KEY_SURFACE;
  var keyLike;
  try {
    keyLike = require("./webcrypto").isCryptoKeyLike(v);   // allow:inline-require -- circular load: webcrypto requires this module
  } catch (e) {
    throw _raise(ErrorClass, code, label + ": reading the key surface threw", e);
  }
  if (keyLike) return _CRYPTO_KEY_SURFACE;
  var then;
  try { then = v.then; }
  catch (e) { throw _raise(ErrorClass, code, label + ": reading \"then\" threw", e); }
  if (typeof then === "function") return _THENABLE_SURFACE;
  return null;
}

function _canChangeAfterTheCheck(v, name) {
  var visited = new _Set();
  for (var o = v; o && !_setHas(visited, o); o = _getPrototypeOf(o)) {
    _setAdd(visited, o);
    var d = _getOwnPropertyDescriptor(o, name);
    if (!d) continue;
    if (d.get || d.set || d.writable || d.configurable) return true;
    return o !== v && _isExtensible(v);
  }
  return false;
}

var _SETTLED_DEPTH = 4;
function _settledValueIsFixed(value, ErrorClass, code, label, depth) {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return true;
  if (depth >= _SETTLED_DEPTH) return false;
  if (util.types.isProxy(value)) return false;
  var surface = _opaqueSurface(value, ErrorClass, code, label);
  if (!surface) return false;
  return _opaqueFieldOutsideSurface(value, surface, ErrorClass, code, label, depth + 1) === null;
}

function _opaqueFieldOutsideSurface(v, surface, ErrorClass, code, label, depth) {
  var keys = _namesToCopy(v, ErrorClass, code, label);
  for (var i = 0; i < keys.length; i++) {
    if (surface[keys[i]]) continue;
    if (typeof keys[i] === "symbol") continue;
    if (!_canChangeAfterTheCheck(v, keys[i]) &&
      _settledValueIsFixed(v[keys[i]], ErrorClass, code, label, depth || 0)) continue;
    return keys[i];
  }
  return null;
}

function _copyBytesSameKind(v, ErrorClass, code, label, collect) {
  var src = source(v, ErrorClass, code, label);
  var srcLen = _lengthOf(src);
  var owned = new _ArrayBuffer(srcLen);
  _taSet(new _Uint8Array(owned), src);
  if (collect) _append(collect, _bufferFrom(owned, 0, srcLen));
  if (_isBuffer(v)) return _bufferFrom(owned, 0, srcLen);
  if (_isArrayBuffer(v)) return owned;
  if (util.types.isDataView(v)) return new _DataView(owned);
  var Ctor = _concreteKindOf(v);
  if (!Ctor) {
    throw _raise(ErrorClass, code, label + ": a " +
      (util.types.isTypedArray(v) ? "typed array of a kind this runtime added" : "byte view") +
      " cannot be copied while keeping its kind; pass a Buffer or a Uint8Array");
  }
  return new Ctor(owned, 0, srcLen / Ctor.BYTES_PER_ELEMENT);
}

function _protoChainIsCyclic(v) {
  var visited = new _Set();
  for (var o = v; o; o = _getPrototypeOf(o)) {
    if (_setHas(visited, o)) return true;
    _setAdd(visited, o);
  }
  return false;
}

function _protoChainHasProxy(v) {
  var visited = new _Set();
  for (var o = v; o && !_setHas(visited, o); o = _getPrototypeOf(o)) {
    _setAdd(visited, o);
    if (util.types.isProxy(o)) return true;
  }
  return false;
}

function _plainCopy(copy) { return copy; }

function _deep(v, ErrorClass, code, label, cap, depth, collect) {
  if (depth > cap) throw _raise(ErrorClass, code, label + " is nested too deeply to copy");
  if (v == null || typeof v !== "object") return v;
  _refuseShared(v, ErrorClass, code, label);
  if (_protoChainHasProxy(v)) {
    throw _raise(ErrorClass, code, label + ": a Proxy cannot be copied faithfully, because the " +
      "keys it reports need not be the ones it answers; pass a plain object");
  }
  if (_protoChainIsCyclic(v)) {
    throw _raise(ErrorClass, code, label + ": its prototype chain is a cycle, so it cannot be " +
      "read or copied; pass a plain object");
  }
  if (_isBuffer(v) || _isView(v) || _isArrayBuffer(v)) {
    var bytesCopy = _copyBytesSameKind(v, ErrorClass, code, label, collect);
    _copyNamed(v, bytesCopy, ErrorClass, code, label, cap, depth, collect);
    return bytesCopy;
  }
  if (require("./guard-parsed").isRecordedAsProduced(v)) return v;   // allow:inline-require -- circular load: guard-parsed requires this module
  if (util.types.isDate(v)) {
    var dateCopy = new _Date(time.instantOf(v));
    _copyNamed(v, dateCopy, ErrorClass, code, label, cap, depth, collect, _DATE_BEHAVIOR);
    return _plainCopy(dateCopy);
  }
  if (_isArray(v)) {
    var arr = [];
    var indexE = function (c, m) { return _raise(ErrorClass, c, m); };
    var indices = _ownArrayIndices(v, v.length);
    if (identifier.readableIndices(v, indexE, code, label).length !== indices.length) {
      throw _raise(ErrorClass, code, label + " has an in-range index supplied by its prototype rather than the array itself; a list resolved through the prototype chain is refused");
    }
    if (depth === 0) identifier.refuseAccessorFields(v, indices, indexE, code, label);
    _forEach(indices, function (k) {
      var element;
      try { element = v[k]; }
      catch (e) { throw _raise(ErrorClass, code, label + ": reading element " + k + " threw", e); }
      arr[k] = _deep(element, ErrorClass, code, label, cap, depth + 1, collect);
    });
    arr.length = v.length;
    _copyNamed(v, arr, ErrorClass, code, label, cap, depth, collect);
    return _plainCopy(arr);
  }
  var surface = _opaqueSurface(v, ErrorClass, code, label);
  if (surface) {
    var carried = _opaqueFieldOutsideSurface(v, surface, ErrorClass, code, label);
    if (carried === null) return v;
    throw _raise(ErrorClass, code, label + ": " + _article(_kindName(v)) + " " + _kindName(v) +
      " carrying its own field " + _stringify(_String(carried)) + " cannot be used here -- its " +
      "state cannot be copied, so that field would stay changeable after it was checked; pass the " +
      "fields as a plain object");
  }
  if (util.types.isMap(v)) {
    return _plainCopy(_copyEntries(v, new _Map(), ErrorClass, code, label, cap, depth, collect));
  }
  if (util.types.isSet(v)) {
    return _plainCopy(_copyEntries(v, new _Set(), ErrorClass, code, label, cap, depth, collect));
  }
  var out = _create(_getPrototypeOf(v) === null ? null : _ObjectProto);
  _copyNamed(v, out, ErrorClass, code, label, cap, depth, collect);
  return out;
}


function _namesToCopy(src, ErrorClass, code, label, atArgument) {
  var E = function (c, m) { return _raise(ErrorClass, c, m); };
  var names = identifier.readableNames(src, E, code, label);
  if (atArgument) identifier.refuseAccessorFields(src, names, E, code, label);
  return names;
}

function _copyEntries(src, dst, ErrorClass, code, label, cap, depth, collect) {
  var walk = util.types.isSet(src) ? _setForEach : _mapForEach;
  walk(src, function (value, key) {
    var copiedValue = _deep(value, ErrorClass, code, label, cap, depth + 1, collect);
    if (util.types.isSet(dst)) _setAdd(dst, copiedValue);
    else _mapSet(dst, _deep(key, ErrorClass, code, label, cap, depth + 1, collect), copiedValue);
  });
  _copyNamed(src, dst, ErrorClass, code, label, cap, depth, collect);
  return dst;
}

var _DATE_BEHAVIOR = (function () {
  var t = _create(null);
  _forEach(_ownKeys(Date.prototype), function (n) { t[n] = 1; });
  return t;
})();

function _copyNamed(src, dst, ErrorClass, code, label, cap, depth, collect, behavior) {
  var keys = _namesToCopy(src, ErrorClass, code, label, depth === 0);
  for (var k = 0; k < keys.length; k++) {
    var value;
    try { value = src[keys[k]]; }
    catch (e) { throw _raise(ErrorClass, code, label + ": reading " + _stringify(keys[k]) + " threw", e); }
    if (behavior && behavior[keys[k]] && typeof value === "function") continue;
    _defineProperty(dst, keys[k], {
      value: typeof value === "function" ? value
        : _deep(value, ErrorClass, code, label, cap, depth + 1, collect),
      writable: true, enumerable: _wasEnumerable(src, keys[k]), configurable: true,
    });
  }
}

function _wasEnumerable(v, name) {
  for (var o = v; o && o !== _ObjectProto; o = _getPrototypeOf(o)) {
    var d = _getOwnPropertyDescriptor(o, name);
    if (d) return !!d.enumerable;
  }
  return false;
}

// @enforced-by behavioral -- there is no rename-proof code shape for "copied every argument". The
function fixArguments(ErrorClass, code, args) {
  var copies = [];
  var values = [];
  function release() {
    require("./guard-secret").zeroizeAll(copies, ErrorClass, code,   // allow:inline-require -- circular load: guard-secret requires this module
      "a copy of a caller-supplied argument");
  }
  try {
    for (var i = 0; i < args.length; i++) {
      _append(values, snapshotDeep(args[i][0], ErrorClass, code, args[i][1], { collect: copies }));
    }
  } catch (e) {
    release();
    throw e;
  }
  return { values: values, release: release };
}

// @enforced-by behavioral -- an arrangement of two calls has no rename-proof shape to detect. The
function fixedCall(ErrorClass, code, args, body) {
  var handle = null;
  return _promiseFinally(async.deferred(function () {
    handle = fixArguments(ErrorClass, code, args);
    return _apply(body, null, handle.values);
  }), function () { if (handle) handle.release(); });
}

module.exports = intrinsic.freeze({
  view: view, source: source, snapshot: snapshot, snapshotSource: snapshotSource,
  isByteSource: isByteSource, asyncStreamOf: asyncStreamOf, translateStreamError: translateStreamError, lengthOf: lengthOf, outputView: outputView,
  snapshotDeep: snapshotDeep, fixArguments: fixArguments, fixedCall: fixedCall,
});
