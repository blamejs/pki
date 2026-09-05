// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
var intrinsic = require("./guard-intrinsic");
var util = { types: intrinsic.types };
// @internal

var _isArray = intrinsic.isArray;
var _create = intrinsic.create;
var _getPrototypeOf = intrinsic.getPrototypeOf;
var _setPrototypeOf = intrinsic.setPrototypeOf;
var _getOwnPropertyDescriptor = intrinsic.getOwnPropertyDescriptor;
var _getOwnPropertyNames = intrinsic.getOwnPropertyNames;
var _defineProperty = intrinsic.defineProperty;
var _ownKeys = intrinsic.ownKeys;
var _isView = intrinsic.isView;
var _isInteger = intrinsic.isInteger;
var _stringify = intrinsic.stringify;
var _forEach = intrinsic.forEach;
var _map = intrinsic.map;
var _filter = intrinsic.filter;
var _every = intrinsic.every;
var _some = intrinsic.some;
var _indexOf = intrinsic.indexOf;
var _sort = intrinsic.sort;
var _setAdd = intrinsic.setAdd;
var _setHas = intrinsic.setHas;
var _mapGet = intrinsic.mapGet;
var _mapSet = intrinsic.mapSet;
var _mapHas = intrinsic.mapHas;
var _Set = intrinsic.Set;
var _Map = intrinsic.Map;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _strSplit = intrinsic.uncurry(String.prototype.split);
var _hasOwn = intrinsic.hasOwn;
var _String = intrinsic.String;
var _Number = intrinsic.Number;
var _BigInt = intrinsic.BigInt;
var _Object = intrinsic.Object;
var _BufferProto = intrinsic.BufferProto;
var _append = require("./guard-list").append;

function _isDottedDecimal(str) {
  if (str.length === 0) return false;
  var arcs = 0, digits = 0, leadingZero = false;
  for (var i = 0; i < str.length; i++) {
    var c = _charCodeAt(str, i);
    if (c === 0x2e) {
      if (digits === 0 || leadingZero) return false;
      arcs++; digits = 0; leadingZero = false;
      continue;
    }
    if (c < 0x30 || c > 0x39) return false;
    if (digits === 1 && _charCodeAt(str, i - 1) === 0x30) leadingZero = true;
    digits++;
  }
  if (digits === 0 || leadingZero) return false;
  return arcs >= 1;
}

// @enforced-by behavioral -- string-form OID canonicalization has no rename-proof
function assertCanonicalOid(str, E, code, label, boundsCode) {
  var who = label || "OID";
  if (typeof str !== "string" || !_isDottedDecimal(str)) {
    throw E(code, who + " must be a canonical dotted-decimal OID string of two or more arcs with no leading-zero component");
  }
  if (boundsCode === null) return str;
  var bcode = boundsCode === undefined ? code : boundsCode;
  var parts = _strSplit(str, ".");
  var root = _BigInt(parts[0]);
  var second = _BigInt(parts[1]);
  if (root > 2n) throw E(bcode, who + " root arc must be 0, 1, or 2 (X.660)");
  if (root < 2n && second > 39n) throw E(bcode, who + " second arc must be 0..39 under roots 0 and 1 (X.660)");
  return str;
}

// @enforced-by behavioral -- an options-shape walk has no rename-proof code shape; the RED vectors
// @enforced-by guard-shape-reinlined
// @guard-shape Object\.keys\(\w+(?:\.\w+)*\)\.forEach\(function \((\w+)\) \{\s*if \(![\w.]+\[\1\]\) (?:\{\s*)?throw
function assertKnownKeys(obj, known, E, code, message) {
  _refuseUnenumerable(obj, E, code, "the options");
  var describe = typeof message === "function" ? message : function (k) { return message + _stringify(k); };
  _forEach(_readableNames(obj), function (k) {
    if (_hasOwn(known, k)) return;
    throw E(code, describe(typeof k === "symbol" ? _String(k) : k));
  });
}

var _PRISTINE_OBJECT_PROTO = (function () {
  var s = _create(null);
  _forEach(["constructor", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
    "toString", "valueOf", "__defineGetter__", "__defineSetter__", "__lookupGetter__",
    "__lookupSetter__", "__proto__"], function (k) { s[k] = 1; });
  return s;
})();

function _looksBuiltIn(d) {
  return !!d && (!!d.get || !!d.set || typeof d.value === "function");
}

function _requireFactory(E) {
  if (typeof E !== "function") {
    throw new TypeError("guard.identifier needs an error factory called as E(code, message); " +
      "a class is not one, so adapt it at the call site");
  }
}

function _refuseUnenumerable(v, E, code, label) {
  _requireFactory(E);
  if (v === null || typeof v !== "object") return;
  var visited = new _Set();
  for (var o = v; o && !_setHas(visited, o); o = _getPrototypeOf(o)) {
    _setAdd(visited, o);
    if (!util.types.isProxy(o)) continue;
    throw E(code, label + (o === v ? " is" : " inherits from") + " a Proxy, whose reported keys " +
      "need not match what it answers, so an option it holds cannot be found; pass a plain object");
  }
}

function _isMethodOf(from, k, fn) {
  var visited = new _Set();
  for (var o = from; o && !_setHas(visited, o); o = _getPrototypeOf(o)) {
    _setAdd(visited, o);
    var d = _getOwnPropertyDescriptor(o, k);
    if (!d) continue;
    return !d.get && !d.set && d.value === fn;
  }
  return false;
}

// @enforced-by behavioral -- a property-surface walk has no rename-proof code shape. The RED
function _isArrayIndex(k) {
  var n = _Number(k);
  return _isInteger(n) && n >= 0 && n < 4294967295 && _String(n) === k;
}

function _isIndexedKind(v) {
  return _isArray(v) || (_isView(v) && !util.types.isDataView(v));
}

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
var _BUFFER_PROTO_MEMBERS = ["parent", "offset"];

var _ARRAY_MEMBERS = _ARRAY_PROTO_MEMBERS;
var _REGEXP_MEMBERS = ["lastIndex"].concat(_REGEXP_PROTO_MEMBERS);
var _VIEW_MEMBERS = _TYPED_PROTO_MEMBERS.concat(_CONCRETE_TYPED_MEMBERS);
var _BUFFER_KIND_MEMBERS = _VIEW_MEMBERS.concat(_BUFFER_PROTO_MEMBERS);
var _DATAVIEW_MEMBERS = _DATAVIEW_PROTO_MEMBERS;
var _ARRAYBUFFER_MEMBERS = _ARRAYBUFFER_PROTO_MEMBERS;
var _SHARED_MEMBERS = _SHARED_PROTO_MEMBERS;

var _TYPED_ARRAY_PROTO = _getPrototypeOf(Uint8Array.prototype);
var _INTRINSIC_HOLDERS = (function () {
  var m = new _Map([[_TYPED_ARRAY_PROTO, _TYPED_PROTO_MEMBERS]]);
  function pair(ctor, members) { if (ctor && ctor.prototype) _mapSet(m, ctor.prototype, members); }
  pair(Array, _ARRAY_PROTO_MEMBERS);
  pair(RegExp, _REGEXP_PROTO_MEMBERS);
  _forEach([Map, Set], function (c) { pair(c, _SIZED_PROTO_MEMBERS); });
  _forEach([WeakMap, WeakSet], function (c) { pair(c, _WEAK_PROTO_MEMBERS); });
  pair(ArrayBuffer, _ARRAYBUFFER_PROTO_MEMBERS);
  pair(typeof SharedArrayBuffer === "function" ? SharedArrayBuffer : null, _SHARED_PROTO_MEMBERS);
  pair(DataView, _DATAVIEW_PROTO_MEMBERS);
  pair(Buffer, _BUFFER_PROTO_MEMBERS);
  _forEach(_getOwnPropertyNames(globalThis), function (n) {
    var d = _getOwnPropertyDescriptor(globalThis, n);
    if (!d || typeof d.value !== "function") return;
    var C = d.value;
    if (typeof C.BYTES_PER_ELEMENT !== "number") return;
    if (!C.prototype || _getPrototypeOf(C.prototype) !== _TYPED_ARRAY_PROTO) return;
    _mapSet(m, C.prototype, _CONCRETE_TYPED_MEMBERS);
  });
  return m;
})();

function _holderMembers(o) {
  return _mapHas(_INTRINSIC_HOLDERS, o) ? _mapGet(_INTRINSIC_HOLDERS, o) : null;
}

function _isNodeBuffer(v) {
  if (!util.types.isUint8Array(v)) return false;
  var visited = new _Set();
  for (var o = v; o && !_setHas(visited, o); o = _getPrototypeOf(o)) {
    _setAdd(visited, o);
    if (o === _BufferProto) return true;
  }
  return false;
}

function _kindMembers(v) {
  if (v === null || v === undefined) return [];
  if (_isArray(v)) return _ARRAY_MEMBERS;
  if (_isNodeBuffer(v)) return _BUFFER_KIND_MEMBERS;
  if (util.types.isDataView(v)) return _DATAVIEW_MEMBERS;
  if (_isView(v)) return _VIEW_MEMBERS;
  if (util.types.isArrayBuffer(v)) return _ARRAYBUFFER_MEMBERS;
  if (util.types.isSharedArrayBuffer(v)) return _SHARED_MEMBERS;
  if (util.types.isRegExp(v)) return _REGEXP_MEMBERS;
  if (util.types.isWeakMap(v) || util.types.isWeakSet(v)) return _WEAK_PROTO_MEMBERS;
  if (util.types.isMap(v) || util.types.isSet(v)) return _SIZED_PROTO_MEMBERS;
  return [];
}

function _isOwnStructuralName(v, k) {
  return util.types.isRegExp(v) && k === "lastIndex";
}

function _looksIntrinsic(d) {
  return !!d && (!!d.get || !!d.set || typeof d.value === "function" ||
                 d.writable === false || d.configurable === false);
}

function _shadowsAnother(v, k, holder) {
  var visited = new _Set();
  var past = false;
  for (var o = v; o !== null && o !== undefined && !_setHas(visited, o); o = _getPrototypeOf(o)) {
    _setAdd(visited, o);
    if (o === holder) { past = true; continue; }
    if (past && _getOwnPropertyDescriptor(o, k)) return true;
  }
  return false;
}

function _readableNames(obj) {
  var seen = _create(null);
  var out = [];
  var o = (obj === null || obj === undefined) ? null : _Object(obj);
  var indexedSelf = _isIndexedKind(o);
  var members = _kindMembers(o);
  var visited = new _Set();
  while (o && !_setHas(visited, o)) {
    _setAdd(visited, o);
    var inherited = (o !== obj);
    var above = _getPrototypeOf(o);
    var atObjectProto = inherited && above === null;
    _forEach(_ownKeys(o), function (k) {
      if (seen[k]) return;
      if (indexedSelf && typeof k === "string" && _isArrayIndex(k)) return;
      if (indexedSelf && k === "length" && !inherited) return;
      if (_isOwnStructuralName(obj, k)) return;
      var d = _getOwnPropertyDescriptor(o, k);
      var here = _holderMembers(o);
      if (inherited && _looksIntrinsic(d) && !_shadowsAnother(obj, k, o) &&
          (here === null ? _indexOf(members, k) !== -1 : _indexOf(here, k) !== -1)) return;
      if (atObjectProto) {
        if (_PRISTINE_OBJECT_PROTO[k] && _looksBuiltIn(d)) return;
        seen[k] = 1;
        _append(out, k);
        return;
      }
      if (d && !d.get && !d.set && typeof d.value === "function" &&
          (inherited || _isMethodOf(above, k, d.value))) return;
      seen[k] = 1;
      _append(out, k);
    });
    o = above;
  }
  return out;
}

// @enforced-by behavioral -- a missing refusal has no rename-proof code shape; the RED vector
function readableNames(obj, E, code, label) {
  _refuseUnenumerable(obj, E, code, label);
  return _readableNames(obj);
}

// @enforced-by behavioral -- an enumeration gap has no rename-proof code shape; the RED vector
function readableIndices(obj, E, code, label) {
  _refuseUnenumerable(obj, E, code, label);
  if (!_isArray(obj)) return [];
  var own = _getOwnPropertyDescriptor(obj, "length");
  var limit = own ? own.value : 0;
  var seen = _create(null);
  var out = [];
  var visited = new _Set();
  for (var o = obj; o && !_setHas(visited, o); o = _getPrototypeOf(o)) {
    _setAdd(visited, o);
    _forEach(_ownKeys(o), function (k) {
      if (typeof k !== "string" || !_isArrayIndex(k) || seen[k]) return;
      if (_Number(k) >= limit) return;
      seen[k] = 1;
      _append(out, k);
    });
  }
  return _sort(out, function (a, b) { return _Number(a) - _Number(b); });
}

function _notAnOptionsBag(v) {
  if (util.types.isBoxedPrimitive(v)) return "a boxed primitive";
  if (util.types.isNativeError(v)) return "an Error";
  if (util.types.isPromise(v)) return "a Promise";
  if (util.types.isArgumentsObject(v)) return "an arguments object";
  return null;
}

function _isBuiltinExotic(v) {
  var t = util.types;
  return t.isDate(v) || t.isMap(v) || t.isSet(v) || t.isWeakMap(v) || t.isWeakSet(v) || t.isRegExp(v) ||
    t.isPromise(v) || t.isArrayBuffer(v) || t.isSharedArrayBuffer(v) || t.isArrayBufferView(v) ||
    t.isBoxedPrimitive(v) || t.isNativeError(v) || t.isArgumentsObject(v) || t.isGeneratorObject(v);
}

function _proxyInChain(v) {
  if (v === null || typeof v !== "object") return false;
  var visited = new _Set();
  for (var o = v; o && !_setHas(visited, o); o = _getPrototypeOf(o)) {
    _setAdd(visited, o);
    if (util.types.isProxy(o)) return true;
  }
  return false;
}
function isPlainRecord(v) {
  if (v === null || typeof v !== "object") return false;
  if (_proxyInChain(v)) return false;
  if (_isNodeBuffer(v) || _isArray(v)) return false;
  return !_isBuiltinExotic(v);
}
// @enforced-by behavioral -- a plain-record refusal has no single rename-proof code shape worth a
function assertPlainRecord(v, E, code, label) {
  _requireFactory(E);
  if (v === null || typeof v !== "object") throw E(code, label + " must be a plain object");
  _refuseUnenumerable(v, E, code, label);
  if (_isNodeBuffer(v) || _isArray(v)) throw E(code, label + " must be a plain object");
  if (_isBuiltinExotic(v)) throw E(code, label + " must be a plain object (a built-in exotic such as a Date or Map is refused)");
}

// @enforced-by behavioral -- the defect is an ordering, which has no rename-proof code shape; the
function optionsObject(opts, E, code, label) {
  if (opts === null || opts === undefined) return _create(null);
  if (typeof opts !== "object") throw E(code, label + " must be an object");
  _refuseUnenumerable(opts, E, code, label);
  if (_isNodeBuffer(opts)) throw E(code, label + " must be an object");
  var wrong = _notAnOptionsBag(opts);
  if (wrong) throw E(code, label + ": " + wrong + " is not an options bag; pass a plain object");
  return _settle(opts, E, code, label);
}

function _descriptorHolder(v, k) {
  var visited = new _Set();
  for (var o = v; o !== null && o !== undefined && !_setHas(visited, o); o = _getPrototypeOf(o)) {
    _setAdd(visited, o);
    var d = _getOwnPropertyDescriptor(o, k);
    if (d) return d;
  }
  return null;
}

// @enforced-by behavioral -- reading an accessor before it is refused has no rename-proof code
function refuseAccessorFields(obj, names, E, code, label) {
  for (var i = 0; i < names.length; i++) {
    var holder = _descriptorHolder(obj, names[i]);
    if (holder && (holder.get || holder.set)) {
      throw E(code, label + " supplies " +
        _stringify(typeof names[i] === "symbol" ? _String(names[i]) : names[i]) +
        " through an accessor, whose value can differ between the check and the read; pass an " +
        "object whose fields are plain values");
    }
  }
}

function _settle(opts, E, code, label) {
  function readAll(names) {
    for (var i = 0; i < names.length; i++) {
      try { void opts[names[i]]; }
      catch (_e) {
        throw E(code, label + ": reading " +
          _stringify(typeof names[i] === "symbol" ? _String(names[i]) : names[i]) + " threw");
      }
    }
  }
  var before = _readableNames(opts);
  refuseAccessorFields(opts, before, E, code, label);
  readAll(before);
  var after = _readableNames(opts);
  var same = after.length === before.length;
  for (var j = 0; same && j < after.length; j++) same = _indexOf(before, after[j]) !== -1;
  if (!same) {
    throw E(code, label + " changes which options it carries while they are read, so no set of " +
      "them can be checked; pass an object whose properties are plain values");
  }
  return opts;
}

module.exports = intrinsic.freeze({
  assertCanonicalOid: assertCanonicalOid,
  assertKnownKeys: assertKnownKeys,
  assertPlainRecord: assertPlainRecord,
  isPlainRecord: isPlainRecord,
  optionsObject: optionsObject,
  refuseAccessorFields: refuseAccessorFields,
  readableNames: readableNames,
  readableIndices: readableIndices
});
