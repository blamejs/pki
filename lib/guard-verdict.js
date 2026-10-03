// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var _freeze = require("./guard-intrinsic").freeze;
var _keys = require("./guard-intrinsic").keys;
var _defineProperty = require("./guard-intrinsic").defineProperty;
var _getOwnPropertyDescriptor = require("./guard-intrinsic").getOwnPropertyDescriptor;
var _hasOwn = require("./guard-intrinsic").hasOwn;
var _Object = require("./guard-intrinsic").Object;

function _copyOwn(out, src) {
  var keys = _keys(src);
  for (var i = 0; i < keys.length; i++) {
    var d = _getOwnPropertyDescriptor(src, keys[i]);
    if (!d) continue;
    var value = _hasOwn(d, "value") ? d.value : src[keys[i]];
    _defineProperty(out, keys[i], { value: value, enumerable: true, configurable: true, writable: true });
  }
}

/** @internal Resolving a promise reads `then` off the value, so an inherited accessor would run with
 * the verdict as its receiver and could rewrite a field or hand the caller a different object. An own
 * `then` ends that lookup, and is non-enumerable so keys, JSON, a spread and a deep-equality
 * comparison do not see it.
 *
 * `shield` adds that sentinel to the object it is given. It is the form for a result whose SHAPE must
 * survive: a parse result carrying nested structure, a row inside an array a caller indexes, an
 * object whose prototype is null. `of` copies, which is right for a verdict assembled from a literal
 * and wrong for anything whose non-enumerable members, accessors or identity a caller reads.
 *
 * @enforced-by behavioral -- the defect is the ABSENCE of this call at a construction site, which has
 * no code shape of its own. The guard is the conformance vector per verb: a verdict-shaped object
 * returned to a caller while an inherited `Object.prototype.then` is installed must still report the
 * toolkit's answer.
 */
function shield(target) {
  if (target === null || typeof target !== "object") return target;
  /** @internal An own `then` the object already carries is left alone when it is not callable: the
   * lookup ends there already, and overwriting it would DELETE a member. A parsed JSON document may
   * carry a `then` of its own, and `{"then":42,"other":1}` round-tripped as `{"other":1}` when this
   * replaced it unconditionally. A CALLABLE own `then` is the thenable itself rather than data, and
   * JSON cannot produce one, so it is replaced. */
  if (_hasOwn(target, "then")) {
    var d = _getOwnPropertyDescriptor(target, "then");
    /** @internal A DATA property only. An own accessor is replaced without being read: it answers each
     * read separately, so one that returns a non-function now can return a function when the promise
     * machinery looks, and reading it to decide would be the one read that does not count. */
    if (d && _hasOwn(d, "value") && typeof d.value !== "function") return target;
  }
  _defineProperty(target, "then", { value: undefined, enumerable: false, configurable: true, writable: true });
  return target;
}

// @enforced-by behavioral -- the defect is the ABSENCE of this call at a construction site, not a
function of(src, extras) {
  var out = {};
  _copyOwn(out, src);
  if (extras != null) _copyOwn(out, extras);
  return shield(out);
}

// @enforced-by behavioral -- Object.hasOwn and hasOwnProperty are replaceable at any time, and a
function carries(obj, key) {
  return obj != null && _hasOwn(_Object(obj), key);
}

// @enforced-by behavioral -- for a target that cannot be rebuilt, an Error carrying a field a
function set(target, key, value) {
  _defineProperty(target, key, { value: value, enumerable: true, configurable: true, writable: true });
  /** @internal The target leaves here carrying the sentinel as well. A field set on an object is the
   * same kind of value a verdict is, and a target that reached a promise resolution without one would
   * hand the lookup to Object.prototype however it was assembled. */
  return shield(target);
}

module.exports = _freeze({ of: of, shield: shield, carries: carries, set: set });
