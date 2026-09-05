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

// @enforced-by behavioral -- the defect is the ABSENCE of this call at a construction site, not a
function of(src, extras) {
  var out = {};
  _copyOwn(out, src);
  if (extras != null) _copyOwn(out, extras);
  /** @internal Resolving a promise reads `then` off the value, so an inherited accessor would run
   * with the verdict as its receiver and could rewrite a field or hand the caller a different
   * object. An own `then` ends that lookup, and is non-enumerable so keys, JSON, a spread and a
   * deep-equality comparison do not see it. */
  _defineProperty(out, "then", { value: undefined, enumerable: false, configurable: true, writable: true });
  return out;
}

// @enforced-by behavioral -- Object.hasOwn and hasOwnProperty are replaceable at any time, and a
function carries(obj, key) {
  return obj != null && _hasOwn(_Object(obj), key);
}

module.exports = _freeze({ of: of, carries: carries });
