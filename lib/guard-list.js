// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var _freeze = require("./guard-intrinsic").freeze;
var _defineProperty = require("./guard-intrinsic").defineProperty;
var _isArray = require("./guard-intrinsic").isArray;

var MAX_ARRAY_LENGTH = 4294967295;

// @enforced-by guard-shape-reinlined
// @guard-shape defineProperty\(\s*\w+\s*,\s*\w+\.length\s*,\s*\{\s*value:
// @guard-via guard\.list\.append\(
function append(list, value) {
  if (!_isArray(list)) throw new TypeError("guard.list.append: the receiver must be an array");
  var n = list.length;
  if (n >= MAX_ARRAY_LENGTH) throw new RangeError("guard.list.append: the array is at its maximum length");
  _defineProperty(list, n, { value: value, writable: true, enumerable: true, configurable: true });
  return list;
}

// @enforced-by behavioral -- `.indexOf(x) !== -1` has no rename-proof form that separates a
function contains(list, value) {
  if (!list) return false;
  for (var i = 0, n = list.length; i < n; i++) if (list[i] === value) return true;
  return false;
}

// @enforced-by behavioral -- the composition of contains() has no rename-proof shape of its own;
function containsAll(list, values) {
  if (!values) return true;
  for (var i = 0, n = values.length; i < n; i++) if (!contains(list, values[i])) return false;
  return true;
}

// @enforced-by behavioral -- `.some(` has legitimate non-rule siblings (building a list, reporting
function anyMatches(list, predicate) {
  if (!list) return false;
  for (var i = 0, n = list.length; i < n; i++) if (predicate(list[i], i)) return true;
  return false;
}

// @enforced-by behavioral -- see anyMatches; the RED vector (an untrusted signer keeps
function allMatch(list, predicate) {
  if (!list) return true;
  for (var i = 0, n = list.length; i < n; i++) if (!predicate(list[i], i)) return false;
  return true;
}

module.exports = _freeze({
  append: append,
  contains: contains,
  containsAll: containsAll,
  anyMatches: anyMatches,
  allMatch: allMatch,
});
