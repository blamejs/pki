// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var _freeze = require("./guard-intrinsic").freeze;

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
  contains: contains,
  containsAll: containsAll,
  anyMatches: anyMatches,
  allMatch: allMatch,
});
