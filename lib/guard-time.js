// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var util = { types: require("./guard-intrinsic").types };
var _freeze = require("./guard-intrinsic").freeze;
var _isNaN = Number.isNaN;

var _dateGetTime = require("./guard-intrinsic").uncurry(Date.prototype.getTime);

// @enforced-by guard-shape-reinlined
// @guard-shape \.getTime\s*\(
function instantOf(value) { return _dateGetTime(value); }

// @enforced-by nan-date-comparison-unguarded
function assertValid(value, E, code, label) {
  if (!util.types.isDate(value) || _isNaN(instantOf(value))) {
    throw E(code, (label || "value") + " must be a valid Date");
  }
  return value;
}

// @enforced-by nan-date-comparison-unguarded
function within(instant, lower, upper, E, code, label, opts) {
  assertValid(instant, E, code, label);
  assertValid(lower, E, code, (label || "window") + " lower bound");
  assertValid(upper, E, code, (label || "window") + " upper bound");
  var t = instantOf(instant);
  var lo = instantOf(lower);
  var hi = instantOf(upper);
  return t >= lo && (opts && opts.upperInclusive ? t <= hi : t < hi);
}

// @enforced-by behavioral -- a prototype test in place of a slot test has no rename-proof code
function isDate(value) {
  return util.types.isDate(value);
}

module.exports = _freeze({
  assertValid: assertValid,
  instantOf: instantOf,
  isDate: isDate,
  within: within,
});
