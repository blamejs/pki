// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var constants = require("./constants");
var _isInteger = require("./guard-intrinsic").isInteger;
var _freeze = require("./guard-intrinsic").freeze;
var _sizeOf = require("./guard-intrinsic").sizeOf;

// @enforced-by behavioral -- a config-time cap validator has no rename-proof code
function cap(value, key, dflt, opts) {
  if (value === undefined) return dflt;
  opts = opts || {};
  var min = opts.min === undefined ? 0 : opts.min;
  if (!_isInteger(min) || (opts.max !== undefined && !_isInteger(opts.max))) {
    throw new TypeError("guard.limits.cap: the min/max bounds for " + key + " must be integers");
  }
  if (!_isInteger(value) || value < min || (opts.max !== undefined && value > opts.max)) {
    var want = "an integer >= " + min + (opts.max !== undefined ? " and <= " + opts.max : "");
    if (min === 0 && opts.max === undefined) want = "a non-negative integer";
    if (opts.E) throw opts.E(opts.code, (opts.label || key) + " must be " + want);
    throw new TypeError("decode: " + key + " must be " + want);
  }
  return value;
}

// @enforced-by guard-shape-reinlined
// @guard-scope file
// @guard-shape \bopts\.maxDepth\b
// @guard-shape \bdepth\s*\+\s*1\b
// @guard-via \.depthCap\s*\(
function depthCap(value, key, dflt) {
  var n = cap(value, key, dflt);
  if (n > constants.LIMITS.MAX_DECODE_DEPTH_CEILING) {
    throw new TypeError("decode: " + key + " " + n + " exceeds the stack-safe ceiling " + constants.LIMITS.MAX_DECODE_DEPTH_CEILING);
  }
  return n;
}

// @enforced-by behavioral -- a monotone counter has no rename-proof code shape
function counter(max, E, code, label) {
  if (!_isInteger(max) || max < 0) {
    throw new TypeError("guard.limits.counter: max must be a non-negative integer");
  }
  var n = 0;
  return {
    tick: function () {
      n += 1;
      if (n > max) throw E(code, (label || "decoded item") + " count exceeds the cap " + max);
    },
    count: function () { return n; },
  };
}

// @enforced-by behavioral -- a `buf.length > cap` size gate has no rename-proof code
function byteCap(buf, max, E, code, label) {
  if (!_isInteger(max) || max < 0) {
    throw new TypeError("guard.limits.byteCap: max must be a non-negative integer");
  }
  var size = _sizeOf(buf);
  if (size > max) {
    throw E(code, (label || "input") + " is " + size + " bytes, over the " + max + "-byte cap");
  }
  return buf;
}

module.exports = _freeze({ cap: cap, depthCap: depthCap, counter: counter, byteCap: byteCap });
