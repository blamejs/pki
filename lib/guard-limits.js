// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var constants = require("./constants");
var _isInteger = require("./guard-intrinsic").isInteger;
var _freeze = require("./guard-intrinsic").freeze;
var _sizeOf = require("./guard-intrinsic").sizeOf;
var _isFinite = require("./guard-intrinsic").isFinite;
var _Number = require("./guard-intrinsic").Number;
var _hrtimeBigint = process.hrtime.bigint;
function _monotonicNow() { return _Number(_hrtimeBigint() / 1000000n); }

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

/** @internal Thrown when a parse exhausts its resource budget. It is not a PkiError subclass,
 *  so a `catch (e) { if (e instanceof PkiError) ...; throw e; }` re-throws it. A parser door
 *  converts it to that door's typed refusal, so the public contract is unchanged. */
function BudgetExceeded(message) {
  var e = new Error(message);
  e.name = "BudgetExceeded";
  e.budgetExceeded = true;
  return e;
}

function isBudgetExceeded(e) {
  return !!(e && e.budgetExceeded === true);
}

/** @internal One budget per top-level parse, carried into every nested decode. `exhausted`
 *  latches, and the object is frozen, so a caller that catches the throw cannot clear it. A
 *  door that re-reads the latch before returning a result therefore still refuses, whatever
 *  code between the two caught the exception. */
function budget(limits) {
  var spent = 0;
  var exhausted = false;
  var max = cap(limits ? limits.maxBytes : undefined, "maxBytes", constants.LIMITS.DER_MAX_BYTES);
  var self = {
    spend: function (n, what) {
      if (!_isInteger(n) || n < 0) throw new TypeError("guard.limits.budget: spend takes a non-negative integer");
      spent += n;
      if (spent > max) {
        exhausted = true;
        throw BudgetExceeded((what || "the parse") + " exceeds the " + max + "-byte budget for this parse");
      }
      return n;
    },
    trip: function (what) {
      exhausted = true;
      throw BudgetExceeded((what || "the parse") + " exceeds the budget for this parse");
    },
    exhausted: function () { return exhausted; },
    spent: function () { return spent; },
    remaining: function () { return max - spent; },
    max: function () { return max; },
  };
  return _freeze(self);
}

/** @internal A wall-clock bound shared across several operations, where a per-operation timeout
 * bounds each one and nothing bounds their sum. `now` is the clock, which a caller supplies so a
 * test drives the bound without waiting; it defaults to the monotonic one, because a wall clock
 * that steps backward would extend the deadline it was meant to enforce.
 *
 * `expired()` answers the question and `remaining()` gives the budget a per-operation timeout
 * should be narrowed to, never below zero, so a caller that hands `remaining()` to a timeout
 * cannot ask for one that outlives the deadline.
 */
// @enforced-by behavioral -- an elapsed-time comparison has no rename-proof shape that separates a deadline from any other subtraction; the vectors driving a checker to its bound are the guard
function deadline(totalMs, opts) {
  opts = opts || {};
  var now = typeof opts.now === "function" ? opts.now : _monotonicNow;
  if (!_isInteger(totalMs) || totalMs < 0) {
    throw new TypeError("guard.limits.deadline: the total must be a non-negative integer of milliseconds");
  }
  var started = now();
  if (typeof started !== "number" || !_isFinite(started)) {
    throw new TypeError("guard.limits.deadline: the clock must return a finite number of milliseconds");
  }
  var self = {
    elapsed: function () {
      var at = now();
      return typeof at === "number" && _isFinite(at) && at > started ? at - started : 0;
    },
    remaining: function () {
      var left = totalMs - self.elapsed();
      return left > 0 ? left : 0;
    },
    expired: function () { return self.remaining() === 0; },
    total: function () { return totalMs; },
  };
  return _freeze(self);
}

module.exports = _freeze({
  cap: cap, depthCap: depthCap, counter: counter, byteCap: byteCap,
  budget: budget, isBudgetExceeded: isBudgetExceeded, deadline: deadline,
});
