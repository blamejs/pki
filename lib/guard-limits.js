// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// decoders whose option validation composes these guards (pki.asn1.decode,
// pki.cbor.decode).
//
// guard-limits -- fail-closed validation of operator-supplied decode limits at
// config time (the tier that throws on a bad argument so the operator catches
// the typo at boot). Enforced choke point: a codebase-patterns detector requires
// the stack-safe recursion ceiling to live only here, so a new decoder cannot be
// configured past it.
//
// Defends the parser-DoS / resource-exhaustion class (CWE-834 excessive
// recursion, CWE-770 allocation without limits; MITRE T1499.001; D3FEND
// Recursion-Bounding + Input-Size-Restriction). A recursive-descent decoder
// bounded only by a caller-tunable maxDepth overflows the native call stack (a
// raw RangeError, not a typed verdict) once the cap is raised past the frame
// limit; depthCap refuses a maxDepth above the stack-safe ceiling. A bad limit
// is an authoring bug, so this tier throws a TypeError (not a PkiError). NIST
// 800-53 SI-10 / SC-5 do not require these bounds (framework lag) -- the bound
// at the parser is the actual control.

var constants = require("./constants");

// cap(value, key, dflt, opts) -> a validated bounded integer, or dflt when value
// is undefined. A non-integer / non-finite / negative value fails closed
// (Number.isInteger already rejects non-numbers, NaN, and Infinity).
//
// With no opts it is the config-time codec default: a bare TypeError with the
// "decode:" prefix and a >= 0 floor (the asn1-der / cbor-det callers are
// untouched). opts lets a caller in another currency reuse the same integer
// floor with its OWN typed verdict and bounds -- so a fractional/negative/NaN
// bound cannot be spelled a fifth way with a dropped Number.isInteger:
//   E     - a (code, message) -> Error factory; when given, an out-of-range
//           value throws E(code, ...) instead of the bare TypeError.
//   code  - the domain/reason code passed to E.
//   label - names the argument in the message (defaults to key).
//   min   - inclusive lower bound (default 0).
//   max   - inclusive upper bound (optional).
// @enforced-by behavioral -- a config-time cap validator has no rename-proof code
//   shape; the decode-rejects-a-bad-cap RED vectors (asn1/cbor/path) are the guard.
function cap(value, key, dflt, opts) {
  if (value === undefined) return dflt;
  opts = opts || {};
  var min = opts.min === undefined ? 0 : opts.min;
  // The bounds themselves are authoring inputs: a NaN / fractional min or max
  // compares false against every value, silently disabling the check (a NaN min
  // even REPLACES the default >= 0 floor). Always a config-time TypeError --
  // the bound wiring is broken regardless of the value currency opts.E selects.
  if (!Number.isInteger(min) || (opts.max !== undefined && !Number.isInteger(opts.max))) {
    throw new TypeError("guard.limits.cap: the min/max bounds for " + key + " must be integers");
  }
  if (!Number.isInteger(value) || value < min || (opts.max !== undefined && value > opts.max)) {
    var want = "an integer >= " + min + (opts.max !== undefined ? " and <= " + opts.max : "");
    if (min === 0 && opts.max === undefined) want = "a non-negative integer";
    if (opts.E) throw opts.E(opts.code, (opts.label || key) + " must be " + want);
    throw new TypeError("decode: " + key + " must be " + want);
  }
  return value;
}

// depthCap(value, key, dflt) -> a validated recursion-depth cap: cap() plus the
// stack-safe ceiling, so a raised maxDepth cannot drive recursive descent into a
// raw RangeError past the native frame limit.
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

// counter(max, E, code, label) -> { tick }. A parse-time item counter: the
// recursive decoder calls tick() once per decoded element so a small input
// cannot fan out into a massive eager node/element tree (CWE-770 / CWE-400 memory
// amplification -- the class pki.cbor closed with CBOR_MAX_ITEMS). Unlike cap
// (config-time TypeError), this is Tier-2 parse validation: an over-count throws
// the caller's typed PkiError via the E(code, message) factory. `max` is the
// caller's already-validated ceiling (an opts.maxItems run through cap()).
// @enforced-by behavioral -- a monotone counter has no rename-proof code shape
//   distinct from any `n++ > max` loop bound; the memory-fanout RED vectors (a
//   dense TLV run rejects at the cap) driving the composing decoders are the guard.
function counter(max, E, code, label) {
  // The ceiling is an authoring input: an undefined / NaN / fractional max
  // builds a counter whose `n > max` NEVER fires -- a silently dead fanout
  // defence. Reject at construction (config-time TypeError).
  if (!Number.isInteger(max) || max < 0) {
    throw new TypeError("guard.limits.counter: max must be a non-negative integer");
  }
  var n = 0;
  return {
    tick: function () {
      n += 1;
      if (n > max) throw E(code, (label || "decoded item") + " count exceeds the cap " + max);
    },
  };
}

module.exports = { cap: cap, depthCap: depthCap, counter: counter };
