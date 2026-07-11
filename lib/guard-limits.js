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

// cap(value, key, dflt) -> a validated non-negative integer, or dflt when value
// is undefined. A non-integer / non-finite / negative value is a config-time
// TypeError (Number.isInteger already rejects non-numbers, NaN, and Infinity).
function cap(value, key, dflt) {
  if (value === undefined) return dflt;
  if (!Number.isInteger(value) || value < 0) {
    throw new TypeError("decode: " + key + " must be a non-negative integer");
  }
  return value;
}

// depthCap(value, key, dflt) -> a validated recursion-depth cap: cap() plus the
// stack-safe ceiling, so a raised maxDepth cannot drive recursive descent into a
// raw RangeError past the native frame limit.
function depthCap(value, key, dflt) {
  var n = cap(value, key, dflt);
  if (n > constants.LIMITS.MAX_DECODE_DEPTH_CEILING) {
    throw new TypeError("decode: " + key + " " + n + " exceeds the stack-safe ceiling " + constants.LIMITS.MAX_DECODE_DEPTH_CEILING);
  }
  return n;
}

module.exports = { cap: cap, depthCap: depthCap };
