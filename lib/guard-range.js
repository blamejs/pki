// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// parsers whose decoded-integer bounds compose this guard (pki.schema.x509 /
// crl / pkcs12 / cmp, pki.path.validate).
//
// guard-range -- fail-closed bound of an untrusted DECODED integer before it is
// narrowed to a JS Number. Parse-time (Tier-2): the value is malformed content,
// so it throws the caller's typed PkiError -- distinct from guard-limits, which
// validates an operator-supplied option at config time (Tier-1, TypeError).
//
// Defends the silent-narrowing class (a decoded ASN.1 INTEGER past 2^53 rounds
// when coerced to a Number, so a caller acting on the result -- a pathLen /
// skipCerts / saltLength / iteration counter -- acts on the WRONG number;
// CWE-190 integer overflow / CWE-681 incorrect conversion). The bound and the
// narrow are ATOMIC here: a caller cannot obtain the Number without the range
// having been enforced, so the value can never round silently and be acted on.

// 2^31 - 1 -- the shared skip-cert / path-length / salt / iteration ceiling.
// This literal lives ONLY here (a re-inline anywhere else is flagged: the
// guard-shape walk anchors on the literal). 2^53 - 1 is the safe-narrow ceiling.
var UINT31_MAX = 2147483647n;
var SAFE_MAX   = 9007199254740991n;
var SAFE_MIN   = -9007199254740991n;
// 2^64 - 1 (also spelled 0xffffffffffffffffn). The uint64 ceiling lives ONLY here
// (both spellings are flagged as a re-inline; see uint64's @guard-shape lines).
var UINT64_MAX = 18446744073709551615n;

// int(value, min, max, E, code, label) -> a Number in [min, max].
//   value : the BigInt result of an ASN.1 INTEGER / ENUMERATED read.
//   min, max : inclusive BigInt bounds.
//   E     : the (code, message, cause) typed-error factory in scope at the call
//           site (ns.E / ctx.E / the module-local E) -- guard-range injects the
//           caller's typed error through it, the tier-appropriate currency (a
//           parse boundary carries a factory, not a bare ErrorClass).
//   code  : the frozen domain/reason code this field rejects under.
//   label : field phrase (+ optional RFC cite) for the message.
// @enforced-by guard-shape-reinlined
// @guard-shape 2147483647n
function int(value, min, max, E, code, label) {
  // Config-time authoring guard (Tier-1): the bounds must be BigInt -- a Number
  // bound (worst: NaN, which compares false against every BigInt) silently
  // disables the range so ANY decoded value narrows. Then: narrowing to Number
  // is lossless only when the WHOLE range sits inside the safe-integer band
  // [-(2^53-1), 2^53-1]. Both ends bind -- a min below the floor rounds a
  // decoded value near it just as a max above the ceiling does. A wider range
  // needs a BigInt-preserving guard, not this one (this is why the uint64
  // Merkle-coordinate domain must NOT route here).
  if (typeof min !== "bigint" || typeof max !== "bigint") {
    throw new TypeError("guard.range.int: the min/max bounds must be BigInt");
  }
  if (max > SAFE_MAX) {
    throw new TypeError("guard.range.int: max " + max + " exceeds the safe-integer ceiling; use a BigInt-preserving guard");
  }
  if (min < SAFE_MIN) {
    throw new TypeError("guard.range.int: min " + min + " is below the safe-integer floor; use a BigInt-preserving guard");
  }
  // Parse-time reject (Tier-2): malformed / out-of-range decoded content.
  if (typeof value !== "bigint" || value < min || value > max) {
    throw E(code, label + " must be an integer within " + min + ".." + max);
  }
  return Number(value);
}

// uint31(value, E, code, label) -> Number in [0, 2^31-1]. The DER-INTEGER
// non-negative skip/path/salt shape (RFC 5280 / 4211 / 9810).
// @enforced-by guard-shape-reinlined  (shares the 2147483647n shape declared on int)
function uint31(value, E, code, label) { return int(value, 0n, UINT31_MAX, E, code, label); }

// positiveInt31(value, E, code, label) -> Number in [1, 2^31-1]. The PKCS#12
// PBKDF2 / MAC iteration-count shape (a count of at least one).
// @enforced-by guard-shape-reinlined  (shares the 2147483647n shape declared on int)
function positiveInt31(value, E, code, label) { return int(value, 1n, UINT31_MAX, E, code, label); }

// uint64(value, E, code, label) -> a BigInt in [0, 2^64-1], WITHOUT narrowing to
// Number. Accepts a non-negative safe-integer Number (widened to BigInt) or a
// BigInt; a Number past 2^53 (precision already lost), a negative, a non-integer,
// or a non-number-non-bigint throws the caller's typed verdict. The uint64 domain
// (a Merkle tree coordinate RFC 9162, an SCT timestamp RFC 6962) must NOT route
// through int() -- narrowing to Number would corrupt the very value it guards, so
// this is the BigInt-preserving sibling int()'s authoring guard points callers to.
// @enforced-by guard-shape-reinlined
// @guard-shape 18446744073709551615n
// @guard-shape 0xffffffffffffffffn
function uint64(value, E, code, label) {
  var v;
  if (typeof value === "bigint") {
    v = value;
  } else if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    v = BigInt(value);
  } else {
    throw E(code, label + " must be a non-negative safe-integer Number or a BigInt (a uint64)");
  }
  if (v < 0n || v > UINT64_MAX) {
    throw E(code, label + " must be a uint64 in [0, 2^64)");
  }
  return v;
}

module.exports = { int: int, uint31: uint31, positiveInt31: positiveInt31, uint64: uint64 };
