// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// verify paths whose comparison composes this guard (pki.merkle,
// pki.webcrypto.subtle.verify).
//
// guard-crypto -- fail-closed cryptographic-invariant guards. Enforced choke
// point: a codebase-patterns detector requires every constant-time byte
// comparison to route through here, so no verify path re-implements it with a
// timing leak.
//
// Defends the timing side-channel class (CWE-208 observable timing discrepancy;
// the Lucky13 / MAC-forgery family). A secret-dependent byte comparison with an
// early exit (=== or a short-circuited &&) leaks the position of the first
// differing byte, letting an attacker recover a MAC / tag / tree root
// byte-by-byte. constantTimeEqual runs the whole comparison: a public length
// gate (lengths are not secret; crypto.timingSafeEqual RangeErrors on unequal
// lengths, so the gate must precede it) then a single timingSafeEqual over the
// equal-length buffers -- both operands are always read, no data-dependent
// branch. A length mismatch is an honest false, never a throw.
//
// Also defends the signature-malleability class (CWE-347 / CWE-20): a signature /
// MAC / digest BIT STRING with a non-zero unused-bits count is not whole octets,
// so trailing sub-octet bits let two encodings carry "one" signature. Every RFC
// 9481/4211/6960/5280 signature output is a whole number of octets, so a value
// with unusedBits !== 0 fails closed BEFORE its bytes reach a verifier.

var nodeCrypto = require("node:crypto");

// constantTimeEqual(a, b) -> boolean. Length-checked, then constant-time over
// equal lengths. a and b are Buffers.
// @enforced-by guard-shape-reinlined
// @guard-shape \.timingSafeEqual\s*\(
function constantTimeEqual(a, b) {
  return a.length === b.length && nodeCrypto.timingSafeEqual(a, b);
}

// isOctetAligned(bitString) -> boolean. True when a decoded BIT STRING (a
// { bytes, unusedBits } node) is whole octets. For the never-throw verify paths
// (a boolean/continue verdict) so a malleable signature is skipped, not honored.
// @enforced-by behavioral -- shares the octet-alignment rule below; a bare
//   .unusedBits check has legitimate non-signature siblings, so the RED vectors
//   (a non-octet-aligned signature is skipped / rejected) are the guard.
function isOctetAligned(bitString) {
  return !!bitString && bitString.unusedBits === 0;
}

// assertOctetAligned(bitString, E, code, label) -> bitString | throws E(code,...).
// The throwing form for a parse boundary: a signature / MAC / digest BIT STRING
// MUST be octet-aligned, else the malleable value is rejected fail-closed.
// @enforced-by behavioral -- .unusedBits !== 0 is a per-field RFC rule, and the
//   same token legitimately tests a DIFFERENT invariant (NamedBitList minimality,
//   schema-engine assertMinimalNamedBits), so a blanket detector would false-fire;
//   the RED vectors (a non-octet-aligned signature/digest rejects) are the guard.
function assertOctetAligned(bitString, E, code, label) {
  if (!isOctetAligned(bitString)) {
    throw E(code, (label || "signature") + " BIT STRING must be octet-aligned (0 unused bits)");
  }
  return bitString;
}

module.exports = { constantTimeEqual: constantTimeEqual, isOctetAligned: isOctetAligned, assertOctetAligned: assertOctetAligned };
