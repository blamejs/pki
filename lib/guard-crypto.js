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

var nodeCrypto = require("node:crypto");

// constantTimeEqual(a, b) -> boolean. Length-checked, then constant-time over
// equal lengths. a and b are Buffers.
function constantTimeEqual(a, b) {
  return a.length === b.length && nodeCrypto.timingSafeEqual(a, b);
}

module.exports = { constantTimeEqual: constantTimeEqual };
