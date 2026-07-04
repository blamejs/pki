// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.asn1.decode
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (local PRs) and
 * OSS-Fuzz (continuous, Google-hosted) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer
 * the engine mutates via coverage-guided fuzzing. Seeds for the
 * initial corpus live in `fuzz/asn1-der_seed_corpus/`.
 *
 * Contract: decoding attacker-controlled bytes has exactly two
 * acceptable outcomes — a successful decode, or a thrown
 * `pki.errors.PkiError` (Asn1Error / OidError on the DER path). Any
 * other throw (RangeError, stack overflow from unbounded recursion, a
 * bare TypeError, a hang) means the decoder surfaced an unguarded
 * invariant break on hostile input: rethrow it so jazzer records the
 * reproducer.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.asn1.decode(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
