// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.crmf.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. The seeds in
 * fuzz/crmf-parse_seed_corpus/ exercise the front door, and the mutator
 * reaches the IMPLICIT-TAGS CertTemplate run, the dual-accepted
 * issuer / subject Name dispatch, the EXPLICIT OptionalValidity times, and
 * the ProofOfPossession CHOICE arms.
 *
 * Contract: parsing an attacker-controlled certificate request message has
 * exactly two acceptable outcomes — a successful parse, or a thrown
 * `pki.errors.PkiError` (CrmfError / Asn1Error / OidError / PemError). Any
 * other throw (RangeError, a stack overflow from the nested walk, a bare
 * TypeError, a hang) means the parser surfaced an unguarded invariant break
 * on hostile input: rethrow it so jazzer records the reproducer.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.crmf.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
