// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.csr.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. The seeds in
 * fuzz/csr-parse_seed_corpus/ exercise the front door, and the mutator
 * reaches the signed CertificationRequest envelope, the strict-INTEGER
 * version read, the Name / SubjectPublicKeyInfo sub-schemas, and the
 * [0] IMPLICIT attributes run with its SET-OF value lists.
 *
 * Contract: parsing an attacker-controlled certification request has
 * exactly two acceptable outcomes — a successful parse, or a thrown
 * `pki.errors.PkiError` (CsrError / Asn1Error / OidError / PemError). Any
 * other throw (RangeError, a stack overflow from the nested walk, a bare
 * TypeError, a hang) means the parser surfaced an unguarded invariant
 * break on hostile input: rethrow it so jazzer records the reproducer.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.csr.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
