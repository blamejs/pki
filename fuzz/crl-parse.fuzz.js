// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.crl.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. The seeds in
 * fuzz/crl-parse_seed_corpus/ exercise the front door, and the mutator
 * reaches the signed CertificateList envelope, the TBSCertList positional
 * walk (optional version / nextUpdate), the revokedCertificates run with
 * per-entry extensions, and the [0] EXPLICIT crlExtensions decode — the
 * same surface lib/path-validate.js drives on attacker-supplied CRL bytes.
 *
 * Contract: parsing an attacker-controlled CRL has exactly two acceptable
 * outcomes — a successful parse, or a thrown `pki.errors.PkiError`
 * (CrlError / Asn1Error / OidError / PemError). Any other throw
 * (RangeError, a stack overflow from the nested walk, a bare TypeError, a
 * hang) means the parser surfaced an unguarded invariant break on hostile
 * input: rethrow it so jazzer records the reproducer.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.crl.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
