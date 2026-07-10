// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.tsp.parse + parseTstInfo + parseToken
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. All three RFC 3161 entry
 * points are driven on the same input — a TimeStampResp, a bare TSTInfo,
 * and a TimeStampToken are all DER SEQUENCEs, so every seed in
 * fuzz/tsp-parse_seed_corpus/ exercises every front door; the token path
 * additionally drives the CMS composition and the nested TSTInfo re-decode.
 *
 * Contract: parsing an attacker-controlled timestamp structure has exactly
 * two acceptable outcomes — a successful parse, or a thrown
 * `pki.errors.PkiError` (TspError / CmsError / Asn1Error / OidError /
 * PemError). Any other throw (RangeError, a stack overflow from the nested
 * walk, a bare TypeError, a hang) means the parser surfaced an unguarded
 * invariant break on hostile input: rethrow it so jazzer records the
 * reproducer.
 */

var pki = require("..");

function drive(fn, data) {
  try {
    fn(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
}

module.exports.fuzz = function (data) {
  drive(pki.schema.tsp.parse, data);
  drive(pki.schema.tsp.parseTstInfo, data);
  drive(pki.schema.tsp.parseToken, data);
};
