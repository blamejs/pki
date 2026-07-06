// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.attrcert.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. An AttributeCertificate is a
 * DER SEQUENCE, so the shared ASN.1 seed corpus exercises the front door;
 * the parser drives the signed envelope, the validated GeneralNames, the
 * IMPLICIT-tagged Holder / V2Form bodies, and the ENUMERATED / GeneralizedTime
 * leaves.
 *
 * Contract: parsing an attacker-controlled attribute certificate has exactly
 * two acceptable outcomes — a successful parse, or a thrown
 * `pki.errors.PkiError` (AttrCertError / Asn1Error / OidError / PemError). Any
 * other throw (RangeError, a stack overflow from the nested walk, a bare
 * TypeError, a hang) means the parser surfaced an unguarded invariant break on
 * hostile input: rethrow it so jazzer records the reproducer.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.attrcert.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
