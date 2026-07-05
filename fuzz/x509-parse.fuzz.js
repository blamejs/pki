// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.x509.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (local PRs) and
 * OSS-Fuzz (continuous, Google-hosted) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer
 * the engine mutates via coverage-guided fuzzing. It reuses the ASN.1
 * seed corpus (`fuzz/asn1-der_seed_corpus/`) — a certificate is a DER
 * SEQUENCE, so those seeds exercise the parser's front door.
 *
 * Contract: parsing an attacker-controlled certificate has exactly two
 * acceptable outcomes — a successful parse, or a thrown
 * `pki.errors.PkiError` (CertificateError / Asn1Error / OidError). Any
 * other throw (RangeError, stack overflow, a bare TypeError, a hang)
 * means the parser surfaced an unguarded invariant break on hostile
 * input: rethrow it so jazzer records the reproducer.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.x509.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
