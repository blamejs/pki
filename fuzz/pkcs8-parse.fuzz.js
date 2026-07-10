// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.pkcs8.parse + pki.schema.pkcs8.parseEncrypted
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Both PKCS#8 entry points are
 * driven on the same input — a PrivateKeyInfo and an
 * EncryptedPrivateKeyInfo are both DER SEQUENCEs, so every seed in
 * fuzz/pkcs8-parse_seed_corpus/ exercises both front doors. parseEncrypted
 * matters doubly: its SEQUENCE{SEQUENCE, OCTET STRING} shape is ambiguous
 * with a PKCS#1 DigestInfo, so it is deliberately NOT auto-routed by
 * pki.schema.parse and no other harness reaches it even indirectly.
 *
 * Contract: parsing attacker-controlled key material has exactly two
 * acceptable outcomes — a successful parse, or a thrown
 * `pki.errors.PkiError` (Pkcs8Error / Asn1Error / OidError / PemError).
 * Any other throw (RangeError, a stack overflow from the nested walk, a
 * bare TypeError, a hang) means the parser surfaced an unguarded invariant
 * break on hostile input: rethrow it so jazzer records the reproducer.
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
  drive(pki.schema.pkcs8.parse, data);
  drive(pki.schema.pkcs8.parseEncrypted, data);
};
