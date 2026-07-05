// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.cms.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. It reuses the ASN.1 seed
 * corpus — a CMS ContentInfo is a DER SEQUENCE, so those seeds exercise
 * the OID-dispatch envelope's front door.
 *
 * Contract: parsing an attacker-controlled CMS message has exactly two
 * acceptable outcomes — a successful parse, or a thrown
 * `pki.errors.PkiError` (CmsError / Asn1Error / OidError / PemError). Any
 * other throw (RangeError, stack overflow from the nested SignedData →
 * SignerInfo → SignedAttributes walk, a bare TypeError, a hang) means the
 * parser surfaced an unguarded invariant break on hostile input: rethrow
 * it so jazzer records the reproducer.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.cms.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
