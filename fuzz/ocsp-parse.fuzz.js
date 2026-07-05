// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.ocsp.parseRequest + pki.schema.ocsp.parseResponse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Both OCSP entry points are
 * driven on the same input — an OCSPRequest and an OCSPResponse are both
 * DER SEQUENCEs, so the shared ASN.1 seed corpus exercises both front
 * doors, and the response path additionally drives the ResponseBytes
 * OID-dispatch + the nested BasicOCSPResponse re-decode.
 *
 * Contract: parsing an attacker-controlled OCSP message has exactly two
 * acceptable outcomes — a successful parse, or a thrown
 * `pki.errors.PkiError` (OcspError / Asn1Error / OidError / PemError). Any
 * other throw (RangeError, a stack overflow from the nested walk, a bare
 * TypeError, a hang) means the parser surfaced an unguarded invariant
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
  drive(pki.schema.ocsp.parseResponse, data);
  drive(pki.schema.ocsp.parseRequest, data);
};
