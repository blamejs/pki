// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.kem.decapsulate + pki.kem.encapsulate (composite ML-KEM,
 * draft-ietf-lamps-pq-composite-kem).
 *
 * Runs under libFuzzer via jazzer.js. The contract: parsing attacker-controlled
 * composite private-key / public-key / ciphertext bytes and running the component
 * KEMs + SHA3-256 combiner may only ever RESOLVE (a shared secret) or REJECT with a
 * pki.errors.PkiError (KemError -- kem/bad-input, kem/bad-key, kem/bad-ciphertext,
 * kem/bad-algorithm, kem/unsupported-algorithm, kem/decapsulation-failed). Any other
 * throw or rejection -- a bare RangeError from a bounds slip, a TypeError, a raw
 * OpenSSL error escaping a component operation, a hang -- is a finding and is
 * rethrown so the fuzzer records a reproducer. The input is split at a
 * fuzzer-controlled offset so the mutator explores every field boundary of the raw
 * concatenation encodings (a lying OID, a truncated ML-KEM half, a malformed
 * traditional component, a mangled ciphertext).
 */
var pki = require("..");

module.exports.fuzz = async function (data) {
  if (data.length < 3) return;
  var mode = data[0] & 1;
  var aLen = data.readUInt16BE(1) % (data.length + 1);
  var body = data.subarray(3);
  var a = body.subarray(0, Math.min(aLen, body.length));
  var b = body.subarray(Math.min(aLen, body.length));
  try {
    if (mode === 0) await pki.kem.decapsulate(a, b);
    else await pki.kem.encapsulate(a);
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
};
