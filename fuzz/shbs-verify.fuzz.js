// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.shbs.verify (HSS) + pki.shbs.verifyLms (LMS)
 *
 * Runs under libFuzzer via jazzer.js. The contract for this verify engine:
 * verifying attacker-controlled public-key / message / signature blobs may only
 * ever RETURN a boolean (valid / invalid) or THROW a pki.errors.PkiError
 * (ShbsError -- shbs/bad-public-key, shbs/bad-signature, shbs/unsupported-
 * parameter-set, shbs/bad-input). Any other throw -- a bare RangeError from the
 * bounded reader, a stack overflow from an unbounded HSS level / Merkle-fold
 * loop, a TypeError, a hang -- is a finding and is rethrown so the fuzzer records
 * a reproducer. The blobs are split at fuzzer-controlled offsets so the mutator
 * explores every field boundary (a lying typecode, a truncated auth path, an
 * out-of-range leaf index, a hostile HSS Nspk).
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  if (data.length < 5) return;
  var mode = data[0] & 1;
  var aLen = data.readUInt16BE(1) % (data.length + 1);
  var bLen = data.readUInt16BE(3) % (data.length + 1);
  var body = data.subarray(5);
  var a = body.subarray(0, Math.min(aLen, body.length));
  var b = body.subarray(Math.min(aLen, body.length), Math.min(aLen + bLen, body.length));
  var c = body.subarray(Math.min(aLen + bLen, body.length));

  try {
    if (mode === 0) pki.shbs.verify(a, b, c);
    else pki.shbs.verifyLms(a, b, c);
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
};
