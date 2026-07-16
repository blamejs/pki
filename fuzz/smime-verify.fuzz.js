// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.smime.verify (RFC 8551 S/MIME message layer).
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = async function (data). The contract: verifying hostile
 * message bytes either resolves or rejects/throws a pki.errors.PkiError -- any
 * other throw (or a hang) is a finding and is rethrown so the fuzzer records a
 * reproducer. This exercises the MIME frame parse (header split, folding,
 * multipart boundary walk), the RFC 8551 sec. 3.1.1 canonicalizer, the base64
 * transfer-encoding decode, and the delegation into the CMS verify path -- a
 * distinct surface from fuzz/smime-parse.fuzz.js (the ESS attribute decoders).
 */
var pki = require("..");

module.exports.fuzz = async function (data) {
  var buf = Buffer.from(data);
  try {
    await pki.smime.verify(buf);
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
};
