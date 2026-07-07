// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.pkcs12.parse
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: parsing hostile bytes
 * either succeeds or throws a pki.errors.PkiError — any other throw (or a
 * hang) is a finding and is rethrown so the fuzzer records a reproducer.
 * PKCS#12 exercises the BER fallback (indefinite lengths, constructed octet
 * strings), the cross-decode budget, and the CMS / PKCS#8 delegation seams.
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.pkcs12.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
