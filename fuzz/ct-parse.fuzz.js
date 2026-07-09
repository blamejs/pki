// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.ct.parseSctList
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: parsing hostile bytes
 * either succeeds or throws a pki.errors.PkiError — any other throw (or a hang)
 * is a finding and is rethrown so the fuzzer records a reproducer. This target
 * exercises the RFC 6962 §3.3 inner DER OCTET-STRING peel and the bounded TLS
 * presentation-language decode (the list / SerializedSCT framing, the version
 * gate, the lying-length overrun checks, the DoS caps).
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.ct.parseSctList(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
