// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.parse (the detect-and-route orchestrator)
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: parsing hostile bytes
 * either succeeds or throws a pki.errors.PkiError -- any other throw (or a
 * hang) is a finding and is rethrown so the fuzzer records a reproducer.
 * This entry has hostile-input surface no per-format harness reaches: the
 * root decode accepts BER shapes (indefinite length, constructed strings)
 * that every strict-DER format harness rejects before its detectors run, the
 * label-agnostic PEM unwrap runs before routing, and the matches() detector
 * loop walks the decoded tree with positional child probes for every
 * registered format. It is also the fuzzed path into the crl, csr, and pkcs8
 * parsers the loop routes to.
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
