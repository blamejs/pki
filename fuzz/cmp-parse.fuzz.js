// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.cmp.parse
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: parsing hostile bytes
 * either succeeds or throws a pki.errors.PkiError — any other throw (or a
 * hang) is a finding and is rethrown so the fuzzer records a reproducer. CMP
 * exercises the 27-arm body dispatch, the CRMF / CMS composition seams, the
 * named-bit failInfo reader, and the cross-field protection/version checks.
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.cmp.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
