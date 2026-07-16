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
 * gate, the lying-length overrun checks, the DoS caps). On a successful parse it
 * also round-trips through pki.ct.encodeSctList: re-encoding the parsed SCTs and
 * re-parsing MUST reproduce the same SCT set (encode is the exact inverse of parse),
 * or throw a PkiError -- never a raw throw.
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  var parsed;
  try {
    parsed = pki.ct.parseSctList(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
  try {
    if (parsed.all.length === 0) return;                // parse never yields an empty non-throwing list, but guard anyway
    // .all preserves wire order across known + unknown, so the re-encode is byte-identical.
    if (!pki.ct.encodeSctList(parsed.all).equals(data)) {
      throw new Error("ct encode(parse.all) is not byte-identical to the input");
    }
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
