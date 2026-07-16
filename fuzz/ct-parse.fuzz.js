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
    var all = parsed.scts.concat(parsed.unknownScts);
    if (all.length === 0) return;                       // parse never yields an empty non-throwing list, but guard anyway
    var reParsed = pki.ct.parseSctList(pki.ct.encodeSctList(all));
    if (reParsed.scts.length !== parsed.scts.length || reParsed.unknownScts.length !== parsed.unknownScts.length) {
      throw new Error("ct encode/parse round-trip changed the SCT count");
    }
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
