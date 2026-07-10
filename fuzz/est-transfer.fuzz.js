// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.est.transferDecode + pki.est.splitMultipartMixed
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract for these hostile-input
 * codecs: each call either succeeds or throws a pki.errors.PkiError (EstError) --
 * any other throw (a RangeError from a malformed multipart split, a bare
 * TypeError, a hang) is a finding and is rethrown so the fuzzer records a
 * reproducer. Exercises the RFC 8951 sec. 3.1 base64 transfer decode (whitespace
 * tolerance, the alphabet gate, the size caps) and the RFC 2046 multipart/mixed
 * splitter (boundary extraction, the terminal-boundary requirement, per-part
 * header parsing) on attacker-controlled bytes.
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  var s = data.toString("latin1");
  try {
    pki.est.transferDecode(s);
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
  try {
    // Feed the fuzz bytes as both the body and a boundary-bearing content-type.
    pki.est.splitMultipartMixed(s, 'multipart/mixed; boundary="' + s.slice(0, 16).replace(/[";\r\n]/g, "") + '"');
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
};
