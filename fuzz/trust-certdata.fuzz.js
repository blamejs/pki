// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.trust.parseCertdata + pki.trust.parseCcadbCsv
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: each call either
 * succeeds or throws a pki.errors.PkiError (TrustError) -- any other throw (a
 * RangeError from an unbounded octal walk, a TypeError from a hostile CSV
 * shape, a hang on a block bomb) is a finding and is rethrown so the fuzzer
 * records a reproducer. The fuzz bytes are fed to both text lexers raw: the
 * certdata object-stream lexer (MULTILINE_OCTAL decoding, attribute typing,
 * pairing) and the RFC 4180 CSV sub-lexer (quoting, header mapping, date and
 * PEM cells) both run on attacker-controlled input.
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  try { pki.trust.parseCertdata(data); }
  catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }

  try { pki.trust.parseCcadbCsv(data); }
  catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }
};
