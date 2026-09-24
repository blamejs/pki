// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: certification-request linting via pki.lint.csr.
 *
 * libFuzzer / jazzer.js harness. The linter is the one toolkit surface whose DATA
 * path must NEVER throw: it surveys a corpus that includes malformed members, so a
 * hostile / truncated / non-DER input must return a LintReport (a `fatal`
 * lint/unparseable finding) rather than raise. This target drives two paths with the
 * fuzzer's bytes: (1) the raw bytes straight into lint.csr (exercises the never-throw
 * ingestion boundary), and (2) the bytes spliced over the tail of a real request so
 * the outer framing still parses and the RULE closures run on attacker-controlled
 * decoded structures. Both paths run once per named profile as well as under the
 * default rule set, because the TLS rows a caller names by profile are not in the
 * default set.
 *
 * Contract: lint.csr(bytes) has exactly ONE acceptable outcome -- it RETURNS a
 * report. Any throw at all (a PkiError the linter should have caught, a RangeError,
 * a bare TypeError, a hang) is an unguarded invariant break: rethrow so jazzer
 * records the reproducer. (LintError is config-time only and unreachable from a
 * bytes input.)
 */

var fs = require("fs");
var path = require("path");
var pki = require("..");

// A real certification request reused read-only as the splice base (its outer
// framing keeps the fuzzer's bytes reaching the rule closures after the splice).
var BASE = fs.readFileSync(path.join(__dirname, "lint-csr_seed_corpus", "full.der"));

// Every certification-request profile pki.lint.csr accepts by name, plus the default rule set
// (undefined), which runs the structural rows alone. DERIVED from the registry, so a profile added
// later is fuzzed without this list being edited.
var PROFILES = [undefined].concat(pki.lint.profiles().filter(function (name) {
  try { pki.lint.csr(BASE, { profile: name }); return true; } catch (_e) { return false; }
}));

function lintNeverThrows(input) {
  for (var i = 0; i < PROFILES.length; i++) {
    var report = PROFILES[i] === undefined
      ? pki.lint.csr(input)
      : pki.lint.csr(input, { profile: PROFILES[i] });
    // A returned report must always be well-formed (findings array + counts).
    if (!report || !Array.isArray(report.findings) || !report.counts) {
      throw new Error("lint.csr returned a malformed report");
    }
  }
}

module.exports.fuzz = function (data) {
  // (1) raw bytes -> the ingestion never-throw boundary.
  lintNeverThrows(data);

  // (2) splice onto a real request so the rules run on hostile decoded values.
  if (data.length >= 2) {
    var der = Buffer.from(BASE);
    var start = Math.max(0, der.length - data.length);
    data.copy(der, start, 0, Math.min(data.length, der.length - start));
    lintNeverThrows(der);
  }
};
