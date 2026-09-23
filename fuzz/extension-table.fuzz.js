// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: the extension doors -- pki.schema.<format>.decodeExtensions
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing.
 *
 * The parse targets already fuzz what `parse` reads. This one reaches what
 * `parse` deliberately does NOT read: the extnValue octets, decoded through
 * the scope registry. One input drives all five doors, so a value that is a
 * certificate extension at one scope and something else at another is
 * exercised both ways, and the decoders reached only through a door
 * (issuingDistributionPoint, deltaCRLIndicator, ipAddrBlocks,
 * autonomousSysIds, tlsFeature) get the same mutation pressure as the ones
 * a parse decodes. Each door is driven in both modes on every input rather
 * than selecting one from the bytes: every object these parsers accept opens
 * with the SEQUENCE tag, so a mode chosen from the input would be the same
 * mode for every input that reaches a decoder at all.
 *
 * Contract: decoding attacker-controlled extension values has exactly two
 * acceptable outcomes -- a table, or a thrown `pki.errors.PkiError`. Any
 * other throw (a RangeError, a stack overflow from a nested value, a bare
 * TypeError, a hang) means a door surfaced an unguarded invariant break on
 * hostile input: rethrow it so jazzer records the reproducer.
 */

var pki = require("..");

var DOORS = [
  pki.schema.x509.decodeExtensions,
  pki.schema.crl.decodeExtensions,
  pki.schema.csr.decodeExtensions,
  pki.schema.attrcert.decodeExtensions,
  pki.schema.crmf.decodeExtensions,
];

var MODES = [undefined, { strict: true }];

module.exports.fuzz = function (data) {
  for (var i = 0; i < DOORS.length; i++) {
    for (var m = 0; m < MODES.length; m++) {
      try {
        DOORS[i](data, MODES[m]);
      } catch (e) {
        if (e instanceof pki.errors.PkiError) continue;
        throw e;
      }
    }
  }
};
