// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.x509.parseDn
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Its seed corpus
 * (`fuzz/dn-string_seed_corpus/`) carries the worked examples of RFC 4514
 * sec. 4 plus every escape form, so the mutator starts from strings the
 * scanner already walks rather than from noise.
 *
 * A distinguished-name string is text an operator can be handed: a
 * command-line argument, a config field, an enrollment request. So the
 * bytes are read as UTF-8 and fed to the verb the way a caller would.
 *
 * Contract: parsing an attacker-controlled name string has exactly two
 * acceptable outcomes -- a `{ rdns, dn, bytes }` result, or a thrown
 * `pki.errors.PkiError` (CertificateError / Asn1Error / OidError). Any
 * other throw (a RangeError from a length the string implies, a bare
 * TypeError from a value the scanner did not expect, a hang inside the
 * escape walk) means the scanner surfaced an unguarded invariant break on
 * hostile input: rethrow it so jazzer records the reproducer.
 *
 * The result is re-parsed when one comes back, because the verb's own
 * output is the input a caller is most likely to feed it next, and a
 * string that parses to something that does not parse is a defect the
 * single pass cannot see.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  var text = data.toString("utf8");
  var first;
  try {
    first = pki.x509.parseDn(text);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
  try {
    pki.x509.parseDn(first.dn);
  } catch (e2) {
    if (e2 instanceof pki.errors.PkiError) {
      throw new Error("parseDn emitted a dn string it cannot read back: " + JSON.stringify(first.dn));
    }
    throw e2;
  }
};
