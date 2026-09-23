// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.pkcs11.parseUri
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Its seed corpus
 * (`fuzz/pkcs11-uri_seed_corpus/`) carries the worked examples of RFC 7512
 * sec. 3 plus one file per ABNF rule the scanner branches on, so the
 * mutator starts from strings the reader already walks rather than noise.
 *
 * A PKCS #11 URI is text an operator can be handed: a command-line
 * argument, a config field, an environment variable. So the bytes are read
 * as UTF-8 and fed to the verb the way a caller would.
 *
 * Contract: parsing an attacker-controlled URI has exactly two acceptable
 * outcomes -- a `{ path, vendorPath, query, vendorQuery }` result, or a
 * thrown `pki.errors.PkiError`. Any other throw (a RangeError from a
 * length the string implies, a bare TypeError from a value the scanner did
 * not expect, a hang inside the escape walk) means the scanner surfaced an
 * unguarded invariant break on hostile input: rethrow it so jazzer records
 * the reproducer.
 *
 * The result is written back and read again, because the verb's own output
 * is the input a caller is most likely to feed it next, and a URI that
 * parses to something that does not parse is a defect the single pass
 * cannot see. Reading and writing a second time must produce the same
 * string as the first, which is what a consumer comparing two URIs as
 * strings relies on.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  var text = data.toString("utf8");
  var first;
  try {
    first = pki.pkcs11.parseUri(text);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
  var written;
  try {
    written = pki.pkcs11.formatUri(first);
  } catch (e2) {
    if (e2 instanceof pki.errors.PkiError) {
      throw new Error("parseUri read a URI formatUri cannot write back: " + JSON.stringify(text));
    }
    throw e2;
  }
  var again;
  try {
    again = pki.pkcs11.formatUri(pki.pkcs11.parseUri(written));
  } catch (e3) {
    if (e3 instanceof pki.errors.PkiError) {
      throw new Error("formatUri emitted a URI parseUri cannot read back: " + JSON.stringify(written));
    }
    throw e3;
  }
  if (again !== written) {
    throw new Error("formatUri is not stable: " + JSON.stringify(written) + " became " + JSON.stringify(again));
  }
};
