// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.pem.decodeBundle
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Its seed corpus
 * (`fuzz/pem-bundle_seed_corpus/`) carries a file per shape the scanner
 * branches on: several blocks, explanatory text around them, each line
 * ending, a boundary that never closes, a block closed under another
 * label, an RFC 1421 encrypted body, and the boundary look-alikes that
 * must read as text.
 *
 * A PEM bundle is a file an operator hands a tool: a fullchain a server
 * was configured with, an anchor store downloaded from a vendor. So the
 * bytes are read as the latin1 the reader reads and fed to the verb the
 * way a caller would.
 *
 * Contract: reading an attacker-controlled file has exactly two acceptable
 * outcomes -- a list of rows, or a thrown `pki.errors.PkiError`. Any other
 * throw (a RangeError from a length the text implies, a bare TypeError from
 * a value the scanner did not expect, a hang inside the block walk) means
 * the reader surfaced an unguarded invariant break on hostile input:
 * rethrow it so jazzer records the reproducer.
 *
 * What comes out is written back and read again, because a file this
 * toolkit wrote is a file it must read, and because the strict writer is
 * what keeps a label from carrying a boundary into the text.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  var text = data.toString("latin1");
  var rows;
  try {
    rows = pki.schema.pem.decodeBundle(text);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error("decodeBundle returned no rows without refusing: " + JSON.stringify(text.slice(0, 120)));
  }
  for (var i = 0; i < rows.length; i++) {
    if (rows[i].index !== i) throw new Error("row " + i + " reports index " + rows[i].index);
    if (!Buffer.isBuffer(rows[i].der)) throw new Error("row " + i + " carries no DER buffer");
    if (typeof rows[i].offset !== "number" || rows[i].offset < 0) {
      throw new Error("row " + i + " carries no byte offset");
    }
  }
  var written;
  try {
    written = pki.schema.pem.encodeBundle(rows);
  } catch (e2) {
    // The reader takes every label RFC 7468 sec. 3 admits and the writer takes the uppercase form
    // this toolkit emits, so a lowercase or punctuated label is a refusal here and not a defect.
    if (e2 instanceof pki.errors.PkiError) return;
    throw e2;
  }
  var again = pki.schema.pem.decodeBundle(written);
  if (again.length !== rows.length) {
    throw new Error("a written bundle read back to " + again.length + " rows, not " + rows.length);
  }
  for (var j = 0; j < again.length; j++) {
    if (!again[j].der.equals(rows[j].der)) throw new Error("row " + j + " changed across a write and a read");
    if (again[j].label !== rows[j].label) throw new Error("row " + j + " changed label across a write and a read");
  }
  if (pki.schema.pem.encodeBundle(again) !== written) {
    throw new Error("writing a bundle twice produced different text");
  }
};
