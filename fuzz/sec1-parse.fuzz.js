// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.sec1.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Its seed corpus
 * (`fuzz/sec1-parse_seed_corpus/`) carries a real key on each of the three
 * NIST curves, one with no stored point, one with a compressed point, and
 * one file per rule the reader applies to the scalar and the parameters
 * field.
 *
 * A SEC1 key is a file an operator hands a tool: the `EC PRIVATE KEY` an
 * appliance exported. So the bytes are fed to the verb the way a caller
 * would.
 *
 * Contract: parsing an attacker-controlled key has exactly two acceptable
 * outcomes -- a structure, or a thrown `pki.errors.PkiError`. Any other
 * throw means the reader surfaced an unguarded invariant break on hostile
 * input: rethrow it so jazzer records the reproducer.
 *
 * What parses is written back and read again: a key this toolkit accepts
 * is one it must be able to write, with the curve it named still on it.
 */

var pki = require("..");

var SCALAR_BYTES = { prime256v1: 32, secp384r1: 48, secp521r1: 66, secp256k1: 32,
  brainpoolP256r1: 32, brainpoolP384r1: 48, brainpoolP512r1: 64 };

module.exports.fuzz = function (data) {
  var key;
  try {
    key = pki.schema.sec1.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
  if (key.version !== 1) throw new Error("parse returned a version other than 1");
  var width = SCALAR_BYTES[key.curve];
  if (width === undefined) throw new Error("parse returned a curve with no scalar width: " + key.curve);
  if (key.privateKey.length !== width) {
    throw new Error("parse returned a " + key.privateKey.length + "-octet scalar on " + key.curve);
  }
  if (key.publicKey !== undefined) {
    var form = key.publicKey[0];
    var expect = form === 0x04 ? 1 + 2 * width : 1 + width;
    if ((form !== 0x04 && form !== 0x02 && form !== 0x03) || key.publicKey.length !== expect) {
      throw new Error("parse returned a stored point outside the forms RFC 5480 sec. 2.2 names");
    }
  }
  var written;
  try {
    written = pki.schema.sec1.encode(key);
  } catch (e2) {
    if (e2 instanceof pki.errors.PkiError) throw new Error("parse accepted a key encode cannot write back");
    throw e2;
  }
  var again = pki.schema.sec1.parse(written);
  if (!again.privateKey.equals(key.privateKey) || again.curve !== key.curve) {
    throw new Error("a key changed across a write and a read");
  }
};
