// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.pkcs1.parse and .parsePublic
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Its seed corpus
 * (`fuzz/pkcs1-parse_seed_corpus/`) carries a real 2048-bit key, its
 * public half, a multi-prime key, and one file per relation the reader
 * checks, so the mutator starts from structures the reader already walks.
 *
 * A PKCS#1 key is a file an operator hands a tool: the `RSA PRIVATE KEY`
 * an appliance exported, the key half of a certificate bundle. So the
 * bytes are fed to the verb the way a caller would.
 *
 * Contract: parsing an attacker-controlled key has exactly two acceptable
 * outcomes -- a structure, or a thrown `pki.errors.PkiError`. Any other
 * throw (a RangeError from a length the DER implies, a bare TypeError
 * from a component the reader did not expect) means the reader surfaced
 * an unguarded invariant break: rethrow it so jazzer records the
 * reproducer.
 *
 * What parses is written back and read again, because a structure this
 * toolkit accepts is one it must be able to write, and a key that parses
 * to something that does not parse is a defect one pass cannot see.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  var key;
  try {
    key = pki.schema.pkcs1.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) {
      // The public reader takes the same bytes. It has its own shape rule, so it may accept what
      // the private one refused; either answer is fine and a raw throw is not.
      try { pki.schema.pkcs1.parsePublic(data); } catch (e2) {
        if (e2 instanceof pki.errors.PkiError) return;
        throw e2;
      }
      return;
    }
    throw e;
  }
  if (typeof key.modulus !== "bigint" || key.modulus <= 0n) {
    throw new Error("parse returned a key whose modulus is not a positive integer");
  }
  if (key.publicExponent < 3n || key.publicExponent >= key.modulus || (key.publicExponent & 1n) === 0n) {
    throw new Error("parse returned a public exponent outside 3 <= e < n or an even one");
  }
  var written;
  try {
    written = pki.schema.pkcs1.encode(key);
  } catch (e3) {
    if (e3 instanceof pki.errors.PkiError) {
      throw new Error("parse accepted a key encode cannot write back");
    }
    throw e3;
  }
  var again = pki.schema.pkcs1.parse(written);
  if (again.modulus !== key.modulus || again.coefficient !== key.coefficient ||
      again.otherPrimeInfos.length !== key.otherPrimeInfos.length) {
    throw new Error("a key changed across a write and a read");
  }
};
