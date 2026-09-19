// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.cms.verifyDigest
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Its seed corpus
 * (`fuzz/cms-digest_seed_corpus/`) carries attached and detached
 * DigestedData messages under each supported digest, so the mutator starts
 * from a shape the OID-dispatch envelope already routes.
 *
 * Contract: verifying an attacker-controlled DigestedData has exactly two
 * acceptable outcomes — a verdict (`valid` true or false), or a thrown
 * `pki.errors.PkiError` (CmsError / Asn1Error / OidError / PemError). Any
 * other throw (a RangeError from a length the message claims and does not
 * carry, a bare TypeError, a hang) means the verb surfaced an unguarded
 * invariant break on hostile input: rethrow it so jazzer records the
 * reproducer.
 *
 * Two modes, selected by the input's parity, because the content a detached
 * message covers is a second attacker-controlled input and reaches a
 * different door than the message itself.
 */

var fs = require("node:fs");
var path = require("node:path");
var pki = require("..");

// A valid detached DigestedData, loaded once. Mode B splices the fuzzer's bytes
// in as the external content so the recompute + compare path runs on them.
var DETACHED = fs.readFileSync(path.join(__dirname, "cms-digest_seed_corpus", "sha256-detached.bin"));

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  if (data.length < 1) return;
  var buf = Buffer.from(data);
  try {
    if (data.length & 1) {
      // Mode B: valid detached message, attacker-controlled content.
      await pki.cms.verifyDigest(DETACHED, { content: buf });
    } else {
      // Mode A: the whole DigestedData DER is hostile.
      await pki.cms.verifyDigest(buf);
    }
  } catch (e) { if (!isPki(e)) throw e; }
};
