// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.identity.match
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Its seed corpus
 * (`fuzz/identity-match_seed_corpus/`) carries a certificate per entry
 * form the matcher branches on: a wildcard dNSName, an IPv6 iPAddress,
 * an RFC 4985 SRVName otherName, a URI with no authority, and a
 * certificate presenting several hundred subjectAltName entries.
 *
 * Both sides of this verb come from outside: the certificate is whatever
 * a peer presented, and a reference identity is whatever a caller built
 * from the name it was trying to reach. So the input is split and read as
 * both, which is how a caller drives it.
 *
 * Contract: an identity check on hostile bytes has exactly two acceptable
 * outcomes -- a verdict object, or a thrown `pki.errors.PkiError`. Any
 * other throw (a RangeError from a length the DER implies, a bare
 * TypeError from a value an arm did not expect, a hang inside the label
 * walk) means an unguarded invariant break: rethrow it so jazzer records
 * the reproducer. A verdict that reports a match without naming what
 * matched is the second contract, because a caller reads
 * `matchedReference` as the validated identity of the service
 * (RFC 9525 sec. 6.6).
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  if (data.length < 2) return;
  // The last byte picks how much of the input is read as the certificate, so the
  // engine can steer both sides from one buffer.
  var split = 1 + (data[data.length - 1] % (data.length - 1));
  var certBytes = data.subarray(0, split);
  var refText = data.subarray(split, data.length - 1).toString("latin1");
  var references = [refText === "" ? "example.com" : refText];

  var verdict;
  try {
    verdict = pki.identity.match(certBytes, references);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
  if (!verdict || typeof verdict.matched !== "boolean") {
    throw new Error("match returned no verdict: " + JSON.stringify(verdict));
  }
  if (verdict.matched) {
    if (verdict.matchedReference === null || verdict.matchedEntry === null) {
      throw new Error("a match names neither the reference nor the entry that matched");
    }
  } else if (verdict.reason === null) {
    throw new Error("a failure carries no reason");
  }
  if (!Array.isArray(verdict.ignored)) throw new Error("the verdict carries no ignored list");

  // The same certificate under the record forms, so the SRV and URI arms are reached by a
  // reference the engine did not have to guess the shape of.
  var records = [
    { type: "srv", service: "_imap", value: "example.com" },
    { type: "uri", scheme: "https", value: "example.com" },
  ];
  for (var i = 0; i < records.length; i++) {
    try { pki.identity.match(certBytes, records[i]); }
    catch (e2) {
      if (e2 instanceof pki.errors.PkiError) continue;
      throw e2;
    }
  }
};
