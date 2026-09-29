// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.merkle.root / inclusionProof / consistencyProof
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: a producing call on
 * hostile inputs either returns or throws a pki.errors.PkiError -- any other
 * throw (a RangeError from the tree recursion, a BigInt fault, an unhandled
 * edge) or a hang is a finding and is rethrown so the fuzzer records a
 * reproducer. The harness slices the fuzzer bytes into leaves of the 32-byte
 * width the verbs require and of a ragged width they must refuse, seeds the
 * coordinates from two leading bytes, and folds every proof it produces back
 * through the matching verifier so a producer that emits a path the toolkit's
 * own fold cannot walk is a finding too.
 */
var pki = require("..");

function guard(fn) {
  try { return fn(); } catch (e) { if (e instanceof pki.errors.PkiError) return null; throw e; }
}

module.exports.fuzz = function (data) {
  var a = data.length > 0 ? BigInt(data[0]) : 0n;
  var b = data.length > 1 ? BigInt(data[1]) : 0n;

  var wide = [];
  for (var off = 2; off + 32 <= data.length && wide.length < 64; off += 32) {
    wide.push(data.subarray(off, off + 32));
  }
  // Leaves of a width the verbs must refuse, alongside the well-formed set.
  var ragged = [];
  for (var r = 2; r + 7 <= data.length && ragged.length < 8; r += 7) {
    ragged.push(data.subarray(r, r + 7));
  }

  guard(function () { pki.merkle.root(wide); });
  guard(function () { pki.merkle.root(ragged); });
  guard(function () { pki.merkle.inclusionProof({ leafHashes: ragged, leafIndex: a }); });
  guard(function () { pki.merkle.consistencyProof({ leafHashes: ragged, oldSize: a }); });

  // Every produced proof must fold back through the shipped verifier: a path the
  // toolkit cannot walk is as much a finding as a throw.
  var rootHash = guard(function () { return pki.merkle.root(wide); });
  if (rootHash === null || wide.length === 0) return;

  var proof = guard(function () {
    return pki.merkle.inclusionProof({ leafHashes: wide, leafIndex: a });
  });
  if (proof !== null) {
    // A produced path means the index was in range, so the fold is driven with
    // the same coordinate the path was produced for.
    guard(function () {
      var i = Number(a);
      pki.merkle.verifyInclusion({
        leafIndex: i, treeSize: wide.length, leafHash: wide[i], proof: proof, rootHash: rootHash,
      });
    });
  }

  var cons = guard(function () {
    return pki.merkle.consistencyProof({ leafHashes: wide, oldSize: b });
  });
  if (cons !== null) {
    guard(function () {
      var m = Number(b);
      pki.merkle.verifyConsistency({
        oldSize: m, newSize: wide.length,
        oldRoot: pki.merkle.root(wide.slice(0, m)), newRoot: rootHash, proof: cons,
      });
    });
  }

  // The coordinates above are raw bytes and usually overshoot the tree, so the
  // refusal paths dominate. Fold the same bytes into range as well, so every
  // input also walks the accept path and the round-trip it ends in.
  var i2 = Number(a % BigInt(wide.length));
  var m2 = Number(b % BigInt(wide.length)) + 1;
  guard(function () {
    var p = pki.merkle.inclusionProof({ leafHashes: wide, leafIndex: i2 });
    pki.merkle.verifyInclusion({
      leafIndex: i2, treeSize: wide.length, leafHash: wide[i2], proof: p, rootHash: rootHash,
    });
  });
  guard(function () {
    var p = pki.merkle.consistencyProof({ leafHashes: wide, oldSize: m2 });
    pki.merkle.verifyConsistency({
      oldSize: m2, newSize: wide.length,
      oldRoot: pki.merkle.root(wide.slice(0, m2)), newRoot: rootHash, proof: p,
    });
  });
};
