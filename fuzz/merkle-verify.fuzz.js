// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.merkle.verifyInclusion / verifyConsistency (+ the tree hashes)
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: a verify call on hostile
 * inputs either returns a boolean or throws a pki.errors.PkiError -- any other
 * throw (a RangeError from timingSafeEqual on a length mismatch, a BigInt fault,
 * an unhandled edge) or a hang is a finding and is rethrown so the fuzzer records
 * a reproducer. The harness derives tree coordinates + a leaf/root hash + a proof
 * (32-byte chunks) from the fuzzer bytes and drives both fold algorithms and the
 * RFC 6962 domain-separated hash producers.
 */
var pki = require("..");

function guard(fn) {
  try { fn(); } catch (e) { if (e instanceof pki.errors.PkiError) return; throw e; }
}

module.exports.fuzz = function (data) {
  // Two leading bytes seed the coordinates; the remainder is sliced into
  // 32-byte hash chunks (leafHash, rootHash, then proof nodes).
  var a = data.length > 0 ? BigInt(data[0]) : 0n;
  var b = data.length > 1 ? BigInt(data[1]) : 0n;
  var chunks = [];
  for (var off = 2; off + 32 <= data.length && chunks.length < 80; off += 32) {
    chunks.push(data.subarray(off, off + 32));
  }
  var leafHash = chunks.length > 0 ? chunks[0] : data.subarray(0, Math.min(data.length, 32));
  var rootHash = chunks.length > 1 ? chunks[1] : leafHash;
  var proof = chunks.slice(2);

  guard(function () {
    pki.merkle.verifyInclusion({ leafIndex: a, treeSize: b, leafHash: leafHash, proof: proof, rootHash: rootHash });
  });
  guard(function () {
    pki.merkle.verifyConsistency({ oldSize: a, newSize: b, oldRoot: leafHash, newRoot: rootHash, proof: proof });
  });
  // Also exercise the hash producers on raw bytes.
  guard(function () { pki.merkle.leafHash(data); });
  guard(function () { if (chunks.length >= 2) pki.merkle.nodeHash(chunks[0], chunks[1]); });
};
