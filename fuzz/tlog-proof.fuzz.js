// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.tlog.inclusionProof / tileWidth / parseTile / parseEntryBundle
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: these verbs on hostile
 * input either return or throw a pki.errors.PkiError -- any other throw (a
 * RangeError from the subtree recursion, a BigInt fault, a hang) is a finding
 * and is rethrown so the fuzzer records a reproducer.
 *
 * The interesting surface is the injected `read`: a proof assembler drives a
 * caller-supplied function, so the harness serves it hostile tiles -- short,
 * over-wide, empty, and derived from the fuzzer bytes -- and also serves a
 * CONSISTENT tree so the accept path and its fold are walked on every input.
 */
var pki = require("..");

function guard(fn) {
  try { return fn(); } catch (e) { if (e instanceof pki.errors.PkiError) return null; throw e; }
}
async function guardAsync(p) {
  try { return await p; } catch (e) { if (e instanceof pki.errors.PkiError) return null; throw e; }
}

module.exports.fuzz = async function (data) {
  var size = data.length > 1 ? BigInt(data[0]) * 256n + BigInt(data[1]) : 1n;
  var level = data.length > 2 ? data[2] % 70 : 0;              // past 63 on purpose
  var index = data.length > 3 ? BigInt(data[3]) : 0n;

  guard(function () { pki.tlog.tileWidth(size, level, index); });
  guard(function () { pki.tlog.parseTile(data); });
  guard(function () { pki.tlog.parseTile(data, { full: true }); });
  guard(function () { pki.tlog.parseEntryBundle(data); });

  // A read that answers with the fuzzer's own bytes: mostly refusals, and the
  // point is that every one of them is a typed refusal.
  await guardAsync(pki.tlog.inclusionProof({
    index: index, size: size === 0n ? 1n : size, read: function () { return data; },
  }));
  // A read that answers with nothing, and one that over-answers.
  await guardAsync(pki.tlog.inclusionProof({
    index: index, size: size === 0n ? 1n : size, read: function () { return Buffer.alloc(0); },
  }));
  await guardAsync(pki.tlog.inclusionProof({
    index: index, size: size === 0n ? 1n : size, read: function () { return Buffer.alloc(32 * 300); },
  }));

  // A CONSISTENT tree, so the accept path and the fold run on every input. The
  // leaf count is bounded well inside the in-memory producer's own cap.
  var n = Number(size % 900n) + 1;
  var leaves = [];
  for (var i = 0; i < n; i++) {
    leaves.push(pki.merkle.leafHash(Buffer.from([i & 0xff, (i >> 8) & 0xff, data.length & 0xff])));
  }
  var units = [leaves];
  for (var l = 1; ; l++) {
    var below = units[l - 1];
    var whole = Math.floor(below.length / 256);
    if (whole === 0) break;
    var here = [];
    for (var u = 0; u < whole; u++) here.push(pki.merkle.root(below.slice(u * 256, u * 256 + 256)));
    units.push(here);
  }
  function read(lvl, tile, width) {
    var have = units[lvl] || [];
    var start = Number(tile) * 256;
    var want = width === null ? 256 : width;
    var slice = have.slice(start, start + want);
    return slice.length === want ? Buffer.concat(slice) : Buffer.alloc(0);
  }
  var leafIndex = Number(index % BigInt(n));
  var proof = await guardAsync(pki.tlog.inclusionProof({
    index: BigInt(leafIndex), size: BigInt(n), read: read,
  }));
  if (proof === null) return;
  // A proof the assembler produced must fold through the shipped verifier: a
  // path pki.merkle cannot walk is as much a finding as a throw.
  guard(function () {
    pki.merkle.verifyInclusion({
      leafIndex: leafIndex, treeSize: n, leafHash: leaves[leafIndex],
      proof: proof, rootHash: pki.merkle.root(leaves),
    });
  });
};
