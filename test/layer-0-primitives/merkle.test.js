// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.merkle (RFC 6962 / RFC 9162 tree-proof verification).
 * Oracle: known-answer trees over deterministic leaves (leaf i = the byte i),
 * the published RFC 6962 leafHash KAT, and adversarial proofs the verifier
 * must reject (bad geometry, wrong root, domain-separation swap, inverted
 * consistency window, the power-of-two append-only bypass, oversize
 * coordinates). Every accept root + proof is independently reference-computed.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
function H(hex) { return Buffer.from(hex, "hex"); }
function P(arr) { return arr.map(H); }

// Leaf hashes leafHash(Buffer.from([i])) = SHA-256(0x00 || [i]) -- known-answer.
var L0 = "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"; // RFC 6962 published KAT
var L1 = "b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2";
var L2 = "fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f";
var L3 = "583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d";
var L4 = "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4";
var L5 = "9f1afa4dc124cba73134e82ff50f17c8f7164257c79fed9a13f5943a6acb8e3d";
var L6 = "40d88127d4d31a3891f41598eeed41174e5bc89b1eb9bbd66a8cbfc09956a3fd";
// Interior + subtree-root hashes.
var R2 = "a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a"; // root(size 2) = nodeHash(L0,L1)
var R3 = "3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688"; // root(size 3)
var R4 = "9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb"; // root(size 4)
var R6 = "bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8"; // root(size 6)
var R7 = "3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3"; // root(size 7)
var EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // SHA-256("")
var N23 = "52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825"; // nodeHash(L2,L3)
var N456 = "89c929834ed1459b07f65b5e1a2143a8cf5d8efdf30f49ffffa328bb1d9133bb"; // root of leaves 4..6
var N45 = "4b8c129ed14cce2c08cfc6766db7f8cdb133b5f698b8de3d5890ea7ff7f0a8d1"; // nodeHash(L4,L5)

function testHashKats() {
  var m = pki.merkle;
  check("emptyRootHash KAT", m.emptyRootHash().toString("hex") === EMPTY);
  check("leafHash(leaf0) KAT", m.leafHash(Buffer.from([0])).toString("hex") === L0);
  check("leafHash(leaf6) KAT", m.leafHash(Buffer.from([6])).toString("hex") === L6);
  check("nodeHash(L0,L1) == root(size2)", m.nodeHash(H(L0), H(L1)).toString("hex") === R2);
  check("nodeHash applies 0x01 (differs from leaf domain)", m.nodeHash(H(L0), H(L1)).toString("hex") !== m.leafHash(Buffer.concat([H(L0), H(L1)])).toString("hex"));
  check("leafHash rejects non-buffer", code(function () { m.leafHash("x"); }) === "merkle/bad-input");
  check("nodeHash rejects a 31-byte operand", code(function () { m.nodeHash(H(L0), Buffer.alloc(31)); }) === "merkle/bad-hash-length");
}

// [id, leafIndex, treeSize, leafHash, proof[], root]
var INCLUSION_ACCEPT = [
  ["incl-n7-i0", 0, 7, L0, [L1, N23, N456], R7],
  ["incl-n7-i1", 1, 7, L1, [L0, N23, N456], R7],
  ["incl-n7-i2", 2, 7, L2, [L3, R2, N456], R7],
  ["incl-n7-i3", 3, 7, L3, [L2, R2, N456], R7],
  ["incl-n7-i4", 4, 7, L4, [L5, L6, R4], R7],
  ["incl-n7-i5", 5, 7, L5, [L4, L6, R4], R7],
  ["incl-n7-i6", 6, 7, L6, [N45, R4], R7],
  ["incl-n1-i0", 0, 1, L0, [], L0],
  ["incl-n4-i0", 0, 4, L0, [L1, N23], R4],
  ["incl-n4-i3", 3, 4, L3, [L2, R2], R4],
];

function testInclusionAccept() {
  INCLUSION_ACCEPT.forEach(function (v) {
    check(v[0] + " verifies true", pki.merkle.verifyInclusion({
      leafIndex: v[1], treeSize: v[2], leafHash: H(v[3]), proof: P(v[4]), rootHash: H(v[5]),
    }) === true);
  });
}

// [id, oldSize, newSize, oldRoot, newRoot, proof[]]
var CONSISTENCY_ACCEPT = [
  ["cons-1-7", 1, 7, L0, R7, [L1, N23, N456]],
  ["cons-3-7", 3, 7, R3, R7, [L2, L3, R2, N456]],
  ["cons-4-7", 4, 7, R4, R7, [N456]],
  ["cons-6-7", 6, 7, R6, R7, [N45, L6, R4]],
  ["cons-7-7", 7, 7, R7, R7, []],
  ["cons-0-7", 0, 7, EMPTY, R7, []],
];

function testConsistencyAccept() {
  CONSISTENCY_ACCEPT.forEach(function (v) {
    check(v[0] + " verifies true", pki.merkle.verifyConsistency({
      oldSize: v[1], newSize: v[2], oldRoot: H(v[3]), newRoot: H(v[4]), proof: P(v[5]),
    }) === true);
  });
}

// XOR the first byte of a hex string (a well-formed but wrong 32-byte hash).
function flip(hex) { var b = H(hex); b[0] ^= 0x01; return b.toString("hex"); }

function testRejects() {
  var m = pki.merkle;
  // --- inclusion, THROW ---
  check("rej-incl-empty-tree", code(function () { m.verifyInclusion({ leafIndex: 0, treeSize: 0, leafHash: H(L0), proof: [], rootHash: H(L0) }); }) === "merkle/empty-tree");
  check("rej-incl-index-oob", code(function () { m.verifyInclusion({ leafIndex: 7, treeSize: 7, leafHash: H(L3), proof: P([L2, R2, N456]), rootHash: H(R7) }); }) === "merkle/index-out-of-range");
  check("rej-incl-bad-hashlen", code(function () { m.verifyInclusion({ leafIndex: 3, treeSize: 7, leafHash: H(L3), proof: [Buffer.alloc(31), H(R2), H(N456)], rootHash: H(R7) }); }) === "merkle/bad-hash-length");
  check("rej-incl-bad-proof-type", code(function () { m.verifyInclusion({ leafIndex: 3, treeSize: 7, leafHash: H(L3), proof: "not-an-array", rootHash: H(R7) }); }) === "merkle/bad-proof");
  check("rej-incl-proof-too-large", code(function () {
    var big = []; for (var i = 0; i < 66; i++) big.push(Buffer.alloc(32));
    m.verifyInclusion({ leafIndex: 3, treeSize: 7, leafHash: H(L3), proof: big, rootHash: H(R7) });
  }) === "merkle/proof-too-large");
  // The coarse cap is 65 (a consistency proof at the uint64 ceiling has up to
  // ceil(log2(newSize))+1 = 65 nodes); a 65-node proof must pass the cap and
  // reach the geometry check, not be rejected as too large.
  check("a 65-node proof passes the cap and reaches the geometry check", code(function () {
    var p = []; for (var i = 0; i < 65; i++) p.push(Buffer.alloc(32));
    m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(R3), newRoot: H(R7), proof: p });
  }) === "merkle/bad-proof-length");
  // A detached-ArrayBuffer-backed view is malformed input: a typed merkle/*
  // error, never a raw TypeError a PkiError-only catch would miss.
  check("detached-ArrayBuffer view throws merkle/bad-input, not a raw TypeError", code(function () {
    var ab = new ArrayBuffer(32); var u = new Uint8Array(ab);
    structuredClone(ab, { transfer: [ab] }); // detaches ab
    m.leafHash(u);
  }) === "merkle/bad-input");
  check("rej-incl-proof-too-long", code(function () { m.verifyInclusion({ leafIndex: 3, treeSize: 7, leafHash: H(L3), proof: P([L2, R2, N456, N45]), rootHash: H(R7) }); }) === "merkle/bad-proof-length");
  check("rej-incl-proof-too-short", code(function () { m.verifyInclusion({ leafIndex: 3, treeSize: 7, leafHash: H(L3), proof: P([L2, R2]), rootHash: H(R7) }); }) === "merkle/bad-proof-length");
  check("rej-coord-too-large", code(function () { m.verifyInclusion({ leafIndex: 0, treeSize: Number.MAX_SAFE_INTEGER + 1, leafHash: H(L0), proof: [], rootHash: H(L0) }); }) === "merkle/bad-input");
  check("rej-coord-negative", code(function () { m.verifyInclusion({ leafIndex: -1, treeSize: 7, leafHash: H(L3), proof: P([L2, R2, N456]), rootHash: H(R7) }); }) === "merkle/bad-input");
  // --- inclusion, RETURN false ---
  check("rej-incl-wrong-root (false)", m.verifyInclusion({ leafIndex: 3, treeSize: 7, leafHash: H(L3), proof: [H(flip(L2)), H(R2), H(N456)], rootHash: H(R7) }) === false);
  check("rej-incl-domain-swap (false)", m.verifyInclusion({ leafIndex: 0, treeSize: 1, leafHash: m.leafHash(Buffer.from([9])), proof: [], rootHash: H(R2) }) === false);
  check("a leaf hash can never equal an interior node value", m.leafHash(Buffer.from([9])).toString("hex") !== R2);
  // --- consistency, THROW ---
  check("rej-cons-old-gt-new", code(function () { m.verifyConsistency({ oldSize: 7, newSize: 3, oldRoot: H(R7), newRoot: H(R3), proof: [] }); }) === "merkle/old-size-exceeds-new");
  check("rej-cons-old-zero-nonempty", code(function () { m.verifyConsistency({ oldSize: 0, newSize: 7, oldRoot: H(EMPTY), newRoot: H(R7), proof: P([L2, L3, R2, N456]) }); }) === "merkle/bad-proof-length");
  check("rej-cons-sizes-equal-nonempty", code(function () { m.verifyConsistency({ oldSize: 7, newSize: 7, oldRoot: H(R7), newRoot: H(R7), proof: P([L2, L3, R2, N456]) }); }) === "merkle/sizes-equal-nonempty-proof");
  check("rej-cons-empty-proof", code(function () { m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(R3), newRoot: H(R7), proof: [] }); }) === "merkle/empty-consistency-proof");
  check("rej-cons-bad-hashlen", code(function () { m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(R3), newRoot: H(R7), proof: [Buffer.alloc(31), H(L3), H(R2), H(N456)] }); }) === "merkle/bad-hash-length");
  check("rej-cons-proof-too-long", code(function () { m.verifyConsistency({ oldSize: 4, newSize: 7, oldRoot: H(R4), newRoot: H(R7), proof: P([N456, N45]) }); }) === "merkle/bad-proof-length");
  // --- consistency, RETURN false (the append-only bypass legs) ---
  check("rej-cons-old-zero-wrongroot (false)", m.verifyConsistency({ oldSize: 0, newSize: 7, oldRoot: H(flip(EMPTY)), newRoot: H(R7), proof: [] }) === false);
  check("rej-cons-wrong-oldroot non-pow2 (false)", m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(flip(R3)), newRoot: H(R7), proof: P([L2, L3, R2, N456]) }) === false);
  check("rej-cons-wrong-oldroot POW2 (false) [load-bearing]", m.verifyConsistency({ oldSize: 4, newSize: 7, oldRoot: H(flip(R4)), newRoot: H(R7), proof: P([N456]) }) === false);
  check("rej-cons-wrong-newroot (false)", m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(R3), newRoot: H(flip(R7)), proof: P([L2, L3, R2, N456]) }) === false);
}

// Advertised-surface exercise: every primitive reachable by its full path.
function testSurface() {
  check("pki.merkle.leafHash is exposed", typeof pki.merkle.leafHash === "function");
  check("pki.merkle.nodeHash is exposed", typeof pki.merkle.nodeHash === "function");
  check("pki.merkle.emptyRootHash is exposed", typeof pki.merkle.emptyRootHash === "function");
  check("pki.merkle.verifyInclusion is exposed", typeof pki.merkle.verifyInclusion === "function");
  check("pki.merkle.verifyConsistency is exposed", typeof pki.merkle.verifyConsistency === "function");
}

function run() {
  testSurface();
  testHashKats();
  testInclusionAccept();
  testConsistencyAccept();
  testRejects();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
