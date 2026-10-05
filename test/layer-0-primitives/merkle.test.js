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
var R5 = "b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f"; // root(size 5)
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
  // Non-pow2 old tree whose old-root reconstruction descends through an
  // even fn === sn boundary (fn is shifted down until odd): the old-root leg
  // exercises the constant-time descent inside the consistency fold.
  ["cons-5-6", 5, 6, R5, R6, [L4, L5, R4]],
  ["cons-6-7", 6, 7, R6, R7, [N45, L6, R4]],
  ["cons-7-7", 7, 7, R7, R7, []],
  // `cons-0-7` used to sit here, asserting that oldSize 0 -> newSize 7 verifies true. It was
  // pinning the overclaim rather than a property: RFC 6962 sec. 2.1.2 defines PROOF(m, D[n]) for
  // 0 < m < n, so an empty older tree has no proof to check and binds nothing about newRoot -- the
  // `true` said a step was proven append-only when nothing had been proven. That case is now a
  // refusal, covered by the rej-cons-old-zero-* vectors below.
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
  // No-argument call: opts defaults to {}, then the missing leafIndex coord
  // fails closed with a typed merkle/* error (never a raw TypeError).
  check("rej-incl-no-opts", code(function () { m.verifyInclusion(); }) === "merkle/bad-input");
  check("rej-incl-empty-tree", code(function () { m.verifyInclusion({ leafIndex: 0, treeSize: 0, leafHash: H(L0), proof: [], rootHash: H(L0) }); }) === "merkle/empty-tree");
  // Every field of these verbs is required, which is what makes a misspelling dangerous: the
  // intended field reads as OMITTED, and an omission of a required field is caught -- so the caller
  // is told about the field they did not mean to leave out and never about the one they misspelled.
  check("rej-incl-unknown-option", code(function () {
    m.verifyInclusion({ leafIndex: 0, treeSize: 1, leafHash: H(L0), proof: [], rootHash: H(L0), leafIdx: 3 });
  }) === "merkle/bad-input");
  check("rej-cons-unknown-option", code(function () {
    m.verifyConsistency({ oldSize: 1, newSize: 1, oldRoot: H(L0), newRoot: H(L0), proof: [], oldsize: 2 });
  }) === "merkle/bad-input");
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
  // No-argument call: opts defaults to {}, missing oldSize fails closed typed.
  check("rej-cons-no-opts", code(function () { m.verifyConsistency(); }) === "merkle/bad-input");
  check("rej-cons-old-gt-new", code(function () { m.verifyConsistency({ oldSize: 7, newSize: 3, oldRoot: H(R7), newRoot: H(R3), proof: [] }); }) === "merkle/old-size-exceeds-new");
  // An empty older tree with a NON-empty newer one is outside RFC 6962 sec. 2.1.2, which defines
  // PROOF(m, D[n]) for 0 < m < n. There is no proof to check and nothing is bound about newRoot, so
  // returning the same `true` the honest path returns would say a step was proven append-only when
  // nothing was proven at all -- a monitor written `if (!verifyConsistency(...)) alarm()` gets no
  // alarm and has verified nothing. Refused, whatever the proof or the roots look like.
  check("rej-cons-old-zero-newsize-nonzero", code(function () { m.verifyConsistency({ oldSize: 0, newSize: 7, oldRoot: H(EMPTY), newRoot: H(R7), proof: [] }); }) === "merkle/no-consistency-claim");
  check("rej-cons-old-zero-nonempty", code(function () { m.verifyConsistency({ oldSize: 0, newSize: 7, oldRoot: H(EMPTY), newRoot: H(R7), proof: P([L2, L3, R2, N456]) }); }) === "merkle/no-consistency-claim");
  check("rej-cons-old-zero-oldroot-irrelevant", code(function () { m.verifyConsistency({ oldSize: 0, newSize: 1, oldRoot: H(flip(EMPTY)), newRoot: H(R7), proof: [] }); }) === "merkle/no-consistency-claim");
  check("rej-cons-sizes-equal-nonempty", code(function () { m.verifyConsistency({ oldSize: 7, newSize: 7, oldRoot: H(R7), newRoot: H(R7), proof: P([L2, L3, R2, N456]) }); }) === "merkle/sizes-equal-nonempty-proof");
  check("rej-cons-empty-proof", code(function () { m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(R3), newRoot: H(R7), proof: [] }); }) === "merkle/empty-consistency-proof");
  check("rej-cons-bad-hashlen", code(function () { m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(R3), newRoot: H(R7), proof: [Buffer.alloc(31), H(L3), H(R2), H(N456)] }); }) === "merkle/bad-hash-length");
  check("rej-cons-proof-too-long", code(function () { m.verifyConsistency({ oldSize: 4, newSize: 7, oldRoot: H(R4), newRoot: H(R7), proof: P([N456, N45]) }); }) === "merkle/bad-proof-length");
  // Too short: the 3->7 proof needs 4 nodes; a 3-node proof completes the fold
  // with sn != 0 and fails closed ("shorter than the geometry requires").
  check("rej-cons-proof-too-short", code(function () { m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(R3), newRoot: H(R7), proof: P([L2, L3, R2]) }); }) === "merkle/bad-proof-length");
  // --- consistency, RETURN false (the append-only bypass legs) ---
  // empty-to-empty (newSize 0) is the one empty-older case that IS answerable: it is the degenerate
  // identity check, not a consistency proof, and BOTH roots must be the empty root -- a bogus
  // newRoot must not pass.
  check("cons-empty-to-empty accepts both empty roots", m.verifyConsistency({ oldSize: 0, newSize: 0, oldRoot: H(EMPTY), newRoot: H(EMPTY), proof: [] }) === true);
  // Two empty trees admit only the empty proof: a node offered here folds into
  // nothing, so accepting it would let a proof exist where none can.
  check("rej-cons-empty-to-empty-nonempty-proof", code(function () {
    m.verifyConsistency({ oldSize: 0, newSize: 0, oldRoot: H(EMPTY), newRoot: H(EMPTY), proof: P([L0]) });
  }) === "merkle/bad-proof-length");
  check("rej-cons-empty-to-empty-wrongnewroot (false)", m.verifyConsistency({ oldSize: 0, newSize: 0, oldRoot: H(EMPTY), newRoot: H(flip(EMPTY)), proof: [] }) === false);
  check("rej-cons-wrong-oldroot non-pow2 (false)", m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(flip(R3)), newRoot: H(R7), proof: P([L2, L3, R2, N456]) }) === false);
  check("rej-cons-wrong-oldroot POW2 (false) [load-bearing]", m.verifyConsistency({ oldSize: 4, newSize: 7, oldRoot: H(flip(R4)), newRoot: H(R7), proof: P([N456]) }) === false);
  check("rej-cons-wrong-newroot (false)", m.verifyConsistency({ oldSize: 3, newSize: 7, oldRoot: H(R3), newRoot: H(flip(R7)), proof: P([L2, L3, R2, N456]) }) === false);
}

// ---------------------------------------------------------------------------
// The producing half: root, inclusionProof, consistencyProof.
//
// Every expected value below is one of the known-answer constants the verifying
// vectors above are written against, so the producer is held to a table that
// predates it. A round-trip alone would not say this much: a producer and a
// verifier that share a wrong tree geometry agree with each other and with
// nothing else.
// ---------------------------------------------------------------------------

var LEAVES = P([L0, L1, L2, L3, L4, L5, L6]);

function hexes(bufs) { return bufs.map(function (b) { return b.toString("hex"); }).join(","); }

// [id, treeSize, expected root]
var ROOT_KAT = [
  ["root-n0", 0, EMPTY], ["root-n1", 1, L0], ["root-n2", 2, R2], ["root-n3", 3, R3],
  ["root-n4", 4, R4], ["root-n5", 5, R5], ["root-n6", 6, R6], ["root-n7", 7, R7],
];

function testRootKats() {
  ROOT_KAT.forEach(function (v) {
    check("root " + v[0] + " reproduces the known-answer root",
      pki.merkle.root(LEAVES.slice(0, v[1])).toString("hex") === v[2]);
  });
  check("root of the empty tree is emptyRootHash()",
    pki.merkle.root([]).toString("hex") === pki.merkle.emptyRootHash().toString("hex"));
  check("root of one leaf is that leaf, with no interior hashing",
    pki.merkle.root([H(L3)]).toString("hex") === L3);
}

// The producer must emit the exact audit path each verifying vector carries.
function testProduceInclusion() {
  INCLUSION_ACCEPT.forEach(function (v) {
    var produced = pki.merkle.inclusionProof({ leafHashes: LEAVES.slice(0, v[2]), leafIndex: v[1] });
    check("inclusionProof " + v[0] + " reproduces the known-answer path",
      hexes(produced) === v[4].join(","));
  });
}

function testProduceConsistency() {
  CONSISTENCY_ACCEPT.forEach(function (v) {
    var produced = pki.merkle.consistencyProof({ leafHashes: LEAVES.slice(0, v[2]), oldSize: v[1] });
    check("consistencyProof " + v[0] + " reproduces the known-answer proof",
      hexes(produced) === v[5].join(","));
  });
}

// Geometry the seven-leaf table does not reach: every index of every tree size
// through 33, which crosses two power-of-two boundaries and every partial-tree
// shape between them. The counts are asserted, not a ratio, so a loop that
// produced nothing cannot read as agreement.
function testProduceRoundTrip() {
  var m = pki.merkle;
  var many = [];
  for (var i = 0; i < 33; i++) many.push(m.leafHash(Buffer.from([i])));
  var inclOk = 0, inclTotal = 0, consOk = 0, consTotal = 0;
  for (var n = 1; n <= 33; n++) {
    var leaves = many.slice(0, n);
    var rootHash = m.root(leaves);
    for (var idx = 0; idx < n; idx++) {
      inclTotal++;
      if (m.verifyInclusion({
        leafIndex: idx, treeSize: n, leafHash: leaves[idx],
        proof: m.inclusionProof({ leafHashes: leaves, leafIndex: idx }), rootHash: rootHash,
      }) === true) inclOk++;
    }
    for (var old = 1; old <= n; old++) {
      consTotal++;
      if (m.verifyConsistency({
        oldSize: old, newSize: n, oldRoot: m.root(leaves.slice(0, old)), newRoot: rootHash,
        proof: m.consistencyProof({ leafHashes: leaves, oldSize: old }),
      }) === true) consOk++;
    }
  }
  check("every inclusion proof produced for sizes 1..33 verifies (" + inclOk + "/" + inclTotal + ")",
    inclOk === inclTotal && inclTotal === 561);
  check("every consistency proof produced for sizes 1..33 verifies (" + consOk + "/" + consTotal + ")",
    consOk === consTotal && consTotal === 561);
}

// A produced proof must be REFUSED when it is offered for a neighboring leaf:
// a producer that emitted a path independent of the index would still round-trip
// against itself, so the discrimination is asserted directly.
function testProducedProofIsIndexBound() {
  var m = pki.merkle;
  var rootHash = m.root(LEAVES);
  var wrong = 0;
  for (var i = 0; i < 7; i++) {
    var proof = m.inclusionProof({ leafHashes: LEAVES, leafIndex: i });
    var other = (i + 1) % 7;
    var verdict;
    try {
      verdict = m.verifyInclusion({
        leafIndex: other, treeSize: 7, leafHash: LEAVES[other], proof: proof, rootHash: rootHash,
      });
    } catch (err) {
      // A path whose length does not fit the other index is refused on geometry
      // before any fold, which is also "does not prove this leaf". Any other
      // throw is recorded as itself so it cannot pass as a refusal.
      verdict = err.code === "merkle/bad-proof-length" ? false : "THREW " + err.code;
    }
    if (verdict === false) wrong++;
  }
  check("a path produced for one leaf proves no other leaf (" + wrong + "/7)", wrong === 7);
}

function testProduceRejects() {
  var m = pki.merkle;
  check("rej-root-no-args", code(function () { m.root(); }) === "merkle/bad-input");
  check("rej-root-not-array", code(function () { m.root("nope"); }) === "merkle/bad-input");
  check("rej-root-bad-leaf-length", code(function () { m.root([Buffer.alloc(31)]); }) === "merkle/bad-hash-length");
  check("rej-root-leaf-not-buffer", code(function () { m.root([H(L0), "x"]); }) === "merkle/bad-input");
  check("rej-root-too-many-leaves", code(function () {
    m.root(new Array(1048577).fill(H(L0)));
  }) === "merkle/too-many-leaves");

  check("rej-incl-proof-no-opts", code(function () { m.inclusionProof(); }) === "merkle/bad-input");
  check("rej-incl-proof-empty-tree", code(function () { m.inclusionProof({ leafHashes: [], leafIndex: 0 }); }) === "merkle/empty-tree");
  check("rej-incl-proof-index-oob", code(function () { m.inclusionProof({ leafHashes: LEAVES, leafIndex: 7 }); }) === "merkle/index-out-of-range");
  check("rej-incl-proof-index-negative", code(function () { m.inclusionProof({ leafHashes: LEAVES, leafIndex: -1 }); }) === "merkle/bad-input");
  // treeSize is not an option here: it is the leaf array's length, so a caller
  // who passes one is told rather than having the two silently disagree.
  check("rej-incl-proof-unknown-option", code(function () {
    m.inclusionProof({ leafHashes: LEAVES, leafIndex: 0, treeSize: 7 });
  }) === "merkle/bad-input");

  check("rej-cons-proof-no-opts", code(function () { m.consistencyProof(); }) === "merkle/bad-input");
  check("rej-cons-proof-old-exceeds-new", code(function () { m.consistencyProof({ leafHashes: LEAVES, oldSize: 8 }); }) === "merkle/old-size-exceeds-new");
  check("rej-cons-proof-old-zero", code(function () { m.consistencyProof({ leafHashes: LEAVES, oldSize: 0 }); }) === "merkle/no-consistency-claim");
  check("rej-cons-proof-unknown-option", code(function () {
    m.consistencyProof({ leafHashes: LEAVES, oldSize: 1, newSize: 7 });
  }) === "merkle/bad-input");

  // The two degenerate proofs the verifier accepts, produced rather than written.
  check("consistencyProof at equal sizes is the empty proof",
    m.consistencyProof({ leafHashes: LEAVES, oldSize: 7 }).length === 0);
  check("the empty-to-empty consistency proof round-trips", m.verifyConsistency({
    oldSize: 0, newSize: 0, oldRoot: m.root([]), newRoot: m.root([]),
    proof: m.consistencyProof({ leafHashes: [], oldSize: 0 }),
  }) === true);
}

// The caller's array is snapshotted before the fold, so a slot that answers
// differently on a second read cannot change the tree under the recursion.
function testProducerSnapshotsItsInput() {
  var m = pki.merkle;
  var before = hexes(LEAVES);
  m.root(LEAVES);
  m.inclusionProof({ leafHashes: LEAVES, leafIndex: 3 });
  m.consistencyProof({ leafHashes: LEAVES, oldSize: 3 });
  check("producing does not mutate the caller's leaf array", hexes(LEAVES) === before);

  var reads = 0;
  var sneaky = [H(L0), H(L1), H(L2), H(L3)];
  Object.defineProperty(sneaky, "0", {
    configurable: true,
    get: function () { reads++; return reads === 1 ? H(L0) : H(L6); },
  });
  var produced = m.root(sneaky);
  check("a leaf slot is read exactly once (" + reads + ")", reads === 1);
  check("the fold uses the leaf that was checked", produced.toString("hex") === R4);

  // The slot count is the other half of the same question, and it was read once for the cap and again
  // on every loop iteration. A getter that SHORTENS the array between those reads made the cap approve
  // four leaves and the loop collect one, so the root committed to a tree the caller never supplied and
  // nothing reported it. The count is captured before any slot is touched, so an array that shrinks
  // under the walk is refused rather than silently folded short.
  function shrinking(n) {
    var a = [H(L0), H(L1), H(L2), H(L3)];
    Object.defineProperty(a, "0", {
      configurable: true,
      get: function () { a.length = n; return H(L0); },
    });
    return a;
  }
  var fourLeafRoot = m.root([H(L0), H(L1), H(L2), H(L3)]).toString("hex");
  check("CONTROL the four-leaf root of the same leaves, for comparison", fourLeafRoot === R4);
  var shrunkCode = "NO-THROW", shrunkRoot = null;
  try { shrunkRoot = m.root(shrinking(1)).toString("hex"); }
  catch (e) { shrunkCode = e.code || e.constructor.name; }
  check("an array a leaf getter shortens is refused rather than folded short (" + shrunkCode + ")",
    shrunkRoot === null && shrunkCode !== "NO-THROW" && shrunkCode.indexOf("merkle/") === 0);
  var ipCode = "NO-THROW";
  try { m.inclusionProof({ leafHashes: shrinking(1), leafIndex: 3 }); }
  catch (e2) { ipCode = e2.code || e2.constructor.name; }
  check("and the inclusion-proof producer refuses it on the same ground (" + ipCode + ")",
    ipCode.indexOf("merkle/") === 0);
  var cpCode = "NO-THROW";
  try { m.consistencyProof({ leafHashes: shrinking(1), oldSize: 3 }); }
  catch (e3) { cpCode = e3.code || e3.constructor.name; }
  check("and so does the consistency-proof producer (" + cpCode + ")",
    cpCode.indexOf("merkle/") === 0);

  // The verifiers take a caller's proof array through the same shape, and MEASURED they were never
  // exposed by it: a proof the walk collects short folds to a root that does not match the one supplied,
  // so the comparison refuses it either way. This pins that fail-closed property rather than the fix;
  // reverting the producer's guard leaves it passing, which is what says so.
  var okProof = m.inclusionProof({ leafHashes: [H(L0), H(L1), H(L2), H(L3)], leafIndex: 0 });
  check("CONTROL a four-leaf inclusion proof verifies",
    m.verifyInclusion({ leafHash: H(L0), leafIndex: 0, treeSize: 4, proof: okProof, rootHash: Buffer.from(R4, "hex") }) === true);
  function shrinkingProof() {
    var p = okProof.slice();
    Object.defineProperty(p, "0", {
      configurable: true,
      get: function () { p.length = 1; return okProof[0]; },
    });
    return p;
  }
  var viCode = "NO-THROW", viResult = null;
  try {
    viResult = m.verifyInclusion({ leafHash: H(L0), leafIndex: 0, treeSize: 4,
      proof: shrinkingProof(), rootHash: Buffer.from(R4, "hex") });
  } catch (e4) { viCode = e4.code || e4.constructor.name; }
  check("a proof array a node getter shortens never verifies, the root comparison catching it (" +
    viCode + ", result " + viResult + ")",
    viResult !== true);

  // The COUNT itself was read twice, once for the cap and once for the walk, and the two can disagree
  // without any slot accessor at all: Array.isArray is true for a Proxy whose target is an array, and a
  // get trap answers "length" afresh on each read. So a cap that saw 0 passed while the walk saw 1, and
  // the root returned was a one-leaf tree's. The count is read once now, and whichever value the proxy
  // hands over is the one the cap judges AND the one the fold uses.
  function varyingLength(target, lengths) {
    var k = 0;
    return new Proxy(target, {
      get: function (t, prop, recv) {
        if (prop === "length") { var v = k < lengths.length ? lengths[k] : t.length; k++; return v; }
        return Reflect.get(t, prop, recv);
      },
    });
  }
  var FOUR = [H(L0), H(L1), H(L2), H(L3)];
  var emptyRoot = m.emptyRootHash().toString("hex");
  var oneRoot = m.root([H(L0)]).toString("hex");
  var fourRoot = m.root(FOUR).toString("hex");
  check("CONTROL the empty, one-leaf and four-leaf roots are three different values",
    emptyRoot !== oneRoot && oneRoot !== fourRoot);
  check("a length answering 0 then 1 yields the tree for 0, the cap and the fold reading one count",
    m.root(varyingLength(FOUR, [0, 1])).toString("hex") === emptyRoot);
  check("a length answering 1 then 4 yields the tree for 1, on the same ground",
    m.root(varyingLength(FOUR, [1, 4])).toString("hex") === oneRoot);

  // Reading the count ONCE is not enough if what is read is not a NUMBER. A get trap may answer
  // `length` with an object, and capturing an object captures no value: the cap coerces it, each
  // comparison in the walk coerces it again, and a `valueOf` answering 0 and then 4 had the cap approve
  // an empty list while the fold produced four leaves. The same lever cleared the leaf cap. The count
  // is narrowed to a non-negative integer where it is taken, so a length that is not one is refused
  // rather than coerced.
  function objectLength(target, values) {
    var k = 0;
    return new Proxy(target, {
      get: function (t, prop, recv) {
        if (prop === "length") {
          return { valueOf: function () { var v = k < values.length ? values[k] : t.length; k++; return v; } };
        }
        return Reflect.get(t, prop, recv);
      },
    });
  }
  var objCode = "NO-THROW", objRoot = null;
  try { objRoot = m.root(objectLength(FOUR, [0, 4, 4, 4, 4])).toString("hex"); }
  catch (e5) { objCode = e5.code || e5.constructor.name; }
  check("a length that is an object whose valueOf answers 0 then 4 is refused rather than coerced (" +
    objCode + ", root " + objRoot + ")",
  objCode === "TypeError" && objRoot === null);
  var capCode = "NO-THROW";
  try { m.root(objectLength(FOUR, [1e9, 4, 4, 4, 4])); }
  catch (e6) { capCode = e6.code || e6.constructor.name; }
  check("and one answering above the leaf cap first does not clear it either (" + capCode + ")",
    capCode === "TypeError" || capCode === "merkle/too-many-leaves");

  // Reading each slot once is not enough if what is read is a VIEW of the caller's store. A getter that
  // hands out one scratch buffer per leaf satisfies the read-once rule and still leaves every collected
  // leaf pointing at the same bytes, so collecting the second leaf overwrote the first: the root of
  // [A, B] came out as the root of [B, B], with nothing reporting it. Each leaf is copied as it is
  // collected now.
  var A = H(L0), B = H(L1);
  var rootAB = m.root([A, B]).toString("hex");
  var rootBB = m.root([B, B]).toString("hex");
  check("CONTROL the roots of [A,B] and [B,B] are different values", rootAB !== rootBB);
  function sharedScratch() {
    var scratch = Buffer.alloc(32);
    A.copy(scratch);
    var a = [];
    Object.defineProperty(a, "0", { configurable: true, enumerable: true,
      get: function () { return scratch; } });
    Object.defineProperty(a, "1", { configurable: true, enumerable: true,
      get: function () { B.copy(scratch); return scratch; } });
    a.length = 2;
    return a;
  }
  check("leaves handed out through one reused buffer still fold as the leaves they were",
    m.root(sharedScratch()).toString("hex") === rootAB);
}

// Advertised-surface exercise: every primitive reachable by its full path.
function testSurface() {
  check("pki.merkle.leafHash is exposed", typeof pki.merkle.leafHash === "function");
  check("pki.merkle.nodeHash is exposed", typeof pki.merkle.nodeHash === "function");
  check("pki.merkle.emptyRootHash is exposed", typeof pki.merkle.emptyRootHash === "function");
  check("pki.merkle.verifyInclusion is exposed", typeof pki.merkle.verifyInclusion === "function");
  check("pki.merkle.verifyConsistency is exposed", typeof pki.merkle.verifyConsistency === "function");
  check("pki.merkle.root is exposed", typeof pki.merkle.root === "function");
  check("pki.merkle.inclusionProof is exposed", typeof pki.merkle.inclusionProof === "function");
  check("pki.merkle.consistencyProof is exposed", typeof pki.merkle.consistencyProof === "function");
}

/* A node is exactly 32 bytes, and the check enforcing that ran on the COPY, so a value handed where a
 * hash belongs was duplicated in full and only then refused: measured, one 64 MiB leaf allocated
 * another 64 MiB to reject it. MEASURED by allocation, `arrayBuffers` counting exactly the pool a
 * Buffer copy comes from, because the copy is far too fast for a time budget to separate. */
function testHashWidthPrecedesTheCopy() {
  var oversize = Buffer.alloc(64 * 1024 * 1024, 0x41);
  var before = process.memoryUsage().arrayBuffers;
  var code;
  try { pki.merkle.root([oversize]); code = "NO-THROW"; } catch (e) { code = e.code || e.name; }
  var grewMiB = (process.memoryUsage().arrayBuffers - before) / (1024 * 1024);
  check("a leaf far wider than a hash is refused before it is copied (" + code + ", " +
    grewMiB.toFixed(1) + " MiB)", code === "merkle/bad-hash-length" && grewMiB < 1);
  /* CONTROL: a valid pair still folds, and a merely WRONG width is still refused with the same code,
     so the bound did not narrow what the verb accepts. */
  var folded = pki.merkle.root([Buffer.alloc(32, 1), Buffer.alloc(32, 2)]);
  var wrongWidth;
  try { pki.merkle.root([Buffer.alloc(31, 1)]); wrongWidth = "NO-THROW"; }
  catch (e2) { wrongWidth = e2.code; }
  check("CONTROL valid leaves still fold and a 31-byte leaf is still refused",
    Buffer.isBuffer(folded) && folded.length === 32 && wrongWidth === "merkle/bad-hash-length");
}

function run() {
  testHashWidthPrecedesTheCopy();
  testSurface();
  testHashKats();
  testInclusionAccept();
  testConsistencyAccept();
  testRejects();
  testRootKats();
  testProduceInclusion();
  testProduceConsistency();
  testProduceRoundTrip();
  testProducedProofIsIndexBound();
  testProduceRejects();
  testProducerSnapshotsItsInput();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
