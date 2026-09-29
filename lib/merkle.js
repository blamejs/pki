// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.merkle
 * @nav        Transparency
 * @title      Merkle
 * @fullname   Merkle trees: inclusion and consistency proofs (RFC 6962)
 * @order      220
 * @slug       merkle
 *
 * @intro
 *   RFC 6962 (Certificate Transparency) / RFC 9162 (CT 2.0) Merkle-tree hash
 *   and proof-verification core: the load-bearing primitive a static-CT
 *   client, a Merkle-Tree-Certificates relying party, and a sigstore / Rekor
 *   inclusion check all compose. Every verb is strict verification over
 *   SHA-256: zero new crypto.
 *
 *   `leafHash` / `nodeHash` / `emptyRootHash` build the tree hashes with the
 *   two domain-separation prefixes fixed by the spec: a leaf is
 *   `SHA-256(0x00 || entry)`, an interior node is `SHA-256(0x01 || left ||
 *   right)`, the empty tree is `SHA-256("")`. Those `0x00` / `0x01` prefixes
 *   are the second-preimage defense: without them a leaf whose bytes equal a
 *   valid interior node's preimage could be smuggled in as present.
 *
 *   `verifyInclusion` folds an audit path back to a root and constant-time-
 *   compares it to a trusted checkpoint root; `verifyConsistency` reconstructs
 *   both the old and the new root from a consistency proof (the append-only
 *   guarantee lives in the old-root leg). Both are fail-closed: a malformed
 *   coordinate, an out-of-range index, an inverted window, a wrong hash length,
 *   or a proof whose node count does not match the tree geometry throws a typed
 *   `merkle/*` error; the one boolean-`false` result is the final root
 *   comparison ("root matched" vs "did not"). A `false` from `verifyInclusion`
 *   means "not proven present against this root", never "validly absent": an
 *   inclusion proof cannot express absence. Tree coordinates are uint64, carried
 *   as `BigInt` so a large index is never `Number`-narrowed. This is not a DER
 *   format. Like `pki.ct` it is a companion module reached explicitly, never
 *   routed by the detect-and-parse orchestrator.
 *
 * @card
 *   `leafHash` / `nodeHash` / `emptyRootHash` + `verifyInclusion` /
 *   `verifyConsistency` over sync SHA-256, fail-closed, transport-free.
 */

var nodeCrypto = require("node:crypto");
var constants = require("./constants");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");

var MerkleError = frameworkError.MerkleError;

function _merkleErr(c, m) { return new MerkleError(c, m); }

var SHA256_BYTES = 32;
var LEAF_PREFIX = Buffer.from([0x00]);
var NODE_PREFIX = Buffer.from([0x01]);
var EMPTY = Buffer.alloc(0);

function _sha256(buf) {
  return nodeCrypto.createHash("sha256").update(buf).digest();
}

function _toBuffer(v, field) {
  return guard.bytes.view(v, MerkleError, "merkle/bad-input", field);
}

function _node32(v, field) {
  var buf = _toBuffer(v, field);
  if (buf.length !== SHA256_BYTES) {
    throw new MerkleError("merkle/bad-hash-length", field + " must be exactly 32 bytes, got " + buf.length);
  }
  return buf;
}

function _coerceCoord(v, field) {
  return guard.range.uint64(v, _merkleErr, "merkle/bad-input", field);
}

function _proofNodes(proof) {
  if (!Array.isArray(proof)) throw new MerkleError("merkle/bad-proof", "proof must be an array");
  if (proof.length > constants.LIMITS.MERKLE_MAX_PROOF_NODES) {
    throw new MerkleError("merkle/proof-too-large", "proof has " + proof.length + " nodes, exceeds " + constants.LIMITS.MERKLE_MAX_PROOF_NODES);
  }
  var out = [];
  for (var i = 0; i < proof.length; i++) out.push(_node32(proof[i], "proof[" + i + "]"));
  return out;
}

function _ctEq(a, b) {
  return guard.crypto.constantTimeEqual(a, b);
}

var NO_CONSISTENCY_CLAIM =
  "an empty older tree (oldSize 0) makes no consistency claim about a non-empty newer tree: " +
  "RFC 6962 sec. 2.1.2 defines the proof for 0 < oldSize < newSize, and nothing here binds " +
  "newRoot. Verify an inclusion proof against the new tree, or start from a signed tree head " +
  "you already trust";

/** @internal Each slot is read once, into the buffer the length check and every later fold both
 *  use, so an array whose accessor answers differently on a second read cannot put one value past
 *  the check and a different one into the tree. The length is bounded before any slot is touched. */
function _leafArray(v, field) {
  if (!Array.isArray(v)) {
    throw new MerkleError("merkle/bad-input", field + " must be an array of 32-byte leaf hashes");
  }
  if (v.length > constants.LIMITS.MERKLE_MAX_LEAVES) {
    throw new MerkleError("merkle/too-many-leaves",
      field + " holds " + v.length + " leaves, exceeds " + constants.LIMITS.MERKLE_MAX_LEAVES);
  }
  var out = [];
  for (var i = 0; i < v.length; i++) out.push(_node32(v[i], field + "[" + i + "]"));
  return out;
}

/** @internal RFC 6962 sec. 2.1's "largest power of two smaller than n", for n >= 2. Doubled from
 *  1 rather than derived through a logarithm: the leaf count is bounded well inside the exact
 *  integer range, and a float log would round at the boundary sizes this splits on. */
function _splitPoint(n) {
  var k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** @internal MTH(D[lo:hi]) for hi > lo. The empty tree is answered by the caller. */
function _mth(leaves, lo, hi) {
  if (hi - lo === 1) return leaves[lo];
  var k = _splitPoint(hi - lo);
  return nodeHash(_mth(leaves, lo, lo + k), _mth(leaves, lo + k, hi));
}

/** @internal PATH(m, D[lo:hi]) of RFC 6962 sec. 2.1.1, with m relative to lo. */
function _path(leaves, lo, hi, m) {
  if (hi - lo === 1) return [];
  var k = _splitPoint(hi - lo);
  if (m < k) return _path(leaves, lo, lo + k, m).concat([_mth(leaves, lo + k, hi)]);
  return _path(leaves, lo + k, hi, m - k).concat([_mth(leaves, lo, lo + k)]);
}

/** @internal SUBPROOF(m, D[lo:hi], b) of RFC 6962 sec. 2.1.2, with m relative to lo. The split
 *  compares m <= k here where PATH compares m < k, which is what puts the old tree's own root in
 *  the proof exactly when the caller did not already hold it. */
function _subproof(leaves, lo, hi, m, b) {
  if (m === hi - lo) return b ? [] : [_mth(leaves, lo, hi)];
  var k = _splitPoint(hi - lo);
  if (m <= k) return _subproof(leaves, lo, lo + k, m, b).concat([_mth(leaves, lo + k, hi)]);
  return _subproof(leaves, lo + k, hi, m - k, false).concat([_mth(leaves, lo, lo + k)]);
}

/**
 * @primitive  pki.merkle.leafHash
 * @signature  pki.merkle.leafHash(entry) -> Buffer
 * @since      0.1.28
 * @status     stable
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.nodeHash, pki.merkle.verifyInclusion
 *
 * The Merkle leaf hash `MTH({d}) = SHA-256(0x00 || entry)`. The `0x00` prefix
 * is the leaf-domain second-preimage separation and is applied unconditionally.
 * Throws `merkle/bad-input` if `entry` is not a Buffer / Uint8Array.
 *
 * @example
 *   pki.merkle.leafHash(Buffer.from("leaf data")); // -> <Buffer 32-byte leaf hash>
 */
function leafHash(entry) {
  var e = _toBuffer(entry, "entry");
  return _sha256(Buffer.concat([LEAF_PREFIX, e]));
}

/**
 * @primitive  pki.merkle.nodeHash
 * @signature  pki.merkle.nodeHash(left, right) -> Buffer
 * @since      0.1.28
 * @status     stable
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.leafHash
 *
 * The Merkle interior-node hash `SHA-256(0x01 || left || right)`. Both operands
 * must be 32-byte hashes; the `0x01` prefix is applied unconditionally. Throws
 * `merkle/bad-input` on a non-buffer operand, `merkle/bad-hash-length` on an
 * operand that is not exactly 32 bytes.
 *
 * @example
 *   var l = pki.merkle.leafHash(Buffer.from([0]));
 *   var r = pki.merkle.leafHash(Buffer.from([1]));
 *   pki.merkle.nodeHash(l, r); // -> <Buffer 32-byte node hash>
 */
function nodeHash(left, right) {
  var l = _node32(left, "left");
  var r = _node32(right, "right");
  return _sha256(Buffer.concat([NODE_PREFIX, l, r]));
}

/**
 * @primitive  pki.merkle.emptyRootHash
 * @signature  pki.merkle.emptyRootHash() -> Buffer
 * @since      0.1.28
 * @status     stable
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.verifyConsistency
 *
 * The Merkle tree head of the empty tree, `MTH({}) = SHA-256("")`
 * (`e3b0c442...b855`). A fresh Buffer each call.
 *
 * @example
 *   pki.merkle.emptyRootHash(); // -> <Buffer e3 b0 c4 42 ...>
 */
function emptyRootHash() {
  return _sha256(EMPTY);
}

/**
 * @primitive  pki.merkle.verifyInclusion
 * @signature  pki.merkle.verifyInclusion(opts) -> boolean
 * @since      0.1.28
 * @status     stable
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.leafHash, pki.merkle.verifyConsistency
 *
 * Verify an RFC 6962 / RFC 9162 audit (inclusion) proof: fold `leafHash` up the
 * audit path and constant-time-compare the reconstructed root to `rootHash`.
 * Returns `true` iff the proof binds the leaf to the root; a well-formed proof
 * that does not match returns `false`, meaning "not proven present against this
 * root" and never "validly absent". A malformed input throws a typed `merkle/*`
 * error: a coordinate that is not a non-negative integer (or a Number >= 2^53),
 * `treeSize` 0, `leafIndex >= treeSize`, a non-32-byte hash, or a proof whose
 * node count does not match the tree geometry.
 *
 * @opts
 *   leafIndex:  number | bigint,  // 0-based leaf position (uint64; pass BigInt above 2^53)
 *   treeSize:   number | bigint,  // total leaf count of the tree the root commits to
 *   leafHash:   Buffer,           // 32-byte leaf hash (e.g. from pki.merkle.leafHash)
 *   proof:      Buffer[],         // the audit path, each node a 32-byte hash
 *   rootHash:   Buffer,           // 32-byte trusted checkpoint root
 *
 * @example
 *   var lh = pki.merkle.leafHash(Buffer.from([0]));
 *   pki.merkle.verifyInclusion({ leafIndex: 0, treeSize: 1, leafHash: lh, proof: [], rootHash: lh }); // -> true
 */
var _INCLUSION_KEYS = Object.assign(Object.create(null), { leafIndex: 1, treeSize: 1, leafHash: 1, rootHash: 1, proof: 1 });
function verifyInclusion(opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _INCLUSION_KEYS, function (c, m) { return new MerkleError(c, m); },
    "merkle/bad-input", "unknown verifyInclusion option ");
  var leafIndex = _coerceCoord(opts.leafIndex, "leafIndex");
  var treeSize = _coerceCoord(opts.treeSize, "treeSize");
  if (treeSize === 0n) throw new MerkleError("merkle/empty-tree", "an empty tree has no leaves to include");
  if (leafIndex >= treeSize) throw new MerkleError("merkle/index-out-of-range", "leafIndex " + leafIndex + " is not less than treeSize " + treeSize);
  var lh = _node32(opts.leafHash, "leafHash");
  var rootHash = _node32(opts.rootHash, "rootHash");
  var proof = _proofNodes(opts.proof);

  var fn = leafIndex;
  var sn = treeSize - 1n;
  var r = lh;
  for (var i = 0; i < proof.length; i++) {
    var p = proof[i];
    if (sn === 0n) throw new MerkleError("merkle/bad-proof-length", "proof is longer than the tree geometry allows");
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1n) === 0n) {
        do { fn >>= 1n; sn >>= 1n; } while ((fn & 1n) === 0n && fn !== 0n);
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  if (sn !== 0n) throw new MerkleError("merkle/bad-proof-length", "proof is shorter than the tree geometry requires");
  return _ctEq(r, rootHash);
}

/**
 * @primitive  pki.merkle.verifyConsistency
 * @signature  pki.merkle.verifyConsistency(opts) -> boolean
 * @since      0.1.28
 * @status     stable
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.verifyInclusion, pki.merkle.emptyRootHash
 *
 * Verify an RFC 6962 / RFC 9162 consistency proof between an older tree of
 * `oldSize` leaves (root `oldRoot`) and a newer tree of `newSize` leaves (root
 * `newRoot`). Reconstructs both roots from the proof and constant-time-compares
 * each; returns `true` iff both match. The append-only guarantee lives in the
 * old-root leg: a proof that yields a valid `newRoot` but the wrong `oldRoot`
 * is a rewritten history and returns `false`. Equal non-zero sizes require an
 * empty proof and `oldRoot == newRoot`.
 *
 * An `oldSize` of 0 with a non-empty newer tree is refused as
 * `merkle/no-consistency-claim`. RFC 6962 sec. 2.1.2 defines the proof for
 * `0 < oldSize < newSize`: the empty tree is a prefix of every tree by
 * definition, so there is no proof to check and nothing at all binds `newRoot`.
 * Two empty trees are still answered:
 * that is the degenerate identity case, and both roots must be `emptyRootHash()`.
 *
 * A malformed input throws a typed `merkle/*` error: `oldSize > newSize`, a
 * non-empty proof where the geometry requires none (or empty where it requires
 * one), a non-32-byte hash, or a wrong node count.
 *
 * @opts
 *   oldSize:  number | bigint,  // leaf count of the older tree (uint64)
 *   newSize:  number | bigint,  // leaf count of the newer tree (>= oldSize)
 *   oldRoot:  Buffer,           // 32-byte root of the older tree
 *   newRoot:  Buffer,           // 32-byte root of the newer tree
 *   proof:    Buffer[],         // the consistency proof, each node a 32-byte hash
 *
 * @example
 *   var r = pki.merkle.leafHash(Buffer.from([0]));
 *   pki.merkle.verifyConsistency({ oldSize: 1, newSize: 1, oldRoot: r, newRoot: r, proof: [] }); // -> true
 */
var _CONSISTENCY_KEYS = Object.assign(Object.create(null), { oldSize: 1, newSize: 1, oldRoot: 1, newRoot: 1, proof: 1 });
function verifyConsistency(opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _CONSISTENCY_KEYS, function (c, m) { return new MerkleError(c, m); },
    "merkle/bad-input", "unknown verifyConsistency option ");
  var oldSize = _coerceCoord(opts.oldSize, "oldSize");
  var newSize = _coerceCoord(opts.newSize, "newSize");
  var oldRoot = _node32(opts.oldRoot, "oldRoot");
  var newRoot = _node32(opts.newRoot, "newRoot");
  var proof = _proofNodes(opts.proof);

  if (oldSize > newSize) throw new MerkleError("merkle/old-size-exceeds-new", "oldSize " + oldSize + " exceeds newSize " + newSize);
  if (oldSize === 0n) {
    var er = emptyRootHash();
    if (newSize === 0n) {
      if (proof.length !== 0) throw new MerkleError("merkle/bad-proof-length", "two empty trees admit only the empty consistency proof");
      // allow:constant-time-compare-short-circuited -- oldRoot, newRoot, and er are public Merkle tree roots, not secrets, so short-circuiting the second compare leaks nothing confidential
      return _ctEq(oldRoot, er) && _ctEq(newRoot, er);
    }
    throw new MerkleError("merkle/no-consistency-claim", NO_CONSISTENCY_CLAIM);
  }
  if (oldSize === newSize) {
    if (proof.length !== 0) throw new MerkleError("merkle/sizes-equal-nonempty-proof", "equal tree sizes require an empty consistency proof");
    return _ctEq(oldRoot, newRoot);
  }
  if (proof.length === 0) throw new MerkleError("merkle/empty-consistency-proof", "a non-trivial consistency proof must not be empty");

  var path = proof;
  if ((oldSize & (oldSize - 1n)) === 0n) {
    path = [oldRoot].concat(proof);
  }
  var fn = oldSize - 1n;
  var sn = newSize - 1n;
  while ((fn & 1n) === 1n) { fn >>= 1n; sn >>= 1n; }
  var fr = path[0];
  var sr = path[0];
  for (var i = 1; i < path.length; i++) {
    var c = path[i];
    if (sn === 0n) throw new MerkleError("merkle/bad-proof-length", "consistency proof is longer than the geometry allows");
    if ((fn & 1n) === 1n || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if ((fn & 1n) === 0n) {
        do { fn >>= 1n; sn >>= 1n; } while ((fn & 1n) === 0n && fn !== 0n);
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  if (sn !== 0n) throw new MerkleError("merkle/bad-proof-length", "consistency proof is shorter than the geometry requires");
  var okOld = _ctEq(fr, oldRoot);
  var okNew = _ctEq(sr, newRoot);
  return okOld && okNew;
}

/**
 * @primitive  pki.merkle.root
 * @signature  pki.merkle.root(leafHashes) -> Buffer
 * @since      0.8.34
 * @status     stable
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.leafHash, pki.merkle.inclusionProof, pki.merkle.verifyInclusion
 *
 * The RFC 6962 Merkle Tree Hash `MTH(D[n])` over a whole tree, returned as a
 * 32-byte root ready to pass to `verifyInclusion` as `rootHash`. Takes leaf
 * HASHES, the same form `verifyInclusion` takes as `leafHash`; map entries
 * through `pki.merkle.leafHash` first. An empty array is the empty tree and
 * returns `emptyRootHash()`.
 *
 * Throws `merkle/bad-input` if `leafHashes` is not an array or a leaf is not a
 * Buffer / Uint8Array, `merkle/bad-hash-length` if a leaf is not exactly 32
 * bytes, and `merkle/too-many-leaves` above `C.LIMITS.MERKLE_MAX_LEAVES`.
 *
 * @example
 *   var leaves = [Buffer.from([0]), Buffer.from([1])].map(pki.merkle.leafHash);
 *   pki.merkle.root(leaves); // -> <Buffer 32-byte tree head>
 */
function root(leafHashes) {
  var leaves = _leafArray(leafHashes, "leafHashes");
  if (leaves.length === 0) return emptyRootHash();
  return _mth(leaves, 0, leaves.length);
}

/**
 * @primitive  pki.merkle.inclusionProof
 * @signature  pki.merkle.inclusionProof(opts) -> Buffer[]
 * @since      0.8.34
 * @status     stable
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.verifyInclusion, pki.merkle.root
 *
 * Produce the RFC 6962 sec. 2.1.1 audit path `PATH(leafIndex, D[n])` for one
 * leaf of a tree held in memory. The returned array is the `proof` that
 * `verifyInclusion` folds against `root(leafHashes)`.
 *
 * The tree size is the length of `leafHashes` and is not a separate option, so
 * a size and a leaf array cannot disagree. Throws `merkle/empty-tree` on an
 * empty tree, `merkle/index-out-of-range` for a `leafIndex` at or above the leaf
 * count, and the `leafHashes` errors `root` throws.
 *
 * @opts
 *   leafHashes:  Buffer[],       // the whole tree, each leaf a 32-byte hash
 *   leafIndex:   number | bigint, // 0-based position of the leaf to prove
 *
 * @example
 *   var leaves = [Buffer.from([0]), Buffer.from([1])].map(pki.merkle.leafHash);
 *   pki.merkle.inclusionProof({ leafHashes: leaves, leafIndex: 0 }); // -> [<Buffer ...>]
 */
var _INCLUSION_PROOF_KEYS = Object.assign(Object.create(null), { leafHashes: 1, leafIndex: 1 });
function inclusionProof(opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _INCLUSION_PROOF_KEYS, _merkleErr,
    "merkle/bad-input", "unknown inclusionProof option ");
  var leaves = _leafArray(opts.leafHashes, "leafHashes");
  var n = leaves.length;
  if (n === 0) throw new MerkleError("merkle/empty-tree", "an empty tree has no leaves to include");
  var leafIndex = _coerceCoord(opts.leafIndex, "leafIndex");
  var m = guard.range.int(leafIndex, 0n, BigInt(n - 1), _merkleErr,
    "merkle/index-out-of-range", "leafIndex");
  return _path(leaves, 0, n, m);
}

/**
 * @primitive  pki.merkle.consistencyProof
 * @signature  pki.merkle.consistencyProof(opts) -> Buffer[]
 * @since      0.8.34
 * @status     stable
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.verifyConsistency, pki.merkle.root
 *
 * Produce the RFC 6962 sec. 2.1.2 consistency proof `PROOF(oldSize, D[n])`
 * between an older tree of `oldSize` leaves and the tree held in `leafHashes`.
 * The returned array is the `proof` that `verifyConsistency` checks against
 * `root(leafHashes.slice(0, oldSize))` and `root(leafHashes)`.
 *
 * The newer size is the length of `leafHashes` and is not a separate option.
 * Equal sizes produce the empty proof, which is what the verifier requires
 * there. Throws `merkle/old-size-exceeds-new` when `oldSize` is past the leaf
 * count and `merkle/no-consistency-claim` for an `oldSize` of 0 against a
 * non-empty tree, matching `verifyConsistency`: RFC 6962 sec. 2.1.2 defines the
 * proof for `0 < oldSize < newSize`, so there is no proof to produce.
 *
 * @opts
 *   leafHashes:  Buffer[],        // the newer tree, each leaf a 32-byte hash
 *   oldSize:     number | bigint, // leaf count of the older tree
 *
 * @example
 *   var leaves = [Buffer.from([0]), Buffer.from([1])].map(pki.merkle.leafHash);
 *   pki.merkle.consistencyProof({ leafHashes: leaves, oldSize: 1 }); // -> [<Buffer ...>]
 */
var _CONSISTENCY_PROOF_KEYS = Object.assign(Object.create(null), { leafHashes: 1, oldSize: 1 });
function consistencyProof(opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _CONSISTENCY_PROOF_KEYS, _merkleErr,
    "merkle/bad-input", "unknown consistencyProof option ");
  var leaves = _leafArray(opts.leafHashes, "leafHashes");
  var n = leaves.length;
  var oldSize = _coerceCoord(opts.oldSize, "oldSize");
  if (oldSize > BigInt(n)) {
    throw new MerkleError("merkle/old-size-exceeds-new", "oldSize " + oldSize + " exceeds newSize " + n);
  }
  if (oldSize === 0n) {
    if (n === 0) return [];
    throw new MerkleError("merkle/no-consistency-claim", NO_CONSISTENCY_CLAIM);
  }
  var m = guard.range.int(oldSize, 1n, BigInt(n), _merkleErr, "merkle/bad-input", "oldSize");
  if (m === n) return [];
  return _subproof(leaves, 0, n, m, true);
}

module.exports = {
  leafHash:          leafHash,
  nodeHash:          nodeHash,
  emptyRootHash:     emptyRootHash,
  root:              root,
  verifyInclusion:   verifyInclusion,
  verifyConsistency: verifyConsistency,
  inclusionProof:    inclusionProof,
  consistencyProof:  consistencyProof,
};
