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
var _INCLUSION_KEYS = { leafIndex: 1, treeSize: 1, leafHash: 1, rootHash: 1, proof: 1 };
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
var _CONSISTENCY_KEYS = { oldSize: 1, newSize: 1, oldRoot: 1, newRoot: 1, proof: 1 };
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
    throw new MerkleError("merkle/no-consistency-claim",
      "an empty older tree (oldSize 0) makes no consistency claim about a non-empty newer tree: " +
      "RFC 6962 sec. 2.1.2 defines the proof for 0 < oldSize < newSize, and nothing here binds " +
      "newRoot. Verify an inclusion proof against the new tree, or start from a signed tree head " +
      "you already trust");
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

module.exports = {
  leafHash:          leafHash,
  nodeHash:          nodeHash,
  emptyRootHash:     emptyRootHash,
  verifyInclusion:   verifyInclusion,
  verifyConsistency: verifyConsistency,
};
