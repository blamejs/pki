// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.merkle
 * @nav        Transparency
 * @title      Merkle
 * @order      220
 * @slug       merkle
 *
 * @intro
 *   RFC 6962 (Certificate Transparency) / RFC 9162 (CT 2.0) Merkle-tree hash
 *   and proof-verification core -- the load-bearing primitive a static-CT
 *   client, a Merkle-Tree-Certificates relying party, and a sigstore / Rekor
 *   inclusion check all compose. It is ALL strict verification over SHA-256:
 *   zero new crypto.
 *
 *   `leafHash` / `nodeHash` / `emptyRootHash` build the tree hashes with the
 *   two domain-separation prefixes fixed by the spec -- a leaf is
 *   `SHA-256(0x00 || entry)`, an interior node is `SHA-256(0x01 || left ||
 *   right)`, the empty tree is `SHA-256("")`. Those `0x00` / `0x01` prefixes
 *   are the second-preimage defense: without them a leaf whose bytes equal a
 *   valid interior node's preimage could be smuggled in as present.
 *
 *   `verifyInclusion` folds an audit path back to a root and constant-time-
 *   compares it to a trusted checkpoint root; `verifyConsistency` reconstructs
 *   BOTH the old and the new root from a consistency proof (the append-only
 *   guarantee lives in the old-root leg). Both are fail-closed: a malformed
 *   coordinate, an out-of-range index, an inverted window, a wrong hash length,
 *   or a proof whose node count does not match the tree geometry throws a typed
 *   `merkle/*` error; the ONLY boolean-`false` result is the final root
 *   comparison ("root matched" vs "did not"). A `false` from `verifyInclusion`
 *   means "not proven present against this root", never "validly absent" -- an
 *   inclusion proof cannot express absence. Tree coordinates are uint64, carried
 *   as `BigInt` so a large index is never `Number`-narrowed. This is NOT a DER
 *   format: like `pki.ct` it is a companion module reached explicitly, never
 *   routed by the detect-and-parse orchestrator.
 *
 * @card
 *   `leafHash` / `nodeHash` / `emptyRootHash` + `verifyInclusion` /
 *   `verifyConsistency` over sync SHA-256, fail-closed, transport-free.
 */

var nodeCrypto = require("node:crypto");
var constants = require("./constants");
var frameworkError = require("./framework-error");

var MerkleError = frameworkError.MerkleError;

var SHA256_BYTES = 32;
var UINT64_MAX = 18446744073709551615n; // 2n ** 64n - 1n
var LEAF_PREFIX = Buffer.from([0x00]);
var NODE_PREFIX = Buffer.from([0x01]);
var EMPTY = Buffer.alloc(0);

function _sha256(buf) {
  return nodeCrypto.createHash("sha256").update(buf).digest();
}

function _toBuffer(v, field) {
  if (!Buffer.isBuffer(v) && !(v instanceof Uint8Array)) {
    throw new MerkleError("merkle/bad-input", field + " must be a Buffer or Uint8Array");
  }
  try {
    // A zero-copy view over the same bytes; this also surfaces a detached
    // backing ArrayBuffer (a transferred / structuredClone'd view) as a typed
    // error here rather than a raw TypeError from a later concat / digest.
    return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
  } catch (e) {
    throw new MerkleError("merkle/bad-input", field + " is not a usable byte view", e);
  }
}

function _node32(v, field) {
  var buf = _toBuffer(v, field);
  if (buf.length !== SHA256_BYTES) {
    throw new MerkleError("merkle/bad-hash-length", field + " must be exactly 32 bytes, got " + buf.length);
  }
  return buf;
}

// number | bigint -> a validated BigInt in [0, 2^64). A Number >= 2^53 (where
// precision is lost), a negative / non-integer, or a non-number-non-bigint
// throws -- the number-narrows-unbounded-integer discipline for uint64 tree
// coordinates.
function _coerceCoord(v, field) {
  var b;
  if (typeof v === "bigint") {
    b = v;
  } else if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0) {
      throw new MerkleError("merkle/bad-input", field + " must be a non-negative safe integer or a BigInt (a Number >= 2^53 loses precision)");
    }
    b = BigInt(v);
  } else {
    throw new MerkleError("merkle/bad-input", field + " must be a number or a BigInt");
  }
  if (b < 0n || b > UINT64_MAX) {
    throw new MerkleError("merkle/bad-input", field + " must be in [0, 2^64)");
  }
  return b;
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

// Constant-time equality of two already-validated equal-length 32-byte buffers.
function _ctEq(a, b) {
  return a.length === b.length && nodeCrypto.timingSafeEqual(a, b);
}

/**
 * @primitive  pki.merkle.leafHash
 * @signature  pki.merkle.leafHash(entry) -> Buffer
 * @since      0.1.28
 * @status     experimental
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
 * @status     experimental
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
 * @status     experimental
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
 * @status     experimental
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.leafHash, pki.merkle.verifyConsistency
 *
 * Verify an RFC 6962 / RFC 9162 audit (inclusion) proof: fold `leafHash` up the
 * audit path and constant-time-compare the reconstructed root to `rootHash`.
 * Returns `true` iff the proof binds the leaf to the root; a well-formed proof
 * that does not match returns `false` ("not proven present against this root",
 * NEVER "validly absent"). A malformed input -- a coordinate that is not a
 * non-negative integer (or a Number >= 2^53), `treeSize` 0, `leafIndex >=
 * treeSize`, a non-32-byte hash, or a proof whose node count does not match the
 * tree geometry -- throws a typed `merkle/*` error.
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
function verifyInclusion(opts) {
  opts = opts || {};
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
 * @status     experimental
 * @spec       RFC 6962, RFC 9162
 * @related    pki.merkle.verifyInclusion, pki.merkle.emptyRootHash
 *
 * Verify an RFC 6962 / RFC 9162 consistency proof between an older tree of
 * `oldSize` leaves (root `oldRoot`) and a newer tree of `newSize` leaves (root
 * `newRoot`). Reconstructs BOTH roots from the proof and constant-time-compares
 * each; returns `true` iff both match (the append-only guarantee lives in the
 * old-root leg -- a proof that yields a valid `newRoot` but the wrong `oldRoot`
 * is a rewritten history and returns `false`). The empty tree is a prefix of
 * every tree, so `oldSize` 0 checks ONLY `oldRoot == emptyRootHash()` and places
 * NO binding on `newRoot` (an empty prior tree carries no append-only guarantee
 * -- authenticate `newRoot` separately, e.g. via its checkpoint signature); equal
 * sizes require an empty proof and `oldRoot == newRoot`. A malformed input --
 * `oldSize > newSize`, a non-empty proof where
 * the geometry requires none (or empty where it requires one), a non-32-byte
 * hash, or a wrong node count -- throws a typed `merkle/*` error.
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
function verifyConsistency(opts) {
  opts = opts || {};
  var oldSize = _coerceCoord(opts.oldSize, "oldSize");
  var newSize = _coerceCoord(opts.newSize, "newSize");
  var oldRoot = _node32(opts.oldRoot, "oldRoot");
  var newRoot = _node32(opts.newRoot, "newRoot");
  var proof = _proofNodes(opts.proof);

  if (oldSize > newSize) throw new MerkleError("merkle/old-size-exceeds-new", "oldSize " + oldSize + " exceeds newSize " + newSize);
  if (oldSize === 0n) {
    if (proof.length !== 0) throw new MerkleError("merkle/bad-proof-length", "an empty older tree admits only the empty consistency proof");
    return _ctEq(oldRoot, emptyRootHash());
  }
  if (oldSize === newSize) {
    if (proof.length !== 0) throw new MerkleError("merkle/sizes-equal-nonempty-proof", "equal tree sizes require an empty consistency proof");
    return _ctEq(oldRoot, newRoot);
  }
  if (proof.length === 0) throw new MerkleError("merkle/empty-consistency-proof", "a non-trivial consistency proof must not be empty");

  var path = proof;
  if ((oldSize & (oldSize - 1n)) === 0n) {
    // oldSize is an exact power of two: the old root is the first proof node
    // (it is not otherwise carried in the proof).
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
  return _ctEq(fr, oldRoot) && _ctEq(sr, newRoot);
}

module.exports = {
  leafHash:          leafHash,
  nodeHash:          nodeHash,
  emptyRootHash:     emptyRootHash,
  verifyInclusion:   verifyInclusion,
  verifyConsistency: verifyConsistency,
};
