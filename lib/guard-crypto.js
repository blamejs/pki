// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var nodeCrypto = require("node:crypto");
var intrinsic = require("./guard-intrinsic");
var _freeze = intrinsic.freeze;

/** @internal The hash operations, captured at load. The prototype is read from an instance rather than
 *  named, `node:crypto` exporting no Hash constructor. */
var _createHash = nodeCrypto.createHash;
var _hashProto = intrinsic.getPrototypeOf(_createHash("sha256"));
var _hashUpdate = intrinsic.uncurry(_hashProto.update);
var _hashDigest = intrinsic.uncurry(_hashProto.digest);

/** A digest taken through operations captured at load. `createHash(name).update(b).digest()` reaches
 * `update` and `digest` off the live hash prototype, both ordinary writable properties, so a
 * replacement decides what the digest is OVER. Measured: a replaced `update` that filled the content
 * buffer before forwarding put the digest of other bytes into the attribute set
 * `pki.cms.authenticate` computes its MAC over, and the message then failed to verify against the
 * content it carries. A digest in this toolkit names a key, binds a certificate, or is the value a
 * signature covers, so the operation that computes it is not the caller's to choose.
 *
 * @enforced-by behavioral -- the shape detector for this one is written and NOT armed. Its rule is
 * `createHash\s*\([^)]*\)\s*\.(?:update|digest)\s*\(`, which is rename-proof and would catch the class
 * anywhere, and 33 sites across 19 lib modules still carry it, so arming it now would fail the gate on
 * a clean tree. It arms with that migration. Until then the guard is the RED conformance vector: a
 * replaced hash `update` cannot choose the content a message digest covers, driven through
 * `pki.cms.authenticate` and read back with `pki.cms.decrypt`.
 */
function digest(name, bytes) {
  return _hashDigest(_hashUpdate(_createHash(name), bytes));
}

// @enforced-by guard-shape-reinlined
// @guard-shape \.timingSafeEqual\s*\(
function constantTimeEqual(a, b) {
  return a.length === b.length && nodeCrypto.timingSafeEqual(a, b);
}

// @enforced-by behavioral -- shares the octet-alignment rule below; a bare
function isOctetAligned(bitString) {
  return !!bitString && bitString.unusedBits === 0;
}

// @enforced-by behavioral -- .unusedBits !== 0 is a per-field RFC rule, and the
function assertOctetAligned(bitString, E, code, label) {
  if (!isOctetAligned(bitString)) {
    throw E(code, (label || "signature") + " BIT STRING must be octet-aligned (0 unused bits)");
  }
  return bitString;
}

module.exports = _freeze({ constantTimeEqual: constantTimeEqual, digest: digest,
  isOctetAligned: isOctetAligned, assertOctetAligned: assertOctetAligned });
