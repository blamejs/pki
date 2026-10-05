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

/** @internal The MAC operations, captured at load. `node:crypto` exports no Hmac constructor either,
 *  and an Hmac does not share the Hash prototype, so it gets its own pair. */
var _createHmac = nodeCrypto.createHmac;
var _hmacProto = intrinsic.getPrototypeOf(_createHmac("sha256", "x"));
var _hmacUpdate = intrinsic.uncurry(_hmacProto.update);
var _hmacDigest = intrinsic.uncurry(_hmacProto.digest);

/** @internal The native signature operations, captured at load. */
var _nodeVerify = nodeCrypto.verify;
var _nodeSign = nodeCrypto.sign;

/** @internal The constant-time comparison, captured at load. It is the operation a MAC verdict rests
 *  on, so a replacement answering `true` accepts any equal-length wrong MAC. */
var _timingSafeEqual = nodeCrypto.timingSafeEqual;

/** @internal The RSA padding and salt-length values, in one home rather than read from the module at
 *  each call site. MEASURED: this is NOT a capture against replacement, because there is nothing to
 *  capture against. `crypto.constants` is a non-writable, non-configurable property of the module and
 *  each value on it is non-writable and non-configurable too, so assignment silently fails,
 *  `defineProperty` throws, and replacing the whole object silently fails. What this gives is one place
 *  that answers which padding scheme a verb runs under, so a reader does not re-derive the question per
 *  module and a new module does not pick a value by copying a neighbor. */
var _nodeConstants = nodeCrypto.constants;
var padding = _freeze({
  RSA_PKCS1: _nodeConstants.RSA_PKCS1_PADDING,
  RSA_PKCS1_OAEP: _nodeConstants.RSA_PKCS1_OAEP_PADDING,
  RSA_PKCS1_PSS: _nodeConstants.RSA_PKCS1_PSS_PADDING,
});
var saltLength = _freeze({
  AUTO: _nodeConstants.RSA_PSS_SALTLEN_AUTO,
  DIGEST: _nodeConstants.RSA_PSS_SALTLEN_DIGEST,
});

/** @internal The key imports, captured at load. A verifier checks a signature against whatever key
 *  object it is handed, so the import decides the verdict as surely as the verifier does: one
 *  returning another genuine key of the same family makes a signature made by that key verify against
 *  the material a caller pinned. */
var _createPublicKey = nodeCrypto.createPublicKey;
var _createPrivateKey = nodeCrypto.createPrivateKey;
var _createSecretKey = nodeCrypto.createSecretKey;

/** @internal The three KeyObject `export` methods, captured at load. `node:crypto` exports no
 *  constructor carrying them: `KeyObject.prototype` has no `export`, and `PublicKeyObject`,
 *  `PrivateKeyObject` and `SecretKeyObject` each own one. So one sample pair and one secret key are
 *  made here to read the three prototypes from, measured at 0.02 ms, and the keys are discarded.
 *
 *  The sample is a P-256 pair, and the generation is part of `require`. An algorithm outside the
 *  FIPS 140-3 boundary would therefore make the whole package unloadable under `crypto.setFips(1)`:
 *  OpenSSL's FIPS provider carries no Ed25519, so the generation raises ERR_OSSL_EVP_UNSUPPORTED
 *  before any export is reached, and a caller needing only approved RSA or EC operations could not
 *  require the package at all. The prototypes do not depend on the algorithm, measured across the
 *  Ed25519, P-256 and RSA pairs, so one approved pair yields both. */
var _sampleKeyPair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
var _publicProto = intrinsic.getPrototypeOf(_sampleKeyPair.publicKey);
var _privateProto = intrinsic.getPrototypeOf(_sampleKeyPair.privateKey);
var _secretProto = intrinsic.getPrototypeOf(_createSecretKey(intrinsic.bufferAlloc(32)));
var _publicExport = intrinsic.uncurry(_publicProto.export);
var _privateExport = intrinsic.uncurry(_privateProto.export);
var _secretExport = intrinsic.uncurry(_secretProto.export);

/** A signature verified through the operation captured at load. Same arguments as `crypto.verify`.
 *
 * `crypto.verify` is an ordinary writable property of the module object, and it was read once per
 * signature at every call site, so a replacement installed after the package loaded decided the
 * verdict: one returning `true` made TUF metadata carrying a 64-byte all-zero signature meet its
 * threshold against a genuine pinned key. That is the whole answer, not a detail of it.
 *
 * The shape excludes its own routing call: `guard.crypto.verify(` contains `crypto.verify(`, so
 * without the lookbehind the detector fires on every consumer it is meant to bless.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.)(?:nodeCrypto|crypto)\.verify\s*\(
 */
function verify(algorithm, data, key, signature) {
  return _nodeVerify(algorithm, data, key, signature);
}

/** A signature produced through the operation captured at load. Same arguments as `crypto.sign`.
 *
 * Captured for the reason `verify` above gives: a replaced signer produces a signature over bytes
 * the caller did not ask about, and the key-pair probe in `pki.key` checks a signature it made
 * itself, so a replacement that agreed with its own forgery would pass the probe.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.)(?:nodeCrypto|crypto)\.sign\s*\(
 */
function sign(algorithm, data, key) {
  return _nodeSign(algorithm, data, key);
}

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
 * anywhere, and 19 sites across 11 lib modules still carry it, so arming it now would fail the gate on
 * a clean tree. It arms with that migration. A module that captures `createHash` into a local and then
 * chains off it is the worst of the three states, since it reads as converted and is not: those are
 * gone. Until then the guard is the RED conformance vector: a
 * replaced hash `update` cannot choose the content a message digest covers, driven through
 * `pki.cms.authenticate` and read back with `pki.cms.decrypt`.
 */
function digest(name, bytes) {
  return _hashDigest(_hashUpdate(_createHash(name), bytes));
}

/** A digest over SEVERAL parts, fed in order through the operations captured at load. It is `digest`
 * for a preimage the caller assembles as a list rather than as one buffer, which keeps a multi-part
 * hash from having to concatenate first: a transparency-log key identifier is a digest over a name, a
 * separator, an algorithm byte and the key, and the identifier is what matches a signature line to a
 * caller's key.
 *
 * A part is passed to the captured `update` as it is, so a string part is read as UTF-8 exactly as
 * `hash.update(string)` would read it.
 *
 * @enforced-by behavioral -- shares the unarmed shape `digest` below describes.
 */
function digestParts(name, parts) {
  var h = _createHash(name);
  for (var i = 0; i < parts.length; i++) _hashUpdate(h, parts[i]);
  return _hashDigest(h);
}

/** An extendable-output function squeezed to `outLen` bytes, through the operations captured at load.
 * A single-stage KDF derives a key pair and the HPKE key schedule's secrets this way, so a replaced
 * `update` chooses what the derivation covers and a replaced `digest` chooses the key material itself.
 * Measured: an `update` returning its receiver without forwarding made two X25519/SHAKE128 setups with
 * different encapsulations derive identical exports, so a session key no longer depended on the
 * encapsulation it was negotiated under.
 *
 * @enforced-by behavioral -- shares the unarmed shape `digest` above describes. The guard is the RED
 * conformance vector: two HPKE setups whose encapsulations differ must not export the same secret
 * while the hash prototype is replaced.
 */
function xof(name, bytes, outLen) {
  return _hashDigest(_hashUpdate(_createHash(name, { outputLength: outLen }), bytes));
}

/** A MAC over `bytes` under `key`, through the operations captured at load. HKDF-Extract and each
 * HKDF-Expand round are MACs, so a replacement here decides the pseudo-random key an entire key
 * schedule hangs off, and the HPKE and CMC paths both derive their traffic keys through it.
 *
 * @enforced-by behavioral -- the Hmac prototype's `update` and `digest` are ordinary writable
 * properties, with the same absence of a rename-proof shape as `digest` above. The guard is the RED
 * conformance vector over the key schedule.
 */
function hmac(name, key, bytes) {
  return _hmacDigest(_hmacUpdate(_createHmac(name, key), bytes));
}

/** A key imported through the operation captured at load. Same arguments as `crypto.createPublicKey`,
 * `crypto.createPrivateKey` and `crypto.createSecretKey`.
 *
 * @enforced-by behavioral -- the shape `nodeCrypto\.create(?:Public|Private|Secret)Key\s*\(` is
 * rename-proof and would catch the class anywhere, and 42 sites across 9 lib modules still reach the
 * module property directly on the key-agreement, KEM and key-format paths, so arming it now would fail
 * the gate on a clean tree. It arms with that migration. Until then the guard is the RED conformance
 * vector: a replaced `crypto.createPublicKey` returning another genuine key cannot substitute the key a
 * signature is verified against, driven through `pki.tlog.verifyNote` and `pki.key.publicFromPrivate`.
 */
function publicKey(spec) { return _createPublicKey(spec); }

// @enforced-by behavioral -- shares the migration note on `publicKey` above; the signer's own key is
function privateKey(spec) { return _createPrivateKey(spec); }

// @enforced-by behavioral -- shares the migration note on `publicKey` above; a MAC key substituted at
function secretKey(material) { return _createSecretKey(material); }

/** A KeyObject exported through the operation captured at load. `keyObject.export(spec)` reaches the
 * method off the live prototype, so a replacement decides the bytes a caller is handed: one exporting
 * a fixed value made two distinct authorized TUF keys carry the same material identifier, which took a
 * two-key threshold down to one signature. The method is chosen by the key's PROTOTYPE rather than by
 * its `type`, which is itself a replaceable accessor, and an object whose prototype is none of the
 * three is refused rather than guessed at.
 *
 * @enforced-by behavioral -- shares the migration note on the imports above.
 */
function exportKey(keyObject, spec) {
  var proto = keyObject === null || keyObject === undefined ? null : intrinsic.getPrototypeOf(keyObject);
  if (proto === _publicProto) return _publicExport(keyObject, spec);
  if (proto === _privateProto) return _privateExport(keyObject, spec);
  if (proto === _secretProto) return _secretExport(keyObject, spec);
  throw new TypeError("guard.crypto.exportKey: expects a node:crypto KeyObject");
}

// @enforced-by guard-shape-reinlined
// @guard-shape \.timingSafeEqual\s*\(
function constantTimeEqual(a, b) {
  return a.length === b.length && _timingSafeEqual(a, b);
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
  digestParts: digestParts, xof: xof, hmac: hmac, verify: verify, sign: sign,
  publicKey: publicKey, privateKey: privateKey, secretKey: secretKey, exportKey: exportKey,
  padding: padding, saltLength: saltLength,
  isOctetAligned: isOctetAligned, assertOctetAligned: assertOctetAligned });
