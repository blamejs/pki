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

/** @internal The key agreement and the key generation, captured at load. Read off the module handle
 *  at call time, each decides a value no later check recovers: a replaced agreement returns the
 *  traditional half of a shared secret outright, measured by driving `pki.hpke.decap` with one
 *  returning a fixed buffer, which derived a secret from the value the replacement chose; and a
 *  replaced generation decides the ephemeral key an encapsulation is made under. `node:crypto` is an
 *  ordinary module object that nothing freezes, so the handle is as replaceable as a prototype. */
var _diffieHellman = nodeCrypto.diffieHellman;
var _generateKeyPairSync = nodeCrypto.generateKeyPairSync;

/** @internal The ML-KEM encapsulation and decapsulation, and the AEAD transform constructions, all
 *  captured at load for the same reason as the agreement above: each returns or decides a value no
 *  later check recovers. `encapsulate` and `decapsulate` carry the post-quantum half of a hybrid
 *  shared secret, and the two transform constructions decide the cipher a seal and an open run
 *  under, so a replacement returns a ciphertext of its own choosing. */
var _encapsulate = nodeCrypto.encapsulate;
var _decapsulate = nodeCrypto.decapsulate;
var _createCipheriv = nodeCrypto.createCipheriv;
var _createDecipheriv = nodeCrypto.createDecipheriv;

/** @internal The randomness, the password-based and extract-and-expand KDFs, the RSA transforms and
 *  the ephemeral-agreement constructor, all captured at load for the same reason. Each decides a
 *  value outright rather than a claim about one: the randomness is where a content-encryption key, a
 *  nonce, an IV and a salt are born, so a replacement returning a value it knows hands it every
 *  message those protect; a replaced KDF decides the key-encryption key a password unwraps; and a
 *  replaced RSA transform decides the key-transport ciphertext a recipient receives, or the secret a
 *  recipient recovers from one. */
var _randomBytes = nodeCrypto.randomBytes;
var _randomFillSync = nodeCrypto.randomFillSync;
var _randomUUID = nodeCrypto.randomUUID;
var _pbkdf2Sync = nodeCrypto.pbkdf2Sync;
var _pbkdf2 = nodeCrypto.pbkdf2;
var _hkdfSync = nodeCrypto.hkdfSync;
var _publicEncrypt = nodeCrypto.publicEncrypt;
var _privateDecrypt = nodeCrypto.privateDecrypt;
var _createECDH = nodeCrypto.createECDH;

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

/** @internal The KeyObject identity accessors, captured at load. These are GETTERS rather than
 *  methods, which makes them no less replaceable and the reads no less live: `key.asymmetricKeyType`
 *  is a call into a function the prototype holds. What each answers is which key this IS, and that
 *  decides an algorithm binding, a curve, a modulus length and whether a pair corresponds, so a
 *  replacement answering `"rsa"` for an Ed25519 key made an import accept that key as RSA-PSS, which
 *  is a type confusion on the one question the import exists to settle. They sit on the shared
 *  parents (`KeyObject.prototype` and the asymmetric parent between it and the two key prototypes),
 *  so the descriptors are taken from there rather than from the leaf prototypes. */
function _getterOf(proto, name) {
  for (var cur = proto; cur !== null && cur !== intrinsic.ObjectProto; cur = intrinsic.getPrototypeOf(cur)) {
    var d = intrinsic.getOwnPropertyDescriptor(cur, name);
    if (d !== undefined && typeof d.get === "function") return intrinsic.uncurry(d.get);
  }
  throw new TypeError("guard-crypto: node:crypto carries no " + name + " accessor to capture");
}
var _keyTypeGet = _getterOf(_publicProto, "asymmetricKeyType");
var _keyDetailsGet = _getterOf(_publicProto, "asymmetricKeyDetails");
var _keyKindGet = _getterOf(_publicProto, "type");
var _secretSizeGet = _getterOf(_secretProto, "symmetricKeySize");

/** @internal The AEAD transform methods, captured at load off the two prototypes. Capturing the
 *  CONSTRUCTION is not enough on its own: the object it returns carries its methods as ordinary
 *  prototype properties, so a caller reaching one through that object takes a live read. The
 *  authentication tag is the worst of them, because a replaced `setAuthTag` makes a decryptor
 *  authenticate against a tag it was never handed, which is a fail-open on the only check that says
 *  an AEAD message is genuine, and a replaced `getAuthTag` puts a chosen tag on the wire.
 *
 *  `Cipheriv` and `Decipheriv` own SEPARATE copies and carry different sets: only an encryptor has
 *  `getAuthTag` and only a decryptor has `setAuthTag`, so the two are captured apart and a verb that
 *  belongs to one refuses the other rather than reaching a method that is not there. The sample
 *  transforms are discarded; AES-256-GCM is inside the FIPS boundary, so the load stays loadable
 *  under `crypto.setFips(1)` for the reason the key pair above gives. */
var _sampleKey = intrinsic.bufferAlloc(32);
var _sampleIv = intrinsic.bufferAlloc(12);
var _cipherProto = intrinsic.getPrototypeOf(_createCipheriv("aes-256-gcm", _sampleKey, _sampleIv));
var _decipherProto = intrinsic.getPrototypeOf(_createDecipheriv("aes-256-gcm", _sampleKey, _sampleIv));
var _cipherUpdate = intrinsic.uncurry(_cipherProto.update);
var _cipherFinal = intrinsic.uncurry(_cipherProto.final);
var _cipherSetAAD = intrinsic.uncurry(_cipherProto.setAAD);
var _cipherGetAuthTag = intrinsic.uncurry(_cipherProto.getAuthTag);
var _cipherSetAutoPadding = intrinsic.uncurry(_cipherProto.setAutoPadding);
var _decipherUpdate = intrinsic.uncurry(_decipherProto.update);
var _decipherFinal = intrinsic.uncurry(_decipherProto.final);
var _decipherSetAAD = intrinsic.uncurry(_decipherProto.setAAD);
var _decipherSetAuthTag = intrinsic.uncurry(_decipherProto.setAuthTag);
var _decipherSetAutoPadding = intrinsic.uncurry(_decipherProto.setAutoPadding);

/** @internal The ephemeral-agreement methods and the point conversion, captured at load for the same
 *  reason. Each decides an EC point, which is a public key: a replacement returns a point of its own
 *  choosing, and a caller that pins a key then pins the replacement's. `convertKey` is a static on
 *  the constructor rather than a module property, which makes it no less replaceable. */
var _ecdhProto = intrinsic.getPrototypeOf(_createECDH("prime256v1"));
var _ecdhSetPrivateKey = intrinsic.uncurry(_ecdhProto.setPrivateKey);
var _ecdhGetPublicKey = intrinsic.uncurry(_ecdhProto.getPublicKey);
var _ecdhConvertKey = nodeCrypto.ECDH.convertKey;

/** @internal Node's own WebCrypto `exportKey`, with the object it is called on, both captured at
 *  load. It is reached as `crypto.webcrypto.subtle.exportKey`, which is three property reads deep,
 *  and it returns key material. */
var _nodeSubtle = nodeCrypto.webcrypto.subtle;
var _nodeSubtleExportKey = intrinsic.uncurry(_nodeSubtle.exportKey);

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
function digest(name, bytes, encodings) {
  var inputEncoding = encodings === undefined ? undefined : encodings.input;
  var outputEncoding = encodings === undefined ? undefined : encodings.output;
  return _hashDigest(_hashUpdate(_createHash(name), bytes, inputEncoding), outputEncoding);
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
function digestParts(name, parts, outLen) {
  var h = outLen === undefined ? _createHash(name) : _createHash(name, { outputLength: outLen });
  for (var i = 0; i < parts.length; i++) _hashUpdate(h, parts[i]);
  return _hashDigest(h);
}

/** A hash handle, through the construction captured at load, for a caller that feeds it in chunks and
 * cannot hold the whole input. An unavailable digest name throws here, which is also how a caller
 * asks whether one is available.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.createHash\s*\(
 */
function hash(name, outLen) {
  return outLen === undefined ? _createHash(name) : _createHash(name, { outputLength: outLen });
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
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.createHmac\s*\(
 */
function hmac(name, key, bytes) {
  return _hmacDigest(_hmacUpdate(_createHmac(name, key), bytes));
}

/** A key imported through the operation captured at load. Same arguments as `crypto.createPublicKey`,
 * `crypto.createPrivateKey` and `crypto.createSecretKey`. A verifier checks a signature against
 * whatever key object it is handed, so an import returning another genuine key of the same family
 * makes a signature made by that key verify against the material a caller pinned.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.createPublicKey\s*\(
 */
function publicKey(spec) { return _createPublicKey(spec); }

/** A private key imported through the operation captured at load. The signer's own key is chosen
 * here, so a replacement signs with a key the caller never named.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.createPrivateKey\s*\(
 */
function privateKey(spec) { return _createPrivateKey(spec); }

/** A raw key imported through the operation captured at load. A MAC key substituted at import makes
 * a MAC verify against material the caller never supplied.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.createSecretKey\s*\(
 */
function secretKey(material) { return _createSecretKey(material); }

/** The static Diffie-Hellman agreement, through the operation captured at load. `crypto.diffieHellman`
 * read off the module handle at call time returns the traditional half of a shared secret, so a
 * replacement supplies that half outright: driving `pki.hpke.decap` with one returning a fixed buffer
 * derived a secret from the value the replacement chose, and no later check recovers it, because the
 * value IS the secret rather than a claim about it.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.diffieHellman\s*\(
 */
function diffieHellman(spec) { return _diffieHellman(spec); }

/** A key pair, through the operation captured at load. A replacement decides the ephemeral key an
 * encapsulation is made under, which is the other half of the same exchange.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.generateKeyPairSync\s*\(
 */
function generateKeyPair(type, options) {
  return options === undefined ? _generateKeyPairSync(type) : _generateKeyPairSync(type, options);
}

/** The ML-KEM encapsulation, through the operation captured at load. It returns the post-quantum half
 * of a hybrid shared secret outright, so a replacement supplies that half.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.encapsulate\s*\(
 * @guard-via compositeKem\.encapsulate\s*\(
 */
function encapsulate(publicKeyObject) { return _encapsulate(publicKeyObject); }

/** The ML-KEM decapsulation, through the operation captured at load.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.decapsulate\s*\(
 * @guard-via compositeKem\.decapsulate\s*\(
 */
function decapsulate(privateKeyObject, enc) { return _decapsulate(privateKeyObject, enc); }

/** An AEAD encryption transform, through the construction captured at load. A replacement decides the
 * cipher a seal runs under, and therefore the ciphertext and the tag.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.createCipheriv\s*\(
 */
function cipher(algorithm, key, iv, options) {
  return options === undefined ? _createCipheriv(algorithm, key, iv)
    : _createCipheriv(algorithm, key, iv, options);
}

/** An AEAD decryption transform, through the construction captured at load.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.createDecipheriv\s*\(
 */
function decipher(algorithm, key, iv, options) {
  return options === undefined ? _createDecipheriv(algorithm, key, iv)
    : _createDecipheriv(algorithm, key, iv, options);
}

/** Random octets, through the operation captured at load. This is where a content-encryption key, a
 * MAC key, an IV, a nonce and a salt are born, so a replacement returning a value it already knows
 * hands it every message those protect, and nothing downstream can tell a chosen key from a random
 * one.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.randomBytes\s*\(
 */
function randomBytes(n) { return _randomBytes(n); }

/** A buffer filled with random octets in place, through the operation captured at load.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.randomFillSync\s*\(
 */
function randomFill(buffer) { return _randomFillSync(buffer); }

/** A random UUID, through the operation captured at load.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.randomUUID\s*\(
 */
function randomUUID() { return _randomUUID(); }

/** The PBKDF2 derivation, through the operation captured at load. It decides the key-encryption key a
 * password unwraps, so a replacement returning a fixed value makes every password open the message.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.pbkdf2Sync\s*\(
 */
function pbkdf2(password, salt, iterations, keylen, digestName) {
  return _pbkdf2Sync(password, salt, iterations, keylen, digestName);
}

/** The PBKDF2 derivation in its callback form, through the operation captured at load.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.pbkdf2\s*\(
 */
function pbkdf2Async(password, salt, iterations, keylen, digestName, callback) {
  return _pbkdf2(password, salt, iterations, keylen, digestName, callback);
}

/** The HKDF expand-and-extract, through the operation captured at load.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.hkdfSync\s*\(
 */
function hkdf(digestName, ikm, salt, info, keylen) {
  return _hkdfSync(digestName, ikm, salt, info, keylen);
}

/** The RSA public-key transform, through the operation captured at load. It decides the key-transport
 * ciphertext a recipient receives, so a replacement encrypts to a key of its own choosing.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.publicEncrypt\s*\(
 */
function publicEncrypt(spec, bytes) { return _publicEncrypt(spec, bytes); }

/** The RSA private-key transform, through the operation captured at load. It returns the secret a
 * recipient recovers from a key-transport ciphertext, so a replacement supplies that secret.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.privateDecrypt\s*\(
 */
function privateDecrypt(spec, bytes) { return _privateDecrypt(spec, bytes); }

/** An ephemeral elliptic-curve agreement, through the constructor captured at load. The object it
 * returns carries its methods live, so a caller derives a point with `ecPointFromScalar` rather than
 * driving this one.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.createECDH\s*\(
 */
function ecdh(curveName) { return _createECDH(curveName); }

/** The EC point a scalar generates, in uncompressed SEC1 form, with the agreement built and driven
 * entirely through operations captured at load. A point is a public key, so a replaced
 * `setPrivateKey` or `getPublicKey` returns one of its own choosing and a caller that pins a key
 * pins the replacement's.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.setPrivateKey\s*\(
 */
function ecPointFromScalar(curveName, scalar) {
  var handle = _createECDH(curveName);
  _ecdhSetPrivateKey(handle, scalar);
  return _ecdhGetPublicKey(handle, null, "uncompressed");
}

/** An EC point converted between SEC1 forms, through the static captured at load. De-compressing a
 * point is also what decides it is ON the curve, so a replacement answers both questions.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.convertKey\s*\(
 */
function ecConvertPoint(point, curveName, format) {
  return _ecdhConvertKey(point, curveName, undefined, undefined, format);
}

/** Key material exported through NODE's own WebCrypto, reached through the operation and the receiver
 * captured at load. This is the fallback for a `CryptoKey` from another implementation, and it
 * returns key material, so a replacement decides those bytes.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape \.webcrypto\.subtle\.exportKey\s*\(
 */
function nodeExportKey(format, key) { return _nodeSubtleExportKey(_nodeSubtle, format, key); }

/** @internal Which of the two transform prototypes `t` has. A verb that belongs to one direction
 *  refuses the other rather than reaching for a method that is not there, and the question is asked
 *  of the PROTOTYPE rather than with `instanceof`, which consults a `Symbol.hasInstance` the
 *  constructor's holder can replace. */
function _transformKind(t) {
  var proto = t === null || t === undefined ? null : intrinsic.getPrototypeOf(t);
  if (proto === _cipherProto) return "cipher";
  if (proto === _decipherProto) return "decipher";
  return null;
}

/** Bytes put through an AEAD or block transform, in either direction, through the method captured at
 * load for that direction.
 *
 * @enforced-by behavioral -- the shape it would declare is the one `guard.secret.cipherFinish`
 * already owns (an `update` paired with a `final`), and that guard is the only caller: a transform is
 * driven to produce bytes that owe a wipe, so the two rules live at one door.
 */
function transformUpdate(t, bytes) {
  var kind = _transformKind(t);
  if (kind === "cipher") return _cipherUpdate(t, bytes);
  if (kind === "decipher") return _decipherUpdate(t, bytes);
  throw new TypeError("guard.crypto.transformUpdate: expects a node:crypto cipher or decipher");
}

/** The trailing bytes of a transform, through the method captured at load for its direction.
 *
 * @enforced-by behavioral -- shares the note on `transformUpdate` above, whose pair it is.
 */
function transformFinal(t) {
  var kind = _transformKind(t);
  if (kind === "cipher") return _cipherFinal(t);
  if (kind === "decipher") return _decipherFinal(t);
  throw new TypeError("guard.crypto.transformFinal: expects a node:crypto cipher or decipher");
}

/** The additional authenticated data an AEAD transform covers, in either direction. A replacement
 * changes what the tag commits to without changing the tag.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.setAAD\s*\(
 */
function transformSetAAD(t, aad) {
  var kind = _transformKind(t);
  if (kind === "cipher") return _cipherSetAAD(t, aad);
  if (kind === "decipher") return _decipherSetAAD(t, aad);
  throw new TypeError("guard.crypto.transformSetAAD: expects a node:crypto cipher or decipher");
}

/** Turns a transform's automatic padding off, in either direction. The key-wrap and CBC paths need
 * the block boundary they computed, not one the transform adds, so a replacement that leaves padding
 * on changes the block count a wrap produces.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.setAutoPadding\s*\(
 */
function transformNoPadding(t) {
  var kind = _transformKind(t);
  if (kind === "cipher") return _cipherSetAutoPadding(t, false);
  if (kind === "decipher") return _decipherSetAutoPadding(t, false);
  throw new TypeError("guard.crypto.transformNoPadding: expects a node:crypto cipher or decipher");
}

/** The authentication tag an encryptor produced. Only an encryptor carries it, so a decryptor is
 * refused rather than silently answering undefined, and a replacement puts a chosen tag on the wire.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.getAuthTag\s*\(
 */
function cipherAuthTag(t) {
  if (_transformKind(t) !== "cipher") {
    throw new TypeError("guard.crypto.cipherAuthTag: expects a node:crypto cipher");
  }
  return _cipherGetAuthTag(t);
}

/** The authentication tag a decryptor must verify against. Only a decryptor carries it. This is the
 * single check that says an AEAD message is genuine, so a replacement that discards the tag makes the
 * decryptor authenticate against one it was never handed, and the message opens.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.setAuthTag\s*\(
 */
function decipherSetAuthTag(t, tag) {
  if (_transformKind(t) !== "decipher") {
    throw new TypeError("guard.crypto.decipherSetAuthTag: expects a node:crypto decipher");
  }
  return _decipherSetAuthTag(t, tag);
}

/** The algorithm family of `v` when `v` IS one of node's KeyObjects, and `undefined` otherwise. The
 * call sites that ask this are deciding whether a caller handed them a key object at all, and the
 * duck-typed form they asked it with (`typeof v === "object" && v.asymmetricKeyType != null`) is
 * satisfied by a plain object carrying that one field, so a forged object passed as a key and was
 * then used as one. Asking the prototype first settles both questions at once.
 *
 * @enforced-by behavioral -- the shape is `keyType`'s, which is declared on it below; this is the
 * tolerant door onto the same accessor, and the RED conformance vector drives a forged object through
 * the verbs that used to accept it.
 */
function keyTypeOf(v) { return isKeyObject(v) ? _keyTypeGet(v) : undefined; }

/** Whether `v` is "public", "private" or "secret" when it IS a KeyObject, and `undefined` otherwise.
 *
 * @enforced-by behavioral -- shares the note on `keyTypeOf` above.
 */
function keyKindOf(v) { return isKeyObject(v) ? _keyKindGet(v) : undefined; }

/** A key's algorithm parameters when `v` IS a KeyObject, and `undefined` otherwise.
 *
 * @enforced-by behavioral -- shares the note on `keyTypeOf` above.
 */
function keyDetailsOf(v) { return isKeyObject(v) ? _keyDetailsGet(v) : undefined; }

/** Which algorithm family a key belongs to ("ed25519", "rsa", "rsa-pss", "ec", "x25519", ...), read
 * through the accessor captured at load. This is the one question an import exists to settle, and it
 * decides which algorithm a signature is checked under, so a replacement answering `"rsa"` for an
 * Ed25519 key made an import accept it as RSA-PSS.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.asymmetricKeyType\b
 */
function keyType(keyObject) { return _keyTypeGet(keyObject); }

/** A key's algorithm parameters (`modulusLength`, `namedCurve`, `hashAlgorithm`, ...), read through
 * the accessor captured at load. A modulus length and a curve name are both checks a caller pinned.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.asymmetricKeyDetails\b
 */
function keyDetails(keyObject) { return _keyDetailsGet(keyObject); }

/** Whether a key is "public", "private" or "secret", read through the accessor captured at load. A
 * signer that accepts a public key where it needed a private one, or the reverse, is deciding on this.
 *
 * @enforced-by behavioral -- `.type` is the most common field name in the toolkit, carried by every
 * parsed ASN.1 node and every algorithm descriptor, so a shape matching it would fire on hundreds of
 * sites that are not key objects at all. The guard is the RED conformance vector over the import.
 */
function keyKind(keyObject) { return _keyKindGet(keyObject); }

/** A raw key's length in bits, read through the accessor captured at load.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape (?<!guard\.crypto)\.symmetricKeySize\b
 */
function secretKeySize(keyObject) { return _secretSizeGet(keyObject); }

/** Whether `v` is one of node's three KeyObject kinds, asked of its PROTOTYPE. `v instanceof
 * crypto.KeyObject` reads the constructor off the module object and then consults a
 * `Symbol.hasInstance` either side can replace, so the answer is taken from the prototypes this
 * module captured at load instead.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape instanceof\s+(?:nodeCrypto|crypto)\.KeyObject
 */
function isKeyObject(v) {
  var proto = v === null || v === undefined ? null : intrinsic.getPrototypeOf(v);
  return proto === _publicProto || proto === _privateProto || proto === _secretProto;
}

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
  digestParts: digestParts, xof: xof, hash: hash, hmac: hmac, verify: verify, sign: sign,
  publicKey: publicKey, privateKey: privateKey, secretKey: secretKey, exportKey: exportKey,
  diffieHellman: diffieHellman, generateKeyPair: generateKeyPair,
  encapsulate: encapsulate, decapsulate: decapsulate, cipher: cipher, decipher: decipher,
  randomBytes: randomBytes, randomFill: randomFill, randomUUID: randomUUID,
  pbkdf2: pbkdf2, pbkdf2Async: pbkdf2Async, hkdf: hkdf,
  publicEncrypt: publicEncrypt, privateDecrypt: privateDecrypt,
  ecdh: ecdh, ecPointFromScalar: ecPointFromScalar,
  ecConvertPoint: ecConvertPoint, nodeExportKey: nodeExportKey, isKeyObject: isKeyObject,
  keyType: keyType, keyDetails: keyDetails, keyKind: keyKind, secretKeySize: secretKeySize,
  keyTypeOf: keyTypeOf, keyKindOf: keyKindOf, keyDetailsOf: keyDetailsOf,
  transformUpdate: transformUpdate, transformFinal: transformFinal,
  transformSetAAD: transformSetAAD, transformNoPadding: transformNoPadding,
  cipherAuthTag: cipherAuthTag, decipherSetAuthTag: decipherSetAuthTag,
  padding: padding, saltLength: saltLength,
  isOctetAligned: isOctetAligned, assertOctetAligned: assertOctetAligned });
