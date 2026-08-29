// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.webcrypto
 * @nav        Core
 * @title      WebCrypto
 * @fullname   WebCrypto: a SubtleCrypto surface over node:crypto
 * @order      50
 * @featured   true
 * @slug       webcrypto
 *
 * @intro
 *   A zero-dependency W3C Web Cryptography API (`Crypto` / `SubtleCrypto`
 *   / `CryptoKey`) built directly on Node's native `node:crypto`. It is
 *   the toolkit's injectable crypto engine, presented in the standard
 *   WebCrypto shape, so operators, and every higher structure (X.509,
 *   CMS, OCSP), reach for one familiar surface.
 *
 *   Unlike the browser's built-in `crypto.subtle`, this engine is
 *   **PQC-first without being PQC-only**: the FIPS 204 ML-DSA and FIPS
 *   205 SLH-DSA signature suites sit alongside the full classical set PKI
 *   still runs on -- RSASSA-PKCS1-v1_5, RSA-PSS, RSA-OAEP, ECDSA, ECDH,
 *   Ed25519 / Ed448, AES-GCM / CBC / KW, HMAC, HKDF, PBKDF2, the SHA family
 *   (including legacy SHA-1 for old certificates and signatures), and the
 *   SHAKE128 / SHAKE256 extendable-output functions as message digests.
 *   FIPS 203 ML-KEM key generation, encoding, certificate/PKCS#8 import,
 *   and encapsulation/decapsulation (encapsulateBits / decapsulateBits over
 *   Node's crypto.encapsulate/decapsulate) are all available.
 *   Because it is OpenSSL-backed, every key and signature it emits is
 *   interoperable with OpenSSL, NSS, and other PKI implementations.
 *
 * @card
 *   A zero-dep, PQC-first W3C WebCrypto (`SubtleCrypto`) engine over
 *   `node:crypto`: ML-DSA and SLH-DSA signatures alongside the full
 *   classical algorithm set.
 */

var nodeCrypto = require("node:crypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var constants = require("./constants");
var asn1 = require("./asn1-der");
var oid = require("./oid");
// What this engine reads from the runtime while it is deciding something, taken at load. The
// decisions here are the ones the whole toolkit signs and verifies behind: whether a value IS a
// CryptoKey, which algorithm a key names, how many octets a modulus has. A caller who receives
// control afterwards -- through an accessor on a key-like object, or while a verb is suspended on
// an await -- can replace any of them, and every check around them still runs and still passes.
// See guard-intrinsic for the whole captured set.
var intrinsic = require("./guard-intrinsic");
var _isArray = intrinsic.isArray;
var _hasOwn = intrinsic.hasOwn;
var _stringify = intrinsic.stringify;
var _bufferFrom = intrinsic.bufferFrom;
var _bufToString = intrinsic.uncurry(Buffer.prototype.toString);
// The node Hash instance methods, captured at load. digestStream feeds chunks across `await` points,
// and a co-resident that replaced Hash.prototype.update while the stream was suspended between chunks
// could drop or alter one -- making digest("ab") equal digest("a") -- and, because both streamed
// signing and verification trust this digest, forge a valid verdict over bytes the stream never
// yielded. Calling the captured update/digest keeps the hash bound to the bytes the stream saw. The
// one-shot digest needs no such capture: its single update and digest run with no suspension between.
var _hashUpdate = intrinsic.uncurry(nodeCrypto.Hash.prototype.update);
var _hashDigest = intrinsic.uncurry(nodeCrypto.Hash.prototype.digest);
var _bufferConcat = intrinsic.bufferConcat;
var _bufferAlloc = intrinsic.bufferAlloc;
var _isBuffer = intrinsic.isBuffer;
var _keys = intrinsic.keys;
var _map = intrinsic.map;
var _forEach = intrinsic.forEach;
var _indexOf = intrinsic.indexOf;
var _isInteger = intrinsic.isInteger;
var _join = intrinsic.join;
var _filter = intrinsic.filter;
var _arraySlice = intrinsic.arraySlice;
var _defineProperty = intrinsic.defineProperty;
var _max = intrinsic.max;
var _parseInt = intrinsic.parseInt;
var _isFinite = intrinsic.isFinite;
var _String = intrinsic.String;
var _Number = intrinsic.Number;
var _BigInt = intrinsic.BigInt;
var _Uint8Array = intrinsic.Uint8Array;
var _assign = intrinsic.assign;
var _create = intrinsic.create;
var _isView = intrinsic.isView;
var _asyncIterator = intrinsic.asyncIterator;
var _toUpperCase = intrinsic.toUpperCase;
var _toLowerCase = intrinsic.toLowerCase;
var _stringIndexOf = intrinsic.stringIndexOf;
var _subarray = intrinsic.subarray;
var _arrayBufferSlice = intrinsic.arrayBufferSlice;
var _numberToString = intrinsic.numberToString;
var _bigIntToString = intrinsic.bigIntToString;
var _push = intrinsic.push;
var _concat = intrinsic.concat;
// Promise.resolve is a constructor method, so it keeps its receiver: `_resolve(Promise, x)`.
var _resolve = intrinsic.uncurry(intrinsic.promiseResolve);
var _types = intrinsic.types;

// Single-owner error class -- co-located with its module (framework-error
// stays the cross-module home; this is webcrypto-private). withCause: a
// failure discovered while processing decrypted/untrusted bytes threads the
// underlying fault instead of discarding it.
var WebCryptoError = frameworkError.defineClass("WebCryptoError", { withCause: true });

var MAX_RANDOM_BYTES = 65536;

// ---- value helpers ---------------------------------------------------

function _toBuf(data, who) {
  return guard.bytes.source(data, WebCryptoError, "webcrypto/data", who || "input");
}

function _toArrayBuffer(buf) {
  return _arrayBufferSlice(buf.buffer, buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function _wcErr(code, msg) { return new WebCryptoError(code, msg); }
// STRICT base64url decode via the shared encoding guard: a missing / non-canonical
// / non-alphabet value throws webcrypto/data instead of silently importing wrong
// key material (the lenient Buffer.from(String(undefined),"base64url") returned a
// bogus 6-byte key). Node's own canonical JWK export (_rawPublic) round-trips
// cleanly, so the strictness is benign there and fail-closed on untrusted import.
function _b64urlToBuf(s, who) { return guard.encoding.base64url(s, null, _wcErr, "webcrypto/data", who || "base64url value"); }
function _bufToB64url(buf) { return _bufToString(_bufferFrom(buf), "base64url"); }

function _normalizeAlg(algorithm, who) {
  var alg = (typeof algorithm === "string") ? { name: algorithm } : algorithm;
  if (!alg || typeof alg.name !== "string") {
    throw new WebCryptoError("webcrypto/syntax", (who || "operation") + ": algorithm must be a string or an object with a name");
  }
  var out = {};
  for (var k in alg) { if (_hasOwn(alg, k)) out[k] = alg[k]; }
  out.name = _toUpperCase(alg.name);
  return out;
}

// The counterpart to _normalizeAlg's upper-casing: _normalizeAlg upper-cases every algorithm name for
// case-insensitive INTERNAL matching, but the name a CryptoKey EMITS on `.algorithm.name` MUST carry the
// WebCrypto-registered casing, which for a few algorithms is not all-upper: "RSASSA-PKCS1-v1_5" (lowercase
// v), "Ed25519" / "Ed448" (mixed). Every emitted algorithm.name passes through here so a consumer that
// compares against the standard name (e.g. a signer matching a CryptoKey to a certificate key) matches.
var _STD_ALG_NAME = { "RSASSA-PKCS1-V1_5": "RSASSA-PKCS1-v1_5", "ED25519": "Ed25519", "ED448": "Ed448" };
function _stdName(name) { return _STD_ALG_NAME[name] || name; }

// WebCrypto hash name -> node digest name. SHA-1 is retained for
// backwards compatibility with legacy certificates and signatures.
var HASH_NODE = {
  "SHA-1":   "sha1",
  "SHA-224": "sha224",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
  "SHA3-256": "sha3-256",
  "SHA3-384": "sha3-384",
  "SHA3-512": "sha3-512",
};

// FIPS 202 extendable-output functions, as message digests. Deliberately a
// separate table from HASH_NODE, not rows added to it: an XOF's output
// length is a parameter and not a property of its name, and node:crypto
// refuses an XOF at every other HASH_NODE consumer (signature, HMAC, HKDF,
// PBKDF2, OAEP). Widening the shared table would turn those consumers' typed
// "unsupported hash" rejection into a raw error from the underlying library.
// The length is fixed by the name, not chosen by the caller: RFC 8702 sec. 4
// requires the output length of SHAKE128 or SHAKE256 used as a message digest
// to be 32 or 64 bytes respectively, and RFC 9814 sec. 4 and
// draft-ietf-lamps-cms-composite-sigs sec. 3 restate it for their profiles.
var XOF_NODE = {
  "SHAKE128": { node: "shake128", length: 32 },
  "SHAKE256": { node: "shake256", length: 64 },
};

function _hashNode(h, who) {
  var name = (typeof h === "string") ? h : (h && h.name);
  // The case fold is what picks the registry row, so it runs through the captured method: dispatched
  // live, a replaced `toUpperCase` answering "SHA-1" makes a caller who asked for SHA-256 receive a
  // SHA-1 digest, and nothing between here and the hash says the algorithm changed.
  var node = HASH_NODE[_toUpperCase(_String(name))];
  if (!node) throw new WebCryptoError("webcrypto/not-supported", (who || "operation") + ": unsupported hash " + _stringify(name));
  return node;
}

// W3C HMAC get-key-length: an explicit `length` is used as given (validated
// to a positive multiple of 8, so the byte-level key material is exact and
// never a raw RangeError out of randomBytes); an OMITTED length defaults to
// the block size of the hash, the HMAC key-pad width, and not the digest
// size. A digest-size default would mint different key material than every
// conforming WebCrypto for identical inputs, so MACs keyed through this
// engine would fail to verify elsewhere.
var HMAC_BLOCK_BITS = {
  "SHA-1": 512, "SHA-256": 512, "SHA-384": 1024, "SHA-512": 1024,
  "SHA3-256": 1088, "SHA3-384": 832, "SHA3-512": 576,
};

function _hmacLengthBits(alg, who) {
  var name = (typeof alg.hash === "string") ? alg.hash : (alg.hash && alg.hash.name);
  var blockBits = HMAC_BLOCK_BITS[_toUpperCase(_String(name))];
  if (!blockBits) throw new WebCryptoError("webcrypto/not-supported", who + ": unsupported hash " + _stringify(name));
  if (alg.length == null) return blockBits;
  if (typeof alg.length !== "number" || !_isFinite(alg.length) || alg.length <= 0 || alg.length % 8 !== 0) {
    throw new WebCryptoError("webcrypto/syntax", who + ": HMAC length must be a positive multiple of 8 bits");
  }
  return alg.length;
}

// WebCrypto namedCurve -> node namedCurve.
var CURVE_NODE = { "P-256": "prime256v1", "P-384": "secp384r1", "P-521": "secp521r1" };
var CURVE_FIELD_BYTES = { "P-256": 32, "P-384": 48, "P-521": 66 };

var ML_DSA_NODE = { "ML-DSA-44": "ml-dsa-44", "ML-DSA-65": "ml-dsa-65", "ML-DSA-87": "ml-dsa-87" };
var ML_KEM_NODE = { "ML-KEM-512": "ml-kem-512", "ML-KEM-768": "ml-kem-768", "ML-KEM-1024": "ml-kem-1024" };

// FIPS 205 SLH-DSA -- stateless hash-based signatures. All twelve
// parameter sets Node exposes; signing is one-shot (null algorithm), the
// same shape as ML-DSA / EdDSA. ML-KEM covers key-generation / encoding /
// import plus encapsulateBits / decapsulateBits over Node's KEM primitive.
var SLH_DSA_NODE = {};
["sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
 "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"
].forEach(function (s) { SLH_DSA_NODE["SLH-DSA-" + _toUpperCase(s)] = "slh-dsa-" + s; });

// The algorithm names each keyed operation recognizes. Membership is checked
// before the algorithm/key name binding so an unrecognized algorithm reports
// NotSupportedError while a recognized-but-wrong-for-this-key one reports
// InvalidAccessError, matching the W3C error ordering.
var SIGN_VERIFY_NAMES = {};
["RSASSA-PKCS1-V1_5", "RSA-PSS", "ECDSA", "ED25519", "ED448", "HMAC"]
  .concat(_keys(ML_DSA_NODE), _keys(SLH_DSA_NODE))
  .forEach(function (n) { SIGN_VERIFY_NAMES[n] = true; });
var ENCRYPT_DECRYPT_NAMES = { "RSA-OAEP": true, "AES-GCM": true, "AES-CBC": true, "AES-CTR": true };
var DERIVE_NAMES = { "ECDH": true, "X25519": true, "X448": true, "HKDF": true, "PBKDF2": true, "X963KDF": true };
// The secret-key / KDF algorithms whose key material is raw octets (imported via "raw" or a
// JWK "oct"), never an SPKI / PKCS#8 asymmetric-key structure. importKey("spki"|"pkcs8", ...)
// under one of these names is unsupported (W3C: NotSupportedError) and, without this gate, it
// would mint a mislabeled CryptoKey wrapping an asymmetric handle and dodge the algorithm-keyed
// pkcs8 pre-validation (e.g. the RFC 9935 ML-KEM CHOICE guard).
var SECRET_KEY_NAMES = { "AES-GCM": true, "AES-CBC": true, "AES-CTR": true, "AES-KW": true, "HMAC": true, "HKDF": true, "PBKDF2": true, "X963KDF": true };

// ---- CryptoKey -------------------------------------------------------

/**
 * @primitive  pki.webcrypto.CryptoKey
 * @signature  new pki.webcrypto.CryptoKey(type, extractable, algorithm, usages, handle)
 * @since      0.1.0
 * @status     stable
 * @spec       W3C WebCrypto sec. cryptokey
 *
 * Opaque handle to key material, matching the W3C `CryptoKey` shape:
 * `{ type, extractable, algorithm, usages }`. The underlying
 * `node:crypto` KeyObject is non-enumerable and never serialized --
 * extract material only through `subtle.exportKey`, and only when the key
 * was created `extractable`. Instances are produced by
 * `subtle.generateKey` / `subtle.importKey`; the constructor is rarely
 * called directly.
 *
 * @example
 *   var kp = await pki.webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
 *   kp.publicKey.type;       // "public"
 *   kp.publicKey.algorithm;  // { name: "Ed25519" }
 */
function CryptoKey(type, extractable, algorithm, usages, handle) {
  this.type = type;
  this.extractable = !!extractable;
  // The algorithm is immutable both ways. The PROPERTY is defined non-writable and non-configurable so
  // it cannot be REPLACED wholesale (`key.algorithm = { hash: "SHA-512" }`), and its value is a frozen
  // COPY -- a caller's importKey params object is left untouched -- so its fields, the nested `hash` an
  // RSA/HMAC signature reads among them, cannot be MUTATED. This engine reads key.algorithm.hash live
  // when it signs, and a W3C CryptoKey's [[algorithm]] is immutable for exactly this reason: neither
  // swapping the object nor a field of it (e.g. from a microtask during a signing await) can make the
  // hash the signature is computed under differ from the one checked against a header algorithm.
  var frozenAlg = algorithm;
  if (frozenAlg && typeof frozenAlg === "object") {
    frozenAlg = _assign({}, algorithm);
    if (frozenAlg.hash && typeof frozenAlg.hash === "object") frozenAlg.hash = intrinsic.freeze(_assign({}, frozenAlg.hash));
    frozenAlg = intrinsic.freeze(frozenAlg);
  }
  _defineProperty(this, "algorithm", { value: frozenAlg, enumerable: true });
  // The copy is what the key will be asked about for the rest of its life, so the method that makes
  // it is the captured one: a replaced `slice` hands back a list the caller still controls. The
  // list-ness is checked rather than left to the copy to discover -- `Array.prototype.slice` on a
  // number yields an empty list, so a non-list would have minted a key permitted for NOTHING
  // instead of naming the bad argument.
  if (usages != null && !_isArray(usages)) {
    throw new WebCryptoError("webcrypto/syntax", "usages must be an array of key-usage strings");
  }
  this.usages = usages ? _arraySlice(usages) : [];
  _defineProperty(this, "_handle", { value: handle, enumerable: false });
}

// This engine reads key material through its own CryptoKey handle, which a key minted by another
// WebCrypto implementation does not carry -- W3C leaves cross-implementation use undefined, and
// reaching for the missing handle raises a bare type error from inside the crypto library rather
// than a verdict. Refuse it here, naming which of the two it is: a foreign CryptoKey (import it
// through this engine, or use the pki.* verbs, which adopt one) or something that is no key at all.
function _requireOwnKey(key, who) {
  if (key instanceof CryptoKey) return;
  if (isCryptoKeyLike(key)) {
    throw new WebCryptoError("webcrypto/invalid-access", who + ": the key was created by a different WebCrypto implementation; re-import it through this one");
  }
  throw new WebCryptoError("webcrypto/invalid-access", who + ": a CryptoKey is required");
}

function _requireUsage(key, usage) {
  _requireOwnKey(key, usage);
  // The membership test IS the permission check, so it runs through the captured method: dispatched
  // live, an `Array.prototype.indexOf` replaced after load reports every usage present and a key
  // minted to verify signs instead, with this refusal never raised.
  if (_indexOf(key.usages, usage) === -1) {
    throw new WebCryptoError("webcrypto/invalid-access", "key is not permitted for '" + usage + "' (usages: " + _join(key.usages, ",") + ")");
  }
}

// W3C WebCrypto sign/verify/encrypt/decrypt/deriveBits/deriveKey/wrapKey/
// unwrapKey MUST throw an InvalidAccessError when the normalized algorithm's
// name differs from the key's own algorithm name. The binding is load-bearing
// for the one-shot signature families (EdDSA / ML-DSA / SLH-DSA): node derives
// the algorithm from the KEY handle, so without this check the requested name
// would be silently ignored and an operation requested under algorithm X could
// be satisfied by a key of algorithm Y (algorithm confusion).
function _requireAlgMatch(alg, key, who) {
  var keyName = key && key.algorithm && key.algorithm.name;
  if (_toUpperCase(_String(keyName)) !== alg.name) {
    throw new WebCryptoError("webcrypto/invalid-access", who + ": algorithm " + _stringify(alg.name) + " does not match the key's algorithm " + _stringify(keyName));
  }
}

// ---- SubtleCrypto ----------------------------------------------------

function SubtleCrypto() {}

SubtleCrypto.prototype.digest = async function digest(algorithm, data) {
  var name = _normalizeAlg(algorithm, "digest").name;
  var xof = XOF_NODE[_toUpperCase(_String(name))];
  // An XOF is always constructed with its output length stated. Omitting it
  // makes node emit a deprecation warning and fall back to a 32-byte squeeze,
  // which for SHAKE256 would silently produce half the required digest.
  var h = xof
    ? nodeCrypto.createHash(xof.node, { outputLength: xof.length })
    : nodeCrypto.createHash(_hashNode(name, "digest"));
  h.update(_toBuf(data, "digest"));
  return _toArrayBuffer(h.digest());
};

// Digest an async iterable of byte chunks under several algorithms in ONE pass, returning one
// ArrayBuffer per algorithm in order. Each result is byte-identical to digest(algorithms[i], <the
// concatenated chunks>): the same createHash + XOF handling, fed incrementally so an arbitrarily
// large payload is never held whole. The single pass is what lets a multi-signer detached CMS sign
// hash a single-use stream once for every distinct digest algorithm. Which algorithm each Hash runs
// is fixed up front through the captured name resolution (_normalizeAlg / _toUpperCase / _hashNode),
// exactly as the one-shot digest resolves it, so a replaced toUpperCase cannot swap SHA-256 for SHA-1
// mid-stream. A chunk that is not a BufferSource throws webcrypto/data, before it reaches a hash.
SubtleCrypto.prototype.digestStream = async function digestStream(algorithms, source) {
  if (!_isArray(algorithms) || !algorithms.length) {
    throw new WebCryptoError("webcrypto/syntax", "digestStream: algorithms must be a non-empty array of digest algorithms");
  }
  if (source == null || typeof source[_asyncIterator] !== "function") {
    throw new WebCryptoError("webcrypto/syntax", "digestStream: source must be an async iterable of byte chunks");
  }
  var hashes = _map(algorithms, function (algorithm) {
    var name = _normalizeAlg(algorithm, "digestStream").name;
    var xof = XOF_NODE[_toUpperCase(_String(name))];
    return xof
      ? nodeCrypto.createHash(xof.node, { outputLength: xof.length })
      : nodeCrypto.createHash(_hashNode(name, "digestStream"));
  });
  for await (var chunk of source) {
    var buf = _toBuf(chunk, "digestStream chunk");
    for (var i = 0; i < hashes.length; i++) _hashUpdate(hashes[i], buf);
  }
  return _map(hashes, function (h) { return _toArrayBuffer(_hashDigest(h)); });
};

SubtleCrypto.prototype.generateKey = async function generateKey(algorithm, extractable, keyUsages) {
  var alg = _normalizeAlg(algorithm, "generateKey");
  // Before the partition below, not only in the CryptoKey constructor: the asymmetric branch splits
  // the usages first, and `Array.prototype.filter` treats a non-list as array-like and yields `[]`,
  // so both halves reached the constructor already valid and the call minted an unusable PAIR
  // instead of naming the argument. The symmetric branches hand `usages` straight to the
  // constructor, which is why its own door caught those and not these.
  if (keyUsages != null && !_isArray(keyUsages)) {
    throw new WebCryptoError("webcrypto/syntax", "generateKey: keyUsages must be an array of key-usage strings");
  }
  var usages = keyUsages || [];
  var name = alg.name;

  // Symmetric keys.
  if (name === "AES-GCM" || name === "AES-CBC" || name === "AES-CTR" || name === "AES-KW") {
    var bits = alg.length;
    if (bits !== 128 && bits !== 192 && bits !== 256) throw new WebCryptoError("webcrypto/syntax", name + ": length must be 128/192/256");
    var secret = nodeCrypto.createSecretKey(nodeCrypto.randomBytes(bits / 8));
    return new CryptoKey("secret", extractable, { name: name, length: bits }, usages, secret);
  }
  if (name === "HMAC") {
    var lenBits = _hmacLengthBits(alg, "generateKey HMAC");
    var hkey = nodeCrypto.createSecretKey(nodeCrypto.randomBytes(lenBits / 8));
    return new CryptoKey("secret", extractable, { name: name, hash: { name: (typeof alg.hash === "string" ? alg.hash : alg.hash.name) }, length: lenBits }, usages, hkey);
  }

  // Asymmetric key pairs.
  var pair = _generateKeyPair(alg);
  var pubAlg = pair.algorithm;
  // Which usages each half of the pair is minted with -- the permission set every later operation
  // is checked against -- so the partition runs through the captured method.
  var privUsages = _filter(usages, function (u) { return u === "sign" || u === "deriveKey" || u === "deriveBits" || u === "decrypt" || u === "unwrapKey" || u === "decapsulateKey" || u === "decapsulateBits"; });
  var pubUsages = _filter(usages, function (u) { return u === "verify" || u === "encrypt" || u === "wrapKey" || u === "encapsulateKey" || u === "encapsulateBits"; });
  return {
    privateKey: new CryptoKey("private", extractable, pubAlg, privUsages, pair.privateKey),
    publicKey:  new CryptoKey("public", true, pubAlg, pubUsages, pair.publicKey),
  };
};

function _generateKeyPair(alg) {
  var name = alg.name, kp, algorithm;
  if (name === "RSASSA-PKCS1-V1_5" || name === "RSA-PSS" || name === "RSA-OAEP") {
    // Resolve the hash BEFORE generating. An RSA keygen is the expensive step here, and a hash
    // this engine cannot use yields a key that can never sign, so the refusal has to come first
    // or the caller pays for a keypair only to be told the request was unusable.
    var rsaHash = _hashObj(alg.hash, "generateKey " + name);
    kp = nodeCrypto.generateKeyPairSync("rsa", {
      modulusLength: alg.modulusLength || 2048,
      publicExponent: alg.publicExponent ? _bufToBigIntNum(alg.publicExponent) : 65537,
    });
    algorithm = { name: _stdName(name), modulusLength: alg.modulusLength || 2048, publicExponent: alg.publicExponent, hash: rsaHash };
  } else if (name === "ECDSA" || name === "ECDH") {
    var curve = alg.namedCurve;
    if (!CURVE_NODE[curve]) throw new WebCryptoError("webcrypto/not-supported", name + ": unsupported curve " + _stringify(curve));
    kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: CURVE_NODE[curve] });
    algorithm = { name: name, namedCurve: curve };
  } else if (name === "ED25519" || name === "ED448" || name === "X25519" || name === "X448") {
    kp = nodeCrypto.generateKeyPairSync(_toLowerCase(name));
    algorithm = { name: _stdName(name) };
  } else if (ML_DSA_NODE[name]) {
    kp = nodeCrypto.generateKeyPairSync(ML_DSA_NODE[name]);
    algorithm = { name: name };
  } else if (ML_KEM_NODE[name]) {
    kp = nodeCrypto.generateKeyPairSync(ML_KEM_NODE[name]);
    algorithm = { name: name };
  } else if (SLH_DSA_NODE[name]) {
    kp = nodeCrypto.generateKeyPairSync(SLH_DSA_NODE[name]);
    algorithm = { name: name };
  } else {
    throw new WebCryptoError("webcrypto/not-supported", "generateKey: unsupported algorithm " + _stringify(name));
  }
  return { publicKey: kp.publicKey, privateKey: kp.privateKey, algorithm: algorithm };
}

// The hash recorded on a CryptoKey's algorithm. The name is RESOLVED here, so an
// entry point refuses a hash this engine cannot use instead of minting a key that
// only fails at its first sign / verify / wrap -- after the caller has already paid
// for the key generation. Resolution runs through _hashNode itself rather than a
// second table, so what an entry point accepts cannot drift from what the
// operations support.
function _hashObj(h, who) { if (!h) return undefined; var n = (typeof h === "string" ? h : h.name); _hashNode(n, who || "importKey"); return { name: n }; }
// The node key argument for an ML-DSA sign/verify: the bare handle, or a
// { key, context } when the caller supplies an ML-DSA context. FIPS 204 bounds the
// context to 0..255 bytes; a longer one is a DataError at the API boundary, not a
// raw ERR_OUT_OF_RANGE from node.
function _mldsaKeyArg(alg, keyHandle, who) {
  if (alg.context == null) return keyHandle;
  var ctx = _toBuf(alg.context, who + " context");
  if (ctx.length > 255) throw new WebCryptoError("webcrypto/data", who + ": an ML-DSA context must be at most 255 bytes (FIPS 204)");
  return { key: keyHandle, context: ctx };
}
// publicExponent arrives as a W3C BigInteger octet string but node:crypto
// takes a JS number, so the value is bounds-checked BEFORE the Number()
// narrowing: an empty buffer has no integer value (BigInt("0x") is a raw
// SyntaxError), and a value above 2^32-1 is outside the interoperable
// WebCrypto exponent range and heads toward Number's exact-integer limit,
// where the narrowing would silently hand node a different exponent than
// the caller requested.
function _bufToBigIntNum(exp) {
  var b = _toBuf(exp, "publicExponent");
  if (b.length === 0) {
    throw new WebCryptoError("webcrypto/syntax", "publicExponent must be a non-empty BigInteger octet string");
  }
  var v = _BigInt("0x" + _bufToString(b, "hex"));
  if (v > 0xffffffffn) {
    throw new WebCryptoError("webcrypto/syntax", "publicExponent " + _bigIntToString(v) + " exceeds the 2^32-1 bound");
  }
  return _Number(v);
}

SubtleCrypto.prototype.sign = async function sign(algorithm, key, data) {
  var alg = _normalizeAlg(algorithm, "sign");
  _requireUsage(key, "sign");
  var buf = _toBuf(data, "sign");
  var name = alg.name;
  if (!SIGN_VERIFY_NAMES[name]) throw new WebCryptoError("webcrypto/not-supported", "sign: unsupported algorithm " + _stringify(name));
  _requireAlgMatch(alg, key, "sign");
  if (name === "RSASSA-PKCS1-V1_5") {
    return _toArrayBuffer(nodeCrypto.sign(_hashNode(key.algorithm.hash, "sign"), buf, key._handle));
  }
  if (name === "RSA-PSS") {
    return _toArrayBuffer(nodeCrypto.sign(_hashNode(key.algorithm.hash, "sign"), buf, {
      key: key._handle, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: (typeof alg.saltLength === "number" ? alg.saltLength : nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST),
    }));
  }
  if (name === "ECDSA") {
    return _toArrayBuffer(nodeCrypto.sign(_hashNode(alg.hash, "sign"), buf, { key: key._handle, dsaEncoding: "ieee-p1363" }));
  }
  if (ML_DSA_NODE[name]) {
    // ML-DSA (FIPS 204) accepts an optional context octet string; thread it through
    // signing symmetrically with verify so a context signature round-trips (a
    // signature made with a context verifies only under the SAME context).
    return _toArrayBuffer(nodeCrypto.sign(null, buf, _mldsaKeyArg(alg, key._handle, "sign")));
  }
  if (name === "ED25519" || name === "ED448" || SLH_DSA_NODE[name]) {
    return _toArrayBuffer(nodeCrypto.sign(null, buf, key._handle));
  }
  if (name === "HMAC") {
    var hm = nodeCrypto.createHmac(_hashNode(key.algorithm.hash, "sign"), key._handle);
    hm.update(buf);
    return _toArrayBuffer(hm.digest());
  }
  throw new WebCryptoError("webcrypto/not-supported", "sign: unsupported algorithm " + _stringify(name));
};

SubtleCrypto.prototype.verify = async function verify(algorithm, key, signature, data) {
  var alg = _normalizeAlg(algorithm, "verify");
  _requireUsage(key, "verify");
  var sig = _toBuf(signature, "verify");
  var buf = _toBuf(data, "verify");
  var name = alg.name;
  if (!SIGN_VERIFY_NAMES[name]) throw new WebCryptoError("webcrypto/not-supported", "verify: unsupported algorithm " + _stringify(name));
  _requireAlgMatch(alg, key, "verify");
  if (name === "RSASSA-PKCS1-V1_5") {
    return nodeCrypto.verify(_hashNode(key.algorithm.hash, "verify"), buf, key._handle, sig);
  }
  if (name === "RSA-PSS") {
    return nodeCrypto.verify(_hashNode(key.algorithm.hash, "verify"), buf, {
      key: key._handle, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: (typeof alg.saltLength === "number" ? alg.saltLength : nodeCrypto.constants.RSA_PSS_SALTLEN_DIGEST),
    }, sig);
  }
  if (name === "ECDSA") {
    return nodeCrypto.verify(_hashNode(alg.hash, "verify"), buf, { key: key._handle, dsaEncoding: "ieee-p1363" }, sig);
  }
  if (ML_DSA_NODE[name]) {
    // ML-DSA (FIPS 204) accepts an optional context octet string (the composite
    // signature construction passes the composite Domain as the ML-DSA context,
    // draft-ietf-lamps-pq-composite-sigs sec. 2). A context mismatch fails.
    return nodeCrypto.verify(null, buf, _mldsaKeyArg(alg, key._handle, "verify"), sig);
  }
  if (name === "ED25519" || name === "ED448" || SLH_DSA_NODE[name]) {
    return nodeCrypto.verify(null, buf, key._handle, sig);
  }
  if (name === "HMAC") {
    var hm = nodeCrypto.createHmac(_hashNode(key.algorithm.hash, "verify"), key._handle);
    hm.update(buf);
    // Verify must RESOLVE false for any invalid signature, including one of
    // the wrong length. timingSafeEqual throws RangeError on a length
    // mismatch, so gate on the (public) length first, then compare the bytes
    // in constant time. The length check leaks nothing a constant-time compare
    // would protect; the secret-dependent byte comparison is timingSafeEqual.
    var digest = hm.digest();
    return guard.crypto.constantTimeEqual(digest, sig);
  }
  throw new WebCryptoError("webcrypto/not-supported", "verify: unsupported algorithm " + _stringify(name));
};

// Run a node:crypto AES cipher sequence, converting any raw node fault -- a bad IV length,
// a failed GCM authentication tag, bad CBC padding -- into a typed OperationError. A
// decrypt of tampered ciphertext (or a malformed cipher parameter) is a typed webcrypto
// verdict, never a raw Error crossing the public API (input prep that already throws a
// typed error runs OUTSIDE this, so a typed fault is never double-wrapped).
function _runCipher(fn, who) {
  try { return fn(); }
  catch (e) { throw new WebCryptoError("webcrypto/operation", who + ": AES cipher operation failed (bad key / iv / tag / padding)", e); }
}

SubtleCrypto.prototype.encrypt = async function encrypt(algorithm, key, data) {
  var alg = _normalizeAlg(algorithm, "encrypt");
  _requireUsage(key, "encrypt");
  var buf = _toBuf(data, "encrypt");
  var name = alg.name;
  if (!ENCRYPT_DECRYPT_NAMES[name]) throw new WebCryptoError("webcrypto/not-supported", "encrypt: unsupported algorithm " + _stringify(name));
  _requireAlgMatch(alg, key, "encrypt");
  if (name === "RSA-OAEP") {
    return _toArrayBuffer(nodeCrypto.publicEncrypt({
      key: key._handle, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: _hashNode(key.algorithm.hash, "encrypt"),
      oaepLabel: alg.label ? _toBuf(alg.label, "encrypt label") : undefined,
    }, buf));
  }
  if (name === "AES-GCM") {
    var iv = _toBuf(alg.iv, "AES-GCM iv");
    var aad = alg.additionalData ? _toBuf(alg.additionalData, "AES-GCM aad") : null;
    return _toArrayBuffer(_runCipher(function () {
      return _withSecretBytes(key, function (kb) {
        var cipher = nodeCrypto.createCipheriv("aes-" + key.algorithm.length + "-gcm", kb, iv, { authTagLength: (alg.tagLength || 128) / 8 });
        if (aad) cipher.setAAD(aad);
        var ct = guard.secret.cipherFinish(cipher, buf, WebCryptoError, "webcrypto/operation", "an AES-GCM encrypt intermediate");
        return _bufferConcat([ct, cipher.getAuthTag()]);
      });
    }, "encrypt"));
  }
  if (name === "AES-CBC") {
    var cbcIv = _toBuf(alg.iv, "AES-CBC iv");
    return _toArrayBuffer(_runCipher(function () {
      return _withSecretBytes(key, function (kb) {
        var c2 = nodeCrypto.createCipheriv("aes-" + key.algorithm.length + "-cbc", kb, cbcIv);
        return guard.secret.cipherFinish(c2, buf, WebCryptoError, "webcrypto/operation", "an AES-CBC encrypt intermediate");
      });
    }, "encrypt"));
  }
  if (name === "AES-CTR") {
    _requireCtrLength128(alg);
    var ctrCounter = _toBuf(alg.counter, "AES-CTR counter");
    return _toArrayBuffer(_runCipher(function () {
      return _withSecretBytes(key, function (kb) {
        var c3 = nodeCrypto.createCipheriv("aes-" + key.algorithm.length + "-ctr", kb, ctrCounter);
        return guard.secret.cipherFinish(c3, buf, WebCryptoError, "webcrypto/operation", "an AES-CTR encrypt intermediate");
      });
    }, "encrypt"));
  }
  throw new WebCryptoError("webcrypto/not-supported", "encrypt: unsupported algorithm " + _stringify(name));
};

SubtleCrypto.prototype.decrypt = async function decrypt(algorithm, key, data) {
  var alg = _normalizeAlg(algorithm, "decrypt");
  _requireUsage(key, "decrypt");
  var buf = _toBuf(data, "decrypt");
  var name = alg.name;
  if (!ENCRYPT_DECRYPT_NAMES[name]) throw new WebCryptoError("webcrypto/not-supported", "decrypt: unsupported algorithm " + _stringify(name));
  _requireAlgMatch(alg, key, "decrypt");
  if (name === "RSA-OAEP") {
    // For a CMS key-transport recipient this plaintext IS the recovered content-encryption key, and
    // _toArrayBuffer copies it -- so the node-allocated buffer is finished with the moment the copy
    // exists, and nothing outside this function can reach it to clear it.
    var oaepOut = nodeCrypto.privateDecrypt({
      key: key._handle, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: _hashNode(key.algorithm.hash, "decrypt"),
      oaepLabel: alg.label ? _toBuf(alg.label, "decrypt label") : undefined,
    }, buf);
    try { return _toArrayBuffer(oaepOut); }
    finally { guard.secret.zeroize(oaepOut, WebCryptoError, "webcrypto/operation", "the RSA-OAEP decryption output"); }
  }
  if (name === "AES-GCM") {
    var tagLen = (alg.tagLength || 128) / 8;
    var iv = _toBuf(alg.iv, "AES-GCM iv");
    if (buf.length < tagLen) throw new WebCryptoError("webcrypto/operation", "decrypt: AES-GCM ciphertext is shorter than its authentication tag");
    // The split between ciphertext and tag decides which bytes are authenticated, so the window it
    // is taken with is the captured one: a replaced `subarray` hands the tag check other bytes.
    var ct = _subarray(buf, 0, buf.length - tagLen);
    var tag = _subarray(buf, buf.length - tagLen);
    var gcmAad = alg.additionalData ? _toBuf(alg.additionalData, "AES-GCM aad") : null;
    return _toArrayBuffer(_runCipher(function () {
      return _withSecretBytes(key, function (kb) {
        var d = nodeCrypto.createDecipheriv("aes-" + key.algorithm.length + "-gcm", kb, iv, { authTagLength: tagLen });
        if (gcmAad) d.setAAD(gcmAad);
        d.setAuthTag(tag);
        // The recovered plaintext exists in full before final() judges the tag, so a forged message
        // would otherwise abandon a readable copy on the throw path.
        return guard.secret.cipherFinish(d, ct, WebCryptoError, "webcrypto/operation", "the recovered AES-GCM plaintext");
      });
    }, "decrypt"));
  }
  if (name === "AES-CBC") {
    var cbcIv2 = _toBuf(alg.iv, "AES-CBC iv");
    return _toArrayBuffer(_runCipher(function () {
      return _withSecretBytes(key, function (kb) {
        var d2 = nodeCrypto.createDecipheriv("aes-" + key.algorithm.length + "-cbc", kb, cbcIv2);
        return guard.secret.cipherFinish(d2, buf, WebCryptoError, "webcrypto/operation", "the recovered AES-CBC plaintext");
      });
    }, "decrypt"));
  }
  if (name === "AES-CTR") {
    _requireCtrLength128(alg);
    var ctrCounter2 = _toBuf(alg.counter, "AES-CTR counter");
    return _toArrayBuffer(_runCipher(function () {
      return _withSecretBytes(key, function (kb) {
        var d3 = nodeCrypto.createDecipheriv("aes-" + key.algorithm.length + "-ctr", kb, ctrCounter2);
        return guard.secret.cipherFinish(d3, buf, WebCryptoError, "webcrypto/operation", "the recovered AES-CTR plaintext");
      });
    }, "decrypt"));
  }
  throw new WebCryptoError("webcrypto/not-supported", "decrypt: unsupported algorithm " + _stringify(name));
};

// _withSecretBytes(key, fn) -- export a secret key's raw material, hand it to fn, and wipe
// the export the moment fn is done with it (NIST SP 800-227 RS5 / sec. 4.2, RFC 9629 sec. 7).
//
// export() allocates a FRESH Buffer this module owns; the CryptoKey keeps its own copy inside
// the node KeyObject, so wiping the export never destroys the caller's key or the key itself.
// Node's cipher and KDF constructors copy the key into their own context, so the export's
// useful life ends when the operation returns.
//
// This is the ONLY way to reach raw secret key material: there is deliberately no unwiped
// `_secretBytes(key)` primitive to call, because a new consumer that forgot the wipe was the
// live defect this replaced -- the AES content-encryption paths and two of the three KDF arms
// each exported the key and left it readable while their sibling arms did not.
//
// When fn returns a PROMISE the wipe rides the settlement rather than the callback's return.
// Node's async primitives copy their inputs when the job is queued, so an eager wipe would not
// corrupt today's derivations -- but that is an implementation detail of the provider, not a
// documented guarantee, and the export's useful life is the operation's, not the callback's.
// Deferring costs nothing and keeps the rule true for any future asynchronous consumer.
function _withSecretBytes(key, fn) {
  var kb = key._handle.export();
  // Set once the export's lifetime has been handed to the promise handlers below, so the
  // `finally` does not clear a buffer the pending operation is still entitled to.
  var deferred = false;
  try {
    var out = fn(kb);
    if (out && typeof out.then === "function") {
      deferred = true;
      return out.then(function (v) { _wipeExport(kb); return v; }, function (e) { _wipeExport(kb); throw e; });
    }
    return out;
  } finally {
    if (!deferred) guard.secret.zeroize(kb, WebCryptoError, "webcrypto/operation", "the exported key material");
  }
}
function _wipeExport(kb) { guard.secret.zeroize(kb, WebCryptoError, "webcrypto/operation", "the exported key material"); }

// AES-CTR: node always treats the full 128-bit block as the counter and
// never reads the spec's `length` (counter-width) parameter. A length < 128
// would silently diverge from the W3C definition, so fail closed -- accept
// only the one value node can honor.
function _requireCtrLength128(alg) {
  if (alg.length !== 128) {
    throw new WebCryptoError("webcrypto/not-supported", "AES-CTR length must be 128");
  }
}

// W3C deriveBits: the requested length must be a positive multiple of 8 --
// the `length / 8` narrowing in the per-algorithm branches below would
// otherwise silently truncate a fractional byte count.
function _requireDeriveLength(length, who) {
  if (typeof length !== "number" || !_isFinite(length) || length <= 0 || length % 8 !== 0) {
    throw new WebCryptoError("webcrypto/operation", who + ": length must be a positive multiple of 8 bits");
  }
}

// Raw key-agreement / KDF derivation with NO usage check -- the usage a
// caller must hold differs by entry point (deriveBits requires "deriveBits",
// deriveKey requires "deriveKey"), so each public method checks its own
// usage and then routes the actual derivation through here.
// PBKDF2 on the libuv threadpool (crypto.pbkdf2, NOT pbkdf2Sync): an attacker-controlled iteration count must
// never block the Node event loop (CWE-400 DoS) -- a network peer can request the maximum iterations without
// knowing the secret (e.g. an unauthenticated PBMAC1 message), so the derivation runs off the main thread.
// Concurrency is CAPPED so many high-iteration jobs cannot monopolize the whole worker pool and starve
// unrelated DNS / filesystem / crypto work: at least two pool threads are left free (default pool is four),
// and derivations beyond the cap queue and run as slots free. The cap tracks UV_THREADPOOL_SIZE when raised.
var _PBKDF2_MAX_CONCURRENT = _max(1, (_parseInt(process.env.UV_THREADPOOL_SIZE, 10) || 4) - 2);
var _pbkdf2InFlight = 0;
var _pbkdf2Waiters = [];
function _pbkdf2Async(pw, salt, iterations, keylen, digest) {
  return new Promise(function (resolve, reject) {
    function start() {
      _pbkdf2InFlight++;
      function done(err, derived) {   // release the slot + admit the next waiter, THEN settle
        _pbkdf2InFlight--;
        var next = _pbkdf2Waiters.shift();
        if (next) next();
        if (err) reject(err); else resolve(derived);
      }
      // A SYNCHRONOUS argument fault (e.g. iterations 0) never reaches the async callback, so release the slot
      // in the catch too -- otherwise a leaked slot would permanently shrink the pool and queue every later job.
      try { nodeCrypto.pbkdf2(pw, salt, iterations, keylen, digest, done); }
      catch (e) { done(e); }
    }
    if (_pbkdf2InFlight < _PBKDF2_MAX_CONCURRENT) start(); else _pbkdf2Waiters.push(start);
  });
}

async function _deriveBitsRaw(alg, key, length) {
  var name = alg.name;
  if (name === "ECDH" || name === "X25519" || name === "X448") {
    _requireAlgMatch(alg, alg.public, name + " public key");
    _requireOwnKey(alg.public, "deriveBits public key");
    // The provider hands back z (ECDH) / mz (X25519, X448) in a Buffer this module owns. It is
    // the raw key-agreement shared secret -- the same class of material as a KEM shared secret --
    // so it is wiped once the caller's copy exists, on EVERY exit including the over-request
    // throw. _toArrayBuffer copies via ArrayBuffer.slice, so the returned bits are unaffected.
    var secret = nodeCrypto.diffieHellman({ privateKey: key._handle, publicKey: alg.public._handle });
    try {
      if (length == null) return _toArrayBuffer(secret);
      _requireDeriveLength(length, name);
      // subarray clamps at the end of the secret, so an unchecked over-request
      // would silently return fewer bytes than asked. W3C deriveBits: throw an
      // OperationError when the requested length cannot be satisfied.
      if (length / 8 > secret.length) {
        throw new WebCryptoError("webcrypto/operation", name + ": requested " + length + " bits but the shared secret has " + (secret.length * 8));
      }
      return _toArrayBuffer(_subarray(secret, 0, length / 8));
    } finally {
      guard.secret.zeroize(secret, WebCryptoError, "webcrypto/operation", "the raw key-agreement shared secret");
    }
  }
  if (name === "HKDF") {
    _requireDeriveLength(length, "HKDF");
    // The export is a fresh Buffer this module owns -- for a KEM flow it is the shared secret
    // itself. A controllable allocation, not one of the runtime-internal copies the best-effort
    // caveat covers, so it is wiped once the derivation has consumed it.
    return _withSecretBytes(key, function (ikm) {
      var derived = nodeCrypto.hkdfSync(_hashNode(alg.hash, "HKDF"), ikm, _toBuf(alg.salt, "HKDF salt"), _toBuf(alg.info || _bufferAlloc(0), "HKDF info"), length / 8);
      return _types.isArrayBuffer(derived) ? derived : _toArrayBuffer(_bufferFrom(derived));
    });
  }
  if (name === "PBKDF2") {
    _requireDeriveLength(length, "PBKDF2");
    // The derivation is asynchronous; _withSecretBytes defers the wipe to the promise's
    // settlement so the export outlives the operation rather than the callback.
    return _withSecretBytes(key, function (pw) {
      return _pbkdf2Async(pw, _toBuf(alg.salt, "PBKDF2 salt"), alg.iterations, length / 8, _hashNode(alg.hash, "PBKDF2"))
        .then(function (out) {
          // _toArrayBuffer COPIES, so the node-allocated derivation buffer is finished with the
          // moment the copy exists -- and nothing else can reach it to clear it.
          try { return _toArrayBuffer(out); }
          finally { guard.secret.zeroize(out, WebCryptoError, "webcrypto/operation", "the PBKDF2 output"); }
        });
    });
  }
  if (name === "X963KDF") {
    // ANSI-X9.63 / SEC1 sec. 3.6.1 single-step KDF: K = H(Z || INT32(counter) || SharedInfo)
    // concatenated over counter = 1, 2, ... The RFC 5753 kari KEK derivation; the base key holds
    // the ECDH shared secret Z, alg.info holds the DER ECC-CMS-SharedInfo.
    _requireDeriveLength(length, "X963KDF");
    // The base key here HOLDS the ECDH shared secret Z of an RFC 5753 kari, so this export is
    // exactly as sensitive as the raw agreement secret wiped above.
    return _withSecretBytes(key, function (z) {
      var derived = _x963Kdf(_hashNode(alg.hash, "X963KDF"), z, _toBuf(alg.info || _bufferAlloc(0), "X963KDF SharedInfo"), length / 8);
      // Same as PBKDF2 above: the copy is what the caller receives, so the derived buffer is cleared.
      try { return _toArrayBuffer(derived); }
      finally { guard.secret.zeroize(derived, WebCryptoError, "webcrypto/operation", "the X9.63 KDF output"); }
    });
  }
  throw new WebCryptoError("webcrypto/not-supported", "deriveBits: unsupported algorithm " + _stringify(name));
}

// The X9.63 single-step KDF counter loop. Bounded by the 2^32 counter range; every input is a
// public/agreed value, so a plain (non-constant-time) hash concat is correct.
function _x963Kdf(hashNode, z, sharedInfo, lenBytes) {
  var blocks = [], counter = 1, got = 0;
  while (got < lenBytes) {
    if (counter > 0xffffffff) throw new WebCryptoError("webcrypto/operation", "X963KDF: requested output exceeds the counter range");
    var ctr = _bufferAlloc(4); ctr.writeUInt32BE(counter, 0);
    var h = nodeCrypto.createHash(hashNode).update(z).update(ctr).update(sharedInfo).digest();
    _push(blocks, h); got += h.length; counter += 1;
  }
  // Return an exact-sized buffer the caller wholly owns, not a VIEW over the joined blocks: a
  // caller clearing what it received would otherwise leave the unused tail of the final digest
  // block -- derived from the shared secret -- readable behind it. The accumulator and the
  // per-block digests are cleared here, where they were allocated.
  var joined = _bufferConcat(blocks);
  var exact = _bufferAlloc(lenBytes);
  joined.copy(exact, 0, 0, lenBytes);
  guard.secret.zeroize(joined, WebCryptoError, "webcrypto/operation", "the KDF accumulator");
  for (var bi = 0; bi < blocks.length; bi++) guard.secret.zeroize(blocks[bi], WebCryptoError, "webcrypto/operation", "a KDF block");
  return exact;
}

SubtleCrypto.prototype.deriveBits = async function deriveBits(algorithm, key, length) {
  var alg = _normalizeAlg(algorithm, "deriveBits");
  _requireUsage(key, "deriveBits");
  if (!DERIVE_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "deriveBits: unsupported algorithm " + _stringify(alg.name));
  _requireAlgMatch(alg, key, "deriveBits");
  return _deriveBitsRaw(alg, key, length);
};

SubtleCrypto.prototype.deriveKey = async function deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
  // deriveKey requires the "deriveKey" usage -- NOT "deriveBits". Delegating
  // to this.deriveBits would false-reject a key created with ["deriveKey"]
  // and fail-open on a ["deriveBits"]-only key, so check the correct usage
  // here and route the raw derivation past deriveBits' own usage gate.
  _requireUsage(baseKey, "deriveKey");
  var alg = _normalizeAlg(algorithm, "deriveKey");
  if (!DERIVE_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "deriveKey: unsupported algorithm " + _stringify(alg.name));
  _requireAlgMatch(alg, baseKey, "deriveKey");
  var dk = _normalizeAlg(derivedKeyType, "deriveKey");
  var bits;
  if (_stringIndexOf(dk.name, "AES") === 0) {
    // W3C get-key-length for AES: the derivedKeyType MUST carry a length of
    // 128/192/256. Without this check the derived key would silently take
    // the size of the raw agreement/KDF output (e.g. a 384-bit "AES" key
    // from a P-384 secret) instead of a usable AES size.
    if (dk.length !== 128 && dk.length !== 192 && dk.length !== 256) {
      throw new WebCryptoError("webcrypto/syntax", "deriveKey: " + dk.name + " length must be 128/192/256");
    }
    bits = dk.length;
  } else if (dk.name === "HMAC") {
    // The same W3C HMAC get-key-length rule as generateKey: an omitted
    // length is the hash's BLOCK size, never a fixed 256.
    bits = _hmacLengthBits(dk, "deriveKey");
  } else {
    // HKDF / PBKDF2 derived-key types carry no intrinsic size (W3C
    // get-key-length is null): the base derivation decides -- a key
    // agreement yields its full shared secret as the input keying
    // material; a KDF base has no implicit output size and fails closed.
    bits = dk.length != null ? dk.length : null;
  }
  // The derived bits are the KEY -- importKey copies them into a KeyObject, so this buffer is a
  // transient copy nothing else can reach once the CryptoKey exists, and it is cleared on the
  // failing import too (a bad derivedKeyType is caller-controlled).
  var raw = await _deriveBitsRaw(alg, baseKey, bits);
  try { return await this.importKey("raw", raw, dk, extractable, keyUsages); }
  finally { guard.secret.zeroize(new _Uint8Array(raw), WebCryptoError, "webcrypto/operation", "the derived key material"); }
};

// ML-KEM (FIPS 203) key encapsulation over Node's crypto.encapsulate/decapsulate.
// encapsulateBits takes the recipient's PUBLIC (encapsulation) key and returns a fresh
// { sharedKey, ciphertext }; decapsulateBits takes the PRIVATE (decapsulation) key + a
// ciphertext and recovers the shared key. ML-KEM's Fujisaki-Okamoto transform gives IMPLICIT
// rejection: a tampered but correctly-sized ciphertext decapsulates to a pseudo-random shared
// key rather than failing, so decapsulateBits only throws (typed) on a malformed / wrong-length
// ciphertext -- the "wrong key" case is indistinguishable by design, which the CMS uniform
// decrypt-failure verdict relies on. The usage split (encapsulateBits -> public, decapsulateBits
// -> private) already lives in the generateKey usage filters; the explicit type check hardens a
// key imported with custom usages.
SubtleCrypto.prototype.encapsulateBits = async function encapsulateBits(algorithm, encapsulationKey) {
  var alg = _normalizeAlg(algorithm, "encapsulateBits");
  _requireUsage(encapsulationKey, "encapsulateBits");
  if (!ML_KEM_NODE[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "encapsulateBits: unsupported algorithm " + _stringify(alg.name));
  _requireAlgMatch(alg, encapsulationKey, "encapsulateBits");
  if (encapsulationKey.type !== "public") throw new WebCryptoError("webcrypto/invalid-access", "encapsulateBits requires a public (encapsulation) key, got " + _stringify(encapsulationKey.type));
  var r;
  try { r = nodeCrypto.encapsulate(encapsulationKey._handle); }
  catch (e) { throw new WebCryptoError("webcrypto/operation", "encapsulateBits: ML-KEM encapsulation failed", e); }
  try {
    // _toArrayBuffer copies via ArrayBuffer.slice, so the shared key is passed straight through --
    // an intermediate Buffer.from would be another copy of the secret that nothing wipes. The
    // ciphertext is public and needs no such care, but it is copied the same way for symmetry.
    return { sharedKey: _toArrayBuffer(r.sharedKey), ciphertext: _toArrayBuffer(r.ciphertext) };
  } finally {
    // Encapsulation produces a shared secret exactly as decapsulation does, so it owes the same
    // duty: the provider's buffer is wiped once the caller's copy exists (NIST SP 800-227 RS5 /
    // sec. 4.2, RFC 9629 sec. 7). Wiping only the decapsulation side would make the guarantee a
    // half-truth -- the sender holds the same secret the recipient does.
    guard.secret.zeroize(r.sharedKey, WebCryptoError, "webcrypto/operation", "the KEM shared secret");
  }
};

SubtleCrypto.prototype.decapsulateBits = async function decapsulateBits(algorithm, decapsulationKey, ciphertext) {
  var alg = _normalizeAlg(algorithm, "decapsulateBits");
  _requireUsage(decapsulationKey, "decapsulateBits");
  if (!ML_KEM_NODE[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "decapsulateBits: unsupported algorithm " + _stringify(alg.name));
  _requireAlgMatch(alg, decapsulationKey, "decapsulateBits");
  if (decapsulationKey.type !== "private") throw new WebCryptoError("webcrypto/invalid-access", "decapsulateBits requires a private (decapsulation) key, got " + _stringify(decapsulationKey.type));
  var ct = _toBuf(ciphertext, "decapsulateBits ciphertext");
  // FIPS 203 sec. 7.3 makes the ciphertext-length check the ONE per-execution input check a
  // decapsulating party owes, so it belongs here, at the engine boundary, rather than only in the
  // format module that happens to call this today: a direct caller -- or a future composite-KEM or
  // HPKE consumer -- inherits nothing from a check that lives in cms-decrypt. A distinct code names
  // the real reason, which "the operation failed" cannot.
  //
  // Length ONLY. A correct-length ciphertext that has been tampered with must still resolve to a
  // pseudo-random shared secret (the Fujisaki-Okamoto implicit rejection of FIPS 203 sec. 6.3);
  // turning that into a throw would hand an attacker a decryption oracle, and it is the property
  // the CMS uniform verdict is built on.
  // The registry is keyed by the registered OID name ("id-ml-kem-768"), which is the node
  // algorithm name this module already maps ("ml-kem-768") under its id- prefix.
  var kemRow = oid.kemParams("id-" + ML_KEM_NODE[alg.name]);
  if (kemRow && ct.length !== kemRow.ct) {
    throw new WebCryptoError("webcrypto/bad-kem-ciphertext",
      "decapsulateBits: " + alg.name + " expects a " + kemRow.ct + "-octet ciphertext, got " + ct.length + " (FIPS 203 sec. 7.3)");
  }
  var ss;
  try { ss = nodeCrypto.decapsulate(decapsulationKey._handle, ct); }
  catch (e) { throw new WebCryptoError("webcrypto/operation", "decapsulateBits: ML-KEM decapsulation failed (malformed or wrong-length ciphertext)", e); }
  try {
    // ss is already a Buffer, and _toArrayBuffer copies via ArrayBuffer.slice -- so it is passed
    // straight through. An intermediate Buffer.from(ss) would be a THIRD copy of the secret that
    // nothing wipes, which would give back most of what the wipe below is for.
    return _toArrayBuffer(ss);
  } finally {
    // The shared secret is returned as a COPY, so the buffer the provider handed back would stay
    // readable until collection -- and a caller wiping only what it receives would leave the
    // original behind, which is the whole secret. Wiping here means the engine owns the lifetime of
    // the buffer it allocated, and every caller (CMS today, a composite KEM or HPKE later) inherits
    // it rather than each having to remember (NIST SP 800-227 RS5 / sec. 4.2).
    guard.secret.zeroize(ss, WebCryptoError, "webcrypto/operation", "the KEM shared secret");
  }
};

SubtleCrypto.prototype.wrapKey = async function wrapKey(format, key, wrappingKey, wrapAlgorithm) {
  //  is the PLAINTEXT serialization of the key being wrapped -- the very material the wrap
  // exists to protect. It is this function's allocation and is cleared once the wrap has consumed
  // it, on the delegated branch as well as the AES-KW one.
  var exported = await this.exportKey(format, key);
  var bytes = (format === "jwk") ? _bufferFrom(_stringify(exported)) : _bufferFrom(exported);
  try {
  var alg = _normalizeAlg(wrapAlgorithm, "wrapKey");
  _requireUsage(wrappingKey, "wrapKey");
  if (alg.name !== "AES-KW" && !ENCRYPT_DECRYPT_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "wrapKey: unsupported algorithm " + _stringify(alg.name));
  _requireAlgMatch(alg, wrappingKey, "wrapKey");
  if (alg.name === "AES-KW") {
    // AES-KW wraps 64-bit blocks (RFC 3394): the serialized key MUST be a multiple of 8
    // bytes and at least 16. A "jwk" serialization (arbitrary-length JSON) or any other
    // non-conforming length is an OperationError -- a typed verdict, never a raw node fault.
    if (bytes.length < 16 || bytes.length % 8 !== 0) {
      throw new WebCryptoError("webcrypto/operation", "wrapKey: AES-KW requires the serialized key be a multiple of 8 bytes (>= 16); got " + bytes.length + " -- format " + _stringify(format) + " is not AES-KW-wrappable");
    }
    // The mirror of unwrapKey below: in a KEM flow this export is the SENDER's copy of the same
    // key-encryption key, so leaving it unwiped would keep a full copy of the KEK alive for the
    // process lifetime and make the wipes the CMS layer performs pointless in the encrypt direction.
    try {
      return _withSecretBytes(wrappingKey, function (wkBytes) {
        var c = nodeCrypto.createCipheriv("aes" + wrappingKey.algorithm.length + "-wrap", wkBytes, _bufferFrom("A6A6A6A6A6A6A6A6", "hex"));
        return _toArrayBuffer(guard.secret.cipherFinish(c, bytes, WebCryptoError, "webcrypto/operation", "an AES-KW wrap intermediate"));
      });
    } catch (e) { throw new WebCryptoError("webcrypto/operation", "wrapKey: AES-KW key wrap failed", e); }
  }
  // Delegate to a content-encryption algorithm (RSA-OAEP / AES-GCM).
  var wrapKeyClone = _cloneWithUsage(wrappingKey, "encrypt");
  return await this.encrypt(wrapAlgorithm, wrapKeyClone, bytes);
  } finally {
    // Clearing  also clears the export it came from: for every non-jwk format
    // Buffer.from(<ArrayBuffer>) is a VIEW over that buffer, not a copy, so one wipe covers both.
    // A "jwk" export is the residual -- its key material lives in immutable JavaScript strings that
    // no code can overwrite -- so wrapping a jwk serialization cannot offer this guarantee, and the
    // documentation does not claim it does.
    guard.secret.zeroize(bytes, WebCryptoError, "webcrypto/operation", "the exported key being wrapped");
  }
};

SubtleCrypto.prototype.unwrapKey = async function unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
  var alg = _normalizeAlg(unwrapAlgorithm, "unwrapKey");
  // Enforce the "unwrapKey" usage before EITHER path. The delegated
  // (RSA-OAEP / AES-GCM) branch clones the key with "decrypt" and hands off
  // to this.decrypt, so without this top-level check the else branch would
  // never verify the caller was actually permitted to unwrap (mirrors
  // wrapKey, which checks before both of its paths).
  _requireUsage(unwrappingKey, "unwrapKey");
  if (alg.name !== "AES-KW" && !ENCRYPT_DECRYPT_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "unwrapKey: unsupported algorithm " + _stringify(alg.name));
  _requireAlgMatch(alg, unwrappingKey, "unwrapKey");
  var bytes;
  if (alg.name === "AES-KW") {
    var wrapped = _toBuf(wrappedKey, "unwrapKey");
    // The wrapped input is the plaintext plus one 64-bit integrity block: a multiple of 8,
    // at least 24. A wrong length, or a failed integrity check inside final(), is an
    // OperationError -- a typed verdict, never a raw node cipher fault.
    if (wrapped.length < 24 || wrapped.length % 8 !== 0) {
      throw new WebCryptoError("webcrypto/operation", "unwrapKey: AES-KW wrapped key must be a multiple of 8 bytes (>= 24); got " + wrapped.length);
    }
    // The exported wrapping key is a Buffer this module owns; in a KEM flow it is the KEK derived
    // from the shared secret, so it is wiped once the unwrap has consumed it -- on the failing path
    // too, which is the one an attacker induces by tampering with the wrapped key.
    // The export happens INSIDE the try: a key whose handle cannot be exported must still surface
    // the typed verdict this branch promises, not a raw node TypeError -- and a non-PkiError throw
    // would also break the fuzz-harness contract.
    try {
      bytes = _withSecretBytes(unwrappingKey, function (kwBytes) {
        var d = nodeCrypto.createDecipheriv("aes" + unwrappingKey.algorithm.length + "-wrap", kwBytes, _bufferFrom("A6A6A6A6A6A6A6A6", "hex"));
        return guard.secret.cipherFinish(d, wrapped, WebCryptoError, "webcrypto/operation", "the unwrapped key material");
      });
    } catch (e) { throw new WebCryptoError("webcrypto/operation", "unwrapKey: AES-KW key unwrap failed (integrity or length)", e); }
  } else {
    var unwrapKeyClone = _cloneWithUsage(unwrappingKey, "decrypt");
    bytes = _bufferFrom(await this.decrypt(unwrapAlgorithm, unwrapKeyClone, wrappedKey));
  }
  var keyData;
  if (format === "jwk") {
    // A NON-authenticating unwrap algorithm (AES-CBC / AES-CTR) decrypts
    // tampered bytes "successfully", so this parse is the first point that can
    // notice. The shared JSON guard parses strictly (bounded, fatal UTF-8, and a
    // smuggled duplicate member rejected rather than resolved last-wins), and its
    // failure surfaces as the module's typed webcrypto/data (W3C: DataError).
    keyData = guard.json.parse(bytes, _wcErr, {
      maxBytes: constants.LIMITS.JSON_MAX_BYTES, maxDepth: constants.LIMITS.JSON_MAX_DEPTH,
      badJson: "webcrypto/data", tooDeep: "webcrypto/data", duplicateMember: "webcrypto/data",
      tooLarge: "webcrypto/data", badInput: "webcrypto/data", label: "the unwrapped JWK",
    });
  } else {
    keyData = bytes;
  }
  try {
    return await this.importKey(format, keyData, unwrappedKeyAlgorithm, extractable, keyUsages);
  } finally {
    // `bytes` is the UNWRAPPED key in plaintext -- a module-owned buffer, and the last plaintext
    // copy this layer controls once importKey has taken its own. Clearing the caller-visible copy
    // downstream while leaving this one live would make that wipe ceremonial.
    guard.secret.zeroize(bytes, WebCryptoError, "webcrypto/operation", "the unwrapped key material");
  }
};

function _cloneWithUsage(key, usage) {
  var k = new CryptoKey(key.type, key.extractable, key.algorithm, _concat(key.usages, [usage]), key._handle);
  return k;
}

// A raw or JWK-oct AES key MUST be 128/192/256 bits: W3C WebCrypto importKey rejects a
// non-conforming length as a DataError AT IMPORT, never a CryptoKey that only faults at
// first use (where node would build an "aes-160-gcm" cipher that fails only then). HMAC /
// HKDF / PBKDF2 keys carry no length restriction, so the check is scoped to the AES names.
function _assertAesImportLen(name, byteLen) {
  if ((name === "AES-GCM" || name === "AES-CBC" || name === "AES-CTR" || name === "AES-KW") &&
      byteLen !== 16 && byteLen !== 24 && byteLen !== 32) {
    throw new WebCryptoError("webcrypto/data", name + ": an imported AES key must be 128, 192, or 256 bits");
  }
}

// Run a node:crypto key-import call, mapping a raw engine error (a malformed DER, an
// inconsistent key) to a typed webcrypto/data DataError -- importKey over hostile bytes
// must never leak a bare OpenSSL/Node exception through the public API.
function _nodeKey(fn, who) {
  try { return fn(); }
  catch (e) {
    // Coverage residual -- every current thunk calls node:crypto (which throws a node error),
    // never a WebCryptoError, so this already-typed passthrough is defensive depth for a future
    // thunk that pre-validates and throws typed; it prevents double-wrapping a typed error.
    if (e instanceof WebCryptoError) throw e;
    throw new WebCryptoError("webcrypto/data", who + ": the key material is malformed or internally inconsistent", e);
  }
}

// RFC 9935 sec. 6 ML-KEM-*-PrivateKey CHOICE: the inner sizes, keyed by the OID -- the OID is
// the SOLE authority for the parameter set (never a length heuristic). ek = 384k+32, dk = the
// FIPS 203 decapsulation key length.
// {ek, dk} come from the shared ML-KEM parameter registry (FIPS 203 Table 3) -- the same rows the
// CMS codec and the linter read, so a parameter set cannot mean one size here and another there.
var ML_KEM_INNER = {};
["id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024"].forEach(function (n) {
  var row = oid.kemParams(n);
  ML_KEM_INNER[oid.byName(n)] = { ek: row.ek, dk: row.dk };
});

function _isOctet(node, size) {
  return node && node.tagClass === "universal" && node.tagNumber === asn1.TAGS.OCTET_STRING &&
    !node.constructed && node.content && node.content.length === size;
}
// Validate the RFC 9935 sec. 6 inner CHOICE structurally, dispatching on the DER tag (0x80 seed
// [0] / 0x04 expandedKey / 0x30 both) -- NEVER on the length of the enclosing OCTET STRING. A
// bare seed, a bare dk, an oqskeypair dk||ek, a constructed [0], or a wrong-size arm is rejected
// fail-closed (guards never guess a plausible layout). The seed/expandedKey CRYPTOGRAPHIC
// consistency (sec. 8 / FIPS 203 sec. 7.3) is enforced by the engine on import (a mismatch is a
// raw node error _nodeKey maps to webcrypto/data).
function _validateMlKemInner(innerBytes, sizes) {
  var node;
  try { node = asn1.decode(innerBytes); }
  catch (e) { throw new WebCryptoError("webcrypto/data", "an ML-KEM private key must be the RFC 9935 sec. 6 seed/expandedKey/both CHOICE, not a bare key", e); }
  if (node.tagClass === "context" && node.tagNumber === 0 && !node.constructed) {
    if (!node.content || node.content.length !== 64) throw new WebCryptoError("webcrypto/data", "an ML-KEM seed must be exactly 64 octets (RFC 9935 sec. 6)");
    return;
  }
  if (_isOctet(node, sizes.dk)) return;
  if (node.tagClass === "universal" && node.tagNumber === asn1.TAGS.OCTET_STRING && !node.constructed) {
    throw new WebCryptoError("webcrypto/data", "an ML-KEM expandedKey must be exactly " + sizes.dk + " octets for this parameter set (RFC 9935 sec. 6)");
  }
  if (node.tagClass === "universal" && node.tagNumber === asn1.TAGS.SEQUENCE) {
    // Coverage residual -- a decoded universal SEQUENCE always carries a children array, so the
    // `|| []` fallback is defensive (asn1.decode never yields a childless constructed node).
    var kids = node.children || [];
    if (kids.length !== 2 || !_isOctet(kids[0], 64) || !_isOctet(kids[1], sizes.dk)) {
      throw new WebCryptoError("webcrypto/data", "an ML-KEM both-arm must be SEQUENCE { seed OCTET STRING(64), expandedKey OCTET STRING(" + sizes.dk + ") } (RFC 9935 sec. 6)");
    }
    return;
  }
  throw new WebCryptoError("webcrypto/data", "an ML-KEM private key must be the seed, expandedKey, or both CHOICE (RFC 9935 sec. 6)");
}

// PKCS#8 inner-key pre-validation, keyed by the privateKeyAlgorithm OID (a registry row, not a
// switch). The parse surfaces the inner key as opaque octets by design; the fail-closed
// per-algorithm structural check lives here, at the one import boundary. Only ML-KEM needs it
// today: the engine ACCEPTS the OpenSSL-legacy bare-seed layout RFC 9935 sec. 6 forbids.
var PKCS8_INNER_VALIDATORS = {};
_forEach(_keys(ML_KEM_INNER), function (o) { PKCS8_INNER_VALIDATORS[o] = function (inner) { _validateMlKemInner(inner, ML_KEM_INNER[o]); }; });

function _preValidatePkcs8(p8, name) {
  if (!ML_KEM_NODE[name]) return;   // only the ML-KEM CHOICE carries the bare-seed hazard
  var algOid, innerBytes;
  try {
    var root = asn1.decode(p8);
    algOid = asn1.read.oid(root.children[1].children[0]);
    innerBytes = asn1.read.octetString(root.children[2]);
  } catch (e) { throw new WebCryptoError("webcrypto/data", "importKey pkcs8: the ML-KEM PKCS#8 envelope is not well-formed", e); }
  var validate = PKCS8_INNER_VALIDATORS[algOid];
  if (!validate) throw new WebCryptoError("webcrypto/data", "importKey pkcs8: " + name + " does not match the key's algorithm OID");
  validate(innerBytes);
}

SubtleCrypto.prototype.importKey = async function importKey(format, keyData, algorithm, extractable, keyUsages) {
  var alg = _normalizeAlg(algorithm, "importKey");
  var usages = keyUsages || [];
  var name = alg.name;

  // spki / pkcs8 carry an asymmetric key; a secret-key / KDF name has no such structure. Reject
  // it up front (W3C NotSupportedError) so it can neither mint a mislabeled key nor bypass the
  // per-algorithm pkcs8 pre-validation below.
  if ((format === "spki" || format === "pkcs8") && SECRET_KEY_NAMES[name]) {
    throw new WebCryptoError("webcrypto/not-supported", "importKey: " + name + " does not support the " + format + " key format");
  }

  if (format === "raw") {
    // Symmetric raw material, or a raw public key for EC/OKP.
    if (SECRET_KEY_NAMES[name]) {
      var raw = _toBuf(keyData, "importKey raw");
      _assertAesImportLen(name, raw.length);
      var secret = nodeCrypto.createSecretKey(raw);
      var symAlg = (name === "HMAC") ? { name: name, hash: _hashObj(alg.hash, "importKey raw HMAC"), length: raw.length * 8 } : { name: name, length: raw.length * 8 };
      return new CryptoKey("secret", extractable, symAlg, usages, secret);
    }
    // Raw public keys are imported via JWK reconstruction below.
    return _importRawPublic(name, alg, _toBuf(keyData, "importKey raw"), extractable, usages);
  }

  if (format === "spki") {
    var spkiBuf = _toBuf(keyData, "importKey spki");
    var pub = _nodeKey(function () { return nodeCrypto.createPublicKey({ key: spkiBuf, format: "der", type: "spki" }); }, "importKey spki");
    return new CryptoKey("public", true, _algFromImport(name, alg, pub), usages, pub);
  }
  if (format === "pkcs8") {
    var p8Buf = _toBuf(keyData, "importKey pkcs8");
    _preValidatePkcs8(p8Buf, name);
    var priv = _nodeKey(function () { return nodeCrypto.createPrivateKey({ key: p8Buf, format: "der", type: "pkcs8" }); }, "importKey pkcs8");
    return new CryptoKey("private", extractable, _algFromImport(name, alg, priv), usages, priv);
  }
  if (format === "jwk") {
    var jwk = keyData;
    // A JWK is a JSON object; null / undefined / an array / a primitive (incl. the JSON token
    // `null` from an unwrapKey over non-authenticating ciphertext) fails closed as a typed
    // DataError, never a raw property-access TypeError.
    if (jwk === null || typeof jwk !== "object" || _isArray(jwk)) {
      throw new WebCryptoError("webcrypto/data", "importKey jwk: keyData must be a JsonWebKey object");
    }
    if (jwk.kty === "oct") {
      var kbuf = _b64urlToBuf(jwk.k, "JWK oct key material");
      _assertAesImportLen(name, kbuf.length);
      var s2 = nodeCrypto.createSecretKey(kbuf);
      var a2 = (name === "HMAC") ? { name: name, hash: _hashObj(alg.hash, "importKey jwk HMAC"), length: kbuf.length * 8 } : { name: name, length: kbuf.length * 8 };
      return new CryptoKey("secret", extractable, a2, usages, s2);
    }
    // The private half is named by the KEY TYPE, not by one spelling. EC and OKP carry it in `d`;
    // an AKP JWK -- how ML-DSA, ML-KEM and SLH-DSA are represented -- carries it in `priv`.
    // Testing `d` alone reads every PQC private JWK as public, so a re-import yields a public key
    // that still announces `usages: ["sign"]` and forces `extractable` true whatever the caller
    // asked, silently dropping the half that signs.
    // `priv` is read ONLY for an AKP key, the type that defines it. RFC 7517 sec. 4 requires an
    // unrecognized member to be ignored, so a member of that name on an EC or OKP JWK is an
    // extension this implementation has no meaning for -- reading it as private material there
    // would turn a valid public-key import into a failure.
    var isPrivate = _hasOwn(jwk, "d") ||
      (jwk.kty === "AKP" && _hasOwn(jwk, "priv"));
    var ko = _nodeKey(function () { return isPrivate ? nodeCrypto.createPrivateKey({ key: jwk, format: "jwk" }) : nodeCrypto.createPublicKey({ key: jwk, format: "jwk" }); }, "importKey jwk");
    return new CryptoKey(isPrivate ? "private" : "public", isPrivate ? extractable : true, _algFromImport(name, alg, ko), usages, ko);
  }
  throw new WebCryptoError("webcrypto/not-supported", "importKey: unsupported format " + _stringify(format));
};

function _importRawPublic(name, alg, raw, extractable, usages) {
  if (name === "ED25519" || name === "ED448" || name === "X25519" || name === "X448") {
    var jwk = { kty: "OKP", crv: (name === "ED25519" ? "Ed25519" : name === "ED448" ? "Ed448" : name === "X25519" ? "X25519" : "X448"), x: _bufToB64url(raw) };
    var ko = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    // The canonical mixed-case EdDSA labels, matching _algFromImport -- a raw
    // import must not label the same key differently than an spki/jwk one.
    return new CryptoKey("public", true, { name: _stdName(name) }, usages, ko);
  }
  if (name === "ECDSA" || name === "ECDH") {
    var fb = CURVE_FIELD_BYTES[alg.namedCurve];
    if (!fb || raw[0] !== 0x04 || raw.length !== 1 + 2 * fb) throw new WebCryptoError("webcrypto/data", "importKey raw EC: expected an uncompressed point for " + alg.namedCurve);
    var ecjwk = { kty: "EC", crv: alg.namedCurve, x: _bufToB64url(_subarray(raw, 1, 1 + fb)), y: _bufToB64url(_subarray(raw, 1 + fb)) };
    var eck = nodeCrypto.createPublicKey({ key: ecjwk, format: "jwk" });
    return new CryptoKey("public", true, { name: name, namedCurve: alg.namedCurve }, usages, eck);
  }
  throw new WebCryptoError("webcrypto/not-supported", "importKey raw: unsupported public-key algorithm " + _stringify(name));
}

// The node asymmetricKeyType(s) each imported asymmetric algorithm requires. The key TYPE
// is a property of the key material, not the caller's claim: an RSA key imported under
// {name:"Ed25519"} must be a DataError, not a CryptoKey mislabeled Ed25519 that then signs
// under the wrong scheme (algorithm confusion). EC is additionally curve-validated below.
var IMPORT_KEY_TYPE = {
  "RSASSA-PKCS1-V1_5": { rsa: 1 }, "RSA-PSS": { rsa: 1, "rsa-pss": 1 }, "RSA-OAEP": { rsa: 1 },
  "ECDSA": { ec: 1 }, "ECDH": { ec: 1 },
  "ED25519": { ed25519: 1 }, "ED448": { ed448: 1 },
  "X25519": { x25519: 1 }, "X448": { x448: 1 },
};
// The FIPS 203/204/205 PQC families import the same key-is-authority rule: each WebCrypto
// algorithm name maps to exactly its node asymmetricKeyType, so an RSA (or any) key imported
// under an ML-DSA / ML-KEM / SLH-DSA name is a DataError, not a mislabeled PQC CryptoKey.
[ML_DSA_NODE, ML_KEM_NODE, SLH_DSA_NODE].forEach(function (m) {
  _forEach(_keys(m), function (webName) { var t = {}; t[m[webName]] = 1; IMPORT_KEY_TYPE[webName] = t; });
});
function _algFromImport(name, alg, keyObject) {
  var wantType = IMPORT_KEY_TYPE[name];
  if (wantType && keyObject && keyObject.asymmetricKeyType && !wantType[keyObject.asymmetricKeyType]) {
    throw new WebCryptoError("webcrypto/data", name + ": the imported key is a " + keyObject.asymmetricKeyType +
      " key, which is not compatible with algorithm " + name);
  }
  if (name === "ECDSA" || name === "ECDH") {
    // W3C WebCrypto EC import -- the curve is a property of the KEY, not the
    // caller's claim. Derive it from the imported key material; reject an
    // unsupported curve (NotSupportedError, matching generateKey) and reject a
    // requested namedCurve that disagrees with the key (DataError). Trusting
    // alg.namedCurve would mislabel the CryptoKey (algorithm confusion) and let
    // a non-approved curve import as an approved one.
    var actualCurve = _curveFromKey(keyObject);
    if (!actualCurve) {
      throw new WebCryptoError("webcrypto/not-supported", name + ": imported key uses an unsupported EC curve");
    }
    if (alg.namedCurve && alg.namedCurve !== actualCurve) {
      throw new WebCryptoError("webcrypto/data", name + ": importKey namedCurve " + _stringify(alg.namedCurve) +
        " does not match the imported key's curve " + _stringify(actualCurve));
    }
    return { name: name, namedCurve: actualCurve };
  }
  if (name === "RSASSA-PKCS1-V1_5" || name === "RSA-PSS" || name === "RSA-OAEP") return { name: _stdName(name), hash: _hashObj(alg.hash, "importKey " + name) };
  if (name === "ED25519" || name === "ED448") return { name: _stdName(name) };
  return { name: alg.name };
}

function _curveFromKey(ko) {
  try {
    var jwk = ko.export({ format: "jwk" });
    for (var k in CURVE_NODE) { if (jwk.crv === k) return k; }
  }
  catch (_e) { /* best-effort */ }
  return undefined;
}

/**
 * @primitive  pki.webcrypto.subtle
 * @signature  await pki.webcrypto.subtle.exportKey(format, key)
 * @since      0.1.0
 * @status     stable
 * @spec       W3C WebCrypto sec. subtlecrypto, FIPS 186-5, FIPS 203, FIPS 204, FIPS 205, RFC 8017
 * @related    pki.webcrypto.CryptoKey
 *
 * Export a `CryptoKey` to `spki` (public), `pkcs8` (private), `jwk`
 * (either), or `raw` (symmetric, or an uncompressed EC / OKP public
 * point). Throws unless the key was created `extractable`.
 *
 * `raw` is defined for public and secret keys only; asking for it on a private
 * key throws `webcrypto/not-supported` instead of answering with the public half.
 * This matters through `wrapKey`, which forwards the caller's format here: wrapping
 * a private key as `raw` would otherwise escrow the public key, and unwrapping it
 * returns a handle announcing `usages: ["sign"]` that cannot sign, with the private
 * key gone. Use `pkcs8` or `jwk` to serialize a private key.
 *
 * A private `jwk` round-trips as a private key for every algorithm, ML-DSA, ML-KEM
 * and SLH-DSA included: those are `kty: "AKP"` and carry the private half in `priv`
 * in place of the `d` an EC or OKP key uses.
 *
 * @example
 *   var keyPair = await pki.webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
 *   var spki = await pki.webcrypto.subtle.exportKey("spki", keyPair.publicKey);
 */
SubtleCrypto.prototype.exportKey = async function exportKey(format, key) {
  _requireOwnKey(key, "exportKey");
  if (!key.extractable) throw new WebCryptoError("webcrypto/invalid-access", "key is not extractable");
  if (format === "jwk") return key._handle.export({ format: "jwk" });
  if (key.type === "secret") {
    // The export is a fresh Buffer holding the secret key, and _toArrayBuffer copies it via
    // ArrayBuffer.slice -- so the export is a controllable allocation nothing references once the
    // copy exists. The unsupported-format throw below clears it too.
    return _withSecretBytes(key, function (raw) {
      if (format === "raw") return _toArrayBuffer(raw);
      throw new WebCryptoError("webcrypto/not-supported", "exportKey: secret keys support 'raw' / 'jwk' only");
    });
  }
  if (format === "spki") return _toArrayBuffer(key._handle.export({ format: "der", type: "spki" }));
  if (format === "pkcs8") return _toArrayBuffer(key._handle.export({ format: "der", type: "pkcs8" }));
  if (format === "raw") {
    // "raw" is defined for PUBLIC and secret keys; there is no raw private-key serialization for
    // EC or OKP. Answering a private-key request with the public half hands back the opposite of
    // what was asked for, with nothing to notice it by -- and `wrapKey` forwards the caller's
    // format straight here, so a private key wrapped as "raw" escrows the PUBLIC key. Unwrapping
    // that yields a handle announcing it can sign, which cannot, and the private key is gone.
    if (key.type !== "public") {
      throw new WebCryptoError("webcrypto/not-supported",
        "exportKey: 'raw' is defined for public and secret keys only -- a " + key.type +
        " key has no raw serialization; use 'pkcs8' or 'jwk'");
    }
    return _toArrayBuffer(_rawPublic(key));
  }
  throw new WebCryptoError("webcrypto/not-supported", "exportKey: unsupported format " + _stringify(format));
};

function _rawPublic(key) {
  var jwk = key._handle.export({ format: "jwk" });
  if (jwk.kty === "OKP") return _b64urlToBuf(jwk.x);
  if (jwk.kty === "EC") return _bufferConcat([_bufferFrom([0x04]), _b64urlToBuf(jwk.x), _b64urlToBuf(jwk.y)]);
  throw new WebCryptoError("webcrypto/not-supported", "exportKey raw: unsupported key type " + jwk.kty);
}

// ---- Crypto ----------------------------------------------------------

/**
 * @primitive  pki.webcrypto
 * @signature  pki.webcrypto.getRandomValues(typedArray) / pki.webcrypto.subtle
 * @since      0.1.0
 * @status     stable
 * @spec       W3C WebCrypto
 * @related    pki.webcrypto.subtle
 *
 * A ready `Crypto` instance (the shape of `globalThis.crypto`) exposing
 * `getRandomValues`, `randomUUID`, and `subtle`. Construct additional
 * instances with `new pki.webcrypto.Crypto()`.
 *
 * @example
 *   var iv = pki.webcrypto.getRandomValues(new Uint8Array(12));
 */
function Crypto() {
  this.subtle = new SubtleCrypto();
}

Crypto.prototype.getRandomValues = function getRandomValues(typedArray) {
  // The kinds W3C WebCrypto refuses here are settled from the value's internal slot, not from an
  // `instanceof` against a replaceable global: replace `Float32Array` after load and the comparison
  // is against a different constructor, so a real Float32Array passes a check written to reject it.
  if (!_isView(typedArray) || _types.isFloat32Array(typedArray) || _types.isFloat64Array(typedArray) || _types.isDataView(typedArray)) {
    throw new WebCryptoError("webcrypto/data", "getRandomValues: expected an integer TypedArray");
  }
  // Re-view the (already integer-TypedArray-validated) output buffer through the OUTPUT door --
  // any TypedArray, not just Uint8Array -- so a detached backing store fails closed here; the
  // returned Buffer aliases typedArray, so randomFillSync writes through to the caller's array.
  //
  // The output door, because the input one refuses shared memory: bytes another thread can rewrite
  // after they have been checked cannot be checked. That answers a question about input. Here the
  // caller is asking for random bytes in memory they chose, and a `SharedArrayBuffer`-backed view
  // is a supported W3C argument that the platform fills; refusing it made a working call an error.
  var out = guard.bytes.outputView(typedArray, WebCryptoError, "webcrypto/data", "getRandomValues");
  // The ceiling is measured on that view, and never on `typedArray.byteLength`. `byteLength` is an
  // accessor on the shared typed-array prototype, so a caller's subclass answers it: one reporting
  // 0 passed the ceiling while the fill below wrote the array's real length, which is the bound
  // being bypassed rather than enforced. The view is built from the internal slot.
  if (out.length > MAX_RANDOM_BYTES) {
    throw new WebCryptoError("webcrypto/data", "getRandomValues: byteLength exceeds " + MAX_RANDOM_BYTES);
  }
  nodeCrypto.randomFillSync(out);
  return typedArray;
};

Crypto.prototype.randomUUID = function randomUUID() { return nodeCrypto.randomUUID(); };

// decompressEcPoint(sec1Compressed, nodeCurve) -> the uncompressed SEC1 point 0x04||X||Y for a
// compressed 0x02/0x03||X input, computing Y on-curve via node's ECDH.convertKey. The crypto-engine
// home for EC point de-compression (Hard rule #8: EC key material is webcrypto's domain). Fail-closed:
// convertKey throws on an off-curve X or an unsupported curve, surfaced as the caller's typed error.
// `nodeCurve` is the OpenSSL curve name (prime256v1 / secp384r1 / secp521r1). The C509-specific
// 0xFE/0xFD marker -> 0x02/0x03 parity translation stays in the C509 layer (this takes a real SEC1 point).
function decompressEcPoint(sec1Compressed, nodeCurve, E, code) {
  var head = sec1Compressed[0];
  if (head !== 0x02 && head !== 0x03) throw E(code, "EC point de-compression expects a compressed SEC1 point (0x02/0x03)");
  try {
    return nodeCrypto.ECDH.convertKey(sec1Compressed, nodeCurve, undefined, undefined, "uncompressed");
  } catch (e) {
    throw E(code, "EC point is not on curve " + nodeCurve + " (de-compression failed)", e);
  }
}

// A CryptoKey from a DIFFERENT WebCrypto implementation -- node:crypto's global `webcrypto`, a
// browser's, or a userland polyfill's -- is indistinguishable from one of this engine's by `type`,
// `algorithm` and `usages`, yet carries none of the key material this engine holds. Handing one to
// this engine raises a bare error from inside the crypto library, so a caller who followed the
// documented "pass a CryptoKey" contract is told the argument is the wrong type rather than which
// implementation it came from. Neither engine can export the other's keys, so a foreign key is
// exported through its OWN implementation and re-imported here. Both take the CALLER's typed error
// factory + code so every boundary keeps its own domain/reason.
var _crypto = new Crypto();
// Null-prototype:  is caller-supplied, and an inherited member ("constructor", "toString")
// would otherwise resolve to a truthy non-format and slip past the check below.
var _EXPORT_FORMAT = _assign(_create(null), { "private": "pkcs8", "public": "spki", "secret": "raw" });

// @internal
// True for any object shaped like a WebCrypto CryptoKey, whichever implementation minted it.
function isCryptoKeyLike(x) {
  return !!x && typeof x === "object" && typeof x.type === "string" &&
    typeof x.extractable === "boolean" && !!x.algorithm && typeof x.algorithm === "object" &&
    typeof x.algorithm.name === "string" && _isArray(x.usages);
}

// @internal
// Export any CryptoKey's material through whichever implementation owns it, in the format its
// `type` implies. A key this engine minted goes through this engine; a foreign one through
// node:crypto's. A foreign key that is not extractable cannot be reached at all -- that is a
// permanent verdict, and it is reported as itself rather than as an export failure.
function exportAnyKey(key, E, code) {
  var format = _EXPORT_FORMAT[key && key.type];
  if (!format) throw E(code, "a CryptoKey with a private, public, or secret type is required");
  if (key instanceof CryptoKey) {
    return _resolve(Promise)
      .then(function () { return _crypto.subtle.exportKey(format, key); })
      .then(function (b) { return _bufferFrom(b); });
  }
  if (!key.extractable) {
    throw E(code, "the CryptoKey comes from a different WebCrypto implementation and is not extractable, so its key material cannot be reached; import it through pki.webcrypto.subtle, or pass the key as DER");
  }
  // A separately-installed copy of this engine is the same code under a different class identity, so
  // its keys fail the `instanceof` above while carrying the very handle this engine reads -- and no
  // WebCrypto implementation but that copy would accept them. Read the handle directly. The
  // extractable check above stays AHEAD of this: the handle can always be read, so honoring the
  // key's own extractable promise is this branch's responsibility, not the crypto library's.
  var handle = key._handle;
  if (handle instanceof nodeCrypto.KeyObject && handle.type === key.type) {
    return _resolve(Promise).then(function () {
      return format === "raw" ? handle.export() : handle.export({ format: "der", type: format });
    }).then(function (b) { return _bufferFrom(b); }, function (e) {
      throw E(code, "the CryptoKey comes from a different copy of this WebCrypto engine and its key material could not be read; import it through pki.webcrypto.subtle, or pass the key as DER", e);
    });
  }
  // Otherwise the only remaining implementation whose keys are reachable from this process is the
  // platform's own. A third party's -- a browser's, a userland polyfill's -- keeps its material
  // behind its own SubtleCrypto, which nothing here holds a reference to, so it is refused below.
  return _resolve(Promise)
    .then(function () { return nodeCrypto.webcrypto.subtle.exportKey(format, key); })
    .then(function (b) { return _bufferFrom(b); }, function (e) {
      throw E(code, "the CryptoKey comes from a different WebCrypto implementation and could not be exported for re-import; import it through pki.webcrypto.subtle, or pass the key as DER", e);
    });
}

// @internal
// A CryptoKey this engine can use. One it minted passes through untouched -- so a non-extractable
// key of its own keeps working -- and a foreign one is re-imported. `importParams` may be null, in
// which case the key's own `algorithm` is used, which is what the key actually is.
function adoptKey(key, importParams, usages, E, code) {
  if (key instanceof CryptoKey) return _resolve(Promise, key);
  // A key's usages are a capability restriction it carries, and re-importing it is the one moment
  // that restriction could be widened -- the new key is created with the usages the CALLER wants,
  // not the ones the original was created with. Require every one of them up front, so an adopted
  // key can do no more than it could where it came from, and a verify-only key is refused here
  // exactly as this engine's own verify-only key is refused by _requireUsage.
  if (!_isArray(key.usages)) throw E(code, "a CryptoKey carrying its permitted usages is required");
  for (var i = 0; i < usages.length; i++) {
    if (_indexOf(key.usages, usages[i]) === -1) {
      throw E(code, "the CryptoKey is not permitted for '" + usages[i] + "' (usages: " + _join(key.usages, ",") + ")");
    }
  }
  return _resolve(Promise)
    .then(function () { return exportAnyKey(key, E, code); })
    .then(function (der) {
      return _crypto.subtle.importKey(_EXPORT_FORMAT[key.type], der, importParams || key.algorithm, false, usages);
    });
}

module.exports = {
  webcrypto:     _crypto,
  Crypto:        Crypto,
  SubtleCrypto:  SubtleCrypto,
  CryptoKey:     CryptoKey,
  WebCryptoError: WebCryptoError,
  decompressEcPoint: decompressEcPoint,
  isCryptoKeyLike: isCryptoKeyLike,
  exportAnyKey:  exportAnyKey,
  adoptKey:      adoptKey,
};
