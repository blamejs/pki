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
 *   still runs on: RSASSA-PKCS1-v1_5, RSA-PSS, RSA-OAEP, ECDSA, ECDH,
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
var intrinsic = require("./guard-intrinsic");
var _isArray = intrinsic.isArray;
var _hasOwn = intrinsic.hasOwn;
var _stringify = intrinsic.stringify;
var _bufferFrom = intrinsic.bufferFrom;
var _bufToString = intrinsic.uncurry(Buffer.prototype.toString);
var _hashUpdate = intrinsic.uncurry(nodeCrypto.Hash.prototype.update);
var _hashDigest = intrinsic.uncurry(nodeCrypto.Hash.prototype.digest);
var _cipherUpdate = intrinsic.uncurry(nodeCrypto.Cipheriv.prototype.update);
var _cipherFinal = intrinsic.uncurry(nodeCrypto.Cipheriv.prototype.final);
var _cipherGetAuthTag = intrinsic.uncurry(nodeCrypto.Cipheriv.prototype.getAuthTag);
var _cipherSetAAD = intrinsic.uncurry(nodeCrypto.Cipheriv.prototype.setAAD);
var _decipherUpdate = intrinsic.uncurry(nodeCrypto.Decipheriv.prototype.update);
var _decipherFinal = intrinsic.uncurry(nodeCrypto.Decipheriv.prototype.final);
var _STREAM_CHUNK = constants.BYTES.kib(64);
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
var _apply = intrinsic.apply;
var _NO_ARGS = intrinsic.freeze([]);
var _toUpperCase = intrinsic.toUpperCase;
var _toLowerCase = intrinsic.toLowerCase;
var _stringIndexOf = intrinsic.stringIndexOf;
var _subarray = intrinsic.subarray;
var _arrayBufferSlice = intrinsic.arrayBufferSlice;
var _numberToString = intrinsic.numberToString;
var _bigIntToString = intrinsic.bigIntToString;
var _push = intrinsic.push;
var _concat = intrinsic.concat;
var _resolve = intrinsic.uncurry(intrinsic.promiseResolve);
var _types = intrinsic.types;

var WebCryptoError = frameworkError.defineClass("WebCryptoError", { withCause: true });

var MAX_RANDOM_BYTES = 65536;


function _toBuf(data, who) {
  return guard.bytes.source(data, WebCryptoError, "webcrypto/data", who || "input");
}

function _toArrayBuffer(buf) {
  return _arrayBufferSlice(buf.buffer, buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function _wcErr(code, msg) { return new WebCryptoError(code, msg); }
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

var _STD_ALG_NAME = intrinsic.assign(intrinsic.create(null), { "RSASSA-PKCS1-V1_5": "RSASSA-PKCS1-v1_5", "ED25519": "Ed25519", "ED448": "Ed448" });
function _stdName(name) { return _STD_ALG_NAME[name] || name; }

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

var XOF_NODE = {
  "SHAKE128": { node: "shake128", length: 32 },
  "SHAKE256": { node: "shake256", length: 64 },
};

function _hashNode(h, who) {
  var name = (typeof h === "string") ? h : (h && h.name);
  var node = HASH_NODE[_toUpperCase(_String(name))];
  if (!node) throw new WebCryptoError("webcrypto/not-supported", (who || "operation") + ": unsupported hash " + _stringify(name));
  return node;
}

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

var CURVE_NODE = intrinsic.assign(intrinsic.create(null), { "P-256": "prime256v1", "P-384": "secp384r1", "P-521": "secp521r1" });
var CURVE_FIELD_BYTES = intrinsic.assign(intrinsic.create(null), { "P-256": 32, "P-384": 48, "P-521": 66 });

var ML_DSA_NODE = intrinsic.assign(intrinsic.create(null), { "ML-DSA-44": "ml-dsa-44", "ML-DSA-65": "ml-dsa-65", "ML-DSA-87": "ml-dsa-87" });
var ML_KEM_NODE = intrinsic.assign(intrinsic.create(null), { "ML-KEM-512": "ml-kem-512", "ML-KEM-768": "ml-kem-768", "ML-KEM-1024": "ml-kem-1024" });

var SLH_DSA_NODE = intrinsic.create(null);
["sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
 "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"
].forEach(function (s) { SLH_DSA_NODE["SLH-DSA-" + _toUpperCase(s)] = "slh-dsa-" + s; });

var SIGN_VERIFY_NAMES = intrinsic.create(null);
["RSASSA-PKCS1-V1_5", "RSA-PSS", "ECDSA", "ED25519", "ED448", "HMAC"]
  .concat(_keys(ML_DSA_NODE), _keys(SLH_DSA_NODE))
  .forEach(function (n) { SIGN_VERIFY_NAMES[n] = true; });
var ENCRYPT_DECRYPT_NAMES = intrinsic.assign(intrinsic.create(null), { "RSA-OAEP": true, "AES-GCM": true, "AES-CBC": true, "AES-CTR": true });
var DERIVE_NAMES = intrinsic.assign(intrinsic.create(null), { "ECDH": true, "X25519": true, "X448": true, "HKDF": true, "PBKDF2": true, "X963KDF": true });
var SECRET_KEY_NAMES = intrinsic.assign(intrinsic.create(null), { "AES-GCM": true, "AES-CBC": true, "AES-CTR": true, "AES-KW": true, "HMAC": true, "HKDF": true, "PBKDF2": true, "X963KDF": true });


/**
 * @primitive  pki.webcrypto.CryptoKey
 * @signature  new pki.webcrypto.CryptoKey(type, extractable, algorithm, usages, handle)
 * @since      0.1.0
 * @status     stable
 * @spec       W3C WebCrypto sec. cryptokey
 *
 * Opaque handle to key material, matching the W3C `CryptoKey` shape:
 * `{ type, extractable, algorithm, usages }`. The underlying
 * `node:crypto` KeyObject is non-enumerable and never serialized.
 * Extract material only through `subtle.exportKey`, and only when the key
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
  var frozenAlg = algorithm;
  if (frozenAlg && typeof frozenAlg === "object") {
    frozenAlg = _assign({}, algorithm);
    if (frozenAlg.hash && typeof frozenAlg.hash === "object") frozenAlg.hash = intrinsic.freeze(_assign({}, frozenAlg.hash));
    frozenAlg = intrinsic.freeze(frozenAlg);
  }
  _defineProperty(this, "algorithm", { value: frozenAlg, enumerable: true });
  if (usages != null && !_isArray(usages)) {
    throw new WebCryptoError("webcrypto/syntax", "usages must be an array of key-usage strings");
  }
  this.usages = usages ? _arraySlice(usages) : [];
  _defineProperty(this, "_handle", { value: handle, enumerable: false });
}

function _requireOwnKey(key, who) {
  if (key instanceof CryptoKey) return;
  if (isCryptoKeyLike(key)) {
    throw new WebCryptoError("webcrypto/invalid-access", who + ": the key was created by a different WebCrypto implementation; re-import it through this one");
  }
  throw new WebCryptoError("webcrypto/invalid-access", who + ": a CryptoKey is required");
}

function _requireUsage(key, usage) {
  _requireOwnKey(key, usage);
  if (_indexOf(key.usages, usage) === -1) {
    throw new WebCryptoError("webcrypto/invalid-access", "key is not permitted for '" + usage + "' (usages: " + _join(key.usages, ",") + ")");
  }
}

function _requireAlgMatch(alg, key, who) {
  var keyName = key && key.algorithm && key.algorithm.name;
  if (_toUpperCase(_String(keyName)) !== alg.name) {
    throw new WebCryptoError("webcrypto/invalid-access", who + ": algorithm " + _stringify(alg.name) + " does not match the key's algorithm " + _stringify(keyName));
  }
}


function SubtleCrypto() {}

SubtleCrypto.prototype.digest = async function digest(algorithm, data) {
  var name = _normalizeAlg(algorithm, "digest").name;
  var xof = XOF_NODE[_toUpperCase(_String(name))];
  var h = xof
    ? nodeCrypto.createHash(xof.node, { outputLength: xof.length })
    : nodeCrypto.createHash(_hashNode(name, "digest"));
  h.update(_toBuf(data, "digest"));
  return _toArrayBuffer(h.digest());
};

SubtleCrypto.prototype.digestStream = async function digestStream(algorithms, source) {
  if (!_isArray(algorithms) || !algorithms.length) {
    throw new WebCryptoError("webcrypto/syntax", "digestStream: algorithms must be a non-empty array of digest algorithms");
  }
  var hashes = [];
  for (var _h = 0; _h < algorithms.length; _h++) {
    var name = _normalizeAlg(algorithms[_h], "digestStream").name;
    var xof = XOF_NODE[_toUpperCase(_String(name))];
    hashes[_h] = xof
      ? nodeCrypto.createHash(xof.node, { outputLength: xof.length })
      : nodeCrypto.createHash(_hashNode(name, "digestStream"));
  }
  var acquire = source == null ? undefined : source[_asyncIterator];
  if (typeof acquire !== "function") {
    throw new WebCryptoError("webcrypto/syntax", "digestStream: source must be an async iterable of byte chunks");
  }
  var iterator = _apply(acquire, source, _NO_ARGS);
  try {
    var nextMethod = iterator == null ? undefined : iterator.next;
    if (typeof nextMethod !== "function") {
      throw new WebCryptoError("webcrypto/syntax", "digestStream: source must be an async iterable of byte chunks");
    }
    for (;;) {
      var step = await _apply(nextMethod, iterator, _NO_ARGS);
      if (step && step.done) break;
      var buf = _toBuf(step == null ? undefined : step.value, "digestStream chunk");
      for (var i = 0; i < hashes.length; i++) _hashUpdate(hashes[i], buf);
    }
  } catch (e) {
    try {
      var ret = iterator == null ? undefined : iterator.return;
      if (typeof ret === "function") await _apply(ret, iterator, _NO_ARGS);
    } catch (_r) { }
    throw e;
  }
  return _map(hashes, function (h) { return _toArrayBuffer(_hashDigest(h)); });
};

SubtleCrypto.prototype.encryptStream = async function encryptStream(spec, source) {
  var cipher = spec.authTagLength
    ? nodeCrypto.createCipheriv(spec.algNode, spec.key, spec.iv, { authTagLength: spec.authTagLength })
    : nodeCrypto.createCipheriv(spec.algNode, spec.key, spec.iv);
  if (spec.aad && spec.aad.length) _cipherSetAAD(cipher, spec.aad);
  var acquire = source == null ? undefined : source[_asyncIterator];
  if (typeof acquire !== "function") {
    throw new WebCryptoError("webcrypto/syntax", "encryptStream: source must be an async iterable of byte chunks");
  }
  var iterator = _apply(acquire, source, _NO_ARGS);
  var out = [];
  try {
    var nextMethod = iterator == null ? undefined : iterator.next;
    if (typeof nextMethod !== "function") {
      throw new WebCryptoError("webcrypto/syntax", "encryptStream: source must be an async iterable of byte chunks");
    }
    for (;;) {
      var step = await _apply(nextMethod, iterator, _NO_ARGS);
      if (step && step.done) break;
      var buf = _toBuf(step == null ? undefined : step.value, "encryptStream chunk");
      var piece = _cipherUpdate(cipher, buf);
      if (piece && piece.length) out[out.length] = piece;
    }
  } catch (e) {
    try {
      var ret = iterator == null ? undefined : iterator.return;
      if (typeof ret === "function") await _apply(ret, iterator, _NO_ARGS);
    } catch (_r) { }
    throw e;
  }
  out[out.length] = _cipherFinal(cipher);
  return { ciphertext: _bufferConcat(out), tag: spec.authTagLength ? _cipherGetAuthTag(cipher) : null };
};

SubtleCrypto.prototype.decryptStream = function decryptStream(spec, ct) {
  var decipher = nodeCrypto.createDecipheriv(spec.algNode, spec.key, spec.iv);
  return _decipherDrive(decipher, _bufferFrom(_toBuf(ct, "decryptStream ciphertext")), _STREAM_CHUNK);
};
async function* _decipherDrive(decipher, ct, chunkSize) {
  for (var off = 0; off < ct.length; off += chunkSize) {
    var end = off + chunkSize;
    var piece = _decipherUpdate(decipher, _subarray(ct, off, end < ct.length ? end : ct.length));
    if (piece && piece.length) yield piece;
  }
  var last = _decipherFinal(decipher);
  if (last && last.length) yield last;
}

SubtleCrypto.prototype.generateKey = async function generateKey(algorithm, extractable, keyUsages) {
  var alg = _normalizeAlg(algorithm, "generateKey");
  if (keyUsages != null && !_isArray(keyUsages)) {
    throw new WebCryptoError("webcrypto/syntax", "generateKey: keyUsages must be an array of key-usage strings");
  }
  var usages = keyUsages || [];
  var name = alg.name;

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

  var pair = _generateKeyPair(alg);
  var pubAlg = pair.algorithm;
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

function _hashObj(h, who) { if (!h) return undefined; var n = (typeof h === "string" ? h : h.name); _hashNode(n, who || "importKey"); return { name: n }; }
function _mldsaKeyArg(alg, keyHandle, who) {
  if (alg.context == null) return keyHandle;
  var ctx = _toBuf(alg.context, who + " context");
  if (ctx.length > 255) throw new WebCryptoError("webcrypto/data", who + ": an ML-DSA context must be at most 255 bytes (FIPS 204)");
  return { key: keyHandle, context: ctx };
}
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
    return nodeCrypto.verify(null, buf, _mldsaKeyArg(alg, key._handle, "verify"), sig);
  }
  if (name === "ED25519" || name === "ED448" || SLH_DSA_NODE[name]) {
    return nodeCrypto.verify(null, buf, key._handle, sig);
  }
  if (name === "HMAC") {
    var hm = nodeCrypto.createHmac(_hashNode(key.algorithm.hash, "verify"), key._handle);
    hm.update(buf);
    var digest = hm.digest();
    return guard.crypto.constantTimeEqual(digest, sig);
  }
  throw new WebCryptoError("webcrypto/not-supported", "verify: unsupported algorithm " + _stringify(name));
};

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
    var ct = _subarray(buf, 0, buf.length - tagLen);
    var tag = _subarray(buf, buf.length - tagLen);
    var gcmAad = alg.additionalData ? _toBuf(alg.additionalData, "AES-GCM aad") : null;
    return _toArrayBuffer(_runCipher(function () {
      return _withSecretBytes(key, function (kb) {
        var d = nodeCrypto.createDecipheriv("aes-" + key.algorithm.length + "-gcm", kb, iv, { authTagLength: tagLen });
        if (gcmAad) d.setAAD(gcmAad);
        d.setAuthTag(tag);
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

function _withSecretBytes(key, fn) {
  var kb = key._handle.export();
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

function _requireCtrLength128(alg) {
  if (alg.length !== 128) {
    throw new WebCryptoError("webcrypto/not-supported", "AES-CTR length must be 128");
  }
}

function _requireDeriveLength(length, who) {
  if (typeof length !== "number" || !_isFinite(length) || length <= 0 || length % 8 !== 0) {
    throw new WebCryptoError("webcrypto/operation", who + ": length must be a positive multiple of 8 bits");
  }
}

var _PBKDF2_MAX_CONCURRENT = _max(1, (_parseInt(process.env.UV_THREADPOOL_SIZE, 10) || 4) - 2);
var _pbkdf2InFlight = 0;
var _pbkdf2Waiters = [];
function _pbkdf2Async(pw, salt, iterations, keylen, digest) {
  return new Promise(function (resolve, reject) {
    function start() {
      _pbkdf2InFlight++;
      function done(err, derived) {
        _pbkdf2InFlight--;
        var next = _pbkdf2Waiters.shift();
        if (next) next();
        if (err) reject(err); else resolve(derived);
      }
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
    var secret = nodeCrypto.diffieHellman({ privateKey: key._handle, publicKey: alg.public._handle });
    try {
      if (length == null) return _toArrayBuffer(secret);
      _requireDeriveLength(length, name);
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
    return _withSecretBytes(key, function (ikm) {
      var derived = nodeCrypto.hkdfSync(_hashNode(alg.hash, "HKDF"), ikm, _toBuf(alg.salt, "HKDF salt"), _toBuf(alg.info || _bufferAlloc(0), "HKDF info"), length / 8);
      return _types.isArrayBuffer(derived) ? derived : _toArrayBuffer(_bufferFrom(derived));
    });
  }
  if (name === "PBKDF2") {
    _requireDeriveLength(length, "PBKDF2");
    return _withSecretBytes(key, function (pw) {
      return _pbkdf2Async(pw, _toBuf(alg.salt, "PBKDF2 salt"), alg.iterations, length / 8, _hashNode(alg.hash, "PBKDF2"))
        .then(function (out) {
          try { return _toArrayBuffer(out); }
          finally { guard.secret.zeroize(out, WebCryptoError, "webcrypto/operation", "the PBKDF2 output"); }
        });
    });
  }
  if (name === "X963KDF") {
    _requireDeriveLength(length, "X963KDF");
    return _withSecretBytes(key, function (z) {
      var derived = _x963Kdf(_hashNode(alg.hash, "X963KDF"), z, _toBuf(alg.info || _bufferAlloc(0), "X963KDF SharedInfo"), length / 8);
      try { return _toArrayBuffer(derived); }
      finally { guard.secret.zeroize(derived, WebCryptoError, "webcrypto/operation", "the X9.63 KDF output"); }
    });
  }
  throw new WebCryptoError("webcrypto/not-supported", "deriveBits: unsupported algorithm " + _stringify(name));
}

function _x963Kdf(hashNode, z, sharedInfo, lenBytes) {
  var blocks = [], counter = 1, got = 0;
  while (got < lenBytes) {
    if (counter > 0xffffffff) throw new WebCryptoError("webcrypto/operation", "X963KDF: requested output exceeds the counter range");
    var ctr = _bufferAlloc(4); ctr.writeUInt32BE(counter, 0);
    var h = nodeCrypto.createHash(hashNode).update(z).update(ctr).update(sharedInfo).digest();
    _push(blocks, h); got += h.length; counter += 1;
  }
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
  _requireUsage(baseKey, "deriveKey");
  var alg = _normalizeAlg(algorithm, "deriveKey");
  if (!DERIVE_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "deriveKey: unsupported algorithm " + _stringify(alg.name));
  _requireAlgMatch(alg, baseKey, "deriveKey");
  var dk = _normalizeAlg(derivedKeyType, "deriveKey");
  var bits;
  if (_stringIndexOf(dk.name, "AES") === 0) {
    if (dk.length !== 128 && dk.length !== 192 && dk.length !== 256) {
      throw new WebCryptoError("webcrypto/syntax", "deriveKey: " + dk.name + " length must be 128/192/256");
    }
    bits = dk.length;
  } else if (dk.name === "HMAC") {
    bits = _hmacLengthBits(dk, "deriveKey");
  } else {
    bits = dk.length != null ? dk.length : null;
  }
  var raw = await _deriveBitsRaw(alg, baseKey, bits);
  try { return await this.importKey("raw", raw, dk, extractable, keyUsages); }
  finally { guard.secret.zeroize(new _Uint8Array(raw), WebCryptoError, "webcrypto/operation", "the derived key material"); }
};

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
    return { sharedKey: _toArrayBuffer(r.sharedKey), ciphertext: _toArrayBuffer(r.ciphertext) };
  } finally {
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
  var kemRow = oid.kemParams("id-" + ML_KEM_NODE[alg.name]);
  if (kemRow && ct.length !== kemRow.ct) {
    throw new WebCryptoError("webcrypto/bad-kem-ciphertext",
      "decapsulateBits: " + alg.name + " expects a " + kemRow.ct + "-octet ciphertext, got " + ct.length + " (FIPS 203 sec. 7.3)");
  }
  var ss;
  try { ss = nodeCrypto.decapsulate(decapsulationKey._handle, ct); }
  catch (e) { throw new WebCryptoError("webcrypto/operation", "decapsulateBits: ML-KEM decapsulation failed (malformed or wrong-length ciphertext)", e); }
  try {
    return _toArrayBuffer(ss);
  } finally {
    guard.secret.zeroize(ss, WebCryptoError, "webcrypto/operation", "the KEM shared secret");
  }
};

SubtleCrypto.prototype.wrapKey = async function wrapKey(format, key, wrappingKey, wrapAlgorithm) {
  var exported = await this.exportKey(format, key);
  var bytes = (format === "jwk") ? _bufferFrom(_stringify(exported)) : _bufferFrom(exported);
  try {
  var alg = _normalizeAlg(wrapAlgorithm, "wrapKey");
  _requireUsage(wrappingKey, "wrapKey");
  if (alg.name !== "AES-KW" && !ENCRYPT_DECRYPT_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "wrapKey: unsupported algorithm " + _stringify(alg.name));
  _requireAlgMatch(alg, wrappingKey, "wrapKey");
  if (alg.name === "AES-KW") {
    if (bytes.length < 16 || bytes.length % 8 !== 0) {
      throw new WebCryptoError("webcrypto/operation", "wrapKey: AES-KW requires the serialized key be a multiple of 8 bytes (>= 16); got " + bytes.length + " -- format " + _stringify(format) + " is not AES-KW-wrappable");
    }
    try {
      return _withSecretBytes(wrappingKey, function (wkBytes) {
        var c = nodeCrypto.createCipheriv("aes" + wrappingKey.algorithm.length + "-wrap", wkBytes, _bufferFrom("A6A6A6A6A6A6A6A6", "hex"));
        return _toArrayBuffer(guard.secret.cipherFinish(c, bytes, WebCryptoError, "webcrypto/operation", "an AES-KW wrap intermediate"));
      });
    } catch (e) { throw new WebCryptoError("webcrypto/operation", "wrapKey: AES-KW key wrap failed", e); }
  }
  var wrapKeyClone = _cloneWithUsage(wrappingKey, "encrypt");
  return await this.encrypt(wrapAlgorithm, wrapKeyClone, bytes);
  } finally {
    guard.secret.zeroize(bytes, WebCryptoError, "webcrypto/operation", "the exported key being wrapped");
  }
};

SubtleCrypto.prototype.unwrapKey = async function unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
  var alg = _normalizeAlg(unwrapAlgorithm, "unwrapKey");
  _requireUsage(unwrappingKey, "unwrapKey");
  if (alg.name !== "AES-KW" && !ENCRYPT_DECRYPT_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "unwrapKey: unsupported algorithm " + _stringify(alg.name));
  _requireAlgMatch(alg, unwrappingKey, "unwrapKey");
  var bytes;
  if (alg.name === "AES-KW") {
    var wrapped = _toBuf(wrappedKey, "unwrapKey");
    if (wrapped.length < 24 || wrapped.length % 8 !== 0) {
      throw new WebCryptoError("webcrypto/operation", "unwrapKey: AES-KW wrapped key must be a multiple of 8 bytes (>= 24); got " + wrapped.length);
    }
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
    guard.secret.zeroize(bytes, WebCryptoError, "webcrypto/operation", "the unwrapped key material");
  }
};

function _cloneWithUsage(key, usage) {
  var k = new CryptoKey(key.type, key.extractable, key.algorithm, _concat(key.usages, [usage]), key._handle);
  return k;
}

function _assertAesImportLen(name, byteLen) {
  if ((name === "AES-GCM" || name === "AES-CBC" || name === "AES-CTR" || name === "AES-KW") &&
      byteLen !== 16 && byteLen !== 24 && byteLen !== 32) {
    throw new WebCryptoError("webcrypto/data", name + ": an imported AES key must be 128, 192, or 256 bits");
  }
}

function _nodeKey(fn, who) {
  try { return fn(); }
  catch (e) {
    if (e instanceof WebCryptoError) throw e;
    throw new WebCryptoError("webcrypto/data", who + ": the key material is malformed or internally inconsistent", e);
  }
}

var ML_KEM_INNER = {};
["id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024"].forEach(function (n) {
  var row = oid.kemParams(n);
  ML_KEM_INNER[oid.byName(n)] = { ek: row.ek, dk: row.dk };
});

function _isOctet(node, size) {
  return node && node.tagClass === "universal" && node.tagNumber === asn1.TAGS.OCTET_STRING &&
    !node.constructed && node.content && node.content.length === size;
}
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
    var kids = node.children || [];
    if (kids.length !== 2 || !_isOctet(kids[0], 64) || !_isOctet(kids[1], sizes.dk)) {
      throw new WebCryptoError("webcrypto/data", "an ML-KEM both-arm must be SEQUENCE { seed OCTET STRING(64), expandedKey OCTET STRING(" + sizes.dk + ") } (RFC 9935 sec. 6)");
    }
    return;
  }
  throw new WebCryptoError("webcrypto/data", "an ML-KEM private key must be the seed, expandedKey, or both CHOICE (RFC 9935 sec. 6)");
}

var PKCS8_INNER_VALIDATORS = {};
_forEach(_keys(ML_KEM_INNER), function (o) { PKCS8_INNER_VALIDATORS[o] = function (inner) { _validateMlKemInner(inner, ML_KEM_INNER[o]); }; });

function _preValidatePkcs8(p8, name) {
  if (!ML_KEM_NODE[name]) return;
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

  if ((format === "spki" || format === "pkcs8") && SECRET_KEY_NAMES[name]) {
    throw new WebCryptoError("webcrypto/not-supported", "importKey: " + name + " does not support the " + format + " key format");
  }

  if (format === "raw") {
    if (SECRET_KEY_NAMES[name]) {
      var raw = _toBuf(keyData, "importKey raw");
      _assertAesImportLen(name, raw.length);
      var secret = nodeCrypto.createSecretKey(raw);
      var symAlg = (name === "HMAC") ? { name: name, hash: _hashObj(alg.hash, "importKey raw HMAC"), length: raw.length * 8 } : { name: name, length: raw.length * 8 };
      return new CryptoKey("secret", extractable, symAlg, usages, secret);
    }
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

var IMPORT_KEY_TYPE = intrinsic.assign(intrinsic.create(null), {
  "RSASSA-PKCS1-V1_5": { rsa: 1 }, "RSA-PSS": { rsa: 1, "rsa-pss": 1 }, "RSA-OAEP": { rsa: 1 },
  "ECDSA": { ec: 1 }, "ECDH": { ec: 1 },
  "ED25519": { ed25519: 1 }, "ED448": { ed448: 1 },
  "X25519": { x25519: 1 }, "X448": { x448: 1 },
});
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
  catch (_e) { }
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
    return _withSecretBytes(key, function (raw) {
      if (format === "raw") return _toArrayBuffer(raw);
      throw new WebCryptoError("webcrypto/not-supported", "exportKey: secret keys support 'raw' / 'jwk' only");
    });
  }
  if (format === "spki") return _toArrayBuffer(key._handle.export({ format: "der", type: "spki" }));
  if (format === "pkcs8") return _toArrayBuffer(key._handle.export({ format: "der", type: "pkcs8" }));
  if (format === "raw") {
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
  if (!_isView(typedArray) || _types.isFloat32Array(typedArray) || _types.isFloat64Array(typedArray) || _types.isDataView(typedArray)) {
    throw new WebCryptoError("webcrypto/data", "getRandomValues: expected an integer TypedArray");
  }
  var out = guard.bytes.outputView(typedArray, WebCryptoError, "webcrypto/data", "getRandomValues");
  if (out.length > MAX_RANDOM_BYTES) {
    throw new WebCryptoError("webcrypto/data", "getRandomValues: byteLength exceeds " + MAX_RANDOM_BYTES);
  }
  nodeCrypto.randomFillSync(out);
  return typedArray;
};

Crypto.prototype.randomUUID = function randomUUID() { return nodeCrypto.randomUUID(); };

function decompressEcPoint(sec1Compressed, nodeCurve, E, code) {
  var head = sec1Compressed[0];
  if (head !== 0x02 && head !== 0x03) throw E(code, "EC point de-compression expects a compressed SEC1 point (0x02/0x03)");
  try {
    return nodeCrypto.ECDH.convertKey(sec1Compressed, nodeCurve, undefined, undefined, "uncompressed");
  } catch (e) {
    throw E(code, "EC point is not on curve " + nodeCurve + " (de-compression failed)", e);
  }
}

var _crypto = new Crypto();
var _EXPORT_FORMAT = _assign(_create(null), { "private": "pkcs8", "public": "spki", "secret": "raw" });

// @internal
function isCryptoKeyLike(x) {
  return !!x && typeof x === "object" && typeof x.type === "string" &&
    typeof x.extractable === "boolean" && !!x.algorithm && typeof x.algorithm === "object" &&
    typeof x.algorithm.name === "string" && _isArray(x.usages);
}

// @internal
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
  var handle = key._handle;
  if (handle instanceof nodeCrypto.KeyObject && handle.type === key.type) {
    return _resolve(Promise).then(function () {
      return format === "raw" ? handle.export() : handle.export({ format: "der", type: format });
    }).then(function (b) { return _bufferFrom(b); }, function (e) {
      throw E(code, "the CryptoKey comes from a different copy of this WebCrypto engine and its key material could not be read; import it through pki.webcrypto.subtle, or pass the key as DER", e);
    });
  }
  return _resolve(Promise)
    .then(function () { return nodeCrypto.webcrypto.subtle.exportKey(format, key); })
    .then(function (b) { return _bufferFrom(b); }, function (e) {
      throw E(code, "the CryptoKey comes from a different WebCrypto implementation and could not be exported for re-import; import it through pki.webcrypto.subtle, or pass the key as DER", e);
    });
}

// @internal
function adoptKey(key, importParams, usages, E, code) {
  if (key instanceof CryptoKey) return _resolve(Promise, key);
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
