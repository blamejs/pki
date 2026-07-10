// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.webcrypto
 * @nav        Core
 * @title      WebCrypto
 * @order      50
 * @featured   true
 * @slug       webcrypto
 *
 * @intro
 *   A zero-dependency W3C Web Cryptography API (`Crypto` / `SubtleCrypto`
 *   / `CryptoKey`) built directly on Node's native `node:crypto`. It is
 *   the toolkit's injectable crypto engine, presented in the standard
 *   WebCrypto shape so operators -- and every higher structure (X.509,
 *   CMS, OCSP) -- reach for one familiar surface.
 *
 *   Unlike the browser's built-in `crypto.subtle`, this engine is
 *   **PQC-first without being PQC-only**: the FIPS 204 ML-DSA and FIPS
 *   205 SLH-DSA signature suites sit alongside the full classical set PKI
 *   still runs on -- RSASSA-PKCS1-v1_5, RSA-PSS, RSA-OAEP, ECDSA, ECDH,
 *   Ed25519 / Ed448, AES-GCM / CBC / KW, HMAC, HKDF, PBKDF2, and the SHA
 *   family (including legacy SHA-1 for old certificates and signatures).
 *   FIPS 203 ML-KEM key generation and encoding are available; KEM
 *   encapsulation follows once Node exposes it. Because it is
 *   OpenSSL-backed, every key and signature it emits is interoperable
 *   with OpenSSL, NSS, and other PKI implementations.
 *
 * @card
 *   A zero-dep, PQC-first W3C WebCrypto (`SubtleCrypto`) engine over
 *   `node:crypto` -- ML-DSA + SLH-DSA signatures alongside the full
 *   classical algorithm set.
 */

var nodeCrypto = require("node:crypto");
var frameworkError = require("./framework-error");

// Single-owner error class -- co-located with its module (framework-error
// stays the cross-module home; this is webcrypto-private). withCause: a
// failure discovered while processing decrypted/untrusted bytes threads the
// underlying fault instead of discarding it.
var WebCryptoError = frameworkError.defineClass("WebCryptoError", { withCause: true });

var MAX_RANDOM_BYTES = 65536;

// ---- value helpers ---------------------------------------------------

function _toBuf(data, who) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  throw new WebCryptoError("webcrypto/data", (who || "input") + ": expected BufferSource (ArrayBuffer / TypedArray / Buffer)");
}

function _toArrayBuffer(buf) {
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function _b64urlToBuf(s) { return Buffer.from(String(s), "base64url"); }
function _bufToB64url(buf) { return Buffer.from(buf).toString("base64url"); }

function _normalizeAlg(algorithm, who) {
  var alg = (typeof algorithm === "string") ? { name: algorithm } : algorithm;
  if (!alg || typeof alg.name !== "string") {
    throw new WebCryptoError("webcrypto/syntax", (who || "operation") + ": algorithm must be a string or an object with a name");
  }
  var out = {};
  for (var k in alg) { if (Object.prototype.hasOwnProperty.call(alg, k)) out[k] = alg[k]; }
  out.name = alg.name.toUpperCase();
  return out;
}

// WebCrypto hash name -> node digest name. SHA-1 is retained for
// backwards compatibility with legacy certificates and signatures.
var HASH_NODE = {
  "SHA-1":   "sha1",
  "SHA-256": "sha256",
  "SHA-384": "sha384",
  "SHA-512": "sha512",
  "SHA3-256": "sha3-256",
  "SHA3-384": "sha3-384",
  "SHA3-512": "sha3-512",
};

function _hashNode(h, who) {
  var name = (typeof h === "string") ? h : (h && h.name);
  var node = HASH_NODE[String(name).toUpperCase()];
  if (!node) throw new WebCryptoError("webcrypto/not-supported", (who || "operation") + ": unsupported hash " + JSON.stringify(name));
  return node;
}

// W3C HMAC get-key-length: an explicit `length` is used as given (validated
// to a positive multiple of 8, so the byte-level key material is exact and
// never a raw RangeError out of randomBytes); an OMITTED length defaults to
// the BLOCK size of the hash -- the HMAC key-pad width -- NOT the digest
// size. A digest-size default would mint different key material than every
// conforming WebCrypto for identical inputs, so MACs keyed through this
// engine would fail to verify elsewhere.
var HMAC_BLOCK_BITS = {
  "SHA-1": 512, "SHA-256": 512, "SHA-384": 1024, "SHA-512": 1024,
  "SHA3-256": 1088, "SHA3-384": 832, "SHA3-512": 576,
};

function _hmacLengthBits(alg, who) {
  var name = (typeof alg.hash === "string") ? alg.hash : (alg.hash && alg.hash.name);
  var blockBits = HMAC_BLOCK_BITS[String(name).toUpperCase()];
  if (!blockBits) throw new WebCryptoError("webcrypto/not-supported", who + ": unsupported hash " + JSON.stringify(name));
  if (alg.length == null) return blockBits;
  if (typeof alg.length !== "number" || !isFinite(alg.length) || alg.length <= 0 || alg.length % 8 !== 0) {
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
// same shape as ML-DSA / EdDSA. KEM encapsulation for ML-KEM is not yet
// in Node's API, so ML-KEM here is key-generation / encoding only.
var SLH_DSA_NODE = {};
["sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
 "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"
].forEach(function (s) { SLH_DSA_NODE["SLH-DSA-" + s.toUpperCase()] = "slh-dsa-" + s; });

// The algorithm names each keyed operation recognizes. Membership is checked
// BEFORE the algorithm/key name binding so an unrecognized algorithm reports
// NotSupportedError while a recognized-but-wrong-for-this-key one reports
// InvalidAccessError, matching the W3C error ordering.
var SIGN_VERIFY_NAMES = {};
["RSASSA-PKCS1-V1_5", "RSA-PSS", "ECDSA", "ED25519", "ED448", "HMAC"]
  .concat(Object.keys(ML_DSA_NODE), Object.keys(SLH_DSA_NODE))
  .forEach(function (n) { SIGN_VERIFY_NAMES[n] = true; });
var ENCRYPT_DECRYPT_NAMES = { "RSA-OAEP": true, "AES-GCM": true, "AES-CBC": true, "AES-CTR": true };
var DERIVE_NAMES = { "ECDH": true, "X25519": true, "X448": true, "HKDF": true, "PBKDF2": true };

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
  this.algorithm = algorithm;
  this.usages = usages ? usages.slice() : [];
  Object.defineProperty(this, "_handle", { value: handle, enumerable: false });
}

function _requireUsage(key, usage) {
  if (key.usages.indexOf(usage) === -1) {
    throw new WebCryptoError("webcrypto/invalid-access", "key is not permitted for '" + usage + "' (usages: " + key.usages.join(",") + ")");
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
  if (String(keyName).toUpperCase() !== alg.name) {
    throw new WebCryptoError("webcrypto/invalid-access", who + ": algorithm " + JSON.stringify(alg.name) + " does not match the key's algorithm " + JSON.stringify(keyName));
  }
}

// ---- SubtleCrypto ----------------------------------------------------

function SubtleCrypto() {}

SubtleCrypto.prototype.digest = async function digest(algorithm, data) {
  var node = _hashNode(_normalizeAlg(algorithm, "digest").name, "digest");
  var h = nodeCrypto.createHash(node);
  h.update(_toBuf(data, "digest"));
  return _toArrayBuffer(h.digest());
};

SubtleCrypto.prototype.generateKey = async function generateKey(algorithm, extractable, keyUsages) {
  var alg = _normalizeAlg(algorithm, "generateKey");
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
  var privUsages = usages.filter(function (u) { return u === "sign" || u === "deriveKey" || u === "deriveBits" || u === "decrypt" || u === "unwrapKey" || u === "decapsulateKey" || u === "decapsulateBits"; });
  var pubUsages = usages.filter(function (u) { return u === "verify" || u === "encrypt" || u === "wrapKey" || u === "encapsulateKey" || u === "encapsulateBits"; });
  return {
    privateKey: new CryptoKey("private", extractable, pubAlg, privUsages, pair.privateKey),
    publicKey:  new CryptoKey("public", true, pubAlg, pubUsages, pair.publicKey),
  };
};

function _generateKeyPair(alg) {
  var name = alg.name, kp, algorithm;
  if (name === "RSASSA-PKCS1-V1_5" || name === "RSA-PSS" || name === "RSA-OAEP") {
    kp = nodeCrypto.generateKeyPairSync("rsa", {
      modulusLength: alg.modulusLength || 2048,
      publicExponent: alg.publicExponent ? _bufToBigIntNum(alg.publicExponent) : 65537,
    });
    algorithm = { name: name, modulusLength: alg.modulusLength || 2048, publicExponent: alg.publicExponent, hash: _hashObj(alg.hash) };
  } else if (name === "ECDSA" || name === "ECDH") {
    var curve = alg.namedCurve;
    if (!CURVE_NODE[curve]) throw new WebCryptoError("webcrypto/not-supported", name + ": unsupported curve " + JSON.stringify(curve));
    kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: CURVE_NODE[curve] });
    algorithm = { name: name, namedCurve: curve };
  } else if (name === "ED25519" || name === "ED448" || name === "X25519" || name === "X448") {
    kp = nodeCrypto.generateKeyPairSync(name.toLowerCase());
    algorithm = { name: (name === "ED25519" ? "Ed25519" : name === "ED448" ? "Ed448" : name) };
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
    throw new WebCryptoError("webcrypto/not-supported", "generateKey: unsupported algorithm " + JSON.stringify(name));
  }
  return { publicKey: kp.publicKey, privateKey: kp.privateKey, algorithm: algorithm };
}

function _hashObj(h) { if (!h) return undefined; return { name: (typeof h === "string" ? h : h.name) }; }
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
  var v = BigInt("0x" + b.toString("hex"));
  if (v > 0xffffffffn) {
    throw new WebCryptoError("webcrypto/syntax", "publicExponent " + v.toString() + " exceeds the 2^32-1 bound");
  }
  return Number(v);
}

SubtleCrypto.prototype.sign = async function sign(algorithm, key, data) {
  var alg = _normalizeAlg(algorithm, "sign");
  _requireUsage(key, "sign");
  var buf = _toBuf(data, "sign");
  var name = alg.name;
  if (!SIGN_VERIFY_NAMES[name]) throw new WebCryptoError("webcrypto/not-supported", "sign: unsupported algorithm " + JSON.stringify(name));
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
  if (name === "ED25519" || name === "ED448" || ML_DSA_NODE[name] || SLH_DSA_NODE[name]) {
    return _toArrayBuffer(nodeCrypto.sign(null, buf, key._handle));
  }
  if (name === "HMAC") {
    var hm = nodeCrypto.createHmac(_hashNode(key.algorithm.hash, "sign"), key._handle);
    hm.update(buf);
    return _toArrayBuffer(hm.digest());
  }
  throw new WebCryptoError("webcrypto/not-supported", "sign: unsupported algorithm " + JSON.stringify(name));
};

SubtleCrypto.prototype.verify = async function verify(algorithm, key, signature, data) {
  var alg = _normalizeAlg(algorithm, "verify");
  _requireUsage(key, "verify");
  var sig = _toBuf(signature, "verify");
  var buf = _toBuf(data, "verify");
  var name = alg.name;
  if (!SIGN_VERIFY_NAMES[name]) throw new WebCryptoError("webcrypto/not-supported", "verify: unsupported algorithm " + JSON.stringify(name));
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
  if (name === "ED25519" || name === "ED448" || ML_DSA_NODE[name] || SLH_DSA_NODE[name]) {
    return nodeCrypto.verify(null, buf, key._handle, sig);
  }
  if (name === "HMAC") {
    var hm = nodeCrypto.createHmac(_hashNode(key.algorithm.hash, "verify"), key._handle);
    hm.update(buf);
    // Verify must RESOLVE false for any invalid signature, including one of
    // the wrong length. timingSafeEqual throws RangeError on a length
    // mismatch, so gate on length first; the length is already public, so
    // this leaks nothing a constant-time compare would protect.
    var mac = hm.digest();
    return mac.length === sig.length && nodeCrypto.timingSafeEqual(mac, sig);
  }
  throw new WebCryptoError("webcrypto/not-supported", "verify: unsupported algorithm " + JSON.stringify(name));
};

SubtleCrypto.prototype.encrypt = async function encrypt(algorithm, key, data) {
  var alg = _normalizeAlg(algorithm, "encrypt");
  _requireUsage(key, "encrypt");
  var buf = _toBuf(data, "encrypt");
  var name = alg.name;
  if (!ENCRYPT_DECRYPT_NAMES[name]) throw new WebCryptoError("webcrypto/not-supported", "encrypt: unsupported algorithm " + JSON.stringify(name));
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
    var cipher = nodeCrypto.createCipheriv("aes-" + key.algorithm.length + "-gcm", _secretBytes(key), iv, { authTagLength: (alg.tagLength || 128) / 8 });
    if (alg.additionalData) cipher.setAAD(_toBuf(alg.additionalData, "AES-GCM aad"));
    var ct = Buffer.concat([cipher.update(buf), cipher.final()]);
    return _toArrayBuffer(Buffer.concat([ct, cipher.getAuthTag()]));
  }
  if (name === "AES-CBC") {
    var c2 = nodeCrypto.createCipheriv("aes-" + key.algorithm.length + "-cbc", _secretBytes(key), _toBuf(alg.iv, "AES-CBC iv"));
    return _toArrayBuffer(Buffer.concat([c2.update(buf), c2.final()]));
  }
  if (name === "AES-CTR") {
    _requireCtrLength128(alg);
    var c3 = nodeCrypto.createCipheriv("aes-" + key.algorithm.length + "-ctr", _secretBytes(key), _toBuf(alg.counter, "AES-CTR counter"));
    return _toArrayBuffer(Buffer.concat([c3.update(buf), c3.final()]));
  }
  throw new WebCryptoError("webcrypto/not-supported", "encrypt: unsupported algorithm " + JSON.stringify(name));
};

SubtleCrypto.prototype.decrypt = async function decrypt(algorithm, key, data) {
  var alg = _normalizeAlg(algorithm, "decrypt");
  _requireUsage(key, "decrypt");
  var buf = _toBuf(data, "decrypt");
  var name = alg.name;
  if (!ENCRYPT_DECRYPT_NAMES[name]) throw new WebCryptoError("webcrypto/not-supported", "decrypt: unsupported algorithm " + JSON.stringify(name));
  _requireAlgMatch(alg, key, "decrypt");
  if (name === "RSA-OAEP") {
    return _toArrayBuffer(nodeCrypto.privateDecrypt({
      key: key._handle, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: _hashNode(key.algorithm.hash, "decrypt"),
      oaepLabel: alg.label ? _toBuf(alg.label, "decrypt label") : undefined,
    }, buf));
  }
  if (name === "AES-GCM") {
    var tagLen = (alg.tagLength || 128) / 8;
    var iv = _toBuf(alg.iv, "AES-GCM iv");
    var ct = buf.subarray(0, buf.length - tagLen);
    var tag = buf.subarray(buf.length - tagLen);
    var d = nodeCrypto.createDecipheriv("aes-" + key.algorithm.length + "-gcm", _secretBytes(key), iv, { authTagLength: tagLen });
    if (alg.additionalData) d.setAAD(_toBuf(alg.additionalData, "AES-GCM aad"));
    d.setAuthTag(tag);
    return _toArrayBuffer(Buffer.concat([d.update(ct), d.final()]));
  }
  if (name === "AES-CBC") {
    var d2 = nodeCrypto.createDecipheriv("aes-" + key.algorithm.length + "-cbc", _secretBytes(key), _toBuf(alg.iv, "AES-CBC iv"));
    return _toArrayBuffer(Buffer.concat([d2.update(buf), d2.final()]));
  }
  if (name === "AES-CTR") {
    _requireCtrLength128(alg);
    var d3 = nodeCrypto.createDecipheriv("aes-" + key.algorithm.length + "-ctr", _secretBytes(key), _toBuf(alg.counter, "AES-CTR counter"));
    return _toArrayBuffer(Buffer.concat([d3.update(buf), d3.final()]));
  }
  throw new WebCryptoError("webcrypto/not-supported", "decrypt: unsupported algorithm " + JSON.stringify(name));
};

function _secretBytes(key) { return key._handle.export(); }

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
  if (typeof length !== "number" || !isFinite(length) || length <= 0 || length % 8 !== 0) {
    throw new WebCryptoError("webcrypto/operation", who + ": length must be a positive multiple of 8 bits");
  }
}

// Raw key-agreement / KDF derivation with NO usage check -- the usage a
// caller must hold differs by entry point (deriveBits requires "deriveBits",
// deriveKey requires "deriveKey"), so each public method checks its own
// usage and then routes the actual derivation through here.
function _deriveBitsRaw(alg, key, length) {
  var name = alg.name;
  if (name === "ECDH" || name === "X25519" || name === "X448") {
    _requireAlgMatch(alg, alg.public, name + " public key");
    var secret = nodeCrypto.diffieHellman({ privateKey: key._handle, publicKey: alg.public._handle });
    if (length == null) return _toArrayBuffer(secret);
    _requireDeriveLength(length, name);
    // subarray clamps at the end of the secret, so an unchecked over-request
    // would silently return fewer bytes than asked. W3C deriveBits: throw an
    // OperationError when the requested length cannot be satisfied.
    if (length / 8 > secret.length) {
      throw new WebCryptoError("webcrypto/operation", name + ": requested " + length + " bits but the shared secret has " + (secret.length * 8));
    }
    return _toArrayBuffer(secret.subarray(0, length / 8));
  }
  if (name === "HKDF") {
    _requireDeriveLength(length, "HKDF");
    var derived = nodeCrypto.hkdfSync(_hashNode(alg.hash, "HKDF"), _secretBytes(key), _toBuf(alg.salt, "HKDF salt"), _toBuf(alg.info || Buffer.alloc(0), "HKDF info"), length / 8);
    return derived instanceof ArrayBuffer ? derived : _toArrayBuffer(Buffer.from(derived));
  }
  if (name === "PBKDF2") {
    _requireDeriveLength(length, "PBKDF2");
    var out = nodeCrypto.pbkdf2Sync(_secretBytes(key), _toBuf(alg.salt, "PBKDF2 salt"), alg.iterations, length / 8, _hashNode(alg.hash, "PBKDF2"));
    return _toArrayBuffer(out);
  }
  throw new WebCryptoError("webcrypto/not-supported", "deriveBits: unsupported algorithm " + JSON.stringify(name));
}

SubtleCrypto.prototype.deriveBits = async function deriveBits(algorithm, key, length) {
  var alg = _normalizeAlg(algorithm, "deriveBits");
  _requireUsage(key, "deriveBits");
  if (!DERIVE_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "deriveBits: unsupported algorithm " + JSON.stringify(alg.name));
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
  if (!DERIVE_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "deriveKey: unsupported algorithm " + JSON.stringify(alg.name));
  _requireAlgMatch(alg, baseKey, "deriveKey");
  var dk = _normalizeAlg(derivedKeyType, "deriveKey");
  var bits;
  if (dk.name.indexOf("AES") === 0) {
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
  var raw = _deriveBitsRaw(alg, baseKey, bits);
  return this.importKey("raw", raw, dk, extractable, keyUsages);
};

SubtleCrypto.prototype.wrapKey = async function wrapKey(format, key, wrappingKey, wrapAlgorithm) {
  var exported = await this.exportKey(format, key);
  var bytes = (format === "jwk") ? Buffer.from(JSON.stringify(exported)) : Buffer.from(exported);
  var alg = _normalizeAlg(wrapAlgorithm, "wrapKey");
  _requireUsage(wrappingKey, "wrapKey");
  if (alg.name !== "AES-KW" && !ENCRYPT_DECRYPT_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "wrapKey: unsupported algorithm " + JSON.stringify(alg.name));
  _requireAlgMatch(alg, wrappingKey, "wrapKey");
  if (alg.name === "AES-KW") {
    var c = nodeCrypto.createCipheriv("aes" + wrappingKey.algorithm.length + "-wrap", _secretBytes(wrappingKey), Buffer.from("A6A6A6A6A6A6A6A6", "hex"));
    return _toArrayBuffer(Buffer.concat([c.update(bytes), c.final()]));
  }
  // Delegate to a content-encryption algorithm (RSA-OAEP / AES-GCM).
  var wrapKeyClone = _cloneWithUsage(wrappingKey, "encrypt");
  return this.encrypt(wrapAlgorithm, wrapKeyClone, bytes);
};

SubtleCrypto.prototype.unwrapKey = async function unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
  var alg = _normalizeAlg(unwrapAlgorithm, "unwrapKey");
  // Enforce the "unwrapKey" usage before EITHER path. The delegated
  // (RSA-OAEP / AES-GCM) branch clones the key with "decrypt" and hands off
  // to this.decrypt, so without this top-level check the else branch would
  // never verify the caller was actually permitted to unwrap (mirrors
  // wrapKey, which checks before both of its paths).
  _requireUsage(unwrappingKey, "unwrapKey");
  if (alg.name !== "AES-KW" && !ENCRYPT_DECRYPT_NAMES[alg.name]) throw new WebCryptoError("webcrypto/not-supported", "unwrapKey: unsupported algorithm " + JSON.stringify(alg.name));
  _requireAlgMatch(alg, unwrappingKey, "unwrapKey");
  var bytes;
  if (alg.name === "AES-KW") {
    var d = nodeCrypto.createDecipheriv("aes" + unwrappingKey.algorithm.length + "-wrap", _secretBytes(unwrappingKey), Buffer.from("A6A6A6A6A6A6A6A6", "hex"));
    bytes = Buffer.concat([d.update(_toBuf(wrappedKey, "unwrapKey")), d.final()]);
  } else {
    var unwrapKeyClone = _cloneWithUsage(unwrappingKey, "decrypt");
    bytes = Buffer.from(await this.decrypt(unwrapAlgorithm, unwrapKeyClone, wrappedKey));
  }
  var keyData;
  if (format === "jwk") {
    // A NON-authenticating unwrap algorithm (AES-CBC / AES-CTR) decrypts
    // tampered bytes "successfully", so this JSON.parse is the first point
    // that can notice -- its failure must surface as the module's typed
    // error (W3C: DataError), never a raw SyntaxError from the public API.
    try { keyData = JSON.parse(bytes.toString()); }
    catch (e) { throw new WebCryptoError("webcrypto/data", "unwrapKey: unwrapped bytes are not a valid JWK", e); }
  } else {
    keyData = bytes;
  }
  return this.importKey(format, keyData, unwrappedKeyAlgorithm, extractable, keyUsages);
};

function _cloneWithUsage(key, usage) {
  var k = new CryptoKey(key.type, key.extractable, key.algorithm, key.usages.concat([usage]), key._handle);
  return k;
}

SubtleCrypto.prototype.importKey = async function importKey(format, keyData, algorithm, extractable, keyUsages) {
  var alg = _normalizeAlg(algorithm, "importKey");
  var usages = keyUsages || [];
  var name = alg.name;

  if (format === "raw") {
    // Symmetric raw material, or a raw public key for EC/OKP.
    if (name === "AES-GCM" || name === "AES-CBC" || name === "AES-CTR" || name === "AES-KW" || name === "HMAC" || name === "HKDF" || name === "PBKDF2") {
      var raw = _toBuf(keyData, "importKey raw");
      var secret = nodeCrypto.createSecretKey(raw);
      var symAlg = (name === "HMAC") ? { name: name, hash: _hashObj(alg.hash), length: raw.length * 8 } : { name: name, length: raw.length * 8 };
      return new CryptoKey("secret", extractable, symAlg, usages, secret);
    }
    // Raw public keys are imported via JWK reconstruction below.
    return _importRawPublic(name, alg, _toBuf(keyData, "importKey raw"), extractable, usages);
  }

  if (format === "spki") {
    var pub = nodeCrypto.createPublicKey({ key: _toBuf(keyData, "importKey spki"), format: "der", type: "spki" });
    return new CryptoKey("public", true, _algFromImport(name, alg, pub), usages, pub);
  }
  if (format === "pkcs8") {
    var priv = nodeCrypto.createPrivateKey({ key: _toBuf(keyData, "importKey pkcs8"), format: "der", type: "pkcs8" });
    return new CryptoKey("private", extractable, _algFromImport(name, alg, priv), usages, priv);
  }
  if (format === "jwk") {
    var jwk = keyData;
    if (jwk.kty === "oct") {
      var kbuf = _b64urlToBuf(jwk.k);
      var s2 = nodeCrypto.createSecretKey(kbuf);
      var a2 = (name === "HMAC") ? { name: name, hash: _hashObj(alg.hash), length: kbuf.length * 8 } : { name: name, length: kbuf.length * 8 };
      return new CryptoKey("secret", extractable, a2, usages, s2);
    }
    var isPrivate = Object.prototype.hasOwnProperty.call(jwk, "d");
    var ko = isPrivate ? nodeCrypto.createPrivateKey({ key: jwk, format: "jwk" }) : nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    return new CryptoKey(isPrivate ? "private" : "public", isPrivate ? extractable : true, _algFromImport(name, alg, ko), usages, ko);
  }
  throw new WebCryptoError("webcrypto/not-supported", "importKey: unsupported format " + JSON.stringify(format));
};

function _importRawPublic(name, alg, raw, extractable, usages) {
  if (name === "ED25519" || name === "ED448" || name === "X25519" || name === "X448") {
    var jwk = { kty: "OKP", crv: (name === "ED25519" ? "Ed25519" : name === "ED448" ? "Ed448" : name === "X25519" ? "X25519" : "X448"), x: _bufToB64url(raw) };
    var ko = nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    // The canonical mixed-case EdDSA labels, matching _algFromImport -- a raw
    // import must not label the same key differently than an spki/jwk one.
    return new CryptoKey("public", true, { name: name === "ED25519" ? "Ed25519" : name === "ED448" ? "Ed448" : alg.name }, usages, ko);
  }
  if (name === "ECDSA" || name === "ECDH") {
    var fb = CURVE_FIELD_BYTES[alg.namedCurve];
    if (!fb || raw[0] !== 0x04 || raw.length !== 1 + 2 * fb) throw new WebCryptoError("webcrypto/data", "importKey raw EC: expected an uncompressed point for " + alg.namedCurve);
    var ecjwk = { kty: "EC", crv: alg.namedCurve, x: _bufToB64url(raw.subarray(1, 1 + fb)), y: _bufToB64url(raw.subarray(1 + fb)) };
    var eck = nodeCrypto.createPublicKey({ key: ecjwk, format: "jwk" });
    return new CryptoKey("public", true, { name: name, namedCurve: alg.namedCurve }, usages, eck);
  }
  throw new WebCryptoError("webcrypto/not-supported", "importKey raw: unsupported public-key algorithm " + JSON.stringify(name));
}

function _algFromImport(name, alg, keyObject) {
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
      throw new WebCryptoError("webcrypto/data", name + ": importKey namedCurve " + JSON.stringify(alg.namedCurve) +
        " does not match the imported key's curve " + JSON.stringify(actualCurve));
    }
    return { name: name, namedCurve: actualCurve };
  }
  if (name === "RSASSA-PKCS1-V1_5" || name === "RSA-PSS" || name === "RSA-OAEP") return { name: name, hash: _hashObj(alg.hash) };
  if (name === "ED25519") return { name: "Ed25519" };
  if (name === "ED448") return { name: "Ed448" };
  return { name: alg.name };
}

function _curveFromKey(ko) {
  try { var jwk = ko.export({ format: "jwk" }); for (var k in CURVE_NODE) { if (jwk.crv === k) return k; } } catch (_e) { /* best-effort */ }
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
 * @example
 *   var keyPair = await pki.webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
 *   var spki = await pki.webcrypto.subtle.exportKey("spki", keyPair.publicKey);
 */
SubtleCrypto.prototype.exportKey = async function exportKey(format, key) {
  if (!key.extractable) throw new WebCryptoError("webcrypto/invalid-access", "key is not extractable");
  if (format === "jwk") return key._handle.export({ format: "jwk" });
  if (key.type === "secret") {
    var raw = key._handle.export();
    if (format === "raw") return _toArrayBuffer(raw);
    throw new WebCryptoError("webcrypto/not-supported", "exportKey: secret keys support 'raw' / 'jwk' only");
  }
  if (format === "spki") return _toArrayBuffer(key._handle.export({ format: "der", type: "spki" }));
  if (format === "pkcs8") return _toArrayBuffer(key._handle.export({ format: "der", type: "pkcs8" }));
  if (format === "raw") return _toArrayBuffer(_rawPublic(key));
  throw new WebCryptoError("webcrypto/not-supported", "exportKey: unsupported format " + JSON.stringify(format));
};

function _rawPublic(key) {
  var jwk = key._handle.export({ format: "jwk" });
  if (jwk.kty === "OKP") return _b64urlToBuf(jwk.x);
  if (jwk.kty === "EC") return Buffer.concat([Buffer.from([0x04]), _b64urlToBuf(jwk.x), _b64urlToBuf(jwk.y)]);
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
  if (!ArrayBuffer.isView(typedArray) || typedArray instanceof Float32Array || typedArray instanceof Float64Array || typedArray instanceof DataView) {
    throw new WebCryptoError("webcrypto/data", "getRandomValues: expected an integer TypedArray");
  }
  if (typedArray.byteLength > MAX_RANDOM_BYTES) {
    throw new WebCryptoError("webcrypto/data", "getRandomValues: byteLength exceeds " + MAX_RANDOM_BYTES);
  }
  nodeCrypto.randomFillSync(Buffer.from(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength));
  return typedArray;
};

Crypto.prototype.randomUUID = function randomUUID() { return nodeCrypto.randomUUID(); };

module.exports = {
  webcrypto:     new Crypto(),
  Crypto:        Crypto,
  SubtleCrypto:  SubtleCrypto,
  CryptoKey:     CryptoKey,
  WebCryptoError: WebCryptoError,
};
