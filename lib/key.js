// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.key
 * @nav        Signing
 * @title      Keys
 * @fullname   Key generation, import and export (RSA, EC, EdDSA, ML-DSA)
 * @intro The key-material lifecycle: export / import a private key as PKCS#8 (`OneAsymmetricKey`,
 *   RFC 5958) or a public key as SPKI (RFC 5280 sec. 4.1.2.7), encrypt / decrypt a private key under
 *   RFC 8018 PBES2 (`EncryptedPrivateKeyInfo`, PBKDF2 + AES-CBC-Pad), and `generate` /
 *   `publicFromPrivate` over every algorithm the WebCrypto engine drives: RSA, EC, Ed25519/Ed448,
 *   X25519/X448, and the FIPS post-quantum ML-DSA / ML-KEM. Unencrypted export / import DELEGATES to the
 *   WebCrypto `exportKey` / `importKey` PKCS#8 / SPKI encoders (which already emit each algorithm's
 *   `AlgorithmIdentifier.parameters` correctly: RSA NULL, EC namedCurve, Ed/X ABSENT), so the wrapper
 *   never re-encodes an AlgorithmIdentifier. PBES2 encrypt / decrypt composes the one shared `lib/pbes2.js`
 *   home (the same PBKDF2 + AES-CBC primitives `pki.cms` uses). Parsing lives at `pki.schema.pkcs8.parse`.
 * @spec RFC 5958, RFC 8018, RFC 5280
 * @card Export / import PKCS#8 and SPKI keys and encrypt a private key under RFC 8018 PBES2.
 */

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var pbes2 = require("./pbes2");
var pkcs8 = require("./schema-pkcs8");
var pkix = require("./schema-pkix");
var webcrypto = require("./webcrypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");

var b = asn1.build;
var subtle = webcrypto.webcrypto.subtle;
var KeyError = frameworkError.KeyError;
var PemError = frameworkError.PemError;
function O(n) { return oid.byName(n); }
function _err(code, msg, cause) { return new KeyError(code, msg, cause); }

var CIPHER_NAME = Object.assign(Object.create(null), { "aes-128-cbc": "aes128-CBC", "aes-192-cbc": "aes192-CBC", "aes-256-cbc": "aes256-CBC" });

var INFER_ALG = {};
["Ed25519", "Ed448", "X25519", "X448"].forEach(function (n) { INFER_ALG[O(n)] = { name: n }; });
[["id-ml-dsa-44", "ML-DSA-44"], ["id-ml-dsa-65", "ML-DSA-65"], ["id-ml-dsa-87", "ML-DSA-87"],
 ["id-ml-kem-512", "ML-KEM-512"], ["id-ml-kem-768", "ML-KEM-768"], ["id-ml-kem-1024", "ML-KEM-1024"]
].forEach(function (r) { INFER_ALG[O(r[0])] = { name: r[1] }; });
["sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
 "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"
].forEach(function (s) { INFER_ALG[O("id-slh-dsa-" + s)] = { name: ("SLH-DSA-" + s).toUpperCase() }; });

function _isCryptoKey(x) { return webcrypto.isCryptoKeyLike(x); }
function _algName(a) { return typeof a === "string" ? a : (a && a.name); }

async function _toPrivateKeyDer(input) {
  if (_isCryptoKey(input)) {
    if (input.type !== "private") throw _err("key/bad-input", "a private CryptoKey is required (got a " + input.type + " key)");
    return webcrypto.exportAnyKey(input, _err, "key/bad-input");
  }
  return pkix.coerceToDer(input, { pemLabel: "PRIVATE KEY", PemError: PemError, ErrorClass: KeyError, prefix: "key" });
}

/**
 * @primitive pki.key.encrypt
 * @signature pki.key.encrypt(privateKey, password, opts?) -> Promise<Buffer|string>
 * @since 0.3.10
 * @status stable
 * @spec RFC 5958 sec. 3, RFC 8018
 * @related pki.key.decrypt, pki.schema.pkcs8.parseEncrypted, pki.cms.encrypt
 *
 * Encrypt a PKCS#8 private key into an RFC 5958 `EncryptedPrivateKeyInfo` under RFC 8018 PBES2 (PBKDF2 +
 * AES-CBC-Pad). `privateKey` is a DER `Buffer`, a `PRIVATE KEY` PEM string, or an extractable private
 * `CryptoKey`; `password` is a string (UTF-8-encoded, byte-identical to OpenSSL), `Buffer`, or `Uint8Array`.
 * The plaintext is the DER `PrivateKeyInfo`, validated as a well-formed PKCS#8 structure before encryption
 * (never encrypt opaque bytes), and the produced `EncryptedPrivateKeyInfo` is re-parsed before return.
 *
 * The PBKDF2 `prf` equal to the default (`hmacWithSHA1`) is omitted from the parameters (X.690 sec. 11.5),
 * `keyLength` is omitted (the AES cipher OID fixes the key size), and the salt / iteration count are bounded,
 * so the output is byte-exact with OpenSSL's `pkcs8 -topk8 -v2`. A bad input throws a typed `KeyError`.
 *
 * @opts
 *   - `cipher` (string) -- `aes-256-cbc` (default), `aes-192-cbc`, or `aes-128-cbc`.
 *   - `prf` (string) -- `hmacWithSHA256` (default), `hmacWithSHA384`, `hmacWithSHA512`, or `hmacWithSHA1`.
 *   - `iterations` (number) -- PBKDF2 iteration count, default 600000 (bounded by the decryptor's cap).
 *   - `salt` (Buffer) -- an explicit PBKDF2 salt (default 16 random octets).
 *   - `pem` (boolean) -- return an `ENCRYPTED PRIVATE KEY` PEM string instead of DER.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.key.export(pair.privateKey);
 *   var enc = await pki.key.encrypt(der, "s3cr3t", { pem: true });
 *   var back = await pki.key.decrypt(enc, "s3cr3t");
 */
var _ENCRYPT_OPTS = { cipher: 1, iterations: 1, pem: 1, prf: 1, salt: 1 };

async function encrypt(privateKey, password, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "key/bad-input", "pki.key.encrypt options");
  guard.identifier.assertKnownKeys(opts, _ENCRYPT_OPTS, _err, "key/bad-input",
    "pki.key.encrypt has an unknown option (the PBKDF2 count here is `iterations`; " +
    "`maxIterations` is the decrypt-side cap): ");
  var der = await _toPrivateKeyDer(privateKey);
  try { pkcs8.parse(der); } catch (e) { throw _err("key/bad-input", "the private key is not a well-formed PKCS#8 PrivateKeyInfo", e); }
  if (opts.cipher != null && typeof opts.cipher !== "string") throw _err("key/bad-input", "unsupported cipher " + guard.text.showValue(opts.cipher) + " (aes-128-cbc / aes-192-cbc / aes-256-cbc)");
  var cipherName = CIPHER_NAME[opts.cipher || "aes-256-cbc"];
  if (!cipherName) throw _err("key/bad-input", "unsupported cipher " + guard.text.showValue(opts.cipher) + " (aes-128-cbc / aes-192-cbc / aes-256-cbc)");
  var keyBits = pbes2.CONTENT_KEYBITS[O(cipherName)];
  var prf = opts.prf || "hmacWithSHA256";
  var prfNode = pbes2.prfNodeByName(prf, _err, "key");
  var iterations = pbes2.assertIterations(opts.iterations == null ? 600000 : opts.iterations, _err, "key");
  var salt = opts.salt != null ? pbes2.assertSalt(guard.bytes.view(opts.salt, KeyError, "key/bad-input", "salt"), _err, "key") : nodeCrypto.randomBytes(16);
  var iv = nodeCrypto.randomBytes(16);
  var pwK = pbes2.passwordBytesOwned(password, _err, "key");
  var dk;
  try { dk = nodeCrypto.pbkdf2Sync(pwK.bytes, salt, iterations, keyBits / 8, prfNode); }
  finally { if (pwK.owned) guard.secret.zeroize(pwK.bytes, KeyError, "key/bad-input", "the password encoding"); }
  try {
    var ciphertext = pbes2.cbcEncrypt(dk, iv, der, keyBits, KeyError, "key/bad-input");
    var epki = b.sequence([pbes2.pbes2AlgId(salt, iterations, prf, cipherName, iv), b.octetString(ciphertext)]);
    pkcs8.parseEncrypted(epki);
    return opts.pem ? pkcs8.pemEncode(epki, "ENCRYPTED PRIVATE KEY") : epki;
  } finally {
    guard.secret.zeroize(dk, KeyError, "key/bad-input", "the password-derived encryption key");
  }
}

/**
 * @primitive pki.key.decrypt
 * @signature pki.key.decrypt(encrypted, password, opts?) -> Promise<Buffer|string>
 * @since 0.3.10
 * @status stable
 * @spec RFC 5958 sec. 3, RFC 8018 sec. 6.2, RFC 8018 sec. 8
 * @defends pbes2-padding-oracle (CWE-208), pbkdf2-work-dos (CWE-400)
 * @related pki.key.encrypt, pki.schema.pkcs8.parse
 *
 * Decrypt an RFC 5958 `EncryptedPrivateKeyInfo` (DER `Buffer` or `ENCRYPTED PRIVATE KEY` PEM) under RFC 8018
 * PBES2, returning the inner `PrivateKeyInfo` (re-validated via `pki.schema.pkcs8.parse`). Only PBES2 with a
 * PBKDF2 key-derivation function and an AES-CBC encryption scheme is accepted; PBES1, PBMAC1, scrypt, and any
 * other `encryptionAlgorithm` fail closed with `key/unsupported-algorithm`.
 *
 * The salt and iteration count are attacker-controlled work: both caps are enforced before any derivation
 * (`opts.maxIterations` may lower the cap, never raise it), and a wrong-length IV or malformed parameter set
 * is a typed `key/bad-algorithm-parameters`. A MAC-less PBES2-CBC decrypt is not a padding oracle: a wrong
 * password and a valid-pad-but-not-a-PrivateKeyInfo both surface the single uniform `key/decrypt-failed`.
 *
 * @opts
 *   - `maxIterations` (number) -- lower the PBKDF2 iteration cap for this decrypt (downward-only).
 *   - `pem` (boolean) -- return a `PRIVATE KEY` PEM string instead of DER.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var enc = await pki.key.encrypt(await pki.key.export(pair.privateKey), "s3cr3t", { pem: true });
 *   var der = await pki.key.decrypt(enc, "s3cr3t");
 */
var _DECRYPT_OPTS = { maxIterations: 1, pem: 1 };

async function decrypt(encrypted, password, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "key/bad-input", "pki.key.decrypt options");
  guard.identifier.assertKnownKeys(opts, _DECRYPT_OPTS, _err, "key/bad-input",
    "pki.key.decrypt has an unknown option (the PBKDF2 cap here is `maxIterations`; " +
    "`iterations` is the encrypt-side count): ");
  if (opts.maxIterations != null && (typeof opts.maxIterations !== "number" || !isFinite(opts.maxIterations) || opts.maxIterations < 1 || Math.floor(opts.maxIterations) !== opts.maxIterations)) {
    throw _err("key/bad-input", "maxIterations must be a positive integer");
  }
  var input = pkix.coerceToDer(encrypted, { pemLabel: "ENCRYPTED PRIVATE KEY", PemError: PemError, ErrorClass: KeyError, prefix: "key" });
  var epki;
  try { epki = pkcs8.parseEncrypted(input); }
  catch (e) { throw _err("key/bad-input", "the input is not a well-formed EncryptedPrivateKeyInfo", e); }
  var encAlg = epki.encryptionAlgorithm;
  if (encAlg.oid !== O("pbes2")) throw _err("key/unsupported-algorithm", "unsupported key encryption algorithm " + (encAlg.name || encAlg.oid) + " (only RFC 8018 PBES2 is supported)");
  var plaintext = _decryptPbes2(encAlg, epki.encryptedData, password, opts);
  return opts.pem ? pkcs8.pemEncode(plaintext, "PRIVATE KEY") : plaintext;
}

function _decryptPbes2(encAlg, ciphertext, password, opts) {
  var pwD = pbes2.passwordBytesOwned(password, _err, "key");
  var plaintext;
  try { plaintext = pbes2.pbes2Decrypt(pwD.bytes, encAlg.parameters, ciphertext, opts, _err, "key"); }
  finally { if (pwD.owned) guard.secret.zeroize(pwD.bytes, KeyError, "key/bad-input", "the password encoding"); }
  try { pkcs8.parse(plaintext); }
  catch (_e) { throw _err("key/decrypt-failed", "decryption failed"); }
  return plaintext;
}

/**
 * @primitive pki.key.export
 * @signature pki.key.export(key, opts?) -> Promise<Buffer|string>
 * @since 0.3.10
 * @status stable
 * @spec RFC 5958, RFC 5280 sec. 4.1.2.7, RFC 8410 sec. 3
 * @related pki.key.import, pki.key.publicFromPrivate, pki.schema.pkcs8.parse
 *
 * Export an extractable `CryptoKey` to DER (or PEM): a private key as PKCS#8 `OneAsymmetricKey`, a public
 * key as SubjectPublicKeyInfo. The encoding is delegated to the WebCrypto `exportKey` PKCS#8 / SPKI encoder,
 * so the algorithm-specific `AlgorithmIdentifier.parameters` are byte-correct: RSA carries an explicit
 * NULL, EC a namedCurve OID, and Ed25519 / Ed448 / X25519 / X448 omit parameters (RFC 8410 sec. 3); the
 * wrapper never re-encodes the AlgorithmIdentifier.
 *
 * The key need not have been created by this toolkit's own WebCrypto: one from the platform's, or from a
 * separately-installed copy of this toolkit, is exported through whichever of them holds its material.
 * A key created non-extractable is refused with that as the reason,
 * as is one whose implementation keeps its material out of this process's reach entirely.
 *
 * @opts
 *   - `format` (string) -- `der` (default) or `pem`.
 *   - `label` (string) -- the PEM label (defaults `PRIVATE KEY` / `PUBLIC KEY` by key type).
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spkiPem = await pki.key.export(pair.publicKey, { format: "pem" });
 */
var _EXPORT_OPTS = { format: 1, label: 1 };

async function export_(key, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "key/bad-input", "pki.key.export options");
  guard.identifier.assertKnownKeys(opts, _EXPORT_OPTS, _err, "key/bad-input",
    "pki.key.export has an unknown option. It serializes only. To protect a private key, call " +
    "pki.key.encrypt(key, password) first and export its result. The unknown option was: ");
  if (!_isCryptoKey(key)) throw _err("key/bad-input", "export expects a WebCrypto CryptoKey");
  var defaultLabel;
  if (key.type === "private") defaultLabel = "PRIVATE KEY";
  else if (key.type === "public") defaultLabel = "PUBLIC KEY";
  else throw _err("key/bad-input", "export supports asymmetric (private / public) CryptoKeys only");
  var der = await webcrypto.exportAnyKey(key, _err, "key/bad-input");
  var fmt = opts.format || "der";
  if (fmt === "der") return der;
  if (fmt === "pem") return pkix.pemEncode(der, opts.label || defaultLabel, PemError);
  throw _err("key/bad-input", "unsupported format " + guard.text.showValue(opts.format) + " (der / pem)");
}

/**
 * @primitive pki.key.import
 * @signature pki.key.import(input, opts?) -> Promise<CryptoKey>
 * @since 0.3.10
 * @status stable
 * @spec RFC 5958, RFC 5280 sec. 4.1.2.7, RFC 8018
 * @related pki.key.export, pki.key.decrypt
 *
 * Import a DER / PEM PKCS#8 private key, SPKI public key, or (with `opts.password`) an `ENCRYPTED PRIVATE
 * KEY`, auto-detecting the structure, into a `CryptoKey`. The WebCrypto algorithm is inferred from the
 * key's OID for the algorithms that name exactly one (Ed25519 / Ed448 / X25519 / X448 / ML-DSA / ML-KEM /
 * SLH-DSA); RSA and EC are ambiguous between signing and key agreement, so `opts.algorithm` must be supplied
 * for them (without it the import fails closed). Default key usages follow the algorithm and key type.
 *
 * @opts
 *   - `algorithm` (string | object) -- the WebCrypto algorithm (required for RSA / EC; overrides inference).
 *   - `usages` (string[]) -- key usages (default derived from the algorithm and public/private type).
 *   - `extractable` (boolean) -- default false.
 *   - `password` (string | Buffer) -- decrypt an `ENCRYPTED PRIVATE KEY` first.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spki = await pki.key.export(pair.publicKey);
 *   var pub = await pki.key.import(spki);                       // Ed25519 -- algorithm inferred
 */
var _IMPORT_OPTS = { algorithm: 1, extractable: 1, password: 1, usages: 1 };

async function import_(input, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "key/bad-input", "pki.key.import options");
  guard.identifier.assertKnownKeys(opts, _IMPORT_OPTS, _err, "key/bad-input",
    "pki.key.import has an unknown option: ");
  var detected = _detectKeyInput(input);
  if (detected.format === "encrypted") {
    if (opts.password == null) throw _err("key/bad-input", "an ENCRYPTED PRIVATE KEY requires opts.password to import");
    detected = { format: "pkcs8", der: await decrypt(detected.der, opts.password) };
  }
  var algorithm = opts.algorithm != null ? opts.algorithm : _inferAlgorithm(detected);
  var isPublic = detected.format === "spki";
  if (opts.usages != null && !Array.isArray(opts.usages)) throw _err("key/bad-input", "opts.usages must be an array of key-usage strings");
  var usages = opts.usages || _importUsages(_algName(algorithm), isPublic);
  var extractable = opts.extractable != null ? opts.extractable : false;
  try {
    return await subtle.importKey(detected.format, detected.der, algorithm, extractable, usages);
  } catch (e) {
    if (e && e.isPkiError) throw e;
    throw _err("key/bad-input", "importKey failed", e);
  }
}

/**
 * @primitive pki.key.generate
 * @signature pki.key.generate(algorithm, opts?) -> Promise<{ privateKey, publicKey }>
 * @since 0.3.10
 * @status stable
 * @spec W3C WebCrypto, FIPS 203, FIPS 204
 * @related pki.key.export, pki.key.publicFromPrivate
 *
 * Generate an asymmetric key pair over the WebCrypto engine: RSA, ECDSA / ECDH, Ed25519 / Ed448, X25519 /
 * X448, and the FIPS post-quantum ML-DSA / ML-KEM. `algorithm` is a WebCrypto algorithm string or object;
 * usages default to the algorithm's natural set (sign/verify, deriveBits/deriveKey, or encapsulate/
 * decapsulate) and keys are extractable by default. Returns the `{ privateKey, publicKey }` `CryptoKey` pair.
 *
 * @opts
 *   - `extractable` (boolean) -- default true.
 *   - `usages` (string[]) -- override the default key usages.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var pkcs8 = await pki.key.export(pair.privateKey);
 */
var _GENERATE_OPTS = { extractable: 1, usages: 1 };

async function generate(algorithm, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "key/bad-input", "pki.key.generate options");
  guard.identifier.assertKnownKeys(opts, _GENERATE_OPTS, _err, "key/bad-input",
    "pki.key.generate has an unknown option (the WebCrypto spelling is `extractable`): ");
  var extractable = opts.extractable != null ? opts.extractable : true;
  if (opts.usages != null && !Array.isArray(opts.usages)) throw _err("key/bad-input", "opts.usages must be an array of key-usage strings");
  var usages = opts.usages || _generateUsages(_algName(algorithm));
  var pair;
  try { pair = await subtle.generateKey(algorithm, extractable, usages); }
  catch (e) { if (e && e.isPkiError) throw e; throw _err("key/bad-input", "generateKey failed", e); }
  if (!pair || !pair.privateKey || !pair.publicKey) throw _err("key/bad-input", "the algorithm does not generate an asymmetric key pair");
  return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

/**
 * @primitive pki.key.publicFromPrivate
 * @signature pki.key.publicFromPrivate(privateKey, opts?) -> Promise<Buffer|string>
 * @since 0.3.10
 * @status stable
 * @spec RFC 5280 sec. 4.1.2.7, RFC 8410 sec. 3
 * @related pki.key.export, pki.key.import
 *
 * Derive the SubjectPublicKeyInfo (SPKI) public key from a PKCS#8 private key (DER `Buffer`, `PRIVATE KEY`
 * PEM, or extractable private `CryptoKey`). The derivation is delegated to the node key engine, which infers
 * the algorithm from the key structure, so no `AlgorithmIdentifier` is re-encoded: Ed25519 stays
 * parameters-absent, RSA keeps its NULL, EC keeps its namedCurve.
 *
 * @opts
 *   - `pem` (boolean) -- return a `PUBLIC KEY` PEM string instead of DER.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spki = await pki.key.publicFromPrivate(await pki.key.export(pair.privateKey));
 */
var _PUBLIC_FROM_PRIVATE_OPTS = { pem: 1 };

async function publicFromPrivate(privateKey, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "key/bad-input", "pki.key.publicFromPrivate options");
  guard.identifier.assertKnownKeys(opts, _PUBLIC_FROM_PRIVATE_OPTS, _err, "key/bad-input",
    "pki.key.publicFromPrivate has an unknown option: ");
  var der = await _toPrivateKeyDer(privateKey);
  var spki;
  try {
    var priv = nodeCrypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    spki = nodeCrypto.createPublicKey(priv).export({ format: "der", type: "spki" });
  } catch (e) { throw _err("key/bad-input", "could not derive the public key from the private key", e); }
  return opts.pem ? pkix.pemEncode(spki, "PUBLIC KEY", PemError) : spki;
}


function _detectKeyInput(input) {
  var der = pkix.coerceToDer(input, { pemLabel: null, PemError: PemError, ErrorClass: KeyError, prefix: "key" });
  var root;
  try { root = asn1.decode(der); } catch (e) { throw _err("key/bad-input", "the input is not DER or a PEM key", e); }
  var kids = root.children || [];
  if (kids.length >= 1 && kids[0].tagClass === "universal" && kids[0].tagNumber === asn1.TAGS.INTEGER) return { format: "pkcs8", der: der };
  if (kids.length === 2 && kids[1].tagClass === "universal" && kids[1].tagNumber === asn1.TAGS.BIT_STRING) return { format: "spki", der: der };
  if (kids.length === 2 && kids[1].tagClass === "universal" && kids[1].tagNumber === asn1.TAGS.OCTET_STRING) return { format: "encrypted", der: der };
  throw _err("key/bad-input", "the input is not a recognized PKCS#8, SPKI, or EncryptedPrivateKeyInfo");
}

function _readAlgOid(detected) {
  try {
    if (detected.format === "pkcs8") return pkcs8.parse(detected.der).privateKeyAlgorithm.oid;
    var alg = asn1.decode(detected.der).children[0];
    if (!alg || alg.tagClass !== "universal" || alg.tagNumber !== asn1.TAGS.SEQUENCE || !alg.children || !alg.children.length) {
      throw _err("key/bad-input", "malformed SubjectPublicKeyInfo algorithm identifier");
    }
    return asn1.read.oid(alg.children[0]);
  } catch (e) {
    if (e instanceof KeyError) throw e;
    throw _err("key/bad-input", "the key algorithm could not be read for inference", e);
  }
}

function _inferAlgorithm(detected) {
  var algOid = _readAlgOid(detected);
  var a = INFER_ALG[algOid];
  if (a) return a;
  throw _err("key/unsupported-algorithm", "cannot infer the WebCrypto algorithm for " + (oid.name(algOid) || algOid) +
    " (RSA and EC are ambiguous between signing and key agreement -- pass opts.algorithm)");
}

function _importUsages(name, isPublic) {
  var n = String(name == null ? "" : name).toUpperCase();
  if (n === "X25519" || n === "X448" || n === "ECDH") return isPublic ? [] : ["deriveBits", "deriveKey"];
  if (n.indexOf("ML-KEM") === 0) return isPublic ? ["encapsulateBits"] : ["decapsulateBits"];
  if (n === "RSA-OAEP") return isPublic ? ["encrypt"] : ["decrypt"];
  return isPublic ? ["verify"] : ["sign"];
}

function _generateUsages(name) {
  var n = String(name == null ? "" : name).toUpperCase();
  if (n === "X25519" || n === "X448" || n === "ECDH") return ["deriveBits", "deriveKey"];
  if (n.indexOf("ML-KEM") === 0) return ["encapsulateBits", "decapsulateBits"];
  if (n === "RSA-OAEP") return ["encrypt", "decrypt"];
  return ["sign", "verify"];
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt,
  export: export_,
  import: import_,
  generate: generate,
  publicFromPrivate: publicFromPrivate,
};
