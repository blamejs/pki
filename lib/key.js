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
var constants = require("./constants");
var oid = require("./oid");
var pbes2 = require("./pbes2");
var pkcs8 = require("./schema-pkcs8");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
var webcrypto = require("./webcrypto");
var compositeKem = require("./composite-kem");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _assign = intrinsic.assign;
var _create = intrinsic.create;
var _keyEquals = intrinsic.uncurry(nodeCrypto.KeyObject.prototype.equals);
var _isArray = intrinsic.isArray;
var _bufferFrom = intrinsic.bufferFrom;
var _floor = intrinsic.floor;
var _isFinite = intrinsic.isFinite;
var _String = intrinsic.String;
var _toUpperCase = intrinsic.toUpperCase;
var _strIndexOf = intrinsic.stringIndexOf;

var b = asn1.build;
var subtle = webcrypto.webcrypto.subtle;
var KeyError = frameworkError.KeyError;
var PemError = frameworkError.PemError;
function O(n) { return oid.byName(n); }
function _err(code, msg, cause) { return new KeyError(code, msg, cause); }

var CIPHER_NAME = _assign(_create(null), { "aes-128-cbc": "aes128-CBC", "aes-192-cbc": "aes192-CBC", "aes-256-cbc": "aes256-CBC" });

var INFER_ALG = _create(null);
["Ed25519", "Ed448", "X25519", "X448"].forEach(function (n) { INFER_ALG[O(n)] = { name: n }; });
[["id-ml-dsa-44", "ML-DSA-44"], ["id-ml-dsa-65", "ML-DSA-65"], ["id-ml-dsa-87", "ML-DSA-87"],
 ["id-ml-kem-512", "ML-KEM-512"], ["id-ml-kem-768", "ML-KEM-768"], ["id-ml-kem-1024", "ML-KEM-1024"]
].forEach(function (r) { INFER_ALG[O(r[0])] = { name: r[1] }; });
["sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
 "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f"
].forEach(function (s) { INFER_ALG[O("id-slh-dsa-" + s)] = { name: _toUpperCase("SLH-DSA-" + s) }; });

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
var _ENCRYPT_OPTS = _assign(_create(null), { cipher: 1, iterations: 1, pem: 1, prf: 1, salt: 1 });

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
var _DECRYPT_OPTS = _assign(_create(null), { maxIterations: 1, pem: 1 });

async function decrypt(encrypted, password, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "key/bad-input", "pki.key.decrypt options");
  guard.identifier.assertKnownKeys(opts, _DECRYPT_OPTS, _err, "key/bad-input",
    "pki.key.decrypt has an unknown option (the PBKDF2 cap here is `maxIterations`; " +
    "`iterations` is the encrypt-side count): ");
  if (opts.maxIterations != null && (typeof opts.maxIterations !== "number" || !_isFinite(opts.maxIterations) || opts.maxIterations < 1 || _floor(opts.maxIterations) !== opts.maxIterations)) {
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
var _EXPORT_OPTS = _assign(_create(null), { format: 1, label: 1 });

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
var _IMPORT_OPTS = _assign(_create(null), { algorithm: 1, extractable: 1, password: 1, usages: 1 });

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
  if (opts.usages != null && !_isArray(opts.usages)) throw _err("key/bad-input", "opts.usages must be an array of key-usage strings");
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
var _GENERATE_OPTS = _assign(_create(null), { extractable: 1, usages: 1 });

async function generate(algorithm, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "key/bad-input", "pki.key.generate options");
  guard.identifier.assertKnownKeys(opts, _GENERATE_OPTS, _err, "key/bad-input",
    "pki.key.generate has an unknown option (the WebCrypto spelling is `extractable`): ");
  var extractable = opts.extractable != null ? opts.extractable : true;
  if (opts.usages != null && !_isArray(opts.usages)) throw _err("key/bad-input", "opts.usages must be an array of key-usage strings");
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
 * @spec RFC 5280 sec. 4.1.2.7, RFC 8410 sec. 3, draft-ietf-lamps-pq-composite-kem sec. 4.1
 * @related pki.key.export, pki.key.import
 *
 * Derive the SubjectPublicKeyInfo (SPKI) public key from a PKCS#8 private key (DER `Buffer`, `PRIVATE KEY`
 * PEM, or extractable private `CryptoKey`). The derivation is delegated to the node key engine, which infers
 * the algorithm from the key structure, so no `AlgorithmIdentifier` is re-encoded: Ed25519 stays
 * parameters-absent, RSA keeps its NULL, EC keeps its namedCurve.
 *
 * A composite ML-KEM key is derived from its two components instead, since the node key engine does not
 * read a composite algorithm. The private key is `seed || tradSK` and the public key is
 * `mlkemEK || tradPK` under the same OID: the seed states the ML-KEM encapsulation key it generates, the
 * traditional half states its own public key, and the two are concatenated. An AlgorithmIdentifier
 * carrying parameters, a key no longer than the ML-KEM seed, and an unregistered composite OID are each
 * refused with a typed `KemError`.
 *
 * @opts
 *   - `pem` (boolean) -- return a `PUBLIC KEY` PEM string instead of DER.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var spki = await pki.key.publicFromPrivate(await pki.key.export(pair.privateKey));
 */
var _PUBLIC_FROM_PRIVATE_OPTS = _assign(_create(null), { pem: 1 });

/** @internal The composite ML-KEM OID a private key names, or null when it names anything else. Read
 * from the AlgorithmIdentifier alone: a key that is not well formed enough to state one is left to the
 * decoder below, which reports it. */
function _compositeKemOidOf(der) {
  var algOid = _algorithmOidAt(der, 1);
  return algOid !== null && compositeKem.isCompositeKem(algOid) ? algOid : null;
}

/** @internal The AlgorithmIdentifier OID a key structure names, read without the structure's strict
 * rules: `at` 1 for a OneAsymmetricKey (version first), 0 for a SubjectPublicKeyInfo. A structure that
 * cannot state one yields null and is left to the decoder that reports it. Reading loosely matters for
 * a composite key: one that breaks a OneAsymmetricKey rule is still a composite key, and the module
 * that owns the algorithm is the one that should say so, since the runtime decoder would report that
 * it cannot read the key rather than that the parameters are not allowed (draft sec. 5.3). */
function _algorithmOidAt(der, at) {
  var algOid;
  try {
    var node = asn1.decode(der);
    if (!node.children || node.children.length <= at) return null;
    var alg = node.children[at];
    if (!alg.children || alg.children.length < 1) return null;
    algOid = asn1.read.oid(alg.children[0]);
  } catch (_e) { return null; } // allow:swallow-unverified a structure that states no algorithm is refused by the decoder it stands before
  return typeof algOid === "string" ? algOid : null;
}

var _OID_DH_X942 = oid.byName("dhpublicnumber");
var _OID_DH_PKCS3 = oid.byName("dhKeyAgreement");
var _isUniversal = schema.isUniversal;

/** @internal Whether an algorithm identifier names a finite-field Diffie-Hellman key in either of
 * its encodings. */
function _isDhOid(algOid) {
  return algOid === _OID_DH_X942 || algOid === _OID_DH_PKCS3;
}

/** @internal ValidationParms is SEQUENCE { seed BIT STRING, pgenCounter INTEGER } (RFC 3279
 * sec. 2.3.3). The conversion drops it, so reading it is the only thing that answers for it: a key
 * whose parameters do not hold the two fields is malformed rather than merely carrying something the
 * conversion does not need, and the counter is the count of a generation procedure, so a negative
 * one is malformed too. */
function _validationParms(node, ErrorClass, code, what) {
  var kids = node.children;
  if (!_isUniversal(node, 16) || !kids || kids.length !== 2 ||
      !_isUniversal(kids[0], 3) || !_isUniversal(kids[1], 2)) {
    throw new ErrorClass(code, what + " X9.42 validationParms is not a seed BIT STRING with a pgenCounter INTEGER");
  }
  asn1.read.bitString(kids[0]);
  if (asn1.read.integer(kids[1]) < 0n) {
    throw new ErrorClass(code, what + " X9.42 validationParms states a negative pgenCounter");
  }
}

/** @internal The p, g, q and cofactor an X9.42 DomainParameters states. DomainParameters is
 * SEQUENCE { p, g, q, j OPTIONAL, validationParms OPTIONAL } (RFC 3279 sec. 2.3.3), and the PKCS #3
 * form the runtime classifies carries none of the last three, so every field is read HERE, before
 * the conversion that drops it. Both halves of a finite-field key carry this structure and both take
 * that conversion, so both read it in this one place: a field read on one side and skipped on the
 * other is a key refused in the encoding it was handed and admitted in the one it was rewritten
 * into. The algorithm named dhpublicnumber, so these bytes are DomainParameters or the key is
 * malformed; there is no third reading that would let a shape this does not recognize travel on.
 * Errors are the caller's: `new ErrorClass(code, message)`, the message led by `what`. */
function x942Domain(paramsNode, ErrorClass, code, what) {
  var domain = asn1.decode(paramsNode.bytes);
  if (!_isUniversal(domain, 16) || !domain.children ||
      domain.children.length < 3 || domain.children.length > 5) {
    throw new ErrorClass(code, what + " X9.42 domain parameters are not a DomainParameters SEQUENCE of p, g and q with at most two optional fields after them");
  }
  var out = {
    p: asn1.read.integer(domain.children[0]),
    g: asn1.read.integer(domain.children[1]),
    q: asn1.read.integer(domain.children[2]),
    j: null,
  };
  /** @internal j and validationParms are independently optional, so a fourth field is told apart by
   * its tag rather than by its position: an INTEGER is the cofactor and a SEQUENCE is the validation
   * parameters, which may appear with no cofactor before them. */
  if (domain.children.length >= 4) {
    var opt = domain.children[3];
    if (_isUniversal(opt, 2)) {
      out.j = asn1.read.integer(opt);
      if (domain.children.length === 5) _validationParms(domain.children[4], ErrorClass, code, what);
    } else if (_isUniversal(opt, 16)) {
      if (domain.children.length === 5) {
        throw new ErrorClass(code, what + " X9.42 domain parameters carry a field after validationParms");
      }
      _validationParms(opt, ErrorClass, code, what);
    } else {
      throw new ErrorClass(code, what + " X9.42 domain parameters carry a fourth field that is neither a cofactor nor validationParms");
    }
  }
  return out;
}

/** @internal One past the largest Diffie-Hellman operand the toolkit computes with: the largest group
 * it agrees over. Built once, as two raised to a count of BITS, so the bound states the width it is
 * named for. */
var _DH_MAX = (function () {
  var v = 1n;
  for (var i = 0; i < 8 * constants.LIMITS.DH_MAX_MODULUS_BYTES; i++) v <<= 1n;
  return v;
}());

/** @internal Whether every Diffie-Hellman operand in `values` (a null is an absent one) is below the
 * largest group the toolkit agrees over. The tests whose cost grows with the operands, a modular
 * exponentiation and a primality proof, run only after this has answered; a path that reads a key
 * without bounding its size, such as one that archives rather than agrees, does not ask it. Errors
 * are the caller's, as in `x942Domain`. */
function assertDhOperandsWithin(values, ErrorClass, code, what) {
  for (var i = 0; i < values.length; i++) {
    if (values[i] !== null && values[i] >= _DH_MAX) {
      throw new ErrorClass(code, what + " parameters are larger than any Diffie-Hellman group this toolkit agrees over (" +
        constants.LIMITS.DH_MAX_MODULUS_BYTES + " bytes)");
    }
  }
}

/** @internal base to the power exp, modulo mod, by square-and-multiply on BigInts. */
function modPow(base, exp, mod) {
  var result = 1n, b = base % mod, e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

/** @internal Whether a stated order is one g has: g raised to q is 1 modulo p, which says the order
 * of g divides q. This is one modular exponentiation, so it is asked only of operands already bounded
 * by `assertDhOperandsWithin`, and after `assertDhDomainCoherent` has answered the cheaper questions.
 * Whether q IS the order rather than a multiple of it is `assertDhOrderPrime`. Errors are the
 * caller's. */
function assertDhGeneratorOrder(p, g, q, ErrorClass, code, what) {
  if (modPow(g, q, p) !== 1n) {
    throw new ErrorClass(code, what + " X9.42 domain parameters state a subgroup order its own p and g do not have");
  }
}

/** @internal Whether a value is prime, by the runtime's test, remembered across calls. Proving a
 * 4096-bit modulus prime costs seconds, and the question is asked of the same group every time:
 * a certifying authority's parameters do not change between the keys it issues, and an enrollment
 * run asks it of the same group per request. What is remembered is a fact about a number rather
 * than anything a caller supplied, so a hit is the same answer the test would give. The map is
 * capped and cleared wholesale when it fills, which bounds it without giving a caller a way to
 * decide what stays. Asked only of operands already bounded by `assertDhOperandsWithin`. */
var _PRIME_MEMO = new intrinsic.Map();
var _PRIME_MEMO_N = 0;
var _checkPrimeSync = nodeCrypto.checkPrimeSync;

function isPrime(n) {
  var hit = intrinsic.mapGet(_PRIME_MEMO, n);
  if (hit !== undefined) return hit;
  var answer = _checkPrimeSync(_bigToBuf(n));
  if (_PRIME_MEMO_N >= constants.LIMITS.DH_PRIME_MEMO_ENTRIES) {
    _PRIME_MEMO = new intrinsic.Map();
    _PRIME_MEMO_N = 0;
  }
  intrinsic.mapSet(_PRIME_MEMO, n, answer);
  _PRIME_MEMO_N++;
  return answer;
}

/** @internal A non-negative BigInt as the big-endian bytes the runtime's primality test reads. */
function _bigToBuf(n) {
  var len = 0, v = n;
  while (v > 0n) { len++; v >>= 8n; }
  if (len === 0) len = 1;
  var buf = intrinsic.bufferAlloc(len);
  v = n;
  for (var i = len - 1; i >= 0; i--) { buf[i] = intrinsic.Number(v & 0xffn); v >>= 8n; }
  return buf;
}

/** @internal Whether a Diffie-Hellman modulus is prime; a composite one describes no group. */
function assertDhModulusPrime(p, ErrorClass, code, what) {
  if (!isPrime(p)) {
    throw new ErrorClass(code, what + " Diffie-Hellman modulus is not prime, so the group its parameters describe does not exist");
  }
}

/** @internal Whether a public value lies in the subgroup its parameters state: y raised to q is 1
 * modulo p. A value outside it agrees a secret that exposes the private exponent of whichever side
 * agrees, modulo the small order the value does have. One modular exponentiation, asked of bounded
 * operands after the order itself was proven. Errors are the caller's. */
function assertDhValueInSubgroup(p, q, y, ErrorClass, code, what) {
  if (modPow(y, q, p) !== 1n) {
    throw new ErrorClass(code, what + " Diffie-Hellman public value is not in the subgroup its own domain parameters state, so agreeing with it would expose the private exponent of whichever side agrees");
  }
}

/** @internal Whether a stated subgroup order is prime. `assertDhGeneratorOrder` proved the order of
 * g divides q; only a prime q makes that order exactly q, so a q that is a multiple of the order
 * (p-1 beside a g of order (p-1)/2 satisfies g^q = 1) names a subgroup the key need not have. */
function assertDhOrderPrime(q, ErrorClass, code, what) {
  if (!isPrime(q)) {
    throw new ErrorClass(code, what + " X9.42 domain parameters state a subgroup order that is not prime, so a public value in it need not have that order");
  }
}

/** @internal Whether a stated order and cofactor describe the p and g stated beside them. These are
 * the tests that answer that question with a comparison, a multiplication and a modulo, so their cost
 * grows gently with the modulus and every path that reads these parameters can afford them, bounded
 * or not; the tests whose cost grows with the modulus, a modular exponentiation and two primality
 * proofs, are asked separately of bounded operands. A cofactor states (p-1)/q, so a cofactor with no
 * order beside it states nothing. Errors are the caller's, as in `x942Domain`. */
function assertDhDomainCoherent(p, g, q, j, ErrorClass, code, what) {
  if (p <= 2n || g <= 1n || g >= p - 1n) {
    throw new ErrorClass(code, what + " parameters are not a Diffie-Hellman group");
  }
  /** @internal Each operand's sign is decided before the multiplication and the modulo that take it:
   * a bound on these is an upper one, and a negative order or cofactor of any width would otherwise
   * be multiplied before it is refused. */
  if (j !== null && (q === null || j <= 0n || q <= 0n || j * q !== p - 1n)) {
    throw new ErrorClass(code, what + " X9.42 cofactor does not match its own p and q");
  }
  if (q !== null && (q <= 1n || (p - 1n) % q !== 0n)) {
    throw new ErrorClass(code, what + " X9.42 domain parameters state a subgroup order its own p and g do not have");
  }
}

/** @internal The p and g a PKCS #3 DHParameter states, read strictly. DHParameter is SEQUENCE
 * { prime, base, privateValueLength OPTIONAL } (PKCS #3 sec. 9); the one optional field is an
 * INTEGER stating how many bits the private value has, so it is a positive count no longer than the
 * modulus's own bit count, which the encoded size bounds before anything is shifted by it, since
 * the codec admits an INTEGER at any width and a caller that archives a key does not bound its
 * modulus. Errors are the caller's, as in `x942Domain`. */
function _dhParameter(paramsNode, ErrorClass, code, what) {
  var prm = asn1.decode(paramsNode.bytes);
  if (!_isUniversal(prm, 16) || !prm.children || prm.children.length < 2 || prm.children.length > 3) {
    throw new ErrorClass(code, what + " PKCS#3 Diffie-Hellman parameters are not a DHParameter SEQUENCE");
  }
  var p = asn1.read.integer(prm.children[0]);
  if (prm.children.length === 3) {
    if (!_isUniversal(prm.children[2], 2)) {
      throw new ErrorClass(code, what + " PKCS#3 privateValueLength is not an INTEGER");
    }
    var pvl = asn1.read.integer(prm.children[2]);
    if (pvl <= 0n) {
      throw new ErrorClass(code, what + " PKCS#3 privateValueLength is not a positive length");
    }
    if (pvl > intrinsic.BigInt(prm.children[0].bytes.length) * 8n || (1n << (pvl - 1n)) > p) {
      throw new ErrorClass(code, what + " PKCS#3 privateValueLength states a private value longer than its own modulus, which no value in the group is");
    }
  }
  return { p: p, g: asn1.read.integer(prm.children[1]) };
}

/** @internal The p, g and public value of a PKCS #3 dhKeyAgreement SubjectPublicKeyInfo, or null
 * when the key is not in that form. The parameters state no subgroup order, so the group they
 * describe is checked without one. A structure that names the algorithm and cannot be read as the
 * key is refused in the caller's class. */
function pkcs3Params(spkiBytes, ErrorClass, code, what) {
  if (_algorithmOidAt(spkiBytes, 0) !== _OID_DH_PKCS3) return null;
  var node = asn1.decode(spkiBytes);
  try {
    var alg = node.children[0];
    if (!alg.children || alg.children.length !== 2 || node.children.length !== 2) {
      throw new ErrorClass(code, what + " PKCS#3 Diffie-Hellman key is not an AlgorithmIdentifier with parameters and a public key");
    }
    var dom = _dhParameter(alg.children[1], ErrorClass, code, what);
    var pub = asn1.read.bitString(node.children[1]);
    if (!guard.crypto.isOctetAligned(pub)) {
      throw new ErrorClass(code, what + " Diffie-Hellman public key BIT STRING must be octet-aligned (0 unused bits)");
    }
    return { p: dom.p, g: dom.g, y: asn1.read.integer(asn1.decode(pub.bytes)) };
  } catch (e) {
    if (e instanceof ErrorClass) throw e;
    throw new ErrorClass(code, what + " PKCS#3 Diffie-Hellman key could not be read", e);
  }
}

/** @internal The p, g and private exponent of a PKCS #3 dhKeyAgreement PrivateKeyInfo, read to the
 * same shape as its public half; null when the key is not in that form. */
function _pkcs3Private(der, what) {
  if (_algorithmOidAt(der, 1) !== _OID_DH_PKCS3) return null;
  var node = asn1.decode(der);
  try {
    var alg = node.children[1];
    if (!alg.children || alg.children.length !== 2 || !node.children[2]) {
      throw _err("key/bad-input", what + " PKCS#3 Diffie-Hellman key is not an AlgorithmIdentifier with parameters and a private key");
    }
    var dom = _dhParameter(alg.children[1], KeyError, "key/bad-input", what);
    return { p: dom.p, g: dom.g, x: asn1.read.integer(asn1.decode(asn1.read.octetString(node.children[2]))) };
  } catch (e) {
    if (e instanceof KeyError) throw e;
    throw _err("key/bad-input", what + " PKCS#3 Diffie-Hellman key could not be read", e);
  }
}

/** @internal A Diffie-Hellman structure in the PKCS #3 form (every DH key is one by the time this
 * reads it), held to the toolkit's group bound and to being a group before the runtime imports it:
 * the import derives or compares a public value by modular exponentiation whose cost is the width
 * of p and of the exponent, and a delivered key states any width it likes. So p, g and the value
 * the structure carries (the private exponent at `at` 1, the public value at `at` 0) are capped at
 * the largest group the toolkit agrees over, the cap that every other path computing in a DH group
 * applies; p and g are then held to describing a group and p to being prime, whichever encoding
 * the key arrived in, so a structure the X9.42 rewrite never saw answers the same questions; and a
 * private exponent is held inside its group: at least 1 and below p (RFC 2631 sec. 2.2 narrows it
 * to [2, q-2], which is the agreement's test). Anything that is not a DH structure is left alone. */
function _assertDhWithin(der, at, what) {
  var read = at === 0 ? pkcs3Params(der, KeyError, "key/bad-input", what) : _pkcs3Private(der, what);
  if (read === null) return;
  var value = at === 0 ? read.y : read.x;
  assertDhOperandsWithin([read.p, read.g, value], KeyError, "key/bad-input", what);
  assertDhDomainCoherent(read.p, read.g, null, null, KeyError, "key/bad-input", what);
  assertDhModulusPrime(read.p, KeyError, "key/bad-input", what);
  if (at === 1 && (value <= 0n || value >= read.p)) {
    throw _err("key/bad-input", what + " Diffie-Hellman private exponent is outside its own group");
  }
  if (at === 0 && (value <= 1n || value >= read.p - 1n)) {
    throw _err("key/bad-input", what + " Diffie-Hellman public value is outside the group (RFC 2875 sec. 3)");
  }
}

/** @internal One finite-field Diffie-Hellman key in the encoding the runtime classifies. A certificate
 * names a DH key in the X9.42 form (RFC 3279 sec. 2.3.3: `dhpublicnumber` with DomainParameters
 * { p, g, q, j, validationParms }), while a generated key is written in the PKCS #3 form
 * (`dhKeyAgreement` with DHParameter { p, g, privateValueLength }); both carry the value itself as one
 * INTEGER. The runtime reads the X9.42 form as a key of no type, which would call the two halves
 * different families, so an X9.42 structure is rewritten with the PKCS #3 identifier over the same
 * p, g and value. The order and cofactor the rewrite drops are read first and held to the p and g
 * beside them, since the PKCS #3 form cannot carry them and nothing after this reads them: a
 * DomainParameters that omits q or states one its own p contradicts is a malformed key, refused
 * whatever value it carries. Anything not X9.42 is returned as given. */
function _dhAsPkcs3(der, at, what) {
  if (_algorithmOidAt(der, at) !== _OID_DH_X942) return der;
  var node = asn1.decode(der);
  var algNode = node.children[at];
  if (!algNode.children || algNode.children.length !== 2) {
    throw _err("key/bad-input", what + " X9.42 AlgorithmIdentifier does not carry DomainParameters");
  }
  var dom = x942Domain(algNode.children[1], KeyError, "key/bad-input", what);
  assertDhOperandsWithin([dom.p, dom.g, dom.q, dom.j], KeyError, "key/bad-input", what);
  assertDhDomainCoherent(dom.p, dom.g, dom.q, dom.j, KeyError, "key/bad-input", what);
  assertDhGeneratorOrder(dom.p, dom.g, dom.q, KeyError, "key/bad-input", what);
  assertDhModulusPrime(dom.p, KeyError, "key/bad-input", what);
  assertDhOrderPrime(dom.q, KeyError, "key/bad-input", what);
  /** @internal The one field the X9.42 form states that the PKCS #3 form cannot be held to is the
   * subgroup, so a public value is held to it here, where q is still known. */
  if (at === 0) {
    var pub = asn1.read.bitString(node.children[1]);
    if (!guard.crypto.isOctetAligned(pub)) {
      throw _err("key/bad-input", what + " Diffie-Hellman public key BIT STRING must be octet-aligned (0 unused bits)");
    }
    var y = asn1.read.integer(asn1.decode(pub.bytes));
    if (y <= 1n || y >= dom.p - 1n) {
      throw _err("key/bad-input", what + " Diffie-Hellman public value is outside the group (RFC 2875 sec. 3)");
    }
    assertDhValueInSubgroup(dom.p, dom.q, y, KeyError, "key/bad-input", what);
  }
  var alg = b.sequence([b.oid(_OID_DH_PKCS3), b.sequence([b.integer(dom.p), b.integer(dom.g)])]);
  var fields = [];
  for (var i = 0; i < node.children.length; i++) guard.list.append(fields, i === at ? alg : b.raw(node.children[i].bytes));
  return b.sequence(fields);
}

/** @internal Whether a composite ML-KEM private key and a SubjectPublicKeyInfo are one pair: a secret
 * encapsulated to the public key decapsulates under the private key to the same value only for the
 * pair. The toolkit's own KEM stands in for the runtime here because the runtime cannot read the
 * algorithm; every secret the probe makes is wiped on every way out. A public key of another
 * algorithm, composite or not, is another family and not a pair. */
async function _compositeCorrespondsTo(privDer, spkiDer, privateOid) {
  if (_algorithmOidAt(spkiDer, 0) !== privateOid) return false;
  var sealed = null, opened = null;
  try {
    /** @internal A structure the KEM cannot read is bad input, the verdict an unreadable classical
     * key gets from the runtime import above; a decapsulation that runs and fails is the pair not
     * deciding. The KEM tells the two apart by its own codes, and so does this. */
    try { sealed = await compositeKem.encapsulate(spkiDer); }
    catch (e) {
      if (_isKemStructureFault(e)) throw _err("key/bad-input", "the public key could not be read", e);
      throw _err("key/unsupported-algorithm", "the key pair could not be exercised to decide whether its two halves correspond", e);
    }
    try { opened = await compositeKem.decapsulate(privDer, sealed.ciphertext); }
    catch (e2) {
      if (_isKemStructureFault(e2)) throw _err("key/bad-input", "the private key could not be read", e2);
      throw _err("key/unsupported-algorithm", "the key pair could not be exercised to decide whether its two halves correspond", e2);
    }
    return guard.crypto.constantTimeEqual(opened, sealed.sharedSecret);
  } finally {
    guard.secret.zeroizeAll([sealed && sealed.sharedSecret, opened], KeyError, "key/bad-input", "the correspondence probe secrets");
  }
}

var _KEM_STRUCTURE_FAULTS = _assign(_create(null), { "kem/bad-key": 1, "kem/bad-input": 1, "kem/bad-algorithm": 1, "kem/bad-ciphertext": 1 });

/** @internal Whether a KEM error says the key or ciphertext could not be READ, as opposed to a
 * decapsulation that ran and failed. */
function _isKemStructureFault(e) {
  return !!(e && e.isPkiError === true && _KEM_STRUCTURE_FAULTS[guard.text.keyOf(e.code)] === 1);
}

async function publicFromPrivate(privateKey, opts) {
  opts = guard.identifier.optionsObject(opts, _err, "key/bad-input", "pki.key.publicFromPrivate options");
  guard.identifier.assertKnownKeys(opts, _PUBLIC_FROM_PRIVATE_OPTS, _err, "key/bad-input",
    "pki.key.publicFromPrivate has an unknown option: ");
  var der = await _toPrivateKeyDer(privateKey);
  var spki;
  /** @internal A composite ML-KEM key is a toolkit-defined algorithm the runtime decoder cannot read,
   * so it is routed before the decoder rather than after it fails. Its own module owns the split and
   * the wipe, and reports its own typed reasons. */
  var compositeOid = _compositeKemOidOf(der);
  if (compositeOid !== null) {
    spki = await compositeKem.publicFromPrivate(der);
    return opts.pem ? pkix.pemEncode(spki, "PUBLIC KEY", PemError) : spki;
  }
  try {
    var priv = nodeCrypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    spki = nodeCrypto.createPublicKey(priv).export({ format: "der", type: "spki" });
  } catch (e) { throw _err("key/bad-input", "could not derive the public key from the private key", e); }
  return opts.pem ? pkix.pemEncode(spki, "PUBLIC KEY", PemError) : spki;
}

/**
 * @internal Whether a private key and a SubjectPublicKeyInfo are the two halves of one key pair, for a
 * caller deciding whether a private key it was handed goes with a certificate it was handed.
 *
 * Deriving the public key and comparing does NOT answer this. A key structure states its own public
 * half and the key engine reads what it is told: RFC 5958 sec. 2 gives a OneAsymmetricKey an optional
 * `publicKey`, an EC key's RFC 5915 `ECPrivateKey` carries its own public point, and an RSA private
 * key carries the modulus and public exponent outright. A structure whose private components were
 * replaced while its stored public ones were left alone therefore derives to exactly the public key
 * that was planted in it, and the comparison accepts a private key that cannot use the certificate.
 *
 * So the pair is proven by USING it, on whichever operation the key type can perform: a signature the
 * public half verifies, a Diffie-Hellman agreement that reaches the same secret from both sides, or a
 * key encapsulation the private half decapsulates to the same secret (the toolkit's own KEM for a
 * composite ML-KEM key the runtime cannot read). Each fails for a key that merely claims the public
 * half. A finite-field DH key, whose private structure carries the exponent alone, is proven by the
 * value the exponent generates, in either of its two encodings (PKCS #3 or X9.42).
 *
 * What a true answer means is exactly that: the private key WORKS with this public key, on the
 * operation its type performs. It is not a statement that every field of the private structure is
 * internally consistent, which no operation reveals. A component the algorithm ignores, such as a bit
 * an X25519 scalar clamps away or an ML-KEM implicit-rejection secret, is not exercised by a
 * correspondence that succeeds, and does not stop the key from being usable with the certificate.
 * A caller needing structural consistency has a different question, and this is not it.
 */
var _PAIR_DIGEST = _assign(_create(null), { rsa: "sha256", ec: "sha256" });
var _PAIR_AGREE = _assign(_create(null), { x25519: 1, x448: 1 });
var _PAIR_KEM = _assign(_create(null),
  { "ml-kem-512": 1, "ml-kem-768": 1, "ml-kem-1024": 1 });
/** @internal RFC 4055 sec. 1.2: ONE RSA key pair may be identified either by `rsaEncryption` or by
 * `id-RSASSA-PSS`, and a delivered private key and the certificate that certifies it need not have
 * chosen the same one. The key engine reports those two encodings as different types, so comparing
 * types alone would call a usable pair no pair at all. They name one algorithm and are exercised
 * together, under PSS, which is the padding the restricted encoding permits. */
var _PAIR_RSA = _assign(_create(null), { rsa: 1, "rsa-pss": 1 });
var _PAIR_PROBE = _bufferFrom("pki.js key pair correspondence", "utf8");

function _sameKeyFamily(priv, pub) {
  if (priv.asymmetricKeyType === pub.asymmetricKeyType) return true;
  return !!(_PAIR_RSA[guard.text.keyOf(priv.asymmetricKeyType)] &&
    _PAIR_RSA[guard.text.keyOf(pub.asymmetricKeyType)]);
}

/** @internal How to exercise a signing pair: the digest, and any padding the encoding requires. An
 * `id-RSASSA-PSS` key may pin the hash and salt length it is usable with, and the engine refuses any
 * other, so a pinned value from either half is what proves the pair. */
function _pairSignOptions(priv, pub) {
  var privPss = priv.asymmetricKeyType === "rsa-pss", pubPss = pub.asymmetricKeyType === "rsa-pss";
  if (!privPss && !pubPss) {
    return { digest: _PAIR_DIGEST[guard.text.keyOf(priv.asymmetricKeyType)] || null, options: null };
  }
  var privDetails = _pssRestrictionOf(priv, privPss);
  var pubDetails = _pssRestrictionOf(pub, pubPss);
  /** @internal A half that pins nothing constrains nothing, so only two halves that BOTH pin can
   * disagree. Both encodings pinning incompatible parameters describes no operation this pair can
   * perform together, which is not the same as being different keys: it is reported as unexercisable
   * rather than as a false "not a pair". Where one pins and the other does not, the pinned half
   * supplies the parameters below and the engine enforces it against its own key. */
  if (_pssConflict(privDetails, pubDetails)) return null;
  var digest = privDetails.hashAlgorithm || pubDetails.hashAlgorithm || "sha256";
  /** @internal The engine derives MGF1 from the digest and takes no separate option for it, so a half
   * that pins a mask generator other than its own hash names an operation this pair cannot perform
   * together. That is the same "cannot be decided" verdict two conflicting halves get, not a false
   * report that the halves are different keys. */
  var mgf1 = privDetails.mgf1HashAlgorithm || pubDetails.mgf1HashAlgorithm;
  if (mgf1 != null && mgf1 !== digest) return null;
  var salt = _pssSalt(privDetails.saltLength, pubDetails.saltLength);
  /** @internal Null-prototype, because the engine READS this object by name. A plain object would
   * let an inherited `saltLength` reach the signature as a restriction neither half stated. */
  var options = _create(null);
  options.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING;
  if (salt != null) options.saltLength = salt;
  return { digest: digest, options: options };
}

var _PSS_PINS = ["hashAlgorithm", "mgf1HashAlgorithm", "saltLength"];

/** @internal What a half pins, as a null-prototype record carrying only what the key itself states.
 * A half pins nothing when it is not an id-RSASSA-PSS key at all, and equally when it is one whose
 * parameters are absent, which RFC 4055 sec. 3.1 leaves optional. Reading either through a plain
 * object would let an inherited `saltLength` or `hashAlgorithm` answer as a restriction the key never
 * carried, and refuse a genuine pair. */
function _pssRestrictionOf(key, isPss) {
  var out = _create(null);
  var details = isPss ? key.asymmetricKeyDetails : null;
  if (details == null) return out;
  for (var i = 0; i < _PSS_PINS.length; i++) {
    var name = _PSS_PINS[i];
    if (intrinsic.hasOwn(details, name) && details[name] != null) out[name] = details[name];
  }
  return out;
}

/** @internal Whether two halves state a restriction that cannot be satisfied at once. RFC 4055
 * sec. 3.3 requires the signature's hash and mask generator to match the key's, so two halves naming
 * different ones describe no shared operation. It treats the salt length differently: "The saltLength
 * field in the signature parameters MUST be greater or equal to that in the key parameters field",
 * and sec. 3.1 says the field "does not need to be fixed for a given RSA key pair". Two halves naming
 * different salt lengths are therefore both satisfied by the larger, and do not conflict. A field
 * only one half states constrains only that half, so it cannot disagree with anything. */
function _pssConflict(a, b) {
  if (a.hashAlgorithm != null && b.hashAlgorithm != null && a.hashAlgorithm !== b.hashAlgorithm) return true;
  if (a.mgf1HashAlgorithm != null && b.mgf1HashAlgorithm != null && a.mgf1HashAlgorithm !== b.mgf1HashAlgorithm) return true;
  return false;
}

/** @internal The smallest salt length both halves accept, which is the larger of the two floors. */
function _pssSalt(a, b) {
  if (a == null) return b;
  if (b == null) return a;
  return a > b ? a : b;
}

async function correspondsTo(privateKey, spkiDer) {
  var privDer = await _toPrivateKeyDer(privateKey);
  var compositeOid = _compositeKemOidOf(privDer);
  if (compositeOid !== null) return _compositeCorrespondsTo(privDer, _bufferFrom(spkiDer), compositeOid);
  /** @internal Whether the two halves are finite-field Diffie-Hellman is answered from their
   * algorithm identifiers before either structure is validated: a DH structure's validation proves
   * its modulus prime, and a half of another family is not a pair with it whatever it states, so
   * that proof is never run to say so. */
  if (_isDhOid(_algorithmOidAt(privDer, 1)) !== _isDhOid(_algorithmOidAt(_bufferFrom(spkiDer), 0))) return false;
  var priv, pub;
  /** @internal The PKCS #3 rewrite of an X9.42 private key is this function's own copy of the
   * exponent, wiped once the runtime holds the key. */
  var privAsPkcs3 = _dhAsPkcs3(privDer, 1, "the private key's");
  try {
    _assertDhWithin(privAsPkcs3, 1, "the private key's");
    try { priv = nodeCrypto.createPrivateKey({ key: privAsPkcs3, format: "der", type: "pkcs8" }); }
    catch (e) { throw _err("key/bad-input", "the private key could not be read", e); }
  } finally { if (privAsPkcs3 !== privDer) guard.secret.zeroize(privAsPkcs3, KeyError, "key/bad-input", "the rewritten private key"); }
  var pubAsPkcs3 = _dhAsPkcs3(_bufferFrom(spkiDer), 0, "the public key's");
  _assertDhWithin(pubAsPkcs3, 0, "the public key's");
  try { pub = nodeCrypto.createPublicKey({ key: pubAsPkcs3, format: "der", type: "spki" }); }
  catch (e) { throw _err("key/bad-input", "the public key could not be read", e); }
  if (!_sameKeyFamily(priv, pub)) return false;
  var kind = guard.text.keyOf(priv.asymmetricKeyType);
  /** @internal Every secret a probe makes, wiped once the verdict is decided, on every way out. */
  var secrets = [];
  try {
    /** @internal A finite-field Diffie-Hellman PrivateKeyInfo carries the exponent alone (RFC 5958 /
     * X9.42), no public copy a caller could plant, so the public value the exponent generates is a
     * proof of the pair on its own; there is no signature to try and no fixed group to draw an
     * ephemeral from. */
    if (kind === "dh") {
      /** @internal Compared as KEYS rather than as encodings: a PKCS #3 DHParameter may carry the
       * optional privateValueLength beside the same p and g, and two encodings of one public value
       * are one key. The runtime's equality compares the group and the value. */
      return _keyEquals(nodeCrypto.createPublicKey(priv), pub) === true;
    }
    if (_PAIR_KEM[kind]) {
      var sealed = nodeCrypto.encapsulate(pub);
      guard.list.append(secrets, sealed.sharedKey);
      var opened = nodeCrypto.decapsulate(priv, sealed.ciphertext);
      guard.list.append(secrets, opened);
      return guard.crypto.constantTimeEqual(opened, sealed.sharedKey);
    }
    if (_PAIR_AGREE[kind]) {
      var ephemeral = nodeCrypto.generateKeyPairSync(priv.asymmetricKeyType);
      var ours = nodeCrypto.diffieHellman({ privateKey: priv, publicKey: ephemeral.publicKey });
      guard.list.append(secrets, ours);
      var theirs = nodeCrypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: pub });
      guard.list.append(secrets, theirs);
      if (!guard.crypto.constantTimeEqual(ours, theirs)) return false;
      /** @internal The agreement proves the SCALAR, not the encoding it was handed. RFC 7748 masks the
       * top bit of an X25519 u-coordinate before the ladder, so a public value differing from the real
       * one only in a masked bit reaches the same secret from both sides. The certificate would then
       * carry bytes this key does not produce, and its subjectKeyIdentifier and any pinning of it
       * would name a key the holder does not have. These types store no public copy in the private
       * structure for an attacker to plant, so what the scalar generates IS the canonical answer and
       * comparing against it adds a bound the agreement alone does not give. */
      return guard.crypto.constantTimeEqual(
        nodeCrypto.createPublicKey(priv).export({ format: "der", type: "spki" }),
        pub.export({ format: "der", type: "spki" }));
    }
    var how = _pairSignOptions(priv, pub);
    if (how === null) {
      throw _err("key/unsupported-algorithm", "the two halves pin incompatible RSASSA-PSS parameters, so no operation exercises them together and whether they are a pair cannot be decided");
    }
    var signKey = how.options ? _assign(_create(null), { key: priv }, how.options) : priv;
    var verifyKey = how.options ? _assign(_create(null), { key: pub }, how.options) : pub;
    return nodeCrypto.verify(how.digest, _PAIR_PROBE, verifyKey,
      nodeCrypto.sign(how.digest, _PAIR_PROBE, signKey)) === true;
  } catch (e) {
    /** @internal The incompatible-parameters verdict is decided rather than caught, so it is passed
     * through with the reason it was raised for. Rewrapping it would tell an operator the pair could
     * not be exercised without saying that the two encodings pin conflicting parameters. */
    if (e && e.code === "key/unsupported-algorithm" && e.isPkiError === true) throw e;
    throw _err("key/unsupported-algorithm", "the key pair could not be exercised to decide whether its two halves correspond", e);
  } finally {
    guard.secret.zeroizeAll(secrets, KeyError, "key/bad-input", "the correspondence probe secrets");
  }
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
  var n = _toUpperCase(_String(name == null ? "" : name));
  if (n === "X25519" || n === "X448" || n === "ECDH") return isPublic ? [] : ["deriveBits", "deriveKey"];
  if (_strIndexOf(n, "ML-KEM") === 0) return isPublic ? ["encapsulateBits"] : ["decapsulateBits"];
  if (n === "RSA-OAEP") return isPublic ? ["encrypt"] : ["decrypt"];
  return isPublic ? ["verify"] : ["sign"];
}

function _generateUsages(name) {
  var n = _toUpperCase(_String(name == null ? "" : name));
  if (n === "X25519" || n === "X448" || n === "ECDH") return ["deriveBits", "deriveKey"];
  if (_strIndexOf(n, "ML-KEM") === 0) return ["encapsulateBits", "decapsulateBits"];
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
  correspondsTo: correspondsTo,   // @internal
  x942Domain: x942Domain,   // @internal
  pkcs3Params: pkcs3Params,   // @internal
  isDhOid: _isDhOid,   // @internal
  algorithmOidAt: _algorithmOidAt,   // @internal
  assertDhOperandsWithin: assertDhOperandsWithin,   // @internal
  assertDhDomainCoherent: assertDhDomainCoherent,   // @internal
  assertDhGeneratorOrder: assertDhGeneratorOrder,   // @internal
  assertDhModulusPrime: assertDhModulusPrime,   // @internal
  assertDhOrderPrime: assertDhOrderPrime,   // @internal
  assertDhValueInSubgroup: assertDhValueInSubgroup,   // @internal
  isPrime: isPrime,   // @internal
  modPow: modPow,   // @internal
};
