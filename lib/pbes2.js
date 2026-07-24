// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the RFC 8018 PBES2 / PBKDF2 primitives, the ONE home shared by pki.cms EncryptedData / PWRI
// password encryption and pki.key EncryptedPrivateKeyInfo (RFC 5958). Error-factory-parameterized like the
// guard family: every reject goes through the CALLER's `E(code, msg, cause)` full-code factory plus a domain
// `prefix`, so pki.cms keeps cms/* codes and pki.key keeps key/* codes off ONE implementation. Extracted
// behavior-preservingly from cms-encrypt.js + cms-decrypt.js -- the shipped CMS PBES2 tests are the guard.
// A shape here that CANNOT route through a guard stays with its caller; the reusable PBES2 shape lives here
// so a fourth copy (the drift a reviewer flags) cannot re-accrete.

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var webcrypto = require("./webcrypto");
var guard = require("./guard-all");
var C = require("./constants");

var b = asn1.build;
function O(n) { return oid.byName(n); }

// PBKDF2 prf tables: the OID name -> node digest (encrypt names the prf) and the OID -> node digest (decrypt
// reads the OID). One source, both directions.
var PRF_NODE_BY_NAME = { hmacWithSHA1: "sha1", hmacWithSHA256: "sha256", hmacWithSHA384: "sha384", hmacWithSHA512: "sha512" };
var PRF_NODE_BY_OID = {}; Object.keys(PRF_NODE_BY_NAME).forEach(function (n) { PRF_NODE_BY_OID[O(n)] = PRF_NODE_BY_NAME[n]; });

// content-encryption OID -> AES key bits (CBC + GCM). The PBES2 encryptionScheme + CMS content cipher table.
var CONTENT_KEYBITS = {};
[["aes128-CBC", 128], ["aes192-CBC", 192], ["aes256-CBC", 256], ["aes128-GCM", 128], ["aes192-GCM", 192], ["aes256-GCM", 256]].forEach(function (r) { CONTENT_KEYBITS[O(r[0])] = r[1]; });

// A password is an octet string (RFC 8018 sec. 2): a string is UTF-8-encoded deterministically (correct for
// non-ASCII, and byte-identical to OpenSSL), a Buffer/Uint8Array used verbatim.
function passwordBytes(p, E, prefix) {
  if (Buffer.isBuffer(p)) return p;
  if (p instanceof Uint8Array) return Buffer.from(p);
  if (typeof p === "string") return Buffer.from(p, "utf8");
  throw E(prefix + "/bad-input", "a password must be a string, Buffer, or Uint8Array");
}

// iterationCount for a PRODUCED PBES2/PWRI structure: a positive integer at or below the cap the decryptor
// enforces, so a structure we emit is always one we can read back (config-time throw on a bad value).
function assertIterations(n, E, prefix) {
  if (typeof n !== "number" || !isFinite(n) || n < 1 || Math.floor(n) !== n) throw E(prefix + "/bad-input", "iterations must be a positive integer");
  if (n > C.LIMITS.PBKDF2_MAX_ITERATIONS) throw E(prefix + "/bad-input", "iterations exceeds the " + C.LIMITS.PBKDF2_MAX_ITERATIONS + " cap");
  return n;
}

// Bound a PRODUCED salt to the same cap the decryptor enforces.
function assertSalt(salt, E, prefix) {
  guard.limits.byteCap(salt, C.LIMITS.PBKDF2_MAX_SALT, E, prefix + "/bad-input", "salt");
  return salt;
}

function prfNodeByName(prf, E, prefix) { if (!PRF_NODE_BY_NAME[prf]) throw E(prefix + "/bad-input", "unsupported prf " + JSON.stringify(prf)); return PRF_NODE_BY_NAME[prf]; }
function prfNodeByOid(oidStr, E, prefix) { if (!PRF_NODE_BY_OID[oidStr]) throw E(prefix + "/unsupported-algorithm", "unsupported PBKDF2 prf " + oidStr); return PRF_NODE_BY_OID[oidStr]; }

// PBKDF2-params { salt OCTET STRING, iterationCount INTEGER, prf DEFAULT hmacWithSHA1 }. prf equal to the
// DEFAULT (hmacWithSHA1) MUST be omitted on encode (X.690 sec. 11.5 / RFC 8018 App. A.2); every other prf is
// an hmacWithSHA_n AlgorithmIdentifier carrying NULL parameters.
function pbkdf2ParamsSeq(salt, iterations, prf) {
  var kids = [b.octetString(salt), b.integer(BigInt(iterations))];
  if (prf !== "hmacWithSHA1") kids.push(b.sequence([b.oid(O(prf)), b.nullValue()]));
  return b.sequence(kids);
}

// The PBES2 AlgorithmIdentifier: SEQUENCE { id-PBES2, SEQUENCE { keyDerivationFunc PBKDF2, encryptionScheme } }.
// The ONE home for the CMS EncryptedData contentEncryptionAlgorithm AND the RFC 5958 EncryptedPrivateKeyInfo
// encryptionAlgorithm -- both wrap the same PBES2 structure around a PBKDF2 KDF plus an AES-CBC scheme whose
// IV rides in the encryptionScheme parameter. `cipherName` is a registry NAME (an AES-CBC OID name).
function pbes2AlgId(salt, iterations, prf, cipherName, iv) {
  var kdf = b.sequence([b.oid(O("pbkdf2")), pbkdf2ParamsSeq(salt, iterations, prf)]);
  var encScheme = b.sequence([b.oid(O(cipherName)), b.octetString(iv)]);
  return b.sequence([b.oid(O("pbes2")), b.sequence([kdf, encScheme])]);
}

// SEQUENCE structural guards -- a malformed (primitive / too-short) attacker-controlled parameter SEQUENCE is
// a typed E(prefix + "/bad-input"), never a raw `.children` dereference fault (a PBES2 structure is public,
// not a decrypt oracle).
function requireChildren(node, minLen, what, E, prefix) {
  if (!node || !node.children || node.children.length < minLen) throw E(prefix + "/bad-input", "malformed " + what);
  return node.children;
}
function seqChildren(paramsDer, minLen, what, E, prefix) {
  if (paramsDer == null) throw E(prefix + "/bad-input", "missing " + what);
  return requireChildren(asn1.decode(paramsDer), minLen, what, E, prefix);
}

// Strict PBKDF2-params decode: salt (capped BEFORE derivation), iterationCount (positiveInt31 + cap, downward-
// overridable via a validated-positive-int opts.maxIterations so Math.min(NaN, cap) cannot silently disable
// the DoS cap), prf. Returns { salt, iterations, prfNode }.
function parsePbkdf2Params(paramsDer, opts, E, prefix, strictPrf) {
  var node = Buffer.isBuffer(paramsDer) ? asn1.decode(paramsDer) : paramsDer;
  var kids = requireChildren(node, 2, "PBKDF2 parameters", E, prefix);
  var salt = asn1.read.octetString(kids[0]);
  if (salt.length > C.LIMITS.PBKDF2_MAX_SALT) throw E(prefix + "/bad-input", "PBKDF2 salt exceeds the " + C.LIMITS.PBKDF2_MAX_SALT + "-octet cap");
  var iterations = guard.range.positiveInt31(asn1.read.integer(kids[1]), E, prefix + "/bad-input", "PBKDF2 iterationCount");
  var cap = C.LIMITS.PBKDF2_MAX_ITERATIONS;
  if (opts && opts.maxIterations != null) {
    if (typeof opts.maxIterations !== "number" || !isFinite(opts.maxIterations) || opts.maxIterations < 1 || Math.floor(opts.maxIterations) !== opts.maxIterations) throw E(prefix + "/bad-input", "maxIterations must be a positive integer");
    cap = Math.min(opts.maxIterations, cap);
  }
  if (iterations > cap) throw E(prefix + "/iteration-limit", "PBKDF2 iterationCount " + iterations + " exceeds the cap " + cap);
  var prfNode = "sha1";
  for (var i = 2; i < node.children.length; i++) {
    var ch = node.children[i];
    if (ch.tagClass === "universal" && ch.tagNumber === asn1.TAGS.SEQUENCE) {
      var prfOid = asn1.read.oid(ch.children[0]);
      // X.690 sec. 11.5 / RFC 8018 App. A.2: a prf equal to the DEFAULT (hmacWithSHA1 with NULL parameters)
      // MUST be omitted -- an explicit encoding of it is non-canonical. A strictPrf caller rejects it.
      if (strictPrf && prfOid === O("hmacWithSHA1") && ch.children.length > 1 && ch.children[1].tagClass === "universal" && ch.children[1].tagNumber === asn1.TAGS.NULL) {
        throw E(prefix + "/bad-input", "a PBKDF2 prf equal to the default hmacWithSHA1 must be omitted (X.690 sec. 11.5)");
      }
      prfNode = prfNodeByOid(prfOid, E, prefix);
    }
  }
  return { salt: salt, iterations: iterations, prfNode: prfNode };
}

// AES-CBC content encryption / decryption (PKCS#7 pad). decrypt's final() throws on bad pad -- the caller
// collapses that into its uniform decrypt-failed verdict.
function cbcEncrypt(key, iv, plaintext, keyBits) {
  var c = nodeCrypto.createCipheriv("aes-" + keyBits + "-cbc", key, iv);
  return Buffer.concat([c.update(plaintext), c.final()]);
}
function cbcDecrypt(key, iv, ct, keyBits) {
  var d = nodeCrypto.createDecipheriv("aes-" + keyBits + "-cbc", key, iv);
  return Buffer.concat([d.update(ct), d.final()]);
}

// Higher-level PBES2 AES-CBC encrypt: derive an AES key from PRE-FORMATTED password bytes (the caller owns
// the encoding -- CMS UTF-8 vs PKCS#12 App. B.1) and encrypt the plaintext, returning the PBES2
// AlgorithmIdentifier + ciphertext. `cipherName` is an AES-CBC registry name (aes128/192/256-CBC).
function pbes2Encrypt(pwBytes, plaintext, opts, E, prefix) {
  opts = opts || {};
  var cipherName = opts.cipher || "aes256-CBC";
  var keyBits = CONTENT_KEYBITS[O(cipherName)];
  if (!keyBits || !/CBC/.test(cipherName)) throw E(prefix + "/bad-input", "unsupported PBES2 cipher " + cipherName + " (AES-CBC only)");
  var prf = opts.prf || "hmacWithSHA256";
  var prfNode = prfNodeByName(prf, E, prefix);
  var iterations = assertIterations(opts.iterations == null ? 2048 : opts.iterations, E, prefix);
  var salt = opts.salt != null ? assertSalt(opts.salt, E, prefix) : nodeCrypto.randomBytes(16);
  var iv = opts.iv != null ? opts.iv : nodeCrypto.randomBytes(16);
  var key = nodeCrypto.pbkdf2Sync(pwBytes, salt, iterations, keyBits / 8, prfNode);
  return { algId: pbes2AlgId(salt, iterations, prf, cipherName, iv), ct: cbcEncrypt(key, iv, plaintext, keyBits) };
}

// PBES2 AES-CBC DECRYPT: parse the PBES2 params (PBKDF2 kdf + AES-CBC scheme), derive the key from
// PRE-FORMATTED password bytes (the caller owns UTF-8 vs BMPString), and AES-CBC-decrypt. Structural faults
// (a non-PBKDF2 KDF, a non-AES-CBC scheme, an over-cap salt/iteration, a wrong-length IV, a malformed param
// SEQUENCE) are typed pre-derivation and password-independent, so they leak no oracle; the generic
// <prefix>/bad-input a param guard raises is normalized to the structural <prefix>/bad-algorithm-parameters.
// A wrong key / bad PKCS#7 pad collapses to the UNIFORM <prefix>/decrypt-failed (RFC 8018 sec. 8). The
// plaintext integrity re-check (re-parse as a PrivateKeyInfo / SafeContents) is the CALLER's step.
function pbes2Decrypt(pwBytes, params, ciphertext, opts, E, prefix) {
  var keyBits, iv, pb;
  try {
    var p = seqChildren(params, 2, "PBES2 parameters", E, prefix);
    var kdf = requireChildren(p[0], 2, "PBES2 keyDerivationFunc", E, prefix);
    var encScheme = requireChildren(p[1], 2, "PBES2 encryptionScheme", E, prefix);
    if (asn1.read.oid(kdf[0]) !== O("pbkdf2")) throw E(prefix + "/unsupported-algorithm", "the PBES2 keyDerivationFunc must be PBKDF2 (RFC 8018 sec. 6.2)");
    pb = parsePbkdf2Params(kdf[1].bytes, opts, E, prefix, true);   // strictPrf: reject a non-canonical explicit default prf
    var encOid = asn1.read.oid(encScheme[0]);
    keyBits = CONTENT_KEYBITS[encOid];
    if (!keyBits || !/CBC/.test(oid.name(encOid) || "")) throw E(prefix + "/unsupported-algorithm", "unsupported PBES2 encryptionScheme " + (oid.name(encOid) || encOid) + " (AES-CBC only)");
    iv = asn1.read.octetString(encScheme[1]);
    if (iv.length !== 16) throw E(prefix + "/bad-algorithm-parameters", "the AES-CBC IV must be 16 octets");
  } catch (e) {
    if (e && e.isPkiError && typeof e.code === "string" && e.code.indexOf(prefix + "/") === 0) {
      if (e.code === prefix + "/bad-input") throw E(prefix + "/bad-algorithm-parameters", e.message, e.cause);
      throw e;
    }
    throw E(prefix + "/bad-algorithm-parameters", "malformed PBES2 parameters", e);
  }
  var dk = nodeCrypto.pbkdf2Sync(pwBytes, pb.salt, pb.iterations, keyBits / 8, pb.prfNode);
  try { return cbcDecrypt(dk, iv, ciphertext, keyBits); }
  catch (_e) { throw E(prefix + "/decrypt-failed", "decryption failed"); }
}

// ---- PBMAC1 (RFC 9579 / RFC 8018 App. A.5) : PBKDF2 -> HMAC over a message --
// An hmacWithSHA_n AlgorithmIdentifier carries NULL parameters (RFC 8018 B.1.1).
function _hmacAlgId(name) { return b.sequence([b.oid(O(name)), b.nullValue()]); }

// The id-PBMAC1 AlgorithmIdentifier: id-PBMAC1 + PBMAC1-params { keyDerivationFunc PBKDF2, messageAuthScheme
// HMAC } -- the byte-exact inverse of schema-pkcs12 / schema-cmp's PBMAC1_PARAMS. `desc` = { salt,
// iterationCount, keyLength, prfName, macName }. The prf is omitted iff it equals the default hmacWithSHA1.
function pbmac1AlgId(desc) {
  var pbkdf2Params = [b.octetString(desc.salt), b.integer(BigInt(desc.iterationCount)), b.integer(BigInt(desc.keyLength))];
  if (desc.prfName !== "hmacWithSHA1") pbkdf2Params.push(_hmacAlgId(desc.prfName));
  var pbkdf2AlgId = b.sequence([b.oid(O("pbkdf2")), b.sequence(pbkdf2Params)]);
  return b.sequence([b.oid(O("pbmac1")), b.sequence([pbkdf2AlgId, _hmacAlgId(desc.macName)])]);
}

// Compute PBMAC1 = HMAC_macHash(PBKDF2(pwBytes, salt, iter, keyLength, prfHash), message). The PBKDF2 prf
// and the HMAC messageAuthScheme are INDEPENDENT (RFC 9579 sec. 4 / RFC 8018 App. A.5) -- e.g. a SHA-512 PRF
// with a SHA-256 HMAC -- so both are passed explicitly. `prfHash` / `macHash` are WebCrypto hash names
// ("SHA-256"); pwBytes is pre-formatted (the caller owns the encoding).
function pbmac1(pwBytes, salt, iterationCount, keyLength, prfHash, macHash, message) {
  var subtle = webcrypto.webcrypto.subtle;
  return subtle.importKey("raw", pwBytes, { name: "PBKDF2" }, false, ["deriveBits"]).then(function (baseKey) {
    return subtle.deriveBits({ name: "PBKDF2", salt: salt, iterations: iterationCount, hash: prfHash }, baseKey, keyLength * 8);
  }).then(function (bits) {
    return subtle.importKey("raw", Buffer.from(bits), { name: "HMAC", hash: macHash }, false, ["sign"]).then(function (hmacKey) {
      return subtle.sign({ name: "HMAC" }, hmacKey, message);
    });
  }).then(function (sig) { return Buffer.from(sig); });
}

module.exports = {
  passwordBytes: passwordBytes, assertIterations: assertIterations, assertSalt: assertSalt,
  prfNodeByName: prfNodeByName, prfNodeByOid: prfNodeByOid,
  pbkdf2ParamsSeq: pbkdf2ParamsSeq, pbes2AlgId: pbes2AlgId, parsePbkdf2Params: parsePbkdf2Params,
  requireChildren: requireChildren, seqChildren: seqChildren,
  cbcEncrypt: cbcEncrypt, cbcDecrypt: cbcDecrypt, pbes2Encrypt: pbes2Encrypt, pbes2Decrypt: pbes2Decrypt, CONTENT_KEYBITS: CONTENT_KEYBITS,
  pbmac1AlgId: pbmac1AlgId, pbmac1: pbmac1,
};
