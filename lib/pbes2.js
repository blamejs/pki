// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var webcrypto = require("./webcrypto");
var guard = require("./guard-all");
var C = require("./constants");

var b = asn1.build;
function O(n) { return oid.byName(n); }

var PRF_NODE_BY_NAME = Object.assign(Object.create(null), { hmacWithSHA1: "sha1", hmacWithSHA256: "sha256", hmacWithSHA384: "sha384", hmacWithSHA512: "sha512" });
var PRF_NODE_BY_OID = {}; Object.keys(PRF_NODE_BY_NAME).forEach(function (n) { PRF_NODE_BY_OID[O(n)] = PRF_NODE_BY_NAME[n]; });

var CONTENT_KEYBITS = {}, CONTENT_MODE = {};
[["aes128-CBC", 128, "cbc"], ["aes192-CBC", 192, "cbc"], ["aes256-CBC", 256, "cbc"],
  ["aes128-GCM", 128, "gcm"], ["aes192-GCM", 192, "gcm"], ["aes256-GCM", 256, "gcm"]].forEach(function (r) {
  CONTENT_KEYBITS[O(r[0])] = r[1];
  CONTENT_MODE[O(r[0])] = r[2];
});

function passwordBytes(p, E, prefix) { return passwordBytesOwned(p, E, prefix).bytes; }

function passwordBytesOwned(p, E, prefix) {
  if (Buffer.isBuffer(p)) return { bytes: p, owned: false };
  if (p instanceof Uint8Array) return { bytes: Buffer.from(p), owned: true };
  if (typeof p === "string") return { bytes: Buffer.from(p, "utf8"), owned: true };
  throw E(prefix + "/bad-input", "a password must be a string, Buffer, or Uint8Array");
}

function assertIterations(n, E, prefix) {
  if (typeof n !== "number" || !isFinite(n) || n < 1 || Math.floor(n) !== n) throw E(prefix + "/bad-input", "iterations must be a positive integer");
  if (n > C.LIMITS.PBKDF2_MAX_ITERATIONS) throw E(prefix + "/bad-input", "iterations exceeds the " + C.LIMITS.PBKDF2_MAX_ITERATIONS + " cap");
  return n;
}

function assertSalt(salt, E, prefix) {
  guard.limits.byteCap(salt, C.LIMITS.PBKDF2_MAX_SALT, E, prefix + "/bad-input", "salt");
  return salt;
}

function prfNodeByName(prf, E, prefix) { if (!PRF_NODE_BY_NAME[prf]) throw E(prefix + "/bad-input", "unsupported prf " + JSON.stringify(prf)); return PRF_NODE_BY_NAME[prf]; }
function prfNodeByOid(oidStr, E, prefix) { if (!PRF_NODE_BY_OID[oidStr]) throw E(prefix + "/unsupported-algorithm", "unsupported PBKDF2 prf " + oidStr); return PRF_NODE_BY_OID[oidStr]; }

function pbkdf2ParamsSeq(salt, iterations, prf) {
  var kids = [b.octetString(salt), b.integer(BigInt(iterations))];
  if (prf !== "hmacWithSHA1") kids.push(b.sequence([b.oid(O(prf)), b.nullValue()]));
  return b.sequence(kids);
}

function pbes2AlgId(salt, iterations, prf, cipherName, iv) {
  var kdf = b.sequence([b.oid(O("pbkdf2")), pbkdf2ParamsSeq(salt, iterations, prf)]);
  var encScheme = b.sequence([b.oid(O(cipherName)), b.octetString(iv)]);
  return b.sequence([b.oid(O("pbes2")), b.sequence([kdf, encScheme])]);
}

function requireChildren(node, minLen, what, E, prefix) {
  if (!node || !node.children || node.children.length < minLen) throw E(prefix + "/bad-input", "malformed " + what);
  return node.children;
}
function seqChildren(paramsDer, minLen, what, E, prefix) {
  if (paramsDer == null) throw E(prefix + "/bad-input", "missing " + what);
  return requireChildren(asn1.decode(paramsDer), minLen, what, E, prefix);
}

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
      if (strictPrf && prfOid === O("hmacWithSHA1") && ch.children.length > 1 && ch.children[1].tagClass === "universal" && ch.children[1].tagNumber === asn1.TAGS.NULL) {
        throw E(prefix + "/bad-input", "a PBKDF2 prf equal to the default hmacWithSHA1 must be omitted (X.690 sec. 11.5)");
      }
      prfNode = prfNodeByOid(prfOid, E, prefix);
    }
  }
  return { salt: salt, iterations: iterations, prfNode: prfNode };
}

function cbcEncrypt(key, iv, plaintext, keyBits, E, code) {
  var c = nodeCrypto.createCipheriv("aes-" + keyBits + "-cbc", key, iv);
  return guard.secret.cipherFinish(c, plaintext, E, code, "a content-encryption intermediate");
}
function cbcDecrypt(key, iv, ct, keyBits, E, code) {
  var d = nodeCrypto.createDecipheriv("aes-" + keyBits + "-cbc", key, iv);
  return guard.secret.cipherFinish(d, ct, E, code, "the partially recovered plaintext");
}

function pbes2Encrypt(pwBytes, plaintext, opts, E, prefix) {
  opts = opts || {};
  var cipherName = opts.cipher || "aes256-CBC";
  var keyBits = CONTENT_KEYBITS[O(cipherName)];
  if (!keyBits || cipherName.indexOf("CBC") === -1) throw E(prefix + "/bad-input", "unsupported PBES2 cipher " + cipherName + " (AES-CBC only)");
  var prf = opts.prf || "hmacWithSHA256";
  var prfNode = prfNodeByName(prf, E, prefix);
  var iterations = assertIterations(opts.iterations == null ? 2048 : opts.iterations, E, prefix);
  var salt = opts.salt != null ? assertSalt(opts.salt, E, prefix) : nodeCrypto.randomBytes(16);
  var iv = opts.iv != null ? opts.iv : nodeCrypto.randomBytes(16);
  var key = nodeCrypto.pbkdf2Sync(pwBytes, salt, iterations, keyBits / 8, prfNode);
  try {
    return { algId: pbes2AlgId(salt, iterations, prf, cipherName, iv), ct: cbcEncrypt(key, iv, plaintext, keyBits, E, prefix + "/bad-input") };
  } finally {
    guard.secret.zeroize(key, E, prefix + "/bad-input", "the password-derived encryption key");
  }
}

function pbes2Decrypt(pwBytes, params, ciphertext, opts, E, prefix, budget) {
  var keyBits, iv, pb;
  try {
    var p = seqChildren(params, 2, "PBES2 parameters", E, prefix);
    var kdf = requireChildren(p[0], 2, "PBES2 keyDerivationFunc", E, prefix);
    var encScheme = requireChildren(p[1], 2, "PBES2 encryptionScheme", E, prefix);
    if (asn1.read.oid(kdf[0]) !== O("pbkdf2")) throw E(prefix + "/unsupported-algorithm", "the PBES2 keyDerivationFunc must be PBKDF2 (RFC 8018 sec. 6.2)");
    pb = parsePbkdf2Params(kdf[1].bytes, opts, E, prefix, true);
    var encOid = asn1.read.oid(encScheme[0]);
    keyBits = CONTENT_KEYBITS[encOid];
    if (!keyBits || (oid.name(encOid) || "").indexOf("CBC") === -1) throw E(prefix + "/unsupported-algorithm", "unsupported PBES2 encryptionScheme " + (oid.name(encOid) || encOid) + " (AES-CBC only)");
    iv = asn1.read.octetString(encScheme[1]);
    if (iv.length !== 16) throw E(prefix + "/bad-algorithm-parameters", "the AES-CBC IV must be 16 octets");
  } catch (e) {
    if (e && e.isPkiError && typeof e.code === "string" && e.code.indexOf(prefix + "/") === 0) {
      if (e.code === prefix + "/bad-input") throw E(prefix + "/bad-algorithm-parameters", e.message, e.cause);
      throw e;
    }
    throw E(prefix + "/bad-algorithm-parameters", "malformed PBES2 parameters", e);
  }
  if (budget) {
    budget.rounds -= pb.iterations;
    if (budget.rounds < 0) throw E(prefix + "/iteration-limit", "the aggregate PBKDF2 key-derivation work exceeds the budget (a hostile many-element input)");
  }
  var dk = nodeCrypto.pbkdf2Sync(pwBytes, pb.salt, pb.iterations, keyBits / 8, pb.prfNode);
  try { return cbcDecrypt(dk, iv, ciphertext, keyBits, E, prefix + "/decrypt-failed"); }
  catch (_e) { throw E(prefix + "/decrypt-failed", "decryption failed"); }
  finally { guard.secret.zeroize(dk, E, prefix + "/bad-input", "the password-derived decryption key"); }
}

function _hmacAlgId(name) { return b.sequence([b.oid(O(name)), b.nullValue()]); }

function pbmac1AlgId(desc) {
  var pbkdf2Params = [b.octetString(desc.salt), b.integer(BigInt(desc.iterationCount)), b.integer(BigInt(desc.keyLength))];
  if (desc.prfName !== "hmacWithSHA1") pbkdf2Params.push(_hmacAlgId(desc.prfName));
  var pbkdf2AlgId = b.sequence([b.oid(O("pbkdf2")), b.sequence(pbkdf2Params)]);
  return b.sequence([b.oid(O("pbmac1")), b.sequence([pbkdf2AlgId, _hmacAlgId(desc.macName)])]);
}

function pbmac1(pwBytes, salt, iterationCount, keyLength, prfHash, macHash, message) {
  var subtle = webcrypto.webcrypto.subtle;
  return subtle.importKey("raw", pwBytes, { name: "PBKDF2" }, false, ["deriveBits"]).then(function (baseKey) {
    return subtle.deriveBits({ name: "PBKDF2", salt: salt, iterations: iterationCount, hash: prfHash }, baseKey, keyLength * 8);
  }).then(function (bits) {
    var mk = Buffer.from(bits);
    return subtle.importKey("raw", mk, { name: "HMAC", hash: macHash }, false, ["sign"]).then(function (hmacKey) {
      return subtle.sign({ name: "HMAC" }, hmacKey, message);
    }).finally(function () {
      guard.secret.zeroize(mk, webcrypto.WebCryptoError, "webcrypto/operation", "the PBMAC1 key");
    });
  }).then(function (sig) { return Buffer.from(sig); });
}

module.exports = {
  passwordBytes: passwordBytes, passwordBytesOwned: passwordBytesOwned, assertIterations: assertIterations, assertSalt: assertSalt,
  prfNodeByName: prfNodeByName, prfNodeByOid: prfNodeByOid,
  pbkdf2ParamsSeq: pbkdf2ParamsSeq, pbes2AlgId: pbes2AlgId, parsePbkdf2Params: parsePbkdf2Params,
  requireChildren: requireChildren, seqChildren: seqChildren,
  cbcEncrypt: cbcEncrypt, cbcDecrypt: cbcDecrypt, pbes2Encrypt: pbes2Encrypt, pbes2Decrypt: pbes2Decrypt, CONTENT_KEYBITS: CONTENT_KEYBITS, CONTENT_MODE: CONTENT_MODE,
  pbmac1AlgId: pbmac1AlgId, pbmac1: pbmac1,
};
