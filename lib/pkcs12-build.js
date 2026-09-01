// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.pkcs12
 * @nav        Signing
 * @title      PKCS#12
 * @fullname   PKCS#12 keystores (.p12 and .pfx): build and open
 * @intro The PKCS#12 (.p12 / .pfx) producing side (RFC 7292, RFC 9579). `pki.pkcs12.build` assembles a
 *   password-integrity PFX -- key, certificate, CRL, and secret bags (shrouded keys and cert safes encrypted
 *   under RFC 8018 PBES2) wrapped in an AuthenticatedSafe, protected by either a classic Appendix B HMAC or
 *   an RFC 9579 PBMAC1 (PBKDF2 + HMAC) MAC, over AES-128/192/256-CBC and SHA-256/384/512. Every password is
 *   encoded the PKCS#12 way (BMPString + NULL, Appendix B.1), so a file it emits opens in OpenSSL and NSS.
 *   `pki.pkcs12.verifyMac` recomputes a store's MAC over the exact AuthenticatedSafe byte range and
 *   constant-time-compares it. Parsing lives at `pki.schema.pkcs12.parse`.
 * @spec RFC 7292, RFC 9579, RFC 8018
 * @card Build a password-integrity PKCS#12 store (RFC 7292 / RFC 9579) and verify its MAC.
 */

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var rc2 = require("./rc2");
var oid = require("./oid");
var pbes2 = require("./pbes2");
var pkcs8 = require("./schema-pkcs8");
var x509 = require("./schema-x509");
var schemaCrl = require("./schema-crl");
var key = require("./key");
var cms = require("./cms-verify");
var cmsSign = require("./cms-sign");
var cmsDecrypt = require("./cms-decrypt");   // @internal
var schemaPkcs12 = require("./schema-pkcs12");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _toLower = intrinsic.uncurry(String.prototype.toLowerCase);
var frameworkError = require("./framework-error");
var C = require("./constants");

var b = asn1.build;
var Pkcs12Error = frameworkError.Pkcs12Error;
var PemError = frameworkError.PemError;
function O(n) { return oid.byName(n); }
function _err(code, msg, cause) { return new Pkcs12Error(code, msg, cause); }

var DEFAULT_MAC_ITER = 2048;
var DEFAULT_PBMAC1_ITER = 2048;
var MAC_SALT_BYTES = 8;
var MAX_PBMAC1_KEYLEN = 1024;
var CLASSIC_MAC_MAX_ITERATIONS = 1000000;
var KDF_MAX_ROUNDS = CLASSIC_MAC_MAX_ITERATIONS;

var P12_KDF_UV = {
  sha1: { u: 20, v: 64 }, sha224: { u: 28, v: 64 }, sha256: { u: 32, v: 64 },
  sha384: { u: 48, v: 128 }, sha512: { u: 64, v: 128 },
};
var PBMAC1_PRF = {
  sha256: { prfName: "hmacWithSHA256", wc: "SHA-256", keyLen: 32 },
  sha384: { prfName: "hmacWithSHA384", wc: "SHA-384", keyLen: 48 },
  sha512: { prfName: "hmacWithSHA512", wc: "SHA-512", keyLen: 64 },
};
var PRF_WC = { hmacWithSHA1: "SHA-1", hmacWithSHA256: "SHA-256", hmacWithSHA384: "SHA-384", hmacWithSHA512: "SHA-512" };
var CIPHER_NAME = { "aes-128-cbc": "aes128-CBC", "aes-192-cbc": "aes192-CBC", "aes-256-cbc": "aes256-CBC" };
var DIGEST_NAME = { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512" };



var _MISSING_PASSWORD = "a password must be a string, Buffer, or Uint8Array -- an omitted password " +
  "is not the empty password; pass \"\" to use the empty one deliberately";

var _INTEGRITY_OPTS = { mode: 1, signer: 1, signers: 1, certificates: 1, sid: 1, signingTime: 1 };
var _BUILD_SPEC_FULL_KEYS = { safeContents: 1 };
var _BUILD_SPEC_SHORTHAND_KEYS = { key: 1, cert: 1, ca: 1, friendlyName: 1, localKeyId: 1 };
var _BUILD_OPTS_FULL = { integrity: 1, mac: 1, password: 1, pem: 1 };
var _BUILD_OPTS_SHORTHAND = { integrity: 1, mac: 1, password: 1, pem: 1, recipientCerts: 1 };
var _SAFE_RECIPIENTS_KEYS = { bags: 1, recipients: 1, contentEncryptionAlgorithm: 1 };
var _SAFE_PASSWORD_KEYS = { bags: 1, encrypt: 1 };
var _SAFE_PLAINTEXT_KEYS = { bags: 1 };
var _BAG_KEYS_BY_TYPE = {
  key:          { type: 1, friendlyName: 1, localKeyId: 1, key: 1 },
  shroudedKey:  { type: 1, friendlyName: 1, localKeyId: 1, key: 1, encrypt: 1 },
  cert:         { type: 1, friendlyName: 1, localKeyId: 1, cert: 1 },
  crl:          { type: 1, friendlyName: 1, localKeyId: 1, crl: 1 },
  secret:       { type: 1, friendlyName: 1, localKeyId: 1, secretTypeId: 1, secretValue: 1 },
  safeContents: { type: 1, friendlyName: 1, localKeyId: 1, nested: 1 },
};
var _ENCRYPT_KEYS = { password: 1, cipher: 1, salt: 1, iterations: 1, prf: 1 };
var _MAC_KEYS = { algorithm: 1, hash: 1, salt: 1, iterations: 1, keyLength: 1, password: 1 };
var _MAC_KEYS_HMAC = { algorithm: 1, hash: 1, salt: 1, iterations: 1, password: 1 };
var _MAC_KEYS_PBMAC1 = { algorithm: 1, hash: 1, salt: 1, iterations: 1, keyLength: 1, password: 1 };
var _OPEN_OPTS = {
  allowUnauthenticated: 1, importAlgorithm: 1, keys: 1, maxIterations: 1, signerCerts: 1,
  recipientKey: 1, recipientCert: 1, recipientIndex: 1,
};
var _VERIFY_MAC_OPTS = { maxIterations: 1 };

function _p12PasswordOwned(pw) {
  if (Buffer.isBuffer(pw)) return { bytes: guard.bytes.view(pw, Pkcs12Error, "pkcs12/bad-input", "the password"), owned: false };
  return { bytes: _p12Encode(pw), owned: true };
}
function _p12Encode(pw) {
  if (Buffer.isBuffer(pw) || pw instanceof Uint8Array) return guard.bytes.snapshot(pw, Pkcs12Error, "pkcs12/bad-input", "the password");   // allow:byte-source-narrow -- password on the ownership contract (string / Buffer / Uint8Array); widening passwords is a separate root decision
  if (typeof pw !== "string") throw _err("pkcs12/bad-input", _MISSING_PASSWORD);
  var out = Buffer.alloc(pw.length * 2 + 2);
  for (var i = 0; i < pw.length; i++) {
    var u = pw.charCodeAt(i);
    if (u >= 0xD800 && u <= 0xDFFF) throw _err("pkcs12/bad-input", "the password contains a non-BMP character (a surrogate code point cannot be BMPString-encoded)");
    out[i * 2] = (u >> 8) & 0xFF;
    out[i * 2 + 1] = u & 0xFF;
  }
  return out;
}

function _pbePasswordOwned(pw) {
  if (Buffer.isBuffer(pw)) return { bytes: guard.bytes.view(pw, Pkcs12Error, "pkcs12/bad-input", "the password"), owned: false };
  if (pw instanceof Uint8Array) return { bytes: guard.bytes.snapshot(pw, Pkcs12Error, "pkcs12/bad-input", "the password"), owned: true };
  if (typeof pw !== "string") throw _err("pkcs12/bad-input", _MISSING_PASSWORD);
  return { bytes: Buffer.from(pw, "utf8"), owned: true };
}
function _wipePw(owned) {
  if (owned.owned) guard.secret.zeroize(owned.bytes, Pkcs12Error, "pkcs12/bad-input", "the password encoding");
}

function _blockFill(src, blockSize) {
  if (src.length === 0) return Buffer.alloc(0);
  var total = blockSize * Math.ceil(src.length / blockSize);
  var out = Buffer.alloc(total);
  for (var i = 0; i < total; i++) out[i] = src[i % src.length];
  return out;
}

function _p12Kdf(hashName, id, pwBytes, salt, iterations, nBytes) {
  var uv = P12_KDF_UV[hashName], u = uv.u, v = uv.v;
  var D = Buffer.alloc(v, id);
  var sFill = _blockFill(salt, v), pFill = _blockFill(pwBytes, v);
  var I = Buffer.concat([sFill, pFill]);
  guard.secret.zeroizeAll([sFill, pFill], Pkcs12Error, "pkcs12/bad-input", "a key-derivation fill");
  var c = Math.ceil(nBytes / u);
  var out = Buffer.alloc(c * u);
  for (var i = 0; i < c; i++) {
    var A = Buffer.concat([D, I]);
    for (var r = 0; r < iterations; r++) {
      var prev = A;
      A = nodeCrypto.createHash(hashName).update(A).digest();
      guard.secret.zeroize(prev, Pkcs12Error, "pkcs12/bad-input", "a key-derivation intermediate");
    }
    A.copy(out, i * u);
    if (i < c - 1) {
      var B = _blockFill(A, v);
      _kdfStepC(I, B, v);
      guard.secret.zeroize(B, Pkcs12Error, "pkcs12/bad-input", "a key-derivation intermediate");
    }
    guard.secret.zeroize(A, Pkcs12Error, "pkcs12/bad-input", "a key-derivation block");
  }
  guard.secret.zeroize(I, Pkcs12Error, "pkcs12/bad-input", "the key-derivation input block");
  var exact = Buffer.alloc(nBytes);
  out.copy(exact, 0, 0, nBytes);
  guard.secret.zeroize(out, Pkcs12Error, "pkcs12/bad-input", "the key-derivation accumulator");
  return exact;
}

function _kdfStepC(I, B, v) {
  for (var j = 0; j < I.length; j += v) {
    var carry = 1;
    for (var k = v - 1; k >= 0; k--) {
      var sum = I[j + k] + B[k] + carry;
      I[j + k] = sum & 0xff;
      carry = sum >>> 8;
    }
  }
}


function _coerceDer(input, what) {
  return pkix.coerceToDer(input, { pemLabel: null, PemError: PemError, ErrorClass: Pkcs12Error, prefix: "pkcs12" });
}
function _bytes(input, label) {
  return guard.bytes.view(input, Pkcs12Error, "pkcs12/bad-input", label);
}
function _assertMacIter(n, cap) {
  if (typeof n !== "number" || !isFinite(n) || n < 1 || Math.floor(n) !== n) throw _err("pkcs12/bad-input", "MAC iterations must be a positive integer");
  if (n === 1) throw _err("pkcs12/bad-input", "MAC iterations must be greater than 1 (a DEFAULT-1 MacData iterations cannot be DER-encoded, X.690 sec. 11.5)");
  if (n > cap) throw _err("pkcs12/bad-input", "MAC iterations exceeds the cap " + cap);
  return n;
}


function _bagAttributes(bag) {
  var attrs = [];
  if (bag.friendlyName != null) attrs.push(b.sequence([b.oid(O("friendlyName")), b.set([b.bmpString(String(bag.friendlyName))])]));
  if (bag.localKeyId != null) {
    if (bag.localKeyId === "ski") throw _err("pkcs12/bad-input", "localKeyId 'ski' auto-derivation is not yet supported -- supply an explicit Buffer");
    attrs.push(b.sequence([b.oid(O("localKeyId")), b.set([b.octetString(_bytes(bag.localKeyId, "localKeyId"))])]));
  }
  return attrs.length ? b.set(attrs) : null;
}

function _secretTypeOid(id) {
  try { return b.oid(O(id) || id); }
  catch (e) { throw _err("pkcs12/bad-input", "secretTypeId must be a registered name or a dotted-decimal OID string", e); }
}

function _safeBag(bagName, bagValueDer, bag) {
  var children = [b.oid(O(bagName)), b.explicit(0, bagValueDer)];
  var attrs = _bagAttributes(bag);
  if (attrs) children.push(attrs);
  return b.sequence(children);
}

function _buildBag(bag, opts, depth) {
  if (!bag || typeof bag !== "object") throw _err("pkcs12/bad-input", "each bag must be an object with a type");
  if (intrinsic.hasOwn(_BAG_KEYS_BY_TYPE, bag.type)) {
    guard.identifier.assertKnownKeys(bag, _BAG_KEYS_BY_TYPE[bag.type], _err, "pkcs12/bad-input", function (k) {
      return "unknown field " + JSON.stringify(k) + " on a " + JSON.stringify(bag.type) +
        " bag; that field is not read for this bag type";
    });
  }
  switch (bag.type) {
    case "key": {
      var keyDer = _coerceDer(bag.key, "keyBag key");
      try { pkcs8.parse(keyDer); } catch (e) { throw _err("pkcs12/bad-input", "keyBag key is not a well-formed PKCS#8 PrivateKeyInfo", e); }
      return _safeBag("keyBag", keyDer, bag);
    }
    case "shroudedKey": {
      var kDer = _coerceDer(bag.key, "shroudedKey key");
      try { pkcs8.parse(kDer); } catch (e2) { throw _err("pkcs12/bad-input", "shroudedKey key is not a well-formed PKCS#8 PrivateKeyInfo", e2); }
      var enc = bag.encrypt || {};
      var bagPbe = _pbeOpts(enc);
      var pw = _pbePasswordOwned(enc.password != null ? enc.password : opts.password);
      var r;
      try { r = pbes2.pbes2Encrypt(pw.bytes, kDer, bagPbe, _err, "pkcs12"); }
      finally { _wipePw(pw); }
      return _safeBag("pkcs8ShroudedKeyBag", b.sequence([r.algId, b.octetString(r.ct)]), bag);
    }
    case "cert": {
      var certDer = _coerceDer(bag.cert, "certBag cert");
      try { x509.parse(certDer); } catch (e3) { throw _err("pkcs12/bad-input", "certBag cert is not a well-formed X.509 certificate", e3); }
      return _safeBag("certBag", b.sequence([b.oid(O("x509Certificate")), b.explicit(0, b.octetString(certDer))]), bag);
    }
    case "crl": {
      var crlDer = _coerceDer(bag.crl, "crlBag crl");
      try { schemaCrl.parse(crlDer); } catch (e4) { throw _err("pkcs12/bad-input", "crlBag crl is not a well-formed X.509 CRL", e4); }
      return _safeBag("crlBag", b.sequence([b.oid(O("x509CRL")), b.explicit(0, b.octetString(crlDer))]), bag);
    }
    case "secret": {
      if (bag.secretTypeId == null) throw _err("pkcs12/bad-input", "a secret bag needs a secretTypeId");
      var secretValueDer = _reqDer(bag.secretValue, "secretValue");
      return _safeBag("secretBag", b.sequence([_secretTypeOid(bag.secretTypeId), b.explicit(0, secretValueDer)]), bag);
    }
    case "safeContents": {
      if (depth + 1 > C.LIMITS.PKCS12_MAX_BAG_DEPTH) throw _err("pkcs12/bad-input", "safeContents bag nesting exceeds the depth cap " + C.LIMITS.PKCS12_MAX_BAG_DEPTH);
      return _safeBag("safeContentsBag", _buildSafeContents(bag.nested || [], opts, depth + 1), bag);
    }
    default:
      throw _err("pkcs12/bad-input", "unknown bag type " + JSON.stringify(bag.type) + " (key / shroudedKey / cert / crl / secret / safeContents)");
  }
}

var _STORE_CLAIM = ["integrityMode", "mac", "macedBytes"];
function _storeFromBytes(pfx) {
  return guard.parsed.fromTrustedSource(pfx, "pkcs12Store", _STORE_CLAIM, function (bytes) {
    return schemaPkcs12.parse(_coerceDer(bytes, "pfx"));
  }, _err, "pkcs12/bad-input",
  "pfx must be the store's DER bytes, a PEM string, or an unmodified pki.schema.pkcs12.parse result: the MAC is verified over a byte range carried on the object and the bags returned as verified are a separate property of it, so a REBUILT store (Object.assign, spread, a JSON round-trip) could have the two describe different stores and is refused");
}

function _reqDer(input, label) {
  if (input == null) throw _err("pkcs12/bad-input", label + " is required");
  var der = _bytes(input, label);
  var node;
  try { node = asn1.decode(der); } catch (e) { throw _err("pkcs12/bad-input", label + " must be one well-formed DER value", e); }
  if (node.bytes.length !== der.length) throw _err("pkcs12/bad-input", label + " must be exactly one DER value with no trailing bytes");
  return der;
}

function _pbeOpts(enc) {
  guard.identifier.assertKnownKeys(enc, _ENCRYPT_KEYS, _err, "pkcs12/bad-input", function (k) {
    return "unknown encrypt field " + JSON.stringify(k) +
      "; the PBE descriptor is { password?, cipher?, salt?, iterations?, prf? }";
  });
  var cipher = CIPHER_NAME[enc.cipher || "aes-256-cbc"];
  if (!cipher) throw _err("pkcs12/bad-input", "unsupported PBES2 cipher " + JSON.stringify(enc.cipher) + " (aes-128-cbc / aes-192-cbc / aes-256-cbc)");
  return {
    cipher: cipher,
    salt: enc.salt != null ? _bytes(enc.salt, "encrypt salt") : undefined,
    iterations: enc.iterations,
    prf: enc.prf,
  };
}

function _buildSafeContents(bags, opts, depth) {
  if (intrinsic.isArray(bags) && bags.length > C.LIMITS.PKCS12_MAX_ELEMENTS) throw _err("pkcs12/bad-input", "a SafeContents exceeds the element cap " + C.LIMITS.PKCS12_MAX_ELEMENTS);
  var dense = pkiBuild.reqDenseArray(bags, "bags", _err, "pkcs12/bad-input");
  return b.sequence(dense.map(function (bag) { return _buildBag(bag, opts, depth); }));
}

async function _buildAuthSafeElement(sc, opts) {
  if (!sc || typeof sc !== "object") throw _err("pkcs12/bad-input", "each safeContents entry must be an object");
  var hasRecipients = sc.recipients !== undefined;
  var hasEncrypt = sc.encrypt !== undefined;
  if (hasEncrypt && hasRecipients) throw _err("pkcs12/bad-input", "a safeContents cannot combine encrypt (password) and recipients (public-key) -- one ContentInfo is one privacy type (RFC 7292 sec. 4.1)");
  guard.identifier.assertKnownKeys(sc, hasRecipients ? _SAFE_RECIPIENTS_KEYS : (hasEncrypt ? _SAFE_PASSWORD_KEYS : _SAFE_PLAINTEXT_KEYS),
    _err, "pkcs12/bad-input", function (k) {
      return "unknown safeContents field " + JSON.stringify(k) + " for a " +
        (hasRecipients ? "public-key safe; it takes { bags, recipients, contentEncryptionAlgorithm? }"
          : hasEncrypt ? "password safe; it takes { bags, encrypt } and its cipher comes from encrypt.cipher"
            : "plaintext safe; it takes { bags }, and a privacy directive must be encrypt or recipients");
    });
  var safeContentsDer = _buildSafeContents(sc.bags || [], opts, 0);
  if (hasRecipients) {
    if (!Array.isArray(sc.recipients) || !sc.recipients.length) throw _err("pkcs12/bad-input", "safeContents.recipients must be a non-empty array of recipient descriptors (RFC 5652 sec. 6.1)");
    sc.recipients.forEach(function (r) {
      if (!r || typeof r !== "object" || r.cert == null) throw _err("pkcs12/bad-input", "a public-key privacy recipient must be a certificate recipient { cert } (a password or KEK recipient is not public-key privacy and cannot be reopened by pkcs12.open)");
    });
    var alg = sc.contentEncryptionAlgorithm || "aes-256-cbc";
    if (alg !== "aes-128-cbc" && alg !== "aes-192-cbc" && alg !== "aes-256-cbc") throw _err("pkcs12/bad-input", "a public-key privacy safe requires an AES-CBC content cipher (aes-128|192|256-cbc), not " + JSON.stringify(alg) + " -- RFC 7292 sec. 4.1 admits only id-envelopedData, not GCM/AuthEnvelopedData");
    var envCi = await cms.encrypt(safeContentsDer, sc.recipients, { contentEncryptionAlgorithm: alg, contentType: "data" });
    return b.raw(envCi);
  }
  if (!hasEncrypt) {
    return b.sequence([b.oid(O("data")), b.explicit(0, b.octetString(safeContentsDer))]);
  }
  if (!sc.encrypt || typeof sc.encrypt !== "object") throw _err("pkcs12/bad-input", "safeContents.encrypt must be an object { password? } (RFC 7292 sec. 5.1) -- omit it entirely for a plaintext safe");
  var safePbe = _pbeOpts(sc.encrypt);
  var pw = _pbePasswordOwned(sc.encrypt.password != null ? sc.encrypt.password : opts.password);
  var r;
  try { r = pbes2.pbes2Encrypt(pw.bytes, safeContentsDer, safePbe, _err, "pkcs12"); }
  finally { _wipePw(pw); }
  var eci = b.sequence([b.oid(O("data")), r.algId, b.contextPrimitive(0, r.ct)]);
  var encData = b.sequence([b.integer(0n), eci]);
  return b.sequence([b.oid(O("encryptedData")), b.explicit(0, encData)]);
}


async function _buildMacData(macOpts, sharedPassword, authSafeDer) {
  var password = macOpts.password != null ? macOpts.password : sharedPassword;
  var algorithm = macOpts.algorithm || "hmac";
  var hash = macOpts.hash || "sha256";
  var salt = macOpts.salt != null ? _bytes(macOpts.salt, "mac salt") : nodeCrypto.randomBytes(MAC_SALT_BYTES);
  if (salt.length === 0) throw _err("pkcs12/bad-input", "the MAC salt must be non-empty (RFC 9579 sec. 4c)");
  if (salt.length > C.LIMITS.PBKDF2_MAX_SALT) throw _err("pkcs12/bad-input", "the MAC salt exceeds the " + C.LIMITS.PBKDF2_MAX_SALT + "-octet cap");

  if (algorithm === "hmac") {
    var node = DIGEST_NAME[hash];
    if (!node || !P12_KDF_UV[node]) throw _err("pkcs12/unsupported-algorithm", "unsupported classic MAC hash " + JSON.stringify(hash) + " (sha1 / sha256 / sha384 / sha512)");
    var iter = _assertMacIter(macOpts.iterations == null ? DEFAULT_MAC_ITER : macOpts.iterations, CLASSIC_MAC_MAX_ITERATIONS);
    var macPw = _p12PasswordOwned(password);
    var macKey = _p12Kdf(node, 3, macPw.bytes, salt, iter, P12_KDF_UV[node].u);
    if (macPw.owned) guard.secret.zeroize(macPw.bytes, Pkcs12Error, "pkcs12/bad-input", "the password encoding");
    try {
      var digest = nodeCrypto.createHmac(node, macKey).update(authSafeDer).digest();
      var digestInfo = b.sequence([b.sequence([b.oid(O(node)), b.nullValue()]), b.octetString(digest)]);
      return b.sequence([digestInfo, b.octetString(salt), b.integer(BigInt(iter))]);
    } finally {
      guard.secret.zeroize(macKey, Pkcs12Error, "pkcs12/bad-input", "the password-derived MAC key");
    }
  }
  if (algorithm === "pbmac1") {
    var prf = PBMAC1_PRF[hash];
    if (!prf) throw _err("pkcs12/unsupported-algorithm", "PBMAC1 requires a SHA-256/384/512 digest (RFC 9579 sec. 5/7 forbids a <= 160-bit digest, e.g. SHA-1)");
    var iter2 = _assertMacIter(macOpts.iterations == null ? DEFAULT_PBMAC1_ITER : macOpts.iterations, C.LIMITS.PBKDF2_MAX_ITERATIONS);
    var keyLen = macOpts.keyLength != null ? macOpts.keyLength : prf.keyLen;
    if (typeof keyLen !== "number" || !Number.isInteger(keyLen) || keyLen < 20 || keyLen > MAX_PBMAC1_KEYLEN) throw _err("pkcs12/bad-input", "PBMAC1 keyLength must be an integer in [20, " + MAX_PBMAC1_KEYLEN + "] (RFC 9579 sec. 9)");
    var macPw2 = _pbePasswordOwned(password);
    var mac;
    try { mac = await pbes2.pbmac1(macPw2.bytes, salt, iter2, keyLen, prf.wc, prf.wc, authSafeDer); }
    finally { _wipePw(macPw2); }
    var desc = { salt: salt, iterationCount: iter2, keyLength: keyLen, prfName: prf.prfName, macName: prf.prfName };
    var digestInfo2 = b.sequence([pbes2.pbmac1AlgId(desc), b.octetString(mac)]);
    return b.sequence([digestInfo2, b.octetString(salt), b.integer(BigInt(iter2))]);
  }
  throw _err("pkcs12/bad-input", "opts.mac.algorithm must be 'hmac' or 'pbmac1', got " + JSON.stringify(algorithm));
}


function _specForm(spec) {
  var isObject = !!spec && typeof spec === "object" && !Buffer.isBuffer(spec);
  var safeContents = isObject ? spec.safeContents : null;
  var full = intrinsic.isArray(safeContents);
  return { isObject: isObject, full: full, safeContents: full ? safeContents : null };
}

function _normalizeSpec(spec, opts, form) {
  if (form.full) return form.safeContents;
  if (spec && (spec.key != null || spec.cert != null)) {
    var recipientCerts = opts.recipientCerts;
    var enveloped = recipientCerts != null;
    if (enveloped && (!intrinsic.isArray(recipientCerts) || !recipientCerts.length)) throw _err("pkcs12/bad-input", "opts.recipientCerts must be a non-empty array of recipient certificates");
    var certBags = [];
    if (spec.cert != null) certBags.push({ type: "cert", cert: spec.cert, friendlyName: spec.friendlyName, localKeyId: spec.localKeyId });
    if (spec.ca != null && !Array.isArray(spec.ca)) throw _err("pkcs12/bad-input", "spec.ca must be an array of certificates");
    (spec.ca || []).forEach(function (ca) { certBags.push({ type: "cert", cert: ca }); });
    var sc = [];
    if (enveloped) {
      var bags = certBags.slice();
      if (spec.key != null) bags.push({ type: "key", key: spec.key, friendlyName: spec.friendlyName, localKeyId: spec.localKeyId });
      sc.push({ recipients: recipientCerts.map(function (c) { return { cert: c }; }), bags: bags });
      return sc;
    }
    if (certBags.length) sc.push({ encrypt: { password: opts.password }, bags: certBags });
    if (spec.key != null) sc.push({ bags: [{ type: "shroudedKey", key: spec.key, encrypt: { password: opts.password }, friendlyName: spec.friendlyName, localKeyId: spec.localKeyId }] });
    return sc;
  }
  throw _err("pkcs12/bad-input", "spec must be { safeContents: [...] } or { key, cert, ca? }");
}


/**
 * @primitive pki.pkcs12.build
 * @signature pki.pkcs12.build(spec, opts?) -> Promise<Buffer|string>
 * @since 0.3.11
 * @status stable
 * @spec RFC 7292, RFC 9579, RFC 8018
 * @related pki.schema.pkcs12.parse, pki.pkcs12.verifyMac
 *
 * Build a PKCS#12 (.p12 / .pfx) store with password OR public-key integrity. `spec` is either the
 * OpenSSL-style convenience form `{ key, cert, ca?, friendlyName?, localKeyId? }` (one PBES2-encrypted cert
 * safe plus one shrouded-key safe) or the full form `{ safeContents: [...] }`, where each element is a
 * plaintext or PBES2-encrypted `SafeContents` of key / shroudedKey / cert / crl / secret / nested
 * safeContents bags. Keys and certs are validated before wrapping. Password integrity (the default) MACs the
 * AuthenticatedSafe with a classic Appendix B HMAC or an RFC 9579 PBMAC1. Public-key integrity
 * (`opts.integrity.mode: "public-key"`) instead wraps the AuthenticatedSafe in a CMS SignedData: a
 * signature from a keypair, no MacData (RFC 7292 sec. 4). Privacy (PBES2 bag encryption via `password`) is
 * independent of the integrity mode. The store is re-parsed before return.
 *
 * @opts
 *   - `password` -- the shared privacy + integrity password (string / Buffer / Uint8Array).
 *   - `mac` -- `false` for a MAC-less store, or `{ algorithm: 'hmac'(default)|'pbmac1', hash: 'sha256'(default)|'sha1'|'sha384'|'sha512', salt?, iterations? }`. `keyLength` is a `pbmac1` field: the classic Appendix B derivation produces a key at the hash's own output length, and naming one under `hmac` is refused.
 *   - `integrity` -- `{ mode: 'public-key', signer: { cert, key, digestAlgorithm?, pss? } | signers: [ ... ], sid?, signingTime?, certificates? }` for public-key integrity (a CMS SignedData authSafe over any `pki.cms.sign` signer algorithm, no MacData). Combining it with a truthy `mac` is rejected.
 *   - `recipientCerts` -- (public-key privacy convenience) `[certDer|PEM, ...]`; the convenience-form cert + key are placed in one recipient-enveloped safe (a plaintext keyBag). For the full form, set per-`safeContents` `recipients: [{ cert }, ...]` -- CERTIFICATE recipients only (RSA-OAEP / ECDH / X25519 / X448 / ML-KEM, dispatched off the cert key); a password or KEK recipient is not public-key privacy and is rejected -- with an optional `contentEncryptionAlgorithm` (`aes-128|192|256-cbc`, default 256; GCM/AEAD rejected). `encrypt` (password) and `recipients` (public-key) on the same safe is rejected; privacy is independent of integrity.
 *   - `pem` (boolean) -- return a PEM `PKCS12` string instead of DER.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [
 *     { type: 'cert', cert: signerCertDer },
 *     { type: 'shroudedKey', key: signerKeyPkcs8, encrypt: { password: 'changeit' } } ] }] },
 *     { password: 'changeit', mac: { algorithm: 'hmac', hash: 'sha256' } });
 */
function build(spec, opts) {
  return guard.bytes.fixedCall(Pkcs12Error, "pkcs12/bad-input", [
    [spec, "the PKCS#12 spec"], [opts, "pki.pkcs12.build options"],
  ], _build);
}

async function _build(spec, opts) {
  opts = opts || {};
  var form = _specForm(spec);
  if (form.isObject) {
    guard.identifier.assertKnownKeys(spec, form.full ? _BUILD_SPEC_FULL_KEYS : _BUILD_SPEC_SHORTHAND_KEYS,
      _err, "pkcs12/bad-input", function (k) {
        return "unknown PKCS#12 spec field " + JSON.stringify(k) + " for the " +
          (form.full ? "safeContents form; the shorthand fields belong to { key, cert, ca } and are not read here"
                     : "shorthand form; pass safeContents instead to build the safes yourself");
      });
  }
  guard.identifier.assertKnownKeys(opts, form.full ? _BUILD_OPTS_FULL : _BUILD_OPTS_SHORTHAND, _err, "pkcs12/bad-input",
    function (k) {
      return "pki.pkcs12.build has an unknown option " + JSON.stringify(k) +
        (form.full && k === "recipientCerts"
          ? " for the safeContents form; the full form carries privacy per entry, as safeContents[i].recipients"
          : "");
    });
  if (opts.integrity != null) {
    if (typeof opts.integrity !== "object" || Array.isArray(opts.integrity)) throw _err("pkcs12/bad-input", "opts.integrity must be an object { mode, signer|signers, ... }");
    guard.identifier.assertKnownKeys(opts.integrity, _INTEGRITY_OPTS, _err, "pkcs12/bad-input", "opts.integrity has an unknown option ");
    if (opts.integrity.mode !== "public-key") {
      throw _err("pkcs12/bad-integrity-mode", "opts.integrity.mode must be \"public-key\" (the only mode it selects); omit opts.integrity for password integrity, got " + JSON.stringify(opts.integrity.mode));
    }
  }
  var pubKey = opts.integrity != null;
  if (pubKey && opts.mac != null && opts.mac !== false) throw _err("pkcs12/bad-integrity-mode", "public-key integrity has no MacData -- do not combine opts.mac with opts.integrity.mode 'public-key' (RFC 7292 sec. 4)");
  var safeContentsSpecs = _normalizeSpec(spec, opts, form);
  if (!Array.isArray(safeContentsSpecs) || !safeContentsSpecs.length) throw _err("pkcs12/bad-input", "the store has no safe contents");
  var elements = [];
  for (var i = 0; i < safeContentsSpecs.length; i++) elements.push(await _buildAuthSafeElement(safeContentsSpecs[i], opts));
  var authSafeDer = b.sequence(elements);

  var pfx;
  if (pubKey) {
    var ig = opts.integrity;
    if (ig.signers != null && ig.signer != null) throw _err("pkcs12/bad-input", "supply exactly one of opts.integrity.signer or opts.integrity.signers, not both");
    var signers = ig.signers != null ? ig.signers : (ig.signer != null ? [ig.signer] : null);
    if (!Array.isArray(signers) || !signers.length) throw _err("pkcs12/bad-input", "public-key integrity requires opts.integrity.signer or opts.integrity.signers (a cms.sign signer descriptor)");
    for (var sx = 0; sx < signers.length; sx++) {
      var sd = signers[sx];
      if (sd == null || typeof sd !== "object" || Buffer.isBuffer(sd)) throw _err("pkcs12/bad-input", "each opts.integrity signer must be a descriptor object");
      var keyOnly = sd.cert == null && sd.spki != null;
      guard.identifier.assertKnownKeys(sd, keyOnly ? cmsSign.KNOWN_SIGNER_KEY_ONLY_KEYS : cmsSign.KNOWN_SIGNER_CERT_KEYS,
        _err, "pkcs12/bad-input", function (k) {
          return "unknown opts.integrity signer field " + JSON.stringify(k) + " for the " + (keyOnly
            ? "key-only form; it takes { key, spki, keyIdentifier } plus the signature parameters"
            : "certificate form; it takes { key, cert } plus the signature parameters");
        });
    }
    var authSafeCi = await cms.sign(authSafeDer, signers, { eContentType: "data", detached: false, certificates: ig.certificates !== false, sid: ig.sid, signingTime: ig.signingTime });
    pfx = b.sequence([b.integer(3n), b.raw(authSafeCi)]);
  } else {
    var pfxChildren = [b.integer(3n), b.sequence([b.oid(O("data")), b.explicit(0, b.octetString(authSafeDer))])];
    if (opts.mac != null && opts.mac !== false && (typeof opts.mac !== "object" || intrinsic.isArray(opts.mac))) throw _err("pkcs12/bad-input", "opts.mac must be false or a { algorithm, hash, salt, iterations, keyLength } object");
    if (opts.mac != null && opts.mac !== false) {
      var macAlg = opts.mac.algorithm == null ? "hmac" : opts.mac.algorithm;
      var macKeys = macAlg === "hmac" ? _MAC_KEYS_HMAC : macAlg === "pbmac1" ? _MAC_KEYS_PBMAC1 : _MAC_KEYS;
      guard.identifier.assertKnownKeys(opts.mac, macKeys, _err, "pkcs12/bad-input", function (k) {
        return "opts.mac has an unknown option " + JSON.stringify(k) +
          (macAlg === "hmac" && k === "keyLength"
            ? " for the classic HMAC algorithm; its key is derived at the hash's own output length, and only pbmac1 takes a keyLength"
            : "");
      });
    }
    if (opts.mac !== false) pfxChildren.push(await _buildMacData(opts.mac || {}, opts.password, authSafeDer));
    pfx = b.sequence(pfxChildren);
  }

  try { schemaPkcs12.parse(pfx); } catch (e) { throw _err("pkcs12/bad-input", "the produced PKCS#12 store did not re-parse (build bug)", e); }
  return opts.pem ? schemaPkcs12.pemEncode(pfx, "PKCS12") : pfx;
}

/**
 * @primitive pki.pkcs12.verifyMac
 * @signature pki.pkcs12.verifyMac(pfx, password, opts?) -> Promise<{ valid, macAlgorithm, macAlgorithmName, iterationCount }>
 * @since 0.3.11
 * @status stable
 * @spec RFC 7292 sec. 5.1, RFC 9579
 * @defends pkcs12-mac-forgery (CWE-347)
 * @related pki.pkcs12.build, pki.schema.pkcs12.parse
 *
 * Verify a password-integrity PKCS#12 store's MAC. `pfx` is the store's DER `Buffer`, a PEM string, or an
 * unmodified `pki.schema.pkcs12.parse` result. A REBUILT parsed store is refused: the MAC is verified over
 * a byte range the object carries, and the parser's mark is what says that range and the store it describes
 * came from one place. `Object.assign`, spread and a JSON round-trip drop the mark. The password is BMPString+NULL encoded (RFC 7292 App. B.1), the MAC is
 * recomputed over the store's exact AuthenticatedSafe byte range (`macedBytes`) using the store's own MAC
 * parameters -- the classic Appendix B (ID=3) HMAC or the RFC 9579 PBMAC1 -- and constant-time-compared to
 * the stored MAC value. The verdict's `valid` is the password match, and `macAlgorithm` (`hmac` or `pbmac1`),
 * `macAlgorithmName` (the digest / scheme, e.g. `sha1`, `sha256`), and `iterationCount` name the integrity
 * algorithm the store used, so a caller can reject a legacy SHA-1 MAC by inspecting them rather than
 * accepting any `valid` store. Throws `Pkcs12Error` on a MAC-less or public-key-integrity store, or an
 * unsupported MAC algorithm (never a falsy verdict standing in for an error).
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var p12 = await pki.pkcs12.build({ key: signerKeyPkcs8, cert: signerCertDer }, { password: 'changeit' });
 *   var res = await pki.pkcs12.verifyMac(p12, 'changeit');   // { valid, macAlgorithm, macAlgorithmName, iterationCount }
 */
async function verifyMac(pfx, password, opts) {
  if (opts != null && typeof opts === "object" && !Buffer.isBuffer(opts)) {
    guard.identifier.assertKnownKeys(opts, _VERIFY_MAC_OPTS, _err, "pkcs12/bad-input", "pki.pkcs12.verifyMac has an unknown option ");
  }
  var m = _storeFromBytes(pfx);
  var valid = await _verifyMacOfStore(m, password, opts);
  var isHmac = m.mac.kind === "hmac";
  return {
    valid: valid,
    macAlgorithm: m.mac.kind,
    macAlgorithmName: isHmac ? _toLower(m.mac.hashName || "") : m.mac.pbmac1.schemeName,
    iterationCount: isHmac ? m.mac.iterations : m.mac.pbmac1.kdf.iterationCount,
  };
}

async function _verifyMacOfStore(m, password, opts) {
  opts = opts || {};
  if (m.integrityMode !== "password" || !m.mac) throw _err("pkcs12/bad-input", "the store carries no password MAC (integrityMode " + m.integrityMode + ")");
  var expected = m.mac.macValue;
  var computed;
  if (m.mac.kind === "hmac") {
    var node = _toLower(m.mac.hashName || "");
    if (!P12_KDF_UV[node]) throw _err("pkcs12/unsupported-algorithm", "unsupported classic MAC hash " + m.mac.hashName);
    _capWork(m.mac.iterations, m.mac.macSalt, opts, undefined, CLASSIC_MAC_MAX_ITERATIONS);
    var vMacPw = _p12PasswordOwned(password);
    var macKey = _p12Kdf(node, 3, vMacPw.bytes, m.mac.macSalt, m.mac.iterations, P12_KDF_UV[node].u);
    if (vMacPw.owned) guard.secret.zeroize(vMacPw.bytes, Pkcs12Error, "pkcs12/bad-input", "the password encoding");
    try { computed = nodeCrypto.createHmac(node, macKey).update(m.macedBytes).digest(); }
    finally { guard.secret.zeroize(macKey, Pkcs12Error, "pkcs12/bad-input", "the password-derived MAC key"); }
  } else {
    var kdf = m.mac.pbmac1.kdf;
    var prfWc = PRF_WC[kdf.prfName];
    var macWc = PRF_WC[m.mac.pbmac1.schemeName];
    if (!prfWc) throw _err("pkcs12/unsupported-algorithm", "unsupported PBMAC1 prf " + kdf.prfName);
    if (!macWc) throw _err("pkcs12/unsupported-algorithm", "unsupported PBMAC1 messageAuthScheme " + m.mac.pbmac1.schemeName);
    if (prfWc === "SHA-1" || macWc === "SHA-1") throw _err("pkcs12/unsupported-algorithm", "PBMAC1 with a <= 160-bit digest (SHA-1) is refused (RFC 9579 sec. 5/7)");
    _capWork(kdf.iterationCount, kdf.salt, opts, kdf.keyLength, C.LIMITS.PBKDF2_MAX_ITERATIONS);
    var vPw = _pbePasswordOwned(password);
    try { computed = await pbes2.pbmac1(vPw.bytes, kdf.salt, kdf.iterationCount, kdf.keyLength, prfWc, macWc, m.macedBytes); }
    finally { _wipePw(vPw); }
  }
  return computed.length === expected.length && guard.crypto.constantTimeEqual(computed, expected);
}

function _capWork(iterations, salt, opts, keyLength, hardCap) {
  var cap = hardCap;
  if (opts.maxIterations != null) {
    if (typeof opts.maxIterations !== "number" || !isFinite(opts.maxIterations) || opts.maxIterations < 1 || Math.floor(opts.maxIterations) !== opts.maxIterations) throw _err("pkcs12/bad-input", "maxIterations must be a positive integer");
    cap = Math.min(opts.maxIterations, cap);
  }
  if (iterations > cap) throw _err("pkcs12/iteration-limit", "the MAC iteration count " + iterations + " exceeds the cap " + cap);
  if (salt && salt.length > C.LIMITS.PBKDF2_MAX_SALT) throw _err("pkcs12/bad-input", "the MAC salt exceeds the " + C.LIMITS.PBKDF2_MAX_SALT + "-octet cap");
  if (keyLength != null && (keyLength < 20 || keyLength > MAX_PBMAC1_KEYLEN)) throw _err("pkcs12/bad-input", "the PBMAC1 keyLength must be in [20, " + MAX_PBMAC1_KEYLEN + "] (RFC 9579 sec. 9)");
}

/**
 * @primitive pki.pkcs12.open
 * @signature pki.pkcs12.open(pfx, password, opts?) -> Promise<OpenResult>
 * @since 0.3.12
 * @status stable
 * @spec RFC 7292 sec. 5.1, RFC 9579, RFC 8018
 * @defends pkcs12-unauthenticated-decrypt (CWE-347), pbes2-padding-oracle (CWE-208)
 * @related pki.pkcs12.build, pki.pkcs12.verifyMac, pki.schema.pkcs12.parse
 *
 * Read a PKCS#12 store: verify its integrity first (a password store's MAC, or a public-key store's CMS
 * SignedData signature, per RFC 7292 sec. 4 / 5.1, so no bag from a store whose integrity check fails is trusted),
 * then decrypt every PBES2 privacy safe and pkcs8ShroudedKeyBag with the password, and every id-envelopedData
 * (public-key privacy) safe with `opts.recipientKey` (RFC 7292 sec. 3.1, via `pki.cms.decrypt`), returning a
 * structured bundle `{ integrityMode, macVerified, signers, keys, certs, crls, secrets }` with each private key as PKCS#8
 * `PrivateKeyInfo` DER (re-validated), each certificate / CRL / secret as raw DER, all carrying their
 * `friendlyName` / `localKeyId` for pairing. `pfx` is the store's DER `Buffer`, a PEM string, or an
 * unmodified `pki.schema.pkcs12.parse` result; a rebuilt parsed store is refused, since the bytes whose
 * integrity is checked and the bags returned as checked are separate properties of it.
 *
 * A MAC-less store is refused (`pkcs12/no-integrity`) unless `opts.allowUnauthenticated` is set. A public-key
 * integrity store is verified through `pki.cms.verify` before any bag is trusted; a signature failure is
 * `pkcs12/signature-invalid`, and `signers` carries the per-signer verdict `[{ ok, sid, cert }]` (`null` in
 * password / MAC-less mode). The signer is surfaced, never trust-chained: anchoring `signers[i].cert` to a
 * trust root is the caller's `pki.path.validate` step (the out-of-path signer contract). Privacy is
 * independent of integrity, so the bag `password` still decrypts a public-key store's bags; a wrong bag
 * password there is the uniform `pkcs12/decrypt-failed` (no MAC to catch it first). Bags encrypted under
 * PBES2 (AES-CBC), or the RFC 7292 App. C legacy schemes an `openssl pkcs12 -legacy` store uses (3-key /
 * 2-key Triple-DES-CBC and 40-/128-bit RC2-CBC, the App. B KDF over the BMPString password, RC2 via an in-tree
 * RFC 2268 cipher), are decrypted; the legacy RC4 schemes are named and refused.
 *
 * @opts
 *   - `allowUnauthenticated` (boolean): open a MAC-less store anyway (result carries `macVerified: false`).
 *   - `signerCerts` (array of cert DER): signer certificate(s) for a public-key store built with `certificates: false` (forwarded to `pki.cms.verify`).
 *   - `recipientKey` (PKCS#8 DER|PEM) + `recipientCert` (cert DER|PEM, or `recipientIndex`): decrypt an id-envelopedData (public-key privacy) safe. The recipient key is a privacy credential only; a wrong key / tampered envelope is the uniform `pkcs12/decrypt-failed`, and an enveloped safe with no `recipientKey` is `pkcs12/no-recipient-key`.
 *   - `maxIterations` (number): lower the PBKDF2 / MAC iteration cap for this call (downward-only).
 *   - `keys` (string): `der` (default) or `crypto` (also `pki.key.import` each private key to a CryptoKey).
 *   - `importAlgorithm` -- forwarded to `pki.key.import` for the ambiguous RSA / EC arms when `keys: crypto`.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var signerKeyPkcs8 = await pki.key.export(pair.privateKey);
 *   var signerCertDer = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: signerKeyPkcs8 });
 *   var p12 = await pki.pkcs12.build({ key: signerKeyPkcs8, cert: signerCertDer }, { password: 'changeit' });
 *   var store = await pki.pkcs12.open(p12, 'changeit');
 *   var keyDer = store.keys[0].pkcs8, certDer = store.certs[0].cert;
 */
async function open(pfx, password, opts) {
  opts = opts || {};
  guard.identifier.assertKnownKeys(opts, _OPEN_OPTS, _err, "pkcs12/bad-input", "pki.pkcs12.open has an unknown option ");
  if (opts.maxIterations != null &&(typeof opts.maxIterations !== "number" || !isFinite(opts.maxIterations) || opts.maxIterations < 1 || Math.floor(opts.maxIterations) !== opts.maxIterations)) {
    throw _err("pkcs12/bad-input", "maxIterations must be a positive integer");
  }
  var m = _storeFromBytes(pfx);
  var macVerified = false;
  var signers = null;
  if (m.integrityMode === "public-key") {
    var res = await cms.verify(m.authSafeSigned, { certs: opts.signerCerts });
    if (!res.valid) throw _err("pkcs12/signature-invalid", "the PKCS#12 SignedData signature did not verify (an untrusted or tampered store)");
    signers = res.signers;
  } else if (m.integrityMode === "password") {
    macVerified = await _verifyMacOfStore(m, password, opts);
    if (!macVerified) throw _err("pkcs12/mac-mismatch", "the PKCS#12 MAC did not verify (wrong password or a tampered store)");
  } else if (!opts.allowUnauthenticated) {
    throw _err("pkcs12/no-integrity", "the store carries no integrity MAC (integrityMode " + m.integrityMode + "); set opts.allowUnauthenticated to open it anyway");
  }
  var out = { valid: macVerified || m.integrityMode === "public-key", integrityMode: m.integrityMode, macVerified: macVerified, signers: signers, keys: [], certs: [], crls: [], secrets: [] };
  var i;
  var kdfBudget = { rounds: KDF_MAX_ROUNDS };
  for (i = 0; i < m.safeBags.length; i++) _openBag(m.safeBags[i], password, opts, out, 0, kdfBudget);
  for (i = 0; i < m.encryptedSafes.length; i++) await _openEncryptedSafe(m.encryptedSafes[i], password, opts, out, 0, kdfBudget);
  if (opts.keys === "crypto") {
    for (i = 0; i < out.keys.length; i++) out.keys[i].key = await key.import(out.keys[i].pkcs8, { algorithm: opts.importAlgorithm });
  }
  return out;
}

function _openBag(bag, password, opts, out, depth, budget) {
  switch (bag.type) {
    case "keyBag":
      try { pkcs8.parse(bag.keyDer); }
      catch (e) { throw _err("pkcs12/bad-der", "a plaintext keyBag PrivateKeyInfo is not canonical DER", e); }
      out.keys.push({ pkcs8: bag.keyDer, encrypted: false, friendlyName: bag.friendlyName, localKeyId: bag.localKeyId });
      break;
    case "pkcs8ShroudedKeyBag":
      out.keys.push({ pkcs8: _decryptShroudedKey(bag.encrypted, password, opts, budget), encrypted: true, friendlyName: bag.friendlyName, localKeyId: bag.localKeyId });
      break;
    case "certBag":
      out.certs.push({ cert: bag.certValue, certType: bag.certType, friendlyName: bag.friendlyName, localKeyId: bag.localKeyId });
      break;
    case "crlBag":
      out.crls.push({ crl: bag.crlValue, crlType: bag.crlType, friendlyName: bag.friendlyName, localKeyId: bag.localKeyId });
      break;
    case "secretBag":
      out.secrets.push({ secretTypeId: bag.secretTypeId, secretTypeName: bag.secretTypeName, secretValue: bag.secretValue, friendlyName: bag.friendlyName, localKeyId: bag.localKeyId });
      break;
    case "safeContentsBag":
      if (depth + 1 > C.LIMITS.PKCS12_MAX_BAG_DEPTH) throw _err("pkcs12/too-deep", "safeContentsBag nesting exceeds the depth cap " + C.LIMITS.PKCS12_MAX_BAG_DEPTH);
      for (var n = 0; n < (bag.nested || []).length; n++) _openBag(bag.nested[n], password, opts, out, depth + 1, budget);
      break;
    default:
      throw _err("pkcs12/bad-input", "unexpected bag type " + bag.type);
  }
}

var LEGACY_PBE = Object.create(null);
LEGACY_PBE[O("pbeWithSHAAnd3-KeyTripleDES-CBC")] = { cipher: "des-ede3-cbc", keyLen: 24, ivLen: 8, hash: "sha1" };
LEGACY_PBE[O("pbeWithSHAAnd2-KeyTripleDES-CBC")] = { cipher: "des-ede-cbc", keyLen: 16, ivLen: 8, hash: "sha1" };
LEGACY_PBE[O("pbeWithSHAAnd128BitRC2-CBC")] = { rc2: 128, keyLen: 16, ivLen: 8, hash: "sha1" };
LEGACY_PBE[O("pbeWithSHAAnd40BitRC2-CBC")] = { rc2: 40, keyLen: 5, ivLen: 8, hash: "sha1" };
LEGACY_PBE[O("pbeWithSHAAnd128BitRC4")] = { rc4: true };
LEGACY_PBE[O("pbeWithSHAAnd40BitRC4")] = { rc4: true };

function _decryptLegacyPbe(ea, ct, password, opts, budget) {
  var scheme = LEGACY_PBE[ea.oid];
  if (!scheme) throw _err("pkcs12/unsupported-algorithm", "the bag uses " + (ea.name || ea.oid) + " (only RFC 8018 PBES2 and the RFC 7292 App. C 3DES / RC2 schemes are decrypted; re-export with -keypbe/-certpbe AES-256-CBC)");
  if (scheme.rc4) throw _err("pkcs12/unsupported-algorithm", "the bag uses " + ea.name + " -- RC4 legacy PBE is not supported; re-export with -keypbe/-certpbe AES-256-CBC or PBE-SHA1-3DES");
  var salt, iterations;
  try {
    var params = asn1.decode(ea.parameters, { ber: true });
    if (params.tagNumber !== asn1.TAGS.SEQUENCE || !params.children || params.children.length < 2) throw _err("pkcs12/bad-algorithm-parameters", "malformed pkcs-12PbeParams (RFC 7292 App. C)");
    salt = Buffer.from(asn1.read.octetString(params.children[0]));
    iterations = guard.range.positiveInt31(asn1.read.integer(params.children[1]), _err, "pkcs12/bad-algorithm-parameters", "legacy PBE iterations");
  } catch (e) {
    if (e && e.isPkcs12Error) throw e;
    throw _err("pkcs12/bad-algorithm-parameters", "malformed pkcs-12PbeParams (RFC 7292 App. C)", e);
  }
  var cap = opts.maxIterations != null ? Math.min(opts.maxIterations, CLASSIC_MAC_MAX_ITERATIONS) : CLASSIC_MAC_MAX_ITERATIONS;
  if (iterations > cap) throw _err("pkcs12/iteration-limit", "the legacy PBE iteration count " + iterations + " exceeds the cap " + cap);
  if (salt.length > C.LIMITS.PBKDF2_MAX_SALT) throw _err("pkcs12/bad-input", "the legacy PBE salt exceeds the " + C.LIMITS.PBKDF2_MAX_SALT + "-octet cap");
  var u = P12_KDF_UV[scheme.hash].u;
  budget.rounds -= (Math.ceil(scheme.keyLen / u) + Math.ceil(scheme.ivLen / u)) * iterations;
  if (budget.rounds < 0) throw _err("pkcs12/iteration-limit", "the store's aggregate legacy PBE key-derivation work exceeds the budget (a hostile many-bag store)");
  var p12pw = _p12PasswordOwned(password);
  var keyM = _p12Kdf(scheme.hash, 1, p12pw.bytes, salt, iterations, scheme.keyLen);
  var iv = _p12Kdf(scheme.hash, 2, p12pw.bytes, salt, iterations, scheme.ivLen);
  if (p12pw.owned) guard.secret.zeroize(p12pw.bytes, Pkcs12Error, "pkcs12/bad-input", "the password encoding");
  try {
    if (scheme.rc2) return rc2.cbcDecrypt(keyM, scheme.rc2, iv, ct, _err, "pkcs12/decrypt-failed");
    var d = nodeCrypto.createDecipheriv(scheme.cipher, keyM, iv);
    return guard.secret.cipherFinish(d, ct, Pkcs12Error, "pkcs12/bad-input", "the recovered safe contents");
  } catch (_e) { throw _err("pkcs12/decrypt-failed", "decryption failed"); }
  finally { guard.secret.zeroize(keyM, Pkcs12Error, "pkcs12/bad-input", "the password-derived decryption key"); }
}

function _decryptBag(ea, ct, password, opts, budget) {
  if (ea.oid === O("pbes2")) {
    var pw = _pbePasswordOwned(password);
    try { return pbes2.pbes2Decrypt(pw.bytes, ea.parameters, ct, opts, _err, "pkcs12", budget); }
    finally { _wipePw(pw); }
  }
  return _decryptLegacyPbe(ea, ct, password, opts, budget);
}

function _decryptShroudedKey(encrypted, password, opts, budget) {
  var der = _decryptBag(encrypted.encryptionAlgorithm, encrypted.encryptedData, password, opts, budget);
  try { pkcs8.parse(der); } catch (_e) { throw _err("pkcs12/decrypt-failed", "decryption failed"); }
  return der;
}

function _mapDecryptError(e) {
  if (e && e.code === "cms/decrypt-failed") return _err("pkcs12/decrypt-failed", "decryption failed", e);
  return e;
}

async function _openEncryptedSafe(encSafe, password, opts, out, depth, budget) {
  if (encSafe.type === "envelopedData") {
    if (opts.recipientKey == null) throw _err("pkcs12/no-recipient-key", "the store has an id-envelopedData privacy safe -- supply opts.recipientKey (and opts.recipientCert) to decrypt it (RFC 7292 sec. 5.2)");
    // @internal
    var res;
    try { res = await cmsDecrypt.decryptEnvelopedData(encSafe.content, { key: opts.recipientKey, cert: opts.recipientCert }, opts, "envelopedData"); }
    catch (e) { throw _mapDecryptError(e); }
    var envBags;
    try { envBags = schemaPkcs12.walkSafeContents(res.content); }
    catch (_e) { throw _err("pkcs12/decrypt-failed", "decryption failed"); }
    for (var k = 0; k < envBags.length; k++) _openBag(envBags[k], password, opts, out, depth, budget);
    return;
  }
  if (encSafe.type !== "encryptedData") throw _err("pkcs12/unsupported-algorithm", "an " + encSafe.type + " privacy safe is not supported (only id-encryptedData under PBES2 or id-envelopedData under a recipient key)");
  var eci = encSafe.content.encryptedContentInfo;
  if (eci.encryptedContent == null) throw _err("pkcs12/bad-input", "the encrypted privacy safe has no content");
  var safeContentsDer = _decryptBag(eci.contentEncryptionAlgorithm, eci.encryptedContent, password, opts, budget);
  var bags;
  try { bags = schemaPkcs12.walkSafeContents(safeContentsDer); }
  catch (_e) { throw _err("pkcs12/decrypt-failed", "decryption failed"); }
  for (var i = 0; i < bags.length; i++) _openBag(bags[i], password, opts, out, depth, budget);
}

module.exports = {
  build: build,
  verifyMac: verifyMac,
  open: open,
};
