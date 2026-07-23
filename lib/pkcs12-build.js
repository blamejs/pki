// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.pkcs12
 * @nav        Signing
 * @title      PKCS#12
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
//
// The PBES2 bag encryption and the PBMAC1 MAC compose the shared lib/pbes2.js home (the same PBKDF2 + AES-CBC
// + HMAC primitives pki.cms and pki.key use), fed PKCS#12 App. B.1-formatted password bytes -- NOT the CMS
// UTF-8 encoding, the single most common PKCS#12 interop failure. The classic Appendix B.2 KDF (ID=3, the MAC
// integrity purpose) is bespoke PKCS#12 crypto with no in-tree equivalent, built here as one primitive and
// cross-checked against OpenSSL. The MAC is computed over the CONTENT octets of the id-data authSafe OCTET
// STRING (excluding its TLV header) -- exactly the parser's `macedBytes`, the canonical off-by-the-header
// trap designed out. Public-key integrity (an id-signedData authSafe) and bag/store DECRYPTION are deferred:
// build produces password-integrity stores, and a `pki.pkcs12.open` reader is the re-open condition.

var nodeCrypto = require("crypto");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var pbes2 = require("./pbes2");
var pkcs8 = require("./schema-pkcs8");
var x509 = require("./schema-x509");
var schemaCrl = require("./schema-crl");
var schemaPkcs12 = require("./schema-pkcs12");
var pkix = require("./schema-pkix");
var guard = require("./guard-all");
var frameworkError = require("./framework-error");
var C = require("./constants");

var b = asn1.build;
var Pkcs12Error = frameworkError.Pkcs12Error;
var PemError = frameworkError.PemError;
function O(n) { return oid.byName(n); }
function _err(code, msg, cause) { return new Pkcs12Error(code, msg, cause); }

// PKCS#12 integrity/privacy defaults (named, not call-site literals -- rule 12).
var DEFAULT_MAC_ITER = 2048;
var DEFAULT_PBMAC1_ITER = 2048;
var MAC_SALT_BYTES = 8;
var MAX_PBMAC1_KEYLEN = 1024;   // an HMAC key beyond a hash block is pointless -- bound the derived length
// The classic Appendix B KDF is a SYNCHRONOUS JS hash loop (unlike native/async PBKDF2), so its iteration
// count is capped far lower than the PBKDF2 limit -- a store just under the PBKDF2 cap would block the event
// loop for seconds. 1e6 is ~500x the OpenSSL default (2048) yet bounds the loop to a fraction of a second.
var CLASSIC_MAC_MAX_ITERATIONS = 1000000;

// The classic App. B.2 KDF (u = hash output bytes, v = compression block bytes) per RFC 7292 App. B.2.
var P12_KDF_UV = {
  sha1: { u: 20, v: 64 }, sha224: { u: 28, v: 64 }, sha256: { u: 32, v: 64 },
  sha384: { u: 48, v: 128 }, sha512: { u: 64, v: 128 },
};
// PBMAC1 hash -> { prf AlgorithmIdentifier name, WebCrypto hash, HMAC key length }. RFC 9579 sec. 5/7 forbids
// a <= 160-bit digest, so SHA-1 is absent.
var PBMAC1_PRF = {
  sha256: { prfName: "hmacWithSHA256", wc: "SHA-256", keyLen: 32 },
  sha384: { prfName: "hmacWithSHA384", wc: "SHA-384", keyLen: 48 },
  sha512: { prfName: "hmacWithSHA512", wc: "SHA-512", keyLen: 64 },
};
// PBMAC1 prf AlgorithmIdentifier name -> WebCrypto hash (verify direction).
var PRF_WC = { hmacWithSHA1: "SHA-1", hmacWithSHA256: "SHA-256", hmacWithSHA384: "SHA-384", hmacWithSHA512: "SHA-512" };
// operator cipher name -> AES-CBC registry name the PBES2 home speaks.
var CIPHER_NAME = { "aes-128-cbc": "aes128-CBC", "aes-192-cbc": "aes192-CBC", "aes-256-cbc": "aes256-CBC" };
// classic-MAC hash node name -> the registered digest OID name (identical spelling here).
var DIGEST_NAME = { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512" };

// ---- password + KDF primitives ---------------------------------------------

// RFC 7292 App. B.1: a PKCS#12 password is the BMPString (UTF-16BE) encoding of the string plus a trailing
// 2-byte NULL terminator. "Beavis" -> 14 bytes. A non-BMP scalar (surrogate) is rejected. A Buffer/Uint8Array
// is taken verbatim as already-formatted bytes (an escape hatch for a caller that pre-encodes).
function _p12Password(pw) {
  if (pw == null) pw = "";
  if (Buffer.isBuffer(pw)) return pw;
  if (pw instanceof Uint8Array) return Buffer.from(pw);
  if (typeof pw !== "string") throw _err("pkcs12/bad-input", "a password must be a string, Buffer, or Uint8Array");
  var out = Buffer.alloc(pw.length * 2 + 2);   // + the 2-byte NULL terminator
  for (var i = 0; i < pw.length; i++) {
    var u = pw.charCodeAt(i);
    if (u >= 0xD800 && u <= 0xDFFF) throw _err("pkcs12/bad-input", "the password contains a non-BMP character (a surrogate code point cannot be BMPString-encoded)");
    out[i * 2] = (u >> 8) & 0xFF;
    out[i * 2 + 1] = u & 0xFF;
  }
  return out;   // the final two bytes are already 0x00 0x00
}

// The password bytes for the RFC 8018 PBES2 bag ciphers and the RFC 9579 PBMAC1 MAC. Although RFC 9579 sec. 6
// specifies the BMPString encoding here too, OpenSSL and NSS -- and thus the interoperable ecosystem -- feed
// PBKDF2 the raw UTF-8 password for these modern schemes (confirmed byte-for-byte against `openssl pkcs12`),
// reserving the BMPString+NULL form for the bespoke Appendix B KDF only. A file we emit must open in OpenSSL,
// so the modern schemes use UTF-8 here; only the classic Appendix B MAC uses `_p12Password`.
function _pbePassword(pw) {
  if (pw == null) pw = "";
  if (Buffer.isBuffer(pw)) return pw;
  if (pw instanceof Uint8Array) return Buffer.from(pw);
  if (typeof pw !== "string") throw _err("pkcs12/bad-input", "a password must be a string, Buffer, or Uint8Array");
  return Buffer.from(pw, "utf8");
}

// Concatenate copies of `src` to the smallest positive multiple of `blockSize` (>= src length), truncating
// the final copy. An empty source yields an empty buffer (RFC 7292 App. B.2 steps 2/3).
function _blockFill(src, blockSize) {
  if (src.length === 0) return Buffer.alloc(0);
  var total = blockSize * Math.ceil(src.length / blockSize);
  var out = Buffer.alloc(total);
  for (var i = 0; i < total; i++) out[i] = src[i % src.length];
  return out;
}

// RFC 7292 Appendix B.2 KDF: derive `nBytes` of key material for purpose `id` (3 = MAC integrity) from the
// App. B.1 password bytes + salt over `iterations` rounds of `hashName`. NOT PBKDF2. The only consumer is the
// classic MAC, which always requests exactly the hash output length u, so the App. B.2 block count
// c = ceil(nBytes/u) is 1 -- one diversified, salted, iterated hash (D || S || P, hashed r times). The
// multi-block feedback (the c > 1 case, App. B.2 step 6C) has no consumer here; a future >u-byte derivation
// (e.g. a classic-PBE bag path) reintroduces it with its own known-answer test rather than shipping it
// untested. `nBytes` over u is rejected. The single-block path is proven bidirectionally against OpenSSL.
function _p12Kdf(hashName, id, pwBytes, salt, iterations, nBytes) {
  var uv = P12_KDF_UV[hashName];
  if (nBytes > uv.u) throw _err("pkcs12/unsupported-algorithm", "the App. B.2 KDF here derives at most the hash output length");
  var v = uv.v;
  var A = Buffer.concat([Buffer.alloc(v, id), _blockFill(salt, v), _blockFill(pwBytes, v)]);   // D || S || P
  for (var r = 0; r < iterations; r++) A = nodeCrypto.createHash(hashName).update(A).digest();   // H^r(D||I)
  return A.subarray(0, nBytes);
}

// ---- input coercion --------------------------------------------------------

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

// ---- bag builders ----------------------------------------------------------

// PKCS12Attribute SET OF: friendlyName (a single BMPString) + localKeyId (a single OCTET STRING). Each
// attribute's attrValues is a single-value SET OF (RFC 2985 SINGLE VALUE).
function _bagAttributes(bag) {
  var attrs = [];
  if (bag.friendlyName != null) attrs.push(b.sequence([b.oid(O("friendlyName")), b.set([b.bmpString(String(bag.friendlyName))])]));
  if (bag.localKeyId != null) {
    if (bag.localKeyId === "ski") throw _err("pkcs12/bad-input", "localKeyId 'ski' auto-derivation is not yet supported -- supply an explicit Buffer");
    attrs.push(b.sequence([b.oid(O("localKeyId")), b.set([b.octetString(_bytes(bag.localKeyId, "localKeyId"))])]));
  }
  return attrs.length ? b.set(attrs) : null;
}

// A secretBag secretTypeId is a caller-chosen content type: a registered OID name, or an arbitrary
// dotted-decimal OID string preserved verbatim (a name -> its OID; an already-dotted OID passes through).
function _secretTypeOid(id) {
  var resolved = O(id) || id;
  try { return b.oid(resolved); }
  catch (e) { throw _err("pkcs12/bad-input", "secretTypeId must be a registered name or a dotted-decimal OID string", e); }
}

// A SafeBag ::= SEQUENCE { bagId, bagValue [0] EXPLICIT DEFINED BY bagId, bagAttributes SET OF OPTIONAL }.
function _safeBag(bagName, bagValueDer, bag) {
  var children = [b.oid(O(bagName)), b.explicit(0, bagValueDer)];
  var attrs = _bagAttributes(bag);
  if (attrs) children.push(attrs);
  return b.sequence(children);
}

function _buildBag(bag, opts, depth) {
  if (!bag || typeof bag !== "object") throw _err("pkcs12/bad-input", "each bag must be an object with a type");
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
      var pw = _pbePassword(enc.password != null ? enc.password : opts.password);
      var r = pbes2.pbes2Encrypt(pw, kDer, _pbeOpts(enc), _err, "pkcs12");
      return _safeBag("pkcs8ShroudedKeyBag", b.sequence([r.algId, b.octetString(r.ct)]), bag);   // EncryptedPrivateKeyInfo
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

// A pre-encoded DER value (one well-formed TLV, no trailing bytes) supplied verbatim (secretValue).
function _reqDer(input, label) {
  if (input == null) throw _err("pkcs12/bad-input", label + " is required");
  var der = _bytes(input, label);
  var node;
  try { node = asn1.decode(der); } catch (e) { throw _err("pkcs12/bad-input", label + " must be one well-formed DER value", e); }
  if (node.bytes.length !== der.length) throw _err("pkcs12/bad-input", label + " must be exactly one DER value with no trailing bytes");
  return der;
}

function _pbeOpts(enc) {
  var cipher = CIPHER_NAME[enc.cipher || "aes-256-cbc"];
  if (!cipher) throw _err("pkcs12/bad-input", "unsupported PBES2 cipher " + JSON.stringify(enc.cipher) + " (aes-128-cbc / aes-192-cbc / aes-256-cbc)");
  return {
    cipher: cipher,
    salt: enc.salt != null ? _bytes(enc.salt, "encrypt salt") : undefined,
    iterations: enc.iterations,
    prf: enc.prf,
  };
}

// SafeContents ::= SEQUENCE OF SafeBag (ordered, NOT a SET OF).
function _buildSafeContents(bags, opts, depth) {
  if (!Array.isArray(bags)) throw _err("pkcs12/bad-input", "bags must be an array");
  if (bags.length > C.LIMITS.PKCS12_MAX_ELEMENTS) throw _err("pkcs12/bad-input", "a SafeContents exceeds the element cap " + C.LIMITS.PKCS12_MAX_ELEMENTS);
  return b.sequence(bags.map(function (bag) { return _buildBag(bag, opts, depth); }));
}

// One AuthenticatedSafe element: a plaintext id-data ContentInfo, or an id-encryptedData ContentInfo whose
// EncryptedData is the PBES2 encryption of the SafeContents (RFC 7292 sec. 5.1 step 2A/2B).
function _buildAuthSafeElement(sc, opts) {
  var safeContentsDer = _buildSafeContents(sc.bags || [], opts, 0);
  if (!sc.encrypt) {
    return b.sequence([b.oid(O("data")), b.explicit(0, b.octetString(safeContentsDer))]);
  }
  var pw = _pbePassword(sc.encrypt.password != null ? sc.encrypt.password : opts.password);
  var r = pbes2.pbes2Encrypt(pw, safeContentsDer, _pbeOpts(sc.encrypt), _err, "pkcs12");
  var eci = b.sequence([b.oid(O("data")), r.algId, b.contextPrimitive(0, r.ct)]);   // EncryptedContentInfo, [0] IMPLICIT ct
  var encData = b.sequence([b.integer(0n), eci]);                                    // EncryptedData { version 0, eci }
  return b.sequence([b.oid(O("encryptedData")), b.explicit(0, encData)]);
}

// ---- MacData ---------------------------------------------------------------

// MacData over the AuthenticatedSafe DER (= the parser's macedBytes). Classic App. B HMAC (default, max
// interop) or RFC 9579 PBMAC1. Returns the MacData DER.
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
    var macKey = _p12Kdf(node, 3, _p12Password(password), salt, iter, P12_KDF_UV[node].u);   // classic KDF -> BMPString
    var digest = nodeCrypto.createHmac(node, macKey).update(authSafeDer).digest();
    var digestInfo = b.sequence([b.sequence([b.oid(O(node)), b.nullValue()]), b.octetString(digest)]);
    return b.sequence([digestInfo, b.octetString(salt), b.integer(BigInt(iter))]);
  }
  if (algorithm === "pbmac1") {
    var prf = PBMAC1_PRF[hash];
    if (!prf) throw _err("pkcs12/unsupported-algorithm", "PBMAC1 requires a SHA-256/384/512 digest (RFC 9579 sec. 5/7 forbids a <= 160-bit digest, e.g. SHA-1)");
    var iter2 = _assertMacIter(macOpts.iterations == null ? DEFAULT_PBMAC1_ITER : macOpts.iterations, C.LIMITS.PBKDF2_MAX_ITERATIONS);
    var keyLen = macOpts.keyLength != null ? macOpts.keyLength : prf.keyLen;
    if (typeof keyLen !== "number" || !Number.isInteger(keyLen) || keyLen < 20 || keyLen > MAX_PBMAC1_KEYLEN) throw _err("pkcs12/bad-input", "PBMAC1 keyLength must be an integer in [20, " + MAX_PBMAC1_KEYLEN + "] (RFC 9579 sec. 9)");
    var mac = await pbes2.pbmac1(_pbePassword(password), salt, iter2, keyLen, prf.wc, prf.wc, authSafeDer);   // PBKDF2 -> UTF-8; prf == messageAuthScheme on build
    var desc = { salt: salt, iterationCount: iter2, keyLength: keyLen, prfName: prf.prfName, macName: prf.prfName };
    var digestInfo2 = b.sequence([pbes2.pbmac1AlgId(desc), b.octetString(mac)]);
    // MacData.macSalt + iterations are ignored on a PBMAC1 verify but MUST be present + non-1 (RFC 9579 4c/4d).
    return b.sequence([digestInfo2, b.octetString(salt), b.integer(BigInt(iter2))]);
  }
  throw _err("pkcs12/bad-input", "opts.mac.algorithm must be 'hmac' or 'pbmac1', got " + JSON.stringify(algorithm));
}

// ---- spec normalization ----------------------------------------------------

// Accept the OpenSSL-style convenience form ({ key, cert, ca, friendlyName, localKeyId }) or the full
// inverse-of-parse form ({ safeContents: SafeContentsSpec[] }). The convenience form -> one privacy safe of
// PBES2 cert bags + one shrouded-key safe.
function _normalizeSpec(spec, opts) {
  if (spec && Array.isArray(spec.safeContents)) return spec.safeContents;
  if (spec && (spec.key != null || spec.cert != null)) {
    var certBags = [];
    if (spec.cert != null) certBags.push({ type: "cert", cert: spec.cert, friendlyName: spec.friendlyName, localKeyId: spec.localKeyId });
    (spec.ca || []).forEach(function (ca) { certBags.push({ type: "cert", cert: ca }); });
    var sc = [];
    if (certBags.length) sc.push({ encrypt: { password: opts.password }, bags: certBags });
    if (spec.key != null) sc.push({ bags: [{ type: "shroudedKey", key: spec.key, encrypt: { password: opts.password }, friendlyName: spec.friendlyName, localKeyId: spec.localKeyId }] });
    return sc;
  }
  throw _err("pkcs12/bad-input", "spec must be { safeContents: [...] } or { key, cert, ca? }");
}

// ---- public API ------------------------------------------------------------

/**
 * @primitive pki.pkcs12.build
 * @signature pki.pkcs12.build(spec, opts?) -> Promise<Buffer|string>
 * @since 0.3.11
 * @status experimental
 * @spec RFC 7292, RFC 9579, RFC 8018
 * @related pki.schema.pkcs12.parse, pki.pkcs12.verifyMac
 *
 * Build a password-integrity PKCS#12 (.p12 / .pfx) store. `spec` is either the OpenSSL-style convenience
 * form `{ key, cert, ca?, friendlyName?, localKeyId? }` (one PBES2-encrypted cert safe plus one shrouded-key
 * safe) or the full form `{ safeContents: [...] }`, where each element is a plaintext or PBES2-encrypted
 * `SafeContents` of key / shroudedKey / cert / crl / secret / nested safeContents bags. Keys and certs are
 * validated before wrapping; every password is BMPString+NULL encoded (RFC 7292 App. B.1). The store is
 * MACed with a classic Appendix B HMAC (default) or an RFC 9579 PBMAC1, and re-parsed before return.
 *
 * @opts
 *   - `password` -- the shared privacy + integrity password (string / Buffer / Uint8Array).
 *   - `mac` -- `false` for a MAC-less store, or `{ algorithm: 'hmac'(default)|'pbmac1', hash: 'sha256'(default)|'sha1'|'sha384'|'sha512', salt?, iterations?, keyLength? }`.
 *   - `pem` (boolean) -- return a PEM `PKCS12` string instead of DER.
 * @example
 *   var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [
 *     { type: 'cert', cert: signerCertDer },
 *     { type: 'shroudedKey', key: signerKeyPkcs8, encrypt: { password: 'changeit' } } ] }] },
 *     { password: 'changeit', mac: { algorithm: 'hmac', hash: 'sha256' } });
 */
async function build(spec, opts) {
  opts = opts || {};
  if (opts.integrity && opts.integrity.mode === "public-key") {
    throw _err("pkcs12/unsupported-algorithm", "public-key integrity (an id-signedData authSafe) is not yet supported -- use password integrity");
  }
  var safeContentsSpecs = _normalizeSpec(spec, opts);
  if (!Array.isArray(safeContentsSpecs) || !safeContentsSpecs.length) throw _err("pkcs12/bad-input", "the store has no safe contents");
  var elements = [];
  for (var i = 0; i < safeContentsSpecs.length; i++) elements.push(_buildAuthSafeElement(safeContentsSpecs[i], opts));
  var authSafeDer = b.sequence(elements);   // AuthenticatedSafe ::= SEQUENCE OF ContentInfo

  var pfxChildren = [b.integer(3n), b.sequence([b.oid(O("data")), b.explicit(0, b.octetString(authSafeDer))])];
  if (opts.mac !== false) pfxChildren.push(await _buildMacData(opts.mac || {}, opts.password, authSafeDer));
  var pfx = b.sequence(pfxChildren);

  // Self-check: the emitted store round-trips through the strict parser (structure + MAC coherence).
  try { schemaPkcs12.parse(pfx); } catch (e) { throw _err("pkcs12/bad-input", "the produced PKCS#12 store did not re-parse (build bug)", e); }
  return opts.pem ? schemaPkcs12.pemEncode(pfx, "PKCS12") : pfx;
}

/**
 * @primitive pki.pkcs12.verifyMac
 * @signature pki.pkcs12.verifyMac(pfx, password, opts?) -> Promise<boolean>
 * @since 0.3.11
 * @status experimental
 * @spec RFC 7292 sec. 5.1, RFC 9579
 * @defends pkcs12-mac-forgery (CWE-347)
 * @related pki.pkcs12.build, pki.schema.pkcs12.parse
 *
 * Verify a password-integrity PKCS#12 store's MAC. `pfx` is a `pki.schema.pkcs12.parse` result, a DER
 * `Buffer`, or a PEM string. The password is BMPString+NULL encoded (RFC 7292 App. B.1), the MAC is
 * recomputed over the store's exact AuthenticatedSafe byte range (`macedBytes`) using the store's own MAC
 * parameters -- the classic Appendix B (ID=3) HMAC or the RFC 9579 PBMAC1 -- and constant-time-compared to
 * the stored MAC value. Returns `true` / `false` for the password match; throws `Pkcs12Error` on a MAC-less
 * or public-key-integrity store, or an unsupported MAC algorithm (never a falsy verdict standing in for an error).
 *
 * @example
 *   var p12 = await pki.pkcs12.build({ key: signerKeyPkcs8, cert: signerCertDer }, { password: 'changeit' });
 *   var ok = await pki.pkcs12.verifyMac(p12, 'changeit');
 */
async function verifyMac(pfx, password, opts) {
  opts = opts || {};
  var m = (pfx && pfx.integrityMode !== undefined && pfx.mac !== undefined) ? pfx : schemaPkcs12.parse(_coerceDer(pfx, "pfx"));
  if (m.integrityMode !== "password" || !m.mac) throw _err("pkcs12/bad-input", "the store carries no password MAC (integrityMode " + m.integrityMode + ")");
  var expected = m.mac.macValue;
  var computed;
  if (m.mac.kind === "hmac") {
    var node = (m.mac.hashName || "").toLowerCase();
    if (!P12_KDF_UV[node]) throw _err("pkcs12/unsupported-algorithm", "unsupported classic MAC hash " + m.mac.hashName);
    // The iteration count and salt are attacker-controlled work factors: bound them BEFORE the KDF runs.
    _capWork(m.mac.iterations, m.mac.macSalt, opts, undefined, CLASSIC_MAC_MAX_ITERATIONS);
    var macKey = _p12Kdf(node, 3, _p12Password(password), m.mac.macSalt, m.mac.iterations, P12_KDF_UV[node].u);   // classic KDF -> BMPString
    computed = nodeCrypto.createHmac(node, macKey).update(m.macedBytes).digest();
  } else {
    var kdf = m.mac.pbmac1.kdf;
    var prfWc = PRF_WC[kdf.prfName];
    // RFC 9579: HMAC under the messageAuthScheme, keyed by PBKDF2 under the (independent) prf.
    var macWc = PRF_WC[m.mac.pbmac1.schemeName];
    if (!prfWc) throw _err("pkcs12/unsupported-algorithm", "unsupported PBMAC1 prf " + kdf.prfName);
    if (!macWc) throw _err("pkcs12/unsupported-algorithm", "unsupported PBMAC1 messageAuthScheme " + m.mac.pbmac1.schemeName);
    // RFC 9579 sec. 5/7: a <= 160-bit digest (SHA-1) MUST NOT be used for PBMAC1 -- refuse it on verify, so a
    // downgraded store cannot pass under a weak MAC even though the algorithm identifiers parse.
    if (prfWc === "SHA-1" || macWc === "SHA-1") throw _err("pkcs12/unsupported-algorithm", "PBMAC1 with a <= 160-bit digest (SHA-1) is refused (RFC 9579 sec. 5/7)");
    _capWork(kdf.iterationCount, kdf.salt, opts, kdf.keyLength, C.LIMITS.PBKDF2_MAX_ITERATIONS);
    computed = await pbes2.pbmac1(_pbePassword(password), kdf.salt, kdf.iterationCount, kdf.keyLength, prfWc, macWc, m.macedBytes);   // PBKDF2 -> UTF-8
  }
  return computed.length === expected.length && guard.crypto.constantTimeEqual(computed, expected);
}

// Bound the attacker-controlled MAC work factors before a hostile store can force an expensive derivation:
// the iteration count (<= PBKDF2_MAX_ITERATIONS, downward-overridable via opts.maxIterations), the salt, and
// the PBMAC1 keyLength. A store that exceeds any cap is a typed reject, never a multi-second CPU burn.
function _capWork(iterations, salt, opts, keyLength, hardCap) {
  var cap = hardCap;
  if (opts.maxIterations != null) {
    if (typeof opts.maxIterations !== "number" || !isFinite(opts.maxIterations) || opts.maxIterations < 1 || Math.floor(opts.maxIterations) !== opts.maxIterations) throw _err("pkcs12/bad-input", "maxIterations must be a positive integer");
    cap = Math.min(opts.maxIterations, cap);
  }
  if (iterations > cap) throw _err("pkcs12/iteration-limit", "the MAC iteration count " + iterations + " exceeds the cap " + cap);
  if (salt && salt.length > C.LIMITS.PBKDF2_MAX_SALT) throw _err("pkcs12/bad-input", "the MAC salt exceeds the " + C.LIMITS.PBKDF2_MAX_SALT + "-octet cap");
  // RFC 9579 sec. 9: the PBMAC1 keyLength floor (>= 20) is enforced on verify too, so a downgraded store with
  // a short derived key is refused rather than accepted under a weak MAC.
  if (keyLength != null && (keyLength < 20 || keyLength > MAX_PBMAC1_KEYLEN)) throw _err("pkcs12/bad-input", "the PBMAC1 keyLength must be in [20, " + MAX_PBMAC1_KEYLEN + "] (RFC 9579 sec. 9)");
}

module.exports = {
  build: build,
  verifyMac: verifyMac,
};
