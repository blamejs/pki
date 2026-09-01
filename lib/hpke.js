// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.hpke
 * @nav        Protocols
 * @title      HPKE
 * @fullname   HPKE (Hybrid Public Key Encryption, RFC 9180)
 * @intro Hybrid Public Key Encryption (RFC 9180) -- the standard construction
 *   behind TLS Encrypted Client Hello, MLS, and OHTTP that turns a recipient KEM
 *   public key into an encapsulated key plus an AEAD-encrypting context. This is
 *   the RFC 9180 base construction: the DHKEM suites P-256, P-521, X25519, and
 *   X448, HKDF-SHA256 / HKDF-SHA512, the three AEADs plus export-only, and all
 *   four modes (base / psk / auth / auth-psk), each proven against the RFC 9180
 *   Appendix A known-answer vectors. DHKEM(P-384) and HKDF-SHA384 are RFC-registered
 *   but Appendix A ships no test vector for them, so they are omitted (a request
 *   fails closed) until an authoritative KAT is available. Pure composition over
 *   node:crypto: no ASN.1, no schema engine. Post-quantum KEMs (ML-KEM, X-Wing)
 *   are a data-row extension the registry is shaped to admit once their
 *   specifications stabilize.
 *   The RFC 9180 sec. 7 registry code points live in pki.hpke.suites
 *   (KEM / KDF / AEAD / MODE), passed to the setup functions to select a suite.
 * @spec RFC 9180
 * @card Encrypt to a KEM public key (RFC 9180; the ECH / MLS / OHTTP primitive).
 */

var nodeCrypto = require("crypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;

var HpkeError = frameworkError.HpkeError;
function _err(code, message, cause) { return new HpkeError(code, message, cause); }


function i2osp(n, len) {
  var b = Buffer.alloc(len);
  var v = BigInt(n);
  for (var i = len - 1; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}
function concat(arr) { return Buffer.concat(arr); }
function xor(a, b) { var o = Buffer.alloc(a.length); for (var i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; }

var HPKE_V1 = Buffer.from("HPKE-v1", "ascii");
function L(s) { return Buffer.from(s, "ascii"); }


var KDFS = {
  0x0001: { hash: "sha256", Nh: 32 },
  0x0003: { hash: "sha512", Nh: 64 },
};
var AEADS = {
  0x0001: { cipher: "aes-128-gcm", Nk: 16, Nn: 12, Nt: 16 },
  0x0002: { cipher: "aes-256-gcm", Nk: 32, Nn: 12, Nt: 16 },
  0x0003: { cipher: "chacha20-poly1305", Nk: 32, Nn: 12, Nt: 16 },
  0xFFFF: { exportOnly: true, Nn: 12 },
};
var KEMS = {
  0x0010: { kind: "ec", curve: "P-256", nodeCurve: "prime256v1", kdf: 0x0001, Nsecret: 32, Npub: 65 },
  0x0012: { kind: "ec", curve: "P-521", nodeCurve: "secp521r1", kdf: 0x0003, Nsecret: 64, Npub: 133 },
  0x0020: { kind: "okp", curve: "X25519", oid: "2b656e", kdf: 0x0001, Nsecret: 32, Npub: 32 },
  0x0021: { kind: "okp", curve: "X448", oid: "2b656f", kdf: 0x0003, Nsecret: 64, Npub: 56 },
};

var MODE_BASE = 0x00, MODE_PSK = 0x01, MODE_AUTH = 0x02, MODE_AUTH_PSK = 0x03;

function _idStr(id) { return typeof id === "number" ? "0x" + id.toString(16) : String(id); }
function _kem(id) { var s = KEMS[id]; if (!s) throw _err("hpke/unknown-suite", "unsupported KEM id " + _idStr(id)); return s; }
function _kdf(id) { var s = KDFS[id]; if (!s) throw _err("hpke/unknown-suite", "unsupported KDF id " + _idStr(id)); return s; }
function _aead(id) { var s = AEADS[id]; if (!s) throw _err("hpke/unknown-suite", "unsupported AEAD id " + _idStr(id)); return s; }


function _extract(hash, Nh, salt, ikm) {
  var key = (salt && salt.length) ? salt : Buffer.alloc(Nh);
  return nodeCrypto.createHmac(hash, key).update(ikm).digest();
}
function _expand(hash, Nh, prk, info, len) {
  if (len > 255 * Nh) throw _err("hpke/export-length", "requested length " + len + " exceeds 255*Nh");
  var out = [], t = Buffer.alloc(0), n = Math.ceil(len / Nh);
  for (var i = 1; i <= n; i++) {
    var fed = concat([t, info, Buffer.from([i])]);
    t = nodeCrypto.createHmac(hash, prk).update(fed).digest();
    guard.secret.zeroize(fed, HpkeError, "hpke/bad-input", "an expand feedback input");
    out.push(t);
  }
  var joined = concat(out);
  var exact = Buffer.alloc(len);
  joined.copy(exact, 0, 0, len);
  guard.secret.zeroize(joined, HpkeError, "hpke/bad-input", "the KDF accumulator");
  for (var oi = 0; oi < out.length; oi++) guard.secret.zeroize(out[oi], HpkeError, "hpke/bad-input", "a KDF block");
  return exact;
}
function _labeledExtract(kdf, suiteId, salt, label, ikm) {
  var labeled = concat([HPKE_V1, suiteId, L(label), ikm]);
  try { return _extract(kdf.hash, kdf.Nh, salt, labeled); }
  finally { guard.secret.zeroize(labeled, HpkeError, "hpke/bad-input", "the labeled extract input"); }
}
function _labeledExpand(kdf, suiteId, prk, label, info, len) {
  return _expand(kdf.hash, kdf.Nh, prk, concat([i2osp(len, 2), HPKE_V1, suiteId, L(label), info]), len);
}


var OKP_SPKI = { X25519: "302a300506032b656e032100", X448: "3042300506032b656f033900" };
var OKP_PKCS8 = { X25519: "302e020100300506032b656e04220420", X448: "3046020100300506032b656f043a0438" };

function _importPublic(kem, raw) {
  if (!Buffer.isBuffer(raw) || raw.length !== kem.Npub) {
    throw _err("hpke/bad-key", kem.curve + " public key must be " + kem.Npub + " bytes");
  }
  try {
    if (kem.kind === "ec") {
      if (raw[0] !== 0x04) throw _err("hpke/bad-key", "EC public key must be an uncompressed 0x04 point (RFC 9180 sec. 7.1.4)");
      var half = (raw.length - 1) / 2;
      var jwk = { kty: "EC", crv: kem.curve, x: raw.subarray(1, 1 + half).toString("base64url"), y: raw.subarray(1 + half).toString("base64url") };
      return nodeCrypto.createPublicKey({ key: jwk, format: "jwk" });
    }
    return nodeCrypto.createPublicKey({ key: Buffer.from(OKP_SPKI[kem.curve] + raw.toString("hex"), "hex"), format: "der", type: "spki" });
  } catch (e) {
    if (e instanceof HpkeError) throw e;
    throw _err("hpke/bad-key", "invalid " + kem.curve + " public key", e);
  }
}
function _exportPublic(kem, keyObject) {
  var jwk = keyObject.export({ format: "jwk" });
  if (kem.kind === "ec") return concat([Buffer.from([0x04]), _b64u(jwk.x), _b64u(jwk.y)]);
  return _b64u(jwk.x);
}
function _b64u(s) { return guard.encoding.base64url(s, null, _err, "hpke/bad-key", "JWK coordinate"); }

function _importPrivate(kem, rawSk, rawPk) {
  try {
    if (kem.kind === "ec") {
      var jwk = { kty: "EC", crv: kem.curve, d: rawSk.toString("base64url") };
      if (rawPk) { jwk.x = rawPk.subarray(1, 1 + (rawPk.length - 1) / 2).toString("base64url"); jwk.y = rawPk.subarray(1 + (rawPk.length - 1) / 2).toString("base64url"); }
      return nodeCrypto.createPrivateKey({ key: jwk, format: "jwk" });
    }
    return nodeCrypto.createPrivateKey({ key: Buffer.from(OKP_PKCS8[kem.curve] + rawSk.toString("hex"), "hex"), format: "der", type: "pkcs8" });
  } catch (e) {
    throw _err("hpke/bad-key", "invalid " + kem.curve + " private key", e);
  }
}
function _dh(privateKey, publicKey) {
  try {
    return nodeCrypto.diffieHellman({ privateKey: privateKey, publicKey: publicKey });
  } catch (e) {
    throw _err("hpke/bad-key", "KEM Diffie-Hellman failed: invalid or low-order public key", e);
  }
}
function _generate(kem) {
  if (kem.kind === "ec") return nodeCrypto.generateKeyPairSync("ec", { namedCurve: kem.nodeCurve });
  return nodeCrypto.generateKeyPairSync(kem.curve.toLowerCase());
}


function _kemSuiteId(kemId) { return concat([L("KEM"), i2osp(kemId, 2)]); }
function _extractAndExpand(kem, dh, kemContext) {
  var kdf = _kdf(kem.kdf), sid = _kemSuiteId(_kemId(kem));
  var eaePrk = _labeledExtract(kdf, sid, Buffer.alloc(0), "eae_prk", dh);
  try { return _labeledExpand(kdf, sid, eaePrk, "shared_secret", kemContext, kem.Nsecret); }
  finally { guard.secret.zeroize(eaePrk, HpkeError, "hpke/bad-input", "the KEM extract PRK"); }
}
function _kemId(kem) { for (var k in KEMS) if (KEMS[k] === kem) return Number(k); return 0; }

function _ephemeral(kem, eph) {
  if (eph) return { skE: _importPrivate(kem, eph.skm, eph.pkm), enc: _buf(eph.pkm) };
  var kp = _generate(kem);
  return { skE: kp.privateKey, enc: _exportPublic(kem, kp.publicKey) };
}
function _wipeDh(dh) { guard.secret.zeroize(dh, HpkeError, "hpke/bad-input", "the KEM shared secret"); }
function _encap(kem, pkR, pkRm, eph) {
  var e = _ephemeral(kem, eph);
  var dh = null;
  try {
    dh = _dh(e.skE, pkR);
    return { sharedSecret: _extractAndExpand(kem, dh, concat([e.enc, pkRm])), enc: e.enc };
  } finally { _wipeDh(dh); }
}
function _decap(kem, enc, skR, pkRm) {
  var pkE = _importPublic(kem, enc);
  var dh = null;
  try {
    dh = _dh(skR, pkE);
    return _extractAndExpand(kem, dh, concat([enc, pkRm]));
  } finally { _wipeDh(dh); }
}
function _authEncap(kem, pkR, pkRm, skS, pkSm, eph) {
  var e = _ephemeral(kem, eph);
  var dh1 = null, dh2 = null, dh = null;
  try {
    dh1 = _dh(e.skE, pkR);
    dh2 = _dh(skS, pkR);
    dh = concat([dh1, dh2]);
    return { sharedSecret: _extractAndExpand(kem, dh, concat([e.enc, pkRm, pkSm])), enc: e.enc };
  } finally { _wipeDh(dh1); _wipeDh(dh2); _wipeDh(dh); }
}
function _authDecap(kem, enc, skR, pkRm, pkS, pkSm) {
  var pkE = _importPublic(kem, enc);
  var dh1 = null, dh2 = null, dh = null;
  try {
    dh1 = _dh(skR, pkE);
    dh2 = _dh(skR, pkS);
    dh = concat([dh1, dh2]);
    return _extractAndExpand(kem, dh, concat([enc, pkRm, pkSm]));
  } finally { _wipeDh(dh1); _wipeDh(dh2); _wipeDh(dh); }
}


function _hpkeSuiteId(kemId, kdfId, aeadId) { return concat([L("HPKE"), i2osp(kemId, 2), i2osp(kdfId, 2), i2osp(aeadId, 2)]); }

function _verifyPsk(mode, psk, pskId) {
  var gotPsk = psk.length > 0, gotId = pskId.length > 0;
  if (gotPsk !== gotId) throw _err("hpke/inconsistent-psk", "psk and psk_id must be provided together (RFC 9180 sec. 5.1)");
  if (gotPsk && (mode === MODE_BASE || mode === MODE_AUTH)) throw _err("hpke/inconsistent-psk", "a PSK was provided for a non-PSK mode");
  if (!gotPsk && (mode === MODE_PSK || mode === MODE_AUTH_PSK)) throw _err("hpke/inconsistent-psk", "mode requires a PSK");
}

function _keySchedule(suite, mode, sharedSecret, info, psk, pskId, role) {
  _verifyPsk(mode, psk, pskId);
  var kdf = suite.kdf, sid = suite.suiteId, aead = suite.aead;
  var pskIdHash = _labeledExtract(kdf, sid, Buffer.alloc(0), "psk_id_hash", pskId);
  var infoHash = _labeledExtract(kdf, sid, Buffer.alloc(0), "info_hash", info);
  var ksc = concat([Buffer.from([mode]), pskIdHash, infoHash]);
  var secret = _labeledExtract(kdf, sid, sharedSecret, "secret", psk);
  try {
    var exporterSecret = _labeledExpand(kdf, sid, secret, "exp", ksc, kdf.Nh);
    var key = null, baseNonce = null;
    if (!aead.exportOnly) {
      key = _labeledExpand(kdf, sid, secret, "key", ksc, aead.Nk);
      baseNonce = _labeledExpand(kdf, sid, secret, "base_nonce", ksc, aead.Nn);
    }
    return new Context(suite, key, baseNonce, exporterSecret, role);
  } finally {
    guard.secret.zeroize(secret, HpkeError, "hpke/bad-input", "the key-schedule PRK");
  }
}


function Context(suite, key, baseNonce, exporterSecret, role) {
  this._suite = suite; this._key = key; this._baseNonce = baseNonce;
  this._exporterSecret = exporterSecret; this._seq = 0n; this._role = role;
}
Context.prototype._dispose = function () {
  guard.secret.zeroizeAll([this._key, this._baseNonce, this._exporterSecret], HpkeError, "hpke/bad-input", "the HPKE context key material");
};
Context.prototype._nonce = function () {
  var aead = this._suite.aead;
  var seqBytes = i2osp(this._seq, aead.Nn);
  return xor(this._baseNonce, seqBytes);
};
Context.prototype._inc = function () {
  var aead = this._suite.aead;
  if (this._seq >= (1n << BigInt(8 * aead.Nn)) - 1n) throw _err("hpke/message-limit", "AEAD sequence number would overflow (RFC 9180 sec. 5.2)");
  this._seq += 1n;
};
Context.prototype.seal = function (aad, pt) {
  var aead = this._suite.aead;
  if (this._role !== "S") throw _err("hpke/wrong-role", "seal is only available on a sender context (RFC 9180 sec. 5.2)");
  if (aead.exportOnly) throw _err("hpke/export-only", "seal is not available for an export-only AEAD");
  var nonce = this._nonce();
  var c = nodeCrypto.createCipheriv(aead.cipher, this._key, nonce, { authTagLength: aead.Nt });
  if (aad && aad.length) c.setAAD(aad);
  var body = guard.secret.cipherFinish(c, _buf(pt), HpkeError, "hpke/bad-input", "a seal intermediate");
  var ct = concat([body, c.getAuthTag()]);
  this._inc();
  return ct;
};
Context.prototype.open = function (aad, ct) {
  var aead = this._suite.aead;
  if (this._role !== "R") throw _err("hpke/wrong-role", "open is only available on a recipient context (RFC 9180 sec. 5.2)");
  if (aead.exportOnly) throw _err("hpke/export-only", "open is not available for an export-only AEAD");
  ct = _buf(ct);
  if (ct.length < aead.Nt) throw _err("hpke/open-failed", "ciphertext is shorter than the AEAD tag");
  var nonce = this._nonce();
  var d = nodeCrypto.createDecipheriv(aead.cipher, this._key, nonce, { authTagLength: aead.Nt });
  if (aad && aad.length) d.setAAD(aad);
  d.setAuthTag(ct.subarray(ct.length - aead.Nt));
  var pt;
  try { pt = guard.secret.cipherFinish(d, ct.subarray(0, ct.length - aead.Nt), HpkeError, "hpke/bad-input", "the recovered plaintext"); }
  catch (e) { throw _err("hpke/open-failed", "AEAD authentication failed (RFC 9180 sec. 5.2)", e); }
  this._inc();
  return pt;
};
Context.prototype.export = function (exporterContext, len) {
  if (!Number.isInteger(len) || len < 0) throw _err("hpke/export-length", "export length must be a non-negative integer");
  return _labeledExpand(this._suite.kdf, this._suite.suiteId, this._exporterSecret, "sec", _buf(exporterContext), len);
};
function _buf(x) { return Buffer.isBuffer(x) ? x : Buffer.from(x || []); }


function _suite(ids) {
  if (!ids || typeof ids !== "object") throw _err("hpke/unknown-suite", "suiteIds must be an object { kem, kdf, aead } from pki.hpke.suites");
  var kemId = ids.kem, kdfId = ids.kdf, aeadId = ids.aead;
  var kem = _kem(kemId), kdf = _kdf(kdfId), aead = _aead(aeadId);
  return { kem: kem, kdf: kdf, aead: aead, kemId: kemId, kdfId: kdfId, aeadId: aeadId, suiteId: _hpkeSuiteId(kemId, kdfId, aeadId) };
}

function _recipPublic(suite, pk) {
  if (Buffer.isBuffer(pk)) return { key: _importPublic(suite.kem, pk), pkm: pk };
  if (pk && pk.pkm) return { key: _importPublic(suite.kem, pk.pkm), pkm: pk.pkm };
  try {
    return { key: pk, pkm: _exportPublic(suite.kem, pk) };
  } catch (e) {
    if (e instanceof HpkeError) throw e;
    throw _err("hpke/bad-key", "invalid KEM public key (expected a node KeyObject, a raw buffer, or { pkm })", e);
  }
}
function _recipPrivate(suite, sk) {
  if (sk && sk.skm) return { key: _importPrivate(suite.kem, sk.skm, sk.pkm), pkm: sk.pkm };
  if (Buffer.isBuffer(sk)) throw _err("hpke/bad-key", "a serialized private key must be provided as { skm, pkm } (raw scalar + public point), not a bare buffer");
  try {
    var pkm = _exportPublic(suite.kem, nodeCrypto.createPublicKey(sk));
    return { key: sk, pkm: pkm };
  } catch (e) {
    if (e instanceof HpkeError) throw e;
    throw _err("hpke/bad-key", "invalid recipient private key (expected a node KeyObject or { skm, pkm })", e);
  }
}

var _COMMON_KEYS = { mode: 1, info: 1, psk: 1, pskId: 1 };
function _withCommon(extra) {
  var out = {};
  Object.keys(_COMMON_KEYS).forEach(function (k) { out[k] = 1; });
  Object.keys(extra).forEach(function (k) { out[k] = 1; });
  return out;
}
var _SETUP_S_KEYS = _withCommon({
  senderKey: 1,
  eph: 1,
});
var _SETUP_R_KEYS = _withCommon({
  senderPublicKey: 1,
});
function _mode(opts, keys, who) {
  guard.identifier.assertKnownKeys(opts, keys, _err, "hpke/bad-input", function (k) {
    var other = (keys === _SETUP_S_KEYS ? _SETUP_R_KEYS : _SETUP_S_KEYS);
    return "unknown HPKE " + who + " option " + JSON.stringify(k) +
      (_hasOwn(other, k)
        ? " -- that option belongs to the other end of the exchange, where it would authenticate or seed; here it would do nothing"
        : "") + " -- accepted: " + Object.keys(keys).sort().join(", ");
  });
  var mode = (opts.mode == null) ? MODE_BASE : opts.mode;
  if (mode !== MODE_BASE && mode !== MODE_PSK && mode !== MODE_AUTH && mode !== MODE_AUTH_PSK) {
    throw _err("hpke/unknown-mode", "unsupported HPKE mode " + JSON.stringify(mode) + " (RFC 9180 sec. 5.1 defines base / psk / auth / auth-psk)");
  }
  return mode;
}

// @module @intro; a data registry, not a callable primitive).
var suites = {
  KEM: { DHKEM_P256_HKDF_SHA256: 0x0010, DHKEM_P521_HKDF_SHA512: 0x0012, DHKEM_X25519_HKDF_SHA256: 0x0020, DHKEM_X448_HKDF_SHA512: 0x0021 },
  KDF: { HKDF_SHA256: 0x0001, HKDF_SHA512: 0x0003 },
  AEAD: { AES_128_GCM: 0x0001, AES_256_GCM: 0x0002, CHACHA20_POLY1305: 0x0003, EXPORT_ONLY: 0xFFFF },
  MODE: { BASE: MODE_BASE, PSK: MODE_PSK, AUTH: MODE_AUTH, AUTH_PSK: MODE_AUTH_PSK },
};


/**
 * @primitive pki.hpke.setupS
 * @signature pki.hpke.setupS(suiteIds, recipientPublicKey, opts?) -> { enc, context }
 * @since 0.2.2
 * @status stable
 * @spec RFC 9180
 * @related pki.hpke.setupR, pki.hpke.seal
 *
 * Establish a sender HPKE context for a recipient KEM public key: encapsulate a
 * shared secret and run the key schedule, returning the encapsulated key `enc`
 * (send it to the recipient) and a `context` whose `.seal(aad, pt)` /
 * `.export(ctx, L)` encrypt and derive further secrets. `suiteIds` is
 * `{ kem, kdf, aead }` from `pki.hpke.suites`; `recipientPublicKey` is a node
 * KeyObject or the serialized public key bytes. `opts.mode` selects base / psk /
 * auth / auth-psk (default base); `opts.info`, `opts.psk`/`opts.pskId`, and
 * `opts.senderKey` (auth modes) supply the corresponding inputs.
 *
 * @example
 *   var s = pki.hpke.suites, ids = { kem: s.KEM.DHKEM_X25519_HKDF_SHA256, kdf: s.KDF.HKDF_SHA256, aead: s.AEAD.AES_128_GCM };
 *   var pkR = Buffer.from("8c7781768956b9dd38997c5a83ab5b9315270a9f73d87d676573c5bca74e3e48", "hex");
 *   var sender = pki.hpke.setupS(ids, pkR, { info: Buffer.from("app") });
 *   var ct = sender.context.seal(Buffer.from("aad"), Buffer.from("secret"));
 */
function _setupS(ids, pkR, opts) {
  opts = opts || {};
  var suite = _suite(ids);
  var mode = _mode(opts, _SETUP_S_KEYS, "sender setup");
  var r = _recipPublic(suite, pkR);
  var kem = suite.kem, k;
  if (mode === MODE_AUTH || mode === MODE_AUTH_PSK) {
    if (kem.kind !== "ec" && kem.kind !== "okp") throw _err("hpke/auth-unsupported", "the KEM does not support authenticated modes");
    if (opts.senderKey == null) throw _err("hpke/auth-key-required", "an authenticated mode requires opts.senderKey (the sender's KEM private key, RFC 9180 sec. 5.1.3)");
    var s = _recipPrivate(suite, opts.senderKey);
    k = _authEncap(kem, r.key, r.pkm, s.key, s.pkm, opts.eph);
  } else {
    k = _encap(kem, r.key, r.pkm, opts.eph);
  }
  var ctx = _keySchedule(suite, mode, k.sharedSecret, _buf(opts.info), _buf(opts.psk), _buf(opts.pskId), "S");
  return { enc: k.enc, context: ctx, sharedSecret: k.sharedSecret };
}
/**
 * @primitive pki.hpke.setupR
 * @signature pki.hpke.setupR(suiteIds, enc, recipientPrivateKey, opts?) -> context
 * @since 0.2.2
 * @status stable
 * @spec RFC 9180
 * @related pki.hpke.setupS, pki.hpke.open
 *
 * Establish the recipient HPKE context from the sender's encapsulated key `enc`
 * and the recipient KEM private key (a node KeyObject, or `{ skm, pkm }` holding
 * the raw private scalar plus its public point),
 * recovering the same shared secret and key schedule. The returned `context`
 * `.open(aad, ct)` decrypts and `.export(ctx, L)` derives secrets. `opts` mirrors
 * `setupS` (mode / info / psk / pskId), with `opts.senderPublicKey` for the auth
 * modes. A ciphertext whose tag does not verify throws `hpke/open-failed`.
 *
 * @example
 *   var s = pki.hpke.suites, ids = { kem: s.KEM.DHKEM_X25519_HKDF_SHA256, kdf: s.KDF.HKDF_SHA256, aead: s.AEAD.AES_128_GCM };
 *   var pkR = Buffer.from("8c7781768956b9dd38997c5a83ab5b9315270a9f73d87d676573c5bca74e3e48", "hex");
 *   var skR = Buffer.from("009f2181fba5f8908632c10ea1137c40a849728fde016c4602458b943a5dc048", "hex");
 *   var sender = pki.hpke.setupS(ids, pkR);
 *   var recipient = pki.hpke.setupR(ids, sender.enc, { skm: skR, pkm: pkR });
 *   var pt = recipient.open(Buffer.alloc(0), sender.context.seal(Buffer.alloc(0), Buffer.from("hi")));
 */
function _setupR(ids, enc, skR, opts) {
  opts = opts || {};
  var suite = _suite(ids);
  var mode = _mode(opts, _SETUP_R_KEYS, "recipient setup");
  var r = _recipPrivate(suite, skR);
  var kem = suite.kem, ss;
  if (mode === MODE_AUTH || mode === MODE_AUTH_PSK) {
    if (opts.senderPublicKey == null) throw _err("hpke/auth-key-required", "an authenticated mode requires opts.senderPublicKey (the sender's KEM public key, RFC 9180 sec. 5.1.3)");
    var pkS = _recipPublic(suite, opts.senderPublicKey);
    ss = _authDecap(kem, _buf(enc), r.key, r.pkm, pkS.key, pkS.pkm);
  } else {
    ss = _decap(kem, _buf(enc), r.key, r.pkm);
  }
  try { return _keySchedule(suite, mode, ss, _buf(opts.info), _buf(opts.psk), _buf(opts.pskId), "R"); }
  finally { guard.secret.zeroize(ss, HpkeError, "hpke/bad-input", "the KEM shared secret"); }
}

/**
 * @primitive pki.hpke.seal
 * @signature pki.hpke.seal(suiteIds, recipientPublicKey, opts, aad, pt) -> { enc, ct }
 * @since 0.2.2
 * @status stable
 * @spec RFC 9180
 * @related pki.hpke.open, pki.hpke.setupS
 *
 * Single-shot HPKE encryption (RFC 9180 sec. 6): set up a sender context and
 * encrypt one plaintext, returning the encapsulated key `enc` and ciphertext
 * `ct`. Equivalent to `setupS` followed by one `context.seal`. `opts` is the
 * `setupS` options object (mode / info / psk / senderKey).
 *
 * @example
 *   var s = pki.hpke.suites, ids = { kem: s.KEM.DHKEM_X25519_HKDF_SHA256, kdf: s.KDF.HKDF_SHA256, aead: s.AEAD.AES_256_GCM };
 *   var pkR = Buffer.from("8c7781768956b9dd38997c5a83ab5b9315270a9f73d87d676573c5bca74e3e48", "hex");
 *   var out = pki.hpke.seal(ids, pkR, {}, Buffer.from("aad"), Buffer.from("msg"));
 */
function seal(ids, pkR, opts, aad, pt) {
  var s = null;
  try {
  s = _setupS(ids, pkR, opts);
  return { enc: s.enc, ct: s.context.seal(_buf(aad), _buf(pt)) };
  } finally {
    if (s) {
      s.context._dispose();
      guard.secret.zeroize(s.sharedSecret, HpkeError, "hpke/bad-input", "the KEM shared secret");
    }
  }
}

/**
 * @primitive pki.hpke.open
 * @signature pki.hpke.open(suiteIds, enc, recipientPrivateKey, opts, aad, ct) -> pt
 * @since 0.2.2
 * @status stable
 * @spec RFC 9180
 * @related pki.hpke.seal, pki.hpke.setupR
 *
 * Single-shot HPKE decryption (RFC 9180 sec. 6): set up a recipient context from
 * `enc` and decrypt one ciphertext, returning the plaintext. A tag that does not
 * verify throws `hpke/open-failed` and returns no plaintext.
 *
 * @example
 *   var s = pki.hpke.suites, ids = { kem: s.KEM.DHKEM_X25519_HKDF_SHA256, kdf: s.KDF.HKDF_SHA256, aead: s.AEAD.AES_256_GCM };
 *   var pkR = Buffer.from("8c7781768956b9dd38997c5a83ab5b9315270a9f73d87d676573c5bca74e3e48", "hex");
 *   var skR = Buffer.from("009f2181fba5f8908632c10ea1137c40a849728fde016c4602458b943a5dc048", "hex");
 *   var o = pki.hpke.seal(ids, pkR, {}, Buffer.alloc(0), Buffer.from("m"));
 *   var pt = pki.hpke.open(ids, o.enc, { skm: skR, pkm: pkR }, {}, Buffer.alloc(0), o.ct);
 */
function open(ids, enc, skR, opts, aad, ct) {
  var ctx = _setupR(ids, enc, skR, opts);
  try { return ctx.open(_buf(aad), _buf(ct)); }
  finally { ctx._dispose(); }
}

module.exports = {
  suites: suites,
  setupS: _setupS, setupR: _setupR,
  seal: seal, open: open,
};
