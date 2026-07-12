// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.hpke
 * @nav        Protocols
 * @title      HPKE
 * @intro Hybrid Public Key Encryption (RFC 9180) -- the standard construction
 *   behind TLS Encrypted Client Hello, MLS, and OHTTP that turns a recipient KEM
 *   public key into an encapsulated key plus an AEAD-encrypting context. This is
 *   the RFC 9180 base construction: the DHKEM suites P-256, P-521, X25519, and
 *   X448, HKDF-SHA256 / HKDF-SHA512, the three AEADs plus export-only, and all
 *   four modes (base / psk / auth / auth-psk), each proven against the RFC 9180
 *   Appendix A known-answer vectors. DHKEM(P-384) and HKDF-SHA384 are RFC-registered
 *   but Appendix A ships no test vector for them, so they are omitted (a request
 *   fails closed) until an authoritative KAT is available. Pure composition over
 *   node:crypto -- no ASN.1, no schema engine. Post-quantum KEMs (ML-KEM, X-Wing)
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

var HpkeError = frameworkError.HpkeError;
function _err(code, message, cause) { return new HpkeError(code, message, cause); }

// ---- I2OSP + byte helpers ----------------------------------------------------

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

// ---- registries (RFC 9180 sec. 7, Tables 2/3/5 -- data, not switch) ----------

// KDF: id -> { hash (node name), Nh }.
// HKDF-SHA384 (0x0002) and DHKEM(P-384) (0x0011) are registered by RFC 9180 sec.
// 7 but Appendix A / the cited [TestVectors] file ship no known-answer vector for
// them, so they are omitted here until an authoritative KAT exists -- a request
// for either fails closed as hpke/unknown-suite rather than running crypto no
// test vector proves. They admit as a one-row addition the moment a KAT lands.
var KDFS = {
  0x0001: { hash: "sha256", Nh: 32 },
  0x0003: { hash: "sha512", Nh: 64 },
};
// AEAD: id -> { cipher (node name), Nk, Nn, Nt } or exportOnly.
var AEADS = {
  0x0001: { cipher: "aes-128-gcm", Nk: 16, Nn: 12, Nt: 16 },
  0x0002: { cipher: "aes-256-gcm", Nk: 32, Nn: 12, Nt: 16 },
  0x0003: { cipher: "chacha20-poly1305", Nk: 32, Nn: 12, Nt: 16 },
  0xFFFF: { exportOnly: true, Nn: 12 },
};
// KEM: id -> DHKEM group descriptor. `group` is the node keygen/import family;
// `kdf` is the KEM-internal KDF (its ExtractAndExpand); Nsecret = that KDF's Nh.
var KEMS = {
  0x0010: { kind: "ec", curve: "P-256", nodeCurve: "prime256v1", kdf: 0x0001, Nsecret: 32, Npub: 65 },
  0x0012: { kind: "ec", curve: "P-521", nodeCurve: "secp521r1", kdf: 0x0003, Nsecret: 64, Npub: 133 },
  0x0020: { kind: "okp", curve: "X25519", oid: "2b656e", kdf: 0x0001, Nsecret: 32, Npub: 32 },
  0x0021: { kind: "okp", curve: "X448", oid: "2b656f", kdf: 0x0003, Nsecret: 64, Npub: 56 },
};

var MODE_BASE = 0x00, MODE_PSK = 0x01, MODE_AUTH = 0x02, MODE_AUTH_PSK = 0x03;

// Format a code point for an error message without assuming it is a number: a
// missing suiteIds member arrives as undefined, and undefined.toString(16) would
// crash the very error path meant to report it.
function _idStr(id) { return typeof id === "number" ? "0x" + id.toString(16) : String(id); }
function _kem(id) { var s = KEMS[id]; if (!s) throw _err("hpke/unknown-suite", "unsupported KEM id " + _idStr(id)); return s; }
function _kdf(id) { var s = KDFS[id]; if (!s) throw _err("hpke/unknown-suite", "unsupported KDF id " + _idStr(id)); return s; }
function _aead(id) { var s = AEADS[id]; if (!s) throw _err("hpke/unknown-suite", "unsupported AEAD id " + _idStr(id)); return s; }

// ---- labeled KDF (RFC 9180 sec. 4): HKDF Extract/Expand SPLIT over HMAC -------
// suite_id is the caller's ("KEM"||... for the KEM layer, "HPKE"||... for the
// rest). Extract = HMAC(salt-or-zeros, ikm); Expand = RFC 5869 sec. 2.3 feedback.

function _extract(hash, Nh, salt, ikm) {
  var key = (salt && salt.length) ? salt : Buffer.alloc(Nh);
  return nodeCrypto.createHmac(hash, key).update(ikm).digest();
}
function _expand(hash, Nh, prk, info, len) {
  if (len > 255 * Nh) throw _err("hpke/export-length", "requested length " + len + " exceeds 255*Nh");
  var out = [], t = Buffer.alloc(0), n = Math.ceil(len / Nh);
  for (var i = 1; i <= n; i++) {
    t = nodeCrypto.createHmac(hash, prk).update(concat([t, info, Buffer.from([i])])).digest();
    out.push(t);
  }
  return concat(out).subarray(0, len);
}
function _labeledExtract(kdf, suiteId, salt, label, ikm) {
  return _extract(kdf.hash, kdf.Nh, salt, concat([HPKE_V1, suiteId, L(label), ikm]));
}
function _labeledExpand(kdf, suiteId, prk, label, info, len) {
  return _expand(kdf.hash, kdf.Nh, prk, concat([i2osp(len, 2), HPKE_V1, suiteId, L(label), info]), len);
}

// ---- KEM key (de)serialization + Diffie-Hellman (node:crypto) ----------------

var OKP_SPKI = { X25519: "302a300506032b656e032100", X448: "3042300506032b656f033900" };
var OKP_PKCS8 = { X25519: "302e020100300506032b656e04220420", X448: "3046020100300506032b656f043a0438" };

// Deserialize a serialized KEM public key (enc / pkRm / pkSm) into a node
// KeyObject. EC is an uncompressed 0x04 point (SerializePublicKey, sec. 7.1.1);
// OKP is the raw curve point. A wrong length / shape fails closed.
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
// Serialize a node public KeyObject back to the RFC 9180 wire encoding.
function _exportPublic(kem, keyObject) {
  var jwk = keyObject.export({ format: "jwk" });
  if (kem.kind === "ec") return concat([Buffer.from([0x04]), _b64u(jwk.x), _b64u(jwk.y)]);
  return _b64u(jwk.x);
}
// Node's own JWK export -- decode its canonical base64url coordinates through the
// guard so the alphabet/canonicality check is the single shared choke point.
function _b64u(s) { return guard.encoding.base64url(s, null, _err, "hpke/bad-key", "JWK coordinate"); }

// Import a serialized KEM private key (skRm / skEm / skSm) into a node KeyObject,
// given the matching serialized public key for the EC JWK (or none for OKP).
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
// The single KEM Diffie-Hellman choke point. node:crypto throws a raw
// ERR_OSSL_FAILED_DURING_DERIVATION when the peer point is low-order / invalid
// (an all-zero X25519 shared secret, a point not on the curve). RFC 9180 sec.
// 4.1: Decap raises an error on DH failure -- surface it as a typed hpke/bad-key
// so no raw OpenSSL error escapes any encap / decap path.
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

// ---- DHKEM (RFC 9180 sec. 4.1) -----------------------------------------------

function _kemSuiteId(kemId) { return concat([L("KEM"), i2osp(kemId, 2)]); }
function _extractAndExpand(kem, dh, kemContext) {
  var kdf = _kdf(kem.kdf), sid = _kemSuiteId(_kemId(kem));
  var eaePrk = _labeledExtract(kdf, sid, Buffer.alloc(0), "eae_prk", dh);
  return _labeledExpand(kdf, sid, eaePrk, "shared_secret", kemContext, kem.Nsecret);
}
function _kemId(kem) { for (var k in KEMS) if (KEMS[k] === kem) return Number(k); return 0; }

// Encap(pkR) -> { sharedSecret, enc }. An injected ephemeral (skE, pkEnc) makes
// the KAT deterministic; otherwise a fresh ephemeral is generated.
function _ephemeral(kem, eph) {
  if (eph) return { skE: _importPrivate(kem, eph.skm, eph.pkm), enc: _buf(eph.pkm) };
  var kp = _generate(kem);
  return { skE: kp.privateKey, enc: _exportPublic(kem, kp.publicKey) };
}
function _encap(kem, pkR, pkRm, eph) {
  var e = _ephemeral(kem, eph);
  var dh = _dh(e.skE, pkR);
  return { sharedSecret: _extractAndExpand(kem, dh, concat([e.enc, pkRm])), enc: e.enc };
}
function _decap(kem, enc, skR, pkRm) {
  var pkE = _importPublic(kem, enc);
  var dh = _dh(skR, pkE);
  return _extractAndExpand(kem, dh, concat([enc, pkRm]));
}
function _authEncap(kem, pkR, pkRm, skS, pkSm, eph) {
  var e = _ephemeral(kem, eph);
  var dh = concat([_dh(e.skE, pkR), _dh(skS, pkR)]);
  return { sharedSecret: _extractAndExpand(kem, dh, concat([e.enc, pkRm, pkSm])), enc: e.enc };
}
function _authDecap(kem, enc, skR, pkRm, pkS, pkSm) {
  var pkE = _importPublic(kem, enc);
  var dh = concat([_dh(skR, pkE), _dh(skR, pkS)]);
  return _extractAndExpand(kem, dh, concat([enc, pkRm, pkSm]));
}

// ---- key schedule (RFC 9180 sec. 5.1) ----------------------------------------

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
  var exporterSecret = _labeledExpand(kdf, sid, secret, "exp", ksc, kdf.Nh);
  var key = null, baseNonce = null;
  if (!aead.exportOnly) {
    key = _labeledExpand(kdf, sid, secret, "key", ksc, aead.Nk);
    baseNonce = _labeledExpand(kdf, sid, secret, "base_nonce", ksc, aead.Nn);
  }
  return new Context(suite, key, baseNonce, exporterSecret, role);
}

// ---- AEAD context (RFC 9180 sec. 5.2 / 5.3) ----------------------------------

// role is "S" (sender: seal only) or "R" (recipient: open only). Sender and
// recipient derive the same key + base_nonce, so a wrong-direction call would
// reuse a nonce (RFC 9180 sec. 5.2); export is available to both.
function Context(suite, key, baseNonce, exporterSecret, role) {
  this._suite = suite; this._key = key; this._baseNonce = baseNonce;
  this._exporterSecret = exporterSecret; this._seq = 0n; this._role = role;
}
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
  var body = concat([c.update(_buf(pt)), c.final()]);
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
  try { pt = concat([d.update(ct.subarray(0, ct.length - aead.Nt)), d.final()]); }
  catch (e) { throw _err("hpke/open-failed", "AEAD authentication failed (RFC 9180 sec. 5.2)", e); }
  this._inc();
  return pt;
};
Context.prototype.export = function (exporterContext, len) {
  if (!Number.isInteger(len) || len < 0) throw _err("hpke/export-length", "export length must be a non-negative integer");
  return _labeledExpand(this._suite.kdf, this._suite.suiteId, this._exporterSecret, "sec", _buf(exporterContext), len);
};
function _buf(x) { return Buffer.isBuffer(x) ? x : Buffer.from(x || []); }

// ---- suite resolution + setup ------------------------------------------------

function _suite(ids) {
  if (!ids || typeof ids !== "object") throw _err("hpke/unknown-suite", "suiteIds must be an object { kem, kdf, aead } from pki.hpke.suites");
  var kemId = ids.kem, kdfId = ids.kdf, aeadId = ids.aead;
  var kem = _kem(kemId), kdf = _kdf(kdfId), aead = _aead(aeadId);
  return { kem: kem, kdf: kdf, aead: aead, kemId: kemId, kdfId: kdfId, aeadId: aeadId, suiteId: _hpkeSuiteId(kemId, kdfId, aeadId) };
}

// A KEM key argument is a node KeyObject or serialized bytes: a public key as a
// raw buffer (or { pkm }), a private key as { skm, pkm } (raw scalar + public
// point). A KAT drives the deterministic path via those serialized forms.
function _recipPublic(suite, pk) {
  if (Buffer.isBuffer(pk)) return { key: _importPublic(suite.kem, pk), pkm: pk };
  if (pk && pk.pkm) return { key: _importPublic(suite.kem, pk.pkm), pkm: pk.pkm };
  // A node KeyObject: derive its wire form. A null/undefined/invalid value must
  // fail closed here rather than let node's export throw a raw error upward.
  try {
    return { key: pk, pkm: _exportPublic(suite.kem, pk) };
  } catch (e) {
    if (e instanceof HpkeError) throw e;
    throw _err("hpke/bad-key", "invalid KEM public key (expected a node KeyObject, a raw buffer, or { pkm })", e);
  }
}
function _recipPrivate(suite, sk) {
  if (sk && sk.skm) return { key: _importPrivate(suite.kem, sk.skm, sk.pkm), pkm: sk.pkm };
  // A raw scalar alone cannot be imported (an EC private key needs its public
  // point for the JWK), so the serialized private form is { skm, pkm }; reject a
  // bare buffer, and fail any other bad key closed rather than let node's
  // createPublicKey throw a raw error out of the setup path.
  if (Buffer.isBuffer(sk)) throw _err("hpke/bad-key", "a serialized private key must be provided as { skm, pkm } (raw scalar + public point), not a bare buffer");
  try {
    var pkm = _exportPublic(suite.kem, nodeCrypto.createPublicKey(sk));
    return { key: sk, pkm: pkm };
  } catch (e) {
    if (e instanceof HpkeError) throw e;
    throw _err("hpke/bad-key", "invalid recipient private key (expected a node KeyObject or { skm, pkm })", e);
  }
}

// Resolve and validate the HPKE mode: RFC 9180 sec. 5.1 defines exactly base /
// psk / auth / auth-psk. An unknown mode must fail closed, never key-schedule
// with an out-of-registry mode byte.
function _mode(opts) {
  var mode = (opts.mode == null) ? MODE_BASE : opts.mode;
  if (mode !== MODE_BASE && mode !== MODE_PSK && mode !== MODE_AUTH && mode !== MODE_AUTH_PSK) {
    throw _err("hpke/unknown-mode", "unsupported HPKE mode " + JSON.stringify(mode) + " (RFC 9180 sec. 5.1 defines base / psk / auth / auth-psk)");
  }
  return mode;
}

// pki.hpke.suites -- the RFC 9180 sec. 7 registry code points (KEM / KDF / AEAD /
// MODE), passed to the setup functions to select a ciphersuite (documented in the
// @module @intro; a data registry, not a callable primitive).
var suites = {
  KEM: { DHKEM_P256_HKDF_SHA256: 0x0010, DHKEM_P521_HKDF_SHA512: 0x0012, DHKEM_X25519_HKDF_SHA256: 0x0020, DHKEM_X448_HKDF_SHA512: 0x0021 },
  KDF: { HKDF_SHA256: 0x0001, HKDF_SHA512: 0x0003 },
  AEAD: { AES_128_GCM: 0x0001, AES_256_GCM: 0x0002, CHACHA20_POLY1305: 0x0003, EXPORT_ONLY: 0xFFFF },
  MODE: { BASE: MODE_BASE, PSK: MODE_PSK, AUTH: MODE_AUTH, AUTH_PSK: MODE_AUTH_PSK },
};

// setup*S(suiteIds, pkR, opts) -> { enc, context }. opts: { info, psk, pskId,
// senderKey (auth), eph (KAT determinism) }. setup*R(suiteIds, enc, skR, opts).

/**
 * @primitive pki.hpke.setupS
 * @signature pki.hpke.setupS(suiteIds, recipientPublicKey, opts?) -> { enc, context }
 * @since 0.2.2
 * @status experimental
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
  var mode = _mode(opts);
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
 * @status experimental
 * @spec RFC 9180
 * @related pki.hpke.setupS, pki.hpke.open
 *
 * Establish the recipient HPKE context from the sender's encapsulated key `enc`
 * and the recipient KEM private key (a node KeyObject or `{ skm, pkm }` -- the
 * raw private scalar plus its public point),
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
  var mode = _mode(opts);
  var r = _recipPrivate(suite, skR);
  var kem = suite.kem, ss;
  if (mode === MODE_AUTH || mode === MODE_AUTH_PSK) {
    if (opts.senderPublicKey == null) throw _err("hpke/auth-key-required", "an authenticated mode requires opts.senderPublicKey (the sender's KEM public key, RFC 9180 sec. 5.1.3)");
    var pkS = _recipPublic(suite, opts.senderPublicKey);
    ss = _authDecap(kem, _buf(enc), r.key, r.pkm, pkS.key, pkS.pkm);
  } else {
    ss = _decap(kem, _buf(enc), r.key, r.pkm);
  }
  return _keySchedule(suite, mode, ss, _buf(opts.info), _buf(opts.psk), _buf(opts.pskId), "R");
}

/**
 * @primitive pki.hpke.seal
 * @signature pki.hpke.seal(suiteIds, recipientPublicKey, opts, aad, pt) -> { enc, ct }
 * @since 0.2.2
 * @status experimental
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
  var s = _setupS(ids, pkR, opts);
  return { enc: s.enc, ct: s.context.seal(_buf(aad), _buf(pt)) };
}

/**
 * @primitive pki.hpke.open
 * @signature pki.hpke.open(suiteIds, enc, recipientPrivateKey, opts, aad, ct) -> pt
 * @since 0.2.2
 * @status experimental
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
  return _setupR(ids, enc, skR, opts).open(_buf(aad), _buf(ct));
}

module.exports = {
  suites: suites,
  setupS: _setupS, setupR: _setupR,
  seal: seal, open: open,
};
