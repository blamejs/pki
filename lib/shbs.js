// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.shbs
 * @nav        Signatures
 * @title      Stateful hash-based
 * @fullname   Stateful hash-based signatures: LMS and XMSS
 * @intro Stateful hash-based signature VERIFICATION -- HSS/LMS (RFC 8554),
 *   carried in X.509 by RFC 9802 and in CMS by RFC 9708, profiled by NIST
 *   SP 800-208. Verify only, by deliberate design: stateful hash-based signing
 *   is catastrophic to get wrong. Each one-time key must be used exactly once,
 *   so the private key embeds a monotonic index whose state must advance and
 *   persist atomically across every signature and every process restart. A single
 *   index reuse (a restored VM snapshot, a crashed writer, a concurrent signer)
 *   forfeits security and can leak enough one-time-key material to forge, which is
 *   why SP 800-208 sec. 8 constrains signing-state handling to hardware. So this
 *   module never mints a signature; it verifies signatures produced in an HSM
 *   elsewhere. Verification is pure public-input SHA-256 / SHAKE256 hashing
 *   (no secret, no side-channel surface), so a pure-JavaScript verifier is safe.
 * @spec RFC 8554, RFC 9802, RFC 9708, NIST SP 800-208
 * @card Verify HSS/LMS signatures (post-quantum, CNSA 2.0 firmware signing).
 */

var nodeCrypto = require("crypto");
var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var constants = require("./constants");

var ShbsError = frameworkError.ShbsError;
function _err(code, message, cause) { return new ShbsError(code, message, cause); }


function u8(x) { return Buffer.from([x & 0xff]); }
function u16(x) { return Buffer.from([(x >> 8) & 0xff, x & 0xff]); }
function u32(x) { return Buffer.from([(x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff]); }

var D_PBLC = 0x8080;
var D_MESG = 0x8181;
var D_LEAF = 0x8282;
var D_INTR = 0x8383;


function _ilog2(x) { var r = 0; while (x > 1) { x = Math.floor(x / 2); r += 1; } return r; }

function _deriveWinternitz(n, w) {
  var u = Math.ceil((8 * n) / w);
  var v = Math.ceil((_ilog2((Math.pow(2, w) - 1) * u) + 1) / w);
  return { p: u + v, ls: 16 - v * w };
}

var LMS_SETS = {};
var LMOTS_SETS = {};
(function seed() {
  var heights = [5, 10, 15, 20, 25];
  var ws = [1, 2, 4, 8];
  [{ base: 0x05, m: 32, f: "sha256" }, { base: 0x0A, m: 24, f: "sha256" },
   { base: 0x0F, m: 32, f: "shake256" }, { base: 0x14, m: 24, f: "shake256" }].forEach(function (fam) {
    heights.forEach(function (h, i) { LMS_SETS[fam.base + i] = { code: fam.base + i, m: fam.m, h: h, hashFamily: fam.f }; });
  });
  [{ base: 0x01, n: 32, f: "sha256" }, { base: 0x05, n: 24, f: "sha256" },
   { base: 0x09, n: 32, f: "shake256" }, { base: 0x0D, n: 24, f: "shake256" }].forEach(function (fam) {
    ws.forEach(function (w, i) {
      var d = _deriveWinternitz(fam.n, w);
      LMOTS_SETS[fam.base + i] = { code: fam.base + i, n: fam.n, w: w, p: d.p, ls: d.ls, hashFamily: fam.f };
    });
  });
})();

function _lmsSet(code) {
  var s = LMS_SETS[code];
  if (!s) throw _err("shbs/unsupported-parameter-set", "unrecognized or unapproved LMS typecode 0x" + code.toString(16));
  return s;
}
function _lmotsSet(code) {
  var s = LMOTS_SETS[code];
  if (!s) throw _err("shbs/unsupported-parameter-set", "unrecognized or unapproved LM-OTS typecode 0x" + code.toString(16));
  return s;
}

function _hash(family, n, parts) {
  var h;
  if (family === "shake256") h = nodeCrypto.createHash("shake256", { outputLength: n });
  else h = nodeCrypto.createHash("sha256");
  for (var i = 0; i < parts.length; i++) h.update(parts[i]);
  var d = h.digest();
  return (family === "shake256" || n === 32) ? d : d.subarray(0, n);
}


function Reader(buf, code, label) { this.buf = buf; this.pos = 0; this.code = code; this.label = label; }
Reader.prototype._need = function (k) {
  if (k < 0 || this.pos + k > this.buf.length) {
    throw _err(this.code, this.label + " is truncated (needed " + k + " byte(s) at offset " + this.pos + ", have " + (this.buf.length - this.pos) + ")");
  }
};
Reader.prototype.u32 = function () { this._need(4); var v = this.buf.readUInt32BE(this.pos); this.pos += 4; return v; };
Reader.prototype.take = function (k) { this._need(k); var b = this.buf.subarray(this.pos, this.pos + k); this.pos += k; return b; };
Reader.prototype.remaining = function () { return this.buf.length - this.pos; };
Reader.prototype.atEnd = function () { return this.pos === this.buf.length; };


function _coef(S, i, w) {
  var idx = Math.floor((i * w) / 8);
  if (idx >= S.length) throw _err("shbs/bad-signature", "Winternitz coefficient index out of range");
  var shift = 8 - (w * (i % (8 / w)) + w);
  return ((1 << w) - 1) & (S[idx] >> shift);
}

function _cksm(Q, set) {
  var w = set.w, sum = 0, u = Math.ceil((8 * set.n) / w);
  for (var i = 0; i < u; i++) sum += ((1 << w) - 1) - _coef(Q, i, w);
  sum = (sum << set.ls) & 0xffff;
  return u16(sum);
}


function _lmotsKc(otsSet, I, q, C, y, message) {
  var n = otsSet.n, w = otsSet.w, p = otsSet.p, f = otsSet.hashFamily;
  var qb = u32(q);
  var Q = _hash(f, n, [I, qb, u16(D_MESG), C, message]);
  var Qc = Buffer.concat([Q, _cksm(Q, otsSet)]);
  var z = [I, qb, u16(D_PBLC)];
  for (var i = 0; i < p; i++) {
    var a = _coef(Qc, i, w);
    var tmp = y[i];
    for (var j = a; j < (1 << w) - 1; j++) tmp = _hash(f, n, [I, qb, u16(i), u8(j), tmp]);
    z.push(tmp);
  }
  return _hash(f, n, z);
}


function _lmsVerify(pubBytes, message, sigBytes) {
  if (pubBytes.length < 8) throw _err("shbs/bad-public-key", "LMS public key is shorter than 8 bytes");
  var pr = new Reader(pubBytes, "shbs/bad-public-key", "LMS public key");
  var lmsSet = _lmsSet(pr.u32());
  var otsSet = _lmotsSet(pr.u32());
  var m = lmsSet.m, h = lmsSet.h;
  if (pubBytes.length !== 24 + m) throw _err("shbs/bad-public-key", "LMS public key must be exactly " + (24 + m) + " bytes");
  var I = pr.take(16);
  var T1 = pr.take(m);

  if (sigBytes.length < 8) throw _err("shbs/bad-signature", "LMS signature is shorter than 8 bytes");
  var sr = new Reader(sigBytes, "shbs/bad-signature", "LMS signature");
  var q = sr.u32();
  var otsSigType = sr.u32();
  if (otsSigType !== otsSet.code) return false;
  var n = otsSet.n, p = otsSet.p;
  var C = sr.take(n);
  var y = [];
  for (var yi = 0; yi < p; yi++) y.push(sr.take(n));
  var sigLmsType = sr.u32();
  if (sigLmsType !== lmsSet.code) return false;
  var path = [];
  for (var pi = 0; pi < h; pi++) path.push(sr.take(m));
  if (!sr.atEnd()) throw _err("shbs/bad-signature", "LMS signature has " + sr.remaining() + " trailing byte(s)");
  if (q >= Math.pow(2, h)) return false;

  var Kc = _lmotsKc(otsSet, I, q, C, y, message);
  var nodeNum = Math.pow(2, h) + q;
  var tmp = _hash(lmsSet.hashFamily, m, [I, u32(nodeNum), u16(D_LEAF), Kc]);
  for (var i2 = 0; nodeNum > 1; i2++) {
    var parent = Math.floor(nodeNum / 2);
    if (nodeNum % 2 === 1) {
      tmp = _hash(lmsSet.hashFamily, m, [I, u32(parent), u16(D_INTR), path[i2], tmp]);
    } else {
      tmp = _hash(lmsSet.hashFamily, m, [I, u32(parent), u16(D_INTR), tmp, path[i2]]);
    }
    nodeNum = parent;
  }
  return guard.crypto.constantTimeEqual(tmp, T1);
}

function _consumeLmsPublicKey(r) {
  var start = r.pos;
  var code = r.u32();
  r.u32();
  var m = _lmsSet(code).m;
  r.take(16 + m);
  return r.buf.subarray(start, r.pos);
}

function _lmsSigLen(keyBytes) {
  if (keyBytes.length < 8) throw _err("shbs/bad-public-key", "LMS public key is shorter than 8 bytes");
  var lmsSet = _lmsSet(keyBytes.readUInt32BE(0));
  var otsSet = _lmotsSet(keyBytes.readUInt32BE(4));
  return 12 + otsSet.n * (otsSet.p + 1) + lmsSet.m * lmsSet.h;
}


function _hssVerify(pubBytes, message, sigBytes) {
  if (pubBytes.length < 4) throw _err("shbs/bad-public-key", "HSS public key is shorter than 4 bytes");
  var pr = new Reader(pubBytes, "shbs/bad-public-key", "HSS public key");
  var L = pr.u32();
  if (L < 1 || L > constants.LIMITS.HSS_MAX_LEVELS) throw _err("shbs/bad-public-key", "HSS level count L=" + L + " is outside 1.." + constants.LIMITS.HSS_MAX_LEVELS);
  var topKey = pr.buf.subarray(pr.pos);

  var sr = new Reader(sigBytes, "shbs/bad-signature", "HSS signature");
  var Nspk = sr.u32();
  if (Nspk + 1 !== L) throw _err("shbs/bad-signature", "HSS Nspk+1 (" + (Nspk + 1) + ") does not equal the public-key level count L (" + L + ")");

  var key = topKey;
  for (var i = 0; i < Nspk; i++) {
    var sig = sr.take(_lmsSigLen(key));
    var nextKey = _consumeLmsPublicKey(sr);
    if (!_lmsVerify(key, nextKey, sig)) return false;
    key = nextKey;
  }
  return _lmsVerify(key, message, sr.buf.subarray(sr.pos));
}


function _asBytes(x, label) { return guard.bytes.source(x, ShbsError, "shbs/bad-input", label); }

/**
 * @primitive pki.shbs.verify
 * @signature pki.shbs.verify(publicKey, message, signature) -> boolean
 * @since 0.2.1
 * @status stable
 * @spec RFC 8554 sec. 6, RFC 9802, RFC 9708
 * @related pki.shbs.verifyLms
 *
 * Verify an HSS (Hierarchical Signature System) signature over `message` under
 * `publicKey` -- the wire form RFC 9802 (X.509) and RFC 9708 (CMS) carry for
 * `id-alg-hss-lms-hashsig`. The public key and signature are the raw HSS octet
 * blobs the certificate / CMS parsers already surface (no ASN.1 wrapping). Every
 * level of the hierarchy must verify: a single failing level yields false.
 * Returns true for a valid signature, false for a well-formed signature that does
 * not verify; a malformed blob (bad length, unknown or unapproved typecode,
 * truncation, a typecode disagreeing between the key and the signature) throws a
 * typed `ShbsError`. Verification only: this module never signs.
 *
 * @example
 *   // throws: shbs/bad-public-key -- an Ed25519 key is not an HSS public key, and
 *   // the verifier fails closed on the wrong key type rather than returning true
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var cert = pki.schema.x509.parse(der);
 *   var ok = pki.shbs.verify(cert.subjectPublicKeyInfo.publicKey.bytes,
 *                            cert.tbsBytes, cert.signatureValue.bytes);
 */
function verify(publicKey, message, signature) {
  return _hssVerify(_asBytes(publicKey, "public key"), _asBytes(message, "message"), _asBytes(signature, "signature"));
}

/**
 * @primitive pki.shbs.verifyLms
 * @signature pki.shbs.verifyLms(publicKey, message, signature) -> boolean
 * @since 0.2.1
 * @status stable
 * @spec RFC 8554 sec. 5
 * @related pki.shbs.verify
 *
 * Verify a single-tree LMS (Leighton-Micali Signature) over `message`: the
 * component an HSS hierarchy composes at each level, and a standalone algorithm
 * in its own right. Same verdict contract as `pki.shbs.verify`: true / false for
 * a well-formed signature, a typed `ShbsError` for a malformed blob.
 *
 * @example
 *   // throws: shbs/unsupported-parameter-set -- lmsPublicKey / lmsSignature are raw
 *   // LMS blobs (an HSS level, or a bare LMS-signed artifact); arbitrary bytes carry
 *   // no recognized LMS typecode, so the verifier refuses them instead of returning
 *   var bytes = Buffer.alloc(64);
 *   var ok = pki.shbs.verifyLms(bytes, bytes, bytes);
 */
function verifyLms(publicKey, message, signature) {
  return _lmsVerify(_asBytes(publicKey, "public key"), _asBytes(message, "message"), _asBytes(signature, "signature"));
}

module.exports = { verify: verify, verifyLms: verifyLms };
