// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.shbs
 * @nav        Signatures
 * @title      Stateful hash-based
 * @intro Stateful hash-based signature VERIFICATION -- HSS/LMS (RFC 8554),
 *   carried in X.509 by RFC 9802 and in CMS by RFC 9708, profiled by NIST
 *   SP 800-208. VERIFY ONLY, by deliberate design: stateful hash-based SIGNING
 *   is catastrophic to get wrong -- each one-time key must be used exactly once,
 *   so the private key embeds a monotonic index whose state must advance and
 *   persist atomically across every signature and every process restart. A single
 *   index reuse (a restored VM snapshot, a crashed writer, a concurrent signer)
 *   forfeits security and can leak enough one-time-key material to forge, which is
 *   why SP 800-208 sec. 8 constrains signing-state handling to hardware. So this
 *   module NEVER mints a signature -- it verifies signatures produced in an HSM
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

// ---- big-endian serialization (RFC 8554 sec. 3.1: network byte order) --------

function u8(x) { return Buffer.from([x & 0xff]); }
function u16(x) { return Buffer.from([(x >> 8) & 0xff, x & 0xff]); }
function u32(x) { return Buffer.from([(x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff]); }

// Domain separators (RFC 8554 sec. 7.1). All exceed 264 (the max Winternitz
// digit index i) so a security-string D can never collide with a chain-hash i,
// which occupies the same 2-byte offset (sec. 9.1).
var D_PBLC = 0x8080;   // LM-OTS public-key finalize
var D_MESG = 0x8181;   // message hash
var D_LEAF = 0x8282;   // LMS leaf hash
var D_INTR = 0x8383;   // LMS interior node hash

// ---- typecode registry (IANA Leighton-Micali Signatures; NIST SP 800-208) ----
// LMS   0x05..0x18 : {m, h, hashFamily}. LM-OTS 0x01..0x10 : {n, w, hashFamily}.
// p and ls are DERIVED from (n, w) per RFC 8554 sec. 4.1 / Appendix B so the
// table stays data, not a switch, and a wrong hardcoded p cannot creep in.

function _ilog2(x) { var r = 0; while (x > 1) { x = Math.floor(x / 2); r += 1; } return r; }

// RFC 8554 Appendix B: u = ceil(8n/w) hash digits; v = the checksum digit count;
// p = u + v total Winternitz digits; ls = the left-shift aligning the checksum's
// significant bits into the digit positions coef reads.
function _deriveWinternitz(n, w) {
  var u = Math.ceil((8 * n) / w);
  var v = Math.ceil((_ilog2((Math.pow(2, w) - 1) * u) + 1) / w);
  return { p: u + v, ls: 16 - v * w };
}

var LMS_SETS = {};
var LMOTS_SETS = {};
(function seed() {
  var heights = [5, 10, 15, 20, 25];   // H5..H25 in typecode order
  var ws = [1, 2, 4, 8];               // W1..W8 in typecode order
  // LMS families in IANA order: SHA-256/M32 (0x05), SHA-256/M24 (0x0A),
  // SHAKE/M32 (0x0F), SHAKE/M24 (0x14).
  [{ base: 0x05, m: 32, f: "sha256" }, { base: 0x0A, m: 24, f: "sha256" },
   { base: 0x0F, m: 32, f: "shake256" }, { base: 0x14, m: 24, f: "shake256" }].forEach(function (fam) {
    heights.forEach(function (h, i) { LMS_SETS[fam.base + i] = { code: fam.base + i, m: fam.m, h: h, hashFamily: fam.f }; });
  });
  // LM-OTS families: SHA-256/N32 (0x01), SHA-256/N24 (0x05), SHAKE/N32 (0x09),
  // SHAKE/N24 (0x0D).
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

// hashFamily + output length -> the n-byte hash of the concatenated inputs.
// SHA-256 truncated to n (n=24 is SHA-256/192); SHAKE256 with an n-byte output.
function _hash(family, n, parts) {
  var h;
  if (family === "shake256") h = nodeCrypto.createHash("shake256", { outputLength: n });
  else h = nodeCrypto.createHash("sha256");
  for (var i = 0; i < parts.length; i++) h.update(parts[i]);
  var d = h.digest();
  return (family === "shake256" || n === 32) ? d : d.subarray(0, n);
}

// ---- bounded big-endian reader (bounds-before-slice; the ct.js TlsReader model
// for a non-DER positional wire, kept shbs-local -- shbs needs u32 typecodes +
// fixed-n reads, not CT's length-prefixed vector helpers) --------------------

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

// ---- Winternitz digit + checksum (RFC 8554 sec. 3.1.3 / sec. 4.4) ------------

// coef(S, i, w): the i-th w-bit digit of S, big-endian WITHIN each byte (digit 0
// is the high-order w bits of byte 0). RFC 8554 sec. 3.1.3.
function _coef(S, i, w) {
  var idx = Math.floor((i * w) / 8);
  if (idx >= S.length) throw _err("shbs/bad-signature", "Winternitz coefficient index out of range");
  var shift = 8 - (w * (i % (8 / w)) + w);
  return ((1 << w) - 1) & (S[idx] >> shift);
}

// Cksm(Q) per RFC 8554 sec. 4.4: sum over the u message digits of (2^w-1 - digit),
// left-shifted by ls, as a 2-byte big-endian value. Computed over Q ALONE; the
// coefficient index space in the chain walk spans Q || Cksm(Q).
function _cksm(Q, set) {
  var w = set.w, sum = 0, u = Math.ceil((8 * set.n) / w);
  for (var i = 0; i < u; i++) sum += ((1 << w) - 1) - _coef(Q, i, w);
  sum = (sum << set.ls) & 0xffff;
  return u16(sum);
}

// ---- LM-OTS public-key candidate Kc (RFC 8554 Algorithm 4b) ------------------
// I, q identify the LMS leaf; otsSet is resolved from the PUBLIC KEY's otstype
// (the authority); C + y[] come from the signature. Returns the n-byte Kc.

function _lmotsKc(otsSet, I, q, C, y, message) {
  var n = otsSet.n, w = otsSet.w, p = otsSet.p, f = otsSet.hashFamily;
  var qb = u32(q);
  var Q = _hash(f, n, [I, qb, u16(D_MESG), C, message]);
  var Qc = Buffer.concat([Q, _cksm(Q, otsSet)]);
  var z = [I, qb, u16(D_PBLC)];
  for (var i = 0; i < p; i++) {
    var a = _coef(Qc, i, w);
    var tmp = y[i];
    // Chain to 2^w - 1 total applications; the bound is EXCLUSIVE (last j = 2^w-2),
    // matching key generation (RFC 8554 sec. 4.5 vs Algorithm 4b step 3).
    for (var j = a; j < (1 << w) - 1; j++) tmp = _hash(f, n, [I, qb, u16(i), u8(j), tmp]);
    z.push(tmp);
  }
  return _hash(f, n, z);
}

// ---- LMS verification core (RFC 8554 Algorithm 6 / 6a) -----------------------
// pubBytes = lmstype(4) || otstype(4) || I(16) || T[1](m); sigBytes an LMS
// signature. Returns true iff the recomputed Merkle root equals T[1]. Throws
// ShbsError on any structural fault; a well-formed-but-wrong signature -> false.

function _lmsVerify(pubBytes, message, sigBytes) {
  // -- public key (the authority for both typecodes; RFC 8554 Algorithm 6) --
  if (pubBytes.length < 8) throw _err("shbs/bad-public-key", "LMS public key is shorter than 8 bytes");
  var pr = new Reader(pubBytes, "shbs/bad-public-key", "LMS public key");
  var lmsSet = _lmsSet(pr.u32());
  var otsSet = _lmotsSet(pr.u32());
  var m = lmsSet.m, h = lmsSet.h;
  if (pubBytes.length !== 24 + m) throw _err("shbs/bad-public-key", "LMS public key must be exactly " + (24 + m) + " bytes");
  var I = pr.take(16);
  var T1 = pr.take(m);

  // -- signature (RFC 8554 Algorithm 6a). q first, then the LM-OTS signature,
  //    then the LMS typecode (AFTER the LM-OTS sig), then the auth path. --
  if (sigBytes.length < 8) throw _err("shbs/bad-signature", "LMS signature is shorter than 8 bytes");
  var sr = new Reader(sigBytes, "shbs/bad-signature", "LMS signature");
  var q = sr.u32();
  var otsSigType = sr.u32();
  // The public key -- never the attacker-controlled signature -- is the authority
  // (downgrade defense): a signature whose OTS typecode does not equal the one the
  // public key commits to cannot verify against it. RFC 8554 Algorithm 6a checks
  // the typecode (step 2c, and 2g for the LMS type below) BEFORE the length (steps
  // 2d / 2i), and returns INVALID -- a verification FAILURE (false), not a
  // structural error. So a mismatch is `false` at this point EVEN for a blob too
  // short to be a complete signature: the mismatch is decidable once q + typecode
  // are read (the bounded reader already threw if those 8 bytes are absent). A
  // matching typecode with a truncated body still throws below (bounds-before-
  // slice). Re-sizing the body by the signature's own mismatched typecode -- to
  // "fully validate before returning false" -- would violate this order and reject
  // a legitimate typecode-mutation test vector as malformed instead of INVALID.
  if (otsSigType !== otsSet.code) return false;
  var n = otsSet.n, p = otsSet.p;
  var C = sr.take(n);
  var y = [];
  for (var yi = 0; yi < p; yi++) y.push(sr.take(n));
  var sigLmsType = sr.u32();
  if (sigLmsType !== lmsSet.code) return false;   // RFC 8554 Algorithm 6a step 2g -> INVALID
  var path = [];
  for (var pi = 0; pi < h; pi++) path.push(sr.take(m));
  if (!sr.atEnd()) throw _err("shbs/bad-signature", "LMS signature has " + sr.remaining() + " trailing byte(s)");
  // RFC 8554 Algorithm 6a step 2i: a leaf index q >= 2^h is INVALID -- a
  // verification FAILURE (false), NOT a structural error. Checked here, AFTER the
  // exact-length validation above (a truncated / trailing blob already threw
  // typed), against the REGISTRY height, never the blob. 2^h fits Number (h<=25).
  if (q >= Math.pow(2, h)) return false;

  // -- recompute the LM-OTS public-key candidate, then fold the Merkle path --
  var Kc = _lmotsKc(otsSet, I, q, C, y, message);
  var nodeNum = Math.pow(2, h) + q;
  var tmp = _hash(lmsSet.hashFamily, m, [I, u32(nodeNum), u16(D_LEAF), Kc]);
  for (var i2 = 0; nodeNum > 1; i2++) {
    var parent = Math.floor(nodeNum / 2);
    if (nodeNum % 2 === 1) {
      // odd node_num: the current node is a RIGHT child, sibling on the LEFT.
      tmp = _hash(lmsSet.hashFamily, m, [I, u32(parent), u16(D_INTR), path[i2], tmp]);
    } else {
      tmp = _hash(lmsSet.hashFamily, m, [I, u32(parent), u16(D_INTR), tmp, path[i2]]);
    }
    nodeNum = parent;
  }
  // The root comparison is over PUBLIC values (T1 is in the public key, tmp is
  // derived from public inputs -- no secret, hence the module's "no side-channel
  // surface" note), so constant time is not strictly required. It routes through
  // the shared crypto guard anyway, for one length-checked comparison primitive
  // across the hash-tree verifiers (pki.merkle folds its root the same way).
  return guard.crypto.constantTimeEqual(tmp, T1);
}

// Consume exactly one LMS public key from a reader (an HSS inner key), returning
// its raw bytes; sized off the LMS typecode it leads with.
function _consumeLmsPublicKey(r) {
  var start = r.pos;
  var code = r.u32();       // lmstype
  r.u32();                  // otstype (validated when the key is verified)
  var m = _lmsSet(code).m;
  r.take(16 + m);           // I || T[1]
  return r.buf.subarray(start, r.pos);
}

// Consume exactly one LMS signature from a reader, returning its raw bytes; its
// length is 12 + n*(p+1) + m*h, resolved by parsing the two embedded typecodes.
function _consumeLmsSignature(r) {
  var start = r.pos;
  r.u32();                              // q
  var otsSet = _lmotsSet(r.u32());      // otstype
  r.take(otsSet.n * (otsSet.p + 1));    // C || y[0..p-1]
  var lmsSet = _lmsSet(r.u32());        // lmstype
  r.take(lmsSet.m * lmsSet.h);          // path[0..h-1]
  return r.buf.subarray(start, r.pos);
}

// ---- HSS verification (RFC 8554 sec. 6.3) ------------------------------------

function _hssVerify(pubBytes, message, sigBytes) {
  if (pubBytes.length < 4) throw _err("shbs/bad-public-key", "HSS public key is shorter than 4 bytes");
  var pr = new Reader(pubBytes, "shbs/bad-public-key", "HSS public key");
  var L = pr.u32();
  if (L < 1 || L > constants.LIMITS.HSS_MAX_LEVELS) throw _err("shbs/bad-public-key", "HSS level count L=" + L + " is outside 1.." + constants.LIMITS.HSS_MAX_LEVELS);
  var topKey = pr.buf.subarray(pr.pos);   // the top-level LMS public key -- its
  // structure (including an under-length blob) is validated by _lmsVerify below
  // (the < 8 and exact-24+m checks), so no direct read here that would bypass the
  // bounded reader and escape as a raw RangeError on a truncated key.

  var sr = new Reader(sigBytes, "shbs/bad-signature", "HSS signature");
  var Nspk = sr.u32();
  // The level-count gate, checked BEFORE parsing any component (RFC 8554 sec. 6.3).
  if (Nspk + 1 !== L) throw _err("shbs/bad-signature", "HSS Nspk+1 (" + (Nspk + 1) + ") does not equal the public-key level count L (" + L + ")");

  var key = topKey;
  for (var i = 0; i < Nspk; i++) {
    var sig = _consumeLmsSignature(sr);
    var nextKey = _consumeLmsPublicKey(sr);
    // Each level signs the SERIALIZED next-level LMS public key; that recovered
    // key becomes the verification key for the level below (chain of trust).
    if (!_lmsVerify(key, nextKey, sig)) return false;
    key = nextKey;
  }
  var finalSig = _consumeLmsSignature(sr);
  if (!sr.atEnd()) throw _err("shbs/bad-signature", "HSS signature has " + sr.remaining() + " trailing byte(s)");
  return _lmsVerify(key, message, finalSig);
}

// ---- public surface ----------------------------------------------------------

function _asBytes(x, label) { return guard.bytes.source(x, ShbsError, "shbs/bad-input", label); }

/**
 * @primitive pki.shbs.verify
 * @signature pki.shbs.verify(publicKey, message, signature) -> boolean
 * @since 0.2.1
 * @status experimental
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
 * typed `ShbsError`. VERIFY ONLY -- this module never signs.
 *
 * @example
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
 * @status experimental
 * @spec RFC 8554 sec. 5
 * @related pki.shbs.verify
 *
 * Verify a single-tree LMS (Leighton-Micali Signature) over `message` -- the
 * component an HSS hierarchy composes at each level, and a standalone algorithm
 * in its own right. Same verdict contract as `pki.shbs.verify`: true / false for
 * a well-formed signature, a typed `ShbsError` for a malformed blob.
 *
 * @example
 *   // lmsPublicKey / lmsSignature are raw LMS blobs (an HSS level, or a bare
 *   // LMS-signed artifact). Shown here on arbitrary bytes, which fail closed.
 *   var ok = pki.shbs.verifyLms(bytes, bytes, bytes);
 */
function verifyLms(publicKey, message, signature) {
  return _lmsVerify(_asBytes(publicKey, "public key"), _asBytes(message, "message"), _asBytes(signature, "signature"));
}

module.exports = { verify: verify, verifyLms: verifyLms };
