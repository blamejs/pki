// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. RC2 is exposed only through the legacy-PBE bag decryption of
// pki.pkcs12.open (RFC 7292 App. C), never as a general cipher; RC2 is a broken 64-bit block cipher (RC2-40
// is export-crippled) kept solely to READ old `openssl pkcs12 -legacy` / NSS stores.
//
// rc2 -- a from-scratch RFC 2268 RC2-CBC. OpenSSL 3.x moved RC2 to the legacy provider (not loaded by Node),
// so node:crypto cannot decrypt these bags; this in-tree primitive fills that single gap (Hard rule #1: own
// code, no npm hop, so MANIFEST stays empty; it is a lib primitive alongside webcrypto.js, outside lib/vendor/). The
// RFC 2268 sec. 5 known-answer vectors pin the cipher; the `openssl -legacy` store is the end-to-end KAT.

// RFC 2268 sec. 2: PITABLE, a fixed 256-byte permutation of the digits of pi used by the key schedule.
var PITABLE = [
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

// RFC 2268 sec. 2: expand `key` (1..128 bytes) to the 64 16-bit words K[0..63], reducing to `effectiveBits`.
function _expandKey(key, effectiveBits) {
  var T = key.length, L = new Array(128);
  for (var i = 0; i < T; i++) L[i] = key[i];
  for (i = T; i < 128; i++) L[i] = PITABLE[(L[i - 1] + L[i - T]) & 0xff];
  var T8 = (effectiveBits + 7) >>> 3;
  var TM = 0xff >>> ((8 - (effectiveBits & 7)) & 7);   // 255 mod 2^(8 + effectiveBits - 8*T8)
  L[128 - T8] = PITABLE[L[128 - T8] & TM];
  for (i = 127 - T8; i >= 0; i--) L[i] = PITABLE[L[i + 1] ^ L[i + T8]];
  var K = new Array(64);
  for (i = 0; i < 64; i++) K[i] = L[2 * i] + (L[2 * i + 1] << 8);
  return K;
}

function _rotl16(x, n) { return ((x << n) | (x >>> (16 - n))) & 0xffff; }
function _rotr16(x, n) { return ((x >>> n) | (x << (16 - n))) & 0xffff; }
var SHIFT = [1, 2, 3, 5];

// RFC 2268 sec. 3: encrypt one 8-byte block (little-endian 16-bit words) in place-ish, returning 8 bytes.
function _encBlock(K, b, off) {
  var R = [b[off] | (b[off + 1] << 8), b[off + 2] | (b[off + 3] << 8), b[off + 4] | (b[off + 5] << 8), b[off + 6] | (b[off + 7] << 8)];
  var j = 0, i;
  function mix() {
    for (var k = 0; k < 4; k++) {
      R[k] = (R[k] + K[j] + (R[(k + 3) & 3] & R[(k + 2) & 3]) + (~R[(k + 3) & 3] & R[(k + 1) & 3])) & 0xffff;
      j++;
      R[k] = _rotl16(R[k], SHIFT[k]);
    }
  }
  function mash() { for (var k = 0; k < 4; k++) R[k] = (R[k] + K[R[(k + 3) & 3] & 63]) & 0xffff; }
  for (i = 0; i < 5; i++) mix();
  mash();
  for (i = 0; i < 6; i++) mix();
  mash();
  for (i = 0; i < 5; i++) mix();
  return R;
}

// RFC 2268 sec. 3 inverse: decrypt one 8-byte block.
function _decBlock(K, b, off) {
  var R = [b[off] | (b[off + 1] << 8), b[off + 2] | (b[off + 3] << 8), b[off + 4] | (b[off + 5] << 8), b[off + 6] | (b[off + 7] << 8)];
  var j = 63, i;
  function rMix() {
    for (var k = 3; k >= 0; k--) {
      R[k] = _rotr16(R[k], SHIFT[k]);
      R[k] = (R[k] - K[j] - (R[(k + 3) & 3] & R[(k + 2) & 3]) - (~R[(k + 3) & 3] & R[(k + 1) & 3])) & 0xffff;
      j--;
    }
  }
  function rMash() { for (var k = 3; k >= 0; k--) R[k] = (R[k] - K[R[(k + 3) & 3] & 63]) & 0xffff; }
  for (i = 0; i < 5; i++) rMix();
  rMash();
  for (i = 0; i < 6; i++) rMix();
  rMash();
  for (i = 0; i < 5; i++) rMix();
  return R;
}

function _wordsToBytes(R) {
  return Buffer.from([R[0] & 0xff, (R[0] >>> 8) & 0xff, R[1] & 0xff, (R[1] >>> 8) & 0xff, R[2] & 0xff, (R[2] >>> 8) & 0xff, R[3] & 0xff, (R[3] >>> 8) & 0xff]);
}

// ECB block encrypt/decrypt (used by the KAT; CBC wraps them).
function encryptBlock(key, effectiveBits, block) { return _wordsToBytes(_encBlock(_expandKey(key, effectiveBits), block, 0)); }
function decryptBlock(key, effectiveBits, block) { return _wordsToBytes(_decBlock(_expandKey(key, effectiveBits), block, 0)); }

// RC2-CBC decrypt with PKCS#7 unpadding. `E`/`code` are the caller's typed-error factory + code; a structural
// fault (bad length, invalid pad) throws E(code) so the caller can collapse it to its uniform decrypt verdict.
function cbcDecrypt(key, effectiveBits, iv, ct, E, code) {
  if (ct.length === 0 || ct.length % 8 !== 0) throw E(code, "RC2-CBC ciphertext length must be a non-zero multiple of 8");
  var K = _expandKey(key, effectiveBits), out = Buffer.alloc(ct.length), prev = iv;
  for (var off = 0; off < ct.length; off += 8) {
    var dec = _wordsToBytes(_decBlock(K, ct, off));
    for (var i = 0; i < 8; i++) out[off + i] = dec[i] ^ prev[i];
    prev = ct.subarray(off, off + 8);
  }
  var pad = out[out.length - 1];
  if (pad < 1 || pad > 8 || pad > out.length) throw E(code, "RC2-CBC invalid PKCS#7 padding");
  for (i = 0; i < pad; i++) if (out[out.length - 1 - i] !== pad) throw E(code, "RC2-CBC invalid PKCS#7 padding");
  return out.subarray(0, out.length - pad);
}

// RC2-CBC encrypt with PKCS#7 padding (for the round-trip KAT; pkcs12.open only decrypts).
function cbcEncrypt(key, effectiveBits, iv, pt) {
  var padLen = 8 - (pt.length % 8), padded = Buffer.concat([pt, Buffer.alloc(padLen, padLen)]);
  var K = _expandKey(key, effectiveBits), out = Buffer.alloc(padded.length), prev = iv;
  for (var off = 0; off < padded.length; off += 8) {
    var x = Buffer.alloc(8);
    for (var i = 0; i < 8; i++) x[i] = padded[off + i] ^ prev[i];
    var enc = _wordsToBytes(_encBlock(K, x, 0));
    enc.copy(out, off);
    prev = enc;
  }
  return out;
}

module.exports = { encryptBlock: encryptBlock, decryptBlock: decryptBlock, cbcDecrypt: cbcDecrypt, cbcEncrypt: cbcEncrypt };
