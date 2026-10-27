// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var zlib = require("zlib");
var _intrinsic = require("./guard-intrinsic");
var _bufferFrom = _intrinsic.bufferFrom;
var _isBuffer = _intrinsic.isBuffer;
var _isInteger = _intrinsic.isInteger;
var _objectKeys = _intrinsic.keys;
var _stringify = _intrinsic.stringify;
var _compare = _intrinsic.compare;
var _sizeOf = _intrinsic.sizeOf;
var _subarray = _intrinsic.uncurry(Uint8Array.prototype.subarray);
var _hasOwn = _intrinsic.hasOwn;

var DECOMPRESS = _intrinsic.assign(_intrinsic.create(null), {
  zlib: zlib.inflateSync,
  brotli: zlib.brotliDecompressSync,
  zstd: zlib.zstdDecompressSync,
});

var _PROBE_COMPRESS = _intrinsic.assign(_intrinsic.create(null), {
  zlib: zlib.deflateSync,
  brotli: zlib.brotliCompressSync,
  zstd: zlib.zstdCompressSync,
});

/** @internal The byte length of the one Zstandard frame at the start of `s` (RFC 8878 sec. 3.1.1),
 *  or -1 when `s` does not open with a complete one. A decoder that follows RFC 8878 decodes every
 *  concatenated frame and skips skippable frames, so the consumed-length check cannot see an empty
 *  frame or a skippable frame next to the real one; this walk is what holds zstd to one frame. Only
 *  the frame magic 0xFD2FB528 starts a frame here, so a skippable frame anywhere is refused. */
var _ZSTD_DID_BYTES = [0, 1, 2, 4];
var _ZSTD_FCS_BYTES = [0, 2, 4, 8];
function _zstdFrameLength(s) {
  var n = _sizeOf(s);
  if (n < 6 || s[0] !== 0x28 || s[1] !== 0xb5 || s[2] !== 0x2f || s[3] !== 0xfd) return -1;
  var fhd = s[4];
  if ((fhd & 0x08) !== 0) return -1;
  var single = (fhd & 0x20) !== 0;
  var fcs = _ZSTD_FCS_BYTES[fhd >>> 6];
  if (fcs === 0 && single) fcs = 1;
  var p = 5 + (single ? 0 : 1) + _ZSTD_DID_BYTES[fhd & 0x03] + fcs;
  for (;;) {
    if (p + 3 > n) return -1;
    var h = s[p] | (s[p + 1] << 8) | (s[p + 2] << 16);
    var type = (h >>> 1) & 0x03;
    if (type === 3) return -1;
    p += 3 + (type === 1 ? 1 : (h >>> 3));
    if (p > n) return -1;
    if ((h & 0x01) !== 0) break;
  }
  if ((fhd & 0x04) !== 0) p += 4;
  return p > n ? -1 : p;
}

var FRAME_LENGTH = _intrinsic.assign(_intrinsic.create(null), { zstd: _zstdFrameLength });

function _reportsTruncation(name) {
  var compress = _PROBE_COMPRESS[name];
  var decompress = DECOMPRESS[name];
  if (typeof compress !== "function" || typeof decompress !== "function") return false;
  var sample = _bufferFrom("0123456789abcdefghijklmnopqrstuvwxyz0123456789");
  var frame, whole;
  try { frame = compress(sample); }
  catch (_e) { /* allow:swallow-unverified a compressor that cannot compress 46 ASCII bytes is a broken runtime; the algorithm simply does not qualify, which is the fail-closed direction */ return false; }
  if (!_isBuffer(frame) || _sizeOf(frame) < 4) return false;
  try { whole = decompress(frame, { maxOutputLength: 4096 }); }
  catch (_e2) { /* allow:swallow-unverified a decompressor that rejects its own compressor's whole frame is a broken runtime; the algorithm does not qualify, again fail-closed */ return false; }
  if (!_isBuffer(whole) || _compare(whole, sample) !== 0) return false;
  var cutAccepted = false;
  try {
    decompress(_subarray(frame, 0, _sizeOf(frame) - 2), { maxOutputLength: 4096 });
    cutAccepted = true;
  } catch (_e3) { }
  return !cutAccepted;
}

var SAFE = _intrinsic.create(null);
_intrinsic.forEach(_objectKeys(DECOMPRESS), function (n) { if (_reportsTruncation(n)) SAFE[n] = true; });

// @enforced-by guard-shape-reinlined
// @guard-shape \bzlib\.(?:inflate|inflateRaw|gunzip|unzip|brotliDecompress|zstdDecompress|createInflate|createInflateRaw|createGunzip|createUnzip|createBrotliDecompress|createZstdDecompress)(?:Sync)?\b
// @guard-via \bguard\.compress\.bounded\s*\(
function bounded(algorithm, stream, cap, E, codes, label) {
  var decompress = DECOMPRESS[algorithm];
  if (!_hasOwn(SAFE, algorithm) || !decompress) {
    throw new TypeError("guard.compress.bounded: unknown or unsafe algorithm " + _stringify(algorithm));
  }
  if (!_isBuffer(stream)) {
    throw new TypeError("guard.compress.bounded: stream must be a Buffer (route the input through guard.bytes.view first)");
  }
  if (!_isInteger(cap) || cap < 1) {
    throw new TypeError("guard.compress.bounded: cap must be a positive integer");
  }
  var what = label || "the compressed input";
  var frameLength = FRAME_LENGTH[algorithm];
  if (frameLength && frameLength(stream) !== _sizeOf(stream)) {
    throw E(codes.failed, what + " is not exactly one " + algorithm + " frame");
  }
  var res;
  try {
    res = decompress(stream, { maxOutputLength: cap, info: true });
  } catch (e) {
    if (e && e.code === "ERR_BUFFER_TOO_LARGE") {
      throw E(codes.tooLarge, what + " decompresses to more than the " + cap + "-byte cap (a decompression-bomb defense)", e);
    }
    throw E(codes.failed, what + " could not be decompressed", e);
  }
  var consumed = res.engine.bytesWritten;
  var streamLen = _sizeOf(stream);
  if (consumed !== streamLen) {
    throw E(codes.failed, what + " carries " + (streamLen - consumed) +
      " trailing byte(s) after the end of the compressed stream");
  }
  return res.buffer;
}

// @enforced-by behavioral -- a read-only list of the safe registry's keys has no
function algorithms() { return _objectKeys(SAFE); }

module.exports = _intrinsic.freeze({ bounded: bounded, algorithms: algorithms });
