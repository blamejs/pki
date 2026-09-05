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
// @guard-shape \bzlib\.(inflate|brotliDecompress|zstdDecompress)Sync\b
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
