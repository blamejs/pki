// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// consumers whose decompression composes this guard (pki.cms.decompress,
// pki.tls.decompressCertificate).
//
// guard-compress -- bounded, non-malleable decompression of an untrusted stream.
// Node's zlib / brotli / zstd decompressors are by default both UNBOUNDED and
// PERMISSIVE, and each is a distinct vulnerability class:
//
//   * Unbounded output (CWE-409, decompression bomb) -- a few hundred bytes
//     expand to gigabytes. `maxOutputLength` refuses the moment the output WOULD
//     exceed the bound; it does not allocate the whole output and then measure.
//     So the cap has to be applied AT the call and can never be a check on the
//     returned value.
//   * Trailing input silently ignored (CWE-20, canonicalization malleability) --
//     all three stop at the end of the first complete frame and discard whatever
//     follows, so a caller may append arbitrary bytes, or a second entire frame,
//     and still recover byte-identical output. One content would then have
//     unboundedly many encodings, and a digest over the compressed object would
//     stop identifying what it decompresses to.
//
// Both defenses are applied here, once, for every algorithm, so a new consumer
// cannot pick up one and miss the other. Verified uniform across zlib, brotli
// and zstd: each reports consumed input as `engine.bytesWritten` under
// `info: true`, each raises ERR_BUFFER_TOO_LARGE on a cap breach, and each
// accepts trailing bytes when left unchecked.
//
// E is the caller's (code, message, cause) typed-error factory, never an error
// class. Passing a class here crashes on the error path ("class cannot be invoked
// without new"), which converts a rejection into a fail-open. `codes` names the
// two verdicts a caller distinguishes: `tooLarge` when the output would exceed
// the cap, `failed` for every other fault. Every non-cap fault collapses to one
// code deliberately -- a per-errno surface is attack telemetry.

var zlib = require("zlib");
// Taken at load. The capability probe below decides which algorithms are safe to expose, and the
// bounded decompress measures its cap with these, so a replacement chooses both. See
// guard-intrinsic for the whole captured set.
var _intrinsic = require("./guard-intrinsic");
var _bufferFrom = _intrinsic.bufferFrom;
var _isBuffer = _intrinsic.isBuffer;
var _isInteger = _intrinsic.isInteger;
var _objectKeys = _intrinsic.keys;
var _stringify = _intrinsic.stringify;
// This probe decides which algorithms qualify as truncation-reporting, so both the round-trip
// comparison and the frame-size floor below settle whether a compressor is trusted. Reading either
// off a prototype lets a replacement qualify one that silently accepts a cut frame.
var _compare = _intrinsic.compare;
var _sizeOf = _intrinsic.sizeOf;
// The cut that makes the truncated frame. A replacement returning the whole frame means the
// decompressor is handed something intact, so an algorithm that ignores truncation qualifies on a
// test that never truncated anything.
var _subarray = _intrinsic.uncurry(Uint8Array.prototype.subarray);
var _hasOwn = _intrinsic.hasOwn;

// The decompressor per algorithm: a registry, so a new algorithm is a row rather
// than a branch and an unrecognized name fails closed.
var DECOMPRESS = {
  zlib: zlib.inflateSync,               // RFC 1950
  brotli: zlib.brotliDecompressSync,    // RFC 7932
  zstd: zlib.zstdDecompressSync,        // RFC 8478
};

// The compressors, used only by the truncation probe below. Producing a compressed stream is
// not the guarded shape; decompressing an untrusted one is.
var _PROBE_COMPRESS = {
  zlib: zlib.deflateSync,
  brotli: zlib.brotliCompressSync,
  zstd: zlib.zstdCompressSync,
};

// A decompressor must REPORT a frame it could not finish. Not all of them do: on some supported
// runtimes the zstd binding returns a SHORT (often empty) result for a truncated frame instead
// of faulting, and reports the entire input as consumed, so neither the returned bytes nor the
// consumed-length check below can see that the frame was cut. That is a silent truncation: a peer
// strips a frame's tail and the receiver processes a prefix as though it were the whole message.
//
// An algorithm whose runtime cannot report this cannot be decompressed safely here, so it is
// dropped from the advertised set at load instead of accepted with a defect. Consumers build
// their wire registries by intersecting with algorithms(), so a protocol simply does not offer
// or accept it, and it returns on its own once the runtime reports truncation.
// Nothing here is enabled by an exception alone: an algorithm qualifies only by positive proof
// that a whole frame round-trips and that a cut frame is refused. Every other outcome (a
// missing function, a compressor fault, a wrong round-trip, an unrelated error) leaves it out.
//
// Coverage residual: the early-return branches are reachable only on a runtime whose own
// compression library is broken (a missing export, a compressor that throws on 46 ASCII bytes, a
// round-trip that does not reproduce its input). The tables are captured at module load, so those
// states cannot be induced from a test without replacing node:zlib beforehand, and forcing them
// would assert nothing about the property this function exists to establish. They stay because
// their absence is what would make a broken runtime silently qualify an algorithm.
function _reportsTruncation(name) {
  var compress = _PROBE_COMPRESS[name];
  var decompress = DECOMPRESS[name];
  if (typeof compress !== "function" || typeof decompress !== "function") return false;
  var sample = _bufferFrom("0123456789abcdefghijklmnopqrstuvwxyz0123456789");
  var frame, whole;
  try { frame = compress(sample); }
  catch (_e) { /* allow:swallow-unverified a compressor that cannot compress 46 ASCII bytes is a broken runtime; the algorithm simply does not qualify, which is the fail-closed direction */ return false; }
  // A cut of 2 removes the frame's end marker; the sample is long enough that what remains is
  // still a plausible frame head and not nothing at all.
  if (!_isBuffer(frame) || _sizeOf(frame) < 4) return false;
  try { whole = decompress(frame, { maxOutputLength: 4096 }); }
  catch (_e2) { /* allow:swallow-unverified a decompressor that rejects its own compressor's whole frame is a broken runtime; the algorithm does not qualify, again fail-closed */ return false; }
  if (!_isBuffer(whole) || _compare(whole, sample) !== 0) return false;
  // The cut frame must be refused. A returned value of any length, including the empty buffer
  // some bindings hand back, means a truncation would pass through unseen.
  var cutAccepted = false;
  try {
    decompress(_subarray(frame, 0, _sizeOf(frame) - 2), { maxOutputLength: 4096 });
    cutAccepted = true;
  } catch (_e3) { /* refused, as a decompressor handed an unfinished frame must */ }
  return !cutAccepted;
}

var SAFE = {};
_intrinsic.forEach(_objectKeys(DECOMPRESS), function (n) { if (_reportsTruncation(n)) SAFE[n] = true; });

// bounded(algorithm, stream, cap, E, codes, label) -> Buffer. Decompress `stream`
// under `algorithm`, refusing any output that would exceed `cap` bytes and any
// input carrying bytes past the end of the compressed frame.
// The shape is the DECOMPRESSOR CALL ITSELF, not the presence of a cap: an
// uncapped call is precisely the dangerous form, so keying on `maxOutputLength`
// would fire on the safe re-inline and stay silent on the unsafe one. Every
// decompression in lib/ therefore belongs to this module or routes through it.
// @enforced-by guard-shape-reinlined
// @guard-shape \bzlib\.(inflate|brotliDecompress|zstdDecompress)Sync\b
// @guard-via \bguard\.compress\.bounded\s*\(
function bounded(algorithm, stream, cap, E, codes, label) {
  var decompress = DECOMPRESS[algorithm];
  // An unknown algorithm -- or one this runtime cannot decompress safely -- is an authoring
  // fault, not untrusted input: a caller resolves a wire value to a name against algorithms()
  // and rejects one it does not find, before reaching here. Arriving with a name outside that
  // set means the consumer skipped the step, so it faults loudly and never silently.
  if (!_hasOwn(SAFE, algorithm) || !decompress) {
    throw new TypeError("guard.compress.bounded: unknown or unsafe algorithm " + _stringify(algorithm));
  }
  // The byte-source normalization is guard.bytes.view's job and belongs at the
  // consumer's boundary; reaching here with anything else means it was skipped.
  if (!_isBuffer(stream)) {
    throw new TypeError("guard.compress.bounded: stream must be a Buffer (route the input through guard.bytes.view first)");
  }
  // The ceiling is an authoring input: an undefined / NaN / fractional / negative
  // cap would silently disable the bomb defense. It must also be at least 1 --
  // node rejects maxOutputLength 0 with a different fault than a cap breach, so a
  // zero cap would surface as a malformed-stream verdict instead of a config error.
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
  // `bytesWritten` is the count of INPUT bytes the engine consumed. A frame that
  // ends before the input does means the remainder was ignored, which is the
  // malleability above, so the whole input must be exactly one frame.
  var consumed = res.engine.bytesWritten;
  var streamLen = _sizeOf(stream);
  if (consumed !== streamLen) {
    throw E(codes.failed, what + " carries " + (streamLen - consumed) +
      " trailing byte(s) after the end of the compressed stream");
  }
  return res.buffer;
}

// The algorithm names this guard can decompress safely on this runtime: the registry
// minus any whose decompressor cannot report an unfinished frame. A consumer intersects
// its protocol's algorithm registry with this, so it never advertises or accepts something
// it could not refuse a truncation of.
// @enforced-by behavioral -- a read-only list of the safe registry's keys has no
// rename-proof code shape to re-inline; the guard's reject path is the contract,
// and a consumer offering an algorithm this list omits fails closed at `bounded`.
function algorithms() { return _objectKeys(SAFE); }

// Frozen for the reason the family header gives: a boundary reads its guard off this object at the
// call, so a writable export would let a caller replace the check rather than pass it.
module.exports = _intrinsic.freeze({ bounded: bounded, algorithms: algorithms });
