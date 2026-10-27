// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard.compress.bounded: the single home for bounded, non-malleable decompression
 * (zlib / brotli / zstd). Its two defenses are applied for every algorithm at once, so a new
 * consumer cannot acquire one and miss the other:
 *
 *   1. the output cap is applied AT the decompressor, so a bomb is refused as its output would
 *      exceed the bound rather than after the memory is committed; and
 *   2. the whole input must be exactly one compressed frame. zlib and brotli stop at the first
 *      frame's end and silently ignore the rest; zstd on Node 24.22.1+ decodes further frames and
 *      skips skippable ones. Either would give one content unboundedly many encodings.
 *
 * The guard is @internal, so this file drives it directly to pin its OWN contract; the shipped
 * consumers (pki.cms.decompress, pki.tls.decompressCertificate) carry the behavioral vectors.
 * The authoring-fault cases matter here in particular: they are TypeErrors rather than typed
 * domain errors precisely because they mean the CALLER is wrong, not the input.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var guard = require("../../lib/guard-all");
var zlib = require("zlib");

// The caller's typed-error FACTORY -- the currency this guard takes. Handing it an error CLASS
// instead would crash on the reject path, which is why that case is pinned below.
function E(code, message, cause) { return new pki.errors.PkiError(message, code, cause); }
var CODES = { tooLarge: "test/too-large", failed: "test/failed" };

function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

var PAYLOAD = Buffer.from("the bounded-decompression payload -- restore me exactly, and only me\n");
var ALL = [
  { name: "zlib", compress: zlib.deflateSync },
  { name: "brotli", compress: zlib.brotliCompressSync },
  { name: "zstd", compress: zlib.zstdCompressSync },
];
// The guard advertises only what THIS RUNTIME can decompress safely: it drops an algorithm
// whose decompressor cannot report an unfinished frame, because a truncation that yields a
// short result instead of a fault is a silent message truncation. That set is a property of
// the runtime, so these vectors assert BEHAVIOR over the advertised set rather than pinning
// a fixed list -- and 6d then proves a dropped algorithm is refused outright.
var SAFE = guard.compress.algorithms();
var ALGS = ALL.filter(function (a) { return SAFE.indexOf(a.name) !== -1; });
var DROPPED = ALL.filter(function (a) { return SAFE.indexOf(a.name) === -1; });

function run() {
  ALGS.forEach(function (a, i) {
    var n = i + 1;
    var frame = a.compress(PAYLOAD);
    check(n + ". " + a.name + " round-trips through the guard",
      guard.compress.bounded(a.name, frame, 4096, E, CODES, "input").equals(PAYLOAD));
    check(n + "a. " + a.name + ": a cap below the output -> the caller's tooLarge code",
      codeOf(function () { return guard.compress.bounded(a.name, frame, 8, E, CODES, "input"); }) === CODES.tooLarge);
    check(n + "b. " + a.name + ": a cap exactly at the output size still succeeds",
      guard.compress.bounded(a.name, frame, PAYLOAD.length, E, CODES, "input").equals(PAYLOAD));
    // Every one of the three ignores trailing bytes when left unguarded -- that is the whole
    // reason the consumed-length check lives here rather than in one consumer.
    check(n + "c. " + a.name + ": trailing bytes after the frame -> the caller's failed code",
      codeOf(function () { return guard.compress.bounded(a.name, Buffer.concat([frame, Buffer.from("junk")]), 4096, E, CODES, "input"); }) === CODES.failed);
    check(n + "d. " + a.name + ": a second whole frame appended -> the caller's failed code",
      codeOf(function () { return guard.compress.bounded(a.name, Buffer.concat([frame, a.compress(Buffer.from("x"))]), 4096, E, CODES, "input"); }) === CODES.failed);
    check(n + "e. " + a.name + ": a single trailing byte is enough to refuse the stream",
      codeOf(function () { return guard.compress.bounded(a.name, Buffer.concat([frame, Buffer.from([0])]), 4096, E, CODES, "input"); }) === CODES.failed);
    check(n + "f. " + a.name + ": a corrupt frame -> the caller's failed code", (function () {
      var bad = Buffer.from(frame); bad[bad.length - 2] ^= 0xff;
      return codeOf(function () { return guard.compress.bounded(a.name, bad, 4096, E, CODES, "input"); });
    })() === CODES.failed);
    check(n + "g. " + a.name + ": a truncated frame -> the caller's failed code",
      codeOf(function () { return guard.compress.bounded(a.name, frame.subarray(0, frame.length - 2), 4096, E, CODES, "input"); }) === CODES.failed);
    check(n + "h. " + a.name + ": a bomb is refused, not allocated", (function () {
      var big = a.compress(Buffer.alloc(32 * 1024 * 1024, 0));
      return codeOf(function () { return guard.compress.bounded(a.name, big, 1024, E, CODES, "input"); });
    })() === CODES.tooLarge);
  });

  // ==== zstd: one frame, whatever the decoder does with the rest ============================
  // A zstd decoder that follows RFC 8878 decodes every concatenated frame and skips skippable
  // frames (magic 0x184D2A50..5F), consuming the whole input. Node 24.22.1 does both, so the
  // consumed-length check alone accepts an empty frame or a skippable frame of arbitrary bytes
  // around the real one: identical output, unboundedly many encodings.
  if (SAFE.indexOf("zstd") !== -1) {
    var zf = zlib.zstdCompressSync(PAYLOAD);
    var skip = Buffer.from([0x50, 0x2a, 0x4d, 0x18, 0x03, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbf]);
    var zcode = function (buf) { return codeOf(function () { return guard.compress.bounded("zstd", buf, 4096, E, CODES, "input"); }); };
    check("7. zstd: an empty frame appended -> the caller's failed code",
      zcode(Buffer.concat([zf, zlib.zstdCompressSync(Buffer.alloc(0))])) === CODES.failed);
    check("7a. zstd: an empty frame prepended -> the caller's failed code",
      zcode(Buffer.concat([zlib.zstdCompressSync(Buffer.alloc(0)), zf])) === CODES.failed);
    check("7b. zstd: a skippable frame appended -> the caller's failed code",
      zcode(Buffer.concat([zf, skip])) === CODES.failed);
    check("7c. zstd: a skippable frame prepended -> the caller's failed code",
      zcode(Buffer.concat([skip, zf])) === CODES.failed);
    check("7d. zstd: a skippable frame alone -> the caller's failed code", zcode(skip) === CODES.failed);
    check("7e. zstd: a frame whose header is cut -> the caller's failed code", zcode(zf.subarray(0, 5)) === CODES.failed);
    check("7f. zstd: a frame with a content checksum still round-trips", (function () {
      var p = {}; p[zlib.constants.ZSTD_c_checksumFlag] = 1;
      var withSum = zlib.zstdCompressSync(PAYLOAD, { params: p });
      return guard.compress.bounded("zstd", withSum, 4096, E, CODES, "input").equals(PAYLOAD) &&
        zcode(Buffer.concat([withSum, zlib.zstdCompressSync(Buffer.alloc(0))])) === CODES.failed;
    })());
    check("7g. zstd: a multi-block frame round-trips", (function () {
      var big = Buffer.alloc(400 * 1024);
      for (var i = 0; i < big.length; i++) big[i] = (i * 2654435761) >>> 24;
      return guard.compress.bounded("zstd", zlib.zstdCompressSync(big), big.length, E, CODES, "input").equals(big);
    })());
    // Frames minted from RFC 8878 sec. 3.1.1: magic, Frame_Header_Descriptor, optional
    // Window_Descriptor / Frame_Content_Size, then 3-byte little-endian block headers
    // (bit 0 Last_Block, bits 1-2 Block_Type, bits 3-23 Block_Size).
    var MAGIC = [0x28, 0xb5, 0x2f, 0xfd];
    var mint = function (rest) { return Buffer.from(MAGIC.concat(rest)); };
    var ok = function (buf, want) {
      return guard.compress.bounded("zstd", buf, 4096, E, CODES, "input").toString() === want;
    };
    check("7h. zstd: a single-segment frame of one raw block decodes",
      ok(mint([0x20, 0x03, 0x19, 0x00, 0x00, 0x61, 0x62, 0x63]), "abc"));
    check("7i. zstd: a frame of one RLE block decodes",
      ok(mint([0x20, 0x05, 0x2b, 0x00, 0x00, 0x7a]), "zzzzz"));
    check("7j. zstd: a frame with a Window_Descriptor and a raw block then a last raw block decodes",
      ok(mint([0x00, 0x00, 0x10, 0x00, 0x00, 0x61, 0x62, 0x09, 0x00, 0x00, 0x63]), "abc"));
    check("7k. zstd: the reserved Frame_Header_Descriptor bit set -> the caller's failed code",
      zcode(mint([0x28, 0x03, 0x19, 0x00, 0x00, 0x61, 0x62, 0x63])) === CODES.failed);
    check("7l. zstd: a reserved Block_Type -> the caller's failed code",
      zcode(mint([0x20, 0x03, 0x07, 0x00, 0x00, 0x61, 0x62, 0x63])) === CODES.failed);
    check("7m. zstd: a block that runs past the end -> the caller's failed code",
      zcode(mint([0x20, 0x03, 0x19, 0x00, 0x00, 0x61, 0x62])) === CODES.failed);
    check("7n. zstd: no block marked last -> the caller's failed code",
      zcode(mint([0x20, 0x03, 0x18, 0x00, 0x00, 0x61, 0x62, 0x63])) === CODES.failed);
    check("7o. zstd: a content checksum cut short -> the caller's failed code",
      zcode(mint([0x24, 0x03, 0x19, 0x00, 0x00, 0x61, 0x62, 0x63, 0x00, 0x00])) === CODES.failed);
    check("7p. zstd: the frame magic alone -> the caller's failed code", zcode(Buffer.from(MAGIC)) === CODES.failed);
  }

  // ==== the cap is the caller's, and every fault carries the CALLER's codes =================
  check("4. each consumer keeps its own domain codes", (function () {
    var own = { tooLarge: "mydomain/too-big", failed: "mydomain/broken" };
    var frame = zlib.deflateSync(PAYLOAD);
    return codeOf(function () { return guard.compress.bounded("zlib", frame, 4, E, own, "input"); }) === "mydomain/too-big" &&
           codeOf(function () { return guard.compress.bounded("zlib", Buffer.from([1, 2, 3]), 4096, E, own, "input"); }) === "mydomain/broken";
  })());
  check("4a. the label appears in the message", (function () {
    try { guard.compress.bounded("zlib", zlib.deflateSync(PAYLOAD), 4, E, CODES, "the widget stream"); return false; }
    catch (e) { return e.message.indexOf("the widget stream") !== -1; }
  })());
  check("4b. the label is optional -- a caller that omits it still gets a legible message", (function () {
    try { guard.compress.bounded("zlib", zlib.deflateSync(PAYLOAD), 4, E, CODES); return false; }
    catch (e) { return e.code === CODES.tooLarge && e.message.indexOf("the compressed input") !== -1; }
  })());

  // ==== authoring faults are TypeErrors: the caller is wrong, not the input =================
  // A cap that is NaN / fractional / negative / zero would silently disable the bomb defense,
  // so it is refused at the call rather than quietly accepted.
  check("5. an unknown algorithm is an authoring fault (TypeError)",
    codeOf(function () { return guard.compress.bounded("lzma", zlib.deflateSync(PAYLOAD), 4096, E, CODES, "input"); }) === "TypeError");
  check("5a. an inherited Object property is not an algorithm",
    codeOf(function () { return guard.compress.bounded("constructor", zlib.deflateSync(PAYLOAD), 4096, E, CODES, "input"); }) === "TypeError");
  check("5b. a non-Buffer stream is an authoring fault (route it through guard.bytes.view first)",
    codeOf(function () { return guard.compress.bounded("zlib", "not bytes", 4096, E, CODES, "input"); }) === "TypeError");
  ["not a number", NaN, Infinity, 2.5, -1, 0, undefined].forEach(function (cap, i) {
    check("5c" + i + ". a cap of " + JSON.stringify(cap === undefined ? "undefined" : cap) + " is refused at the call (TypeError)",
      codeOf(function () { return guard.compress.bounded("zlib", zlib.deflateSync(PAYLOAD), cap, E, CODES, "input"); }) === "TypeError");
  });

  // ==== the registry a consumer builds its wire mapping against ============================
  var names = guard.compress.algorithms();
  check("6. algorithms() always carries zlib, the algorithm every consumer relies on",
    names.indexOf("zlib") !== -1);
  check("6a. algorithms() reports a subset of the implemented set",
    names.every(function (n) { return ALL.some(function (a) { return a.name === n; }); }));
  check("6b. every name algorithms() reports actually decompresses", names.every(function (n) {
    var c = ALL.filter(function (a) { return a.name === n; })[0];
    return c && guard.compress.bounded(n, c.compress(PAYLOAD), 4096, E, CODES, "input").equals(PAYLOAD);
  }));
  // The property that earns a place in the advertised set: a cut frame must FAULT, not come
  // back short. This is what makes the set safe to hand to a protocol as its algorithm menu.
  check("6c. every advertised algorithm reports an unfinished frame rather than a short result",
    names.every(function (n) {
      var c = ALL.filter(function (a) { return a.name === n; })[0];
      var frame = c.compress(PAYLOAD);
      return codeOf(function () { return guard.compress.bounded(n, frame.subarray(0, frame.length - 2), 4096, E, CODES, "input"); }) === CODES.failed;
    }));
  // An algorithm this runtime cannot decompress safely is refused OUTRIGHT, even for a
  // perfectly well-formed frame -- accepting one would mean accepting a truncation of it too.
  check("6d. an algorithm dropped for this runtime is refused even on a valid frame",
    DROPPED.every(function (a) {
      return codeOf(function () { return guard.compress.bounded(a.name, a.compress(PAYLOAD), 4096, E, CODES, "input"); }) === "TypeError";
    }));
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(e && e.stack || e); process.exit(1); }
  );
}
