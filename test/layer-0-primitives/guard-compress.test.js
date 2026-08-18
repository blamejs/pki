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
 *   2. the whole input must be exactly one compressed frame, because every decompressor stops at
 *      the first frame's end and silently ignores the rest -- which would give one content
 *      unboundedly many encodings.
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
