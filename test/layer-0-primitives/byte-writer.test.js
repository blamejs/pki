// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- lib/byte-writer.js, the big-endian length-prefixed TLS-vector sink (the
 * encode twin of lib/byte-reader.js). Every fixed-width integer is range-checked
 * against its field width and every vector against its declared bound BEFORE a byte
 * is committed, faulting through the caller's ErrorClass -- never a silent wrap. The
 * load-bearing gate is the write->read round-trip against ByteReader: what the writer
 * emits, the reader consumes back to identical values.
 */

var helpers = require("../helpers");
var check = helpers.check;
var ByteWriter = require("../../lib/byte-writer.js");
var ByteReader = require("../../lib/byte-reader.js");

// A stand-in caller ErrorClass carrying (code, message), like the domain PkiError subclasses.
function E(code, message) { this.code = code; this.message = message; }
E.prototype = Object.create(Error.prototype);

function W() { return new ByteWriter(E, "w/bad"); }
function fault(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }

function run() {
  // ---- write -> read round-trip: every field the reader defines has an inverse ----
  var w = W();
  w.u8(0x12).u16(0x3456).u24(0x789abc).u32(0xdeadbeef).u64(0x0102030405060708n)
    .bytes(Buffer.from([0xAA, 0xBB])).vector(2, 0, 0xffff, Buffer.from("hello")).vector(3, 0, null, Buffer.from([0x01]));
  var buf = w.build();
  check("1. build() length equals the running length()", buf.length === w.length());
  var r = new ByteReader(buf, 0, buf.length, E, "r/trunc");
  check("2. u8 round-trips", r.u8() === 0x12);
  check("3. u16 round-trips", r.u16() === 0x3456);
  check("4. u24 round-trips", r.u24() === 0x789abc);
  check("5. u32 round-trips", r.u32() === 0xdeadbeef);
  check("6. u64 round-trips (BigInt)", r.u64() === 0x0102030405060708n);
  check("7. fixed bytes round-trip", r.fixed(2).equals(Buffer.from([0xAA, 0xBB])));
  check("8. 2-byte vector round-trips", r.vector(2, 0, null, "r/e").toString() === "hello");
  check("9. 3-byte vector round-trips", r.vector(3, 0, null, "r/e").equals(Buffer.from([0x01])));
  check("10. the reader is exactly at the end", r.atEnd());

  // ---- u64 also accepts a safe-integer Number ----
  var w2 = W(); w2.u64(1700000000000);
  check("11. u64 accepts a non-negative safe-integer Number", new ByteReader(w2.build(), 0, 8, E, "r").u64() === 1700000000000n);

  // ---- fixed-width range faults (each width refuses out-of-range / non-integer) ----
  check("12. u8(256) -> w/bad", fault(function () { W().u8(256); }) === "w/bad");
  check("13. u8(-1) -> w/bad", fault(function () { W().u8(-1); }) === "w/bad");
  check("14. u8(1.5) -> w/bad", fault(function () { W().u8(1.5); }) === "w/bad");
  check("15. u16(65536) -> w/bad", fault(function () { W().u16(65536); }) === "w/bad");
  check("16. u24(2^24) -> w/bad", fault(function () { W().u24(0x1000000); }) === "w/bad");
  check("17. u32(2^32) -> w/bad", fault(function () { W().u32(0x100000000); }) === "w/bad");
  check("18. a per-write code overrides the default", fault(function () { W().u8(256, "w/custom"); }) === "w/custom");

  // ---- u64 faults ----
  check("19. u64(-1n) -> w/bad", fault(function () { W().u64(-1n); }) === "w/bad");
  check("20. u64 above 2^64-1 -> w/bad", fault(function () { W().u64(0x10000000000000000n); }) === "w/bad");
  check("21. u64 of a non-integer Number -> w/bad", fault(function () { W().u64(1.5); }) === "w/bad");
  check("22. u64 of a negative Number -> w/bad", fault(function () { W().u64(-1); }) === "w/bad");

  // ---- bytes / vector guards ----
  check("23. bytes() of a non-Buffer -> w/bad", fault(function () { W().bytes("nope"); }) === "w/bad");
  check("24. vector() of a non-Buffer body -> w/bad", fault(function () { W().vector(2, 0, 0xffff, "nope"); }) === "w/bad");
  check("25. a vector body below the minimum -> w/bad", fault(function () { W().vector(2, 1, 0xffff, Buffer.alloc(0)); }) === "w/bad");
  check("26. a vector body above the maximum -> w/bad", fault(function () { W().vector(2, 0, 3, Buffer.alloc(4)); }) === "w/bad");
  check("27. a vector body whose length overflows the prefix width -> w/bad", fault(function () { W().vector(1, 0, null, Buffer.alloc(256)); }) === "w/bad");
  check("28. an unbounded (max=null) vector accepts a large body", (function () { var v = W().vector(2, 0, null, Buffer.alloc(1000)).build(); return v.length === 1002; })());

  // ---- the default code kicks in when a write is not given its own ----
  check("29. the constructor default code is used when none is supplied", fault(function () { new ByteWriter(E).u8(256); }) === "byte-writer/bad-value");

  // ---- an unsupported length-prefix width is refused (not silently mis-sized via 32-bit shift wrap) ----
  check("30. vector with a 0-byte length prefix -> w/bad", fault(function () { W().vector(0, 0, null, Buffer.alloc(1)); }) === "w/bad");
  check("31. vector with a 5-byte length prefix -> w/bad", fault(function () { W().vector(5, 0, null, Buffer.alloc(1)); }) === "w/bad");
  check("32. vector with a non-integer length prefix width -> w/bad", fault(function () { W().vector(2.5, 0, null, Buffer.alloc(1)); }) === "w/bad");

  // ---- the declared length and the written bytes describe one byte string -------------------
  // A length prefix that outlives its payload is a framing lie: a reader takes the declared count
  // and consumes whatever follows. The body is copied before it is measured, so a backing buffer
  // that shrinks between the measurement and the write cannot separate the two. The bound's own
  // `valueOf` is the window, because it runs inside the comparison the length is checked by.
  var resizable = new ArrayBuffer(2, { maxByteLength: 2 });
  var shrinking = Buffer.from(resizable, 0, 2);
  shrinking[0] = 0xaa; shrinking[1] = 0xbb;
  var hostileMin = { valueOf: function () { resizable.resize(1); return 0; } };
  var framed;
  try { framed = W().vector(1, hostileMin, null, shrinking).build(); }
  catch (e) { framed = "THROW:" + ((e && e.code) || "UNTYPED:" + (e && e.message)); }
  // The frame must be self-consistent, or the writer must refuse it with ITS OWN code. Measuring the
  // caller's view instead left neither: the shrink took the body out of bounds and the concatenation
  // threw a raw TypeError out of `build()`, which is not this writer's verdict about its input.
  check("33. a body whose buffer shrinks mid-call frames consistently or is refused typed (" +
    (Buffer.isBuffer(framed) ? framed.toString("hex") : framed) + ")",
  Buffer.isBuffer(framed)
    ? (framed.length === framed[0] + 1 && framed[1] === 0xaa)
    : framed.indexOf("THROW:w/") === 0);

  // ---- a bound's own valueOf cannot replace the write that states the length -----------------
  // The bound is converted inside the comparison the length is checked by, so its `valueOf` runs
  // before the prefix is written: through the live prototype that was a window to replace the write
  // itself, and the vector declared a length of 0 over a payload of two bytes.
  var realWriteUIntBE = Buffer.prototype.writeUIntBE;
  var swapped = 0, swapOut;
  var swappingMin = {
    valueOf: function () {
      Buffer.prototype.writeUIntBE = function () { swapped += 1; return realWriteUIntBE.call(this, 0, 0, 1); };
      return 0;
    },
  };
  try { swapOut = W().vector(1, swappingMin, 255, Buffer.from([0xaa, 0xbb])).build(); }
  catch (e) { swapOut = "THROW:" + ((e && e.code) || "UNTYPED"); }
  finally { Buffer.prototype.writeUIntBE = realWriteUIntBE; }
  check("34. a bound that replaces the length write mid-call cannot mis-state the length (" +
    (Buffer.isBuffer(swapOut) ? swapOut.toString("hex") : swapOut) + ", swapped x" + swapped + ")",
  Buffer.isBuffer(swapOut) && swapOut.toString("hex") === "02aabb" && swapped === 0);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
