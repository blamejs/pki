// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @internal
 * lib/byte-writer.js -- a growable big-endian byte sink: the ENCODING-layer twin of
 * lib/byte-reader.js, the shared producer under the toolkit's non-ASN.1 length-prefixed
 * wire formats (the TLS-vector SCT list pki.ct emits; any future TLS-presentation
 * producer). Every fixed-width integer is range-checked against its field width and
 * every length-prefixed vector against its declared bound BEFORE a byte is committed,
 * so an out-of-range value or an over-long body faults through the caller's typed
 * ErrorClass rather than silently truncating mod 2^(8*width). It carries the CALLER's
 * ErrorClass exactly as ByteReader / the guard family do, so every wire format keeps
 * its own `domain/reason` fault code.
 *
 * This is an engine primitive, not a format: a new fixed-width or length-prefixed wire
 * field is a method here (with its own range check), never a hand-rolled Buffer write
 * in a format module.
 */

// A growable big-endian sink, faulting through the caller's ErrorClass `E`
// (constructed `new E(code, message)`). `defaultCode` is the fault code used when a
// write is not given its own.
function ByteWriter(E, defaultCode) {
  this.parts = [];
  this.len = 0;
  this.E = E;
  this.defaultCode = defaultCode || "byte-writer/bad-value";
}
ByteWriter.prototype._push = function (buf) { this.parts.push(buf); this.len += buf.length; };
// A non-negative integer that fills exactly `width` (1..4) big-endian octets; a value
// outside [0, 2^(8*width)-1] (or a non-integer) faults rather than wrapping.
ByteWriter.prototype._uint = function (v, width, code) {
  var max = width >= 4 ? 0xffffffff : (1 << (8 * width)) - 1;
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0 || v > max) {
    throw new this.E(code || this.defaultCode, "a uint" + (8 * width) + " must be an integer in 0.." + max + ", got " + v);
  }
  var b = Buffer.alloc(width); b.writeUIntBE(v, 0, width); this._push(b);
};
ByteWriter.prototype.u8 = function (v, code) { this._uint(v, 1, code); return this; };
ByteWriter.prototype.u16 = function (v, code) { this._uint(v, 2, code); return this; };
ByteWriter.prototype.u24 = function (v, code) { this._uint(v, 3, code); return this; };
ByteWriter.prototype.u32 = function (v, code) { this._uint(v, 4, code); return this; };
// A uint64 from a BigInt or a safe-integer Number; refused if out of [0, 2^64-1].
ByteWriter.prototype.u64 = function (v, code) {
  var big;
  if (typeof v === "bigint") big = v;
  else if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) big = BigInt(v);
  else throw new this.E(code || this.defaultCode, "a uint64 must be a non-negative integer or BigInt, got " + v);
  if (big < 0n || big > 0xffffffffffffffffn) throw new this.E(code || this.defaultCode, "a uint64 must be in 0..2^64-1");
  var b = Buffer.alloc(8); b.writeBigUInt64BE(big); this._push(b);
  return this;
};
// Append a raw opaque slice verbatim (a fixed-width field).
ByteWriter.prototype.bytes = function (buf, code) {
  if (!Buffer.isBuffer(buf)) throw new this.E(code || this.defaultCode, "bytes() requires a Buffer");
  this._push(buf); return this;
};
// opaque<min..max> -- a `lenWidth`-byte big-endian length prefix (1..4) then `body`.
// The body length is bounded [min, max] BEFORE the prefix is written, so an over-long
// body cannot emit a prefix that disagrees with what follows.
ByteWriter.prototype.vector = function (lenWidth, min, max, body, code) {
  if (!Buffer.isBuffer(body)) throw new this.E(code || this.defaultCode, "vector() body must be a Buffer");
  if (body.length < min) throw new this.E(code || this.defaultCode, "vector body " + body.length + " below minimum " + min);
  if (max != null && body.length > max) throw new this.E(code || this.defaultCode, "vector body " + body.length + " above maximum " + max);
  this._uint(body.length, lenWidth, code);
  this._push(body);
  return this;
};
ByteWriter.prototype.length = function () { return this.len; };
ByteWriter.prototype.build = function () { return Buffer.concat(this.parts, this.len); };

module.exports = ByteWriter;
