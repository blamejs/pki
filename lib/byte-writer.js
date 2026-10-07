// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @internal
 * lib/byte-writer.js: a growable big-endian byte sink, the ENCODING-layer twin of
 * lib/byte-reader.js, the shared producer under the toolkit's non-ASN.1 length-prefixed
 * wire formats (the TLS-vector SCT list pki.ct emits; any future TLS-presentation
 * producer). Every fixed-width integer is range-checked against its field width and
 * every length-prefixed vector against its declared bound before a byte is committed,
 * so an out-of-range value or an over-long body faults through the caller's typed
 * ErrorClass instead of silently truncating mod 2^(8*width). It carries the caller's
 * ErrorClass exactly as ByteReader and the guard family do, so every wire format keeps
 * its own `domain/reason` fault code.
 *
 * This is an engine primitive, not a format: a new fixed-width or length-prefixed wire
 * field is a method here (with its own range check), never a hand-rolled Buffer write
 * in a format module.
 */

var intrinsic = require("./guard-intrinsic");
/** @internal Every operation this writer decides a field's width, range or bytes with is bound at
 *  load. Each one participates in what gets emitted: the integer tests decide whether a value fits
 *  the field, the allocation decides how wide the field is, and the concatenation decides the byte
 *  string a caller signs or sends. */
var _isInteger = intrinsic.isInteger;
var _isSafeInteger = intrinsic.isSafeInteger;
var _bufferAlloc = intrinsic.bufferAlloc;
var _isBuffer = intrinsic.isBuffer;
var _bufferConcat = intrinsic.bufferConcat;
var _BigInt = intrinsic.BigInt;
var _taSet = intrinsic.typedArraySet;
/** @internal The two writes that place an integer into its field, bound at load. A bound's own
 *  `valueOf` runs inside the comparison the length is checked by, which is a window to replace a
 *  method the write that follows would otherwise read off the prototype: measured, a vector declared
 *  a length of 0 over a payload of two bytes that way. */
var _writeUIntBE = intrinsic.uncurry(Buffer.prototype.writeUIntBE);
var _writeBigUInt64BE = intrinsic.uncurry(Buffer.prototype.writeBigUInt64BE);

/** @internal A real copy of the bytes, in this writer's own allocation. A slice of a view shares the
 *  backing buffer, so a buffer that can be resized takes the slice out of bounds with it, and the
 *  copy has to be taken before anything else in the call can run code. */
function _copyOf(view) {
  var n = intrinsic.sizeOf(view);
  var out = _bufferAlloc(n);
  if (n !== 0) _taSet(out, view, 0);
  return out;
}

function ByteWriter(E, defaultCode) {
  this.parts = [];
  this.len = 0;
  this.E = E;
  this.defaultCode = defaultCode || "byte-writer/bad-value";
}
/** @internal The piece is APPENDED by defining its index, not stored by `push`. A store walks the
 *  prototype chain for a setter, so an accessor installed at an array index receives each piece as it
 *  is added and can define something else in its place, and these pieces are the bytes this writer
 *  emits. The length is accumulated from the buffer's own byte length rather than a `length`
 *  property, so a view that overstates itself cannot make the declared length disagree with the
 *  bytes. */
ByteWriter.prototype._push = function (buf) {
  intrinsic.append(this.parts, buf);
  this.len += intrinsic.sizeOf(buf);
};
ByteWriter.prototype._uint = function (v, width, code) {
  if (!_isInteger(width) || width < 1 || width > 4) throw new this.E(code || this.defaultCode, "an integer width must be 1..4, got " + width);
  var max = width === 4 ? 0xffffffff : (1 << (8 * width)) - 1;
  if (typeof v !== "number" || !_isSafeInteger(v) || v < 0 || v > max) {
    throw new this.E(code || this.defaultCode, "a uint" + (8 * width) + " must be an integer in 0.." + max + ", got " + v);
  }
  var b = _bufferAlloc(width); _writeUIntBE(b, v, 0, width); this._push(b);
};
ByteWriter.prototype.u8 = function (v, code) { this._uint(v, 1, code); return this; };
ByteWriter.prototype.u16 = function (v, code) { this._uint(v, 2, code); return this; };
ByteWriter.prototype.u24 = function (v, code) { this._uint(v, 3, code); return this; };
ByteWriter.prototype.u32 = function (v, code) { this._uint(v, 4, code); return this; };
ByteWriter.prototype.u64 = function (v, code) {
  var big;
  if (typeof v === "bigint") big = v;
  else if (typeof v === "number" && _isSafeInteger(v) && v >= 0) big = _BigInt(v);
  else throw new this.E(code || this.defaultCode, "a uint64 must be a non-negative integer or BigInt, got " + v);
  if (big < 0n || big > 0xffffffffffffffffn) throw new this.E(code || this.defaultCode, "a uint64 must be in 0..2^64-1");
  var b = _bufferAlloc(8); _writeBigUInt64BE(b, big); this._push(b);
  return this;
};
ByteWriter.prototype.bytes = function (buf, code) {
  if (!_isBuffer(buf)) throw new this.E(code || this.defaultCode, "bytes() requires a Buffer");
  this._push(buf); return this;
};
ByteWriter.prototype.vector = function (lenWidth, min, max, body, code) {
  if (!_isBuffer(body)) throw new this.E(code || this.defaultCode, "vector() body must be a Buffer");
  /** @internal The body is COPIED before it is measured, and the copy is what gets written. The
   *  bounds, the length prefix and the bytes then all describe one byte string that nothing else
   *  holds. Measuring the caller's view instead left a window: a resizable backing buffer shrunk
   *  between the measurement and the write (a `min` whose `valueOf` resizes it is enough) and the
   *  vector declared two bytes over a payload of one. The bounds are converted to numbers up front
   *  for the same reason, so a bound cannot run code in the middle of the comparison it is part of. */
  var bytes = _copyOf(body);
  var bodyLen = intrinsic.sizeOf(bytes);
  var lo = intrinsic.Number(min);
  if (!_isSafeInteger(lo) || lo < 0) throw new this.E(code || this.defaultCode, "a vector minimum must be a non-negative integer, got " + lo);
  var hi = max == null ? null : intrinsic.Number(max);
  if (hi !== null && (!_isSafeInteger(hi) || hi < lo)) throw new this.E(code || this.defaultCode, "a vector maximum must be an integer not below the minimum, got " + hi);
  if (bodyLen < lo) throw new this.E(code || this.defaultCode, "vector body " + bodyLen + " below minimum " + lo);
  if (hi !== null && bodyLen > hi) throw new this.E(code || this.defaultCode, "vector body " + bodyLen + " above maximum " + hi);
  this._uint(bodyLen, lenWidth, code);
  this._push(bytes);
  return this;
};
ByteWriter.prototype.length = function () { return this.len; };
ByteWriter.prototype.build = function () { return _bufferConcat(this.parts, this.len); };

module.exports = ByteWriter;
