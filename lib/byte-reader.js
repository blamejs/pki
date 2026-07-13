// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @internal
 * lib/byte-reader.js -- a bounded big-endian byte cursor: the shared ENCODING-layer
 * primitive under the toolkit's non-ASN.1 length-prefixed wire formats (TLS-vector
 * SCTs in pki.ct, the packed big-endian TPM2B_* / authenticatorData structures in
 * pki.webauthn). Every read is length-checked against a hard [pos, end) window
 * BEFORE a byte is taken, so a lying inner length can overrun only the current
 * sub-reader's `end`, never the parent buffer -- bounds-before-slice is structural,
 * not a per-call discipline. It carries the CALLER's typed ErrorClass so every wire
 * format keeps its own `domain/reason` fault code, exactly as the guard family does.
 *
 * This is an engine primitive, not a format: a new fixed-width or length-prefixed
 * wire field is a method here (with its own bounds check), never a hand-rolled
 * offset walk in a format module.
 */

// A bounded cursor over `buf[start, end)`, faulting through the caller's ErrorClass
// `E` (constructed `new E(code, message)`). `defaultCode` is the fault code used
// when a read is not given its own.
function ByteReader(buf, start, end, E, defaultCode) {
  if (!Buffer.isBuffer(buf)) throw new TypeError("ByteReader: buf must be a Buffer");
  this.buf = buf;
  this.pos = start | 0;
  this.end = end == null ? buf.length : (end | 0);
  this.E = E;
  this.defaultCode = defaultCode || "byte-reader/truncated";
}
ByteReader.prototype._need = function (n, code) {
  if (this.pos + n > this.end) {
    throw new this.E(code || this.defaultCode, "need " + n + " byte(s), only " + (this.end - this.pos) + " remain");
  }
};
ByteReader.prototype.u8 = function (code) { this._need(1, code); return this.buf[this.pos++]; };
ByteReader.prototype.u16 = function (code) { this._need(2, code); var v = this.buf.readUInt16BE(this.pos); this.pos += 2; return v; };
ByteReader.prototype.u24 = function (code) {
  this._need(3, code);
  var v = (this.buf[this.pos] << 16) | (this.buf[this.pos + 1] << 8) | this.buf[this.pos + 2];
  this.pos += 3; return v >>> 0;
};
ByteReader.prototype.u32 = function (code) { this._need(4, code); var v = this.buf.readUInt32BE(this.pos); this.pos += 4; return v; };
ByteReader.prototype.u64 = function (code) { this._need(8, code); var v = this.buf.readBigUInt64BE(this.pos); this.pos += 8; return v; };
// A fixed-width opaque slice (zero-copy view into the backing buffer).
ByteReader.prototype.fixed = function (n, code) {
  this._need(n, code);
  var s = this.buf.subarray(this.pos, this.pos + n); this.pos += n; return s;
};
// opaque<min..max> -- a length-prefixed vector (lenWidth-byte big-endian prefix:
// 2 or 3). The length prefix itself is a plain read (a truncation there is the
// default code); only a LYING length whose body overruns the bound carries `code`.
ByteReader.prototype.vector = function (lenWidth, min, max, code) {
  var len = lenWidth === 3 ? this.u24() : this.u16();
  if (len < min) throw new this.E(code, "vector length " + len + " below minimum " + min);
  if (max != null && len > max) throw new this.E(code, "vector length " + len + " above maximum " + max);
  this._need(len, code);
  var s = this.buf.subarray(this.pos, this.pos + len); this.pos += len; return s;
};
// A bounded child cursor over the next `len` bytes, sharing the same ErrorClass.
ByteReader.prototype.subReader = function (len, code) {
  this._need(len, code);
  var r = new ByteReader(this.buf, this.pos, this.pos + len, this.E, this.defaultCode); this.pos += len; return r;
};
ByteReader.prototype.remaining = function () { return this.end - this.pos; };
ByteReader.prototype.atEnd = function () { return this.pos === this.end; };

module.exports = ByteReader;
