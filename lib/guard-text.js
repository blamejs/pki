// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var bytes = require("./guard-bytes");
var intrinsic = require("./guard-intrinsic");

var _toString = intrinsic.uncurry(Buffer.prototype.toString);
var _decode = intrinsic.uncurry(TextDecoder.prototype.decode);
var _byteLength = Buffer.byteLength;
var _isInteger = Number.isInteger;
var _TextDecoder = TextDecoder;

var LATIN1 = "latin1";

// @enforced-by behavioral -- cap-before-copy has no rename-proof code shape; the
function decode(input, maxBytes, ErrorClass, spec) {
  if (!_isInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError("guard.text.decode: maxBytes must be a non-negative integer");
  }
  var charset = spec.charset || LATIN1;
  if (bytes.isByteSource(input)) {
    input = bytes.source(input, ErrorClass, spec.badInput, spec.label);
    if (bytes.lengthOf(input) > maxBytes) throw new ErrorClass(spec.tooLarge, spec.label + " exceeds the size cap");
    if (spec.fatal) {
      try { return _decode(new _TextDecoder(charset, { fatal: true, ignoreBOM: true }), input); }
      catch (e) { throw new ErrorClass(spec.badDecode, spec.label + " is not valid " + charset, e); }
    }
    return _toString(input, charset);
  }
  if (typeof input === "string") {
    var byteLen = charset === LATIN1 ? input.length : _byteLength(input, "utf8");
    if (byteLen > maxBytes) throw new ErrorClass(spec.tooLarge, spec.label + " exceeds the size cap");
    return input;
  }
  throw new ErrorClass(spec.badInput, spec.label + " expects a string or a byte source (Buffer / TypedArray / DataView / ArrayBuffer)");
}

// @enforced-by behavioral -- a safe error-message formatter has no rename-proof code shape; the RED vector (a BigInt or cyclic caller value renders to a typed error, never a native TypeError out of a raw JSON.stringify) is the guard.
function showValue(v) {
  if (typeof v === "string") return intrinsic.stringify(v);
  if (typeof v === "number" || typeof v === "boolean" || typeof v === "bigint") return intrinsic.String(v);
  if (v === null) return "null";
  return "a value of type " + typeof v;
}

// @enforced-by behavioral -- a coercion-safe property-key narrowing has no rename-proof code shape; the RED vector (a caller value with no primitive coercion, an Object.create(null) or a throwing Symbol.toPrimitive, reaches a table lookup as the typed error, never a native TypeError from the key coercion) is the guard. A string or number passes through; anything else becomes undefined so the lookup misses without coercing the value.
function keyOf(v) {
  return typeof v === "string" || typeof v === "number" ? v : undefined;
}

/** @internal What a caught value says about itself, as a string, for a boundary that reports a
 * fault it did not cause. The value came from caller code, so every step of reading it is a step
 * the caller chose the behavior of: `message` may be an accessor that throws, a Symbol that
 * refuses string conversion, or an object whose `toString` throws, and the value itself may be a
 * Proxy that refuses every read. A boundary whose whole contract is to turn a fault into a verdict
 * cannot afford any of those to leave it, which is what happens when the description is built by
 * reading `e.message` in the open.
 *
 * Every read is attempted and none is required. A value that answers nothing readable is described
 * by its type, which is what `showValue` would have said about it anyway.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape /([\w$]+)\s*&&\s*\1\.message\s*\?\s*\1\.message\s*:|([\w$]+)\.message\s*\|\|\s*\2\b/ */
function describeThrown(e) {
  var m;
  try { m = e === null || e === undefined ? undefined : e.message; }
  catch (_readFailed) { return _thrownFallback(e); }
  if (typeof m === "string" && m.length > 0) return m;
  if (m === undefined || m === null) return _thrownFallback(e);
  try {
    if (typeof m === "symbol") return intrinsic.String(m);
    return "" + m;
  } catch (_convertFailed) { return _thrownFallback(e); }
}

function _thrownFallback(e) {
  try { return showValue(e); }
  catch (_showFailed) { return "a value that reports nothing readable"; }
}

module.exports = intrinsic.freeze({
  decode: decode, showValue: showValue, keyOf: keyOf, describeThrown: describeThrown,
});
