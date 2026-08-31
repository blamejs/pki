// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// primitives whose text boundaries compose this guard (pki.jose.parseJson, the
// PEM decoders, the EST transfer decoders).
//
// guard-text -- fail-closed decode of an untrusted byte-source input to a
// string, capping the raw byte length before the string is materialized.
// Enforced choke point for the byte->string boundary.
//
// Defends the parser-DoS string-allocation class (CWE-770 allocation without
// limits, CWE-400 uncontrolled resource consumption; MITRE T1499.001). The
// ORDERING is the invariant: cap the byte length, THEN decode. Decoding a Buffer
// to a string first allocates a full-size string for input the cap is about to
// reject; worse, a buffer above Node's max string length escapes the decode as
// an untyped ERR_STRING_TOO_LONG instead of the caller's typed <tooLarge>. This
// guard defines the cap-before-copy ordering and the fatal-UTF-8 decode once so
// no boundary re-derives it (and drifts to cap-after, as some had).

var bytes = require("./guard-bytes");
var intrinsic = require("./guard-intrinsic");

// Everything this guard does to a caller's input, taken at module load. Each name below is an
// ordinary writable property of a global, so reading it at call time would let a caller decide what
// the guard does at the moment it does it. Between them these four cover both of the guard's
// contracts, and both of its input arms:
//
//   _toString / _decode  produce the guard's entire output on the Buffer arm. Replaced with a
//                        function returning a constant, they hand a PEM header, a JOSE segment or a
//                        DN attribute value a string the caller chose in place of the bytes that
//                        were checked -- while the cap, the detached-view refusal and the strict
//                        UTF-8 rule all still run and all still pass.
//   _byteLength          measures the string arm against the cap. One returning 0 admits a string
//                        of any size, which is the allocation-DoS this guard exists to bound.
//   _isInteger           decides whether the cap itself is usable; guard.bytes.isByteSource decides
//                        whether an input takes the byte arm or the string arm.
// The two method captures are uncurried, so their call sites read no property of them; see
// guard-intrinsic for why capturing a method and then reading `.call` on it reopens the hole.
var _toString = intrinsic.uncurry(Buffer.prototype.toString);
var _decode = intrinsic.uncurry(TextDecoder.prototype.decode);
// Already plain functions rather than methods, so these are invoked directly.
var _byteLength = Buffer.byteLength;
var _isInteger = Number.isInteger;
var _TextDecoder = TextDecoder;

var LATIN1 = "latin1";

// decode(input, maxBytes, ErrorClass, spec) -> string.
//   input     : a Buffer (decoded per spec.charset) or a string (taken as-is).
//   maxBytes  : the raw byte-length ceiling, checked before any string copy.
//   ErrorClass: a PkiError subclass (withCause where spec.fatal is set).
//   spec      : { charset: "latin1"|"utf-8" (default latin1),
//                 fatal:   boolean, strict UTF-8 (a lone continuation /
//                          truncated sequence throws, never substitutes U+FFFD),
//                 tooLarge: code for the over-cap reject,
//                 badDecode: code for a fatal-charset (bad-UTF-8) reject
//                            (required only when fatal is set),
//                 badInput: code for a non-byte-source/non-string reject,
//                 label:    human phrase for the message }
// @enforced-by behavioral -- cap-before-copy has no rename-proof code shape; the
//   over-cap RED vectors + the detached re-view through guard.bytes.source (itself
//   enforced) are the guard.
function decode(input, maxBytes, ErrorClass, spec) {
  // maxBytes is an authoring input: an undefined / NaN / fractional cap makes
  // the `length > maxBytes` comparison always false, silently disabling the size
  // cap on the guard whose whole contract is cap-before-copy. Config-time
  // TypeError (every composing boundary passes a C.LIMITS constant).
  if (!_isInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError("guard.text.decode: maxBytes must be a non-negative integer");
  }
  var charset = spec.charset || LATIN1;
  if (bytes.isByteSource(input)) {
    // Re-view through the byte guard first so any byte source (a Buffer, a Uint8Array or other typed array, a
    // DataView, or a raw ArrayBuffer -- a caller-injected transport may return any of these) is normalized to a
    // usable view, and a detached backing ArrayBuffer (a transferred / structuredClone'd view, which reads as
    // zero-length) fails closed here instead of being decoded as an empty string. Then cap, then decode.
    input = bytes.source(input, ErrorClass, spec.badInput, spec.label);
    // Measured through the byte guard's captured intrinsic getter, never `input.length`. On a typed
    // array `length` is an accessor on the prototype and it is configurable, so a replacement
    // returning 0 lets a buffer of any size past the cap and straight into the decode -- the
    // allocation this guard exists to bound, defeated by the one read that bounds it.
    if (bytes.lengthOf(input) > maxBytes) throw new ErrorClass(spec.tooLarge, spec.label + " exceeds the size cap");
    if (spec.fatal) {
      try { return _decode(new _TextDecoder(charset, { fatal: true }), input); }
      catch (e) { throw new ErrorClass(spec.badDecode, spec.label + " is not valid " + charset, e); }
    }
    return _toString(input, charset);
  }
  if (typeof input === "string") {
    // A latin1 string's char length equals its byte length; a UTF-8 string's
    // does not, so bound the encoded byte length.
    var byteLen = charset === LATIN1 ? input.length : _byteLength(input, "utf8");
    if (byteLen > maxBytes) throw new ErrorClass(spec.tooLarge, spec.label + " exceeds the size cap");
    return input;
  }
  throw new ErrorClass(spec.badInput, spec.label + " expects a string or a byte source (Buffer / TypedArray / DataView / ArrayBuffer)");
}

// Frozen for the reason the family header gives: a boundary reads its guard off this object at the
// call, so a writable export would let a caller replace the check rather than pass it.
module.exports = intrinsic.freeze({ decode: decode });
