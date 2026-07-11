// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// primitives whose text boundaries compose this guard (pki.jose.parseJson, the
// PEM decoders, the EST transfer decoders).
//
// guard-text -- fail-closed decode of an untrusted byte-source input to a
// string, capping the RAW byte length BEFORE the string is materialized.
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

var LATIN1 = "latin1";

// decode(input, maxBytes, ErrorClass, spec) -> string.
//   input     : a Buffer (decoded per spec.charset) or a string (taken as-is).
//   maxBytes  : the raw byte-length ceiling, checked BEFORE any string copy.
//   ErrorClass: a PkiError subclass (withCause where spec.fatal is set).
//   spec      : { charset: "latin1"|"utf-8" (default latin1),
//                 fatal:   boolean -- strict UTF-8 (a lone continuation /
//                          truncated sequence throws, never substitutes U+FFFD),
//                 tooLarge: code for the over-cap reject,
//                 badDecode: code for a fatal-charset (bad-UTF-8) reject
//                            (required only when fatal is set),
//                 badInput: code for a non-Buffer/non-string reject,
//                 label:    human phrase for the message }
function decode(input, maxBytes, ErrorClass, spec) {
  var charset = spec.charset || LATIN1;
  if (Buffer.isBuffer(input)) {
    // Re-view through the byte guard FIRST so a detached backing ArrayBuffer (a
    // transferred / structuredClone'd Buffer, which reads as zero-length) fails
    // closed here -- the same detached-buffer defence the byte boundaries get --
    // instead of being decoded as an empty string. Then cap, then decode.
    input = bytes.view(input, ErrorClass, spec.badInput, spec.label);
    if (input.length > maxBytes) throw new ErrorClass(spec.tooLarge, spec.label + " exceeds the size cap");
    if (spec.fatal) {
      try { return new TextDecoder(charset, { fatal: true }).decode(input); }
      catch (e) { throw new ErrorClass(spec.badDecode, spec.label + " is not valid " + charset, e); }
    }
    return input.toString(charset);
  }
  if (typeof input === "string") {
    // A latin1 string's char length equals its byte length; a UTF-8 string's
    // does not, so bound the encoded byte length.
    var byteLen = charset === LATIN1 ? input.length : Buffer.byteLength(input, "utf8");
    if (byteLen > maxBytes) throw new ErrorClass(spec.tooLarge, spec.label + " exceeds the size cap");
    return input;
  }
  throw new ErrorClass(spec.badInput, spec.label + " expects a string or Buffer");
}

module.exports = { decode: decode };
