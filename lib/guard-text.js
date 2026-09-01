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
      try { return _decode(new _TextDecoder(charset, { fatal: true }), input); }
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

module.exports = intrinsic.freeze({ decode: decode });
