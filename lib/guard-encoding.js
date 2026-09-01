// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

function _alphabet(chars) {
  // allow:guard-reads-runtime-live -- the three tables below are the only callers and they are
  var t = new Uint8Array(128);
  for (var i = 0; i < chars.length; i++) t[_charCodeAt(chars, i)] = 1;
  return t;
}
var _intrinsic = require("./guard-intrinsic");
var _bufferFrom = _intrinsic.bufferFrom;
var _toString = _intrinsic.uncurry(Buffer.prototype.toString);
var _charCodeAt = _intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = _intrinsic.uncurry(String.prototype.slice);
var _toLowerCase = _intrinsic.uncurry(String.prototype.toLowerCase);
var _isInteger = _intrinsic.isInteger;
var _floor = _intrinsic.floor;

var UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", LOWER = "abcdefghijklmnopqrstuvwxyz", DIGITS = "0123456789";
var B64URL_ALPHABET = _alphabet(UPPER + LOWER + DIGITS + "-_");
var B64_ALPHABET = _alphabet(UPPER + LOWER + DIGITS + "+/");
var HEX_ALPHABET = _alphabet(DIGITS + "abcdef" + "ABCDEF");

function _inAlphabet(text, table) {
  for (var i = 0; i < text.length; i++) {
    var c = _charCodeAt(text, i);
    if (c > 127 || table[c] !== 1) return false;
  }
  return true;
}

function _capBefore(nChars, perByteChars, maxBytes, E, code, label) {
  if (maxBytes == null) return;
  if (!_isInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError("guard.encoding: maxBytes must be a non-negative integer or null");
  }
  if (_floor(nChars / perByteChars) > maxBytes) {
    throw E(code, label + " exceeds the maximum decoded size of " + maxBytes + " bytes");
  }
}

// @enforced-by base64-decode-not-via-guard
function base64url(text, maxBytes, E, code, label) {
  if (typeof text !== "string") throw E(code, label + " must be a string");
  if (!_inAlphabet(text, B64URL_ALPHABET)) throw E(code, label + " is not base64url (padding or a non-alphabet character)");
  if (text.length % 4 === 1) throw E(code, label + " has an impossible base64url length");
  _capBefore(text.length * 3, 4, maxBytes, E, code, label);
  var buf = _bufferFrom(text,"base64url");
  if (_toString(buf, "base64url") !== text) throw E(code, label + " is not canonical base64url");
  return buf;
}

// @enforced-by base64-decode-not-via-guard
function base64(text, maxBytes, E, code, label) {
  if (typeof text !== "string") throw E(code, label + " must be a string");
  var pad = 0;
  while (pad < 2 && text.length > pad && _charCodeAt(text, text.length - 1 - pad) === 0x3d) pad++;
  if (!_inAlphabet(_strSlice(text, 0, text.length - pad), B64_ALPHABET)) throw E(code, label + " is not base64 (a non-alphabet character)");
  if (text.length % 4 !== 0) throw E(code, label + " must be whole 4-character base64 groups (RFC 4648 sec. 3.5)");
  _capBefore(text.length * 3, 4, maxBytes, E, code, label);
  var buf = _bufferFrom(text,"base64");
  if (_toString(buf, "base64") !== text) throw E(code, label + " is not canonical base64 (RFC 4648 sec. 3.5)");
  return buf;
}

// @enforced-by behavioral -- the hex Buffer.from token has legitimate non-decode
function hex(text, maxBytes, E, code, label) {
  if (typeof text !== "string") throw E(code, label + " must be a string");
  if (!_inAlphabet(text, HEX_ALPHABET)) throw E(code, label + " is not hexadecimal");
  if (text.length % 2 !== 0) throw E(code, label + " must have an even number of hex digits");
  _capBefore(text.length, 2, maxBytes, E, code, label);
  var buf = _bufferFrom(text,"hex");
  if (_toString(buf, "hex") !== _toLowerCase(text)) throw E(code, label + " is not canonical hexadecimal");
  return buf;
}

module.exports = _intrinsic.freeze({ base64url: base64url, base64: base64, hex: hex });
