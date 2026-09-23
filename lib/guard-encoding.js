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
var _charAt = _intrinsic.uncurry(String.prototype.charAt);
var _fromCharCode = String.fromCharCode;
var _guardBytes = require("./guard-bytes");
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

/**
 * @internal The value of one hexadecimal digit, or -1 when the byte is not one. Every
 * character-scanning reader of an escape (a DN string, a JSON string, a URI) asks the same
 * question, and asking it in one place keeps the three ranges from drifting apart.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape c >= 0x30 && c <= 0x39\) return c - 0x30
 */
function hexNibble(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return -1;
}

/**
 * @internal Whether a byte is an ASCII letter or digit. It is the base of every
 * character-class a textual syntax defines on top of it, so the three ranges live here
 * rather than being spelled again per reader.
 *
 * @enforced-by behavioral -- the ranges have no rename-proof shape distinct from a legitimate
 * range test, and each consumer's own acceptance vector is the guard.
 */
function isAlphanumericByte(c) {
  return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39);
}

var _HEX_UPPER = "0123456789ABCDEF";

/** @internal Whether a byte is in RFC 3986 sec. 2.3's unreserved set: `ALPHA / DIGIT / "-" / "."
 * / "_" / "~"`. Every other byte is written as a percent-triplet, which is what sec. 2.1 requires
 * of a character that is not allowed where it sits. The set is deliberately the unreserved one
 * and not the larger set a path segment also admits, so the output is safe wherever it is
 * placed and a caller cannot reach a delimiter by choosing a component. */
function _isUnreservedByte(c) {
  return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) ||
    c === 0x2d || c === 0x2e || c === 0x5f || c === 0x7e;
}

/** @internal Percent-encode bytes to RFC 3986 sec. 2.1, with the unreserved set of sec. 2.3 passed
 * through and every other byte written as `%` and two upper-case hex digits. sec. 2.1 states that
 * the hexadecimal digits of a triplet may be either case and that uppercase is the canonical form
 * a producer emits.
 *
 * This is the only escaping in `lib/`. `encodeURIComponent` reads a JavaScript string, so bytes
 * reach it only after a decode this cannot assume, and it leaves `!`, `*`, `'`, `(` and `)`
 * unescaped, which are sub-delims in sec. 2.2 and therefore delimiters in some components. */
// @enforced-by guard-shape-reinlined
// @guard-shape %[0-9A-F]{2}|toString\(16\)[\s\S]{0,80}?padStart\(\s*2
// @guard-via guard\.encoding\.(?:percentEncode|uriPathSegment)\(
function percentEncode(bytes, E, code, label) {
  var buf = _guardBytes.source(bytes, _rawError(E), code, label || "value to percent-encode");
  var out = "";
  for (var i = 0; i < buf.length; i++) {
    var c = buf[i];
    if (_isUnreservedByte(c)) { out += _fromCharCode(c); continue; }
    out += "%" + _charAt(_HEX_UPPER, (c >> 4) & 0x0f) + _charAt(_HEX_UPPER, c & 0x0f);
  }
  return out;
}

/** @internal One path segment of a URI, built from `text` read as its latin1 bytes. Every byte
 * outside the unreserved set becomes a triplet, so a value carrying `/`, `?`, `#` or a percent of
 * its own cannot reach past the segment it was placed in. */
function uriPathSegment(text, E, code, label) {
  if (typeof text !== "string") {
    throw _rawError(E)(code, (label || "URI path segment") + " must be a string");
  }
  return percentEncode(_bufferFrom(text, "latin1"), E, code, label);
}

/** @internal The guards take a `(code, message)` factory. A caller that passes an error CLASS is a
 * configuration fault and not an input one, so it is refused here instead of producing
 * `undefined is not a constructor` at the first refusal. */
function _rawError(E) {
  if (typeof E !== "function") throw new TypeError("guard.encoding: an error factory (code, message) is required");
  return E;
}

/** @internal Whether a string is already the form that goes on the wire. RFC 3986 sec. 2 builds a
 * URI out of US-ASCII alone, so a string carrying anything above it is an IRI (RFC 3987) and the
 * bytes a transport would send are not the characters counted here. Every length a specification
 * states about a URL is a byte count, which makes this the check a boundary needs before measuring
 * one: a code point in U+0080..U+07FF is one character and two UTF-8 bytes, so a rule measured in
 * characters passes a URL the rule was meant to refuse.
 *
 * @enforced-by guard-shape-reinlined
 * @guard-shape /charCodeAt\s*\(\s*[\w$]+\s*,\s*[\w$]+\s*\)\s*>\s*(?:0x7f|127)\b/ */
function isAsciiText(s) {
  if (typeof s !== "string") return false;
  for (var i = 0; i < s.length; i++) {
    if (_charCodeAt(s, i) > 0x7f) return false;
  }
  return true;
}

module.exports = _intrinsic.freeze({
  base64url: base64url, base64: base64, hex: hex,
  hexNibble: hexNibble, isAlphanumericByte: isAlphanumericByte,
  isAsciiText: isAsciiText,
  percentEncode: percentEncode, uriPathSegment: uriPathSegment,
});
