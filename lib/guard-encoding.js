// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// consumers whose textual-encoding integrity composes this guard (pki.jose
// base64url, pki.schema.* PEM bodies, pki.webcrypto JWK key material, pki.acme
// / pki.est transfer encodings).
//
// guard-encoding -- strict decode of an untrusted base64 / base64url / hex text
// to bytes. Node's Buffer.from(x, "base64"|"base64url"|"hex") is LENIENT: it
// silently drops the first invalid character (and everything after a stray one),
// accepts non-canonical trailing bits, and tolerates missing/extra padding. Two
// distinct texts can therefore alias one byte string, and a malformed text can
// decode to a shorter, different value than intended. And it allocates the whole
// decode before any size is checked. This is CWE-172 (encoding-transformation error) /
// CWE-20 (canonicalization malleability) + CWE-770 (allocate-before-cap): RFC
// 4648 sec. 3.5 / sec. 5 and RFC 8555 sec. 6.1 require the UNIQUE canonical
// encoding. Each decoder here gates the alphabet, rejects an impossible length,
// enforces the byte cap before the copy, decodes, and verifies canonicality by a
// re-encode round-trip, so a value that is not the one canonical encoding of
// its bytes fails closed with the caller's typed error.
//
// E is the caller's (code, message) typed-error factory; `code` the frozen
// domain/reason; `label` the field phrase; `maxBytes` an optional decoded-size
// cap (null/undefined = uncapped, for a PEM cert body already bounded upstream).

// The alphabets are tables, walked one character at a time. Regular expressions
// would be the obvious alternative, but a guard runs on the most hostile input
// the toolkit sees, and a pattern engine's cost on a non-matching string is
// decided by the pattern, which is the one thing a bound cannot be placed on from
// the outside. A table lookup is one array index per character, so its cost
// follows the length, which the caller already caps. It is also the more honest
// statement of the rule: the set of permitted characters is the rule, written out.
function _alphabet(chars) {
  var t = new Uint8Array(128);
  for (var i = 0; i < chars.length; i++) t[chars.charCodeAt(i)] = 1;
  return t;
}
// Both halves of the round trip, taken at load, along with the string reads the alphabet checks
// are built on. Canonicality here is decided by decoding the text and re-encoding the result, so
// either half is enough to decide the answer: a `toString` returning the input makes every
// non-canonical encoding canonical, and a `charCodeAt` deciding what is in the alphabet chooses
// which characters are there to be judged.
var _intrinsic = require("./guard-intrinsic");
var _bufferFrom = _intrinsic.bufferFrom;
var _toString = _intrinsic.uncurry(Buffer.prototype.toString);
var _charCodeAt = _intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = _intrinsic.uncurry(String.prototype.slice);
var _toLowerCase = _intrinsic.uncurry(String.prototype.toLowerCase);

var UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", LOWER = "abcdefghijklmnopqrstuvwxyz", DIGITS = "0123456789";
var B64URL_ALPHABET = _alphabet(UPPER + LOWER + DIGITS + "-_");
var B64_ALPHABET = _alphabet(UPPER + LOWER + DIGITS + "+/");
var HEX_ALPHABET = _alphabet(DIGITS + "abcdef" + "ABCDEF");

// Every character of `text` is in `table`. A code point outside Latin-1's low half
// (including every astral half) is outside all three alphabets, and the explicit
// bound rejects it, so no lookup can read undefined off the end of the table.
function _inAlphabet(text, table) {
  for (var i = 0; i < text.length; i++) {
    var c = _charCodeAt(text, i);
    if (c > 127 || table[c] !== 1) return false;
  }
  return true;
}

// Reject before Buffer.from allocates: a base64 text of N chars decodes to at
// most floor(N*3/4) bytes, a hex text to N/2.
function _capBefore(nChars, perByteChars, maxBytes, E, code, label) {
  if (maxBytes == null) return;   // documented uncapped mode (bounded upstream)
  // The cap is an authoring input: a NaN / fractional / negative maxBytes makes
  // the comparison below always false -- the cap silently disabled. Config-time
  // TypeError instead (null/undefined stays the documented uncapped mode).
  if (!Number.isInteger(maxBytes) || maxBytes < 0) {
    throw new TypeError("guard.encoding: maxBytes must be a non-negative integer or null");
  }
  if (Math.floor(nChars / perByteChars) > maxBytes) {
    throw E(code, label + " exceeds the maximum decoded size of " + maxBytes + " bytes");
  }
}

// base64url(text, maxBytes, E, code, label) -> Buffer. Unpadded base64url (RFC
// 4648 sec. 5 / RFC 7515): no "=" padding, no "+"/"/", canonical final char.
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

// base64(text, maxBytes, E, code, label) -> Buffer. Padded base64 (RFC 4648
// sec. 4): whole 4-character groups, canonical padding + trailing bits.
// @enforced-by base64-decode-not-via-guard
function base64(text, maxBytes, E, code, label) {
  if (typeof text !== "string") throw E(code, label + " must be a string");
  // Padding is positional, not alphabetic: at most two "=" and only at the end, so
  // the body is measured first and the alphabet applies to what remains. An "="
  // anywhere else leaves a non-alphabet character in the body and rejects there.
  var pad = 0;
  while (pad < 2 && text.length > pad && _charCodeAt(text, text.length - 1 - pad) === 0x3d) pad++;
  if (!_inAlphabet(_strSlice(text, 0, text.length - pad), B64_ALPHABET)) throw E(code, label + " is not base64 (a non-alphabet character)");
  if (text.length % 4 !== 0) throw E(code, label + " must be whole 4-character base64 groups (RFC 4648 sec. 3.5)");
  _capBefore(text.length * 3, 4, maxBytes, E, code, label);
  var buf = _bufferFrom(text,"base64");
  if (_toString(buf, "base64") !== text) throw E(code, label + " is not canonical base64 (RFC 4648 sec. 3.5)");
  return buf;
}

// hex(text, maxBytes, E, code, label) -> Buffer. Even-length hex; canonical via
// a lower-case re-encode round-trip (RFC 4514 sec. 2.4 hex-string values).
// @enforced-by behavioral -- the hex Buffer.from token has legitimate non-decode
//   siblings in the tree (a hard-coded AES-KW IV constant, an internal
//   parser-emitted canonical serial, an internal BigInt->hex), so a blanket
//   Buffer.from(x,"hex") detector would false-fire; the RED conformance vectors
//   (a non-canonical / odd-length / non-hex #hex attribute value rejects) guard it.
function hex(text, maxBytes, E, code, label) {
  if (typeof text !== "string") throw E(code, label + " must be a string");
  if (!_inAlphabet(text, HEX_ALPHABET)) throw E(code, label + " is not hexadecimal");
  if (text.length % 2 !== 0) throw E(code, label + " must have an even number of hex digits");
  _capBefore(text.length, 2, maxBytes, E, code, label);
  var buf = _bufferFrom(text,"hex");
  if (_toString(buf, "hex") !== _toLowerCase(text)) throw E(code, label + " is not canonical hexadecimal");
  return buf;
}

module.exports = { base64url: base64url, base64: base64, hex: hex };
