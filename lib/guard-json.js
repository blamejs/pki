// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal
var text = require("./guard-text");
var _defineProperty = require("./guard-intrinsic").defineProperty;
var _freeze = require("./guard-intrinsic").freeze;
var _fromCharCode = require("./guard-intrinsic").fromCharCode;
var _charCodeAt = require("./guard-intrinsic").uncurry(String.prototype.charCodeAt);
var _strSlice = require("./guard-intrinsic").uncurry(String.prototype.slice);
var _hasOwn = require("./guard-intrinsic").hasOwn;
var _Number = require("./guard-intrinsic").Number;
var _isFinite = require("./guard-intrinsic").isFinite;
var _BigInt = require("./guard-intrinsic").BigInt;
/** @internal The largest integer a double holds exactly, as a BigInt, for `spec.exactIntegers`. Past it a
 *  value reads back as a different one: 2^53 + 1 converts to 2^53. */
var _MAX_EXACT = _BigInt(Number.MAX_SAFE_INTEGER);
var _stringify = require("./guard-intrinsic").stringify;
var _append = require("./guard-list").append;
var limits = require("./guard-limits");

var _hexVal = require("./guard-encoding").hexNibble;

// @enforced-by json-parse-not-via-guard
function parse(input, ErrorClass, spec) {
  function E(code, message, cause) { return new ErrorClass(code, message, cause); }
  if (spec.maxBytes === undefined || spec.maxDepth === undefined) {
    throw new TypeError("guard.json.parse: spec.maxBytes and spec.maxDepth are required");
  }
  var maxBytes = limits.cap(spec.maxBytes, "guard.json.parse spec.maxBytes", undefined);
  var maxDepth = limits.depthCap(spec.maxDepth, "guard.json.parse spec.maxDepth", undefined);
  var str = text.decode(input, maxBytes, ErrorClass, {
    charset: "utf-8", fatal: true, tooLarge: spec.tooLarge, badDecode: spec.badJson, badInput: spec.badInput, label: spec.label,
  });
  var i = 0, n = str.length;
  function ws() { while (i < n) { var c = _charCodeAt(str, i); if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++; else break; } }
  function fail(msg) { throw E(spec.badJson, "invalid JSON at offset " + i + ": " + msg); }
  function value(depth) {
    if (depth > maxDepth) throw E(spec.tooDeep, "JSON nesting exceeds the depth cap");
    ws();
    if (i >= n) fail("unexpected end of input");
    var c = str[i];
    if (c === "{") return object(depth);
    if (c === "[") return array(depth);
    if (c === "\"") return string();
    if (c === "-" || (c >= "0" && c <= "9")) return number();
    if (_strSlice(str, i, i + 4) === "true") { i += 4; return true; }
    if (_strSlice(str, i, i + 5) === "false") { i += 5; return false; }
    if (_strSlice(str, i, i + 4) === "null") { i += 4; return null; }
    fail("unexpected token");
    return undefined;
  }
  /** @internal The member name whose value is being parsed, or null at the top level and inside an array.
   *  Read only by the number policy below. */
  var currentMember = null;
  function object(depth) {
    i++;
    var out = {};
    ws();
    if (str[i] === "}") { i++; return out; }
    for (;;) {
      ws();
      if (str[i] !== "\"") fail("expected a string key");
      var key = string();
      if (_hasOwn(out, key)) throw E(spec.duplicateMember, "duplicate JSON member " + _stringify(key));
      ws();
      if (str[i] !== ":") fail("expected ':'");
      i++;
      /** @internal The member name is carried into the value so a per-member number policy can apply to
       *  the members that need it. A document can be ordinary JSON, where a fractional number is legal
       *  somewhere in it, and still read ONE member as an integer: the FIDO metadata BLOB carries
       *  biometric false-accept rates as genuine doubles beside a rollback counter that must be an exact
       *  integer, so a document-wide rule refuses the real catalogue and no rule at all leaves the
       *  counter readable as a rounded spelling. */
      var outerMember = currentMember;
      currentMember = key;
      var memberValue;
      try { memberValue = value(depth + 1); } finally { currentMember = outerMember; }
      _defineProperty(out, key, { value: memberValue, writable: true, enumerable: true, configurable: true });
      ws();
      if (str[i] === ",") { i++; continue; }
      if (str[i] === "}") { i++; return out; }
      fail("expected ',' or '}'");
    }
  }
  function array(depth) {
    i++;
    var out = [];
    ws();
    if (str[i] === "]") { i++; return out; }
    /** @internal The enclosing member's name does not reach the elements. A per-member number policy names
     *  a member whose VALUE is an integer, so a member holding an array holds no number for the rule to
     *  apply to, and letting the name reach inside would constrain a whole subtree from one name: the
     *  document-wide rule in miniature, and the shape that refuses a conforming document. */
    var outerMember = currentMember;
    currentMember = null;
    try {
      for (;;) {
        _append(out, value(depth + 1));
        ws();
        if (str[i] === ",") { i++; continue; }
        if (str[i] === "]") { i++; return out; }
        fail("expected ',' or ']'");
      }
    } finally { currentMember = outerMember; }
  }
  function string() {
    i++;
    var s = "";
    for (;;) {
      if (i >= n) fail("unterminated string");
      var c = str[i++];
      if (c === "\"") return s;
      if (c === "\\") {
        if (i >= n) fail("unterminated escape");
        var e = str[i++];
        if (e === "\"") s += "\"";
        else if (e === "\\") s += "\\";
        else if (e === "/") s += "/";
        else if (e === "b") s += "\b";
        else if (e === "f") s += "\f";
        else if (e === "n") s += "\n";
        else if (e === "r") s += "\r";
        else if (e === "t") s += "\t";
        else if (e === "u") {
          var cp = 0;
          if (i + 4 > n) fail("bad \\u escape");
          for (var h = 0; h < 4; h++) {
            var d = _hexVal(_charCodeAt(str, i + h));
            if (d < 0) fail("bad \\u escape");
            cp = (cp << 4) | d;
          }
          s += _fromCharCode(cp);
          i += 4;
        } else fail("bad escape");
      } else if (_charCodeAt(c, 0) < 0x20) {
        fail("control character in string");
      } else s += c;
    }
  }
  function number() {
    var start = i;
    if (str[i] === "-") i++;
    var intStart = i;
    while (i < n && str[i] >= "0" && str[i] <= "9") i++;
    var intLen = i - intStart;
    if (intLen === 0) fail("malformed number");
    if (intLen > 1 && str[intStart] === "0") fail("malformed number");
    var intDigits = _strSlice(str, intStart, i);
    var fracDigits = "";
    var expValue = 0;
    var notAnInteger = false;
    if (str[i] === ".") {
      i++;
      var fracStart = i;
      while (i < n && str[i] >= "0" && str[i] <= "9") i++;
      if (i === fracStart) fail("malformed number");
      fracDigits = _strSlice(str, fracStart, i);
      notAnInteger = true;
    }
    if (str[i] === "e" || str[i] === "E") {
      i++;
      var expNeg = false;
      if (str[i] === "+") i++;
      else if (str[i] === "-") { expNeg = true; i++; }
      var expStart = i;
      while (i < n && str[i] >= "0" && str[i] <= "9") i++;
      if (i === expStart) fail("malformed number");
      /** @internal The exponent is read as written, with no bound on its spelling. Bounding the character
       *  COUNT refuses valid numbers: `1e0000000` is 1 and `0e1000000` is 0, both exactly representable,
       *  and the bound applied to every caller whether or not one asked for an integer policy. Nothing
       *  below needs the bound, because the exact-integer decision is taken from digit COUNTS and never
       *  expands the value, and a magnitude that overflows a double is caught by the `_isFinite` check
       *  that every number already passes through. */
      expValue = _Number(_strSlice(str, expStart, i));
      if (expNeg) expValue = -expValue;
      notAnInteger = true;
    }
    /** @internal `spec.integersOnly` refuses a fractional or exponent-form token HERE, while the token is
     *  still text. Conversion to a Number loses the distinction: 1.0000000000000001 becomes 1, so a check
     *  for an integer afterwards sees one and a format that permits only integers has been read as
     *  conforming. A caller asks for this when its own format forbids floating point. */
    if (spec.integersOnly && notAnInteger) {
      fail("a fractional or exponent-form number, where this format admits only integers");
    }
    /** @internal `spec.exactIntegers` is the laxer rule, for a format that is ordinary JSON but will treat
     *  this value as an integer. It refuses nothing a producer may legally write: `1e3`, `1.0` and
     *  `1500e-2` all denote integers and are accepted. What it refuses is a spelling whose VALUE is not
     *  exactly its own integer, which conversion to a Number cannot be asked about afterwards:
     *  `1.0000000000000001` becomes 1, so an `isInteger` check made after conversion sees a conforming
     *  document and the value the caller reports is not the spelling the producer sent. Where that value
     *  is folded back into a binary preimage, as a CT tree size is, the rounded spelling verifies.
     *
     *  Decided on the DIGITS, with no float arithmetic: the token is `digits x 10^scale`, so it denotes an
     *  integer exactly when the scale is non-negative or when every digit the scale would drop is a zero.
     *  The resulting integer must also be one a double holds exactly, since 2^53 + 1 reads back as 2^53
     *  and that is the same loss by another route. */
    /** @internal The rule applies to every number when `spec.exactIntegers` is set, and to the named
     *  members alone when `spec.exactIntegerMembers` is. The second form is for a document that is
     *  ordinary JSON, where a fractional number is legal somewhere in it, but reads one member as an
     *  integer: the FIDO metadata BLOB is that, and the live catalogue carries ten genuinely non-integral
     *  biometric rates, so the document-wide rule refuses it outright. Verified against the published
     *  BLOB rather than against the specification text. */
    var exactWanted = spec.exactIntegers ||
      (spec.exactIntegerMembers && currentMember !== null && _hasOwn(spec.exactIntegerMembers, currentMember));
    if (exactWanted) {
      var digits = intDigits + fracDigits;
      var scale = expValue - fracDigits.length;
      /** @internal Decided from the DIGIT COUNT and the scale, never by expanding the value. Computing
       *  `digits x 10^scale` to find out whether it is an integer means building the power first, and an
       *  exponent is six digits wide: `0e999999` expands to a million digits and then multiplies by a
       *  zero mantissa, so it passed, and a document can carry one such token per few bytes of its size
       *  cap. Measured at 1566 ms for a 907-byte CT response before this. Nothing below constructs a
       *  BigInt until the value is known to be small. */
      var lead = 0;
      while (lead < digits.length && digits[lead] === "0") lead++;
      if (lead === digits.length) {
        /** @internal Every digit is a zero, so the value is zero whatever the scale, and zero is an
         *  exact integer. Taken here because it is also the shape that made the expansion free to
         *  request: `0e999999` is this case. */
        var zeroValue = _Number(_strSlice(str, start, i));
        if (!_isFinite(zeroValue)) fail("bad number");
        return zeroValue;
      }
      /** @internal The significant digits, and the trailing zeros among them that the scale may cancel.
       *  A negative scale drops that many digits off the end, and the value is an integer only when every
       *  digit it drops is a zero. Counted rather than sliced, so a long mantissa costs a scan. */
      var lastSig = digits.length - 1;
      while (lastSig > lead && digits[lastSig] === "0") lastSig--;
      var trailingZeros = digits.length - 1 - lastSig;
      if (scale < 0 && -scale > trailingZeros) {
        fail("a number whose value is not exactly an integer, where this format reads it as one");
      }
      /** @internal The integer's decimal width, from the counts alone. MAX_SAFE_INTEGER is 16 digits, so
       *  anything wider than that is outside the exactly-representable range and is refused before a
       *  BigInt exists. Only a value already known to be at most 17 digits reaches the arithmetic. */
      var sigCount = lastSig - lead + 1;
      var intWidth = sigCount + scale + trailingZeros;
      if (intWidth > 17) {
        fail("an integer beyond the range a double represents exactly, so the value read back would not be the value written");
      }
      var exactDigits = _strSlice(digits, lead, lastSig + 1);
      var zerosAfter = scale + trailingZeros;
      for (var pad = 0; pad < zerosAfter; pad++) exactDigits += "0";
      var exact = _BigInt(exactDigits);
      if (exact > _MAX_EXACT) {
        fail("an integer beyond the range a double represents exactly, so the value read back would not be the value written");
      }
    }
    var v = _Number(_strSlice(str, start, i));
    if (!_isFinite(v)) fail("bad number");
    return v;
  }
  var result = value(0);
  ws();
  if (i !== n) fail("trailing content after JSON value");
  return result;
}

module.exports = _freeze({ parse: parse });
