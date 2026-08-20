// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// consumers whose JSON integrity composes this guard (pki.jose message parsing,
// pki.acme resource objects, pki.webcrypto JWK unwrap).
//
// guard-json -- strict, bounded parse of an untrusted JSON document. JSON.parse
// silently takes the last value of a duplicate member, so a signed or wrapped
// object carrying two members of the same name resolves differently for a
// verifier than for a consumer. That is the JSON smuggling / parser-differential
// class (CWE-20 / CWE-436). It also caps neither size nor nesting (CWE-770 /
// CWE-400), and over a Buffer substitutes U+FFFD for invalid UTF-8 instead of failing.
//
// This is a single hand-written recursive-descent reader that composes
// guard.text.decode (the byte cap runs before the strict/fatal UTF-8 decode, so
// an oversized document is rejected before it is materialized), then rejects a
// duplicate member at every nesting depth, caps nesting, assigns each member as
// an own data property (a "__proto__" key becomes a normal member: it cannot
// mutate the prototype nor, being a non-own assignment for a primitive, silently
// defeat the duplicate-member gate), and enforces the RFC 8259 number/string
// grammar (no leading zero, a fraction/exponent needs a digit, no bare "-").
//
var text = require("./guard-text");
// Taken at load. `defineProperty` is how a decoded member lands on the result without consulting a
// setter, and `fromCharCode` is how an escape becomes the character it names; a replacement for
// either decides what this parser produces. See guard-intrinsic for the whole captured set.
var _defineProperty = require("./guard-intrinsic").defineProperty;
var _fromCharCode = require("./guard-intrinsic").fromCharCode;
// The character-code read the whole scanner is built on: whitespace, escapes and the control-byte
// reject all consult it, so one that lies decides what this parser sees in the input.
var _charCodeAt = require("./guard-intrinsic").uncurry(String.prototype.charCodeAt);
// The scanner has already found where a number literal starts and ends; this is the step that cuts
// it out. A replacement hands `Number` a different span than the one the parser validated, so the
// value the document is understood to carry is not the value its bytes spell.
var _strSlice = require("./guard-intrinsic").uncurry(String.prototype.slice);
// The duplicate-member gate below asks whether a key is already present. Spelled
// `Object.prototype.hasOwnProperty.call(...)` it reads two replaceable properties to answer that,
// and either of them answering wrongly lets a document carry the same member twice.
var _hasOwn = require("./guard-intrinsic").hasOwn;
var _stringify = require("./guard-intrinsic").stringify;
// Appended by index rather than through `push`, so the growth reads no prototype method at all.
function _append(arr, v) { _defineProperty(arr, arr.length, { value: v, writable: true, enumerable: true, configurable: true }); }
var limits = require("./guard-limits");

// One hex digit's value, or -1. Written out because the three ranges ARE the rule.
function _hexVal(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;          // 0-9
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;     // a-f
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;     // A-F
  return -1;
}

// parse(input, ErrorClass, spec) -> value. `input` is a Buffer or a string.
// spec = { maxBytes, maxDepth, badJson, tooDeep, duplicateMember, tooLarge,
//   badInput, label }, the caller's caps and frozen domain/reason codes.
// Both caps are required authoring inputs: an omitted, NaN or fractional cap
// would silently disable the bound it configures (a depth-uncapped recursive
// descent escapes as a raw stack-overflow RangeError), so they are validated
// through the shared cap guards at entry, maxDepth additionally against the
// stack-safe recursion ceiling, so no caller cap can exceed frame safety.
// @enforced-by json-parse-not-via-guard
function parse(input, ErrorClass, spec) {
  function E(code, message, cause) { return new ErrorClass(code, message, cause); }
  if (spec.maxBytes === undefined || spec.maxDepth === undefined) {
    throw new TypeError("guard.json.parse: spec.maxBytes and spec.maxDepth are required");
  }
  var maxBytes = limits.cap(spec.maxBytes, "guard.json.parse spec.maxBytes", undefined);
  var maxDepth = limits.depthCap(spec.maxDepth, "guard.json.parse spec.maxDepth", undefined);
  // Byte cap before the fatal UTF-8 decode (an oversized/ill-encoded document is
  // rejected before it is turned into a string).
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
    // Through the captured slice, not `substr`: these three comparisons ARE the literal grammar, so
    // one returning something else accepts a token the document does not spell.
    if (_strSlice(str, i, i + 4) === "true") { i += 4; return true; }
    if (_strSlice(str, i, i + 5) === "false") { i += 5; return false; }
    if (_strSlice(str, i, i + 4) === "null") { i += 4; return null; }
    fail("unexpected token");
    return undefined;
  }
  function object(depth) {
    i++; // {
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
      // Own data property (not out[key]=...): a "__proto__" key becomes a normal
      // member, never a prototype mutation nor a silent duplicate-gate bypass.
      _defineProperty(out, key, { value: value(depth + 1), writable: true, enumerable: true, configurable: true });
      ws();
      if (str[i] === ",") { i++; continue; }
      if (str[i] === "}") { i++; return out; }
      fail("expected ',' or '}'");
    }
  }
  function array(depth) {
    i++; // [
    var out = [];
    ws();
    if (str[i] === "]") { i++; return out; }
    for (;;) {
      _append(out, value(depth + 1));
      ws();
      if (str[i] === ",") { i++; continue; }
      if (str[i] === "]") { i++; return out; }
      fail("expected ',' or ']'");
    }
  }
  function string() {
    i++; // opening quote
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
          // Four hex digits, read as digits instead of matched as a pattern: the
          // scanner is already walking this string one character at a time, and a
          // parser handed hostile input should not hand any of it to a second engine.
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
  // RFC 8259 sec. 6, enforced by the walk itself and not by re-matching the token
  // afterwards. The scan already knows where each part starts and ends, so the
  // grammar's three rules (an integer part that is "0" or has no leading zero, a
  // fraction with at least one digit, an exponent with at least one digit) are
  // checked as it goes. Re-matching what the scanner just read meant maintaining
  // the same grammar twice, in two notations, and the pattern was the copy whose
  // cost on a rejecting token could not be bounded from outside.
  function number() {
    var start = i;
    if (str[i] === "-") i++;
    var intStart = i;
    while (i < n && str[i] >= "0" && str[i] <= "9") i++;
    var intLen = i - intStart;
    if (intLen === 0) fail("malformed number");
    if (intLen > 1 && str[intStart] === "0") fail("malformed number");   // no leading zero
    if (str[i] === ".") {
      i++;
      var fracStart = i;
      while (i < n && str[i] >= "0" && str[i] <= "9") i++;
      if (i === fracStart) fail("malformed number");                     // "1." has no fraction
    }
    if (str[i] === "e" || str[i] === "E") {
      i++;
      if (str[i] === "+" || str[i] === "-") i++;
      var expStart = i;
      while (i < n && str[i] >= "0" && str[i] <= "9") i++;
      if (i === expStart) fail("malformed number");                      // "1e" has no exponent
    }
    var v = Number(_strSlice(str, start, i));
    if (!isFinite(v)) fail("bad number");
    return v;
  }
  var result = value(0);
  ws();
  if (i !== n) fail("trailing content after JSON value");
  return result;
}

module.exports = { parse: parse };
