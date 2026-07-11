// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. The documented surface is the
// consumers whose JSON integrity composes this guard (pki.jose message parsing,
// pki.acme resource objects, pki.webcrypto JWK unwrap).
//
// guard-json -- strict, bounded parse of an untrusted JSON document. JSON.parse
// silently takes the LAST value of a DUPLICATE member, so a signed / wrapped
// object carrying two members of the same name resolves differently for a
// verifier than for a consumer -- the JSON smuggling / parser-differential class
// (CWE-20 / CWE-436). It also caps neither size nor nesting (CWE-770 / CWE-400),
// and over a Buffer substitutes U+FFFD for invalid UTF-8 rather than failing.
//
// This is a single hand-written recursive-descent reader that composes
// guard.text.decode (the byte cap runs BEFORE the strict/fatal UTF-8 decode, so
// an oversized document is rejected before it is materialized), then rejects a
// duplicate member at EVERY nesting depth, caps nesting, assigns each member as
// an OWN data property (a "__proto__" key becomes a normal member -- it cannot
// mutate the prototype nor, being a non-own assignment for a primitive, silently
// defeat the duplicate-member gate), and enforces the RFC 8259 number/string
// grammar (no leading zero, a fraction/exponent needs a digit, no bare "-").
//
var text = require("./guard-text");
var limits = require("./guard-limits");

// parse(input, ErrorClass, spec) -> value. `input` is a Buffer or a string.
// spec = { maxBytes, maxDepth, badJson, tooDeep, duplicateMember, tooLarge,
//   badInput, label } -- the caller's caps + frozen domain/reason codes.
// Both caps are REQUIRED authoring inputs: an omitted / NaN / fractional cap
// would silently disable the bound it configures (a depth-uncapped recursive
// descent escapes as a raw stack-overflow RangeError), so they are validated
// through the shared cap guards at entry -- maxDepth additionally against the
// stack-safe recursion ceiling, so no caller cap can exceed frame safety.
// @enforced-by json-parse-not-via-guard
function parse(input, ErrorClass, spec) {
  function E(code, message, cause) { return new ErrorClass(code, message, cause); }
  if (spec.maxBytes === undefined || spec.maxDepth === undefined) {
    throw new TypeError("guard.json.parse: spec.maxBytes and spec.maxDepth are required");
  }
  var maxBytes = limits.cap(spec.maxBytes, "guard.json.parse spec.maxBytes", undefined);
  var maxDepth = limits.depthCap(spec.maxDepth, "guard.json.parse spec.maxDepth", undefined);
  // Byte cap BEFORE the fatal UTF-8 decode (an oversized/ill-encoded document is
  // rejected before it is turned into a string).
  var str = text.decode(input, maxBytes, ErrorClass, {
    charset: "utf-8", fatal: true, tooLarge: spec.tooLarge, badDecode: spec.badJson, badInput: spec.badInput, label: spec.label,
  });
  var i = 0, n = str.length;
  function ws() { while (i < n) { var c = str.charCodeAt(i); if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++; else break; } }
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
    if (str.substr(i, 4) === "true") { i += 4; return true; }
    if (str.substr(i, 5) === "false") { i += 5; return false; }
    if (str.substr(i, 4) === "null") { i += 4; return null; }
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
      if (Object.prototype.hasOwnProperty.call(out, key)) throw E(spec.duplicateMember, "duplicate JSON member " + JSON.stringify(key));
      ws();
      if (str[i] !== ":") fail("expected ':'");
      i++;
      // Own data property (not out[key]=...): a "__proto__" key becomes a normal
      // member, never a prototype mutation nor a silent duplicate-gate bypass.
      Object.defineProperty(out, key, { value: value(depth + 1), writable: true, enumerable: true, configurable: true });
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
      out.push(value(depth + 1));
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
          var hex = str.substr(i, 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad \\u escape");
          s += String.fromCharCode(parseInt(hex, 16));
          i += 4;
        } else fail("bad escape");
      } else if (c.charCodeAt(0) < 0x20) {
        fail("control character in string");
      } else s += c;
    }
  }
  function number() {
    var start = i;
    if (str[i] === "-") i++;
    while (i < n && str[i] >= "0" && str[i] <= "9") i++;
    if (str[i] === ".") { i++; while (i < n && str[i] >= "0" && str[i] <= "9") i++; }
    if (str[i] === "e" || str[i] === "E") { i++; if (str[i] === "+" || str[i] === "-") i++; while (i < n && str[i] >= "0" && str[i] <= "9") i++; }
    var tok = str.slice(start, i);
    if (!/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/.test(tok)) fail("malformed number");
    var v = Number(tok);
    if (!isFinite(v)) fail("bad number");
    return v;
  }
  var result = value(0);
  ws();
  if (i !== n) fail("trailing content after JSON value");
  return result;
}

module.exports = { parse: parse };
