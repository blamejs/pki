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
var _stringify = require("./guard-intrinsic").stringify;
function _append(arr, v) { _defineProperty(arr, arr.length, { value: v, writable: true, enumerable: true, configurable: true }); }
var limits = require("./guard-limits");

function _hexVal(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  return -1;
}

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
      _defineProperty(out, key, { value: value(depth + 1), writable: true, enumerable: true, configurable: true });
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
    for (;;) {
      _append(out, value(depth + 1));
      ws();
      if (str[i] === ",") { i++; continue; }
      if (str[i] === "]") { i++; return out; }
      fail("expected ',' or ']'");
    }
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
    if (str[i] === ".") {
      i++;
      var fracStart = i;
      while (i < n && str[i] >= "0" && str[i] <= "9") i++;
      if (i === fracStart) fail("malformed number");
    }
    if (str[i] === "e" || str[i] === "E") {
      i++;
      if (str[i] === "+" || str[i] === "-") i++;
      var expStart = i;
      while (i < n && str[i] >= "0" && str[i] <= "9") i++;
      if (i === expStart) fail("malformed number");
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
