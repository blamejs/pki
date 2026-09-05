// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var intrinsic = require("./guard-intrinsic");
var _slice = intrinsic.uncurry(String.prototype.slice);
var _padStart = intrinsic.uncurry(String.prototype.padStart);
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _lastIndexOf = intrinsic.uncurry(String.prototype.lastIndexOf);
var _toLowerCase = intrinsic.toLowerCase;
var _indexOf = intrinsic.stringIndexOf;
var _numToString = intrinsic.numberToString;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferAlloc = intrinsic.bufferAlloc;
var _defineProperty = intrinsic.defineProperty;
var _Number = intrinsic.Number;
var _push = require("./guard-list").append;
function _splitOn(str, sep) {
  var out = [], from = 0, at;
  while ((at = _indexOf(str, sep, from)) !== -1) { _push(out, _slice(str, from, at)); from = at + sep.length; }
  _push(out, _slice(str, from));
  return out;
}

function _isDigitCode(c) { return c >= 48 && c <= 57; }
function _isHexCode(c) { return (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70); }

function _isOctet(p) {
  var n = p.length, i, c;
  if (n < 1 || n > 3) return false;
  for (i = 0; i < n; i += 1) { c = _charCodeAt(p, i); if (!_isDigitCode(c)) return false; }
  if (n > 1 && _charCodeAt(p, 0) === 48) return false;
  return _Number(p) <= 255;
}

function isIPv4(s) {
  if (typeof s !== "string") return false;
  var parts = _splitOn(s, ".");
  if (parts.length !== 4) return false;
  for (var i = 0; i < 4; i += 1) { if (!_isOctet(parts[i])) return false; }
  return true;
}

function _isHexGroup(g) {
  var n = g.length, i;
  if (n < 1 || n > 4) return false;
  for (i = 0; i < n; i += 1) { if (!_isHexCode(_charCodeAt(g, i))) return false; }
  return true;
}

function _isDottedQuadShape(t) {
  var q = _splitOn(t, "."), i, p, j;
  if (q.length !== 4) return false;
  for (i = 0; i < 4; i += 1) {
    p = q[i];
    if (p.length < 1 || p.length > 3) return false;
    for (j = 0; j < p.length; j += 1) { if (!_isDigitCode(_charCodeAt(p, j))) return false; }
  }
  return true;
}

var IPV6_TEXT_MAX_LEN = 45;
function expandIpv6Hex(ip) {
  if (typeof ip !== "string" || ip.length > IPV6_TEXT_MAX_LEN || _indexOf(ip, ":") === -1) return null;
  var lastColon = _lastIndexOf(ip, ":");
  var tail = _slice(ip, lastColon + 1);
  if (_indexOf(tail, ".") !== -1) {
    if (!_isDottedQuadShape(tail) || !isIPv4(tail)) return null;
    var q = _splitOn(tail, "."), o0 = _Number(q[0]), o1 = _Number(q[1]), o2 = _Number(q[2]), o3 = _Number(q[3]);
    ip = _slice(ip, 0, lastColon) + ":" + _numToString((o0 << 8) | o1, 16) + ":" + _numToString((o2 << 8) | o3, 16);
  }
  var dbl = _splitOn(ip, "::");
  if (dbl.length > 2) return null;
  var left = dbl[0] === "" ? [] : _splitOn(dbl[0], ":");
  var right = dbl.length === 2 ? (dbl[1] === "" ? [] : _splitOn(dbl[1], ":")) : [];
  if (dbl.length === 1 && left.length !== 8) return null;
  var fill = 8 - left.length - right.length;
  if (dbl.length === 2 ? fill < 1 : fill !== 0) return null;
  var groups = left, i;
  for (i = 0; i < fill; i += 1) _push(groups, "0");
  for (i = 0; i < right.length; i += 1) _push(groups, right[i]);
  if (groups.length !== 8) return null;
  var hex = "";
  for (i = 0; i < 8; i += 1) {
    var g = groups[i];
    if (!_isHexGroup(g)) return null;
    hex += _padStart(_toLowerCase(g), 4, "0");
  }
  return hex;
}

function isIpLiteral(s) { return isIPv4(s) || expandIpv6Hex(s) !== null; }

function packIpLiteral(s) {
  if (isIPv4(s)) {
    var parts = _splitOn(s, "."), buf = _bufferAlloc(4), i;
    for (i = 0; i < 4; i += 1) buf[i] = _Number(parts[i]);
    return buf;
  }
  var hex = expandIpv6Hex(s);
  return hex === null ? null : _bufferFrom(hex, "hex");
}

module.exports = { isIPv4: isIPv4, expandIpv6Hex: expandIpv6Hex, isIpLiteral: isIpLiteral, packIpLiteral: packIpLiteral };
