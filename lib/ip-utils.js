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

/** @internal The RFC 5952 sec. 4 textual form of an IPv6 address given as eight group values: each
 * group written in lower-case hexadecimal with no leading zeros, and the longest run of two or more
 * zero groups replaced by `::`. A run of one is written out, which sec. 4.2.2 requires. */
function _ipv6Text(nums) {
  var hex = [], i;
  for (i = 0; i < 8; i += 1) _push(hex, _numToString(nums[i], 16));
  var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (i = 0; i < 8; i += 1) {
    if (nums[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen += 1;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) return _joinOn(hex, 0, 8, ":");
  return _joinOn(hex, 0, bestStart, ":") + "::" + _joinOn(hex, bestStart + bestLen, 8, ":");
}

function _joinOn(list, from, to, sep) {
  var out = "";
  for (var i = from; i < to; i += 1) out += (i > from ? sep : "") + list[i];
  return out;
}

/** @internal The textual address an `iPAddress` entry's octets carry: dotted-quad for four octets
 * and the RFC 5952 form for sixteen. `null` for any other length, because no IP version is defined
 * for one (RFC 9110 sec. 4.3.5). The inverse of `packIpLiteral` for every value it produces. */
function textFromOctets(buf) {
  if (!buf || typeof buf.length !== "number") return null;
  if (buf.length === 4) return buf[0] + "." + buf[1] + "." + buf[2] + "." + buf[3];
  if (buf.length !== 16) return null;
  var nums = [];
  for (var i = 0; i < 16; i += 2) _push(nums, (buf[i] << 8) | buf[i + 1]);
  return _ipv6Text(nums);
}

/** @internal The RFC 5952 canonical form of an IPv6 address written as text, or `null` when the
 * text is not eight groups. A caller comparing its input against the result learns whether the
 * input was already canonical. */
function canonicalizeIpv6(value) {
  if (typeof value !== "string") return null;
  var hex = expandIpv6Hex(value);
  if (hex === null) return null;
  var nums = [];
  for (var i = 0; i < 8; i += 1) _push(nums, _Number("0x" + _slice(hex, i * 4, i * 4 + 4)));
  return _ipv6Text(nums);
}

module.exports = {
  isIPv4: isIPv4, expandIpv6Hex: expandIpv6Hex, isIpLiteral: isIpLiteral, packIpLiteral: packIpLiteral,
  textFromOctets: textFromOctets, canonicalizeIpv6: canonicalizeIpv6,
};
