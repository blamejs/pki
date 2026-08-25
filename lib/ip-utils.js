// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. Textual IP-literal validation, shared so a
// consumer (pki.lint's commonName-in-SAN check today; the SAN iPAddress GeneralName shorthand
// and name-constraint surfaces) does not hand-roll a partial regex that misses a valid IPv6 form.
//
// The IPv4 grammar is strict per-octet 0-255 (RFC 791); the IPv6 parser follows RFC 4291
// sec. 2.2 (8 groups of 1-4 hex, one "::" run compressing a contiguous zero run) plus the
// RFC 4291 sec. 2.5.5.2 / RFC 5952 sec. 5 IPv4-mapped + dual-stack "::ffff:1.2.3.4" tail.
// This mirrors the vetted validation in the sibling blamejs framework (lib/ip-utils.js);
// this toolkit keeps its own copy, since Hard rule #1 rules out a runtime dependency.

// This parser uses no regular expression. packIpLiteral gates a GeneralName form decision (iPAddress
// vs dNSName), and a regex is matched through a live, replaceable protocol -- RegExp.prototype.exec /
// test and String.prototype.match / split consult the regex's own `exec` and the `[Symbol.match]` /
// `[Symbol.split]` hooks, and RegExp.prototype.compile can mutate a pattern in place -- so co-resident
// code could steer the decision after load. Instead every byte is read directly through captured string
// primitives, and separation on a literal is done by scanning with captured indexOf/slice, so nothing the
// decision rests on is re-dispatchable.
var intrinsic = require("./guard-intrinsic");
var _slice = intrinsic.uncurry(String.prototype.slice);
var _padStart = intrinsic.uncurry(String.prototype.padStart);
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _lastIndexOf = intrinsic.uncurry(String.prototype.lastIndexOf);
var _toLowerCase = intrinsic.toLowerCase;
var _indexOf = intrinsic.stringIndexOf;
// Array results are built with indexed assignment, never Array.prototype.map / concat: those consult
// `Array[Symbol.species]` at call time (ArraySpeciesCreate), and a hostile species constructor could return
// a Proxy that rewrites the mapped octet values -- steering packIpLiteral to emit an attacker-chosen address.
// Split on a literal string separator without String.prototype.split, which consults the separator's
// `[Symbol.split]` and so is (in principle) steerable; this scans with captured indexOf/slice only.
function _splitOn(str, sep) {
  var out = [], from = 0, at;
  while ((at = _indexOf(str, sep, from)) !== -1) { out[out.length] = _slice(str, from, at); from = at + sep.length; }
  out[out.length] = _slice(str, from);
  return out;
}
var _numToString = intrinsic.numberToString;
var _bufferFrom = intrinsic.bufferFrom;
var _Number = intrinsic.Number;
// Convert each string in `arr` to its Number, building the result with indexed assignment (no
// Array.prototype.map, so no Symbol.species protocol runs on the octet values).
function _numArray(arr) {
  var out = [], i;
  for (i = 0; i < arr.length; i += 1) out[out.length] = _Number(arr[i]);
  return out;
}

function _isDigitCode(c) { return c >= 48 && c <= 57; }                                      // 0-9
function _isHexCode(c) { return (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70); }

// A strict RFC 791 dotted-quad octet: 1-3 digits, value 0-255, no leading zero beyond "0" itself.
function _isOctet(p) {
  var n = p.length, i, c;
  if (n < 1 || n > 3) return false;
  for (i = 0; i < n; i += 1) { c = _charCodeAt(p, i); if (!_isDigitCode(c)) return false; }
  if (n > 1 && _charCodeAt(p, 0) === 48) return false;   // a leading zero is not the canonical form
  return _Number(p) <= 255;
}

// Strict RFC 791 dotted quad: four 0-255 octets, nothing else.
function isIPv4(s) {
  if (typeof s !== "string") return false;
  var parts = _splitOn(s, ".");
  if (parts.length !== 4) return false;
  for (var i = 0; i < 4; i += 1) { if (!_isOctet(parts[i])) return false; }
  return true;
}

// A single 1-4 hex-digit IPv6 group.
function _isHexGroup(g) {
  var n = g.length, i;
  if (n < 1 || n > 4) return false;
  for (i = 0; i < n; i += 1) { if (!_isHexCode(_charCodeAt(g, i))) return false; }
  return true;
}

// The RFC 4291 sec. 2.5.5.2 dual-stack tail SHAPE: exactly four 1-3 digit groups joined by dots. Validity
// (0-255 per octet) is a separate isIPv4 check, matching the historical two-step (shape then value).
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

// Expand an IPv6 textual address to its 32-hex-character form, or null on any parse failure
// (bad hex group, group count != 8, more than one "::", an over-length group). Accepts the
// IPv4-mapped / dual-stack ".d.d.d.d" tail.
var IPV6_TEXT_MAX_LEN = 45;   // 8 groups x4 hex + 7 colons + a dotted-quad tail headroom
function expandIpv6Hex(ip) {
  if (typeof ip !== "string" || ip.length > IPV6_TEXT_MAX_LEN || _indexOf(ip, ":") === -1) return null;
  // RFC 4291 sec. 2.5.5.2 IPv4-mapped / dual-stack: fold a trailing dotted-quad (the suffix after the
  // last colon, when it carries a dot) into two 16-bit hex groups before the pure-hex parse.
  var lastColon = _lastIndexOf(ip, ":");
  var tail = _slice(ip, lastColon + 1);
  if (_indexOf(tail, ".") !== -1) {
    if (!_isDottedQuadShape(tail) || !isIPv4(tail)) return null;
    var v4 = _numArray(_splitOn(tail, "."));
    ip = _slice(ip, 0, lastColon) + ":" + _numToString((v4[0] << 8) | v4[1], 16) + ":" + _numToString((v4[2] << 8) | v4[3], 16);
  }
  var dbl = _splitOn(ip, "::");
  if (dbl.length > 2) return null;
  var left = dbl[0] === "" ? [] : _splitOn(dbl[0], ":");
  var right = dbl.length === 2 ? (dbl[1] === "" ? [] : _splitOn(dbl[1], ":")) : [];
  if (dbl.length === 1 && left.length !== 8) return null;
  var fill = 8 - left.length - right.length;
  // A "::" run MUST compress at least one zero group (RFC 4291 sec. 2.2 / RFC 5952 sec.
  // 4.2.2): a "::" with fill 0 is a full 8-group address that must not use compression.
  if (dbl.length === 2 ? fill < 1 : fill !== 0) return null;
  var groups = left, i;   // `left` is a fresh array we own; append by index (no species-aware concat)
  for (i = 0; i < fill; i += 1) groups[groups.length] = "0";
  for (i = 0; i < right.length; i += 1) groups[groups.length] = right[i];
  if (groups.length !== 8) return null;
  var hex = "";
  for (i = 0; i < 8; i += 1) {
    var g = groups[i];
    if (!_isHexGroup(g)) return null;
    hex += _padStart(_toLowerCase(g), 4, "0");
  }
  return hex;
}

// Is `s` a syntactically valid IPv4 or IPv6 textual literal?
function isIpLiteral(s) { return isIPv4(s) || expandIpv6Hex(s) !== null; }

// Pack an IPv4/IPv6 textual literal to its network-order octets (4 for IPv4, 16 for IPv6),
// or null when `s` is not a valid literal. The binary inverse of the textual forms isIPv4 /
// expandIpv6Hex validate, so a SAN/GeneralName iPAddress (RFC 5280 sec. 4.2.1.6, always a bare
// host address of 4 or 16 octets) can be given as a string instead of a pre-packed Buffer.
function packIpLiteral(s) {
  if (isIPv4(s)) return _bufferFrom(_numArray(_splitOn(s, ".")));   // each octet already range-checked by _isOctet
  var hex = expandIpv6Hex(s);
  return hex === null ? null : _bufferFrom(hex, "hex");
}

module.exports = { isIPv4: isIPv4, expandIpv6Hex: expandIpv6Hex, isIpLiteral: isIpLiteral, packIpLiteral: packIpLiteral };
