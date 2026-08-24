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

// Every operation this parser makes a decision on is captured at load, because packIpLiteral now
// gates a GeneralName FORM decision (iPAddress vs dNSName): co-resident code that replaced
// RegExp.prototype.test or String.prototype.split AFTER load could otherwise make a hostname parse
// as an address and be emitted as an iPAddress the caller never requested. Reading them live would
// hand that decision to whoever last touched the prototype.
var intrinsic = require("./guard-intrinsic");
// RegExp matching goes through the captured builtin RegExp.prototype.exec, NEVER through String.match /
// RegExp.prototype.test: both of those re-dispatch at call time through the regex's own `exec` and the
// `[Symbol.match]` protocol hook, which co-resident code can replace after load to fabricate a match
// (e.g. return capture groups making a hostname read as a dual-stack IPv6). exec is the terminal
// primitive that reads internal slots directly, so a captured reference is not re-dispatchable.
var _exec = intrinsic.uncurry(RegExp.prototype.exec);
var _split = intrinsic.uncurry(String.prototype.split);
var _padStart = intrinsic.uncurry(String.prototype.padStart);
var _map = intrinsic.map;
var _concat = intrinsic.concat;
var _toLowerCase = intrinsic.toLowerCase;
var _indexOf = intrinsic.stringIndexOf;
var _numToString = intrinsic.numberToString;
var _bufferFrom = intrinsic.bufferFrom;
var _Number = intrinsic.Number;

// Strict RFC 791 dotted-quad: four 0-255 octets. Anchored + per-octet repeat-capped (no
// ReDoS on unbounded input).
var IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
var DUAL_RE = /^(.*):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;
var HEXGROUP_RE = /^[0-9a-f]+$/i;
function isIPv4(s) { return typeof s === "string" && _exec(IPV4_RE, s) !== null; }

// Expand an IPv6 textual address to its 32-hex-character form, or null on any parse failure
// (bad hex group, group count != 8, more than one "::", an over-length group). Accepts the
// IPv4-mapped / dual-stack ".d.d.d.d" tail.
var IPV6_TEXT_MAX_LEN = 45;   // 8 groups x4 hex + 7 colons + a dotted-quad tail headroom
function expandIpv6Hex(ip) {
  if (typeof ip !== "string" || ip.length > IPV6_TEXT_MAX_LEN || _indexOf(ip, ":") === -1) return null;
  // RFC 4291 sec. 2.5.5.2 IPv4-mapped / dual-stack: fold a trailing dotted-quad into two
  // 16-bit hex groups before the pure-hex parse.
  var dual = _exec(DUAL_RE, ip);
  if (dual) {
    if (!isIPv4(dual[2])) return null;
    var v4 = _map(_split(dual[2], "."), _Number);
    ip = dual[1] + ":" + _numToString((v4[0] << 8) | v4[1], 16) + ":" + _numToString((v4[2] << 8) | v4[3], 16);
  }
  var dbl = _split(ip, "::");
  if (dbl.length > 2) return null;
  var left = dbl[0] === "" ? [] : _split(dbl[0], ":");
  var right = dbl.length === 2 ? (dbl[1] === "" ? [] : _split(dbl[1], ":")) : [];
  if (dbl.length === 1 && left.length !== 8) return null;
  var fill = 8 - left.length - right.length;
  // A "::" run MUST compress at least one zero group (RFC 4291 sec. 2.2 / RFC 5952 sec.
  // 4.2.2): a "::" with fill 0 is a full 8-group address that must not use compression.
  if (dbl.length === 2 ? fill < 1 : fill !== 0) return null;
  var groups = left, i;
  for (i = 0; i < fill; i += 1) groups = _concat(groups, ["0"]);
  groups = _concat(groups, right);
  if (groups.length !== 8) return null;
  var hex = "";
  for (i = 0; i < 8; i += 1) {
    var g = groups[i];
    if (g.length < 1 || g.length > 4 || _exec(HEXGROUP_RE, g) === null) return null;
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
  if (isIPv4(s)) return _bufferFrom(_map(_split(s, "."), _Number));   // each octet already range-checked by IPV4_RE
  var hex = expandIpv6Hex(s);
  return hex === null ? null : _bufferFrom(hex, "hex");
}

module.exports = { isIPv4: isIPv4, expandIpv6Hex: expandIpv6Hex, isIpLiteral: isIpLiteral, packIpLiteral: packIpLiteral, IPV4_RE: IPV4_RE };
