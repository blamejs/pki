// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. Textual IP-literal validation, shared so a
// consumer (pki.lint's commonName-in-SAN check today; a future SAN iPAddress / name-
// constraint surface) does not hand-roll a partial regex that misses a valid IPv6 form.
//
// The IPv4 grammar is strict per-octet 0-255 (RFC 791); the IPv6 parser follows RFC 4291
// sec. 2.2 (8 groups of 1-4 hex, one "::" run compressing a contiguous zero run) plus the
// RFC 4291 sec. 2.5.5.2 / RFC 5952 sec. 5 IPv4-mapped + dual-stack "::ffff:1.2.3.4" tail.
// This mirrors the vetted validation in the sibling blamejs framework (lib/ip-utils.js);
// this toolkit keeps its own copy rather than take a runtime dependency (Hard rule #1).

// Strict RFC 791 dotted-quad: four 0-255 octets. Anchored + per-octet repeat-capped (no
// ReDoS on unbounded input).
var IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
function isIPv4(s) { return typeof s === "string" && IPV4_RE.test(s); }

// Expand an IPv6 textual address to its 32-hex-character form, or null on any parse failure
// (bad hex group, group count != 8, more than one "::", an over-length group). Accepts the
// IPv4-mapped / dual-stack ".d.d.d.d" tail.
var IPV6_TEXT_MAX_LEN = 45;   // 8 groups x4 hex + 7 colons + a dotted-quad tail headroom
function expandIpv6Hex(ip) {
  if (typeof ip !== "string" || ip.length > IPV6_TEXT_MAX_LEN || ip.indexOf(":") === -1) return null;
  // RFC 4291 sec. 2.5.5.2 IPv4-mapped / dual-stack: fold a trailing dotted-quad into two
  // 16-bit hex groups before the pure-hex parse.
  var dual = ip.match(/^(.*):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dual) {
    if (!isIPv4(dual[2])) return null;
    var v4 = dual[2].split(".").map(Number);
    ip = dual[1] + ":" + (((v4[0] << 8) | v4[1]).toString(16)) + ":" + (((v4[2] << 8) | v4[3]).toString(16));
  }
  var dbl = ip.split("::");
  if (dbl.length > 2) return null;
  var left = dbl[0] === "" ? [] : dbl[0].split(":");
  var right = dbl.length === 2 ? (dbl[1] === "" ? [] : dbl[1].split(":")) : [];
  if (dbl.length === 1 && left.length !== 8) return null;
  var fill = 8 - left.length - right.length;
  // A "::" run MUST compress at least one zero group (RFC 4291 sec. 2.2 / RFC 5952 sec.
  // 4.2.2): a "::" with fill 0 is a full 8-group address that must not use compression.
  if (dbl.length === 2 ? fill < 1 : fill !== 0) return null;
  var groups = left, i;
  for (i = 0; i < fill; i += 1) groups = groups.concat(["0"]);
  groups = groups.concat(right);
  if (groups.length !== 8) return null;
  var hex = "";
  for (i = 0; i < 8; i += 1) {
    var g = groups[i];
    if (g.length < 1 || g.length > 4 || !/^[0-9a-f]+$/i.test(g)) return null;
    hex += g.toLowerCase().padStart(4, "0");
  }
  return hex;
}

// Is `s` a syntactically valid IPv4 or IPv6 textual literal?
function isIpLiteral(s) { return isIPv4(s) || expandIpv6Hex(s) !== null; }

module.exports = { isIPv4: isIPv4, expandIpv6Hex: expandIpv6Hex, isIpLiteral: isIpLiteral, IPV4_RE: IPV4_RE };
