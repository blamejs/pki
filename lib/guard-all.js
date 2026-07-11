// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. This is lib composition only; the
// documented surface is the primitives whose boundaries compose these guards.
//
// guard-all -- the guard-family orchestrator (schema-all's role for the guard
// family). It assembles the per-shape fail-closed guards into one namespaced
// surface every input boundary composes, so a boundary depends on the family
// rather than re-implementing a guard inline:
//
//   guard.bytes.view / .source        -- untrusted byte-source -> Buffer re-view
//                                         (detached-buffer fail-open defence)
//   guard.text.decode                 -- byte-source -> string, cap BEFORE copy
//                                         (parser-DoS string-allocation defence)
//   guard.limits.cap / .depthCap      -- config-time resource-cap validation
//                                         (recursion / allocation DoS defence)
//   guard.crypto.constantTimeEqual    -- length-checked constant-time compare
//                                         (timing side-channel defence)
//   guard.range.int / .uint31 / .positiveInt31
//                                     -- bound a decoded integer before narrowing
//                                        to Number (silent-narrowing defence)
//   guard.name.dnEqual / .rdnEqual / .assertNoControlBytes / .assertPrintableIa5
//                                     -- canonical DN identity + name-string integrity
//                                        (CVE-2009-2408 truncation / identity defence)
//   guard.encoding.base64url / .base64 / .hex
//                                     -- strict textual-encoding decode, canonical
//                                        + capped (encoding-malleability defence)
//   guard.identifier.assertCanonicalOid
//                                     -- canonical dotted-decimal OID string form
//                                        (canonicalization-divergence defence)
//
// Each shape is enforced by a codebase-patterns detector: the characteristic
// token of a guard (the Buffer.from(x.buffer, byteOffset) re-view, the
// timingSafeEqual call, the MAX_DECODE_DEPTH_CEILING check) must appear ONLY in
// its guard module, so a new boundary cannot re-inline the shape and forget the
// defence.

var bytes  = require("./guard-bytes");
var text   = require("./guard-text");
var limits = require("./guard-limits");
var crypto = require("./guard-crypto");
var range  = require("./guard-range");
var name   = require("./guard-name");
var encoding = require("./guard-encoding");
var json   = require("./guard-json");
var identifier = require("./guard-identifier");

module.exports = {
  bytes:  bytes,
  text:   text,
  limits: limits,
  crypto: crypto,
  range:  range,
  name:   name,
  encoding: encoding,
  json:   json,
  identifier: identifier,
};
