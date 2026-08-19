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
// itself, with no guard re-implemented inline:
//
//   guard.bytes.view / .source        -- untrusted byte-source -> Buffer re-view
//                                         (detached-buffer fail-open defense)
//   guard.text.decode                 -- byte-source -> string, cap before copy
//                                         (parser-DoS string-allocation defense)
//   guard.limits.cap / .depthCap      -- config-time resource-cap validation
//                                         (recursion / allocation DoS defense)
//   guard.crypto.constantTimeEqual    -- length-checked constant-time compare
//                                         (timing side-channel defense)
//   guard.range.int / .uint31 / .positiveInt31
//                                     -- bound a decoded integer before narrowing
//                                        to Number (silent-narrowing defense)
//   guard.time.assertValid / .within  -- validate a Date-instant before a temporal
//                                        comparison (NaN-Date fail-open defense)
//   guard.name.dnEqual / .rdnEqual / .assertNoControlBytes / .assertPrintableIa5
//                                     -- canonical DN identity + name-string integrity
//   guard.name.escapeControlBytes / .escapeDnValue
//                                     -- render-side name safety: control-byte + RFC 4514 escaping
//                                        (CVE-2009-2408 truncation / identity defense)
//   guard.encoding.base64url / .base64 / .hex
//                                     -- strict textual-encoding decode, canonical
//                                        + capped (encoding-malleability defense)
//   guard.identifier.assertCanonicalOid
//                                     -- canonical dotted-decimal OID string form
//                                        (canonicalization-divergence defense)
//   guard.compress.bounded            -- decompress an untrusted stream under a hard
//                                        output cap, whole-input (decompression-bomb +
//                                        trailing-frame malleability defense)
//   guard.header.assertField          -- emitted MIME/RFC 5322 header field name +
//                                        value integrity (CR/LF/NUL header-injection
//                                        defense, CWE-93)
//   guard.parsed.accept               -- a CLAIMED-parsed structure carries every
//                                        field the consuming code dereferences
//                                        (type confusion / unverified provenance,
//                                        CWE-843 / CWE-345)
//
// Each shape is enforced by a codebase-patterns detector: the characteristic
// token of a guard (the Buffer.from(x.buffer, byteOffset) re-view, the
// timingSafeEqual call, the MAX_DECODE_DEPTH_CEILING check) must appear only in
// its guard module, so a new boundary cannot re-inline the shape and forget the
// defense.

var bytes  = require("./guard-bytes");
var text   = require("./guard-text");
var limits = require("./guard-limits");
var crypto = require("./guard-crypto");
var range  = require("./guard-range");
var time   = require("./guard-time");
var name   = require("./guard-name");
var encoding = require("./guard-encoding");
var der = require("./guard-der");
var json   = require("./guard-json");
var identifier = require("./guard-identifier");
var header = require("./guard-header");
var compress = require("./guard-compress");
var secret = require("./guard-secret");
var parsed = require("./guard-parsed");
var async_ = require("./guard-async");
var intrinsic = require("./guard-intrinsic");

module.exports = {
  bytes:  bytes,
  text:   text,
  limits: limits,
  crypto: crypto,
  range:  range,
  time:   time,
  name:   name,
  encoding: encoding,
  der:    der,
  json:   json,
  identifier: identifier,
  header: header,
  compress: compress,
  secret: secret,
  parsed: parsed,
  async:  async_,
  intrinsic: intrinsic,
};
