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

module.exports = {
  bytes:  bytes,
  text:   text,
  limits: limits,
  crypto: crypto,
};
