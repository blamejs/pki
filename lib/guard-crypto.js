// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var nodeCrypto = require("node:crypto");
var _freeze = require("./guard-intrinsic").freeze;

// @enforced-by guard-shape-reinlined
// @guard-shape \.timingSafeEqual\s*\(
function constantTimeEqual(a, b) {
  return a.length === b.length && nodeCrypto.timingSafeEqual(a, b);
}

// @enforced-by behavioral -- shares the octet-alignment rule below; a bare
function isOctetAligned(bitString) {
  return !!bitString && bitString.unusedBits === 0;
}

// @enforced-by behavioral -- .unusedBits !== 0 is a per-field RFC rule, and the
function assertOctetAligned(bitString, E, code, label) {
  if (!isOctetAligned(bitString)) {
    throw E(code, (label || "signature") + " BIT STRING must be octet-aligned (0 unused bits)");
  }
  return bitString;
}

module.exports = _freeze({ constantTimeEqual: constantTimeEqual, isOctetAligned: isOctetAligned, assertOctetAligned: assertOctetAligned });
