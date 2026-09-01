// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var C = require("./constants");
var _byteLength = require("./guard-intrinsic").byteLength;
var _freeze = require("./guard-intrinsic").freeze;
var _charCodeAt = require("./guard-intrinsic").uncurry(String.prototype.charCodeAt);
var _stringify = require("./guard-intrinsic").stringify;
var _String = require("./guard-intrinsic").String;

// @enforced-by behavioral -- the CR/LF/NUL value reject + the ftext name check have
function assertField(name, value, E, code) {
  if (typeof name !== "string" || name.length === 0) throw new E(code, "a header field name must be a non-empty string");
  for (var i = 0; i < name.length; i++) {
    var nc = _charCodeAt(name, i);
    if (nc < 0x21 || nc > 0x7e || nc === 0x3a) throw new E(code, "a header field name must be RFC 5322 ftext (printable ASCII, no space / ':' / control): " + _stringify(name));
  }
  var v = typeof value === "string" ? value : _String(value);
  for (var j = 0; j < v.length; j++) {
    var vc = _charCodeAt(v, j);
    if (vc === 0x00 || vc === 0x0d || vc === 0x0a) throw new E(code, "a header field value must not contain CR / LF / NUL (header injection) in " + _stringify(name));
  }
  if (_byteLength(name, "utf8") + 2 + _byteLength(v, "utf8") > C.LIMITS.HEADER_LINE_MAX_OCTETS) {
    throw new E(code, "a header field line exceeds RFC 5322's " + C.LIMITS.HEADER_LINE_MAX_OCTETS + "-octet limit: " + _stringify(name));
  }
  return v;
}

module.exports = _freeze({ assertField: assertField });
