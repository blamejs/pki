// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var bytes = require("./guard-bytes");
var intrinsic = require("./guard-intrinsic");

var _fill = intrinsic.uncurry(Uint8Array.prototype.fill);
var _concat = intrinsic.bufferConcat;

// @enforced-by guard-shape-reinlined
// @guard-shape \.fill\s*\(\s*0\s*[,)]
function zeroize(value, ErrorClass, code, label) {
  if (value === null || value === undefined) return value;
  var view = bytes.view(value, ErrorClass, code, label);
  _fill(view, 0);
  return value;
}

// @enforced-by behavioral -- this is a loop over zeroize, which carries the family's only
function zeroizeAll(list, ErrorClass, code, label) {
  if (!list) return list;
  for (var i = 0; i < list.length; i++) zeroize(list[i], ErrorClass, code, label);
  return list;
}

// @enforced-by guard-shape-reinlined
// @guard-shape \.update\s*\([\s\S]{0,300}?\)\s*,\s*[A-Za-z_$][\w$]*\s*\.\s*final\s*\(\s*\)
function cipherFinish(transform, input, ErrorClass, code, label) {
  var head = null, tail = null;
  try {
    head = transform.update(input);
    tail = transform.final();
    return _concat([head, tail]);
  } finally {
    zeroize(head, ErrorClass, code, label);
    zeroize(tail, ErrorClass, code, label);
  }
}

module.exports = intrinsic.freeze({ zeroize: zeroize, zeroizeAll: zeroizeAll, cipherFinish: cipherFinish });
