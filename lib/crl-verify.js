// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("crl-verify", frameworkError.CrlError, "crl/bad-input");

function verifyCrlSignature(crl, spkiBytes) {
  return _seam.verify(crl.signatureAlgorithm, crl.signatureValue, spkiBytes, crl.tbsBytes);
}

module.exports = { setEngine: _seam.setEngine, verifyCrlSignature: verifyCrlSignature };
