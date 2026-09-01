// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("attrcert-verify", frameworkError.AttrCertError, "attrcert/bad-input");

function verifyAcSignature(ac, spkiBytes) {
  return _seam.verify(ac.signatureAlgorithm, ac.signatureValue, spkiBytes, ac.tbsBytes);
}

module.exports = { setEngine: _seam.setEngine, verifyAcSignature: verifyAcSignature };
