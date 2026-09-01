// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("csr-verify", frameworkError.CsrError, "csr/bad-input");

function verifyCsrSignature(parsed) {
  return _seam.verify(parsed.signatureAlgorithm, parsed.signatureValue,
    parsed.subjectPublicKeyInfo.bytes, parsed.certificationRequestInfoBytes);
}

module.exports = { setEngine: _seam.setEngine, verifyCsrSignature: verifyCsrSignature };
