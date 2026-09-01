// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("ocsp-request-verify", frameworkError.OcspError, "ocsp/bad-input");

function verifyRequestSignature(signatureAlgorithm, signature, signerSpkiBytes, tbsRequestBytes) {
  return _seam.verify(signatureAlgorithm, signature, signerSpkiBytes, tbsRequestBytes);
}

module.exports = { setEngine: _seam.setEngine, verifyRequestSignature: verifyRequestSignature };
