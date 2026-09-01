// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("crmf-verify", frameworkError.CrmfError, "crmf/bad-input");

function verifyPopSignature(popo, spkiBytes, preimage) {
  return _seam.verify(popo.algorithmIdentifier, popo.signature, spkiBytes, preimage);
}

module.exports = { setEngine: _seam.setEngine, verifyPopSignature: verifyPopSignature };
