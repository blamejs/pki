// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the RFC 5755 attribute-certificate signature seam, shared by pki.attrcert.verify and
// by any path that accepts an inbound AC. The slot, the wiring assertion and the octet-alignment
// refusal are the shared seam (lib/verify-seam.js); what is domain-specific is the error class and
// the byte range the signature covers. It is not wired into index.js and is reached only by require.

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("attrcert-verify", frameworkError.AttrCertError, "attrcert/bad-input");

// Verify a parsed attribute certificate's signature over its exact AttributeCertificateInfo bytes
// under the AC issuer's SubjectPublicKeyInfo DER (RFC 5755 sec. 5, item 2).
function verifyAcSignature(ac, spkiBytes) {
  return _seam.verify(ac.signatureAlgorithm, ac.signatureValue, spkiBytes, ac.tbsBytes);
}

module.exports = { setEngine: _seam.setEngine, verifyAcSignature: verifyAcSignature };
