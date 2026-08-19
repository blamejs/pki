// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the single PKCS#10 proof-of-possession signature seam for an INBOUND request, shared
// by pki.csr.verify and by every enrollment path that accepts one, so all of them route through one
// signature engine and no second, weaker verifier of untrusted requests can drift. The producing
// side runs its own check over what it just signed (pki-build's assertSignatureVerifies, called
// from csr-sign), which is a different question about a key the caller already controls. The slot,
// the wiring assertion and the octet-alignment refusal are the shared seam (lib/verify-seam.js). It
// is not wired into index.js and is reached only by require.

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("csr-verify", frameworkError.CsrError, "csr/bad-input");

// Verify a parsed certification request's signature over its exact certificationRequestInfo bytes
// under the subjectPKInfo the request carries. A CSR has no issuer: the verifying key is the one
// inside the signed preimage, which is what makes the signature a proof of possession and nothing
// more.
function verifyCsrSignature(parsed) {
  return _seam.verify(parsed.signatureAlgorithm, parsed.signatureValue,
    parsed.subjectPublicKeyInfo.bytes, parsed.certificationRequestInfoBytes);
}

module.exports = { setEngine: _seam.setEngine, verifyCsrSignature: verifyCsrSignature };
