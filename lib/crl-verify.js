// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the single CRL signature-verify seam, shared by pki.path.crlChecker and pki.crl.verify
// so both route through one signature engine (algorithm-confusion + EdDSA low-order + composite
// gates) and no second, weaker CRL verifier can drift. The slot, the wiring assertion and the
// octet-alignment refusal are the shared seam (lib/verify-seam.js). The seam lives in this internal
// module, not on path-validate's module.exports, which keeps it off the public pki.path surface: it
// takes the path-internal SubjectPublicKeyInfo bytes, not a documented issuer shape. It is not
// wired into index.js and is reached only by require.

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("crl-verify", frameworkError.CrlError, "crl/bad-input");

// Verify a parsed CRL's signature over its raw tbsCertList bytes under the issuer
// SubjectPublicKeyInfo DER.
function verifyCrlSignature(crl, spkiBytes) {
  return _seam.verify(crl.signatureAlgorithm, crl.signatureValue, spkiBytes, crl.tbsBytes);
}

module.exports = { setEngine: _seam.setEngine, verifyCrlSignature: verifyCrlSignature };
