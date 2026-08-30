// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the single signature seam for an inbound signed OCSPRequest (RFC 6960 sec. 4.1.1),
// composed by pki.ocsp.verifyRequest. It routes the request-signature check through the same
// certification-path signature engine (its EdDSA low-order-point and algorithm-confusion gates
// included) that pki.ocsp.verify uses for a response and pki.crl.verify / pki.cms.verify use for
// theirs, so no second, weaker verifier of an untrusted request can drift. The producing side runs
// its own check over what it just signed (pki.ocsp.buildRequest's signer path); this is the
// different question a responder asks about a request someone else produced. The slot, the wiring
// assertion and the octet-alignment refusal are the shared seam (lib/verify-seam.js). It is not
// wired into index.js and is reached only by require.

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("ocsp-request-verify", frameworkError.OcspError, "ocsp/bad-input");

// Verify a signed OCSPRequest's signature over its exact tbsRequest bytes under the SPKI of the
// requestor certificate the request carries (RFC 6960 sec. 4.1.1). Unlike a CSR there is no
// self-signature: the verifying key is the requestor's, identified to the responder by
// requestorName and proven by the certificate embedded in (or supplied alongside) the request.
function verifyRequestSignature(signatureAlgorithm, signature, signerSpkiBytes, tbsRequestBytes) {
  return _seam.verify(signatureAlgorithm, signature, signerSpkiBytes, tbsRequestBytes);
}

module.exports = { setEngine: _seam.setEngine, verifyRequestSignature: verifyRequestSignature };
