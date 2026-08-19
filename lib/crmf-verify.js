// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the single RFC 4211 proof-of-possession signature seam for an INBOUND CertReqMsg,
// shared by pki.crmf.verifyPop and by every enrollment path that accepts one. The slot, the wiring
// assertion and the octet-alignment refusal are the shared seam (lib/verify-seam.js); what is
// domain-specific is the error class and which bytes the signature covers. It is not wired into
// index.js and is reached only by require.

var frameworkError = require("./framework-error");
var seam = require("./verify-seam");

var _seam = seam.makeSeam("crmf-verify", frameworkError.CrmfError, "crmf/bad-input");

// Verify one CertReqMsg's POPOSigningKey signature over `preimage` under `spkiBytes`.
//
// `preimage` is chosen by the caller from the two the RFC defines, because the choice is a
// conformance rule about the message rather than a property of the signature: the DER of
// poposkInput when that field is present, and the DER of `CertReqMsg certReq` when it is absent
// (RFC 4211 sec. 4.1 and the ASN.1 module on p.33).
function verifyPopSignature(popo, spkiBytes, preimage) {
  return _seam.verify(popo.algorithmIdentifier, popo.signature, spkiBytes, preimage);
}

module.exports = { setEngine: _seam.setEngine, verifyPopSignature: verifyPopSignature };
