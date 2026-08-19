// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the single PKCS#10 proof-of-possession signature seam for an INBOUND request, shared
// by pki.csr.verify and by every enrollment path that accepts one, so all of them route through one
// signature engine (algorithm-confusion + EdDSA low-order + composite gates) and no second, weaker
// verifier of untrusted requests can drift. The producing side runs its own check over what it just
// signed (pki-build's assertSignatureVerifies, called from csr-sign), which is a different question
// about a key the caller already controls. path-validate owns the engine (_verifyWithSpki) and
// injects it here at its module load (setEngine). The seam lives in this internal module, not on
// path-validate's module.exports, which keeps it off the public pki.path surface. It is not wired
// into index.js and is reached only by require.
//
// It deliberately does NOT compose pki-build's assertSignatureVerifies. That helper is a producing-
// side self-check over a key the caller already controls, and it waives the EdDSA low-order-point
// gate on exactly that reasoning. An inbound request is untrusted input, where the gate is the
// point.

var guard = require("./guard-all");
var frameworkError = require("./framework-error");

var CsrError = frameworkError.CsrError;
var _engine = null;   // path-validate's _verifyWithSpki, injected at path-validate's module load via setEngine.

function setEngine(verifyWithSpki) { _engine = verifyWithSpki; }

// Verify a parsed certification request's signature over its exact certificationRequestInfo bytes
// under the subjectPKInfo the request carries. A CSR has no issuer: the verifying key is the one
// inside the signed preimage, which is what makes the signature a proof of possession and nothing
// more. Fail-closed to false on a non-octet-aligned signature or any engine fault (the engine
// never throws out).
function verifyCsrSignature(parsed) {
  // pki.csr.sign requires path-validate for the injection side-effect, so the engine is set on every
  // route that reaches here through the public verb. A future internal consumer that requires this
  // module without it would otherwise call null and surface a raw TypeError out of a verify, which
  // names neither the defect nor a verdict, so the wiring is asserted rather than assumed.
  if (_engine == null) throw new CsrError("csr/bad-input", "the csr-verify signature engine is not initialized (require pki before use)");
  if (!guard.crypto.isOctetAligned(parsed.signatureValue)) return Promise.resolve(false);   // non-octet-aligned signature
  return _engine(parsed.signatureAlgorithm, parsed.signatureValue.bytes,
    parsed.subjectPublicKeyInfo.bytes, parsed.certificationRequestInfoBytes);
}

module.exports = { setEngine: setEngine, verifyCsrSignature: verifyCsrSignature };
