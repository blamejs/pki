// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the ONE CRL signature-verify seam, shared by pki.path.crlChecker and pki.crl.verify so both
// route through the SAME signature engine (algorithm-confusion + EdDSA low-order + composite gates) and no
// second, weaker CRL verifier can drift. path-validate owns that engine (_verifyWithSpki) and injects it
// here at its module load (setEngine). Keeping the seam in this internal module -- rather than on
// path-validate's module.exports -- keeps it OFF the public pki.path surface (it takes the path-internal
// SubjectPublicKeyInfo bytes, not a documented issuer shape). NOT wired into index.js; reached only by require.

var guard = require("./guard-all");

var _engine = null;   // path-validate's _verifyWithSpki, injected at path-validate's module load via setEngine.

function setEngine(verifyWithSpki) { _engine = verifyWithSpki; }

// Verify a parsed CRL's signature over its raw tbsCertList bytes under the issuer SubjectPublicKeyInfo DER.
// Fail-closed to false on a non-octet-aligned signature or any engine fault (the engine never throws out).
function verifyCrlSignature(crl, spkiBytes) {
  // _engine is injected by path-validate at its module load (setEngine); pki.crl.sign requires path-validate
  // for exactly that side-effect, so the engine is always set before a verify runs.
  if (!guard.crypto.isOctetAligned(crl.signatureValue)) return Promise.resolve(false);   // non-octet-aligned signature
  return _engine(crl.signatureAlgorithm, crl.signatureValue.bytes, spkiBytes, crl.tbsBytes);
}

module.exports = { setEngine: setEngine, verifyCrlSignature: verifyCrlSignature };
