// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the injected-signature-engine seam, once.
//
// A CRL, a PKCS#10 certification request and an RFC 4211 CertReqMsg all verify an untrusted
// signature through the same path-validation engine, which carries the algorithm-confusion, EdDSA
// low-order and composite gates. None of them may reach that engine through pki.path's public
// surface, so each holds a slot that path-validate fills at its module load. Each was writing the
// same slot, the same wiring assertion and the same octet-alignment refusal. That shape lives here
// now. A format module supplies what is its own: an error class, a code, and the preimage bytes.
//
// The producing side of each format asks a different question, through pki-build's
// assertSignatureVerifies: whether the signature it has just made verifies under a key the caller
// already controls. That check waives the EdDSA low-order-point gate for that reason, and is a
// separate mechanism from this one.

var guard = require("./guard-all");

// makeSeam(name, ErrorClass, code) -> { setEngine, verify }.
//
// `verify(sigAlg, signature, spkiBytes, preimage)` takes the signature as the parsed BIT STRING
// ({ unusedBits, bytes }), because the octet-alignment refusal is part of the contract: a signature
// carrying unused bits is malformed for every algorithm these formats admit, and a caller that had
// already discarded `unusedBits` could not be held to it.
function makeSeam(name, ErrorClass, code) {
  var engine = null;

  return {
    setEngine: function (verifyWithSpki) { engine = verifyWithSpki; },

    verify: function (sigAlg, signature, spkiBytes, preimage) {
      // Each format's producing verb requires path-validate for the injection side-effect, so the
      // engine is set on every route that reaches here through a public verb. A future internal
      // consumer that required a seam without it would otherwise call null and surface a raw
      // TypeError out of a verify, which names neither the defect nor a verdict.
      if (engine == null) {
        throw new ErrorClass(code, "the " + name + " signature engine is not initialized (require pki before use)");
      }
      if (!guard.crypto.isOctetAligned(signature)) return Promise.resolve(false);
      return engine(sigAlg, signature.bytes, spkiBytes, preimage);
    },
  };
}

module.exports = { makeSeam: makeSeam };
