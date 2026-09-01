// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var guard = require("./guard-all");

function makeSeam(name, ErrorClass, code) {
  var engine = null;

  return {
    setEngine: function (verifyWithSpki) { engine = verifyWithSpki; },

    verify: function (sigAlg, signature, spkiBytes, preimage) {
      if (engine == null) {
        throw new ErrorClass(code, "the " + name + " signature engine is not initialized (require pki before use)");
      }
      if (!guard.crypto.isOctetAligned(signature)) return Promise.resolve(false);
      return engine(sigAlg, signature.bytes, spkiBytes, preimage);
    },
  };
}

module.exports = { makeSeam: makeSeam };
