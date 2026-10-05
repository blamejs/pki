// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var guard = require("./guard-all");
var _seamIntrinsic = require("./guard-intrinsic");
/** @internal The refusal below is a RESOLVED promise carrying `false`, and `Promise.resolve` builds
 *  from its RECEIVER. Read from the global binding at the call, that refusal is constructed by whatever
 *  the binding holds, so a replacement settling truthy turns it into an acceptance. */
var _Promise = _seamIntrinsic.Promise;
var _promiseResolve = _seamIntrinsic.uncurry(_seamIntrinsic.promiseResolve);

function makeSeam(name, ErrorClass, code) {
  var engine = null;

  return {
    setEngine: function (verifyWithSpki) { engine = verifyWithSpki; },

    verify: function (sigAlg, signature, spkiBytes, preimage) {
      if (engine == null) {
        throw new ErrorClass(code, "the " + name + " signature engine is not initialized (require pki before use)");
      }
      if (!guard.crypto.isOctetAligned(signature)) return _promiseResolve(_Promise, false);
      return engine(sigAlg, signature.bytes, spkiBytes, preimage);
    },
  };
}

module.exports = { makeSeam: makeSeam };
