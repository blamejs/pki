// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: CMS SignedData signing via pki.cms.sign.
 *
 * The hostile surface is the ENCODER over arbitrary content: pki.cms.sign(fuzzBytes, signer)
 * must, for ANY content, either produce a SignedData that round-trips through pki.cms.verify
 * (valid === true) or throw a typed pki.errors.PkiError. A signer certificate + key are built
 * once; the fuzzer drives the content (and, on alternate runs, the detached path).
 *
 * Contract: any other outcome -- a non-PkiError throw, or an output that does not verify -- is
 * a finding; rethrow so jazzer records the reproducer.
 */

var pki = require("..");
var SIGNER = require("../test/helpers/signing").makeSigner("ec-p256");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var content = Buffer.from(data);
  try {
    if (data.length & 1) {
      var detached = await pki.cms.sign(content, SIGNER, { detached: true });
      var vd = await pki.cms.verify(detached, { content: content });
      if (vd.valid !== true) throw new Error("cms.sign detached output did not verify");
    } else {
      var attached = await pki.cms.sign(content, SIGNER);
      var va = await pki.cms.verify(attached);
      if (va.valid !== true) throw new Error("cms.sign attached output did not verify");
    }
  } catch (e) { if (!isPki(e)) throw e; }
};
