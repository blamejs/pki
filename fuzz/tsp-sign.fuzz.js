// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 3161 timestamp token creation via pki.tsp.sign.
 *
 * The hostile surface is the TSTInfo + CMS encoder over an attacker-controlled message imprint:
 * pki.tsp.sign({ hashAlgorithm, hashedMessage: fuzzBytes }, tsa, opts) must either produce a
 * TimeStampToken that round-trips through pki.cms.verify (valid === true) AND decodes through
 * pki.schema.tsp.parseToken, or throw a typed pki.errors.PkiError. A TSA certificate + key are
 * built once; the fuzzer drives the imprint bytes.
 *
 * Contract: any other outcome -- a non-PkiError throw, an output that does not verify, or one
 * that does not parse -- is a finding; rethrow so jazzer records the reproducer.
 */

var pki = require("..");
var TSA = require("../test/helpers/signing").makeSigner("ec-p256");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var imprint = { hashAlgorithm: "sha256", hashedMessage: Buffer.from(data) };
  try {
    var token = await pki.tsp.sign(imprint, TSA, { policy: "1.3.6.1.4.1.1", serialNumber: 1, nonce: 7 });
    var v = await pki.cms.verify(token);
    if (v.valid !== true) throw new Error("tsp.sign output did not verify");
    pki.schema.tsp.parseToken(token);   // must decode as a well-formed TimeStampToken
  } catch (e) { if (!isPki(e)) throw e; }
};
