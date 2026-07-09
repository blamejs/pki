// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.smime (RFC 5035 ESS + RFC 8551 SMIMECapabilities).
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: parsing hostile bytes
 * either succeeds or throws a pki.errors.PkiError — any other throw (or a hang)
 * is a finding and is rethrown so the fuzzer records a reproducer. Exercises the
 * three signed-attribute value decoders (the ESSCertID / ESSCertIDv2 DEFAULT
 * disambiguation, the IssuerSerial GeneralNames validation, the ordered
 * capability list) and the OID-dispatch entry.
 */
var pki = require("..");

var DECODERS = [
  pki.schema.smime.parseSigningCertificate,
  pki.schema.smime.parseSigningCertificateV2,
  pki.schema.smime.parseSmimeCapabilities,
];

module.exports.fuzz = function (data) {
  for (var i = 0; i < DECODERS.length; i++) {
    try { DECODERS[i](data); }
    catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }
  }
  try { pki.schema.smime.decodeAttribute({ type: pki.oid.byName("signingCertificateV2"), values: [data] }); }
  catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }
};
