// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.csrattrs.parse
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: parsing hostile bytes
 * either succeeds or throws a pki.errors.PkiError (CsrattrsError / Asn1Error /
 * OidError) -- any other throw (a RangeError, a bare TypeError, a hang from the
 * AttrOrOID / template walk) is a finding and is rethrown so the fuzzer records
 * a reproducer. Exercises the RFC 8951 sec. 3.5 SEQUENCE OF AttrOrOID front
 * door, the universal-tag arm dispatch, and the RFC 9908 semantic checks
 * (single id-ExtensionReq, the extension-req / template re-walks).
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.csrattrs.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
