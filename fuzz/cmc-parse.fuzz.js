// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.cmc.parse
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: parsing hostile bytes
 * either succeeds or throws a pki.errors.PkiError (CmcError / CmsError /
 * Asn1Error / OidError / PemError) -- any other throw (a RangeError, a bare
 * TypeError, a hang) is a finding and is rethrown so the fuzzer records a
 * reproducer.
 *
 * The interesting surface here is everything the CMS layer hands on: the
 * eContentType dispatch, the four/three-field body arity, whole-message
 * BodyPartID uniqueness and its 0..4294967295 narrow, the TaggedRequest arm
 * tags, and above all the OtherStatusInfo CHOICE -- whose `pendInfo` and
 * `extendedFailInfo` arms are BOTH untagged SEQUENCEs in the RFC 5272 / 6402
 * 1988 module and are told apart only by their first element's tag. That
 * disambiguation reads a child that a malformed message may not have, which is
 * exactly the shape a fuzzer should be pushing on.
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  try {
    pki.schema.cmc.parse(data);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
};
