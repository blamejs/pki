// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.acme object validators + identify + parseAriCertId
 *
 * Runs under libFuzzer via jazzer.js; ClusterFuzzLite + OSS-Fuzz consume
 * module.exports.fuzz = function (data). The contract: each call either succeeds
 * or throws a pki.errors.PkiError (AcmeError) -- any other throw (a RangeError
 * from a malformed identifier walk, a TypeError from a hostile nested shape, a
 * hang) is a finding and is rethrown so the fuzzer records a reproducer. The fuzz
 * bytes are parsed with the strict JSON reader, then routed through every RFC 8555
 * / 9773 resource validator, the identify discriminator, the RenewalInfo window
 * check, and the ARI certID parser on attacker-controlled input.
 */
var pki = require("..");

var KINDS = ["directory", "account", "order", "authorization", "challenge", "renewalInfo", "problem"];

module.exports.fuzz = function (data) {
  var s = data.toString("latin1");

  var obj;
  try { obj = pki.jose.parseJson(data); }
  catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; return; }

  if (obj && typeof obj === "object" && !Array.isArray(obj)) {
    for (var i = 0; i < KINDS.length; i++) {
      try { pki.acme.validate(KINDS[i], obj); }
      catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }
    }
    try { pki.acme.identify(obj); }
    catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }
    try { pki.acme.validateRenewalInfo(obj); }
    catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }
  }

  // The ARI certID parser takes a raw string; feed the fuzz bytes directly.
  try { pki.acme.parseAriCertId(s.slice(0, 256)); }
  catch (e) { if (!(e instanceof pki.errors.PkiError)) throw e; }
};
