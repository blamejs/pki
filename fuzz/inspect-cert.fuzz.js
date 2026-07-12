// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.inspect.certificate
 *
 * Runs under libFuzzer via jazzer.js. The contract for the human-readable
 * inspector: rendering attacker-controlled bytes as a certificate report may only
 * ever RETURN a string or THROW a pki.errors.PkiError (InspectError --
 * inspect/bad-input, inspect/bad-certificate -- or the x509/* / asn1/* fault it
 * wraps). Any other throw -- a raw TypeError from an unexpected parsed-field shape
 * the renderer dereferenced, a RangeError, a hang -- is a finding and is rethrown
 * so the fuzzer records a reproducer. The renderer is best-effort: a malformed
 * extension must fall back to a hex dump, never crash the report, so the mutator
 * probes truncated TLVs, odd key/curve shapes, and hostile extension values.
 */
var pki = require("..");

module.exports.fuzz = function (data) {
  // A Buffer is always treated as DER, so this covers the DER / already-parsed path.
  try {
    var out = pki.inspect.certificate(data);
    if (typeof out !== "string") throw new Error("inspect.certificate returned a non-string");
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
  // The same bytes as a string exercise the documented PEM-string path -- x509.pemDecode
  // and malformed-PEM handling -- which the Buffer path never reaches.
  try {
    var out2 = pki.inspect.certificate(data.toString("latin1"));
    if (typeof out2 !== "string") throw new Error("inspect.certificate returned a non-string");
  } catch (e2) {
    if (!(e2 instanceof pki.errors.PkiError)) throw e2;
  }
};
