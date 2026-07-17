// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: C509 certificate encoding via pki.schema.c509.encode.
 *
 * The hostile surface is the ENCODER over an arbitrary parsed C509 structure. Any bytes the strict
 * deterministic-CBOR C509 parser accepts must, when re-emitted, produce a C509 the same parser accepts:
 * for ANY input, encode(parse(bytes)) MUST either throw a typed pki.errors.PkiError or produce bytes that
 * round-trip through pki.schema.c509.parse. A non-PkiError throw or an emission the producer's own strict
 * parser rejects is an unguarded invariant break; either is a finding, so it propagates for jazzer.
 */

var pki = require("..");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = function (data) {
  var d = Buffer.from(data);
  var parsed;
  try { parsed = pki.schema.c509.parse(d); }
  catch (e) { if (isPki(e)) return; throw e; }
  // parse succeeded: re-emit the parsed structure, then it MUST re-parse (any non-PkiError throw is a finding).
  var encoded;
  try { encoded = pki.schema.c509.encode(parsed); }
  catch (e) { if (isPki(e)) return; throw e; }
  pki.schema.c509.parse(encoded);
};
