// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.ct.parseLogList (RFC 6962 sec. 3.2 + the CT log-list v3 JSON schema).
 *
 * libFuzzer / jazzer.js harness. parseLogList routes hostile bytes through the bounded, duplicate-
 * member-rejecting JSON reader, then base64-decodes each log key, recomputes SHA-256(SPKI) and binds it
 * to the stated log_id, validates the SPKI profile, and decodes the state / temporal-interval / RFC 3339
 * dates -- every byte of which is attacker-controlled. The guard.json byte + depth caps guarantee a
 * malicious document cannot OOM the harness (an oversized / deep input is a caught ct/too-large /
 * ct/too-deep, not a hang).
 *
 * Contract: parsing attacker-controlled bytes has exactly two acceptable outcomes -- a resolved result,
 * or a thrown `pki.errors.PkiError` (CtError / OidError / Asn1Error). Any other throw (RangeError, a bare
 * TypeError, a stack overflow, an OOM, a hang) is an unguarded invariant break -- rethrow so jazzer
 * records the reproducer.
 */

var pki = require("..");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = function (data) {
  var buf = Buffer.from(data);
  try {
    pki.ct.parseLogList(buf);
  } catch (e) { if (!isPki(e)) throw e; }
};
