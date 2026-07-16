// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.schema.c509.parse (draft-ietf-cose-cbor-encoded-cert).
 *
 * libFuzzer / jazzer.js harness. parse routes hostile bytes through the shipped deterministic-CBOR
 * decoder (bounded size/depth/item caps), reads the 11 unwrapped fields (~biguint / ~time / ~oid, the
 * tag-48 MAC, the int/oid algorithm + attribute + extension registries, the keyUsage int-shortcut), and
 * for a type-3 certificate reconstructs the original DER byte-for-byte -- de-compressing a 0xFE/0xFD EC
 * point (via the crypto engine) and re-emitting every field as canonical DER. Every byte is attacker-
 * controlled; the CBOR caps guarantee a malicious document cannot OOM the harness (an oversized / deep
 * input is a caught cbor/too-large / cbor/too-deep, not a hang), and an off-curve point or an
 * unreconstructable field is a caught c509/non-invertible, not an engine crash.
 *
 * Contract: parsing attacker-controlled bytes has exactly two acceptable outcomes -- a resolved result,
 * or a thrown `pki.errors.PkiError` (C509Error / CborError / Asn1Error / OidError). Any other throw
 * (RangeError, a bare TypeError, a stack overflow, an OOM, a hang) is an unguarded invariant break --
 * rethrow so jazzer records the reproducer.
 */

var pki = require("..");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = function (data) {
  var buf = Buffer.from(data);
  try {
    pki.schema.c509.parse(buf);
  } catch (e) { if (!isPki(e)) throw e; }
};
