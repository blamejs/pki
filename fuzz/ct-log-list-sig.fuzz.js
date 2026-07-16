// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.ct.verifyLogListSignature (the CT log-list detached-signature verifier).
 *
 * libFuzzer / jazzer.js harness. The verifier decodes the caller-pinned SubjectPublicKeyInfo (`_spkiAlg`'s
 * bounded ASN.1 decode + the RSA e>=3 / >=2048 gate), routes an ECDSA signature through the strict DER
 * Sig-Value conformance gate, and verifies via WebCrypto -- every one of the three inputs (the SPKI, the
 * signature, the message) is attacker-controlled. The harness rotates the hostile bytes across each path:
 * a hostile SPKI (the decode/import path), a hostile signature against a valid RSA / EC key (the verify +
 * EC-DER-gate path), and all-hostile.
 *
 * Contract: verifying attacker-controlled bytes has exactly two acceptable outcomes -- a resolved boolean,
 * or a thrown `pki.errors.PkiError` (CtError / Asn1Error / OidError). Any other throw (RangeError, a bare
 * TypeError, a stack overflow, a hang) is an unguarded invariant break -- rethrow so jazzer records it.
 */

var pki = require("..");
var crypto = require("crypto");

var RSA_SPKI = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "der", type: "spki" });
var EC_SPKI = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({ format: "der", type: "spki" });
var JSON_FIXED = Buffer.from('{"operators":[]}');

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var buf = Buffer.from(data);
  if (buf.length < 1) return;
  try {
    switch (buf[0] & 3) {
      case 0: await pki.ct.verifyLogListSignature(JSON_FIXED, Buffer.alloc(256), buf); break;   // hostile SPKI
      case 1: await pki.ct.verifyLogListSignature(JSON_FIXED, buf, EC_SPKI); break;              // hostile sig, EC key (the DER gate)
      case 2: await pki.ct.verifyLogListSignature(JSON_FIXED, buf, RSA_SPKI); break;             // hostile sig, RSA key
      default: await pki.ct.verifyLogListSignature(buf, buf, buf); break;                        // all-hostile
    }
  } catch (e) { if (!isPki(e)) throw e; }
};
