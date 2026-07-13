// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: composite ML-DSA signature verification via pki.path.validate.
 *
 * libFuzzer / jazzer.js harness. The composite verify path (the fixed-offset
 * split of the concatenated public key / signature, the M' reconstruction, the
 * two component imports + verifies, the AND-combination) processes attacker-
 * controlled bytes. This target splices the fuzzer's bytes over the signature /
 * key region of a real composite certificate so the outer TLV structure still
 * parses and the composite combinator runs on hostile component bytes.
 *
 * Contract: validating an attacker-controlled composite certificate has exactly
 * two acceptable outcomes -- a result object (valid true/false), or a thrown
 * `pki.errors.PkiError`. Any other throw (RangeError, a bare TypeError, a hang)
 * is an unguarded invariant break: rethrow so jazzer records the reproducer.
 */

var fs = require("fs");
var path = require("path");
var pki = require("..");

var KAT = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "test", "fixtures", "composite", "kat.json"), "utf8"));
var BASE = Buffer.from(KAT.tests.find(function (t) { return t.tcId === "id-MLDSA65-ECDSA-P256-SHA512"; }).x5c, "base64");
var T = new Date("2030-01-01T00:00:00Z");
function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  if (data.length < 2) return;
  // Overlay the fuzz bytes onto the tail (the concatenated composite signature and
  // the SPKI that precedes it), leaving the outer certificate framing intact.
  var der = Buffer.from(BASE);
  var start = Math.max(0, der.length - data.length);
  data.copy(der, start, 0, Math.min(data.length, der.length - start));
  var cert;
  try { cert = pki.schema.x509.parse(der); }
  catch (e) { if (!isPki(e)) throw e; return; }
  try {
    await pki.path.validate([cert], {
      time: T,
      trustAnchor: { name: cert.subject, publicKey: cert.subjectPublicKeyInfo.bytes, algorithm: cert.subjectPublicKeyInfo.algorithm },
    });
  } catch (e) { if (!isPki(e)) throw e; }
};
