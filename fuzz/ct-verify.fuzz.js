// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: SCT signature verification via pki.ct.verifySct.
 *
 * libFuzzer / jazzer.js harness. verifySct reconstructs the signed data, reads the log
 * key SPKI, routes an ECDSA signature through the strict DER conformance gate, and verifies
 * through the WebCrypto engine -- all over attacker-controlled bytes (the log key and the
 * SCT signature travel with the certificate). This target overlays the fuzzer's bytes onto
 * the SCT signature and, on alternate runs, the log key SPKI, leaving a valid reconstructed
 * entry so the verify composition runs on hostile crypto inputs.
 *
 * Contract: verifying an attacker-controlled SCT has exactly two acceptable outcomes -- a
 * resolved boolean (true/false), or a thrown/rejected `pki.errors.PkiError`. Any other throw
 * (RangeError, a bare TypeError, a hang) is an unguarded invariant break: rethrow so jazzer
 * records the reproducer.
 */

var crypto = require("crypto");
var pki = require("..");

// A valid entry + EC log key + signed SCT, built once. Each run splices the fuzzer's bytes
// over the signature (and, when long enough, the log key SPKI).
var CERT = pki.schema.x509.pemDecode(require("../test/helpers/vectors").CERT_EC_PEM, "CERTIFICATE");
var LOG = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
var LOG_SPKI = LOG.publicKey.export({ format: "der", type: "spki" });
var ENTRY = { entryType: 0, leafCert: CERT };
var BASE_SCT = { version: 0, timestamp: 1700000000000n, signatureAlgorithm: { hash: 4, hashName: "sha256", signature: 3, signatureName: "ecdsa" }, signature: null, extensions: Buffer.alloc(0) };
BASE_SCT.signature = crypto.sign("sha256", pki.ct.reconstructSignedData(ENTRY, BASE_SCT), LOG.privateKey);

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  if (data.length < 1) return;
  var sct = Object.assign({}, BASE_SCT, { signature: Buffer.from(data) });
  var logKey = LOG_SPKI;
  // On alternate runs, corrupt the log key SPKI instead of using a raw fuzz signature.
  if (data.length & 1) {
    logKey = Buffer.from(LOG_SPKI);
    data.copy(logKey, 0, 0, Math.min(data.length, logKey.length));
    sct = BASE_SCT;
  }
  try { await pki.ct.verifySct(ENTRY, sct, logKey); }
  catch (e) { if (!isPki(e)) throw e; }
};
