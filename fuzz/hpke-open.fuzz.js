// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.hpke.setupR + pki.hpke.open (RFC 9180 recipient path)
 *
 * Runs under libFuzzer via jazzer.js. The contract for the recipient side:
 * decapsulating an attacker-controlled encapsulated key and opening an
 * attacker-controlled ciphertext against a fixed, valid recipient key may only
 * ever RETURN plaintext bytes or THROW a pki.errors.PkiError (HpkeError --
 * hpke/bad-key, hpke/open-failed, hpke/unknown-suite, hpke/inconsistent-psk,
 * hpke/export-only, hpke/message-limit). Any other throw -- a bare RangeError, a
 * TypeError out of node:crypto key import, an assertion from the AEAD, a hang --
 * is a finding and is rethrown so the fuzzer records a reproducer. The input is
 * split at fuzzer-controlled offsets so the mutator explores every field
 * boundary (a truncated enc, a flipped point, a hostile suite triple, hostile
 * aad, a short/long ct that undershoots or overshoots the AEAD tag).
 */
var pki = require("..");

// Two fixed, valid recipient keys (the decapsulation path under test is the
// recipient's; the keys are constants so the fuzzer mutates only the hostile
// enc / aad / ct, not the key): an X25519 pair for the DHKEM decap, and the
// ML-KEM-768 seed of draft-ietf-hpke-pq-05 Appendix A.2 for the ML-KEM decap.
var SK_R = Buffer.from("009f2181fba5f8908632c10ea1137c40a849728fde016c4602458b943a5dc048", "hex");
var PK_R = Buffer.from("8c7781768956b9dd38997c5a83ab5b9315270a9f73d87d676573c5bca74e3e48", "hex");
var SEED_ML768 = Buffer.from("80008d036609972cf761d7e2d3b831e48d3e941cda94fbf9bae09bca87373f9bb7411f58fd3324ba1d0daa5a7b42768c5b53e1df29c28d4f5428a8233a905089", "hex");
var S = pki.hpke.suites;
var RECIPIENTS = [
  { kem: S.KEM.DHKEM_X25519_HKDF_SHA256, skR: { skm: SK_R, pkm: PK_R } },
  { kem: S.KEM.ML_KEM_768, skR: { skm: SEED_ML768 } },
];
var KDFS = [S.KDF.HKDF_SHA256, S.KDF.HKDF_SHA384, S.KDF.HKDF_SHA512];
var AEADS = [S.AEAD.AES_128_GCM, S.AEAD.AES_256_GCM, S.AEAD.CHACHA20_POLY1305, S.AEAD.EXPORT_ONLY];

module.exports.fuzz = function (data) {
  if (data.length < 5) return;
  // Suite selectors: the KEM picks one of the two baked recipients; the KDF and
  // AEAD are fuzzer-chosen from the registry so every key-schedule variant and
  // every AEAD (including export-only, which must reject seal/open) is hit.
  var recipient = RECIPIENTS[(data[0] >> 4) % RECIPIENTS.length];
  var ids = { kem: recipient.kem, kdf: KDFS[data[0] % KDFS.length], aead: AEADS[data[1] % AEADS.length] };
  var encLen = data.readUInt16BE(2) % (data.length + 1);
  var body = data.subarray(4);
  var enc = body.subarray(0, Math.min(encLen, body.length));
  var rest = body.subarray(Math.min(encLen, body.length));
  var half = rest.length >> 1;
  var aad = rest.subarray(0, half);
  var ct = rest.subarray(half);
  var skR = recipient.skR;

  try {
    pki.hpke.open(ids, enc, skR, {}, aad, ct);
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
  // Also exercise setupR in isolation (context establishment without an open),
  // so a decap that succeeds but a later key-schedule/PSK check that throws is
  // still held to the PkiError-only contract.
  try {
    pki.hpke.setupR(ids, enc, skR, { info: aad });
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
};
