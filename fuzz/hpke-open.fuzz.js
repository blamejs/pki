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
// The 32-byte hybrid seed of draft-irtf-cfrg-concrete-hybrid-kems-04 Appendix B, which all three
// suites' vectors use. A hybrid decapsulation key IS this seed: both component keys are expanded
// from it inside the KEM, so the mutator reaches the ML-KEM decap, the nominal-group exponentiation
// and the combiner through one constant.
var SEED_HYBRID = Buffer.alloc(32, 0x09);
// The DHKEM(P-384) pair of draft-ietf-hpke-pq-05 Appendix A.8, so the P-384 scalar multiplication and
// its HKDF-SHA384 ExtractAndExpand are reached under a key the draft publishes.
var SK_P384 = Buffer.from("679172205e04663f40fda1018cd46c18ebaa876ede6998ba86b051614ca4d5e4bfbea34b720617a4b958cc80f6305244", "hex");
var PK_P384 = Buffer.from("04a5f53da8564364255bc36850df793672782a5c9e4a7fb5fb2e2146eb12e4d8477ab1f326a361dfd1e41212109510e813380547c68c0964c1908f16f67b902a061be27b2f8b43f1fab1bf0dbf89f5167ce80aca2c210b8fc0f040699db9ee1229", "hex");
var S = pki.hpke.suites;
var RECIPIENTS = [
  { kem: S.KEM.DHKEM_X25519_HKDF_SHA256, skR: { skm: SK_R, pkm: PK_R } },
  { kem: S.KEM.ML_KEM_768, skR: { skm: SEED_ML768 } },
  { kem: S.KEM.MLKEM768_P256, skR: { skm: SEED_HYBRID } },
  { kem: S.KEM.MLKEM1024_P384, skR: { skm: SEED_HYBRID } },
  { kem: S.KEM.MLKEM768_X25519, skR: { skm: SEED_HYBRID } },
  { kem: S.KEM.DHKEM_P384_HKDF_SHA384, skR: { skm: SK_P384, pkm: PK_P384 } },
];
// Both key schedules: the two-stage HKDF sizes and the single-stage SHAKE XOFs, whose schedule derives
// the key, base nonce and exporter secret from one squeeze and caps its length-prefixed inputs.
var KDFS = [S.KDF.HKDF_SHA256, S.KDF.HKDF_SHA384, S.KDF.HKDF_SHA512, S.KDF.SHAKE128, S.KDF.SHAKE256];
var AEADS = [S.AEAD.AES_128_GCM, S.AEAD.AES_256_GCM, S.AEAD.CHACHA20_POLY1305, S.AEAD.EXPORT_ONLY];

// Suite selectors: the high nibble of the first byte picks a baked recipient, its whole value picks the
// KDF and the second byte picks the AEAD, so every KEM x key schedule x AEAD combination is reachable
// (including export-only, which must reject seal/open). Exported because the seed corpus is generated
// against this exact mapping; a corpus built against a stale copy would name suites it does not select.
function selectSuite(data) {
  var recipient = RECIPIENTS[(data[0] >> 4) % RECIPIENTS.length];
  return {
    recipient: recipient,
    ids: { kem: recipient.kem, kdf: KDFS[data[0] % KDFS.length], aead: AEADS[data[1] % AEADS.length] },
  };
}
module.exports._selectSuite = selectSuite;
module.exports._counts = { recipients: RECIPIENTS.length, kdfs: KDFS.length, aeads: AEADS.length };

module.exports.fuzz = function (data) {
  if (data.length < 5) return;
  var sel = selectSuite(data);
  var recipient = sel.recipient, ids = sel.ids;
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
  // The KEM alone, through the standalone decap export. It reaches the same
  // decapsulation as setupR but without a key schedule after it, so a throw the
  // key schedule would otherwise mask is attributed to the KEM that raised it.
  try {
    pki.hpke.decap(ids.kem, enc, skR);
  } catch (e) {
    if (!(e instanceof pki.errors.PkiError)) throw e;
  }
};
