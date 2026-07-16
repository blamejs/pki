// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.smime.decrypt (RFC 8551 S/MIME encryption layer).
 *
 * libFuzzer / jazzer.js harness. decrypt parses a MIME entity (header split, folding, structured
 * Content-Type), decodes the base64 transfer-encoding, parses the enveloped CMS structure over the
 * strict pki.schema.cms codec, and delegates into pki.cms.decrypt (recipient selection + CEK
 * acquisition + AEAD/CBC content opening) -- the whole MIME frame and every byte of the enveloped
 * body are attacker-controlled. The fixed recipient key set (an RSA and an ML-KEM keypair plus a
 * password and a symmetric KEK) is the only pinned input; the mutated message is the attack surface.
 * A distinct surface from fuzz/smime-verify.fuzz.js (the signed path) and fuzz/cms-decrypt.fuzz.js
 * (the raw CMS body without the MIME frame).
 *
 * Contract: decrypting attacker-controlled bytes has exactly two acceptable outcomes -- a resolved
 * result, or a thrown/rejected `pki.errors.PkiError` (SmimeError / CmsError / Asn1Error / OidError /
 * PemError). Any other throw (RangeError, a bare TypeError, a stack overflow, a hang) is an unguarded
 * invariant break -- rethrow so jazzer records the reproducer.
 */

var pki = require("..");
var makeRecipient = require("../test/helpers/signing").makeRecipient;

// A fixed recipient set, generated once (no committed private keys). The fuzzer drives its bytes
// against each in turn so a mutation that reaches any recipient arm's CEK acquisition is exercised.
var RSA = makeRecipient("rsa");
var KEM = makeRecipient("ml-kem-768");
var KMS = [
  { key: RSA.key, cert: RSA.cert },
  { key: KEM.key, cert: KEM.cert },
  { password: "fuzz-password" },
  { kek: Buffer.alloc(32, 0x5a) },
];

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  if (data.length < 1) return;
  var buf = Buffer.from(data);
  var km = KMS[data[0] % KMS.length];
  try {
    await pki.smime.decrypt(buf, km, { strictSmimeType: (data[0] & 0x80) !== 0 });
  } catch (e) { if (!isPki(e)) throw e; }
};
