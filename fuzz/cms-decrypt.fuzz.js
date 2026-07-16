// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: CMS EnvelopedData / AuthEnvelopedData / EncryptedData decryption via pki.cms.decrypt.
 *
 * libFuzzer / jazzer.js harness. decrypt parses an enveloped structure over the strict
 * pki.schema.cms codec, selects a recipient, acquires the content-encryption key through the
 * matching arm (RSA-OAEP / v1.5 / ECDH / X25519 / X448 / AES-KW / PBKDF2 / ML-KEM), and opens the
 * content (AEAD verify / CBC decrypt+unpad) -- every byte of which (the recipient infos, the
 * wrapped keys, the KEM ciphertext, the encrypted content, the mac, the KDF parameters) is
 * attacker-controlled. The fixed recipient key set (an RSA and an ML-KEM keypair, plus a password
 * and a symmetric KEK) is the only pinned input; the mutated message is the whole attack surface,
 * reaching the CEK-acquisition + content-opening arms behind the parser.
 *
 * Contract: decrypting attacker-controlled bytes has exactly two acceptable outcomes -- a resolved
 * result object, or a thrown/rejected `pki.errors.PkiError` (CmsError / Asn1Error / OidError /
 * PemError). Any other throw (RangeError, a bare TypeError, a stack overflow, a hang) is an
 * unguarded invariant break -- rethrow so jazzer records the reproducer.
 */

var pki = require("..");
var makeRecipient = require("../test/helpers/signing").makeRecipient;

// A fixed recipient set, generated once (no committed private keys). The fuzzer drives its bytes
// against each in turn so a mutation that reaches any arm's CEK acquisition is exercised.
var RSA = makeRecipient("rsa");
var KEM = makeRecipient("ml-kem-768");
var KMS = [
  { key: RSA.key, cert: RSA.cert },
  { key: KEM.key, cert: KEM.cert },
  { password: "fuzz-password" },
  { kek: Buffer.alloc(32, 0x5a) },
  { cek: Buffer.alloc(32, 0x33) },
];

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  if (data.length < 1) return;
  var buf = Buffer.from(data);
  var km = KMS[data[0] % KMS.length];
  try {
    await pki.cms.decrypt(buf, km);
  } catch (e) { if (!isPki(e)) throw e; }
};
