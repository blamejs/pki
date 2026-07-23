// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: RFC 5958 / RFC 8018 EncryptedPrivateKeyInfo decryption via pki.key.decrypt.
 *
 * The hostile surface is an arbitrary EncryptedPrivateKeyInfo + an arbitrary password: attacker-controlled
 * PBES2 parameters (a malformed / truncated parameter SEQUENCE, a non-PBKDF2 KDF, a non-AES-CBC scheme, an
 * over-cap salt or iteration count, a wrong-length IV) reach the decoder before any key derivation, and the
 * derived-key path can produce a bad PKCS#7 pad or a valid pad that is not a PrivateKeyInfo. The fuzz bytes
 * are fed straight in as the encrypted input; a slice is the password, and a caller maxIterations cap is
 * exercised on some inputs.
 *
 * Contract: pki.key.decrypt must, for ANY input, EITHER return a Buffer (which -- by the internal integrity
 * re-parse -- is a well-formed PrivateKeyInfo) OR throw a typed pki.errors.PkiError. Any other throw (a
 * native TypeError from a raw children[] dereference, a node RangeError from an unchecked IV, an
 * ERR_STRING_TOO_LONG) is an unguarded invariant break, so it propagates for jazzer to record.
 */

var pki = require("..");

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  var d = Buffer.from(data);
  var pw = d.length ? d.subarray(0, Math.min(8, d.length)).toString("latin1") : "";
  var opts = (d.length && (d[0] & 1)) ? { maxIterations: 1 + (d[d.length - 1] || 1) } : undefined;

  var out;
  try {
    out = await pki.key.decrypt(d, pw, opts);
  } catch (e) {
    if (isPki(e)) return;
    throw e;
  }
  // decrypt succeeded on hostile bytes: the recovered plaintext is a Buffer the internal re-parse accepted
  // as a PrivateKeyInfo -- assert the contract holds (a non-Buffer / non-parseable success is a finding).
  if (!Buffer.isBuffer(out)) throw new Error("key-decrypt fuzz: a decrypt success returned a non-Buffer");
  pki.schema.pkcs8.parse(out);
};
