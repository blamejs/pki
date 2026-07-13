// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.webauthn.parseAttestationObject + pki.webauthn.verify
 *
 * Runs under libFuzzer via jazzer.js. The contract for the WebAuthn attestation
 * verifier: feeding attacker-controlled bytes -- as a raw attestation object, or
 * spliced into a real attestation's CBOR against a fixed clientDataHash -- may only
 * ever RESOLVE (a structured verdict) or THROW a pki.errors.PkiError (WebauthnError:
 * webauthn/bad-attestation-object, webauthn/bad-auth-data, webauthn/bad-cose-key,
 * webauthn/bad-att-stmt, webauthn/bad-att-cert, webauthn/bad-tpm, webauthn/bad-signature,
 * webauthn/key-mismatch, webauthn/aaguid-mismatch, webauthn/verify-failed,
 * webauthn/verify-error, webauthn/unsupported-format, webauthn/unsupported-algorithm,
 * webauthn/bad-input; or a CborError / Asn1Error the composed codecs raise). Any other
 * throw -- a raw SyntaxError from a BigInt/base parse, a bare RangeError from a bounded
 * read, a node:crypto assertion, an unhandled rejection, a hang -- is a finding and is
 * rethrown so the fuzzer records a reproducer. The seed corpus is the five real
 * attestation formats (packed / tpm / android-key / apple / fido-u2f), so mutations
 * reach the CBOR decode, the authenticatorData bounded reader, the COSE_Key decode, the
 * big-endian TPM struct readers, the DER ECDSA signature reshape, and each format's
 * structural bindings.
 */
var fs = require("fs");
var path = require("path");
var pki = require("..");

var KAT = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "test", "fixtures", "webauthn", "py-webauthn-kat.json"), "utf8"));
function b64u(s) { var b = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (b.length % 4) b += "="; return Buffer.from(b, "base64"); }
var FORMS = Object.keys(KAT.formats).map(function (k) { return b64u(KAT.formats[k].attestationObject); });
var FIXED_HASH = Buffer.alloc(32, 0x5a);

function isPki(e) { return e instanceof pki.errors.PkiError; }

module.exports.fuzz = async function (data) {
  // Target A -- the structural entry on raw hostile bytes.
  try { pki.webauthn.parseAttestationObject(data); } catch (e) { if (!isPki(e)) throw e; }

  if (data.length < 2) return;
  // Target B -- verify on a fuzzer-chosen real attestation whose authData or
  // attStmt bytes are overwritten by fuzzer input, driving the format verifiers'
  // signature reshape + TPM/COSE readers on mutations that still frame as CBOR.
  var base = FORMS[data[0] % FORMS.length];
  var att = Buffer.from(base);
  var off = data.length > 2 ? (data[1] % att.length) : 0;
  var patch = data.subarray(2);
  patch.copy(att, off);
  try { await pki.webauthn.verify(att, FIXED_HASH, {}); }
  catch (e) { if (!isPki(e)) throw e; }

  // Also drive verify on the raw bytes (rarely frames as CBOR, but free coverage
  // of the reject paths at the pipeline entry).
  try { await pki.webauthn.verify(data, FIXED_HASH, {}); }
  catch (e) { if (!isPki(e)) throw e; }
};
