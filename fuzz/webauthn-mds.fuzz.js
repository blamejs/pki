// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.webauthn.verifyMetadataBlob + metadataFor + metadataAnchors
 *
 * Runs under libFuzzer via jazzer.js. The contract for the FIDO Metadata Service reader:
 * feeding attacker-controlled bytes -- as a raw BLOB, or spliced into a real signed BLOB's
 * payload and re-signed -- may only ever RESOLVE (a verified catalogue) or THROW a
 * pki.errors.PkiError (WebauthnError: webauthn/bad-metadata-blob, webauthn/metadata-no-root,
 * webauthn/metadata-untrusted, webauthn/metadata-rollback, webauthn/metadata-stale,
 * webauthn/bad-metadata-entry, webauthn/duplicate-metadata-entry, webauthn/too-large,
 * webauthn/unsupported-algorithm, webauthn/verify-failed, webauthn/bad-input; or an
 * Asn1Error / X509Error a composed codec raises). Any other throw -- a raw SyntaxError from
 * the JSON reader, a bare RangeError from a bounded read, an unhandled rejection, a hang --
 * is a finding and is rethrown so the fuzzer records a reproducer.
 *
 * Two targets, because a signature gate that fuzzing cannot pass would leave everything
 * behind it unfuzzed. Target A drives raw bytes at the entry, covering the JWS split, the
 * base64url decode, the header JSON read, and the x5c certificate decode -- everything
 * ahead of the signature check. Target B splices fuzzer bytes into a real payload and
 * RE-SIGNS with the minted signer's key, so the mutation arrives with a valid signature
 * and a chain that reaches the root: that is the only way the payload reader, the entry
 * walk, the rollback and freshness comparisons, the status-report policy, and the
 * per-entry anchor decode are reached at all.
 */
var pki = require("..");
var mdsHelper = require("../test/helpers/mds-blob");

var FIXED_TIME = new Date("2026-06-01T00:00:00Z");
function isPki(e) { return e instanceof pki.errors.PkiError; }

// Minted once, then reused: the keygen and four certificate signings are far too slow to
// repeat per iteration, and none of that material is what is under test.
var ready = null;
function fixture() {
  if (!ready) {
    ready = (async function () {
      var m = await mdsHelper.mint({});
      var parts = m.blob.toString("ascii").split(".");
      return { m: m, h64: parts[0], payload: Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64") };
    })();
  }
  return ready;
}

module.exports.fuzz = async function (data) {
  var f = await fixture();
  var opts = { rootCertificates: [f.m.rootDer], time: FIXED_TIME };

  // Target A -- raw hostile bytes at the entry.
  try { await pki.webauthn.verifyMetadataBlob(data, opts); }
  catch (e) { if (!isPki(e)) throw e; }

  if (data.length < 2) return;

  // Target B -- fuzzer bytes spliced into the real payload, re-signed so the mutation
  // actually reaches the payload reader behind the verified signature.
  var payload = Buffer.from(f.payload);
  var off = data[0] % payload.length;
  data.subarray(1).copy(payload, off);
  var p64 = mdsHelper.b64u(payload);
  var signing = Buffer.from(f.h64 + "." + p64, "ascii");
  var sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, f.m.signerKey, signing));
  var blob = Buffer.from(f.h64 + "." + p64 + "." + mdsHelper.b64u(sig), "utf8");

  var md = null;
  try { md = await pki.webauthn.verifyMetadataBlob(blob, opts); }
  catch (e) { if (!isPki(e)) throw e; }

  // The lookup + anchor decode run only on a catalogue that verified, which is where an
  // attacker-shaped entry lands: a malformed aaguid, a status report of the wrong type, an
  // attestationRootCertificates value that is not a certificate at all.
  if (!md) return;
  try {
    var entry = pki.webauthn.metadataFor(md, f.m.aaguid);
    if (entry) pki.webauthn.metadataAnchors(entry);
  } catch (e) { if (!isPki(e)) throw e; }
};
