// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.sigstore.parseBundle + pki.sigstore.verifyBundle
 *
 * Runs under libFuzzer via jazzer.js. The contract for the Sigstore bundle
 * verifier: feeding attacker-controlled bytes -- as a raw JSON bundle, or spliced
 * into a real bundle's fields against fixed caller trust material -- may only ever
 * RESOLVE (a structured verdict) or THROW a pki.errors.PkiError (SigstoreError --
 * sigstore/bad-bundle, sigstore/bad-dsse, sigstore/dsse-verify-failed,
 * sigstore/bad-inclusion-proof, sigstore/inclusion-proof-mismatch,
 * sigstore/unsigned-root, sigstore/entry-mismatch, sigstore/chain-invalid,
 * sigstore/identity-mismatch, sigstore/bad-statement, sigstore/bad-certificate,
 * sigstore/unsupported-content, sigstore/bad-bundle-version, sigstore/bad-key) or
 * a config-time TypeError on a non-bundle. Any other throw -- a raw SyntaxError
 * from the JSON reader, a bare RangeError, a node:crypto assertion, an unhandled
 * rejection, a hang -- is a finding and is rethrown so the fuzzer records a
 * reproducer. This is the toolkit's first JSON input surface, so the mutator
 * explores the reader (unbalanced braces, deep nesting, duplicate members, huge
 * numbers) and every verify leg (a truncated proof, a flipped signature, a
 * mutated Rekor entry body, a corrupt certificate).
 */
var fs = require("fs");
var path = require("path");
var pki = require("..");

var FX = path.join(__dirname, "..", "test", "fixtures", "sigstore");
var REAL = fs.readFileSync(path.join(FX, "npm-provenance-bundle.json"), "utf8");
var TRUST_ROOT = JSON.parse(fs.readFileSync(path.join(FX, "trusted-root.json"), "utf8"));
var TRUST = { fulcioRoots: [], rekorKeys: (TRUST_ROOT.tlogs || []).map(function (t) { return { keyId: Buffer.from((t.logId && t.logId.keyId) || "", "base64"), spki: Buffer.from((t.publicKey && t.publicKey.rawBytes) || "", "base64") }; }) };
(TRUST_ROOT.certificateAuthorities || []).forEach(function (ca) { ((ca.certChain && ca.certChain.certificates) || []).forEach(function (c) { TRUST.fulcioRoots.push(Buffer.from(c.rawBytes, "base64")); }); });

function isPki(e) { return e instanceof pki.errors.PkiError || e instanceof TypeError; }

module.exports.fuzz = async function (data) {
  // Target A -- the JSON bundle reader on raw hostile bytes.
  try { pki.sigstore.parseBundle(data); } catch (e) { if (!isPki(e)) throw e; }

  if (data.length < 3) return;
  // Target B -- verifyBundle on the real bundle with one fuzzer-chosen leaf field
  // overwritten by fuzzer bytes (drives the DSSE / Rekor / chain legs on mutations
  // that still parse as a structural bundle).
  var bundle;
  try { bundle = JSON.parse(REAL); } catch (_e) { return; }
  var pick = data[0] % 6;
  var inject = data.subarray(1).toString("base64");
  var d = bundle.dsseEnvelope, vm = bundle.verificationMaterial, te = vm.tlogEntries[0];
  if (pick === 0) d.signatures[0].sig = inject;
  else if (pick === 1) d.payload = inject;
  else if (pick === 2) vm.certificate.rawBytes = inject;
  else if (pick === 3) te.canonicalizedBody = inject;
  else if (pick === 4) te.inclusionProof.rootHash = inject;
  else te.inclusionProof.hashes = [inject];

  try { await pki.sigstore.verifyBundle(bundle, TRUST); }
  catch (e) { if (!isPki(e)) throw e; }
};
