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
 * sigstore/unsupported-content, sigstore/bad-bundle-version, sigstore/bad-key,
 * sigstore/bad-message-signature, sigstore/artifact-required,
 * sigstore/artifact-mismatch, sigstore/signature-verify-failed) or
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
var MSG = fs.readFileSync(path.join(FX, "conformance", "happy-path-v0.3.sigstore.json"), "utf8");
var TRUST_ROOT = JSON.parse(fs.readFileSync(path.join(FX, "trusted-root.json"), "utf8"));
var TRUST = { fulcioRoots: [], rekorKeys: (TRUST_ROOT.tlogs || []).map(function (t) { return { keyId: Buffer.from((t.logId && t.logId.keyId) || "", "base64"), spki: Buffer.from((t.publicKey && t.publicKey.rawBytes) || "", "base64") }; }) };
(TRUST_ROOT.certificateAuthorities || []).forEach(function (ca) { ((ca.certChain && ca.certChain.certificates) || []).forEach(function (c) { TRUST.fulcioRoots.push(Buffer.from(c.rawBytes, "base64")); }); });

// Only a typed PkiError is an acceptable outcome. A raw TypeError (a null/wrong-
// type field dereferenced) is a finding, NOT whitelisted -- the harness feeds a
// Buffer / a structural bundle object, never a config-time non-object, so a
// TypeError here means malformed input escaped the fail-closed contract.
function isPki(e) { return e instanceof pki.errors.PkiError; }

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

  // Target C -- the message_signature arm, whose artifact comes from the caller rather than from
  // the bundle. The fuzzer drives both halves of that door: the bytes handed over as the artifact,
  // and the arm and log-entry fields the artifact is compared against.
  var ms;
  try { ms = JSON.parse(MSG); } catch (_e2) { return; }
  var mpick = data[0] % 5;
  var mte = ms.verificationMaterial.tlogEntries[0];
  if (mpick === 0) ms.messageSignature.signature = inject;
  else if (mpick === 1) ms.messageSignature.messageDigest.digest = inject;
  else if (mpick === 2) ms.messageSignature.messageDigest.algorithm = data.subarray(1).toString("latin1");
  else if (mpick === 3) mte.canonicalizedBody = inject;

  var opts = { fulcioRoots: TRUST.fulcioRoots, rekorKeys: TRUST.rekorKeys, artifact: data.subarray(1) };
  try { await pki.sigstore.verifyBundle(ms, opts); }
  catch (e) { if (!isPki(e)) throw e; }

  // Target D -- the Rekor v2 arm. A hashedrekord v0.0.2 body is built with the
  // fuzzer's bytes in each field the binding reads, so the version dispatch, the
  // three comparisons and the digest recomputation are driven on hostile values.
  // tsaRoots and the timestamp list are fuzzed too, since an RFC 3161 token is the
  // only thing that can date such an entry.
  var v2;
  try { v2 = JSON.parse(REAL); } catch (_e3) { return; }
  var vpick = data[0] % 7;
  var vte = v2.verificationMaterial.tlogEntries[0];
  var hr = { signature: { content: inject,
      verifier: { x509Certificate: { rawBytes: inject },
        keyDetails: data.subarray(1, 40).toString("latin1") } },
    data: { algorithm: "SHA2_256", digest: inject } };
  if (vpick === 0) hr.signature.content = v2.dsseEnvelope.signatures[0].sig;
  else if (vpick === 1) hr.signature.verifier.x509Certificate.rawBytes = v2.verificationMaterial.certificate.rawBytes;
  else if (vpick === 2) hr.signature.verifier.keyDetails = "PKIX_ECDSA_P256_SHA_256";
  else if (vpick === 3) delete hr.signature.verifier.keyDetails;
  else if (vpick === 4) hr.data.algorithm = data.subarray(1, 12).toString("latin1");
  else if (vpick === 5) hr.data.digest = null;
  vte.canonicalizedBody = Buffer.from(JSON.stringify({
    apiVersion: "0.0.2", kind: "hashedrekord", spec: { hashedRekordV002: hr },
  })).toString("base64");
  vte.integratedTime = 0;
  v2.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: [{ signedTimestamp: inject }] };
  // A pinned anchor that does not parse is a config fault and refuses before any
  // entry is read, so most inputs pin a real certificate: the token will not verify
  // under it, but the entry binding is reached, which is the surface being driven.
  // One pick still hands the anchor list fuzzer bytes, to drive that door too.
  var vopts = { fulcioRoots: TRUST.fulcioRoots, rekorKeys: TRUST.rekorKeys,
    tsaRoots: vpick === 6 ? [data.subarray(1)] : [TRUST.fulcioRoots[0]] };
  try { await pki.sigstore.verifyBundle(v2, vopts); }
  catch (e) { if (!isPki(e)) throw e; }
};
