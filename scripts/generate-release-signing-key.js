#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/generate-release-signing-key.js
 *
 * One-time setup: generate the ML-DSA-65 release-signing keypair that the
 * npm-publish workflow uses to sign every release tarball. The keypair is
 * produced with Node's built-in node:crypto (OpenSSL 3.5, FIPS 204) — the
 * same native primitive the toolkit exposes through pki.webcrypto; no
 * vendored crypto is involved.
 *
 * Run this ONCE locally before the first PQC-signed release. The script:
 *   - Writes the PUBLIC key to `keys/release-pqc-pub.json` (commit this
 *     file — operators verify against the in-tree pubkey).
 *   - Prints the PRIVATE key (base64url PKCS#8 DER) to stdout. Store it as
 *     the `RELEASE_PQC_SIGNING_KEY` secret in the npm-publish GitHub Actions
 *     environment (same scope as NPM_TOKEN).
 *   - Prints the public-key fingerprint (SHA3-512 of the raw public-key
 *     bytes). Add it to SECURITY.md so operators can verify the in-tree
 *     pubkey out of band against the commit-signed SECURITY.md.
 *
 * Re-running this script ROTATES the key. To rotate:
 *   1. Run this script (overwrites keys/release-pqc-pub.json).
 *   2. Update the `RELEASE_PQC_SIGNING_KEY` env secret.
 *   3. Update SECURITY.md with the new fingerprint.
 *   4. Commit + ship a release.
 *   Previously-signed releases remain verifiable against the OLD public key —
 *   operators can `git log keys/release-pqc-pub.json` to walk the history.
 *
 * Algorithm: ML-DSA-65 (FIPS 204) — NIST PQC security level 3
 * (~192-bit classical, ~128-bit post-quantum collision margin on the
 * SHA3-512 fingerprint).
 */

var fs     = require("node:fs");
var path   = require("node:path");
var crypto = require("node:crypto");

// FIPS 204 ML-DSA-65 raw public-key length. The pubkey is stored raw
// (base64url) so it is engine-portable and small.
var ML_DSA_65_PUBKEY_BYTES = 1952;

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function sha3_512_hex(buf) {
  return crypto.createHash("sha3-512").update(buf).digest("hex");
}

// Raw public-key bytes come out of the JWK export (`pub` is base64url of
// the FIPS 204 encoded public key); this keeps the stored pubkey to the
// spec's 1952 bytes rather than the SPKI-wrapped form.
function _rawPublicKey(publicKey) {
  var jwk = publicKey.export({ format: "jwk" });
  if (!jwk || typeof jwk.pub !== "string") {
    throw new Error("could not extract raw ML-DSA public key from JWK export");
  }
  return Buffer.from(jwk.pub, "base64url");
}

function main() {
  var pair;
  try {
    pair = crypto.generateKeyPairSync("ml-dsa-65");
  } catch (e) {
    process.stderr.write("[generate-release-signing-key] node:crypto ML-DSA-65 keygen failed: " +
      ((e && e.message) || e) + "\n");
    process.stderr.write("[generate-release-signing-key] ML-DSA requires the engine floor (Node >=24.18, OpenSSL 3.5).\n");
    process.exit(1);
  }

  var pubBytes = _rawPublicKey(pair.publicKey);
  if (pubBytes.length !== ML_DSA_65_PUBKEY_BYTES) {
    process.stderr.write("[generate-release-signing-key] unexpected public-key length " +
      pubBytes.length + " (expected " + ML_DSA_65_PUBKEY_BYTES + " for ML-DSA-65)\n");
    process.exit(1);
  }
  // The private key is exported as PKCS#8 DER (seed form) — self-contained,
  // standard, and reconstructable by scripts/sign-release-artifact.js with
  // a single createPrivateKey call.
  var pkcs8 = pair.privateKey.export({ type: "pkcs8", format: "der" });
  var fingerprint = sha3_512_hex(pubBytes);

  var pubJson = {
    algorithm:            "ml-dsa-65",
    publicKey:            b64url(pubBytes),
    fingerprint_sha3_512: fingerprint,
    createdAt:            new Date().toISOString().slice(0, 10),
    rotation_note:        "Re-running scripts/generate-release-signing-key.js rotates the key. Update the RELEASE_PQC_SIGNING_KEY secret + the SECURITY.md fingerprint in the same commit.",
  };

  var pubPath = path.resolve(__dirname, "..", "keys", "release-pqc-pub.json");
  fs.mkdirSync(path.dirname(pubPath), { recursive: true });
  fs.writeFileSync(pubPath, JSON.stringify(pubJson, null, 2) + "\n");

  process.stderr.write("\n=== ML-DSA-65 release-signing keypair (node:crypto, FIPS 204) ===\n\n");
  process.stderr.write("Public key written to: " + pubPath + "\n");
  process.stderr.write("Fingerprint (SHA3-512): " + fingerprint + "\n\n");
  process.stderr.write("Private key (base64url PKCS#8 DER — paste into RELEASE_PQC_SIGNING_KEY secret):\n");
  process.stderr.write("------------------------\n");
  process.stdout.write(b64url(pkcs8) + "\n");
  process.stderr.write("------------------------\n\n");
  process.stderr.write("Next steps:\n");
  process.stderr.write("  1. Verify the public-key write:\n");
  process.stderr.write("       cat " + pubPath + "\n");
  process.stderr.write("  2. Set the secret in the npm-publish environment:\n");
  process.stderr.write("       gh secret set RELEASE_PQC_SIGNING_KEY --env npm-publish --body \"<paste from above>\"\n");
  process.stderr.write("  3. Update SECURITY.md with the fingerprint above.\n");
  process.stderr.write("  4. Commit keys/release-pqc-pub.json + SECURITY.md, ship a release.\n");
}

main();
