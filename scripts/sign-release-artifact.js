#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/sign-release-artifact.js
 *
 * Sign a release artifact (typically the npm tarball) with the toolkit's
 * ML-DSA-65 release-signing key, then write the signature alongside as
 * `<artifact>.mldsa.sig`.
 *
 * Signing runs on Node's built-in node:crypto (OpenSSL 3.5, FIPS 204) — no
 * vendored crypto.
 *
 * Operator-run against the packed tarball; no workflow invokes it
 * automatically. The operator attaches the resulting sidecar to the GitHub
 * release when post-quantum release signing is wanted:
 *
 *   node scripts/sign-release-artifact.js dist/blamejs-pki-X.Y.Z.tgz
 *
 * Reads the private key from `RELEASE_PQC_SIGNING_KEY` (base64url PKCS#8
 * DER, as emitted by scripts/generate-release-signing-key.js). The pubkey
 * lives in `keys/release-pqc-pub.json` (in-tree). After signing, the script
 * verifies the signature against the in-tree pubkey BEFORE writing the .sig
 * file. If verify fails it refuses to write — this defends against a stale /
 * wrong env secret silently producing un-verifiable signatures.
 */

var fs     = require("node:fs");
var path   = require("node:path");
var crypto = require("node:crypto");

// FIPS 204 ML-DSA-65 raw public-key length.
var ML_DSA_65_PUBKEY_BYTES = 1952;

function fail(msg) {
  process.stderr.write("[sign-release-artifact] " + msg + "\n");
  process.exit(1);
}

function readPubKey() {
  var pubPath = path.resolve(__dirname, "..", "keys", "release-pqc-pub.json");
  var raw;
  try { raw = fs.readFileSync(pubPath, "utf8"); }
  catch (e) { fail("cannot read " + pubPath + ": " + ((e && e.message) || e)); }
  var doc;
  try { doc = JSON.parse(raw); }
  catch (e) { fail("malformed " + pubPath + ": " + ((e && e.message) || e)); }
  if (doc.algorithm !== "ml-dsa-65") {
    fail("unexpected algorithm in pubkey: " + JSON.stringify(doc.algorithm) +
      " (expected ml-dsa-65); re-run scripts/generate-release-signing-key.js to migrate");
  }
  if (typeof doc.publicKey !== "string" || doc.publicKey.length === 0) {
    fail("publicKey missing/empty in " + pubPath);
  }
  var pubBytes = Buffer.from(doc.publicKey, "base64url");
  if (pubBytes.length !== ML_DSA_65_PUBKEY_BYTES) {
    fail("in-tree publicKey decodes to " + pubBytes.length +
      " bytes; expected " + ML_DSA_65_PUBKEY_BYTES + " (FIPS 204 ML-DSA-65). keys/release-pqc-pub.json corrupted.");
  }
  // Reconstruct a KeyObject from the raw bytes via the AKP JWK shape.
  try {
    return crypto.createPublicKey({
      key:    { kty: "AKP", alg: "ML-DSA-65", pub: doc.publicKey },
      format: "jwk",
    });
  } catch (e) {
    fail("could not reconstruct in-tree public key: " + ((e && e.message) || e));
  }
  return null;   // unreachable
}

function readPrivateKey() {
  var secB64 = process.env.RELEASE_PQC_SIGNING_KEY;   // env-driven release script
  if (!secB64 || secB64.length === 0) {
    fail("RELEASE_PQC_SIGNING_KEY env not set. Run scripts/generate-release-signing-key.js once + set the secret in the npm-publish env.");
  }
  var der = Buffer.from(secB64, "base64url");
  try {
    return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  } catch (e) {
    fail("RELEASE_PQC_SIGNING_KEY did not decode to a valid ML-DSA-65 PKCS#8 key: " +
      ((e && e.message) || e) + " — the secret may be corrupted or from a different algorithm.");
  }
  return null;   // unreachable
}

function main() {
  var artifactPath = process.argv[2];
  if (!artifactPath) fail("usage: node scripts/sign-release-artifact.js <artifact-path>");

  var privateKey = readPrivateKey();
  var publicKey  = readPubKey();

  // Guard against an env secret that isn't the counterpart of the in-tree
  // pubkey: the public key derived from the private key must match.
  var derivedPub = crypto.createPublicKey(privateKey).export({ format: "jwk" }).pub;
  var expectedPub = publicKey.export({ format: "jwk" }).pub;
  if (derivedPub !== expectedPub) {
    fail("RELEASE_PQC_SIGNING_KEY does NOT correspond to keys/release-pqc-pub.json " +
      "(derived public key differs). Either the env secret is stale (re-run " +
      "scripts/generate-release-signing-key.js + update the secret) or the in-tree " +
      "pubkey was committed without the matching secret update. Refusing to sign.");
  }

  var artifactBytes = fs.readFileSync(artifactPath);
  process.stderr.write("[sign-release-artifact] signing " + artifactPath +
    " (" + artifactBytes.length + " bytes) with ml-dsa-65...\n");

  var sigBytes = crypto.sign(null, artifactBytes, privateKey);

  // Self-verify against the in-tree pubkey before writing — the operator-
  // side verification path uses this same pubkey, so a failure here would
  // ship a signature no one can verify.
  var ok = crypto.verify(null, artifactBytes, publicKey, sigBytes);
  if (!ok) {
    fail("self-verify FAILED — refusing to write a non-verifiable .sig.");
  }

  var sigPath = artifactPath + ".mldsa.sig";
  fs.writeFileSync(sigPath, sigBytes);
  process.stderr.write("[sign-release-artifact] OK — wrote " + sigPath +
    " (" + sigBytes.length + " bytes); self-verified against in-tree pubkey\n");
}

main();
