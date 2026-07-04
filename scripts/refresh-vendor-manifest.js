// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/refresh-vendor-manifest.js
 *
 * Recomputes SHA-256 over every vendored file declared in
 * lib/vendor/MANIFEST.json and writes the hashes back to the manifest.
 * The operator runs this after a vendored bundle is re-built.
 *
 * Verification (catching drift between the manifest's recorded hashes and
 * the on-disk content) is done by the vendor-manifest smoke check — this
 * script is the refresh-tool side only.
 *
 *   node scripts/refresh-vendor-manifest.js
 */

var fs     = require("node:fs");
var crypto = require("node:crypto");
var path   = require("node:path");

var MANIFEST_PATH = path.join(__dirname, "..", "lib", "vendor", "MANIFEST.json");

function hashFile(p) {
  return "sha256:" + crypto.createHash("sha256")
    .update(fs.readFileSync(p)).digest("hex");
}

function hashTree(dir) {
  var entries = fs.readdirSync(dir, { withFileTypes: true })
    .sort(function (a, b) { return a.name.localeCompare(b.name); });
  var h = crypto.createHash("sha256");
  for (var i = 0; i < entries.length; i += 1) {
    var e = entries[i];
    var p = path.join(dir, e.name);
    h.update(e.name);
    if (e.isDirectory()) h.update(hashTree(p));
    else h.update(fs.readFileSync(p));
  }
  return "sha256-tree:" + h.digest("hex");
}

// File paths in MANIFEST.json are repo-relative (e.g.
// "lib/vendor/noble-ciphers.cjs"); resolve them against the repo root.
function _resolve(fp) {
  return path.join(__dirname, "..", fp);
}

function computeHashes(pkgEntry) {
  if (!pkgEntry.files) return {};
  var out = {};
  var keys = Object.keys(pkgEntry.files);
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    var fp = pkgEntry.files[k];
    if (typeof fp !== "string") continue;
    var abs = _resolve(fp);
    if (fp.endsWith("/")) {
      if (fs.existsSync(abs)) out[k] = hashTree(abs);
      else out[k] = "MISSING";
    } else if (fs.existsSync(abs)) {
      out[k] = hashFile(abs);
    } else {
      out[k] = "MISSING";
    }
  }
  return out;
}

// Encoding gate. Reject manifests that carry Latin-1-of-UTF-8 mojibake
// (typographic punctuation re-encoded through a mis-set editor codepage)
// or a U+FFFD replacement character (a lossy encoding round-trip).
// Operator-facing artifacts MUST be clean UTF-8.
function _refuseMojibake(raw) {
  if (/â/.test(raw)) {
    process.stderr.write("[refresh-vendor-manifest] FAIL: MANIFEST.json contains UTF-8-as-Latin-1 mojibake.\n");
    process.stderr.write("[refresh-vendor-manifest] Re-author affected prose fields in clean UTF-8 before refreshing.\n");
    process.exit(1);
  }
  if (raw.indexOf("�") !== -1) {
    process.stderr.write("[refresh-vendor-manifest] FAIL: MANIFEST.json contains U+FFFD replacement character (encoding loss).\n");
    process.exit(1);
  }
}

// RFC 3339 timestamp. Date-only strings boundary-flip across midnight-UTC
// under Date.parse comparisons; emit the full seconds-precision form so a
// currency check comparing bundledAt against an upstream commit time is
// boundary-safe.
function _rfc3339Now() {
  return new Date().toISOString();
}

function main() {
  var raw = fs.readFileSync(MANIFEST_PATH, "utf8");
  _refuseMojibake(raw);
  var manifest = JSON.parse(raw);
  var pkgs = Object.keys(manifest.packages || {});
  var totalHashes = 0;
  var refreshedAt = _rfc3339Now();
  for (var i = 0; i < pkgs.length; i += 1) {
    var pkg = manifest.packages[pkgs[i]];
    pkg.hashes = computeHashes(pkg);
    totalHashes += Object.keys(pkg.hashes).length;
    // Promote date-only bundledAt fields to RFC 3339 UTC so a
    // Date.parse-based currency comparison is boundary-safe.
    if (typeof pkg.bundledAt === "string" && /^\d{4}-\d{2}-\d{2}$/.test(pkg.bundledAt)) {
      pkg.bundledAt = pkg.bundledAt + "T00:00:00Z";
    }
    // Stamp the refresh timestamp so operators can diff "when did this
    // bundle last get re-hashed" without trawling git log.
    pkg.refreshedAt = refreshedAt;
  }
  var out = JSON.stringify(manifest, null, 2) + "\n";
  _refuseMojibake(out);
  fs.writeFileSync(MANIFEST_PATH, out);
  process.stdout.write("[refresh-vendor-manifest] wrote " +
    pkgs.length + " packages / " + totalHashes + " hashes to " +
    MANIFEST_PATH + " (refreshedAt=" + refreshedAt + ")\n");
}

main();
