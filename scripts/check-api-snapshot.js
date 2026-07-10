// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/check-api-snapshot.js
 *
 * CI gate. Captures the current public surface and compares it against
 * the committed api-snapshot.json baseline. Fails on breaking changes
 * (removed members, kind changes, arity changes); logs additive changes
 * for visibility without failing.
 *
 * Exit codes:
 *   0  — no breaking changes (additive changes printed but not failing)
 *   1  — breaking changes detected
 *   2  — script-level error (missing baseline, IO failure, etc.)
 *
 * Operators see this gate as a CI promise: removed methods or changed
 * signatures fail the build before they reach a published release.
 *
 * Usage:
 *   node scripts/check-api-snapshot.js
 */

var path = require("node:path");
var snap = require("./refresh-api-snapshot.js");
var pki  = require("../index.js");
var pkg  = require("../package.json");

try {
  var baselinePath = path.join(__dirname, "..", "api-snapshot.json");
  var baseline;
  try {
    baseline = snap.read(baselinePath);
  } catch (e) {
    console.error("[check-api-snapshot] baseline missing or unreadable: " +
      ((e && e.message) || String(e)));
    console.error("[check-api-snapshot] generate one with " +
      "`node scripts/refresh-api-snapshot.js` and commit it.");
    process.exit(2);
  }

  var sinceByPrimitive = snap.extractSince();
  var current = snap.capture(pki, { packageVersion: pkg.version, sinceByPrimitive: sinceByPrimitive });
  var diff = snap.compare(baseline, current);

  console.log(snap.formatDiff(diff));

  if (diff.breaking.length > 0) {
    console.error("[check-api-snapshot] BREAKING changes detected. If intentional, " +
      "regenerate the baseline with `node scripts/refresh-api-snapshot.js` and commit it " +
      "alongside the version bump per the LTS calendar.");
    process.exit(1);
  }

  // @since contract: a shipped primitive's introduction version is immutable
  // and never exceeds the package version. (A newly-added primitive is gated
  // against the introducing version at refresh time, where the pre-refresh
  // baseline is still on disk — see refresh-api-snapshot.js.)
  var sinceViolations = snap.checkSince(baseline.sinceByPrimitive, sinceByPrimitive, pkg.version);
  if (sinceViolations.length > 0) {
    console.error("[check-api-snapshot] @since contract violation(s):");
    sinceViolations.forEach(function (m) { console.error("  - " + m); });
    console.error("[check-api-snapshot] a shipped primitive's @since is immutable and cannot " +
      "exceed the package version; fix the source @since tag.");
    process.exit(1);
  }

  // Deleting a documented primitive's @since line must not vacate the
  // immutability freeze: every token the committed baseline records must
  // still be documented in source, or its origin preserved via @originated
  // when the documented path moved. checkSince alone iterates only the
  // CURRENT map, so a deleted tag would otherwise vanish without a verdict.
  var droppedViolations = snap.checkSinceDropped(
    baseline.sinceByPrimitive || {}, sinceByPrimitive, snap.extractOriginated());
  if (droppedViolations.length > 0) {
    console.error("[check-api-snapshot] @since deletion violation(s):");
    droppedViolations.forEach(function (m) { console.error("  - " + m); });
    console.error("[check-api-snapshot] restore the @since tag (or declare @originated on the " +
      "corrected path) — a shipped primitive's introduction record is immutable.");
    process.exit(1);
  }

  if (diff.additive.length > 0) {
    console.log("[check-api-snapshot] " + diff.additive.length +
      " additive change(s) — refresh the baseline at the next release " +
      "(`node scripts/refresh-api-snapshot.js`) so the new surfaces are tracked.");
  }
  process.exit(0);
} catch (e) {
  console.error("[check-api-snapshot] error: " + ((e && e.stack) || e));
  process.exit(2);
}
