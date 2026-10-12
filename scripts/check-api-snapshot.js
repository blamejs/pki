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

  // The error-code surface. A `domain/reason` code is a contract an operator
  // switches on, so a code the baseline recorded and the source no longer throws
  // was renamed or deleted under them. A code no test names is the hole that
  // freeze exists to close: nothing would catch its rename, so a NEW code arrives
  // with a vector, and the recorded residual that predates the rule only shrinks.
  if (baseline.errorCodes) {
    var liveCodes = snap.extractErrorCodes(null, Object.keys(pki));
    var assertedCodes = snap.extractAssertedCodes();
    var codeVerdict = snap.checkErrorCodes(baseline, liveCodes.codes, assertedCodes);

    if (codeVerdict.removed.length > 0) {
      console.error("[check-api-snapshot] " + codeVerdict.removed.length +
        " frozen error code(s) no longer thrown by the source:");
      codeVerdict.removed.forEach(function (c) { console.error("  - " + c); });
      console.error("[check-api-snapshot] an error code is a stable contract callers switch on. " +
        "Restore it, or make the removal a deliberate breaking change: regenerate the baseline " +
        "with `node scripts/refresh-api-snapshot.js` and record it in the release notes.");
      process.exit(1);
    }

    if (codeVerdict.unasserted.length > 0) {
      console.error("[check-api-snapshot] " + codeVerdict.unasserted.length +
        " error code(s) no test names:");
      codeVerdict.unasserted.forEach(function (c) { console.error("  - " + c); });
      console.error("[check-api-snapshot] add a vector that drives the shipped path and asserts " +
        "the code, so a later rename is caught by something.");
      process.exit(1);
    }

    console.log("[check-api-snapshot] error codes: " + liveCodes.codes.length + " across " +
      liveCodes.domains.length + " domain(s); " +
      (baseline.errorCodesWithoutVector || []).length + " in the recorded residual" +
      (codeVerdict.closed.length > 0 ? ", " + codeVerdict.closed.length + " of which now have one" : "") +
      (liveCodes.stems.length > 0 ? "; " + liveCodes.stems.length +
        " code(s) are built from a stem and are not frozen by name" : "") + ".");
    if (codeVerdict.added.length > 0) {
      console.log("[check-api-snapshot] " + codeVerdict.added.length +
        " new error code(s), each named by a test — refresh the baseline at the next release.");
    }
  } else {
    console.log("[check-api-snapshot] baseline carries no error-code surface; " +
      "run `node scripts/refresh-api-snapshot.js` to record it.");
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
