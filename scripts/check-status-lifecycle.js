// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Drives the @status lifecycle: experimental -> stable -> deprecated. Nothing
// else forces these transitions, so this gate surfaces them on every release.
//
// Reads each @primitive block's @status + @since, computes how many releases the
// primitive has run, and enforces conscious transitions through a ledger
// (lifecycle-reviews.json):
//
//   - An `experimental` primitive older than REVIEW_AFTER releases must carry a
//     dated `keep-experimental` decision in the ledger (with a future `reviewBy`
//     version) — otherwise the gate FAILS until it is graduated to `stable` or
//     the decision is re-recorded. This is the driver: silence is not an option.
//   - A `deprecated` primitive must declare `@deprecated <remove-by-version>`,
//     and the gate FAILS once that version is reached (blamejs Hard Rule #6 —
//     deprecations do not linger).
//
// The graduation criterion (documented in LTS-CALENDAR.md): a primitive becomes
// `stable` once its governing standard is settled AND it is interop-proven
// through the integration harness — not on a timer. The timer only forces the
// DECISION to be made and recorded.

var fs = require("fs");
var path = require("path");

var ROOT = path.resolve(__dirname, "..");
var LIB_DIR = path.join(ROOT, "lib");
var LEDGER_PATH = path.join(ROOT, "lifecycle-reviews.json");
var CURRENT = require(path.join(ROOT, "package.json")).version;

// Releases an experimental primitive may run before a graduation review is due.
// Pre-1.0 every ship is a patch, so "releases" is measured in patch increments.
var REVIEW_AFTER = 6;

var SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)$/;

function parseSemver(v) {
  var m = SEMVER_RE.exec(String(v || ""));
  return m ? { major: +m[1], minor: +m[2], patch: +m[3] } : null;
}

function cmpSemver(a, b) {
  var pa = parseSemver(a), pb = parseSemver(b);
  if (!pa || !pb) return NaN;
  if (pa.major !== pb.major) return pa.major - pb.major;
  if (pa.minor !== pb.minor) return pa.minor - pb.minor;
  return pa.patch - pb.patch;
}

// Number of releases between `since` and `current`. Pre-1.0 (same major.minor)
// that is the patch delta; a minor/major bump counts as "well past review".
function releaseAge(since, current) {
  var ps = parseSemver(since), pc = parseSemver(current);
  if (!ps || !pc) return NaN;
  if (ps.major !== pc.major || ps.minor !== pc.minor) return REVIEW_AFTER + Math.max(0, pc.patch - ps.patch) + 100;
  return pc.patch - ps.patch;
}

// Extract every @primitive block's status/since/remove-by from lib/*.js.
function parsePrimitives() {
  var out = [];
  fs.readdirSync(LIB_DIR).filter(function (f) { return /\.js$/.test(f); }).forEach(function (f) {
    var src = fs.readFileSync(path.join(LIB_DIR, f), "utf8");
    var blocks = src.match(/\/\*\*[\s\S]*?\*\//g) || [];
    blocks.forEach(function (b) {
      var prim = /@primitive\s+(\S+)/.exec(b);
      if (!prim) return;
      var status = /@status\s+(\S+)/.exec(b);
      var since = /@since\s+(\S+)/.exec(b);
      var dep = /@deprecated\s+(\S+)/.exec(b);
      out.push({
        primitive: prim[1],
        status: status ? status[1] : null,
        since: since ? since[1] : null,
        removeBy: dep ? dep[1] : null,
        file: "lib/" + f,
      });
    });
  });
  return out;
}

function loadLedger() {
  if (!fs.existsSync(LEDGER_PATH)) return {};
  return JSON.parse(fs.readFileSync(LEDGER_PATH, "utf8"));
}

// Pure evaluation (exported for the test): returns { failures, reminders }.
var KNOWN_STATUSES = { experimental: 1, stable: 1, deprecated: 1 };

function evaluate(primitives, ledger, current) {
  var failures = [], reminders = [];
  primitives.forEach(function (p) {
    // Every @primitive MUST declare a recognized @status. A missing or
    // misspelled one is not silently skipped — otherwise deleting @status on an
    // overdue experimental primitive would make it vanish from this gate.
    if (!p.status || !KNOWN_STATUSES[p.status]) {
      failures.push(p.primitive + " has a missing or unrecognized @status (" + (p.status || "none") + ") — declare @status experimental|stable|deprecated.");
      return;
    }
    if (p.status === "experimental") {
      if (!p.since) { failures.push(p.primitive + " is @status experimental but has no @since to age from."); return; }
      var age = releaseAge(p.since, current);
      if (isNaN(age)) { failures.push(p.primitive + " has an unparseable @since (" + p.since + ")."); return; }
      if (age < REVIEW_AFTER) return;
      var entry = ledger[p.primitive];
      // A conscious documented decision requires ALL of: keep-experimental, a
      // non-empty reason, the version it was reviewedAt, and a future reviewBy.
      // A bare { decision, reviewBy } is not a review — it must not pass the gate.
      var acknowledged = entry
        && entry.decision === "keep-experimental"
        && typeof entry.reason === "string" && entry.reason.trim().length > 0
        && entry.reviewedAt && parseSemver(entry.reviewedAt)
        && entry.reviewBy && parseSemver(entry.reviewBy) && cmpSemver(current, entry.reviewBy) < 0;
      if (!acknowledged) {
        failures.push(p.primitive + " has been experimental since " + p.since + " (" + age + " releases) and is due for a graduation review. Graduate it to `stable` (drop @status experimental) if its standard is settled and it is interop-proven, OR record a dated keep-experimental decision in lifecycle-reviews.json with a future reviewBy.");
      } else {
        reminders.push(p.primitive + " kept experimental by decision (re-review by " + entry.reviewBy + ").");
      }
    } else if (p.status === "deprecated") {
      if (!p.removeBy) { failures.push(p.primitive + " is @status deprecated but declares no `@deprecated <remove-by-version>`."); return; }
      if (!parseSemver(p.removeBy)) { failures.push(p.primitive + " @deprecated remove-by (" + p.removeBy + ") is not semver."); return; }
      if (cmpSemver(current, p.removeBy) >= 0) {
        failures.push(p.primitive + " is deprecated with remove-by " + p.removeBy + ", reached at " + current + " — remove it now (Hard Rule #6).");
      } else {
        reminders.push(p.primitive + " deprecated; scheduled for removal at " + p.removeBy + ".");
      }
    }
  });
  // A ledger entry for a primitive that is no longer experimental is stale noise.
  Object.keys(ledger).forEach(function (name) {
    var p = primitives.filter(function (x) { return x.primitive === name; })[0];
    if (!p) reminders.push("ledger entry for unknown primitive `" + name + "` — drop it.");
    else if (p.status !== "experimental") reminders.push("ledger entry for `" + name + "` is stale (now @status " + p.status + ") — drop it.");
  });
  return { failures: failures, reminders: reminders };
}

function main() {
  var res = evaluate(parsePrimitives(), loadLedger(), CURRENT);
  res.reminders.forEach(function (r) { console.log("[status-lifecycle] note: " + r); });
  if (res.failures.length) {
    res.failures.forEach(function (r) { console.error("[status-lifecycle] DUE: " + r); });
    console.error("[status-lifecycle] " + res.failures.length + " @status transition(s) due — see LTS-CALENDAR.md.");
    process.exit(1);
  }
  console.log("[status-lifecycle] OK - no @status transitions overdue (current " + CURRENT + ").");
}

module.exports = { evaluate: evaluate, releaseAge: releaseAge, cmpSemver: cmpSemver, REVIEW_AFTER: REVIEW_AFTER };

if (require.main === module) main();
