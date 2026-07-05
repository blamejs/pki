// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * check + counter — the framework's custom assertion + cross-file
 * counter (kept instead of node:test for now; the per-file split is
 * the modularity win, the assertion swap is orthogonal scope).
 *
 * One global counter shared by every test file via this module's
 * singleton-require semantics. The smoke runner reads getChecks()
 * after walking every layer to print the total.
 */

var _checks = 0;
var _skips = [];

function check(label, condition) {
  if (!condition) throw new Error("FAIL: " + label);
  _checks += 1;
}

// skip(reason) — record a check that COULD NOT run because a precondition the
// test does not control was absent (e.g. the OpenSSL interop oracle predates a
// signature algorithm). A skip is NOT a pass: it increments a separate counter,
// never `_checks`, so a run that skipped a cross-check does not report the same
// "N passed" as one that actually ran it. Never fake a skip with
// `check(<reason>, true)` — that is exactly the skip-counted-as-pass that hides
// missing coverage.
function skip(reason) {
  _skips.push(String(reason));
  console.log("  SKIP: " + reason);
}

function getChecks()         { return _checks; }
function getSkips()          { return _skips.length; }
function getSkipReasons()    { return _skips.slice(); }
function resetChecksForTest() { _checks = 0; _skips = []; }

// addExternalChecks — the parallel smoke runner forks per-file
// children; each child runs its own _checks counter in its process
// and reports it back to the parent. The parent calls this to fold
// the children's counts into the parent total so the final
// "OK — N checks passed" line aggregates correctly.
function addExternalChecks(n) {
  if (typeof n === "number" && isFinite(n) && n >= 0) _checks += n;
}

// formatErr — render a thrown error as a single-line, bounded diagnostic for a
// test runner's failure catch. A thrown error's message/stack can carry a test
// fixture's bytes verbatim; replacing CR/LF (a recognized log-injection
// barrier) keeps the "FAIL:" line on one row so a fixture value can't forge
// extra log lines. The newline .replace() is what breaks the log-injection
// data flow; the tab/run-collapse + length bound are cosmetic.
function formatErr(e) {
  var raw = (e && typeof e.stack === "string" && e.stack) ||
            (e && typeof e.message === "string" && e.message) ||
            String(e);
  var oneLine = raw
    .replace(/[\r\n]+/g, " ")
    .replace(/\t+/g, " ")
    .replace(/ {2,}/g, " ");
  return oneLine.length > 2000 ? oneLine.slice(0, 2000) + "..." : oneLine;
}

module.exports = {
  check:              check,
  skip:               skip,
  getChecks:          getChecks,
  getSkips:           getSkips,
  getSkipReasons:     getSkipReasons,
  resetChecksForTest: resetChecksForTest,
  addExternalChecks:  addExternalChecks,
  formatErr:          formatErr,
};
