// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * check + counter — the framework's custom assertion + cross-file
 * counter (kept instead of node:test for now; the per-file split is
 * the modularity win, the assertion swap is orthogonal scope).
 *
 * One counter per process via this module's singleton-require
 * semantics. Each test file's CLI entry prints `CHECKS <n>` from
 * getChecks(); the smoke runner forks each file as its own process and
 * parses that line out of the child's stdout to aggregate the total.
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
  formatErr:          formatErr,
};
