// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Unified cross-layer branch coverage. `npm run coverage` measures c8 over the smoke
// suite ONLY; it misses lib branches exercised by the cross-implementation integration
// suite (the encode -> reconstruct path an OpenSSL/NSS oracle validates) and the wiki
// e2e (the source-driven doc generator). This runner accumulates all three under one
// shared V8-coverage directory and emits a single merged report + lcov, so the coverage
// floor reflects EVERY test layer -- the honest number to rank the least-covered modules
// against and drive up. It writes coverage/lcov.info, so `check-swallow-coverage` runs
// against the merged report too.
//
//   node scripts/coverage-unified.js            merged text-summary + lcov
//   node scripts/coverage-unified.js --detail   also the per-file table
//
// The smoke and integration layers are required (a failing layer fails the run); the
// wiki e2e is best-effort (a missing local wiki toolchain warns and is skipped rather
// than failing the coverage number for the layers that did run).
//
// Each layer runs its entrypoint DIRECTLY under node with NODE_V8_COVERAGE pointed at
// the shared directory (child test processes inherit it), so raw V8 coverage from every
// layer accumulates; `c8 report --temp-directory` then merges it. This avoids wrapping
// each command through the c8 CLI (whose argument parsing differs per layer cwd).

var spawnSync = require("node:child_process").spawnSync;
var path = require("node:path");
var fs = require("node:fs");

var ROOT = path.resolve(__dirname, "..");
var COV = path.join(ROOT, "coverage");
var TMP = path.join(COV, "tmp-unified");
var C8 = path.join(ROOT, "node_modules", "c8", "bin", "c8.js");
var INCLUDE = ["--include=lib/**", "--include=index.js"];
var detail = process.argv.indexOf("--detail") >= 0;

fs.rmSync(COV, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });

var covEnv = Object.assign({}, process.env, { NODE_V8_COVERAGE: TMP });

// One coverage layer: run its entrypoint under node with NODE_V8_COVERAGE set. A required
// layer that exits non-zero fails the run; a best-effort layer only warns and is skipped.
function layer(opts) {
  process.stdout.write("\n[coverage-unified] === " + opts.label + " ===\n");
  var r = spawnSync(process.execPath, opts.cmd, { cwd: opts.cwd || ROOT, stdio: "inherit", env: covEnv });
  if (r.status !== 0) {
    if (opts.required) { process.stderr.write("[coverage-unified] " + opts.label + " FAILED (exit " + r.status + ") -- required layer\n"); process.exit(r.status || 1); }
    process.stderr.write("[coverage-unified] " + opts.label + " skipped (exit " + r.status + ") -- best-effort layer, continuing\n");
    return false;
  }
  return true;
}

layer({ label: "smoke", cmd: [path.join("test", "smoke.js")], required: true });
layer({ label: "integration (cross-implementation)", cmd: [path.join("scripts", "test-integration.js")], required: true });
layer({ label: "wiki e2e", cmd: [path.join("test", "e2e.js")], cwd: path.join(ROOT, "examples", "wiki"), required: false });

process.stdout.write("\n[coverage-unified] === merged cross-layer report ===\n");
var reporters = ["--reporter=text-summary", "--reporter=lcov"];
if (detail) reporters.push("--reporter=text");
var report = spawnSync(
  process.execPath,
  [C8, "report", "--temp-directory=" + TMP, "--reports-dir=" + COV].concat(INCLUDE, reporters),
  { cwd: ROOT, stdio: "inherit", env: process.env }
);
process.exit(report.status || 0);
