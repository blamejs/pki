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
var MERGE = path.join(COV, "tmp-merged");
var C8 = path.join(ROOT, "node_modules", "c8", "bin", "c8.js");
var INCLUDE = ["--include=lib/**", "--include=index.js"];
var detail = process.argv.indexOf("--detail") >= 0;

fs.rmSync(COV, { recursive: true, force: true });
fs.mkdirSync(MERGE, { recursive: true });

// One coverage layer: run its entrypoint under node with NODE_V8_COVERAGE pointed at a PER-LAYER directory,
// and fold that directory into the shared MERGE set ONLY on success. A required layer that exits non-zero
// fails the whole run; a best-effort layer that exits non-zero has its coverage DISCARDED (the per-layer dir
// is removed, never merged) -- so partial execution from a suite that loaded lib and then failed can never
// inflate the merged floor or satisfy check-swallow-coverage with a failed run's hits.
function layer(opts) {
  process.stdout.write("\n[coverage-unified] === " + opts.label + " ===\n");
  var layerDir = path.join(COV, "tmp-" + opts.slug);
  fs.rmSync(layerDir, { recursive: true, force: true });
  fs.mkdirSync(layerDir, { recursive: true });
  var env = Object.assign({}, process.env, { NODE_V8_COVERAGE: layerDir });
  var r = spawnSync(process.execPath, opts.cmd, { cwd: opts.cwd || ROOT, stdio: "inherit", env: env });
  if (r.status !== 0) {
    fs.rmSync(layerDir, { recursive: true, force: true });   // discard a failed layer's coverage -- never merge it
    if (opts.required) { process.stderr.write("[coverage-unified] " + opts.label + " FAILED (exit " + r.status + ") -- required layer\n"); process.exit(r.status || 1); }
    process.stderr.write("[coverage-unified] " + opts.label + " skipped (exit " + r.status + ") -- coverage discarded, continuing\n");
    return false;
  }
  fs.readdirSync(layerDir).forEach(function (fn) { fs.renameSync(path.join(layerDir, fn), path.join(MERGE, fn)); });
  fs.rmSync(layerDir, { recursive: true, force: true });
  return true;
}

layer({ slug: "smoke", label: "smoke", cmd: [path.join("test", "smoke.js")], required: true });
layer({ slug: "integration", label: "integration (cross-implementation)", cmd: [path.join("scripts", "test-integration.js")], required: true });
layer({ slug: "wiki", label: "wiki e2e", cmd: [path.join("test", "e2e.js")], cwd: path.join(ROOT, "examples", "wiki"), required: false });

process.stdout.write("\n[coverage-unified] === merged cross-layer report ===\n");
var reporters = ["--reporter=text-summary", "--reporter=lcov"];
if (detail) reporters.push("--reporter=text");
var report = spawnSync(
  process.execPath,
  [C8, "report", "--temp-directory=" + MERGE, "--reports-dir=" + COV].concat(INCLUDE, reporters),
  { cwd: ROOT, stdio: "inherit", env: process.env }
);
process.exit(report.status || 0);
