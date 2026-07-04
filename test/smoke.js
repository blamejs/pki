// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Smoke test — orchestrator.
 *
 * Run: `npm test` (or `node test/smoke.js`)
 *
 * Tests run in dependency order (lowest layer first). Each layer is a
 * `test/layer-N-<name>/` directory of per-primitive `*.test.js` files:
 *
 *   Layer 0 — pure primitives   test/layer-0-primitives/*.test.js
 *   (further layers are added as the toolkit grows a state / consumer
 *    surface — the walker picks up any `test/layer-*-*` directory)
 *
 * Per-file layout:
 *   - One file per primitive, named `<thing>.test.js`.
 *   - Exports `run()` (sync or async).
 *   - Has a CLI entry: `node test/layer-0-primitives/asn1-der.test.js`
 *     runs that file standalone and prints `CHECKS <n>`.
 *
 * The orchestrator forks each file as its own process (so a crash or a
 * leaked handle is contained to one file), aggregates the per-file check
 * counts, and reports per-file timing. `SMOKE_PARALLEL=N` runs up to N
 * files concurrently; the default is serial.
 *
 * Every line of output is persisted to `.test-output/smoke.log` via
 * synchronous fd writes, so a failing run's detail is on disk even if the
 * process dies mid-run — read the log instead of re-running.
 */

var fs    = require("node:fs");
var path  = require("node:path");
var os    = require("node:os");
var { spawn } = require("node:child_process");
var helpers = require("./helpers");
var pki     = helpers.pki;

// ---- Persistent output ----
var REPO_ROOT  = path.resolve(__dirname, "..");
var OUTPUT_DIR = path.join(REPO_ROOT, ".test-output");
try { fs.mkdirSync(OUTPUT_DIR, { recursive: true }); } catch (_e) { /* best-effort */ }
var LOG_PATH = path.join(OUTPUT_DIR, "smoke.log");
try { fs.unlinkSync(LOG_PATH); } catch (_e) { /* fresh start */ }
var _logFd = fs.openSync(LOG_PATH, "w");
function _logWrite(chunk) {
  try {
    var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
    fs.writeSync(_logFd, buf, 0, buf.length, null);
  } catch (_e) { /* best-effort */ }
}
var _origStdoutWrite = process.stdout.write.bind(process.stdout);
process.stdout.write = function (chunk, encoding, cb) { _logWrite(chunk); return _origStdoutWrite(chunk, encoding, cb); };
process.on("exit", function () { try { fs.closeSync(_logFd); } catch (_e) { /* best-effort */ } });

console.log("@blamejs/pki v" + pki.version + " — smoke test");
console.log("output: " + LOG_PATH);

var PARALLEL = Math.max(1, parseInt(process.env.SMOKE_PARALLEL || "1", 10) || 1);

function _discover() {
  var files = [];
  var entries = fs.readdirSync(__dirname, { withFileTypes: true })
    .filter(function (e) { return e.isDirectory() && /^layer-\d+-/.test(e.name); })
    .map(function (e) { return e.name; })
    .sort();
  entries.forEach(function (dir) {
    var full = path.join(__dirname, dir);
    fs.readdirSync(full)
      .filter(function (f) { return f.endsWith(".test.js"); })
      .sort()
      .forEach(function (f) { files.push({ layer: dir, file: path.join(full, f), name: f }); });
  });
  return files;
}

function _runOne(entry) {
  return new Promise(function (resolve) {
    var started = Date.now();
    var child = spawn(process.execPath, [entry.file], { stdio: ["ignore", "pipe", "pipe"] });
    var out = "";
    child.stdout.on("data", function (d) { out += d.toString(); });
    child.stderr.on("data", function (d) { out += d.toString(); });
    child.on("close", function (code) {
      var ms = Date.now() - started;
      var m = /CHECKS\s+(\d+)/.exec(out);
      var checks = m ? parseInt(m[1], 10) : 0;
      resolve({ entry: entry, code: code, checks: checks, ms: ms, out: out });
    });
    child.on("error", function (e) {
      resolve({ entry: entry, code: 1, checks: 0, ms: Date.now() - started, out: String(e && e.stack || e) });
    });
  });
}

async function _pool(items, worker, concurrency) {
  var results = new Array(items.length);
  var next = 0;
  async function lane() {
    for (;;) {
      var i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  }
  var lanes = [];
  for (var k = 0; k < Math.min(concurrency, items.length); k++) lanes.push(lane());
  await Promise.all(lanes);
  return results;
}

(async function main() {
  var files = _discover();
  if (!files.length) {
    console.error("no test files discovered under test/layer-*-*/");
    process.exit(1);
    return;
  }
  console.log("running " + files.length + " file(s), parallelism " + PARALLEL + " on " + os.type());
  var results = await _pool(files, _runOne, PARALLEL);

  var totalChecks = 0;
  var failures = [];
  var currentLayer = "";
  results.forEach(function (r) {
    if (r.entry.layer !== currentLayer) { currentLayer = r.entry.layer; console.log("\n" + currentLayer); }
    var status = r.code === 0 ? "ok " : "FAIL";
    console.log("  " + status + "  " + r.entry.name + "  (" + r.ms + "ms, " + r.checks + " checks)");
    if (r.code === 0) { totalChecks += r.checks; }
    else { failures.push(r); }
  });

  if (failures.length) {
    console.error("\n" + failures.length + " file(s) FAILED:");
    failures.forEach(function (r) {
      console.error("\n=== " + r.entry.layer + " / " + r.entry.name + " (exit " + r.code + ") ===");
      console.error(r.out.trim().split("\n").slice(-25).join("\n"));
    });
    process.exit(1);
    return;
  }
  console.log("\nOK — " + totalChecks + " checks passed across " + files.length + " file(s)");
})();
