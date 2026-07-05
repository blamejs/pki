// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/test-integration.js
 *
 * Interop integration runner. Confirms the cross-checking toolchain is
 * present (scripts/check-services.js), then spawns each file in
 * test/integration/ as its own node process and aggregates the per-file
 * "CHECKS <n>" counts.
 *
 * Each integration file drives a real, independent implementation (the
 * `openssl` CLI today) as an oracle so a certificate / CMS / PKCS#12
 * structure the toolkit emits is validated by something other than its own
 * decoder. A fresh process per file contains a crash or leaked handle to
 * one file and keeps the check counter isolated.
 *
 * Distinct from test/smoke.js — the smoke gate must stay pure (runs in CI,
 * on a laptop with no external toolchain) and must never "skip silently
 * when the oracle is down," which would make its pass count misleading.
 *
 * Exit codes:
 *   0 — every integration file passed
 *   1 — required cross-checker unreachable (install it, or run the compose
 *       interop service); re-run with --skip-service-check to bypass
 *   2 — at least one file threw / returned non-zero
 *   3 — script-level error (no files found, bad dir)
 *
 * Usage:
 *   node scripts/test-integration.js
 *   node scripts/test-integration.js x509-openssl-interop     — one file
 *   node scripts/test-integration.js --skip-service-check     — assume ready
 */

var fs   = require("node:fs");
var path = require("node:path");
var spawn = require("node:child_process").spawn;

var INTEGRATION_DIR = path.join(__dirname, "..", "test", "integration");
var CHECK_SERVICES  = path.join(__dirname, "check-services.js");

function _padRight(s, n) {
  s = String(s);
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function _spawn(cmd, args, opts) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, Object.assign({ stdio: "inherit" }, opts || {}));
    child.once("exit", function (code, signal) { resolve({ code: code, signal: signal }); });
    child.once("error", reject);
  });
}

function _spawnCapturing(cmd, args, env) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, { env: env, stdio: ["ignore", "pipe", "pipe"] });
    var stdout = "";
    var stderr = "";
    child.stdout.on("data", function (b) { stdout += b.toString(); });
    child.stderr.on("data", function (b) { stderr += b.toString(); });
    child.once("exit", function (code, signal) {
      resolve({ code: code, signal: signal, stdout: stdout, stderr: stderr });
    });
    child.once("error", reject);
  });
}

(async function main() {
  var args = process.argv.slice(2);
  var skipCheck = args.indexOf("--skip-service-check") !== -1;
  var named = args.filter(function (a) { return a.charAt(0) !== "-"; });

  if (!fs.existsSync(INTEGRATION_DIR)) {
    console.error("[test-integration] missing dir: " + INTEGRATION_DIR);
    process.exit(3);
  }

  var files = fs.readdirSync(INTEGRATION_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); })
    .filter(function (f) {
      if (named.length === 0) return true;
      return named.some(function (n) { return f === n || f === n + ".test.js"; });
    })
    .sort();

  if (files.length === 0) {
    console.error("[test-integration] no test files matched " +
      (named.length === 0 ? "test/integration/*.test.js" : named.join(", ")));
    process.exit(3);
  }

  if (!skipCheck) {
    console.log("[test-integration] running scripts/check-services.js gate...");
    var checkExit = await _spawn(process.execPath, [CHECK_SERVICES]);
    if (checkExit.code !== 0) {
      console.error("[test-integration] service-check gate failed (exit " + checkExit.code + ")");
      console.error("[test-integration] install the cross-checker (openssl) or run the compose service:");
      console.error("[test-integration]   docker compose -f docker-compose.test.yml run --rm interop");
      console.error("[test-integration] OR re-run with --skip-service-check to bypass");
      process.exit(1);
    }
  }

  console.log("");
  console.log("[test-integration] running " + files.length + " integration file" +
    (files.length === 1 ? "" : "s") + " (each in a fresh node process)...");
  var suiteStart = Date.now();
  var failed = 0;
  var totalChecks = 0;
  var totalSkips = 0;
  for (var i = 0; i < files.length; i++) {
    var fullPath = path.join(INTEGRATION_DIR, files[i]);
    var fileStart = Date.now();
    var rv;
    try {
      rv = await _spawnCapturing(process.execPath, [fullPath], process.env);
    } catch (err) {
      failed += 1;
      console.error("  " + _padRight(files[i], 40) + " SPAWN FAILED");
      console.error("    " + (err.message || String(err)));
      continue;
    }
    var ms = Date.now() - fileStart;
    var m = /CHECKS\s+(\d+)/.exec(rv.stdout || "");
    var checks = m ? parseInt(m[1], 10) : 0;
    // A cross-check the oracle can't perform is reported as a SKIP, never folded
    // into the pass count, so "N checks passed" is not inflated by skips.
    var sm = /SKIPS\s+(\d+)/.exec(rv.stdout || "");
    var skips = sm ? parseInt(sm[1], 10) : 0;
    if (rv.code === 0) {
      totalChecks += checks;
      totalSkips += skips;
      console.log("  " + _padRight(files[i], 40) + " (" + ms + "ms, " + checks + " checks" +
        (skips > 0 ? ", " + skips + " skipped" : "") + ")");
    } else {
      failed += 1;
      console.error("  " + _padRight(files[i], 40) + " FAILED (exit " + rv.code + ")");
      var lines = (rv.stderr || rv.stdout || "").split(/\r?\n/).filter(Boolean).slice(-12);
      lines.forEach(function (l) { console.error("    " + l); });
    }
  }
  console.log("");
  if (failed === 0) {
    console.log("[test-integration] OK — " + totalChecks + " checks passed" +
      (totalSkips > 0 ? " (" + totalSkips + " cross-check(s) skipped — oracle capability absent)" : "") +
      " across " + files.length + " file(s) in " + (Date.now() - suiteStart) + "ms");
    process.exit(0);
  }
  console.error("[test-integration] " + failed + " of " + files.length + " file(s) failed");
  process.exit(2);
})().catch(function (err) {
  console.error("[test-integration] runner error: " + ((err && err.stack) || err));
  process.exit(3);
});
