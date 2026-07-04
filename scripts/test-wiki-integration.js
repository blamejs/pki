// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/test-wiki-integration.js
 *
 * Wiki-app integration runner. Boots the source-driven documentation site
 * (examples/wiki) through the same path an operator runs and drives its
 * end-to-end suite: the HTTP server on an ephemeral port, every generated
 * namespace page, and the comment-block validator against the toolkit's
 * lib/.
 *
 * The @blamejs/pki wiki has NO network backends — the toolkit itself talks
 * to no services, and the site is generated entirely from the toolkit's own
 * @module/@primitive comment blocks. So this runner needs no docker stack,
 * no CA export, and no rejectUnauthorized bypass: it simply exercises the
 * wiki's real boot path end-to-end. It complements
 * `scripts/test-integration.js` (the toolkit's OpenSSL interop cross-check)
 * and `test/smoke.js` (the pure primitive suite).
 *
 * Usage:
 *   node scripts/test-wiki-integration.js
 *
 * Exit codes:
 *   0 — wiki integration passed
 *   2 — wiki integration failed
 *   3 — runner error (missing test file, spawn failure, etc.)
 */

var fs    = require("node:fs");
var path  = require("node:path");
var spawn = require("node:child_process").spawn;

var ROOT           = path.join(__dirname, "..");
var WIKI_DIR       = path.join(ROOT, "examples", "wiki");
var WIKI_TEST_FILE = path.join(WIKI_DIR, "test", "e2e.js");

function _spawnCapturing(cmd, args, opts) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, Object.assign({ stdio: ["ignore", "pipe", "pipe"] }, opts || {}));
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
  if (!fs.existsSync(WIKI_TEST_FILE)) {
    console.error("[test-wiki-integration] missing test file: " + WIKI_TEST_FILE);
    process.exit(3);
  }

  // Clean generated data dirs so a stale build can't mask a regression
  // (mirrors the release-flow wiki-e2e reset).
  ["data", "data-e2e"].forEach(function (d) {
    try { fs.rmSync(path.join(WIKI_DIR, d), { recursive: true, force: true }); } catch (_e) { /* ignore */ }
  });

  console.log("[test-wiki-integration] booting wiki + running e2e suite...");
  var start = Date.now();
  var childEnv = Object.assign({}, process.env, { PKIJS_INTEGRATION_RUNNER: "1" });
  var rv = await _spawnCapturing(process.execPath, [WIKI_TEST_FILE], {
    cwd: WIKI_DIR,
    env: childEnv,
  });
  var ms = Date.now() - start;

  // Stream child output so the operator sees the assertions + the CHECKS
  // count the wiki e2e prints on success.
  process.stdout.write(rv.stdout);
  if (rv.stderr) process.stderr.write(rv.stderr);

  console.log("");
  if (rv.code === 0) {
    console.log("[test-wiki-integration] OK — wiki integration green in " + ms + "ms");
    process.exit(0);
  }
  console.error("[test-wiki-integration] FAIL — wiki integration failed (exit " + rv.code + ", " + ms + "ms)");
  process.exit(2);
})().catch(function (err) {
  console.error("[test-wiki-integration] runner error: " + ((err && err.stack) || err));
  process.exit(3);
});
