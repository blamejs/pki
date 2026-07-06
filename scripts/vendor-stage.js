#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// vendor-stage.js — resolve a package spec to an integrity-pinned lockfile
// in an isolated staging workspace (the resolution half of the vendoring
// flow driven by scripts/vendor-update.sh).
//
// Writes <stage>/package.json depending on exactly <package>@<version>,
// then resolves the full dependency tree to <stage>/package-lock.json with
// `npm install --package-lock-only` — a metadata-only resolution: no
// tarball is downloaded and no install script runs. The caller installs
// from that lockfile with `npm ci --ignore-scripts`, which verifies every
// package against its recorded integrity hash before a byte of it is
// bundled. This is the same lockfile-backed discipline scripts/pin-all.js
// maintains for the repo's own committed workspaces, applied to the
// throwaway staging directory a vendoring run uses.
//
// Usage: node scripts/vendor-stage.js <package> <version> <stage-dir>

var fs = require("node:fs");
var path = require("node:path");
var cp = require("node:child_process");

var pkg = process.argv[2];
var ver = process.argv[3] || "latest";
var stage = process.argv[4];
if (!pkg || !stage) {
  console.error("Usage: node scripts/vendor-stage.js <package> <version> <stage-dir>");
  process.exit(1);
}
if (!fs.existsSync(stage) || !fs.statSync(stage).isDirectory()) {
  console.error("vendor-stage: staging directory does not exist: " + stage);
  process.exit(1);
}

var manifest = { name: "vendor-stage", version: "0.0.0", private: true, dependencies: {} };
manifest.dependencies[pkg] = ver;
fs.writeFileSync(path.join(stage, "package.json"), JSON.stringify(manifest, null, 2) + "\n");

// The staging dir lives outside the repo, so the repo .npmrc does not
// apply — every behavior the resolution needs rides as an explicit flag.
// One command STRING (not an args array + shell): Windows needs a shell
// for the npm .cmd shim, and a shell concatenates an args array without
// escaping (Node's DEP0190). Every token is a static flag literal; the
// package spec rides in the staged package.json, never on this line.
var r = cp.spawnSync(
  "npm install --package-lock-only --ignore-scripts --no-audit --no-fund --save-exact",
  { cwd: stage, stdio: "inherit", shell: true });
if (r.status !== 0) {
  console.error("vendor-stage: lockfile resolution failed for " + pkg + "@" + ver);
  process.exit(1);
}
console.log("vendor-stage: " + pkg + "@" + ver + " resolved to " + path.join(stage, "package-lock.json"));
