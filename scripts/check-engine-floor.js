// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Engine-floor agreement gate.
 *
 * package.json "engines".node states the supported Node floor. That figure is
 * repeated in the runtime pins CI installs, the container the interop and smoke
 * phases run in, and the prose an operator reads before upgrading.
 *
 * This reads the floor from package.json and asserts every other statement of it
 * matches. A file named here that is missing is a finding, not a skip. Released
 * history is excluded: CHANGELOG.md and release-notes/ record the floor each
 * version shipped with and are not restated.
 *
 * Run locally:
 *   node scripts/check-engine-floor.js
 *   node scripts/check-engine-floor.js --json
 */

var fs   = require("node:fs");
var path = require("node:path");

var ROOT     = path.join(__dirname, "..");
var JSON_OUT = process.argv.indexOf("--json") !== -1;

function read(rel) {
  var p = path.join(ROOT, rel);
  if (!fs.existsSync(p)) return null;
  return fs.readFileSync(p, "utf8");
}

// The floor, as the package declares it. ">=24.21.0" -> {major:24, minor:21, patch:0}
function parseFloor() {
  var pkg = JSON.parse(read("package.json"));
  var spec = pkg && pkg.engines && pkg.engines.node;
  if (typeof spec !== "string") throw new Error("package.json engines.node is missing");
  var digits = spec.replace(/^[^0-9]*/, "");
  var parts = digits.split(".");
  if (parts.length < 3) throw new Error("package.json engines.node must name major.minor.patch, got " + spec);
  var n = parts.map(Number);
  if (n.some(function (x) { return !Number.isInteger(x) || x < 0; })) {
    throw new Error("package.json engines.node is not a version: " + spec);
  }
  return { spec: spec, major: n[0], minor: n[1], patch: n[2], full: n[0] + "." + n[1] + "." + n[2] };
}

// Every file that states the floor, and how to read the statement out of it.
// A file listed here with no match is a finding: the statement was expected.
function sites(f) {
  return [
    { file: ".nvmrc", want: f.full, find: function (s) { return [s.trim()]; } },
    { file: "examples/wiki/package.json", want: ">=" + f.full,
      find: function (s) { var j = JSON.parse(s); return [j.engines && j.engines.node]; } },
    { file: "package-lock.json", want: ">=" + f.full,
      find: function (s) { var j = JSON.parse(s); return [j.packages && j.packages[""] && j.packages[""].engines && j.packages[""].engines.node]; } },
    { file: "examples/wiki/package-lock.json", want: ">=" + f.full,
      find: function (s) { var j = JSON.parse(s); return [j.packages && j.packages[""] && j.packages[""].engines && j.packages[""].engines.node]; } },
    { file: "docker-compose.test.yml", want: "node:" + f.full + "-alpine",
      find: function (s) { return matchAll(s, /image:\s*(node:[^\s]+)/g); } },
    { file: ".github/workflows/ci.yml", want: f.full, find: findNodeVersions },
    { file: ".github/workflows/npm-publish.yml", want: f.full, find: findNodeVersions },
    { file: ".github/workflows/release-container.yml", want: f.full, find: findNodeVersions },
  ];
}

function matchAll(s, re) {
  var out = [], m;
  while ((m = re.exec(s)) !== null) out.push(m[1]);
  return out;
}

// setup-node pins. A bare major ('24') states no minor, so only fully-qualified
// values are held to the floor.
function findNodeVersions(s) {
  return matchAll(s, /node-version:\s*'?"?([0-9][^'"\s]*)'?"?/g)
    .filter(function (v) { return v.split(".").length >= 3; });
}

// Prose and comments that name a Node version. Any 24.x that is not the floor is
// stale. A bare major does not state a minor and is left alone.
var PROSE = [
  "README.md", "CONTRIBUTING.md", "SUPPORT.md", "SECURITY.md", "LTS-CALENDAR.md",
  "lib/vendor/README.md", "lib/vendor/MANIFEST.json", "lib/tls-cert-compress.js",
  "scripts/generate-release-signing-key.js",
];

function main() {
  var f = parseFloor();
  var findings = [];

  sites(f).forEach(function (site) {
    var src = read(site.file);
    if (src === null) { findings.push({ file: site.file, problem: "missing", want: site.want }); return; }
    var found;
    try { found = site.find(src).filter(function (v) { return v !== null && v !== undefined; }); }
    catch (e) { findings.push({ file: site.file, problem: "unreadable: " + e.message, want: site.want }); return; }
    if (found.length === 0) { findings.push({ file: site.file, problem: "states no version", want: site.want }); return; }
    found.forEach(function (got) {
      if (got !== site.want) findings.push({ file: site.file, problem: "says " + got, want: site.want });
    });
  });

  // A named file that is gone is a finding rather than a skip. A renamed document that quietly
  // stops being checked is how a stale floor survives a gate that reports OK.
  PROSE.forEach(function (rel) {
    var src = read(rel);
    if (src === null) { findings.push({ file: rel, problem: "missing", want: "a document stating the floor, or removal from PROSE" }); return; }
    src.split("\n").forEach(function (line, i) {
      matchAll(line, /\b(\d+\.\d+(?:\.\d+)?)\b/g).forEach(function (v) {
        var p = v.split(".");
        if (Number(p[0]) !== f.major) return;
        if (Number(p[1]) === f.minor) return;
        findings.push({ file: rel + ":" + (i + 1), problem: "names Node " + v, want: f.major + "." + f.minor });
      });
    });
  });

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({ floor: f.full, findings: findings }, null, 2) + "\n");
  } else if (findings.length === 0) {
    process.stdout.write("[engine-floor] OK: every pin and every statement agrees with engines.node " + f.spec + "\n");
  } else {
    process.stderr.write("[engine-floor] the declared floor is " + f.spec + ", and these disagree:\n");
    findings.forEach(function (x) {
      process.stderr.write("  " + x.file + ": " + x.problem + " (expected " + x.want + ")\n");
    });
  }
  process.exit(findings.length === 0 ? 0 : 1);
}

module.exports = { _parseFloor: parseFloor };

if (require.main === module) {
  try { main(); }
  catch (e) {
    process.stderr.write("[engine-floor] script crashed: " + ((e && e.stack) || e) + "\n");
    process.exit(2);
  }
}
