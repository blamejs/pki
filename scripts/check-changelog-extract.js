#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Pre-push static gate — exercise the CHANGELOG section extract that the
 * release workflow runs to pull the current version's notes into the
 * published GitHub Release / npm release notes.
 *
 * Running it locally before tag-push means CHANGELOG format drift (a new
 * entry that doesn't match the canonical `## vX.Y.Z — YYYY-MM-DD` header)
 * fails at the desk instead of mid-workflow.
 *
 * Exit codes:
 *   0  — extract produced >= 1 lines AND the header matches the canonical
 *        `## vX.Y.Z — YYYY-MM-DD` shape
 *   1  — no entry found OR header shape malformed
 *
 * Usage:
 *   node scripts/check-changelog-extract.js          # uses package.json version
 *   node scripts/check-changelog-extract.js 0.1.0    # explicit version
 */

var fs   = require("node:fs");
var path = require("node:path");

var ROOT         = path.resolve(__dirname, "..");
var CHANGELOG    = path.join(ROOT, "CHANGELOG.md");
var PACKAGE_JSON = path.join(ROOT, "package.json");

function readPackageVersion() {
  var pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON, "utf8"));
  return pkg.version;
}

// Pull the block from the `## v<version> — <date>` header up to (but not
// including) the next `## v` header or end of file.
function extractSection(text, version) {
  var lines = text.split(/\r?\n/);
  var out = [];
  var capturing = false;
  var headerRe = /^## v(\d+\.\d+\.\d+)\b/;
  for (var i = 0; i < lines.length; i += 1) {
    var ln = lines[i];
    var m = ln.match(headerRe);
    if (m) {
      if (capturing) break;              // next version header ends the block
      if (m[1] === version) {
        capturing = true;
        out.push(ln);
        continue;
      }
    }
    if (capturing) out.push(ln);
  }
  // Trim trailing blank lines so the "section length" reflects real content.
  while (out.length > 0 && out[out.length - 1].trim() === "") out.pop();
  return out;
}

function main() {
  var version = process.argv[2] || readPackageVersion();
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    console.error("[check-changelog-extract] FAIL: bad version arg: " +
      JSON.stringify(version) + " (expected `MAJOR.MINOR.PATCH`)");
    process.exit(1);
  }

  var text;
  try { text = fs.readFileSync(CHANGELOG, "utf8"); }
  catch (e) {
    console.error("[check-changelog-extract] FAIL: cannot read CHANGELOG.md: " +
      ((e && e.message) || e));
    process.exit(1);
  }

  var section = extractSection(text, version);
  if (section.length === 0) {
    console.error("[check-changelog-extract] FAIL: no CHANGELOG entry found for v" + version);
    console.error("[check-changelog-extract] Expected a header matching `## v" + version +
      " — YYYY-MM-DD`.");
    console.error("[check-changelog-extract] The release workflow's notes extract will produce 0 lines and refuse to publish.");
    process.exit(1);
  }

  // The header line must match the canonical shape — `## vX.Y.Z — YYYY-MM-DD`
  // (em-dash separator). The date lets the workflow stamp the release.
  var header = section[0];
  var canonical = new RegExp(
    "^## v" + version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
    " \\u2014 \\d{4}-\\d{2}-\\d{2}\\s*$"
  );
  if (!canonical.test(header)) {
    console.error("[check-changelog-extract] FAIL: v" + version +
      " header does not match the canonical shape:");
    console.error("[check-changelog-extract]   expected: `## v" + version + " — YYYY-MM-DD`");
    console.error("[check-changelog-extract]   got:       " + JSON.stringify(header));
    process.exit(1);
  }

  console.log("[check-changelog-extract] OK — v" + version + " entry extracts cleanly (" +
    section.length + " line(s)); header shape canonical.");
}

main();
