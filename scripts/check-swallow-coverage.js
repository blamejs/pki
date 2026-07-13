// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// check-swallow-coverage -- the execution-traced swallow gate.
//
// A `catch (e) { ... }` that does NOT re-throw is a SWALLOW: it converts a thrown fault
// into a returned value / recorded verdict. A swallow is only safe if it fails CLOSED --
// and the way this gate proves that, WITHOUT an allowlist of "known-good" swallows, is by
// EXECUTION: every swallow's catch body MUST be exercised by the test suite (its lines
// carry a non-zero hit in the c8 lcov report). A test that drives the error path and still
// passes is live proof the swallow behaves as the suite asserts; a swallow no test ever
// enters is an unproven fail-open risk.
//
// So the gate is: for every lib swallow, either
//   - the catch RE-THROWS (propagates -- fail-closed by construction), or
//   - the catch body is COVERED (a test drives it, asserting its fail-closed verdict), or
//   - it carries an `allow:swallow-unverified <reason>` marker (a deliberate, documented
//     drop-silent sink -- the escape hatch of last resort, never the default).
// An uncovered, unmarked, non-re-throwing swallow FAILS the gate: add a RED vector that
// drives the catch, or re-throw.
//
// Runs AFTER `npm run coverage` (which writes coverage/lcov.info). Reads that report; it
// does not run the suite itself.

var fs = require("fs");
var path = require("path");

var REPO_ROOT = path.resolve(__dirname, "..");
var LIB_DIR = path.join(REPO_ROOT, "lib");
var LCOV = path.join(REPO_ROOT, "coverage", "lcov.info");

// ---- lcov: per-file { line -> hitCount } -----------------------------------
function parseLcov(text) {
  var byFile = {};
  var cur = null;
  text.split(/\r?\n/).forEach(function (line) {
    if (line.indexOf("SF:") === 0) { cur = {}; byFile[_norm(line.slice(3))] = cur; return; }
    if (line.indexOf("DA:") === 0 && cur) {
      var parts = line.slice(3).split(",");
      cur[parseInt(parts[0], 10)] = parseInt(parts[1], 10);
    }
  });
  return byFile;
}
// Normalise an lcov SF path to a repo-relative lib/<file> key (paths may be absolute or
// backslash-separated on Windows).
function _norm(p) {
  p = p.replace(/\\/g, "/");
  var i = p.indexOf("lib/");
  return i >= 0 ? p.slice(i) : p;
}

// ---- static: enumerate catch swallows --------------------------------------
// Strip line comments + block comments + string/regex literals so a `throw`/`return`
// inside a comment or string never counts. (A light strip: enough for catch bodies.)
function _strip(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, function (m) { return m.replace(/[^\n]/g, " "); })
    .replace(/\/\/[^\n]*/g, "")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""')
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/`(?:[^`\\]|\\.)*`/g, "``");
}

function findSwallows(rel, src) {
  var stripped = _strip(src);
  var out = [];
  var re = /catch\s*\(([^)]*)\)\s*\{/g, m;
  while ((m = re.exec(stripped))) {
    // Brace-match the catch body in the STRIPPED source (so string braces don't confuse).
    var i = m.index + m[0].length, depth = 1;
    while (i < stripped.length && depth > 0) { var c = stripped[i]; if (c === "{") depth++; else if (c === "}") depth--; if (depth > 0) i++; }
    var bodyStart = m.index + m[0].length, bodyEnd = i;
    var body = stripped.slice(bodyStart, bodyEnd);
    var startLine = stripped.slice(0, m.index).split("\n").length;
    var endLine = stripped.slice(0, bodyEnd).split("\n").length;
    // A re-throw (a `throw`, or a returned rejected promise) propagates -> fail-closed.
    var reThrows = /\bthrow\b/.test(body) && !/\breturn\s+(?!Promise\.reject)/.test(body);
    var rejectsOnly = /return\s+Promise\.reject\b/.test(body) && !/\breturn\s+(?!Promise\.reject)/.test(body);
    if (reThrows || rejectsOnly) continue;   // safe: propagates the fault
    // Otherwise it is a swallow: it must be exercised (covered) or explicitly marked.
    out.push({ startLine: startLine, endLine: endLine, param: m[1].trim() });
  }
  return out;
}

// A per-line `allow:swallow-unverified` marker on any line of the catch body (or up to 2
// lines above the catch), matching the codebase-patterns marker convention.
function isMarked(srcLines, startLine, endLine) {
  for (var ln = startLine - 2; ln <= endLine; ln++) {
    var s = srcLines[ln - 1];
    if (s && /\ballow:swallow-unverified\b/.test(s)) return true;
  }
  return false;
}

function main() {
  if (!fs.existsSync(LCOV)) {
    console.error("[check-swallow-coverage] coverage/lcov.info not found -- run `npm run coverage` first.");
    process.exit(2);
  }
  var cov = parseLcov(fs.readFileSync(LCOV, "utf8"));
  var bad = [];
  var swallowCount = 0, coveredCount = 0, markedCount = 0;
  fs.readdirSync(LIB_DIR).filter(function (f) { return /\.js$/.test(f); }).forEach(function (f) {
    var rel = "lib/" + f;
    var src = fs.readFileSync(path.join(LIB_DIR, f), "utf8");
    var srcLines = src.split(/\r?\n/);
    var fileCov = cov[rel] || {};
    findSwallows(rel, src).forEach(function (sw) {
      swallowCount++;
      // Covered iff any body line carries a non-zero hit.
      var covered = false;
      for (var ln = sw.startLine; ln <= sw.endLine; ln++) { if (fileCov[ln] > 0) { covered = true; break; } }
      if (covered) { coveredCount++; return; }
      if (isMarked(srcLines, sw.startLine, sw.endLine)) { markedCount++; return; }
      bad.push({ file: rel, line: sw.startLine, param: sw.param });
    });
  });
  console.log("[check-swallow-coverage] swallows=" + swallowCount + " covered=" + coveredCount + " marked=" + markedCount + " unverified=" + bad.length);
  if (bad.length) {
    console.error("\nUnverified swallows (no test drives the catch; not re-throwing; not marked):");
    bad.forEach(function (b) {
      console.error("  " + b.file + ":" + b.line + "  catch (" + b.param + ") -- add a RED vector that drives this catch, re-throw, or mark `allow:swallow-unverified <reason>`");
    });
    process.exit(1);
  }
  console.log("[check-swallow-coverage] OK -- every lib swallow re-throws, is execution-covered, or is explicitly marked.");
}

main();
