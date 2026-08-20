// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Write examples/wiki/page-lastmod.json: the commit date of the last change to each source file the
// wiki generates a page from.
//
// The sitemap needs a truthful <lastmod>, and the two obvious sources are both wrong. Build time
// says every page changed on every deploy, which is false for 45 of 46 URLs and teaches a crawler
// that the field carries no information -- sitemaps.org makes <lastmod> optional precisely so a
// publisher who cannot state it accurately can leave it out instead. Filesystem mtime is no better:
// a CI checkout stamps every file with the clone time.
//
// Git holds the real answer, but the wiki container ships without a .git directory (the Dockerfile
// copies lib/, README.md and examples/wiki/ alone) and the generator runs at boot, so it cannot ask.
// This script runs where the repository exists -- a developer's tree, CI, the release flow -- and
// leaves the answer behind as data the container can read.
//
// A file with no commit yet (staged or untracked) is simply absent from the map; the generator omits
// <lastmod> for its page rather than inventing one.
//
// The working tree counts. This runs during a release cut, when the changes being released are
// modified but not yet committed, so `git log` alone would report each of those files at its
// PREVIOUS commit -- understating every page the release actually changes, which is the failure this
// script exists to prevent. A file the working tree reports as modified has a change dated today,
// and saying so is a statement about a change that really happened. That is the whole distinction
// from stamping build time: build time claimed all 46 pages changed on every deploy, true of none of
// them; this claims a date only for files git or the working tree says did change.

var cp = require("node:child_process");
var fs = require("node:fs");
var path = require("node:path");

var ROOT = path.resolve(__dirname, "..");
var OUT = path.join(ROOT, "examples", "wiki", "page-lastmod.json");
// The whole-history walk grows with the repository, so it gets the larger ceiling; the working-tree
// status is bounded by the size of one cut. Both are far above what either has ever produced -- they
// exist so a future repository does not truncate silently, which would drop dates rather than fail.
var MAX_HISTORY = 256 * 1024 * 1024;
var MAX_STATUS = 64 * 1024 * 1024;

// One `git log` walk over the whole history, newest first, recording the first (therefore most
// recent) date seen for each path. Per-file `git log -1` would be one process per page.
function collect() {
  var out = cp.execFileSync("git", ["log", "--format=%x00%cI", "--name-only", "--no-renames"], {
    cwd: ROOT, encoding: "utf8", maxBuffer: MAX_HISTORY,
  });
  var dates = {};
  var current = null;
  out.split("\n").forEach(function (line) {
    if (line.charCodeAt(0) === 0) { current = line.slice(1).trim().slice(0, 10); return; }
    var file = line.trim();
    if (!file || !current) return;
    if (!Object.prototype.hasOwnProperty.call(dates, file)) dates[file] = current;
  });
  return dates;
}

// Paths git reports as changed in the working tree or the index, in the porcelain v1 short format:
// two status columns, a space, then the path (quoted when it contains unusual bytes). A rename
// records `old -> new`; the new name is the one that exists now, so it is the one taken.
function dirtyPaths() {
  var out = cp.execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], {
    cwd: ROOT, encoding: "utf8", maxBuffer: MAX_STATUS,
  });
  var set = {};
  out.split("\n").forEach(function (line) {
    if (line.length < 4) return;
    var p = line.slice(3).trim();
    var arrow = p.indexOf(" -> ");
    if (arrow !== -1) p = p.slice(arrow + 4);
    if (p.charAt(0) === '"' && p.charAt(p.length - 1) === '"') p = p.slice(1, -1);
    if (p) set[p] = true;
  });
  return set;
}

function main() {
  var all = collect();
  // A modified file's most recent change is the one sitting in the working tree, not the one in
  // history. `git log` cannot see it, so it is applied here.
  var today = new Date().toISOString().slice(0, 10);
  var dirty = dirtyPaths();
  Object.keys(dirty).forEach(function (f) { all[f] = today; });
  // Only the paths a page's content depends on: the toolkit's modules (whose @module and @primitive
  // blocks every namespace page renders), the README the home and overview pages render, the
  // concepts file, and the wiki's OWN renderers. That last group matters because several pages have
  // their text authored in the generator rather than in a content file -- the home page's headings
  // and examples, the API index, the error catalogue -- so a generator change IS a change to those
  // pages, and dating them only by the content file they also read reports a revision older than
  // the page. Shipping the whole repository's history as a lookup table would put thousands of
  // irrelevant rows in the container image.
  var keep = {};
  Object.keys(all).forEach(function (f) {
    if (/^lib\/[^/]+\.js$/.test(f) || f === "README.md" ||
        /^examples\/wiki\/(concepts\.js|site\.config\.js|lib\/[^/]+\.js)$/.test(f)) keep[f] = all[f];
  });
  var sorted = {};
  Object.keys(keep).sort().forEach(function (k) { sorted[k] = keep[k]; });
  fs.writeFileSync(OUT, JSON.stringify(sorted, null, 2) + "\n");
  process.stdout.write("[wiki-lastmod] " + Object.keys(sorted).length + " source file(s) -> " +
    path.relative(ROOT, OUT) + "\n");
}

main();
