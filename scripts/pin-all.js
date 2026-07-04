#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// pin-all.js — aggregate every supply-chain PIN in one pass so a fix run
// keeps all segments in sync instead of hand-editing each. Segments:
//
//   1. Committed lockfiles — the dev/example manifests whose committed
//      package-lock.json lets CI's `npm ci` pin exact reviewed versions with
//      integrity hashes (root dev-tools, fuzz harnesses). OpenSSF Scorecard
//      keys "pinned" on the `npm ci` verb, so the committed lockfile IS the
//      pin.
//   2. GitHub Action SHAs — delegated to check-actions-currency.js (its --fix
//      resolves each `uses:` tag to the upstream commit SHA and pins it,
//      honoring the .pinact.yaml exceptions).
//   3. Docker base-image digests — mirror any Dependabot-tracked reference
//      Dockerfile's `@sha256:` digest into a sibling that Scorecard scans but
//      that the tracked pipeline never builds. This repo ships no such
//      mirror today, so the segment is empty and runs as a clean no-op.
//
//   --check (default): verify segments 1 + 3 are in sync (fast, no network)
//     and exit non-zero on drift. Segment 2 currency has its own CI gate;
//     --check does not re-run it to avoid duplicate rate-limited API calls.
//   --fix: regenerate all lockfiles, pin/bump the Action SHAs, and sync the
//     Docker digests. One command re-pins the repo.
//   --lockfiles: regenerate ONLY the committed lockfiles (no Action/digest
//     work, no token) — release.js regen runs this after the version bump.
//
// Wire `--check` into CI + release.js so no pin can silently drift; run
// `--fix` (with GH_TOKEN for the Action step) whenever a pin needs refreshing.

var fs = require("node:fs");
var path = require("node:path");
var cp = require("node:child_process");

var ROOT = path.resolve(__dirname, "..");
var FIX = process.argv.indexOf("--fix") !== -1;
var LOCKFILES_ONLY = process.argv.indexOf("--lockfiles") !== -1;

function readJson(p) { return JSON.parse(fs.readFileSync(p, "utf8")); }

// Every directory whose committed package-lock.json backs a CI `npm ci`.
// The wiki example declares zero dependencies (its docs are generated from
// the toolkit's own source), so it carries no lockfile and is not listed.
var LOCKFILE_DIRS = [
  { dir: ".",    args: [], label: "root dev-tools (esbuild)" },
  { dir: "fuzz", args: [], label: "fuzz harnesses (jazzer.js)" },
];

// Docker base images pinned by MIRRORING a Dependabot-maintained reference.
// Empty in this repo — no oss-fuzz/clusterfuzzlite mirror ships here. The
// forEach over an empty list is a clean no-op.
var DIGEST_SYNCS = [];

var problems = [];
var fixed = [];

// ---- Segment 1: lockfiles ----

function topSpecs(node) {
  var out = {};
  ["dependencies", "devDependencies", "optionalDependencies"].forEach(function (k) {
    var d = (node && node[k]) || {};
    Object.keys(d).forEach(function (n) { out[n] = d[n]; });
  });
  return out;
}

function checkLockfile(entry) {
  var dirAbs = path.join(ROOT, entry.dir);
  var pkgPath = path.join(dirAbs, "package.json");
  if (!fs.existsSync(pkgPath)) return; // nothing to lock
  // A package.json with zero deps needs no lockfile.
  var pkgForSpecs;
  try { pkgForSpecs = readJson(pkgPath); }
  catch (e) { problems.push(entry.dir + ": unreadable package.json: " + (e && e.message)); return; }
  if (Object.keys(topSpecs(pkgForSpecs)).length === 0) return;

  var lockPath = path.join(dirAbs, "package-lock.json");
  if (!fs.existsSync(lockPath)) {
    problems.push(entry.dir + "/package-lock.json is missing (" + entry.label + ") — run `node scripts/pin-all.js --fix`");
    return;
  }
  var pkg, lock;
  try { pkg = readJson(pkgPath); lock = readJson(lockPath); }
  catch (e) { problems.push(entry.dir + ": unreadable package.json/lockfile: " + (e && e.message)); return; }
  // The lockfile's root package node must carry the exact package.json specs;
  // `npm ci` refuses to run when they disagree, so drift here breaks CI.
  var want = topSpecs(pkg);
  var have = topSpecs((lock.packages && lock.packages[""]) || {});
  Object.keys(want).forEach(function (name) {
    if (have[name] !== want[name]) {
      problems.push(entry.dir + "/package-lock.json spec for " + name + " is " +
        (have[name] === undefined ? "<absent>" : have[name]) + " but package.json wants " + want[name] +
        " — regenerate with `node scripts/pin-all.js --fix`");
    }
  });

  // Version drift: a version-only release bumps package.json but a spec-only
  // comparison still passes, leaving the lockfile's own recorded version
  // pointing at the prior release. npm ci tolerates it until something
  // linked breaks, so catch the drift here.
  var pkgs = lock.packages || {};
  var selfVer = pkgs[""] && pkgs[""].version;
  if (entry.dir === "." && selfVer !== undefined && selfVer !== pkg.version) {
    problems.push(entry.dir + "/package-lock.json records root version " + selfVer +
      " but package.json is " + pkg.version + " — regenerate with `node scripts/pin-all.js --lockfiles`");
  }
}

function fixLockfile(entry) {
  var dirAbs = path.join(ROOT, entry.dir);
  var pkgPath = path.join(dirAbs, "package.json");
  if (!fs.existsSync(pkgPath)) return;
  // Skip a zero-dependency manifest — no lockfile is needed.
  try { if (Object.keys(topSpecs(readJson(pkgPath))).length === 0) return; }
  catch (e) { problems.push(entry.dir + ": unreadable package.json: " + (e && e.message)); return; }
  var args = ["install", "--package-lock-only", "--no-audit", "--no-fund"].concat(entry.args);
  var r = cp.spawnSync("npm", args, {
    cwd: dirAbs, encoding: "utf8", shell: process.platform === "win32",
  });
  if (r.status !== 0) {
    problems.push(entry.dir + ": `npm install --package-lock-only` failed: " + ((r.stderr || r.stdout || "").trim().slice(-300)));
    return;
  }
  fixed.push(entry.dir + "/package-lock.json regenerated (" + entry.label + ")");
}

// ---- Segment 3: Docker digest mirror ----

function reEscape(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function readFrom(file, image) {
  var abs = path.join(ROOT, file);
  var src;
  try { src = fs.readFileSync(abs, "utf8"); }
  catch (e) { return { err: file + " unreadable: " + (e && e.message) }; }
  var re = new RegExp("FROM\\s+" + reEscape(image) + "(@sha256:[0-9a-f]{64})?", "m");
  var m = re.exec(src);
  if (!m) return { err: file + " has no `FROM " + image + "` line" };
  return { digest: m[1] ? m[1].slice(1) : null, src: src, matched: m[0] };
}

function checkDigestSync(entry) {
  var ref = readFrom(entry.reference, entry.image);
  var tgt = readFrom(entry.target, entry.image);
  if (ref.err) { problems.push(ref.err); return; }
  if (tgt.err) { problems.push(tgt.err); return; }
  if (!ref.digest) {
    problems.push(entry.reference + " `FROM " + entry.image + "` is not @sha256-pinned — the reference must be pinned for the mirror to have a source of truth");
    return;
  }
  if (tgt.digest !== ref.digest) {
    problems.push(entry.target + " `FROM " + entry.image + "` digest " + (tgt.digest || "<unpinned>") +
      " != reference " + entry.reference + " " + ref.digest + " — sync with `node scripts/pin-all.js --fix`");
  }
}

function fixDigestSync(entry) {
  var ref = readFrom(entry.reference, entry.image);
  var tgt = readFrom(entry.target, entry.image);
  if (ref.err) { problems.push(ref.err); return; }
  if (tgt.err) { problems.push(tgt.err); return; }
  if (!ref.digest) { problems.push(entry.reference + " reference is not @sha256-pinned"); return; }
  if (tgt.digest === ref.digest) return;
  var newSrc = tgt.src.replace(tgt.matched, "FROM " + entry.image + "@" + ref.digest);
  fs.writeFileSync(path.join(ROOT, entry.target), newSrc);
  fixed.push(entry.target + " base digest synced to " + ref.digest.slice(0, 19) + "... (" + entry.label + ")");
}

// ---- Segment 2: GitHub Action SHAs (delegate) ----

function fixActions() {
  var script = path.join(__dirname, "check-actions-currency.js");
  if (!fs.existsSync(script)) {
    problems.push("Action-SHA --fix skipped: scripts/check-actions-currency.js not present");
    return;
  }
  var r = cp.spawnSync(process.execPath, [script, "--fix"], { cwd: ROOT, encoding: "utf8" });
  if (r.status !== 0) {
    problems.push("Action-SHA --fix (check-actions-currency.js) failed:\n" + ((r.stdout || "") + (r.stderr || "")).trim().slice(-600));
    return;
  }
  fixed.push("GitHub Action SHAs pinned/updated (check-actions-currency.js --fix)");
}

// ---- Run ----

if (LOCKFILES_ONLY) {
  LOCKFILE_DIRS.forEach(fixLockfile);
} else if (FIX) {
  LOCKFILE_DIRS.forEach(fixLockfile);
  DIGEST_SYNCS.forEach(fixDigestSync);
  fixActions();
} else {
  LOCKFILE_DIRS.forEach(checkLockfile);
  DIGEST_SYNCS.forEach(checkDigestSync);
}

fixed.forEach(function (f) { console.log("[pin-all] fixed: " + f); });
if (problems.length) {
  problems.forEach(function (p) { console.error("[pin-all] " + ((FIX || LOCKFILES_ONLY) ? "ERROR" : "DRIFT") + ": " + p); });
  process.exit(1);
}
console.log("[pin-all] OK — " + (LOCKFILES_ONLY
  ? "committed lockfiles regenerated to the current versions."
  : FIX
    ? "lockfiles regenerated, Action SHAs pinned, Docker digests synced."
    : "committed lockfiles (specs + versions) in sync with package.json (Action-SHA currency has its own gate)."));
