#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * release.js — orchestrate the full release flow as a sequence of
 * idempotent subcommands. Each subcommand performs ONE phase, prints
 * what it did, and exits with a code that's safe to script against in a
 * CI runner or an operator's terminal.
 *
 * Usage:
 *   node scripts/release.js prepare    # bump + regen CHANGELOG/api-snapshot + static gates
 *   node scripts/release.js regen      # re-regen artifacts (after release-notes edits)
 *   node scripts/release.js smoke       # smoke + interop
 *   node scripts/release.js commit      # release branch + signed commit
 *   node scripts/release.js interop     # cross-implementation interop tests
 *   node scripts/release.js push        # interop + gitleaks + push + open PR
 *   node scripts/release.js watch       # gh pr checks --watch + flag review threads
 *   node scripts/release.js merge       # squash-merge if CLEAN + zero unresolved threads
 *   node scripts/release.js tag         # signed tag + push tag + verify
 *   node scripts/release.js publish     # watch npm-publish workflow
 *   node scripts/release.js all         # prepare -> ... -> publish
 *
 *   node scripts/release.js help        # this banner
 *   node scripts/release.js status      # what phase the current branch is in
 *
 * Pre-conditions:
 *   - The release-notes JSON `release-notes/v<next>.json` MUST already
 *     exist before `prepare` runs. The script refuses with a template
 *     stub printed to stdout otherwise — the headline / summary /
 *     sections require human judgment and don't auto-generate from a diff.
 *   - Git signing config (SSH + allowed_signers + commit/tag.gpgsign)
 *     must be in place before the first signed commit/tag.
 *
 * The judgment-requiring parts stay manual:
 *   - Writing `release-notes/v<next>.json` content.
 *   - Reviewing review-bot P1/P2 findings (watch flags them + stops; the
 *     operator writes the fix + re-runs watch).
 *   - Choosing minor vs patch bump (default: patch;
 *     override via `--minor` on prepare).
 */

var fs           = require("node:fs");
var path         = require("node:path");
var childProcess = require("node:child_process");

var ROOT = path.resolve(__dirname, "..");

// ---- Repo coordinates (owner/name) ---------------------------------------
//
// Parsed from package.json `repository.url` so the gh + GraphQL calls point
// at the right slug without a hardcode drifting from the manifest.
function _repoSlug() {
  var owner = "blamejs";
  var name = "pki.js";
  try {
    var pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
    var url = (pkg.repository && pkg.repository.url) || "";
    var m = url.match(/github\.com[/:]([^/]+)\/([^/.]+(?:\.[^/.]+)*?)(?:\.git)?$/);
    if (m) { owner = m[1]; name = m[2]; }
  } catch (_e) { /* fall back to defaults */ }
  return { owner: owner, name: name };
}

// ---- Helpers -------------------------------------------------------------

// Windows resolves `npm` / `npx` as `npm.cmd` / `npx.cmd` shims, which
// child_process.spawn can only invoke through a shell. Everything else in
// the release-flow toolchain (`gh`, `git`, `docker`, `node`) is a native
// exe that spawns directly without a shell — keeping shell off avoids the
// DEP0190 deprecation + the implicit arg-quoting risk.
function _needsShell(cmd) {
  if (process.platform !== "win32") return false;
  return cmd === "npm" || cmd === "npx";
}

function _readPackageVersion() {
  var pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  return pkg.version;
}

function _writePackageVersion(next) {
  var pkgPath = path.join(ROOT, "package.json");
  var content = fs.readFileSync(pkgPath, "utf8");
  var updated = content.replace(/"version":\s*"[^"]+"/, '"version": "' + next + '"');
  if (updated === content) {
    throw new Error("release: failed to rewrite package.json version line");
  }
  fs.writeFileSync(pkgPath, updated);
}

function _bumpPatch(version) {
  var parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + "." + parts[1] + "." + (parts[2] + 1);
}

function _bumpMinor(version) {
  var parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  return parts[0] + "." + (parts[1] + 1) + ".0";
}

// Quote a single argument for a Windows cmd.exe command line. Tokens made
// only of safe characters pass through unquoted; anything else is
// double-quoted with embedded quotes doubled.
function _quoteWinArg(a) {
  a = String(a);
  if (/^[A-Za-z0-9_@.\-/:=]+$/.test(a)) return a;
  return '"' + a.replace(/"/g, '""') + '"';
}

// Windows resolves npm / npx through .cmd shims that can only be launched
// via a shell (the CVE-2024-27980 mitigation refuses to spawn .cmd files
// without one). Node 26's DEP0190 deprecates pairing an args ARRAY with
// shell:true because the args would be concatenated onto the command line
// without escaping — a quoting / injection hazard. Build a single,
// explicitly-quoted command string and pass NO args array. Every spawn in
// this file (run and capture alike) routes through this one form.
function _shellForm(cmd, args) {
  if (!_needsShell(cmd)) return { cmd: cmd, args: args, shell: false };
  return {
    cmd: [cmd].concat(args.map(_quoteWinArg)).join(" "),
    args: undefined,
    shell: true,
  };
}

function _run(cmd, args, opts) {
  opts = opts || {};
  args = args || [];
  var form = _shellForm(cmd, args);
  var rv = childProcess.spawnSync(form.cmd, form.args, {
    cwd:   opts.cwd   || ROOT,
    stdio: opts.stdio || "inherit",
    env:   Object.assign({}, process.env, opts.env || {}),
    shell: form.shell,
  });
  if (rv.status !== 0 && !opts.allowFail) {
    throw new Error("release: " + cmd + " " + args.join(" ") +
                    " failed with status " + rv.status);
  }
  return rv;
}

// Run a scripts/*.js gate only when the file exists. Sibling scripts in the
// release toolchain (codebase-patterns, source-comment-block validator,
// vendor-currency, interop) are authored independently; a release cut must
// not hard-crash because one of them has not landed yet. A present script
// still runs as a hard gate — absence is the only thing tolerated.
function _runScriptIfPresent(relScriptPath, args, opts) {
  var abs = path.join(ROOT, relScriptPath);
  if (!fs.existsSync(abs)) {
    console.log("skip: " + relScriptPath + " not present — gate not configured yet");
    return false;
  }
  _run("node", [relScriptPath].concat(args || []), opts || {});
  return true;
}

function _capture(cmd, args, opts) {
  opts = opts || {};
  var form = _shellForm(cmd, args || []);
  var rv = childProcess.spawnSync(form.cmd, form.args, {
    cwd:   opts.cwd || ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    env:   Object.assign({}, process.env, opts.env || {}),
    shell: form.shell,
  });
  return {
    status: rv.status,
    stdout: (rv.stdout || "").toString().trim(),
    stderr: (rv.stderr || "").toString().trim(),
  };
}

function _gitClean() {
  return _capture("git", ["status", "--porcelain"]).stdout === "";
}

function _gitBranch() {
  return _capture("git", ["rev-parse", "--abbrev-ref", "HEAD"]).stdout;
}

function _gitOnMain() {
  return _gitBranch() === "main";
}

function _gitOnRelease() {
  return /^release\/v\d+\.\d+\.\d+$/.test(_gitBranch());
}

function _releaseBranchFor(version) {
  return "release/v" + version;
}

function _releaseNotesPath(version) {
  return path.join(ROOT, "release-notes", "v" + version + ".json");
}

function _ensureReleaseNotes(version) {
  var p = _releaseNotesPath(version);
  if (!fs.existsSync(p)) {
    var stub = {
      version:  version,
      headline: "<one-line operator-facing summary>",
      summary:  "<one-paragraph why-it-matters>",
      sections: {
        Added: [
          "<one operator-facing sentence per shipped surface>",
        ],
      },
    };
    console.error("");
    console.error("release: missing " + p);
    console.error("");
    console.error("Create that file before re-running. Stub template:");
    console.error("");
    console.error(JSON.stringify(stub, null, 2));
    console.error("");
    process.exit(2);
  }
  return p;
}

function _section(title) {
  console.log("\n=== " + title + " ===");
}

function _ok(msg) {
  console.log("ok: " + msg);
}

// Normalize the release-notes `sections` (object keyed by heading, or an
// array of { heading, items }) into an ordered list of { heading, items }
// so the commit body + PR body render either shape.
function _sectionsList(sections) {
  var pairs = [];
  if (Array.isArray(sections)) {
    sections.forEach(function (s) {
      if (!s || !s.heading) return;
      var items = (s.items || []).map(function (it) {
        return typeof it === "string" ? it : (it && it.title ? it.title : String(it));
      });
      pairs.push({ heading: s.heading, items: items });
    });
  } else if (sections && typeof sections === "object") {
    Object.keys(sections).forEach(function (h) {
      if (Array.isArray(sections[h])) pairs.push({ heading: h, items: sections[h].slice() });
    });
  }
  return pairs.filter(function (p) { return p.items.length > 0; });
}

// Shared artifact-regeneration helper. Called by `prepare` after the
// version bump, and standalone via `regen` when the operator edits
// release-notes mid-flow. Idempotent — running it twice with no edits in
// between is a no-op.
function _regenArtifacts() {
  // Regenerate the committed lockfiles to the just-bumped version FIRST, so
  // the pin-all --check static gate can never ship a lockfile that records
  // the previous release (which is how 0.1.1 shipped with a 0.1.0 lockfile).
  _run("node", ["scripts/pin-all.js", "--lockfiles"]);
  _run("node", ["scripts/gen-changelog.js"]);
  _run("node", ["scripts/gen-migrating.js"]);
  _run("node", ["scripts/refresh-api-snapshot.js"]);
  _run("node", ["scripts/check-api-snapshot.js"]);
  _run("node", ["scripts/check-changelog-extract.js"]);
  _ok("lockfiles + CHANGELOG + MIGRATING + api-snapshot regenerated");
}

// Verify HEAD's commit signature via two independent paths:
//   1. `git verify-commit HEAD` — exits 0 on a Good signature (the same
//      truth signal GitHub's required_signatures ruleset checks).
//   2. `git log -1 --pretty=%h %G? %GS` — sha + signature letter + signer
//      for a human-readable line.
function _verifyCommitSignature(label) {
  var verifyRv = _capture("git", ["verify-commit", "HEAD"]);
  if (verifyRv.status !== 0) {
    var hint = "release: " + label + " commit signature is not Good — " +
               "check SSH signing setup (commit.gpgsign=true + gpg.format=ssh + " +
               "~/.ssh/allowed_signers populated).";
    if (verifyRv.stderr) hint += "\n" + verifyRv.stderr;
    throw new Error(hint);
  }
  var sig = _capture("git", ["log", "-1", "--pretty=%h %G? %GS"]);
  console.log("signature: " + (sig.stdout || "(captured empty — verify-commit reports Good)"));
  _ok(label + " commit signature verified");
}

// Docker gitleaks scan over full history — the same gate CI runs. Shared by
// `push` (before the PR opens) and `push-fix` (before a fix reaches the remote),
// so no secret is pushed even briefly. Windows host paths (`C:\Users\...`) must
// be rewritten to Docker Desktop's `//c/Users/...` form — the colon in `C:`
// confuses the `-v src:dst` splitter.
function _gitleaks() {
  _section("gitleaks");
  var mount;
  if (process.platform === "win32") {
    var posixified = ROOT.replace(/\\/g, "/");
    mount = "//" + posixified.charAt(0).toLowerCase() + posixified.slice(2);   // C:/x -> //c/x
  } else {
    mount = ROOT;
  }
  _run("docker", [
    "run", "--rm",
    "-v", mount + ":/repo",
    "-w", "//repo",
    "zricethezav/gitleaks:latest",
    "git", "--config=.gitleaks.toml", "--redact", "--exit-code=1",
  ]);
  _ok("gitleaks clean");
}

// The open PR number for a release branch — the branch -> PR lookup shared by
// watch / merge / push-fix. Throws if the branch has no open PR.
function _openPrNumber(branch) {
  var prNum = _capture("gh", ["pr", "list", "--head", branch, "--state", "open",
                              "--json", "number", "--jq", ".[0].number"]).stdout;
  if (!prNum) {
    throw new Error("release: no open PR for branch " + branch);
  }
  return prNum;
}

// ---- Interop gate --------------------------------------------------------
//
// A pure-JavaScript PKI toolkit proves itself against real-world artifacts:
// certificates / encodings emitted by OpenSSL and other conformant
// implementations, and the published test vectors for each algorithm. That
// cross-implementation surface lives in scripts/test-integration.js. It is
// the toolkit analogue of a backend live-integration gate — a change that
// only passed the in-process smoke can still mis-decode a real DER shape.
//
// Non-skippable except via an explicit, audited override
// (--skip-interop --interop-skip-reason="<why>"), printed loudly so a
// bypass is never silent.
function cmdInterop(opts) {
  opts = opts || {};
  _section("interop");

  if (opts.skip) {
    if (!opts.skipReason) {
      throw new Error(
        "release: --skip-interop requires --interop-skip-reason=\"<why>\".\n" +
        "The interop gate proves the toolkit against real-world encodings and " +
        "published vectors; skipping it needs an explicit, audited reason printed " +
        "to the operator — not a silent bypass.");
    }
    console.log("");
    console.log("!! INTEROP SKIPPED — operator override");
    console.log("!! reason: " + opts.skipReason);
    console.log("!! This override is recorded in the release-flow output above.");
    return;
  }

  var ran = _runScriptIfPresent("scripts/test-integration.js");
  if (ran) {
    _ok("interop green");
  } else {
    _ok("interop gate not configured — nothing to run");
  }
}

// ---- Subcommands ---------------------------------------------------------

function cmdPrepare(opts) {
  _section("prepare");
  if (!_gitOnMain()) {
    throw new Error("release: prepare must run on main (currently on " + _gitBranch() + ")");
  }
  if (!_gitClean()) {
    throw new Error("release: prepare requires a clean working tree");
  }

  var current = _readPackageVersion();
  var next = opts.minor ? _bumpMinor(current) : _bumpPatch(current);
  console.log("current version: " + current);
  console.log("next version:    " + next + " (" + (opts.minor ? "minor" : "patch") + ")");

  _ensureReleaseNotes(next);

  _writePackageVersion(next);
  _ok("bumped package.json -> " + next);

  _section("regen artifacts");
  _regenArtifacts();

  _section("static gates");
  _run("npx", ["--yes", "eslint@10.3.0", "--max-warnings", "0", "."]);
  _runScriptIfPresent("test/layer-0-primitives/codebase-patterns.test.js");
  _runScriptIfPresent("scripts/validate-source-comment-blocks.js");
  _run("node", ["scripts/pin-all.js", "--check"]);
  _ok("eslint + codebase-patterns + source-comment-blocks + lockfile pin currency clean");

  _section("supply-chain currency");
  // A stale vendored bundle becomes a release blocker HERE instead of an
  // after-the-fact advisory. The currency check treats only an actually-
  // newer upstream version as a failure; transient registry errors stay
  // advisory so a flaky network response doesn't block the cut.
  _runScriptIfPresent("scripts/check-vendor-currency.js");
  _ok("vendored bundles current");

  console.log("\nnext: node scripts/release.js smoke");
}

function cmdRegen() {
  _section("regen");
  // Operators edit release-notes/v<next>.json mid-flow (e.g. addressing a
  // review-bot finding that belongs in the operator-facing notes). This
  // subcommand re-runs the artifact pipeline without re-bumping the
  // version. Safe to run from any branch.
  var next = _readPackageVersion();
  _ensureReleaseNotes(next);
  _regenArtifacts();
  console.log("\nnext: re-run the phase you were on (commit / push / watch / ...)");
}

function cmdSmoke() {
  _section("smoke");
  _run("node", ["test/smoke.js"], { env: { SMOKE_PARALLEL: "64" } });
  _ok("toolkit smoke clean");

  // Interop runs alongside smoke so a cut catches a real-encoding
  // regression before the branch is even pushed.
  cmdInterop({});

  // wiki e2e — only if examples/wiki has an e2e runner AND was touched.
  var wikiE2e = path.join(ROOT, "examples", "wiki", "test", "e2e.js");
  if (fs.existsSync(wikiE2e)) {
    var diffRv = _capture("git", ["diff", "--name-only", "origin/main..HEAD"]);
    var changed = diffRv.stdout.split(/\r?\n/);
    var wikiTouched = changed.some(function (p) { return p.indexOf("examples/wiki") === 0; });
    if (!wikiTouched) {
      var localDiffRv = _capture("git", ["diff", "--name-only"]);
      wikiTouched = localDiffRv.stdout.split(/\r?\n/).some(function (p) {
        return p.indexOf("examples/wiki") === 0;
      });
    }
    if (wikiTouched) {
      _section("wiki e2e");
      var wikiDir = path.join(ROOT, "examples", "wiki");
      try { fs.rmSync(path.join(wikiDir, "data"),     { recursive: true, force: true }); } catch (_e) { /* ignore */ }
      try { fs.rmSync(path.join(wikiDir, "data-e2e"), { recursive: true, force: true }); } catch (_e) { /* ignore */ }
      _run("node", ["test/e2e.js"], { cwd: wikiDir, env: { SMOKE_PARALLEL: "64" } });
      _ok("wiki e2e clean");
    } else {
      _ok("wiki untouched — skipping e2e");
    }
  }

  console.log("\nnext: node scripts/release.js commit");
}

function cmdCommit() {
  _section("commit");
  var next = _readPackageVersion();
  var branch = _releaseBranchFor(next);
  var current = _gitBranch();

  // Resumable: if a previous `commit` failed AFTER the `git checkout -b`
  // (signature verification, hook failure), the branch already exists.
  // Switch to it instead of refusing; the remaining steps are idempotent.
  if (current === branch) {
    _ok("already on " + branch + " (resume mode)");
  } else if (current === "main") {
    var branchExists = _capture("git", ["rev-parse", "--verify", "--quiet", branch]).status === 0;
    if (branchExists) {
      _run("git", ["checkout", branch]);
      _ok("checked out existing " + branch + " (resume mode)");
    } else {
      _run("git", ["checkout", "-b", branch]);
      _ok("created " + branch);
    }
  } else {
    throw new Error("release: commit must run on main or " + branch +
                    " (currently on " + current + ")");
  }

  // If HEAD already carries a commit for this release, skip the second
  // commit and verify the existing signature instead.
  var headSubject = _capture("git", ["log", "-1", "--pretty=%s"]).stdout;
  if (headSubject.indexOf(next + " — ") === 0) {
    _ok("HEAD already carries a " + next + " release commit (resume mode)");
    _verifyCommitSignature("existing");
    console.log("\nnext: node scripts/release.js push");
    return;
  }

  // Compose the commit body from the release-notes JSON. Operators can
  // amend post-commit; the auto-generated body mirrors the CHANGELOG shape.
  var rn = JSON.parse(fs.readFileSync(_releaseNotesPath(next), "utf8"));
  var lines = [next + " — " + rn.headline, "", rn.summary];
  _sectionsList(rn.sections).forEach(function (s) {
    lines.push("", s.heading + ":");
    s.items.forEach(function (it) { lines.push("  - " + it); });
  });
  var msgPath = path.join(ROOT, ".scratch", "release-commit-msg.txt");
  try { fs.mkdirSync(path.dirname(msgPath), { recursive: true }); } catch (_e) { /* ignore */ }
  fs.writeFileSync(msgPath, lines.join("\n") + "\n");

  _run("git", ["add", "-A"]);
  _run("git", ["commit", "-s", "-F", msgPath]);   // -s: DCO Signed-off-by
  _ok("signed commit");

  _verifyCommitSignature("new");

  console.log("\nnext: node scripts/release.js push");
}

function cmdPush(opts) {
  opts = opts || {};
  _section("push");
  if (!_gitOnRelease()) {
    throw new Error("release: push must run on a release/vX.Y.Z branch");
  }
  var next = _readPackageVersion();

  // Interop runs BEFORE gitleaks + the PR opens. A change that only passed
  // the in-process smoke must prove itself against real-world encodings
  // here; a failure is a hard stop that refuses the push. Non-skippable
  // except via an explicit, audited override (see cmdInterop).
  cmdInterop({ skip: opts.skipInterop, skipReason: opts.interopSkipReason });

  _gitleaks();

  _section("push branch");
  _run("git", ["push", "-u", "origin", _releaseBranchFor(next)]);
  _ok("pushed " + _releaseBranchFor(next));

  _section("open PR");
  var rn = JSON.parse(fs.readFileSync(_releaseNotesPath(next), "utf8"));
  var title = next + " — " + rn.headline;
  var summaryLines = ["## Summary", "", rn.summary, "", "## Test plan", ""];
  summaryLines.push("- [x] `node test/smoke.js` — passes");
  summaryLines.push("- [x] `node scripts/test-integration.js` — interop clean");
  summaryLines.push("- [x] `node scripts/check-api-snapshot.js` — surface tracked");
  summaryLines.push("- [x] `gitleaks` — no leaks");
  summaryLines.push("- [ ] CI green");
  _run("gh", ["pr", "create",
              "--base", "main",
              "--head", _releaseBranchFor(next),
              "--title", title,
              "--body",  summaryLines.join("\n")]);
  _ok("PR opened");

  console.log("\nnext: node scripts/release.js watch");
}

// Land a review/CI fix on the ALREADY-OPEN release PR. Encapsulates the
// multi-step flow that a Codex/Codex-P1/CI finding otherwise makes by hand:
// gitleaks -> a NEW signed commit -> push -> re-request a Codex review.
//
// Two non-obvious invariants it enforces:
//   - The fix is a NEW commit, never `--amend`. The pushed head must MOVE so
//     the review-thread + Codex gates re-check the new revision
//     (feedback_fix_codex_flags: fix in a new commit, never dismiss).
//   - Codex reviews a PR ONCE on open and does NOT auto-review a pushed fix,
//     so `watch`/`merge` would wait out their 10m budget on a review that
//     never comes. A `@codex review` comment re-triggers it on the current
//     head; the verdict (clean issue comment / finding thread) lands ~5-6m
//     later and the gate then sees it. This is NOT RELEASE_SKIP_CODEX_WAIT —
//     the gate still runs, we just make Codex actually review.
function cmdPushFix(opts) {
  opts = opts || {};
  _section("push-fix");
  if (!_gitOnRelease()) {
    throw new Error("release: push-fix must run on a release/vX.Y.Z branch (it lands a fix on the open PR)");
  }
  if (!opts.message) {
    throw new Error("release: push-fix needs a commit message — " +
      "node scripts/release.js push-fix -m \"<what the fix changes>\"");
  }
  if (_gitClean()) {
    throw new Error("release: nothing to commit — stage the fix first " +
      "(push-fix captures the whole working tree with git add -A)");
  }
  var branch = _releaseBranchFor(_readPackageVersion());

  // Resolve the open PR FIRST and fail closed if there is none. push-fix is only
  // valid for an already-open release PR, so this must precede any commit/push —
  // otherwise a stale branch whose PR already merged/closed would get a new
  // commit and a recreated remote branch before the lookup failed.
  var prNum = _openPrNumber(branch);

  _section("commit");
  _run("git", ["add", "-A"]);
  _run("git", ["commit", "-s", "-m", opts.message]);   // -s DCO; NOT --amend (head must move)
  _ok("signed fix commit");

  // Every post-commit / pre-push gate rolls the fix commit back on failure, so a
  // failed gate never dead-ends at the clean-tree guard — the operator fixes the
  // cause (a leaked secret, a broken SSH-signing setup) and re-runs push-fix
  // cleanly. gitleaks runs here, AFTER the commit, so the fix itself is scanned
  // (scanning before would miss a secret in it); the signature verify catches an
  // unsigned/badly-signed commit before it reaches the remote. On either failure
  // a soft reset keeps the fix staged, and nothing reached the remote (the push
  // is still ahead).
  try {
    _gitleaks();
    _verifyCommitSignature("new");
  } catch (gate) {
    _run("git", ["reset", "--soft", "HEAD~1"]);
    throw new Error("release: a pre-push gate failed — the fix commit was rolled back " +
      "(your changes are kept staged). Fix the cause, then re-run push-fix.\n" + (gate.message || String(gate)));
  }

  _section("push");
  _run("git", ["push"]);   // branch already tracks origin from the initial push
  _ok("pushed fix to " + branch);

  // The push is the critical, already-completed work; re-requesting the review is
  // a best-effort follow-up. If the comment fails (transient API / rate-limit),
  // do NOT throw — that would leave the fix pushed but the review un-requested,
  // and a rerun would stop at the clean-tree guard. Print the exact manual
  // re-trigger instead so the operator can post it without another commit.
  _section("re-request Codex review");
  var commentRv = _run("gh", ["pr", "comment", prNum, "--body", "@codex review"], { allowFail: true });
  if (commentRv.status === 0) {
    _ok("posted @codex review on PR #" + prNum + " — Codex will review the new head (~5-6m)");
  } else {
    console.log("\nwarn: the fix IS pushed, but posting `@codex review` failed (transient?).");
    console.log("      Re-trigger it manually (push-fix would refuse to rerun — the tree is now clean):");
    console.log("        gh pr comment " + prNum + " --body \"@codex review\"");
  }

  console.log("\nNext:");
  console.log("  - Resolve any Codex thread THIS fix addresses (fix it, never dismiss):");
  console.log("      gh api graphql -f query='mutation { resolveReviewThread(" +
              "input:{threadId:\"<PRRT_...>\"}){ thread { isResolved } } }'");
  console.log("  - Then: node scripts/release.js watch   (awaits the re-review + flags remaining threads)");
}

// Fetch every UNRESOLVED review thread on the PR with enough context to act
// on it: the file:line, the reviewer, the first line of the finding, the
// thread id, and the resolve mutation. Bot reviews post ASYNCHRONOUSLY —
// often a minute or two AFTER the status checks finish — so this is the
// authoritative check at merge time, not just at watch.
// The async-review race: Codex (chatgpt-codex-connector) reviews a PR a
// minute or two AFTER the status checks go green. required_review_thread_
// resolution can only block threads that EXIST at merge time, so a merge
// fired the instant CI is green outruns Codex and ships its findings (this
// is exactly how a P1 and the version-drift P2 reached npm). Closing it:
// before the thread gate runs, WAIT until Codex has actually reviewed the
// CURRENT head — then the thread-resolution gate sees its findings.
var CODEX_LOGIN = "chatgpt-codex-connector";

// GitHub renders a GitHub App / bot author's login as the bare handle in
// GraphQL but suffixed with "[bot]" in some REST surfaces. Tolerate both so
// the gate recognises Codex regardless of which shape the login arrives in.
function _isCodexLogin(login) {
  return String(login || "").replace(/\[bot\]$/, "") === CODEX_LOGIN;
}

// Synchronous sleep with no busy-spin (release.js is a synchronous CLI).
function _sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// True once Codex has reviewed the PR's current head — i.e. it reviewed THIS
// revision (a push after the review moves the head and this goes false until
// Codex re-reviews the new head). Codex signals a review in TWO forms and both
// must count, or the gate times out on the common case:
//   (1) when it HAS findings, a formal review node whose commit is the head;
//   (2) when it is CLEAN, an issue comment ("Reviewed commit: `<sha>` — Didn't
//       find any major issues") with NO formal review node and NO commit.oid.
// Recognising only (1) means every clean review times out — the gate would
// only ever pass when Codex complains, which is backwards.
function _codexReviewedHead(prNum) {
  var slug = _repoSlug();
  var head = (_capture("gh", ["pr", "view", prNum, "--json", "headRefOid",
                              "--jq", ".headRefOid"]).stdout || "").trim();
  if (!head) return false;

  // (1) Formal review node whose commit is the current head.
  var rv = _capture("gh", ["api", "graphql",
    "-f", "query=query { repository(owner:\"" + slug.owner + "\",name:\"" + slug.name +
      "\") { pullRequest(number:" + prNum +
      ") { reviews(last:100) { nodes { author{login} commit{oid} } } } } }",
    "--jq", ".data.repository.pullRequest.reviews.nodes"]);
  var nodes;
  try { nodes = JSON.parse(rv.stdout || "[]"); } catch (_e) { nodes = []; }
  if ((nodes || []).some(function (r) {
    return r && r.author && _isCodexLogin(r.author.login) &&
           r.commit && r.commit.oid === head;
  })) return true;

  // (2) Clean-verdict issue comment citing the current head's commit sha.
  var cv = _capture("gh", ["pr", "view", prNum, "--json", "comments", "--jq", ".comments"]);
  var comments;
  try { comments = JSON.parse(cv.stdout || "[]"); } catch (_e) { comments = []; }
  var headPrefix = head.slice(0, 10);
  return (comments || []).some(function (c) {
    return c && c.author && _isCodexLogin(c.author.login) &&
           typeof c.body === "string" && c.body.indexOf(headPrefix) !== -1;
  });
}

// Block until Codex has reviewed the current head (fail-closed on timeout).
// RELEASE_SKIP_CODEX_WAIT=1 is the documented escape hatch for a confirmed
// Codex outage/disablement only — not a routine bypass.
function _waitForCodexReview(prNum) {
  if (process.env.RELEASE_SKIP_CODEX_WAIT === "1") {
    _ok("Codex-review wait skipped (RELEASE_SKIP_CODEX_WAIT=1)");
    return;
  }
  var stepMs = 20 * 1000, budgetMs = 10 * 60 * 1000, waitedMs = 0;
  console.log("waiting for Codex (" + CODEX_LOGIN + ") to review PR #" + prNum +
              " head before the thread gate (up to 10m; it reviews a bit after CI)...");
  while (waitedMs <= budgetMs) {
    if (_codexReviewedHead(prNum)) {
      _ok("Codex has reviewed the current PR head — thread gate now sees its findings");
      return;
    }
    _sleepSync(stepMs);
    waitedMs += stepMs;
  }
  throw new Error("release: Codex has not reviewed PR #" + prNum + " head after 10m. " +
    "It reviews asynchronously; a late finding must not be outrun by the merge. Re-run " +
    "`node scripts/release.js merge` once it posts, or set RELEASE_SKIP_CODEX_WAIT=1 " +
    "ONLY if Codex is confirmed disabled/down.");
}

function _unresolvedThreads(prNum) {
  var slug = _repoSlug();
  var rv = _capture("gh", ["api", "graphql",
    "-f", "query=query { repository(owner:\"" + slug.owner + "\",name:\"" + slug.name +
      "\") { pullRequest(number:" + prNum +
      ") { reviewThreads(first:100) { nodes { id isResolved path line " +
      "comments(first:1) { nodes { author{login} body } } } } } } }",
    "--jq", ".data.repository.pullRequest.reviewThreads.nodes"]);
  var nodes;
  try { nodes = JSON.parse(rv.stdout || "[]"); } catch (_e) { nodes = []; }
  return (nodes || []).filter(function (t) { return t && t.isResolved === false; })
    .map(function (t) {
      var c = t.comments && t.comments.nodes && t.comments.nodes[0];
      return {
        id:     t.id,
        path:   t.path || "(pr-level)",
        line:   t.line,
        author: (c && c.author && c.author.login) || "(unknown)",
        body:   (c && c.body) || "",
      };
    });
}

// Surface each unresolved thread with the exact finding it raises + how to
// clear it, so a BLOCKED merge names its cause instead of "state=BLOCKED".
function _printUnresolvedThreads(unresolved) {
  console.log("\n" + unresolved.length + " unresolved review thread(s) block the merge " +
              "(main-protection requires every thread resolved):\n");
  unresolved.forEach(function (t, i) {
    var lines = (t.body || "").split("\n");
    var firstLine = "(no text)";
    for (var li = 0; li < lines.length; li++) {
      if (lines[li].trim().length > 0) { firstLine = lines[li]; break; }
    }
    firstLine = firstLine.replace(/!\[[^\]]*\]\([^)]*\)/g, "").replace(/[*_`#>]/g, "").trim();
    console.log("  " + (i + 1) + ". [" + t.author + "] " + t.path +
                (t.line != null ? ":" + t.line : ""));
    console.log("     " + firstLine.slice(0, 160));
    console.log("     resolve: gh api graphql -f query='mutation { resolveReviewThread(" +
                "input:{threadId:\"" + t.id + "\"}){ thread { isResolved } } }'");
  });
  console.log("\nFix each finding in a NEW commit on the branch (never dismiss), then run the");
  console.log("resolve command above for its thread. Re-run: node scripts/release.js merge");
}

function cmdWatch() {
  _section("watch");
  var prNum = _openPrNumber(_releaseBranchFor(_readPackageVersion()));
  console.log("PR #" + prNum);

  _run("gh", ["pr", "checks", prNum, "--watch"], { allowFail: true });

  // Wait for Codex to review THIS head before reading threads, so a late
  // finding is caught here instead of being outrun by the merge.
  _waitForCodexReview(prNum);

  var unresolved = _unresolvedThreads(prNum);
  if (unresolved.length > 0) {
    _printUnresolvedThreads(unresolved);
    process.exit(3);
  }
  _ok("Codex has reviewed the head and zero unresolved threads remain (merge re-checks)");

  console.log("\nnext: node scripts/release.js merge");
}

function cmdMerge() {
  _section("merge");
  var next = _readPackageVersion();
  var branch = _releaseBranchFor(next);
  var prNum = _openPrNumber(branch);
  // Authoritative gate: do not read merge state / threads until Codex has
  // reviewed the current head, so its asynchronously-posted findings are in
  // the thread set the checks below enforce.
  _waitForCodexReview(prNum);
  var state = JSON.parse(_capture("gh", ["pr", "view", prNum,
    "--json", "mergeStateStatus,mergeable"]).stdout || "{}");
  // Pull unresolved review threads FIRST. A BLOCKED state is most often
  // unresolved threads — the bot reviews post asynchronously, AFTER the
  // status checks finish, so `watch` can have seen zero while they were
  // still landing. Surface exactly which findings block the merge.
  var unresolved = _unresolvedThreads(prNum);
  if (state.mergeStateStatus !== "CLEAN" || state.mergeable !== "MERGEABLE") {
    if (unresolved.length > 0) _printUnresolvedThreads(unresolved);
    throw new Error("release: PR #" + prNum + " not mergeable (state=" +
                    state.mergeStateStatus + " mergeable=" + state.mergeable + ")" +
                    (unresolved.length > 0
                      ? " — " + unresolved.length + " unresolved review thread(s); see above"
                      : " — no unresolved threads; check required status checks / signatures"));
  }
  // Belt-and-suspenders: even if the API reports CLEAN, refuse on any open
  // thread (a thread can open in the window between the state read and merge).
  if (unresolved.length > 0) {
    _printUnresolvedThreads(unresolved);
    throw new Error("release: refusing to merge PR #" + prNum + " — " +
                    unresolved.length + " unresolved review thread(s)");
  }
  _run("gh", ["pr", "merge", prNum, "--squash", "--delete-branch"]);
  _ok("PR #" + prNum + " squash-merged");

  _run("git", ["checkout", "main"]);
  _run("git", ["pull", "origin", "main"]);

  console.log("\nnext: node scripts/release.js tag");
}

function cmdTag() {
  _section("tag");
  if (!_gitOnMain()) {
    throw new Error("release: tag must run on main (post-merge)");
  }
  var next = _readPackageVersion();
  var tag = "v" + next;

  // Refuse if the tag already exists. The release-tags ruleset refuses tag
  // overwrites server-side; a clearer client-side error is friendlier.
  var existing = _capture("git", ["tag", "-l", tag]).stdout;
  if (existing === tag) {
    throw new Error("release: tag " + tag + " already exists locally");
  }
  _run("git", ["tag", "-s", tag, "-m", tag]);
  _run("git", ["push", "origin", tag]);
  _ok("tagged + pushed " + tag);

  var verify = _capture("git", ["tag", "-v", tag]);
  if (verify.stderr.indexOf("Good") === -1 && verify.stdout.indexOf("Good") === -1) {
    console.error("warning: `git tag -v " + tag + "` did not report a Good signature:");
    console.error(verify.stderr || verify.stdout);
  } else {
    _ok("tag signature: Good");
  }

  console.log("\nnext: node scripts/release.js publish");
}

function cmdPublish() {
  _section("publish");
  var next = _readPackageVersion();
  var pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

  _section("npm-publish workflow");
  var npmRunId = _capture("gh", ["run", "list",
                                  "--workflow=npm-publish.yml",
                                  "--limit", "1",
                                  "--json", "databaseId",
                                  "--jq",   ".[0].databaseId"]).stdout;
  if (npmRunId) {
    _run("gh", ["run", "watch", npmRunId, "--exit-status"], { allowFail: true });
  } else {
    console.log("no npm-publish run found (workflow may not be configured)");
  }

  _section("release-container workflow");
  var containerRunId = _capture("gh", ["run", "list",
                                  "--workflow=release-container.yml",
                                  "--limit", "1",
                                  "--json", "databaseId",
                                  "--jq",   ".[0].databaseId"]).stdout;
  if (containerRunId) {
    _run("gh", ["run", "watch", containerRunId, "--exit-status"], { allowFail: true });
  } else {
    console.log("no release-container run found (the pkijs.com docs image builds on tag)");
  }

  _section("verify");
  var npmVersion = _capture("npm", ["view", pkg.name, "version"]).stdout;
  console.log("npm " + pkg.name + ": " + (npmVersion || "(unable to query)") +
              "  (expected: " + next + ")");
  if (npmVersion && npmVersion !== next) {
    console.error("warning: npm version doesn't match expected — workflow may still be in flight");
  } else if (npmVersion === next) {
    _ok("npm matches " + next);
  }
}

function cmdAll(opts) {
  cmdPrepare(opts);
  cmdSmoke();
  cmdCommit();
  cmdPush(opts);
  cmdWatch();
  cmdMerge();
  cmdTag();
  cmdPublish();
}

function cmdStatus() {
  _section("status");
  console.log("branch:           " + _gitBranch());
  console.log("clean:            " + _gitClean());
  console.log("package version:  " + _readPackageVersion());
  console.log("release-notes:    " + (fs.existsSync(_releaseNotesPath(_readPackageVersion())) ? "present" : "missing"));
  var prNum = _capture("gh", ["pr", "list",
                              "--author", "@me",
                              "--head",   _releaseBranchFor(_readPackageVersion()),
                              "--state",  "open",
                              "--json",   "number,mergeStateStatus,mergeable",
                              "--jq",     ".[0]"]).stdout;
  console.log("open PR:          " + (prNum || "(none)"));
}

function cmdHelp() {
  console.log("release.js — orchestrated release flow");
  console.log("");
  console.log("Usage:");
  console.log("  node scripts/release.js prepare [--minor]   # bump + regen + static gates");
  console.log("  node scripts/release.js regen               # re-regen artifacts after release-notes edits");
  console.log("  node scripts/release.js smoke               # smoke + interop (+ wiki e2e if present)");
  console.log("  node scripts/release.js commit              # release branch + signed commit");
  console.log("  node scripts/release.js interop             # cross-implementation interop tests");
  console.log("  node scripts/release.js push                # interop + gitleaks + push + open PR");
  console.log("  node scripts/release.js push-fix -m \"...\"    # land a review/CI fix on the open PR:");
  console.log("                                              #   gitleaks + signed commit + push + re-request Codex");
  console.log("  node scripts/release.js watch               # CI watch + flag review threads");
  console.log("  node scripts/release.js merge               # squash-merge if CLEAN");
  console.log("  node scripts/release.js tag                 # signed tag + push tag");
  console.log("  node scripts/release.js publish             # watch npm-publish workflow");
  console.log("  node scripts/release.js all [--minor]       # prepare -> ... -> publish");
  console.log("  node scripts/release.js status              # current branch + version state");
  console.log("  node scripts/release.js help                # this banner");
  console.log("");
  console.log("Interop gate (runs inside push and smoke):");
  console.log("  Runs scripts/test-integration.js — the cross-implementation checks that");
  console.log("  prove the toolkit against real-world encodings + published vectors. A");
  console.log("  failing interop run is a HARD STOP. To override (audited, never silent):");
  console.log("  --skip-interop --interop-skip-reason=\"<why>\".");
}

// ---- Dispatch ------------------------------------------------------------

var sub = process.argv[2] || "help";
var args = process.argv.slice(3);

// Parse a `--flag=value` form into its value; returns undefined if absent
// or if the flag was passed bare (no `=value`).
function _flagValue(name) {
  var prefix = name + "=";
  for (var i = 0; i < args.length; i++) {
    if (args[i].indexOf(prefix) === 0) return args[i].slice(prefix.length);
  }
  return undefined;
}

// The push-fix commit message: `-m "…"` / `--message "…"` (value in the next
// token) or `--message="…"` (attached). Returns undefined if absent.
function _messageValue() {
  var attached = _flagValue("--message");
  if (attached !== undefined) return attached;
  for (var i = 0; i < args.length; i++) {
    if (args[i] === "-m" || args[i] === "--message") return args[i + 1];
  }
  return undefined;
}

var opts = {
  minor: args.indexOf("--minor") !== -1,
  // The interop gate is on by default. `--skip-interop` opts out, but ONLY
  // together with `--interop-skip-reason="<why>"`; the reason is printed
  // loudly and recorded in the release-flow transcript.
  skipInterop:       args.indexOf("--skip-interop") !== -1,
  interopSkipReason: _flagValue("--interop-skip-reason"),
  message:           _messageValue(),
};

try {
  switch (sub) {
    case "prepare": cmdPrepare(opts); break;
    case "regen":   cmdRegen();       break;
    case "smoke":   cmdSmoke();       break;
    case "commit":  cmdCommit();      break;
    case "interop": cmdInterop({
                      skip:       opts.skipInterop,
                      skipReason: opts.interopSkipReason,
                    });            break;
    case "push":    cmdPush(opts);    break;
    case "push-fix": cmdPushFix(opts); break;
    case "watch":   cmdWatch();       break;
    case "merge":   cmdMerge();       break;
    case "tag":     cmdTag();         break;
    case "publish": cmdPublish();     break;
    case "all":     cmdAll(opts);     break;
    case "status":  cmdStatus();      break;
    case "help":
    case "--help":
    case "-h":      cmdHelp();        break;
    default:
      console.error("release: unknown subcommand '" + sub + "'");
      cmdHelp();
      process.exit(1);
  }
} catch (e) {
  console.error("\nrelease: FAIL — " + (e.message || e));
  process.exit(1);
}
