#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// scripts/check-operator-prose - static gate that runs the technical-writing
// skill's offline prose checker over every operator-facing document in this
// repository.
//
// Why: README.md, SECURITY.md, MIGRATING.md and their siblings are the surface
// an operator reads after `npm install`. The checker catches the mechanical
// defects a human reviewer skims past. What is ENFORCED here is the set that can
// mislead someone acting on the document: a dash inside a flag that turns a
// copy-pasteable command into a broken one, a malformed RFC or CVE reference, a
// credential-shaped token, a regional spelling mix. The rest of the checker's
// families are advisory in this repository and run under `check:prose:all`; the
// CHECKS constant below carries the evidence for each exclusion.
//
// The checker is a machine-local tool, NOT a dependency of this repository.
// Hard rule #1 is zero npm runtime dependencies, and dev tooling never ships in
// the tarball, so this gate LOCATES the checker at run time and never installs,
// vendors, or postinstalls it.
//
// ABSENCE FAILS. A gate that silently skips when its tool is missing stops
// gating at exactly the moment nobody is told, and the skip bucket is where the
// defect it hunts ends up. The only way past this gate without the checker is a
// declaration that costs something visible - PKI_PROSE_CHECK=off, which someone
// has to write down and can be read back later. A missing file is not that
// declaration, so a missing file is an error.
//
// Availability is decided by PROBING FOR THE FILE, never by reading the
// checker's own output or exit code. "The tool errored, so it must not be
// installed" is precisely how a genuine regression in the tool reads as absence
// and the gate quietly stops gating.
//
// AN INERT CHECKER FAILS TOO. Absence is one failure mode. The other is a
// checker that still runs and has regressed into reporting nothing, and that
// one reads as a clean bill of health on every document it is handed. So a
// positive control runs first: the gate writes a document carrying a defect the
// checker is required to catch, runs the checker on it under the same
// invocation the real documents get, and requires a finding back. A control
// that comes back clean stops the gate there, because a checker that reports
// nothing about a known-bad document reports nothing about the real ones
// either.
//
// The control is an untagged fenced code block. That rule is structural,
// decided by the checker's own fence parser rather than by a data file it
// loads, so it survives a data refresh and a retuning of the style heuristics.
// The control asserts only that SOMETHING was reported - never a finding id, a
// message, or a count above one - so the checker stays free to reword and
// renumber its output.
//
// A CRASHED CHECKER IS NOT A PROSE DEFECT. A tool that throws on load and a
// tool that found twenty real findings both exit non-zero. Telling an operator
// to fix their writing when the tool fell over sends them hunting for a defect
// that is not there, and hides the one that is. A non-zero exit is therefore
// classified before it is reported: the gate asks the checker for a
// machine-readable report of the same run and reads its SHAPE and its finding
// COUNT. Finding TEXT is never read to decide a verdict - that would make this
// script an opinion about the checker's output, which is the thing the
// inherited stdio below exists to prevent.
//
// Coverage is DISCOVERED from disk rather than enumerated, so a document added
// anywhere in the repository is gated the day it lands. There is no list to go
// stale: the gate walks the tree for *.md at every depth, and everything it
// finds is in scope unless the file appears in EXCLUDED or its directory
// appears in SKIPPED_DIRS, each with a written reason that prints on every run.
// Depth is not a scope boundary - .github/ISSUE_TEMPLATE, examples/wiki, fuzz,
// lib/vendor and test/integration all reach anyone who clones the repository,
// which is this project's test for operator-facing.
//
// Environment:
//   PKI_PROSE_CHECKER - path to check_technical_text.mjs, overriding the
//                       default location. Keeps the gate portable to a machine
//                       that installs the skill somewhere else.
//   PKI_PROSE_CHECK   - "off", and only "off", declares a deliberate skip. Any
//                       other value is refused rather than guessed at, because
//                       a misspelt opt-out that silently gates (or silently
//                       does not) is the ambiguity this gate exists to remove.
//
// Exit codes:
//   0 - the checker reported no findings, or a skip was explicitly declared
//   1 - findings present, or the checker could not be found
//   2 - the gate itself could not run (bad configuration, spawn failure)
//   3 - the checker did not flag a known-bad control document, so it is not
//       checking anything and its verdict cannot be trusted
//   4 - the checker did not complete a run, so it returned no verdict at all
//
// Codes 3 and 4 are failures of the TOOL. They say nothing about the prose in
// this repository, and the message on each says so.

var fs    = require("node:fs");
var os    = require("node:os");
var path  = require("node:path");
var proc  = require("node:child_process");

var TAG  = "[check-operator-prose]";
var ROOT = path.resolve(__dirname, "..");

// The default install location of the technical-writing skill. Not the only
// option - PKI_PROSE_CHECKER overrides it - but the one this machine uses.
var DEFAULT_CHECKER = path.join(
  os.homedir(), ".claude", "skills", "technical-writing",
  "scripts", "check_technical_text.mjs"
);

// Markdown that is NOT operator-facing, by repository-relative path. Every
// entry carries the reason it is out of scope, so an exclusion has to be argued
// for in writing rather than added quietly. Anything not listed here is gated.
var EXCLUDED = [
  { file: "CLAUDE.md", reason: "gitignored working instructions - never reaches the repository or the tarball" }
];

// Directories the walk does not enter, by name, at any depth. Same discipline
// as EXCLUDED: a reason per entry, printed on every run. A directory that is
// not listed here is walked, so the only way a document goes unchecked is by
// somebody writing down why.
var SKIPPED_DIRS = [
  { dir: "node_modules", reason: "installed dependencies - another project's prose, and a clone of this one does not carry them" },
  { dir: ".git",         reason: "the object store - no documents, and walking it is slow" },
  { dir: ".claude",      reason: "local agent settings and worktree checkouts - a worktree is a second copy of this repository and would gate every document twice" },
  { dir: ".references",  reason: "internal research and build plans - gitignored, never in a clone or the tarball" },
  { dir: ".scratch",     reason: "internal working notes - gitignored, never in a clone or the tarball" },
  { dir: "memory",       reason: "cross-session working notes - gitignored, never in a clone or the tarball" },
  { dir: "coverage",     reason: "generated coverage report - build output, gitignored" },
  { dir: ".test-output", reason: "gate logs - build output, gitignored" }
];

// The deepest gated document in this tree sits three directories down. The cap
// is a stop for a pathological tree, not a scope decision, so hitting it fails
// the gate rather than silently truncating what gets checked.
var MAX_DEPTH = 8;

function fail(code, lines) {
  lines.forEach(function (l) { console.error(TAG + " " + l); });
  process.exit(code);
}

function msg(e) { return (e && e.message) || String(e); }

// The first lines of a captured run, for a diagnostic. Only ever used to show
// an operator why the checker failed to produce a verdict, never to decide one.
function captured(run) {
  var out = [];
  ["stderr", "stdout"].forEach(function (stream) {
    var text = String(run[stream] || "").replace(/\s+$/, "");
    if (!text) return;
    out.push("", "  --- checker " + stream + " ---");
    text.split(/\r?\n/).slice(0, 20).forEach(function (l) { out.push("  " + l); });
  });
  return out;
}

// ---------------------------------------------------------------------------
// The declared skip. Checked first: it is the one sanctioned way past the gate,
// and it must not depend on the tool it is declaring the absence of.
// ---------------------------------------------------------------------------
var declared = process.env.PKI_PROSE_CHECK;
if (declared !== undefined && String(declared).trim() !== "") {
  var value = String(declared).trim().toLowerCase();
  if (value !== "off") {
    fail(2, [
      "PKI_PROSE_CHECK is set to \"" + declared + "\", which is not a value this gate knows.",
      "The only recognized value is \"off\". An unrecognized value is refused rather than",
      "guessed at, because guessing turns a typo into a silently disabled gate."
    ]);
  }
  console.log(TAG + " ==================================================================");
  console.log(TAG + " SKIPPED BY DECLARATION - PKI_PROSE_CHECK=off");
  console.log(TAG + " Operator-facing prose was NOT checked on this run.");
  console.log(TAG + " This is a declared exemption, not a clean result. Unset");
  console.log(TAG + " PKI_PROSE_CHECK to restore the gate.");
  console.log(TAG + " ==================================================================");
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Resolve the checker, and say which one was used. Order: the environment
// override, then the default location.
// ---------------------------------------------------------------------------
var override = process.env.PKI_PROSE_CHECKER;
var fromEnv  = override !== undefined && String(override).trim() !== "";
var checker  = fromEnv ? path.resolve(String(override).trim()) : DEFAULT_CHECKER;

console.log(TAG + " checker: " + checker);
console.log(TAG + " source:  " + (fromEnv ? "PKI_PROSE_CHECKER" : "default location"));

// Probe for the FILE. Never infer availability from the checker's behavior: a
// tool that has regressed into erroring on every run must fail this gate, not
// be mistaken for a tool that was never installed.
if (!fs.existsSync(checker)) {
  fail(1, [
    "the prose checker was not found.",
    "",
    "  looked for: " + checker,
    "  source:     " + (fromEnv ? "PKI_PROSE_CHECKER environment variable" : "default location"),
    "",
    "This gate fails closed. A missing checker is not a pass - operator-facing prose",
    "went unchecked, and reporting that as success is how the defect it hunts ships.",
    "",
    "To proceed, do one of:",
    "  1. Install the technical-writing skill so the path above resolves.",
    "  2. Point PKI_PROSE_CHECKER at check_technical_text.mjs where it does live.",
    "  3. Declare the skip: PKI_PROSE_CHECK=off. It prints loudly and is a deliberate,",
    "     written act - which is the difference between it and a missing file."
  ]);
}

// ---------------------------------------------------------------------------
// Ask the checker whether it COMPLETED, by re-running it over the same inputs
// for its machine-readable envelope. A crash and a report full of findings both
// exit non-zero, and the two call for opposite actions from the operator.
//
// The envelope is read for its shape - does it parse, does it carry a findings
// array, does it say it examined anything - and for the LENGTH of that array.
// Finding text is never read. A gate that decided its verdict by grepping the
// checker's messages would be filtering the tool it is running, which is the
// defect the inherited stdio on the real run exists to prevent.
// ---------------------------------------------------------------------------
var MAX_REPORT = 32 * 1024 * 1024;

// The scope the gate enforces. Declared here because BOTH the completion probe and the real
// run must use it: scoping only the run would make the probe count a different population,
// and the summary line would then report a number the gate never acted on.
// PKI_PROSE_CHECKS=all widens this to every family the checker implements, which is what
// `npm run check:prose:all` sets. The advisory families are then read by a human rather than
// enforced; the narrow set below is what a machine gets to decide.
var CHECKS = String(process.env.PKI_PROSE_CHECKS || "").trim() === "all"
  ? null
  : "notation,identifiers,secrets,region";
function withChecks(argv) { return CHECKS === null ? argv : argv.concat(["--checks=" + CHECKS]); }

function completionOf(fileArgs) {
  var probe = proc.spawnSync(
    process.execPath,
    withChecks([checker].concat(fileArgs, ["--fail-on-findings", "--json"])),
    { cwd: ROOT, encoding: "utf8", maxBuffer: MAX_REPORT }
  );
  if (probe.error)  return { completed: false, why: "it could not be started (" + msg(probe.error) + ")" };
  if (probe.signal) return { completed: false, why: "it was killed by signal " + probe.signal };
  var env;
  try {
    env = JSON.parse(String(probe.stdout || ""));
  } catch (e) {
    return {
      completed: false,
      why: "it wrote no parseable report to stdout (" + msg(e).split(/\r?\n/)[0].slice(0, 120) + ")"
    };
  }
  if (!env || typeof env !== "object" || !Array.isArray(env.findings)) {
    return { completed: false, why: "its report carries no findings array" };
  }
  if (env.ok !== true) {
    return { completed: false, why: "its own report says it examined nothing (ok=" + JSON.stringify(env.ok) + ")" };
  }
  return { completed: true, findings: env.findings.length };
}

// ---------------------------------------------------------------------------
// The positive control. Everything above proves the checker is THERE; this
// proves it still CHECKS. The fixture goes in the OS temp directory - writing a
// deliberately defective document inside the repository would put it in the
// very tree being gated, and a throw partway would leave it there.
// ---------------------------------------------------------------------------
// The known-bad input must be a defect the gate ENFORCES, not merely one the checker can
// find. An earlier canary used a bare code fence, which is a `convention` finding; once the
// gate was scoped to notation/identifiers/secrets/region that fence stopped tripping, and
// the control correctly reported that its own verdict had become worthless. The defect below
// is a `notation` one -- an em dash where a command's double hyphen belongs, which turns a
// copy-pasteable flag into a broken one -- so the control fails whenever the enforced scope
// stops working. Change CHECKS and this must change with it.
var CANARY_DOC = [
  "# canary",
  "",
  "A control document the prose gate writes, checks, and deletes on every run.",
  "",
  "```bash",
  "npm run build " + "—" + "dry-run",
  "```",
  ""
].join("\n");

function runCanary() {
  var dir;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "pki-prose-canary-"));
  } catch (e) {
    return { code: 2, lines: ["cannot create a canary fixture under " + os.tmpdir() + ": " + msg(e)] };
  }
  var doc = path.join(dir, "canary.md");
  try {
    fs.writeFileSync(doc, CANARY_DOC, "utf8");

    // The same argv the real documents get, INCLUDING the check scope. A control run
    // under a wider scope proves the checker works in a mode nothing else uses: if
    // `notation` regressed but any advisory family still flagged the fixture, the run
    // would exit nonzero and the canary would report OK while the enforced set was dead.
    // All three invocations here -- probe, control, real run -- go through withChecks
    // for that reason.
    var run = proc.spawnSync(
      process.execPath, withChecks([checker, doc, "--fail-on-findings"]),
      { cwd: ROOT, encoding: "utf8", maxBuffer: MAX_REPORT }
    );
    if (run.error) {
      return { code: 2, lines: ["could not run the checker on the control document: " + msg(run.error)] };
    }
    if (run.signal) {
      return {
        code: 4,
        lines: ["the checker was killed by signal " + run.signal + " on the control document."].concat(captured(run))
      };
    }
    if (run.status === 0) {
      return {
        code: 3,
        lines: [
          "the checker did not flag a known-bad input.",
          "",
          "  checker: " + checker,
          "  control: a markdown document whose fenced command writes a flag with an em dash",
          "           where the double hyphen belongs, which is a `notation` defect and so",
          "           sits inside the enforced set above",
          "  result:  exit 0 under --fail-on-findings, which means it found nothing",
          "",
          "A checker that reports nothing about a document written to be reported on will",
          "report nothing about the real documents either, so its verdict on them cannot be",
          "trusted. This is a regression in the TOOL. The prose in this repository has not",
          "been assessed on this run.",
          "",
          "To proceed, do one of:",
          "  1. Repair or reinstall the technical-writing skill so its checker reports again.",
          "  2. Point PKI_PROSE_CHECKER at a check_technical_text.mjs that works.",
          "  3. Declare the skip: PKI_PROSE_CHECK=off. It prints loudly and is on the record."
        ].concat(captured(run))
      };
    }
    var done = completionOf([doc]);
    if (!done.completed) {
      return {
        code: 4,
        lines: [
          "the checker did not complete a run on the control document: " + done.why + ".",
          "It exited " + run.status + " without producing a report.",
          "",
          "  checker: " + checker,
          "",
          "This is a failure of the TOOL. Nothing here is a verdict on the prose in this",
          "repository - no document was assessed on this run."
        ].concat(captured(run))
      };
    }
    if (done.findings < 1) {
      return {
        code: 3,
        lines: [
          "the checker exited " + run.status + " on the control document and then reported zero",
          "findings when asked for the same run again. The two answers disagree, so neither is",
          "a result this gate can act on.",
          "",
          "  checker: " + checker,
          "",
          "This is a failure of the TOOL, and says nothing about the prose in this repository."
        ].concat(captured(run))
      };
    }
    return { ok: true, findings: done.findings };
  } catch (e) {
    return { code: 2, lines: ["the control document could not be prepared: " + msg(e)] };
  } finally {
    // A throw or a failed control must not leave the fixture behind, and
    // process.exit does not run a finally - so every arm above RETURNS and the
    // gate exits after this function, never inside it.
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      console.error(TAG + " warning: the canary fixture " + dir + " could not be removed: " + msg(e));
    }
  }
}

var canary = runCanary();
if (!canary.ok) fail(canary.code, canary.lines);
console.log(TAG + " canary:  OK - the checker flagged the known-bad control document (" +
  canary.findings + " finding(s)), so its verdict below is a real one");

// ---------------------------------------------------------------------------
// Discover the document set. Nothing is hardcoded, so a new document cannot
// join the repository ungated - at any depth.
// ---------------------------------------------------------------------------
var excludedNames = EXCLUDED.map(function (e) { return e.file; });
var skipped = {};
SKIPPED_DIRS.forEach(function (s) { skipped[s.dir] = true; });

var found     = [];
var walkError = null;
var tooDeep   = null;

function walk(dir, rel, depth) {
  if (walkError || tooDeep) return;
  if (depth > MAX_DEPTH) { tooDeep = rel || "."; return; }
  var entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    walkError = (rel || ".") + " - " + msg(e);
    return;
  }
  entries.forEach(function (d) {
    // A symlink is never followed. It is the only way this walk can loop, and a
    // link pointing out of the tree would pull in documents the repository does
    // not carry. Windows junctions report as symlinks here too.
    if (d.isSymbolicLink()) return;
    var child = rel ? rel + "/" + d.name : d.name;
    if (d.isDirectory()) {
      if (skipped[d.name]) return;
      walk(path.join(dir, d.name), child, depth + 1);
      return;
    }
    if (d.isFile() && /\.md$/i.test(d.name)) found.push(child);
  });
}

walk(ROOT, "", 0);

if (walkError) {
  fail(2, [
    "cannot read " + walkError,
    "Discovery stopped there, so the scope of this run is unknown and no part of it",
    "can be reported as clean."
  ]);
}
if (tooDeep) {
  fail(2, [
    "the walk hit its depth cap of " + MAX_DEPTH + " at " + tooDeep + ".",
    "Anything below that directory would go unchecked, and a truncated scope reported",
    "as a pass is the failure this gate exists to prevent. Raise MAX_DEPTH deliberately,",
    "or add the directory to SKIPPED_DIRS with a reason."
  ]);
}

var docs = found
  .filter(function (n) { return excludedNames.indexOf(n) === -1; })
  .sort();

if (docs.length === 0) {
  fail(2, [
    "no operator-facing document was found under " + ROOT + ".",
    "Nothing was checked, which is not a clean result."
  ]);
}

console.log(TAG + " documents (" + docs.length + ", discovered from disk): " + docs.join(", "));
SKIPPED_DIRS.forEach(function (s) {
  console.log(TAG + " skipped:  " + s.dir + "/ - " + s.reason);
});
EXCLUDED.forEach(function (e) {
  console.log(TAG + " excluded: " + e.file + " - " + e.reason);
});
console.log("");

// ---------------------------------------------------------------------------
// Run it. --fail-on-findings is what turns a report into a gate; the checker
// exits 0 with findings otherwise, because its findings are a review by default.
// stdio is inherited so the checker's own output reaches the operator verbatim -
// a summary written here would be this script's opinion of the findings, and
// filtering them would be the exact defect the gate exists to prevent.
// ---------------------------------------------------------------------------
// The gate is SCOPED to the check families that decide something here, because a gate that
// fires on correct prose is one an operator learns to ignore, and then it protects nothing.
//
//   notation     a dash inside --dry-run, a smart quote inside a command, a mangled version
//                constraint. This is the damage the whole checker exists to prevent, and the
//                one class where a false negative ships a broken copy-pasteable command.
//   identifiers  a malformed RFC / CVE / CWE / GHSA / SPDX / package reference.
//   secrets      a credential-shaped token committed into a document.
//   region       a regional-spelling MIX, which is a real inconsistency rather than a taste.
//
// The families left out are advisory here, not silent. `npm run check:prose:all` runs the
// full set for a human read. Each is excluded on evidence, verified against this repository:
//   acronyms      92 flags on CA, TLS, SAN, CSR, DSA. The checker's own text says to leave
//                 them where context disambiguates, and a PKI toolkit is that context.
//                 Expanding "CA" 51 times in a changelog makes the document worse.
//   productnames  fires inside identifiers and URLs its own rule text calls protected
//                 (`tls.servername`, `application/json`, `https://`), and on a bare "r" the
//                 rule says never to fire on.
//   spelling      fires on punctuation: "::", "()", "[]" in badge and code spans.
//   markup        duplicate "Added" / "Fixed" headings, which Keep a Changelog requires once
//                 per release, in a file this repository generates.
//   claims,       flag-only by design: they route to a human owner rather than to a verdict,
//   sources,      so failing a build on them would assert a judgement the checker is
//   style,        explicitly not making.
//   comments
var args = withChecks([checker].concat(docs, ["--fail-on-findings"]));
var run  = proc.spawnSync(process.execPath, args, { cwd: ROOT, stdio: "inherit" });

if (run.error) {
  fail(2, ["could not run the checker: " + msg(run.error)]);
}
if (run.signal) {
  fail(4, ["the checker was killed by signal " + run.signal + " - treat as not run, not as clean."]);
}

var code = run.status;
if (code === 0) {
  console.log("");
  console.log(TAG + " OK - no findings in " + docs.length + " operator-facing document(s)");
  process.exit(0);
}

// A non-zero exit carries two different results, and they ask opposite things of
// the operator: rewrite a sentence, or repair a tool. Classify before reporting.
console.error("");
var outcome = completionOf(docs);

if (!outcome.completed) {
  fail(4, [
    "the checker did not complete a run: " + outcome.why + ".",
    "It exited " + code + " without producing a report.",
    "",
    "  checker:   " + checker,
    "  documents: " + docs.length + ", none of them assessed",
    "",
    "This is a failure of the TOOL. Whatever it printed above is not a verdict on the",
    "prose in this repository - there is no defect here to go and fix. Repair or",
    "reinstall the checker and run the gate again."
  ]);
}
if (outcome.findings === 0) {
  fail(4, [
    "the checker exited " + code + " and then reported zero findings when asked for the same",
    "run again. The two answers disagree, so neither is a result this gate can act on.",
    "",
    "  checker:   " + checker,
    "  documents: " + docs.length,
    "",
    "This is a failure of the TOOL, and says nothing about the prose in this repository."
  ]);
}
fail(1, [
  "the checker completed and reported " + outcome.findings + " finding(s) across " +
    docs.length + " document(s).",
  "Read every one and fix the defect in the prose. This is a REPORT, not yet a blocking",
  "gate: the checker has no per-finding suppression, and this repository has findings that",
  "are correct as they stand -- RFC 8894's title really is \"Simple Certificate Enrolment",
  "Protocol\", security@pkijs.com really is the reporting address, and `rm -rf data data-e2e`",
  "really is the documented wiki test step. No check family reaches zero here, so wiring it",
  "into `npm run gates` would fail every build forever and teach everyone to ignore it.",
  "It goes into `gates` when the checker gains a way to record a reviewed exception."
]);
