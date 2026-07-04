#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/generate-changelog-entry.js
 *
 * Emit the changelog entry for ONE release from its structured source at
 * `release-notes/v<version>.json`. This is the single-version companion to
 * `scripts/gen-changelog.js` (which renders the whole CHANGELOG.md): it
 * performs the same section->markdown transform for exactly one version so
 * a downstream consumer — a GitHub release body, an npm release note — can
 * pull just that entry.
 *
 * The structured source keeps the entry operator-facing by construction:
 * every field has a known semantic (headline, summary, sections[heading]),
 * and each string runs through a leak-vocabulary validator before render.
 * Hand-written prose can drift into internal-process narrative (phase /
 * sweep / tier numbering, AI-tooling vocabulary); the JSON pipeline refuses
 * such input at validation time.
 *
 * Usage:
 *   node scripts/generate-changelog-entry.js            # version from package.json
 *   node scripts/generate-changelog-entry.js 0.1.0      # explicit version
 *   node scripts/generate-changelog-entry.js 0.1.0 --json
 *
 * Output:
 *   default   Keep-a-Changelog markdown for the one version, to stdout:
 *               ## vX.Y.Z — YYYY-MM-DD
 *               <headline>
 *               ### <Section>
 *               - <item>
 *   --json    a structured JSON object to stdout — { version, date,
 *             headline, summary, sections, markdown } — so tooling that
 *             wants the entry's fields (not just the rendered form) can
 *             consume them directly. The `markdown` field carries the same
 *             text the default mode prints.
 *
 * release-notes/v<version>.json shape (object-keyed sections; each item is
 * a plain operator-facing sentence):
 *   {
 *     "version":  "0.1.0",
 *     "date":     "2026-07-04",   // optional; falls back to the v<version>
 *                                 // tag date, else today (UTC)
 *     "headline": "one-line summary",
 *     "summary":  "one-paragraph why-it-matters",   // optional
 *     "sections": { "Added": [ "...", ... ], "Security": [ "..." ] }
 *   }
 * `sections` may also be an array of { heading, items } for forward
 * compatibility; either shape renders identically. When the per-patch file
 * is absent the lookup falls back to a consolidated minor-line rollup at
 * `release-notes/v<minor>.x.json` (see scripts/consolidate-release-notes.js).
 *
 * Exit codes:
 *   0  entry rendered
 *   1  release notes missing / malformed / failed validation
 */

var fs   = require("node:fs");
var path = require("node:path");
var cp   = require("node:child_process");

var ROOT         = path.resolve(__dirname, "..");
var PACKAGE_JSON = path.join(ROOT, "package.json");
var NOTES_DIR    = path.join(ROOT, "release-notes");

// Keep a Changelog's canonical section order (mirrors gen-changelog.js so
// the single-entry render is byte-identical to that version's block in the
// full CHANGELOG). Unknown headings sort after, in first-seen order.
var SECTION_ORDER = ["Added", "Changed", "Deprecated", "Removed", "Fixed", "Security", "Detectors", "Migration"];

// LEAK_PATTERNS — tokens that signal internal-process narrative instead of
// operator-facing description. The `claude`-file token is assembled from
// char codes so the literal string doesn't appear in this validator's own
// source either.
function _leakPatterns() {
  var cfg = [67, 76, 65, 85, 68, 69]
    .map(function (c) { return String.fromCharCode(c); })
    .join("");
  return [
    new RegExp("\\b" + cfg + "\\.md\\b"),
    new RegExp("\\bper\\s+" + cfg + "\\b"),
    /\bper\s+project\s+rule\s+§/,
    /\bper\s+rule\s+§\d/,
    /\bphase\s+\d/i,
    /\bsweep\s+\d/i,
    /\btier[- ]?[abc]\b/i,
    /\bbatch\s+\d/i,
    /\bgroup\s+[a-h]\b/i,
    /\bslice\s+\d/i,
    /\baudit[- ]derived\b/i,
    /\bpost[- ]audit\b/i,
    /\b(?:anthropic|chatgpt|openai|copilot|sonnet|opus|haiku|gemini|co[- ]authored[- ]by|llm[- ]generated|ai[- ]generated)\b/i,
  ];
}

function _exit(msg) {
  process.stderr.write("[generate-changelog-entry] " + msg + "\n");
  process.exit(1);
}

function _readJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, "utf8"); }
  catch (e) { _exit("cannot read " + label + " (" + filePath + "): " + ((e && e.message) || e)); }
  try { return JSON.parse(raw); }
  catch (e) { _exit("malformed JSON in " + label + " (" + filePath + "): " + ((e && e.message) || e)); }
  return null;   // unreachable
}

// Read-without-pre-check: one readFileSync that distinguishes ENOENT
// (file genuinely absent — caller decides) from other errors (fail loud),
// avoiding the existsSync -> readFileSync TOCTOU race.
function _tryReadJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, "utf8"); }
  catch (e) {
    if (e && e.code === "ENOENT") return null;
    _exit("cannot read " + label + " (" + filePath + "): " + ((e && e.message) || e));
  }
  try { return JSON.parse(raw); }
  catch (e) { _exit("malformed JSON in " + label + " (" + filePath + "): " + ((e && e.message) || e)); }
  return null;   // unreachable
}

// Strict semver gate at the trust boundary — every downstream use of
// `version` builds a path segment or a `v<version>` string. Refuse anything
// that isn't `\d+.\d+.\d+` before it reaches a path join.
function _requireSemver(version, label) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version)) {
    _exit(label + " is not strict semver `\\d+.\\d+.\\d+`: " + JSON.stringify(version));
  }
  return version;
}

function _readPackageVersion() {
  return _readJson(PACKAGE_JSON, "package.json").version;
}

// Tag date for v<version>, or null when the tag isn't present yet (the
// version being cut has no tag until after merge).
function _tagDate(version) {
  var rv = cp.spawnSync("git",
    ["log", "-1", "--format=%cd", "--date=short", "v" + version],
    { cwd: ROOT, encoding: "utf8" });
  if (rv.status !== 0) return null;
  var out = (rv.stdout || "").trim();
  return /^\d{4}-\d{2}-\d{2}$/.test(out) ? out : null;
}

function _todayUtc() {
  return new Date().toISOString().slice(0, 10);
}

// Normalize `sections` (object keyed by heading, OR an array of
// { heading, items }) into an ordered list of { heading, items } sorted to
// the canonical section order. Items are coerced to plain strings so both
// the string-item shape and a forward-compatible { title } shape render.
function _normalizeSections(sections) {
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
      var arr = sections[h];
      if (!Array.isArray(arr)) return;
      pairs.push({
        heading: h,
        items: arr.map(function (it) {
          return typeof it === "string" ? it : (it && it.title ? it.title : String(it));
        }),
      });
    });
  }
  pairs.sort(function (a, b) {
    var ia = SECTION_ORDER.indexOf(a.heading);
    var ib = SECTION_ORDER.indexOf(b.heading);
    if (ia === -1 && ib === -1) return 0;
    if (ia === -1) return 1;
    if (ib === -1) return -1;
    return ia - ib;
  });
  return pairs.filter(function (p) { return p.items.length > 0; });
}

function _walkForLeaks(node, basePath, patterns, out) {
  if (typeof node === "string") {
    for (var i = 0; i < patterns.length; i += 1) {
      if (patterns[i].test(node)) out.push({ path: basePath, pattern: patterns[i].source });
    }
    return;
  }
  if (Array.isArray(node)) {
    for (var j = 0; j < node.length; j += 1) {
      _walkForLeaks(node[j], basePath + "[" + j + "]", patterns, out);
    }
    return;
  }
  if (node && typeof node === "object") {
    var keys = Object.keys(node);
    for (var k = 0; k < keys.length; k += 1) {
      if (keys[k] === "$schema") continue;
      _walkForLeaks(node[keys[k]], basePath + "." + keys[k], patterns, out);
    }
  }
}

// Validate the release-notes document against the object-keyed shape used
// across this repo, then sweep every string for leak vocabulary. Refuses
// loud on any problem so a malformed entry never renders half-formed.
function validate(notes, version) {
  var errs = [];

  if (notes.version !== version) {
    errs.push("`version` is " + JSON.stringify(notes.version) + " but expected " + JSON.stringify(version));
  }
  if (notes.date !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(String(notes.date))) {
    errs.push("`date` (when present) must be `YYYY-MM-DD`; got " + JSON.stringify(notes.date));
  }
  if (typeof notes.headline !== "string" || notes.headline.trim().length === 0) {
    errs.push("`headline` missing or empty");
  } else if (notes.headline !== notes.headline.trim()) {
    errs.push("`headline` has leading/trailing whitespace");
  }
  if (notes.summary !== undefined) {
    if (typeof notes.summary !== "string") errs.push("`summary` must be a string when present");
    else if (notes.summary !== notes.summary.trim()) errs.push("`summary` has leading/trailing whitespace");
  }

  var normalized = _normalizeSections(notes.sections);
  if (normalized.length === 0) {
    errs.push("`sections` must be a non-empty object/array with at least one non-empty section");
  } else {
    var seen = {};
    for (var s = 0; s < normalized.length; s += 1) {
      var sec = normalized[s];
      if (SECTION_ORDER.indexOf(sec.heading) === -1) {
        errs.push("section heading " + JSON.stringify(sec.heading) +
          " not in allowlist: " + SECTION_ORDER.join(" / "));
      }
      if (seen[sec.heading]) {
        errs.push("section heading " + JSON.stringify(sec.heading) + " appears twice — consolidate its items");
      }
      seen[sec.heading] = true;
      for (var t = 0; t < sec.items.length; t += 1) {
        if (typeof sec.items[t] !== "string" || sec.items[t].trim().length === 0) {
          errs.push("sections." + sec.heading + "[" + t + "] must be a non-empty string");
        }
      }
    }
  }

  var hits = [];
  _walkForLeaks(notes, "$", _leakPatterns(), hits);
  if (hits.length > 0) {
    process.stderr.write("[generate-changelog-entry] FAIL: leak-vocabulary tokens found in release-notes JSON:\n");
    for (var h = 0; h < hits.length; h += 1) {
      process.stderr.write("  " + hits[h].path + "  <-  pattern /" + hits[h].pattern + "/\n");
    }
    process.stderr.write("[generate-changelog-entry] Each field must be operator-facing. Strip internal-process narrative + rewrite.\n");
    process.exit(1);
  }

  if (errs.length > 0) {
    process.stderr.write("[generate-changelog-entry] FAIL:\n");
    for (var e = 0; e < errs.length; e += 1) process.stderr.write("  - " + errs[e] + "\n");
    process.exit(1);
  }

  return normalized;
}

// Look up the release notes: per-patch `v<version>.json` first, then the
// consolidated minor-line rollup `v<minor>.x.json` (a { releases: [...] }
// wrapper) so historical minors collapsed by consolidate-release-notes.js
// still resolve.
function _loadReleaseNotes(version) {
  var perPatch = _tryReadJson(path.join(NOTES_DIR, "v" + version + ".json"),
    "release-notes/v" + version + ".json");
  if (perPatch !== null) return { notes: perPatch, source: "v" + version + ".json" };

  var minor = version.replace(/\.\d+$/, "");   // pre-validated semver, no metachars
  var con = _tryReadJson(path.join(NOTES_DIR, "v" + minor + ".x.json"),
    "release-notes/v" + minor + ".x.json");
  if (con !== null) {
    if (!Array.isArray(con.releases)) {
      _exit("consolidated file release-notes/v" + minor + ".x.json missing `releases` array");
    }
    for (var i = 0; i < con.releases.length; i += 1) {
      if (con.releases[i] && con.releases[i].version === version) {
        return { notes: con.releases[i], source: "v" + minor + ".x.json (releases[" + i + "])" };
      }
    }
    _exit("v" + version + " not found inside consolidated file release-notes/v" + minor + ".x.json");
  }
  _exit("cannot find release notes for v" + version + " — looked at " +
    "release-notes/v" + version + ".json AND release-notes/v" + minor + ".x.json");
  return null;   // unreachable
}

// Render the single-version Keep-a-Changelog block. Format matches
// gen-changelog.js exactly (em-dash header separator; blank line between
// headline, each section header, and its bullet list).
function renderEntry(notes, date, sections) {
  var EM = "—";
  var out = [];
  out.push("## v" + notes.version + " " + EM + " " + date);
  out.push("");
  if (notes.headline) {
    out.push(notes.headline);
    out.push("");
  }
  sections.forEach(function (s) {
    out.push("### " + s.heading);
    out.push("");
    s.items.forEach(function (item) { out.push("- " + item); });
    out.push("");
  });
  return out.join("\n").replace(/\n+$/, "\n");
}

function main() {
  var argv = process.argv.slice(2);
  var jsonMode = argv.indexOf("--json") !== -1;
  var explicitVersion = null;
  for (var a = 0; a < argv.length; a += 1) {
    if (!argv[a].startsWith("--")) { explicitVersion = argv[a]; break; }
  }

  var version = _requireSemver(
    explicitVersion || _readPackageVersion(),
    explicitVersion ? "version argument" : "package.json#version"
  );

  var loaded     = _loadReleaseNotes(version);
  var notes      = loaded.notes;
  var sections   = validate(notes, version);
  var date       = (notes.date && /^\d{4}-\d{2}-\d{2}$/.test(String(notes.date)))
    ? notes.date
    : (_tagDate(version) || _todayUtc());
  var markdown   = renderEntry(notes, date, sections);

  if (jsonMode) {
    var doc = {
      version:  version,
      date:     date,
      headline: notes.headline || "",
      summary:  typeof notes.summary === "string" ? notes.summary : null,
      sections: sections,
      markdown: markdown,
    };
    process.stdout.write(JSON.stringify(doc, null, 2) + "\n");
    process.stderr.write("[generate-changelog-entry] OK — v" + version +
      " structured entry (" + sections.length + " section(s)) from " + loaded.source + "\n");
    return;
  }

  process.stdout.write(markdown);
  process.stderr.write("[generate-changelog-entry] OK — rendered v" + version +
    " entry (" + markdown.length + " chars) from " + loaded.source + ". Use --json for structured output.\n");
}

main();
