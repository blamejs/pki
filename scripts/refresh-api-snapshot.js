// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/refresh-api-snapshot.js
 *
 * Captures the toolkit's public API surface (namespaces, function names,
 * and arities) and writes it to api-snapshot.json at the repo root.
 *
 * The CI gate (scripts/check-api-snapshot.js) compares the live surface
 * against the committed baseline on every PR: removed members, kind
 * changes, or arity changes fail the build; additive changes are logged
 * for visibility so the baseline is refreshed at the next release.
 *
 * Run this script:
 *   - Locally before tagging a release that intentionally changes the
 *     surface (a new primitive, a renamed export, a removed method).
 *   - After every release commit so the baseline tracks the published
 *     version.
 *
 * Usage:
 *   node scripts/refresh-api-snapshot.js
 *
 * The capture / compare / read / write / formatDiff functions are also
 * exported so scripts/check-api-snapshot.js reuses the exact walk that
 * produced the baseline (one source of truth for the surface shape).
 */

var fs   = require("node:fs");
var path = require("node:path");

// Walk cap — the public surface is a shallow tree of namespaces holding
// functions and small data tables. A cap well above the real depth keeps
// a pathological self-referential value from spinning the walker without
// coupling the snapshot to an exact layout.
var MAX_DEPTH = 8;

// Serialize one value into a stable descriptor node:
//   function  -> { kind: "function", arity: N }
//   array     -> { kind: "array", length: N }
//   object    -> { kind: "object", members: { <sorted keys> } }
//   primitive -> { kind: <typeof> }
// `ancestors` is the set of objects on the current path — a cycle guard
// that still lets the same object appear under two different keys (the
// `C` / `constants` alias, for instance) rather than silently dropping
// the second reference.
function _describe(value, depth, ancestors) {
  var t = typeof value;
  if (t === "function") {
    return { kind: "function", arity: value.length };
  }
  if (value === null || t !== "object") {
    return { kind: t };
  }
  if (Array.isArray(value)) {
    return { kind: "array", length: value.length };
  }
  if (depth >= MAX_DEPTH || ancestors.indexOf(value) !== -1) {
    // Bounded: record the shape without descending further.
    return { kind: "object", members: {} };
  }
  var nextAncestors = ancestors.concat([value]);
  var members = {};
  Object.keys(value).sort().forEach(function (k) {
    members[k] = _describe(value[k], depth + 1, nextAncestors);
  });
  return { kind: "object", members: members };
}

// Capture the whole exported surface. `rootExports` is the object returned
// by require("../index.js"); `meta.packageVersion` stamps the snapshot for
// human diffing (it is NOT part of the surface comparison — a version bump
// alone never counts as a breaking change). `meta.sinceByPrimitive` records
// each documented primitive's @since so the introduction version can be
// gated (see checkSince): a primitive's @since is immutable once shipped and
// a newly-added primitive's @since must equal the version introducing it.
function capture(rootExports, meta) {
  meta = meta || {};
  var surface = {};
  Object.keys(rootExports).sort().forEach(function (k) {
    surface[k] = _describe(rootExports[k], 0, []);
  });
  return {
    generator:        "scripts/refresh-api-snapshot.js",
    packageVersion:   meta.packageVersion || null,
    surface:          surface,
    sinceByPrimitive: meta.sinceByPrimitive || {},
  };
}

// Scan the shipped source for every `@primitive <token>` … `@since <ver>`
// pair. Self-contained (no dependency on the wiki comment-block parser) so
// the snapshot tooling stays inside scripts/. Returns { "<token>": "<ver>" }.
function extractSince(libDir) {
  libDir = libDir || path.join(__dirname, "..", "lib");
  var out = {};
  fs.readdirSync(libDir).filter(function (f) { return /\.js$/.test(f); }).sort()
    .forEach(function (f) {
      var src = fs.readFileSync(path.join(libDir, f), "utf8");
      var cur = null;                     // token of the @primitive block in scope
      src.split(/\r?\n/).forEach(function (line) {
        var mp = line.match(/@primitive\s+(\S+)/);
        if (mp) { cur = mp[1]; return; }
        var ms = line.match(/@since\s+(\S+)/);
        if (ms && cur) { out[cur] = ms[1]; cur = null; }
      });
    });
  return out;
}

// Parse a plain "X.Y.Z" version into comparable numbers. Returns null for a
// non-semver string so callers can flag it rather than mis-order it.
function _verParts(v) {
  if (typeof v !== "string" || !/^\d+\.\d+\.\d+$/.test(v)) return null;
  return v.split(".").map(Number);
}

// -1 / 0 / 1 for a<b / a==b / a>b; null if either side is un-parseable.
function _cmpVer(a, b) {
  var pa = _verParts(a), pb = _verParts(b);
  if (!pa || !pb) return null;
  for (var i = 0; i < 3; i++) { if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1; }
  return 0;
}

// Gate the @since map against the introduction-version contract. `oldMap` is
// the prior on-disk snapshot's sinceByPrimitive (undefined/null on the first
// run that seeds the field — bootstrap: skip the immutability / new-primitive
// checks that need a baseline, but still enforce the always-valid ≤ bound).
// Returns an array of human-readable violation strings (empty = clean):
//   (a) any primitive whose @since is not valid semver or is > packageVersion
//       (a primitive cannot be introduced in a future version);
//   (b) a primitive present in both maps whose @since changed (immutable once
//       shipped);
//   (c) a primitive absent from oldMap (newly added) whose @since is not
//       exactly packageVersion (this is the registerFamily-@since-0.1.1 class).
function checkSince(oldMap, newMap, packageVersion) {
  var violations = [];
  var haveBaseline = oldMap && typeof oldMap === "object";
  Object.keys(newMap).sort().forEach(function (tok) {
    var since = newMap[tok];
    var cmp = _cmpVer(since, packageVersion);
    if (cmp === null) {
      violations.push(tok + ": @since " + JSON.stringify(since) + " is not a valid X.Y.Z version");
      return;
    }
    if (cmp > 0) {
      violations.push(tok + ": @since " + since + " is later than the package version " +
        packageVersion + " (a primitive cannot be introduced in a future version)");
    }
    if (haveBaseline && Object.prototype.hasOwnProperty.call(oldMap, tok)) {
      if (oldMap[tok] !== since) {
        violations.push(tok + ": @since changed " + oldMap[tok] + " -> " + since +
          " (a shipped primitive's introduction version is immutable)");
      }
    } else if (haveBaseline && cmp !== 0) {
      violations.push(tok + ": new primitive @since " + since + " must equal the introducing " +
        "version " + packageVersion + " (set @since to the release that adds it)");
    }
  });
  return violations;
}

// Scan the shipped source for every `@primitive <token>` … `@originated <ver>`
// pair (mirrors extractSince). @originated records the earlier version the
// callable was already reachable when its documented @primitive PATH was later
// corrected. Returns { "<token>": "<ver>" } for the primitives that declare it.
function extractOriginated(libDir) {
  libDir = libDir || path.join(__dirname, "..", "lib");
  var out = {};
  fs.readdirSync(libDir).filter(function (f) { return /\.js$/.test(f); }).sort()
    .forEach(function (f) {
      var src = fs.readFileSync(path.join(libDir, f), "utf8");
      var cur = null;
      src.split(/\r?\n/).forEach(function (line) {
        var mp = line.match(/@primitive\s+(\S+)/);
        if (mp) { cur = mp[1]; return; }
        var mo = line.match(/@originated\s+(\S+)/);
        if (mo && cur) { out[cur] = mo[1]; }
      });
    });
  return out;
}

// Enforce the @originated contract: when a documented @primitive path is REMOVED
// from the since-map while the exported SURFACE is unchanged, the removal is a
// documentation-path CORRECTION (the callable still ships), not a deletion — so
// the origin version must not be lost. Some source primitive MUST declare
// `@originated <removed>.since`. `surfaceUnchanged` is compare(old,new) reporting
// zero breaking + zero additive (a pure doc-path release). A real surface change
// (a genuine add/remove) is governed by the breaking-change flow, not this gate.
// Returns human-readable violation strings (empty = clean).
function checkOriginated(oldSince, newSince, originatedMap, surfaceUnchanged) {
  if (!oldSince || !surfaceUnchanged) return [];
  var declared = Object.keys(originatedMap || {}).map(function (k) { return originatedMap[k]; });
  var violations = [];
  Object.keys(oldSince).forEach(function (tok) {
    if (Object.prototype.hasOwnProperty.call(newSince, tok)) return;   // still documented
    if (declared.indexOf(oldSince[tok]) === -1) {
      violations.push(tok + ": documented path removed while the exported surface is unchanged " +
        "(a path correction) — the replacement primitive must declare `@originated " + oldSince[tok] +
        "` so the origin version is preserved");
    }
  });
  return violations;
}

// Compare two captured snapshots. Only the `surface` tree is compared —
// packageVersion drift is ignored on purpose. Returns:
//   { breaking: [ "<path>: <reason>" ], additive: [ "<path>: added" ] }
// A removed member, a kind change, or a function-arity change is breaking;
// a newly-present member is additive.
function compare(baseline, current) {
  var breaking = [];
  var additive = [];
  _diffNode("pki", (baseline && baseline.surface) || {},
    (current && current.surface) || {}, breaking, additive, true);
  return { breaking: breaking, additive: additive };
}

// `isRoot` distinguishes the top-level namespace map (whose entries are
// keyed directly) from an object node (whose entries live under `.members`).
function _diffNode(pathPrefix, baseNode, curNode, breaking, additive, isRoot) {
  var baseMembers = isRoot ? baseNode : ((baseNode && baseNode.members) || {});
  var curMembers  = isRoot ? curNode  : ((curNode  && curNode.members)  || {});

  Object.keys(baseMembers).forEach(function (k) {
    var childPath = pathPrefix + "." + k;
    var b = baseMembers[k];
    var c = curMembers[k];
    if (!Object.prototype.hasOwnProperty.call(curMembers, k) || c === undefined) {
      breaking.push(childPath + ": removed");
      return;
    }
    if (b.kind !== c.kind) {
      breaking.push(childPath + ": kind changed (" + b.kind + " -> " + c.kind + ")");
      return;
    }
    if (b.kind === "function" && b.arity !== c.arity) {
      breaking.push(childPath + ": arity changed (" + b.arity + " -> " + c.arity + ")");
    }
    if (b.kind === "object") {
      _diffNode(childPath, b, c, breaking, additive, false);
    }
  });

  Object.keys(curMembers).forEach(function (k) {
    if (!Object.prototype.hasOwnProperty.call(baseMembers, k)) {
      additive.push(pathPrefix + "." + k + ": added");
    }
  });
}

function formatDiff(diff) {
  var lines = [];
  if (diff.breaking.length === 0 && diff.additive.length === 0) {
    return "[api-snapshot] surface unchanged.";
  }
  if (diff.breaking.length > 0) {
    lines.push("[api-snapshot] BREAKING (" + diff.breaking.length + "):");
    diff.breaking.forEach(function (m) { lines.push("  - " + m); });
  }
  if (diff.additive.length > 0) {
    lines.push("[api-snapshot] additive (" + diff.additive.length + "):");
    diff.additive.forEach(function (m) { lines.push("  + " + m); });
  }
  return lines.join("\n");
}

function read(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function write(snapshot, p) {
  fs.writeFileSync(p, JSON.stringify(snapshot, null, 2) + "\n");
}

module.exports = {
  capture:      capture,
  compare:      compare,
  formatDiff:   formatDiff,
  extractSince: extractSince,
  checkSince:   checkSince,
  extractOriginated: extractOriginated,
  checkOriginated:   checkOriginated,
  read:         read,
  write:        write,
};

if (require.main === module) {
  var pki = require("../index.js");
  var pkg = require("../package.json");
  var outPath = path.join(__dirname, "..", "api-snapshot.json");
  var sinceByPrimitive = extractSince();

  // Gate @since against the prior on-disk snapshot BEFORE overwriting it —
  // this is the only point where "what existed before this refresh" is still
  // readable, so a newly-added primitive with the wrong introduction version
  // (or a mutated @since) is refused here rather than silently baked in.
  var prior = null;
  try { prior = read(outPath); } catch (_e) { /* first run — nothing to compare */ }
  var sinceViolations = checkSince(prior && prior.sinceByPrimitive, sinceByPrimitive, pkg.version);
  if (sinceViolations.length > 0) {
    process.stderr.write("[refresh-api-snapshot] @since violations (fix the source @since tags):\n");
    sinceViolations.forEach(function (m) { process.stderr.write("  - " + m + "\n"); });
    process.exit(2);
  }

  var snapshot = capture(pki, { packageVersion: pkg.version, sinceByPrimitive: sinceByPrimitive });

  // @originated gate: when this refresh removes a documented @primitive path while
  // the exported surface is unchanged, the path was CORRECTED (not deleted) — the
  // origin version must be preserved via an @originated tag somewhere in source.
  if (prior) {
    var diff = compare(prior, snapshot);
    var surfaceUnchanged = diff.breaking.length === 0 && diff.additive.length === 0;
    var origViolations = checkOriginated(prior.sinceByPrimitive, sinceByPrimitive, extractOriginated(), surfaceUnchanged);
    if (origViolations.length > 0) {
      process.stderr.write("[refresh-api-snapshot] @originated violations (a corrected path must preserve its origin):\n");
      origViolations.forEach(function (m) { process.stderr.write("  - " + m + "\n"); });
      process.exit(2);
    }
  }

  write(snapshot, outPath);
  process.stdout.write("[refresh-api-snapshot] wrote " + outPath +
    " (packageVersion=" + snapshot.packageVersion + ")\n");
}
