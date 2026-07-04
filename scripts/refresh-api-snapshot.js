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
// alone never counts as a breaking change).
function capture(rootExports, meta) {
  meta = meta || {};
  var surface = {};
  Object.keys(rootExports).sort().forEach(function (k) {
    surface[k] = _describe(rootExports[k], 0, []);
  });
  return {
    generator:      "scripts/refresh-api-snapshot.js",
    packageVersion: meta.packageVersion || null,
    surface:        surface,
  };
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
  capture:    capture,
  compare:    compare,
  formatDiff: formatDiff,
  read:       read,
  write:      write,
};

if (require.main === module) {
  var pki = require("../index.js");
  var pkg = require("../package.json");
  var snapshot = capture(pki, { packageVersion: pkg.version });
  var outPath = path.join(__dirname, "..", "api-snapshot.json");
  write(snapshot, outPath);
  process.stdout.write("[refresh-api-snapshot] wrote " + outPath +
    " (packageVersion=" + snapshot.packageVersion + ")\n");
}
