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
  var out = {
    generator:        "scripts/refresh-api-snapshot.js",
    packageVersion:   meta.packageVersion || null,
    surface:          surface,
    sinceByPrimitive: meta.sinceByPrimitive || {},
  };
  // The error-code surface rides in the same baseline as the API surface, because
  // a `domain/reason` code is the same kind of promise: an operator switches on it.
  if (meta.errorCodes) {
    out.errorCodes = meta.errorCodes;
    out.errorCodeDomains = meta.errorCodeDomains || [];
    out.errorCodeStems = meta.errorCodeStems || [];
    out.errorCodesWithoutVector = meta.errorCodesWithoutVector || [];
  }
  return out;
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

// Strip comments, keeping string literals. The error-code scan below reads
// literals off the source, and `framework-error.js` documents how to define an
// error class with an @example that throws `my/bad-input`; a scan that reads
// comments admits that example as a shipped code and `my` as a domain. A `//`
// inside a string (`http://`) must not open a comment, so this walks characters
// rather than matching a pattern.
function _stripComments(src) {
  var out = "", i = 0, n = src.length;
  while (i < n) {
    var c = src[i], d = src[i + 1];
    if (c === "\"" || c === "'" || c === "`") {
      var q = c; out += c; i++;
      while (i < n) {
        if (src[i] === "\\") { out += src[i] + (src[i + 1] || ""); i += 2; continue; }
        out += src[i];
        if (src[i] === q) { i++; break; }
        i++;
      }
      continue;
    }
    if (c === "/" && d === "/") { while (i < n && src[i] !== "\n") i++; continue; }
    if (c === "/" && d === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    out += c; i++;
  }
  return out;
}

function _jsFilesUnder(dir, out) {
  out = out || [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var p = path.join(dir, e.name);
    if (e.isDirectory()) _jsFilesUnder(p, out);
    else if (/\.js$/.test(e.name)) out.push(p);
  });
  return out;
}

// A code-shaped literal is not necessarily a code: `application/pkcs7-mime`,
// `text/plain`, `multipart/mixed` and `message/rfc822` are media types and share
// the shape exactly. So the DOMAIN set is derived first, from literals sitting in
// an error factory's own first argument, and only then is a code-shaped literal
// accepted on the strength of its domain. A media type cannot be admitted that
// way, because nothing throws `application/...`.
//
// The callee names vary per module (`_err`, `E`, `_signE`, `_ctErr`, `NS.E`, a bare
// `CmsError`, and `lib/lint.js`'s `_cfg`), so matching the call is only half of the
// answer: a pattern over factory names is a naming convention, and `_cfg` is what
// happens when a module does not follow it. Anchoring there omitted the whole `lint`
// domain, codes and all, from a gate whose job is to notice exactly that.
//
// So the domain set is a UNION of two sources that fail in different directions:
// the call shape below, which finds a domain no namespace is named after, and the
// shipped namespace list, which is authoritative and has no naming convention to
// break. A media type cannot enter through either: nothing throws
// `application/...`, and no namespace is called `application`, `text`, `multipart`
// or `message`.
var _CODE_FACTORY = /(?:\b(?:_?err|_?E|[A-Za-z_$][\w$]*(?:Err|Error|E|_cfg))\s*)\(\s*["']([a-z][a-z0-9]*)\/([a-z][a-z0-9-]*)["']/g;
var _CODE_ANY = /["']([a-z][a-z0-9]*)\/([a-z][a-z0-9-]*)["']/g;

// Every `domain/reason` the shipped source can throw, as a sorted array.
// A literal ending in a dash is a STEM a value is appended to
// (`"acme/bad-" + _codeSlug(kind)`), so it is not a whole code; stems are
// returned separately rather than silently dropped, because a gate that claims to
// freeze the surface has to say which part of it it cannot see.
// `namespaceHints` is the shipped namespace list (`Object.keys(pki)`), the half of the
// domain set that does not depend on how a module names its error factory.
function extractErrorCodes(libDir, namespaceHints) {
  libDir = libDir || path.join(__dirname, "..", "lib");
  var sources = _jsFilesUnder(libDir).sort().map(function (f) {
    return _stripComments(fs.readFileSync(f, "utf8"));
  });
  var domains = {}, m;
  sources.forEach(function (src) {
    _CODE_FACTORY.lastIndex = 0;
    while ((m = _CODE_FACTORY.exec(src)) !== null) domains[m[1]] = true;
  });
  (namespaceHints || []).forEach(function (k) {
    if (typeof k === "string" && /^[A-Za-z][\w$]*$/.test(k)) domains[k.toLowerCase()] = true;
  });
  // A literal in a COMPARISON or a `case` label is a code being READ, not one being
  // thrown: `if (e.code === "tuf/bad-signature")` sits beside the throw that produces it.
  // Counting those would let a stale read keep a code in the frozen set after its throw
  // was deleted, so the freeze would report nothing on the removal it exists to catch.
  // The test is on what precedes the literal, which is what tells a read from an argument;
  // a code reached only through a variable is still seen, because the assignment that
  // names it is not a comparison.
  var READ_POSITION = /(?:===|!==|==|!=|\bcase)\s*$/;
  var codes = {}, stems = {};
  sources.forEach(function (src) {
    _CODE_ANY.lastIndex = 0;
    while ((m = _CODE_ANY.exec(src)) !== null) {
      if (!domains[m[1]]) continue;
      if (READ_POSITION.test(src.slice(Math.max(0, m.index - 8), m.index))) continue;
      var code = m[1] + "/" + m[2];
      if (code.charAt(code.length - 1) === "-") stems[code] = true;
      else codes[code] = true;
    }
  });
  return {
    codes: Object.keys(codes).sort(),
    domains: Object.keys(domains).sort(),
    stems: Object.keys(stems).sort(),
  };
}

// The codes a test names. Comments are stripped here too: a code mentioned only
// in a test's prose is not a test that asserts it.
function extractAssertedCodes(testDir) {
  testDir = testDir || path.join(__dirname, "..", "test");
  var joined = _jsFilesUnder(testDir).map(function (f) {
    return _stripComments(fs.readFileSync(f, "utf8"));
  }).join("\n");
  var found = {}, m;
  _CODE_ANY.lastIndex = 0;
  while ((m = _CODE_ANY.exec(joined)) !== null) found[m[1] + "/" + m[2]] = true;
  return found;
}

// The two verdicts over the code surface.
//
// `removed` is the freeze: a `domain/reason` is a contract an operator switches
// on, so a code the baseline recorded and the source no longer throws was renamed
// or deleted under them.
//
// `unasserted` is the coverage rule: a code no test names is a code whose rename
// no gate would catch, which is the hole the freeze exists to close. The baseline
// carries the residual that predates the rule, and it may only shrink: a code
// outside it has to arrive with a test that names it.
function checkErrorCodes(baseline, live, asserted) {
  var baseCodes = (baseline && baseline.errorCodes) || [];
  var allowed = (baseline && baseline.errorCodesWithoutVector) || [];
  var liveSet = {};
  live.forEach(function (c) { liveSet[c] = true; });
  return {
    removed: baseCodes.filter(function (c) { return !liveSet[c]; }),
    added: live.filter(function (c) { return baseCodes.indexOf(c) === -1; }),
    unasserted: live.filter(function (c) { return !asserted[c] && allowed.indexOf(c) === -1; }),
    closed: allowed.filter(function (c) { return asserted[c] || !liveSet[c]; }),
  };
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

// Gate against silent deletion of a documented primitive's introduction
// record: every token in the prior map must still be present in the new map,
// or its origin version preserved by an @originated declaration (the
// documented-path-correction flow). Deleting the @since line would otherwise
// vacate the immutability freeze for that primitive, letting a later re-add
// pass the new-primitive check with a rewritten introduction version.
// Returns human-readable violation strings (empty = clean).
function checkSinceDropped(oldMap, newMap, originatedMap) {
  if (!oldMap || typeof oldMap !== "object") return [];
  var declared = Object.keys(originatedMap || {}).map(function (k) { return originatedMap[k]; });
  var violations = [];
  Object.keys(oldMap).sort().forEach(function (tok) {
    if (Object.prototype.hasOwnProperty.call(newMap, tok)) return;   // still documented
    if (declared.indexOf(oldMap[tok]) !== -1) return;                // origin preserved
    violations.push(tok + ": documented @since " + oldMap[tok] + " was removed from source " +
      "(a shipped primitive's introduction record cannot be deleted; a corrected path must " +
      "declare `@originated " + oldMap[tok] + "`)");
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
    // An exported array's length is part of the surface: a shrink removes
    // members (breaking), a growth adds them (additive).
    if (b.kind === "array" && b.length !== c.length) {
      if (c.length < b.length) {
        breaking.push(childPath + ": array length changed (" + b.length + " -> " + c.length + ")");
      } else {
        additive.push(childPath + ": array grew (" + b.length + " -> " + c.length + ")");
      }
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

// Read the committed baseline, distinguishing "absent" from "unreadable":
// only ENOENT bootstraps (returns null). A corrupted or merge-conflicted
// baseline rethrows so the @since / @originated gates never degrade to
// first-run mode and overwrite the record they exist to protect.
function readBaselineIfPresent(p) {
  try {
    return read(p);
  } catch (e) {
    if (e && e.code === "ENOENT") return null;
    throw e;
  }
}

function write(snapshot, p) {
  fs.writeFileSync(p, JSON.stringify(snapshot, null, 2) + "\n");
}

module.exports = {
  capture:      capture,
  compare:      compare,
  formatDiff:   formatDiff,
  extractSince: extractSince,
  extractErrorCodes:   extractErrorCodes,
  extractAssertedCodes: extractAssertedCodes,
  checkErrorCodes:     checkErrorCodes,
  checkSince:   checkSince,
  checkSinceDropped: checkSinceDropped,
  extractOriginated: extractOriginated,
  checkOriginated:   checkOriginated,
  read:         read,
  readBaselineIfPresent: readBaselineIfPresent,
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
  var prior = readBaselineIfPresent(outPath);   // null ONLY when genuinely absent
  var sinceViolations = checkSince(prior && prior.sinceByPrimitive, sinceByPrimitive, pkg.version);
  if (sinceViolations.length > 0) {
    process.stderr.write("[refresh-api-snapshot] @since violations (fix the source @since tags):\n");
    sinceViolations.forEach(function (m) { process.stderr.write("  - " + m + "\n"); });
    process.exit(2);
  }

  // The error-code surface. The residual of codes no test names may only SHRINK:
  // a refresh that absorbed a new one would hand the next release a code whose
  // rename nothing would catch, and `release.js regen` runs this script, so a
  // silent absorb is exactly how the gate would rot.
  var liveCodes = extractErrorCodes(null, Object.keys(pki));
  var assertedCodes = extractAssertedCodes();
  // A baseline that carries no code surface yet has no residual to compare against,
  // so the first refresh RECORDS what is there. Every refresh after it enforces.
  var firstRecord = !(prior && prior.errorCodes);
  if (!firstRecord) {
    var codeVerdict = checkErrorCodes(prior, liveCodes.codes, assertedCodes);
    if (codeVerdict.unasserted.length > 0) {
      process.stderr.write("[refresh-api-snapshot] " + codeVerdict.unasserted.length +
        " error code(s) no test names, and outside the recorded residual:\n");
      codeVerdict.unasserted.forEach(function (c) { process.stderr.write("  - " + c + "\n"); });
      process.stderr.write("[refresh-api-snapshot] add a vector that drives the shipped path and " +
        "asserts the code, so a later rename is caught. The residual in api-snapshot.json " +
        "(errorCodesWithoutVector) records what predates this rule and only shrinks.\n");
      process.exit(2);
    }
  }
  var priorAllowed = firstRecord
    ? liveCodes.codes.filter(function (c) { return !assertedCodes[c]; })
    : (prior.errorCodesWithoutVector || []);
  var stillWithoutVector = priorAllowed.filter(function (c) {
    return !assertedCodes[c] && liveCodes.codes.indexOf(c) !== -1;
  });

  var snapshot = capture(pki, {
    packageVersion: pkg.version,
    sinceByPrimitive: sinceByPrimitive,
    errorCodes: liveCodes.codes,
    errorCodeDomains: liveCodes.domains,
    errorCodeStems: liveCodes.stems,
    errorCodesWithoutVector: stillWithoutVector,
  });
  if (priorAllowed.length !== stillWithoutVector.length) {
    process.stdout.write("[refresh-api-snapshot] residual shrank: " + priorAllowed.length +
      " -> " + stillWithoutVector.length + " error code(s) without a vector\n");
  }

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
