// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Build a CycloneDX 1.6 SBOM covering lib/vendor/* bundles.
//
// Run via:
//   node scripts/build-vendored-sbom.js > sbom.vendored.cdx.json
//
// The primary SBOM (sbom.cdx.json) describes the npm package's (empty)
// runtime deps; this doc describes the actual code shipping inside the
// tarball.
//
// @blamejs/pki vendors NOTHING today — its cryptography runs entirely on
// Node's built-in node:crypto (see lib/vendor/README.md). With an empty
// MANIFEST `packages: {}`, this emits a VALID CycloneDX document with zero
// components rather than erroring, so the SBOM step is unconditional. A
// vendored package added later appears here automatically.

var fs     = require("node:fs");
var path   = require("node:path");
var crypto = require("node:crypto");

var manifestPath = path.resolve(__dirname, "..", "lib", "vendor", "MANIFEST.json");
var manifest;
try {
  var raw = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  // MANIFEST.json shape: { _comment, packages: { key: entry, ... } }.
  // `packages` may be {} — that's the native-first default, not an error.
  manifest = raw.packages || {};
} catch (e) {
  process.stderr.write("[build-vendored-sbom] failed to read MANIFEST.json: " + e.message + "\n");
  process.exit(1);
}

var rootPkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "package.json"), "utf8"));
var PKG_NAME = rootPkg.name || "@blamejs/pki";

// CycloneDX 1.6 §4.2 requires serialNumber to be a UUID uniquely
// identifying the BOM artifact. Use a fresh UUID per invocation so BOM-diff
// tools treat each rebuild as its own artifact.
var serialNumber = "urn:uuid:" + crypto.randomUUID();

// CycloneDX 1.6 §4.4 (metadata.supplier) + SLSA v1.0 provenance require a
// `supplier` block on every BOM the build pipeline emits.
var TOOLKIT_SUPPLIER = {
  "name": "blamejs",
  "url":  ["https://pkijs.com/"],
};

// metadata.lifecycles[].externalReferences[] point at the GH Actions run
// URL when the build ran in CI. Absent locally the externalRef is omitted.
function _githubActionsRunUrl() {
  var server = process.env.GITHUB_SERVER_URL;   // env-driven script
  var repo   = process.env.GITHUB_REPOSITORY;   // env-driven script
  var runId  = process.env.GITHUB_RUN_ID;       // env-driven script
  if (typeof server === "string" && server.length > 0 &&
      typeof repo === "string" && repo.length > 0 &&
      typeof runId === "string" && runId.length > 0) {
    return server + "/" + repo + "/actions/runs/" + runId;
  }
  return null;
}

// CycloneDX 1.6 §4.6 — license.id MUST be a valid SPDX identifier. Non-SPDX
// prose falls into license.name (the free-text fallback) so consumers
// parsing SBOM-as-SPDX don't reject the whole BOM.
var SPDX_LICENSE_IDS = Object.freeze({
  "0BSD": 1, "Apache-2.0": 1, "BSD-2-Clause": 1, "BSD-3-Clause": 1,
  "CC0-1.0": 1, "CC-BY-3.0": 1, "CC-BY-4.0": 1, "CC-BY-SA-4.0": 1,
  "GPL-2.0-only": 1, "GPL-2.0-or-later": 1, "GPL-3.0-only": 1,
  "GPL-3.0-or-later": 1, "LGPL-2.1-only": 1, "LGPL-2.1-or-later": 1,
  "LGPL-3.0-only": 1, "LGPL-3.0-or-later": 1, "ISC": 1, "MIT": 1,
  "MIT-0": 1, "MPL-2.0": 1, "Unlicense": 1, "WTFPL": 1, "Zlib": 1,
});

function _licenseFor(entry) {
  if (typeof entry.license !== "string" || entry.license.length === 0) return null;
  if (entry.license_is_spdx === false) {
    return [{ license: { name: entry.license } }];
  }
  if (SPDX_LICENSE_IDS[entry.license]) {
    return [{ license: { id: entry.license } }];
  }
  return [{ license: { name: entry.license } }];
}

function _purlFor(entry, key) {
  if (/^(@[a-z0-9-_.]+\/)?[a-z0-9-_.]+$/i.test(key) && entry.source && /npm|github\.com\//.test(entry.source)) {
    if (/^https?:\/\/github\.com\//.test(entry.source)) {
      var m = /^https?:\/\/github\.com\/([^/]+)\/([^/]+)/.exec(entry.source);
      if (m && !/^@/.test(key)) {
        return "pkg:github/" + m[1] + "/" + m[2].replace(/\.git$/, "") + "@" + entry.version;
      }
    }
    return "pkg:npm/" + key.replace(/^@/, "%40").replace("/", "%2F") + "@" + entry.version;
  }
  return "pkg:generic/" + key + "@" + entry.version;
}

function _hashesFor(entry) {
  var rv = [];
  if (entry.sha256) {
    rv.push({ alg: "SHA-256", content: entry.sha256 });
    return rv;
  }
  // MANIFEST.json shape: hashes: { server: "sha256:<hex>", ... }
  if (entry.hashes && typeof entry.hashes === "object") {
    Object.keys(entry.hashes).forEach(function (slot) {
      var v = entry.hashes[slot];
      if (typeof v !== "string") return;
      var m = /^sha256:([a-f0-9]{64})$/i.exec(v);
      if (m) rv.push({ alg: "SHA-256", content: m[1] });
    });
  }
  return rv;
}

// Sub-component dependsOn graph. Entries carrying a `components` map of
// inner sub-bundles emit each as its own SBOM component + register the
// parent's dependsOn so CVE walkers see the inner bundle structure.
var _subDeps = [];   // [{ parentRef, childRef }, ...]

function _buildComponent(key, entry) {
  var c = {
    "type":    "library",
    "bom-ref": key + "@" + entry.version,
    "name":    key,
    "version": entry.version,
    "purl":    _purlFor(entry, key),
    "scope":   "required",
  };
  if (entry.author) {
    c.author = entry.author;
    c.supplier = { "name": entry.author };
  }
  if (entry.description) c.description = entry.description;
  var licenses = _licenseFor(entry);
  if (licenses) c.licenses = licenses;
  if (typeof entry.cpe === "string" && entry.cpe.length > 0) {
    c.cpe = entry.cpe;
  }
  if (entry.source) {
    c.externalReferences = [{ type: "vcs", url: entry.source }];
  }
  var hashes = _hashesFor(entry);
  if (hashes.length > 0) c.hashes = hashes;
  if (entry.bundledAt) {
    c.properties = [{ name: "blamejs:bundledAt", value: entry.bundledAt }];
  }
  return c;
}

var components = [];
Object.keys(manifest).filter(function (key) {
  if (key.charAt(0) === "_") return false;   // skip _comment + metadata
  var entry = manifest[key];
  return entry && typeof entry === "object" && typeof entry.version === "string";
}).forEach(function (key) {
  var entry = manifest[key];
  var parent = _buildComponent(key, entry);
  components.push(parent);

  // Sub-component expansion. `entry.components` is a map keyed by
  // sub-component name; each value is either a bare "<vcs-url>" (legacy;
  // inherits the parent version) or { url, version } (explicit upstream
  // version, preferred for meta-bundles whose parent version is composite).
  if (entry.components && typeof entry.components === "object" && !Array.isArray(entry.components)) {
    var subKeys = Object.keys(entry.components);
    for (var si = 0; si < subKeys.length; si++) {
      var subName  = subKeys[si];
      var subValue = entry.components[subName];
      var subUrl;
      var subVersion;
      if (typeof subValue === "string") {
        subUrl     = subValue;
        subVersion = entry.version;
      } else if (subValue && typeof subValue === "object" && typeof subValue.url === "string") {
        subUrl     = subValue.url;
        subVersion = typeof subValue.version === "string" && subValue.version.length > 0
          ? subValue.version : entry.version;
      } else {
        continue;
      }
      if (subUrl.length === 0) continue;
      var subEntry = {
        version:         subVersion,
        license:         entry.license,
        license_is_spdx: entry.license_is_spdx,
        author:          entry.author,
        source:          subUrl,
        bundledAt:       entry.bundledAt,
      };
      var subKey = key + "/" + subName;
      var sub = _buildComponent(subKey, subEntry);
      components.push(sub);
      _subDeps.push({ parentRef: parent["bom-ref"], childRef: sub["bom-ref"] });
    }
  }
});

var _buildLifecycle = { "phase": "build" };
var _runUrl = _githubActionsRunUrl();
if (_runUrl) {
  _buildLifecycle.externalReferences = [{ type: "build-meta", url: _runUrl }];
}

// Assemble the dependency graph. Top-level entries depend on the vendored
// bundle; sub-components depend on their parent. Top-level refs are derived
// by exclusion: a component is top-level iff its bom-ref never appears as a
// child in _subDeps. With zero components the bundle simply dependsOn [].
var _childRefs = Object.create(null);
for (var di = 0; di < _subDeps.length; di++) _childRefs[_subDeps[di].childRef] = true;
var _topLevelRefs = components
  .map(function (c) { return c["bom-ref"]; })
  .filter(function (ref) { return !_childRefs[ref]; });

var BUNDLE_REF = PKG_NAME + "@" + rootPkg.version + "/vendored-bundle";
var _dependencies = [
  { "ref": BUNDLE_REF, "dependsOn": _topLevelRefs },
];
var _byParent = Object.create(null);
for (var pi = 0; pi < _subDeps.length; pi++) {
  var pd = _subDeps[pi];
  if (!_byParent[pd.parentRef]) _byParent[pd.parentRef] = [];
  _byParent[pd.parentRef].push(pd.childRef);
}
var _parents = Object.keys(_byParent);
for (var pj = 0; pj < _parents.length; pj++) {
  _dependencies.push({ ref: _parents[pj], dependsOn: _byParent[_parents[pj]] });
}

var doc = {
  "$schema":      "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat":    "CycloneDX",
  "specVersion":  "1.6",
  "serialNumber": serialNumber,
  "version":      1,
  "metadata": {
    "timestamp": new Date().toISOString(),
    "lifecycles": [_buildLifecycle],
    "supplier":  TOOLKIT_SUPPLIER,
    "tools": [
      {
        "vendor":  "blamejs",
        "name":    "build-vendored-sbom.js",
        "version": rootPkg.version,
      },
    ],
    "component": {
      "bom-ref":     BUNDLE_REF,
      "type":        "library",
      "name":        "blamejs-pki-vendored-bundle",
      "version":     rootPkg.version,
      "description": "Vendored runtime deps bundled inside " + PKG_NAME +
                     " (CommonJS rollups under lib/vendor/). Empty by default — the toolkit runs on Node's built-in node:crypto.",
      "supplier":    TOOLKIT_SUPPLIER,
    },
  },
  "components":   components,
  "dependencies": _dependencies,
};

process.stdout.write(JSON.stringify(doc, null, 2) + "\n");
