// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Vendor-currency gate.
 *
 * Reads lib/vendor/MANIFEST.json and asserts that every npm-mapped
 * vendored package matches the latest release on the public npm registry.
 * Intended to fire as a CI gate so a stale vendored bundle (a
 * security-relevant dependency bumped upstream while we sat pinned)
 * becomes a release blocker, not a quietly-aging tarball.
 *
 * Run locally:
 *   node scripts/check-vendor-currency.js
 *   node scripts/check-vendor-currency.js --json     // structured output
 *   node scripts/check-vendor-currency.js --warn     // exit 0, print only
 *
 * Failure policy: any "stale" result fails the gate. registry-error
 * results are advisory unless PKI_VENDOR_CURRENCY_STRICT=1 (which converts
 * them into hard fails too). --warn flips the exit policy to always-0 for
 * advisory-only local runs.
 *
 * Packages with no single upstream npm version to track are declared in
 * SPECIAL_MAP as `{ type: "skip", reason }`; skipped packages do NOT trip
 * the gate by design — the gate is for version drift on packages we COULD
 * have shipped fresh.
 */

var fs    = require("node:fs");
var path  = require("node:path");
var https = require("node:https");

var MANIFEST_PATH = path.join(__dirname, "..", "lib", "vendor", "MANIFEST.json");
var REGISTRY_BASE = "https://registry.npmjs.org/";

var WARN_ONLY  = process.argv.indexOf("--warn") !== -1;
var JSON_OUT   = process.argv.indexOf("--json") !== -1;
var TIMEOUT_MS = 10000;

// Per-package overrides keyed by MANIFEST.json package key. Missing entries
// are treated as "the manifest key IS the npm package name verbatim" — the
// common case for scoped packages like @noble/ciphers.
//
// shape:
//   { type: "npm", name: "<npm-package>" }  — query registry, compare version
//   { type: "skip", reason: "..." }         — skip with a documented reason
var SPECIAL_MAP = {};

function _registryFetch(name) {
  // Direct node:https for portability — the gate runs from scripts/ before
  // any toolkit state exists. node:https with TLS 1.3 is sufficient for a
  // public-registry GET.
  return new Promise(function (resolve, reject) {
    var url = REGISTRY_BASE + encodeURIComponent(name).replace("%40", "@") + "/latest";
    var req = https.get(url, { timeout: TIMEOUT_MS,
      headers: { "User-Agent": "pkijs-vendor-currency/1", "Accept": "application/json" }
    }, function (res) {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error("registry " + name + " status " + res.statusCode));
      }
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () {
        try {
          var doc = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (!doc || typeof doc.version !== "string") {
            return reject(new Error("registry " + name + " returned no .version"));
          }
          resolve(doc.version);
        } catch (e) { reject(e); }
      });
    });
    req.on("timeout", function () { req.destroy(new Error("registry " + name + " timed out after " + TIMEOUT_MS + "ms")); });
    req.on("error", reject);
  });
}

function _semverParse(v) {
  // Strip leading "v" + any pre-release tail. Returns [maj, min, pat] as
  // numbers, or null if not parseable.
  var m = String(v).match(/^v?(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

function _semverCompare(a, b) {
  if (!a || !b) return 0;
  for (var i = 0; i < 3; i++) {
    if (a[i] > b[i]) return  1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

async function _checkOne(key, manifestEntry) {
  var special = SPECIAL_MAP[key];
  if (special && special.type === "skip") {
    return { key: key, status: "skipped", reason: special.reason };
  }
  var npmName = (special && special.type === "npm" && special.name) || key;
  var current = manifestEntry.version;
  try {
    var latest = await _registryFetch(npmName);
    var cmp = _semverCompare(_semverParse(current), _semverParse(latest));
    return {
      key:     key,
      npm:     npmName,
      current: current,
      latest:  latest,
      status:  cmp === 0 ? "current" : (cmp < 0 ? "stale" : "ahead"),
    };
  } catch (e) {
    return {
      key:     key,
      npm:     npmName,
      current: current,
      status:  "registry-error",
      error:   (e && e.message) || String(e),
    };
  }
}

async function main() {
  var raw = fs.readFileSync(MANIFEST_PATH, "utf8");
  var manifest = JSON.parse(raw);
  var pkgs = manifest.packages || {};
  var keys = Object.keys(pkgs);
  var results = [];
  // Sequential — the npm registry is fine with serial polite traffic, and
  // the total package count is small. Parallel would burn sockets for no
  // measurable gain.
  for (var i = 0; i < keys.length; i++) {
    results.push(await _checkOne(keys[i], pkgs[keys[i]]));
  }

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({ results: results }, null, 2) + "\n");
  } else {
    process.stdout.write("[vendor-currency] " + keys.length + " vendored package(s) inspected:\n");
    for (var j = 0; j < results.length; j++) {
      var r = results[j];
      var label = r.status === "current"       ? "OK"
                : r.status === "stale"         ? "STALE"
                : r.status === "ahead"         ? "AHEAD"
                : r.status === "registry-error" ? "ERR"
                : r.status === "skipped"       ? "skip"
                :                                 r.status;
      var line = "  [" + label + "] " + r.key;
      if (r.current && r.latest) line += "  " + r.current + " -> " + r.latest;
      else if (r.current)        line += "  " + r.current;
      if (r.reason) line += "  (" + r.reason + ")";
      if (r.error)  line += "  (registry: " + r.error + ")";
      process.stdout.write(line + "\n");
    }
  }

  var stale   = results.filter(function (r) { return r.status === "stale"; });
  var errored = results.filter(function (r) { return r.status === "registry-error"; });

  if (WARN_ONLY) {
    if (stale.length || errored.length) {
      process.stdout.write("[vendor-currency] --warn: " + stale.length + " stale, " +
        errored.length + " errored — exit 0 anyway\n");
    }
    process.exit(0);
  }

  var strictErrors = process.env.PKI_VENDOR_CURRENCY_STRICT === "1";
  if (stale.length > 0 || (strictErrors && errored.length > 0)) {
    process.stdout.write("[vendor-currency] FAIL — " + stale.length + " stale, " +
      errored.length + " registry-error(s)\n");
    process.exit(1);
  }
  process.stdout.write("[vendor-currency] OK — every checked package matches the latest registry version\n");
  process.exit(0);
}

// Exported for hermetic unit tests (the semver comparison is pure — no
// network — and is the load-bearing ordering logic).
module.exports = {
  _semverParse:   _semverParse,
  _semverCompare: _semverCompare,
  SPECIAL_MAP:    SPECIAL_MAP,
};

if (require.main === module) {
  main().catch(function (e) {
    process.stderr.write("[vendor-currency] script crashed: " + ((e && e.stack) || e) + "\n");
    process.exit(2);
  });
}
