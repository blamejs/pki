// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Vendoring tool for the x509-limbo conformance slice.
 *
 * Fetches the upstream `limbo.json` at a pinned commit, drops the testcase
 * namespaces this repository does not commit, and writes the slice plus the
 * numbers the test suite pins against it.
 *
 * Run by hand; its output is committed. It is never on the test path, so no
 * generator runs during a test. `scripts/` is outside the package `files`
 * allowlist, so this never ships.
 *
 *   node scripts/vendor-x509-limbo.js --commit <sha>
 *   node scripts/vendor-x509-limbo.js --commit <sha> --expect-upstream <sha256>
 *   node scripts/vendor-x509-limbo.js --commit <sha> --dry-run
 *
 * Upstream is Apache-2.0. Redistributing a filtered copy engages section 4, so
 * the committed fixture carries the LICENSE text, attribution, and a statement
 * that the file was modified. This tool prints the modification statement it
 * performed so the provenance file can quote it rather than paraphrase it.
 */

var fs    = require("node:fs");
var path  = require("node:path");
var https = require("node:https");
var crypto = require("node:crypto");

var ROOT = path.join(__dirname, "..");
var OUT_DIR = path.join(ROOT, "test", "fixtures", "x509-limbo");
var OUT_FILE = path.join(OUT_DIR, "limbo-slice.json");

// The namespaces that are not committed. bettertls:: is 9,572 cases and tens of
// megabytes, and its importer does not honor upstream's failureIsWarning flag.
// online:: is captured production chains that upstream refreshes on a schedule.
var DROP_PREFIXES = ["bettertls::", "online::"];

function arg(name) {
  var i = process.argv.indexOf("--" + name);
  return i === -1 ? null : process.argv[i + 1];
}
var HAS = function (name) { return process.argv.indexOf("--" + name) !== -1; };

function fetchText(url) {
  return new Promise(function (resolve, reject) {
    https.get(url, { headers: { "user-agent": "blamejs-pki-vendor" } }, function (res) {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        return resolve(fetchText(res.headers.location));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(url + " returned HTTP " + res.statusCode));
      }
      var chunks = [];
      res.on("data", function (c) { chunks.push(c); });
      res.on("end", function () { resolve(Buffer.concat(chunks)); });
    }).on("error", reject);
  });
}

function sha256(buf) { return crypto.createHash("sha256").update(buf).digest("hex"); }

// A case's namespace is everything before the first "::".
function namespaceOf(id) {
  var i = id.indexOf("::");
  return i === -1 ? id : id.slice(0, i);
}

function tally(cases, keyFn) {
  var out = Object.create(null);
  cases.forEach(function (c) { var k = keyFn(c); out[k] = (out[k] || 0) + 1; });
  return out;
}

async function main() {
  var commit = arg("commit");
  if (!commit || !/^[0-9a-f]{40}$/.test(commit)) {
    throw new Error("--commit <40-hex-sha> is required; upstream publishes no tags and no releases, so a commit is the only pin");
  }
  var url = "https://raw.githubusercontent.com/C2SP/x509-limbo/" + commit + "/limbo.json";
  process.stdout.write("[vendor-x509-limbo] fetching " + url + "\n");
  var raw = await fetchText(url);
  var upstreamSha = sha256(raw);
  process.stdout.write("[vendor-x509-limbo] upstream limbo.json: " + raw.length + " bytes, sha256 " + upstreamSha + "\n");

  var expect = arg("expect-upstream");
  if (expect && expect !== upstreamSha) {
    throw new Error("upstream sha256 " + upstreamSha + " does not match --expect-upstream " + expect);
  }

  var doc = JSON.parse(raw.toString("utf8"));
  if (doc.version !== 1) throw new Error("unexpected limbo schema version " + doc.version);
  if (!Array.isArray(doc.testcases)) throw new Error("limbo.json has no testcases array");

  var before = doc.testcases.length;
  var kept = doc.testcases.filter(function (c) {
    return !DROP_PREFIXES.some(function (p) { return String(c.id).indexOf(p) === 0; });
  });

  process.stdout.write("\n[vendor-x509-limbo] namespaces upstream:\n");
  var upstreamTally = tally(doc.testcases, function (c) { return namespaceOf(c.id); });
  Object.keys(upstreamTally).sort().forEach(function (k) {
    process.stdout.write("    " + k + ": " + upstreamTally[k] + "\n");
  });

  process.stdout.write("\n[vendor-x509-limbo] kept " + kept.length + " of " + before + "\n");
  var keptTally = tally(kept, function (c) { return namespaceOf(c.id); });
  Object.keys(keptTally).sort().forEach(function (k) {
    process.stdout.write("    " + k + ": " + keptTally[k] + "\n");
  });

  // Fields the harness asserts are empty across the whole corpus. If upstream
  // starts populating one, the loader must learn it rather than skip it.
  ["signature_algorithms", "key_usage", "extended_key_usage"].forEach(function (f) {
    var nonEmpty = kept.filter(function (c) { return Array.isArray(c[f]) && c[f].length > 0; });
    process.stdout.write("[vendor-x509-limbo] " + f + " non-empty on " + nonEmpty.length + " kept case(s)"
      + (nonEmpty.length ? " -> " + nonEmpty.slice(0, 5).map(function (c) { return c.id; }).join(", ") : "") + "\n");
  });

  // The clock. Cases carrying no validation_time need one corpus-wide instant,
  // and it must sit inside every such case's validity window or the suite rots.
  var noTime = kept.filter(function (c) { return !c.validation_time; });
  process.stdout.write("[vendor-x509-limbo] cases with no validation_time: " + noTime.length + " of " + kept.length + "\n");

  // Every distinct feature tag present, so the loader's allowlist is derived
  // rather than copied from documentation.
  var tags = Object.create(null);
  kept.forEach(function (c) { (c.features || []).forEach(function (t) { tags[t] = (tags[t] || 0) + 1; }); });
  process.stdout.write("[vendor-x509-limbo] feature tags in the slice:\n");
  Object.keys(tags).sort().forEach(function (t) {
    process.stdout.write("    " + t + ": " + tags[t] + "\n");
  });

  // Every distinct expected_result and validation_kind, so an unexpected enum
  // member is seen here rather than at runtime.
  process.stdout.write("[vendor-x509-limbo] expected_result values: "
    + JSON.stringify(tally(kept, function (c) { return c.expected_result; })) + "\n");
  process.stdout.write("[vendor-x509-limbo] validation_kind values: "
    + JSON.stringify(tally(kept, function (c) { return c.validation_kind; })) + "\n");

  var slice = { version: doc.version, testcases: kept };
  // Two-space JSON with a trailing newline, so the committed bytes are stable
  // under any re-run of this tool.
  var out = Buffer.from(JSON.stringify(slice, null, 2) + "\n", "utf8");
  process.stdout.write("\n[vendor-x509-limbo] slice: " + out.length + " bytes, sha256 " + sha256(out) + "\n");

  if (HAS("dry-run")) {
    process.stdout.write("[vendor-x509-limbo] --dry-run, nothing written\n");
    return;
  }
  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(OUT_FILE, out);
  process.stdout.write("[vendor-x509-limbo] wrote " + path.relative(ROOT, OUT_FILE) + "\n");
  process.stdout.write("\n[vendor-x509-limbo] Apache-2.0 section 4(b) modification statement:\n");
  process.stdout.write("    every testcase whose id begins with "
    + DROP_PREFIXES.join(" or ") + " was removed; no testcase was otherwise altered.\n");
}

module.exports = { _namespaceOf: namespaceOf, DROP_PREFIXES: DROP_PREFIXES };

if (require.main === module) {
  main().catch(function (e) {
    process.stderr.write("[vendor-x509-limbo] " + ((e && e.message) || e) + "\n");
    process.exit(1);
  });
}
