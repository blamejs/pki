// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — release + publish gate scripts.
 * Oracles:
 *   - scripts/check-pack-against-gitignore.js: the last gate between a
 *     gitignored file and the published tarball. A gitignored packed path
 *     fails the publish; a `!`-negation-unignored path and the CI-generated
 *     sbom.cdx.json pass.
 *   - scripts/build-vendored-sbom.js: scoped-npm purls keep the '/'
 *     namespace separator literal (purl npm type), and every hash the SBOM
 *     emits is re-derived from the on-disk vendored bytes — the SBOM never
 *     attests a hash nothing checked.
 *   - scripts/generate-ssdf-attestation.js: the software identity fails
 *     closed without a commit source — an attestation is auditable only
 *     against a specific source revision.
 */

var cp   = require("node:child_process");
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var crypto = require("node:crypto");

var helpers = require("../helpers");
var check   = helpers.check;

var ROOT = path.resolve(__dirname, "..", "..");

// Parse captured stdout as JSON; a parse failure surfaces as a marker object
// (never a throw) so each check can assert on the shape it expected.
function parseJson(s) {
  try { return JSON.parse(s); }
  catch (e) { return { parseError: String((e && e.message) || e) }; }
}

// ---- prepack tarball guard (scripts/check-pack-against-gitignore.js) ----

var GUARD = path.join(ROOT, "scripts", "check-pack-against-gitignore.js");

// A hermetic packable fixture: its own git repo (so `git check-ignore`
// resolves only the fixture's .gitignore), a package.json whose `files`
// list names the paths under test, and the files themselves.
function makePackFixture(files, gitignore) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pki-pack-guard-"));
  cp.spawnSync("git", ["init", "-q"], { cwd: dir, encoding: "utf8" });
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({
    name: "pack-guard-fixture",
    version: "1.0.0",
    license: "Apache-2.0",
    files: files,
  }, null, 2));
  files.forEach(function (f) { fs.writeFileSync(path.join(dir, f), "fixture: " + f + "\n"); });
  if (gitignore !== null) fs.writeFileSync(path.join(dir, ".gitignore"), gitignore);
  return dir;
}

function runGuard(cwd) {
  return cp.spawnSync(process.execPath, [GUARD], { cwd: cwd, encoding: "utf8" });
}

function testPackGuardClean() {
  var dir = makePackFixture(["keep.txt"], null);
  try {
    var rv = runGuard(dir);
    check("no gitignored path: guard passes", rv.status === 0);
    check("no gitignored path: reports none gitignored", /none gitignored/.test(rv.stdout));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testPackGuardRefusesIgnoredPath() {
  var dir = makePackFixture(["keep.txt", "generated.bin"], "generated.bin\n");
  try {
    var rv = runGuard(dir);
    check("a gitignored packed path fails the publish", rv.status === 1);
    check("the refusal names the gitignored path", /generated\.bin/.test(rv.stderr));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testPackGuardAllowsNegationUnignored() {
  // `git check-ignore -v` prints negation matches with exit 0; a path whose
  // LAST matching rule is a `!`-negation is NOT ignored and must ship.
  var dir = makePackFixture(["secret-ok.txt"], "secret*\n!secret-ok.txt\n");
  try {
    var rv = runGuard(dir);
    check("a negation-unignored path passes", rv.status === 0);
    check("the pass names the negation rule", /negation/.test(rv.stdout));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function testPackGuardExemptsGeneratedSbom() {
  // sbom.cdx.json is gitignored on purpose (CI generates it just-in-time
  // before publish) and exempt from the guard.
  var dir = makePackFixture(["keep.txt", "sbom.cdx.json"], "sbom.cdx.json\n");
  try {
    var rv = runGuard(dir);
    check("the CI-generated sbom.cdx.json is exempt", rv.status === 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

// ---- vendored SBOM builder (scripts/build-vendored-sbom.js) -------------

var sbom = require(path.join(ROOT, "scripts", "build-vendored-sbom.js"));

function testScopedPurlKeepsNamespaceSeparator() {
  // purl npm type: the scope is the namespace with '/' as the un-encoded
  // separator (pkg:npm/%40scope/name@v). Percent-encoding the separator
  // collapses namespace+name into one segment and breaks CVE/OSV matching.
  var scoped = sbom.purlFor({ version: "1.2.3", source: "https://registry.npmjs.org/@scope/name" }, "@scope/name");
  check("scoped npm purl keeps the namespace '/' literal", scoped === "pkg:npm/%40scope/name@1.2.3");
  var plain = sbom.purlFor({ version: "1.2.3", source: "npm" }, "name");
  check("unscoped npm purl unchanged", plain === "pkg:npm/name@1.2.3");
  var gh = sbom.purlFor({ version: "2.0.0", source: "https://github.com/owner/repo.git" }, "repo");
  check("github-source purl unchanged", gh === "pkg:github/owner/repo@2.0.0");
}

function testSbomHashesVerifiedAgainstDisk() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pki-sbom-hash-"));
  try {
    var content = Buffer.from("vendored bundle bytes\n");
    fs.writeFileSync(path.join(tmp, "bundle.cjs"), content);
    var hex = crypto.createHash("sha256").update(content).digest("hex");

    // canonical files+hashes shape: matching on-disk bytes pass through.
    var ok = sbom.hashesFor({
      version: "1.0.0",
      files:  { main: "bundle.cjs" },
      hashes: { main: "sha256:" + hex },
    }, tmp);
    check("a matching recorded hash is emitted", ok.length === 1 && ok[0].alg === "SHA-256" && ok[0].content === hex);

    // tampered bytes: the recorded hash no longer matches — fail closed.
    fs.writeFileSync(path.join(tmp, "bundle.cjs"), "tampered\n");
    var mismatch = false;
    try {
      sbom.hashesFor({ version: "1.0.0", files: { main: "bundle.cjs" }, hashes: { main: "sha256:" + hex } }, tmp);
    } catch (e) { mismatch = /mismatch|match/.test(String(e && e.message)); }
    check("a recorded hash that mismatches the on-disk bytes throws", mismatch);

    // a recorded hash with no backing file is unverifiable — fail closed.
    var missing = false;
    try {
      sbom.hashesFor({ version: "1.0.0", files: { main: "gone.cjs" }, hashes: { main: "sha256:" + hex } }, tmp);
    } catch (e) { missing = e instanceof Error; }
    check("a recorded hash whose file is missing throws", missing);

    // bare entry.sha256 must be 64-hex.
    var badHex = false;
    try {
      sbom.hashesFor({ version: "1.0.0", sha256: "nothex" }, tmp);
    } catch (e) { badHex = /64-hex|hex/.test(String(e && e.message)); }
    check("a bare sha256 that is not 64-hex throws", badHex);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function testSbomEmptyManifestStillEmits() {
  // packages: {} is the native-first default — the script emits a valid
  // zero-component CycloneDX document rather than erroring.
  var rv = cp.spawnSync(process.execPath, [path.join(ROOT, "scripts", "build-vendored-sbom.js")],
    { cwd: ROOT, encoding: "utf8" });
  check("empty manifest: builder exits 0", rv.status === 0);
  var doc = parseJson(rv.stdout);
  check("empty manifest: valid CycloneDX doc with zero components",
    doc && doc.bomFormat === "CycloneDX" && Array.isArray(doc.components) && doc.components.length === 0);
}

// ---- SSDF attestation generator (scripts/generate-ssdf-attestation.js) --

function testSsdfAttestationRequiresCommit() {
  var script = path.join(ROOT, "scripts", "generate-ssdf-attestation.js");
  // GITHUB_SHA emptied: in CI the runner injects it, and the fail-closed
  // branch under test is the one with NO commit source at all.
  var bare = cp.spawnSync(process.execPath, [script, "--date", "2026-01-01T00:00:00Z"],
    { cwd: ROOT, encoding: "utf8", env: Object.assign({}, process.env, { GITHUB_SHA: "", SOURCE_DATE_EPOCH: "" }) });
  check("no commit source: generator fails closed", bare.status !== 0 && /commit/.test(bare.stderr));

  var ok = cp.spawnSync(process.execPath, [script, "--date", "2026-01-01T00:00:00Z", "--commit", "abc123"],
    { cwd: ROOT, encoding: "utf8", env: Object.assign({}, process.env, { GITHUB_SHA: "", SOURCE_DATE_EPOCH: "" }) });
  var doc = parseJson(ok.stdout);
  check("--commit: attestation carries the commit",
    ok.status === 0 && doc.software && doc.software.commit === "abc123");

  var env = cp.spawnSync(process.execPath, [script, "--date", "2026-01-01T00:00:00Z"],
    { cwd: ROOT, encoding: "utf8", env: Object.assign({}, process.env, { GITHUB_SHA: "def456", SOURCE_DATE_EPOCH: "" }) });
  var envDoc = parseJson(env.stdout);
  check("GITHUB_SHA: attestation carries the env commit",
    env.status === 0 && envDoc.software && envDoc.software.commit === "def456");
}

function run() {
  testPackGuardClean();
  testPackGuardRefusesIgnoredPath();
  testPackGuardAllowsNegationUnignored();
  testPackGuardExemptsGeneratedSbom();
  testScopedPurlKeepsNamespaceSeparator();
  testSbomHashesVerifiedAgainstDisk();
  testSbomEmptyManifestStillEmits();
  testSsdfAttestationRequiresCommit();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
