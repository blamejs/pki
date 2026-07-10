// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — api-snapshot @since introduction-version contract.
 * Oracle: a primitive's @since is the release that introduced it; it is
 * immutable once shipped and never exceeds the package version. Guards the
 * "new primitive documented with an older @since" class (registerFamily was
 * tagged @since 0.1.1 while it is introduced in 0.1.2).
 */

var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");

var helpers = require("../helpers");
var check   = helpers.check;

var snap = require(path.resolve(__dirname, "../../scripts/refresh-api-snapshot.js"));
var pkg  = require(path.resolve(__dirname, "../../package.json"));
var live = require(path.resolve(__dirname, "../../api-snapshot.json"));

// extractSince() reads the shipped source and pairs every @primitive with its
// @since. The registerFamily fix is the concrete oracle.
function testExtractSinceFromSource() {
  var m = snap.extractSince();
  check("registerFamily @since is the release that introduced it (0.1.2)", m["pki.oid.registerFamily"] === "0.1.2");
  check("a foundation primitive keeps its 0.1.0 @since", m["pki.oid.name"] === "0.1.0");
  check("every extracted @since is valid X.Y.Z", Object.keys(m).every(function (k) { return /^\d+\.\d+\.\d+$/.test(m[k]); }));
}

// A primitive absent from the prior baseline (newly
// added) must carry @since === the introducing version, not an earlier one.
function testNewPrimitiveMustMatchIntroVersion() {
  var base = { "pki.oid.name": "0.1.0" }; // baseline WITHOUT the new primitive
  var bad  = { "pki.oid.name": "0.1.0", "pki.oid.registerFamily": "0.1.1" };
  var good = { "pki.oid.name": "0.1.0", "pki.oid.registerFamily": "0.1.2" };
  var v = snap.checkSince(base, bad, "0.1.2");
  check("a new primitive with an older @since is flagged", v.length === 1 && /registerFamily/.test(v[0]) && /must equal/.test(v[0]));
  check("a new primitive with @since === package version is clean", snap.checkSince(base, good, "0.1.2").length === 0);
}

// @since is immutable once a primitive ships.
function testSinceImmutable() {
  var v = snap.checkSince({ "pki.oid.name": "0.1.0" }, { "pki.oid.name": "0.1.1" }, "0.1.2");
  check("changing a shipped primitive's @since is flagged", v.length === 1 && /immutable/.test(v[0]));
}

// A primitive cannot be introduced in a future version, and a non-semver
// @since is rejected rather than mis-ordered.
function testSinceNotFutureDated() {
  check("@since later than the package version is flagged",
    snap.checkSince(null, { "pki.x.y": "0.2.0" }, "0.1.2").some(function (m) { return /later than/.test(m); }));
  check("a non-semver @since is flagged",
    snap.checkSince(null, { "pki.x.y": "0.1" }, "0.1.2").some(function (m) { return /not a valid/.test(m); }));
}

// Seeding the field for the first time (no prior map) allows the existing
// mixed-version set — only the ≤ bound applies during bootstrap.
function testBootstrapSeedAllowsMixed() {
  check("bootstrap (no prior map) allows the existing mixed-version set",
    snap.checkSince(null, { "pki.a": "0.1.0", "pki.b": "0.1.2" }, "0.1.2").length === 0);
}

// When a documented @primitive PATH is corrected (removed from the since-map while
// the exported SURFACE is unchanged — e.g. pki.asn1.readOid -> pki.asn1.read.oid),
// the origin version MUST be preserved via an @originated tag; otherwise the gate fires.
function testOriginatedRequiredOnPathCorrection() {
  var oldSince = { "pki.asn1.readOid": "0.1.0", "pki.oid.name": "0.1.0" };
  var newSince = { "pki.asn1.read.oid": "0.1.14", "pki.oid.name": "0.1.0" };
  // surface unchanged (the callable still ships) + no @originated -> flagged.
  var missing = snap.checkOriginated(oldSince, newSince, {}, true);
  check("a corrected path with no @originated is flagged", missing.length === 1 && /readOid/.test(missing[0]) && /@originated 0\.1\.0/.test(missing[0]));
  // the replacement declares @originated 0.1.0 -> clean.
  var ok = snap.checkOriginated(oldSince, newSince, { "pki.asn1.read.oid": "0.1.0" }, true);
  check("a corrected path that declares @originated is clean", ok.length === 0);
  // a genuine surface change (a real deletion) is NOT governed by this gate.
  check("a real surface change is not flagged by the @originated gate", snap.checkOriginated(oldSince, newSince, {}, false).length === 0);
  // the live tree already reconciles read.oid -> read.oid, so no removal remains.
  check("read.oid carries @originated 0.1.0 in source", snap.extractOriginated()["pki.asn1.read.oid"] === "0.1.0");
}

// Deleting a documented primitive's @since line must not vacate the
// immutability freeze: a token recorded in the prior map that vanishes from
// the new map is flagged unless its origin version is preserved by an
// @originated declaration (the documented-path-correction flow).
function testDroppedSinceRefused() {
  var oldMap = { "pki.oid.name": "0.1.0", "pki.oid.registerFamily": "0.1.2" };
  var newMap = { "pki.oid.name": "0.1.0" };
  var v = snap.checkSinceDropped(oldMap, newMap, {});
  check("deleting a documented @since is flagged",
    v.length === 1 && /registerFamily/.test(v[0]) && /0\.1\.2/.test(v[0]));
  check("a dropped token whose origin is preserved via @originated is clean",
    snap.checkSinceDropped(oldMap, newMap, { "pki.oid.register": "0.1.2" }).length === 0);
  check("no removals is clean", snap.checkSinceDropped(oldMap, oldMap, {}).length === 0);
  check("bootstrap (no prior map) is clean", snap.checkSinceDropped(null, newMap, {}).length === 0);
  // live tree end to end: nothing recorded in the committed baseline has been
  // dropped from source.
  check("live baseline records no dropped @since tokens",
    snap.checkSinceDropped(live.sinceByPrimitive || {}, snap.extractSince(), snap.extractOriginated()).length === 0);
}

// An exported array's length is part of the surface: a shrink removes members
// (breaking), a growth adds them (additive) — neither may diff clean.
function testArrayLengthCompared() {
  var base   = { surface: { arr: { kind: "array", length: 3 } } };
  var shrunk = { surface: { arr: { kind: "array", length: 2 } } };
  var grown  = { surface: { arr: { kind: "array", length: 4 } } };
  var d1 = snap.compare(base, shrunk);
  check("a shrunk exported array is a breaking change",
    d1.breaking.length === 1 && /length/.test(d1.breaking[0]));
  var d2 = snap.compare(base, grown);
  check("a grown exported array is additive, not breaking",
    d2.breaking.length === 0 && d2.additive.length === 1);
  var d3 = snap.compare(base, base);
  check("an unchanged array diffs clean", d3.breaking.length === 0 && d3.additive.length === 0);
}

// A corrupted or merge-conflicted baseline must never be mistaken for a
// missing one: only ENOENT bootstraps (null); any other read/parse failure
// rethrows so the @since / @originated gates keep their baseline instead of
// degrading to first-run mode and overwriting the record they protect.
function testCorruptBaselineRefused() {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pki-snap-"));
  try {
    check("an absent baseline bootstraps to null",
      snap.readBaselineIfPresent(path.join(tmp, "absent.json")) === null);
    var corrupt = path.join(tmp, "corrupt.json");
    fs.writeFileSync(corrupt, "{ \"surface\": <<<<<<< conflict");
    var threw = false;
    try { snap.readBaselineIfPresent(corrupt); } catch (e) { threw = e instanceof SyntaxError; }
    check("a corrupt baseline rethrows instead of bootstrapping", threw);
    var intact = path.join(tmp, "intact.json");
    fs.writeFileSync(intact, JSON.stringify({ surface: {}, sinceByPrimitive: { "pki.a": "0.1.0" } }));
    var got = snap.readBaselineIfPresent(intact);
    check("an intact baseline reads through", got && got.sinceByPrimitive["pki.a"] === "0.1.0");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// The committed baseline must agree with the shipped source, and the live
// surface must satisfy the contract end to end.
function testLiveSnapshotConsistent() {
  var m = snap.extractSince();
  var stored = live.sinceByPrimitive || {};
  var keysMatch = Object.keys(m).length === Object.keys(stored).length &&
    Object.keys(m).every(function (k) { return stored[k] === m[k]; });
  check("committed api-snapshot sinceByPrimitive matches the source", keysMatch);
  check("live @since set satisfies the contract", snap.checkSince(stored, m, pkg.version).length === 0);
}

function run() {
  testExtractSinceFromSource();
  testNewPrimitiveMustMatchIntroVersion();
  testSinceImmutable();
  testSinceNotFutureDated();
  testBootstrapSeedAllowsMixed();
  testOriginatedRequiredOnPathCorrection();
  testDroppedSinceRefused();
  testArrayLengthCompared();
  testCorruptBaselineRefused();
  testLiveSnapshotConsistent();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
