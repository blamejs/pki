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

// The exact Codex finding: a primitive absent from the prior baseline (newly
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
  testLiveSnapshotConsistent();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
