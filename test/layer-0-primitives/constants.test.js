// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.C (constants + scale helpers).
 * Oracle: hand-computed durations / sizes; the config-time throw contract.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

function testTime() {
  check("ms(1500) === 1500", pki.C.TIME.ms(1500) === 1500);
  check("seconds(1) === 1000", pki.C.TIME.seconds(1) === 1000);
  check("minutes(1) === 60000", pki.C.TIME.minutes(1) === 60000);
  check("hours(1) === 3600000", pki.C.TIME.hours(1) === 3600000);
  check("days(1) === 86400000", pki.C.TIME.days(1) === 86400000);
  check("days(365) === 31536000000", pki.C.TIME.days(365) === 31536000000);
  check("weeks(1) === 604800000", pki.C.TIME.weeks(1) === 604800000);
}

function testBytes() {
  check("b(10) === 10", pki.C.BYTES.b(10) === 10);
  check("kib(1) === 1024", pki.C.BYTES.kib(1) === 1024);
  check("mib(1) === 1048576", pki.C.BYTES.mib(1) === 1048576);
  check("mib(16) === 16777216", pki.C.BYTES.mib(16) === 16777216);
  check("gib(1) === 1073741824", pki.C.BYTES.gib(1) === 1073741824);
}

function testThrows() {
  // Config-time tier — a bad scale argument throws ConstantsError.
  check("TIME.days(-1) throws", code(function () { pki.C.TIME.days(-1); }) === "constants/bad-scale");
  check("TIME.days(NaN) throws", code(function () { pki.C.TIME.days(NaN); }) === "constants/bad-scale");
  check("TIME.days(Infinity) throws", code(function () { pki.C.TIME.days(Infinity); }) === "constants/bad-scale");
  check("BYTES.mib('x') throws", code(function () { pki.C.BYTES.mib("x"); }) === "constants/bad-scale");
  check("ConstantsError is a PkiError", (function () {
    try { pki.C.TIME.days(-1); return false; } catch (e) { return e instanceof pki.errors.PkiError; }
  })());
}

function testMeta() {
  check("version is a semver string", /^\d+\.\d+\.\d+/.test(pki.C.version));
  check("version matches pki.version", pki.C.version === pki.version);
  check("LIMITS.DER_MAX_BYTES === 16 MiB", pki.C.LIMITS.DER_MAX_BYTES === 16 * 1024 * 1024);
  check("LIMITS.DER_MAX_DEPTH is a positive int", pki.C.LIMITS.DER_MAX_DEPTH > 0);
}

function run() {
  testTime();
  testBytes();
  testThrows();
  testMeta();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
