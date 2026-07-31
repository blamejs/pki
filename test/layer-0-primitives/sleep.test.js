// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- lib/sleep.js, the shared bounded poll sleeper (pki.acme.client / pki.cmp.session). The network
// clients inject a fake sleeper in their tests, so the REAL default -- the only sleeper touching a timer --
// is exercised here directly. The load-bearing behaviour is the delay-chunking: a delay past Node's 32-bit
// setTimeout ceiling (2^31-1 ms) must be SPLIT into chained maximum-size chunks, because a bare
// setTimeout(fn, > 2^31-1) is silently clamped to 1 ms and would then re-poll immediately instead of waiting.
// setTimeout is stubbed (recording each requested delay, firing the callback on a real 0 ms timer) so the
// multi-chunk chain runs in microseconds instead of the ~24.85 real days a single ceiling chunk would take.

var helpers = require("../helpers");
var check = helpers.check;
var sleepUtil = require("../../lib/sleep");

var MAX = sleepUtil.SETTIMEOUT_MAX_MS;

// Run `fn` with a stubbed global.setTimeout that records every requested delay and fires each callback on a
// real 0 ms timer, so a chunked sleep resolves promptly. Returns the recorded delays after `fn` settles.
function withStubbedTimer(fn) {
  var realSetTimeout = global.setTimeout;
  var delays = [];
  global.setTimeout = function (cb, ms) { delays.push(ms); return realSetTimeout(cb, 0); };
  return Promise.resolve().then(fn).then(function () { global.setTimeout = realSetTimeout; return delays; },
    function (e) { global.setTimeout = realSetTimeout; throw e; });
}

async function run() {
  // ===== 1. the ceiling constant is Node's 32-bit setTimeout max =====
  check("1. SETTIMEOUT_MAX_MS is 2^31 - 1 (Node's setTimeout delay ceiling)", MAX === 2147483647);

  // ===== 2. a sub-ceiling delay schedules ONE timer with the exact delay =====
  var d2 = await withStubbedTimer(function () { return sleepUtil.sleep(5); });
  check("2. a delay within the ceiling schedules a single setTimeout(resolve, ms)", d2.length === 1 && d2[0] === 5);

  // ===== 3. a delay one past the ceiling splits into a ceiling chunk + the remainder =====
  var d3 = await withStubbedTimer(function () { return sleepUtil.sleep(MAX + 100); });
  check("3. a delay just past the ceiling chunks into [MAX, remainder] and still resolves", d3.length === 2 && d3[0] === MAX && d3[1] === 100);

  // ===== 4. a multi-ceiling delay chains N full chunks then the remainder =====
  var d4 = await withStubbedTimer(function () { return sleepUtil.sleep(2 * MAX + 7); });
  check("4. a multi-ceiling delay chains full chunks then the remainder", d4.length === 3 && d4[0] === MAX && d4[1] === MAX && d4[2] === 7);

  // ===== 5. a delay exactly at the ceiling is a single (not chunked) timer =====
  var d5 = await withStubbedTimer(function () { return sleepUtil.sleep(MAX); });
  check("5. a delay exactly at the ceiling is a single timer (the <= boundary, not chunked)", d5.length === 1 && d5[0] === MAX);

  console.log("CHECKS " + helpers.getChecks());
}

if (require.main === module) { run().catch(function (e) { console.error(e); process.exit(1); }); }
module.exports = { run: run };
