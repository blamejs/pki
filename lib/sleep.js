// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the shared bounded poll sleeper for the stateful network clients (pki.acme.client and
// pki.cmp.session). A delay above Node's 32-bit setTimeout ceiling is SPLIT into chained maximum-size
// chunks: a bare setTimeout(fn, > 2^31-1) is silently clamped to 1 ms (a TimeoutOverflowWarning) and would
// then rapidly re-poll instead of waiting the full interval. Each client's opts.sleep overrides this in
// tests, so this default, the one sleeper that touches a real timer, is never driven by a test wait.

var SETTIMEOUT_MAX_MS = 2147483647;   // 2^31 - 1: Node's setTimeout delay ceiling

// sleep(ms) -> Promise resolved after `ms` milliseconds, chunking a delay past the timer ceiling.
function sleep(ms) {
  return new Promise(function (resolve) {
    (function step(remaining) {
      if (remaining <= SETTIMEOUT_MAX_MS) { setTimeout(resolve, remaining); return; }
      setTimeout(function () { step(remaining - SETTIMEOUT_MAX_MS); }, SETTIMEOUT_MAX_MS);
    })(ms);
  });
}

module.exports = { sleep: sleep, SETTIMEOUT_MAX_MS: SETTIMEOUT_MAX_MS };
