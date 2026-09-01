// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var SETTIMEOUT_MAX_MS = 2147483647;

function sleep(ms) {
  return new Promise(function (resolve) {
    (function step(remaining) {
      if (remaining <= SETTIMEOUT_MAX_MS) { setTimeout(resolve, remaining); return; }
      setTimeout(function () { step(remaining - SETTIMEOUT_MAX_MS); }, SETTIMEOUT_MAX_MS);
    })(ms);
  });
}

module.exports = { sleep: sleep, SETTIMEOUT_MAX_MS: SETTIMEOUT_MAX_MS };
