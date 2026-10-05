// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var intrinsic = require("./guard-intrinsic");
/** @internal The constructor is captured at load like every operation the toolkit decides with. A
 *  replacement reached here settles the wait itself, so a backoff a caller asked for does not happen.
 *  `setTimeout` is deliberately NOT captured: the delay this splits is observed through the global, and
 *  capturing it would make the split unobservable. */
var _Promise = intrinsic.Promise;

var SETTIMEOUT_MAX_MS = 2147483647;

function sleep(ms) {
  return new _Promise(function (resolve) {
    (function step(remaining) {
      if (remaining <= SETTIMEOUT_MAX_MS) { setTimeout(resolve, remaining); return; }
      setTimeout(function () { step(remaining - SETTIMEOUT_MAX_MS); }, SETTIMEOUT_MAX_MS);
    })(ms);
  });
}

module.exports = { sleep: sleep, SETTIMEOUT_MAX_MS: SETTIMEOUT_MAX_MS };
