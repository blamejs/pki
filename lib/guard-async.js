// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var _intrinsic = require("./guard-intrinsic");
var _resolve = _intrinsic.uncurry(_intrinsic.promiseResolve);
var _reject = _intrinsic.uncurry(_intrinsic.promiseReject);
var _Promise = Promise;
// @internal
// @enforced-by behavioral -- the rule has no rename-proof code shape (it is the ABSENCE of a wrapper
function deferred(body) {
  try { return _resolve(_Promise, body()); }
  catch (e) { return _reject(_Promise, e); }
}

module.exports = _intrinsic.freeze({ deferred: deferred });
