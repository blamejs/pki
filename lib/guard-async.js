// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var _intrinsic = require("./guard-intrinsic");
var _resolve = _intrinsic.uncurry(_intrinsic.promiseResolve);
var _reject = _intrinsic.uncurry(_intrinsic.promiseReject);
var _apply = _intrinsic.apply;
var _Promise = Promise;
// @internal
// @enforced-by behavioral -- the rule has no rename-proof code shape (it is the ABSENCE of a wrapper
function deferred(body) {
  try { return _resolve(_Promise, body()); }
  catch (e) { return _reject(_Promise, e); }
}

// @internal
// @enforced-by behavioral -- a RED vector in each client suite refuses a transport yielding no thenable
function awaited(value, E, code, label) {
  var thenFn;
  try { thenFn = value == null ? null : value.then; }
  catch (_te) { thenFn = null; }
  if (typeof thenFn !== "function") {
    throw E(code, label + " must return a promise of the response; got " +
      (value === null ? "null" : typeof value));
  }
  return new _Promise(function (resolve, reject) {
    _apply(thenFn, value, [resolve, reject]);
  });
}

module.exports = _intrinsic.freeze({ deferred: deferred, awaited: awaited });
