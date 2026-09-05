// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var _intrinsic = require("./guard-intrinsic");
var _resolve = _intrinsic.uncurry(_intrinsic.promiseResolve);
var _reject = _intrinsic.uncurry(_intrinsic.promiseReject);
var _apply = _intrinsic.apply;
var _String = _intrinsic.String;
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
  return _resolve(_Promise, {
    then: function (resolve, reject) { _apply(thenFn, value, [resolve, reject]); },
  });
}

// @internal
// @enforced-by behavioral -- a RED vector drives a bound class constructor through a client verb
/** @internal Call a caller-supplied producer and hand back its promise. A synchronous throw from
 * the call becomes the boundary's typed error, the same as a rejected promise or a non-thenable
 * return already does. Some values pass a callability check and still throw when called: binding a
 * class constructor hides its source, and a proxy can throw from its apply trap. */
function invoked(fn, args, E, code, label) {
  var out;
  try { out = _apply(fn, undefined, args); }
  catch (e) {
    throw E(code, label + " threw when it was called: " + (e && e.message ? e.message : _String(e)), e);
  }
  return awaited(out, E, code, label);
}

module.exports = _intrinsic.freeze({ deferred: deferred, awaited: awaited, invoked: invoked });
