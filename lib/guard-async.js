// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var _intrinsic = require("./guard-intrinsic");
var _resolve = _intrinsic.uncurry(_intrinsic.promiseResolve);
var _reject = _intrinsic.uncurry(_intrinsic.promiseReject);
var _apply = _intrinsic.apply;
var _String = _intrinsic.String;
var _Promise = Promise;
/** @internal Bound at load, like every other operation this module decides with: a replacement
 * installed later would otherwise choose when a bound expires, or whether it ever does. */
var _setTimeout = setTimeout;
var _clearTimeout = clearTimeout;
/** @internal The losing side of a race is observed, not acted on: attaching this is what keeps an
 * outcome nobody wants from becoming an unhandled rejection. */
function _ignore() { return undefined; }
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
    /** @internal The thrown value is the caller's, so describing it is a read of caller data: a
     * `message` accessor that throws would leave this boundary by the one path it exists to close.
     * @guard-via guard.text.describeThrown */
    // allow:inline-require guard-text reaches guard-bytes, which reaches this module, so binding it at load leaves guard-bytes half-built for whichever of the two is required first; this line runs only after a producer has already thrown
    throw E(code, label + " threw when it was called: " +
      require("./guard-text").describeThrown(e), e);
  }
  return awaited(out, E, code, label);
}

// @internal
// @enforced-by behavioral -- a RED vector drives a never-settling caller operation through a client
/** @internal Await a caller-supplied operation under a bound this side controls. A request field
 * naming a timeout is a request: an operation that does not implement it never settles, and the
 * verb awaiting it never returns. The timer holds the event loop until it fires or is cleared,
 * which is what keeps a process from exiting while a bound is still in flight and abandoning the
 * await in silence. It is cleared on either outcome, so it holds the loop for at most `ms`. The
 * losing side of the race is not cancelled, because a promise cannot be; the caller stops waiting.
 *
 * `ms` at or below zero is already past and refuses without awaiting anything. */
function bounded(value, ms, E, code, label) {
  var settled = false;
  return new _Promise(function (resolve, reject) {
    if (!(ms > 0)) {
      /** @internal The operation may already be running: a deadline can expire between the check
       * that started it and the bound computed for it. Refusing without observing its promise
       * leaves a rejection nobody handled, which ends the process on the default
       * `unhandledRejection` behavior, and the caller catching this refusal does not help. */
      _resolve(_Promise, value).then(_ignore, _ignore);
      reject(E(code, label + " had no time left to run in"));
      return;
    }
    var timer = _setTimeout(function () {
      if (settled) return;
      settled = true;
      reject(E(code, label + " did not settle within " + ms + "ms"));
    }, ms);
    function done(fn) {
      return function (x) {
        if (settled) return;
        settled = true;
        _clearTimeout(timer);
        fn(x);
      };
    }
    _resolve(_Promise, value).then(done(resolve), done(reject));
  });
}

module.exports = _intrinsic.freeze({ deferred: deferred, awaited: awaited, invoked: invoked, bounded: bounded });
