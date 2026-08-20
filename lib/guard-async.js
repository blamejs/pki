// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// The two settle operations, taken at load and uncurried so the call sites read no property of
// them. These are how a synchronous fault becomes the rejection this guard promises, so a replaced
// `reject` returning a resolved promise turns a refusal into a pass at the one place the exit shape
// is decided. See guard-intrinsic for the whole captured set.
var _intrinsic = require("./guard-intrinsic");
var _resolve = _intrinsic.uncurry(_intrinsic.promiseResolve);
var _reject = _intrinsic.uncurry(_intrinsic.promiseReject);
var _Promise = Promise;
//
// @internal -- no operator-facing namespace. The documented surface is every verb whose
// @signature says `-> Promise<...>`; this is how each of them refuses.
//
// guard-async -- a verb documented as Promise-returning refuses by REJECTING, never by throwing.
//
// The failure is invisible at the call site, which is what makes it worth a choke point. An operator
// reads `-> Promise<...>` in the reference and writes the documented shape:
//
//     pki.acme.newOrder(opts).catch(handleIt);
//
// A validation that runs before the promise is created throws straight past that `.catch`, so a
// misspelled option or a malformed input becomes an uncaught exception in code that already handles
// errors -- and nothing in the shape of the call tells the caller which verbs do that. Eleven verbs
// across five modules had it (pki.cms.verify / sign / countersign, pki.ocsp.sign, pki.tsp.sign and
// six pki.acme verbs), each having grown the same way: a cheap synchronous check added at the top of
// a function that returns a promise further down.
//
// What this does not change is when the work happens. The body still runs synchronously, because
// several of these verbs must resolve a caller's mutable options object before any turn passes --
// reading a key, a nonce, or a request's bytes a turn later is a different value than the one that
// was checked. Only the exit changes: a fault leaves as a rejection instead of a throw.
//
// @enforced-by behavioral -- the rule has no rename-proof code shape (it is the ABSENCE of a wrapper
//   around a synchronous prefix, which no lexical pattern can see). The guard is the derived test
//   test/layer-0-primitives/promise-contract.test.js, which reads every `-> Promise<` @signature out
//   of lib/ and calls each verb to prove the refusal arrives as a rejection. A new verb is in
//   scope the day it is documented, so no list here can go stale.
// Both taken at load. These are how a synchronous fault becomes the rejection this guard promises,
// so a replaced `reject` returning a resolved promise turns a refusal into a pass at the one place
// the exit shape is decided. See guard-intrinsic for the whole captured set.
function deferred(body) {
  try { return _resolve(_Promise, body()); }
  catch (e) { return _reject(_Promise, e); }
}

module.exports = { deferred: deferred };
