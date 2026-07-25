// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- the shared HTTP Retry-After parser (lib/http-retry-after.js, RFC 7231 sec. 7.1.3). An
// @internal primitive the enrollment clients (pki.est, pki.acme) compose, so its contract is pinned
// here directly (the guard-*.test.js pattern): the delay-seconds | HTTP-date grammar, the one-year
// ceiling, and the error-factory parameterization (opts.E) that lets each caller keep its own typed
// verdict while a missing factory falls back to a TypeError.

var helpers = require("../helpers");
var check = helpers.check;
var retryAfter = require("../../lib/http-retry-after");

var E_CODE = "x/bad-retry-after";
function E(code, msg) { var e = new Error(msg); e.code = code; return e; }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || ("RAW:" + e.constructor.name); } }

function run() {
  // delay-seconds, and the no-opts default path (opts || {}).
  check("a delay-seconds value parses with no opts at all", retryAfter.parse("30").retryAfterSeconds === 30);
  check("a delay-seconds value surfaces retryAfterSeconds, no date", retryAfter.parse("0", { E: E, code: E_CODE }).retryAfterSeconds === 0);

  // an IMF-fixdate (the required form) -> an absolute date, plus a bounded delay when `now` is given.
  var imf = retryAfter.parse("Wed, 21 Oct 2026 07:28:00 GMT", { now: Date.UTC(2026, 9, 21, 7, 27, 0), E: E, code: E_CODE });
  check("an IMF-fixdate surfaces retryAfterDate", imf.retryAfterDate === Date.UTC(2026, 9, 21, 7, 28, 0));
  check("an IMF-fixdate with now surfaces a bounded retryAfterSeconds", imf.retryAfterSeconds === 60);

  // the obsolete rfc850-date (two-digit year): both century arms (< 70 -> 2000s, >= 70 -> 1900s).
  check("an rfc850 date with a >=70 two-digit year maps to the 1900s", retryAfter.httpDateMs("Sunday, 06-Nov-94 08:49:37 GMT") === Date.UTC(1994, 10, 6, 8, 49, 37));
  check("an rfc850 date with a <70 two-digit year maps to the 2000s", retryAfter.httpDateMs("Sunday, 06-Nov-25 08:49:37 GMT") === Date.UTC(2025, 10, 6, 8, 49, 37));

  // the obsolete asctime-date (no GMT token; parsed as UTC, not local).
  check("an asctime date parses as UTC", retryAfter.httpDateMs("Sun Nov  6 08:49:37 1994") === Date.UTC(1994, 10, 6, 8, 49, 37));

  // an rfc850 two-digit year is interpreted RELATIVE TO the receipt year (HTTP sliding window), not a
  // fixed 70 cutoff: at a 2069 receipt, `70` is 2070 (one year ahead), not 1970.
  check("an rfc850 year uses the receipt-relative sliding window", retryAfter.httpDateMs("Sunday, 06-Nov-70 08:49:37 GMT", Date.UTC(2069, 5, 15)) === Date.UTC(2070, 10, 6, 8, 49, 37));

  // a malformed value fails closed: with a factory it is the caller's typed code; with none it is a
  // TypeError (the fallback that keeps the parser usable outside a PkiError domain).
  check("a malformed value with a factory throws the caller's code", codeOf(function () { return retryAfter.parse("not-a-delay", { E: E, code: E_CODE }); }) === E_CODE);
  check("a malformed value with NO factory throws a TypeError", codeOf(function () { return retryAfter.parse("not-a-delay"); }) === "RAW:TypeError");

  // the one-year ceiling: an overflowing delay-seconds and a far-future date both fail closed.
  check("a delay-seconds beyond the one-year ceiling fails closed", codeOf(function () { return retryAfter.parse(String(retryAfter.MAX_RETRY_AFTER_SECONDS + 1), { E: E, code: E_CODE }); }) === E_CODE);
  check("a Retry-After date beyond the horizon fails closed", codeOf(function () {
    return retryAfter.parse("Wed, 21 Oct 2099 07:28:00 GMT", { now: Date.UTC(2026, 0, 1), E: E, code: E_CODE });
  }) === E_CODE);

  // a sub-second-ahead HTTP-date rounds the delay UP to the next whole second (never 0, which would retry
  // before the server's requested time); a past date clamps to 0.
  var base = Date.UTC(2026, 9, 21, 7, 28, 0);
  check("a sub-second-ahead date rounds up to 1s (not 0)", retryAfter.parse("Wed, 21 Oct 2026 07:28:00 GMT", { now: base - 300, E: E, code: E_CODE }).retryAfterSeconds === 1);
  check("a past Retry-After date clamps the delay to 0", retryAfter.parse("Wed, 21 Oct 2026 07:28:00 GMT", { now: base + 5000, E: E, code: E_CODE }).retryAfterSeconds === 0);

  // an HTTP-date with an impossible calendar day is rejected (round-trip check), returning NaN.
  check("an impossible calendar date returns NaN", isNaN(retryAfter.httpDateMs("Wed, 31 Feb 2026 00:00:00 GMT")));

  console.log("CHECKS " + helpers.getChecks());
}

run();
