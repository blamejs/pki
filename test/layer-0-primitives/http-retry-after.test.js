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

  // the obsolete rfc850-date carries two year digits, and RFC 7231 sec. 7.1.1.1 resolves them against
  // the time the value is received: a year "more than 50 years in the future" names "the most recent
  // year in the past that had the same last two digits". At a receipt in the 2020s, 94 is 2094, which
  // is more than 50 years ahead, so it names 1994; 25 is within the window and names 2025.
  check("an rfc850 year more than 50 years ahead names the most recent past year with those digits", retryAfter.httpDateMs("Sunday, 06-Nov-94 08:49:37 GMT") === Date.UTC(1994, 10, 6, 8, 49, 37));
  check("an rfc850 year inside the window names the coming one", retryAfter.httpDateMs("Sunday, 06-Nov-25 08:49:37 GMT") === Date.UTC(2025, 10, 6, 8, 49, 37));

  // the obsolete asctime-date (no GMT token; parsed as UTC, not local).
  check("an asctime date parses as UTC", retryAfter.httpDateMs("Sun Nov  6 08:49:37 1994") === Date.UTC(1994, 10, 6, 8, 49, 37));

  // an rfc850 two-digit year is interpreted RELATIVE TO the receipt year (HTTP sliding window), not a
  // fixed 70 cutoff: at a 2069 receipt, `70` is 2070 (one year ahead), not 1970.
  check("an rfc850 year uses the receipt-relative sliding window", retryAfter.httpDateMs("Sunday, 06-Nov-70 08:49:37 GMT", Date.UTC(2069, 5, 15)) === Date.UTC(2070, 10, 6, 8, 49, 37));
  // an old two-digit year stays in the PAST (never advanced a century): at a 2090 receipt, `25` is 2025.
  check("an old rfc850 year is kept in the past, not advanced", retryAfter.httpDateMs("Sunday, 06-Nov-25 08:49:37 GMT", Date.UTC(2090, 0, 1)) === Date.UTC(2025, 10, 6, 8, 49, 37));
  // The clause compares the TIMESTAMP, not its year, so the boundary falls inside the fiftieth year
  // ahead: received on 1 January 2026, 1 January 2076 is exactly fifty years ahead and is not more, so
  // it names 2076, while 31 December 2076 is fifty years and a day more and names 1976.
  check("the 50-year horizon is compared as a timestamp, not as a year",
    retryAfter.httpDateMs("Wednesday, 01-Jan-76 00:00:00 GMT", Date.UTC(2026, 0, 1)) === Date.UTC(2076, 0, 1) &&
    retryAfter.httpDateMs("Thursday, 31-Dec-76 00:00:00 GMT", Date.UTC(2026, 0, 1)) === Date.UTC(1976, 11, 31) &&
    retryAfter.httpDateMs("Thursday, 31-Dec-76 00:00:00 GMT", Date.UTC(2027, 0, 1)) === Date.UTC(2076, 11, 31));
  // The clause says MORE than 50 years, so the boundary belongs to the future: at a 2026 receipt 76 is
  // exactly 50 years ahead and names 2076, while 77 is 51 and names 1977.
  var ref2026 = Date.UTC(2026, 0, 1);
  check("the boundary is exclusive: exactly 50 years ahead names the future year",
    retryAfter.httpDateMs("Saturday, 01-Jan-76 00:00:00 GMT", ref2026) === Date.UTC(2076, 0, 1) &&
    retryAfter.httpDateMs("Saturday, 01-Jan-77 00:00:00 GMT", ref2026) === Date.UTC(1977, 0, 1));
  // And it moves with the receipt year, which is what no fixed cutoff can do: one year later, 77 is
  // inside the window, and at a receipt a century on the same digits name a year a century on.
  check("the boundary moves with the receipt year",
    retryAfter.httpDateMs("Saturday, 01-Jan-77 00:00:00 GMT", Date.UTC(2027, 0, 1)) === Date.UTC(2077, 0, 1) &&
    retryAfter.httpDateMs("Saturday, 01-Jan-76 00:00:00 GMT", Date.UTC(2126, 0, 1)) === Date.UTC(2176, 0, 1));
  // A caller may omit the receipt time: `parse`'s `opts.now` is optional and `est.js` passes it through
  // from an optional option of its own. The reading is then the same rule against the current clock,
  // asserted as the same verdict the explicit call gives rather than as a year written here, which
  // would be this test's arithmetic instead of the parser's.
  var nowMs = Date.now();
  check("with no receipt time the same rule is applied against the current clock",
    retryAfter.httpDateMs("Saturday, 01-Jan-76 00:00:00 GMT") ===
      retryAfter.httpDateMs("Saturday, 01-Jan-76 00:00:00 GMT", nowMs) &&
    retryAfter.httpDateMs("Saturday, 01-Jan-70 00:00:00 GMT") ===
      retryAfter.httpDateMs("Saturday, 01-Jan-70 00:00:00 GMT", nowMs));
  // CONTROL: the other two formats carry four year digits, so no receipt time can move them.
  check("CONTROL: a four-digit year is unaffected by the receipt time",
    retryAfter.httpDateMs("Wed, 21 Oct 2026 07:28:00 GMT", Date.UTC(1990, 0, 1)) ===
      retryAfter.httpDateMs("Wed, 21 Oct 2026 07:28:00 GMT") &&
    retryAfter.httpDateMs("Sun Nov  6 08:49:37 1994", Date.UTC(2200, 0, 1)) ===
      retryAfter.httpDateMs("Sun Nov  6 08:49:37 1994"));

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

  // opts.cap clamps a value above the cap to the cap instead of rejecting it (a caller that clamps anyway).
  check("cap clamps a delay above the cap to the cap", retryAfter.parse("100000", { cap: 86400, E: E, code: E_CODE }).retryAfterSeconds === 86400);
  check("cap leaves a delay at/below the cap unchanged", retryAfter.parse("30", { cap: 86400, E: E, code: E_CODE }).retryAfterSeconds === 30);
  check("cap clamps a delay beyond the one-year ceiling rather than rejecting", retryAfter.parse(String(retryAfter.MAX_RETRY_AFTER_SECONDS + 1000), { cap: 86400, E: E, code: E_CODE }).retryAfterSeconds === 86400);
  check("cap clamps a far-future Retry-After date to the cap", retryAfter.parse("Wed, 21 Oct 2099 07:28:00 GMT", { now: Date.UTC(2026, 0, 1), cap: 86400, E: E, code: E_CODE }).retryAfterSeconds === 86400);
  // opts.lenient surfaces an otherwise-rejected value as a null retryAfterSeconds instead of throwing.
  check("lenient surfaces a garbage value as null (no throw)", retryAfter.parse("not-a-delay", { lenient: true, E: E, code: E_CODE }).retryAfterSeconds === null);
  check("lenient surfaces an over-ceiling delay as null when uncapped", retryAfter.parse(String(retryAfter.MAX_RETRY_AFTER_SECONDS + 1), { lenient: true, E: E, code: E_CODE }).retryAfterSeconds === null);
  check("lenient surfaces an over-horizon date as null when uncapped", retryAfter.parse("Wed, 21 Oct 2099 07:28:00 GMT", { now: Date.UTC(2026, 0, 1), lenient: true, E: E, code: E_CODE }).retryAfterSeconds === null);

  console.log("CHECKS " + helpers.getChecks());
}

run();
