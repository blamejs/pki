// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the shared HTTP Retry-After parser (RFC 7231 sec. 7.1.3): a delay-seconds count OR an
// HTTP-date (sec. 7.1.1.1). The enrollment protocol clients (pki.est now, pki.acme next) all surface a
// server's Retry-After as a bounded delay -- never sleeping on it in a single-step call -- so the
// delay-seconds | HTTP-date grammar and the one-year ceiling live in ONE place both compose, error-
// factory-parameterized so each domain keeps its own typed verdict. A malformed / overflowing value
// fails closed (the caller's E(code, ...)); the value is never returned unparsed.

var constants = require("./constants");

// The largest delay this parser surfaces as a number: a generous one-year ceiling that keeps the
// value a safe integer and rejects an overflowing / nonsensical delay-seconds or far-future date.
var MAX_RETRY_AFTER_SECONDS = constants.TIME.days(365) / constants.TIME.seconds(1);

// The three HTTP-date forms (RFC 7231 sec. 7.1.1.1): IMF-fixdate (the required form), and the obsolete
// rfc850-date / asctime-date a recipient must still accept. Gating Date.parse on this grammar keeps its
// permissiveness (an ISO string like "2026-07-10") from passing as a valid Retry-After header.
var MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(" ");
var MONTH = "(?:" + MONTHS.join("|") + ")";
var HTTP_DATE_FORMS = [
  new RegExp("^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \\d{2} " + MONTH + " \\d{4} \\d{2}:\\d{2}:\\d{2} GMT$"),
  new RegExp("^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), \\d{2}-" + MONTH + "-\\d{2} \\d{2}:\\d{2}:\\d{2} GMT$"),
  new RegExp("^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) " + MONTH + " [ \\d]\\d \\d{2}:\\d{2}:\\d{2} \\d{4}$"),
];

// Parse an HTTP-date to epoch ms, or NaN when its grammar, calendar, or time is invalid. Built from the
// extracted fields via Date.UTC (never Date.parse): every HTTP-date is UTC -- the asctime form carries
// no GMT token, so delegating would parse it in LOCAL time -- and the round-trip check rejects an
// impossible date / time (Date.UTC normalizes Feb 31 -> Mar 2 just as Date.parse would).
function httpDateMs(s) {
  if (!HTTP_DATE_FORMS.some(function (re) { return re.test(s); })) return NaN;
  var day, monName, year;
  var asc = /^\w{3} (\w{3}) ([ \d]\d) /.exec(s);                           // asctime: month then day
  if (asc) { monName = asc[1]; day = parseInt(asc[2], 10); year = parseInt(/(\d{4})$/.exec(s)[1], 10); }
  else {
    var dmy = /(\d{2})[ -](\w{3})[ -](\d{2,4})/.exec(s);                   // IMF / rfc850: day month year
    if (!dmy) return NaN;
    day = parseInt(dmy[1], 10); monName = dmy[2]; year = parseInt(dmy[3], 10);
    if (year < 100) year += (year < 70 ? 2000 : 1900);                    // rfc850 two-digit year
  }
  var t = /(\d{2}):(\d{2}):(\d{2})/.exec(s);
  var mon = MONTHS.indexOf(monName);
  if (!t || mon < 0) return NaN;
  var hh = parseInt(t[1], 10), mi = parseInt(t[2], 10), ss = parseInt(t[3], 10);
  var when = Date.UTC(year, mon, day, hh, mi, ss);
  var d = new Date(when);
  if (d.getUTCDate() !== day || d.getUTCMonth() !== mon || d.getUTCFullYear() !== year ||
      d.getUTCHours() !== hh || d.getUTCMinutes() !== mi || d.getUTCSeconds() !== ss) return NaN;
  return when;
}

// parse(value, opts) -> { retryAfterSeconds, retryAfterDate }. A PRESENT Retry-After value (the caller
// gates absence with its own code) is a delay-seconds integer -> retryAfterSeconds, or an HTTP-date ->
// retryAfterDate (epoch ms) plus, when opts.now (epoch ms) is given, a bounded retryAfterSeconds. Either
// form beyond the one-year ceiling, or a value that is neither, fails closed via opts.E(opts.code, ...).
// Never slept on here -- the value is SURFACED for the caller to decide.
function parse(value, opts) {
  opts = opts || {};
  var raStr = String(value).trim();
  var out = { retryAfterSeconds: null, retryAfterDate: null };
  if (/^\d+$/.test(raStr)) {
    var n = parseInt(raStr, 10);
    if (!Number.isSafeInteger(n) || n > MAX_RETRY_AFTER_SECONDS) throw _fail(opts, "the Retry-After delay is out of the supported range (0.." + MAX_RETRY_AFTER_SECONDS + " seconds)");
    out.retryAfterSeconds = n;
    return out;
  }
  var when = httpDateMs(raStr);
  if (isNaN(when)) throw _fail(opts, "a Retry-After must be delay-seconds or a valid HTTP-date (RFC 7231 sec. 7.1.1.1/7.1.3), got " + JSON.stringify(raStr));
  out.retryAfterDate = when;
  if (typeof opts.now === "number" && isFinite(opts.now)) {
    // Round the remaining whole-second delay UP (a sub-second date must not retry before the requested
    // time), clamping a past date to 0.
    var d = Math.max(0, Math.ceil((when - opts.now) / constants.TIME.seconds(1)));
    if (d > MAX_RETRY_AFTER_SECONDS) throw _fail(opts, "the Retry-After date is beyond the supported horizon (" + MAX_RETRY_AFTER_SECONDS + " seconds)");
    out.retryAfterSeconds = d;
  }
  return out;
}

function _fail(opts, message) {
  return typeof opts.E === "function" ? opts.E(opts.code, message) : new TypeError(message);
}

module.exports = { MAX_RETRY_AFTER_SECONDS: MAX_RETRY_AFTER_SECONDS, httpDateMs: httpDateMs, parse: parse };
