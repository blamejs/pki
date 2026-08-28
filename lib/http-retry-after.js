// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- the shared HTTP Retry-After parser (RFC 7231 sec. 7.1.3): a delay-seconds count OR an
// HTTP-date (sec. 7.1.1.1). The enrollment protocol clients (pki.est now, pki.acme next) all surface a
// server's Retry-After as a bounded delay, never sleeping on it in a single-step call, so the
// delay-seconds | HTTP-date grammar and the one-year ceiling live in one place both compose, error-
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
var DOW_SHORT = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
var DOW_LONG = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

// The grammar is scanned character by character (no regex): each form is a fixed layout of a
// day-of-week name, delimiters, an all-digit field, a three-letter month name, and an HH:MM:SS time.
function _isDigit(ch) { return ch >= "0" && ch <= "9"; }
// The two-digit / four-digit integer at `i`, or -1 when those positions are not all digits.
function _digits2(s, i) { return _isDigit(s.charAt(i)) && _isDigit(s.charAt(i + 1)) ? (s.charCodeAt(i) - 48) * 10 + (s.charCodeAt(i + 1) - 48) : -1; }
function _digits4(s, i) { for (var k = 0; k < 4; k++) if (!_isDigit(s.charAt(i + k))) return -1; return parseInt(s.slice(i, i + 4), 10); }
// The length of a name from `list` matching `s` at `i` (the day-of-week alternation), or -1.
function _matchName(s, i, list) { for (var j = 0; j < list.length; j++) { if (s.slice(i, i + list[j].length) === list[j]) return list[j].length; } return -1; }
// The three-letter month at `i` when it is a real month name, else null.
function _monthAt(s, i) { return _matchName(s, i, MONTHS) === -1 ? null : s.slice(i, i + 3); }
// An "HH:MM:SS" time at `i` -> { hh, mi, ss, next } (next = i + 8), or null.
function _timeAt(s, i) {
  var hh = _digits2(s, i); if (hh < 0 || s.charAt(i + 2) !== ":") return null;
  var mi = _digits2(s, i + 3); if (mi < 0 || s.charAt(i + 5) !== ":") return null;
  var ss = _digits2(s, i + 6); if (ss < 0) return null;
  return { hh: hh, mi: mi, ss: ss, next: i + 8 };
}
// A non-empty run of ASCII digits (matching /^\d+$/, the delay-seconds form).
function _isAllDigits(s) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i++) if (!_isDigit(s.charAt(i))) return false;
  return true;
}

// Expand an obsolete RFC 850 two-digit year: HTTP interprets it relative to the receipt year, as the full
// year with these two digits within [refYear-50, refYear+49] (moved to the past only when it would
// otherwise be more than 50 years ahead). A fixed cutoff would misdate a year near the century boundary.
// With no receipt time, fall back to the RFC 6265 fixed rule (< 70 -> 2000s, else 1900s).
function _rfc850Year(yy, refMs) {
  if (typeof refMs !== "number" || !isFinite(refMs)) return yy + (yy < 70 ? 2000 : 1900);
  var refYear = new Date(refMs).getUTCFullYear();
  var full = Math.floor(refYear / 100) * 100 + yy;
  // Move to the previous century only when the same-century year would be more than 50 years ahead; never
  // advance a past year to the future (an old two-digit year stays in the past).
  if (full - refYear > 50) full -= 100;
  return full;
}

// IMF-fixdate (the required form): "Sun, 06 Nov 1994 08:49:37 GMT".
function _scanImf(s) {
  var p = _matchName(s, 0, DOW_SHORT);
  if (p === -1 || s.slice(p, p + 2) !== ", ") return null; p += 2;
  var dd = _digits2(s, p); if (dd < 0 || s.charAt(p + 2) !== " ") return null; p += 3;
  var mo = _monthAt(s, p); if (!mo || s.charAt(p + 3) !== " ") return null; p += 4;
  var yy = _digits4(s, p); if (yy < 0 || s.charAt(p + 4) !== " ") return null; p += 5;
  var t = _timeAt(s, p); if (!t || s.slice(t.next, t.next + 4) !== " GMT" || t.next + 4 !== s.length) return null;
  return { day: dd, monName: mo, year: yy, hh: t.hh, mi: t.mi, ss: t.ss };
}
// rfc850-date (obsolete, still accepted): "Sunday, 06-Nov-94 08:49:37 GMT" -- a two-digit year expanded
// relative to the receipt year.
function _scanRfc850(s, refMs) {
  var p = _matchName(s, 0, DOW_LONG);
  if (p === -1 || s.slice(p, p + 2) !== ", ") return null; p += 2;
  var dd = _digits2(s, p); if (dd < 0 || s.charAt(p + 2) !== "-") return null; p += 3;
  var mo = _monthAt(s, p); if (!mo || s.charAt(p + 3) !== "-") return null; p += 4;
  var yy = _digits2(s, p); if (yy < 0 || s.charAt(p + 2) !== " ") return null; p += 3;
  var t = _timeAt(s, p); if (!t || s.slice(t.next, t.next + 4) !== " GMT" || t.next + 4 !== s.length) return null;
  return { day: dd, monName: mo, year: _rfc850Year(yy, refMs), hh: t.hh, mi: t.mi, ss: t.ss };
}
// asctime-date (obsolete, still accepted): "Sun Nov  6 08:49:37 1994" -- a space-padded one/two-digit day.
function _scanAsctime(s) {
  var p = _matchName(s, 0, DOW_SHORT);
  if (p === -1 || s.charAt(p) !== " ") return null; p += 1;
  var mo = _monthAt(s, p); if (!mo || s.charAt(p + 3) !== " ") return null; p += 4;
  var c0 = s.charAt(p);
  if (!(c0 === " " || _isDigit(c0)) || !_isDigit(s.charAt(p + 1))) return null;
  var dd = parseInt(s.slice(p, p + 2), 10); if (s.charAt(p + 2) !== " ") return null; p += 3;
  var t = _timeAt(s, p); if (!t || s.charAt(t.next) !== " ") return null;
  var yy = _digits4(s, t.next + 1); if (yy < 0 || t.next + 1 + 4 !== s.length) return null;
  return { day: dd, monName: mo, year: yy, hh: t.hh, mi: t.mi, ss: t.ss };
}

// Parse an HTTP-date to epoch ms, or NaN when its grammar, calendar, or time is invalid. Built from the
// extracted fields via Date.UTC (never Date.parse): every HTTP-date is UTC, the asctime form carries
// no GMT token so delegating would parse it in local time, and the round-trip check rejects an
// impossible date / time (Date.UTC normalizes Feb 31 -> Mar 2 just as Date.parse would).
function httpDateMs(s, refMs) {
  var f = _scanImf(s) || _scanRfc850(s, refMs) || _scanAsctime(s);
  if (!f) return NaN;
  var mon = MONTHS.indexOf(f.monName);
  if (mon < 0) return NaN;
  var when = Date.UTC(f.year, mon, f.day, f.hh, f.mi, f.ss);
  var d = new Date(when);
  if (d.getUTCDate() !== f.day || d.getUTCMonth() !== mon || d.getUTCFullYear() !== f.year ||
      d.getUTCHours() !== f.hh || d.getUTCMinutes() !== f.mi || d.getUTCSeconds() !== f.ss) return NaN;
  return when;
}

// parse(value, opts) -> { retryAfterSeconds, retryAfterDate }. A PRESENT Retry-After value (the caller
// gates absence with its own code) is a delay-seconds integer -> retryAfterSeconds, or an HTTP-date ->
// retryAfterDate (epoch ms) plus, when opts.now (epoch ms) is given, a bounded retryAfterSeconds. Either
// form beyond the one-year ceiling, or a value that is neither, fails closed via opts.E(opts.code, ...).
// opts.cap (seconds) clamps a value above the cap to the cap instead of rejecting it; opts.lenient surfaces
// an otherwise-rejected value as a null retryAfterSeconds. Both exist for a caller (e.g. an ARI poll
// cadence) for whom the value is advisory and must not discard the response. Nothing sleeps here; the
// value is surfaced for the caller to decide.
function parse(value, opts) {
  opts = opts || {};
  var raStr = String(value).trim();
  var out = { retryAfterSeconds: null, retryAfterDate: null };
  if (_isAllDigits(raStr)) {
    var n = parseInt(raStr, 10);
    // opts.cap (seconds): a caller that will clamp anyway (e.g. an ARI poll cadence) wants a delay above its
    // ceiling reduced to the ceiling, not rejected, so a valid-but-huge value never discards the response.
    if (typeof opts.cap === "number" && n > opts.cap) { out.retryAfterSeconds = opts.cap; return out; }
    // opts.lenient: a caller for whom the value is purely advisory wants an unparseable one surfaced as
    // null (retryAfterSeconds stays null) instead of a hard reject that would discard the whole response.
    if (!Number.isSafeInteger(n) || n > MAX_RETRY_AFTER_SECONDS) { if (opts.lenient) return out; throw _fail(opts, "the Retry-After delay is out of the supported range (0.." + MAX_RETRY_AFTER_SECONDS + " seconds)"); }
    out.retryAfterSeconds = n;
    return out;
  }
  var when = httpDateMs(raStr, opts.now);
  if (isNaN(when)) { if (opts.lenient) return out; throw _fail(opts, "a Retry-After must be delay-seconds or a valid HTTP-date (RFC 7231 sec. 7.1.1.1/7.1.3), got " + JSON.stringify(raStr)); }
  out.retryAfterDate = when;
  if (typeof opts.now === "number" && isFinite(opts.now)) {
    // Round the remaining whole-second delay UP (a sub-second date must not retry before the requested
    // time), clamping a past date to 0.
    var d = Math.max(0, Math.ceil((when - opts.now) / constants.TIME.seconds(1)));
    if (typeof opts.cap === "number" && d > opts.cap) { out.retryAfterSeconds = opts.cap; return out; }
    if (d > MAX_RETRY_AFTER_SECONDS) { if (opts.lenient) return out; throw _fail(opts, "the Retry-After date is beyond the supported horizon (" + MAX_RETRY_AFTER_SECONDS + " seconds)"); }
    out.retryAfterSeconds = d;
  }
  return out;
}

function _fail(opts, message) {
  return typeof opts.E === "function" ? opts.E(opts.code, message) : new TypeError(message);
}

module.exports = { MAX_RETRY_AFTER_SECONDS: MAX_RETRY_AFTER_SECONDS, httpDateMs: httpDateMs, parse: parse };
