// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var constants = require("./constants");

var MAX_RETRY_AFTER_SECONDS = constants.TIME.days(365) / constants.TIME.seconds(1);

var MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(" ");
var DOW_SHORT = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
var DOW_LONG = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

function _isDigit(ch) { return ch >= "0" && ch <= "9"; }
function _digits2(s, i) { return _isDigit(s.charAt(i)) && _isDigit(s.charAt(i + 1)) ? (s.charCodeAt(i) - 48) * 10 + (s.charCodeAt(i + 1) - 48) : -1; }
function _digits4(s, i) { for (var k = 0; k < 4; k++) if (!_isDigit(s.charAt(i + k))) return -1; return parseInt(s.slice(i, i + 4), 10); }
function _matchName(s, i, list) { for (var j = 0; j < list.length; j++) { if (s.slice(i, i + list[j].length) === list[j]) return list[j].length; } return -1; }
function _monthAt(s, i) { return _matchName(s, i, MONTHS) === -1 ? null : s.slice(i, i + 3); }
function _timeAt(s, i) {
  var hh = _digits2(s, i); if (hh < 0 || s.charAt(i + 2) !== ":") return null;
  var mi = _digits2(s, i + 3); if (mi < 0 || s.charAt(i + 5) !== ":") return null;
  var ss = _digits2(s, i + 6); if (ss < 0) return null;
  return { hh: hh, mi: mi, ss: ss, next: i + 8 };
}
function _isAllDigits(s) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i++) if (!_isDigit(s.charAt(i))) return false;
  return true;
}

function _rfc850Year(yy, refMs) {
  if (typeof refMs !== "number" || !isFinite(refMs)) return yy + (yy < 70 ? 2000 : 1900);
  var refYear = new Date(refMs).getUTCFullYear();
  var full = Math.floor(refYear / 100) * 100 + yy;
  if (full - refYear > 50) full -= 100;
  return full;
}

function _scanImf(s) {
  var p = _matchName(s, 0, DOW_SHORT);
  if (p === -1 || s.slice(p, p + 2) !== ", ") return null; p += 2;
  var dd = _digits2(s, p); if (dd < 0 || s.charAt(p + 2) !== " ") return null; p += 3;
  var mo = _monthAt(s, p); if (!mo || s.charAt(p + 3) !== " ") return null; p += 4;
  var yy = _digits4(s, p); if (yy < 0 || s.charAt(p + 4) !== " ") return null; p += 5;
  var t = _timeAt(s, p); if (!t || s.slice(t.next, t.next + 4) !== " GMT" || t.next + 4 !== s.length) return null;
  return { day: dd, monName: mo, year: yy, hh: t.hh, mi: t.mi, ss: t.ss };
}
function _scanRfc850(s, refMs) {
  var p = _matchName(s, 0, DOW_LONG);
  if (p === -1 || s.slice(p, p + 2) !== ", ") return null; p += 2;
  var dd = _digits2(s, p); if (dd < 0 || s.charAt(p + 2) !== "-") return null; p += 3;
  var mo = _monthAt(s, p); if (!mo || s.charAt(p + 3) !== "-") return null; p += 4;
  var yy = _digits2(s, p); if (yy < 0 || s.charAt(p + 2) !== " ") return null; p += 3;
  var t = _timeAt(s, p); if (!t || s.slice(t.next, t.next + 4) !== " GMT" || t.next + 4 !== s.length) return null;
  return { day: dd, monName: mo, year: _rfc850Year(yy, refMs), hh: t.hh, mi: t.mi, ss: t.ss };
}
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

function parse(value, opts) {
  opts = opts || {};
  var raStr = String(value).trim();
  var out = { retryAfterSeconds: null, retryAfterDate: null };
  if (_isAllDigits(raStr)) {
    var n = parseInt(raStr, 10);
    if (typeof opts.cap === "number" && n > opts.cap) { out.retryAfterSeconds = opts.cap; return out; }
    if (!Number.isSafeInteger(n) || n > MAX_RETRY_AFTER_SECONDS) { if (opts.lenient) return out; throw _fail(opts, "the Retry-After delay is out of the supported range (0.." + MAX_RETRY_AFTER_SECONDS + " seconds)"); }
    out.retryAfterSeconds = n;
    return out;
  }
  var when = httpDateMs(raStr, opts.now);
  if (isNaN(when)) { if (opts.lenient) return out; throw _fail(opts, "a Retry-After must be delay-seconds or a valid HTTP-date (RFC 7231 sec. 7.1.1.1/7.1.3), got " + JSON.stringify(raStr)); }
  out.retryAfterDate = when;
  if (typeof opts.now === "number" && isFinite(opts.now)) {
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
