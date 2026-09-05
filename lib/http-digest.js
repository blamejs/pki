// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var crypto = require("crypto");
var constants = require("./constants");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _fromCharCode = intrinsic.fromCharCode;
var pkix = require("./schema-pkix");

var ALGS = intrinsic.assign(intrinsic.create(null), {
  "SHA-512-256": { hash: "sha512-256", rank: 3, sess: false }, "SHA-512-256-SESS": { hash: "sha512-256", rank: 3, sess: true },
  "SHA-256": { hash: "sha256", rank: 2, sess: false }, "SHA-256-SESS": { hash: "sha256", rank: 2, sess: true },
  "MD5": { hash: "md5", rank: 1, sess: false }, "MD5-SESS": { hash: "md5", rank: 1, sess: true },
});
var DEFAULT_CODES = intrinsic.assign(intrinsic.create(null), {
  unsupportedAlgorithm: "digest/unsupported-algorithm", weakAlgorithm: "digest/weak-algorithm",
  noQop: "digest/no-qop", badChallenge: "digest/bad-challenge",
});

function H(hash, s) { return crypto.createHash(hash).update(s, "latin1").digest("hex"); }
function KD(hash, secret, data) { return H(hash, secret + ":" + data); }
function _qstr(v) {
  var s = String(v), out = "";
  for (var i = 0; i < s.length; i++) { var c = _charCodeAt(s, i); if (c === 34 || c === 92) out += "\\"; out += _fromCharCode(c); }
  return "\"" + out + "\"";
}

function _commaSplitOutsideQuotes(s) {
  var out = [], buf = "", inQ = false, esc = false;
  for (var i = 0; i < s.length; i++) {
    var c = s.charAt(i);
    if (esc) { buf += c; esc = false; continue; }
    if (inQ && c === "\\") { buf += c; esc = true; continue; }
    if (c === "\"") { inQ = !inQ; buf += c; continue; }
    if (c === "," && !inQ) { out.push(buf); buf = ""; continue; }
    buf += c;
  }
  out.push(buf);
  return out;
}
function _firstEqOutsideQuotes(s) {
  var inQ = false, esc = false;
  for (var i = 0; i < s.length; i++) {
    var c = s.charAt(i);
    if (esc) { esc = false; continue; }
    if (inQ && c === "\\") { esc = true; continue; }
    if (c === "\"") { inQ = !inQ; continue; }
    if (c === "=" && !inQ) return i;
  }
  return -1;
}
function _unq(s) {
  var out = "", last = 1, n = s.length;
  for (var i = 1; i < n - 1; i++) { if (_charCodeAt(s, i) === 92) { out += _strSlice(s, last, i); last = i + 1; i += 1; } }
  return out + _strSlice(s, last, n - 1);
}
function _closedQuote(s) {
  if (s.length < 2 || s.charAt(0) !== "\"") return false;
  var esc = false;
  for (var i = 1; i < s.length; i++) {
    var c = s.charAt(i);
    if (esc) { esc = false; continue; }
    if (c === "\\") { esc = true; continue; }
    if (c === "\"") return i === s.length - 1;
  }
  return false;
}
function _hasCtl(s) {
  for (var i = 0; i < s.length; i++) { var c = _charCodeAt(s, i); if ((c < 0x20 && c !== 0x09) || c === 0x7f) return true; }
  return false;
}

function _matchTokenRest(pre) {
  var n = pre.length, p = 0;
  while (p < n && !pkix.isJsWhitespace(_charCodeAt(pre, p))) p += 1;
  if (p === 0) return null;
  var tokEnd = p;
  if (p >= n || !pkix.isJsWhitespace(_charCodeAt(pre, p))) return null;
  while (p < n && pkix.isJsWhitespace(_charCodeAt(pre, p))) p += 1;
  if (p >= n || pkix.isJsWhitespace(_charCodeAt(pre, p))) return null;
  return _strSlice(pre, 0, tokEnd);
}
function _stripTokenIndex(seg) {
  var n = seg.length, p = 0;
  while (p < n && pkix.isJsWhitespace(_charCodeAt(seg, p))) p += 1;
  var ts = p;
  while (p < n && !pkix.isJsWhitespace(_charCodeAt(seg, p))) p += 1;
  if (p === ts) return 0;
  var ws = p;
  while (p < n && pkix.isJsWhitespace(_charCodeAt(seg, p))) p += 1;
  return p === ws ? 0 : p;
}
function _splitWhitespace(s) {
  var out = [], i = 0, n = s.length, ps = 0;
  while (i < n) {
    if (pkix.isJsWhitespace(_charCodeAt(s, i))) {
      out[out.length] = _strSlice(s, ps, i);
      while (i < n && pkix.isJsWhitespace(_charCodeAt(s, i))) i += 1;
      ps = i;
    } else i += 1;
  }
  out[out.length] = _strSlice(s, ps);
  return out;
}

function _splitChallenges(s) {
  var segs = _commaSplitOutsideQuotes(s);
  var out = [], cur = null;
  for (var i = 0; i < segs.length; i++) {
    var seg = segs[i].trim();
    if (seg === "") continue;
    var eq = _firstEqOutsideQuotes(seg);
    var pre = (eq < 0 ? seg : _strSlice(seg, 0, eq)).trim();
    var scheme = _matchTokenRest(pre);
    if (eq < 0) { cur = { scheme: seg, paramText: "" }; out.push(cur); }
    else if (scheme !== null) { cur = { scheme: scheme, paramText: _strSlice(seg, _stripTokenIndex(seg)) }; out.push(cur); }
    else if (cur) { cur.paramText = cur.paramText ? cur.paramText + "," + seg : seg; }
  }
  return out;
}
function _parseParams(paramText, E, code) {
  var segs = _commaSplitOutsideQuotes(paramText), map = Object.create(null);
  for (var i = 0; i < segs.length; i++) {
    var seg = segs[i].trim();
    if (seg === "") continue;
    var eq = _firstEqOutsideQuotes(seg);
    if (eq < 0) throw E(code, "malformed Digest auth-param (no '='): " + JSON.stringify(seg));
    var key = _strSlice(seg, 0, eq).trim().toLowerCase();
    var rawVal = _strSlice(seg, eq + 1).trim();
    var quoted = rawVal.charAt(0) === "\"";
    if (quoted && !_closedQuote(rawVal)) throw E(code, "an unterminated or trailing-garbage Digest quoted-string (RFC 7230 sec. 3.2.6)");
    if (_hasOwn(map, key)) throw E(code, "repeated Digest auth-param " + JSON.stringify(key));
    var value = quoted ? _unq(rawVal) : rawVal;
    if (_hasCtl(value)) throw E(code, "a Digest auth-param value contains a control character (RFC 7230 sec. 3.2.6)");
    map[key] = { value: value, quoted: quoted };
  }
  return map;
}
function _validateDigest(paramText, E, code) {
  var p = _parseParams(paramText, E, code);
  if (!p.realm || !p.realm.quoted || p.realm.value === "") throw E(code, "a Digest challenge requires a non-empty quoted realm (RFC 7616 sec. 3.3)");
  if (!p.nonce || !p.nonce.quoted || p.nonce.value === "") throw E(code, "a Digest challenge requires a non-empty quoted nonce (RFC 7616 sec. 3.3)");
  if (p.algorithm && p.algorithm.quoted) throw E(code, "the Digest algorithm must be a token, not a quoted-string (RFC 7616 sec. 3.3)");
  var qop = [];
  if (p.qop) {
    if (!p.qop.quoted) throw E(code, "the Digest qop must be a quoted list (RFC 7616 sec. 3.3)");
    qop = p.qop.value.split(",").map(function (x) { return x.trim().toLowerCase(); }).filter(Boolean);
    if (qop.length === 0) throw E(code, "a present Digest qop directive must list at least one value (RFC 7616 sec. 3.3)");
  }
  if (p.domain && !p.domain.quoted) throw E(code, "the Digest domain must be a quoted-string (RFC 7616 sec. 3.3)");
  var domain = (p.domain && p.domain.value.trim() !== "")
    ? _splitWhitespace(p.domain.value.trim()) : null;
  if (p.charset && (p.charset.quoted || String(p.charset.value).toUpperCase() !== "UTF-8")) throw E(code, "the Digest charset must be the unquoted token UTF-8 (RFC 7616 sec. 3.3)");
  if (p.stale) {
    var sv = String(p.stale.value).toLowerCase();
    if (p.stale.quoted || (sv !== "true" && sv !== "false")) throw E(code, "the Digest stale directive must be the unquoted token true or false (RFC 7616 sec. 3.3)");
  }
  if (p.userhash) {
    var uhv = String(p.userhash.value).toLowerCase();
    if (p.userhash.quoted || (uhv !== "true" && uhv !== "false")) throw E(code, "the Digest userhash directive must be the unquoted token true or false (RFC 7616 sec. 3.3)");
  }
  if (p.opaque && !p.opaque.quoted) throw E(code, "the Digest opaque directive must be a quoted-string (RFC 7616 sec. 3.3)");
  return {
    scheme: "Digest", realm: p.realm.value, nonce: p.nonce.value, qop: qop, domain: domain,
    algorithm: p.algorithm ? p.algorithm.value.toUpperCase() : "MD5",
    opaque: p.opaque ? p.opaque.value : null,
    stale: !!(p.stale && String(p.stale.value).toLowerCase() === "true"),
    userhash: !!(p.userhash && String(p.userhash.value).toLowerCase() === "true"),
    charset: p.charset ? p.charset.value : null,
  };
}

function parseChallenge(www, E, code, policy) {
  var pol = policy || {};
  var codes = pol.codes || DEFAULT_CODES;
  var preferStale = !!pol.preferStale;
  var raw = String(www == null ? "" : www);
  if (raw.length > constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES) throw E(code, "the WWW-Authenticate header exceeds the " + constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES + "-byte cap");
  var challenges = _splitChallenges(raw);
  var best = null, bestUsable = false, bestApplicable = false, bestStale = false, bestRank = -1, sawDigest = false;
  for (var i = 0; i < challenges.length; i++) {
    if (challenges[i].scheme.toLowerCase() !== "digest") continue;
    sawDigest = true;
    var parsed;
    try { parsed = _validateDigest(challenges[i].paramText, E, code); }
    catch (_e) {
      continue;
    }
    var alg = ALGS[parsed.algorithm];
    var rank = alg ? alg.rank : 0;
    var usable = _rejection(parsed, pol, codes) === null;
    var applicable = pol.requestTarget === undefined ? true : inProtectionSpace(parsed, pol.requestOrigin, pol.requestTarget);
    var retryable = preferStale && !!parsed.stale && parsed.nonce !== pol.priorNonce && parsed.realm === pol.priorRealm;
    if (best === null ||
        (usable && !bestUsable) ||
        (usable === bestUsable && applicable && !bestApplicable) ||
        (usable === bestUsable && applicable === bestApplicable && retryable && !bestStale) ||
        (usable === bestUsable && applicable === bestApplicable && retryable === bestStale && rank > bestRank)) {
      best = parsed; bestUsable = usable; bestApplicable = applicable; bestStale = retryable; bestRank = rank;
    }
  }
  if (best) return best;
  if (sawDigest) throw E(code, "no valid Digest challenge: every Digest offer was malformed (missing realm / nonce or a bad directive, RFC 7616 sec. 3.3)");
  return null;
}

function _octets(s, charset) {
  var v = s == null ? "" : String(s);
  return (charset && String(charset).toUpperCase() === "UTF-8") ? Buffer.from(v, "utf8").toString("latin1") : v;
}

function _hasNonAscii(s) {
  s = String(s == null ? "" : s);
  for (var i = 0; i < s.length; i++) { if (_charCodeAt(s, i) > 0x7F) return true; }
  return false;
}

function _pctEncodeUtf8(s) {
  var bytes = Buffer.from(String(s == null ? "" : s), "utf8");
  var out = "";
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    if ((b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) ||
        b === 0x21 || b === 0x23 || b === 0x24 || b === 0x26 || b === 0x2B || b === 0x2D ||
        b === 0x2E || b === 0x5E || b === 0x5F || b === 0x60 || b === 0x7C || b === 0x7E) {
      out += _fromCharCode(b);
    } else {
      out += "%" + (b < 0x10 ? "0" : "") + b.toString(16).toUpperCase();
    }
  }
  return out;
}

function _rejection(challenge, pol, codes) {
  var alg = ALGS[challenge.algorithm];
  if (!alg) return { code: codes.unsupportedAlgorithm, msg: "unsupported Digest algorithm " + challenge.algorithm + " (supported: SHA-512-256, SHA-256, MD5)" };
  if (alg.hash === "md5" && !pol.allowMD5) return { code: codes.weakAlgorithm, msg: "MD5 Digest refused by default (RFC 7616 sec. 3.4 discourages it); set opts.auth.allowMD5 for legacy interop" };
  if (challenge.qop.length === 0) {
    if (!pol.allowLegacyQop) return { code: codes.noQop, msg: "a no-qop (RFC 2069) Digest challenge is refused by default; set opts.auth.allowLegacyQop for legacy interop" };
  } else if (challenge.qop.indexOf("auth") === -1 && challenge.qop.indexOf("auth-int") === -1) {
    return { code: codes.badChallenge, msg: "the Digest qop offered no member this client supports (auth / auth-int)" };
  }
  return null;
}

function answer(challenge, params, E) {
  var pol = params.policy || {};
  var codes = pol.codes || DEFAULT_CODES;
  var rej = _rejection(challenge, pol, codes);
  if (rej) throw E(rej.code, rej.msg);
  var alg = ALGS[challenge.algorithm];
  var useQop = challenge.qop.indexOf("auth") !== -1 ? "auth" : (challenge.qop.indexOf("auth-int") !== -1 ? "auth-int" : null);
  var cnonce = String((params.rng || function () { return crypto.randomBytes(18).toString("base64"); })());
  var realm = challenge.realm, nonce = challenge.nonce;
  var isUtf8 = String(challenge.charset || "").toUpperCase() === "UTF-8";
  var pUser = params.username == null ? "" : String(params.username);
  var pPass = params.password == null ? "" : String(params.password);
  if (isUtf8) { pUser = pUser.normalize("NFC"); pPass = pPass.normalize("NFC"); }
  var user = _octets(pUser, challenge.charset);
  var pass = _octets(pPass, challenge.charset);
  var HA1 = H(alg.hash, user + ":" + realm + ":" + pass);
  if (alg.sess) HA1 = H(alg.hash, HA1 + ":" + nonce + ":" + cnonce);
  var A2 = (useQop === "auth-int")
    ? params.method + ":" + params.uri + ":" + H(alg.hash, params.body == null ? "" : params.body)
    : params.method + ":" + params.uri;
  var HA2 = H(alg.hash, A2);
  var ncNum = (typeof params.nc === "number" && params.nc >= 1) ? Math.floor(params.nc) : 1;
  var nc = _strSlice("0000000" + ncNum.toString(16), -8);
  var response = useQop
    ? KD(alg.hash, HA1, nonce + ":" + nc + ":" + cnonce + ":" + useQop + ":" + HA2)
    : KD(alg.hash, HA1, nonce + ":" + HA2);
  var parts;
  if (!challenge.userhash && isUtf8 && _hasNonAscii(pUser)) {
    parts = ["username*=UTF-8''" + _pctEncodeUtf8(pUser)];
  } else {
    var sentUser = challenge.userhash ? H(alg.hash, _octets(pUser, challenge.charset) + ":" + realm) : _octets(pUser, challenge.charset);
    parts = ["username=" + _qstr(sentUser)];
  }
  parts.push("realm=" + _qstr(realm), "nonce=" + _qstr(nonce), "uri=" + _qstr(params.uri), "algorithm=" + challenge.algorithm);
  if (useQop) { parts.push("qop=" + useQop); parts.push("nc=" + nc); }
  if (useQop || alg.sess) { parts.push("cnonce=" + _qstr(cnonce)); }
  parts.push("response=" + _qstr(response));
  if (challenge.opaque != null) parts.push("opaque=" + _qstr(challenge.opaque));
  if (challenge.userhash) parts.push("userhash=true");
  return "Digest " + parts.join(", ");
}

function _domainEntry(d) {
  d = String(d == null ? "" : d);
  if (d.charAt(0) === "/") return { origin: null, full: d };
  try { var u = new URL(d); return { origin: u.origin.toLowerCase(), full: (u.pathname || "/") + (u.search || "") }; }
  catch (_e) { return null; }
}

function inProtectionSpace(challenge, requestOrigin, requestPathAndSearch) {
  var domain = challenge && challenge.domain;
  if (!domain || !domain.length) return true;
  var origin = String(requestOrigin == null ? "" : requestOrigin).toLowerCase();
  var full = String(requestPathAndSearch == null ? "" : requestPathAndSearch);
  for (var i = 0; i < domain.length; i++) {
    var e = _domainEntry(domain[i]);
    if (e === null) continue;
    if (e.origin !== null && e.origin !== origin) continue;
    if (full.indexOf(e.full) === 0) return true;
  }
  return false;
}

module.exports = { parseChallenge: parseChallenge, answer: answer, inProtectionSpace: inProtectionSpace };
