// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var crypto = require("crypto");
var constants = require("./constants");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
/** @internal The URL parser, taken at load: the origin it reports is what a challenge is bound to.
 *  Its accessors are taken with it, since the constructor's capture does not cover the prototype the
 *  value reads its parts off and this origin is what a credential is scoped by. */
var _URL = intrinsic.URL;
var _urlOrigin = intrinsic.urlOrigin;
var _urlPathname = intrinsic.urlPathname;
var _urlSearch = intrinsic.urlSearch;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
/** @internal The operations the challenge is parsed and classified through. This module decides which
 * algorithm and which qop a credential is built for, and whether a weak algorithm is refused at all,
 * so every one of them is a decision: measured, a replaced global `String` rewriting an `MD5`
 * challenge as `SHA-256` turned `transport/proxy-digest-weak-algorithm` into an accepted credential. */
var _strTrim = intrinsic.uncurry(String.prototype.trim);
var _strSplit = intrinsic.uncurry(String.prototype.split);
/** @internal The LEXER's character reads, captured because the lexer copies the challenge one
 * character at a time and a replacement therefore chooses the token the parse assembles. Measured,
 * rewriting `algorithm=MD5` to `algorithm=SHA-256` as the split copies it does NOT reach an accepted
 * credential: the policy still refuses, as `proxy-digest-unsupported-algorithm` rather than
 * `proxy-digest-weak-algorithm`. What is steerable is the REASON, so the capture is what keeps a
 * refusal naming the fault it actually found. A parser is captured at its characters or not at all. */
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var _strNormalize = intrinsic.uncurry(String.prototype.normalize);
var _arrIndexOf = intrinsic.uncurry(Array.prototype.indexOf);
var _arrJoin = intrinsic.uncurry(Array.prototype.join);
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

/** @internal The hash the credential is computed with, taken at load along with the methods of the
 * object it returns. Every Digest response value is this function's output, so a replacement chooses
 * what is sent in place of the password-derived proof. */
var _createHash = crypto.createHash;
var _randomBytes = crypto.randomBytes;
var _hashUpdate = intrinsic.uncurry(crypto.createHash("sha256").update);
var _hashDigest = intrinsic.uncurry(crypto.createHash("sha256").digest);
function H(hash, s) { return _hashDigest(_hashUpdate(_createHash(hash), s, "latin1"), "hex"); }
function KD(hash, secret, data) { return H(hash, secret + ":" + data); }
function _qstr(v) {
  var s = intrinsic.String(v), out = "";
  for (var i = 0; i < s.length; i++) { var c = _charCodeAt(s, i); if (c === 34 || c === 92) out += "\\"; out += _fromCharCode(c); }
  return "\"" + out + "\"";
}

function _commaSplitOutsideQuotes(s) {
  var out = [], buf = "", inQ = false, esc = false;
  for (var i = 0; i < s.length; i++) {
    var c = _charAt(s, i);
    if (esc) { buf += c; esc = false; continue; }
    if (inQ && c === "\\") { buf += c; esc = true; continue; }
    if (c === "\"") { inQ = !inQ; buf += c; continue; }
    if (c === "," && !inQ) { intrinsic.push(out, buf); buf = ""; continue; }
    buf += c;
  }
  intrinsic.push(out, buf);
  return out;
}
function _firstEqOutsideQuotes(s) {
  var inQ = false, esc = false;
  for (var i = 0; i < s.length; i++) {
    var c = _charAt(s, i);
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
  if (s.length < 2 || _charAt(s, 0) !== "\"") return false;
  var esc = false;
  for (var i = 1; i < s.length; i++) {
    var c = _charAt(s, i);
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
    /** @internal The OUTER trim is captured as well as the inner ones. It controls the complete
     * auth-param before anything slices it, so a replacement mapping the segment `algorithm=MD5` to
     * `algorithm=SHA-256` classifies a weak challenge as a strong one and the refusal never fires:
     * capturing only the key and value slices left the whole parameter steerable. */
    var seg = _strTrim(segs[i]);
    if (seg === "") continue;
    var eq = _firstEqOutsideQuotes(seg);
    var pre = _strTrim(eq < 0 ? seg : _strSlice(seg, 0, eq));
    var scheme = _matchTokenRest(pre);
    if (eq < 0) { cur = { scheme: seg, paramText: "" }; intrinsic.push(out, cur); }
    else if (scheme !== null) { cur = { scheme: scheme, paramText: _strSlice(seg, _stripTokenIndex(seg)) }; intrinsic.push(out, cur); }
    else if (cur) { cur.paramText = cur.paramText ? cur.paramText + "," + seg : seg; }
  }
  return out;
}
function _parseParams(paramText, E, code) {
  var segs = _commaSplitOutsideQuotes(paramText), map = Object.create(null);
  for (var i = 0; i < segs.length; i++) {
    var seg = _strTrim(segs[i]);
    if (seg === "") continue;
    var eq = _firstEqOutsideQuotes(seg);
    if (eq < 0) throw E(code, "malformed Digest auth-param (no '='): " + JSON.stringify(seg));
    var key = intrinsic.toLowerCase(_strTrim(_strSlice(seg, 0, eq)));
    var rawVal = _strTrim(_strSlice(seg, eq + 1));
    var quoted = _charCodeAt(rawVal, 0) === 34;
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
    qop = intrinsic.filter(intrinsic.map(_strSplit(p.qop.value, ","), function (x) {
      return intrinsic.toLowerCase(_strTrim(x));
    }), Boolean);
    if (qop.length === 0) throw E(code, "a present Digest qop directive must list at least one value (RFC 7616 sec. 3.3)");
  }
  if (p.domain && !p.domain.quoted) throw E(code, "the Digest domain must be a quoted-string (RFC 7616 sec. 3.3)");
  var domain = (p.domain && _strTrim(p.domain.value) !== "")
    ? _splitWhitespace(_strTrim(p.domain.value)) : null;
  if (p.charset && (p.charset.quoted || intrinsic.toUpperCase(intrinsic.String(p.charset.value)) !== "UTF-8")) throw E(code, "the Digest charset must be the unquoted token UTF-8 (RFC 7616 sec. 3.3)");
  if (p.stale) {
    var sv = intrinsic.toLowerCase(intrinsic.String(p.stale.value));
    if (p.stale.quoted || (sv !== "true" && sv !== "false")) throw E(code, "the Digest stale directive must be the unquoted token true or false (RFC 7616 sec. 3.3)");
  }
  if (p.userhash) {
    var uhv = intrinsic.toLowerCase(intrinsic.String(p.userhash.value));
    if (p.userhash.quoted || (uhv !== "true" && uhv !== "false")) throw E(code, "the Digest userhash directive must be the unquoted token true or false (RFC 7616 sec. 3.3)");
  }
  if (p.opaque && !p.opaque.quoted) throw E(code, "the Digest opaque directive must be a quoted-string (RFC 7616 sec. 3.3)");
  return {
    scheme: "Digest", realm: p.realm.value, nonce: p.nonce.value, qop: qop, domain: domain,
    algorithm: p.algorithm ? intrinsic.toUpperCase(p.algorithm.value) : "MD5",
    opaque: p.opaque ? p.opaque.value : null,
    stale: !!(p.stale && intrinsic.toLowerCase(intrinsic.String(p.stale.value)) === "true"),
    userhash: !!(p.userhash && intrinsic.toLowerCase(intrinsic.String(p.userhash.value)) === "true"),
    charset: p.charset ? p.charset.value : null,
  };
}

function parseChallenge(www, E, code, policy) {
  var pol = policy || {};
  var codes = pol.codes || DEFAULT_CODES;
  var preferStale = !!pol.preferStale;
  var raw = intrinsic.String(www == null ? "" : www);
  if (raw.length > constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES) throw E(code, "the WWW-Authenticate header exceeds the " + constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES + "-byte cap");
  var challenges = _splitChallenges(raw);
  var best = null, bestUsable = false, bestApplicable = false, bestStale = false, bestRank = -1, sawDigest = false;
  for (var i = 0; i < challenges.length; i++) {
    if (intrinsic.toLowerCase(challenges[i].scheme) !== "digest") continue;
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

/** @internal The bytes a credential is computed over, so the conversion and the encoding both come
 * from the captures: what this returns is hashed, and a replacement changes the input to the proof. */
function _octets(s, charset) {
  var v = s == null ? "" : intrinsic.String(s);
  return (charset && intrinsic.toUpperCase(intrinsic.String(charset)) === "UTF-8")
    ? intrinsic.bufToString(intrinsic.bufferFrom(v, "utf8"), "latin1") : v;
}

function _hasNonAscii(s) {
  s = intrinsic.String(s == null ? "" : s);
  for (var i = 0; i < s.length; i++) { if (_charCodeAt(s, i) > 0x7F) return true; }
  return false;
}

function _pctEncodeUtf8(s) {
  var bytes = intrinsic.bufferFrom(intrinsic.String(s == null ? "" : s), "utf8");
  var out = "";
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    if ((b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) ||
        b === 0x21 || b === 0x23 || b === 0x24 || b === 0x26 || b === 0x2B || b === 0x2D ||
        b === 0x2E || b === 0x5E || b === 0x5F || b === 0x60 || b === 0x7C || b === 0x7E) {
      out += _fromCharCode(b);
    } else {
      out += "%" + (b < 0x10 ? "0" : "") + intrinsic.toUpperCase(intrinsic.numberToString(b, 16));
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
    /** @internal The qop membership tests come from the capture. This arm REFUSES a challenge whose
     * qop offers nothing this client supports, and the one below SELECTS which qop the credential is
     * computed for, so a replaced `indexOf` either skips the refusal or changes the computation. */
  } else if (_arrIndexOf(challenge.qop, "auth") === -1 && _arrIndexOf(challenge.qop, "auth-int") === -1) {
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
  var useQop = _arrIndexOf(challenge.qop, "auth") !== -1 ? "auth"
    : (_arrIndexOf(challenge.qop, "auth-int") !== -1 ? "auth-int" : null);
  /** @internal The client nonce comes from the captured random source. Read off the module export it
   * is replaceable, and a predictable cnonce is a replayable response: the whole point of the value
   * is that the server cannot have seen it before. A caller's own `rng` still wins, as before. */
  /** @internal The ENCODING of the random bytes is captured too. Capturing the random source alone
   * left the value it produced readable through a replaced `Buffer.prototype.toString`, which can
   * answer with a fixed string: the unpredictability is a property of what reaches the header, not of
   * where the bytes came from. A caller's own `rng` still wins. */
  var cnonce = intrinsic.String((params.rng || function () {
    return intrinsic.bufToString(_randomBytes(18), "base64");
  })());
  var realm = challenge.realm, nonce = challenge.nonce;
  var isUtf8 = intrinsic.toUpperCase(intrinsic.String(challenge.charset || "")) === "UTF-8";
  var pUser = params.username == null ? "" : intrinsic.String(params.username);
  var pPass = params.password == null ? "" : intrinsic.String(params.password);
  /** @internal The credentials are normalized through the capture: what this produces is hashed, so a
   * replaced `normalize` changes the input to the proof the server checks. */
  if (isUtf8) { pUser = _strNormalize(pUser, "NFC"); pPass = _strNormalize(pPass, "NFC"); }
  var user = _octets(pUser, challenge.charset);
  var pass = _octets(pPass, challenge.charset);
  var HA1 = H(alg.hash, user + ":" + realm + ":" + pass);
  if (alg.sess) HA1 = H(alg.hash, HA1 + ":" + nonce + ":" + cnonce);
  var A2 = (useQop === "auth-int")
    ? params.method + ":" + params.uri + ":" + H(alg.hash, params.body == null ? "" : params.body)
    : params.method + ":" + params.uri;
  var HA2 = H(alg.hash, A2);
  var ncNum = (typeof params.nc === "number" && params.nc >= 1) ? Math.floor(params.nc) : 1;
  var nc = _strSlice("0000000" + intrinsic.numberToString(ncNum, 16), -8);
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
  /** @internal The header is assembled through the captures. These decide which parameters reach the
   * server: a dropped `cnonce` or `nc` is a credential the server reads under different rules than
   * the one it was computed under. */
  intrinsic.push(parts, "realm=" + _qstr(realm), "nonce=" + _qstr(nonce), "uri=" + _qstr(params.uri), "algorithm=" + challenge.algorithm);
  if (useQop) { intrinsic.push(parts, "qop=" + useQop); intrinsic.push(parts, "nc=" + nc); }
  if (useQop || alg.sess) { intrinsic.push(parts, "cnonce=" + _qstr(cnonce)); }
  intrinsic.push(parts, "response=" + _qstr(response));
  if (challenge.opaque != null) intrinsic.push(parts, "opaque=" + _qstr(challenge.opaque));
  if (challenge.userhash) intrinsic.push(parts, "userhash=true");
  return "Digest " + _arrJoin(parts, ", ");
}

/** @internal The protection-space entries are parsed through the captures. They decide whether a
 * request is inside the space a credential was issued for, so an entry read differently is a
 * credential sent to an origin the challenge did not cover. */
function _domainEntry(d) {
  d = intrinsic.String(d == null ? "" : d);
  if (_charAt(d, 0) === "/") return { origin: null, full: d };
  try { var u = new _URL(d); return { origin: intrinsic.toLowerCase(_urlOrigin(u)), full: (_urlPathname(u) || "/") + (_urlSearch(u) || "") }; }
  catch (_e) { return null; }
}

function inProtectionSpace(challenge, requestOrigin, requestPathAndSearch) {
  var domain = challenge && challenge.domain;
  if (!domain || !domain.length) return true;
  /** @internal This answers whether a credential may be sent to this request's origin, so every
   * operation it compares through is captured: `true` here is what lets the credential go out. */
  var origin = intrinsic.toLowerCase(intrinsic.String(requestOrigin == null ? "" : requestOrigin));
  var full = intrinsic.String(requestPathAndSearch == null ? "" : requestPathAndSearch);
  for (var i = 0; i < domain.length; i++) {
    var e = _domainEntry(domain[i]);
    if (e === null) continue;
    if (e.origin !== null && e.origin !== origin) continue;
    if (intrinsic.stringIndexOf(full, e.full) === 0) return true;
  }
  return false;
}

module.exports = { parseChallenge: parseChallenge, answer: answer, inProtectionSpace: inProtectionSpace };
