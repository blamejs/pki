// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- NOT on pki.*. HTTP Digest access authentication (RFC 7616): parse an UNTRUSTED
// WWW-Authenticate challenge (fail-closed, quoted-string-honoring) and compute the Authorization
// response header (byte-exact A1/A2/KD). Prefix-agnostic: every thrown code comes from the caller's
// E(code, msg) FACTORY (never a defineClass class -- feedback_guard_error_factory_not_class) and its
// policy.codes map, so pki.est composes it now and pki.acme / pki.cmp can reuse it as config, not a fork.
//
// The challenge is attacker-shaped: a comma inside a quoted value is NOT a delimiter (the _hasBasicChallenge
// substring-scan bug class), a missing realm / nonce is REJECTED not defaulted, and an unsupported / weak
// algorithm or a no-qop challenge fails closed rather than downgrading (feedback_guards_fail_closed_not_guess).

var crypto = require("crypto");
var constants = require("./constants");

// Algorithm registry (a data row, not a switch -- Hard rule #2): rank orders the RFC 7616 sec. 3.7
// "most secure the client can use" selection (SHA-512-256 > SHA-256 > MD5); an unknown algorithm ranks 0.
var ALGS = {
  "SHA-512-256": { hash: "sha512-256", rank: 3, sess: false }, "SHA-512-256-SESS": { hash: "sha512-256", rank: 3, sess: true },
  "SHA-256": { hash: "sha256", rank: 2, sess: false }, "SHA-256-SESS": { hash: "sha256", rank: 2, sess: true },
  "MD5": { hash: "md5", rank: 1, sess: false }, "MD5-SESS": { hash: "md5", rank: 1, sess: true },
};
var DEFAULT_CODES = {
  unsupportedAlgorithm: "digest/unsupported-algorithm", weakAlgorithm: "digest/weak-algorithm",
  noQop: "digest/no-qop", badChallenge: "digest/bad-challenge",
};

// H = lowercase-hex digest; the octet string is fed as latin1 so a UTF-8-encoded credential (charset=UTF-8)
// is hashed over its exact bytes. KD(secret, data) = H(secret ":" data).
function H(hash, s) { return crypto.createHash(hash).update(s, "latin1").digest("hex"); }
function KD(hash, secret, data) { return H(hash, secret + ":" + data); }
function _qstr(v) { return "\"" + String(v).replace(/(["\\])/g, "\\$1") + "\""; }

// Split a header at commas that are OUTSIDE a quoted-string (a quoted comma is a literal, not a delimiter).
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
// Index of the first '=' OUTSIDE a quoted-string, or -1.
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
function _unq(s) { return s.slice(1, -1).replace(/\\(.)/g, "$1"); }   // only ever called on a well-formed quoted-string (see _closedQuote)
// A well-formed quoted-string: opens with ", closes with an UNESCAPED " that is the LAST character (nothing trails
// it). An unterminated / trailing-garbage quoted-string is malformed (RFC 7230 sec. 3.2.6) and rejected.
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
// A control octet (RFC 7230 sec. 3.2.6 quoted-string / qdtext forbids CTL except HTAB). Scanned with charCodeAt
// rather than a control-char regex literal (which eslint no-control-regex correctly refuses).
function _hasCtl(s) {
  for (var i = 0; i < s.length; i++) { var c = s.charCodeAt(i); if ((c < 0x20 && c !== 0x09) || c === 0x7f) return true; }
  return false;
}

// Split a WWW-Authenticate header into [{ scheme, paramText }]. A comma-separated segment whose pre-'='
// text is "token WS token" (a scheme name before the first auth-param key), or a bare token with no '=',
// STARTS a new challenge; a "key=value" segment is a param continuation of the current challenge.
function _splitChallenges(s) {
  var segs = _commaSplitOutsideQuotes(s);
  var out = [], cur = null;
  for (var i = 0; i < segs.length; i++) {
    var seg = segs[i].replace(/^\s+|\s+$/g, "");
    if (seg === "") continue;
    var eq = _firstEqOutsideQuotes(seg);
    var pre = (eq < 0 ? seg : seg.slice(0, eq)).replace(/^\s+|\s+$/g, "");
    var ws = /^(\S+)\s+(\S[\s\S]*)$/.exec(pre);
    if (eq < 0) { cur = { scheme: seg, paramText: "" }; out.push(cur); }        // a bare scheme token (e.g. "Basic")
    else if (ws) { cur = { scheme: ws[1], paramText: seg.replace(/^\s*\S+\s+/, "") }; out.push(cur); }   // "scheme firstKey=..."
    else if (cur) { cur.paramText = cur.paramText ? cur.paramText + "," + seg : seg; }                   // "key=value" continuation
  }
  return out;
}
// Parse a challenge's params into { key(lower): { value, quoted } }; a repeated key is malformed (fail closed).
function _parseParams(paramText, E, code) {
  var segs = _commaSplitOutsideQuotes(paramText), map = Object.create(null);
  for (var i = 0; i < segs.length; i++) {
    var seg = segs[i].replace(/^\s+|\s+$/g, "");
    if (seg === "") continue;
    var eq = _firstEqOutsideQuotes(seg);
    if (eq < 0) throw E(code, "malformed Digest auth-param (no '='): " + JSON.stringify(seg));
    var key = seg.slice(0, eq).replace(/^\s+|\s+$/g, "").toLowerCase();
    var rawVal = seg.slice(eq + 1).replace(/^\s+|\s+$/g, "");
    var quoted = rawVal.charAt(0) === "\"";
    if (quoted && !_closedQuote(rawVal)) throw E(code, "an unterminated or trailing-garbage Digest quoted-string (RFC 7230 sec. 3.2.6)");
    if (Object.prototype.hasOwnProperty.call(map, key)) throw E(code, "repeated Digest auth-param " + JSON.stringify(key));
    var value = quoted ? _unq(rawVal) : rawVal;
    // Reject a control octet in any value (CR / LF / NUL / ...): it is a MUST-reject per RFC 7230 qdtext AND a
    // header-injection sink -- an unescaped CR/LF reflected into the outgoing Authorization would split the header.
    if (_hasCtl(value)) throw E(code, "a Digest auth-param value contains a control character (RFC 7230 sec. 3.2.6)");
    map[key] = { value: value, quoted: quoted };
  }
  return map;
}
// Structural validation of ONE Digest challenge's params (RFC 7616 sec. 3.3). Throws on any violation.
function _validateDigest(paramText, E, code) {
  var p = _parseParams(paramText, E, code);
  if (!p.realm || !p.realm.quoted || p.realm.value === "") throw E(code, "a Digest challenge requires a non-empty quoted realm (RFC 7616 sec. 3.3)");
  if (!p.nonce || !p.nonce.quoted || p.nonce.value === "") throw E(code, "a Digest challenge requires a non-empty quoted nonce (RFC 7616 sec. 3.3)");
  if (p.algorithm && p.algorithm.quoted) throw E(code, "the Digest algorithm must be a token, not a quoted-string (RFC 7616 sec. 3.3)");
  var qop = [];
  if (p.qop) {
    if (!p.qop.quoted) throw E(code, "the Digest qop must be a quoted list (RFC 7616 sec. 3.3)");
    qop = p.qop.value.split(",").map(function (x) { return x.replace(/^\s+|\s+$/g, "").toLowerCase(); }).filter(Boolean);
  }
  return {
    scheme: "Digest", realm: p.realm.value, nonce: p.nonce.value, qop: qop,
    algorithm: p.algorithm ? p.algorithm.value.toUpperCase() : "MD5",
    opaque: p.opaque ? p.opaque.value : null,
    stale: !!(p.stale && String(p.stale.value).toLowerCase() === "true"),
    userhash: !!(p.userhash && String(p.userhash.value).toLowerCase() === "true"),
    charset: p.charset ? p.charset.value : null,
  };
}

// parseChallenge(www, E, code, policy?) -> the most-secure USABLE structurally-valid Digest challenge,
//   OR null (no Digest challenge present),  OR throw E(code) (a Digest challenge present but none valid).
// Selection is policy-aware: a challenge answer() would refuse under the active policy (an unsupported /
// MD5-when-disallowed algorithm, or a qop this client cannot satisfy) is ranked BELOW every usable one, so a
// higher-algorithm-rank but unusable offer (e.g. a SHA-512-256 no-qop challenge under the default policy)
// never shadows a lower-ranked usable one (e.g. SHA-256 with qop="auth") -- RFC 7616 sec. 3.3. When NO
// challenge is usable the highest-algorithm-rank one is still returned, so answer() reports the specific
// policy reason (which opt to set) rather than a generic "no challenge".
function parseChallenge(www, E, code, policy) {
  var pol = policy || {};
  var codes = pol.codes || DEFAULT_CODES;
  var raw = String(www == null ? "" : www);
  if (raw.length > constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES) throw E(code, "the WWW-Authenticate header exceeds the " + constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES + "-byte cap");
  var challenges = _splitChallenges(raw);
  var best = null, bestUsable = false, bestRank = -1, sawDigest = false;
  for (var i = 0; i < challenges.length; i++) {
    if (challenges[i].scheme.toLowerCase() !== "digest") continue;
    sawDigest = true;
    var parsed = _validateDigest(challenges[i].paramText, E, code);   // throws on a structural violation (fail closed)
    var alg = ALGS[parsed.algorithm];
    var rank = alg ? alg.rank : 0;
    var usable = _rejection(parsed, pol, codes) === null;
    // Usability dominates algorithm rank; among equally-usable offers the stronger algorithm wins.
    if (best === null || (usable && !bestUsable) || (usable === bestUsable && rank > bestRank)) {
      best = parsed; bestUsable = usable; bestRank = rank;
    }
  }
  if (best) return best;
  if (sawDigest) throw E(code, "no usable Digest challenge (missing realm / nonce)");   // unreachable-in-practice: a structural fault above already threw
  return null;
}

// Credential octets for the given charset (RFC 7616 sec. 4): UTF-8 -> the exact UTF-8 bytes; else the
// string as-is (ASCII / latin1). H() hashes over latin1, so a UTF-8 credential is fed as its octet string.
function _octets(s, charset) {
  var v = s == null ? "" : String(s);
  return (charset && String(charset).toUpperCase() === "UTF-8") ? Buffer.from(v, "utf8").toString("latin1") : v;
}

// The policy gates a parsed challenge must clear to be answerable (RFC 7616 sec. 3.4): a supported
// algorithm, MD5 only when allowed, and a qop this client can satisfy (auth / auth-int, or no-qop only when
// allowLegacyQop). Returns a { code, msg } rejection or null. This is the SINGLE definition both answer()
// and parseChallenge() consult, so challenge SELECTION can never rank a challenge as usable that answer()
// would then refuse (or vice-versa) -- the two cannot drift.
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

// answer(challenge, { method, uri, username, password, body, policy, rng }, E) -> the Authorization header value.
function answer(challenge, params, E) {
  var pol = params.policy || {};
  var codes = pol.codes || DEFAULT_CODES;
  var rej = _rejection(challenge, pol, codes);
  if (rej) throw E(rej.code, rej.msg);
  var alg = ALGS[challenge.algorithm];
  var useQop = challenge.qop.indexOf("auth") !== -1 ? "auth" : (challenge.qop.indexOf("auth-int") !== -1 ? "auth-int" : null);
  var cnonce = String((params.rng || function () { return crypto.randomBytes(18).toString("base64"); })());
  var realm = challenge.realm, nonce = challenge.nonce;
  var user = _octets(params.username, challenge.charset);
  var pass = _octets(params.password, challenge.charset);
  var HA1 = H(alg.hash, user + ":" + realm + ":" + pass);
  if (alg.sess) HA1 = H(alg.hash, HA1 + ":" + nonce + ":" + cnonce);
  var A2 = (useQop === "auth-int")
    ? params.method + ":" + params.uri + ":" + H(alg.hash, params.body == null ? "" : params.body)
    : params.method + ":" + params.uri;
  var HA2 = H(alg.hash, A2);
  // The nonce-count: a (nonce, nc) pair MUST NOT be reused (RFC 7616 sec. 3.4), so a request that REUSES a nonce
  // (a same-origin redirect, an auth-int retry) increments nc; a fresh nonce restarts at 1. The caller supplies
  // the count for this nonce (default 1); formatted as 8 lowercase hex.
  var ncNum = (typeof params.nc === "number" && params.nc >= 1) ? Math.floor(params.nc) : 1;
  var nc = ("0000000" + ncNum.toString(16)).slice(-8);
  var response = useQop
    ? KD(alg.hash, HA1, nonce + ":" + nc + ":" + cnonce + ":" + useQop + ":" + HA2)
    : KD(alg.hash, HA1, nonce + ":" + HA2);
  // The username sent is hashed when the server set userhash=true (RFC 7616 sec. 3.4.4, privacy); A1 above
  // still used the REAL username. charset=UTF-8 -> the sent username is the UTF-8 octet string.
  var sentUser = challenge.userhash ? H(alg.hash, _octets(params.username, challenge.charset) + ":" + realm) : _octets(params.username, challenge.charset);
  var parts = [
    "username=" + _qstr(sentUser), "realm=" + _qstr(realm), "nonce=" + _qstr(nonce),
    "uri=" + _qstr(params.uri), "algorithm=" + challenge.algorithm,
  ];
  if (useQop) { parts.push("qop=" + useQop); parts.push("nc=" + nc); }
  // The cnonce directive is emitted whenever the server needs it to recompute the response: under a qop, and
  // also under a -sess algorithm whose A1 folds in the cnonce even with no qop (RFC 7616 sec. 3.4.2 / 3.9.1).
  if (useQop || alg.sess) { parts.push("cnonce=" + _qstr(cnonce)); }
  parts.push("response=" + _qstr(response));
  if (challenge.opaque != null) parts.push("opaque=" + _qstr(challenge.opaque));
  if (challenge.userhash) parts.push("userhash=true");
  return "Digest " + parts.join(", ");
}

module.exports = { parseChallenge: parseChallenge, answer: answer };
