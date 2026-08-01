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
    // A qop directive that is PRESENT but lists no value (qop="" / qop=", ,") is malformed -- it is NOT the
    // absent-qop (RFC 2069) case. Reject it rather than silently collapsing to a no-qop response the server
    // cannot accept (RFC 7616 sec. 3.3). Only an OMITTED qop directive selects the legacy no-qop path.
    if (qop.length === 0) throw E(code, "a present Digest qop directive must list at least one value (RFC 7616 sec. 3.3)");
  }
  // domain (RFC 7616 sec. 3.3): a QUOTED, space-separated list of URIs defining the protection space. An
  // UNQUOTED domain is malformed and rejected (fail closed like realm / nonce / qop) rather than silently
  // widened -- widening a mis-encoded scope to "the whole server" would send credentials MORE broadly than the
  // server intended. Surfaced as an array of the listed URIs, or null when omitted / quoted-empty -- which per
  // the RFC means "all URIs on the responding server" (the answer may be reused for any same-origin URI, sec. 3.5).
  if (p.domain && !p.domain.quoted) throw E(code, "the Digest domain must be a quoted-string (RFC 7616 sec. 3.3)");
  var domain = (p.domain && p.domain.value.replace(/^\s+|\s+$/g, "") !== "")
    ? p.domain.value.replace(/^\s+|\s+$/g, "").split(/\s+/) : null;
  // charset (RFC 7616 sec. 3.3): the ONLY permitted value is the token "UTF-8". A challenge naming any other
  // charset is malformed -- answering it would hash the credentials in the wrong encoding -- so it is rejected
  // (and thus skipped during multi-offer selection in favour of a valid offer).
  if (p.charset && String(p.charset.value).toUpperCase() !== "UTF-8") throw E(code, "the only allowed Digest charset is UTF-8 (RFC 7616 sec. 3.3)");
  return {
    scheme: "Digest", realm: p.realm.value, nonce: p.nonce.value, qop: qop, domain: domain,
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
  // preferStale marks a CREDENTIAL-REJECTION context (a 401 answering a credentialed request in the same space):
  // there, a stale=true offer is RETRYABLE with a fresh nonce while a stale=false offer is a terminal rejection,
  // so a retryable offer must outrank a stronger non-retryable one (RFC 7616 sec. 3.3). In the initial context
  // it is not set and stale plays no part.
  var preferStale = !!pol.preferStale;
  var raw = String(www == null ? "" : www);
  if (raw.length > constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES) throw E(code, "the WWW-Authenticate header exceeds the " + constants.LIMITS.HTTP_AUTH_HEADER_MAX_BYTES + "-byte cap");
  var challenges = _splitChallenges(raw);
  var best = null, bestUsable = false, bestStale = false, bestRank = -1, sawDigest = false;
  for (var i = 0; i < challenges.length; i++) {
    if (challenges[i].scheme.toLowerCase() !== "digest") continue;
    sawDigest = true;
    var parsed;
    // A MALFORMED offer is skipped, not fatal: parseChallenge's contract is to throw only when NO valid Digest
    // offer exists (RFC 7616 sec. 3.3), so a bad offer alongside a good one still authenticates on the good one.
    try { parsed = _validateDigest(challenges[i].paramText, E, code); }
    catch (_e) {
      continue;
    }
    var alg = ALGS[parsed.algorithm];
    var rank = alg ? alg.rank : 0;
    var usable = _rejection(parsed, pol, codes) === null;
    // A RETRYABLE offer (only meaningful in the rejection context) is stale=true AND carries a FRESH nonce --
    // the two conditions _drive requires to re-answer. A stale=true offer REPEATING the prior nonce is NOT
    // retryable, so it must not out-rank a weaker offer that is (RFC 7616 sec. 3.3).
    var retryable = preferStale && !!parsed.stale && parsed.nonce !== pol.priorNonce;
    // Usability dominates; then (in a rejection context) a retryable offer; then the stronger algorithm.
    if (best === null ||
        (usable && !bestUsable) ||
        (usable === bestUsable && retryable && !bestStale) ||
        (usable === bestUsable && retryable === bestStale && rank > bestRank)) {
      best = parsed; bestUsable = usable; bestStale = retryable; bestRank = rank;
    }
  }
  if (best) return best;
  if (sawDigest) throw E(code, "no valid Digest challenge: every Digest offer was malformed (missing realm / nonce or a bad directive, RFC 7616 sec. 3.3)");
  return null;
}

// Credential octets for the given charset (RFC 7616 sec. 4): UTF-8 -> the exact UTF-8 bytes; else the
// string as-is (ASCII / latin1). H() hashes over latin1, so a UTF-8 credential is fed as its octet string.
function _octets(s, charset) {
  var v = s == null ? "" : String(s);
  return (charset && String(charset).toUpperCase() === "UTF-8") ? Buffer.from(v, "utf8").toString("latin1") : v;
}

// Does the string carry any non-ASCII code unit (> U+007F)? Such a UTF-8 username is sent via `username*`.
function _hasNonAscii(s) {
  s = String(s == null ? "" : s);
  for (var i = 0; i < s.length; i++) { if (s.charCodeAt(i) > 0x7F) return true; }
  return false;
}

// RFC 5987 / RFC 8187 percent-encoding of a string's UTF-8 octets: attr-char (ALPHA / DIGIT / "!#$&+-.^_`|~")
// is kept literal, every other octet is %XX (upper-hex). Used for the Digest `username*` extended value.
function _pctEncodeUtf8(s) {
  var bytes = Buffer.from(String(s == null ? "" : s), "utf8");
  var out = "";
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    if ((b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) ||
        b === 0x21 || b === 0x23 || b === 0x24 || b === 0x26 || b === 0x2B || b === 0x2D ||
        b === 0x2E || b === 0x5E || b === 0x5F || b === 0x60 || b === 0x7C || b === 0x7E) {
      out += String.fromCharCode(b);
    } else {
      out += "%" + (b < 0x10 ? "0" : "") + b.toString(16).toUpperCase();
    }
  }
  return out;
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
  // The realm is used with its incoming header OCTETS unchanged (RFC 7616 sec. 4). The realm arrives from the
  // wire, so a transport that exposes header bytes as Latin-1 (the Node default) already presents the server's
  // UTF-8 octets one-per-char; re-encoding them as UTF-8 (as user / pass, which come from the caller as Unicode
  // strings, correctly do) would DOUBLE-encode and make the digest disagree with the server. H() hashes over
  // Latin-1, so the raw realm string contributes exactly the octets the server used.
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
  // The username field (RFC 7616 sec. 3.4). userhash=true sends H(username:realm) for privacy (sec. 3.4.4) --
  // an ASCII hex value; A1 above still used the REAL username. Otherwise a charset=UTF-8 username containing
  // non-ASCII characters MUST be carried in the extended `username*` form (RFC 5987 / RFC 8187 percent-encoded
  // UTF-8), because a server reads the legacy quoted `username` as ISO-8859-1 and could not resolve the account;
  // `username` and `username*` MUST NOT both appear. An ASCII (or userhash) username uses the legacy quoted form.
  var parts;
  if (!challenge.userhash && String(challenge.charset || "").toUpperCase() === "UTF-8" && _hasNonAscii(params.username)) {
    parts = ["username*=UTF-8''" + _pctEncodeUtf8(params.username)];
  } else {
    var sentUser = challenge.userhash ? H(alg.hash, _octets(params.username, challenge.charset) + ":" + realm) : _octets(params.username, challenge.charset);
    parts = ["username=" + _qstr(sentUser)];
  }
  parts.push("realm=" + _qstr(realm), "nonce=" + _qstr(nonce), "uri=" + _qstr(params.uri), "algorithm=" + challenge.algorithm);
  if (useQop) { parts.push("qop=" + useQop); parts.push("nc=" + nc); }
  // The cnonce directive is emitted whenever the server needs it to recompute the response: under a qop, and
  // also under a -sess algorithm whose A1 folds in the cnonce even with no qop (RFC 7616 sec. 3.4.2 / 3.9.1).
  if (useQop || alg.sess) { parts.push("cnonce=" + _qstr(cnonce)); }
  parts.push("response=" + _qstr(response));
  if (challenge.opaque != null) parts.push("opaque=" + _qstr(challenge.opaque));
  if (challenge.userhash) parts.push("userhash=true");
  return "Digest " + parts.join(", ");
}

// Parse one domain URI entry (RFC 7616 sec. 3.3) into { origin, full }: an abs_path ("/a", "/a?x=1") is
// relative to the responding server -> origin null (any same-origin request); an ABSOLUTE URI carries its own
// authority -> origin "scheme://authority" (lowercased, default port normalized) and matches ONLY a request to
// that SAME origin, since an entry to a different host names a protection space on a different server. `full` is
// the pathname + query the request URI is prefix-compared against. A relative / unparseable absolute entry -> null.
function _domainEntry(d) {
  d = String(d == null ? "" : d);
  if (d.charAt(0) === "/") return { origin: null, full: d };
  // An absolute entry is parsed through the URL constructor so its origin is NORMALIZED the same way the
  // request's URL.origin is -- an explicit default port (https :443 / http :80) is dropped, so a domain naming
  // "https://h:443/x" still matches a request whose origin normalizes to "https://h". A relative / unparseable
  // entry throws and never matches (fail closed).
  try { var u = new URL(d); return { origin: u.origin.toLowerCase(), full: (u.pathname || "/") + (u.search || "") }; }
  catch (_e) { return null; }
}

// inProtectionSpace(challenge, requestOrigin, requestPathAndSearch) -> is the request within the challenge's
// protection space? An absent / empty domain means "all URIs on the responding server" (RFC 7616 sec. 3.3), so
// any same-origin request matches; otherwise membership is by LITERAL URI PREFIX (RFC 7616 sec. 3.5 / RFC 2617
// sec. 1.2): the request's pathname + query must have a listed domain URI as a prefix, and for an absolute entry
// the same origin. The query is part of the prefix, so /enroll?tenant=a does not cover /enroll?tenant=b while a
// query-less /enroll covers its whole subtree (including /enroll?...). Used to scope where a cached answer is reused.
function inProtectionSpace(challenge, requestOrigin, requestPathAndSearch) {
  var domain = challenge && challenge.domain;
  if (!domain || !domain.length) return true;
  var origin = String(requestOrigin == null ? "" : requestOrigin).toLowerCase();
  var full = String(requestPathAndSearch == null ? "" : requestPathAndSearch);
  for (var i = 0; i < domain.length; i++) {
    var e = _domainEntry(domain[i]);
    if (e === null) continue;
    if (e.origin !== null && e.origin !== origin) continue;   // an absolute entry to a DIFFERENT origin is a different protection space
    if (full.indexOf(e.full) === 0) return true;
  }
  return false;
}

module.exports = { parseChallenge: parseChallenge, answer: answer, inProtectionSpace: inProtectionSpace };
