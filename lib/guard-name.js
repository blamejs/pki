// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var intrinsic = require("./guard-intrinsic");
var _append = require("./guard-list").append;
var _assertCanonicalOid = require("./guard-identifier").assertCanonicalOid;
var _ipUtils = require("./ip-utils");
var _isIPv4 = _ipUtils.isIPv4;
var _expandIpv6Hex = _ipUtils.expandIpv6Hex;

var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var _toLowerCase = intrinsic.uncurry(String.prototype.toLowerCase);
var _toUpperCase = intrinsic.uncurry(String.prototype.toUpperCase);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _lastIndexOf = intrinsic.uncurry(String.prototype.lastIndexOf);
var _indexOf = intrinsic.uncurry(String.prototype.indexOf);
var _numToString = intrinsic.uncurry(Number.prototype.toString);
var _create = intrinsic.create;
var _hasOwn = intrinsic.hasOwn;
var _fromCharCode = String.fromCharCode;
var _bufferFrom = intrinsic.bufferFrom;
var _TextDecoderCtor = TextDecoder;
var _utf8Fatal = new _TextDecoderCtor("utf-8", { fatal: true, ignoreBOM: true });
var _decodeUtf8 = intrinsic.uncurry(_TextDecoderCtor.prototype.decode);
var _String = String;
var _isArray = Array.isArray;
var _isBuffer = intrinsic.isBuffer;
var _bufferEquals = intrinsic.bufferEquals;
var _getOwnPropertyDescriptor = intrinsic.getOwnPropertyDescriptor;

// @enforced-by behavioral -- the control-byte reject has no rename-proof code
function assertNoControlBytes(str, E, code, label) {
  for (var i = 0; i < str.length; i++) {
    var c = _charCodeAt(str, i);
    if (c === 0 || (c < 0x20 && c !== 0x09)) {
      throw E(code, label + " contains an embedded control byte (CVE-2009-2408)");
    }
  }
  return str;
}

// @enforced-by behavioral -- the printable-IA5 byte-range reject has no rename-proof
function assertPrintableIa5(buf, E, code, label) {
  var n = intrinsic.sizeOf(buf);
  for (var i = 0; i < n; i++) {
    if (buf[i] < 0x20 || buf[i] > 0x7e) {
      throw E(code, label + " must be a printable IA5String (no control bytes)");
    }
  }
  return buf;
}

function _isSpace(c) { return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d; }
function _canonAttrValue(v, E, code, label) {
  if (typeof v !== "string") return v;
  assertNoControlBytes(v, E, code, label);
  var out = "", lastWasSpace = true;
  for (var i = 0; i < v.length; i++) {
    if (_isSpace(_charCodeAt(v, i))) { lastWasSpace = true; continue; }
    if (lastWasSpace && out.length) out += " ";
    lastWasSpace = false;
    out += _charAt(v, i);
  }
  return _toLowerCase(out);
}
function _assertSequence(a, b, E, code, label, what) {
  if (!_isArray(a) || !_isArray(b)) {
    throw E(code, "cannot compare " + label + ": " + what + " comparison requires the RDN sequence on both sides (pass name.rdns, not the parsed Name)");
  }
  if (_hasHole(a) || _hasHole(b)) {
    throw E(code, "cannot compare " + label + ": " + what + " comparison requires a dense sequence on both sides");
  }
}

function _hasHole(arr) {
  for (var i = 0; i < arr.length; i++) { if (!_hasOwn(arr, i)) return true; }
  return false;
}
// @enforced-by guard-shape-reinlined  (shares the canonicalization shape declared on dnEqual)
function rdnEqual(a, b, E, code, label) {
  _assertSequence(a, b, E, code, label, "an RDN");
  if (a.length !== b.length) return false;
  var used = _create(null);
  for (var i = 0; i < a.length; i++) {
    var found = false;
    for (var j = 0; j < b.length; j++) {
      if (used[j]) continue;
      if (a[i].type === b[j].type && _canonAttrValue(a[i].value, E, code, label) === _canonAttrValue(b[j].value, E, code, label)) {
        used[j] = true; found = true; break;
      }
    }
    if (!found) return false;
  }
  return true;
}
// @enforced-by guard-shape-reinlined
// @guard-shape replace\(/\\s\+/g,
function dnEqual(rdnsA, rdnsB, E, code, label) {
  _assertSequence(rdnsA, rdnsB, E, code, label, "a distinguished-name");
  if (rdnsA.length !== rdnsB.length) return false;
  for (var i = 0; i < rdnsA.length; i++) {
    if (!rdnEqual(rdnsA[i], rdnsB[i], E, code, label)) return false;
  }
  return true;
}

// @enforced-by behavioral -- the rule's identity is carried by the kind strings, which the
function dpnCorresponds(a, b, E, code, label) {
  var x = _reduceDpn(a, E, code, label), y = _reduceDpn(b, E, code, label);
  if (x.kind !== y.kind) return false;
  if (x.kind === "rdn") return _bufferEquals(x.bytes, y.bytes);
  for (var i = 0; i < x.names.length; i++) {
    for (var j = 0; j < y.names.length; j++) {
      if (_bufferEquals(x.names[i], y.names[j])) return true;
    }
  }
  return false;
}

function _reduceDpn(d, E, code, label) {
  function refuse(why) { return E(code, "cannot compare " + label + ": " + why); }
  function ownValue(o, k) {
    var desc = _getOwnPropertyDescriptor(o, k);
    if (!desc || !_hasOwn(desc, "value")) throw refuse("a distribution-point comparison requires " + k + " to be the comparand's own value (RFC 5280 sec. 6.3.3 compares decoded names)");
    return desc.value;
  }
  if (!d || typeof d !== "object") {
    throw refuse("a distribution-point comparison requires the decoded DistributionPointName on both sides (kind fullName or rdn)");
  }
  var kind = ownValue(d, "kind");
  if (kind !== "fullName" && kind !== "rdn") throw refuse("a DistributionPointName is fullName or nameRelativeToCRLIssuer, and this is neither");
  if (kind === "rdn") {
    var bytes = ownValue(d, "bytes");
    if (!_isBuffer(bytes)) throw refuse("a nameRelativeToCRLIssuer distribution point must carry its encoded bytes");
    return { kind: kind, bytes: bytes };
  }
  var names = ownValue(d, "names");
  if (!_isArray(names)) throw refuse("a fullName distribution point must carry a sequence of encoded GeneralNames");
  var len = names.length;
  var taken = [];
  for (var i = 0; i < len; i++) {
    var n = ownValue(names, i);
    if (!_isBuffer(n)) throw refuse("every fullName GeneralName must be its encoded bytes");
    taken[i] = n;
  }
  return { kind: kind, names: taken };
}

// @enforced-by guard-shape-reinlined
// @guard-shape < 0x20 \|\| \w+ === 0x7f
function escapeControlBytes(str) {
  var s = _String(str), out = "";
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    out += (c < 0x20 || c === 0x7f)
      ? "\\x" + (c < 16 ? "0" : "") + _toUpperCase(_numToString(c, 16))
      : _charAt(s, i);
  }
  return out;
}

var DN_SPECIAL = intrinsic.assign(intrinsic.create(null), { 0x2c: 1, 0x2b: 1, 0x22: 1, 0x5c: 1, 0x3c: 1, 0x3e: 1, 0x3b: 1 });

var _hexNibble = require("./guard-encoding").hexNibble;
function _isAttrTypeStart(c) { return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a); }
function _isAttrTypeChar(c) { return _isAttrTypeStart(c) || (c >= 0x30 && c <= 0x39) || c === 0x2d; }
function _isDigit(c) { return c >= 0x30 && c <= 0x39; }

// @enforced-by behavioral -- the descriptor grammar has no rename-proof shape distinct
function isAttributeDescriptor(name) {
  if (typeof name !== "string" || name.length === 0) return false;
  if (!_isAttrTypeStart(_charCodeAt(name, 0))) return false;
  for (var i = 1; i < name.length; i++) {
    if (!_isAttrTypeChar(_charCodeAt(name, i))) return false;
  }
  return true;
}

// @enforced-by behavioral -- the inverse of escapeDnValue has no rename-proof shape distinct
function parseDnString(str, E, code, label) {
  if (typeof str !== "string") throw E(code, label + " must be a string");
  var rdns = [], atvs = [], i = 0, n = str.length;
  if (n === 0) return rdns;
  for (;;) {
    var typeStart = i;
    var first = _charCodeAt(str, i);
    if (_isDigit(first)) {
      while (i < n && (_isDigit(_charCodeAt(str, i)) || _charCodeAt(str, i) === 0x2e)) i++;
    } else if (_isAttrTypeStart(first)) {
      while (i < n && _isAttrTypeChar(_charCodeAt(str, i))) i++;
    }
    if (i === typeStart) throw E(code, label + " has a component with no attribute type");
    var type = _strSlice(str, typeStart, i);
    if (i >= n || _charCodeAt(str, i) !== 0x3d) throw E(code, label + " component " + type + " has no '=' after its attribute type");
    i++;

    var value = "", hex = null, pending = [];
    function flushPending() {
      if (pending.length === 0) return;
      var decoded;
      try { decoded = _decodeUtf8(_utf8Fatal, _bufferFrom(pending)); }
      catch (e) { throw E(code, label + " has a run of '\\' hex escapes that is not valid UTF-8 (RFC 4514 sec. 3)", e); }
      value += decoded;
      pending = [];
    }
    if (i < n && _charCodeAt(str, i) === 0x23) {
      i++;
      var hexStart = i;
      while (i < n && _hexNibble(_charCodeAt(str, i)) >= 0) i++;
      var span = i - hexStart;
      if (span === 0 || (span & 1) === 1) throw E(code, label + " has a '#' value that is not an even number of hex digits");
      hex = _strSlice(str, hexStart, i);
    } else {
      var valueStart = i, lastWasBareSpace = false;
      for (; i < n; i++) {
        var c = _charCodeAt(str, i);
        if (c === 0x2c || c === 0x2b) break;
        if (c !== 0x5c) {
          if (c === 0x00 || c === 0x22 || c === 0x3b || c === 0x3c || c === 0x3e) {
            throw E(code, label + " has an unescaped character RFC 4514 sec. 3 requires to be escaped");
          }
          if (c === 0x20 && i === valueStart) {
            throw E(code, label + " has an unescaped leading space, which RFC 4514 sec. 3 requires to be escaped");
          }
          lastWasBareSpace = c === 0x20;
        } else {
          lastWasBareSpace = false;
        }
        if (c === 0x5c) {
          i++;
          if (i >= n) throw E(code, label + " ends with a trailing '\\' that escapes nothing");
          var e1 = _charCodeAt(str, i);
          var h1 = _hexNibble(e1);
          if (h1 >= 0) {
            if (i + 1 >= n) throw E(code, label + " has a '\\' hex escape with only one digit");
            var h2 = _hexNibble(_charCodeAt(str, i + 1));
            if (h2 < 0) throw E(code, label + " has a '\\' hex escape whose second digit is not hex");
            _append(pending, h1 * 16 + h2);
            i++;
            continue;
          }
          if (e1 !== 0x20 && e1 !== 0x23 && e1 !== 0x3d && DN_SPECIAL[e1] !== 1) {
            throw E(code, label + " escapes a character RFC 4514 sec. 2.4 does not give a meaning to");
          }
          flushPending();
          value += _charAt(str, i);
          continue;
        }
        flushPending();
        value += _charAt(str, i);
      }
      flushPending();
      if (lastWasBareSpace) {
        throw E(code, label + " has an unescaped trailing space, which RFC 4514 sec. 3 requires to be escaped");
      }
    }
    _append(atvs, { type: type, value: hex === null ? value : null, hex: hex });

    if (i >= n) { _append(rdns, atvs); return rdns; }
    var sep = _charCodeAt(str, i);
    if (sep !== 0x2c && sep !== 0x2b) {
      throw E(code, label + " has a component followed by a character that is not a separator");
    }
    i++;
    if (sep === 0x2b) {
      if (i >= n) throw E(code, label + " ends with a '+' that joins nothing");
    } else {
      _append(rdns, atvs);
      atvs = [];
      if (i >= n) throw E(code, label + " ends with a separator that joins nothing");
      while (i < n && _charCodeAt(str, i) === 0x20) i++;
      if (i >= n) throw E(code, label + " ends with a separator that joins nothing");
    }
  }
}
// @enforced-by behavioral -- the escaping has no rename-proof code shape distinct
function escapeDnValue(v) {
  var s = _String(v), out = "";
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    if (c < 0x20 || c === 0x7f) out += "\\" + (c < 16 ? "0" : "") + _toUpperCase(_numToString(c, 16));
    else if (DN_SPECIAL[c] === 1) out += "\\" + _charAt(s, i);
    else out += _charAt(s, i);
  }
  if (out.length && _charAt(out, out.length - 1) === " ") out = _strSlice(out, 0, -1) + "\\ ";
  if (_charAt(out, 0) === "#" || _charAt(out, 0) === " ") out = "\\" + out;
  return out;
}

// @enforced-by guard-shape-reinlined
// @guard-shape lastIndexOf\("@"\)
function emailEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return "not-comparable";
  var ai = _lastIndexOf(a, "@"), bi = _lastIndexOf(b, "@");
  if (ai <= 0 || bi <= 0 || ai === a.length - 1 || bi === b.length - 1) return "not-comparable";
  var aLocal = _strSlice(a, 0, ai), bLocal = _strSlice(b, 0, bi);
  var aHost = _strSlice(a, ai + 1), bHost = _strSlice(b, bi + 1);
  if (!_asciiHost(aHost) || !_asciiHost(bHost)) return "not-comparable";
  if (aLocal !== bLocal) return "no-match";
  return lowerAscii(aHost) === lowerAscii(bHost) ? "match" : "no-match";
}

function _asciiHost(h) {
  if (h.length === 0) return false;
  for (var i = 0; i < h.length; i++) if (_charCodeAt(h, i) > 0x7f) return false;
  return true;
}

// @enforced-by guard-shape-reinlined
// @guard-shape 0x41\s*&&\s*[A-Za-z_$][\w$]*\s*<=\s*0x5[aA]\s*\)\s*\?[^:]*\+\s*(?:32|0x20)\s*\)
function lowerAscii(s) {
  var out = "";
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    out += (c >= 0x41 && c <= 0x5a) ? _fromCharCode(c + 32) : _charAt(s, i);
  }
  return out;
}

function _charTable(chars) {
  var t = _create(null);
  for (var i = 0; i < chars.length; i++) t[_charCodeAt(chars, i)] = true;
  return t;
}
var _DIGDOT_TABLE = _charTable("0123456789.");
function _allCharsIn(s, table) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i++) if (!table[_charCodeAt(s, i)]) return false;
  return true;
}

function stripTrailingDot(s) { return _charAt(s, s.length - 1) === "." ? _strSlice(s, 0, -1) : s; }

/** @internal Whether `s` opens with `scheme` followed by a colon, the scheme compared without
 * regard to ASCII case (RFC 3986 sec. 3.1). `scheme` is given in lower case. */
// @enforced-by behavioral -- a scheme comparison has no rename-proof code shape; the vectors refusing a location under the wrong scheme are the guard
function uriSchemeIs(s, scheme) {
  if (typeof s !== "string" || s.length <= scheme.length) return false;
  if (_charCodeAt(s, scheme.length) !== 0x3a) return false;
  return lowerAscii(_strSlice(s, 0, scheme.length)) === scheme;
}

/** @internal A host name that is not an address, which is the form a URI name constraint is
 * compared by (RFC 5280 sec. 4.2.1.10). The clause holds a URI constraint to "a fully qualified
 * domain name" and names in the same sentence what that excludes: a URI with no authority
 * component, and one whose authority names an IP address. It states no label count, so a single
 * label is a host like any other and `com` constrains a top-level domain. The host is read by its
 * labels rather than by which characters it holds: a character test admits an empty label and a
 * hyphen at a label edge, and the suffix comparison below would then match a base against a name
 * that is not a name. */
function isFqdnHost(host) {
  if (typeof host !== "string") return false;
  var h = stripTrailingDot(host);
  if (!_isHostName(h)) return false;
  if (_allCharsIn(h, _DIGDOT_TABLE)) return false;
  return true;
}

var _LDH_ALNUM = _charTable("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
var MAX_LABEL = 63;
var MAX_HOST = 253;
var MAX_LOCAL_PART = 64;

/** @internal One label of a host name (RFC 1034 sec. 3.5, RFC 1123 sec. 2.1): letters, digits and
 * hyphens, with a hyphen at neither edge, and 63 characters at most. */
function _isHostLabel(s, from, to) {
  var n = to - from;
  if (n === 0 || n > MAX_LABEL) return false;
  if (!_LDH_ALNUM[_charCodeAt(s, from)] || !_LDH_ALNUM[_charCodeAt(s, to - 1)]) return false;
  for (var i = from + 1; i < to - 1; i++) {
    var c = _charCodeAt(s, i);
    if (!_LDH_ALNUM[c] && c !== 0x2d) return false;
  }
  return true;
}

/** @internal A host name written as labels separated by dots, carrying no trailing dot: the caller
 * strips the one dot the comparison strips, so a second one is an empty label and is refused. */
function _isHostName(s) {
  if (s.length === 0 || s.length > MAX_HOST) return false;
  var start = 0;
  for (var i = 0; i <= s.length; i++) {
    if (i === s.length || _charCodeAt(s, i) === 0x2e) {
      if (!_isHostLabel(s, start, i)) return false;
      start = i + 1;
    }
  }
  return true;
}

/** @internal A host name written as labels separated by dots (RFC 1034 sec. 3.5, RFC 1123 sec. 2.1),
 * with no trailing dot: the caller strips the one dot a comparison strips, so a second one is an
 * empty label and is refused. */
// @enforced-by behavioral -- an LDH label walk has no rename-proof shape that separates it from any other per-character scan; the vectors refusing an empty label, a hyphen at a label edge and a name past 253 octets are the guard
function isHostName(s) { return typeof s === "string" && _isHostName(s); }

/** @internal The labels of `s`, in order, with no trailing-dot handling of its own: the caller
 * normalizes the dot through `stripTrailingDot` so both sides of a comparison are normalized by
 * one symbol. A name carrying an empty label yields an empty string at that position, which a
 * label test then refuses, rather than being dropped. */
// @enforced-by behavioral -- splitting on a dot has no rename-proof shape; the vectors counting the labels of a name carrying an empty one are the guard
function hostLabels(s) {
  var out = [], start = 0;
  for (var i = 0; i <= s.length; i++) {
    if (i === s.length || _charCodeAt(s, i) === 0x2e) {
      _append(out, _strSlice(s, start, i));
      start = i + 1;
    }
  }
  return out;
}

function _isAlnumLower(c) { return (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39); }

/** @internal Whether `l` is a well-formed A-label (RFC 5890 sec. 2.3.2.1): the `xn--` prefix
 * followed by groups of lower-case alphanumerics separated by single hyphens, each group non-empty.
 * The label is not decoded, because RFC 5891 sec. 3.1 rule 2 compares a pair of A-labels as
 * case-insensitive ASCII without validating either. */
// @enforced-by behavioral -- an `xn--` prefix scan has no rename-proof shape; the vectors refusing `xn--`, a trailing hyphen and an empty group are the guard
function isXnLabel(l) {
  if (typeof l !== "string") return false;
  var n = l.length;
  if (!(n >= 4 && _charCodeAt(l, 0) === 0x78 && _charCodeAt(l, 1) === 0x6e &&
        _charCodeAt(l, 2) === 0x2d && _charCodeAt(l, 3) === 0x2d)) return false;
  var i = 4, g = 0;
  while (i < n && _isAlnumLower(_charCodeAt(l, i))) { i++; g++; }
  if (g < 1) return false;
  while (i < n) {
    if (_charCodeAt(l, i) !== 0x2d) return false;
    i++;
    var g2 = 0;
    while (i < n && _isAlnumLower(_charCodeAt(l, i))) { i++; g2++; }
    if (g2 < 1) return false;
  }
  return true;
}

var _SCHEME_TABLE = _charTable("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-");

/** @internal The scheme and the host of a URI, read to RFC 3986 sec. 3: the scheme up to its colon,
 * and, when `//` follows that colon, the authority up to the first `/`, `?` or `#`, with userinfo
 * and port removed and an IPv6 literal's brackets stripped. `hasAuthority` is false for a URI
 * written without `//`, which RFC 3986 sec. 3.3 permits and which therefore has no host; a caller
 * that needs a host decides what to do with that rather than being handed a guess. `host` is null
 * when the authority carries none, and `bracketed` says the host arrived inside `[]`, which is the
 * only place an IPv6 literal may appear. Percent-escapes are left as written, so a caller comparing
 * the host decides whether to accept one. */
// @enforced-by behavioral -- a URI walk has no rename-proof shape that separates it from any other character scan; the vectors reading a scheme, refusing two userinfo separators and stripping a port are the guard
function uriParts(uri) {
  if (typeof uri !== "string") return null;
  var n = uri.length;
  if (n === 0) return null;
  var c0 = _charCodeAt(uri, 0);
  if (!((c0 >= 0x41 && c0 <= 0x5a) || (c0 >= 0x61 && c0 <= 0x7a))) return null;
  var p = 1;
  while (p < n && _SCHEME_TABLE[_charCodeAt(uri, p)]) p += 1;
  if (_charCodeAt(uri, p) !== 0x3a) return null;
  var scheme = _strSlice(uri, 0, p);
  if (_charCodeAt(uri, p + 1) !== 0x2f || _charCodeAt(uri, p + 2) !== 0x2f) {
    return { scheme: scheme, hasAuthority: false, host: null, bracketed: false };
  }
  p += 3;
  var authStart = p;
  while (p < n) {
    var d = _charCodeAt(uri, p);
    if (d === 0x2f || d === 0x3f || d === 0x23) break;
    p += 1;
  }
  var authority = _strSlice(uri, authStart, p);
  var firstAt = _indexOf(authority, "@");
  if (firstAt !== _lastIndexOf(authority, "@")) return null;
  if (firstAt !== -1) authority = _strSlice(authority, firstAt + 1);
  var host = _strSlice(authority, 0, _portStripIndex(authority));
  if (host === "") return { scheme: scheme, hasAuthority: true, host: null, bracketed: false };
  var hn = host.length;
  if (hn >= 2 && _charCodeAt(host, 0) === 0x5b && _charCodeAt(host, hn - 1) === 0x5d) {
    return { scheme: scheme, hasAuthority: true, host: _strSlice(host, 1, hn - 1), bracketed: true };
  }
  return { scheme: scheme, hasAuthority: true, host: host, bracketed: false };
}

/** @internal Where a `:port` suffix starts, or the length when there is none. RFC 3986 sec. 3.2.3
 * writes `port = *DIGIT`, so a colon with nothing after it is a port too, and leaving that colon on
 * the host would make the authority compare as a name carrying a character no name carries. A
 * bracketed IPv6 literal has colons of its own, so the scan reads digits back from the end and
 * requires the colon immediately before them; the closing bracket is what stops it. */
function _portStripIndex(s) {
  var i = s.length;
  while (i > 0) {
    var c = _charCodeAt(s, i - 1);
    if (c >= 0x30 && c <= 0x39) i -= 1;
    else break;
  }
  return (i > 0 && _charCodeAt(s, i - 1) === 0x3a) ? i - 1 : s.length;
}

var _ATEXT_TABLE = _charTable("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~");

/** @internal A quoted local part (RFC 5321 sec. 4.1.2 Quoted-string): printable ASCII between
 * quotes, where a backslash escapes the character after it. */
function _isQuotedLocal(s) {
  var n = s.length;
  if (n < 2 || _charCodeAt(s, n - 1) !== 0x22) return false;
  for (var i = 1; i < n - 1; i++) {
    var c = _charCodeAt(s, i);
    if (c === 0x5c) {
      i += 1;
      if (i >= n - 1) return false;
      var e = _charCodeAt(s, i);
      if (e < 0x20 || e > 0x7e) return false;
      continue;
    }
    if (c < 0x20 || c > 0x7e || c === 0x22) return false;
  }
  return true;
}

/** @internal The local part of a mailbox (RFC 5321 sec. 4.1.2): either a quoted string, or atoms
 * separated by dots, which is the form a certificate's mailbox is compared against. */
function _isMailboxLocal(s) {
  if (s.length === 0 || s.length > MAX_LOCAL_PART) return false;
  if (_charCodeAt(s, 0) === 0x22) return _isQuotedLocal(s);
  var pieceLen = 0;
  for (var i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    if (c === 0x2e) {
      if (pieceLen === 0) return false;
      pieceLen = 0;
      continue;
    }
    if (!_ATEXT_TABLE[c]) return false;
    pieceLen += 1;
  }
  return pieceLen > 0;
}

var _IPV6_TAG = "ipv6:";
/** @internal An address literal (RFC 5321 sec. 4.1.3), the other form a mailbox may name its domain
 * in: an IPv4 address in brackets, or an IPv6 address behind the tag that introduces one. The
 * comparison holds a mailbox constraint's domain to an exact match, so a literal is a domain it can
 * reach a verdict on. */
function _isAddressLiteral(s) {
  var n = s.length;
  if (n < 3 || _charCodeAt(s, 0) !== 0x5b || _charCodeAt(s, n - 1) !== 0x5d) return false;
  var inner = _strSlice(s, 1, n - 1);
  if (_toLowerCase(_strSlice(inner, 0, _IPV6_TAG.length)) === _IPV6_TAG) {
    return _expandIpv6Hex(_strSlice(inner, _IPV6_TAG.length)) !== null;
  }
  return _isIPv4(inner);
}

/** @internal The two halves of a mailbox, `null` when it carries no separator and the string
 * "ambiguous" when it carries more than one. This is the split the rfc822Name comparison runs, so a
 * constraint the comparison cannot separate is one this answers the same way. */
function splitMailbox(addr) {
  var first = _indexOf(addr, "@");
  if (first === -1) return null;
  if (first !== _lastIndexOf(addr, "@")) return "ambiguous";
  return [_strSlice(addr, 0, first), _strSlice(addr, first + 1)];
}

/** @internal A host name, optionally written as a subtree with a leading dot, and with the one
 * trailing dot the comparison strips. */
function _hostConstraintBody(s) {
  var h = stripTrailingDot(s);
  return _charAt(h, 0) === "." ? _strSlice(h, 1) : h;
}

/** @internal A label with nothing in it, which is what makes a subtree base unmatchable. The
 * comparisons in lib/path-validate.js compare a base against a name by suffix, so a base carrying an
 * empty label asks for a name carrying one, and a name that carries one is not a name. */
function _hasEmptyLabel(s) {
  if (s.length === 0) return true;
  if (_charAt(s, 0) === "." || _charAt(s, s.length - 1) === ".") return true;
  return _indexOf(s, "..") !== -1;
}

/** @internal Whether the comparison can read a constraint base at all, which is a narrower question
 * than whether a caller may state one. The door holds a caller to a well-formed host name; the
 * comparison asks only whether an empty label leaves the base matching no name, and answers such a
 * base with no verdict rather than with no match, since an excluded subtree that matches nothing
 * excludes nothing. The two differ in both directions. A label carrying an underscore or edged with a
 * hyphen is not a host name the door accepts, and the suffix comparison still applies it to exactly
 * the names it names, so it stays enforced. The reduction here is the comparison's own, so the two
 * cannot part company over a base like "..", whose body is empty only once a leading dot the
 * comparison keeps has been taken off.
 *
 * The rule follows the comparison's own branches rather than the tag alone, since one tag can be
 * compared two ways. An rfc822Name base carrying an at-sign is matched exactly and is read as a
 * mailbox; one without an at-sign constrains the host and is read as a subtree, as a dNSName base is.
 *
 * A base that reduces to nothing is read by tag, because the comparisons do not agree on it. For
 * dNSName it names the root of the namespace and `hostConstraintMatch` matches every name, so it is
 * readable. For rfc822Name the same reduction leaves no domain to compare and `emailMatch` matches no
 * mailbox, and for uniformResourceIdentifier `uriMatch` reads no host, so both are unreadable.
 * @enforced-by behavioral -- the rule has no rename-proof code shape, and the RED vectors in
 * path-validate.test.js driving a CA's own nameConstraints extension are the guard. */
function constraintBaseUnreadable(tag, base) {
  if (typeof base !== "string") return true;
  /** @internal A base carrying an at-sign names one mailbox, and `emailMatch` compares it to a name
   * exactly, local part and domain alike, rather than as a subtree. Each half is therefore read on
   * its own terms: the local part by the RFC 5321 sec. 4.1.2 Dot-string or Quoted-string rule, which
   * admits an underscore and refuses an empty atom, and the domain by the empty-label rule. A
   * bracketed address literal carries no empty label in either accepted form, so the domain rule
   * passes it through to the comparison, which reads it whole. */
  if (tag === 1 && _lastIndexOf(base, "@") !== -1) {
    var mb = splitMailbox(base);
    if (mb === null || mb === "ambiguous") return true;
    if (!_isMailboxLocal(mb[0])) return true;
    return _hasEmptyLabel(stripTrailingDot(mb[1]));
  }
  var body = stripTrailingDot(base);
  if (body === "") return tag !== 2;
  if (_charAt(body, 0) === ".") body = _strSlice(body, 1);
  return _hasEmptyLabel(body);
}

/** @internal Why a name-constraint base cannot be enforced, or null when it can. A base outside the
 * form its tag names is not a narrower namespace: an empty dNSName base matches every name, and a
 * base holding characters no host name can hold matches none, so the same value that reads as a
 * restriction either lifts one or applies to nothing. The comparisons this mirrors are in
 * lib/path-validate.js, and a base refused here is one they would answer with no verdict. */
function constraintBaseRefusal(tag, base) {
  if (typeof base !== "string") return "must be a string for tag " + tag;
  if (tag === 1) {
    var mb = splitMailbox(base);
    if (mb === null) {
      if (_isAddressLiteral(base)) return null;
      return _isHostName(_hostConstraintBody(base)) ? null
        : "must be a mailbox, a host name, or a host name written as a subtree with a leading dot";
    }
    if (mb === "ambiguous") {
      return "carries more than one at-sign, so the comparison cannot tell which one separates the mailbox";
    }
    if (!_isMailboxLocal(mb[0])) return "must carry the local part of a mailbox before its at-sign";
    if (_isAddressLiteral(mb[1])) return null;
    return _isHostName(stripTrailingDot(mb[1])) ? null
      : "must end in the host name or bracketed address literal of a mailbox";
  }
  if (tag === 2) {
    return _isHostName(_hostConstraintBody(base)) ? null
      : "must be a host name, optionally written as a subtree with a leading dot";
  }
  /** @internal RFC 5280 sec. 4.2.1.10 says of a URI constraint: "The constraint MUST be specified as
   * a fully qualified domain name and MAY specify a host or a domain", and the same sentence names
   * what that excludes: a URI with no authority component, and one whose authority names an IP
   * address. Its dNSName paragraph states no such requirement, so an address is a valid dNSName base
   * and is not a valid URI base. Neither paragraph states a label count. A caller meets this rule at
   * the door, whether through `pki.trust.anchor` or through the validator's subtree seeds. A base a
   * certificate carries in its own extension never reaches a door, and `uriMatch` holds it to the
   * same `isFqdnHost` this calls, so the door and the comparison cannot answer differently. */
  if (tag === 6) {
    /** @internal Only the leading dot comes off here. `isFqdnHost` takes a host as a URI carries
     * it and strips the one trailing dot that makes a name absolute, so stripping it here too
     * would let a base ending in two dots through as one ending in none. */
    var uriBody = _toLowerCase(base);
    if (_charAt(uriBody, 0) === ".") uriBody = _strSlice(uriBody, 1);
    if (isFqdnHost(uriBody)) return null;
    return _allCharsIn(stripTrailingDot(uriBody), _DIGDOT_TABLE)
      ? "must be a domain name rather than an address, RFC 5280 sec. 4.2.1.10 naming an address in a URI's authority as what a URI constraint cannot be compared against"
      : "must be a domain name, which RFC 5280 sec. 4.2.1.10 requires of a URI constraint, optionally written as a subtree with a leading dot";
  }
  return null;
}

var _ATV_KEYS = ["type", "value", "name"];

/** @internal A distinguished name a caller supplied, copied into fresh plain objects by reading
 * descriptors only. A Proxy answers its own reads and an accessor runs caller code, so either one
 * at any level is refused before anything is copied: a name that decides what it says while it is
 * being read can show a narrow value to a check and a wide one to the use, and where the name is a
 * namespace restriction that is the difference between a certificate being refused and admitted. */
function copyDnRdns(rdns, E, code, who) {
  assertPlainDnRdns(rdns, E, code, who);
  /** @internal A name of no relative names is a prefix of every name, so as a constraint it reaches
   * the same verdict on all of them. */
  if (rdns.length === 0) throw E(code, who + " must name at least one relative distinguished name");
  var out = [];
  for (var i = 0; i < rdns.length; i++) {
    var rd = intrinsic.getOwnPropertyDescriptor(rdns, i);
    if (rd === undefined) throw E(code, who + " index " + i + " is a hole or is inherited; every entry must be its own");
    var rdn = rd.value;
    if (!_isArray(rdn)) throw E(code, who + "[" + i + "] must be an array of attributes");
    if (rdn.length === 0) throw E(code, who + "[" + i + "] must carry at least one attribute");
    var rdnOut = [];
    for (var j = 0; j < rdn.length; j++) {
      var ad = intrinsic.getOwnPropertyDescriptor(rdn, j);
      if (ad === undefined) throw E(code, who + "[" + i + "] index " + j + " is a hole or is inherited; every entry must be its own");
      var atv = ad.value;
      if (atv === null || typeof atv !== "object") throw E(code, who + "[" + i + "][" + j + "] must be an attribute object carrying a type and a value");
      var atvOut = {};
      for (var k = 0; k < _ATV_KEYS.length; k++) {
        var fd = intrinsic.getOwnPropertyDescriptor(atv, _ATV_KEYS[k]);
        if (fd === undefined) continue;
        intrinsic.defineProperty(atvOut, _ATV_KEYS[k], { value: fd.value, enumerable: true, configurable: true, writable: true });
      }
      if (!_hasOwn(atvOut, "type") || !_hasOwn(atvOut, "value")) {
        throw E(code, who + "[" + i + "][" + j + "] must carry its type and value as own data properties");
      }
      /** @internal Every attribute a certificate's name is compared against is a string compared to
       * a string, so an attribute holding anything else is equal to nothing it will ever meet, and
       * NaN is not even equal to itself. A name built out of those is not a narrower namespace. */
      _assertCanonicalOid(atvOut.type, E, code, who + "[" + i + "][" + j + "].type");
      if (typeof atvOut.value !== "string") {
        throw E(code, who + "[" + i + "][" + j + "].value must be a string, the form a name is compared in");
      }
      assertNoControlBytes(atvOut.value, E, code, who + "[" + i + "][" + j + "].value");
      _append(rdnOut, atvOut);
    }
    _append(out, rdnOut);
  }
  return out;
}

/** @internal The shape check the copy above relies on. */
function assertPlainDnRdns(rdns, E, code, who) {
  if (intrinsic.types.isProxy(rdns)) throw E(code, who + " must be a plain array, not a Proxy");
  for (var i = 0; i < rdns.length; i++) {
    var rd = intrinsic.getOwnPropertyDescriptor(rdns, i);
    if (rd === undefined) continue;
    if (!_hasOwn(rd, "value")) throw E(code, who + " entry " + i + " must be a data property, not an accessor");
    var rdn = rd.value;
    if (!_isArray(rdn)) continue;
    if (intrinsic.types.isProxy(rdn)) throw E(code, who + "[" + i + "] must be a plain array, not a Proxy");
    for (var j = 0; j < rdn.length; j++) {
      var ad = intrinsic.getOwnPropertyDescriptor(rdn, j);
      if (ad === undefined) continue;
      if (!_hasOwn(ad, "value")) throw E(code, who + "[" + i + "] entry " + j + " must be a data property, not an accessor");
      var atv = ad.value;
      if (atv === null || typeof atv !== "object") continue;
      if (intrinsic.types.isProxy(atv)) throw E(code, who + "[" + i + "][" + j + "] must not be a Proxy");
      if (_isArray(atv)) throw E(code, who + "[" + i + "][" + j + "] must be an attribute object, not an array");
      for (var k = 0; k < _ATV_KEYS.length; k++) {
        var fd = intrinsic.getOwnPropertyDescriptor(atv, _ATV_KEYS[k]);
        if (fd !== undefined && !_hasOwn(fd, "value")) {
          throw E(code, who + "[" + i + "][" + j + "]." + _ATV_KEYS[k] + " must be a data property, not an accessor");
        }
      }
    }
  }
}

/** @internal The `rdns` of a directoryName base, captured the same way. An inherited Proxy answers
 * `in` through its has trap, which is caller code running inside a read meant to be getter-free, so
 * the prototype chain is walked before the property is asked for at all. Returns undefined when the
 * base carries no rdns array, which the caller reads as "not a directoryName base". */
function capturedRdns(base, E, code, who) {
  if (intrinsic.types.isProxy(base)) throw E(code, who + " must not be a Proxy");
  var baseProto = intrinsic.getPrototypeOf(base);
  while (baseProto !== null) {
    if (intrinsic.types.isProxy(baseProto)) throw E(code, who + " must not inherit from a Proxy");
    baseProto = intrinsic.getPrototypeOf(baseProto);
  }
  var d = intrinsic.getOwnPropertyDescriptor(base, "rdns");
  if (d === undefined) {
    if ("rdns" in base) throw E(code, who + " rdns must be an own data property, not inherited");
    return undefined;
  }
  if (!_hasOwn(d, "value")) throw E(code, who + " rdns must be a data property, not an accessor");
  if (!_isArray(d.value)) return undefined;
  return copyDnRdns(d.value, E, code, who + " rdns");
}

module.exports = intrinsic.freeze({
  capturedRdns: capturedRdns, copyDnRdns: copyDnRdns,
  assertNoControlBytes: assertNoControlBytes, assertPrintableIa5: assertPrintableIa5,
  dnEqual: dnEqual, rdnEqual: rdnEqual, emailEqual: emailEqual, dpnCorresponds: dpnCorresponds,
  escapeControlBytes: escapeControlBytes, escapeDnValue: escapeDnValue, parseDnString: parseDnString,
  isAttributeDescriptor: isAttributeDescriptor,
  lowerAscii: lowerAscii, uriSchemeIs: uriSchemeIs,
  stripTrailingDot: stripTrailingDot, isFqdnHost: isFqdnHost, splitMailbox: splitMailbox,
  isHostName: isHostName, hostLabels: hostLabels, isXnLabel: isXnLabel, uriParts: uriParts,
  constraintBaseRefusal: constraintBaseRefusal,
  constraintBaseUnreadable: constraintBaseUnreadable,
});
