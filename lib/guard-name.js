// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var intrinsic = require("./guard-intrinsic");
var _append = require("./guard-list").append;
var _assertCanonicalOid = require("./guard-identifier").assertCanonicalOid;

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
var _FQDN_TABLE = _charTable("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-");
var _DIGDOT_TABLE = _charTable("0123456789.");
function _allCharsIn(s, table) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i++) if (!table[_charCodeAt(s, i)]) return false;
  return true;
}

function stripTrailingDot(s) { return _charAt(s, s.length - 1) === "." ? _strSlice(s, 0, -1) : s; }

/** @internal A host name of two or more labels that is not an address, which is the form a URI
 * name constraint is compared by (RFC 5280 sec. 4.2.1.10). */
function isFqdnHost(host) {
  var h = stripTrailingDot(host);
  if (h === "" || _indexOf(h, ".") === -1) return false;
  if (!_allCharsIn(h, _FQDN_TABLE)) return false;
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

/** @internal A host name, optionally written as a subtree with a leading dot, and with the one
 * trailing dot the comparison strips. */
function _hostConstraintBody(s) {
  var h = stripTrailingDot(s);
  return _charAt(h, 0) === "." ? _strSlice(h, 1) : h;
}

/** @internal Why a name-constraint base cannot be enforced, or null when it can. A base outside the
 * form its tag names is not a narrower namespace: an empty dNSName base matches every name, and a
 * base holding characters no host name can hold matches none, so the same value that reads as a
 * restriction either lifts one or applies to nothing. The comparisons this mirrors are in
 * lib/path-validate.js, and a base refused here is one they would answer with no verdict. */
function constraintBaseRefusal(tag, base) {
  if (typeof base !== "string") return "must be a string for tag " + tag;
  if (tag === 1) {
    var at = _indexOf(base, "@");
    if (at === -1) {
      return _isHostName(_hostConstraintBody(base)) ? null
        : "must be a mailbox, a host name, or a host name written as a subtree with a leading dot";
    }
    if (at !== _lastIndexOf(base, "@")) return "must name one mailbox, and it carries more than one at-sign";
    if (!_isMailboxLocal(_strSlice(base, 0, at))) return "must carry the local part of a mailbox before its at-sign";
    return _isHostName(stripTrailingDot(_strSlice(base, at + 1))) ? null : "must end in the host name of a mailbox";
  }
  if (tag === 2) {
    return _isHostName(_hostConstraintBody(base)) ? null
      : "must be a host name, optionally written as a subtree with a leading dot";
  }
  if (tag === 6) {
    var h = _hostConstraintBody(_toLowerCase(base));
    var dotted = _isHostName(h) && _indexOf(h, ".") !== -1 && !_allCharsIn(h, _DIGDOT_TABLE);
    return dotted ? null
      : "must be a dotted host name, which is the part of a URI a certificate is compared by";
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
  escapeControlBytes: escapeControlBytes, escapeDnValue: escapeDnValue,
  lowerAscii: lowerAscii,
  stripTrailingDot: stripTrailingDot, isFqdnHost: isFqdnHost, constraintBaseRefusal: constraintBaseRefusal,
});
