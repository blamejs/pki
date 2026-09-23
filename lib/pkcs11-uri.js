// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.pkcs11
 * @nav        Keys
 * @title      PKCS#11 URI
 * @fullname   PKCS #11 URIs: naming a token and an object on it (RFC 7512)
 * @order      235
 * @slug       pkcs11
 *
 * @intro
 *   RFC 7512 defines a URI that names a token, a slot, a library and an object
 *   on a PKCS #11 device, which is how an operator points a tool at a key in a
 *   hardware security module, a smart card or a PIV slot without naming a file.
 *   `parseUri` reads one into a record and `formatUri` writes the record back.
 *
 *   The path component carries what identifies the object: `token`,
 *   `manufacturer`, `serial`, `model`, the three `library-*` attributes, the
 *   three `slot-*` attributes, `object`, `type` and `id`. The query component
 *   carries what tells a consumer how to reach it: `pin-source`, `pin-value`,
 *   `module-name` and `module-path`. A vendor attribute in either component is
 *   kept under its own name rather than dropped. A vendor query attribute is
 *   carried as a list of its values, which sec. 2.4 permits to repeat and leaves
 *   to the consumer to interpret; a vendor path attribute carries one value.
 *
 *   Parsing is fail-closed and follows the ABNF of sec. 2.3 and sec. 2.4 rather
 *   than a general URI reader: a character a component does not admit unencoded
 *   is refused, a truncated or non-hex escape is refused, an empty attribute
 *   between two delimiters is refused, a repeated attribute is refused wherever
 *   the RFC does not permit one, and the attributes the RFC writes as digits or
 *   as literal alternatives are read that way rather than through an escape. `id` is decoded to a `Buffer`, because it
 *   names bytes and not text. A URI carrying both `pin-source` and `pin-value`
 *   is refused, and so is a `module-path` that is not absolute, both of which
 *   sec. 2.4 asks a consumer to treat as invalid.
 *
 *   An attribute name and a `type` value are read whichever case they arrive in,
 *   RFC 5234 sec. 2.3 making an ABNF quoted literal case-insensitive, so
 *   `PIN-SOURCE` is the `pin-source` attribute and is held to the rules
 *   `pin-source` is held to rather than passing as vendor data. Writing produces
 *   the canonical form, which is what lets two URIs naming one object be compared
 *   as strings, and every rule parsing refuses writing refuses too, so the two
 *   directions cannot drift. This is a syntax, not a driver: nothing here loads a
 *   PKCS #11 module or talks to a token.
 *
 * @card
 *   `parseUri` / `formatUri` over the RFC 7512 ABNF, fail-closed, with `id` as
 *   bytes and no module loading.
 */

var frameworkError = require("./framework-error");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");

var _create = intrinsic.create;
var _assign = intrinsic.assign;
var _hasOwn = intrinsic.hasOwn;
var _keys = intrinsic.keys;
var _forEach = intrinsic.forEach;
var _push = intrinsic.push;
var _join = intrinsic.join;
var _String = intrinsic.String;
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _fromCharCode = String.fromCharCode;

var Pkcs11Error = frameworkError.Pkcs11Error;

function _err(code, message, cause) { return new Pkcs11Error(code, message, cause); }

var SCHEME = "pkcs11:";

/** @internal The RFC 7512 sec. 2.3 / sec. 2.4 attribute tables, keyed by the name on the wire.
 *  `field` is the name the parsed record carries, `kind` how the value is read. A vendor
 *  attribute matches neither table and is kept under its own wire name. */
var PATH_ATTRS = _assign(_create(null), {
  "token": { field: "token", kind: "text" },
  "manufacturer": { field: "manufacturer", kind: "text" },
  "serial": { field: "serial", kind: "text" },
  "model": { field: "model", kind: "text" },
  "library-manufacturer": { field: "libraryManufacturer", kind: "text" },
  "library-description": { field: "libraryDescription", kind: "text" },
  "library-version": { field: "libraryVersion", kind: "version" },
  "object": { field: "object", kind: "text" },
  "type": { field: "type", kind: "type" },
  "id": { field: "id", kind: "bytes" },
  "slot-manufacturer": { field: "slotManufacturer", kind: "text" },
  "slot-description": { field: "slotDescription", kind: "text" },
  "slot-id": { field: "slotId", kind: "number" },
});
var QUERY_ATTRS = _assign(_create(null), {
  "pin-source": { field: "pinSource", kind: "text" },
  "pin-value": { field: "pinValue", kind: "text" },
  "module-name": { field: "moduleName", kind: "text" },
  "module-path": { field: "modulePath", kind: "path" },
});
var OBJECT_TYPES = _assign(_create(null), {
  "public": 1, "private": 1, "cert": 1, "secret-key": 1, "data": 1,
});

/** @internal The wire name each record field writes back to, derived from the tables above so the
 *  two directions cannot name different attributes. */
function _byField(table) {
  var out = _create(null);
  _forEach(_keys(table), function (wire) { out[table[wire].field] = _assign(_create(null), { wire: wire, kind: table[wire].kind }); });
  return out;
}
var PATH_BY_FIELD = _byField(PATH_ATTRS);
var QUERY_BY_FIELD = _byField(QUERY_ATTRS);

/** @internal `unreserved` of RFC 3986 sec. 2.3: ALPHA / DIGIT / "-" / "." / "_" / "~". */
function _isUnreserved(c) {
  return guard.encoding.isAlphanumericByte(c) || c === 0x2d || c === 0x2e || c === 0x5f || c === 0x7e;
}
/** @internal `pk11-res-avail` of sec. 2.3: the reserved characters both components admit unencoded. */
function _isResAvail(c) {
  return c === 0x3a || c === 0x5b || c === 0x5d || c === 0x40 || c === 0x21 || c === 0x24 ||
    c === 0x27 || c === 0x28 || c === 0x29 || c === 0x2a || c === 0x2b || c === 0x2c || c === 0x3d;
}
/** @internal `pk11-pchar` minus pct-encoded: the path admits "&" on top of the shared set. */
function _isPathChar(c) { return _isUnreserved(c) || _isResAvail(c) || c === 0x26; }
/** @internal `pk11-qchar` minus pct-encoded: the query admits "/", "?" and "|" instead. */
function _isQueryChar(c) { return _isUnreserved(c) || _isResAvail(c) || c === 0x2f || c === 0x3f || c === 0x7c; }

var _hexValue = guard.encoding.hexNibble;

/** @internal The ASCII fold, not the Unicode one. RFC 5234 sec. 2.3 makes a quoted literal
 *  case-insensitive over the US-ASCII the ABNF is written in, and `String.prototype.toLowerCase`
 *  folds further than that: U+212A KELVIN SIGN lowercases to "k", so folding before the grammar
 *  check would read a name carrying one as a standard attribute it is not. */
function _asciiLower(text) {
  var out = "";
  for (var i = 0; i < text.length; i++) {
    var c = _charCodeAt(text, i);
    out += _fromCharCode(c >= 0x41 && c <= 0x5a ? c + 32 : c);
  }
  return out;
}

var HEX = "0123456789ABCDEF";
function _pctEncodeByte(b) {
  return "%" + _fromCharCode(_charCodeAt(HEX, b >> 4)) + _fromCharCode(_charCodeAt(HEX, b & 0x0f));
}

/** @internal The octets a component's value encodes, with every escape decoded and every bare
 *  character held to the component's own set. A character outside that set is not a URI this
 *  toolkit reads: the ABNF admits it only percent-encoded, so accepting it would accept a string
 *  no conforming producer emits and no other consumer reads the same way. */
function _decodeOctets(text, isChar, what) {
  var out = intrinsic.bufferAlloc(text.length);
  var n = 0;
  for (var i = 0; i < text.length; i++) {
    var c = _charCodeAt(text, i);
    if (c === 0x25) {
      if (i + 2 >= text.length) throw _err("pkcs11/bad-escape", what + " ends in a truncated percent-escape");
      var hi = _hexValue(_charCodeAt(text, i + 1));
      var lo = _hexValue(_charCodeAt(text, i + 2));
      if (hi < 0 || lo < 0) throw _err("pkcs11/bad-escape", what + " carries a percent-escape that is not two hexadecimal digits");
      out[n++] = (hi << 4) | lo;
      i += 2;
      continue;
    }
    if (!isChar(c)) {
      throw _err("pkcs11/bad-uri", what + " carries a character this URI component admits only percent-encoded (RFC 7512 sec. 2.3, sec. 2.4)");
    }
    out[n++] = c;
  }
  return intrinsic.subarray(out, 0, n);
}

/** @internal A value read as text is UTF-8, per sec. 2.3. A byte run that is not valid UTF-8 is
 *  refused rather than replaced, because a replacement character would compare equal to a
 *  different token's name. */
function _decodeText(text, isChar, what) {
  var octets = _decodeOctets(text, isChar, what);
  return guard.text.decode(octets, octets.length, Pkcs11Error, {
    charset: "utf-8", fatal: true, tooLarge: "pkcs11/bad-uri",
    badInput: "pkcs11/bad-input", badDecode: "pkcs11/bad-encoding", label: what,
  });
}

function _decimal(text, what) {
  if (text.length === 0) throw _err("pkcs11/bad-uri", what + " must be a decimal number (RFC 7512 sec. 2.3)");
  var value = 0;
  for (var i = 0; i < text.length; i++) {
    var c = _charCodeAt(text, i);
    if (c < 0x30 || c > 0x39) throw _err("pkcs11/bad-uri", what + " must be a decimal number (RFC 7512 sec. 2.3)");
    value = value * 10 + (c - 0x30);
    if (!intrinsic.isSafeInteger(value)) throw _err("pkcs11/bad-uri", what + " is larger than this toolkit reads as a number");
  }
  return value;
}

/** @internal sec. 2.3: "Both numbers are one byte in size; see the 'libraryVersion' member of the
 *  CK_INFO structure". A larger number names a version no token can report. */
var VERSION_MAX = 255;
function _versionPart(text, what) {
  var value = _decimal(text, "library-version");
  if (value > VERSION_MAX) {
    throw _err("pkcs11/bad-uri", "the library-version " + what + " is one byte, so it is 0 to 255 (RFC 7512 sec. 2.3), got " + text);
  }
  return value;
}

/** @internal `pk11-lib-ver` of sec. 2.3: the major is required, the minor defaults to zero. */
function _libraryVersion(text) {
  var dot = -1;
  for (var i = 0; i < text.length; i++) { if (_charCodeAt(text, i) === 0x2e) { dot = i; break; } }
  var out = _create(null);
  if (dot === -1) {
    out.major = _versionPart(text, "major");
    out.minor = 0;
    return out;
  }
  out.major = _versionPart(_strSlice(text, 0, dot), "major");
  out.minor = _versionPart(_strSlice(text, dot + 1), "minor");
  return out;
}

/** @internal `pk11-type`, `pk11-slot-id` and `pk11-lib-ver` are written in the ABNF as literal
 *  alternatives and digit runs, with no `pct-encoded` among them. Decoding an escape there and
 *  then reading the result would make `%70ublic` and `public` two spellings of one value, and
 *  sec. 2.6 asks a consumer to be able to compare two URIs as strings. */
/** @internal sec. 2.4 asks a consumer to refuse a module-path that is relative, because a relative
 *  one names a different shared object depending on where the process happens to be running. What
 *  counts as absolute is the platform's answer rather than the RFC's, and this toolkit runs on
 *  every platform Node does: a leading separator, a drive letter followed by one, and a UNC root
 *  are the three forms. */
function _isAbsolutePath(text) {
  var first = _charCodeAt(text, 0);
  if (first === 0x2f || first === 0x5c) return true;
  var isDriveLetter = (first >= 0x41 && first <= 0x5a) || (first >= 0x61 && first <= 0x7a);
  if (!isDriveLetter || _charCodeAt(text, 1) !== 0x3a) return false;
  var third = _charCodeAt(text, 2);
  return third === 0x2f || third === 0x5c;
}

function _assertNoEscape(raw, wire) {
  for (var i = 0; i < raw.length; i++) {
    if (_charCodeAt(raw, i) === 0x25) {
      throw _err("pkcs11/bad-uri", "the " + wire + " attribute is written out rather than percent-encoded (RFC 7512 sec. 2.3)");
    }
  }
  return raw;
}

function _readValue(spec, raw, isChar, wire) {
  if (spec.kind === "bytes") return _decodeOctets(raw, isChar, "the " + wire + " attribute");
  if (spec.kind === "number") return _decimal(_assertNoEscape(raw, wire), wire);
  if (spec.kind === "version") return _libraryVersion(_assertNoEscape(raw, wire));
  if (spec.kind === "type") {
    /** @internal RFC 5234 sec. 2.3 makes an ABNF quoted literal case-insensitive, and sec. 2.6
     *  asks for comparison after case normalization, so the spelling is read either way and
     *  carried in one form. */
    var named = _asciiLower(_assertNoEscape(raw, wire));
    if (OBJECT_TYPES[named] !== 1) {
      throw _err("pkcs11/bad-uri", "the type attribute is one of public, private, cert, secret-key or data (RFC 7512 sec. 2.3), got " + intrinsic.stringify(raw));
    }
    return named;
  }
  var text = _decodeText(raw, isChar, "the " + wire + " attribute");
  if (spec.kind === "path" && !_isAbsolutePath(text)) {
    throw _err("pkcs11/relative-module-path", "a module-path with a relative path is refused (RFC 7512 sec. 2.4)");
  }
  return text;
}

/** @internal `pk11-v-attr-nm-char` of sec. 2.3, asked once so reading and writing hold a vendor
 *  name to the same rule. A name the component's own table owns is refused as a vendor name, and
 *  a name carrying a delimiter is refused outright: written out, it would put a standard attribute
 *  into the URI that the caller never named and that neither component's checks ever saw. */
function _assertVendorName(wire, table, component, code) {
  if (wire.length === 0) throw _err(code, "a " + component + " attribute name must not be empty (RFC 7512 sec. 2.3)");
  for (var i = 0; i < wire.length; i++) {
    var c = _charCodeAt(wire, i);
    if (!(guard.encoding.isAlphanumericByte(c) || c === 0x2d || c === 0x5f)) {
      throw _err(code, "a vendor attribute name is letters, digits, hyphen and underscore (RFC 7512 sec. 2.3), got " + intrinsic.stringify(wire));
    }
  }
  if (_hasOwn(table, _asciiLower(wire))) {
    throw _err(code, "the " + component + " attribute " + wire + " is defined by RFC 7512 sec. 2.3, so it is named as itself rather than as a vendor attribute");
  }
}

/** @internal One `name=value` run. The name is a vendor name when neither table knows it, and a
 *  vendor name is held to `pk11-v-attr-nm-char` so a stray delimiter cannot pass as one. */
function _attribute(run, table, isChar, component, known, vendor, vendorRepeats) {
  if (run.length === 0) {
    throw _err("pkcs11/bad-uri", "a " + component + " component carries no empty attribute between its delimiters (RFC 7512 sec. 2.3)");
  }
  var eq = -1;
  for (var i = 0; i < run.length; i++) { if (_charCodeAt(run, i) === 0x3d) { eq = i; break; } }
  if (eq === -1) throw _err("pkcs11/bad-uri", "every " + component + " attribute is name=value (RFC 7512 sec. 2.3), got " + intrinsic.stringify(run));
  /** @internal RFC 7512 writes each attribute name as an ABNF quoted literal, which RFC 5234
   *  sec. 2.3 makes case-insensitive, so the name is matched in one case. Matching it as written
   *  would read `PIN-SOURCE` as a vendor attribute and let it past the rules pin-source is held
   *  to, which is the opposite of what those rules are for. */
  var wire = _asciiLower(_strSlice(run, 0, eq));
  var raw = _strSlice(run, eq + 1);
  var spec = _hasOwn(table, wire) ? table[wire] : null;
  if (spec) {
    if (_hasOwn(known, spec.field)) {
      throw _err("pkcs11/duplicate-attribute", "the " + wire + " attribute appears more than once (RFC 7512 sec. 2.3)");
    }
    known[spec.field] = _readValue(spec, raw, isChar, wire);
    return;
  }
  _assertVendorName(wire, table, component, "pkcs11/bad-uri");
  var text = _decodeText(raw, isChar, "the " + wire + " attribute");
  /** @internal sec. 2.4: "Aside from the query attributes defined in this document, duplicate
   *  (vendor) attributes MAY be present in the URI query component". The path admits none at all
   *  (sec. 2.3), which is why the query carries its vendor values as a list and the path does not. */
  if (!vendorRepeats) {
    if (_hasOwn(vendor, wire)) {
      throw _err("pkcs11/duplicate-attribute", "the " + wire + " attribute appears more than once (RFC 7512 sec. 2.3)");
    }
    vendor[wire] = text;
    return;
  }
  if (!_hasOwn(vendor, wire)) vendor[wire] = [];
  _push(vendor[wire], text);
}

function _split(text, delimiter, into) {
  var start = 0;
  for (var i = 0; i < text.length; i++) {
    if (_charCodeAt(text, i) === delimiter) { _push(into, _strSlice(text, start, i)); start = i + 1; }
  }
  _push(into, _strSlice(text, start));
  return into;
}

function _assertPinExclusive(query) {
  if (query.pinSource != null && query.pinValue != null) {
    throw _err("pkcs11/conflicting-pin", "a URI carrying both pin-source and pin-value is refused (RFC 7512 sec. 2.4)");
  }
}

/**
 * @primitive  pki.pkcs11.parseUri
 * @signature  pki.pkcs11.parseUri(uri) -> parsed
 * @since      0.8.7
 * @status     stable
 * @spec       RFC 7512
 * @related    pki.pkcs11.formatUri
 *
 * Read an RFC 7512 PKCS #11 URI. Returns `{ path, vendorPath, query, vendorQuery }`,
 * each a prototype-less record, so a computed read answers from the URI and never from
 * `Object.prototype`. `path.id` is a `Buffer`, since the attribute names bytes;
 * `path.slotId` and `path.libraryVersion` (`{ major, minor }`) are numbers. A
 * `vendorQuery` attribute carries a list of its values, which sec. 2.4 permits to repeat;
 * a `vendorPath` attribute carries one value.
 *
 * Fail-closed against the ABNF rather than a general URI reader: a character the
 * component admits only percent-encoded, a truncated or non-hex escape, a value that is
 * not valid UTF-8, an empty attribute between two delimiters, a repeated attribute the
 * RFC does not permit to repeat, a percent-escape inside `type`, `slot-id` or
 * `library-version`, a `type` outside the five
 * the RFC enumerates, a `library-version` component above 255, a URI carrying both
 * `pin-source` and `pin-value`, and a `module-path` that is not absolute are each refused
 * with their own `pkcs11/*` code. An attribute name is matched case-insensitively, so a
 * standard attribute cannot arrive spelled differently and pass as vendor data.
 *
 * @example
 *   var u = pki.pkcs11.parseUri("pkcs11:token=My%20Token;object=signing-key;type=private?module-name=softhsm2");
 *   u.path.token;         // "My Token"
 *   u.path.type;          // "private"
 *   u.query.moduleName;   // "softhsm2"
 */
function parseUri(uri) {
  if (typeof uri !== "string") {
    throw _err("pkcs11/bad-input", "a PKCS #11 URI must be a string, got " + guard.text.showValue(uri));
  }
  var head = _strSlice(uri, 0, SCHEME.length);
  if (_asciiLower(head) !== SCHEME) {
    throw _err("pkcs11/bad-uri", "a PKCS #11 URI begins with the pkcs11: scheme (RFC 7512 sec. 2.1)");
  }
  var rest = _strSlice(uri, SCHEME.length);
  var mark = -1;
  for (var i = 0; i < rest.length; i++) { if (_charCodeAt(rest, i) === 0x3f) { mark = i; break; } }
  var pathText = mark === -1 ? rest : _strSlice(rest, 0, mark);
  var queryText = mark === -1 ? "" : _strSlice(rest, mark + 1);

  var path = _create(null), vendorPath = _create(null);
  var query = _create(null), vendorQuery = _create(null);
  /** @internal `pk11-path` and `pk11-query` are each optional as a whole, and only as a whole:
   *  between two delimiters the ABNF requires an attribute, so an empty run there is a refusal
   *  rather than something to skip past. */
  if (pathText.length) {
    _forEach(_split(pathText, 0x3b, []), function (run) {
      _attribute(run, PATH_ATTRS, _isPathChar, "path", path, vendorPath);
    });
  }
  if (queryText.length) {
    _forEach(_split(queryText, 0x26, []), function (run) {
      _attribute(run, QUERY_ATTRS, _isQueryChar, "query", query, vendorQuery, true);
    });
  }
  _assertPinExclusive(query);

  var out = _create(null);
  out.path = path;
  out.vendorPath = vendorPath;
  out.query = query;
  out.vendorQuery = vendorQuery;
  return out;
}

/** @internal A caller's string is encoded as the UTF-8 sec. 2.3 asks for. An unpaired surrogate
 *  has no UTF-8 form, and writing the replacement character for it would put a different name in
 *  the URI than the caller asked for, so it is refused instead. */
function _encodeText(text, isChar, what) {
  var octets = intrinsic.bufferFrom(text, "utf8");
  if (intrinsic.bufToString(octets, "utf8") !== text) {
    throw _err("pkcs11/bad-input", what + " carries a character with no UTF-8 form (an unpaired surrogate)");
  }
  var parts = [];
  for (var i = 0; i < octets.length; i++) {
    var b = octets[i];
    _push(parts, isChar(b) ? _fromCharCode(b) : _pctEncodeByte(b));
  }
  return _join(parts, "");
}

/** @internal sec. 2.3 asks for `id` to be percent-encoded whole rather than read as text, since it
 *  carries bytes, and for the hexadecimal to be uppercase so two spellings of one identifier
 *  compare equal. */
function _encodeBytes(value) {
  var octets = guard.bytes.snapshotSource(value, Pkcs11Error, "pkcs11/bad-input", "the id attribute");
  var parts = [];
  for (var i = 0; i < octets.length; i++) _push(parts, _pctEncodeByte(octets[i]));
  return _join(parts, "");
}

function _writableDecimal(value) {
  return intrinsic.isSafeInteger(value) && value >= 0;
}

/** @internal A text attribute carries what the URI carries, which is a string, and `parseUri`
 *  answers with one. Coercing anything else writes a value the caller never named: an object
 *  reaches the URI as its default string form and a list as its members joined with a comma,
 *  and both read back as one value. So the value is required to be a string rather than turned
 *  into one, which also settles the second question a coercion raises, since a string cannot
 *  answer differently between the check and the encoding. */
function _writableText(value, what) {
  if (typeof value !== "string") {
    throw _err("pkcs11/bad-input", what + " must be a string, got " + guard.text.showValue(value));
  }
  return value;
}

function _writeValue(kind, value, isChar, wire) {
  if (kind === "bytes") return _encodeBytes(value);
  /** @internal The bound is the one the reader applies, so nothing is written that reading it back
   *  would refuse: past the safe-integer range a number also stringifies in exponent notation,
   *  which `1*DIGIT` does not admit. */
  if (kind === "number") {
    if (!_writableDecimal(value)) {
      throw _err("pkcs11/bad-input", "the " + wire + " attribute must be a non-negative integer this toolkit reads back (RFC 7512 sec. 2.3)");
    }
    return _String(value);
  }
  if (kind === "version") {
    /** @internal Each member read ONCE, into the number the check and the URI both use. Read
     *  again per use, a getter could answer inside the range for the check and outside it for
     *  the string, which is the same "checked one value, wrote another" the component snapshot
     *  above closes one level up. */
    var pair = value != null && typeof value === "object" ? value : {};
    var major = pair.major;
    var minor = pair.minor;
    if (!_writableDecimal(major) || !_writableDecimal(minor) || major > VERSION_MAX || minor > VERSION_MAX) {
      throw _err("pkcs11/bad-input", "library-version is { major, minor }, each one byte and so 0 to 255 (RFC 7512 sec. 2.3)");
    }
    return _String(major) + "." + _String(minor);
  }
  var text = _writableText(value, "the " + wire + " attribute");
  if (kind === "type") {
    var named = _asciiLower(text);
    if (OBJECT_TYPES[named] !== 1) {
      throw _err("pkcs11/bad-input", "the type attribute is one of public, private, cert, secret-key or data (RFC 7512 sec. 2.3), got " + intrinsic.stringify(text));
    }
    return named;
  }
  if (kind === "path" && !_isAbsolutePath(text)) {
    throw _err("pkcs11/relative-module-path", "a module-path with a relative path is refused (RFC 7512 sec. 2.4)");
  }
  return _encodeText(text, isChar, "the " + wire + " attribute");
}

/** @internal One read per known field, into a record of this module's own. */
function _snapshotComponent(record, byField, component) {
  if (record == null) return _create(null);
  if (typeof record !== "object") {
    throw _err("pkcs11/bad-input", "the " + component + " component must be an object of attributes");
  }
  guard.identifier.assertKnownKeys(record, byField, _err, "pkcs11/bad-input",
    "the " + component + " component has an unknown attribute ");
  return guard.identifier.snapshotOptions(record, byField);
}

/** @internal One read per own name, since a vendor component names its own attributes. */
function _snapshotVendor(record, component) {
  var out = _create(null);
  if (record == null) return out;
  if (typeof record !== "object") {
    throw _err("pkcs11/bad-input", "the " + component + " vendor attributes must be an object");
  }
  /** @internal A list is copied too, so a value appended to it while another component is being
   *  written cannot reach the URI. */
  _forEach(_keys(record), function (name) {
    var value = record[name];
    if (!intrinsic.isArray(value)) { out[name] = value; return; }
    var copy = [];
    for (var i = 0; i < value.length; i++) _push(copy, value[i]);
    out[name] = copy;
  });
  return out;
}

function _writeComponent(record, byField, isChar, component, parts) {
  _forEach(_keys(byField), function (field) {
    if (!_hasOwn(record, field) || record[field] == null) return;
    var spec = byField[field];
    _push(parts, spec.wire + "=" + _writeValue(spec.kind, record[field], isChar, spec.wire));
  });
}

function _writeVendor(record, table, isChar, component, parts, repeats) {
  /** @internal Lowercased and ordered by name, because the canonical form is what lets two URIs
   *  naming one object be compared as strings: the reader matches a name in one case, and the
   *  order a caller happened to build the record in is not part of what the URI says. Two names
   *  that differ only in case are the one attribute twice, which is what the reader would call
   *  them. A name's own values keep the order they were given, since sec. 2.4 leaves what a
   *  repeated vendor attribute means to the consumer and the order may be part of it. The
   *  standard attributes are already in the order the RFC lists them.
   *
   *  A name in this record IS an attribute the caller asked for, the standard components being
   *  where a field is named in advance and left unset. So a name carrying nothing is refused
   *  rather than skipped: writing the URI without it answers a different URI than the one that
   *  was asked for, and says so nowhere. */
  var written = _create(null), names = [];
  _forEach(_keys(record), function (given) {
    _assertVendorName(given, table, component, "pkcs11/bad-input");
    var wire = _asciiLower(given);
    if (_hasOwn(written, wire)) {
      throw _err("pkcs11/duplicate-attribute", "the " + wire + " attribute appears more than once (RFC 7512 sec. 2.3)");
    }
    var value = record[given];
    if (value == null) {
      throw _err("pkcs11/bad-input", "the " + wire + " attribute is named with no value; remove the name or give it one");
    }
    if (repeats) {
      if (!intrinsic.isArray(value)) {
        throw _err("pkcs11/bad-input", "a vendor query attribute carries a list of values, since RFC 7512 sec. 2.4 permits it to repeat; got " + guard.text.showValue(value));
      }
      if (value.length === 0) {
        throw _err("pkcs11/bad-input", "the " + wire + " attribute is named with an empty list; remove the name or give it a value");
      }
      written[wire] = _mapValues(value, wire, isChar);
    } else {
      written[wire] = [_encodeText(_writableText(value, "the " + wire + " attribute"), isChar, "the " + wire + " attribute")];
    }
    _push(names, wire);
  });
  _forEach(intrinsic.sort(names), function (wire) {
    _forEach(written[wire], function (encoded) { _push(parts, wire + "=" + encoded); });
  });
}

function _mapValues(list, wire, isChar) {
  var out = [];
  for (var i = 0; i < list.length; i++) {
    if (list[i] == null) {
      throw _err("pkcs11/bad-input", "a vendor query attribute's list carries no missing value; the " + wire + " attribute has one");
    }
    _push(out, _encodeText(_writableText(list[i], "the " + wire + " attribute"), isChar, "the " + wire + " attribute"));
  }
  return out;
}

var KNOWN_RECORD_KEYS = _assign(_create(null), { path: 1, vendorPath: 1, query: 1, vendorQuery: 1 });

/**
 * @primitive  pki.pkcs11.formatUri
 * @signature  pki.pkcs11.formatUri(record) -> string
 * @since      0.8.7
 * @status     stable
 * @spec       RFC 7512
 * @related    pki.pkcs11.parseUri
 *
 * Write an RFC 7512 PKCS #11 URI from `{ path, vendorPath, query, vendorQuery }`, the
 * shape `parseUri` returns. What comes out is the canonical form rather than the input
 * byte for byte: attributes are emitted in the order the RFC lists them, each value is
 * percent-encoded to what its own component admits unencoded, `id` is encoded whole with
 * uppercase hexadecimal, `slot-id` drops leading zeros and `library-version` states its
 * minor. That is what makes two URIs naming one object compare equal as strings, which
 * sec. 2.6 asks of a consumer, and the form is stable: writing it again changes nothing.
 *
 * The rules `parseUri` refuses are refused here too rather than written out: a `type`
 * outside the five the RFC enumerates, both `pin-source` and `pin-value`, a relative
 * `module-path`, and a number this toolkit would not read back. An attribute the RFC does
 * not define is named in the refusal, so a misspelled field is a refusal rather than a
 * silently dropped one; put a vendor attribute under `vendorPath` or `vendorQuery`, where
 * its name is held to the vendor grammar and refused if a standard attribute owns it, so
 * a name carrying a delimiter cannot put an attribute into the URI the caller never named.
 * A `vendorQuery` attribute is given as a list and its values are written in the order the
 * list gives them, which is the shape `parseUri` returns; a `vendorPath` attribute is
 * given one value. A vendor name given no value, or given an empty list, is refused as
 * well, since the name is the attribute the caller asked for.
 *
 * @example
 *   pki.pkcs11.formatUri({ path: { token: "My Token", type: "private" }, query: { moduleName: "softhsm2" } });
 *   // -> "pkcs11:token=My%20Token;type=private?module-name=softhsm2"
 */
function formatUri(record) {
  if (record == null || typeof record !== "object" || guard.bytes.isByteSource(record)) {
    throw _err("pkcs11/bad-input", "a PKCS #11 URI is written from { path, vendorPath, query, vendorQuery }");
  }
  guard.identifier.assertKnownKeys(record, KNOWN_RECORD_KEYS, _err, "pkcs11/bad-input",
    "a PKCS #11 URI record has an unknown field ");

  /** @internal Every component is snapshotted BEFORE anything is written. A getter on one
   *  component that ran while another was being written could otherwise add an attribute to a
   *  component written after it, past a check that had already passed. What is checked is what
   *  is written. */
  var path = _snapshotComponent(record.path, PATH_BY_FIELD, "path");
  var query = _snapshotComponent(record.query, QUERY_BY_FIELD, "query");
  var vendorPath = _snapshotVendor(record.vendorPath, "path");
  var vendorQuery = _snapshotVendor(record.vendorQuery, "query");
  _assertPinExclusive(query);

  var pathParts = [], queryParts = [];
  _writeComponent(path, PATH_BY_FIELD, _isPathChar, "path", pathParts);
  _writeVendor(vendorPath, PATH_ATTRS, _isPathChar, "path", pathParts);
  _writeComponent(query, QUERY_BY_FIELD, _isQueryChar, "query", queryParts);
  _writeVendor(vendorQuery, QUERY_ATTRS, _isQueryChar, "query", queryParts, true);

  var out = SCHEME + _join(pathParts, ";");
  if (queryParts.length) out += "?" + _join(queryParts, "&");
  return out;
}

module.exports = intrinsic.freeze({
  parseUri: parseUri,
  formatUri: formatUri,
});
