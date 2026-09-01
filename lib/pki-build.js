// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var asn1 = require("./asn1-der");
var schema = require("./schema-engine");
var compositeSig = require("./composite-sig");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _isArray = intrinsic.isArray;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferEquals = intrinsic.bufferEquals;
var oid = require("./oid");
var ipUtils = require("./ip-utils");
var _packIpLiteral = ipUtils.packIpLiteral;
var nodeCrypto = require("crypto");
var _keyEquals = intrinsic.uncurry(nodeCrypto.KeyObject.prototype.equals);
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _stringIndexOf = intrinsic.stringIndexOf;
var _stringLastIndexOf = intrinsic.uncurry(String.prototype.lastIndexOf);
var _sliceStr = intrinsic.uncurry(String.prototype.slice);
var _String = intrinsic.String;
var _objectKeys = intrinsic.keys;
var _isBufferChk = intrinsic.isBuffer;
var _stringify = intrinsic.stringify;

function _isAlphaCode(c) { return (c >= 65 && c <= 90) || (c >= 97 && c <= 122); }
function _isDigitCode(c) { return c >= 48 && c <= 57; }
function _isHexCode(c) { return (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70); }

function _isUnreserved(c) { return _isAlphaCode(c) || _isDigitCode(c) || c === 45 || c === 46 || c === 95 || c === 126; }
function _isSubDelim(c) {
  switch (c) {
    case 33: case 36: case 38: case 39: case 40: case 41: case 42: case 43: case 44: case 59: case 61: return true;
    default: return false;
  }
}
function _isUserinfoByte(c) { return _isUnreserved(c) || _isSubDelim(c) || c === 58; }
function _isUriByte(c) {
  return _isUnreserved(c) || _isSubDelim(c) || c === 58 || c === 47 || c === 63 || c === 35 || c === 64;
}

function _isAtextByte(c) {
  if (_isAlphaCode(c) || _isDigitCode(c)) return true;
  switch (c) {
    case 33: case 35: case 36: case 37: case 38: case 39:
    case 42: case 43: case 45: case 47: case 61: case 63:
    case 94: case 95: case 96: case 123: case 124: case 125: case 126:
      return true;
    default: return false;
  }
}

function _looksLikeIPv4Shape(s) {
  var n = s.length, i, c, sawDot = false, atomEmpty = true;
  if (n === 0) return false;
  for (i = 0; i < n; i += 1) {
    c = _charCodeAt(s, i);
    if (c === 46) { if (atomEmpty) return false; sawDot = true; atomEmpty = true; }
    else if (_isDigitCode(c)) { atomEmpty = false; }
    else return false;
  }
  return sawDot && !atomEmpty;
}

function _componentBytesOk(s, from, to, byteOk) {
  var i = from, c;
  while (i < to) {
    c = _charCodeAt(s, i);
    if (c === 37) {
      if (i + 2 >= to || !_isHexCode(_charCodeAt(s, i + 1)) || !_isHexCode(_charCodeAt(s, i + 2))) return false;
      i += 3;
    } else if (byteOk(c)) { i += 1; }
    else return false;
  }
  return true;
}

function _validUriHost(s, from, to) {
  if (to <= from) return false;
  var host = _sliceStr(s, from, to), len = host.length;
  if (_looksLikeIPv4Shape(host)) return _packIpLiteral(host) !== null;
  var end = _charCodeAt(host, len - 1) === 46 ? len - 1 : len;
  if (end > 253) return false;
  var firstDot = _stringIndexOf(host, ".", 0);
  if (firstDot === -1 || firstDot >= end) return false;
  return _labelsValid(host, 0, len, _isHostLabelRange, true);
}

function _validUriIp6Host(s, from, to) {
  if (to <= from) return false;
  var packed = _packIpLiteral(_sliceStr(s, from, to));
  return packed !== null && intrinsic.sizeOf(packed) === 16;
}

function _validUriAuthority(s, from, to) {
  var i, c, at = -1;
  for (i = from; i < to; i += 1) {
    c = _charCodeAt(s, i);
    if (c === 64) { if (at !== -1) return false; at = i; }
  }
  var hostStart = at === -1 ? from : at + 1;
  if (at !== -1 && !_componentBytesOk(s, from, at, _isUserinfoByte)) return false;
  if (hostStart < to && _charCodeAt(s, hostStart) === 91) {
    var close = -1;
    for (i = hostStart + 1; i < to; i += 1) { if (_charCodeAt(s, i) === 93) { close = i; break; } }
    if (close === -1) return false;
    if (!_validUriIp6Host(s, hostStart + 1, close)) return false;
    var after = close + 1;
    if (after === to) return true;
    if (_charCodeAt(s, after) !== 58) return false;
    for (i = after + 1; i < to; i += 1) { if (!_isDigitCode(_charCodeAt(s, i))) return false; }
    return true;
  }
  var colon = -1;
  for (i = hostStart; i < to; i += 1) { if (_charCodeAt(s, i) === 58) { colon = i; break; } }
  var hostEnd = colon === -1 ? to : colon;
  if (!_validUriHost(s, hostStart, hostEnd)) return false;
  if (colon !== -1) {
    for (i = colon + 1; i < to; i += 1) { if (!_isDigitCode(_charCodeAt(s, i))) return false; }
  }
  return true;
}

function _looksLikeUri(s) {
  var n = s.length, i, c;
  if (n === 0 || !_isAlphaCode(_charCodeAt(s, 0))) return false;
  i = 1;
  while (i < n) {
    c = _charCodeAt(s, i);
    if (_isAlphaCode(c) || _isDigitCode(c) || c === 43 || c === 45 || c === 46) i += 1;
    else break;
  }
  if (i + 3 > n || _charCodeAt(s, i) !== 58 || _charCodeAt(s, i + 1) !== 47 || _charCodeAt(s, i + 2) !== 47) return false;
  i += 3;
  var authStart = i, authEnd = n;
  for (; i < n; i += 1) { c = _charCodeAt(s, i); if (c === 47 || c === 63 || c === 35) { authEnd = i; break; } }
  if (authEnd === authStart) return false;
  if (!_validUriAuthority(s, authStart, authEnd)) return false;
  var sawHash = false;
  i = authEnd;
  while (i < n) {
    c = _charCodeAt(s, i);
    if (c === 37) {
      if (i + 2 >= n || !_isHexCode(_charCodeAt(s, i + 1)) || !_isHexCode(_charCodeAt(s, i + 2))) return false;
      i += 3;
      continue;
    }
    if (c === 35) { if (sawHash) return false; sawHash = true; }
    if (!_isUriByte(c)) return false;
    i += 1;
  }
  return true;
}

function _isDnsLabelRange(s, from, to) {
  var len = to - from, i, c;
  if (len < 1 || len > 63) return false;
  for (i = from; i < to; i += 1) {
    c = _charCodeAt(s, i);
    if (_isAlphaCode(c) || _isDigitCode(c)) continue;
    if (i === to - 1) return false;
    if (c === 95) continue;
    if (c === 45 && i !== from) continue;
    return false;
  }
  return true;
}

function _isHostLabelRange(s, from, to) {
  var len = to - from, i, c, edge;
  if (len < 1 || len > 63) return false;
  for (i = from; i < to; i += 1) {
    c = _charCodeAt(s, i);
    edge = (i === from || i === to - 1);
    if (_isAlphaCode(c) || _isDigitCode(c)) continue;
    if (c === 45 && !edge) continue;
    return false;
  }
  return true;
}

function _labelsValid(s, from, to, labelFn, allowRootDot) {
  if (allowRootDot && to - from >= 1 && _charCodeAt(s, to - 1) === 46) to -= 1;
  if (to <= from) return false;
  var start = from, dot;
  for (;;) {
    dot = _stringIndexOf(s, ".", start);
    var end = (dot === -1 || dot >= to) ? to : dot;
    if (!labelFn(s, start, end)) return false;
    if (end === to) return true;
    start = end + 1;
  }
}

function _looksLikeDnsName(s) {
  var n = s.length, start = 0;
  if (n < 1) return false;
  var end = _charCodeAt(s, n - 1) === 46 ? n - 1 : n;
  if (end < 1 || end > 253) return false;
  if (end >= 2 && _charCodeAt(s, 0) === 42 && _charCodeAt(s, 1) === 46) start = 2;
  if (start >= end) return false;
  return _labelsValid(s, start, n, _isDnsLabelRange, true);
}

function _looksLikeEmail(s) {
  if (s.length > 254) return false;
  var at = _stringIndexOf(s, "@", 0);
  if (at < 1 || at > 64 || _stringLastIndexOf(s, "@") !== at) return false;
  var i, c, atomEmpty = true;
  for (i = 0; i < at; i += 1) {
    c = _charCodeAt(s, i);
    if (c === 46) { if (atomEmpty) return false; atomEmpty = true; }
    else if (_isAtextByte(c)) { atomEmpty = false; }
    else return false;
  }
  if (atomEmpty) return false;
  var dStart = at + 1, dLen = s.length - dStart;
  if (dLen < 1 || dLen > 253 || _stringIndexOf(s, ".", dStart) === -1) return false;
  return _labelsValid(s, dStart, s.length, _isHostLabelRange, false);
}

function _isDottedOid(s) {
  var n = s.length, i, c, d0, arcs = 0;
  if (n < 3) return false;
  c = _charCodeAt(s, 0);
  if (c < 48 || c > 50) return false;
  i = 1;
  while (i < n) {
    if (_charCodeAt(s, i) !== 46) return false;
    i += 1;
    if (i >= n) return false;
    d0 = _charCodeAt(s, i);
    if (d0 === 48) { i += 1; }
    else if (d0 >= 49 && d0 <= 57) { i += 1; while (i < n && _isDigitCode(_charCodeAt(s, i))) i += 1; }
    else { return false; }
    arcs += 1;
  }
  return arcs >= 1;
}

var b = asn1.build;

var KU_BIT = {
  digitalSignature: 0, nonRepudiation: 1, contentCommitment: 1, keyEncipherment: 2,
  dataEncipherment: 3, keyAgreement: 4, keyCertSign: 5, cRLSign: 6, encipherOnly: 7, decipherOnly: 8,
};

function reqDenseArrayImpl(list, what, E, code) {
  if (!_isArray(list)) throw E(code, what + " must be an array");
  var n = list.length;
  var out = [];
  for (var i = 0; i < n; i++) {
    if (!intrinsic.hasOwn(list, i)) throw E(code, what + "[" + i + "] is missing (a sparse array is not allowed)");
    var v = list[i];
    if (v === undefined || v === null) throw E(code, what + "[" + i + "] is missing (a nullish array entry is not allowed)");
    intrinsic.defineProperty(out, i, { value: v, writable: true, enumerable: true, configurable: true });
  }
  return out;
}

function makeBuilder(ctx) {
  var ErrorClass = ctx.ErrorClass, O = ctx.O, NS = ctx.NS;
  var NAME_SCHEMA = ctx.NAME_SCHEMA, SPKI_SCHEMA = ctx.SPKI_SCHEMA;
  function E(kind, message, cause) { return new ErrorClass(ctx.prefix + "/" + kind, message, cause); }
  function code(kind) { return ctx.prefix + "/" + kind; }
  function rawErr(fullCode, message, cause) { return new ErrorClass(fullCode, message, cause); }

  function timeDer(date, which) {
    guard.time.assertValid(date, rawErr, code("bad-input"), which);
    var y = date.getUTCFullYear();
    return (y >= 1950 && y <= 2049) ? b.utcTime(date) : b.generalizedTime(date);
  }

  function atvString(attrName, value) {
    if (attrName === "countryName") {
      if (String(value).length !== 2) throw E("bad-name", "countryName must be a two-letter ISO 3166 code (PrintableString SIZE(2))");
      return b.printable(value);
    }
    if (attrName === "emailAddress") return b.ia5(value);
    return b.utf8(value);
  }
  function encodeAtv(attrName, value) {
    if (value == null || value === "") throw E("bad-name", "the " + attrName + " attribute value must be a non-empty string");
    var typeOid = O(attrName);
    if (typeOid == null) throw E("bad-name", "unknown distinguished-name attribute " + JSON.stringify(attrName));
    var valueTlv;
    try { valueTlv = atvString(attrName, value); }
    catch (e) { if (e instanceof ErrorClass) throw e; throw E("bad-name", "the " + attrName + " value has characters invalid for its string type", e); }
    return b.sequence([b.oid(typeOid), valueTlv]);
  }
  function encodeRdn(rdnSpec) {
    if (!rdnSpec || typeof rdnSpec !== "object" || Buffer.isBuffer(rdnSpec)) throw E("bad-name", "each RDN must be an object of { attributeName: value }");
    var keys = Object.keys(rdnSpec);
    if (!keys.length) throw E("bad-name", "an RDN must carry at least one attribute");
    return b.set(keys.map(function (k) { return encodeAtv(k, rdnSpec[k]); }));
  }
  function encodeName(spec) {
    if (guard.bytes.isByteSource(spec)) { var _nd = guard.bytes.snapshotSource(spec, ErrorClass, ctx.prefix + "/bad-name", "raw Name DER"); assertValidNameDer(_nd); return _nd; }
    if (typeof spec === "string") spec = [{ commonName: spec }];
    if (!_isArray(spec)) throw E("bad-name", "a name must be a string, an array of RDNs, or raw Name DER");
    return b.sequence(spec.map(encodeRdn));
  }
  function assertValidNameDer(der) {
    var node;
    try { node = asn1.decode(der); }
    catch (e) { throw E("bad-name", "the raw Name DER is not valid DER", e); }
    try { schema.walk(NAME_SCHEMA, node, NS); }
    catch (e) {
      if (e instanceof ErrorClass || (e && e.name === "Asn1Error")) throw e;
      throw E("bad-name", "the raw Name DER is not a well-formed distinguished name", e);
    }
  }
  function isEmptyName(nameDer) { return asn1.decode(nameDer).children.length === 0; }

  function ia5Content(s) {
    s = _String(s);
    for (var i = 0; i < s.length; i++) {
      if (_charCodeAt(s, i) > 0x7F) throw E("bad-input", "value requires 7-bit ASCII (IA5String): " + _stringify(s));
    }
    return _bufferFrom(s, "latin1");
  }
  function _classifyBareGeneralName(s) {
    if (_packIpLiteral(s) !== null) return { iPAddress: s };
    if (_looksLikeIPv4Shape(s)) {
      throw E("bad-input", "the bare GeneralName string " + _stringify(s) + " looks like an IPv4 address but is not a valid one; pass { iPAddress: ... } for an address or { dNSName: ... } for a name");
    }
    if (_looksLikeUri(s)) return { uniformResourceIdentifier: s };
    if (_looksLikeEmail(s)) return { rfc822Name: s };
    if (_looksLikeDnsName(s)) return { dNSName: s };
    var _qs = _stringify(s);
    throw E("bad-input", "cannot classify the bare GeneralName string " + _qs +
      " as a dNSName, rfc822Name, iPAddress, or URI; pass an explicit form object, e.g. { dNSName: " + _qs + " }");
  }
  function encodeGeneralName(entry) {
    if (typeof entry === "string") {
      if (entry === "") throw E("bad-input", "an empty GeneralName value is not permitted (RFC 5280 sec. 4.2.1.6)");
      entry = _classifyBareGeneralName(entry);
    }
    if (!entry || typeof entry !== "object" || _isBufferChk(entry)) throw E("bad-input", "a GeneralName must be an object with exactly one name form");
    var keys = _objectKeys(entry);
    if (keys.length !== 1) throw E("bad-input", "a GeneralName entry must have exactly one form, got " + keys.length);
    var k = keys[0], v = entry[k];
    if (v == null || v === "") throw E("bad-input", "an empty GeneralName value is not permitted (RFC 5280 sec. 4.2.1.6)");
    switch (k) {
      case "rfc822Name": return b.contextPrimitive(1, ia5Content(v));
      case "dNSName": return b.contextPrimitive(2, ia5Content(v));
      case "uniformResourceIdentifier": case "uri": return b.contextPrimitive(6, ia5Content(v));
      case "iPAddress":
        var ipBuf = v;
        if (typeof v === "string") {
          ipBuf = _packIpLiteral(v);
          if (ipBuf === null) throw E("bad-input", "iPAddress string is not a valid IPv4 or IPv6 literal: " + _stringify(v));
        }
        if (!_isBufferChk(ipBuf) || (ipBuf.length !== 4 && ipBuf.length !== 16)) throw E("bad-input", "iPAddress must be a 4- or 16-octet Buffer or an IPv4/IPv6 string");
        return b.contextPrimitive(7, ipBuf);
      case "directoryName": return b.explicit(4, encodeName(v));
      case "otherName":
        if (typeof v !== "object" || Buffer.isBuffer(v)) throw E("bad-input", "otherName must be an object { typeId, value }");
        if (typeof v.typeId !== "string" || !v.typeId) throw E("bad-input", "otherName requires a `typeId` OID string");
        if (!Buffer.isBuffer(v.value) || v.value.length === 0) {
          throw E("bad-input", "otherName requires a `value` Buffer holding one DER element");
        }
        guard.der.tlv(v.value, E, "bad-input", "otherName `value`");
        var typeIdDer;
        try { typeIdDer = b.oid(v.typeId); }
        catch (e) { throw E("bad-input", "invalid otherName type-id OID " + JSON.stringify(v.typeId) + " (violates the X.660 arc bounds)", e); }
        return b.contextConstructed(0, Buffer.concat([typeIdDer, b.explicit(0, v.value)]));
      default: throw E("bad-input", "unsupported GeneralName form " + JSON.stringify(k) + " (supported: rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, directoryName, otherName)");
    }
  }

  function extKeyUsage(names) {
    if (!_isArray(names) || !names.length) throw E("bad-input", "keyUsage must assert at least one bit (RFC 5280 sec. 4.2.1.3)");
    var positions = names.map(function (n) {
      var pos = KU_BIT[n];
      if (pos == null) throw E("bad-input", "unknown keyUsage bit " + JSON.stringify(n));
      return pos;
    });
    return b.namedBitString(positions);
  }
  function _resolveOid(n, label) {
    var dotted = O(n);
    if (dotted != null) return dotted;
    if (typeof n === "string" && _isDottedOid(n)) {
      try { b.oid(n); }
      catch (e) { throw E("bad-input", "invalid " + label + " OID " + JSON.stringify(n) + " (violates the X.660 arc bounds)", e); }
      return n;
    }
    throw E("bad-input", "unknown " + label + " " + JSON.stringify(n) + " (expected a registered name or a dotted-decimal OID)");
  }
  function extExtKeyUsage(names) {
    if (!_isArray(names) || !names.length) throw E("bad-input", "extendedKeyUsage must list at least one KeyPurposeId");
    return b.sequence(names.map(function (n) { return b.oid(_resolveOid(n, "extendedKeyUsage purpose")); }));
  }
  function validateBcSpec(bc) {
    if (bc.cA != null && typeof bc.cA !== "boolean") throw E("bad-input", "basicConstraints cA must be a boolean");
    if (bc.critical != null && typeof bc.critical !== "boolean") throw E("bad-input", "basicConstraints critical must be a boolean");
    if (bc.pathLen != null) pathLen(bc.pathLen);
    guard.identifier.assertKnownKeys(bc, BC_KEYS, E, "bad-input", "unknown basicConstraints field ");
  }
  function extBasicConstraints(spec) {
    var children = [];
    if (spec.cA === true) children.push(b.boolean(true));
    if (spec.pathLen != null) children.push(b.integer(pathLen(spec.pathLen)));
    return b.sequence(children);
  }
  function pathLen(v) {
    if (typeof v !== "number" || !isFinite(v) || v < 0 || (v | 0) !== v) throw E("bad-input", "basicConstraints pathLenConstraint must be a non-negative integer");
    return BigInt(v);
  }
  function extSki(keyid) { return b.octetString(keyid); }
  function extAki(keyid) { return b.sequence([b.contextPrimitive(0, keyid)]); }
  function encodeGeneralNames(entries, implicitTag) {
    if (!_isArray(entries) || !entries.length) throw E("bad-input", "a GeneralNames must carry at least one GeneralName");
    var members = entries.map(encodeGeneralName);
    if (implicitTag == null) return b.sequence(members);
    return b.contextConstructed(implicitTag, Buffer.concat(members));
  }
  function extSan(entries) { return encodeGeneralNames(entries); }
  function extCertPolicies(names) {
    if (!_isArray(names) || !names.length) throw E("bad-input", "certificatePolicies must list at least one policy OID");
    var seen = {};
    return b.sequence(names.map(function (n) {
      var pOid = _resolveOid(n, "certificate policy");
      if (seen[pOid]) throw E("bad-input", "duplicate certificate policy " + JSON.stringify(n) + " (RFC 5280 sec. 4.2.1.4)");
      seen[pOid] = true;
      return b.sequence([b.oid(pOid)]);
    }));
  }
  function ext(oidStr, critical, valueDer) {
    var children = [b.oid(oidStr)];
    if (critical) children.push(b.boolean(true));
    children.push(b.octetString(valueDer));
    return b.sequence(children);
  }

  function spkiKeyId(spkiDer) {
    var keyBytes = asn1.read.bitString(asn1.decode(spkiDer).children[1]).bytes;
    return nodeCrypto.createHash("sha1").update(keyBytes).digest();
  }
  function skiKeyId(val, spkiDer) {
    if (guard.bytes.isByteSource(val)) return guard.bytes.snapshotSource(val, ErrorClass, ctx.prefix + "/bad-input", "subjectKeyIdentifier");
    if (val === true) return spkiKeyId(spkiDer);
    throw E("bad-input", "subjectKeyIdentifier must be true (auto-derive) or a BufferSource key id");
  }

  function reqDer(v, what) {
    if (guard.bytes.isByteSource(v)) return guard.bytes.snapshotSource(v, ErrorClass, ctx.prefix + "/bad-input", what);
    throw E("bad-input", what + " must be a DER Buffer");
  }
  function reqDenseArray(list, what) { return reqDenseArrayImpl(list, what, rawErr, ctx.prefix + "/bad-input"); }
  function reqDerSequence(v, what) {
    var der = reqDer(v, what);
    if (der.length === 0 || der[0] !== 0x30) throw E("bad-input", what + " must be DER (a SEQUENCE), not PEM or other bytes");
    return der;
  }
  function assertValidSpki(spkiDer, what) {
    var node;
    try { node = asn1.decode(spkiDer); }
    catch (e) { throw E("bad-input", what + " is not valid DER", e); }
    try { schema.walk(SPKI_SCHEMA, node, NS); }
    catch (e) {
      if (e instanceof ErrorClass || (e && e.name === "Asn1Error")) throw e;
      throw E("bad-input", what + " is not a well-formed SubjectPublicKeyInfo", e);
    }
  }
  function assertValidExtension(der, idx) {
    var n;
    try { n = asn1.decode(der); }
    catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] is not valid DER", e); }
    if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length < 2 || n.children.length > 3) throw E("bad-input", "pre-encoded extension [" + idx + "] must be an Extension SEQUENCE { extnID, critical?, extnValue }");
    try { asn1.read.oid(n.children[0]); }
    catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] extnID is not an OBJECT IDENTIFIER", e); }
    if (n.children.length === 3) {
      var crit;
      try { crit = asn1.read.boolean(n.children[1]); }
      catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] critical must be a BOOLEAN", e); }
      if (crit !== true) throw E("bad-input", "pre-encoded extension [" + idx + "] critical=FALSE must be omitted (DER DEFAULT)");
    }
    var last = n.children[n.children.length - 1];
    if (last.tagNumber !== asn1.TAGS.OCTET_STRING || last.tagClass !== "universal") throw E("bad-input", "pre-encoded extension [" + idx + "] extnValue must be an OCTET STRING");
  }
  var BC_KEYS = { cA: 1, pathLen: 1, critical: 1 };
  var REQ_EXT_KEYS = {
    subjectAltName: 1, keyUsage: 1, keyUsageCritical: 1, extendedKeyUsage: 1, extendedKeyUsageCritical: 1,
    basicConstraints: 1, certificatePolicies: 1, certificatePoliciesCritical: 1, subjectKeyIdentifier: 1,
  };
  function requestedExtensions(extSpec, spki) {
    var EXT_DECODERS = ctx.EXT_DECODERS;
    if (_isArray(extSpec)) {
      if (!extSpec.length) throw E("bad-input", "the requested extensions list must carry at least one extension");
      var seen = {};
      return b.sequence(extSpec.map(function (e, i) {
        var der = reqDer(e, "extension");
        assertValidExtension(der, i);
        var n = asn1.decode(der);
        var extnId = asn1.read.oid(n.children[0]);
        if (seen[extnId]) throw E("bad-input", "duplicate requested extension " + extnId + " (RFC 5280 sec. 4.2)");
        seen[extnId] = true;
        var dec = EXT_DECODERS && EXT_DECODERS[extnId];
        if (dec) {
          try { dec(asn1.read.octetString(n.children[n.children.length - 1])); }
          catch (err) { if (err instanceof ErrorClass) throw err; throw E("bad-input", "pre-encoded " + (oid.name(extnId) || extnId) + " extension value is malformed", err); }
        }
        return b.raw(der);
      }));
    }
    if (!extSpec || typeof extSpec !== "object") throw E("bad-input", "requested extensions must be an object or an array of pre-encoded Extension DER");
    guard.identifier.assertKnownKeys(extSpec, REQ_EXT_KEYS, E, "bad-input", function (k) {
      return "unknown requested extension " + JSON.stringify(k) + "; pass a pre-encoded Extension DER via the array form for a custom extension";
    });
    var out = [];
    if (extSpec.subjectKeyIdentifier != null) {
      if (extSpec.subjectKeyIdentifier === true && spki == null) throw E("bad-input", "subjectKeyIdentifier auto-derive (true) requires the public key -- supply a Buffer key id, or include the public key");
      out.push(ext(O("subjectKeyIdentifier"), false, extSki(skiKeyId(extSpec.subjectKeyIdentifier, spki))));
    }
    if (extSpec.keyUsage != null) out.push(ext(O("keyUsage"), extSpec.keyUsageCritical !== false, extKeyUsage(extSpec.keyUsage)));
    if (extSpec.extendedKeyUsage != null) out.push(ext(O("extKeyUsage"), !!extSpec.extendedKeyUsageCritical, extExtKeyUsage(extSpec.extendedKeyUsage)));
    if (extSpec.basicConstraints != null) { validateBcSpec(extSpec.basicConstraints); out.push(ext(O("basicConstraints"), extSpec.basicConstraints.critical !== false, extBasicConstraints(extSpec.basicConstraints))); }
    if (extSpec.subjectAltName != null) out.push(ext(O("subjectAltName"), false, extSan(extSpec.subjectAltName)));
    if (extSpec.certificatePolicies != null) out.push(ext(O("certificatePolicies"), !!extSpec.certificatePoliciesCritical, extCertPolicies(extSpec.certificatePolicies)));
    if (!out.length) throw E("bad-input", "the requested extensions object must request at least one extension");
    return b.sequence(out);
  }

  function serialInteger(serial) {
    var v;
    if (serial == null) {
      var rnd = nodeCrypto.randomBytes(20);
      rnd[0] &= 0x7f;
      if (rnd[0] === 0) rnd[0] = 0x01;
      v = BigInt("0x" + rnd.toString("hex"));
    } else if (typeof serial === "bigint") { v = serial; }
    else if (typeof serial === "number") { if (!Number.isSafeInteger(serial)) throw E("bad-serial", "serialNumber number must be a safe integer (pass a BigInt, hex string, or Buffer for a value above 2^53-1)"); v = BigInt(serial); }
    else if (typeof serial === "string") { try { v = BigInt(serial); } catch (e) { throw E("bad-serial", "serialNumber string must be a decimal or 0x-hex integer", e); } }
    else if (guard.bytes.isByteSource(serial)) { var _sb = guard.bytes.source(serial, ErrorClass, ctx.prefix + "/bad-serial", "serialNumber"); v = _sb.length ? BigInt("0x" + _sb.toString("hex")) : 0n; }
    else { throw E("bad-serial", "serialNumber must be a BigInt, integer, hex string, or BufferSource"); }
    if (v <= 0n) throw E("bad-serial", "serialNumber must be a positive integer (RFC 5280 sec. 4.1.2.2)");
    var tlv = b.integer(v);
    if (asn1.decode(tlv).content.length > 20) throw E("bad-serial", "serialNumber must not exceed 20 octets (RFC 5280 sec. 4.1.2.2)");
    return tlv;
  }
  function certLikeFromSpki(spkiDer) {
    var spki = asn1.decode(spkiDer);
    if (!spki.children || !spki.children.length) throw E("bad-input", "the signing key SPKI is not a SubjectPublicKeyInfo");
    var alg = spki.children[0];
    var keyOid;
    try { keyOid = asn1.read.oid(alg.children[0]); }
    catch (e) { throw E("bad-input", "the signing key SPKI algorithm is not an OID", e); }
    return { subjectPublicKeyInfo: { algorithm: { oid: keyOid, parameters: alg.children.length > 1 ? alg.children[1].bytes : undefined } } };
  }

  function assertSignatureVerifies(preimage, sig, spki, scheme) {
    if (scheme.composite) {
      return compositeSig.compositeVerify(spki, sig, preimage, scheme.composite, ErrorClass, code("unsupported-algorithm"), code("bad-input")).then(function (r) {
        if (!r.ok) throw E("bad-input", "the composite signing key does not correspond to the public key -- the signature would not verify");
      });
    }
    var pub;
    try { pub = nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" }); }
    catch (e) { throw E("bad-input", "the public key could not be imported for the signature self-check", e); }
    var s = scheme.sign, ok;
    try {
      if (s.name === "ECDSA") ok = nodeCrypto.verify(scheme.digest, preimage, { key: pub, dsaEncoding: "der" }, sig);
      else if (s.name === "RSA-PSS") ok = nodeCrypto.verify(scheme.digest, preimage, { key: pub, padding: nodeCrypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: s.saltLength }, sig);
      else if (s.name === "RSASSA-PKCS1-v1_5") ok = nodeCrypto.verify(scheme.digest, preimage, pub, sig);
      // allow:eddsa-verify-without-loworder-gate -- a self-check that OUR just-produced signature verifies
      else ok = nodeCrypto.verify(null, preimage, pub, sig);
    } catch (e) { throw E("bad-input", "the signature self-check could not run against the public key", e); }
    if (!ok) throw E("bad-input", "the signing key does not correspond to the public key -- the signature would not verify");
  }

  function samePublicKey(spkiA, spkiB) {
    var a = _bufferFrom(spkiA), bb = _bufferFrom(spkiB);
    if (_bufferEquals(a, bb)) return true;
    var ka, kb;
    // allow:swallow-unverified an SPKI the key layer cannot import matches nothing, which is the
    try {
      ka = nodeCrypto.createPublicKey({ key: a, format: "der", type: "spki" });
      kb = nodeCrypto.createPublicKey({ key: bb, format: "der", type: "spki" });
    } catch (_e) { return false; }
    return _keyEquals(ka, kb) === true;
  }

  return {
    E: E, code: code, KU_BIT: KU_BIT,
    encodeName: encodeName, isEmptyName: isEmptyName, encodeGeneralName: encodeGeneralName,
    encodeGeneralNames: encodeGeneralNames, serialInteger: serialInteger, timeDer: timeDer,
    requestedExtensions: requestedExtensions,
    extKeyUsage: extKeyUsage, extExtKeyUsage: extExtKeyUsage, validateBcSpec: validateBcSpec,
    extBasicConstraints: extBasicConstraints, pathLen: pathLen, extSki: extSki, extAki: extAki,
    extSan: extSan, extCertPolicies: extCertPolicies, ext: ext,
    spkiKeyId: spkiKeyId, skiKeyId: skiKeyId,
    reqDer: reqDer, reqDenseArray: reqDenseArray, reqDerSequence: reqDerSequence, assertValidSpki: assertValidSpki, assertValidExtension: assertValidExtension,
    certLikeFromSpki: certLikeFromSpki, assertSignatureVerifies: assertSignatureVerifies,
    samePublicKey: samePublicKey,
  };
}

function tbsNameField(cert, which) {
  var tbs = asn1.decode(cert.tbsBytes);
  var hasVersion = tbs.children[0].tagClass === "context" && tbs.children[0].tagNumber === 0;
  return tbs.children[(hasVersion ? 1 : 0) + (which === "subject" ? 4 : 2)].bytes;
}

function tbsSerialNumber(cert) {
  var tbs = asn1.decode(cert.tbsBytes);
  var hasVersion = tbs.children[0].tagClass === "context" && tbs.children[0].tagNumber === 0;
  return asn1.read.integer(tbs.children[hasVersion ? 1 : 0]);
}

module.exports = intrinsic.freeze({ makeBuilder: makeBuilder, reqDenseArray: reqDenseArrayImpl, KU_BIT: KU_BIT, tbsNameField: tbsNameField, tbsSerialNumber: tbsSerialNumber });
