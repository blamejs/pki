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
var C = require("./constants");
var pkix = require("./schema-pkix");
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
var _mapIntrinsic = intrinsic.map;
var _bufferConcatIntrinsic = intrinsic.bufferConcat;
var OID_SKI = oid.byName("subjectKeyIdentifier");

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

function _validUriHost(s, from, to, singleLabel) {
  if (to <= from) return false;
  var host = _sliceStr(s, from, to), len = host.length;
  if (_looksLikeIPv4Shape(host)) return _packIpLiteral(host) !== null;
  var end = _charCodeAt(host, len - 1) === 46 ? len - 1 : len;
  if (end > 253) return false;
  var firstDot = _stringIndexOf(host, ".", 0);
  if (!singleLabel && (firstDot === -1 || firstDot >= end)) return false;
  return _labelsValid(host, 0, len, _isHostLabelRange, true);
}

function _validUriIp6Host(s, from, to) {
  if (to <= from) return false;
  var packed = _packIpLiteral(_sliceStr(s, from, to));
  return packed !== null && intrinsic.sizeOf(packed) === 16;
}

function _validUriAuthority(s, from, to, shape) {
  var i, c, at = -1;
  for (i = from; i < to; i += 1) {
    c = _charCodeAt(s, i);
    if (c === 64) { if (at !== -1 || !shape.userinfo) return false; at = i; }
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
  var portAlone = hostEnd === hostStart && colon !== -1 && shape.emptyHost;
  if (!portAlone && !_validUriHost(s, hostStart, hostEnd, shape.singleLabel)) return false;
  if (colon !== -1) {
    for (i = colon + 1; i < to; i += 1) { if (!_isDigitCode(_charCodeAt(s, i))) return false; }
  }
  return true;
}

/** @internal The shape a bare string must have to be read as a URI GeneralName without being told:
 *  a scheme, "//", an authority naming a multi-label host (a single label reads as a dNSName), and
 *  a well-formed remainder, a fragment included. */
var _URI_SHAPE = intrinsic.assign(intrinsic.create(null), { singleLabel: false, userinfo: true, emptyAuthority: false, emptyHost: false, queryNeedsPath: false, fragment: true });
/** @internal An HTTP URL (RFC 2616 sec. 3.2.2: "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]):
 *  no userinfo, a host of one label or many, a query only after an absolute path, no fragment. */
var _HTTP_URL_SHAPE = intrinsic.assign(intrinsic.create(null), { singleLabel: true, userinfo: false, emptyAuthority: false, emptyHost: false, queryNeedsPath: true, fragment: false });
/** @internal An LDAP URL (RFC 4516 sec. 2: scheme "://" [host [":" port]] ["/" dn ...]): no
 *  userinfo, a host of any label count that may be left out, with or without a port, and no
 *  fragment. The dn, attributes, scope and filter after the "/" are not parsed. */
var _LDAP_URL_SHAPE = intrinsic.assign(intrinsic.create(null), { singleLabel: true, userinfo: false, emptyAuthority: true, emptyHost: true, queryNeedsPath: false, fragment: false });

function _looksLikeUri(s) { return _uriShape(s, _URI_SHAPE); }
function isHttpUrl(s) { return typeof s === "string" && guard.name.uriSchemeIs(s, "http") && _uriShape(s, _HTTP_URL_SHAPE); }
function isLdapUrl(s) { return typeof s === "string" && guard.name.uriSchemeIs(s, "ldap") && _uriShape(s, _LDAP_URL_SHAPE); }

function _uriShape(s, shape) {
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
  if (authEnd === authStart) { if (!shape.emptyAuthority) return false; }
  else if (!_validUriAuthority(s, authStart, authEnd, shape)) return false;
  if (authEnd < n && shape.queryNeedsPath && _charCodeAt(s, authEnd) === 63) return false;
  var sawHash = false;
  i = authEnd;
  while (i < n) {
    c = _charCodeAt(s, i);
    if (c === 37) {
      if (i + 2 >= n || !_isHexCode(_charCodeAt(s, i + 1)) || !_isHexCode(_charCodeAt(s, i + 2))) return false;
      i += 3;
      continue;
    }
    if (c === 35) { if (sawHash || !shape.fragment) return false; sawHash = true; }
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

var KU_BIT = intrinsic.assign(intrinsic.create(null), {
  digitalSignature: 0, nonRepudiation: 1, contentCommitment: 1, keyEncipherment: 2,
  dataEncipherment: 3, keyAgreement: 4, keyCertSign: 5, cRLSign: 6, encipherOnly: 7, decipherOnly: 8,
});

/** @internal ReasonFlags bit positions (RFC 5280 sec. 4.2.1.13). These do NOT line up with the
 * CRLReason ENUMERATED of sec. 5.3.1, which leaves 7 unused and numbers privilegeWithdrawn 9 and
 * aACompromise 10; here they are bits 7 and 8. Bit 0 is named `unused` and is not settable, and
 * unspecified and removeFromCRL have no bit at all. */
var REASON_FLAG_BIT = intrinsic.assign(intrinsic.create(null), {
  keyCompromise: 1, cACompromise: 2, affiliationChanged: 3, superseded: 4,
  cessationOfOperation: 5, certificateHold: 6, privilegeWithdrawn: 7, aACompromise: 8,
});
var AIA_KEYS = intrinsic.assign(intrinsic.create(null), { accessMethod: 1, accessLocation: 1 });
var PC_KEYS = intrinsic.assign(intrinsic.create(null), { requireExplicitPolicy: 1, inhibitPolicyMapping: 1 });
var PM_KEYS = intrinsic.assign(intrinsic.create(null), { issuerDomainPolicy: 1, subjectDomainPolicy: 1 });
var QC_STATEMENT_KEYS = intrinsic.assign(intrinsic.create(null), { statementId: 1, info: 1 });
/** @internal The fields of a certificate-policy entry and of the qualifiers it may carry (RFC 5280
 *  sec. 4.2.1.4), and of the authority key identifier (sec. 4.2.1.1). A key outside its object's set
 *  is refused rather than ignored: a misspelled field would otherwise be dropped and the certificate
 *  would carry a policy or an identifier the caller did not write. */
var POLICY_ENTRY_KEYS = intrinsic.assign(intrinsic.create(null), { oid: 1, cps: 1, userNotice: 1 });
var USER_NOTICE_KEYS = intrinsic.assign(intrinsic.create(null), { noticeRef: 1, explicitText: 1 });
var NOTICE_REF_KEYS = intrinsic.assign(intrinsic.create(null), { organization: 1, noticeNumbers: 1 });
var AKI_KEYS = intrinsic.assign(intrinsic.create(null), { keyIdentifier: 1, authorityCertIssuer: 1, authorityCertSerialNumber: 1 });
/** @internal The fields of the Active Directory Certificate Services enrollment extensions. These
 *  are proprietary, so the toolkit's own readers in schema-pkix define the shape the builder emits. */
var MS_TEMPLATE_KEYS = intrinsic.assign(intrinsic.create(null), { templateID: 1, templateMajorVersion: 1, templateMinorVersion: 1 });
var MS_CA_VERSION_KEYS = intrinsic.assign(intrinsic.create(null), { caKeyIndex: 1, certIndex: 1 });
var SDA_ATTR_KEYS = intrinsic.assign(intrinsic.create(null), { type: 1, values: 1 });
/** @internal The fields each typed statementInfo defines, by statement id. A key outside its
 *  statement's set is refused rather than ignored: a misspelled field would otherwise be dropped and
 *  the certificate would carry a statement the caller did not write. */
var QC_INFO_KEYS = intrinsic.create(null);
[["qcType", { types: 1 }], ["qcIdentMethod", { methods: 1 }],
  ["qcCClegislation", { countries: 1 }], ["qcQSCDlegislation", { countries: 1 }],
  ["qcRetentionPeriod", { years: 1 }], ["qcLimitValue", { currency: 1, amount: 1, exponent: 1 }],
  ["qcPDS", { locations: 1 }],
  ["qcsPkixQCSyntaxV1", { semanticsIdentifier: 1, nameRegistrationAuthorities: 1 }],
  ["qcsPkixQCSyntaxV2", { semanticsIdentifier: 1, nameRegistrationAuthorities: 1 }]].forEach(function (r) {
  QC_INFO_KEYS[oid.byName(r[0])] = intrinsic.assign(intrinsic.create(null), r[1]);
});
var QC_PDS_LOCATION_KEYS = intrinsic.assign(intrinsic.create(null), { url: 1, language: 1 });
var DP_KEYS = intrinsic.assign(intrinsic.create(null), { fullName: 1, reasons: 1, cRLIssuer: 1 });

/** @internal The serial a certificate gets when the caller names none: 20 CSPRNG octets read as a
 * positive integer, the top of the range RFC 5280 sec. 4.1.2.2 allows. The top bit is cleared so the
 * DER INTEGER carries no sign octet. A zero leading octet is drawn again. Substituting a fixed value
 * for it would fold the zero case onto that value and leave one leading octet twice as likely as the
 * others, so the loop keeps the leading octet uniform over 1 to 127. */
function randomSerial() {
  for (;;) {
    var rnd = nodeCrypto.randomBytes(20);
    rnd[0] &= 0x7f;
    if (rnd[0] !== 0) return BigInt("0x" + rnd.toString("hex"));
  }
}

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

/** @internal The criticality RFC 5280 sec. 4.2 fixes for a certificate extension, by OID, read from
 *  the shared table the certificate lint profile reports from, so the two cannot disagree. */
var CERT_FIXED_CRITICALITY = pkix.certFixedCriticality(oid);

var NC_KEYS = intrinsic.assign(intrinsic.create(null), { permitted: 1, excluded: 1 });
var NC_FORM_TAG = intrinsic.assign(intrinsic.create(null), {
  rfc822Name: 1, dNSName: 2, directoryName: 4, uniformResourceIdentifier: 6, uri: 6, iPAddress: 7,
});
/** @internal permittedSubtrees is [0] and excludedSubtrees is [1], in that order. */
function _forEachNcSide(fn) { fn("permitted", 0); fn("excluded", 1); }

function makeBuilder(ctx) {
  var ErrorClass = ctx.ErrorClass, O = ctx.O, NS = ctx.NS;
  var NAME_SCHEMA = ctx.NAME_SCHEMA, SPKI_SCHEMA = ctx.SPKI_SCHEMA;
  function E(kind, message, cause) { return new ErrorClass(ctx.prefix + "/" + kind, message, cause); }
  function code(kind) { return ctx.prefix + "/" + kind; }
  function rawErr(fullCode, message, cause) { return new ErrorClass(fullCode, message, cause); }

  function timeDer(date, which) {
    guard.time.assertEncodable(date, rawErr, code("bad-input"), which);
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
    if (typeOid == null) throw E("bad-name", "unknown distinguished-name attribute " + guard.text.showValue(attrName));
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
    /** @internal Held to the same density every other authoring list is held to. Mapping over a
     * sparse array leaves the hole in place, so an absent element reached the encoder and surfaced
     * as an untyped read of undefined rather than as a refusal a caller can act on. */
    return b.sequence(reqDenseArray(spec, "a name's RDN array").map(encodeRdn));
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
        catch (e) { throw E("bad-input", "invalid otherName type-id OID " + guard.text.showValue(v.typeId) + " (violates the X.660 arc bounds)", e); }
        return b.contextConstructed(0, Buffer.concat([typeIdDer, b.explicit(0, v.value)]));
      default: throw E("bad-input", "unsupported GeneralName form " + JSON.stringify(k) + " (supported: rfc822Name, dNSName, uniformResourceIdentifier, iPAddress, directoryName, otherName)");
    }
  }

  function extKeyUsage(names) {
    if (!_isArray(names) || !names.length) throw E("bad-input", "keyUsage must assert at least one bit (RFC 5280 sec. 4.2.1.3)");
    var positions = names.map(function (n) {
      var pos = KU_BIT[guard.text.keyOf(n)];
      if (pos == null) throw E("bad-input", "unknown keyUsage bit " + guard.text.showValue(n));
      return pos;
    });
    return b.namedBitString(positions);
  }
  function _resolveOid(n, label) {
    /** @internal A fault in a producer spec is this module's, so the name is typed BEFORE the OID
     *  registry sees it: `oid.byName` raises its own oid/* error for a non-string, which names a
     *  different domain than the one a caller of this verb branches on. The dotted-but-invalid case
     *  is caught below for the same reason. */
    if (typeof n !== "string" || !n.length) {
      throw E("bad-input", "unknown " + label + " " + guard.text.showValue(n) + " (expected a registered name or a dotted-decimal OID)");
    }
    var dotted = O(n);
    if (dotted != null) return dotted;
    if (typeof n === "string" && _isDottedOid(n)) {
      try { b.oid(n); }
      catch (e) { throw E("bad-input", "invalid " + label + " OID " + guard.text.showValue(n) + " (violates the X.660 arc bounds)", e); }
      return n;
    }
    throw E("bad-input", "unknown " + label + " " + guard.text.showValue(n) + " (expected a registered name or a dotted-decimal OID)");
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
  /** @internal AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OPTIONAL, authorityCertIssuer
   *  [1] OPTIONAL, authorityCertSerialNumber [2] OPTIONAL } (RFC 5280 sec. 4.2.1.1), in that order.
   *  The reader requires the issuer name and the serial to be both present or both absent, so the
   *  builder is held to the same rule: one structure drives both directions. */
  function extAki(keyid, issuerNames, serial) {
    if ((issuerNames == null) !== (serial == null)) {
      throw E("bad-input", "authorityKeyIdentifier authorityCertIssuer and authorityCertSerialNumber must both be present or both absent (RFC 5280 sec. 4.2.1.1)");
    }
    var fields = [];
    if (keyid != null) guard.list.append(fields, b.contextPrimitive(0, keyid));
    if (issuerNames != null) {
      guard.list.append(fields, encodeGeneralNames(reqDenseArray(issuerNames, "authorityKeyIdentifier authorityCertIssuer"), 1));
      guard.list.append(fields, b.contextPrimitive(2, asn1.decode(serialInteger(serial)).content));
    }
    if (!fields.length) {
      throw E("bad-input", "authorityKeyIdentifier must name a keyIdentifier, or an authorityCertIssuer with its authorityCertSerialNumber");
    }
    return b.sequence(fields);
  }
  function encodeGeneralNames(entries, implicitTag) {
    if (!_isArray(entries) || !entries.length) throw E("bad-input", "a GeneralNames must carry at least one GeneralName");
    var members = entries.map(encodeGeneralName);
    if (implicitTag == null) return b.sequence(members);
    return b.contextConstructed(implicitTag, Buffer.concat(members));
  }
  function extSan(entries) { return encodeGeneralNames(entries); }
  /** @internal One QCStatement statementInfo, by statement id (RFC 3739 sec. 3.2.6, ETSI EN 319
   *  412-5). Each entry mirrors the decoder that reads the value back, so a statement this builder
   *  emits is one `pki.schema.x509.parse` decodes under the same syntax. A `null` encoder means the
   *  statement is presence-only and carries no statementInfo at all. */
  /** @internal A PrintableString carries digits, spaces and punctuation, so the string type alone
   *  does not make a value an ISO code. The alphabetic codes these statements declare are checked for
   *  letters, in either case, before the value is encoded. */
  function _alphaCode(s, n, at, what) {
    var ok = typeof s === "string" && s.length === n;
    for (var i = 0; ok && i < n; i++) {
      var c = _charCodeAt(s, i);
      ok = (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A);
    }
    if (!ok) throw E("bad-input", at + " " + guard.text.showValue(s) + " must be " + what);
    return b.printable(s);
  }
  function _qcCountrySeq(info, who) {
    if (!info || !_isArray(info.countries) || !info.countries.length) {
      throw E("bad-input", who + " requires a non-empty countries array of 2-letter ISO 3166-1 codes");
    }
    return b.sequence(_mapIntrinsic(reqDenseArray(info.countries, who + " countries"), function (c) {
      return _alphaCode(c, 2, who + " country", "a 2-letter ISO 3166-1 code");
    }));
  }
  function _qcOidSeqOf(list, who) {
    if (!_isArray(list) || !list.length) throw E("bad-input", who + " requires a non-empty array of object identifiers");
    return b.sequence(_mapIntrinsic(reqDenseArray(list, who), function (n) { return b.oid(_resolveOid(n, who + " entry")); }));
  }
  var QC_INFO = intrinsic.create(null);
  QC_INFO[oid.byName("qcCompliance")] = null;
  QC_INFO[oid.byName("qcSSCD")] = null;
  QC_INFO[oid.byName("qcType")] = function (info, who) { return _qcOidSeqOf(info && info.types, who + " types"); };
  QC_INFO[oid.byName("qcIdentMethod")] = function (info, who) { return _qcOidSeqOf(info && info.methods, who + " methods"); };
  QC_INFO[oid.byName("qcCClegislation")] = _qcCountrySeq;
  QC_INFO[oid.byName("qcQSCDlegislation")] = _qcCountrySeq;
  QC_INFO[oid.byName("qcRetentionPeriod")] = function (info, who) {
    if (!info || info.years == null) throw E("bad-input", who + " requires a years count");
    return b.integer(skipCount(info.years, who + " years"));
  };
  QC_INFO[oid.byName("qcLimitValue")] = function (info, who) {
    if (!info || info.amount == null || info.exponent == null || info.currency == null) {
      throw E("bad-input", who + " requires currency, amount and exponent (a MonetaryValue)");
    }
    var cur;
    if (typeof info.currency === "string") {
      cur = _alphaCode(info.currency, 3, who + " alphabetic currency", "a 3-letter ISO 4217 code");
    } else {
      cur = b.integer(guard.range.int(guard.range.authoredInteger(info.currency, rawErr, ctx.prefix + "/bad-input", who + " currency"),
        1n, 999n, rawErr, ctx.prefix + "/bad-input", who + " numeric currency (ISO 4217, 1..999)"));
    }
    /** @internal The decoder reads amount as 0..2^53-1 and exponent as its signed range, so the
     *  builder is held to the same bounds; a wider one would emit a MonetaryValue this toolkit's own
     *  reader refuses. */
    var code = ctx.prefix + "/bad-input";
    var amount = guard.range.int(guard.range.authoredInteger(info.amount, rawErr, code, who + " amount"),
      0n, 9007199254740991n, rawErr, code, who + " amount");
    var exponent = guard.range.int(guard.range.authoredInteger(info.exponent, rawErr, code, who + " exponent"),
      -9007199254740991n, 9007199254740991n, rawErr, code, who + " exponent");
    return b.sequence([cur, b.integer(amount), b.integer(exponent)]);
  };
  QC_INFO[oid.byName("qcPDS")] = function (info, who) {
    if (!info || !_isArray(info.locations) || !info.locations.length) {
      throw E("bad-input", who + " requires a non-empty locations array of { url, language }");
    }
    return b.sequence(_mapIntrinsic(reqDenseArray(info.locations, who + " locations"), function (loc, i) {
      var at = who + " location " + i;
      if (!loc || typeof loc !== "object" || _isArray(loc) || _isBufferChk(loc)) throw E("bad-input", at + " must be an object { url, language }");
      guard.identifier.assertKnownKeys(loc, QC_PDS_LOCATION_KEYS, E, "bad-input", function (k) {
        return "unknown " + at + " field " + _stringify(k) + " (accepted: url, language)";
      });
      if (typeof loc.url !== "string" || !loc.url.length) throw E("bad-input", at + " requires a url");
      return b.sequence([b.ia5(loc.url), _alphaCode(loc.language, 2, at + " language", "a 2-letter ISO 639-1 code")]);
    }));
  };
  function _qcSemanticsInfo(info, who) {
    /** @internal SemanticsInformation is OPTIONAL on this statement, which is the form the decoder
     *  accepts for a null statementInfo, so an omitted info emits the statementId alone. An info
     *  object that IS present must carry at least one of the two fields. */
    if (info == null) return null;
    if (info.semanticsIdentifier == null && info.nameRegistrationAuthorities == null) {
      throw E("bad-input", who + " requires a semanticsIdentifier, nameRegistrationAuthorities, or both (RFC 3739 sec. 3.2.6.1)");
    }
    var fields = [];
    if (info.semanticsIdentifier != null) guard.list.append(fields, b.oid(_resolveOid(info.semanticsIdentifier, who + " semanticsIdentifier")));
    if (info.nameRegistrationAuthorities != null) {
      guard.list.append(fields, encodeGeneralNames(reqDenseArray(info.nameRegistrationAuthorities, who + " nameRegistrationAuthorities")));
    }
    return b.sequence(fields);
  }
  QC_INFO[oid.byName("qcsPkixQCSyntaxV1")] = _qcSemanticsInfo;
  QC_INFO[oid.byName("qcsPkixQCSyntaxV2")] = _qcSemanticsInfo;

  /** @internal QCStatements (RFC 3739 sec. 3.2.6): SEQUENCE OF QCStatement { statementId, info? }.
   *  A statement id the toolkit knows encodes its own value syntax; any other id is reachable only
   *  with pre-encoded DER, since nothing here can know what its statementInfo should look like. */
  function extQcStatements(list) {
    if (!_isArray(list) || !list.length) {
      throw E("bad-input", "qcStatements must name at least one statement (RFC 3739 sec. 3.2.6)");
    }
    var dense = reqDenseArray(list, "qcStatements");
    return b.sequence(_mapIntrinsic(dense, function (st, i) {
      var who = "qcStatements entry " + i;
      if (!st || typeof st !== "object" || _isArray(st) || _isBufferChk(st)) {
        throw E("bad-input", who + " must be an object { statementId, info? }");
      }
      guard.identifier.assertKnownKeys(st, QC_STATEMENT_KEYS, E, "bad-input", function (k) {
        return "unknown " + who + " field " + _stringify(k) + " (accepted: statementId, info)";
      });
      var id = _resolveOid(st.statementId, who + " statementId");
      var known = intrinsic.hasOwn(QC_INFO, id);
      /** @internal The pre-encoded escape hatch is for an id whose syntax is NOT known here. A known
       *  id routed through it would skip the rule its typed form is held to and emit a statement the
       *  reader cannot decode, so it is refused rather than passed through. */
      if (guard.bytes.isByteSource(st.info)) {
        if (known) {
          throw E("bad-input", who + " statementId " + guard.text.showValue(st.statementId) +
            " has a known statementInfo syntax, so its info is named as fields rather than pre-encoded DER");
        }
        return b.sequence([b.oid(id), b.raw(guard.der.tlv(guard.bytes.source(st.info, ErrorClass, ctx.prefix + "/bad-input", who + " info"),
          rawErr, ctx.prefix + "/bad-input", who + " pre-encoded info"))]);
      }
      if (!known) {
        /** @internal statementInfo is OPTIONAL on every QCStatement (RFC 3739 sec. 3.2.6), so a
         *  proprietary presence-only statement is a valid shape and emits its id alone. Only a
         *  statement that names a value needs a syntax this module does not have for an unknown id. */
        if (st.info == null) return b.sequence([b.oid(id)]);
        throw E("bad-input", who + " statementId " + guard.text.showValue(st.statementId) +
          " has no known statementInfo syntax; supply the info as pre-encoded DER");
      }
      var encode = QC_INFO[id];
      if (encode === null) {
        if (st.info != null) throw E("bad-input", who + " statement carries no statementInfo, so info must be omitted");
        return b.sequence([b.oid(id)]);
      }
      var infoKeys = QC_INFO_KEYS[id];
      if (infoKeys && st.info != null && typeof st.info === "object" && !_isArray(st.info) && !_isBufferChk(st.info)) {
        guard.identifier.assertKnownKeys(st.info, infoKeys, E, "bad-input", function (k) {
          return "unknown " + who + " info field " + _stringify(k);
        });
      }
      /** @internal An encoder returns null when the statement's info is OPTIONAL and omitted, which
       *  is the form the SemanticsInformation decoder accepts. */
      var value;
      /** @internal A statementInfo field is named in a typed spec, so a character its ASN.1 string
       *  type cannot carry is a fault in the spec this verb was handed rather than in bytes a caller
       *  supplied pre-encoded, and it is reported against this verb. */
      try { value = encode(st.info, who); }
      catch (e) {
        if (e instanceof ErrorClass) throw e;
        throw E("bad-input", who + " statementInfo has characters invalid for its string type", e);
      }
      return value === null ? b.sequence([b.oid(id)]) : b.sequence([b.oid(id), value]);
    }));
  }
  /** @internal A path-validation skip count: a BaseDistance the decoders read back through
   *  guard.range.uint31, so the builder is held to the same bound rather than a wider one. */
  function skipCount(v, label) {
    var code = ctx.prefix + "/bad-input";
    return guard.range.uint31(guard.range.authoredInteger(v, rawErr, code, label), rawErr, code, label);
  }
  /** @internal PolicyConstraints (RFC 5280 sec. 4.2.1.11): requireExplicitPolicy [0] and
   *  inhibitPolicyMapping [1], both IMPLICIT SkipCerts. The clause forbids an empty sequence, so one
   *  of the two is required. Emitted critical by its caller, which the same clause requires. */
  function extPolicyConstraints(spec) {
    if (!spec || typeof spec !== "object" || _isArray(spec) || _isBufferChk(spec)) {
      throw E("bad-input", "policyConstraints must be an object naming requireExplicitPolicy and/or inhibitPolicyMapping");
    }
    guard.identifier.assertKnownKeys(spec, PC_KEYS, E, "bad-input", function (k) {
      return "unknown policyConstraints field " + _stringify(k) + " (accepted: requireExplicitPolicy, inhibitPolicyMapping)";
    });
    var fields = [];
    if (spec.requireExplicitPolicy != null) {
      guard.list.append(fields, b.implicit(0, b.integer(skipCount(spec.requireExplicitPolicy, "policyConstraints.requireExplicitPolicy"))));
    }
    if (spec.inhibitPolicyMapping != null) {
      guard.list.append(fields, b.implicit(1, b.integer(skipCount(spec.inhibitPolicyMapping, "policyConstraints.inhibitPolicyMapping"))));
    }
    if (!fields.length) {
      throw E("bad-input", "policyConstraints must name requireExplicitPolicy or inhibitPolicyMapping (RFC 5280 sec. 4.2.1.11 forbids an empty sequence)");
    }
    return b.sequence(fields);
  }
  /** @internal InhibitAnyPolicy (RFC 5280 sec. 4.2.1.14): a bare SkipCerts INTEGER. */
  function extInhibitAnyPolicy(v) { return b.integer(skipCount(v, "inhibitAnyPolicy")); }
  /** @internal PolicyMappings (RFC 5280 sec. 4.2.1.5): SEQUENCE SIZE (1..MAX) OF
   *  { issuerDomainPolicy, subjectDomainPolicy }. The clause forbids mapping either to or from
   *  anyPolicy, so neither side may name it. */
  function extPolicyMappings(list) {
    if (!_isArray(list) || !list.length) {
      throw E("bad-input", "policyMappings must name at least one { issuerDomainPolicy, subjectDomainPolicy } (RFC 5280 sec. 4.2.1.5)");
    }
    var anyPolicy = O("anyPolicy");
    var dense = reqDenseArray(list, "policyMappings");
    return b.sequence(_mapIntrinsic(dense, function (m, i) {
      var who = "policyMappings entry " + i;
      if (!m || typeof m !== "object" || _isArray(m) || _isBufferChk(m)) {
        throw E("bad-input", who + " must be an object { issuerDomainPolicy, subjectDomainPolicy }");
      }
      guard.identifier.assertKnownKeys(m, PM_KEYS, E, "bad-input", function (k) {
        return "unknown " + who + " field " + _stringify(k) + " (accepted: issuerDomainPolicy, subjectDomainPolicy)";
      });
      if (m.issuerDomainPolicy == null || m.subjectDomainPolicy == null) {
        throw E("bad-input", who + " requires both issuerDomainPolicy and subjectDomainPolicy");
      }
      var idp = _resolveOid(m.issuerDomainPolicy, who + " issuerDomainPolicy");
      var sdp = _resolveOid(m.subjectDomainPolicy, who + " subjectDomainPolicy");
      if (idp === anyPolicy || sdp === anyPolicy) {
        throw E("bad-input", who + " must not map to or from anyPolicy (RFC 5280 sec. 4.2.1.5)");
      }
      return b.sequence([b.oid(idp), b.oid(sdp)]);
    }));
  }
  /** @internal AuthorityInfoAccessSyntax (RFC 5280 sec. 4.2.2.1): SEQUENCE SIZE (1..MAX) OF
   *  AccessDescription { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName }. */
  /** @internal Sec. 4.2.2.1 and sec. 4.2.2.2 define the same SEQUENCE SIZE (1..MAX) OF
   *  AccessDescription, so one encoder serves both and is told which structure it is writing: a fault
   *  in a subjectInfoAccess must not be reported against authorityInfoAccess. */
  function extAccessDescriptions(list, label, clause) {
    if (!_isArray(list) || !list.length) {
      throw E("bad-input", label + " must name at least one { accessMethod, accessLocation } (" + clause + ")");
    }
    var dense = reqDenseArray(list, label);
    return b.sequence(_mapIntrinsic(dense, function (d, i) {
      var who = label + " entry " + i;
      if (!d || typeof d !== "object" || _isArray(d) || _isBufferChk(d)) {
        throw E("bad-input", who + " must be an object { accessMethod, accessLocation }");
      }
      guard.identifier.assertKnownKeys(d, AIA_KEYS, E, "bad-input", function (k) {
        return "unknown " + who + " field " + _stringify(k) + " (accepted: accessMethod, accessLocation)";
      });
      if (d.accessLocation == null) throw E("bad-input", who + " requires an accessLocation GeneralName");
      /** @internal A fault in the SPEC is this module's, so the name is typed here rather than left
       *  to the OID registry, whose own error names a different domain than the one a caller of this
       *  verb branches on. */
      if (typeof d.accessMethod !== "string" || !d.accessMethod.length) {
        throw E("bad-input", who + " requires an accessMethod naming a registered access method or a dotted-decimal OID");
      }
      return b.sequence([b.oid(_resolveOid(d.accessMethod, who + " accessMethod")), encodeGeneralName(d.accessLocation)]);
    }));
  }
  function extAuthorityInfoAccess(list) {
    return extAccessDescriptions(list, "authorityInfoAccess", "RFC 5280 sec. 4.2.2.1");
  }
  function extSubjectInfoAccess(list) {
    return extAccessDescriptions(list, "subjectInfoAccess", "RFC 5280 sec. 4.2.2.2");
  }
  /** @internal SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute (RFC 5280
   *  sec. 4.2.1.8). The reader surfaces each value as its raw DER, so the spec supplies it the same
   *  way and the two directions describe one structure. */
  function extSubjectDirectoryAttributes(list) {
    if (!_isArray(list) || !list.length) {
      throw E("bad-input", "subjectDirectoryAttributes must name at least one { type, values } (RFC 5280 sec. 4.2.1.8)");
    }
    var dense = reqDenseArray(list, "subjectDirectoryAttributes");
    return b.sequence(_mapIntrinsic(dense, function (a, i) {
      var who = "subjectDirectoryAttributes entry " + i;
      if (!a || typeof a !== "object" || _isArray(a) || _isBufferChk(a)) {
        throw E("bad-input", who + " must be an object { type, values }");
      }
      guard.identifier.assertKnownKeys(a, SDA_ATTR_KEYS, E, "bad-input", function (k) {
        return "unknown " + who + " field " + _stringify(k) + " (accepted: type, values)";
      });
      if (!_isArray(a.values) || !a.values.length) throw E("bad-input", who + " requires a non-empty values array of pre-encoded DER");
      /** @internal The reader caps an Attribute's values, so the writer is held to the same ceiling
       *  and cannot emit an attribute this toolkit's own decoder refuses. */
      if (a.values.length > C.LIMITS.ATTRIBUTE_MAX_VALUES) {
        throw E("bad-input", who + " carries " + a.values.length + " values, exceeding the " + C.LIMITS.ATTRIBUTE_MAX_VALUES + " an Attribute may hold");
      }
      var vals = _mapIntrinsic(reqDenseArray(a.values, who + " values"), function (v, j) {
        return b.raw(guard.der.tlv(guard.bytes.source(v, ErrorClass, ctx.prefix + "/bad-input", who + " value " + j),
          rawErr, ctx.prefix + "/bad-input", who + " value " + j));
      });
      return b.sequence([b.oid(_resolveOid(a.type, who + " type")), b.set(vals)]);
    }));
  }
  /** @internal One DistributionPoint (RFC 5280 sec. 4.2.1.13). distributionPoint [0] wraps a
   *  DistributionPointName whose fullName is [0] IMPLICIT GeneralNames; reasons is [1] IMPLICIT
   *  ReasonFlags; cRLIssuer is [2] IMPLICIT GeneralNames. A DistributionPoint must not consist of
   *  only the reasons field, so one of the other two is required. An entry that names none of the
   *  three field names is a GeneralName standing for a single fullName. */
  function distributionPoint(entry, what, idx) {
    var who = what + " entry " + idx;
    var spec = entry;
    var isDpObject = !!entry && typeof entry === "object" && !_isArray(entry) && !_isBufferChk(entry) &&
      guard.list.anyMatches(_objectKeys(entry), function (k) { return DP_KEYS[k] === 1; });
    if (!isDpObject) spec = { fullName: [entry] };
    guard.identifier.assertKnownKeys(spec, DP_KEYS, E, "bad-input", function (k) {
      return "unknown " + who + " field " + _stringify(k) + " (accepted: fullName, reasons, cRLIssuer)";
    });
    if (spec.fullName == null && spec.cRLIssuer == null) {
      throw E("bad-input", who + " must name a fullName or a cRLIssuer; a DistributionPoint must not consist of only the reasons field (RFC 5280 sec. 4.2.1.13)");
    }
    var fields = [];
    if (spec.fullName != null) {
      /** @internal [0] distributionPoint wraps [0] fullName, so the GeneralNames tag nests inside it. */
      guard.list.append(fields, b.contextConstructed(0, encodeGeneralNames(reqDenseArray(spec.fullName, who + " fullName"), 0)));
    }
    if (spec.reasons != null) {
      if (!_isArray(spec.reasons) || !spec.reasons.length) throw E("bad-input", who + " reasons must name at least one ReasonFlags bit");
      var bits = _mapIntrinsic(reqDenseArray(spec.reasons, who + " reasons"), function (r) {
        var bit = REASON_FLAG_BIT[guard.text.keyOf(r)];
        if (bit == null) throw E("bad-input", who + " names an unknown CRL reason " + guard.text.showValue(r));
        return bit;
      });
      guard.list.append(fields, b.implicit(1, b.namedBitString(bits)));
    }
    if (spec.cRLIssuer != null) {
      /** @internal Sec. 4.2.1.13 requires cRLIssuer to carry the NAME of the CRL issuer, and a
       *  GeneralName carries an X.501 Name only as directoryName. The path validator compares only
       *  directoryName entries, so a cRLIssuer naming none matches no issuer and the distribution
       *  point would leave revocation undetermined rather than point at a CRL. */
      var issuers = reqDenseArray(spec.cRLIssuer, who + " cRLIssuer");
      /** @internal A Name with no RDNs names nobody, and pki.crl.sign refuses to issue a CRL under
       *  one, so an empty directoryName leaves the point matching no conforming CRL exactly as a
       *  missing one would. The name is encoded to ask, since a caller may write it as a string, an
       *  RDN array, or raw Name DER. */
      var named = guard.list.anyMatches(issuers, function (e) {
        if (!e || typeof e !== "object" || _isArray(e) || _isBufferChk(e) || e.directoryName == null) return false;
        try {
          return !isEmptyName(encodeName(e.directoryName));
        } catch (_e) {
          /** @internal A directoryName that cannot encode as a Name is not a usable issuer name, so
           *  it does not satisfy the requirement; the refusal below names the real fault. */
          return false;
        }
      });
      if (!named) {
        throw E("bad-input", who + " cRLIssuer must name the CRL issuer as a non-empty directoryName (RFC 5280 sec. 4.2.1.13); a cRLIssuer carrying no usable directoryName matches no CRL issuer");
      }
      guard.list.append(fields, encodeGeneralNames(issuers, 2));
    }
    return b.sequence(fields);
  }
  /** @internal CRLDistributionPoints (RFC 5280 sec. 4.2.1.13). freshestCRL (sec. 4.2.1.15) states
   *  that the same syntax is used, so both route here. */
  function extCrlDistributionPoints(list, what) {
    if (!_isArray(list) || !list.length) {
      throw E("bad-input", what + " must name at least one distribution point (RFC 5280 sec. 4.2.1.13)");
    }
    var dense = reqDenseArray(list, what);
    return b.sequence(_mapIntrinsic(dense, function (e, i) { return distributionPoint(e, what, i); }));
  }
  /** @internal One GeneralSubtree (RFC 5280 sec. 4.2.1.10). Within this profile minimum is 0 and
   *  maximum is absent, so a subtree is its base alone. A base names a NAMESPACE rather than a
   *  subject, so it is held to the constraint-base rule: it may carry a leading dot, and an
   *  iPAddress base is an address followed by its mask. */
  function constraintSubtree(entry, where, idx) {
    var who = "nameConstraints." + where + " entry " + idx;
    if (!entry || typeof entry !== "object" || _isArray(entry) || _isBufferChk(entry)) {
      throw E("bad-input", who + " must be an object naming one GeneralName form; a bare string does not say which namespace is constrained");
    }
    var keys = _objectKeys(entry);
    if (keys.length !== 1) throw E("bad-input", who + " must name exactly one GeneralName form, got " + keys.length);
    var k = keys[0], v = entry[k];
    var tag = NC_FORM_TAG[k];
    if (tag == null) {
      throw E("bad-input", who + " names an unsupported constraint form " + _stringify(k) +
        " (supported: rfc822Name, dNSName, directoryName, uniformResourceIdentifier, iPAddress)");
    }
    if (tag === 7) {
      if (!guard.bytes.isByteSource(v)) throw E("bad-input", who + " iPAddress base must be a byte source");
      var ip = guard.bytes.source(v, ErrorClass, ctx.prefix + "/bad-input", who + " iPAddress base");
      if (ip.length !== 8 && ip.length !== 32) {
        throw E("bad-input", who + " iPAddress base must be 8 octets (an IPv4 address and its mask) or 32 (IPv6), got " + ip.length);
      }
      return b.sequence([b.contextPrimitive(7, ip)]);
    }
    if (tag === 4) return b.sequence([b.explicit(4, encodeName(v))]);
    if (typeof v !== "string") throw E("bad-input", who + " base must be a string for " + k);
    var why = guard.name.constraintBaseRefusal(tag, v);
    if (why !== null) throw E("bad-input", who + " base " + why);
    return b.sequence([b.contextPrimitive(tag, ia5Content(v))]);
  }
  /** @internal NameConstraints (RFC 5280 sec. 4.2.1.10). permittedSubtrees [0] and excludedSubtrees
   *  [1] are IMPLICIT, so each replaces the GeneralSubtrees SEQUENCE tag and holds its members
   *  directly. The extension is emitted critical by its caller, which that clause requires. */
  function extNameConstraints(spec) {
    if (!spec || typeof spec !== "object" || _isArray(spec)) {
      throw E("bad-input", "nameConstraints must be an object naming permitted and/or excluded subtrees");
    }
    guard.identifier.assertKnownKeys(spec, NC_KEYS, E, "bad-input", function (k) {
      return "unknown nameConstraints field " + _stringify(k) + " (accepted: permitted, excluded)";
    });
    var kids = [];
    _forEachNcSide(function (where, implicitTag) {
      var list = spec[where];
      if (list == null) return;
      if (!_isArray(list) || !list.length) {
        throw E("bad-input", "nameConstraints." + where + " must be a non-empty array of GeneralName-form objects");
      }
      var dense = reqDenseArray(list, "nameConstraints." + where);
      var subs = _mapIntrinsic(dense, function (e, idx) { return constraintSubtree(e, where, idx); });
      guard.list.append(kids, b.contextConstructed(implicitTag, _bufferConcatIntrinsic(subs)));
    });
    if (!kids.length) {
      throw E("bad-input", "nameConstraints must name at least one of permitted or excluded (RFC 5280 sec. 4.2.1.10 forbids an empty sequence)");
    }
    return b.sequence(kids);
  }
  /** @internal DisplayText is SIZE (1..200) counted in characters, and sec. 4.2.1.4 forbids a
   *  conforming CA from encoding it as VisibleString or BMPString while naming UTF8String as the form
   *  such a CA uses. Emitting UTF8String settles the encoding rule by construction; the size is
   *  counted with the reader's own counter so the two can never disagree, and a control character is
   *  refused because the section says the string should carry none. */
  function displayText(v, who) {
    if (typeof v !== "string") throw E("bad-input", who + " must be a string");
    var chars = pkix.displayTextChars(v);
    if (chars < 1 || chars > pkix.DISPLAY_TEXT_MAX) {
      throw E("bad-input", who + " must be 1 to " + pkix.DISPLAY_TEXT_MAX + " characters (RFC 5280 sec. 4.2.1.4)");
    }
    for (var i = 0; i < v.length; i++) {
      var c = _charCodeAt(v, i);
      if (c <= 0x1F || (c >= 0x7F && c <= 0x9F)) {
        throw E("bad-input", who + " must not carry a control character (RFC 5280 sec. 4.2.1.4)");
      }
    }
    /** @internal The text is named in a TYPED spec, so text the codec cannot encode is a fault in
     *  the spec this verb was handed, reported against this verb rather than as an asn1/* code. */
    try { return b.utf8(v); }
    catch (e) {
      if (e instanceof ErrorClass) throw e;
      throw E("bad-input", who + " must be text the UTF8String encoding can carry", e);
    }
  }
  /** @internal UserNotice ::= SEQUENCE { noticeRef OPTIONAL, explicitText OPTIONAL }, in that order.
   *  Both fields are optional, which is the form the reader accepts, so a notice naming neither is
   *  an empty SEQUENCE rather than a fault. */
  function userNoticeDer(notice, who) {
    guard.identifier.assertKnownKeys(notice, USER_NOTICE_KEYS, E, "bad-input", function (k) {
      return "unknown " + who + " field " + _stringify(k) + " (accepted: noticeRef, explicitText)";
    });
    var fields = [];
    if (notice.noticeRef != null) {
      var ref = notice.noticeRef;
      if (typeof ref !== "object" || _isArray(ref) || _isBufferChk(ref)) throw E("bad-input", who + " noticeRef must be an object { organization, noticeNumbers }");
      guard.identifier.assertKnownKeys(ref, NOTICE_REF_KEYS, E, "bad-input", function (k) {
        return "unknown " + who + " noticeRef field " + _stringify(k) + " (accepted: organization, noticeNumbers)";
      });
      if (ref.organization == null) throw E("bad-input", who + " noticeRef requires an organization");
      if (!_isArray(ref.noticeNumbers)) throw E("bad-input", who + " noticeRef requires a noticeNumbers array");
      var nums = _mapIntrinsic(reqDenseArray(ref.noticeNumbers, who + " noticeRef noticeNumbers"), function (n, i) {
        return b.integer(guard.range.authoredInteger(n, rawErr, ctx.prefix + "/bad-input", who + " noticeRef noticeNumber " + i));
      });
      guard.list.append(fields, b.sequence([displayText(ref.organization, who + " noticeRef organization"), b.sequence(nums)]));
    }
    if (notice.explicitText != null) guard.list.append(fields, displayText(notice.explicitText, who + " explicitText"));
    return b.sequence(fields);
  }
  /** @internal PolicyInformation ::= SEQUENCE { policyIdentifier, policyQualifiers SIZE (1..MAX)
   *  OPTIONAL }. The qualifiers sequence is emitted only when a qualifier is named, because the
   *  reader refuses an empty one. A bare name or dotted OID stays the shipped shorthand. */
  function extCertPolicies(names) {
    if (!_isArray(names) || !names.length) throw E("bad-input", "certificatePolicies must list at least one policy OID");
    var seen = intrinsic.create(null);
    return b.sequence(_mapIntrinsic(names, function (n, i) {
      var entry = n, quals = [];
      if (n != null && typeof n === "object" && !_isArray(n) && !_isBufferChk(n)) {
        guard.identifier.assertKnownKeys(n, POLICY_ENTRY_KEYS, E, "bad-input", function (k) {
          return "unknown certificatePolicies entry " + i + " field " + _stringify(k) + " (accepted: oid, cps, userNotice)";
        });
        entry = n.oid;
        if (n.cps != null) {
          if (typeof n.cps !== "string" || !n.cps.length) throw E("bad-input", "certificatePolicies entry " + i + " cps must be a non-empty URI string");
          ia5Content(n.cps);
          guard.list.append(quals, b.sequence([b.oid(oid.byName("cps")), b.ia5(n.cps)]));
        }
        if (n.userNotice != null) {
          if (typeof n.userNotice !== "object" || _isArray(n.userNotice) || _isBufferChk(n.userNotice)) {
            throw E("bad-input", "certificatePolicies entry " + i + " userNotice must be an object { noticeRef?, explicitText? }");
          }
          guard.list.append(quals, b.sequence([b.oid(oid.byName("unotice")),
            userNoticeDer(n.userNotice, "certificatePolicies entry " + i + " userNotice")]));
        }
      }
      var pOid = _resolveOid(entry, "certificate policy");
      if (seen[pOid]) throw E("bad-input", "duplicate certificate policy " + guard.text.showValue(entry) + " (RFC 5280 sec. 4.2.1.4)");
      seen[pOid] = true;
      return quals.length ? b.sequence([b.oid(pOid), b.sequence(quals)]) : b.sequence([b.oid(pOid)]);
    }));
  }
  /** @internal A DWORD as the schema-pkix readers bound it: 0 to 2^32-1. */
  function msDword(v, who) {
    var code = ctx.prefix + "/bad-input";
    return guard.range.int(guard.range.authoredInteger(v, rawErr, code, who), 0n, 4294967295n, rawErr, code, who);
  }
  /** @internal CertificateTemplateOID: SEQUENCE { templateID, templateMajorVersion OPTIONAL,
   *  templateMinorVersion OPTIONAL }. The reader takes the versions positionally, so a minor without
   *  a major has no encoding and is refused rather than silently written as the major. */
  function extMsCertificateTemplate(spec) {
    if (!spec || typeof spec !== "object" || _isArray(spec) || _isBufferChk(spec)) {
      throw E("bad-input", "msCertificateTemplate must be an object { templateID, templateMajorVersion?, templateMinorVersion? }");
    }
    guard.identifier.assertKnownKeys(spec, MS_TEMPLATE_KEYS, E, "bad-input", function (k) {
      return "unknown msCertificateTemplate field " + _stringify(k) + " (accepted: templateID, templateMajorVersion, templateMinorVersion)";
    });
    if (spec.templateID == null) throw E("bad-input", "msCertificateTemplate requires a templateID");
    if (spec.templateMinorVersion != null && spec.templateMajorVersion == null) {
      throw E("bad-input", "msCertificateTemplate templateMinorVersion follows templateMajorVersion, so a minor version requires a major one");
    }
    var fields = [b.oid(_resolveOid(spec.templateID, "msCertificateTemplate templateID"))];
    if (spec.templateMajorVersion != null) guard.list.append(fields, b.integer(msDword(spec.templateMajorVersion, "msCertificateTemplate templateMajorVersion")));
    if (spec.templateMinorVersion != null) guard.list.append(fields, b.integer(msDword(spec.templateMinorVersion, "msCertificateTemplate templateMinorVersion")));
    return b.sequence(fields);
  }
  /** @internal CACertVersion is one DWORD the reader splits into a CA key index in the high word and
   *  a certificate index in the low word, so the spec names either the two indexes or the DWORD. */
  function extMsCaVersion(spec) {
    if (spec != null && typeof spec === "object" && !_isArray(spec) && !_isBufferChk(spec)) {
      guard.identifier.assertKnownKeys(spec, MS_CA_VERSION_KEYS, E, "bad-input", function (k) {
        return "unknown msCaVersion field " + _stringify(k) + " (accepted: caKeyIndex, certIndex)";
      });
      if (spec.caKeyIndex == null || spec.certIndex == null) throw E("bad-input", "msCaVersion requires both caKeyIndex and certIndex, or the composed DWORD");
      var code = ctx.prefix + "/bad-input";
      var hi = guard.range.int(guard.range.authoredInteger(spec.caKeyIndex, rawErr, code, "msCaVersion caKeyIndex"), 0n, 65535n, rawErr, code, "msCaVersion caKeyIndex");
      var lo = guard.range.int(guard.range.authoredInteger(spec.certIndex, rawErr, code, "msCaVersion certIndex"), 0n, 65535n, rawErr, code, "msCaVersion certIndex");
      return b.integer((hi * 65536) + lo);
    }
    return b.integer(msDword(spec, "msCaVersion"));
  }
  /** @internal CAPrevCertHash is the SHA-1 thumbprint of the previous CA certificate, and the reader
   *  requires exactly twenty octets. */
  function extMsPreviousCertHash(v) {
    var hash = guard.bytes.snapshotSource(v, ErrorClass, ctx.prefix + "/bad-input", "msPreviousCertHash");
    if (hash.length !== 20) throw E("bad-input", "msPreviousCertHash must be a 20-octet SHA-1 certificate thumbprint");
    return b.octetString(hash);
  }
  /** @internal The legacy v1 template name is a BMPString, which is UCS-2, so a character outside the
   *  basic multilingual plane has no encoding; `b.bmpString` refuses one and the fault is named here. */
  function extMsEnrollCertType(v) {
    if (typeof v !== "string" || !v.length) throw E("bad-input", "msEnrollCertType must be a non-empty template name");
    try { return b.bmpString(v); }
    catch (e) {
      if (e instanceof ErrorClass) throw e;
      throw E("bad-input", "msEnrollCertType must be text a BMPString can carry", e);
    }
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
  /** @internal `decoders`, when given, names the extensions the caller decodes itself after this
   *  check, so a malformed value there keeps the decoder's own code; every other extnValue is held
   *  here to being one DER value. */
  function assertValidExtension(der, idx, decoders) {
    var n, extnId;
    try { n = asn1.decode(der); }
    catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] is not valid DER", e); }
    if (n.tagNumber !== asn1.TAGS.SEQUENCE || n.tagClass !== "universal" || !n.children || n.children.length < 2 || n.children.length > 3) throw E("bad-input", "pre-encoded extension [" + idx + "] must be an Extension SEQUENCE { extnID, critical?, extnValue }");
    try { extnId = asn1.read.oid(n.children[0]); }
    catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] extnID is not an OBJECT IDENTIFIER", e); }
    if (n.children.length === 3) {
      var crit;
      try { crit = asn1.read.boolean(n.children[1]); }
      catch (e) { throw E("bad-input", "pre-encoded extension [" + idx + "] critical must be a BOOLEAN", e); }
      if (crit !== true) throw E("bad-input", "pre-encoded extension [" + idx + "] critical=FALSE must be omitted (DER DEFAULT)");
    }
    var last = n.children[n.children.length - 1];
    if (last.tagNumber !== asn1.TAGS.OCTET_STRING || last.tagClass !== "universal") throw E("bad-input", "pre-encoded extension [" + idx + "] extnValue must be an OCTET STRING");
    if (!(decoders && intrinsic.hasOwn(decoders, extnId))) assertExtnValueIsDer(last.content, "pre-encoded extension [" + idx + "]");
  }
  /** @internal RFC 5280 sec. 4.1: extnValue holds the DER encoding of one ASN.1 value, so the octets
   *  must decode as exactly one TLV, which the strict codec's trailing-byte refusal also enforces. */
  function assertExtnValueIsDer(content, label) {
    try { asn1.decode(content); }
    catch (e) { throw E("bad-input", label + " extnValue must hold exactly one DER-encoded value (RFC 5280 sec. 4.1)", e); }
  }
  /** @internal Applies the certificate profile's fixed-criticality table. The CRL, CRL-entry and
   *  attribute-certificate profiles set their own criticality in their own signers. */
  function assertCertCriticality(extnId, isCritical, label) {
    if (!intrinsic.hasOwn(CERT_FIXED_CRITICALITY, extnId)) return;
    var req = CERT_FIXED_CRITICALITY[extnId];
    if (isCritical === req.critical) return;
    throw E("bad-input", label + " " + (oid.name(extnId) || extnId) + " extension must be marked " +
      (req.critical ? "critical" : "non-critical") + " (" + req.citation + ")");
  }
  var BC_KEYS = { cA: 1, pathLen: 1, critical: 1 };
  var REQ_EXT_KEYS = {
    subjectAltName: 1, keyUsage: 1, keyUsageCritical: 1, extendedKeyUsage: 1, extendedKeyUsageCritical: 1,
    basicConstraints: 1, certificatePolicies: 1, certificatePoliciesCritical: 1, subjectKeyIdentifier: 1,
    nameConstraints: 1, authorityInfoAccess: 1, cRLDistributionPoints: 1, freshestCRL: 1,
    policyConstraints: 1, inhibitAnyPolicy: 1, policyMappings: 1, policyMappingsCritical: 1,
    issuerAltName: 1, qcStatements: 1, qcStatementsCritical: 1,
    msCertificateTemplate: 1, msEnrollCertType: 1, msApplicationPolicies: 1,
    subjectInfoAccess: 1, subjectDirectoryAttributes: 1,
  };
  /** @internal RFC 2985 sec. 5.4.2 has the attribute carry "certificate extensions the requester
   *  wishes to be included". What the issuing CA assigns is not a wish: the authority key
   *  identifier names the CA's key, the precertificate poison and SCT list are the CA's exchange
   *  with a log, the CA version and previous-certificate hash are the CA's own, and the OCSP
   *  no-check marker is the CA's decision about a responder. Those stay out of this table so a
   *  request naming one is refused rather than written and ignored. */
  function requestedExtensions(extSpec, spki) {
    var EXT_DECODERS = ctx.EXT_DECODERS;
    if (_isArray(extSpec)) {
      if (!extSpec.length) throw E("bad-input", "the requested extensions list must carry at least one extension");
      var seen = intrinsic.create(null);
      return b.sequence(extSpec.map(function (e, i) {
        var der = reqDer(e, "extension");
        assertValidExtension(der, i, EXT_DECODERS);
        var n = asn1.decode(der);
        var extnId = asn1.read.oid(n.children[0]);
        if (seen[extnId]) throw E("bad-input", "duplicate requested extension " + extnId + " (RFC 5280 sec. 4.2)");
        seen[extnId] = true;
        assertCertCriticality(extnId, n.children.length === 3, "requested");
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
    /** @internal RFC 5280 sec. 4.2.1.10 fixes this extension critical, in a request as in the certificate. */
    if (extSpec.nameConstraints != null) guard.list.append(out, ext(O("nameConstraints"), true, extNameConstraints(extSpec.nameConstraints)));
    if (extSpec.authorityInfoAccess != null) guard.list.append(out, ext(O("authorityInfoAccess"), false, extAuthorityInfoAccess(extSpec.authorityInfoAccess)));
    if (extSpec.cRLDistributionPoints != null) guard.list.append(out, ext(O("cRLDistributionPoints"), false, extCrlDistributionPoints(extSpec.cRLDistributionPoints, "cRLDistributionPoints")));
    if (extSpec.freshestCRL != null) guard.list.append(out, ext(O("freshestCRL"), false, extCrlDistributionPoints(extSpec.freshestCRL, "freshestCRL")));
    if (extSpec.policyConstraints != null) guard.list.append(out, ext(O("policyConstraints"), true, extPolicyConstraints(extSpec.policyConstraints)));
    if (extSpec.inhibitAnyPolicy != null) guard.list.append(out, ext(O("inhibitAnyPolicy"), true, extInhibitAnyPolicy(extSpec.inhibitAnyPolicy)));
    if (extSpec.policyMappings != null) guard.list.append(out, ext(O("policyMappings"), !!extSpec.policyMappingsCritical, extPolicyMappings(extSpec.policyMappings)));
    if (extSpec.issuerAltName != null) guard.list.append(out, ext(O("issuerAltName"), false, encodeGeneralNames(reqDenseArray(extSpec.issuerAltName, "issuerAltName"))));
    if (extSpec.qcStatements != null) guard.list.append(out, ext(O("qcStatements"), !!extSpec.qcStatementsCritical, extQcStatements(extSpec.qcStatements)));
    if (extSpec.msCertificateTemplate != null) guard.list.append(out, ext(O("msCertificateTemplate"), false, extMsCertificateTemplate(extSpec.msCertificateTemplate)));
    if (extSpec.msEnrollCertType != null) guard.list.append(out, ext(O("msEnrollCertType"), false, extMsEnrollCertType(extSpec.msEnrollCertType)));
    if (extSpec.msApplicationPolicies != null) guard.list.append(out, ext(O("msApplicationPolicies"), false, extCertPolicies(extSpec.msApplicationPolicies)));
    if (extSpec.subjectInfoAccess != null) guard.list.append(out, ext(O("subjectInfoAccess"), false, extSubjectInfoAccess(extSpec.subjectInfoAccess)));
    if (extSpec.subjectDirectoryAttributes != null) guard.list.append(out, ext(O("subjectDirectoryAttributes"), false, extSubjectDirectoryAttributes(extSpec.subjectDirectoryAttributes)));
    if (!out.length) throw E("bad-input", "the requested extensions object must request at least one extension");
    return b.sequence(out);
  }

  function serialInteger(serial) {
    var v;
    if (serial == null) {
      v = randomSerial();
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
    /** @internal Two keys of different types are never the same key, and comparing them through
     *  the runtime's equality leaves a fault queued in the crypto library that surfaces on the
     *  next unrelated key import in the process, so the type decides that case first. */
    if (ka.asymmetricKeyType !== kb.asymmetricKeyType) return false;
    return _keyEquals(ka, kb) === true;
  }

  return {
    E: E, code: code, KU_BIT: KU_BIT,
    encodeName: encodeName, isEmptyName: isEmptyName, encodeGeneralName: encodeGeneralName,
    extNameConstraints: extNameConstraints, extAuthorityInfoAccess: extAuthorityInfoAccess,
    extCrlDistributionPoints: extCrlDistributionPoints, extPolicyConstraints: extPolicyConstraints,
    extInhibitAnyPolicy: extInhibitAnyPolicy, extPolicyMappings: extPolicyMappings,
    extQcStatements: extQcStatements,
    encodeGeneralNames: encodeGeneralNames, serialInteger: serialInteger, timeDer: timeDer,
    requestedExtensions: requestedExtensions,
    extKeyUsage: extKeyUsage, extExtKeyUsage: extExtKeyUsage, validateBcSpec: validateBcSpec,
    extBasicConstraints: extBasicConstraints, pathLen: pathLen, extSki: extSki, extAki: extAki, AKI_KEYS: AKI_KEYS,
    extSan: extSan, extCertPolicies: extCertPolicies, ext: ext,
    extSubjectInfoAccess: extSubjectInfoAccess, extSubjectDirectoryAttributes: extSubjectDirectoryAttributes,
    extMsCertificateTemplate: extMsCertificateTemplate, extMsCaVersion: extMsCaVersion,
    extMsPreviousCertHash: extMsPreviousCertHash, extMsEnrollCertType: extMsEnrollCertType,
    spkiKeyId: spkiKeyId, skiKeyId: skiKeyId, skiValueOf: skiValueOf,
    reqDer: reqDer, reqDenseArray: reqDenseArray, reqDerSequence: reqDerSequence, assertValidSpki: assertValidSpki, assertValidExtension: assertValidExtension,
    assertExtnValueIsDer: assertExtnValueIsDer,
    assertCertCriticality: assertCertCriticality,
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

/** @internal The subjectKeyIdentifier a parsed certificate carries, or null without one. RFC 5280
 *  sec. 4.2.1.1 names it as the authorityKeyIdentifier keyIdentifier of everything issued under
 *  that certificate, so a signer reads it here before deriving one from the key, and a verifier
 *  matches a signer by it. */
function skiValueOf(parsedCert) {
  var exts = intrinsic.filter(parsedCert.extensions, function (e) { return e.oid === OID_SKI; });
  if (!exts.length) return null;
  try { return asn1.read.octetString(asn1.decode(exts[0].value)); }
  catch (_e) { return null; }   // allow:swallow-unverified -- a malformed SKI is read as absent; a signer then derives the authorityKeyIdentifier keyIdentifier from the public key, and a verifier matches on nothing
}

module.exports = intrinsic.freeze({ makeBuilder: makeBuilder, reqDenseArray: reqDenseArrayImpl, KU_BIT: KU_BIT, tbsNameField: tbsNameField, tbsSerialNumber: tbsSerialNumber, randomSerial: randomSerial, skiValueOf: skiValueOf, isHttpUrl: isHttpUrl, isLdapUrl: isLdapUrl });
