// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var asn1 = require("./asn1-der");
var constants = require("./constants");
var schema = require("./schema-engine");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var _hasOwn = intrinsic.hasOwn;
var _forEach = intrinsic.forEach;
var _map = intrinsic.map;
var _push = intrinsic.push;
var _join = intrinsic.join;
var _stringify = intrinsic.stringify;
var _String = intrinsic.String;
var _isBuffer = intrinsic.isBuffer;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferConcat = intrinsic.bufferConcat;
var _assign = intrinsic.assign;
var _subarray = intrinsic.subarray;
var _strIndexOf = intrinsic.stringIndexOf;
var _bufToString = intrinsic.uncurry(Buffer.prototype.toString);
var _strSlice = intrinsic.uncurry(String.prototype.slice);
var _charAt = intrinsic.uncurry(String.prototype.charAt);
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _split = intrinsic.uncurry(String.prototype.split);
var _create = intrinsic.create;
var _isUint8Array = intrinsic.types.isUint8Array;
var _bigIntToString = intrinsic.bigIntToString;
var _weakGet = intrinsic.weakGet;
var _weakSet = intrinsic.weakSet;
var _WeakMapI = intrinsic.WeakMap;
var _arrayFrom = Array.from;
var _getUTCFullYear = intrinsic.uncurry(Date.prototype.getUTCFullYear);

function _isJsWhitespace(c) {
  return c === 0x09 || c === 0x0a || c === 0x0b || c === 0x0c || c === 0x0d || c === 0x20 ||
         c === 0xa0 || c === 0x1680 || (c >= 0x2000 && c <= 0x200a) || c === 0x2028 || c === 0x2029 ||
         c === 0x202f || c === 0x205f || c === 0x3000 || c === 0xfeff;
}
function _hasWhitespace(s) {
  for (var i = 0; i < s.length; i++) { if (_isJsWhitespace(_charCodeAt(s, i))) return true; }
  return false;
}
function _hasNonWhitespace(s) {
  for (var i = 0; i < s.length; i++) { if (!_isJsWhitespace(_charCodeAt(s, i))) return true; }
  return false;
}
function _charTable(chars) { var t = []; for (var i = 0; i < chars.length; i++) t[_charCodeAt(chars, i)] = true; return t; }
function _allCharsIn(s, table) {
  if (s.length === 0) return false;
  for (var i = 0; i < s.length; i++) { if (!table[_charCodeAt(s, i)]) return false; }
  return true;
}
var ct = require("./ct");

var _PEM_BEGIN = "-----BEGIN ";
var _PEM_END = "-----END ";
var _PEM_DASHES = "-----";

function _findPemBlock(text, from) {
  var searchFrom = from;
  for (;;) {
    var bi = _strIndexOf(text, _PEM_BEGIN, searchFrom);
    if (bi === -1) return null;
    var p = bi + _PEM_BEGIN.length, ls = p;
    while (p < text.length) {
      var c = _charCodeAt(text, p);
      if (!((c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 32)) break;
      p += 1;
    }
    if (p === ls || _strSlice(text, p, p + 5) !== _PEM_DASHES) { searchFrom = bi + 1; continue; }
    var label = _strSlice(text, ls, p);
    var bodyStart = p + 5;
    var endMarker = _PEM_END + label + _PEM_DASHES;
    var ei = _strIndexOf(text, endMarker, bodyStart);
    if (ei === -1) { searchFrom = bi + 1; continue; }
    return { index: bi, label: label, body: _strSlice(text, bodyStart, ei), end: ei + endMarker.length };
  }
}

function _stripB64Whitespace(s) {
  var out = "", runStart = 0, i;
  for (i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    if (c === 13 || c === 10 || c === 9 || c === 32) {
      if (i > runStart) out += _strSlice(s, runStart, i);
      runStart = i + 1;
    }
  }
  if (i > runStart) out += _strSlice(s, runStart, i);
  return out;
}

function _wrap64(s) {
  var out = "";
  for (var i = 0; i < s.length; i += 64) {
    if (i > 0) out += "\n";
    out += _strSlice(s, i, i + 64);
  }
  return out;
}


function pemDecode(text, label, PemError) {
  text = guard.text.decode(text, constants.LIMITS.PEM_MAX_BYTES, PemError, {
    charset: "latin1", tooLarge: "pem/too-large", badInput: "pem/bad-input", label: "PEM input",
  });
  var m = _findPemBlock(text, 0);
  if (!m) throw new PemError("pem/no-block", "no PEM block found");
  if (label && m.label !== label) throw new PemError("pem/label-mismatch", "expected " + _stringify(label) + " block, got " + _stringify(m.label));
  var b64 = _stripB64Whitespace(m.body);
  return guard.encoding.base64(b64, null, function (c, msg) { return new PemError(c, msg); }, "pem/bad-base64", "PEM base64 body");
}

function pemDecodeAll(text, label, PemError) {
  label = label || "CERTIFICATE";
  text = guard.text.decode(text, constants.LIMITS.PEM_MAX_BYTES, PemError, {
    charset: "latin1", tooLarge: "pem/too-large", badInput: "pem/bad-input", label: "PEM input",
  });
  var blocks = [];
  var lastEnd = 0, m;
  while ((m = _findPemBlock(text, lastEnd)) !== null) {
    if (_hasNonWhitespace(_strSlice(text, lastEnd, m.index))) throw new PemError("pem/explanatory-text", "explanatory text is not permitted around PEM blocks (RFC 8555 sec. 9.1)");
    if (m.label !== label) throw new PemError("pem/label-mismatch", "expected " + _stringify(label) + " block, got " + _stringify(m.label));
    var b64 = _stripB64Whitespace(m.body);
    _push(blocks, guard.encoding.base64(b64, null, function (c, msg) { return new PemError(c, msg); }, "pem/bad-base64", "PEM base64 body"));
    lastEnd = m.end;
  }
  if (blocks.length === 0) throw new PemError("pem/no-block", "no PEM block found");
  if (_hasNonWhitespace(_strSlice(text, lastEnd))) throw new PemError("pem/explanatory-text", "explanatory text is not permitted after the PEM chain (RFC 8555 sec. 9.1)");
  return blocks;
}

function _isPemLabel(s) {
  var n = s.length;
  if (n === 0) return false;
  for (var i = 0; i < n; i++) {
    var ch = _charAt(s, i);
    if (ch === " ") {
      if (i === 0 || i === n - 1 || _charAt(s, i - 1) === " ") return false;
    } else if (!((ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9"))) {
      return false;
    }
  }
  return true;
}

function pemEncode(der, label, PemError) {
  if (typeof label !== "string" || !_isPemLabel(label)) {
    throw new PemError("pem/bad-label", "pemEncode requires an uppercase A-Z0-9 label with single spaces");
  }
  var buf = guard.bytes.view(der, PemError, "pem/bad-input", "pemEncode DER input");
  var b64 = _wrap64(_bufToString(buf, "base64"));
  return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
}

function _keepBase64(s) {
  var out = "", runStart = 0, i;
  for (i = 0; i < s.length; i++) {
    var c = _charCodeAt(s, i);
    if (!((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47 || c === 61)) {
      if (i > runStart) out += _strSlice(s, runStart, i);
      runStart = i + 1;
    }
  }
  if (i > runStart) out += _strSlice(s, runStart, i);
  return out;
}

// @internal
function pemDecodeLenient(text, label) {
  var begin = _PEM_BEGIN + label + _PEM_DASHES;
  var end = _PEM_END + label + _PEM_DASHES;
  var bi = _strIndexOf(text, begin);
  if (bi === -1) return null;
  var bodyStart = bi + begin.length;
  var ei = _strIndexOf(text, end, bodyStart);
  if (ei === -1) return null;
  return _bufferFrom(_keepBase64(_strSlice(text, bodyStart, ei)), "base64");
}

function coerceToDer(input, opts) {
  if (typeof input === "string") return pemDecode(input, opts.pemLabel, opts.PemError);
  if (guard.bytes.isByteSource(input)) {
    var buf = guard.bytes.source(input, opts.ErrorClass, opts.prefix + "/bad-input", "parse");
    return _isPemArmor(buf) ? pemDecode(buf, opts.pemLabel, opts.PemError) : buf;
  }
  throw new opts.ErrorClass(opts.prefix + "/bad-input", "parse expects a DER BufferSource (Buffer, typed array, DataView, or ArrayBuffer) or a PEM string");
}

function _isPemArmor(buf) {
  var head = _bufToString(_subarray(buf, 0, 4096), "latin1");
  var idx = _strIndexOf(head, "-----BEGIN");
  if (idx === -1) return false;
  for (var i = 0; i < idx; i++) {
    var c = buf[i];
    var textByte = (c >= 0x20 && c < 0x7f) || c === 0x09 || c === 0x0a || c === 0x0d ||
      c === 0xef || c === 0xbb || c === 0xbf;
    if (!textByte) return false;
  }
  return true;
}

function decodeRoot(der, opts) {
  try { return asn1.decode(der, opts.ber ? { ber: true } : undefined); }
  catch (e) {
    throw new opts.ErrorClass(opts.prefix + "/bad-der", (opts.what || "input") + " DER did not decode: " + ((e && e.message) || _String(e)), e);
  }
}

function runParse(input, opts) {
  return schema.walk(opts.topSchema, decodeRoot(coerceToDer(input, opts), opts), opts.ns).result;
}

var DN_SHORT = constants.NAMES.DN_SHORT;

function makeNS(prefix, ErrorClass, oidModule) {
  return { prefix: prefix, E: function (code, message, cause) { return new ErrorClass(code, message, cause); }, oid: oidModule };
}

function versionReader(ns, accept) {
  return schema.decode(function (n) {
    var key = _bigIntToString(asn1.read.integer(n));
    if (_hasOwn(accept, key)) return accept[key];
    throw ns.E(ns.prefix + "/bad-version", "unsupported version " + key);
  });
}

function algorithmIdentifier(ns, opts) {
  opts = opts || {};
  return schema.seq([
    schema.field("algorithm", schema.oidLeaf()),
    schema.optional("parameters", schema.any(), { whenAny: true }),
  ], {
    assert: opts.implicitTag != null ? "implicit" : "sequence", implicitTag: opts.implicitTag,
    arity: { min: 1 }, code: ns.prefix + "/bad-algorithm-identifier", what: "AlgorithmIdentifier",
    build: function (m, ctx) {
      var dotted = m.fields.algorithm.value;
      if (m.fields.parameters.present && ctx.oid.paramsMustBeAbsent(dotted)) {
        throw ctx.E(ctx.prefix + "/bad-algorithm-parameters",
          "the " + (ctx.oid.name(dotted) || dotted) + " AlgorithmIdentifier parameters field MUST be absent");
      }
      return { oid: dotted, name: ctx.oid.name(dotted) || null, parameters: m.fields.parameters.present ? m.fields.parameters.node.bytes : null };
    },
  });
}

function pbkdf2Params(ns) {
  return schema.seq([
    schema.field("salt", schema.octetString()),
    schema.field("iterationCount", schema.integerLeaf()),
    schema.optional("keyLength", schema.integerLeaf(), { whenUniversal: [asn1.TAGS.INTEGER] }),
    schema.optional("prf", algorithmIdentifier(ns), { whenUniversal: [asn1.TAGS.SEQUENCE] }),
  ], {
    assert: "sequence", code: ns.prefix + "/bad-mac-data", what: "PBKDF2-params",
    build: function (m, ctx) {
      var hmacSha1 = ctx.oid.byName("hmacWithSHA1");
      if (!m.fields.keyLength.present) {
        throw ctx.E(ctx.prefix + "/bad-mac-data", "PBMAC1 PBKDF2-params must carry keyLength (RFC 9579 sec. 5)");
      }
      var iterationCount = guard.range.positiveInt31(m.fields.iterationCount.value, ctx.E, ctx.prefix + "/bad-mac-data", "PBKDF2 iterationCount");
      var keyLength = guard.range.positiveInt31(m.fields.keyLength.value, ctx.E, ctx.prefix + "/bad-mac-data", "PBKDF2 keyLength");
      var prf = m.fields.prf.present ? m.fields.prf.value.result : null;
      var pp = prf ? prf.parameters : null;
      if (prf && prf.oid === hmacSha1 && pp !== null && pp.length === 2 && pp[0] === 0x05 && pp[1] === 0x00) {
        throw ctx.E(ctx.prefix + "/bad-mac-data", "a PBKDF2 prf equal to its DEFAULT algid-hmacWithSHA1 must be omitted (X.690 sec. 11.5, RFC 8018 sec. 5.2)");
      }
      if (prf && pp !== null && !(pp.length === 2 && pp[0] === 0x05 && pp[1] === 0x00)) {
        throw ctx.E(ctx.prefix + "/bad-mac-data", "the PBKDF2 prf parameters must be absent or NULL (RFC 8018 App. B.1)");
      }
      return {
        salt: m.fields.salt.value,
        iterationCount: iterationCount,
        keyLength: keyLength,
        prfOid: prf ? prf.oid : hmacSha1,
        prfName: prf ? prf.name : "hmacWithSHA1",
      };
    },
  });
}

function pbmac1Params(ns) {
  return schema.seq([
    schema.field("keyDerivationFunc", schema.seq([
      schema.field("algorithm", schema.oidLeaf()),
      schema.field("parameters", pbkdf2Params(ns)),
    ], { assert: "sequence", arity: { exact: 2 }, code: ns.prefix + "/bad-mac-data", what: "PBMAC1 keyDerivationFunc" })),
    schema.field("messageAuthScheme", algorithmIdentifier(ns)),
  ], {
    assert: "sequence", arity: { exact: 2 }, code: ns.prefix + "/bad-mac-data", what: "PBMAC1-params",
    build: function (m, ctx) {
      var kdf = m.fields.keyDerivationFunc.value;
      if (kdf.fields.algorithm.value !== ctx.oid.byName("pbkdf2")) {
        throw ctx.E(ctx.prefix + "/bad-mac-data", "PBMAC1 keyDerivationFunc must be PBKDF2 (RFC 9579 sec. 4)");
      }
      var scheme = m.fields.messageAuthScheme.value.result;
      var sp = scheme.parameters;
      if (sp !== null && !(sp.length === 2 && sp[0] === 0x05 && sp[1] === 0x00)) {
        throw ctx.E(ctx.prefix + "/bad-mac-data", "the PBMAC1 messageAuthScheme parameters must be absent or NULL (RFC 8018 App. B.1)");
      }
      return {
        kdf: kdf.fields.parameters.value.result,
        schemeOid: scheme.oid,
        schemeName: scheme.name,
      };
    },
  });
}

function attrValueToString(ns) {
  return schema.decode(function (node) {
    var s;
    try { s = asn1.read.string(node); }
    catch (e) {
      if (!e || (e.code !== "asn1/expected-string" && e.code !== "asn1/expected-primitive")) {
        throw ns.E(ns.prefix + "/bad-atv", "malformed string in attribute value: " + ((e && e.message) || _String(e)));
      }
      if (node.tagClass === "universal" && node.tagNumber === asn1.TAGS.NUMERIC_STRING) {
        try { asn1.read.numericString(node); }
        catch (e2) { throw ns.E(ns.prefix + "/bad-atv", "malformed NumericString in attribute value: " + ((e2 && e2.message) || _String(e2))); }
      }
      return "#" + _bufToString(node.bytes, "hex");
    }
    if (_charAt(s, 0) === "#" || _charAt(s, 0) === "\\") return "\\" + s;
    return s;
  }, function (value) {
    if (typeof value === "string" && _charAt(value, 0) === "\\") return asn1.build.utf8(_strSlice(value, 1));
    if (typeof value === "string" && _charAt(value, 0) === "#") {
      var hex = _strSlice(value, 1);
      if (hex.length === 0) {
        throw ns.E(ns.prefix + "/bad-atv", "a #hex attribute value must be a non-empty even run of hex digits (RFC 4514 sec. 2.4)");
      }
      var raw = guard.encoding.hex(hex, null, ns.E, ns.prefix + "/bad-atv", "a #hex attribute value");
      try { asn1.decode(raw); }
      catch (e) { throw ns.E(ns.prefix + "/bad-atv", "a #hex attribute value must encode exactly one DER TLV", e); }
      return raw;
    }
    return asn1.build.utf8(value);
  });
}

var _escapeDnValue = guard.name.escapeDnValue;

function _dnDisplayValue(v) {
  if (typeof v !== "string") return v;
  if (_charAt(v, 0) === "#") return v;
  return _escapeDnValue(_charAt(v, 0) === "\\" ? _strSlice(v, 1) : v);
}

function time(ns) {
  var base = schema.time(ns);
  return schema.decode(function (n, ctx) {
    var d = base.fn(n, ctx);
    if (n.tagNumber === asn1.TAGS.GENERALIZED_TIME) {
      var y = _getUTCFullYear(d);
      if (y >= 1950 && y < 2050) {
        throw ctx.E(ctx.prefix + "/bad-time", "a date through 2049 must be encoded as UTCTime, not GeneralizedTime (RFC 5280 sec. 4.1.2.5)");
      }
    }
    return d;
  }, base.write);
}

function attributeTypeAndValue(ns) {
  return schema.seq([
    schema.field("type", schema.oidLeaf()),
    schema.field("value", attrValueToString(ns)),
  ], {
    assert: "sequence", arity: { min: 2 }, code: ns.prefix + "/bad-atv", what: "AttributeTypeAndValue",
    build: function (m, ctx) {
      var typeOid = m.fields.type.value;
      return { type: typeOid, name: ctx.oid.name(typeOid) || null, value: m.fields.value.value };
    },
  });
}
function relativeDistinguishedName(ns) {
  return schema.setOf(attributeTypeAndValue(ns), { assert: "set", min: 1, code: ns.prefix + "/bad-rdn", what: "RelativeDistinguishedName" });
}
function name(ns, opts) {
  opts = opts || {};
  function nameBuild(m) {
    var rdns = [], parts = [];
    _forEach(m.items, function (rdnItem) {
      var atvs = [], atvParts = [];
      _forEach(rdnItem.value.items, function (atvItem) {
        var a = atvItem.value.result;
        _push(atvs, a);
        var label = (a.name && _hasOwn(DN_SHORT, a.name) && DN_SHORT[a.name]) || a.name || a.type;
        _push(atvParts, label + "=" + _dnDisplayValue(a.value));
      });
      _push(rdns, atvs);
      _push(parts, _join(atvParts, "+"));
    });
    return { rdns: rdns, dn: _join(parts, ", "), bytes: opts.implicitTag != null ? asn1.sequenceTlv(m.node) : m.node.bytes };
  }
  if (opts.implicitTag != null) {
    return schema.implicitSeqOf(opts.implicitTag, relativeDistinguishedName(ns), {
      code: ns.prefix + "/bad-name", what: "Name", build: nameBuild });
  }
  return schema.seqOf(relativeDistinguishedName(ns), {
    assert: "sequence", code: ns.prefix + "/bad-name", what: "Name", build: nameBuild });
}

function generalizedTime(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-time");
  var message = opts.message || "the time must be a GeneralizedTime";
  var readOpts = opts.allowFractional ? { allowFractional: true } : undefined;
  return schema.decode(function (n, ctx) {
    if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.GENERALIZED_TIME) {
      throw ctx.E(code, message);
    }
    return asn1.read.time(n, readOpts);
  });
}

function utf8Text(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-freetext");
  var message = opts.message || "the element must be a UTF8String";
  return schema.decode(function (n, ctx) {
    if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.UTF8_STRING) {
      throw ctx.E(code, message);
    }
    return asn1.read.string(n);
  });
}

function rawNonEmptySequence(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-sequence");
  var message = opts.message || "expected a non-empty universal SEQUENCE";
  return schema.decode(function (n, ctx) {
    if (!(n.tagClass === "universal" && n.tagNumber === asn1.TAGS.SEQUENCE && n.children && n.children.length >= 1)) {
      throw ctx.E(code, message);
    }
    return n.bytes;
  });
}

var CRL_REASON_NAMES = constants.NAMES.CRL_REASON;

var GN_CONSTRUCTED = _assign(_create(null), { 0: 1, 3: 1, 4: 1, 5: 1 });
var GN_IA5 = _assign(_create(null), { 1: 1, 2: 1, 6: 1 });
function generalName(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-general-name");
  var decodeValue = opts.decodeValue === true;
  var subtreeBase = opts.subtreeBase === true;
  var NAME = name(ns);
  return schema.decode(function (n, ctx) {
    if (n.tagClass !== "context" || n.tagNumber < 0 || n.tagNumber > 8) {
      throw ctx.E(code, "value must be a GeneralName (context tag [0]..[8]) (RFC 5280 sec. 4.2.1.6)");
    }
    var t = n.tagNumber;
    var constructed = !!n.children;
    var value;
    if (GN_CONSTRUCTED[t]) {
      if (!constructed || n.children.length < 1) throw ctx.E(code, "GeneralName [" + t + "] must be a non-empty constructed value (RFC 5280 sec. 4.2.1.6)");
      if (t === 0) {
        if (n.children.length !== 2) throw ctx.E(code, "GeneralName otherName [0] must be a SEQUENCE { type-id, value [0] }");
        var typeId;
        try { typeId = asn1.read.oid(n.children[0]); }
        catch (e) { throw ctx.E(code, "GeneralName otherName [0] must lead with a type-id OBJECT IDENTIFIER", e); }
        var ov = n.children[1];
        if (!(ov.tagClass === "context" && ov.tagNumber === 0 && ov.children && ov.children.length === 1)) {
          throw ctx.E(code, "GeneralName otherName [0] value must be a [0] EXPLICIT wrapper carrying exactly one value");
        }
        if (decodeValue) value = { typeId: typeId, valueBytes: ov.children[0].bytes };
      } else if (t === 4) {
        if (n.children.length !== 1) throw ctx.E(code, "GeneralName directoryName [4] must wrap exactly one Name");
        var dnMatch = schema.walk(NAME, n.children[0], ctx);
        if (decodeValue) value = dnMatch.result;
      }
    } else {
      if (constructed) throw ctx.E(code, "GeneralName [" + t + "] must be primitive (X.690 sec. 10.2)");
      if (GN_IA5[t]) {
        if (n.content.length === 0) throw ctx.E(code, "GeneralName [" + t + "] must be a non-empty IA5String");
        guard.name.assertPrintableIa5(n.content, ctx.E, code, "GeneralName [" + t + "]");
        if (decodeValue) value = _bufToString(n.content, "latin1");
      } else if (t === 7) {
        if (subtreeBase) {
          if (n.content.length !== 8 && n.content.length !== 32) throw ctx.E(code, "GeneralName iPAddress [7] subtree base must be an 8- or 32-octet address+mask (RFC 5280 sec. 4.2.1.10)");
        } else if (n.content.length !== 4 && n.content.length !== 16) {
          throw ctx.E(code, "GeneralName iPAddress [7] must be a 4- or 16-octet address");
        }
        if (decodeValue) value = _bufferConcat([n.content]);
      } else if (t === 8) {
        var regId;
        try { regId = asn1.decodeOidContent(n.content); }
        catch (e) { throw ctx.E(code, "GeneralName registeredID [8] must be a valid OBJECT IDENTIFIER", e); }
        if (decodeValue) value = regId;
      }
    }
    var out = { bytes: n.bytes, tagClass: n.tagClass, tagNumber: n.tagNumber };
    if (decodeValue) out.value = value === undefined ? null : value;
    return out;
  });
}

function generalNames(ns, opts) {
  opts = opts || {};
  var code = opts.code || (ns.prefix + "/bad-general-names");
  var gn = generalName(ns, { code: code, decodeValue: opts.decodeValue === true, subtreeBase: opts.subtreeBase === true });
  function build(m) { return { names: _map(m.items, function (it) { return it.value; }), bytes: m.node.bytes }; }
  if (opts.implicitTag != null) {
    return schema.implicitSeqOf(opts.implicitTag, gn, { min: 1, code: code, what: opts.what || "GeneralNames", build: build });
  }
  return schema.seqOf(gn, { assert: "sequence", min: 1, code: code, what: opts.what || "GeneralNames", build: build });
}

function distributionPointName(ns, node, code) {
  if (node && node.tagClass === "context" && node.tagNumber === 0) {
    var gns = schema.walk(generalNames(ns, { implicitTag: 0, code: code, what: "DistributionPointName fullName" }), node, ns).result;
    return { kind: "fullName", names: _map(gns.names, function (n) { return n.bytes; }) };
  }
  if (node && node.tagClass === "context" && node.tagNumber === 1) {
    schema.walk(schema.implicitSetOf(1, attributeTypeAndValue(ns), {
      min: 1, code: code, what: "DistributionPointName nameRelativeToCRLIssuer" }), node, ns);
    return { kind: "rdn", bytes: node.bytes };
  }
  throw ns.E(code, "DistributionPointName must be fullName [0] or nameRelativeToCRLIssuer [1] (RFC 5280 sec. 4.2.1.13)");
}

var _KU_DECODER = new _WeakMapI();
function keyUsageOf(ns, cert, E, code, label) {
  var exts = (cert && cert.extensions) || [];
  var want = ns.oid.byName("keyUsage");
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid !== want || exts[i].value == null) continue;
    var dec = _weakGet(_KU_DECODER, ns);
    if (!dec) { dec = certExtensionDecoders(ns).byOid[want]; _weakSet(_KU_DECODER, ns, dec); }
    try { return dec(exts[i].value); }
    catch (e) { throw E(code, "the " + label + " keyUsage extension is malformed", e); }
  }
  return null;
}

function issuingDistributionPoint(code) {
  return schema.seq([
    schema.trailing([
      { tag: 0, name: "distributionPoint", schema: schema.any() },
      { tag: 1, name: "onlyContainsUserCerts", schema: schema.implicitBoolean(1) },
      { tag: 2, name: "onlyContainsCACerts", schema: schema.implicitBoolean(2) },
      { tag: 3, name: "onlySomeReasons", schema: schema.implicitBitString(3) },
      { tag: 4, name: "indirectCRL", schema: schema.implicitBoolean(4) },
      { tag: 5, name: "onlyContainsAttributeCerts", schema: schema.implicitBoolean(5) },
    ], { minTag: 0, maxTag: 5, unexpectedCode: code, orderCode: code }),
  ], { assert: "sequence", code: code, what: "IssuingDistributionPoint" });
}

var _T = asn1.TAGS;

function assertPolicyQualifiers(qNode, fail) {
  if (qNode.tagClass !== "universal" || qNode.tagNumber !== _T.SEQUENCE || !qNode.children || !qNode.children.length) {
    fail("policyQualifiers must be a non-empty SEQUENCE (RFC 5280 sec. 4.2.1.4)");
  }
  _forEach(qNode.children, function (pq) {
    if (pq.tagClass !== "universal" || pq.tagNumber !== _T.SEQUENCE || !pq.children || pq.children.length !== 2) {
      fail("policyQualifiers element must be a PolicyQualifierInfo SEQUENCE { policyQualifierId, qualifier } (RFC 5280 sec. 4.2.1.4)");
    }
    try { asn1.read.oid(pq.children[0]); } catch (e) { fail("PolicyQualifierInfo must lead with a policyQualifierId OID", e); }
  });
}

var DISPLAY_TEXT_MAX = 200;
function displayTextChars(str) { return _arrayFrom(str).length; }

// @internal
var _DISPLAY_TEXT_TAGS = null;
function _isDisplayTextNode(n) {
  if (!_DISPLAY_TEXT_TAGS) {
    _DISPLAY_TEXT_TAGS = _create(null);
    _DISPLAY_TEXT_TAGS[_T.IA5_STRING] = 1; _DISPLAY_TEXT_TAGS[_T.VISIBLE_STRING] = 1;
    _DISPLAY_TEXT_TAGS[_T.BMP_STRING] = 1; _DISPLAY_TEXT_TAGS[_T.UTF8_STRING] = 1;
  }
  return !!n && n.tagClass === "universal" && _DISPLAY_TEXT_TAGS[n.tagNumber] === 1;
}
function _dtEntry(field, node) {
  var text;
  // allow:swallow-unverified an undecodable DisplayText keeps its tag and drops its text; the callers branch on text === null
  try { text = asn1.read.string(node); } catch (_e) { text = null; }
  return { field: field, tagNumber: node.tagNumber, text: text, chars: text === null ? null : displayTextChars(text) };
}
function _noticeNumbers(node) {
  if (!node || node.tagClass !== "universal" || node.tagNumber !== _T.SEQUENCE || !node.children) return null;
  var nums = [], ok = true;
  _forEach(node.children, function (n) {
    // allow:swallow-unverified a non-INTEGER member makes the whole reference undecodable, and the caller falls back
    try { _push(nums, _String(asn1.read.integer(n))); } catch (_e) { ok = false; }
  });
  return ok ? nums : null;
}
function userNoticeTexts(qualifier) {
  if (!qualifier || qualifier.tagClass !== "universal" || qualifier.tagNumber !== _T.SEQUENCE || !qualifier.children) return [];
  var kids = qualifier.children;
  if (kids.length > 2) return [];
  var i = 0, out = [];
  if (i < kids.length && kids[i].tagClass === "universal" && kids[i].tagNumber === _T.SEQUENCE) {
    var nr = kids[i];
    if (!nr.children || nr.children.length !== 2 || !_isDisplayTextNode(nr.children[0])) return [];
    var org = _dtEntry("organization", nr.children[0]);
    org.noticeNumbers = _noticeNumbers(nr.children[1]);
    _push(out, org);
    i++;
  }
  if (i < kids.length) {
    if (!_isDisplayTextNode(kids[i])) return [];
    _push(out, _dtEntry("explicitText", kids[i]));
    i++;
  }
  return i === kids.length ? out : [];
}

function _decodeHelpers(ns) {
  function decodeTop(buf, code, what) {
    var n;
    try { n = asn1.decode(buf); }
    catch (e) { throw ns.E(code, "malformed " + what + " value: " + ((e && e.message) || _String(e)), e); }
    return n;
  }
  function seqChildren(buf, code, what) {
    var n = decodeTop(buf, code, what);
    if (n.tagClass !== "universal" || n.tagNumber !== _T.SEQUENCE || !n.children) {
      throw ns.E(code, what + " must be a SEQUENCE (RFC 5280 sec. 4.2.1)");
    }
    return n.children;
  }
  function readInt(node, code, what) {
    try { return asn1.read.integer(node); }
    catch (e) { throw ns.E(code, what + " must be an INTEGER", e); }
  }
  function O(nm) {
    var d = ns.oid.byName(nm);
    if (typeof d !== "string") throw new TypeError("pki.schema.pkix: " + _stringify(nm) + " is not a registered OID name");
    return d;
  }
  return { decodeTop: decodeTop, seqChildren: seqChildren, readInt: readInt, O: O };
}

function certExtensionDecoders(ns) {
  var GN_SUBTREE = generalName(ns, { decodeValue: true, subtreeBase: true, code: ns.prefix + "/bad-name-constraints" });
  var _h = _decodeHelpers(ns), decodeTop = _h.decodeTop, seqChildren = _h.seqChildren, readInt = _h.readInt, O = _h.O;

  function basicConstraints(buf) {
    var C = ns.prefix + "/bad-basic-constraints";
    var kids = seqChildren(buf, C, "BasicConstraints");
    var i = 0, cA = false, pathLen = null;
    if (kids[i] && kids[i].tagClass === "universal" && kids[i].tagNumber === _T.BOOLEAN) {
      var v;
      try { v = asn1.read.boolean(kids[i]); } catch (e) { throw ns.E(C, "BasicConstraints cA must be a BOOLEAN", e); }
      if (v !== true) throw ns.E(C, "BasicConstraints cA DEFAULT FALSE must be omitted, not an explicit FALSE (X.690 sec. 11.5)");
      cA = true; i++;
    }
    if (kids[i] && kids[i].tagClass === "universal" && kids[i].tagNumber === _T.INTEGER) {
      if (!cA) throw ns.E(C, "BasicConstraints pathLenConstraint is only permitted when cA is TRUE (RFC 5280 sec. 4.2.1.9)");
      var pl = readInt(kids[i], C, "pathLenConstraint");
      pathLen = guard.range.uint31(pl, ns.E, C, "BasicConstraints pathLenConstraint (RFC 5280 sec. 4.2.1.9)"); i++;
    }
    if (i !== kids.length) throw ns.E(C, "BasicConstraints has unexpected trailing fields");
    return { cA: cA, pathLenConstraint: pathLen };
  }

  var KU_BITS = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
    "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
  function keyUsage(buf) {
    var C = ns.prefix + "/bad-key-usage";
    var n = decodeTop(buf, C, "KeyUsage");
    if (n.tagClass !== "universal" || n.tagNumber !== _T.BIT_STRING) throw ns.E(C, "KeyUsage must be a BIT STRING (RFC 5280 sec. 4.2.1.3)");
    var bs;
    try { bs = asn1.read.bitString(n); } catch (e) { throw ns.E(C, "KeyUsage must be a well-formed BIT STRING", e); }
    var anyBit = false;
    for (var z = 0; z < bs.bytes.length; z++) { if (bs.bytes[z] !== 0) { anyBit = true; break; } }
    if (!anyBit) throw ns.E(C, "KeyUsage must assert at least one bit (RFC 5280 sec. 4.2.1.3)");
    schema.assertMinimalNamedBits(bs.unusedBits, bs.bytes, function (m) { throw ns.E(C, m); });
    var out = {};
    _forEach(KU_BITS, function (nm, bit) {
      var byte = bit >> 3, mask = 0x80 >> (bit & 7);
      out[nm] = byte < bs.bytes.length && (bs.bytes[byte] & mask) !== 0;
    });
    var reserved = false;
    for (var bit2 = KU_BITS.length; bit2 < bs.bytes.length * 8 && !reserved; bit2++) {
      if ((bs.bytes[bit2 >> 3] & (0x80 >> (bit2 & 7))) !== 0) reserved = true;
    }
    out.reservedBitsSet = reserved;
    return out;
  }

  function subtreeList(node, C) {
    if (!node.children || node.children.length < 1) throw ns.E(C, "NameConstraints permittedSubtrees/excludedSubtrees must be a non-empty GeneralSubtrees (SIZE 1..MAX, RFC 5280 sec. 4.2.1.10)");
    return _map(node.children, function (st) {
      if (st.tagClass !== "universal" || st.tagNumber !== _T.SEQUENCE || !st.children || st.children.length < 1) {
        throw ns.E(C, "GeneralSubtree must be a SEQUENCE { base, minimum?, maximum? }");
      }
      var base = schema.walk(GN_SUBTREE, st.children[0], ns);
      for (var j = 1; j < st.children.length; j++) {
        var f = st.children[j];
        if (f.tagClass !== "context" || (f.tagNumber !== 0 && f.tagNumber !== 1)) throw ns.E(C, "GeneralSubtree has an unexpected field");
        if (f.tagNumber === 0) throw ns.E(C, "GeneralSubtree minimum DEFAULT 0 must be omitted (RFC 5280 sec. 4.2.1.10 requires minimum = 0)");
        if (f.tagNumber === 1) throw ns.E(C, "GeneralSubtree maximum is not permitted in the RFC 5280 profile (sec. 4.2.1.10)");
      }
      return { base: base };
    });
  }
  function nameConstraints(buf) {
    var C = ns.prefix + "/bad-name-constraints";
    var kids = seqChildren(buf, C, "NameConstraints");
    var permitted = [], excluded = [], sawP = false, sawE = false, ncLastTag = -1;
    _forEach(kids, function (k) {
      if (k.tagClass !== "context" || !k.children) throw ns.E(C, "NameConstraints fields are [0] permittedSubtrees / [1] excludedSubtrees");
      if (k.tagNumber <= ncLastTag) throw ns.E(C, "NameConstraints fields must be unique and in ascending order (DER)");
      ncLastTag = k.tagNumber;
      if (k.tagNumber === 0) { if (sawP) throw ns.E(C, "duplicate permittedSubtrees"); sawP = true; permitted = subtreeList(k, C); }
      else if (k.tagNumber === 1) { if (sawE) throw ns.E(C, "duplicate excludedSubtrees"); sawE = true; excluded = subtreeList(k, C); }
      else throw ns.E(C, "NameConstraints has an unexpected field [" + k.tagNumber + "]");
    });
    if (!sawP && !sawE) throw ns.E(C, "NameConstraints must contain permittedSubtrees or excludedSubtrees (RFC 5280 sec. 4.2.1.10)");
    return { permittedSubtrees: permitted, excludedSubtrees: excluded };
  }

  function certificatePolicies(buf) {
    var C = ns.prefix + "/bad-policy";
    var kids = seqChildren(buf, C, "CertificatePolicies");
    if (kids.length < 1) throw ns.E(C, "CertificatePolicies must contain at least one PolicyInformation (RFC 5280 sec. 4.2.1.4)");
    var seen = _create(null);
    return _map(kids, function (pi) {
      if (pi.tagClass !== "universal" || pi.tagNumber !== _T.SEQUENCE || !pi.children || pi.children.length < 1 || pi.children.length > 2) {
        throw ns.E(C, "PolicyInformation must be a SEQUENCE { policyIdentifier, policyQualifiers? }");
      }
      var pid;
      try { pid = asn1.read.oid(pi.children[0]); } catch (e) { throw ns.E(C, "PolicyInformation policyIdentifier must be an OBJECT IDENTIFIER", e); }
      if (seen[pid]) throw ns.E(C, "duplicate policy OID " + pid + " (RFC 5280 sec. 4.2.1.4)");
      seen[pid] = true;
      var qualifiers = null;
      if (pi.children.length > 1) {
        var q = pi.children[1];
        assertPolicyQualifiers(q, function (msg, cause) { throw ns.E(C, msg, cause); });
        qualifiers = q.bytes;
      }
      return { policyIdentifier: pid, qualifiersBytes: qualifiers };
    });
  }

  function policyMappings(buf) {
    var C = ns.prefix + "/bad-policy";
    var kids = seqChildren(buf, C, "PolicyMappings");
    if (kids.length < 1) throw ns.E(C, "PolicyMappings must contain at least one mapping (RFC 5280 sec. 4.2.1.5)");
    return _map(kids, function (mp) {
      if (mp.tagClass !== "universal" || mp.tagNumber !== _T.SEQUENCE || !mp.children || mp.children.length !== 2) {
        throw ns.E(C, "policy mapping must be a SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }");
      }
      var idp, sdp;
      try { idp = asn1.read.oid(mp.children[0]); sdp = asn1.read.oid(mp.children[1]); }
      catch (e) { throw ns.E(C, "policy mapping members must be OBJECT IDENTIFIERs", e); }
      return { issuerDomainPolicy: idp, subjectDomainPolicy: sdp };
    });
  }

  function policyConstraints(buf) {
    var C = ns.prefix + "/bad-policy";
    var kids = seqChildren(buf, C, "PolicyConstraints");
    if (kids.length < 1) throw ns.E(C, "PolicyConstraints must contain at least one field (RFC 5280 sec. 4.2.1.11)");
    var rep = null, ipm = null, pcLastTag = -1;
    _forEach(kids, function (k) {
      if (k.tagClass !== "context") throw ns.E(C, "PolicyConstraints fields are context-tagged [0]/[1]");
      if (k.tagNumber <= pcLastTag) throw ns.E(C, "PolicyConstraints fields must be unique and in ascending order (DER)");
      pcLastTag = k.tagNumber;
      var v;
      try { v = asn1.read.integerImplicit(k, k.tagNumber); } catch (e) { throw ns.E(C, "PolicyConstraints field must be an INTEGER", e); }
      var skip = guard.range.uint31(v, ns.E, C, "PolicyConstraints skip count (RFC 5280 sec. 4.2.1.11)");
      if (k.tagNumber === 0) rep = skip;
      else if (k.tagNumber === 1) ipm = skip;
      else throw ns.E(C, "PolicyConstraints has an unexpected field [" + k.tagNumber + "]");
    });
    return { requireExplicitPolicy: rep, inhibitPolicyMapping: ipm };
  }

  function inhibitAnyPolicy(buf) {
    var C = ns.prefix + "/bad-policy";
    var n = decodeTop(buf, C, "InhibitAnyPolicy");
    if (n.tagClass !== "universal" || n.tagNumber !== _T.INTEGER) throw ns.E(C, "InhibitAnyPolicy must be an INTEGER (RFC 5280 sec. 4.2.1.14)");
    var v = readInt(n, C, "InhibitAnyPolicy");
    return guard.range.uint31(v, ns.E, C, "InhibitAnyPolicy skip count (RFC 5280 sec. 4.2.1.14)");
  }

  function altName(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var n = decodeTop(buf, C, "GeneralNames");
    return schema.walk(generalNames(ns, { decodeValue: true, code: C }), n, ns).result;
  }

  function authorityInfoAccess(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var descs = seqChildren(buf, C, "AuthorityInfoAccessSyntax");
    if (descs.length < 1) throw ns.E(C, "AuthorityInfoAccessSyntax must contain at least one AccessDescription (RFC 5280 sec. 4.2.2.1, SIZE(1..MAX))");
    var GN = generalName(ns, { decodeValue: true, code: C });
    return _map(descs, function (d) {
      if (d.tagClass !== "universal" || d.tagNumber !== _T.SEQUENCE || !d.children || d.children.length !== 2) {
        throw ns.E(C, "AccessDescription must be a SEQUENCE { accessMethod, accessLocation } (RFC 5280 sec. 4.2.2.1)");
      }
      var method;
      try { method = asn1.read.oid(d.children[0]); }
      catch (e) { throw ns.E(C, "AccessDescription accessMethod must be an OBJECT IDENTIFIER", e); }
      var loc = schema.walk(GN, d.children[1], ns);
      return { accessMethod: method, accessLocation: { tag: loc.tagNumber, value: loc.value } };
    });
  }

  function extKeyUsage(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var kids = seqChildren(buf, C, "ExtKeyUsage");
    if (kids.length < 1) throw ns.E(C, "ExtKeyUsage must contain at least one KeyPurposeId (RFC 5280 sec. 4.2.1.12)");
    return _map(kids, function (k) {
      try { return asn1.read.oid(k); } catch (e) { throw ns.E(C, "ExtKeyUsage KeyPurposeId must be an OBJECT IDENTIFIER", e); }
    });
  }

  function authorityKeyIdentifier(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var kids = seqChildren(buf, C, "AuthorityKeyIdentifier");
    var out = { keyIdentifier: null, authorityCertIssuer: null, authorityCertSerialNumber: null };
    var lastTag = -1;
    _forEach(kids, function (k) {
      if (k.tagClass !== "context") throw ns.E(C, "AuthorityKeyIdentifier fields are context-tagged");
      if (k.tagNumber <= lastTag) throw ns.E(C, "AuthorityKeyIdentifier fields must be unique and in ascending order (DER)");
      lastTag = k.tagNumber;
      if (k.tagNumber === 0) { try { out.keyIdentifier = _bufferFrom(asn1.read.octetStringImplicit(k, 0)); } catch (e) { throw ns.E(C, "AuthorityKeyIdentifier keyIdentifier [0] must be an IMPLICIT OCTET STRING", e); } }
      else if (k.tagNumber === 1) out.authorityCertIssuer = schema.walk(generalNames(ns, { implicitTag: 1, decodeValue: true, code: C }), k, ns).result;
      else if (k.tagNumber === 2) { try { out.authorityCertSerialNumber = asn1.read.integerImplicit(k, 2); } catch (e) { throw ns.E(C, "authorityCertSerialNumber must be an INTEGER", e); } }
      else throw ns.E(C, "AuthorityKeyIdentifier has an unexpected field [" + k.tagNumber + "]");
    });
    if ((out.authorityCertIssuer === null) !== (out.authorityCertSerialNumber === null)) {
      throw ns.E(C, "AuthorityKeyIdentifier authorityCertIssuer and authorityCertSerialNumber must both be present or both absent (RFC 5280 sec. 4.2.1.1)");
    }
    return out;
  }

  function subjectKeyIdentifier(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var n = decodeTop(buf, C, "SubjectKeyIdentifier");
    try { return _bufferConcat([asn1.read.octetString(n)]); }
    catch (e) { throw ns.E(C, "SubjectKeyIdentifier must be an OCTET STRING (RFC 5280 sec. 4.2.1.2)", e); }
  }

  function sctList(buf) {
    var C = ns.prefix + "/bad-extension-value";
    try { return ct.parseSctList(buf); }
    catch (e) { throw ns.E(C, "malformed signedCertificateTimestampList extension value (RFC 6962 sec. 3.3)", e); }
  }

  function precertPoison(buf) {
    var C = ns.prefix + "/bad-extension-value";
    var n = decodeTop(buf, C, "PrecertificatePoison");
    try { asn1.read.nullValue(n); }
    catch (e) { throw ns.E(C, "the precertificate poison extension value must be ASN.1 NULL (RFC 6962 sec. 3.1)", e); }
    return { poison: true };
  }

  function crlDistributionPoints(buf) {
    var C = ns.prefix + "/bad-crl-distribution-points";
    var kids = seqChildren(buf, C, "CRLDistributionPoints");
    if (kids.length < 1) throw ns.E(C, "CRLDistributionPoints must contain at least one DistributionPoint (RFC 5280 sec. 4.2.1.13)");
    return _map(kids, function (dp) {
      if (dp.tagClass !== "universal" || dp.tagNumber !== _T.SEQUENCE || !dp.children) {
        throw ns.E(C, "DistributionPoint must be a SEQUENCE { distributionPoint?, reasons?, cRLIssuer? }");
      }
      var out = { distributionPoint: null, reasons: null, cRLIssuer: null };
      var lastTag = -1;
      _forEach(dp.children, function (f) {
        if (f.tagClass !== "context") throw ns.E(C, "DistributionPoint fields are context-tagged [0]/[1]/[2]");
        if (f.tagNumber <= lastTag) throw ns.E(C, "DistributionPoint fields must be unique and in ascending order (DER)");
        lastTag = f.tagNumber;
        if (f.tagNumber === 0) {
          if (!f.children || f.children.length !== 1) throw ns.E(C, "DistributionPoint distributionPoint [0] must wrap exactly one DistributionPointName");
          out.distributionPoint = distributionPointName(ns, f.children[0], C);
        } else if (f.tagNumber === 1) {
          var bs;
          try { bs = asn1.read.bitStringImplicit(f, 1); }
          catch (e) { throw ns.E(C, "DistributionPoint reasons [1] must be an IMPLICIT ReasonFlags BIT STRING", e); }
          schema.assertMinimalNamedBits(bs.unusedBits, bs.bytes, function (msg) { throw ns.E(C, "DistributionPoint reasons: " + msg); });
          out.reasons = { unusedBits: bs.unusedBits, bytes: bs.bytes };
        } else if (f.tagNumber === 2) {
          out.cRLIssuer = schema.walk(generalNames(ns, { implicitTag: 2, decodeValue: true, code: C, what: "DistributionPoint cRLIssuer" }), f, ns).result;
        } else {
          throw ns.E(C, "DistributionPoint has an unexpected field [" + f.tagNumber + "]");
        }
      });
      if (out.distributionPoint === null && out.cRLIssuer === null) {
        throw ns.E(C, "a DistributionPoint must include distributionPoint or cRLIssuer -- it MUST NOT consist of only the reasons field (RFC 5280 sec. 4.2.1.13)");
      }
      return out;
    });
  }

  function _qcStr(node, tag, C, what) {
    if (!node || node.tagClass !== "universal" || node.tagNumber !== tag) throw ns.E(C, what);
    try { return asn1.read.string(node); } catch (e) { throw ns.E(C, what, e); }
  }
  function _qcOidSeq(node, C, what) {
    if (!node || node.tagClass !== "universal" || node.tagNumber !== _T.SEQUENCE || !node.children || !node.children.length) throw ns.E(C, what + " must be a non-empty SEQUENCE OF OBJECT IDENTIFIER");
    return _map(node.children, function (c) {
      if (c.tagClass !== "universal" || c.tagNumber !== _T.OBJECT_IDENTIFIER) throw ns.E(C, what + " members must be OBJECT IDENTIFIERs");
      try { return asn1.read.oid(c); } catch (e) { throw ns.E(C, what + " member is not a valid OID", e); }
    });
  }
  function _qcPresenceOnly(nm) { return function (node, C) { if (node) throw ns.E(C, nm + " carries no statementInfo (ETSI EN 319 412-5)"); return null; }; }
  function _qcSemantics(node, C) {
    if (node === null) return null;
    if (node.tagClass !== "universal" || node.tagNumber !== _T.SEQUENCE || !node.children || !node.children.length) throw ns.E(C, "SemanticsInformation must be a SEQUENCE with at least one field (RFC 3739 sec. 3.2.6.1)");
    var sid = null, i = 0;
    if (node.children[0].tagClass === "universal" && node.children[0].tagNumber === _T.OBJECT_IDENTIFIER) {
      try { sid = asn1.read.oid(node.children[0]); } catch (e) { throw ns.E(C, "SemanticsInformation semanticsIdentifier must be an OID", e); }
      i++;
    }
    var nras = [];
    if (node.children[i]) {
      nras = schema.walk(generalNames(ns, { decodeValue: true, code: C }), node.children[i], ns).result.names;
      i++;
    }
    if (i !== node.children.length) throw ns.E(C, "SemanticsInformation has unexpected trailing fields");
    return { semanticsIdentifier: sid, nameRegistrationAuthorities: nras };
  }
  var qcInfoByOid = _create(null);
  qcInfoByOid[O("qcCompliance")] = _qcPresenceOnly("QcCompliance");
  qcInfoByOid[O("qcSSCD")] = _qcPresenceOnly("QcSSCD");
  qcInfoByOid[O("qcsPkixQCSyntaxV1")] = _qcSemantics;
  qcInfoByOid[O("qcsPkixQCSyntaxV2")] = _qcSemantics;
  qcInfoByOid[O("qcType")] = function (node, C) {
    var oids = _qcOidSeq(node, C, "QcType");
    return { types: oids, typeNames: _map(oids, function (d) { return ns.oid.name(d) || null; }) };
  };
  qcInfoByOid[O("qcRetentionPeriod")] = function (node, C) {
    if (!node) throw ns.E(C, "QcRetentionPeriod requires an INTEGER statementInfo");
    return { years: guard.range.uint31(readInt(node, C, "QcRetentionPeriod"), ns.E, C, "QcRetentionPeriod (years)") };
  };
  qcInfoByOid[O("qcLimitValue")] = function (node, C) {
    if (!node || node.tagClass !== "universal" || node.tagNumber !== _T.SEQUENCE || !node.children || node.children.length !== 3) throw ns.E(C, "QcLimitValue must be a MonetaryValue SEQUENCE { currency, amount, exponent }");
    var cur = node.children[0], currency;
    if (cur.tagClass === "universal" && cur.tagNumber === _T.PRINTABLE_STRING) {
      currency = _qcStr(cur, _T.PRINTABLE_STRING, C, "QcLimitValue alphabetic currency must be a PrintableString");
      if (currency.length !== 3) throw ns.E(C, "QcLimitValue alphabetic currency must be a 3-letter ISO 4217 code");
    } else if (cur.tagClass === "universal" && cur.tagNumber === _T.INTEGER) {
      currency = guard.range.int(readInt(cur, C, "QcLimitValue numeric currency"), 1n, 999n, ns.E, C, "QcLimitValue numeric currency (ISO 4217, 1..999)");
    } else throw ns.E(C, "QcLimitValue currency must be a PrintableString(3) or INTEGER(1..999)");
    return {
      currency: currency,
      amount: guard.range.int(readInt(node.children[1], C, "QcLimitValue amount"), 0n, 9007199254740991n, ns.E, C, "QcLimitValue amount"),
      exponent: guard.range.int(readInt(node.children[2], C, "QcLimitValue exponent"), -9007199254740991n, 9007199254740991n, ns.E, C, "QcLimitValue exponent"),
    };
  };
  qcInfoByOid[O("qcCClegislation")] = function (node, C) {
    if (!node || node.tagClass !== "universal" || node.tagNumber !== _T.SEQUENCE || !node.children || !node.children.length) throw ns.E(C, "QcCClegislation must be a non-empty SEQUENCE OF CountryName");
    return { countries: _map(node.children, function (c) { var v = _qcStr(c, _T.PRINTABLE_STRING, C, "QcCClegislation CountryName must be a PrintableString"); if (v.length !== 2) throw ns.E(C, "QcCClegislation CountryName must be a 2-letter ISO 3166-1 code"); return v; }) };
  };
  qcInfoByOid[O("qcPDS")] = function (node, C) {
    if (!node || node.tagClass !== "universal" || node.tagNumber !== _T.SEQUENCE || !node.children || !node.children.length) throw ns.E(C, "QcPDS must be a non-empty SEQUENCE OF PdsLocation");
    return { locations: _map(node.children, function (loc) {
      if (loc.tagClass !== "universal" || loc.tagNumber !== _T.SEQUENCE || !loc.children || loc.children.length !== 2) throw ns.E(C, "a QcPDS PdsLocation must be a SEQUENCE { url, language }");
      var lang = _qcStr(loc.children[1], _T.PRINTABLE_STRING, C, "a QcPDS language must be a PrintableString");
      if (lang.length !== 2) throw ns.E(C, "a QcPDS language must be a 2-letter ISO 639-1 code");
      return { url: _qcStr(loc.children[0], _T.IA5_STRING, C, "a QcPDS url must be an IA5String"), language: lang };
    }) };
  };
  qcInfoByOid[O("qcIdentMethod")] = function (node, C) {
    var oids = _qcOidSeq(node, C, "QcIdentMethod");
    return { methods: oids, methodNames: _map(oids, function (d) { return ns.oid.name(d) || null; }) };
  };
  qcInfoByOid[O("qcQSCDlegislation")] = function (node, C) {
    if (!node || node.tagClass !== "universal" || node.tagNumber !== _T.SEQUENCE || !node.children || !node.children.length) throw ns.E(C, "QcQSCDlegislation must be a non-empty SEQUENCE OF CountryName");
    return { countries: _map(node.children, function (c) { var v = _qcStr(c, _T.PRINTABLE_STRING, C, "QcQSCDlegislation CountryName must be a PrintableString"); if (v.length !== 2) throw ns.E(C, "QcQSCDlegislation CountryName must be a 2-letter ISO 3166-1 code"); return v; }) };
  };
  function qcStatements(buf) {
    var C = ns.prefix + "/bad-qc-statements", CS = ns.prefix + "/bad-qc-statement";
    var kids = seqChildren(buf, C, "QCStatements");
    if (!kids.length) throw ns.E(C, "QCStatements must contain at least one QCStatement (RFC 3739 sec. 3.2.6)");
    var out = [];
    for (var i = 0; i < kids.length; i++) {
      var st = kids[i];
      if (st.tagClass !== "universal" || st.tagNumber !== _T.SEQUENCE || !st.children || st.children.length < 1 || st.children.length > 2) {
        throw ns.E(CS, "each QCStatement must be a SEQUENCE of a statementId and an OPTIONAL statementInfo");
      }
      var id;
      try { id = asn1.read.oid(st.children[0]); } catch (e) { throw ns.E(CS, "a QCStatement statementId must be an OBJECT IDENTIFIER", e); }
      var infoNode = st.children.length === 2 ? st.children[1] : null;
      var decoder = qcInfoByOid[id];
      var info = decoder ? decoder(infoNode, CS) : { opaque: true, bytes: infoNode ? infoNode.bytes : null };
      _push(out, { statementId: id, name: ns.oid.name(id) || null, info: info });
    }
    return out;
  }

  function msCertificateTemplate(buf) {
    var C = ns.prefix + "/bad-ms-certificate-template";
    var kids = seqChildren(buf, C, "CertificateTemplate");
    if (!kids.length || kids.length > 3) throw ns.E(C, "CertificateTemplateOID must be a SEQUENCE of a templateID and up to two version INTEGERs");
    if (kids[0].tagClass !== "universal" || kids[0].tagNumber !== _T.OBJECT_IDENTIFIER) throw ns.E(C, "CertificateTemplateOID templateID must be an OBJECT IDENTIFIER");
    var id;
    try { id = asn1.read.oid(kids[0]); } catch (e) { throw ns.E(C, "CertificateTemplateOID templateID must be an OBJECT IDENTIFIER", e); }
    function ver(i, what) {
      if (!kids[i]) return null;
      if (kids[i].tagClass !== "universal" || kids[i].tagNumber !== _T.INTEGER) throw ns.E(C, what + " must be an INTEGER");
      return guard.range.int(readInt(kids[i], C, what), 0n, 4294967295n, ns.E, C, what);
    }
    return { templateID: id, name: ns.oid.name(id) || null, templateMajorVersion: ver(1, "templateMajorVersion"), templateMinorVersion: ver(2, "templateMinorVersion") };
  }

  function msEnrollCertType(buf) {
    var C = ns.prefix + "/bad-ms-enroll-cert-type";
    var n = decodeTop(buf, C, "EnrollCertType");
    if (n.tagClass !== "universal" || n.tagNumber !== _T.BMP_STRING) throw ns.E(C, "the enroll cert-type name must be a BMPString");
    try { return asn1.read.string(n); } catch (e) { throw ns.E(C, "the enroll cert-type name must be a well-formed BMPString", e); }
  }

  function msCaVersion(buf) {
    var C = ns.prefix + "/bad-ms-ca-version";
    var n = decodeTop(buf, C, "CACertVersion");
    if (n.tagClass !== "universal" || n.tagNumber !== _T.INTEGER) throw ns.E(C, "CACertVersion must be an INTEGER");
    var v = guard.range.int(readInt(n, C, "CACertVersion"), 0n, 4294967295n, ns.E, C, "CACertVersion (DWORD)");
    return { caVersion: v, caKeyIndex: v >>> 16, certIndex: v & 0xffff };
  }

  function msPreviousCertHash(buf) {
    var C = ns.prefix + "/bad-ms-previous-cert-hash";
    var n = decodeTop(buf, C, "CAPrevCertHash");
    var hash;
    try { hash = _bufferConcat([asn1.read.octetString(n)]); }
    catch (e) { throw ns.E(C, "CAPrevCertHash must be an OCTET STRING", e); }
    if (hash.length !== 20) throw ns.E(C, "CAPrevCertHash must be a 20-octet SHA-1 certificate thumbprint");
    return hash;
  }

  var byOid = _create(null);
  byOid[O("qcStatements")] = qcStatements;
  byOid[O("basicConstraints")] = basicConstraints;
  byOid[O("keyUsage")] = keyUsage;
  byOid[O("nameConstraints")] = nameConstraints;
  byOid[O("certificatePolicies")] = certificatePolicies;
  byOid[O("policyMappings")] = policyMappings;
  byOid[O("policyConstraints")] = policyConstraints;
  byOid[O("inhibitAnyPolicy")] = inhibitAnyPolicy;
  byOid[O("subjectAltName")] = altName;
  byOid[O("issuerAltName")] = altName;
  byOid[O("extKeyUsage")] = extKeyUsage;
  byOid[O("authorityKeyIdentifier")] = authorityKeyIdentifier;
  byOid[O("subjectKeyIdentifier")] = subjectKeyIdentifier;
  byOid[O("signedCertificateTimestampList")] = sctList;
  byOid[O("precertificatePoison")] = precertPoison;
  byOid[O("cRLDistributionPoints")] = crlDistributionPoints;
  byOid[O("freshestCRL")] = crlDistributionPoints;
  byOid[O("authorityInfoAccess")] = authorityInfoAccess;
  byOid[O("msCertificateTemplate")] = msCertificateTemplate;
  byOid[O("msEnrollCertType")] = msEnrollCertType;
  byOid[O("msCaVersion")] = msCaVersion;
  byOid[O("msPreviousCertHash")] = msPreviousCertHash;
  byOid[O("msApplicationPolicies")] = certificatePolicies;
  return { byOid: byOid };
}

function extension(ns) {
  return schema.decode(function (ext) {
    if (!ext.children || ext.tagClass !== "universal" || ext.tagNumber !== asn1.TAGS.SEQUENCE ||
        ext.children.length < 2 || ext.children.length > 3) {
      throw ns.E(ns.prefix + "/bad-extension", "Extension must be a SEQUENCE of {extnID, critical?, extnValue}");
    }
    var extnID = asn1.read.oid(ext.children[0]);
    var critical = false, valueNode;
    if (ext.children.length === 3) {
      critical = asn1.read.boolean(ext.children[1]);
      if (critical === false) throw ns.E(ns.prefix + "/bad-extension", "an explicit critical FALSE must be omitted (BOOLEAN DEFAULT FALSE)");
      valueNode = ext.children[2];
    } else {
      valueNode = ext.children[1];
    }
    return { oid: extnID, name: ns.oid.name(extnID) || null, critical: critical, value: asn1.read.octetString(valueNode) };
  });
}
function extensions(ns, opts) {
  opts = opts || {};
  var EXT = extension(ns);
  var extOpts = {
    min: 1, code: ns.prefix + "/bad-extensions", what: "Extensions",
    unique: function (it) { return it.value.oid; }, dupCode: ns.prefix + "/duplicate-extension",
    build: function (m) { return _map(m.items, function (it) { return it.value; }); },
  };
  if (opts.implicitTag != null) return schema.implicitSeqOf(opts.implicitTag, EXT, extOpts);
  return schema.seqOf(EXT, _assign({ assert: "sequence" }, extOpts));
}

function spki(ns, opts) {
  opts = opts || {};
  return schema.seq([
    schema.field("algorithm", algorithmIdentifier(ns)),
    schema.field("subjectPublicKey", schema.bitString()),
  ], {
    assert: opts.implicitTag != null ? "implicit" : "sequence", implicitTag: opts.implicitTag,
    arity: { exact: 2 }, code: ns.prefix + "/bad-spki", what: "SubjectPublicKeyInfo",
    build: function (m) {
      return {
        algorithm: m.fields.algorithm.value.result,
        publicKey: { unusedBits: m.fields.subjectPublicKey.value.unusedBits, bytes: m.fields.subjectPublicKey.value.bytes },
        bytes: opts.implicitTag != null ? asn1.sequenceTlv(m.node) : m.node.bytes,
      };
    },
  });
}

function attribute(ns, opts) {
  opts = opts || {};
  var minValues = opts.minValues === undefined ? 1 : opts.minValues;
  return schema.seq([
    schema.field("type", schema.oidLeaf()),
    schema.field("values", schema.setOf(schema.any(), { assert: "set", min: minValues, max: constants.LIMITS.ATTRIBUTE_MAX_VALUES,
      code: ns.prefix + "/bad-attribute-values", what: "attribute values" })),
  ], {
    assert: "sequence", arity: { exact: 2 }, code: ns.prefix + "/bad-attribute", what: "Attribute",
    build: function (m, ctx) {
      var t = m.fields.type.value;
      return {
        type: t,
        name: ctx.oid.name(t) || null,
        values: _map(m.fields.values.value.items, function (it) { return it.node.bytes; }),
      };
    },
  });
}

function signedEnvelopeTbs(root) {
  if (!schema.isUniversal(root, asn1.TAGS.SEQUENCE)) return null;
  if (!root.children || root.children.length !== 3) return null;
  var tbs = root.children[0];
  if (!tbs.children || !schema.isUniversal(tbs, asn1.TAGS.SEQUENCE)) return null;
  return tbs;
}

function rootSequenceChildren(root, minLen, maxLen) {
  if (!schema.isUniversal(root, asn1.TAGS.SEQUENCE) || !root.children) return null;
  var n = root.children.length;
  if (n < (minLen || 0)) return null;
  if (maxLen != null && n > maxLen) return null;
  return root.children;
}

function makeParser(opts) {
  return function (input) { return runParse(input, opts); };
}

function makeRecordingParser(opts, kind) {
  return guard.parsed.recordingParser(kind, makeParser(opts), opts.ErrorClass,
    opts.prefix + "/bad-input", "a " + opts.what);
}

function signedEnvelope(ns, tbsSchema, opts) {
  return schema.seq([
    schema.field("toBeSigned", tbsSchema),
    schema.field("signatureAlgorithm", algorithmIdentifier(ns)),
    schema.field("signatureValue", schema.bitString()),
  ], {
    assert: "sequence", arity: { exact: 3 }, code: opts.code, what: opts.what,
    build: function (m, ctx) {
      var tbsMatch = m.fields.toBeSigned.value;
      var sigBits = m.fields.signatureValue.value;
      return opts.build({
        tbsMatch: tbsMatch,
        tbsBytes: tbsMatch.node.bytes,
        outerSignatureAlgorithmBytes: m.fields.signatureAlgorithm.node.bytes,
        signatureAlgorithm: m.fields.signatureAlgorithm.value.result,
        signatureValue: { unusedBits: sigBits.unusedBits, bytes: sigBits.bytes },
      }, ctx);
    },
  });
}

function _isLdhLabel(s) {
  var n = s.length;
  if (n === 0) return false;
  for (var i = 0; i < n; i++) {
    var ch = _charAt(s, i);
    if ((ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9")) continue;
    if (ch === "-") { if (i === 0 || i === n - 1) return false; } else return false;
  }
  return true;
}

function dnsNameProblem(s) {
  if (typeof s !== "string" || !s.length) return "empty";
  if (s.length > 253) return "exceeds 253 octets";
  if (_hasWhitespace(s)) return "whitespace";
  if (_charAt(s, 0) === "." || _charAt(s, s.length - 1) === ".") return "leading/trailing dot";
  if (_strIndexOf(s, "_") !== -1) return "underscore forbidden in dNSName";
  var labels = _split(s, ".");
  for (var i = 0; i < labels.length; i++) {
    var label = labels[i];
    if (label.length === 0) return "empty label";
    if (label.length > 63) return "label exceeds 63 octets";
    if (i === 0 && label === "*") {
      if (labels.length < 2) return "bare wildcard";
      continue;
    }
    if (!_isLdhLabel(label)) return "invalid label syntax";
  }
  return null;
}

module.exports = {
  dnsNameProblem: dnsNameProblem,
  pemDecode: pemDecode,
  pemDecodeAll: pemDecodeAll,
  pemDecodeLenient: pemDecodeLenient,
  pemEncode: pemEncode,
  isJsWhitespace: _isJsWhitespace,
  stripBase64Whitespace: _stripB64Whitespace,
  charTable: _charTable,
  allCharsIn: _allCharsIn,
  coerceToDer: coerceToDer,
  isPemArmor: _isPemArmor,
  decodeRoot: decodeRoot,
  runParse: runParse,
  makeNS: makeNS,
  versionReader: versionReader,
  DN_SHORT: DN_SHORT,
  time: time,
  algorithmIdentifier: algorithmIdentifier,
  pbkdf2Params: pbkdf2Params,
  pbmac1Params: pbmac1Params,
  spki: spki,
  makeParser: makeParser,
  makeRecordingParser: makeRecordingParser,
  signedEnvelopeTbs: signedEnvelopeTbs,
  rootSequenceChildren: rootSequenceChildren,
  assertPolicyQualifiers: assertPolicyQualifiers,
  DISPLAY_TEXT_MAX: DISPLAY_TEXT_MAX,
  displayTextChars: displayTextChars,
  userNoticeTexts: userNoticeTexts,
  signedEnvelope: signedEnvelope,
  attrValueToString: attrValueToString,
  attributeTypeAndValue: attributeTypeAndValue,
  relativeDistinguishedName: relativeDistinguishedName,
  name: name,
  generalName: generalName,
  generalNames: generalNames,
  distributionPointName: distributionPointName,
  issuingDistributionPoint: issuingDistributionPoint,
  keyUsageOf: keyUsageOf,
  generalizedTime: generalizedTime,
  utf8Text: utf8Text,
  rawNonEmptySequence: rawNonEmptySequence,
  CRL_REASON_NAMES: CRL_REASON_NAMES,
  certExtensionDecoders: certExtensionDecoders,
  _decodeHelpers: _decodeHelpers,
  attribute: attribute,
  extension: extension,
  extensions: extensions,
};

