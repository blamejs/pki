// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.inspect
 * @nav        Tooling
 * @title      Inspect
 * @intro Human-readable inspection of a parsed certificate: the pure-JS
 *   equivalent of `openssl x509 -text`. `certificate(input)` ingests a PEM string,
 *   a DER Buffer, or an already-parsed certificate and returns a familiar
 *   OpenSSL-style report: version, serial, signature algorithm, the issuer and
 *   subject distinguished names, the validity window, the public-key details
 *   (curve or modulus size plus the raw point/modulus), every decoded extension
 *   with its critical flag, and the signature. It renders purely from the toolkit's
 *   own strict parser and two-way OID registry, with no OpenSSL dependency and no
 *   drift-prone second naming table, so it names extension and algorithm OIDs an
 *   OpenSSL build shows only as raw bytes. The format is stable and OpenSSL-*familiar*,
 *   never byte-identical to any one OpenSSL version (those disagree across
 *   releases). Rendering is best-effort: a malformed extension falls back to a hex
 *   dump and does not throw.
 * @spec RFC 5280
 * @card Read a certificate like `openssl x509 -text`, in pure JS.
 */

var frameworkError = require("./framework-error");
var constants = require("./constants");
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var crl = require("./schema-crl");
var csr = require("./schema-csr");
var cms = require("./schema-cms");
var schemaAll = require("./schema-all");
var pkix = require("./schema-pkix");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");

// The operations this report is assembled out of, captured at load. Until then each is an ordinary
// writable property, and a report is only evidence about a certificate if the functions that build
// it are the language's own: a replaced push or join drops the line an operator would have acted
// on, a replaced isBuffer routes real bytes to the "(empty)" arm, and a replaced String, toString
// or Date decides the serial, the key size and the validity window the report prints.
var _isBuffer = intrinsic.isBuffer;
var _isArray = intrinsic.isArray;
var _bufferFrom = intrinsic.bufferFrom;
var _bufferAlloc = intrinsic.bufferAlloc;
var _bufferConcat = intrinsic.bufferConcat;
var _keys = intrinsic.keys;
var _push = intrinsic.uncurry(Array.prototype.push);
var _forEach = intrinsic.forEach;
var _map = intrinsic.map;
var _every = intrinsic.every;
var _join = intrinsic.join;
var _arraySlice = intrinsic.arraySlice;
// A byte view carries its own iteration method, so the printable test is uncurried from the typed
// array prototype rather than the array one it would otherwise borrow.
var _viewEvery = intrinsic.uncurry(Uint8Array.prototype.every);
var _subarray = intrinsic.uncurry(Buffer.prototype.subarray);
var _bufToString = intrinsic.uncurry(Buffer.prototype.toString);
var _bigIntToString = intrinsic.uncurry(BigInt.prototype.toString);
var _toUpperCase = intrinsic.uncurry(String.prototype.toUpperCase);
var _strSplit = intrinsic.uncurry(String.prototype.split);
var _strReplace = intrinsic.uncurry(String.prototype.replace);
var _String = intrinsic.String;
var _BigInt = intrinsic.BigInt;
var _Date = intrinsic.Date;
var _isNaN = intrinsic.isNaN;
var _parseInt = intrinsic.parseInt;

// Display-naming conventions are centralized in pki.C.NAMES (shared with the strict
// parsers so the labels can't drift); this module only composes them.
var NAMES = constants.NAMES;

var InspectError = frameworkError.InspectError;
function _err(code, message, cause) { return new InspectError(code, message, cause); }

// A dedicated namespace + decoder set: the shared RFC 5280 extension decoders,
// composed exactly as path-validate / acme compose them. Decode failures here are
// caught by the renderer and fall back to a hex dump (inspection is best-effort).
var NS = pkix.makeNS("inspect", InspectError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
// Dispatch on the stable OID, not the display name: pki.oid.register() can override a built-in
// name, which would silently skip the userNotice rendering and hex-dump the notice instead.
var OID_UNOTICE = oid.byName("unotice");

// ---- formatting helpers ------------------------------------------------------

var HEX = "0123456789abcdef";
function _hexColon(buf, opts) {
  opts = opts || {};
  var hex = [];
  for (var i = 0; i < buf.length; i++) {
    var b = buf[i], s = HEX[(b >> 4) & 0xf] + HEX[b & 0xf];
    _push(hex, opts.upper ? _toUpperCase(s) : s);
  }
  if (!opts.wrap) return _join(hex, ":");
  // Wrap at `opts.wrap` bytes per line, each line indented by `opts.indent`.
  var pad = " ".repeat(opts.indent || 0), lines = [];
  for (var j = 0; j < hex.length; j += opts.wrap) {
    var chunk = _join(_arraySlice(hex, j, j + opts.wrap), ":");
    _push(lines, pad + chunk + (j + opts.wrap < hex.length ? ":" : ""));
  }
  return _join(lines, "\n");
}

// Coverage residual: two _hexColon default arms are unreachable through the public API.
//   * `opts = opts || {}`. All call sites pass an explicit opts object literal, so the
//     `|| {}` default never fires.
//   * `" ".repeat(opts.indent || 0)`. Every wrap-mode caller passes a positive indent
//     (pad.length + 8 >= 8, or inner.length == 16), so `opts.indent` is never falsy.

// Control-byte neutralization for a GeneralName string value routes through the
// guard family (the guard-shape-reinlined detector protects the shape).
// @guard-via guard\.name\.escape
var _clean = guard.name.escapeControlBytes;

// The DN display string. pki.schema.pkix already assembles a fully RFC 4514-escaped
// dn (short names from pki.C.NAMES.DN_SHORT, values escaped via guard.name.escapeDnValue,
// with the '#'-hex / leading-'\' sentinel handled), so reuse it and never re-escape
// the already-escaped values (which would double-escape a leading '#' / '\').
function _dnString(name) { return (name && name.dn) || ""; }

var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function _two(n) { return (n < 10 ? "0" : "") + n; }
// OpenSSL date: "Jul  4 07:00:27 2026 GMT" (month, space-padded day, time, year, GMT).
function _date(iso) {
  // Rebuilt from the instant the value holds, so every field below is read off a Date of this
  // realm. The calendar methods are ordinary ones a subclass answers, and a parsed structure can
  // carry a Date a caller supplied, so reading them off that value let it decide the date printed
  // beside a certificate rather than the one the certificate carries.
  var held = guard.time.isDate(iso) ? guard.time.instantOf(iso) : Date.parse(_String(iso));
  if (_isNaN(held)) return _String(iso);
  var d = new _Date(held);
  var day = d.getUTCDate(), dd = (day < 10 ? " " : "") + day;
  return MONTHS[d.getUTCMonth()] + " " + dd + " " +
    _two(d.getUTCHours()) + ":" + _two(d.getUTCMinutes()) + ":" + _two(d.getUTCSeconds()) +
    " " + d.getUTCFullYear() + " GMT";
}

function _algName(a) { return (a && (a.name || a.oid)) || "unknown"; }

// ---- serial + public key -----------------------------------------------------

function _serial(cert, indent) {
  var hex = cert.serialNumberHex || "";
  if (hex.length % 2) hex = "0" + hex;
  var buf = _bufferFrom(hex, "hex");
  // Strip a single DER positive-sign 00 byte (present when the value's high bit is
  // set) so the printed serial is the integer value, matching OpenSSL, and not the
  // encoding's leading octet.
  if (buf.length > 1 && buf[0] === 0x00 && (buf[1] & 0x80)) buf = _subarray(buf, 1);
  // Small non-negative serials render inline as decimal (0xhex), like OpenSSL;
  // anything larger renders as a colon-hex block.
  if (buf.length <= 6) {
    var n = _parseInt(_bufToString(buf, "hex") || "0", 16);
    return "Serial Number: " + n + " (0x" + (_bufToString(buf, "hex").replace(/^0+/, "") || "0") + ")";
  }
  return "Serial Number:\n" + " ".repeat(indent) + _hexColon(buf, {});
}

var CURVE_BITS = { "P-256": 256, "P-384": 384, "P-521": 521, "prime256v1": 256, "secp384r1": 384, "secp521r1": 521 };
var NIST_NAME = NAMES.NIST_CURVE;
// Every RSA-family key algorithm carries the same SPKI subjectPublicKey, an
// RSAPublicKey SEQUENCE { modulus, publicExponent } (RFC 4055 sec. 1.2 for
// id-RSASSA-PSS / id-RSAES-OAEP), so all decode to modulus + exponent, not raw bytes.
var RSA_KEY_ALGS = { rsaEncryption: 1, rsassaPss: 1, rsaesOaep: 1 };
function _keyBlock(spki, pad) {
  var algName = _algName(spki.algorithm);
  var out = [pad + "Public Key Algorithm: " + algName];
  var inner = pad + "    ";
  var pub = _isBuffer(spki.publicKey) ? spki.publicKey : (spki.publicKey && _isBuffer(spki.publicKey.bytes) ? spki.publicKey.bytes : null);

  if (algName === "ecPublicKey" || algName === "id-ecPublicKey") {
    var curveName = null;
    try { curveName = oid.name(asn1.read.oid(asn1.decode(spki.algorithm.parameters))); }
    catch (_e) { /* unknown curve */ }
    var bits = CURVE_BITS[curveName] || (pub ? ((pub.length - 1) / 2) * 8 : 0);
    _push(out, inner + "Public-Key: (" + bits + " bit)");
    if (pub) { _push(out, inner + "pub:"); _push(out, _hexColon(pub, { wrap: 16, indent: (pad.length + 8) })); }
    if (curveName) { _push(out, inner + "ASN1 OID: " + curveName); if (NIST_NAME[curveName]) _push(out, inner + "NIST CURVE: " + NIST_NAME[curveName]); }
    return _join(out, "\n");
  }
  if (RSA_KEY_ALGS[algName]) {
    try {
      var rsa = asn1.decode(pub);   // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
      var modBig = asn1.read.integer(rsa.children[0]);
      var expBig = asn1.read.integer(rsa.children[1]);
      var modHex = _bigIntToString(modBig, 16); if (modHex.length % 2) modHex = "0" + modHex;
      var modBuf = _bufferFrom(modHex, "hex");
      // Bit length is the value's, not the byte count's (a 0x7f.. modulus is 127-bit,
      // not 128), and the DER sign-padding 00 is present only when the top bit is set.
      _push(out, inner + "Public-Key: (" + _bigIntToString(modBig, 2).length + " bit)");
      _push(out, inner + "Modulus:");
      var modDisplay = (modBuf.length && (modBuf[0] & 0x80)) ? _bufferConcat([_bufferFrom([0x00]), modBuf]) : modBuf;
      _push(out, _hexColon(modDisplay, { wrap: 16, indent: (pad.length + 8) }));
      _push(out, inner + "Exponent: " + _bigIntToString(expBig, 10) + " (0x" + _bigIntToString(expBig, 16) + ")");
      return _join(out, "\n");
    } catch (_e) { /* fall through to raw */ }
  }
  // EdDSA / ML-DSA / SLH-DSA / anything else: show the raw public-key bytes.
  if (pub) { _push(out, inner + "Public-Key: (" + (pub.length * 8) + " bit)"); _push(out, inner + "pub:"); _push(out, _hexColon(pub, { wrap: 16, indent: (pad.length + 8) })); }
  return _join(out, "\n");
}

// ---- extensions --------------------------------------------------------------

// Display-naming conventions from pki.C.NAMES (see constants.js); an entry absent
// from a table falls back to the registered name / OID.
var EXT_LABEL = NAMES.EXTENSION;
var KU_LABEL = NAMES.KEY_USAGE;
var EKU_LABEL = NAMES.EXT_KEY_USAGE;
var GN_KIND = NAMES.GENERAL_NAME;

// An iPAddress octet string -> a readable address, matching OpenSSL: 4 bytes as a
// dotted-quad, 16 as (non-compressed, uppercase) IPv6, and the name-constraints
// 8/32-byte address+mask forms as "addr/mask". Never emits a raw octet (a stray
// 0x0a would inject a newline into the report); an odd length falls back to hex.
function _ipString(buf) {
  if (!_isBuffer(buf)) return "";
  if (buf.length === 4) return buf[0] + "." + buf[1] + "." + buf[2] + "." + buf[3];
  if (buf.length === 8) return _ipString(_subarray(buf, 0, 4)) + "/" + _ipString(_subarray(buf, 4));
  if (buf.length === 16 || buf.length === 32) {
    var groups = [];
    for (var i = 0; i < 16; i += 2) _push(groups, (((buf[i] << 8) | buf[i + 1]) >>> 0).toString(16).toUpperCase());
    var s = _join(groups, ":");
    return buf.length === 32 ? s + "/" + _ipString(_subarray(buf, 16)) : s;
  }
  return _hexColon(buf, {});
}

// Format a decoded GeneralName ({tagClass, tagNumber, value, bytes}) the way
// OpenSSL labels each choice. A directoryName carries a full DN (RFC 4514-escaped
// via _dnString); an iPAddress is a Buffer rendered as an address (never raw bytes);
// an otherName / unknown choice falls back to hex so a hostile value can never break
// the report's line structure. The string choices (DNS / URI / email) are
// control-byte-escaped -- which stops the severe case, a forged report line -- but
// their structural separators are left as-is, matching OpenSSL (a GeneralName has no
// RFC 4514-equivalent escaping profile, and escaping a legitimate comma in a URI
// would misrepresent it).
// The DN of a decoded directoryName GeneralName value. Shared so every renderer that meets this
// form (the SAN/AKI GeneralName path and the AIA/SIA accessLocation path, which carry different
// decoded shapes) prints the same DN, with neither falling back to a bare tag number.
function _gnDn(value) {
  return (value && _isArray(value.rdns)) ? _dnString(value) : ((value && value.dn) || "");
}
function _gn(g) {
  if (!g || typeof g !== "object") return "";
  var t = g.tagNumber;
  if (t === 7 && _isBuffer(g.value)) return "IP Address:" + _ipString(g.value);
  if (t === 4) return "DirName:" + _gnDn(g.value);
  if (t === 0) return "othername:" + (_isBuffer(g.bytes) ? _hexColon(g.bytes, {}) : "<unsupported>");
  var kind = GN_KIND[t] || ("tag" + t);
  var v = (typeof g.value === "string") ? _clean(g.value)
    : _isBuffer(g.value) ? _hexColon(g.value, {})
      : _isBuffer(g.bytes) ? _hexColon(g.bytes, {}) : "";
  return kind + ":" + v;
}

// Format a GeneralName still in its raw DER TLV (a CRL distribution point leaves
// its fullName entries undecoded): decode the context tag and render its content.
function _gnRaw(buf) {
  if (!_isBuffer(buf)) return "";
  try {
    var node = asn1.decode(buf);
    var t = node.tagNumber;
    if (t === 1 || t === 2 || t === 6) return GN_KIND[t] + ":" + _clean(_bufToString(node.content, "latin1"));
    if (t === 7) return "IP Address:" + _ipString(node.content);
    return _hexColon(buf, {});   // dirName / otherName / registeredID -> best-effort hex
    // allow:swallow-unverified drop-silent display fallback (tier-3): fullName GNs reach here as
    // schema-validated TLVs so asn1.decode cannot throw -- an unreachable defensive best-effort hex render.
  } catch (_e) { return _hexColon(buf, {}); }
}

// Coverage residual: the GeneralName render fallbacks are unreachable because the strict
// generalName decoder and each caller already narrow the shape (the _gnRaw catch above is
// separately documented).
//   * _ipString `if (!Buffer.isBuffer(buf)) return "";`. Every caller passes a Buffer (the
//     recursion slices a Buffer, _gn guards Buffer.isBuffer(g.value), _gnRaw passes
//     asn1.decode(...).content).
//   * _ipString trailing `return _hexColon(buf, {});`. generalName enforces iPAddress to
//     4/16 octets (8/32 for a name-constraints subtree base), so length is only ever 4/8/16/32.
//   * _gn `if (!g || typeof g !== "object") return "";`. Every _gn call maps a decoder-produced
//     GeneralName object; the decoders never emit a null element.
//   * _gn directoryName `: ((g.value && g.value.dn) || "")`. A decoded directoryName [4] always
//     carries a Name with an rdns array, so the rdns arm is always taken.
//   * _gn otherName `: "<unsupported>"`. A decoded GeneralName always carries its raw bytes TLV.
//   * _gn `|| ("tag" + t)`. GeneralName CHOICE tags are 0..8, all mapped in NAMES.GENERAL_NAME;
//     generalName rejects a tag outside 0..8.
//   * _gn `? _hexColon(g.value, {})`. iPAddress [7] is the only choice whose decoded value is a
//     Buffer, handled at the t === 7 branch before this ternary; other tags' value is string or null.
//   * _gn trailing `: ""`. A decoded GeneralName always carries a bytes Buffer, so the
//     Buffer.isBuffer(g.bytes) arm is always taken.
//   * _gnRaw `if (!Buffer.isBuffer(buf)) return "";`. The sole caller (the CRL-DP fullName loop)
//     guards Buffer.isBuffer(nm) before calling _gnRaw.

// Shared value renderers reused by more than one extension key.
function _renderAltName(decoded, inner) {
  return inner + (decoded.names || []).map(_gn).join(", ");
}
function _renderCrlDp(decoded, inner) {
  var dpLines = [];
  (decoded || []).forEach(function (dp) {
    var d = dp.distributionPoint, wrote = false;
    if (d && d.kind === "fullName" && _isArray(d.names)) {
      _push(dpLines, inner + "Full Name:");
      _forEach(d.names, function (nm) { _push(dpLines, inner + "  " + (_isBuffer(nm) ? _gnRaw(nm) : _gn(nm))); });
      wrote = true;
    } else if (d && d.kind === "rdn") {
      _push(dpLines, inner + "Relative Name (to CRL issuer)");
      wrote = true;
    }
    // The reasons BIT STRING scopes which revocation reasons this DP covers; dropping
    // it would make a scoped revocation source look generally applicable.
    if (dp.reasons && _isBuffer(dp.reasons.bytes)) {
      var rf = [], rb = dp.reasons.bytes;
      for (var bit = 1; bit < rb.length * 8; bit++) {
        if ((rb[bit >> 3] & (0x80 >> (bit & 7))) && NAMES.REASON_FLAGS[bit]) _push(rf, NAMES.REASON_FLAGS[bit]);
      }
      if (rf.length) { _push(dpLines, inner + "Reasons: " + _join(rf, ", ")); wrote = true; }
    }
    // A DistributionPoint may carry only cRLIssuer (an indirect CRL, no
    // distributionPoint): render the issuer GeneralNames, never drop them.
    if (dp.cRLIssuer && _isArray(dp.cRLIssuer.names)) {
      _push(dpLines, inner + "CRL Issuer:");
      _forEach(dp.cRLIssuer.names, function (g) { _push(dpLines, inner + "  " + _gn(g)); });
      wrote = true;
    }
    if (!wrote) _push(dpLines, inner + "(distribution point)");
  });
  return _join(dpLines, "\n");
}

// Coverage residual -- the shared alt-name / CRL-DP render fallbacks are unreachable because the
// strict decoders already narrow the shape:
//   * _renderAltName `(decoded.names || [])` -- the subjectAltName/issuerAltName decoder always
//     yields a names array.
//   * _renderCrlDp `(decoded || [])`. The cRLDistributionPoints/freshestCRL decoder always
//     yields an array.
//   * _renderCrlDp `: _gn(nm)`. distributionPointName surfaces fullName entries as raw
//     GeneralName Buffers, so Buffer.isBuffer(nm) is always true.
//   * _renderCrlDp `if (!wrote) ... "(distribution point)"`. crlDistributionPoints throws unless
//     a distributionPoint (always fullName/rdn) or cRLIssuer (sets wrote) is present, so !wrote
//     never holds.

// Declarative extension-value renderer registry: extension name -> (decoded, inner) ->
// text. Data-driven dispatch (the schema family's "registry, not switch" shape) so a
// new extension is a row, never another hand-coded branch, and the set an
// operator sees rendered is visible in one place. An extension with no row here
// hex-dumps its raw value (best-effort); each row's output is pinned by an
// inspect.test.js conformance vector.
var EXT_RENDERERS = {
  keyUsage: function (decoded, inner) {
    return inner + _keys(KU_LABEL).filter(function (k) { return decoded[k]; }).map(function (k) { return KU_LABEL[k]; }).join(", ");
  },
  extKeyUsage: function (decoded, inner) {
    return inner + _map(decoded, function (o) {
      var n = null;
      try { n = oid.name(o); }
      catch (_e) { /* unregistered EKU OID */ }
      return EKU_LABEL[n] || n || o;
    }).join(", ");
  },
  basicConstraints: function (decoded, inner) {
    var s = "CA:" + (decoded.cA ? "TRUE" : "FALSE");
    if (decoded.pathLenConstraint != null) s += ", pathlen:" + decoded.pathLenConstraint;
    return inner + s;
  },
  qcStatements: function (decoded, inner) {
    return _map(decoded, function (s) {
      var label = inner + (s.name || s.statementId), info = s.info;
      if (!info) return label;                                                              // presence-only (QcCompliance / QcSSCD)
      if (info.opaque) return label + " (opaque)";
      if (typeof info.amount !== "undefined") return label + ": " + info.amount + " " + info.currency + (info.exponent ? " x10^" + info.exponent : "");   // QcLimitValue
      if (typeof info.years !== "undefined") return label + ": " + info.years + " years";   // QcRetentionPeriod
      if (info.typeNames) return label + ": " + _map(info.typeNames, function (n, i) { return n || info.types[i]; }).join(", ");         // QcType
      if (info.methodNames) return label + ": " + _map(info.methodNames, function (n, i) { return n || info.methods[i]; }).join(", ");   // QcIdentMethod
      if (info.locations) return label + ": " + _map(info.locations, function (l) { return l.url + " (" + l.language + ")"; }).join(", "); // QcPDS
      if (info.countries) return label + ": " + _join(info.countries, ", ");                // QcCClegislation / QcQSCDlegislation
      if (typeof info.semanticsIdentifier !== "undefined") {                                // SemanticsInformation (id-qcs)
        var nra = info.nameRegistrationAuthorities && info.nameRegistrationAuthorities.length;
        return label + (info.semanticsIdentifier ? ": " + info.semanticsIdentifier : "") + (nra ? " (" + nra + " NRA)" : "");
      }
      return label;
    }).join("\n");
  },
  msCertificateTemplate: function (decoded, inner) {
    var v = decoded.templateMajorVersion === null ? "" : " v" + decoded.templateMajorVersion + "." + (decoded.templateMinorVersion === null ? 0 : decoded.templateMinorVersion);
    return inner + "Template: " + (decoded.name || decoded.templateID) + v;
  },
  msEnrollCertType: function (decoded, inner) {
    return inner + "Cert Type: " + _clean(_String(decoded));
  },
  msCaVersion: function (decoded, inner) {
    return inner + "CA Version: V" + decoded.caKeyIndex + "." + decoded.certIndex;
  },
  msPreviousCertHash: function (decoded, inner) {
    return inner + _hexColon(_isBuffer(decoded) ? decoded : _bufferAlloc(0), { upper: true });
  },
  subjectAltName: _renderAltName,
  issuerAltName: _renderAltName,
  certificatePolicies: function (decoded, inner) {
    var lines = [];
    _forEach(decoded, function (p) {
      _push(lines, inner + "Policy: " + p.policyIdentifier);
      if (!_isBuffer(p.qualifiersBytes)) return;
      // Render each PolicyQualifierInfo { policyQualifierId, qualifier }: a printable
      // qualifier (a CPS URI is an IA5String) shows as text, else a hex dump, and is never
      // dropped (which would make a qualified policy look unqualified).
      try {
        (asn1.decode(p.qualifiersBytes).children || []).forEach(function (pqi) {
          var qid = asn1.read.oid(pqi.children[0]), q = pqi.children[1];
          var label = null;
          try { label = oid.name(qid); }
          catch (_e) { /* unregistered qualifier */ }
          // A userNotice is a constructed SEQUENCE, so the printable-content test below can never
          // read it and it would hex-dump -- leaving the operator unable to read the very text the
          // qualifier exists to display. Render its DisplayText members through the shared pkix
          // reader (the same one pki.lint measures), so both agree on what the notice says.
          if (qid === OID_UNOTICE) {
            // Render only when every member decoded under its declared string type. A null text means
            // the value did not, and showing the members that happened to decode would present a
            // partial notice as a complete one, so the whole qualifier falls through to the hex
            // dump, where the operator sees the bytes the certificate actually holds.
            // A null noticeNumbers means the reference did not fully decode, and is refused for the
            // same reason as a null text: a partially decoded notice must not be shown as a whole one.
            var texts = pkix.userNoticeTexts(q);
            if (texts.length && _every(texts, function (t) {
              return t.text !== null && (t.field !== "organization" || t.noticeNumbers !== null);
            })) {
              _forEach(texts, function (t) {
                // A NoticeReference is identified by organization AND number, so the numbers ride with
                // the organization -- printing the text alone would drop the key that names the notice.
                var nums = (t.noticeNumbers && t.noticeNumbers.length) ? " #" + _join(t.noticeNumbers, ", ") : "";
                _push(lines, inner + "  " + (label || qid) + " " + t.field + ": " + _clean(t.text) + nums);
              });
              return;
            }
          }
          var val = (q && !q.constructed && _isBuffer(q.content) && _printable(q.content))
            ? _clean(_bufToString(q.content, "latin1"))
            : _hexColon(q && _isBuffer(q.bytes) ? q.bytes : _bufferAlloc(0), {});
          _push(lines, inner + "  " + (label || qid) + ": " + val);
        });
      } catch (_e) {
        _push(lines, inner + "  " + _hexColon(p.qualifiersBytes, {}));
      }
    });
    return _join(lines, "\n");
  },
  cRLDistributionPoints: _renderCrlDp,
  freshestCRL: _renderCrlDp,
  authorityInfoAccess: function (decoded, inner) {
    // AccessDescription list: <accessMethod> - <accessLocation>. The method resolves to its name (caIssuers /
    // ocsp); the accessLocation is a GeneralName (a URI in the common case). An unregistered method / an
    // uncommon accessLocation tag falls back to the raw OID / bracketed tag, and the entry is never dropped.
    var LABEL = { caIssuers: "CA Issuers", ocsp: "OCSP" };
    return (decoded || []).map(function (ad) {
      var m = null;
      try { m = oid.name(ad.accessMethod); } catch (_e) { /* allow:swallow-unverified display best-effort: an unregistered accessMethod OID falls back to the raw dotted OID below (inspection is best-effort, never a verdict) */ }
      var loc = ad.accessLocation || {}, lv;
      // The string choices (URI/DNS/email) are IA5String values already control-byte-rejected at decode by the
      // CVE-2009-2408 guard, so they are safe to emit directly. The iPAddress choice is a raw 4/16-byte Buffer,
      // so render it through _ipString (never raw) and a byte such as 0x0a cannot inject a line and spoof a field.
      if (loc.tag === 6) lv = "URI:" + loc.value;
      else if (loc.tag === 2) lv = "DNS:" + loc.value;
      else if (loc.tag === 1) lv = "email:" + loc.value;
      else if (loc.tag === 7) lv = "IP:" + _ipString(loc.value);
      // A directoryName accessLocation carries a decoded Name, so print the DN. Without this it fell
      // to the bracketed-tag fallback and rendered a bare "[4]", hiding the responder/issuer identity
      // the entry exists to convey -- while the same form already printed as DirName elsewhere.
      else if (loc.tag === 4) lv = "DirName:" + _gnDn(loc.value);
      else lv = typeof loc.value === "string" ? loc.value : "[" + loc.tag + "]";
      return inner + (LABEL[m] || m || ad.accessMethod) + " - " + lv;
    }).join("\n");
  },
  nameConstraints: function (decoded, inner) {
    var ncLines = [];
    ["permittedSubtrees:Permitted", "excludedSubtrees:Excluded"].forEach(function (pair) {
      var key = _strSplit(pair, ":")[0], label = _strSplit(pair, ":")[1], arr = decoded[key];
      if (!_isArray(arr) || !arr.length) return;
      _push(ncLines, inner + label + ":");
      _forEach(arr, function (st) { _push(ncLines, inner + "  " + _gn(st.base)); });
    });
    return _join(ncLines, "\n");
  },
  policyConstraints: function (decoded, inner) {
    var pc = [];
    if (decoded.requireExplicitPolicy != null) _push(pc, inner + "Require Explicit Policy: " + decoded.requireExplicitPolicy);
    if (decoded.inhibitPolicyMapping != null) _push(pc, inner + "Inhibit Policy Mapping: " + decoded.inhibitPolicyMapping);
    return pc.length ? _join(pc, "\n") : inner + "(empty)";
  },
  inhibitAnyPolicy: function (decoded, inner) {
    return inner + "Inhibit Any Policy Skip Certs: " + decoded;
  },
  policyMappings: function (decoded, inner) {
    return _map(decoded, function (m) { return inner + m.issuerDomainPolicy + " -> " + m.subjectDomainPolicy; }).join("\n");
  },
  signedCertificateTimestampList: function (decoded, inner) {
    var sct = [];
    (decoded.scts || []).forEach(function (s) {
      _push(sct, inner + "Signed Certificate Timestamp:");
      _push(sct, inner + "    Version: v" + ((typeof s.version === "number" ? s.version : 0) + 1));
      if (s.logIdHex) _push(sct, inner + "    Log ID: " + _String(s.logIdHex).toUpperCase());
      if (s.timestamp != null) _push(sct, inner + "    Timestamp: " + _String(s.timestamp));
    });
    var unk = (decoded.unknownScts || []).length;
    if (unk) _push(sct, inner + "(" + unk + " SCT(s) of an unrecognized version)");
    return sct.length ? _join(sct, "\n") : inner + "(empty SCT list)";
  },
  precertificatePoison: function (decoded, inner) {
    return inner + "Precertificate Poison (this is a precertificate, not a certificate)";
  },
  subjectKeyIdentifier: function (decoded, inner) {
    return inner + _hexColon(_isBuffer(decoded) ? decoded : (decoded.bytes || _bufferAlloc(0)), { upper: true });
  },
  authorityKeyIdentifier: function (decoded, inner) {
    // Any of the three fields may be present; the issuer+serial form carries no
    // keyIdentifier, so render whichever the decoder populated, never claiming
    // "keyid:(none)" and dropping the certificate's real authority identifier.
    var akiLines = [];
    if (_isBuffer(decoded.keyIdentifier)) _push(akiLines, inner + "keyid:" + _hexColon(decoded.keyIdentifier, { upper: true }));
    if (decoded.authorityCertIssuer && _isArray(decoded.authorityCertIssuer.names)) {
      _forEach(decoded.authorityCertIssuer.names, function (g) { _push(akiLines, inner + _gn(g)); });
    }
    if (decoded.authorityCertSerialNumber != null) {
      var sn = (typeof decoded.authorityCertSerialNumber === "bigint"
        ? decoded.authorityCertSerialNumber : _BigInt(decoded.authorityCertSerialNumber)).toString(16);
      if (sn.length % 2) sn = "0" + sn;
      _push(akiLines, inner + "serial:0x" + _toUpperCase(sn));
    }
    return akiLines.length ? _join(akiLines, "\n") : inner + "keyid:(none)";
  },
};
// [MS-WCCE] szOID-APPLICATION_CERT_POLICIES decodes as certificatePolicies, so it renders identically.
EXT_RENDERERS.msApplicationPolicies = EXT_RENDERERS.certificatePolicies;

// Coverage residual -- the EXT_RENDERERS entry fallbacks are unreachable because each shared
// decoder (and asn1.read.oid) already narrows the shape before the renderer runs:
//   * extKeyUsage `catch (_e) { /* unregistered EKU OID */ }` and certificatePolicies
//     `catch (_e) { /* unregistered qualifier */ }`. oid.name returns undefined (never throws)
//     for a well-formed unregistered OID; it throws only on a non-dotted argument, and both OIDs
//     come from asn1.read.oid (always a valid dotted OID).
//   * certificatePolicies `(asn1.decode(p.qualifiersBytes).children || [])`. asn1.decode of the
//     assertPolicyQualifiers-validated qualifiers SEQUENCE always yields a children array.
//   * certificatePolicies `: Buffer.alloc(0)`. assertPolicyQualifiers requires every
//     PolicyQualifierInfo to be a 2-child SEQUENCE, so pqi.children[1] is always a present node
//     carrying a bytes Buffer.
//   * certificatePolicies outer `catch (_e) { ... _hexColon(p.qualifiersBytes, {}) ... }`.
//     certificatePolicies already validated qualifiersBytes as a SEQUENCE of 2-child PQIs each
//     leading with a valid OID, so the re-decode + asn1.read.oid cannot throw.
//   * policyConstraints `: inner + "(empty)"`. policyConstraints rejects an empty SEQUENCE
//     (>= 1 context field), so requireExplicitPolicy or inhibitPolicyMapping is non-null;
//     pc.length is never 0.
//   * SCT `(decoded.scts || [])` / `(decoded.unknownScts || [])`. ct.parseSctList always returns
//     both arrays.
//   * SCT `: 0`. Every scts entry is a decoded v1 SCT with numeric version 0 (unknown-version
//     SCTs go to unknownScts and are not iterated here).
//   * SCT `: inner + "(empty SCT list)"`. ct.parseSctList rejects an empty list and routes every
//     SerializedSCT into scts/unknownScts, so at least one line is always emitted.
//   * subjectKeyIdentifier `: (decoded.bytes || Buffer.alloc(0))`. The subjectKeyIdentifier
//     decoder returns the KeyIdentifier as a Buffer, so Buffer.isBuffer(decoded) is always true.
//   * authorityKeyIdentifier `: BigInt(decoded.authorityCertSerialNumber)`. The AKI decoder reads
//     authorityCertSerialNumber via asn1.read.integerImplicit (a bigint), so typeof === "bigint"
//     is always true.

function _renderExtValue(ext, decoded, inner) {
  var fn = EXT_RENDERERS[ext.name];
  return fn ? fn(decoded, inner) : null;   // no registered renderer -> caller hex-dumps
}

// Fallback for an extension with no decoder or a decode failure. Best-effort,
// more useful than OpenSSL's raw-octet dump: a directly-printable value shows as a
// string; a DER-wrapped character string is decoded and shown; otherwise a hex
// dump. Never throws.
var _STRING_TAGS = { 12: 1, 19: 1, 22: 1, 20: 1, 26: 1, 27: 1, 30: 1 }; // UTF8/Printable/IA5/Teletex/Visible/General/BMP
// A value renders as text only when every byte is a printable, non-control ASCII
// character. A control byte (a bare CR / LF / TAB, etc.) is rejected here so a
// hostile private-extension value cannot forge or overwrite report lines in a
// terminal or log -- such a value falls through to the hex dump instead.
function _printable(buf) {
  return buf.length > 0 && _viewEvery(buf, function (b) { return b >= 0x20 && b < 0x7f; });
}
function _fallback(value, inner) {
  if (!_isBuffer(value) || value.length === 0) return inner + "(empty)";
  if (_printable(value)) return inner + _bufToString(value, "latin1");
  try {
    var n = asn1.decode(value);
    if (n.tagClass === "universal" && _STRING_TAGS[n.tagNumber]) {
      var s = asn1.read.string(n);
      if (_printable(_bufferFrom(s, "utf8"))) return inner + s;
    }
  } catch (_e) { /* not DER / not a string -> hex */ }
  return _hexColon(value, { wrap: 16, indent: inner.length });
}

function _extension(ext, pad) {
  var label = EXT_LABEL[ext.name] || ext.name || ext.oid;
  var header = pad + label + ":" + (ext.critical ? " critical" : "");
  var inner = pad + "    ";
  var decoder = EXT_DECODERS[ext.oid];
  if (decoder) {
    try {
      var body = _renderExtValue(ext, decoder(ext.value), inner);
      if (body != null) return header + "\n" + body;
    } catch (_e) { /* fall through to the raw fallback */ }
  }
  return header + "\n" + _fallback(ext.value, inner);
}

// ---- input coercion ----------------------------------------------------------

// A genuine pki.schema.x509.parse result carries this whole shape. The fast path
// accepts a pre-parsed certificate to skip re-parsing, but a bare or partial object
// with only a tbsBytes property is not a certificate: without this check the renderer
// would dereference a missing field (c.validity.notBefore, ...) and throw a raw
// TypeError instead of the documented typed inspect/bad-input (the API's error contract).
function _looksParsed(o) {
  return typeof o.version === "number" && typeof o.serialNumberHex === "string" &&
    o.signatureAlgorithm && typeof o.signatureAlgorithm === "object" &&
    o.issuer && typeof o.issuer === "object" && o.subject && typeof o.subject === "object" &&
    o.validity && o.validity.notBefore != null && o.validity.notAfter != null &&
    o.subjectPublicKeyInfo && typeof o.subjectPublicKeyInfo === "object" && _isArray(o.extensions);
}

function _parse(input) {
  if (input && typeof input === "object" && !_isBuffer(input) && input.tbsBytes) {
    if (!_looksParsed(input)) throw _err("inspect/bad-input", "input has a tbsBytes property but is not a complete pki.schema.x509.parse result");
    return input;   // a genuine already-parsed certificate
  }
  var der;
  if (_isBuffer(input)) der = input;
  else if (typeof input === "string") {
    try { der = x509.pemDecode(input, "CERTIFICATE"); }
    catch (e) { throw _err("inspect/bad-input", "input is not a PEM CERTIFICATE", e); }
  } else {
    throw _err("inspect/bad-input", "input must be a parsed certificate, a DER Buffer, or a PEM string");
  }
  try { return x509.parse(der); }
  catch (e) { throw _err("inspect/bad-certificate", "input is not a well-formed X.509 certificate", e); }
}

// ---- public: certificate -----------------------------------------------------

/**
 * @primitive pki.inspect.certificate
 * @signature pki.inspect.certificate(input) -> string
 * @since 0.2.4
 * @status stable
 * @spec RFC 5280
 * @related pki.schema.x509.parse
 *
 * Render a certificate as a human-readable, OpenSSL-familiar text report. `input`
 * is a PEM string, a DER Buffer, or a `pki.schema.x509.parse` result. A value that
 * is none of those throws `inspect/bad-input`; a malformed certificate throws
 * `inspect/bad-certificate`; but a malformed individual extension is rendered as a
 * hex dump and does not fail the whole report. Pure, with no OpenSSL dependency.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var cert = pki.schema.x509.parse(der);
 *   pki.inspect.certificate(cert).split("\n")[0]; // "Certificate:"
 */
function certificate(input) {
  var c = _parse(input);
  var L = [];
  _push(L, "Certificate:");
  _push(L, "    Data:");
  _push(L, "        Version: " + c.version + " (0x" + (c.version - 1).toString(16) + ")");
  _push(L, "        " + _serial(c, 12));
  _push(L, "        Signature Algorithm: " + _algName(c.signatureAlgorithm));
  _push(L, "        Issuer: " + _dnString(c.issuer));
  _push(L, "        Validity");
  _push(L, "            Not Before: " + _date(c.validity.notBefore));
  _push(L, "            Not After : " + _date(c.validity.notAfter));
  _push(L, "        Subject: " + _dnString(c.subject));
  _push(L, "        Subject Public Key Info:");
  _push(L, _keyBlock(c.subjectPublicKeyInfo, "            "));
  // Coverage residual -- `c.extensions || []` is unreachable: both input paths guarantee an array
  // (x509.parse yields one; the pre-parsed fast path requires Array.isArray(extensions) in _looksParsed).
  if ((c.extensions || []).length) {
    _push(L, "        X509v3 extensions:");
    _forEach(c.extensions, function (ext) { _push(L, _extension(ext, "            ")); });
  }
  _push(L, "    Signature Algorithm: " + _algName(c.signatureAlgorithm));
  var sig = c.signatureValue && (c.signatureValue.bytes || c.signatureValue);
  if (_isBuffer(sig)) { _push(L, "    Signature Value:"); _push(L, _hexColon(sig, { wrap: 16, indent: 8 })); }
  return _join(L, "\n") + "\n";
}

// ---- CRL / CSR / CMS coercion (the _parse model, per format) -----------------

// Each fast-path completeness check mirrors _looksParsed: a bare/partial object
// with only the marker field is NOT a parsed result, so it throws the documented
// typed inspect/bad-input rather than dereferencing a missing field.
function _looksParsedCrl(o) {
  return typeof o.version === "number" && o.issuer && typeof o.issuer === "object" &&
    o.thisUpdate != null && _isArray(o.revokedCertificates) && _isArray(o.crlExtensions) &&
    o.signatureAlgorithm && typeof o.signatureAlgorithm === "object";
}
function _looksParsedCsr(o) {
  return typeof o.version === "number" && o.subject && typeof o.subject === "object" &&
    o.subjectPublicKeyInfo && typeof o.subjectPublicKeyInfo === "object" &&
    _isArray(o.attributes) && o.signatureAlgorithm && typeof o.signatureAlgorithm === "object";
}
function _looksParsedCms(o) {
  if (typeof o.contentType !== "string" || typeof o.contentTypeName !== "string" || typeof o.version !== "number") return false;
  // A real parse result is one of the six dispatched content types AND carries that type's
  // required structural fields (_CMS_SHAPE). An unrecognized contentType, or a recognized one
  // missing its fields, is not a parse result: fail closed as inspect/bad-input, not a partial render.
  var shape = _CMS_SHAPE[o.contentType];
  return shape ? shape(o) : false;
}
// The shared inspect coercion boundary, composed by every direct inspector AND any():
// pemLabel:null unwraps a PEM string OR a PEM-armored Buffer (a .pem read with
// fs.readFileSync) under ANY block label -- so an aliased label (PKCS7 for CMS,
// CRL for an X509 CRL) routes like any() instead of hitting a canonical-label
// mismatch -- while a raw DER Buffer / Uint8Array passes through the detached-store guard.
var _INSPECT_ENTRY = { pemLabel: null, PemError: InspectError, ErrorClass: InspectError, prefix: "inspect" };
// A parameterized _parse clone: marker field, fast-path completeness check, then
// the shared label-agnostic coercion to DER, then parse(der) inside try.
function _coerce(input, spec) {
  if (input && typeof input === "object" && !_isBuffer(input) && !(input instanceof Uint8Array) && input[spec.marker] !== undefined) {
    if (!spec.looksParsed(input)) throw _err("inspect/bad-input", "input has a " + spec.marker + " property but is not a complete " + spec.parsedName + " result");
    return input;
  }
  var der;
  // Compose the ONE coercion every format parser + any() use, so a PEM string and a
  // PEM-armored Buffer unwrap under any label (not just the format's canonical one)
  // and a detached-store Buffer fails closed here, not divergently per inspector.
  try { der = pkix.coerceToDer(input, _INSPECT_ENTRY); }
  catch (e) { throw _err("inspect/bad-input", "input must be a parsed " + spec.what + ", a DER Buffer, or a PEM block", e); }
  try { return spec.parse(der); }
  catch (e) { throw _err(spec.badCode, "input is not a well-formed " + spec.what, e); }
}
function _parseCrl(input) { return _coerce(input, { marker: "thisUpdate", looksParsed: _looksParsedCrl, parsedName: "pki.schema.crl.parse", parse: crl.parse, badCode: "inspect/bad-crl", what: "X.509 CRL" }); }
function _parseCsr(input) { return _coerce(input, { marker: "certificationRequestInfoBytes", looksParsed: _looksParsedCsr, parsedName: "pki.schema.csr.parse", parse: csr.parse, badCode: "inspect/bad-csr", what: "PKCS#10 certification request" }); }
function _parseCms(input) { return _coerce(input, { marker: "contentType", looksParsed: _looksParsedCms, parsedName: "pki.schema.cms.parse", parse: cms.parse, badCode: "inspect/bad-cms", what: "CMS message" }); }

// ---- shared attribute-value renderer (CSR attributes + CMS signed/unsigned) ---

// Attribute/extension dispatch keys on the STABLE OID, never the display name a
// pki.oid.register() override can change (the schema stores the overridden name).
var OID_EXTENSION_REQUEST = oid.byName("extensionRequest");
var OID_CONTENT_TYPE = oid.byName("contentType");
var OID_MESSAGE_DIGEST = oid.byName("messageDigest");
var OID_SIGNING_TIME = oid.byName("signingTime");

// Decode the known content-binding attribute types for display; anything else, or
// a decode failure, falls back to printable-or-hex. Never throws once parsed.
// Keyed on the attribute's OID (stable), not its display name (register-mutable).
function _attrValue(typeOid, rawDer, inner) {
  try {
    if (typeOid === OID_CONTENT_TYPE) { var ct = asn1.read.oid(asn1.decode(rawDer)); return inner + (oid.name(ct) || ct); }
    if (typeOid === OID_MESSAGE_DIGEST) return _hexColon(asn1.read.octetString(asn1.decode(rawDer)), { wrap: 16, indent: inner.length });
    if (typeOid === OID_SIGNING_TIME) return inner + _date(asn1.read.time(asn1.decode(rawDer)));
  } catch (_e) { /* fall through to the raw fallback */ }
  return _fallback(rawDer, inner);
}

// ---- CRL report --------------------------------------------------------------

// The CRL decoder PRE-DECODES three extension values to a JS type (not the raw
// Buffer the shared _extension consumes): cRLNumber -> BigInt, reasonCode ->
// Number, invalidityDate -> Date. Dispatch on the STABLE OID exactly as the decoder
// does (schema-crl decodeExt), NOT the display name -- pki.oid.register() can override
// a built-in name, which would skip these branches and hand _extension a non-Buffer
// value (rendering "(empty)" for the CRL number or reason). deltaCRLIndicator is a
// raw-Buffer extension the decoder does NOT pre-decode, but its value is a bare INTEGER
// (BaseCRLNumber) the operator needs in decimal to relate a delta CRL to its base -- so
// decode it here for display (best-effort: a malformed value falls through to hex).
// Delegate every other raw-value extension (AKI / IDP / freshestCRL / certificateIssuer)
// to the shared _extension verbatim.
var OID_CRL_NUMBER = oid.byName("cRLNumber");
var OID_REASON_CODE = oid.byName("reasonCode");
var OID_INVALIDITY_DATE = oid.byName("invalidityDate");
var OID_DELTA_CRL_INDICATOR = oid.byName("deltaCRLIndicator");
function _crlExtension(ext, pad) {
  var label = EXT_LABEL[ext.name] || ext.name || ext.oid;
  var header = pad + label + ":" + (ext.critical ? " critical" : "");
  var inner = pad + "    ";
  if (ext.oid === OID_CRL_NUMBER && typeof ext.value === "bigint") return header + "\n" + inner + _String(ext.value);
  if (ext.oid === OID_REASON_CODE && typeof ext.value === "number") return header + "\n" + inner + (NAMES.CRL_REASON[ext.value] || _String(ext.value));
  if (ext.oid === OID_INVALIDITY_DATE && guard.time.isDate(ext.value)) return header + "\n" + inner + _date(ext.value);
  if (ext.oid === OID_DELTA_CRL_INDICATOR && _isBuffer(ext.value)) {
    try { return header + "\n" + inner + "BaseCRLNumber: " + _String(asn1.read.integer(asn1.decode(ext.value))); }
    catch (_e) { /* malformed BaseCRLNumber -> fall through to the shared _extension (hex) */ }
  }
  return _extension(ext, pad);
}

/**
 * @primitive pki.inspect.crl
 * @signature pki.inspect.crl(input) -> string
 * @since 0.3.8
 * @status stable
 * @spec RFC 5280
 * @related pki.schema.crl.parse, pki.inspect.certificate
 *
 * Render a certificate revocation list as an `openssl crl -text`-familiar text
 * report: issuer, Last/Next Update, the CRL extensions, each revoked entry (serial,
 * revocation date, entry extensions), and the signature. `input` is a PEM string, a
 * DER Buffer, or a `pki.schema.crl.parse` result; a non-CRL throws
 * `inspect/bad-crl`, a wrong-type input `inspect/bad-input`. A malformed individual
 * extension renders as hex and does not fail the report.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var caCert = await pki.x509.sign({ subject: "Issuing CA", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["cRLSign"] } }, { key: key });
 *   var crlDer = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), crlNumber: 1n, revoked: [] },
 *     { cert: caCert, key: key });
 *   pki.inspect.crl(crlDer).split("\n")[0]; // "Certificate Revocation List (CRL):"
 */
function crlReport(input) {
  var c = _parseCrl(input);
  var L = ["Certificate Revocation List (CRL):"];
  _push(L, "        Version " + c.version + " (0x" + (c.version - 1).toString(16) + ")");
  _push(L, "    Signature Algorithm: " + _algName(c.signatureAlgorithm));
  _push(L, "        Issuer: " + _dnString(c.issuer));
  _push(L, "        Last Update: " + _date(c.thisUpdate));
  _push(L, "        Next Update: " + (c.nextUpdate ? _date(c.nextUpdate) : "NONE"));
  if (c.crlExtensions.length) {
    _push(L, "        CRL extensions:");
    _forEach(c.crlExtensions, function (ext) { _push(L, _crlExtension(ext, "            ")); });
  }
  if (c.revokedCertificates.length) {
    _push(L, "Revoked Certificates:");
    _forEach(c.revokedCertificates, function (e) {
      _push(L, "    " + _serial(e, 8));
      _push(L, "        Revocation Date: " + _date(e.revocationDate));
      if ((e.crlEntryExtensions || []).length) {
        _push(L, "        CRL entry extensions:");
        _forEach(e.crlEntryExtensions, function (ext) { _push(L, _crlExtension(ext, "            ")); });
      }
    });
  } else {
    _push(L, "No Revoked Certificates.");
  }
  _push(L, "    Signature Algorithm: " + _algName(c.signatureAlgorithm));
  var sig = c.signatureValue && (c.signatureValue.bytes || c.signatureValue);
  if (_isBuffer(sig)) { _push(L, "    Signature Value:"); _push(L, _hexColon(sig, { wrap: 16, indent: 8 })); }
  return _join(L, "\n") + "\n";
}

// ---- CSR report --------------------------------------------------------------

function _attribute(attr, pad) {
  var inner = pad + "    ";
  // extensionRequest carries decoded RFC 5280 extensions (the cert-extension shape)
  // -> render each through the shared _extension, identically to a certificate's.
  if (attr.type === OID_EXTENSION_REQUEST && _isArray(attr.extensions)) {
    var lines = [pad + "Requested Extensions:"];
    _forEach(attr.extensions, function (ext) { _push(lines, _extension(ext, inner)); });
    return _join(lines, "\n");
  }
  var header = pad + (attr.name || oid.name(attr.type) || attr.type) + ":";
  var vals = (attr.values || []).map(function (v) { return _attrValue(attr.type, v, inner); });
  return vals.length ? header + "\n" + _join(vals, "\n") : header;
}

/**
 * @primitive pki.inspect.csr
 * @signature pki.inspect.csr(input) -> string
 * @since 0.3.8
 * @status stable
 * @spec RFC 2986
 * @related pki.schema.csr.parse, pki.inspect.certificate
 *
 * Render a PKCS#10 certification request as an `openssl req -text`-familiar text
 * report: subject, the subject public key, the requested extensions and other
 * attributes, and the signature. `input` is a PEM string, a DER Buffer, or a
 * `pki.schema.csr.parse` result; a non-CSR throws `inspect/bad-csr`, a wrong-type
 * input `inspect/bad-input`. Best-effort like `certificate`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var csrDer = await pki.csr.sign({ subject: "req.example", subjectPublicKey: await pki.key.export(pair.publicKey) },
 *     { key: await pki.key.export(pair.privateKey) });
 *   pki.inspect.csr(csrDer).split("\n")[0]; // "Certificate Request:"
 */
function csrReport(input) {
  var c = _parseCsr(input);
  var L = ["Certificate Request:", "    Data:"];
  _push(L, "        Version: " + c.version + " (0x" + (c.version - 1).toString(16) + ")");
  _push(L, "        Subject: " + _dnString(c.subject));
  _push(L, "        Subject Public Key Info:");
  _push(L, _keyBlock(c.subjectPublicKeyInfo, "            "));
  _push(L, "        Attributes:");
  if (c.attributes.length) _forEach(c.attributes, function (attr) { _push(L, _attribute(attr, "            ")); });
  else _push(L, "            (none)");
  _push(L, "    Signature Algorithm: " + _algName(c.signatureAlgorithm));
  var sig = c.signatureValue && (c.signatureValue.bytes || c.signatureValue);
  if (_isBuffer(sig)) { _push(L, "    Signature Value:"); _push(L, _hexColon(sig, { wrap: 16, indent: 8 })); }
  return _join(L, "\n") + "\n";
}

// ---- CMS report --------------------------------------------------------------

// Dispatch on the STABLE contentType OID, never the display name: pki.oid.register()
// lets an application override the built-in "signedData" name, and dispatching on the
// mutable name would then misroute a valid SignedData to the generic summary.
var OID_SIGNED_DATA = oid.byName("signedData");
// pki.schema.cms.parse dispatches ONLY these six RFC 5652 content types (every other
// OID throws cms/unsupported- or cms/unknown-content-type -- it never yields an object).
// Each maps to a predicate over the REQUIRED (non-OPTIONAL) fields of its top-level
// SEQUENCE, so the parsed-object fast path in _looksParsedCms accepts a genuine parse
// result but a partial/hand-built object (the type OID + name + version, none of the
// structural fields) fails closed as inspect/bad-input -- the documented boundary.
function _isObj(x) { return !!x && typeof x === "object"; }
var _CMS_SHAPE = {};
_CMS_SHAPE[OID_SIGNED_DATA] = function (o) { return _isArray(o.digestAlgorithms) && _isObj(o.encapContentInfo) && _isArray(o.signerInfos); };                       // sec. 5.1
_CMS_SHAPE[oid.byName("envelopedData")] = function (o) { return _isArray(o.recipientInfos) && _isObj(o.encryptedContentInfo); };                                    // sec. 6.1
_CMS_SHAPE[oid.byName("encryptedData")] = function (o) { return _isObj(o.encryptedContentInfo); };                                                                  // sec. 8
_CMS_SHAPE[oid.byName("authData")] = function (o) { return _isArray(o.recipientInfos) && _isObj(o.macAlgorithm) && _isObj(o.encapContentInfo) && _isBuffer(o.mac); }; // sec. 9.1
_CMS_SHAPE[oid.byName("authEnvelopedData")] = function (o) { return _isArray(o.recipientInfos) && _isObj(o.encryptedContentInfo) && _isBuffer(o.mac); };            // RFC 5083 (build surfaces encryptedContentInfo)
_CMS_SHAPE[oid.byName("compressedData")] = function (o) { return _isObj(o.compressionAlgorithm) && _isObj(o.encapContentInfo); };                                   // RFC 3274

// Coverage residuals in the report assemblers -- verified-hard-to-reach, not gaps:
//   * The `x.bytes || x` / `oid.name(o) || o` / `a.name || oid.name || a.type` fallbacks are
//     belts for shapes the strict parsers never produce (a parsed CSR always carries
//     signatureValue.bytes; a decoded algorithm always names its OID) -- they mirror
//     certificate()'s own defensive fallbacks.
//   * The embedded-CRL delegation and the CONTEXT-tagged embedded-element summary need a CMS
//     carrying a crls element or an attribute-certificate CHOICE alternative, and the
//     AuthenticatedData macAlgorithm / countersignature-unsignedAttrs arms need CMS shapes the
//     toolkit's own producers (cms.sign / encrypt / compress) do not emit; every such arm is
//     driven best-effort (never throws) and its structural sibling (embedded Certificate,
//     envelopedData recipientInfo, CompressedData compressionAlgorithm, signed attributes) is
//     covered.

// An embedded certificate/CRL element {bytes,tagClass,tagNumber}: a UNIVERSAL
// SEQUENCE is a real Certificate/CertificateList -> delegate to the full sub-report
// (guarded; a one-line summary on any failure); a CONTEXT-tagged CHOICE alternative
// (attribute certificate / other) renders a one-line tag+size summary, never parsed.
function _cmsEmbedded(kind, el, pad) {
  if (el.tagClass === "universal") {
    try {
      var sub = (kind === "CRL") ? crlReport(el.bytes) : certificate(el.bytes);
      return pad + kind + ":\n" + _strReplace(sub, /\n$/, "").split("\n").map(function (l) { return pad + "    " + l; }).join("\n");
    } catch (_e) { /* fall through to the summary */ }
  }
  return pad + kind + " [" + el.tagClass + " " + el.tagNumber + "] (" + el.bytes.length + " bytes)";
}

function _signerInfoAttrs(title, attrs, pad) {
  var lines = [pad + title + ":"];
  var inner = pad + "    ";
  _forEach(attrs, function (a) {
    var vals = (a.values || []).map(function (v) { return _attrValue(a.type, v, inner + "    "); });
    _push(lines, inner + (a.name || oid.name(a.type) || a.type) + ":");
    _forEach(vals, function (v) { _push(lines, v); });
  });
  return _join(lines, "\n");
}

function _signerInfo(si, pad) {
  var inner = pad + "    ";
  var L = [pad + "SignerInfo:", inner + "Version: " + si.version];
  if (si.sid && si.sid.serialNumberHex !== undefined) {
    _push(L, inner + "Issuer: " + _dnString(si.sid.issuer));
    _push(L, inner + _serial(si.sid, pad.length + 8));
  } else if (si.sid && _isBuffer(si.sid.subjectKeyIdentifier)) {
    _push(L, inner + "Subject Key Identifier: " + _hexColon(si.sid.subjectKeyIdentifier, {}));
  }
  _push(L, inner + "Digest Algorithm: " + _algName(si.digestAlgorithm));
  if (si.signedAttrs && si.signedAttrs.length) _push(L, _signerInfoAttrs("Signed Attributes", si.signedAttrs, inner));
  _push(L, inner + "Signature Algorithm: " + _algName(si.signatureAlgorithm));
  if (si.unsignedAttrs && si.unsignedAttrs.length) _push(L, _signerInfoAttrs("Unsigned Attributes", si.unsignedAttrs, inner));
  if (_isBuffer(si.signature)) { _push(L, inner + "Signature Value:"); _push(L, _hexColon(si.signature, { wrap: 16, indent: pad.length + 8 })); }
  return _join(L, "\n");
}

/**
 * @primitive pki.inspect.cms
 * @signature pki.inspect.cms(input) -> string
 * @since 0.3.8
 * @status stable
 * @spec RFC 5652
 * @related pki.schema.cms.parse, pki.inspect.certificate
 *
 * Render a CMS message as an `openssl cms -cmsout -print`-familiar text report. A
 * SignedData shows the content type, digest algorithms, encapsulated content,
 * embedded certificates/CRLs, and each SignerInfo (signer identifier, algorithms,
 * signed/unsigned attributes, signature); a non-SignedData ContentInfo renders a
 * stable top-field summary. `input` is a PEM string, a DER Buffer, or a
 * `pki.schema.cms.parse` result; a non-CMS throws `inspect/bad-cms`. Best-effort.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "Signer", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var cmsDer = await pki.cms.sign(Buffer.from("hello"), { cert: cert, key: key });
 *   pki.inspect.cms(cmsDer).split("\n")[0]; // "CMS ContentInfo:"
 */
// A ContentInfo whose content type pki.schema.cms.parse does not dispatch (id-data,
// digestedData, ...) is a VALID CMS the parser defers, not a malformed message -- render an
// outer-only summary (the named content type) rather than failing the report.
function _cmsOuterSummary(input) {
  var ct = null;
  try {
    var der = pkix.coerceToDer(input, _INSPECT_ENTRY);
    ct = asn1.read.oid(asn1.decode(der).children[0]);
  } catch (_e) { /* best-effort: name unknown */ }
  return "CMS ContentInfo:\n    Content Type: " + (ct ? (oid.name(ct) || ct) + " (" + ct + ")" : "unknown") +
    "\n    (content type not further parsed; outer ContentInfo only)\n";
}

function cmsReport(input) {
  var m;
  try { m = _parseCms(input); }
  catch (e) {
    // A ContentInfo whose contentType the parser does not dispatch is a valid CMS, not a malformed
    // message: a known-but-deferred type (cms/unsupported-content-type, e.g. id-data) or a private/
    // unregistered OID (cms/unknown-content-type). Either renders the outer-only summary.
    var cc = e && e.cause && e.cause.code;
    if (e && e.code === "inspect/bad-cms" && (cc === "cms/unsupported-content-type" || cc === "cms/unknown-content-type")) return _cmsOuterSummary(input);
    throw e;
  }
  var L = ["CMS ContentInfo:"];
  _push(L, "    Content Type: " + (m.contentTypeName || oid.name(m.contentType) || m.contentType) + " (" + m.contentType + ")");
  if (m.contentType === OID_SIGNED_DATA) {
    _push(L, "    SignedData:");
    _push(L, "        Version: " + m.version);
    _push(L, "        Digest Algorithms:");
    (m.digestAlgorithms || []).forEach(function (a) { _push(L, "            " + _algName(a)); });
    if (m.encapContentInfo) {
      _push(L, "        Encapsulated Content Info:");
      _push(L, "            Content Type: " + (oid.name(m.encapContentInfo.eContentType) || m.encapContentInfo.eContentType) + " (" + m.encapContentInfo.eContentType + ")");
      _push(L, "            " + (m.encapContentInfo.eContent == null ? "<no content (detached)>" : (m.encapContentInfo.eContent.length + " content byte(s)")));
    }
    (m.certificates || []).forEach(function (el) { _push(L, _cmsEmbedded("Certificate", el, "        ")); });
    (m.crls || []).forEach(function (el) { _push(L, _cmsEmbedded("CRL", el, "        ")); });
    (m.signerInfos || []).forEach(function (si) { _push(L, _signerInfo(si, "        ")); });
  } else {
    // Non-SignedData: a stable top-field summary (no plaintext to show); never throws.
    _push(L, "    " + (m.contentTypeName || "content") + ":");
    if (m.version != null) _push(L, "        Version: " + m.version);
    (m.recipientInfos || []).forEach(function (ri) { _push(L, "        RecipientInfo: " + (ri.type || "?") + (ri.ridType ? " (" + ri.ridType + ")" : "")); });
    if (m.encryptedContentInfo) {
      _push(L, "        Content Type: " + (oid.name(m.encryptedContentInfo.contentType) || m.encryptedContentInfo.contentType));
      if (m.encryptedContentInfo.contentEncryptionAlgorithm) _push(L, "        Content Encryption Algorithm: " + _algName(m.encryptedContentInfo.contentEncryptionAlgorithm));
    }
    if (m.macAlgorithm) _push(L, "        MAC Algorithm: " + _algName(m.macAlgorithm));
    if (m.compressionAlgorithm) _push(L, "        Compression Algorithm: " + _algName(m.compressionAlgorithm));
  }
  return _join(L, "\n") + "\n";
}

// ---- unified detect-and-dispatch ---------------------------------------------

var _INSPECT_BY_FORMAT = { x509: certificate, crl: crlReport, csr: csrReport, cms: cmsReport };

/**
 * @primitive pki.inspect.any
 * @signature pki.inspect.any(input) -> string
 * @since 0.3.8
 * @status stable
 * @spec RFC 5280
 * @related pki.schema.detectFormat, pki.inspect.certificate
 *
 * Detect which PKI format `input` (a PEM string or DER Buffer) encodes and render
 * it with the matching report -- the inspect analogue of `pki.schema.parse`. Routes
 * a certificate / CRL / CSR / CMS to `certificate` / `crl` / `csr` / `cms`; a
 * detected but out-of-scope format (OCSP, TSP, PKCS#8/#12, CRMF, CMP, ...) throws
 * `inspect/unsupported-format` naming it, and an unrecognized input
 * `inspect/bad-input`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) });
 *   pki.inspect.any(der);  // routes to the right report by detected format
 */
function any(input) {
  // Unwrap to DER ONCE (any PEM label), detect from the DER, then route the DER Buffer -- the
  // renderer parses a Buffer directly and never re-applies its own strict PEM label.
  var der, fmt;
  try {
    der = pkix.coerceToDer(input, _INSPECT_ENTRY);
    fmt = schemaAll.detectFormat(der);   // decodes the root -- a non-DER Buffer throws here, not at coerce
  } catch (e) { throw _err("inspect/bad-input", "input is not a decodable DER Buffer or PEM string", e); }
  if (fmt === null) throw _err("inspect/bad-input", "input does not match any registered PKI format");
  var render = _INSPECT_BY_FORMAT[fmt];
  if (!render) throw _err("inspect/unsupported-format", "inspect does not support the detected format \"" + fmt + "\" (supported: certificate, crl, csr, cms)");
  return render(der);
}

module.exports = {
  certificate: certificate,
  crl: crlReport,
  csr: csrReport,
  cms: cmsReport,
  any: any,
  // The extension names certificate() renders to their decoded values (vs the raw
  // hex fallback). The inspect test asserts this covers every extension the shared
  // decoders decode, so a newly-decodable extension cannot silently hex-dump.
  // allow:guard-reads-runtime-live -- module-init, the exports object is built before any caller runs
  renderedExtensions: Object.keys(EXT_RENDERERS),
};
