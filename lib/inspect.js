// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.inspect
 * @nav        Tooling
 * @title      Inspect
 * @intro Human-readable inspection of a parsed certificate -- the pure-JS
 *   equivalent of `openssl x509 -text`. `certificate(input)` ingests a PEM string,
 *   a DER Buffer, or an already-parsed certificate and returns a familiar
 *   OpenSSL-style report: version, serial, signature algorithm, the issuer and
 *   subject distinguished names, the validity window, the public-key details
 *   (curve or modulus size plus the raw point/modulus), every decoded extension
 *   with its critical flag, and the signature. It renders purely from the toolkit's
 *   own strict parser and two-way OID registry -- no OpenSSL dependency, and no
 *   drift-prone second naming table -- so it names extension and algorithm OIDs an
 *   OpenSSL build shows only as raw bytes. The format is stable and OpenSSL-*familiar*
 *   rather than byte-identical to any one OpenSSL version (those disagree across
 *   releases). Rendering is best-effort: a malformed extension falls back to a hex
 *   dump rather than throwing.
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

// ---- formatting helpers ------------------------------------------------------

var HEX = "0123456789abcdef";
function _hexColon(buf, opts) {
  opts = opts || {};
  var hex = [];
  for (var i = 0; i < buf.length; i++) {
    var b = buf[i], s = HEX[(b >> 4) & 0xf] + HEX[b & 0xf];
    hex.push(opts.upper ? s.toUpperCase() : s);
  }
  if (!opts.wrap) return hex.join(":");
  // Wrap at `opts.wrap` bytes per line, each line indented by `opts.indent`.
  var pad = " ".repeat(opts.indent || 0), lines = [];
  for (var j = 0; j < hex.length; j += opts.wrap) {
    var chunk = hex.slice(j, j + opts.wrap).join(":");
    lines.push(pad + chunk + (j + opts.wrap < hex.length ? ":" : ""));
  }
  return lines.join("\n");
}

// Coverage residual -- two _hexColon default arms are unreachable through the public API:
//   * `opts = opts || {}` -- all call sites pass an explicit opts object literal, so the
//     `|| {}` default never fires.
//   * `" ".repeat(opts.indent || 0)` -- every wrap-mode caller passes a positive indent
//     (pad.length + 8 >= 8, or inner.length == 16), so `opts.indent` is never falsy.

// Control-byte neutralization for a GeneralName string value routes through the
// guard family (the guard-shape-reinlined detector protects the shape).
// @guard-via guard\.name\.escape
var _clean = guard.name.escapeControlBytes;

// The DN display string. pki.schema.pkix already assembles a fully RFC 4514-escaped
// dn (short names from pki.C.NAMES.DN_SHORT, values escaped via guard.name.escapeDnValue,
// with the '#'-hex / leading-'\' sentinel handled), so reuse it rather than re-escaping
// the already-escaped values (which would double-escape a leading '#' / '\').
function _dnString(name) { return (name && name.dn) || ""; }

var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function _two(n) { return (n < 10 ? "0" : "") + n; }
// OpenSSL date: "Jul  4 07:00:27 2026 GMT" (month, space-padded day, time, year, GMT).
function _date(iso) {
  var d = (iso instanceof Date) ? iso : new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
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
  var buf = Buffer.from(hex, "hex");
  // Strip a single DER positive-sign 00 byte (present when the value's high bit is
  // set) so the printed serial is the integer VALUE, matching OpenSSL -- not the
  // encoding's leading octet.
  if (buf.length > 1 && buf[0] === 0x00 && (buf[1] & 0x80)) buf = buf.subarray(1);
  // Small non-negative serials render inline as decimal (0xhex), like OpenSSL;
  // anything larger renders as a colon-hex block.
  if (buf.length <= 6) {
    var n = parseInt(buf.toString("hex") || "0", 16);
    return "Serial Number: " + n + " (0x" + (buf.toString("hex").replace(/^0+/, "") || "0") + ")";
  }
  return "Serial Number:\n" + " ".repeat(indent) + _hexColon(buf, {});
}

var CURVE_BITS = { "P-256": 256, "P-384": 384, "P-521": 521, "prime256v1": 256, "secp384r1": 384, "secp521r1": 521 };
var NIST_NAME = NAMES.NIST_CURVE;
// Every RSA-family key algorithm carries the same SPKI subjectPublicKey -- an
// RSAPublicKey SEQUENCE { modulus, publicExponent } (RFC 4055 sec. 1.2 for
// id-RSASSA-PSS / id-RSAES-OAEP) -- so all decode to modulus + exponent, not raw bytes.
var RSA_KEY_ALGS = { rsaEncryption: 1, rsassaPss: 1, rsaesOaep: 1 };
function _keyBlock(spki, pad) {
  var algName = _algName(spki.algorithm);
  var out = [pad + "Public Key Algorithm: " + algName];
  var inner = pad + "    ";
  var pub = Buffer.isBuffer(spki.publicKey) ? spki.publicKey : (spki.publicKey && Buffer.isBuffer(spki.publicKey.bytes) ? spki.publicKey.bytes : null);

  if (algName === "ecPublicKey" || algName === "id-ecPublicKey") {
    var curveName = null;
    try { curveName = oid.name(asn1.read.oid(asn1.decode(spki.algorithm.parameters))); }
    catch (_e) { /* unknown curve */ }
    var bits = CURVE_BITS[curveName] || (pub ? ((pub.length - 1) / 2) * 8 : 0);
    out.push(inner + "Public-Key: (" + bits + " bit)");
    if (pub) { out.push(inner + "pub:"); out.push(_hexColon(pub, { wrap: 16, indent: (pad.length + 8) })); }
    if (curveName) { out.push(inner + "ASN1 OID: " + curveName); if (NIST_NAME[curveName]) out.push(inner + "NIST CURVE: " + NIST_NAME[curveName]); }
    return out.join("\n");
  }
  if (RSA_KEY_ALGS[algName]) {
    try {
      var rsa = asn1.decode(pub);   // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
      var modBig = asn1.read.integer(rsa.children[0]);
      var expBig = asn1.read.integer(rsa.children[1]);
      var modHex = modBig.toString(16); if (modHex.length % 2) modHex = "0" + modHex;
      var modBuf = Buffer.from(modHex, "hex");
      // Bit length is the value's, not the byte count's (a 0x7f.. modulus is 127-bit,
      // not 128), and the DER sign-padding 00 is present only when the top bit is set.
      out.push(inner + "Public-Key: (" + modBig.toString(2).length + " bit)");
      out.push(inner + "Modulus:");
      var modDisplay = (modBuf.length && (modBuf[0] & 0x80)) ? Buffer.concat([Buffer.from([0x00]), modBuf]) : modBuf;
      out.push(_hexColon(modDisplay, { wrap: 16, indent: (pad.length + 8) }));
      out.push(inner + "Exponent: " + expBig.toString(10) + " (0x" + expBig.toString(16) + ")");
      return out.join("\n");
    } catch (_e) { /* fall through to raw */ }
  }
  // EdDSA / ML-DSA / SLH-DSA / anything else: show the raw public-key bytes.
  if (pub) { out.push(inner + "Public-Key: (" + (pub.length * 8) + " bit)"); out.push(inner + "pub:"); out.push(_hexColon(pub, { wrap: 16, indent: (pad.length + 8) })); }
  return out.join("\n");
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
  if (!Buffer.isBuffer(buf)) return "";
  if (buf.length === 4) return buf[0] + "." + buf[1] + "." + buf[2] + "." + buf[3];
  if (buf.length === 8) return _ipString(buf.subarray(0, 4)) + "/" + _ipString(buf.subarray(4));
  if (buf.length === 16 || buf.length === 32) {
    var groups = [];
    for (var i = 0; i < 16; i += 2) groups.push((((buf[i] << 8) | buf[i + 1]) >>> 0).toString(16).toUpperCase());
    var s = groups.join(":");
    return buf.length === 32 ? s + "/" + _ipString(buf.subarray(16)) : s;
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
function _gn(g) {
  if (!g || typeof g !== "object") return "";
  var t = g.tagNumber;
  if (t === 7 && Buffer.isBuffer(g.value)) return "IP Address:" + _ipString(g.value);
  if (t === 4) {
    var dn = (g.value && Array.isArray(g.value.rdns)) ? _dnString(g.value) : ((g.value && g.value.dn) || "");
    return "DirName:" + dn;
  }
  if (t === 0) return "othername:" + (Buffer.isBuffer(g.bytes) ? _hexColon(g.bytes, {}) : "<unsupported>");
  var kind = GN_KIND[t] || ("tag" + t);
  var v = (typeof g.value === "string") ? _clean(g.value)
    : Buffer.isBuffer(g.value) ? _hexColon(g.value, {})
      : Buffer.isBuffer(g.bytes) ? _hexColon(g.bytes, {}) : "";
  return kind + ":" + v;
}

// Format a GeneralName still in its raw DER TLV (a CRL distribution point leaves
// its fullName entries undecoded) -- decode the context tag and render its content.
function _gnRaw(buf) {
  if (!Buffer.isBuffer(buf)) return "";
  try {
    var node = asn1.decode(buf);
    var t = node.tagNumber;
    if (t === 1 || t === 2 || t === 6) return GN_KIND[t] + ":" + _clean(node.content.toString("latin1"));
    if (t === 7) return "IP Address:" + _ipString(node.content);
    return _hexColon(buf, {});   // dirName / otherName / registeredID -> best-effort hex
    // allow:swallow-unverified drop-silent display fallback (tier-3): fullName GNs reach here as
    // schema-validated TLVs so asn1.decode cannot throw -- an unreachable defensive best-effort hex render.
  } catch (_e) { return _hexColon(buf, {}); }
}

// Coverage residual -- the GeneralName render fallbacks are unreachable because the strict
// generalName decoder and each caller already narrow the shape (the _gnRaw catch above is
// separately documented):
//   * _ipString `if (!Buffer.isBuffer(buf)) return "";` -- every caller passes a Buffer (the
//     recursion slices a Buffer, _gn guards Buffer.isBuffer(g.value), _gnRaw passes
//     asn1.decode(...).content).
//   * _ipString trailing `return _hexColon(buf, {});` -- generalName enforces iPAddress to
//     4/16 octets (8/32 for a name-constraints subtree base), so length is only ever 4/8/16/32.
//   * _gn `if (!g || typeof g !== "object") return "";` -- every _gn call maps a decoder-produced
//     GeneralName object; the decoders never emit a null element.
//   * _gn directoryName `: ((g.value && g.value.dn) || "")` -- a decoded directoryName [4] always
//     carries a Name with an rdns array, so the rdns arm is always taken.
//   * _gn otherName `: "<unsupported>"` -- a decoded GeneralName always carries its raw bytes TLV.
//   * _gn `|| ("tag" + t)` -- GeneralName CHOICE tags are 0..8, all mapped in NAMES.GENERAL_NAME;
//     generalName rejects a tag outside 0..8.
//   * _gn `? _hexColon(g.value, {})` -- iPAddress [7] is the only choice whose decoded value is a
//     Buffer, handled at the t === 7 branch before this ternary; other tags' value is string or null.
//   * _gn trailing `: ""` -- a decoded GeneralName always carries a bytes Buffer, so the
//     Buffer.isBuffer(g.bytes) arm is always taken.
//   * _gnRaw `if (!Buffer.isBuffer(buf)) return "";` -- the sole caller (the CRL-DP fullName loop)
//     guards Buffer.isBuffer(nm) before calling _gnRaw.

// Shared value renderers reused by more than one extension key.
function _renderAltName(decoded, inner) {
  return inner + (decoded.names || []).map(_gn).join(", ");
}
function _renderCrlDp(decoded, inner) {
  var dpLines = [];
  (decoded || []).forEach(function (dp) {
    var d = dp.distributionPoint, wrote = false;
    if (d && d.kind === "fullName" && Array.isArray(d.names)) {
      dpLines.push(inner + "Full Name:");
      d.names.forEach(function (nm) { dpLines.push(inner + "  " + (Buffer.isBuffer(nm) ? _gnRaw(nm) : _gn(nm))); });
      wrote = true;
    } else if (d && d.kind === "rdn") {
      dpLines.push(inner + "Relative Name (to CRL issuer)");
      wrote = true;
    }
    // The reasons BIT STRING scopes which revocation reasons this DP covers; dropping
    // it would make a scoped revocation source look generally applicable.
    if (dp.reasons && Buffer.isBuffer(dp.reasons.bytes)) {
      var rf = [], rb = dp.reasons.bytes;
      for (var bit = 1; bit < rb.length * 8; bit++) {
        if ((rb[bit >> 3] & (0x80 >> (bit & 7))) && NAMES.REASON_FLAGS[bit]) rf.push(NAMES.REASON_FLAGS[bit]);
      }
      if (rf.length) { dpLines.push(inner + "Reasons: " + rf.join(", ")); wrote = true; }
    }
    // A DistributionPoint may carry only cRLIssuer (an indirect CRL, no
    // distributionPoint) -- render the issuer GeneralNames rather than dropping them.
    if (dp.cRLIssuer && Array.isArray(dp.cRLIssuer.names)) {
      dpLines.push(inner + "CRL Issuer:");
      dp.cRLIssuer.names.forEach(function (g) { dpLines.push(inner + "  " + _gn(g)); });
      wrote = true;
    }
    if (!wrote) dpLines.push(inner + "(distribution point)");
  });
  return dpLines.join("\n");
}

// Coverage residual -- the shared alt-name / CRL-DP render fallbacks are unreachable because the
// strict decoders already narrow the shape:
//   * _renderAltName `(decoded.names || [])` -- the subjectAltName/issuerAltName decoder always
//     yields a names array.
//   * _renderCrlDp `(decoded || [])` -- the cRLDistributionPoints/freshestCRL decoder always
//     yields an array.
//   * _renderCrlDp `: _gn(nm)` -- distributionPointName surfaces fullName entries as raw
//     GeneralName Buffers, so Buffer.isBuffer(nm) is always true.
//   * _renderCrlDp `if (!wrote) ... "(distribution point)"` -- crlDistributionPoints throws unless
//     a distributionPoint (always fullName/rdn) or cRLIssuer (sets wrote) is present, so !wrote
//     never holds.

// Declarative extension-value renderer registry: extension name -> (decoded, inner) ->
// text. Data-driven dispatch (the schema family's "registry, not switch" shape) so a
// new extension is a row rather than another hand-coded branch, and the set an
// operator sees rendered is visible in one place. An extension with no row here
// hex-dumps its raw value (best-effort); each row's output is pinned by an
// inspect.test.js conformance vector.
var EXT_RENDERERS = {
  keyUsage: function (decoded, inner) {
    return inner + Object.keys(KU_LABEL).filter(function (k) { return decoded[k]; }).map(function (k) { return KU_LABEL[k]; }).join(", ");
  },
  extKeyUsage: function (decoded, inner) {
    return inner + decoded.map(function (o) {
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
    return decoded.map(function (s) {
      var label = inner + (s.name || s.statementId), info = s.info;
      if (!info) return label;                                                              // presence-only (QcCompliance / QcSSCD)
      if (info.opaque) return label + " (opaque)";
      if (typeof info.amount !== "undefined") return label + ": " + info.amount + " " + info.currency + (info.exponent ? " x10^" + info.exponent : "");   // QcLimitValue
      if (typeof info.years !== "undefined") return label + ": " + info.years + " years";   // QcRetentionPeriod
      if (info.typeNames) return label + ": " + info.typeNames.map(function (n, i) { return n || info.types[i]; }).join(", ");         // QcType
      if (info.methodNames) return label + ": " + info.methodNames.map(function (n, i) { return n || info.methods[i]; }).join(", ");   // QcIdentMethod
      if (info.locations) return label + ": " + info.locations.map(function (l) { return l.url + " (" + l.language + ")"; }).join(", "); // QcPDS
      if (info.countries) return label + ": " + info.countries.join(", ");                  // QcCClegislation / QcQSCDlegislation
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
    return inner + "Cert Type: " + _clean(String(decoded));
  },
  msCaVersion: function (decoded, inner) {
    return inner + "CA Version: V" + decoded.caKeyIndex + "." + decoded.certIndex;
  },
  msPreviousCertHash: function (decoded, inner) {
    return inner + _hexColon(Buffer.isBuffer(decoded) ? decoded : Buffer.alloc(0), { upper: true });
  },
  subjectAltName: _renderAltName,
  issuerAltName: _renderAltName,
  certificatePolicies: function (decoded, inner) {
    var lines = [];
    decoded.forEach(function (p) {
      lines.push(inner + "Policy: " + p.policyIdentifier);
      if (!Buffer.isBuffer(p.qualifiersBytes)) return;
      // Render each PolicyQualifierInfo { policyQualifierId, qualifier }: a printable
      // qualifier (a CPS URI is an IA5String) shows as text, else a hex dump -- never
      // dropped (which would make a qualified policy look unqualified).
      try {
        (asn1.decode(p.qualifiersBytes).children || []).forEach(function (pqi) {
          var qid = asn1.read.oid(pqi.children[0]), q = pqi.children[1];
          var label = null;
          try { label = oid.name(qid); }
          catch (_e) { /* unregistered qualifier */ }
          var val = (q && !q.constructed && Buffer.isBuffer(q.content) && _printable(q.content))
            ? _clean(q.content.toString("latin1"))
            : _hexColon(q && Buffer.isBuffer(q.bytes) ? q.bytes : Buffer.alloc(0), {});
          lines.push(inner + "  " + (label || qid) + ": " + val);
        });
      } catch (_e) {
        lines.push(inner + "  " + _hexColon(p.qualifiersBytes, {}));
      }
    });
    return lines.join("\n");
  },
  cRLDistributionPoints: _renderCrlDp,
  freshestCRL: _renderCrlDp,
  nameConstraints: function (decoded, inner) {
    var ncLines = [];
    ["permittedSubtrees:Permitted", "excludedSubtrees:Excluded"].forEach(function (pair) {
      var key = pair.split(":")[0], label = pair.split(":")[1], arr = decoded[key];
      if (!Array.isArray(arr) || !arr.length) return;
      ncLines.push(inner + label + ":");
      arr.forEach(function (st) { ncLines.push(inner + "  " + _gn(st.base)); });
    });
    return ncLines.join("\n");
  },
  policyConstraints: function (decoded, inner) {
    var pc = [];
    if (decoded.requireExplicitPolicy != null) pc.push(inner + "Require Explicit Policy: " + decoded.requireExplicitPolicy);
    if (decoded.inhibitPolicyMapping != null) pc.push(inner + "Inhibit Policy Mapping: " + decoded.inhibitPolicyMapping);
    return pc.length ? pc.join("\n") : inner + "(empty)";
  },
  inhibitAnyPolicy: function (decoded, inner) {
    return inner + "Inhibit Any Policy Skip Certs: " + decoded;
  },
  policyMappings: function (decoded, inner) {
    return decoded.map(function (m) { return inner + m.issuerDomainPolicy + " -> " + m.subjectDomainPolicy; }).join("\n");
  },
  signedCertificateTimestampList: function (decoded, inner) {
    var sct = [];
    (decoded.scts || []).forEach(function (s) {
      sct.push(inner + "Signed Certificate Timestamp:");
      sct.push(inner + "    Version: v" + ((typeof s.version === "number" ? s.version : 0) + 1));
      if (s.logIdHex) sct.push(inner + "    Log ID: " + String(s.logIdHex).toUpperCase());
      if (s.timestamp != null) sct.push(inner + "    Timestamp: " + String(s.timestamp));
    });
    var unk = (decoded.unknownScts || []).length;
    if (unk) sct.push(inner + "(" + unk + " SCT(s) of an unrecognized version)");
    return sct.length ? sct.join("\n") : inner + "(empty SCT list)";
  },
  precertificatePoison: function (decoded, inner) {
    return inner + "Precertificate Poison (this is a precertificate, not a certificate)";
  },
  subjectKeyIdentifier: function (decoded, inner) {
    return inner + _hexColon(Buffer.isBuffer(decoded) ? decoded : (decoded.bytes || Buffer.alloc(0)), { upper: true });
  },
  authorityKeyIdentifier: function (decoded, inner) {
    // Any of the three fields may be present; the issuer+serial form carries no
    // keyIdentifier, so render whichever the decoder populated rather than claiming
    // "keyid:(none)" and dropping the certificate's real authority identifier.
    var akiLines = [];
    if (Buffer.isBuffer(decoded.keyIdentifier)) akiLines.push(inner + "keyid:" + _hexColon(decoded.keyIdentifier, { upper: true }));
    if (decoded.authorityCertIssuer && Array.isArray(decoded.authorityCertIssuer.names)) {
      decoded.authorityCertIssuer.names.forEach(function (g) { akiLines.push(inner + _gn(g)); });
    }
    if (decoded.authorityCertSerialNumber != null) {
      var sn = (typeof decoded.authorityCertSerialNumber === "bigint"
        ? decoded.authorityCertSerialNumber : BigInt(decoded.authorityCertSerialNumber)).toString(16);
      if (sn.length % 2) sn = "0" + sn;
      akiLines.push(inner + "serial:0x" + sn.toUpperCase());
    }
    return akiLines.length ? akiLines.join("\n") : inner + "keyid:(none)";
  },
};
// [MS-WCCE] szOID-APPLICATION_CERT_POLICIES decodes as certificatePolicies, so it renders identically.
EXT_RENDERERS.msApplicationPolicies = EXT_RENDERERS.certificatePolicies;

// Coverage residual -- the EXT_RENDERERS entry fallbacks are unreachable because each shared
// decoder (and asn1.read.oid) already narrows the shape before the renderer runs:
//   * extKeyUsage `catch (_e) { /* unregistered EKU OID */ }` and certificatePolicies
//     `catch (_e) { /* unregistered qualifier */ }` -- oid.name returns undefined (never throws)
//     for a well-formed unregistered OID; it throws only on a non-dotted argument, and both OIDs
//     come from asn1.read.oid (always a valid dotted OID).
//   * certificatePolicies `(asn1.decode(p.qualifiersBytes).children || [])` -- asn1.decode of the
//     assertPolicyQualifiers-validated qualifiers SEQUENCE always yields a children array.
//   * certificatePolicies `: Buffer.alloc(0)` -- assertPolicyQualifiers requires every
//     PolicyQualifierInfo to be a 2-child SEQUENCE, so pqi.children[1] is always a present node
//     carrying a bytes Buffer.
//   * certificatePolicies outer `catch (_e) { ... _hexColon(p.qualifiersBytes, {}) ... }` --
//     certificatePolicies already validated qualifiersBytes as a SEQUENCE of 2-child PQIs each
//     leading with a valid OID, so the re-decode + asn1.read.oid cannot throw.
//   * policyConstraints `: inner + "(empty)"` -- policyConstraints rejects an empty SEQUENCE
//     (>= 1 context field), so requireExplicitPolicy or inhibitPolicyMapping is non-null;
//     pc.length is never 0.
//   * SCT `(decoded.scts || [])` / `(decoded.unknownScts || [])` -- ct.parseSctList always returns
//     both arrays.
//   * SCT `: 0` -- every scts entry is a decoded v1 SCT with numeric version 0 (unknown-version
//     SCTs go to unknownScts and are not iterated here).
//   * SCT `: inner + "(empty SCT list)"` -- ct.parseSctList rejects an empty list and routes every
//     SerializedSCT into scts/unknownScts, so at least one line is always emitted.
//   * subjectKeyIdentifier `: (decoded.bytes || Buffer.alloc(0))` -- the subjectKeyIdentifier
//     decoder returns the KeyIdentifier as a Buffer, so Buffer.isBuffer(decoded) is always true.
//   * authorityKeyIdentifier `: BigInt(decoded.authorityCertSerialNumber)` -- the AKI decoder reads
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
// A value renders as text only when EVERY byte is a printable, non-control ASCII
// character. A control byte (a bare CR / LF / TAB, etc.) is rejected here so a
// hostile private-extension value cannot forge or overwrite report lines in a
// terminal or log -- such a value falls through to the hex dump instead.
function _printable(buf) {
  return buf.length > 0 && buf.every(function (b) { return b >= 0x20 && b < 0x7f; });
}
function _fallback(value, inner) {
  if (!Buffer.isBuffer(value) || value.length === 0) return inner + "(empty)";
  if (_printable(value)) return inner + value.toString("latin1");
  try {
    var n = asn1.decode(value);
    if (n.tagClass === "universal" && _STRING_TAGS[n.tagNumber]) {
      var s = asn1.read.string(n);
      if (_printable(Buffer.from(s, "utf8"))) return inner + s;
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
// with only a tbsBytes property is NOT a certificate: without this check the renderer
// would dereference a missing field (c.validity.notBefore, ...) and throw a raw
// TypeError instead of the documented typed inspect/bad-input (the API's error contract).
function _looksParsed(o) {
  return typeof o.version === "number" && typeof o.serialNumberHex === "string" &&
    o.signatureAlgorithm && typeof o.signatureAlgorithm === "object" &&
    o.issuer && typeof o.issuer === "object" && o.subject && typeof o.subject === "object" &&
    o.validity && o.validity.notBefore != null && o.validity.notAfter != null &&
    o.subjectPublicKeyInfo && typeof o.subjectPublicKeyInfo === "object" && Array.isArray(o.extensions);
}

function _parse(input) {
  if (input && typeof input === "object" && !Buffer.isBuffer(input) && input.tbsBytes) {
    if (!_looksParsed(input)) throw _err("inspect/bad-input", "input has a tbsBytes property but is not a complete pki.schema.x509.parse result");
    return input;   // a genuine already-parsed certificate
  }
  var der;
  if (Buffer.isBuffer(input)) der = input;
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
 * @status experimental
 * @spec RFC 5280
 * @related pki.schema.x509.parse
 *
 * Render a certificate as a human-readable, OpenSSL-familiar text report. `input`
 * is a PEM string, a DER Buffer, or a `pki.schema.x509.parse` result. A value that
 * is none of those throws `inspect/bad-input`; a malformed certificate throws
 * `inspect/bad-certificate`; but a malformed individual extension is rendered as a
 * hex dump rather than failing the whole report. Pure -- no OpenSSL dependency.
 *
 * @example
 *   var cert = pki.schema.x509.parse(der);
 *   pki.inspect.certificate(cert).split("\n")[0]; // "Certificate:"
 */
function certificate(input) {
  var c = _parse(input);
  var L = [];
  L.push("Certificate:");
  L.push("    Data:");
  L.push("        Version: " + c.version + " (0x" + (c.version - 1).toString(16) + ")");
  L.push("        " + _serial(c, 12));
  L.push("        Signature Algorithm: " + _algName(c.signatureAlgorithm));
  L.push("        Issuer: " + _dnString(c.issuer));
  L.push("        Validity");
  L.push("            Not Before: " + _date(c.validity.notBefore));
  L.push("            Not After : " + _date(c.validity.notAfter));
  L.push("        Subject: " + _dnString(c.subject));
  L.push("        Subject Public Key Info:");
  L.push(_keyBlock(c.subjectPublicKeyInfo, "            "));
  // Coverage residual -- `c.extensions || []` is unreachable: both input paths guarantee an array
  // (x509.parse yields one; the pre-parsed fast path requires Array.isArray(extensions) in _looksParsed).
  if ((c.extensions || []).length) {
    L.push("        X509v3 extensions:");
    c.extensions.forEach(function (ext) { L.push(_extension(ext, "            ")); });
  }
  L.push("    Signature Algorithm: " + _algName(c.signatureAlgorithm));
  var sig = c.signatureValue && (c.signatureValue.bytes || c.signatureValue);
  if (Buffer.isBuffer(sig)) { L.push("    Signature Value:"); L.push(_hexColon(sig, { wrap: 16, indent: 8 })); }
  return L.join("\n") + "\n";
}

// ---- CRL / CSR / CMS coercion (the _parse model, per format) -----------------

// Each fast-path completeness check mirrors _looksParsed: a bare/partial object
// with only the marker field is NOT a parsed result, so it throws the documented
// typed inspect/bad-input rather than dereferencing a missing field.
function _looksParsedCrl(o) {
  return typeof o.version === "number" && o.issuer && typeof o.issuer === "object" &&
    o.thisUpdate != null && Array.isArray(o.revokedCertificates) && Array.isArray(o.crlExtensions) &&
    o.signatureAlgorithm && typeof o.signatureAlgorithm === "object";
}
function _looksParsedCsr(o) {
  return typeof o.version === "number" && o.subject && typeof o.subject === "object" &&
    o.subjectPublicKeyInfo && typeof o.subjectPublicKeyInfo === "object" &&
    Array.isArray(o.attributes) && o.signatureAlgorithm && typeof o.signatureAlgorithm === "object";
}
function _looksParsedCms(o) {
  if (typeof o.contentType !== "string" || typeof o.contentTypeName !== "string" || typeof o.version !== "number") return false;
  // A SignedData parse result additionally carries the fields the report reads, so a partial
  // object (contentType/name only) fails closed as inspect/bad-input rather than a partial render.
  if (o.contentType === OID_SIGNED_DATA) {
    return Array.isArray(o.digestAlgorithms) && o.encapContentInfo && typeof o.encapContentInfo === "object" && Array.isArray(o.signerInfos);
  }
  return true;
}
// A parameterized _parse clone: marker field, fast-path completeness check, then
// Buffer -> DER, string -> pemDecode(label), then parse(der) inside try.
function _coerce(input, spec) {
  if (input && typeof input === "object" && !Buffer.isBuffer(input) && input[spec.marker] !== undefined) {
    if (!spec.looksParsed(input)) throw _err("inspect/bad-input", "input has a " + spec.marker + " property but is not a complete " + spec.parsedName + " result");
    return input;
  }
  var der;
  if (Buffer.isBuffer(input)) der = input;
  else if (typeof input === "string") {
    try { der = spec.pemDecode(input, spec.pemLabel); }
    catch (e) { throw _err("inspect/bad-input", "input is not a PEM " + spec.pemLabel, e); }
  } else {
    throw _err("inspect/bad-input", "input must be a parsed " + spec.what + ", a DER Buffer, or a PEM string");
  }
  try { return spec.parse(der); }
  catch (e) { throw _err(spec.badCode, "input is not a well-formed " + spec.what, e); }
}
function _parseCrl(input) { return _coerce(input, { marker: "thisUpdate", looksParsed: _looksParsedCrl, parsedName: "pki.schema.crl.parse", pemDecode: crl.pemDecode, pemLabel: "X509 CRL", parse: crl.parse, badCode: "inspect/bad-crl", what: "X.509 CRL" }); }
function _parseCsr(input) { return _coerce(input, { marker: "certificationRequestInfoBytes", looksParsed: _looksParsedCsr, parsedName: "pki.schema.csr.parse", pemDecode: csr.pemDecode, pemLabel: "CERTIFICATE REQUEST", parse: csr.parse, badCode: "inspect/bad-csr", what: "PKCS#10 certification request" }); }
function _parseCms(input) { return _coerce(input, { marker: "contentType", looksParsed: _looksParsedCms, parsedName: "pki.schema.cms.parse", pemDecode: cms.pemDecode, pemLabel: "CMS", parse: cms.parse, badCode: "inspect/bad-cms", what: "CMS message" }); }

// ---- shared attribute-value renderer (CSR attributes + CMS signed/unsigned) ---

// Decode the known content-binding attribute types for display; anything else, or
// a decode failure, falls back to printable-or-hex. Never throws once parsed.
function _attrValue(name, rawDer, inner) {
  try {
    if (name === "contentType") { var ct = asn1.read.oid(asn1.decode(rawDer)); return inner + (oid.name(ct) || ct); }
    if (name === "messageDigest") return _hexColon(asn1.read.octetString(asn1.decode(rawDer)), { wrap: 16, indent: inner.length });
    if (name === "signingTime") return inner + _date(asn1.read.time(asn1.decode(rawDer)));
  } catch (_e) { /* fall through to the raw fallback */ }
  return _fallback(rawDer, inner);
}

// ---- CRL report --------------------------------------------------------------

// The CRL decoder PRE-DECODES three extension values to a JS type (not the raw
// Buffer the shared _extension consumes): cRLNumber -> BigInt, reasonCode ->
// Number, invalidityDate -> Date. Render those directly; delegate every raw-value
// extension (AKI / IDP / deltaCRLIndicator / freshestCRL / certificateIssuer) to
// the shared _extension verbatim.
function _crlExtension(ext, pad) {
  var label = EXT_LABEL[ext.name] || ext.name || ext.oid;
  var header = pad + label + ":" + (ext.critical ? " critical" : "");
  var inner = pad + "    ";
  if (ext.name === "cRLNumber" && typeof ext.value === "bigint") return header + "\n" + inner + String(ext.value);
  if (ext.name === "reasonCode" && typeof ext.value === "number") return header + "\n" + inner + (NAMES.CRL_REASON[ext.value] || String(ext.value));
  if (ext.name === "invalidityDate" && ext.value instanceof Date) return header + "\n" + inner + _date(ext.value);
  return _extension(ext, pad);
}

/**
 * @primitive pki.inspect.crl
 * @signature pki.inspect.crl(input) -> string
 * @since 0.3.8
 * @status experimental
 * @spec RFC 5280
 * @related pki.schema.crl.parse, pki.inspect.certificate
 *
 * Render a certificate revocation list as an `openssl crl -text`-familiar text
 * report: issuer, Last/Next Update, the CRL extensions, each revoked entry (serial,
 * revocation date, entry extensions), and the signature. `input` is a PEM string, a
 * DER Buffer, or a `pki.schema.crl.parse` result; a non-CRL throws
 * `inspect/bad-crl`, a wrong-type input `inspect/bad-input`. A malformed individual
 * extension renders as hex rather than failing the report.
 *
 * @example
 *   pki.inspect.crl(crlDer).split("\n")[0]; // "Certificate Revocation List (CRL):"
 */
function crlReport(input) {
  var c = _parseCrl(input);
  var L = ["Certificate Revocation List (CRL):"];
  L.push("        Version " + c.version + " (0x" + (c.version - 1).toString(16) + ")");
  L.push("    Signature Algorithm: " + _algName(c.signatureAlgorithm));
  L.push("        Issuer: " + _dnString(c.issuer));
  L.push("        Last Update: " + _date(c.thisUpdate));
  L.push("        Next Update: " + (c.nextUpdate ? _date(c.nextUpdate) : "NONE"));
  if (c.crlExtensions.length) {
    L.push("        CRL extensions:");
    c.crlExtensions.forEach(function (ext) { L.push(_crlExtension(ext, "            ")); });
  }
  if (c.revokedCertificates.length) {
    L.push("Revoked Certificates:");
    c.revokedCertificates.forEach(function (e) {
      L.push("    " + _serial(e, 8));
      L.push("        Revocation Date: " + _date(e.revocationDate));
      if ((e.crlEntryExtensions || []).length) {
        L.push("        CRL entry extensions:");
        e.crlEntryExtensions.forEach(function (ext) { L.push(_crlExtension(ext, "            ")); });
      }
    });
  } else {
    L.push("No Revoked Certificates.");
  }
  L.push("    Signature Algorithm: " + _algName(c.signatureAlgorithm));
  var sig = c.signatureValue && (c.signatureValue.bytes || c.signatureValue);
  if (Buffer.isBuffer(sig)) { L.push("    Signature Value:"); L.push(_hexColon(sig, { wrap: 16, indent: 8 })); }
  return L.join("\n") + "\n";
}

// ---- CSR report --------------------------------------------------------------

function _attribute(attr, pad) {
  var inner = pad + "    ";
  // extensionRequest carries decoded RFC 5280 extensions (the cert-extension shape)
  // -> render each through the shared _extension, identically to a certificate's.
  if (attr.name === "extensionRequest" && Array.isArray(attr.extensions)) {
    var lines = [pad + "Requested Extensions:"];
    attr.extensions.forEach(function (ext) { lines.push(_extension(ext, inner)); });
    return lines.join("\n");
  }
  var header = pad + (attr.name || oid.name(attr.type) || attr.type) + ":";
  var vals = (attr.values || []).map(function (v) { return _attrValue(attr.name, v, inner); });
  return vals.length ? header + "\n" + vals.join("\n") : header;
}

/**
 * @primitive pki.inspect.csr
 * @signature pki.inspect.csr(input) -> string
 * @since 0.3.8
 * @status experimental
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
 *   pki.inspect.csr(csrDer).split("\n")[0]; // "Certificate Request:"
 */
function csrReport(input) {
  var c = _parseCsr(input);
  var L = ["Certificate Request:", "    Data:"];
  L.push("        Version: " + c.version + " (0x" + (c.version - 1).toString(16) + ")");
  L.push("        Subject: " + _dnString(c.subject));
  L.push("        Subject Public Key Info:");
  L.push(_keyBlock(c.subjectPublicKeyInfo, "            "));
  L.push("        Attributes:");
  if (c.attributes.length) c.attributes.forEach(function (attr) { L.push(_attribute(attr, "            ")); });
  else L.push("            (none)");
  L.push("    Signature Algorithm: " + _algName(c.signatureAlgorithm));
  var sig = c.signatureValue && (c.signatureValue.bytes || c.signatureValue);
  if (Buffer.isBuffer(sig)) { L.push("    Signature Value:"); L.push(_hexColon(sig, { wrap: 16, indent: 8 })); }
  return L.join("\n") + "\n";
}

// ---- CMS report --------------------------------------------------------------

// Dispatch on the STABLE contentType OID, never the display name: pki.oid.register()
// lets an application override the built-in "signedData" name, and dispatching on the
// mutable name would then misroute a valid SignedData to the generic summary.
var OID_SIGNED_DATA = oid.byName("signedData");

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
      return pad + kind + ":\n" + sub.replace(/\n$/, "").split("\n").map(function (l) { return pad + "    " + l; }).join("\n");
    } catch (_e) { /* fall through to the summary */ }
  }
  return pad + kind + " [" + el.tagClass + " " + el.tagNumber + "] (" + el.bytes.length + " bytes)";
}

function _signerInfoAttrs(title, attrs, pad) {
  var lines = [pad + title + ":"];
  var inner = pad + "    ";
  attrs.forEach(function (a) {
    var vals = (a.values || []).map(function (v) { return _attrValue(a.name, v, inner + "    "); });
    lines.push(inner + (a.name || oid.name(a.type) || a.type) + ":");
    vals.forEach(function (v) { lines.push(v); });
  });
  return lines.join("\n");
}

function _signerInfo(si, pad) {
  var inner = pad + "    ";
  var L = [pad + "SignerInfo:", inner + "Version: " + si.version];
  if (si.sid && si.sid.serialNumberHex !== undefined) {
    L.push(inner + "Issuer: " + _dnString(si.sid.issuer));
    L.push(inner + _serial(si.sid, pad.length + 8));
  } else if (si.sid && Buffer.isBuffer(si.sid.subjectKeyIdentifier)) {
    L.push(inner + "Subject Key Identifier: " + _hexColon(si.sid.subjectKeyIdentifier, {}));
  }
  L.push(inner + "Digest Algorithm: " + _algName(si.digestAlgorithm));
  if (si.signedAttrs && si.signedAttrs.length) L.push(_signerInfoAttrs("Signed Attributes", si.signedAttrs, inner));
  L.push(inner + "Signature Algorithm: " + _algName(si.signatureAlgorithm));
  if (si.unsignedAttrs && si.unsignedAttrs.length) L.push(_signerInfoAttrs("Unsigned Attributes", si.unsignedAttrs, inner));
  if (Buffer.isBuffer(si.signature)) { L.push(inner + "Signature Value:"); L.push(_hexColon(si.signature, { wrap: 16, indent: pad.length + 8 })); }
  return L.join("\n");
}

/**
 * @primitive pki.inspect.cms
 * @signature pki.inspect.cms(input) -> string
 * @since 0.3.8
 * @status experimental
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
 *   pki.inspect.cms(cmsDer).split("\n")[0]; // "CMS ContentInfo:"
 */
// A ContentInfo whose content type pki.schema.cms.parse does not dispatch (id-data,
// digestedData, ...) is a VALID CMS the parser defers, not a malformed message -- render an
// outer-only summary (the named content type) rather than failing the report.
function _cmsOuterSummary(input) {
  var ct = null;
  try {
    var der = Buffer.isBuffer(input) ? input : cms.pemDecode(input, "CMS");
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
  L.push("    Content Type: " + (m.contentTypeName || oid.name(m.contentType) || m.contentType) + " (" + m.contentType + ")");
  if (m.contentType === OID_SIGNED_DATA) {
    L.push("    SignedData:");
    L.push("        Version: " + m.version);
    L.push("        Digest Algorithms:");
    (m.digestAlgorithms || []).forEach(function (a) { L.push("            " + _algName(a)); });
    if (m.encapContentInfo) {
      L.push("        Encapsulated Content Info:");
      L.push("            Content Type: " + (oid.name(m.encapContentInfo.eContentType) || m.encapContentInfo.eContentType) + " (" + m.encapContentInfo.eContentType + ")");
      L.push("            " + (m.encapContentInfo.eContent == null ? "<no content (detached)>" : (m.encapContentInfo.eContent.length + " content byte(s)")));
    }
    (m.certificates || []).forEach(function (el) { L.push(_cmsEmbedded("Certificate", el, "        ")); });
    (m.crls || []).forEach(function (el) { L.push(_cmsEmbedded("CRL", el, "        ")); });
    (m.signerInfos || []).forEach(function (si) { L.push(_signerInfo(si, "        ")); });
  } else {
    // Non-SignedData: a stable top-field summary (no plaintext to show); never throws.
    L.push("    " + (m.contentTypeName || "content") + ":");
    if (m.version != null) L.push("        Version: " + m.version);
    (m.recipientInfos || []).forEach(function (ri) { L.push("        RecipientInfo: " + (ri.type || "?") + (ri.ridType ? " (" + ri.ridType + ")" : "")); });
    if (m.encryptedContentInfo) {
      L.push("        Content Type: " + (oid.name(m.encryptedContentInfo.contentType) || m.encryptedContentInfo.contentType));
      if (m.encryptedContentInfo.contentEncryptionAlgorithm) L.push("        Content Encryption Algorithm: " + _algName(m.encryptedContentInfo.contentEncryptionAlgorithm));
    }
    if (m.macAlgorithm) L.push("        MAC Algorithm: " + _algName(m.macAlgorithm));
    if (m.compressionAlgorithm) L.push("        Compression Algorithm: " + _algName(m.compressionAlgorithm));
  }
  return L.join("\n") + "\n";
}

// ---- unified detect-and-dispatch ---------------------------------------------

var _INSPECT_BY_FORMAT = { x509: certificate, crl: crlReport, csr: csrReport, cms: cmsReport };
// Label-agnostic coercion for any(): a PEM block of any label unwraps to its DER, so a
// SignedData armored as "PKCS7" (not "CMS") still detects + routes -- detectFormat already
// ignores the label, so the routed renderer must receive the DER, not the strict-label armor.
var _INSPECT_ENTRY = { pemLabel: null, PemError: InspectError, ErrorClass: InspectError, prefix: "inspect" };

/**
 * @primitive pki.inspect.any
 * @signature pki.inspect.any(input) -> string
 * @since 0.3.8
 * @status experimental
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
  renderedExtensions: Object.keys(EXT_RENDERERS),
};
