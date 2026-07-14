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

module.exports = {
  certificate: certificate,
  // The extension names certificate() renders to their decoded values (vs the raw
  // hex fallback). The inspect test asserts this covers every extension the shared
  // decoders decode, so a newly-decodable extension cannot silently hex-dump.
  renderedExtensions: Object.keys(EXT_RENDERERS),
};
