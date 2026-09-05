// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.inspect
 * @nav        Tooling
 * @title      Inspect
 * @fullname   Inspect: render any PKI structure as readable text
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

var NAMES = constants.NAMES;

var InspectError = frameworkError.InspectError;
function _err(code, message, cause) { return new InspectError(code, message, cause); }

var NS = pkix.makeNS("inspect", InspectError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;
var OID_UNOTICE = oid.byName("unotice");


var HEX = "0123456789abcdef";
function _hexColon(buf, opts) {
  opts = opts || {};
  var hex = [];
  for (var i = 0; i < buf.length; i++) {
    var b = buf[i], s = HEX[(b >> 4) & 0xf] + HEX[b & 0xf];
    hex.push(opts.upper ? s.toUpperCase() : s);
  }
  if (!opts.wrap) return hex.join(":");
  var pad = " ".repeat(opts.indent || 0), lines = [];
  for (var j = 0; j < hex.length; j += opts.wrap) {
    var chunk = hex.slice(j, j + opts.wrap).join(":");
    lines.push(pad + chunk + (j + opts.wrap < hex.length ? ":" : ""));
  }
  return lines.join("\n");
}


// @guard-via guard\.name\.escape
var _clean = guard.name.escapeControlBytes;

function _dnString(name) { return (name && name.dn) || ""; }

var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function _two(n) { return (n < 10 ? "0" : "") + n; }
function _date(iso) {
  var held = guard.time.isDate(iso) ? guard.time.instantOf(iso) : Date.parse(String(iso));
  if (isNaN(held)) return String(iso);
  var d = new Date(held);
  var day = d.getUTCDate(), dd = (day < 10 ? " " : "") + day;
  return MONTHS[d.getUTCMonth()] + " " + dd + " " +
    _two(d.getUTCHours()) + ":" + _two(d.getUTCMinutes()) + ":" + _two(d.getUTCSeconds()) +
    " " + d.getUTCFullYear() + " GMT";
}

function _algName(a) { return (a && (a.name || a.oid)) || "unknown"; }


function _serial(cert, indent) {
  var hex = cert.serialNumberHex || "";
  if (hex.length % 2) hex = "0" + hex;
  var buf = Buffer.from(hex, "hex");
  if (buf.length > 1 && buf[0] === 0x00 && (buf[1] & 0x80)) buf = buf.subarray(1);
  if (buf.length <= 6) {
    var n = parseInt(buf.toString("hex") || "0", 16);
    return "Serial Number: " + n + " (0x" + (_stripLeadingZeros(buf.toString("hex")) || "0") + ")";
  }
  return "Serial Number:\n" + " ".repeat(indent) + _hexColon(buf, {});
}

var CURVE_BITS = Object.assign(Object.create(null), { "P-256": 256, "P-384": 384, "P-521": 521, "prime256v1": 256, "secp384r1": 384, "secp521r1": 521 });
var NIST_NAME = NAMES.NIST_CURVE;
var RSA_KEY_ALGS = Object.assign(Object.create(null), { rsaEncryption: 1, rsassaPss: 1, rsaesOaep: 1 });
function _keyBlock(spki, pad) {
  var algName = _algName(spki.algorithm);
  var out = [pad + "Public Key Algorithm: " + algName];
  var inner = pad + "    ";
  var pub = Buffer.isBuffer(spki.publicKey) ? spki.publicKey : (spki.publicKey && Buffer.isBuffer(spki.publicKey.bytes) ? spki.publicKey.bytes : null);

  if (algName === "ecPublicKey" || algName === "id-ecPublicKey") {
    var curveName = null;
    try { curveName = oid.name(asn1.read.oid(asn1.decode(spki.algorithm.parameters))); }
    catch (_e) { }
    var bits = CURVE_BITS[curveName] || (pub ? ((pub.length - 1) / 2) * 8 : 0);
    out.push(inner + "Public-Key: (" + bits + " bit)");
    if (pub) { out.push(inner + "pub:"); out.push(_hexColon(pub, { wrap: 16, indent: (pad.length + 8) })); }
    if (curveName) { out.push(inner + "ASN1 OID: " + curveName); if (NIST_NAME[curveName]) out.push(inner + "NIST CURVE: " + NIST_NAME[curveName]); }
    return out.join("\n");
  }
  if (RSA_KEY_ALGS[algName]) {
    try {
      var rsa = asn1.decode(pub);
      var modBig = asn1.read.integer(rsa.children[0]);
      var expBig = asn1.read.integer(rsa.children[1]);
      var modHex = modBig.toString(16); if (modHex.length % 2) modHex = "0" + modHex;
      var modBuf = Buffer.from(modHex, "hex");
      out.push(inner + "Public-Key: (" + modBig.toString(2).length + " bit)");
      out.push(inner + "Modulus:");
      var modDisplay = (modBuf.length && (modBuf[0] & 0x80)) ? Buffer.concat([Buffer.from([0x00]), modBuf]) : modBuf;
      out.push(_hexColon(modDisplay, { wrap: 16, indent: (pad.length + 8) }));
      out.push(inner + "Exponent: " + expBig.toString(10) + " (0x" + expBig.toString(16) + ")");
      return out.join("\n");
    } catch (_e) { }
  }
  if (pub) { out.push(inner + "Public-Key: (" + (pub.length * 8) + " bit)"); out.push(inner + "pub:"); out.push(_hexColon(pub, { wrap: 16, indent: (pad.length + 8) })); }
  return out.join("\n");
}


var EXT_LABEL = NAMES.EXTENSION;
var KU_LABEL = NAMES.KEY_USAGE;
var EKU_LABEL = NAMES.EXT_KEY_USAGE;
var GN_KIND = NAMES.GENERAL_NAME;

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

function _gnDn(value) {
  return (value && Array.isArray(value.rdns)) ? _dnString(value) : ((value && value.dn) || "");
}
function _gn(g) {
  if (!g || typeof g !== "object") return "";
  var t = g.tagNumber;
  if (t === 7 && Buffer.isBuffer(g.value)) return "IP Address:" + _ipString(g.value);
  if (t === 4) return "DirName:" + _gnDn(g.value);
  if (t === 0) return "othername:" + (Buffer.isBuffer(g.bytes) ? _hexColon(g.bytes, {}) : "<unsupported>");
  var kind = GN_KIND[t] || ("tag" + t);
  var v = (typeof g.value === "string") ? _clean(g.value)
    : Buffer.isBuffer(g.value) ? _hexColon(g.value, {})
      : Buffer.isBuffer(g.bytes) ? _hexColon(g.bytes, {}) : "";
  return kind + ":" + v;
}

function _gnRaw(buf) {
  if (!Buffer.isBuffer(buf)) return "";
  try {
    var node = asn1.decode(buf);
    var t = node.tagNumber;
    if (t === 1 || t === 2 || t === 6) return GN_KIND[t] + ":" + _clean(node.content.toString("latin1"));
    if (t === 7) return "IP Address:" + _ipString(node.content);
    return _hexColon(buf, {});
    // allow:swallow-unverified drop-silent display fallback (tier-3): fullName GNs reach here as
  } catch (_e) { return _hexColon(buf, {}); }
}


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
    if (dp.reasons && Buffer.isBuffer(dp.reasons.bytes)) {
      var rf = [], rb = dp.reasons.bytes;
      for (var bit = 1; bit < rb.length * 8; bit++) {
        if ((rb[bit >> 3] & (0x80 >> (bit & 7))) && NAMES.REASON_FLAGS[bit]) rf.push(NAMES.REASON_FLAGS[bit]);
      }
      if (rf.length) { dpLines.push(inner + "Reasons: " + rf.join(", ")); wrote = true; }
    }
    if (dp.cRLIssuer && Array.isArray(dp.cRLIssuer.names)) {
      dpLines.push(inner + "CRL Issuer:");
      dp.cRLIssuer.names.forEach(function (g) { dpLines.push(inner + "  " + _gn(g)); });
      wrote = true;
    }
    if (!wrote) dpLines.push(inner + "(distribution point)");
  });
  return dpLines.join("\n");
}


var EXT_RENDERERS = Object.assign(Object.create(null), {
  keyUsage: function (decoded, inner) {
    return inner + Object.keys(KU_LABEL).filter(function (k) { return decoded[k]; }).map(function (k) { return KU_LABEL[k]; }).join(", ");
  },
  extKeyUsage: function (decoded, inner) {
    return inner + decoded.map(function (o) {
      var n = null;
      try { n = oid.name(o); }
      catch (_e) { }
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
      if (!info) return label;
      if (info.opaque) return label + " (opaque)";
      if (typeof info.amount !== "undefined") return label + ": " + info.amount + " " + info.currency + (info.exponent ? " x10^" + info.exponent : "");
      if (typeof info.years !== "undefined") return label + ": " + info.years + " years";
      if (info.typeNames) return label + ": " + info.typeNames.map(function (n, i) { return n || info.types[i]; }).join(", ");
      if (info.methodNames) return label + ": " + info.methodNames.map(function (n, i) { return n || info.methods[i]; }).join(", ");
      if (info.locations) return label + ": " + info.locations.map(function (l) { return l.url + " (" + l.language + ")"; }).join(", ");
      if (info.countries) return label + ": " + info.countries.join(", ");
      if (typeof info.semanticsIdentifier !== "undefined") {
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
      try {
        (asn1.decode(p.qualifiersBytes).children || []).forEach(function (pqi) {
          var qid = asn1.read.oid(pqi.children[0]), q = pqi.children[1];
          var label = null;
          try { label = oid.name(qid); }
          catch (_e) { }
          if (qid === OID_UNOTICE) {
            var texts = pkix.userNoticeTexts(q);
            if (texts.length && texts.every(function (t) {
              return t.text !== null && (t.field !== "organization" || t.noticeNumbers !== null);
            })) {
              texts.forEach(function (t) {
                var nums = (t.noticeNumbers && t.noticeNumbers.length) ? " #" + t.noticeNumbers.join(", ") : "";
                lines.push(inner + "  " + (label || qid) + " " + t.field + ": " + _clean(t.text) + nums);
              });
              return;
            }
          }
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
  authorityInfoAccess: function (decoded, inner) {
    var LABEL = { caIssuers: "CA Issuers", ocsp: "OCSP" };
    return (decoded || []).map(function (ad) {
      var m = null;
      try { m = oid.name(ad.accessMethod); } catch (_e) { /* allow:swallow-unverified display best-effort: an unregistered accessMethod OID falls back to the raw dotted OID below (inspection is best-effort, never a verdict) */ }
      var loc = ad.accessLocation || {}, lv;
      if (loc.tag === 6) lv = "URI:" + loc.value;
      else if (loc.tag === 2) lv = "DNS:" + loc.value;
      else if (loc.tag === 1) lv = "email:" + loc.value;
      else if (loc.tag === 7) lv = "IP:" + _ipString(loc.value);
      else if (loc.tag === 4) lv = "DirName:" + _gnDn(loc.value);
      else lv = typeof loc.value === "string" ? loc.value : "[" + loc.tag + "]";
      return inner + (LABEL[m] || m || ad.accessMethod) + " - " + lv;
    }).join("\n");
  },
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
});
EXT_RENDERERS.msApplicationPolicies = EXT_RENDERERS.certificatePolicies;


function _renderExtValue(ext, decoded, inner) {
  var fn = EXT_RENDERERS[ext.name];
  return fn ? fn(decoded, inner) : null;
}

var _STRING_TAGS = Object.assign(Object.create(null), { 12: 1, 19: 1, 22: 1, 20: 1, 26: 1, 27: 1, 30: 1 });
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
  } catch (_e) { }
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
    } catch (_e) { }
  }
  return header + "\n" + _fallback(ext.value, inner);
}


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
    return input;
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
  if ((c.extensions || []).length) {
    L.push("        X509v3 extensions:");
    c.extensions.forEach(function (ext) { L.push(_extension(ext, "            ")); });
  }
  L.push("    Signature Algorithm: " + _algName(c.signatureAlgorithm));
  var sig = c.signatureValue && (c.signatureValue.bytes || c.signatureValue);
  if (Buffer.isBuffer(sig)) { L.push("    Signature Value:"); L.push(_hexColon(sig, { wrap: 16, indent: 8 })); }
  return L.join("\n") + "\n";
}


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
  var shape = _CMS_SHAPE[o.contentType];
  return shape ? shape(o) : false;
}
var _INSPECT_ENTRY = { pemLabel: null, PemError: InspectError, ErrorClass: InspectError, prefix: "inspect" };
function _coerce(input, spec) {
  if (input && typeof input === "object" && !Buffer.isBuffer(input) && !(input instanceof Uint8Array) && input[spec.marker] !== undefined) {
    if (!spec.looksParsed(input)) throw _err("inspect/bad-input", "input has a " + spec.marker + " property but is not a complete " + spec.parsedName + " result");
    return input;
  }
  var der;
  try { der = pkix.coerceToDer(input, _INSPECT_ENTRY); }
  catch (e) { throw _err("inspect/bad-input", "input must be a parsed " + spec.what + ", a DER Buffer, or a PEM block", e); }
  try { return spec.parse(der); }
  catch (e) { throw _err(spec.badCode, "input is not a well-formed " + spec.what, e); }
}
function _parseCrl(input) { return _coerce(input, { marker: "thisUpdate", looksParsed: _looksParsedCrl, parsedName: "pki.schema.crl.parse", parse: crl.parse, badCode: "inspect/bad-crl", what: "X.509 CRL" }); }
function _parseCsr(input) { return _coerce(input, { marker: "certificationRequestInfoBytes", looksParsed: _looksParsedCsr, parsedName: "pki.schema.csr.parse", parse: csr.parse, badCode: "inspect/bad-csr", what: "PKCS#10 certification request" }); }
function _parseCms(input) { return _coerce(input, { marker: "contentType", looksParsed: _looksParsedCms, parsedName: "pki.schema.cms.parse", parse: cms.parse, badCode: "inspect/bad-cms", what: "CMS message" }); }


var OID_EXTENSION_REQUEST = oid.byName("extensionRequest");
var OID_CONTENT_TYPE = oid.byName("contentType");
var OID_MESSAGE_DIGEST = oid.byName("messageDigest");
var OID_SIGNING_TIME = oid.byName("signingTime");

function _attrValue(typeOid, rawDer, inner) {
  try {
    if (typeOid === OID_CONTENT_TYPE) { var ct = asn1.read.oid(asn1.decode(rawDer)); return inner + (oid.name(ct) || ct); }
    if (typeOid === OID_MESSAGE_DIGEST) return _hexColon(asn1.read.octetString(asn1.decode(rawDer)), { wrap: 16, indent: inner.length });
    if (typeOid === OID_SIGNING_TIME) return inner + _date(asn1.read.time(asn1.decode(rawDer)));
  } catch (_e) { }
  return _fallback(rawDer, inner);
}


var OID_CRL_NUMBER = oid.byName("cRLNumber");
var OID_REASON_CODE = oid.byName("reasonCode");
var OID_INVALIDITY_DATE = oid.byName("invalidityDate");
var OID_DELTA_CRL_INDICATOR = oid.byName("deltaCRLIndicator");
function _crlExtension(ext, pad) {
  var label = EXT_LABEL[ext.name] || ext.name || ext.oid;
  var header = pad + label + ":" + (ext.critical ? " critical" : "");
  var inner = pad + "    ";
  if (ext.oid === OID_CRL_NUMBER && typeof ext.value === "bigint") return header + "\n" + inner + String(ext.value);
  if (ext.oid === OID_REASON_CODE && typeof ext.value === "number") return header + "\n" + inner + (NAMES.CRL_REASON[ext.value] || String(ext.value));
  if (ext.oid === OID_INVALIDITY_DATE && guard.time.isDate(ext.value)) return header + "\n" + inner + _date(ext.value);
  if (ext.oid === OID_DELTA_CRL_INDICATOR && Buffer.isBuffer(ext.value)) {
    try { return header + "\n" + inner + "BaseCRLNumber: " + String(asn1.read.integer(asn1.decode(ext.value))); }
    catch (_e) { }
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


function _attribute(attr, pad) {
  var inner = pad + "    ";
  if (attr.type === OID_EXTENSION_REQUEST && Array.isArray(attr.extensions)) {
    var lines = [pad + "Requested Extensions:"];
    attr.extensions.forEach(function (ext) { lines.push(_extension(ext, inner)); });
    return lines.join("\n");
  }
  var header = pad + (attr.name || oid.name(attr.type) || attr.type) + ":";
  var vals = (attr.values || []).map(function (v) { return _attrValue(attr.type, v, inner); });
  return vals.length ? header + "\n" + vals.join("\n") : header;
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


var OID_SIGNED_DATA = oid.byName("signedData");
function _isObj(x) { return !!x && typeof x === "object"; }
var _CMS_SHAPE = Object.create(null);
_CMS_SHAPE[OID_SIGNED_DATA] = function (o) { return Array.isArray(o.digestAlgorithms) && _isObj(o.encapContentInfo) && Array.isArray(o.signerInfos); };
_CMS_SHAPE[oid.byName("envelopedData")] = function (o) { return Array.isArray(o.recipientInfos) && _isObj(o.encryptedContentInfo); };
_CMS_SHAPE[oid.byName("encryptedData")] = function (o) { return _isObj(o.encryptedContentInfo); };
_CMS_SHAPE[oid.byName("authData")] = function (o) { return Array.isArray(o.recipientInfos) && _isObj(o.macAlgorithm) && _isObj(o.encapContentInfo) && Buffer.isBuffer(o.mac); };
_CMS_SHAPE[oid.byName("authEnvelopedData")] = function (o) { return Array.isArray(o.recipientInfos) && _isObj(o.encryptedContentInfo) && Buffer.isBuffer(o.mac); };
_CMS_SHAPE[oid.byName("compressedData")] = function (o) { return _isObj(o.compressionAlgorithm) && _isObj(o.encapContentInfo); };


function _stripLeadingZeros(s) {
  var i = 0;
  while (i < s.length && s.charAt(i) === "0") i += 1;
  return s.slice(i);
}
function _stripTrailingNewline(s) {
  return (s.length > 0 && s.charAt(s.length - 1) === "\n") ? s.slice(0, s.length - 1) : s;
}

function _cmsEmbedded(kind, el, pad) {
  if (el.tagClass === "universal") {
    try {
      var sub = (kind === "CRL") ? crlReport(el.bytes) : certificate(el.bytes);
      return pad + kind + ":\n" + _stripTrailingNewline(sub).split("\n").map(function (l) { return pad + "    " + l; }).join("\n");
    } catch (_e) { }
  }
  return pad + kind + " [" + el.tagClass + " " + el.tagNumber + "] (" + el.bytes.length + " bytes)";
}

function _signerInfoAttrs(title, attrs, pad) {
  var lines = [pad + title + ":"];
  var inner = pad + "    ";
  attrs.forEach(function (a) {
    var vals = (a.values || []).map(function (v) { return _attrValue(a.type, v, inner + "    "); });
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
function _cmsOuterSummary(input) {
  var ct = null;
  try {
    var der = pkix.coerceToDer(input, _INSPECT_ENTRY);
    ct = asn1.read.oid(asn1.decode(der).children[0]);
  } catch (_e) { }
  return "CMS ContentInfo:\n    Content Type: " + (ct ? (oid.name(ct) || ct) + " (" + ct + ")" : "unknown") +
    "\n    (content type not further parsed; outer ContentInfo only)\n";
}

function cmsReport(input) {
  var m;
  try { m = _parseCms(input); }
  catch (e) {
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


var _INSPECT_BY_FORMAT = Object.assign(Object.create(null), { x509: certificate, crl: crlReport, csr: csrReport, cms: cmsReport });

/**
 * @primitive pki.inspect.any
 * @signature pki.inspect.any(input) -> string
 * @since 0.3.8
 * @status stable
 * @spec RFC 5280
 * @related pki.schema.detectFormat, pki.inspect.certificate
 *
 * Detect which PKI format `input` (a PEM string or DER Buffer) encodes and render
 * it with the matching report, the inspect analogue of `pki.schema.parse`. Routes
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
  var der, fmt;
  try {
    der = pkix.coerceToDer(input, _INSPECT_ENTRY);
    fmt = schemaAll.detectFormat(der);
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
  renderedExtensions: Object.keys(EXT_RENDERERS),
};
