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
var asn1 = require("./asn1-der");
var oid = require("./oid");
var x509 = require("./schema-x509");
var pkix = require("./schema-pkix");

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

// Escape ASCII control bytes in any string value pulled from an untrusted
// certificate before it reaches the report. A GeneralName string type (DNS / URI /
// email are IA5String, where 0x0a is a legal byte) or a DN attribute value can
// otherwise carry a newline that injects a forged line into the text report.
function _clean(s) {
  s = String(s);
  var out = "";
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    out += (c < 0x20 || c === 0x7f) ? "\\x" + (c < 16 ? "0" : "") + c.toString(16).toUpperCase() : s.charAt(i);
  }
  return out;
}

// OpenSSL RDN short names; fall back to the registered long name or the OID.
var DN_SHORT = {
  countryName: "C", stateOrProvinceName: "ST", localityName: "L",
  organizationName: "O", organizationalUnitName: "OU", commonName: "CN",
  emailAddress: "emailAddress", domainComponent: "DC", serialNumber: "serialNumber",
  givenName: "GN", surname: "SN", title: "title", pseudonym: "pseudonym",
  businessCategory: "businessCategory", streetAddress: "street", postalCode: "postalCode",
};
function _attr(a) {
  var label = DN_SHORT[a.name] || a.name || a.type;
  return label + "=" + _clean(a.value);
}
function _dnString(name) {
  if (!name || !Array.isArray(name.rdns)) return (name && name.dn) || "";
  return name.rdns.map(function (rdn) {
    return rdn.map(_attr).join(" + ");   // a multi-valued RDN joins with " + "
  }).join(", ");
}

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
var NIST_NAME = { prime256v1: "P-256", secp384r1: "P-384", secp521r1: "P-521" };
function _keyBlock(spki, pad) {
  var algName = _algName(spki.algorithm);
  var out = [pad + "Public Key Algorithm: " + algName];
  var inner = pad + "    ";
  var pub = Buffer.isBuffer(spki.publicKey) ? spki.publicKey : (spki.publicKey && Buffer.isBuffer(spki.publicKey.bytes) ? spki.publicKey.bytes : null);

  if (algName === "ecPublicKey" || algName === "id-ecPublicKey") {
    var curveName = null;
    try { curveName = oid.name(asn1.read.oid(asn1.decode(spki.algorithm.parameters))); } catch (_e) { /* unknown curve */ }
    var bits = CURVE_BITS[curveName] || (pub ? ((pub.length - 1) / 2) * 8 : 0);
    out.push(inner + "Public-Key: (" + bits + " bit)");
    if (pub) { out.push(inner + "pub:"); out.push(_hexColon(pub, { wrap: 16, indent: (pad.length + 8) })); }
    if (curveName) { out.push(inner + "ASN1 OID: " + curveName); if (NIST_NAME[curveName]) out.push(inner + "NIST CURVE: " + NIST_NAME[curveName]); }
    return out.join("\n");
  }
  if (algName === "rsaEncryption") {
    try {
      var rsa = asn1.decode(pub);   // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
      var modBig = asn1.read.integer(rsa.children[0]);
      var expBig = asn1.read.integer(rsa.children[1]);
      var modHex = modBig.toString(16); if (modHex.length % 2) modHex = "0" + modHex;
      var modBuf = Buffer.from(modHex, "hex");
      out.push(inner + "Public-Key: (" + (modBuf.length * 8) + " bit)");
      out.push(inner + "Modulus:");
      out.push(_hexColon(Buffer.concat([Buffer.from([0x00]), modBuf]), { wrap: 16, indent: (pad.length + 8) }));
      out.push(inner + "Exponent: " + expBig.toString(10) + " (0x" + expBig.toString(16) + ")");
      return out.join("\n");
    } catch (_e) { /* fall through to raw */ }
  }
  // EdDSA / ML-DSA / SLH-DSA / anything else: show the raw public-key bytes.
  if (pub) { out.push(inner + "Public-Key: (" + (pub.length * 8) + " bit)"); out.push(inner + "pub:"); out.push(_hexColon(pub, { wrap: 16, indent: (pad.length + 8) })); }
  return out.join("\n");
}

// ---- extensions --------------------------------------------------------------

// OpenSSL-familiar display names for the common extensions; fall back to the
// registered name / OID (the registry names OIDs OpenSSL prints only as bytes).
var EXT_LABEL = {
  basicConstraints: "X509v3 Basic Constraints", keyUsage: "X509v3 Key Usage",
  extKeyUsage: "X509v3 Extended Key Usage", subjectAltName: "X509v3 Subject Alternative Name",
  issuerAltName: "X509v3 Issuer Alternative Name", subjectKeyIdentifier: "X509v3 Subject Key Identifier",
  authorityKeyIdentifier: "X509v3 Authority Key Identifier", certificatePolicies: "X509v3 Certificate Policies",
  cRLDistributionPoints: "X509v3 CRL Distribution Points", nameConstraints: "X509v3 Name Constraints",
  authorityInfoAccess: "Authority Information Access",
};
var KU_LABEL = {
  digitalSignature: "Digital Signature", nonRepudiation: "Non Repudiation", keyEncipherment: "Key Encipherment",
  dataEncipherment: "Data Encipherment", keyAgreement: "Key Agreement", keyCertSign: "Certificate Sign",
  cRLSign: "CRL Sign", encipherOnly: "Encipher Only", decipherOnly: "Decipher Only",
};
var EKU_LABEL = {
  serverAuth: "TLS Web Server Authentication", clientAuth: "TLS Web Client Authentication",
  codeSigning: "Code Signing", emailProtection: "E-mail Protection", timeStamping: "Time Stamping",
  ocspSigning: "OCSP Signing",
};
var GN_KIND = { 1: "email", 2: "DNS", 4: "DirName", 6: "URI", 7: "IP Address", 8: "Registered ID", 0: "othername" };

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
// OpenSSL labels each choice. A directoryName carries a full DN; an iPAddress is a
// Buffer rendered as an address (never raw bytes); an otherName / unknown choice
// falls back to hex so a hostile value can never break the report's line structure.
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
  } catch (_e) { return _hexColon(buf, {}); }
}

function _renderExtValue(ext, decoded, inner) {
  var name = ext.name;
  if (name === "keyUsage") {
    return inner + Object.keys(KU_LABEL).filter(function (k) { return decoded[k]; }).map(function (k) { return KU_LABEL[k]; }).join(", ");
  }
  if (name === "extKeyUsage") {
    return inner + decoded.map(function (o) { var n = null; try { n = oid.name(o); } catch (_e) { /* unregistered EKU OID */ } return EKU_LABEL[n] || n || o; }).join(", ");
  }
  if (name === "basicConstraints") {
    var s = "CA:" + (decoded.cA ? "TRUE" : "FALSE");
    if (decoded.pathLenConstraint != null) s += ", pathlen:" + decoded.pathLenConstraint;
    return inner + s;
  }
  if (name === "subjectAltName" || name === "issuerAltName") {
    return inner + (decoded.names || []).map(_gn).join(", ");
  }
  if (name === "certificatePolicies") {
    return decoded.map(function (p) { return inner + "Policy: " + p.policyIdentifier; }).join("\n");
  }
  if (name === "cRLDistributionPoints" || name === "freshestCRL") {
    var dpLines = [];
    (decoded || []).forEach(function (dp) {
      var d = dp.distributionPoint;
      if (d && d.kind === "fullName" && Array.isArray(d.names)) {
        dpLines.push(inner + "Full Name:");
        d.names.forEach(function (nm) { dpLines.push(inner + "  " + (Buffer.isBuffer(nm) ? _gnRaw(nm) : _gn(nm))); });
      } else {
        dpLines.push(inner + "(distribution point)");
      }
    });
    return dpLines.join("\n");
  }
  if (name === "nameConstraints") {
    var ncLines = [];
    ["permittedSubtrees:Permitted", "excludedSubtrees:Excluded"].forEach(function (pair) {
      var key = pair.split(":")[0], label = pair.split(":")[1], arr = decoded[key];
      if (!Array.isArray(arr) || !arr.length) return;
      ncLines.push(inner + label + ":");
      arr.forEach(function (st) { ncLines.push(inner + "  " + _gn(st.base)); });
    });
    return ncLines.join("\n");
  }
  if (name === "subjectKeyIdentifier") {
    return inner + _hexColon(Buffer.isBuffer(decoded) ? decoded : (decoded.bytes || Buffer.alloc(0)), { upper: true });
  }
  if (name === "authorityKeyIdentifier") {
    var kid = decoded.keyIdentifier;
    return inner + "keyid:" + (Buffer.isBuffer(kid) ? _hexColon(kid, { upper: true }) : "(none)");
  }
  return null;   // no special renderer -> caller does the fallback
}

// Fallback for an extension with no decoder or a decode failure. Best-effort,
// more useful than OpenSSL's raw-octet dump: a directly-printable value shows as a
// string; a DER-wrapped character string is decoded and shown; otherwise a hex
// dump. Never throws.
var _STRING_TAGS = { 12: 1, 19: 1, 22: 1, 20: 1, 26: 1, 27: 1, 30: 1 }; // UTF8/Printable/IA5/Teletex/Visible/General/BMP
function _printable(buf) {
  return buf.length > 0 && buf.every(function (b) { return b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b < 0x7f); });
}
function _fallback(value, inner) {
  if (!Buffer.isBuffer(value) || value.length === 0) return inner + "(empty)";
  if (_printable(value)) return inner + value.toString("utf8").replace(/\r?\n/g, "\n" + inner);
  try {
    var n = asn1.decode(value);
    if (n.tagClass === "universal" && _STRING_TAGS[n.tagNumber]) {
      var s = asn1.read.string(n);
      if (_printable(Buffer.from(s, "utf8"))) return inner + s.replace(/\r?\n/g, "\n" + inner);
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

function _parse(input) {
  if (input && typeof input === "object" && !Buffer.isBuffer(input) && input.tbsBytes) return input;   // already parsed
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
};
