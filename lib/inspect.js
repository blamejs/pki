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
var pkcs8 = require("./schema-pkcs8");
var pkcs12 = require("./schema-pkcs12");
var crmf = require("./schema-crmf");
var cmp = require("./schema-cmp");
var csrattrs = require("./schema-csrattrs");
var trustanchor = require("./schema-trustanchor");
var ocsp = require("./schema-ocsp");
var tsp = require("./schema-tsp");
var attrcert = require("./schema-attrcert");
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
  /** @internal Only a hex string is read as one. A caller's pre-parsed object can carry anything here, and
   *  the byte reader below faults on a value that is not a string rather than reporting an unreadable one. */
  var hex = typeof cert.serialNumberHex === "string" && _isHexDigits(cert.serialNumberHex)
    ? cert.serialNumberHex : "";
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


var TLS_FEATURE_NAMES = NAMES.TLS_FEATURE;
var AFI_NAMES = NAMES.ADDRESS_FAMILY;
var ipUtils = require("./ip-utils");
/** @internal An RFC 3779 IPAddress is a BIT STRING carrying only the leading bits of the address.
 *  What the bits it does not carry stand for depends on where the address sits: RFC 3779 sec. 2.1.2
 *  makes them zero in a range's `min` and ONE in its `max`, so a max written out zero-filled names
 *  a different address from the one the range ends at. `fillOnes` selects the rule, and it applies
 *  to the unused bits inside the last present octet as well as to the octets left off entirely. */
var AFI_OCTETS = Object.assign(Object.create(null), { 1: 4, 2: 16 });
function _ipAddressText(afi, addr, fillOnes) {
  var width = AFI_OCTETS[afi];
  if (!width || addr.bytes.length > width) return addr.bytes.toString("hex");
  var padded = Buffer.alloc(width, fillOnes ? 0xff : 0x00);
  addr.bytes.copy(padded, 0, 0, addr.bytes.length);
  if (addr.unusedBits > 0 && addr.bytes.length > 0) {
    var last = addr.bytes.length - 1;
    var keep = (0xff << addr.unusedBits) & 0xff;
    padded[last] = fillOnes ? (padded[last] | (~keep & 0xff)) : (padded[last] & keep);
  }
  return ipUtils.textFromOctets(padded) || padded.toString("hex");
}
/** @internal A prefix names a block, so it is written as its address and its length in bits. A
 *  range endpoint names one address and carries no length. */
function _ipPrefix(afi, addr) { return _ipAddressText(afi, addr, false) + "/" + addr.prefixLength; }

var EXT_LABEL = NAMES.EXTENSION;
var KU_LABEL = NAMES.KEY_USAGE;
var EKU_LABEL = NAMES.EXT_KEY_USAGE;
var GN_KIND = NAMES.GENERAL_NAME;

/** @internal A 4- or 16-octet buffer is ONE address, rendered by the shared home so that one address
 *  reads the same wherever a report carries it: the RFC 3779 blocks reach that home through
 *  `_ipAddressText`, and a GeneralName reaching it through a second renderer would print the same
 *  octets two ways in one report. An 8- or 32-octet buffer is a name constraint's address AND mask,
 *  which is not an address, so each half is rendered and the two are joined. The home is not widened
 *  to take those widths, because a mask reaching it as an address would render as one everywhere. */
function _ipString(buf) {
  if (!Buffer.isBuffer(buf)) return "";
  if (buf.length === 4 || buf.length === 16) return ipUtils.textFromOctets(buf) || _hexColon(buf, {});
  if (buf.length === 8) return _ipString(buf.subarray(0, 4)) + "/" + _ipString(buf.subarray(4));
  if (buf.length === 32) return _ipString(buf.subarray(0, 16)) + "/" + _ipString(buf.subarray(16));
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
    var LABEL = Object.assign(Object.create(null), {
      caIssuers: "CA Issuers", ocsp: "OCSP",
      "id-ad-caRepository": "CA Repository", "id-ad-timeStamping": "Time Stamping",
    });
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
  /** @internal RFC 5280 sec. 4.2.2.2 gives subjectInfoAccess sec. 4.2.2.1's AccessDescription
   *  syntax, so it renders through the same rows; only the access methods it names differ. */
  subjectInfoAccess: function (decoded, inner) {
    return EXT_RENDERERS.authorityInfoAccess(decoded, inner);
  },
  /** @internal Each Attribute value is raw DER, so it renders through the same best-effort value
   *  fallback every other opaque value uses rather than a second reading of the same bytes. */
  subjectDirectoryAttributes: function (decoded, inner) {
    return (decoded || []).map(function (a) {
      var lines = (a.values || []).map(function (v) { return _fallback(v, inner + "    "); });
      return inner + (a.name || a.type) + ":" + (lines.length ? "\n" + lines.join("\n") : "");
    }).join("\n");
  },
  ocspNoCheck: function (decoded, inner) {
    return inner + "OCSP No Check (this is an OCSP responder certificate; do not check its revocation)";
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
  /** @internal RFC 7633 sec. 6 carries TLS ExtensionType values, so each is named from the registry
   *  where the toolkit knows it and printed as its number where it does not. */
  tlsFeature: function (decoded, inner) {
    return (decoded.features || []).map(function (f) {
      var text = String(f);
      var name = TLS_FEATURE_NAMES[text];
      return inner + (name ? name + " (" + text + ")" : text);
    }).join("\n") || inner + "(none)";
  },
  ipAddrBlocks: function (decoded, inner) {
    return (decoded.families || []).map(function (f) {
      var head = inner + (AFI_NAMES[f.afi] || "AFI " + f.afi) + (f.safi === null ? "" : " SAFI " + f.safi) + ":";
      if (f.inherit) return head + " inherit";
      var rows = (f.addressesOrRanges || []).map(function (r) {
        if (r.kind === "addressPrefix") return inner + "    " + _ipPrefix(f.afi, r.addressPrefix);
        return inner + "    " + _ipAddressText(f.afi, r.min, false) + " to " + _ipAddressText(f.afi, r.max, true);
      });
      return head + (rows.length ? "\n" + rows.join("\n") : " (none)");
    }).join("\n") || inner + "(none)";
  },
  autonomousSysIds: function (decoded, inner) {
    var lines = [];
    [["asnum", decoded.asnum], ["rdi", decoded.rdi]].forEach(function (pair) {
      if (pair[1] === null) return;
      if (pair[1].inherit) { lines.push(inner + pair[0] + ": inherit"); return; }
      lines.push(inner + pair[0] + ":");
      (pair[1].asIdsOrRanges || []).forEach(function (r) {
        lines.push(inner + "    " + (r.kind === "id" ? String(r.id) : String(r.min) + " to " + String(r.max)));
      });
    });
    return lines.length ? lines.join("\n") : inner + "(none)";
  },
});
EXT_RENDERERS.msApplicationPolicies = EXT_RENDERERS.certificatePolicies;
EXT_RENDERERS.ipAddrBlocksV2 = EXT_RENDERERS.ipAddrBlocks;
EXT_RENDERERS.autonomousSysIdsV2 = EXT_RENDERERS.autonomousSysIds;


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
  /** @internal An extension whose own parser decoded it, which is how the attribute-certificate and
   *  revocation-list tables reach here: the certificate decoders above do not know those OIDs, and without
   *  this the decoded value fell through to a hex dump of the bytes it was decoded from. */
  if (ext.decoded && typeof ext.decoded === "object" && ext.decoded.opaque !== true) {
    var fromParser = _decodedRecord(ext.decoded, inner);
    if (fromParser) return header + "\n" + fromParser;
  }
  var enriched = _extraFields(ext, _ROW_PLUMBING, inner);
  if (enriched) return header + "\n" + enriched;
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
var _INSPECT_ENTRY = Object.assign(Object.create(null), { pemLabel: null, PemError: InspectError, ErrorClass: InspectError, prefix: "inspect" });
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
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: key });
 *   var crlDer = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"),
 *     nextUpdate: new Date("2026-02-01T00:00:00Z"), crlNumber: 1n, revoked: [] },
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


/** @internal Whether a value is one of the four shapes the name renderer reads: a parsed Name, a
 *  GeneralNames list, a decoded GeneralName, or a raw one still carrying its context tag. Anything else is a
 *  record and is rendered as its fields. */
function _looksLikeName(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  if (v.dn !== undefined || Array.isArray(v.rdns) || Array.isArray(v.names)) return true;
  return typeof v.tagNumber === "number" && (v.value !== undefined || Buffer.isBuffer(v.bytes));
}

/** @internal A decoded record as label/value lines. Each field is rendered by the vocabulary that already
 *  exists for its kind, because the alternative is string conversion, which prints a decoded value as its
 *  object notation. Depth is bounded so a record carrying a parsed structure cannot walk the whole of it. */
function _decodedRecord(rec, pad, depth) {
  if (depth === undefined) depth = 3;
  var lines = [];
  Object.keys(rec).forEach(function (k) {
    var v = rec[k];
    if (v === null || v === undefined || k === "opaque") return;
    if (Buffer.isBuffer(v)) { lines.push(pad + k + ": " + _hexColon(v, {})); return; }
    if (v instanceof Date) { lines.push(pad + k + ": " + _date(v)); return; }
    if (typeof v !== "object") { lines.push(pad + k + ": " + _clean(String(v))); return; }
    /** @internal Only a value that LOOKS like a name is rendered as one. Asked of every record, the name
     *  renderer answers a non-name with the truthy `tag<undefined>:`, and that answer then stood in for the
     *  record's own fields: a group attribute rendered as that string instead of its memberships. */
    if (_looksLikeName(v)) {
      var asName = _nameOrGn(v);
      if (asName && asName !== "(none)" && asName !== "(empty)" && asName !== "(unrecognized name form)") {
        lines.push(pad + k + ": " + asName);
        return;
      }
    }
    if (depth <= 0) return;
    if (Array.isArray(v)) {
      if (!v.length) return;
      lines.push(pad + k + ":");
      v.forEach(function (m) {
        if (m === null || typeof m !== "object" || Buffer.isBuffer(m)) {
          lines.push(pad + "    " + (Buffer.isBuffer(m) ? _hexColon(m, {}) : _clean(String(m))));
        } else {
          var sub = _decodedRecord(m, pad + "    ", depth - 1);
          if (sub) lines.push(sub);
        }
      });
      return;
    }
    var nested = _decodedRecord(v, pad + "    ", depth - 1);
    if (nested) { lines.push(pad + k + ":"); lines.push(nested); }
  });
  return lines.join("\n");
}

/** @internal The fields a parser ENRICHED a row with, which are whatever it carries beyond the plumbing every
 *  row has. A table that decodes its own values attaches them here rather than under `decoded`, and routing
 *  such a row through a renderer that knows only the plumbing printed the bytes the parser had already read:
 *  an EST key-size constraint as its DER, an OCSP archive cutoff as a GeneralizedTime's octets. */
function _extraFields(row, skip, pad) {
  var extra = Object.create(null), any = false;
  Object.keys(row).forEach(function (k) {
    if (skip.indexOf(k) !== -1) return;
    var v = row[k];
    if (v === null || v === undefined || v === false) return;
    extra[k] = v;
    any = true;
  });
  return any ? _decodedRecord(extra, pad) : "";
}
var _ROW_PLUMBING = ["oid", "name", "critical", "value", "valueBytes", "bytes", "scope", "index",
  "containerIndex", "state", "code", "decoded", "kind", "values", "type", "extensions"];

function _attribute(attr, pad) {
  var inner = pad + "    ";
  if (attr.type === OID_EXTENSION_REQUEST && Array.isArray(attr.extensions)) {
    var lines = [pad + "Requested Extensions:"];
    attr.extensions.forEach(function (ext) { lines.push(_extension(ext, inner)); });
    return lines.join("\n");
  }
  /** @internal The registry lookup takes a dotted identifier, and a caller's object can carry anything in
   *  `type`: asked about a number it refuses with its own code, which is not this verb's contract. */
  var registryName = null;
  if (!attr.name && typeof attr.type === "string") {
    try { registryName = oid.name(attr.type); }
    // allow:swallow-unverified drop-silent display fallback: an unreadable type prints as itself
    catch (_notAnIdentifier) { registryName = null; }
  }
  var header = pad + (attr.name || registryName || String(attr.type)) + ":";
  /** @internal Where the parser DECODED the value, render that rather than the bytes it decoded from: an
   *  attribute certificate's whole content is the attributes it asserts, and a role naming a URI printed as
   *  a hex run said nothing a reader could act on. An entry the decoder left opaque still prints as bytes. */
  var vals;
  if (Array.isArray(attr.decoded) && attr.decoded.length === _list(attr.values).length) {
    vals = attr.decoded.map(function (d, i) {
      if (!d || typeof d !== "object" || d.opaque === true) return _attrValue(attr.type, attr.values[i], inner);
      return _decodedRecord(d, inner) || _attrValue(attr.type, attr.values[i], inner);
    });
  } else {
    vals = _list(attr.values).map(function (v) { return _attrValue(attr.type, v, inner); });
  }
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


/** @internal The remaining detected formats, each composing the vocabulary above and each a named verb as
 *  well as a route from `any`.
 *
 *  NO REPORT PRINTS PRIVATE KEY MATERIAL. A PKCS#8 and a PKCS#12 both carry a private key, and a renderer
 *  that wrote one out would make an inspection tool a way of reading a key out of a file somebody opened
 *  only to look at it. Each shows the algorithm, the public half where the structure carries one, and that
 *  a private key is present, never its bytes. `inspect-formats.test.js` searches each report for byte runs
 *  of the key in hex, base64 and colon-hex, so the rule is measured rather than stated here. */

/** @internal Each predicate asks whether the object has the STRUCTURE its parser returns, not whether it
 *  carries the marker property, because an object that merely has the marker is a caller's own object and
 *  a report rendered from one says what the caller wrote rather than what any bytes encode. The marker
 *  selects the predicate; the predicate is what admits the object. */
function _looksParsedPkcs8(o) {
  return typeof o.version === "number" && o.privateKeyAlgorithm && typeof o.privateKeyAlgorithm === "object" &&
    Buffer.isBuffer(o.privateKey) && Array.isArray(o.attributes);
}
function _looksParsedPkcs12(o) {
  return typeof o.version === "number" && typeof o.integrityMode === "string" &&
    Array.isArray(o.safeBags) && Array.isArray(o.encryptedSafes);
}
/** @internal Every message has to carry the structure the renderer reads. Checking only that `messages` is
 *  an array admitted `{ messages: [{}] }`, and the renderer then dereferenced a certTemplate that was not
 *  there, so a caller's own object left an untyped TypeError where this door promises inspect/bad-input. */
function _looksParsedCrmf(o) {
  if (!Array.isArray(o.messages) || !o.messages.length) return false;
  return o.messages.every(function (m) {
    return !!m && typeof m === "object" && !!m.certReq && typeof m.certReq === "object" &&
      !!m.certReq.certTemplate && typeof m.certReq.certTemplate === "object";
  });
}
function _looksParsedCmp(o) {
  return o.header && typeof o.header === "object" && o.body && typeof o.body === "object" &&
    typeof o.body.arm === "string";
}
/** @internal Every item has to be one of the two shapes the parser produces, a bare object identifier or an
 *  attribute carrying a values array, because the report reads both: an array of nullish or wrong-typed
 *  members faulted the renderer where this door promises a typed refusal. */
function _looksParsedCsrattrs(o) {
  if (!Array.isArray(o.items)) return false;
  return o.items.every(function (it) {
    if (!it || typeof it !== "object") return false;
    if (it.kind === "oid") return true;
    return it.kind === "attribute" && (it.values === undefined || it.values === null || Array.isArray(it.values));
  });
}
/** @internal Each anchor has to carry the member its own kind names, because that is what the report reads:
 *  an anchor with a kind and nothing under it faulted the renderer where this door promises a typed
 *  refusal. */
function _looksParsedTrustAnchor(o) {
  if (!Array.isArray(o.anchors) || !o.anchors.length) return false;
  return o.anchors.every(function (a) {
    if (!a || typeof a !== "object" || typeof a.kind !== "string") return false;
    var held = a.kind === "certificate" ? a.certificate : (a.kind === "tbsCert" ? a.tbsCert : a.taInfo);
    return !!held && typeof held === "object";
  });
}
function _looksParsedOcspReq(o) {
  if (typeof o.version !== "number" || !Array.isArray(o.requestList) || !Buffer.isBuffer(o.tbsRequestBytes)) return false;
  return o.requestList.every(function (r) { return !!r && typeof r === "object" && !!r.certID && typeof r.certID === "object"; });
}
function _looksParsedOcspResp(o) {
  var st = o.responseStatus;
  if (!st || typeof st !== "object" || typeof st.code !== "number" || typeof st.name !== "string") return false;
  var br = o.basicResponse;
  /** @internal A response with no basic response is a status-only answer the report handles, but one that
   *  HAS a basic response has to carry the answers the report walks: a responderID and a responses list whose
   *  entries name a CertID and a status. */
  if (br === null || br === undefined) return true;
  if (typeof br !== "object" || !br.responderID || typeof br.responderID !== "object") return false;
  if (!Array.isArray(br.responses)) return false;
  return br.responses.every(function (r) {
    return !!r && typeof r === "object" && !!r.certID && typeof r.certID === "object" &&
      !!r.certStatus && typeof r.certStatus === "object";
  });
}
/** @internal A rejected or waiting response carries `timeStampToken: null`, which is the shape RFC 3161
 *  sec. 2.4.2 gives a non-granted status, so the token is required to be PRESENT as a key and not to be an
 *  object. Requiring an object here refused a parsed rejection that the same bytes rendered fine. */
function _looksParsedTsp(o) {
  if (typeof o.status !== "number" || !("timeStampToken" in o)) return false;
  /** @internal PKIFailureInfo is a bit record whose asserted names are an array, so a present failInfo of any
   *  other shape is a caller's own object and not this parser's output. The readers below still fault on
   *  nothing, and this makes an obviously wrong shape a typed refusal rather than an empty line. */
  if (o.failInfo !== null && o.failInfo !== undefined) {
    if (typeof o.failInfo !== "object" || !Array.isArray(o.failInfo.bits)) return false;
  }
  var tok = o.timeStampToken;
  return tok === null || (!!tok && typeof tok === "object" && !!tok.tstInfo && typeof tok.tstInfo === "object");
}
function _looksParsedAttrCert(o) {
  return typeof o.version === "number" && o.holder && typeof o.holder === "object" &&
    !!o.issuer && typeof o.issuer === "object" &&
    Array.isArray(o.attributes) && o.signatureAlgorithm && typeof o.signatureAlgorithm === "object";
}

function _parsePkcs8(input) { return _coerce(input, { marker: "privateKeyAlgorithm", looksParsed: _looksParsedPkcs8, parsedName: "pki.schema.pkcs8.parse", parse: pkcs8.parse, badCode: "inspect/bad-pkcs8", what: "PKCS#8 private key" }); }
function _parsePkcs12(input) { return _coerce(input, { marker: "safeBags", looksParsed: _looksParsedPkcs12, parsedName: "pki.schema.pkcs12.parse", parse: pkcs12.parse, badCode: "inspect/bad-pkcs12", what: "PKCS#12 store" }); }
function _parseCrmf(input) { return _coerce(input, { marker: "messages", looksParsed: _looksParsedCrmf, parsedName: "pki.schema.crmf.parse", parse: crmf.parse, badCode: "inspect/bad-crmf", what: "CRMF certificate request message" }); }
function _parseCmp(input) { return _coerce(input, { marker: "header", looksParsed: _looksParsedCmp, parsedName: "pki.schema.cmp.parse", parse: cmp.parse, badCode: "inspect/bad-cmp", what: "CMP message" }); }
function _parseCsrattrs(input) { return _coerce(input, { marker: "items", looksParsed: _looksParsedCsrattrs, parsedName: "pki.schema.csrattrs.parse", parse: csrattrs.parse, badCode: "inspect/bad-csrattrs", what: "CSR attributes response" }); }
function _parseTrustAnchor(input) { return _coerce(input, { marker: "anchors", looksParsed: _looksParsedTrustAnchor, parsedName: "pki.schema.trustanchor.parse", parse: trustanchor.parse, badCode: "inspect/bad-trustanchor", what: "trust anchor list" }); }
function _parseOcspReq(input) { return _coerce(input, { marker: "requestList", looksParsed: _looksParsedOcspReq, parsedName: "pki.schema.ocsp.parseRequest", parse: ocsp.parseRequest, badCode: "inspect/bad-ocsp-request", what: "OCSP request" }); }
function _parseOcspResp(input) { return _coerce(input, { marker: "responseStatus", looksParsed: _looksParsedOcspResp, parsedName: "pki.schema.ocsp.parseResponse", parse: ocsp.parseResponse, badCode: "inspect/bad-ocsp-response", what: "OCSP response" }); }
function _parseTsp(input) { return _coerce(input, { marker: "timeStampToken", looksParsed: _looksParsedTsp, parsedName: "pki.schema.tsp.parseResponse", parse: tsp.parseResponse, badCode: "inspect/bad-tsp", what: "timestamp response" }); }
function _parseAttrCert(input) { return _coerce(input, { marker: "holder", looksParsed: _looksParsedAttrCert, parsedName: "pki.schema.attrcert.parse", parse: attrcert.parse, badCode: "inspect/bad-attrcert", what: "attribute certificate" }); }

/** @internal A GeneralName, a distinguished name, a GeneralNames list, or nothing, whichever the field
 *  carries. These structures reach a name through four different shapes and a report reads one the same
 *  way wherever it sits. The list form arrives with each member still raw, carrying its context tag and
 *  its bytes and no decoded value, so each is read through the attribute-certificate module's own
 *  GeneralName reader rather than rendered from the wrapper, which is what printed the whole list as one
 *  hex run under a tag number the wrapper does not have. */
function _nameOrGn(v) {
  if (!v || typeof v !== "object") return "(none)";
  if (v.dn !== undefined || Array.isArray(v.rdns)) return _dnString(v) || "(empty)";
  if (Array.isArray(v.names)) {
    var parts = v.names.map(function (n) {
      if (n && n.value !== undefined) return _gn(n);
      if (n && Buffer.isBuffer(n.bytes)) {
        try { return _gn(attrcert.readGeneralName(n.bytes)); }
        // allow:swallow-unverified drop-silent display fallback: an unreadable name prints as its bytes
        catch (_unreadable) { return _gnRaw(n.bytes); }
      }
      return "";
    }).filter(function (s) { return s !== ""; });
    return parts.length ? parts.join(", ") : "(empty)";
  }
  /** @internal A STANDALONE GeneralName arrives raw from some parsers exactly as a list member does, and it
   *  needs the same decode: passed straight to the renderer, a directoryName printed as its label with no
   *  name after it and every other form printed its bytes. The list path had this and the single path did
   *  not, which is one rule applied to one of its two callers. */
  if (v.value === undefined && Buffer.isBuffer(v.bytes) && typeof v.tagNumber === "number") {
    try { return _gn(attrcert.readGeneralName(v.bytes)); }
    // allow:swallow-unverified drop-silent display fallback: an unreadable name prints as its bytes
    catch (_unreadableSingle) { return _gnRaw(v.bytes); }
  }
  var g = _gn(v);
  return g || "(unrecognized name form)";
}
function _optLine(L, pad, label, v) { if (v !== null && v !== undefined) L.push(pad + label + ": " + v); }

/** @internal A list is a list only when it IS one. `x && x.length` is true of a string and of anything else
 *  carrying a length, and `(x || [])` passes a truthy non-array straight through, so both admitted a value
 *  the following forEach then faulted on. These reports take a caller's pre-parsed object, whose members no
 *  door can validate to arbitrary depth, so a report must not fault on any shape it is handed. */
function _list(v) { return Array.isArray(v) ? v : []; }
/** @internal The same for a member a loop body dereferences. */
function _obj(v) { return (v !== null && typeof v === "object") ? v : {}; }

/** @internal A serial reads the same wherever a report carries one, through the certificate report's own
 *  presentation: small values as decimal with the hex beside them, long ones as wrapped colon-hex. Printed
 *  as bare hex, the serial 99 renders "63" and reads as the decimal 63. */
function _serialLine(hexOrValue, pad) {
  if (hexOrValue === null || hexOrValue === undefined) return null;
  /** @internal Only the two forms a parser produces, a hex string or a bigint. Anything else is a caller's
   *  own value, and `toString(16)` on it reaches the hex reader with something that is not hex. */
  var hex;
  if (typeof hexOrValue === "string") hex = hexOrValue;
  else if (typeof hexOrValue === "bigint" || typeof hexOrValue === "number") hex = hexOrValue.toString(16);
  else return null;
  if (!_isHexDigits(hex)) return null;
  return pad + _serial({ serialNumberHex: hex }, pad.length + 4);
}
/** @internal Whether every character is a hex digit, by character code so no regex is involved. */
function _isHexDigits(s) {
  if (typeof s !== "string" || s.length === 0) return false;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    var ok = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) || (c >= 0x41 && c <= 0x46);
    if (!ok) return false;
  }
  return true;
}
function _serialInto(L, pad, hexOrValue) {
  var line = _serialLine(hexOrValue, pad);
  if (line !== null) L.push(line);
}

/**
 * @primitive pki.inspect.pkcs8
 * @signature pki.inspect.pkcs8(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 5958
 * @related pki.schema.pkcs8.parse, pki.inspect.pkcs12
 *
 * Render a PKCS#8 private key as a text report: the version, the key algorithm and
 * its parameters, any attributes, and the public key when the structure carries
 * one. The private key itself is never rendered, only its presence and length, so
 * inspecting a key file does not write the key anywhere a report is written.
 * `input` is a PEM string, a DER Buffer, or a `pki.schema.pkcs8.parse` result; a
 * non-PKCS#8 throws `inspect/bad-pkcs8`, a wrong-type input `inspect/bad-input`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   pki.inspect.pkcs8(await pki.key.export(pair.privateKey)).split("\n")[0];  // "PKCS#8 Private Key:"
 */
function pkcs8Report(input) {
  var k = _parsePkcs8(input);
  var L = ["PKCS#8 Private Key:", "    Version: " + k.version];
  L.push("    Private Key Algorithm: " + _algName(k.privateKeyAlgorithm));
  /** @internal The algorithm's PARAMETERS say which curve an EC key is on, and without them an EC report
   *  named only `ecPublicKey` and identified nothing. They are public: an AlgorithmIdentifier's parameters
   *  describe the algorithm, not the key, so rendering them discloses nothing the key itself holds. */
  var alg = k.privateKeyAlgorithm;
  if (alg && Buffer.isBuffer(alg.parameters)) {
    var paramName;
    try { paramName = oid.name(asn1.read.oid(asn1.decode(alg.parameters))); }
    // allow:swallow-unverified drop-silent display fallback: parameters that are not an OID print as bytes
    catch (_notAnOid) { paramName = null; }
    L.push("    Algorithm Parameters: " + (paramName || _hexColon(alg.parameters, { wrap: 16, indent: 8 })));
  }
  L.push("    Private Key: present, " + k.privateKey.length + " bytes (not rendered)");
  /** @internal The public half is rendered only when the bytes are actually there: an RFC 5958 OneAsymmetricKey
   *  carries it as a BIT STRING record and a caller's object can carry anything, and the byte renderer faults
   *  on a value that is not a buffer rather than reporting one it cannot read. */
  var pubBytes = Buffer.isBuffer(k.publicKey) ? k.publicKey : _obj(k.publicKey).bytes;
  if (Buffer.isBuffer(pubBytes)) {
    L.push("    Public Key:");
    L.push(_hexColon(pubBytes, { wrap: 16, indent: 8 }));
  } else if (k.publicKey) {
    L.push("    Public Key: present, not readable as bytes");
  }
  L.push("    Attributes:");
  if (_list(k.attributes).length) _list(k.attributes).forEach(function (a) { L.push(_attribute(_obj(a), "        ")); });
  else L.push("        (none)");
  return L.join("\n") + "\n";
}

/**
 * @primitive pki.inspect.pkcs12
 * @signature pki.inspect.pkcs12(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 7292
 * @related pki.schema.pkcs12.parse, pki.pkcs12.open
 *
 * Render a PKCS#12 store's outer structure as a text report: the version, the
 * integrity mode, the MAC algorithm and its iteration count, and one line per safe
 * bag giving its type. No private key is rendered, and an encrypted safe's contents
 * are not decrypted, because this verb takes no password: the report names
 * `pki.pkcs12.open` as what reads the contents. `input` is a PEM string, a DER
 * Buffer, or a `pki.schema.pkcs12.parse` result; a non-PKCS#12 throws
 * `inspect/bad-pkcs12`, a wrong-type input `inspect/bad-input`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "p12.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var store = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: cert }] }] }, { password: "1234" });
 *   pki.inspect.pkcs12(store).split("\n")[0];  // "PKCS#12 Store:"
 */
function pkcs12Report(input) {
  var p = _parsePkcs12(input);
  var L = ["PKCS#12 Store:", "    Version: " + p.version];
  L.push("    Integrity Mode: " + p.integrityMode);
  if (p.mac) {
    L.push("    MAC:");
    L.push("        Kind: " + p.mac.kind);
    /** @internal RFC 9579's PBMAC1 carries the parameters that actually protect the store inside its own
     *  structure, and the outer MacData fields then describe nothing: read from there, a store with 2048
     *  PBKDF2 iterations reported one iteration, an empty salt, and "pbmac1" as its digest. */
    if (p.mac.pbmac1) {
      var kdf = p.mac.pbmac1.kdf || {};
      _optLine(L, "        ", "Digest", p.mac.pbmac1.schemeName || p.mac.pbmac1.schemeOid);
      _optLine(L, "        ", "Key Derivation", kdf.prfName || kdf.prfOid);
      _optLine(L, "        ", "Iterations", kdf.iterationCount);
      _optLine(L, "        ", "Key Length", kdf.keyLength);
      if (Buffer.isBuffer(kdf.salt)) L.push("        Salt: " + _hexColon(kdf.salt, {}));
    } else {
      _optLine(L, "        ", "Digest", p.mac.hashName || p.mac.hashOid);
      _optLine(L, "        ", "Iterations", p.mac.iterations);
      if (Buffer.isBuffer(p.mac.macSalt)) L.push("        Salt: " + _hexColon(p.mac.macSalt, {}));
    }
  } else {
    L.push("    MAC: (none)");
  }
  L.push("    Safe Bags: " + _list(p.safeBags).length);
  /** @internal RFC 7292 sec. 4.2.6's safeContentsBag holds further bags, and reporting only the container
   *  made a container of keys and certificates read the same as an empty one. The no-key-material rule
   *  carries into the nested level, because a key inside a container is still a key. */
  (function walkBags(bags, pad) {
    _list(bags).forEach(function (rawBag, i) {
      var bag = _obj(rawBag);
      /** @internal The PARSER's vocabulary, which is the ASN.1 bag-type name, not the builder's shorthand:
       *  keyed on `shroudedKey` and `key` the marker never once fired, because a parsed bag reports itself as
       *  `pkcs8ShroudedKeyBag` or `keyBag`. */
      var isKey = bag.type === "pkcs8ShroudedKeyBag" || bag.type === "keyBag";
      L.push(pad + "[" + i + "] " + bag.type + (isKey ? "  (private key, not rendered)" : "") +
        (Array.isArray(bag.nested) ? "  (" + bag.nested.length + " nested)" : ""));
      if (Array.isArray(bag.nested) && bag.nested.length) walkBags(bag.nested, pad + "    ");
    });
  })(p.safeBags, "        ");
  L.push("    Encrypted Safes: " + _list(p.encryptedSafes).length);
  var needsRecipientKey = false, needsSafePassword = false;
  _list(p.encryptedSafes).forEach(function (rawSafe, i) {
    var safe = _obj(rawSafe);
    if (safe.type === "envelopedData") needsRecipientKey = true;
    else needsSafePassword = true;
    /** @internal An encrypted safe is a CMS EncryptedData, so the algorithm that protects it sits on that
     *  structure's encryptedContentInfo rather than on the safe. Read off the safe it was absent and every
     *  encrypted store reported its algorithm as unknown. */
    var eci = _obj(safe.content).encryptedContentInfo;
    /** @internal The safe's TYPE says which credential opens it, so the row names it: RFC 7292 sec. 4.1's
     *  password privacy is an EncryptedData and its public-key privacy an EnvelopedData, and the two are
     *  opened by different things. */
    L.push("        [" + i + "] " + (safe.type ? safe.type + ": " : "") +
      _algName(_obj(eci).contentEncryptionAlgorithm) + "  (not decrypted)");
  });
  /** @internal WHICH credential opens the contents, because naming the wrong one sends an operator to look
   *  for something the store does not want: RFC 7292 sec. 4.1's public-key privacy is opened with a recipient
   *  key and `pki.pkcs12.open` refuses it with pkcs12/no-recipient-key, not with a password prompt. */
  var needs = [];
  if (needsSafePassword || !_list(p.encryptedSafes).length) needs.push("the password");
  if (needsRecipientKey) needs.push("opts.recipientKey for the enveloped safe");
  L.push("    The bag contents are read with pki.pkcs12.open, which takes " + needs.join(" and ") +
    ", which this report has no access to.");
  return L.join("\n") + "\n";
}

/**
 * @primitive pki.inspect.crmf
 * @signature pki.inspect.crmf(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 4211
 * @related pki.schema.crmf.parse, pki.inspect.csr
 *
 * Render CRMF certificate request messages as a text report: one block per message
 * giving its request id, the certificate template's subject, issuer, validity and
 * public key, the requested extensions, and whether a proof of possession and
 * registration controls are present. `input` is a PEM string, a DER Buffer, or a
 * `pki.schema.crmf.parse` result; a non-CRMF throws `inspect/bad-crmf`, a
 * wrong-type input `inspect/bad-input`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.crmf.build({ certReqId: 0, certTemplate: { subject: "crmf.example",
 *     publicKey: await pki.key.export(pair.publicKey) } }, { key: await pki.key.export(pair.privateKey) });
 *   pki.inspect.crmf(der).split("\n")[0];  // "CRMF Certificate Request Messages:"
 */
function crmfReport(input) {
  var m = _parseCrmf(input);
  var L = ["CRMF Certificate Request Messages:", "    Messages: " + m.messages.length];
  m.messages.forEach(function (msg, i) {
    var req = msg.certReq, t = req.certTemplate;
    L.push("    [" + i + "] Certificate Request:");
    _optLine(L, "        ", "Request ID", req.certReqId === undefined ? null : String(req.certReqId));
    /** @internal RFC 4211 sec. 5 carries the DER value, so 2 names v3, exactly as a certificate's does. The
     *  raw value read as a request for v2, which is the opposite of what the template asks for, and the
     *  certificate report beside it writes the same number the other way. */
    _optLine(L, "        ", "Version", t.version === undefined || t.version === null
      ? null : (Number(t.version) + 1) + " (0x" + Number(t.version).toString(16) + ")");
    if (t.serialNumber !== undefined && t.serialNumber !== null) L.push("        Serial Number: " + t.serialNumber);
    if (t.issuer) L.push("        Issuer: " + _nameOrGn(t.issuer));
    if (t.subject) L.push("        Subject: " + _nameOrGn(t.subject));
    if (t.signingAlg) L.push("        Signing Algorithm: " + _algName(t.signingAlg));
    if (t.validity) {
      L.push("        Validity:");
      _optLine(L, "            ", "Not Before", t.validity.notBefore ? _date(t.validity.notBefore) : null);
      _optLine(L, "            ", "Not After", t.validity.notAfter ? _date(t.validity.notAfter) : null);
    }
    if (t.publicKey) { L.push("        Subject Public Key Info:"); L.push(_keyBlock(t.publicKey, "            ")); }
    if (_list(t.extensions).length) {
      L.push("        Requested Extensions:");
      _list(t.extensions).forEach(function (e) { L.push(_extension(_obj(e), "            ")); });
    }
    /** @internal WHICH proof of possession a request carries is the difference between a key whose holder
     *  proved possession by signing and one an RA vouched for, so the form is named rather than reported as
     *  merely present. */
    L.push("        Proof of Possession: " + (msg.popo ? (msg.popo.type || "present") : "(none)"));
    L.push("        Registration Controls: " + ((req.controls && req.controls.length) || 0));
    L.push("        Registration Info: " + ((msg.regInfo && msg.regInfo.length) || 0));
  });
  return L.join("\n") + "\n";
}

/**
 * @primitive pki.inspect.cmp
 * @signature pki.inspect.cmp(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 9810
 * @related pki.schema.cmp.parse, pki.inspect.crmf
 *
 * Render a CMP message as a text report: the header's protocol version, sender and
 * recipient, transaction id and nonces, the body arm the message carries, and
 * whether protection and extra certificates are present. The body's inner content
 * is named rather than expanded, since each arm is its own structure that its own
 * verb reads. `input` is a PEM string, a DER Buffer, or a `pki.schema.cmp.parse`
 * result; a non-CMP throws `inspect/bad-cmp`, a wrong-type input
 * `inspect/bad-input`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "cmp.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var der = await pki.cmp.build({ header: { sender: { directoryName: "CN=cmp.example" },
 *     recipient: { directoryName: "CN=A CA" } },
 *     body: { ir: { certTemplate: { subject: [{ commonName: "cmp.example" }], publicKey: await pki.key.export(pair.publicKey) } } } },
 *     { cert: cert, key: key });
 *   pki.inspect.cmp(der).split("\n")[0];  // "CMP Message:"
 */
function cmpReport(input) {
  var m = _parseCmp(input);
  var h = m.header, body = m.body;
  var L = ["CMP Message:", "    Header:"];
  _optLine(L, "        ", "Protocol Version", h.pvno);
  L.push("        Sender: " + _nameOrGn(h.sender));
  L.push("        Recipient: " + _nameOrGn(h.recipient));
  if (h.messageTime) L.push("        Message Time: " + _date(h.messageTime));
  if (h.protectionAlg) L.push("        Protection Algorithm: " + _algName(h.protectionAlg));
  if (Buffer.isBuffer(h.transactionID)) L.push("        Transaction ID: " + _hexColon(h.transactionID, {}));
  if (Buffer.isBuffer(h.senderNonce)) L.push("        Sender Nonce: " + _hexColon(h.senderNonce, {}));
  if (Buffer.isBuffer(h.recipNonce)) L.push("        Recipient Nonce: " + _hexColon(h.recipNonce, {}));
  if (Buffer.isBuffer(h.senderKID)) L.push("        Sender Key ID: " + _hexColon(h.senderKID, {}));
  L.push("        General Info: " + ((h.generalInfo && h.generalInfo.length) || 0));
  L.push("    Body:");
  L.push("        Arm: " + body.arm);
  L.push("    Protection: " + (m.protection ? "present" : "(none)"));
  L.push("    Extra Certificates: " + ((m.extraCerts && m.extraCerts.length) || 0));
  return L.join("\n") + "\n";
}

/**
 * @primitive pki.inspect.csrattrs
 * @signature pki.inspect.csrattrs(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 7030, RFC 8951
 * @related pki.schema.csrattrs.parse, pki.inspect.csr
 *
 * Render an EST CSR Attributes response as a text report: one line per item, each
 * either a bare object identifier the server asks the client to supply or an
 * attribute with its type and values. `input` is a PEM string, a DER Buffer, or a
 * `pki.schema.csrattrs.parse` result; a non-CsrAttrs throws
 * `inspect/bad-csrattrs`, a wrong-type input `inspect/bad-input`.
 *
 * @example
 *   var b = pki.asn1.build;
 *   var der = b.sequence([b.oid("1.2.840.113549.1.9.7")]);
 *   pki.inspect.csrattrs(der).split("\n")[0];  // "EST CSR Attributes:"
 */
function csrattrsReport(input) {
  var a = _parseCsrattrs(input);
  var L = ["EST CSR Attributes:", "    Items: " + a.items.length];
  a.items.forEach(function (item, i) {
    var label = item.kind === "oid" ? "OID" : "Attribute";
    var name = item.name || item.oid || "unknown";
    L.push("    [" + i + "] " + label + ": " + name + (item.name && item.oid ? " (" + item.oid + ")" : ""));
    /** @internal The CONSTRAINT a client has to act on is what the parser added beside the raw value: a key
     *  size, a curve set, a template. Printed as its DER, a request for a 2048-bit key read as four bytes. */
    var constraint = _extraFields(item, _ROW_PLUMBING, "        ");
    if (constraint) L.push(constraint);
    if (item.kind !== "oid" && _list(item.values).length) {
      L.push("        Values: " + _list(item.values).length);
      _list(item.values).forEach(function (v) {
        /** @internal An attribute value a server chose is escaped for the reason a distinguished name is. */
        L.push("            " + (Buffer.isBuffer(v) ? _hexColon(v, {}) : _clean(String(v))));
      });
    }
  });
  return L.join("\n") + "\n";
}

/**
 * @primitive pki.inspect.trustanchor
 * @signature pki.inspect.trustanchor(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 5914
 * @related pki.schema.trustanchor.parse, pki.inspect.certificate
 *
 * Render an RFC 5914 trust anchor list as a text report: one block per anchor
 * giving which of the three forms it takes, its public key, key identifier and
 * title where present, and the certificate path controls that bound what it may
 * anchor. `input` is a PEM string, a DER Buffer, or a
 * `pki.schema.trustanchor.parse` result; a non-list throws
 * `inspect/bad-trustanchor`, a wrong-type input `inspect/bad-input`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var b = pki.asn1.build;
 *   var spki = await pki.key.export(pair.publicKey);
 *   var der = b.sequence([b.explicit(2, b.sequence([b.raw(spki), b.octetString(Buffer.alloc(20, 1))]))]);
 *   pki.inspect.trustanchor(der).split("\n")[0];  // "Trust Anchor List:"
 */
function trustAnchorReport(input) {
  var t = _parseTrustAnchor(input);
  var L = ["Trust Anchor List:", "    Anchors: " + t.anchors.length];
  t.anchors.forEach(function (a, i) {
    L.push("    [" + i + "] Form: " + a.kind);
    /** @internal RFC 5914 sec. 3 gives three forms, and only the TrustAnchorInfo one carries its key and
     *  name at the top: the other two hold a certificate, whose subject and subjectPublicKeyInfo are what
     *  name the anchor. Read as though every form were TrustAnchorInfo, a certificate anchor rendered its
     *  form and nothing else, so two different anchors produced the same report. */
    var held = a.kind === "certificate" ? a.certificate : (a.kind === "tbsCert" ? a.tbsCert : null);
    if (held) {
      if (held.subject) L.push("        Subject: " + _dnString(held.subject));
      if (held.issuer) L.push("        Issuer: " + _dnString(held.issuer));
      if (held.serialNumberHex) _serialInto(L, "        ", held.serialNumberHex);
      if (held.subjectPublicKeyInfo) {
        L.push("        Subject Public Key Info:");
        L.push(_keyBlock(held.subjectPublicKeyInfo, "            "));
      }
      /** @internal Rendered, not counted, and for the same reason the TrustAnchorInfo arm renders its own:
       *  the extensions bound what trusting the anchor means, so a count made a path-limited anchor read the
       *  same as an unlimited one. One rule, both arms. */
      if (_list(held.extensions).length) {
        L.push("        Extensions:");
        _list(held.extensions).forEach(function (e) { L.push(_extension(_obj(e), "            ")); });
      }
      return;
    }
    var info = a.taInfo;
    if (info.pubKey) { L.push("        Subject Public Key Info:"); L.push(_keyBlock(info.pubKey, "            ")); }
    if (Buffer.isBuffer(info.keyId)) L.push("        Key Identifier: " + _hexColon(info.keyId, {}));
    /** @internal A taTitle is text whoever wrote the anchor list chose, so it is escaped as the rest are. */
    _optLine(L, "        ", "Title", info.taTitle == null ? null : _clean(String(info.taTitle)));
    /** @internal RFC 5914 sec. 3's exts carry certificate extensions that bound what trusting the anchor
     *  means, a basicConstraints path length among them. Skipped, an anchor carrying one read the same as one
     *  carrying none. */
    if (_list(info.exts).length) {
      L.push("        Extensions:");
      _list(info.exts).forEach(function (e) { L.push(_extension(_obj(e), "            ")); });
    }
    var cpc = info.certPath;
    if (cpc) {
      L.push("        Certificate Path Controls:");
      if (cpc.taName) L.push("            Name: " + _nameOrGn(cpc.taName));
      _optLine(L, "            ", "Path Length", cpc.pathLenConstraint);
      /** @internal The policy IDENTIFIERS, because a count made two anchors restricted to different single
       *  policies read the same, and which policies an anchor is restricted to is what a reader asks. */
      if (_list(cpc.policySet).length) {
        L.push("            Policies:");
        _list(cpc.policySet).forEach(function (pol) {
          var p = _obj(pol);
          L.push("                " + (p.name ? p.name + " (" + p.policyIdentifier + ")" : String(p.policyIdentifier)));
        });
      }
      /** @internal RFC 5914 sec. 3's policyFlags is a BIT STRING the parser decodes to a record of named
       *  booleans, so it has no length: read as an array the line never ran and a trust anchor's active
       *  policy restrictions were absent from the report rather than shown as off. */
      if (cpc.policyFlags) {
        var onFlags = Object.keys(cpc.policyFlags).filter(function (n) { return cpc.policyFlags[n] === true; });
        L.push("            Policy Flags: " + (onFlags.length ? onFlags.join(", ") : "(none set)"));
      }
      /** @internal The subtrees an anchor may certify within are what a reader inspects an anchor to learn,
       *  and omitted they made a restricted anchor read identically to an unrestricted one. The shape is the
       *  certificate extension's own, so the extension renderer formats it rather than a second copy. */
      if (cpc.nameConstr) {
        var ncText = EXT_RENDERERS.nameConstraints(cpc.nameConstr, "                ");
        if (ncText) { L.push("            Name Constraints:"); L.push(ncText); }
      }
    }
  });
  return L.join("\n") + "\n";
}

/**
 * @primitive pki.inspect.ocspRequest
 * @signature pki.inspect.ocspRequest(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 6960
 * @related pki.schema.ocsp.parseRequest, pki.inspect.ocspResponse
 *
 * Render an OCSP request as a text report: the version, the requestor name where
 * one is given, one block per requested certificate giving the CertID's hash
 * algorithm and the issuer name and key hashes with the serial asked about, the
 * request extensions, and whether the request is signed. `input` is a PEM string, a
 * DER Buffer, or a `pki.schema.ocsp.parseRequest` result; a non-request throws
 * `inspect/bad-ocsp-request`, a wrong-type input `inspect/bad-input`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "ocsp.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var der = await pki.ocsp.buildRequest({ cert: cert, issuer: cert });
 *   pki.inspect.ocspRequest(der).split("\n")[0];  // "OCSP Request:"
 */
function ocspRequestReport(input) {
  var r = _parseOcspReq(input);
  var L = ["OCSP Request:", "    Version: " + r.version];
  L.push("    Requestor Name: " + (r.requestorName ? _nameOrGn(r.requestorName) : "(none)"));
  L.push("    Requests: " + r.requestList.length);
  r.requestList.forEach(function (req, i) {
    var id = req.certID;
    L.push("        [" + i + "] Certificate ID:");
    L.push("            Hash Algorithm: " + _algName(id.hashAlgorithm));
    if (Buffer.isBuffer(id.issuerNameHash)) L.push("            Issuer Name Hash: " + _hexColon(id.issuerNameHash, {}));
    if (Buffer.isBuffer(id.issuerKeyHash)) L.push("            Issuer Key Hash: " + _hexColon(id.issuerKeyHash, {}));
    _serialInto(L, "            ", id.serialNumberHex || id.serialNumber);
    if (_list(req.singleRequestExtensions).length) {
      L.push("            Single Request Extensions:");
      _list(req.singleRequestExtensions).forEach(function (e) { L.push(_extension(_obj(e), "                ")); });
    }
  });
  if (_list(r.requestExtensions).length) {
    L.push("    Request Extensions:");
    _list(r.requestExtensions).forEach(function (e) { L.push(_extension(_obj(e), "        ")); });
  } else {
    L.push("    Request Extensions: (none)");
  }
  L.push("    Signature: " + (r.optionalSignature ? "present" : "(unsigned)"));
  return L.join("\n") + "\n";
}

/**
 * @primitive pki.inspect.ocspResponse
 * @signature pki.inspect.ocspResponse(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 6960
 * @related pki.schema.ocsp.parseResponse, pki.inspect.ocspRequest
 *
 * Render an OCSP response as a text report: the response status, and for a basic
 * response the responder id, the time it was produced, one block per answer giving
 * the CertID, the certificate's status with its revocation time and reason where it
 * is revoked, and the validity window of the answer, plus the response extensions
 * and the certificates carried for the relying party to chain. `input` is a PEM
 * string, a DER Buffer, or a `pki.schema.ocsp.parseResponse` result; a non-response
 * throws `inspect/bad-ocsp-response`, a wrong-type input `inspect/bad-input`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey);
 *   var cert = await pki.x509.sign({ subject: "ocsp.example", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") }, { key: key });
 *   var der = await pki.ocsp.sign({ responderID: "byName",
 *     responses: [{ cert: cert, issuer: cert, status: "good", thisUpdate: new Date("2026-01-02T00:00:00Z") }] },
 *     { cert: cert, key: key });
 *   pki.inspect.ocspResponse(der).split("\n")[0];  // "OCSP Response:"
 */
function ocspResponseReport(input) {
  var r = _parseOcspResp(input);
  var st = r.responseStatus;
  var L = ["OCSP Response:", "    Response Status: " + st.name];
  if (r.responseBytes) L.push("    Response Type: " + (r.responseBytes.responseTypeName || r.responseBytes.responseType));
  var br = r.basicResponse;
  if (!br) { L.push("    (no basic response to render)"); return L.join("\n") + "\n"; }
  L.push("    Version: " + br.version);
  /** @internal RFC 6960 sec. 4.2.1 gives ResponderID two forms, and the key form is a hash rather than a
   *  name: passed to the name renderer it printed neither, so a responder that identifies itself by key was
   *  not identified in the report at all. */
  L.push("    Responder ID: " + (Buffer.isBuffer(br.responderID.byKey)
    ? "keyHash:" + _hexColon(br.responderID.byKey, {})
    : _nameOrGn(br.responderID.byName)));
  if (br.producedAt) L.push("    Produced At: " + _date(br.producedAt));
  L.push("    Responses: " + br.responses.length);
  br.responses.forEach(function (one, i) {
    var id = one.certID;
    L.push("        [" + i + "] Certificate ID:");
    L.push("            Hash Algorithm: " + _algName(id.hashAlgorithm));
    if (Buffer.isBuffer(id.issuerNameHash)) L.push("            Issuer Name Hash: " + _hexColon(id.issuerNameHash, {}));
    if (Buffer.isBuffer(id.issuerKeyHash)) L.push("            Issuer Key Hash: " + _hexColon(id.issuerKeyHash, {}));
    _serialInto(L, "            ", id.serialNumberHex || id.serialNumber);
    var status = one.certStatus;
    L.push("            Cert Status: " + status.type);
    if (status.revocationTime) L.push("            Revocation Time: " + _date(status.revocationTime));
    _optLine(L, "            ", "Revocation Reason", status.revocationReason);
    if (one.thisUpdate) L.push("            This Update: " + _date(one.thisUpdate));
    L.push("            Next Update: " + (one.nextUpdate ? _date(one.nextUpdate) : "NONE"));
    if (_list(one.singleExtensions).length) {
      L.push("            Single Extensions:");
      _list(one.singleExtensions).forEach(function (e) { L.push(_extension(_obj(e), "                ")); });
    }
  });
  if (_list(br.responseExtensions).length) {
    L.push("    Response Extensions:");
    _list(br.responseExtensions).forEach(function (e) { L.push(_extension(_obj(e), "        ")); });
  }
  if (br.signatureAlgorithm) L.push("    Signature Algorithm: " + _algName(br.signatureAlgorithm));
  L.push("    Certificates: " + ((br.certs && br.certs.length) || 0));
  return L.join("\n") + "\n";
}

/**
 * @primitive pki.inspect.tsp
 * @signature pki.inspect.tsp(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 3161
 * @related pki.schema.tsp.parseResponse, pki.inspect.cms
 *
 * Render an RFC 3161 timestamp response as a text report: the PKI status with its
 * status strings and failure info, and the TSTInfo inside the token, giving the
 * policy, the message imprint, the serial, the time it was stamped with its
 * accuracy and ordering, the nonce, and the TSA name. The token's own CMS structure,
 * its signer identifier and its signed attributes, is what `pki.inspect.cms`
 * renders, and a bare timestamp TOKEN is a CMS ContentInfo rather than a response,
 * so that verb reads one of those directly. `input` is a PEM string, a DER Buffer, or a
 * `pki.schema.tsp.parseResponse` result; a non-response throws `inspect/bad-tsp`,
 * a wrong-type input `inspect/bad-input`.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var key = await pki.key.export(pair.privateKey), spki = await pki.key.export(pair.publicKey);
 *   var ca = await pki.x509.sign({ subject: "tsa.example", subjectPublicKey: spki,
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true } },
 *     { key: key });
 *   var imprint = { hashAlgorithm: "sha256", hashedMessage: Buffer.alloc(32, 7) };
 *   var token = await pki.tsp.sign(imprint, { cert: ca, key: key }, { policy: "1.2.3", serialNumber: 1 });
 *   pki.inspect.tsp(pki.tsp.response(token, {})).split("\n")[0];  // "Timestamp Response:"
 */
function tspReport(input) {
  var r = _parseTsp(input);
  var L = ["Timestamp Response:", "    Status: " + r.status];
  /** @internal A statusString is text a responder chose, so it reaches the report through the same escape
   *  every other caller-controlled string does: copied raw, a newline forges a report line and a terminal
   *  escape rewrites the screen around it. */
  if (r.statusString) {
    var strings = Array.isArray(r.statusString) ? r.statusString : [r.statusString];
    L.push("    Status String: " + strings.map(function (s) { return _clean(String(s)); }).join("; "));
  }
  /** @internal PKIFailureInfo is a BIT STRING, and the parser decodes it to a record carrying the named
   *  bits it asserts in `bits`. Read as an array or a string it rendered as its own object notation and the
   *  reason a request was rejected, which is the one thing this line is for, was lost. */
  if (r.failInfo) L.push("    Failure Info: " + _list(_obj(r.failInfo).bits).join(", "));
  var tok = r.timeStampToken;
  if (!tok) { L.push("    Token: (none)"); return L.join("\n") + "\n"; }
  var t = tok.tstInfo;
  L.push("    TSTInfo:");
  _optLine(L, "        ", "Version", t.version);
  _optLine(L, "        ", "Policy", t.policyName ? t.policyName + " (" + t.policy + ")" : t.policy);
  if (t.messageImprint) {
    L.push("        Message Imprint:");
    L.push("            Hash Algorithm: " + _algName(t.messageImprint.hashAlgorithm));
    if (Buffer.isBuffer(t.messageImprint.hashedMessage)) {
      L.push("            Hashed Message:");
      L.push(_hexColon(t.messageImprint.hashedMessage, { wrap: 16, indent: 16 }));
    }
  }
  _serialInto(L, "        ", t.serialNumberHex || t.serialNumber);
  /** @internal A timestamp's value is the instant it names, and RFC 3161 sec. 2.4.2 puts the sub-second part
   *  in the GeneralizedTime's fraction, which the shared date renderer does not carry. Dropped, two stamps a
   *  fraction of a second apart read as the same instant. */
  if (t.genTime) {
    L.push("        Gen Time: " + _date(t.genTime) +
      (t.genTimeFraction ? "  (fraction: ." + t.genTimeFraction + ")" : ""));
  }
  if (t.accuracy) {
    var acc = [];
    if (t.accuracy.seconds != null) acc.push(t.accuracy.seconds + "s");
    if (t.accuracy.millis != null) acc.push(t.accuracy.millis + "ms");
    if (t.accuracy.micros != null) acc.push(t.accuracy.micros + "us");
    L.push("        Accuracy: " + (acc.length ? acc.join(" ") : "(empty)"));
  } else {
    L.push("        Accuracy: (none stated)");
  }
  L.push("        Ordering: " + (t.ordering === true));
  if (t.nonceHex) L.push("        Nonce: " + t.nonceHex);
  if (t.tsa) L.push("        TSA: " + _nameOrGn(t.tsa));
  if (_list(t.extensions).length) {
    L.push("        Extensions:");
    _list(t.extensions).forEach(function (e) { L.push(_extension(_obj(e), "            ")); });
  }
  L.push("    Certificates: " + _list(tok.certificates).length);
  return L.join("\n") + "\n";
}

/**
 * @primitive pki.inspect.attrcert
 * @signature pki.inspect.attrcert(input) -> string
 * @since 0.8.29
 * @status stable
 * @spec RFC 5755
 * @related pki.schema.attrcert.parse, pki.inspect.certificate
 *
 * Render an RFC 5755 attribute certificate as a text report: the version, the
 * holder and the issuer in whichever form each takes, the serial, the validity
 * period, the attributes the certificate asserts, its extensions, and the signature
 * algorithm. `input` is a PEM string, a DER Buffer, or a
 * `pki.schema.attrcert.parse` result; a non-attribute-certificate throws
 * `inspect/bad-attrcert`, a wrong-type input `inspect/bad-input`. An
 * X.509-1997 v1 attribute certificate is not parsed by this build, and the report
 * surfaces that refusal rather than rendering a partial one.
 *
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.attrcert.sign({ holder: { entityName: { directoryName: "CN=Alice" } },
 *     notBeforeTime: new Date("2026-01-01T00:00:00Z"), notAfterTime: new Date("2027-01-01T00:00:00Z"),
 *     attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } } },
 *     { name: "CN=An AA", publicKey: await pki.key.export(pair.publicKey), key: await pki.key.export(pair.privateKey) });
 *   pki.inspect.attrcert(der).split("\n")[0];  // "Attribute Certificate:"
 */
function attrCertReport(input) {
  var a = _parseAttrCert(input);
  var L = ["Attribute Certificate:", "    Data:"];
  L.push("        Version: " + a.version);
  var holder = a.holder;
  L.push("        Holder:");
  if (holder.entityName) L.push("            Entity Name: " + _nameOrGn(holder.entityName));
  if (holder.baseCertificateID) {
    var bid = holder.baseCertificateID;
    L.push("            Base Certificate ID:");
    if (bid.issuer) L.push("                Issuer: " + _nameOrGn(bid.issuer));
    /** @internal RFC 5755's IssuerSerial names its field `serial`, which the parser surfaces as `serial`
     *  and `serialHex`, not as the `serialNumber` a certificate carries. Read by the certificate's names
     *  both operands were undefined and the holder's serial was dropped, leaving two holders under one
     *  issuer indistinguishable in the report. */
    _serialInto(L, "                ", bid.serialHex || bid.serial);
  }
  /** @internal The DIGEST is what identifies a holder named this way, so the algorithm alone left every
   *  holder identified by one digest algorithm reading the same. The object type says what was hashed. */
  if (holder.objectDigestInfo) {
    var odi = holder.objectDigestInfo;
    L.push("            Object Digest Info:");
    L.push("                Digested Object Type: " +
      ((odi.digestedObjectType && odi.digestedObjectType.name) || "unspecified"));
    if (odi.otherObjectTypeID) L.push("                Other Object Type: " + odi.otherObjectTypeID);
    L.push("                Digest Algorithm: " + _algName(odi.digestAlgorithm));
    var digestBytes = odi.objectDigest && (Buffer.isBuffer(odi.objectDigest) ? odi.objectDigest : odi.objectDigest.bytes);
    if (Buffer.isBuffer(digestBytes)) {
      L.push("                Digest:");
      L.push(_hexColon(digestBytes, { wrap: 16, indent: 20 }));
    }
  }
  /** @internal RFC 5755 sec. 4.2.3's V2Form names the issuer by name, by a base certificate id, or by an
   *  object digest, and only the first was rendered: an issuer identified either other way appeared as
   *  nothing at all. The v1Form is a GeneralNames list, which the name renderer reads. */
  var iss = a.issuer;
  var issuedBy = iss.v2Form ? _nameOrGn(iss.v2Form.issuerName) : _nameOrGn(iss.v1Form || iss);
  if (issuedBy === "(none)" && iss.v2Form) {
    var v2 = iss.v2Form;
    if (v2.baseCertificateID) {
      issuedBy = "baseCertificateID " + _nameOrGn(v2.baseCertificateID.issuer) +
        (v2.baseCertificateID.serialHex ? " serial " + v2.baseCertificateID.serialHex : "");
    } else if (v2.objectDigestInfo) {
      issuedBy = "objectDigest " + _algName(v2.objectDigestInfo.digestAlgorithm);
    }
  }
  L.push("        Issuer: " + issuedBy);
  if (iss.form) L.push("        Issuer Form: " + iss.form);
  L.push("        " + _serial(a, 12));
  if (a.validity) {
    L.push("        Validity:");
    if (a.validity.notBeforeTime) L.push("            Not Before: " + _date(a.validity.notBeforeTime));
    if (a.validity.notAfterTime) L.push("            Not After : " + _date(a.validity.notAfterTime));
  }
  L.push("        Attributes:");
  if (_list(a.attributes).length) _list(a.attributes).forEach(function (at) { L.push(_attribute(_obj(at), "            ")); });
  else L.push("            (none)");
  if (_list(a.extensions).length) {
    L.push("        Extensions:");
    _list(a.extensions).forEach(function (e) { L.push(_extension(_obj(e), "            ")); });
  }
  L.push("    Signature Algorithm: " + _algName(a.signatureAlgorithm));
  return L.join("\n") + "\n";
}

var _INSPECT_BY_FORMAT = Object.assign(Object.create(null), {
  x509: certificate, crl: crlReport, csr: csrReport, cms: cmsReport,
  pkcs8: pkcs8Report, pkcs12: pkcs12Report, crmf: crmfReport, cmp: cmpReport,
  csrattrs: csrattrsReport, trustanchor: trustAnchorReport,
  "ocsp-request": ocspRequestReport, "ocsp-response": ocspResponseReport,
  tsp: tspReport, attrcert: attrCertReport,
});

/**
 * @primitive pki.inspect.any
 * @signature pki.inspect.any(input) -> string
 * @since 0.3.8
 * @status stable
 * @spec RFC 5280
 * @related pki.schema.detectFormat, pki.inspect.certificate
 *
 * Detect which PKI format `input` (a PEM string or DER Buffer) encodes and render
 * it with the matching report, the inspect analogue of `pki.schema.parse`. Every
 * format `pki.schema.all()` detects has a report and its own named verb, so the
 * same bytes render the same whether the format is detected or asked for by name.
 * An X.509-1997 v1 attribute certificate is detected so it can be named, and it is
 * refused with the reason its own parser gives rather than as an unsupported
 * format. An unrecognized input throws `inspect/bad-input`.
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
  /** @internal A format with no renderer is one whose parser refuses the bytes outright, and the reason
   *  it refuses is what a reader of that file needs. `attrcert-v1` is the case: an X.509-1997 attribute
   *  certificate is detected so it can be named rather than misread as the v2 form, and its parser
   *  throws `attrcert/legacy-v1-not-supported`. Reporting "inspect does not support this format" would
   *  send an operator looking for a missing feature instead of telling them which form they hold, so the
   *  format's own parse runs and its error propagates. */
  if (!render) {
    schemaAll.parse(der);
    throw _err("inspect/unsupported-format", "inspect does not support the detected format \"" + fmt +
      "\" (supported: " + Object.keys(_INSPECT_BY_FORMAT).sort().join(", ") + ")");
  }
  return render(der);
}

module.exports = {
  certificate: certificate,
  crl: crlReport,
  csr: csrReport,
  cms: cmsReport,
  pkcs8: pkcs8Report,
  pkcs12: pkcs12Report,
  crmf: crmfReport,
  cmp: cmpReport,
  csrattrs: csrattrsReport,
  trustanchor: trustAnchorReport,
  ocspRequest: ocspRequestReport,
  ocspResponse: ocspResponseReport,
  tsp: tspReport,
  attrcert: attrCertReport,
  any: any,
  renderedExtensions: Object.keys(EXT_RENDERERS),
};
