// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.lint
 * @nav        Tooling
 * @title      Lint
 * @fullname   Certificate, revocation-list and OCSP-response linting against RFC 5280, RFC 6960
 *             and CA/Browser Forum requirements
 * @intro The LINTING engine, the zlint / pkilint of JavaScript. It walks an ALREADY-PARSED
 *   certificate, certificate revocation list or OCSP response (from `pki.schema.x509.parse`,
 *   `pki.schema.crl.parse` or `pki.schema.ocsp.parseResponse`, whose extension values it
 *   decodes with the shared RFC 5280 decoders) and emits graded, advisory FINDINGS: each with
 *   a stable id, a severity (`fatal` > `error` > `warn` > `notice` > `pass`), a source, a
 *   spec-clause citation, and a human message. It ships the RFC 5280 certificate profile, the
 *   RFC 5280 section 5 revocation-list profile, the RFC 6960 OCSP response profile with the
 *   RFC 5019 lightweight rows, the post-quantum certificate profiles for ML-KEM, ML-DSA and
 *   SLH-DSA, and a representative CA/Browser Forum TLS Baseline Requirements subset.
 *
 *   Unlike every other toolkit entry, the lint data path never throws. A linter surveys a
 *   corpus that includes malformed members, so `pki.lint.certificate(hostileBytes)` returns
 *   a report whose worst finding is a `fatal` id `lint/unparseable` (carrying the inner
 *   `PkiError.code`) and does not raise. The one throw path is config-time misuse (an
 *   unknown profile, an out-of-range severity threshold, or a wrong-type input), which
 *   raises a typed `LintError`. This deliberate inversion of the toolkit's fail-closed-throw
 *   posture is what lets an operator lint a whole directory without a try/catch per file.
 * @spec RFC 5280, RFC 6960, RFC 5019, RFC 9654, RFC 9881, RFC 9909, RFC 9935, CA/Browser Forum TLS Baseline Requirements
 * @card Lint a certificate, CRL or OCSP response against RFC 5280, RFC 6960 + CABF TLS BR, in pure JS.
 */

var frameworkError = require("./framework-error");
var asn1 = require("./asn1-der");
var guard = require("./guard-all");
var oid = require("./oid");
var x509 = require("./schema-x509");
var crlSchema = require("./schema-crl");
var csrSchema = require("./schema-csr");
var ocspSchema = require("./schema-ocsp");
var pkix = require("./schema-pkix");
var pkiBuild = require("./pki-build");
var schema = require("./schema-engine");
var path = require("./path-validate");
var C = require("./constants");
var ipUtils = require("./ip-utils");

var MS_PER_DAY = C.TIME.days(1);

var LintError = frameworkError.LintError;
function _cfg(code, message, cause) { return new LintError(code, message, cause); }

function _sameName(a, b) {
  if (!a || !b || !a.rdns || !b.rdns) return false;
  try { return guard.name.dnEqual(a.rdns, b.rdns, _cfg, "lint/bad-input", "distinguished name") === true; }
  catch (_e) { return a.dn === b.dn; }
}

var NS = pkix.makeNS("lint", LintError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;



var SEVERITY = Object.assign(Object.create(null), { fatal: 5, error: 4, warn: 3, notice: 2, pass: 1 });
var VALID_SEVERITY = Object.keys(SEVERITY);

function _worst(findings) {
  var w = null, wv = 0;
  findings.forEach(function (f) { var v = SEVERITY[f.severity] || 0; if (v > wv) { wv = v; w = f.severity; } });
  return w;
}

function _finding(rule, detail) {
  var f = { id: rule.id, severity: rule.severity, source: rule.source, citation: rule.citation, message: rule.message };
  if (detail && detail.context) f.context = detail.context;
  return f;
}


function _derivedCert(o) {
  if (!o || typeof o !== "object" || guard.bytes.isByteSource(o)) return null;
  try {
    var p = guard.parsed.acceptDerived(o, "certificate", x509.parse, _cfg, "lint/bad-input", "the certificate");
    return guard.parsed.isCert(p) ? p : null;
  } catch (_e) {
    return null;
  }
}

/** @internal The bytes a lint verb was handed, as a Buffer, or null where the input is not bytes
 *  at all and the caller's own branches answer for it. Every parser in this toolkit reads any
 *  BufferSource, so the one surface that promises never to throw on the data path does not turn
 *  away a caller holding a Uint8Array from the network or an ArrayBuffer from a reader. Taking a
 *  snapshot rather than the caller's view is also what closes the detached-backing-buffer hazard,
 *  since a caller can neuter the buffer between the check and the read. */
function _derBytesOf(input) {
  if (!guard.bytes.isByteSource(input)) return null;
  try {
    return { der: guard.bytes.snapshotSource(input, LintError, "lint/bad-input", "pki.lint input") };
  } catch (e) {
    /** @internal A byte source whose backing buffer was detached is still a byte source, and it
     * fails at the door rather than at the parse. The data path answers with a verdict either
     * way, or one neutered buffer aborts the scan of a whole corpus. */
    return { fatal: { id: "lint/unparseable", severity: "fatal", source: "engine", citation: "pki.lint",
      message: "input is a byte source whose bytes could not be read", context: { code: e.code } } };
  }
}

function _ingest(input) {
  var derived = _derivedCert(input);
  if (derived) return { cert: derived };
  var der;
  var bytes = _derBytesOf(input);
  if (bytes !== null && bytes.fatal) return { fatal: bytes.fatal };
  if (bytes !== null) der = bytes.der;
  else if (typeof input === "string") {
    try { der = x509.pemDecode(input, "CERTIFICATE"); }
    catch (e) { return { fatal: { id: "lint/unparseable", severity: "fatal", source: "engine", citation: "pki.lint", message: "input is not a decodable PEM/DER certificate", context: { code: e.code } } }; }
  } else {
    throw _cfg("lint/bad-input", "pki.lint input must be a parsed certificate, a DER Buffer, or a PEM string");
  }
  try { return { cert: x509.parse(der) }; }
  catch (e) { return { fatal: { id: "lint/unparseable", severity: "fatal", source: "engine", citation: "RFC 5280", message: "input is not a well-formed X.509 certificate", context: { code: e.code } } }; }
}


function _findRaw(cert, name) {
  var dotted = oid.byName(name);
  var list = cert.extensions || [];
  for (var i = 0; i < list.length; i++) { if (list[i].oid === dotted) return list[i]; }
  return null;
}
// allow:swallow-unverified the decode fault is reported by the extension-undecodable rule
function _decodeOrNull(cert, name) {
  var ext = _findRaw(cert, name);
  if (!ext) return null;
  var dec = EXT_DECODERS[oid.byName(name)];
  if (!dec) return null;
  try { return { critical: ext.critical, value: dec(ext.value) }; }
  catch (_e) { return null; }
}

function _hasEku(cert, ekuName) {
  var d = _decodeOrNull(cert, "extKeyUsage");
  return !!(d && Array.isArray(d.value) && d.value.indexOf(oid.byName(ekuName)) !== -1);
}

function _makeCtx(cert, profile) {
  var explicitTls = profile === "cabf-tls";
  var bc = _decodeOrNull(cert, "basicConstraints");
  var isCa = !!(bc && bc.value && bc.value.cA === true);
  return {
    profile: profile,
    explicitTlsProfile: explicitTls,
    /** @internal An S/MIME subscriber certificate names its exact profile through a reserved
     * policy identifier, so unlike the TLS case the rows detect it from the certificate itself and
     * the flag only records that the caller also named it. */
    explicitSmimeProfile: profile === "cabf-smime",
    /** @internal A code signing subscriber certificate names its kind through a reserved policy
     * identifier the same way, so this flag only records that the caller also named the profile. */
    explicitCsProfile: profile === "cabf-cs",
    isCaCert: isCa,
    isTlsServerCert: explicitTls || (_hasEku(cert, "serverAuth") && !isCa),
    decode: function (name) { return _decodeOrNull(cert, name); },
    raw: function (name) { return _findRaw(cert, name); },
  };
}


function _effective(rule, cert) {
  if (!rule.effectiveDate) return true;
  var nb = cert.validity && cert.validity.notBefore;
  // allow:nan-date-comparison-unguarded -- nb is a codec-parsed cert notBefore (asn1 readTime rejects a NaN instant); effectiveDate is a Date literal.
  return guard.time.isDate(nb) && guard.time.instantOf(nb) >= guard.time.instantOf(rule.effectiveDate);
}

function _runLints(rules, cert, ctx) {
  var findings = [], ran = [];
  var counts = Object.assign(Object.create(null), { fatal: 0, error: 0, warn: 0, notice: 0, pass: 0, na: 0, ne: 0 });
  rules.forEach(function (rule) {
    if (rule.appliesTo && !rule.appliesTo(cert, ctx)) { counts.na++; return; }
    if (!_effective(rule, cert)) { counts.ne++; return; }
    ran.push(rule.id);
    var res = rule.check(cert, ctx);
    if (res == null || res === false) { counts.pass++; return; }
    var details = Array.isArray(res) ? res : [res];
    details.forEach(function (d) {
      var f = _finding(rule, d === true ? null : d);
      findings.push(f);
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
  });
  return { findings: findings, counts: counts, ran: ran };
}


/** @internal The octet length of a big-endian magnitude. DER prefixes a 0x00 to a positive integer
 * whose top bit is set, so that octet is encoding overhead rather than part of the number. Every
 * rule that measures a number against a ceiling reads it here, so no two of them can answer
 * differently for one value.
 *
 * The ceiling is measured against the VALUE, not its encoding. Sections 4.1.2.2 and 5.2.3 bound
 * "serialNumber values" and "CRLNumber values", and each requires that users be able to handle
 * values up to 20 octets. Every value from 2^159 through 2^160-1 is a 20-octet value whose DER
 * content needs a 21st octet for the sign, so reading the ceiling against the encoding would make
 * conforming values unrepresentable. Measuring the encoding is a real reading elsewhere in the
 * ecosystem, which is why some CAs clear the top bit of a 20-octet serial; this is a deliberate
 * choice between the two, not an oversight. */
function _magnitudeOctets(buf) {
  if (buf.length > 1 && buf[0] === 0x00 && (buf[1] & 0x80)) return buf.length - 1;
  return buf.length;
}

function _serialOctets(cert) {
  var hex = cert.serialNumberHex || "";
  if (hex.length % 2) hex = "0" + hex;
  return _magnitudeOctets(Buffer.from(hex, "hex"));
}

function _dnsNameProblem(s) { return pkix.dnsNameProblem(s); }

function _looksLikeIp(s) { return ipUtils.isIpLiteral(s); }

function _sanDnsNames(ctx) {
  var d = ctx.decode("subjectAltName");
  if (!d || !d.value || !Array.isArray(d.value.names)) return [];
  return d.value.names.filter(function (n) { return n && n.tagNumber === 2; }).map(function (n) { return n.value; });
}
/** @internal Every subject attribute, flattened across the RDNs, since a distinguished name says
 *  the same thing whether it carries one multi-valued RDN or several single-valued ones. */
function _subjectAttributes(cert) {
  var out = [];
  ((cert.subject && cert.subject.rdns) || []).forEach(function (rdn) {
    rdn.forEach(function (a) { out.push(a); });
  });
  return out;
}
/** @internal The string values of one subject attribute type, named through the registry. */
function _subjectValuesOf(cert, name) {
  var dotted = oid.byName(name);
  var out = [];
  _subjectAttributes(cert).forEach(function (a) {
    if (a.type === dotted && typeof a.value === "string") out.push(a.value);
  });
  return out;
}
function _subjectCNs(cert) { return _subjectValuesOf(cert, "commonName"); }

/** @internal The criticality RFC 5280 fixes for a certificate extension, read from the shared table
 * the certificate signer refuses to write against. The profile has its own row for each extension
 * the table holds CRITICAL (basicConstraints, nameConstraints, policyConstraints, inhibitAnyPolicy),
 * so only the NON-critical direction is graded through this table, under one id, the way the CRL
 * profile grades its criticality rows. */
var CERT_FIXED_CRITICALITY = pkix.certFixedCriticality(oid);
var _CRITICAL_LEGIT = Object.create(null);
_CRITICAL_LEGIT[oid.byName("precertificatePoison")] = true;
/** @internal An extension whose criticality the profile fixes is one it recognizes: marked against
 * the table it is a criticality fault with its own row, never an unrecognized extension. */
function _isUnknownExtension(extOid) {
  if (CERT_FIXED_CRITICALITY[extOid] !== undefined) return false;
  if (path.PROCESSED_EXTENSIONS[extOid] !== true) return _CRITICAL_LEGIT[extOid] !== true;
  return path.TARGET_UNPROCESSED_IF_CRITICAL[extOid] === true;
}

function _rsaModulusBits(spki) {
  try {
    var pk = spki.publicKey && (spki.publicKey.bytes || spki.publicKey);
    if (!Buffer.isBuffer(pk)) return null;
    var seq = asn1.decode(pk);
    if (!seq.children || seq.children.length !== 2) return null;
    var mod = asn1.read.integer(seq.children[0]);
    asn1.read.integer(seq.children[1]);
    if (mod <= 0n) return null;
    return mod.toString(2).length;
  } catch (_e) { return null; }
}
/** @internal The RSA public exponent, read from the same RSAPublicKey the modulus comes from, or
 *  null where the key does not decode as one. */
function _rsaExponent(spki) {
  try {
    var pk = spki.publicKey && (spki.publicKey.bytes || spki.publicKey);
    if (!Buffer.isBuffer(pk)) return null;
    var seq = asn1.decode(pk);
    if (!seq.children || seq.children.length !== 2) return null;
    return asn1.read.integer(seq.children[1]);
  } catch (_e) { return null; }
}
var RSA_KEY_ALGS = Object.assign(Object.create(null), { rsaEncryption: 1, rsassaPss: 1, rsaesOaep: 1 });
var APPROVED_EC_CURVES = ["prime256v1", "secp384r1", "secp521r1"];
function _ecCurveName(spki) {
  try {
    var params = spki.algorithm && spki.algorithm.parameters;
    if (!Buffer.isBuffer(params)) return null;
    return oid.name(asn1.read.oid(asn1.decode(params)));
  } catch (_e) { return null; }
}

var OID_UNOTICE = oid.byName("unotice");
var OID_ANY_POLICY = oid.byName("anyPolicy");
var OID_CPS = oid.byName("cps");
/** @internal The extensions RFC 5280 says a conforming CA SHOULD mark non-critical, keyed by OID
 *  with the clause; the MUSTs live in the shared CERT_FIXED_CRITICALITY table. The subjectAltName
 *  and extKeyUsage recommendations are conditional and have their own rules. */
var CERT_RECOMMENDED_NON_CRITICAL = Object.create(null);
CERT_RECOMMENDED_NON_CRITICAL[oid.byName("issuerAltName")] = "RFC 5280 sec. 4.2.1.7";
CERT_RECOMMENDED_NON_CRITICAL[oid.byName("cRLDistributionPoints")] = "RFC 5280 sec. 4.2.1.13";
var _T_BMP = asn1.TAGS.BMP_STRING, _T_VISIBLE = asn1.TAGS.VISIBLE_STRING, _T_UTF8 = asn1.TAGS.UTF8_STRING;
function _hasControlChar(str) {
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) return true;
  }
  return false;
}
/** @internal Every policy qualifier of every PolicyInformation, handed to `fn` as its qualifier
 *  OID, its value node, and the PolicyInformation carrying it. The decoder surfaces the qualifiers
 *  as raw DER, because a qualifier may carry any type and the reader does not choose one for the
 *  caller, so every walk re-decodes bytes that already passed the policy-qualifier door. */
function _eachPolicyQualifier(ctx, fn) {
  var d = ctx.decode("certificatePolicies");
  if (!d || !Array.isArray(d.value)) return;
  d.value.forEach(function (pi) {
    if (!pi.qualifiersBytes || !pi.qualifiersBytes.length) return;
    var quals;
    // allow:swallow-unverified re-decoding bytes that already decoded under assertPolicyQualifiers cannot throw
    try {
      quals = asn1.decode(pi.qualifiersBytes).children;
    } catch (_e) {
      return;
    }
    (quals || []).forEach(function (pq) {
      var qid;
      // allow:swallow-unverified assertPolicyQualifiers already read this OID, so re-reading it cannot throw
      try {
        qid = asn1.read.oid(pq.children[0]);
      } catch (_e2) {
        return;
      }
      fn(qid, pq.children[1], pi);
    });
  });
}
function _policyDisplayTexts(ctx) {
  var out = [];
  _eachPolicyQualifier(ctx, function (qid, value) {
    if (qid !== OID_UNOTICE) return;
    out = out.concat(pkix.userNoticeTexts(value));
  });
  return out;
}
function _hasPolicyDisplayText(cert, ctx) { return _policyDisplayTexts(ctx).length > 0; }

function _criticalityRule(name, id, severity, citation, message) {
  return {
    id: id, severity: severity, source: "rfc5280", citation: citation, message: message,
    appliesTo: function (cert, ctx) { return !!ctx.raw(name); },
    check: function (cert, ctx) { var e = ctx.raw(name); return (e && e.critical !== true) ? true : null; },
  };
}

var RFC5280_RULES = [
  {
    id: "lint/rfc5280/signature-empty", severity: "error", source: "rfc5280", citation: "RFC 5280 4.1.1.3",
    /** @internal The strict parser admits an empty BIT STRING, since one is well-formed DER; a
     * signatureValue that contains no signature is not the field section 4.1.1.3 defines. */
    message: "the signatureValue contains no signature",
    check: function (cert) { return cert.signatureValue.bytes.length === 0 ? true : null; },
  },
  {
    id: "lint/rfc5280/extension-criticality", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2.1.1 / 4.2.1.2 / 4.2.1.8 / 4.2.1.15 / 4.2.2.1 / 4.2.2.2",
    message: "an extension a conforming CA must mark non-critical is marked critical",
    /** @internal Keyed by the extension's OID throughout. The display name the parser attaches can
     * be re-pointed through the registry, so a lookup by name would answer for a different
     * extension, or for none. */
    check: function (cert) {
      var rows = [];
      (cert.extensions || []).forEach(function (e) {
        var fixed = CERT_FIXED_CRITICALITY[e.oid];
        if (fixed === undefined || fixed.critical !== false || e.critical !== true) return;
        rows.push({ context: { extension: e.name || e.oid, oid: e.oid, required: "non-critical", was: "critical", scope: "extensions", citation: fixed.citation } });
      });
      return rows.length ? rows : null;
    },
  },
  {
    id: "lint/rfc5280/serial-not-positive", severity: "error", source: "rfc5280", citation: "RFC 5280 4.1.2.2",
    message: "the certificate serialNumber must be a positive integer",
    check: function (cert) { return cert.serialNumber <= 0n ? true : null; },
  },
  {
    id: "lint/rfc5280/serial-too-long", severity: "error", source: "rfc5280", citation: "RFC 5280 4.1.2.2",
    message: "the certificate serialNumber must not exceed 20 octets",
    check: function (cert) { return _serialOctets(cert) > 20 ? { context: { octets: _serialOctets(cert) } } : null; },
  },
  {
    id: "lint/rfc5280/validity-inverted", severity: "error", source: "rfc5280", citation: "RFC 5280 4.1.2.5",
    message: "the certificate notBefore must not be later than notAfter",
    check: function (cert) {
      var v = cert.validity;
      // allow:nan-date-comparison-unguarded -- notBefore/notAfter are codec-parsed cert dates (asn1 readTime rejects a NaN instant).
      return (guard.time.isDate(v.notBefore) && guard.time.isDate(v.notAfter) &&
        guard.time.instantOf(v.notBefore) > guard.time.instantOf(v.notAfter)) ? true : null;
    },
  },
  {
    id: "lint/rfc5280/ca-without-keycertsign", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2.1.3 / 4.2.1.9",
    message: "a CA certificate (basicConstraints cA=TRUE) must assert the keyCertSign key usage",
    appliesTo: function (cert, ctx) { var bc = ctx.decode("basicConstraints"); return !!(bc && bc.value && bc.value.cA === true); },
    check: function (cert, ctx) { var ku = ctx.decode("keyUsage"); return (ku && ku.value && ku.value.keyCertSign === true) ? null : true; },
  },
  {
    id: "lint/rfc5280/keycertsign-without-ca", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2.1.3",
    message: "a certificate asserting the keyCertSign key usage must also assert basicConstraints cA=TRUE",
    appliesTo: function (cert, ctx) { var ku = ctx.decode("keyUsage"); return !!(ku && ku.value && ku.value.keyCertSign === true); },
    check: function (cert, ctx) { var bc = ctx.decode("basicConstraints"); return (bc && bc.value && bc.value.cA === true) ? null : true; },
  },
  {
    id: "lint/rfc5280/unknown-critical-extension", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2",
    message: "a critical extension is not recognized by the profile -- a conforming consumer must reject it",
    check: function (cert) {
      var out = [];
      (cert.extensions || []).forEach(function (e) {
        if (e.critical === true && _isUnknownExtension(e.oid)) out.push({ context: { oid: e.oid, name: e.name || null } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280/empty-subject-san-not-critical", severity: "error", source: "rfc5280", citation: "RFC 5280 4.1.2.6",
    message: "a certificate with an empty subject must carry a subjectAltName marked critical",
    appliesTo: function (cert) { return !((cert.subject && cert.subject.rdns) || []).length; },
    check: function (cert, ctx) { var san = ctx.decode("subjectAltName"); return (san && san.critical === true) ? null : true; },
  },
  {
    id: "lint/rfc5280/extension-undecodable", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2",
    message: "a recognized extension's value does not decode under its RFC 5280 syntax",
    check: function (cert) {
      var out = [];
      (cert.extensions || []).forEach(function (e) {
        var dec = EXT_DECODERS[e.oid];
        if (!dec) return;
        try { dec(e.value); }
        catch (err) {
          out.push({ context: { oid: e.oid, name: e.name || null, code: err.code } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280/ski-missing", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2.1.2",
    message: "a CA certificate must carry a subjectKeyIdentifier extension",
    appliesTo: function (cert, ctx) { var bc = ctx.decode("basicConstraints"); return !!(bc && bc.value && bc.value.cA === true); },
    check: function (cert, ctx) { return ctx.raw("subjectKeyIdentifier") ? null : true; },
  },
  {
    id: "lint/rfc5280/aki-missing", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2.1.1",
    message: "a non-self-issued certificate must carry an authorityKeyIdentifier extension",
    appliesTo: function (cert) { return !!(cert.issuer && cert.subject) && !_sameName(cert.issuer, cert.subject); },
    check: function (cert, ctx) { return ctx.raw("authorityKeyIdentifier") ? null : true; },
  },
  {
    id: "lint/rfc5280/basic-constraints-not-critical", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2.1.9",
    message: "a CA certificate that validates certificate signatures must mark basicConstraints critical",
    appliesTo: function (cert, ctx) {
      var bc = ctx.decode("basicConstraints");
      if (!(bc && bc.value && bc.value.cA === true)) return false;
      var ku = ctx.decode("keyUsage");
      return !ku || !ku.value || ku.value.keyCertSign === true;
    },
    check: function (cert, ctx) { var e = ctx.raw("basicConstraints"); return (e && e.critical !== true) ? true : null; },
  },
  _criticalityRule("nameConstraints", "lint/rfc5280/name-constraints-not-critical", "error",
    "RFC 5280 4.2.1.10", "the nameConstraints extension must be marked critical"),
  {
    id: "lint/rfc5280/name-constraints-not-ca", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2.1.10",
    message: "the nameConstraints extension must appear only in a CA certificate",
    appliesTo: function (cert, ctx) { return !!ctx.raw("nameConstraints"); },
    check: function (cert, ctx) { var bc = ctx.decode("basicConstraints"); return (bc && bc.value && bc.value.cA === true) ? null : true; },
  },
  _criticalityRule("policyConstraints", "lint/rfc5280/policy-constraints-not-critical", "error",
    "RFC 5280 4.2.1.11", "the policyConstraints extension must be marked critical"),
  _criticalityRule("inhibitAnyPolicy", "lint/rfc5280/inhibit-any-policy-not-critical", "error",
    "RFC 5280 4.2.1.14", "the inhibitAnyPolicy extension must be marked critical"),
  _criticalityRule("keyUsage", "lint/rfc5280/key-usage-not-critical", "warn",
    "RFC 5280 4.2.1.3", "the keyUsage extension should be marked critical"),
  {
    id: "lint/rfc5280/recommended-criticality", severity: "warn", source: "rfc5280", citation: "RFC 5280 4.2.1.7 / 4.2.1.13",
    message: "an extension a conforming CA should mark non-critical is marked critical",
    check: function (cert) {
      var rows = [];
      (cert.extensions || []).forEach(function (e) {
        var row = CERT_RECOMMENDED_NON_CRITICAL[e.oid];
        if (row === undefined || e.critical !== true) return;
        rows.push({ context: { extension: e.name || e.oid, oid: e.oid, recommended: "non-critical", was: "critical", citation: row } });
      });
      return rows.length ? rows : null;
    },
  },
  {
    id: "lint/rfc5280/policy-mapping-any-policy", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2.1.5",
    message: "a policy mapping names anyPolicy as its issuer or subject domain policy, which a mapping must not do",
    appliesTo: function (cert, ctx) { return !!ctx.raw("policyMappings"); },
    check: function (cert, ctx) {
      var d = ctx.decode("policyMappings");
      if (!d || !Array.isArray(d.value)) return null;
      var bad = d.value.filter(function (m) { return m.issuerDomainPolicy === OID_ANY_POLICY || m.subjectDomainPolicy === OID_ANY_POLICY; });
      return bad.length ? { context: { count: bad.length } } : null;
    },
  },
  {
    id: "lint/rfc5280/unique-identifier-present", severity: "error", source: "rfc5280", citation: "RFC 5280 4.1.2.8",
    message: "the certificate carries a unique identifier, which a conforming CA must not generate",
    check: function (cert) {
      var which = [];
      if (cert.issuerUniqueID) which.push("issuerUniqueID");
      if (cert.subjectUniqueID) which.push("subjectUniqueID");
      return which.length ? { context: { fields: which } } : null;
    },
  },
  {
    id: "lint/rfc5280/san-critical-with-subject", severity: "warn", source: "rfc5280", citation: "RFC 5280 4.2.1.6",
    message: "a subjectAltName beside a non-empty subject should be marked non-critical",
    appliesTo: function (cert, ctx) { return !!ctx.raw("subjectAltName"); },
    check: function (cert, ctx) {
      var e = ctx.raw("subjectAltName");
      return (e.critical === true && cert.subject.rdns.length > 0) ? true : null;
    },
  },
  {
    id: "lint/rfc5280/eku-critical-with-any-purpose", severity: "warn", source: "rfc5280", citation: "RFC 5280 4.2.1.12",
    message: "an extKeyUsage that names anyExtendedKeyUsage should not be marked critical",
    appliesTo: function (cert, ctx) { return !!ctx.raw("extKeyUsage"); },
    check: function (cert, ctx) {
      var e = ctx.raw("extKeyUsage");
      return (e.critical === true && _hasEku(cert, "anyExtendedKeyUsage")) ? true : null;
    },
  },
  {
    id: "lint/rfc5280/notice-ref-used", severity: "warn", source: "rfc5280", citation: "RFC 5280 4.2.1.4",
    message: "a userNotice policy qualifier carries a noticeRef, which should not be used",
    appliesTo: _hasPolicyDisplayText,
    check: function (cert, ctx) {
      var refs = _policyDisplayTexts(ctx).filter(function (d) { return d.field === "organization"; });
      return refs.length ? { context: { count: refs.length } } : null;
    },
  },
  {
    id: "lint/rfc5280/ski-missing-ee", severity: "warn", source: "rfc5280", citation: "RFC 5280 4.2.1.2",
    message: "an end-entity certificate should carry a subjectKeyIdentifier extension",
    appliesTo: function (cert, ctx) { var bc = ctx.decode("basicConstraints"); return !(bc && bc.value && bc.value.cA === true); },
    check: function (cert, ctx) { return ctx.raw("subjectKeyIdentifier") ? null : true; },
  },
  {
    id: "lint/rfc5280/explicit-text-too-long", severity: "warn", source: "rfc5280", citation: "RFC 5280 4.2.1.4",
    message: "a userNotice DisplayText should not exceed 200 characters",
    appliesTo: _hasPolicyDisplayText,
    check: function (cert, ctx) {
      var over = _policyDisplayTexts(ctx).filter(function (d) { return d.text !== null && d.chars > pkix.DISPLAY_TEXT_MAX; });
      return over.length ? { context: { count: over.length, longest: Math.max.apply(null, over.map(function (d) { return d.chars; })) } } : null;
    },
  },
  {
    id: "lint/rfc5280/explicit-text-empty", severity: "warn", source: "rfc5280", citation: "RFC 5280 4.2.1.4",
    message: "a userNotice DisplayText must not be empty (SIZE (1..200))",
    appliesTo: _hasPolicyDisplayText,
    check: function (cert, ctx) {
      var empty = _policyDisplayTexts(ctx).filter(function (d) { return d.text !== null && d.chars < 1; });
      return empty.length ? { context: { count: empty.length } } : null;
    },
  },
  {
    id: "lint/rfc5280/explicit-text-bad-encoding", severity: "error", source: "rfc5280", citation: "RFC 5280 4.2.1.4",
    message: "conforming CAs must not encode explicitText as VisibleString or BMPString",
    appliesTo: _hasPolicyDisplayText,
    check: function (cert, ctx) {
      var bad = _policyDisplayTexts(ctx).filter(function (d) { return d.field === "explicitText" && (d.tagNumber === _T_VISIBLE || d.tagNumber === _T_BMP); });
      return bad.length ? { context: { count: bad.length, encoding: bad[0].tagNumber === _T_BMP ? "BMPString" : "VisibleString" } } : null;
    },
  },
  {
    id: "lint/rfc5280/explicit-text-control-chars", severity: "warn", source: "rfc5280", citation: "RFC 5280 4.2.1.4",
    message: "an explicitText should not include control characters (U+0000 to U+001F, U+007F to U+009F)",
    appliesTo: _hasPolicyDisplayText,
    check: function (cert, ctx) {
      var bad = _policyDisplayTexts(ctx).filter(function (d) { return d.field === "explicitText" && d.text !== null && _hasControlChar(d.text); });
      return bad.length ? { context: { count: bad.length } } : null;
    },
  },
  {
    id: "lint/rfc5280/explicit-text-not-nfc", severity: "notice", source: "rfc5280", citation: "RFC 5280 4.2.1.4",
    message: "a UTF8String explicitText should be normalized to Unicode normalization form C (NFC)",
    appliesTo: _hasPolicyDisplayText,
    check: function (cert, ctx) {
      var bad = _policyDisplayTexts(ctx).filter(function (d) {
        return d.field === "explicitText" && d.text !== null && d.tagNumber === _T_UTF8 && d.text.normalize("NFC") !== d.text;
      });
      return bad.length ? { context: { count: bad.length } } : null;
    },
  },
];

function _isTls(cert, ctx) { return ctx.isTlsServerCert; }

var VALIDITY_SCHEDULE = [
  { from: new Date("2029-03-15T00:00:00Z"), maxDays: 47 },
  { from: new Date("2027-03-15T00:00:00Z"), maxDays: 100 },
  { from: new Date("2026-03-15T00:00:00Z"), maxDays: 200 },
  { from: new Date("2020-09-01T00:00:00Z"), maxDays: 398 },
];
var VALIDITY_SCHEDULE_START = VALIDITY_SCHEDULE[VALIDITY_SCHEDULE.length - 1].from;
function _validityCeilingDays(notBefore) {
  for (var i = 0; i < VALIDITY_SCHEDULE.length; i++) {
    // allow:nan-date-comparison-unguarded -- notBefore is a codec-parsed cert date (NaN-rejected); the schedule bounds are Date literals.
    if (guard.time.instantOf(notBefore) >= guard.time.instantOf(VALIDITY_SCHEDULE[i].from)) return VALIDITY_SCHEDULE[i].maxDays;
  }
  return VALIDITY_SCHEDULE[VALIDITY_SCHEDULE.length - 1].maxDays;
}

/** @internal All FOUR reserved policy identifiers of BR sec. 7.1.6.1, one per Subscriber
 *  Certificate type named in sec. 7.1.2.7.1: Domain, Organization and Individual Validated under
 *  the baseline-requirements arc, and Extended Validation under ev-guidelines. Sec. 7.1.2.7.9:
 *  "the Certificate Policies extension MUST contain exactly one Reserved Certificate Policy
 *  Identifier", so a list short of one type reports every certificate of that type as asserting
 *  none. */
var CABF_RESERVED_POLICIES = ["domain-validated", "organization-validated", "individual-validated",
  "ev-guidelines"]
  .map(function (n) { return oid.byName(n); }).filter(function (d) { return !!d; });

/** @internal BR sec. 7.1.2.7.10. Each is MUST NOT for a Subscriber Certificate. */
var CABF_FORBIDDEN_EKU = ["codeSigning", "emailProtection", "timeStamping", "ocspSigning",
  "anyExtendedKeyUsage", "precertificateSigningCert"]
  .map(function (n) { var d = oid.byName(n); return d ? { name: n, oid: d } : null; })
  .filter(function (e) { return !!e; });

/** @internal BR sec. 7.1.2.7.7. Only these two accessMethods are permitted; any other MUST NOT. */
var CABF_AIA_METHODS = ["ocsp", "caIssuers"].map(function (n) { return oid.byName(n); });

/** @internal BR sec. 7.1.2.7.11, the two Key Usage tables. A bit marked "Permitted: N" for the
 *  certificate's key type may not be set. The tables differ by key type, which is the point: the
 *  same bit is permitted for one and forbidden for the other. */
var CABF_KU_FORBIDDEN_RSA = ["nonRepudiation", "keyAgreement", "keyCertSign", "cRLSign",
  "encipherOnly", "decipherOnly"];
var CABF_KU_FORBIDDEN_ECC = ["nonRepudiation", "keyEncipherment", "dataEncipherment",
  "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];
var CABF_KU_RSA_BITS = ["digitalSignature", "keyEncipherment", "dataEncipherment"];

/** @internal BR sec. 7.1.2.7.12: only dNSName and iPAddress are permitted in a Subscriber
 *  Certificate's subjectAltName. The GeneralName context tag numbers are RFC 5280 sec. 4.2.1.6's. */
var CABF_SAN_PERMITTED_TAGS = [2, 7];
var CABF_SAN_TAG_NAMES = Object.assign(Object.create(null), {
  0: "otherName", 1: "rfc822Name", 2: "dNSName", 3: "x400Address", 4: "directoryName",
  5: "ediPartyName", 6: "uniformResourceIdentifier", 7: "iPAddress", 8: "registeredID",
});

/** @internal Which of the two Key Usage tables sec. 7.1.2.7.11 gives applies to this certificate,
 *  or null where neither does. The section opens "The acceptable Key Usage values vary based on
 *  whether the Certificate's subjectPublicKeyInfo identifies an RSA public key or an ECC public
 *  key", and gives a table for each and none for anything else. A key outside the two, such as an
 *  ML-DSA one, therefore has no table to be held to, and treating everything that is not ECC as
 *  RSA would report it against requirements written for a different algorithm. */
function _cabfKeyUsageTable(cert) {
  var spki = cert.subjectPublicKeyInfo;
  var name = spki && spki.algorithm && spki.algorithm.name;
  if (name === "ecPublicKey") return "ecc";
  if (RSA_KEY_ALGS[name]) return "rsa";
  return null;
}
function _isEccKey(cert) { return _cabfKeyUsageTable(cert) === "ecc"; }
function _subjectIsEmpty(cert) {
  var rdns = cert.subject && cert.subject.rdns;
  return !(Array.isArray(rdns) && rdns.length);
}

/** @internal Every policy qualifier of every PolicyInformation, as its qualifier OID. */
function _policyQualifierIds(ctx) {
  var out = [];
  _eachPolicyQualifier(ctx, function (qid) { out.push(qid); });
  return out;
}

/** @internal The S/MIME BR sec. 7.1.6.1 reserved policy identifiers, keyed by OID to the
 *  generation that OID declares. A subscriber certificate asserts exactly one, so reading it is
 *  how this profile learns which generation's table to hold the certificate to, and the presence
 *  of one is also what says the certificate is one of these at all. */
var SMIME_GENERATION_BY_POLICY = Object.create(null);
/** @internal The same twelve identifiers keyed to the certificate TYPE they declare. The tables of
 *  sec. 7.1.2.3 (l) are keyed on the type where the rest of the section is keyed on the
 *  generation, so both directions of the matrix are read. */
var SMIME_TYPE_BY_POLICY = Object.create(null);
["mailbox", "organization", "sponsor", "individual"].forEach(function (type) {
  ["legacy", "multipurpose", "strict"].forEach(function (gen) {
    var d = oid.byName("smime-" + type + "-" + gen);
    if (d) { SMIME_GENERATION_BY_POLICY[d] = gen; SMIME_TYPE_BY_POLICY[d] = type; }
  });
});

/** @internal The keyUsage tables of sec. 7.1.2.3 (e). Each cell states its usage MODES (signing
 *  only, key management only, dual use), and each mode fixes bits with SHALL and admits others
 *  with MAY, so a conforming certificate asserts every bit of some one mode and no bit outside
 *  that same mode. Flattening a cell into one permitted set loses that: on RSA, digitalSignature
 *  with dataEncipherment sets only bits the cell names somewhere and still matches no mode,
 *  because dataEncipherment belongs to the key-management modes and those require keyEncipherment.
 *  The RSA cell is the one that also differs by GENERATION, Multipurpose and Legacy admitting
 *  dataEncipherment where Strict does not. The elliptic-curve cell names encipherOnly and
 *  decipherOnly only in the modes that require keyAgreement, which is how it states "only if
 *  keyAgreement is set". A certificate declaring no generation is held to the Strict cell, the
 *  narrowest of the three. */
function _smimeKuModes(kind, gen) {
  var relaxed = gen === "multipurpose" || gen === "legacy";
  if (kind === "rsa") {
    return [
      { required: ["digitalSignature"], optional: ["nonRepudiation"] },
      { required: ["keyEncipherment"], optional: relaxed ? ["dataEncipherment"] : [] },
      { required: ["digitalSignature", "keyEncipherment"],
        optional: relaxed ? ["nonRepudiation", "dataEncipherment"] : ["nonRepudiation"] },
    ];
  }
  if (kind === "ec") {
    return [
      { required: ["digitalSignature"], optional: ["nonRepudiation"] },
      { required: ["keyAgreement"], optional: ["encipherOnly", "decipherOnly"] },
      { required: ["digitalSignature", "keyAgreement"],
        optional: ["nonRepudiation", "encipherOnly", "decipherOnly"] },
    ];
  }
  if (kind === "eddsa" || kind === "mldsa") {
    return [{ required: ["digitalSignature"], optional: ["nonRepudiation"] }];
  }
  if (kind === "mlkem") return [{ required: ["keyEncipherment"], optional: [] }];
  return null;
}
/** @internal Every bit any mode of the cell names, which is the complement of "Other bit positions
 *  SHALL NOT be set". */
function _smimeKuNamedAnywhere(modes) {
  var out = [];
  modes.forEach(function (m) {
    m.required.concat(m.optional).forEach(function (bit) {
      if (out.indexOf(bit) === -1) out.push(bit);
    });
  });
  return out;
}
function _smimeKuAsserted(value) {
  var out = [];
  KU_BIT_NAMES.forEach(function (bit) { if (value[bit] === true) out.push(bit); });
  return out;
}
/** @internal Whether the asserted bits are exactly some mode: every bit that mode requires, and no
 *  bit it does not name. */
function _smimeKuMatchesAMode(modes, asserted) {
  for (var i = 0; i < modes.length; i++) {
    var allowed = modes[i].required.concat(modes[i].optional);
    var ok = true;
    modes[i].required.forEach(function (bit) { if (asserted.indexOf(bit) === -1) ok = false; });
    asserted.forEach(function (bit) { if (allowed.indexOf(bit) === -1) ok = false; });
    if (ok) return true;
  }
  return false;
}

/** @internal Code Signing BR sec. 7.1.6.1 reserves three policy identifiers, keyed here to the KIND
 *  of certificate each declares. The EV and the non-EV code signing identifiers declare the same
 *  kind, because sec. 7.1.2.3 (f) asks one question of both; only the timestamping identifier takes
 *  the other arm. */
var CS_KIND_BY_POLICY = Object.create(null);
["code-signing", "code-signing-ev", "code-signing-timestamping"].forEach(function (name) {
  var dotted = oid.byName(name);
  if (dotted) CS_KIND_BY_POLICY[dotted] = name;
});
/** @internal "Effective September 15, 2026 a Certificate issued to a Subscriber MUST contain
 *  exactly one of the reserved policy OIDs specified in Section 7.1.6.1" (sec. 7.1.6.4). Dated, so
 *  a certificate issued before it is not held to a rule that did not yet apply. */
var CS_RESERVED_POLICY_REQUIRED = new Date("2026-09-15T00:00:00Z");
/** @internal Sec. 6.3.2 states three ceilings: 39 months for a code signing certificate issued
 *  before this date, 460 days for one issued on or after it, and 135 months for a timestamp
 *  certificate whichever side of it. */
var CS_VALIDITY_DAYS_START = new Date("2026-03-01T00:00:00Z");
/** @internal Sec. 6.1.5.2, the curves, the modulus floor and the two DSA parameter options for a
 *  subscriber key. The TLS profile names the same three curves from its own document; these are
 *  this one's. The section names RSA, ECDSA and DSA, so each family is read on its own terms and a
 *  family it does not name is what the row reports. */
var CS_EC_CURVES = ["prime256v1", "secp384r1", "secp521r1"];
var CS_RSA_MIN_BITS = 3072;
var CS_DSA_L = 2048;
var CS_DSA_N = [224, 256];
/** @internal The DSA key length L and modulus length N, read as the bit lengths of p and q in the
 *  Dss-Parms the AlgorithmIdentifier carries. */
function _dsaParamBits(spki) {
  try {
    var params = spki.algorithm && spki.algorithm.parameters;
    if (!Buffer.isBuffer(params)) return null;
    var seq = asn1.decode(params);
    if (!seq.children || seq.children.length !== 3) return null;
    var p = asn1.read.integer(seq.children[0]);
    var q = asn1.read.integer(seq.children[1]);
    asn1.read.integer(seq.children[2]);
    if (p <= 0n || q <= 0n) return null;
    return { L: p.toString(2).length, N: q.toString(2).length };
  } catch (_e) { return null; }
}
/** @internal Sec. 7.1.2.3 (c) names these two accessMethods and no other. */
var CS_AIA_METHODS = ["ocsp", "caIssuers"].map(function (n) { return oid.byName(n); });
/** @internal Sec. 7.1.2.3 (f): forbidden at every kind, and the three the clause names as MAY
 *  beside id-kp-codeSigning, which the discouraged-purpose row passes over. */
var CS_FORBIDDEN_EKU = ["anyExtendedKeyUsage", "serverAuth"].map(function (n) { return oid.byName(n); });
var CS_PERMITTED_EXTRA_EKU = ["ms-lifetime-signing", "emailProtection", "ms-document-signing",
  "ms-document-signing-as-printed"].map(function (n) { return oid.byName(n); });
/** @internal Sec. 7.1.2.3 (e) names these two as MUST NOT, and every other bit beside
 *  digitalSignature as SHOULD NOT, so one sentence becomes two rows at two strengths. */
var CS_FORBIDDEN_KU = ["keyCertSign", "cRLSign"];
/** @internal Sec. 7.1.4.2.4 (b): the field MUST contain one of these four strings, which the clause
 *  fixes exactly, so a differing case is a differing string. */
var CS_BUSINESS_CATEGORIES = ["Private Organization", "Government Entity", "Business Entity",
  "Non-Commercial Entity"];
/** @internal Sec. 7.1.4.2.4 (c) bounds the jurisdiction fields against the LEVEL the incorporating
 *  or registration agency operates at, which the certificate does not carry, so no row grades the
 *  relationship between them. The clause requires the state or province at the locality level only
 *  "where the state or province regulates the registration of the entities at the locality level",
 *  so a country with a locality and no state is conformant for such an agency and reporting it
 *  would fail a valid certificate. The country is required outright and has its own row. */

/** @internal Whether a subject attribute value carries nothing but the metadata sec. 7.1.4.2.2 (d)
 *  names, which is a full stop, a hyphen and a space. An empty value is the same statement that
 *  the value is absent, so it is read the same way. The clause also covers "any other indication
 *  that the value is absent, incomplete, or not applicable", which names no further characters, so
 *  the row reports the ones it does name. */
function _isMetadataOnlyValue(s) {
  if (typeof s !== "string") return false;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c !== 46 && c !== 45 && c !== 32) return false;
  }
  return true;
}
/** @internal Whether a value is the two-letter form sec. 7.1.4.2.3 (f) requires of a country code.
 *  The code's membership of ISO 3166-1 is not decided here, because the section names no list and
 *  the toolkit carries none; the builders hold their own country inputs to the same two-letter
 *  shape. */
function _isTwoLetterCountry(s) {
  if (typeof s !== "string" || s.length !== 2) return false;
  for (var i = 0; i < 2; i++) {
    var c = s.charCodeAt(i);
    if (c < 65 || c > 90) return false;
  }
  return true;
}

/** @internal Which reserved identifiers the certificate ASSERTS, as a set. Order in the extension
 *  carries no meaning, and a certificate asserting two of them claims both, so reading only the
 *  first would let the DER order decide which rules it answers for. Sec. 7.1.6.4 reports more than
 *  one, but only for a certificate issued on or after the date it states. */
function _csAsserted(ctx) {
  var out = Object.create(null);
  var d = ctx.decode("certificatePolicies");
  if (!d || !Array.isArray(d.value)) return out;
  for (var i = 0; i < d.value.length; i++) {
    var k = CS_KIND_BY_POLICY[d.value[i].policyIdentifier];
    if (k) out[k] = true;
  }
  return out;
}
/** @internal Sec. 7.1.6.3 gives a subordinate CA these identifiers too, so detection asks for the
 *  identifier AND that the certificate is not a CA, as the S/MIME profile does and for the same
 *  reason. Naming the profile overrides, which is how a malformed subscriber is checked. */
function _isCs(cert, ctx) {
  if (ctx.explicitCsProfile) return true;
  var a = _csAsserted(ctx);
  var any = a["code-signing"] === true || a["code-signing-ev"] === true ||
    a["code-signing-timestamping"] === true;
  return any && !ctx.isCaCert;
}
/** @internal A certificate declaring no kind is read as a code signing one, which is the arm the
 *  section states first and the only arm a caller who named the profile without a reserved
 *  identifier can have meant. */
function _isCsTimestamp(cert, ctx) {
  return _isCs(cert, ctx) && _csAsserted(ctx)["code-signing-timestamping"] === true;
}
/** @internal A certificate asserting a code signing identifier is one, and so is a certificate
 *  asserting none, which is the arm the section states first and the only arm a caller who named
 *  the profile without an identifier can have meant. A certificate asserting the timestamping
 *  identifier alone is not. */
function _isCsCodeSigning(cert, ctx) {
  if (!_isCs(cert, ctx)) return false;
  var a = _csAsserted(ctx);
  if (a["code-signing"] === true || a["code-signing-ev"] === true) return true;
  return a["code-signing-timestamping"] !== true;
}
/** @internal Sec. 7.1.4.2.4 covers EV code signing certificates alone, where sec. 7.1.4.2.3 covers
 *  non-EV ones and sec. 7.1.4.2.2 covers both. None of the three names a Timestamp Certificate, so
 *  the subject rows are scoped by the arm rather than by the profile. */
function _isCsEv(cert, ctx) { return _isCs(cert, ctx) && _csAsserted(ctx)["code-signing-ev"] === true; }
/** @internal The accessLocation URIs of the two accessMethods sec. 7.1.2.3 (c) names, flat: unlike
 *  the S/MIME clause this one states one rule for both, so they are not grouped by method. A
 *  location that is not a uniformResourceIdentifier is kept as null, since the method is still
 *  provided and still carries no HTTP URL. */
function _csAiaLocations(ctx) {
  var d = ctx.decode("authorityInfoAccess");
  if (!d || !Array.isArray(d.value)) return [];
  var out = [];
  for (var i = 0; i < d.value.length; i++) {
    var ad = d.value[i];
    if (CS_AIA_METHODS.indexOf(ad.accessMethod) === -1) continue;
    var loc = ad.accessLocation;
    out.push(loc && loc.tag === 6 && typeof loc.value === "string" ? loc.value : null);
  }
  return out;
}

/** @internal Sec. 7.1.2.3 (c) gives a URI scheme table for each of these two accessMethods and
 *  none for any other, so a scheme is measured on these and an unrecognized accessMethod has no
 *  table to be held to. */
var SMIME_AIA_METHODS = ["ocsp", "caIssuers"].map(function (n) { return oid.byName(n); });

/** @internal Sec. 7.1.2.3 (l): the Legal Entity Identifier table is keyed on the certificate type.
 *  The identifier is prohibited outright for two types; for Organization-validated the role
 *  identifier alone is prohibited, and Sponsor-validated admits both. */
var SMIME_LEI_EXTS = Object.assign(Object.create(null), { identifier: "lei-identifier", role: "lei-role" });
/** @internal Whether the cell for a certificate type ADMITS one of the two extensions. A cell that
 *  reads "Prohibited" carries no criticality sentence, so the criticality row is asked only where
 *  this is true and a prohibited extension breaks one clause rather than two. A certificate
 *  declaring no type names no cell and is held to neither row. */
function _smimeLeiAdmits(type, which) {
  if (type === "sponsor") return true;
  if (type === "organization") return which === "identifier";
  return false;
}

/** @internal Sec. 7.1.2.3 (m): both Adobe extensions the table names, prohibited under Strict. */
var SMIME_ADOBE_EXTS = ["adobe-timestamp", "adobe-archive-rev-info"];

/** @internal Sec. 7.1.2.3 (f): these four SHALL NOT be present at any generation, where any other
 *  purpose is forbidden under Strict alone. */
var SMIME_FORBIDDEN_EKU = ["serverAuth", "codeSigning", "timeStamping", "anyExtendedKeyUsage"]
  .map(function (n) { var d = oid.byName(n); return d ? { name: n, oid: d } : null; })
  .filter(function (e) { return !!e; });

/** @internal "Effective July 15, 2025 S/MIME Subscriber Certificates SHALL NOT be issued using the
 *  Legacy Generation profiles" (sec. 7.1.6.1). Dated, so a certificate issued before it is not
 *  held to a rule that did not yet apply. */
var SMIME_LEGACY_RETIRED = new Date("2025-07-15T00:00:00Z");

function _smimeGeneration(ctx) {
  var d = ctx.decode("certificatePolicies");
  if (!d || !Array.isArray(d.value)) return null;
  var found = null;
  d.value.forEach(function (pi) {
    var gen = SMIME_GENERATION_BY_POLICY[pi.policyIdentifier];
    if (gen && found === null) found = gen;
  });
  return found;
}
/** @internal A reserved policy identifier alone does not make a certificate a SUBSCRIBER one: sec.
 *  7.1.6.3 says a certificate issued to a Subordinate CA "SHALL include one or more explicit policy
 *  identifiers defined in Section 7.1.6.1", so an intermediate carries them too. Detection
 *  therefore asks for the identifier AND that the certificate is not a CA, or these subscriber-only
 *  rows would report an intermediate for asserting cA and keyCertSign and naming no mailbox.
 *  Naming the profile still overrides, which is how a malformed subscriber is checked. */
function _isSmime(cert, ctx) {
  if (ctx.explicitSmimeProfile) return true;
  return _smimeGeneration(ctx) !== null && !ctx.isCaCert;
}
function _smimeStrict(cert, ctx) { return _isSmime(cert, ctx) && _smimeGenerationOrStrict(ctx) === "strict"; }
/** @internal The cell every table in sec. 7.1.2.3 is read against. A certificate declaring no
 *  generation names no cell, and is held to Strict, the narrowest of the three. */
function _smimeGenerationOrStrict(ctx) {
  var gen = _smimeGeneration(ctx);
  return gen === null ? "strict" : gen;
}
/** @internal The certificate type the asserted reserved identifier declares, for the sec.
 *  7.1.2.3 (l) tables. Null where none is asserted, which is every certificate the caller named
 *  the profile for rather than one that declared itself. */
function _smimeType(ctx) {
  var d = ctx.decode("certificatePolicies");
  if (!d || !Array.isArray(d.value)) return null;
  var found = null;
  for (var i = 0; i < d.value.length; i++) {
    var t = SMIME_TYPE_BY_POLICY[d.value[i].policyIdentifier];
    if (t && found === null) found = t;
  }
  return found;
}

/** @internal Which sec. 7.1.2.3 (e) table applies, from the subject key's own algorithm. A key
 *  outside them has no table to be held to. */
function _smimeKeyKind(cert) {
  var spki = cert.subjectPublicKeyInfo;
  var name = spki && spki.algorithm && spki.algorithm.name;
  if (RSA_KEY_ALGS[name]) return "rsa";
  if (name === "ecPublicKey") return "ec";
  if (name === "Ed25519" || name === "Ed448") return "eddsa";
  if (typeof name === "string" && name.indexOf("ml-dsa") !== -1) return "mldsa";
  if (typeof name === "string" && name.indexOf("ml-kem") !== -1) return "mlkem";
  return null;
}

/** @internal The URI of a GeneralName carried as raw DER, or null where it is not one. The
 *  cRLDistributionPoints decoder surfaces each fullName entry as bytes, since a distribution point
 *  may name any GeneralName type and the reader does not choose one for the caller. */
function _generalNameUri(der) {
  var n;
  // allow:swallow-unverified an entry that does not decode is answered by the extension-syntax row
  try { n = asn1.decode(der); } catch (_e) { return null; }
  if (!n || n.tagClass !== "context" || n.tagNumber !== 6) return null;
  return n.content.toString("latin1");
}
/** @internal HTTP, not HTTPS. The S/MIME BR distinguishes the two by wording: the policy qualifier
 *  of sec. 7.1.2.3 (a) "SHALL be a HTTP or HTTPS URL", where the distribution point and access
 *  method tables say "SHALL have the URI scheme HTTP" and "Other schemes SHALL NOT be present".
 *  HTTPS is another scheme, and a revocation list fetched over TLS is a circular dependency.
 *  Having that scheme means being a URI of it, so both readings go through the one place that
 *  decides what an http or https URL is and differ only in which answer they accept. */
function _isHttpUri(u) {
  return pkiBuild.httpUrlScheme(u) === "http";
}
/** @internal The policy-qualifier clause of sec. 7.1.2.3 (a) names both schemes, where the URI
 *  scheme tables name HTTP alone. It also asks for a URL rather than a scheme, so a bare
 *  "http://" naming no host does not satisfy it. The shape is the one a reader holds a URL it was
 *  given to, not the narrower one the builders hold what they emit to. */
function _isHttpOrHttpsUrl(u) {
  return pkiBuild.httpUrlScheme(u) !== null;
}
/** @internal The accessLocation URIs of sec. 7.1.2.3 (c), grouped BY accessMethod. The clause
 *  gives id-ad-ocsp and id-ad-caIssuers a table each, where clause (b) gives the whole extension
 *  one, so each method's URIs answer that method's table alone and an accessMethod with no table
 *  is not measured. An accessLocation of another GeneralName type carries no URI to measure a
 *  scheme on. */
function _smimeAiaLocationsByMethod(ctx) {
  var d = ctx.decode("authorityInfoAccess");
  var out = Object.create(null);
  if (!d || !Array.isArray(d.value)) return out;
  for (var i = 0; i < d.value.length; i++) {
    var ad = d.value[i];
    if (SMIME_AIA_METHODS.indexOf(ad.accessMethod) === -1) continue;
    if (!out[ad.accessMethod]) out[ad.accessMethod] = [];
    /** @internal A location that is not a uniformResourceIdentifier carries no scheme, so it is
     * kept as null rather than dropped: the method is still provided and still has no HTTP URI. */
    var loc = ad.accessLocation;
    out[ad.accessMethod].push(loc && loc.tag === 6 && typeof loc.value === "string" ? loc.value : null);
  }
  return out;
}
function _crldpUris(ctx) {
  var d = ctx.decode("cRLDistributionPoints");
  if (!d || !Array.isArray(d.value)) return [];
  var out = [];
  d.value.forEach(function (dp) {
    var point = dp.distributionPoint;
    if (!point || point.kind !== "fullName" || !Array.isArray(point.names)) return;
    point.names.forEach(function (raw) {
      var u = _generalNameUri(raw);
      if (u !== null) out.push(u);
    });
  });
  return out;
}

var SMIME_OID_SMTP_UTF8 = oid.byName("smtpUtf8Mailbox");

/** @internal The nine named keyUsage bits of RFC 5280 sec. 4.2.1.3, in their bit order. */
var KU_BIT_NAMES = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
  "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"];

/** @internal The type OID of an otherName GeneralName. Every otherName is a [0], so the type is
 *  the only thing telling one apart from another, and a decoded entry carries it on `value` where
 *  the reader recognized the form and as bytes where it did not. */
function _otherNameTypeOf(gn) {
  if (gn && gn.value && typeof gn.value.typeId === "string") return gn.value.typeId;
  if (gn && gn.value && typeof gn.value.type === "string") return gn.value.type;
  var src = gn && (gn.bytes || gn.value);
  if (!Buffer.isBuffer(src)) return null;
  var n;
  // allow:swallow-unverified an entry that does not decode is answered by the extension-syntax row
  try { n = asn1.decode(src); } catch (_e) { return null; }
  if (!n || !n.children || !n.children.length) return null;
  // allow:swallow-unverified a first child that is not an OID is not an otherName type
  try { return asn1.read.oid(n.children[0]); } catch (_e2) { return null; }
}

var CABF_SMIME_RULES = [
  {
    id: "lint/cabf-smime/policies-critical", severity: "warn", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (a)",
    /** @internal SHOULD NOT, so a warning rather than an error: the clause states a preference and
     * the certificate is still conformant against the MUSTs around it. */
    message: "certificatePolicies should not be marked critical",
    appliesTo: _isSmime,
    check: function (cert, ctx) { var e = ctx.raw("certificatePolicies"); return (e && e.critical === true) ? true : null; },
  },
  {
    id: "lint/cabf-smime/policies-missing", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (a)",
    /** @internal Reachable only where the caller named the profile: without the extension there is
     * no reserved identifier, and the reserved identifier is what otherwise says the certificate
     * is one of these. Naming the profile is the caller supplying that statement. */
    message: "a subscriber certificate must carry a certificatePolicies extension",
    appliesTo: _isSmime,
    check: function (cert, ctx) { return ctx.raw("certificatePolicies") ? null : true; },
  },
  {
    id: "lint/cabf-smime/policies-reserved-identifier-count", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (a)",
    /** @internal "It SHALL include exactly one of the reserved policyIdentifiers", so two is as
     * much a fault as none and the count says which. A certificate's own generation is read from
     * that identifier, so two of them also leaves the generation ambiguous. */
    message: "certificatePolicies must include exactly one reserved policy identifier",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      /** @internal An absent extension is the presence row's answer, not this one's, so it is
       * skipped here and counted where it is present but names no reserved identifier. */
      if (!ctx.raw("certificatePolicies")) return null;
      var d = ctx.decode("certificatePolicies");
      var list = (d && Array.isArray(d.value)) ? d.value : [];
      var found = list.filter(function (pi) { return !!SMIME_GENERATION_BY_POLICY[pi.policyIdentifier]; });
      return found.length === 1 ? null : { context: { count: found.length } };
    },
  },
  {
    id: "lint/cabf-smime/legacy-generation-retired", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.6.1",
    message: "a subscriber certificate must not be issued under a Legacy generation profile",
    appliesTo: _isSmime,
    effectiveDate: SMIME_LEGACY_RETIRED,
    check: function (cert, ctx) {
      return _smimeGeneration(ctx) === "legacy" ? true : null;
    },
  },
  {
    id: "lint/cabf-smime/crldp-missing", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (b)",
    message: "a subscriber certificate must carry a cRLDistributionPoints extension",
    appliesTo: _isSmime,
    check: function (cert, ctx) { return ctx.raw("cRLDistributionPoints") ? null : true; },
  },
  {
    id: "lint/cabf-smime/crldp-non-http-uri", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (b)",
    /** @internal The scheme rule differs by generation: Strict and Multipurpose require EVERY
     * uniformResourceIdentifier to be HTTP, where Legacy requires at least one and permits others
     * beside it. One row measures both, because the generation decides which question to ask. */
    message: "a cRLDistributionPoints URI does not meet the URI scheme rule for this generation",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      /** @internal An extension carrying no URI at all fails both readings: every generation
       * requires an HTTP one, so an empty list is a violation rather than nothing to measure. The
       * presence row answers only for the extension being absent. */
      if (!ctx.raw("cRLDistributionPoints")) return null;
      var uris = _crldpUris(ctx);
      var gen = _smimeGeneration(ctx);
      if (gen === "legacy" || !uris.length) {
        return uris.some(_isHttpUri) ? null : { context: { generation: gen || "strict", uris: uris } };
      }
      var bad = uris.filter(function (u) { return !_isHttpUri(u); });
      return bad.length ? { context: { generation: gen, uris: bad } } : null;
    },
  },
  {
    id: "lint/cabf-smime/aia-critical", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (c)",
    message: "authorityInformationAccess must not be marked critical",
    appliesTo: _isSmime,
    check: function (cert, ctx) { var e = ctx.raw("authorityInfoAccess"); return (e && e.critical === true) ? true : null; },
  },
  {
    id: "lint/cabf-smime/basic-constraints-ca-true", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (d)",
    message: "a subscriber certificate's basicConstraints cA field must not be true",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var d = ctx.decode("basicConstraints");
      return (d && d.value && d.value.cA === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-smime/basic-constraints-path-len", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (d)",
    message: "a subscriber certificate's basicConstraints must not carry a pathLenConstraint",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var d = ctx.decode("basicConstraints");
      var pl = d && d.value ? d.value.pathLenConstraint : null;
      return pl === null || pl === undefined ? null : { context: { pathLenConstraint: pl } };
    },
  },
  {
    id: "lint/cabf-smime/key-usage-missing", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (e)",
    message: "a subscriber certificate must carry a keyUsage extension",
    appliesTo: _isSmime,
    check: function (cert, ctx) { return ctx.raw("keyUsage") ? null : true; },
  },
  {
    id: "lint/cabf-smime/key-usage-forbidden-bit", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (e)",
    /** @internal "Other bit positions SHALL NOT be set", over a table that differs by key
     * algorithm: keyEncipherment belongs to the RSA table and keyAgreement to the EC one, so the
     * same bit is conformant on one key and not on the other. A key algorithm the section gives no
     * table for is held to neither. "Other bit positions" reaches past the nine RFC 5280 names as
     * well, so a bit set beyond them is reported for every key algorithm. */
    message: "a keyUsage bit this key algorithm's table does not permit is set",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var d = ctx.decode("keyUsage");
      if (!d || !d.value) return null;
      var kind = _smimeKeyKind(cert);
      if (kind === null) return null;
      var modes = _smimeKuModes(kind, _smimeGeneration(ctx));
      if (modes === null) return null;
      var named = _smimeKuNamedAnywhere(modes);
      var out = [];
      KU_BIT_NAMES.forEach(function (bit) {
        if (d.value[bit] === true && named.indexOf(bit) === -1) {
          out.push({ context: { keyUsage: bit, keyAlgorithm: kind } });
        }
      });
      if (d.value.reservedBitsSet === true) {
        out.push({ context: { reservedBitSet: true, keyAlgorithm: kind } });
      }
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/key-usage-matches-no-mode", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (e)",
    /** @internal A cell is a set of modes rather than a set of bits, so bits that all appear
     * somewhere in the cell can still combine into no mode: digitalSignature with dataEncipherment
     * on RSA, or encipherOnly without keyAgreement on an elliptic curve. This row runs only where
     * every asserted bit is one the cell names, since a bit outside the cell is the row above. */
    message: "the keyUsage bits set match no usage mode of this key algorithm's table",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var d = ctx.decode("keyUsage");
      if (!d || !d.value || d.value.reservedBitsSet === true) return null;
      var kind = _smimeKeyKind(cert);
      if (kind === null) return null;
      var gen = _smimeGeneration(ctx);
      var modes = _smimeKuModes(kind, gen);
      if (modes === null) return null;
      var asserted = _smimeKuAsserted(d.value);
      var named = _smimeKuNamedAnywhere(modes);
      for (var i = 0; i < asserted.length; i++) {
        if (named.indexOf(asserted[i]) === -1) return null;
      }
      return _smimeKuMatchesAMode(modes, asserted)
        ? null
        : { context: { keyAlgorithm: kind, generation: gen || "strict", keyUsage: asserted } };
    },
  },
  {
    id: "lint/cabf-smime/eku-missing-email-protection", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (f)",
    message: "extKeyUsage must include id-kp-emailProtection",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return true;
      return d.value.indexOf(oid.byName("emailProtection")) === -1 ? true : null;
    },
  },
  {
    id: "lint/cabf-smime/eku-forbidden-purpose", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (f)",
    message: "a key purpose the profile forbids at every generation is present in extKeyUsage",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      var out = [];
      SMIME_FORBIDDEN_EKU.forEach(function (e) {
        if (d.value.indexOf(e.oid) !== -1) out.push({ context: { keyPurpose: e.name, oid: e.oid } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/eku-extra-purpose-strict", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (f)",
    /** @internal Strict alone says "Other values SHALL NOT be present"; Multipurpose and Legacy
     * say they MAY be. So this row is the one place the generation turns a permission into a
     * prohibition, and it runs only where the certificate declared Strict. The four values the
     * sentence after the table forbids at every generation are left to the row that owns them, so
     * one purpose draws one finding citing the narrower of the two rules it breaks. */
    message: "under the Strict generation, extKeyUsage must carry no purpose beyond id-kp-emailProtection",
    appliesTo: _smimeStrict,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      var email = oid.byName("emailProtection");
      var extra = d.value.filter(function (o) {
        if (o === email) return false;
        for (var i = 0; i < SMIME_FORBIDDEN_EKU.length; i++) {
          if (SMIME_FORBIDDEN_EKU[i].oid === o) return false;
        }
        return true;
      });
      return extra.length ? { context: { purposes: extra } } : null;
    },
  },
  {
    id: "lint/cabf-smime/aki-missing", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (g)",
    message: "a subscriber certificate must carry an authorityKeyIdentifier extension",
    appliesTo: _isSmime,
    check: function (cert, ctx) { return ctx.raw("authorityKeyIdentifier") ? null : true; },
  },
  {
    id: "lint/cabf-smime/aki-critical", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (g)",
    message: "authorityKeyIdentifier must not be marked critical",
    appliesTo: _isSmime,
    check: function (cert, ctx) { var e = ctx.raw("authorityKeyIdentifier"); return (e && e.critical === true) ? true : null; },
  },
  {
    id: "lint/cabf-smime/san-no-mailbox", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.4.2.1",
    /** @internal "SHALL contain at least one GeneralName entry of the following types: Rfc822Name
     * and/or otherName of type id-on-SmtpUTF8Mailbox". An otherName is read for its type OID,
     * since any otherName is a [0] and only that one carries a mailbox. */
    message: "subjectAltName must carry at least one rfc822Name or SmtpUTF8Mailbox otherName",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var d = ctx.decode("subjectAltName");
      if (!d || !d.value || !Array.isArray(d.value.names)) return true;
      var found = d.value.names.some(function (gn) {
        if (gn.tagNumber === 1) return true;
        if (gn.tagNumber !== 0) return false;
        return _otherNameTypeOf(gn) === SMIME_OID_SMTP_UTF8;
      });
      return found ? null : true;
    },
  },
  {
    id: "lint/cabf-smime/ski-critical", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (n)",
    message: "subjectKeyIdentifier must not be marked critical",
    appliesTo: _isSmime,
    check: function (cert, ctx) { var e = ctx.raw("subjectKeyIdentifier"); return (e && e.critical === true) ? true : null; },
  },
  {
    id: "lint/cabf-smime/smime-capabilities-critical", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (i)",
    message: "smimeCapabilities must not be marked critical",
    appliesTo: _isSmime,
    check: function (cert, ctx) { var e = ctx.raw("smimeCapabilities"); return (e && e.critical === true) ? true : null; },
  },
  {
    id: "lint/cabf-smime/subject-directory-attributes-prohibited", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (j)",
    /** @internal Prohibited under Strict and Multipurpose, permitted under Legacy. The generation
     * the certificate declares decides, so this runs at two of the three. */
    message: "subjectDirectoryAttributes is prohibited under the Strict and Multipurpose generations",
    appliesTo: function (cert, ctx) {
      return _isSmime(cert, ctx) && _smimeGenerationOrStrict(ctx) !== "legacy";
    },
    check: function (cert, ctx) { return ctx.raw("subjectDirectoryAttributes") ? true : null; },
  },
  {
    id: "lint/cabf-smime/subject-directory-attributes-critical", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (j)",
    /** @internal The criticality sentence sits in the Legacy row alone, which reads "MAY be present
     * and SHALL NOT be marked critical". The other row reads "Prohibited" and carries no
     * criticality sentence, so a critical extension there breaks one clause rather than two. */
    message: "subjectDirectoryAttributes must not be marked critical",
    appliesTo: function (cert, ctx) {
      return _isSmime(cert, ctx) && _smimeGenerationOrStrict(ctx) === "legacy";
    },
    check: function (cert, ctx) {
      var e = ctx.raw("subjectDirectoryAttributes");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-smime/policies-cps-not-http-url", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (a)",
    /** @internal "the value of the qualifier SHALL be a HTTP or HTTPS URL". This clause names both
     * schemes where the URI scheme tables of (b) and (c) name HTTP alone. */
    message: "an id-qt-cps policy qualifier must be a HTTP or HTTPS URL",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var out = [];
      _eachPolicyQualifier(ctx, function (qid, value, pi) {
        if (qid !== OID_CPS) return;
        var uri = null;
        // allow:swallow-unverified a CPSuri that will not read as a string is not a URL either, so it falls to the report below rather than out of the rule
        try {
          uri = asn1.read.string(value);
        } catch (_e) {
          void 0;
        }
        if (!_isHttpOrHttpsUrl(uri)) {
          out.push({ context: { policyIdentifier: pi.policyIdentifier, cps: uri } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/policies-unotice-no-explicit-text", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (a)",
    /** @internal "If a qualifier of type id-qt-unotice is included, then it SHALL contain
     * explicitText". Both halves of that sentence are rows, since a notice can fail either. */
    message: "an id-qt-unotice policy qualifier must contain explicitText",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var out = [];
      _eachPolicyQualifier(ctx, function (qid, value, pi) {
        if (qid !== OID_UNOTICE) return;
        var carries = pkix.userNoticeTexts(value).some(function (t) { return t.field === "explicitText"; });
        if (!carries) out.push({ context: { policyIdentifier: pi.policyIdentifier } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/policies-unotice-notice-ref", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (a)",
    /** @internal "...and SHALL NOT contain noticeRef." */
    message: "an id-qt-unotice policy qualifier must not contain a noticeRef",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var out = [];
      _eachPolicyQualifier(ctx, function (qid, value, pi) {
        if (qid !== OID_UNOTICE) return;
        /** @internal NoticeReference requires its organization DisplayText, which userNoticeTexts
         * surfaces under that field name, so the field's presence is the noticeRef's presence. */
        var carries = pkix.userNoticeTexts(value).some(function (t) { return t.field === "organization"; });
        if (carries) out.push({ context: { policyIdentifier: pi.policyIdentifier } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/crldp-critical", severity: "warn", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (b)",
    message: "cRLDistributionPoints should not be marked critical",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var e = ctx.raw("cRLDistributionPoints");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-smime/aia-missing", severity: "warn", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (c)",
    /** @internal "(SHOULD be present)", where the TLS profile's own heading for the same extension
     * reads SHALL, so the two profiles report it at different strengths. */
    message: "a subscriber certificate should carry an authorityInformationAccess extension",
    appliesTo: _isSmime,
    check: function (cert, ctx) { return ctx.raw("authorityInfoAccess") ? null : true; },
  },
  {
    id: "lint/cabf-smime/aia-ca-issuers-missing", severity: "warn", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (c)",
    /** @internal "SHOULD contain at least one accessMethod value of type id-ad-caIssuers". Read
     * only where the extension is there at all, since its absence is the row above. */
    message: "authorityInformationAccess should carry an id-ad-caIssuers accessMethod",
    appliesTo: function (cert, ctx) { return _isSmime(cert, ctx) && !!ctx.raw("authorityInfoAccess"); },
    check: function (cert, ctx) {
      var d = ctx.decode("authorityInfoAccess");
      if (!d || !Array.isArray(d.value)) return null;
      var wanted = oid.byName("caIssuers");
      for (var i = 0; i < d.value.length; i++) {
        if (d.value[i].accessMethod === wanted) return null;
      }
      return true;
    },
  },
  {
    id: "lint/cabf-smime/aia-non-http-uri", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (c)",
    /** @internal Strict and Multipurpose require every accessMethod URI to be HTTP, Legacy at
     * least one. Each accessMethod has its OWN table, so "at least one" is answered per method and
     * an HTTP URI on one does not satisfy the other's row. */
    message: "an authorityInformationAccess accessMethod URI does not meet the URI scheme rule for this generation",
    appliesTo: function (cert, ctx) { return _isSmime(cert, ctx) && !!ctx.raw("authorityInfoAccess"); },
    check: function (cert, ctx) {
      var byMethod = _smimeAiaLocationsByMethod(ctx);
      var gen = _smimeGeneration(ctx);
      var out = [];
      function report(method, offending) {
        out.push({ context: { generation: gen || "strict", accessMethod: oid.name(method) || method,
          uris: offending.filter(function (u) { return u !== null; }),
          nonUriLocations: offending.filter(function (u) { return u === null; }).length } });
      }
      SMIME_AIA_METHODS.forEach(function (method) {
        var locs = byMethod[method];
        if (!locs || !locs.length) return;
        if (gen === "legacy") {
          if (!locs.some(_isHttpUri)) report(method, locs);
          return;
        }
        var bad = locs.filter(function (u) { return !_isHttpUri(u); });
        if (bad.length) report(method, bad);
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/key-usage-not-critical", severity: "warn", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (e)",
    message: "keyUsage should be marked critical",
    appliesTo: function (cert, ctx) { return _isSmime(cert, ctx) && !!ctx.raw("keyUsage"); },
    check: function (cert, ctx) {
      var e = ctx.raw("keyUsage");
      return (e && e.critical === true) ? null : true;
    },
  },
  {
    id: "lint/cabf-smime/aki-key-identifier-missing", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (g)",
    /** @internal "The keyIdentifier field SHALL be present", which is a field rule rather than the
     * extension-presence one above it: an authorityKeyIdentifier naming only an issuer and serial
     * satisfies that row and not this one. */
    message: "the authorityKeyIdentifier keyIdentifier field must be present",
    appliesTo: function (cert, ctx) { return _isSmime(cert, ctx) && !!ctx.raw("authorityKeyIdentifier"); },
    check: function (cert, ctx) {
      var d = ctx.decode("authorityKeyIdentifier");
      if (!d || !d.value) return null;
      var kid = d.value.keyIdentifier;
      return (kid === null || kid === undefined) ? true : null;
    },
  },
  {
    id: "lint/cabf-smime/aki-issuer-or-serial-present", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (g)",
    /** @internal "authorityCertIssuer and authorityCertSerialNumber fields SHALL NOT be present."
     * Either one alone is a violation, so both are reported by name. */
    message: "the authorityKeyIdentifier must not carry authorityCertIssuer or authorityCertSerialNumber",
    appliesTo: function (cert, ctx) { return _isSmime(cert, ctx) && !!ctx.raw("authorityKeyIdentifier"); },
    check: function (cert, ctx) {
      var d = ctx.decode("authorityKeyIdentifier");
      if (!d || !d.value) return null;
      var out = [];
      ["authorityCertIssuer", "authorityCertSerialNumber"].forEach(function (f) {
        var v = d.value[f];
        if (v !== null && v !== undefined) out.push({ context: { field: f } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/san-missing", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (h)",
    message: "a subscriber certificate must carry a subjectAltName extension",
    appliesTo: _isSmime,
    check: function (cert, ctx) { return ctx.raw("subjectAltName") ? null : true; },
  },
  {
    id: "lint/cabf-smime/san-critical", severity: "warn", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (h)",
    /** @internal "SHOULD NOT be marked critical unless the subject field is an empty sequence",
     * which is the one condition that lifts it, so the subject is read rather than assumed. */
    message: "subjectAltName should not be marked critical where the subject is not an empty sequence",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var e = ctx.raw("subjectAltName");
      if (!e || e.critical !== true) return null;
      var rdns = cert.subject && cert.subject.rdns;
      var empty = !Array.isArray(rdns) || rdns.length === 0;
      return empty ? null : true;
    },
  },
  {
    id: "lint/cabf-smime/qc-statements-critical", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (k)",
    message: "qcStatements must not be marked critical",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var e = ctx.raw("qcStatements");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-smime/lei-prohibited", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (l)",
    /** @internal The table is keyed on the certificate TYPE: Mailbox-validated and
     * Individual-validated admit neither identifier, Organization-validated admits the LEI but not
     * the role, and Sponsor-validated admits both. A certificate declaring no type is held to
     * none, since the table has no row to select. */
    message: "a Legal Entity Identifier extension is prohibited for this certificate type",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var type = _smimeType(ctx);
      if (type === null) return null;
      var out = [];
      ["identifier", "role"].forEach(function (which) {
        if (_smimeLeiAdmits(type, which)) return;
        if (ctx.raw(SMIME_LEI_EXTS[which])) out.push({ context: { certificateType: type, extension: which } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/lei-critical", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (l)",
    /** @internal Where the table admits one it reads "MAY be present and SHALL NOT be marked
     * critical", so criticality is fixed in the cells that admit it and nowhere else. */
    message: "a Legal Entity Identifier extension must not be marked critical",
    appliesTo: _isSmime,
    check: function (cert, ctx) {
      var type = _smimeType(ctx);
      if (type === null) return null;
      var out = [];
      ["identifier", "role"].forEach(function (which) {
        if (!_smimeLeiAdmits(type, which)) return;
        var e = ctx.raw(SMIME_LEI_EXTS[which]);
        if (e && e.critical === true) out.push({ context: { certificateType: type, extension: which } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/adobe-extension-prohibited", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (m)",
    /** @internal Prohibited under Strict, permitted under Multipurpose and Legacy. */
    message: "an Adobe extension is prohibited under the Strict generation",
    appliesTo: function (cert, ctx) {
      return _isSmime(cert, ctx) && _smimeGenerationOrStrict(ctx) === "strict";
    },
    check: function (cert, ctx) {
      var out = [];
      SMIME_ADOBE_EXTS.forEach(function (name) {
        if (ctx.raw(name)) out.push({ context: { extension: name } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/adobe-extension-critical", severity: "error", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (m)",
    /** @internal The criticality sentence sits in the Multipurpose and Legacy row. The Strict row
     * reads "Prohibited" and carries none, so a critical extension there breaks one clause. */
    message: "an Adobe extension must not be marked critical",
    appliesTo: function (cert, ctx) {
      return _isSmime(cert, ctx) && _smimeGenerationOrStrict(ctx) !== "strict";
    },
    check: function (cert, ctx) {
      var out = [];
      SMIME_ADOBE_EXTS.forEach(function (name) {
        var e = ctx.raw(name);
        if (e && e.critical === true) out.push({ context: { extension: name } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-smime/ski-missing", severity: "warn", source: "cabf-smime", citation: "CABF S/MIME BR 7.1.2.3 (n)",
    /** @internal "(SHOULD be present)". The same clause adds that the value SHOULD be derived from
     * the public key, which names no derivation, so a certificate using one this cannot recompute
     * is conformant and no row reports it. */
    message: "a subscriber certificate should carry a subjectKeyIdentifier extension",
    appliesTo: _isSmime,
    check: function (cert, ctx) { return ctx.raw("subjectKeyIdentifier") ? null : true; },
  },
];

/** @internal Mozilla Root Store Policy v3.1 sec. 5.1.1 and 5.1.2 give the permitted
 *  AlgorithmIdentifier encodings as hex-encoded BYTES, so these are compared as DER rather than as
 *  a decoded triple: the point of the clause is the encoding, and two AlgorithmIdentifiers naming
 *  the same algorithm can differ in whether the parameters are an explicit NULL or absent. */
var MOZILLA_SPKI_ALGORITHMS = [
  "300d06092a864886f70d0101010500",
  "301306072a8648ce3d020106082a8648ce3d030107",
  "301006072a8648ce3d020106052b81040022",
  "301006072a8648ce3d020106052b81040023",
];
var MOZILLA_SIGNATURE_ALGORITHMS = [
  "300d06092a864886f70d0101050500",
  "300d06092a864886f70d01010b0500",
  "300d06092a864886f70d01010c0500",
  "300d06092a864886f70d01010d0500",
  "304106092a864886f70d01010a3034a00f300d060960864801650304020105" +
    "00a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120",
  "304106092a864886f70d01010a3034a00f300d060960864801650304020205" +
    "00a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130",
  "304106092a864886f70d01010a3034a00f300d060960864801650304020305" +
    "00a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140",
  "300a06082a8648ce3d040302",
  "300a06082a8648ce3d040303",
  "300a06082a8648ce3d040304",
];
/** @internal The RSASSA-PKCS1-v1_5 with SHA-1 encoding, which sec. 5.1.1 admits and sec. 5.1.3
 *  then restricts by date and by key purpose. */
var MOZILLA_SHA1_RSA = "300d06092a864886f70d0101050500";
var MOZILLA_SHA1_ECDSA = "300906072a8648ce3d0401";
var MOZILLA_SHA1_EMAIL_FROM = new Date("2022-07-01T00:00:00Z");
var MOZILLA_SHA1_OCSP_CA_FROM = new Date("2023-07-01T00:00:00Z");
/** @internal "Intermediate certificates created after January 1, 2019" (sec. 5.3). */
var MOZILLA_INTERMEDIATE_EKU_FROM = new Date("2019-01-01T00:00:00Z");
/** @internal "at least 64 bits of output from a CSPRNG" in the serial (sec. 5.2), of which the
 *  eight octets are what a certificate's bytes can answer for. */
var MOZILLA_SERIAL_MIN_OCTETS = 8;
var MOZILLA_RSA_MIN_BITS = 2048;

/** @internal The SubjectPublicKeyInfo's AlgorithmIdentifier as DER hex. The parsed record carries
 *  the decoded triple, and this clause is about the encoding, so the bytes are read back out. */
function _mozillaSpkiAlgorithmHex(cert) {
  try {
    var spki = cert.subjectPublicKeyInfo;
    if (!spki || !Buffer.isBuffer(spki.bytes)) return null;
    var node = asn1.decode(spki.bytes);
    if (!node.children || !node.children.length) return null;
    return node.children[0].bytes.toString("hex");
  } catch (_e) { return null; }
}
/** @internal The signature AlgorithmIdentifier as DER hex, read from the TBSCertificate. Only one
 *  of the two algorithm fields needs reading: schema-x509 refuses a certificate whose outer
 *  signatureAlgorithm differs byte-for-byte from tbsCertificate.signature, so by the time a rule
 *  sees one they cannot disagree. */
function _mozillaSignatureAlgorithmHex(cert) {
  // allow:swallow-unverified the ingest door has already produced a parsed certificate, so this reads bytes the parser accepted and a fault answers null
  try {
    var kids = asn1.decode(cert.tbsBytes).children;
    if (!kids || kids.length < 2) return null;
    var idx = (kids[0].tagClass === "context" && kids[0].tagNumber === 0) ? 2 : 1;
    return kids[idx] ? kids[idx].bytes.toString("hex") : null;
  } catch (_e) { return null; }
}
function _mozillaIsEdDsa(cert) {
  var spki = cert.subjectPublicKeyInfo;
  var name = spki && spki.algorithm && spki.algorithm.name;
  return name === "Ed25519" || name === "Ed448";
}
function _mozillaIsSha1Signature(cert) {
  var hex = _mozillaSignatureAlgorithmHex(cert);
  return hex === MOZILLA_SHA1_RSA || hex === MOZILLA_SHA1_ECDSA;
}
/** @internal The profile is NAMED, never detected. Every other profile here is selected by
 *  something the certificate declares; a root program's policy applies because the certificate
 *  chains to a root in that store, which the certificate does not state and a single-certificate
 *  lint cannot know. */
function _isMozilla(cert, ctx) { return ctx.profile === "mozilla-root"; }
/** @internal An INTERMEDIATE, which is what sec. 5.3 governs. Being an intermediate is a role in a
 *  hierarchy and a certificate does not state it, so this reads the one thing the bytes give: a
 *  certificate issued in its own name is passed over. That is every root, which the clause does not
 *  govern, and it is also a self-issued rollover intermediate, which the clause DOES govern, so the
 *  rows under-report rather than reporting a root for carrying no extended key usage. The
 *  cross-certificate the clause exempts need not carry matching names, which is why each message
 *  names that exemption for the operator to apply. */
function _isMozillaIntermediate(cert, ctx) {
  return _isMozilla(cert, ctx) && ctx.isCaCert && !_sameName(cert.issuer, cert.subject);
}
function _isMozillaEndEntity(cert, ctx) { return _isMozilla(cert, ctx) && !ctx.isCaCert; }

/** @internal The Mozilla Root Store Policy v3.1 profile. */
var MOZILLA_RULES = [
  {
    id: "lint/mozilla-root/spki-algorithm-encoding", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.1.1 and 5.1.2",
    /** @internal An EdDSA key is exempt here and answered by its own row: sec. 5.1 admits one in a
     * certificate carrying id-kp-emailProtection and gives no EdDSA encoding, so holding it to
     * this list would report every conforming certificate of that kind. */
    message: "the subjectPublicKeyInfo AlgorithmIdentifier is not one of the encodings this policy names",
    appliesTo: function (cert, ctx) { return _isMozilla(cert, ctx) && !_mozillaIsEdDsa(cert); },
    check: function (cert) {
      var hex = _mozillaSpkiAlgorithmHex(cert);
      return MOZILLA_SPKI_ALGORITHMS.indexOf(hex) === -1 ? { context: { algorithmIdentifier: hex } } : null;
    },
  },
  {
    id: "lint/mozilla-root/eddsa-without-email-protection", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.1",
    /** @internal "EdDSA keys MAY be included in certificates that chain to a root certificate in
     * our root store if the certificate contains id-kp-emailProtection in the EKU extension.
     * Otherwise, EdDSA keys MUST NOT be included." */
    message: "an EdDSA key needs id-kp-emailProtection in the extKeyUsage extension",
    appliesTo: function (cert, ctx) { return _isMozilla(cert, ctx) && _mozillaIsEdDsa(cert); },
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return true;
      return d.value.indexOf(oid.byName("emailProtection")) === -1 ? true : null;
    },
  },
  {
    id: "lint/mozilla-root/signature-algorithm-encoding", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.1.1 and 5.1.2",
    /** @internal Membership of the ten, and nothing more: sec. 5.1.2 binds a curve to a digest for
     * the SIGNING key, which is the issuer's and is not in this certificate. Matching
     * distinguished names would not prove the subject key made the signature, which is the
     * cross-certificate shape sec. 5.2 calls out.
     * An EdDSA signature is outside these clauses rather than in breach of them: sec. 5.1.1 and
     * sec. 5.1.2 fix the encodings for a signing RSA key and a signing ECDSA key, and sec. 5.1
     * admits an EdDSA key in a certificate carrying id-kp-emailProtection, which can be an
     * intermediate and sign with it. Reporting the certificates it signs would fail them for the
     * issuer's key. */
    message: "the signature AlgorithmIdentifier is not one of the encodings this policy names",
    appliesTo: function (cert, ctx) {
      var name = cert.signatureAlgorithm && cert.signatureAlgorithm.name;
      return _isMozilla(cert, ctx) && name !== "Ed25519" && name !== "Ed448";
    },
    check: function (cert) {
      var hex = _mozillaSignatureAlgorithmHex(cert);
      return MOZILLA_SIGNATURE_ALGORITHMS.indexOf(hex) === -1 ? { context: { algorithmIdentifier: hex } } : null;
    },
  },
  {
    id: "lint/mozilla-root/rsa-modulus-invalid", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.1",
    /** @internal "RSA keys whose modulus size in bits is divisible by 8, and is at least 2048
     * bits". The AlgorithmIdentifier row above cannot answer for this, since the modulus lives in
     * the subjectPublicKey rather than in the algorithm field. */
    message: "an RSA modulus must be at least 2048 bits and a whole number of octets",
    appliesTo: function (cert, ctx) {
      var spki = cert.subjectPublicKeyInfo;
      return _isMozilla(cert, ctx) && !!(spki && spki.algorithm && RSA_KEY_ALGS[spki.algorithm.name]);
    },
    check: function (cert) {
      var bits = _rsaModulusBits(cert.subjectPublicKeyInfo);
      if (bits === null) return { context: { rsaBits: null } };
      return (bits < MOZILLA_RSA_MIN_BITS || bits % 8 !== 0) ? { context: { rsaBits: bits } } : null;
    },
  },
  {
    id: "lint/mozilla-root/rsa-exponent-one", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.2",
    /** @internal "invalid public keys (e.g., RSA certificates with public exponent equal to 1)",
     * the one example the clause gives and the one a certificate's bytes settle. */
    message: "an RSA public exponent of 1 is not a usable key",
    appliesTo: function (cert, ctx) {
      var spki = cert.subjectPublicKeyInfo;
      return _isMozilla(cert, ctx) && !!(spki && spki.algorithm && RSA_KEY_ALGS[spki.algorithm.name]);
    },
    check: function (cert) {
      var e = _rsaExponent(cert.subjectPublicKeyInfo);
      return e !== null && e <= 1n ? { context: { exponent: e.toString() } } : null;
    },
  },
  {
    id: "lint/mozilla-root/serial-number-not-positive", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.2",
    /** @internal "all new certificates MUST have a serial number greater than zero", the half of
     * the sentence a certificate's bytes settle outright. */
    message: "a serial number must be greater than zero",
    appliesTo: _isMozilla,
    check: function (cert) {
      if (typeof cert.serialNumber !== "bigint") return null;
      return cert.serialNumber > 0n ? null : { context: { serialNumber: cert.serialNumber.toString() } };
    },
  },
  {
    id: "lint/mozilla-root/serial-number-short", severity: "warn", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.2",
    /** @internal "containing at least 64 bits of output from a CSPRNG" constrains the DRAW, and a
     * DER INTEGER does not carry the leading zero octets a draw can produce: eight random octets
     * whose first is zero encode to seven of magnitude, which happens to a conforming certificate
     * about once in 256. So the magnitude is evidence rather than a verdict and the row is graded
     * below the sentence's other half, which is its own row above. */
    message: "a serial number carries fewer than eight octets of magnitude, which 64 bits of CSPRNG output rarely produces",
    appliesTo: _isMozilla,
    check: function (cert) {
      var octets = _serialOctets(cert);
      return octets < MOZILLA_SERIAL_MIN_OCTETS ? { context: { octets: octets } } : null;
    },
  },
  {
    id: "lint/mozilla-root/end-entity-eku-missing", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.2",
    message: "an end entity certificate must carry an extKeyUsage extension",
    appliesTo: _isMozillaEndEntity,
    check: function (cert, ctx) { return ctx.raw("extKeyUsage") ? null : true; },
  },
  {
    id: "lint/mozilla-root/end-entity-eku-any", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.2",
    message: "an end entity certificate's extKeyUsage must not name anyExtendedKeyUsage",
    appliesTo: _isMozillaEndEntity,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      return d.value.indexOf(oid.byName("anyExtendedKeyUsage")) !== -1 ? true : null;
    },
  },
  {
    id: "lint/mozilla-root/sha1-email-protection", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.1.3",
    /** @internal "Effective July 1, 2022, CAs SHALL NOT sign SHA-1 hashes over end entity
     * certificates with an EKU extension containing the id-kp-emailProtection key purpose." */
    message: "a SHA-1 signature over an end entity certificate carrying id-kp-emailProtection",
    appliesTo: _isMozillaEndEntity,
    effectiveDate: MOZILLA_SHA1_EMAIL_FROM,
    check: function (cert, ctx) {
      if (!_mozillaIsSha1Signature(cert)) return null;
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      return d.value.indexOf(oid.byName("emailProtection")) !== -1 ? true : null;
    },
  },
  {
    id: "lint/mozilla-root/sha1-end-entity-outside-allowance", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.1.3",
    /** @internal SHA-1 over an end entity is permitted "only if all the following are true", and
     * the conditions this certificate answers for are that it "contains an EKU extension that does
     * not contain the id-kp-serverAuth, id-kp-emailProtection, or anyExtendedKeyUsage key
     * purposes". The remaining conditions name the issuing certificate and the BR scope, which are
     * not in these bytes. The id-kp-emailProtection arm has its own dated row, so this one passes
     * over it and a certificate draws one finding rather than two. */
    message: "a SHA-1 signature over an end entity certificate outside the allowance this clause gives",
    appliesTo: _isMozillaEndEntity,
    check: function (cert, ctx) {
      if (!_mozillaIsSha1Signature(cert)) return null;
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return { context: { reason: "no extKeyUsage extension" } };
      var out = [];
      ["serverAuth", "anyExtendedKeyUsage"].forEach(function (name) {
        if (d.value.indexOf(oid.byName(name)) !== -1) out.push({ context: { purpose: name } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/mozilla-root/sha1-ocsp-or-ca", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.1.3",
    /** @internal "Effective July 1, 2023, CAs SHALL NOT sign SHA-1 hashes over: certificates with
     * an EKU extension containing the id-kp-ocspSigning key purpose; intermediate certificates
     * that chain up to roots in Mozilla's program; OCSP responses; or CRLs." The two the
     * certificate answers for are the key purpose and being an INTERMEDIATE. The clause names
     * intermediate certificates rather than CA certificates, so a root's own self-signature is not
     * one of the four things it lists, and the intermediate reading is the one the sec. 5.3 rows
     * use with the limit it carries. */
    message: "a SHA-1 signature over an OCSP signing certificate or an intermediate certificate",
    appliesTo: _isMozilla,
    effectiveDate: MOZILLA_SHA1_OCSP_CA_FROM,
    check: function (cert, ctx) {
      if (!_mozillaIsSha1Signature(cert)) return null;
      if (_isMozillaIntermediate(cert, ctx)) return { context: { reason: "intermediate certificate" } };
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      return d.value.indexOf(oid.byName("ocspSigning")) !== -1
        ? { context: { reason: "id-kp-OCSPSigning" } } : null;
    },
  },
  {
    id: "lint/mozilla-root/intermediate-eku-missing", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.3",
    /** @internal The clause exempts "cross-certificates that share a private key with a
     * corresponding root certificate", which names a role in a hierarchy that a certificate does
     * not state, so the message carries the exemption for the operator to apply. */
    message: "an intermediate certificate must carry an extKeyUsage extension, unless it is a cross-certificate sharing a private key with a root",
    appliesTo: _isMozillaIntermediate,
    effectiveDate: MOZILLA_INTERMEDIATE_EKU_FROM,
    check: function (cert, ctx) { return ctx.raw("extKeyUsage") ? null : true; },
  },
  {
    id: "lint/mozilla-root/intermediate-eku-any", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.3",
    message: "an intermediate certificate's extKeyUsage must not name anyExtendedKeyUsage, unless it is a cross-certificate sharing a private key with a root",
    appliesTo: _isMozillaIntermediate,
    effectiveDate: MOZILLA_INTERMEDIATE_EKU_FROM,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      return d.value.indexOf(oid.byName("anyExtendedKeyUsage")) !== -1 ? true : null;
    },
  },
  {
    id: "lint/mozilla-root/intermediate-eku-server-and-email", severity: "error", source: "mozilla-root", citation: "Mozilla Root Store Policy 5.3",
    message: "an intermediate certificate must not name both id-kp-serverAuth and id-kp-emailProtection, unless it is a cross-certificate sharing a private key with a root",
    appliesTo: _isMozillaIntermediate,
    effectiveDate: MOZILLA_INTERMEDIATE_EKU_FROM,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      var server = d.value.indexOf(oid.byName("serverAuth")) !== -1;
      var email = d.value.indexOf(oid.byName("emailProtection")) !== -1;
      return (server && email) ? true : null;
    },
  },
];

/** @internal The three purposes ETSI EN 319 412-5 clause 4.2.3 names, of which a QcType declares
 *  "one and only one". The ASN.1 carries an extension marker, so an identifier outside the three
 *  is admitted and is not one of the purposes being counted. */
var QC_TYPE_PURPOSES = ["qctEsign", "qctEseal", "qctWeb"].map(function (n) { return oid.byName(n); });
/** @internal The identity type references EN 319 412-1 sec. 5.1.3 and 5.1.4 define, each three
 *  characters. A reference may instead be the locally defined form, two characters and a colon,
 *  which is three characters as well, so the two forms differ in which references are admitted and
 *  not in where the country code begins. The clause's own examples read "PASSK-P3000180" and
 *  "EI:SE-200007292386". */
var QC_NATURAL_TYPES = ["PAS", "IDC", "PNO", "TAX", "TIN"];
var QC_LEGAL_TYPES = ["VAT", "NTR", "PSD", "LEI"];
/** @internal "The value 'TAX' is deprecated. The value 'TIN' should be used instead."
 *  (NAT-5.1.3-04), a SHOULD, so the row that reports it is graded below the structural ones. */
var QC_DEPRECATED_NATURAL_TYPE = "TAX";
/** @internal "LEI ... The 2 character ISO 3166-1 country code shall be set to 'XG'"
 *  (LEG-5.1.4-03). */
var QC_LEI_COUNTRY = "XG";

/** @internal An identity type reference as EN 319 412-1 writes it, with the rest of the value, or
 *  null where the value takes neither form. The locally defined form is two characters and a
 *  colon; every defined reference is three characters. Both are followed by a two-character
 *  country code and a hyphen-minus. */
function _qcIdentityParts(value) {
  if (typeof value !== "string") return null;
  var localForm = value.length > 2 && value.charCodeAt(2) === 58;
  var ref = value.slice(0, 3);
  var rest = value.slice(3);
  if (rest.length < 3 || rest.charCodeAt(2) !== 45) return null;
  var country = rest.slice(0, 2);
  for (var i = 0; i < 2; i++) {
    var c = country.charCodeAt(i);
    if ((c < 65 || c > 90) && (c < 97 || c > 122)) return null;
  }
  if (rest.length <= 3) return null;
  return { reference: ref, local: localForm, country: country, identifier: rest.slice(3) };
}
/** @internal Whether an identity type reference is one the clause defines, in either form. */
function _qcKnownReference(parts, defined) {
  if (parts === null) return false;
  if (parts.local) return true;
  return defined.indexOf(parts.reference) !== -1;
}
/** @internal EVERY SemanticsInformation the certificate carries that names an identifier. RFC 3739
 *  sec. 3.2.6 puts no cardinality on QCStatements, so a certificate may carry more than one, and
 *  reading only the first would let their order in the extension suppress a rule. Both statement
 *  versions carry the same syntax. */
function _qcSemanticsAll(ctx) {
  var out = [];
  var d = ctx.decode("qcStatements");
  if (!d || !Array.isArray(d.value)) return out;
  var v1 = oid.byName("qcsPkixQCSyntaxV1"), v2 = oid.byName("qcsPkixQCSyntaxV2");
  for (var i = 0; i < d.value.length; i++) {
    var st = d.value[i];
    if (st.statementId !== v1 && st.statementId !== v2) continue;
    if (st.info && st.info.semanticsIdentifier) out.push(st.info);
  }
  return out;
}
/** @internal The decoded info of EVERY statement of one name, for the same reason. */
function _qcStatementInfos(ctx, name) {
  var out = [];
  var d = ctx.decode("qcStatements");
  if (!d || !Array.isArray(d.value)) return out;
  var dotted = oid.byName(name);
  for (var i = 0; i < d.value.length; i++) {
    if (d.value[i].statementId === dotted) out.push(d.value[i].info === null ? {} : d.value[i].info);
  }
  return out;
}
/** @internal The SemanticsInformation where it names one of the two identifiers EN 319 412-1
 *  defines, or null. The requirements of sec. 5.1.3 and 5.1.4 each sit under their own identifier,
 *  so a certificate naming a private one is held to neither. */
/** @internal Whether ANY qcsPkixQCSyntax statement names a given semantics identifier. */
function _qcNamesSemantics(ctx, name) {
  var dotted = oid.byName(name);
  return _qcSemanticsAll(ctx).some(function (info) { return info.semanticsIdentifier === dotted; });
}
function _qcEtsiSemanticsAll(ctx) {
  var nat = oid.byName("semanticsId-Natural"), leg = oid.byName("semanticsId-Legal");
  return _qcSemanticsAll(ctx).filter(function (info) {
    return info.semanticsIdentifier === nat || info.semanticsIdentifier === leg;
  });
}
/** @internal Whether a subject attribute names the locally defined identity type reference form,
 *  which is what conditions the name registration authority requirements. */
function _qcHasLocalReference(cert, attr) {
  var values = _subjectValuesOf(cert, attr);
  for (var i = 0; i < values.length; i++) {
    var parts = _qcIdentityParts(values[i]);
    if (parts !== null && parts.local) return true;
  }
  return false;
}
function _qcHasStatement(ctx, name) {
  var d = ctx.decode("qcStatements");
  if (!d || !Array.isArray(d.value)) return false;
  var dotted = oid.byName(name);
  for (var i = 0; i < d.value.length; i++) {
    if (d.value[i].statementId === dotted) return true;
  }
  return false;
}
/** @internal A certificate carrying the extension at all, which is what clause 4 governs. */
function _isQc(cert, ctx) { return !!ctx.raw("qcStatements"); }
/** @internal An EU qualified certificate, which is what clause 5 governs. Table 1A reads it off
 *  the bytes: QcCompliance says the certificate is qualified, and QcCClegislation names the
 *  country or countries whose framework it is qualified under, so with that statement present the
 *  certificate claims a framework other than the Regulation and clause 5 does not bind it. */
function _isEuQc(cert, ctx) {
  return _isQc(cert, ctx) && _qcHasStatement(ctx, "qcCompliance") &&
    !_qcHasStatement(ctx, "qcCClegislation");
}
/** @internal Whether the name registration authorities carry a uniformResourceIdentifier, which
 *  NAT-5.1.3-06 and LEG-5.1.4-05 both require of them. A decoded GeneralName names its form in
 *  `tagNumber`; the `tag` an accessDescription carries is that record rebuilt by its own decoder,
 *  and these are the plain form. */
function _qcHasUriAuthority(info) {
  var list = info && info.nameRegistrationAuthorities;
  if (!Array.isArray(list)) return false;
  for (var i = 0; i < list.length; i++) {
    if (list[i] && list[i].tagNumber === 6) return true;
  }
  return false;
}

/** @internal The ETSI qualified-certificate profile, from EN 319 412-5 V2.4.1 and the semantics
 *  identifiers of EN 319 412-1 V1.5.1. Clause 4 governs any certificate carrying the extension and
 *  clause 5 an EU qualified one, so the two scopes are separate predicates. */
var ETSI_QC_RULES = [
  {
    id: "lint/etsi-qc/qc-statements-critical", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-5 QCS-4.1-02",
    message: "the qcStatements extension must not be marked critical",
    appliesTo: _isQc,
    check: function (cert, ctx) {
      var e = ctx.raw("qcStatements");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-type-multiple-purposes", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-5 4.2.3",
    /** @internal "declares that a CERTIFICATE is issued as one and only one of the purposes of
     * electronic signature, electronic seal or web site authentication", so the limit is on the
     * certificate and the purposes are counted across every QcType statement it carries: two
     * statements naming one purpose each break the same rule as one naming two. The QcType ASN.1
     * carries an extension marker, so an identifier outside the three is admitted and is not one
     * of the purposes being counted. */
    message: "the certificate names more than one of the three purposes this clause defines",
    appliesTo: _isQc,
    check: function (cert, ctx) {
      var named = [];
      _qcStatementInfos(ctx, "qcType").forEach(function (info) {
        if (!Array.isArray(info.types)) return;
        info.types.forEach(function (d) {
          if (QC_TYPE_PURPOSES.indexOf(d) !== -1 && named.indexOf(d) === -1) named.push(d);
        });
      });
      return named.length > 1 ? { context: { purposes: named } } : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-pds-no-https-url", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-5 QCS-4.3.4-03",
    /** @internal "As a minimum, a URL to a PDS provided in this statement shall use the https
     * scheme", which is the at-least-one reading: reporting each URL that is not https would fail
     * a statement the clause admits. */
    message: "a QcPDS statement provides no https URL",
    appliesTo: function (cert, ctx) { return _isQc(cert, ctx) && _qcHasStatement(ctx, "qcPDS"); },
    check: function (cert, ctx) {
      var out = [];
      _qcStatementInfos(ctx, "qcPDS").forEach(function (info) {
        if (!Array.isArray(info.locations)) return;
        var https = info.locations.filter(function (l) {
          return pkiBuild.httpUrlScheme(l && l.url) === "https";
        });
        if (!https.length) out.push({ context: { locations: info.locations.length } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-pds-no-english", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-5 table 2",
    /** @internal "it shall provide at least one URL to a PDS in English", an additional
     * requirement Table 2 states on the QcPDS statement, so it binds an EU qualified certificate
     * and no other. The language is an ISO 639-1 code (QCS-4.3.4-01), where English is "en". */
    message: "an EU qualified certificate's QcPDS statement names no document in English",
    appliesTo: function (cert, ctx) { return _isEuQc(cert, ctx) && _qcHasStatement(ctx, "qcPDS"); },
    check: function (cert, ctx) {
      var out = [];
      _qcStatementInfos(ctx, "qcPDS").forEach(function (info) {
        if (!Array.isArray(info.locations)) return;
        var english = info.locations.filter(function (l) {
          return typeof l.language === "string" && l.language.toLowerCase() === "en";
        });
        if (!english.length) {
          out.push({ context: { languages: info.locations.map(function (l) { return l.language; }) } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-pds-duplicate-language", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-5 table 2",
    /** @internal "it shall not reference more than one PDS per language", the other additional
     * requirement Table 2 states on the same statement. */
    message: "an EU qualified certificate's QcPDS statement names more than one document in a language",
    appliesTo: function (cert, ctx) { return _isEuQc(cert, ctx) && _qcHasStatement(ctx, "qcPDS"); },
    check: function (cert, ctx) {
      var out = [];
      _qcStatementInfos(ctx, "qcPDS").forEach(function (info) {
        if (!Array.isArray(info.locations)) return;
        var seen = Object.create(null);
        info.locations.forEach(function (l) {
          if (typeof l.language !== "string") return;
          var key = l.language.toLowerCase();
          if (seen[key]) { out.push({ context: { language: l.language } }); return; }
          seen[key] = true;
        });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-natural-serial-number-structure", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-1 NAT-5.1.3-02 and NAT-5.1.3-03",
    /** @internal "When the natural person semantics identifier is included, any present
     * serialNumber attribute in the subject field shall contain information using the following
     * structure": a three character identity type reference, a two character country code, a
     * hyphen-minus, and an identifier. The reference is one the clause defines or the locally
     * defined form of two characters and a colon. */
    message: "a subject serialNumber does not take the structure the natural person semantics identifier requires",
    appliesTo: function (cert, ctx) {
      return _isQc(cert, ctx) && _qcNamesSemantics(ctx, "semanticsId-Natural") &&
        _subjectValuesOf(cert, "serialNumber").length > 0;
    },
    check: function (cert) {
      var out = [];
      _subjectValuesOf(cert, "serialNumber").forEach(function (v) {
        var parts = _qcIdentityParts(v);
        if (!_qcKnownReference(parts, QC_NATURAL_TYPES)) out.push({ context: { serialNumber: v } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-natural-identity-type-deprecated", severity: "warn", source: "etsi-qc", citation: "ETSI EN 319 412-1 NAT-5.1.3-04",
    message: "the TAX identity type reference is deprecated and TIN should be used instead",
    appliesTo: function (cert, ctx) {
      return _isQc(cert, ctx) && _qcNamesSemantics(ctx, "semanticsId-Natural");
    },
    check: function (cert) {
      var out = [];
      _subjectValuesOf(cert, "serialNumber").forEach(function (v) {
        var parts = _qcIdentityParts(v);
        if (parts && !parts.local && parts.reference === QC_DEPRECATED_NATURAL_TYPE) {
          out.push({ context: { serialNumber: v } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-legal-organization-identifier-structure", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-1 LEG-5.1.4-02 and LEG-5.1.4-03",
    message: "a subject organizationIdentifier does not take the structure the legal person semantics identifier requires",
    appliesTo: function (cert, ctx) {
      return _isQc(cert, ctx) && _qcNamesSemantics(ctx, "semanticsId-Legal") &&
        _subjectValuesOf(cert, "organizationIdentifier").length > 0;
    },
    check: function (cert) {
      var out = [];
      _subjectValuesOf(cert, "organizationIdentifier").forEach(function (v) {
        var parts = _qcIdentityParts(v);
        if (!_qcKnownReference(parts, QC_LEGAL_TYPES)) out.push({ context: { organizationIdentifier: v } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-legal-lei-country-not-xg", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-1 LEG-5.1.4-03",
    /** @internal "LEI for a global Legal Entity Identifier as specified in ISO 17442. The 2
     * character ISO 3166-1 country code shall be set to 'XG'", the one reference whose country
     * code the clause fixes. */
    message: "an LEI organizationIdentifier must carry the country code XG",
    appliesTo: function (cert, ctx) {
      return _isQc(cert, ctx) && _qcNamesSemantics(ctx, "semanticsId-Legal");
    },
    check: function (cert) {
      var out = [];
      _subjectValuesOf(cert, "organizationIdentifier").forEach(function (v) {
        var parts = _qcIdentityParts(v);
        if (!parts || parts.local || parts.reference !== "LEI") return;
        if (parts.country !== QC_LEI_COUNTRY) out.push({ context: { country: parts.country } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-semantics-registration-authority-missing", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-1 NAT-5.1.3-05 and LEG-5.1.4-05",
    /** @internal "When a locally defined identity type reference is provided (two characters
     * followed by ':'), the nameRegistrationAuthorities element of SemanticsInformation shall be
     * present." The same sentence appears under each semantics identifier, so one row answers for
     * both and reads whichever attribute the identifier governs. */
    message: "a locally defined identity type reference requires a nameRegistrationAuthorities element",
    appliesTo: function (cert, ctx) { return _isQc(cert, ctx) && _qcEtsiSemanticsAll(ctx).length > 0; },
    check: function (cert, ctx) {
      var out = [];
      _qcEtsiSemanticsAll(ctx).forEach(function (info) {
        var attr = info.semanticsIdentifier === oid.byName("semanticsId-Legal")
          ? "organizationIdentifier" : "serialNumber";
        if (!_qcHasLocalReference(cert, attr)) return;
        var list = info.nameRegistrationAuthorities;
        if (!Array.isArray(list) || !list.length) out.push({ context: { attribute: attr } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/etsi-qc/qc-semantics-registration-authority-not-uri", severity: "error", source: "etsi-qc", citation: "ETSI EN 319 412-1 NAT-5.1.3-06 and LEG-5.1.4-05",
    /** @internal It "shall contain at least a uniformResourceIdentifier generalName", which is what
     * makes a locally defined reference resolvable. The two clauses state it differently and the
     * rows follow them: NAT-5.1.3-06 states it of the element itself, so it binds wherever a
     * natural person identifier carries one, where LEG-5.1.4-05 states it inside the sentence
     * about a locally defined reference and binds only there. Both sit under their own semantics
     * identifier, so a certificate naming a private one is held to neither. */
    message: "a nameRegistrationAuthorities element must carry a uniformResourceIdentifier",
    appliesTo: function (cert, ctx) { return _isQc(cert, ctx) && _qcEtsiSemanticsAll(ctx).length > 0; },
    check: function (cert, ctx) {
      var out = [];
      _qcEtsiSemanticsAll(ctx).forEach(function (info) {
        var list = info.nameRegistrationAuthorities;
        if (!Array.isArray(list) || !list.length) return;
        var natural = info.semanticsIdentifier === oid.byName("semanticsId-Natural");
        if (!natural && !_qcHasLocalReference(cert, "organizationIdentifier")) return;
        if (!_qcHasUriAuthority(info)) {
          out.push({ context: { semanticsIdentifier: oid.name(info.semanticsIdentifier) } });
        }
      });
      return out.length ? out : null;
    },
  },
];

/** @internal The CA/Browser Forum Code Signing BR v3.11.0 subscriber profile. Every severity is
 *  graded against the clause the row cites, never against the same-named row of another profile:
 *  this document says MUST where the S/MIME one says SHOULD for cRLDistributionPoints criticality,
 *  authorityInformationAccess presence and keyUsage criticality. */
var CABF_CS_RULES = [
  {
    id: "lint/cabf-cs/policies-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (a)",
    message: "a subscriber certificate must carry a certificatePolicies extension",
    appliesTo: _isCs,
    check: function (cert, ctx) { return ctx.raw("certificatePolicies") ? null : true; },
  },
  {
    id: "lint/cabf-cs/policies-critical", severity: "warn", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (a)",
    message: "certificatePolicies should not be marked critical",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var e = ctx.raw("certificatePolicies");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-cs/policies-reserved-identifier-count", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.6.4",
    /** @internal "a Certificate issued to a Subscriber MUST contain exactly one of the reserved
     * policy OIDs specified in Section 7.1.6.1", so both none and two are reported. */
    message: "a subscriber certificate must assert exactly one reserved code signing policy identifier",
    appliesTo: _isCs,
    effectiveDate: CS_RESERVED_POLICY_REQUIRED,
    check: function (cert, ctx) {
      var d = ctx.decode("certificatePolicies");
      if (!d || !Array.isArray(d.value)) return null;
      var found = d.value.filter(function (pi) { return !!CS_KIND_BY_POLICY[pi.policyIdentifier]; });
      return found.length === 1 ? null : { context: { count: found.length } };
    },
  },
  {
    id: "lint/cabf-cs/policies-cps-not-http-url", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (a)",
    /** @internal "HTTP URL for the Subordinate CA's Certification Practice Statement". This clause
     * names one scheme where the S/MIME clause for the same qualifier names two, so an HTTPS
     * qualifier is conformant there and reported here. */
    message: "an id-qt-cps policy qualifier must be a HTTP URL",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var out = [];
      _eachPolicyQualifier(ctx, function (qid, value, pi) {
        if (qid !== OID_CPS) return;
        var uri = null;
        // allow:swallow-unverified a CPSuri that will not read as a string is not a URL either, so it falls to the report below rather than out of the rule
        try {
          uri = asn1.read.string(value);
        } catch (_e) {
          void 0;
        }
        if (pkiBuild.httpUrlScheme(uri) !== "http") {
          out.push({ context: { policyIdentifier: pi.policyIdentifier, cps: uri } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-cs/crldp-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (b)",
    message: "a subscriber certificate must carry a cRLDistributionPoints extension",
    appliesTo: _isCs,
    check: function (cert, ctx) { return ctx.raw("cRLDistributionPoints") ? null : true; },
  },
  {
    id: "lint/cabf-cs/crldp-critical", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (b)",
    /** @internal "It MUST NOT be marked critical", where the S/MIME clause for the same extension
     * says SHOULD NOT, so the same certificate draws an error here and a warning there. */
    message: "cRLDistributionPoints must not be marked critical",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var e = ctx.raw("cRLDistributionPoints");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-cs/crldp-no-http-uri", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (b)",
    /** @internal "it MUST contain the HTTP URL of the CA's CRL service". One HTTP URL is required
     * and the clause forbids no other scheme beside it. */
    message: "cRLDistributionPoints must contain a HTTP URL",
    appliesTo: function (cert, ctx) { return _isCs(cert, ctx) && !!ctx.raw("cRLDistributionPoints"); },
    check: function (cert, ctx) {
      var uris = _crldpUris(ctx);
      return uris.some(_isHttpUri) ? null : { context: { uris: uris } };
    },
  },
  {
    id: "lint/cabf-cs/aia-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (c)",
    /** @internal "This extension MUST be present", where the S/MIME clause asks at SHOULD. */
    message: "a subscriber certificate must carry an authorityInformationAccess extension",
    appliesTo: _isCs,
    check: function (cert, ctx) { return ctx.raw("authorityInfoAccess") ? null : true; },
  },
  {
    id: "lint/cabf-cs/aia-critical", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (c)",
    message: "authorityInformationAccess must not be marked critical",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var e = ctx.raw("authorityInfoAccess");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-cs/aia-ca-issuers-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (c)",
    /** @internal "It MUST contain the HTTP URL of the Issuing CA's certificate", so the method is
     * required rather than recommended, unlike the S/MIME clause's SHOULD. */
    message: "authorityInformationAccess must carry an id-ad-caIssuers accessMethod",
    appliesTo: function (cert, ctx) { return _isCs(cert, ctx) && !!ctx.raw("authorityInfoAccess"); },
    check: function (cert, ctx) {
      var d = ctx.decode("authorityInfoAccess");
      if (!d || !Array.isArray(d.value)) return null;
      var wanted = oid.byName("caIssuers");
      for (var i = 0; i < d.value.length; i++) {
        if (d.value[i].accessMethod === wanted) return null;
      }
      return true;
    },
  },
  {
    id: "lint/cabf-cs/aia-non-http-uri", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (c)",
    /** @internal The clause states one rule for both accessMethods it names, so unlike the S/MIME
     * clause there is no table per method and every location is held to the same reading. */
    message: "an authorityInformationAccess accessLocation must be a HTTP URL",
    appliesTo: function (cert, ctx) { return _isCs(cert, ctx) && !!ctx.raw("authorityInfoAccess"); },
    check: function (cert, ctx) {
      var locs = _csAiaLocations(ctx);
      var bad = locs.filter(function (u) { return !_isHttpUri(u); });
      if (!bad.length) return null;
      return { context: { uris: bad.filter(function (u) { return u !== null; }),
        nonUriLocations: bad.filter(function (u) { return u === null; }).length } };
    },
  },
  {
    id: "lint/cabf-cs/basic-constraints-ca-true", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (d)",
    message: "a subscriber certificate's basicConstraints cA field must not be true",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var d = ctx.decode("basicConstraints");
      return (d && d.value && d.value.cA === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-cs/key-usage-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (e)",
    message: "a subscriber certificate must carry a keyUsage extension",
    appliesTo: _isCs,
    check: function (cert, ctx) { return ctx.raw("keyUsage") ? null : true; },
  },
  {
    id: "lint/cabf-cs/key-usage-not-critical", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (e)",
    /** @internal "MUST be marked critical", where the S/MIME clause says SHOULD. */
    message: "keyUsage must be marked critical",
    appliesTo: function (cert, ctx) { return _isCs(cert, ctx) && !!ctx.raw("keyUsage"); },
    check: function (cert, ctx) {
      var e = ctx.raw("keyUsage");
      return (e && e.critical === true) ? null : true;
    },
  },
  {
    id: "lint/cabf-cs/key-usage-missing-digital-signature", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (e)",
    message: "keyUsage must assert digitalSignature",
    appliesTo: function (cert, ctx) { return _isCs(cert, ctx) && !!ctx.raw("keyUsage"); },
    check: function (cert, ctx) {
      var d = ctx.decode("keyUsage");
      if (!d || !d.value) return null;
      return d.value.digitalSignature === true ? null : true;
    },
  },
  {
    id: "lint/cabf-cs/key-usage-forbidden-bit", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (e)",
    /** @internal "Bit positions for keyCertSign and cRLSign MUST NOT be set." The next sentence
     * covers every other bit at SHOULD NOT, so the two lists are two rows at two strengths. */
    message: "keyUsage must not assert keyCertSign or cRLSign",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var d = ctx.decode("keyUsage");
      if (!d || !d.value) return null;
      var out = [];
      CS_FORBIDDEN_KU.forEach(function (bit) {
        if (d.value[bit] === true) out.push({ context: { keyUsage: bit } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-cs/key-usage-discouraged-bit", severity: "warn", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (e)",
    /** @internal "All other bit positions SHOULD NOT be set", which reaches every bit other than
     * the required digitalSignature and the two the row above forbids, including one set past the
     * nine RFC 5280 names. */
    message: "keyUsage should not assert a bit beyond digitalSignature",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var d = ctx.decode("keyUsage");
      if (!d || !d.value) return null;
      var out = [];
      KU_BIT_NAMES.forEach(function (bit) {
        if (bit === "digitalSignature" || CS_FORBIDDEN_KU.indexOf(bit) !== -1) return;
        if (d.value[bit] === true) out.push({ context: { keyUsage: bit } });
      });
      if (d.value.reservedBitsSet === true) out.push({ context: { reservedBitSet: true } });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-cs/eku-missing-code-signing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (f)",
    message: "a code signing certificate must carry id-kp-codeSigning",
    appliesTo: _isCsCodeSigning,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return true;
      return d.value.indexOf(oid.byName("codeSigning")) === -1 ? true : null;
    },
  },
  {
    id: "lint/cabf-cs/eku-missing-time-stamping", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (f)",
    message: "a timestamp certificate must carry id-kp-timeStamping",
    appliesTo: _isCsTimestamp,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return true;
      return d.value.indexOf(oid.byName("timeStamping")) === -1 ? true : null;
    },
  },
  {
    id: "lint/cabf-cs/eku-not-critical-timestamp", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (f)",
    /** @internal "id-kp-timeStamping MUST be present and MUST be marked critical", the one place
     * this section requires a critical extKeyUsage. */
    message: "a timestamp certificate's extKeyUsage must be marked critical",
    appliesTo: function (cert, ctx) { return _isCsTimestamp(cert, ctx) && !!ctx.raw("extKeyUsage"); },
    check: function (cert, ctx) {
      var e = ctx.raw("extKeyUsage");
      return (e && e.critical === true) ? null : true;
    },
  },
  {
    id: "lint/cabf-cs/eku-forbidden-purpose", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (f)",
    message: "extKeyUsage must not carry anyExtendedKeyUsage or id-kp-serverAuth",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      var out = [];
      CS_FORBIDDEN_EKU.forEach(function (dotted) {
        if (d.value.indexOf(dotted) !== -1) {
          out.push({ context: { purpose: dotted, name: oid.name(dotted) || null } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-cs/eku-discouraged-purpose", severity: "warn", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (f)",
    /** @internal "Other values SHOULD NOT be present." The clause continues that a CA presenting
     * one must hold a business agreement with a platform vendor, which is a fact about the CA
     * rather than about the certificate, so this row reports the value and says nothing about the
     * agreement. The purpose each kind requires, the three the clause names as MAY, and the two
     * the row above forbids are all passed over here. */
    message: "extKeyUsage should not carry a purpose beyond the ones this profile names",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      var required = [];
      if (_isCsTimestamp(cert, ctx)) required.push(oid.byName("timeStamping"));
      if (_isCsCodeSigning(cert, ctx)) required.push(oid.byName("codeSigning"));
      var out = [];
      d.value.forEach(function (dotted) {
        if (required.indexOf(dotted) !== -1) return;
        if (CS_PERMITTED_EXTRA_EKU.indexOf(dotted) !== -1) return;
        if (CS_FORBIDDEN_EKU.indexOf(dotted) !== -1) return;
        out.push({ context: { purpose: dotted, name: oid.name(dotted) || null } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-cs/aki-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (g)",
    message: "a subscriber certificate must carry an authorityKeyIdentifier extension",
    appliesTo: _isCs,
    check: function (cert, ctx) { return ctx.raw("authorityKeyIdentifier") ? null : true; },
  },
  {
    id: "lint/cabf-cs/aki-critical", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.2.3 (g)",
    message: "authorityKeyIdentifier must not be marked critical",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var e = ctx.raw("authorityKeyIdentifier");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-cs/validity-too-long", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 6.3.2",
    /** @internal Three ceilings, keyed on the kind and on the issuance date: 39 months for a code
     * signing certificate issued before 1 March 2026, 460 days for one issued on or after it, and
     * 135 months for a timestamp certificate either side of that date. A ceiling stated in months
     * is measured in months, through guard.time.addMonths, since how many days 39 months hold
     * depends on which 39. */
    message: "the validity period exceeds the maximum this profile gives for the certificate's kind and issuance date",
    appliesTo: _isCs,
    check: function (cert, ctx) {
      var v = cert.validity;
      if (!guard.time.isDate(v.notBefore) || !guard.time.isDate(v.notAfter)) return null;
      var notAfter = guard.time.instantOf(v.notAfter);
      /** @internal A certificate claiming both kinds is held to the code signing ceiling, the
       * tighter of the two, since it must satisfy every ceiling it claims. */
      if (!_isCsCodeSigning(cert, ctx)) {
        var tsCeiling = guard.time.addMonths(v.notBefore, 135, _cfg, "lint/bad-input", "notBefore");
        return notAfter > guard.time.instantOf(tsCeiling)
          ? { context: { maxMonths: 135 } } : null;
      }
      if (guard.time.instantOf(v.notBefore) < guard.time.instantOf(CS_VALIDITY_DAYS_START)) {
        var monthCeiling = guard.time.addMonths(v.notBefore, 39, _cfg, "lint/bad-input", "notBefore");
        return notAfter > guard.time.instantOf(monthCeiling)
          ? { context: { maxMonths: 39 } } : null;
      }
      var days = (notAfter - guard.time.instantOf(v.notBefore)) / MS_PER_DAY;
      return days > 460 ? { context: { days: Math.round(days), maxDays: 460 } } : null;
    },
  },
  {
    id: "lint/cabf-cs/weak-key", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 6.1.5.2",
    /** @internal The section names RSA, ECDSA and DSA and no other family, so a key outside the
     * three is reported: a certificate the profile covers must carry one it names. */
    message: "the subject public key is below the Code Signing BR minimum (RSA < 3072 bits, or a curve or family the section does not name)",
    appliesTo: _isCs,
    check: function (cert) {
      var spki = cert.subjectPublicKeyInfo, name = spki && spki.algorithm && spki.algorithm.name;
      if (RSA_KEY_ALGS[name]) {
        var bits = _rsaModulusBits(spki);
        return (bits === null || bits < CS_RSA_MIN_BITS) ? { context: { rsaBits: bits } } : null;
      }
      if (name === "ecPublicKey") {
        var curve = _ecCurveName(spki);
        return CS_EC_CURVES.indexOf(curve) === -1 ? { context: { curve: curve } } : null;
      }
      if (name === "dsa") {
        var dsa = _dsaParamBits(spki);
        if (dsa === null) return { context: { keyAlgorithm: "dsa", dsaL: null, dsaN: null } };
        return (dsa.L === CS_DSA_L && CS_DSA_N.indexOf(dsa.N) !== -1)
          ? null : { context: { keyAlgorithm: "dsa", dsaL: dsa.L, dsaN: dsa.N } };
      }
      return { context: { keyAlgorithm: name || null } };
    },
  },
  {
    id: "lint/cabf-cs/subject-common-name-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.2 (a)",
    message: "a code signing certificate's subject must carry a commonName",
    appliesTo: _isCsCodeSigning,
    check: function (cert) { return _subjectValuesOf(cert, "commonName").length ? null : true; },
  },
  {
    id: "lint/cabf-cs/subject-domain-component-prohibited", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.2 (c)",
    message: "a code signing certificate's subject must not carry a domainComponent",
    appliesTo: _isCsCodeSigning,
    check: function (cert) {
      var n = _subjectValuesOf(cert, "domainComponent").length;
      return n ? { context: { count: n } } : null;
    },
  },
  {
    id: "lint/cabf-cs/subject-attribute-metadata-only", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.2 (d)",
    /** @internal "Subject attributes MUST NOT contain only metadata such as '.', '-', and ' '
     * (i.e. space) characters, and/or any other indication that the value is absent, incomplete,
     * or not applicable." Read over every attribute, since the clause names none in particular. */
    message: "a subject attribute carries only metadata characters",
    appliesTo: _isCsCodeSigning,
    check: function (cert) {
      var out = [];
      _subjectAttributes(cert).forEach(function (a) {
        if (typeof a.value !== "string" || !_isMetadataOnlyValue(a.value)) return;
        out.push({ context: { attribute: oid.name(a.type) || a.type, value: a.value } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-cs/subject-organization-name-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.3 (a) / 7.1.4.2.4 (a)",
    /** @internal Required by the non-EV subsection and again by the EV one, so the row covers both
     * arms and cites each clause. */
    message: "a code signing certificate's subject must carry an organizationName",
    appliesTo: _isCsCodeSigning,
    check: function (cert) { return _subjectValuesOf(cert, "organizationName").length ? null : true; },
  },
  {
    id: "lint/cabf-cs/subject-locality-and-state-absent", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.3 (c) and (d)",
    /** @internal localityName is "Required if the stateOrProvinceName field is absent" and the
     * state row says the same in the other direction, so one of the two must be present and
     * either alone satisfies both. Sec. 7.1.4.2.4 (e) carries these rows onto an EV certificate. */
    message: "a code signing certificate's subject must carry a localityName or a stateOrProvinceName",
    appliesTo: _isCsCodeSigning,
    check: function (cert) {
      return (_subjectValuesOf(cert, "localityName").length ||
        _subjectValuesOf(cert, "stateOrProvinceName").length) ? null : true;
    },
  },
  {
    id: "lint/cabf-cs/subject-country-name-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.3 (f)",
    message: "a code signing certificate's subject must carry a countryName",
    appliesTo: _isCsCodeSigning,
    check: function (cert) { return _subjectValuesOf(cert, "countryName").length ? null : true; },
  },
  {
    id: "lint/cabf-cs/subject-country-name-bad-syntax", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.3 (f)",
    /** @internal "MUST contain the two-letter ISO 3166-1 country code", with the user-assigned XX
     * admitted by the same clause, which is itself two letters. */
    message: "a subject countryName must be a two-letter code",
    appliesTo: _isCsCodeSigning,
    check: function (cert) {
      var out = [];
      _subjectValuesOf(cert, "countryName").forEach(function (v) {
        if (!_isTwoLetterCountry(v)) out.push({ context: { countryName: v } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-cs/subject-business-category-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.4 (b)",
    message: "an EV code signing certificate's subject must carry a businessCategory",
    appliesTo: _isCsEv,
    check: function (cert) { return _subjectValuesOf(cert, "businessCategory").length ? null : true; },
  },
  {
    id: "lint/cabf-cs/subject-business-category-invalid", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.4 (b)",
    message: "a subject businessCategory must be one of the four strings this clause names",
    appliesTo: _isCsEv,
    check: function (cert) {
      var out = [];
      _subjectValuesOf(cert, "businessCategory").forEach(function (v) {
        if (CS_BUSINESS_CATEGORIES.indexOf(v) === -1) out.push({ context: { businessCategory: v } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-cs/subject-jurisdiction-country-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.4 (c)",
    /** @internal The clause lists the locality and the state as required only where the agency
     * operates at that level, and the country without that qualification. */
    message: "an EV code signing certificate's subject must carry a jurisdictionCountryName",
    appliesTo: _isCsEv,
    check: function (cert) { return _subjectValuesOf(cert, "jurisdictionCountryName").length ? null : true; },
  },
  {
    id: "lint/cabf-cs/subject-serial-number-missing", severity: "error", source: "cabf-cs", citation: "CABF Code Signing BR 7.1.4.2.4 (d)",
    message: "an EV code signing certificate's subject must carry a serialNumber",
    appliesTo: _isCsEv,
    check: function (cert) { return _subjectValuesOf(cert, "serialNumber").length ? null : true; },
  },
];

var CABF_TLS_RULES = [
  {
    id: "lint/cabf-tls/aia-missing", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.6",
    message: "a subscriber certificate must carry an authorityInformationAccess extension",
    appliesTo: _isTls,
    check: function (cert, ctx) { return ctx.raw("authorityInfoAccess") ? null : true; },
  },
  {
    id: "lint/cabf-tls/aia-critical", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.6",
    message: "authorityInformationAccess must not be marked critical",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var e = ctx.raw("authorityInfoAccess");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-tls/aia-forbidden-access-method", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.7",
    /** @internal The table permits id-ad-ocsp and id-ad-caIssuers and says of any other value
     * "No other accessMethods may be used". */
    message: "an authorityInformationAccess accessMethod other than id-ad-ocsp or id-ad-caIssuers is not permitted",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var d = ctx.decode("authorityInfoAccess");
      if (!d || !Array.isArray(d.value)) return null;
      var out = [];
      d.value.forEach(function (ad) {
        if (CABF_AIA_METHODS.indexOf(ad.accessMethod) === -1) {
          out.push({ context: { accessMethod: ad.accessMethod, name: oid.name(ad.accessMethod) || null } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-tls/aia-location-not-uri", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.7",
    /** @internal Each permitted accessMethod states uniformResourceIdentifier as its accessLocation
     * GeneralName type, and "each accessLocation MUST be encoded as the specified GeneralName type". */
    message: "an authorityInformationAccess accessLocation must be a uniformResourceIdentifier",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var d = ctx.decode("authorityInfoAccess");
      if (!d || !Array.isArray(d.value)) return null;
      var out = [];
      d.value.forEach(function (ad) {
        if (CABF_AIA_METHODS.indexOf(ad.accessMethod) === -1) return;
        var loc = ad.accessLocation;
        if (!loc || loc.tag !== 6) {
          out.push({ context: { accessMethod: oid.name(ad.accessMethod) || ad.accessMethod,
            generalNameTag: loc ? loc.tag : null } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-tls/policies-missing", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.6",
    message: "a subscriber certificate must carry a certificatePolicies extension",
    appliesTo: _isTls,
    check: function (cert, ctx) { return ctx.raw("certificatePolicies") ? null : true; },
  },
  {
    id: "lint/cabf-tls/policies-any-policy", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.9",
    /** @internal "The anyPolicy Policy Identifier MUST NOT be present." */
    message: "certificatePolicies must not assert anyPolicy",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var d = ctx.decode("certificatePolicies");
      if (!d || !Array.isArray(d.value)) return null;
      return d.value.some(function (pi) { return pi.policyIdentifier === OID_ANY_POLICY; }) ? true : null;
    },
  },
  {
    id: "lint/cabf-tls/policies-reserved-identifier-count", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.9",
    /** @internal "Regardless of the order of PolicyInformation values, the Certificate Policies
     * extension MUST contain exactly one Reserved Certificate Policy Identifier." Exactly one, so
     * naming none and naming two are the same fault and the count says which. */
    message: "certificatePolicies must assert exactly one reserved certificate policy identifier",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var d = ctx.decode("certificatePolicies");
      if (!d || !Array.isArray(d.value)) return null;
      var found = d.value.filter(function (pi) {
        return CABF_RESERVED_POLICIES.indexOf(pi.policyIdentifier) !== -1;
      });
      return found.length === 1 ? null : { context: { count: found.length,
        identifiers: found.map(function (pi) { return pi.policyIdentifier; }) } };
    },
  },
  {
    id: "lint/cabf-tls/policy-qualifier-forbidden", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.9",
    /** @internal The permitted-qualifier table admits id-qt-cps and says of any other qualifier
     * MUST NOT, which includes the userNotice RFC 5280 otherwise allows. */
    message: "a certificatePolicies qualifier other than id-qt-cps is not permitted",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var out = [];
      _policyQualifierIds(ctx).forEach(function (qid) {
        if (qid !== OID_CPS) out.push({ context: { qualifier: qid, name: oid.name(qid) || null } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-tls/eku-forbidden-purpose", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.10",
    message: "a key purpose the subscriber profile forbids is present in extKeyUsage",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var d = ctx.decode("extKeyUsage");
      if (!d || !Array.isArray(d.value)) return null;
      var out = [];
      CABF_FORBIDDEN_EKU.forEach(function (e) {
        if (d.value.indexOf(e.oid) !== -1) out.push({ context: { keyPurpose: e.name, oid: e.oid } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-tls/name-constraints-present", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.6",
    message: "a subscriber certificate must not carry a nameConstraints extension",
    appliesTo: _isTls,
    check: function (cert, ctx) { return ctx.raw("nameConstraints") ? true : null; },
  },
  {
    id: "lint/cabf-tls/basic-constraints-ca-true", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.8",
    message: "a subscriber certificate's basicConstraints cA must be FALSE",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var d = ctx.decode("basicConstraints");
      return (d && d.value && d.value.cA === true) ? true : null;
    },
  },
  {
    id: "lint/cabf-tls/basic-constraints-path-len", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.8",
    message: "a subscriber certificate's basicConstraints must not carry a pathLenConstraint",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var d = ctx.decode("basicConstraints");
      var pl = d && d.value ? d.value.pathLenConstraint : null;
      return pl === null || pl === undefined ? null : { context: { pathLenConstraint: pl } };
    },
  },
  {
    id: "lint/cabf-tls/key-usage-forbidden-bit", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.11",
    /** @internal The two Key Usage tables differ by key type, which is the whole point: the same
     * bit is permitted for one and forbidden for the other, so the key decides which table asks. */
    message: "a keyUsage bit the subscriber profile does not permit for this key type is set",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var d = ctx.decode("keyUsage");
      if (!d || !d.value) return null;
      var table = _cabfKeyUsageTable(cert);
      if (table === null) return null;
      var forbidden = table === "ecc" ? CABF_KU_FORBIDDEN_ECC : CABF_KU_FORBIDDEN_RSA;
      var out = [];
      forbidden.forEach(function (bit) {
        if (d.value[bit] === true) out.push({ context: { keyUsage: bit, keyType: table } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-tls/key-usage-ecc-without-digital-signature", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.11",
    /** @internal The ECC table marks digitalSignature Required: MUST, where the RSA table marks it
     * SHOULD and admits a keyEncipherment-only certificate. */
    message: "an ECC subscriber certificate's keyUsage must assert digitalSignature",
    appliesTo: function (cert, ctx) { return _isTls(cert, ctx) && _isEccKey(cert); },
    check: function (cert, ctx) {
      var d = ctx.decode("keyUsage");
      if (!d || !d.value) return null;
      return d.value.digitalSignature === true ? null : true;
    },
  },
  {
    id: "lint/cabf-tls/key-usage-rsa-no-bit-set", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.11",
    /** @internal "At least one Key Usage MUST be set for RSA Public Keys." Measured over the bits
     * that table permits, since a forbidden bit being set is the row above's answer, not this one's. */
    message: "an RSA subscriber certificate's keyUsage must set at least one permitted bit",
    appliesTo: function (cert, ctx) { return _isTls(cert, ctx) && _cabfKeyUsageTable(cert) === "rsa"; },
    check: function (cert, ctx) {
      var d = ctx.decode("keyUsage");
      if (!d || !d.value) return null;
      var any = CABF_KU_RSA_BITS.some(function (bit) { return d.value[bit] === true; });
      return any ? null : true;
    },
  },
  {
    id: "lint/cabf-tls/san-forbidden-name-type", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.12",
    /** @internal The GeneralName table permits dNSName and iPAddress and marks every other type
     * Permitted: N, including the uniformResourceIdentifier and rfc822Name RFC 5280 allows. */
    message: "a subjectAltName entry of a type the subscriber profile does not permit is present",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var d = ctx.decode("subjectAltName");
      if (!d || !d.value || !Array.isArray(d.value.names)) return null;
      var out = [];
      d.value.names.forEach(function (gn) {
        if (CABF_SAN_PERMITTED_TAGS.indexOf(gn.tagNumber) === -1) {
          out.push({ context: { generalName: CABF_SAN_TAG_NAMES[gn.tagNumber] || null, tag: gn.tagNumber } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-tls/san-criticality-mismatch", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.12",
    /** @internal "If the subject field of the certificate is an empty SEQUENCE, this extension MUST
     * be marked critical ... Otherwise, this extension MUST NOT be marked critical." Both
     * directions are MUST, so one row measures the pair and the context says which way it failed. */
    message: "subjectAltName must be critical where the subject is empty and non-critical otherwise",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var e = ctx.raw("subjectAltName");
      if (!e) return null;
      var empty = _subjectIsEmpty(cert);
      var critical = e.critical === true;
      if (empty === critical) return null;
      return { context: { subjectEmpty: empty, critical: critical } };
    },
  },
  {
    id: "lint/cabf-tls/dnsname-trailing-dot", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.12",
    /** @internal "The zero-length Domain Label representing the root zone ... MUST NOT be included
     * (e.g. 'example.com' MUST be encoded as 'example.com' and MUST NOT be encoded as
     * 'example.com.')." */
    message: "a subjectAltName dNSName must not carry the root zone's zero-length label",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var out = [];
      _sanDnsNames(ctx).forEach(function (name) {
        if (typeof name === "string" && name.length > 0 && name.charAt(name.length - 1) === ".") {
          out.push({ context: { dnsName: name } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-tls/ski-present", severity: "notice", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.6",
    /** @internal NOT RECOMMENDED here, which is the opposite of what RFC 5280 sec. 4.2.1.2 asks of
     * an end-entity certificate. Both readings ship, each under the profile that states it, so a
     * caller running one profile is not told the other's answer. Graded notice because the clause
     * is NOT RECOMMENDED rather than MUST NOT. */
    message: "a subscriber certificate's subjectKeyIdentifier is NOT RECOMMENDED by this profile",
    appliesTo: _isTls,
    check: function (cert, ctx) { return ctx.raw("subjectKeyIdentifier") ? true : null; },
  },
  {
    id: "lint/cabf-tls/san-missing", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.4.2.1",
    message: "a TLS server certificate must include a usable subjectAltName extension",
    appliesTo: _isTls,
    check: function (cert, ctx) { var san = ctx.decode("subjectAltName"); return (san && san.value && san.value.names && san.value.names.length) ? null : true; },
  },
  {
    id: "lint/cabf-tls/cn-not-in-san", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.4.2.2",
    message: "a subject commonName value must also appear as a subjectAltName dNSName",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var sans = _sanDnsNames(ctx).map(function (s) { return typeof s === "string" ? s.toLowerCase() : s; }), out = [];
      _subjectCNs(cert).forEach(function (cn) {
        if (_looksLikeIp(cn)) return;
        if (sans.indexOf(cn.toLowerCase()) === -1) out.push({ context: { cn: cn } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-tls/dnsname-bad-syntax", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.4.2.1",
    message: "a subjectAltName dNSName is not well-formed",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      var out = [];
      _sanDnsNames(ctx).forEach(function (name) { var p = _dnsNameProblem(name); if (p) out.push({ context: { dnsName: name, problem: p } }); });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/cabf-tls/eku-missing-serverauth", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.2.7.6",
    message: "a TLS server certificate's extKeyUsage must include id-kp-serverAuth",
    appliesTo: function (cert, ctx) { return ctx.explicitTlsProfile; },
    check: function (cert, ctx) { return _hasEku(cert, "serverAuth") ? null : true; },
  },
  {
    id: "lint/cabf-tls/weak-key", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 6.1.5",
    message: "the subject public key is below the CABF TLS BR minimum (RSA < 2048 bits, or a non-approved EC curve)",
    appliesTo: _isTls,
    check: function (cert) {
      var spki = cert.subjectPublicKeyInfo, name = spki && spki.algorithm && spki.algorithm.name;
      if (RSA_KEY_ALGS[name]) { var bits = _rsaModulusBits(spki); return (bits === null || bits < 2048) ? { context: { rsaBits: bits } } : null; }
      if (name === "ecPublicKey") { var curve = _ecCurveName(spki); return APPROVED_EC_CURVES.indexOf(curve) === -1 ? { context: { curve: curve } } : null; }
      return null;
    },
  },
  {
    id: "lint/cabf-tls/validity-too-long", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 6.3.2 (Ballots SC22 + SC081v3)",
    message: "a TLS server certificate validity period exceeds the CABF maximum for its issuance date",
    appliesTo: _isTls,
    effectiveDate: VALIDITY_SCHEDULE_START,
    check: function (cert) {
      var v = cert.validity;
      if (!guard.time.isDate(v.notBefore) || !guard.time.isDate(v.notAfter)) return null;
      var maxDays = _validityCeilingDays(v.notBefore);
      var days = (guard.time.instantOf(v.notAfter) - guard.time.instantOf(v.notBefore)) / MS_PER_DAY;
      return days > maxDays ? { context: { days: Math.round(days), maxDays: maxDays } } : null;
    },
  },
];

var ML_KEM_EK_LEN = Object.create(null);
["id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024"].forEach(function (n) { ML_KEM_EK_LEN[n] = oid.kemParams(n).ek; });
function _isMlKem(cert) {
  var spki = cert.subjectPublicKeyInfo;
  return !!(spki && spki.algorithm && ML_KEM_EK_LEN[spki.algorithm.name] !== undefined);
}
var RFC9935_RULES = [
  {
    id: "lint/rfc9935/kem-key-usage", severity: "error", source: "rfc9935", citation: "RFC 9935 5",
    message: "an ML-KEM certificate's keyUsage, if present, must assert keyEncipherment as the only key usage set",
    appliesTo: _isMlKem,
    check: function (cert, ctx) {
      var ku = ctx.decode("keyUsage");
      if (!ku || !ku.value) return null;
      var v = ku.value;
      var others = v.digitalSignature || v.nonRepudiation || v.dataEncipherment || v.keyAgreement ||
        v.keyCertSign || v.cRLSign || v.encipherOnly || v.decipherOnly || v.reservedBitsSet === true;
      return (v.keyEncipherment && !others) ? null : true;
    },
  },
  {
    id: "lint/rfc9935/kem-key-length", severity: "error", source: "rfc9935", citation: "RFC 9935 4 / FIPS 203",
    message: "an ML-KEM subjectPublicKey must be the raw encapsulation key at its exact FIPS 203 size for the OID, in a byte-aligned BIT STRING",
    appliesTo: _isMlKem,
    check: function (cert) {
      var spki = cert.subjectPublicKeyInfo;
      var want = ML_KEM_EK_LEN[spki.algorithm.name];
      var pub = spki.publicKey;
      return (guard.crypto.isOctetAligned(pub) && pub.bytes.length === want) ? null
        : { context: { expected: want, got: pub.bytes.length, unusedBits: pub.unusedBits } };
    },
  },
];

/** @internal RFC 9881 sec. 5 and RFC 9909 sec. 6 state one pair of requirements for a post-quantum
 * signature key, both conditioned on keyUsage being present: at least one of digitalSignature,
 * nonRepudiation, keyCertSign or cRLSign is set, and none of keyEncipherment, dataEncipherment,
 * keyAgreement, encipherOnly or decipherOnly is. The nine RFC 5280 bits are exhausted by those two
 * lists, so the only input that fails the signing-bit requirement without also setting a
 * key-establishment bit is one whose sole bit is reserved. A keyUsage with no bits set never
 * reaches either rule: the extension decoder refuses it first. */
function _spkiAlgName(cert) {
  var spki = cert.subjectPublicKeyInfo;
  var n = spki && spki.algorithm && spki.algorithm.name;
  return typeof n === "string" ? n : "";
}
function _isMlDsa(cert) { return _spkiAlgName(cert).indexOf("id-ml-dsa-") === 0; }
/** @internal RFC 9909 sec. 5 admits both the pure and the prehash identifier as a subject public
 * key algorithm, and sec. 6 binds the key usage of both. */
function _isSlhDsa(cert) {
  var n = _spkiAlgName(cert);
  return n.indexOf("id-slh-dsa-") === 0 || n.indexOf("id-hash-slh-dsa-") === 0;
}
var PQC_SIG_ESTABLISHMENT_BITS = ["keyEncipherment", "dataEncipherment", "keyAgreement", "encipherOnly", "decipherOnly"];
var PQC_SIG_SIGNING_BITS = ["digitalSignature", "nonRepudiation", "keyCertSign", "cRLSign"];
function _pqcSigKeyUsage(cert, ctx) {
  var ku = ctx.decode("keyUsage");
  if (!ku || !ku.value) return null;
  var v = ku.value;
  var establishment = PQC_SIG_ESTABLISHMENT_BITS.filter(function (bit) { return v[bit] === true; });
  var signing = PQC_SIG_SIGNING_BITS.some(function (bit) { return v[bit] === true; });
  if (establishment.length === 0 && signing) return null;
  return { context: { keyEstablishmentBitsSet: establishment, signingBitSet: signing } };
}
function _pqcSigKeyUsageRule(id, source, citation, family, appliesTo) {
  return {
    id: id, severity: "error", source: source, citation: citation,
    message: "an " + family + " certificate's keyUsage, if present, must set at least one signing bit "
      + "(digitalSignature, nonRepudiation, keyCertSign, cRLSign) and no key-establishment bit "
      + "(keyEncipherment, dataEncipherment, keyAgreement, encipherOnly, decipherOnly)",
    appliesTo: appliesTo,
    check: _pqcSigKeyUsage,
  };
}
var RFC9881_RULES = [
  _pqcSigKeyUsageRule("lint/rfc9881/mldsa-key-usage", "rfc9881", "RFC 9881 5", "ML-DSA", _isMlDsa),
];
var RFC9909_RULES = [
  _pqcSigKeyUsageRule("lint/rfc9909/slhdsa-key-usage", "rfc9909", "RFC 9909 6", "SLH-DSA", _isSlhDsa),
];

/** @internal RFC 5280 sec. 5 states the criticality of each CRL extension it profiles, and sec. 5.3
 * does the same for the entry extensions. certificateIssuer is critical (sec. 5.3.3) because a
 * consumer that ignores it attributes an entry to the wrong issuer. */
/** @internal The extensions section 5.2 profiles for a CRL. This is the RECOGNIZED set, which is
 * wider than the table below: issuerAltName is profiled here but its criticality is a SHOULD, so it
 * is recognized without being held to a required value. */
var CRL_KNOWN_EXTENSIONS = Object.create(null);
["authorityKeyIdentifier", "issuerAltName", "cRLNumber", "deltaCRLIndicator",
  "issuingDistributionPoint", "freshestCRL", "authorityInfoAccess"]
  .forEach(function (n) { CRL_KNOWN_EXTENSIONS[oid.byName(n)] = true; });

/** @internal Only the extensions whose criticality section 5.2 states as a MUST. issuerAltName is
 * deliberately absent: section 5.2.2 says a conforming issuer SHOULD mark it non-critical, and
 * grading a SHOULD as an error would promote the requirement level the clause states. */
var CRL_CRITICALITY = Object.create(null);
[["cRLNumber", false], ["authorityKeyIdentifier", false], ["freshestCRL", false],
  ["authorityInfoAccess", false],
  ["issuingDistributionPoint", true], ["deltaCRLIndicator", true]]
  .forEach(function (r) { CRL_CRITICALITY[oid.byName(r[0])] = r[1]; });
var CRL_ENTRY_CRITICALITY = Object.create(null);
(function () {
  var shared = crlSchema.entryExtensionCriticality(oid);
  Object.keys(shared).forEach(function (k) { CRL_ENTRY_CRITICALITY[k] = shared[k].critical; });
})();

function _crlExtList(crl) { return crl.crlExtensions || []; }
function _crlExtByName(crl, name) {
  var dotted = oid.byName(name), list = _crlExtList(crl);
  for (var i = 0; i < list.length; i++) { if (list[i].oid === dotted) return list[i]; }
  return null;
}
/** @internal An AuthorityKeyIdentifier value read through the shared extension decoder, which holds
 * it to the structure RFC 5280 sec. 4.2.1.1 states. Scanning for a [0] child by hand would admit a
 * SET carrying one, and a SEQUENCE whose [0] is constructed, neither of which is an
 * AuthorityKeyIdentifier. Bytes the decoder refuses come back as null and the caller reports that;
 * nothing here returns a verdict. */
function _akiValue(bytes) {
  var dec = EXT_DECODERS[oid.byName("authorityKeyIdentifier")];
  if (!dec) return null;
  // allow:swallow-unverified a value the shared decoder refuses is not an AuthorityKeyIdentifier, which the caller reports
  try { return dec(bytes) || null; }
  catch (_e) { return null; }
}

/** @internal The decoded names of a GeneralNames value, or null when the bytes are not one. The
 * value-syntax row reports that separately, so nothing here returns a verdict. */
function _generalNamesOf(bytes) {
  // allow:swallow-unverified bytes that are not GeneralNames carry no names for the caller to read
  try {
    var m = schema.walk(pkix.generalNames(NS, { decodeValue: true, code: _LINT_VALUE_CODE }), asn1.decode(bytes), NS);
    return (m.result && m.result.names) || null;
  } catch (_e) { return null; }
}

/** @internal A CRLReason value mapped onto its ReasonFlags bit. The two enumerations do NOT line
 * up: RFC 5280 sec. 5.3.1 leaves CRLReason 7 unused and numbers privilegeWithdrawn 9 and
 * aACompromise 10, while sec. 4.2.1.13 gives them ReasonFlags bits 7 and 8. unspecified(0) and
 * removeFromCRL(8) have no bit at all, so neither can sit outside a reason scope and both are
 * absent here; their own rows answer for them. Assuming identity would report conforming CRLs. */
var REASON_TO_FLAG_BIT = Object.create(null);
[[1, 1], [2, 2], [3, 3], [4, 4], [5, 5], [6, 6], [9, 7], [10, 8]]
  .forEach(function (p) { REASON_TO_FLAG_BIT[p[0]] = p[1]; });

/** @internal Whether a ReasonFlags BIT STRING has the given bit set. */
function _reasonBitSet(bs, bit) {
  if (!bs || !bs.bytes) return false;
  var byteI = bit >> 3;
  if (byteI >= bs.bytes.length) return false;
  return (bs.bytes[byteI] & (0x80 >> (bit & 7))) !== 0;
}

/** @internal Whether a ReasonFlags mask names at least one reason code. Bit 0 is named `unused`,
 * so a mask setting only it, or setting nothing at all, names none and partitions nothing.
 *
 * Bit 0 set ALONGSIDE a real reason is deliberately not reported. Section 5.2.5 requires the reason
 * codes associated with a distribution point to be specified here, and such a mask specifies one;
 * RFC 5280 states nothing about bit 0 being clear, so reporting it would name a violation the
 * profile does not state. */
function _scopeNamesAnyReason(bs) {
  for (var bit = 1; bit <= 8; bit++) { if (_reasonBitSet(bs, bit)) return true; }
  return false;
}

/** @internal The ReasonFlags of a CRL's issuingDistributionPoint, or null when it states no reason
 * scope. Read through the shared decoder, so a malformed one scopes nothing. A mask naming no
 * reason scopes nothing either: it gives an entry no partition to belong to, so the extension is
 * what is at fault and the profile row reports it rather than every entry in turn. */
function _crlReasonScope(crl) {
  var e = _crlExtByName(crl, "issuingDistributionPoint");
  if (!e || !Buffer.isBuffer(e.value)) return null;
  var idp = pkix.decodeIssuingDistributionPointValue(NS, e.value, _LINT_VALUE_CODE);
  if (idp.malformed || !idp.onlySomeReasonsPresent) return null;
  if (!_scopeNamesAnyReason(idp.onlySomeReasonsValue)) return null;
  return idp.onlySomeReasonsValue || null;
}

/** @internal Whether the CRL is scoped to some reason codes, which is what makes a revocation
 * reason load-bearing: the reason decides which partition an entry belongs in. Reads the scope
 * itself so the two cannot answer differently about the same CRL. */
function _crlHasReasonScope(crl) {
  return _crlReasonScope(crl) !== null;
}

/** @internal Whether the CRL affirmatively declares itself DIRECT, read from the same
 * IssuingDistributionPoint decoder certification-path validation uses. Three cases, because a
 * malformed extension is not the same as an absent one: a CRL carrying no issuingDistributionPoint
 * is direct by omission, a well-formed one answers with its indirectCRL flag, and one that does not
 * decode declares neither direction. The rows that only mean something on a direct CRL stand aside
 * for that last case, so an unreadable declaration is reported against the extension by the
 * value-syntax row rather than against each entry in turn. That row is an error, so no CRL reaches
 * a clean report with those rows unevaluated. */
function _crlDeclaresDirect(crl) {
  var e = _crlExtByName(crl, "issuingDistributionPoint");
  if (!e) return true;
  if (!Buffer.isBuffer(e.value)) return false;
  var idp = pkix.decodeIssuingDistributionPointValue(NS, e.value, _LINT_VALUE_CODE);
  if (idp.malformed) return false;
  return idp.indirect !== true;
}

var CA_ISSUERS_OID = oid.byName("caIssuers");

/** @internal A recognized CRL extension's value, read through the same decoder every other consumer
 * of that extension uses. null when the extension is absent or its value does not read, and the
 * value-syntax row reports the latter on its own. */
function _crlDecodedExtension(crl, name) {
  var e = _crlExtByName(crl, name);
  if (!e || !Buffer.isBuffer(e.value)) return null;
  var dec = EXT_DECODERS[oid.byName(name)];
  if (!dec) return null;
  try {
    return dec(e.value);
  } catch (_e) {
    return null;
  }
}

/** @internal The schemes that satisfy the section 5.2.7 recommendation. The secured forms count:
 * warning about an https or ldaps location would report the more protected spelling of the two the
 * clause names. */
var AIA_RECOMMENDED_SCHEMES = ["http", "https", "ldap", "ldaps"];

/** @internal The DER content length an integer occupies, which is what the 20-octet ceilings in
 * RFC 5280 bound. Measured by re-encoding, since the parser hands back the decoded value; a
 * non-minimal encoding cannot reach here because strict DER refuses one at parse. */
function _integerOctets(v) {
  if (typeof v !== "bigint") return null;
  // allow:swallow-unverified a value the codec cannot re-encode is not one this can size
  try { return _magnitudeOctets(asn1.decode(asn1.build.integer(v)).content); }
  catch (_e) { return null; }
}

/** @internal The extensions that carry a CRLNumber. RFC 5280 sec. 5.2.4 defines BaseCRLNumber as a
 * CRLNumber, so the sec. 5.2.3 ceiling bounds the delta indicator's value as well as the CRL's own
 * number. The parser decodes cRLNumber to a bigint and leaves deltaCRLIndicator opaque, so each
 * carrier names how its value is read. */
var CRL_NUMBER_CARRIERS = [
  { name: "cRLNumber", read: function (e) { return e.value; } },
  { name: "deltaCRLIndicator", read: function (e) { return _crlIntegerValue(e.value); } },
];

/** @internal An extension value the CRL parser leaves opaque, read as the INTEGER it should be.
 * Bytes that are not one come back as null and the caller decides what that means. */
function _crlIntegerValue(bytes) {
  if (!Buffer.isBuffer(bytes)) return null;
  // allow:swallow-unverified bytes that are not an INTEGER are reported by the value-syntax row, not decided here
  try {
    var n = asn1.decode(bytes);
    if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.INTEGER) return null;
    return asn1.read.integer(n);
  } catch (_e) { return null; }
}

/** @internal How each recognized extension's value is read, for the ones the CRL parser leaves as
 * opaque bytes. Each walks the shared schema for that structure rather than testing an outer tag:
 * a SEQUENCE carrying a NULL is not an IssuingDistributionPoint, and matching the outer type would
 * admit it. Where a shared decoder exists it answers instead, and where the parser already decoded
 * the value to a JavaScript type there is nothing left to check. */
var _LINT_VALUE_CODE = "lint/bad-extension-value";
var CRL_VALUE_READER = Object.create(null);
CRL_VALUE_READER[oid.byName("deltaCRLIndicator")] = function (bytes) {
  var n = asn1.decode(bytes);
  if (n.tagClass !== "universal" || n.tagNumber !== asn1.TAGS.INTEGER) throw _cfg(_LINT_VALUE_CODE, "not an INTEGER");
  /** @internal BaseCRLNumber is a CRLNumber, which RFC 5280 sec. 5.2.3 constrains to a
   * non-negative integer, so a negative one is not a BaseCRLNumber at all. */
  if (asn1.read.integer(n) < 0n) throw _cfg(_LINT_VALUE_CODE, "a negative BaseCRLNumber");
};
/** @internal Read through the SAME decoder certification-path validation uses, rather than a walk
 * assembled here. The shared IssuingDistributionPoint schema leaves distributionPoint as `any`, so
 * validating only that far accepts a wrapper carrying something that is not a DistributionPointName
 * at all, and the linter would call well formed what the path validator rejects. */
CRL_VALUE_READER[oid.byName("issuingDistributionPoint")] = function (bytes) {
  if (pkix.decodeIssuingDistributionPointValue(NS, bytes, _LINT_VALUE_CODE).malformed) {
    throw _cfg(_LINT_VALUE_CODE, "malformed IssuingDistributionPoint");
  }
};
/** @internal Only certificateIssuer. The parser decodes reasonCode and invalidityDate itself and
 * refuses a value that is not the type they name, so an entry for either would be dead. */
var CRL_ENTRY_VALUE_READER = Object.create(null);
CRL_ENTRY_VALUE_READER[oid.byName("certificateIssuer")] = function (bytes) {
  schema.walk(pkix.generalNames(NS, { code: _LINT_VALUE_CODE }), asn1.decode(bytes), NS);
};

/** @internal Whether a recognized extension's value reads as the structure its identifier names.
 * Returns null when it does, and a reason when it does not. An extension whose value the parser
 * already turned into a JavaScript value needs no check: it could not have been decoded otherwise. */
function _valueSyntaxFault(e, knownTable, readerTable) {
  /** @internal Only an extension section 5 profiles FOR A CRL has a syntax to enforce here. A
   * certificate-only extension carried on a CRL is an unrecognized one, which section 5.2 lets a
   * consumer ignore when it is non-critical and the unknown-critical row reports when it is not;
   * decoding its value against the CERTIFICATE profile would report a fault no CRL rule states. */
  if (knownTable[e.oid] === undefined) return null;
  var dec = EXT_DECODERS[e.oid];
  if (dec && Buffer.isBuffer(e.value)) {
    // allow:swallow-unverified the decoder's refusal IS the fault this returns
    try { dec(e.value); return null; }
    catch (_e) { return "does not decode as the structure its extension identifier names"; }
  }
  var read = readerTable[e.oid];
  if (read === undefined || !Buffer.isBuffer(e.value)) return null;
  // allow:swallow-unverified the reader's refusal IS the fault this returns
  try { read(e.value); return null; }
  catch (_e) { return "does not decode as the structure its extension identifier names"; }
}

function _criticalityRows(list, table, what) {
  var out = [];
  (list || []).forEach(function (e) {
    /** @internal The table has a null prototype and boolean values, so an absent OID is undefined. */
    var want = table[e.oid];
    if (want === undefined) return;
    if ((e.critical === true) !== want) {
      out.push({ context: { extension: e.name || e.oid, required: want ? "critical" : "non-critical", was: e.critical === true ? "critical" : "non-critical", scope: what } });
    }
  });
  return out;
}

/** @internal Three of the section 5 rules have no row here, because the strict parser refuses them
 * before a rule could run and a rule for them would be dead: the version against the extensions
 * present (sec. 5.1.2.1, `crl/bad-version`), an empty issuer name (sec. 5.1.2.3, `crl/bad-issuer`),
 * and a present-but-empty revokedCertificates (sec. 5.1.2.6, `crl/bad-revoked-certificates`). Each
 * reaches a caller as the engine's fatal lint/unparseable carrying that code. */
var RFC5280_CRL_RULES = [
  {
    id: "lint/rfc5280-crl/signature-empty", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.1.1.3",
    message: "the signatureValue contains no signature",
    check: function (crl) { return crl.signatureValue.bytes.length === 0 ? true : null; },
  },
  {
    id: "lint/rfc5280-crl/next-update-missing", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.1.2.5",
    message: "a conforming CRL issuer includes the nextUpdate field in every CRL",
    check: function (crl) { return crl.nextUpdate == null ? true : null; },
  },
  {
    id: "lint/rfc5280-crl/update-times-inverted", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.1.2.4 / 5.1.2.5",
    message: "a CRL's thisUpdate must not follow its nextUpdate",
    check: function (crl) {
      // allow:nan-date-comparison-unguarded -- both are codec-parsed CRL times (asn1 readTime rejects a NaN instant).
      if (!guard.time.isDate(crl.thisUpdate) || !guard.time.isDate(crl.nextUpdate)) return null;
      return guard.time.instantOf(crl.thisUpdate) > guard.time.instantOf(crl.nextUpdate) ? true : null;
    },
  },
  {
    id: "lint/rfc5280-crl/crl-number-missing", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.3",
    message: "a conforming CRL issuer includes the cRLNumber extension in every CRL",
    check: function (crl) { return _crlExtByName(crl, "cRLNumber") ? null : true; },
  },
  {
    id: "lint/rfc5280-crl/crl-number-too-long", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.3 / 5.2.4",
    /** @internal One requirement over two carriers, so one row measures both and the context names
     * which one it measured. A value that is not an INTEGER sizes as null here and is reported by
     * the value-syntax row instead. */
    message: "a CRL number must not be longer than 20 octets",
    check: function (crl) {
      var out = [];
      CRL_NUMBER_CARRIERS.forEach(function (carrier) {
        var e = _crlExtByName(crl, carrier.name);
        if (!e) return;
        var octets = _integerOctets(carrier.read(e));
        if (octets !== null && octets > 20) out.push({ context: { extension: carrier.name, octets: octets } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/aki-missing", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.1",
    /** @internal Section 5.2.1 states this in the same terms section 5.2.3 states cRLNumber:
     * conforming CRL issuers MUST include the extension in all CRLs. Two clauses of the same
     * strength are graded the same, so a caller filtering at `error` sees both or neither. The
     * certificate profile grades its own authorityKeyIdentifier row differently, and that is
     * shipped surface left as it is rather than re-graded from here. */
    message: "a conforming CRL issuer includes an authorityKeyIdentifier in every CRL",
    check: function (crl) { return _crlExtByName(crl, "authorityKeyIdentifier") ? null : true; },
  },
  {
    id: "lint/rfc5280-crl/aki-without-key-identifier", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.1",
    message: "a CRL's authorityKeyIdentifier must be well formed and use the key identifier method",
    /** @internal Section 5.2.1 states two requirements: include the extension, and use the key
     * identifier method. The row above answers the first. This answers the second, and it also
     * answers for the value being an AuthorityKeyIdentifier at all, since the CRL parser leaves
     * this extension as opaque bytes and nothing else reads it. */
    appliesTo: function (crl) { return !!_crlExtByName(crl, "authorityKeyIdentifier"); },
    check: function (crl) {
      var e = _crlExtByName(crl, "authorityKeyIdentifier");
      if (!Buffer.isBuffer(e.value)) return null;
      var v = _akiValue(e.value);
      if (v === null) return { context: { undecodable: true } };
      return v.keyIdentifier ? null : true;
    },
  },
  {
    id: "lint/rfc5280-crl/extension-criticality", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2",
    message: "a CRL extension is marked with a criticality the profile does not allow",
    check: function (crl) {
      var rows = _criticalityRows(_crlExtList(crl), CRL_CRITICALITY, "crlExtensions");
      return rows.length ? rows : null;
    },
  },
  {
    id: "lint/rfc5280-crl/entry-extension-criticality", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.3",
    message: "a CRL entry extension is marked with a criticality the profile does not allow",
    check: function (crl) {
      /** @internal Appended rather than concatenated: a CRL may list very many entries, and this
       * verb exists to survey ones that arrived from elsewhere, so rebuilding the accumulator per
       * entry would make the rule quadratic in the length of a list an attacker chooses. */
      var rows = [];
      (crl.revokedCertificates || []).forEach(function (r, i) {
        _criticalityRows(r.crlEntryExtensions, CRL_ENTRY_CRITICALITY, "crlEntryExtensions")
          .forEach(function (row) { row.context.entry = i; rows.push(row); });
      });
      return rows.length ? rows : null;
    },
  },
  {
    id: "lint/rfc5280-crl/issuer-alt-name-critical", severity: "warn", source: "rfc5280-crl", citation: "RFC 5280 5.2.2",
    message: "a conforming CRL issuer should mark the issuerAltName extension as non-critical",
    check: function (crl) {
      var e = _crlExtByName(crl, "issuerAltName");
      return (e && e.critical === true) ? true : null;
    },
  },
  {
    id: "lint/rfc5280-crl/duplicate-entry-serial", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.1.2.6",
    /** @internal On a direct CRL a serial identifies one certificate, so listing it twice states
     * two revocations of the same certificate and a reader cannot tell which entry governs. An
     * INDIRECT CRL is excluded: there a serial is unique per issuer rather than per list, and the
     * effective issuer is carried forward by certificateIssuer, which is a different computation
     * from the one here. */
    appliesTo: function (crl) { return _crlDeclaresDirect(crl); },
    message: "a direct CRL lists the same certificate serial number more than once",
    check: function (crl) {
      var seen = Object.create(null), out = [];
      (crl.revokedCertificates || []).forEach(function (row, i) {
        if (typeof row.serialNumber !== "bigint") return;
        var key = row.serialNumber.toString(16);
        if (seen[key] !== undefined) out.push({ context: { entry: i, firstSeenAt: seen[key], serialNumber: String(row.serialNumber) } });
        else seen[key] = i;
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/certificate-issuer-on-direct-crl", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.3.3",
    /** @internal certificateIssuer names the issuer an entry belongs to, which only means something
     * on a CRL that declares itself indirect through the issuingDistributionPoint indirectCRL flag.
     * On a direct CRL the entry and the list disagree about whose certificates are covered, and no
     * revocation status follows from it. */
    appliesTo: function (crl) { return _crlDeclaresDirect(crl); },
    message: "a revoked entry carries certificateIssuer on a CRL that does not declare itself indirect",
    check: function (crl) {
      var out = [];
      (crl.revokedCertificates || []).forEach(function (row, i) {
        (row.crlEntryExtensions || []).forEach(function (e) {
          if (e.oid === oid.byName("certificateIssuer")) out.push({ context: { entry: i } });
        });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/certificate-issuer-without-dn", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.3.3",
    message: "a certificateIssuer must carry the issuer distinguished name of the certificate its entry names",
    /** @internal Section 5.3.3: a conforming issuer MUST include in this extension the distinguished
     * name from the issuer field of the certificate the entry names. In a GeneralNames that is the
     * directoryName [4] arm, so a certificateIssuer carrying only some other name form does not
     * attribute the entry to an issuer at all. Separate from whether the value decodes. */
    check: function (crl) {
      var out = [];
      (crl.revokedCertificates || []).forEach(function (row, i) {
        (row.crlEntryExtensions || []).forEach(function (e) {
          if (e.oid !== oid.byName("certificateIssuer") || !Buffer.isBuffer(e.value)) return;
          var names = _generalNamesOf(e.value);
          if (names === null) return;
          /** @internal A directoryName wrapping an empty Name is a name container holding no name.
           * RFC 5280 sec. 4.1.2.4 gives a certificate's issuer a non-empty distinguished name, so
           * an empty one cannot be the DN sec. 5.3.3 requires, and matching only the tag would
           * accept it. */
          var hasDn = false;
          names.forEach(function (n) {
            if (n.tagNumber === 4 && n.value && (n.value.rdns || []).length > 0) hasDn = true;
          });
          if (!hasDn) out.push({ context: { entry: i } });
        });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/unspecified-reason-in-reason-scoped-crl", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.5",
    /** @internal Section 5.2.5: where the issuingDistributionPoint carries onlySomeReasons, every
     * revoked certificate in scope MUST be assigned a reason other than unspecified, because the
     * reason is what decides which partition the entry belongs in. That is a MUST here, where the
     * same encoding is only a SHOULD under section 5.3.1, so it is reported as an error and the
     * SHOULD row stands aside. An entry carrying NO reasonCode is untouched: the clause says the
     * extension need not be present. */
    appliesTo: function (crl) { return _crlHasReasonScope(crl); },
    message: "a CRL scoped to some reason codes lists an entry whose reasonCode is unspecified(0)",
    check: function (crl) {
      var out = [];
      (crl.revokedCertificates || []).forEach(function (row, i) {
        (row.crlEntryExtensions || []).forEach(function (e) {
          if (e.oid === oid.byName("reasonCode") && Number(e.value) === 0) out.push({ context: { entry: i } });
        });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/reason-outside-crl-scope", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.5",
    /** @internal Section 5.2.5: the reason codes associated with a distribution point MUST be
     * specified in onlySomeReasons, and the section's own partitioning example shows a CRL carrying
     * only the reasons it declares. An entry whose reason is not among them is a revocation this
     * CRL says it does not carry, so a reader partitioning by reason would miss it. */
    appliesTo: function (crl) { return _crlReasonScope(crl) !== null; },
    message: "a revoked entry states a reason the CRL's issuingDistributionPoint does not declare",
    check: function (crl) {
      var scope = _crlReasonScope(crl), out = [];
      (crl.revokedCertificates || []).forEach(function (row, i) {
        (row.crlEntryExtensions || []).forEach(function (e) {
          if (e.oid !== oid.byName("reasonCode")) return;
          var bit = REASON_TO_FLAG_BIT[Number(e.value)];
          if (bit === undefined) return;
          if (!_reasonBitSet(scope, bit)) out.push({ context: { entry: i, reasonCode: Number(e.value) } });
        });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/reason-code-unspecified", severity: "warn", source: "rfc5280-crl", citation: "RFC 5280 5.3.1",
    /** @internal Section 5.3.1 states this as a SHOULD, so it is a warning rather than an error:
     * the reason code extension should be absent instead of encoding unspecified(0), which says
     * nothing a reader can act on while costing an extension slot. Where the CRL is scoped to some
     * reason codes the row above answers instead, at the strength section 5.2.5 states. */
    message: "a reasonCode extension encoding unspecified(0) should be absent instead",
    appliesTo: function (crl) { return !_crlHasReasonScope(crl); },
    check: function (crl) {
      var out = [];
      (crl.revokedCertificates || []).forEach(function (row, i) {
        (row.crlEntryExtensions || []).forEach(function (e) {
          if (e.oid === oid.byName("reasonCode") && Number(e.value) === 0) out.push({ context: { entry: i } });
        });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/entry-serial-not-positive", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 4.1.2.2",
    message: "a revoked entry's certificate serial number must be a positive integer",
    /** @internal userCertificate is a CertificateSerialNumber, so it carries the sec. 4.1.2.2
     * profile the certificate rows already apply to a certificate's own serial. */
    check: function (crl) {
      var out = [];
      (crl.revokedCertificates || []).forEach(function (row, i) {
        if (typeof row.serialNumber === "bigint" && row.serialNumber <= 0n) {
          out.push({ context: { entry: i, serialNumber: String(row.serialNumber) } });
        }
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/entry-serial-too-long", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 4.1.2.2",
    message: "a revoked entry's certificate serial number must not be longer than 20 octets",
    check: function (crl) {
      var out = [];
      (crl.revokedCertificates || []).forEach(function (row, i) {
        var octets = _integerOctets(row.serialNumber);
        if (octets !== null && octets > 20) out.push({ context: { entry: i, octets: octets } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/idp-profile", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.5",
    message: "an issuingDistributionPoint states a scope the profile does not permit",
    /** @internal A separate decision from whether the value DECODES, which the value-syntax row
     * answers. These are the constraints section 5.2.5 places on a well-formed one, read from the
     * same decoder certification-path validation uses. */
    appliesTo: function (crl) { return !!_crlExtByName(crl, "issuingDistributionPoint"); },
    check: function (crl) {
      var idp = pkix.decodeIssuingDistributionPointValue(NS, _crlExtByName(crl, "issuingDistributionPoint").value, _LINT_VALUE_CODE);
      if (idp.malformed) return null;
      var out = [];
      if (!idp.hasDistributionPoint && !idp.onlyUser && !idp.onlyCa && !idp.onlySomeReasonsPresent && !idp.indirect && !idp.onlyAttr) {
        out.push({ context: { reason: "states no scope at all" } });
      }
      if (idp.onlyUser && idp.onlyCa) out.push({ context: { reason: "sets both onlyContainsUserCerts and onlyContainsCACerts" } });
      if (idp.onlyAttr) out.push({ context: { reason: "sets onlyContainsAttributeCerts" } });
      if (idp.onlySomeReasonsPresent && !_scopeNamesAnyReason(idp.onlySomeReasonsValue)) {
        out.push({ context: { reason: "sets onlySomeReasons to a mask naming no reason code" } });
      }
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/freshest-crl-forbidden-field", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.6",
    /** @internal Section 5.2.6 reuses the cRLDistributionPoints syntax but states that only the
     * distribution point field is meaningful on a CRL, and that reasons and cRLIssuer are omitted.
     * The shared decoder accepts both because the certificate extension permits them, so this row
     * carries the restriction the certificate profile does not have. */
    message: "a CRL's freshestCRL must omit the reasons and cRLIssuer fields",
    appliesTo: function (crl) { return !!_crlExtByName(crl, "freshestCRL"); },
    check: function (crl) {
      var dps = _crlDecodedExtension(crl, "freshestCRL");
      if (dps === null) return null;
      var out = [];
      dps.forEach(function (dp, i) {
        if (dp.reasons) out.push({ context: { index: i, field: "reasons" } });
        if (dp.cRLIssuer) out.push({ context: { index: i, field: "cRLIssuer" } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/aia-without-ca-issuers", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.7",
    /** @internal caIssuers is what this extension is for on a CRL: it names where to fetch the
     * certificates a reader verifies the CRL's signature with. Present without one, it gives a
     * reader nothing to fetch. */
    message: "a CRL's authorityInfoAccess must include an AccessDescription whose method is caIssuers",
    appliesTo: function (crl) { return !!_crlExtByName(crl, "authorityInfoAccess"); },
    check: function (crl) {
      var descs = _crlDecodedExtension(crl, "authorityInfoAccess");
      if (descs === null) return null;
      var found = descs.some(function (d) { return d.accessMethod === CA_ISSUERS_OID; });
      if (found) return null;
      return { context: { methods: descs.map(function (d) { return oid.name(d.accessMethod) || d.accessMethod; }) } };
    },
  },
  {
    id: "lint/rfc5280-crl/aia-forbidden-access-method", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.7",
    message: "a CRL's authorityInfoAccess must not carry an access method other than caIssuers",
    appliesTo: function (crl) { return !!_crlExtByName(crl, "authorityInfoAccess"); },
    check: function (crl) {
      var descs = _crlDecodedExtension(crl, "authorityInfoAccess");
      if (descs === null) return null;
      var out = [];
      descs.forEach(function (d, i) {
        if (d.accessMethod === CA_ISSUERS_OID) return;
        out.push({ context: { index: i, method: oid.name(d.accessMethod) || d.accessMethod } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/aia-location-not-http-or-ldap", severity: "warn", source: "rfc5280-crl", citation: "RFC 5280 5.2.7",
    /** @internal Section 5.2.7 states this one as a SHOULD, so it is a warning where the two rules
     * above are errors. */
    message: "at least one authorityInfoAccess location should be an HTTP or LDAP URI",
    appliesTo: function (crl) { return !!_crlExtByName(crl, "authorityInfoAccess"); },
    check: function (crl) {
      var descs = _crlDecodedExtension(crl, "authorityInfoAccess");
      if (descs === null || descs.length === 0) return null;
      var reachable = descs.some(function (d) {
        var loc = d.accessLocation;
        if (!loc || loc.tag !== 6) return false;
        return AIA_RECOMMENDED_SCHEMES.some(function (s) { return guard.name.uriSchemeIs(loc.value, s); });
      });
      return reachable ? null : true;
    },
  },
  {
    id: "lint/rfc5280-crl/distribution-point-name-relative", severity: "warn", source: "rfc5280-crl", citation: "RFC 5280 5.2.5 / 5.2.6 / 4.2.1.13",
    /** @internal Sections 5.2.5 and 5.2.6 both give their distribution point the syntax and
     * encoding conventions section 4.2.1.13 states, and there naming a distribution point relative
     * to the CRL issuer is a SHOULD NOT, so this is a warning rather than an error. One requirement
     * over two carriers, so one row reads both and the context names which it read. The MUST NOT
     * stated beside it is conditioned on cRLIssuer carrying more than one name; an
     * IssuingDistributionPoint has no cRLIssuer field, and section 5.2.6 requires freshestCRL to
     * omit its own, so that sentence cannot reach a CRL either way. */
    message: "a distribution point name should not be given relative to the CRL issuer",
    appliesTo: function (crl) {
      return !!_crlExtByName(crl, "issuingDistributionPoint") || !!_crlExtByName(crl, "freshestCRL");
    },
    check: function (crl) {
      var out = [];
      var e = _crlExtByName(crl, "issuingDistributionPoint");
      if (e && Buffer.isBuffer(e.value)) {
        var idp = pkix.decodeIssuingDistributionPointValue(NS, e.value, _LINT_VALUE_CODE);
        if (!idp.malformed && idp.distributionPoint && idp.distributionPoint.kind === "rdn") {
          out.push({ context: { extension: "issuingDistributionPoint", form: "nameRelativeToCRLIssuer" } });
        }
      }
      var dps = _crlDecodedExtension(crl, "freshestCRL");
      if (dps) {
        dps.forEach(function (dp, i) {
          if (!dp.distributionPoint || dp.distributionPoint.kind !== "rdn") return;
          out.push({ context: { extension: "freshestCRL", index: i, form: "nameRelativeToCRLIssuer" } });
        });
      }
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/delta-number-not-advancing", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.4",
    message: "a delta CRL's cRLNumber must be greater than its baseCRLNumber",
    appliesTo: function (crl) { return !!_crlExtByName(crl, "deltaCRLIndicator"); },
    check: function (crl) {
      var num = _crlExtByName(crl, "cRLNumber");
      var base = _crlIntegerValue(_crlExtByName(crl, "deltaCRLIndicator").value);
      if (base === null || !num || typeof num.value !== "bigint") return null;
      return num.value > base ? null : { context: { crlNumber: String(num.value), baseCRLNumber: String(base) } };
    },
  },
  {
    id: "lint/rfc5280-crl/remove-from-crl-outside-delta", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.3.1",
    message: "the removeFromCRL reason code may appear only in a delta CRL",
    appliesTo: function (crl) { return !_crlExtByName(crl, "deltaCRLIndicator"); },
    check: function (crl) {
      var out = [];
      (crl.revokedCertificates || []).forEach(function (row, i) {
        (row.crlEntryExtensions || []).forEach(function (e) {
          if (e.oid === oid.byName("reasonCode") && Number(e.value) === 8) out.push({ context: { entry: i } });
        });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/freshest-in-delta", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2.6",
    message: "the freshestCRL extension must not appear in a delta CRL",
    appliesTo: function (crl) { return !!_crlExtByName(crl, "deltaCRLIndicator"); },
    check: function (crl) { return _crlExtByName(crl, "freshestCRL") ? true : null; },
  },
  {
    id: "lint/rfc5280-crl/extension-value-syntax", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2 / 5.3",
    message: "a recognized extension's value does not read as the structure its identifier names",
    /** @internal Recognizing an extension by its identifier says only that the profile names it.
     * Without this, a critical extension the profile recognizes but whose value no consumer can
     * process reports clean: the criticality row is satisfied and the unknown-critical row does not
     * fire, because the identifier IS known. Both scopes are walked. */
    check: function (crl) {
      var out = [];
      _crlExtList(crl).forEach(function (e) {
        var why = _valueSyntaxFault(e, CRL_KNOWN_EXTENSIONS, CRL_VALUE_READER);
        if (why) out.push({ context: { extension: e.name || e.oid, scope: "crlExtensions", reason: why } });
      });
      (crl.revokedCertificates || []).forEach(function (row, i) {
        (row.crlEntryExtensions || []).forEach(function (e) {
          var why = _valueSyntaxFault(e, CRL_ENTRY_CRITICALITY, CRL_ENTRY_VALUE_READER);
          if (why) out.push({ context: { extension: e.name || e.oid, scope: "crlEntryExtensions", entry: i, reason: why } });
        });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc5280-crl/unknown-critical-extension", severity: "error", source: "rfc5280-crl", citation: "RFC 5280 5.2 / 5.3",
    message: "a critical extension is not recognized by the profile -- a conforming consumer must not use the CRL",
    /** @internal Sections 5.2 and 5.3 state the same obligation, once for the CRL's extensions and
     * once for a revoked entry's, so both lists are walked. The recognized set for each scope is
     * the extensions that section profiles, which is exactly the table its criticality rule keys
     * on. The certificate registry cannot answer here: it does not recognize deltaCRLIndicator or
     * issuingDistributionPoint, which section 5.2 REQUIRES to be critical, and it does recognize
     * certificate-only extensions that have no meaning on a CRL. */
    check: function (crl) {
      var out = [];
      _crlExtList(crl).forEach(function (e) {
        if (e.critical === true && CRL_KNOWN_EXTENSIONS[e.oid] === undefined) {
          out.push({ context: { oid: e.oid, name: e.name || null, scope: "crlExtensions" } });
        }
      });
      (crl.revokedCertificates || []).forEach(function (row, i) {
        (row.crlEntryExtensions || []).forEach(function (e) {
          if (e.critical === true && CRL_ENTRY_CRITICALITY[e.oid] === undefined) {
            out.push({ context: { oid: e.oid, name: e.name || null, scope: "crlEntryExtensions", entry: i } });
          }
        });
      });
      return out.length ? out : null;
    },
  },
];

var CRL_PROFILES = Object.assign(Object.create(null), { "rfc5280-crl": RFC5280_CRL_RULES });
var ALL_CRL_RULES = RFC5280_CRL_RULES;


/** @internal The extensions RFC 6960 and RFC 9654 place on a response, by the list each belongs
 * in. The nonce and the extended revoked definition are response extensions; the archive cutoff and
 * the CRL references are single extensions, and sec. 4.4.5 carries every RFC 5280 sec. 5.3 CRL
 * entry extension into a SingleResponse as well. Three more are defined for REQUESTS only. */
var OCSP_RESPONSE_KNOWN = Object.create(null);
["ocspNonce", "ocspExtendedRevoke"].forEach(function (n) { OCSP_RESPONSE_KNOWN[oid.byName(n)] = true; });
var OCSP_SINGLE_KNOWN = Object.create(null);
["ocspArchiveCutoff", "ocspCrl", "reasonCode", "invalidityDate", "certificateIssuer"]
  .forEach(function (n) { OCSP_SINGLE_KNOWN[oid.byName(n)] = true; });
var OCSP_REQUEST_ONLY = ocspSchema.extensionPlacement(oid).requestOnly;
/** @internal Only the criticality a clause states. Sec. 4.4.8 forbids a critical extended revoked
 * definition; sec. 4.4.5 carries the RFC 5280 sec. 5.3 rules for the three entry extensions. RFC
 * 6960 states nothing about the criticality of the nonce, the archive cutoff or the CRL references,
 * so they are absent here. */
var OCSP_RESPONSE_CRITICALITY = Object.create(null);
OCSP_RESPONSE_CRITICALITY[oid.byName("ocspExtendedRevoke")] = false;
var OCSP_SINGLE_CRITICALITY = CRL_ENTRY_CRITICALITY;

var OID_OCSP_NONCE = oid.byName("ocspNonce");
var OID_OCSP_EXTENDED_REVOKE = oid.byName("ocspExtendedRevoke");
var OID_OCSP_ARCHIVE_CUTOFF = oid.byName("ocspArchiveCutoff");
var OID_OCSP_CRL = oid.byName("ocspCrl");
var OID_REASON_CODE = oid.byName("reasonCode");

/** @internal How each single extension the OCSP parser leaves opaque is read: reasonCode and
 * invalidityDate through the CRL parser's own entry-extension reader, so the linter and the CRL
 * parser cannot disagree about what a well-formed one is, and certificateIssuer through the shared
 * GeneralNames walk the CRL rows use. The parser decodes the nonce, the archive cutoff and the CRL
 * references itself and refuses a malformed one, so an entry for any of those would be dead. */
var OCSP_SINGLE_VALUE_READER = Object.create(null);
OCSP_SINGLE_VALUE_READER[OID_REASON_CODE] = function (bytes) {
  crlSchema.decodeExt({ oid: OID_REASON_CODE, name: "reasonCode", critical: false, value: bytes });
};
OCSP_SINGLE_VALUE_READER[oid.byName("invalidityDate")] = function (bytes) {
  crlSchema.decodeExt({ oid: oid.byName("invalidityDate"), name: "invalidityDate", critical: false, value: bytes });
};
OCSP_SINGLE_VALUE_READER[oid.byName("certificateIssuer")] = CRL_ENTRY_VALUE_READER[oid.byName("certificateIssuer")];
var OCSP_RESPONSE_VALUE_READER = Object.create(null);
/** @internal Read through the codec's NULL reader, which refuses content octets as well as a wrong
 * tag; the decoder alone frames `05 01 00` as a NULL carrying one octet. */
OCSP_RESPONSE_VALUE_READER[OID_OCSP_EXTENDED_REVOKE] = function (bytes) {
  asn1.read.nullValue(asn1.decode(bytes));
};

function _ocspBasic(resp) { return resp.basicResponse; }
/** @internal The parser refuses an empty `responses`, so the list is never empty here. */
function _ocspResponses(resp) { return _ocspBasic(resp).responses; }
function _ocspResponseExts(resp) { return _ocspBasic(resp).responseExtensions || []; }
function _ocspSingleExts(sr) { return sr.singleExtensions || []; }
function _extIn(list, dotted) {
  for (var i = 0; i < list.length; i++) { if (list[i].oid === dotted) return list[i]; }
  return null;
}
/** @internal The revocation reason a single extension carries, read with the CRL parser's reader,
 * or null when the extension is absent or does not read (the value-syntax row reports that). */
function _singleReasonCode(sr) {
  var e = _extIn(_ocspSingleExts(sr), OID_REASON_CODE);
  if (!e || !Buffer.isBuffer(e.value)) return null;
  // allow:swallow-unverified a value the CRL reader refuses carries no reason; the value-syntax row reports it
  try { return crlSchema.decodeExt(e).value; }
  catch (_e) { return null; }
}
/** @internal RFC 6960 sec. 2.2 gives a "revoked" answer for a non-issued certificate a fixed shape:
 * the reason certificateHold and the revocation time January 1, 1970. That shape is how a response
 * says it is answering for a certificate that was never issued, and the rows that hold such an
 * answer to the rest of sec. 2.2 recognize it by exactly those two values. */
function _isNonIssuedShape(sr) {
  var st = sr.certStatus;
  return !!st && st.type === "revoked" && st.revocationReason === "certificateHold" &&
    guard.time.isDate(st.revocationTime) && guard.time.instantOf(st.revocationTime) === 0;
}
/** @internal The rows in one list that carry a per-response index, so a finding names which
 * SingleResponse it is about the way the CRL entry rows name their entry. */
function _perResponse(resp, fn) {
  var rows = [];
  _ocspResponses(resp).forEach(function (sr, i) {
    var out = fn(sr, i);
    if (out == null) return;
    (Array.isArray(out) ? out : [out]).forEach(function (row) { row.context.response = i; rows.push(row); });
  });
  return rows.length ? rows : null;
}
/** @internal A CertID as one lookup key, every field included, so two SingleResponses name the same
 * certificate under the same hash exactly when their keys match. Keyed rather than compared
 * pairwise: a response lists as many SingleResponses as its author chooses, and this verb exists to
 * survey ones that arrived from elsewhere, so a pairwise scan would be quadratic in that choice. */
function _certIdKey(c) {
  return c.hashAlgorithm.algorithm + "|" + c.issuerNameHash.toString("hex") + "|" + c.issuerKeyHash.toString("hex") + "|" + c.serialNumberHex;
}
function _statusKey(st) {
  return st.type + (st.type === "revoked" ? ":" + guard.time.instantOf(st.revocationTime) + ":" + (st.revocationReason || "") : "");
}
/** @internal The placement rows share one shape: an extension found in the list the specification
 * does not define it for. `where` names the list it was found in; `context.placed` says where the
 * specification puts it. */
function _placementRow(name, placed, where) {
  return { context: { extension: name, placed: placed, was: where } };
}

/** @internal Four sec. 4.2 rules have no row because the strict parser refuses them first and a rule
 * for them would be dead: a version other than v1 (sec. 4.2.2.3, `ocsp/bad-version`), an undefined
 * CRLReason value (`ocsp/bad-revocation-reason`), an empty extension list (`ocsp/bad-extensions`)
 * and a repeated extension (`ocsp/duplicate-extension`); so are an empty `responses`
 * (`ocsp/bad-responses`), a nonce outside 1..128 octets (`ocsp/bad-nonce`), a malformed archive
 * cutoff or CrlID, a responseStatus that disagrees with responseBytes, and every time-format rule of
 * RFC 5019 sec. 2.2.4, which the DER codec enforces. Each reaches a caller as the engine's fatal
 * lint/unparseable carrying that code. */
var RFC6960_OCSP_RULES = [
  {
    id: "lint/rfc6960/signature-empty", severity: "error", source: "rfc6960", citation: "RFC 6960 2.2",
    message: "a definitive response shall be digitally signed; the signature BIT STRING is empty",
    check: function (resp) { return _ocspBasic(resp).signature.length === 0 ? true : null; },
  },
  {
    id: "lint/rfc6960/update-times-inverted", severity: "error", source: "rfc6960", citation: "RFC 6960 2.4 / 4.2.2.1",
    /** @internal Sec. 4.2.2.1 defines the two as a validity interval and says it corresponds to the
     * CRL's, whose inversion the CRL profile grades the same way; an interval whose end precedes
     * its start is a fault of definition, like an extension on the wrong list, rather than a
     * reading, and pki.ocsp.sign refuses to write one. */
    message: "a SingleResponse's thisUpdate must not follow its nextUpdate",
    check: function (resp) {
      return _perResponse(resp, function (sr) {
        // allow:nan-date-comparison-unguarded -- both are codec-parsed OCSP times (asn1 readTime rejects a NaN instant).
        if (sr.nextUpdate === null) return null;
        return guard.time.instantOf(sr.thisUpdate) > guard.time.instantOf(sr.nextUpdate) ? { context: {} } : null;
      });
    },
  },
  {
    id: "lint/rfc6960/produced-before-this-update", severity: "notice", source: "rfc6960", citation: "RFC 6960 2.4 / 2.5",
    /** @internal producedAt is the time the responder signed, thisUpdate the most recent time the
     * status was known to be correct; a response signed before that time certifies status it did
     * not yet know. No clause forbids it, so this is advisory. */
    message: "producedAt is earlier than a SingleResponse's thisUpdate, so the response was signed before the status it certifies was known",
    check: function (resp) {
      var produced = _ocspBasic(resp).producedAt;
      return _perResponse(resp, function (sr) {
        // allow:nan-date-comparison-unguarded -- both are codec-parsed OCSP times (asn1 readTime rejects a NaN instant).
        return guard.time.instantOf(produced) < guard.time.instantOf(sr.thisUpdate) ? { context: {} } : null;
      });
    },
  },
  {
    id: "lint/rfc6960/certs-present-but-empty", severity: "warn", source: "rfc6960", citation: "RFC 6960 4.2.1",
    message: "certs should be absent when no certificates are included",
    check: function (resp) { var bs = _ocspBasic(resp); return bs.certsPresent === true && bs.certs.length === 0 ? true : null; },
  },
  {
    id: "lint/rfc6960/response-extension-criticality", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4.8",
    message: "a response extension is marked with a criticality the profile does not allow",
    check: function (resp) {
      var rows = _criticalityRows(_ocspResponseExts(resp), OCSP_RESPONSE_CRITICALITY, "responseExtensions");
      return rows.length ? rows : null;
    },
  },
  {
    id: "lint/rfc6960/single-extension-criticality", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4.5 / RFC 5280 5.3.1 / 5.3.2 / 5.3.3",
    message: "a single extension is marked with a criticality the profile does not allow",
    check: function (resp) {
      return _perResponse(resp, function (sr) { return _criticalityRows(_ocspSingleExts(sr), OCSP_SINGLE_CRITICALITY, "singleExtensions"); });
    },
  },
  {
    id: "lint/rfc6960/extended-revoke-value-not-null", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4.8",
    message: "the value of the extended revoked definition extension shall be NULL",
    check: function (resp) {
      var e = _extIn(_ocspResponseExts(resp), OID_OCSP_EXTENDED_REVOKE);
      return e && _valueSyntaxFault(e, OCSP_RESPONSE_KNOWN, OCSP_RESPONSE_VALUE_READER) !== null ? true : null;
    },
  },
  {
    id: "lint/rfc6960/extended-revoke-in-single-extensions", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4.8",
    message: "the extended revoked definition extension must be placed in responseExtensions and must not appear in singleExtensions",
    check: function (resp) {
      return _perResponse(resp, function (sr) {
        return _extIn(_ocspSingleExts(sr), OID_OCSP_EXTENDED_REVOKE) ? _placementRow("ocspExtendedRevoke", "responseExtensions", "singleExtensions") : null;
      });
    },
  },
  {
    id: "lint/rfc6960/non-issued-without-extended-revoke", severity: "error", source: "rfc6960", citation: "RFC 6960 2.2",
    message: "a revoked answer for a non-issued certificate (certificateHold at January 1, 1970) must be accompanied by the extended revoked definition response extension",
    check: function (resp) {
      if (_extIn(_ocspResponseExts(resp), OID_OCSP_EXTENDED_REVOKE)) return null;
      return _perResponse(resp, function (sr) { return _isNonIssuedShape(sr) ? { context: {} } : null; });
    },
  },
  {
    id: "lint/rfc6960/non-issued-with-crl-extensions", severity: "error", source: "rfc6960", citation: "RFC 6960 2.2",
    message: "a revoked answer for a non-issued certificate must not include a CRL references extension or any CRL entry extension",
    check: function (resp) {
      return _perResponse(resp, function (sr) {
        if (!_isNonIssuedShape(sr)) return null;
        var rows = [];
        _ocspSingleExts(sr).forEach(function (e) {
          if (e.oid === OID_OCSP_CRL || CRL_ENTRY_CRITICALITY[e.oid] !== undefined) rows.push({ context: { extension: e.name } });
        });
        return rows.length ? rows : null;
      });
    },
  },
  {
    id: "lint/rfc6960/archive-cutoff-in-response-extensions", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4.4",
    message: "an archive cutoff shall be provided as a singleExtensions extension",
    check: function (resp) {
      return _extIn(_ocspResponseExts(resp), OID_OCSP_ARCHIVE_CUTOFF) ? _placementRow("ocspArchiveCutoff", "singleExtensions", "responseExtensions") : null;
    },
  },
  {
    id: "lint/rfc6960/crl-references-in-response-extensions", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4.2",
    message: "the CRL references extension is specified as a singleExtensions extension",
    check: function (resp) {
      return _extIn(_ocspResponseExts(resp), OID_OCSP_CRL) ? _placementRow("ocspCrl", "singleExtensions", "responseExtensions") : null;
    },
  },
  {
    id: "lint/rfc6960/nonce-in-single-extensions", severity: "error", source: "rfc6960", citation: "RFC 9654 2.1",
    message: "in a response the nonce is included as one of the responseExtensions",
    check: function (resp) {
      return _perResponse(resp, function (sr) {
        return _extIn(_ocspSingleExts(sr), OID_OCSP_NONCE) ? _placementRow("ocspNonce", "responseExtensions", "singleExtensions") : null;
      });
    },
  },
  {
    id: "lint/rfc6960/request-extension-in-response", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4.3 / 4.4.6 / 4.4.7",
    message: "an extension defined for OCSP requests only is carried on a response",
    check: function (resp) {
      var rows = [];
      _ocspResponseExts(resp).forEach(function (e) {
        if (OCSP_REQUEST_ONLY[e.oid] !== undefined) rows.push({ context: { extension: e.name, defined: OCSP_REQUEST_ONLY[e.oid], was: "responseExtensions" } });
      });
      var per = _perResponse(resp, function (sr) {
        var out = [];
        _ocspSingleExts(sr).forEach(function (e) {
          if (OCSP_REQUEST_ONLY[e.oid] !== undefined) out.push({ context: { extension: e.name, defined: OCSP_REQUEST_ONLY[e.oid], was: "singleExtensions" } });
        });
        return out.length ? out : null;
      });
      if (per) per.forEach(function (row) { rows.push(row); });
      return rows.length ? rows : null;
    },
  },
  {
    id: "lint/rfc6960/archive-cutoff-after-produced-at", severity: "notice", source: "rfc6960", citation: "RFC 6960 4.4.4",
    /** @internal The archive cutoff is defined as producedAt minus the responder's retention
     * interval, so a cutoff after producedAt states a negative interval. Stated by definition
     * rather than as a requirement, so advisory. */
    message: "an archive cutoff later than producedAt implies a negative retention interval",
    check: function (resp) {
      var produced = _ocspBasic(resp).producedAt;
      return _perResponse(resp, function (sr) {
        var e = _extIn(_ocspSingleExts(sr), OID_OCSP_ARCHIVE_CUTOFF);
        // allow:nan-date-comparison-unguarded -- both are codec-parsed OCSP times (the parser refuses an archive cutoff that is not a GeneralizedTime).
        if (!e) return null;
        return guard.time.instantOf(e.archiveCutoff) > guard.time.instantOf(produced) ? { context: {} } : null;
      });
    },
  },
  {
    id: "lint/rfc6960/extension-value-syntax", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4.5 / 4.4.8",
    message: "a recognized extension's value does not decode as the structure its identifier names",
    check: function (resp) {
      var rows = [];
      _ocspResponseExts(resp).forEach(function (e) {
        var why = _valueSyntaxFault(e, OCSP_RESPONSE_KNOWN, OCSP_RESPONSE_VALUE_READER);
        if (why !== null) rows.push({ context: { extension: e.name, scope: "responseExtensions", problem: why } });
      });
      var per = _perResponse(resp, function (sr) {
        var out = [];
        _ocspSingleExts(sr).forEach(function (e) {
          var why = _valueSyntaxFault(e, OCSP_SINGLE_KNOWN, OCSP_SINGLE_VALUE_READER);
          if (why !== null) out.push({ context: { extension: e.name, scope: "singleExtensions", problem: why } });
        });
        return out.length ? out : null;
      });
      if (per) per.forEach(function (row) { rows.push(row); });
      return rows.length ? rows : null;
    },
  },
  {
    id: "lint/rfc6960/unknown-critical-extension", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4 / RFC 5019 2.2.1",
    /** @internal RFC 6960 adopts the RFC 5280 extension model, under which a consumer that cannot
     * process a critical extension must not use the structure, and RFC 5019 lets a client ignore
     * only an unrecognized NON-critical response extension. The recognized set is the one this
     * profile reads, per list. */
    message: "a critical extension the profile does not recognize is present",
    check: function (resp) {
      var rows = [];
      _ocspResponseExts(resp).forEach(function (e) {
        if (e.critical === true && OCSP_RESPONSE_KNOWN[e.oid] === undefined) rows.push({ context: { extension: e.name || e.oid, scope: "responseExtensions" } });
      });
      var per = _perResponse(resp, function (sr) {
        var out = [];
        _ocspSingleExts(sr).forEach(function (e) {
          if (e.critical === true && OCSP_SINGLE_KNOWN[e.oid] === undefined) out.push({ context: { extension: e.name || e.oid, scope: "singleExtensions" } });
        });
        return out.length ? out : null;
      });
      if (per) per.forEach(function (row) { rows.push(row); });
      return rows.length ? rows : null;
    },
  },
  /** @internal The two reason rules each have two carriers graded apart. The reasonCode single
   * extension IS the RFC 5280 sec. 5.3.1 extension, carried into a SingleResponse by sec. 4.4.5, so
   * its rows grade at that clause's strength. RevokedInfo's own revocationReason is a separate field
   * of the same CRLReason type, and the clause is applied to it by reading, so its rows are advisory. */
  {
    id: "lint/rfc6960/reason-code-unspecified", severity: "warn", source: "rfc6960", citation: "RFC 6960 4.4.5 / RFC 5280 5.3.1",
    message: "a reasonCode single extension of unspecified(0) should be absent instead",
    check: function (resp) { return _perResponse(resp, function (sr) { return _singleReasonCode(sr) === 0 ? { context: {} } : null; }); },
  },
  {
    id: "lint/rfc6960/remove-from-crl-reason", severity: "error", source: "rfc6960", citation: "RFC 6960 4.4.5 / RFC 5280 5.3.1",
    message: "a reasonCode of removeFromCRL may only appear in a delta CRL; a status response is not one",
    check: function (resp) { return _perResponse(resp, function (sr) { return _singleReasonCode(sr) === 8 ? { context: {} } : null; }); },
  },
  {
    id: "lint/rfc6960/revocation-reason-unspecified", severity: "notice", source: "rfc6960", citation: "RFC 6960 4.2.1 / RFC 5280 5.3.1",
    message: "a revocationReason of unspecified(0) states no reason; the reasonCode extension it mirrors should be absent instead",
    check: function (resp) {
      return _perResponse(resp, function (sr) {
        return sr.certStatus.type === "revoked" && sr.certStatus.revocationReason === "unspecified" ? { context: {} } : null;
      });
    },
  },
  {
    id: "lint/rfc6960/revocation-reason-remove-from-crl", severity: "notice", source: "rfc6960", citation: "RFC 6960 4.2.1 / RFC 5280 5.3.1",
    message: "a revocationReason of removeFromCRL names a delta-CRL action, which a status response cannot state",
    check: function (resp) {
      return _perResponse(resp, function (sr) {
        return sr.certStatus.type === "revoked" && sr.certStatus.revocationReason === "removeFromCRL" ? { context: {} } : null;
      });
    },
  },
  {
    id: "lint/rfc6960/duplicate-cert-id", severity: "notice", source: "rfc6960", citation: "RFC 6960 4.2.2.3",
    /** @internal A response carries a SingleResponse per certificate. Two for the same CertID
     * answer one certificate twice, and when the two statuses differ a relying party cannot tell
     * which governs; the context says which case it is. No clause forbids the repeat, so advisory. */
    message: "two SingleResponses answer for the same CertID",
    check: function (resp) {
      var rows = [], first = Object.create(null);
      _ocspResponses(resp).forEach(function (sr, i) {
        var key = _certIdKey(sr.certID), seen = first[key];
        if (seen === undefined) { first[key] = { index: i, status: _statusKey(sr.certStatus) }; return; }
        rows.push({ context: { response: i, first: seen.index, conflicting: seen.status !== _statusKey(sr.certStatus) } });
      });
      return rows.length ? rows : null;
    },
  },
];

/** @internal Nothing in a response says which profile its responder follows, so the RFC 5019 rows
 * run only when that profile is selected and count as not applicable otherwise. */
function _isLightweight(resp, ctx) { return ctx.profile === "rfc5019"; }

var RFC5019_OCSP_RULES = [
  {
    id: "lint/rfc5019/next-update-missing", severity: "error", source: "rfc5019", citation: "RFC 5019 2.2.4",
    message: "a lightweight-profile responder must always include nextUpdate",
    appliesTo: _isLightweight,
    check: function (resp) { return _perResponse(resp, function (sr) { return sr.nextUpdate == null ? { context: {} } : null; }); },
  },
  {
    id: "lint/rfc5019/multiple-single-responses", severity: "warn", source: "rfc5019", citation: "RFC 5019 2.2.1",
    message: "a lightweight-profile response should include only one SingleResponse",
    appliesTo: _isLightweight,
    check: function (resp) { var n = _ocspResponses(resp).length; return n > 1 ? { context: { responses: n } } : null; },
  },
  {
    id: "lint/rfc5019/response-extensions-present", severity: "warn", source: "rfc5019", citation: "RFC 5019 2.2.1",
    message: "a lightweight-profile responder should not include responseExtensions",
    appliesTo: _isLightweight,
    check: function (resp) { return _ocspBasic(resp).responseExtensions ? true : null; },
  },
  {
    id: "lint/rfc5019/responder-id-by-name", severity: "notice", source: "rfc5019", citation: "RFC 5019 2.2.2",
    /** @internal A SHOULD conditioned on bandwidth being at issue, which the response cannot show,
     * so it grades as advisory rather than as the warning an unconditional SHOULD would draw. */
    message: "a lightweight-profile responder should use the byKey ResponderID where reducing bandwidth matters",
    appliesTo: _isLightweight,
    check: function (resp) { var rid = _ocspBasic(resp).responderID; return rid && rid.byName !== undefined ? true : null; },
  },
];

var OCSP_PROFILES = Object.assign(Object.create(null), { "rfc6960": RFC6960_OCSP_RULES, "rfc5019": RFC5019_OCSP_RULES });
var ALL_OCSP_RULES = RFC6960_OCSP_RULES.concat(RFC5019_OCSP_RULES);

/** @internal The extensions an issuer determines, which a request may carry and a CA does not take
 *  from one. subjectKeyIdentifier and authorityKeyIdentifier are computed from the keys, and the
 *  three pointers name services the issuer operates. A request for any of them is not a fault in
 *  the request, so these are reported at notice: the CA simply does not honor them. */
var CA_DETERMINED_EXTENSIONS = [
  "authorityKeyIdentifier", "subjectKeyIdentifier", "authorityInfoAccess",
  "cRLDistributionPoints", "freshestCRL",
];

/** @internal The signature algorithms a request must not be signed under. A certification request
 *  is signed by the requester's own key, and the signature is the only evidence the requester
 *  holds it, so a collision-broken digest removes the one thing the structure proves. */
var WEAK_CSR_SIG_DIGESTS = ["md2", "md4", "md5", "sha1"];

/** @internal Named outright, because reading the digest out of the algorithm's NAME misses the one
 *  whose name does not carry it: `shaWithRSAEncryption` is the original SHA, now SHA-0, and it
 *  spells neither "sha1" nor any other substring above. The set is resolved through the registry
 *  rather than written as OIDs, so a name that stops resolving fails the round-trip gate in
 *  oid.test.js rather than silently dropping out of this set. */
var WEAK_CSR_SIG_OIDS = Object.create(null);
["shaWithRSAEncryption",
  "md2WithRSAEncryption", "md4WithRSAEncryption", "md4WithRSAEncryption-pkcs1",
  "md5WithRSAEncryption", "sha1WithRSAEncryption",
  "md4WithRSA", "md5WithRSA",
  "md2WithRSASignature", "md5WithRSASignature", "sha1WithRSASignature",
  "ecdsaWithSHA1", "dsaWithSha1",
].forEach(function (n) { var d = oid.byName(n); if (d) WEAK_CSR_SIG_OIDS[d] = n; });

/** @internal RSASSA-PSS carries its digest in the parameters rather than in the algorithm name, so
 *  the name alone never reads as weak. RFC 4055 sec. 3.1 makes the hashAlgorithm `[0]` field
 *  DEFAULT sha1, which means ABSENT parameters and an empty parameter SEQUENCE both name SHA-1:
 *  the shape that looks like it says nothing is the one that says the weakest thing. */
function _pssDigestName(sigAlg) {
  if (!sigAlg || sigAlg.oid !== oid.byName("rsassaPss")) return null;
  var params = sigAlg.parameters;
  if (params === null || params === undefined) return "sha1";
  var node;
  try { node = asn1.decode(params); }
  // allow:swallow-unverified parameters that do not decode are reported by the value-syntax path
  catch (_e) { return null; }
  if (!node || node.tagNumber !== asn1.TAGS.SEQUENCE || !node.children) return null;
  for (var i = 0; i < node.children.length; i++) {
    var c = node.children[i];
    if (c.tagClass !== "context" || c.tagNumber !== 0) continue;
    var inner = c.children && c.children[0];
    if (!inner || !inner.children || !inner.children[0]) return null;
    var dotted;
    try { dotted = asn1.read.oid(inner.children[0]); }
    // allow:swallow-unverified a hashAlgorithm that does not read is not a digest this names
    catch (_e2) { return null; }
    return oid.name(dotted) || dotted;
  }
  return "sha1";
}

var RFC2986_CSR_RULES = [
  {
    id: "lint/rfc2986/subject-empty-no-identity", severity: "error", source: "rfc2986", citation: "RFC 5280 sec. 4.1.2.6",
    /** @internal Section 4.1.2.6 admits an empty subject only where the subjectAltName carries the
     * identity instead. A request with neither names nothing to certify, so there is no name for
     * the issuer to put in the certificate. */
    message: "a request with an empty subject must request a subjectAltName, or it names nothing to certify",
    check: function (csr, ctx) {
      if (_subjectIsNonEmpty(csr)) return null;
      var san = ctx.decode("subjectAltName");
      return (san && san.value && san.value.names && san.value.names.length) ? null : true;
    },
  },
  {
    id: "lint/rfc2986/san-not-critical-empty-subject", severity: "error", source: "rfc2986", citation: "RFC 5280 sec. 4.1.2.6 / 4.2.1.6",
    /** @internal "If the subject field contains an empty sequence, then the issuing CA MUST
     * include a subjectAltName extension that is marked as critical." A request whose only
     * identity is a non-critical SAN asks for a certificate the profile refuses. */
    message: "where the subject is empty the requested subjectAltName must be critical",
    check: function (csr, ctx) {
      if (_subjectIsNonEmpty(csr)) return null;
      var san = ctx.decode("subjectAltName");
      if (!san || !san.value || !san.value.names || !san.value.names.length) return null;
      return san.critical === true ? null : true;
    },
  },
  {
    id: "lint/rfc2986/ca-determined-extension-requested", severity: "notice", source: "rfc2986", citation: "RFC 5280 sec. 4.2.1.1 / 4.2.1.2 / 4.2.2",
    message: "the request asks for an extension the issuer determines, which a CA does not take from a request",
    check: function (csr, ctx) {
      var out = [];
      CA_DETERMINED_EXTENSIONS.forEach(function (name) {
        if (ctx.raw(name)) out.push({ context: { extension: name } });
      });
      return out.length ? out : null;
    },
  },
  {
    id: "lint/rfc2986/basic-constraints-ca-requested", severity: "warn", source: "rfc2986", citation: "RFC 5280 sec. 4.2.1.9",
    /** @internal A subscriber request asking for cA TRUE is the request that turns a subscriber
     * into an issuer if it is honored, so it is named rather than passed over. It is a warning
     * and not an error because a CA legitimately issues intermediates from a request. */
    message: "the request asks for a CA certificate (basicConstraints cA TRUE)",
    check: function (csr, ctx) {
      var bc = ctx.decode("basicConstraints");
      return (bc && bc.value && bc.value.cA === true) ? { context: { pathLenConstraint: bc.value.pathLenConstraint } } : null;
    },
  },
  {
    id: "lint/rfc2986/weak-signature-algorithm", severity: "error", source: "rfc2986", citation: "RFC 2986 sec. 4.2",
    message: "the request is signed under a digest no longer fit to carry a proof of possession",
    check: function (csr) {
      var alg = csr.signatureAlgorithm;
      if (alg && WEAK_CSR_SIG_OIDS[alg.oid]) {
        return { context: { signatureAlgorithm: WEAK_CSR_SIG_OIDS[alg.oid], from: "algorithm" } };
      }
      var pss = _pssDigestName(alg);
      var named = pss !== null ? pss : (alg && alg.name);
      if (typeof named !== "string") return null;
      var lower = named.toLowerCase();
      for (var i = 0; i < WEAK_CSR_SIG_DIGESTS.length; i++) {
        if (lower.indexOf(WEAK_CSR_SIG_DIGESTS[i]) !== -1) {
          return { context: { signatureAlgorithm: (alg && alg.name) || (alg && alg.oid),
            digest: WEAK_CSR_SIG_DIGESTS[i], from: pss !== null ? "parameters" : "algorithm" } };
        }
      }
      return null;
    },
  },
  {
    id: "lint/rfc2986/extension-request-ambiguous", severity: "error", source: "rfc2986", citation: "RFC 2985 sec. 5.4.2 / X.501 sec. 8.2",
    /** @internal An attribute type appears once in a SET OF Attributes, and extensionRequest is
     * SINGLE VALUE besides. Two of them parse when they are in DER order, and which one a reader
     * takes then depends on how the bytes happened to sort, so one request reads two ways. Every
     * one of them is linted below, and this row says the request did not ask once. */
    message: "the request carries more than one extensionRequest attribute, so what it asks for depends on which is read",
    check: function (csr) {
      var n = _csrAttributesOf(csr, "extensionRequest").length;
      return n > 1 ? { context: { count: n } } : null;
    },
  },
  {
    id: "lint/rfc2986/challenge-password-present", severity: "notice", source: "rfc2986", citation: "RFC 2985 sec. 5.4.1",
    /** @internal The attribute travels inside the request, so wherever the request is stored or
     * logged the password is too. Reported so an operator knows it is in the artifact, not
     * because the structure is wrong. */
    message: "the request carries a challengePassword, which travels and is stored with it",
    check: function (csr) { return _csrHasAttribute(csr, "challengePassword") ? true : null; },
  },
];

/** @internal The certificate rows that read only the subject, the public key and the requested
 *  subjectAltName, which a request carries too. They are REUSED rather than restated so the
 *  pre-issuance answer cannot drift from the post-issuance one: the row, its severity and its
 *  citation are the certificate profile's own. */
var CABF_TLS_CSR_RULE_IDS = [
  "lint/cabf-tls/san-missing",
  "lint/cabf-tls/cn-not-in-san",
  "lint/cabf-tls/dnsname-bad-syntax",
  "lint/cabf-tls/weak-key",
];

/** @internal RFC 5280 sec. 4.2 fixes each extension's syntax wherever it is carried. Every row in
 *  every profile below asks for an extension BY NAME, and the shared decoder returns null both for
 *  one that is absent and for one whose value does not decode, so without this row a malformed
 *  value reads as absence and passes every row that asks for it. The certificate's own row is
 *  reused rather than restated, and it is folded into each named profile rather than into the
 *  *_RULES arrays, which `ALL_RULES` concatenates and would otherwise report it twice. */
var RFC5280_EXTENSION_SYNTAX_RULES = RFC5280_RULES.filter(function (r) {
  return r.id === "lint/rfc5280/extension-undecodable";
});
var PROFILES = Object.assign(Object.create(null), {
  "rfc5280": RFC5280_RULES,
  "rfc9881": RFC9881_RULES.concat(RFC5280_EXTENSION_SYNTAX_RULES),
  "rfc9909": RFC9909_RULES.concat(RFC5280_EXTENSION_SYNTAX_RULES),
  "rfc9935": RFC9935_RULES.concat(RFC5280_EXTENSION_SYNTAX_RULES),
  "cabf-tls": CABF_TLS_RULES.concat(RFC5280_EXTENSION_SYNTAX_RULES),
  "cabf-smime": CABF_SMIME_RULES.concat(RFC5280_EXTENSION_SYNTAX_RULES),
  "cabf-cs": CABF_CS_RULES.concat(RFC5280_EXTENSION_SYNTAX_RULES),
  "etsi-qc": ETSI_QC_RULES.concat(RFC5280_EXTENSION_SYNTAX_RULES),
  "mozilla-root": MOZILLA_RULES.concat(RFC5280_EXTENSION_SYNTAX_RULES),
});
var ALL_RULES = RFC5280_RULES.concat(RFC9881_RULES).concat(RFC9909_RULES).concat(RFC9935_RULES)
  .concat(CABF_TLS_RULES).concat(CABF_SMIME_RULES).concat(CABF_CS_RULES).concat(ETSI_QC_RULES)
  /** @internal The Mozilla rows are in the registry so `rules()` enumerates them, and stay inert
   * under the default set because each one asks whether the caller named the profile. */
  .concat(MOZILLA_RULES);

var CABF_TLS_CSR_RULES = CABF_TLS_RULES.filter(function (r) {
  return CABF_TLS_CSR_RULE_IDS.indexOf(r.id) !== -1;
});
/** @internal A requested extension whose value does not decode is the same fault in a request as
 *  in a certificate, so the request profiles take the same row the certificate profiles do. */
var CSR_STRUCTURAL_RULES = RFC2986_CSR_RULES.concat(RFC5280_EXTENSION_SYNTAX_RULES);
var CSR_PROFILES = Object.assign(Object.create(null), {
  "rfc2986": CSR_STRUCTURAL_RULES,
  "cabf-tls": CSR_STRUCTURAL_RULES.concat(CABF_TLS_CSR_RULES),
});
var ALL_CSR_RULES = CSR_STRUCTURAL_RULES;

function _subjectIsNonEmpty(csr) {
  var rdns = csr.subject && csr.subject.rdns;
  return !!(Array.isArray(rdns) && rdns.length);
}

function _csrAttributesOf(csr, name) {
  var dotted = oid.byName(name);
  var list = csr.attributes || [];
  var out = [];
  for (var i = 0; i < list.length; i++) { if (list[i].type === dotted) out.push(list[i]); }
  return out;
}
function _csrHasAttribute(csr, name) { return _csrAttributesOf(csr, name).length > 0; }

/** @internal A request read the way the certificate rows read a certificate: the subject and the
 *  public key are the request's own, and `extensions` is what the extensionRequest attribute asked
 *  for. Shaped this way so `_findRaw`, `_decodeOrNull` and the reused CABF rows run unchanged
 *  against a request rather than each restating how to reach a requested extension. */
function _csrViewWith(csr, exts) {
  var view = Object.create(null);
  view.subject = csr.subject;
  view.subjectPublicKeyInfo = csr.subjectPublicKeyInfo;
  view.signatureAlgorithm = csr.signatureAlgorithm;
  view.attributes = csr.attributes;
  view.extensions = exts;
  return view;
}

/** @internal One view per extensionRequest attribute, rather than one view over all of them
 *  flattened. A rule that asks for an extension BY NAME reads the first match, so flattening lets
 *  a basicConstraints of cA FALSE in one attribute hide a cA TRUE in the next: the value that
 *  decides the answer would be the one that happened to sort first. Each attribute is linted as
 *  the request it states, and the findings are merged. A request carrying one attribute, which is
 *  every conforming one, produces exactly one view and the same answer as before. */
function _csrViews(csr) {
  var attrs = _csrAttributesOf(csr, "extensionRequest");
  if (!attrs.length) return [_csrViewWith(csr, [])];
  return attrs.map(function (attr) {
    return _csrViewWith(csr, Array.isArray(attr.extensions) ? attr.extensions : []);
  });
}

/** @internal The same rule firing on two views of one request is one finding, since the rows that
 *  do not read an extension see the identical request each time. */
function _mergeCsrReports(reports) {
  var findings = [], ran = [], seen = Object.create(null), ranSeen = Object.create(null);
  reports.forEach(function (r) {
    r.findings.forEach(function (f) {
      var key = f.id + "\u0000" + JSON.stringify(f.context === undefined ? null : f.context);
      if (seen[key]) return;
      seen[key] = true;
      findings.push(f);
    });
    r.ran.forEach(function (id) { if (!ranSeen[id]) { ranSeen[id] = true; ran.push(id); } });
  });
  var counts = Object.assign(Object.create(null), { fatal: 0, error: 0, warn: 0, notice: 0, pass: 0, na: 0, ne: 0 });
  var failed = Object.create(null), failedCount = 0;
  findings.forEach(function (f) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    if (!failed[f.id]) { failed[f.id] = true; failedCount += 1; }
  });
  /** @internal A rule that reports twice is still ONE rule that did not pass, which is what
   * `_runLints` counts, so the distinct failing ids come off the executed ones. Subtracting the
   * finding count instead understates `pass` the moment any rule reports more than once. */
  counts.pass = ran.length - failedCount > 0 ? ran.length - failedCount : 0;
  return { findings: findings, counts: counts, ran: ran };
}

/** @internal A request carries no extKeyUsage, so nothing in its bytes says it is for TLS. The
 *  caller names that profile or the TLS rows do not run, which is why `isTlsServerCert` here is
 *  the caller's statement rather than something read off the artifact. */
function _makeCsrCtx(view, profile) {
  var explicitTls = profile === "cabf-tls";
  return {
    profile: profile,
    explicitTlsProfile: explicitTls,
    isTlsServerCert: explicitTls,
    decode: function (name) { return _decodeOrNull(view, name); },
    raw: function (name) { return _findRaw(view, name); },
  };
}

/** @internal The kind-checked door the other lint verbs use, rather than a property test of our
 *  own: a parsed certificate carries a subjectPublicKeyInfo too, so a shape test admits one as a
 *  request and then reads its extensions from an extensionRequest attribute it does not have,
 *  reporting on a request that was never made. */
function _derivedCsr(o) {
  if (!o || typeof o !== "object" || guard.bytes.isByteSource(o)) return null;
  // allow:swallow-unverified an object the guard refuses is not a parsed request, and the byte paths below answer for it
  try { return guard.parsed.acceptDerived(o, "csr", csrSchema.parse, _cfg, "lint/bad-input", "the certification request"); }
  catch (_e) { return null; }
}

function _ingestCsr(input) {
  var derived = _derivedCsr(input);
  if (derived) return { csr: derived };
  var der;
  var bytes = _derBytesOf(input);
  if (bytes !== null && bytes.fatal) return { fatal: bytes.fatal };
  if (bytes !== null) der = bytes.der;
  else if (typeof input === "string") {
    try { der = csrSchema.pemDecode(input); }
    catch (e) { return { fatal: { id: "lint/unparseable", severity: "fatal", source: "engine", citation: "pki.lint", message: "input is not a decodable PEM/DER certification request", context: { code: e.code } } }; }
  } else {
    throw _cfg("lint/bad-input", "pki.lint.csr input must be a parsed certification request, a DER Buffer, or a PEM string");
  }
  try { return { csr: csrSchema.parse(der) }; }
  catch (e) { return { fatal: { id: "lint/unparseable", severity: "fatal", source: "engine", citation: "RFC 2986", message: "input is not a well-formed PKCS#10 certification request", context: { code: e.code } } }; }
}

function _selectRules(profile) {
  if (profile == null || profile === "all" || profile === "default") return ALL_RULES;
  if (!PROFILES[profile]) {
    if (CRL_PROFILES[profile]) throw _cfg("lint/unknown-profile", "\"" + profile + "\" is a CRL profile; lint a CRL with pki.lint.crl");
    if (OCSP_PROFILES[profile]) throw _cfg("lint/unknown-profile", "\"" + profile + "\" is an OCSP profile; lint a response with pki.lint.ocsp");
    throw _cfg("lint/unknown-profile", "unknown lint profile \"" + profile + "\" (known: " + Object.keys(PROFILES).join(", ") + ")");
  }
  return PROFILES[profile];
}

function _applyThreshold(report, severity) {
  var floor = SEVERITY[severity == null ? "notice" : severity];
  return report.findings.filter(function (f) { return (SEVERITY[f.severity] || 0) >= floor; });
}


/**
 * @primitive  pki.lint.certificate
 * @signature  pki.lint.certificate(input, opts?) -> LintReport
 * @since      0.2.10
 * @status     stable
 * @spec       RFC 5280, RFC 9881, RFC 9909, RFC 9935, CA/Browser Forum TLS BR
 * @related    pki.schema.x509.parse, pki.inspect.certificate, pki.path.validate
 *
 * Lint a certificate against the RFC 5280 profile, the post-quantum certificate profiles,
 * and a representative CABF TLS BR subset. `input` is a PEM string, a DER `Buffer`, or an
 * already-parsed
 * `pki.schema.x509` object. Returns a `LintReport`
 * `{ findings: [{id, severity, source, citation, message, context?}], counts, worst, ran }`.
 *
 * The data path never throws: hostile bytes produce a single `fatal` finding
 * `lint/unparseable` and no exception. The one throw path is config-time misuse
 * (`opts.profile` unknown, `opts.severity` out of range, or a wrong-type input), which
 * raises a typed `LintError`.
 *
 * @opts  profile   One of `pki.lint.profiles()` (default runs every profile). Selecting
 *                  `"cabf-tls"` lints the input AS a TLS SUBSCRIBER certificate, which is an
 *                  assertion about the input rather than a question asked of it: the section
 *                  7.1.2.7 rows then apply whatever the certificate says it is, so naming it for
 *                  a CA certificate reports that CA against subscriber requirements. The CA
 *                  profiles of section 7.1.2.10 are a separate set this does not yet carry. Left
 *                  unnamed, a certificate is held to those rows only where it asserts
 *                  id-kp-serverAuth and is not a CA.
 * @opts  severity  Suppress findings below this floor (default `"notice"`). `counts` and
 *                  `worst` always reflect the complete, unfiltered result.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var pemString = await pki.x509.sign({ subject: "example.com", subjectPublicKey: await pki.key.export(pair.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { key: await pki.key.export(pair.privateKey) }, { pem: true });
 *   var report = pki.lint.certificate(pemString);
 *   report.worst;                              // "notice" | "error" | ...
 *   report.findings.map(function (f) { return f.id; });
 */
var _CERTIFICATE_OPTS = Object.assign(Object.create(null), { profile: 1, severity: 1 });

function certificate(input, opts) {
  opts = guard.identifier.optionsObject(opts, _cfg, "lint/bad-input", "pki.lint options");
  guard.identifier.assertKnownKeys(opts, _CERTIFICATE_OPTS, _cfg, "lint/bad-input",
    "pki.lint.certificate has an unknown option: ");
  if (opts.severity != null && VALID_SEVERITY.indexOf(opts.severity) === -1) {
    throw _cfg("lint/bad-severity", "unknown severity threshold \"" + opts.severity + "\" (known: " + VALID_SEVERITY.join(", ") + ")");
  }
  var rules = _selectRules(opts.profile);
  var ingested = _ingest(input);
  var report;
  if (ingested.fatal) {
    report = { findings: [ingested.fatal], ran: [],
      counts: Object.assign(Object.create(null), { fatal: 1, error: 0, warn: 0, notice: 0, pass: 0, na: 0, ne: 0 }) };
  } else {
    var ctx = _makeCtx(ingested.cert, opts.profile);
    report = _runLints(rules, ingested.cert, ctx);
  }
  report.worst = _worst(report.findings);
  report.findings = _applyThreshold(report, opts.severity);
  return report;
}

var _CRL_OPTS = Object.assign(Object.create(null), { profile: 1, severity: 1 });

/** @internal The same door the certificate path uses. A parsed CRL is admitted only when the shared
 * guard says it is one, so an object that merely carries a `crlExtensions` property is refused with
 * the typed config error rather than reaching a rule and faulting there. */
function _derivedCrl(o) {
  if (!o || typeof o !== "object" || guard.bytes.isByteSource(o)) return null;
  // allow:swallow-unverified an object the guard refuses is not a parsed CRL, and the byte paths below answer for it
  try {
    var p = guard.parsed.acceptDerived(o, "crl", crlSchema.parse, _cfg, "lint/bad-input", "the CRL");
    return guard.parsed.isCrl(p) ? p : null;
  } catch (_e) {
    return null;
  }
}

function _ingestCrl(input) {
  var derived = _derivedCrl(input);
  if (derived) return { crl: derived };
  var der;
  var bytes = _derBytesOf(input);
  if (bytes !== null && bytes.fatal) return { fatal: bytes.fatal };
  if (bytes !== null) der = bytes.der;
  else if (typeof input === "string") {
    try { der = crlSchema.pemDecode(input); }
    catch (e) { return { fatal: { id: "lint/unparseable", severity: "fatal", source: "engine", citation: "pki.lint", message: "input is not a decodable PEM/DER CRL", context: { code: e.code } } }; }
  } else {
    throw _cfg("lint/bad-input", "pki.lint.crl input must be a parsed CRL, a DER Buffer, or a PEM string");
  }
  try { return { crl: crlSchema.parse(der) }; }
  catch (e) { return { fatal: { id: "lint/unparseable", severity: "fatal", source: "engine", citation: "RFC 5280", message: "input is not a well-formed X.509 CRL", context: { code: e.code } } }; }
}

/**
 * @primitive  pki.lint.crl
 * @signature  pki.lint.crl(pem | der | parsed, opts?) -> LintReport
 * @since      0.7.9
 * @status     stable
 * @spec       RFC 5280 sec. 5
 * @related    pki.lint.certificate, pki.schema.crl.parse, pki.crl.sign
 *
 * Lint a certificate revocation list against the RFC 5280 section 5 profile. `input` is a PEM
 * string, a DER `Buffer`, or an already-parsed `pki.schema.crl` object. It returns the same
 * `LintReport` shape `pki.lint.certificate` returns, and it never throws on the data path:
 * bytes that are not a well-formed CRL produce a single `fatal` finding `lint/unparseable`
 * carrying the strict parser's own code.
 *
 * The rows cover the CRL's update times (nextUpdate presence and ordering), its extensions
 * (cRLNumber presence and length, authorityKeyIdentifier presence and the key identifier method,
 * the criticality every profiled extension is required to carry, the scope an
 * issuingDistributionPoint states, freshestCRL in a delta CRL, and an unrecognized critical
 * extension), and each revoked entry (the serial profile, a reason code against the scope the CRL
 * declares, certificateIssuer, and entry-extension criticality).
 *
 * Six section 5 rules never appear here because the strict parser refuses them first, and a rule
 * for them could not fire. A CRL carrying extensions without the version that admits them
 * (section 5.1.2.1), a `signatureAlgorithm` differing from the `signature` field inside
 * `tbsCertList` (section 5.1.1.2), an empty issuer name (section 5.1.2.3), a present-but-empty
 * `revokedCertificates` (section 5.1.2.6), a date carried in the wrong time type, which is UTCTime
 * through 2049 and GeneralizedTime from 2050 (sections 5.1.2.4, 5.1.2.6 and 5.3.2), and an
 * extension repeated on the CRL or on an entry (section 4.2) each arrive as `lint/unparseable`
 * carrying the parser's own code.
 *
 * @opts  profile   `"rfc5280-crl"`, the only CRL profile (default runs every CRL rule). A
 *                  certificate profile name is refused rather than run against a CRL.
 * @opts  severity  Suppress findings below this floor (default `"notice"`). `counts` and `worst`
 *                  always reflect the complete, unfiltered result.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var crlDer = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"),
 *     nextUpdate: new Date("2026-02-01T00:00:00Z"), crlNumber: 1n },
 *     { name: "Example CA", publicKey: await pki.key.export(pair.publicKey), key: pair.privateKey });
 *   var report = pki.lint.crl(crlDer);
 *   report.worst;                                       // -> "error", for the missing AKI
 *   report.findings.map(function (f) { return f.id; }); // -> ["lint/rfc5280-crl/aki-missing"]
 */
/**
 * @primitive  pki.lint.csr
 * @signature  pki.lint.csr(pem | der | parsed, opts?) -> LintReport
 * @since      0.8.16
 * @status     stable
 * @spec       RFC 2986, RFC 2985 sec. 5.4, RFC 5280 sec. 4.1.2.6, CA/Browser Forum TLS BR
 * @related    pki.lint.certificate, pki.csr.verify, pki.schema.csr.parse, pki.csr.sign
 *
 * Lint a PKCS#10 certification request, which is the artifact a CA reads before it issues. `input`
 * is a PEM string, a DER `Buffer`, or an already-parsed `pki.schema.csr` object. It returns the
 * same `LintReport` shape `pki.lint.certificate` returns, and it never throws on the data path:
 * bytes that are not a well-formed request produce a single `fatal` finding `lint/unparseable`
 * carrying the strict parser's own code.
 *
 * The rows cover what the request asks for: an empty subject and whether a subjectAltName carries
 * the identity in its place, the extensions an issuer determines rather than takes from a request,
 * a request asking for a CA certificate, the digest the request is signed under, and a
 * challengePassword traveling inside it.
 *
 * This does not check the request's signature. That signature is the requester's proof that it
 * holds the private key, verifying it is a cryptographic operation rather than a profile question,
 * and `pki.csr.verify` is the verb for it. A CA runs both.
 *
 * The CA/Browser Forum rows run only under `opts.profile: "cabf-tls"`. A request carries no
 * extKeyUsage, so nothing in its bytes says it is for TLS, and the caller states that. Those rows
 * are the certificate profile's own, applied to what the request asks for, so the answer before
 * issuance is the answer after it.
 *
 * Five shapes never appear here because the strict parser refuses them first and a rule for them
 * could not fire. A version other than 0 (RFC 2986 sec. 4.1), a challengePassword or
 * extensionRequest attribute carrying more than one value, an extensionRequest carrying no
 * extensions (RFC 2985 sec. 5.4), the same extension OID twice inside one, and attributes out of
 * DER order each arrive as `lint/unparseable` carrying the parser's own code. A SECOND
 * extensionRequest attribute does parse, where the two sort in DER order, and is reported by
 * `lint/rfc2986/extension-request-ambiguous`; every one of them is read, so nothing a later
 * attribute asks for escapes the rows below.
 *
 * @opts  profile   `"rfc2986"` for the structural rows alone, or `"cabf-tls"` to add the TLS rows
 *                  (default runs the structural rows). A certificate, CRL or OCSP profile name is
 *                  refused rather than run against a request.
 * @opts  severity  Suppress findings below this floor (default `"notice"`). `counts` and `worst`
 *                  always reflect the complete, unfiltered result.
 * @example
 *   var pair = await pki.key.generate("Ed25519");
 *   var der = await pki.csr.sign({ subject: [{ commonName: "example.com" }],
 *     subjectPublicKey: await pki.key.export(pair.publicKey) },
 *     { key: await pki.key.export(pair.privateKey) });
 *   var report = pki.lint.csr(der, { profile: "cabf-tls" });
 *   report.findings.map(function (f) { return f.id; }); // -> ["lint/cabf-tls/san-missing"]
 */
function csr(input, opts) {
  opts = guard.identifier.optionsObject(opts, _cfg, "lint/bad-input", "pki.lint options");
  guard.identifier.assertKnownKeys(opts, _CRL_OPTS, _cfg, "lint/bad-input",
    "pki.lint.csr has an unknown option: ");
  if (opts.severity != null && VALID_SEVERITY.indexOf(opts.severity) === -1) {
    throw _cfg("lint/bad-severity", "unknown severity threshold \"" + opts.severity + "\" (known: " + VALID_SEVERITY.join(", ") + ")");
  }
  var profile = opts.profile;
  var rules_;
  if (profile == null || profile === "all" || profile === "default") rules_ = ALL_CSR_RULES;
  else if (CSR_PROFILES[profile]) rules_ = CSR_PROFILES[profile];
  else if (CRL_PROFILES[profile]) throw _cfg("lint/unknown-profile", "\"" + profile + "\" is a CRL profile; lint a CRL with pki.lint.crl");
  else if (OCSP_PROFILES[profile]) throw _cfg("lint/unknown-profile", "\"" + profile + "\" is an OCSP profile; lint a response with pki.lint.ocsp");
  else if (PROFILES[profile]) throw _cfg("lint/unknown-profile", "\"" + profile + "\" is a certificate profile; lint a certificate with pki.lint.certificate");
  else throw _cfg("lint/unknown-profile", "unknown certification-request lint profile \"" + profile + "\" (known: " + Object.keys(CSR_PROFILES).join(", ") + ")");

  var ingested = _ingestCsr(input);
  var report;
  if (ingested.fatal) {
    report = { findings: [ingested.fatal], ran: [],
      counts: Object.assign(Object.create(null), { fatal: 1, error: 0, warn: 0, notice: 0, pass: 0, na: 0, ne: 0 }) };
  } else {
    report = _mergeCsrReports(_csrViews(ingested.csr).map(function (view) {
      return _runLints(rules_, view, _makeCsrCtx(view, profile));
    }));
  }
  report.worst = _worst(report.findings);
  report.findings = _applyThreshold(report, opts.severity);
  return report;
}

function crl(input, opts) {
  opts = guard.identifier.optionsObject(opts, _cfg, "lint/bad-input", "pki.lint options");
  guard.identifier.assertKnownKeys(opts, _CRL_OPTS, _cfg, "lint/bad-input",
    "pki.lint.crl has an unknown option: ");
  if (opts.severity != null && VALID_SEVERITY.indexOf(opts.severity) === -1) {
    throw _cfg("lint/bad-severity", "unknown severity threshold \"" + opts.severity + "\" (known: " + VALID_SEVERITY.join(", ") + ")");
  }
  var profile = opts.profile;
  var rules_;
  if (profile == null || profile === "all" || profile === "default") rules_ = ALL_CRL_RULES;
  else if (CRL_PROFILES[profile]) rules_ = CRL_PROFILES[profile];
  else if (PROFILES[profile]) throw _cfg("lint/unknown-profile", "\"" + profile + "\" is a certificate profile; lint a certificate with pki.lint.certificate");
  else if (OCSP_PROFILES[profile]) throw _cfg("lint/unknown-profile", "\"" + profile + "\" is an OCSP profile; lint a response with pki.lint.ocsp");
  else throw _cfg("lint/unknown-profile", "unknown CRL lint profile \"" + profile + "\" (known: " + Object.keys(CRL_PROFILES).join(", ") + ")");

  var ingested = _ingestCrl(input);
  var report;
  if (ingested.fatal) {
    report = { findings: [ingested.fatal], ran: [],
      counts: Object.assign(Object.create(null), { fatal: 1, error: 0, warn: 0, notice: 0, pass: 0, na: 0, ne: 0 }) };
  } else {
    report = _runLints(rules_, ingested.crl, { profile: profile, decode: function () { return null; }, raw: function () { return null; } });
  }
  report.worst = _worst(report.findings);
  report.findings = _applyThreshold(report, opts.severity);
  return report;
}

var _OCSP_OPTS = Object.assign(Object.create(null), { profile: 1, severity: 1 });
var _OCSP_CLAIM = ["responseStatus", "basicResponse", "tbsResponseDataBytes"];

/** @internal The door pki.ocsp.verify uses for a parsed response: a result the parser recorded is
 * re-read from the source it came from, which is the DER when the parser was fed bytes and the PEM
 * text when it was fed a string, and an object that merely carries a response's field names is
 * refused as config-time misuse rather than linted, since its fields could describe different
 * responses. Bytes and PEM take the fatal path below, never a throw. */
function _ingestOcsp(input) {
  var der;
  var bytes = _derBytesOf(input);
  if (bytes !== null && bytes.fatal) return { fatal: bytes.fatal };
  if (bytes !== null) der = bytes.der;
  else if (typeof input === "string") {
    try { der = ocspSchema.pemDecode(input); }
    catch (e) { return { fatal: { id: "lint/unparseable", severity: "fatal", source: "engine", citation: "pki.lint", message: "input is not a decodable PEM/DER OCSP response", context: { code: e.code } } }; }
  } else if (input !== null && typeof input === "object" && !guard.bytes.isByteSource(input)) {
    return { response: guard.parsed.fromTrustedSource(input, "ocspResponse", _OCSP_CLAIM, function (src) {
      if (!Buffer.isBuffer(src) && typeof src !== "string") throw _cfg("lint/bad-input", "pki.lint.ocsp input must be a parsed OCSP response, a DER Buffer, or a PEM string");
      return ocspSchema.parseResponse(src);
    }, _cfg, "lint/bad-input",
    "pki.lint.ocsp input must be its DER bytes, a PEM string, or an unmodified pki.schema.ocsp.parseResponse result: the signed byte range, the signature and the fields that range encodes are separate properties of a parsed object, so a rebuilt response could have them describe different responses") };
  } else {
    throw _cfg("lint/bad-input", "pki.lint.ocsp input must be a parsed OCSP response, a DER Buffer, or a PEM string");
  }
  try { return { response: ocspSchema.parseResponse(der) }; }
  catch (e) { return { fatal: { id: "lint/unparseable", severity: "fatal", source: "engine", citation: "RFC 6960", message: "input is not a well-formed OCSP response", context: { code: e.code } } }; }
}

/**
 * @primitive  pki.lint.ocsp
 * @signature  pki.lint.ocsp(pem | der | parsed, opts?) -> LintReport
 * @since      0.7.26
 * @status     stable
 * @spec       RFC 6960, RFC 5019, RFC 9654
 * @related    pki.lint.certificate, pki.lint.crl, pki.schema.ocsp.parseResponse, pki.ocsp.sign, pki.ocsp.verify
 *
 * Lint an OCSP response against the RFC 6960 profile, and on request against the RFC 5019
 * lightweight profile. `input` is a PEM string (`OCSP RESPONSE`), a DER `Buffer`, or an
 * already-parsed `pki.schema.ocsp.parseResponse` object. It returns the same `LintReport` shape
 * `pki.lint.certificate` returns, and it never throws on the data path: bytes that are not a
 * well-formed response produce a single `fatal` finding `lint/unparseable` carrying the strict
 * parser's own code. A non-successful response carries no BasicOCSPResponse and draws no row.
 *
 * The `rfc6960` rows cover each SingleResponse's update times and their relation to producedAt,
 * an empty `certs` field, the extended revoked definition (criticality, value and placement) and
 * the fixed shape of a revoked answer for a non-issued certificate, the placement of the nonce,
 * archive cutoff, CRL references and the request-only extensions, an archive cutoff later than
 * producedAt, the criticality and value syntax of the CRL entry extensions a SingleResponse may
 * carry, an unrecognized critical extension, the revocation reasons unspecified and removeFromCRL,
 * and two SingleResponses answering for one CertID. The `rfc5019` rows (nextUpdate present, one
 * SingleResponse, no responseExtensions, a byKey ResponderID) run only when that profile is
 * selected, since nothing in a response says which profile its responder follows; in the default
 * run they count as not applicable.
 *
 * Shapes the strict parser refuses never reach a rule and arrive as `lint/unparseable` carrying the
 * parser's code: a version other than v1, an undefined revocation reason, an empty or repeated
 * extension, an empty `responses`, a nonce outside 1..128 octets, a malformed archive cutoff or
 * CRL reference, a responseStatus that disagrees with responseBytes, and a time not in the
 * `YYYYMMDDHHMMSSZ` form RFC 5019 requires. What needs the issuer or the signature (responder
 * authorization, the ResponderID matching the signing certificate, freshness against a clock)
 * is `pki.ocsp.verify`'s, and the certificates in `certs` are linted with `pki.lint.certificate`.
 *
 * @opts  profile   `"rfc6960"` or `"rfc5019"` (default runs the rfc6960 rows and marks the rfc5019
 *                  rows not applicable). A certificate or CRL profile name is refused rather than
 *                  run against a response.
 * @opts  severity  Suppress findings below this floor (default `"notice"`). `counts` and `worst`
 *                  always reflect the complete, unfiltered result.
 * @example
 *   var ca = await pki.key.generate("Ed25519");
 *   var caKey = await pki.key.export(ca.privateKey);
 *   var caDer = await pki.x509.sign({ subject: "Example CA", subjectPublicKey: await pki.key.export(ca.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
 *     extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true } }, { key: caKey });
 *   var leaf = await pki.key.generate("Ed25519");
 *   var leafDer = await pki.x509.sign({ subject: "leaf.example", subjectPublicKey: await pki.key.export(leaf.publicKey),
 *     notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") },
 *     { cert: caDer, key: caKey });
 *   var der = await pki.ocsp.sign({ responderID: "byKey", responses: [{ cert: leafDer, issuer: caDer, status: "good" }] },
 *     { cert: caDer, key: caKey });
 *   var report = pki.lint.ocsp(der);
 *   report.findings.length;                              // -> 0
 *   pki.lint.ocsp(der, { profile: "rfc5019" }).worst;    // -> null
 */
function ocsp(input, opts) {
  opts = guard.identifier.optionsObject(opts, _cfg, "lint/bad-input", "pki.lint options");
  guard.identifier.assertKnownKeys(opts, _OCSP_OPTS, _cfg, "lint/bad-input",
    "pki.lint.ocsp has an unknown option: ");
  if (opts.severity != null && VALID_SEVERITY.indexOf(opts.severity) === -1) {
    throw _cfg("lint/bad-severity", "unknown severity threshold \"" + opts.severity + "\" (known: " + VALID_SEVERITY.join(", ") + ")");
  }
  var profile = opts.profile;
  var rules_;
  if (profile == null || profile === "all" || profile === "default") rules_ = ALL_OCSP_RULES;
  else if (OCSP_PROFILES[profile]) rules_ = OCSP_PROFILES[profile];
  else if (PROFILES[profile]) throw _cfg("lint/unknown-profile", "\"" + profile + "\" is a certificate profile; lint a certificate with pki.lint.certificate");
  else if (CRL_PROFILES[profile]) throw _cfg("lint/unknown-profile", "\"" + profile + "\" is a CRL profile; lint a CRL with pki.lint.crl");
  else throw _cfg("lint/unknown-profile", "unknown OCSP lint profile \"" + profile + "\" (known: " + Object.keys(OCSP_PROFILES).join(", ") + ")");

  var ingested = _ingestOcsp(input);
  var report;
  if (ingested.fatal) {
    report = { findings: [ingested.fatal], ran: [],
      counts: Object.assign(Object.create(null), { fatal: 1, error: 0, warn: 0, notice: 0, pass: 0, na: 0, ne: 0 }) };
  } else if (!ingested.response.basicResponse) {
    /** @internal A non-successful response carries no BasicOCSPResponse, so every row is not
     * applicable to it: the profile grades responses, and an error status is not one. */
    report = { findings: [], ran: [],
      counts: Object.assign(Object.create(null), { fatal: 0, error: 0, warn: 0, notice: 0, pass: 0, na: rules_.length, ne: 0 }) };
  } else {
    report = _runLints(rules_, ingested.response, { profile: profile, decode: function () { return null; }, raw: function () { return null; } });
  }
  report.worst = _worst(report.findings);
  report.findings = _applyThreshold(report, opts.severity);
  return report;
}

/**
 * @primitive  pki.lint.rules
 * @signature  pki.lint.rules(profile?, artifact?) -> [{id, severity, source, citation}]
 * @since      0.2.10
 * @status     stable
 * @spec       RFC 5280, CA/Browser Forum TLS BR
 *
 * Enumerate the rule registry (all rules, or one profile's). Each entry exposes its
 * stable `id`, `severity`, `source`, and spec-clause `citation` for documentation and
 * corpus tooling. Each id appears once, including where two artifacts run the same rule.
 *
 * `artifact` says which verb's reading of a profile name to return, and is needed because
 * `"cabf-tls"` names a set for both `pki.lint.certificate` and `pki.lint.csr` and the two are not
 * the same rows: a request has no extKeyUsage and no validity period, and carries structural rows
 * a certificate does not. It is `"certificate"`, `"csr"`, `"crl"` or `"ocsp"`, and defaults to the
 * artifact that first claims the name, which is the certificate for `"cabf-tls"`.
 *
 * @example
 *   pki.lint.rules("rfc5280").length;              // -> a positive count
 *   pki.lint.rules("cabf-tls", "csr").length;      // -> the rows pki.lint.csr runs under it
 */
/** @internal Prototype-less, because `artifact` is the caller's string and a computed lookup on a
 *  literal would answer for "constructor" and the rest of Object.prototype. */
var BY_ARTIFACT = Object.assign(Object.create(null), {
  certificate: PROFILES, csr: CSR_PROFILES, crl: CRL_PROFILES, ocsp: OCSP_PROFILES,
});

function rules(profile, artifact) {
  /** @internal Every lint verb reads "all" and "default" as naming no profile, so the enumerator
   * reads them the same way: a caller who linted under one of those names and then asked which
   * rows ran would otherwise be refused the answer by the same registry that ran them. */
  if (profile === "all" || profile === "default") profile = null;
  if (artifact != null && !Object.prototype.hasOwnProperty.call(BY_ARTIFACT, artifact)) {
    throw _cfg("lint/bad-input", "unknown lint artifact \"" + artifact +
      "\" (known: " + Object.keys(BY_ARTIFACT).join(", ") + ")");
  }
  var set;
  if (profile == null && artifact != null) {
    /** @internal An artifact without a profile asks what that VERB can run, which is the union of
     * its own profiles. Returning the whole registry would answer with a certificate's validity
     * rows and the CRL and OCSP sets, none of which a request or a response is ever held to. */
    set = [];
    Object.keys(BY_ARTIFACT[artifact]).forEach(function (name) {
      BY_ARTIFACT[artifact][name].forEach(function (r) { set.push(r); });
    });
  } else if (profile == null) {
    set = ALL_RULES.concat(ALL_CRL_RULES).concat(ALL_OCSP_RULES).concat(ALL_CSR_RULES);
  } else if (artifact != null) {
    set = BY_ARTIFACT[artifact][profile];
    if (!set) {
      throw _cfg("lint/unknown-profile", "\"" + profile + "\" is not a " + artifact +
        " lint profile (known: " + Object.keys(BY_ARTIFACT[artifact]).join(", ") + ")");
    }
  } else {
    set = PROFILES[profile] || CRL_PROFILES[profile] || OCSP_PROFILES[profile] || CSR_PROFILES[profile];
    if (!set) throw _cfg("lint/unknown-profile", "unknown lint profile \"" + profile + "\"");
  }
  /** @internal One row per id: a rule reused across artifacts, like the RFC 5280 sec. 4.2
   * extension-syntax row a request and a certificate both run, is one rule with one id, and
   * tooling that counts or registers from this list would otherwise process it twice. */
  var seen = Object.create(null), out = [];
  set.forEach(function (r) {
    if (seen[r.id]) return;
    seen[r.id] = true;
    out.push({ id: r.id, severity: r.severity, source: r.source, citation: r.citation });
  });
  return out;
}

/**
 * @primitive  pki.lint.profiles
 * @signature  pki.lint.profiles() -> [string]
 * @since      0.2.10
 * @status     stable
 * @spec       RFC 5280, RFC 9881, RFC 9909, RFC 9935, CA/Browser Forum TLS BR
 *
 * List the known lint-profile names.
 * @example
 *   pki.lint.profiles();   // -> ["rfc5280", "rfc9881", "rfc9909", "rfc9935", "cabf-tls", "rfc5280-crl", "rfc6960", "rfc5019"]
 */
/** @internal `cabf-tls` names the certificate profile in this list and is not repeated for the
 *  request form: `pki.lint.csr` takes the same name and runs those rows against what a request
 *  asks for, so one name means one set of requirements whichever artifact carries it. */
function profiles() {
  var out = Object.keys(PROFILES).concat(Object.keys(CRL_PROFILES)).concat(Object.keys(OCSP_PROFILES));
  Object.keys(CSR_PROFILES).forEach(function (name) { if (out.indexOf(name) === -1) out.push(name); });
  return out;
}

module.exports = {
  certificate: certificate,
  csr: csr,
  crl: crl,
  ocsp: ocsp,
  rules: rules,
  profiles: profiles,
};
