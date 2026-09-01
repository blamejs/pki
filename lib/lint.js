// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.lint
 * @nav        Tooling
 * @title      Lint
 * @fullname   Certificate linting against CA/Browser Forum requirements
 * @intro The certificate LINTING engine -- the zlint / pkilint of JavaScript. It walks an
 *   ALREADY-PARSED certificate (from `pki.schema.x509.parse`, whose extension values it
 *   decodes with the shared RFC 5280 decoders) and emits graded, advisory FINDINGS: each
 *   with a stable id, a severity (`fatal` > `error` > `warn` > `notice` > `pass`), a source,
 *   a spec-clause citation, and a human message. It ships the RFC 5280 certificate profile
 *   plus a representative CA/Browser Forum TLS Baseline Requirements subset.
 *
 *   Unlike every other toolkit entry, the lint data path never throws. A linter surveys a
 *   corpus that includes malformed members, so `pki.lint.certificate(hostileBytes)` returns
 *   a report whose worst finding is a `fatal` id `lint/unparseable` (carrying the inner
 *   `PkiError.code`) and does not raise. The one throw path is config-time misuse (an
 *   unknown profile, an out-of-range severity threshold, or a wrong-type input), which
 *   raises a typed `LintError`. This deliberate inversion of the toolkit's fail-closed-throw
 *   posture is what lets an operator lint a whole directory without a try/catch per file.
 * @spec RFC 5280, CA/Browser Forum TLS Baseline Requirements
 * @card Lint a certificate against RFC 5280 + CABF TLS BR, in pure JS.
 */

var frameworkError = require("./framework-error");
var asn1 = require("./asn1-der");
var guard = require("./guard-all");
var oid = require("./oid");
var x509 = require("./schema-x509");
var pkix = require("./schema-pkix");
var path = require("./path-validate");
var C = require("./constants");
var ipUtils = require("./ip-utils");

var MS_PER_DAY = C.TIME.days(1);

var LintError = frameworkError.LintError;
function _cfg(code, message, cause) { return new LintError(code, message, cause); }

var NS = pkix.makeNS("lint", LintError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;



var SEVERITY = { fatal: 5, error: 4, warn: 3, notice: 2, pass: 1 };
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

function _ingest(input) {
  var derived = _derivedCert(input);
  if (derived) return { cert: derived };
  var der;
  if (Buffer.isBuffer(input)) der = input;
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
  var findings = [], counts = { fatal: 0, error: 0, warn: 0, notice: 0, pass: 0, na: 0, ne: 0 }, ran = [];
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


function _serialOctets(cert) {
  var hex = cert.serialNumberHex || "";
  if (hex.length % 2) hex = "0" + hex;
  var buf = Buffer.from(hex, "hex");
  if (buf.length > 1 && buf[0] === 0x00 && (buf[1] & 0x80)) buf = buf.subarray(1);
  return buf.length;
}

function _dnsNameProblem(s) { return pkix.dnsNameProblem(s); }

function _looksLikeIp(s) { return ipUtils.isIpLiteral(s); }

function _sanDnsNames(ctx) {
  var d = ctx.decode("subjectAltName");
  if (!d || !d.value || !Array.isArray(d.value.names)) return [];
  return d.value.names.filter(function (n) { return n && n.tagNumber === 2; }).map(function (n) { return n.value; });
}
function _subjectCNs(cert) {
  var out = [];
  ((cert.subject && cert.subject.rdns) || []).forEach(function (rdn) {
    rdn.forEach(function (a) { if (a.type === oid.byName("commonName") && typeof a.value === "string") out.push(a.value); });
  });
  return out;
}

var _CRITICAL_LEGIT = {};
_CRITICAL_LEGIT[oid.byName("precertificatePoison")] = true;
function _isUnknownExtension(extOid) {
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
var RSA_KEY_ALGS = { rsaEncryption: 1, rsassaPss: 1, rsaesOaep: 1 };
var APPROVED_EC_CURVES = ["prime256v1", "secp384r1", "secp521r1"];
function _ecCurveName(spki) {
  try {
    var params = spki.algorithm && spki.algorithm.parameters;
    if (!Buffer.isBuffer(params)) return null;
    return oid.name(asn1.read.oid(asn1.decode(params)));
  } catch (_e) { return null; }
}

var OID_UNOTICE = oid.byName("unotice");
var _T_BMP = asn1.TAGS.BMP_STRING, _T_VISIBLE = asn1.TAGS.VISIBLE_STRING, _T_UTF8 = asn1.TAGS.UTF8_STRING;
function _hasControlChar(str) {
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) return true;
  }
  return false;
}
function _policyDisplayTexts(ctx) {
  var d = ctx.decode("certificatePolicies");
  if (!d || !Array.isArray(d.value)) return [];
  var out = [];
  d.value.forEach(function (pi) {
    if (!pi.qualifiersBytes || !pi.qualifiersBytes.length) return;
    var quals;
    // allow:swallow-unverified re-decoding bytes that already decoded under assertPolicyQualifiers cannot throw
    try { quals = asn1.decode(pi.qualifiersBytes).children; } catch (_e) { return; }
    (quals || []).forEach(function (pq) {
      var qid;
      // allow:swallow-unverified assertPolicyQualifiers already read this OID, so re-reading it cannot throw
      try { qid = asn1.read.oid(pq.children[0]); } catch (_e2) { return; }
      if (qid !== OID_UNOTICE) return;
      out = out.concat(pkix.userNoticeTexts(pq.children[1]));
    });
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
    id: "lint/rfc5280/ski-missing", severity: "notice", source: "rfc5280", citation: "RFC 5280 4.2.1.2",
    message: "a CA certificate should carry a subjectKeyIdentifier extension",
    appliesTo: function (cert, ctx) { var bc = ctx.decode("basicConstraints"); return !!(bc && bc.value && bc.value.cA === true); },
    check: function (cert, ctx) { return ctx.raw("subjectKeyIdentifier") ? null : true; },
  },
  {
    id: "lint/rfc5280/aki-missing", severity: "notice", source: "rfc5280", citation: "RFC 5280 4.2.1.1",
    message: "a non-self-issued certificate should carry an authorityKeyIdentifier extension",
    appliesTo: function (cert) { return !!(cert.issuer && cert.subject && cert.issuer.dn !== cert.subject.dn); },
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
    id: "lint/rfc5280/ski-missing-ee", severity: "notice", source: "rfc5280", citation: "RFC 5280 4.2.1.2",
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

var CABF_TLS_RULES = [
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

var ML_KEM_EK_LEN = {};
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

var PROFILES = {
  "rfc5280": RFC5280_RULES,
  "rfc9935": RFC9935_RULES,
  "cabf-tls": CABF_TLS_RULES,
};
var ALL_RULES = RFC5280_RULES.concat(RFC9935_RULES).concat(CABF_TLS_RULES);

function _selectRules(profile) {
  if (profile == null || profile === "all" || profile === "default") return ALL_RULES;
  if (!PROFILES[profile]) throw _cfg("lint/unknown-profile", "unknown lint profile \"" + profile + "\" (known: " + Object.keys(PROFILES).join(", ") + ")");
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
 * @spec       RFC 5280, CA/Browser Forum TLS BR
 * @related    pki.schema.x509.parse, pki.inspect.certificate, pki.path.validate
 *
 * Lint a certificate against the RFC 5280 profile plus a representative CABF TLS BR
 * subset. `input` is a PEM string, a DER `Buffer`, or an already-parsed
 * `pki.schema.x509` object. Returns a `LintReport`
 * `{ findings: [{id, severity, source, citation, message, context?}], counts, worst, ran }`.
 *
 * The data path never throws: hostile bytes produce a single `fatal` finding
 * `lint/unparseable` and no exception. The one throw path is config-time misuse
 * (`opts.profile` unknown, `opts.severity` out of range, or a wrong-type input), which
 * raises a typed `LintError`.
 *
 * @opts  profile   One of `pki.lint.profiles()` (default runs every profile). Selecting
 *                  `"cabf-tls"` lints the input AS a TLS server certificate.
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
var _CERTIFICATE_OPTS = { profile: 1, severity: 1 };

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
    report = { findings: [ingested.fatal], counts: { fatal: 1, error: 0, warn: 0, notice: 0, pass: 0, na: 0, ne: 0 }, ran: [] };
  } else {
    var ctx = _makeCtx(ingested.cert, opts.profile);
    report = _runLints(rules, ingested.cert, ctx);
  }
  report.worst = _worst(report.findings);
  report.findings = _applyThreshold(report, opts.severity);
  return report;
}

/**
 * @primitive  pki.lint.rules
 * @signature  pki.lint.rules(profile?) -> [{id, severity, source, citation}]
 * @since      0.2.10
 * @status     stable
 * @spec       RFC 5280, CA/Browser Forum TLS BR
 *
 * Enumerate the rule registry (all rules, or one profile's). Each entry exposes its
 * stable `id`, `severity`, `source`, and spec-clause `citation` for documentation and
 * corpus tooling.
 * @example
 *   pki.lint.rules("rfc5280").length;   // -> a positive count
 */
function rules(profile) {
  var set = profile == null ? ALL_RULES : (PROFILES[profile] || (function () { throw _cfg("lint/unknown-profile", "unknown lint profile \"" + profile + "\""); })());
  return set.map(function (r) { return { id: r.id, severity: r.severity, source: r.source, citation: r.citation }; });
}

/**
 * @primitive  pki.lint.profiles
 * @signature  pki.lint.profiles() -> [string]
 * @since      0.2.10
 * @status     stable
 * @spec       RFC 5280, CA/Browser Forum TLS BR
 *
 * List the known lint-profile names.
 * @example
 *   pki.lint.profiles();   // -> ["rfc5280", "rfc9935", "cabf-tls"]
 */
function profiles() { return Object.keys(PROFILES); }

module.exports = {
  certificate: certificate,
  rules: rules,
  profiles: profiles,
};
