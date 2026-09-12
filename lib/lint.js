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
var ocspSchema = require("./schema-ocsp");
var pkix = require("./schema-pkix");
var schema = require("./schema-engine");
var path = require("./path-validate");
var C = require("./constants");
var ipUtils = require("./ip-utils");

var MS_PER_DAY = C.TIME.days(1);

var LintError = frameworkError.LintError;
function _cfg(code, message, cause) { return new LintError(code, message, cause); }

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
function _subjectCNs(cert) {
  var out = [];
  ((cert.subject && cert.subject.rdns) || []).forEach(function (rdn) {
    rdn.forEach(function (a) { if (a.type === oid.byName("commonName") && typeof a.value === "string") out.push(a.value); });
  });
  return out;
}

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

/** @internal Whether a string opens with the given URI scheme followed by a colon, compared
 * without regard to case by scanning character codes. */
function _uriSchemeIs(s, scheme) {
  if (typeof s !== "string" || s.length <= scheme.length) return false;
  for (var i = 0; i < scheme.length; i++) {
    var c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) c += 32;
    if (c !== scheme.charCodeAt(i)) return false;
  }
  return s.charCodeAt(scheme.length) === 58;
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
        return AIA_RECOMMENDED_SCHEMES.some(function (s) { return _uriSchemeIs(loc.value, s); });
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
  crlSchema.decodeExtension({ oid: OID_REASON_CODE, name: "reasonCode", critical: false, value: bytes });
};
OCSP_SINGLE_VALUE_READER[oid.byName("invalidityDate")] = function (bytes) {
  crlSchema.decodeExtension({ oid: oid.byName("invalidityDate"), name: "invalidityDate", critical: false, value: bytes });
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
  try { return crlSchema.decodeExtension(e).value; }
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

var PROFILES = Object.assign(Object.create(null), {
  "rfc5280": RFC5280_RULES,
  "rfc9881": RFC9881_RULES,
  "rfc9909": RFC9909_RULES,
  "rfc9935": RFC9935_RULES,
  "cabf-tls": CABF_TLS_RULES,
});
var ALL_RULES = RFC5280_RULES.concat(RFC9881_RULES).concat(RFC9909_RULES).concat(RFC9935_RULES).concat(CABF_TLS_RULES);

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
  if (Buffer.isBuffer(input)) der = input;
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
  if (Buffer.isBuffer(input)) der = input;
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
  var set = profile == null
    ? ALL_RULES.concat(ALL_CRL_RULES).concat(ALL_OCSP_RULES)
    : (PROFILES[profile] || CRL_PROFILES[profile] || OCSP_PROFILES[profile]
      || (function () { throw _cfg("lint/unknown-profile", "unknown lint profile \"" + profile + "\""); })());
  return set.map(function (r) { return { id: r.id, severity: r.severity, source: r.source, citation: r.citation }; });
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
function profiles() { return Object.keys(PROFILES).concat(Object.keys(CRL_PROFILES)).concat(Object.keys(OCSP_PROFILES)); }

module.exports = {
  certificate: certificate,
  crl: crl,
  ocsp: ocsp,
  rules: rules,
  profiles: profiles,
};
