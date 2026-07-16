// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module pki.lint
 * @nav        Tooling
 * @title      Lint
 * @intro The certificate LINTING engine -- the zlint / pkilint of JavaScript. It walks an
 *   ALREADY-PARSED certificate (from `pki.schema.x509.parse`, whose extension values it
 *   decodes with the shared RFC 5280 decoders) and emits graded, advisory FINDINGS: each
 *   with a stable id, a severity (`fatal` > `error` > `warn` > `notice` > `pass`), a source,
 *   a spec-clause citation, and a human message. It ships the RFC 5280 certificate profile
 *   plus a representative CA/Browser Forum TLS Baseline Requirements subset.
 *
 *   Unlike every other toolkit entry, the lint DATA path NEVER throws. A linter surveys a
 *   corpus that includes malformed members, so `pki.lint.certificate(hostileBytes)` returns
 *   a report whose worst finding is a `fatal` id `lint/unparseable` (carrying the inner
 *   `PkiError.code`) rather than raising. The SOLE throw path is CONFIG-time misuse -- an
 *   unknown profile, an out-of-range severity threshold, or a wrong-type input -- which
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
var C = require("./constants");
var ipUtils = require("./ip-utils");

var MS_PER_DAY = C.TIME.days(1);

var LintError = frameworkError.LintError;
function _cfg(code, message, cause) { return new LintError(code, message, cause); }

// Strict-parse pre-emption: this toolkit's parser is strict-DER, so several RFC 5280
// profile violations a lenient linter (zlint/pkilint) would report as a SPECIFIC finding
// are instead rejected fail-closed at PARSE and surface here as a single `fatal`
// lint/unparseable whose context.code names the exact structural violation -- e.g. a
// duplicate extension OID (x509/duplicate-extension), a pathLenConstraint without cA
// (bad-basic-constraints), an explicit cA=FALSE, or a signatureAlgorithm/tbs mismatch.
// The registry therefore ships no dedicated rule for a violation the parser already
// rejects (a dead rule that could never fire); the specific reason is preserved in the
// unparseable finding's context.
//
// The shared RFC 5280 extension decoders, composed exactly as path-validate / inspect
// compose them -- the linter owns no second decoder table.
var NS = pkix.makeNS("lint", LintError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;

// Coverage note: the rules and helpers below carry defensive guards -- `|| []` / `|| ""`
// on fields the strict parser ALWAYS sets (extensions, serialNumberHex, subject.rdns), and
// `!Buffer.isBuffer` / `instanceof Date` / minimal-encoding checks against malformed-but-
// parsed shapes the strict parser never produces. These are fail-safe belts, not reachable
// paths; they stay verified-unreachable (documented) rather than removed, since the lint
// data path must never throw even on an unexpected upstream shape.

// ---- the advisory result surface (the Do-FIRST: graded findings, not a throw) ----

// Severity ordering (zlint's LintStatus). NA (not applicable) and NE (not effective --
// outside a rule's date window) are rule OUTCOMES, tracked in counts, not severities.
var SEVERITY = { fatal: 5, error: 4, warn: 3, notice: 2, pass: 1 };
var VALID_SEVERITY = Object.keys(SEVERITY);

function _worst(findings) {
  var w = null, wv = 0;
  findings.forEach(function (f) { var v = SEVERITY[f.severity] || 0; if (v > wv) { wv = v; w = f.severity; } });
  return w;
}

// A profile groups rules by source; a rule is `{ id, severity, source, citation,
// appliesTo?, effectiveDate?, check }`. `check(cert, ctx)` returns null (pass) or a detail
// / array of details, each becoming one finding under the rule. A detail carries only an
// optional `context` object; the human message is the rule's.
function _finding(rule, detail) {
  var f = { id: rule.id, severity: rule.severity, source: rule.source, citation: rule.citation, message: rule.message };
  if (detail && detail.context) f.context = detail.context;
  return f;
}

// ---- ingestion: bytes/PEM/parsed -> parsed, or a fatal lint/unparseable finding ----

function _looksParsed(o) {
  return o && typeof o === "object" && !Buffer.isBuffer(o) &&
    Buffer.isBuffer(o.tbsBytes) && o.validity && o.subjectPublicKeyInfo && Array.isArray(o.extensions);
}

// Returns { cert } on success, or { fatal: <Finding> } when hostile bytes do not parse
// (the never-throw data path). Throws LintError ONLY on a wrong-TYPE input (config misuse).
function _ingest(input) {
  if (_looksParsed(input)) return { cert: input };
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

// ---- per-cert context the rules read ----

function _findRaw(cert, name) {
  var dotted = oid.byName(name);
  var list = cert.extensions || [];
  for (var i = 0; i < list.length; i++) { if (list[i].oid === dotted) return list[i]; }
  return null;
}
// Decode a known extension to { critical, value }, or null when absent OR undecodable.
// The undecodable case is surfaced by the dedicated `extension-undecodable` rule; every
// other rule treats an undecodable extension as "not usable" and simply does not fire.
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
  // A CA certificate is not a TLS server (leaf) certificate even when it carries a
  // serverAuth EKU, so the default profile must NOT apply the CABF leaf rules (SAN
  // required, CN-in-SAN, validity ceiling, ...) to it. An explicit cabf-tls selection
  // still lints whatever the caller hands it as a server cert.
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

// ---- the runner ----

// A date-gated rule is effective for a cert only when the cert's notBefore is at or after
// the rule's effectiveDate; a cert issued before it reports NE (not effective, never fires).
// This encodes a scheduled requirement (the CABF validity-day ceiling) against issuance date.
function _effective(rule, cert) {
  if (!rule.effectiveDate) return true;
  var nb = cert.validity && cert.validity.notBefore;
  // allow:nan-date-comparison-unguarded -- nb is a codec-parsed cert notBefore (asn1 readTime rejects a NaN instant); effectiveDate is a Date literal.
  return (nb instanceof Date) && nb.getTime() >= rule.effectiveDate.getTime();
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

// ---- rule registry ----

function _serialOctets(cert) {
  var hex = cert.serialNumberHex || "";
  if (hex.length % 2) hex = "0" + hex;
  var buf = Buffer.from(hex, "hex");
  // Strip a single DER positive-sign 00 (present only when the value's high bit is set);
  // the octet COUNT the profile bounds is the value's, not the encoding's leading pad.
  if (buf.length > 1 && buf[0] === 0x00 && (buf[1] & 0x80)) buf = buf.subarray(1);
  return buf.length;
}

// dNSName syntax (a representative CABF check): no whitespace, no leading/trailing dot,
// no empty label, and no underscore (forbidden in a dNSName). IDN must already be an
// A-label (we do not transcode). Returns a reason string, or null when well-formed.
function _dnsNameProblem(s) {
  if (typeof s !== "string" || !s.length) return "empty";
  if (s.length > 253) return "exceeds 253 octets";
  if (/\s/.test(s)) return "whitespace";
  if (s.charAt(0) === "." || s.charAt(s.length - 1) === ".") return "leading/trailing dot";
  if (s.indexOf("_") !== -1) return "underscore forbidden in dNSName";
  var labels = s.split(".");
  for (var i = 0; i < labels.length; i++) {
    var label = labels[i];
    if (label.length === 0) return "empty label";
    if (label.length > 63) return "label exceeds 63 octets";
    // A leftmost "*" wildcard label is permitted only when at least one more label follows
    // (a bare "*" is not a domain name).
    if (i === 0 && label === "*") {
      if (labels.length < 2) return "bare wildcard";
      continue;
    }
    // RFC 1034 preferred name syntax: an LDH label that neither begins nor ends with a
    // hyphen. Rejects "-bad" / "bad-" and any non-letter/digit/hyphen character.
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label)) return "invalid label syntax";
  }
  return null;
}

// A genuine IPv4 or IPv6 literal -- a CN validated against an iPAddress SAN rather than a
// dNSName. Routed through the shared strict validator (no node:net, so the toolkit needs no
// networking module): a per-octet-bounded dotted quad, or a full RFC 4291 IPv6 form
// (including the IPv4-mapped / dual-stack tail). Rejects 999.999.999.999 and "api:443".
function _looksLikeIp(s) { return ipUtils.isIpLiteral(s); }

function _sanDnsNames(ctx) {
  var d = ctx.decode("subjectAltName");
  if (!d || !d.value || !Array.isArray(d.value.names)) return [];
  return d.value.names.filter(function (n) { return n && n.tagNumber === 2; }).map(function (n) { return n.value; });
}
// The subject CN string values (an RDN attribute of type commonName), if any.
function _subjectCNs(cert) {
  var out = [];
  ((cert.subject && cert.subject.rdns) || []).forEach(function (rdn) {
    rdn.forEach(function (a) { if (a.type === oid.byName("commonName") && typeof a.value === "string") out.push(a.value); });
  });
  return out;
}

// An extension is "recognized" (RFC 5280 4.2: a consumer MUST reject a critical extension
// it does NOT recognize / cannot process) when the toolkit has a DECODER for it -- the
// shared certExtensionDecoders table IS the set of extensions this toolkit processes. This
// is registry-driven (no curated list to omit a legitimately-critical extension such as
// policyMappings, which the table decodes) and correctly scoped to EXTENSION OIDs: an
// algorithm / EKU-purpose OID the name registry happens to resolve is NOT in the decoder
// table, so a critical extension carrying such an OID is still flagged.
//
// The one exception: an extension the table DECODES for display but whose CRITICAL semantics
// the toolkit does not enforce. qcStatements decodes (for pki.inspect / this linter) yet a
// critical instance asserts qualified-certificate constraints (a reliance limit, a certificate
// purpose) no consumer here processes -- path-validate rejects a critical qcStatements as
// unrecognized-critical for exactly that reason. Structural decodability is not validation
// processing, so a critical qcStatements is still flagged here, keeping lint consistent with
// certification-path validation.
var _DECODE_ONLY_UNPROCESSED_CRITICAL = {};
_DECODE_ONLY_UNPROCESSED_CRITICAL[oid.byName("qcStatements")] = true;
function _isUnknownExtension(extOid) { return !EXT_DECODERS[extOid] || _DECODE_ONLY_UNPROCESSED_CRITICAL[extOid] === true; }

// RSA-modulus / EC-curve helpers for the weak-key lint. Each returns null when the key
// material cannot be read as expected (a malformed RSA modulus, or EC parameters that are
// absent / explicit / not a named-curve OID); the weak-key rule treats null as fail-closed
// (a key it cannot confirm meets the minimum is flagged, not silently passed).
function _rsaModulusBits(spki) {
  try {
    var pk = spki.publicKey && (spki.publicKey.bytes || spki.publicKey);
    if (!Buffer.isBuffer(pk)) return null;
    var seq = asn1.decode(pk);
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } -- exactly two
    // INTEGERs, and the modulus MUST be positive. A negative/zero modulus (a high-bit key
    // mis-encoded without a sign pad) or a missing exponent is malformed, not a real key.
    if (!seq.children || seq.children.length !== 2) return null;
    var mod = asn1.read.integer(seq.children[0]);
    asn1.read.integer(seq.children[1]);   // the exponent must be a valid INTEGER
    if (mod <= 0n) return null;
    return mod.toString(2).length;
  } catch (_e) { return null; }   // a modulus that will not decode cannot be sized
}
// Every RSA-family SPKI (rsaEncryption, RSASSA-PSS, RSAES-OAEP) carries an RSAPublicKey
// SEQUENCE, so all are weighed by modulus size; matching only "rsaEncryption" would let an
// RSA-PSS or RSAES-OAEP key skip the check.
var RSA_KEY_ALGS = { rsaEncryption: 1, rsassaPss: 1, rsaesOaep: 1 };
var APPROVED_EC_CURVES = ["prime256v1", "secp384r1", "secp521r1"]; // P-256 / P-384 / P-521
function _ecCurveName(spki) {
  try {
    var params = spki.algorithm && spki.algorithm.parameters;
    if (!Buffer.isBuffer(params)) return null;
    return oid.name(asn1.read.oid(asn1.decode(params)));   // named-curve OID, or throw on explicit params
  } catch (_e) { return null; }   // explicit / invalid EC parameters are not an approved named curve
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
    // Counts the VALUE magnitude (a single DER sign-pad 0x00 stripped), not the encoded
    // length: a 20-byte random serial whose high bit is set encodes as 21 octets but is a
    // conformant 20-octet value, so this avoids false-positiving on the common CA serial.
    check: function (cert) { return _serialOctets(cert) > 20 ? { context: { octets: _serialOctets(cert) } } : null; },
  },
  {
    id: "lint/rfc5280/validity-inverted", severity: "error", source: "rfc5280", citation: "RFC 5280 4.1.2.5",
    message: "the certificate notBefore must not be later than notAfter",
    check: function (cert) {
      var v = cert.validity;
      // allow:nan-date-comparison-unguarded -- notBefore/notAfter are codec-parsed cert dates (asn1 readTime rejects a NaN instant).
      return (v.notBefore instanceof Date && v.notAfter instanceof Date && v.notBefore.getTime() > v.notAfter.getTime()) ? true : null;
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
    // The inverse coherence check: keyCertSign asserted -> cA MUST be TRUE. Fires when a
    // cert claims certificate-signing usage but omits basicConstraints or is not a CA.
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
];

function _isTls(cert, ctx) { return ctx.isTlsServerCert; }

// The CABF TLS BR maximum validity period (in days) by certificate issuance date --
// the SC22 398-day ceiling (2020-09-01) reduced on the SC081v3 schedule: 200 days from
// 2026-03-15, 100 days from 2027-03-15, 47 days from 2029-03-15. Newest-first so the first
// entry whose `from` is at or before the cert's notBefore gives the applicable ceiling.
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
    if (notBefore.getTime() >= VALIDITY_SCHEDULE[i].from.getTime()) return VALIDITY_SCHEDULE[i].maxDays;
  }
  // Unreachable: the rule's effectiveDate (VALIDITY_SCHEDULE_START) reports NE for any cert
  // whose notBefore predates the schedule, so the loop always matches the last entry.
  return VALIDITY_SCHEDULE[VALIDITY_SCHEDULE.length - 1].maxDays;
}

var CABF_TLS_RULES = [
  {
    id: "lint/cabf-tls/san-missing", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.4.2.1",
    message: "a TLS server certificate must include a usable subjectAltName extension",
    appliesTo: _isTls,
    // A SAN that is absent -- OR present but undecodable / carrying no names -- is not a
    // usable subjectAltName, so all three cases are treated as missing for the TLS profile.
    check: function (cert, ctx) { var san = ctx.decode("subjectAltName"); return (san && san.value && san.value.names && san.value.names.length) ? null : true; },
  },
  {
    id: "lint/cabf-tls/cn-not-in-san", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.4.2.2",
    message: "a subject commonName value must also appear as a subjectAltName dNSName",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      // dNSNames are case-insensitive (RFC 4343), so match case-folded.
      var sans = _sanDnsNames(ctx).map(function (s) { return typeof s === "string" ? s.toLowerCase() : s; }), out = [];
      _subjectCNs(cert).forEach(function (cn) {
        // A commonName MUST match a dNSName OR an iPAddress SAN (CABF 7.1.4.2.2). This
        // subset checks dNSName values only, so an IP-literal CN (validated against the
        // iPAddress SAN this subset does not yet render) is skipped, not false-flagged.
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
    // Only meaningful when the caller EXPLICITLY lints against the TLS profile; under the
    // default profile a cert is recognized as TLS BY its serverAuth EKU, so the check is
    // vacuous and reports NA rather than firing on every non-TLS certificate.
    appliesTo: function (cert, ctx) { return ctx.explicitTlsProfile; },
    check: function (cert, ctx) { return _hasEku(cert, "serverAuth") ? null : true; },
  },
  {
    id: "lint/cabf-tls/weak-key", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 6.1.5",
    message: "the subject public key is below the CABF TLS BR minimum (RSA < 2048 bits, or a non-approved EC curve)",
    appliesTo: _isTls,
    check: function (cert) {
      var spki = cert.subjectPublicKeyInfo, name = spki && spki.algorithm && spki.algorithm.name;
      // Fail closed: a key whose size/curve cannot be confirmed to meet the minimum is
      // flagged, not passed. RSA below 2048 bits (or an unreadable modulus), or an EC key
      // NOT on an approved named curve (including absent / explicit / invalid parameters,
      // which resolve to a null curve) is a finding -- CABF permits only P-256/384/521.
      if (RSA_KEY_ALGS[name]) { var bits = _rsaModulusBits(spki); return (bits === null || bits < 2048) ? { context: { rsaBits: bits } } : null; }
      if (name === "ecPublicKey") { var curve = _ecCurveName(spki); return APPROVED_EC_CURVES.indexOf(curve) === -1 ? { context: { curve: curve } } : null; }
      // Any other key type (e.g. EdDSA) is out of this rule's RSA-size / EC-curve scope --
      // key-TYPE approval for TLS is a separate concern, so weak-key does not fire here.
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
      if (!(v.notBefore instanceof Date) || !(v.notAfter instanceof Date)) return null;
      var maxDays = _validityCeilingDays(v.notBefore);
      var days = (v.notAfter.getTime() - v.notBefore.getTime()) / MS_PER_DAY;
      return days > maxDays ? { context: { days: Math.round(days), maxDays: maxDays } } : null;
    },
  },
];

// RFC 9935 -- ML-KEM public keys in X.509 certificates. The OID is the sole authority for the
// parameter set; the SPKI BIT STRING is the raw ek, exactly 384k+32 octets for that OID.
var ML_KEM_EK_LEN = {};
["id-ml-kem-512", "id-ml-kem-768", "id-ml-kem-1024"].forEach(function (n, i) { ML_KEM_EK_LEN[n] = [800, 1184, 1568][i]; });
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
      if (!ku || !ku.value) return null;   // absent keyUsage is unconstrained (RFC 5280 4.2.1.3)
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
      var pub = spki.publicKey;   // a parsed SPKI always surfaces the BIT STRING as { bytes, unusedBits }
      // The ek is a raw byte string carried in the BIT STRING: it must be the exact size AND
      // byte-aligned. A right-length but non-octet-aligned BIT STRING (unusedBits != 0) is not the
      // raw ek (RFC 9935 sec. 4); route the alignment test through the shared guard primitive.
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
  // An explicit cabf-tls run still needs the always-on rfc5280 structural rules? No: the
  // caller asked for ONE profile. Return exactly that profile's rules.
  return PROFILES[profile];
}

// Filter the emitted findings to the threshold floor (default `notice`). The threshold
// is validated at the certificate() entry, so it is a known severity here; `counts` and
// `worst` are computed before this filter and stay complete.
function _applyThreshold(report, severity) {
  var floor = SEVERITY[severity == null ? "notice" : severity];
  return report.findings.filter(function (f) { return (SEVERITY[f.severity] || 0) >= floor; });
}

// ---- public surface ----

/**
 * @primitive  pki.lint.certificate
 * @signature  pki.lint.certificate(input, opts?) -> LintReport
 * @since      0.2.10
 * @status     experimental
 * @spec       RFC 5280, CA/Browser Forum TLS BR
 * @related    pki.schema.x509.parse, pki.inspect.certificate, pki.path.validate
 *
 * Lint a certificate against the RFC 5280 profile plus a representative CABF TLS BR
 * subset. `input` is a PEM string, a DER `Buffer`, or an already-parsed
 * `pki.schema.x509` object. Returns a `LintReport`
 * `{ findings: [{id, severity, source, citation, message, context?}], counts, worst, ran }`.
 *
 * The DATA path never throws: hostile bytes produce a single `fatal` finding
 * `lint/unparseable` rather than raising. The ONLY throw path is config-time misuse
 * (`opts.profile` unknown, `opts.severity` out of range, or a wrong-type input) -- a
 * typed `LintError`.
 *
 * @opts  profile   One of `pki.lint.profiles()` (default runs every profile). Selecting
 *                  `"cabf-tls"` lints the input AS a TLS server certificate.
 * @opts  severity  Suppress findings below this floor (default `"notice"`). `counts` and
 *                  `worst` always reflect the complete, unfiltered result.
 * @example
 *   var report = pki.lint.certificate(pemString);
 *   report.worst;                              // "notice" | "error" | ...
 *   report.findings.map(function (f) { return f.id; });
 */
function certificate(input, opts) {
  opts = opts || {};
  if (typeof opts !== "object") throw _cfg("lint/bad-input", "pki.lint options must be an object");
  // Validate BOTH config options up front so a config error fails fast, before any work.
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
 * @status     experimental
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
 * @status     experimental
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
