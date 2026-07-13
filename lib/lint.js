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
var oid = require("./oid");
var x509 = require("./schema-x509");
var pkix = require("./schema-pkix");
var C = require("./constants");

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
  return {
    profile: profile,
    explicitTlsProfile: explicitTls,
    isTlsServerCert: explicitTls || _hasEku(cert, "serverAuth"),
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
  if (/\s/.test(s)) return "whitespace";
  if (s.charAt(0) === "." || s.charAt(s.length - 1) === ".") return "leading/trailing dot";
  if (s.indexOf("_") !== -1) return "underscore forbidden in dNSName";
  if (s.split(".").some(function (label) { return label.length === 0; })) return "empty label";
  return null;
}

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
// it does NOT recognize) when the two-way OID registry resolves its OID to a name --
// registry-driven so no curated extension list can silently omit a legitimately-critical
// extension (e.g. policyMappings) and false-positive on it.
function _isUnknownExtension(extOid) { return !oid.name(extOid); }

// RSA-modulus / EC-curve helpers for the weak-key lint.
function _rsaModulusBits(spki) {
  var pk = spki.publicKey && (spki.publicKey.bytes || spki.publicKey);
  if (!Buffer.isBuffer(pk)) return null;
  var seq = asn1.decode(pk);
  if (!seq.children || !seq.children.length) return null;
  var mod = asn1.read.integer(seq.children[0]);   // RSAPublicKey ::= SEQUENCE { modulus, e }
  if (mod < 0n) mod = -mod;
  return mod.toString(2).length;
}
// RSA and RSASSA-PSS SPKIs both carry an RSAPublicKey SEQUENCE, so both are weighed by
// modulus size; matching only "rsaEncryption" would let an RSA-PSS key skip the check.
var RSA_KEY_ALGS = { rsaEncryption: 1, rsassaPss: 1 };
var APPROVED_EC_CURVES = ["prime256v1", "secp384r1", "secp521r1"]; // P-256 / P-384 / P-521
function _ecCurveName(spki) {
  var params = spki.algorithm && spki.algorithm.parameters;
  if (!Buffer.isBuffer(params)) return null;
  var node = asn1.decode(params);
  return oid.name(asn1.read.oid(node));
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

var CABF_TLS_RULES = [
  {
    id: "lint/cabf-tls/san-missing", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.4.2.1",
    message: "a TLS server certificate must include a subjectAltName extension",
    appliesTo: _isTls,
    check: function (cert, ctx) { return ctx.raw("subjectAltName") ? null : true; },
  },
  {
    id: "lint/cabf-tls/cn-not-in-san", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 7.1.4.2.2",
    message: "a subject commonName value must also appear as a subjectAltName dNSName",
    appliesTo: _isTls,
    check: function (cert, ctx) {
      // dNSNames are case-insensitive (RFC 4343), so match case-folded.
      var sans = _sanDnsNames(ctx).map(function (s) { return typeof s === "string" ? s.toLowerCase() : s; }), out = [];
      _subjectCNs(cert).forEach(function (cn) { if (sans.indexOf(cn.toLowerCase()) === -1) out.push({ context: { cn: cn } }); });
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
      try {
        if (RSA_KEY_ALGS[name]) { var bits = _rsaModulusBits(spki); return (bits != null && bits < 2048) ? { context: { rsaBits: bits } } : null; }
        // Flag any EC key NOT on an approved named curve -- an unresolved/unknown curve
        // (curve === null) is itself a finding, not a pass (CABF permits only P-256/384/521).
        if (name === "ecPublicKey") { var curve = _ecCurveName(spki); return APPROVED_EC_CURVES.indexOf(curve) === -1 ? { context: { curve: curve } } : null; }
      } catch (_e) { return null; }   // allow:swallow-unverified an undecodable SPKI is not a key-strength verdict
      return null;
    },
  },
  {
    id: "lint/cabf-tls/validity-too-long", severity: "error", source: "cabf-tls", citation: "CABF TLS BR 6.3.2 (Ballot SC22)",
    message: "a TLS server certificate validity period must not exceed 398 days",
    appliesTo: _isTls,
    effectiveDate: new Date("2020-09-01T00:00:00Z"),
    check: function (cert) {
      var v = cert.validity;
      if (!(v.notBefore instanceof Date) || !(v.notAfter instanceof Date)) return null;
      var days = (v.notAfter.getTime() - v.notBefore.getTime()) / MS_PER_DAY;
      return days > 398 ? { context: { days: Math.round(days) } } : null;
    },
  },
];

var PROFILES = {
  "rfc5280": RFC5280_RULES,
  "cabf-tls": CABF_TLS_RULES,
};
var ALL_RULES = RFC5280_RULES.concat(CABF_TLS_RULES);

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
 *   pki.lint.profiles();   // -> ["rfc5280", "cabf-tls"]
 */
function profiles() { return Object.keys(PROFILES); }

module.exports = {
  certificate: certificate,
  rules: rules,
  profiles: profiles,
};
