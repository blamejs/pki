// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.lint: the certificate LINTING engine (RFC 5280 profile + a representative
 * CABF TLS BR subset). Unlike every other toolkit entry, the lint DATA path never throws --
 * it surveys a corpus that includes malformed members, so hostile bytes return a LintReport
 * whose worst finding is a `fatal` id lint/unparseable (carrying the inner PkiError code),
 * and only CONFIG-time misuse (unknown profile / bad opts) throws a typed LintError. These
 * vectors pin that inversion, the per-rule finding ids + severities, applicability (NA),
 * the effective-date window (NE), the severity threshold, determinism, and bytes/parsed
 * parity -- all driving the SHIPPED pki.lint.certificate consumer path.
 */

var pki = require("../../index.js");
var asn1 = require("../../lib/asn1-der");
var b = asn1.build;
var oid = require("../../lib/oid");
var helpers = require("../helpers");
var vectors = helpers.vectors;
var check = helpers.check;

function throwsCode(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
// A report's finding ids (in order) + a helper to test membership + severity.
function ids(report) { return report.findings.map(function (f) { return f.id; }); }
function has(report, id) { return report.findings.some(function (f) { return f.id === id; }); }
function sevOf(report, id) { var f = report.findings.filter(function (x) { return x.id === id; })[0]; return f && f.severity; }

// ---- cert fixtures: derive from a real v3 cert, swap individual TBS fields ----
// x509.parse is STRUCTURAL (a placeholder signature is fine), so mutating serial / validity
// / subject / extensions yields a parseable cert that exercises one profile rule.
var REAL = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM);
function tbsKids() { return asn1.decode(REAL).children[0].children.map(function (c) { return c.bytes; }); }
function assemble(kids) { var c = asn1.decode(REAL); return b.sequence([b.sequence(kids), c.children[1].bytes, c.children[2].bytes]); }
function makeCert(opts) {
  opts = opts || {};
  var kids = tbsKids();
  if (opts.serial !== undefined) kids[1] = opts.serial;
  if (opts.issuer !== undefined) kids[3] = opts.issuer;
  if (opts.validity !== undefined) kids[4] = opts.validity;
  if (opts.subject !== undefined) kids[5] = opts.subject;
  if (opts.spki !== undefined) kids[6] = opts.spki;
  if (opts.exts !== undefined) kids[7] = b.explicit(3, b.sequence(opts.exts));
  return assemble(kids);
}
// Extension { extnID, [critical], extnValue OCTET STRING wrapping innerDer }.
function ext(name, critical, innerDer) {
  var kids = [b.oid(oid.byName(name))];
  if (critical) kids.push(b.boolean(true));
  kids.push(b.octetString(innerDer));
  return b.sequence(kids);
}
function extByOid(dotted, critical, innerDer) {
  var kids = [b.oid(dotted)];
  if (critical) kids.push(b.boolean(true));
  kids.push(b.octetString(innerDer));
  return b.sequence(kids);
}
function dnsName(v) { return b.contextPrimitive(2, Buffer.from(v, "ascii")); }
function san(names, critical) { return ext("subjectAltName", critical, b.sequence(names)); }
// keyUsage BIT STRING over the named-bit positions (digitalSignature=0 .. decipherOnly=8).
function keyUsage(bitIdxs, critical) {
  var maxBit = Math.max.apply(null, bitIdxs);
  var nbytes = Math.floor(maxBit / 8) + 1;
  var buf = Buffer.alloc(nbytes);
  bitIdxs.forEach(function (i) { buf[Math.floor(i / 8)] |= (0x80 >> (i % 8)); });
  return ext("keyUsage", critical, b.bitString(buf, nbytes * 8 - (maxBit + 1)));
}
function basicConstraints(ca, pathLen, critical) {
  var inner = [b.boolean(ca)];
  if (pathLen !== undefined && pathLen !== null) inner.push(b.integer(BigInt(pathLen)));
  return ext("basicConstraints", critical === undefined ? true : critical, b.sequence(inner));
}
function eku(names, critical) { return ext("extKeyUsage", !!critical, b.sequence(names.map(function (n) { return b.oid(oid.byName(n)); }))); }
function ski(bytes) { return ext("subjectKeyIdentifier", false, b.octetString(bytes || Buffer.alloc(20, 1))); }
function aki(keyId) { return ext("authorityKeyIdentifier", false, b.sequence([b.contextPrimitive(0, keyId || Buffer.alloc(20, 2))])); }
// NameConstraints { permittedSubtrees [0] SEQUENCE OF GeneralSubtree { base dNSName } } -- a
// valid value so extension-undecodable does not co-fire; the criticality rules read only .critical.
function nameConstraints(critical) {
  var subtree = b.sequence([b.contextPrimitive(2, Buffer.from("example.com", "ascii"))]);
  return ext("nameConstraints", critical, b.sequence([b.contextConstructed(0, subtree)]));
}
// PolicyConstraints { requireExplicitPolicy [0] INTEGER 0 }.
function policyConstraints(critical) { return ext("policyConstraints", critical, b.sequence([b.contextPrimitive(0, Buffer.from([0x00]))])); }
// InhibitAnyPolicy ::= INTEGER (SkipCerts 0).
function inhibitAnyPolicy(critical) { return ext("inhibitAnyPolicy", critical, b.integer(0n)); }
// A minimal RDNSequence with a single CN.
function dnCN(cn) { return b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8(cn)])])]); }
var EMPTY_DN = b.sequence([]);
var VALID_INVERTED = b.sequence([b.utcTime(new Date("2035-01-01T00:00:00Z")), b.utcTime(new Date("2020-01-01T00:00:00Z"))]);
// A conformant TLS validity window: ~59 days, notBefore after the 398-day rule's 2020-09-01
// effective date (so the rule is effective and passes).
var VALID_OK = b.sequence([b.utcTime(new Date("2026-01-01T00:00:00Z")), b.utcTime(new Date("2026-03-01T00:00:00Z"))]);
// A serial of 21 octets (exceeds the 20-octet ceiling); high bit clear so it stays positive.
var SERIAL_21 = b.integer(BigInt("0x1" + "00".repeat(20)));

function run() {
  // ---- engine: clean cert, never-throw data path, config-time throw ----
  var clean = pki.lint.certificate(REAL);
  check("a real cert lints with zero error/fatal findings", clean.counts.error === 0 && clean.counts.fatal === 0);
  check("a clean report's worst is at most notice", ["fatal", "error", "warn"].indexOf(clean.worst) === -1);
  check("lint accepts raw PEM/DER bytes too", pki.lint.certificate(REAL).findings !== undefined);
  // The counts map is keyed by severity names, so it carries no prototype, and it is built the same
  // way whether the certificate parsed or not. A report whose shape depended on which input arrived
  // would make a consumer's check pass on one certificate and fail on the next.
  var unparseable = pki.lint.certificate(Buffer.from([0]));
  check("counts carries no prototype on a parsed certificate", Object.getPrototypeOf(clean.counts) === null);
  check("counts is built the same way when the certificate does not parse",
    Object.getPrototypeOf(unparseable.counts) === Object.getPrototypeOf(clean.counts) && unparseable.counts.fatal === 1);

  // The load-bearing inversion: hostile bytes NEVER throw -- one fatal lint/unparseable.
  var truncated = pki.lint.certificate(REAL.subarray(0, 12));
  check("truncated DER does not throw -- returns a fatal lint/unparseable", has(truncated, "lint/unparseable") && truncated.worst === "fatal");
  check("lint/unparseable carries the inner PkiError code as context",
    truncated.findings[0].context && typeof truncated.findings[0].context.code === "string");
  check("garbage bytes do not throw either", pki.lint.certificate(Buffer.from([0xff, 0xff, 0xff])).worst === "fatal");

  // Config-time misuse is the ONLY throw path (a typed LintError).
  check("an unknown profile throws lint/unknown-profile", throwsCode(function () { pki.lint.certificate(REAL, { profile: "does-not-exist" }); }) === "lint/unknown-profile");
  check("an inherited-property profile (toString) throws lint/unknown-profile, not a bare TypeError", throwsCode(function () { pki.lint.certificate(REAL, { profile: "toString" }); }) === "lint/unknown-profile");
  check("a wrong-type input throws lint/bad-input", throwsCode(function () { pki.lint.certificate(42); }) === "lint/bad-input");
  check("a bad severity threshold throws lint/bad-severity", throwsCode(function () { pki.lint.certificate(REAL, { severity: "nope" }); }) === "lint/bad-severity");

  // ---- RFC 5280 per-rule positives (each drives pki.lint.certificate, asserts id+severity) ----
  check("negative serial -> serial-not-positive (error)",
    sevOf(pki.lint.certificate(makeCert({ serial: b.integer(-1n) })), "lint/rfc5280/serial-not-positive") === "error");
  check("21-octet serial -> serial-too-long (error)",
    has(pki.lint.certificate(makeCert({ serial: SERIAL_21 })), "lint/rfc5280/serial-too-long"));
  check("notBefore > notAfter -> validity-inverted (error)",
    sevOf(pki.lint.certificate(makeCert({ validity: VALID_INVERTED })), "lint/rfc5280/validity-inverted") === "error");
  check("CA cert without keyCertSign -> ca-without-keycertsign (error)",
    has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([0], true)] })), "lint/rfc5280/ca-without-keycertsign"));
  check("a CA cert WITH keyCertSign does NOT flag ca-without-keycertsign",
    !has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([5], true), ski()] })), "lint/rfc5280/ca-without-keycertsign"));
  // The inverse coherence rule: keyCertSign asserted without cA=TRUE is a violation.
  check("keyCertSign asserted without cA -> keycertsign-without-ca (error)",
    sevOf(pki.lint.certificate(makeCert({ exts: [keyUsage([5], true)] })), "lint/rfc5280/keycertsign-without-ca") === "error");
  check("keyCertSign with cA=TRUE does NOT flag keycertsign-without-ca",
    !has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([5], true), ski()] })), "lint/rfc5280/keycertsign-without-ca"));
  check("a leaf without keyCertSign does NOT flag keycertsign-without-ca",
    !has(pki.lint.certificate(makeCert({ exts: [keyUsage([0], true)] })), "lint/rfc5280/keycertsign-without-ca"));
  check("an unknown critical extension -> unknown-critical-extension (error)",
    has(pki.lint.certificate(makeCert({ exts: [extByOid("1.3.6.1.4.1.99999.7.7", true, b.nullValue())] })), "lint/rfc5280/unknown-critical-extension"));
  // Strict-parse pre-emption (Open Q8): a duplicate extension OID / pathLen-without-cA are
  // rejected at PARSE, so they surface as a fatal lint/unparseable naming the exact code --
  // not a dedicated finding. Pin that documented behavioral difference here.
  check("a duplicate extension OID surfaces as lint/unparseable (strict-parse pre-emption)",
    has(pki.lint.certificate(makeCert({ exts: [ski(Buffer.alloc(20, 1)), ski(Buffer.alloc(20, 2))] })), "lint/unparseable"));
  check("empty subject with a non-critical SAN -> empty-subject-san-not-critical (error)",
    has(pki.lint.certificate(makeCert({ subject: EMPTY_DN, exts: [san([dnsName("x.example")], false)] })), "lint/rfc5280/empty-subject-san-not-critical"));
  check("empty subject with a CRITICAL SAN does NOT flag it",
    !has(pki.lint.certificate(makeCert({ subject: EMPTY_DN, exts: [san([dnsName("x.example")], true)] })), "lint/rfc5280/empty-subject-san-not-critical"));
  check("an undecodable known extension -> extension-undecodable (error)",
    has(pki.lint.certificate(makeCert({ exts: [ext("basicConstraints", true, b.integer(5n))] })), "lint/rfc5280/extension-undecodable"));

  // SHOULD-level advisories (notice).
  check("a CA cert without SKI -> ski-missing (notice)",
    sevOf(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([5], true)] })), "lint/rfc5280/ski-missing") === "notice");
  check("a non-self-signed cert without AKI -> aki-missing (notice)",
    has(pki.lint.certificate(makeCert({ subject: dnCN("leaf.example") })), "lint/rfc5280/aki-missing"));

  // ---- RFC 5280 extension criticality + CA-scope coherence lints ----
  // basicConstraints: a CA whose key validates certificate signatures (keyCertSign) MUST mark
  // basicConstraints critical (4.2.1.9). A non-critical instance is an error.
  var bcNotCrit = pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, false), keyUsage([5], true), ski()] }));
  check("a CA (keyCertSign) with non-critical basicConstraints -> basic-constraints-not-critical (error)",
    sevOf(bcNotCrit, "lint/rfc5280/basic-constraints-not-critical") === "error");
  check("the basicConstraints fixture does not co-fire ca-without-keycertsign or ski-missing",
    !has(bcNotCrit, "lint/rfc5280/ca-without-keycertsign") && !has(bcNotCrit, "lint/rfc5280/ski-missing"));
  check("a critical basicConstraints does NOT flag basic-constraints-not-critical",
    !has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([5], true), ski()] })), "lint/rfc5280/basic-constraints-not-critical"));
  // RFC 5280 4.2.1.9: a CA key used EXCLUSIVELY for non-cert-signing (e.g. CRL signing) MAY carry a
  // non-critical basicConstraints -> the rule is NA (no keyCertSign), not a false-positive error.
  check("a CRL-signing-only CA (no keyCertSign) with non-critical BC is NA, not flagged",
    !has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, false), keyUsage([6], true), ski()] })), "lint/rfc5280/basic-constraints-not-critical"));
  // A CA with NO keyUsage cannot rule out certificate-signing, so MUST-critical still applies.
  check("a CA with no keyUsage and non-critical basicConstraints -> basic-constraints-not-critical",
    has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, false), ski()] })), "lint/rfc5280/basic-constraints-not-critical"));

  // nameConstraints MUST be critical (4.2.1.10) -- in a CA so name-constraints-not-ca does not co-fire.
  var ncNotCrit = pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([5], true), ski(), nameConstraints(false)] }));
  check("a CA with non-critical nameConstraints -> name-constraints-not-critical (error)",
    sevOf(ncNotCrit, "lint/rfc5280/name-constraints-not-critical") === "error");
  check("the nameConstraints fixture does not co-fire unknown-critical-extension or extension-undecodable",
    !has(ncNotCrit, "lint/rfc5280/unknown-critical-extension") && !has(ncNotCrit, "lint/rfc5280/extension-undecodable"));
  check("a critical nameConstraints in a CA does NOT flag name-constraints-not-critical",
    !has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([5], true), ski(), nameConstraints(true)] })), "lint/rfc5280/name-constraints-not-critical"));

  // nameConstraints MUST appear only in a CA certificate (4.2.1.10) -- critical NC in a non-CA cert.
  var ncNotCa = pki.lint.certificate(makeCert({ exts: [nameConstraints(true), aki()] }));
  check("a critical nameConstraints in a non-CA cert -> name-constraints-not-ca (error)",
    sevOf(ncNotCa, "lint/rfc5280/name-constraints-not-ca") === "error");
  check("the non-CA nameConstraints fixture does not co-fire name-constraints-not-critical (it IS critical)",
    !has(ncNotCa, "lint/rfc5280/name-constraints-not-critical"));
  check("nameConstraints in a CA cert does NOT flag name-constraints-not-ca",
    !has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([5], true), ski(), nameConstraints(true)] })), "lint/rfc5280/name-constraints-not-ca"));

  // policyConstraints MUST be critical (4.2.1.11).
  check("a non-critical policyConstraints -> policy-constraints-not-critical (error)",
    sevOf(pki.lint.certificate(makeCert({ exts: [policyConstraints(false)] })), "lint/rfc5280/policy-constraints-not-critical") === "error");
  check("a critical policyConstraints does NOT flag policy-constraints-not-critical",
    !has(pki.lint.certificate(makeCert({ exts: [policyConstraints(true)] })), "lint/rfc5280/policy-constraints-not-critical"));

  // inhibitAnyPolicy MUST be critical (4.2.1.14).
  check("a non-critical inhibitAnyPolicy -> inhibit-any-policy-not-critical (error)",
    sevOf(pki.lint.certificate(makeCert({ exts: [inhibitAnyPolicy(false)] })), "lint/rfc5280/inhibit-any-policy-not-critical") === "error");
  check("a critical inhibitAnyPolicy does NOT flag inhibit-any-policy-not-critical",
    !has(pki.lint.certificate(makeCert({ exts: [inhibitAnyPolicy(true)] })), "lint/rfc5280/inhibit-any-policy-not-critical"));

  // keyUsage SHOULD be critical (4.2.1.3) -- present-gated: the issuing CA should mark keyUsage
  // critical in ANY certificate (EE or CA), so a non-critical keyUsage on a leaf warns too.
  check("a non-critical keyUsage on an end-entity cert -> key-usage-not-critical (warn)",
    sevOf(pki.lint.certificate(makeCert({ exts: [keyUsage([0], false), aki()] })), "lint/rfc5280/key-usage-not-critical") === "warn");
  check("a critical keyUsage does NOT flag key-usage-not-critical",
    !has(pki.lint.certificate(makeCert({ exts: [keyUsage([0], true), aki()] })), "lint/rfc5280/key-usage-not-critical"));
  check("a cert with no keyUsage is NA for key-usage-not-critical",
    !has(pki.lint.certificate(makeCert({ exts: [ski(), aki()] })), "lint/rfc5280/key-usage-not-critical"));

  // end-entity SKI SHOULD be present (4.2.1.2) -- notice; distinct from the CA-only ski-missing.
  var eeNoSki = pki.lint.certificate(makeCert({ exts: [keyUsage([0], true), aki()] }));
  check("an end-entity cert without SKI -> ski-missing-ee (notice)",
    sevOf(eeNoSki, "lint/rfc5280/ski-missing-ee") === "notice");
  check("the EE-SKI fixture carries an AKI so aki-missing does not blur it", !has(eeNoSki, "lint/rfc5280/aki-missing"));
  check("an end-entity cert WITH an SKI does NOT flag ski-missing-ee",
    !has(pki.lint.certificate(makeCert({ exts: [keyUsage([0], true), ski(), aki()] })), "lint/rfc5280/ski-missing-ee"));
  check("a CA cert is NA for ski-missing-ee (the CA path is ski-missing)",
    !has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([5], true), ski()] })), "lint/rfc5280/ski-missing-ee"));

  // ---- CABF TLS BR subset (applies to a TLS server cert) ----
  var tlsCert = makeCert({ subject: dnCN("example.com"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName("example.com")], false), aki()] });
  check("a conformant TLS cert has no cabf-tls error", pki.lint.certificate(tlsCert).findings.every(function (f) { return f.source !== "cabf-tls" || (f.severity !== "error" && f.severity !== "fatal"); }));
  check("a TLS cert with no SAN -> san-missing (error)",
    has(pki.lint.certificate(makeCert({ subject: dnCN("example.com"), exts: [eku(["serverAuth"]), aki()] })), "lint/cabf-tls/san-missing"));
  // A SAN that is present but does not decode (or carries no names) is not usable -> missing.
  check("a present-but-undecodable SAN is treated as missing -> san-missing",
    has(pki.lint.certificate(makeCert({ subject: dnCN("example.com"), validity: VALID_OK, exts: [eku(["serverAuth"]), ext("subjectAltName", false, b.integer(5n)), aki()] })), "lint/cabf-tls/san-missing"));
  check("a CN not present as a dNSName SAN -> cn-not-in-san (error)",
    has(pki.lint.certificate(makeCert({ subject: dnCN("notlisted.example"), exts: [eku(["serverAuth"]), san([dnsName("other.example")], false), aki()] })), "lint/cabf-tls/cn-not-in-san"));
  // dNSNames are case-insensitive: a CN differing from its SAN only in case is NOT a finding.
  check("a CN matching a SAN case-insensitively does NOT flag cn-not-in-san",
    !has(pki.lint.certificate(makeCert({ subject: dnCN("Example.COM"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName("example.com")], false), aki()] })), "lint/cabf-tls/cn-not-in-san"));
  // An IP-literal CN is validated against an iPAddress SAN (out of this subset's scope), so
  // it is skipped -- not false-flagged against the dNSName list.
  check("an IP-literal CN does NOT flag cn-not-in-san",
    !has(pki.lint.certificate(makeCert({ subject: dnCN("192.0.2.1"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName("example.com")], false), aki()] })), "lint/cabf-tls/cn-not-in-san"));
  // A colon-bearing CN that is NOT a valid IPv6 literal ("api:443") is not an IP, so it is
  // checked as a hostname against the SAN dNSNames -> cn-not-in-san fires (not skipped).
  check("a non-IP colon CN (api:443) is checked, not skipped -> cn-not-in-san",
    has(pki.lint.certificate(makeCert({ subject: dnCN("api:443"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName("other.example")], false), aki()] })), "lint/cabf-tls/cn-not-in-san"));
  check("a dNSName with an underscore -> dnsname-bad-syntax (error)",
    has(pki.lint.certificate(makeCert({ subject: dnCN("bad_host.example"), exts: [eku(["serverAuth"]), san([dnsName("bad_host.example")], false), aki()] })), "lint/cabf-tls/dnsname-bad-syntax"));
  // eku-missing-serverauth only fires under an EXPLICIT cabf-tls profile selection.
  check("explicit cabf-tls profile + no serverAuth EKU -> eku-missing-serverauth (error)",
    has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), exts: [san([dnsName("x.example")], false)] }), { profile: "cabf-tls" }), "lint/cabf-tls/eku-missing-serverauth"));
  // A >398-day validity on a TLS cert (issued after the rule's effective date) -> too-long.
  check("a TLS cert with a >398-day validity -> validity-too-long (error)",
    has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), exts: [eku(["serverAuth"]), san([dnsName("x.example")], false), aki()] })), "lint/cabf-tls/validity-too-long"));
  // The SC081v3 reducing schedule: a cert issued on/after 2026-03-15 is held to 200 days,
  // so a 250-day validity there fails though it would pass under the earlier 398-day ceiling.
  function vwin(fromIso, days) { var nb = new Date(fromIso); return b.sequence([b.utcTime(nb), b.utcTime(new Date(nb.getTime() + days * 86400000))]); }
  function tlsWith(validity) { return makeCert({ subject: dnCN("x.example"), validity: validity, exts: [eku(["serverAuth"]), san([dnsName("x.example")], false), aki()] }); }
  check("a 250-day cert issued after 2026-03-15 -> validity-too-long (200-day tier)",
    has(pki.lint.certificate(tlsWith(vwin("2026-04-01T00:00:00Z", 250))), "lint/cabf-tls/validity-too-long"));
  check("a 150-day cert issued after 2026-03-15 passes the 200-day tier",
    !has(pki.lint.certificate(tlsWith(vwin("2026-04-01T00:00:00Z", 150))), "lint/cabf-tls/validity-too-long"));
  check("a 300-day cert issued before 2026-03-15 passes (still the 398-day tier)",
    !has(pki.lint.certificate(tlsWith(vwin("2026-01-01T00:00:00Z", 300))), "lint/cabf-tls/validity-too-long"));
  check("a 150-day cert issued after 2027-03-15 -> validity-too-long (100-day tier)",
    has(pki.lint.certificate(tlsWith(vwin("2027-04-01T00:00:00Z", 150))), "lint/cabf-tls/validity-too-long"));
  check("a 60-day cert issued after 2029-03-15 -> validity-too-long (47-day tier)",
    has(pki.lint.certificate(tlsWith(vwin("2029-04-01T00:00:00Z", 60))), "lint/cabf-tls/validity-too-long"));
  // An RSA-1024 key -> weak-key. Splice a real RSA-1024 SPKI (crypto.generateKeyPairSync).
  var rsa1024 = require("crypto").generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({ format: "der", type: "spki" });
  check("an RSA-1024 subject key -> weak-key (error)",
    has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, spki: rsa1024, exts: [eku(["serverAuth"]), san([dnsName("x.example")], false), aki()] })), "lint/cabf-tls/weak-key"));

  // ---- applicability (NA) + effective-date (NE) ----
  // A cabf-tls rule reports NA on a non-TLS cert (no serverAuth EKU, default profile).
  var nonTls = pki.lint.certificate(makeCert({ subject: dnCN("x.example"), exts: [aki()] }));
  check("cabf-tls rules are NA on a non-TLS cert (no spurious finding)",
    !nonTls.findings.some(function (f) { return f.source === "cabf-tls"; }) && nonTls.counts.na > 0);
  // The default profile still runs rfc5280 on that same cert.
  check("rfc5280 still runs on a non-TLS cert", nonTls.ran.some(function (r) { return r.indexOf("lint/rfc5280/") === 0; }));
  // Effective-date window (NE): a TLS cert whose notBefore predates the 398-day rule's
  // 2020-09-01 effective date is NOT subject to it -- the rule reports NE, never fires,
  // even though its (long) validity would violate the current ceiling. Pins invariant 8.
  var PRE_2020 = b.sequence([b.utcTime(new Date("2018-01-01T00:00:00Z")), b.utcTime(new Date("2019-06-01T00:00:00Z"))]);
  var oldCert = pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: PRE_2020, exts: [eku(["serverAuth"]), san([dnsName("x.example")], false), aki()] }));
  check("a date-gated rule reports NE before its effective date (never fires)", !has(oldCert, "lint/cabf-tls/validity-too-long") && oldCert.counts.ne > 0);

  // ---- severity threshold ----
  var withNotices = pki.lint.certificate(makeCert({ subject: dnCN("leaf.example") }));  // aki-missing notice
  var filtered = pki.lint.certificate(makeCert({ subject: dnCN("leaf.example") }), { severity: "error" });
  check("a severity:error threshold suppresses notice-level findings", !has(filtered, "lint/rfc5280/aki-missing") && has(withNotices, "lint/rfc5280/aki-missing"));
  check("the threshold filters findings but leaves counts complete", filtered.counts.notice === withNotices.counts.notice);

  // ---- determinism + bytes/parsed parity ----
  var r1 = pki.lint.certificate(makeCert({ serial: b.integer(-1n) }));
  var r2 = pki.lint.certificate(makeCert({ serial: b.integer(-1n) }));
  check("two runs over the same bytes produce identical finding ids", JSON.stringify(ids(r1)) === JSON.stringify(ids(r2)));
  var derBytes = makeCert({ serial: b.integer(-1n) });
  var parsed = pki.schema.x509.parse(derBytes);
  check("bytes-path and parsed-object-path agree", JSON.stringify(ids(pki.lint.certificate(derBytes))) === JSON.stringify(ids(pki.lint.certificate(parsed))));
  // A lint report is a decision an operator acts on, so it describes the certificate the BYTES
  // describe. Every rule reads a sibling field off the object and none re-derives it, so an
  // assembled object would otherwise produce a report -- possibly a clean one -- about fields that
  // were never in any certificate. The report is taken from the parser's record instead, so editing
  // the object changes nothing about what is reported.
  var lintEdited = pki.schema.x509.parse(derBytes);
  lintEdited.serialNumber = 1n;                       // the negative serial the bytes carry is the finding
  check("editing a parsed certificate does not change what lint reports",
    JSON.stringify(ids(pki.lint.certificate(lintEdited))) === JSON.stringify(ids(pki.lint.certificate(derBytes))));
  // ...and an object the parser never produced is not linted as though it were a certificate. It is
  // a wrong-TYPE argument -- not one of the accepted forms -- so it takes this verb's config-misuse
  // throw rather than yielding a findings list about fields a caller wrote. Telling the caller their
  // input was not a certificate is the useful answer; a clean report over it would not be.
  var lintRebuilt = Object.assign({}, pki.schema.x509.parse(derBytes));
  check("a rebuilt certificate object is refused as a wrong-type input, not linted",
    throwsCode(function () { pki.lint.certificate(lintRebuilt); }) === "lint/bad-input");

  // ---- ingestion variants + config throws (coverage of the ingest + select paths) ----
  check("lint accepts a PEM string input", pki.lint.certificate(vectors.CERT_EC_PEM).counts.error === 0);
  check("an undecodable PEM string -> fatal lint/unparseable (no throw)",
    has(pki.lint.certificate("-----BEGIN CERTIFICATE-----\nnotbase64!!!\n-----END CERTIFICATE-----"), "lint/unparseable"));
  check("a non-object opts throws lint/bad-input", throwsCode(function () { pki.lint.certificate(REAL, "not-an-object"); }) === "lint/bad-input");
  check("profile:all runs both profiles' rules", pki.lint.certificate(tlsCert, { profile: "all" }).ran.some(function (r) { return r.indexOf("lint/cabf-tls/") === 0; }));
  check("profile:rfc5280 runs no cabf-tls rule", pki.lint.certificate(tlsCert, { profile: "rfc5280" }).ran.every(function (r) { return r.indexOf("lint/cabf-tls/") !== 0; }));

  // weak-key EC branch: a non-approved named curve (secp256k1) -> weak-key.
  var ecBad = require("crypto").generateKeyPairSync("ec", { namedCurve: "secp256k1" }).publicKey.export({ format: "der", type: "spki" });
  check("a non-approved EC curve -> weak-key (error)",
    has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, spki: ecBad, exts: [eku(["serverAuth"]), san([dnsName("x.example")], false), aki()] })), "lint/cabf-tls/weak-key"));

  // dNSName syntax branches: whitespace + a leading dot (beyond the underscore case above).
  check("a dNSName with whitespace -> dnsname-bad-syntax",
    has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName("a b.example")], false), aki()] })), "lint/cabf-tls/dnsname-bad-syntax"));
  check("a dNSName with a leading dot -> dnsname-bad-syntax",
    has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName(".example.com")], false), aki()] })), "lint/cabf-tls/dnsname-bad-syntax"));
  check("a dNSName with an internal empty label -> dnsname-bad-syntax",
    has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName("a..b.example")], false), aki()] })), "lint/cabf-tls/dnsname-bad-syntax"));
  check("a dNSName with a non-LDH character -> dnsname-bad-syntax",
    has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName("exa$mple.com")], false), aki()] })), "lint/cabf-tls/dnsname-bad-syntax"));
  check("a leftmost-wildcard dNSName is well-formed (not flagged)",
    !has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName("*.example.com")], false), aki()] })), "lint/cabf-tls/dnsname-bad-syntax"));
  function dnsCert(name) { return makeCert({ subject: dnCN("x.example"), validity: VALID_OK, exts: [eku(["serverAuth"]), san([dnsName(name)], false), aki()] }); }
  check("a bare wildcard dNSName -> dnsname-bad-syntax", has(pki.lint.certificate(dnsCert("*")), "lint/cabf-tls/dnsname-bad-syntax"));
  check("a label beginning with a hyphen -> dnsname-bad-syntax", has(pki.lint.certificate(dnsCert("-bad.example")), "lint/cabf-tls/dnsname-bad-syntax"));
  check("a label ending with a hyphen -> dnsname-bad-syntax", has(pki.lint.certificate(dnsCert("bad-.example")), "lint/cabf-tls/dnsname-bad-syntax"));
  check("a label over 63 octets -> dnsname-bad-syntax", has(pki.lint.certificate(dnsCert(new Array(65).join("a") + ".example")), "lint/cabf-tls/dnsname-bad-syntax"));
  check("a dNSName over 253 octets -> dnsname-bad-syntax", has(pki.lint.certificate(dnsCert([1, 2, 3, 4].map(function () { return new Array(64).join("a"); }).join("."))), "lint/cabf-tls/dnsname-bad-syntax"));
  // A serial whose value has its high bit set carries a DER 0x00 sign pad; the octet COUNT
  // must strip it, so a 20-value-octet serial does NOT trip serial-too-long (covers the strip).
  var SERIAL_20_HIGHBIT = b.integer(BigInt("0x80" + "00".repeat(19)));
  check("a 20-octet high-bit serial (with DER sign pad) does NOT trip serial-too-long",
    !has(pki.lint.certificate(makeCert({ serial: SERIAL_20_HIGHBIT })), "lint/rfc5280/serial-too-long"));
  // Explicit cabf-tls profile WITH serverAuth present -> the eku rule passes (no finding).
  check("explicit cabf-tls profile + serverAuth present passes the eku rule",
    !has(pki.lint.certificate(tlsCert, { profile: "cabf-tls" }), "lint/cabf-tls/eku-missing-serverauth"));
  // A conformant RSA-2048 key passes weak-key (the RSA >= 2048 branch).
  var rsa2048 = require("crypto").generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "der", type: "spki" });
  check("a conformant RSA-2048 key does NOT trip weak-key",
    !has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, spki: rsa2048, exts: [eku(["serverAuth"]), san([dnsName("x.example")], false), aki()] })), "lint/cabf-tls/weak-key"));
  // An RSASSA-PSS key is also weighed by modulus size (it carries an RSAPublicKey SPKI).
  var rsaPss1024 = require("crypto").generateKeyPairSync("rsa-pss", { modulusLength: 1024 }).publicKey.export({ format: "der", type: "spki" });
  check("a weak RSASSA-PSS key -> weak-key (error)",
    has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, spki: rsaPss1024, exts: [eku(["serverAuth"]), san([dnsName("x.example")], false), aki()] })), "lint/cabf-tls/weak-key"));

  // weak-key is scoped to RSA size + EC curve: another key type (Ed25519) is out of scope
  // and does NOT fire weak-key (key-TYPE approval for TLS is a separate future rule).
  var ed25519 = require("crypto").generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" });
  check("an Ed25519 key does NOT trip weak-key (out of the size/curve scope)",
    !has(pki.lint.certificate(makeCert({ subject: dnCN("x.example"), validity: VALID_OK, spki: ed25519, exts: [eku(["serverAuth"]), san([dnsName("x.example")], false), aki()] })), "lint/cabf-tls/weak-key"));
  function tlsKeyCert(spki) { return makeCert({ subject: dnCN("x.example"), validity: VALID_OK, spki: spki, exts: [eku(["serverAuth"]), san([dnsName("x.example")], false), aki()] }); }
  // Fail-closed: an EC key with EXPLICIT (non-named-curve) parameters is not on an approved
  // curve -> weak-key. Swap a real P-256 SPKI's curve OID for an explicit-params SEQUENCE.
  var ecNode = asn1.decode(require("crypto").generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "der", type: "spki" }));
  var explicitParamsSpki = b.sequence([b.sequence([b.oid(oid.byName("ecPublicKey")), b.sequence([b.integer(1n)])]), ecNode.children[1].bytes]);
  check("an EC key with explicit (non-named) parameters -> weak-key (fail-closed)",
    has(pki.lint.certificate(tlsKeyCert(explicitParamsSpki)), "lint/cabf-tls/weak-key"));
  // Fail-closed: an EC key with ABSENT AlgorithmIdentifier parameters carries no named curve.
  // The algorithm SEQUENCE holds only the ecPublicKey OID, so the strict parser records
  // algorithm.parameters === null; _ecCurveName's non-Buffer params guard fires and resolves a
  // null curve (not in APPROVED_EC_CURVES) -> weak-key with context.curve null. Distinct from
  // the explicit-params case above (a SEQUENCE is a Buffer -> the decode catch resolves it).
  var ecNoParamsSpki = b.sequence([b.sequence([b.oid(oid.byName("ecPublicKey"))]), ecNode.children[1].bytes]);
  var ecNoParamsReport = pki.lint.certificate(tlsKeyCert(ecNoParamsSpki));
  var ecNoParamsWeak = ecNoParamsReport.findings.filter(function (f) { return f.id === "lint/cabf-tls/weak-key"; })[0];
  check("an EC key with absent parameters -> weak-key (curve null, fail-closed)",
    has(ecNoParamsReport, "lint/cabf-tls/weak-key") && ecNoParamsWeak && ecNoParamsWeak.context.curve === null);
  // Fail-closed: an RSA SPKI whose publicKey is not a decodable RSAPublicKey -> weak-key.
  var rsaNode = asn1.decode(require("crypto").generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "der", type: "spki" }));
  var badModulusSpki = b.sequence([rsaNode.children[0].bytes, b.bitString(Buffer.from([0xde, 0xad, 0xbe, 0xef]), 0)]);
  check("an RSA key with an unreadable modulus -> weak-key (fail-closed)",
    has(pki.lint.certificate(tlsKeyCert(badModulusSpki)), "lint/cabf-tls/weak-key"));
  // A negative RSA modulus (a high-bit key mis-encoded without a sign pad) is malformed --
  // it must fail closed, not be sized by absolute value into a passing >= 2048.
  var rsaHdr = rsaNode.children[0].bytes;
  var negModSpki = b.sequence([rsaHdr, b.bitString(b.sequence([b.integer(-(1n << 2047n)), b.integer(65537n)]), 0)]);
  check("a negative RSA modulus -> weak-key (not abs-valued into a pass)",
    has(pki.lint.certificate(tlsKeyCert(negModSpki)), "lint/cabf-tls/weak-key"));
  // An RSAPublicKey missing the exponent is malformed -> weak-key.
  var noExpSpki = b.sequence([rsaHdr, b.bitString(b.sequence([b.integer((1n << 2047n) | 1n)]), 0)]);
  check("an RSA key missing the exponent -> weak-key (fail-closed)",
    has(pki.lint.certificate(tlsKeyCert(noExpSpki)), "lint/cabf-tls/weak-key"));
  // An RSAES-OAEP key also carries an RSAPublicKey, so a weak one is weighed by weak-key.
  var oaepSpki = b.sequence([b.sequence([b.oid(oid.byName("rsaesOaep")), b.nullValue()]), b.bitString(b.sequence([b.integer((1n << 1023n) | 1n), b.integer(65537n)]), 0)]);
  check("a weak RSAES-OAEP key -> weak-key (error)", has(pki.lint.certificate(tlsKeyCert(oaepSpki)), "lint/cabf-tls/weak-key"));

  // unknown-critical-extension mirrors path-validate's processed set. policyMappings is prepare-next-
  // only and unprocessed on the TARGET certificate; path-validate decides target status by path
  // position, so ANY cert (a leaf OR a subordinate CA) can be validated as the target where a critical
  // instance is rejected. A linter has no path context, so it flags a critical policyMappings on both.
  var pmVal = b.sequence([b.sequence([b.oid("2.5.29.32.0"), b.oid("2.5.29.32.0")])]);
  check("a critical policyMappings on a leaf cert IS unknown-critical (unprocessed on the target)",
    has(pki.lint.certificate(makeCert({ exts: [ext("policyMappings", true, pmVal)] })), "lint/rfc5280/unknown-critical-extension"));
  check("a critical policyMappings on a CA cert is ALSO flagged (a subordinate CA can be a path target)",
    has(pki.lint.certificate(makeCert({ exts: [basicConstraints(true, null, true), keyUsage([5], true), ski(), ext("policyMappings", true, pmVal)] })), "lint/rfc5280/unknown-critical-extension"));
  check("a NON-critical policyMappings is not unknown-critical",
    !has(pki.lint.certificate(makeCert({ exts: [ext("policyMappings", false, pmVal)] })), "lint/rfc5280/unknown-critical-extension"));
  // A critical extension carrying a NON-extension OID (an algorithm OID the name registry
  // resolves) is still unknown-critical -- recognition is scoped to extension OIDs.
  check("a critical extension with an algorithm OID is still unknown-critical",
    has(pki.lint.certificate(makeCert({ exts: [extByOid(oid.byName("sha256"), true, b.nullValue())] })), "lint/rfc5280/unknown-critical-extension"));
  // qcStatements decodes for display but its CRITICAL semantics are not processed here (path-validate
  // rejects a critical instance for the same reason), so a critical qcStatements is still flagged --
  // structural decodability is not validation processing -- while a non-critical one is informational.
  var qcExtVal = b.sequence([b.sequence([b.oid(oid.byName("qcCompliance"))])]);
  check("a critical qcStatements is unknown-critical (decoded, but semantics not processed)",
    has(pki.lint.certificate(makeCert({ exts: [ext("qcStatements", true, qcExtVal)] })), "lint/rfc5280/unknown-critical-extension"));
  check("a non-critical qcStatements is NOT unknown-critical (informational, still decoded)",
    !has(pki.lint.certificate(makeCert({ exts: [ext("qcStatements", false, qcExtVal)] })), "lint/rfc5280/unknown-critical-extension"));
  // Recognition mirrors path-validate's PROCESSED_EXTENSIONS, not the decoder table: a decode-only
  // extension the validator does NOT process is flagged when critical (an authorityKeyIdentifier and
  // an MS enterprise-CA extension both decode for display but MUST be non-critical), while
  // precertificatePoison -- the one decode-only extension RFC 6962 REQUIRES critical -- is not flagged.
  check("a critical authorityKeyIdentifier is unknown-critical (decode-only, not path-processed)",
    has(pki.lint.certificate(makeCert({ exts: [extByOid(oid.byName("authorityKeyIdentifier"), true, b.nullValue())] })), "lint/rfc5280/unknown-critical-extension"));
  check("a critical msCertificateTemplate is unknown-critical (decode-only enterprise extension)",
    has(pki.lint.certificate(makeCert({ exts: [extByOid(oid.byName("msCertificateTemplate"), true, b.sequence([b.oid("1.2.3")]))] })), "lint/rfc5280/unknown-critical-extension"));
  check("a critical precertificatePoison is NOT unknown-critical (RFC 6962 requires it critical)",
    !has(pki.lint.certificate(makeCert({ exts: [extByOid(oid.byName("precertificatePoison"), true, b.nullValue())] })), "lint/rfc5280/unknown-critical-extension"));

  // A CA certificate is NOT a TLS server (leaf) cert even with a serverAuth EKU: the
  // default profile must NOT apply the CABF leaf rules (e.g. san-missing) to it.
  var caWithServerAuth = makeCert({ subject: dnCN("Intermediate CA"), exts: [basicConstraints(true, null, true), keyUsage([5], true), eku(["serverAuth"]), ski(), aki()] });
  var caReport = pki.lint.certificate(caWithServerAuth);
  check("a CA with a serverAuth EKU does NOT get the CABF leaf san-missing rule",
    !has(caReport, "lint/cabf-tls/san-missing") && !caReport.findings.some(function (f) { return f.source === "cabf-tls"; }));
  check("but an EXPLICIT cabf-tls profile still lints a CA as a server cert", has(pki.lint.certificate(caWithServerAuth, { profile: "cabf-tls" }), "lint/cabf-tls/san-missing"));

  // ---- registry introspection ----
  check("pki.lint.rules('bad-profile') throws lint/unknown-profile", throwsCode(function () { pki.lint.rules("does-not-exist"); }) === "lint/unknown-profile");
  check("pki.lint.profiles() lists the profile names", pki.lint.profiles().indexOf("rfc5280") !== -1 && pki.lint.profiles().indexOf("cabf-tls") !== -1);
  check("pki.lint.rules() enumerates the registry with stable ids", pki.lint.rules().length > 10 && pki.lint.rules().every(function (r) { return typeof r.id === "string" && typeof r.citation === "string"; }));
  check("pki.lint.rules('rfc5280') filters to one profile", pki.lint.rules("rfc5280").every(function (r) { return r.source === "rfc5280"; }));

  // ---- RFC 9935 ML-KEM certificate rows ----
  // sec. 5: keyEncipherment MUST be the only key usage set; sec. 4: the SPKI BIT STRING
  // is the raw ek, exactly 800/1184/1568 octets FOR THE OID (the OID is the authority).
  var kemKp = require("node:crypto").generateKeyPairSync("ml-kem-768");
  var kemSpkiDer = kemKp.publicKey.export({ format: "der", type: "spki" });
  var kemEk = asn1.read.bitString(asn1.decode(kemSpkiDer).children[1]).bytes;
  function kemSpkiOf(bytes, set) {
    return b.sequence([b.sequence([b.oid(oid.byName("id-ml-kem-" + (set || 768)))]), b.bitString(bytes, 0)]);
  }
  var kemGood = makeCert({ spki: kemSpkiDer, exts: [keyUsage([2], true), ski()] });
  var kemGoodReport = pki.lint.certificate(kemGood);
  check("ML-KEM cert with keyEncipherment-only keyUsage is silent on the rfc9935 rows",
    !has(kemGoodReport, "lint/rfc9935/kem-key-usage") && !has(kemGoodReport, "lint/rfc9935/kem-key-length"));
  check("ML-KEM cert without keyUsage is silent on kem-key-usage (absent = unconstrained)",
    !has(pki.lint.certificate(makeCert({ spki: kemSpkiDer, exts: [ski()] })), "lint/rfc9935/kem-key-usage"));
  check("ML-KEM cert with digitalSignature keyUsage -> lint/rfc9935/kem-key-usage",
    has(pki.lint.certificate(makeCert({ spki: kemSpkiDer, exts: [keyUsage([0], true), ski()] })), "lint/rfc9935/kem-key-usage"));
  check("ML-KEM cert with keyEncipherment+keyAgreement -> lint/rfc9935/kem-key-usage",
    has(pki.lint.certificate(makeCert({ spki: kemSpkiDer, exts: [keyUsage([2, 4], true), ski()] })), "lint/rfc9935/kem-key-usage"));
  check("ML-KEM cert with a truncated ek -> lint/rfc9935/kem-key-length",
    has(pki.lint.certificate(makeCert({ spki: kemSpkiOf(kemEk.subarray(0, kemEk.length - 1)), exts: [keyUsage([2], true), ski()] })), "lint/rfc9935/kem-key-length"));
  check("ML-KEM cert with an OCTET-wrapped ek -> lint/rfc9935/kem-key-length (RFC 9935 sec. 4)",
    has(pki.lint.certificate(makeCert({ spki: kemSpkiOf(b.octetString(kemEk)), exts: [keyUsage([2], true), ski()] })), "lint/rfc9935/kem-key-length"));
  check("ML-KEM ek sized for a DIFFERENT set than the OID -> lint/rfc9935/kem-key-length",
    has(pki.lint.certificate(makeCert({ spki: kemSpkiOf(kemEk, 512), exts: [keyUsage([2], true), ski()] })), "lint/rfc9935/kem-key-length"));
  // RFC 9935 sec. 4: the ek BIT STRING must be BYTE-ALIGNED. A right-length key with a non-zero
  // unused-bit count is not the raw ek -- length alone is not sufficient. (Canonical-DER build
  // requires the unused low bit be zero, so clear it before declaring unusedBits=1.)
  var alignedEk = Buffer.from(kemEk); alignedEk[alignedEk.length - 1] &= 0xFE;
  var kemUnaligned = b.sequence([b.sequence([b.oid(oid.byName("id-ml-kem-768"))]), b.bitString(alignedEk, 1)]);
  check("ML-KEM ek in a non-octet-aligned BIT STRING (unusedBits=1) -> lint/rfc9935/kem-key-length",
    has(pki.lint.certificate(makeCert({ spki: kemUnaligned, exts: [keyUsage([2], true), ski()] })), "lint/rfc9935/kem-key-length"));
  check("a non-KEM cert never carries the rfc9935 rows",
    !has(pki.lint.certificate(REAL), "lint/rfc9935/kem-key-usage") && !has(pki.lint.certificate(REAL), "lint/rfc9935/kem-key-length"));

  // ---- RFC 9881 sec. 5 (ML-DSA) + RFC 9909 sec. 6 (SLH-DSA) key usage rows ----
  // Both clauses are the same pair of requirements, conditioned on keyUsage being PRESENT:
  // at least one of digitalSignature / nonRepudiation / keyCertSign / cRLSign MUST be set, and
  // none of keyEncipherment / dataEncipherment / keyAgreement / encipherOnly / decipherOnly may
  // be. The nine defined bits are exhausted by those two lists, so the only input that fails the
  // signing-bit half WITHOUT also setting a key-establishment bit is one whose sole bit is
  // reserved (bit 9 or above). A keyUsage with no bits at all cannot reach either rule: the
  // decoder refuses it as lint/bad-key-usage, surfaced as lint/rfc5280/extension-undecodable.
  var nodeCrypto = require("node:crypto");
  function spkiOf(type) { return nodeCrypto.generateKeyPairSync(type).publicKey.export({ format: "der", type: "spki" }); }
  function reOid(spkiDer, name) {
    var kids = asn1.decode(spkiDer).children;
    return b.sequence([b.sequence([b.oid(oid.byName(name))]), kids[1].bytes]);
  }
  var KU_DS = 0, KU_NR = 1, KU_KE = 2, KU_DE = 3, KU_KA = 4, KU_KCS = 5, KU_CRL = 6, KU_EO = 7, KU_DO = 8;
  var KU_RESERVED = 9;

  var mldsaSpki = spkiOf("ml-dsa-44");
  function mldsaReport(exts) { return pki.lint.certificate(makeCert({ spki: mldsaSpki, exts: exts })); }
  check("ML-DSA cert with digitalSignature keyUsage is silent on the rfc9881 row",
    !has(mldsaReport([keyUsage([KU_DS], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("ML-DSA cert with keyCertSign+cRLSign keyUsage is silent on the rfc9881 row",
    !has(mldsaReport([keyUsage([KU_KCS, KU_CRL], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("ML-DSA cert WITHOUT keyUsage is silent (RFC 9881 sec. 5 is conditioned on presence)",
    !has(mldsaReport([ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("ML-DSA cert asserting keyEncipherment -> lint/rfc9881/mldsa-key-usage",
    has(mldsaReport([keyUsage([KU_DS, KU_KE], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("ML-DSA cert asserting keyAgreement -> lint/rfc9881/mldsa-key-usage",
    has(mldsaReport([keyUsage([KU_DS, KU_KA], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("ML-DSA cert asserting dataEncipherment -> lint/rfc9881/mldsa-key-usage",
    has(mldsaReport([keyUsage([KU_DS, KU_DE], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("ML-DSA cert asserting encipherOnly -> lint/rfc9881/mldsa-key-usage",
    has(mldsaReport([keyUsage([KU_DS, KU_EO], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("ML-DSA cert asserting decipherOnly -> lint/rfc9881/mldsa-key-usage",
    has(mldsaReport([keyUsage([KU_DS, KU_DO], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("ML-DSA cert whose only keyUsage bit is reserved -> lint/rfc9881/mldsa-key-usage",
    has(mldsaReport([keyUsage([KU_RESERVED], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("ML-DSA cert with a reserved bit ALONGSIDE digitalSignature is silent (sec. 5 constrains neither)",
    !has(mldsaReport([keyUsage([KU_DS, KU_RESERVED], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("an empty ML-DSA keyUsage is refused by the decoder before any profile rule runs",
    has(mldsaReport([ext("keyUsage", true, b.bitString(Buffer.alloc(0), 0)), ski()]), "lint/rfc5280/extension-undecodable"));
  check("the rfc9881 row reaches all three ML-DSA parameter sets", ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]
    .every(function (t) {
      return has(pki.lint.certificate(makeCert({ spki: spkiOf(t), exts: [keyUsage([KU_KE], true), ski()] })), "lint/rfc9881/mldsa-key-usage");
    }));

  // RFC 9909 sec. 6 names BOTH the pure id-slh-dsa-* and the prehash id-hash-slh-dsa-* OIDs as
  // subject public key identifiers, so the rule must reach the prehash half too.
  var slhSpki = spkiOf("slh-dsa-sha2-128s");
  function slhReport(spki, exts) { return pki.lint.certificate(makeCert({ spki: spki, exts: exts })); }
  check("pure SLH-DSA cert with digitalSignature is silent on the rfc9909 row",
    !has(slhReport(slhSpki, [keyUsage([KU_DS], true), ski()]), "lint/rfc9909/slhdsa-key-usage"));
  check("pure SLH-DSA cert WITHOUT keyUsage is silent (conditioned on presence)",
    !has(slhReport(slhSpki, [ski()]), "lint/rfc9909/slhdsa-key-usage"));
  check("pure SLH-DSA cert asserting keyEncipherment -> lint/rfc9909/slhdsa-key-usage",
    has(slhReport(slhSpki, [keyUsage([KU_DS, KU_KE], true), ski()]), "lint/rfc9909/slhdsa-key-usage"));
  check("pure SLH-DSA cert asserting keyAgreement -> lint/rfc9909/slhdsa-key-usage",
    has(slhReport(slhSpki, [keyUsage([KU_NR, KU_KA], true), ski()]), "lint/rfc9909/slhdsa-key-usage"));
  check("pure SLH-DSA cert whose only keyUsage bit is reserved -> lint/rfc9909/slhdsa-key-usage",
    has(slhReport(slhSpki, [keyUsage([KU_RESERVED], true), ski()]), "lint/rfc9909/slhdsa-key-usage"));
  check("PREHASH HashSLH-DSA cert asserting keyEncipherment -> lint/rfc9909/slhdsa-key-usage",
    has(slhReport(reOid(slhSpki, "id-hash-slh-dsa-sha2-128s-with-sha256"), [keyUsage([KU_DS, KU_KE], true), ski()]),
      "lint/rfc9909/slhdsa-key-usage"));
  check("the rfc9909 row reaches a shake parameter set as well as a sha2 one",
    has(slhReport(reOid(spkiOf("slh-dsa-shake-128f"), "id-slh-dsa-shake-128f"), [keyUsage([KU_KE], true), ski()]),
      "lint/rfc9909/slhdsa-key-usage"));

  check("an ML-DSA cert never carries the SLH-DSA row, and the reverse",
    !has(mldsaReport([keyUsage([KU_KE], true), ski()]), "lint/rfc9909/slhdsa-key-usage") &&
    !has(slhReport(slhSpki, [keyUsage([KU_KE], true), ski()]), "lint/rfc9881/mldsa-key-usage"));
  check("a classical cert never carries either PQC signature row",
    !has(pki.lint.certificate(REAL), "lint/rfc9881/mldsa-key-usage") &&
    !has(pki.lint.certificate(REAL), "lint/rfc9909/slhdsa-key-usage"));
  // An SPKI algorithm outside every registry family parses with a null name, so the two
  // applicability tests read a name that is not a string and must decline rather than throw.
  var unknownSpki = b.sequence([b.sequence([b.oid("1.3.6.1.4.1.55738.777.1")]), b.bitString(Buffer.alloc(32, 7), 0)]);
  var unknownReport = pki.lint.certificate(makeCert({ spki: unknownSpki, exts: [keyUsage([KU_KE], true), ski()] }));
  check("a cert whose SPKI algorithm has no registered name carries neither PQC signature row",
    !has(unknownReport, "lint/rfc9881/mldsa-key-usage") && !has(unknownReport, "lint/rfc9909/slhdsa-key-usage"));
  check("pki.lint.profiles() lists the two PQC signature profiles",
    pki.lint.profiles().indexOf("rfc9881") !== -1 && pki.lint.profiles().indexOf("rfc9909") !== -1);
  check("pki.lint.rules('rfc9881') filters to that profile",
    pki.lint.rules("rfc9881").length > 0 && pki.lint.rules("rfc9881").every(function (r) { return r.source === "rfc9881"; }));
  check("pki.lint.rules('rfc9909') filters to that profile",
    pki.lint.rules("rfc9909").length > 0 && pki.lint.rules("rfc9909").every(function (r) { return r.source === "rfc9909"; }));

  // ---- RFC 5280 4.2.1.4 userNotice DisplayText ----
  // These four rules live here rather than in the decoder because 4.2.1.4 directs certificate users
  // to gracefully handle an over-long explicitText: a verifier that rejected one would refuse
  // certificates that exist in the wild. The linter is the layer that may report them, so each rule
  // is pinned firing on its own defect AND silent on a conforming notice (no false positive).
  function policyCert(qualifiers) {
    var v = b.sequence([b.sequence([b.oid(oid.byName("anyPolicy")), b.sequence(qualifiers)])]);
    return makeCert({ exts: [ext("certificatePolicies", false, v), ski()] });
  }
  function unoticeOf(displayTextDer) { return b.sequence([b.oid(oid.byName("unotice")), b.sequence([displayTextDer])]); }
  var dtClean = pki.lint.certificate(policyCert([unoticeOf(b.utf8("A short conforming notice"))]));
  check("a conforming explicitText raises none of the 4.2.1.4 findings",
    !has(dtClean, "lint/rfc5280/explicit-text-too-long") && !has(dtClean, "lint/rfc5280/explicit-text-bad-encoding")
    && !has(dtClean, "lint/rfc5280/explicit-text-control-chars") && !has(dtClean, "lint/rfc5280/explicit-text-not-nfc"));
  check("an explicitText over 200 characters -> lint/rfc5280/explicit-text-too-long (warn, not a reject)",
    has(pki.lint.certificate(policyCert([unoticeOf(b.utf8("a".repeat(201)))])), "lint/rfc5280/explicit-text-too-long"));
  check("an explicitText of exactly 200 characters does not fire the length rule",
    !has(pki.lint.certificate(policyCert([unoticeOf(b.utf8("a".repeat(200)))])), "lint/rfc5280/explicit-text-too-long"));
  // SIZE (1..200) has TWO ends. The upper one is the one the RFC tells certificate users to handle
  // gracefully; the lower one has no such carve-out -- an empty DisplayText is a degenerate value no
  // conforming CA emits, and reporting only the ceiling leaves half the constraint unenforced.
  check("an empty explicitText is reported against the SIZE lower bound",
    has(pki.lint.certificate(policyCert([unoticeOf(b.utf8(""))])), "lint/rfc5280/explicit-text-empty"));
  check("an empty IA5String explicitText is reported the same way",
    has(pki.lint.certificate(policyCert([unoticeOf(b.ia5(""))])), "lint/rfc5280/explicit-text-empty"));
  check("an empty NoticeReference organization is reported too",
    has(pki.lint.certificate(policyCert([b.sequence([b.oid(pki.oid.byName("unotice")),
      b.sequence([b.sequence([b.utf8(""), b.sequence([b.integer(1n)])])])])])), "lint/rfc5280/explicit-text-empty"));
  check("a one-character explicitText satisfies the lower bound",
    !has(pki.lint.certificate(policyCert([unoticeOf(b.utf8("x"))])), "lint/rfc5280/explicit-text-empty"));
  // The bound is on CHARACTERS: 150 astral characters are a conforming notice occupying 300 UTF-16
  // units and 600 UTF-8 octets, so a `.length` or byte count would report a false positive here.
  check("a 150-character astral explicitText (300 UTF-16 units) does not fire the length rule",
    !has(pki.lint.certificate(policyCert([unoticeOf(b.utf8(String.fromCodePoint(0x1f600).repeat(150)))])), "lint/rfc5280/explicit-text-too-long"));
  // VisibleString (tag 26) and BMPString (tag 30) are the two arms conforming CAs MUST NOT use;
  // the TLVs are built raw so the fixture does not depend on a builder for an arm nothing emits.
  function rawString(tag, bytes) { return b.raw(Buffer.concat([Buffer.from([tag, bytes.length]), bytes])); }
  // The finding must NAME which of the two forbidden encodings was used -- a report that fires but
  // misnames the encoding sends the operator to the wrong value. Asserting only the finding id would
  // pass while the context said VisibleString for every BMPString.
  function encodingOf(rep) {
    var f = rep.findings.filter(function (x) { return x.id === "lint/rfc5280/explicit-text-bad-encoding"; })[0];
    return f && f.context && f.context.encoding;
  }
  check("an explicitText encoded as VisibleString -> the finding, naming VisibleString",
    encodingOf(pki.lint.certificate(policyCert([unoticeOf(rawString(0x1a, Buffer.from("hi")))]))) === "VisibleString");
  check("an explicitText encoded as BMPString -> the finding, naming BMPString",
    encodingOf(pki.lint.certificate(policyCert([unoticeOf(rawString(0x1e, Buffer.from([0, 0x68, 0, 0x69])))]))) === "BMPString");
  check("an IA5String explicitText is permitted (4.2.1.4 allows it) and raises no encoding finding",
    !has(pki.lint.certificate(policyCert([unoticeOf(b.ia5("plain"))])), "lint/rfc5280/explicit-text-bad-encoding"));
  // The control byte is built at runtime so this source stays pure ASCII.
  check("an explicitText carrying a control character -> lint/rfc5280/explicit-text-control-chars",
    has(pki.lint.certificate(policyCert([unoticeOf(b.utf8("bad" + String.fromCharCode(7) + "text"))])), "lint/rfc5280/explicit-text-control-chars"));
  check("a decomposed UTF8String explicitText -> lint/rfc5280/explicit-text-not-nfc (notice)",
    has(pki.lint.certificate(policyCert([unoticeOf(b.utf8("cafe" + String.fromCharCode(0x0301)))])), "lint/rfc5280/explicit-text-not-nfc"));
  check("the composed (NFC) form of the same text raises no normalization finding",
    !has(pki.lint.certificate(policyCert([unoticeOf(b.utf8(("cafe" + String.fromCharCode(0x0301)).normalize("NFC")))])), "lint/rfc5280/explicit-text-not-nfc"));
  // NoticeReference.organization is a DisplayText too, so the SIZE bound must be reported there as
  // well -- measuring explicitText alone would leave the sibling field unchecked.
  check("a NoticeReference organization over 200 characters is measured too",
    has(pki.lint.certificate(policyCert([b.sequence([b.oid(oid.byName("unotice")),
      b.sequence([b.sequence([b.utf8("o".repeat(201)), b.sequence([b.integer(1n)])])])])])), "lint/rfc5280/explicit-text-too-long"));
  // A DisplayText that does not decode under its own declared string type is not analyzable, and a
  // lenient decode would invent one: 201 octets of 0x80 read leniently become 201 replacement
  // characters and would fire the length rule over text that was never valid. Nothing is reported.
  var badUtf8 = Buffer.concat([Buffer.from([0x0c, 0x81, 0xc9]), Buffer.alloc(201, 0x80)]);
  var repBad = pki.lint.certificate(policyCert([unoticeOf(b.raw(badUtf8))]));
  check("an explicitText that is not valid UTF-8 raises no length finding over a substituted decode",
    !has(repBad, "lint/rfc5280/explicit-text-too-long") && !has(repBad, "lint/rfc5280/explicit-text-not-nfc"));
  // An odd-length BMPString cannot be UCS-2 at all; a decoder that dropped the trailing octet would
  // silently analyze a value the bytes do not contain. The rules that read the TEXT stay silent --
  // but the encoding rule reads only the ASN.1 TAG, so it must still fire: a certificate using a
  // prohibited encoding does not escape that finding by also being malformed inside.
  var oddBmp = pki.lint.certificate(policyCert([unoticeOf(rawString(0x1e, Buffer.from([0, 0x68, 0])))]));
  check("an odd-length BMPString explicitText is not analyzed as if the stray octet were absent",
    !has(oddBmp, "lint/rfc5280/explicit-text-too-long") && !has(oddBmp, "lint/rfc5280/explicit-text-control-chars"));
  check("an odd-length BMPString explicitText STILL reports the prohibited encoding",
    encodingOf(oddBmp) === "BMPString");
  // Same for a VisibleString whose contents do not decode: the tag alone establishes the violation.
  var badVis = pki.lint.certificate(policyCert([unoticeOf(rawString(0x1a, Buffer.from([0x1b, 0x5b, 0x30, 0x6d])))]));
  check("a VisibleString explicitText reports the prohibited encoding regardless of its contents",
    encodingOf(badVis) === "VisibleString");
  // A cPSuri is an IA5String with no SIZE, so the DisplayText rules must not leak onto it.
  check("a long cPSuri raises no DisplayText finding",
    !has(pki.lint.certificate(policyCert([b.sequence([b.oid(oid.byName("cps")), b.ia5("http://x.test/" + "p".repeat(300))])])), "lint/rfc5280/explicit-text-too-long"));

  // An option this verb does not read is refused. A misspelled `profile` would otherwise lint
  // against the default rule set while the call site reads as though it had named one, so the
  // findings would answer a question nobody asked.
  check("lint.certificate refuses a misspelled profile", (function () {
    try { pki.lint.certificate(REAL, { profil: "cabf" }); return false; }
    catch (e) { return e.code === "lint/bad-input"; }
  })());
  check("lint.certificate still accepts the options it reads",
        pki.lint.certificate(REAL, { severity: "error" }).findings !== undefined);

  testCrlProfile();

  console.log("CHECKS " + helpers.getChecks());
}

// ---- RFC 5280 sec. 5, the CRL profile ----
// A CertificateList is assembled from parts so a single clause can be broken while the rest stays
// conforming. The signature is a placeholder: linting reads structure and never verifies it, the
// same way the certificate fixtures above are built.
function testCrlProfile() {
  var ALG = b.sequence([b.oid(oid.byName("ecdsaWithSHA256"))]);
  var ISSUER = b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8("Test CA")])])]);
  var SIG = b.bitString(Buffer.alloc(8, 1), 0);
  function utc(s) { return b.utcTime(new Date(s)); }
  function crlExt(name, critical, innerDer) {
    var kids = [b.oid(oid.byName(name))];
    if (critical) kids.push(b.boolean(true));
    kids.push(b.octetString(innerDer));
    return b.sequence(kids);
  }
  function akiKeyId() { return crlExt("authorityKeyIdentifier", false, b.sequence([b.contextPrimitive(0, Buffer.alloc(20, 7))])); }
  function crlNumber(n) { return crlExt("cRLNumber", false, b.integer(BigInt(n))); }
  // o: { version, noNextUpdate, revoked (array of entry DER), exts (array of extension DER),
  //      thisUpdate, nextUpdate, issuer }
  function makeCrl(o) {
    o = o || {};
    var kids = [];
    if (o.version !== null) kids.push(b.integer(BigInt(o.version === undefined ? 1 : o.version)));
    kids.push(ALG);
    kids.push(o.issuer === undefined ? ISSUER : o.issuer);
    kids.push(utc(o.thisUpdate || "2026-01-01T00:00:00Z"));
    if (!o.noNextUpdate) kids.push(utc(o.nextUpdate || "2026-02-01T00:00:00Z"));
    if (o.revoked) kids.push(b.sequence(o.revoked));
    var exts = o.exts === undefined ? [crlNumber(1), akiKeyId()] : o.exts;
    if (exts !== null) kids.push(b.explicit(0, b.sequence(exts)));
    return b.sequence([b.sequence(kids), ALG, SIG]);
  }
  function entry(serial, entryExts) {
    var kids = [b.integer(BigInt(serial)), utc("2026-01-15T00:00:00Z")];
    if (entryExts) kids.push(b.sequence(entryExts));
    return b.sequence(kids);
  }
  function ids(r) { return r.findings.map(function (f) { return f.id; }); }
  function hasId(r, id) { return ids(r).indexOf(id) !== -1; }

  // CONTROL FIRST: a conforming CRL must draw none of these rows, or no result below is evidence.
  var okReport = pki.lint.crl(makeCrl());
  check("CONTROL: a conforming CRL is clean of the rfc5280-crl rows",
    ids(okReport).filter(function (i) { return i.indexOf("lint/rfc5280-crl/") === 0; }).length === 0);
  check("CONTROL: a conforming CRL is not fatal", okReport.worst !== "fatal");

  check("hostile bytes return a fatal lint/unparseable rather than throwing",
    pki.lint.crl(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])).worst === "fatal");
  // The PEM string is a documented input, so both of its outcomes are driven: a string that is not
  // a decodable CRL fails closed as the engine's fatal, and a real one lints like the DER form.
  check("a string that is not a decodable CRL PEM -> fatal lint/unparseable",
    (function () {
      var r = pki.lint.crl("-----BEGIN X509 CRL-----\nnot base64 at all\n-----END X509 CRL-----\n");
      return r.worst === "fatal" && hasId(r, "lint/unparseable");
    })());
  check("a CRL supplied as PEM lints the same as the DER",
    (function () {
      var der = makeCrl();
      var pem = pki.schema.crl.pemEncode(der);
      return JSON.stringify(ids(pki.lint.crl(pem))) === JSON.stringify(ids(pki.lint.crl(der)));
    })());

  check("a CRL with no nextUpdate -> next-update-missing",
    hasId(pki.lint.crl(makeCrl({ noNextUpdate: true })), "lint/rfc5280-crl/next-update-missing"));
  check("a CRL whose thisUpdate follows its nextUpdate -> update-times-inverted",
    hasId(pki.lint.crl(makeCrl({ thisUpdate: "2026-03-01T00:00:00Z" })), "lint/rfc5280-crl/update-times-inverted"));

  // Three sec. 5 rules have no row, because the strict parser refuses them first and a rule for
  // them could never fire. Each is pinned here as the engine's fatal, so the boundary between the
  // parser and the profile stays stated rather than assumed.
  function fatalCode(der) {
    var r = pki.lint.crl(der);
    return r.worst === "fatal" && hasId(r, "lint/unparseable") && r.findings[0].context
      ? r.findings[0].context.code : null;
  }
  // The version must be OMITTED here, not set to 0. An explicit INTEGER 0 is refused as a bad
  // version VALUE whether or not extensions are present, so it would pass this row without ever
  // exercising the version-against-extensions gate the clause states.
  check("a CRL carrying extensions with no version field is fatal at parse (sec. 5.1.2.1)",
    fatalCode(makeCrl({ version: null })) === "crl/bad-version");
  check("...and an explicit v1 is refused too, as a bad version value",
    fatalCode(makeCrl({ version: 0 })) === "crl/bad-version");
  check("an empty issuer name is fatal at parse (sec. 5.1.2.3)",
    fatalCode(makeCrl({ issuer: b.sequence([]) })) === "crl/bad-issuer");
  check("a repeated CRL extension is fatal at parse, not a profile row (sec. 4.2)",
    fatalCode(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("cRLNumber", false, b.integer(2n))] })) === "crl/duplicate-extension");
  check("a repeated ENTRY extension is fatal at parse too",
    fatalCode(makeCrl({ revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(1n)),
      crlExt("reasonCode", false, b.enumerated(2n))])] })) === "crl/duplicate-extension");
  check("a present-but-empty revokedCertificates is fatal at parse (sec. 5.1.2.6)",
    fatalCode(makeCrl({ revoked: [] })) === "crl/bad-revoked-certificates");
  check("a CRL listing a revoked certificate lints cleanly",
    ids(pki.lint.crl(makeCrl({ revoked: [entry(5)] })))
      .filter(function (i) { return i.indexOf("lint/rfc5280-crl/") === 0; }).length === 0);

  check("a CRL with no cRLNumber -> crl-number-missing",
    hasId(pki.lint.crl(makeCrl({ exts: [akiKeyId()] })), "lint/rfc5280-crl/crl-number-missing"));
  check("a cRLNumber longer than 20 octets -> crl-number-too-long",
    hasId(pki.lint.crl(makeCrl({ exts: [crlExt("cRLNumber", false, b.integer((1n << 168n) + 1n)), akiKeyId()] })),
      "lint/rfc5280-crl/crl-number-too-long"));
  // Sec. 5.2.4 defines BaseCRLNumber as a CRLNumber, so the sec. 5.2.3 ceiling governs the delta
  // indicator's value too. The issuance path bounds both; the profile answers for both.
  var OVER_20 = (1n << 168n) + 1n;
  function tooLongFindings(r) {
    return r.findings.filter(function (f) { return f.id === "lint/rfc5280-crl/crl-number-too-long"; });
  }
  var baseOverlong = pki.lint.crl(makeCrl({
    exts: [crlNumber(3), akiKeyId(), crlExt("deltaCRLIndicator", true, b.integer(OVER_20))] }));
  check("a baseCRLNumber longer than 20 octets -> crl-number-too-long",
    hasId(baseOverlong, "lint/rfc5280-crl/crl-number-too-long"));
  check("the overlong baseCRLNumber finding names the extension it measured",
    tooLongFindings(baseOverlong).length === 1 &&
    tooLongFindings(baseOverlong)[0].context.extension === "deltaCRLIndicator");
  var bothOverlong = pki.lint.crl(makeCrl({
    exts: [crlExt("cRLNumber", false, b.integer(OVER_20)), akiKeyId(),
      crlExt("deltaCRLIndicator", true, b.integer(OVER_20))] }));
  check("both numbers overlong -> one finding per carrier, not one for the pair",
    tooLongFindings(bothOverlong).length === 2 &&
    tooLongFindings(bothOverlong).map(function (f) { return f.context.extension; }).sort().join(",") ===
      "cRLNumber,deltaCRLIndicator");
  check("a delta CRL with in-range numbers reports no length finding",
    tooLongFindings(pki.lint.crl(makeCrl({ exts: [crlNumber(9), akiKeyId(), deltaExt(3)] }))).length === 0);
  // A revoked entry's userCertificate is a CertificateSerialNumber, so it carries the same
  // sec. 4.1.2.2 profile the certificate rows apply to a certificate's own serial.
  function entrySerial(n) {
    var kids = [b.integer(BigInt(n)), utc("2026-01-15T00:00:00Z")];
    return b.sequence(kids);
  }
  // Two more rules the toolkit already applies elsewhere, applied to a CRL that arrived from
  // elsewhere. A serial listed twice on a direct CRL states two revocations of one certificate,
  // and certificateIssuer means nothing unless the CRL declares itself indirect.
  var certIssuerExt = crlExt("certificateIssuer", true, b.sequence([b.contextPrimitive(2, Buffer.from("other.example", "latin1"))]));
  var idpIndirect = crlExt("issuingDistributionPoint", true, b.sequence([b.contextPrimitive(4, Buffer.from([0xff]))]));
  check("a direct CRL listing one serial twice -> duplicate-entry-serial",
    hasId(pki.lint.crl(makeCrl({ revoked: [entry(5), entry(5)] })), "lint/rfc5280-crl/duplicate-entry-serial"));
  check("a direct CRL listing distinct serials is not flagged",
    !hasId(pki.lint.crl(makeCrl({ revoked: [entry(5), entry(6)] })), "lint/rfc5280-crl/duplicate-entry-serial"));
  check("an INDIRECT CRL is exempt from the duplicate-serial row",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpIndirect], revoked: [entry(5), entry(5)] })),
      "lint/rfc5280-crl/duplicate-entry-serial"));
  check("certificateIssuer on a DIRECT CRL -> certificate-issuer-on-direct-crl",
    hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [certIssuerExt])] })),
      "lint/rfc5280-crl/certificate-issuer-on-direct-crl"));
  check("certificateIssuer on an INDIRECT CRL is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpIndirect], revoked: [entry(5, [certIssuerExt])] })),
      "lint/rfc5280-crl/certificate-issuer-on-direct-crl"));
  // A malformed issuingDistributionPoint declares neither direction. The rows below only mean
  // something on a CRL that IS direct, so they stand aside and the value-syntax row reports the
  // extension: an unreadable declaration is the extension's fault, not the entries'. Nothing is
  // lost, because that row is an error, so no CRL reaches a clean report with them unevaluated.
  var idpMalformed = crlExt("issuingDistributionPoint", true, b.nullValue());
  var idpDirect = crlExt("issuingDistributionPoint", true, b.sequence([b.contextPrimitive(1, Buffer.from([0xff]))]));
  var malformedWithCertIssuer = pki.lint.crl(makeCrl({
    exts: [crlNumber(1), akiKeyId(), idpMalformed], revoked: [entry(5, [certIssuerExt])] }));
  check("a MALFORMED issuingDistributionPoint reports the extension, not the entry",
    hasId(malformedWithCertIssuer, "lint/rfc5280-crl/extension-value-syntax") &&
    !hasId(malformedWithCertIssuer, "lint/rfc5280-crl/certificate-issuer-on-direct-crl"));
  check("a MALFORMED issuingDistributionPoint does not accuse entries of duplicate serials",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpMalformed],
      revoked: [entry(5, [certIssuerExt]), entry(5, [certIssuerExt])] })),
      "lint/rfc5280-crl/duplicate-entry-serial"));
  // Standing aside is for an unreadable declaration only. A CRL with NO issuingDistributionPoint
  // is direct by omission, and one whose well-formed extension omits indirectCRL says so outright.
  check("a CRL with a well-formed IDP that omits indirectCRL is still direct",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpDirect], revoked: [entry(5, [certIssuerExt])] })),
      "lint/rfc5280-crl/certificate-issuer-on-direct-crl") &&
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpDirect], revoked: [entry(5), entry(5)] })),
      "lint/rfc5280-crl/duplicate-entry-serial"));

  // Section 5.3.3 requires the DN from the certificate's issuer field, which in a GeneralNames is
  // the directoryName [4] arm. A certificateIssuer carrying only another name form decodes fine and
  // still attributes the entry to nobody, so it is a profile row rather than a syntax one.
  var dnName = b.sequence([b.set([b.sequence([b.oid(oid.byName("commonName")), b.utf8("Other CA")])])]);
  var ciWithDn = crlExt("certificateIssuer", true, b.sequence([b.contextConstructed(4, dnName)]));
  check("a certificateIssuer carrying only a dNSName -> certificate-issuer-without-dn",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpIndirect], revoked: [entry(5, [certIssuerExt])] })),
      "lint/rfc5280-crl/certificate-issuer-without-dn"));
  check("a certificateIssuer whose directoryName wraps an EMPTY Name -> certificate-issuer-without-dn",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpIndirect],
      revoked: [entry(5, [crlExt("certificateIssuer", true, b.sequence([b.contextConstructed(4, b.sequence([]))]))])] })),
      "lint/rfc5280-crl/certificate-issuer-without-dn"));
  check("a certificateIssuer carrying a directoryName is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpIndirect], revoked: [entry(5, [ciWithDn])] })),
      "lint/rfc5280-crl/certificate-issuer-without-dn"));

  // Section 5.3.1 states this as a SHOULD, so it is a warn, like the issuerAltName criticality row.
  check("a reasonCode encoding unspecified(0) -> reason-code-unspecified at warn",
    hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(0n))])] })),
      "lint/rfc5280-crl/reason-code-unspecified"));
  // Section 5.2.5 makes the same encoding a MUST violation where the CRL is scoped to some reason
  // codes, because the reason is what decides which partition an entry belongs in. The SHOULD row
  // stands aside there so one fault is not reported twice at two strengths.
  // onlySomeReasons [3] IMPLICIT BIT STRING with keyCompromise(1) set: 6 unused bits, byte 0x40.
  var idpReasons = crlExt("issuingDistributionPoint", true, b.sequence([b.contextPrimitive(3, Buffer.from([0x06, 0x40]))]));
  var scopedUnspecified = pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpReasons],
    revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(0n))])] }));
  check("unspecified(0) in a reason-scoped CRL -> unspecified-reason-in-reason-scoped-crl at error",
    hasId(scopedUnspecified, "lint/rfc5280-crl/unspecified-reason-in-reason-scoped-crl"));
  check("...and the SHOULD row stands aside, so the fault is reported once",
    !hasId(scopedUnspecified, "lint/rfc5280-crl/reason-code-unspecified"));
  check("a reason-scoped CRL with a meaningful reason is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpReasons],
      revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(1n))])] })),
      "lint/rfc5280-crl/unspecified-reason-in-reason-scoped-crl"));
  check("a reason-scoped CRL entry carrying NO reasonCode is permitted (sec. 5.2.5 says so)",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpReasons], revoked: [entry(5)] })),
      "lint/rfc5280-crl/unspecified-reason-in-reason-scoped-crl"));
  // Section 5.2.5: a CRL declaring a reason scope carries only those reasons. The CRLReason and
  // ReasonFlags enumerations do NOT line up (CRLReason 7 is unused, privilegeWithdrawn is 9 against
  // bit 7, aACompromise is 10 against bit 8), so every value is driven: a wrong mapping here would
  // report conforming CRLs, which is the worst thing a linter can do.
  // A ReasonFlags BIT STRING over the given bit positions, minimally encoded: DER drops trailing
  // zero bits, so the length follows the HIGHEST bit set. [3] is IMPLICIT, so the content is the
  // unused-bit count followed by the data bytes.
  function scopeOf(bits) {
    var highest = Math.max.apply(null, bits);
    var nBytes = (highest >> 3) + 1;
    var data = Buffer.alloc(nBytes);
    bits.forEach(function (n) { data[n >> 3] |= (0x80 >> (n & 7)); });
    var unused = (nBytes * 8) - (highest + 1);
    return crlExt("issuingDistributionPoint", true,
      b.sequence([b.contextPrimitive(3, Buffer.concat([Buffer.from([unused]), data]))]));
  }
  // A scope naming keyCompromise(1) only.
  var scopeKeyCompromise = scopeOf([1]);
  [[1, false], [2, true], [3, true], [4, true], [5, true], [6, true], [9, true], [10, true]].forEach(function (pair) {
    var reason = pair[0], shouldFire = pair[1];
    var r = pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), scopeKeyCompromise],
      revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(BigInt(reason)))])] }));
    check("reason " + reason + " against a keyCompromise-only scope " + (shouldFire ? "-> reason-outside-crl-scope" : "is in scope"),
      hasId(r, "lint/rfc5280-crl/reason-outside-crl-scope") === shouldFire);
  });
  check("removeFromCRL has no ReasonFlags bit, so it is never out of scope",
    !hasId(pki.lint.crl(makeCrl({
      exts: [crlNumber(9), akiKeyId(), scopeKeyCompromise, crlExt("deltaCRLIndicator", true, b.integer(3n))],
      revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(8n))])],
    })), "lint/rfc5280-crl/reason-outside-crl-scope"));
  // These two prove the mapping is NOT identity. privilegeWithdrawn is CRLReason 9 against
  // ReasonFlags bit 7, and aACompromise is CRLReason 10 against bit 8. Under an identity mapping
  // both of these conforming CRLs would be reported, since bits 9 and 10 do not exist.
  check("privilegeWithdrawn(9) is IN scope when the CRL declares ReasonFlags bit 7",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), scopeOf([7])],
      revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(9n))])] })),
      "lint/rfc5280-crl/reason-outside-crl-scope"));
  check("aACompromise(10) is IN scope when the CRL declares ReasonFlags bit 8",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), scopeOf([8])],
      revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(10n))])] })),
      "lint/rfc5280-crl/reason-outside-crl-scope"));
  check("...and privilegeWithdrawn is still OUT of scope where only bit 8 is declared",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), scopeOf([8])],
      revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(9n))])] })),
      "lint/rfc5280-crl/reason-outside-crl-scope"));

  check("a CRL declaring NO reason scope never draws the row",
    !hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(5n))])] })),
      "lint/rfc5280-crl/reason-outside-crl-scope"));
  check("an entry with no reasonCode never draws the row",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), scopeKeyCompromise], revoked: [entry(5)] })),
      "lint/rfc5280-crl/reason-outside-crl-scope"));

  check("a meaningful reason code is not flagged",
    !hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(1n))])] })),
      "lint/rfc5280-crl/reason-code-unspecified"));
  check("the unspecified reason row is suppressed by a severity floor of error",
    !hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(0n))])] }), { severity: "error" }),
      "lint/rfc5280-crl/reason-code-unspecified"));

  // A certificate-only extension carried NON-critically on a CRL is an unrecognized extension the
  // profile lets a consumer ignore, so its inner value has no CRL syntax to enforce. Decoding it
  // against the CERTIFICATE profile would report a fault section 5 does not state.
  check("a NON-critical certificate-only extension with a junk value is not a syntax fault",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("basicConstraints", false, b.nullValue())] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  check("...but the same extension marked CRITICAL is still an unknown critical extension",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("basicConstraints", true, b.nullValue())] })),
      "lint/rfc5280-crl/unknown-critical-extension"));

  check("a revoked entry with a ZERO serial -> entry-serial-not-positive",
    hasId(pki.lint.crl(makeCrl({ revoked: [entrySerial(0)] })), "lint/rfc5280-crl/entry-serial-not-positive"));
  check("a revoked entry with a NEGATIVE serial -> entry-serial-not-positive",
    hasId(pki.lint.crl(makeCrl({ revoked: [entrySerial(-5)] })), "lint/rfc5280-crl/entry-serial-not-positive"));
  check("a revoked entry with a serial past 20 octets -> entry-serial-too-long",
    hasId(pki.lint.crl(makeCrl({ revoked: [entrySerial((1n << 168n) + 1n)] })), "lint/rfc5280-crl/entry-serial-too-long"));
  check("a revoked entry with an ordinary serial draws neither row",
    (function () {
      var r = pki.lint.crl(makeCrl({ revoked: [entrySerial(5)] }));
      return !hasId(r, "lint/rfc5280-crl/entry-serial-not-positive") && !hasId(r, "lint/rfc5280-crl/entry-serial-too-long");
    })());
  check("a serial of exactly 20 octets is accepted (the ceiling is inclusive)",
    !hasId(pki.lint.crl(makeCrl({ revoked: [entrySerial((1n << 152n) + 1n)] })), "lint/rfc5280-crl/entry-serial-too-long"));

  check("a CRL with no authorityKeyIdentifier -> aki-missing",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1)] })), "lint/rfc5280-crl/aki-missing"));
  // Sections 5.2.1 and 5.2.3 state their requirements in the same terms, so the rows must carry the
  // same severity: a caller filtering at `error` sees both or neither, never one of the two.
  check("the authorityKeyIdentifier and cRLNumber rows are graded alike, since both clauses are MUSTs",
    (function () {
      var sev = {};
      pki.lint.rules("rfc5280-crl").forEach(function (r) { sev[r.id] = r.severity; });
      return sev["lint/rfc5280-crl/aki-missing"] === "error"
        && sev["lint/rfc5280-crl/aki-without-key-identifier"] === "error"
        && sev["lint/rfc5280-crl/crl-number-missing"] === "error";
    })());
  check("a CRL missing its authorityKeyIdentifier survives a severity floor of error",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1)] }), { severity: "error" }), "lint/rfc5280-crl/aki-missing"));
  // Section 5.2.1 states two things: include the extension, and use the key identifier method. An
  // AKI that is present but carries no keyIdentifier satisfies the first and fails the second.
  check("an authorityKeyIdentifier with no keyIdentifier -> aki-without-key-identifier",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), crlExt("authorityKeyIdentifier", false, b.sequence([])) ] })),
      "lint/rfc5280-crl/aki-without-key-identifier"));
  check("an authorityKeyIdentifier carrying a keyIdentifier is not flagged",
    !hasId(pki.lint.crl(makeCrl()), "lint/rfc5280-crl/aki-without-key-identifier"));
  // The value is read through the shared AuthorityKeyIdentifier decoder, so a container that merely
  // carries a [0] child is refused. A hand-rolled scan for the tag would admit both of these.
  check("an AKI encoded as a SET carrying [0] -> aki-without-key-identifier",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), crlExt("authorityKeyIdentifier", false,
      b.set([b.contextPrimitive(0, Buffer.alloc(20, 7))])) ] })),
      "lint/rfc5280-crl/aki-without-key-identifier"));
  check("an AKI whose [0] is CONSTRUCTED -> aki-without-key-identifier",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), crlExt("authorityKeyIdentifier", false,
      b.sequence([b.contextConstructed(0, b.octetString(Buffer.alloc(20, 7)))])) ] })),
      "lint/rfc5280-crl/aki-without-key-identifier"));
  check("an AKI naming only an issuer and serial (no keyIdentifier) -> aki-without-key-identifier",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), crlExt("authorityKeyIdentifier", false,
      b.sequence([b.contextConstructed(1, b.contextPrimitive(2, Buffer.from("ca.example", "latin1"))),
        b.contextPrimitive(2, Buffer.from([0x2a]))])) ] })),
      "lint/rfc5280-crl/aki-without-key-identifier"));

  check("a critical cRLNumber -> extension-criticality (sec. 5.2.3 requires non-critical)",
    hasId(pki.lint.crl(makeCrl({ exts: [crlExt("cRLNumber", true, b.integer(1n)), akiKeyId()] })),
      "lint/rfc5280-crl/extension-criticality"));
  check("a NON-critical deltaCRLIndicator -> extension-criticality (sec. 5.2.4 requires critical)",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("deltaCRLIndicator", false, b.integer(1n))] })),
      "lint/rfc5280-crl/extension-criticality"));
  check("a freshestCRL in a delta CRL -> freshest-in-delta",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(5), akiKeyId(),
      crlExt("deltaCRLIndicator", true, b.integer(1n)),
      crlExt("freshestCRL", false, b.sequence([b.sequence([b.contextConstructed(0,
        b.contextConstructed(0, b.contextPrimitive(6, Buffer.from("http://e/x", "latin1"))))])]))] })),
      "lint/rfc5280-crl/freshest-in-delta"));
  // Three semantic rules the ISSUING path already enforces, applied to a CRL that arrived from
  // elsewhere. Recognizing an extension by its identifier says only that the profile names it, so
  // each of these reports clean without its own row.
  function deltaExt(base) { return crlExt("deltaCRLIndicator", true, b.integer(BigInt(base))); }
  check("a delta CRL whose cRLNumber does not exceed its baseCRLNumber -> delta-number-not-advancing",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(3), akiKeyId(), deltaExt(9)] })),
      "lint/rfc5280-crl/delta-number-not-advancing"));
  check("a delta CRL whose cRLNumber equals its baseCRLNumber -> delta-number-not-advancing",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(5), akiKeyId(), deltaExt(5)] })),
      "lint/rfc5280-crl/delta-number-not-advancing"));
  check("a delta CRL that advances its number is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(9), akiKeyId(), deltaExt(3)] })),
      "lint/rfc5280-crl/delta-number-not-advancing"));

  var removeReason = crlExt("reasonCode", false, b.enumerated(8n));
  check("removeFromCRL in a COMPLETE CRL -> remove-from-crl-outside-delta (sec. 5.3.1)",
    hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [removeReason])] })),
      "lint/rfc5280-crl/remove-from-crl-outside-delta"));
  check("removeFromCRL in a DELTA CRL is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(9), akiKeyId(), deltaExt(3)], revoked: [entry(5, [removeReason])] })),
      "lint/rfc5280-crl/remove-from-crl-outside-delta"));
  check("an ordinary reason code in a complete CRL is not flagged",
    !hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(1n))])] })),
      "lint/rfc5280-crl/remove-from-crl-outside-delta"));

  // A recognized extension whose VALUE no consumer can read. The criticality row is satisfied and
  // the unknown-critical row cannot fire, because the identifier is one the profile names.
  check("a critical issuingDistributionPoint whose value is a NULL -> extension-value-syntax",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("issuingDistributionPoint", true, b.nullValue())] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  check("a freshestCRL whose value is a NULL -> extension-value-syntax",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("freshestCRL", false, b.nullValue())] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  check("an entry certificateIssuer whose value is a NULL -> extension-value-syntax",
    hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [crlExt("certificateIssuer", true, b.nullValue())])] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  check("a deltaCRLIndicator whose value is a SEQUENCE -> extension-value-syntax",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("deltaCRLIndicator", true, b.sequence([]))] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  // reasonCode and invalidityDate are NOT in the table: the parser decodes both and refuses a value
  // that is not the type they name, so a row for either could never fire.
  check("an entry reasonCode whose value is a NULL is fatal at parse, not a value-syntax row",
    fatalCode(makeCrl({ revoked: [entry(5, [crlExt("reasonCode", false, b.nullValue())])] })) === "crl/bad-extension-value");
  // The value is walked through the shared schema, not matched on its outer tag. A SEQUENCE
  // carrying a NULL has the right outer type and is still not an IssuingDistributionPoint.
  check("an issuingDistributionPoint of SEQUENCE { NULL } -> extension-value-syntax",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      crlExt("issuingDistributionPoint", true, b.sequence([b.nullValue()]))] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  // Whether the value DECODES and whether section 5.2.5 PERMITS the scope it states are different
  // decisions, so they are different rows. An empty IDP and one claiming two exclusive scopes both
  // decode perfectly well.
  function idpExt(inner) { return crlExt("issuingDistributionPoint", true, inner); }
  check("an EMPTY issuingDistributionPoint -> idp-profile (sec. 5.2.5)",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpExt(b.sequence([]))] })),
      "lint/rfc5280-crl/idp-profile"));
  check("an IDP setting both onlyContainsUserCerts and onlyContainsCACerts -> idp-profile",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      idpExt(b.sequence([b.contextPrimitive(1, Buffer.from([0xff])), b.contextPrimitive(2, Buffer.from([0xff]))]))] })),
      "lint/rfc5280-crl/idp-profile"));
  check("an IDP setting onlyContainsAttributeCerts -> idp-profile",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      idpExt(b.sequence([b.contextPrimitive(5, Buffer.from([0xff]))]))] })),
      "lint/rfc5280-crl/idp-profile"));
  check("an IDP stating a single scope is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      idpExt(b.sequence([b.contextPrimitive(1, Buffer.from([0xff]))]))] })),
      "lint/rfc5280-crl/idp-profile"));
  // Sec. 5.2.5 says the reason codes associated with a distribution point MUST be specified in
  // onlySomeReasons, and ReasonFlags bit 0 is named `unused`. A mask setting nothing, or setting
  // only bit 0, specifies no reason code, so the extension states a scope covering no revocation.
  function rawScope(content) { return idpExt(b.sequence([b.contextPrimitive(3, content)])); }
  function reasonExt(n) { return crlExt("reasonCode", false, b.enumerated(BigInt(n))); }
  var SCOPE_NONE = Buffer.from([0x00]);            // no data bytes at all
  var SCOPE_UNUSED_ONLY = Buffer.from([0x07, 0x80]); // only bit 0
  check("an onlySomeReasons naming no reason -> idp-profile",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), rawScope(SCOPE_NONE)] })),
      "lint/rfc5280-crl/idp-profile"));
  check("an onlySomeReasons setting only the unused bit -> idp-profile",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), rawScope(SCOPE_UNUSED_ONLY)] })),
      "lint/rfc5280-crl/idp-profile"));
  check("a scope naming one real reason is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), scopeOf([1])] })),
      "lint/rfc5280-crl/idp-profile"));
  // The fault is the extension's, so it is reported once against the extension rather than once
  // per revoked entry: a mask naming nothing gives the entry rows no partition to judge against.
  var emptyScopeWithEntries = pki.lint.crl(makeCrl({
    exts: [crlNumber(1), akiKeyId(), rawScope(SCOPE_NONE)],
    revoked: [entry(5, [reasonExt(1)]), entry(6, [reasonExt(2)]), entry(7, [reasonExt(0)])] }));
  check("a scope naming no reason reports the extension, not each entry",
    hasId(emptyScopeWithEntries, "lint/rfc5280-crl/idp-profile") &&
    !hasId(emptyScopeWithEntries, "lint/rfc5280-crl/reason-outside-crl-scope") &&
    !hasId(emptyScopeWithEntries, "lint/rfc5280-crl/unspecified-reason-in-reason-scoped-crl"));
  // The two unspecified(0) rows partition on whether the CRL is meaningfully reason scoped, so
  // exactly one answers for a given entry. A scope naming nothing is not meaningfully scoped, and
  // the entry falls to the sec. 5.3.1 SHOULD rather than to an error that blames it for the
  // extension's fault.
  check("a degenerate scope leaves an unspecified reason to the SHOULD row",
    hasId(emptyScopeWithEntries, "lint/rfc5280-crl/reason-code-unspecified"));
  function unspecifiedRows(r) {
    return ["lint/rfc5280-crl/unspecified-reason-in-reason-scoped-crl", "lint/rfc5280-crl/reason-code-unspecified"]
      .filter(function (id) { return hasId(r, id); });
  }
  check("exactly one unspecified row answers, whatever the scope shape",
    unspecifiedRows(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), rawScope(SCOPE_NONE)],
      revoked: [entry(5, [reasonExt(0)])] }))).length === 1 &&
    unspecifiedRows(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), scopeOf([1])],
      revoked: [entry(5, [reasonExt(0)])] }))).length === 1 &&
    unspecifiedRows(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId()],
      revoked: [entry(5, [reasonExt(0)])] }))).length === 1);
  check("a real scope still judges entry reasons against it",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), scopeOf([1])],
      revoked: [entry(6, [reasonExt(2)])] })), "lint/rfc5280-crl/reason-outside-crl-scope"));
  check("a malformed IDP draws the syntax row and NOT the profile row",
    (function () {
      var r = pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), idpExt(b.nullValue())] }));
      return hasId(r, "lint/rfc5280-crl/extension-value-syntax") && !hasId(r, "lint/rfc5280-crl/idp-profile");
    })());

  // Read through the same decoder path validation uses, so the two verbs cannot disagree about a
  // well-formed IssuingDistributionPoint. The shared schema alone leaves distributionPoint as
  // `any`, which would admit a [0] wrapper carrying a NULL.
  check("an issuingDistributionPoint of SEQUENCE { [0] NULL } -> extension-value-syntax",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      crlExt("issuingDistributionPoint", true, b.sequence([b.contextConstructed(0, b.nullValue())]))] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  check("an issuingDistributionPoint carrying a real distributionPoint is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      crlExt("issuingDistributionPoint", true, b.sequence([b.contextConstructed(0,
        b.contextConstructed(0, b.contextPrimitive(6, Buffer.from("http://e/c", "latin1"))))]))] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  check("a certificateIssuer of SEQUENCE { NULL } -> extension-value-syntax",
    hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [crlExt("certificateIssuer", true, b.sequence([b.nullValue()]))])] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  // BaseCRLNumber is a CRLNumber, which sec. 5.2.3 constrains to a non-negative integer. A negative
  // one passes an outer-tag check AND the advancing comparison, so it needs its own coverage.
  check("a deltaCRLIndicator carrying a NEGATIVE base number -> extension-value-syntax",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("deltaCRLIndicator", true, b.integer(-1n))] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  // ReasonFlags is a NamedBitList, so DER drops its trailing zero bits. A value keeping them is
  // malformed for the linter exactly as it is for path validation, which is why the check lives in
  // the shared structural read rather than in either caller.
  check("an IDP whose onlySomeReasons keeps trailing zero bits -> extension-value-syntax",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      crlExt("issuingDistributionPoint", true, b.raw(Buffer.from([0x30, 0x04, 0x83, 0x02, 0x00, 0x40])))] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  check("a well-formed issuingDistributionPoint is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("issuingDistributionPoint", true, b.sequence([]))] })),
      "lint/rfc5280-crl/extension-value-syntax"));
  check("the conforming baseline draws no value-syntax row",
    !hasId(okReport, "lint/rfc5280-crl/extension-value-syntax"));

  check("an unrecognized CRITICAL extension -> unknown-critical-extension",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      b.sequence([b.oid("1.3.6.1.4.1.55738.777.2"), b.boolean(true), b.octetString(b.nullValue())])] })),
      "lint/rfc5280-crl/unknown-critical-extension"));
  // The recognized set is the one section 5.2 profiles, not the certificate registry. Two of the
  // extensions this section REQUIRES to be critical are unknown to the certificate path validator,
  // and several extensions it does recognize have no meaning on a CRL at all.
  check("a conforming delta CRL (critical deltaCRLIndicator) draws no unknown-critical row",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(5), akiKeyId(), crlExt("deltaCRLIndicator", true, b.integer(1n))] })),
      "lint/rfc5280-crl/unknown-critical-extension"));
  check("a conforming scoped CRL (critical issuingDistributionPoint) draws no unknown-critical row",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("issuingDistributionPoint", true, b.sequence([]))] })),
      "lint/rfc5280-crl/unknown-critical-extension"));
  // Section 5.2.2 states issuerAltName's criticality as a SHOULD, not a MUST, so a critical one is
  // a warn of its own rather than an error from the required-criticality table. It is still a
  // RECOGNIZED extension, so it must not be reported as an unknown critical one either.
  var critIan = crlExt("issuerAltName", true, b.sequence([b.contextPrimitive(2, Buffer.from("ca.example", "latin1"))]));
  var ianReport = pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), critIan] }));
  check("a critical issuerAltName -> issuer-alt-name-critical at warn (sec. 5.2.2 is a SHOULD)",
    hasId(ianReport, "lint/rfc5280-crl/issuer-alt-name-critical"));
  check("a critical issuerAltName is NOT an extension-criticality error",
    !hasId(ianReport, "lint/rfc5280-crl/extension-criticality"));
  check("a critical issuerAltName is NOT reported as an unknown critical extension",
    !hasId(ianReport, "lint/rfc5280-crl/unknown-critical-extension"));
  check("a critical issuerAltName is suppressed by a severity floor of error",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), critIan] }), { severity: "error" }),
      "lint/rfc5280-crl/issuer-alt-name-critical"));
  check("a NON-critical issuerAltName is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      crlExt("issuerAltName", false, b.sequence([b.contextPrimitive(2, Buffer.from("ca.example", "latin1"))]))] })),
      "lint/rfc5280-crl/issuer-alt-name-critical"));

  check("a certificate-only critical extension on a CRL -> unknown-critical-extension",
    hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("basicConstraints", true, b.sequence([]))] })),
      "lint/rfc5280-crl/unknown-critical-extension"));

  check("an unrecognized NON-critical extension is not flagged",
    !hasId(pki.lint.crl(makeCrl({ exts: [crlNumber(1), akiKeyId(),
      b.sequence([b.oid("1.3.6.1.4.1.55738.777.2"), b.octetString(b.nullValue())])] })),
      "lint/rfc5280-crl/unknown-critical-extension"));

  // Sections 5.2 and 5.3 state the same obligation about an unrecognized CRITICAL extension, so a
  // revoked entry carrying one is refused the same way the CRL's own list is.
  check("an unrecognized CRITICAL entry extension -> unknown-critical-extension (sec. 5.3)",
    hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [
      b.sequence([b.oid("1.3.6.1.4.1.55738.777.3"), b.boolean(true), b.octetString(b.nullValue())])])] })),
      "lint/rfc5280-crl/unknown-critical-extension"));
  check("an unrecognized NON-critical entry extension is not flagged",
    !hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [
      b.sequence([b.oid("1.3.6.1.4.1.55738.777.3"), b.octetString(b.nullValue())])])] })),
      "lint/rfc5280-crl/unknown-critical-extension"));

  // The parsed-input door is the shared guard, not a property test, so an object that merely looks
  // CRL-shaped is refused with the typed config error rather than faulting inside a rule.
  check("an object that is not a parsed CRL -> lint/bad-input",
    throwsCode(function () { pki.lint.crl({ crlExtensions: {} }); }) === "lint/bad-input");
  check("a number is refused with the typed config error",
    throwsCode(function () { pki.lint.crl(42); }) === "lint/bad-input");

  check("a CRITICAL reasonCode entry extension -> entry-extension-criticality (sec. 5.3.1)",
    hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [crlExt("reasonCode", true, b.enumerated(1n))])] })),
      "lint/rfc5280-crl/entry-extension-criticality"));
  check("a non-critical reasonCode entry extension is not flagged",
    !hasId(pki.lint.crl(makeCrl({ revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(1n))])] })),
      "lint/rfc5280-crl/entry-extension-criticality"));
  // A finding against an entry names which entry, as every other entry-scope row does. Without it
  // two entries breaking the same rule are indistinguishable and a caller has to rescan the CRL.
  var lateEntryCriticality = pki.lint.crl(makeCrl({ revoked: [
    entry(5, [crlExt("reasonCode", false, b.enumerated(1n))]),
    entry(6, [crlExt("reasonCode", false, b.enumerated(1n))]),
    entry(7, [crlExt("reasonCode", true, b.enumerated(1n))])] }));
  check("an entry-criticality finding names the entry it came from",
    lateEntryCriticality.findings.filter(function (f) {
      return f.id === "lint/rfc5280-crl/entry-extension-criticality";
    }).map(function (f) { return f.context.entry; }).join(",") === "2");
  var twoBadEntries = pki.lint.crl(makeCrl({ revoked: [
    entry(5, [crlExt("reasonCode", true, b.enumerated(1n))]),
    entry(6, [crlExt("invalidityDate", true, b.generalizedTime(new Date("2026-01-02T00:00:00Z")))])] }));
  check("two entries breaking the criticality rule are distinguishable",
    twoBadEntries.findings.filter(function (f) {
      return f.id === "lint/rfc5280-crl/entry-extension-criticality";
    }).map(function (f) { return f.context.entry + ":" + f.context.extension; }).sort().join(",") ===
      "0:reasonCode,1:invalidityDate");
  check("a CRL-level criticality finding carries no entry index",
    pki.lint.crl(makeCrl({ exts: [crlExt("cRLNumber", true, b.integer(1n)), akiKeyId()] })).findings
      .filter(function (f) { return f.id === "lint/rfc5280-crl/extension-criticality"; })
      .every(function (f) { return f.context.entry === undefined && f.context.scope === "crlExtensions"; }));

  // Every finding must carry a human message. `rules()` does not expose one, so a rule shipped
  // without it renders as undefined to an operator and no id-based assertion notices. This drives a
  // battery covering every CRL row and reads the message off each finding produced.
  var messageBattery = [
    makeCrl({ noNextUpdate: true }),
    makeCrl({ thisUpdate: "2026-03-01T00:00:00Z" }),
    makeCrl({ exts: [akiKeyId()] }),
    makeCrl({ exts: [crlExt("cRLNumber", false, b.integer((1n << 168n) + 1n)), akiKeyId()] }),
    makeCrl({ exts: [crlNumber(1)] }),
    makeCrl({ exts: [crlNumber(1), crlExt("authorityKeyIdentifier", false, b.sequence([]))] }),
    makeCrl({ exts: [crlExt("cRLNumber", true, b.integer(1n)), akiKeyId()] }),
    makeCrl({ exts: [crlNumber(1), akiKeyId(), critIan] }),
    makeCrl({ exts: [crlNumber(3), akiKeyId(), deltaExt(9)] }),
    makeCrl({ exts: [crlNumber(1), akiKeyId(), idpExt(b.sequence([]))] }),
    makeCrl({ exts: [crlNumber(1), akiKeyId(), idpExt(b.nullValue())] }),
    makeCrl({ exts: [crlNumber(1), akiKeyId(), crlExt("basicConstraints", true, b.sequence([]))] }),
    makeCrl({ revoked: [entry(5, [crlExt("reasonCode", true, b.enumerated(1n))])] }),
    makeCrl({ revoked: [entry(5, [removeReason])] }),
    makeCrl({ revoked: [entry(5, [certIssuerExt])] }),
    makeCrl({ revoked: [entrySerial(0)] }),
    makeCrl({ revoked: [entrySerial((1n << 168n) + 1n)] }),
    makeCrl({ revoked: [entry(5), entry(5)] }),
    makeCrl({ revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(0n))])] }),
    makeCrl({ exts: [crlNumber(1), akiKeyId(), idpReasons],
      revoked: [entry(5, [crlExt("reasonCode", false, b.enumerated(0n))])] }),
    makeCrl({ exts: [crlNumber(1), akiKeyId(), idpIndirect],
      revoked: [entry(5, [certIssuerExt])] }),
    // A critical extension the entry profile does not recognize, so the battery covers a second
    // entry-scoped row and the locatability check below is not answering for one rule alone.
    makeCrl({ revoked: [entry(5, [crlExt("basicConstraints", true, b.sequence([]))])] }),
  ];
  var seenIds = Object.create(null), messageless = [], unlocatable = [], entryScoped = 0;
  messageBattery.forEach(function (der) {
    pki.lint.crl(der).findings.forEach(function (f) {
      seenIds[f.id] = true;
      if (typeof f.message !== "string" || f.message.length === 0) messageless.push(f.id);
      // A finding against an entry extension must say WHICH entry, or two entries breaking the
      // same rule are indistinguishable and a caller has to rescan the CRL to place it.
      if (f.context && f.context.scope === "crlEntryExtensions") {
        entryScoped++;
        if (typeof f.context.entry !== "number") unlocatable.push(f.id);
      }
    });
  });
  check("every CRL finding the battery produces carries a message", messageless.length === 0);
  check("every entry-scoped finding names the entry it came from", unlocatable.length === 0);
  check("the battery actually produces entry-scoped findings, so that check is not vacuous",
    entryScoped >= 2);
  check("the battery reaches most of the CRL registry, so the message check is not vacuous",
    Object.keys(seenIds).length >= 15);

  // Surface: the CRL rules are their own registry and the two verbs do not accept each other's
  // profile names, so a caller cannot silently lint a CRL against certificate rules.
  check("pki.lint.profiles() lists the CRL profile so it is discoverable",
    pki.lint.profiles().indexOf("rfc5280-crl") !== -1);
  check("every name profiles() lists resolves through rules()",
    pki.lint.profiles().every(function (p) { return pki.lint.rules(p).length > 0; }));
  check("pki.lint.rules('rfc5280-crl') enumerates the CRL registry",
    pki.lint.rules("rfc5280-crl").length > 0 &&
    pki.lint.rules("rfc5280-crl").every(function (r) { return r.source === "rfc5280-crl"; }));
  check("pki.lint.certificate refuses a CRL profile name",
    throwsCode(function () { pki.lint.certificate(REAL, { profile: "rfc5280-crl" }); }) === "lint/unknown-profile");
  check("pki.lint.crl refuses a certificate profile name",
    throwsCode(function () { pki.lint.crl(makeCrl(), { profile: "cabf-tls" }); }) === "lint/unknown-profile");
  check("pki.lint.crl refuses an unknown option",
    throwsCode(function () { pki.lint.crl(makeCrl(), { severty: "error" }); }) === "lint/bad-input");
  check("pki.lint.crl honors the severity threshold",
    pki.lint.crl(makeCrl({ exts: [crlNumber(1)] }), { severity: "error" }).findings
      .every(function (f) { return f.severity === "error" || f.severity === "fatal"; }));
}

module.exports = { run: run };

if (require.main === module) run();
