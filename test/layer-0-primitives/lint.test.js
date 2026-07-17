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

  // The load-bearing inversion: hostile bytes NEVER throw -- one fatal lint/unparseable.
  var truncated = pki.lint.certificate(REAL.subarray(0, 12));
  check("truncated DER does not throw -- returns a fatal lint/unparseable", has(truncated, "lint/unparseable") && truncated.worst === "fatal");
  check("lint/unparseable carries the inner PkiError code as context",
    truncated.findings[0].context && typeof truncated.findings[0].context.code === "string");
  check("garbage bytes do not throw either", pki.lint.certificate(Buffer.from([0xff, 0xff, 0xff])).worst === "fatal");

  // Config-time misuse is the ONLY throw path (a typed LintError).
  check("an unknown profile throws lint/unknown-profile", throwsCode(function () { pki.lint.certificate(REAL, { profile: "does-not-exist" }); }) === "lint/unknown-profile");
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

  // keyUsage SHOULD be critical (4.2.1.3) -- a SHOULD, hence warn; present-gated (EE or CA).
  check("a non-critical keyUsage -> key-usage-not-critical (warn)",
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

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
