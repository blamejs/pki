// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.crl (X.509 CRL parser, RFC 5280 §5).
 * Spec-first conformance vectors: valid CRLs parse to the documented shape;
 * every malformed CertificateList / TBSCertList is rejected fail-closed with a
 * typed crl/* (or leaf-level asn1/*) error. The parser composes the shared
 * schema engine + PKIX factories, so it inherits the codec's fail-closed
 * verdicts (trailing bytes, indefinite length, non-minimal encodings).
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseCode(der) { return code(function () { pki.schema.crl.parse(der); }); }
function parse(der) { return pki.schema.crl.parse(der); }

// ---- CRL fixture builders --------------------------------------------
var SIGALG = "1.2.840.10045.4.3.2"; // ecdsa-with-SHA256

function algId(oidStr) { return b.sequence([b.oid(oidStr)]); }
function name(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
function utc(iso) { return b.utcTime(new Date(iso)); }
function gen(iso) { return b.generalizedTime(new Date(iso)); }
// a raw UTCTime TLV with arbitrary content (for malformed-date vectors)
function utcRaw(content) { return Buffer.concat([Buffer.from([0x17, content.length]), Buffer.from(content, "latin1")]); }

function ext(oidStr, valueBytes, critical) {
  var children = [b.oid(oidStr)];
  if (critical) children.push(b.boolean(true));
  children.push(b.octetString(valueBytes));
  return b.sequence(children);
}
function revoked(serial, dateNode, entryExts) {
  var c = [b.integer(serial), dateNode];
  if (entryExts) c.push(b.sequence(entryExts));
  return b.sequence(c);
}

// crl(o): assemble a CertificateList. `o` overrides any part; omit a part to
// leave that OPTIONAL field absent. o.tbsChildren / o.outerChildren replace the
// whole tbs / outer element array for the adversarial structural vectors.
function crl(o) {
  o = o || {};
  var tbs;
  if (o.tbsChildren) {
    tbs = b.sequence(o.tbsChildren);
  } else {
    var t = [];
    if (o.version !== undefined) t.push(b.integer(o.version)); // bare INTEGER (NOT [0] EXPLICIT)
    t.push(o.signature || algId(SIGALG));
    t.push(o.issuer || name("Test CA"));
    t.push(o.thisUpdate || utc("2026-01-01T00:00:00Z"));
    if (o.nextUpdate) t.push(o.nextUpdate);
    if (o.revoked) t.push(b.sequence(o.revoked));
    if (o.crlExtensions) t.push(b.explicit(0, b.sequence(o.crlExtensions)));
    else if (o.crlExtensionsRaw) t.push(o.crlExtensionsRaw);
    tbs = b.sequence(t);
  }
  if (o.outerChildren) return b.sequence(o.outerChildren);
  return b.sequence([tbs, o.outerSig || algId(SIGALG), o.sigVal || b.bitString(Buffer.from([0x00]), 0)]);
}

// ---- valid CRLs -------------------------------------------------------
function testValid() {
  // minimal v1: no version, no nextUpdate, no revoked, no extensions
  var m = parse(crl({}));
  check("minimal v1 parses: version 1", m.version === 1);
  check("minimal v1: nextUpdate absent", m.nextUpdate === null);
  check("minimal v1: empty revoked list", Array.isArray(m.revokedCertificates) && m.revokedCertificates.length === 0);
  check("minimal v1: thisUpdate is a Date", m.thisUpdate instanceof Date && m.thisUpdate.toISOString() === "2026-01-01T00:00:00.000Z");
  check("minimal v1: tbsBytes is a non-empty Buffer", Buffer.isBuffer(m.tbsBytes) && m.tbsBytes.length > 0);
  check("minimal v1: issuer dn", m.issuer.dn === "CN=Test CA");
  check("minimal v1: signatureAlgorithm named", m.signatureAlgorithm.oid === SIGALG);

  // full v2: version, nextUpdate, two revoked entries, crlExtensions
  var full = parse(crl({
    version: 1n,
    nextUpdate: gen("2030-01-01T00:00:00Z"),
    revoked: [revoked(3n, utc("2026-02-01T00:00:00Z")), revoked(1n, utc("2026-03-01T00:00:00Z"))],
    crlExtensions: [ext("2.5.29.20", b.integer(42n))], // cRLNumber = 42
  }));
  check("full v2 parses: version 2", full.version === 2);
  check("full v2: nextUpdate a Date", full.nextUpdate instanceof Date);
  check("full v2: two revoked entries in encoded order", full.revokedCertificates.length === 2 &&
    full.revokedCertificates[0].serialNumber === 3n && full.revokedCertificates[1].serialNumber === 1n);
  check("full v2: revoked serialNumberHex", full.revokedCertificates[0].serialNumberHex === "03");
  check("full v2: revocationDate a Date", full.revokedCertificates[0].revocationDate instanceof Date);
  check("full v2: crlExtensions surfaced with name", full.crlExtensions.length === 1 && full.crlExtensions[0].name === "cRLNumber");
  check("full v2: cRLNumber value decoded to BigInt", full.crlExtensions[0].value === 42n);

  // order preservation + non-dedup
  var ordered = parse(crl({ version: 1n,
    revoked: [revoked(3n, utc("2026-02-01T00:00:00Z")), revoked(1n, utc("2026-02-02T00:00:00Z")), revoked(2n, utc("2026-02-03T00:00:00Z"))],
    crlExtensions: [ext("2.5.29.20", b.integer(1n))] }));
  check("revoked order preserved (3,1,2 not sorted)", ordered.revokedCertificates.map(function (r) { return r.serialNumber; }).join(",") === "3,1,2");
  var dup = parse(crl({ version: 1n,
    revoked: [revoked(5n, utc("2026-02-01T00:00:00Z")), revoked(5n, utc("2026-02-02T00:00:00Z"))],
    crlExtensions: [ext("2.5.29.20", b.integer(1n))] }));
  check("repeated serial NOT deduplicated (indirect CRL)", dup.revokedCertificates.length === 2);
}

// ---- outer structure --------------------------------------------------
function testOuterStructure() {
  check("outer not a SEQUENCE rejected", parseCode(b.set([algId(SIGALG)])) === "crl/not-a-crl");
  check("outer SEQUENCE with 2 elements rejected", parseCode(crl({ outerChildren: [b.sequence([]), algId(SIGALG)] })) === "crl/not-a-crl");
  check("outer SEQUENCE with 4 elements rejected", parseCode(crl({ outerChildren: [b.sequence([]), algId(SIGALG), b.bitString(Buffer.from([0]), 0), b.integer(1n)] })) === "crl/not-a-crl");
  var good = crl({});
  check("trailing byte after outer SEQUENCE rejected (bad-der)", parseCode(Buffer.concat([good, Buffer.from([0x00])])) === "crl/bad-der");
  check("sig-alg mismatch (inner != outer) rejected", parseCode(crl({ signature: algId(SIGALG), outerSig: algId("1.2.840.10045.4.3.3") })) === "crl/bad-signature-algorithm");
}

// ---- tbsCertList fields ----------------------------------------------
function testTbsFields() {
  check("tbs not a SEQUENCE rejected", parseCode(crl({ tbsChildren: null, outerChildren: [b.integer(1n), algId(SIGALG), b.bitString(Buffer.from([0]), 0)] })) === "crl/bad-tbs");
  check("tbs missing thisUpdate rejected", parseCode(crl({ tbsChildren: [algId(SIGALG), name("CA")] })) === "crl/bad-tbs");
  check("empty issuer rejected", parseCode(crl({ issuer: b.sequence([]) })) === "crl/bad-issuer");
  check("empty RDN (SET {}) in issuer rejected", parseCode(crl({ issuer: b.sequence([b.set([])]) })) === "crl/bad-rdn");
  check("thisUpdate wrong tag (INTEGER) rejected", parseCode(crl({ thisUpdate: b.integer(5n) })) === "crl/bad-time");
  check("thisUpdate impossible date (Feb 30) rejected", parseCode(crl({ thisUpdate: utcRaw("260230000000Z") })) !== "NO-THROW");
}

// ---- version rules (§5.1.2.1) ----------------------------------------
function testVersion() {
  check("explicit v1 (INTEGER 0) rejected", parseCode(crl({ version: 0n })) === "crl/bad-version");
  check("version 2 (would be v3) rejected", parseCode(crl({ version: 2n })) === "crl/bad-version");
  check("cert-shaped [0] EXPLICIT version rejected (CRL uses bare INTEGER)",
    parseCode(crl({ tbsChildren: [b.explicit(0, b.integer(1n)), algId(SIGALG), name("CA"), utc("2026-01-01T00:00:00Z")] })) !== "NO-THROW");
  check("version absent + crlExtensions present rejected (v1 MUST NOT carry extensions)",
    parseCode(crl({ crlExtensions: [ext("2.5.29.20", b.integer(1n))] })) === "crl/bad-version");
  check("version absent + entry crlEntryExtensions present rejected",
    parseCode(crl({ revoked: [revoked(1n, utc("2026-02-01T00:00:00Z"), [ext("2.5.29.21", b.enumerated ? b.enumerated(1n) : b.integer(1n))])] })) === "crl/bad-version");
}

// ---- nextUpdate / revoked disambiguation (§5.1.2.5/2.6) ---------------
function testOptionalDisambiguation() {
  check("nextUpdate present (GeneralizedTime) parses", parse(crl({ nextUpdate: gen("2030-01-01T00:00:00Z") })).nextUpdate instanceof Date);
  check("revokedCertificates present-but-empty rejected", parseCode(crl({ version: 1n, revoked: [], crlExtensions: [ext("2.5.29.20", b.integer(1n))] })) === "crl/bad-revoked-certificates");
  check("revoked entry not a SEQUENCE rejected", parseCode(crl({ revoked: [b.integer(1n)] })) === "crl/bad-revoked-entry");
  check("revoked entry missing revocationDate rejected", parseCode(crl({ revoked: [b.sequence([b.integer(1n)])] })) === "crl/bad-revoked-entry");
}

// ---- extensions (§5.2/§5.3) ------------------------------------------
function testExtensions() {
  check("duplicate top-level extension OID rejected", parseCode(crl({ version: 1n, crlExtensions: [ext("2.5.29.20", b.integer(1n)), ext("2.5.29.20", b.integer(2n))] })) === "crl/duplicate-extension");
  check("empty [0] crlExtensions wrapper rejected", parseCode(crl({ crlExtensionsRaw: b.contextConstructed(0, Buffer.alloc(0)) })) === "crl/bad-extensions");
  check("crlExtensions [0] wrapping empty Extensions rejected", parseCode(crl({ crlExtensions: [] })) === "crl/bad-extensions");
  check("stray non-[0] trailing context tag rejected",
    parseCode(crl({ tbsChildren: [algId(SIGALG), name("CA"), utc("2026-01-01T00:00:00Z"), b.contextPrimitive(1, Buffer.from([1]))] })) === "crl/bad-tbs");
  var crit = parse(crl({ version: 1n, crlExtensions: [ext("2.5.29.28", b.sequence([]), true), ext("2.5.29.20", b.integer(1n))] }));
  check("critical flag preserved (not coerced to false)", crit.crlExtensions[0].critical === true && crit.crlExtensions[1].critical === false);
  check("IDP (GeneralNames-based) left raw with bytes reachable", Buffer.isBuffer(crit.crlExtensions[0].value));
}

// ---- extension strictness (fail-closed value decoding) ---------------
function testExtensionStrictness() {
  // An Extension with 4+ children is malformed — the 4th element is NOT silently ignored.
  var fourChild = b.sequence([b.oid("2.5.29.20"), b.octetString(b.integer(1n)), b.boolean(true), b.octetString(Buffer.from([1]))]);
  check("extension with 4 children rejected", parseCode(crl({ version: 1n, crlExtensions: [fourChild] })) === "crl/bad-extension");
  // A context-tagged constructed item ([5]{OID, OCTET STRING}) is not a universal
  // SEQUENCE — reject it even though the child count looks right.
  var bogusItem = b.contextConstructed(5, Buffer.concat([b.oid("2.5.29.20"), b.octetString(Buffer.from([1]))]));
  check("context-tagged extension item ([5]) rejected", parseCode(crl({ version: 1n, crlExtensions: [bogusItem] })) === "crl/bad-extension");
  // reasonCode is ENUMERATED — a bare INTEGER value is rejected (strict RFC 5280).
  check("reasonCode as INTEGER rejected (must be ENUMERATED)",
    parseCode(crl({ version: 1n, revoked: [revoked(1n, utc("2026-02-01T00:00:00Z"), [ext("2.5.29.21", b.integer(1n))])] })) === "crl/bad-extension-value");
  check("reasonCode as ENUMERATED decodes to the int", (function () {
    var m = parse(crl({ version: 1n, revoked: [revoked(1n, utc("2026-02-01T00:00:00Z"), [ext("2.5.29.21", b.enumerated(1n))])] }));
    return m.revokedCertificates[0].crlEntryExtensions[0].value === 1;
  })());
  // cRLNumber is INTEGER (0..MAX) — a negative value is malformed.
  check("negative cRLNumber rejected", parseCode(crl({ version: 1n, crlExtensions: [ext("2.5.29.20", b.integer(-1n))] })) === "crl/bad-extension-value");
  // reasonCode must be a DEFINED CRLReason — 7 is unused, 11 is out of range.
  check("reasonCode 7 (unused) rejected", parseCode(crl({ version: 1n, revoked: [revoked(1n, utc("2026-02-01T00:00:00Z"), [ext("2.5.29.21", b.enumerated(7n))])] })) === "crl/bad-extension-value");
  check("reasonCode 11 (out of range) rejected", parseCode(crl({ version: 1n, revoked: [revoked(1n, utc("2026-02-01T00:00:00Z"), [ext("2.5.29.21", b.enumerated(11n))])] })) === "crl/bad-extension-value");
  // serialNumberHex uses the raw INTEGER content bytes (matches x509, preserves DER sign padding).
  check("high-bit revoked serial hex preserves DER sign padding (0x80 -> 0080)", (function () {
    var m = parse(crl({ version: 1n, revoked: [revoked(0x80n, utc("2026-02-01T00:00:00Z"))], crlExtensions: [ext("2.5.29.20", b.integer(1n))] }));
    return m.revokedCertificates[0].serialNumberHex === "0080";
  })());
  // Extension-value decode keys off the stable dotted OID, not the mutable display name.
  check("extension decode survives an OID display-name override", (function () {
    var dotted = pki.oid.byName("cRLNumber");
    var orig = pki.oid.name(dotted);
    pki.oid.register(dotted, "cRLNumberRenamed");
    try {
      return parse(crl({ version: 1n, crlExtensions: [ext("2.5.29.20", b.integer(5n))] })).crlExtensions[0].value === 5n;
    } finally { pki.oid.register(dotted, orig); }
  })());
  // The CRL PEM decoder caps input size before scanning / base64-decoding.
  check("oversized CRL PEM rejected before decode (pem/too-large)", (function () {
    var huge = "-----BEGIN X509 CRL-----\n" + "A".repeat(pki.constants.LIMITS.PEM_MAX_BYTES) + "\n-----END X509 CRL-----";
    return code(function () { pki.schema.crl.parse(huge); }) === "pem/too-large";
  })());
}

// ---- input coercion (parity with the certificate parser) -------------
function testInputCoercion() {
  var der = crl({});
  var pem = "-----BEGIN X509 CRL-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END X509 CRL-----";
  check("crl.parse accepts a DER Buffer", parse(der).thisUpdate instanceof Date);
  check("crl.parse accepts a PEM string", parse(pem).thisUpdate instanceof Date);
  check("crl.parse accepts a PEM Buffer (readFileSync path)", parse(Buffer.from(pem, "utf8")).thisUpdate instanceof Date);
  check("crl.parse accepts a PEM Buffer with a leading newline", parse(Buffer.from("\n" + pem, "utf8")).thisUpdate instanceof Date);
  check("crl.parse accepts a PEM Buffer with a UTF-8 BOM", parse(Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(pem, "utf8")])).thisUpdate instanceof Date);
  check("crl.parse accepts a Uint8Array DER", parse(new Uint8Array(der)).thisUpdate instanceof Date);
  check("crl.parse rejects a non-buffer/string input", parseCode(42) === "crl/bad-input");
}

// ---- multi-defect fail-closed ----------------------------------------
function testMultiDefectFailClosed() {
  var c = parseCode(crl({ signature: algId(SIGALG), outerSig: algId("1.2.840.10045.4.3.3"), issuer: b.sequence([]), thisUpdate: b.integer(9n) }));
  check("multi-defect CRL stays fail-closed (typed rejection, no raw crash)", c !== "NO-THROW" && c.indexOf("RAW:") !== 0);
}

function run() {
  testValid();
  testOuterStructure();
  testTbsFields();
  testVersion();
  testOptionalDisambiguation();
  testExtensions();
  testExtensionStrictness();
  testInputCoercion();
  testMultiDefectFailClosed();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
