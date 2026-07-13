// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.trust (Mozilla/NSS certdata.txt + CCADB CSV trust-store
 * ingestion). RED conformance vectors written BEFORE the implementation:
 * every vector drives the SHIPPED consumer surface (pki.trust.parseCertdata /
 * pki.trust.parseCcadbCsv / pki.trust.anchor, and anchor() ->
 * pki.path.validate for the wiring proof) on fixtures built around REAL
 * signed certificates, asserting the observable verdict (anchor fields or
 * the typed trust/* code) -- never a hand-decoded internal.
 *
 * Vector numbering follows the build plan's RED list:
 *   T1-T3   pairing (byte-exact issuer+serial join, never adjacency)
 *   T4-T8   MULTILINE_OCTAL decode + fail-closed bounds
 *   T9-T11  per-purpose distrust-after (NSS bare-ASCII time reuse)
 *   T12-T13 CKT_* purpose bits (only TRUSTED_DELEGATOR grants)
 *   T14     block delimiting / comments / preamble / malformed lines
 *   T15-T18 CCADB CSV (header-keyed columns, RFC 4180 quoting, same Anchor)
 *   T27     real-certdata slice -> anchor() -> pki.path.validate wiring
 *   T28     dedup by subjectDer + publicKey (never dropping a distinct root)
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

var b = pki.asn1.build;
var subtle = pki.webcrypto.subtle;

function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.name; } }
function causeOf(fn) { try { fn(); return "NO-CAUSE"; } catch (e) { return (e.cause && e.cause.code) || "NO-CAUSE"; } }

// Extract the failing codes across all per-cert checks of a validate() result.
function failCodes(res) {
  var out = [];
  (res.results || []).forEach(function (r) {
    (r.checks || []).forEach(function (c) { if (!c.ok && c.code) out.push(c.code); });
  });
  return out;
}

// ---------------------------------------------------------------------------
// Real-certificate fixtures (Ed25519 -- deterministic, parameter-free), built
// once. rootC shares rootA's subject DN but carries a DIFFERENT key (the
// dedup-must-not-drop case); the two leaves straddle the distrust boundary.
// ---------------------------------------------------------------------------

function nameDer(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
function bcExt() { return b.sequence([b.oid("2.5.29.19"), b.boolean(true), b.octetString(b.sequence([b.boolean(true)]))]); }

async function mkCert(o) {
  var tbsKids = [
    b.explicit(0, b.integer(2n)),
    b.integer(o.serial),
    b.sequence([b.oid("1.3.101.112")]),
    nameDer(o.issuer),
    b.sequence([
      b.utcTime(o.notBefore || new Date("2026-01-01T00:00:00Z")),
      b.utcTime(o.notAfter || new Date("2032-01-01T00:00:00Z")),
    ]),
    nameDer(o.subject),
    b.raw(o.spki),
  ];
  if (o.ca) tbsKids.push(b.explicit(3, b.sequence([bcExt()])));
  var tbs = b.sequence(tbsKids);
  var sig = Buffer.from(await subtle.sign({ name: "Ed25519" }, o.signKey, tbs));
  return b.sequence([tbs, b.sequence([b.oid("1.3.101.112")]), b.bitString(sig, 0)]);
}

var FX = null;
async function fixtures() {
  if (FX) return FX;
  var kpA = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var kpB = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var kpC = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var kpL = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var spkiA = Buffer.from(await subtle.exportKey("spki", kpA.publicKey));
  var spkiB = Buffer.from(await subtle.exportKey("spki", kpB.publicKey));
  var spkiC = Buffer.from(await subtle.exportKey("spki", kpC.publicKey));
  var spkiL = Buffer.from(await subtle.exportKey("spki", kpL.publicKey));

  var rootADer = await mkCert({ subject: "Test Root A", issuer: "Test Root A", serial: 4801n, signKey: kpA.privateKey, spki: spkiA, ca: true });
  var rootBDer = await mkCert({ subject: "Test Root B", issuer: "Test Root B", serial: 4802n, signKey: kpB.privateKey, spki: spkiB, ca: true });
  // Same subject DN as rootA, different key + serial: a DISTINCT root.
  var rootCDer = await mkCert({ subject: "Test Root A", issuer: "Test Root A", serial: 4803n, signKey: kpC.privateKey, spki: spkiC, ca: true });

  // Leaves signed by rootA's key, straddling the 2027-06-01T23:59:59Z
  // distrust-after boundary the T27 fixture carries.
  var leafBeforeDer = await mkCert({ subject: "T27 Leaf Before", issuer: "Test Root A", serial: 9001n, signKey: kpA.privateKey, spki: spkiL, notBefore: new Date("2026-03-01T00:00:00Z") });
  var leafAfterDer = await mkCert({ subject: "T27 Leaf After", issuer: "Test Root A", serial: 9002n, signKey: kpA.privateKey, spki: spkiL, notBefore: new Date("2027-06-02T00:00:00Z") });

  FX = {
    rootADer: rootADer, rootA: pki.schema.x509.parse(rootADer), spkiA: spkiA,
    rootBDer: rootBDer, rootB: pki.schema.x509.parse(rootBDer), spkiB: spkiB,
    rootCDer: rootCDer, rootC: pki.schema.x509.parse(rootCDer), spkiC: spkiC,
    leafBefore: pki.schema.x509.parse(leafBeforeDer),
    leafAfter: pki.schema.x509.parse(leafAfterDer),
  };
  return FX;
}

// ---------------------------------------------------------------------------
// certdata.txt fixture builders (the real file's shape: contiguous \ooo
// escapes, 16 per line, END-terminated; blocks separated by blank lines).
// ---------------------------------------------------------------------------

function octalBody(buf) {
  var lines = [];
  for (var i = 0; i < buf.length; i += 16) {
    var toks = [];
    for (var j = i; j < Math.min(i + 16, buf.length); j++) {
      toks.push("\\" + ("000" + buf[j].toString(8)).slice(-3));
    }
    lines.push(toks.join(""));
  }
  return lines.length ? lines.join("\n") : "";
}
function attrOctal(name, buf) { return name + " MULTILINE_OCTAL\n" + octalBody(buf) + "\nEND"; }
function ascii(str) { return Buffer.from(str, "latin1"); }
function serialTlv(cert) { return b.integer(cert.serialNumber); }

// A CKO_CERTIFICATE object block. o.server / o.email: "FALSE" for the
// CK_BBOOL CK_FALSE form, a bare time string for the MULTILINE_OCTAL form.
function certBlock(o) {
  var lines = [
    "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE",
    "CKA_TOKEN CK_BBOOL CK_TRUE",
    "CKA_LABEL UTF8 \"" + o.label + "\"",
    "CKA_CERTIFICATE_TYPE CK_CERTIFICATE_TYPE CKC_X_509",
  ];
  if (o.subject !== null) lines.push(attrOctal("CKA_SUBJECT", o.subject || o.cert.subject.bytes));
  lines.push(attrOctal("CKA_ISSUER", o.issuer || o.cert.issuer.bytes));
  lines.push(attrOctal("CKA_SERIAL_NUMBER", o.serial || serialTlv(o.cert)));
  lines.push(attrOctal("CKA_VALUE", o.der));
  if (o.policy) lines.push("CKA_NSS_MOZILLA_CA_POLICY CK_BBOOL CK_TRUE");
  if (o.server) {
    lines.push(o.server === "FALSE"
      ? "CKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_FALSE"
      : attrOctal("CKA_NSS_SERVER_DISTRUST_AFTER", ascii(o.server)));
  }
  if (o.email) {
    lines.push(o.email === "FALSE"
      ? "CKA_NSS_EMAIL_DISTRUST_AFTER CK_BBOOL CK_FALSE"
      : attrOctal("CKA_NSS_EMAIL_DISTRUST_AFTER", ascii(o.email)));
  }
  return lines.join("\n");
}

// A CKO_NSS_TRUST object block, paired by issuer+serial (o.cert, or the
// explicit o.issuer/o.serial buffers for a deliberately mispaired object).
function trustBlock(o) {
  var lines = [
    "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST",
    "CKA_TOKEN CK_BBOOL CK_TRUE",
    "CKA_LABEL UTF8 \"" + o.label + "\"",
  ];
  if (o.hashes) {
    lines.push(attrOctal("CKA_CERT_SHA1_HASH", Buffer.alloc(20, 0xab)));
    lines.push(attrOctal("CKA_CERT_MD5_HASH", Buffer.alloc(16, 0xcd)));
  }
  lines.push(attrOctal("CKA_ISSUER", o.issuer || o.cert.issuer.bytes));
  lines.push(attrOctal("CKA_SERIAL_NUMBER", o.serial || serialTlv(o.cert)));
  lines.push("CKA_TRUST_SERVER_AUTH CK_TRUST " + (o.serverAuth || "CKT_NSS_MUST_VERIFY_TRUST"));
  lines.push("CKA_TRUST_EMAIL_PROTECTION CK_TRUST " + (o.email || "CKT_NSS_MUST_VERIFY_TRUST"));
  lines.push("CKA_TRUST_CODE_SIGNING CK_TRUST " + (o.code || "CKT_NSS_MUST_VERIFY_TRUST"));
  lines.push("CKA_TRUST_STEP_UP_APPROVED CK_BBOOL CK_FALSE");
  return lines.join("\n");
}

function certdata(blocks) {
  return "# certdata fixture\n# comment line\nBEGINDATA\n\n" + blocks.join("\n\n") + "\n";
}

// ---------------------------------------------------------------------------
// CCADB CSV fixture builders (RFC 4180).
// ---------------------------------------------------------------------------

function q(s) { return "\"" + String(s).replace(/"/g, "\"\"") + "\""; }
function csvOf(rows) {
  return rows.map(function (r) { return r.join(","); }).join("\r\n") + "\r\n";
}
var CSV_HEADER = ["Common Name or Certificate Name", "Trust Bits", "Distrust for TLS After Date", "Distrust for S/MIME After Date", "PEM Info"];

// ---------------------------------------------------------------------------
// T1-T3 -- pairing: byte-exact (CKA_ISSUER, CKA_SERIAL_NUMBER), never adjacency
// ---------------------------------------------------------------------------

async function testCertdataPairing() {
  var fx = await fixtures();

  // T1: cert A, cert B, trust B, trust A -- each trust object is NON-adjacent
  // to its certificate; pairing must ride the issuer+serial key.
  var t1 = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }),
    certBlock({ label: "Test Root B", cert: fx.rootB, der: fx.rootBDer }),
    trustBlock({ label: "Test Root B", cert: fx.rootB, email: "CKT_NSS_TRUSTED_DELEGATOR" }),
    trustBlock({ label: "Test Root A", cert: fx.rootA, serverAuth: "CKT_NSS_TRUSTED_DELEGATOR" }),
  ]);
  var out1 = pki.trust.parseCertdata(t1);
  check("T1: two anchors from two interleaved cert/trust pairs", out1.anchors.length === 2);
  var a1 = out1.anchors[0], b1 = out1.anchors[1];
  check("T1: anchor A carries ITS OWN trust bits (serverAuth delegator)",
    a1.label === "Test Root A" && a1.purposes.serverAuth === true &&
    a1.purposes.emailProtection === false && a1.purposes.codeSigning === false);
  check("T1: anchor B carries ITS OWN trust bits (email delegator)",
    b1.label === "Test Root B" && b1.purposes.emailProtection === true &&
    b1.purposes.serverAuth === false && b1.purposes.codeSigning === false);
  check("T1: anchor A carries its own cert's SPKI", a1.publicKey.equals(fx.rootA.subjectPublicKeyInfo.bytes));
  check("T1: anchor B carries its own cert's SPKI", b1.publicKey.equals(fx.rootB.subjectPublicKeyInfo.bytes));

  // T2: a cert object whose CKA_ISSUER disagrees with its parsed DER.
  var t2a = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, issuer: fx.rootB.issuer.bytes }),
  ]);
  check("T2: CKA_ISSUER vs parsed-DER disagreement -> trust/pairing-mismatch",
    codeOf(function () { pki.trust.parseCertdata(t2a); }) === "trust/pairing-mismatch");

  // T2: a cert object whose CKA_SERIAL_NUMBER disagrees with its parsed DER.
  var t2b = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, serial: b.integer(31337n) }),
  ]);
  check("T2: CKA_SERIAL_NUMBER vs parsed-DER disagreement -> trust/pairing-mismatch",
    codeOf(function () { pki.trust.parseCertdata(t2b); }) === "trust/pairing-mismatch");

  // T2: a trust object matching no certificate object is IGNORED -- its bits
  // must never attach to any root (metadata never attaches to the wrong root).
  var t2c = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }),
    trustBlock({ label: "ghost", issuer: fx.rootB.issuer.bytes, serial: b.integer(777n), serverAuth: "CKT_NSS_TRUSTED_DELEGATOR" }),
  ]);
  var out2c = pki.trust.parseCertdata(t2c);
  check("T2: an orphan trust object is ignored -- its bits attach to nothing",
    out2c.anchors.length === 1 && out2c.anchors[0].purposes.serverAuth === false);

  // T3: a cert object with NO trust object -> anchor trusted for nothing,
  // not silently dropped.
  var t3 = certdata([certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer })]);
  var out3 = pki.trust.parseCertdata(t3);
  check("T3: cert with no trust object -> anchor with all-false purposes",
    out3.anchors.length === 1 &&
    out3.anchors[0].purposes.serverAuth === false &&
    out3.anchors[0].purposes.emailProtection === false &&
    out3.anchors[0].purposes.codeSigning === false);
}

// ---------------------------------------------------------------------------
// T4-T8 -- MULTILINE_OCTAL decode + fail-closed bounds
// ---------------------------------------------------------------------------

async function testOctalDecode() {
  var fx = await fixtures();

  // T4: the octal round-trip is byte-exact (CKA_VALUE -> x509.parse; the
  // anchor surfaces the exact SPKI / subject TLVs off the parsed DER).
  var t4 = certdata([certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer })]);
  var a4 = pki.trust.parseCertdata(t4).anchors[0];
  check("T4: publicKey is the exact SPKI SEQUENCE TLV", a4.publicKey.equals(fx.rootA.subjectPublicKeyInfo.bytes));
  check("T4: subjectDer is the exact subject Name TLV", a4.subjectDer.equals(fx.rootA.subject.bytes));
  check("T4: algorithm is the SPKI public-key algorithm OID (not signatureAlgorithm)", a4.algorithm === fx.rootA.subjectPublicKeyInfo.algorithm.oid);
  check("T4: name is the parsed subject (has .rdns)", Array.isArray(a4.name.rdns) && a4.name.dn === "CN=Test Root A");

  // T4: whitespace-separated escapes decode identically to the contiguous form
  // ("conventionally 16 per line but not required").
  var spaced = certdata([certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer })])
    .replace(/\\(?=[0-7])/g, " \\").replace(/^ \\/gm, "\\");
  var aSpaced = pki.trust.parseCertdata(spaced).anchors[0];
  check("T4: whitespace-separated octal escapes decode identically", aSpaced.publicKey.equals(a4.publicKey));

  // T5: an escape past \377 (value > 255) fails closed.
  var t5 = certdata(["CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n\\400\nEND"]);
  check("T5: \\400 escape -> trust/bad-octal",
    codeOf(function () { pki.trust.parseCertdata(t5); }) === "trust/bad-octal");

  // T6: a short / non-octal escape fails closed.
  var t6a = certdata(["CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n\\09\nEND"]);
  check("T6: \\09 (non-octal digit) -> trust/bad-octal",
    codeOf(function () { pki.trust.parseCertdata(t6a); }) === "trust/bad-octal");
  var t6b = certdata(["CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n\\1\nEND"]);
  check("T6: \\1 (short escape) -> trust/bad-octal",
    codeOf(function () { pki.trust.parseCertdata(t6b); }) === "trust/bad-octal");
  var t6c = certdata(["CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\nnotoctal\nEND"]);
  check("T6: a stray non-escape token -> trust/bad-octal",
    codeOf(function () { pki.trust.parseCertdata(t6c); }) === "trust/bad-octal");

  // T7: EOF before END, and a blank line before END -- never a silently
  // truncated certificate.
  var t7a = "BEGINDATA\n\nCKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n\\060\\061";
  check("T7: EOF before END -> trust/bad-octal",
    codeOf(function () { pki.trust.parseCertdata(t7a); }) === "trust/bad-octal");
  var t7b = certdata(["CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n\\060\\061\n\nEND"]);
  check("T7: blank line before END -> trust/bad-octal",
    codeOf(function () { pki.trust.parseCertdata(t7b); }) === "trust/bad-octal");

  // T8: a blob past TRUST_MAX_OCTAL_BYTES is refused BEFORE full accumulation.
  var cap = pki.C.LIMITS.TRUST_MAX_OCTAL_BYTES;
  check("T8: TRUST_MAX_OCTAL_BYTES is a positive ceiling", typeof cap === "number" && cap > 0);
  var big = new Array(cap + 1).fill("\\000").join("");
  var t8 = certdata(["CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n" + big + "\nEND"]);
  check("T8: over-cap MULTILINE_OCTAL blob -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(t8); }) === "trust/bad-block");
}

// ---------------------------------------------------------------------------
// T9-T11 -- distrust-after: bare-ASCII NSS time through the strict reader
// ---------------------------------------------------------------------------

async function testDistrustAfter() {
  var fx = await fixtures();

  // T9: the 13-byte UTCTime form (in the CERTIFICATE object) -> exact Date
  // via the reused strict reader (Z-terminator, seconds, 2050 pivot).
  var t9 = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, server: "241130235959Z", email: "FALSE" }),
  ]);
  var a9 = pki.trust.parseCertdata(t9).anchors[0];
  check("T9: CKA_NSS_SERVER_DISTRUST_AFTER decodes to the exact instant",
    a9.distrustAfter.serverAuth instanceof Date &&
    a9.distrustAfter.serverAuth.getTime() === Date.UTC(2024, 10, 30, 23, 59, 59));

  // T9: the 15-byte GeneralizedTime branch (a far-future date).
  var t9b = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, email: "20501130235959Z" }),
  ]);
  var a9b = pki.trust.parseCertdata(t9b).anchors[0];
  check("T9: a 15-byte YYYYMMDDHHMMSSZ decodes via the GeneralizedTime branch",
    a9b.distrustAfter.emailProtection instanceof Date &&
    a9b.distrustAfter.emailProtection.getTime() === Date.UTC(2050, 10, 30, 23, 59, 59));

  // T10: CK_BBOOL CK_FALSE -> no distrust-after in force (key absent).
  var t10 = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, email: "FALSE" }),
  ]);
  var a10 = pki.trust.parseCertdata(t10).anchors[0];
  check("T10: CK_BBOOL CK_FALSE -> distrustAfter.emailProtection absent",
    !("emailProtection" in a10.distrustAfter));

  // T11: an out-of-range time (month 13) -> trust/bad-distrust-after with the
  // asn1 fault threaded as .cause.
  var t11a = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, server: "241399235959Z" }),
  ]);
  check("T11: month-13 time -> trust/bad-distrust-after",
    codeOf(function () { pki.trust.parseCertdata(t11a); }) === "trust/bad-distrust-after");
  check("T11: the asn1 fault rides as .cause",
    /^asn1\//.test(causeOf(function () { pki.trust.parseCertdata(t11a); })));

  // T11: a wrong-length blob (neither 13 nor 15 bytes) fails closed.
  var t11b = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, server: "2411302359Z" }),
  ]);
  check("T11: wrong-length distrust blob -> trust/bad-distrust-after",
    codeOf(function () { pki.trust.parseCertdata(t11b); }) === "trust/bad-distrust-after");

  // T11: a missing Z terminator fails closed through the strict reader.
  var t11c = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, server: "2411302359590" }),
  ]);
  check("T11: no-Z time -> trust/bad-distrust-after",
    codeOf(function () { pki.trust.parseCertdata(t11c); }) === "trust/bad-distrust-after");
}

// ---------------------------------------------------------------------------
// T12-T13 -- purpose bits: ONLY CKT_NSS_TRUSTED_DELEGATOR grants
// ---------------------------------------------------------------------------

async function testTrustBits() {
  var fx = await fixtures();

  // T12: a delegator bit grants exactly its purpose.
  var t12 = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }),
    trustBlock({ label: "Test Root A", cert: fx.rootA, code: "CKT_NSS_TRUSTED_DELEGATOR" }),
  ]);
  var a12 = pki.trust.parseCertdata(t12).anchors[0];
  check("T12: CKT_NSS_TRUSTED_DELEGATOR -> purposes.codeSigning === true",
    a12.purposes.codeSigning === true && a12.purposes.serverAuth === false && a12.purposes.emailProtection === false);

  // T13: every non-delegator token is fail-closed false.
  var t13 = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }),
    trustBlock({ label: "Test Root A", cert: fx.rootA, serverAuth: "CKT_NSS_MUST_VERIFY_TRUST", email: "CKT_NSS_NOT_TRUSTED", code: "CKT_NSS_TRUSTED" }),
  ]);
  var a13 = pki.trust.parseCertdata(t13).anchors[0];
  check("T13: MUST_VERIFY_TRUST / NOT_TRUSTED / TRUSTED (non-delegator) -> all false",
    a13.purposes.serverAuth === false && a13.purposes.emailProtection === false && a13.purposes.codeSigning === false);

  // T13: an unrecognized CK_TRUST token fails closed with a typed verdict.
  var t13b = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }),
    trustBlock({ label: "Test Root A", cert: fx.rootA, serverAuth: "CKT_NSS_TOTALLY_BOGUS" }),
  ]);
  check("T13: unrecognized CKT_* token -> trust/bad-trust-value",
    codeOf(function () { pki.trust.parseCertdata(t13b); }) === "trust/bad-trust-value");
}

// ---------------------------------------------------------------------------
// T14 -- block delimiting: comments, preamble, blank lines, malformed lines
// ---------------------------------------------------------------------------

async function testBlockDelimiting() {
  var fx = await fixtures();

  // Comments and attribute-shaped preamble lines before BEGINDATA are inert.
  var t14 = "# leading comment\nThis line is prose, not an attribute.\n" +
    "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n" +   // pre-BEGINDATA: ignored
    "BEGINDATA\n\n# a comment between blocks\n\n" +
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }) + "\n\n" +
    "# trailing comment\n";
  var out14 = pki.trust.parseCertdata(t14);
  check("T14: preamble + comments + blank-line delimiting -> one anchor",
    out14.anchors.length === 1 && out14.anchors[0].label === "Test Root A");

  // A malformed attribute line (missing the type token) fails closed.
  var t14b = certdata(["CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_TOKEN"]);
  check("T14: attribute line missing its type token -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(t14b); }) === "trust/bad-block");

  // A non-attribute token line inside the data section fails closed.
  var t14c = certdata(["CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nWAT 1 2"]);
  check("T14: a non-CKA_* token line -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(t14c); }) === "trust/bad-block");

  // No BEGINDATA marker at all: not a certdata stream.
  check("T14: input with no BEGINDATA -> trust/bad-input",
    codeOf(function () { pki.trust.parseCertdata("# just comments\n"); }) === "trust/bad-input");

  // A non-string/non-Buffer input fails closed at the guard.
  check("T14: non-text input -> trust/bad-input",
    codeOf(function () { pki.trust.parseCertdata(12345); }) === "trust/bad-input");

  // A detached-backed Buffer fails closed (the guard.text.decode re-view),
  // never lexes as an empty stream.
  var ab = new ArrayBuffer(10);
  var det = Buffer.from(ab);
  det.write("BEGINDATA\n", "latin1");
  structuredClone(ab, { transfer: [ab] });
  check("T14: detached-backed Buffer -> trust/bad-input",
    codeOf(function () { pki.trust.parseCertdata(det); }) === "trust/bad-input");

  // A CKA_VALUE that decodes as octal but is not a certificate carries the
  // x509 leaf fault as .cause.
  var t14d = certdata(["CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL\n\\001\\002\\003\nEND"]);
  check("T14: non-certificate CKA_VALUE -> trust/not-a-certificate",
    codeOf(function () { pki.trust.parseCertdata(t14d); }) === "trust/not-a-certificate");
  check("T14: the x509 leaf fault rides as .cause",
    /^(x509|asn1)\//.test(causeOf(function () { pki.trust.parseCertdata(t14d); })));
}

// ---------------------------------------------------------------------------
// T15-T16 -- CCADB CSV: header-keyed columns, fail-closed required set
// ---------------------------------------------------------------------------

async function testCsvHeaderKeyed() {
  var fx = await fixtures();
  var pemA = pki.schema.x509.pemEncode(fx.rootADer, "CERTIFICATE");

  // T15: extra, unknown, reordered columns -- location is by header NAME.
  var csv = csvOf([
    ["Salesforce Record ID", "PEM Info", "Unknown Future Column", "Common Name or Certificate Name", "Distrust for S/MIME After Date", "Trust Bits", "Distrust for TLS After Date"],
    ["0018Z00002", q(pemA), "whatever", "Test Root A", "", q("Websites; Email"), "2027.06.01"],
  ]);
  var out15 = pki.trust.parseCcadbCsv(csv);
  check("T15: one anchor from a reordered, extra-column CSV", out15.anchors.length === 1);
  var a15 = out15.anchors[0];
  check("T15: label from Common Name or Certificate Name", a15.label === "Test Root A");
  check("T15: Trust Bits Websites;Email -> serverAuth + emailProtection",
    a15.purposes.serverAuth === true && a15.purposes.emailProtection === true && a15.purposes.codeSigning === false);
  check("T15: PEM Info column parses to the certificate", a15.publicKey.equals(fx.rootA.subjectPublicKeyInfo.bytes));
  check("T15: Distrust for TLS After Date expands to end-of-day UTC",
    a15.distrustAfter.serverAuth instanceof Date &&
    a15.distrustAfter.serverAuth.getTime() === Date.UTC(2027, 5, 1, 23, 59, 59));
  check("T15: empty S/MIME distrust cell -> absent", !("emailProtection" in a15.distrustAfter));

  // T15: a dash-separated date parses to the same instant (tolerant Y-M-D).
  var csvDash = csvOf([
    CSV_HEADER,
    ["Test Root A", q("Websites"), "2027-06-01", "", q(pemA)],
  ]);
  var a15b = pki.trust.parseCcadbCsv(csvDash).anchors[0];
  check("T15: Y-M-D with dashes parses to the same end-of-day instant",
    a15b.distrustAfter.serverAuth.getTime() === Date.UTC(2027, 5, 1, 23, 59, 59));

  // T16: each missing REQUIRED column fails closed.
  ["Common Name or Certificate Name", "Trust Bits", "Distrust for TLS After Date", "Distrust for S/MIME After Date", "PEM Info"].forEach(function (drop) {
    var idx = CSV_HEADER.indexOf(drop);
    var header = CSV_HEADER.filter(function (_, i) { return i !== idx; });
    var row = ["Test Root A", q("Websites"), "2027.06.01", "", q(pemA)].filter(function (_, i) { return i !== idx; });
    var bad = csvOf([header, row]);
    check("T16: CSV missing " + JSON.stringify(drop) + " -> trust/bad-csv",
      codeOf(function () { pki.trust.parseCcadbCsv(bad); }) === "trust/bad-csv");
  });

  // T16: an unrecognized Trust Bits token is surfaced, never silently skipped.
  var badBits = csvOf([CSV_HEADER, ["Test Root A", q("Websites; Wormholes"), "", "", q(pemA)]]);
  check("T16: unknown Trust Bits token -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(badBits); }) === "trust/bad-csv");

  // T16b: the CURRENT CCADB vocabulary (the EKU-derived trust-bit names) maps to
  // the same purposes as the legacy Mozilla-report labels.
  var curBits = csvOf([CSV_HEADER, ["Test Root A", q("Server Authentication; Secure Email; Code Signing"), "", "", q(pemA)]]);
  var curAnchor = pki.trust.parseCcadbCsv(curBits).anchors[0];
  check("T16b: Server Authentication / Secure Email / Code Signing map to the purposes",
    curAnchor.purposes.serverAuth === true && curAnchor.purposes.emailProtection === true && curAnchor.purposes.codeSigning === true);
  // T16c: the KNOWN CCADB purposes the anchor model does not track are tolerated
  // and grant nothing (a purpose is only ever granted by a recognized delegator
  // token -- the fail-closed direction); a token outside the known universe
  // still errors (T16 above), so vocabulary drift keeps surfacing.
  var tolBits = csvOf([CSV_HEADER, ["Test Root A", q("Client Authentication; Time Stamping; Document Signing; OCSP Signing; Websites"), "", "", q(pemA)]]);
  var tolAnchor = pki.trust.parseCcadbCsv(tolBits).anchors[0];
  check("T16c: known unmapped CCADB purposes tolerated, grant nothing beyond the mapped token",
    tolAnchor.purposes.serverAuth === true && tolAnchor.purposes.emailProtection === false && tolAnchor.purposes.codeSigning === false);

  // T16: an unparseable non-empty distrust date fails closed.
  var badDate = csvOf([CSV_HEADER, ["Test Root A", q("Websites"), "soon", "", q(pemA)]]);
  check("T16: unparseable distrust date -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(badDate); }) === "trust/bad-csv");

  // T16: a PEM Info cell that is not a certificate carries the leaf fault.
  var badPem = csvOf([CSV_HEADER, ["Test Root A", q("Websites"), "", "", q("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")]]);
  check("T16: a non-certificate PEM Info -> trust/not-a-certificate",
    codeOf(function () { pki.trust.parseCcadbCsv(badPem); }) === "trust/not-a-certificate");

  // T16: two columns claiming one REQUIRED name make the mapping ambiguous.
  var dupCol = csvOf([["Trust Bits"].concat(CSV_HEADER), [q("Email"), "Test Root A", q("Websites"), "", "", q(pemA)]]);
  check("T16: duplicate required column -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(dupCol); }) === "trust/bad-csv");

  // T15: a BOM-prefixed export still resolves its first header cell.
  var bom = String.fromCharCode(0xFEFF);
  var bomCsv = bom + csvOf([CSV_HEADER, ["Test Root A", q("Websites"), "", "", q(pemA)]]);
  var outBom = pki.trust.parseCcadbCsv(bomCsv);
  check("T15: a UTF-8 BOM before the header is tolerated",
    outBom.anchors.length === 1 && outBom.anchors[0].purposes.serverAuth === true);
}

// ---------------------------------------------------------------------------
// T17 -- the SAME root through both sources yields an IDENTICAL Anchor
// ---------------------------------------------------------------------------

function sameDistrust(x, y) {
  var kx = Object.keys(x).sort(), ky = Object.keys(y).sort();
  if (kx.join(",") !== ky.join(",")) return false;
  return kx.every(function (k) { return x[k] instanceof Date && y[k] instanceof Date && x[k].getTime() === y[k].getTime(); });
}

function anchorsIdentical(x, y) {
  return x.label === y.label &&
    x.name.dn === y.name.dn &&
    x.publicKey.equals(y.publicKey) &&
    x.algorithm === y.algorithm &&
    ((x.parameters === null && y.parameters === null) ||
     (Buffer.isBuffer(x.parameters) && Buffer.isBuffer(y.parameters) && x.parameters.equals(y.parameters))) &&
    x.subjectDer.equals(y.subjectDer) &&
    sameDistrust(x.distrustAfter, y.distrustAfter) &&
    x.purposes.serverAuth === y.purposes.serverAuth &&
    x.purposes.emailProtection === y.purposes.emailProtection &&
    x.purposes.codeSigning === y.purposes.codeSigning &&
    x.mozillaCaPolicy === y.mozillaCaPolicy;
}

async function testCsvSameShape() {
  var fx = await fixtures();

  // NSS side: end-of-day UTCTime distrust + serverAuth/email delegator bits.
  var nss = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, server: "270601235959Z", email: "FALSE" }),
    trustBlock({ label: "Test Root A", cert: fx.rootA, serverAuth: "CKT_NSS_TRUSTED_DELEGATOR", email: "CKT_NSS_TRUSTED_DELEGATOR" }),
  ]);
  var fromNss = pki.trust.parseCertdata(nss).anchors[0];

  // CCADB side: the DATE-only column expands to the same ...T23:59:59Z instant.
  var pemA = pki.schema.x509.pemEncode(fx.rootADer, "CERTIFICATE");
  var csv = csvOf([CSV_HEADER, ["Test Root A", q("Websites; Email"), "2027.06.01", "", q(pemA)]]);
  var fromCsv = pki.trust.parseCcadbCsv(csv).anchors[0];

  check("T17: certdata and CCADB yield an IDENTICAL Anchor for the same root",
    anchorsIdentical(fromNss, fromCsv));
  check("T17: the NSS end-of-day and the expanded CCADB date are the same instant",
    fromNss.distrustAfter.serverAuth.getTime() === fromCsv.distrustAfter.serverAuth.getTime());
}

// ---------------------------------------------------------------------------
// T18 -- RFC 4180 quoting: embedded commas, newlines, "" escapes
// ---------------------------------------------------------------------------

async function testCsvQuoting() {
  var fx = await fixtures();
  var pemB = pki.schema.x509.pemEncode(fx.rootBDer, "CERTIFICATE");

  // The PEM block spans lines inside its quoted field; the label carries an
  // embedded comma and a "" escape.
  var csv = csvOf([
    CSV_HEADER,
    [q("Root, T18 \"Q\""), q("Websites"), "", "", q(pemB)],
  ]);
  var out = pki.trust.parseCcadbCsv(csv);
  check("T18: quoted PEM with embedded newlines decodes to the certificate",
    out.anchors.length === 1 && out.anchors[0].publicKey.equals(fx.rootB.subjectPublicKeyInfo.bytes));
  check("T18: embedded comma + doubled-quote escape survive in the label",
    out.anchors[0].label === "Root, T18 \"Q\"");

  // An unterminated quoted field is a framing violation.
  var bad = "Common Name or Certificate Name,Trust Bits,Distrust for TLS After Date,Distrust for S/MIME After Date,PEM Info\r\n\"Root,Websites,,,x\r\n";
  check("T18: unterminated quoted field -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(bad); }) === "trust/bad-csv");
}

// ---------------------------------------------------------------------------
// T27 -- a real-looking certdata slice, wired through anchor() -> validate()
// ---------------------------------------------------------------------------

async function testRealCertdataSlice() {
  var fx = await fixtures();

  // A trimmed real-shaped fragment: license-style preamble, the builtin
  // ROOT_LIST object (ignored), two roots with the full realistic attribute
  // set, one carrying a real-shaped CKA_NSS_SERVER_DISTRUST_AFTER.
  var slice = [
    "# certdata.txt",
    "#",
    "# This Source Code Form is a trimmed test fixture.",
    "BEGINDATA",
    "",
    "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_BUILTIN_ROOT_LIST",
    "CKA_TOKEN CK_BBOOL CK_TRUE",
    "CKA_PRIVATE CK_BBOOL CK_FALSE",
    "CKA_MODIFIABLE CK_BBOOL CK_FALSE",
    "CKA_LABEL UTF8 \"Mozilla Builtin Roots\"",
    "",
    "# Certificate \"Test Root A\"",
    "#",
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, policy: true, server: "270601235959Z", email: "FALSE" }),
    "",
    "# Certificate \"Test Root B\"",
    certBlock({ label: "Test Root B", cert: fx.rootB, der: fx.rootBDer }),
    "",
    "# Trust for \"Test Root B\"",
    trustBlock({ label: "Test Root B", cert: fx.rootB, hashes: true, email: "CKT_NSS_TRUSTED_DELEGATOR" }),
    "",
    "# Trust for \"Test Root A\"",
    trustBlock({ label: "Test Root A", cert: fx.rootA, hashes: true, serverAuth: "CKT_NSS_TRUSTED_DELEGATOR" }),
    "",
  ].join("\n");

  var out = pki.trust.parseCertdata(slice);
  check("T27: the slice parses to two anchors", out.anchors.length === 2);
  var entryA = out.anchors[0];
  check("T27: root A carries the real-shaped distrust-after",
    entryA.distrustAfter.serverAuth instanceof Date &&
    entryA.distrustAfter.serverAuth.getTime() === Date.UTC(2027, 5, 1, 23, 59, 59));
  check("T27: CKA_NSS_MOZILLA_CA_POLICY CK_TRUE surfaces", entryA.mozillaCaPolicy === true);

  // anchor() -> validate(): the anchor's publicKey/algorithm must import and
  // genuinely verify a real leaf signature through the shipped validator.
  var anchorA = pki.trust.anchor(entryA, { purpose: "serverAuth" });
  var T = new Date("2027-07-01T00:00:00Z");

  var resBefore = await pki.path.validate([fx.leafBefore], { time: T, trustAnchor: anchorA, checkPurpose: "serverAuth" });
  check("T27: a leaf issued BEFORE the distrust date validates", resBefore.valid === true);

  var resAfter = await pki.path.validate([fx.leafAfter], { time: T, trustAnchor: anchorA, checkPurpose: "serverAuth" });
  check("T27: a leaf issued AFTER the distrust date is rejected",
    resAfter.valid === false && failCodes(resAfter).indexOf("path/distrusted-after") !== -1);

  // anchor() fail-fast: root A is NOT an email delegator.
  check("T27: anchor(entry, { purpose }) fail-fasts on an untrusted purpose",
    codeOf(function () { pki.trust.anchor(entryA, { purpose: "emailProtection" }); }) === "trust/purpose-not-trusted");
  check("T27: anchor() rejects an unknown purpose name",
    codeOf(function () { pki.trust.anchor(entryA, { purpose: "wormholes" }); }) === "trust/bad-input");
  check("T27: anchor() rejects a non-entry input",
    codeOf(function () { pki.trust.anchor(null); }) === "trust/bad-input");
}

// ---------------------------------------------------------------------------
// T28 -- dedup by subjectDer + publicKey; distinct roots never dropped
// ---------------------------------------------------------------------------

async function testDedup() {
  var fx = await fixtures();

  // A duplicated identical block pair collapses to one anchor.
  var certA = certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer });
  var trustA = trustBlock({ label: "Test Root A", cert: fx.rootA, serverAuth: "CKT_NSS_TRUSTED_DELEGATOR" });
  var dup = certdata([certA, trustA, certA, trustA]);
  var outDup = pki.trust.parseCertdata(dup);
  check("T28: a duplicated identical root collapses to one anchor",
    outDup.anchors.length === 1 && outDup.anchors[0].purposes.serverAuth === true);

  // Two DISTINCT roots sharing a subject DN (different keys) both survive.
  var shared = certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }),
    certBlock({ label: "Test Root A v2", cert: fx.rootC, der: fx.rootCDer }),
  ]);
  var outShared = pki.trust.parseCertdata(shared);
  check("T28: distinct roots sharing a subject DN are NOT collapsed",
    outShared.anchors.length === 2 &&
    outShared.anchors[0].subjectDer.equals(outShared.anchors[1].subjectDer) &&
    !outShared.anchors[0].publicKey.equals(outShared.anchors[1].publicKey));

  // A duplicate whose metadata DISAGREES is ambiguous -- fail closed, never
  // silently pick one.
  var conflict = certdata([
    certA, trustA, certA,
    trustBlock({ label: "Test Root A", cert: fx.rootA, email: "CKT_NSS_TRUSTED_DELEGATOR" }),
  ]);
  check("T28: conflicting duplicate trust metadata -> trust/pairing-mismatch",
    codeOf(function () { pki.trust.parseCertdata(conflict); }) === "trust/pairing-mismatch");

  // Cross-source: the dedup key (subjectDer + publicKey) is byte-identical
  // from certdata and CCADB, so an operator-level merge collapses to one.
  var pemA = pki.schema.x509.pemEncode(fx.rootADer, "CERTIFICATE");
  var csv = csvOf([CSV_HEADER, ["Test Root A", q("Websites"), "", "", q(pemA)]]);
  var fromCsv = pki.trust.parseCcadbCsv(csv).anchors[0];
  var fromNss = pki.trust.parseCertdata(certdata([certA, trustA])).anchors[0];
  var keys = new Set([
    fromCsv.subjectDer.toString("hex") + "|" + fromCsv.publicKey.toString("hex"),
    fromNss.subjectDer.toString("hex") + "|" + fromNss.publicKey.toString("hex"),
  ]);
  check("T28: the cross-source dedup key is byte-identical", keys.size === 1);
}

// ---------------------------------------------------------------------------
// Lexer fail-closed edges: per-type value grammar, duplicate attrs, unknown
// value types, the block-count ceiling, and the final-block flush at EOF.
// ---------------------------------------------------------------------------

async function testLexerEdges() {
  var fx = await fixtures();

  // A duplicate attribute within one object block.
  check("duplicate attribute in one block -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_TOKEN CK_BBOOL CK_TRUE\nCKA_TOKEN CK_BBOOL CK_FALSE"])); }) === "trust/bad-block");

  // A MULTILINE_OCTAL attribute carrying an unexpected inline value.
  check("MULTILINE_OCTAL with an inline value -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_VALUE MULTILINE_OCTAL \\060"])); }) === "trust/bad-block");

  // CK_BBOOL that is neither CK_TRUE nor CK_FALSE, and one with no value token.
  check("CK_BBOOL with a bogus value -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_TOKEN CK_BBOOL MAYBE"])); }) === "trust/bad-block");
  check("CK_BBOOL with no value token -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_TOKEN CK_BBOOL"])); }) === "trust/bad-block");

  // UTF8 with a present-but-unquoted value, and UTF8 with no value token.
  check("UTF8 with an unquoted value -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_LABEL UTF8 unquoted"])); }) === "trust/bad-block");
  check("UTF8 with no value token -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_LABEL UTF8"])); }) === "trust/bad-block");

  // CK_TRUST with no value token, and CK_TRUST carrying two tokens.
  check("CK_TRUST with no value token -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_TRUST_SERVER_AUTH CK_TRUST"])); }) === "trust/bad-block");
  check("CK_TRUST with two tokens -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_TRUST_SERVER_AUTH CK_TRUST CKT_A CKT_B"])); }) === "trust/bad-block");

  // CK_OBJECT_CLASS / CK_CERTIFICATE_TYPE with no single-token value.
  check("CK_OBJECT_CLASS with no value token -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata(["CKA_CLASS CK_OBJECT_CLASS"])); }) === "trust/bad-block");
  check("CK_CERTIFICATE_TYPE with two tokens -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_CERTIFICATE_TYPE CK_CERTIFICATE_TYPE A B"])); }) === "trust/bad-block");

  // An unrecognized attribute value TYPE cannot be lexed safely -> fail closed.
  check("an unrecognized attribute type -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_FOO BOGUSTYPE bar"])); }) === "trust/bad-block");

  // The block-count DoS ceiling is refused BEFORE lexing the next block.
  var many = "BEGINDATA\n\n" +
    new Array(pki.C.LIMITS.TRUST_MAX_OBJECTS + 1).fill("CKA_TOKEN CK_BBOOL CK_TRUE").join("\n\n") + "\n";
  check("certdata object count over LIMITS.TRUST_MAX_OBJECTS -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(many); }) === "trust/bad-block");

  // A final object block with no trailing blank line / newline is still flushed
  // -- never a silently dropped last root.
  var noTrail = "BEGINDATA\n\n" + certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer });
  var outNoTrail = pki.trust.parseCertdata(noTrail);
  check("a final block with no trailing newline is flushed -> one anchor",
    outNoTrail.anchors.length === 1 && outNoTrail.anchors[0].label === "Test Root A");
}

// ---------------------------------------------------------------------------
// Certificate-object semantics: required attrs, distrust-after typing, serial
// INTEGER shape, subject/label/policy typing, missing/mistyped CKA_CLASS.
// ---------------------------------------------------------------------------

async function testCertSemanticEdges() {
  var fx = await fixtures();

  // A cert object missing its CKA_VALUE MULTILINE_OCTAL attribute.
  check("cert object missing CKA_VALUE -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n" +
      attrOctal("CKA_ISSUER", fx.rootA.issuer.bytes) + "\n" +
      attrOctal("CKA_SERIAL_NUMBER", serialTlv(fx.rootA))])); }) === "trust/bad-block");

  // A cert object whose CKA_ISSUER is present but not MULTILINE_OCTAL.
  check("cert object with a non-octal CKA_ISSUER -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\nCKA_ISSUER UTF8 \"x\"\n" +
      attrOctal("CKA_SERIAL_NUMBER", serialTlv(fx.rootA)) + "\n" +
      attrOctal("CKA_VALUE", fx.rootADer)])); }) === "trust/bad-block");

  // CKA_NSS_SERVER_DISTRUST_AFTER as CK_BBOOL CK_TRUE (only CK_FALSE allowed).
  check("CKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_TRUE -> trust/bad-distrust-after",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }) +
      "\nCKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_TRUE"])); }) === "trust/bad-distrust-after");

  // CKA_NSS_SERVER_DISTRUST_AFTER as a wrong type (neither CK_BBOOL nor octal).
  check("CKA_NSS_SERVER_DISTRUST_AFTER as UTF8 -> trust/bad-distrust-after",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }) +
      "\nCKA_NSS_SERVER_DISTRUST_AFTER UTF8 \"x\""])); }) === "trust/bad-distrust-after");

  // CKA_SERIAL_NUMBER whose bytes are not a DER INTEGER (issuer still agrees).
  check("CKA_SERIAL_NUMBER not a DER INTEGER -> trust/pairing-mismatch",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, serial: b.octetString(Buffer.from([0x2a])) })])); }) === "trust/pairing-mismatch");

  // CKA_SUBJECT present but disagreeing with the certificate's subject DER.
  check("CKA_SUBJECT disagrees with the parsed subject -> trust/pairing-mismatch",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, subject: fx.rootB.subject.bytes })])); }) === "trust/pairing-mismatch");

  // CKA_LABEL present as a non-UTF8 type.
  check("CKA_LABEL as a non-UTF8 type -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE\n" + attrOctal("CKA_LABEL", ascii("x")) + "\n" +
      attrOctal("CKA_ISSUER", fx.rootA.issuer.bytes) + "\n" +
      attrOctal("CKA_SERIAL_NUMBER", serialTlv(fx.rootA)) + "\n" +
      attrOctal("CKA_VALUE", fx.rootADer)])); }) === "trust/bad-block");

  // CKA_NSS_MOZILLA_CA_POLICY present as a non-CK_BBOOL type.
  check("CKA_NSS_MOZILLA_CA_POLICY as a non-CK_BBOOL type -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer }) +
      "\nCKA_NSS_MOZILLA_CA_POLICY UTF8 \"x\""])); }) === "trust/bad-block");

  // An object block with no CKA_CLASS at all.
  check("object block missing CKA_CLASS -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_TOKEN CK_BBOOL CK_TRUE\nCKA_LABEL UTF8 \"x\""])); }) === "trust/bad-block");

  // CKA_CLASS present but not typed CK_OBJECT_CLASS.
  check("CKA_CLASS not typed CK_OBJECT_CLASS -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([
      "CKA_CLASS UTF8 \"CKO_CERTIFICATE\""])); }) === "trust/bad-block");
}

// ---------------------------------------------------------------------------
// Trust-object edges: absent purpose attrs stay untrusted; a purpose attr with
// a non-CK_TRUST type fails closed.
// ---------------------------------------------------------------------------

async function testTrustEntryEdges() {
  var fx = await fixtures();
  var certBlk = certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer });

  // A trust object omitting two of the three purpose attributes: the absent
  // bits stay untrusted (fail-closed), the present delegator grants its purpose.
  var partialTrust = "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\n" +
    attrOctal("CKA_ISSUER", fx.rootA.issuer.bytes) + "\n" +
    attrOctal("CKA_SERIAL_NUMBER", serialTlv(fx.rootA)) + "\n" +
    "CKA_TRUST_EMAIL_PROTECTION CK_TRUST CKT_NSS_TRUSTED_DELEGATOR";
  var aPartial = pki.trust.parseCertdata(certdata([certBlk, partialTrust])).anchors[0];
  check("a trust object missing purpose attrs -> absent bits untrusted, present one granted",
    aPartial.purposes.emailProtection === true &&
    aPartial.purposes.serverAuth === false && aPartial.purposes.codeSigning === false);

  // A purpose attribute present with a non-CK_TRUST type.
  var trustWrongType = "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST\n" +
    attrOctal("CKA_ISSUER", fx.rootA.issuer.bytes) + "\n" +
    attrOctal("CKA_SERIAL_NUMBER", serialTlv(fx.rootA)) + "\n" +
    "CKA_TRUST_SERVER_AUTH CK_BBOOL CK_TRUE";
  check("a purpose attribute typed CK_BBOOL instead of CK_TRUST -> trust/bad-block",
    codeOf(function () { pki.trust.parseCertdata(certdata([certBlk, trustWrongType])); }) === "trust/bad-block");
}

// ---------------------------------------------------------------------------
// Duplicate-identity and dedup conflicts: two cert objects for one identity
// disagreeing on metadata, and two dedup-colliding anchors disagreeing.
// ---------------------------------------------------------------------------

async function testDuplicateAndDedupConflicts() {
  var fx = await fixtures();

  // Two certificate objects sharing one (issuer, serial) but disagreeing on the
  // distrust-after date are an ambiguous/forged identity -> fail closed.
  var certDist = certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, server: "270601235959Z", email: "FALSE" });
  var certNoDist = certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer, server: "FALSE", email: "FALSE" });
  check("two cert objects, same identity, different distrust-after -> trust/pairing-mismatch",
    codeOf(function () { pki.trust.parseCertdata(certdata([certDist, certNoDist])); }) === "trust/pairing-mismatch");

  // Two CCADB rows for the SAME certificate (byte-identical subject + key) that
  // disagree on the purpose bits are ambiguous -> fail closed at dedup.
  var pemA = pki.schema.x509.pemEncode(fx.rootADer, "CERTIFICATE");
  var conflictCsv = csvOf([
    CSV_HEADER,
    ["Test Root A", q("Websites"), "", "", q(pemA)],
    ["Test Root A", q("Email"), "", "", q(pemA)],
  ]);
  check("two CCADB rows for one root disagreeing on trust bits -> trust/pairing-mismatch",
    codeOf(function () { pki.trust.parseCcadbCsv(conflictCsv); }) === "trust/pairing-mismatch");
}

// ---------------------------------------------------------------------------
// CSV lexer bounds + RFC 4180 framing: field / row ceilings, quote placement.
// ---------------------------------------------------------------------------

async function testCsvLexBounds() {
  // A single field over LIMITS.TRUST_MAX_CSV_FIELD_BYTES is refused as it fills.
  var bigField = new Array(pki.C.LIMITS.TRUST_MAX_CSV_FIELD_BYTES + 2).join("a");
  check("a CSV field over LIMITS.TRUST_MAX_CSV_FIELD_BYTES -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(bigField + "\n"); }) === "trust/bad-csv");

  // Row count over LIMITS.TRUST_MAX_CSV_ROWS is refused as the ceiling is hit.
  var manyRows = new Array(pki.C.LIMITS.TRUST_MAX_CSV_ROWS + 2).join("a\n");
  check("CSV row count over LIMITS.TRUST_MAX_CSV_ROWS -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(manyRows); }) === "trust/bad-csv");

  // A quote opening mid-field violates RFC 4180 field framing.
  check("a quote opening mid-field -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv("ab\"cd\r\n"); }) === "trust/bad-csv");

  // Content after a closing quote violates RFC 4180.
  check("content after a closing quote -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv("\"ab\"cd\r\n"); }) === "trust/bad-csv");
}

// ---------------------------------------------------------------------------
// CSV semantics: header row presence, duplicate non-required columns, row-width
// agreement, empty tokens, single-digit + calendar-invalid dates, S/MIME date,
// empty label, single-quote-wrapped and empty PEM cells.
// ---------------------------------------------------------------------------

async function testCsvSemanticEdges() {
  var fx = await fixtures();
  var pemA = pki.schema.x509.pemEncode(fx.rootADer, "CERTIFICATE");

  // An empty CSV (no rows at all) has no header row.
  check("empty CSV input -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(""); }) === "trust/bad-csv");

  // A duplicate NON-required column is tolerated (only required dups fail).
  var dupExtra = csvOf([
    CSV_HEADER.concat(["Extra", "Extra"]),
    ["Test Root A", q("Websites"), "", "", q(pemA), "x", "y"],
  ]);
  check("a duplicate non-required column is tolerated",
    pki.trust.parseCcadbCsv(dupExtra).anchors.length === 1);

  // A data row whose field count disagrees with the header.
  var shortRow = "Common Name or Certificate Name,Trust Bits,Distrust for TLS After Date," +
    "Distrust for S/MIME After Date,PEM Info\r\nA,B,C,D\r\n";
  check("a data row with the wrong field count -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(shortRow); }) === "trust/bad-csv");

  // An empty Trust Bits token (Websites;;Email) is skipped; the real bits stand.
  var emptyTok = pki.trust.parseCcadbCsv(csvOf([CSV_HEADER, ["Test Root A", q("Websites;;Email"), "", "", q(pemA)]])).anchors[0];
  check("an empty Trust Bits token is skipped, real bits granted",
    emptyTok.purposes.serverAuth === true && emptyTok.purposes.emailProtection === true && emptyTok.purposes.codeSigning === false);

  // A single-digit month/day date zero-pads to the same end-of-day instant.
  var singleDigit = pki.trust.parseCcadbCsv(csvOf([CSV_HEADER, ["Test Root A", q("Websites"), "2027.6.1", "", q(pemA)]])).anchors[0];
  check("a single-digit Y-M-D date zero-pads to end-of-day UTC",
    singleDigit.distrustAfter.serverAuth.getTime() === Date.UTC(2027, 5, 1, 23, 59, 59));

  // A syntactically-valid but calendar-invalid date (month 13) fails closed
  // through the strict time reader.
  check("a calendar-invalid distrust date (month 13) -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(csvOf([CSV_HEADER, ["Test Root A", q("Websites"), "2027.13.01", "", q(pemA)]])); }) === "trust/bad-csv");

  // The S/MIME distrust column populates emailProtection independently of TLS.
  var smime = pki.trust.parseCcadbCsv(csvOf([CSV_HEADER, ["Test Root A", q("Email"), "", "2028.01.15", q(pemA)]])).anchors[0];
  check("Distrust for S/MIME After Date -> distrustAfter.emailProtection (TLS absent)",
    smime.distrustAfter.emailProtection instanceof Date &&
    smime.distrustAfter.emailProtection.getTime() === Date.UTC(2028, 0, 15, 23, 59, 59) &&
    !("serverAuth" in smime.distrustAfter));

  // An empty Common Name cell -> label null (never the empty string).
  var emptyName = pki.trust.parseCcadbCsv(csvOf([CSV_HEADER, ["", q("Websites"), "", "", q(pemA)]])).anchors[0];
  check("an empty Common Name cell -> label null", emptyName.label === null);

  // A PEM Info cell wrapped in one layer of single quotes is unwrapped.
  var quotedPem = pki.trust.parseCcadbCsv(csvOf([CSV_HEADER, ["Test Root A", q("Websites"), "", "", q("'" + pemA + "'")]])).anchors[0];
  check("a single-quote-wrapped PEM Info cell parses to the certificate",
    quotedPem.publicKey.equals(fx.rootA.subjectPublicKeyInfo.bytes));

  // An empty PEM Info cell fails closed.
  check("an empty PEM Info cell -> trust/bad-csv",
    codeOf(function () { pki.trust.parseCcadbCsv(csvOf([CSV_HEADER, ["Test Root A", q("Websites"), "", "", ""]])); }) === "trust/bad-csv");
}

// ---------------------------------------------------------------------------
// anchor() defensive defaults: no-opts call, and a minimally-shaped entry that
// omits parameters / distrustAfter / purposes (fail-closed fill-ins).
// ---------------------------------------------------------------------------

async function testAnchorDefensiveDefaults() {
  var fx = await fixtures();
  var entry = pki.trust.parseCertdata(certdata([
    certBlock({ label: "Test Root A", cert: fx.rootA, der: fx.rootADer })])).anchors[0];

  // anchor(entry) with no opts argument returns the validate hand-off shape.
  var a = pki.trust.anchor(entry);
  check("anchor(entry) with no opts returns the validate hand-off shape",
    a.name === entry.name && a.publicKey.equals(entry.publicKey) && a.algorithm === entry.algorithm);

  // A minimally-shaped entry (no parameters / distrustAfter / purposes) fills
  // the fail-closed defaults: parameters null, distrustAfter {}, purposes all false.
  var minimal = { name: entry.name, publicKey: entry.publicKey, algorithm: entry.algorithm };
  var am = pki.trust.anchor(minimal);
  check("anchor() defaults a missing parameters to null", am.parameters === null);
  check("anchor() defaults a missing distrustAfter to {}",
    am.distrustAfter && typeof am.distrustAfter === "object" && Object.keys(am.distrustAfter).length === 0);
  check("anchor() defaults missing purposes to all-false",
    am.purposes.serverAuth === false && am.purposes.emailProtection === false && am.purposes.codeSigning === false);
}

// ---------------------------------------------------------------------------

async function run() {
  await testCertdataPairing();
  await testOctalDecode();
  await testDistrustAfter();
  await testTrustBits();
  await testBlockDelimiting();
  await testCsvHeaderKeyed();
  await testCsvSameShape();
  await testCsvQuoting();
  await testRealCertdataSlice();
  await testDedup();
  await testLexerEdges();
  await testCertSemanticEdges();
  await testTrustEntryEdges();
  await testDuplicateAndDedupConflicts();
  await testCsvLexBounds();
  await testCsvSemanticEdges();
  await testAnchorDefensiveDefaults();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
