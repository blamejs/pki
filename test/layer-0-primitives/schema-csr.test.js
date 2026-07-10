// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema.csr (PKCS#10 CertificationRequest parser, RFC 2986).
 * Spec-first conformance vectors: valid CSRs parse to the documented shape;
 * every malformed CertificationRequest / CertificationRequestInfo is rejected
 * fail-closed with a typed csr/* (or leaf-level asn1/*) error. Composes the
 * shared parse-entry + PKIX sub-schemas. The cert/CRL sig-alg agreement,
 * non-empty-subject, and OID-uniqueness guards MUST NOT appear here.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

var SIGALG = "1.2.840.10045.4.3.2"; // ecdsa-with-SHA256
var CHALLENGE = "1.2.840.113549.1.9.7"; // challengePassword

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }
function parseCode(der) { return code(function () { pki.schema.csr.parse(der); }); }
function parse(der) { return pki.schema.csr.parse(der); }

function algId(o) { return b.sequence([b.oid(o)]); }
function name(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
function spki() { return b.sequence([b.sequence([b.oid("1.2.840.10045.2.1"), b.oid("1.2.840.10045.3.1.7")]), b.bitString(Buffer.from([0x04, 0x01, 0x02, 0x03]), 0)]); }
function attribute(t, vals) { return b.sequence([b.oid(t), b.set(vals)]); }
function attrs(list) { return b.contextConstructed(0, list.length ? Buffer.concat(list) : Buffer.alloc(0)); }
// A raw universal SET (tag 0x31) over the given element TLVs in the ORDER GIVEN —
// unlike b.set it does NOT sort, so it can encode a non-canonical (unsorted) SET
// for the DER §11.6 ordering vectors. Short-form length only (body < 128 bytes).
function rawSetOf(children) {
  var body = Buffer.concat(children);
  return Buffer.concat([Buffer.from([0x31, body.length]), body]);
}
function cri(o) {
  o = o || {};
  var c = [];
  c.push(o.version !== undefined ? o.version : b.integer(0n));
  c.push(o.subject || name("req.example"));
  c.push(o.spki || spki());
  if (o.attrNode !== null) c.push(o.attrNode || attrs([]));
  return b.sequence(c);
}
function csr(o) {
  o = o || {};
  var criNode = o.criNode || cri(o.cri || {});
  if (o.outerChildren) return b.sequence(o.outerChildren);
  return b.sequence([criNode, o.sigAlg || algId(SIGALG), o.sigVal || b.bitString(Buffer.from([0x00]), 0)]);
}

function testValid() {
  var minimalDer = csr({ cri: { subject: b.sequence([]), attrNode: attrs([]) } });
  var m = parse(minimalDer);
  check("minimal CSR: version 1", m.version === 1);
  check("minimal CSR: empty subject accepted", Array.isArray(m.subject.rdns) && m.subject.rdns.length === 0 && m.subject.dn === "");
  check("minimal CSR: empty attributes", Array.isArray(m.attributes) && m.attributes.length === 0);
  check("minimal CSR: subjectPublicKeyInfo", m.subjectPublicKeyInfo.algorithm.oid === "1.2.840.10045.2.1" && m.subjectPublicKeyInfo.publicKey.bytes.length > 0);
  check("minimal CSR: signatureAlgorithm named", m.signatureAlgorithm.oid === SIGALG);
  check("minimal CSR: certificationRequestInfoBytes is a non-empty Buffer", Buffer.isBuffer(m.certificationRequestInfoBytes) && m.certificationRequestInfoBytes.length > 0);
  // certificationRequestInfoBytes is the exact proof-of-possession region an
  // external verifier hashes — it must be the CRI TLV byte-for-byte off the
  // wire, never re-serialized.
  check("minimal CSR: certificationRequestInfoBytes byte-identical to the CRI TLV on the wire",
    m.certificationRequestInfoBytes.equals(pki.asn1.decode(minimalDer).children[0].bytes));

  var full = parse(csr({ cri: { subject: name("req.example"), attrNode: attrs([attribute(CHALLENGE, [b.printable("secret")])]) } }));
  check("CSR subject dn", full.subject.dn === "CN=req.example");
  check("CSR one attribute, stable dotted type", full.attributes.length === 1 && full.attributes[0].type === CHALLENGE && full.attributes[0].values.length === 1);
  check("CSR attribute value kept as raw DER", Buffer.isBuffer(full.attributes[0].values[0]));

  // The pem surfaces: pemEncode emits armor that pemDecode returns to
  // byte-identical DER, with the requested label enforced.
  var csrPem = pki.schema.csr.pemEncode(minimalDer, "CERTIFICATE REQUEST");
  check("csr.pemEncode/pemDecode round-trips to identical DER",
    pki.schema.csr.pemDecode(csrPem, "CERTIFICATE REQUEST").equals(minimalDer));
}

// Anti-regression: guards that MUST NOT be copied from the cert/CRL parsers.
function testDoNotCopyGuards() {
  check("no sig-alg agreement — differing outer sig-alg parses",
    parseCode(csr({ cri: { spki: b.sequence([b.sequence([b.oid("1.2.840.113549.1.1.1")]), b.bitString(Buffer.from([0x04, 1, 2, 3]), 0)]) }, sigAlg: algId(SIGALG) })) === "NO-THROW");
  check("empty subject stays valid (no non-empty-DN guard)", parseCode(csr({ cri: { subject: b.sequence([]) } })) === "NO-THROW");
  check("duplicate attribute type OIDs + repeated RDN types accepted (no SET-OF uniqueness)",
    parseCode(csr({ cri: {
      subject: b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("a")]), b.sequence([b.oid("2.5.4.3"), b.utf8("b")])])]),
      attrNode: attrs([attribute(CHALLENGE, [b.printable("x")]), attribute(CHALLENGE, [b.printable("y")])]) } })) === "NO-THROW");
}

function testVersion() {
  check("version 1 rejected (PKCS#10 requires v1=0)", parseCode(csr({ cri: { version: b.integer(1n) } })) === "csr/bad-version");
  check("version 2 rejected", parseCode(csr({ cri: { version: b.integer(2n) } })) === "csr/bad-version");
  check("version -1 rejected", parseCode(csr({ cri: { version: b.integer(-1n) } })) === "csr/bad-version");
  var c = parseCode(csr({ cri: { version: b.explicit(0, b.integer(0n)) } }));
  check("cert-shaped [0] EXPLICIT version fails closed (CSR version is a bare INTEGER)", c !== "NO-THROW" && (c.indexOf("csr/") === 0 || c.indexOf("asn1/") === 0));
  // ENUMERATED shares INTEGER's content encoding; a version encoded as
  // ENUMERATED(0) must NOT be coerced to v1 (type confusion, fail-open).
  var ce = parseCode(csr({ cri: { version: b.enumerated(0n) } }));
  check("ENUMERATED-tagged version rejected (version is a strict INTEGER)", ce !== "NO-THROW" && (ce.indexOf("csr/") === 0 || ce.indexOf("asn1/") === 0));
}

function testOuterAndCri() {
  check("outer not a SEQUENCE rejected", parseCode(b.set([algId(SIGALG)])) === "csr/not-a-certification-request");
  check("outer with 2 elements rejected", parseCode(csr({ outerChildren: [cri({}), algId(SIGALG)] })) === "csr/not-a-certification-request");
  check("outer with 4 elements rejected", parseCode(csr({ outerChildren: [cri({}), algId(SIGALG), b.bitString(Buffer.from([0]), 0), b.integer(1n)] })) === "csr/not-a-certification-request");
  check("trailing byte after outer SEQUENCE rejected", parseCode(Buffer.concat([csr({}), Buffer.from([0x00])])) === "csr/bad-der");
  check("CRI not a SEQUENCE (a SET) rejected", parseCode(csr({ criNode: b.set([b.integer(0n), name("x"), spki(), attrs([])]) })) === "csr/bad-cri");
  check("CRI missing the required attributes [0] rejected", parseCode(csr({ cri: { attrNode: null } })) === "csr/bad-cri");
  check("subjectPKInfo malformed rejected", parseCode(csr({ cri: { spki: b.sequence([b.sequence([b.oid("1.2.840.10045.2.1")])]) } })) === "csr/bad-spki");
  // SubjectPublicKeyInfo MUST be a universal SEQUENCE — a [0]-tagged constructed
  // node carrying the right children is NOT a SEQUENCE and must be rejected (no
  // constructed-any leniency).
  var spkiCtx = b.contextConstructed(0, Buffer.concat([b.sequence([b.oid("1.2.840.10045.2.1"), b.oid("1.2.840.10045.3.1.7")]), b.bitString(Buffer.from([0x04, 1, 2, 3]), 0)]));
  check("subjectPKInfo as [0]-constructed (non-SEQUENCE) rejected", parseCode(csr({ cri: { spki: spkiCtx } })) === "csr/bad-spki");
  // DER §11.6 — the RDN SET and the attributes SET OF must be in ascending encoded
  // order. An unsorted encoding is non-canonical, rejected fail-closed.
  var rdnUnsorted = b.sequence([rawSetOf([b.sequence([b.oid("2.5.4.3"), b.utf8("b")]), b.sequence([b.oid("2.5.4.3"), b.utf8("a")])])]);
  check("unsorted RDN SET rejected (DER ascending order)", parseCode(csr({ cri: { subject: rdnUnsorted } })) === "csr/bad-rdn");
  var attrsUnsorted = attrs([attribute(CHALLENGE, [b.printable("y")]), attribute(CHALLENGE, [b.printable("x")])]);
  check("unsorted [0] SET OF attributes rejected (DER ascending order)", parseCode(csr({ cri: { attrNode: attrsUnsorted } })) === "csr/bad-attributes");
  var valuesUnsorted = attrs([b.sequence([b.oid(CHALLENGE), rawSetOf([b.printable("b"), b.printable("a")])])]);
  check("unsorted Attribute values SET rejected (DER ascending order)", parseCode(csr({ cri: { attrNode: valuesUnsorted } })) === "csr/bad-attribute-values");
}

function testAttributes() {
  check("attributes not [0]-tagged (a universal SET) rejected", parseCode(csr({ cri: { attrNode: b.set([attribute(CHALLENGE, [b.printable("x")])]) } })) === "csr/bad-attributes");
  check("attributes wrong context tag [1] rejected", parseCode(csr({ cri: { attrNode: b.contextConstructed(1, Buffer.alloc(0)) } })) === "csr/bad-attributes");
  check("attributes primitive [0] rejected (must be constructed)", parseCode(csr({ cri: { attrNode: b.contextPrimitive(0, Buffer.from([1, 2, 3])) } })) === "csr/bad-attributes");
  check("Attribute element not a SEQUENCE rejected", parseCode(csr({ cri: { attrNode: attrs([b.integer(1n)]) } })) === "csr/bad-attribute");
  check("Attribute missing the values SET rejected", parseCode(csr({ cri: { attrNode: attrs([b.sequence([b.oid(CHALLENGE)])]) } })) === "csr/bad-attribute");
  check("Attribute values not a SET rejected", parseCode(csr({ cri: { attrNode: attrs([b.sequence([b.oid(CHALLENGE), b.printable("secret")])]) } })) === "csr/bad-attribute-values");
  check("Attribute empty values SET rejected (SET SIZE 1..MAX)", parseCode(csr({ cri: { attrNode: attrs([b.sequence([b.oid(CHALLENGE), b.set([])])]) } })) === "csr/bad-attribute-values");
}

// PKCS#9 recognized-attribute value syntax (RFC 2985 §5.4.1 / §5.4.2):
// extensionRequest and challengePassword are SINGLE VALUE TRUE with a fixed
// WITH SYNTAX — one Extensions value / one DirectoryString (1..255 chars). A
// recognized type carrying a malformed value fails closed with
// csr/bad-attribute-value; an UNRECOGNIZED type stays opaque raw DER; and
// duplicate attribute TYPES stay legal (no SET-OF uniqueness — see
// testDoNotCopyGuards).
var EXTREQ = "1.2.840.113549.1.9.14"; // extensionRequest
function extNode(o, v) { return b.sequence([b.oid(o), b.octetString(v)]); }
function testRecognizedAttributeValues() {
  var ext1 = extNode("2.5.29.14", Buffer.from([0x04, 0x01, 0xaa]));
  var ext2 = extNode("2.5.29.15", Buffer.from([0x03, 0x02, 0x05, 0xa0]));
  function attrsCsr(list) { return csr({ cri: { attrNode: attrs(list) } }); }

  check("extensionRequest with one Extensions value parses",
    parseCode(attrsCsr([attribute(EXTREQ, [b.sequence([ext1])])])) === "NO-THROW");
  check("extensionRequest with a non-Extensions value (INTEGER) rejected",
    parseCode(attrsCsr([attribute(EXTREQ, [b.integer(42n)])])) === "csr/bad-attribute-value");
  check("extensionRequest with an empty Extensions SEQUENCE rejected (SIZE 1..MAX)",
    parseCode(attrsCsr([attribute(EXTREQ, [b.sequence([])])])) === "csr/bad-attribute-value");
  check("extensionRequest with two values rejected (SINGLE VALUE TRUE)",
    parseCode(attrsCsr([attribute(EXTREQ, [b.sequence([ext1]), b.sequence([ext2])])])) === "csr/bad-attribute-value");
  check("extensionRequest carrying a duplicate extension OID rejected",
    parseCode(attrsCsr([attribute(EXTREQ, [b.sequence([ext1, extNode("2.5.29.14", Buffer.from([0x04, 0x01, 0xbb]))])])])) === "csr/bad-attribute-value");
  check("two separate extensionRequest attributes still parse (no SET-OF uniqueness)",
    parseCode(attrsCsr([attribute(EXTREQ, [b.sequence([ext1])]), attribute(EXTREQ, [b.sequence([ext2])])])) === "NO-THROW");

  check("challengePassword as PrintableString parses",
    parseCode(attrsCsr([attribute(CHALLENGE, [b.printable("secret")])])) === "NO-THROW");
  check("challengePassword as UTF8String parses",
    parseCode(attrsCsr([attribute(CHALLENGE, [b.utf8("secret")])])) === "NO-THROW");
  check("challengePassword as INTEGER rejected (DirectoryString required)",
    parseCode(attrsCsr([attribute(CHALLENGE, [b.integer(1n)])])) === "csr/bad-attribute-value");
  check("challengePassword as IA5String rejected (not a DirectoryString alternative)",
    parseCode(attrsCsr([attribute(CHALLENGE, [b.ia5("pw")])])) === "csr/bad-attribute-value");
  check("empty challengePassword rejected (SIZE 1..255)",
    parseCode(attrsCsr([attribute(CHALLENGE, [b.utf8("")])])) === "csr/bad-attribute-value");
  check("challengePassword with two values rejected (SINGLE VALUE TRUE)",
    parseCode(attrsCsr([attribute(CHALLENGE, [b.printable("a"), b.printable("b")])])) === "csr/bad-attribute-value");

  check("unrecognized attribute type stays opaque raw DER (INTEGER value parses)",
    parseCode(attrsCsr([attribute("1.2.840.113549.1.9.99", [b.integer(7n)])])) === "NO-THROW");
}

function testMultiDefectFailClosed() {
  var c = parseCode(csr({ cri: { version: b.integer(9n), subject: b.set([]), attrNode: attrs([b.integer(1n)]) } }));
  check("multi-defect CSR stays fail-closed (typed rejection, no raw crash)", c !== "NO-THROW" && c.indexOf("RAW:") !== 0);
}

function run() {
  testValid();
  testDoNotCopyGuards();
  testVersion();
  testOuterAndCri();
  testAttributes();
  testRecognizedAttributeValues();
  testMultiDefectFailClosed();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
