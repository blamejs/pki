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
  var m = parse(csr({ cri: { subject: b.sequence([]), attrNode: attrs([]) } }));
  check("minimal CSR: version 1", m.version === 1);
  check("minimal CSR: empty subject accepted", Array.isArray(m.subject.rdns) && m.subject.rdns.length === 0 && m.subject.dn === "");
  check("minimal CSR: empty attributes", Array.isArray(m.attributes) && m.attributes.length === 0);
  check("minimal CSR: subjectPublicKeyInfo", m.subjectPublicKeyInfo.algorithm.oid === "1.2.840.10045.2.1" && m.subjectPublicKeyInfo.publicKey.bytes.length > 0);
  check("minimal CSR: signatureAlgorithm named", m.signatureAlgorithm.oid === SIGALG);
  check("minimal CSR: certificationRequestInfoBytes is a non-empty Buffer", Buffer.isBuffer(m.certificationRequestInfoBytes) && m.certificationRequestInfoBytes.length > 0);

  var full = parse(csr({ cri: { subject: name("req.example"), attrNode: attrs([attribute(CHALLENGE, [b.printable("secret")])]) } }));
  check("CSR subject dn", full.subject.dn === "CN=req.example");
  check("CSR one attribute, stable dotted type", full.attributes.length === 1 && full.attributes[0].type === CHALLENGE && full.attributes[0].values.length === 1);
  check("CSR attribute value kept as raw DER", Buffer.isBuffer(full.attributes[0].values[0]));
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
  testMultiDefectFailClosed();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
