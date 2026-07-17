// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for pki.csr.sign -- the PKCS#10 certification-request producing side
// (RFC 2986 / RFC 2985). Every vector drives the shipped consumer pki.csr.sign(spec, key, opts) and
// asserts through pki.schema.csr.parse or err.code. Keys from the makeSigner / makeCompositeSigner
// helpers. A CSR is self-signed by the SUBJECT's own key (proof of possession) -- no issuer.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;
var asn1 = pki.asn1;

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}

// ---- round-trip + byte-stability -------------------------------------------

async function testRoundTrip() {
  var s = makeSigner("ec-p256");
  var der = await pki.csr.sign({ subject: "req.example", subjectPublicKey: s.spki }, { key: s.key });
  check("sign returns a Buffer", Buffer.isBuffer(der));
  var c = pki.schema.csr.parse(der);
  check("round-trip subject CN", /req.example/.test(c.subject.dn));
  check("round-trip SPKI bytes", Buffer.compare(c.subjectPublicKeyInfo.bytes, s.spki) === 0);
  check("round-trip version v1", c.version === 1);
  check("round-trip has zero attributes", c.attributes.length === 0);

  // the signed region (certificationRequestInfoBytes) is embedded verbatim, byte-identical on re-parse.
  var reparsed = pki.schema.csr.parse(der);
  check("CRI bytes byte-stable across re-parse", Buffer.compare(c.certificationRequestInfoBytes, reparsed.certificationRequestInfoBytes) === 0);
}

async function testPemOutput() {
  var s = makeSigner("ed25519");
  var pem = await pki.csr.sign({ subject: "PEM", subjectPublicKey: s.spki }, { key: s.key }, { pem: true });
  check("opts.pem returns a string", typeof pem === "string");
  check("opts.pem has BEGIN CERTIFICATE REQUEST", /-----BEGIN CERTIFICATE REQUEST-----/.test(pem));
  check("PEM decodes to a parseable CSR", pki.schema.csr.parse(pki.schema.csr.pemDecode(pem)).subject.dn.length > 0);
}

// ---- version == 0 bare INTEGER (not the cert [0] EXPLICIT) ------------------

async function testVersionBareInteger() {
  var s = makeSigner("ed25519");
  var der = await pki.csr.sign({ subject: "v", subjectPublicKey: s.spki }, { key: s.key });
  var cri = asn1.decode(der).children[0];
  var v = cri.children[0];   // CRI: version, subject, spki, attributes
  check("CRI version is a universal INTEGER (not context [0])", v.tagClass === "universal" && v.tagNumber === 2);
  check("CRI version value is 0", asn1.read.integer(v) === 0n);
}

// ---- every algorithm arm ---------------------------------------------------

async function testAlgorithmArms() {
  var arms = ["rsa", "rsa-pss", "ec-p256", "ec-p384", "ec-p521", "ed25519", "ed448",
    "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-shake-256s"];
  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = makeSigner(alg);
    var opts = alg === "rsa-pss" ? { pss: true } : {};
    var der = await pki.csr.sign({ subject: alg, subjectPublicKey: s.spki }, { key: s.key }, opts);
    var c = pki.schema.csr.parse(der);
    check(alg + " CSR parses + carries a signature algorithm", !!c.signatureAlgorithm.name && Buffer.compare(c.subjectPublicKeyInfo.bytes, s.spki) === 0);
  }
}

async function testCompositeArm() {
  var arm = "id-MLDSA65-ECDSA-P256-SHA512";
  var cs;
  try { cs = makeCompositeSigner(arm); }
  catch { check("composite arm " + arm + " available", false); return; }
  var der = await pki.csr.sign({ subject: "composite req", subjectPublicKey: cs.spki }, { key: cs.key });
  check("composite CSR parses", pki.schema.csr.parse(der).subject.dn.length > 0);
}

// ---- empty subject + empty attributes --------------------------------------

async function testEmptySubjectAndAttrs() {
  var s = makeSigner("ed25519");
  // empty subject is allowed for a CSR (no SAN requirement, unlike an empty-subject certificate).
  var der = await pki.csr.sign({ subject: [], subjectPublicKey: s.spki }, { key: s.key });
  var c = pki.schema.csr.parse(der);
  check("empty subject accepted", c.subject.dn === "");
  // the CRI's 4th child is the [0] IMPLICIT SET OF attributes, emitted even when empty (A0 00).
  var attrs = asn1.decode(der).children[0].children[3];
  check("attributes is context [0] constructed", attrs.tagClass === "context" && attrs.tagNumber === 0);
  check("empty attributes -> zero members in [0]", (attrs.children || []).length === 0 && attrs.length === 0);   // A0 00
  // subject omitted entirely behaves the same.
  check("subject omitted -> empty subject", pki.schema.csr.parse(await pki.csr.sign({ subjectPublicKey: s.spki }, { key: s.key })).subject.dn === "");
}

// ---- extensionRequest carrying a SAN + a CA copying it ---------------------

async function testExtensionRequest() {
  var s = makeSigner("ec-p256");
  var der = await pki.csr.sign({
    subject: "leaf.example", subjectPublicKey: s.spki,
    extensionRequest: { subjectAltName: [{ dNSName: "leaf.example" }], keyUsage: ["digitalSignature"] },
  }, { key: s.key });
  var c = pki.schema.csr.parse(der);
  check("extensionRequest attribute present", c.attributes.length === 1);
  var er = c.attributes[0];
  check("extensionRequest decodes its extensions", Array.isArray(er.extensions) && er.extensions.some(function (e) { return (e.name || e.oid) === "subjectAltName"; }));

  // end-to-end: a CA copies the requested SAN into an issued cert via the pre-encoded array form.
  var sanExt = er.extensions.filter(function (e) { return (e.name || e.oid) === "subjectAltName"; })[0];
  var ca = makeSigner("ec-p256");
  var caCert = pki.schema.x509.parse(await pki.x509.sign({
    subject: "Issuing CA", subjectPublicKey: ca.spki, notBefore: new Date("2026-01-01Z"), notAfter: new Date("2030-01-01Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: ca.key }));
  // rebuild the SAN extension DER (oid + extnValue) for the array form.
  var B = pki.asn1.build;
  var sanDer = B.sequence([B.oid(pki.oid.byName("subjectAltName")), B.octetString(sanExt.value)]);
  var leaf = pki.schema.x509.parse(await pki.x509.sign({
    subject: "leaf.example", subjectPublicKey: s.spki, notBefore: new Date("2026-01-01Z"), notAfter: new Date("2030-01-01Z"),
    extensions: [sanDer],
  }, { cert: caCert, key: ca.key }));
  var res = await pki.path.validate([leaf], { time: new Date("2027-06-01Z"), trustAnchor: { name: caCert.subject, publicKey: caCert.subjectPublicKeyInfo.bytes, algorithm: caCert.subjectPublicKeyInfo.algorithm.oid } });
  check("a CA copies the requested SAN into a valid issued cert", res.valid === true && leaf.extensions.some(function (e) { return (e.name || e.oid) === "subjectAltName"; }));
}

// ---- challengePassword -----------------------------------------------------

async function testChallengePassword() {
  var s = makeSigner("ed25519");
  var der = await pki.csr.sign({ subject: "cp", subjectPublicKey: s.spki, challengePassword: "secret" }, { key: s.key });
  var c = pki.schema.csr.parse(der);
  check("challengePassword attribute present", c.attributes.some(function (a) { return (a.name || a.type) === "challengePassword"; }));
  // boundary: >255 chars -> config-time reject; empty -> reject.
  check("256-char challengePassword -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, challengePassword: "a".repeat(256) }, { key: s.key })) === "csr/bad-input");
  check("empty challengePassword -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, challengePassword: "" }, { key: s.key })) === "csr/bad-input");
}

// ---- proof of possession: wrong key fails the post-sign verify -------------

async function testProofOfPossession() {
  var a = makeSigner("ec-p256"), b2 = makeSigner("ec-p256");
  check("wrong signing key (subject SPKI != key) -> csr/bad-input",
    await codeOf(pki.csr.sign({ subject: "pop", subjectPublicKey: a.spki }, { key: b2.key })) === "csr/bad-input");
  var cs, cs2;
  try { cs = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512"); cs2 = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512"); }
  catch { check("composite POP arm available", false); return; }
  check("mismatched composite key -> csr/bad-input",
    await codeOf(pki.csr.sign({ subject: "pop", subjectPublicKey: cs.spki }, { key: cs2.key })) === "csr/bad-input");
}

// ---- fail-closed on malformed inputs ---------------------------------------

async function testFailClosed() {
  var s = makeSigner("ed25519");
  var B = pki.asn1.build;
  check("unknown DN attribute -> csr/bad-name", await codeOf(pki.csr.sign({ subject: [{ notAnAttr: "x" }], subjectPublicKey: s.spki }, { key: s.key })) === "csr/bad-name");
  check("countryName not 2 chars -> csr/bad-name", await codeOf(pki.csr.sign({ subject: [{ countryName: "USA" }], subjectPublicKey: s.spki }, { key: s.key })) === "csr/bad-name");
  check("non-DER raw Name -> csr/bad-name", await codeOf(pki.csr.sign({ subject: Buffer.from([1, 2, 3]), subjectPublicKey: s.spki }, { key: s.key })) === "csr/bad-name");
  check("garbage subjectPublicKey -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: B.sequence([B.integer(1n), B.integer(2n)]) }, { key: s.key })) !== null);
  check("non-Buffer subjectPublicKey -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: 5 }, { key: s.key })) === "csr/bad-input");
  check("missing signing key -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki }, {})) === "csr/bad-input");
  check("empty SAN in extensionRequest -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, extensionRequest: { subjectAltName: [] } }, { key: s.key })) === "csr/bad-input");
  check("unknown extensionRequest key -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, extensionRequest: { notAnExt: 1 } }, { key: s.key })) === "csr/bad-input");
  check("unknown extendedKeyUsage purpose -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, extensionRequest: { extendedKeyUsage: ["notAPurpose"] } }, { key: s.key })) === "csr/bad-input");
  check("unknown certificate policy -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, extensionRequest: { certificatePolicies: ["notAPolicy"] } }, { key: s.key })) === "csr/bad-input");
  check("unknown top-level spec key -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, subjcet: "typo" }, { key: s.key })) === "csr/bad-input");
  // a pre-encoded extensionRequest extension is validated in shape AND value.
  var kuExt = B.sequence([B.oid(pki.oid.byName("keyUsage")), B.octetString(B.namedBitString([0]))]);
  check("duplicate extension in extensionRequest array -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, extensionRequest: [kuExt, kuExt] }, { key: s.key })) === "csr/bad-input");
  var critFalse = B.sequence([B.oid(pki.oid.byName("keyUsage")), B.boolean(false), B.octetString(B.namedBitString([0]))]);
  check("pre-encoded extension with explicit critical=FALSE -> csr/bad-input", await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, extensionRequest: [critFalse] }, { key: s.key })) === "csr/bad-input");
  var malformedBc = B.sequence([B.oid(pki.oid.byName("basicConstraints")), B.octetString(Buffer.from([0x30, 0x05]))]);   // truncated value
  check("malformed pre-encoded extension value -> typed csr/*", /^csr\//.test(await codeOf(pki.csr.sign({ subject: "x", subjectPublicKey: s.spki, extensionRequest: [malformedBc] }, { key: s.key })) || ""));
}

async function main() {
  await testRoundTrip();
  await testPemOutput();
  await testVersionBareInteger();
  await testAlgorithmArms();
  await testCompositeArm();
  await testEmptySubjectAndAttrs();
  await testExtensionRequest();
  await testChallengePassword();
  await testProofOfPossession();
  await testFailClosed();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
