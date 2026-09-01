// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for pki.csr.verify -- the PKCS#10 proof-of-possession verifier (RFC 2986
// sec. 4.2). Every vector drives the shipped consumer pki.csr.verify(csr) and asserts the boolean
// verdict or err.code. A certification request carries no issuer: the verifying key is the
// subjectPKInfo inside the request, so a `true` says the producer held the private half of the key
// it is asking to have certified, and nothing about who they are.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var surgery = require("../helpers/der-surgery");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;
var asn1 = pki.asn1;

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}

// The verb answers with a verdict object carrying the fields it verified. Most vectors below are
// about the flag, so they drive the shipped verb through this and read `verified`; the object's
// own shape, and the fields it re-derives, have their own vectors.
function csrVerified(request) {
  return pki.csr.verify(request).then(function (r) { return r.verified; });
}

// ---- accept: a well-formed request verifies under its own subject key ------

async function testAcceptsEveryAlgorithmArm() {
  var arms = ["rsa", "rsa-pss", "ec-p256", "ec-p384", "ec-p521", "ed25519", "ed448", "ml-dsa-44", "slh-dsa-sha2-128s"];
  for (var i = 0; i < arms.length; i++) {
    var s = makeSigner(arms[i]);
    var der = await pki.csr.sign({ subject: "arm.example", subjectPublicKey: s.spki }, { key: s.key });
    check("verify accepts a " + arms[i] + " request", (await csrVerified(der)) === true);
  }
}

async function testAcceptsCompositeArm() {
  var arm = "id-MLDSA65-ECDSA-P256-SHA512";
  var s;
  try { s = makeCompositeSigner(arm); }
  catch { check("composite arm " + arm + " available", false); return; }
  var der = await pki.csr.sign({ subject: "composite.example", subjectPublicKey: s.spki }, { key: s.key });
  check("verify accepts a composite request", (await csrVerified(der)) === true);
}

async function testAcceptsPemAndParsed() {
  var s = makeSigner("ed25519");
  var pem = await pki.csr.sign({ subject: "pem.example", subjectPublicKey: s.spki }, { key: s.key }, { pem: true });
  check("verify accepts a PEM request", (await csrVerified(pem)) === true);
  var der = pki.schema.csr.pemDecode(pem);
  check("verify accepts a DER Buffer", (await csrVerified(der)) === true);
  check("verify accepts a parsed request", (await csrVerified(pki.schema.csr.parse(der))) === true);
}

// ---- refuse: the signature does not verify under the subject key ----------

// The load-bearing vector. A request whose subjectPKInfo is swapped for a DIFFERENT key of the same
// algorithm keeps every structural property -- it parses, its algorithm resolves, its signature is
// well-formed -- and the only thing that fails is the proof of possession itself.
async function testKeySubstitutionIsRefused() {
  var mine = makeSigner("ec-p256");
  var theirs = makeSigner("ec-p256");
  var der = await pki.csr.sign({ subject: "swap.example", subjectPublicKey: mine.spki }, { key: mine.key });
  check("the honest request verifies", (await csrVerified(der)) === true);

  var swap = surgery.replaceTlv(der, mine.spki, theirs.spki);
  check("the key substitution matched exactly one node", swap.count === 1);
  check("the swapped request still parses", !!pki.schema.csr.parse(swap.der));
  check("a request signed by a key other than its subjectPKInfo is refused",
    (await csrVerified(swap.der)) === false);
}

// A single flipped bit in the signature value.
async function testCorruptSignatureIsRefused() {
  var s = makeSigner("ed25519");
  var der = await pki.csr.sign({ subject: "bitflip.example", subjectPublicKey: s.spki }, { key: s.key });
  var parsed = pki.schema.csr.parse(der);
  var bad = Buffer.from(parsed.signatureValue.bytes);
  bad[bad.length - 1] ^= 0x01;
  // The whole BIT STRING TLV, since signatureValue.bytes is its payload without the unused-bits octet.
  var forged = surgery.replaceTlv(der, asn1.build.bitString(parsed.signatureValue.bytes, 0),
    asn1.build.bitString(bad, 0));
  check("the signature substitution matched exactly one node", forged.count === 1);
  check("a flipped signature bit is refused", (await csrVerified(forged.der)) === false);
}

// The subject named in the request is inside the signed CertificationRequestInfo, so changing it
// after signing must break the signature. A verifier reading the subject from anywhere other than
// the verified preimage would miss this.
async function testSubjectTamperIsRefused() {
  var s = makeSigner("ec-p256");
  var der = await pki.csr.sign({ subject: "honest.example", subjectPublicKey: s.spki }, { key: s.key });
  var b = asn1.build;
  var honest = b.utf8("honest.example");
  var forgedName = b.utf8("attacker.examp");   // same length, so no length field shifts
  var forged = surgery.replaceTlv(der, honest, forgedName);
  check("the subject substitution matched exactly one node", forged.count === 1);
  check("the tampered request still parses", !!pki.schema.csr.parse(forged.der));
  check("a subject changed after signing is refused", (await csrVerified(forged.der)) === false);
}

// ---- a rebuilt parse result is not a request ------------------------------

// The verdict re-derives from the recorded certificationRequestInfo bytes, and a CA acts on the
// fields beside them. Rebuilding the parse result separates the two: verify answers about the
// bytes it kept while the CA issues from a subject nobody signed. Proven by removing the door,
// where this same input verifies as `true` against a subject reading CN=attacker.
async function testRebuiltParseResultIsRefused() {
  var s = makeSigner("ed25519");
  var der = await pki.csr.sign({ subject: "honest.example", subjectPublicKey: s.spki }, { key: s.key });
  var parsed = pki.schema.csr.parse(der);
  check("the parser's own result verifies", (await csrVerified(parsed)) === true);

  var rebuilt = Object.assign({}, parsed);
  rebuilt.subject = { dn: "CN=attacker", rdns: [] };
  check("a rebuilt request with a swapped subject is refused",
    (await codeOf(pki.csr.verify(rebuilt))) === "csr/bad-input");

  // The same for the key it claims possession of, and for the requested extensions.
  var swappedKey = Object.assign({}, parsed);
  swappedKey.subjectPublicKeyInfo = { bytes: makeSigner("ec-p256").spki };
  check("a rebuilt request with a swapped subject key is refused",
    (await codeOf(pki.csr.verify(swappedKey))) === "csr/bad-input");

  var swappedAttrs = Object.assign({}, parsed);
  swappedAttrs.attributes = [];
  check("a rebuilt request with swapped attributes is refused",
    (await codeOf(pki.csr.verify(swappedAttrs))) === "csr/bad-input");

  // A spread, a JSON round-trip and a bare shape all reach the same door.
  check("a spread of the parse result is refused",
    (await codeOf(pki.csr.verify(Object.assign({}, parsed)))) === "csr/bad-input");
  check("a hand-built object carrying the same field names is refused",
    (await codeOf(pki.csr.verify({
      certificationRequestInfoBytes: parsed.certificationRequestInfoBytes,
      subjectPublicKeyInfo: parsed.subjectPublicKeyInfo,
      attributes: parsed.attributes,
      signatureAlgorithm: parsed.signatureAlgorithm,
      signatureValue: parsed.signatureValue,
    }))) === "csr/bad-input");
}

// ---- the verdict carries the fields it verified ---------------------------

// A copy of a parse result is refused, but the parser's own object still carries its record, so a
// caller who normalizes it IN PLACE keeps a verifying request whose visible fields are their edits.
// The verb answers with the fields re-derived from the signed bytes, so a CA that issues from the
// result issues what was signed however the argument was handled.
async function testVerdictCarriesTheVerifiedFields() {
  var s = makeSigner("ed25519");
  var der = await pki.csr.sign({
    subject: "honest.example", subjectPublicKey: s.spki,
    extensionRequest: { subjectAltName: [{ dNSName: "honest.example" }] },
  }, { key: s.key });

  var r = await pki.csr.verify(der);
  check("the verdict is an object, not a bare boolean", r !== null && typeof r === "object");
  check("verified is true for an honest request", r.verified === true);
  check("#78 valid aliases verified on the csr verdict", r.valid === true && r.valid === r.verified);
  check("the verdict carries the subject", /honest.example/.test(r.subject.dn));
  check("the verdict carries the subject key", Buffer.compare(r.subjectPublicKeyInfo.bytes, s.spki) === 0);
  check("the verdict carries the attributes", Array.isArray(r.attributes) && r.attributes.length > 0);
  check("the verdict carries the signed byte range",
    Buffer.compare(r.certificationRequestInfoBytes, pki.schema.csr.parse(der).certificationRequestInfoBytes) === 0);

  // The finding this shape exists for: the parse result mutated in place before verifying.
  var parsed = pki.schema.csr.parse(der);
  parsed.subject = { dn: "CN=attacker", rdns: [] };
  parsed.attributes = [];
  var m = await pki.csr.verify(parsed);
  check("an in-place edit still verifies against the signed bytes", m.verified === true);
  check("the verdict reports the SIGNED subject, not the edited one", /honest.example/.test(m.subject.dn));
  check("the verdict reports the SIGNED attributes, not the emptied ones", m.attributes.length > 0);
  check("the caller's own object keeps their edit", m.subject !== parsed.subject);

  // A refused request still answers with the shape, so a caller reading `.verified` is never
  // handed undefined from a verb that returned something else.
  var other = makeSigner("ed25519");
  var swap = surgery.replaceTlv(der, s.spki, other.spki);
  var bad = await pki.csr.verify(swap.der);
  check("a refused request still answers with the verdict shape", bad !== null && typeof bad === "object");
  check("verified is false for a refused request", bad.verified === false);
  check("a refused verdict still carries the fields it read", /honest.example/.test(bad.subject.dn));
}

// ---- algorithm confusion: the sig algorithm must match the key ------------

// RFC 9814 sec. 4 / the shared engine's key-OID == sig-OID gate. Retagging the outer
// signatureAlgorithm to a different algorithm than the subject key must not verify, and must not
// throw either -- it is a statement about the request.
async function testAlgorithmConfusionIsRefused() {
  var s = makeSigner("ed25519");
  var der = await pki.csr.sign({ subject: "confuse.example", subjectPublicKey: s.spki }, { key: s.key });
  var b = asn1.build;
  // Ed25519 appears twice: in subjectPKInfo and in the outer signatureAlgorithm. Rewriting the LAST
  // leaves the key naming what it is while the request asks to be verified as ECDSA.
  var retagged = surgery.replaceLastAlgId(der, pki.oid.byName("Ed25519"), function () {
    return b.sequence([b.oid(pki.oid.byName("ecdsaWithSHA256"))]);
  });
  check("both Ed25519 algorithm identifiers were found", retagged.count === 2);
  check("a signature algorithm that disagrees with the subject key is refused",
    (await csrVerified(retagged.der)) === false);
}

// ---- fail closed on malformed input ---------------------------------------

// The same doors, and the same codes, pki.crl.verify presents: the parser owns the structural
// refusal and the PEM decoder owns the string one, so neither is a CSR-specific dialect.
async function testMalformedInputThrows() {
  check("a well-formed non-CSR Buffer throws csr/not-a-certification-request",
    (await codeOf(pki.csr.verify(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00])))) === "csr/not-a-certification-request");
  check("a missing argument throws csr/bad-input",
    (await codeOf(pki.csr.verify())) === "csr/bad-input");
  check("null throws csr/bad-input", (await codeOf(pki.csr.verify(null))) === "csr/bad-input");
  check("a number throws csr/bad-input", (await codeOf(pki.csr.verify(7))) === "csr/bad-input");
  check("a non-PEM string throws pem/no-block", (await codeOf(pki.csr.verify("not a csr"))) === "pem/no-block");
  check("truncated DER throws csr/bad-der",
    (await codeOf(pki.csr.verify(Buffer.from([0x30, 0x82, 0x01])))) === "csr/bad-der");
}

// The verb is a Promise verb: malformed input REJECTS rather than throwing synchronously, so a
// caller who only attached .catch still sees the error (guard.async.deferred).
async function testRejectsRatherThanThrows() {
  var threw = false, p = null;
  try { p = pki.csr.verify(undefined); } catch (_e) { threw = true; }
  check("verify does not throw synchronously", threw === false);
  check("verify returns a Promise", !!p && typeof p.then === "function");
  check("that Promise rejects", (await codeOf(p)) === "csr/bad-input");
}

// ---- the subject key itself must be usable --------------------------------

// A request carrying an unimportable subjectPKInfo cannot prove anything. It fails closed to false
// through the engine rather than throwing, the same way a corrupt signature does.
async function testUnusableSubjectKeyIsRefused() {
  var s = makeSigner("ec-p256");
  var der = await pki.csr.sign({ subject: "badkey.example", subjectPublicKey: s.spki }, { key: s.key });
  var parsed = pki.schema.csr.parse(der);
  var truncated = Buffer.concat([parsed.subjectPublicKeyInfo.bytes.subarray(0, 4),
    Buffer.alloc(parsed.subjectPublicKeyInfo.bytes.length - 4, 0)]);
  var broken = surgery.replaceTlv(der, parsed.subjectPublicKeyInfo.bytes, truncated);
  check("the subject-key substitution matched exactly one node", broken.count === 1);
  var verdict = await csrVerified(broken.der).catch(function (e) { return e && e.code; });
  check("a request whose subject key cannot be imported never verifies", verdict !== true);
}

async function main() {
  await testAcceptsEveryAlgorithmArm();
  await testAcceptsCompositeArm();
  await testAcceptsPemAndParsed();
  await testKeySubstitutionIsRefused();
  await testCorruptSignatureIsRefused();
  await testSubjectTamperIsRefused();
  await testRebuiltParseResultIsRefused();
  await testVerdictCarriesTheVerifiedFields();
  await testAlgorithmConfusionIsRefused();
  await testMalformedInputThrows();
  await testRejectsRatherThanThrows();
  await testUnusableSubjectKeyIsRefused();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
