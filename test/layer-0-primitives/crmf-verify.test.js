// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for pki.crmf.verifyPop -- the RFC 4211 sec. 4 proof-of-possession verifier.
// Every vector drives the shipped consumer pki.crmf.verifyPop(input) and asserts the returned verdict
// or err.code. The three normative rules the verb exists to enforce, each with its own vector:
//
//   sec. 4.1 / the ASN.1 module (RFC 4211 p.33) -- the signature covers the DER of poposkInput when
//     that field is present, and the DER of `CertReqMsg certReq` when it is absent. Section 4.1's
//     case-3 prose says "certificate template" instead; the field definition and the ASN.1 module
//     both say certReq, and the builder in this repo signs certReq, so certReq is what is verified.
//   the ASN.1 module -- poposkInput MUST be omitted when the CertTemplate carries BOTH subject and
//     publicKey, and MUST be present when it does not. A complete template carrying a poposkInput
//     anyway is signed over a preimage that does not include the subject, so the CA would issue a
//     name nobody signed.
//   sec. 4.1 -- poposkInput.publicKey MUST be exactly the certTemplate publicKey. Without that,
//     possession is proven for one key while the certificate is issued for another.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var surgery = require("../helpers/der-surgery");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}

// A request whose CertTemplate carries both subject and publicKey: poposkInput omitted, the
// signature over the CertRequest DER.
function completeRequest(s, subject) {
  return pki.crmf.build({
    certReqId: 1n,
    certTemplate: { subject: subject || "complete.example", publicKey: s.spki },
  }, { key: s.key });
}

// A request whose CertTemplate omits the subject: poposkInput present, the signature over it.
function incompleteRequest(s) {
  return pki.crmf.build({
    certReqId: 2n,
    certTemplate: { publicKey: s.spki },
    pop: { type: "signature", sender: { dNSName: "sender.example" } },
  }, { key: s.key });
}

async function firstOf(input) {
  var r = await pki.crmf.verifyPop(input);
  return r.messages[0];
}

// ---- accept: both preimage cases, across every algorithm arm ---------------

async function testAcceptsCompleteTemplateAcrossArms() {
  var arms = ["rsa", "rsa-pss", "ec-p256", "ec-p384", "ed25519", "ml-dsa-44", "slh-dsa-sha2-128s"];
  for (var i = 0; i < arms.length; i++) {
    var s = makeSigner(arms[i]);
    var m = await firstOf(await completeRequest(s));
    check("a " + arms[i] + " complete-template request verifies", m.verified === true);
    check("a " + arms[i] + " request reports the signature method", m.method === "signature");
  }
}

async function testAcceptsPoposkInputCase() {
  var s = makeSigner("ec-p256");
  var m = await firstOf(await incompleteRequest(s));
  check("a poposkInput request verifies", m.verified === true);
  check("a poposkInput request reports the signature method", m.method === "signature");
}

async function testAcceptsCompositeArm() {
  var arm = "id-MLDSA65-ECDSA-P256-SHA512";
  var s;
  try { s = makeCompositeSigner(arm); }
  catch { check("composite arm " + arm + " available", false); return; }
  var m = await firstOf(await completeRequest(s));
  check("a composite request verifies", m.verified === true);
}

async function testAcceptsPemDerAndParsed() {
  var s = makeSigner("ed25519");
  var der = await completeRequest(s);
  check("verifyPop accepts a DER Buffer", (await firstOf(der)).verified === true);
  var pem = pki.schema.crmf.pemEncode(der, "CERTIFICATE REQUEST MESSAGE");
  check("verifyPop accepts a PEM string", (await firstOf(pem)).verified === true);
  check("verifyPop accepts a parsed message", (await firstOf(pki.schema.crmf.parse(der))).verified === true);
}

// ---- the verdict reports what it verified ---------------------------------

async function testVerdictCarriesTheVerifiedFields() {
  var s = makeSigner("ec-p256");
  var der = await completeRequest(s, "carried.example");
  var r = await pki.crmf.verifyPop(der);
  check("the top-level verdict is an object", r !== null && typeof r === "object");
  check("the top-level verified is true when every message verified", r.verified === true);
  check("the verdict carries one entry per message", Array.isArray(r.messages) && r.messages.length === 1);
  var m = r.messages[0];
  check("the message verdict carries certReqId", m.certReqId === 1n);
  check("the message verdict carries the subject", /carried.example/.test(m.subject.dn));
  check("the message verdict carries the requested key", Buffer.compare(m.publicKey, s.spki) === 0);
  check("cryptographicallyVerified is true for a signature POP", m.cryptographicallyVerified === true);
}

// ---- refuse: the signature does not hold ----------------------------------

// The CertTemplate carries the SPKI as an IMPLICIT [6] field, so the SEQUENCE tag is replaced on the
// wire and a plain TLV search never finds it. Rewrite the [6] node itself, re-tagging the donor key
// the same way. `pki.crmf.build` refuses to produce this shape (it self-checks the POP before
// returning), which is why the vector is built by surgery rather than by the builder.
function replaceTemplateKey(der, donorSpki) {
  var b = pki.asn1.build;
  var count = 0;
  var out = surgery.patch(der, function (n) {
    if (n.tagClass !== "context" || n.tagNumber !== 6) return undefined;
    count++;
    return b.implicit(6, donorSpki);
  });
  return { der: out, count: count };
}

async function testKeySubstitutionIsRefused() {
  var mine = makeSigner("ec-p256");
  var theirs = makeSigner("ec-p256");
  var der = await completeRequest(mine);
  var swap = replaceTemplateKey(der, theirs.spki);
  check("the template key substitution matched exactly one node", swap.count === 1);
  var m = await firstOf(swap.der);
  check("a request signed by a key other than the requested one is refused", m.verified === false);
  check("the refusal names a reason", typeof m.reason === "string" && m.reason.length > 0);
}

async function testSubjectTamperIsRefused() {
  var s = makeSigner("ec-p256");
  var der = await completeRequest(s, "honest.example");
  var b = pki.asn1.build;
  var forged = surgery.replaceTlv(der, b.utf8("honest.example"), b.utf8("attacker.exam"));
  check("the subject substitution matched exactly one node", forged.count === 1);
  check("a subject changed after signing is refused", (await firstOf(forged.der)).verified === false);
}

// ---- the ASN.1 module's poposkInput presence rule -------------------------

// A complete template MUST omit poposkInput. Splicing one in leaves a signature that covers the key
// and the sender but never the subject, so a CA reading certTemplate.subject would issue a name the
// requester never signed. The signature itself still verifies over the spliced preimage.
async function testPoposkInputOnACompleteTemplateIsRefused() {
  var s = makeSigner("ec-p256");
  var complete = await completeRequest(s, "complete.example");
  var incomplete = await incompleteRequest(s);
  var donor = pki.schema.crmf.parse(incomplete).messages[0].popo.poposkInput.bytes;

  // Graft the donor's poposkInput [0] in as the first child of the POPOSigningKey [1] node, which
  // on the wire is a context-1 constructed SEQUENCE of { algorithmIdentifier, signature }.
  var b = pki.asn1.build;
  var grafted = 0;
  var out = surgery.patch(complete, function (n) {
    if (n.tagClass !== "context" || n.tagNumber !== 1 || !n.children || n.children.length !== 2) return undefined;
    grafted++;
    return b.implicit(1, b.sequence([
      b.raw(Buffer.from(donor)),
      b.raw(Buffer.from(n.children[0].bytes)),
      b.raw(Buffer.from(n.children[1].bytes)),
    ]));
  });
  check("the poposkInput graft matched exactly one POPOSigningKey", grafted === 1);
  // The rule is enforced one layer down, at parse, so the message is refused before a verdict is
  // reached. That is the stronger placement -- every consumer of the parser gets it, not only this
  // verb -- and the vector pins it where it actually lives.
  check("a complete template carrying a poposkInput is refused at parse",
    (await codeOf(pki.crmf.verifyPop(out))) === "crmf/bad-popo");
}

// ---- the sec. 4.1 publicKey-equality rule ---------------------------------

// poposkInput.publicKey MUST equal the certTemplate publicKey. When it does not, possession is
// proven for the key inside poposkInput while the CA issues a certificate for the template's key.
async function testPoposkInputKeyMustMatchTemplate() {
  var s = makeSigner("ec-p256");
  var other = makeSigner("ec-p256");
  var der = await incompleteRequest(s);
  // Replace ONLY the certTemplate copy (the IMPLICIT [6] field), leaving poposkInput's own copy and
  // therefore the signature itself intact. The signature still verifies over its preimage; what
  // fails is the sec. 4.1 rule binding that key to the one the certificate would be issued for.
  var swap = replaceTemplateKey(der, other.spki);
  check("the template key substitution matched exactly one node", swap.count === 1);
  // Enforced at parse for the same reason as the presence rule: it is a property of the message,
  // so refusing it there covers every consumer rather than only this verb.
  check("a poposkInput key that disagrees with the template is refused at parse",
    (await codeOf(pki.crmf.verifyPop(swap.der))) === "crmf/bad-popo");
}

// ---- the arms that are not decidable from the message ---------------------

async function testRaVerifiedNeverReadsAsVerified() {
  var s = makeSigner("ec-p256");
  var der = await pki.crmf.build({
    certReqId: 3n,
    certTemplate: { subject: "ra.example", publicKey: s.spki },
    pop: { type: "raVerified", raVerified: true },
  });
  var m = await firstOf(der);
  check("raVerified does not read as verified", m.verified === false);
  check("raVerified is reported as its own method", m.method === "raVerified");
  check("raVerified is not a cryptographic proof", m.cryptographicallyVerified === false);
  check("raVerified still carries the requested key", Buffer.compare(m.publicKey, s.spki) === 0);
}

async function testAbsentPopIsNotVerified() {
  var s = makeSigner("ec-p256");
  var der = await pki.crmf.build({
    certReqId: 4n,
    certTemplate: { subject: "nopop.example", publicKey: s.spki },
  });
  var m = await firstOf(der);
  check("a request with no popo is not verified", m.verified === false);
  check("a request with no popo reports no method", m.method === null);
}

// ---- fail closed on malformed input ---------------------------------------

async function testMalformedInputThrows() {
  check("a missing argument throws crmf/bad-input", (await codeOf(pki.crmf.verifyPop())) === "crmf/bad-input");
  check("null throws crmf/bad-input", (await codeOf(pki.crmf.verifyPop(null))) === "crmf/bad-input");
  check("a number throws crmf/bad-input", (await codeOf(pki.crmf.verifyPop(7))) === "crmf/bad-input");
  var threw = false, p = null;
  try { p = pki.crmf.verifyPop(undefined); } catch (_e) { threw = true; }
  check("verifyPop does not throw synchronously", threw === false);
  check("verifyPop returns a Promise", !!p && typeof p.then === "function");
  check("that Promise rejects", (await codeOf(p)) === "crmf/bad-input");
}

// ---- a rebuilt parse result is not a message ------------------------------

async function testRebuiltParseResultIsRefused() {
  var s = makeSigner("ed25519");
  var der = await completeRequest(s);
  var parsed = pki.schema.crmf.parse(der);
  check("the parser's own result verifies", (await firstOf(parsed)).verified === true);
  var rebuilt = Object.assign({}, parsed);
  check("a rebuilt message set is refused", (await codeOf(pki.crmf.verifyPop(rebuilt))) === "crmf/bad-input");
}

// ---- several messages: each answers for itself ----------------------------

async function testEveryMessageAnswersForItself() {
  var good = makeSigner("ec-p256");
  var der = await pki.crmf.build({
    messages: [
      { certReqId: 1n, certTemplate: { subject: "a.example", publicKey: good.spki } },
      { certReqId: 2n, certTemplate: { subject: "b.example", publicKey: good.spki } },
    ],
  }, { key: good.key });
  var r = await pki.crmf.verifyPop(der);
  check("both messages are reported", r.messages.length === 2);
  check("both messages verified", r.messages[0].verified === true && r.messages[1].verified === true);
  check("the top-level verified is true when all verified", r.verified === true);
  check("each message keeps its own certReqId", r.messages[0].certReqId === 1n && r.messages[1].certReqId === 2n);
}

async function main() {
  await testAcceptsCompleteTemplateAcrossArms();
  await testAcceptsPoposkInputCase();
  await testAcceptsCompositeArm();
  await testAcceptsPemDerAndParsed();
  await testVerdictCarriesTheVerifiedFields();
  await testKeySubstitutionIsRefused();
  await testSubjectTamperIsRefused();
  await testPoposkInputOnACompleteTemplateIsRefused();
  await testPoposkInputKeyMustMatchTemplate();
  await testRaVerifiedNeverReadsAsVerified();
  await testAbsentPopIsNotVerified();
  await testMalformedInputThrows();
  await testRebuiltParseResultIsRefused();
  await testEveryMessageAnswersForItself();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
