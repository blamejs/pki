// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for pki.attrcert.verify -- the RFC 5755 sec. 5 attribute-certificate
// validation rules. Every vector drives the shipped consumer pki.attrcert.verify(ac, issuer, opts)
// and asserts the returned verdict or err.code.
//
// Section 5 lists seven MUSTs. The ones this verb owns, each with its own vector below:
//   5(2) the signature is cryptographically correct under the AC issuer's PKC;
//   5(3) that PKC conforms to sec. 4.5 -- keyUsage MUST NOT deny digitalSignature, and
//        basicConstraints cA MUST NOT be TRUE (an AC issuer cannot also be a CA);
//   5(4) the AC issuer is directly trusted as an AC issuer, which is the caller's configuration
//        and is therefore an argument this verb refuses to guess;
//   5(5) the evaluation time is within the validity, where equality with notBeforeTime or
//        notAfterTime SUCCEEDS ("then the AC is timely and this check succeeds");
//   5(6) the targeting check of sec. 4.3.2 -- a verifier not named by a targeted AC MUST reject it;
//   5(7) an unsupported critical extension MUST be rejected.
// 5(1) (the holder's own PKC path) and the issuer's full PKC path in 5(2) are the caller's to run
// through pki.path.validate; the verdict reports which of those it was given rather than assuming.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var surgery = require("../helpers/der-surgery");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2027-01-01T00:00:00Z");
var WITHIN = new Date("2026-06-01T00:00:00Z");
var ROLE = { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } };

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}

function spec(over) {
  return Object.assign({
    holder: { entityName: { directoryName: "CN=Alice" } },
    notBeforeTime: NB, notAfterTime: NA, attributes: ROLE,
  }, over || {});
}
function aaOf(s) { return { name: "CN=Example AA", publicKey: s.spki, key: s.key }; }
// The issuer argument the verifier takes: the AC issuer this caller directly trusts (sec. 5(4)).
function trusted(s) { return { name: "CN=Example AA", publicKey: s.spki }; }

// ---- accept: a well-formed AC verifies under the issuer the caller named ---

async function testAcceptsEveryAlgorithmArm() {
  var arms = ["rsa", "rsa-pss", "ec-p256", "ec-p384", "ed25519", "ml-dsa-44", "slh-dsa-sha2-128s"];
  for (var i = 0; i < arms.length; i++) {
    var aa = makeSigner(arms[i]);
    var der = await pki.attrcert.sign(spec(), aaOf(aa));
    var r = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN });
    check("a " + arms[i] + " attribute certificate verifies", r.verified === true);
    check("a " + arms[i] + " verdict reports the signature checked", r.signatureValid === true);
  }
}

async function testAcceptsCompositeArm() {
  var arm = "id-MLDSA65-ECDSA-P256-SHA512";
  var aa;
  try { aa = makeCompositeSigner(arm); }
  catch { check("composite arm " + arm + " available", false); return; }
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  check("a composite attribute certificate verifies",
    (await pki.attrcert.verify(der, trusted(aa), { time: WITHIN })).verified === true);
}

async function testAcceptsPemAndParsed() {
  var aa = makeSigner("ed25519");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var pem = pki.schema.attrcert.pemEncode(der, "ATTRIBUTE CERTIFICATE");
  check("verify accepts a DER Buffer",
    (await pki.attrcert.verify(der, trusted(aa), { time: WITHIN })).verified === true);
  check("verify accepts a PEM string",
    (await pki.attrcert.verify(pem, trusted(aa), { time: WITHIN })).verified === true);
  check("verify accepts a parsed attribute certificate",
    (await pki.attrcert.verify(pki.schema.attrcert.parse(der), trusted(aa), { time: WITHIN })).verified === true);
}

// ---- the verdict carries what it verified ---------------------------------

async function testVerdictCarriesTheVerifiedFields() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var r = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN });
  check("the verdict is an object", r !== null && typeof r === "object");
  check("the verdict carries the holder", !!r.holder);
  check("the verdict carries the issuer name", /Example AA/.test(r.issuer.dn));
  check("the verdict carries the attributes", Array.isArray(r.attributes) && r.attributes.length === 1);
  check("the verdict carries the validity window",
    r.notBefore.getTime() === NB.getTime() && r.notAfter.getTime() === NA.getTime());
  check("the verdict carries the serial", typeof r.serialNumberHex === "string");
  // The two checks this verb does not perform are reported as not performed, never as passes.
  check("holderBindingChecked is false when no holder certificate was supplied", r.holderBindingChecked === false);
  check("issuerPathChecked is false when no anchors were supplied", r.issuerPathChecked === false);
}

// ---- 5(2): the signature must be cryptographically correct ----------------

async function testTamperedTbsIsRefused() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var parsed = pki.schema.attrcert.parse(der);
  var bad = Buffer.from(parsed.signatureValue.bytes);
  bad[bad.length - 1] ^= 0x01;
  var forged = surgery.replaceTlv(der, pki.asn1.build.bitString(parsed.signatureValue.bytes, 0),
    pki.asn1.build.bitString(bad, 0));
  check("the signature substitution matched exactly one node", forged.count === 1);
  var r = await pki.attrcert.verify(forged.der, trusted(aa), { time: WITHIN });
  check("a flipped signature bit is refused", r.verified === false);
  check("the verdict reports the signature as invalid", r.signatureValid === false);
}

async function testWrongIssuerKeyIsRefused() {
  var aa = makeSigner("ec-p256");
  var other = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var r = await pki.attrcert.verify(der, trusted(other), { time: WITHIN });
  check("an AC checked against another issuer's key is refused", r.verified === false);
}

// ---- 5(4): the AC issuer is the caller's configuration --------------------

async function testTheTrustedIssuerIsRequired() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  check("an omitted issuer throws attrcert/bad-input",
    (await codeOf(pki.attrcert.verify(der, undefined, { time: WITHIN }))) === "attrcert/bad-input");
  check("an issuer with no public key throws attrcert/bad-input",
    (await codeOf(pki.attrcert.verify(der, { name: "CN=Example AA" }, { time: WITHIN }))) === "attrcert/bad-input");
  // The AC names its issuer; a caller who trusts a DIFFERENT name has not trusted THIS issuer.
  var r = await pki.attrcert.verify(der, { name: "CN=Someone Else", publicKey: aa.spki }, { time: WITHIN });
  check("an issuer name that is not the one the AC names is refused", r.verified === false);
  check("the refusal names the issuer mismatch", /issuer/i.test(String(r.reason)));
}

// ---- 5(5): validity, where equality with either bound succeeds ------------

async function testValidityWindow() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var at = async function (t) { return pki.attrcert.verify(der, trusted(aa), { time: t }); };

  check("inside the window verifies", (await at(WITHIN)).verified === true);
  // "If the evaluation time is equal to either notBeforeTime or notAfterTime, then the AC is
  // timely and this check succeeds" -- both bounds are inclusive.
  check("equality with notBeforeTime succeeds", (await at(new Date(NB.getTime()))).verified === true);
  check("equality with notAfterTime succeeds", (await at(new Date(NA.getTime()))).verified === true);
  check("one millisecond before notBeforeTime is refused", (await at(new Date(NB.getTime() - 1))).verified === false);
  check("one millisecond after notAfterTime is refused", (await at(new Date(NA.getTime() + 1))).verified === false);
  var early = await at(new Date(NB.getTime() - 1));
  check("an out-of-window verdict still reports the signature as valid", early.signatureValid === true);
  check("an out-of-window verdict names the window", /valid/i.test(String(early.reason)));
}

// An absent instant leaves the question unasked, the way pki.crl.isRevoked settled it in v0.5.12.
// It must never read as a pass.
async function testAnAbsentTimeIsNotAPass() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var r = await pki.attrcert.verify(der, trusted(aa));
  check("an omitted time leaves the AC unverified", r.verified === false);
  check("an omitted time reports the validity as unchecked", r.validityChecked === false);
  check("the signature was still checked", r.signatureValid === true);
  check("the reason names the missing instant", /time/i.test(String(r.reason)));
}

// ---- 5(7): an unsupported critical extension is rejected ------------------

async function testUnsupportedCriticalExtensionIsRejected() {
  var aa = makeSigner("ec-p256");
  // The escape hatch takes a pre-encoded Extension, which is what an AC from another implementation
  // carrying an extension this build has never heard of looks like on the wire.
  var b = pki.asn1.build;
  var ext = b.sequence([b.oid("1.3.6.1.4.1.99999.1"), b.boolean(true), b.octetString(b.nullValue())]);
  var der = await pki.attrcert.sign(spec({ extensions: [ext] }), aaOf(aa));
  var r = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN });
  check("an unrecognized critical extension is refused", r.verified === false);
  check("the refusal names the extension", /critical/i.test(String(r.reason)));
  check("the signature itself was still valid", r.signatureValid === true);
}

// Section 5 defines support as parsing the value AND rejecting where the value would reject. An
// extension this build parses cleanly but whose constraints the verb never evaluates satisfies only
// the first, so it must still be refused: aaControls constrains what an AA may delegate (sec. 7.4)
// and acProxying constrains proxy use (sec. 7.2), and neither is evaluated here.
async function testAParsedButUnevaluatedCriticalIsRefused() {
  var aa = makeSigner("ec-p256");
  for (var name of ["aaControls", "acProxying"]) {
    var over = {};
    over[name] = name === "aaControls"
      ? { pathLenConstraint: 0, permittedAttrs: [], excludedAttrs: [], permitUnSpecified: false }
      : [{ targetName: { dNSName: "proxy.example" } }];
    var der;
    try { der = await pki.attrcert.sign(spec({ extensions: over }), aaOf(aa)); }
    catch { check(name + " is buildable", false); continue; }
    var parsedExt = pki.schema.attrcert.parse(der).extensions[0];
    check(name + " is emitted critical and parses cleanly",
      parsedExt.critical === true && !!parsedExt.decoded && parsedExt.decoded.opaque !== true);
    var r = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN });
    check("a critical " + name + " this verb does not evaluate is refused", r.verified === false);
    check("the refusal names the extension (" + name + ")", /critical/i.test(String(r.reason)));
  }
}

// An audit identity states no rule that rejects an AC (sec. 4.3.1), so parsing it is the whole of
// support, and it must reach the caller for the logging that section asks for.
async function testAnAuditIdentityIsSupportedAndSurfaced() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec({
    extensions: { auditIdentity: Buffer.from("opaque-audit-handle", "latin1") },
  }), aaOf(aa));
  var r = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN });
  check("a critical audit identity does not refuse the AC", r.verified === true);
  check("the verdict carries the extensions it read", Array.isArray(r.extensions) && r.extensions.length === 1);
  check("the audit identity is reachable on the verdict", r.extensions[0].name === "acAuditIdentity");
}

// ---- 5(6): targeting -----------------------------------------------------

async function testTargetingIsEnforced() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec({
    extensions: { targetInformation: [{ targetName: { dNSName: "server-a.example" } }] },
  }), aaOf(aa));

  var named = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN, target: { dNSName: "server-a.example" } });
  check("a verifier the AC names accepts it", named.verified === true);
  check("the verdict reports targeting as checked", named.targetingChecked === true);

  var other = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN, target: { dNSName: "server-b.example" } });
  check("a verifier the AC does not name refuses it", other.verified === false);
  check("the refusal names targeting", /target/i.test(String(other.reason)));

  // A targeted AC with no target supplied cannot be evaluated: sec. 4.3.2 makes rejection the duty
  // of servers not named, which a verifier that does not know its own name cannot establish.
  var unnamed = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN });
  check("a targeted AC with no target supplied is not verified", unnamed.verified === false);
  check("the verdict reports targeting as unchecked", unnamed.targetingChecked === false);
}

// A targetCert names a CERTIFICATE, and the GeneralName inside it identifies that certificate's
// issuer. Searching the extension's raw bytes for the caller's encoded name would match it and
// accept the AC at a server the issuer never targeted, so only the decoded targetName and
// targetGroup alternatives count.
async function testATargetCertIssuerIsNotATarget() {
  var aa = makeSigner("ec-p256");
  // This module's builder emits only targetName and targetGroup, so the targetCert arm is written
  // as the encoding it would arrive as. RFC 5755: Target ::= CHOICE { targetName [0] GeneralName,
  // targetGroup [1] GeneralName, targetCert [2] TargetCert }, and TargetCert is a SEQUENCE, so its
  // [2] is IMPLICIT; TargetCert ::= SEQUENCE { targetCertificate IssuerSerial, ... } and
  // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serial CertificateSerialNumber }.
  var b = pki.asn1.build;
  var victimName = b.contextPrimitive(2, Buffer.from("not-a-target.example", "latin1"));
  var issuerSerial = b.sequence([b.sequence([victimName]), b.integer(7n)]);
  var targetCert = b.contextConstructed(2, issuerSerial);
  var extnValue = b.sequence([b.sequence([targetCert])]);
  var ext = b.sequence([b.oid(pki.oid.byName("targetInformation")), b.boolean(true), b.octetString(extnValue)]);
  var der = await pki.attrcert.sign(spec({ extensions: [ext] }), aaOf(aa));

  // The name is present in the extension bytes, which is exactly what makes this the trap.
  var parsedExt = pki.schema.attrcert.parse(der).extensions[0];
  check("the targetCert issuer name is inside the extension bytes",
    parsedExt.value.indexOf(victimName) !== -1);

  var r = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN, target: { dNSName: "not-a-target.example" } });
  check("a targetCert issuer name does not make a verifier a target", r.verified === false);
  check("the refusal names targeting", /target/i.test(String(r.reason)));
}

// RFC 5280 sec. 7.2: "When comparing DNS names for equality, conforming implementations MUST
// perform a case-insensitive exact match on the entire DNS name." Sec. 7.5 gives a mailbox its own
// rule: the local-part is an exact match and the host-part is case-insensitive.
async function testGeneralNameMatchingRules() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec({
    extensions: {
      targetInformation: [
        { targetName: { dNSName: "Server-A.Example" } },
        { targetName: { rfc822Name: "Ops@Example.COM" } },
      ],
    },
  }), aaOf(aa));
  var at = async function (target) { return pki.attrcert.verify(der, trusted(aa), { time: WITHIN, target: target }); };

  check("a dNSName differing only in case matches (sec. 7.2)",
    (await at({ dNSName: "server-a.example" })).verified === true);
  check("a dNSName differing in content is still refused",
    (await at({ dNSName: "server-b.example" })).verified === false);
  check("a mailbox host-part differing only in case matches (sec. 7.5)",
    (await at({ rfc822Name: "Ops@example.com" })).verified === true);
  // The local-part is an exact match, so folding it would accept a different mailbox.
  check("a mailbox local-part differing in case is refused (sec. 7.5)",
    (await at({ rfc822Name: "ops@Example.COM" })).verified === false);
}

// A directoryName target is a distinguished name, so it compares through the one DN comparator
// rather than being refused for being constructed.
async function testADirectoryNameTargetIsCompared() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec({
    extensions: { targetInformation: [{ targetName: { directoryName: "Server A" } }] },
  }), aaOf(aa));

  var hit = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN, target: { directoryName: "Server A" } });
  check("a directoryName target the AC names is accepted", hit.verified === true);
  check("the directoryName comparison counts as a targeting check", hit.targetingChecked === true);

  var miss = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN, target: { directoryName: "Server B" } });
  check("a directoryName target the AC does not name is refused", miss.verified === false);
  check("that refusal is a performed check", miss.targetingChecked === true);
}

// The extension's syntax is SEQUENCE OF Targets, and RFC 5755 sec. 4.3.2 says what several groups
// mean: "If more than one Targets element is found in an AC, the extension MUST be treated as if
// all Target elements had been found within one Targets element." They FLATTEN. Requiring a match
// in every group would refuse an AC the paragraph says to accept, so the flatten is pinned here.
async function testSeveralTargetsGroupsFlatten() {
  var aa = makeSigner("ec-p256");
  var b = pki.asn1.build;
  var gn = function (host) { return b.explicit(0, b.contextPrimitive(2, Buffer.from(host, "latin1"))); };
  // Two separate Targets groups, each naming one server.
  var extnValue = b.sequence([b.sequence([gn("server-a.example")]), b.sequence([gn("server-b.example")])]);
  var ext = b.sequence([b.oid(pki.oid.byName("targetInformation")), b.boolean(true), b.octetString(extnValue)]);
  var der = await pki.attrcert.sign(spec({ extensions: [ext] }), aaOf(aa));

  check("the AC carries two Targets groups",
    pki.schema.attrcert.parse(der).extensions[0].decoded.length === 2);
  for (var host of ["server-a.example", "server-b.example"]) {
    var r = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN, target: { dNSName: host } });
    check("a server named in one of several groups is accepted (" + host + ")", r.verified === true);
  }
  var miss = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN, target: { dNSName: "server-c.example" } });
  check("a server named in no group is still refused", miss.verified === false);
}

// An untargeted AC is usable anywhere, so supplying no target is not a gap for it.
async function testAnUntargetedAcNeedsNoTarget() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var r = await pki.attrcert.verify(der, trusted(aa), { time: WITHIN });
  check("an untargeted AC verifies with no target supplied", r.verified === true);
  check("targetingChecked is true when there is nothing to target", r.targetingChecked === true);
}

// ---- a rebuilt parse result is not an attribute certificate ---------------

async function testRebuiltParseResultIsRefused() {
  var aa = makeSigner("ed25519");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  var parsed = pki.schema.attrcert.parse(der);
  check("the parser's own result verifies",
    (await pki.attrcert.verify(parsed, trusted(aa), { time: WITHIN })).verified === true);
  var rebuilt = Object.assign({}, parsed);
  rebuilt.attributes = [];
  check("a rebuilt attribute certificate is refused",
    (await codeOf(pki.attrcert.verify(rebuilt, trusted(aa), { time: WITHIN }))) === "attrcert/bad-input");
}

// Every field the verdict rests on is re-derived from the recorded signed bytes, so editing one on
// the parser's own object changes nothing. The provenance record is what carries that, not the
// claim-field list, which only recognizes an object as a parse result in the first place: extending
// an expired window, swapping the issuer, or deleting the extension that would refuse the AC are
// each discarded, and the verdict reports what was signed.
async function testInPlaceEditsDoNotReachTheVerdict() {
  var aa = makeSigner("ec-p256");
  var b = pki.asn1.build;

  // An expired AC whose validity is extended on the parsed object.
  var expired = await pki.attrcert.sign(spec({
    notBeforeTime: new Date("2020-01-01T00:00:00Z"), notAfterTime: new Date("2021-01-01T00:00:00Z"),
  }), aaOf(aa));
  var pe = pki.schema.attrcert.parse(expired);
  pe.validity.notAfterTime = new Date("2030-01-01T00:00:00Z");
  var e = await pki.attrcert.verify(pe, trusted(aa), { time: WITHIN });
  check("an extended validity does not revive an expired AC", e.verified === false);
  check("the verdict reports the signed notAfter", e.notAfter.getTime() === new Date("2021-01-01T00:00:00Z").getTime());

  // A targeted AC whose targeting extension is deleted on the parsed object.
  var targeted = await pki.attrcert.sign(spec({
    extensions: { targetInformation: [{ targetName: { dNSName: "only-a.example" } }] },
  }), aaOf(aa));
  var pt = pki.schema.attrcert.parse(targeted);
  pt.extensions = [];
  var t = await pki.attrcert.verify(pt, trusted(aa), { time: WITHIN });
  check("deleting the targeting extension does not untarget the AC", t.verified === false);

  // An AC carrying an unsupported critical extension, deleted on the parsed object.
  var ux = b.sequence([b.oid("1.3.6.1.4.1.99999.1"), b.boolean(true), b.octetString(b.nullValue())]);
  var crit = await pki.attrcert.sign(spec({ extensions: [ux] }), aaOf(aa));
  var pc = pki.schema.attrcert.parse(crit);
  pc.extensions = [];
  check("deleting an unsupported critical extension does not make the AC usable",
    (await pki.attrcert.verify(pc, trusted(aa), { time: WITHIN })).verified === false);

  // The issuer the trust decision is made against is re-derived too.
  var ok = await pki.attrcert.sign(spec(), aaOf(aa));
  var po = pki.schema.attrcert.parse(ok);
  po.issuer = { form: "v2Form", v2Form: { issuerName: { names: [{ bytes: Buffer.alloc(4) }] } } };
  var o = await pki.attrcert.verify(po, trusted(aa), { time: WITHIN });
  check("a replaced issuer does not decide the trust comparison", o.verified === true);
  check("the verdict reports the signed issuer", /Example AA/.test(o.issuer.dn));
}

// ---- fail closed on malformed input --------------------------------------

async function testMalformedInputThrows() {
  var aa = makeSigner("ec-p256");
  check("a missing argument throws attrcert/bad-input",
    (await codeOf(pki.attrcert.verify())) === "attrcert/bad-input");
  check("null throws attrcert/bad-input",
    (await codeOf(pki.attrcert.verify(null, trusted(aa)))) === "attrcert/bad-input");
  check("a number throws attrcert/bad-input",
    (await codeOf(pki.attrcert.verify(7, trusted(aa)))) === "attrcert/bad-input");
  var threw = false, p = null;
  try { p = pki.attrcert.verify(undefined, trusted(aa)); } catch (_e) { threw = true; }
  check("verify does not throw synchronously", threw === false);
  check("verify returns a Promise", !!p && typeof p.then === "function");
  check("that Promise rejects", (await codeOf(p)) === "attrcert/bad-input");
}

async function testUnknownOptionIsRefused() {
  var aa = makeSigner("ec-p256");
  var der = await pki.attrcert.sign(spec(), aaOf(aa));
  check("an unknown option is refused",
    (await codeOf(pki.attrcert.verify(der, trusted(aa), { time: WITHIN, nosuch: 1 }))) === "attrcert/bad-input");
}

async function main() {
  await testAcceptsEveryAlgorithmArm();
  await testAcceptsCompositeArm();
  await testAcceptsPemAndParsed();
  await testVerdictCarriesTheVerifiedFields();
  await testTamperedTbsIsRefused();
  await testWrongIssuerKeyIsRefused();
  await testTheTrustedIssuerIsRequired();
  await testValidityWindow();
  await testAnAbsentTimeIsNotAPass();
  await testUnsupportedCriticalExtensionIsRejected();
  await testAParsedButUnevaluatedCriticalIsRefused();
  await testAnAuditIdentityIsSupportedAndSurfaced();
  await testTargetingIsEnforced();
  await testATargetCertIssuerIsNotATarget();
  await testGeneralNameMatchingRules();
  await testADirectoryNameTargetIsCompared();
  await testSeveralTargetsGroupsFlatten();
  await testAnUntargetedAcNeedsNoTarget();
  await testRebuiltParseResultIsRefused();
  await testInPlaceEditsDoNotReachTheVerdict();
  await testMalformedInputThrows();
  await testUnknownOptionIsRefused();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
