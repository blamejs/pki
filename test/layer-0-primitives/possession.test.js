// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for RFC 9883, "An Attribute for Statement of Possession of a Private Key".
//
// The problem it solves: PKCS#10 proves possession of the key being certified by signing the request
// with it, and a key-establishment key cannot sign. ML-KEM, X25519 and X448 keys therefore cannot be
// certified through a PKCS#10 request at all. RFC 9883's answer is to sign the request with a DIFFERENT
// key, one the requester already holds a certificate for, and to name that certificate in an attribute:
//
//   id-at-statementOfPossession OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 22112 2 1 }
//
//   PrivateKeyPossessionStatement ::= SEQUENCE {
//     signer  IssuerAndSerialNumber,
//     cert    Certificate OPTIONAL }
//
// The same OID is the PKCS#10 attribute and the CRMF registration control, which the RFC states by
// assigning `id-regCtrl-statementOfPossession` the value of `id-at-statementOfPossession`.
//
// So the request's own signature is the proof, made by a key that is not the subject's. Two things this
// toolkit refused before this release are exactly what such a request needs: a subject key that cannot
// sign, and a signing key that is not the subject's. Both are now allowed WHEN the attribute is
// present and refused when it is not, which is what keeps the relaxation from becoming a hole.
//
// What the CA must then do, verbatim from the RFC:
//   - "The CA MUST perform certification path validation for the signature certificate as specified in
//     Section 6 of [RFC5280]. If the certification path is not valid, then the CA MUST reject the
//     request for the key establishment certificate."
//   - "The CA MUST validate the signature on the certificate request using the public key from the
//     signature certificate. If the signature is not valid, then the CA MUST reject the certificate
//     request."
//   - "The subject in the signature certificate SHOULD be the same as the subject name in the
//     certificate request. If they are different, the certificate policy MUST describe how the CA can
//     determine that the two subject names identify the same entity."
//   - the same, for subject alternative names.
//   - "The privateKeyPossessionStatement attribute MUST NOT be used to obtain a signature certificate."
//
// The two SHOULDs end in a policy question a library cannot answer, so the comparison is REPORTED and
// the caller's policy decides; the two MUSTs are enforced.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");

var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || "NO-CODE"; } }
async function codeAsync(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || "NO-CODE"; } }

var SOP_OID = "1.3.6.1.4.1.22112.2.1";
var NB = new Date("2027-01-01T00:00:00Z");
var NA = new Date("2028-01-01T00:00:00Z");
var AT = new Date("2027-06-01T00:00:00Z");

// A CA, and a signature certificate it issued to the requester. The requester holds the private key
// for that certificate, and that is the key it signs the request with.
async function world(opts) {
  opts = opts || {};
  // A distinct CA name per world. A serial is unique only within an issuer, so two worlds sharing both
  // would make one world's signature certificate genuinely named by the other's statement, and a vector
  // asserting a mismatch would pass or fail for the wrong reason.
  var caKp = signing.makeSigner("ec-p256");
  var caDer = await pki.x509.sign({
    subject: opts.caSubject || "Possession CA", subjectPublicKey: caKp.spki,
    serialNumber: BigInt(opts.caSerial || 1), notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: caKp.key });
  var sigKp = signing.makeSigner(opts.sigAlg || "ec-p256");
  var sigCertDer = await pki.x509.sign({
    subject: opts.sigSubject || "kem.example", subjectPublicKey: sigKp.spki,
    serialNumber: BigInt(opts.sigSerial || 0x22), notBefore: NB, notAfter: NA,
    extensions: opts.sigExts || { keyUsage: ["digitalSignature"] },
  }, { cert: caDer, key: caKp.key });
  var sigParsed = pki.schema.x509.parse(sigCertDer);
  var kem = crypto.generateKeyPairSync(opts.kemAlg || "ml-kem-768");
  return {
    caDer: caDer, caKp: caKp, sigKp: sigKp, sigCertDer: sigCertDer, sigParsed: sigParsed,
    kemSpki: kem.publicKey.export({ format: "der", type: "spki" }),
    signer: { issuer: sigParsed.issuer.bytes, serialNumber: sigParsed.serialNumber },
  };
}

function testSurface() {
  ["parse", "verifyRequest"].forEach(function (n) {
    check("pki.possession." + n + " is exposed", typeof pki.possession[n] === "function");
  });
  check("O1: the attribute OID is on the RFC's enterprise arc, both directions",
    O("statementOfPossession") === SOP_OID && pki.oid.name(SOP_OID) === "statementOfPossession");
}

// ---- the statement value, read back --------------------------------------

async function testDecode(w) {
  // Built here from the ASN.1 rather than by the library, so the vector is a known answer.
  var isn = b.sequence([b.raw(w.sigParsed.issuer.bytes), b.integer(w.sigParsed.serialNumber)]);
  var withCert = b.sequence([isn, b.raw(w.sigCertDer)]);
  var withoutCert = b.sequence([isn]);

  var a = pki.possession.parse(withCert);
  check("D1: the signer's issuer and serial round-trip",
    Buffer.compare(a.signer.issuer.bytes, w.sigParsed.issuer.bytes) === 0 &&
    a.signer.serialNumber === w.sigParsed.serialNumber);
  check("D2: the optional certificate round-trips byte-identically",
    Buffer.compare(a.certificate, w.sigCertDer) === 0);
  var bNoCert = pki.possession.parse(withoutCert);
  check("D3: the certificate is null when omitted, which the RFC allows when the issuer is the same",
    bNoCert.certificate === null && bNoCert.signer.serialNumber === w.sigParsed.serialNumber);

  check("D4: an empty SEQUENCE is refused, the signer being mandatory",
    code(function () { pki.possession.parse(b.sequence([])); }) === "possession/bad-statement");
  check("D5: a third field is refused rather than ignored",
    code(function () { pki.possession.parse(b.sequence([isn, b.raw(w.sigCertDer), b.nullValue()])); }) === "possession/bad-statement");
  check("D6: a signer that is not an IssuerAndSerialNumber is refused",
    code(function () { pki.possession.parse(b.sequence([b.sequence([b.raw(w.sigParsed.issuer.bytes)])])); }) === "possession/bad-statement");
  check("D7: a cert field that is not a Certificate is refused",
    code(function () { pki.possession.parse(b.sequence([isn, b.nullValue()])); }) === "possession/bad-statement");
  check("D8: input that is not DER is refused",
    code(function () { pki.possession.parse(Buffer.from([5, 0])); }) === "possession/bad-statement");
  // The certificate carried must be the one the signer names: two values that name different
  // certificates describe two different keys, and only one of them signed the request.
  check("D9: a carried certificate that is not the one signer names is refused",
    code(function () {
      return pki.possession.parse(b.sequence([
        b.sequence([b.raw(w.sigParsed.issuer.bytes), b.integer(w.sigParsed.serialNumber + 1n)]),
        b.raw(w.sigCertDer)]));
    }) === "possession/signer-mismatch");
  return { isn: isn, withCert: withCert, withoutCert: withoutCert };
}

// ---- building the request -------------------------------------------------

async function testBuild(w) {
  // A KEM subject key, which cannot sign, and a signature key that can. Before this release the
  // builder refused both halves of that: the scheme resolved from the subject key.
  var der = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: w.kemSpki,
    privateKeyPossessionStatement: { signer: w.signer, certificate: w.sigCertDer },
  }, { key: w.sigKp.key });
  check("B1: a request for a KEM key is produced", Buffer.isBuffer(der));

  var parsed = pki.schema.csr.parse(der);
  check("B2: the subject key certified is the KEM key",
    Buffer.compare(parsed.subjectPublicKeyInfo.bytes, w.kemSpki) === 0);
  var attrs = parsed.attributes.filter(function (x) { return x.type === SOP_OID; });
  check("B3: exactly one statementOfPossession attribute is emitted", attrs.length === 1);
  check("B4: it names the signature certificate's issuer and serial",
    attrs[0].privateKeyPossessionStatement.signer.serialNumber === w.sigParsed.serialNumber);
  check("B5: and carries the certificate it was given",
    Buffer.compare(attrs[0].privateKeyPossessionStatement.certificate, w.sigCertDer) === 0);

  // The signature is by the signature key, so the algorithm is that key's and it verifies under that
  // key. Both are the point: a verifier reading the subject key gets nothing.
  check("B6: the request's signature verifies under the signature certificate's key",
    crypto.verify("sha256", parsed.certificationRequestInfoBytes,
      { key: crypto.createPublicKey({ key: w.sigKp.spki, format: "der", type: "spki" }), dsaEncoding: "der" },
      parsed.signatureValue.bytes) === true);
  check("B7: and does not verify under the KEM key being certified, which cannot sign at all",
    (await pki.csr.verify(der)).verified === false);

  // The wire form may omit the certificate, which the RFC allows when the issuers are the same, leaving
  // the CA to look it up. The BUILDER still needs it, because it resolves the signature algorithm from
  // that key and checks its own signature against it, so the omission is a flag rather than an absence.
  var noCert = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: w.kemSpki,
    privateKeyPossessionStatement: { signer: w.signer, certificate: w.sigCertDer, includeCertificate: false },
  }, { key: w.sigKp.key });
  check("B8: includeCertificate false emits the compact form the RFC allows",
    pki.schema.csr.parse(noCert).attributes
      .filter(function (x) { return x.type === SOP_OID; })[0].privateKeyPossessionStatement.certificate === null);
  check("B8a: and it is still signed by the same key, so a CA that looks the certificate up verifies it",
    crypto.verify("sha256", pki.schema.csr.parse(noCert).certificationRequestInfoBytes,
      { key: crypto.createPublicKey({ key: w.sigKp.spki, format: "der", type: "spki" }), dsaEncoding: "der" },
      pki.schema.csr.parse(noCert).signatureValue.bytes) === true);
  check("B8b: omitting the certificate entirely is refused, the builder needing the key it names",
    (await codeAsync(pki.csr.sign({ subject: "k", subjectPublicKey: w.kemSpki,
      privateKeyPossessionStatement: { signer: w.signer } }, { key: w.sigKp.key }))) === "csr/bad-input");
  check("B8c: includeCertificate must be a flag",
    (await codeAsync(pki.csr.sign({ subject: "k", subjectPublicKey: w.kemSpki,
      privateKeyPossessionStatement: { signer: w.signer, certificate: w.sigCertDer, includeCertificate: "no" } },
      { key: w.sigKp.key }))) === "csr/bad-input");

  // The relaxation is scoped to the attribute. Without it, both old refusals stand.
  check("B9: without the attribute, a KEM subject key is still refused",
    (await codeAsync(pki.csr.sign({ subject: "kem.example", subjectPublicKey: w.kemSpki },
      { key: w.sigKp.key }))) === "csr/unsupported-algorithm");
  var stranger = signing.makeSigner("ec-p256");
  check("B10: without the attribute, a signing key that is not the subject's is still refused",
    (await codeAsync(pki.csr.sign({ subject: "x.example", subjectPublicKey: stranger.spki },
      { key: w.sigKp.key }))) === "csr/bad-input");

  // Guards on the spec field.
  check("B11: a statement with no signer is refused",
    (await codeAsync(pki.csr.sign({ subject: "k", subjectPublicKey: w.kemSpki,
      privateKeyPossessionStatement: { certificate: w.sigCertDer } }, { key: w.sigKp.key }))) === "csr/bad-input");
  check("B12: an unknown field in the statement is refused, including the ASN.1 field's own name",
    (await codeAsync(pki.csr.sign({ subject: "k", subjectPublicKey: w.kemSpki,
      privateKeyPossessionStatement: { signer: w.signer, cert: w.sigCertDer } }, { key: w.sigKp.key }))) === "csr/bad-input");
  check("B13: a carried certificate that the signer does not name is refused at build time",
    (await codeAsync(pki.csr.sign({ subject: "k", subjectPublicKey: w.kemSpki,
      privateKeyPossessionStatement: { signer: { issuer: w.signer.issuer, serialNumber: w.signer.serialNumber + 1n },
        certificate: w.sigCertDer } }, { key: w.sigKp.key }))) === "csr/bad-input");
  check("B14: a signing key that is not the carried certificate's is refused at build time",
    (await codeAsync(pki.csr.sign({ subject: "kem.example", subjectPublicKey: w.kemSpki,
      privateKeyPossessionStatement: { signer: w.signer, certificate: w.sigCertDer } },
      { key: stranger.key }))) === "csr/bad-input");
  check("B15: a pre-encoded statementOfPossession attribute is refused, as the other recognized ones are",
    (await codeAsync(pki.csr.sign({ subject: "k", subjectPublicKey: w.kemSpki,
      attributes: [b.sequence([b.oid(O("statementOfPossession")), b.set([b.sequence([
        b.sequence([b.raw(w.sigParsed.issuer.bytes), b.integer(w.sigParsed.serialNumber)])])])])] },
      { key: w.sigKp.key }))) === "csr/bad-input");
  return { der: der, noCert: noCert };
}

// ---- the CA-side check ----------------------------------------------------

async function testVerify(w, built) {
  var v = await pki.possession.verifyRequest(built.der, { trustAnchors: [w.caDer], time: AT });
  check("V1: the request verifies under the key of the certificate the statement names", v.verified === true);
  check("V2: and the verdict is valid, every MUST the RFC states having been applied", v.valid === true);
  check("V3: the certification path of the signature certificate was validated, which the RFC makes a MUST",
    v.pathValidated === true);
  check("V4: the signer the statement names is reported",
    v.signer.serialNumber === w.sigParsed.serialNumber);
  check("V5: the subject comparison is reported, the RFC stating it as a SHOULD whose resolution is policy",
    v.subjectMatches === true);

  // Path validation is a MUST, so the verb refuses to answer without anchors rather than reporting a
  // verdict that skipped it.
  check("V6: no trustAnchors is refused rather than answered without the path check",
    (await codeAsync(pki.possession.verifyRequest(built.der, { time: AT }))) === "possession/bad-input");
  check("V7: an unknown option is refused rather than dropped",
    (await codeAsync(pki.possession.verifyRequest(built.der,
      { trustAnchors: [w.caDer], time: AT, anchors: [w.caDer] }))) === "possession/bad-input");

  // A signature certificate that does not chain to the anchors fails the MUST, and `valid` is false
  // even though the signature itself verified.
  var other = await world({ caSubject: "Other CA", caSerial: 9, sigSerial: 0x99 });
  var vBad = await pki.possession.verifyRequest(built.der, { trustAnchors: [other.caDer], time: AT });
  check("V8: a signature certificate that does not chain to the anchors is not valid",
    vBad.valid === false && vBad.pathValidated === false);
  check("V9: and the signature verdict is reported separately, so the reason is legible",
    vBad.verified === true);

  // The path MUST failed in isolation, with everything else good: validated at an instant outside the
  // signature certificate's validity. The signature still verifies, so the two verdicts are independent
  // and the reason says which one failed.
  var vExpired = await pki.possession.verifyRequest(built.der,
    { trustAnchors: [w.caDer], time: new Date("2030-01-01T00:00:00Z") });
  check("V8a: validated outside the signature certificate's validity, the path check fails alone",
    vExpired.pathValidated === false && vExpired.verified === true && vExpired.valid === false);
  check("V8b: and the reason names the path, not the signature",
    /certification path/i.test(vExpired.reason || ""));

  // The certificate omitted: the CA looks it up and supplies it.
  var vLookup = await pki.possession.verifyRequest(built.noCert,
    { trustAnchors: [w.caDer], time: AT, signatureCertificate: w.sigCertDer });
  check("V10: a statement with no certificate verifies against one the caller supplies",
    vLookup.valid === true && vLookup.verified === true);
  check("V11: and without one it is refused, there being no key to verify under",
    (await codeAsync(pki.possession.verifyRequest(built.noCert,
      { trustAnchors: [w.caDer], time: AT }))) === "possession/no-certificate");
  check("V12: a supplied certificate the signer does not name is refused",
    (await codeAsync(pki.possession.verifyRequest(built.noCert,
      { trustAnchors: [w.caDer], time: AT, signatureCertificate: other.sigCertDer }))) === "possession/signer-mismatch");

  // A request carrying no statement at all is a different question, so it is refused rather than
  // answered.
  var plain = signing.makeSigner("ec-p256");
  var plainCsr = await pki.csr.sign({ subject: "plain.example", subjectPublicKey: plain.spki }, { key: plain.key });
  check("V13: a request carrying no statement is refused, not reported unverified",
    (await codeAsync(pki.possession.verifyRequest(plainCsr, { trustAnchors: [w.caDer], time: AT }))) === "possession/absent");

  // A tampered request: the signature no longer verifies, so the verdict is false rather than throwing.
  var tampered = Buffer.from(built.der);
  tampered[tampered.length - 1] ^= 0xff;
  var vTamper = await pki.possession.verifyRequest(tampered, { trustAnchors: [w.caDer], time: AT });
  check("V14: a request whose signature was altered does not verify and is not valid",
    vTamper.verified === false && vTamper.valid === false);
}

// ---- the SHOULDs the RFC ends in a policy question ------------------------

async function testNameComparison(w) {
  // The signature certificate's subject differs from the request's. The RFC states this as a SHOULD and
  // hands the resolution to the certificate policy, so it is reported and never enforced: a library
  // cannot know whether two names identify the same entity.
  var mism = await world({ sigSubject: "someone-else.example" });
  var der = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: mism.kemSpki,
    privateKeyPossessionStatement: { signer: mism.signer, certificate: mism.sigCertDer },
  }, { key: mism.sigKp.key });
  var v = await pki.possession.verifyRequest(der, { trustAnchors: [mism.caDer], time: AT });
  check("N1: a differing subject is reported rather than refused", v.subjectMatches === false);
  check("N2: and the signature verdict is unaffected, the comparison being a policy question",
    v.verified === true);
  check("N3: `valid` does not assert the policy question was answered",
    v.valid === false && /policy/i.test(v.reason || ""));

  // Subject alternative names, when the request has them.
  var sanW = await world({ sigExts: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: "kem.example" }] } });
  var sanCsr = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: sanW.kemSpki,
    extensionRequest: { subjectAltName: [{ dNSName: "kem.example" }] },
    privateKeyPossessionStatement: { signer: sanW.signer, certificate: sanW.sigCertDer },
  }, { key: sanW.sigKp.key });
  var vSan = await pki.possession.verifyRequest(sanCsr, { trustAnchors: [sanW.caDer], time: AT });
  check("N4: matching subject alternative names are reported as matching", vSan.subjectAltNamesMatch === true);
  var sanBad = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: sanW.kemSpki,
    extensionRequest: { subjectAltName: [{ dNSName: "other.example" }] },
    privateKeyPossessionStatement: { signer: sanW.signer, certificate: sanW.sigCertDer },
  }, { key: sanW.sigKp.key });
  var vSanBad = await pki.possession.verifyRequest(sanBad, { trustAnchors: [sanW.caDer], time: AT });
  check("N5: names the request asks for that the signature certificate does not carry are reported",
    vSanBad.subjectAltNamesMatch === false);
  check("N6: a request asking for no alternative names reports null rather than a false match",
    (await pki.possession.verifyRequest(
      await pki.csr.sign({ subject: "kem.example", subjectPublicKey: sanW.kemSpki,
        privateKeyPossessionStatement: { signer: sanW.signer, certificate: sanW.sigCertDer } },
        { key: sanW.sigKp.key }),
      { trustAnchors: [sanW.caDer], time: AT })).subjectAltNamesMatch === null);
}

// ---- the MUST NOT --------------------------------------------------------

async function testMustNot(w) {
  // "The privateKeyPossessionStatement attribute MUST NOT be used to obtain a signature certificate."
  // A request whose subject key can sign, or which asks for a signature key usage, is that misuse.
  var signKp = signing.makeSigner("ec-p256");
  var der = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: signKp.spki,
    extensionRequest: { keyUsage: ["digitalSignature"] },
    privateKeyPossessionStatement: { signer: w.signer, certificate: w.sigCertDer },
  }, { key: w.sigKp.key });
  var v = await pki.possession.verifyRequest(der, { trustAnchors: [w.caDer], time: AT });
  check("M1: a request asking for a signature key usage is reported as the misuse the RFC forbids",
    v.requestsSignatureCertificate === true);
  check("M2: and it is not valid, the rule being a MUST NOT", v.valid === false);
  check("M3: a request for a key-establishment usage is not flagged",
    (await pki.possession.verifyRequest(
      await pki.csr.sign({ subject: "kem.example", subjectPublicKey: w.kemSpki,
        extensionRequest: { keyUsage: ["keyEncipherment"] },
        privateKeyPossessionStatement: { signer: w.signer, certificate: w.sigCertDer } },
        { key: w.sigKp.key }),
      { trustAnchors: [w.caDer], time: AT })).requestsSignatureCertificate === false);

  var rows = pki.lint.csr(der, { profile: "rfc9883" }).findings
    .filter(function (f) { return f.id === "lint/rfc9883/signature-certificate-requested"; });
  check("M4: pki.lint.csr grades it, at error, the rule being a MUST NOT",
    rows.length === 1 && rows[0].severity === "error");
}

// ---- the CRMF registration control ---------------------------------------

async function testCrmf(w) {
  var msg = await pki.crmf.build({
    certReqId: 1n,
    certTemplate: { subject: "kem.example", publicKey: w.kemSpki },
    controls: { statementOfPossession: { signer: w.signer, certificate: w.sigCertDer } },
  }, { key: w.sigKp.key });
  check("R1: a CertReqMsg carrying the registration control is produced", Buffer.isBuffer(msg));
  var parsed = pki.schema.crmf.parse(msg);
  var ctl = (parsed.messages[0].certReq.controls || [])
    .filter(function (c) { return c.type === SOP_OID; })[0];
  check("R2: the control is present and named, the RFC giving it the attribute's own OID",
    ctl !== undefined && ctl.name === "statementOfPossession");
  check("R3: its value reads through the same statement reader the CSR attribute uses",
    pki.possession.parse(ctl.value).signer.serialNumber === w.sigParsed.serialNumber);
  // The proof of possession is made by the statement's key, not by the KEM key being requested, which
  // is the same relaxation the PKCS#10 side makes and scoped the same way.
  var vPop = await pki.crmf.verifyPop(msg);
  check("R4: the proof of possession verifies, checked under the statement certificate's key",
    vPop.verified === true && vPop.messages[0].verified === true);
  // It proves possession of the SIGNATURE key, not of the key-establishment key being requested, and
  // the verdict says so: nothing in the message demonstrates possession of a key that cannot sign.
  check("R4a: and it is reported as NOT binding the requested key, which is what the mechanism trades away",
    vPop.messages[0].subjectBound === false);
  check("R4b: the key it was checked under is the statement certificate's, not the requested one",
    Buffer.compare(vPop.messages[0].publicKey, w.sigKp.spki) === 0);
  check("R5: a control with no certificate is refused, the builder needing the key it names",
    (await codeAsync(pki.crmf.build({ certReqId: 1n,
      certTemplate: { subject: "kem.example", publicKey: w.kemSpki },
      controls: { statementOfPossession: { signer: w.signer } } }, { key: w.sigKp.key }))) === "crmf/bad-controls");
  check("R6: a control whose certificate the signer does not name is refused",
    (await codeAsync(pki.crmf.build({ certReqId: 1n,
      certTemplate: { subject: "kem.example", publicKey: w.kemSpki },
      controls: { statementOfPossession: { signer: { issuer: w.signer.issuer, serialNumber: w.signer.serialNumber + 1n },
        certificate: w.sigCertDer } } }, { key: w.sigKp.key }))) === "crmf/bad-controls");
}

// ---- the algorithm matrix -------------------------------------------------
//
// The mechanism exists for keys that cannot sign, so every such key kind the toolkit certifies is driven,
// and every signer kind that can hold the signature certificate. Two classes, so each is swept rather
// than sampled at one member: a single pair could pass while the relaxation reached only that pair.
async function testMatrix() {
  var kems = ["ml-kem-512", "ml-kem-768", "ml-kem-1024", "x25519", "x448"];
  var signers = ["rsa", "ec-p256", "ec-p384", "ed25519", "ed448", "ml-dsa-44", "ml-dsa-65"];

  async function oneCase(kemAlg, sigAlg, serial) {
    var caKp = signing.makeSigner("ec-p256");
    var caDer = await pki.x509.sign({
      subject: "Matrix CA " + serial, subjectPublicKey: caKp.spki, serialNumber: BigInt(serial),
      notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
    }, { key: caKp.key });
    var sigKp = signing.makeSigner(sigAlg);
    var sigCert = await pki.x509.sign({
      subject: "holder.example", subjectPublicKey: sigKp.spki, serialNumber: BigInt(serial + 500),
      notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] },
    }, { cert: caDer, key: caKp.key });
    var p = pki.schema.x509.parse(sigCert);
    var kemSpki = crypto.generateKeyPairSync(kemAlg).publicKey.export({ format: "der", type: "spki" });
    var der = await pki.csr.sign({
      subject: "holder.example", subjectPublicKey: kemSpki,
      privateKeyPossessionStatement: {
        signer: { issuer: p.issuer.bytes, serialNumber: p.serialNumber }, certificate: sigCert,
      },
    }, { key: sigKp.key });
    var v = await pki.possession.verifyRequest(der, { trustAnchors: [caDer], time: AT });
    return { der: der, verdict: v, kemSpki: kemSpki };
  }

  // Every key kind that cannot sign, against one signer.
  for (var i = 0; i < kems.length; i++) {
    var r = await oneCase(kems[i], "ec-p256", 1000 + i);
    check("X" + (i + 1) + ": a " + kems[i] + " key is certified by a request another key signed",
      r.verdict.valid === true && r.verdict.verified === true);
    check("X" + (i + 1) + "a: and the key certified is that " + kems[i] + " key",
      Buffer.compare(pki.schema.csr.parse(r.der).subjectPublicKeyInfo.bytes, r.kemSpki) === 0);
  }
  // Every signer kind that can hold the signature certificate, against one KEM key.
  for (var j = 0; j < signers.length; j++) {
    var s = await oneCase("ml-kem-768", signers[j], 2000 + j);
    check("Y" + (j + 1) + ": a statement certificate holding a " + signers[j] + " key proves possession",
      s.verdict.valid === true && s.verdict.verified === true);
  }
}

async function run() {
  testSurface();
  var w = await world();
  await testDecode(w);
  var built = await testBuild(w);
  await testVerify(w, built);
  await testNameComparison(w);
  await testMustNot(w);
  await testCrmf(w);
  await testMatrix();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
