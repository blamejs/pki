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
// A copy of a CSR carrying its single extensionRequest attribute TWICE. The builder emits one, so the
// second is spliced in at the DER level, reassembling the containers around the attribute's own raw bytes
// rather than re-encoding it. The signature no longer covers the result, which is fine and is asserted:
// the ambiguity has to be refused BEFORE the signature is checked, so the code that comes back names the
// ambiguity rather than a bad signature.
function _duplicateAttribute(csrDer, attrName) {
  var root = pki.asn1.decode(csrDer);
  var cri = root.children[0];
  var attrs = cri.children[cri.children.length - 1];   // [0] IMPLICIT SET OF Attribute
  if (!attrs || !attrs.children || !attrs.children.length) return null;
  // The request carries several attributes, so the one to duplicate is found by its own type rather than by
  // being the only one, and every other attribute is kept as it stands.
  var wanted = pki.oid.byName(attrName);
  var parts = [], found = false;
  for (var a = 0; a < attrs.children.length; a++) {
    var attr = attrs.children[a];
    parts.push(attr.bytes);
    if (pki.asn1.read.oid(attr.children[0]) === wanted) { parts.push(attr.bytes); found = true; }
  }
  if (!found) return null;
  var newAttrs = b.contextConstructed(0, Buffer.concat(parts));
  var keptCri = [];
  for (var i = 0; i < cri.children.length - 1; i++) keptCri.push(cri.children[i].bytes);
  var newCri = b.sequence([b.raw(Buffer.concat(keptCri)), b.raw(newAttrs)]);
  return b.sequence([b.raw(newCri), b.raw(root.children[1].bytes), b.raw(root.children[2].bytes)]);
}

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

// A CertificationRequest assembled here rather than by `pki.csr.sign`, because the builder reads every
// statement back through `possession.parse` with the certificate present and so cannot emit a
// non-conforming one. The request is properly signed by the signature certificate's key, so the
// signature MUST is satisfied and the only thing wrong with it is the statement's binding: its signer
// names a serial the carried certificate does not have.
async function mismatchedRequest(w, serialOffset) {
  var badIsn = b.sequence([b.raw(w.sigParsed.issuer.bytes), b.integer(w.sigParsed.serialNumber + serialOffset)]);
  var statement = b.sequence([badIsn, b.raw(w.sigCertDer)]);
  var attr = b.sequence([b.oid(O("statementOfPossession")), b.set([b.raw(statement)])]);
  var cri = b.sequence([
    b.integer(0n),
    b.raw(w.sigParsed.subject.bytes),
    b.raw(w.kemSpki),
    b.contextConstructed(0, b.raw(attr)),
  ]);
  var sigAlg = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
  var sig = crypto.sign("sha256", cri, w.sigKp.keyObject);
  return b.sequence([b.raw(cri), b.raw(sigAlg), b.bitString(sig)]);
}

// The statement reached through a PARSED request, which is a second door onto the same rule. The
// recognized-attribute reader decodes the statement in place while parsing the request, so a consumer
// that takes the decoded record gets one that never passed the binding check `possession.parse` runs.
// A statement naming one certificate while carrying another describes two different keys, and only one
// of them signed the request, so the door that skips the check accepts a request whose signer field
// does not identify the key that signed.
async function testStatementBindingThroughParsedRequest(w) {
  var der = await mismatchedRequest(w, 977n);
  var parsed = pki.schema.csr.parse(der);

  // CONTROL: the request itself is well formed and properly signed, so a refusal below is about the
  // binding and not about a broken fixture.
  check("B0: the hand-built request parses and carries the statement attribute",
    parsed.attributes.length === 1 && parsed.attributes[0].type === O("statementOfPossession"));
  // The signature is not asserted separately here: B3 requires the EXACT code
  // `possession/signer-mismatch`, and a request whose signature did not verify would report a signature
  // fault instead, so a broken fixture cannot be mistaken for the binding refusal.
  check("B2: statementOf applies the binding check to an in-place decoded attribute",
    code(function () { return pki.possession.statementOf(parsed); }) === "possession/signer-mismatch");
  // verifyRequest takes the request as DER, so it re-parses and reaches the statement through the same
  // in-place decoded attribute. It is the shipped consumer path for the whole rule.
  check("B3: verifyRequest does not accept a request whose statement names another certificate",
    (await codeAsync(pki.possession.verifyRequest(der,
      { trustAnchors: [w.caDer], time: AT }))) === "possession/signer-mismatch");

  // The same request with the binding intact must go through, or B2 and B3 would pass for a request
  // that fails for some unrelated reason.
  var good = await mismatchedRequest(w, 0n);
  var goodParsed = pki.schema.csr.parse(good);
  var st = pki.possession.statementOf(goodParsed);
  check("B4: CONTROL the same request with a matching signer is accepted",
    st !== null && st.signer.serialNumber === w.sigParsed.serialNumber);
}

// RFC 9883 sec. 4 makes certification path validation of the signature certificate a MUST, and a real
// PKI issues end-entity certificates from an intermediate rather than from the root. The validator is
// handed an ordered path and does not build one, so validating the signature certificate alone against
// a root anchor cannot succeed whenever an intermediate sits between them: the request is refused for a
// path that is in fact valid, and a caller had no way to supply the rest of it. The chain is an option,
// ordered the way the validator takes a path: from the certificate nearest the anchor DOWN to the one
// that issued the signature certificate, which is then appended last. P0 and P0a prove that order
// rather than assuming it, one of them being a chain the validator accepts and the other the same
// certificates with the intermediate left out.
async function testPathThroughAnIntermediate() {
  var rootKp = signing.makeSigner("ec-p256");
  var rootDer = await pki.x509.sign({
    subject: "Possession Root", subjectPublicKey: rootKp.spki, serialNumber: 0x31n,
    notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: rootKp.key });
  var interKp = signing.makeSigner("ec-p256");
  var interDer = await pki.x509.sign({
    subject: "Possession Issuing CA", subjectPublicKey: interKp.spki, serialNumber: 0x32n,
    notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { cert: rootDer, key: rootKp.key });
  var sigKp = signing.makeSigner("ec-p256");
  var sigCertDer = await pki.x509.sign({
    subject: "kem.example", subjectPublicKey: sigKp.spki, serialNumber: 0x33n,
    notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] },
  }, { cert: interDer, key: interKp.key });
  var sigParsed = pki.schema.x509.parse(sigCertDer);
  var kem = crypto.generateKeyPairSync("ml-kem-768");

  // CONTROL: the chain itself is valid when the validator is handed the whole of it, so a refusal below
  // is about what verifyRequest passes on and not about a chain that does not validate.
  check("P0: CONTROL the leaf validates against the root when the intermediate is in the path",
    (await pki.path.validate([interDer, sigCertDer], { trustAnchors: [rootDer], time: AT })).valid === true);
  check("P0a: CONTROL and does NOT validate with the intermediate left out, which is the whole point",
    (await pki.path.validate([sigCertDer], { trustAnchors: [rootDer], time: AT })).valid === false);

  var der = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: kem.publicKey.export({ format: "der", type: "spki" }),
    privateKeyPossessionStatement: {
      signer: { issuer: sigParsed.issuer.bytes, serialNumber: sigParsed.serialNumber },
      certificate: sigCertDer,
    },
  }, { key: sigKp.key });

  var withChain = await pki.possession.verifyRequest(der,
    { trustAnchors: [rootDer], time: AT, intermediates: [interDer] });
  check("P1: the request is accepted when the intermediate is supplied",
    withChain.valid === true && withChain.pathValidated === true);

  var withoutChain = await pki.possession.verifyRequest(der,
    { trustAnchors: [rootDer], time: AT });
  check("P2: and reports the path as not validated when it is not, rather than claiming it was",
    withoutChain.pathValidated === false && withoutChain.valid === false);
  check("P3: the signature still verifies in that case, so the two verdicts stay separate",
    withoutChain.verified === true);

  check("P4: intermediates must be an array of certificates",
    (await codeAsync(pki.possession.verifyRequest(der,
      { trustAnchors: [rootDer], time: AT, intermediates: sigCertDer }))) === "possession/bad-input");

  // A certificate whose keyUsage confines its key to keyAgreement does not authorize a signature over a
  // certification request (RFC 5280 sec. 4.2.1.3), so it must not authorize issuance either. The signature
  // itself still verifies, which is why the two verdicts stay separate: an authorization gate is not a
  // cryptographic one.
  var agreeOnly = await world({ caSubject: "Agree CA", caSerial: 9, sigSerial: 0x33,
    sigExts: { keyUsage: ["keyAgreement"] } });
  var agreeCsr = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: agreeOnly.kemSpki,
    privateKeyPossessionStatement: { signer: agreeOnly.signer, certificate: agreeOnly.sigCertDer },
  }, { key: agreeOnly.sigKp.key });
  var agreeVerdict = await pki.possession.verifyRequest(agreeCsr,
    { trustAnchors: [agreeOnly.caDer], time: AT });
  check("P5: a signature certificate confined to keyAgreement does not authorize the request",
    agreeVerdict.valid === false && agreeVerdict.signerMaySign === false);
  check("P6: and the signature still verifies, so the authorization gate is separate from the cryptography",
    agreeVerdict.verified === true && agreeVerdict.pathValidated === true);
  check("P7: the reason names the key usage rather than leaving valid false unexplained",
    typeof agreeVerdict.reason === "string" && agreeVerdict.reason.indexOf("keyUsage") >= 0);
  // The controls: digitalSignature is accepted, and so is a certificate with no keyUsage at all, which
  // RFC 5280 leaves unconfined. Without these, P5 would also pass for a gate that refused everything.
  var signOk = await world({ caSubject: "Sign CA", caSerial: 10, sigSerial: 0x34,
    sigExts: { keyUsage: ["digitalSignature"] } });
  var signCsr = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: signOk.kemSpki,
    privateKeyPossessionStatement: { signer: signOk.signer, certificate: signOk.sigCertDer },
  }, { key: signOk.sigKp.key });
  check("P8: CONTROL a digitalSignature certificate is accepted",
    (await pki.possession.verifyRequest(signCsr, { trustAnchors: [signOk.caDer], time: AT })).valid === true);
  var noKu = await world({ caSubject: "NoKu CA", caSerial: 11, sigSerial: 0x35, sigExts: {} });
  var noKuCsr = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: noKu.kemSpki,
    privateKeyPossessionStatement: { signer: noKu.signer, certificate: noKu.sigCertDer },
  }, { key: noKu.sigKp.key });
  var noKuVerdict = await pki.possession.verifyRequest(noKuCsr, { trustAnchors: [noKu.caDer], time: AT });
  check("P9: CONTROL a certificate with no keyUsage is unconfined and is accepted",
    noKuVerdict.valid === true && noKuVerdict.signerMaySign === true);

  // The prohibition and the name comparisons all read the extensions a request ASKS FOR, and each lookup
  // took the FIRST attribute whose extension matched. A request carrying two extensionRequest attributes
  // could therefore ask for keyAgreement in the first and digitalSignature in the second and have only the
  // first read. Which one a CA should honor is stated nowhere, so the ambiguity is refused, as
  // pki.schema.csr.decodeExtensions refuses it.
  var twoAttrs = await world({ caSubject: "Two CA", caSerial: 13, sigSerial: 0x37 });
  var oneAttrCsr = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: twoAttrs.kemSpki,
    extensionRequest: { keyUsage: ["keyAgreement"] },
    privateKeyPossessionStatement: { signer: twoAttrs.signer, certificate: twoAttrs.sigCertDer },
  }, { key: twoAttrs.sigKp.key });
  check("P11: CONTROL one extensionRequest attribute is read and accepted",
    (await pki.possession.verifyRequest(oneAttrCsr, { trustAnchors: [twoAttrs.caDer], time: AT })).valid === true);
  // A second extensionRequest attribute is spliced in at the DER level, because the builder emits one.
  var dup = _duplicateAttribute(oneAttrCsr, "extensionRequest");
  check("P11a: the spliced request really carries two extensionRequest attributes",
    dup !== null && code(function () { return pki.schema.csr.decodeExtensions(dup); }) === "csr/ambiguous-extension-request");
  check("P11b: a request carrying two extensionRequest attributes is refused rather than half-read",
    (await codeAsync(pki.possession.verifyRequest(dup, { trustAnchors: [twoAttrs.caDer], time: AT }))) === "possession/bad-request");

  // The same ambiguity for the STATEMENT attribute, which is the one that carries the binding checks. A
  // request with a sound statement followed by a second one naming a different certificate was accepted on
  // the strength of the first, the rest never being looked at. The refusal is one helper for both, because
  // fixing the extensionRequest case alone is how this one survived the first pass.
  var dupStmt = _duplicateAttribute(oneAttrCsr, "statementOfPossession");
  check("P12: the spliced request really carries two statement attributes",
    dupStmt !== null && pki.schema.csr.parse(dupStmt).attributes.filter(function (a) {
      return a.type === pki.possession.OID_SOP;
    }).length === 2);
  check("P12a: a request carrying two possession statements is refused rather than judged on the first",
    (await codeAsync(pki.possession.verifyRequest(dupStmt, { trustAnchors: [twoAttrs.caDer], time: AT }))) === "possession/bad-request");
  check("P12b: and pki.possession.parse of the same request is refused too, both doors agreeing",
    code(function () { return pki.possession.statementOf(pki.schema.csr.parse(dupStmt)); }) !== "NO-THROW");
}

// A requested extension that will not decode is not an absent one. The two policy comparisons RFC 9883
// states, the subject name and the subject alternative names, read the extensions a request ASKS FOR, and
// an unreadable one was caught and reported as absent: the comparison then had nothing to compare and the
// verdict said so, while a correctly signed request carrying a malformed extension came back `valid:
// true`. Reading a field the policy depends on has to either produce the field or refuse the request; it
// cannot quietly decide the policy does not apply. The CSR parser holds the extension WRAPPER to its
// shape and not its decoded value, so it does not catch this on the way in.
async function testUndecodableRequestedExtension(w) {
  var kem = crypto.generateKeyPairSync("ml-kem-768");
  var kemSpki = kem.publicKey.export({ format: "der", type: "spki" });
  var signer = { issuer: w.sigParsed.issuer.bytes, serialNumber: w.sigParsed.serialNumber };

  // A CONTROL first: the same request with a well-formed subjectAltName reports a real comparison.
  var good = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: kemSpki,
    extensionRequest: { subjectAltName: [{ dNSName: "kem.example" }] },
    privateKeyPossessionStatement: { signer: signer, certificate: w.sigCertDer },
  }, { key: w.sigKp.key });
  var goodV = await pki.possession.verifyRequest(good, { trustAnchors: [w.caDer], time: AT });
  check("X1: CONTROL a well-formed requested subjectAltName is compared, not reported absent",
    goodV.subjectAltNamesMatch !== null);

  // The same request, with the subjectAltName extension's value replaced by DER NULL. Hand-built,
  // because the builder encodes the extension from a spec and so cannot emit an undecodable one.
  var sanOid = O("subjectAltName");
  var badExt = b.sequence([b.oid(sanOid), b.octetString(b.nullValue())]);
  var extReqAttr = b.sequence([b.oid(O("extensionRequest")), b.set([b.sequence([b.raw(badExt)])])]);
  var sopAttr = b.sequence([b.oid(O("statementOfPossession")),
    b.set([b.sequence([b.sequence([b.raw(w.sigParsed.issuer.bytes), b.integer(w.sigParsed.serialNumber)]),
      b.raw(w.sigCertDer)])])]);
  var cri = b.sequence([
    b.integer(0n), b.raw(w.sigParsed.subject.bytes), b.raw(kemSpki),
    b.contextConstructed(0, Buffer.concat([extReqAttr, sopAttr].slice().sort(Buffer.compare))),
  ]);
  var badDer = b.sequence([b.raw(cri), b.raw(b.sequence([b.oid(O("ecdsaWithSHA256"))])),
    b.bitString(crypto.sign("sha256", cri, w.sigKp.keyObject))]);

  var verdict = null, verdictCode = null;
  try { verdict = await pki.possession.verifyRequest(badDer, { trustAnchors: [w.caDer], time: AT }); }
  catch (e) { verdictCode = e.code || e.message; }
  check("X2: a request whose requested subjectAltName does not decode is not accepted" +
    (verdictCode ? " (refused with " + verdictCode + ")" : ""),
    verdict === null || verdict.valid !== true);
  check("X3: and it does not report the comparison as inapplicable while accepting the request",
    verdict === null || verdict.subjectAltNamesMatch !== null || verdict.valid !== true);
}

// RFC 9883 sec. 6: "The privateKeyPossessionStatement attribute MUST NOT be used to obtain a signature
// certificate", and sec. 4: "the subjectPKInfo MUST contain the public key for the key establishment
// algorithm." That was read only off the key usages a request ASKS FOR, so omitting keyUsage entirely
// reported the prohibition as not engaged. The mechanism exists because a key-establishment key cannot
// sign and so cannot prove possession the PKCS#10 way; a subject key that can ONLY sign has no such
// problem, and a request for one is the misuse whether or not it names a usage. The discriminator is the
// key, not the extension: EdDSA, ML-DSA and SLH-DSA cannot establish a key at all, while RSA and EC can
// do either and so say nothing on their own.
async function testSignatureOnlySubjectKey(w) {
  var signer = { issuer: w.sigParsed.issuer.bytes, serialNumber: w.sigParsed.serialNumber };
  // Every signature-only family the toolkit supports, not one example of one. An RSASSA-PSS SPKI is the
  // one that reads like an exception and is not: unlike a bare rsaEncryption key, which can do key
  // transport, an id-RSASSA-PSS key is restricted to signing and so cannot establish a key either.
  // `dsa` is here because it was the one classical signature-only family this list missed, and a list that
  // misses one is how the prohibition went unenforced for it.
  var SIGN_ONLY = ["ed25519", "ed448", "ml-dsa-65", "rsa-pss", "slh-dsa-sha2-128f", "dsa"];
  for (var i = 0; i < SIGN_ONLY.length; i++) {
    var alg = SIGN_ONLY[i];
    var kp = alg === "rsa-pss" ? crypto.generateKeyPairSync("rsa-pss", { modulusLength: 2048 })
      : alg === "dsa" ? crypto.generateKeyPairSync("dsa", { modulusLength: 2048, divisorLength: 256 })
        : crypto.generateKeyPairSync(alg);
    var spki = kp.publicKey.export({ format: "der", type: "spki" });
    // No extensionRequest at all, so nothing names a usage.
    var req = await pki.csr.sign({
      subject: "kem.example", subjectPublicKey: spki,
      privateKeyPossessionStatement: { signer: signer, certificate: w.sigCertDer },
    }, { key: w.sigKp.key });
    var v = null, code = null;
    try { v = await pki.possession.verifyRequest(req, { trustAnchors: [w.caDer], time: AT }); }
    catch (e) { code = e.code || e.message; }
    check("Y" + (i + 1) + ": a request for a signature-only " + alg + " key is not accepted, " +
      "even with no keyUsage named" + (code ? " (refused with " + code + ")" : ""),
      v === null || v.valid !== true);
    check("Y" + (i + 1) + "a: and the prohibition is reported rather than silently passed",
      v === null || v.requestsSignatureCertificate === true);
  }

  // CONTROL: a key-establishment key with no keyUsage named is the case the mechanism exists for, and it
  // still goes through. Without this the checks above would pass for a verb that refused everything.
  var kem = crypto.generateKeyPairSync("ml-kem-768");
  var kemReq = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: kem.publicKey.export({ format: "der", type: "spki" }),
    privateKeyPossessionStatement: { signer: signer, certificate: w.sigCertDer },
  }, { key: w.sigKp.key });
  var kemV = await pki.possession.verifyRequest(kemReq, { trustAnchors: [w.caDer], time: AT });
  check("Y3: CONTROL an ML-KEM subject key with no keyUsage named is accepted, which is the mechanism",
    kemV.valid === true && kemV.requestsSignatureCertificate === false);
  // And an X25519 key, the other kind that cannot sign.
  var x = crypto.generateKeyPairSync("x25519");
  var xReq = await pki.csr.sign({
    subject: "kem.example", subjectPublicKey: x.publicKey.export({ format: "der", type: "spki" }),
    privateKeyPossessionStatement: { signer: signer, certificate: w.sigCertDer },
  }, { key: w.sigKp.key });
  check("Y4: CONTROL and so is an X25519 subject key",
    (await pki.possession.verifyRequest(xReq, { trustAnchors: [w.caDer], time: AT })).valid === true);
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

  await testSanFormComparisonRules();
}

// Each GeneralName form has its own comparison rule, and the comparison was made on the rendered value for
// all of them at once: a dNSName differing only in case read as a second host although RFC 4343 makes DNS
// case-insensitive, and a directoryName re-encoded to equivalent bytes read as a second name although
// RFC 5280 sec. 7.1 compares it attribute by attribute. Every form the decoder renders gets a vector, in
// both directions: the pair that differs only where its rule folds MATCHES, and the pair that differs where
// its rule is exact does NOT. One arm alone would pass for a comparison that folded case everywhere, which
// is the opposite defect.
async function testSanFormComparisonRules() {
  // certSan is what the signature certificate carries; askSan is what the request asks for.
  async function compare(certSan, askSan) {
    var w = await world({ sigExts: { keyUsage: ["digitalSignature"], subjectAltName: certSan } });
    var der = await pki.csr.sign({
      subject: "kem.example", subjectPublicKey: w.kemSpki,
      extensionRequest: { subjectAltName: askSan },
      privateKeyPossessionStatement: { signer: w.signer, certificate: w.sigCertDer },
    }, { key: w.sigKp.key });
    var v = await pki.possession.verifyRequest(der, { trustAnchors: [w.caDer], time: AT });
    return v.subjectAltNamesMatch;
  }

  // dNSName: case-insensitive throughout (RFC 4343).
  check("N7a: a dNSName differing only in case is the same host",
    (await compare([{ dNSName: "KEM.Example.COM" }], [{ dNSName: "kem.example.com" }])) === true);
  check("N7b: and a different host is still a different host",
    (await compare([{ dNSName: "kem.example.com" }], [{ dNSName: "other.example.com" }])) === false);

  // rfc822Name: the host folds, the local part does not (RFC 5280 sec. 7.5).
  check("N8a: an rfc822Name differing only in the case of its host is the same mailbox",
    (await compare([{ rfc822Name: "alice@EXAMPLE.com" }], [{ rfc822Name: "alice@example.com" }])) === true);
  check("N8b: but one differing in the case of its local part is NOT, the local part being case-sensitive",
    (await compare([{ rfc822Name: "Alice@example.com" }], [{ rfc822Name: "alice@example.com" }])) === false);

  // uniformResourceIdentifier: the scheme and host fold, the path does not (RFC 5280 sec. 7.4).
  check("N9a: a URI differing only in the case of its scheme and host names the same resource",
    (await compare([{ uniformResourceIdentifier: "HTTPS://EXAMPLE.com/Path" }],
      [{ uniformResourceIdentifier: "https://example.com/Path" }])) === true);
  check("N9b: but one differing in the case of its path does not, the path being case-sensitive",
    (await compare([{ uniformResourceIdentifier: "https://example.com/PATH" }],
      [{ uniformResourceIdentifier: "https://example.com/path" }])) === false);

  // directoryName: RFC 5280 sec. 7.1, attribute by attribute, so a value differing in case and
  // insignificant whitespace is one name where the attribute's own matching rule says so.
  check("N10a: a directoryName whose attribute values differ only in case is the same name",
    (await compare([{ directoryName: [{ commonName: "Example Co" }] }],
      [{ directoryName: [{ commonName: "EXAMPLE CO" }] }])) === true);
  check("N10b: but a different attribute value is a different name",
    (await compare([{ directoryName: [{ commonName: "Example Co" }] }],
      [{ directoryName: [{ commonName: "Other Co" }] }])) === false);

  // iPAddress: bytes, with no case to fold.
  check("N11a: the same iPAddress matches",
    (await compare([{ iPAddress: "192.0.2.1" }], [{ iPAddress: "192.0.2.1" }])) === true);
  check("N11b: and a different one does not",
    (await compare([{ iPAddress: "192.0.2.1" }], [{ iPAddress: "192.0.2.2" }])) === false);

  // A form the guard has no rule for compares by its encoded bytes, and never folds case into one it
  // cannot read. Equal bytes match; anything else does not.
  var on = { typeId: pki.oid.byName("commonName"), value: b.utf8("x") };
  check("N12a: an otherName matches itself, byte for byte",
    (await compare([{ otherName: on }], [{ otherName: on }])) === true);
  check("N12b: and differs from one whose encoded value differs only in case, the form's rule being unknown",
    (await compare([{ otherName: { typeId: pki.oid.byName("commonName"), value: b.utf8("X") } }],
      [{ otherName: on }])) === false);

  // Two different FORMS never match, whatever they render to: a dNSName is not a URI.
  check("N13: two entries of different forms do not match",
    (await compare([{ dNSName: "kem.example.com" }],
      [{ uniformResourceIdentifier: "kem.example.com" }])) === false);
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
  await testStatementBindingThroughParsedRequest(w);
  await testPathThroughAnIntermediate();
  await testUndecodableRequestedExtension(w);
  await testSignatureOnlySubjectKey(w);
  await testMatrix();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
