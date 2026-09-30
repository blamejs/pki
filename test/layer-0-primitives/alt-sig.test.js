// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for the ITU-T X.509 (2019) clause 9.8 alternative-signature extensions, the
// "Catalyst" shape: one certificate carrying two signatures, so a PKI can migrate from one set of
// algorithms to another without reissuing to every relying party at once.
//
// Clause 9.8 defines three certificate extensions, and the OIDs are read off the ASN.1 module ITU-T
// publishes rather than recalled:
//
//   id-ce-subjectAltPublicKeyInfo  ::= {id-ce 72}
//   id-ce-altSignatureAlgorithm    ::= {id-ce 73}
//   id-ce-altSignatureValue        ::= {id-ce 74}
//
//   SubjectAltPublicKeyInfo ::= SEQUENCE {
//     algorithm            AlgorithmIdentifier{{SupportedAlgorithms}},
//     subjectAltPublicKey  BIT STRING }
//   AltSignatureAlgorithm ::= AlgorithmIdentifier{{SupportedAlgorithms}}
//   AltSignatureValue ::= BIT STRING
//
// SubjectAltPublicKeyInfo has the same two components in the same order as SubjectPublicKeyInfo, and a
// field name is not encoded, so the extension value IS an SPKI on the wire. A vector asserts that,
// because it is the reason the issuer's alternative key needs no conversion before it is imported.
//
// What the alternative signature covers is the load-bearing part, and clause 7.2.2 states it exactly:
// "when generating the value in the altSignatureValue extension, exclude the signature component and
// the altSignatureValue extension from the public-key certificate, and generate the digital signature
// over the remaining DER encoded public-key certificate using the algorithm specified in the
// altSignatureAlgorithm extension". The `signature` component is the outer BIT STRING, which the
// sibling bullet identifies by saying the native signature is the value generated INTO it.
//
// So the preimage is the Certificate SEQUENCE carrying its tbsCertificate and its outer
// algorithmIdentifier, with the altSignatureValue extension removed from the tbsCertificate and the
// outer signature BIT STRING absent. Clause 7.2.2 is explicit that a verifier has to rebuild it:
// "the relying party shall decode the public-key certificate and then re-DER-encode the same
// public-key certificate after the above modifications have been made, otherwise the validation of the
// alternative signature will fail." That re-encode is the one this toolkit otherwise refuses, so the
// vectors pin it against bytes built independently of the implementation.
//
// Clause 7.10.3 states the same procedure for a CRL, where the same two extensions apply and
// subjectAltPublicKeyInfo does not.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");

var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || "NO-CODE"; } }
async function codeAsync(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || "NO-CODE"; } }

var SAPKI_OID = "2.5.29.72";
var ALT_ALG_OID = "2.5.29.73";
var ALT_VAL_OID = "2.5.29.74";
var NB = new Date("2027-01-01T00:00:00Z");
var NA = new Date("2028-01-01T00:00:00Z");

function ext(oidDotted, critical, valueDer) {
  var f = [b.oid(oidDotted)];
  if (critical) f.push(b.boolean(true));
  f.push(b.octetString(valueDer));
  return b.sequence(f);
}
function dn(cn) { return b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable(cn)])])]); }
var VALIDITY = b.sequence([b.utcTime(NB), b.utcTime(NA)]);

// A Catalyst certificate built by hand, following clause 7.2.2 step by step, so the fixture is an
// independent oracle rather than a second call into the code under test. `extraExts` go before the
// three alternative ones; `omit` drops one of the three, for the refusal vectors.
function makeCatalyst(opts) {
  opts = opts || {};
  var nativeKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var altKp = crypto.generateKeyPairSync(opts.altAlg || "ml-dsa-65");
  var nativeSpki = nativeKp.publicKey.export({ format: "der", type: "spki" });
  var altSpki = altKp.publicKey.export({ format: "der", type: "spki" });
  var nativeAlgId = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
  var altAlgId = b.sequence([b.oid(O(opts.altOidName || "id-ml-dsa-65"))]);
  var name = dn(opts.cn || "Catalyst Signer");

  function tbs(withAltValue) {
    var exts = (opts.extraExts || []).slice();
    if (!opts.omitSapki) exts.push(ext(SAPKI_OID, opts.criticalSapki === true, altSpki));
    if (!opts.omitAltAlg) exts.push(ext(ALT_ALG_OID, false, altAlgId));
    if (withAltValue && !opts.omitAltValue) exts.push(ext(ALT_VAL_OID, false, b.bitString(withAltValue, 0)));
    var fields = [b.explicit(0, b.integer(2n)), b.integer(BigInt(opts.serial || 0x11)), nativeAlgId,
      name, VALIDITY, name, b.raw(nativeSpki)];
    if (exts.length) fields.push(b.explicit(3, b.sequence(exts)));
    return b.sequence(fields);
  }

  // Clause 7.2.2: the alternative signature covers the certificate with the outer signature absent and
  // the altSignatureValue extension removed.
  var preimage = b.sequence([tbs(null), nativeAlgId]);
  var altSig = opts.forgeAltSig
    ? Buffer.from(opts.forgeAltSig)
    : crypto.sign(null, preimage, altKp.privateKey);
  var finalTbs = tbs(altSig);
  var nativeSig = crypto.sign("sha256", finalTbs, { key: nativeKp.privateKey, dsaEncoding: "der" });
  return {
    der: b.sequence([finalTbs, nativeAlgId, b.bitString(nativeSig, 0)]),
    preimage: preimage, altSpki: altSpki, nativeSpki: nativeSpki,
    altKeyObject: altKp.privateKey, nativeKeyObject: nativeKp.privateKey,
    altAlgId: altAlgId, nativeAlgId: nativeAlgId, altSig: altSig,
  };
}

function testSurface() {
  ["signedData", "verify", "subjectAltPublicKey"].forEach(function (n) {
    check("pki.altSig." + n + " is exposed", typeof pki.altSig[n] === "function");
  });
  [["subjectAltPublicKeyInfo", SAPKI_OID], ["altSignatureAlgorithm", ALT_ALG_OID],
    ["altSignatureValue", ALT_VAL_OID]].forEach(function (r, i) {
    check("O" + (i + 1) + ": " + r[0] + " is {id-ce " + r[1].split(".").pop() + "}, both directions",
      O(r[0]) === r[1] && pki.oid.name(r[1]) === r[0]);
  });
}

// ---- the preimage, against bytes built independently ------------------------

function testPreimage() {
  var c = makeCatalyst({ serial: 0x21 });
  var got = pki.altSig.signedData(c.der);
  check("P1: the preimage is the certificate with the outer signature and altSignatureValue removed",
    Buffer.compare(got, c.preimage) === 0);
  check("P2: it is a SEQUENCE of exactly two members, the tbsCertificate and the outer algorithm",
    pki.asn1.decode(got).children.length === 2);

  // Every byte of a kept component is the byte that was there. Removing a member changes three
  // SEQUENCE headers and nothing else, so the tbsCertificate's own fields must be byte-identical.
  var origTbs = pki.asn1.decode(c.der).children[0];
  var newTbs = pki.asn1.decode(got).children[0];
  check("P3: the outer algorithmIdentifier is carried unchanged",
    Buffer.compare(pki.asn1.decode(got).children[1].bytes, pki.asn1.decode(c.der).children[1].bytes) === 0);
  check("P4: every tbsCertificate field before the extensions is carried byte-identically",
    origTbs.children.slice(0, 7).every(function (n, i) { return Buffer.compare(n.bytes, newTbs.children[i].bytes) === 0; }));
  var origExts = origTbs.children[7].children[0].children;
  var newExts = newTbs.children[7].children[0].children;
  check("P5: the extensions block loses exactly the altSignatureValue extension",
    origExts.length === 3 && newExts.length === 2 &&
    origExts.slice(0, 2).every(function (n, i) { return Buffer.compare(n.bytes, newExts[i].bytes) === 0; }));
  check("P6: and what it loses is that extension, not merely the last one",
    pki.asn1.read.oid(origExts[2].children[0]) === ALT_VAL_OID &&
    newExts.map(function (n) { return pki.asn1.read.oid(n.children[0]); }).indexOf(ALT_VAL_OID) === -1);

  // The altSignatureValue extension need not be last, and removal must find it wherever it sits.
  var mid = makeCatalyst({ serial: 0x22,
    extraExts: [ext(O("keyUsage"), true, b.namedBitString([0]))] });
  check("P7: the preimage is right with another extension present",
    Buffer.compare(pki.altSig.signedData(mid.der), mid.preimage) === 0);

  check("P8: a structure carrying no altSignatureAlgorithm is refused, there being no algorithm to verify under",
    code(function () { pki.altSig.signedData(makeCatalyst({ serial: 0x23, omitAltAlg: true }).der); }) === "altsig/absent");
  check("P9: input that is not a certificate or a CRL is refused",
    code(function () { pki.altSig.signedData(Buffer.from([5, 0])); }) === "altsig/bad-input");
  check("P10: a plain certificate with none of the extensions is refused",
    code(function () { pki.altSig.signedData(signing.makeSigner("ec-p256").cert); }) === "altsig/absent");
}

// ---- verification -----------------------------------------------------------

async function testVerify() {
  var c = makeCatalyst({ serial: 0x31 });
  check("V1: the alternative signature verifies under the issuer's alternative public key",
    (await pki.altSig.verify(c.der, c.altSpki)) === true);

  // SubjectAltPublicKeyInfo is an SPKI on the wire, which is why the extension value goes straight in.
  var sapki = pki.altSig.subjectAltPublicKey(c.der);
  check("V2: subjectAltPublicKey returns the extension value, and it is the alternative SPKI",
    Buffer.compare(sapki, c.altSpki) === 0);
  check("V3: those bytes import as a SubjectPublicKeyInfo, the two types having one encoding",
    crypto.createPublicKey({ key: sapki, format: "der", type: "spki" }).asymmetricKeyType === "ml-dsa-65");
  check("V4: and the certificate verifies under the key read back out of its own extension",
    (await pki.altSig.verify(c.der, sapki)) === true);

  var other = makeCatalyst({ serial: 0x32 });
  check("V5: it does not verify under another key of the same algorithm",
    (await pki.altSig.verify(c.der, other.altSpki)) === false);
  check("V6: a forged alternative signature does not verify",
    (await pki.altSig.verify(makeCatalyst({ serial: 0x33, forgeAltSig: Buffer.alloc(3309, 7) }).der, c.altSpki)) === false);

  // The native signature is unaffected and still checks the way it always did, which is the whole
  // point of the mechanism: a relying party that has not migrated reads it and ignores the rest.
  check("V7: the native signature still verifies over the tbsCertificate as it stands",
    crypto.verify("sha256", pki.asn1.decode(c.der).children[0].bytes,
      { key: crypto.createPublicKey({ key: c.nativeSpki, format: "der", type: "spki" }), dsaEncoding: "der" },
      pki.asn1.read.bitString(pki.asn1.decode(c.der).children[2]).bytes) === true);

  // Tampering anywhere inside the preimage breaks the alternative signature.
  var tampered = Buffer.from(c.der);
  var serialNode = pki.asn1.decode(c.der).children[0].children[1];
  tampered[c.der.indexOf(serialNode.bytes) + serialNode.bytes.length - 1] ^= 0xff;
  check("V8: altering the serial breaks the alternative signature",
    (await pki.altSig.verify(tampered, c.altSpki)) === false);

  check("V9: a key of the wrong algorithm for the stated altSignatureAlgorithm does not verify",
    (await pki.altSig.verify(c.der, signing.makeSigner("ec-p256").spki)) === false);
  check("V10: an alternative key that is not an SPKI is refused",
    (await codeAsync(pki.altSig.verify(c.der, Buffer.from([5, 0])))) === "altsig/bad-input");
  check("V11: a structure with no alternative signature is refused",
    (await codeAsync(pki.altSig.verify(signing.makeSigner("ec-p256").cert, c.altSpki))) === "altsig/absent");
  check("V12: an unknown option is refused rather than dropped",
    (await codeAsync(pki.altSig.verify(c.der, c.altSpki, { key: c.altSpki }))) === "altsig/bad-input");

  // subjectAltPublicKeyInfo is a certificate extension only, so asking a certificate that has none.
  check("V13: subjectAltPublicKey refuses a certificate carrying no such extension",
    code(function () { pki.altSig.subjectAltPublicKey(signing.makeSigner("ec-p256").cert); }) === "altsig/absent");

  // Clause 9.8.2 permits either criticality, with a NOTE recommending non-critical, so a critical one
  // parses and verifies: a NOTE is weaker than a SHOULD and must not become a refusal.
  var crit = makeCatalyst({ serial: 0x34, criticalSapki: true });
  check("V14: a critical subjectAltPublicKeyInfo still parses and verifies, clause 9.8.2 permitting either",
    (await pki.altSig.verify(crit.der, crit.altSpki)) === true);
  return c;
}

// ---- the three extension values, read back ---------------------------------

function testDecode() {
  var c = makeCatalyst({ serial: 0x41 });
  var parsed = pki.schema.x509.parse(c.der);
  function decoded(oidDotted) {
    var e = parsed.extensions.filter(function (x) { return x.oid === oidDotted; })[0];
    return e === undefined ? undefined : pki.schema.x509.decodeExtension(e).decoded;
  }
  var sapki = decoded(SAPKI_OID);
  check("D1: subjectAltPublicKeyInfo decodes to its algorithm and key",
    sapki.algorithm.name === "id-ml-dsa-65" && Buffer.isBuffer(sapki.subjectAltPublicKey) &&
    sapki.subjectAltPublicKey.length === 1952);
  check("D2: and surfaces the whole value as an SPKI, so it needs no rebuilding to be imported",
    Buffer.compare(sapki.bytes, c.altSpki) === 0);
  var alg = decoded(ALT_ALG_OID);
  check("D3: altSignatureAlgorithm decodes to an AlgorithmIdentifier",
    alg.oid === O("id-ml-dsa-65") && alg.name === "id-ml-dsa-65");
  var val = decoded(ALT_VAL_OID);
  check("D4: altSignatureValue decodes to the signature bits",
    val.unusedBits === 0 && Buffer.compare(val.bytes, c.altSig) === 0);

  // Refusals on values no builder here emits.
  async function parseExtValue(oidDotted, valueDer, serial) {
    return await codeAsync(pki.x509.sign({
      subject: "X", subjectPublicKey: signing.makeSigner("ec-p256").spki, serialNumber: serial,
      notBefore: NB, notAfter: NA, extensions: [ext(oidDotted, false, valueDer)],
    }, { key: signing.makeSigner("ec-p256").key }));
  }
  return { parseExtValue: parseExtValue };
}

async function testDecodeRefusals(ctx) {
  var p = ctx.parseExtValue;
  var bad = "x509/bad-extension-value";
  check("D5: a subjectAltPublicKeyInfo that is not a two-field SEQUENCE is refused",
    (await p(SAPKI_OID, b.sequence([b.sequence([b.oid(O("id-ml-dsa-65"))])]), 0x50n)) === bad);
  check("D6: a subjectAltPublicKeyInfo whose key is not a BIT STRING is refused",
    (await p(SAPKI_OID, b.sequence([b.sequence([b.oid(O("id-ml-dsa-65"))]), b.octetString(Buffer.alloc(8))]), 0x51n)) === bad);
  check("D7: a subjectAltPublicKeyInfo with an empty key is refused",
    (await p(SAPKI_OID, b.sequence([b.sequence([b.oid(O("id-ml-dsa-65"))]), b.bitString(Buffer.alloc(0), 0)]), 0x52n)) === bad);
  check("D8: an altSignatureAlgorithm that is not an AlgorithmIdentifier is refused",
    (await p(ALT_ALG_OID, b.oid(O("id-ml-dsa-65")), 0x53n)) === bad);
  check("D9: an altSignatureValue that is not a BIT STRING is refused",
    (await p(ALT_VAL_OID, b.octetString(Buffer.alloc(32)), 0x54n)) === bad);
  check("D10: an altSignatureValue whose BIT STRING is not octet-aligned is refused",
    (await p(ALT_VAL_OID, b.bitString(Buffer.alloc(32), 3), 0x55n)) === bad);
  check("D11: an empty altSignatureValue is refused",
    (await p(ALT_VAL_OID, b.bitString(Buffer.alloc(0), 0), 0x56n)) === bad);
}

// ---- the builder -----------------------------------------------------------

async function testBuilder() {
  var ca = signing.makeSigner("ec-p256", { cn: "Catalyst CA", serial: 0x60 });
  var altKp = crypto.generateKeyPairSync("ml-dsa-65");
  var altSpki = altKp.publicKey.export({ format: "der", type: "spki" });
  var altPkcs8 = altKp.privateKey.export({ format: "der", type: "pkcs8" });
  var subject = signing.makeSigner("ec-p256");
  var subjAltKp = crypto.generateKeyPairSync("ml-dsa-65");
  var subjAltSpki = subjAltKp.publicKey.export({ format: "der", type: "spki" });

  // A real CA certificate, issued by the shipped path, so the issuer form under test is the one an
  // operator uses. It carries its own alternative key, which is what the certificates below verify
  // against: clause 9.8.4 checks an alternative signature with the issuer's alternative public key.
  var caDer = await pki.x509.sign({
    subject: "Catalyst CA", subjectPublicKey: ca.spki, serialNumber: 0x60n, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
      subjectAltPublicKeyInfo: altSpki },
  }, { key: ca.key, altKey: altPkcs8, altPublicKey: altSpki });
  var nativeS = { cert: caDer, key: ca.key, spki: ca.spki, keyObject: ca.keyObject };
  check("B0: the CA certificate is itself a Catalyst certificate and verifies under its own alternative key",
    (await pki.altSig.verify(caDer, altSpki)) === true);
  check("B0a: and its alternative key is readable from it, which is how the chain below is checked",
    Buffer.compare(pki.altSig.subjectAltPublicKey(caDer), altSpki) === 0);

  var der = await pki.x509.sign({
    subject: "leaf.example", subjectPublicKey: subject.spki, serialNumber: 0x61n,
    notBefore: NB, notAfter: NA,
    extensions: { subjectAltPublicKeyInfo: subjAltSpki },
  }, { cert: nativeS.cert, key: nativeS.key, altKey: altPkcs8, altPublicKey: altSpki });
  check("B1: pki.x509.sign emits a Catalyst certificate", Buffer.isBuffer(der));

  var oids = pki.schema.x509.parse(der).extensions.map(function (e) { return e.oid; });
  check("B2: all three extensions are emitted",
    oids.indexOf(SAPKI_OID) !== -1 && oids.indexOf(ALT_ALG_OID) !== -1 && oids.indexOf(ALT_VAL_OID) !== -1);
  check("B3: the alternative signature verifies under the issuer's alternative key",
    (await pki.altSig.verify(der, altSpki)) === true);
  check("B4: the subject's alternative key is the one that was asked for",
    Buffer.compare(pki.altSig.subjectAltPublicKey(der), subjAltSpki) === 0);
  // The native signature is untouched by the mechanism, and it covers the tbsCertificate INCLUDING all
  // three extensions, which clause 7.2.2 states as the second bullet. A relying party that has not
  // migrated reads only this one.
  var bDecoded = pki.asn1.decode(der);
  check("B5: the native signature verifies over the tbsCertificate as it stands, all three extensions included",
    crypto.verify("sha256", bDecoded.children[0].bytes,
      { key: crypto.createPublicKey({ key: nativeS.spki, format: "der", type: "spki" }), dsaEncoding: "der" },
      pki.asn1.read.bitString(bDecoded.children[2]).bytes) === true);
  check("B5a: and the tbsCertificate it covers does carry the altSignatureValue extension",
    bDecoded.children[0].children[7].children[0].children
      .map(function (n) { return pki.asn1.read.oid(n.children[0]); }).indexOf(ALT_VAL_OID) !== -1);

  // The three extensions are emitted non-critical, which clause 9.8's NOTEs recommend.
  var byOid = {};
  pki.schema.x509.parse(der).extensions.forEach(function (e) { byOid[e.oid] = e; });
  check("B6: all three are emitted non-critical, which clause 9.8 recommends in a NOTE",
    byOid[SAPKI_OID].critical === false && byOid[ALT_ALG_OID].critical === false &&
    byOid[ALT_VAL_OID].critical === false);

  // Clause 7.2.2 requires all three together, so the builder refuses the halves.
  check("B7: an alternative key with no subjectAltPublicKeyInfo is refused",
    (await codeAsync(pki.x509.sign({
      subject: "x", subjectPublicKey: subject.spki, serialNumber: 0x62n, notBefore: NB, notAfter: NA,
    }, { cert: nativeS.cert, key: nativeS.key, altKey: altPkcs8, altPublicKey: altSpki }))) === "x509/bad-input");
  check("B8: a subjectAltPublicKeyInfo with no alternative signing key is refused",
    (await codeAsync(pki.x509.sign({
      subject: "x", subjectPublicKey: subject.spki, serialNumber: 0x63n, notBefore: NB, notAfter: NA,
      extensions: { subjectAltPublicKeyInfo: subjAltSpki },
    }, { cert: nativeS.cert, key: nativeS.key }))) === "x509/bad-input");
  // Both alternative key positions are held to being a SubjectPublicKeyInfo, and by the same code the
  // native subjectPublicKey is: one rule for every key this verb is handed.
  check("B9: a subject alternative key that is not an SPKI is refused",
    (await codeAsync(pki.x509.sign({
      subject: "x", subjectPublicKey: subject.spki, serialNumber: 0x64n, notBefore: NB, notAfter: NA,
      extensions: { subjectAltPublicKeyInfo: Buffer.from([5, 0]) },
    }, { cert: nativeS.cert, key: nativeS.key, altKey: altPkcs8, altPublicKey: altSpki }))) === "x509/bad-spki");
  check("B9a: an issuer alternative public key that is not an SPKI is refused the same way",
    (await codeAsync(pki.x509.sign({
      subject: "x", subjectPublicKey: subject.spki, serialNumber: 0x64n, notBefore: NB, notAfter: NA,
      extensions: { subjectAltPublicKeyInfo: subjAltSpki },
    }, { cert: nativeS.cert, key: nativeS.key, altKey: altPkcs8, altPublicKey: Buffer.from([5, 0]) }))) === "x509/bad-spki");
  check("B9b: an altKey with no altPublicKey is refused, there being nothing to resolve the algorithm from",
    (await codeAsync(pki.x509.sign({
      subject: "x", subjectPublicKey: subject.spki, serialNumber: 0x64n, notBefore: NB, notAfter: NA,
      extensions: { subjectAltPublicKeyInfo: subjAltSpki },
    }, { cert: nativeS.cert, key: nativeS.key, altKey: altPkcs8 }))) === "x509/bad-input");
  check("B9c: naming altSignatureAlgorithm by hand is refused, it being resolved from the key",
    (await codeAsync(pki.x509.sign({
      subject: "x", subjectPublicKey: subject.spki, serialNumber: 0x64n, notBefore: NB, notAfter: NA,
      extensions: { subjectAltPublicKeyInfo: subjAltSpki, altSignatureAlgorithm: b.sequence([b.oid(O("id-ml-dsa-65"))]) },
    }, { cert: nativeS.cert, key: nativeS.key, altKey: altPkcs8, altPublicKey: altSpki }))) === "x509/bad-input");
  check("B10: naming altSignatureValue by hand is refused, the builder computing it",
    (await codeAsync(pki.x509.sign({
      subject: "x", subjectPublicKey: subject.spki, serialNumber: 0x65n, notBefore: NB, notAfter: NA,
      extensions: { subjectAltPublicKeyInfo: subjAltSpki, altSignatureValue: Buffer.alloc(64) },
    }, { cert: nativeS.cert, key: nativeS.key, altKey: altPkcs8, altPublicKey: altSpki }))) === "x509/bad-input");

  // A self-signed Catalyst certificate: the issuer's alternative key is the subject's own.
  var selfDer = await pki.x509.sign({
    subject: "self.example", subjectPublicKey: nativeS.spki, serialNumber: 0x66n, notBefore: NB, notAfter: NA,
    extensions: { subjectAltPublicKeyInfo: altSpki },
  }, { key: nativeS.key, altKey: altPkcs8, altPublicKey: altSpki });
  check("B11: a self-signed Catalyst certificate verifies under the key it certifies",
    (await pki.altSig.verify(selfDer, altSpki)) === true);

  // Every algorithm class the toolkit signs with, as the alternative one.
  var kinds = ["ml-dsa-44", "ml-dsa-87", "ed25519", "rsa"];
  for (var i = 0; i < kinds.length; i++) {
    var kp = kinds[i] === "rsa" ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
      : crypto.generateKeyPairSync(kinds[i]);
    var sp = kp.publicKey.export({ format: "der", type: "spki" });
    var pk = kp.privateKey.export({ format: "der", type: "pkcs8" });
    var d = await pki.x509.sign({
      subject: "alt." + kinds[i], subjectPublicKey: subject.spki, serialNumber: BigInt(0x70 + i),
      notBefore: NB, notAfter: NA, extensions: { subjectAltPublicKeyInfo: sp },
    }, { cert: nativeS.cert, key: nativeS.key, altKey: pk, altPublicKey: sp });
    check("B12." + (i + 1) + ": an alternative signature by a " + kinds[i] + " key verifies",
      (await pki.altSig.verify(d, sp)) === true);
  }
  // The alternative CHAIN, which is the mechanism's whole point: a leaf's alternative signature is
  // verified with the key read out of the ISSUER's subjectAltPublicKeyInfo (clause 9.8.4), so a relying
  // party that has migrated follows a second chain of its own using the same certificates.
  var leafAltKp = crypto.generateKeyPairSync("ml-dsa-65");
  var leafAltSpki = leafAltKp.publicKey.export({ format: "der", type: "spki" });
  var chainLeaf = await pki.x509.sign({
    subject: "chain-leaf.example", subjectPublicKey: subject.spki, serialNumber: 0x90n, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], subjectAltPublicKeyInfo: leafAltSpki },
  }, { cert: caDer, key: ca.key, altKey: altPkcs8, altPublicKey: altSpki });
  check("B13: a leaf's alternative signature verifies under the key read from its ISSUER's certificate",
    (await pki.altSig.verify(chainLeaf, pki.altSig.subjectAltPublicKey(caDer))) === true);
  check("B14: and not under the leaf's own alternative key, which signed nothing",
    (await pki.altSig.verify(chainLeaf, leafAltSpki)) === false);
  check("B15: the leaf certifies the alternative key it was asked to, not the issuer's",
    Buffer.compare(pki.altSig.subjectAltPublicKey(chainLeaf), leafAltSpki) === 0 &&
    Buffer.compare(pki.altSig.subjectAltPublicKey(chainLeaf), altSpki) !== 0);
  // A relying party that has not migrated reads the native signature and ignores the extensions, so a
  // Catalyst certificate must validate exactly as a plain one does. The plain chain is the control:
  // without it, a `true` here could not be told from a validator that ignores everything.
  var at = new Date(NB.getTime() + 86400000);
  var plainCa = await pki.x509.sign({
    subject: "Plain CA", subjectPublicKey: ca.spki, serialNumber: 0x92n, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: ca.key });
  var plainLeaf = await pki.x509.sign({
    subject: "plain-leaf.example", subjectPublicKey: subject.spki, serialNumber: 0x93n, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"] },
  }, { cert: plainCa, key: ca.key });
  check("B16: the native path validates a Catalyst leaf against its Catalyst anchor",
    (await pki.path.validate([chainLeaf], { trustAnchors: [caDer], time: at })).valid === true);
  check("B17: and the same holds for a plain chain, so the validator is not just passing everything",
    (await pki.path.validate([plainLeaf], { trustAnchors: [plainCa], time: at })).valid === true);
  check("B18: a Catalyst leaf under the WRONG anchor still fails, so the extensions did not disable a check",
    (await pki.path.validate([chainLeaf], { trustAnchors: [plainCa], time: at })).valid === false);

  return { nativeS: nativeS, altPkcs8: altPkcs8, altSpki: altSpki, caDer: caDer, ca: ca };
}

// ---- CRLs (clause 7.10.3) --------------------------------------------------

async function testCrl(ctx) {
  var crlDer = await pki.crl.sign({
    thisUpdate: NB, nextUpdate: NA, crlNumber: 1n,
    revoked: [{ serialNumber: 9n, revocationDate: NB }],
  }, { cert: ctx.nativeS.cert, key: ctx.nativeS.key, altKey: ctx.altPkcs8, altPublicKey: ctx.altSpki });
  check("C1: pki.crl.sign emits a CRL carrying the two alternative extensions", Buffer.isBuffer(crlDer));
  var parsed = pki.schema.crl.parse(crlDer);
  var oids = (parsed.crlExtensions || []).map(function (e) { return e.oid; });
  check("C2: altSignatureAlgorithm and altSignatureValue are present, and subjectAltPublicKeyInfo is not",
    oids.indexOf(ALT_ALG_OID) !== -1 && oids.indexOf(ALT_VAL_OID) !== -1 && oids.indexOf(SAPKI_OID) === -1);
  check("C3: the alternative signature over the CRL verifies, clause 7.10.3 giving the same procedure",
    (await pki.altSig.verify(crlDer, ctx.altSpki)) === true);
  check("C4: and does not verify under another key",
    (await pki.altSig.verify(crlDer, crypto.generateKeyPairSync("ml-dsa-65").publicKey.export({ format: "der", type: "spki" }))) === false);
  check("C5: the preimage is the CRL with its outer signature and altSignatureValue removed",
    pki.asn1.decode(pki.altSig.signedData(crlDer)).children.length === 2);
  check("C6: subjectAltPublicKey refuses a CRL, the extension being certificate-only",
    code(function () { pki.altSig.subjectAltPublicKey(crlDer); }) === "altsig/absent");
}

// ---- lint ------------------------------------------------------------------

async function testLint(ctx) {
  function rows(der, prefix) {
    return pki.lint.certificate(der, { profile: "x509-altsig" }).findings
      .filter(function (f) { return f.id.indexOf(prefix) === 0; });
  }
  var good = await pki.x509.sign({
    subject: "lint.example", subjectPublicKey: ctx.nativeS.spki, serialNumber: 0x80n, notBefore: NB, notAfter: NA,
    extensions: { subjectAltPublicKeyInfo: ctx.altSpki },
  }, { cert: ctx.nativeS.cert, key: ctx.nativeS.key, altKey: ctx.altPkcs8, altPublicKey: ctx.altSpki });
  check("L1: a conforming Catalyst certificate draws no finding", rows(good, "lint/x509-altsig/").length === 0);
  check("L2: a certificate with none of the extensions draws no finding, so nothing fires on absence",
    rows(ctx.nativeS.cert, "lint/x509-altsig/").length === 0);

  // Clause 9.8.3: "When the altSignatureAlgorithm extension is included ... the altSignatureValue
  // extension shall also be included." A shall, so this one is an error.
  var noValue = makeCatalyst({ serial: 0x81, omitAltValue: true }).der;
  var r1 = rows(noValue, "lint/x509-altsig/algorithm-without-value");
  check("L3: altSignatureAlgorithm without altSignatureValue is graded, at error",
    r1.length === 1 && r1[0].severity === "error");

  // Clause 7.2.2 requires all three in a certificate that carries the mechanism.
  var noSapki = makeCatalyst({ serial: 0x82, omitSapki: true }).der;
  var r2 = rows(noSapki, "lint/x509-altsig/incomplete-set");
  check("L4: a certificate missing subjectAltPublicKeyInfo is graded, at error",
    r2.length === 1 && r2[0].severity === "error");

  // Clause 9.8.2/9.8.3 state criticality in a NOTE, weaker than a SHOULD, so a critical one is graded
  // at the lowest strength the linter has and never as an error.
  var crit = makeCatalyst({ serial: 0x83, criticalSapki: true }).der;
  var r3 = rows(crit, "lint/x509-altsig/critical");
  check("L5: a critical extension is graded below error, clause 9.8 stating criticality in a NOTE",
    r3.length === 1 && r3[0].severity !== "error");
}

// ---- inspection ------------------------------------------------------------

function testInspect() {
  var c = makeCatalyst({ serial: 0x91 });
  var txt = pki.inspect.certificate(c.der);
  check("I1: all three extensions are named rather than hex-dumped",
    txt.indexOf("subjectAltPublicKeyInfo:") !== -1 && txt.indexOf("altSignatureAlgorithm:") !== -1 &&
    txt.indexOf("altSignatureValue:") !== -1);
  check("I2: the alternative key is reported by its algorithm and its length",
    txt.indexOf("Algorithm: id-ml-dsa-65") !== -1 &&
    txt.indexOf("Alternative Public Key: " + c.altSpki.length + " bytes") === -1 &&
    txt.indexOf("Alternative Public Key: 1952 bytes") !== -1);
  check("I3: the alternative signature algorithm is named",
    txt.indexOf("altSignatureAlgorithm:\n") !== -1 || /altSignatureAlgorithm:[\s\S]{0,40}id-ml-dsa-65/.test(txt));
  check("I4: the alternative signature is reported by length, not dumped whole",
    txt.indexOf("Alternative Signature: " + c.altSig.length + " bytes") !== -1 &&
    txt.indexOf(c.altSig.subarray(0, 16).toString("hex").toUpperCase()) === -1);
  check("I5: a certificate carrying none of them renders without those labels",
    pki.inspect.certificate(signing.makeSigner("ec-p256").cert).indexOf("altSignature") === -1);
}

// ---- the OUTER alternative-signature fields, which the 2019 text forbids ----
//
// X.509 (2019) extended the SIGNED parameterized type itself, at an extension marker, with two more
// optional components AFTER the native signature:
//
//   SIGNED{ToBeSigned} ::= SEQUENCE {
//     toBeSigned ToBeSigned, COMPONENTS OF SIGNATURE, ...,
//     [[4: altAlgorithmIdentifier AlgorithmIdentifier{{SupportedAltAlgorithms}} OPTIONAL,
//          altSignature BIT STRING OPTIONAL]] }
//
// so an alternative signature could in principle ride in the outer SEQUENCE rather than in an
// extension. The same edition then forbids it, in one sentence repeated once per structure it
// profiles: "When generating a digital signature using the SIGNED parameterized data type, only one
// digital signature shall be generated, i.e., the altAlgorithmIdentifier and the altSignature
// components shall be absent." That sentence appears in clause 7.2.1 (certificate), 7.10.2 (CRL),
// 11.3 (authorization and validation list) and 14.2 (attribute certificate).
//
// The shared signed envelope already fixes the outer arity at three, so every structure composing it
// refuses these components in one place. Nothing here asserted that, which is the gap these vectors
// close: a rule the specification states as a shall, and a reader that honors it only as long as one
// shared arity stays exact.
async function testOuterAltFieldsRefused() {
  var s = signing.makeSigner("ec-p256");
  var ca = await pki.x509.sign({
    subject: "Envelope CA", subjectPublicKey: s.spki, serialNumber: 0xa0n, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: s.key });
  var crl = await pki.crl.sign({ thisUpdate: NB, nextUpdate: NA, crlNumber: 1n }, { cert: ca, key: s.key });
  var csr = await pki.csr.sign({ subject: "envelope.example", subjectPublicKey: s.spki }, { key: s.key });
  var ac = await pki.attrcert.sign({
    holder: { entityName: { directoryName: "CN=Alice" } }, notBeforeTime: NB, notAfterTime: NA,
    attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } },
  }, { name: "CN=Example AA", publicKey: s.spki, key: s.key });

  // The two components appended to a structure that is otherwise valid and would parse.
  function appended(der, howMany) {
    var n = pki.asn1.decode(der);
    var kids = [b.raw(n.children[0].bytes), b.raw(n.children[1].bytes), b.raw(n.children[2].bytes)];
    if (howMany >= 1) kids.push(b.sequence([b.oid(O("id-ml-dsa-65"))]));
    if (howMany >= 2) kids.push(b.bitString(Buffer.alloc(64, 7), 0));
    return b.sequence(kids);
  }

  var subjects = [
    ["a certificate", ca, function (d) { return pki.schema.x509.parse(d); }, "x509/not-a-certificate"],
    ["a CRL", crl, function (d) { return pki.schema.crl.parse(d); }, "crl/not-a-crl"],
    ["a certification request", csr, function (d) { return pki.schema.csr.parse(d); }, "csr/not-a-certification-request"],
    ["an attribute certificate", ac, function (d) { return pki.schema.attrcert.parse(d); }, "attrcert/not-an-attribute-certificate"],
  ];
  subjects.forEach(function (row, i) {
    // A passing control on the same route: the structure parses before the components are appended, so
    // a refusal below is the appended components and not a broken fixture.
    check("S" + (i + 1) + ".0: " + row[0] + " parses before the outer components are appended",
      code(function () { return row[2](row[1]); }) === "NO-THROW");
    check("S" + (i + 1) + ".1: " + row[0] + " carrying altAlgorithmIdentifier and altSignature is refused",
      code(function () { return row[2](appended(row[1], 2)); }) === row[3]);
    check("S" + (i + 1) + ".2: and carrying altAlgorithmIdentifier alone is refused, the two being both-or-neither",
      code(function () { return row[2](appended(row[1], 1)); }) === row[3]);
    check("S" + (i + 1) + ".3: the format detector does not route " + row[0] + " with them either",
      code(function () { return pki.schema.parse(appended(row[1], 2)); }) === "schema/unknown-format");
  });
}

async function run() {
  testSurface();
  testPreimage();
  await testVerify();
  var dctx = testDecode();
  await testDecodeRefusals(dctx);
  var bctx = await testBuilder();
  await testCrl(bctx);
  await testLint(bctx);
  testInspect();
  await testOuterAltFieldsRefused();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
