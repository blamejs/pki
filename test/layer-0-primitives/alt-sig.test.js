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
// altSignatureAlgorithm extension". Two members are named `signature`, the outer BIT STRING and the
// toBeSigned's own AlgorithmIdentifier, and the clause names neither.
//
// draft-truskovsky-lamps-pq-hybrid-x509 gives the excluded one a type: the PreTBSCertificate of section
// 4 is the tbsCertificate without "the signature field (the third element in the TBSCertificate
// sequence)", and the PreTBSCertList of section 5 is the tbsCertList without its second element. So the
// preimage is the toBeSigned alone, carrying one member fewer, with the altSignatureValue extension
// removed and the order of the remaining extensions unchanged. Clause 7.2.2 is explicit that a verifier
// has to rebuild it:
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

// A copy of a certificate carrying one of its extensions TWICE, reassembled around the extension's own raw
// bytes rather than re-encoded. The signature no longer covers the result, which is the point: the
// structural refusal has to come before any signature is checked, so the code that comes back names the
// malformed structure rather than a bad signature.
function _duplicateExtension(der, extOid) {
  var root = pki.asn1.decode(der);
  var tbs = root.children[0];
  var tagged = null, taggedIndex = -1;
  for (var i = tbs.children.length - 1; i >= 0; i--) {
    var k = tbs.children[i];
    if (k.tagClass === "context" && k.tagNumber === 3) { tagged = k; taggedIndex = i; break; }
  }
  if (tagged === null) return null;
  var exts = tagged.children[0];
  var parts = [], found = false;
  for (var e = 0; e < exts.children.length; e++) {
    var one = exts.children[e];
    parts.push(one.bytes);
    if (pki.asn1.read.oid(one.children[0]) === extOid) { parts.push(one.bytes); found = true; }
  }
  if (!found) return null;
  var newTagged = b.explicit(3, b.sequence([b.raw(Buffer.concat(parts))]));
  var keptTbs = [];
  for (var t = 0; t < tbs.children.length; t++) {
    if (t !== taggedIndex) keptTbs.push(tbs.children[t].bytes);
  }
  var newTbs = b.sequence([b.raw(Buffer.concat(keptTbs)), b.raw(newTagged)]);
  return b.sequence([b.raw(newTbs), b.raw(root.children[1].bytes), b.raw(root.children[2].bytes)]);
}

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

  // `withSignatureAlg` of false omits the `signature` AlgorithmIdentifier, which is what separates the
  // PreTBSCertificate from the TBSCertificate.
  function fieldsOf(withAltValue, withSignatureAlg) {
    var exts = (opts.extraExts || []).slice();
    if (!opts.omitSapki) exts.push(ext(SAPKI_OID, opts.criticalSapki === true, altSpki));
    if (!opts.omitAltAlg) exts.push(ext(ALT_ALG_OID, false, altAlgId));
    if (withAltValue && !opts.omitAltValue) exts.push(ext(ALT_VAL_OID, false, b.bitString(withAltValue, 0)));
    var fields = [b.explicit(0, b.integer(2n)), b.integer(BigInt(opts.serial || 0x11))];
    if (withSignatureAlg) fields.push(nativeAlgId);
    fields.push(name, VALIDITY, name, b.raw(nativeSpki));
    if (exts.length) fields.push(b.explicit(3, b.sequence(exts)));
    return b.sequence(fields);
  }
  function tbs(withAltValue) { return fieldsOf(withAltValue, true); }

  // draft-truskovsky-lamps-pq-hybrid-x509 sec. 4: the alternative signature covers the
  // PreTBSCertificate, the TBSCertificate without its `signature` AlgorithmIdentifier and without the
  // altSignatureValue extension.
  var preimage = fieldsOf(null, false);
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
  check("P1: the preimage is the PreTBSCertificate, the toBeSigned without its signature field and without altSignatureValue",
    Buffer.compare(got, c.preimage) === 0);

  // Every byte of a kept component is the byte that was there. Removing a member changes two SEQUENCE
  // headers and nothing else, so the retained fields must be byte-identical.
  var origTbs = pki.asn1.decode(c.der).children[0];
  var newTbs = pki.asn1.decode(got);
  check("P2: it is the toBeSigned alone, carrying one member fewer than the tbsCertificate",
    origTbs.children.length === 8 && newTbs.children.length === 7);
  check("P3: the member it loses is the signature AlgorithmIdentifier, so no AlgorithmIdentifier sits at the third element",
    Buffer.compare(origTbs.children[2].bytes, c.nativeAlgId) === 0 &&
    newTbs.children.every(function (n) { return Buffer.compare(n.bytes, c.nativeAlgId) !== 0; }));
  check("P4: every other field is carried byte-identically, in order",
    [0, 1].every(function (i) { return Buffer.compare(origTbs.children[i].bytes, newTbs.children[i].bytes) === 0; }) &&
    [3, 4, 5, 6].every(function (i) { return Buffer.compare(origTbs.children[i].bytes, newTbs.children[i - 1].bytes) === 0; }));
  var origExts = origTbs.children[7].children[0].children;
  var newExts = newTbs.children[6].children[0].children;
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

  // Every algorithm class the toolkit signs with, as the alternative one. Each algorithm needs its own
  // issuing CA, because an alternative signature is bound to the alternative key the ISSUER's certificate
  // publishes: signing a leaf under a key the issuer does not publish would emit a certificate no relying
  // party could check, and is refused. So the CA is self-signed with the algorithm under test as its own
  // alternative key, and the leaf is then issued from it.
  var kinds = ["ml-dsa-44", "ml-dsa-87", "ed25519", "rsa"];
  for (var i = 0; i < kinds.length; i++) {
    var kp = kinds[i] === "rsa" ? crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })
      : crypto.generateKeyPairSync(kinds[i]);
    var sp = kp.publicKey.export({ format: "der", type: "spki" });
    var pk = kp.privateKey.export({ format: "der", type: "pkcs8" });
    var kindCa = signing.makeSigner("ec-p256");
    var kindCaDer = await pki.x509.sign({
      subject: "Alt CA " + kinds[i], subjectPublicKey: kindCa.spki, serialNumber: BigInt(0x80 + i),
      notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
        subjectAltPublicKeyInfo: sp },
    }, { key: kindCa.key, altKey: pk, altPublicKey: sp });
    var d = await pki.x509.sign({
      subject: "alt." + kinds[i], subjectPublicKey: subject.spki, serialNumber: BigInt(0x70 + i),
      notBefore: NB, notAfter: NA, extensions: { subjectAltPublicKeyInfo: sp },
    }, { cert: kindCaDer, key: kindCa.key, altKey: pk, altPublicKey: sp });
    check("B12." + (i + 1) + ": an alternative signature by a " + kinds[i] + " key verifies",
      (await pki.altSig.verify(d, sp)) === true);
    check("B12." + (i + 1) + "a: and it verifies under the key read off the issuer's own certificate",
      (await pki.altSig.verify(d, pki.altSig.subjectAltPublicKey(kindCaDer))) === true);
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
  // A CRL's version is a bare INTEGER rather than a tagged field, so its `signature` AlgorithmIdentifier
  // is the SECOND element and not the third. The preimage drops that one.
  var crlTbs = pki.asn1.decode(crlDer).children[0];
  var crlPre = pki.asn1.decode(pki.altSig.signedData(crlDer));
  var crlAlgId = pki.asn1.decode(crlDer).children[1].bytes;
  check("C5: the preimage is the PreTBSCertList, carrying one member fewer than the tbsCertList",
    crlPre.children.length === crlTbs.children.length - 1);
  check("C5a: and the member it loses is the signature AlgorithmIdentifier at the second element",
    Buffer.compare(crlTbs.children[1].bytes, crlAlgId) === 0 &&
    crlPre.children.every(function (n) { return Buffer.compare(n.bytes, crlAlgId) !== 0; }));
  check("C6: subjectAltPublicKey refuses a CRL, the extension being certificate-only",
    code(function () { pki.altSig.subjectAltPublicKey(crlDer); }) === "altsig/absent");
}

// The alternative signature is checked against the alternative public key BEFORE it is emitted, which is
// the gate the native pass has always had. Without it, an altKey and an altPublicKey that are different
// keys of the same algorithm sign and emit without complaint, and what ships is a certificate whose
// alternative signature does not verify under the key the certificate itself names. The two keys have to
// share an algorithm for this to be the defect rather than an algorithm mismatch: a different algorithm
// is caught when the scheme is resolved, and the vector would then pass without reaching the gate.
async function testAltKeyPairMismatchRefused(ctx) {
  var ca = signing.makeSigner("ec-p256", { cn: "Mismatch CA", serial: 0x70 });
  var altA = crypto.generateKeyPairSync("ml-dsa-65");
  var altB = crypto.generateKeyPairSync("ml-dsa-65");
  var aPkcs8 = altA.privateKey.export({ format: "der", type: "pkcs8" });
  var aSpki = altA.publicKey.export({ format: "der", type: "spki" });
  var bSpki = altB.publicKey.export({ format: "der", type: "spki" });
  var subject = signing.makeSigner("ec-p256");
  var subjAltSpki = crypto.generateKeyPairSync("ml-dsa-65").publicKey.export({ format: "der", type: "spki" });

  // CONTROL: the matching pair signs, so a refusal below is about the mismatch and not about the setup.
  var okDer = await pki.x509.sign({
    subject: "Mismatch CA", subjectPublicKey: ca.spki, serialNumber: 0x70n, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
      subjectAltPublicKeyInfo: aSpki },
  }, { key: ca.key, altKey: aPkcs8, altPublicKey: aSpki });
  check("M0: CONTROL an altKey matching its altPublicKey signs and verifies",
    (await pki.altSig.verify(okDer, aSpki)) === true);

  // Detecting which FORMAT the bytes are is not the same as their being a well-formed one of it. A
  // certificate carrying the altSignatureValue extension twice passed the detector, the verb read the first
  // and the preimage builder removed both, so an ambiguous certificate the shared parser refuses received a
  // successful verdict. The structure is parsed now, so the rules the shared parser enforces hold here.
  var dupExt = _duplicateExtension(okDer, pki.oid.byName("altSignatureValue"));
  check("M0a: the spliced certificate really carries the extension twice, and the shared parser refuses it",
    dupExt !== null && code(function () { return pki.schema.x509.parse(dupExt); }) === "x509/duplicate-extension");
  check("M0b: a certificate carrying altSignatureValue twice is refused rather than verified",
    (await codeAsync(pki.altSig.verify(dupExt, aSpki))) === "altsig/bad-input");

  check("M1: a certificate whose altKey is not the altPublicKey's private half is refused",
    (await codeAsync(pki.x509.sign({
      subject: "leaf.example", subjectPublicKey: subject.spki, serialNumber: 0x71n,
      notBefore: NB, notAfter: NA,
      extensions: { subjectAltPublicKeyInfo: subjAltSpki },
    }, { cert: okDer, key: ca.key, altKey: aPkcs8, altPublicKey: bSpki }))) === "x509/bad-input");

  check("M2: and a CRL under the same mismatched pair is refused, the rule reaching both signers",
    (await codeAsync(pki.crl.sign({
      thisUpdate: NB, nextUpdate: NA, crlNumber: 2n,
      revoked: [{ serialNumber: 7n, revocationDate: NB }],
    }, { cert: okDer, key: ca.key, altKey: aPkcs8, altPublicKey: bSpki }))) === "crl/bad-input");

  // CONTROL for M2: the matching pair produces a CRL whose alternative signature verifies, so M2's
  // refusal is the gate firing rather than the CRL path being broken for this issuer.
  var okCrl = await pki.crl.sign({
    thisUpdate: NB, nextUpdate: NA, crlNumber: 3n,
    revoked: [{ serialNumber: 7n, revocationDate: NB }],
  }, { cert: okDer, key: ca.key, altKey: aPkcs8, altPublicKey: aSpki });
  check("M3: CONTROL the matching pair emits a CRL that verifies under that key",
    (await pki.altSig.verify(okCrl, aSpki)) === true);

  // A self-consistent alt pair is not enough: it also has to be the pair the ISSUER CERTIFICATE
  // publishes. The native signature is bound that way already, its key being read out of issuer.cert,
  // while the alternative key is supplied beside the certificate and was never compared to it. A CA that
  // signs with a second alt pair emits a certificate that verifies under no key any relying party can
  // find: clause 9.8.4 checks an alternative signature with the issuer's alternative public key, and the
  // issuer's certificate names A while the signature was made with B.
  var otherAlt = crypto.generateKeyPairSync("ml-dsa-65");
  var otherPkcs8 = otherAlt.privateKey.export({ format: "der", type: "pkcs8" });
  var otherSpki = otherAlt.publicKey.export({ format: "der", type: "spki" });
  check("M4: a certificate signed with an alt pair the issuer certificate does not publish is refused",
    (await codeAsync(pki.x509.sign({
      subject: "leaf.example", subjectPublicKey: subject.spki, serialNumber: 0x72n,
      notBefore: NB, notAfter: NA,
      extensions: { subjectAltPublicKeyInfo: subjAltSpki },
    }, { cert: okDer, key: ca.key, altKey: otherPkcs8, altPublicKey: otherSpki }))) === "x509/bad-input");
  check("M5: and a CRL under that same second pair is refused, the rule reaching both signers",
    (await codeAsync(pki.crl.sign({
      thisUpdate: NB, nextUpdate: NA, crlNumber: 4n,
      revoked: [{ serialNumber: 8n, revocationDate: NB }],
    }, { cert: okDer, key: ca.key, altKey: otherPkcs8, altPublicKey: otherSpki }))) === "crl/bad-input");

  // An issuer certificate that publishes NO alternative key cannot have signed with one either: a
  // relying party has nothing to check the alternative signature against.
  var plainCa = await pki.x509.sign({
    subject: "Plain CA", subjectPublicKey: ca.spki, serialNumber: 0x73n, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: ca.key });
  check("M6: an issuer certificate publishing no alternative key cannot sign an alternative signature",
    (await codeAsync(pki.x509.sign({
      subject: "leaf.example", subjectPublicKey: subject.spki, serialNumber: 0x74n,
      notBefore: NB, notAfter: NA,
      extensions: { subjectAltPublicKeyInfo: subjAltSpki },
    }, { cert: plainCa, key: ca.key, altKey: aPkcs8, altPublicKey: aSpki }))) === "x509/bad-input");

  // CONTROL: signing under the pair the issuer certificate DOES publish still works, and what comes out
  // verifies under the key read off that certificate, which is the whole point of the binding.
  var bound = await pki.x509.sign({
    subject: "leaf.example", subjectPublicKey: subject.spki, serialNumber: 0x75n,
    notBefore: NB, notAfter: NA,
    extensions: { subjectAltPublicKeyInfo: subjAltSpki },
  }, { cert: okDer, key: ca.key, altKey: aPkcs8, altPublicKey: aSpki });
  check("M7: CONTROL a certificate signed with the published pair verifies under the issuer's own alt key",
    (await pki.altSig.verify(bound, pki.altSig.subjectAltPublicKey(okDer))) === true);

  // A root is self-signed whether the caller says so by omitting the issuer entirely or by naming an
  // issuer whose name and key are the subject's. Both produce a certificate that publishes its own
  // alternative key, so both are held to signing with it; a rule that reads only the omitted form leaves
  // the explicit one emitting a root that does not verify under the key it publishes.
  var rootName = [{ commonName: "Explicit Self Signed" }];
  check("M8: an explicit self-issued root signing with an alt key it does not publish is refused",
    (await codeAsync(pki.x509.sign({
      subject: rootName, subjectPublicKey: ca.spki, serialNumber: 0x76n, notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
        subjectAltPublicKeyInfo: aSpki },
    }, { name: rootName, publicKey: ca.spki, key: ca.key,
      altKey: otherPkcs8, altPublicKey: otherSpki }))) === "x509/bad-input");
  var explicitRoot = await pki.x509.sign({
    subject: rootName, subjectPublicKey: ca.spki, serialNumber: 0x77n, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
      subjectAltPublicKeyInfo: aSpki },
  }, { name: rootName, publicKey: ca.spki, key: ca.key, altKey: aPkcs8, altPublicKey: aSpki });
  check("M9: CONTROL the same explicit root signing with the key it publishes verifies under it",
    (await pki.altSig.verify(explicitRoot, pki.altSig.subjectAltPublicKey(explicitRoot))) === true);
  return ctx;
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

// ---- the preimage another implementation computes --------------------------
//
// draft-truskovsky-lamps-pq-hybrid-x509 states the preimage as a type of its own rather than as prose
// about which component to drop, and the definition is element-by-element:
//
//   PreTBSCertificate  ::=  SEQUENCE  {
//        version              [0]  EXPLICIT Version DEFAULT v1,
//        serialNumber              CertificateSerialNumber,
//        issuer                    Name,
//        validity                  Validity,
//        subject                   Name,
//        subjectPublicKeyInfo      SubjectPublicKeyInfo,
//        issuerUniqueID       [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//        subjectUniqueID      [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//        extensions           [3]  EXPLICIT Extensions OPTIONAL  }
//
// "The PreTBSCertificate type is similar to the TBSCertificate type, except that the PreTBSCertificate
// does not include the signature field (the third element in the TBSCertificate sequence). In a
// TBSCertificate the signature field contains the AlgorithmIdentifier of the algorithm which will be
// used to sign the final certificate, and this value might not be known at the time that the
// alternative signature is calculated." Section 5 defines PreTBSCertList the same way for a CRL, where
// the signature field is the SECOND element.
//
// Both procedures add the signature field in a step AFTER the alternative signature is computed, so at
// the time it is computed the toBeSigned does not carry one.
//
// The vectors here rebuild the preimage from a structure's own bytes, following section 4.2 steps (a)
// to (d): decode the toBeSigned, remove altSignatureValue, remove the signature field, DER encode. The
// reconstruction is independent of the implementation, and `crypto.verify` checks the carried signature
// against it directly, so a pass means the bytes this toolkit emits are the bytes an implementation
// following that definition rebuilds. Bouncy Castle is that implementation: its generator signs
// `generatePreTBSCertificate()` after `tbsGen.setSignature(null)`, and
// `X509CertificateHolder.isAlternativeSignatureValid` rebuilds every toBeSigned element except index 2
// with altSignatureValue trimmed.

// `sigIndex` of -1 keeps the signature field, which builds the other reading of the clause for the
// refusal vectors. A `replaceAltValue` of null drops the extension, as both readings do.
function _rebuildTbs(der, sigIndex, extTag, replaceAltValue) {
  var tbs = pki.asn1.decode(der).children[0];
  var out = [];
  tbs.children.forEach(function (k, i) {
    if (i === sigIndex) return;
    if (!(k.tagClass === "context" && k.tagNumber === extTag)) { out.push(k.bytes); return; }
    var kept = [];
    k.children[0].children.forEach(function (e) {
      if (pki.asn1.read.oid(e.children[0]) !== ALT_VAL_OID) { kept.push(e.bytes); return; }
      if (replaceAltValue !== null) kept.push(ext(ALT_VAL_OID, false, b.bitString(replaceAltValue, 0)));
    });
    out.push(b.explicit(extTag, b.sequence([b.raw(Buffer.concat(kept))])));
  });
  return b.sequence([b.raw(Buffer.concat(out))]);
}

// The signature field is located where its type places it, which differs between the two structures:
// a certificate's version is `[0] EXPLICIT` so the field is the third element, while a CRL's version is
// a bare INTEGER so it is the second.
function _signatureIndex(der, kind) {
  var kids = pki.asn1.decode(der).children[0].children;
  if (kind === "certificate") {
    return (kids[0].tagClass === "context" && kids[0].tagNumber === 0) ? 2 : 1;
  }
  return (kids[0].tagClass === "universal" && kids[0].tagNumber === pki.asn1.TAGS.INTEGER) ? 1 : 0;
}

function _preTbsOf(der, kind, extTag) {
  return _rebuildTbs(der, _signatureIndex(der, kind), extTag, null);
}

// The whole structure minus its outer signature BIT STRING, with the signature field retained: the
// reading in which `signature` names the outer component rather than the toBeSigned's own field.
function _wholeStructureForm(der, extTag) {
  return b.sequence([
    b.raw(_rebuildTbs(der, -1, extTag, null)),
    b.raw(pki.asn1.decode(der).children[1].bytes),
  ]);
}

// The alternative signature a structure carries, read out of its extension.
function _carriedAltSignature(der, extTag) {
  var kids = pki.asn1.decode(der).children[0].children;
  for (var i = kids.length - 1; i >= 0; i--) {
    var k = kids[i];
    if (!(k.tagClass === "context" && k.tagNumber === extTag)) continue;
    var list = k.children[0].children;
    for (var e = 0; e < list.length; e++) {
      if (pki.asn1.read.oid(list[e].children[0]) !== ALT_VAL_OID) continue;
      var value = pki.asn1.read.octetString(list[e].children[list[e].children.length - 1]);
      return pki.asn1.read.bitString(pki.asn1.decode(value)).bytes;
    }
  }
  return null;
}

// A copy of a structure whose altSignatureValue carries `sig`, everything else byte-identical. The
// native signature no longer covers it, which does not matter: these vectors drive the alternative
// signature alone, and the structural parser the verb runs first does not check the native one.
function _withAltSignature(der, extTag, sig) {
  var root = pki.asn1.decode(der);
  return b.sequence([
    b.raw(_rebuildTbs(der, -1, extTag, sig)),
    b.raw(root.children[1].bytes), b.raw(root.children[2].bytes),
  ]);
}

async function testPreTbsPreimage(ctx) {
  var spkiKey = { key: ctx.altSpki, format: "der", type: "spki" };
  var rows = [
    ["certificate", await pki.x509.sign({
      subject: "pretbs-leaf.example", subjectPublicKey: ctx.ca.spki, serialNumber: 0xa1n,
      notBefore: NB, notAfter: NA,
      extensions: { keyUsage: ["digitalSignature"], subjectAltPublicKeyInfo: ctx.altSpki },
    }, { cert: ctx.caDer, key: ctx.ca.key, altKey: ctx.altPkcs8, altPublicKey: ctx.altSpki }), 3],
    ["CRL", await pki.crl.sign({
      thisUpdate: NB, nextUpdate: NA, crlNumber: 0xa2n,
      revoked: [{ serialNumber: 0xa3n, revocationDate: NB }],
    }, { cert: ctx.caDer, key: ctx.ca.key, altKey: ctx.altPkcs8, altPublicKey: ctx.altSpki }), 0],
  ];

  for (var i = 0; i < rows.length; i++) {
    var kind = rows[i][0], der = rows[i][1], extTag = rows[i][2];
    var n = "T" + (i + 1);
    var pre = _preTbsOf(der, kind, extTag);
    var whole = _wholeStructureForm(der, extTag);
    var carried = _carriedAltSignature(der, extTag);

    check(n + ".0: CONTROL the " + kind + " carries an alternative signature to check at all",
      carried !== null && carried.length > 0);
    check(n + ".1: CONTROL the two readings of the clause are different bytes, so the rest distinguishes them",
      Buffer.compare(pre, whole) !== 0);

    // The toolkit's own answer for the bytes, and the independently rebuilt one.
    check(n + ".2: signedData returns the " + (kind === "CRL" ? "PreTBSCertList" : "PreTBSCertificate"),
      Buffer.compare(pki.altSig.signedData(der), pre) === 0);
    check(n + ".3: which drops the signature field, so the toBeSigned carries no AlgorithmIdentifier there",
      pki.asn1.decode(pre).children.length ===
        pki.asn1.decode(der).children[0].children.length - 1);
    check(n + ".4: and is the toBeSigned alone, not a SEQUENCE wrapping it and the outer algorithm",
      Buffer.compare(pki.altSig.signedData(der), whole) !== 0);

    // The interop fact, computed without this toolkit's verify path: the signature the structure
    // carries checks out against the independently rebuilt preimage.
    check(n + ".5: the carried signature verifies against the independently rebuilt preimage",
      crypto.verify(null, pre, crypto.createPublicKey(spkiKey), carried) === true);
    check(n + ".6: and does NOT verify against the other reading, the two being different bytes",
      crypto.verify(null, whole, crypto.createPublicKey(spkiKey), carried) === false);

    // The verb's own verdict on each form. A structure signed the other way is a signature that does
    // not cover these bytes, so it is refused rather than accepted under a second scope.
    check(n + ".7: the verb verifies a " + kind + " signed over the preimage it computes",
      (await pki.altSig.verify(_withAltSignature(der, extTag,
        crypto.sign(null, pre, crypto.createPrivateKey({ key: ctx.altPkcs8, format: "der", type: "pkcs8" })))
      , ctx.altSpki)) === true);
    check(n + ".8: and refuses one signed over the whole structure instead",
      (await pki.altSig.verify(_withAltSignature(der, extTag,
        crypto.sign(null, whole, crypto.createPrivateKey({ key: ctx.altPkcs8, format: "der", type: "pkcs8" })))
      , ctx.altSpki)) === false);
  }
}

async function run() {
  testSurface();
  testPreimage();
  await testVerify();
  var dctx = testDecode();
  await testDecodeRefusals(dctx);
  var bctx = await testBuilder();
  await testCrl(bctx);
  await testPreTbsPreimage(bctx);
  await testAltKeyPairMismatchRefused(bctx);
  await testLint(bctx);
  testInspect();
  await testOuterAltFieldsRefused();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
