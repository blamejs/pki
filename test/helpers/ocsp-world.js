// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// makeOcspWorld(alg) -- a real mini-CA for pki.ocsp tests. Unlike cms.verify (which skips the
// signer cert self-signature), pki.ocsp.verify VERIFIES the responder/delegate cert's issuance
// signature under the issuer key, so the fixture cannot use a dummy signature: it mints a real
// issuer that REALLY self-signs, a delegate whose tbs is REALLY signed by the issuer, and a target
// leaf issued by the issuer. Private keys are generated at runtime (CI gitleaks blocks committed
// PEM private keys). `alg` picks the RESPONDER key algorithm (the CA is always Ed25519, since it
// only signs certs); default "ec-p256".

var pki = require("../../index.js");
var b = pki.asn1.build;
var subtle = pki.webcrypto.subtle;
function O(n) { return pki.oid.byName(n); }

function nameDN(cn) { return b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable(cn)])])]); }
function ext(name, critical, innerDer) {
  var kids = [b.oid(O(name))];
  if (critical) kids.push(b.boolean(true));
  kids.push(b.octetString(innerDer));
  return b.sequence(kids);
}
var ED_ALGID = b.sequence([b.oid(O("Ed25519"))]);

// The extensions of a real issuing CA: basicConstraints cA:TRUE + a keyUsage asserting
// digitalSignature (bit 0) + keyCertSign (bit 5) + cRLSign (bit 6), both critical. A CA
// without cA:TRUE is rejected by an independent verifier (openssl ocsp: "invalid CA
// certificate"), so the mini-CA carries them to be cross-implementation valid.
function caExts() {
  return [
    ext("basicConstraints", true, b.sequence([b.boolean(true)])),
    ext("keyUsage", true, b.bitString(Buffer.from([0x86]), 1)),
  ];
}

// The WebCrypto gen/sign params + signatureAlgorithm for a responder algorithm key.
var RESP_ALG = {
  "ec-p256": { gen: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" }, sigOid: "ecdsaWithSHA256", p1363: 32 },
  "ec-p384": { gen: { name: "ECDSA", namedCurve: "P-384" }, sign: { name: "ECDSA", hash: "SHA-384" }, sigOid: "ecdsaWithSHA384", p1363: 48 },
  "rsa": { gen: { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, sign: { name: "RSASSA-PKCS1-v1_5" }, sigOid: "sha256WithRSAEncryption", nullParams: true },
  "ed25519": { gen: { name: "Ed25519" }, sign: { name: "Ed25519" }, sigOid: "Ed25519" },
  "ml-dsa-65": { gen: { name: "ML-DSA-65" }, sign: { name: "ML-DSA-65" }, sigOid: "id-ml-dsa-65" },
  "slh-dsa-sha2-128f": { gen: { name: "SLH-DSA-SHA2-128F" }, sign: { name: "SLH-DSA-SHA2-128F" }, sigOid: "id-slh-dsa-sha2-128f" },
};

// Sign a v3 cert's tbs with the Ed25519 issuer private key.
async function signCert(o) {
  var tbsKids = [
    b.explicit(0, b.integer(2n)),
    b.integer(BigInt(o.serial)),
    ED_ALGID,
    nameDN(o.issuerCN),
    b.sequence([b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(o.notAfter || new Date("2040-01-01T00:00:00Z"))]),
    o.emptySubject ? b.sequence([]) : nameDN(o.subjectCN),
    b.raw(o.spki),
  ];
  if (o.exts && o.exts.length) tbsKids.push(b.explicit(3, b.sequence(o.exts)));
  var tbs = b.sequence(tbsKids);
  var sig = Buffer.from(await subtle.sign({ name: "Ed25519" }, o.issuerKey, tbs));
  return b.sequence([tbs, ED_ALGID, b.bitString(sig, 0)]);
}

// makeOcspWorld(alg) -> { issuerKeyPkcs8, issuerCertDer, responderKeyPkcs8, responderCertDer,
//   targetCertDer, altCaCertDer, delegateOpts } for one-line vectors. `delegateOpts(overrides)`
// re-mints a responder delegate cert with custom EKU / nocheck / validity for the reject family.
async function makeOcspWorld(alg) {
  alg = alg || "ec-p256";
  var ra = RESP_ALG[alg];
  if (!ra) throw new Error("makeOcspWorld: unknown responder alg " + alg);

  var caKp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var caSpki = Buffer.from(await subtle.exportKey("spki", caKp.publicKey));
  var issuerCertDer = await signCert({ serial: 1, issuerCN: "OCSP Mini CA", subjectCN: "OCSP Mini CA", spki: caSpki, issuerKey: caKp.privateKey, exts: caExts() });
  var issuerKeyPkcs8 = Buffer.from(await subtle.exportKey("pkcs8", caKp.privateKey));

  var respKp = await subtle.generateKey(ra.gen, true, ["sign", "verify"]);
  var respSpki = Buffer.from(await subtle.exportKey("spki", respKp.publicKey));
  var respKeyPkcs8 = Buffer.from(await subtle.exportKey("pkcs8", respKp.privateKey));

  async function delegate(overrides) {
    overrides = overrides || {};
    var exts = [];
    if (overrides.eku !== null) exts.push(ext("extKeyUsage", false, b.sequence((overrides.eku || ["ocspSigning"]).map(function (n) { return b.oid(O(n)); }))));
    if (overrides.keyUsage) exts.push(ext("keyUsage", false, overrides.keyUsage));
    if (overrides.nocheck !== false) exts.push(ext("ocspNoCheck", false, b.nullValue()));
    if (overrides.extraExts) overrides.extraExts.forEach(function (e) { exts.push(e); });
    return signCert({ serial: overrides.serial || 2, issuerCN: overrides.issuerCN || "OCSP Mini CA", subjectCN: "OCSP Responder", spki: respSpki, issuerKey: overrides.issuerKey || caKp.privateKey, exts: exts, notAfter: overrides.notAfter });
  }
  var responderCertDer = await delegate({});

  // A target leaf issued by the CA.
  var leafKp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var targetCertDer = await signCert({ serial: 100, issuerCN: "OCSP Mini CA", subjectCN: "leaf.example", spki: Buffer.from(await subtle.exportKey("spki", leafKp.publicKey)), issuerKey: caKp.privateKey });

  // A DIFFERENT CA (for the wrong-issuer reject).
  var altKp = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  var altCaCertDer = await signCert({ serial: 9, issuerCN: "Other CA", subjectCN: "Other CA", spki: Buffer.from(await subtle.exportKey("spki", altKp.publicKey)), issuerKey: altKp.privateKey, exts: caExts() });

  return {
    alg: alg,
    issuerKeyPkcs8: issuerKeyPkcs8, issuerCertDer: issuerCertDer, issuerKeyObject: caKp.privateKey,
    responderKeyPkcs8: respKeyPkcs8, responderCertDer: responderCertDer, responderKeyObject: respKp.privateKey,
    targetCertDer: targetCertDer, altCaCertDer: altCaCertDer, altCaKeyObject: altKp.privateKey,
    delegate: delegate,
  };
}

module.exports = { makeOcspWorld: makeOcspWorld, ext: ext, nameDN: nameDN };
