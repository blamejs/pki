// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- a `node:crypto` KeyObject signs wherever a WebCrypto CryptoKey does.
 *
 * A KeyObject is what `crypto.createPrivateKey` returns and what an OpenSSL engine or
 * provider hands back, and it may hold key material this process cannot export. It is
 * signed with through `node:crypto` rather than exported to PKCS#8, so a key that
 * refuses to be exported still signs.
 *
 * What the vectors pin is that it is held to the same rules a CryptoKey is: the
 * algorithm and the curve answer to the certificate's key, a public key is refused,
 * and the bytes produced are the bytes WebCrypto would have produced.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var nodeCrypto = require("crypto");
var signing = require("../helpers/signing");

function code(p) {
  return Promise.resolve(p).then(function () { return "NO-THROW"; }, function (e) { return (e && e.code) || e.name; });
}

var NOT_BEFORE = new Date("2026-01-01T00:00:00Z");
var NOT_AFTER = new Date("2036-01-01T00:00:00Z");

async function keyObjectFor(algorithm) {
  var pair = await pki.key.generate(algorithm);
  var pkcs8 = await pki.key.export(pair.privateKey);
  var spki = await pki.key.export(pair.publicKey);
  return {
    pair: pair, spki: spki,
    priv: nodeCrypto.createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }),
    pub: nodeCrypto.createPublicKey({ key: spki, format: "der", type: "spki" }),
  };
}

function rootSpec(spki, cn) {
  return {
    subject: cn || "CN=KeyObject Root",
    subjectPublicKey: spki,
    serialNumber: 20260920n,
    notBefore: NOT_BEFORE,
    notAfter: NOT_AFTER,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  };
}

// ---- one algorithm per class, each signing and verifying -------------------
async function testEveryAlgorithmClassSigns() {
  var classes = [
    ["Ed25519", "Ed25519"],
    ["Ed448", "Ed448"],
    ["ECDSA P-256", { name: "ECDSA", namedCurve: "P-256" }],
    ["ECDSA P-384", { name: "ECDSA", namedCurve: "P-384" }],
    ["ECDSA P-521", { name: "ECDSA", namedCurve: "P-521" }],
    ["RSASSA-PKCS1-v1_5", { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }],
    ["RSA-PSS", { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }],
    ["ML-DSA-44", { name: "ML-DSA-44" }],
    ["ML-DSA-65", { name: "ML-DSA-65" }],
    ["ML-DSA-87", { name: "ML-DSA-87" }],
    ["SLH-DSA-SHA2-128S", { name: "SLH-DSA-SHA2-128S" }],
    ["SLH-DSA-SHAKE-128F", { name: "SLH-DSA-SHAKE-128F" }],
  ];
  var refused = [];
  for (var i = 0; i < classes.length; i++) {
    var name = classes[i][0];
    var k = await keyObjectFor(classes[i][1]);
    var verdict = await code(pki.x509.sign(rootSpec(k.spki, "CN=" + name), { key: k.priv }));
    if (verdict !== "NO-THROW") refused.push(name + ": " + verdict);
  }
  check("a KeyObject signs in every algorithm class (" + refused.join("; ") + ")", refused.length === 0);
}

// ---- the bytes are the bytes WebCrypto would have produced -----------------
async function testTheSignatureIsTheSameSignature() {
  var k = await keyObjectFor("Ed25519");
  var viaKeyObject = await pki.x509.sign(rootSpec(k.spki), { key: k.priv });
  var viaCryptoKey = await pki.x509.sign(rootSpec(k.spki), { key: k.pair.privateKey });
  check("an Ed25519 certificate is byte-identical whichever key form signed it",
    viaKeyObject.equals(viaCryptoKey));

  // ECDSA is randomized, so the check is that an independent verifier accepts it.
  var ec = await keyObjectFor({ name: "ECDSA", namedCurve: "P-256" });
  var cert = await pki.x509.sign(rootSpec(ec.spki), { key: ec.priv });
  var parsed = pki.schema.x509.parse(cert);
  check("an ECDSA certificate signed by a KeyObject verifies against its own key",
    nodeCrypto.verify("sha256", parsed.tbsBytes, { key: ec.pub, dsaEncoding: "der" },
      parsed.signatureValue.bytes) === true);
}

// ---- held to the same rules a CryptoKey is --------------------------------
async function testKeyObjectIsHeldToTheCertificatesKey() {
  var ed = await keyObjectFor("Ed25519");
  var ec = await keyObjectFor({ name: "ECDSA", namedCurve: "P-256" });
  var ec384 = await keyObjectFor({ name: "ECDSA", namedCurve: "P-384" });

  check("a KeyObject whose algorithm does not match the certificate's key is refused",
    await code(pki.x509.sign(rootSpec(ed.spki), { key: ec.priv })) === "x509/bad-input");
  check("a KeyObject on a different curve than the certificate's key is refused",
    await code(pki.x509.sign(rootSpec(ec.spki), { key: ec384.priv })) === "x509/bad-input");
  check("a public KeyObject is refused",
    await code(pki.x509.sign(rootSpec(ed.spki), { key: ed.pub })) === "x509/bad-input");
  check("a secret KeyObject is refused",
    await code(pki.x509.sign(rootSpec(ed.spki), {
      key: nodeCrypto.createSecretKey(Buffer.alloc(32)),
    })) === "x509/bad-input");

  // The signature is still proven against the key the certificate names, so a KeyObject for a
  // different key of the same algorithm cannot produce a certificate nobody can validate.
  var other = await keyObjectFor("Ed25519");
  check("a KeyObject for a different key of the same algorithm is refused",
    await code(pki.x509.sign(rootSpec(ed.spki), { key: other.priv })) === "x509/bad-input");

  // A composite signature comes from both component private keys, which one KeyObject cannot
  // hold, so the form is refused by name rather than half-signed.
  var cs = signing.makeCompositeSigner("id-MLDSA44-Ed25519-SHA512");
  check("a composite certificate refuses a KeyObject, naming why", await (async function () {
    try {
      await pki.x509.sign({ subject: "composite", subjectPublicKey: cs.spki, notBefore: NOT_BEFORE, notAfter: NOT_AFTER },
        { key: ed.priv });
      return false;
    } catch (e) { return e.code === "x509/bad-input" && /composite/.test(e.message); }
  })());
}

// ---- every signing verb takes one -----------------------------------------
async function testEverySigningVerbTakesAKeyObject() {
  var k = await keyObjectFor("Ed25519");
  var caCert = await pki.x509.sign(rootSpec(k.spki), { key: k.priv });
  var leaf = await pki.key.generate("Ed25519");
  var leafSpki = await pki.key.export(leaf.publicKey);

  var refused = [];
  async function drive(name, run) {
    try { await run(); } catch (err) { refused.push(name + ": " + ((err && err.code) || (err && err.message))); }
  }

  await drive("x509.sign", function () {
    return pki.x509.sign({ subject: "CN=Leaf", subjectPublicKey: leafSpki, notBefore: NOT_BEFORE, notAfter: NOT_AFTER },
      { key: k.priv, cert: caCert });
  });
  await drive("crl.sign", function () {
    return pki.crl.sign({ thisUpdate: NOT_BEFORE, nextUpdate: NOT_AFTER, revoked: [] }, { key: k.priv, cert: caCert });
  });
  await drive("csr.sign", function () {
    return pki.csr.sign({ subject: "CN=Requester", subjectPublicKey: k.spki }, { key: k.priv });
  });
  await drive("cms.sign", function () {
    return pki.cms.sign(Buffer.from("content"), { key: k.priv, cert: caCert });
  });
  await drive("ocsp.sign", function () {
    return pki.ocsp.sign({ responses: [{ cert: caCert, issuer: caCert, status: "good", thisUpdate: NOT_BEFORE }] },
      { key: k.priv, cert: caCert });
  });
  await drive("attrcert.sign", function () {
    return pki.attrcert.sign({
      holder: { entityName: { directoryName: "CN=Alice" } },
      notBeforeTime: NOT_BEFORE, notAfterTime: NOT_AFTER,
      attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } },
    }, { cert: caCert, key: k.priv });
  });
  await drive("crmf.build", function () {
    return pki.crmf.build({ certReqId: 0, certTemplate: { subject: "device-42", publicKey: k.spki } }, { key: k.priv });
  });

  check("every signing verb takes a KeyObject (" + refused.join("; ") + ")", refused.length === 0);
}

// ---- a private key that cannot be exported still signs ---------------------
async function testAnUnexportableKeyObjectStillSigns() {
  var k = await keyObjectFor("Ed25519");
  // A KeyObject held by an engine or a provider will not hand over its private bytes, so the
  // signing path must never ask for them. The recorder is installed on the prototype for the
  // duration of one signature and removed again, whatever the signature does.
  var proto = Object.getPrototypeOf(k.priv);
  var original = proto.export;
  var asked = 0;
  proto.export = function () { asked += 1; return original.apply(this, arguments); };
  var verdict;
  try { verdict = await code(pki.x509.sign(rootSpec(k.spki), { key: k.priv })); }
  finally { proto.export = original; }

  check("a KeyObject signs (" + verdict + ")", verdict === "NO-THROW");
  check("and nothing on the signing path asked it to export itself (" + asked + ")", asked === 0);
  check("CONTROL: the recorder was removed", proto.export === original);
  check("CONTROL: and it does record an export when one is asked for",
    (function () {
      var before = asked;
      proto.export = function () { asked += 1; return original.apply(this, arguments); };
      try { k.priv.export({ format: "der", type: "pkcs8" }); } finally { proto.export = original; }
      return asked === before + 1;
    })());
}

async function run() {
  await testEveryAlgorithmClassSigns();
  await testTheSignatureIsTheSameSignature();
  await testKeyObjectIsHeldToTheCertificatesKey();
  await testEverySigningVerbTakesAKeyObject();
  await testAnUnexportableKeyObjectStillSigns();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
