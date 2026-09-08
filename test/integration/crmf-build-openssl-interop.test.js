// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- RFC 4211 certificate-request-message issuance (pki.crmf.build) cross-implementation interop.
 *
 * A full CMP transaction is out of scope for a unit oracle, so the check is two-part and honest:
 *  (a) STRUCTURE -- `openssl asn1parse -inform DER` (an independent DER decoder) accepts the emitted
 *      CertReqMessages and its dump exposes the CertRequest / CertTemplate / POP layout, across a classical
 *      arm (RSA, ECDSA, EdDSA) and, on OpenSSL >= 3.5, the post-quantum ML-DSA arm;
 *  (b) PROOF OF POSSESSION -- the in-tree round trip is the signature oracle: pki.schema.crmf.parse
 *      re-decodes the emitted bytes strictly (surfacing the exact CertRequest bytes the POP signature
 *      covers) and the POPOSigningKey signature verifies under the requested public key; a flipped
 *      signature byte fails that verify.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var nodeCrypto = require("node:crypto");

function popVerify(msg, spki) {
  var pub = nodeCrypto.createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
  var sig = msg.popo.signature.bytes, region = msg.certReq.certReqBytes;
  var kt = pub.asymmetricKeyType;
  if (kt === "ec") return nodeCrypto.verify("sha256", region, { key: pub, dsaEncoding: "der" }, sig);
  if (kt === "rsa" || kt === "rsa-pss") return nodeCrypto.verify("sha256", region, pub, sig);
  return nodeCrypto.verify(null, region, pub, sig);
}

async function run() {
  var arms = ["rsa", "ec-p256", "ed25519"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65");

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var der = await pki.crmf.build({
      certReqId: i,
      certTemplate: { subject: [{ commonName: alg + " requester" }], publicKey: s.spki,
        extensions: { subjectAltName: [{ dNSName: "req.example" }] } },
    }, { key: s.key });

    ctx.withTmp(Buffer.from(der), "crmf-" + alg + ".der", function (p) {
      var t = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p], { allowNonZero: true });
      check("openssl asn1parse structurally accepts the toolkit-issued " + alg + " CertReqMessages", t.code === 0);
    });

    var msg = pki.schema.crmf.parse(der).messages[0];
    check(alg + " CertReqMessages round-trips through the strict parser", msg.certReq.certReqId === BigInt(i));
    check(alg + " POPOSigningKey signature verifies over the CertRequest", popVerify(msg, s.spki) === true);
  }

  // The agreeMAC arm carries a wire structure nothing else in this suite emits: a POPOPrivKey [3]
  // holding the RFC 2875 sec. 3 DhPopStatic. OpenSSL cannot check a CRMF proof of possession, so the
  // independent half is its DER decoder, and the arithmetic half is the authority's own side of the
  // agreement, computed here from the private key the builder never sees.
  var caDh = nodeCrypto.generateKeyPairSync("dh", { group: "modp14" });
  var eeDh = nodeCrypto.generateKeyPairSync("dh", { group: "modp14" });
  var caSpki = caDh.publicKey.export({ format: "der", type: "spki" });
  var eeSpki = eeDh.publicKey.export({ format: "der", type: "spki" });
  var root = signing.makeSigner("ed25519");
  var rootCert = await pki.x509.sign({
    subject: "dh interop root", subjectPublicKey: root.spki, serialNumber: 61,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: root.key });
  var caCert = await pki.x509.sign({
    subject: "dh interop authority", subjectPublicKey: caSpki, serialNumber: 62,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { keyUsage: ["keyAgreement"] },
  }, { key: root.key, cert: rootCert });

  var agreeDer = await pki.crmf.build({
    certReqId: 61, certTemplate: { subject: [{ commonName: "dh requester" }], publicKey: eeSpki },
    pop: { type: "keyAgreement", method: "agreeMAC",
      key: eeDh.privateKey.export({ format: "der", type: "pkcs8" }), caCert: caCert },
  });

  ctx.withTmp(Buffer.from(agreeDer), "crmf-agreemac.der", function (p) {
    var t = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p], { allowNonZero: true });
    check("openssl asn1parse structurally accepts the toolkit-issued agreeMAC CertReqMessages", t.code === 0);
    // OpenSSL resolves the algorithm from its own tables and prints its own label for it,
    // id-alg-dh-sig-hmac-sha1, which is what RFC 2875 calls id-dhPop-static-HMAC-SHA1.
    check("openssl names the proof's algorithm from its own tables rather than echoing the arc",
      (t.stdout || "").indexOf("id-alg-dh-sig-hmac-sha1") !== -1);
    check("openssl descends the POPOPrivKey [3] agreeMAC arm to the BIT STRING carrying the proof",
      (t.stdout || "").indexOf("cont [ 3 ]") !== -1 && (t.stdout || "").indexOf("BIT STRING") !== -1);
  });

  var agreeMsg = pki.schema.crmf.parse(agreeDer).messages[0];
  check("the agreeMAC CertReqMessages round-trips through the strict parser",
    agreeMsg.popo.type === "keyAgreement" && agreeMsg.popo.method === "agreeMAC");

  // The authority's side: agree the same secret, derive the same key, reach the same MAC.
  var parsedCa = pki.schema.x509.parse(caCert);
  var zz = nodeCrypto.diffieHellman({
    privateKey: caDh.privateKey,
    publicKey: nodeCrypto.createPublicKey({ key: eeSpki, format: "der", type: "spki" }),
  });
  var k = nodeCrypto.createHash("sha1")
    .update(parsedCa.subject.bytes).update(zz).update(parsedCa.issuer.bytes).digest();
  var expected = nodeCrypto.createHmac("sha1", k).update(agreeMsg.certReq.certReqBytes).digest();
  // POPOPrivKey [3] holds a PKMACValue: SEQUENCE { algId, BIT STRING }, and the BIT STRING carries
  // the DhPopStatic whose second field is the MAC (RFC 2875 sec. 3).
  var pkMac = pki.asn1.decode(pki.asn1.decode(agreeMsg.popo.bytes).children[0].bytes);
  var popStatic = pki.asn1.decode(Buffer.from(pki.asn1.read.bitString(pkMac.children[1]).bytes));
  var carried = pki.asn1.read.octetString(popStatic.children[1]);
  check("the authority reaches the same MAC from its own side of the agreement",
    Buffer.from(carried).equals(expected));

  // A tampered POP signature byte fails the proof-of-possession verify.
  var s2 = signing.makeSigner("ec-p256");
  var good = await pki.crmf.build({ certTemplate: { subject: "tamper", publicKey: s2.spki } }, { key: s2.key });
  var bad = Buffer.from(good); bad[bad.length - 1] ^= 0xff;
  check("the untampered CertReqMessages POP verifies", popVerify(pki.schema.crmf.parse(good).messages[0], s2.spki) === true);
  var badMsg = pki.schema.crmf.parse(bad).messages[0];
  check("a flipped POP signature byte fails the proof-of-possession verify", popVerify(badMsg, s2.spki) === false);
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
