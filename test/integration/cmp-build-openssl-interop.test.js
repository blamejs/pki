// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- RFC 9810 CMP PKIMessage building (pki.cmp.build) cross-implementation interop.
 *
 * A full CMP transaction needs a live RFC 9483 responder, out of scope for a unit oracle, so the check is
 * three-part and honest:
 *  (a) STRUCTURE -- `openssl asn1parse -inform DER` (an independent DER decoder) accepts the emitted
 *      PKIMessage, across a classical signature arm (RSA, ECDSA, EdDSA), a PBMAC1 MAC message, and, on
 *      OpenSSL >= 3.5, the post-quantum ML-DSA arm;
 *  (b) ROUND-TRIP -- pki.schema.cmp.parse re-decodes the emitted bytes strictly (enforcing every RFC 9810
 *      envelope MUST and surfacing the exact headerBytes / bodyBytes the protection covers);
 *  (c) PROTECTION -- the in-tree independent oracle: reconstruct ProtectedPart = SEQUENCE(headerBytes,
 *      bodyBytes) from the parser slices; for a signature verify it via node:crypto under the sender key;
 *      for PBMAC1 recompute PBKDF2 + HMAC-SHA256; a flipped ProtectedPart byte fails.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var nodeCrypto = require("node:crypto");

function reconProtectedPart(m) {
  return pki.asn1.build.sequence([pki.asn1.build.raw(m.headerBytes), pki.asn1.build.raw(m.bodyBytes)]);
}
function verifyProtection(m, spki) {
  var pub = nodeCrypto.createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
  var recon = reconProtectedPart(m), sig = m.protection.bytes, kt = pub.asymmetricKeyType;
  if (kt === "ec") return nodeCrypto.verify("sha256", recon, { key: pub, dsaEncoding: "der" }, sig);
  if (kt === "rsa" || kt === "rsa-pss") return nodeCrypto.verify("sha256", recon, pub, sig);
  return nodeCrypto.verify(null, recon, pub, sig);
}

async function run() {
  var arms = ["rsa", "ec-p256", "ed25519"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65");
  var HDR = { sender: { directoryName: "CN=client" }, recipient: { directoryName: "CN=CA" }, transactionID: Buffer.alloc(16, 7) };

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var csrDer = await pki.csr.sign({ subject: [{ commonName: alg + " client" }], subjectPublicKey: s.spki }, s.key);
    var der = await pki.cmp.build({ header: HDR, body: { p10cr: csrDer } }, { key: s.key, cert: s.cert });

    ctx.withTmp(Buffer.from(der), "cmp-" + alg + ".der", function (p) {
      var t = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p], { allowNonZero: true });
      check("openssl asn1parse structurally accepts the toolkit-built " + alg + " PKIMessage", t.code === 0);
    });

    var m = pki.schema.cmp.parse(der);
    check(alg + " PKIMessage round-trips through the strict parser (p10cr body)", m.body.arm === "p10cr" && !!m.header.protectionAlg);
    check(alg + " signature protection verifies over the reconstructed ProtectedPart", verifyProtection(m, s.spki) === true);
  }

  // PBMAC1: openssl structural + independent PBKDF2/HMAC recompute.
  var sm = signing.makeSigner("ec-p256");
  var macDer = await pki.cmp.build(
    { header: HDR, body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "mac client" }], subjectPublicKey: sm.spki }, sm.key) } },
    { mac: { secret: "correct horse battery staple", salt: Buffer.alloc(16, 3), iterationCount: 4096 } });
  ctx.withTmp(Buffer.from(macDer), "cmp-pbmac1.der", function (p) {
    var t = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p], { allowNonZero: true });
    check("openssl asn1parse structurally accepts the PBMAC1-protected PKIMessage", t.code === 0);
  });
  var mm = pki.schema.cmp.parse(macDer);
  var reconM = reconProtectedPart(mm);
  var key = nodeCrypto.pbkdf2Sync(Buffer.from("correct horse battery staple", "utf8"), Buffer.alloc(16, 3), 4096, 32, "sha256");
  var mac = nodeCrypto.createHmac("sha256", key).update(reconM).digest();
  check("PBMAC1 protectionAlg is pbmac1 and the MAC recomputes independently (PBKDF2 + HMAC-SHA256)", mm.header.protectionAlg.name === "pbmac1" && mac.equals(mm.protection.bytes));

  // A CA-response arm: openssl structural + round-trip. ip carries a CertRepMessage with a granting
  // CertResponse embedding the CA's own certificate.
  var sc = signing.makeSigner("ec-p256");
  var ipDer = await pki.cmp.build({ header: HDR, body: { ip: { caPubs: [sc.cert], response: [{ certReqId: 0, status: { status: 0 }, certifiedKeyPair: { certificate: sc.cert } }] } } }, { key: sc.key, cert: sc.cert });
  ctx.withTmp(Buffer.from(ipDer), "cmp-ip.der", function (p) {
    var t = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p], { allowNonZero: true });
    check("openssl asn1parse structurally accepts the ip CertRepMessage response", t.code === 0);
  });
  var mIp = pki.schema.cmp.parse(ipDer);
  check("ip CertRepMessage round-trips through the strict parser", mIp.body.arm === "ip" && !!mIp.body.decoded && verifyProtection(mIp, sc.spki) === true);

  // A flipped ProtectedPart byte fails the independent signature verify.
  var s2 = signing.makeSigner("ec-p256");
  var good = await pki.cmp.build({ header: HDR, body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "t" }], subjectPublicKey: s2.spki }, s2.key) } }, { key: s2.key, cert: s2.cert });
  var mg = pki.schema.cmp.parse(good);
  var badRecon = reconProtectedPart(mg); badRecon[badRecon.length - 1] ^= 0xff;
  var pub2 = nodeCrypto.createPublicKey({ key: Buffer.from(s2.spki), format: "der", type: "spki" });
  check("a flipped ProtectedPart byte fails the signature verify", nodeCrypto.verify("sha256", badRecon, { key: pub2, dsaEncoding: "der" }, mg.protection.bytes) === false);
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
