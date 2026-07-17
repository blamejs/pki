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
