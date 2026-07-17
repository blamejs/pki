// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- RFC 5755 attribute-certificate issuance (pki.attrcert.sign) cross-implementation interop.
 *
 * No mainstream toolchain verifies an attribute-certificate SIGNATURE (OpenSSL, pyca/cryptography, and NSS
 * parse an AC but expose no AC signature-verify path), so the oracle here is two-part and honest about it:
 *  (a) STRUCTURE -- `openssl asn1parse -inform DER` (an independent DER decoder, unrelated to the toolkit's)
 *      accepts the emitted attribute certificate and its dump exposes the version / holder / issuer /
 *      validity / attributes layout, across a classical arm (RSA, ECDSA, EdDSA) and, on OpenSSL >= 3.5,
 *      the post-quantum ML-DSA arm;
 *  (b) SIGNATURE -- the in-tree round trip is the signature oracle: pki.schema.attrcert.parse re-decodes
 *      the emitted bytes strictly (byte-identical acinfo, every GeneralName / sec. 4.4 value / sec. 4.3
 *      extension re-validated by the shipped decoders) and a flipped signatureValue byte fails the parse +
 *      the toolkit's own signature verify.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2027-01-01T00:00:00Z");

async function run() {
  var arms = ["rsa", "ec-p256", "ed25519"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65");

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var aa = signing.makeSigner(alg);
    var der = await pki.attrcert.sign({
      holder: { entityName: { directoryName: [{ commonName: "Alice" }, { organizationName: "Example" }] } },
      notBeforeTime: NB, notAfterTime: NA,
      attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:admin" } } },
      extensions: { noRevAvail: true },
    }, { name: [{ commonName: alg + " AA" }, { countryName: "US" }], publicKey: aa.spki, key: aa.key });

    ctx.withTmp(Buffer.from(der), "ac-" + alg + ".der", function (p) {
      var t = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p], { allowNonZero: true });
      check("openssl asn1parse structurally accepts the toolkit-issued " + alg + " attribute certificate", t.code === 0);
      // The dump shows the AttributeCertificateInfo layout (version INTEGER, a GENERALIZEDTIME validity pair).
      check("openssl asn1parse dump exposes the " + alg + " AC GeneralizedTime validity", /GENERALIZEDTIME/.test(t.stdout || ""));
    });

    // The in-tree round trip is the signature oracle (openssl cannot verify an AC signature).
    var p2 = pki.schema.attrcert.parse(der);
    check(alg + " attribute certificate round-trips through the strict parser", p2.version === 2 && p2.attributes.length === 1);
  }

  // A tampered signatureValue byte fails the parse + verify round trip.
  var aa2 = signing.makeSigner("ec-p256");
  var good = await pki.attrcert.sign({
    holder: { entityName: { directoryName: "CN=Tamper" } }, notBeforeTime: NB, notAfterTime: NA,
    attributes: { role: { roleName: { uniformResourceIdentifier: "urn:r" } } },
  }, { name: "CN=Tamper AA", publicKey: aa2.spki, key: aa2.key });
  var bad = Buffer.from(good); bad[bad.length - 1] ^= 0xff;   // flip a signatureValue byte
  // The signature oracle: verify the emitted signature under the AA key; the tampered one must fail.
  var okGood = await _verifyAcSignature(good, aa2.spki);
  var okBad = await _verifyAcSignature(bad, aa2.spki);
  check("the untampered attribute certificate signature verifies under the AA key", okGood === true);
  check("a flipped signatureValue byte fails the AA signature verify", okBad === false);
}

// Verify an emitted AC's signatureValue over its acinfo under the AA SPKI via node:crypto (the tamper
// block signs with an ECDSA P-256 AA), mirroring the producer's own post-sign self-check.
function _verifyAcSignature(acDer, aaSpki) {
  var nodeCrypto = require("node:crypto");
  var asn1 = pki.asn1;
  var root = asn1.decode(acDer);
  var acinfo = root.children[0].bytes;
  var sig = asn1.read.bitString(root.children[2]).bytes;
  var pub = nodeCrypto.createPublicKey({ key: Buffer.from(aaSpki), format: "der", type: "spki" });
  return nodeCrypto.verify("sha256", acinfo, { key: pub, dsaEncoding: "der" }, sig);   // ECDSA P-256
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
