// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- PKCS#10 certification-request issuance (pki.csr.sign) cross-implementation interop.
 *
 * OpenSSL is the independent oracle for the toolkit's CSR producing side:
 *  (a) a certification request the toolkit issues parses (`openssl req -text`) and its proof-of-possession
 *      self-signature verifies (`openssl req -verify`) across a classical arm (RSA, ECDSA, EdDSA) and, on
 *      OpenSSL >= 3.5, the post-quantum ML-DSA and SLH-DSA arms;
 *  (b) a request whose proof-of-possession signature byte is flipped is REJECTED by `openssl req -verify`.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");

async function run() {
  var arms = ["rsa", "ec-p256", "ec-p521", "ed25519", "ed448"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65");
  if (ctx.opensslSupports("SLH-DSA")) arms.push("slh-dsa-sha2-128f");

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var pem = await pki.csr.sign({
      subject: [{ commonName: alg + " request" }, { organizationName: "Interop" }, { countryName: "US" }],
      subjectPublicKey: s.spki,
      extensionRequest: { subjectAltName: [{ dNSName: "req.example" }] },
    }, { key: s.key }, { pem: true });
    ctx.withTmp(Buffer.from(pem, "utf8"), "csr-" + alg + ".pem", function (p) {
      var t = ctx.runOpenssl(["req", "-in", p, "-noout", "-text"], { allowNonZero: true });
      check("openssl req -text parses the toolkit-issued " + alg + " request", t.code === 0);
      var v = ctx.runOpenssl(["req", "-in", p, "-noout", "-verify"], { allowNonZero: true });
      check("openssl req -verify accepts the toolkit-issued " + alg + " proof of possession", v.code === 0);
    });
  }

  // A tampered proof-of-possession signature is rejected.
  var s2 = signing.makeSigner("ec-p256");
  var der = await pki.csr.sign({ subject: "tamper.example", subjectPublicKey: s2.spki }, { key: s2.key });
  var bad = Buffer.from(der); bad[bad.length - 1] ^= 0xff;   // flip a signature byte
  ctx.withTmp(Buffer.from(pki.schema.csr.pemEncode(bad, "CERTIFICATE REQUEST"), "utf8"), "csr-bad.pem", function (p) {
    var v = ctx.runOpenssl(["req", "-in", p, "-noout", "-verify"], { allowNonZero: true });
    check("openssl req -verify REJECTS a toolkit request with a flipped signature byte", v.code !== 0);
  });
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
