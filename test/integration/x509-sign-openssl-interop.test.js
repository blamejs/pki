// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- X.509 certificate issuance (pki.x509.sign) cross-implementation interop.
 *
 * OpenSSL is the independent oracle for the toolkit's certificate PRODUCING side:
 *  (a) a self-signed certificate the toolkit issues parses (`openssl x509 -text`) and verifies
 *      (`openssl verify`) across a classical arm (RSA, ECDSA, EdDSA) and, on OpenSSL >= 3.5, the
 *      post-quantum ML-DSA and SLH-DSA arms;
 *  (b) a CA-signed chain the toolkit assembles (a leaf issued under a toolkit-issued CA) is validated
 *      end to end by `openssl verify -CAfile` -- OpenSSL checks the CA's signature over the leaf;
 *  (c) a certificate whose signature is flipped is REJECTED by `openssl verify`.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var os = require("node:os");
var fs = require("node:fs");
var path = require("node:path");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2036-01-01T00:00:00Z");

function caSpec(cn, spki) {
  return { subject: [{ commonName: cn }], subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } };
}

async function run() {
  // ---- (a) per-arm self-signed cert: openssl parses + verifies ----
  var arms = ["rsa", "ec-p256", "ec-p521", "ed25519", "ed448"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65");
  if (ctx.opensslSupports("SLH-DSA")) arms.push("slh-dsa-sha2-128f");

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var pem = await pki.x509.sign(caSpec(alg + " Root", s.spki), { key: s.key }, { pem: true });
    ctx.withTmp(Buffer.from(pem, "utf8"), "cert-" + alg + ".pem", function (p) {
      var t = ctx.runOpenssl(["x509", "-in", p, "-noout", "-text"], { allowNonZero: true });
      check("openssl x509 -text parses the toolkit-issued " + alg + " certificate", t.code === 0);
      var v = ctx.runOpenssl(["verify", "-CAfile", p, p], { allowNonZero: true });
      check("openssl verify accepts the toolkit-issued self-signed " + alg + " certificate", v.code === 0 && /:\s*OK\s*$/.test(v.stdout.trim()));
    });
  }

  // ---- (b) CA-signed chain the toolkit assembles: openssl validates the CA's signature over the leaf ----
  var ca = signing.makeSigner("ec-p256");
  var caPem = await pki.x509.sign(caSpec("Interop Issuing CA", ca.spki), { key: ca.key }, { pem: true });
  var caCert = pki.schema.x509.parse(pki.schema.x509.pemDecode(caPem, "CERTIFICATE"));
  var leafKp = signing.makeSigner("ed25519");
  var leafPem = await pki.x509.sign({
    subject: [{ commonName: "leaf.interop.example" }], subjectPublicKey: leafKp.spki, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: "leaf.interop.example" }], authorityKeyIdentifier: true },
  }, { cert: caCert, key: ca.key }, { pem: true });

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-x509sign-"));
  try {
    var caFile = path.join(dir, "ca.pem"); fs.writeFileSync(caFile, caPem);
    var leafFile = path.join(dir, "leaf.pem"); fs.writeFileSync(leafFile, leafPem);
    var vc = ctx.runOpenssl(["verify", "-CAfile", caFile, leafFile], { allowNonZero: true });
    check("openssl verify validates a toolkit CA-signed chain (leaf under the toolkit CA)", vc.code === 0 && /:\s*OK\s*$/.test(vc.stdout.trim()));

    // ---- (c) a tampered leaf is rejected against the (untampered) CA ----
    // Flip a byte of the LEAF's signature and verify it against the real CA: openssl checks the CA's
    // signature over the leaf, so the tamper is caught. (A self-signed anchor is trusted a priori, so
    // it must be a leaf-under-CA to exercise a real signature check.)
    var badLeaf = Buffer.from(pki.schema.x509.pemDecode(leafPem, "CERTIFICATE"));
    badLeaf[badLeaf.length - 1] ^= 0xff;   // flip a signature byte
    var badFile = path.join(dir, "bad-leaf.pem"); fs.writeFileSync(badFile, pki.schema.x509.pemEncode(badLeaf, "CERTIFICATE"));
    var vb = ctx.runOpenssl(["verify", "-CAfile", caFile, badFile], { allowNonZero: true });
    check("openssl verify REJECTS a toolkit leaf with a flipped signature byte", vb.code !== 0);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
