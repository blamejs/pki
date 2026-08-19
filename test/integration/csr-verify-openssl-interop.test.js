// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- PKCS#10 proof-of-possession verification (pki.csr.verify) cross-implementation interop.
 *
 * The sibling file points OpenSSL at requests this toolkit issued. This one runs the other direction,
 * which is the direction pki.csr.verify is for: OpenSSL generates the key and the request, and the
 * toolkit's verifier is the one under test. A verifier exercised only against its own signer agrees
 * with itself about conventions no spec fixes -- the DN string types it emits, whether it writes an
 * empty attributes set, how it encodes the signature -- so an independent producer is what shows the
 * check is about the signature rather than about the shape one builder happens to make.
 *
 *  (a) a request OpenSSL generated verifies TRUE, across a classical arm (RSA, ECDSA, EdDSA) and, on
 *      OpenSSL >= 3.5, the post-quantum ML-DSA and SLH-DSA arms;
 *  (b) an OpenSSL-generated request whose signature byte is flipped verifies FALSE, so (a) is not a
 *      verifier that says true about everything;
 *  (c) both directions agree on the same bytes: what `openssl req -verify` accepts, pki.csr.verify
 *      accepts, and what it rejects, pki.csr.verify rejects.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var os = require("os");
var path = require("path");
var fs = require("fs");
var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;

// OpenSSL's own -newkey spec per arm, so the key and the request both come from the oracle.
var ARMS = [
  { name: "rsa", newkey: "rsa:2048" },
  { name: "ec-p256", curve: "prime256v1" },
  { name: "ed25519", newkey: "ed25519" },
];

function genRequest(arm) {
  // -nodes leaves the generated private key unencrypted, so no passphrase prompt can block the run.
  var args = ["req", "-new", "-nodes", "-subj", "/CN=" + arm.name + " interop/O=Interop/C=US",
    "-keyout", arm._keyPath, "-out", arm._csrPath];
  if (arm.curve) args = args.concat(["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:" + arm.curve]);
  else args = args.concat(["-newkey", arm.newkey]);
  return ctx.runOpenssl(args, { allowNonZero: true });
}

async function run() {
  var arms = ARMS.slice();
  if (ctx.opensslSupports("ML-DSA")) arms.push({ name: "ml-dsa-65", newkey: "ML-DSA-65" });
  if (ctx.opensslSupports("SLH-DSA")) arms.push({ name: "slh-dsa-sha2-128f", newkey: "SLH-DSA-SHA2-128f" });

  for (var i = 0; i < arms.length; i++) {
    var arm = arms[i];
    var stem = path.join(os.tmpdir(), "pkijs-csrv-" + process.pid + "-" + i);
    arm._keyPath = stem + ".key.pem";
    arm._csrPath = stem + ".csr.pem";
    try {
      var g = genRequest(arm);
      if (g.code !== 0 || !fs.existsSync(arm._csrPath)) {
        ctx.skip("openssl could not generate a " + arm.name + " certification request");
        continue;
      }
      var pem = fs.readFileSync(arm._csrPath, "utf8");

      // (c) the oracle's own verdict on the bytes it produced, so the comparison below is anchored.
      var ov = ctx.runOpenssl(["req", "-in", arm._csrPath, "-noout", "-verify"], { allowNonZero: true });
      check("openssl req -verify accepts its own " + arm.name + " request", ov.code === 0);

      // (a) the toolkit's verifier over a request it did not produce.
      var v = await pki.csr.verify(pem);
      check("pki.csr.verify accepts an OpenSSL-generated " + arm.name + " request", v.verified === true);
      // The verdict's fields come from the request OpenSSL built, so this also checks the toolkit
      // reads a foreign producer's subject and key rather than only its own encoding conventions.
      check("the verdict reports the subject OpenSSL wrote for " + arm.name, /interop/i.test(v.subject.dn));
      check("the verdict reports a subject key for " + arm.name,
        !!v.subjectPublicKeyInfo && v.subjectPublicKeyInfo.bytes.length > 0);

      // (b) the same request with a flipped signature byte.
      var der = pki.schema.csr.pemDecode(pem);
      var bad = Buffer.from(der);
      bad[bad.length - 1] ^= 0xff;
      check("pki.csr.verify REJECTS an OpenSSL " + arm.name + " request with a flipped signature byte",
        (await pki.csr.verify(bad)).verified === false);

      var badPem = pki.schema.csr.pemEncode(bad, "CERTIFICATE REQUEST");
      var bv = ctx.withTmp(Buffer.from(badPem, "utf8"), "csr-bad-" + arm.name + ".pem", function (p) {
        return ctx.runOpenssl(["req", "-in", p, "-noout", "-verify"], { allowNonZero: true });
      });
      check("both verifiers reject the same tampered " + arm.name + " bytes", bv.code !== 0);
    } finally {
      try { fs.unlinkSync(arm._keyPath); } catch (_e) { /* best-effort */ }
      try { fs.unlinkSync(arm._csrPath); } catch (_e) { /* best-effort */ }
    }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
