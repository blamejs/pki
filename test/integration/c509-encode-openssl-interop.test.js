// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- C509 certificate encoding (pki.schema.c509.encode) cross-implementation interop.
 *
 * No mainstream tool parses a C509 CBOR certificate, so the oracle is the type-3 round trip through an
 * independent DER implementation: a DER X.509 certificate the toolkit encodes to a compact type-3 C509,
 * re-parsed, MUST reconstruct to bytes OpenSSL accepts as the same certificate -- and, because the
 * reconstruction is byte-exact, equal to the original DER (so the original signature verifies). Across the
 * ECDSA curves the type-3 covered set supports.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");

async function run() {
  var arms = ["ec-p256", "ec-p384", "ec-p521"];
  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var der = await pki.x509.sign({
      subject: [{ commonName: alg + " leaf" }, { organizationName: "Interop" }, { countryName: "US" }],
      subjectPublicKey: s.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
      extensions: { keyUsage: ["digitalSignature"], basicConstraints: { cA: false } },
    }, { key: s.key });

    var c509 = pki.schema.c509.encode(der);
    var recon = pki.schema.c509.parse(c509).reconstructedDer;
    check(alg + " type-3 C509 is smaller than the source DER", c509.length < der.length);
    check(alg + " type-3 reconstructs the source DER byte-for-byte", recon.equals(der));

    ctx.withTmp(Buffer.from(recon), "c509-recon-" + alg + ".der", function (p) {
      var t = ctx.runOpenssl(["x509", "-inform", "DER", "-in", p, "-noout", "-text"], { allowNonZero: true });
      check("openssl x509 accepts the reconstructed " + alg + " certificate", t.code === 0);
    });
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
