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
  var armCurve = { "ec-p256": "P-256", "ec-p384": "P-384", "ec-p521": "P-521" };
  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var der = await pki.x509.sign({
      subject: [{ commonName: alg + " leaf" }, { organizationName: "Interop" }, { countryName: "US" }],
      subjectPublicKey: s.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
      extensions: { keyUsage: ["digitalSignature"], basicConstraints: { cA: false } },
    }, { key: s.key });

    // these signers pair every curve with SHA-256, so the issuer curve is supplied explicitly.
    var c509 = pki.schema.c509.encode(der, { issuerCurve: armCurve[alg] });
    var recon = pki.schema.c509.parse(c509).reconstructedDer;
    check(alg + " type-3 C509 is smaller than the source DER", c509.length < der.length);
    check(alg + " type-3 reconstructs the source DER byte-for-byte", recon.equals(der));

    ctx.withTmp(Buffer.from(recon), "c509-recon-" + alg + ".der", function (p) {
      var t = ctx.runOpenssl(["x509", "-inform", "DER", "-in", p, "-noout", "-text"], { allowNonZero: true });
      check("openssl x509 accepts the reconstructed " + alg + " certificate", t.code === 0);
    });
  }

  // A certificate bearing the compact general-name value form: a subjectAltName with a dNSName, rfc822Name,
  // URI, and iPAddress rides the draft-20 sec. 3.3 GeneralNames array, and the reconstructed DER MUST be the
  // certificate OpenSSL parses -- including the Subject Alternative Name it now carries the compact way.
  var b = pki.asn1.build, O = pki.oid.byName;
  var sanExt = b.sequence([b.oid(O("subjectAltName")), b.octetString(b.sequence([
    b.contextPrimitive(2, Buffer.from("interop.example", "latin1")),
    b.contextPrimitive(1, Buffer.from("ca@interop.example", "latin1")),
    b.contextPrimitive(6, Buffer.from("https://interop.example/crl", "latin1")),
    b.contextPrimitive(7, Buffer.from([192, 0, 2, 10])),
  ]))]);
  var ss = signing.makeSigner("ec-p256");
  var sanDer = Buffer.from(await pki.x509.sign({
    subject: [{ commonName: "san leaf" }], subjectPublicKey: ss.spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
    extensions: [sanExt],
  }, { key: ss.key }));
  var sanC509 = pki.schema.c509.encode(sanDer, { issuerCurve: "P-256" });
  var sanRecon = pki.schema.c509.parse(sanC509).reconstructedDer;
  check("subjectAltName cert type-3 reconstructs the source DER byte-for-byte", sanRecon.equals(sanDer));
  // the subjectAltName rode the compact GeneralNames array (extension integer 3 with a CBOR array value),
  // not the unwrapped-OID byte-string fallback.
  var sanExtsNode = pki.cbor.decode(sanC509).children[9].children || [];
  var sanCompact = false;
  for (var k = 0; k + 1 < sanExtsNode.length; k += 2) {
    if (sanExtsNode[k].majorType <= 1 && Math.abs(Number(pki.cbor.read.int(sanExtsNode[k]))) === 3 && sanExtsNode[k + 1].majorType === 4) sanCompact = true;
  }
  check("subjectAltName encodes as the compact GeneralNames array (not the ~oid fallback)", sanCompact);
  ctx.withTmp(sanRecon, "c509-recon-san.der", function (p) {
    var t = ctx.runOpenssl(["x509", "-inform", "DER", "-in", p, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 accepts the reconstructed subjectAltName certificate", t.code === 0);
    check("openssl reads the reconstructed Subject Alternative Name", /interop\.example/.test(t.stdout || ""));
  });
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
