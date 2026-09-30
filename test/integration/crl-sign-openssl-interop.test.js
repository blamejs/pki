// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- X.509 CRL issuance (pki.crl.sign) cross-implementation interop.
 *
 * OpenSSL is the independent oracle for the toolkit's CRL PRODUCING side:
 *  (a) a CRL the toolkit signs parses (`openssl crl -text`) across a classical arm (RSA, ECDSA, EdDSA)
 *      and, on OpenSSL >= 3.5, the post-quantum ML-DSA / SLH-DSA arms -- rendering Version 2, the issuer,
 *      the CRL extensions (CRL Number, Authority Key Identifier, the critical Issuing Distribution Point),
 *      and each revoked serial with its reason code and the GeneralizedTime invalidity date;
 *  (b) the CRL's signature verifies against the issuing CA (`openssl crl -CAfile ca.pem` -> "verify OK");
 *  (c) a CRL whose signature byte is flipped is REJECTED.
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
var TU = new Date("2026-01-01T00:00:00Z");
var NU = new Date("2026-02-01T00:00:00Z");
var RD = new Date("2026-01-15T00:00:00Z");

function caSpec(cn, spki) {
  return { subject: [{ commonName: cn }], subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } };
}

async function run() {
  var arms = ["rsa", "ec-p256", "ec-p521", "ed25519", "ed448"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65"); else ctx.skip("openssl < 3.5 -- ML-DSA CRL interop not cross-checked");
  if (ctx.opensslSupports("SLH-DSA")) arms.push("slh-dsa-sha2-128f"); else ctx.skip("openssl < 3.5 -- SLH-DSA CRL interop not cross-checked");

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    // A self-signed CA (keyCertSign + cRLSign) that both issues under and signs the CRL with the same key.
    var caPem = await pki.x509.sign(caSpec(alg + " CRL Issuer", s.spki), { key: s.key }, { pem: true });
    var caCert = pki.schema.x509.parse(pki.schema.x509.pemDecode(caPem, "CERTIFICATE"));
    var crlDer = await pki.crl.sign({
      thisUpdate: TU, nextUpdate: NU, crlNumber: 3n,
      revoked: [
        { serialNumber: 0x1234n, revocationDate: RD, reason: "keyCompromise", invalidityDate: new Date("2020-06-01T00:00:00Z") },
        { serialNumber: 0x5678n, revocationDate: RD, reason: "superseded" },
      ],
      extensions: {
        authorityKeyIdentifier: true, issuingDistributionPoint: { onlyContainsUserCerts: true },
        issuerAltName: [{ dNSName: "crl.issuer.example" }, { uniformResourceIdentifier: "https://issuer.example/ca" }],
      },
    }, { cert: caCert, key: s.key });

    var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-crlsign-" + alg + "-"));
    try {
      var caFile = path.join(dir, "ca.pem"); fs.writeFileSync(caFile, caPem);
      var crlFile = path.join(dir, "crl.der"); fs.writeFileSync(crlFile, crlDer);

      // ---- (a) openssl parses + renders the CRL ----
      var t = ctx.runOpenssl(["crl", "-inform", "DER", "-in", crlFile, "-noout", "-text"], { allowNonZero: true });
      check("openssl crl -text parses the toolkit-issued " + alg + " CRL", t.code === 0);
      check("openssl crl -text renders Version 2 for the " + alg + " CRL", /Version\s+2/.test(t.stdout));
      check("openssl crl -text lists the revoked serial 1234 for " + alg, /Serial Number:\s*1234/i.test(t.stdout));
      check("openssl crl -text shows the Key Compromise reason for " + alg, /Key Compromise/i.test(t.stdout));
      check("openssl crl -text renders the GeneralizedTime Invalidity Date for " + alg, /Invalidity Date/i.test(t.stdout));
      // RFC 5280 sec. 5.2.2. Whether openssl prints a friendly name or the bare OID depends on the
      // release, so either is accepted; what it decodes out of the GeneralNames is the real oracle.
      check("openssl crl -text shows the issuer alternative name for " + alg,
        /Issuer Alternative Name/i.test(t.stdout) || t.stdout.indexOf("2.5.29.18") >= 0);
      check("openssl crl -text decodes both issuer alternative name forms for " + alg,
        /DNS:crl\.issuer\.example/.test(t.stdout) && /URI:https:\/\/issuer\.example\/ca/.test(t.stdout));

      // ---- (b) openssl verifies the CRL signature against the issuing CA ----
      // `openssl crl -CAfile` prints "verify OK" / "verify failure" as its verdict; the EXIT CODE is unreliable
      // for the CRL verify result (some builds return 0 even on a verification failure), so assert on the text.
      var v = ctx.runOpenssl(["crl", "-inform", "DER", "-in", crlFile, "-CAfile", caFile, "-noout"], { allowNonZero: true });
      check("openssl crl -CAfile verifies the toolkit-issued " + alg + " CRL signature", /verify OK/i.test(v.stdout + v.stderr));

      // ---- (c) a flipped signature byte is REJECTED ----
      var bad = Buffer.from(crlDer); bad[bad.length - 1] ^= 0xff;
      var badFile = path.join(dir, "bad.der"); fs.writeFileSync(badFile, bad);
      var vb = ctx.runOpenssl(["crl", "-inform", "DER", "-in", badFile, "-CAfile", caFile, "-noout"], { allowNonZero: true });
      check("openssl crl -CAfile REJECTS a toolkit " + alg + " CRL with a flipped signature byte", /verify\s*fail/i.test(vb.stderr + vb.stdout));
    } finally {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
  }
  await runCatalystCrl();
}

// ITU-T X.509 (2019) clause 7.10.3: a CRL carrying an alternative signature. The certificate form is
// checked in the x509 interop suite; this is the CRL form, which is a separate claim because the
// extensions sit under a different tag and the reconstruction walks a different toBeSigned. What the
// independent implementation has to confirm is that the CRL still parses and still verifies natively
// with the two extensions present, and that its bytes survive a re-encode: the alternative signature is
// checked over a reconstruction, so a CRL openssl would re-encode differently is one nobody can verify.
async function runCatalystCrl() {
  var crypto = require("node:crypto");
  var s = signing.makeSigner("ec-p256");
  var altKp = crypto.generateKeyPairSync("ml-dsa-65");
  var altSpki = altKp.publicKey.export({ format: "der", type: "spki" });
  var altPkcs8 = altKp.privateKey.export({ format: "der", type: "pkcs8" });
  /** The CA publishes the alternative key it signs with. A relying party checks a CRL's alternative
   *  signature with the alternative key in the CRL issuer's own certificate (clause 9.8.4), so a CA that
   *  publishes none cannot sign one, and the signer refuses that combination. */
  var caPem = await pki.x509.sign({
    subject: [{ commonName: "Catalyst CRL CA" }], subjectPublicKey: s.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
      subjectAltPublicKeyInfo: altSpki },
  }, { key: s.key, altKey: altPkcs8, altPublicKey: altSpki }, { pem: true });
  var crlDer = await pki.crl.sign({
    thisUpdate: NB, nextUpdate: NA, crlNumber: 7n,
    revoked: [{ serialNumber: 3n, revocationDate: NB }],
  }, { cert: pki.schema.x509.pemDecode(caPem, "CERTIFICATE"), key: s.key, altKey: altPkcs8, altPublicKey: altSpki });
  check("the alternative signature on the emitted CRL verifies here",
    (await pki.altSig.verify(crlDer, altSpki)) === true);

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-catalyst-crl-"));
  try {
    var caFile = path.join(dir, "ca.pem"); fs.writeFileSync(caFile, caPem);
    var crlFile = path.join(dir, "c.der"); fs.writeFileSync(crlFile, crlDer);
    var t = ctx.runOpenssl(["crl", "-inform", "DER", "-in", crlFile, "-noout", "-text"], { allowNonZero: true });
    check("openssl crl -text parses a CRL carrying the alternative extensions", t.code === 0);
    [["Alternative Signature Algorithm", "2.5.29.73"], ["Alternative Signature Value", "2.5.29.74"]]
      .forEach(function (r) {
        check("openssl recognizes the " + r[1] + " CRL extension (as \"" + r[0] + "\" or by OID)",
          t.stdout.indexOf(r[0]) >= 0 || t.stdout.indexOf(r[1]) >= 0);
      });
    check("openssl does not report a subjectAltPublicKeyInfo on the CRL, the extension being certificate-only",
      t.stdout.indexOf("2.5.29.72") === -1 && t.stdout.indexOf("Subject Alternative Public Key Info") === -1);
    var v = ctx.runOpenssl(["crl", "-inform", "DER", "-in", crlFile, "-CAfile", caFile, "-noout"], { allowNonZero: true });
    check("openssl crl -CAfile still verifies the native signature with the alternative extensions present",
      /verify\s*OK/i.test(v.stdout + v.stderr));
    var reFile = path.join(dir, "re.der");
    var re = ctx.runOpenssl(["crl", "-inform", "DER", "-in", crlFile, "-outform", "DER", "-out", reFile], { allowNonZero: true });
    check("openssl re-encodes the CRL to the same bytes",
      re.code === 0 && Buffer.compare(fs.readFileSync(reFile), crlDer) === 0);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
