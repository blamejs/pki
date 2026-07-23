// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- PKCS#12 (.p12 / .pfx) issuance (pki.pkcs12.build / verifyMac) cross-implementation interop.
 *
 * OpenSSL is the independent oracle for the toolkit's PKCS#12 producing side:
 *  (a) a store the toolkit builds (classic HMAC-SHA256 integrity, PBES2 AES-256-CBC cert safe + shrouded key)
 *      is MAC-verified AND fully decrypted by `openssl pkcs12 -info -nodes` -- it lists the certificate and
 *      the private key, proving the App. B MAC, the PBES2 bag cipher, and the BMPString/UTF-8 password split;
 *  (b) a toolkit PBMAC1 store is verified + listed by OpenSSL;
 *  (c) an OpenSSL-exported store (classic and, on OpenSSL >= 3.4, PBMAC1) is parsed by pki.schema.pkcs12 and
 *      its MAC accepted by pki.pkcs12.verifyMac.
 *
 * The password encoding is the known interop wart: the classic Appendix B MAC uses BMPString+NULL, the PBES2
 * bags and PBMAC1 use UTF-8 (what OpenSSL/NSS consume). Runs under scripts/test-integration.js.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var os = require("node:os");
var fs = require("node:fs");
var path = require("node:path");

var PW = "1234";

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-p12-"));
  try {
    var s = signing.makeSigner("rsa");
    var keyPem = pki.schema.pkcs8.pemEncode(s.key, "PRIVATE KEY");
    var certPem = pki.schema.x509.pemEncode(s.cert, "CERTIFICATE");
    var keyFile = path.join(dir, "key.pem"); fs.writeFileSync(keyFile, keyPem);
    var certFile = path.join(dir, "cert.pem"); fs.writeFileSync(certFile, certPem);

    // ---- (a) OURS (classic HMAC + PBES2 bags) -> OpenSSL verifies + decrypts ----
    var oursClassic = await pki.pkcs12.build({ safeContents: [
      { encrypt: { password: PW, cipher: "aes-256-cbc" }, bags: [{ type: "cert", cert: s.cert }] },
      { bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: PW, cipher: "aes-256-cbc" } }] } ] },
      { password: PW, mac: { algorithm: "hmac", hash: "sha256", iterations: 2048 } });
    var ocFile = path.join(dir, "ours-classic.p12"); fs.writeFileSync(ocFile, oursClassic);
    var mv = ctx.runOpenssl(["pkcs12", "-in", ocFile, "-noout", "-passin", "pass:" + PW], { allowNonZero: true });
    check("openssl verifies the toolkit classic-HMAC PKCS#12 MAC", mv.code === 0);
    var info = ctx.runOpenssl(["pkcs12", "-in", ocFile, "-info", "-nodes", "-passin", "pass:" + PW], { allowNonZero: true });
    check("openssl decrypts + lists the toolkit classic PKCS#12 (cert bag)", /BEGIN CERTIFICATE/.test(info.stdout));
    check("openssl decrypts + lists the toolkit classic PKCS#12 (shrouded key)", /BEGIN PRIVATE KEY/.test(info.stdout));

    // ---- (b) OURS (PBMAC1) -> OpenSSL verifies + lists ----
    var oursPbmac1 = await pki.pkcs12.build({ safeContents: [{ bags: [
      { type: "cert", cert: s.cert }, { type: "shroudedKey", key: s.key, encrypt: { password: PW } } ] }] },
      { password: PW, mac: { algorithm: "pbmac1", hash: "sha256" } });
    var opFile = path.join(dir, "ours-pbmac1.p12"); fs.writeFileSync(opFile, oursPbmac1);
    var pinfo = ctx.runOpenssl(["pkcs12", "-in", opFile, "-info", "-nodes", "-passin", "pass:" + PW], { allowNonZero: true });
    check("openssl verifies + lists the toolkit PBMAC1 PKCS#12", pinfo.code === 0 && /BEGIN CERTIFICATE/.test(pinfo.stdout));

    // ---- (c) OpenSSL-exported store -> the toolkit parses + verifies its MAC ----
    var oClassic = path.join(dir, "openssl-classic.p12");
    var ec = ctx.runOpenssl(["pkcs12", "-export", "-inkey", keyFile, "-in", certFile, "-passout", "pass:" + PW,
      "-macalg", "sha256", "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-iter", "2048", "-name", "t", "-out", oClassic], { allowNonZero: true });
    check("openssl exports a classic PKCS#12", ec.code === 0);
    var parsedClassic = pki.schema.pkcs12.parse(fs.readFileSync(oClassic));
    check("the toolkit parses the OpenSSL classic PKCS#12", parsedClassic.integrityMode === "password" && parsedClassic.mac.kind === "hmac");
    check("pki.pkcs12.verifyMac accepts the OpenSSL classic PKCS#12", (await pki.pkcs12.verifyMac(parsedClassic, PW)) === true);
    check("pki.pkcs12.verifyMac rejects a wrong password on the OpenSSL store", (await pki.pkcs12.verifyMac(parsedClassic, "wrong")) === false);

    var oPbmac1 = path.join(dir, "openssl-pbmac1.p12");
    var ep = ctx.runOpenssl(["pkcs12", "-export", "-inkey", keyFile, "-in", certFile, "-passout", "pass:" + PW,
      "-pbmac1_pbkdf2", "-pbmac1_pbkdf2_md", "sha256", "-macalg", "sha256", "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-name", "t", "-out", oPbmac1], { allowNonZero: true });
    if (ep.code === 0) {
      var parsedPbmac1 = pki.schema.pkcs12.parse(fs.readFileSync(oPbmac1));
      check("the toolkit parses the OpenSSL PBMAC1 PKCS#12", parsedPbmac1.mac.kind === "pbmac1");
      check("pki.pkcs12.verifyMac accepts the OpenSSL PBMAC1 PKCS#12", (await pki.pkcs12.verifyMac(parsedPbmac1, PW)) === true);
    } else {
      ctx.skip("openssl could not export a -pbmac1_pbkdf2 store -- PBMAC1 inbound interop not cross-checked");
    }
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
