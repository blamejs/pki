// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- PKCS#12 public-key integrity (RFC 7292 sec. 4) cross-implementation interop.
 *
 * OpenSSL 3.5.7 `pkcs12` is PASSWORD-integrity ONLY (its -help exposes only MAC controls), so it cannot
 * produce or consume a public-key-integrity PFX directly. But a public-key PFX's authSafe IS a CMS
 * SignedData, so `openssl cms` is the oracle at the CMS layer:
 *   Gate A (ours -> openssl): the authSafe ContentInfo of a PFX we build verifies under
 *     `openssl cms -verify -noverify`, and the recovered content byte-equals our AuthenticatedSafe.
 *   Gate B (openssl -> ours): OpenSSL signs our AuthenticatedSafe with `openssl cms -sign -nodetach`;
 *     wrapped as a PFX, that store opens through pki.pkcs12.open (its signature verifies, its bags decrypt).
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var PW = "P";

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-p12pk-"));
  try {
    var s = signing.makeSigner("rsa");
    var keyFile = path.join(dir, "key.pem"); fs.writeFileSync(keyFile, pki.schema.pkcs8.pemEncode(s.key, "PRIVATE KEY"));
    var certFile = path.join(dir, "cert.pem"); fs.writeFileSync(certFile, pki.schema.x509.pemEncode(s.cert, "CERTIFICATE"));
    var bagSpec = { safeContents: [
      { encrypt: { password: PW }, bags: [{ type: "cert", cert: s.cert }] },
      { bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: PW } }] } ] };

    // ---- Gate A: OURS public-key PFX -> openssl cms verifies the authSafe ----
    var pfx = await pki.pkcs12.build(bagSpec, { integrity: { mode: "public-key", signer: { cert: s.cert, key: s.key } }, password: PW });
    var m = pki.schema.pkcs12.parse(pfx);
    var authSafeCi = pki.asn1.decode(pfx).children[1].bytes;          // the id-signedData authSafe ContentInfo
    var ourAuthSafe = Buffer.from(m.authSafeSigned.encapContentInfo.eContent);
    var ciFile = path.join(dir, "authsafe.der"); fs.writeFileSync(ciFile, authSafeCi);
    var outFile = path.join(dir, "recovered.bin");
    var v = ctx.runOpenssl(["cms", "-verify", "-inform", "DER", "-in", ciFile, "-noverify", "-binary", "-out", outFile], { allowNonZero: true });
    check("Gate A: openssl cms -verify accepts our public-key PFX authSafe signature", v.code === 0);
    check("Gate A: the openssl-recovered content byte-equals our AuthenticatedSafe", fs.existsSync(outFile) && Buffer.compare(fs.readFileSync(outFile), ourAuthSafe) === 0);

    // ---- Gate B: openssl-signed AuthenticatedSafe -> our pki.pkcs12.open ----
    // extract the AuthenticatedSafe from a password store (macedBytes IS the AuthenticatedSafe DER).
    var pwPfx = await pki.pkcs12.build(bagSpec, { password: PW, mac: { algorithm: "hmac", hash: "sha256" } });
    var authSafeDer = Buffer.from(pki.schema.pkcs12.parse(pwPfx).macedBytes);
    var asFile = path.join(dir, "as.der"); fs.writeFileSync(asFile, authSafeDer);
    var signedFile = path.join(dir, "signed.der");
    var sg = ctx.runOpenssl(["cms", "-sign", "-signer", certFile, "-inkey", keyFile, "-in", asFile, "-binary", "-nodetach", "-outform", "DER", "-out", signedFile], { allowNonZero: true });
    check("Gate B: openssl cms -sign wraps our AuthenticatedSafe as an id-signedData ContentInfo", sg.code === 0 && fs.existsSync(signedFile));
    if (sg.code === 0) {
      var opensslPfx = pki.asn1.build.sequence([pki.asn1.build.integer(3n), pki.asn1.build.raw(fs.readFileSync(signedFile))]);
      var opened = await pki.pkcs12.open(opensslPfx, PW);
      check("Gate B: the openssl-produced public-key PFX opens through pki.pkcs12.open", opened.integrityMode === "public-key" && opened.signers[0].ok === true);
      check("Gate B: its bags decrypt (key + cert recovered)", opened.keys.length === 1 && opened.certs.length === 1);
    }
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
