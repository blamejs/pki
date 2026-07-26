// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- S/MIME header protection (RFC 9788) cross-implementation interop. OpenSSL has NO
 * header-protection mode: it neither generates nor interprets the `hp` Content-Type parameter. So interop is
 * STRUCTURAL -- OpenSSL must still parse a header-protected message we emit (its outer display headers precede
 * the Cryptographic Envelope's Content-Type), verify the CMS signature over our `hp="clear"` payload, and
 * decrypt our `hp="cipher"` payload -- recovering the inner Cryptographic Payload bytes, which carry the `hp`
 * marker + the protected headers. The HP-specific outer-vs-inner semantics are our own round-trip, not
 * OpenSSL's. Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var helpers = require("../helpers");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-smimehp-"));
  try {
    // ---- Gate A: OUR signed-HP (hp="clear") message -> openssl smime -verify ----
    var s = signing.makeSigner("rsa");
    var signedHp = await pki.smime.sign(Buffer.from("the message body\n"), [{ cert: s.cert, key: s.key }],
      { protectHeaders: true, headers: { Subject: "Interop subject", From: "a@ex.example" } });
    var msgFile = path.join(dir, "signed-hp.eml"); fs.writeFileSync(msgFile, signedHp);
    var recFile = path.join(dir, "recovered.txt");
    // -noverify: check the CMS signature but skip the signer-cert chain (our minimal signer certs are self-issued).
    var vr = ctx.runOpenssl(["smime", "-verify", "-in", msgFile, "-noverify", "-out", recFile], { allowNonZero: true });
    check("Gate A: openssl smime -verify accepts + validates our header-protected signed message", vr.code === 0);
    if (fs.existsSync(recFile)) {
      var rec = fs.readFileSync(recFile).toString("latin1");
      check("Gate A: the openssl-recovered payload carries the hp=clear marker + the protected Subject", /hp="?clear"?/.test(rec) && rec.indexOf("Interop subject") >= 0);
    }

    // ---- Gate B: OUR encrypted-HP (hp="cipher") message -> openssl smime -decrypt ----
    var r = signing.makeRecipient("rsa");
    var rKeyFile = path.join(dir, "rkey.pem"); fs.writeFileSync(rKeyFile, pki.schema.pkcs8.pemEncode(r.key, "PRIVATE KEY"));
    var rCertFile = path.join(dir, "rcert.pem"); fs.writeFileSync(rCertFile, pki.schema.x509.pemEncode(r.cert, "CERTIFICATE"));
    var encHp = await pki.smime.encrypt(Buffer.from("the message body\n"), [{ cert: r.cert }],
      { protectHeaders: true, headers: { Subject: "Secret subject", From: "a@ex.example" } });
    var encFile = path.join(dir, "enc-hp.eml"); fs.writeFileSync(encFile, encHp);
    var decFile = path.join(dir, "decrypted.txt");
    // `cms` (not `smime`) -- our default is AES-GCM AuthEnvelopedData, which the legacy `smime` verb predates.
    var dr = ctx.runOpenssl(["cms", "-decrypt", "-in", encFile, "-recip", rCertFile, "-inkey", rKeyFile, "-out", decFile], { allowNonZero: true });
    check("Gate B: openssl smime -decrypt opens our header-protected encrypted message", dr.code === 0);
    if (fs.existsSync(decFile)) {
      var dec = fs.readFileSync(decFile).toString("latin1");
      check("Gate B: the openssl-recovered payload carries hp=cipher + the REAL inner Subject", /hp="?cipher"?/.test(dec) && dec.indexOf("Secret subject") >= 0);
      check("Gate B: the obscured outer Subject value [...] is NOT in the recovered inner payload's real Subject", /Subject:\s*Secret subject/i.test(dec));
    }
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort cleanup */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + helpers.getChecks()); console.log("SKIPS " + helpers.getSkips()); },
  function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
);
