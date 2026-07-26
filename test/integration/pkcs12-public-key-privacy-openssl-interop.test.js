// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- PKCS#12 public-key PRIVACY (RFC 7292 sec. 3.1) cross-implementation interop.
 *
 * OpenSSL `pkcs12` is PASSWORD-privacy ONLY, so it cannot produce or consume a public-key-privacy PFX
 * directly. But a public-key-privacy safe IS a CMS EnvelopedData (id-envelopedData over a SafeContents), so
 * `openssl cms` is the oracle at the CMS layer:
 *   Gate A (ours -> openssl): the id-envelopedData ContentInfo of a privacy PFX we build decrypts under
 *     `openssl cms -decrypt`, and the recovered SafeContents byte-equals what our own pki.cms.decrypt recovers.
 *   Gate B (openssl -> ours): OpenSSL encrypts our SafeContents to the recipient with `openssl cms -encrypt`;
 *     spliced as an AuthenticatedSafe element into a MAC-less PFX, that store opens through pki.pkcs12.open
 *     with opts.recipientKey (its bags decrypt).
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

var b = pki.asn1.build;
var O = pki.oid.byName;
var PW = "P";

// The id-envelopedData ContentInfo reconstructed from the parser-surfaced raw EnvelopedData bytes.
function envelopedContentInfo(pfx) {
  var env = pki.schema.pkcs12.parse(pfx).encryptedSafes.filter(function (e) { return e.type === "envelopedData"; })[0];
  return b.sequence([b.oid(O("envelopedData")), b.explicit(0, b.raw(env.envelopedDataDer))]);
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-p12priv-"));
  try {
    var payload = signing.makeSigner("rsa");                 // the key + cert stored in the pfx
    var r = signing.makeRecipient("rsa");                    // the privacy recipient (openssl-usable RSA key)
    var rKeyFile = path.join(dir, "rkey.pem"); fs.writeFileSync(rKeyFile, pki.schema.pkcs8.pemEncode(r.key, "PRIVATE KEY"));
    var rCertFile = path.join(dir, "rcert.pem"); fs.writeFileSync(rCertFile, pki.schema.x509.pemEncode(r.cert, "CERTIFICATE"));
    var scSpec = { safeContents: [{ bags: [{ type: "cert", cert: payload.cert }, { type: "key", key: payload.key }], recipients: [{ cert: r.cert }], contentEncryptionAlgorithm: "aes-256-cbc" }] };

    // ---- Gate A: OURS public-key-privacy envelope -> openssl cms -decrypt ----
    var pfx = await pki.pkcs12.build(scSpec, { password: PW });
    var ci = envelopedContentInfo(pfx);
    var ourSafeContents = Buffer.from((await pki.cms.decrypt(ci, { key: r.key, cert: r.cert })).content);   // our composed-layer recovery (the byte oracle)
    var ciFile = path.join(dir, "env.der"); fs.writeFileSync(ciFile, ci);
    var outFile = path.join(dir, "recovered.der");
    var d = ctx.runOpenssl(["cms", "-decrypt", "-inform", "DER", "-in", ciFile, "-recip", rCertFile, "-inkey", rKeyFile, "-binary", "-out", outFile], { allowNonZero: true });
    check("Gate A: openssl cms -decrypt opens our id-envelopedData privacy safe", d.code === 0);
    check("Gate A: the openssl-recovered SafeContents byte-equals ours", fs.existsSync(outFile) && Buffer.compare(fs.readFileSync(outFile), ourSafeContents) === 0);

    // ---- Gate B: openssl cms -encrypt over our SafeContents -> our pki.pkcs12.open ----
    var scFile = path.join(dir, "sc.der"); fs.writeFileSync(scFile, ourSafeContents);
    var encFile = path.join(dir, "env-openssl.der");
    var e = ctx.runOpenssl(["cms", "-encrypt", "-aes-256-cbc", "-in", scFile, "-outform", "DER", "-binary", "-out", encFile, rCertFile], { allowNonZero: true });
    check("Gate B: openssl cms -encrypt produces an EnvelopedData over our SafeContents", e.code === 0 && fs.existsSync(encFile));
    if (e.code === 0) {
      // AuthenticatedSafe ::= SEQUENCE OF ContentInfo -- one openssl id-envelopedData element; wrap in a
      // MAC-less PFX (id-data authSafe, no MacData) so no MAC recomputation is needed for the oracle.
      var authSafe = b.sequence([b.raw(fs.readFileSync(encFile))]);
      var pfxB = b.sequence([b.integer(3n), b.sequence([b.oid(O("data")), b.explicit(0, b.octetString(authSafe))])]);
      var openedB = await pki.pkcs12.open(pfxB, null, { allowUnauthenticated: true, recipientKey: r.key, recipientCert: r.cert });
      check("Gate B: the openssl-produced envelope opens through pki.pkcs12.open", openedB.keys.length === 1 && openedB.certs.length === 1);
    }
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
