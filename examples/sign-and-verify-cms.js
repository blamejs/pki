// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Sign a document and verify the signature (CMS SignedData, RFC 5652).
 *
 *   node examples/sign-and-verify-cms.js
 *
 * Signs bytes into a SignedData, verifies it, and shows what changes when the content is
 * detached and when the signature is over content that has since been altered. No network,
 * nothing written to disk.
 */

var pki = require("@blamejs/pki");

async function main() {
  // A signer needs a key and a certificate naming it: a signature that no certificate binds to an
  // identity proves only that someone held a key.
  var keys = await pki.key.generate("ML-DSA-65");
  var key = await pki.key.export(keys.privateKey);
  var now = new Date();
  var cert = await pki.x509.sign({
    subject: pki.x509.parseDn("CN=signer.example").bytes,
    subjectPublicKey: await pki.key.export(keys.publicKey),
    notBefore: now,
    notAfter: new Date(now.getTime() + pki.C.TIME.days(365)),
    extensions: { keyUsage: ["digitalSignature"] },
  }, { key: key });

  var content = Buffer.from("the bytes under signature", "utf8");
  var signed = await pki.cms.sign(content, { cert: cert, key: key });
  console.log("signeddata:   " + signed.length + " bytes");

  // Verifying against the signer certificate. `verify` answers about the signature; whether that
  // certificate is trusted is what pki.path.validate answers, and they are separate questions.
  var ok = await pki.cms.verify(signed, { certs: [cert] });
  console.log("verified:     " + ok.valid);
  console.log("signers:      " + ok.signers.length);

  // Detached: the signature travels without the content, so the verifier is given the content it
  // already has. This is how a signature over a large artifact is shipped.
  var detached = await pki.cms.sign(content, { cert: cert, key: key }, { detached: true });
  var okDetached = await pki.cms.verify(detached, { certs: [cert], content: content });
  console.log("detached:     " + detached.length + " bytes, verified " + okDetached.valid);

  // The same detached signature against content that changed by one byte. A signature is over
  // bytes, so this is the answer that makes it worth having.
  var altered = Buffer.from(content);
  altered[0] ^= 0x01;
  var verdict;
  try {
    var bad = await pki.cms.verify(detached, { certs: [cert], content: altered });
    verdict = bad.valid ? "accepted (this would be a defect)" : "rejected";
  } catch (e) {
    verdict = "rejected (" + (e.code || "threw") + ")";
  }
  console.log("altered:      " + verdict);
}

main().then(null, function (e) {
  console.error(e && (e.code ? e.code + ": " + e.message : e.message));
  process.exitCode = 1;
});
