// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Revoke a certificate and see a path stop trusting it (CRL, RFC 5280 section 5).
 *
 *   node examples/revoke-and-check.js
 *
 * Issues a leaf, validates it, publishes a CRL that revokes it, and validates again with that
 * CRL supplied. The second answer is the one revocation exists to produce. No network.
 */

var pki = require("@blamejs/pki");

function dn(s) { return pki.x509.parseDn(s).bytes; }

async function main() {
  var now = new Date();
  var caKeys = await pki.key.generate("Ed25519");
  var caKey = await pki.key.export(caKeys.privateKey);
  var caDer = await pki.x509.sign({
    subject: dn("CN=Revocation CA"),
    subjectPublicKey: await pki.key.export(caKeys.publicKey),
    notBefore: now,
    notAfter: new Date(now.getTime() + pki.C.TIME.days(3650)),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true },
  }, { key: caKey });
  var ca = pki.schema.x509.parse(caDer);

  var leafKeys = await pki.key.generate("Ed25519");
  var leafDer = await pki.x509.sign({
    subject: dn("CN=doomed.example"),
    subjectPublicKey: await pki.key.export(leafKeys.publicKey),
    notBefore: now,
    notAfter: new Date(now.getTime() + pki.C.TIME.days(90)),
    extensions: { keyUsage: ["digitalSignature"] },
  }, { key: caKey, cert: caDer });
  var leaf = pki.schema.x509.parse(leafDer);
  console.log("leaf serial:  " + leaf.serialNumberHex.slice(0, 16) + "...");

  var anchor = {
    name: ca.subject,
    publicKey: ca.subjectPublicKeyInfo.bytes,
    algorithm: ca.subjectPublicKeyInfo.algorithm.oid,
  };
  var before = await pki.path.validate([leafDer], { time: now, trustAnchors: anchor });
  console.log("before crl:   " + before.valid);

  // The CA publishes a CRL naming that serial. nextUpdate is required by RFC 5280 section 5.1.2.5
  // and is what tells a relying party how long the list may be believed.
  // The issuer argument names the CA through its certificate, so the spec does not repeat it: the
  // name a CRL is signed under is the one in that certificate.
  var crlDer = await pki.crl.sign({
    thisUpdate: now,
    nextUpdate: new Date(now.getTime() + pki.C.TIME.days(7)),
    crlNumber: 1n,
    revoked: [{
      serialNumber: BigInt("0x" + leaf.serialNumberHex),
      revocationDate: now,
      reason: "keyCompromise",
    }],
  }, { key: caKey, cert: caDer });
  var crl = pki.schema.crl.parse(crlDer);
  console.log("crl entries:  " + crl.revokedCertificates.length +
    ", next update in " + Math.round((crl.nextUpdate - crl.thisUpdate) / pki.C.TIME.days(1)) + " days");

  // The same path, with the CRL supplied. Revocation is a pluggable hook rather than a built-in
  // fetch: pki.path.crlChecker answers from the CRLs you hand it, and a validator given none
  // cannot know a certificate was revoked. Supplying it is what changes the answer.
  var after = await pki.path.validate([leafDer], {
    time: now,
    trustAnchors: anchor,
    revocationChecker: pki.path.crlChecker([crlDer]),
  });
  console.log("after crl:    " + after.valid);
  var reasons = [];
  (after.results || []).forEach(function (r) {
    (r.checks || []).forEach(function (c) { if (c.ok === false) reasons.push(c.code); });
  });
  console.log("refused for:  " + (reasons.join(", ") || "(nothing)"));
}

main().then(null, function (e) {
  console.error(e && (e.code ? e.code + ": " + e.message : e.message));
  process.exitCode = 1;
});
