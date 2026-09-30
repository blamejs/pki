// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Post-quantum signatures and key establishment, through the same verbs as everything else.
 *
 *   node examples/post-quantum.js
 *
 * ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) sign certificates here the way ECDSA and Ed25519 do:
 * an algorithm is a registry entry, so nothing about issuing, verifying or validating a path
 * changes with the suite. ML-KEM (FIPS 203) does key establishment. No network.
 */

var pki = require("@blamejs/pki");

async function certificateFor(alg) {
  var keys = await pki.key.generate(alg);
  var now = new Date();
  var der = await pki.x509.sign({
    subject: pki.x509.parseDn("CN=" + alg.toLowerCase() + ".example").bytes,
    subjectPublicKey: await pki.key.export(keys.publicKey),
    notBefore: now,
    notAfter: new Date(now.getTime() + pki.C.TIME.days(365)),
    extensions: { keyUsage: ["digitalSignature"] },
  }, { key: await pki.key.export(keys.privateKey) });
  return { der: der, cert: pki.schema.x509.parse(der) };
}

async function main() {
  // The same call shape across three signature families. The name the certificate carries comes
  // from the OID registry, so a reader sees the algorithm rather than a dotted string.
  for (var alg of ["ML-DSA-65", "SLH-DSA-SHA2-128s", "Ed25519"]) {
    var made = await certificateFor(alg);
    console.log(alg.padEnd(18) + " certificate " + String(made.der.length).padStart(6) +
      " bytes, signed with " + made.cert.signatureAlgorithm.name);
  }

  // A post-quantum certificate validates through the same path validator, with no suite-specific
  // argument: the anchor names its own key algorithm and the verifier resolves the rest.
  var ca = await certificateFor("ML-DSA-65");
  var result = await pki.path.validate([ca.der], {
    time: new Date(),
    trustAnchors: {
      name: ca.cert.subject,
      publicKey: ca.cert.subjectPublicKeyInfo.bytes,
      algorithm: ca.cert.subjectPublicKeyInfo.algorithm.oid,
    },
  });
  console.log("path validates with a post-quantum anchor: " + result.valid);

  // ML-KEM is key establishment rather than signing: the sender encapsulates to the recipient's
  // public key and both sides end up with the same secret, which neither transmitted. This is the
  // pair the CMS KEMRecipientInfo arm rides on.
  var kemAlg = { name: "ML-KEM-768" };
  var kem = await pki.key.generate("ML-KEM-768");
  var sent = await pki.webcrypto.subtle.encapsulateBits(kemAlg, kem.publicKey);
  var received = await pki.webcrypto.subtle.decapsulateBits(kemAlg, kem.privateKey, sent.ciphertext);
  var agreed = Buffer.compare(Buffer.from(sent.sharedKey), Buffer.from(received)) === 0;
  console.log("ml-kem-768 ciphertext " + sent.ciphertext.byteLength + " bytes, shared secret " +
    sent.sharedKey.byteLength + " bytes, both sides agree: " + agreed);
}

main().then(null, function (e) {
  console.error(e && (e.code ? e.code + ": " + e.message : e.message));
  process.exitCode = 1;
});
