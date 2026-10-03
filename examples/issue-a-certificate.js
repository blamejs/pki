// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Issue a certificate from your own CA, then validate the path.
 *
 *   node examples/issue-a-certificate.js
 *
 * Generates a CA key and a self-signed CA certificate, generates a leaf key, issues a leaf
 * certificate from the CA, and validates leaf-against-CA through RFC 5280 path validation.
 * Nothing is written to disk and no network is used.
 */

var pki = require("@blamejs/pki");

// A subject is a distinguished name, and `pki.x509.parseDn(s).bytes` is how a DN string becomes one
// the builders take. Handing them the string directly is not an error and not the same thing: a bare
// string is read as a COMMON NAME, so "CN=Example CA, O=Example" would certify one commonName whose
// value is that whole text.
function dn(s) { return pki.x509.parseDn(s).bytes; }

async function main() {
  // A CA key and the self-signed certificate that names it. basicConstraints cA marks it as a CA
  // and keyCertSign is what lets it sign other certificates; a CA missing either is refused as an
  // issuer during path validation.
  var caKeys = await pki.key.generate("ML-DSA-65");
  var caSpki = await pki.key.export(caKeys.publicKey);
  var caKey = await pki.key.export(caKeys.privateKey);
  var now = new Date();
  var caDer = await pki.x509.sign({
    subject: dn("CN=Example CA, O=Example"),
    subjectPublicKey: caSpki,
    notBefore: now,
    notAfter: new Date(now.getTime() + pki.C.TIME.days(3650)),
    extensions: {
      basicConstraints: { cA: true },
      keyUsage: ["keyCertSign", "cRLSign"],
      subjectKeyIdentifier: true,
    },
  }, { key: caKey });
  console.log("ca subject:   " + pki.schema.x509.parse(caDer).subject.dn);

  // The leaf. Its key is its own; the CA only signs over its public half.
  var leafKeys = await pki.key.generate("ML-DSA-65");
  var leafDer = await pki.x509.sign({
    subject: dn("CN=host.example"),
    subjectPublicKey: await pki.key.export(leafKeys.publicKey),
    notBefore: now,
    notAfter: new Date(now.getTime() + pki.C.TIME.days(90)),
    extensions: {
      subjectAltName: ["host.example", "www.host.example"],
      keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["serverAuth"],
    },
  }, { key: caKey, cert: caDer });
  var leaf = pki.schema.x509.parse(leafDer);
  console.log("leaf subject: " + leaf.subject.dn);
  console.log("leaf issuer:  " + leaf.issuer.dn);
  console.log("leaf serial:  " + leaf.serialNumberHex.length / 2 + " bytes of entropy");

  // Path validation is the verb that decides whether the leaf is trusted, and it is separate from
  // having issued it: the anchor is supplied as a name and a key, never as bytes to be trusted.
  var ca = pki.schema.x509.parse(caDer);
  var result = await pki.path.validate([leafDer], {
    time: now,
    trustAnchors: {
      name: ca.subject,
      publicKey: ca.subjectPublicKeyInfo.bytes,
      algorithm: ca.subjectPublicKeyInfo.algorithm.oid,
    },
  });
  console.log("path valid:   " + result.valid);

  // The same validation one day after the leaf expires. A certificate outside its validity window
  // is not trusted, which is the check an expiry outage is.
  var expired = await pki.path.validate([leafDer], {
    time: new Date(now.getTime() + pki.C.TIME.days(91)),
    trustAnchors: {
      name: ca.subject,
      publicKey: ca.subjectPublicKeyInfo.bytes,
      algorithm: ca.subjectPublicKeyInfo.algorithm.oid,
    },
  });
  console.log("after expiry: " + expired.valid);
}

main().then(null, function (e) {
  console.error(e && (e.code ? e.code + ": " + e.message : e.message));
  process.exitCode = 1;
});
