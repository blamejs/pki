// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Read a certificate: parse it, render it, lint it, dump its bytes.
 *
 *   node examples/read-a-certificate.js
 *
 * The four ways this toolkit reads one certificate, from the structured fields a program uses to
 * the byte offsets a debugger needs. No network, nothing written to disk.
 */

var pki = require("@blamejs/pki");

async function main() {
  // A certificate to read. Any DER or PEM certificate works here; this one is generated so the
  // example needs no fixture.
  var keys = await pki.key.generate("Ed25519");
  var now = new Date();
  var der = await pki.x509.sign({
    subject: pki.x509.parseDn("CN=host.example, O=Example").bytes,
    subjectPublicKey: await pki.key.export(keys.publicKey),
    notBefore: now,
    notAfter: new Date(now.getTime() + pki.C.TIME.days(90)),
    extensions: { subjectAltName: ["host.example"], keyUsage: ["digitalSignature"] },
  }, { key: await pki.key.export(keys.privateKey) });

  // 1. parse -- the structured fields, validated. This is what a program reads.
  var cert = pki.schema.x509.parse(der);
  console.log("subject:      " + cert.subject.dn);
  console.log("algorithm:    " + cert.signatureAlgorithm.name);
  console.log("extensions:   " + cert.extensions.map(function (e) { return e.name || e.oid; }).join(", "));

  // 2. inspect -- the report a person reads, the pure-JS equivalent of `openssl x509 -text`.
  //    pki.inspect.any detects the format, so the same call reads a CRL or a CMS message.
  var report = pki.inspect.any(der);
  console.log("report lines: " + report.split("\n").length);

  // 3. lint -- graded conformance findings. The data path never throws: malformed bytes become a
  //    fatal finding rather than an exception, so a survey over a corpus cannot be stopped by one
  //    bad file. `worst` is the highest severity present, and "pass" means nothing was found.
  var lint = pki.lint.certificate(der);
  console.log("lint worst:   " + (lint.worst || "pass"));
  console.log("lint findings: " + lint.findings.length);

  // 4. asn1 -- the structural dump, in the shape `openssl asn1parse` prints. This one renders every
  //    value in the file, so it is the verb to reach for on a file that is wrong rather than one
  //    holding a key.
  var dump = pki.inspect.asn1(der);
  console.log("first node:   " + dump.split("\n")[1].trim());
}

main().then(null, function (e) {
  console.error(e && (e.code ? e.code + ": " + e.message : e.message));
  process.exitCode = 1;
});
