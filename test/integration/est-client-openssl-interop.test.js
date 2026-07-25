// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- EST client (RFC 7030) cross-implementation interop.
 *
 * There is no `openssl est`, so the oracle drops to the COMPOSED layer: an EST /cacerts and
 * /simpleenroll response is a certs-only degenerate PKCS#7 (an RFC 5272 Simple PKI Response),
 * which `openssl crl2pkcs7 -nocrl` produces and `openssl pkcs7 -print_certs` consumes. The bytes
 * ride an INJECTED transport (no live server), so this validates that our client correctly parses
 * OpenSSL-produced certs-only PKCS#7 -- both directions -- and picks the issued certificate by
 * public-key match when OpenSSL acts as the issuing CA.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var fakeTransport = require("../helpers/fake-transport").fakeTransport;
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var b = pki.asn1.build;
var ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var ID_DATA = "1.2.840.113549.1.7.1";
function certsOnly(certs) {
  var sd = [b.integer(1n), b.set([]), b.sequence([b.oid(ID_DATA)])];
  sd.push(b.contextConstructed(0, Buffer.concat(certs.slice().sort(Buffer.compare))));
  sd.push(b.set([]));
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence(sd))]);
}

async function run() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-est-"));
  function p(name) { return path.join(dir, name); }
  try {
    // Two self-signed CA certs from OpenSSL.
    ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", p("a.key"), "-out", p("a.pem"), "-days", "3650", "-subj", "/CN=EST CA A"]);
    ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", p("b.key"), "-out", p("b.pem"), "-days", "3650", "-subj", "/CN=EST CA B"]);
    ctx.runOpenssl(["x509", "-in", p("a.pem"), "-outform", "DER", "-out", p("a.der")]);
    ctx.runOpenssl(["x509", "-in", p("b.pem"), "-outform", "DER", "-out", p("b.der")]);
    var certAder = fs.readFileSync(p("a.der"));
    var certBder = fs.readFileSync(p("b.der"));

    // ---- Gate A (forward): openssl certs-only PKCS#7 -> our cacerts parses it ----
    // The certificates field is a DER SET OF, so it must be ascending -- our strict parser rejects
    // an unsorted set (X.690 sec. 11.6). crl2pkcs7 emits the certs in -certfile order, so they are
    // passed DER-sorted to produce a canonical container an EST server would return.
    var order = Buffer.compare(certAder, certBder) <= 0 ? [p("a.pem"), p("b.pem")] : [p("b.pem"), p("a.pem")];
    ctx.runOpenssl(["crl2pkcs7", "-nocrl", "-certfile", order[0], "-certfile", order[1], "-outform", "DER", "-out", p("cacerts.p7")]);
    var bagDer = fs.readFileSync(p("cacerts.p7"));
    var t = fakeTransport({ status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: pki.est.transferEncode(bagDer) });
    var r = await pki.est.cacerts("https://ca.example", { transport: t });
    check("Gate A: our cacerts parses an OpenSSL certs-only PKCS#7 (both certs)", r.certificates.length === 2);
    check("Gate A: the returned certs byte-equal the OpenSSL certs (order-independent)",
      r.certificates.some(function (c) { return c.equals(certAder); }) && r.certificates.some(function (c) { return c.equals(certBder); }));

    // ---- Gate B (reverse): our certs-only bag -> openssl pkcs7 -print_certs reads it ----
    var ourBag = certsOnly([certAder, certBder]);
    var printed = ctx.runOpenssl(["pkcs7", "-inform", "DER", "-print_certs", "-noout"], { input: ourBag });
    check("Gate B: OpenSSL enumerates both subjects in our certs-only bag", /EST CA A/.test(printed) && /EST CA B/.test(printed));

    // ---- Gate C (simpleenroll): OpenSSL issues a cert for OUR CSR key; simpleenroll picks it by SPKI ----
    var s = signing.makeSigner("ec-p256", { cn: "device.example" });
    var csrPem = await pki.csr.sign({ subject: "device.example", subjectPublicKey: s.spki }, { key: s.key }, { pem: true });
    fs.writeFileSync(p("device.csr"), csrPem);
    ctx.runOpenssl(["x509", "-req", "-in", p("device.csr"), "-CA", p("a.pem"), "-CAkey", p("a.key"), "-days", "365", "-outform", "DER", "-out", p("issued.der")]);
    var issuedDer = fs.readFileSync(p("issued.der"));
    var enrollBag = certsOnly([issuedDer, certAder]);   // the leaf plus the CA (chain)
    var t2 = fakeTransport({ status: 200, headers: { "content-type": "application/pkcs7-mime; smime-type=certs-only" }, body: pki.est.transferEncode(enrollBag) });
    var er = await pki.est.simpleenroll("https://ca.example", csrPem, { transport: t2 });
    check("Gate C: simpleenroll picks the OpenSSL-issued cert by public-key match", er.certificate.equals(issuedDer));
    check("Gate C: the CA cert is surfaced as chain", er.chain.length === 1 && er.chain[0].equals(certAder));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
