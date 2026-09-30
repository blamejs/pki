// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- PKCS#10 certification-request issuance (pki.csr.sign) cross-implementation interop.
 *
 * OpenSSL is the independent oracle for the toolkit's CSR producing side:
 *  (a) a certification request the toolkit issues parses (`openssl req -text`) and its proof-of-possession
 *      self-signature verifies (`openssl req -verify`) across a classical arm (RSA, ECDSA, EdDSA) and, on
 *      OpenSSL >= 3.5, the post-quantum ML-DSA and SLH-DSA arms;
 *  (b) a request whose proof-of-possession signature byte is flipped is REJECTED by `openssl req -verify`.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");

async function run() {
  var arms = ["rsa", "ec-p256", "ec-p521", "ed25519", "ed448"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65");
  if (ctx.opensslSupports("SLH-DSA")) arms.push("slh-dsa-sha2-128f");

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var pem = await pki.csr.sign({
      subject: [{ commonName: alg + " request" }, { organizationName: "Interop" }, { countryName: "US" }],
      subjectPublicKey: s.spki,
      extensionRequest: { subjectAltName: [{ dNSName: "req.example" }] },
    }, { key: s.key }, { pem: true });
    ctx.withTmp(Buffer.from(pem, "utf8"), "csr-" + alg + ".pem", function (p) {
      var t = ctx.runOpenssl(["req", "-in", p, "-noout", "-text"], { allowNonZero: true });
      check("openssl req -text parses the toolkit-issued " + alg + " request", t.code === 0);
      var v = ctx.runOpenssl(["req", "-in", p, "-noout", "-verify"], { allowNonZero: true });
      check("openssl req -verify accepts the toolkit-issued " + alg + " proof of possession", v.code === 0);
    });
  }

  // A request naming the subject-owned extensions that reach it through the certificate encoders.
  // OpenSSL decodes the access description and the attribute value out of the request, and its
  // proof-of-possession check still passes, so the attribute is well-formed where it sits.
  var s3 = signing.makeSigner("ec-p256");
  var ownPem = await pki.csr.sign({
    subject: [{ commonName: "own.interop.example" }], subjectPublicKey: s3.spki,
    extensionRequest: {
      msCertificateTemplate: { templateID: "1.3.6.1.4.1.311.21.8.1.2", templateMajorVersion: 100, templateMinorVersion: 2 },
      subjectInfoAccess: [{ accessMethod: "id-ad-caRepository", accessLocation: { uniformResourceIdentifier: "https://r.interop.example" } }],
      subjectDirectoryAttributes: [{ type: "1.3.6.1.4.1.99999.1", values: [pki.asn1.build.utf8("DE")] }],
    },
  }, { key: s3.key }, { pem: true });
  ctx.withTmp(Buffer.from(ownPem, "utf8"), "csr-own.pem", function (p) {
    var t = ctx.runOpenssl(["req", "-in", p, "-noout", "-text"], { allowNonZero: true });
    check("openssl req -text parses a request carrying the subject-owned extensions", t.code === 0);
    // Names are release-dependent, so presence is by name or OID; the decoded VALUES are the oracle.
    check("openssl shows the requested certificate template, named or by OID",
      /Microsoft certificate template/i.test(t.stdout) || t.stdout.indexOf("1.3.6.1.4.1.311.21.7") >= 0);
    check("openssl decodes the requested subject information access down to its location",
      /CA Repository/i.test(t.stdout) && /URI:https:\/\/r\.interop\.example/.test(t.stdout));
    check("openssl decodes the requested subject directory attribute value", /\bDE\b/.test(t.stdout));
    var v = ctx.runOpenssl(["req", "-in", p, "-noout", "-verify"], { allowNonZero: true });
    check("openssl req -verify still accepts the proof of possession with them present", v.code === 0);
  });

  // RFC 9763 sec. 3.1's relatedCertRequest attribute. The two properties an independent
  // implementation has to confirm are that an unknown attribute does not stop the request being read,
  // and that the request's own proof of possession still verifies with it present -- an attribute that
  // broke `req -verify` would make the extension unusable in enrollment. openssl has no name for the
  // OID, so its ASN.1 parser is the oracle for the value: it walks the RequesterCertificate and
  // reports the serial, the BinaryTime and each IA5String URI, independently of our decoder.
  var rcHeld = signing.makeSigner("ec-p256", { cn: "Held Interop", serial: 0x77 });
  var rcHeldParsed = pki.schema.x509.parse(rcHeld.cert);
  var rcNew = signing.makeSigner("ec-p256");
  var rcCertId = { issuer: rcHeldParsed.issuer.bytes, serialNumber: rcHeldParsed.serialNumber };
  var rcWhen = 1800000000;
  var rcUris = ["https://a.interop.example/held.cer", "https://b.interop.example/held.cer"];
  var rcProof = require("node:crypto").sign("sha256",
    pki.relatedCert.requestSignedData({ certID: rcCertId, requestTime: rcWhen }),
    { key: rcHeld.keyObject, dsaEncoding: "der" });
  var rcPem = await pki.csr.sign({
    subject: [{ commonName: "related.interop.example" }], subjectPublicKey: rcNew.spki,
    relatedCertRequest: { certID: rcCertId, requestTime: rcWhen, locationInfo: rcUris, signature: rcProof },
  }, { key: rcNew.key }, { pem: true });
  var rcDer = pki.schema.csr.pemDecode(rcPem);
  var rcAttr = pki.schema.csr.parse(rcDer).attributes
    .filter(function (a) { return a.type === "1.2.840.113549.1.9.16.2.60"; })[0];
  ctx.withTmp(Buffer.from(rcPem, "utf8"), "csr-related.pem", function (p) {
    var t = ctx.runOpenssl(["req", "-in", p, "-noout", "-text"], { allowNonZero: true });
    check("openssl req -text parses a request carrying the relatedCertRequest attribute", t.code === 0);
    check("openssl reports the attribute by its OID", t.stdout.indexOf("1.2.840.113549.1.9.16.2.60") >= 0);
    var v = ctx.runOpenssl(["req", "-in", p, "-noout", "-verify"], { allowNonZero: true });
    check("openssl req -verify still accepts the request's own proof of possession with it present", v.code === 0);
    var reDer = p.replace(/\.pem$/, ".der");
    var re = ctx.runOpenssl(["req", "-in", p, "-outform", "DER", "-out", reDer], { allowNonZero: true });
    check("openssl re-encodes the request to the same bytes, carrying the attribute unaltered",
      re.code === 0 && Buffer.compare(require("node:fs").readFileSync(reDer), rcDer) === 0);
  });
  ctx.withTmp(rcAttr.values[0], "related-attr.der", function (p) {
    var a1 = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p], { allowNonZero: true });
    check("openssl's ASN.1 parser walks the RequesterCertificate value", a1.code === 0);
    check("openssl reads the certID serial the attribute names",
      /INTEGER\s*:77\b/.test(a1.stdout));
    check("openssl reads the BinaryTime as the integer seconds it is",
      a1.stdout.indexOf(":6B49D200") >= 0);
    check("openssl reads every locationInfo URI as an IA5String, in the order written",
      a1.stdout.indexOf("IA5STRING         :" + rcUris[0]) >= 0 &&
      a1.stdout.indexOf("IA5STRING         :" + rcUris[1]) >= 0 &&
      a1.stdout.indexOf(rcUris[0]) < a1.stdout.indexOf(rcUris[1]));
  });
  check("the proof in the request openssl accepted verifies here too",
    (await pki.relatedCert.verifyRequest(rcAttr.relatedCertRequest, rcHeld.cert)) === true);

  // A tampered proof-of-possession signature is rejected.
  var s2 = signing.makeSigner("ec-p256");
  var der = await pki.csr.sign({ subject: "tamper.example", subjectPublicKey: s2.spki }, { key: s2.key });
  var bad = Buffer.from(der); bad[bad.length - 1] ^= 0xff;   // flip a signature byte
  ctx.withTmp(Buffer.from(pki.schema.csr.pemEncode(bad, "CERTIFICATE REQUEST"), "utf8"), "csr-bad.pem", function (p) {
    var v = ctx.runOpenssl(["req", "-in", p, "-noout", "-verify"], { allowNonZero: true });
    check("openssl req -verify REJECTS a toolkit request with a flipped signature byte", v.code !== 0);
  });
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
