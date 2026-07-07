// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.schema (the family orchestrator). Detect-and-route dispatch +
 * the stable schema/* error codes. SchemaError is (code, message), so a caller
 * reading err.code must see the schema/* code, not the human message.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var fs = require("fs");
var path = require("path");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }

function crlDer() {
  var tbs = b.sequence([
    b.sequence([b.oid("1.2.840.10045.4.3.2")]),
    b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("CA")])])]),
    b.utcTime(new Date("2026-01-01T00:00:00Z")),
  ]);
  return b.sequence([tbs, b.sequence([b.oid("1.2.840.10045.4.3.2")]), b.bitString(Buffer.from([0x00]), 0)]);
}

function run() {
  check("all() lists the registered formats in detection order", JSON.stringify(pki.schema.all()) === JSON.stringify(["cms", "tsp", "crmf", "ocsp-request", "ocsp-response", "pkcs8", "csr", "attrcert", "attrcert-v1", "crl", "x509"]));

  // A CertReqMessages (RFC 4211) routes to crmf, not to the ocsp-request it sits ahead of.
  var crmfSubject = b.contextConstructed(5, b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("req")])]));
  var crmfDer = b.sequence([b.sequence([b.sequence([b.integer(0n), b.sequence([crmfSubject])])])]);
  check("parse routes a CertReqMessages to crmf", Array.isArray(pki.schema.parse(crmfDer).messages));

  var certPem = fs.readFileSync(path.join(__dirname, "..", "fixtures", "pkijs-selfsigned-ec.pem"), "utf8");
  var cert = pki.schema.parse(certPem);
  check("parse routes a certificate to x509", cert.version === 3 && cert.validity && cert.validity.notBefore instanceof Date);

  var crl = pki.schema.parse(crlDer());
  check("parse routes a CRL to crl", crl.thisUpdate instanceof Date && Array.isArray(crl.revokedCertificates));

  // A .pem file read with fs.readFileSync arrives as a Buffer of ASCII armor,
  // not DER — parse must unwrap it, then route.
  check("parse unwraps + routes a PEM Buffer (readFileSync path)", pki.schema.parse(Buffer.from(certPem, "utf8")).version === 3);
  // A raw DER Buffer still routes directly.
  check("parse routes a raw DER Buffer", pki.schema.parse(pki.schema.x509.pemDecode(certPem, "CERTIFICATE")).version === 3);

  // Stable schema/* codes: err.code must be the code, not the message
  // (SchemaError is (code, message); the base PkiError is (message, code)).
  check("unknown format → err.code schema/unknown-format", code(function () { pki.schema.parse(b.integer(5n)); }) === "schema/unknown-format");
  check("bad input → err.code schema/bad-input", code(function () { pki.schema.parse(42); }) === "schema/bad-input");
  check("undecodable DER → err.code schema/bad-der", code(function () { pki.schema.parse(Buffer.from([0x30, 0x80])); }) === "schema/bad-der");

  // A CertificationRequestInfo missing the mandatory [0] attributes element (only
  // 3 children) is neither a certificate (no Validity) nor a well-formed CSR (no
  // attributes) — it must NOT be misrouted; it is an unknown format.
  var incompleteCri = b.sequence([
    b.sequence([b.integer(0n), b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("req")])])]), b.sequence([b.sequence([b.oid("1.2.840.10045.2.1")]), b.bitString(Buffer.from([1, 2, 3]), 0)])]),
    b.sequence([b.oid("1.2.840.10045.4.3.2")]),
    b.bitString(Buffer.from([0x00]), 0),
  ]);
  check("an incomplete CRI (no [0] attributes) is unknown-format (not misrouted)", code(function () { pki.schema.parse(incompleteCri); }) === "schema/unknown-format");

  // A complete PKCS#10 CSR (a 4-child CRI ending in the IMPLICIT [0] attributes)
  // routes to csr — never misclassified as a certificate or CRL.
  var completeCsr = b.sequence([
    b.sequence([
      b.integer(0n),
      b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("req.example")])])]),
      b.sequence([b.sequence([b.oid("1.2.840.10045.2.1"), b.oid("1.2.840.10045.3.1.7")]), b.bitString(Buffer.from([0x04, 1, 2, 3]), 0)]),
      b.contextConstructed(0, Buffer.alloc(0)),
    ]),
    b.sequence([b.oid("1.2.840.10045.4.3.2")]),
    b.bitString(Buffer.from([0x00]), 0),
  ]);
  var routedCsr = pki.schema.parse(completeCsr);
  check("parse routes a complete CSR to csr", routedCsr.version === 1 && routedCsr.subject.dn === "CN=req.example" && Array.isArray(routedCsr.attributes));
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
