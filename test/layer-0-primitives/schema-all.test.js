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

// The matches() detectors are internal dispatch infrastructure (off the curated
// surface) — reached via the modules directly, keyed by registry name.
var DETECTORS = {
  "cms":           require("../../lib/schema-cms").matches,
  "tsp":           require("../../lib/schema-tsp").matches,
  "crmf":          require("../../lib/schema-crmf").matches,
  "ocsp-request":  require("../../lib/schema-ocsp").matchesRequest,
  "ocsp-response": require("../../lib/schema-ocsp").matchesResponse,
  "pkcs12":        require("../../lib/schema-pkcs12").matches,
  "pkcs8":         require("../../lib/schema-pkcs8").matches,
  "csr":           require("../../lib/schema-csr").matches,
  "attrcert":      require("../../lib/schema-attrcert").matches,
  "attrcert-v1":   require("../../lib/schema-attrcert").matchesV1,
  "crl":           require("../../lib/schema-crl").matches,
  "x509":          require("../../lib/schema-x509").matches,
};

function crlDer() {
  var tbs = b.sequence([
    b.sequence([b.oid("1.2.840.10045.4.3.2")]),
    b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8("CA")])])]),
    b.utcTime(new Date("2026-01-01T00:00:00Z")),
  ]);
  return b.sequence([tbs, b.sequence([b.oid("1.2.840.10045.4.3.2")]), b.bitString(Buffer.from([0x00]), 0)]);
}

function run() {
  check("all() lists the registered formats in detection order", JSON.stringify(pki.schema.all()) === JSON.stringify(["cms", "tsp", "crmf", "ocsp-request", "ocsp-response", "pkcs12", "pkcs8", "csr", "attrcert", "attrcert-v1", "crl", "x509"]));

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

  // ---- dispatch first-match matrix -----------------------------------
  // Detection is a first-match loop over FORMATS, so the routing invariant is:
  // for every format's canonical fixture, the FIRST detector (in registry
  // order) returning true is the owning format. This pins both mutual
  // exclusivity where it must hold AND the deliberate refinement orderings
  // (tsp shadows ocsp-request by design). Generated over pki.schema.all(), so
  // a newly registered format fails here until it adds its fixture row —
  // exclusivity coverage is structural, not per-format authoring discipline.
  function algIdOf(o) { return b.sequence([b.oid(o)]); }
  function nameOf(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }
  function gtime(iso) { return b.generalizedTime(new Date(iso)); }
  var DIG = "2.16.840.1.101.3.4.2.1";
  var SIG = "1.2.840.10045.4.3.2";
  var DATA = "1.2.840.113549.1.7.1";
  var cmsFixture = b.sequence([b.oid("1.2.840.113549.1.7.2"),
    b.explicit(0, b.sequence([b.integer(1n), b.set([algIdOf(DIG)]), b.sequence([b.oid(DATA)]), b.set([])]))]);
  var tspFixture = b.sequence([b.sequence([b.integer(0n)])]);
  var ocspRequestFixture = b.sequence([b.sequence([b.sequence([b.sequence([
    b.sequence([algIdOf(DIG), b.octetString(Buffer.from([1])), b.octetString(Buffer.from([2])), b.integer(5n)])])])])]);
  var ocspResponseFixture = b.sequence([b.enumerated(0)]);
  var certBagValue = b.sequence([b.oid("1.2.840.113549.1.9.22.1"), b.explicit(0, b.octetString(Buffer.from([0x30, 0x00])))]);
  var p12SafeBag = b.sequence([b.oid("1.2.840.113549.1.12.10.1.3"), b.explicit(0, certBagValue)]);
  var p12AuthSafe = b.sequence([b.sequence([b.oid(DATA), b.explicit(0, b.octetString(b.sequence([p12SafeBag])))])]);
  var p12MacData = b.sequence([b.sequence([algIdOf(DIG), b.octetString(Buffer.alloc(32, 2))]), b.octetString(Buffer.alloc(8, 3)), b.integer(2048n)]);
  var pkcs12Fixture = b.sequence([b.integer(3n), b.sequence([b.oid(DATA), b.explicit(0, b.octetString(p12AuthSafe))]), p12MacData]);
  var pkcs8Fixture = b.sequence([b.integer(0n), algIdOf("1.2.840.10045.2.1"), b.octetString(Buffer.from([1, 2, 3]))]);
  var acinfoV2 = b.sequence([b.integer(1n),
    b.sequence([b.contextConstructed(1, Buffer.concat([b.explicit(4, nameOf("H"))]))]),
    b.contextConstructed(0, Buffer.concat([b.sequence([b.explicit(4, nameOf("I"))])])),
    algIdOf(SIG), b.integer(7n),
    b.sequence([gtime("2026-01-01T00:00:00Z"), gtime("2027-01-01T00:00:00Z")]),
    b.sequence([b.sequence([b.oid("2.5.4.72"), b.set([b.utf8("a")])])])]);
  var attrcertFixture = b.sequence([acinfoV2, algIdOf(SIG), b.bitString(Buffer.from([0x00]), 0)]);
  var acinfoV1 = b.sequence([
    b.contextConstructed(1, Buffer.concat([b.explicit(4, nameOf("H"))])),
    b.sequence([b.explicit(4, nameOf("I"))]),
    algIdOf(SIG), b.integer(7n),
    b.sequence([gtime("2026-01-01T00:00:00Z"), gtime("2027-01-01T00:00:00Z")]),
    b.sequence([b.sequence([b.oid("2.5.4.72"), b.set([b.utf8("a")])])])]);
  var attrcertV1Fixture = b.sequence([acinfoV1, algIdOf(SIG), b.bitString(Buffer.from([0x00]), 0)]);
  var MATRIX_FIXTURES = {
    "cms":           cmsFixture,
    "tsp":           tspFixture,
    "crmf":          crmfDer,
    "ocsp-request":  ocspRequestFixture,
    "ocsp-response": ocspResponseFixture,
    "pkcs12":        pkcs12Fixture,
    "pkcs8":         pkcs8Fixture,
    "csr":           completeCsr,
    "attrcert":      attrcertFixture,
    "attrcert-v1":   attrcertV1Fixture,
    "crl":           crlDer(),
    "x509":          pki.schema.x509.pemDecode(certPem, "CERTIFICATE"),
  };
  var order = pki.schema.all();
  order.forEach(function (name) {
    check("dispatch matrix: registry member " + name + " has a fixture and a detector",
          Boolean(MATRIX_FIXTURES[name]) && typeof DETECTORS[name] === "function");
  });
  order.forEach(function (name) {
    var root = pki.asn1.decode(MATRIX_FIXTURES[name]);
    var first = null;
    for (var i = 0; i < order.length; i++) {
      if (DETECTORS[order[i]](root)) { first = order[i]; break; }
    }
    check("dispatch matrix: the " + name + " fixture first-matches " + name, first === name);
  });
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
