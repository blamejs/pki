// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- C509 certificate encoding (pki.schema.c509.encode) cross-implementation interop.
 *
 * No mainstream tool parses a C509 CBOR certificate, so the oracle is the type-3 round trip through an
 * independent DER implementation: a DER X.509 certificate the toolkit encodes to a compact type-3 C509,
 * re-parsed, MUST reconstruct to bytes OpenSSL accepts as the same certificate -- and, because the
 * reconstruction is byte-exact, equal to the original DER (so the original signature verifies). Across the
 * ECDSA curves the type-3 covered set supports.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");

async function run() {
  var arms = ["ec-p256", "ec-p384", "ec-p521"];
  var armCurve = { "ec-p256": "P-256", "ec-p384": "P-384", "ec-p521": "P-521" };
  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var der = await pki.x509.sign({
      subject: [{ commonName: alg + " leaf" }, { organizationName: "Interop" }, { countryName: "US" }],
      subjectPublicKey: s.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
      extensions: { keyUsage: ["digitalSignature"], basicConstraints: { cA: false } },
    }, { key: s.key });

    // these signers pair every curve with SHA-256, so the issuer curve is supplied explicitly.
    var c509 = pki.schema.c509.encode(der, { issuerCurve: armCurve[alg] });
    var recon = pki.schema.c509.parse(c509).reconstructedDer;
    check(alg + " type-3 C509 is smaller than the source DER", c509.length < der.length);
    check(alg + " type-3 reconstructs the source DER byte-for-byte", recon.equals(der));

    ctx.withTmp(Buffer.from(recon), "c509-recon-" + alg + ".der", function (p) {
      var t = ctx.runOpenssl(["x509", "-inform", "DER", "-in", p, "-noout", "-text"], { allowNonZero: true });
      check("openssl x509 accepts the reconstructed " + alg + " certificate", t.code === 0);
    });
  }

  // A certificate bearing the compact general-name value form: a subjectAltName with a dNSName, rfc822Name,
  // URI, and iPAddress rides the draft-20 sec. 3.3 GeneralNames array, and the reconstructed DER MUST be the
  // certificate OpenSSL parses -- including the Subject Alternative Name it now carries the compact way.
  var b = pki.asn1.build, O = pki.oid.byName;
  var sanExt = b.sequence([b.oid(O("subjectAltName")), b.octetString(b.sequence([
    b.contextPrimitive(2, Buffer.from("interop.example", "latin1")),
    b.contextPrimitive(1, Buffer.from("ca@interop.example", "latin1")),
    b.contextPrimitive(6, Buffer.from("https://interop.example/crl", "latin1")),
    b.contextPrimitive(7, Buffer.from([192, 0, 2, 10])),
  ]))]);
  var ss = signing.makeSigner("ec-p256");
  var sanDer = Buffer.from(await pki.x509.sign({
    subject: [{ commonName: "san leaf" }], subjectPublicKey: ss.spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"),
    extensions: [sanExt],
  }, { key: ss.key }));
  var sanC509 = pki.schema.c509.encode(sanDer, { issuerCurve: "P-256" });
  var sanRecon = pki.schema.c509.parse(sanC509).reconstructedDer;
  check("subjectAltName cert type-3 reconstructs the source DER byte-for-byte", sanRecon.equals(sanDer));
  // the subjectAltName rode the compact GeneralNames array (extension integer 3 with a CBOR array value),
  // not the unwrapped-OID byte-string fallback.
  var sanExtsNode = pki.cbor.decode(sanC509).children[9].children || [];
  var sanCompact = false;
  for (var k = 0; k + 1 < sanExtsNode.length; k += 2) {
    if (sanExtsNode[k].majorType <= 1 && Math.abs(Number(pki.cbor.read.int(sanExtsNode[k]))) === 3 && sanExtsNode[k + 1].majorType === 4) sanCompact = true;
  }
  check("subjectAltName encodes as the compact GeneralNames array (not the ~oid fallback)", sanCompact);
  ctx.withTmp(sanRecon, "c509-recon-san.der", function (p) {
    var t = ctx.runOpenssl(["x509", "-inform", "DER", "-in", p, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 accepts the reconstructed subjectAltName certificate", t.code === 0);
    check("openssl reads the reconstructed Subject Alternative Name", /interop\.example/.test(t.stdout || ""));
  });

  // A certificate bearing the compact certificatePolicies value form: a registered policy with a CPS URI and a
  // UserNotice explicitText rides the draft-20 sec. 3.3 CBOR array, and OpenSSL reads the reconstructed policies.
  var cpExtDer = b.sequence([b.oid(O("certificatePolicies")), b.octetString(b.sequence([
    b.sequence([b.oid(O("domain-validated")), b.sequence([
      b.sequence([b.oid(O("cps")), b.ia5("http://cps.interop.example")]),
      b.sequence([b.oid(O("unotice")), b.sequence([b.utf8("Interop notice")])]),
    ])]),
  ]))]);
  var cs = signing.makeSigner("ec-p256");
  var cpDer = Buffer.from(await pki.x509.sign({
    subject: [{ commonName: "cp leaf" }], subjectPublicKey: cs.spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: [cpExtDer],
  }, { key: cs.key }));
  var cpC509 = pki.schema.c509.encode(cpDer, { issuerCurve: "P-256" });
  var cpRecon = pki.schema.c509.parse(cpC509).reconstructedDer;
  check("certificatePolicies cert type-3 reconstructs the source DER byte-for-byte", cpRecon.equals(cpDer));
  var cpExtsNode = pki.cbor.decode(cpC509).children[9].children || [], cpCompact = false;
  for (var kk = 0; kk + 1 < cpExtsNode.length; kk += 2) {
    if (cpExtsNode[kk].majorType <= 1 && Math.abs(Number(pki.cbor.read.int(cpExtsNode[kk]))) === 6 && cpExtsNode[kk + 1].majorType === 4) cpCompact = true;
  }
  check("certificatePolicies encodes as the compact CBOR array (not the ~oid fallback)", cpCompact);
  ctx.withTmp(cpRecon, "c509-recon-cp.der", function (p) {
    var t = ctx.runOpenssl(["x509", "-inform", "DER", "-in", p, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 accepts the reconstructed certificatePolicies certificate", t.code === 0);
    check("openssl reads the reconstructed CPS URI", /cps\.interop\.example/.test(t.stdout || ""));
  });

  // A certificate bearing the compact policyMappings + policyConstraints value forms: a registered policy mapping
  // rides the draft-20 sec. 3.3 flat-pair array and a policy constraints skip-count pair rides the fixed 2-element
  // array, and OpenSSL parses the reconstructed certificate carrying both extensions.
  var pmExtDer = b.sequence([b.oid(O("policyMappings")), b.octetString(b.sequence([
    b.sequence([b.oid(O("domain-validated")), b.oid(O("organization-validated"))]),
  ]))]);
  var pcExtDer = b.sequence([b.oid(O("policyConstraints")), b.boolean(true), b.octetString(b.sequence([
    b.implicit(0, b.integer(0n)), b.implicit(1, b.integer(1n)),
  ]))]);
  var ps = signing.makeSigner("ec-p256");
  var polDer = Buffer.from(await pki.x509.sign({
    subject: [{ commonName: "pol leaf" }], subjectPublicKey: ps.spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: [pmExtDer, pcExtDer],
  }, { key: ps.key }));
  var polC509 = pki.schema.c509.encode(polDer, { issuerCurve: "P-256" });
  var polRecon = pki.schema.c509.parse(polC509).reconstructedDer;
  check("policyMappings/policyConstraints cert type-3 reconstructs the source DER byte-for-byte", polRecon.equals(polDer));
  // both rode their compact CBOR value form (extension ints 27 and 28 with array values), not the ~oid fallback.
  var polExtsNode = pki.cbor.decode(polC509).children[9].children || [], pmCompact = false, pcCompact = false;
  for (var pk = 0; pk + 1 < polExtsNode.length; pk += 2) {
    if (polExtsNode[pk].majorType <= 1 && polExtsNode[pk + 1].majorType === 4) {
      var pid = Math.abs(Number(pki.cbor.read.int(polExtsNode[pk])));
      if (pid === 27) pmCompact = true;
      if (pid === 28) pcCompact = true;
    }
  }
  check("policyMappings + policyConstraints encode as compact CBOR arrays (not the ~oid fallback)", pmCompact && pcCompact);
  ctx.withTmp(polRecon, "c509-recon-pol.der", function (p) {
    var t = ctx.runOpenssl(["x509", "-inform", "DER", "-in", p, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 accepts the reconstructed policyMappings/policyConstraints certificate", t.code === 0);
    check("openssl reads the reconstructed Policy Mappings + Policy Constraints", /Policy Mappings/.test(t.stdout || "") && /Policy Constraints/.test(t.stdout || ""));
  });

  // A certificate bearing the compact subjectDirectoryAttributes value form: registered (title, a multi-value
  // organizationalUnitName SET) and a ~oid-form (emailAddress) attribute ride the draft-20 sec. 3.3 flat array,
  // and OpenSSL parses the reconstructed certificate carrying the extension.
  var sdaExtDer = b.sequence([b.oid(O("subjectDirectoryAttributes")), b.octetString(b.sequence([
    b.sequence([b.oid(O("title")), b.set([b.utf8("Director")])]),
    b.sequence([b.oid(O("organizationalUnitName")), b.set([b.utf8("Eng"), b.utf8("Ops")])]),
    b.sequence([b.oid(O("emailAddress")), b.set([b.ia5("ca@interop.example")])]),
  ]))]);
  var das = signing.makeSigner("ec-p256");
  var sdaDer = Buffer.from(await pki.x509.sign({
    subject: [{ commonName: "sda leaf" }], subjectPublicKey: das.spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2027-01-01T00:00:00Z"), extensions: [sdaExtDer],
  }, { key: das.key }));
  var sdaC509 = pki.schema.c509.encode(sdaDer, { issuerCurve: "P-256" });
  var sdaRecon = pki.schema.c509.parse(sdaC509).reconstructedDer;
  check("subjectDirectoryAttributes cert type-3 reconstructs the source DER byte-for-byte", sdaRecon.equals(sdaDer));
  var sdaExtsNode = pki.cbor.decode(sdaC509).children[9].children || [], sdaCompact = false;
  for (var si = 0; si + 1 < sdaExtsNode.length; si += 2) {
    if (sdaExtsNode[si].majorType <= 1 && Math.abs(Number(pki.cbor.read.int(sdaExtsNode[si]))) === 24 && sdaExtsNode[si + 1].majorType === 4) sdaCompact = true;
  }
  check("subjectDirectoryAttributes encodes as the compact CBOR array (not the ~oid fallback)", sdaCompact);
  ctx.withTmp(sdaRecon, "c509-recon-sda.der", function (p) {
    var t = ctx.runOpenssl(["x509", "-inform", "DER", "-in", p, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 accepts the reconstructed subjectDirectoryAttributes certificate", t.code === 0);
    check("openssl reads the reconstructed subjectDirectoryAttributes extension", /Subject Directory Attributes|X509v3 Subject Directory|2\.5\.29\.9/.test(t.stdout || ""));
  });
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
