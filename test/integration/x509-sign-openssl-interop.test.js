// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- X.509 certificate issuance (pki.x509.sign) cross-implementation interop.
 *
 * OpenSSL is the independent oracle for the toolkit's certificate PRODUCING side:
 *  (a) a self-signed certificate the toolkit issues parses (`openssl x509 -text`) and verifies
 *      (`openssl verify`) across a classical arm (RSA, ECDSA, EdDSA) and, on OpenSSL >= 3.5, the
 *      post-quantum ML-DSA and SLH-DSA arms;
 *  (b) a CA-signed chain the toolkit assembles (a leaf issued under a toolkit-issued CA) is validated
 *      end to end by `openssl verify -CAfile` -- OpenSSL checks the CA's signature over the leaf;
 *  (c) a certificate whose signature is flipped is REJECTED by `openssl verify`.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var os = require("node:os");
var fs = require("node:fs");
var path = require("node:path");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2036-01-01T00:00:00Z");

function caSpec(cn, spki) {
  return { subject: [{ commonName: cn }], subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true } };
}

async function run() {
  // ---- (a) per-arm self-signed cert: openssl parses + verifies ----
  var arms = ["rsa", "ec-p256", "ec-p521", "ed25519", "ed448"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65");
  if (ctx.opensslSupports("SLH-DSA")) arms.push("slh-dsa-sha2-128f");

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var pem = await pki.x509.sign(caSpec(alg + " Root", s.spki), { key: s.key }, { pem: true });
    ctx.withTmp(Buffer.from(pem, "utf8"), "cert-" + alg + ".pem", function (p) {
      var t = ctx.runOpenssl(["x509", "-in", p, "-noout", "-text"], { allowNonZero: true });
      check("openssl x509 -text parses the toolkit-issued " + alg + " certificate", t.code === 0);
      var v = ctx.runOpenssl(["verify", "-CAfile", p, p], { allowNonZero: true });
      check("openssl verify accepts the toolkit-issued self-signed " + alg + " certificate", v.code === 0 && /:\s*OK\s*$/.test(v.stdout.trim()));
    });
  }

  // ---- (b) CA-signed chain the toolkit assembles: openssl validates the CA's signature over the leaf ----
  var ca = signing.makeSigner("ec-p256");
  var caPem = await pki.x509.sign(caSpec("Interop Issuing CA", ca.spki), { key: ca.key }, { pem: true });
  var caCert = pki.schema.x509.parse(pki.schema.x509.pemDecode(caPem, "CERTIFICATE"));
  var leafKp = signing.makeSigner("ed25519");
  var leafPem = await pki.x509.sign({
    subject: [{ commonName: "leaf.interop.example" }], subjectPublicKey: leafKp.spki, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: "leaf.interop.example" }], authorityKeyIdentifier: true },
  }, { cert: caCert, key: ca.key }, { pem: true });

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-x509sign-"));
  try {
    var caFile = path.join(dir, "ca.pem"); fs.writeFileSync(caFile, caPem);
    var leafFile = path.join(dir, "leaf.pem"); fs.writeFileSync(leafFile, leafPem);
    var vc = ctx.runOpenssl(["verify", "-CAfile", caFile, leafFile], { allowNonZero: true });
    check("openssl verify validates a toolkit CA-signed chain (leaf under the toolkit CA)", vc.code === 0 && /:\s*OK\s*$/.test(vc.stdout.trim()));

    // ---- (c) a tampered leaf is rejected against the (untampered) CA ----
    // Flip a byte of the LEAF's signature and verify it against the real CA: openssl checks the CA's
    // signature over the leaf, so the tamper is caught. (A self-signed anchor is trusted a priori, so
    // it must be a leaf-under-CA to exercise a real signature check.)
    var badLeaf = Buffer.from(pki.schema.x509.pemDecode(leafPem, "CERTIFICATE"));
    badLeaf[badLeaf.length - 1] ^= 0xff;   // flip a signature byte
    var badFile = path.join(dir, "bad-leaf.pem"); fs.writeFileSync(badFile, pki.schema.x509.pemEncode(badLeaf, "CERTIFICATE"));
    var vb = ctx.runOpenssl(["verify", "-CAfile", caFile, badFile], { allowNonZero: true });
    check("openssl verify REJECTS a toolkit leaf with a flipped signature byte", vb.code !== 0);

    // ---- (d) nameConstraints the toolkit emits are ENFORCED by the independent implementation ----
    // A constraint that only parses is not a constraint. OpenSSL applies RFC 5280 sec. 4.2.1.10 in
    // `verify`, so a leaf inside the permitted subtree passes and one outside it is refused by the
    // same CA file: the difference between the two is the extension the toolkit encoded.
    var ncCa = signing.makeSigner("ec-p256");
    var ncCaPem = await pki.x509.sign({
      subject: [{ commonName: "Interop Constrained CA" }], subjectPublicKey: ncCa.spki, notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
        nameConstraints: { permitted: [{ dNSName: ".example.com" }] } },
    }, { key: ncCa.key }, { pem: true });
    var ncCaCert = pki.schema.x509.parse(pki.schema.x509.pemDecode(ncCaPem, "CERTIFICATE"));
    var ncCaFile = path.join(dir, "nc-ca.pem"); fs.writeFileSync(ncCaFile, ncCaPem);
    var ncT = ctx.runOpenssl(["x509", "-in", ncCaFile, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 -text renders the toolkit-encoded X509v3 Name Constraints",
      ncT.code === 0 && /Name Constraints/i.test(ncT.stdout) && /\.example\.com/.test(ncT.stdout));

    async function ncLeaf(dns, file) {
      var lk = signing.makeSigner("ed25519");
      var pemLeaf = await pki.x509.sign({
        subject: [{ commonName: dns }], subjectPublicKey: lk.spki, notBefore: NB, notAfter: NA,
        extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: dns }] },
      }, { cert: ncCaCert, key: ncCa.key }, { pem: true });
      var p = path.join(dir, file); fs.writeFileSync(p, pemLeaf);
      return p;
    }
    var inFile = await ncLeaf("host.example.com", "nc-in.pem");
    var outFile = await ncLeaf("host.other.example", "nc-out.pem");
    var vIn = ctx.runOpenssl(["verify", "-CAfile", ncCaFile, inFile], { allowNonZero: true });
    check("openssl verify accepts a leaf inside the toolkit-emitted permitted subtree",
      vIn.code === 0 && /:\s*OK\s*$/.test(vIn.stdout.trim()));
    var vOut = ctx.runOpenssl(["verify", "-CAfile", ncCaFile, outFile], { allowNonZero: true });
    check("openssl verify REJECTS a leaf outside it, so the constraint is enforced and not merely encoded",
      vOut.code !== 0);

    // ---- (e) the access and distribution pointers an operator issues are read back by OpenSSL ----
    // These say where to fetch the issuer and the CRL, so a renderer that cannot read them leaves a
    // relying party with no route. OpenSSL names each field it understood.
    var apKp = signing.makeSigner("ec-p256");
    var apPem = await pki.x509.sign({
      subject: [{ commonName: "pointers.interop.example" }], subjectPublicKey: apKp.spki, notBefore: NB, notAfter: NA,
      extensions: {
        keyUsage: ["digitalSignature"],
        authorityInfoAccess: [
          { accessMethod: "ocsp", accessLocation: "http://ocsp.interop.example" },
          { accessMethod: "caIssuers", accessLocation: "http://ca.interop.example/ca.cer" },
        ],
        cRLDistributionPoints: [{ fullName: ["http://crl.interop.example/a.crl"], reasons: ["keyCompromise", "aACompromise"] }],
        freshestCRL: ["http://crl.interop.example/delta.crl"],
      },
    }, { key: apKp.key }, { pem: true });
    var apFile = path.join(dir, "pointers.pem"); fs.writeFileSync(apFile, apPem);
    var apT = ctx.runOpenssl(["x509", "-in", apFile, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 -text renders the toolkit-encoded Authority Information Access",
      apT.code === 0 && /Authority Information Access/i.test(apT.stdout) &&
      /OCSP - URI:http:\/\/ocsp\.interop\.example/.test(apT.stdout) &&
      /CA Issuers - URI:http:\/\/ca\.interop\.example\/ca\.cer/.test(apT.stdout));
    check("openssl x509 -text renders the CRL Distribution Points, its URI and its reason flags",
      /X509v3 CRL Distribution Points/i.test(apT.stdout) &&
      /URI:http:\/\/crl\.interop\.example\/a\.crl/.test(apT.stdout) &&
      /Key Compromise/i.test(apT.stdout) && /AA Compromise/i.test(apT.stdout));
    check("openssl x509 -text renders the Freshest CRL under its own heading",
      /Freshest CRL/i.test(apT.stdout) && /URI:http:\/\/crl\.interop\.example\/delta\.crl/.test(apT.stdout));

    // ---- (f) the policy machinery path validation acts on ----
    // These carry skip counts and policy OIDs that decide how a chain is validated, so a renderer
    // reading a different number than the toolkit encoded is the failure that matters.
    var polKp = signing.makeSigner("ec-p256");
    var polPem = await pki.x509.sign({
      subject: [{ commonName: "Interop Policy CA" }], subjectPublicKey: polKp.spki, notBefore: NB, notAfter: NA,
      extensions: {
        basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
        certificatePolicies: ["domain-validated"],
        policyConstraints: { requireExplicitPolicy: 0, inhibitPolicyMapping: 3 },
        inhibitAnyPolicy: 2,
        policyMappings: [{ issuerDomainPolicy: "domain-validated", subjectDomainPolicy: "organization-validated" }],
        issuerAltName: [{ dNSName: "issuer.interop.example" }],
      },
    }, { key: polKp.key }, { pem: true });
    var polFile = path.join(dir, "policy.pem"); fs.writeFileSync(polFile, polPem);
    var polT = ctx.runOpenssl(["x509", "-in", polFile, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 -text renders Policy Constraints with both skip counts as encoded",
      polT.code === 0 && /Policy Constraints/i.test(polT.stdout) &&
      /Require Explicit Policy:\s*0/i.test(polT.stdout) && /Inhibit Policy Mapping:\s*3/i.test(polT.stdout));
    check("openssl x509 -text renders Inhibit Any Policy with the encoded skip count",
      /Inhibit Any Policy/i.test(polT.stdout) && /Inhibit Any Policy:\s*[\s\S]{0,40}2/i.test(polT.stdout));
    // ---- (g) the qualified-certificate statements an eIDAS issuer emits ----
    // OpenSSL names the qcStatements extension and renders the statement OIDs it carries, so a
    // statement encoded under the wrong syntax shows up as an unparsed blob rather than a statement.
    var qcKp = signing.makeSigner("ec-p256");
    var qcPem = await pki.x509.sign({
      subject: [{ commonName: "qc.interop.example" }], subjectPublicKey: qcKp.spki, notBefore: NB, notAfter: NA,
      extensions: {
        keyUsage: ["digitalSignature"],
        qcStatements: [
          { statementId: "qcCompliance" },
          { statementId: "qcType", info: { types: ["qctEsign"] } },
          { statementId: "qcRetentionPeriod", info: { years: 10 } },
          { statementId: "qcPDS", info: { locations: [{ url: "https://pds.interop.example/en.pdf", language: "en" }] } },
        ],
      },
    }, { key: qcKp.key }, { pem: true });
    var qcFile = path.join(dir, "qc.pem"); fs.writeFileSync(qcFile, qcPem);
    var qcT = ctx.runOpenssl(["x509", "-in", qcFile, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 -text renders the qcStatements extension the toolkit encoded",
      qcT.code === 0 && /qcStatements|Qualified/i.test(qcT.stdout));
    // The toolkit's own reader is the precise oracle for the statement values.
    var qcBack = pki.schema.x509.parse(pki.schema.x509.pemDecode(qcPem, "CERTIFICATE"));
    var qcExt = qcBack.extensions.filter(function (e) { return (e.name || e.oid) === "qcStatements"; })[0];
    check("every emitted statement decodes under its own syntax on the way back",
      !!qcExt && pki.lint.certificate(pki.schema.x509.pemDecode(qcPem, "CERTIFICATE"))
        .findings.filter(function (f) { return f.severity === "error"; }).length === 0);

    check("openssl x509 -text renders Policy Mappings and the Issuer Alternative Name",
      /Policy Mappings/i.test(polT.stdout) && /Issuer Alternative Name/i.test(polT.stdout) &&
      /DNS:issuer\.interop\.example/.test(polT.stdout));

    // RFC 5280 sec. 4.2.1.4 policy qualifiers and the sec. 4.2.1.1 authority key identifier in full.
    // OpenSSL prints the CPS pointer, the explicit text, and the AKI's issuer name and serial, so it
    // reads the qualifier structures rather than only naming the extension.
    var pqKp = signing.makeSigner("ec-p256");
    var pqCaKp = signing.makeSigner("ec-p256");
    var pqCaPem = await pki.x509.sign(caSpec("pq.interop.ca", pqCaKp.spki), { key: pqCaKp.key }, { pem: true });
    var pqCaDer = pki.schema.x509.pemDecode(pqCaPem, "CERTIFICATE");
    var pqPem = await pki.x509.sign({
      subject: [{ commonName: "pq.interop.example" }], subjectPublicKey: pqKp.spki, notBefore: NB, notAfter: NA,
      extensions: {
        keyUsage: ["digitalSignature"],
        certificatePolicies: [{
          oid: "1.3.6.1.4.1.99999.1",
          cps: "https://cps.interop.example/cps.pdf",
          userNotice: { noticeRef: { organization: "InteropCA", noticeNumbers: [1] }, explicitText: "Interop test policy." },
        }],
        authorityKeyIdentifier: {
          keyIdentifier: true,
          authorityCertIssuer: [{ dNSName: "ca.interop.example" }],
          authorityCertSerialNumber: "0x0102030405",
        },
      },
    }, { cert: pqCaDer, key: pqCaKp.key }, { pem: true });
    var pqFile = path.join(dir, "pq.pem"); fs.writeFileSync(pqFile, pqPem);
    var pqT = ctx.runOpenssl(["x509", "-in", pqFile, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 -text parses the certificate carrying policy qualifiers", pqT.code === 0);
    check("openssl renders the CPS pointer the toolkit encoded",
      /CPS:\s*https:\/\/cps\.interop\.example\/cps\.pdf/i.test(pqT.stdout));
    check("openssl renders the user notice explicit text and its notice reference",
      /Interop test policy\./.test(pqT.stdout) && /InteropCA/.test(pqT.stdout));
    check("openssl renders the authority key identifier issuer name and serial",
      /DirName|DNS:ca\.interop\.example/i.test(pqT.stdout) && /serial:\s*01:02:03:04:05/i.test(pqT.stdout));

    // RFC 6962. OpenSSL names the poison and, for the SCT list, decodes the TLS structure itself
    // (log id, timestamp, signature), so it is an independent oracle for the encoding rather than
    // only for the extension's presence.
    var ctKp = signing.makeSigner("ec-p256");
    var ctBase = {
      subject: [{ commonName: "ct.interop.example" }], subjectPublicKey: ctKp.spki,
      notBefore: NB, notAfter: NA, serialNumber: "0102030405",
    };
    var poisonPem = await pki.x509.sign(Object.assign({}, ctBase, {
      extensions: { keyUsage: ["digitalSignature"], precertificatePoison: true },
    }), { key: ctKp.key }, { pem: true });
    var poisonFile = path.join(dir, "precert.pem"); fs.writeFileSync(poisonFile, poisonPem);
    var poisonT = ctx.runOpenssl(["x509", "-in", poisonFile, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 -text parses the toolkit-issued precertificate", poisonT.code === 0);
    check("openssl names the CT precertificate poison and marks it critical",
      /CT Precertificate Poison/i.test(poisonT.stdout) && /Poison[\s\S]{0,40}critical|critical[\s\S]{0,40}Poison/i.test(poisonT.stdout));

    var ctLog = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
    var ctLogPriv = await pki.key.export(ctLog.privateKey);
    var seedSct = await pki.ct.signSct({ entryType: 0, leafCert: pki.schema.x509.pemDecode(poisonPem, "CERTIFICATE") }, ctLogPriv);
    var sctPem = await pki.x509.sign(Object.assign({}, ctBase, {
      extensions: { keyUsage: ["digitalSignature"], signedCertificateTimestampList: [seedSct] },
    }), { key: ctKp.key }, { pem: true });
    var sctFile = path.join(dir, "sct.pem"); fs.writeFileSync(sctFile, sctPem);
    var sctT = ctx.runOpenssl(["x509", "-in", sctFile, "-noout", "-text"], { allowNonZero: true });
    check("openssl x509 -text parses the certificate carrying an embedded SCT list", sctT.code === 0);
    check("openssl decodes the embedded SCT list down to its log id and timestamp",
      /CT Precertificate SCTs/i.test(sctT.stdout) && /Log ID/i.test(sctT.stdout) && /Timestamp/i.test(sctT.stdout));
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
