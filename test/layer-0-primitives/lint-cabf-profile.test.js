// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the CA/Browser Forum TLS BR section 7.1 subscriber certificate profile in
 * pki.lint.certificate. RED conformance vectors written BEFORE the rules, each driving the shipped
 * verb under `{ profile: "cabf-tls" }` and asserting the finding id, never a hand-decoded internal.
 *
 * Every row here is derived from the profile tables of BR v2.3.0 section 7.1.2.7, read from the
 * document rather than recalled: the extension presence and criticality table (7.1.2.7.6), the
 * authorityInformationAccess accessMethod table (7.1.2.7.7), basicConstraints (7.1.2.7.8),
 * certificatePolicies and its permitted qualifiers (7.1.2.7.9), the extKeyUsage table
 * (7.1.2.7.10), the two Key Usage tables that differ by key type (7.1.2.7.11), and the
 * subjectAltName GeneralName table (7.1.2.7.12).
 *
 * Each vector states the clause it drives, and each carries a CONTROL where the conforming shape
 * is what distinguishes the rule from an adjacent one.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2026-03-01T00:00:00Z");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }

async function run() {
  var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var ecPriv = await pki.key.export(ec.privateKey), ecPub = await pki.key.export(ec.publicKey);
  var rsa = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  var rsaPriv = await pki.key.export(rsa.privateKey), rsaPub = await pki.key.export(rsa.publicKey);

  // A conforming subscriber certificate, built from the 7.1.2.7.6 table: every MUST extension
  // present at the criticality the table states, and nothing it forbids.
  function conformingExts(over) {
    var e = {
      basicConstraints: { cA: false },
      keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["serverAuth"],
      subjectAltName: [{ dNSName: "example.com" }],
      certificatePolicies: [{ oid: "2.23.140.1.2.1" }],
      authorityInfoAccess: [{ accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } }],
      subjectKeyIdentifier: false,
      authorityKeyIdentifier: false,
    };
    Object.keys(over || {}).forEach(function (k) {
      if (over[k] === undefined) delete e[k]; else e[k] = over[k];
    });
    return e;
  }
  function signEc(over, subject) {
    return pki.x509.sign({ subject: subject === undefined ? [{ commonName: "example.com" }] : subject,
      subjectPublicKey: ecPub, notBefore: NB, notAfter: NA, extensions: conformingExts(over) },
      { key: ecPriv });
  }
  function lint(der) { return pki.lint.certificate(der, { profile: "cabf-tls" }); }
  async function lintEc(over, subject) { return lint(await signEc(over, subject)); }

  /** Splice one extension into a signed certificate's TBS, replacing any of the same OID. The
   *  signer validates a pre-encoded extension exactly as it validates the named spec form, and
   *  refuses several of the shapes this profile forbids, which is the signer doing its job. A CA
   *  that emits one is what these rows exist to catch, so the bytes are assembled here. The
   *  signature no longer matches, which the linter does not check and does not claim to: hostile
   *  or non-conforming bytes are its input, not its output. */
  function spliceExt(baseDer, extraDer) {
    var cert = pki.asn1.decode(baseDer);
    var tbs = cert.children[0];
    var addedOid = pki.asn1.read.oid(pki.asn1.decode(extraDer).children[0]);
    var kids = [];
    tbs.children.forEach(function (child) {
      if (!(child.tagClass === "context" && child.tagNumber === 3)) { kids.push(b.raw(child.bytes)); return; }
      var list = child.children[0];
      var keep = list.children.filter(function (e) {
        return pki.asn1.read.oid(e.children[0]) !== addedOid;
      }).map(function (e) { return b.raw(e.bytes); });
      kids.push(b.contextConstructed(3, b.sequence(keep.concat([b.raw(extraDer)]))));
    });
    return b.sequence([b.sequence(kids), b.raw(cert.children[1].bytes), b.raw(cert.children[2].bytes)]);
  }
  async function signWithRawExt(extraDer, dropName) {
    var exts = conformingExts(dropName ? (function () { var o = {}; o[dropName] = undefined; return o; })() : {});
    return spliceExt(await pki.x509.sign({ subject: [{ commonName: "example.com" }],
      subjectPublicKey: ecPub, notBefore: NB, notAfter: NA, extensions: exts }, { key: ecPriv }), extraDer);
  }

  // ---- the control the whole file rests on -------------------------------------------------
  var baseline = await lintEc({});
  var baselineErrors = baseline.findings.filter(function (f) {
    return f.severity === "error" || f.severity === "fatal";
  });
  check("B1. CONTROL: a conforming subscriber certificate reports nothing at error or worse (" +
    baselineErrors.map(function (f) { return f.id; }).join(",") + ")",
    baselineErrors.length === 0);

  // ---- 7.1.2.7.6, the extension presence and criticality table ------------------------------
  check("P1. authorityInformationAccess MUST be present",
    has(await lintEc({ authorityInfoAccess: undefined }), "lint/cabf-tls/aia-missing"));
  check("P2. certificatePolicies MUST be present",
    has(await lintEc({ certificatePolicies: undefined }), "lint/cabf-tls/policies-missing"));
  // The signer refuses nameConstraints on a non-CA certificate (RFC 5280 sec. 4.2.1.10), which is
  // exactly the shape this row is for, so it is written pre-encoded.
  // NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL, ... }, where
  // GeneralSubtrees is a SEQUENCE OF GeneralSubtree and the [0] is IMPLICIT, so the context tag
  // replaces that SEQUENCE OF tag and its content is the members themselves.
  var ncDer = b.sequence([b.oid(pki.oid.byName("nameConstraints")), b.boolean(true),
    b.octetString(b.sequence([b.contextConstructed(0,
      b.sequence([b.contextPrimitive(2, Buffer.from("example.com", "latin1"))]))]))]);
  check("P3. nameConstraints MUST NOT be present",
    has(lint(await signWithRawExt(ncDer)), "lint/cabf-tls/name-constraints-present"));
  check("P4. subjectKeyIdentifier is NOT RECOMMENDED, and is a notice rather than an error",
    (function (rep) {
      return rep.findings.some(function (f) {
        return f.id === "lint/cabf-tls/ski-present" && f.severity === "notice";
      });
    })(await lintEc({ subjectKeyIdentifier: true })));

  // ---- 7.1.2.7.7, the accessMethod table ----------------------------------------------------
  check("P5. an accessMethod outside id-ad-ocsp and id-ad-caIssuers is not permitted",
    has(await lintEc({ authorityInfoAccess: [
      { accessMethod: "ocspNoCheck", accessLocation: { uniformResourceIdentifier: "http://r.example" } }] }),
      "lint/cabf-tls/aia-forbidden-access-method"));
  check("P6. CONTROL: id-ad-caIssuers is permitted and is not reported",
    !has(await lintEc({ authorityInfoAccess: [
      { accessMethod: "caIssuers", accessLocation: { uniformResourceIdentifier: "http://i.example" } }] }),
      "lint/cabf-tls/aia-forbidden-access-method"));
  // The table marks authorityInformationAccess Critical: N. The signer emits it non-critical, so
  // the critical form is spliced.
  var criticalAia = b.sequence([b.oid(pki.oid.byName("authorityInfoAccess")), b.boolean(true),
    b.octetString(b.sequence([b.sequence([b.oid(pki.oid.byName("ocsp")),
      b.contextPrimitive(6, Buffer.from("http://ocsp.example", "latin1"))])]))]);
  check("P6b. authorityInformationAccess must not be marked critical",
    has(lint(await signWithRawExt(criticalAia, "authorityInfoAccess")), "lint/cabf-tls/aia-critical"));
  check("P6c. CONTROL: the non-critical form is not reported",
    !has(baseline, "lint/cabf-tls/aia-critical"));

  check("P7. an accessLocation that is not a uniformResourceIdentifier is not permitted",
    has(await lintEc({ authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { dNSName: "ocsp.example" } }] }),
      "lint/cabf-tls/aia-location-not-uri"));

  // ---- 7.1.2.7.8, basicConstraints ----------------------------------------------------------
  // cA TRUE cannot be minted through the signer for an EE profile, so the extension is written
  // pre-encoded: a CA that issues one is exactly what this row exists to catch.
  // A certificate asserting serverAuth AND cA TRUE is what this row exists to catch, and the
  // signer refuses that combination, so the extension is written pre-encoded.
  function signWithRawBc(bcInnerDer) {
    return signWithRawExt(b.sequence([b.oid(pki.oid.byName("basicConstraints")), b.boolean(true),
      b.octetString(bcInnerDer)]), "basicConstraints");
  }
  check("P8. a subscriber certificate's basicConstraints cA MUST be FALSE",
    has(lint(await signWithRawBc(b.sequence([b.boolean(true)]))),
      "lint/cabf-tls/basic-constraints-ca-true"));
  check("P8b. ...and its pathLenConstraint MUST NOT be present",
    has(lint(await signWithRawBc(b.sequence([b.boolean(true), b.integer(0n)]))),
      "lint/cabf-tls/basic-constraints-path-len"));
  check("P8c. CONTROL: cA FALSE with no pathLenConstraint is reported for neither",
    !has(baseline, "lint/cabf-tls/basic-constraints-ca-true") &&
    !has(baseline, "lint/cabf-tls/basic-constraints-path-len"));

  // ---- 7.1.2.7.9, certificatePolicies -------------------------------------------------------
  check("P9. anyPolicy MUST NOT be asserted",
    has(await lintEc({ certificatePolicies: [{ oid: pki.oid.byName("anyPolicy") }] }),
      "lint/cabf-tls/policies-any-policy"));
  check("P10. exactly one reserved policy identifier: none is a fault",
    has(await lintEc({ certificatePolicies: [{ oid: "1.3.6.1.4.1.99999.1" }] }),
      "lint/cabf-tls/policies-reserved-identifier-count"));
  check("P11. ...and two is the same fault",
    has(await lintEc({ certificatePolicies: [{ oid: "2.23.140.1.2.1" }, { oid: "2.23.140.1.2.2" }] }),
      "lint/cabf-tls/policies-reserved-identifier-count"));
  // Section 7.1.2.7.1 names FOUR subscriber types, and section 7.1.6.1 gives each its reserved
  // identifier. A list short of one reports every certificate of that type as asserting none, so
  // each is driven rather than the three that share the baseline-requirements arc.
  var reservedMisses = [];
  for (var ri = 0; ri < 4; ri++) {
    var name = ["domain-validated", "organization-validated", "individual-validated", "ev-guidelines"][ri];
    var rep2 = await lintEc({ certificatePolicies: [{ oid: pki.oid.byName(name) }] });
    if (has(rep2, "lint/cabf-tls/policies-reserved-identifier-count")) reservedMisses.push(name);
  }
  check("P11b. each of the four reserved policy identifiers satisfies the exactly-one rule" +
    (reservedMisses.length ? " (reported for: " + reservedMisses.join(",") + ")" : ""),
    reservedMisses.length === 0);

  check("P12. CONTROL: exactly one reserved identifier beside another policy is not reported",
    !has(await lintEc({ certificatePolicies: [{ oid: "2.23.140.1.2.1" }, { oid: "1.3.6.1.4.1.99999.1" }] }),
      "lint/cabf-tls/policies-reserved-identifier-count"));
  check("P13. a policy qualifier other than id-qt-cps is not permitted",
    has(await lintEc({ certificatePolicies: [{ oid: "2.23.140.1.2.1",
      userNotice: { explicitText: "hello" } }] }), "lint/cabf-tls/policy-qualifier-forbidden"));
  check("P14. CONTROL: an id-qt-cps qualifier is permitted",
    !has(await lintEc({ certificatePolicies: [{ oid: "2.23.140.1.2.1", cps: "http://cps.example" }] }),
      "lint/cabf-tls/policy-qualifier-forbidden"));

  // ---- 7.1.2.7.10, the extKeyUsage table ----------------------------------------------------
  var forbidden = ["codeSigning", "emailProtection", "timeStamping", "ocspSigning"];
  var ekuMisses = [];
  for (var i = 0; i < forbidden.length; i++) {
    var rep = await lintEc({ extendedKeyUsage: ["serverAuth", forbidden[i]] });
    if (!has(rep, "lint/cabf-tls/eku-forbidden-purpose")) ekuMisses.push(forbidden[i]);
  }
  check("P15. every key purpose the table forbids is reported" +
    (ekuMisses.length ? " (missed: " + ekuMisses.join(",") + ")" : ""), ekuMisses.length === 0);
  check("P16. CONTROL: id-kp-clientAuth is permitted beside serverAuth",
    !has(await lintEc({ extendedKeyUsage: ["serverAuth", "clientAuth"] }),
      "lint/cabf-tls/eku-forbidden-purpose"));

  // ---- 7.1.2.7.11, the two Key Usage tables -------------------------------------------------
  // The tables differ by key type, which is the point: keyEncipherment is permitted for RSA and
  // forbidden for ECC, so a rule reading one table answers wrongly for the other key.
  function signRsa(over) {
    return pki.x509.sign({ subject: [{ commonName: "example.com" }], subjectPublicKey: rsaPub,
      notBefore: NB, notAfter: NA, extensions: conformingExts(over) }, { key: rsaPriv });
  }
  check("P17. keyEncipherment is forbidden for an ECC subscriber key",
    has(await lintEc({ keyUsage: ["digitalSignature", "keyEncipherment"] }),
      "lint/cabf-tls/key-usage-forbidden-bit"));
  check("P18. ...and permitted for an RSA one, which is why the key decides the table",
    !has(lint(await signRsa({ keyUsage: ["digitalSignature", "keyEncipherment"] })),
      "lint/cabf-tls/key-usage-forbidden-bit"));
  check("P19. cRLSign is forbidden for either key type",
    has(await lintEc({ keyUsage: ["digitalSignature", "cRLSign"] }),
      "lint/cabf-tls/key-usage-forbidden-bit") &&
    has(lint(await signRsa({ keyUsage: ["digitalSignature", "cRLSign"] })),
      "lint/cabf-tls/key-usage-forbidden-bit"));
  check("P20. an ECC subscriber certificate must assert digitalSignature",
    has(await lintEc({ keyUsage: ["keyAgreement"] }),
      "lint/cabf-tls/key-usage-ecc-without-digital-signature"));
  // "At least one Key Usage MUST be set for RSA Public Keys", measured over the bits that table
  // permits: a certificate whose only bit is one the table forbids has set none of them.
  check("P19b. an RSA certificate setting no permitted keyUsage bit is reported",
    has(lint(await signRsa({ keyUsage: ["keyAgreement"] })), "lint/cabf-tls/key-usage-rsa-no-bit-set"));
  check("P19c. CONTROL: digitalSignature alone satisfies it",
    !has(lint(await signRsa({ keyUsage: ["digitalSignature"] })), "lint/cabf-tls/key-usage-rsa-no-bit-set"));

  // Section 7.1.2.7.11 gives a table for an RSA key and a table for an ECC key, and none for
  // anything else. A key outside the two has no table to be held to, so neither table is applied
  // to it: treating everything that is not ECC as RSA would report a post-quantum certificate
  // against requirements written for a different algorithm.
  var mldsa = await pki.key.generate("ML-DSA-44").then(function (k) { return k; }, function () { return null; });
  if (mldsa) {
    var mlPub = await pki.key.export(mldsa.publicKey), mlPriv = await pki.key.export(mldsa.privateKey);
    var mlCert = await pki.x509.sign({ subject: [{ commonName: "example.com" }],
      subjectPublicKey: mlPub, notBefore: NB, notAfter: NA,
      extensions: conformingExts({ keyUsage: ["digitalSignature", "nonRepudiation"] }) },
      { key: mlPriv });
    check("P21b. a key type the profile gives no table for is not held to either table (" +
      ids(lint(mlCert)).join(",") + ")",
      !has(lint(mlCert), "lint/cabf-tls/key-usage-forbidden-bit") &&
      !has(lint(mlCert), "lint/cabf-tls/key-usage-rsa-no-bit-set"));
  } else {
    helpers.skip("ML-DSA is not available in this runtime, so the no-table key case is not driven");
  }

  check("P21. CONTROL: an RSA certificate asserting only keyEncipherment is not held to that",
    !has(lint(await signRsa({ keyUsage: ["keyEncipherment"] })),
      "lint/cabf-tls/key-usage-ecc-without-digital-signature"));

  // ---- 7.1.2.7.12, the subjectAltName GeneralName table -------------------------------------
  check("P22. a subjectAltName type outside dNSName and iPAddress is not permitted",
    has(await lintEc({ subjectAltName: [{ dNSName: "example.com" },
      { uniformResourceIdentifier: "https://example.com" }] }), "lint/cabf-tls/san-forbidden-name-type"));
  check("P23. CONTROL: an iPAddress entry is permitted",
    !has(await lintEc({ subjectAltName: [{ dNSName: "example.com" }, { iPAddress: "192.0.2.1" }] }),
      "lint/cabf-tls/san-forbidden-name-type"));
  check("P24. a dNSName carrying the root zone's zero-length label is reported",
    has(await lintEc({ subjectAltName: [{ dNSName: "example.com." }] }),
      "lint/cabf-tls/dnsname-trailing-dot"));

  // The criticality rule is a pair of MUSTs: critical where the subject is empty, non-critical
  // otherwise. One row measures both, so each direction needs its own vector.
  // An empty subject makes a self-signed certificate's issuer empty too, which the signer
  // refuses, so this one is issued from a CA.
  var issuingCa = await pki.x509.sign({ subject: [{ commonName: "Issuing CA" }],
    subjectPublicKey: ecPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: ecPriv });
  var emptySubject = await pki.x509.sign({ subject: [], subjectPublicKey: ecPub,
    notBefore: NB, notAfter: NA,
    extensions: conformingExts({ authorityKeyIdentifier: undefined }) },
    { cert: issuingCa, key: ecPriv });
  // The signer marks the SAN critical when the subject is empty, which is the profile being
  // followed, so the non-critical form is spliced in.
  var nonCriticalSan = b.sequence([b.oid(pki.oid.byName("subjectAltName")),
    b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("example.com", "latin1"))]))]);
  check("P25. a non-critical subjectAltName beside an empty subject is reported",
    has(lint(spliceExt(emptySubject, nonCriticalSan)), "lint/cabf-tls/san-criticality-mismatch"));
  check("P25c. ...and a critical one beside an empty subject is not",
    !has(lint(emptySubject), "lint/cabf-tls/san-criticality-mismatch"));
  check("P25b. CONTROL: a non-critical one beside a named subject is not",
    !has(baseline, "lint/cabf-tls/san-criticality-mismatch"));

  // ---- 7.1.2.7, the serial bound ------------------------------------------------------------
  // The clause says "less than 2^159", and no separate row measures it: a positive DER INTEGER of
  // 20 octets reaches exactly 2^159 - 1, because the leading bit must be clear for the value to be
  // positive. So a serial at or above the BR's bound necessarily exceeds RFC 5280 sec. 4.1.2.2's
  // 20 octets, and lint/rfc5280/serial-too-long is the row that answers for both. A CABF row would
  // be a second finding for one fault, never the only one.
  var atBound = await pki.x509.sign({ subject: [{ commonName: "example.com" }],
    subjectPublicKey: ecPub, notBefore: NB, notAfter: NA, serialNumber: (1n << 159n) - 1n,
    extensions: conformingExts({}) }, { key: ecPriv });
  check("P26. the largest serial the BR admits is the largest RFC 5280 admits, and lints clean",
    !has(lint(atBound), "lint/rfc5280/serial-too-long"));
  check("P27. ...and one above it cannot be encoded in the 20 octets RFC 5280 allows",
    (function () {
      var enc = pki.asn1.build.integer(1n << 159n);
      return enc.length - 2 === 21;
    })());

  // ---- the rows run only for a TLS server certificate ---------------------------------------
  // Naming the profile is an assertion that the input IS a subscriber certificate, so the rows
  // then apply whatever it says it is. Left unnamed, they reach a certificate only where it
  // asserts id-kp-serverAuth and is not a CA, which is what keeps a CA certificate from being
  // reported against requirements written for subscribers.
  var caSubscriberShape = await pki.x509.sign({ subject: [{ commonName: "Issuing CA" }],
    subjectPublicKey: ecPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
      extendedKeyUsage: ["serverAuth"] } }, { key: ecPriv });
  var caAuto = pki.lint.certificate(caSubscriberShape);
  check("P27b. a CA certificate is not held to the subscriber rows under automatic detection (" +
    ids(caAuto).filter(function (i) { return i.indexOf("lint/cabf-tls/") === 0; }).join(",") + ")",
    !has(caAuto, "lint/cabf-tls/basic-constraints-ca-true") &&
    !has(caAuto, "lint/cabf-tls/key-usage-forbidden-bit") &&
    !has(caAuto, "lint/cabf-tls/policies-missing"));
  check("P27c. ...and naming the profile applies them, which is what naming it asserts",
    has(lint(caSubscriberShape), "lint/cabf-tls/basic-constraints-ca-true"));

  check("P28. the profile's rows do not run against a certificate that is not one",
    !has(pki.lint.certificate(await pki.x509.sign({ subject: [{ commonName: "mail.example" }],
      subjectPublicKey: ecPub, notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { cA: false }, extendedKeyUsage: ["emailProtection"] } },
      { key: ecPriv })), "lint/cabf-tls/aia-missing"));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
