// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the CA/Browser Forum Code Signing BR subscriber certificate profile in
 * pki.lint.certificate. RED conformance vectors written BEFORE the rules, each driving the shipped
 * verb and asserting the finding id, never a hand-decoded internal.
 *
 * Every row is derived from Code Signing BR v3.11.0, read from the document. The profile varies by
 * the KIND of certificate, and a subscriber certificate names its own kind through one of the three
 * reserved policy identifiers of sec. 7.1.6.1, so the rules read that declaration.
 *
 * The severities differ from the same-named cabf-smime rows, and that is the point: this document
 * says MUST where the S/MIME one says SHOULD. Each row is graded against the clause it cites, and
 * C8 pins one such difference on the same input.
 *
 *   C1-C4    detection: the reserved identifier says which kind this is
 *   C5-C8    certificatePolicies (7.1.2.3 a) and the 7.1.6.4 exactly-one rule
 *   C9-C11   cRLDistributionPoints (b)
 *   C12-C15  authorityInformationAccess (c)
 *   C16      basicConstraints (d)
 *   C17-C21  keyUsage (e), whose sentence splits into a MUST list and a SHOULD list
 *   C22-C26  extKeyUsage (f), whose required purpose differs by kind
 *   C27-C28  authorityKeyIdentifier (g)
 *   C29-C31  the validity ceilings (6.3.2), stated in months and in days
 *   C32-C33  the key floors (6.1.5.2)
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

// On or after 1 March 2026, so the 460-day ceiling is the one that applies.
var NB = new Date("2026-04-01T00:00:00Z");
var NA = new Date("2026-06-01T00:00:00Z");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function sevOf(rep, id) {
  var f = rep.findings.filter(function (x) { return x.id === id; })[0];
  return f && f.severity;
}
function lint(der, opts) { return pki.lint.certificate(der, opts || { profile: "cabf-cs" }); }

async function run() {
  var ed = await pki.key.generate("Ed25519");
  var edPriv = await pki.key.export(ed.privateKey), edPub = await pki.key.export(ed.publicKey);
  var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var ecPub = await pki.key.export(ec.publicKey);
  var ec521 = await pki.key.generate({ name: "ECDSA", namedCurve: "P-521" });
  var ec521Pub = await pki.key.export(ec521.publicKey);
  var rsaWeak = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  var rsaWeakPub = await pki.key.export(rsaWeak.publicKey);
  var rsaOk = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 3072, hash: "SHA-256" });
  var rsaOkPub = await pki.key.export(rsaOk.publicKey);

  var CS = pki.oid.byName("code-signing");
  var EV = pki.oid.byName("code-signing-ev");
  var TS = pki.oid.byName("code-signing-timestamping");

  // A conforming non-EV subject, from the 7.1.4.2.2 and 7.1.4.2.3 lists, and the EV one that adds
  // what 7.1.4.2.4 requires on top.
  var NONEV_SUBJECT = [{ commonName: "Example Corp" }, { organizationName: "Example Corp" },
    { localityName: "Dover" }, { countryName: "US" }];
  var EV_SUBJECT = NONEV_SUBJECT.concat([{ businessCategory: "Private Organization" },
    { jurisdictionCountryName: "US" }, { serialNumber: "R12345" }]);

  // A conforming non-EV code signing certificate, from the 7.1.2.3 list.
  function exts(over) {
    var e = {
      certificatePolicies: [{ oid: CS }],
      cRLDistributionPoints: [{ fullName: [{ uniformResourceIdentifier: "http://crl.example/a.crl" }] }],
      authorityInfoAccess: [
        { accessMethod: "caIssuers", accessLocation: { uniformResourceIdentifier: "http://i.example/ca.cer" } },
        { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } }],
      keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["codeSigning"],
    };
    Object.keys(over || {}).forEach(function (k) {
      if (over[k] === undefined) delete e[k]; else e[k] = over[k];
    });
    return e;
  }
  // Issued from a CA, because the profile requires an authorityKeyIdentifier and the signer emits
  // one only for a certificate it did not self-sign.
  var issuingCa = await pki.x509.sign({ subject: [{ commonName: "Issuing CA" }],
    subjectPublicKey: edPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: edPriv });
  function sign(over, pub, window, subject) {
    var w = window || {};
    return pki.x509.sign({ subject: subject || NONEV_SUBJECT, subjectPublicKey: pub || ecPub,
      notBefore: w.notBefore || NB, notAfter: w.notAfter || NA, extensions: exts(over) },
      { cert: issuingCa, key: edPriv });
  }
  /** Self-signed, so the subject key is the signing key: the signer refuses a self-signature whose
   *  subject key is not the one that made it. */
  function signSelf(over, pub) {
    return pki.x509.sign({ subject: NONEV_SUBJECT, subjectPublicKey: pub || edPub,
      notBefore: NB, notAfter: NA, extensions: exts(over) }, { key: edPriv });
  }
  async function lintOver(over, pub, window, subject) { return lint(await sign(over, pub, window, subject)); }

  /** Splice one extension into a signed certificate's TBS, replacing any of the same OID. The
   *  signer refuses several shapes this profile forbids, which is the signer doing its job; a CA
   *  that emits one is what these rows exist to catch. The signature no longer matches, which the
   *  linter does not check and does not claim to. */
  function splice(baseDer, extraDer) {
    var cert = pki.asn1.decode(baseDer);
    var addedOid = pki.asn1.read.oid(pki.asn1.decode(extraDer).children[0]);
    var kids = [];
    cert.children[0].children.forEach(function (child) {
      if (!(child.tagClass === "context" && child.tagNumber === 3)) { kids.push(b.raw(child.bytes)); return; }
      var keep = child.children[0].children.filter(function (e) {
        return pki.asn1.read.oid(e.children[0]) !== addedOid;
      }).map(function (e) { return b.raw(e.bytes); });
      kids.push(b.contextConstructed(3, b.sequence(keep.concat([b.raw(extraDer)]))));
    });
    return b.sequence([b.sequence(kids), b.raw(cert.children[1].bytes), b.raw(cert.children[2].bytes)]);
  }
  function extDer(name, critical, innerDer) {
    var kids = [b.oid(pki.oid.byName(name))];
    if (critical) kids.push(b.boolean(true));
    kids.push(b.octetString(innerDer));
    return b.sequence(kids);
  }
  function ekuDer(names, critical) {
    return extDer("extKeyUsage", critical,
      b.sequence(names.map(function (n) { return b.oid(pki.oid.byName(n) || n); })));
  }

  // ---- C1-C4: what makes a certificate one of these -----------------------------------------
  var baseline = await lintOver({});
  var baseErrors = baseline.findings.filter(function (f) {
    return f.source === "cabf-cs" && (f.severity === "error" || f.severity === "fatal");
  });
  check("C1. CONTROL: a conforming code signing certificate reports nothing at error or worse (" +
    baseErrors.map(function (f) { return f.id; }).join(",") + ")", baseErrors.length === 0);
  // Detection is what the certificate declares, so each identifier is driven with NO profile named
  // and the rows must run of their own accord.
  var kindCases = [[CS, "codeSigning"], [EV, "codeSigning"], [TS, "timeStamping"]];
  var detected = [];
  for (var ki = 0; ki < kindCases.length; ki++) {
    var kindDer = await sign({ certificatePolicies: [{ oid: kindCases[ki][0] }],
      extendedKeyUsage: [kindCases[ki][1]] });
    detected.push(pki.lint.certificate(kindDer).ran.some(function (id) {
      return id.indexOf("lint/cabf-cs/") === 0;
    }));
  }
  check("C2. each of the three reserved identifiers is read as this profile unprompted",
    detected.length === 3 && detected.every(function (d) { return d === true; }));
  var noneDer = await sign({ certificatePolicies: [{ oid: pki.oid.byName("anyPolicy") }] });
  check("C3. a certificate asserting no reserved identifier is left alone",
    pki.lint.certificate(noneDer).ran.every(function (id) { return id.indexOf("lint/cabf-cs/") !== 0; }));
  // Sec. 7.1.6.3 gives a subordinate CA the same identifiers, so carrying one does not make a
  // certificate a subscriber certificate.
  var csCa = await pki.x509.sign({ subject: [{ commonName: "CS Issuing CA" }],
    subjectPublicKey: edPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
      certificatePolicies: [{ oid: CS }] } }, { key: edPriv });
  check("C4. an intermediate carrying a reserved identifier is not read as a subscriber",
    !has(pki.lint.certificate(csCa), "lint/cabf-cs/basic-constraints-ca-true") &&
    !has(pki.lint.certificate(csCa), "lint/cabf-cs/key-usage-forbidden-bit"));
  check("C4b. ...and naming the profile still checks it",
    has(lint(csCa), "lint/cabf-cs/basic-constraints-ca-true"));

  // ---- C5-C8: certificatePolicies (a) and the 7.1.6.4 exactly-one rule -----------------------
  check("C5. certificatePolicies MUST be present",
    has(await lintOver({ certificatePolicies: undefined }), "lint/cabf-cs/policies-missing"));
  check("C6. ...and SHOULD NOT be critical, which is a warning rather than an error",
    has(lint(splice(await sign({}), extDer("certificatePolicies", true,
      b.sequence([b.sequence([b.oid(CS)])])))), "lint/cabf-cs/policies-critical") &&
    sevOf(lint(splice(await sign({}), extDer("certificatePolicies", true,
      b.sequence([b.sequence([b.oid(CS)])])))), "lint/cabf-cs/policies-critical") === "warn");
  // Sec. 7.1.6.4 is dated 15 September 2026, so the row is gated on the issuance date the
  // certificate states and a certificate issued before it is not held to a rule that did not apply.
  var afterRule = { notBefore: new Date("2026-10-01T00:00:00Z"), notAfter: new Date("2026-12-01T00:00:00Z") };
  check("C7. exactly one reserved identifier, so two are reported",
    has(await lintOver({ certificatePolicies: [{ oid: CS }, { oid: TS }] }, ecPub, afterRule),
      "lint/cabf-cs/policies-reserved-identifier-count"));
  check("C7b. ...and none is reported too, where the caller named the profile",
    has(lint(await sign({ certificatePolicies: [{ oid: pki.oid.byName("anyPolicy") }] }, ecPub, afterRule)),
      "lint/cabf-cs/policies-reserved-identifier-count"));
  check("C7c. CONTROL: a certificate issued before 15 September 2026 is not held to it",
    !has(await lintOver({ certificatePolicies: [{ oid: CS }, { oid: TS }] }),
      "lint/cabf-cs/policies-reserved-identifier-count"));
  // "HTTP URL for the Subordinate CA's Certification Practice Statement". The S/MIME clause names
  // both schemes; this one names HTTP, so the same qualifier answers differently under each.
  function policiesDer(policyOid, cpsUri) {
    return extDer("certificatePolicies", false, b.sequence([b.sequence([b.oid(policyOid),
      b.sequence([b.sequence([b.oid(pki.oid.byName("cps")), b.ia5(cpsUri)])])])]));
  }
  check("C8. an HTTPS cPSuri is reported here, where the S/MIME clause admits one",
    has(lint(splice(await sign({}), policiesDer(CS, "https://cps.example/x"))),
      "lint/cabf-cs/policies-cps-not-http-url") &&
    !has(lint(splice(await sign({}), policiesDer(CS, "http://cps.example/x"))),
      "lint/cabf-cs/policies-cps-not-http-url"));

  // ---- C9-C11: cRLDistributionPoints (b) ----------------------------------------------------
  check("C9. cRLDistributionPoints MUST be present",
    has(await lintOver({ cRLDistributionPoints: undefined }), "lint/cabf-cs/crldp-missing"));
  check("C10. ...MUST NOT be critical, which is an error here and a warning under cabf-smime",
    has(lint(splice(await sign({}), extDer("cRLDistributionPoints", true,
      b.sequence([b.sequence([b.contextConstructed(0, b.contextConstructed(0,
        b.contextPrimitive(6, Buffer.from("http://crl.example/a.crl", "latin1"))))])])))),
      "lint/cabf-cs/crldp-critical"));
  check("C11. ...and MUST contain an HTTP URL",
    has(await lintOver({ cRLDistributionPoints: [
      { fullName: [{ uniformResourceIdentifier: "ldap://crl.example/a" }] }] }),
      "lint/cabf-cs/crldp-no-http-uri"));

  // ---- C12-C15: authorityInformationAccess (c) ----------------------------------------------
  check("C12. authorityInformationAccess MUST be present, an error where cabf-smime asks at SHOULD",
    has(await lintOver({ authorityInfoAccess: undefined }), "lint/cabf-cs/aia-missing") &&
    sevOf(await lintOver({ authorityInfoAccess: undefined }), "lint/cabf-cs/aia-missing") === "error");
  check("C13. ...and MUST NOT be critical",
    has(lint(splice(await sign({}), extDer("authorityInfoAccess", true,
      b.sequence([b.sequence([b.oid(pki.oid.byName("caIssuers")),
        b.contextPrimitive(6, Buffer.from("http://i.example/ca.cer", "latin1"))])])))),
      "lint/cabf-cs/aia-critical"));
  check("C14. an id-ad-caIssuers HTTP URL MUST be there",
    has(await lintOver({ authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } }] }),
      "lint/cabf-cs/aia-ca-issuers-missing"));
  check("C15. ...and every location the clause names is an HTTP URL",
    has(await lintOver({ authorityInfoAccess: [
      { accessMethod: "caIssuers", accessLocation: { uniformResourceIdentifier: "ldap://i.example/ca" } }] }),
      "lint/cabf-cs/aia-non-http-uri"));

  // ---- C16: basicConstraints (d) ------------------------------------------------------------
  check("C16. the cA field MUST NOT be true",
    has(lint(splice(await sign({}), extDer("basicConstraints", true, b.sequence([b.boolean(true)])))),
      "lint/cabf-cs/basic-constraints-ca-true"));

  // ---- C17-C21: keyUsage (e) ----------------------------------------------------------------
  // "Bit positions for keyCertSign and cRLSign MUST NOT be set. All other bit positions SHOULD NOT
  // be set." One sentence, two strengths, so two rows.
  check("C17. keyUsage MUST be present",
    has(await lintOver({ keyUsage: undefined }), "lint/cabf-cs/key-usage-missing"));
  check("C18. ...and MUST be critical, an error where cabf-smime asks at SHOULD",
    has(lint(splice(await sign({}), extDer("keyUsage", false, b.bitString(Buffer.from([0x80]), 7)))),
      "lint/cabf-cs/key-usage-not-critical") &&
    sevOf(lint(splice(await sign({}), extDer("keyUsage", false, b.bitString(Buffer.from([0x80]), 7)))),
      "lint/cabf-cs/key-usage-not-critical") === "error");
  check("C19. digitalSignature MUST be set",
    has(lint(splice(await sign({}), extDer("keyUsage", true, b.bitString(Buffer.from([0x40]), 6)))),
      "lint/cabf-cs/key-usage-missing-digital-signature"));
  // keyCertSign (bit 5) and cRLSign (bit 6) beside digitalSignature (bit 0).
  check("C20. keyCertSign and cRLSign are reported at error",
    has(lint(splice(await sign({}), extDer("keyUsage", true, b.bitString(Buffer.from([0x86]), 1)))),
      "lint/cabf-cs/key-usage-forbidden-bit") &&
    sevOf(lint(splice(await sign({}), extDer("keyUsage", true, b.bitString(Buffer.from([0x86]), 1)))),
      "lint/cabf-cs/key-usage-forbidden-bit") === "error");
  // nonRepudiation (bit 1) beside digitalSignature: not required, not forbidden, discouraged.
  check("C21. any other bit is reported at warn, which is the other half of the same sentence",
    has(await lintOver({ keyUsage: ["digitalSignature", "nonRepudiation"] }),
      "lint/cabf-cs/key-usage-discouraged-bit") &&
    sevOf(await lintOver({ keyUsage: ["digitalSignature", "nonRepudiation"] }),
      "lint/cabf-cs/key-usage-discouraged-bit") === "warn" &&
    !has(await lintOver({ keyUsage: ["digitalSignature", "nonRepudiation"] }),
      "lint/cabf-cs/key-usage-forbidden-bit"));

  // ---- C22-C26: extKeyUsage (f), whose required purpose differs by kind ----------------------
  check("C22. a code signing certificate MUST carry id-kp-codeSigning",
    has(await lintOver({ extendedKeyUsage: ["emailProtection"] }),
      "lint/cabf-cs/eku-missing-code-signing"));
  check("C22b. ...and an EV one is a code signing certificate too",
    has(await lintOver({ certificatePolicies: [{ oid: EV }], extendedKeyUsage: ["emailProtection"] }),
      "lint/cabf-cs/eku-missing-code-signing"));
  check("C23. a timestamp certificate MUST carry id-kp-timeStamping instead",
    has(await lintOver({ certificatePolicies: [{ oid: TS }], extendedKeyUsage: ["codeSigning"] }),
      "lint/cabf-cs/eku-missing-time-stamping") &&
    !has(await lintOver({ certificatePolicies: [{ oid: TS }], extendedKeyUsage: ["codeSigning"] }),
      "lint/cabf-cs/eku-missing-code-signing"));
  check("C24. a timestamp certificate's extKeyUsage MUST be marked critical",
    has(lint(splice(await sign({ certificatePolicies: [{ oid: TS }] }), ekuDer(["timeStamping"], false))),
      "lint/cabf-cs/eku-not-critical-timestamp") &&
    !has(lint(splice(await sign({ certificatePolicies: [{ oid: TS }] }), ekuDer(["timeStamping"], true))),
      "lint/cabf-cs/eku-not-critical-timestamp"));
  var ekuBase = await sign({});
  check("C25. anyExtendedKeyUsage and id-kp-serverAuth MUST NOT be present",
    ["anyExtendedKeyUsage", "serverAuth"].every(function (p) {
      return has(lint(splice(ekuBase, ekuDer(["codeSigning", p], false))),
        "lint/cabf-cs/eku-forbidden-purpose");
    }));
  var extraEku = lint(splice(ekuBase, ekuDer(["codeSigning", "clientAuth"], false)));
  check("C26. any other purpose is reported at warn, and the three the clause names as MAY are not",
    has(extraEku, "lint/cabf-cs/eku-discouraged-purpose") &&
    sevOf(extraEku, "lint/cabf-cs/eku-discouraged-purpose") === "warn" &&
    // Asserted against the LITERAL identifiers rather than through the registry names the rule
    // itself reads, so this cannot pass by both sides resolving the same wrong entry. Microsoft
    // assigns Document Signing 1.3.6.1.4.1.311.10.3.12, the sibling of the Lifetime Signing arc;
    // the clause prints 1.3.6.1.4.1.311.3.10.3.12. A certificate carrying either is permitted.
    ["1.3.6.1.4.1.311.10.3.13", "1.3.6.1.5.5.7.3.4",
      "1.3.6.1.4.1.311.10.3.12", "1.3.6.1.4.1.311.3.10.3.12"].every(function (p) {
      return !has(lint(splice(ekuBase, ekuDer(["codeSigning", p], false))),
        "lint/cabf-cs/eku-discouraged-purpose");
    }));

  // ---- C27-C28: authorityKeyIdentifier (g) --------------------------------------------------
  check("C27. authorityKeyIdentifier MUST be present",
    has(lint(await signSelf({})), "lint/cabf-cs/aki-missing"));
  check("C28. ...and MUST NOT be critical",
    has(lint(splice(await sign({}), extDer("authorityKeyIdentifier", true,
      b.sequence([b.contextPrimitive(0, Buffer.alloc(20, 9))])))), "lint/cabf-cs/aki-critical"));

  // ---- C29-C31: the validity ceilings (6.3.2) -----------------------------------------------
  // Two ceilings for code signing, keyed on the issuance date, and one for timestamping. Each is
  // driven at the boundary and one day past it, because a ceiling reads "MUST NOT exceed".
  var beforeMarch = new Date("2026-01-01T00:00:00Z");
  check("C29. a code signing certificate issued before 1 March 2026 may run 39 months",
    !has(await lintOver({}, ecPub, { notBefore: beforeMarch, notAfter: new Date("2029-04-01T00:00:00Z") }),
      "lint/cabf-cs/validity-too-long") &&
    has(await lintOver({}, ecPub, { notBefore: beforeMarch, notAfter: new Date("2029-04-02T00:00:00Z") }),
      "lint/cabf-cs/validity-too-long"));
  check("C30. one issued on or after it may run 460 days",
    !has(await lintOver({}, ecPub, { notBefore: NB, notAfter: new Date("2027-07-05T00:00:00Z") }),
      "lint/cabf-cs/validity-too-long") &&
    has(await lintOver({}, ecPub, { notBefore: NB, notAfter: new Date("2027-07-06T00:00:00Z") }),
      "lint/cabf-cs/validity-too-long"));
  check("C31. a timestamp certificate may run 135 months",
    !has(await lintOver({ certificatePolicies: [{ oid: TS }], extendedKeyUsage: ["timeStamping"] },
      ecPub, { notBefore: NB, notAfter: new Date("2037-07-01T00:00:00Z") }),
      "lint/cabf-cs/validity-too-long") &&
    has(await lintOver({ certificatePolicies: [{ oid: TS }], extendedKeyUsage: ["timeStamping"] },
      ecPub, { notBefore: NB, notAfter: new Date("2037-07-02T00:00:00Z") }),
      "lint/cabf-cs/validity-too-long"));

  // ---- C32-C33: the key floors (6.1.5.2) ----------------------------------------------------
  check("C32. an RSA modulus below 3072 bits is reported, and one at the floor is not",
    has(await lintOver({}, rsaWeakPub), "lint/cabf-cs/weak-key") &&
    !has(await lintOver({}, rsaOkPub), "lint/cabf-cs/weak-key"));
  check("C33. the three named curves are accepted and nothing else is",
    !has(await lintOver({}, ecPub), "lint/cabf-cs/weak-key") &&
    !has(await lintOver({}, ec521Pub), "lint/cabf-cs/weak-key") &&
    has(await lintOver({}, edPub), "lint/cabf-cs/weak-key"));
  // The section names three families, so the DSA arm is read rather than the family refused: one
  // of L 2048 with N 224 or 256 conforms, and anything else does not.
  var nodeCrypto = require("node:crypto");
  function dsaSpki(modulusLength, divisorLength) {
    return nodeCrypto.generateKeyPairSync("dsa", { modulusLength: modulusLength, divisorLength: divisorLength })
      .publicKey.export({ format: "der", type: "spki" });
  }
  check("C34. a conforming DSA key is accepted",
    !has(await lintOver({}, dsaSpki(2048, 256)), "lint/cabf-cs/weak-key") &&
    !has(await lintOver({}, dsaSpki(2048, 224)), "lint/cabf-cs/weak-key"));
  check("C35. ...and a DSA key outside the two parameter options is reported",
    has(await lintOver({}, dsaSpki(1024, 160)), "lint/cabf-cs/weak-key"));

  // ---- C36-C48: the subject distinguished name (7.1.4.2.2, 7.1.4.2.3 and 7.1.4.2.4) -----------
  // Three subsections, scoped by their own headings: (2) covers EV and non-EV code signing, (3)
  // non-EV alone, (4) EV alone, and none of them names a Timestamp Certificate.
  var EV_POLICY = { oid: EV };
  function evSubject(over) {
    return EV_SUBJECT.filter(function (a) {
      var k = Object.keys(a)[0];
      return !(over && Object.prototype.hasOwnProperty.call(over, k) && over[k] === undefined);
    }).map(function (a) {
      var k = Object.keys(a)[0];
      return (over && over[k] !== undefined && over[k] !== null) ? (function () { var o = {}; o[k] = over[k]; return o; })() : a;
    }).concat(over && over.extra ? over.extra : []);
  }
  async function lintEv(subject) { return lint(await sign({ certificatePolicies: [EV_POLICY] }, ecPub, undefined, subject)); }
  async function lintNonEv(subject) { return lint(await sign({}, ecPub, undefined, subject)); }
  var evBase = await lintEv(EV_SUBJECT);
  var nonEvBase = await lintNonEv(NONEV_SUBJECT);

  check("C36. subject:commonName is required",
    has(await lintNonEv([{ organizationName: "O" }, { localityName: "L" }, { countryName: "US" }]),
      "lint/cabf-cs/subject-common-name-missing") &&
    !has(nonEvBase, "lint/cabf-cs/subject-common-name-missing"));
  check("C37. subject:domainComponent is prohibited",
    has(await lintNonEv(NONEV_SUBJECT.concat([{ domainComponent: "example" }])),
      "lint/cabf-cs/subject-domain-component-prohibited") &&
    !has(nonEvBase, "lint/cabf-cs/subject-domain-component-prohibited"));
  // "Subject attributes MUST NOT contain only metadata such as '.', '-', and ' ' (i.e. space)
  // characters", so a value made of nothing else is reported and one carrying anything else is not.
  var metadataOnly = [];
  for (var mi = 0; mi < 5; mi++) {
    var mv = [".", "-", " ", " - . ", "..."][mi];
    metadataOnly.push(has(await lintNonEv([{ commonName: "Example Corp" }, { organizationName: mv },
      { localityName: "L" }, { countryName: "US" }]), "lint/cabf-cs/subject-attribute-metadata-only"));
  }
  check("C38. a subject attribute of metadata characters alone is reported (" + metadataOnly.join(",") + ")",
    metadataOnly.every(function (m) { return m === true; }) &&
    !has(nonEvBase, "lint/cabf-cs/subject-attribute-metadata-only"));
  check("C38b. CONTROL: a value carrying anything else is not reported",
    !has(await lintNonEv([{ commonName: "Example Corp" }, { organizationName: "A-1 Ltd." },
      { localityName: "L" }, { countryName: "US" }]), "lint/cabf-cs/subject-attribute-metadata-only"));
  check("C39. subject:organizationName is required under both subsections",
    has(await lintNonEv([{ commonName: "C" }, { localityName: "L" }, { countryName: "US" }]),
      "lint/cabf-cs/subject-organization-name-missing") &&
    has(await lintEv(evSubject({ organizationName: undefined })),
      "lint/cabf-cs/subject-organization-name-missing") &&
    !has(nonEvBase, "lint/cabf-cs/subject-organization-name-missing") &&
    !has(evBase, "lint/cabf-cs/subject-organization-name-missing"));
  // localityName is "Required if the stateOrProvinceName field is absent" and the state row says
  // the same in the other direction, so one of the two must be there and either alone satisfies it.
  check("C40. one of subject:localityName and subject:stateOrProvinceName must be present",
    has(await lintNonEv([{ commonName: "C" }, { organizationName: "O" }, { countryName: "US" }]),
      "lint/cabf-cs/subject-locality-and-state-absent") &&
    !has(await lintNonEv([{ commonName: "C" }, { organizationName: "O" },
      { stateOrProvinceName: "Delaware" }, { countryName: "US" }]),
      "lint/cabf-cs/subject-locality-and-state-absent") &&
    !has(nonEvBase, "lint/cabf-cs/subject-locality-and-state-absent"));
  check("C41. subject:countryName is required",
    has(await lintNonEv([{ commonName: "C" }, { organizationName: "O" }, { localityName: "L" }]),
      "lint/cabf-cs/subject-country-name-missing") &&
    !has(nonEvBase, "lint/cabf-cs/subject-country-name-missing"));
  // The builder holds countryName to a two-character PrintableString, which is the signer doing its
  // job, so a longer one is spliced into the signed subject.
  function dnDer(attrs) {
    return b.sequence(attrs.map(function (a) {
      var enc = a.printable ? b.printable(a.value) : b.utf8(a.value);
      return b.set([b.sequence([b.oid(pki.oid.byName(a.type)), enc])]);
    }));
  }
  function spliceSubject(baseDer, subjectDer) {
    var cert = pki.asn1.decode(baseDer);
    var kids = cert.children[0].children.map(function (c, i) {
      return i === 5 ? b.raw(subjectDer) : b.raw(c.bytes);
    });
    return b.sequence([b.sequence(kids), b.raw(cert.children[1].bytes), b.raw(cert.children[2].bytes)]);
  }
  var longCountry = dnDer([{ type: "commonName", value: "C" }, { type: "organizationName", value: "O" },
    { type: "localityName", value: "L" }, { type: "countryName", value: "USA", printable: true }]);
  check("C42. subject:countryName must be a two-letter code",
    has(lint(spliceSubject(await sign({}), longCountry)), "lint/cabf-cs/subject-country-name-bad-syntax") &&
    !has(nonEvBase, "lint/cabf-cs/subject-country-name-bad-syntax"));

  // Subsection 4 alone, so a non-EV certificate is not held to any of it.
  check("C43. subject:businessCategory is required on an EV certificate and not on a non-EV one",
    has(await lintEv(evSubject({ businessCategory: undefined })),
      "lint/cabf-cs/subject-business-category-missing") &&
    !has(nonEvBase, "lint/cabf-cs/subject-business-category-missing") &&
    !has(evBase, "lint/cabf-cs/subject-business-category-missing"));
  // The clause fixes the four strings exactly, so a differing case is a differing string.
  check("C44. ...and must be one of the four strings the clause names",
    has(await lintEv(evSubject({ businessCategory: "Private organization" })),
      "lint/cabf-cs/subject-business-category-invalid") &&
    has(await lintEv(evSubject({ businessCategory: "Charity" })),
      "lint/cabf-cs/subject-business-category-invalid"));
  var categories = [];
  for (var bc = 0; bc < 4; bc++) {
    var name = ["Private Organization", "Government Entity", "Business Entity", "Non-Commercial Entity"][bc];
    categories.push(!has(await lintEv(evSubject({ businessCategory: name })),
      "lint/cabf-cs/subject-business-category-invalid"));
  }
  check("C44b. each of the four is accepted", categories.every(function (c) { return c === true; }));
  check("C45. subject:jurisdictionCountryName is required on an EV certificate",
    has(await lintEv(evSubject({ jurisdictionCountryName: undefined })),
      "lint/cabf-cs/subject-jurisdiction-country-missing") &&
    !has(evBase, "lint/cabf-cs/subject-jurisdiction-country-missing"));
  // The clause bounds the jurisdiction fields against the LEVEL the agency operates at, which the
  // certificate does not carry, and it requires the state at the locality level only "where the
  // state or province regulates the registration of the entities at the locality level". So a
  // country with a locality and no state is conformant for such an agency, and no row grades the
  // relationship. The country is required outright and C45 covers it.
  var jurisdictionShapes = [
    [{ jurisdictionLocalityName: "Dover" }],
    [{ jurisdictionStateOrProvinceName: "Delaware" }],
    [{ jurisdictionStateOrProvinceName: "Delaware" }, { jurisdictionLocalityName: "Dover" }],
  ];
  var jurisdictionQuiet = [];
  for (var ji = 0; ji < jurisdictionShapes.length; ji++) {
    var jRep = await lintEv(evSubject({ extra: jurisdictionShapes[ji] }));
    jurisdictionQuiet.push(jRep.findings.every(function (f) {
      return f.id.indexOf("lint/cabf-cs/subject-jurisdiction") !== 0 ||
        f.id === "lint/cabf-cs/subject-jurisdiction-country-missing";
    }));
  }
  check("C46. no row grades a jurisdiction level against an agency level the certificate does not carry",
    jurisdictionQuiet.every(function (q) { return q === true; }));
  // A certificate asserting two reserved identifiers claims BOTH, and the order they sit in the
  // extension is not meaning. Before 15 September 2026 the exactly-one rule does not fire, so
  // nothing else reports such a certificate and a first-match read would let DER order decide which
  // rules it answers for.
  function idsOf(rep) {
    return rep.findings.map(function (f) { return f.id; }).filter(function (id) {
      return id.indexOf("lint/cabf-cs/") === 0;
    }).sort().join(",");
  }
  var bothOrders = [[{ oid: CS }, EV_POLICY], [EV_POLICY, { oid: CS }]];
  var bothReports = [];
  for (var bo = 0; bo < bothOrders.length; bo++) {
    bothReports.push(idsOf(lint(await sign({ certificatePolicies: bothOrders[bo] }, ecPub, undefined,
      NONEV_SUBJECT))));
  }
  check("C46b. the rules a certificate answers for do not depend on the order of its policies",
    bothReports[0] === bothReports[1] &&
    bothReports[0].indexOf("lint/cabf-cs/subject-business-category-missing") !== -1);
  // The same for the two arms of the extKeyUsage clause: a certificate claiming both kinds is held
  // to both required purposes whichever order it names them in.
  var bothKinds = [[{ oid: CS }, { oid: TS }], [{ oid: TS }, { oid: CS }]];
  var kindReports = [];
  for (var bk = 0; bk < bothKinds.length; bk++) {
    kindReports.push(idsOf(lint(await sign({ certificatePolicies: bothKinds[bk],
      extendedKeyUsage: ["codeSigning"] }, ecPub, undefined, NONEV_SUBJECT))));
  }
  check("C46c. ...and a certificate claiming both kinds answers for both arms, in either order",
    kindReports[0] === kindReports[1] &&
    kindReports[0].indexOf("lint/cabf-cs/eku-missing-time-stamping") !== -1);
  check("C47. subject:serialNumber is required on an EV certificate",
    has(await lintEv(evSubject({ serialNumber: undefined })),
      "lint/cabf-cs/subject-serial-number-missing") &&
    !has(nonEvBase, "lint/cabf-cs/subject-serial-number-missing") &&
    !has(evBase, "lint/cabf-cs/subject-serial-number-missing"));
  // None of the three subsections names a Timestamp Certificate, so none of these rows reaches one.
  var tsBare = await lintOver({ certificatePolicies: [{ oid: TS }], extendedKeyUsage: ["timeStamping"] },
    ecPub, undefined, [{ commonName: "A Timestamp Authority" }]);
  check("C48. no subject row reaches a timestamp certificate",
    ["subject-common-name-missing", "subject-organization-name-missing", "subject-country-name-missing",
      "subject-locality-and-state-absent", "subject-business-category-missing",
      "subject-jurisdiction-country-missing", "subject-serial-number-missing",
      "subject-domain-component-prohibited", "subject-attribute-metadata-only"]
      .every(function (id) { return !has(tsBare, "lint/cabf-cs/" + id); }));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
