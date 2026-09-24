// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the CA/Browser Forum S/MIME BR subscriber certificate profile in
 * pki.lint.certificate. RED conformance vectors written BEFORE the rules, each driving the shipped
 * verb and asserting the finding id, never a hand-decoded internal.
 *
 * Every row is derived from section 7.1.2.3 of S/MIME BR v1.0.15, read from the document. The
 * profile varies by GENERATION (Legacy, Multipurpose, Strict), and a subscriber certificate names
 * its own generation through the reserved policy identifier of section 7.1.6.1, a 4x3 matrix of
 * certificate type by generation. So the rules read the certificate's own declaration rather than
 * taking a generation from the caller, and a rule whose table differs by generation is driven at
 * each generation it differs for.
 *
 *   S1-S4    detection: the reserved identifier is what says this is an S/MIME certificate
 *   S5-S9    certificatePolicies (7.1.2.3 a) and the Legacy sunset (7.1.6.1)
 *   S10-S13  cRLDistributionPoints (b) and authorityInformationAccess (c)
 *   S14-S15  basicConstraints (d)
 *   S16-S19  keyUsage (e), whose table differs by key type
 *   S20-S23  extKeyUsage (f), whose permitted set differs by generation
 *   S24-S27  authorityKeyIdentifier (g) and subjectAltName (h)
 *   S28-S30  the optional extensions (i, j, n) and their criticality
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2026-06-01T00:00:00Z");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function lint(der, opts) { return pki.lint.certificate(der, opts || { profile: "cabf-smime" }); }

async function run() {
  var ed = await pki.key.generate("Ed25519");
  var edPriv = await pki.key.export(ed.privateKey), edPub = await pki.key.export(ed.publicKey);
  var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var ecPub = await pki.key.export(ec.publicKey);
  var rsa = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  var rsaPub = await pki.key.export(rsa.publicKey);

  var STRICT = pki.oid.byName("smime-mailbox-strict");
  var MULTI = pki.oid.byName("smime-mailbox-multipurpose");
  var LEGACY = pki.oid.byName("smime-mailbox-legacy");

  // A conforming Strict-generation mailbox-validated certificate, from the 7.1.2.3 list.
  function exts(over) {
    var e = {
      certificatePolicies: [{ oid: STRICT }],
      cRLDistributionPoints: [{ fullName: [{ uniformResourceIdentifier: "http://crl.example/a.crl" }] }],
      authorityInfoAccess: [
        { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } },
        { accessMethod: "caIssuers", accessLocation: { uniformResourceIdentifier: "http://i.example/ca.cer" } }],
      keyUsage: ["digitalSignature"],
      extendedKeyUsage: ["emailProtection"],
      subjectAltName: [{ rfc822Name: "a@example.com" }],
      subjectKeyIdentifier: true,
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
  function sign(over, pub, subject) {
    return pki.x509.sign({ subject: subject === undefined ? [{ commonName: "A Person" }] : subject,
      subjectPublicKey: pub || edPub, notBefore: NB, notAfter: NA, extensions: exts(over) },
      { cert: issuingCa, key: edPriv });
  }
  function signSelf(over, pub) {
    return pki.x509.sign({ subject: [{ commonName: "A Person" }], subjectPublicKey: pub || edPub,
      notBefore: NB, notAfter: NA, extensions: exts(over) }, { key: edPriv });
  }
  async function lintOver(over, pub, subject) { return lint(await sign(over, pub, subject)); }

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

  // ---- S1-S4: what makes a certificate one of these -----------------------------------------
  var baseline = await lintOver({});
  var baseErrors = baseline.findings.filter(function (f) {
    return f.source === "cabf-smime" && (f.severity === "error" || f.severity === "fatal");
  });
  check("S1. CONTROL: a conforming Strict certificate reports nothing at error or worse (" +
    baseErrors.map(function (f) { return f.id; }).join(",") + ")", baseErrors.length === 0);

  // A certificate asserting a reserved identifier IS an S/MIME certificate, so the rows reach it
  // with no profile named. That is the detector: unlike a TLS certificate, which says what it is
  // through an extended key purpose, this one names its exact profile.
  var autoRep = pki.lint.certificate(await sign({ extendedKeyUsage: ["emailProtection", "serverAuth"] }));
  check("S2. the rows reach a certificate that asserts a reserved identifier, unprompted",
    has(autoRep, "lint/cabf-smime/eku-forbidden-purpose"));
  check("S3. ...and do not reach one that asserts none",
    !has(pki.lint.certificate(await pki.x509.sign({ subject: [{ commonName: "A Person" }],
      subjectPublicKey: edPub, notBefore: NB, notAfter: NA,
      extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["emailProtection", "serverAuth"] } },
      { key: edPriv })), "lint/cabf-smime/eku-forbidden-purpose"));
  // Section 7.1.6.3: a certificate issued to a Subordinate CA "SHALL include one or more explicit
  // policy identifiers defined in Section 7.1.6.1", so an intermediate carries the same ones. The
  // identifier alone therefore does not say a certificate is a SUBSCRIBER, and these rows would
  // otherwise report an intermediate for asserting cA and keyCertSign and naming no mailbox.
  var smimeCa = await pki.x509.sign({ subject: [{ commonName: "S/MIME Issuing CA" }],
    subjectPublicKey: edPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
      certificatePolicies: [{ oid: STRICT }] } }, { key: edPriv });
  var caAuto = pki.lint.certificate(smimeCa);
  check("S3b. an intermediate carrying a reserved identifier is not read as a subscriber (" +
    ids(caAuto).filter(function (i) { return i.indexOf("lint/cabf-smime/") === 0; }).join(",") + ")",
    !has(caAuto, "lint/cabf-smime/basic-constraints-ca-true") &&
    !has(caAuto, "lint/cabf-smime/key-usage-forbidden-bit") &&
    !has(caAuto, "lint/cabf-smime/san-no-mailbox"));
  check("S3c. ...and naming the profile still checks it, which is how a malformed one is read",
    has(lint(smimeCa), "lint/cabf-smime/basic-constraints-ca-true"));

  check("S4. the twelve reserved identifiers are named by the registry",
    ["mailbox", "organization", "sponsor", "individual"].every(function (t) {
      return ["legacy", "multipurpose", "strict"].every(function (g) {
        return typeof pki.oid.byName("smime-" + t + "-" + g) === "string";
      });
    }));

  // ---- S5-S9: certificatePolicies (7.1.2.3 a) and the Legacy sunset -------------------------
  check("S5. certificatePolicies SHOULD NOT be critical, which is a warning",
    (function (rep) {
      return rep.findings.some(function (f) {
        return f.id === "lint/cabf-smime/policies-critical" && f.severity === "warn";
      });
    })(lint(splice(await sign({}), extDer("certificatePolicies", true,
      b.sequence([b.sequence([b.oid(STRICT)])]))))));
  // Reachable only where the caller names the profile: without the extension there is no reserved
  // identifier, which is what otherwise says the certificate is one of these.
  check("S5b. certificatePolicies SHALL be present",
    has(await lintOver({ certificatePolicies: undefined }), "lint/cabf-smime/policies-missing"));
  check("S5c. ...and its absence is not counted as naming zero reserved identifiers as well",
    !has(await lintOver({ certificatePolicies: undefined }),
      "lint/cabf-smime/policies-reserved-identifier-count"));

  check("S6. exactly one reserved identifier: two is a fault",
    has(await lintOver({ certificatePolicies: [{ oid: STRICT }, { oid: MULTI }] }),
      "lint/cabf-smime/policies-reserved-identifier-count"));
  check("S7. CONTROL: one reserved identifier beside a CA's own policy is not",
    !has(await lintOver({ certificatePolicies: [{ oid: STRICT }, { oid: "1.3.6.1.4.1.99999.7" }] }),
      "lint/cabf-smime/policies-reserved-identifier-count"));
  // "Effective July 15, 2025 S/MIME Subscriber Certificates SHALL NOT be issued using the Legacy
  // Generation profiles", so the row is gated to the issuance date the certificate states.
  check("S8. a Legacy-generation certificate issued after the sunset is reported",
    has(await lintOver({ certificatePolicies: [{ oid: LEGACY }] }),
      "lint/cabf-smime/legacy-generation-retired"));
  var oldLegacy = await pki.x509.sign({ subject: [{ commonName: "A Person" }],
    subjectPublicKey: edPub, notBefore: new Date("2024-01-01T00:00:00Z"),
    notAfter: new Date("2024-06-01T00:00:00Z"),
    extensions: exts({ certificatePolicies: [{ oid: LEGACY }] }) }, { key: edPriv });
  check("S9. CONTROL: one issued before it is not",
    !has(lint(oldLegacy), "lint/cabf-smime/legacy-generation-retired"));

  // ---- S10-S13: cRLDistributionPoints (b) and authorityInformationAccess (c) ------------------
  check("S10. cRLDistributionPoints SHALL be present",
    has(await lintOver({ cRLDistributionPoints: undefined }), "lint/cabf-smime/crldp-missing"));
  // Strict and Multipurpose: "Every uniformResourceIdentifier SHALL have the URI scheme HTTP."
  check("S11. under Strict, a non-HTTP distribution point URI is reported",
    has(await lintOver({ cRLDistributionPoints: [
      { fullName: [{ uniformResourceIdentifier: "ldap://crl.example/a" }] }] }),
      "lint/cabf-smime/crldp-non-http-uri"));
  // Legacy: "At least one ... SHALL have the URI scheme HTTP. Other schemes ... MAY be present."
  check("S12. under Legacy, a non-HTTP URI beside an HTTP one is permitted",
    !has(await lintOver({ certificatePolicies: [{ oid: LEGACY }], cRLDistributionPoints: [
      { fullName: [{ uniformResourceIdentifier: "http://crl.example/a.crl" },
        { uniformResourceIdentifier: "ldap://crl.example/a" }] }] }),
      "lint/cabf-smime/crldp-non-http-uri"));
  // "SHALL have the URI scheme HTTP", where the policy-qualifier clause of (a) says "HTTP or
  // HTTPS URL". The document distinguishes the two by wording, and "Other schemes SHALL NOT be
  // present" makes HTTPS another scheme, not a stricter HTTP.
  check("S12b. an HTTPS distribution point does not satisfy the HTTP scheme requirement",
    has(await lintOver({ cRLDistributionPoints: [
      { fullName: [{ uniformResourceIdentifier: "https://crl.example/a.crl" }] }] }),
      "lint/cabf-smime/crldp-non-http-uri"));
  check("S12c. ...under Legacy either, where only one HTTP URI is required",
    has(await lintOver({ certificatePolicies: [{ oid: LEGACY }], cRLDistributionPoints: [
      { fullName: [{ uniformResourceIdentifier: "https://crl.example/a.crl" }] }] }),
      "lint/cabf-smime/crldp-non-http-uri"));
  // The clause is "SHALL contain at least one distributionPoint whose fullName value includes a
  // GeneralName of type uniformResourceIdentifier", so an extension carrying NO URI anywhere fails
  // it. A second point without a URI beside one that has an HTTP URI does not: at least one is the
  // requirement, and reading it per point would report a conforming certificate.
  check("S12d. an extension carrying no URI at all is reported, not passed over",
    has(await lintOver({ cRLDistributionPoints: [{ fullName: [{ dNSName: "crl.example" }] }] }),
      "lint/cabf-smime/crldp-non-http-uri"));
  // RFC 7230 sec. 2.7.1 writes http-URI as "http:" "//" authority path-abempty, so carrying the
  // scheme token without the authority is not an http URI and does not satisfy the table. The
  // scheme name itself compares case-insensitively (RFC 3986 sec. 3.1).
  check("S12f. the scheme token alone is not the scheme, and the comparison folds case",
    has(await lintOver({ cRLDistributionPoints: [
      { fullName: [{ uniformResourceIdentifier: "http:crl.example/a.crl" }] }] }),
      "lint/cabf-smime/crldp-non-http-uri") &&
    !has(await lintOver({ cRLDistributionPoints: [
      { fullName: [{ uniformResourceIdentifier: "HTTP://crl.example/a.crl" }] }] }),
      "lint/cabf-smime/crldp-non-http-uri"));
  check("S12g. a malformed http URI does not satisfy the table either, in a distribution point or an accessMethod",
    has(await lintOver({ cRLDistributionPoints: [
      { fullName: [{ uniformResourceIdentifier: "http://:80/a.crl" }] }] }),
      "lint/cabf-smime/crldp-non-http-uri") &&
    has(await lintOver({ authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } },
      { accessMethod: "caIssuers", accessLocation: { uniformResourceIdentifier: "http://:80/ca.cer" } }] }),
      "lint/cabf-smime/aia-non-http-uri"));
  check("S12e. CONTROL: a second point without a URI beside an HTTP one satisfies 'at least one'",
    !has(await lintOver({ cRLDistributionPoints: [
      { fullName: [{ uniformResourceIdentifier: "http://crl.example/a.crl" }] },
      { fullName: [{ dNSName: "crl.example" }] }] }), "lint/cabf-smime/crldp-non-http-uri"));

  check("S13. authorityInformationAccess SHALL NOT be critical",
    has(lint(splice(await sign({}), extDer("authorityInfoAccess", true,
      b.sequence([b.sequence([b.oid(pki.oid.byName("caIssuers")),
        b.contextPrimitive(6, Buffer.from("http://i.example", "latin1"))])])))),
      "lint/cabf-smime/aia-critical"));

  // ---- S14-S15: basicConstraints (d) ---------------------------------------------------------
  check("S14. the cA field SHALL NOT be true",
    has(lint(splice(await sign({}), extDer("basicConstraints", true,
      b.sequence([b.boolean(true)])))), "lint/cabf-smime/basic-constraints-ca-true"));
  check("S15. pathLenConstraint SHALL NOT be present",
    has(lint(splice(await sign({}), extDer("basicConstraints", true,
      b.sequence([b.boolean(true), b.integer(0n)])))), "lint/cabf-smime/basic-constraints-path-len"));
  // Every row above asks for an extension by name, and the shared decoder returns null both for one
  // that is absent and for one whose value does not decode, so a malformed value reads as absence
  // and passes every row that asks for it. `3003020100` carries pathLenConstraint with cA
  // unasserted, which RFC 5280 sec. 4.2.1.9 refuses.
  check("S15b. an extension whose value does not decode is reported under the named profile",
    has(lint(splice(await sign({}), extDer("basicConstraints", true,
      b.raw(Buffer.from("3003020100", "hex"))))), "lint/rfc5280/extension-undecodable"));

  // ---- S16-S19: keyUsage (e), whose table differs by key type --------------------------------
  check("S16. keyUsage SHALL be present",
    has(await lintOver({ keyUsage: undefined }), "lint/cabf-smime/key-usage-missing"));
  // "Other bit positions SHALL NOT be set", over a table that differs by key algorithm:
  // keyEncipherment is permitted for an RSA key and not for an EC one.
  check("S17. keyEncipherment is permitted for an RSA key",
    !has(await lintOver({ keyUsage: ["digitalSignature", "keyEncipherment"] }, rsaPub),
      "lint/cabf-smime/key-usage-forbidden-bit"));
  check("S18. ...and reported for an EC key, whose table gives keyAgreement instead",
    has(await lintOver({ keyUsage: ["digitalSignature", "keyEncipherment"] }, ecPub),
      "lint/cabf-smime/key-usage-forbidden-bit"));
  // keyCertSign without cA is refused by the signer, which is the signer doing its job, so the
  // bits are spliced: digitalSignature (bit 0) and keyCertSign (bit 5).
  var kuCertSign = extDer("keyUsage", true, b.bitString(Buffer.from([0x84]), 2));
  check("S19. keyCertSign is reported for either key algorithm",
    has(lint(splice(await sign({}, rsaPub), kuCertSign)), "lint/cabf-smime/key-usage-forbidden-bit") &&
    has(lint(splice(await sign({}, ecPub), kuCertSign)), "lint/cabf-smime/key-usage-forbidden-bit"));
  // A bit past the nine named positions is in no table, so it is forbidden on every key algorithm:
  // digitalSignature (bit 0), which both tables permit, plus reserved bit 9.
  var kuReserved = extDer("keyUsage", true, b.bitString(Buffer.from([0x80, 0x40]), 6));
  check("S19b. a bit beyond the named positions is reported for either key algorithm",
    has(lint(splice(await sign({}, rsaPub), kuReserved)), "lint/cabf-smime/key-usage-forbidden-bit") &&
    has(lint(splice(await sign({}, ecPub), kuReserved)), "lint/cabf-smime/key-usage-forbidden-bit"));

  // ---- S20-S23: extKeyUsage (f), whose permitted set differs by generation --------------------
  check("S20. id-kp-emailProtection SHALL be present",
    has(await lintOver({ extendedKeyUsage: ["clientAuth"] }), "lint/cabf-smime/eku-missing-email-protection"));
  // "The values id-kp-serverAuth, id-kp-codeSigning, id-kp-timeStamping, and anyExtendedKeyUsage
  // SHALL NOT be present", with no generation qualifying it. Each is driven on its own, at a
  // generation that permits other purposes, so a pass cannot come from the Strict row instead.
  var forbiddenEku = ["serverAuth", "codeSigning", "timeStamping", "anyExtendedKeyUsage"];
  var forbiddenReports = [];
  for (var fi = 0; fi < forbiddenEku.length; fi++) {
    forbiddenReports.push(has(await lintOver({ certificatePolicies: [{ oid: MULTI }],
      extendedKeyUsage: ["emailProtection", forbiddenEku[fi]] }), "lint/cabf-smime/eku-forbidden-purpose"));
  }
  check("S21. each of the four purposes forbidden at every generation is reported (" +
    forbiddenEku.join(",") + ")", forbiddenReports.every(function (r) { return r === true; }));
  // Strict: "Other values SHALL NOT be present." Multipurpose and Legacy: "Other values MAY be."
  check("S22. under Strict, any other purpose is reported",
    has(await lintOver({ extendedKeyUsage: ["emailProtection", "clientAuth"] }),
      "lint/cabf-smime/eku-extra-purpose-strict"));
  // The four the sentence after the table forbids everywhere have their own row, so under Strict
  // one of them draws that row and not this one: a purpose breaks one rule, the narrower of the
  // two it falls under.
  check("S22b. a purpose forbidden at every generation draws its own row, not this one",
    has(await lintOver({ extendedKeyUsage: ["emailProtection", "serverAuth"] }),
      "lint/cabf-smime/eku-forbidden-purpose") &&
    !has(await lintOver({ extendedKeyUsage: ["emailProtection", "serverAuth"] }),
      "lint/cabf-smime/eku-extra-purpose-strict"));
  check("S23. ...and under Multipurpose it is not",
    !has(await lintOver({ certificatePolicies: [{ oid: MULTI }],
      extendedKeyUsage: ["emailProtection", "clientAuth"] }), "lint/cabf-smime/eku-extra-purpose-strict"));

  // ---- S24-S27: authorityKeyIdentifier (g) and subjectAltName (h) ----------------------------
  // A self-signed certificate carries no authorityKeyIdentifier, which the profile requires of a
  // subscriber certificate: the signer omits it only where the issuer is the subject.
  check("S24. authorityKeyIdentifier SHALL be present",
    has(lint(await signSelf({})), "lint/cabf-smime/aki-missing"));
  check("S25. CONTROL: the CA-issued baseline carries one and is not reported",
    !has(baseline, "lint/cabf-smime/aki-missing"));
  check("S25b. authorityKeyIdentifier SHALL NOT be critical",
    has(lint(splice(await sign({}), extDer("authorityKeyIdentifier", true,
      b.sequence([b.contextPrimitive(0, Buffer.alloc(20, 9))])))), "lint/cabf-smime/aki-critical"));
  check("S25c. CONTROL: the non-critical form the signer emits is not reported",
    !has(baseline, "lint/cabf-smime/aki-critical"));

  check("S26. subjectAltName SHALL contain a mailbox address",
    has(await lintOver({ subjectAltName: [{ dNSName: "example.com" }] }),
      "lint/cabf-smime/san-no-mailbox"));
  // An otherName is a [0] whatever it carries, so only its type OID tells a mailbox from anything
  // else. RFC 9598 gives id-on-SmtpUTF8Mailbox as the form that carries one.
  check("S27. CONTROL: an SmtpUTF8Mailbox otherName satisfies it",
    !has(await lintOver({ subjectAltName: [{ otherName: {
      typeId: pki.oid.byName("smtpUtf8Mailbox"), value: b.utf8("a@example.com") } }] }),
      "lint/cabf-smime/san-no-mailbox"));
  check("S27b. ...and an otherName of another type does not",
    has(await lintOver({ subjectAltName: [{ otherName: {
      typeId: pki.oid.byName("hardwareModuleName"), value: b.utf8("x") } }] }),
      "lint/cabf-smime/san-no-mailbox"));

  // ---- S28-S30: the optional extensions and their criticality --------------------------------
  check("S28. subjectKeyIdentifier SHALL NOT be critical",
    has(lint(splice(await sign({}), extDer("subjectKeyIdentifier", true,
      b.octetString(Buffer.alloc(20, 3))))), "lint/cabf-smime/ski-critical"));
  check("S29. smimeCapabilities SHALL NOT be critical",
    has(lint(splice(await sign({}), extDer("smimeCapabilities", true, b.sequence([])))),
      "lint/cabf-smime/smime-capabilities-critical"));
  // Strict and Multipurpose: subjectDirectoryAttributes is Prohibited. Legacy: MAY be present.
  // The row asks whether the extension is PRESENT, not what it carries, so any well-formed
  // attribute serves. countryName is registered and its value form is a two-letter code.
  var sdaDer = extDer("subjectDirectoryAttributes", false,
    b.sequence([b.sequence([b.oid(pki.oid.byName("countryName")),
      b.set([b.printable("US")])])]));
  check("S30. subjectDirectoryAttributes is prohibited under Strict and permitted under Legacy",
    has(lint(splice(await sign({}), sdaDer)), "lint/cabf-smime/subject-directory-attributes-prohibited") &&
    !has(lint(splice(await sign({ certificatePolicies: [{ oid: LEGACY }] }), sdaDer)),
      "lint/cabf-smime/subject-directory-attributes-prohibited"));

  // ---- S31-S50: the rest of 7.1.2.3, measured from the certificate's own bytes ---------------
  /** Lift an extension's decoded value out of a signed certificate, so a criticality vector
   *  re-wraps the encoding the signer produced rather than a second hand-built one. */
  function extValueOf(der, name) {
    var dotted = pki.oid.byName(name), found = null;
    pki.asn1.decode(der).children[0].children.forEach(function (child) {
      if (!(child.tagClass === "context" && child.tagNumber === 3)) return;
      child.children[0].children.forEach(function (e) {
        if (pki.asn1.read.oid(e.children[0]) === dotted) found = e.children[e.children.length - 1];
      });
    });
    return found === null ? null : pki.asn1.read.octetString(found);
  }
  async function recritical(name, critical, over) {
    var der = await sign(over || {});
    return lint(splice(der, extDer(name, critical, b.raw(extValueOf(der, name)))));
  }

  // (a) "If the value of this extension includes a PolicyInformation which contains a qualifier of
  // type id-qt-cps, then the value of the qualifier SHALL be a HTTP or HTTPS URL... If a qualifier
  // of type id-qt-unotice is included, then it SHALL contain explicitText and SHALL NOT contain
  // noticeRef." Both schemes are named here, unlike the CRLDP clause which names HTTP alone.
  function policiesDer(policyOid, qualifiers) {
    var pi = [b.oid(policyOid)];
    if (qualifiers && qualifiers.length) pi.push(b.sequence(qualifiers));
    return extDer("certificatePolicies", false, b.sequence([b.sequence(pi)]));
  }
  function cpsQ(uri) { return b.sequence([b.oid(pki.oid.byName("cps")), b.ia5(uri)]); }
  function noticeQ(inner) { return b.sequence([b.oid(pki.oid.byName("unotice")), inner]); }
  check("S31. an id-qt-cps qualifier that is not an HTTP or HTTPS URL is reported",
    has(lint(splice(await sign({}), policiesDer(STRICT, [cpsQ("ldap://cps.example/x")]))),
      "lint/cabf-smime/policies-cps-not-http-url"));
  check("S31b. CONTROL: this clause names both schemes, so each satisfies it",
    !has(lint(splice(await sign({}), policiesDer(STRICT, [cpsQ("http://cps.example/x")]))),
      "lint/cabf-smime/policies-cps-not-http-url") &&
    !has(lint(splice(await sign({}), policiesDer(STRICT, [cpsQ("https://cps.example/x")]))),
      "lint/cabf-smime/policies-cps-not-http-url"));
  // The clause asks for a URL, not a scheme, so a bare scheme naming no host does not satisfy it.
  check("S31c. a bare scheme is not a URL",
    has(lint(splice(await sign({}), policiesDer(STRICT, [cpsQ("http://")]))),
      "lint/cabf-smime/policies-cps-not-http-url"));
  // RFC 7230 sec. 2.7.1 writes path-abempty, which MAY be empty, so a query sits directly after
  // the authority; RFC 3986 sec. 3.5 allows a fragment on the reference. Each is a conforming URL
  // and reporting one would fail a certificate the clause admits.
  var baseForQualifiers = await sign({});
  check("S31d. CONTROL: a query with no path, and a fragment, are both conforming",
    ["https://cps.example?doc=1", "http://cps.example?doc=1", "https://cps.example/cps#s7"].every(function (u) {
      return !has(lint(splice(baseForQualifiers, policiesDer(STRICT, [cpsQ(u)]))),
        "lint/cabf-smime/policies-cps-not-http-url");
    }));
  // RFC 3986 sec. 3.2.2 admits a reg-name carrying unreserved bytes and sub-delims that no DNS
  // label may, and an IP-literal besides. The builders hold a URL they EMIT to DNS label rules;
  // holding a value someone else wrote to that rule reports a conforming URL.
  check("S31e. CONTROL: a legal authority a DNS label rule would refuse is not reported",
    ["http://foo~bar/", "http://foo!bar/", "http://[2001:db8::1]:8080/cps", "http://u:p@cps.example/"]
      .every(function (u) {
        return !has(lint(splice(baseForQualifiers, policiesDer(STRICT, [cpsQ(u)]))),
          "lint/cabf-smime/policies-cps-not-http-url");
      }));
  // Permitting a reg-name's own bytes is not the same as dropping the authority's structure. RFC
  // 7230 sec. 2.7.1 forbids an empty host, RFC 3986 sec. 3.2.3 writes the port as digits, and
  // sec. 3.2.2 writes a bracketed host as an IPv6 or IPvFuture literal.
  check("S31f. a malformed authority is still reported",
    ["http://@", "http://:80", "http://[bad]", "https://cps.example:abc", "http://[2001:db8::1/"]
      .every(function (u) {
        return has(lint(splice(baseForQualifiers, policiesDer(STRICT, [cpsQ(u)]))),
          "lint/cabf-smime/policies-cps-not-http-url");
      }));
  check("S32. an id-qt-unotice qualifier carrying no explicitText is reported",
    has(lint(splice(await sign({}), policiesDer(STRICT, [noticeQ(b.sequence([]))]))),
      "lint/cabf-smime/policies-unotice-no-explicit-text"));
  check("S33. an id-qt-unotice qualifier carrying a noticeRef is reported",
    has(lint(splice(await sign({}), policiesDer(STRICT, [noticeQ(b.sequence([
      b.sequence([b.utf8("Org"), b.sequence([b.integer(1n)])]), b.utf8("text")]))]))),
      "lint/cabf-smime/policies-unotice-notice-ref"));

  // (b) "This extension SHOULD NOT be marked critical."
  check("S34. cRLDistributionPoints SHOULD NOT be critical",
    has(await recritical("cRLDistributionPoints", true), "lint/cabf-smime/crldp-critical") &&
    !has(baseline, "lint/cabf-smime/crldp-critical"));

  // (c) "SHOULD be present", "SHOULD contain at least one accessMethod value of type
  // id-ad-caIssuers", and the same generation-dependent URI scheme table clause (b) carries.
  check("S35. authorityInformationAccess SHOULD be present",
    has(await lintOver({ authorityInfoAccess: undefined }), "lint/cabf-smime/aia-missing") &&
    !has(baseline, "lint/cabf-smime/aia-missing"));
  check("S36. under Strict every accessMethod URI must be HTTP",
    has(await lintOver({ authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } },
      { accessMethod: "caIssuers", accessLocation: { uniformResourceIdentifier: "ldap://i.example" } }] }),
      "lint/cabf-smime/aia-non-http-uri"));
  // Clause (c) gives id-ad-ocsp and id-ad-caIssuers a table EACH, unlike clause (b) whose single
  // table reads "at least one distributionPoint" for the whole extension. So "at least one" under
  // Legacy is per accessMethod, and an HTTP URI on one method does not answer for the other.
  check("S36b. ...and under Legacy at least one suffices for each method, where others sit beside it",
    !has(await lintOver({ certificatePolicies: [{ oid: LEGACY }], authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } },
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "ldap://ocsp.example" } },
      { accessMethod: "caIssuers", accessLocation: { uniformResourceIdentifier: "http://i.example/ca.cer" } }] }),
      "lint/cabf-smime/aia-non-http-uri"));
  check("S36c. ...but a Legacy certificate whose only accessMethod URI is not HTTP is reported",
    has(await lintOver({ certificatePolicies: [{ oid: LEGACY }], authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "ldap://ocsp.example" } }] }),
      "lint/cabf-smime/aia-non-http-uri"));
  check("S36d. ...and an HTTP URI on one accessMethod does not answer for the other's table",
    has(await lintOver({ certificatePolicies: [{ oid: LEGACY }], authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } },
      { accessMethod: "caIssuers", accessLocation: { uniformResourceIdentifier: "ldap://i.example" } }] }),
      "lint/cabf-smime/aia-non-http-uri"));
  // An accessLocation that is not a uniformResourceIdentifier carries no scheme at all, so the
  // method it belongs to still has no HTTP URI and the table is still unmet.
  check("S36e. an accessLocation that is not a URI is reported, not passed over",
    has(await lintOver({ authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } },
      { accessMethod: "caIssuers", accessLocation: { dNSName: "i.example" } }] }),
      "lint/cabf-smime/aia-non-http-uri"));
  check("S36f. ...under Legacy too, where that method carries nothing else",
    has(await lintOver({ certificatePolicies: [{ oid: LEGACY }], authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } },
      { accessMethod: "caIssuers", accessLocation: { dNSName: "i.example" } }] }),
      "lint/cabf-smime/aia-non-http-uri"));
  check("S37. authorityInformationAccess SHOULD carry an id-ad-caIssuers accessMethod",
    has(await lintOver({ authorityInfoAccess: [
      { accessMethod: "ocsp", accessLocation: { uniformResourceIdentifier: "http://ocsp.example" } }] }),
      "lint/cabf-smime/aia-ca-issuers-missing") &&
    !has(baseline, "lint/cabf-smime/aia-ca-issuers-missing"));

  // (e) "This extension SHOULD be marked critical."
  check("S38. keyUsage SHOULD be critical",
    has(await recritical("keyUsage", false), "lint/cabf-smime/key-usage-not-critical") &&
    !has(baseline, "lint/cabf-smime/key-usage-not-critical"));

  // (g) "The keyIdentifier field SHALL be present. authorityCertIssuer and
  // authorityCertSerialNumber fields SHALL NOT be present."
  var akiIssuerSerial = b.sequence([
    b.contextConstructed(1, b.contextPrimitive(2, Buffer.from("ca.example", "latin1"))),
    b.contextPrimitive(2, Buffer.from([0x01]))]);
  check("S39. an authorityKeyIdentifier carrying no keyIdentifier is reported",
    has(lint(splice(await sign({}), extDer("authorityKeyIdentifier", false, akiIssuerSerial))),
      "lint/cabf-smime/aki-key-identifier-missing") &&
    !has(baseline, "lint/cabf-smime/aki-key-identifier-missing"));
  check("S40. an authorityCertIssuer or authorityCertSerialNumber field is reported",
    has(lint(splice(await sign({}), extDer("authorityKeyIdentifier", false, akiIssuerSerial))),
      "lint/cabf-smime/aki-issuer-or-serial-present") &&
    !has(baseline, "lint/cabf-smime/aki-issuer-or-serial-present"));

  // (h) "SHALL be present", and "SHOULD NOT be marked critical unless the subject field is an
  // empty sequence", which is the one condition that lifts it.
  check("S41. subjectAltName SHALL be present",
    has(await lintOver({ subjectAltName: undefined }), "lint/cabf-smime/san-missing") &&
    !has(baseline, "lint/cabf-smime/san-missing"));
  check("S42. a critical subjectAltName beside a non-empty subject is reported",
    has(await recritical("subjectAltName", true), "lint/cabf-smime/san-critical"));
  check("S42b. CONTROL: an empty subject lifts it",
    !has(lint(splice(await sign({}, undefined, []),
      extDer("subjectAltName", true, b.sequence([b.contextPrimitive(1, Buffer.from("a@example.com", "latin1"))])))),
      "lint/cabf-smime/san-critical"));

  // (j) Legacy: "MAY be present and SHALL NOT be marked critical."
  var sdaCritical = extDer("subjectDirectoryAttributes", true,
    b.sequence([b.sequence([b.oid(pki.oid.byName("countryName")), b.set([b.printable("US")])])]));
  check("S43. under Legacy subjectDirectoryAttributes SHALL NOT be critical",
    has(lint(splice(await sign({ certificatePolicies: [{ oid: LEGACY }] }), sdaCritical)),
      "lint/cabf-smime/subject-directory-attributes-critical"));
  // The criticality sentence sits in the Legacy cell. The Strict and Multipurpose cell reads
  // "Prohibited" and carries no such sentence, so a critical extension there is one violation of
  // one clause, not two.
  check("S43b. under Strict the same extension draws the prohibition alone",
    has(lint(splice(await sign({}), sdaCritical)), "lint/cabf-smime/subject-directory-attributes-prohibited") &&
    !has(lint(splice(await sign({}), sdaCritical)), "lint/cabf-smime/subject-directory-attributes-critical"));

  // (k) "MAY be present and SHALL NOT be marked critical."
  var qcDer = b.sequence([b.sequence([b.oid(pki.oid.byName("qcStatements"))])]);
  check("S44. qcStatements SHALL NOT be critical",
    has(lint(splice(await sign({}), extDer("qcStatements", true, qcDer))),
      "lint/cabf-smime/qc-statements-critical") &&
    !has(lint(splice(await sign({}), extDer("qcStatements", false, qcDer))),
      "lint/cabf-smime/qc-statements-critical"));

  // (l) The LEI table is keyed on the certificate TYPE rather than the generation: prohibited for
  // Mailbox-validated and Individual-validated, and the role identifier prohibited for
  // Organization-validated.
  var ORG_STRICT = pki.oid.byName("smime-organization-strict");
  var SPONSOR_STRICT = pki.oid.byName("smime-sponsor-strict");
  var leiDer = extDer("lei-identifier", false, b.printable("5493001KJTIIGC8Y1R12"));
  var roleDer = extDer("lei-role", false, b.printable("5493001KJTIIGC8Y1R12"));
  check("S45. a Legal Entity Identifier is prohibited on a Mailbox-validated certificate",
    has(lint(splice(await sign({}), leiDer)), "lint/cabf-smime/lei-prohibited"));
  check("S45b. ...and on an Individual-validated one",
    has(lint(splice(await sign({ certificatePolicies: [{ oid: pki.oid.byName("smime-individual-strict") }] }), leiDer)),
      "lint/cabf-smime/lei-prohibited"));
  check("S45c. CONTROL: an Organization-validated certificate may carry one",
    !has(lint(splice(await sign({ certificatePolicies: [{ oid: ORG_STRICT }] }), leiDer)),
      "lint/cabf-smime/lei-prohibited"));
  check("S46. the role identifier is prohibited on an Organization-validated certificate",
    has(lint(splice(await sign({ certificatePolicies: [{ oid: ORG_STRICT }] }), roleDer)),
      "lint/cabf-smime/lei-prohibited") &&
    !has(lint(splice(await sign({ certificatePolicies: [{ oid: SPONSOR_STRICT }] }), roleDer)),
      "lint/cabf-smime/lei-prohibited"));
  check("S47. where it is permitted it SHALL NOT be critical",
    has(lint(splice(await sign({ certificatePolicies: [{ oid: ORG_STRICT }] }),
      extDer("lei-identifier", true, b.printable("5493001KJTIIGC8Y1R12")))),
      "lint/cabf-smime/lei-critical"));
  // "Prohibited" is the whole of the Mailbox-validated and Individual-validated cells, and the
  // criticality sentence belongs to the cells that admit the extension.
  var leiCritical = extDer("lei-identifier", true, b.printable("5493001KJTIIGC8Y1R12"));
  check("S47b. where it is prohibited the prohibition is the only finding",
    has(lint(splice(await sign({}), leiCritical)), "lint/cabf-smime/lei-prohibited") &&
    !has(lint(splice(await sign({}), leiCritical)), "lint/cabf-smime/lei-critical"));
  check("S47c. ...and the role identifier is the same on an Organization-validated certificate",
    has(lint(splice(await sign({ certificatePolicies: [{ oid: ORG_STRICT }] }),
      extDer("lei-role", true, b.printable("5493001KJTIIGC8Y1R12")))), "lint/cabf-smime/lei-prohibited") &&
    !has(lint(splice(await sign({ certificatePolicies: [{ oid: ORG_STRICT }] }),
      extDer("lei-role", true, b.printable("5493001KJTIIGC8Y1R12")))), "lint/cabf-smime/lei-critical"));

  // (m) Strict: "Prohibited." Multipurpose and Legacy: "MAY be present and SHALL NOT be marked
  // critical."
  var adobeDer = extDer("adobe-timestamp", false, b.sequence([]));
  check("S48. an Adobe extension is prohibited under Strict and permitted under Legacy",
    has(lint(splice(await sign({}), adobeDer)), "lint/cabf-smime/adobe-extension-prohibited") &&
    !has(lint(splice(await sign({ certificatePolicies: [{ oid: LEGACY }] }), adobeDer)),
      "lint/cabf-smime/adobe-extension-prohibited"));
  check("S48b. the second Adobe extension is measured too",
    has(lint(splice(await sign({}), extDer("adobe-archive-rev-info", false, b.sequence([])))),
      "lint/cabf-smime/adobe-extension-prohibited"));
  check("S49. where it is permitted it SHALL NOT be critical",
    has(lint(splice(await sign({ certificatePolicies: [{ oid: LEGACY }] }),
      extDer("adobe-timestamp", true, b.sequence([])))), "lint/cabf-smime/adobe-extension-critical"));
  var adobeCritical = extDer("adobe-timestamp", true, b.sequence([]));
  check("S49b. under Strict the prohibition is the only finding",
    has(lint(splice(await sign({}), adobeCritical)), "lint/cabf-smime/adobe-extension-prohibited") &&
    !has(lint(splice(await sign({}), adobeCritical)), "lint/cabf-smime/adobe-extension-critical"));
  // A certificate declaring no generation names no cell, and every table in the section is read
  // against Strict for it, which is the narrowest of the three.
  check("S49c. a certificate declaring no generation is held to the Strict cell",
    has(lint(splice(await sign({ certificatePolicies: undefined }), adobeDer)),
      "lint/cabf-smime/adobe-extension-prohibited"));
  check("S49d. ...on every table the section keys on the generation, not just this one",
    has(await lintOver({ certificatePolicies: undefined,
      extendedKeyUsage: ["emailProtection", "clientAuth"] }), "lint/cabf-smime/eku-extra-purpose-strict") &&
    has(lint(splice(await sign({ certificatePolicies: undefined }), sdaDer)),
      "lint/cabf-smime/subject-directory-attributes-prohibited"));

  // (e) again, the two halves of the table the forbidden-bit row does not answer for. The RSA
  // column is the one cell that differs by generation: "For key management only, bit positions
  // SHALL be set for keyEncipherment and MAY be set for dataEncipherment" under Multipurpose and
  // Legacy, where the Strict cell names keyEncipherment alone.
  check("S51. dataEncipherment is reported on a Strict RSA certificate",
    has(await lintOver({ keyUsage: ["digitalSignature", "keyEncipherment", "dataEncipherment"] }, rsaPub),
      "lint/cabf-smime/key-usage-forbidden-bit"));
  check("S51b. CONTROL: the Multipurpose and Legacy cells admit it",
    !has(await lintOver({ certificatePolicies: [{ oid: MULTI }],
      keyUsage: ["digitalSignature", "keyEncipherment", "dataEncipherment"] }, rsaPub),
      "lint/cabf-smime/key-usage-forbidden-bit") &&
    !has(await lintOver({ certificatePolicies: [{ oid: LEGACY }],
      keyUsage: ["digitalSignature", "keyEncipherment", "dataEncipherment"] }, rsaPub),
      "lint/cabf-smime/key-usage-forbidden-bit"));
  // A cell is a set of MODES, not a set of bits: every mode fixes bits with SHALL and admits
  // others with MAY, so bits that each appear somewhere in the cell can still combine into no
  // mode. nonRepudiation is a MAY in every mode that names it, which makes it the bit that tells a
  // flat permitted-set reading from a mode reading.
  check("S52. a certificate setting only a MAY bit matches no mode of its cell",
    has(await lintOver({ keyUsage: ["nonRepudiation"] }), "lint/cabf-smime/key-usage-matches-no-mode") &&
    has(await lintOver({ keyUsage: ["nonRepudiation"] }, rsaPub), "lint/cabf-smime/key-usage-matches-no-mode") &&
    has(await lintOver({ keyUsage: ["nonRepudiation"] }, ecPub), "lint/cabf-smime/key-usage-matches-no-mode"));
  check("S52b. CONTROL: each column's key-management mode is satisfied by its own bit",
    !has(await lintOver({ keyUsage: ["digitalSignature"] }), "lint/cabf-smime/key-usage-matches-no-mode") &&
    !has(await lintOver({ keyUsage: ["keyEncipherment"] }, rsaPub), "lint/cabf-smime/key-usage-matches-no-mode") &&
    !has(await lintOver({ keyUsage: ["keyAgreement"] }, ecPub), "lint/cabf-smime/key-usage-matches-no-mode"));
  // dataEncipherment is admitted by the Multipurpose and Legacy key-management modes, and both of
  // those require keyEncipherment, so it never rides beside digitalSignature alone. Each bit here
  // is one the cell names, which is what a flat reading of the cell cannot tell apart.
  check("S52c. bits the cell names can still combine into no mode",
    has(await lintOver({ certificatePolicies: [{ oid: MULTI }],
      keyUsage: ["digitalSignature", "dataEncipherment"] }, rsaPub),
      "lint/cabf-smime/key-usage-matches-no-mode") &&
    !has(await lintOver({ certificatePolicies: [{ oid: MULTI }],
      keyUsage: ["digitalSignature", "dataEncipherment"] }, rsaPub),
      "lint/cabf-smime/key-usage-forbidden-bit"));
  check("S52d. CONTROL: the dual-use mode admits it beside keyEncipherment",
    !has(await lintOver({ certificatePolicies: [{ oid: MULTI }],
      keyUsage: ["digitalSignature", "keyEncipherment", "dataEncipherment"] }, rsaPub),
      "lint/cabf-smime/key-usage-matches-no-mode"));
  // "MAY be set for encipherOnly or decipherOnly (only if keyAgreement is set)", which the cell
  // states by naming them only in the modes that require keyAgreement.
  var kuEncipherOnly = extDer("keyUsage", true, b.bitString(Buffer.from([0x81]), 0));
  check("S53. an elliptic-curve encipherOnly without keyAgreement matches no mode",
    has(lint(splice(await sign({}, ecPub), kuEncipherOnly)),
      "lint/cabf-smime/key-usage-matches-no-mode"));
  check("S53b. CONTROL: with keyAgreement set it is admitted",
    !has(await lintOver({ keyUsage: ["digitalSignature", "keyAgreement", "encipherOnly"] }, ecPub),
      "lint/cabf-smime/key-usage-matches-no-mode"));

  // (n) "SHOULD be present."
  check("S50. subjectKeyIdentifier SHOULD be present",
    has(await lintOver({ subjectKeyIdentifier: false }), "lint/cabf-smime/ski-missing") &&
    !has(baseline, "lint/cabf-smime/ski-missing"));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
