// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the ETSI qualified-certificate profile in pki.lint.certificate. RED conformance
 * vectors written BEFORE the rules, each driving the shipped verb and asserting the finding id.
 *
 * Every row is derived from ETSI EN 319 412-5 V2.4.1 and EN 319 412-1 V1.5.1, read from the
 * documents. The profile has two scopes inside it: clause 4 governs any certificate carrying a
 * qcStatements extension, and clause 5 governs an EU qualified one, which Table 1A defines from
 * the bytes as QcCompliance present with QcCClegislation absent.
 *
 *   Q1-Q2    detection and the extension's own criticality (QCS-4.1-02)
 *   Q3-Q4    QcType, one purpose and one only (4.2.3)
 *   Q5-Q7    QcPDS (QCS-4.3.4-03 and the clause 5 additions)
 *   Q8-Q13   the semantics identifiers of EN 319 412-1 sec. 5.1.3 and 5.1.4
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

var NB = new Date("2026-04-01T00:00:00Z");
var NA = new Date("2026-06-01T00:00:00Z");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function sevOf(rep, id) {
  var f = rep.findings.filter(function (x) { return x.id === id; })[0];
  return f && f.severity;
}
function lint(der, opts) { return pki.lint.certificate(der, opts || { profile: "etsi-qc" }); }

async function run() {
  var ed = await pki.key.generate("Ed25519");
  var edPriv = await pki.key.export(ed.privateKey), edPub = await pki.key.export(ed.publicKey);

  var EU_PDS = { statementId: "qcPDS", info: { locations: [{ url: "https://pds.example/en", language: "en" }] } };

  function sign(statements, subject) {
    return pki.x509.sign({ subject: subject || [{ commonName: "A Subject" }], subjectPublicKey: edPub,
      notBefore: NB, notAfter: NA,
      extensions: statements === null ? {} : { qcStatements: statements } }, { key: edPriv });
  }
  async function lintQc(statements, subject) { return lint(await sign(statements, subject)); }

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
  function semantics(id, nras) {
    var info = { semanticsIdentifier: id };
    if (nras) info.nameRegistrationAuthorities = nras;
    return { statementId: "qcsPkixQCSyntaxV2", info: info };
  }

  // ---- Q1-Q2: detection and the extension's own criticality ---------------------------------
  var euBase = await lintQc([{ statementId: "qcCompliance" }, EU_PDS]);
  var euErrors = euBase.findings.filter(function (f) {
    return f.source === "etsi-qc" && (f.severity === "error" || f.severity === "fatal");
  });
  check("Q1. CONTROL: a conforming EU qualified certificate reports nothing at error or worse (" +
    euErrors.map(function (f) { return f.id; }).join(",") + ")", euErrors.length === 0);
  check("Q1b. a certificate carrying no qcStatements extension is left alone",
    pki.lint.certificate(await sign(null)).ran.every(function (id) { return id.indexOf("lint/etsi-qc/") !== 0; }));
  check("Q1c. ...and one carrying the extension is read unprompted",
    pki.lint.certificate(await sign([{ statementId: "qcCompliance" }, EU_PDS]))
      .ran.some(function (id) { return id.indexOf("lint/etsi-qc/") === 0; }));
  // QCS-4.1-02: "The qcStatements extension shall not be marked as critical." The builder writes it
  // non-critical, which is the builder doing its job, so the critical form is spliced.
  var qcDer = b.sequence([b.sequence([b.oid(pki.oid.byName("qcCompliance"))])]);
  check("Q2. the qcStatements extension must not be marked critical",
    has(lint(splice(await sign([{ statementId: "qcCompliance" }, EU_PDS]),
      extDer("qcStatements", true, qcDer))), "lint/etsi-qc/qc-statements-critical") &&
    !has(euBase, "lint/etsi-qc/qc-statements-critical"));

  // ---- Q3-Q4: QcType names one purpose and one only ------------------------------------------
  // Clause 4.2.3: "issued as one and only one of the purposes of electronic signature, electronic
  // seal or web site authentication".
  check("Q3. a QcType naming two of the three purposes is reported",
    has(await lintQc([{ statementId: "qcCompliance" }, EU_PDS,
      { statementId: "qcType", info: { types: ["qctEsign", "qctEseal"] } }]),
      "lint/etsi-qc/qc-type-multiple-purposes"));
  var onePurpose = [];
  for (var qi = 0; qi < 3; qi++) {
    var t = ["qctEsign", "qctEseal", "qctWeb"][qi];
    onePurpose.push(!has(await lintQc([{ statementId: "qcCompliance" }, EU_PDS,
      { statementId: "qcType", info: { types: [t] } }]), "lint/etsi-qc/qc-type-multiple-purposes"));
  }
  check("Q3b. CONTROL: each of the three alone is conformant", onePurpose.every(function (o) { return o === true; }));
  // The ASN.1 carries an extension marker (esign | eseal | web, ...), so a purpose outside the
  // three is admitted and the row counts only the three the clause names.
  check("Q4. CONTROL: an identifier outside the three is not one of the purposes and is not counted",
    !has(await lintQc([{ statementId: "qcCompliance" }, EU_PDS,
      { statementId: "qcType", info: { types: ["qctEsign", "qcCompliance"] } }]),
      "lint/etsi-qc/qc-type-multiple-purposes"));

  // ---- Q5-Q7: QcPDS ---------------------------------------------------------------------------
  // QCS-4.3.4-03: "As a minimum, a URL to a PDS provided in this statement shall use the https
  // scheme", which is the at-least-one reading, so one https URL among others satisfies it.
  check("Q5. a QcPDS carrying no https URL is reported",
    has(await lintQc([{ statementId: "qcCompliance" },
      { statementId: "qcPDS", info: { locations: [{ url: "http://pds.example/en", language: "en" }] } }]),
      "lint/etsi-qc/qc-pds-no-https-url"));
  check("Q5b. CONTROL: one https URL beside a plain one satisfies it",
    !has(await lintQc([{ statementId: "qcCompliance" },
      { statementId: "qcPDS", info: { locations: [{ url: "http://pds.example/de", language: "de" },
        { url: "https://pds.example/en", language: "en" }] } }]), "lint/etsi-qc/qc-pds-no-https-url"));
  // Table 2, on esi4-qcStatement-5, scoped by QCS-5-01 to an EU qualified certificate:
  // "a) it shall provide at least one URL to a PDS in English".
  check("Q6. an EU qualified certificate whose QcPDS names no English document is reported",
    has(await lintQc([{ statementId: "qcCompliance" },
      { statementId: "qcPDS", info: { locations: [{ url: "https://pds.example/de", language: "de" }] } }]),
      "lint/etsi-qc/qc-pds-no-english"));
  // Table 1A: with QcCClegislation present the certificate claims a named non-EU framework, so
  // clause 5 does not bind it.
  check("Q6b. CONTROL: a certificate naming its own legislation is not held to clause 5",
    !has(await lintQc([{ statementId: "qcCompliance" },
      { statementId: "qcCClegislation", info: { countries: ["CH"] } },
      { statementId: "qcPDS", info: { locations: [{ url: "https://pds.example/de", language: "de" }] } }]),
      "lint/etsi-qc/qc-pds-no-english"));
  // "b) it shall not reference more than one PDS per language."
  check("Q7. two PDS documents in one language are reported",
    has(await lintQc([{ statementId: "qcCompliance" },
      { statementId: "qcPDS", info: { locations: [{ url: "https://pds.example/en", language: "en" },
        { url: "https://pds.example/en2", language: "en" }] } }]),
      "lint/etsi-qc/qc-pds-duplicate-language") &&
    !has(euBase, "lint/etsi-qc/qc-pds-duplicate-language"));

  // ---- Q8-Q13: the semantics identifiers of EN 319 412-1 --------------------------------------
  // NAT-5.1.3-02: with the natural person semantics identifier, a present subject serialNumber is
  // "3 character natural person identity type reference; 2 character ISO 3166-1 country code;
  // hyphen-minus; and identifier".
  var NAT = "semanticsId-Natural", LEG = "semanticsId-Legal";
  function natCert(serial, nras) {
    return lintQc([{ statementId: "qcCompliance" }, EU_PDS, semantics(NAT, nras)],
      [{ commonName: "A Person" }, { serialNumber: serial }]);
  }
  function legCert(orgId, nras) {
    return lintQc([{ statementId: "qcCompliance" }, EU_PDS, semantics(LEG, nras)],
      [{ commonName: "A Company" }, { organizationIdentifier: orgId }]);
  }
  var natGood = [];
  for (var ni = 0; ni < 5; ni++) {
    var ref = ["PAS", "IDC", "PNO", "TAX", "TIN"][ni];
    natGood.push(!has(await natCert(ref + "SK-P3000180"),
      "lint/etsi-qc/qc-natural-serial-number-structure"));
  }
  check("Q8. CONTROL: each identity type reference the clause defines is accepted (" + natGood.join(",") + ")",
    natGood.every(function (g) { return g === true; }));
  var natBad = [];
  for (var nb = 0; nb < 5; nb++) {
    var badVal = ["XXXSK-1", "PASS-1", "PASSKK1", "PAS", "PASSK1"][nb];
    natBad.push(has(await natCert(badVal), "lint/etsi-qc/qc-natural-serial-number-structure"));
  }
  check("Q9. a serialNumber outside that structure is reported (" + natBad.join(",") + ")",
    natBad.every(function (x) { return x === true; }));
  // LEG-5.1.4-03: VAT, NTR, PSD, LEI, or two characters and a colon.
  var legGood = [];
  for (var li = 0; li < 3; li++) {
    var lref = ["VAT", "NTR", "PSD"][li];
    legGood.push(!has(await legCert(lref + "BE-0876866142"),
      "lint/etsi-qc/qc-legal-organization-identifier-structure"));
  }
  check("Q10. CONTROL: each legal person identity type reference is accepted (" + legGood.join(",") + ")",
    legGood.every(function (g) { return g === true; }) &&
    has(await legCert("XXXBE-1"), "lint/etsi-qc/qc-legal-organization-identifier-structure"));
  // LEG-5.1.4-03 (4): "LEI ... The 2 character ISO 3166-1 country code shall be set to 'XG'."
  check("Q11. an LEI identifier whose country code is not XG is reported",
    has(await legCert("LEIBE-5493001KJTIIGC8Y1R12"), "lint/etsi-qc/qc-legal-lei-country-not-xg") &&
    !has(await legCert("LEIXG-5493001KJTIIGC8Y1R12"), "lint/etsi-qc/qc-legal-lei-country-not-xg"));
  // NAT-5.1.3-04: "The value 'TAX' is deprecated. The value 'TIN' should be used instead."
  check("Q12. TAX is reported at warn, and TIN is not reported",
    has(await natCert("TAXSK-1"), "lint/etsi-qc/qc-natural-identity-type-deprecated") &&
    sevOf(await natCert("TAXSK-1"), "lint/etsi-qc/qc-natural-identity-type-deprecated") === "warn" &&
    !has(await natCert("TINSK-1"), "lint/etsi-qc/qc-natural-identity-type-deprecated"));
  // NAT-5.1.3-05 and LEG-5.1.4-05: a locally defined reference is two characters and a colon, which
  // makes the reference FOUR characters, and it requires nameRegistrationAuthorities.
  check("Q13. a locally defined identity type reference requires a name registration authority",
    has(await natCert("EI:SE-200007292386"),
      "lint/etsi-qc/qc-semantics-registration-authority-missing") &&
    !has(await natCert("EI:SE-200007292386", [{ uniformResourceIdentifier: "https://ra.example" }]),
      "lint/etsi-qc/qc-semantics-registration-authority-missing") &&
    !has(await natCert("EI:SE-200007292386", [{ uniformResourceIdentifier: "https://ra.example" }]),
      "lint/etsi-qc/qc-natural-serial-number-structure"));
  // NAT-5.1.3-06: it "shall contain at least a uniformResourceIdentifier generalName".
  check("Q13b. ...and that authority must carry a uniformResourceIdentifier",
    has(await natCert("EI:SE-200007292386", [{ dNSName: "ra.example" }]),
      "lint/etsi-qc/qc-semantics-registration-authority-not-uri") &&
    !has(await natCert("EI:SE-200007292386", [{ uniformResourceIdentifier: "https://ra.example" }]),
      "lint/etsi-qc/qc-semantics-registration-authority-not-uri"));
  check("Q13c. ...and the same holds for the legal person identifier",
    has(await legCert("EI:SE-5567971433"),
      "lint/etsi-qc/qc-semantics-registration-authority-missing") &&
    !has(await legCert("EI:SE-5567971433", [{ uniformResourceIdentifier: "https://ra.example" }]),
      "lint/etsi-qc/qc-legal-organization-identifier-structure"));
  // Both rules are conditioned on the semantics identifier being present: without one, the subject
  // attribute is not read.
  // Every requirement of sec. 5.1.3 and 5.1.4 sits under its own semantics identifier, so a
  // certificate naming a private one is held to none of them.
  var privateSemantics = await lintQc([{ statementId: "qcCompliance" }, EU_PDS,
    { statementId: "qcsPkixQCSyntaxV2", info: { semanticsIdentifier: "1.3.6.1.4.1.99999.4",
      nameRegistrationAuthorities: [{ dNSName: "ra.example" }] } }],
    [{ commonName: "A Person" }, { serialNumber: "not-a-structure" }]);
  check("Q13e. CONTROL: a private semantics identifier is held to neither clause (" +
    ids(privateSemantics).join(",") + ")",
    privateSemantics.findings.every(function (f) { return f.source !== "etsi-qc"; }));
  // LEG-5.1.4-05 states the URI requirement inside the sentence about a locally defined reference,
  // where NAT-5.1.3-06 states it of the element itself, so the two clauses bind differently.
  check("Q13f. a legal person identifier requires the URI only where the reference is locally defined",
    !has(await legCert("VATBE-0876866142", [{ dNSName: "ra.example" }]),
      "lint/etsi-qc/qc-semantics-registration-authority-not-uri") &&
    has(await legCert("EI:SE-5567971433", [{ dNSName: "ra.example" }]),
      "lint/etsi-qc/qc-semantics-registration-authority-not-uri"));
  check("Q13d. CONTROL: without a semantics identifier neither attribute is read",
    !has(await lintQc([{ statementId: "qcCompliance" }, EU_PDS],
      [{ commonName: "A Person" }, { serialNumber: "not-a-structure" }]),
      "lint/etsi-qc/qc-natural-serial-number-structure"));

  // ---- Q14-Q15: a statement is not hidden by one that comes before it ------------------------
  // RFC 3739 sec. 3.2.6 puts no cardinality on QCStatements, so a certificate may carry two of a
  // kind, and reading only the first would let their order in the extension suppress a rule.
  check("Q14. a second QcPDS is read, not hidden by the first",
    has(await lintQc([{ statementId: "qcCompliance" }, EU_PDS,
      { statementId: "qcPDS", info: { locations: [{ url: "http://pds.example/fr", language: "fr" }] } }]),
      "lint/etsi-qc/qc-pds-no-https-url"));
  check("Q15. a second semantics statement is read, not hidden by a private one before it",
    has(await lintQc([{ statementId: "qcCompliance" }, EU_PDS,
      { statementId: "qcsPkixQCSyntaxV1", info: { semanticsIdentifier: "1.3.6.1.4.1.99999.4" } },
      semantics(NAT)], [{ commonName: "A Person" }, { serialNumber: "not-a-structure" }]),
      "lint/etsi-qc/qc-natural-serial-number-structure"));

  // Clause 4.2.3 limits the CERTIFICATE to one purpose, not each statement, so two statements
  // naming one purpose each are the same violation as one statement naming two.
  check("Q16. purposes are counted across the certificate, not within a statement",
    has(await lintQc([{ statementId: "qcCompliance" }, EU_PDS,
      { statementId: "qcType", info: { types: ["qctEsign"] } },
      { statementId: "qcType", info: { types: ["qctEseal"] } }]),
      "lint/etsi-qc/qc-type-multiple-purposes"));
  check("Q16b. CONTROL: two statements naming the same purpose are one purpose",
    !has(await lintQc([{ statementId: "qcCompliance" }, EU_PDS,
      { statementId: "qcType", info: { types: ["qctEsign"] } },
      { statementId: "qcType", info: { types: ["qctEsign"] } }]),
      "lint/etsi-qc/qc-type-multiple-purposes"));

  // The identifier resolves to its registered name the way QcType's and QcIdentMethod's values do.
  var semParsed = pki.schema.x509.parse(await sign([semantics(NAT)]));
  var semExt = semParsed.extensions.filter(function (e) { return e.name === "qcStatements"; })[0];
  var semInfo = pki.schema.x509.decodeExtension(semExt).decoded[0].info;
  check("Q17. a registered semantics identifier reads back with its name (" +
    semInfo.semanticsIdentifierName + ")",
    semInfo.semanticsIdentifier === pki.oid.byName("semanticsId-Natural") &&
    semInfo.semanticsIdentifierName === "semanticsId-Natural");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
