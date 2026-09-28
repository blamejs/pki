// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the CNSA 2.0 suite profile in pki.lint.certificate, pki.lint.crl and pki.lint.ocsp.
 * RED conformance vectors written BEFORE the rules, each driving the shipped verb.
 *
 * Every row is derived from `draft-jenkins-cnsa2-pkix-profile-05` (M. Jenkins, NSA-CCSS, 5 July 2026,
 * Informational, obsoletes RFC 8603 if approved), read from the draft text. The NSA notice lists
 * algorithms; the draft states what a certificate must carry, which is what a profile can read.
 * Like the root-program profiles, this one is NAMED and never detected: which policy a certificate is
 * held to is the caller's assertion.
 *
 *   K1-K3    named, never detected, enumerated under all three verbs, with conforming controls
 *   K4-K6    sec. 4 and 6, the suite itself, and the clauses the parser settles instead
 *   K7-K11   sec. 7.1, the self-signed CA scope
 *   K12-K14  sec. 7.2, the non-self-signed CA scope
 *   K15-K20  sec. 7.3, the end entity scope, whose key-usage set follows the subject key's kind
 *   K21-K22  sec. 8 and 9, the same signature rule over a CRL and an OCSP response
 */

var helpers = require("../helpers");
var surgery = require("../helpers/der-surgery");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2036-01-01T00:00:00Z");
var P = "lint/cnsa-2.0/";

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function sevOf(rep, id) {
  var f = rep.findings.filter(function (x) { return x.id === id; })[0];
  return f && f.severity;
}
function findingsOf(rep, id) { return rep.findings.filter(function (f) { return f.id === id; }); }
function cnsaIds(rep) {
  return ids(rep).filter(function (id) { return id.indexOf(P) === 0; });
}
function lint(der) { return pki.lint.certificate(der, { profile: "cnsa-2.0" }); }

async function run() {
  async function pair(spec) {
    var k = await pki.key.generate(spec);
    return { pub: await pki.key.export(k.publicKey), priv: await pki.key.export(k.privateKey) };
  }
  var mldsa = await pair("ML-DSA-87");
  var mlkem = await pair("ML-KEM-1024");
  var ed = await pair("Ed25519");

  /** A self-signed CA, which sec. 7.1 governs. */
  function root(ext, key) {
    var k = key || mldsa;
    return pki.x509.sign({ subject: [{ commonName: "A CNSA Root" }], subjectPublicKey: k.pub,
      notBefore: NB, notAfter: NA,
      extensions: Object.assign({ basicConstraints: { cA: true },
        keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true }, ext || {}) },
      { key: k.priv });
  }
  var issuer = { name: [{ commonName: "A CNSA Root" }], publicKey: mldsa.pub, key: mldsa.priv };
  /** A CA issued by another, which sec. 7.2 governs. */
  function subCa(ext) {
    return pki.x509.sign({ subject: [{ commonName: "A CNSA Intermediate" }],
      subjectPublicKey: mldsa.pub, notBefore: NB, notAfter: NA,
      extensions: Object.assign({ basicConstraints: { cA: true },
        keyUsage: ["keyCertSign", "cRLSign"], authorityKeyIdentifier: true }, ext || {}) }, issuer);
  }
  /** An end entity, which sec. 7.3 governs. `key` decides the kind its key declares. */
  function endEntity(ext, key) {
    var k = key || mldsa;
    return pki.x509.sign({ subject: [{ commonName: "A CNSA End Entity" }], subjectPublicKey: k.pub,
      notBefore: NB, notAfter: NA,
      extensions: Object.assign({ keyUsage: ["digitalSignature"], extendedKeyUsage: ["clientAuth"],
        authorityKeyIdentifier: true, subjectKeyIdentifier: true }, ext || {}) }, issuer);
  }

  // ---- K1-K3: named, enumerated, and three conforming controls --------------------------------
  var conformingRoot = await root();
  check("K1. the rows are inert unless the profile is named",
    cnsaIds(pki.lint.certificate(await root({ keyUsage: ["keyCertSign", "cRLSign", "keyEncipherment"] }))).length === 0 &&
    cnsaIds(pki.lint.certificate(conformingRoot, { profile: "rfc5280" })).length === 0);
  var certRows = pki.lint.rules("cnsa-2.0", "certificate").filter(function (r) { return r.source === "cnsa-2.0"; });
  check("K2. the profile is enumerated under each verb that runs it, and listed once",
    certRows.length >= 14 &&
    pki.lint.rules("cnsa-2.0", "crl").length === 1 &&
    pki.lint.rules("cnsa-2.0", "ocsp").length === 1 &&
    pki.lint.profiles().filter(function (n) { return n === "cnsa-2.0"; }).length === 1 &&
    certRows.every(function (r) { return r.citation.indexOf("draft-jenkins-cnsa2-pkix-profile-05") === 0; }));
  check("K3. a conforming self-signed CA, sub CA and end entity of each kind draw no finding",
    cnsaIds(lint(conformingRoot)).length === 0 &&
    cnsaIds(lint(await subCa())).length === 0 &&
    cnsaIds(lint(await endEntity())).length === 0 &&
    cnsaIds(lint(await endEntity({ keyUsage: ["keyEncipherment"] }, mlkem))).length === 0);

  // ---- K4-K6: sec. 4 and 6 --------------------------------------------------------------------
  // "Every CNSA Suite certificate MUST ... contain one of the following as its subject public key:
  // A ML-DSA-87 signature verification key. A ML-KEM-1024 public encapsulation key."
  check("K4. a subject key outside the suite is an error",
    sevOf(lint(await root({}, ed)), P + "spki-not-suite") === "error" &&
    !has(lint(conformingRoot), P + "spki-not-suite") &&
    !has(lint(await endEntity({ keyUsage: ["keyEncipherment"] }, mlkem)), P + "spki-not-suite"));
  // "The signature applied to all CNSA Suite certificates and CRLs MUST be made with a ML-DSA-87
  // signing key", which a HashML-DSA identifier is not either, so that sentence needs no second row.
  var signedByEd = await pki.x509.sign({ subject: [{ commonName: "A CNSA End Entity" }],
    subjectPublicKey: mldsa.pub, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["clientAuth"],
      authorityKeyIdentifier: true, subjectKeyIdentifier: true } },
    { name: [{ commonName: "A Classical Root" }], publicKey: ed.pub, key: ed.priv });
  check("K5. a signature that is not id-ml-dsa-87 is an error",
    sevOf(lint(signedByEd), P + "signature-not-ml-dsa-87") === "error" &&
    !has(lint(conformingRoot), P + "signature-not-ml-dsa-87"));
  // Sec. 6.3's version and sec. 6.1 / 6.4's absent parameters are settled by the parser, so an
  // operator sees its code rather than a row. Asserted against the code, because a certificate that
  // does not parse is silent about every row and asserting that silence would pass for any reason.
  var v1 = surgery.patch(conformingRoot, function (n) {
    if (n.tagClass !== "context" || n.tagNumber !== 0 || !n.constructed) return undefined;
    if (!n.children || n.children.length !== 1) return undefined;
    if (n.children[0].tagClass !== "universal" || n.children[0].tagNumber !== 2) return undefined;
    return b.explicit(0, b.integer(0n));
  });
  var mlOid = b.oid(pki.oid.byName("id-ml-dsa-87"));
  var withParams = surgery.patch(conformingRoot, function (n) {
    if (n.tagClass !== "universal" || n.tagNumber !== 16 || !n.children) return undefined;
    if (n.children.length !== 1 || !mlOid.equals(n.children[0].bytes)) return undefined;
    return b.sequence([b.raw(mlOid), b.nullValue()]);
  });
  function fatalCode(der) {
    var rep = lint(der);
    var f = rep.findings.filter(function (x) { return x.id === "lint/unparseable"; })[0];
    return f && f.context.code;
  }
  check("K6. the version and absent-parameters clauses reach an operator as the parser's verdict",
    fatalCode(v1) === "x509/bad-version" &&
    fatalCode(withParams) === "x509/bad-algorithm-parameters");
  // Sec. 6.1 names the inner `signature` field of a TBSCertificate and TBSCertList as well as the
  // outer `signatureAlgorithm`. Both parsers refuse an artifact whose two disagree, so the row reading
  // one answers for both, and this asserts that verdict rather than a second row reading the same OID.
  function innerSigRewritten(der) {
    var ml = b.oid(pki.oid.byName("id-ml-dsa-87")), ed = b.oid(pki.oid.byName("Ed25519"));
    var seen = 0;
    return surgery.patch(der, function (n) {
      if (n.tagClass !== "universal" || n.tagNumber !== 16 || !n.children || n.children.length !== 1) return undefined;
      if (!ml.equals(n.children[0].bytes)) return undefined;
      seen += 1;
      return seen === 1 ? b.sequence([b.raw(ed)]) : undefined;
    });
  }
  var crlForInner = await pki.crl.sign({ thisUpdate: new Date("2026-06-01T00:00:00Z"),
    nextUpdate: new Date("2026-07-01T00:00:00Z"), revoked: [], crlNumber: 1 },
    { cert: await root({ keyUsage: ["keyCertSign", "cRLSign", "digitalSignature"] }), key: mldsa.priv });
  function crlFatalCode(der) {
    var rep = pki.lint.crl(der, { profile: "cnsa-2.0" });
    var f = rep.findings.filter(function (x) { return x.id === "lint/unparseable"; })[0];
    return f && f.context.code;
  }
  check("K6b. an inner signature identifier that differs from the outer one is refused at parse",
    fatalCode(innerSigRewritten(conformingRoot)) === "x509/bad-signature-algorithm" &&
    crlFatalCode(innerSigRewritten(crlForInner)) === "crl/bad-signature-algorithm");

  // ---- K7-K11: sec. 7.1, the self-signed CA ---------------------------------------------------
  // The builder writes a subjectKeyIdentifier and an authorityKeyIdentifier whether or not the spec
  // asks for one, which is the builder holding itself to RFC 5280. A certificate that carries neither
  // is what an operator may be handed, so the fixtures for the missing-extension rows are built by
  // removing the extension from a signed certificate. The signature no longer verifies, which is not
  // what these rows read.
  /** Rebuild the tbsCertificate extensions without the named one. */
  function withoutExtension(der, extName) {
    var wanted = pki.oid.byName(extName);
    return surgery.patch(der, function (n) {
      if (n.tagClass !== "context" || n.tagNumber !== 3 || !n.constructed) return undefined;
      if (!n.children || n.children.length !== 1) return undefined;
      var list = n.children[0];
      if (list.tagClass !== "universal" || list.tagNumber !== 16 || !list.children) return undefined;
      var kept = list.children.filter(function (ext) {
        return !(ext.children && ext.children.length && b.oid(wanted).equals(ext.children[0].bytes));
      });
      if (kept.length === list.children.length) return undefined;
      return b.explicit(3, b.sequence(kept.map(function (e) { return b.raw(e.bytes); })));
    });
  }
  var noSki = withoutExtension(conformingRoot, "subjectKeyIdentifier");
  check("K7. a self-signed CA carrying no subjectKeyIdentifier is an error naming the extension",
    sevOf(lint(noSki), P + "self-signed-ca-missing-extension") === "error" &&
    findingsOf(lint(noSki), P + "self-signed-ca-missing-extension")[0].context.extension === "subjectKeyIdentifier");
  // A certificate carrying no basicConstraints is not a CA certificate to read, so it is graded
  // against sec. 7.3 instead. That is the scope the bytes settle, and the vector says so.
  var noBc = withoutExtension(conformingRoot, "basicConstraints");
  check("K8. one carrying no basicConstraints is read under the end entity section, not this one",
    !has(lint(noBc), P + "self-signed-ca-missing-extension") &&
    has(lint(noBc), P + "end-entity-missing-extension"));
  // "The keyUsage extension MUST be marked as critical."
  check("K9. a non-critical keyUsage is an error",
    sevOf(lint(await root({ keyUsageCritical: false })), P + "key-usage-not-critical") === "error" &&
    !has(lint(conformingRoot), P + "key-usage-not-critical"));
  // "The keyCertSign and cRLSign bits MUST be set. The digitalSignature and nonRepudiation bits MAY
  // be set. All other bits MUST NOT be set." Each departure is its own finding, so a certificate with
  // two of them shows both.
  var missingCrlSign = await root({ keyUsage: ["keyCertSign"] });
  var twoForbidden = await root({ keyUsage: ["keyCertSign", "cRLSign", "keyEncipherment", "keyAgreement"] });
  check("K10. each departure from the CA key-usage set is its own finding",
    findingsOf(lint(missingCrlSign), P + "ca-key-usage-bits").length === 1 &&
    findingsOf(lint(missingCrlSign), P + "ca-key-usage-bits")[0].context.bit === "cRLSign" &&
    findingsOf(lint(twoForbidden), P + "ca-key-usage-bits").length === 2 &&
    !has(lint(await root({ keyUsage: ["keyCertSign", "cRLSign", "digitalSignature", "nonRepudiation"] })),
      P + "ca-key-usage-bits"));
  // "the pathLenConstraint MUST NOT be present", for a self-signed CA alone: sec. 7.2 calls the same
  // field OPTIONAL, so the row must not reach a non-self-signed one.
  check("K11. a pathLenConstraint is an error on a self-signed CA and not on a sub CA",
    sevOf(lint(await root({ basicConstraints: { cA: true, pathLen: 0 } })), P + "self-signed-ca-path-len-present") === "error" &&
    !has(lint(await subCa({ basicConstraints: { cA: true, pathLen: 0 } })), P + "self-signed-ca-path-len-present") &&
    !has(lint(conformingRoot), P + "self-signed-ca-path-len-present"));

  // ---- K12-K14: sec. 7.2, the non-self-signed CA ----------------------------------------------
  var subNoAki = withoutExtension(await subCa(), "authorityKeyIdentifier");
  check("K12. a sub CA carrying no authorityKeyIdentifier is an error naming the extension",
    findingsOf(lint(subNoAki), P + "ca-missing-extension").length === 1 &&
    findingsOf(lint(subNoAki), P + "ca-missing-extension")[0].context.extension === "authorityKeyIdentifier" &&
    !has(lint(subNoAki), P + "self-signed-ca-missing-extension"));
  // "the basicConstraints extension MUST be marked as critical." The builder refuses to write one
  // non-critical, so the criticality boolean is removed from the encoded extension, whose DEFAULT is
  // FALSE.
  var bcOid = b.oid(pki.oid.byName("basicConstraints"));
  var bcNonCritical = surgery.patch(conformingRoot, function (n) {
    if (n.tagClass !== "universal" || n.tagNumber !== 16 || !n.children || n.children.length !== 3) return undefined;
    if (!bcOid.equals(n.children[0].bytes)) return undefined;
    return b.sequence([b.raw(n.children[0].bytes), b.raw(n.children[2].bytes)]);
  });
  check("K13. CONTROL: the rewritten certificate parses and its basicConstraints reads non-critical",
    !has(lint(bcNonCritical), "lint/unparseable") &&
    pki.schema.x509.parse(bcNonCritical).extensions.filter(function (e) {
      return e.oid === pki.oid.byName("basicConstraints");
    })[0].critical === false);
  check("K13b. a non-critical basicConstraints is an error on a CA certificate",
    sevOf(lint(bcNonCritical), P + "basic-constraints-not-critical") === "error" &&
    !has(lint(conformingRoot), P + "basic-constraints-not-critical"));
  // "If a policy is asserted, the certificatePolicies extension MUST be marked as non-critical ...
  // and SHOULD NOT use the policyQualifiers option." Sec. 7.1 says neither of a self-signed CA.
  var policy = [{ oid: "1.3.6.1.4.1.99999.1" }];
  check("K14. a critical certificatePolicies is an error, and a qualifier a warning",
    sevOf(lint(await subCa({ certificatePolicies: policy, certificatePoliciesCritical: true })),
      P + "certificate-policies-critical") === "error" &&
    sevOf(lint(await subCa({ certificatePolicies: [{ oid: "1.3.6.1.4.1.99999.1", cps: "https://cps.example/" }] })),
      P + "certificate-policies-qualifiers") === "warn" &&
    !has(lint(await subCa({ certificatePolicies: policy })), P + "certificate-policies-critical") &&
    !has(lint(await subCa({ certificatePolicies: policy })), P + "certificate-policies-qualifiers"));
  check("K14b. and neither reaches a self-signed CA, which sec. 7.1 does not govern for policies",
    !has(lint(await root({ certificatePolicies: policy, certificatePoliciesCritical: true })),
      P + "certificate-policies-critical"));

  // ---- K15-K20: sec. 7.3, the end entity -------------------------------------------------------
  var eeNoAki = withoutExtension(await endEntity(), "authorityKeyIdentifier");
  check("K15. an end entity carrying no authorityKeyIdentifier is an error naming the extension",
    findingsOf(lint(eeNoAki), P + "end-entity-missing-extension").length === 1 &&
    findingsOf(lint(eeNoAki), P + "end-entity-missing-extension")[0].context.extension === "authorityKeyIdentifier");
  // "End-entity certificates SHOULD contain the subjectKeyIdentifier extension", a recommendation.
  var eeNoSki = withoutExtension(await endEntity(), "subjectKeyIdentifier");
  check("K16. an end entity carrying no subjectKeyIdentifier is a warning",
    sevOf(lint(eeNoSki), P + "end-entity-no-subject-key-identifier") === "warn" &&
    !has(lint(await endEntity()), P + "end-entity-no-subject-key-identifier"));
  // The key-usage set follows the KIND the subject key declares, which is the whole reason the two
  // sentences of sec. 7.3 can be read from the bytes at all.
  check("K17. a signature certificate's set is digitalSignature, with nonRepudiation permitted",
    !has(lint(await endEntity({ keyUsage: ["digitalSignature", "nonRepudiation"] })), P + "end-entity-key-usage-bits") &&
    findingsOf(lint(await endEntity({ keyUsage: ["keyEncipherment"] })), P + "end-entity-key-usage-bits").length === 2);
  check("K18. a key establishment certificate's set is keyEncipherment alone",
    !has(lint(await endEntity({ keyUsage: ["keyEncipherment"] }, mlkem)), P + "end-entity-key-usage-bits") &&
    findingsOf(lint(await endEntity({ keyUsage: ["keyEncipherment", "nonRepudiation"] }, mlkem)),
      P + "end-entity-key-usage-bits").length === 1 &&
    findingsOf(lint(await endEntity({ keyUsage: ["digitalSignature"] }, mlkem)),
      P + "end-entity-key-usage-bits").length === 2);
  check("K19. a key outside the suite has no set to be held to, and is reported as the key instead",
    !has(lint(await endEntity({ keyUsage: ["digitalSignature"] }, ed)), P + "end-entity-key-usage-bits") &&
    has(lint(await endEntity({ keyUsage: ["digitalSignature"] }, ed)), P + "spki-not-suite"));
  // "the extended key usage extension MUST be present ... The anyExtendedKeyUsage MUST NOT be
  // asserted."
  var eeNoEku = withoutExtension(await endEntity(), "extKeyUsage");
  check("K20. a missing extKeyUsage is an error, and anyExtendedKeyUsage is another",
    sevOf(lint(eeNoEku), P + "end-entity-eku-missing") === "error" &&
    sevOf(lint(await endEntity({ extendedKeyUsage: ["anyExtendedKeyUsage"] })), P + "end-entity-eku-any") === "error" &&
    !has(lint(await endEntity()), P + "end-entity-eku-missing") &&
    !has(lint(await endEntity()), P + "end-entity-eku-any") &&
    !has(lint(conformingRoot), P + "end-entity-eku-missing"));

  // ---- K21-K22: sec. 8 and 9 -------------------------------------------------------------------
  // "The signatures on CRLs in this profile MUST follow the same rules from this profile that apply
  // to signatures in the certificates", and sec. 9 asks the same of an OCSP response. One rule, so
  // the same verdict in each of its three homes.
  var edRoot = await pki.x509.sign({ subject: [{ commonName: "A Classical Root" }],
    subjectPublicKey: ed.pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign", "digitalSignature"],
      subjectKeyIdentifier: true } }, { key: ed.priv });
  var caForCrl = await root({ keyUsage: ["keyCertSign", "cRLSign", "digitalSignature"] });
  var crlSpec = { thisUpdate: new Date("2026-06-01T00:00:00Z"),
    nextUpdate: new Date("2026-07-01T00:00:00Z"), revoked: [], crlNumber: 1 };
  var mlCrl = await pki.crl.sign(crlSpec, { cert: caForCrl, key: mldsa.priv });
  var edCrl = await pki.crl.sign(crlSpec, { cert: edRoot, key: ed.priv });
  check("K21. a CRL signed outside the suite is an error, and one signed with it is not",
    sevOf(pki.lint.crl(edCrl, { profile: "cnsa-2.0" }), P + "crl-signature-not-ml-dsa-87") === "error" &&
    !has(pki.lint.crl(mlCrl, { profile: "cnsa-2.0" }), P + "crl-signature-not-ml-dsa-87") &&
    !has(pki.lint.crl(edCrl, { profile: "rfc5280-crl" }), P + "crl-signature-not-ml-dsa-87"));
  var eeForOcsp = await endEntity();
  function ocspFor(ca, key) {
    return pki.ocsp.sign({ responses: [{ cert: eeForOcsp, issuer: caForCrl, status: "good",
      thisUpdate: new Date("2026-06-01T00:00:00Z") }] }, { cert: ca, key: key });
  }
  var mlResp = await ocspFor(caForCrl, mldsa.priv);
  var edResp = await pki.ocsp.sign({ responses: [{ cert: eeForOcsp, issuer: edRoot, status: "good",
    thisUpdate: new Date("2026-06-01T00:00:00Z") }] }, { cert: edRoot, key: ed.priv });
  check("K22. an OCSP response signed outside the suite is an error, and one signed with it is not",
    sevOf(pki.lint.ocsp(edResp, { profile: "cnsa-2.0" }), P + "response-signature-not-ml-dsa-87") === "error" &&
    !has(pki.lint.ocsp(mlResp, { profile: "cnsa-2.0" }), P + "response-signature-not-ml-dsa-87") &&
    !has(pki.lint.ocsp(edResp, { profile: "rfc6960" }), P + "response-signature-not-ml-dsa-87"));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
