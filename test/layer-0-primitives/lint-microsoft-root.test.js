// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the Microsoft Trusted Root Program profile in pki.lint.certificate. RED conformance
 * vectors written BEFORE the rules, each driving the shipped verb and asserting the finding id.
 *
 * Every row is derived from the Program Requirements page, read from the markdown it is maintained
 * in. Like mozilla-root and chrome-root, the profile is NAMED and never detected.
 *
 *   W1-W5    the profile is named, and its three scopes do not leak into each other
 *   W6-W13   sec. 3.A.1 and 3.A.3, the root certificate rows
 *   W14-W17  sec. 3.A.5 and 3.A.8, the issuing CA rows
 *   W18-W21  sec. 3.A.10 and 3.A.13, the end entity rows
 *   W22-W23  sec. 3.A.14, an OCSP responder's extended key usage
 *   W24-W30  sec. 3.B, the signature and key table
 *   W31-W32  sec. 3.E, the extended key usages the program enables on a root
 */

var helpers = require("../helpers");
var surgery = require("../helpers/der-surgery");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

var NB = new Date("2026-04-01T00:00:00Z");
var ROOT_NA = new Date("2036-04-01T00:00:00Z");
var EE_NA = new Date("2026-06-01T00:00:00Z");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function findingsOf(rep, id) {
  return rep.findings.filter(function (f) { return f.id === id; });
}
function sevOf(rep, id) {
  var f = findingsOf(rep, id)[0];
  return f && f.severity;
}
function lint(der) { return pki.lint.certificate(der, { profile: "microsoft-root" }); }
function msIds(rep, prefix) {
  return ids(rep).filter(function (id) { return id.indexOf("lint/microsoft-root/" + prefix) === 0; });
}

async function run() {
  var rsa = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  var rsaPriv = await pki.key.export(rsa.privateKey), rsaPub = await pki.key.export(rsa.publicKey);
  var rsa4096 = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 4096, hash: "SHA-256" });
  var rsa4096Priv = await pki.key.export(rsa4096.privateKey);
  var rsa4096Pub = await pki.key.export(rsa4096.publicKey);

  /** A self-signed ROOT, which sec. 3.A.2 names as the thing the program takes. */
  async function root(over, window, key) {
    var w = window || {};
    var k = key || { pub: rsaPub, priv: rsaPriv };
    var e = { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
      keyUsageCritical: true };
    Object.keys(over || {}).forEach(function (n) {
      if (over[n] === undefined) delete e[n]; else e[n] = over[n];
    });
    return pki.x509.sign({ subject: w.subject || [{ commonName: "A Program Root" }],
      subjectPublicKey: k.pub, notBefore: w.notBefore || NB, notAfter: w.notAfter || ROOT_NA,
      extensions: e }, { key: k.priv });
  }
  var issuer = await root({});

  /** An ISSUING CA: a CA certificate whose issuer and subject names differ. */
  async function issuingCa(over, key) {
    var k = key || { pub: rsaPub, priv: rsaPriv };
    var e = { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
      keyUsageCritical: true,
      cRLDistributionPoints: [{ fullName: [{ uri: "http://crl.example.com/a.crl" }] }] };
    Object.keys(over || {}).forEach(function (n) {
      if (over[n] === undefined) delete e[n]; else e[n] = over[n];
    });
    return pki.x509.sign({ subject: [{ commonName: "An Issuing CA" }], subjectPublicKey: k.pub,
      notBefore: NB, notAfter: EE_NA, extensions: e }, { cert: issuer, key: rsaPriv });
  }
  /** An END ENTITY, carrying one of the seventeen policy identifiers sec. 3.A.10 lists. */
  async function endEntity(over, key) {
    var k = key || { pub: rsaPub, priv: rsaPriv };
    var e = { certificatePolicies: [{ oid: pki.oid.byName("organization-validated") }] };
    Object.keys(over || {}).forEach(function (n) {
      if (over[n] === undefined) delete e[n]; else e[n] = over[n];
    });
    return pki.x509.sign({ subject: [{ commonName: "A Subject" }], subjectPublicKey: k.pub,
      notBefore: NB, notAfter: EE_NA, extensions: e }, { cert: issuer, key: rsaPriv });
  }

  // ---- W1-W5: named, never detected, and three scopes that do not leak -----------------------
  var rootRep = lint(issuer);
  var rootErrors = rootRep.findings.filter(function (f) {
    return f.source === "microsoft-root" && (f.severity === "error" || f.severity === "fatal");
  });
  check("W1. CONTROL: a conforming root reports nothing at error or worse (" +
    rootErrors.map(function (f) { return f.id; }).join(",") + ")", rootErrors.length === 0);
  check("W2. no row runs unless the profile is named",
    pki.lint.certificate(issuer).ran.every(function (id) {
      return id.indexOf("lint/microsoft-root/") !== 0;
    }) && rootRep.ran.some(function (id) { return id.indexOf("lint/microsoft-root/") === 0; }));
  check("W3. rules() enumerates the microsoft-root rows",
    pki.lint.rules().filter(function (r) { return r.source === "microsoft-root"; }).length >= 18);
  var caRep = lint(await issuingCa({}));
  var eeRep = lint(await endEntity({}));
  check("W4. a root draws no issuing CA row and no end entity row (" +
    msIds(rootRep, "issuing-ca-").concat(msIds(rootRep, "end-entity-")).join(",") + ")",
    msIds(rootRep, "issuing-ca-").length === 0 && msIds(rootRep, "end-entity-").length === 0);
  check("W5. an issuing CA and an end entity draw no root row (" +
    msIds(caRep, "root-").concat(msIds(eeRep, "root-")).join(",") + ")",
    msIds(caRep, "root-").length === 0 && msIds(eeRep, "root-").length === 0);
  // A CA reissued in its own name under a NEW key carries one name in both fields and was signed by
  // its predecessor. The root rows read the key identifiers and pass over it, and the issuing CA
  // rows read the names and pass over it too, because the bytes do not tell it from the succession
  // certificate a root issues to its replacement. That is the same under-report mozilla-root and
  // chrome-root carry, and it is pinned here so the three agree by decision rather than by accident.
  var rollKeys = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  var rollPub = await pki.key.export(rollKeys.publicKey);
  var rollover = await pki.x509.sign({ subject: [{ commonName: "A Program Root" }],
    subjectPublicKey: rollPub, notBefore: NB, notAfter: ROOT_NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"],
      keyUsageCritical: true } }, { cert: issuer, key: rsaPriv });
  var rolloverRep = lint(rollover);
  check("W5b. a CA reissued in its own name draws neither a root row nor an issuing CA row (" +
    msIds(rolloverRep, "root-").concat(msIds(rolloverRep, "issuing-ca-")).join(",") + ")",
    msIds(rolloverRep, "root-").length === 0 &&
    msIds(rolloverRep, "issuing-ca-").length === 0);

  // ---- W6-W13: sec. 3.A.1 and 3.A.3, the root certificate rows -------------------------------
  // "Root certificates must be x.509 v3 certificates" carries no row, and this is why: schema-x509
  // refuses every other version, so a certificate that is not v3 never reaches a rule. A row for it
  // would be a branch no input can drive. The verdict an operator sees is the parser's.
  var otherVersions = [0, 1].map(function (v) {
    return surgery.patch(issuer, function (n, path) {
      if (path.length !== 2 || n.tagClass !== "context" || n.tagNumber !== 0) return undefined;
      return b.explicit(0, b.integer(v));
    });
  });
  var versionVerdicts = otherVersions.map(function (der) {
    var rep = lint(der);
    return has(rep, "lint/unparseable") && rep.findings[0].context.code === "x509/bad-version";
  });
  check("W6. a certificate that is not v3 is refused at parse rather than linted (" +
    versionVerdicts.join(",") + ")",
    versionVerdicts.length === 2 && versionVerdicts.every(function (v) { return v === true; }));
  check("W7. a root with no commonName is reported",
    has(lint(await root({}, { subject: [{ organizationName: "A Program Operator" }] })),
      "lint/microsoft-root/root-common-name-missing"));
  check("W8. a root with no keyUsage extension is reported",
    has(lint(await root({ keyUsage: undefined, keyUsageCritical: undefined })),
      "lint/microsoft-root/root-key-usage-missing"));
  check("W9. a root whose keyUsage is not critical is reported",
    has(lint(await root({ keyUsageCritical: false })),
      "lint/microsoft-root/root-key-usage-not-critical"));
  // Both bits are named, so each missing one draws its own finding rather than a boolean that
  // cannot tell them apart.
  var noCrlSign = lint(await root({ keyUsage: ["keyCertSign"] }));
  var noCertSign = lint(await root({ keyUsage: ["cRLSign"] }));
  check("W10. each of keyCertSign and cRLSign missing is reported, naming the bit",
    findingsOf(noCrlSign, "lint/microsoft-root/root-key-usage-bits")
      .some(function (f) { return f.context.bit === "cRLSign"; }) &&
    findingsOf(noCertSign, "lint/microsoft-root/root-key-usage-bits")
      .some(function (f) { return f.context.bit === "keyCertSign"; }));
  // Sec. 3.A.3 measures from the date of SUBMISSION, which is at or after notBefore, so a term
  // measured from notBefore is the longest the certificate can offer from any submission date.
  // Under eight years is therefore under eight years from every one of them.
  var eightExact = await root({}, { notBefore: new Date("2026-04-01T00:00:00Z"),
    notAfter: new Date("2034-04-01T00:00:00Z") });
  var eightShort = await root({}, { notBefore: new Date("2026-04-01T00:00:00Z"),
    notAfter: new Date("2034-03-31T00:00:00Z") });
  check("W11. a root valid for less than eight years is reported, and exactly eight is not",
    has(lint(eightShort), "lint/microsoft-root/root-validity-under-eight-years") &&
    !has(lint(eightExact), "lint/microsoft-root/root-validity-under-eight-years"));
  // The maximum runs the other way and is NOT sound on these bytes: a 30-year term still meets
  // 25 years from submission if submission came five years on. Reported below error.
  var over25 = await root({}, { notBefore: new Date("2026-04-01T00:00:00Z"),
    notAfter: new Date("2051-04-02T00:00:00Z") });
  var at25 = await root({}, { notBefore: new Date("2026-04-01T00:00:00Z"),
    notAfter: new Date("2051-04-01T00:00:00Z") });
  check("W12. a root valid for more than 25 years is reported at warn, and exactly 25 is not",
    sevOf(lint(over25), "lint/microsoft-root/root-validity-over-25-years") === "warn" &&
    !has(lint(at25), "lint/microsoft-root/root-validity-over-25-years"));
  check("W13. CONTROL: the eight-year floor reads a root and not an issuing CA",
    !has(lint(await issuingCa({})), "lint/microsoft-root/root-validity-under-eight-years"));

  // ---- W14-W17: sec. 3.A.5 and 3.A.8, the issuing CA rows -------------------------------------
  check("W14. an issuing CA with neither a distribution point nor an OCSP responder is reported",
    has(lint(await issuingCa({ cRLDistributionPoints: undefined })),
      "lint/microsoft-root/issuing-ca-no-revocation-pointer"));
  // "an AIA extension to an OCSP responder" is reached by a URL. The shared decoder admits any
  // GeneralName in an accessLocation, so an entry naming the ocsp accessMethod with a dNSName
  // beside it satisfies the extension's syntax and points at no responder.
  check("W14b. an OCSP accessMethod whose location is not a URI does not satisfy the clause",
    has(lint(await issuingCa({ cRLDistributionPoints: undefined,
      authorityInfoAccess: [{ accessMethod: "ocsp", accessLocation: { dNSName: "ocsp.example.com" } }] })),
      "lint/microsoft-root/issuing-ca-no-revocation-pointer"));
  check("W15. CONTROL: either pointer alone satisfies the clause",
    !has(lint(await issuingCa({})), "lint/microsoft-root/issuing-ca-no-revocation-pointer") &&
    !has(lint(await issuingCa({ cRLDistributionPoints: undefined,
      authorityInfoAccess: [{ accessMethod: "ocsp", accessLocation: { uri: "http://ocsp.example.com" } }] })),
      "lint/microsoft-root/issuing-ca-no-revocation-pointer"));
  // "a single Issuing CA must not combine server authentication with S/MIME, code signing, or time
  // stamping EKU", the sentence every reading of sec. 3.A.8 agrees on.
  var mixedWithServer = [];
  var others = ["emailProtection", "codeSigning", "timeStamping"];
  for (var mi = 0; mi < others.length; mi++) {
    var rep = lint(await issuingCa({ extendedKeyUsage: ["serverAuth", others[mi]] }));
    mixedWithServer.push(findingsOf(rep, "lint/microsoft-root/issuing-ca-mixes-server-auth")
      .some(function (f) { return f.context.purpose === others[mi]; }));
  }
  check("W16. server authentication beside each of the other three is reported (" +
    mixedWithServer.join(",") + ")",
    mixedWithServer.length === 3 && mixedWithServer.every(function (v) { return v === true; }));
  // The clause's other two sentences are broader than that one: "must separate Server
  // Authentication, S/MIME, Code Signing, and Time Stamping uses" and "A separate intermediate must
  // be used for each use case" forbid a pair the middle sentence does not name. Both readings are
  // in the clause, so the pair only two sentences forbid is graded below the pair all three do.
  var smimeAndCode = lint(await issuingCa({ extendedKeyUsage: ["emailProtection", "codeSigning"] }));
  check("W17. a pair the clause's other sentences forbid is reported at warn",
    sevOf(smimeAndCode, "lint/microsoft-root/issuing-ca-mixes-uses") === "warn" &&
    !has(smimeAndCode, "lint/microsoft-root/issuing-ca-mixes-server-auth") &&
    !has(lint(await issuingCa({ extendedKeyUsage: ["codeSigning"] })),
      "lint/microsoft-root/issuing-ca-mixes-uses"));

  // ---- W18-W21: sec. 3.A.10 and 3.A.13, the end entity rows -----------------------------------
  var SEVENTEEN = ["domain-validated", "organization-validated", "ev-guidelines",
    "individual-validated", "code-signing",
    "smime-mailbox-legacy", "smime-mailbox-multipurpose", "smime-mailbox-strict",
    "smime-organization-legacy", "smime-organization-multipurpose", "smime-organization-strict",
    "smime-sponsor-legacy", "smime-sponsor-multipurpose", "smime-sponsor-strict",
    "smime-individual-legacy", "smime-individual-multipurpose", "smime-individual-strict"];
  var accepted = [];
  for (var pi = 0; pi < SEVENTEEN.length; pi++) {
    accepted.push(!has(lint(await endEntity({
      certificatePolicies: [{ oid: pki.oid.byName(SEVENTEEN[pi]) }] })),
      "lint/microsoft-root/end-entity-reserved-policy-missing"));
  }
  check("W18. each of the seventeen identifiers is accepted (" + accepted.join(",") + ")",
    accepted.length === 17 && accepted.every(function (v) { return v === true; }));
  check("W19. an end entity declaring none of them is reported",
    has(lint(await endEntity({ certificatePolicies: [{ oid: pki.oid.byName("anyPolicy") }] })),
      "lint/microsoft-root/end-entity-reserved-policy-missing") &&
    has(lint(await endEntity({ certificatePolicies: undefined })),
      "lint/microsoft-root/end-entity-reserved-policy-missing"));
  // Sec. 3.A.13 carries no row for the same reason sec. 3.A.1 does not: the shared basicConstraints
  // decoder refuses a pathLenConstraint without cA under RFC 5280 sec. 4.2.1.9, so the extension
  // does not decode and the syntax row answers. The signer refuses to build it too, so the fixture
  // is cut by hand from one it did build.
  var BC_OID_DER = b.oid(pki.oid.byName("basicConstraints"));
  var eeWithPathLen = surgery.patch(await endEntity({ basicConstraints: { cA: false } }),
    function (n) {
      if (!n.constructed || n.tagNumber !== 16 || !n.children || !n.children.length) return undefined;
      if (!BC_OID_DER.equals(n.children[0].bytes)) return undefined;
      var kids = n.children.slice(0, n.children.length - 1).map(function (c) { return b.raw(c.bytes); });
      kids.push(b.octetString(b.sequence([b.integer(0)])));
      return b.sequence(kids);
    });
  check("W20. an end entity carrying a pathLenConstraint is refused by the decoder, not linted",
    has(lint(eeWithPathLen), "lint/rfc5280/extension-undecodable") &&
    msIds(lint(eeWithPathLen), "end-entity-path").length === 0);
  check("W21. CONTROL: basicConstraints with cA false and no path length decodes and is clean",
    !has(lint(await endEntity({ basicConstraints: { cA: false } })),
      "lint/rfc5280/extension-undecodable"));

  // ---- W22-W23: sec. 3.A.14, an OCSP responder's extended key usage ---------------------------
  check("W22. an OCSP responder naming a second purpose is reported, naming it",
    findingsOf(lint(await endEntity({ extendedKeyUsage: ["ocspSigning", "serverAuth"] })),
      "lint/microsoft-root/ocsp-responder-extra-eku")
      .some(function (f) { return f.context.purpose === "serverAuth"; }));
  check("W23. CONTROL: id-kp-OCSPSigning alone is not reported",
    !has(lint(await endEntity({ extendedKeyUsage: ["ocspSigning"] })),
      "lint/microsoft-root/ocsp-responder-extra-eku"));

  // ---- W24-W30: sec. 3.B, the signature and key table -----------------------------------------
  var sha1Root = surgery.patch(await root({}), function (n) {
    if (!n.constructed || n.tagNumber !== 16 || !n.children || n.children.length !== 2) return undefined;
    if (!b.oid(pki.oid.byName("sha256WithRSAEncryption")).equals(n.children[0].bytes)) return undefined;
    return b.sequence([b.raw(b.oid(pki.oid.byName("sha1WithRSAEncryption"))), b.nullValue()]);
  });
  check("W24. a signature over a digest outside SHA-256, SHA-384 and SHA-512 is reported",
    has(lint(sha1Root), "lint/microsoft-root/signature-digest-not-sha2"));
  var sha2Accepted = [];
  var digests = ["SHA-256", "SHA-384", "SHA-512"];
  for (var di = 0; di < digests.length; di++) {
    var pair = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
      hash: digests[di] });
    var pub = await pki.key.export(pair.publicKey), priv = await pki.key.export(pair.privateKey);
    sha2Accepted.push(!has(lint(await root({}, {}, { pub: pub, priv: priv })),
      "lint/microsoft-root/signature-digest-not-sha2"));
  }
  check("W25. each of the three digests the table names is accepted (" + sha2Accepted.join(",") +
    ")", sha2Accepted.length === 3 && sha2Accepted.every(function (v) { return v === true; }));
  var rsa1024 = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 1024, hash: "SHA-256" });
  var rsa1024Pub = await pki.key.export(rsa1024.publicKey);
  check("W26. an RSA modulus under 2048 bits is reported",
    has(lint(await endEntity({}, { pub: rsa1024Pub, priv: rsaPriv })),
      "lint/microsoft-root/rsa-modulus-under-2048"));
  var curveAccepted = [];
  var curves = ["P-256", "P-384", "P-521"];
  for (var ci = 0; ci < curves.length; ci++) {
    var ecPair = await pki.key.generate({ name: "ECDSA", namedCurve: curves[ci] });
    var ecPairPub = await pki.key.export(ecPair.publicKey);
    curveAccepted.push(!has(lint(await endEntity({}, { pub: ecPairPub, priv: rsaPriv })),
      "lint/microsoft-root/ec-curve-not-permitted"));
  }
  check("W27. each of the three curves the table names is accepted (" + curveAccepted.join(",") +
    ")", curveAccepted.length === 3 && curveAccepted.every(function (v) { return v === true; }));
  var ed = await pki.key.generate("Ed25519");
  var edPub = await pki.key.export(ed.publicKey);
  check("W28. a key outside the RSA and named-curve rows is reported",
    has(lint(await endEntity({}, { pub: edPub, priv: rsaPriv })),
      "lint/microsoft-root/key-algorithm-not-in-table"));
  // "Code Signing does not support ECC or keys > 4096", and the ECC cell of that column reads
  // "Not Supported".
  var ecPub384 = await pki.key.export((await pki.key.generate({ name: "ECDSA", namedCurve: "P-384" })).publicKey);
  check("W29. an elliptic curve key in a code signing or time stamping certificate is reported",
    has(lint(await endEntity({ extendedKeyUsage: ["codeSigning"],
      certificatePolicies: [{ oid: pki.oid.byName("code-signing") }] }, { pub: ecPub384, priv: rsaPriv })),
      "lint/microsoft-root/code-signing-ecc") &&
    !has(lint(await endEntity({}, { pub: ecPub384, priv: rsaPriv })),
      "lint/microsoft-root/code-signing-ecc"));
  // The RSA cell of that column reads "4096 (New roots only)", so the floor is scoped to a root.
  check("W30. a code signing root below 4096 bits is reported, and 4096 is not",
    has(lint(await root({ extendedKeyUsage: ["codeSigning"] })),
      "lint/microsoft-root/root-code-signing-rsa-under-4096") &&
    !has(lint(await root({ extendedKeyUsage: ["codeSigning"] }, {},
      { pub: rsa4096Pub, priv: rsa4096Priv })),
      "lint/microsoft-root/root-code-signing-rsa-under-4096"));

  // ---- W31-W32: sec. 3.E, the extended key usages the program enables on a root ---------------
  var outsideSet = lint(await root({ extendedKeyUsage: ["anyExtendedKeyUsage"] }));
  check("W31. a root naming a purpose outside the enabled set is reported at warn, naming it",
    sevOf(outsideSet, "lint/microsoft-root/root-eku-not-enabled") === "warn" &&
    findingsOf(outsideSet, "lint/microsoft-root/root-eku-not-enabled")
      .some(function (f) { return f.context.purpose === "anyExtendedKeyUsage"; }));
  // The document contradicts itself: sec. 3.E.2 omits id-kp-codeSigning while the whole of
  // sec. 3.D governs code signing roots and D.3 says "all Code Signing certificates will be
  // treated equally". Reporting a code signing root would contradict sec. 3.D, so the safe
  // direction is taken and pinned here as a decision rather than a drift.
  var enabled = ["serverAuth", "clientAuth", "emailProtection", "timeStamping",
    "ms-document-signing", "codeSigning"];
  var enabledClean = [];
  for (var ei = 0; ei < enabled.length; ei++) {
    enabledClean.push(!has(lint(await root({ extendedKeyUsage: [enabled[ei]] },
      {}, { pub: rsa4096Pub, priv: rsa4096Priv })), "lint/microsoft-root/root-eku-not-enabled"));
  }
  check("W32. the five the clause names, and code signing, are all accepted (" +
    enabledClean.join(",") + ")",
    enabledClean.length === 6 && enabledClean.every(function (v) { return v === true; }));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
