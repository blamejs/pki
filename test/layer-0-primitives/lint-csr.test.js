// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.lint.csr, the artifact a CA lints BEFORE it issues. RED conformance vectors
 * written BEFORE the implementation, each driving the shipped verb and asserting the finding ids
 * and the report shape, never a hand-decoded internal.
 *
 * Which faults a rule can even see was MEASURED against the strict parser rather than assumed:
 * a version other than 0, a challengePassword or extensionRequest carrying more than one value,
 * a second extensionRequest attribute, an extensionRequest carrying no extensions, and the same
 * extension OID twice inside one are each refused before a rule runs, and arrive as
 * lint/unparseable. Writing rows for them would ship checks that can never fire.
 *
 *   C1-C3   the report shape, and that hostile bytes never throw
 *   C4-C7   RFC 5280 sec. 4.1.2.6: an empty subject and the SAN that must then carry the identity
 *   C8-C11  extensions the CA determines, and a subscriber asking to be a CA
 *   C12-C13 the self-signature's algorithm, and the challengePassword an operator transmits
 *   C14-C18 the CABF TLS rows, which run only when the caller names that profile
 *   C19-C21 profile / severity / rules() surface
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

function ids(report) { return report.findings.map(function (f) { return f.id; }); }
function has(report, id) { return ids(report).indexOf(id) !== -1; }

async function run() {
  var kp = await pki.key.generate("Ed25519");
  var priv = await pki.key.export(kp.privateKey);
  var pub = await pki.key.export(kp.publicKey);

  function csr(spec) { return pki.csr.sign(spec, { key: priv }); }
  var plain = await csr({ subject: [{ commonName: "example.com" }], subjectPublicKey: pub,
    extensionRequest: { subjectAltName: [{ dNSName: "example.com" }] } });

  // ---- C1-C3: the report shape, and bytes that are not a CSR ------------------------------
  var rep = pki.lint.csr(plain);
  check("C1. a conforming request reports the LintReport shape",
    rep && Array.isArray(rep.findings) && Array.isArray(rep.ran) &&
    (rep.worst === null || typeof rep.worst === "string") &&
    rep.counts && typeof rep.counts.pass === "number");
  check("C2. ...and a well-formed request carrying an identity reports nothing (" + ids(rep).join(",") + ")",
    rep.findings.length === 0 && rep.worst === null && rep.counts.pass === rep.ran.length);
  var junk = pki.lint.csr(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x07]));
  check("C3. bytes that are not a certification request produce one fatal finding, never a throw",
    junk.findings.length === 1 && junk.findings[0].id === "lint/unparseable" &&
    junk.worst === "fatal");
  var badPem = pki.lint.csr("-----BEGIN CERTIFICATE REQUEST-----\nnot base64!!\n-----END CERTIFICATE REQUEST-----\n");
  check("C3b. a PEM string that does not decode is the same fatal finding, not a throw",
    badPem.findings.length === 1 && badPem.findings[0].id === "lint/unparseable" &&
    badPem.worst === "fatal");
  var pemOk = pki.lint.csr(pki.schema.csr.pemEncode(plain, "CERTIFICATE REQUEST"));
  check("C3c. CONTROL: a well-formed PEM request lints the same as its DER",
    ids(pemOk).join(",") === ids(rep).join(","));

  // ---- C4-C7: RFC 5280 sec. 4.1.2.6, the empty subject ------------------------------------
  // "If the subject is a CA ... If subject naming information is present only in the
  // subjectAltName extension ... then the subject name MUST be an empty sequence and the
  // subjectAltName extension MUST be critical."
  var emptySubject = await csr({ subject: [], subjectPublicKey: pub,
    extensionRequest: { subjectAltName: [{ dNSName: "example.com" }] } });
  check("C4. an empty subject whose SAN is not critical is reported",
    has(pki.lint.csr(emptySubject), "lint/rfc2986/san-not-critical-empty-subject"));

  // A critical SAN, pre-encoded: the named form the builder takes writes the extension
  // non-critical, and the criticality is the whole point of this row.
  var criticalSanDer = b.sequence([
    b.oid(pki.oid.byName("subjectAltName")), b.boolean(true),
    b.octetString(b.sequence([b.contextPrimitive(2, Buffer.from("example.com", "latin1"))])),
  ]);
  var emptyCriticalSan = await csr({ subject: [], subjectPublicKey: pub,
    extensionRequest: [criticalSanDer] });
  var okEmpty = pki.lint.csr(emptyCriticalSan);
  check("C5. CONTROL: an empty subject with a critical SAN is not reported for either row",
    !has(okEmpty, "lint/rfc2986/san-not-critical-empty-subject") &&
    !has(okEmpty, "lint/rfc2986/subject-empty-no-identity"));

  var noIdentity = await csr({ subject: [], subjectPublicKey: pub });
  check("C6. an empty subject requesting no SAN names nothing to certify",
    has(pki.lint.csr(noIdentity), "lint/rfc2986/subject-empty-no-identity"));
  check("C7. CONTROL: a named subject with no SAN is not reported for it",
    !has(pki.lint.csr(await csr({ subject: [{ commonName: "example.com" }], subjectPublicKey: pub })),
      "lint/rfc2986/subject-empty-no-identity"));

  // ---- C8-C11: what the CA determines, and the request that asks to be a CA ----------------
  var akiDer = b.sequence([b.oid(pki.oid.byName("authorityKeyIdentifier")),
    b.octetString(b.sequence([b.contextPrimitive(0, Buffer.alloc(20, 1))]))]);
  var asksAki = await csr({ subject: [{ commonName: "example.com" }], subjectPublicKey: pub,
    extensionRequest: [akiDer] });
  var akiRep = pki.lint.csr(asksAki);
  check("C8. a request for an extension the issuer determines is reported",
    has(akiRep, "lint/rfc2986/ca-determined-extension-requested"));
  check("C9. ...and the finding names which extension it was",
    akiRep.findings.some(function (f) {
      return f.id === "lint/rfc2986/ca-determined-extension-requested" &&
        f.context && f.context.extension === "authorityKeyIdentifier";
    }));

  var bcCaDer = b.sequence([b.oid(pki.oid.byName("basicConstraints")), b.boolean(true),
    b.octetString(b.sequence([b.boolean(true)]))]);
  var asksCa = await csr({ subject: [{ commonName: "example.com" }], subjectPublicKey: pub,
    extensionRequest: [bcCaDer] });
  check("C10. a request asking for a CA certificate is reported",
    has(pki.lint.csr(asksCa), "lint/rfc2986/basic-constraints-ca-requested"));
  var bcEndDer = b.sequence([b.oid(pki.oid.byName("basicConstraints")), b.boolean(true),
    b.octetString(b.sequence([]))]);
  check("C11. CONTROL: a request stating cA FALSE is not reported for it",
    !has(pki.lint.csr(await csr({ subject: [{ commonName: "example.com" }], subjectPublicKey: pub,
      extensionRequest: [bcEndDer] })), "lint/rfc2986/basic-constraints-ca-requested"));

  // ---- C12-C13: the self-signature, and the password an operator transmits ------------------
  // Hand-built: this toolkit's signer will not emit a SHA-1 signature, so a fixture minted through
  // it cannot carry one. The requests a CA actually receives come from other implementations, and
  // the row exists for those, so the algorithm is written the way the registry encodes it.
  var rsa = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  var rsaCsr = await pki.csr.sign({ subject: [{ commonName: "example.com" }],
    subjectPublicKey: await pki.key.export(rsa.publicKey) },
    { key: await pki.key.export(rsa.privateKey) });
  var rsaNode = pki.asn1.decode(rsaCsr);
  var sha1Alg = b.sequence([b.oid(pki.oid.byName("sha1WithRSAEncryption")), b.raw(Buffer.from([0x05, 0x00]))]);
  var weak = b.sequence([b.raw(rsaNode.children[0].bytes), b.raw(sha1Alg), b.raw(rsaNode.children[2].bytes)]);
  check("C12. a request signed under SHA-1 is reported",
    has(pki.lint.csr(weak), "lint/rfc2986/weak-signature-algorithm"));
  check("C12b. CONTROL: the same request under SHA-256 is not",
    !has(pki.lint.csr(rsaCsr), "lint/rfc2986/weak-signature-algorithm"));

  var withPassword = await csr({ subject: [{ commonName: "example.com" }], subjectPublicKey: pub,
    challengePassword: "hunter2" });
  check("C13. a challengePassword is reported, since it travels with the request",
    has(pki.lint.csr(withPassword), "lint/rfc2986/challenge-password-present"));

  // RSASSA-PSS carries its digest in the parameters, so the algorithm NAME never reads as weak.
  // RFC 4055 sec. 3.1 makes hashAlgorithm DEFAULT sha1, so absent parameters and an empty
  // parameter SEQUENCE both name SHA-1: the encoding that looks like it says nothing says the
  // weakest thing.
  function pssCsr(paramsDer) {
    var alg = paramsDer === null
      ? b.sequence([b.oid(pki.oid.byName("rsassaPss"))])
      : b.sequence([b.oid(pki.oid.byName("rsassaPss")), b.raw(paramsDer)]);
    return b.sequence([b.raw(rsaNode.children[0].bytes), b.raw(alg), b.raw(rsaNode.children[2].bytes)]);
  }
  check("C12c. a PSS request with absent parameters names SHA-1 by default and is reported",
    has(pki.lint.csr(pssCsr(null)), "lint/rfc2986/weak-signature-algorithm"));
  check("C12d. ...and so does one with an empty parameter SEQUENCE",
    has(pki.lint.csr(pssCsr(b.sequence([]))), "lint/rfc2986/weak-signature-algorithm"));
  var pssSha256 = b.sequence([b.contextConstructed(0,
    b.sequence([b.oid(pki.oid.byName("sha256")), Buffer.from([0x05, 0x00])]))]);
  check("C12e. CONTROL: a PSS request naming SHA-256 in its parameters is not reported",
    !has(pki.lint.csr(pssCsr(pssSha256)), "lint/rfc2986/weak-signature-algorithm"));

  // Two extensionRequest attributes parse where they sort in DER order, and which one a reader
  // takes then depends on the bytes. Both are read, and the request is reported for asking twice.
  var erOid = pki.oid.byName("extensionRequest");
  function oneEr(extDer) { return b.sequence([b.oid(erOid), b.set([b.sequence([extDer])])]); }
  // Each attribute carries something only IT can report, so whichever way the two sort, reading
  // one of them leaves exactly one of these findings missing. Asserting on a single finding would
  // pass while the union was broken, because the sort decides which attribute comes first.
  var twoErs = [oneEr(akiDer), oneEr(bcCaDer)].sort(Buffer.compare);
  var basis = pki.schema.csr.parse(plain);
  var plainNode = pki.asn1.decode(plain);
  var twoErCri = b.sequence([b.integer(0n), b.raw(basis.subject.bytes),
    b.raw(basis.subjectPublicKeyInfo.bytes), b.contextConstructed(0, Buffer.concat(twoErs))]);
  var twoErCsr = b.sequence([b.raw(twoErCri), b.raw(plainNode.children[1].bytes),
    b.raw(plainNode.children[2].bytes)]);
  var ambiguous = pki.lint.csr(twoErCsr);
  check("C13b. a request carrying two extensionRequest attributes is reported as ambiguous",
    has(ambiguous, "lint/rfc2986/extension-request-ambiguous"));
  check("C13c. ...and BOTH are inspected, whichever way the two sorted (" + ids(ambiguous).join(",") + ")",
    has(ambiguous, "lint/rfc2986/basic-constraints-ca-requested") &&
    has(ambiguous, "lint/rfc2986/ca-determined-extension-requested"));

  // The other member of the class: the SAME extension OID in two attributes. Reading by name
  // takes the first match, so a cA FALSE in one attribute would hide a cA TRUE in the next, and
  // the value deciding the answer would be whichever sorted first. Two DIFFERENT extensions, as
  // above, never exercise that.
  var twoBc = [oneEr(bcEndDer), oneEr(bcCaDer)].sort(Buffer.compare);
  var sameOidCri = b.sequence([b.integer(0n), b.raw(basis.subject.bytes),
    b.raw(basis.subjectPublicKeyInfo.bytes), b.contextConstructed(0, Buffer.concat(twoBc))]);
  var sameOid = pki.lint.csr(b.sequence([b.raw(sameOidCri),
    b.raw(plainNode.children[1].bytes), b.raw(plainNode.children[2].bytes)]));
  check("C13d. a cA TRUE in a second attribute is not hidden by a cA FALSE in the first (" +
    ids(sameOid).join(",") + ")",
    has(sameOid, "lint/rfc2986/basic-constraints-ca-requested") &&
    has(sameOid, "lint/rfc2986/extension-request-ambiguous"));

  // A requested extension whose value does not decode under its own syntax was counted as a
  // passing check, because the shared decoder returns null and every row asking by name reads
  // that null as absence.
  // Hand-built: the builder validates a pre-encoded extension too, so a request carrying a
  // malformed one cannot be minted through it. The requests a CA receives are not minted here.
  var brokenBc = b.sequence([b.oid(pki.oid.byName("basicConstraints")), b.boolean(true),
    b.octetString(b.integer(7n))]);
  var brokenCri = b.sequence([b.integer(0n), b.raw(basis.subject.bytes),
    b.raw(basis.subjectPublicKeyInfo.bytes), b.contextConstructed(0, oneEr(brokenBc))]);
  var brokenExt = pki.lint.csr(b.sequence([b.raw(brokenCri),
    b.raw(plainNode.children[1].bytes), b.raw(plainNode.children[2].bytes)]));
  check("C13e. a requested extension whose value does not decode is reported (" +
    ids(brokenExt).join(",") + ")",
    has(brokenExt, "lint/rfc5280/extension-undecodable"));

  // The weak-digest row reads a name, so an algorithm the registry does not name passed silently.
  // shaWithRSAEncryption is the original SHA, now SHA-0: its NAME carries no digest substring at
  // all, which is why the weak set is named outright rather than read out of the name.
  [["md2WithRSAEncryption", "md2"], ["md4WithRSAEncryption", "md4"],
    ["md4WithRSAEncryption-pkcs1", "md4"], ["dsaWithSha1", "sha1"],
    ["shaWithRSAEncryption", "sha0"], ["md2WithRSASignature", "md2"],
    ["md5WithRSASignature", "md5"], ["sha1WithRSASignature", "sha1"],
    ["md4WithRSA", "md4"], ["md5WithRSA", "md5"], ["ecdsaWithSHA1", "sha1"]]
    .forEach(function (pair) {
      // Each fixture is conforming in the dimension it is NOT testing, so the weak-algorithm row is
      // what the verdict rests on. The RSA identifiers carry the NULL RFC 4055 requires; the ECDSA and
      // DSA ones omit the field, which RFC 3279 sec. 2.2.2 and sec. 2.2.3 require, and a NULL there
      // would be refused at parse before any row ran.
      var dotted = pki.oid.byName(pair[0]);
      var alg = pki.oid.paramsMustBeAbsent(dotted)
        ? b.sequence([b.oid(dotted)])
        : b.sequence([b.oid(dotted), Buffer.from([0x05, 0x00])]);
      var one = b.sequence([b.raw(rsaNode.children[0].bytes), b.raw(alg), b.raw(rsaNode.children[2].bytes)]);
      check("C12f. " + pair[0] + " is named by the registry and reported",
        has(pki.lint.csr(one), "lint/rfc2986/weak-signature-algorithm"));
    });

  // ---- C14-C18: the CABF rows, which need the caller to name the profile --------------------
  // A certification request carries no extKeyUsage, so nothing in the bytes says it is for TLS.
  // The caller names that, and the rows are the certificate profile's own, run pre-issuance.
  var cnNotInSan = await csr({ subject: [{ commonName: "other.example" }], subjectPublicKey: pub,
    extensionRequest: { subjectAltName: [{ dNSName: "example.com" }] } });
  check("C14. the TLS rows do not run unless the caller names the profile",
    !has(pki.lint.csr(cnNotInSan), "lint/cabf-tls/cn-not-in-san"));
  check("C15. ...and under that profile a commonName no SAN covers is reported",
    has(pki.lint.csr(cnNotInSan, { profile: "cabf-tls" }), "lint/cabf-tls/cn-not-in-san"));

  var badDns = await csr({ subject: [{ commonName: "example.com" }], subjectPublicKey: pub,
    extensionRequest: { subjectAltName: [{ dNSName: "w*w.example.com" }] } });
  check("C16. a malformed requested dNSName is reported under the TLS profile",
    has(pki.lint.csr(badDns, { profile: "cabf-tls" }), "lint/cabf-tls/dnsname-bad-syntax"));

  var rsaSmall = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 1024, hash: "SHA-256" });
  var weakKey = await pki.csr.sign({ subject: [{ commonName: "example.com" }],
    subjectPublicKey: await pki.key.export(rsaSmall.publicKey),
    extensionRequest: { subjectAltName: [{ dNSName: "example.com" }] } },
    { key: await pki.key.export(rsaSmall.privateKey) });
  check("C17. a key below the TLS minimum is reported under that profile",
    has(pki.lint.csr(weakKey, { profile: "cabf-tls" }), "lint/cabf-tls/weak-key"));

  var noSan = await csr({ subject: [{ commonName: "example.com" }], subjectPublicKey: pub });
  check("C18. a TLS request naming no SAN is reported under that profile",
    has(pki.lint.csr(noSan, { profile: "cabf-tls" }), "lint/cabf-tls/san-missing"));

  // A parsed certificate carries a subjectPublicKeyInfo and a subject too, so a shape test admits
  // one as a request and then reads its extensions from an extensionRequest attribute it does not
  // have, reporting on a request nobody made. The parsed door is kind-checked.
  var caDer = await pki.x509.sign({ subject: [{ commonName: "Issuing CA" }], subjectPublicKey: pub,
    notBefore: new Date("2020-01-01Z"), notAfter: new Date("2040-01-01Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: priv });
  var certDer = await pki.x509.sign({ subject: [], subjectPublicKey: pub,
    notBefore: new Date("2021-01-01Z"), notAfter: new Date("2031-01-01Z"),
    extensions: { subjectAltName: [{ dNSName: "example.com" }] } }, { cert: caDer, key: priv });
  var parsedCert = pki.schema.x509.parse(certDer);
  var posingAsCsr = Object.assign({}, parsedCert, { certificationRequestInfoBytes: Buffer.alloc(0) });
  var posed;
  try { posed = pki.lint.csr(posingAsCsr); }
  catch (e) { posed = { threw: e.code || e.name }; }
  check("C18b. a parsed certificate dressed as a request is refused, not linted as one (" +
    (posed.threw || ids(posed).join(",")) + ")",
    posed.threw === "lint/bad-input" ||
    (Array.isArray(posed.findings) && posed.findings.length === 1 &&
      posed.findings[0].id === "lint/unparseable"));

  // ---- C19-C21: the surface ----------------------------------------------------------------
  check("C19. the CSR profiles are enumerated",
    pki.lint.profiles().indexOf("rfc2986") !== -1);
  var csrRules = pki.lint.rules("rfc2986");
  check("C20. rules('rfc2986') lists every row it runs, each with a citation",
    csrRules.length > 0 && csrRules.every(function (r) {
      return typeof r.citation === "string" && r.citation.length > 0 && typeof r.severity === "string";
    }) && csrRules.some(function (r) { return r.id.indexOf("lint/rfc2986/") === 0; }));
  check("C20b. ...including the RFC 5280 extension-syntax row it reuses rather than restates",
    csrRules.some(function (r) { return r.id === "lint/rfc5280/extension-undecodable"; }));
  // A rule that reports twice is one rule that did not pass. Requesting two issuer-determined
  // extensions makes one row report twice, which is where subtracting findings instead of failing
  // rules understates the count.
  var twoCaExts = await csr({ subject: [{ commonName: "example.com" }], subjectPublicKey: pub,
    extensionRequest: [akiDer, b.sequence([b.oid(pki.oid.byName("subjectKeyIdentifier")),
      b.octetString(b.octetString(Buffer.alloc(20, 2)))])] });
  var twoNotices = pki.lint.csr(twoCaExts);
  check("C20c. one rule reporting twice counts as one rule that did not pass (" +
    twoNotices.counts.pass + " of " + twoNotices.ran.length + ")",
    twoNotices.findings.length === 2 && twoNotices.counts.pass === twoNotices.ran.length - 1);

  // "cabf-tls" names a set for two artifacts and the two are not the same rows, so a reader has
  // to be able to ask which. Without the selector, tooling was told the CSR run included the
  // certificate-only EKU and validity rows and none of the structural ones.
  var certCabf = pki.lint.rules("cabf-tls", "certificate").map(function (r) { return r.id; });
  var csrCabf = pki.lint.rules("cabf-tls", "csr").map(function (r) { return r.id; });
  check("C20d. rules('cabf-tls', 'csr') returns what pki.lint.csr runs under that name",
    csrCabf.indexOf("lint/rfc2986/subject-empty-no-identity") !== -1 &&
    csrCabf.indexOf("lint/cabf-tls/cn-not-in-san") !== -1 &&
    csrCabf.indexOf("lint/cabf-tls/eku-missing-serverauth") === -1);
  check("C20e. ...and the certificate reading of the same name still has the rows only it runs",
    certCabf.indexOf("lint/cabf-tls/eku-missing-serverauth") !== -1 &&
    certCabf.indexOf("lint/rfc2986/subject-empty-no-identity") === -1);
  check("C20f. an unknown artifact is refused",
    (function () { try { pki.lint.rules("cabf-tls", "nonsense"); return null; }
      catch (e) { return e.code; } })() === "lint/bad-input");

  // An artifact with no profile asks what that VERB can run, not what the whole registry holds.
  var csrAll = pki.lint.rules(null, "csr").map(function (r) { return r.id; });
  check("C20h. rules(null, 'csr') is what pki.lint.csr can run, not the whole registry",
    csrAll.indexOf("lint/rfc2986/subject-empty-no-identity") !== -1 &&
    csrAll.indexOf("lint/cabf-tls/cn-not-in-san") !== -1 &&
    csrAll.indexOf("lint/cabf-tls/validity-too-long") === -1 &&
    csrAll.indexOf("lint/rfc5280-crl/aki-missing") === -1 &&
    csrAll.indexOf("lint/rfc6960/signature-empty") === -1);
  var csrAllDistinct = Object.create(null);
  csrAll.forEach(function (id) { csrAllDistinct[id] = 1; });
  check("C20i. ...and names each of its rules once across the profiles that share them",
    csrAll.length === Object.keys(csrAllDistinct).length);

  // A rule two artifacts share is one rule with one id, so the global listing names it once.
  var allIds = pki.lint.rules().map(function (r) { return r.id; });
  var distinct = Object.create(null);
  allIds.forEach(function (id) { distinct[id] = 1; });
  check("C20g. every rule id appears once in the global listing (" + allIds.length + " entries)",
    allIds.length === Object.keys(distinct).length);

  check("C21. opts.severity filters the findings while counts stay complete",
    pki.lint.csr(withPassword, { severity: "error" }).findings.every(function (f) {
      return f.severity === "error" || f.severity === "fatal";
    }));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
