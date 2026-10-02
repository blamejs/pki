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
var signing = require("../helpers/signing");
var crypto = require("crypto");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;

function ids(report) { return report.findings.map(function (f) { return f.id; }); }
function has(report, id) { return ids(report).indexOf(id) !== -1; }

var SOP_ROW = "lint/rfc9883/signature-certificate-requested";

// A second copy of a named attribute spliced into a signed request. The builder emits one, so a request
// carrying two exists only on the wire, and the shape has to be made rather than built.
function duplicateAttribute(csrDer, attrOidDotted) {
  var root = pki.asn1.decode(csrDer);
  var cri = root.children[0];
  var attrs = cri.children[cri.children.length - 1];
  if (!attrs || !attrs.children || !attrs.children.length) return null;
  var parts = [], found = false;
  for (var a = 0; a < attrs.children.length; a++) {
    var attr = attrs.children[a];
    parts.push(attr.bytes);
    if (pki.asn1.read.oid(attr.children[0]) === attrOidDotted) { parts.push(attr.bytes); found = true; }
  }
  if (!found) return null;
  var newAttrs = b.contextConstructed(0, Buffer.concat(parts));
  var keptCri = [];
  for (var i = 0; i < cri.children.length - 1; i++) keptCri.push(cri.children[i].bytes);
  var newCri = b.sequence([b.raw(Buffer.concat(keptCri)), b.raw(newAttrs)]);
  return b.sequence([b.raw(newCri), b.raw(root.children[1].bytes), b.raw(root.children[2].bytes)]);
}

// ---- R1-R11: the RFC 9883 request profile --------------------------------------------------
// Sec. 6 states "The privateKeyPossessionStatement attribute MUST NOT be used to obtain a signature
// certificate", and sec. 4 states the same requirement as a property of the request: "the subjectPKInfo
// MUST contain the public key for the key establishment algorithm." The row read that off the keyUsage
// extension the request ASKS FOR, so a request that
// named no usage at all reported the prohibition as not engaged while asking to certify a key that can
// only ever sign. `pki.possession.verifyRequest` reads the subject key as well and rejects that request,
// so the linter graded conforming what the verifier refuses, and `pki.csr.sign` under this profile
// emitted it. The two doors answer from one table of the signature-only families.
async function testRfc9883Profile() {
  var caKp = signing.makeSigner("ec-p256");
  var NB = new Date("2026-01-01T00:00:00Z");
  var NA = new Date("2030-01-01T00:00:00Z");
  var caDer = await pki.x509.sign({
    subject: "Possession CA", subjectPublicKey: caKp.spki, serialNumber: 1n,
    notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: caKp.key });
  var sigKp = signing.makeSigner("ec-p256");
  var sigCertDer = await pki.x509.sign({
    subject: "kem.example", subjectPublicKey: sigKp.spki, serialNumber: 0x22n,
    notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] },
  }, { cert: caDer, key: caKp.key });
  var sigParsed = pki.schema.x509.parse(sigCertDer);
  var signer = { issuer: sigParsed.issuer.bytes, serialNumber: sigParsed.serialNumber };

  function spec(spki, extensionRequest) {
    var s = {
      subject: "kem.example", subjectPublicKey: spki,
      privateKeyPossessionStatement: { signer: signer, certificate: sigCertDer },
    };
    if (extensionRequest) s.extensionRequest = extensionRequest;
    return s;
  }
  function spkiOf(alg, opts) {
    return crypto.generateKeyPairSync(alg, opts).publicKey.export({ format: "der", type: "spki" });
  }
  // Built under "none" so the fixture exists whatever the build gate does with it; the gate is the
  // separate subject of R8-R10.
  async function request(spki, extensionRequest) {
    return pki.csr.sign(spec(spki, extensionRequest), { key: sigKp.key }, { profile: "none" });
  }
  function lint(der) { return pki.lint.csr(der, { profile: "rfc9883" }); }

  // R1-R4: a subject key that can ONLY sign, with nothing naming a usage. Four families rather than
  // one example of one, since a table that misses a family is how the prohibition goes unenforced for it.
  var SIGN_ONLY = [
    ["Ed25519", "ed25519", undefined],
    ["Ed448", "ed448", undefined],
    ["ML-DSA-65", "ml-dsa-65", undefined],
    ["DSA", "dsa", { modulusLength: 2048, divisorLength: 256 }],
  ];
  for (var i = 0; i < SIGN_ONLY.length; i++) {
    var der = await request(spkiOf(SIGN_ONLY[i][1], SIGN_ONLY[i][2]), null);
    var rep = lint(der);
    check("R" + (i + 1) + ". a request to certify a signature-only " + SIGN_ONLY[i][0] +
      " key is flagged even though it names no keyUsage (" + (ids(rep).join(",") || "no findings") + ")",
      has(rep, SOP_ROW));
    // The linter's verdict and the verifier's are the same question, so they answer alike.
    var refused;
    try {
      var v = await pki.possession.verifyRequest(der, { trustAnchors: [caDer], time: NB });
      refused = v.valid !== true;
    } catch (e) { void e; refused = true; }
    check("R" + (i + 1) + "a. ...and pki.possession.verifyRequest refuses the same request, the two agreeing",
      refused === true);
  }

  // R5-R7: CONTROLS. The attribute exists so a key that CANNOT sign can be certified, and a key that can
  // do either says nothing on its own. Without these the rows above would pass for a rule that flagged
  // every request carrying the attribute.
  var kemDer = await request(spkiOf("ml-kem-768"), null);
  check("R5. CONTROL an ML-KEM subject key naming no usage is not flagged, which is the mechanism",
    !has(lint(kemDer), SOP_ROW));
  var x25519Der = await request(spkiOf("x25519"), null);
  check("R6. CONTROL nor is an X25519 subject key, the other kind that cannot sign",
    !has(lint(x25519Der), SOP_ROW));
  var rsaDer = await request(spkiOf("rsa", { modulusLength: 2048 }), null);
  check("R7. CONTROL nor is an RSA key, which can do either and so says nothing on its own",
    !has(lint(rsaDer), SOP_ROW));

  // R8: the route that already worked. A request naming a signature usage outright is still flagged, so
  // reading the subject key ADDED a reason rather than replacing one.
  var namedDer = await request(spkiOf("rsa", { modulusLength: 2048 }), { keyUsage: ["digitalSignature"] });
  check("R8. a request naming digitalSignature outright is still flagged",
    has(lint(namedDer), SOP_ROW));

  // R9-R11: the build gate advertises this profile, so it enforces what the profile states.
  var gateCode = "NO-THROW";
  try {
    await pki.csr.sign(spec(spkiOf("ed25519"), null), { key: sigKp.key }, { profile: "rfc9883" });
  } catch (e) { gateCode = (e && e.code) || "NO-CODE"; }
  check("R9. pki.csr.sign under profile rfc9883 refuses to emit the request the profile forbids (" +
    gateCode + ")", gateCode === "csr/profile-violation");
  var kemGate;
  try {
    kemGate = await pki.csr.sign(spec(spkiOf("ml-kem-768"), null), { key: sigKp.key }, { profile: "rfc9883" });
  } catch (e) { void e; kemGate = null; }
  check("R10. CONTROL ...and still emits the key-establishment request the attribute exists for",
    kemGate !== null && kemGate.length > 0);
  var rows = pki.lint.rules("rfc9883", "csr").map(function (r) { return r.id; });
  check("R11. rules('rfc9883', 'csr') lists the row whose reach this covers",
    rows.indexOf(SOP_ROW) !== -1);

  // R12-R13: the other half of the same divergence. Nothing in RFC 9883 says which of several statements a
  // CA should honor, so `pki.possession.verifyRequest` refuses a request carrying more than one; the linter
  // reported nothing about it, so the build gate under this profile would have emitted one.
  var oneStatement = await request(spkiOf("ml-kem-768"), null);
  var twoStatements = duplicateAttribute(oneStatement, pki.oid.byName("statementOfPossession"));
  check("R12. a request carrying two statementOfPossession attributes is flagged (" +
    (ids(lint(twoStatements)).join(",") || "no findings") + ")",
    has(lint(twoStatements), "lint/rfc9883/statement-attribute-repeated"));
  var twoRefused;
  try {
    var tv = await pki.possession.verifyRequest(twoStatements, { trustAnchors: [caDer], time: NB });
    twoRefused = tv.valid !== true;
  } catch (e) { void e; twoRefused = true; }
  check("R12a. ...and pki.possession.verifyRequest refuses it, the two agreeing",
    twoRefused === true);
  check("R13. CONTROL the same request carrying one statement is not flagged",
    !has(lint(oneStatement), "lint/rfc9883/statement-attribute-repeated"));
}

async function run() {
  var kp = await pki.key.generate("Ed25519");
  var priv = await pki.key.export(kp.privateKey);
  var pub = await pki.key.export(kp.publicKey);

  // profile "none": these fixtures are the linter's corpus, so several of them are the requests the
  // build-time gate on pki.csr.sign refuses. Holding them to it would leave the rows below untestable.
  function csr(spec) { return pki.csr.sign(spec, { key: priv }, { profile: "none" }); }
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

  await testRfc9883Profile();

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
