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
  // The CRL and response registries carry the two halves of the one sentence sections 8 and 9 give
  // them: which algorithm signed the artifact, and whether the signature is the length that algorithm
  // fixes. A certificate is told the second by the RFC 9881 row its own profile runs.
  check("K2. the profile is enumerated under each verb that runs it, and listed once",
    certRows.length >= 14 &&
    pki.lint.rules("cnsa-2.0", "crl").length === 2 &&
    pki.lint.rules("cnsa-2.0", "ocsp").length === 2 &&
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
  // Sec. 4 names RFC 9881 and RFC 9935 for the syntax and semantics of the two subject keys, so those
  // documents' rows run under this profile too. Without them the profile read the algorithm OID alone,
  // and bytes claiming to be an ML-KEM-1024 key while being the wrong size for one were reported as
  // conforming. The key is truncated by a byte, which leaves the OID saying what it said.
  var kemCert = await endEntity({ keyUsage: ["keyEncipherment"] }, mlkem);
  var truncatedKem = surgery.patch(kemCert, function (n) {
    if (n.tagClass !== "universal" || n.tagNumber !== 3 || !Buffer.isBuffer(n.content)) return undefined;
    if (n.content.length !== 1569 || n.content[0] !== 0x00) return undefined;
    return b.bitString(Buffer.from(n.content.subarray(1, n.content.length - 1)));
  });
  check("K3b. CONTROL: the truncated certificate parses and still names ML-KEM-1024",
    !has(lint(truncatedKem), "lint/unparseable") &&
    pki.schema.x509.parse(truncatedKem).subjectPublicKeyInfo.algorithm.name === "id-ml-kem-1024" &&
    !truncatedKem.equals(kemCert));
  check("K3c. an encapsulation key of the wrong size is reported under this profile",
    sevOf(lint(truncatedKem), "lint/rfc9935/kem-key-length") === "error" &&
    !has(lint(kemCert), "lint/rfc9935/kem-key-length"));
  // The signature key owes the same thing to the same clause: an identifier names one FIPS 204
  // parameter set, so bytes of any other length are not the key it claims. Reading the identifier and
  // not the length accepted them for one of the two suite algorithms and not the other.
  var truncatedMlDsa = surgery.patch(conformingRoot, function (n) {
    if (n.tagClass !== "universal" || n.tagNumber !== 3 || !Buffer.isBuffer(n.content)) return undefined;
    if (n.content.length !== 2593 || n.content[0] !== 0x00) return undefined;
    return b.bitString(Buffer.from(n.content.subarray(1, n.content.length - 1)));
  });
  check("K3d. CONTROL: the truncated certificate parses and still names id-ml-dsa-87",
    !has(lint(truncatedMlDsa), "lint/unparseable") &&
    pki.schema.x509.parse(truncatedMlDsa).subjectPublicKeyInfo.algorithm.name === "id-ml-dsa-87" &&
    !truncatedMlDsa.equals(conformingRoot));
  check("K3e. a signature key of the wrong size is reported under this profile",
    sevOf(lint(truncatedMlDsa), "lint/rfc9881/mldsa-key-length") === "error" &&
    !has(lint(conformingRoot), "lint/rfc9881/mldsa-key-length"));
  // FIPS 204 fixes the SIGNATURE's length per parameter set as it fixes the public key's, so a
  // signatureValue of another length is not a signature of the algorithm the identifier names. The
  // signature is the certificate's last BIT STRING, and the only one 4,628 bytes long.
  var truncatedSig = surgery.patch(conformingRoot, function (n) {
    if (n.tagClass !== "universal" || n.tagNumber !== 3 || !Buffer.isBuffer(n.content)) return undefined;
    if (n.content.length !== 4628 || n.content[0] !== 0x00) return undefined;
    return b.bitString(Buffer.from(n.content.subarray(1, n.content.length - 1)));
  });
  check("K3f. CONTROL: the rewritten certificate parses and still names id-ml-dsa-87 as its signature",
    !has(lint(truncatedSig), "lint/unparseable") &&
    pki.schema.x509.parse(truncatedSig).signatureAlgorithm.name === "id-ml-dsa-87" &&
    !truncatedSig.equals(conformingRoot));
  check("K3g. a signature of the wrong size is reported under this profile",
    sevOf(lint(truncatedSig), "lint/rfc9881/mldsa-signature-length") === "error" &&
    !has(lint(conformingRoot), "lint/rfc9881/mldsa-signature-length"));
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
  // Sec. 6.1 and 6.4's absent parameters are settled by the parser, so an operator sees its code
  // rather than a row. Asserted against the code, because a certificate that does not parse is silent
  // about every row and asserting that silence would pass for any reason.
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
  check("K6. the absent-parameters clause reaches an operator as the parser's verdict",
    fatalCode(withParams) === "x509/bad-algorithm-parameters");
  // Sec. 6.3 requires version 3, and it needs a row of its own: a version 1 certificate carrying no
  // extensions is well-formed, since RFC 5280 sec. 4.1.2.1 puts the field at DEFAULT v1 and the parser
  // refuses only an extensions field beneath that version. Both wrappers are removed to build one.
  // Encoding the default version explicitly instead would test DER's rule about a DEFAULT, which the
  // parser answers on its own and which is a different clause from this one.
  function asVersion1(der) {
    return surgery.patch(der, function (n) {
      if (n.tagClass !== "universal" || n.tagNumber !== 16 || !n.children) return undefined;
      var kids = n.children;
      var hasVersion = kids[0] && kids[0].tagClass === "context" && kids[0].tagNumber === 0;
      var hasExtensions = kids.some(function (c) { return c.tagClass === "context" && c.tagNumber === 3; });
      if (!hasVersion || !hasExtensions) return undefined;
      return b.sequence(kids.filter(function (c) {
        return !(c.tagClass === "context" && (c.tagNumber === 0 || c.tagNumber === 3));
      }).map(function (c) { return b.raw(c.bytes); }));
    });
  }
  var v1Cert = asVersion1(conformingRoot);
  check("K6c. CONTROL: a version 1 certificate carrying no extensions parses",
    !has(lint(v1Cert), "lint/unparseable") && pki.schema.x509.parse(v1Cert).version === 1);
  check("K6d. a certificate that is not version 3 is an error naming its version",
    sevOf(lint(v1Cert), P + "version-not-3") === "error" &&
    findingsOf(lint(v1Cert), P + "version-not-3")[0].context.version === 1 &&
    !has(lint(conformingRoot), P + "version-not-3"));
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
  // A certificate that omits basicConstraints is exactly the one this clause is about, so the scope
  // cannot be decided on that extension alone: its keyUsage asserting keyCertSign says it is a CA, and
  // RFC 5280 sec. 4.2.1.3 requires the cA boolean of any certificate that asserts the bit. Deciding on
  // the extension graded this certificate as an end entity and reported requirements written for a
  // different kind while staying silent about the one it broke.
  var noBc = withoutExtension(conformingRoot, "basicConstraints");
  check("K8. one carrying no basicConstraints is still read as a CA, and told which extension it owes",
    findingsOf(lint(noBc), P + "self-signed-ca-missing-extension").length === 1 &&
    findingsOf(lint(noBc), P + "self-signed-ca-missing-extension")[0].context.extension === "basicConstraints" &&
    !has(lint(noBc), P + "end-entity-missing-extension") &&
    !has(lint(noBc), P + "end-entity-eku-missing"));
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
  // "All other bits MUST NOT be set" reaches past the nine RFC 5280 sec. 4.2.1.3 names: a bit beyond
  // them is one of the others. The builder writes only the nine, so the extension value is written
  // here: keyCertSign and cRLSign set, plus a bit past the named positions.
  var kuOid = b.oid(pki.oid.byName("keyUsage"));
  function withKeyUsageBits(der, bytes, unused) {
    return surgery.patch(der, function (n) {
      if (n.tagClass !== "universal" || n.tagNumber !== 16 || !n.children || n.children.length !== 3) return undefined;
      if (!kuOid.equals(n.children[0].bytes)) return undefined;
      return b.sequence([b.raw(n.children[0].bytes), b.raw(n.children[1].bytes),
        b.octetString(b.bitString(Buffer.from(bytes), unused))]);
    });
  }
  var caReservedBit = withKeyUsageBits(conformingRoot, [0x06, 0x40], 6);
  check("K10b. CONTROL: the rewritten certificate parses and keeps its two required bits",
    !has(lint(caReservedBit), "lint/unparseable") &&
    !has(lint(caReservedBit), P + "ca-missing-extension") &&
    !caReservedBit.equals(conformingRoot));
  check("K10c. a bit past the nine named positions is outside the set this profile fixes",
    findingsOf(lint(caReservedBit), P + "ca-key-usage-bits").length === 1 &&
    findingsOf(lint(caReservedBit), P + "ca-key-usage-bits")[0].context.bit === "beyond the nine named positions");
  var eeReservedBit = withKeyUsageBits(await endEntity(), [0x80, 0x40], 6);
  check("K10d. and the same holds in the end entity set",
    findingsOf(lint(eeReservedBit), P + "end-entity-key-usage-bits").length === 1 &&
    findingsOf(lint(eeReservedBit), P + "end-entity-key-usage-bits")[0].context.bit === "beyond the nine named positions");
  // "the pathLenConstraint MUST NOT be present", for a self-signed CA alone: sec. 7.2 calls the same
  // field OPTIONAL, so the row must not reach a non-self-signed one.
  check("K11. a pathLenConstraint is an error on a self-signed CA and not on a sub CA",
    sevOf(lint(await root({ basicConstraints: { cA: true, pathLen: 0 } })), P + "self-signed-ca-path-len-present") === "error" &&
    !has(lint(await subCa({ basicConstraints: { cA: true, pathLen: 0 } })), P + "self-signed-ca-path-len-present") &&
    !has(lint(conformingRoot), P + "self-signed-ca-path-len-present"));
  // A CA reissued IN ITS OWN NAME under a new key carries matching issuer and subject names and was
  // signed by its predecessor, so sec. 7.2 governs it and the pathLenConstraint that section calls
  // optional is permitted. Its key identifiers are what separate it from a self-signed CA without a
  // signature check: the authorityKeyIdentifier names the predecessor's key rather than its own
  // subjectKeyIdentifier. Reading the names alone reported a conforming rollover for that field.
  var rollover = await pki.x509.sign({ subject: [{ commonName: "A CNSA Root" }],
    subjectPublicKey: mldsa.pub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true, pathLen: 0 },
      keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true,
      authorityKeyIdentifier: true } },
    { name: [{ commonName: "A CNSA Root" }], publicKey: ed.pub, key: ed.priv });
  var rolloverParsed = pki.schema.x509.parse(rollover);
  function extValue(parsed, name) {
    var e = (parsed.extensions || []).filter(function (x) { return x.oid === pki.oid.byName(name); })[0];
    return e && e.value;
  }
  check("K11b. CONTROL: the rollover carries its own name on both sides and a different key identifier",
    rolloverParsed.subject.rdns.length === rolloverParsed.issuer.rdns.length &&
    Buffer.isBuffer(extValue(rolloverParsed, "subjectKeyIdentifier")) &&
    Buffer.isBuffer(extValue(rolloverParsed, "authorityKeyIdentifier")) &&
    !extValue(rolloverParsed, "authorityKeyIdentifier").equals(extValue(rolloverParsed, "subjectKeyIdentifier")));
  check("K11c. a self-issued rollover CA is read under sec. 7.2, so its pathLenConstraint is permitted",
    !has(lint(rollover), P + "self-signed-ca-path-len-present") &&
    !has(lint(rollover), P + "self-signed-ca-missing-extension") &&
    !has(lint(rollover), P + "ca-missing-extension"));
  // What makes a self-issued CA a rollover is its two key identifiers DISAGREEING. A certificate
  // carrying no subjectKeyIdentifier for that comparison to read is one sec. 7.1 requires the extension
  // of, so it stays in sec. 7.1 and is told so: letting the absence move it to sec. 7.2 left the
  // certificate with no finding at all, which is the same shape as deciding the CA scope on
  // basicConstraints.
  var selfIssuedNoSki = withoutExtension(rollover, "subjectKeyIdentifier");
  check("K11d. CONTROL: it carries an authorityKeyIdentifier and no subjectKeyIdentifier",
    !has(lint(selfIssuedNoSki), "lint/unparseable") &&
    Buffer.isBuffer(extValue(pki.schema.x509.parse(selfIssuedNoSki), "authorityKeyIdentifier")) &&
    extValue(pki.schema.x509.parse(selfIssuedNoSki), "subjectKeyIdentifier") === undefined);
  check("K11e. a self-issued CA with no subjectKeyIdentifier is told sec. 7.1 requires it",
    findingsOf(lint(selfIssuedNoSki), P + "self-signed-ca-missing-extension")
      .some(function (f) { return f.context.extension === "subjectKeyIdentifier"; }) &&
    !has(lint(selfIssuedNoSki), P + "ca-missing-extension"));

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
  // "The cA boolean MUST be set to indicate that the subject is a CA." A certificate reaches this
  // scope by carrying that boolean OR by asserting keyCertSign, so the boolean can be read as unset:
  // a certificate whose keyUsage claims the CA role while its basicConstraints denies it says both
  // things. The value is emptied to the DEFAULT FALSE that an empty BasicConstraints SEQUENCE encodes,
  // which the builder will not write.
  var bcEmpty = surgery.patch(conformingRoot, function (n) {
    if (n.tagClass !== "universal" || n.tagNumber !== 16 || !n.children || n.children.length !== 3) return undefined;
    if (!bcOid.equals(n.children[0].bytes)) return undefined;
    return b.sequence([b.raw(n.children[0].bytes), b.raw(n.children[1].bytes),
      b.octetString(b.sequence([]))]);
  });
  check("K13c. CONTROL: the rewritten certificate parses and its basicConstraints reads cA false",
    !has(lint(bcEmpty), "lint/unparseable") &&
    pki.schema.x509.parse(bcEmpty).extensions.filter(function (e) {
      return e.oid === pki.oid.byName("basicConstraints");
    }).length === 1);
  check("K13d. a basicConstraints that does not set cA is an error where the keyUsage claims the role",
    sevOf(lint(bcEmpty), P + "ca-boolean-not-set") === "error" &&
    !has(lint(conformingRoot), P + "ca-boolean-not-set") &&
    !has(lint(await endEntity()), P + "ca-boolean-not-set"));
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
  // The same sentence's other half: the signature must be the length FIPS 204 fixes. A certificate is
  // told this by the RFC 9881 row its own profile runs, so the CRL and the response are told it here.
  var shortCrlSig = surgery.patch(mlCrl, function (n) {
    if (n.tagClass !== "universal" || n.tagNumber !== 3 || !Buffer.isBuffer(n.content)) return undefined;
    if (n.content.length !== 4628 || n.content[0] !== 0x00) return undefined;
    return b.bitString(Buffer.from(n.content.subarray(1, n.content.length - 1)));
  });
  check("K21b. CONTROL: the shortened CRL parses and still names id-ml-dsa-87",
    !has(pki.lint.crl(shortCrlSig, { profile: "cnsa-2.0" }), "lint/unparseable") &&
    pki.schema.crl.parse(shortCrlSig).signatureAlgorithm.name === "id-ml-dsa-87" &&
    !shortCrlSig.equals(mlCrl));
  check("K21c. a CRL signature of the wrong length is an error",
    sevOf(pki.lint.crl(shortCrlSig, { profile: "cnsa-2.0" }), P + "crl-signature-length") === "error" &&
    !has(pki.lint.crl(mlCrl, { profile: "cnsa-2.0" }), P + "crl-signature-length"));
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
  // The BasicOCSPResponse sits inside the responseBytes OCTET STRING, which the patcher does not
  // descend into, so it is decoded, patched and wrapped again.
  function shortenBitString(der) {
    return surgery.patch(der, function (n) {
      if (n.tagClass !== "universal" || n.tagNumber !== 3 || !Buffer.isBuffer(n.content)) return undefined;
      if (n.content.length !== 4628 || n.content[0] !== 0x00) return undefined;
      return b.bitString(Buffer.from(n.content.subarray(1, n.content.length - 1)));
    });
  }
  var shortRespSig = surgery.patch(mlResp, function (n) {
    if (n.tagClass !== "universal" || n.tagNumber !== 4 || !Buffer.isBuffer(n.content)) return undefined;
    // The one that holds the BasicOCSPResponse: a SEQUENCE long enough to carry the signature. Read
    // as a tag rather than by decoding, so no other octet string has to be decoded to be passed over.
    if (n.content.length <= 4628 || n.content[0] !== 0x30) return undefined;
    var rebuilt = shortenBitString(n.content);
    return rebuilt.equals(n.content) ? undefined : b.octetString(rebuilt);
  });
  check("K22b. CONTROL: the shortened response parses and still names id-ml-dsa-87",
    !has(pki.lint.ocsp(shortRespSig, { profile: "cnsa-2.0" }), "lint/unparseable") &&
    !shortRespSig.equals(mlResp));
  check("K22c. a response signature of the wrong length is an error",
    sevOf(pki.lint.ocsp(shortRespSig, { profile: "cnsa-2.0" }), P + "response-signature-length") === "error" &&
    !has(pki.lint.ocsp(mlResp, { profile: "cnsa-2.0" }), P + "response-signature-length"));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
