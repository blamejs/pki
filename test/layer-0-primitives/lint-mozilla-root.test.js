// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the Mozilla Root Store Policy profile in pki.lint.certificate. RED conformance
 * vectors written BEFORE the rules, each driving the shipped verb and asserting the finding id.
 *
 * Every row is derived from Mozilla Root Store Policy v3.1, read from the markdown the policy is
 * maintained in. Unlike every other profile here, this one is NAMED and never detected: a root
 * program's policy applies because the certificate chains to a root in that store, which the
 * certificate does not state.
 *
 *   M1-M2    the profile is named, never detected
 *   M3-M7    the sec. 5.1 algorithm encodings, which the policy gives byte-exact
 *   M8-M9    the sec. 5.1.3 SHA-1 prohibitions, each gated to its own date
 *   M10-M13  the sec. 5.2 practices
 *   M14-M16  the sec. 5.3 intermediate rules, gated to 2019
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
function lint(der, opts) { return pki.lint.certificate(der, opts || { profile: "mozilla-root" }); }

async function run() {
  var rsa = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  var rsaPriv = await pki.key.export(rsa.privateKey), rsaPub = await pki.key.export(rsa.publicKey);
  var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var ecPriv = await pki.key.export(ec.privateKey), ecPub = await pki.key.export(ec.publicKey);
  var ec384 = await pki.key.generate({ name: "ECDSA", namedCurve: "P-384" });
  var ec384Pub = await pki.key.export(ec384.publicKey);
  var ec521 = await pki.key.generate({ name: "ECDSA", namedCurve: "P-521" });
  var ec521Pub = await pki.key.export(ec521.publicKey);
  var ed = await pki.key.generate("Ed25519");
  var edPub = await pki.key.export(ed.publicKey);

  // Issued from a CA rather than self-signed, so the subject key may be a curve the signing key is
  // not: a self-signature is refused where the two differ, which is the signer doing its job.
  var issuingCa = await pki.x509.sign({ subject: [{ commonName: "Issuing CA" }],
    subjectPublicKey: ecPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: ecPriv });
  function sign(over, pub, window) {
    var w = window || {};
    var e = { extendedKeyUsage: ["clientAuth"] };
    Object.keys(over || {}).forEach(function (k) {
      if (over[k] === undefined) delete e[k]; else e[k] = over[k];
    });
    return pki.x509.sign({ subject: [{ commonName: "A Subject" }], subjectPublicKey: pub || ecPub,
      notBefore: w.notBefore || NB, notAfter: w.notAfter || NA, extensions: e },
      { cert: issuingCa, key: ecPriv });
  }
  async function lintOver(over, pub, window) { return lint(await sign(over, pub, window)); }

  /** Replace one field of the TBSCertificate, which is how a non-conforming AlgorithmIdentifier is
   *  reached: the signer emits exactly the bytes this policy requires, so a violating encoding
   *  cannot be built through it. The signature no longer matches, which the linter does not check
   *  and does not claim to. */
  function spliceTbsField(baseDer, index, replacement) {
    var cert = pki.asn1.decode(baseDer);
    var kids = cert.children[0].children.map(function (c, i) {
      return i === index ? b.raw(replacement) : b.raw(c.bytes);
    });
    return b.sequence([b.sequence(kids), b.raw(cert.children[1].bytes), b.raw(cert.children[2].bytes)]);
  }
  /** Replace BOTH algorithm fields. schema-x509 refuses a certificate whose outer
   *  signatureAlgorithm differs byte-for-byte from tbsCertificate.signature, so changing one alone
   *  yields a certificate that does not parse rather than one that breaks this policy. */
  function spliceSignatureAlgorithm(baseDer, algHex) {
    var withTbs = spliceTbsField(baseDer, 2, Buffer.from(algHex, "hex"));
    var cert = pki.asn1.decode(withTbs);
    return b.sequence([b.raw(cert.children[0].bytes), b.raw(Buffer.from(algHex, "hex")),
      b.raw(cert.children[2].bytes)]);
  }
  /** Replace the SubjectPublicKeyInfo's AlgorithmIdentifier, keeping its BIT STRING. */
  function spliceSpkiAlgorithm(baseDer, algHex) {
    var cert = pki.asn1.decode(baseDer);
    var spki = cert.children[0].children[6];
    var newSpki = b.sequence([b.raw(Buffer.from(algHex, "hex")), b.raw(spki.children[1].bytes)]);
    return spliceTbsField(baseDer, 6, newSpki);
  }
  function hexOfTbsField(der, index) {
    return pki.asn1.decode(pki.asn1.decode(der).children[0].bytes).children[index].bytes.toString("hex");
  }
  /** The SubjectPublicKeyInfo's own AlgorithmIdentifier, which is what the clause fixes. */
  function spkiAlgorithmHex(der) {
    var spki = pki.asn1.decode(pki.asn1.decode(der).children[0].bytes).children[6];
    return spki.children[0].bytes.toString("hex");
  }

  // ---- M1-M2: named, never detected ----------------------------------------------------------
  var base = await sign({});
  var baseRep = lint(base);
  var baseErrors = baseRep.findings.filter(function (f) {
    return f.source === "mozilla-root" && (f.severity === "error" || f.severity === "fatal");
  });
  check("M1. CONTROL: a conforming certificate reports nothing at error or worse (" +
    baseErrors.map(function (f) { return f.id; }).join(",") + ")", baseErrors.length === 0);
  // A root program's policy applies because the certificate chains to a root in that store, which
  // the certificate does not state, so no row runs unless the caller names the profile.
  check("M2. no row runs unless the profile is named",
    pki.lint.certificate(base).ran.every(function (id) { return id.indexOf("lint/mozilla-root/") !== 0; }) &&
    lint(base).ran.some(function (id) { return id.indexOf("lint/mozilla-root/") === 0; }));

  // ---- M3-M7: the sec. 5.1 algorithm encodings ----------------------------------------------
  // The signer already emits the bytes the policy requires, which is what makes M1 a real control.
  check("M3. CONTROL: this toolkit's own encodings are the ones the policy names",
    spkiAlgorithmHex(await sign({}, rsaPub, { key: rsaPriv })) === "300d06092a864886f70d0101010500" &&
    spkiAlgorithmHex(base) === "301306072a8648ce3d020106082a8648ce3d030107" &&
    hexOfTbsField(base, 2) === "300a06082a8648ce3d040302");
  // An rsaEncryption AlgorithmIdentifier with the parameters omitted rather than an explicit NULL
  // is the shape sec. 5.1.1 rules out, and it is not one of the four byte strings.
  check("M4. a SubjectPublicKeyInfo algorithm outside the four is reported",
    has(lint(spliceSpkiAlgorithm(base, "300b06092a864886f70d010101")),
      "lint/mozilla-root/spki-algorithm-encoding"));
  var fourKeys = [["RSA", rsaPub, rsaPriv], ["P-256", ecPub, ecPriv],
    ["P-384", ec384Pub, ecPriv], ["P-521", ec521Pub, ecPriv]];
  var accepted = [];
  for (var fi = 0; fi < fourKeys.length; fi++) {
    accepted.push(!has(lint(await sign({}, fourKeys[fi][1], { key: fourKeys[fi][2] })),
      "lint/mozilla-root/spki-algorithm-encoding"));
  }
  check("M4b. ...and each of the four the policy names is accepted (" + accepted.join(",") + ")",
    accepted.length === 4 && accepted.every(function (a) { return a === true; }));
  // Sec. 5.1 permits an EdDSA key only in a certificate carrying id-kp-emailProtection, and gives
  // no EdDSA AlgorithmIdentifier encoding, so the encoding row must leave one alone.
  check("M5. an EdDSA key without id-kp-emailProtection is reported",
    has(await lintOver({}, edPub), "lint/mozilla-root/eddsa-without-email-protection"));
  check("M5b. CONTROL: with it the key is admitted, and the encoding row does not report it",
    !has(await lintOver({ extendedKeyUsage: ["emailProtection"] }, edPub),
      "lint/mozilla-root/eddsa-without-email-protection") &&
    !has(await lintOver({ extendedKeyUsage: ["emailProtection"] }, edPub),
      "lint/mozilla-root/spki-algorithm-encoding"));
  // ecdsa-with-SHA1 (1.2.840.10045.4.1), which is not one of the ten the policy names.
  check("M6. a signature AlgorithmIdentifier outside the ten is reported",
    has(lint(spliceSignatureAlgorithm(base, "300906072a8648ce3d0401")),
      "lint/mozilla-root/signature-algorithm-encoding"));
  // The binding of a curve to a digest is to the SIGNING key, which this certificate does not
  // carry, so the row checks membership and nothing more.
  check("M6b. CONTROL: a P-384 certificate signed with SHA-256 is membership-conformant",
    !has(await lintOver({}, ec384Pub), "lint/mozilla-root/signature-algorithm-encoding"));
  // Sec. 5.1 admits an EdDSA key in a certificate carrying id-kp-emailProtection, so such a
  // certificate can be an intermediate and sign with that key. Sections 5.1.1 and 5.1.2 fix the
  // encodings for a signing RSA key and a signing ECDSA key and say nothing of an EdDSA one, so a
  // certificate it signs is outside the list rather than in breach of it.
  var edPrivKey = await pki.key.export(ed.privateKey);
  var edIssuer = await pki.x509.sign({ subject: [{ commonName: "An Email Intermediate" }],
    subjectPublicKey: edPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
      extendedKeyUsage: ["emailProtection"] } }, { key: edPrivKey });
  var edSigned = await pki.x509.sign({ subject: [{ commonName: "Signed By EdDSA" }],
    subjectPublicKey: ecPub, notBefore: NB, notAfter: NA,
    extensions: { extendedKeyUsage: ["emailProtection"] } }, { cert: edIssuer, key: edPrivKey });
  check("M6c. CONTROL: a certificate signed by a permitted EdDSA key is not reported",
    !has(lint(edSigned), "lint/mozilla-root/signature-algorithm-encoding"));
  var rsa1024 = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 1024, hash: "SHA-256" });
  check("M7. an RSA modulus below 2048 bits is reported",
    has(await lintOver({}, await pki.key.export(rsa1024.publicKey)), "lint/mozilla-root/rsa-modulus-invalid") &&
    !has(await lintOver({}, rsaPub), "lint/mozilla-root/rsa-modulus-invalid"));

  // ---- M8-M9: the sec. 5.1.3 SHA-1 prohibitions, each on its own date ------------------------
  var SHA1_RSA = "300d06092a864886f70d0101050500";
  function sha1Cert(over, pub, window) {
    return sign(over, pub, window).then(function (der) {
      return spliceSignatureAlgorithm(der, SHA1_RSA);
    });
  }
  check("M8. SHA-1 over an end entity carrying id-kp-emailProtection is reported",
    has(lint(await sha1Cert({ extendedKeyUsage: ["emailProtection"] })),
      "lint/mozilla-root/sha1-email-protection"));
  check("M8b. CONTROL: gated to 1 July 2022, so one issued before it is not held to the rule",
    !has(lint(await sha1Cert({ extendedKeyUsage: ["emailProtection"] }, ecPub,
      { notBefore: new Date("2022-01-01T00:00:00Z"), notAfter: new Date("2022-06-01T00:00:00Z") })),
      "lint/mozilla-root/sha1-email-protection"));
  check("M9. SHA-1 over an OCSP signing certificate or a CA certificate is reported",
    has(lint(await sha1Cert({ extendedKeyUsage: ["ocspSigning"] })), "lint/mozilla-root/sha1-ocsp-or-ca") &&
    has(lint(await sha1Cert({ basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
      extendedKeyUsage: ["clientAuth"] })), "lint/mozilla-root/sha1-ocsp-or-ca"));
  check("M9b. CONTROL: an end entity that is neither is not held to that row",
    !has(lint(await sha1Cert({})), "lint/mozilla-root/sha1-ocsp-or-ca"));
  // The clause names "intermediate certificates that chain up to roots in Mozilla's program", not
  // CA certificates, so a root's own self-signature is not one of the four things it lists.
  var sha1Root = spliceSignatureAlgorithm(await pki.x509.sign({ subject: [{ commonName: "A Root" }],
    subjectPublicKey: ecPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: ecPriv }),
    SHA1_RSA);
  check("M9e. a SHA-1 root self-signature is not one of the four the clause lists",
    !has(lint(sha1Root), "lint/mozilla-root/sha1-ocsp-or-ca"));
  var sha1Intermediate = spliceSignatureAlgorithm(await pki.x509.sign({
    subject: [{ commonName: "An Intermediate" }], subjectPublicKey: ecPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"],
      extendedKeyUsage: ["clientAuth"] } }, { cert: issuingCa, key: ecPriv }), SHA1_RSA);
  check("M9f. CONTROL: a SHA-1 intermediate still is",
    has(lint(sha1Intermediate), "lint/mozilla-root/sha1-ocsp-or-ca"));
  // Sec. 5.1.3 permits SHA-1 over an end entity only where it "contains an EKU extension that does
  // not contain the id-kp-serverAuth, id-kp-emailProtection, or anyExtendedKeyUsage key purposes",
  // so a SHA-1 certificate carrying one of the other two, or carrying no extKeyUsage at all, is
  // outside the allowance. The emailProtection arm has its own dated row.
  var outsideAllowance = [];
  var allowanceCases = [{ extendedKeyUsage: ["serverAuth"] },
    { extendedKeyUsage: ["anyExtendedKeyUsage"] }, { extendedKeyUsage: undefined }];
  for (var ai = 0; ai < allowanceCases.length; ai++) {
    outsideAllowance.push(has(lint(await sha1Cert(allowanceCases[ai])),
      "lint/mozilla-root/sha1-end-entity-outside-allowance"));
  }
  check("M9c. a SHA-1 end entity outside the allowance is reported (" + outsideAllowance.join(",") + ")",
    outsideAllowance.every(function (r) { return r === true; }));
  check("M9d. CONTROL: one inside the allowance is not, and an SHA-256 one is never read",
    !has(lint(await sha1Cert({ extendedKeyUsage: ["clientAuth"] })),
      "lint/mozilla-root/sha1-end-entity-outside-allowance") &&
    !has(lint(await sign({ extendedKeyUsage: ["serverAuth"] })),
      "lint/mozilla-root/sha1-end-entity-outside-allowance"));

  // ---- M10-M13: the sec. 5.2 practices --------------------------------------------------------
  // "a serial number greater than zero, containing at least 64 bits of output from a CSPRNG". The
  // CSPRNG half is unverifiable from bytes; eight magnitude octets is what is there to check.
  function serialCert(serialNumber) {
    return pki.x509.sign({ subject: [{ commonName: "S" }], subjectPublicKey: ecPub,
      serialNumber: serialNumber, notBefore: NB, notAfter: NA,
      extensions: { extendedKeyUsage: ["clientAuth"] } }, { key: ecPriv });
  }
  var shortSerials = [1n, 255n, 0x7fffffffffffffn];
  var shortReported = [];
  for (var si = 0; si < shortSerials.length; si++) {
    shortReported.push(has(lint(await serialCert(shortSerials[si])),
      "lint/mozilla-root/serial-number-short"));
  }
  check("M10. a serial number below eight magnitude octets is reported (" + shortReported.join(",") + ")",
    shortReported.every(function (r) { return r === true; }));
  check("M10c. CONTROL: eight magnitude octets satisfies it",
    !has(lint(await serialCert(0x7fffffffffffffffn)), "lint/mozilla-root/serial-number-short"));
  // The clause constrains the DRAW, not the integer: eight CSPRNG octets whose first is zero encode
  // to seven magnitude octets, which a conforming certificate does about once in 256. So the
  // magnitude row is a warning, and only the positivity half of the sentence is an error.
  check("M10d. the magnitude row is a warning, since a conforming draw can produce a short one",
    sevOf(lint(await serialCert(1n)), "lint/mozilla-root/serial-number-short") === "warn");
  // The signer refuses a zero serial, which is the signer doing its job, so it is spliced.
  var zeroSerial = spliceTbsField(await serialCert(1n), 1, Buffer.from("020100", "hex"));
  check("M10e. a serial number that is not greater than zero is an error",
    has(lint(zeroSerial), "lint/mozilla-root/serial-number-not-positive") &&
    sevOf(lint(zeroSerial), "lint/mozilla-root/serial-number-not-positive") === "error" &&
    !has(baseRep, "lint/mozilla-root/serial-number-not-positive"));
  check("M10b. CONTROL: the serial the signer draws by default satisfies it",
    !has(baseRep, "lint/mozilla-root/serial-number-insufficient-entropy"));
  check("M11. an end entity carrying no extKeyUsage is reported",
    has(await lintOver({ extendedKeyUsage: undefined }), "lint/mozilla-root/end-entity-eku-missing") &&
    !has(baseRep, "lint/mozilla-root/end-entity-eku-missing"));
  check("M12. an end entity naming anyExtendedKeyUsage is reported",
    has(await lintOver({ extendedKeyUsage: ["anyExtendedKeyUsage"] }),
      "lint/mozilla-root/end-entity-eku-any"));

  // ---- M14-M16: the sec. 5.3 intermediate rules, gated to 2019 --------------------------------
  function caCert(over, window) {
    var e = { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] };
    Object.keys(over || {}).forEach(function (k) {
      if (over[k] === undefined) delete e[k]; else e[k] = over[k];
    });
    var w = window || {};
    // Issued by another name, because sec. 5.3 governs intermediates and a certificate issued in
    // its own name is a root or the cross-certificate the clause exempts.
    return pki.x509.sign({ subject: [{ commonName: "An Intermediate" }], subjectPublicKey: ecPub,
      notBefore: w.notBefore || NB, notAfter: w.notAfter || NA, extensions: e },
      { cert: issuingCa, key: ecPriv });
  }
  check("M14. an intermediate carrying no extKeyUsage is reported",
    has(lint(await caCert({})), "lint/mozilla-root/intermediate-eku-missing"));
  check("M14b. CONTROL: gated to 1 January 2019",
    !has(lint(await caCert({}, { notBefore: new Date("2018-06-01T00:00:00Z"),
      notAfter: new Date("2018-12-01T00:00:00Z") })), "lint/mozilla-root/intermediate-eku-missing"));
  check("M15. an intermediate naming anyExtendedKeyUsage is reported",
    has(lint(await caCert({ extendedKeyUsage: ["anyExtendedKeyUsage"] })),
      "lint/mozilla-root/intermediate-eku-any"));
  check("M16. an intermediate naming both id-kp-serverAuth and id-kp-emailProtection is reported",
    has(lint(await caCert({ extendedKeyUsage: ["serverAuth", "emailProtection"] })),
      "lint/mozilla-root/intermediate-eku-server-and-email") &&
    !has(lint(await caCert({ extendedKeyUsage: ["serverAuth"] })),
      "lint/mozilla-root/intermediate-eku-server-and-email"));
  // Sec. 5.3 governs INTERMEDIATE certificates. A root is not one, and neither is the
  // cross-certificate the clause exempts, and both carry an issuer that equals their subject. A
  // certificate whose issuer and subject are the same name is left to the other rows.
  var selfIssued = await pki.x509.sign({ subject: [{ commonName: "A Root" }],
    subjectPublicKey: ecPub, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: ecPriv });
  check("M17. a self-issued CA certificate is held to none of the three intermediate rows",
    ["intermediate-eku-missing", "intermediate-eku-any", "intermediate-eku-server-and-email"]
      .every(function (id) { return !has(lint(selfIssued), "lint/mozilla-root/" + id); }));
  check("M17b. CONTROL: the same shape issued by another name is still reported",
    has(lint(await caCert({})), "lint/mozilla-root/intermediate-eku-missing"));
  // The under-report is a stated contract, not an accident: a rollover intermediate reissued in
  // its own name IS governed by sec. 5.3 and is passed over here, because the bytes do not tell it
  // from a root. Pinned so the reading is a decision rather than a drift.
  check("M17c. a self-issued rollover intermediate is passed over, which is the stated limit",
    !has(lint(selfIssued), "lint/mozilla-root/intermediate-eku-missing") &&
    lint(selfIssued).ran.indexOf("lint/mozilla-root/intermediate-eku-missing") === -1);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
