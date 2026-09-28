// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the NIST IR 8547 transition profile in pki.lint.certificate. RED conformance vectors
 * written BEFORE the rules, each driving the shipped verb and asserting the finding id.
 *
 * NIST IR 8547, "Transition to Post-Quantum Cryptography Standards", is an INITIAL PUBLIC DRAFT
 * (12 November 2024), so the dates are a draft's dates and the citation says so. Its Table 2 gives
 * every classical signature family a transition, and Table 4 repeats it for key establishment:
 * deprecated after 2030 at the 112-bit security strength, disallowed after 2035 at the 128-bit one.
 * IR 8547 does not map a strength onto a key size; SP 800-57 Part 1 Rev 5 Table 2 does, and the two
 * disagree about Ed25519, which N10 pins.
 *
 *   N1-N2    the profile is named, never detected, and enumerated
 *   N3-N5    the 2035 boundary, driven either side, on each classical family and on a PQC one
 *   N6-N10   the 2030 boundary, which applies at one strength and not the other
 *   N11      the signature algorithm is read as well as the subject key
 */

var helpers = require("../helpers");
var surgery = require("../helpers/der-surgery");
var signing = require("../helpers/signing");
var check = helpers.check;
var pki = helpers.pki;
var b = pki.asn1.build;
var crypto = require("node:crypto");

var DISALLOWED = "lint/nist-pqc-transition/classical-disallowed-after-2035";
var DEPRECATED = "lint/nist-pqc-transition/classical-deprecated-after-2030";

// "After 2030" and "after 2035" name whole years, so the boundaries are the first day of the year
// that follows each.
var BEFORE_2031 = new Date("2030-12-31T00:00:00Z");
var FROM_2031 = new Date("2031-01-01T00:00:00Z");
var BEFORE_2036 = new Date("2035-12-31T00:00:00Z");
var FROM_2036 = new Date("2036-01-01T00:00:00Z");
var NA = new Date("2045-01-01T00:00:00Z");

function ids(rep) { return rep.findings.map(function (f) { return f.id; }); }
function has(rep, id) { return ids(rep).indexOf(id) !== -1; }
function sevOf(rep, id) {
  var f = rep.findings.filter(function (x) { return x.id === id; })[0];
  return f && f.severity;
}
function lint(der) { return pki.lint.certificate(der, { profile: "nist-pqc-transition" }); }

async function run() {
  async function pair(spec) {
    var k = await pki.key.generate(spec);
    return { pub: await pki.key.export(k.publicKey), priv: await pki.key.export(k.privateKey) };
  }
  var rsa2048 = await pair({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" });
  var rsa3072 = await pair({ name: "RSASSA-PKCS1-v1_5", modulusLength: 3072, hash: "SHA-256" });
  var p256 = await pair({ name: "ECDSA", namedCurve: "P-256" });
  var ed = await pair("Ed25519");
  var mldsa = await pair("ML-DSA-87");

  /** A self-signed certificate, so the signature algorithm follows the subject key unless a test
   *  deliberately separates them. */
  function cert(key, notBefore) {
    return pki.x509.sign({ subject: [{ commonName: "A Transition Subject" }],
      subjectPublicKey: key.pub, notBefore: notBefore, notAfter: NA,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } },
      { key: key.priv });
  }

  // ---- N1-N2: named, never detected, enumerated ------------------------------------------------
  var classicalLate = await cert(rsa2048, FROM_2036);
  check("N1. the rows are inert unless the profile is named",
    !has(pki.lint.certificate(classicalLate), DISALLOWED) &&
    !has(pki.lint.certificate(classicalLate, { profile: "rfc5280" }), DISALLOWED) &&
    !has(pki.lint.certificate(classicalLate), DEPRECATED));
  check("N1b. and the profile refuses an artifact it does not lint",
    (function () {
      try { pki.lint.crl(Buffer.from([0x30, 0x00]), { profile: "nist-pqc-transition" }); return false; }
      catch (e) { return e.code === "lint/unknown-profile"; }
    })());
  // Every named profile also runs the shared extension-syntax row, whose source is its own, so the
  // profile's rows are the ones naming it as their source.
  var rows = pki.lint.rules("nist-pqc-transition");
  var own = rows.filter(function (r) { return r.source === "nist-pqc-transition"; });
  check("N2. rules() enumerates the profile's rows and profiles() lists it",
    own.length === 2 && pki.lint.profiles().indexOf("nist-pqc-transition") !== -1 &&
    own.every(function (r) { return typeof r.citation === "string" && r.citation.indexOf("IR 8547") !== -1; }) &&
    rows.some(function (r) { return r.id === "lint/rfc5280/extension-undecodable"; }));

  // ---- N3-N5: the 2035 boundary --------------------------------------------------------------
  // Table 2: every classical family is disallowed after 2035, at every parameter set it lists, so
  // this row needs no strength mapping at all.
  check("N3. a classical key issued from 2036 is an error, and one issued before is not",
    sevOf(lint(classicalLate), DISALLOWED) === "error" &&
    !has(lint(await cert(rsa2048, BEFORE_2036)), DISALLOWED));
  check("N4. the same holds for ECDSA and for EdDSA, which the table lists at 128 bits",
    sevOf(lint(await cert(p256, FROM_2036)), DISALLOWED) === "error" &&
    sevOf(lint(await cert(ed, FROM_2036)), DISALLOWED) === "error" &&
    !has(lint(await cert(p256, BEFORE_2036)), DISALLOWED) &&
    !has(lint(await cert(ed, BEFORE_2036)), DISALLOWED));
  check("N5. a post-quantum key is what the transition moves to, so no date reports it",
    !has(lint(await cert(mldsa, FROM_2036)), DISALLOWED) &&
    !has(lint(await cert(mldsa, FROM_2031)), DEPRECATED));

  // ---- N6-N10: the 2030 boundary, which needs the strength mapping ----------------------------
  // SP 800-57 Part 1 Rev 5 Table 2 puts an RSA modulus of 2048 at the 112-bit level and 3072 at the
  // 128-bit one, so the 2030 row reaches the first and not the second.
  check("N6. an RSA 2048 key issued from 2031 is a warning, and one issued before is not",
    sevOf(lint(await cert(rsa2048, FROM_2031)), DEPRECATED) === "warn" &&
    !has(lint(await cert(rsa2048, BEFORE_2031)), DEPRECATED));
  check("N7. an RSA 3072 key is at the 128-bit level, so 2031 does not reach it",
    !has(lint(await cert(rsa3072, FROM_2031)), DEPRECATED) &&
    sevOf(lint(await cert(rsa3072, FROM_2036)), DISALLOWED) === "error");
  check("N8. a P-256 key is at the 128-bit level too",
    !has(lint(await cert(p256, FROM_2031)), DEPRECATED));
  // A curve whose field is 224 to 255 bits is the 112-bit ECC row. The engine does not generate a
  // P-224 key, so the subject key comes from node's own generator: a real key on that curve, rather
  // than a larger key relabelled, because the field size is read from the point the key encodes and a
  // relabelled key would state one curve and carry another.
  var p224Spki = require("node:crypto").generateKeyPairSync("ec", { namedCurve: "secp224r1" })
    .publicKey.export({ format: "der", type: "spki" });
  var p224Cert = await pki.x509.sign({ subject: [{ commonName: "A Transition Subject" }],
    subjectPublicKey: p224Spki, notBefore: FROM_2031, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"] } },
    { name: [{ commonName: "A Post-Quantum Issuer" }], publicKey: mldsa.pub, key: mldsa.priv });
  check("N9. CONTROL: the certificate parses and carries an elliptic-curve subject key",
    pki.schema.x509.parse(p224Cert).subjectPublicKeyInfo.algorithm.name === "ecPublicKey" &&
    !has(lint(p224Cert), "lint/unparseable"));
  check("N9b. a curve at the 112-bit level is deprecated from 2031",
    sevOf(lint(p224Cert), DEPRECATED) === "warn");
  // IR 8547's EdDSA row carries a 128-bit entry alone, with no 112-bit entry and no 2030
  // deprecation. Reading SP 800-57's ECC column instead would put Ed25519's 255-bit field in the
  // 112-bit row and deprecate it after 2030; the profile cites IR 8547, so it follows IR 8547.
  check("N10. Ed25519 is not deprecated after 2030, which is IR 8547's table rather than SP 800-57's",
    !has(lint(await cert(ed, FROM_2031)), DEPRECATED) &&
    sevOf(lint(await cert(ed, FROM_2036)), DISALLOWED) === "error");

  // ---- N11: the signature algorithm is read too ------------------------------------------------
  // A certificate carries two algorithms, and the transition covers both: a post-quantum subject key
  // signed with a classical one still leaves a classical signature to be verified after the date.
  var mldsaSignedByRsa = await pki.x509.sign({ subject: [{ commonName: "A Transition Subject" }],
    subjectPublicKey: mldsa.pub, notBefore: FROM_2036, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"] } },
    { name: [{ commonName: "A Classical Issuer" }], publicKey: rsa2048.pub, key: rsa2048.priv });
  check("N11. a classical signature over a post-quantum key is reported on the signature",
    sevOf(lint(mldsaSignedByRsa), DISALLOWED) === "error");
  var rsaSignedByMldsa = await pki.x509.sign({ subject: [{ commonName: "A Transition Subject" }],
    subjectPublicKey: rsa3072.pub, notBefore: FROM_2036, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"] } },
    { name: [{ commonName: "A Post-Quantum Issuer" }], publicKey: mldsa.pub, key: mldsa.priv });
  check("N11b. and on the subject key when that is the classical one",
    sevOf(lint(rsaSignedByMldsa), DISALLOWED) === "error");
  check("N11c. CONTROL: both post-quantum draws neither row",
    !has(lint(await cert(mldsa, FROM_2036)), DISALLOWED));

  // ---- N12: the classifier covers every key a CERTIFICATE can carry ----------------------------
  // The row reads a table of algorithm names, and a name absent from it is passed over rather than
  // called classical. That is the right answer for a family the tables do not date and the wrong one
  // for a classical family the table forgot, so every subject key is driven through the shipped verb.
  // The set is what a certificate can CARRY rather than what this engine generates: reading it as the
  // engine's own key types left DSA and Diffie-Hellman out, which is exactly where the table's first
  // gap was. Node's generator supplies those three. Each is signed by the ML-DSA issuer, so the
  // verdict belongs to the subject key alone.
  var pqcIssuer = { name: [{ commonName: "A Post-Quantum Issuer" }], publicKey: mldsa.pub, key: mldsa.priv };
  function nodeSpki(kind, opts) {
    return crypto.generateKeyPairSync(kind, opts).publicKey.export({ format: "der", type: "spki" });
  }
  var SUBJECT_KEYS = [
    ["RSASSA-PKCS1-v1_5", { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" }, "classical"],
    ["RSA-PSS", { name: "RSA-PSS", modulusLength: 2048, hash: "SHA-256" }, "classical"],
    ["RSA-OAEP", { name: "RSA-OAEP", modulusLength: 2048, hash: "SHA-256" }, "classical"],
    ["ECDSA", { name: "ECDSA", namedCurve: "P-256" }, "classical"],
    ["ECDH", { name: "ECDH", namedCurve: "P-256" }, "classical"],
    ["Ed25519", "Ed25519", "classical"],
    ["Ed448", "Ed448", "classical"],
    ["X25519", "X25519", "classical"],
    ["X448", "X448", "classical"],
    ["ML-DSA-87", "ML-DSA-87", "pqc"],
    ["ML-KEM-1024", "ML-KEM-1024", "pqc"],
    ["SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S", "pqc"],
    ["DSA (2048/224)", nodeSpki("dsa", { modulusLength: 2048, divisorLength: 224 }), "classical"],
    ["DH dhKeyAgreement (2048)", nodeSpki("dh", { primeLength: 2048 }), "classical"],
    ["DH 3072", nodeSpki("dh", { primeLength: 3072 }), "classical"],
  ];
  var unclassified = [];
  for (var i = 0; i < SUBJECT_KEYS.length; i++) {
    var row = SUBJECT_KEYS[i];
    var spki = Buffer.isBuffer(row[1]) ? row[1]
      : await pki.key.export((await pki.key.generate(row[1])).publicKey);
    var der = await pki.x509.sign({ subject: [{ commonName: "A Transition Subject" }],
      subjectPublicKey: spki, notBefore: FROM_2036, notAfter: NA,
      extensions: { keyUsage: ["digitalSignature"] } }, pqcIssuer);
    var reported = has(lint(der), DISALLOWED);
    if (reported !== (row[2] === "classical")) unclassified.push(row[0] + " read as " + (reported ? "classical" : "not classical"));
  }
  check("N12. every key a certificate can carry is classified (" +
    (unclassified.join(", ") || "all " + SUBJECT_KEYS.length + " as expected") + ")",
    unclassified.length === 0);

  // ---- N12b: the 112-bit level in the third family the tables list -----------------------------
  // Table 4 lists finite-field DH and MQV beside the RSA and ECC rows, and SP 800-57's FFC column
  // states the level as L, the field prime's bit length. A row reading only the RSA modulus and the
  // curve left every DSA and Diffie-Hellman key outside the deprecation it promises.
  async function ffcCert(spki, notBefore) {
    return pki.x509.sign({ subject: [{ commonName: "An FFC Subject" }], subjectPublicKey: spki,
      notBefore: notBefore, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] } }, pqcIssuer);
  }
  var dsa2048 = nodeSpki("dsa", { modulusLength: 2048, divisorLength: 224 });
  var dh2048 = nodeSpki("dh", { primeLength: 2048 });
  var dh3072 = nodeSpki("dh", { primeLength: 3072 });
  check("N12b. a finite-field key at L of 2048 is deprecated from 2031, in both spellings",
    sevOf(lint(await ffcCert(dsa2048, FROM_2031)), DEPRECATED) === "warn" &&
    sevOf(lint(await ffcCert(dh2048, FROM_2031)), DEPRECATED) === "warn" &&
    !has(lint(await ffcCert(dsa2048, BEFORE_2031)), DEPRECATED));
  check("N12c. and one at L of 3072 is at the 128-bit level, so 2031 does not reach it",
    !has(lint(await ffcCert(dh3072, FROM_2031)), DEPRECATED) &&
    sevOf(lint(await ffcCert(dh3072, FROM_2036)), DISALLOWED) === "error");
  // SP 800-57 Table 2 states the finite-field level as a PAIR: 112 bits is L of 2048 WITH N of 224, and
  // 128 bits is L of 3072 with N of 256. So either parameter caps the strength, and a group with a
  // 3072-bit prime and a 224-bit subgroup is a 112-bit key however large its prime is.
  var dsa3072n224 = nodeSpki("dsa", { modulusLength: 3072, divisorLength: 224 });
  var dsa3072n256 = nodeSpki("dsa", { modulusLength: 3072, divisorLength: 256 });
  check("N12d. a subgroup order of 224 caps the strength whatever the prime's length",
    sevOf(lint(await ffcCert(dsa3072n224, FROM_2031)), DEPRECATED) === "warn" &&
    !has(lint(await ffcCert(dsa3072n256, FROM_2031)), DEPRECATED) &&
    sevOf(lint(await ffcCert(dsa3072n256, FROM_2036)), DISALLOWED) === "error");
  // A shape that states no subgroup order settles the question on its prime, which is all it states.
  check("N12e. CONTROL: a PKCS#3 group carries no subgroup order and is read on its prime",
    sevOf(lint(await ffcCert(dh2048, FROM_2031)), DEPRECATED) === "warn" &&
    !has(lint(await ffcCert(dh3072, FROM_2031)), DEPRECATED));

  // ---- N12f: the curve's field, read off the key rather than off a list of curve names ----------
  // SP 800-57's ECC column states the level as a field size, and a certificate can be on any curve a
  // CA chose. A table of curve names left the ones nobody had added outside the deprecation, so the
  // size is read from the encoded point, which carries it for every curve.
  var CURVES = [
    ["secp224r1", true], ["brainpoolP224r1", true], ["sect233r1", true], ["prime239v1", true],
    ["prime256v1", false], ["brainpoolP256r1", false], ["secp384r1", false], ["secp521r1", false],
  ];
  var curveWrong = [];
  for (var c = 0; c < CURVES.length; c++) {
    var name = CURVES[c][0], expectDeprecated = CURVES[c][1];
    var spkiDer;
    try { spkiDer = nodeSpki("ec", { namedCurve: name }); }
    catch (_e) { curveWrong.push(name + " could not be generated"); continue; }
    var certDer = await ffcCert(spkiDer, FROM_2031);
    if (has(lint(certDer), DEPRECATED) !== expectDeprecated) {
      curveWrong.push(name + (expectDeprecated ? " not reported" : " reported"));
    }
  }
  check("N12f. a curve at or below the 112-bit field size is deprecated, whichever curve it is (" +
    (curveWrong.join(", ") || CURVES.length + " curves as expected") + ")",
    curveWrong.length === 0);

  // ---- N13: a composite signature is the transition, not a breach of it ------------------------
  // A composite identifier names two algorithms, one of them classical, and IR 8547's tables list
  // pure families. The guidance the profile cites endorses "hybrid and dual-algorithm operation
  // through the transition", so a certificate signed under a composite arm is passed over rather than
  // reported for the traditional half of the construction that exists to carry it across these dates.
  var arm = "id-MLDSA65-ECDSA-P256-SHA512";
  var cs = signing.makeCompositeSigner(arm);
  var compositeCert = await pki.x509.sign({ subject: [{ commonName: "A Composite Subject" }],
    subjectPublicKey: cs.spki, notBefore: FROM_2036, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: cs.key });
  check("N13. CONTROL: the composite certificate parses and its signature is the composite arm",
    !has(lint(compositeCert), "lint/unparseable") &&
    pki.schema.x509.parse(compositeCert).signatureAlgorithm.oid === pki.oid.byName(arm));
  check("N13b. a composite signature is passed over at both dates",
    !has(lint(compositeCert), DISALLOWED) && !has(lint(compositeCert), DEPRECATED));

  // ---- N14: no classical signature identifier the registry knows escapes the 2036 row ----------
  // The row reads a family off the algorithm's OID, and the risk is a family it fails to read at all,
  // which is silence rather than a wrong answer. So every name in the OID registry that reads as an
  // RSA, DSA, ECDSA, EdDSA or Diffie-Hellman algorithm is spliced into a certificate's signature
  // fields and driven through the shipped verb: each must be reported. The name heuristic is the
  // ORACLE here rather than the implementation, which is what makes it useful, and each exclusion
  // below is an identifier that is not an algorithm either field can name, with the reason.
  var NOT_A_CERTIFICATE_ALGORITHM = {
    sha1: "a digest, sharing the OIW arc with the RSA signatures",
    rsaKeyLen: "an attribute carrying a key length, not an algorithm",
    rsaKeyTransport: "a CMS content-encryption algorithm",
    dhBasedMac: "a CMP message authentication code",
    "id-alg-dhPOP": "a proof-of-possession algorithm, not a signature",
    "id-dhPop-static-HMAC-SHA1": "the same, in its static form",
  };
  var registry = pki.oid.all();
  var classicalNames = Object.keys(registry).filter(function (dotted) {
    var n = String(registry[dotted]);
    if (NOT_A_CERTIFICATE_ALGORITHM[n]) return false;
    // A key-agreement scheme names a KDF rather than a certificate algorithm.
    if (n.indexOf("dhSinglePass-") === 0) return false;
    // A composite arm is deliberately outside both rows, which N13 pins.
    if (n.indexOf("id-MLDSA") === 0 || n.indexOf("id-MLKEM") === 0) return false;
    var l = n.toLowerCase();
    return l.indexOf("rsa") !== -1 || l.indexOf("dsa") !== -1 ||
      l.indexOf("dh") !== -1 || n === "Ed25519" || n === "Ed448" || n === "X25519" || n === "X448" ||
      n === "ecPublicKey";
  }).filter(function (dotted) {
    // The post-quantum families carry "dsa" in their names and are what the transition moves to.
    var n = String(registry[dotted]);
    return !(n.indexOf("id-ml-dsa-") === 0 || n.indexOf("id-slh-dsa-") === 0 ||
      n.indexOf("id-hash-slh-dsa-") === 0 || n.indexOf("id-hash-ml-dsa-") === 0 ||
      n.indexOf("id-ml-kem-") === 0);
  });
  // The signature identifier is rewritten in both places a certificate carries it, since the parser
  // refuses a certificate whose two disagree.
  var mldsaSigOid = b.oid(pki.oid.byName("id-ml-dsa-87"));
  function withSignatureOid(der, dotted) {
    var replacement = b.sequence([b.oid(dotted)]);
    return surgery.patch(der, function (n) {
      if (n.tagClass !== "universal" || n.tagNumber !== 16 || !n.children) return undefined;
      if (n.children.length !== 1 || !mldsaSigOid.equals(n.children[0].bytes)) return undefined;
      return replacement;
    });
  }
  var pqcSubjectAt2036 = await pki.x509.sign({ subject: [{ commonName: "A Transition Subject" }],
    subjectPublicKey: mldsa.pub, notBefore: FROM_2036, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"] } },
    { name: [{ commonName: "A Post-Quantum Issuer" }], publicKey: mldsa.pub, key: mldsa.priv });
  var escaped = [], unreadable = 0;
  classicalNames.forEach(function (dotted) {
    var der = withSignatureOid(pqcSubjectAt2036, dotted);
    var rep = lint(der);
    if (has(rep, "lint/unparseable")) { unreadable += 1; return; }
    if (!has(rep, DISALLOWED)) escaped.push(registry[dotted] + " (" + dotted + ")");
  });
  check("N14. every classical algorithm identifier the registry names is reported after 2035 (" +
    classicalNames.length + " read, " + unreadable + " refused at parse, escaped: " +
    (escaped.join(", ") || "none") + ")",
    classicalNames.length > 60 && escaped.length === 0);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
