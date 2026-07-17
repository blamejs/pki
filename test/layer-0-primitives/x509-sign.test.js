// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for pki.x509.sign -- the X.509 certificate-issuance producing side
// (RFC 5280 sec. 4). Every vector drives the shipped consumer pki.x509.sign(spec, issuer, opts)
// and asserts through pki.schema.x509.parse round-trip, pki.path.validate, or err.code. Keys come
// from the makeSigner / makeCompositeSigner helpers (real runtime keypairs, every algorithm arm).

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;
var asn1 = pki.asn1;

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2030-01-01T00:00:00Z");
var IN_WINDOW = new Date("2027-06-01T00:00:00Z");

// A self-signed anchor tuple path.validate accepts for a cert we just issued.
function anchorFor(cert) {
  return { name: cert.subject, publicKey: cert.subjectPublicKeyInfo.bytes, algorithm: cert.subjectPublicKeyInfo.algorithm.oid };
}

// ---- round-trip + byte-stability -------------------------------------------

async function testRoundTrip() {
  var s = makeSigner("ec-p256");
  var der = await pki.x509.sign({
    serialNumber: 0x1234n,
    subject: "Test Root",
    subjectPublicKey: s.spki,
    notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true },
  }, { key: s.key });

  check("sign returns a Buffer", Buffer.isBuffer(der));
  var c = pki.schema.x509.parse(der);
  check("round-trip version = 3", c.version === 3);
  check("round-trip serialNumberHex", c.serialNumberHex === "1234");
  check("round-trip subject CN", /Test Root/.test(c.subject.dn));
  check("self-signed issuer == subject", c.issuer.dn === c.subject.dn);
  check("round-trip notBefore Date", c.validity.notBefore.getTime() === NB.getTime());
  check("round-trip notAfter Date", c.validity.notAfter.getTime() === NA.getTime());
  check("round-trip SPKI bytes", Buffer.compare(c.subjectPublicKeyInfo.bytes, s.spki) === 0);
  check("round-trip has 3 extensions", c.extensions.length === 3);

  // tbsBytes is the exact signed range -- re-parsing must recover the identical bytes that were signed.
  var reparsed = pki.schema.x509.parse(der);
  check("tbsBytes byte-stable across re-parse", Buffer.compare(c.tbsBytes, reparsed.tbsBytes) === 0);

  // inner tbs.signature == outer signatureAlgorithm (RFC 5280 sec. 4.1.1.2) -- else parse throws.
  check("inner==outer sig alg (parse accepted)", c.signatureAlgorithm.name === c.tbsSignatureAlgorithm.name);
}

async function testPemOutput() {
  var s = makeSigner("ed25519");
  var pem = await pki.x509.sign({ subject: "PEM", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { key: s.key }, { pem: true });
  check("opts.pem returns a string", typeof pem === "string");
  check("opts.pem has BEGIN CERTIFICATE", /-----BEGIN CERTIFICATE-----/.test(pem));
  var der = pki.schema.x509.pemDecode(pem);
  check("PEM decodes to a parseable cert", pki.schema.x509.parse(der).subject.dn.length > 0);
}

// ---- independent verification (path.validate) ------------------------------

async function testSelfSignedValidates() {
  var s = makeSigner("ed25519");
  var der = await pki.x509.sign({
    subject: "Root CA", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: s.key });
  var c = pki.schema.x509.parse(der);
  var res = await pki.path.validate([c], { time: IN_WINDOW, trustAnchor: anchorFor(c) });
  check("self-signed cert path.validate valid", res.valid === true);

  // flip one signed byte -> signature must fail.
  var bad = Buffer.from(der); bad[bad.length - 1] ^= 0xff;
  var resBad = await pki.path.validate([pki.schema.x509.parse(bad)], { time: IN_WINDOW, trustAnchor: anchorFor(c) });
  check("tampered signature -> invalid", resBad.valid === false);
}

async function testCaSignedLeaf() {
  var ca = makeSigner("ec-p256");
  var caDer = await pki.x509.sign({
    subject: "Issuing CA", subjectPublicKey: ca.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"], subjectKeyIdentifier: true },
  }, { key: ca.key });
  var caCert = pki.schema.x509.parse(caDer);

  var leaf = makeSigner("ed25519");
  var leafDer = await pki.x509.sign({
    subject: "leaf.example.com", subjectPublicKey: leaf.spki, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], subjectAltName: [{ dNSName: "leaf.example.com" }], authorityKeyIdentifier: true },
  }, { cert: caCert, key: ca.key });
  var leafCert = pki.schema.x509.parse(leafDer);

  check("leaf issuer dnEquals CA subject", leafCert.issuer.dn === caCert.subject.dn);
  // The RFC 5280 path excludes the anchor: the leaf, issued directly by the CA, validates to the CA anchor.
  var res = await pki.path.validate([leafCert], { time: IN_WINDOW, trustAnchor: anchorFor(caCert) });
  check("CA-signed leaf validates to the CA anchor", res.valid === true);
}

// ---- every algorithm arm ---------------------------------------------------

async function testAlgorithmArms() {
  var arms = ["rsa", "rsa-pss", "ec-p256", "ec-p384", "ec-p521", "ed25519", "ed448",
    "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
    "slh-dsa-sha2-128f", "slh-dsa-shake-256s"];
  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = makeSigner(alg);
    var opts = alg === "rsa-pss" ? { pss: true } : {};
    var der = await pki.x509.sign({
      subject: alg + " signer", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
    }, { key: s.key }, opts);
    var c = pki.schema.x509.parse(der);
    var res = await pki.path.validate([c], { time: IN_WINDOW, trustAnchor: anchorFor(c) });
    check(alg + " self-signed cert verifies", res.valid === true);
  }
}

async function testCompositeArm() {
  // Use one supported composite arm from the helper.
  var arm = "id-MLDSA65-ECDSA-P256-SHA512";
  var cs;
  try { cs = makeCompositeSigner(arm); }
  catch (_e) { check("composite arm " + arm + " available", false); return; }
  var der = await pki.x509.sign({
    subject: "composite CA", subjectPublicKey: cs.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: cs.key });
  var c = pki.schema.x509.parse(der);
  var res = await pki.path.validate([c], { time: IN_WINDOW, trustAnchor: anchorFor(c) });
  check("composite self-signed cert verifies", res.valid === true);
  // a mismatched composite signer (a different composite key pair claiming this SPKI) fails the
  // post-sign composite verify -- the certificate would not chain.
  var cs2 = makeCompositeSigner(arm);
  check("mismatched composite signer -> x509/bad-input",
    await codeOf(pki.x509.sign({ subject: "composite", subjectPublicKey: cs.spki, notBefore: NB, notAfter: NA }, { name: "CA", publicKey: cs.spki, key: cs2.key })) === "x509/bad-input");
}

// ---- version coherence -----------------------------------------------------

async function testVersionCoherence() {
  var s = makeSigner("ed25519");
  // no extensions -> v1, and the [0] version tag is OMITTED (DER DEFAULT).
  var v1 = await pki.x509.sign({ subject: "v1", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { key: s.key });
  var c1 = pki.schema.x509.parse(v1);
  check("no extensions -> version 1", c1.version === 1);
  // the raw tbs must have no context-[0] version wrapper as its first element (it is the serial INTEGER).
  var tbs = asn1.decode(v1).children[0];
  check("v1 omits the [0] version tag", !(tbs.children[0].tagClass === "context" && tbs.children[0].tagNumber === 0));

  // extensions -> v3.
  var v3 = await pki.x509.sign({ subject: "v3", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] } }, { key: s.key });
  check("extensions -> version 3", pki.schema.x509.parse(v3).version === 3);
}

// ---- serial bounds (RFC 5280 sec. 4.1.2.2) ---------------------------------

async function testSerialBounds() {
  var s = makeSigner("ed25519");
  var base = { subject: "serial", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA };
  check("serial 0 -> x509/bad-serial", await codeOf(pki.x509.sign(Object.assign({ serialNumber: 0n }, base), { key: s.key })) === "x509/bad-serial");
  check("serial negative -> x509/bad-serial", await codeOf(pki.x509.sign(Object.assign({ serialNumber: -5n }, base), { key: s.key })) === "x509/bad-serial");
  // 21-octet serial (magnitude needs 21 content octets) -> rejected.
  var big = BigInt("0x" + "ff".repeat(21));
  check("21-octet serial -> x509/bad-serial", await codeOf(pki.x509.sign(Object.assign({ serialNumber: big }, base), { key: s.key })) === "x509/bad-serial");
  // a valid 20-octet positive serial is accepted.
  var ok = BigInt("0x7f" + "ab".repeat(19));
  var der = await pki.x509.sign(Object.assign({ serialNumber: ok }, base), { key: s.key });
  check("20-octet serial accepted", pki.schema.x509.parse(der).serialNumberHex === ok.toString(16));
}

// ---- validity encoding auto-selection (RFC 5280 sec. 4.1.2.5) --------------

async function testValidityEncoding() {
  var s = makeSigner("ed25519");
  // notBefore 2048 -> UTCTime; notAfter 2051 -> GeneralizedTime (one cert mixes arms).
  var der = await pki.x509.sign({
    subject: "validity", subjectPublicKey: s.spki,
    notBefore: new Date("2048-06-01T00:00:00Z"), notAfter: new Date("2051-06-01T00:00:00Z"),
  }, { key: s.key });
  // locate the validity SEQUENCE (v1: [serial, sigAlg, issuer, VALIDITY, subject, spki]).
  var tbs = asn1.decode(der).children[0];
  var val = tbs.children[3];   // v1 (no [0]): index 3 is validity
  check("notBefore <=2049 is UTCTime", val.children[0].tagClass === "universal" && val.children[0].tagNumber === 23);
  check("notAfter >=2050 is GeneralizedTime", val.children[1].tagClass === "universal" && val.children[1].tagNumber === 24);
  var c = pki.schema.x509.parse(der);
  check("mixed-arm validity round-trips notBefore", c.validity.notBefore.getUTCFullYear() === 2048);
  check("mixed-arm validity round-trips notAfter", c.validity.notAfter.getUTCFullYear() === 2051);

  // Invalid Date -> throws.
  check("Invalid Date notAfter -> throws", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: new Date("nonsense") }, { key: s.key })) !== null);
  // notBefore after notAfter -> config-time reject.
  check("notBefore after notAfter -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NA, notAfter: NB }, { key: s.key })) === "x509/bad-input");
}

// ---- DER canonical / cross-field -------------------------------------------

async function testDerCanonical() {
  var s = makeSigner("ed25519");
  // basicConstraints cA=FALSE (default) -> the cA field is OMITTED (empty SEQUENCE).
  var der = await pki.x509.sign({
    subject: "ee", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: false }, keyUsage: ["digitalSignature"] },
  }, { key: s.key });
  var c = pki.schema.x509.parse(der);
  var bc = c.extensions.filter(function (x) { return (x.name || x.oid) === "basicConstraints"; })[0];
  check("basicConstraints present", !!bc);
  // decode the extnValue: cA=FALSE must be an empty SEQUENCE (no boolean).
  var bcVal = asn1.decode(bc.value);
  check("cA=FALSE omits the boolean (empty BasicConstraints SEQUENCE)", bcVal.children.length === 0);

  // a critical extension emits critical TRUE; a non-critical one omits the boolean. keyUsage is critical.
  var kuExt = c.extensions.filter(function (x) { return (x.name || x.oid) === "keyUsage"; })[0];
  check("keyUsage critical", kuExt.critical === true);
  check("basicConstraints critical (CA policy default)", bc.critical === true);
}

async function testKeyUsageMinimalBits() {
  var s = makeSigner("ed25519");
  // digitalSignature (bit 0) only -> minimal BIT STRING: 1 value byte 0x80, unused-bits 7.
  var der = await pki.x509.sign({
    subject: "ku", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"] },
  }, { key: s.key });
  var c = pki.schema.x509.parse(der);
  var ku = c.extensions.filter(function (x) { return (x.name || x.oid) === "keyUsage"; })[0];
  var bs = asn1.decode(ku.value);
  check("keyUsage digitalSignature: unused-bits 7", bs.content[0] === 7);
  check("keyUsage digitalSignature: single 0x80 byte", bs.content.length === 2 && bs.content[1] === 0x80);
}

// ---- cross-field CA coherence ----------------------------------------------

async function testCaCrossField() {
  var s = makeSigner("ed25519");
  var base = { subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA };
  // keyCertSign without cA=TRUE -> config-time throw.
  check("keyCertSign without cA -> throws", await codeOf(pki.x509.sign(Object.assign({ extensions: { keyUsage: ["keyCertSign"], basicConstraints: { cA: false } } }, base), { key: s.key })) !== null);
  // pathLen without cA -> throws.
  check("pathLen without cA -> throws", await codeOf(pki.x509.sign(Object.assign({ extensions: { basicConstraints: { cA: false, pathLen: 2 } } }, base), { key: s.key })) !== null);
  // a proper CA cert with pathLen 0 is accepted.
  var der = await pki.x509.sign(Object.assign({ extensions: { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign"] } }, base), { key: s.key });
  check("CA with pathLen 0 accepted", pki.schema.x509.parse(der).version === 3);
}

// ---- fail-closed -----------------------------------------------------------

async function testFailClosed() {
  var s = makeSigner("ed25519");
  var base = { subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA };
  // empty issuer DN (explicit empty array) -> x509/bad-issuer.
  check("empty issuer -> x509/bad-issuer", await codeOf(pki.x509.sign(base, { name: [], key: s.key, publicKey: s.spki })) === "x509/bad-issuer");
  // a key/scheme mismatch (sign an EC-keyed cert with an Ed25519 private key) -> x509/bad-input.
  var ec = makeSigner("ec-p256");
  check("key mismatch -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: ec.spki, notBefore: NB, notAfter: NA }, { name: "x", publicKey: ec.spki, key: s.key })) === "x509/bad-input");
  // missing subjectPublicKey -> throws.
  check("missing subjectPublicKey -> throws", await codeOf(pki.x509.sign({ subject: "x", notBefore: NB, notAfter: NA }, { key: s.key })) !== null);
  // a typo'd extension key is rejected at config-time (not silently dropped).
  check("unknown extension key -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: { keyUsag: ["digitalSignature"] } }, { key: s.key })) === "x509/bad-input");
  // a malformed subject SPKI is rejected at issuance (validated before it is embedded raw).
  var B = pki.asn1.build;
  check("non-DER subjectPublicKey -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: Buffer.from([0x30, 0x05]), notBefore: NB, notAfter: NA }, { key: s.key })) === "x509/bad-input");   // truncated SEQUENCE
  check("structurally-wrong subjectPublicKey -> typed x509/* error", /^x509\//.test(await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: B.sequence([B.integer(1n), B.integer(2n)]), notBefore: NB, notAfter: NA }, { key: s.key })) || ""));
  // a malformed pre-encoded extension is rejected before signing.
  check("malformed pre-encoded extension -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: [B.sequence([B.integer(1n)])] }, { key: s.key })) === "x509/bad-input");
  // a malformed raw Name DER (the escape hatch) is validated before embedding.
  check("non-DER raw subject Name -> x509/bad-name", await codeOf(pki.x509.sign({ subject: Buffer.from([1, 2, 3]), subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { key: s.key })) === "x509/bad-name");
  check("structurally-wrong raw Name (RDN not a SET) -> x509/bad-rdn", await codeOf(pki.x509.sign({ subject: B.sequence([B.integer(1n)]), subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { key: s.key })) === "x509/bad-rdn");
  // duplicate extension in the array form is rejected (RFC 5280 sec. 4.2).
  var kuExt = B.sequence([B.oid(pki.oid.byName("keyUsage")), B.octetString(B.namedBitString([0]))]);
  check("duplicate extension in the array form -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: [kuExt, kuExt] }, { key: s.key })) === "x509/bad-input");
  // a pre-encoded extension with an explicit critical=FALSE is non-canonical DER (DEFAULT must be omitted).
  var critFalse = B.sequence([B.oid(pki.oid.byName("keyUsage")), B.boolean(false), B.octetString(B.namedBitString([0]))]);
  check("pre-encoded extension with explicit critical=FALSE -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: [critFalse] }, { key: s.key })) === "x509/bad-input");
  // countryName must be a two-letter ISO 3166 code.
  check("countryName not 2 chars -> x509/bad-name", await codeOf(pki.x509.sign({ subject: [{ countryName: "USA" }], subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { key: s.key })) === "x509/bad-name");
  check("countryName of 2 chars accepted", Buffer.isBuffer(await pki.x509.sign({ subject: [{ countryName: "US" }], subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { key: s.key })));
  // a recognized array extension whose value is malformed is fully validated by its real decoder and
  // fails closed with that decoder's typed x509/* code (not a raw asn1 error).
  var badBc = B.sequence([B.oid(pki.oid.byName("basicConstraints")), B.octetString(Buffer.from([0x30, 0x05]))]);   // value is a truncated SEQUENCE
  check("malformed basicConstraints value in the array form -> x509/bad-basic-constraints", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: [badBc] }, { key: s.key })) === "x509/bad-basic-constraints");
  // a pre-encoded basicConstraints that encodes an explicit cA=FALSE is rejected by the real decoder.
  var bcFalseExplicit = B.sequence([B.oid(pki.oid.byName("basicConstraints")), B.octetString(B.sequence([B.boolean(false)]))]);
  check("pre-encoded basicConstraints with explicit cA=FALSE -> x509/bad-basic-constraints", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: [bcFalseExplicit] }, { key: s.key })) === "x509/bad-basic-constraints");
  // a DN attribute value with characters invalid for its string type fails closed as a typed x509/bad-name.
  check("emailAddress with non-ASCII -> x509/bad-name", await codeOf(pki.x509.sign({ subject: [{ emailAddress: "tëst@example.com" }], subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { key: s.key })) === "x509/bad-name");
  // an issuer certificate that is not a CA cannot sign certificates -> rejected.
  var iss = makeSigner("ec-p256");
  var notCaCert = pki.schema.x509.parse(await pki.x509.sign({ subject: "Not A CA", subjectPublicKey: iss.spki, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] } }, { key: iss.key }));
  check("non-CA issuer.cert -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "leaf", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { cert: notCaCert, key: iss.key })) === "x509/bad-input");
  var caNoKcs = pki.schema.x509.parse(await pki.x509.sign({ subject: "CRL-only CA", subjectPublicKey: iss.spki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["cRLSign"] } }, { key: iss.key }));
  check("CA issuer.cert without keyCertSign -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "leaf", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { cert: caNoKcs, key: iss.key })) === "x509/bad-input");
  // basicConstraints spec is validated strictly (a truthy non-boolean cA, or an unknown field, is rejected).
  check("basicConstraints cA non-boolean -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: 1 } } }, { key: s.key })) === "x509/bad-input");
  check("unknown basicConstraints field -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true, foo: 1 } } }, { key: s.key })) === "x509/bad-input");
  // RFC 5280 sec. 4.2.1.9 -- a CA's basicConstraints MUST be critical, on OUTPUT and on an issuer input.
  check("issuing a CA with critical:false -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true, critical: false }, keyUsage: ["keyCertSign"] } }, { key: s.key })) === "x509/bad-input");
  // an externally-built CA with NON-critical basicConstraints is rejected as an issuer (x509.sign cannot mint one).
  var Bf = pki.asn1.build, Of = pki.oid.byName;
  var nonCritBc = Bf.sequence([Bf.oid(Of("basicConstraints")), Bf.octetString(Bf.sequence([Bf.boolean(true)]))]);   // cA=true, critical omitted
  var kcsKu = Bf.sequence([Bf.oid(Of("keyUsage")), Bf.boolean(true), Bf.octetString(Bf.namedBitString([5]))]);
  var nonCritBcCa = pki.schema.x509.parse(signing.minimalCert(iss.spki, { cn: "NonCrit CA", exts: [nonCritBc, kcsKu] }));
  check("issuer.cert with non-critical basicConstraints -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "leaf", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { cert: nonCritBcCa, key: iss.key })) === "x509/bad-input");
  // A pathLen=0 issuer forbids a CA below it but allows a leaf.
  var pl0Ca = pki.schema.x509.parse(await pki.x509.sign({ subject: "PathLen0 CA", subjectPublicKey: iss.spki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true, pathLen: 0 }, keyUsage: ["keyCertSign"] } }, { key: iss.key }));
  check("pathLen=0 issuer issuing a CA -> x509/bad-input", await codeOf(pki.x509.sign({ subject: "sub CA", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { cert: pl0Ca, key: iss.key })) === "x509/bad-input");
  check("pathLen=0 issuer issuing a leaf is accepted", Buffer.isBuffer(await pki.x509.sign({ subject: "leaf", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] } }, { cert: pl0Ca, key: iss.key })));
  // a self-issued CA rollover (subject == issuer) does not consume path length -> accepted at pathLen 0.
  var rolloverKey = makeSigner("ed25519");
  check("pathLen=0 issuer issuing a self-issued CA rollover is accepted", Buffer.isBuffer(await pki.x509.sign({ subject: "PathLen0 CA", subjectPublicKey: rolloverKey.spki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { cert: pl0Ca, key: iss.key })));
}

// ---- OpenSSL interop (a new certificate wire format -> an independent verifier) ----

var cp = require("node:child_process");
var os = require("node:os");
var fsMod = require("node:fs");
var pathMod = require("node:path");
function _opensslAvailable() { try { cp.execFileSync("openssl", ["version"], { stdio: "ignore" }); return true; } catch { return false; } }
// ML-DSA / SLH-DSA certificate support landed in OpenSSL 3.5; an older openssl cannot parse or verify a
// PQC certificate, so those arms are only cross-checked when the openssl on PATH is >= 3.5.
function _opensslHasPqc() {
  try {
    var v = cp.execFileSync("openssl", ["version"], { encoding: "utf8" });
    var m = v.match(/OpenSSL\s+(\d+)\.(\d+)/);
    return !!m && (Number(m[1]) > 3 || (Number(m[1]) === 3 && Number(m[2]) >= 5));
  } catch { return false; }
}

async function testOpensslInterop() {
  if (!_opensslAvailable()) { helpers.skip("openssl not on PATH -- interop skipped (runs on the host gate)"); return; }
  // A self-signed cert we emit must parse (openssl x509 -text) AND verify (openssl verify) across a
  // classical, an ECDSA, and an EdDSA arm -- and the post-quantum arms when openssl is >= 3.5.
  var arms = ["rsa", "ec-p256", "ed25519"];
  if (_opensslHasPqc()) arms.push("ml-dsa-65", "slh-dsa-sha2-128f");
  else helpers.skip("openssl < 3.5 on PATH -- ML-DSA/SLH-DSA certificate interop not cross-checked");
  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = makeSigner(alg);
    var pem = await pki.x509.sign({
      subject: [{ commonName: alg + " Root" }, { organizationName: "Interop" }, { countryName: "US" }],
      subjectPublicKey: s.spki, notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true },
    }, { key: s.key }, { pem: true });
    var f = pathMod.join(os.tmpdir(), "pki-x509sign-" + alg + "-" + process.pid + ".pem");
    fsMod.writeFileSync(f, pem);
    var ok;
    try {
      cp.execFileSync("openssl", ["x509", "-in", f, "-noout", "-text"], { stdio: "ignore" });
      var out = cp.execFileSync("openssl", ["verify", "-CAfile", f, f], { encoding: "utf8" });
      ok = /: OK\s*$/.test(out.trim());
    } catch { ok = false; } finally { try { fsMod.unlinkSync(f); } catch { /* best effort */ } }
    check("openssl accepts + verifies our " + alg + " self-signed cert", ok);
  }
}

// ---- full extension surface + GeneralName forms + input forms (coverage + surface) --------

async function testExtensionSurface() {
  var s = makeSigner("ec-p256");
  var der = await pki.x509.sign({
    subject: [{ commonName: "full" }], subjectPublicKey: s.spki, notBefore: NB, notAfter: NA,
    extensions: {
      basicConstraints: { cA: true, pathLen: 3 },
      keyUsage: ["keyCertSign", "cRLSign"],
      extendedKeyUsage: ["serverAuth", "clientAuth"],
      subjectKeyIdentifier: Buffer.alloc(20, 0xab),          // explicit key id (not auto-derived)
      authorityKeyIdentifier: Buffer.alloc(20, 0xcd),        // explicit key id
      subjectAltName: [{ dNSName: "a.example" }, { rfc822Name: "x@example.com" },
        { uniformResourceIdentifier: "https://example.com/p" }, { iPAddress: Buffer.from([10, 0, 0, 1]) },
        { directoryName: [{ commonName: "dir" }] }],
      certificatePolicies: ["anyPolicy"],
    },
  }, { key: s.key });
  var c = pki.schema.x509.parse(der);
  check("full extension set parses (7 extensions)", c.extensions.length === 7);
  check("extendedKeyUsage present", c.extensions.some(function (x) { return (x.name || x.oid) === "extKeyUsage"; }));
  var ski = c.extensions.filter(function (x) { return (x.name || x.oid) === "subjectKeyIdentifier"; })[0];
  check("explicit SKI value embedded verbatim", Buffer.compare(asn1.read.octetString(asn1.decode(ski.value)), Buffer.alloc(20, 0xab)) === 0);
  var bc = c.extensions.filter(function (x) { return (x.name || x.oid) === "basicConstraints"; })[0];
  check("basicConstraints pathLen encoded", asn1.decode(bc.value).children.length === 2);
}

async function testGeneralNameForms() {
  var s = makeSigner("ed25519");
  function base(exts) { return { subject: "gn", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: { subjectAltName: exts } }; }
  check("empty SAN value -> throws", await codeOf(pki.x509.sign(base([{ dNSName: "" }]), { key: s.key })) === "x509/bad-input");
  check("multi-form GeneralName -> throws", await codeOf(pki.x509.sign(base([{ dNSName: "a", rfc822Name: "b" }]), { key: s.key })) === "x509/bad-input");
  check("unsupported GeneralName form -> throws", await codeOf(pki.x509.sign(base([{ registeredID: "1.2.3" }]), { key: s.key })) === "x509/bad-input");
  check("iPAddress wrong length -> throws", await codeOf(pki.x509.sign(base([{ iPAddress: Buffer.from([1, 2, 3]) }]), { key: s.key })) === "x509/bad-input");
  check("non-ASCII rfc822Name -> throws", await codeOf(pki.x509.sign(base([{ rfc822Name: "nÖn@ascii" }]), { key: s.key })) === "x509/bad-input");
  check("empty SAN list -> throws", await codeOf(pki.x509.sign(base([]), { key: s.key })) === "x509/bad-input");
}

async function testInputForms() {
  var s = makeSigner("ed25519");
  function base(over) { return Object.assign({ subject: "in", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, over); }
  check("serial as number", pki.schema.x509.parse(await pki.x509.sign(base({ serialNumber: 42 }), { key: s.key })).serialNumberHex === "2a");
  // 0xbeef has its MSB set, so DER prepends a 0x00 sign octet to keep the INTEGER positive (-> "00beef").
  check("serial as hex string (MSB-set gets a sign pad)", pki.schema.x509.parse(await pki.x509.sign(base({ serialNumber: "0xbeef" }), { key: s.key })).serialNumberHex === "00beef");
  check("serial as Buffer", pki.schema.x509.parse(await pki.x509.sign(base({ serialNumber: Buffer.from([0x12, 0x34]) }), { key: s.key })).serialNumberHex === "1234");
  check("serial auto-random is 20 octets", pki.schema.x509.parse(await pki.x509.sign(base({}), { key: s.key })).serialNumberHex.length === 40);
  check("non-integer number serial -> throws", await codeOf(pki.x509.sign(base({ serialNumber: 1.5 }), { key: s.key })) === "x509/bad-serial");

  // explicit issuer { name, publicKey, key } CA-signed path (distinct from the { cert } convenience).
  var ca = makeSigner("ec-p256");
  var caName = [{ commonName: "Explicit CA" }];
  var caDer = await pki.x509.sign({ subject: caName, subjectPublicKey: ca.spki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: ca.key });
  var leaf = await pki.x509.sign(base({}), { name: caName, publicKey: ca.spki, key: ca.key });
  check("explicit-issuer leaf chains to CA subject", pki.schema.x509.parse(leaf).issuer.dn === pki.schema.x509.parse(caDer).subject.dn);

  // array-form pre-encoded extension pass-through.
  var B = pki.asn1.build, oidB = pki.oid.byName;
  var preExt = B.sequence([B.oid(oidB("basicConstraints")), B.boolean(true), B.octetString(B.sequence([B.boolean(true)]))]);
  check("array-form pre-encoded extension parses", pki.schema.x509.parse(await pki.x509.sign(base({ extensions: [preExt] }), { key: s.key })).extensions.length === 1);

  // PKCS#8 PEM signing key input.
  var pemKey = ca.keyObject.export({ type: "pkcs8", format: "pem" });
  check("PEM signing key accepted", Buffer.isBuffer(await pki.x509.sign({ subject: caName, subjectPublicKey: ca.spki, notBefore: NB, notAfter: NA }, { key: pemKey })));

  // raw Name DER as subject (the escape hatch) round-trips.
  var rawName = B.sequence([B.set([B.sequence([B.oid(oidB("commonName")), B.utf8("Raw DN")])])]);
  check("raw Name DER subject round-trips", /Raw DN/.test(pki.schema.x509.parse(await pki.x509.sign(base({ subject: rawName }), { key: s.key })).subject.dn));
}

async function testCoverageEdges() {
  var s = makeSigner("ed25519");
  var B = pki.asn1.build;
  function base(over) { return Object.assign({ subject: "e", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, over); }
  // Unsupported signing-key algorithm -> the sign-scheme resolver throws through _signE (x509/*).
  var bogusSpki = B.sequence([B.sequence([B.oid("1.2.3.4.5.6.7")]), B.bitString(Buffer.from([1, 2, 3]), 0)]);
  check("unsupported signing alg -> x509/unsupported-algorithm", await codeOf(pki.x509.sign(base({}), { name: "CA", publicKey: bogusSpki, key: s.key })) === "x509/unsupported-algorithm");
  // Invalid SKI / AKI / serial spec values.
  check("invalid subjectKeyIdentifier spec -> throws", await codeOf(pki.x509.sign(base({ extensions: { subjectKeyIdentifier: "nope" } }), { key: s.key })) === "x509/bad-input");
  check("invalid authorityKeyIdentifier spec -> throws", await codeOf(pki.x509.sign(base({ extensions: { authorityKeyIdentifier: 5 } }), { key: s.key })) === "x509/bad-input");
  check("invalid serial type -> x509/bad-serial", await codeOf(pki.x509.sign(base({ serialNumber: {} }), { key: s.key })) === "x509/bad-serial");
  // Empty subject requires a CA issuer (a self-signed empty subject fails the issuer non-empty rule
  // first, since issuer == subject): rejected without a SAN, accepted (SAN forced critical) with one.
  var ca = makeSigner("ec-p256");
  var caIssuer = { name: "Empty-Subject CA", publicKey: ca.spki, key: ca.key };
  check("empty subject without SAN -> throws", await codeOf(pki.x509.sign(base({ subject: [] }), caIssuer)) === "x509/bad-input");
  var okC = pki.schema.x509.parse(await pki.x509.sign(base({ subject: [], extensions: { subjectAltName: [{ dNSName: "host.example" }] } }), caIssuer));
  var san = okC.extensions.filter(function (x) { return (x.name || x.oid) === "subjectAltName"; })[0];
  check("empty subject with SAN -> valid, SAN forced critical", okC.subject.dn === "" && san.critical === true);
  // CA-signed leaf whose CA carries NO subjectKeyIdentifier: AKI auto-derives from the issuer SPKI.
  var caNoSki = await pki.x509.sign({ subject: "CA No SKI", subjectPublicKey: ca.spki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: ca.key });
  var leaf = await pki.x509.sign(base({ extensions: { authorityKeyIdentifier: true } }), { cert: pki.schema.x509.parse(caNoSki), key: ca.key });
  check("AKI auto-derives when the CA lacks an SKI", pki.schema.x509.parse(leaf).extensions.some(function (x) { return (x.name || x.oid) === "authorityKeyIdentifier"; }));

  // Input-coercion + fail-closed edges.
  check("Uint8Array subjectPublicKey accepted", Buffer.isBuffer(await pki.x509.sign(base({ subjectPublicKey: new Uint8Array(s.spki) }), { key: s.key })));
  check("missing issuer.key -> throws", await codeOf(pki.x509.sign(base({}), {})) === "x509/bad-input");
  check("issuer.cert as raw DER Buffer chains", pki.schema.x509.parse(await pki.x509.sign(base({}), { cert: caNoSki, key: ca.key })).issuer.dn === pki.schema.x509.parse(caNoSki).subject.dn);
  check("issuer.cert without tbsBytes -> throws", await codeOf(pki.x509.sign(base({}), { cert: {}, key: ca.key })) === "x509/bad-input");
  check("non-SPKI issuer publicKey -> x509/bad-spki", await codeOf(pki.x509.sign(base({}), { name: "x", publicKey: B.sequence([]), key: s.key })) === "x509/bad-spki");
  check("explicit issuer with no name -> x509/bad-issuer", await codeOf(pki.x509.sign(base({}), { publicKey: ca.spki, key: ca.key })) === "x509/bad-issuer");
  check("unparseable serial string -> x509/bad-serial", await codeOf(pki.x509.sign(base({ serialNumber: "not-a-number" }), { key: s.key })) === "x509/bad-serial");
  // subject omitted entirely (=> empty) is the same empty-subject rule, via a CA issuer.
  check("subject omitted -> empty-subject rule (needs SAN)", await codeOf(pki.x509.sign({ subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, caIssuer)) === "x509/bad-input");
}

async function testKeyMatchAndTimeAndSan() {
  var B = pki.asn1.build, oidB = pki.oid.byName;
  // (Fix) the signing key must correspond to the issuer public key -- a mismatched but same-algorithm
  // key pair would produce a certificate that does not chain, so it is rejected.
  var a = makeSigner("ec-p256"), a2 = makeSigner("ec-p256");
  check("mismatched same-algorithm signing key -> x509/bad-input",
    await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: a.spki, notBefore: NB, notAfter: NA }, { name: "CA", publicKey: a.spki, key: a2.key })) === "x509/bad-input");
  check("matching key pair still signs",
    Buffer.isBuffer(await pki.x509.sign({ subject: "x", subjectPublicKey: a.spki, notBefore: NB, notAfter: NA }, { name: "CA", publicKey: a.spki, key: a.key })));

  // (Fix) a validity date before 1950 uses GeneralizedTime (UTCTime cannot represent pre-1950 years).
  var s = makeSigner("ed25519");
  var derPre = await pki.x509.sign({ subject: "pre1950", subjectPublicKey: s.spki, notBefore: new Date("1940-06-01T00:00:00Z"), notAfter: NA }, { key: s.key });
  var valPre = asn1.decode(derPre).children[0].children[3];   // v1: validity at index 3
  check("pre-1950 notBefore encodes as GeneralizedTime", valPre.children[0].tagClass === "universal" && valPre.children[0].tagNumber === 24);
  check("pre-1950 notBefore round-trips to 1940", pki.schema.x509.parse(derPre).validity.notBefore.getUTCFullYear() === 1940);

  // (Fix) an empty subject accepts a critical SAN supplied in the pre-encoded array form.
  var ca = makeSigner("ec-p256");
  var caIssuer = { name: "SAN CA", publicKey: ca.spki, key: ca.key };
  var sanVal = B.sequence([B.contextPrimitive(2, Buffer.from("host.example", "latin1"))]);   // GeneralNames { dNSName }
  var criticalSan = B.sequence([B.oid(oidB("subjectAltName")), B.boolean(true), B.octetString(sanVal)]);
  var derSan = await pki.x509.sign({ subject: [], subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: [criticalSan] }, caIssuer);
  check("empty subject with a pre-encoded critical SAN (array form) is accepted", pki.schema.x509.parse(derSan).subject.dn === "");
  var nonCriticalSan = B.sequence([B.oid(oidB("subjectAltName")), B.octetString(sanVal)]);   // no critical flag
  check("empty subject with a NON-critical pre-encoded SAN -> x509/bad-input",
    await codeOf(pki.x509.sign({ subject: [], subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: [nonCriticalSan] }, caIssuer)) === "x509/bad-input");

  // (Fix) a WebCrypto CryptoKey signer is bound to the issuer public key by the post-sign verify.
  var subtle = pki.webcrypto.subtle;
  var kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var ckSpki = Buffer.from(await subtle.exportKey("spki", kp.publicKey));
  check("CryptoKey signer produces a chaining certificate", Buffer.isBuffer(await pki.x509.sign({ subject: "ck", subjectPublicKey: ckSpki, notBefore: NB, notAfter: NA }, { key: kp.privateKey })));
  var kp2 = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  check("mismatched CryptoKey signer -> x509/bad-input",
    await codeOf(pki.x509.sign({ subject: "ck", subjectPublicKey: ckSpki, notBefore: NB, notAfter: NA }, { name: "CA", publicKey: ckSpki, key: kp2.privateKey })) === "x509/bad-input");

  // (Fix) the CA cross-field rules apply to the pre-encoded array form too.
  var kcsKu = B.sequence([B.oid(oidB("keyUsage")), B.boolean(true), B.octetString(B.namedBitString([5]))]);   // keyCertSign
  var bcFalse = B.sequence([B.oid(oidB("basicConstraints")), B.boolean(true), B.octetString(B.sequence([]))]);   // cA absent (FALSE)
  check("array keyCertSign without cA=TRUE -> x509/bad-input",
    await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: [kcsKu, bcFalse] }, { key: s.key })) === "x509/bad-input");
  var bcTrue = B.sequence([B.oid(oidB("basicConstraints")), B.boolean(true), B.octetString(B.sequence([B.boolean(true), B.integer(1n)]))]);   // cA=TRUE, pathLen 1
  check("array pathLen with cA=TRUE + keyCertSign is accepted",
    Buffer.isBuffer(await pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: [kcsKu, bcTrue] }, { key: s.key })));
}

async function main() {
  await testRoundTrip();
  await testPemOutput();
  await testSelfSignedValidates();
  await testCaSignedLeaf();
  await testAlgorithmArms();
  await testCompositeArm();
  await testVersionCoherence();
  await testSerialBounds();
  await testValidityEncoding();
  await testDerCanonical();
  await testKeyUsageMinimalBits();
  await testCaCrossField();
  await testExtensionSurface();
  await testGeneralNameForms();
  await testInputForms();
  await testCoverageEdges();
  await testKeyMatchAndTimeAndSan();
  await testFailClosed();
  await testOpensslInterop();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
