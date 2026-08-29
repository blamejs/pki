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
  // #68: a byte-magnitude serialNumber accepts any BufferSource, not only a Buffer. An ArrayBuffer of
  // the magnitude bytes signs the same serial; before the widening it was rejected as x509/bad-serial.
  var serX509AB = new ArrayBuffer(2); new Uint8Array(serX509AB).set([0x7f, 0xab]);
  check("serialNumber as an ArrayBuffer accepted (#68)",
    pki.schema.x509.parse(await pki.x509.sign(Object.assign({ serialNumber: serX509AB }, base), { key: s.key })).serialNumberHex === "7fab");
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

  // The SPEC itself gets the same door the extensions sub-object already had. Without it a
  // misspelled `extension` produced a SIGNED CERTIFICATE CARRYING NO EXTENSIONS: the caller asked
  // for basicConstraints and keyUsage and got neither, with nothing to read as a failure. The
  // artifact is asserted absent, not merely the code, because the failure was that one WAS emitted.
  async function specReject(spec, issuer) {
    var emitted = null, err = null;
    try { emitted = await pki.x509.sign(spec, issuer || { key: s.key }); } catch (e) { err = e; }
    return { code: err && err.code, msg: (err && err.message) || "", emitted: emitted };
  }
  var typo = await specReject({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA,
    extension: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } });
  check("spec.extension (typo for extensions) -> x509/bad-input", typo.code === "x509/bad-input");
  check("...and NO certificate is emitted", typo.emitted === null);
  check("...and the message names the offending key", /extension/.test(typo.msg));

  var invented = await specReject({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, pathLenConstraint: 0 });
  check("an invented spec key -> x509/bad-input", invented.code === "x509/bad-input" && invented.emitted === null);

  // The issuer is argument TWO. Nesting it in the spec silently self-signed, which reads as a
  // toolkit bug rather than a mis-shaped call, so the door has to cover this spelling too.
  var nested = await specReject({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, issuer: { key: s.key } });
  check("spec.issuer (the issuer is argument two) -> x509/bad-input", nested.code === "x509/bad-input" && nested.emitted === null);

  // The other two caller-owned objects get the same treatment: one door per argument, so no
  // argument is the one nobody thought to gate. On the issuer the door carries a verdict of its
  // own: the issuing certificate is OPTIONAL, so a dropped one falls through to self-signing
  // rather than being missed. This spec certifies the signer's own key, which is what a
  // cross-certificate or a re-issue looks like, so the key/public-key correspondence check
  // cannot tell the two apart -- without the door the misspelling below emits a certificate
  // naming its own subject as its issuer, and nothing in the result says so.
  var badIssuer = await specReject({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA },
    { key: s.key, certificate: s.cert });
  check("an unknown issuer key -> x509/bad-input", badIssuer.code === "x509/bad-input" && badIssuer.emitted === null);

  // The control that gives the vector above its meaning. Spelled correctly, this same call is
  // REFUSED: the supplied issuer is not a CA. So the misspelling did not merely lose a field, it
  // routed around that refusal and emitted a certificate -- the door restores the verdict the
  // correctly-spelled call gets.
  check("cert spelled correctly -> refused, the issuer is not a CA",
    await codeOf(pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA },
      { key: s.key, cert: s.cert })) === "x509/bad-input");

  // The issuer has two mutually exclusive FORMS: an issuing certificate, or an explicit name plus
  // public key. The certificate branch wins whenever cert is present and neither name nor publicKey
  // is read on it, so a caller who supplied both got a certificate issued by the CERT's DN while
  // having named a different issuer -- the same silent discard a misspelling produces.
  var ca = makeSigner("ec-p256");
  var caCert = pki.schema.x509.parse(await pki.x509.sign({
    subject: "Issuing CA", subjectPublicKey: ca.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] },
  }, { key: ca.key }));
  var mixedIssuer = await specReject(base, { key: ca.key, cert: caCert, name: "CN=Different CA" });
  check("an issuing cert mixed with an explicit name -> x509/bad-input", mixedIssuer.code === "x509/bad-input");
  check("...and NO certificate is emitted", mixedIssuer.emitted === null);
  check("each issuer form on its own still signs",
    (await pki.x509.sign(base, { key: ca.key, cert: caCert })) != null &&
    (await pki.x509.sign(base, { key: ca.key, name: "CN=Explicit CA", publicKey: ca.spki })) != null);

  var badOpts = null;
  try { await pki.x509.sign({ subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, { key: s.key }, { digestAlgorithms: "sha256" }); }
  catch (e) { badOpts = e; }
  check("an unknown option -> x509/bad-input", badOpts && badOpts.code === "x509/bad-input");

  // The six real spec keys still round-trip, so the table admits what the producer reads.
  check("every documented spec key is still accepted", (await pki.x509.sign({
    subject: "x", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, serialNumber: 42n,
    extensions: { keyUsage: ["digitalSignature"] },
  }, { key: s.key })) != null);
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

  // subjectKeyIdentifier and authorityKeyIdentifier accept any BufferSource key id, not only a
  // Buffer: an ArrayBuffer key id embeds the same 20 bytes. Before the widening the one-form
  // Buffer.isBuffer gate refused it and the sign threw x509/bad-input.
  var skiAB = new ArrayBuffer(20); new Uint8Array(skiAB).fill(0xab);
  var akiAB = new ArrayBuffer(20); new Uint8Array(akiAB).fill(0xcd);
  var derKidAB = await pki.x509.sign({ subject: [{ commonName: "kidAB" }], subjectPublicKey: s.spki,
    notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true },
      subjectKeyIdentifier: skiAB, authorityKeyIdentifier: akiAB } }, { key: s.key });
  var cKidAB = pki.schema.x509.parse(derKidAB);
  var skiExtAB = cKidAB.extensions.filter(function (x) { return (x.name || x.oid) === "subjectKeyIdentifier"; })[0];
  check("an ArrayBuffer subjectKeyIdentifier embeds the same key id (#68 A3 skiKeyId 1-form widening)",
    !!skiExtAB && Buffer.compare(asn1.read.octetString(asn1.decode(skiExtAB.value)), Buffer.alloc(20, 0xab)) === 0);
  check("an ArrayBuffer authorityKeyIdentifier is accepted (#68 x509 _akiKeyId 1-form widening)",
    cKidAB.extensions.some(function (x) { return (x.name || x.oid) === "authorityKeyIdentifier"; }));
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

  // issue #116: an iPAddress SAN may be given as a dotted-quad / colon-hex STRING (packed internally),
  // matching dNSName/URI ergonomics -- not only a pre-packed Buffer. The string must produce the exact
  // same GeneralNames octets as the equivalent Buffer.
  function sanValue(der) {
    var c = pki.schema.x509.parse(der);
    return c.extensions.filter(function (x) { return (x.name || x.oid) === "subjectAltName"; })[0].value;
  }
  var ipStr4 = await pki.x509.sign(base([{ iPAddress: "10.0.0.1" }]), { key: s.key });
  var ipBuf4 = await pki.x509.sign(base([{ iPAddress: Buffer.from([10, 0, 0, 1]) }]), { key: s.key });
  check("iPAddress IPv4 string packs to the same octets as the Buffer form", Buffer.compare(sanValue(ipStr4), sanValue(ipBuf4)) === 0);
  var ipStr6 = await pki.x509.sign(base([{ iPAddress: "2001:db8::1" }]), { key: s.key });
  var ipBuf6 = await pki.x509.sign(base([{ iPAddress: Buffer.concat([Buffer.from([0x20, 0x01, 0x0d, 0xb8]), Buffer.alloc(11), Buffer.from([0x01])]) }]), { key: s.key });
  check("iPAddress IPv6 string packs to the same 16 octets as the Buffer form", Buffer.compare(sanValue(ipStr6), sanValue(ipBuf6)) === 0);
  check("invalid iPAddress string -> throws", await codeOf(pki.x509.sign(base([{ iPAddress: "not.an.ip" }]), { key: s.key })) === "x509/bad-input");
  check("out-of-range iPAddress octet string -> throws", await codeOf(pki.x509.sign(base([{ iPAddress: "999.0.0.1" }]), { key: s.key })) === "x509/bad-input");

  // #75 Half B -- a bare STRING SAN entry is classified fail-closed into its GeneralName form. Context
  // tag map: rfc822Name=1, dNSName=2, uniformResourceIdentifier=6, iPAddress=7. sanForms decodes the
  // SAN SEQUENCE and reports each entry's context tag, so the assertion is on the emitted wire form.
  function sanForms(der) {
    var node = asn1.decode(sanValue(der));
    if (node.tagClass === "universal" && node.tagNumber === 4) node = asn1.decode(node.content);
    return node.children.map(function (c) { return c.tagNumber; }).join(",");
  }
  check("Half B: bare 'example.com' -> dNSName [2]", sanForms(await pki.x509.sign(base(["example.com"]), { key: s.key })) === "2");
  check("Half B: bare '*.example.com' wildcard -> dNSName [2]", sanForms(await pki.x509.sign(base(["*.example.com"]), { key: s.key })) === "2");
  check("Half B: bare 'localhost' single label -> dNSName [2]", sanForms(await pki.x509.sign(base(["localhost"]), { key: s.key })) === "2");
  check("Half B: bare 'user@example.com' -> rfc822Name [1]", sanForms(await pki.x509.sign(base(["user@example.com"]), { key: s.key })) === "1");
  check("Half B: bare '192.0.2.1' -> iPAddress [7]", sanForms(await pki.x509.sign(base(["192.0.2.1"]), { key: s.key })) === "7");
  check("Half B: bare '2001:db8::1' -> iPAddress [7]", sanForms(await pki.x509.sign(base(["2001:db8::1"]), { key: s.key })) === "7");
  check("Half B: bare 'https://example.com/x' -> URI [6]", sanForms(await pki.x509.sign(base(["https://example.com/x"]), { key: s.key })) === "6");
  check("Half B: 'https://h.test/p?q=1#f' (query+fragment) -> URI [6]", sanForms(await pki.x509.sign(base(["https://h.test/p?q=1#f"]), { key: s.key })) === "6");
  check("Half B: 'https://user@host.test/x' -> URI [6] (userinfo not read as email)", sanForms(await pki.x509.sign(base(["https://user@host.test/x"]), { key: s.key })) === "6");
  check("Half B: underscore label '_acme-challenge.example.com' -> dNSName [2]", sanForms(await pki.x509.sign(base(["_acme-challenge.example.com"]), { key: s.key })) === "2");
  // The dNSName underscore tolerance is leading/embedded only (the real _acme-challenge / _dmarc forms);
  // a TRAILING underscore has no such use, so a label ending in "_" is refused rather than classified.
  check("Half B: embedded underscore 'a_b.example.com' -> dNSName [2]", sanForms(await pki.x509.sign(base(["a_b.example.com"]), { key: s.key })) === "2");
  check("Half B: absolute FQDN 'example.com.' (trailing root dot) -> dNSName [2]", sanForms(await pki.x509.sign(base(["example.com."]), { key: s.key })) === "2");
  // The RFC 1035 253-byte name limit excludes the presentation root dot: a 253-byte name plus a trailing
  // "." (254 bytes) is accepted, while a 255-byte name is refused.
  var _max253 = new Array(127).fill("a").join(".");   // 127 one-byte labels = 253 bytes
  check("Half B: a 253-byte dNSName + trailing root dot -> dNSName [2]", sanForms(await pki.x509.sign(base([_max253 + "."]), { key: s.key })) === "2");
  check("Half B: a 255-byte dNSName -> throws", await codeOf(pki.x509.sign(base([new Array(128).fill("a").join(".")]), { key: s.key })) === "x509/bad-input");
  check("Half B: trailing underscore 'host_.example' -> throws", await codeOf(pki.x509.sign(base(["host_.example"]), { key: s.key })) === "x509/bad-input");
  check("Half B: mixed shorthand + object form -> [dNSName, dNSName, iPAddress]", sanForms(await pki.x509.sign(base(["example.com", { dNSName: "b.example" }, "10.0.0.1"]), { key: s.key })) === "2,2,7");
  // unclassifiable / ambiguous -> throws (fail-closed; the object form is the escape)
  check("Half B: 'example.com:8080' host:port -> throws", await codeOf(pki.x509.sign(base(["example.com:8080"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'urn:oid:1.2.3' (opaque, no //) -> throws", await codeOf(pki.x509.sign(base(["urn:oid:1.2.3"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'mailto:x@y.com' (scheme, no //) -> throws", await codeOf(pki.x509.sign(base(["mailto:x@y.com"]), { key: s.key })) === "x509/bad-input");
  // A string that merely starts with scheme:// but has an empty or space-carrying authority is refused.
  // RFC 5280 sec. 4.2.1.6 requires a URI with an authority to carry an FQDN or IP host, so an empty-host
  // authority is non-conformant for a certificate SAN even where RFC 3986 generic syntax would allow it --
  // an empty-authority "file:///path" URI uses the object form { uniformResourceIdentifier }.
  check("Half B: 'file:///tmp/example' (empty-host authority) -> throws", await codeOf(pki.x509.sign(base(["file:///tmp/example"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://' (empty authority) -> throws", await codeOf(pki.x509.sign(base(["https://"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://not a uri' (space in authority) -> throws", await codeOf(pki.x509.sign(base(["https://not a uri"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https:///path' (empty authority before /) -> throws", await codeOf(pki.x509.sign(base(["https:///path"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://?query' (empty authority before ?) -> throws", await codeOf(pki.x509.sign(base(["https://?query"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://#frag' (empty authority before #) -> throws", await codeOf(pki.x509.sign(base(["https://#frag"]), { key: s.key })) === "x509/bad-input");
  // A URI-shaped string that carries a character outside the RFC 3986 grammar -- a bare "%" not starting a
  // "%HEXHEX" triplet, or a byte like "^" that is neither unreserved, reserved, nor percent-encoded -- is
  // not a valid URI, so it is refused rather than classified as one (the object form accepts an odd value).
  check("Half B: 'https://h.test/%' (bare percent, not %HEXHEX) -> throws", await codeOf(pki.x509.sign(base(["https://h.test/%"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://h.test/%zz' (invalid percent-encoding) -> throws", await codeOf(pki.x509.sign(base(["https://h.test/%zz"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://h.test/a^b' (caret is not a URI character) -> throws", await codeOf(pki.x509.sign(base(["https://h.test/a^b"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://h.test/%2f?a=1' (valid percent-encoding) -> URI [6]", sanForms(await pki.x509.sign(base(["https://h.test/%2f?a=1"]), { key: s.key })) === "6");
  // A bracketed IPv6-literal host ("[::1]") is classified (#201): RFC 3986 sec. 3.2.2 IP-literal is taken as
  // one unit before the optional port, and an IPv6 host is a valid iPAddress per RFC 5280 sec. 4.2.1.6. The
  // bracket is the only way to write an IPv6 host in a URI. An unbalanced bracket, a bracket body that is not
  // a valid IPv6 address, or bytes other than a port after the "]" stay refused.
  check("Half B: 'https://[' (unbalanced IP-literal bracket) -> throws", await codeOf(pki.x509.sign(base(["https://["]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://[::1]/p' (bracketed IPv6 host) -> URI [6]", sanForms(await pki.x509.sign(base(["https://[::1]/p"]), { key: s.key })) === "6");
  check("Half B: 'https://[2001:db8::1]:8443/p' (bracketed IPv6 host + port) -> URI [6]", sanForms(await pki.x509.sign(base(["https://[2001:db8::1]:8443/p"]), { key: s.key })) === "6");
  check("Half B: 'https://[not-ipv6]/' (non-IPv6 bracket body) -> throws", await codeOf(pki.x509.sign(base(["https://[not-ipv6]/"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://[::1]x/' (junk after IP-literal bracket) -> throws", await codeOf(pki.x509.sign(base(["https://[::1]x/"]), { key: s.key })) === "x509/bad-input");
  // The URI form is parsed by component (RFC 3986): the authority carries at most one "@", an FQDN-or-IP
  // host, and a numeric port, and there is at most one "#". A structurally malformed URL is refused, not
  // signed as a uniformResourceIdentifier; a fully well-formed URL (userinfo, port, path, query, fragment)
  // is still accepted.
  check("Half B: 'https://u@v@host.test/' (two userinfo '@') -> throws", await codeOf(pki.x509.sign(base(["https://u@v@host.test/"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://host.test:abc/' (non-numeric port) -> throws", await codeOf(pki.x509.sign(base(["https://host.test:abc/"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://host.test##fragment' (two '#') -> throws", await codeOf(pki.x509.sign(base(["https://host.test##fragment"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://host.test/a#b#c' (two '#') -> throws", await codeOf(pki.x509.sign(base(["https://host.test/a#b#c"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://:8080/p' (empty host before port) -> throws", await codeOf(pki.x509.sign(base(["https://:8080/p"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://user:pass@host.test:8080/p?q=1#f' (full valid URL) -> URI [6]", sanForms(await pki.x509.sign(base(["https://user:pass@host.test:8080/p?q=1#f"]), { key: s.key })) === "6");
  check("Half B: 'https://host.test:8080/p' (numeric port) -> URI [6]", sanForms(await pki.x509.sign(base(["https://host.test:8080/p"]), { key: s.key })) === "6");
  check("Half B: 'https://host.test:/p' (empty port is allowed) -> URI [6]", sanForms(await pki.x509.sign(base(["https://host.test:/p"]), { key: s.key })) === "6");
  // The URI host itself must be a valid FQDN or IP (RFC 5280 sec. 4.2.1.6): a label with a leading/trailing
  // hyphen, an IPv4-shaped but out-of-range host, a byte outside the hostname grammar, or a single-label
  // host that is not fully qualified is refused; a valid dotted FQDN and a valid IPv4 host are kept.
  check("Half B: 'https://-bad-.example/' (hyphen at host label edge) -> throws", await codeOf(pki.x509.sign(base(["https://-bad-.example/"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://999.999.999.999/' (IPv4-shaped invalid host) -> throws", await codeOf(pki.x509.sign(base(["https://999.999.999.999/"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://$/' (sub-delim host is not a hostname) -> throws", await codeOf(pki.x509.sign(base(["https://$/"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://localhost/p' (single-label host, not an FQDN) -> throws", await codeOf(pki.x509.sign(base(["https://localhost/p"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'https://192.0.2.1/p' (valid IPv4 host) -> URI [6]", sanForms(await pki.x509.sign(base(["https://192.0.2.1/p"]), { key: s.key })) === "6");
  // An absolute FQDN carries a trailing root "." and is still a valid multi-label host; a single label plus
  // the root ("localhost.") is not multi-label, and a host over the 253-byte name length is refused.
  check("Half B: 'https://example.com./p' (absolute FQDN, trailing root dot) -> URI [6]", sanForms(await pki.x509.sign(base(["https://example.com./p"]), { key: s.key })) === "6");
  check("Half B: 'https://localhost./p' (single label + root dot, not an FQDN) -> throws", await codeOf(pki.x509.sign(base(["https://localhost./p"]), { key: s.key })) === "x509/bad-input");
  check("Half B: a URI host over 253 bytes -> throws", await codeOf(pki.x509.sign(base(["https://" + new Array(128).join("a.") + "com/p"]), { key: s.key })) === "x509/bad-input");
  // A control byte in an email local part is malformed -> refused (same fail-closed rule as the URI form).
  check("Half B: an rfc822Name local part with a control byte -> throws", await codeOf(pki.x509.sign(base(["a" + String.fromCharCode(1) + "b@example.com"]), { key: s.key })) === "x509/bad-input");
  // The local part is an unquoted RFC 5321 dot-atom: atext runs joined by SINGLE dots. Consecutive,
  // leading, or trailing dots, and a non-atext byte, are malformed -> refused (the object form is the
  // escape for a quoted-string local part). A single valid dot-atom still classifies as an rfc822Name.
  check("Half B: 'a..b@example.com' (consecutive dots) -> throws", await codeOf(pki.x509.sign(base(["a..b@example.com"]), { key: s.key })) === "x509/bad-input");
  check("Half B: '.a@example.com' (leading dot) -> throws", await codeOf(pki.x509.sign(base([".a@example.com"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'a.@example.com' (trailing dot) -> throws", await codeOf(pki.x509.sign(base(["a.@example.com"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'a<b@example.com' (non-atext byte) -> throws", await codeOf(pki.x509.sign(base(["a<b@example.com"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'user.name+tag@example.com' (valid dot-atom) -> rfc822Name [1]", sanForms(await pki.x509.sign(base(["user.name+tag@example.com"]), { key: s.key })) === "1");
  // The email DOMAIN is a strict RFC 5321 LDH hostname (no underscore), unlike a dNSName label, which
  // tolerates a leading/embedded underscore -- so an underscore in the domain is a malformed mailbox and
  // is refused, while an underscore-bearing dNSName (see _acme-challenge above) is still accepted.
  check("Half B: 'user@foo_bar.example' (underscore in email domain) -> throws", await codeOf(pki.x509.sign(base(["user@foo_bar.example"]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'user@host-name.example.com' (hyphen in email domain) -> rfc822Name [1]", sanForms(await pki.x509.sign(base(["user@host-name.example.com"]), { key: s.key })) === "1");
  // Unlike a URI host or dNSName, an RFC 5321 mailbox domain has no trailing root dot, so it is refused.
  check("Half B: 'user@example.com.' (trailing dot in email domain) -> throws", await codeOf(pki.x509.sign(base(["user@example.com."]), { key: s.key })) === "x509/bad-input");
  // RFC 5321 sec. 4.5.3.1.1 caps the local part at 64 octets: a 64-octet local part is accepted, 65 is refused.
  check("Half B: a 64-octet email local part -> rfc822Name [1]", sanForms(await pki.x509.sign(base([new Array(65).join("a") + "@example.com"]), { key: s.key })) === "1");
  check("Half B: a 65-octet email local part -> throws", await codeOf(pki.x509.sign(base([new Array(66).join("a") + "@example.com"]), { key: s.key })) === "x509/bad-input");
  // Even with a valid 64-octet local part and a valid dotted domain, the whole mailbox is capped at 254
  // octets (RFC 5321 sec. 4.5.3.1.3): a 64-octet local + "@" + a 197-octet domain (262 total) is refused.
  check("Half B: an email over the 254-octet mailbox limit -> throws", await codeOf(pki.x509.sign(base([new Array(65).join("a") + "@" + new Array(99).fill("a").join(".")]), { key: s.key })) === "x509/bad-input");
  check("Half B: '' empty bare string -> throws", await codeOf(pki.x509.sign(base([""]), { key: s.key })) === "x509/bad-input");
  check("Half B: 'foo@bar' bare-label domain -> throws", await codeOf(pki.x509.sign(base(["foo@bar"]), { key: s.key })) === "x509/bad-input");
  // An IPv4-SHAPED string that is not a valid address is ambiguous (an invalid IP vs an all-numeric name),
  // so it throws rather than being silently guessed as a dNSName -- the object form is the escape.
  check("Half B: '999.999.999.999' malformed IPv4 -> throws (not guessed as dNSName)", await codeOf(pki.x509.sign(base(["999.999.999.999"]), { key: s.key })) === "x509/bad-input");
  check("Half B: '1.2.3.4.5' (5 numeric groups) -> throws (IPv4-shaped, invalid)", await codeOf(pki.x509.sign(base(["1.2.3.4.5"]), { key: s.key })) === "x509/bad-input");
  check("Half B: '256.1.1.1' (octet out of range) -> throws (IPv4-shaped, invalid)", await codeOf(pki.x509.sign(base(["256.1.1.1"]), { key: s.key })) === "x509/bad-input");
  // The form decision captures packIpLiteral at load, so reassigning the exported ipUtils.packIpLiteral
  // cannot steer a hostname into an iPAddress -- example.com stays dNSName even when packIpLiteral is
  // replaced to force every string to an address.
  var _ipUtils = require("../../lib/ip-utils");
  var _origPack = _ipUtils.packIpLiteral;
  _ipUtils.packIpLiteral = function () { return Buffer.from([1, 2, 3, 4]); };
  var _immForms;
  try { _immForms = sanForms(await pki.x509.sign(base(["example.com"]), { key: s.key })); }
  finally { _ipUtils.packIpLiteral = _origPack; }
  check("Half B immunity: hostname stays dNSName [2] when ipUtils.packIpLiteral is reassigned (captured at load)", _immForms === "2");
  // The IA5String byte conversion (ia5Content) captures Buffer.from at load, so replacing Buffer.from after
  // load cannot steer the emitted dNSName away from the value the classifier checked.
  var _origBufFrom = Buffer.from;
  var _victim = _origBufFrom("victim.example", "latin1"), _evil = _origBufFrom("evil.example", "latin1");   // built BEFORE the swap
  Buffer.from = function (a, b) {
    return (typeof a === "string" && a.indexOf("victim.example") !== -1)
      ? _origBufFrom(a.split("victim.example").join("evil.example"), b) : _origBufFrom(a, b);
  };
  var _immDer;
  try { _immDer = await pki.x509.sign(base(["victim.example"]), { key: s.key }); }
  finally { Buffer.from = _origBufFrom; }
  check("Half B immunity: emitted dNSName comes from the captured Buffer.from, not a replaced one",
    _immDer.indexOf(_victim) !== -1 && _immDer.indexOf(_evil) === -1);
  // The GeneralName emitter reads the classified object's form through captured Object.keys, so a replaced
  // Object.keys cannot relabel a classified dNSName into another form after the classifier validated it.
  var _origKeys = Object.keys;
  Object.keys = function (o) {
    if (o && typeof o === "object" && o.dNSName === "safe.example") { o.rfc822Name = "attacker@evil.example"; return ["rfc822Name"]; }
    return _origKeys(o);
  };
  var _keyDer;
  try { _keyDer = await pki.x509.sign(base(["safe.example"]), { key: s.key }); }
  finally { Object.keys = _origKeys; }
  check("Half B immunity: a classified dNSName is not relabeled by a replaced Object.keys", sanForms(_keyDer) === "2");
  // The DER builder is frozen at load, so a builder method cannot be replaced to steer emitted bytes.
  check("the asn1 DER builder is frozen (no replaceable builder method)", Object.isFrozen(require("../../lib/asn1-der").build) === true);
}

async function testCryptoKeySigningKey() {
  // #75 Half A -- a WebCrypto CryptoKey (from pki.key.generate) is accepted as the signing key directly,
  // without exporting to PKCS#8 first. The capability already worked through signScheme._importKey; these
  // pin it (the advertised-untested closure) and pin the PRECISE refusals the hardened _importKey gives.
  var kp = await pki.key.generate("Ed25519");
  var spki = await pki.key.export(kp.publicKey);
  var certDer = await pki.x509.sign({ subject: "ck-leaf", subjectPublicKey: spki, notBefore: NB, notAfter: NA }, { key: kp.privateKey });
  check("Half A: x509.sign accepts a WebCrypto CryptoKey private key", pki.schema.x509.parse(certDer).subject.dn === "CN=ck-leaf");
  // uniformity: the same CryptoKey signs through csr.sign (the shared _importKey home, not per-verb).
  var csrDer = await pki.csr.sign({ subject: "ck-csr", subjectPublicKey: spki }, { key: kp.privateKey });
  check("Half A: csr.sign accepts a WebCrypto CryptoKey private key", pki.schema.csr.parse(csrDer).subject.dn === "CN=ck-csr");
  // refusal: a PUBLIC CryptoKey cannot sign -- refused precisely by type, not the generic byte message.
  check("Half A: a public CryptoKey is refused, naming the wrong type", await (async function () {
    try { await pki.x509.sign({ subject: "x", subjectPublicKey: spki, notBefore: NB, notAfter: NA }, { key: kp.publicKey }); return false; }
    catch (e) { return e.code === "x509/bad-input" && /type "public"/.test(e.message) && /private key/.test(e.message); }
  })());
  // refusal: a node:crypto KeyObject is not a WebCrypto CryptoKey -- refused precisely, naming it.
  var ko = require("crypto").generateKeyPairSync("ed25519").privateKey;
  check("Half A: a node KeyObject is refused, naming it not a CryptoKey", await (async function () {
    try { await pki.x509.sign({ subject: "x", subjectPublicKey: spki, notBefore: NB, notAfter: NA }, { key: ko }); return false; }
    catch (e) { return e.code === "x509/bad-input" && /KeyObject/.test(e.message); }
  })());
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

  // issue #120: a pki.webcrypto RSASSA-PKCS1-v1_5 CryptoKey is accepted as issuer.key -- the WebCrypto
  // algorithm-name match is ASCII-case-folded, and pki.webcrypto now emits the standard-cased name, so the
  // toolkit's OWN CryptoKey works as the signer (previously it threw on the RSASSA-PKCS1-V1_5 vs -v1_5 casing).
  var wcKp = await pki.webcrypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" }, true, ["sign", "verify"]);
  var wcSpki = Buffer.from(await pki.webcrypto.subtle.exportKey("spki", wcKp.publicKey));
  check("#120 a pki.webcrypto RSASSA-PKCS1-v1_5 CryptoKey signs a certificate", Buffer.isBuffer(await pki.x509.sign({ subject: caName, subjectPublicKey: wcSpki, notBefore: NB, notAfter: NA, extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign"] } }, { key: wcKp.privateKey })));

  // A CryptoKey from a DIFFERENT WebCrypto implementation is indistinguishable from this engine's
  // own by type / algorithm / usages, but carries none of the key material this engine signs with.
  // issuer.key is documented as taking a CryptoKey, so an extractable foreign key is re-imported
  // through this engine, and a non-extractable one -- whose material cannot be reached at all --
  // is refused with THAT reason rather than a raw type error from inside the crypto library.
  var nodeWc = require("crypto").webcrypto;
  var foreignKp = await nodeWc.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var foreignSpki = Buffer.from(await nodeWc.subtle.exportKey("spki", foreignKp.publicKey));
  var foreignPkcs8 = Buffer.from(await nodeWc.subtle.exportKey("pkcs8", foreignKp.privateKey));
  check("a platform WebCrypto CryptoKey signs a certificate", Buffer.isBuffer(
    await pki.x509.sign({ subject: caName, subjectPublicKey: foreignSpki, notBefore: NB, notAfter: NA }, { key: foreignKp.privateKey })));
  // ... and the certificate it produces verifies under the matching public key, so the re-import
  // carried the SAME key rather than quietly signing with something else.
  var foreignDer = await pki.x509.sign({ subject: caName, subjectPublicKey: foreignSpki, notBefore: NB, notAfter: NA }, { key: foreignKp.privateKey });
  var foreignParsed = pki.schema.x509.parse(foreignDer);
  check("the platform-key certificate verifies under its own public key",
    (await pki.path.validate([foreignParsed], { time: NB, trustAnchor: { name: foreignParsed.subject, publicKey: foreignParsed.subjectPublicKeyInfo.bytes, algorithm: foreignParsed.subjectPublicKeyInfo.algorithm } }))
      .results[0].checks.find(function (c) { return c.name === "signature"; }).ok === true);
  var sealed = await nodeWc.subtle.importKey("pkcs8", foreignPkcs8, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  check("a non-extractable platform CryptoKey is refused, naming the real reason", await (async function () {
    try { await pki.x509.sign({ subject: caName, subjectPublicKey: foreignSpki, notBefore: NB, notAfter: NA }, { key: sealed }); return false; }
    catch (e) { return e.code === "x509/bad-input" && /is not extractable/.test(e.message); }
  })());
  // The same path holds for a second key class, so it is the foreign-key handling that is generic
  // and not one algorithm'"'"'s import parameters happening to line up.
  var foreignRsa = await nodeWc.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  // A key that does not carry its permitted usages cannot be adopted without inventing them, so it
  // is refused rather than being re-imported with whatever the operation happened to need.
  check("a key object carrying no usages is refused", await (async function () {
    try { await pki.x509.sign({ subject: caName, subjectPublicKey: foreignSpki, notBefore: NB, notAfter: NA },
      { key: { type: "private", extractable: true, algorithm: { name: "ECDSA", namedCurve: "P-256" } } }); return false; }
    catch (e) { return e.code === "x509/bad-input" && /carrying its permitted usages/.test(e.message); }
  })());
  // A key object shaped like a CryptoKey but belonging to neither implementation -- what a userland
  // WebCrypto polyfill hands back -- reaches the export step and cannot be exported; it is refused
  // with that reason rather than with a rejection raised inside the crypto library.
  var polyfillKey = { type: "private", extractable: true, algorithm: { name: "ECDSA", namedCurve: "P-256" }, usages: ["sign"] };
  check("a CryptoKey-shaped key that cannot be exported is refused, naming the real reason", await (async function () {
    try { await pki.x509.sign({ subject: caName, subjectPublicKey: foreignSpki, notBefore: NB, notAfter: NA }, { key: polyfillKey }); return false; }
    catch (e) { return e.code === "x509/bad-input" && /could not be exported for re-import/.test(e.message); }
  })());
  check("a platform WebCrypto RSA CryptoKey signs a certificate", Buffer.isBuffer(
    await pki.x509.sign({ subject: caName, subjectPublicKey: Buffer.from(await nodeWc.subtle.exportKey("spki", foreignRsa.publicKey)), notBefore: NB, notAfter: NA }, { key: foreignRsa.privateKey })));

  // #75 Half A: a WebCrypto RSA-PSS CryptoKey is bound to PSS. Its generic rsaEncryption SPKI resolves to
  // the default RSASSA-PKCS1-v1_5 under default opts, which a PSS-bound key cannot produce -- the error
  // names opts.pss -- and it signs once opts.pss selects the RSASSA-PSS scheme.
  var pssKp = await nodeWc.subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  var pssSpki = Buffer.from(await nodeWc.subtle.exportKey("spki", pssKp.publicKey));
  check("an RSA-PSS CryptoKey under default opts is refused, naming opts.pss", await (async function () {
    try { await pki.x509.sign({ subject: caName, subjectPublicKey: pssSpki, notBefore: NB, notAfter: NA }, { key: pssKp.privateKey }); return false; }
    catch (e) { return e.code === "x509/bad-input" && /pass opts\.pss/.test(e.message); }
  })());
  check("an RSA-PSS CryptoKey signs a certificate with opts.pss", Buffer.isBuffer(
    await pki.x509.sign({ subject: caName, subjectPublicKey: pssSpki, notBefore: NB, notAfter: NA }, { key: pssKp.privateKey }, { pss: true })));

  // raw Name DER as subject (the escape hatch) round-trips.
  var rawName = B.sequence([B.set([B.sequence([B.oid(oidB("commonName")), B.utf8("Raw DN")])])]);
  check("raw Name DER subject round-trips", /Raw DN/.test(pki.schema.x509.parse(await pki.x509.sign(base({ subject: rawName }), { key: s.key })).subject.dn));
  // #68: a raw Name DER subject accepts any BufferSource. An ArrayBuffer of the same DER round-trips.
  var rawNameAB = new ArrayBuffer(rawName.length); new Uint8Array(rawNameAB).set(rawName);
  check("raw Name DER subject as an ArrayBuffer round-trips (#68)",
    /Raw DN/.test(pki.schema.x509.parse(await pki.x509.sign(base({ subject: rawNameAB }), { key: s.key })).subject.dn));
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

// The shared name / extension-value builder's documented rejects (lib/pki-build.js), driven through
// pki.x509.sign. Every one is a config-time contract an operator can trip on a typo, and each is a
// distinct failure mode the module advertises -- so each gets its own vector rather than being
// represented by a neighbor that happens to throw the same code.
async function testSharedBuilderRejects() {
  var s = makeSigner("ed25519");
  var B = pki.asn1.build;
  function base(over) { return Object.assign({ subject: "e", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA }, over); }
  function sign(over, issuer) { return pki.x509.sign(base(over), issuer || { key: s.key }); }

  // ---- distinguished-name specs ----
  check("an empty-string DN attribute value -> x509/bad-name",
    await codeOf(sign({ subject: [{ commonName: "" }] })) === "x509/bad-name");
  check("a null DN attribute value -> x509/bad-name",
    await codeOf(sign({ subject: [{ commonName: null }] })) === "x509/bad-name");
  check("an unregistered DN attribute name -> x509/bad-name",
    await codeOf(sign({ subject: [{ notAnAttribute: "x" }] })) === "x509/bad-name");
  check("an RDN that is not an object -> x509/bad-name",
    await codeOf(sign({ subject: ["Common Name"] })) === "x509/bad-name");
  check("an RDN given as a Buffer -> x509/bad-name",
    await codeOf(sign({ subject: [Buffer.from([0x30, 0x00])] })) === "x509/bad-name");
  check("an RDN object with no attributes -> x509/bad-name",
    await codeOf(sign({ subject: [{}] })) === "x509/bad-name");
  check("a name that is neither string, array nor Buffer -> x509/bad-name",
    await codeOf(sign({ subject: 42 })) === "x509/bad-name");
  // Raw Name DER goes through the same RDNSequence parser the decoder uses, so a well-formed TLV that
  // is not a Name is refused rather than riding into the certificate unvalidated.
  check("raw Name DER that is not valid DER -> x509/bad-name",
    await codeOf(sign({ subject: Buffer.from([0x30, 0x7f, 0x01]) })) === "x509/bad-name");
  check("raw Name DER whose RDN is not a SET -> x509/bad-rdn",
    await codeOf(sign({ subject: B.sequence([B.integer(1n)]) })) === "x509/bad-rdn");
  check("raw Name DER whose RDN member is not an AttributeTypeAndValue SEQUENCE -> x509/bad-atv",
    await codeOf(sign({ subject: B.sequence([B.set([B.integer(1n)])]) })) === "x509/bad-atv");
  check("raw Name DER that is not a SEQUENCE at all -> x509/bad-name",
    await codeOf(sign({ subject: B.octetString(Buffer.from([1])) })) === "x509/bad-name");
  // A leaf fault inside an otherwise well-formed Name surfaces the codec's own DER code rather than an
  // x509/* one: pki-build re-throws an Asn1Error unchanged, so a caller filtering on the x509 domain
  // alone would miss this. Pinned so the two-domain contract is visible rather than incidental.
  check("a raw Name whose attribute type is not an OID surfaces the codec's DER fault",
    await codeOf(sign({ subject: B.sequence([B.set([B.sequence([B.integer(1n), B.utf8("x")])])]) })) === "asn1/unexpected-tag");
  check("a countryName that is not two letters -> x509/bad-name",
    await codeOf(sign({ subject: [{ countryName: "USA" }] })) === "x509/bad-name");

  // ---- GeneralName specs (subjectAltName) ----
  // A bare string is now the #75 shorthand (classified into its form -- see testGeneralNameForms); a
  // non-object, non-string value (a number here) is still rejected as a mis-shaped GeneralName.
  check("a GeneralName that is neither an object nor a string -> x509/bad-input",
    await codeOf(sign({ extensions: { subjectAltName: [123] } })) === "x509/bad-input");
  check("a GeneralName given as a Buffer -> x509/bad-input",
    await codeOf(sign({ extensions: { subjectAltName: [Buffer.from([1])] } })) === "x509/bad-input");
  check("a GeneralName with two forms at once -> x509/bad-input",
    await codeOf(sign({ extensions: { subjectAltName: [{ dNSName: "a.example", rfc822Name: "b@example" }] } })) === "x509/bad-input");
  check("an empty GeneralName value -> x509/bad-input",
    await codeOf(sign({ extensions: { subjectAltName: [{ dNSName: "" }] } })) === "x509/bad-input");
  check("a non-ASCII value in an IA5String GeneralName form -> x509/bad-input",
    await codeOf(sign({ extensions: { subjectAltName: [{ dNSName: "h" + String.fromCharCode(0xe9) + "st.example" }] } })) === "x509/bad-input");
  check("an empty subjectAltName list -> x509/bad-input",
    await codeOf(sign({ extensions: { subjectAltName: [] } })) === "x509/bad-input");

  // ---- keyUsage / extendedKeyUsage ----
  check("an empty keyUsage list -> x509/bad-input",
    await codeOf(sign({ extensions: { keyUsage: [] } })) === "x509/bad-input");
  check("a keyUsage that is not an array -> x509/bad-input",
    await codeOf(sign({ extensions: { keyUsage: "digitalSignature" } })) === "x509/bad-input");
  check("an unknown keyUsage bit name -> x509/bad-input",
    await codeOf(sign({ extensions: { keyUsage: ["digitalSignature", "notABit"] } })) === "x509/bad-input");
  check("an empty extendedKeyUsage list -> x509/bad-input",
    await codeOf(sign({ extensions: { extendedKeyUsage: [] } })) === "x509/bad-input");
  check("an extendedKeyUsage that is not an array -> x509/bad-input",
    await codeOf(sign({ extensions: { extendedKeyUsage: "serverAuth" } })) === "x509/bad-input");

  // ---- basicConstraints ----
  check("a non-boolean basicConstraints cA -> x509/bad-input",
    await codeOf(sign({ extensions: { basicConstraints: { cA: "yes" } } })) === "x509/bad-input");
  check("a non-boolean basicConstraints critical -> x509/bad-input",
    await codeOf(sign({ extensions: { basicConstraints: { cA: true, critical: "yes" } } })) === "x509/bad-input");
  check("a non-integer pathLen -> x509/bad-input",
    await codeOf(sign({ extensions: { basicConstraints: { cA: true, pathLen: 1.5 } } })) === "x509/bad-input");
  check("a negative pathLen -> x509/bad-input",
    await codeOf(sign({ extensions: { basicConstraints: { cA: true, pathLen: -1 } } })) === "x509/bad-input");
  check("a non-numeric pathLen -> x509/bad-input",
    await codeOf(sign({ extensions: { basicConstraints: { cA: true, pathLen: "2" } } })) === "x509/bad-input");
  check("an unknown basicConstraints field -> x509/bad-input",
    await codeOf(sign({ extensions: { basicConstraints: { cA: true, pathLenConstraint: 2 } } })) === "x509/bad-input");

  // ---- certificatePolicies ----
  check("an empty certificatePolicies list -> x509/bad-input",
    await codeOf(sign({ extensions: { certificatePolicies: [] } })) === "x509/bad-input");
  check("a certificatePolicies that is not an array -> x509/bad-input",
    await codeOf(sign({ extensions: { certificatePolicies: "anyPolicy" } })) === "x509/bad-input");
  // The duplicate is caught on the OID, so a registered NAME and its dotted form collide -- the check
  // an operator most needs and the one a name-only comparison would miss.
  check("the same policy twice by name -> x509/bad-input",
    await codeOf(sign({ extensions: { certificatePolicies: ["anyPolicy", "anyPolicy"] } })) === "x509/bad-input");
  check("a policy repeated as a name and as its dotted OID -> x509/bad-input",
    await codeOf(sign({ extensions: { certificatePolicies: ["anyPolicy", pki.oid.byName("anyPolicy")] } })) === "x509/bad-input");
  check("an unknown policy token that is neither a registered name nor dotted -> x509/bad-input",
    await codeOf(sign({ extensions: { certificatePolicies: ["not a policy"] } })) === "x509/bad-input");
  // A dotted string passes the shape check but b.oid is the authoritative arc-bounds test: a first arc
  // of 1 caps the second at 39, and the failure must surface as this producer's code, not a leaked oid/*.
  check("a dotted OID violating the X.660 arc bounds -> x509/bad-input",
    await codeOf(sign({ extensions: { certificatePolicies: ["1.40.1"] } })) === "x509/bad-input");
  check("an out-of-range arc in an extendedKeyUsage OID -> x509/bad-input",
    await codeOf(sign({ extensions: { extendedKeyUsage: ["1.99.1"] } })) === "x509/bad-input");

  // ---- pre-encoded extension array (the escape hatch) ----
  check("a pre-encoded extension that is not valid DER -> x509/bad-input",
    await codeOf(sign({ extensions: [Buffer.from([0x30, 0x7f, 0x01])] })) === "x509/bad-input");
  check("a pre-encoded extension whose extnID is not an OID -> x509/bad-input",
    await codeOf(sign({ extensions: [B.sequence([B.integer(1n), B.octetString(B.nullValue())])] })) === "x509/bad-input");
  check("a pre-encoded extension whose critical field is not a BOOLEAN -> x509/bad-input",
    await codeOf(sign({ extensions: [B.sequence([B.oid(pki.oid.byName("ocspNoCheck")), B.integer(1n), B.octetString(B.nullValue())])] })) === "x509/bad-input");
  check("a pre-encoded extension whose extnValue is not an OCTET STRING -> x509/bad-input",
    await codeOf(sign({ extensions: [B.sequence([B.oid(pki.oid.byName("ocspNoCheck")), B.integer(1n)])] })) === "x509/bad-input");
  check("an extensions spec that is neither an object nor an array -> x509/bad-input",
    await codeOf(sign({ extensions: "basicConstraints" })) === "x509/bad-input");
  // An EMPTY extensions spec is not an error at this entry: the certificate version derives from the
  // field set, so `[]` / `{}` issue a v1 certificate with no extensions block. (The builder's
  // "must carry at least one" rejects belong to the CSR extensionRequest path, covered in csr-sign.)
  var v1Empty = pki.schema.x509.parse(await sign({ extensions: [] }));
  var v1EmptyObj = pki.schema.x509.parse(await sign({ extensions: {} }));
  check("an empty extensions array issues a v1 certificate with no extensions",
    v1Empty.version === 1 && (v1Empty.extensions || []).length === 0);
  check("an empty extensions object does the same",
    v1EmptyObj.version === 1 && (v1EmptyObj.extensions || []).length === 0);

  // ---- issuer signing-key SPKI ----
  check("an issuer publicKey SPKI with no children -> x509/bad-spki",
    await codeOf(sign({}, { name: "CA", publicKey: B.sequence([]), key: s.key })) === "x509/bad-spki");
  check("an issuer publicKey SPKI that is not a SEQUENCE -> x509/bad-spki",
    await codeOf(sign({}, { name: "CA", publicKey: B.integer(1n), key: s.key })) === "x509/bad-spki");
  check("an issuer publicKey with an empty AlgorithmIdentifier -> x509/bad-algorithm-identifier",
    await codeOf(sign({}, { name: "CA", publicKey: B.sequence([B.sequence([]), B.bitString(Buffer.from([1]), 0)]), key: s.key })) === "x509/bad-algorithm-identifier");
  // The same two-domain split as the raw-Name case above: a STRUCTURAL fault in caller-supplied DER is
  // an x509/* code, but a LEAF read fault surfaces the codec's own asn1/* code unchanged.
  check("an issuer publicKey whose algorithm field is not an OID surfaces the codec's DER fault",
    await codeOf(sign({}, { name: "CA", publicKey: B.sequence([B.sequence([B.integer(1n)]), B.bitString(Buffer.from([1]), 0)]), key: s.key })) === "asn1/unexpected-tag");

  // That two-domain contract is documented on every producer that accepts raw DER, so it is asserted
  // across all of them together: a contract stated in four @primitive blocks but pinned for only one
  // would let the other three drift to a different code without a test noticing.
  var ec = makeSigner("ec-p256");
  var badName = B.sequence([B.set([B.sequence([B.integer(1n), B.utf8("x")])])]);
  var goodName = B.sequence([B.set([B.sequence([B.oid(pki.oid.byName("commonName")), B.utf8("CA")])])]);
  var rawIssuer = { name: badName, publicKey: ec.spki, key: ec.key };
  var attrSpec = { holder: { entityName: [{ directoryName: goodName }] }, notBeforeTime: NB, notAfterTime: NA, attributes: [{ type: "role", value: B.sequence([]) }] };
  check("csr.sign surfaces the codec's DER fault for a malformed raw subject Name",
    await codeOf(pki.csr.sign({ subject: badName, subjectPublicKey: ec.spki }, { key: ec.key })) === "asn1/unexpected-tag");
  check("crl.sign surfaces the codec's DER fault for a malformed raw issuer Name",
    await codeOf(pki.crl.sign({ thisUpdate: NB, nextUpdate: NA, revoked: [] }, rawIssuer)) === "asn1/unexpected-tag");
  check("attrcert.sign surfaces the codec's DER fault for a malformed raw issuer Name",
    await codeOf(pki.attrcert.sign(attrSpec, rawIssuer)) === "asn1/unexpected-tag");
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

// issue #119: extendedKeyUsage / certificatePolicies accept a raw dotted-OID (an unregistered KeyPurposeId
// or private policy OID -- BIMI, document-signing, vendor purposes) alongside registered names.
async function testDottedOidPurposes() {
  var s = makeSigner("ec-p256");
  function base(exts) { return { subject: "eku", subjectPublicKey: s.spki, notBefore: NB, notAfter: NA, extensions: exts }; }
  var bimi = "1.3.6.1.5.5.7.3.31";                 // id-kp-BrandIndicatorforMessageIdentification (unregistered here)
  var serverAuth = "1.3.6.1.5.5.7.3.1";            // the registered id-kp-serverAuth OID
  var der = await pki.x509.sign(base({ extendedKeyUsage: ["serverAuth", bimi] }), { key: s.key });
  var eku = pki.schema.x509.parse(der).extensions.filter(function (x) { return (x.name || x.oid) === "extKeyUsage"; })[0];
  var purposeOids = asn1.decode(eku.value).children.map(function (n) { return asn1.read.oid(n); });
  check("#119 a dotted-OID extendedKeyUsage purpose is emitted verbatim", purposeOids.indexOf(bimi) !== -1);
  check("#119 a registered EKU name still resolves alongside a dotted OID", purposeOids.indexOf(serverAuth) !== -1);
  check("#119 an unknown EKU name (not a dotted OID) still fails closed", await codeOf(pki.x509.sign(base({ extendedKeyUsage: ["notAPurpose"] }), { key: s.key })) === "x509/bad-input");
  check("#119 a malformed dotted EKU OID fails closed", await codeOf(pki.x509.sign(base({ extendedKeyUsage: ["1.2.bad"] }), { key: s.key })) === "x509/bad-input");
  check("#119 a lexically-dotted but arc-invalid OID surfaces the producer's bad-input, not oid/*", await codeOf(pki.x509.sign(base({ extendedKeyUsage: ["1.40"] }), { key: s.key })) === "x509/bad-input");
  var privPolicy = "1.3.6.1.4.1.99999.1";
  var derP = await pki.x509.sign(base({ certificatePolicies: ["anyPolicy", privPolicy] }), { key: s.key });
  var cp = pki.schema.x509.parse(derP).extensions.filter(function (x) { return (x.name || x.oid) === "certificatePolicies"; })[0];
  var policyOids = asn1.decode(cp.value).children.map(function (pi) { return asn1.read.oid(pi.children[0]); });
  check("#119 a dotted-OID certificatePolicy is emitted verbatim", policyOids.indexOf(privPolicy) !== -1);
  check("#119 an unknown certificate policy name still fails closed", await codeOf(pki.x509.sign(base({ certificatePolicies: ["notAPolicy"] }), { key: s.key })) === "x509/bad-input");
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
  await testCryptoKeySigningKey();
  await testDottedOidPurposes();
  await testInputForms();
  await testCoverageEdges();
  await testSharedBuilderRejects();
  await testKeyMatchAndTimeAndSan();
  await testFailClosed();
  await testOpensslInterop();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
