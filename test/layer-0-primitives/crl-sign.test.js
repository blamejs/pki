// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// RED conformance vectors for pki.crl.sign / .verify / .isRevoked -- the X.509 CRL producing side
// (RFC 5280 sec. 5). Every vector drives the shipped consumer and asserts through pki.schema.crl.parse
// round-trip, a raw asn1.decode of the emitted DER, pki.crl.verify's boolean verdict, or err.code. Keys
// come from the makeSigner helper (real runtime keypairs, every algorithm arm). schema-crl's strict
// decoder is the round-trip oracle -- it enforces the reasonCode ENUMERATED tag, the invalidityDate
// GeneralizedTime-only rule, the v2-iff-extensions rule, the non-empty revokedCertificates SEQUENCE OF,
// and the outer==inner signatureAlgorithm agreement, so a successful parse proves those on the wire.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var asn1 = pki.asn1;
var TAGS = asn1.TAGS;
function byName(n) { return pki.oid.byName(n); }

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}

var TU = new Date("2026-01-01T00:00:00Z");
var NU = new Date("2026-02-01T00:00:00Z");
var RD = new Date("2026-01-15T00:00:00Z");

function issuerOf(s, name) { return { name: name || "Test CRL Issuer", publicKey: s.spki, key: s.key }; }
function crlExt(c, name) { return c.crlExtensions.filter(function (x) { return x.oid === byName(name); })[0]; }
function entryExt(entry, name) { return entry.crlEntryExtensions.filter(function (x) { return x.oid === byName(name); })[0]; }

// ---- round-trip + field decoding -------------------------------------------

async function testRoundTrip() {
  var s = makeSigner("ec-p256");
  var der = await pki.crl.sign({
    thisUpdate: TU, nextUpdate: NU, crlNumber: 7n,
    revoked: [{ serialNumber: 0x1234n, revocationDate: RD, reason: "keyCompromise" }],
    extensions: { authorityKeyIdentifier: Buffer.alloc(20, 0xab) },
  }, issuerOf(s));

  check("sign returns a Buffer", Buffer.isBuffer(der));
  var c = pki.schema.crl.parse(der);
  check("round-trip version = 2", c.version === 2);
  check("round-trip issuer CN", /Test CRL Issuer/.test(c.issuer.dn));
  check("round-trip thisUpdate Date", c.thisUpdate.getTime() === TU.getTime());
  check("round-trip nextUpdate Date", c.nextUpdate.getTime() === NU.getTime());
  check("one revoked entry", c.revokedCertificates.length === 1);
  check("round-trip serialNumberHex", c.revokedCertificates[0].serialNumberHex === "1234");
  check("round-trip revocationDate Date", c.revokedCertificates[0].revocationDate.getTime() === RD.getTime());
  check("reasonCode decoded to 1", (entryExt(c.revokedCertificates[0], "reasonCode") || {}).value === 1);
  check("cRLNumber decoded to 7n", (crlExt(c, "cRLNumber") || {}).value === 7n);

  // tbsBytes is the exact signed range -- re-parsing must recover identical bytes.
  check("tbsBytes byte-stable across re-parse", Buffer.compare(c.tbsBytes, pki.schema.crl.parse(der).tbsBytes) === 0);
}

// ---- sec. 5.1.2.6 -- an empty revocation list omits the field (not an empty SEQUENCE) ----

async function testEmptyListOmitsRevoked() {
  var s = makeSigner("ed25519");
  // schema-crl's REVOKED_LIST has min:1, so an emitted EMPTY SEQUENCE OF would throw crl/bad-revoked-certificates
  // here -- a clean parse proves the field was OMITTED entirely.
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [] }, issuerOf(s)));
  check("empty revoked list parses (field omitted, no empty SEQUENCE)", c.revokedCertificates.length === 0);
  check("no-extension CRL is v1", c.version === 1);
}

// ---- sec. 5.1.2.1 -- version derived from the extension set ----

async function testVersionDerivation() {
  var s = makeSigner("ec-p256");
  var v1 = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 5n, revocationDate: RD }] }, issuerOf(s)));
  check("no extensions -> v1 (version omitted)", v1.version === 1);
  var v2n = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, issuerOf(s)));
  check("a CRL extension -> v2", v2n.version === 2);
  var v2e = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 5n, revocationDate: RD, reason: "superseded" }] }, issuerOf(s)));
  check("an entry extension -> v2", v2e.version === 2);
}

// ---- sec. 5.3.2 -- invalidityDate is ALWAYS GeneralizedTime (not the UTCTime cutover) ----

async function testInvalidityDateGeneralizedTime() {
  var s = makeSigner("ec-p256");
  var when = new Date("2020-06-01T00:00:00Z");   // < year 2050: the timeDer cutover would wrongly pick UTCTime
  // schema-crl.decodeExt REQUIRES GeneralizedTime for invalidityDate, so a clean parse proves the builder
  // used b.generalizedTime directly (the trap is reusing timeDer here).
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 9n, revocationDate: RD, invalidityDate: when }] }, issuerOf(s)));
  var iv = entryExt(c.revokedCertificates[0], "invalidityDate");
  check("invalidityDate decoded (GeneralizedTime-only enforced)", iv && iv.value.getTime() === when.getTime());
}

// ---- sec. 5.3.1 -- reasonCode ENUMERATED + value rules ----

async function testReasonCodeRules() {
  var s = makeSigner("ec-p256");
  // read.enumerated in schema-crl rejects a bare INTEGER, so a clean parse proves the ENUMERATED tag (0x0A).
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: "cACompromise" }] }, issuerOf(s)));
  check("reason cACompromise -> ENUMERATED value 2", (entryExt(c.revokedCertificates[0], "reasonCode") || {}).value === 2);
  check("reason 7 (unused) -> crl/bad-reason-code",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: 7 }] }, issuerOf(s))) === "crl/bad-reason-code");
  check("removeFromCRL(8) in a complete CRL -> crl/bad-reason-code",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: "removeFromCRL" }] }, issuerOf(s))) === "crl/bad-reason-code");
  // unspecified(0) SHOULD be absent -> the builder OMITS it (no extension -> v1).
  var u = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, reason: 0 }] }, issuerOf(s)));
  check("unspecified(0) reason omitted -> entry has no extensions", u.revokedCertificates[0].crlEntryExtensions.length === 0);
  check("an unspecified(0)-only CRL is v1", u.version === 1);
}

// ---- sec. 5.1.1.2 -- signature == signatureAlgorithm, single source ----

async function testSigAlgSingleSource() {
  var s = makeSigner("ec-p256");
  var der = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, issuerOf(s));
  var top = asn1.decode(der);
  var tbs = top.children[0], outerSig = top.children[1];
  var i = (tbs.children[0].tagClass === "universal" && tbs.children[0].tagNumber === TAGS.INTEGER) ? 1 : 0;   // skip the bare version INTEGER
  check("tbs.signature bytes == outer signatureAlgorithm bytes", Buffer.compare(tbs.children[i].bytes, outerSig.bytes) === 0);
  check("parse accepts it (no crl/bad-signature-algorithm)", pki.schema.crl.parse(der).version === 2);
}

// ---- sec. 5.2.3 -- cRLNumber INTEGER (0..MAX), <= 20 octets ----

async function testCrlNumberCap() {
  var s = makeSigner("ec-p256");
  var big21 = Buffer.alloc(21, 0xff); big21[0] = 0x7f;   // 21 content octets (top bit clear -> no sign pad)
  var big20 = Buffer.alloc(20, 0xff); big20[0] = 0x7f;   // 20 content octets
  check("21-octet cRLNumber -> crl/bad-crl-number",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: big21 }, issuerOf(s))) === "crl/bad-crl-number");
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: big20 }, issuerOf(s)));
  check("20-octet cRLNumber accepted + round-trips", (crlExt(c, "cRLNumber") || {}).value === BigInt("0x" + big20.toString("hex")));
}

// ---- sec. 5.2.1 -- authorityKeyIdentifier: keyIdentifier method only, non-critical ----

async function testAkiShape() {
  var s = makeSigner("ec-p256", { ski: true });
  var der = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, extensions: { authorityKeyIdentifier: true } }, { cert: s.cert, key: s.key });
  var aki = crlExt(pki.schema.crl.parse(der), "authorityKeyIdentifier");
  check("AKI present", !!aki);
  check("AKI non-critical", aki.critical === false);
  var v = asn1.decode(aki.value);
  check("AKI is SEQUENCE { [0] keyIdentifier } only", v.children.length === 1 && v.children[0].tagClass === "context" && v.children[0].tagNumber === 0);
  var ski = pki.schema.x509.parse(s.cert).extensions.filter(function (x) { return x.oid === byName("subjectKeyIdentifier"); })[0];
  check("AKI key id == the issuer cert SKI", Buffer.compare(v.children[0].content, asn1.read.octetString(asn1.decode(ski.value))) === 0);
}

// ---- sec. 5.1.1.3 -- verify over the raw tbs, per algorithm, fail-closed ----

async function testVerifyPerAlgorithm() {
  var arms = ["rsa", "ec-p256", "ed25519", "ml-dsa-65"];
  for (var k = 0; k < arms.length; k++) {
    var alg = arms[k];
    var s = makeSigner(alg);
    var der = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, revoked: [{ serialNumber: 3n, revocationDate: RD, reason: "keyCompromise" }] }, issuerOf(s));
    check(alg + " verify true with the correct key", (await pki.crl.verify(der, { publicKey: s.spki })) === true);
    var bad = Buffer.from(der); bad[bad.length - 1] ^= 0xff;
    check(alg + " verify false on a tampered signature", (await pki.crl.verify(bad, { publicKey: s.spki })) === false);
    check(alg + " verify false with a wrong key", (await pki.crl.verify(der, { publicKey: makeSigner(alg).spki })) === false);
  }
  // RSA-PSS arm (opts.pss)
  var rp = makeSigner("rsa");
  var pssDer = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, issuerOf(rp), { pss: true });
  check("RSA-PSS CRL verifies", (await pki.crl.verify(pssDer, { publicKey: rp.spki })) === true);
}

// ---- RFC 9814 sec. 4 -- algorithm-confusion fails closed ----

async function testVerifyAlgorithmConfusion() {
  var ec = makeSigner("ec-p256"), ed = makeSigner("ed25519");
  var der = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, issuerOf(ec));
  check("ECDSA CRL against an Ed25519 SPKI -> verify false", (await pki.crl.verify(der, { publicKey: ed.spki })) === false);
}

// ---- sec. 5.2.5 -- IssuingDistributionPoint gates ----

async function testIdpGates() {
  var s = makeSigner("ec-p256");
  function idp(v) { return pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, extensions: { issuingDistributionPoint: v } }, issuerOf(s)); }
  var e = crlExt(pki.schema.crl.parse(await idp({ onlyContainsUserCerts: true })), "issuingDistributionPoint");
  check("IDP present + critical", e && e.critical === true);
  var vv = asn1.decode(e.value);
  check("IDP emits only the [1] scope boolean (DEFAULT-FALSE omitted)", vv.children.length === 1 && vv.children[0].tagClass === "context" && vv.children[0].tagNumber === 1);
  check("empty IDP -> crl/bad-idp", await codeOf(idp({})) === "crl/bad-idp");
  check("two scope booleans TRUE -> crl/bad-idp", await codeOf(idp({ onlyContainsUserCerts: true, onlyContainsCACerts: true })) === "crl/bad-idp");
  check("onlyContainsAttributeCerts=TRUE -> crl/bad-idp", await codeOf(idp({ onlyContainsAttributeCerts: true })) === "crl/bad-idp");
}

// ---- sec. 5.2.4 / 5.2.6 -- delta CRL indicator + freshestCRL conflict ----

async function testDeltaAndFreshest() {
  var s = makeSigner("ec-p256");
  var d = crlExt(pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: { deltaCRLIndicator: 3n } }, issuerOf(s))), "deltaCRLIndicator");
  check("deltaCRLIndicator present + critical", d && d.critical === true);
  check("delta CRL + freshestCRL -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: { deltaCRLIndicator: 3n, freshestCRL: [{ uniformResourceIdentifier: "http://x/f.crl" }] } }, issuerOf(s))) === "crl/bad-input");
  var rc = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 6n, extensions: { deltaCRLIndicator: 3n }, revoked: [{ serialNumber: 2n, revocationDate: RD, reason: "removeFromCRL" }] }, issuerOf(s)));
  check("removeFromCRL(8) accepted in a delta CRL", (entryExt(rc.revokedCertificates[0], "reasonCode") || {}).value === 8);
}

// ---- PEM output + isRevoked lookup ----

async function testPemAndIsRevoked() {
  var s = makeSigner("ed25519");
  var pem = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, revoked: [{ serialNumber: 0xabcdn, revocationDate: RD }] }, issuerOf(s), { pem: true });
  check("opts.pem returns a string", typeof pem === "string");
  check("opts.pem has BEGIN X509 CRL", /-----BEGIN X509 CRL-----/.test(pem));
  var der = pki.schema.crl.pemDecode(pem);
  check("isRevoked finds a listed serial", pki.crl.isRevoked(der, 0xabcdn) !== null);
  // 0xabcd has its top bit set, so the DER INTEGER content carries a leading 00 sign octet -- isRevoked
  // normalizes the query the same way schema-crl surfaces serialNumberHex, so the padded forms match.
  check("isRevoked returns the matching entry (sign padding preserved)", pki.crl.isRevoked(der, 0xabcdn).serialNumberHex === "00abcd");
  check("isRevoked returns null for an absent serial", pki.crl.isRevoked(der, 0x9999n) === null);
}

// ---- config-time fail-closed ----

async function testFailClosed() {
  var s = makeSigner("ec-p256");
  check("no signing key -> crl/bad-input", await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU }, { publicKey: s.spki })) === "crl/bad-input");
  check("empty issuer DN -> crl/bad-issuer", await codeOf(pki.crl.sign({ issuer: [], thisUpdate: TU, nextUpdate: NU }, { publicKey: s.spki, key: s.key })) === "crl/bad-issuer");
  check("missing thisUpdate -> crl/bad-input", await codeOf(pki.crl.sign({ nextUpdate: NU }, issuerOf(s))) === "crl/bad-input");
  check("nextUpdate before thisUpdate -> crl/bad-input", await codeOf(pki.crl.sign({ thisUpdate: NU, nextUpdate: TU }, issuerOf(s))) === "crl/bad-input");
  check("revoked entry without a serialNumber -> crl/bad-input", await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ revocationDate: RD }] }, issuerOf(s))) === "crl/bad-input");
  check("unknown CRL extension key -> crl/bad-input", await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: { bogus: 1 } }, issuerOf(s))) === "crl/bad-input");
}

// ---- sec. 5.2.3 / 5.2.4 -- a delta CRL MUST carry a cRLNumber greater than its baseCRLNumber ----

async function testDeltaRequiresCrlNumber() {
  var s = makeSigner("ec-p256");
  check("delta CRL with no cRLNumber -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: { deltaCRLIndicator: 3n } }, issuerOf(s))) === "crl/bad-input");
  check("delta CRL whose cRLNumber == baseCRLNumber -> crl/bad-crl-number",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 3n, extensions: { deltaCRLIndicator: 3n } }, issuerOf(s))) === "crl/bad-crl-number");
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: { deltaCRLIndicator: 3n } }, issuerOf(s)));
  check("delta CRL with cRLNumber > baseCRLNumber accepted", (crlExt(c, "deltaCRLIndicator") || {}).critical === true && (crlExt(c, "cRLNumber") || {}).value === 5n);
}

// ---- sec. 4.2.1.3 -- an issuer cert whose keyUsage omits cRLSign cannot sign a CRL ----

async function testIssuerCertCrlSign() {
  var s = makeSigner("ec-p256");
  var base = { subjectPublicKey: s.spki, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z") };
  var caCrlSign = pki.schema.x509.parse(await pki.x509.sign(Object.assign({ subject: "CA cRLSign", extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, base), { key: s.key }));
  check("issuer cert asserting cRLSign signs a CRL", Buffer.isBuffer(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, { cert: caCrlSign, key: s.key })));
  var caNoCrlSign = pki.schema.x509.parse(await pki.x509.sign(Object.assign({ subject: "CA no cRLSign", extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "digitalSignature"] } }, base), { key: s.key }));
  check("issuer cert whose keyUsage omits cRLSign -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n }, { cert: caNoCrlSign, key: s.key })) === "crl/bad-input");
}

// ---- sec. 5.2 -- the pre-encoded Extension escape hatch is held to the profile (criticality + delta rules) ----

async function testPreEncodedExtProfile() {
  var s = makeSigner("ec-p256");
  var B = pki.asn1.build;
  function extDer(name, critical, valueDer) {
    var kids = [B.oid(byName(name))];
    if (critical) kids.push(B.boolean(true));
    kids.push(B.octetString(valueDer));
    return B.sequence(kids);
  }
  // cRLNumber MUST be non-critical (sec. 5.2.3) -- a critical pre-encoded one is rejected.
  check("pre-encoded critical cRLNumber -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: [extDer("cRLNumber", true, B.integer(1n))] }, issuerOf(s))) === "crl/bad-input");
  // deltaCRLIndicator MUST be critical (sec. 5.2.4) -- a non-critical pre-encoded one is rejected.
  check("pre-encoded non-critical deltaCRLIndicator -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: [extDer("deltaCRLIndicator", false, B.integer(2n))] }, issuerOf(s))) === "crl/bad-input");
  // A pre-encoded (critical) delta with NO cRLNumber anywhere -> rejected (sec. 5.2.3/5.2.4).
  check("pre-encoded delta without a cRLNumber -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: [extDer("deltaCRLIndicator", true, B.integer(2n))] }, issuerOf(s))) === "crl/bad-input");
  // A pre-encoded (critical) delta whose base (5) is >= spec.crlNumber (5) -> rejected.
  check("pre-encoded delta with cRLNumber <= baseCRLNumber -> crl/bad-crl-number",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: [extDer("deltaCRLIndicator", true, B.integer(5n))] }, issuerOf(s))) === "crl/bad-crl-number");
  // A conforming pre-encoded delta (critical, base 2) + spec.crlNumber 5 is accepted.
  var c = pki.schema.crl.parse(await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: [extDer("deltaCRLIndicator", true, B.integer(2n))] }, issuerOf(s)));
  check("conforming pre-encoded delta + spec.crlNumber accepted", (crlExt(c, "deltaCRLIndicator") || {}).critical === true);
  // The entry-extension escape hatch is held to the same profile: reasonCode MUST be non-critical (sec. 5.3.1).
  check("pre-encoded critical entry reasonCode -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, revoked: [{ serialNumber: 1n, revocationDate: RD, extensions: [extDer("reasonCode", true, B.enumerated(1n))] }] }, issuerOf(s))) === "crl/bad-input");
  // freshestCRL: a distribution point with an empty fullName is rejected (GeneralNames is SIZE(1..MAX)).
  check("freshestCRL DP with an empty fullName -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, extensions: { freshestCRL: [{ fullName: [] }] } }, issuerOf(s))) === "crl/bad-input");
  // A pre-encoded freshestCRL co-present with a pre-encoded delta indicator is rejected (sec. 5.2.6).
  check("pre-encoded freshestCRL in a pre-encoded delta CRL -> crl/bad-input",
    await codeOf(pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 5n, extensions: [extDer("deltaCRLIndicator", true, B.integer(2n)), extDer("freshestCRL", false, B.sequence([]))] }, issuerOf(s))) === "crl/bad-input");
}

async function main() {
  await testRoundTrip();
  await testEmptyListOmitsRevoked();
  await testVersionDerivation();
  await testInvalidityDateGeneralizedTime();
  await testReasonCodeRules();
  await testSigAlgSingleSource();
  await testCrlNumberCap();
  await testAkiShape();
  await testVerifyPerAlgorithm();
  await testVerifyAlgorithmConfusion();
  await testIdpGates();
  await testDeltaAndFreshest();
  await testDeltaRequiresCrlNumber();
  await testIssuerCertCrlSign();
  await testPreEncodedExtProfile();
  await testPemAndIsRevoked();
  await testFailClosed();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
