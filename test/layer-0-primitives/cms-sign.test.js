// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.cms.sign (RFC 5652 sec. 5 CMS SignedData signing, the producing side of
 * pki.cms.verify). Drives the shipped consumer path pki.cms.sign(...) and asserts the output
 * through the INDEPENDENT verifier pki.cms.verify (the sign->verify round-trip is the primary
 * correctness gate; OpenSSL cms -verify is the cross-implementation gate in the integration
 * harness). Every algorithm (RSA PKCS#1 v1.5 + RSASSA-PSS, ECDSA P-256/384/521, Ed25519, Ed448),
 * content mode (attached/detached), signer count, signer-identifier form, and the signed-
 * attributes shapes are covered; config-time misuse fails closed with a typed cms/* error.
 *
 * RED baseline: pki.cms.sign is undefined until the module lands, so every vector throws.
 */

var crypto = require("node:crypto");
var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;

var CONTENT = Buffer.from("the content to be signed by pki.cms.sign");

async function rejects(label, fn, code) {
  var e = null;
  try { await fn(); } catch (err) { e = err; }
  check(label + " throws", e !== null);
  check(label + " code=" + code, e && e.code === code);
}

// ---- round-trip: every algorithm signs and verifies ----
async function testAlgorithms() {
  var cases = [
    ["RSA PKCS#1 v1.5", makeSigner("rsa"), {}],
    ["RSASSA-PSS", makeSigner("rsa"), { pss: true }],
    ["ECDSA P-256", makeSigner("ec-p256"), {}],
    ["ECDSA P-384", makeSigner("ec-p384"), {}],
    ["ECDSA P-521", makeSigner("ec-p521"), {}],
    ["Ed25519", makeSigner("ed25519"), {}],
    ["Ed448", makeSigner("ed448"), {}],
  ];
  for (var i = 0; i < cases.length; i++) {
    var s = Object.assign({}, cases[i][1], cases[i][2]);
    var p7 = await pki.cms.sign(CONTENT, s);
    var res = await pki.cms.verify(p7);
    check(cases[i][0] + " signs -> verifies", res.valid === true && res.signers[0].ok === true);
  }
  // a non-default digest (SHA-384) for RSA and ECDSA round-trips.
  var r384 = await pki.cms.verify(await pki.cms.sign(CONTENT, Object.assign(makeSigner("rsa"), { digestAlgorithm: "sha384" })));
  check("RSA + SHA-384 digest -> verifies", r384.valid === true);
  // an id-RSASSA-PSS signer certificate (a PSS-restricted RSA key) signs with RSASSA-PSS.
  var rpssKey = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("rsa-pss")));
  check("id-RSASSA-PSS signer cert -> signs+verifies (PSS)", rpssKey.valid === true);
}

// ---- content modes: attached / detached ----
async function testContentModes() {
  var s = makeSigner("ec-p256");
  var attached = await pki.cms.verify(await pki.cms.sign(CONTENT, s));
  check("attached content -> verifies without opts.content", attached.valid === true);

  var det = await pki.cms.sign(CONTENT, s, { detached: true });
  var withContent = await pki.cms.verify(det, { content: CONTENT });
  check("detached + content -> verifies", withContent.valid === true);
  await rejects("detached verified without content", function () { return pki.cms.verify(det); }, "cms/detached-content-required");
  // the detached content is genuinely bound: a different content does not verify.
  var wrong = await pki.cms.verify(det, { content: Buffer.from("different content") });
  check("detached + wrong content -> message-digest-mismatch", wrong.valid === false && wrong.signers[0].code === "cms/message-digest-mismatch");
}

// ---- multiple signers ----
async function testMultiSigner() {
  var p7 = await pki.cms.sign(CONTENT, [makeSigner("ec-p256"), makeSigner("rsa"), makeSigner("ed25519")]);
  var res = await pki.cms.verify(p7);
  check("three signers -> all verify", res.valid === true && res.signers.length === 3 && res.signers.every(function (x) { return x.ok === true; }));
}

// ---- signer identifier: issuerAndSerialNumber (default) vs subjectKeyIdentifier ----
async function testSignerIdentifier() {
  var is = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ec-p256")));
  check("issuerAndSerial sid -> matched by issuer+serial", is.signers[0].sid.serialNumberHex != null && is.signers[0].sid.subjectKeyIdentifier == null);

  var ski = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ec-p256", { ski: true }), { sid: "ski" }));
  check("subjectKeyIdentifier sid -> matched by SKI", ski.valid === true && ski.signers[0].sid.subjectKeyIdentifier != null);
  // a ski sid requires the signer cert to carry an SKI extension.
  await rejects("ski sid without an SKI extension", function () { return pki.cms.sign(CONTENT, makeSigner("ec-p256"), { sid: "ski" }); }, "cms/no-ski");
}

// ---- signed attributes: default, disabled, custom, signing-time ----
async function testSignedAttributes() {
  // no signed attributes: the signature is over the content directly.
  var noAttr = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ec-p256"), { signedAttributes: false }));
  check("signedAttributes:false -> verifies (content-signed)", noAttr.valid === true);

  // the default signed attributes bind the content: verify then tamper -> invalid.
  var p7 = await pki.cms.sign(CONTENT, makeSigner("ec-p256"));
  var parsed = pki.schema.cms.parse(p7);
  var mutated = pki.schema.cms.parse(p7);
  var c = Buffer.from(mutated.encapContentInfo.eContent); c[0] = c[0] ^ 0xff; mutated.encapContentInfo.eContent = c;
  var tampered = await pki.cms.verify(mutated);
  check("signed attributes bind the content (tamper -> invalid)", tampered.valid === false);
  check("default output carries three signed attributes", parsed.signerInfos[0].signedAttrs.length === 3);

  // a custom signed attribute rides along and the signature still verifies.
  var attrVal = pki.asn1.build.printable("custom");
  var withExtra = await pki.cms.sign(CONTENT, makeSigner("ec-p256"), { additionalSignedAttributes: [{ type: "1.2.840.113549.1.9.16.2.4", values: [attrVal] }] });
  var er = await pki.cms.verify(withExtra);
  check("additional signed attribute -> still verifies", er.valid === true);
  check("additional signed attribute is present", pki.schema.cms.parse(withExtra).signerInfos[0].signedAttrs.length === 4);

  // signing-time omitted on request.
  var noTime = pki.schema.cms.parse(await pki.cms.sign(CONTENT, makeSigner("ec-p256"), { signingTime: false }));
  check("signingTime:false -> two signed attributes", noTime.signerInfos[0].signedAttrs.length === 2);
}

// ---- output forms + structure: PEM, no-certs, eContentType/version, CryptoKey ----
async function testOutputForms() {
  var pem = await pki.cms.sign(CONTENT, makeSigner("ec-p256"), { pem: true });
  check("pem:true -> a CMS PEM string", typeof pem === "string" && pem.indexOf("-----BEGIN CMS-----") === 0);
  check("PEM output verifies", (await pki.cms.verify(pem)).valid === true);

  // certificates:false -> the signer is not embedded; supply it via opts.certs to verify.
  var s = makeSigner("ec-p256");
  var noCerts = await pki.cms.sign(CONTENT, s, { certificates: false });
  check("certificates:false + no opts.certs -> signer-cert-not-found", (await pki.cms.verify(noCerts)).signers[0].code === "cms/signer-cert-not-found");
  check("certificates:false + opts.certs -> verifies", (await pki.cms.verify(noCerts, { certs: [s.cert] })).valid === true);

  // a non-id-data eContentType lifts the CMSVersion to 3.
  var v3 = pki.schema.cms.parse(await pki.cms.sign(CONTENT, makeSigner("ec-p256"), { eContentType: "tSTInfo" }));
  check("non-data eContentType -> SignedData version 3", v3.version === 3);

  // a signer key supplied as an already-imported WebCrypto CryptoKey.
  var s2 = makeSigner("ec-p256");
  var ck = await pki.webcrypto.subtle.importKey("pkcs8", s2.key, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  var fromCk = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: s2.cert, key: ck }));
  check("CryptoKey signer key -> verifies", fromCk.valid === true);

  // a PEM certificate + a PEM PKCS#8 key.
  var s3 = makeSigner("ec-p256");
  var certPem = pki.schema.x509.pemEncode(s3.cert, "CERTIFICATE");
  var keyPem = s3.keyObject.export({ format: "pem", type: "pkcs8" });
  var fromPem = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: certPem, key: keyPem }));
  check("PEM cert + PEM key -> verifies", fromPem.valid === true);
}

// ---- config-time misuse fails closed with a typed cms/* error ----
async function testBadInput() {
  var s = makeSigner("ec-p256");
  await rejects("options not an object", function () { return pki.cms.sign(CONTENT, s, "nope"); }, "cms/bad-input");
  await rejects("content not a Buffer", function () { return pki.cms.sign("string", s); }, "cms/bad-input");
  await rejects("no signers", function () { return pki.cms.sign(CONTENT, []); }, "cms/bad-input");
  // signed attributes are REQUIRED for a non-data eContentType (RFC 5652 sec. 5.3).
  await rejects("signedAttributes:false with a non-data eContentType", function () { return pki.cms.sign(CONTENT, makeSigner("ec-p256"), { eContentType: "tSTInfo", signedAttributes: false }); }, "cms/bad-input");
  // an additional signed attribute that duplicates a built-in type is rejected (RFC 5652 sec. 5.3).
  await rejects("a duplicated signed-attribute type", function () { return pki.cms.sign(CONTENT, makeSigner("ec-p256"), { additionalSignedAttributes: [{ type: "messageDigest", values: [pki.asn1.build.octetString(Buffer.alloc(32))] }] }); }, "cms/bad-input");
  await rejects("signer without a cert", function () { return pki.cms.sign(CONTENT, { key: s.key }); }, "cms/bad-input");
  await rejects("signer cert a bad type", function () { return pki.cms.sign(CONTENT, { cert: 12345, key: s.key }); }, "cms/bad-input");
  await rejects("signer key a bad type", function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: 12345 }); }, "cms/bad-input");
  // an unsupported signer key algorithm (X25519 is a KEM key, not a signing key).
  var x = crypto.generateKeyPairSync("x25519");
  var xSpki = x.publicKey.export({ format: "der", type: "spki" });
  var xCert = signing.minimalCert(xSpki);
  await rejects("unsupported signer key algorithm", function () { return pki.cms.sign(CONTENT, { cert: xCert, key: x.privateKey.export({ format: "der", type: "pkcs8" }) }); }, "cms/unsupported-algorithm");
}

// ---- scheme resolution errors + input variants (branch coverage) ----
async function testSchemeAndInputs() {
  var un = "cms/unsupported-algorithm";
  // unsupported digest per key family.
  await rejects("RSA + unsupported digest", function () { return pki.cms.sign(CONTENT, Object.assign(makeSigner("rsa"), { digestAlgorithm: "sha1" })); }, un);
  await rejects("ECDSA + unsupported digest", function () { return pki.cms.sign(CONTENT, Object.assign(makeSigner("ec-p256"), { digestAlgorithm: "sha1" })); }, un);
  await rejects("Ed25519 + unsupported digest", function () { return pki.cms.sign(CONTENT, Object.assign(makeSigner("ed25519"), { digestAlgorithm: "sha1" })); }, un);
  // an EC signer on an unsupported curve (secp256k1).
  var k1 = crypto.generateKeyPairSync("ec", { namedCurve: "secp256k1" });
  var k1cert = signing.minimalCert(k1.publicKey.export({ format: "der", type: "spki" }));
  await rejects("unsupported EC curve", function () { return pki.cms.sign(CONTENT, { cert: k1cert, key: k1.privateKey.export({ format: "der", type: "pkcs8" }) }); }, un);
  // an EC SPKI whose curve parameter is not a decodable OID.
  var s = makeSigner("ec-p256");
  var badSpki = _corruptEcCurveOid(s.spki);
  var badCert = signing.minimalCert(badSpki);
  var kBad = s.keyObject.export({ format: "der", type: "pkcs8" });
  await rejects("EC params not a curve OID", function () { return pki.cms.sign(CONTENT, { cert: badCert, key: kBad }); }, un);
  // a null signer entry.
  await rejects("a null signer entry", function () { return pki.cms.sign(CONTENT, [null]); }, "cms/bad-input");
  // a signer certificate PEM that is not a CERTIFICATE block.
  await rejects("a non-CERTIFICATE PEM cert", function () { return pki.cms.sign(CONTENT, { cert: "-----BEGIN X-----\nAAAA\n-----END X-----", key: s.key }); }, "cms/bad-input");
  // a signer key PEM that will not decode.
  await rejects("an undecodable PEM key", function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: "-----BEGIN PRIVATE KEY-----\nnotbase64!!!\n-----END PRIVATE KEY-----" }); }, "cms/bad-input");

  // input variants that must be accepted: Uint8Array content / cert / key, PEM cert as a Buffer.
  var s2 = makeSigner("ec-p256");
  var u8 = await pki.cms.verify(await pki.cms.sign(new Uint8Array(CONTENT), { cert: new Uint8Array(s2.cert), key: new Uint8Array(s2.key) }));
  check("Uint8Array content/cert/key -> verifies", u8.valid === true);
  var pemBuf = Buffer.from(pki.schema.x509.pemEncode(s2.cert, "CERTIFICATE"));
  var pb = await pki.cms.verify(await pki.cms.sign(CONTENT, { cert: pemBuf, key: s2.key }));
  check("PEM certificate as a Buffer -> verifies", pb.valid === true);

  // a v1 signer certificate (no version field -> issuer at a different tbs index).
  var v1 = _v1Signer();
  check("v1 signer certificate -> verifies", (await pki.cms.verify(await pki.cms.sign(CONTENT, v1))).valid === true);

  // signing-time supplied as a Date, and a post-2050 time (GeneralizedTime).
  var st = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ec-p256"), { signingTime: new Date("2030-06-01T00:00:00Z") }));
  check("signingTime Date -> verifies", st.valid === true);
  var g2050 = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ec-p256"), { signingTime: new Date("2060-06-01T00:00:00Z") }));
  check("post-2050 signingTime (GeneralizedTime) -> verifies", g2050.valid === true);

  // an additional signed attribute keyed by OID NAME (not a dotted string), with a Uint8Array value.
  var byName = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ec-p256"), { additionalSignedAttributes: [{ type: "signingCertificateV2", values: [new Uint8Array(pki.asn1.build.sequence([]))] }] }));
  check("additional signed attribute by OID name -> verifies", byName.valid === true);

  // a ski sid whose SKI extension value is not an OCTET STRING fails closed.
  await rejects("ski sid with a malformed SKI value", function () { return pki.cms.sign(CONTENT, makeSigner("ec-p256", { ski: true, badSki: true }), { sid: "ski" }); }, "cms/no-ski");

  // an additional signed attribute with no values is non-conformant (RFC 5652 SET SIZE 1..MAX)
  // and fails closed at config time rather than producing a malformed CMS.
  await rejects("additional attribute with no values", function () { return pki.cms.sign(CONTENT, makeSigner("ec-p256"), { additionalSignedAttributes: [{ type: "1.2.3.4.5" }] }); }, "cms/bad-input");
}

// Flip the named-curve OID tag inside an EC SubjectPublicKeyInfo (0x06 -> 0x04) so it no longer
// decodes as an OID -- x509.parse accepts it (parameters are opaque), the sign path rejects it.
function _corruptEcCurveOid(spki) {
  var pat = Buffer.from([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);   // ecPublicKey OID
  var i = spki.indexOf(pat);
  var out = Buffer.from(spki);
  if (i >= 0 && out[i + 9] === 0x06) out[i + 9] = 0x04;
  return out;
}
// A v1 signer certificate (no [0] version) around a fresh EC key.
function _v1Signer() {
  var b = pki.asn1.build, O = function (n) { return pki.oid.byName(n); };
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  var alg = b.sequence([b.oid(O("ecdsaWithSHA256"))]);
  var name = b.sequence([b.set([b.sequence([b.oid(O("commonName")), b.printable("v1 Signer")])])]);
  var validity = b.sequence([b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2040-01-01T00:00:00Z"))]);
  var tbs = b.sequence([b.integer(0x66n), alg, name, validity, name, b.raw(spki)]);   // NO version field (v1)
  var cert = b.sequence([tbs, alg, b.bitString(Buffer.from([0, 0, 0, 0]), 0)]);
  return { cert: cert, key: kp.privateKey.export({ format: "der", type: "pkcs8" }) };
}

async function run() {
  await testAlgorithms();
  await testSchemeAndInputs();
  await testContentModes();
  await testMultiSigner();
  await testSignerIdentifier();
  await testSignedAttributes();
  await testOutputForms();
  await testBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
