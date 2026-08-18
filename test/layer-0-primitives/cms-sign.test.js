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
var surgery = require("../helpers/der-surgery");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;

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
  // an id-RSASSA-PSS key whose SPKI params pin SHA-384: signing honors the pinned hash (Node
  // rejects signing a SHA-384-restricted key under the SHA-256 default), so the token verifies.
  var pinned = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("rsa-pss", { pssHash: "sha384" })));
  check("id-RSASSA-PSS SHA-384-pinned key -> signs under SHA-384 + verifies", pinned.valid === true);
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
  // Flip a content byte in the ENCODING. The content rides the message verbatim, so it is found by
  // value, and a one-byte flip keeps every length intact -- the message stays well-formed and the
  // only thing that changed is what the message-digest attribute promised.
  var mutated = Buffer.from(p7);
  var at = mutated.indexOf(CONTENT);
  check("the eContent octets located in the encoding", at >= 0);
  mutated[at] = mutated[at] ^ 0xff;
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

  // a pre-imported CryptoKey whose algorithm disagrees with the certificate is rejected -- the
  // baked-in hash / curve / algorithm must match the resolved signing scheme (fail closed).
  var rk = makeSigner("rsa");
  var ckHash = await pki.webcrypto.subtle.importKey("pkcs8", rk.key, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, false, ["sign"]);
  await rejects("CryptoKey hash mismatching the digest", function () { return pki.cms.sign(CONTENT, { cert: rk.cert, key: ckHash }); }, "cms/bad-input");
  var ckCurve = await pki.webcrypto.subtle.importKey("pkcs8", makeSigner("ec-p384").key, { name: "ECDSA", namedCurve: "P-384" }, false, ["sign"]);
  await rejects("CryptoKey curve mismatching the certificate", function () { return pki.cms.sign(CONTENT, { cert: makeSigner("ec-p256").cert, key: ckCurve }); }, "cms/bad-input");
  await rejects("CryptoKey algorithm mismatching the certificate", function () { return pki.cms.sign(CONTENT, { cert: rk.cert, key: ck }); }, "cms/bad-input");

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

  // An option this verb does not read is refused, not ignored. A misspelling does not select the
  // mode the caller meant, and swallowing it signs the message the other way with nothing said --
  // `signedAttribute` for `signedAttributes` decides whether the signature covers the content
  // directly or a set of attributes, which is the difference the stripping attack turns on.
  await rejects("an unknown sign option", function () {
    return pki.cms.sign(CONTENT, s, { signedAttribute: false });
  }, "cms/bad-input");
  await rejects("an option only countersign takes", function () {
    return pki.cms.sign(CONTENT, s, { signerIndex: 0 });
  }, "cms/bad-input");
  // The whole documented set is still accepted -- a gate that refuses a real option would be the
  // worse defect, and `sid` is omitted here because it needs a certificate carrying an SKI.
  check("every documented sign option is accepted", Buffer.isBuffer(await pki.cms.sign(CONTENT, s, {
    signedAttributes: true, signingTime: new Date(0), additionalSignedAttributes: [],
    unsignedAttributes: [], eContentType: "data", detached: false, certificates: true, pem: false,
  })));

  var countersigned = await pki.cms.sign(CONTENT, s);
  await rejects("an unknown countersign option", function () {
    return pki.cms.countersign(countersigned, s, { signerIndexes: 0 });
  }, "cms/bad-input");
  // countersign has no content of its own, so the options that describe one are not its to take.
  await rejects("a content option passed to countersign", function () {
    return pki.cms.countersign(countersigned, s, { detached: true });
  }, "cms/bad-input");
  check("every documented countersign option is accepted",
    Buffer.isBuffer(await pki.cms.countersign(countersigned, s, {
      signerIndex: 0, signingTime: new Date(0), certificates: true, pem: false,
      signedAttributes: true, additionalSignedAttributes: [],
    })));
  await rejects("content not a Buffer", function () { return pki.cms.sign("string", s); }, "cms/bad-input");
  await rejects("no signers", function () { return pki.cms.sign(CONTENT, []); }, "cms/bad-input");
  // signed attributes are REQUIRED for a non-data eContentType (RFC 5652 sec. 5.3).
  await rejects("signedAttributes:false with a non-data eContentType", function () { return pki.cms.sign(CONTENT, makeSigner("ec-p256"), { eContentType: "tSTInfo", signedAttributes: false }); }, "cms/bad-input");
  // an additional signed attribute that duplicates a built-in type is rejected (RFC 5652 sec. 5.3).
  await rejects("a duplicated signed-attribute type", function () { return pki.cms.sign(CONTENT, makeSigner("ec-p256"), { additionalSignedAttributes: [{ type: "messageDigest", values: [pki.asn1.build.octetString(Buffer.alloc(32))] }] }); }, "cms/bad-input");
  await rejects("signer without a cert", function () { return pki.cms.sign(CONTENT, { key: s.key }); }, "cms/bad-input");
  await rejects("signer cert a bad type", function () { return pki.cms.sign(CONTENT, { cert: 12345, key: s.key }); }, "cms/bad-input");
  await rejects("signer key a bad type", function () { return pki.cms.sign(CONTENT, { cert: s.cert, key: 12345 }); }, "cms/bad-input");
  await rejects("an invalid signingTime Date", function () { return pki.cms.sign(CONTENT, s, { signingTime: new Date("not a date") }); }, "cms/bad-input");
  await rejects("a non-Date signingTime", function () { return pki.cms.sign(CONTENT, s, { signingTime: "2026-01-01" }); }, "cms/bad-input");
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
  // a digestAlgorithm that contradicts an id-RSASSA-PSS key's SPKI-pinned hash is rejected
  // fail-closed (the key forbids that digest), not silently signed under the wrong hash.
  await rejects("PSS-pinned key + conflicting digestAlgorithm", function () { return pki.cms.sign(CONTENT, Object.assign(makeSigner("rsa-pss", { pssHash: "sha384" }), { digestAlgorithm: "sha256" })); }, "cms/bad-input");
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
  // a certificate as a Uint8Array of PEM bytes is DECODED to DER (not embedded as PEM text).
  var pemU8 = new Uint8Array(pemBuf);
  var pu8out = await pki.cms.sign(CONTENT, { cert: pemU8, key: s2.key });
  check("Uint8Array PEM cert -> verifies + embeds DER (0x30), not PEM", (await pki.cms.verify(pu8out)).valid === true && pki.schema.cms.parse(pu8out).certificates[0].bytes[0] === 0x30);

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

// ---- ML-DSA (RFC 9882): the first post-quantum SignerInfo, pure mode, empty context ----
async function testMlDsa() {
  // A1 -- ML-DSA-65 attached, signed attrs present, default SHA-512 message digest.
  var a1 = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65")));
  check("A1 ML-DSA-65 attached signed-attrs -> valid", a1.valid === true);
  // A2 -- ML-DSA-44 with the SHAKE256 message digest (the sec. 3.3 SHOULD path).
  var a2 = await pki.cms.verify(await pki.cms.sign(CONTENT, Object.assign(makeSigner("ml-dsa-44"), { digestAlgorithm: "shake256" })));
  check("A2 ML-DSA-44 shake256 digest -> valid", a2.valid === true);
  // A3 -- ML-DSA-87 detached; correct content verifies, wrong content does not.
  var s87 = makeSigner("ml-dsa-87");
  var det = await pki.cms.sign(CONTENT, s87, { detached: true });
  check("A3 ML-DSA-87 detached + content -> valid", (await pki.cms.verify(det, { content: CONTENT })).valid === true);
  check("A3 ML-DSA-87 detached + wrong content -> invalid", (await pki.cms.verify(det, { content: Buffer.from("other") })).valid === false);
  // A4 -- ML-DSA-65 with NO signed attributes (signature over the content directly).
  var a4 = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65"), { signedAttributes: false }));
  check("A4 ML-DSA-65 no-signed-attrs -> valid", a4.valid === true);
  // A5 -- multi-signer: a classical ECDSA signer + an ML-DSA signer over one SignedData.
  var a5 = await pki.cms.verify(await pki.cms.sign(CONTENT, [makeSigner("ec-p256"), makeSigner("ml-dsa-65")]));
  check("A5 mixed ECDSA + ML-DSA multi-signer -> all valid", a5.valid === true && a5.signers.length === 2 && a5.signers.every(function (x) { return x.ok; }));
  // A6 -- subjectKeyIdentifier signer identifier (v3 SignerInfo).
  var a6 = await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-44", { ski: true }), { sid: "ski" }));
  check("A6 ML-DSA-44 sid=ski -> valid", a6.valid === true && a6.signers[0].sid.subjectKeyIdentifier != null);
  // A7 -- byte-level: default digestAlgorithm is SHA-512 params-absent; signatureAlgorithm params absent; PEM round-trips.
  var der = await pki.cms.sign(CONTENT, makeSigner("ml-dsa-44"));
  var parsed = pki.schema.cms.parse(der);
  check("A7 digestAlgorithm == sha512", parsed.signerInfos[0].digestAlgorithm.name === "sha512");
  check("A7 signatureAlgorithm == id-ml-dsa-44, params absent", parsed.signerInfos[0].signatureAlgorithm.name === "id-ml-dsa-44" && parsed.signerInfos[0].signatureAlgorithm.parameters == null);
  var pem = await pki.cms.sign(CONTENT, makeSigner("ml-dsa-44"), { pem: true });
  check("A7 PEM output", typeof pem === "string" && pem.indexOf("-----BEGIN CMS-----") === 0 && (await pki.cms.verify(pem)).valid === true);
  // A9 -- ML-DSA-44 + SHA-256: SHA-256 IS suitable for ML-DSA-44 (Table 1) -> MUST be accepted
  // (the negative control for the per-parameter-set digest-strength gate).
  var a9 = await pki.cms.verify(await pki.cms.sign(CONTENT, Object.assign(makeSigner("ml-dsa-44"), { digestAlgorithm: "sha256" })));
  check("A9 ML-DSA-44 + sha256 (suitable) -> valid", a9.valid === true);

  // R9 -- no-signed-attrs + a non-`data` eContentType is rejected at config time.
  await rejects("R9 ML-DSA no-attrs non-data eContentType", function () { return pki.cms.sign(CONTENT, makeSigner("ml-dsa-65"), { signedAttributes: false, eContentType: "signedData" }); }, "cms/bad-input");
  // R10 -- no-signed-attrs generation MUST emit digestAlgorithm = SHA-512 (RFC 9882 sec. 3.3).
  var r10 = pki.schema.cms.parse(await pki.cms.sign(CONTENT, makeSigner("ml-dsa-65"), { signedAttributes: false }));
  check("R10 no-attrs digestAlgorithm == sha512 params-absent", r10.signerInfos[0].digestAlgorithm.name === "sha512" && r10.signerInfos[0].digestAlgorithm.parameters == null);
  // R13 -- no-attrs signing MUST emit SHA-512 even when the caller requests another suitable digest
  // (RFC 9882 sec. 3.3: without signed attributes the digestAlgorithm has no meaning, so the signer
  // forces the interoperable SHA-512 rather than carry a value a strict peer would reject).
  var r13 = pki.schema.cms.parse(await pki.cms.sign(CONTENT, Object.assign(makeSigner("ml-dsa-44"), { digestAlgorithm: "shake256" }), { signedAttributes: false }));
  check("R13 no-attrs ML-DSA forces sha512 digestAlgorithm", r13.signerInfos[0].digestAlgorithm.name === "sha512");
  // R12 (sign side, Q1 = ENFORCE) -- a below-strength digest for the parameter set is refused at
  // config time: SHA-256 (128-bit) under ML-DSA-87 (lambda 256) / ML-DSA-65 (lambda 192).
  await rejects("R12 ML-DSA-87 + sha256 (below strength) -> reject", function () { return pki.cms.sign(CONTENT, Object.assign(makeSigner("ml-dsa-87"), { digestAlgorithm: "sha256" })); }, "cms/unsupported-algorithm");
  await rejects("R12 ML-DSA-65 + sha256 (below strength) -> reject", function () { return pki.cms.sign(CONTENT, Object.assign(makeSigner("ml-dsa-65"), { digestAlgorithm: "sha256" })); }, "cms/unsupported-algorithm");
  await rejects("R8 ML-DSA-65 + sha3-512 (unwired digest) -> reject", function () { return pki.cms.sign(CONTENT, Object.assign(makeSigner("ml-dsa-65"), { digestAlgorithm: "sha3-512" })); }, "cms/unsupported-algorithm");
  // R11 -- an ML-DSA-44 CryptoKey against an ML-DSA-65 certificate is a fail-closed mismatch.
  var subtle = require("../../lib/webcrypto").webcrypto.subtle;
  var key44 = await subtle.importKey("pkcs8", makeSigner("ml-dsa-44").key, { name: "ML-DSA-44" }, false, ["sign"]);
  await rejects("R11 ML-DSA-44 CryptoKey vs ML-DSA-65 cert", function () { return pki.cms.sign(CONTENT, { cert: makeSigner("ml-dsa-65").cert, key: key44 }); }, "cms/bad-input");
}

// An id-RSASSA-PSS signer whose SPKI carries CUSTOM RSASSA-PSS-params (over a real RSA public key),
// exercising the pinned-hash reader (_pssHashFromSpki) across every shape branch.
function pssSignerWithParams(paramsNode) {
  var b = pki.asn1.build;
  var base = makeSigner("rsa-pss");
  var spki = pki.asn1.decode(base.spki);   // SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING }
  var alg = paramsNode ? b.sequence([b.oid(pki.oid.byName("rsassaPss")), paramsNode]) : b.sequence([b.oid(pki.oid.byName("rsassaPss"))]);
  return { cert: signing.minimalCert(b.sequence([alg, b.raw(spki.children[1].bytes)])), key: base.key };
}

// ---- coverage: the id-RSASSA-PSS SPKI pinned-hash reader across malformed / unpinned params ----
async function testPssSpkiParams() {
  var b = pki.asn1.build;
  // RFC 4055 sec. 3.1 makes the PRESENCE of the parameters the line: absent, they restrict nothing;
  // present, "the certificate user MUST perform those operations using the one-way hash function
  // ... identified in the ... parameters". So none of these three shapes is an absent restriction.
  // A params field that is not an RSASSA-PSS-params SEQUENCE, and one whose hashAlgorithm cannot be
  // read, are restrictions this code cannot honor. An EMPTY SEQUENCE is the subtlest of the three
  // and the reason the old fall-through was wrong: hashAlgorithm is `[0] ... DEFAULT
  // sha1Identifier`, so omitting it NAMES SHA-1 -- and falling back to SHA-256 there signed under a
  // digest the certificate forbids.
  var shapes = [
    b.nullValue(),                                                            // not a SEQUENCE
    b.sequence([]),                                                           // no [0] -> DEFAULT sha1
    b.sequence([b.explicit(0, b.sequence([b.nullValue()]))]),                 // [0] hashAlgorithm inner is not an OID
  ];
  for (var i = 0; i < shapes.length; i++) {
    await rejects("PSS SPKI params shape " + i + " -> a restriction that cannot be honored is refused, never read as absent",
      (function (shape) {
        return function () { return pki.cms.sign(CONTENT, pssSignerWithParams(shape)); };
      })(shapes[i]), "cms/unsupported-algorithm");
  }
  // a [0] hashAlgorithm pinning a hash this toolkit does not map (SHA-1) fails closed at sign time,
  // rather than silently signing under a digest the key forbids.
  await rejects("PSS SPKI pins an unsupported hash -> reject", function () { return pki.cms.sign(CONTENT, pssSignerWithParams(b.sequence([b.explicit(0, b.sequence([b.oid(pki.oid.byName("sha1"))]))]))); }, "cms/unsupported-algorithm");
}

// ---- SLH-DSA (RFC 9814): the twelve pure FIPS 205 sets; the message digest is PINNED per set ----
var SLH_DSA_SETS = [
  "sha2-128s", "sha2-128f", "sha2-192s", "sha2-192f", "sha2-256s", "sha2-256f",
  "shake-128s", "shake-128f", "shake-192s", "shake-192f", "shake-256s", "shake-256f",
];
var SLH_DSA_PINNED = {   // RFC 9814 sec. 4 message-digest per parameter set
  "sha2-128s": "sha256", "sha2-128f": "sha256", "sha2-192s": "sha512", "sha2-192f": "sha512",
  "sha2-256s": "sha512", "sha2-256f": "sha512", "shake-128s": "shake128", "shake-128f": "shake128",
  "shake-192s": "shake256", "shake-192f": "shake256", "shake-256s": "shake256", "shake-256f": "shake256",
};
async function testSlhDsa() {
  // every one of the twelve pure sets signs and verifies, carrying its RFC 9814 sec. 4 pinned digest.
  for (var i = 0; i < SLH_DSA_SETS.length; i++) {
    var set = SLH_DSA_SETS[i];
    var der = await pki.cms.sign(CONTENT, makeSigner("slh-dsa-" + set));
    check("SLH-DSA " + set + " -> verifies", (await pki.cms.verify(der)).valid === true);
    check("SLH-DSA " + set + " -> digestAlgorithm == " + SLH_DSA_PINNED[set], pki.schema.cms.parse(der).signerInfos[0].digestAlgorithm.name === SLH_DSA_PINNED[set]);
  }
  // detached, no-signed-attributes, and mixed with a classical signer, on the fast sha2-128f set.
  var det = await pki.cms.sign(CONTENT, makeSigner("slh-dsa-sha2-128f"), { detached: true });
  check("SLH-DSA detached + content -> valid", (await pki.cms.verify(det, { content: CONTENT })).valid === true);
  check("SLH-DSA no-attrs -> valid", (await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("slh-dsa-sha2-128f"), { signedAttributes: false }))).valid === true);
  var mixed = await pki.cms.verify(await pki.cms.sign(CONTENT, [makeSigner("ec-p256"), makeSigner("slh-dsa-sha2-128f")]));
  check("SLH-DSA + ECDSA multi-signer -> all valid", mixed.valid === true && mixed.signers.length === 2 && mixed.signers.every(function (x) { return x.ok; }));
  // sid=subjectKeyIdentifier.
  check("SLH-DSA sid=ski -> valid", (await pki.cms.verify(await pki.cms.sign(CONTENT, makeSigner("slh-dsa-shake-128f", { ski: true }), { sid: "ski" }))).valid === true);
  // signatureAlgorithm / signer-key parameter-set disagreement is a fail-closed mismatch (sameKeyOid).
  // Rewritten in the ENCODING, on the SignerInfo's own AlgorithmIdentifier (the last one), so the
  // signer certificate keeps naming sha2-128f and what disagrees is the parameter set the message
  // asks to be verified under.
  var p128 = await pki.cms.sign(CONTENT, makeSigner("slh-dsa-sha2-128f"));
  var m = surgery.replaceLastAlgId(p128, pki.oid.byName("id-slh-dsa-sha2-128f"),
    function () { return b.sequence([b.oid(pki.oid.byName("id-slh-dsa-sha2-256f"))]); });
  check("SLH-DSA parameter-set swap changed the DER", !m.der.equals(p128));
  check("SLH-DSA sig-alg / key set mismatch -> unsupported", (function (r) { return r.valid === false && r.signers[0].code === "cms/unsupported-algorithm"; })(await pki.cms.verify(m.der)));
  // a caller digestAlgorithm that contradicts the parameter set's RFC 9814 sec. 4 pinned digest
  // (sha2-128f pins SHA-256) is rejected at config time rather than emitting a non-conformant digest.
  await rejects("SLH-DSA + contradicting digestAlgorithm -> reject", function () { return pki.cms.sign(CONTENT, Object.assign(makeSigner("slh-dsa-sha2-128f"), { digestAlgorithm: "sha512" })); }, "cms/bad-input");
  // a SHAKE-digest SLH-DSA SignerInfo (shake-128f pins SHAKE128) whose digestAlgorithm carries a
  // present parameter (even DER NULL) is rejected -- RFC 8702 sec. 3.1 requires SHAKE params absent.
  var pShk = await pki.cms.sign(CONTENT, makeSigner("slh-dsa-shake-128f"));
  var shk = surgery.replaceLastAlgId(pShk, pki.oid.byName("shake128"),
    function (n) { return surgery.algIdWithParams(n.children[0].bytes, b.nullValue()); });
  check("SLH-DSA shake128 digest-params splice changed the DER", !shk.der.equals(pShk));
  check("SLH-DSA shake128 digestAlgorithm NULL parameters -> unsupported", (function (r) { return r.valid === false && r.signers[0].code === "cms/unsupported-algorithm"; })(await pki.cms.verify(shk.der)));
  // RFC 9814 sec. 4: a message-digest that is not the parameter set's paired hash is rejected on
  // verify -- SHA-256 on sha2-256f (which pairs SHA-512, twice the 256-bit tree hash) fails closed.
  var p256f = await pki.cms.sign(CONTENT, makeSigner("slh-dsa-sha2-256f"));
  var wrongMd = surgery.replaceLastAlgId(p256f, pki.oid.byName("sha512"),
    function () { return b.sequence([b.oid(pki.oid.byName("sha256"))]); });
  check("SLH-DSA digest swap changed the DER", !wrongMd.der.equals(p256f));
  check("SLH-DSA sha2-256f + mismatched sha256 digest -> unsupported", (function (r) { return r.valid === false && r.signers[0].code === "cms/unsupported-algorithm"; })(await pki.cms.verify(wrongMd.der)));
}

// A KEY-ONLY signer: `{ key, spki, keyIdentifier }` with no certificate. RFC 5272
// sec. 3.2 needs exactly this to sign a Full PKI Request with the key of a
// certification request it carries -- there is no certificate yet.
//
// Such a SignedData CANNOT be checked by pki.cms.verify (no certificate matches
// the sid) nor by `openssl cms -verify` (it needs a signer certificate), so the
// signature is proven by RECONSTRUCTING the signed-attributes SET-OF preimage and
// verifying it against the request's own SPKI. Saying so here rather than
// pretending cms.verify closes it.
async function testKeyOnlySigner() {
  var subtle = pki.webcrypto.subtle;
  var pair = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var keyPkcs8 = await pki.key.export(pair.privateKey);
  var spki = await pki.key.export(pair.publicKey);
  var keyId = Buffer.from(await subtle.digest("SHA-1", spki));   // the SKI the request would declare

  var der = await pki.cms.sign(CONTENT, { key: keyPkcs8, spki: spki, keyIdentifier: keyId },
    { eContentType: "id-cct-PKIData" });
  var m = pki.schema.cms.parse(der);

  check("key-only signer: the SignerInfo is version 3", m.signerInfos[0].version === 3);
  check("key-only signer: the sid is the subjectKeyIdentifier form carrying the request's key id",
    m.signerInfos[0].sid.subjectKeyIdentifier != null &&
    Buffer.compare(m.signerInfos[0].sid.subjectKeyIdentifier, keyId) === 0);
  check("key-only signer: NO certificates field is emitted (there is no certificate)",
    !m.certificates || m.certificates.length === 0);

  // A key-only signer names a public key it does not otherwise prove it holds:
  // the identifier and the signature scheme come from `spki`, the signature from
  // `key`. Two different keys produce a well-formed SignerInfo nobody can verify,
  // because the recipient resolves the identifier to the declared key and checks
  // a signature made by another. There is no certificate here to catch it.
  var strangerPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var strangerKey = await pki.key.export(strangerPair.privateKey);
  await rejects("key-only signer: a `key` that is not the declared `spki`", function () {
    return pki.cms.sign(CONTENT, { key: strangerKey, spki: spki, keyIdentifier: keyId },
      { eContentType: "id-cct-PKIData" });
  }, "cms/bad-input");

  // ...and that check must not lock out the keys this signer exists to serve. An
  // enrollment key held in an HSM is a non-extractable CryptoKey: its public half
  // cannot be derived, which is the point of it, so the comparison simply does not
  // apply there and signing proceeds.
  // A COMPOSITE key-only signer: { mldsa, trad } is two component private keys, a
  // form no single public key can be derived from -- but the correspondence is
  // still provable, from the signature it just produced against the declared spki.
  // Refusing it instead would have broken a signing arm the engine supports.
  var comp = makeCompositeSigner("id-MLDSA65-Ed25519-SHA512");
  var compId = Buffer.from(await subtle.digest("SHA-1", comp.spki));
  check("key-only signer: a COMPOSITE key signs, its correspondence proven from the signature",
    pki.schema.cms.parse(await pki.cms.sign(CONTENT,
      { key: comp.key, spki: comp.spki, keyIdentifier: compId },
      { eContentType: "id-cct-PKIData" })).signerInfos.length === 1);

  await rejects("key-only signer: a composite key that is not the declared spki", function () {
    return pki.cms.sign(CONTENT,
      { key: makeCompositeSigner("id-MLDSA65-Ed25519-SHA512").key, spki: comp.spki, keyIdentifier: compId },
      { eContentType: "id-cct-PKIData" });
  }, "cms/bad-input");

  // The signer descriptor is the CALLER's object, and sign() defers: the
  // SignerIdentifier is built from `keyIdentifier` on the way in, the signature
  // is made a turn later. A descriptor whose `key` and `spki` are both swapped
  // for another matching pair in that gap would satisfy the key/spki match --
  // both halves moved together -- while the SignerInfo still names the first
  // key, and nothing could verify the result.
  // The same proof for a CERTIFICATE-backed signer. The SignerInfo names the
  // embedded certificate's key, so signing with a different one of the same
  // algorithm emits a structure the CA it is sent to cannot verify -- and nothing
  // else in the message contradicts it.
  var certA = makeSigner("ec-p256"), certB = makeSigner("ec-p256");
  check("a certificate-backed signer whose key matches its certificate signs",
    pki.schema.cms.parse(await pki.cms.sign(CONTENT, certA)).signerInfos.length === 1);
  await rejects("a certificate-backed signer whose key is NOT its certificate's is refused", function () {
    return pki.cms.sign(CONTENT, { cert: certA.cert, key: certB.key });
  }, "cms/bad-input");

  // Ed25519, so the CMS signature IS the raw signature and the check below needs
  // no re-encoding between what was emitted and what is verified.
  var pinned = makeSigner("ed25519");
  var swapped = makeSigner("ed25519");
  var pinnedKeyId = Buffer.from(await subtle.digest("SHA-1", pinned.spki));
  var live = { key: pinned.key, spki: pinned.spki, keyIdentifier: pinnedKeyId };
  var livePromise = pki.cms.sign(CONTENT, live, { eContentType: "id-cct-PKIData" });
  live.key = swapped.key;                     // rewritten on the very next line
  live.spki = swapped.spki;
  var liveSi = pki.schema.cms.parse(await livePromise).signerInfos[0];
  // The signature covers the signedAttrs as a SET OF, not as the [0] IMPLICIT
  // form they ride on the wire (RFC 5652 sec. 5.4), so the tag is put back.
  var liveSigned = Buffer.from(liveSi.signedAttrsBytes);
  liveSigned[0] = 0x31;
  check("key-only signer: a descriptor rewritten after the call still signs under the key it named",
    // Verified under the ORIGINAL public key -- the one the SignerIdentifier
    // names -- not under the replacement the descriptor was rewritten to hold.
    (await subtle.verify({ name: "Ed25519" },
      await subtle.importKey("spki", pinned.spki, { name: "Ed25519" }, false, ["verify"]),
      liveSi.signature, liveSigned)) === true);

  // The declared spki is validated as a WHOLE SubjectPublicKeyInfo, not just far
  // enough to find the algorithm. For an opaque key handle the correspondence check
  // is deliberately skipped, so this is the only thing between the caller's bytes
  // and a SignerInfo declaring them: an algorithm with no key, a key that is not a
  // BIT STRING, or an extra field would all be emitted as the signer's public key
  // and resolve to nothing for anyone verifying.
  var algOnly = pki.asn1.build.sequence([
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("Ed25519"))])]);
  await rejects("key-only signer: an spki carrying an algorithm but NO subjectPublicKey", function () {
    return pki.cms.sign(CONTENT, { key: pinned.key, spki: algOnly, keyIdentifier: pinnedKeyId },
      { eContentType: "id-cct-PKIData" });
  }, "cms/bad-input");

  var keyNotBitString = pki.asn1.build.sequence([
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("Ed25519"))]),
    pki.asn1.build.octetString(Buffer.alloc(32))]);
  await rejects("key-only signer: an spki whose subjectPublicKey is not a BIT STRING", function () {
    return pki.cms.sign(CONTENT, { key: pinned.key, spki: keyNotBitString, keyIdentifier: pinnedKeyId },
      { eContentType: "id-cct-PKIData" });
  }, "cms/bad-input");

  // The skip for an unexportable key is for an opaque HANDLE, and nothing else.
  // A composite key is a plain object the derivation also declines, and treating
  // that as "cannot check" would skip the comparison for a key whose halves are
  // perfectly readable -- the fail-open this check exists to prevent.
  await rejects("key-only signer: a key the check cannot read is refused, not skipped", function () {
    return pki.cms.sign(CONTENT, { key: { mldsa: keyPkcs8, trad: keyPkcs8 }, spki: spki, keyIdentifier: keyId },
      { eContentType: "id-cct-PKIData" });
  }, "cms/bad-input");

  // The single-SignerInfo rule is RFC 5272 sec. 3.2's, so it binds for a Full PKI
  // Request and not for ordinary CMS. Applying it to every content type would
  // refuse a multi-signer SignedData that nothing objects to -- CMS permits
  // several, and a key-only signer's certificate can reach a verifier by other
  // means.
  var certSigner = makeSigner("ec-p256");
  await rejects("key-only + another signer under id-cct-PKIData", function () {
    return pki.cms.sign(CONTENT, [certSigner, { key: keyPkcs8, spki: spki, keyIdentifier: keyId }],
      { eContentType: "id-cct-PKIData" });
  }, "cms/bad-input");
  check("the same pair over ordinary content is not this rule's business",
    pki.schema.cms.parse(await pki.cms.sign(CONTENT,
      [certSigner, { key: keyPkcs8, spki: spki, keyIdentifier: keyId }])).signerInfos.length === 2);

  // Generated extractable, then the private half re-imported non-extractable --
  // the shape a key that lives in a token has, without needing one.
  var hsmGen = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var hsmSpki = await pki.key.export(hsmGen.publicKey);
  var hsmKey = await subtle.importKey("pkcs8", await pki.key.export(hsmGen.privateKey),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  var hsmDer = await pki.cms.sign(CONTENT,
    { key: hsmKey, spki: hsmSpki, keyIdentifier: Buffer.from(await subtle.digest("SHA-1", hsmSpki)) },
    { eContentType: "id-cct-PKIData" });
  check("key-only signer: a NON-EXTRACTABLE private key still signs",
    pki.schema.cms.parse(hsmDer).signerInfos.length === 1);

  // ... and its declared public key is still PROVEN, not taken on the caller's
  // word. The correspondence comes from the signature, which an opaque handle can
  // produce as readily as an exportable key -- so there is no key kind for which
  // this check is skipped, and signing with handle A while declaring a valid
  // same-algorithm key B is refused rather than emitted as an unverifiable
  // SignerInfo.
  var otherEc = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var otherSpki = await pki.key.export(otherEc.publicKey);
  var otherKeyId = Buffer.from(await subtle.digest("SHA-1", otherSpki));
  await rejects("key-only signer: an opaque key with SOMEONE ELSE'S spki is refused", function () {
    return pki.cms.sign(CONTENT, { key: hsmKey, spki: otherSpki, keyIdentifier: otherKeyId },
      { eContentType: "id-cct-PKIData" });
  }, "cms/bad-input");

  // The signature, verified directly. The signed attributes are signed as a SET OF
  // (RFC 5652 sec. 5.4), which is the [0] IMPLICIT node re-tagged to a universal
  // SET -- reconstructing that is the whole point of the check.
  var si = pki.schema.cms.parse(der).signerInfos[0];
  var attrsDer = si.signedAttrsBytes;
  var preimage = Buffer.concat([Buffer.from([0x31]), attrsDer.subarray(1)]);   // [0] IMPLICIT -> SET
  var pub = await subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  // CMS carries an ECDSA signature as DER SEQUENCE(r, s); WebCrypto verifies the
  // raw fixed-width r||s pair, so unwrap it here rather than reach for a private
  // helper.
  var sigNode = pki.asn1.decode(si.signature);
  var fixed = function (n) {
    var v = pki.asn1.read.integer(n);
    var hex = v.toString(16);
    return Buffer.from(hex.padStart(64, "0"), "hex");
  };
  var raw = Buffer.concat([fixed(sigNode.children[0]), fixed(sigNode.children[1])]);
  var ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, raw, preimage);
  check("key-only signer: the signature verifies against the request's own SPKI", ok === true);

  // PD3(c): "If the request key is used for signing, there MUST be only one
  // SignerInfo in the SignedData."
  var withCert = makeSigner("ec-p256");
  check("key-only signer alongside a second signer is refused (RFC 5272 sec. 3.2)",
    (await (async function () {
      try {
        await pki.cms.sign(CONTENT, [{ key: keyPkcs8, spki: spki, keyIdentifier: keyId }, withCert],
          { eContentType: "id-cct-PKIData" });
        return "NO-THROW";
      } catch (e) { return e.code; }
    })()) === "cms/bad-input");

  check("a key-only signer with no keyIdentifier is refused",
    (await (async function () {
      try { await pki.cms.sign(CONTENT, { key: keyPkcs8, spki: spki }, { eContentType: "id-cct-PKIData" }); return "NO-THROW"; }
      catch (e) { return e.code; }
    })()) === "cms/bad-input");

  // A key identifier is BYTES. Anything Buffer.from() merely ACCEPTS is not a key
  // identifier: Buffer.from(20) allocates twenty zero octets, and Buffer.from("a1b2")
  // takes the ASCII of the text rather than the two octets a reader means by it. Either
  // one emits a structurally valid SignerIdentifier carrying an identifier the caller
  // never asked for, which no verifier can match to the certification request -- so the
  // type is refused rather than coerced.
  var badKeyIds = [[20, "a number"], ["a1b2", "a hex-looking string"], [[1, 2, 3], "a plain array"], [{ length: 4 }, "an array-like object"]];
  for (var bi = 0; bi < badKeyIds.length; bi++) {
    check("a key-only signer's keyIdentifier as " + badKeyIds[bi][1] + " is refused, never coerced",
      (await (async function (v) {
        try {
          await pki.cms.sign(CONTENT, { key: keyPkcs8, spki: spki, keyIdentifier: v }, { eContentType: "id-cct-PKIData" });
          return "NO-THROW";
        } catch (e) { return e.code; }
      })(badKeyIds[bi][0])) === "cms/bad-input");
  }

  check("a key-only signer's keyIdentifier as a Uint8Array is accepted (bytes are bytes)",
    (await (async function () {
      try {
        var d = await pki.cms.sign(CONTENT, { key: keyPkcs8, spki: spki, keyIdentifier: new Uint8Array([1, 2, 3, 4]) },
          { eContentType: "id-cct-PKIData" });
        return Buffer.isBuffer(d) && d.length > 0;
      } catch (e) { return "THREW:" + e.code; }
    })()) === true);

  check("a signer with neither cert nor spki is still refused",
    (await (async function () {
      try { await pki.cms.sign(CONTENT, { key: keyPkcs8 }); return "NO-THROW"; }
      catch (e) { return e.code; }
    })()) === "cms/bad-input");
}

async function run() {
  await testPssSpkiParams();
  await testSlhDsa();
  await testKeyOnlySigner();
  await testAlgorithms();
  await testSchemeAndInputs();
  await testContentModes();
  await testMultiSigner();
  await testSignerIdentifier();
  await testSignedAttributes();
  await testOutputForms();
  await testBadInput();
  await testMlDsa();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
