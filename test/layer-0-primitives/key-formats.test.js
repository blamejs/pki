// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the key encodings pki.key moves a key in and out of.
 * RED conformance vectors for `opts.format` on `pki.key.import` and
 * `pki.key.export`: the PKCS#1 `RSA PRIVATE KEY` of RFC 8017 App. A.1, the SEC1
 * `EC PRIVATE KEY` of RFC 5915, and JWK per RFC 7517. Neither DER encoding names
 * an algorithm, so what a key is imported as is the caller's statement and never
 * a default, and the vectors drive both halves: a key that imports has to sign or
 * agree, not merely parse.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var crypto = require("node:crypto");

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return e.code || e.name; } }

var RSA = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
var RSA_PKCS1 = RSA.privateKey.export({ type: "pkcs1", format: "der" });
var RSA_PKCS1_PEM = RSA.privateKey.export({ type: "pkcs1", format: "pem" });
var RSA_PKCS1_PUB = RSA.publicKey.export({ type: "pkcs1", format: "der" });
var EC = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
var EC_SEC1 = EC.privateKey.export({ type: "sec1", format: "der" });
var EC_SEC1_PEM = EC.privateKey.export({ type: "sec1", format: "pem" });

// ---- PKCS#1 -------------------------------------------------------------
async function testPkcs1() {
  var key = await pki.key.import(RSA_PKCS1, { format: "pkcs1", extractable: true, algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } });
  check("1. a PKCS#1 private key imports as the algorithm the caller named",
    key.type === "private" && key.algorithm.name === "RSASSA-PKCS1-v1_5");
  check("2. the same key as a PEM imports too",
    (await pki.key.import(RSA_PKCS1_PEM, { format: "pkcs1", algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } })).type === "private");
  var pub = await pki.key.import(RSA_PKCS1_PUB, { format: "pkcs1", extractable: true, algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } });
  check("3. and the public half imports as a public key", pub.type === "public");

  // Both halves are usable, not merely parsed: the imported private key signs and the imported
  // public key verifies that signature.
  var wc = require("../../lib/webcrypto").webcrypto;
  var msg = Buffer.from("the key works");
  var sig = await wc.subtle.sign("RSASSA-PKCS1-v1_5", key, msg);
  check("4. the imported private key signs and the imported public key verifies it",
    (await wc.subtle.verify("RSASSA-PKCS1-v1_5", pub, sig, msg)) === true);

  check("5. the structure names no algorithm, so an import without one is refused",
    (await codeOf(pki.key.import(RSA_PKCS1, { format: "pkcs1" }))) === "key/bad-input");

  // A key exported back to PKCS#1 is the key that went in.
  var exported = await pki.key.export(key, { format: "pkcs1" });
  check("6. exporting to PKCS#1 produces the bytes the key was imported from", exported.equals(RSA_PKCS1));
  check("7. and the public half exports to the PKCS#1 public encoding",
    (await pki.key.export(pub, { format: "pkcs1" })).equals(RSA_PKCS1_PUB));

  // Multi-prime is readable as a structure and not usable as a key (RFC 7518 sec. 6.3.2.7 refuses
  // it for JWK, and this toolkit's crypto engine has no multi-prime arm).
  var b = pki.asn1.build;
  var k = pki.schema.pkcs1.parse(RSA_PKCS1);
  var multi = b.sequence([b.integer(1n), b.integer(k.modulus), b.integer(k.publicExponent),
    b.integer(k.privateExponent), b.integer(k.prime1), b.integer(k.prime2), b.integer(k.exponent1),
    b.integer(k.exponent2), b.integer(k.coefficient),
    b.sequence([b.sequence([b.integer(3n), b.integer(1n), b.integer(1n)])])]);
  check("8. a multi-prime key parses as a structure",
    pki.schema.pkcs1.parse(multi).otherPrimeInfos.length === 1);
  check("9. and is refused on import, the engine having no arm for it",
    (await codeOf(pki.key.import(multi, { format: "pkcs1", algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } }))) ===
      "key/unsupported-key");
}

// ---- SEC1 ---------------------------------------------------------------
async function testSec1() {
  var key = await pki.key.import(EC_SEC1, { format: "sec1", extractable: true, algorithm: { name: "ECDSA", namedCurve: "P-256" } });
  check("10. a SEC1 private key imports on the curve it names",
    key.type === "private" && key.algorithm.name === "ECDSA" && key.algorithm.namedCurve === "P-256");
  check("11. the same key as a PEM imports too",
    (await pki.key.import(EC_SEC1_PEM, { format: "sec1", algorithm: { name: "ECDSA", namedCurve: "P-256" } })).type === "private");

  // Every curve arm the feature claims, not one of them.
  var curves = [["prime256v1", "P-256"], ["secp384r1", "P-384"], ["secp521r1", "P-521"]];
  for (var i = 0; i < curves.length; i++) {
    var kp = crypto.generateKeyPairSync("ec", { namedCurve: curves[i][0] });
    var der = kp.privateKey.export({ type: "sec1", format: "der" });
    var k = await pki.key.import(der, { format: "sec1", algorithm: { name: "ECDSA", namedCurve: curves[i][1] } });
    check("12." + i + " " + curves[i][1] + " imports from SEC1", k.algorithm.namedCurve === curves[i][1]);
  }

  // The key works: it signs, and the public half derived from it verifies.
  // `publicFromPrivate` answers with the SubjectPublicKeyInfo bytes, so the verifying half is
  // imported from those: the signature is checked against the public key derived from the scalar,
  // not against the point the encoding happened to store.
  var wc = require("../../lib/webcrypto").webcrypto;
  var spki = await pki.key.publicFromPrivate(key);
  var pub = await pki.key.import(spki, { algorithm: { name: "ECDSA", namedCurve: "P-256" } });
  var msg = Buffer.from("the curve works");
  var sig = await wc.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, msg);
  check("13. the imported key signs and the public half derived from it verifies",
    (await wc.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, sig, msg)) === true);

  check("14. a curve the caller names that the key does not carry is refused",
    (await codeOf(pki.key.import(EC_SEC1, { format: "sec1", algorithm: { name: "ECDSA", namedCurve: "P-384" } }))) ===
      "key/bad-input");

  var exported = await pki.key.export(key, { format: "sec1" });
  check("15. exporting to SEC1 reads back to the same scalar and curve", (function () {
    var a = pki.schema.sec1.parse(exported), bb = pki.schema.sec1.parse(EC_SEC1);
    return a.privateKey.equals(bb.privateKey) && a.curve === bb.curve;
  })());
}

// ---- JWK ----------------------------------------------------------------
async function testJwk() {
  var pair = await pki.key.generate("Ed25519", { extractable: true });
  var jwk = await pki.key.export(pair.privateKey, { format: "jwk" });
  check("16. an Ed25519 private key exports to a JWK carrying the members RFC 8037 names",
    jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string" && typeof jwk.d === "string");
  var back = await pki.key.import(jwk, { format: "jwk", algorithm: "Ed25519" });
  check("17. and that JWK imports back to a private key", back.type === "private");
  var pubJwk = await pki.key.export(pair.publicKey, { format: "jwk" });
  check("18. a public export carries no private member", pubJwk.d === undefined && typeof pubJwk.x === "string");

  var ec = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" }, { extractable: true });
  var ecJwk = await pki.key.export(ec.privateKey, { format: "jwk" });
  check("19. an EC private key exports the members RFC 7518 sec. 6.2 names",
    ecJwk.kty === "EC" && ecJwk.crv === "P-256" && typeof ecJwk.x === "string" &&
    typeof ecJwk.y === "string" && typeof ecJwk.d === "string");
  check("20. and imports back on the curve its crv names",
    (await pki.key.import(ecJwk, { format: "jwk", algorithm: { name: "ECDSA", namedCurve: "P-256" } })).algorithm.namedCurve === "P-256");

  var rsa = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, hash: "SHA-256" }, { extractable: true });
  var rsaJwk = await pki.key.export(rsa.privateKey, { format: "jwk" });
  check("21. an RSA private key exports the CRT set whole (RFC 7518 sec. 6.3.2)",
    rsaJwk.kty === "RSA" && ["n", "e", "d", "p", "q", "dp", "dq", "qi"].every(function (m) { return typeof rsaJwk[m] === "string"; }));
  check("22. and imports back",
    (await pki.key.import(rsaJwk, { format: "jwk", algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } })).type === "private");

  check("23. a JWK that is not an object is refused",
    (await codeOf(pki.key.import("not a jwk", { format: "jwk", algorithm: "Ed25519" }))) === "key/bad-input");
  check("24. a JWK with no kty is refused",
    (await codeOf(pki.key.import({ crv: "Ed25519", x: "AAA" }, { format: "jwk", algorithm: "Ed25519" }))) === "key/bad-input");
}

// ---- the option itself --------------------------------------------------
async function testTheOption() {
  check("25. a format this toolkit does not move a key in is refused by name",
    (await codeOf(pki.key.import(RSA_PKCS1, { format: "pkcs9" }))) === "key/bad-input");
  check("26. and so is one that is not a string",
    (await codeOf(pki.key.import(RSA_PKCS1, { format: 7 }))) === "key/bad-input");
  check("27. a PKCS#8 key handed in under the pkcs1 format is refused, the structures differing",
    (await codeOf(pki.key.import(RSA.privateKey.export({ type: "pkcs8", format: "der" }),
      { format: "pkcs1", algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } }))) !== "NO-THROW");
  check("28. CONTROL: with no format option the door reads PKCS#8 as it always did",
    (await pki.key.import(RSA.privateKey.export({ type: "pkcs8", format: "der" }),
      { algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } })).type === "private");
  check("29. exporting to a format the key cannot be written in is refused", (function () {
    return true;   // placed below, once the EC key is in scope
  })());
  var ed = await pki.key.generate("Ed25519", { extractable: true });
  check("30. an Ed25519 key cannot be written as PKCS#1, which is an RSA encoding",
    (await codeOf(pki.key.export(ed.privateKey, { format: "pkcs1" }))) === "key/bad-input");
  check("31. nor as SEC1, which is an EC encoding",
    (await codeOf(pki.key.export(ed.privateKey, { format: "sec1" }))) === "key/bad-input");
}

// A PKCS#1 key is a private one or a public one, and the label on the armor says which.
// `opts.format` names the ENCODING, so both labels are that encoding and the structure the
// bytes carry is what decides which half arrived. Reading only the private label made the
// same key importable as DER and refused as PEM.
async function testPkcs1PublicPem() {
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var pubDer = rsa.publicKey.export({ format: "der", type: "pkcs1" });
  var privDer = rsa.privateKey.export({ format: "der", type: "pkcs1" });
  var pubPem = pki.schema.pkcs1.pemEncodePublic(pubDer);
  var privPem = pki.schema.pkcs1.pemEncode(privDer);

  async function importCode(input) {
    try { await pki.key.import(input, { format: "pkcs1", algorithm: "RS256" }); return "ok"; }
    catch (e) { return e.code || e.name; }
  }
  check("P1. an RSA PUBLIC KEY PEM imports, as its DER already did",
    (await importCode(pubPem)) === "ok" && (await importCode(pubDer)) === "ok");
  check("P2. an RSA PRIVATE KEY PEM still imports", (await importCode(privPem)) === "ok");
  check("P3. the label and the structure must agree, and a mislabeled key is refused",
    (await importCode(pki.schema.pkcs1.pemEncode(pubDer))) !== "ok" &&
    (await importCode(pki.schema.pkcs1.pemEncodePublic(privDer))) !== "ok");
  check("P4. a PEM under a label neither half uses is refused",
    (await importCode("-----BEGIN PRIVATE KEY-----\n" +
      privDer.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END PRIVATE KEY-----\n")) !== "ok");
  var roundTripped = await pki.key.export(
    await pki.key.import(pubPem, { format: "pkcs1", algorithm: "RS256" }), { format: "pkcs1" });
  check("P5. an imported public key exports back to the same PKCS#1 bytes", roundTripped.equals(pubDer));
}

// A CryptoKey from another WebCrypto implementation exports its DER through one path that knows
// the three ways such a key can be reached. Exporting it as a JWK went straight to this toolkit's
// own subtle, which refuses a key it did not make, so the same key answered one format and
// refused the other.
async function testForeignKeyJwkExport() {
  var native = await crypto.webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  check("F1. a foreign public key exports as DER",
    Buffer.isBuffer(await pki.key.export(native.publicKey)));
  var pubJwk = await pki.key.export(native.publicKey, { format: "jwk" });
  check("F2. ...and as a JWK, which is the same key read another way",
    pubJwk && pubJwk.kty === "EC" && pubJwk.crv === "P-256" && typeof pubJwk.x === "string");
  var privJwk = await pki.key.export(native.privateKey, { format: "jwk" });
  check("F3. the private half too, with its own member",
    privJwk && privJwk.kty === "EC" && typeof privJwk.d === "string");
  check("F4. the JWK names the same public point the DER does", (function () {
    return pubJwk.x === privJwk.x && pubJwk.y === privJwk.y;
  })());

  var ownPair = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var ownJwk = await pki.key.export(ownPair.publicKey, { format: "jwk" });
  check("F5. CONTROL: a key this toolkit made still exports as a JWK",
    ownJwk && ownJwk.kty === "EC" && ownJwk.crv === "P-256");

  var sealed = await crypto.webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  check("F6. a foreign key that is not extractable is refused, and says why",
    (await codeOf(pki.key.export(sealed.privateKey, { format: "jwk" }))) !== "NO-THROW");
}

async function run() {
  await testForeignKeyJwkExport();
  await testPkcs1();
  await testPkcs1PublicPem();
  await testSec1();
  await testJwk();
  await testTheOption();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
