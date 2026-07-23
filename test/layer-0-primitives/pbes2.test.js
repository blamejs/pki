// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// PBES2 / PBKDF2 parameter byte-exactness (RFC 8018 App. A.2 / A.4 / B.2.5) -- the shared lib/pbes2.js home
// that pki.cms and pki.key both compose. The byte-layout vectors drive the shipped consumer pki.key.encrypt
// and decode the emitted PBKDF2-params: a prf equal to the DEFAULT (hmacWithSHA1) is OMITTED (X.690 sec.
// 11.5), every other prf is an hmacWithSHA_n AlgorithmIdentifier carrying NULL parameters, and keyLength is
// never emitted for an AES cipher (the cipher OID fixes the size). The primitive contracts (password
// encoding, the DoS bounds, the prf tables) are pinned directly against the internal home so a regression
// in the extraction is caught at the primitive, not only through a consumer.

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var pbes2 = require("../../lib/pbes2");
var signing = require("../helpers/signing");
var makeSigner = signing.makeSigner;
var asn1 = pki.asn1;
var b = asn1.build;
var TAGS = asn1.TAGS;
function byName(n) { return pki.oid.byName(n); }

// A plain (code, msg) error factory -- the shape pbes2 rejects through (never a class, per the guard
// error-factory convention).
function E(code, msg) { var e = new Error(msg); e.code = code; return e; }
function codeFrom(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }

// Decode the PBKDF2-params SEQUENCE out of a pki.key.encrypt EncryptedPrivateKeyInfo.
function pbkdf2ParamsOf(epki) {
  var pe = pki.schema.pkcs8.parseEncrypted(epki);
  var pbes2Params = asn1.decode(pe.encryptionAlgorithm.parameters); // SEQ { kdf, encScheme }
  return pbes2Params.children[0].children[1];                       // kdf = SEQ { pbkdf2-OID, PBKDF2-params }
}

// ---- #4 / #5 byte-exact PBKDF2-params through pki.key.encrypt ---------------
async function testParamByteExactness() {
  var rsaDer = makeSigner("rsa").key;

  // #4 prf == the DEFAULT (hmacWithSHA1) -> the prf element is OMITTED: params are exactly [salt, iter].
  var kp1 = pbkdf2ParamsOf(await pki.key.encrypt(rsaDer, "pw", { prf: "hmacWithSHA1" }));
  check("#4 hmacWithSHA1 prf is omitted (PBKDF2-params = salt + iterationCount only)", kp1.children.length === 2);
  check("#4 PBKDF2-params[0] is the salt OCTET STRING", kp1.children[0].tagNumber === TAGS.OCTET_STRING);
  check("#4 PBKDF2-params[1] is the iterationCount INTEGER", kp1.children[1].tagNumber === TAGS.INTEGER);

  // A non-default prf IS emitted, as an hmacWithSHA_n AlgorithmIdentifier with NULL parameters.
  var prfs = [["hmacWithSHA256", "hmacWithSHA256"], ["hmacWithSHA384", "hmacWithSHA384"], ["hmacWithSHA512", "hmacWithSHA512"]];
  for (var i = 0; i < prfs.length; i++) {
    var kp = pbkdf2ParamsOf(await pki.key.encrypt(rsaDer, "pw", { prf: prfs[i][0] }));
    check("#5 " + prfs[i][0] + " PBKDF2-params carry [salt, iter, prf] (no keyLength)", kp.children.length === 3);
    var prfAlg = kp.children[2];
    check("#5 " + prfs[i][0] + " prf is SEQ { OID, NULL }", prfAlg.tagNumber === TAGS.SEQUENCE && prfAlg.children.length === 2 &&
      asn1.read.oid(prfAlg.children[0]) === byName(prfs[i][1]) && prfAlg.children[1].tagNumber === TAGS.NULL);
    // #5 no keyLength: the second child is always the iterationCount INTEGER, never a second INTEGER after it.
    check("#5 " + prfs[i][0] + " emits no keyLength INTEGER", kp.children[1].tagNumber === TAGS.INTEGER);
  }

  // The PBES2 AlgorithmIdentifier structure: SEQ { pbes2, SEQ { SEQ{pbkdf2,..}, SEQ{aes,iv} } }.
  var pe = pki.schema.pkcs8.parseEncrypted(await pki.key.encrypt(rsaDer, "pw", { cipher: "aes-256-cbc" }));
  var params = asn1.decode(pe.encryptionAlgorithm.parameters);
  check("PBES2 params has [keyDerivationFunc, encryptionScheme]", params.children.length === 2);
  check("PBES2 keyDerivationFunc names PBKDF2", asn1.read.oid(params.children[0].children[0]) === byName("pbkdf2"));
  check("PBES2 encryptionScheme names aes256-CBC with a 16-octet IV", asn1.read.oid(params.children[1].children[0]) === byName("aes256-CBC") &&
    asn1.read.octetString(params.children[1].children[1]).length === 16);
}

// ---- shared primitive contracts (the extraction guard) ---------------------
function testPrimitiveContracts() {
  // passwordBytes: UTF-8 for a string (byte-identical to OpenSSL), verbatim for Buffer/Uint8Array. The
  // non-ASCII sample is built at runtime so the test source stays pure ASCII.
  var utf8pw = String.fromCharCode(0x70, 0xff, 0xe7);   // "p", U+00FF, U+00E7
  check("passwordBytes UTF-8-encodes a string", Buffer.compare(pbes2.passwordBytes(utf8pw, E, "t"), Buffer.from(utf8pw, "utf8")) === 0);
  var buf = Buffer.from([1, 2, 3]);
  check("passwordBytes returns a Buffer verbatim", pbes2.passwordBytes(buf, E, "t") === buf);
  check("passwordBytes rejects a non-octet password", codeFrom(function () { pbes2.passwordBytes(42, E, "t"); }) === "t/bad-input");

  // assertIterations: positive integer, at or below the hard cap.
  check("assertIterations accepts a positive integer", pbes2.assertIterations(600000, E, "t") === 600000);
  check("assertIterations rejects a non-integer", codeFrom(function () { pbes2.assertIterations(1.5, E, "t"); }) === "t/bad-input");
  check("assertIterations rejects zero", codeFrom(function () { pbes2.assertIterations(0, E, "t"); }) === "t/bad-input");
  check("assertIterations rejects over the hard cap", codeFrom(function () { pbes2.assertIterations(pki.constants.LIMITS.PBKDF2_MAX_ITERATIONS + 1, E, "t"); }) === "t/bad-input");

  // assertSalt: bounded by the shared cap.
  check("assertSalt accepts a salt at the cap", pbes2.assertSalt(Buffer.alloc(pki.constants.LIMITS.PBKDF2_MAX_SALT, 1), E, "t").length === pki.constants.LIMITS.PBKDF2_MAX_SALT);
  check("assertSalt rejects a salt over the cap", codeFrom(function () { pbes2.assertSalt(Buffer.alloc(pki.constants.LIMITS.PBKDF2_MAX_SALT + 1, 1), E, "t"); }) === "t/bad-input");

  // prf tables, both directions.
  check("prfNodeByName maps a name to a node digest", pbes2.prfNodeByName("hmacWithSHA256", E, "t") === "sha256");
  check("prfNodeByName rejects an unknown prf name", codeFrom(function () { pbes2.prfNodeByName("hmacWithMD5", E, "t"); }) === "t/bad-input");
  check("prfNodeByOid maps an OID to a node digest", pbes2.prfNodeByOid(byName("hmacWithSHA384"), E, "t") === "sha384");
  check("prfNodeByOid rejects an unknown prf OID", codeFrom(function () { pbes2.prfNodeByOid(byName("aes256-CBC"), E, "t"); }) === "t/unsupported-algorithm");

  // pbkdf2ParamsSeq builder: prf omitted iff it equals the default.
  var withDefault = asn1.decode(pbes2.pbkdf2ParamsSeq(Buffer.alloc(16, 1), 1000, "hmacWithSHA1"));
  check("pbkdf2ParamsSeq omits the default prf", withDefault.children.length === 2);
  var withPrf = asn1.decode(pbes2.pbkdf2ParamsSeq(Buffer.alloc(16, 1), 1000, "hmacWithSHA512"));
  check("pbkdf2ParamsSeq emits a non-default prf", withPrf.children.length === 3);

  // parsePbkdf2Params DoS bounds (attacker-controlled work): salt cap and iteration cap.
  var overIter = b.sequence([b.octetString(Buffer.alloc(16, 1)), b.integer(BigInt(pki.constants.LIMITS.PBKDF2_MAX_ITERATIONS + 1))]);
  check("parsePbkdf2Params rejects an over-cap iterationCount", codeFrom(function () { pbes2.parsePbkdf2Params(overIter.subarray ? asn1.decode(overIter) : overIter, {}, E, "t"); }) === "t/iteration-limit");
  check("parsePbkdf2Params validates opts.maxIterations (NaN would disable the cap)", codeFrom(function () { pbes2.parsePbkdf2Params(asn1.decode(b.sequence([b.octetString(Buffer.alloc(16, 1)), b.integer(1000n)])), { maxIterations: NaN }, E, "t"); }) === "t/bad-input");
}

// ---- pbes2Encrypt (the shared higher-level PBES2 encrypt) ------------------
function testPbes2Encrypt() {
  var nc = require("node:crypto");
  var pw = Buffer.from("pw", "utf8");
  // round-trip with an explicit salt + iv + iterations, decrypted via the sibling cbcDecrypt.
  var salt = Buffer.alloc(8, 3), iv = Buffer.alloc(16, 4), pt = Buffer.from("sixteen-byte-pt!");
  var r = pbes2.pbes2Encrypt(pw, pt, { cipher: "aes256-CBC", salt: salt, iv: iv, iterations: 4096 }, E, "t");
  var key = nc.pbkdf2Sync(pw, salt, 4096, 32, "sha256");
  check("pbes2Encrypt round-trips through cbcDecrypt", pbes2.cbcDecrypt(key, iv, r.ct, 256).equals(pt));
  var params = asn1.decode(r.algId);
  check("pbes2Encrypt algId names pbes2 + the AES-CBC scheme", asn1.read.oid(params.children[0]) === byName("pbes2"));
  // default cipher/salt/iv path (no explicit opts) still produces a decodable structure.
  var r2 = pbes2.pbes2Encrypt(pw, pt, {}, E, "t");
  check("pbes2Encrypt defaults produce a PBES2 algId", asn1.read.oid(asn1.decode(r2.algId).children[0]) === byName("pbes2"));
  // an unsupported cipher fails closed -- both a known-but-non-CBC scheme and an unknown name.
  check("pbes2Encrypt rejects a non-AES-CBC cipher", codeFrom(function () { pbes2.pbes2Encrypt(pw, pt, { cipher: "aes256-GCM" }, E, "t"); }) === "t/bad-input");
  check("pbes2Encrypt rejects an unknown cipher name", codeFrom(function () { pbes2.pbes2Encrypt(pw, pt, { cipher: "bogus" }, E, "t"); }) === "t/bad-input");
}

// ---- cross-consumer: the same shared home serves cms and key ---------------
async function testSharedHome() {
  // A PBES2 structure pki.cms.encrypt emits and one pki.key.encrypt emits share the identical AlgorithmId
  // shape (both compose pbes2.pbes2AlgId): pbes2 OID -> { PBKDF2 kdf, AES-CBC scheme }.
  var rsaDer = makeSigner("rsa").key;
  var keyEnc = pki.schema.pkcs8.parseEncrypted(await pki.key.encrypt(rsaDer, "pw", { cipher: "aes-256-cbc", prf: "hmacWithSHA256" }));
  check("shared PBES2 home: key encrypt names pbes2 + pbkdf2 + aes256-CBC", keyEnc.encryptionAlgorithm.oid === byName("pbes2") &&
    asn1.read.oid(asn1.decode(keyEnc.encryptionAlgorithm.parameters).children[0].children[0]) === byName("pbkdf2"));
}

async function main() {
  await testParamByteExactness();
  testPrimitiveContracts();
  testPbes2Encrypt();
  await testSharedHome();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
