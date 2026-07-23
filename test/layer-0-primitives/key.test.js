// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for pki.key -- the key-material lifecycle producing surface (RFC 5958 PKCS#8 /
// SubjectPublicKeyInfo export/import, RFC 8018 PBES2 encrypt/decrypt). Every vector drives the shipped
// consumer (pki.key.*) and asserts through pki.schema.pkcs8.parse / .parseEncrypted round-trips, a raw
// asn1.decode of the emitted DER, or err.code. pki.schema.pkcs8's strict decoder is the round-trip oracle.
//
// A MAC-less PBES2-CBC decrypt is not a padding oracle (RFC 8018 sec. 8): a wrong password and a valid pad
// that is not a PrivateKeyInfo BOTH surface the single uniform key/decrypt-failed. The structural
// pre-derivation faults (non-PBKDF2 KDF, non-AES-CBC scheme, over-cap salt/iteration, wrong-length IV,
// malformed parameter SEQUENCE) stay distinct and typed. OpenSSL byte-parity + non-ASCII password interop
// (vectors #3 / #18) live in test/integration/key-openssl-interop.test.js. The v2 OneAsymmetricKey
// attached-public export (#12) and caller attributes-on-export (#20) are deferred: the delegating export
// never re-encodes a PKCS#8, and both would require it (the biconditional is already enforced on parse).

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var asn1 = pki.asn1;
var b = asn1.build;
var TAGS = asn1.TAGS;
var subtle = pki.webcrypto.subtle;
function byName(n) { return pki.oid.byName(n); }

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}

// A PBES2 EncryptedPrivateKeyInfo built from parts, for the malformed / reject vectors.
function pbes2Epki(kdfOid, kdfParams, encOid, iv, ct) {
  var kdf = b.sequence([b.oid(byName(kdfOid)), kdfParams]);
  var enc = b.sequence([b.oid(byName(encOid)), b.octetString(iv || Buffer.alloc(16, 2))]);
  var alg = b.sequence([b.oid(byName("pbes2")), b.sequence([kdf, enc])]);
  return b.sequence([alg, b.octetString(ct || Buffer.alloc(48, 3))]);
}
var GOOD_PBKDF2 = b.sequence([b.octetString(Buffer.alloc(16, 1)), b.integer(1000n)]);

// ---- #1 export -> parse -> byte round-trip, per key type -------------------
async function testExportRoundTrip() {
  var arms = [
    { name: "RSA", alg: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, oid: "rsaEncryption" },
    { name: "P-256", alg: { name: "ECDSA", namedCurve: "P-256" }, oid: "ecPublicKey" },
    { name: "Ed25519", alg: "Ed25519", oid: "Ed25519" },
    { name: "X25519", alg: "X25519", oid: "X25519" },
    { name: "ML-KEM-768", alg: { name: "ML-KEM-768" }, oid: "id-ml-kem-768" },
  ];
  for (var i = 0; i < arms.length; i++) {
    var a = arms[i];
    var pair = await pki.key.generate(a.alg);
    var p8 = await pki.key.export(pair.privateKey);
    var parsed = pki.schema.pkcs8.parse(p8);
    check("#1 " + a.name + " export parses as PKCS#8", parsed != null && parsed.privateKey != null);
    check("#1 " + a.name + " privateKeyAlgorithm OID matches", parsed.privateKeyAlgorithm.oid === byName(a.oid));
    var direct = Buffer.from(await subtle.exportKey("pkcs8", pair.privateKey));
    check("#1 " + a.name + " export is byte-identical to webcrypto exportKey (no re-encode)", Buffer.compare(p8, direct) === 0);
    // import inference / round-trip for the algorithms that name exactly one WebCrypto algorithm.
    var spki = await pki.key.export(pair.publicKey);
    if (a.oid === "Ed25519" || a.oid === "X25519" || /ml-kem/.test(a.oid)) {
      var imp = await pki.key.import(spki);
      check("#1 " + a.name + " import(spki) round-trips (inferred)", imp.type === "public");
    }
  }
}

// ---- #2 / #19 encrypt -> decrypt PBES2 round-trip ---------------------------
async function testPbes2RoundTrip() {
  var rsaDer = makeSigner("rsa").key;
  var ciphers = ["aes-256-cbc", "aes-192-cbc", "aes-128-cbc"];
  var prfs = ["hmacWithSHA256", "hmacWithSHA384", "hmacWithSHA512", "hmacWithSHA1"];
  for (var i = 0; i < ciphers.length; i++) {
    var enc = await pki.key.encrypt(rsaDer, "s3cr3t", { cipher: ciphers[i], prf: prfs[i % prfs.length] });
    var pe = pki.schema.pkcs8.parseEncrypted(enc);
    check("#2 " + ciphers[i] + " intermediate is PBES2", pe.encryptionAlgorithm.oid === byName("pbes2"));
    var back = await pki.key.decrypt(enc, "s3cr3t");
    check("#2 " + ciphers[i] + " decrypt recovers the exact PrivateKeyInfo DER", Buffer.compare(back, rsaDer) === 0);
  }
  // #19 the produced EncryptedPrivateKeyInfo is a strict 2-field SEQUENCE, encryptedData held raw.
  var out = await pki.key.encrypt(rsaDer, "pw");
  var root = asn1.decode(out);
  check("#19 EncryptedPrivateKeyInfo is exactly 2 children", root.children.length === 2);
  var pe2 = pki.schema.pkcs8.parseEncrypted(out);
  check("#19 encryptedData is the raw ciphertext OCTET STRING", Buffer.isBuffer(pe2.encryptedData) && pe2.encryptedData.length > 0);
  // PEM round-trip
  var pem = await pki.key.encrypt(rsaDer, "pw", { pem: true });
  check("#19 pem output carries the ENCRYPTED PRIVATE KEY armor", /-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(pem));
  var backPem = await pki.key.decrypt(pem, "pw", { pem: true });
  check("#19 pem decrypt yields PRIVATE KEY armor", /-----BEGIN PRIVATE KEY-----/.test(backPem));
  // #18 (our-own half) non-ASCII UTF-8 password round-trips (built at runtime -- source stays pure ASCII)
  var utf8pw = String.fromCharCode(0x70, 0xff, 0xe7);   // "p", U+00FF, U+00E7
  var encU = await pki.key.encrypt(rsaDer, utf8pw);
  check("#18 non-ASCII UTF-8 password round-trips", Buffer.compare(await pki.key.decrypt(encU, utf8pw), rsaDer) === 0);
}

// ---- #13 / #14 SPKI / PKCS8 AlgorithmIdentifier params encoding -------------
async function testAlgIdParams() {
  var ed = await pki.key.generate("Ed25519");
  var edSpki = await pki.key.export(ed.publicKey);
  check("#13 Ed25519 SPKI AlgorithmIdentifier has no parameters (RFC 8410 sec. 3)", asn1.decode(edSpki).children[0].children.length === 1);
  var edImp = await pki.key.import(edSpki);
  check("#13 Ed25519 SPKI import round-trips to a public key", edImp.type === "public" && edImp.algorithm.name === "Ed25519");

  var rsa = await pki.key.generate({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var rsaSpki = await pki.key.export(rsa.publicKey);
  var spkiAlg = asn1.decode(rsaSpki).children[0];
  check("#14 RSA SPKI parameters are exactly DER NULL", spkiAlg.children.length === 2 && spkiAlg.children[1].tagNumber === TAGS.NULL);
  var rsaP8 = await pki.key.export(rsa.privateKey);
  var p8Alg = asn1.decode(rsaP8).children[1];
  check("#14 RSA PKCS8 privateKeyAlgorithm parameters are exactly DER NULL", p8Alg.children.length === 2 && p8Alg.children[1].tagNumber === TAGS.NULL);
}

// ---- #6 / #7 / #8 / #15 / #16 / #17 decrypt fail-closed --------------------
async function testDecryptFailClosed() {
  var rsaDer = makeSigner("rsa").key;
  var enc = await pki.key.encrypt(rsaDer, "pw");

  // #7 wrong password and #8 valid-pad-non-PrivateKeyInfo are indistinguishable (uniform verdict).
  check("#7 wrong password -> key/decrypt-failed", (await codeOf(pki.key.decrypt(enc, "wrong"))) === "key/decrypt-failed");
  var tampered = Buffer.from(enc); tampered[tampered.length - 20] ^= 0xff;
  check("#8 tampered ciphertext -> same key/decrypt-failed", (await codeOf(pki.key.decrypt(tampered, "pw"))) === "key/decrypt-failed");

  // #6 iteration cap enforced BEFORE derivation (a fast typed fail, no pbkdf2 work).
  var overCap = pbes2Epki("pbkdf2", b.sequence([b.octetString(Buffer.alloc(16, 1)), b.integer(10000001n)]), "aes256-CBC");
  check("#6 iterationCount over the cap -> key/iteration-limit", (await codeOf(pki.key.decrypt(overCap, "pw"))) === "key/iteration-limit");
  var count2000 = pbes2Epki("pbkdf2", b.sequence([b.octetString(Buffer.alloc(16, 1)), b.integer(2000n)]), "aes256-CBC");
  check("#6 opts.maxIterations lowers the cap (downward-only)", (await codeOf(pki.key.decrypt(count2000, "pw", { maxIterations: 1000 }))) === "key/iteration-limit");
  check("#6 invalid opts.maxIterations -> key/bad-input (config bound)", (await codeOf(pki.key.decrypt(enc, "pw", { maxIterations: NaN }))) === "key/bad-input");

  // #15 salt over the cap, before any derivation.
  var bigSalt = pbes2Epki("pbkdf2", b.sequence([b.octetString(Buffer.alloc(2048, 1)), b.integer(1000n)]), "aes256-CBC");
  check("#15 over-cap salt -> typed pre-derivation reject", (await codeOf(pki.key.decrypt(bigSalt, "pw"))) === "key/bad-algorithm-parameters");

  // #16 malformed PBES2-params is a typed KeyError, never a raw children[] dereference.
  var oneElem = b.sequence([b.oid(byName("pbes2")), b.sequence([b.sequence([b.oid(byName("pbkdf2")), GOOD_PBKDF2])])]);
  var malformed = b.sequence([oneElem, b.octetString(Buffer.alloc(48, 3))]);
  check("#16 1-element PBES2-params -> key/bad-algorithm-parameters", (await codeOf(pki.key.decrypt(malformed, "pw"))) === "key/bad-algorithm-parameters");
  var truncKdf = pbes2Epki("pbkdf2", b.sequence([b.octetString(Buffer.alloc(16, 1))]), "aes256-CBC");
  check("#16 truncated PBKDF2-params -> key/bad-algorithm-parameters", (await codeOf(pki.key.decrypt(truncKdf, "pw"))) === "key/bad-algorithm-parameters");

  // #17 wrong-length IV, before decipher.
  var badIv = pbes2Epki("pbkdf2", GOOD_PBKDF2, "aes256-CBC", Buffer.alloc(8, 2));
  check("#17 8-octet AES-CBC IV -> key/bad-algorithm-parameters", (await codeOf(pki.key.decrypt(badIv, "pw"))) === "key/bad-algorithm-parameters");

  // A non-canonical explicit default prf (hmacWithSHA1 with NULL params) MUST be rejected (X.690 sec. 11.5 /
  // RFC 8018 App. A.2 -- the default MUST be omitted, never emitted explicitly).
  var explicitDefaultPrf = b.sequence([b.octetString(Buffer.alloc(16, 1)), b.integer(1000n), b.sequence([b.oid(byName("hmacWithSHA1")), b.nullValue()])]);
  var nonCanonPrf = pbes2Epki("pbkdf2", explicitDefaultPrf, "aes256-CBC");
  check("non-canonical explicit hmacWithSHA1 prf -> key/bad-algorithm-parameters", (await codeOf(pki.key.decrypt(nonCanonPrf, "pw"))) === "key/bad-algorithm-parameters");
}

// ---- #9 / #10 / #11 unsupported-algorithm boundaries -----------------------
async function testUnsupportedAlgorithms() {
  // #9 PBES1 legacy encryptionAlgorithm (pbeWithSHA1AndDES-CBC, pkcs-5.10) -- fail closed.
  var pbes1 = b.sequence([b.sequence([b.oid("1.2.840.113549.1.5.10"), b.nullValue()]), b.octetString(Buffer.alloc(16, 3))]);
  check("#9 PBES1 encryptionAlgorithm -> key/unsupported-algorithm", (await codeOf(pki.key.decrypt(pbes1, "pw"))) === "key/unsupported-algorithm");
  // #10 PBMAC1 as encryptionAlgorithm (a MAC scheme is not content-encryption).
  var mac = b.sequence([b.sequence([b.oid(byName("pbmac1")), b.nullValue()]), b.octetString(Buffer.alloc(16, 3))]);
  check("#10 PBMAC1 encryptionAlgorithm -> key/unsupported-algorithm", (await codeOf(pki.key.decrypt(mac, "pw"))) === "key/unsupported-algorithm");
  // #11 non-PBKDF2 KDF inside PBES2 (RFC 8018 sec. 6.2 "shall be PBKDF2").
  var nonPbkdf2 = pbes2Epki("hmacWithSHA256", GOOD_PBKDF2, "aes256-CBC");
  check("#11 non-PBKDF2 keyDerivationFunc -> key/unsupported-algorithm", (await codeOf(pki.key.decrypt(nonPbkdf2, "pw"))) === "key/unsupported-algorithm");
  // A non-AES-CBC PBES2 encryptionScheme (GCM is a CMS scheme, not a PBES2 key-encryption one).
  var gcm = pbes2Epki("pbkdf2", GOOD_PBKDF2, "aes256-GCM");
  check("#11 non-AES-CBC PBES2 encryptionScheme -> key/unsupported-algorithm", (await codeOf(pki.key.decrypt(gcm, "pw"))) === "key/unsupported-algorithm");
}

// ---- import / generate / publicFromPrivate verbs ---------------------------
async function testVerbs() {
  var ed = await pki.key.generate("Ed25519");
  var p8 = await pki.key.export(ed.privateKey);
  var spki = await pki.key.export(ed.publicKey);
  // publicFromPrivate derives the SAME SPKI the engine exports.
  check("publicFromPrivate derives the SPKI public key", Buffer.compare(await pki.key.publicFromPrivate(p8), Buffer.from(spki)) === 0);
  check("publicFromPrivate accepts a CryptoKey", Buffer.compare(await pki.key.publicFromPrivate(ed.privateKey), Buffer.from(spki)) === 0);

  // import fails closed for an ambiguous algorithm (RSA / EC): guards never guess.
  var rsa = await pki.key.generate({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var rsaSpki = await pki.key.export(rsa.publicKey);
  check("import RSA without opts.algorithm -> fail closed (ambiguous)", (await codeOf(pki.key.import(rsaSpki))) === "key/unsupported-algorithm");
  var imp = await pki.key.import(rsaSpki, { algorithm: { name: "RSA-PSS", hash: "SHA-256" } });
  check("import RSA with explicit opts.algorithm succeeds", imp.type === "public" && imp.algorithm.name === "RSA-PSS");

  // import an ENCRYPTED PRIVATE KEY (decrypt-first) with the password.
  var encPem = await pki.key.encrypt(p8, "pw", { pem: true });
  var back = await pki.key.import(encPem, { password: "pw" });
  check("import ENCRYPTED PRIVATE KEY with password decrypts + imports", back.type === "private" && back.algorithm.name === "Ed25519");
  check("import ENCRYPTED PRIVATE KEY without password -> key/bad-input", (await codeOf(pki.key.import(encPem))) === "key/bad-input");

  // bad-input surfaces (not a CryptoKey to export; not DER/PEM to encrypt).
  check("export of a non-CryptoKey -> key/bad-input", (await codeOf(pki.key.export({}))) === "key/bad-input");
  check("encrypt of non-key bytes -> key/bad-input", (await codeOf(pki.key.encrypt(Buffer.from([1, 2, 3]), "pw"))) === "key/bad-input");
  check("decrypt of a non-EncryptedPrivateKeyInfo -> key/bad-input", (await codeOf(pki.key.decrypt(p8, "pw"))) === "key/bad-input");
}

// ---- reachable-branch edges (fail-closed corners) --------------------------
async function testEdges() {
  // A raw ASN.1 fault inside the PBES2 structural parse (the IV slot is an INTEGER, not an OCTET STRING) is
  // normalized to a typed key/bad-algorithm-parameters, never propagated as a bare Asn1Error.
  var badIvType = b.sequence([b.oid(byName("pbes2")), b.sequence([b.sequence([b.oid(byName("pbkdf2")), GOOD_PBKDF2]), b.sequence([b.oid(byName("aes256-CBC")), b.integer(5n)])])]);
  var badIvEpki = b.sequence([badIvType, b.octetString(Buffer.alloc(48, 3))]);
  check("non-OCTET-STRING IV slot -> key/bad-algorithm-parameters (raw asn1 fault normalized)", (await codeOf(pki.key.decrypt(badIvEpki, "pw"))) === "key/bad-algorithm-parameters");

  // A PBES2 AlgorithmIdentifier with NO parameters -> the shared seqChildren missing-params branch.
  var noParams = b.sequence([b.sequence([b.oid(byName("pbes2"))]), b.octetString(Buffer.alloc(48, 3))]);
  check("PBES2 with absent parameters -> key/bad-algorithm-parameters", (await codeOf(pki.key.decrypt(noParams, "pw"))) === "key/bad-algorithm-parameters");

  // export of a secret (symmetric) CryptoKey is rejected -- export is asymmetric-only.
  var secret = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  check("export of a secret CryptoKey -> key/bad-input", (await codeOf(pki.key.export(secret))) === "key/bad-input");

  // export with an unsupported output format.
  var pair = await pki.key.generate("Ed25519");
  check("export with an unsupported format -> key/bad-input", (await codeOf(pki.key.export(pair.publicKey, { format: "jwk" }))) === "key/bad-input");

  // import with an opts.algorithm that mismatches the key structure -> the WebCrypto fault propagates typed.
  var edSpki = await pki.key.export(pair.publicKey);
  var mismatchCode = await codeOf(pki.key.import(edSpki, { algorithm: { name: "RSA-PSS", hash: "SHA-256" } }));
  check("import with a mismatched opts.algorithm -> a typed PkiError propagates", typeof mismatchCode === "string" && mismatchCode.indexOf("/") !== -1);
  // A raw (non-PkiError) importKey fault -- a non-array usages -- is normalized to a typed key/bad-input.
  check("import with a non-array usages -> key/bad-input (raw fault normalized)", (await codeOf(pki.key.import(edSpki, { algorithm: { name: "Ed25519" }, usages: 42 }))) === "key/bad-input");

  // import of a structure that is neither PKCS#8, SPKI, nor EncryptedPrivateKeyInfo (a certificate).
  var certDer = makeSigner("ec-p256").cert;
  check("import of an unrecognized structure (a certificate) -> key/bad-input", (await codeOf(pki.key.import(certDer))) === "key/bad-input");
  // a bare primitive DER (no children) reaches the childless fallthrough.
  check("import of a bare primitive DER -> key/bad-input", (await codeOf(pki.key.import(b.integer(5n)))) === "key/bad-input");
  // undecodable bytes reach the asn1.decode catch inside detection.
  check("import of undecodable bytes -> key/bad-input", (await codeOf(pki.key.import(Buffer.from([0xff, 0xff])))) === "key/bad-input");
}

// ---- option defaults, generate/derive corners, usages-table arms -----------
async function testOptionsAndUsages() {
  // opts.extractable and opts.usages honored on both directions.
  var ed = await pki.key.generate("Ed25519", { extractable: false, usages: ["sign", "verify"] });
  check("generate honors opts.extractable=false", ed.privateKey.extractable === false);
  var edSpki = await pki.key.export((await pki.key.generate("Ed25519")).publicKey);
  var edImp = await pki.key.import(edSpki, { extractable: true });
  check("import honors opts.extractable=true", edImp.extractable === true);

  // generate: a symmetric algorithm succeeds but is not a key pair -> the non-pair guard.
  check("generate of a symmetric algorithm -> key/bad-input (not a key pair)", (await codeOf(pki.key.generate({ name: "AES-GCM", length: 256 }, { usages: ["encrypt", "decrypt"] }))) === "key/bad-input");
  // generate: an unknown algorithm -> the generateKey catch propagates the typed WebCrypto fault.
  var bogusCode = await codeOf(pki.key.generate("Bogus-Alg"));
  check("generate of an unknown algorithm -> a typed PkiError propagates", typeof bogusCode === "string" && bogusCode.indexOf("/") !== -1);
  // generate: a raw (non-PkiError) generateKey fault -- a non-array usages -- is normalized to key/bad-input.
  check("generate with a non-array usages -> key/bad-input (raw fault normalized)", (await codeOf(pki.key.generate("Ed25519", { usages: 42 }))) === "key/bad-input");

  // publicFromPrivate: a bad private key -> the derive catch; PEM output.
  check("publicFromPrivate of non-key bytes -> key/bad-input", (await codeOf(pki.key.publicFromPrivate(Buffer.from([1, 2, 3])))) === "key/bad-input");
  var pfpPem = await pki.key.publicFromPrivate(await pki.key.export((await pki.key.generate("Ed25519")).privateKey), { pem: true });
  check("publicFromPrivate returns PEM with opts.pem", /-----BEGIN PUBLIC KEY-----/.test(pfpPem));

  // usages-table arms: a PRIVATE X25519 (deriveBits/deriveKey) and a PRIVATE ML-KEM (decapsulateBits).
  var x = await pki.key.generate("X25519");
  check("import infers a private X25519 key", (await pki.key.import(await pki.key.export(x.privateKey))).type === "private");
  var mk = await pki.key.generate({ name: "ML-KEM-768" });
  check("import infers a private ML-KEM key", (await pki.key.import(await pki.key.export(mk.privateKey))).type === "private");

  // SLH-DSA is signing-only (unambiguous) -- import infers it, both public and private, with no opts.algorithm.
  var slh = await pki.key.generate({ name: "SLH-DSA-SHA2-128F" });
  var slhPub = await pki.key.import(await pki.key.export(slh.publicKey));
  check("import infers an SLH-DSA public key", slhPub.type === "public" && /^SLH-DSA/.test(slhPub.algorithm.name));
  var slhPriv = await pki.key.import(await pki.key.export(slh.privateKey));
  check("import infers an SLH-DSA private key", slhPriv.type === "private" && /^SLH-DSA/.test(slhPriv.algorithm.name));

  // RSA-OAEP generate + import (the encrypt/decrypt usages arms, both public and private).
  var oaep = await pki.key.generate({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var oaepPub = await pki.key.import(await pki.key.export(oaep.publicKey), { algorithm: { name: "RSA-OAEP", hash: "SHA-256" } });
  check("RSA-OAEP public import (encrypt usage)", oaepPub.type === "public");
  var oaepPriv = await pki.key.import(await pki.key.export(oaep.privateKey), { algorithm: { name: "RSA-OAEP", hash: "SHA-256" } });
  check("RSA-OAEP private import (decrypt usage)", oaepPriv.type === "private");
}

// ---- encrypt-input corners + crafted padding-oracle pair -------------------
async function testEncryptCorners() {
  var nc = require("node:crypto");
  var rsaDer = makeSigner("rsa").key;
  var pair = await pki.key.generate("Ed25519");

  // encrypt of a PUBLIC CryptoKey is rejected (a private key is required).
  check("encrypt of a public CryptoKey -> key/bad-input", (await codeOf(pki.key.encrypt(pair.publicKey, "pw"))) === "key/bad-input");
  // encrypt with an unsupported cipher.
  check("encrypt with an unsupported cipher -> key/bad-input", (await codeOf(pki.key.encrypt(rsaDer, "pw", { cipher: "des-cbc" }))) === "key/bad-input");
  // encrypt honoring an explicit iteration count and salt round-trips.
  var enc = await pki.key.encrypt(rsaDer, "pw", { iterations: 120000, salt: Buffer.alloc(16, 5) });
  check("encrypt with explicit iterations + salt round-trips", Buffer.compare(await pki.key.decrypt(enc, "pw"), rsaDer) === 0);

  // decrypt: a PBES2 encryptionScheme whose OID is not an AES cipher at all (no key size).
  var unknownScheme = pbes2Epki("pbkdf2", GOOD_PBKDF2, "rsaEncryption");
  check("decrypt with an unknown encryptionScheme OID -> key/unsupported-algorithm", (await codeOf(pki.key.decrypt(unknownScheme, "pw"))) === "key/unsupported-algorithm");

  // #8 deterministic: a crafted EncryptedPrivateKeyInfo whose plaintext is validly padded but NOT a
  // PrivateKeyInfo -- the decipher succeeds and the re-parse integrity check rejects it as decrypt-failed.
  var salt = Buffer.alloc(16, 7), iters = 2048, iv = Buffer.alloc(16, 9);
  var dk = nc.pbkdf2Sync(Buffer.from("pw", "utf8"), salt, iters, 32, "sha1");   // omitted prf -> default sha1
  var cbc = nc.createCipheriv("aes-256-cbc", dk, iv);
  var ct = Buffer.concat([cbc.update(Buffer.alloc(48, 0xee)), cbc.final()]);
  var craftAlg = b.sequence([b.oid(byName("pbes2")), b.sequence([b.sequence([b.oid(byName("pbkdf2")), b.sequence([b.octetString(salt), b.integer(BigInt(iters))])]), b.sequence([b.oid(byName("aes256-CBC")), b.octetString(iv)])])]);
  check("#8 valid-pad non-PrivateKeyInfo plaintext -> key/decrypt-failed (re-parse integrity)", (await codeOf(pki.key.decrypt(b.sequence([craftAlg, b.octetString(ct)]), "pw"))) === "key/decrypt-failed");

  // import of an SPKI naming an unregistered algorithm OID -> fail closed (cannot infer, oid unnamed).
  var bogusSpki = b.sequence([b.sequence([b.oid("1.2.3.4.5.6.7.8")]), b.bitString(Buffer.from([4, 1, 2]), 0)]);
  check("import of an unregistered-algorithm SPKI -> key/unsupported-algorithm", (await codeOf(pki.key.import(bogusSpki))) === "key/unsupported-algorithm");
}

async function main() {
  await testExportRoundTrip();
  await testPbes2RoundTrip();
  await testAlgIdParams();
  await testDecryptFailClosed();
  await testUnsupportedAlgorithms();
  await testVerbs();
  await testEdges();
  await testOptionsAndUsages();
  await testEncryptCorners();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
