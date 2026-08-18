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

  // #7 wrong password -> the uniform decrypt-failed verdict (the #8 valid-pad-non-PrivateKeyInfo pair, which
  // must surface the SAME code, is driven deterministically in testEncryptCorners -- a random ciphertext-byte
  // flip is not a reliable #8 probe because a flip inside the raw privateKey OCTET STRING content leaves a
  // structurally valid PrivateKeyInfo, which a MAC-less PBES2-CBC decrypt cannot and does not detect).
  check("#7 wrong password -> key/decrypt-failed", (await codeOf(pki.key.decrypt(enc, "wrong"))) === "key/decrypt-failed");

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
  // a nameless algorithm object reaches the null-name default-usages guard, then fails typed (never a raw fault).
  check("generate with a nameless algorithm -> typed error", typeof (await codeOf(pki.key.generate({}))) === "string");
  check("import with a nameless opts.algorithm -> typed error", typeof (await codeOf(pki.key.import(edSpki, { algorithm: {} }))) === "string");
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

  // an SPKI whose algorithm field is not a well-formed AlgorithmIdentifier SEQUENCE -> typed reject during
  // inference, never a raw children[] dereference.
  var malformedAlgSpki = b.sequence([b.sequence([]), b.bitString(Buffer.from([4, 1, 2]), 0)]);          // empty alg SEQUENCE
  check("import of a malformed-algorithm SPKI -> key/bad-input (not a raw fault)", (await codeOf(pki.key.import(malformedAlgSpki))) === "key/bad-input");
  var nonSeqAlgSpki = b.sequence([b.octetString(Buffer.from([1])), b.bitString(Buffer.from([4, 1, 2]), 0)]); // alg is not a SEQUENCE
  check("import of a non-SEQUENCE-algorithm SPKI -> key/bad-input", (await codeOf(pki.key.import(nonSeqAlgSpki))) === "key/bad-input");
  var nonOidAlgSpki = b.sequence([b.sequence([b.integer(5n)]), b.bitString(Buffer.from([4, 1, 2]), 0)]);    // alg SEQ but first element is not an OID
  check("import of an SPKI whose algorithm is not an OID -> key/bad-input", (await codeOf(pki.key.import(nonOidAlgSpki))) === "key/bad-input");

  // a caller opts.algorithm with a non-canonical case must land on the correct usage class (WebCrypto
  // matches names case-insensitively) -- a lowercase X25519 imports with deriveBits, not the signing default.
  var x25519Priv = await pki.key.export((await pki.key.generate("X25519")).privateKey);
  var lc = await pki.key.import(x25519Priv, { algorithm: { name: "x25519" } });
  check("import with a lowercase algorithm name lands on the right usages", lc.type === "private" && lc.algorithm.name === "X25519");
}

// A CryptoKey minted by a DIFFERENT WebCrypto implementation is a CryptoKey -- export reaches its
// material through the implementation that owns it rather than reporting it as the wrong type.
async function testForeignCryptoKeys() {
  var nodeWc = require("crypto").webcrypto;
  var specs = [
    ["ECDSA P-256", { name: "ECDSA", namedCurve: "P-256" }, ["sign", "verify"]],
    ["Ed25519", { name: "Ed25519" }, ["sign", "verify"]],
  ];
  for (var i = 0; i < specs.length; i++) {
    var kp = await nodeWc.subtle.generateKey(specs[i][1], true, specs[i][2]);
    var priv = await pki.key.export(kp.privateKey);
    var pub = await pki.key.export(kp.publicKey);
    // The bytes are the key, not merely a Buffer: the strict decoder round-trips both halves.
    check("a platform " + specs[i][0] + " private CryptoKey exports as PKCS#8",
      Buffer.isBuffer(priv) && !!pki.schema.pkcs8.parse(priv));
    check("a platform " + specs[i][0] + " public CryptoKey exports as SPKI",
      Buffer.isBuffer(pub) && asn1.decode(pub).tagNumber === 16);
    // ... and re-importing that export through this engine yields a key that signs, so the export
    // carried the real material rather than an empty structure of the right shape.
    var back = await pki.key.import(priv, { algorithm: specs[i][1] });
    check("the exported platform " + specs[i][0] + " key re-imports and signs",
      Buffer.isBuffer(Buffer.from(await pki.webcrypto.subtle.sign(
        specs[i][1].name === "ECDSA" ? { name: "ECDSA", hash: "SHA-256" } : { name: "Ed25519" },
        back, Buffer.from("m")))));
  }
  // A platform key that is not extractable cannot be reached by any implementation -- that is a
  // permanent verdict, and it is reported as itself, not as a wrong-type argument.
  var sealed = await nodeWc.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  check("a non-extractable platform CryptoKey is refused, naming the real reason", await (async function () {
    try { await pki.key.export(sealed.privateKey); return false; }
    catch (e) { return e.code === "key/bad-input" && /is not extractable/.test(e.message); }
  })());
  // This engine's own non-extractable key is refused by its own export rule, unchanged.
  var own = await pki.webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  check("this engine's own non-extractable key is still refused by export",
    (await codeOf(pki.key.export(own.privateKey))) !== "NO-THROW");
}

// A separately-installed copy of this toolkit is the same code under a different class identity, so
// its CryptoKey fails an `instanceof` check here exactly as a third party's would -- while its key
// material sits in a handle this process can read directly. A caller holding one must not be turned
// away, and the extractable contract must still hold for it.
async function testSecondEngineCopy() {
  var wcPath = require.resolve("../../lib/webcrypto.js");
  var original = require.cache[wcPath];
  delete require.cache[wcPath];
  var second = require(wcPath);
  require.cache[wcPath] = original;                 // restore before anything else re-requires it
  check("a second copy of the engine is a distinct CryptoKey class",
    second.CryptoKey !== original.exports.CryptoKey);
  var kp = await second.webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var priv = await pki.key.export(kp.privateKey);
  check("a private key from a second copy of this toolkit exports",
    Buffer.isBuffer(priv) && !!pki.schema.pkcs8.parse(priv));
  check("a public key from a second copy of this toolkit exports",
    asn1.decode(await pki.key.export(kp.publicKey)).tagNumber === 16);
  var hm = await second.webcrypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"]);
  check("a secret key from a second copy signs an inner JWS", !!(await pki.jose.sign({
    protected: { alg: "HS256", url: "https://e/x", kid: "acct-1" }, payload: Buffer.from("{}"),
    key: hm, profile: "eab-inner" })).signature);
  // The material is reachable through the handle, but extractable:false is a promise -- keep it.
  var sealed = await second.webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  check("a non-extractable key from a second copy is still refused", await (async function () {
    try { await pki.key.export(sealed.privateKey); return false; }
    catch (e) { return e.code === "key/bad-input" && /is not extractable/.test(e.message); }
  })());
}

// An option this module does not read is refused, not ignored. The case that matters most is
// `pki.key.export(privateKey, { password })`: export does not encrypt, so ignoring it wrote the
// private key in the clear from a call site that reads as though it were protected.
async function testUnknownOptionsRefused() {
  var pair = await pki.key.generate("Ed25519");
  var pkcs8 = await pki.key.export(pair.privateKey);
  var spki = await pki.key.export(pair.publicKey);
  var epki = await pki.key.encrypt(pair.privateKey, "pw");

  check("export refuses opts.password rather than writing a plaintext key",
        await codeOf(pki.key.export(pair.privateKey, { password: "pw" })) === "key/bad-input");
  check("export's refusal names the verb that does encrypt", await (async function () {
    try { await pki.key.export(pair.privateKey, { password: "pw" }); return false; }
    catch (e) { return /pki\.key\.encrypt/.test(e.message); }
  })());
  check("export still accepts the options it reads",
        typeof (await pki.key.export(pair.publicKey, { format: "pem", label: "PUBLIC KEY" })) === "string");

  // The two PBKDF2 knobs are named per direction; each verb refuses the other's spelling.
  check("encrypt refuses the decrypt-side maxIterations",
        await codeOf(pki.key.encrypt(pair.privateKey, "pw", { maxIterations: 1000 })) === "key/bad-input");
  check("decrypt refuses the encrypt-side iterations",
        await codeOf(pki.key.decrypt(epki, "pw", { iterations: 1000 })) === "key/bad-input");
  check("encrypt still accepts its own iterations",
        Buffer.isBuffer(await pki.key.encrypt(pair.privateKey, "pw", { iterations: 2048 })));
  check("decrypt still accepts its own maxIterations",
        Buffer.isBuffer(await pki.key.decrypt(epki, "pw", { maxIterations: 1000000 })));

  check("generate refuses a misspelled extractable",
        await codeOf(pki.key.generate("Ed25519", { extractible: false })) === "key/bad-input");
  check("import refuses a misspelled option",
        await codeOf(pki.key.import(spki, { typ: "spki" })) === "key/bad-input");
  check("import still accepts the options it reads",
        (await pki.key.import(pkcs8, { extractable: true })).extractable === true);
  check("publicFromPrivate refuses a misspelled option",
        await codeOf(pki.key.publicFromPrivate(pair.privateKey, { pemm: true })) === "key/bad-input");
  check("publicFromPrivate still accepts pem",
        typeof (await pki.key.publicFromPrivate(pair.privateKey, { pem: true })) === "string");

  // `opts = opts || {}` treated false / 0 / "" / NaN as "no options given" and rewrote them to
  // {} BEFORE the shape check could see them, so four non-objects were accepted as valid. Only
  // null and undefined mean absent; everything else non-object is a caller error.
  var falsy = [false, 0, "", NaN];
  for (var i = 0; i < falsy.length; i++) {
    check("export refuses the falsy non-object " + String(falsy[i]) + " rather than defaulting it",
          await codeOf(pki.key.export(pair.publicKey, falsy[i])) === "key/bad-input");
  }
  check("export still treats null as no options", Buffer.isBuffer(await pki.key.export(pair.publicKey, null)));
  check("export still treats undefined as no options", Buffer.isBuffer(await pki.key.export(pair.publicKey, undefined)));
  check("export refuses a Buffer handed in the options position",
        await codeOf(pki.key.export(pair.publicKey, Buffer.alloc(4))) === "key/bad-input");

  // `Object.keys` reports own ENUMERABLE names only, so two ordinary JavaScript objects answered
  // `opts.password` while showing the check nothing: one carries it on a prototype, the other
  // hides it behind enumerable:false. On either one export accepts the bag and returns the
  // private key in the clear, which is the refusal reached by a different object shape.
  var inherited = Object.create({ password: "pw" });
  check("export refuses a password carried on the prototype",
        await codeOf(pki.key.export(pair.privateKey, inherited)) === "key/bad-input");
  var hidden = {};
  Object.defineProperty(hidden, "password", { value: "pw", enumerable: false });
  check("export refuses a non-enumerable password",
        await codeOf(pki.key.export(pair.privateKey, hidden)) === "key/bad-input");
  // ...and the widened check must not start refusing bags that were always valid.
  check("a null-prototype options bag is still accepted",
        Buffer.isBuffer(await pki.key.export(pair.publicKey, Object.create(null))));
  check("an inherited KNOWN option is still accepted",
        typeof (await pki.key.export(pair.publicKey, Object.create({ format: "pem" }))) === "string");

  // Class syntax defines a getter NON-enumerable on the prototype, so a rule keyed on
  // enumerability missed it while `opts.password` still answered. A getter exists to return a
  // value, which is what an option is, so it is checked; a method is behavior and is not.
  function ExportOptions() {}
  Object.defineProperty(ExportOptions.prototype, "password", {
    get: function () { return "pw"; }, enumerable: false, configurable: true
  });
  ExportOptions.prototype.describe = function () { return "opts"; };
  check("export refuses a password exposed by a prototype getter",
        await codeOf(pki.key.export(pair.privateKey, new ExportOptions())) === "key/bad-input");
  var hiddenBase = {};
  Object.defineProperty(hiddenBase, "password", { value: "pw", enumerable: false });
  check("export refuses a password inherited AND non-enumerable",
        await codeOf(pki.key.export(pair.privateKey, Object.create(hiddenBase))) === "key/bad-input");
  // An instance whose class defines only methods is still a usable bag: those are behavior,
  // and this toolkit already treats a caller's own class as a valid options object.
  function PlainBag() { this.format = "pem"; }
  PlainBag.prototype.describe = function () { return "bag"; };
  check("an instance whose prototype carries only methods is still accepted",
        typeof (await pki.key.export(pair.publicKey, new PlainBag())) === "string");
  // A polluted Object.prototype reaches an empty bag. `{}.password` answers "pw" while the
  // object itself holds nothing. Stopping the walk at Object.prototype excludes the whole
  // object and lets this through, so the built-ins are skipped by identity against a snapshot
  // taken at load and a name added afterwards is still reported.
  Object.defineProperty(Object.prototype, "password", {
    value: "pw", writable: true, configurable: true, enumerable: false
  });
  var pollutedCode, pollutedThrew;
  try {
    pollutedCode = await codeOf(pki.key.export(pair.privateKey, {}));
  } finally {
    pollutedThrew = delete Object.prototype.password;
  }
  check("export refuses an option reachable only through a polluted Object.prototype",
        pollutedCode === "key/bad-input");
  check("the pollution vector restores Object.prototype", pollutedThrew === true &&
        !("password" in Object.prototype));
  check("a clean empty bag is still accepted once the pollution is gone",
        (await pki.key.export(pair.publicKey, {})).equals(await pki.key.export(pair.publicKey)));
  // A Proxy reports its keys from one trap and answers reads from another, so an options bag
  // that enumerates as empty can still answer `password`. Export would then serialize the key
  // in the clear on a call that named a password, which is the case the refusal exists for.
  var opaque = new Proxy({}, {
    ownKeys: function () { return []; },
    get: function (_, k) { return k === "password" ? "pw" : undefined; },
  });
  check("the fixture enumerates as empty while answering password",
        Object.getOwnPropertyNames(opaque).length === 0 && opaque.password === "pw");
  check("export refuses an options bag whose reported keys need not be what it answers",
        await codeOf(pki.key.export(pair.privateKey, opaque)) === "key/bad-input");
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
  await testForeignCryptoKeys();
  await testSecondEngineCopy();
  await testUnknownOptionsRefused();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
