// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for pki.kem -- composite ML-KEM encapsulate / decapsulate
// (draft-ietf-lamps-pq-composite-kem). Oracle: the draft Appendix G official test
// vectors (test/fixtures/composite-kem/kat.json). The deterministic known-answer
// test is DECAPSULATION: decapsulate(dk_pkcs8, c) yields k. Encapsulation is
// randomized, so it is exercised by an encapsulate -> decapsulate round-trip whose
// two shared secrets must agree.

var fs = require("fs");
var path = require("path");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

var KAT = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "composite-kem", "kat.json"), "utf8"));

function b64(s) { return Buffer.from(s, "base64"); }
async function codeOf(p) { try { await p; return null; } catch (e) { return e && e.code; } }
// A composite SubjectPublicKeyInfo: AlgorithmIdentifier { composite OID } (parameters absent)
// + subjectPublicKey BIT STRING = the raw serialized public key (draft sec. 5.1).
function spkiFrom(tcId, ek) {
  return pki.asn1.build.sequence([
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName(tcId))]),
    pki.asn1.build.bitString(ek, 0),
  ]);
}

async function run() {
  var composites = KAT.tests.filter(function (t) { return t.tcId.indexOf("id-alg-ml-kem") !== 0; });

  // 1. Appendix G decapsulation KAT (all 12 rows): decapsulate(dk_pkcs8, c) === k.
  for (var i = 0; i < composites.length; i++) {
    var t = composites[i];
    var ss = await pki.kem.decapsulate(b64(t.dk_pkcs8), b64(t.c));
    check("decaps KAT " + t.tcId + " (ss == k)", Buffer.from(ss).length === 32 && Buffer.from(ss).equals(b64(t.k)));
  }

  // 2. encapsulate -> decapsulate round-trip (encapsulation is randomized; the secrets must agree).
  for (var j = 0; j < composites.length; j++) {
    var r = composites[j];
    var enc = await pki.kem.encapsulate(spkiFrom(r.tcId, b64(r.ek)));
    var dec = await pki.kem.decapsulate(b64(r.dk_pkcs8), Buffer.from(enc.ciphertext));
    check("round-trip " + r.tcId + " (enc.ss == dec.ss, 32 bytes)",
      Buffer.from(enc.sharedSecret).length === 32 && Buffer.from(dec).equals(Buffer.from(enc.sharedSecret)));
  }

  // 2b. X.509 recognition: a composite ML-KEM public key parses in a certificate (each vector's x5c),
  // and that certificate's SubjectPublicKeyInfo feeds pki.kem.encapsulate directly -- one row per
  // traditional component kind (RSA, ECDH, X25519).
  var certRows = ["id-MLKEM768-RSA2048-SHA3-256", "id-MLKEM768-ECDH-P256-SHA3-256", "id-MLKEM768-X25519-SHA3-256"];
  for (var c = 0; c < certRows.length; c++) {
    var cv = composites.find(function (t) { return t.tcId === certRows[c]; });
    var cert = pki.schema.x509.parse(b64(cv.x5c));
    var certEnc = await pki.kem.encapsulate(cert.subjectPublicKeyInfo.bytes);
    check("X.509 cert with a " + cv.tcId + " key encapsulates",
      Buffer.from(certEnc.sharedSecret).length === 32 && cert.subjectPublicKeyInfo.algorithm.oid === pki.oid.byName(cv.tcId));
  }

  // 3. structural guards on a representative row.
  var x = composites.find(function (t) { return t.tcId === "id-MLKEM768-X25519-SHA3-256"; });
  // a ciphertext shorter than the fixed ML-KEM component is refused.
  check("truncated ciphertext refused",
    (await codeOf(pki.kem.decapsulate(b64(x.dk_pkcs8), b64(x.c).subarray(0, 1000)))) === "kem/bad-ciphertext");
  // a composite SPKI whose AlgorithmIdentifier carries parameters is refused (draft sec. 5.3).
  var badParams = pki.asn1.build.sequence([
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName(x.tcId)), pki.asn1.build.nullValue()]),
    pki.asn1.build.bitString(b64(x.ek), 0),
  ]);
  check("SPKI with algorithm parameters refused",
    (await codeOf(pki.kem.encapsulate(badParams))) === "kem/bad-algorithm");
  // a non-composite-KEM OID is refused as unsupported.
  var notKem = spkiFrom("id-ml-kem-768", b64(x.ek));
  check("non-composite-KEM OID refused",
    (await codeOf(pki.kem.encapsulate(notKem))) === "kem/unsupported-algorithm");

  // 4. adversarial / branch coverage.
  var B = pki.asn1.build;
  var rsa = composites.find(function (t) { return t.tcId === "id-MLKEM768-RSA2048-SHA3-256"; });
  function pkcs8(tcId, sk) {
    return B.sequence([B.integer(0n), B.sequence([B.oid(pki.oid.byName(tcId))]), B.octetString(sk)]);
  }
  // a mangled RSA-OAEP ciphertext (a flipped byte in the traditional half) surfaces a typed
  // decapsulation failure, never a silent wrong secret (explicit rejection, draft sec. 3.5).
  var badRsaCt = Buffer.from(b64(rsa.c)); badRsaCt[badRsaCt.length - 1] ^= 0x01;
  check("mangled RSA-OAEP ciphertext -> kem/decapsulation-failed",
    (await codeOf(pki.kem.decapsulate(b64(rsa.dk_pkcs8), badRsaCt))) === "kem/decapsulation-failed");
  // a mangled DHKEM ciphertext does not recover the original secret: X25519 is non-validating, so a
  // flipped point yields a different shared secret (or, for a degenerate point, a typed error) -- never
  // the original secret k.
  var badEcCt = Buffer.from(b64(x.c)); badEcCt[badEcCt.length - 1] ^= 0x01;
  var mangled;
  try { mangled = { ss: Buffer.from(await pki.kem.decapsulate(b64(x.dk_pkcs8), badEcCt)) }; }
  catch (e) { mangled = { code: e && e.code }; }
  check("mangled X25519 ciphertext does not recover the original secret",
    mangled.code ? /^kem\//.test(mangled.code) : !mangled.ss.equals(b64(x.k)));
  // an RSA component whose modulus does not match the composite OID (an RSA2048 key under the RSA3072
  // arm) is refused before use (draft sec. 6 fixes the modulus per algorithm). The ciphertext is padded
  // to the RSA3072 arm's exact length (ML-KEM-768 ct 1088 + 384-byte RSA-3072 block) so the check reached
  // is the modulus mismatch, not the length.
  var rsa3072LenCt = Buffer.concat([b64(rsa.c).subarray(0, 1088), Buffer.alloc(384, 0)]);
  check("RSA modulus mismatch refused",
    (await codeOf(pki.kem.decapsulate(pkcs8("id-MLKEM768-RSA3072-SHA3-256", b64(rsa.dk)), rsa3072LenCt))) === "kem/bad-key");
  // a private key shorter than the fixed ML-KEM seed is refused.
  check("private key shorter than the ML-KEM seed refused",
    (await codeOf(pki.kem.decapsulate(pkcs8(x.tcId, b64(x.dk).subarray(0, 64)), b64(x.c)))) === "kem/bad-key");
  // a composite PKCS#8 whose AlgorithmIdentifier carries parameters is refused (draft sec. 5.3).
  var p8Params = B.sequence([B.integer(0n), B.sequence([B.oid(pki.oid.byName(x.tcId)), B.nullValue()]), B.octetString(b64(x.dk))]);
  check("PKCS#8 with algorithm parameters refused",
    (await codeOf(pki.kem.decapsulate(p8Params, b64(x.c)))) === "kem/bad-algorithm");
  // a non-composite OID in the PKCS#8 is unsupported.
  check("non-composite OID PKCS#8 refused",
    (await codeOf(pki.kem.decapsulate(pkcs8("id-ml-kem-768", b64(x.dk)), b64(x.c)))) === "kem/unsupported-algorithm");
  // an SPKI whose subjectPublicKey BIT STRING has unused bits is refused.
  var unusedSpki = B.sequence([B.sequence([B.oid(pki.oid.byName(x.tcId))]), B.bitString(b64(x.ek), 3)]);
  check("SPKI with unused bits refused",
    (await codeOf(pki.kem.encapsulate(unusedSpki))) === "kem/bad-key");
  // input that is not valid DER is refused as a bad key, never an uncaught throw.
  check("non-DER private key refused",
    (await codeOf(pki.kem.decapsulate(Buffer.from([1, 2, 3]), b64(x.c)))) === "kem/bad-key");
  // the verbs snapshot their BufferSource arguments at the door: mutating the caller's ciphertext
  // buffer after the call has begun does not change the recovered secret.
  var live = Buffer.from(b64(x.c));
  var pending = pki.kem.decapsulate(b64(x.dk_pkcs8), live);
  live.fill(0xff);
  check("ciphertext is snapshotted at the door (post-call mutation is inert)",
    Buffer.from(await pending).equals(b64(x.k)));

  // 5. remaining error branches (malformed component key material, degenerate DH, and every
  // structural refusal in the composite key / ciphertext / AlgorithmIdentifier decoders).
  var ec = composites.find(function (t) { return t.tcId === "id-MLKEM768-ECDH-P256-SHA3-256"; });
  // an EC composite whose traditional private key is not a valid ECPrivateKey is refused.
  check("malformed EC component private key refused",
    (await codeOf(pki.kem.decapsulate(pkcs8(ec.tcId, Buffer.concat([b64(ec.dk).subarray(0, 64), Buffer.alloc(50, 0xff)])), b64(ec.c)))) === "kem/bad-key");
  // an X25519 ciphertext whose ephemeral point is all-zero yields an all-zero (degenerate) shared
  // secret, which node's Diffie-Hellman rejects -> a typed decapsulation failure.
  var lowCt = Buffer.concat([b64(x.c).subarray(0, 1088), Buffer.alloc(32, 0)]);
  check("degenerate (all-zero) X25519 ephemeral point -> kem/decapsulation-failed",
    (await codeOf(pki.kem.decapsulate(b64(x.dk_pkcs8), lowCt))) === "kem/decapsulation-failed");
  // an unregistered OID surfaces as unsupported, named by its dotted form.
  var unknownP8 = B.sequence([B.integer(0n), B.sequence([B.oid("1.3.6.1.4.1.99999.1")]), B.octetString(b64(x.dk))]);
  check("unregistered OID refused as unsupported",
    (await codeOf(pki.kem.decapsulate(unknownP8, b64(x.c)))) === "kem/unsupported-algorithm");
  // a structurally malformed AlgorithmIdentifier inside the PKCS#8 -- an empty SEQUENCE, or a first
  // element that is not an OID -- is rejected by the shared OneAsymmetricKey parser as a malformed key.
  var emptyAlg = B.sequence([B.integer(0n), B.sequence([]), B.octetString(b64(x.dk))]);
  check("empty AlgorithmIdentifier refused",
    (await codeOf(pki.kem.decapsulate(emptyAlg, b64(x.c)))) === "kem/bad-key");
  var nonOidAlg = B.sequence([B.integer(0n), B.sequence([B.integer(5n)]), B.octetString(b64(x.dk))]);
  check("non-OID AlgorithmIdentifier algorithm refused",
    (await codeOf(pki.kem.decapsulate(nonOidAlg, b64(x.c)))) === "kem/bad-key");
  // a PKCS#8 with fewer than three elements, and an SPKI with fewer than two, are refused.
  var shortP8 = B.sequence([B.integer(0n), B.sequence([B.oid(pki.oid.byName(x.tcId))])]);
  check("PKCS#8 with fewer than three elements refused",
    (await codeOf(pki.kem.decapsulate(shortP8, b64(x.c)))) === "kem/bad-key");
  var shortSpki = B.sequence([B.sequence([B.oid(pki.oid.byName(x.tcId))])]);
  check("SPKI with fewer than two elements refused",
    (await codeOf(pki.kem.encapsulate(shortSpki))) === "kem/bad-key");
  // a non-DER public key, and an SPKI whose public key is shorter than the ML-KEM component.
  check("non-DER public key refused",
    (await codeOf(pki.kem.encapsulate(Buffer.from([1, 2, 3])))) === "kem/bad-key");
  var shortEkSpki = B.sequence([B.sequence([B.oid(pki.oid.byName(x.tcId))]), B.bitString(Buffer.alloc(100), 0)]);
  check("SPKI public key shorter than the ML-KEM component refused",
    (await codeOf(pki.kem.encapsulate(shortEkSpki))) === "kem/bad-key");
  // a SubjectPublicKeyInfo carries exactly two elements; a trailing element after the BIT STRING is a
  // non-canonical shape and is refused rather than silently ignored.
  var extraSpki = B.sequence([B.sequence([B.oid(pki.oid.byName(x.tcId))]), B.bitString(b64(x.ek), 0), B.integer(0n)]);
  check("SPKI with a trailing element after the BIT STRING refused",
    (await codeOf(pki.kem.encapsulate(extraSpki))) === "kem/bad-key");
  // a SubjectPublicKeyInfo whose AlgorithmIdentifier is an empty SEQUENCE, or whose algorithm is not an
  // OBJECT IDENTIFIER, is refused as a bad algorithm.
  var emptyAlgSpki = B.sequence([B.sequence([]), B.bitString(b64(x.ek), 0)]);
  check("SPKI with an empty AlgorithmIdentifier refused",
    (await codeOf(pki.kem.encapsulate(emptyAlgSpki))) === "kem/bad-algorithm");
  var nonOidAlgSpki = B.sequence([B.sequence([B.integer(5n)]), B.bitString(b64(x.ek), 0)]);
  check("SPKI with a non-OID algorithm refused",
    (await codeOf(pki.kem.encapsulate(nonOidAlgSpki))) === "kem/bad-algorithm");
  // a SubjectPublicKeyInfo and its AlgorithmIdentifier are SEQUENCEs; a SET carrying the same children is
  // a non-canonical encoding and is refused rather than accepted for its shape.
  var setSpki = B.set([B.sequence([B.oid(pki.oid.byName(x.tcId))]), B.bitString(b64(x.ek), 0)]);
  check("SPKI encoded as a SET refused",
    (await codeOf(pki.kem.encapsulate(setSpki))) === "kem/bad-key");
  var setAlgSpki = B.sequence([B.set([B.oid(pki.oid.byName(x.tcId))]), B.bitString(b64(x.ek), 0)]);
  check("SPKI whose AlgorithmIdentifier is a SET refused",
    (await codeOf(pki.kem.encapsulate(setAlgSpki))) === "kem/bad-algorithm");
  // a OneAsymmetricKey carries at most five elements (version, algorithm, privateKey, optional [0]
  // attributes, optional [1] publicKey); a sixth element is refused.
  var longP8 = B.sequence([B.integer(0n), B.sequence([B.oid(pki.oid.byName(x.tcId))]), B.octetString(b64(x.dk)),
    B.integer(1n), B.integer(2n), B.integer(3n)]);
  check("PKCS#8 with more than five elements refused",
    (await codeOf(pki.kem.decapsulate(longP8, b64(x.c)))) === "kem/bad-key");
  // the OneAsymmetricKey version field is validated: a version that is not an INTEGER is refused rather
  // than read past positionally.
  var badVerP8 = B.sequence([B.octetString(Buffer.from([1, 2])), B.sequence([B.oid(pki.oid.byName(x.tcId))]), B.octetString(b64(x.dk))]);
  check("PKCS#8 with a non-INTEGER version refused",
    (await codeOf(pki.kem.decapsulate(badVerP8, b64(x.c)))) === "kem/bad-key");
  // a fourth element within the 3..5 range that is not the [0] attributes context tag is refused: the
  // optional trailing fields are validated, not merely counted.
  var badTrailP8 = B.sequence([B.integer(0n), B.sequence([B.oid(pki.oid.byName(x.tcId))]), B.octetString(b64(x.dk)), B.integer(9n)]);
  check("PKCS#8 with a mistyped trailing element refused",
    (await codeOf(pki.kem.decapsulate(badTrailP8, b64(x.c)))) === "kem/bad-key");

  // 6. encapsulate error branches (a malformed or wrong-size traditional public key half).
  var rsa3072 = composites.find(function (t) { return t.tcId === "id-MLKEM1024-RSA3072-SHA3-256"; });
  function ekWith(mlkemEk, tradPk) { return Buffer.concat([mlkemEk, tradPk]); }
  // a malformed RSA public key half (valid ML-KEM prefix, garbage RSA tradPK) is refused.
  check("encapsulate: malformed RSA public key half refused",
    (await codeOf(pki.kem.encapsulate(spkiFrom(rsa.tcId, ekWith(b64(rsa.ek).subarray(0, 1184), Buffer.alloc(100, 0xff)))))) === "kem/bad-key");
  // an RSA public key whose modulus does not match the composite OID (a 3072-bit key under the RSA2048
  // arm) is refused before encapsulation.
  check("encapsulate: RSA modulus mismatch refused",
    (await codeOf(pki.kem.encapsulate(spkiFrom(rsa.tcId, ekWith(b64(rsa.ek).subarray(0, 1184), b64(rsa3072.ek).subarray(1568)))))) === "kem/bad-key");
  // a malformed EC public point half is refused.
  check("encapsulate: malformed EC public point half refused",
    (await codeOf(pki.kem.encapsulate(spkiFrom(ec.tcId, ekWith(b64(ec.ek).subarray(0, 1184), Buffer.alloc(65, 0xff)))))) === "kem/bad-key");
  // the draft requires the uncompressed X9.62 point; a valid compressed P-256 point (which node would
  // otherwise decompress) is refused as non-canonical, in both the recipient key and the ephemeral ciphertext.
  var compressedP256 = Buffer.from("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "hex");
  check("encapsulate: a compressed EC recipient point refused",
    (await codeOf(pki.kem.encapsulate(spkiFrom(ec.tcId, ekWith(b64(ec.ek).subarray(0, 1184), compressedP256))))) === "kem/bad-key");
  var ecMlkemCt = b64(ec.c).subarray(0, b64(ec.c).length - 65);   // strip the 65-byte uncompressed ephemeral
  // a compressed ephemeral point (33 bytes rather than the 65-byte uncompressed form) makes the composite
  // ciphertext the wrong length, so the exact length check refuses it as a bad ciphertext.
  check("decapsulate: a compressed EC ephemeral ciphertext point refused",
    (await codeOf(pki.kem.decapsulate(b64(ec.dk_pkcs8), Buffer.concat([ecMlkemCt, compressedP256])))) === "kem/bad-ciphertext");
  // an oversized traditional ciphertext component is refused by the exact length check before any key is
  // built, so a large attacker-controlled component cannot force an unbounded allocation (CWE-770).
  check("decapsulate: an oversized DH ciphertext component is refused before key construction",
    (await codeOf(pki.kem.decapsulate(b64(ec.dk_pkcs8), Buffer.concat([ecMlkemCt, Buffer.alloc(200000, 0x04)])))) === "kem/bad-ciphertext");
  // a malformed ML-KEM public-key half (with a valid traditional half) is refused as a typed error --
  // the ML-KEM component fails while the traditional one succeeds, and its secret is wiped (sec. 3.5).
  check("encapsulate: malformed ML-KEM public key half refused (traditional half succeeds)",
    (await codeOf(pki.kem.encapsulate(spkiFrom(x.tcId, ekWith(Buffer.alloc(1184, 0xff), b64(x.ek).subarray(1184)))))) === "kem/bad-key");
  // a composite RSA private key whose traditional half is not a valid RSAPrivateKey is refused.
  check("decapsulate: malformed RSA private key half refused",
    (await codeOf(pki.kem.decapsulate(pkcs8(rsa.tcId, Buffer.concat([b64(rsa.dk).subarray(0, 64), Buffer.alloc(100, 0xff)])), b64(rsa.c)))) === "kem/bad-key");
  // node's RSA key readers ignore trailing bytes after the RSAPublicKey / RSAPrivateKey; a composite key
  // carrying extra bytes after the RSA component must still be refused (draft sec. 4.1 / 4.2, exact encoding).
  check("encapsulate: trailing bytes after the RSA public component refused",
    (await codeOf(pki.kem.encapsulate(spkiFrom(rsa.tcId, ekWith(b64(rsa.ek).subarray(0, 1184), Buffer.concat([b64(rsa.ek).subarray(1184), Buffer.from([0, 0, 0])])))))) === "kem/bad-key");
  check("decapsulate: trailing bytes after the RSA private component refused",
    (await codeOf(pki.kem.decapsulate(pkcs8(rsa.tcId, Buffer.concat([b64(rsa.dk), Buffer.from([0, 0, 0])])), b64(rsa.c)))) === "kem/bad-key");
  // node's SEC1 reader likewise ignores trailing bytes after an ECPrivateKey; the EC composite private
  // component is decoded strictly, so extra bytes after it are refused.
  check("decapsulate: trailing bytes after the EC private component refused",
    (await codeOf(pki.kem.decapsulate(pkcs8(ec.tcId, Buffer.concat([b64(ec.dk), Buffer.from([0, 0, 0])])), b64(ec.c)))) === "kem/bad-key");
  // the RSA-OAEP ciphertext component is exactly one modulus block; a composite ciphertext whose
  // traditional half is a different length is a bad ciphertext, named as such rather than a decrypt failure.
  check("decapsulate: RSA ciphertext component of the wrong length refused",
    (await codeOf(pki.kem.decapsulate(b64(rsa.dk_pkcs8), Buffer.concat([b64(rsa.c), Buffer.from([0, 0, 0])])))) === "kem/bad-ciphertext");
  // draft sec. 2.1 fixes the RSA-OAEP-transported secret at 32 bytes. A ciphertext that OAEP-decrypts to
  // a different length under the recipient's key is non-conforming and is refused, never mixed into the
  // combiner: encrypt a 16-byte plaintext to the recipient RSA key and splice it onto the real ML-KEM half.
  var nodeCrypto = require("crypto");
  var rsaPub = nodeCrypto.createPublicKey({ key: b64(rsa.ek).subarray(1184), format: "der", type: "pkcs1" });
  var rsaCtLen = rsaPub.asymmetricKeyDetails.modulusLength / 8;
  var shortPtCt = nodeCrypto.publicEncrypt({ key: rsaPub, padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, Buffer.alloc(16, 0xab));
  var shortPtComposite = Buffer.concat([b64(rsa.c).subarray(0, b64(rsa.c).length - rsaCtLen), shortPtCt]);
  check("decapsulate: RSA-OAEP secret that is not 32 bytes refused",
    (await codeOf(pki.kem.decapsulate(b64(rsa.dk_pkcs8), shortPtComposite))) === "kem/decapsulation-failed");
  // the wrong-length plaintext and an OAEP-invalid ciphertext MUST fail indistinguishably (identical code
  // AND message): a distinct verdict for either would be an RSA-OAEP padding-validity oracle (Manger).
  // the fingerprint includes the cause: attaching the OpenSSL error to one path but not the other would
  // itself distinguish the two failures, so it must be absent (or identical) on both.
  async function errTextOf(p) { try { await p; return null; } catch (e) { return e && (e.code + "|" + e.message + "|" + (e.cause ? "cause" : "no-cause")); } }
  var badPadCt = Buffer.from(b64(rsa.c)); badPadCt[badPadCt.length - 1] ^= 0x01;
  check("decapsulate: wrong-length and OAEP-invalid RSA ciphertexts fail indistinguishably",
    (await errTextOf(pki.kem.decapsulate(b64(rsa.dk_pkcs8), shortPtComposite))) ===
    (await errTextOf(pki.kem.decapsulate(b64(rsa.dk_pkcs8), badPadCt))));
  // draft sec. 3.5: the rejected non-32-byte plaintext is itself key material and is wiped before the
  // rejection. Alias the decrypted plaintext into an ArrayBuffer (Buffer.from(ArrayBuffer) shares memory
  // with the module's ss buffer) and confirm it is all-zero after the reject.
  var nodeCryptoMod = require("node:crypto");
  var origPrivDec = nodeCryptoMod.privateDecrypt;
  var ptAb = null;
  nodeCryptoMod.privateDecrypt = function () {
    var pt = origPrivDec.apply(this, arguments);
    if (ptAb === null && pt.length !== 32) {   // the non-conforming 16-byte plaintext
      ptAb = pt.buffer.slice(pt.byteOffset, pt.byteOffset + pt.byteLength);
      return ptAb;
    }
    return pt;
  };
  try {
    await codeOf(pki.kem.decapsulate(b64(rsa.dk_pkcs8), shortPtComposite));
  } finally { nodeCryptoMod.privateDecrypt = origPrivDec; }
  var ptObserved = ptAb === null ? null : Buffer.from(ptAb);
  check("decapsulate: the rejected RSA-OAEP plaintext is wiped (draft sec. 3.5)",
    ptObserved !== null && ptObserved.length === 16 && ptObserved.every(function (byte) { return byte === 0; }));

  // 7. a low-order recipient point during ENCAPSULATION surfaces a typed error, not a raw Diffie-Hellman
  // throw (the decapsulation path already refuses one; the encapsulation path must too).
  var lowEk = Buffer.concat([b64(x.ek).subarray(0, 1184), Buffer.alloc(32, 0)]);
  check("encapsulate: low-order X25519 recipient point -> kem/bad-key",
    (await codeOf(pki.kem.encapsulate(spkiFrom(x.tcId, lowEk)))) === "kem/bad-key");

  // 8. both verbs accept a PEM block as well as DER.
  function toPem(der, label) { return "-----BEGIN " + label + "-----\n" + der.toString("base64") + "\n-----END " + label + "-----\n"; }
  check("decapsulate accepts a PRIVATE KEY PEM (== k)",
    Buffer.from(await pki.kem.decapsulate(toPem(b64(x.dk_pkcs8), "PRIVATE KEY"), b64(x.c))).equals(b64(x.k)));
  var pemEnc = await pki.kem.encapsulate(toPem(spkiFrom(x.tcId, b64(x.ek)), "PUBLIC KEY"));
  check("encapsulate accepts a PUBLIC KEY PEM", Buffer.from(pemEnc.sharedSecret).length === 32);
  check("a PEM block with the wrong label is refused",
    (await codeOf(pki.kem.decapsulate(toPem(b64(x.dk_pkcs8), "PUBLIC KEY"), b64(x.c)))) === "kem/bad-key");
  // a PEM block supplied as a Buffer (not a string) is also accepted.
  check("decapsulate accepts a PRIVATE KEY PEM supplied as a Buffer",
    Buffer.from(await pki.kem.decapsulate(Buffer.from(toPem(b64(x.dk_pkcs8), "PRIVATE KEY"), "utf8"), b64(x.c))).equals(b64(x.k)));
  // a PEM Buffer with leading text before "-----BEGIN" is recognized, matching the rest of the toolkit
  // (RFC 7468 permits leading text), rather than being mistaken for DER. The encapsulation path decodes
  // the SPKI directly, so it is where _toDer's own PEM detection is exercised.
  var leadingPemPub = Buffer.from("leading comment\n\n" + toPem(spkiFrom(x.tcId, b64(x.ek)), "PUBLIC KEY"), "utf8");
  check("encapsulate accepts a PEM Buffer with leading text",
    (await codeOf(pki.kem.encapsulate(leadingPemPub))) === null);

  // 9. draft sec. 3.5: on a component-failure path the shared secret the OTHER component already
  // produced must be wiped, not left readable. Capture the ML-KEM shared-secret buffer via a hook on
  // decapsulateBits, force the traditional half to fail (a mangled RSA-OAEP ciphertext, which rejects
  // AFTER the ML-KEM half has resolved), and confirm the captured secret is all-zero afterward.
  var subtle = require("../../lib/webcrypto").webcrypto.subtle;
  var origDecap = subtle.decapsulateBits;
  var capturedSS = null;
  subtle.decapsulateBits = function () { return origDecap.apply(this, arguments).then(function (ab) { capturedSS = Buffer.from(ab); return ab; }); };
  try {
    var wipeCt = Buffer.from(b64(rsa.c)); wipeCt[wipeCt.length - 1] ^= 0x01;
    await codeOf(pki.kem.decapsulate(b64(rsa.dk_pkcs8), wipeCt));
  } finally { subtle.decapsulateBits = origDecap; }
  check("draft sec. 3.5: the ML-KEM secret is wiped when the traditional component fails",
    capturedSS !== null && capturedSS.length === 32 && capturedSS.every(function (byte) { return byte === 0; }));

  // draft sec. 3.5 binds the combiner too: if the SHA3-256 digest fails after both components resolve, the
  // intermediate secrets must still be wiped. Capture the ML-KEM secret as a view over the shared
  // decapsulateBits ArrayBuffer, force the SHA3-256 digest to reject, and confirm it is all-zero after.
  var origDigest = subtle.digest;
  var capComb = null;
  subtle.decapsulateBits = function () { return origDecap.apply(this, arguments).then(function (ab) { capComb = Buffer.from(ab); return ab; }); };
  subtle.digest = function (algo) {
    var name = typeof algo === "string" ? algo : (algo && algo.name);
    if (name === "SHA3-256") return Promise.reject(new Error("forced digest failure"));
    return origDigest.apply(this, arguments);
  };
  try {
    await codeOf(pki.kem.decapsulate(b64(x.dk_pkcs8), b64(x.c)));   // both halves resolve, the combiner digest fails
  } finally { subtle.decapsulateBits = origDecap; subtle.digest = origDigest; }
  check("draft sec. 3.5: the combiner secrets are wiped when the SHA3-256 digest fails",
    capComb !== null && capComb.length === 32 && capComb.every(function (byte) { return byte === 0; }));

  // draft sec. 3.5 binds the RSA encapsulation secret: the random 32-byte secret is allocated before the
  // RSA public operation, so if that operation fails the secret must be wiped, not left readable. Force
  // publicEncrypt to throw, capturing the secret buffer it was handed, and confirm it is all-zero after.
  var nodeCryptoMod2 = require("node:crypto");
  var origPubEnc = nodeCryptoMod2.publicEncrypt;
  var capEncSs = null;
  nodeCryptoMod2.publicEncrypt = function (opts, data) { capEncSs = data; throw new Error("forced encrypt failure"); };
  var encWipeCode;
  try {
    encWipeCode = await codeOf(pki.kem.encapsulate(spkiFrom(rsa.tcId, b64(rsa.ek))));
  } finally { nodeCryptoMod2.publicEncrypt = origPubEnc; }
  check("draft sec. 3.5: the RSA encapsulation secret is wiped when publicEncrypt fails",
    encWipeCode === "kem/bad-key" && capEncSs !== null && capEncSs.length === 32 && capEncSs.every(function (byte) { return byte === 0; }));

  // draft sec. 3.5 also binds the length-validation exits: the reconstructed private-key copy is wiped
  // even when a structural check rejects the input before any component runs. Drive the "private key
  // shorter than the ML-KEM seed" exit while making the private-key OCTET STRING read return a standalone
  // ArrayBuffer -- Buffer.from(ArrayBuffer) aliases rather than copies, so the internal sk buffer views
  // the same memory this test holds. After the rejection the memory is all-zero on the fixed tree and
  // still 0x5a on the pre-fix tree, where the length check throws above the wipe.
  var schemaPkcs8 = require("../../lib/schema-pkcs8");
  var origParse = schemaPkcs8.parse;
  var probeAb = null;
  schemaPkcs8.parse = function () {
    var info = origParse.apply(this, arguments);
    if (probeAb === null && info.privateKey && info.privateKey.length === 64) {   // the 64-byte 0x5a key
      probeAb = info.privateKey.buffer.slice(info.privateKey.byteOffset, info.privateKey.byteOffset + info.privateKey.byteLength);
      info.privateKey = probeAb;   // an ArrayBuffer, so the module's Buffer.from(info.privateKey) aliases it
    }
    return info;
  };
  try {
    var seedLenP8 = pkcs8(x.tcId, Buffer.alloc(64, 0x5a));   // a private key of exactly the ML-KEM seed length
    await codeOf(pki.kem.decapsulate(seedLenP8, b64(x.c)));
  } finally { schemaPkcs8.parse = origParse; }
  var observed = probeAb === null ? null : Buffer.from(probeAb);
  check("draft sec. 3.5: the private-key copy is wiped on the length-validation exit",
    observed !== null && observed.length === 64 && observed.every(function (byte) { return byte === 0; }));

  // draft sec. 3.5: the snapshotted PKCS#8 copy also holds the private-key octets and is wiped on every
  // path. schemaPkcs8.parse receives that buffer as its argument; capture it and confirm it is all-zero
  // after a successful decapsulation (the buffer is the module's own snapshot, not the caller's).
  var capturedP8 = null;
  schemaPkcs8.parse = function (der) { capturedP8 = der; return origParse.apply(this, arguments); };
  try {
    await pki.kem.decapsulate(b64(x.dk_pkcs8), b64(x.c));
  } finally { schemaPkcs8.parse = origParse; }
  check("draft sec. 3.5: the snapshotted PKCS#8 buffer is wiped after decapsulation",
    capturedP8 !== null && capturedP8.length > 0 && capturedP8.every(function (byte) { return byte === 0; }));
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
