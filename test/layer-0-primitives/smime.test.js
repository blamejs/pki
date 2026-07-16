// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.smime (RFC 8551 S/MIME assembly + verification over the CMS layer). Both forms round
 * -trip through sign->verify (multipart/signed clear-signed + application/pkcs7-mime opaque); the
 * detached signature binds the first part's RFC 8551 sec. 3.1.1 canonical form, so a tampered part
 * fails and a transport that re-wraps line endings still verifies (the shared canonicalizer). The
 * S/MIME layer is algorithm-agnostic -- it carries any pki.cms.sign signer. Malformed frames fail
 * closed with a typed smime/* error, never a raw throw. (openssl bidirectional interop is the
 * integration harness's job; this pins the shape + the fail-closed surface.)
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var signing = require("../helpers/signing");
var makeRecipient = signing.makeRecipient;

async function codeOf(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

async function run() {
  var rsa = signing.makeSigner("rsa"), signers = [{ cert: rsa.cert, key: rsa.key }];
  var MSG = Buffer.from("Hello S/MIME\nsecond line\n");

  // ---- A1: multipart/signed round-trip ----
  var mp = await pki.smime.sign(MSG, signers, { form: "multipart" });
  check("1. multipart/signed emits a multipart/signed Content-Type", /^Content-Type: multipart\/signed;/.test(mp.toString()));
  check("2. it declares protocol=application/pkcs7-signature", /protocol="application\/pkcs7-signature"/.test(mp.toString()));
  check("3. it declares micalg=sha-256", /micalg=sha-256/.test(mp.toString()));
  var v = await pki.smime.verify(mp);
  check("4. multipart/signed verifies valid", v.valid === true && v.signers.length === 1 && v.signers[0].ok === true);
  check("5. the verdict form is multipart/signed + micalg surfaced", v.form === "multipart/signed" && v.micalg === "sha-256");
  check("6. the recovered content carries the signed text", v.content.indexOf(Buffer.from("Hello S/MIME")) >= 0);

  // ---- A2: application/pkcs7-mime (opaque) round-trip ----
  var op = await pki.smime.sign(MSG, signers, { form: "pkcs7-mime" });
  check("7. pkcs7-mime emits application/pkcs7-mime; smime-type=signed-data", /application\/pkcs7-mime; smime-type=signed-data/.test(op.toString()));
  var vo = await pki.smime.verify(op);
  check("8. pkcs7-mime verifies valid + recovers the inner entity", vo.valid === true && vo.form === "pkcs7-mime" && vo.content.indexOf(Buffer.from("Hello S/MIME")) >= 0);

  // ---- default form is multipart ----
  check("9. the default form is multipart/signed", (await pki.smime.verify(await pki.smime.sign(MSG, signers))).form === "multipart/signed");

  // ---- A4: algorithm-agnostic -- any CMS signer carries through ----
  var algs = ["ec-p256", "ed25519", "ml-dsa-65", "slh-dsa-sha2-128s"];
  for (var i = 0; i < algs.length; i++) {
    var sg = signing.makeSigner(algs[i]);
    var m = await pki.smime.sign(MSG, [{ cert: sg.cert, key: sg.key }], { form: "multipart" });
    check("10." + i + " a " + algs[i] + " signer round-trips through multipart/signed", (await pki.smime.verify(m)).valid === true);
  }

  // ---- R1: a tampered first part fails (the canonical digest binding) ----
  var tampered = Buffer.from(mp); var ti = tampered.indexOf(Buffer.from("Hello")); tampered[ti] ^= 0x20;
  check("11. a tampered first part -> valid:false (no partial trust)", (await pki.smime.verify(tampered)).valid === false);

  // ---- R3: a transport that mangles line endings still verifies (shared canonicalizer) ----
  var relf = Buffer.from(mp.toString().replace(/Hello S\/MIME\r\n/, "Hello S/MIME\n"));  // one CRLF -> LF in the signed part
  check("12. a line-ending-mangled first part still verifies (canonicalization repairs it)", (await pki.smime.verify(relf)).valid === true);

  // ---- entity input form: a caller-supplied full MIME entity ----
  var entity = Buffer.from("Content-Type: text/plain\r\nX-Custom: yes\r\n\r\nbody with headers\n");
  check("13. opts.entity signs a caller's full MIME entity", (await pki.smime.verify(await pki.smime.sign(entity, signers, { entity: true }))).valid === true);

  // ---- Reject / fail-closed surface ----
  check("14. a non-S/MIME message -> smime/unsupported-type", (await codeOf(function () { return pki.smime.verify(Buffer.from("Content-Type: text/plain\r\n\r\njust text")); })) === "smime/unsupported-type");
  check("15. an unknown smime-type -> smime/unsupported-type", (await codeOf(function () { return pki.smime.verify(Buffer.from("Content-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\nAAAA")); })) === "smime/unsupported-type");
  var oneBoundary = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: text/plain\r\n\r\nonly one part\r\n--BB--\r\n";
  check("16. a multipart/signed with != 2 parts -> smime/bad-multipart", (await codeOf(function () { return pki.smime.verify(Buffer.from(oneBoundary)); })) === "smime/bad-multipart");
  var badProto = mp.toString().replace('protocol="application/pkcs7-signature"', 'protocol="application/x-bogus"');
  check("17. a wrong multipart protocol -> smime/bad-multipart", (await codeOf(function () { return pki.smime.verify(Buffer.from(badProto)); })) === "smime/bad-multipart");
  var mangledB64 = op.toString().replace(/\r\n\r\n[A-Za-z0-9+/=\r\n]+/, "\r\n\r\n!!!not base64!!!\r\n");
  check("18. a mangled pkcs7-mime base64 body -> smime/bad-mime", /^smime\//.test(await codeOf(function () { return pki.smime.verify(Buffer.from(mangledB64)); })));
  check("19. sign with an unknown form -> smime/bad-input", (await codeOf(function () { return pki.smime.sign(MSG, signers, { form: "bogus" }); })) === "smime/bad-input");
  check("20. verify of a non-Buffer -> smime/bad-mime or bad-input", /^smime\//.test(await codeOf(function () { return pki.smime.verify(42); })));

  // ---- strict micalg ----
  var wrongMicalg = Buffer.from(mp.toString().replace(/micalg=sha-256/, "micalg=sha-512"));
  check("21. a mismatched micalg is advisory by default (still verifies)", (await pki.smime.verify(wrongMicalg)).valid === true);
  check("22. opts.strictMicalg flags a micalg mismatch -> smime/micalg-mismatch", (await codeOf(function () { return pki.smime.verify(wrongMicalg, { strictMicalg: true }); })) === "smime/micalg-mismatch");

  // ---- multi-signer ----
  var ec = signing.makeSigner("ec-p256");
  var multi = await pki.smime.verify(await pki.smime.sign(MSG, [{ cert: rsa.cert, key: rsa.key }, { cert: ec.cert, key: ec.key }], { form: "multipart" }));
  check("23. a two-signer multipart/signed verifies both signers", multi.valid === true && multi.signers.length === 2);

  // a pkcs7-mime whose CMS body uses a binary/7bit CTE (no base64) verifies -- the body passes through.
  var rawDer = await pki.cms.sign(Buffer.concat([Buffer.from("Content-Type: text/plain\r\n\r\n"), MSG]), signers);
  var binMsg = Buffer.concat([Buffer.from("Content-Type: application/pkcs7-mime; smime-type=signed-data\r\nContent-Transfer-Encoding: binary\r\n\r\n", "latin1"), rawDer]);
  check("24. a binary-CTE pkcs7-mime verifies (raw CMS body, no base64)", (await pki.smime.verify(binMsg)).valid === true);

  // opts forwarding: signingTime / sid / signedAttributes reach cms.sign; certs reach cms.verify.
  var withOpts = await pki.smime.sign(MSG, signers, { form: "multipart", signingTime: new Date("2020-01-01T00:00:00Z"), sid: "issuerAndSerial", signedAttributes: true, additionalSignedAttributes: [] });
  check("25. sign forwards signingTime / sid / signedAttributes and verify forwards certs", (await pki.smime.verify(withOpts, { certs: [rsa.cert] })).valid === true);
  // a multipart/signed whose second part is not application/pkcs7-signature (protocol still correct) -> bad-multipart.
  var notSig = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--BB\r\nContent-Type: text/plain\r\n\r\nnot a signature\r\n--BB--\r\n";
  check("26. a second part that is not pkcs7-signature -> smime/bad-multipart", (await codeOf(function () { return pki.smime.verify(Buffer.from(notSig)); })) === "smime/bad-multipart");
  // a pkcs7-mime with a well-formed base64 body that is not a CMS SignedData -> a typed PkiError (cms/* or smime/*).
  check("27. a pkcs7-mime whose body is not a CMS SignedData -> a typed PkiError", /^(smime|cms|asn1)\//.test(await codeOf(function () { return pki.smime.verify(Buffer.from("Content-Type: application/pkcs7-mime; smime-type=signed-data\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAAAAAA\r\n")); })));

  // SECURITY (content-substitution forgery): a multipart/signed whose pkcs7-signature part carries an
  // ATTACHED SignedData (its own eContent) must be REJECTED -- otherwise cms.verify would verify over the
  // embedded bytes and ignore the first part, letting an attacker pair any validly-signed blob with an
  // arbitrary (forged) first part. The signature over the attached blob is genuinely valid, so a
  // byte-flip test (11) does NOT catch this.
  var attachedP7 = await pki.cms.sign(Buffer.from("genuine signed bytes"), signers);   // attached by default
  var attB64 = attachedP7.toString("base64").replace(/(.{64})/g, "$1\r\n").replace(/\r\n$/, "");
  var forged = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"BB\"\r\n\r\n--BB\r\nContent-Type: text/plain\r\n\r\nFORGED: pay Mallory\r\n--BB\r\nContent-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n" + attB64 + "\r\n--BB--\r\n";
  check("28. an ATTACHED SignedData in the signature part -> smime/bad-multipart (no content-substitution forgery)", (await codeOf(function () { return pki.smime.verify(Buffer.from(forged)); })) === "smime/bad-multipart");

  // RFC 8551 sec. 3.4.3.2: a multi-signer message with MIXED digests lists EVERY digest in micalg
  // (distinct, sorted) -- not just the first signer's. rsa uses SHA-256; ML-DSA-65 uses SHA-512.
  var ml = signing.makeSigner("ml-dsa-65");
  var mixed = await pki.smime.sign(MSG, [{ cert: rsa.cert, key: rsa.key }, { cert: ml.cert, key: ml.key }], { form: "multipart" });
  check("29. a mixed-digest multi-signer lists every digest in micalg (sorted)", /micalg=sha-256,sha-512/.test(mixed.toString()) && (await pki.smime.verify(mixed, { strictMicalg: true })).valid === true);
  check("30. strictMicalg compares the micalg as an order-independent, whitespace-tolerant set", (await pki.smime.verify(Buffer.from(mixed.toString().replace(/micalg=[^;]+/, "micalg=\"sha-512, sha-256\"")), { strictMicalg: true })).valid === true);
  check("31. strictMicalg still flags a genuinely wrong micalg set", (await codeOf(function () { return pki.smime.verify(Buffer.from(mixed.toString().replace(/micalg=[^;]+/, "micalg=sha-384")), { strictMicalg: true }); })) === "smime/micalg-mismatch");

  // RFC 2045: 8-bit (non-ASCII) default content is declared 8bit, not (falsely) 7bit; it round-trips.
  var m8 = await pki.smime.sign(Buffer.from("café — résumé\n", "utf8"), signers, { form: "multipart" });
  check("32. non-ASCII default content is declared Content-Transfer-Encoding: 8bit", /Content-Transfer-Encoding: 8bit/.test(m8.toString("latin1")) && (await pki.smime.verify(m8)).valid === true);
  check("33. ASCII default content stays 7bit", /Content-Transfer-Encoding: 7bit/.test((await pki.smime.sign(Buffer.from("plain ascii body"), signers)).toString()));

  // a SHAKE-digest signer (SLH-DSA / RFC 8702) keeps its micalg name verbatim -- never "sha-ke256".
  var shakeSg = signing.makeSigner("slh-dsa-shake-128s");
  var shakeMsg = await pki.smime.sign(MSG, [{ cert: shakeSg.cert, key: shakeSg.key }], { form: "multipart" });
  check("34. a SHAKE digest preserves its micalg name (shake128, not sha-ke128)", /micalg=shake128/.test(shakeMsg.toString()) && (await pki.smime.verify(shakeMsg, { strictMicalg: true })).valid === true);

  // ==== S/MIME encryption (enveloped-data), RFC 8551 sec. 3.3 / sec. 3.4 ============================
  // No trailing newline: the recovered content is the CANONICAL entity (bare LF -> CRLF), so a needle
  // ending in "\n" would not match "payload\r\n" -- search for a needle that does not span a line end.
  var ENC = Buffer.from("secret payload");

  // ---- E1: round-trip per recipient type (recipient-agnostic -- every cms.encrypt arm carries through) ----
  var eRsa = makeRecipient("rsa");
  var enc = await pki.smime.encrypt(ENC, [{ cert: eRsa.cert }]);
  check("35. encrypt emits application/pkcs7-mime; smime-type=authEnveloped-data (the AEAD default)", /Content-Type: application\/pkcs7-mime; smime-type=authEnveloped-data; name=smime\.p7m/.test(enc.toString("latin1")));
  check("36. it declares base64 transfer + attachment disposition", /Content-Transfer-Encoding: base64/.test(enc.toString("latin1")) && /Content-Disposition: attachment; filename=smime\.p7m/.test(enc.toString("latin1")));
  var dRsa = await pki.smime.decrypt(enc, { key: eRsa.key, cert: eRsa.cert });
  check("37. RSA (ktri/OAEP) round-trips: recovered content is the inner text/plain entity", dRsa.content.indexOf(ENC) >= 0 && dRsa.content.indexOf(Buffer.from("text/plain")) >= 0);
  check("38. the decrypt verdict surfaces smimeType + authenticated:true (AuthEnvelopedData)", dRsa.smimeType === "authEnveloped-data" && dRsa.authenticated === true && dRsa.recipientType === "ktri");

  var recips = ["ec-p256", "x25519", "ml-kem-768"];
  for (var e = 0; e < recips.length; e++) {
    var rc = makeRecipient(recips[e]);
    var enc2 = await pki.smime.encrypt(ENC, [{ cert: rc.cert }]);
    var dec2 = await pki.smime.decrypt(enc2, { key: rc.key, cert: rc.cert });
    check("39." + e + " a " + recips[e] + " recipient round-trips through S/MIME encryption", dec2.content.indexOf(ENC) >= 0 && dec2.authenticated === true);
  }

  // ---- E2: password (pwri) + kek (kekri) recipients need no certificate ----
  var pwEnc = await pki.smime.encrypt(ENC, [{ password: "s3cret" }]);
  check("40. a password recipient (pwri) round-trips", (await pki.smime.decrypt(pwEnc, { password: "s3cret" })).content.indexOf(ENC) >= 0);
  var kek = Buffer.alloc(32, 7), kekId = Buffer.from("kek-1");
  var kekEnc = await pki.smime.encrypt(ENC, [{ kek: kek, kekId: kekId }]);
  check("41. a kek recipient (kekri) round-trips", (await pki.smime.decrypt(kekEnc, { kek: kek, kekId: kekId })).content.indexOf(ENC) >= 0);

  // ---- E3: smime-type is DERIVED from the produced CMS content type; CBC -> enveloped-data (no integrity) ----
  var cbc = await pki.smime.encrypt(ENC, [{ cert: eRsa.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  check("42. a CBC choice yields smime-type=enveloped-data (EnvelopedData)", /smime-type=enveloped-data/.test(cbc.toString("latin1")));
  var dCbc = await pki.smime.decrypt(cbc, { key: eRsa.key, cert: eRsa.cert });
  check("43. an enveloped-only (CBC) message surfaces authenticated:false (the EFAIL / no-integrity caveat)", dCbc.smimeType === "enveloped-data" && dCbc.authenticated === false && dCbc.content.indexOf(ENC) >= 0);

  // ---- E4: entity input forms ----
  var entEnc = await pki.smime.encrypt(Buffer.from("Content-Type: application/json\r\n\r\n{\"k\":1}\n"), [{ cert: eRsa.cert }], { entity: true });
  check("44. opts.entity encrypts a caller's full MIME entity verbatim", (await pki.smime.decrypt(entEnc, { key: eRsa.key, cert: eRsa.cert })).content.indexOf(Buffer.from("application/json")) >= 0);
  var ctEnc = await pki.smime.encrypt(ENC, [{ cert: eRsa.cert }], { contentType: "text/html; charset=utf-8" });
  check("45. opts.contentType is honored on the wrapped entity", (await pki.smime.decrypt(ctEnc, { key: eRsa.key, cert: eRsa.cert })).content.indexOf(Buffer.from("text/html")) >= 0);

  // ---- E5: a single non-array recipient descriptor is normalized to the enveloped path (ergonomic) ----
  check("46. a single {cert} (not an array) still encrypts as enveloped (not EncryptedData)", (await pki.smime.decrypt(await pki.smime.encrypt(ENC, { cert: eRsa.cert }), { key: eRsa.key, cert: eRsa.cert })).content.indexOf(ENC) >= 0);

  // ---- E6: multi-recipient: ONE content-encryption key, each recipient's key material recovers it ----
  var eEc = makeRecipient("ec-p256");
  var multiEnc = await pki.smime.encrypt(ENC, [{ cert: eRsa.cert }, { cert: eEc.cert }, { password: "pw" }]);
  check("47. multi-recipient: RSA key recovers", (await pki.smime.decrypt(multiEnc, { key: eRsa.key, cert: eRsa.cert })).content.indexOf(ENC) >= 0);
  check("48. multi-recipient: EC key recovers the same content", (await pki.smime.decrypt(multiEnc, { key: eEc.key, cert: eEc.cert })).content.indexOf(ENC) >= 0);
  check("49. multi-recipient: password recovers the same content", (await pki.smime.decrypt(multiEnc, { password: "pw" })).content.indexOf(ENC) >= 0);

  // ---- E7: receive tolerance -- OpenSSL's x-pkcs7-mime + a MISSING smime-type both decrypt ----
  var xType = Buffer.from(enc.toString("latin1").replace("application/pkcs7-mime", "application/x-pkcs7-mime"), "latin1");
  check("50. an application/x-pkcs7-mime (OpenSSL legacy) message decrypts", (await pki.smime.decrypt(xType, { key: eRsa.key, cert: eRsa.cert })).content.indexOf(ENC) >= 0);
  var noType = Buffer.from(enc.toString("latin1").replace("; smime-type=authEnveloped-data", ""), "latin1");
  check("51. a MISSING smime-type decrypts (off the CMS content type)", (await pki.smime.decrypt(noType, { key: eRsa.key, cert: eRsa.cert })).content.indexOf(ENC) >= 0);

  // ---- E8: reject / fail-closed ----
  check("52. a non-pkcs7-mime message -> smime/unsupported-type", (await codeOf(function () { return pki.smime.decrypt(Buffer.from("Content-Type: text/plain\r\n\r\njust text"), { key: eRsa.key, cert: eRsa.cert }); })) === "smime/unsupported-type");
  check("53. a signed-data pkcs7-mime is not a decrypt input -> smime/unsupported-type", (await codeOf(function () { return pki.smime.decrypt(Buffer.from("Content-Type: application/pkcs7-mime; smime-type=signed-data\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAAAAAA\r\n"), { key: eRsa.key, cert: eRsa.cert }); })) === "smime/unsupported-type");
  check("54. a garbage base64 body -> a typed PkiError (never a raw throw)", /^(smime|cms|asn1)\//.test(await codeOf(function () { return pki.smime.decrypt(Buffer.from("Content-Type: application/pkcs7-mime; smime-type=authEnveloped-data\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAAAAAA\r\n"), { key: eRsa.key, cert: eRsa.cert }); })));
  check("55. wrong recipient key material -> cms/no-matching-recipient (propagated, fail-closed)", (await codeOf(function () { return pki.smime.decrypt(enc, { key: makeRecipient("rsa").key, cert: makeRecipient("rsa").cert }); })) === "cms/no-matching-recipient");
  // a tampered AEAD ciphertext collapses to the uniform cms/decrypt-failed (oracle freedom is the CMS
  // layer's guarantee -- smime.decrypt must PROPAGATE it, never add a distinguishing branch).
  var tEnc = enc.toString("latin1");
  var b64start = tEnc.indexOf("\r\n\r\n") + 4, mid = b64start + 200;
  var tampChar = tEnc[mid] === "A" ? "B" : "A";
  var tampEnc = Buffer.from(tEnc.slice(0, mid) + tampChar + tEnc.slice(mid + 1), "latin1");
  check("56. a tampered AEAD ciphertext -> a typed PkiError (fail-closed, no oracle)", /^(cms|smime|asn1)\//.test(await codeOf(function () { return pki.smime.decrypt(tampEnc, { key: eRsa.key, cert: eRsa.cert }); })));

  // ---- E9: strictSmimeType (belt-and-braces, mirrors strictMicalg) ----
  var mislabel = Buffer.from(enc.toString("latin1").replace("smime-type=authEnveloped-data", "smime-type=enveloped-data"), "latin1");
  check("57. a mislabeled smime-type is advisory by default (still decrypts off the CMS content type)", (await pki.smime.decrypt(mislabel, { key: eRsa.key, cert: eRsa.cert })).content.indexOf(ENC) >= 0);
  check("58. opts.strictSmimeType flags a smime-type that disagrees with the CMS body -> smime/smime-type-mismatch", (await codeOf(function () { return pki.smime.decrypt(mislabel, { key: eRsa.key, cert: eRsa.cert }, { strictSmimeType: true }); })) === "smime/smime-type-mismatch");

  // ---- E10: a message larger than the MIME cap fails closed on receive (size ceiling) ----
  check("59. decrypt of a non-Buffer/bad input -> a typed smime/* error", /^smime\//.test(await codeOf(function () { return pki.smime.decrypt(42, { key: eRsa.key, cert: eRsa.cert }); })));

  // ---- E11: a pkcs7-mime whose body is a CMS structure that is NOT enveloped (a bare EncryptedData, or
  // a SignedData) and carries NO smime-type is not a decrypt input -> smime/unsupported-type. EncryptedData
  // in particular is deliberately NOT an S/MIME construct (RFC 8551 registers no smime-type for it). ----
  var encData = Buffer.from(await pki.cms.encrypt(Buffer.from("x"), { cek: Buffer.alloc(32, 3) }, { contentEncryptionAlgorithm: "aes-256-cbc" }));   // non-array -> EncryptedData (CBC only)
  var wrapped = Buffer.concat([Buffer.from("Content-Type: application/pkcs7-mime\r\nContent-Transfer-Encoding: base64\r\n\r\n", "latin1"), Buffer.from(encData.toString("base64"), "latin1"), Buffer.from("\r\n", "latin1")]);
  check("60. a pkcs7-mime wrapping a bare EncryptedData (no smime-type) -> smime/unsupported-type", (await codeOf(function () { return pki.smime.decrypt(wrapped, { cek: Buffer.alloc(32, 3) }); })) === "smime/unsupported-type");
  var signedDer = Buffer.from(await pki.cms.sign(Buffer.from("Content-Type: text/plain\r\n\r\nsigned"), signers));
  var wrapSigned = Buffer.concat([Buffer.from("Content-Type: application/pkcs7-mime\r\nContent-Transfer-Encoding: base64\r\n\r\n", "latin1"), Buffer.from(signedDer.toString("base64"), "latin1"), Buffer.from("\r\n", "latin1")]);
  check("61. a pkcs7-mime wrapping a SignedData (no smime-type) is not a decrypt input -> smime/unsupported-type", (await codeOf(function () { return pki.smime.decrypt(wrapSigned, { key: eRsa.key, cert: eRsa.cert }); })) === "smime/unsupported-type");

  // ---- E12: every advertised opt is forwarded to the CMS layer (encrypt: oaepHash / keyIdentifier / ukm;
  // decrypt: recipientIndex / maxIterations) -- an advertised-untested opt is an unasserted guarantee. ----
  check("62. encrypt forwards opts.oaepHash to the ktri recipient", (await pki.smime.decrypt(await pki.smime.encrypt(ENC, [{ cert: eRsa.cert }], { oaepHash: "sha384" }), { key: eRsa.key, cert: eRsa.cert })).content.indexOf(ENC) >= 0);
  var eSki = makeRecipient("rsa", { ski: Buffer.from("smime-ski-20-bytes!!", "latin1") });
  check("63. encrypt forwards opts.keyIdentifier=subjectKeyIdentifier", (await pki.smime.decrypt(await pki.smime.encrypt(ENC, [{ cert: eSki.cert }], { keyIdentifier: "subjectKeyIdentifier" }), { key: eSki.key, cert: eSki.cert })).content.indexOf(ENC) >= 0);
  check("64. encrypt forwards opts.ukm to a kari recipient", (await pki.smime.decrypt(await pki.smime.encrypt(ENC, [{ cert: eEc.cert }], { ukm: Buffer.from("user-keying-material") }), { key: eEc.key, cert: eEc.cert })).content.indexOf(ENC) >= 0);
  check("65. decrypt forwards opts.recipientIndex + opts.maxIterations to cms.decrypt", (await pki.smime.decrypt(multiEnc, { password: "pw" }, { recipientIndex: 2, maxIterations: 1000000 })).content.indexOf(ENC) >= 0);

  // ---- E13: the smime-type header is advisory + case-insensitive on receive (the CMS body is authoritative);
  // strict on emit. A legitimately oddly-cased header decrypts, and strictSmimeType matches case-insensitively. ----
  var oddCase = Buffer.from(enc.toString("latin1").replace("smime-type=authEnveloped-data", "smime-type=AuthEnveloped-DATA"), "latin1");
  check("66. an oddly-cased smime-type still decrypts (advisory, body-authoritative)", (await pki.smime.decrypt(oddCase, { key: eRsa.key, cert: eRsa.cert })).content.indexOf(ENC) >= 0);
  check("67. strictSmimeType matches an oddly-cased-but-correct smime-type (case-insensitive)", (await pki.smime.decrypt(oddCase, { key: eRsa.key, cert: eRsa.cert }, { strictSmimeType: true })).content.indexOf(ENC) >= 0);

  // ---- E14: encrypt fails closed on a missing / empty / malformed recipient set (an advertised guarantee:
  // an S/MIME enveloped message is never emitted with no recipient). Surfaces the CMS layer's typed code. ----
  check("68. an empty recipient array -> fail-closed typed error (never a recipient-less envelope)", /^(smime|cms)\//.test(await codeOf(function () { return pki.smime.encrypt(ENC, []); })));
  check("69. null recipients -> fail-closed typed error", /^(smime|cms)\//.test(await codeOf(function () { return pki.smime.encrypt(ENC, null); })));
  check("70. a bogus recipient descriptor -> fail-closed typed error", /^(smime|cms)\//.test(await codeOf(function () { return pki.smime.encrypt(ENC, [{ nonsense: 1 }]); })));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
