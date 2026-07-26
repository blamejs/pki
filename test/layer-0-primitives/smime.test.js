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

  // ==== S/MIME compression (compressed-data), RFC 8551 sec. 3.6 / RFC 3274 =========================
  var CMP = Buffer.from("compress me: " + "the quick brown fox ".repeat(64));   // compressible

  // ---- Z1: compress -> decompress recovers the inner MIME entity; the p7z header shape (M9) ----
  var z = await pki.smime.compress(CMP);
  check("71. compress emits application/pkcs7-mime; smime-type=compressed-data; name=smime.p7z", /Content-Type: application\/pkcs7-mime; smime-type=compressed-data; name=smime\.p7z/.test(z.toString("latin1")));
  check("72. it declares base64 transfer + attachment filename=smime.p7z", /Content-Transfer-Encoding: base64/.test(z.toString("latin1")) && /Content-Disposition: attachment; filename=smime\.p7z/.test(z.toString("latin1")));
  var dz = await pki.smime.decompress(z);
  check("73. decompress recovers the inner text/plain entity carrying the content", dz.content.indexOf(Buffer.from("the quick brown fox")) >= 0 && dz.content.indexOf(Buffer.from("text/plain")) >= 0);
  check("74. the decompress verdict carries NO authenticated/valid field (not a security assertion, M13/M20)", dz.authenticated === undefined && dz.valid === undefined && dz.compressionAlgorithm === "id-alg-zlibCompress");

  // ---- Z2: entity input forms (M10) ----
  var zEnt = await pki.smime.compress(Buffer.from("Content-Type: application/json\r\n\r\n{\"k\":1}\n"), { entity: true });
  check("75. opts.entity compresses a caller's full MIME entity verbatim", (await pki.smime.decompress(zEnt)).content.indexOf(Buffer.from("application/json")) >= 0);
  check("76. opts.contentType is honored on the wrapped entity", (await pki.smime.decompress(await pki.smime.compress(CMP, { contentType: "text/html; charset=utf-8" }))).content.indexOf(Buffer.from("text/html")) >= 0);

  // ---- Z3: receive tolerance (M11) ----
  check("77. an application/x-pkcs7-mime (OpenSSL legacy) compressed message decompresses", (await pki.smime.decompress(Buffer.from(z.toString("latin1").replace("application/pkcs7-mime", "application/x-pkcs7-mime"), "latin1"))).content.indexOf(Buffer.from("the quick brown fox")) >= 0);
  check("78. a MISSING smime-type decompresses (off the CMS content type)", (await pki.smime.decompress(Buffer.from(z.toString("latin1").replace("; smime-type=compressed-data", ""), "latin1"))).content.indexOf(Buffer.from("the quick brown fox")) >= 0);
  check("79. a mixed-case smime-type decompresses (advisory, body-authoritative)", (await pki.smime.decompress(Buffer.from(z.toString("latin1").replace("smime-type=compressed-data", "smime-type=Compressed-Data"), "latin1"))).content.indexOf(Buffer.from("the quick brown fox")) >= 0);
  check("80. a signed-data smime-type is not a decompress input -> smime/unsupported-type", (await codeOf(function () { return pki.smime.decompress(Buffer.from("Content-Type: application/pkcs7-mime; smime-type=signed-data\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n")); })) === "smime/unsupported-type");
  check("81. a non-pkcs7-mime message -> smime/unsupported-type", (await codeOf(function () { return pki.smime.decompress(Buffer.from("Content-Type: text/plain\r\n\r\njust text")); })) === "smime/unsupported-type");

  // ---- Z4: nesting (RFC 8551 sec. 3.7): compress(sign(...)) -> decompress returns the inner signed entity;
  // a following smime.verify on it is valid (no auto-recursion; the caller re-verifies) (M12) ----
  var signedMsg = await pki.smime.sign(Buffer.from("nested payload\n"), signers, { form: "pkcs7-mime" });
  var nested = await pki.smime.compress(signedMsg, { entity: true });
  var inner = await pki.smime.decompress(nested);
  check("82. compress-then-sign nests: decompress returns the inner signed message, which then verifies", (await pki.smime.verify(inner.content)).valid === true);

  // ---- Z5: forwarding + bomb defense at the smime layer ----
  check("83. decompress forwards opts.maxOutputBytes (a tightened cap fails a large payload)", (await codeOf(function () { return pki.smime.decompress(z, { maxOutputBytes: 8 }); })) === "cms/decompress-too-large");
  check("84. compress of a non-Buffer -> a typed error", /^(smime|cms)\//.test(await codeOf(function () { return pki.smime.compress(42); })));
  check("85. compress forwards opts.level to cms.compress", (await pki.smime.decompress(await pki.smime.compress(CMP, { level: 9 }))).content.indexOf(Buffer.from("the quick brown fox")) >= 0);

  // ==== HP: RFC 9788 header protection over the shipped sign/encrypt path ===========================
  // HP sign/encrypt produce the FULL message (outer display headers + the crypto envelope whose inner
  // Cryptographic Payload root carries the protected header copies + hp="clear"/"cipher"); verify/decrypt
  // surface the AUTHENTICATED inner set as res.protectedHeaders + res.headerProtection{present,mode,fromMismatch}.
  var rcpt = makeRecipient("rsa");
  var HB = Buffer.from("the message body\n");

  // (a) signed HP (hp="clear") round-trip: verify surfaces the authenticated inner headers.
  var hpSigned = await pki.smime.sign(HB, signers, { protectHeaders: true, headers: { Subject: "Real subject", From: "a@ex.example", To: "b@ex.example" } });
  var hv = await pki.smime.verify(hpSigned);
  check("86. a signed-HP message verifies valid", hv.valid === true);
  check("86. verify surfaces the authenticated inner Subject", hv.protectedHeaders != null && hv.protectedHeaders.Subject === "Real subject");
  check("86. verify surfaces the inner From + To", hv.protectedHeaders != null && hv.protectedHeaders.From === "a@ex.example" && hv.protectedHeaders.To === "b@ex.example");
  check("86. headerProtection is present with mode clear (signed-only)", hv.headerProtection != null && hv.headerProtection.present === true && hv.headerProtection.mode === "clear");
  check("86. the payload root carries hp=\"clear\"", /hp="?clear"?/.test(hpSigned.toString("latin1")));

  // (b) encrypted HP (hp="cipher") + hcp_baseline: the real Subject lives ONLY inside the ciphertext.
  var hpEnc = await pki.smime.encrypt(HB, [{ cert: rcpt.cert }], { protectHeaders: true, headers: { Subject: "Secret contract terms", From: "a@ex.example" }, hcp: "hcp_baseline" });
  check("87. the encrypted-HP outer Subject is obscured to [...]", /(^|\r\n)Subject:\s*\[\.\.\.\]\s*(\r\n|$)/.test(hpEnc.toString("latin1")));
  check("87. the real Subject appears NOWHERE in the outer/enveloped bytes", hpEnc.toString("latin1").indexOf("Secret contract terms") < 0);
  var hd = await pki.smime.decrypt(hpEnc, { key: rcpt.key, cert: rcpt.cert });
  check("87. decrypt recovers the real inner Subject", hd.protectedHeaders != null && hd.protectedHeaders.Subject === "Secret contract terms");
  check("87. decrypt reports headerProtection mode cipher", hd.headerProtection != null && hd.headerProtection.mode === "cipher");

  // (c) injection (the #1 fragile area): a CR / LF / NUL in a value or a bad field NAME -> smime/bad-header.
  check("88. a CRLF-injected header value is rejected (smime/bad-header)", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { Subject: "x\r\nBcc: mallory@evil" } }); })) === "smime/bad-header");
  check("88. a bare LF in a header value is rejected", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { Subject: "x\nBcc: e" } }); })) === "smime/bad-header");
  check("88. a bare CR in a header value is rejected", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { Subject: "x\rBcc: e" } }); })) === "smime/bad-header");
  check("88. a NUL in a header value is rejected", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { Subject: "x" + String.fromCharCode(0) + "y" } }); })) === "smime/bad-header");
  check("88. a field NAME with an embedded colon is rejected", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "Sub:ject": "x" } }); })) === "smime/bad-header");
  check("88. a field NAME with a space is rejected", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "Bad Name": "x" } }); })) === "smime/bad-header");

  // (d) BACKWARD COMPAT (the tripwire): no protectHeaders -> no hp, protectedHeaders null.
  var plain = await pki.smime.sign(HB, signers);
  check("89. a non-HP signed message emits no hp parameter", plain.toString("latin1").indexOf("hp=") < 0);
  var pv = await pki.smime.verify(plain);
  check("89. verify of a non-HP message reports protectedHeaders null", pv.protectedHeaders == null && (pv.headerProtection == null || pv.headerProtection.present === false));

  // (e) tamper-invariance: mutate ONLY the OUTER From (the first occurrence, before the crypto envelope) --
  // the inner From is inside the signed part, so protectedHeaders is unchanged and the mismatch is flagged.
  var outerTampered = Buffer.from(hpSigned.toString("latin1").replace("a@ex.example", "mallory@evil.example"), "latin1");
  var tv = await pki.smime.verify(outerTampered);
  check("90. tampering the OUTER From leaves the authenticated inner From unchanged + still valid", tv.valid === true && tv.protectedHeaders != null && tv.protectedHeaders.From === "a@ex.example");
  check("90. an outer From differing from the inner From is flagged fromMismatch", tv.headerProtection.fromMismatch === true);

  // (f) downgrade / contradiction (fail-closed, MUST 2/16): the hp mode is bound to the actual envelope.
  var badVal = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp=\"bogus\"\r\n\r\nbody\n"), signers, { entity: true });
  check("91. a payload with an invalid hp value -> smime/bad-header-protection", (await codeOf(function () { return pki.smime.verify(badVal); })) === "smime/bad-header-protection");
  var cipherOnSigned = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp=\"cipher\"\r\n\r\nbody\n"), signers, { entity: true });
  check("91. a SIGNED message whose payload claims hp=cipher -> smime/bad-header-protection (no encryption layer)", (await codeOf(function () { return pki.smime.verify(cipherOnSigned); })) === "smime/bad-header-protection");
  var malformed = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp=\"clear\"\r\nNoColonHeaderLine\r\n\r\nbody\n"), signers, { entity: true });
  check("91. a payload DECLARING hp with a malformed header block -> smime/bad-header-protection (no silent downgrade)", (await codeOf(function () { return pki.smime.verify(malformed); })) === "smime/bad-header-protection");

  // (g) canonicalization: a transport that mangles a CRLF in the signed HP part still verifies + surfaces the
  // same inner headers (the shared RFC 8551 sec. 3.1.1 canonicalizer repairs both signer + verifier sides).
  var mangled = Buffer.from(hpSigned.toString("latin1").replace("the message body\r\n", "the message body\n"), "latin1");
  var mv = await pki.smime.verify(mangled);
  check("92. a CRLF->LF-mangled HP part still verifies + surfaces the same inner Subject", mv.valid === true && mv.protectedHeaders != null && mv.protectedHeaders.Subject === "Real subject");

  // (h) alternate opts.headers forms + HCP variants + 8-bit body + fail-closed input shapes (branch coverage).
  var arrHp = await pki.smime.sign(HB, signers, { protectHeaders: true, headers: [{ name: "Subject", value: "Arr subject" }, { name: "From", value: "a@ex.example" }] });
  check("93. opts.headers as an array of { name, value } works", (await pki.smime.verify(arrHp)).protectedHeaders.Subject === "Arr subject");
  var eightBit = await pki.smime.sign(Buffer.from("caf" + String.fromCharCode(0xe9) + " body\n", "latin1"), signers, { protectHeaders: true, headers: { Subject: "8bit" } });
  check("93. an 8-bit HP body round-trips (Content-Transfer-Encoding 8bit)", /hp="clear"/.test(eightBit.toString("latin1")) && (await pki.smime.verify(eightBit)).protectedHeaders.Subject === "8bit");
  // encrypt HP + hcp_baseline removes Comments/Keywords from the outer section, recovers them inside
  var hpEncC = await pki.smime.encrypt(HB, [{ cert: rcpt.cert }], { protectHeaders: true, headers: { Subject: "S", Comments: "secret comment", Keywords: "kw" } });
  var hpEncCs = hpEncC.toString("latin1");
  check("94. hcp_baseline removes Comments/Keywords from the outer section", !/(^|\r\n)Comments:/i.test(hpEncCs) && !/(^|\r\n)Keywords:/i.test(hpEncCs) && hpEncCs.indexOf("secret comment") < 0);
  var hpEncCd = await pki.smime.decrypt(hpEncC, { key: rcpt.key, cert: rcpt.cert });
  check("94. decrypt recovers the removed Comments/Keywords from the ciphertext", hpEncCd.protectedHeaders.Comments === "secret comment" && hpEncCd.protectedHeaders.Keywords === "kw");
  var encNoConf = await pki.smime.encrypt(HB, [{ cert: rcpt.cert }], { protectHeaders: true, headers: { Subject: "Visible" }, hcp: "hcp_no_confidentiality" });
  check("95. hcp_no_confidentiality leaves the outer Subject visible", /(^|\r\n)Subject:\s*Visible/.test(encNoConf.toString("latin1")));
  // fail-closed input shapes
  check("96. a malformed opts.headers array entry -> smime/bad-input", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: [{ value: "no name" }] }); })) === "smime/bad-input");
  check("96. a non-object opts.headers -> smime/bad-input", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: 42 }); })) === "smime/bad-input");
  check("96. a non-string opts.hcp -> smime/bad-input", (await codeOf(function () { return pki.smime.encrypt(HB, [{ cert: rcpt.cert }], { protectHeaders: true, headers: { Subject: "x" }, hcp: 5 }); })) === "smime/bad-input");
  check("96. a Structural header in opts.headers -> smime/bad-input (only Non-Structural fields protected)", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "Content-Type": "text/html" } }); })) === "smime/bad-input");
  check("96. MIME-Version in opts.headers -> smime/bad-input", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "MIME-Version": "1.0" } }); })) === "smime/bad-input");
  // an HP payload with no blank-line separator is still detected (the _declaresHp no-separator arm)
  var noBody = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp=\"clear\""), signers, { entity: true });
  check("97. an HP payload with no blank-line separator is still detected", (await pki.smime.verify(noBody)).headerProtection.mode === "clear");

  // (i) a non-ASCII (RFC 6532) protected header value round-trips intact (not latin1-mangled).
  var utf8Subj = "caf" + String.fromCharCode(0xe9);   // "cafe" with an acute e
  var utf8Hp = await pki.smime.sign(HB, signers, { protectHeaders: true, headers: { Subject: utf8Subj } });
  check("97b. a UTF-8 protected header value round-trips intact (RFC 6532)", (await pki.smime.verify(utf8Hp)).protectedHeaders.Subject === utf8Subj);
  var utf8Enc = await pki.smime.encrypt(HB, [{ cert: rcpt.cert }], { protectHeaders: true, headers: { Subject: utf8Subj }, hcp: "hcp_no_confidentiality" });
  check("97b. a UTF-8 value round-trips through encrypt/decrypt", (await pki.smime.decrypt(utf8Enc, { key: rcpt.key, cert: rcpt.cert })).protectedHeaders.Subject === utf8Subj);

  // (j) opts.entity + protectHeaders is rejected (an unsupported combination, not a silent re-wrap).
  check("97c. opts.entity with protectHeaders -> smime/bad-input (unsupported combination)", (await codeOf(function () { return pki.smime.sign(Buffer.from("Content-Type: application/json\r\n\r\n{}"), signers, { entity: true, protectHeaders: true }); })) === "smime/bad-input");

  // (k) an unknown opts.hcp policy name is rejected, not silently treated as baseline.
  check("97d. an unknown opts.hcp policy -> smime/bad-input", (await codeOf(function () { return pki.smime.encrypt(HB, [{ cert: rcpt.cert }], { protectHeaders: true, headers: { Subject: "x" }, hcp: "hcp_bogus" }); })) === "smime/bad-input");
  // an hp= that appears only inside a quoted param value (not as the hp parameter) is NOT header protection.
  var fpHp = await pki.smime.sign(Buffer.from("Content-Type: text/plain; charset=\"a hp=b\"\r\n\r\nbody\n"), signers, { entity: true });
  check("97e. an hp= inside a quoted param value is not treated as header protection", (await pki.smime.verify(fpHp)).protectedHeaders === null);
  // a DECRYPT of an encrypted message whose payload declares hp="clear" contradicts the envelope -> fail closed.
  var clearInCipher = await pki.smime.encrypt(Buffer.from("Content-Type: text/plain; hp=\"clear\"\r\n\r\nbody\n"), [{ cert: rcpt.cert }], { entity: true });
  check("97f. decrypt of a payload claiming hp=clear (a signed-only marker) -> smime/bad-header-protection", (await codeOf(function () { return pki.smime.decrypt(clearInCipher, { key: rcpt.key, cert: rcpt.cert }); })) === "smime/bad-header-protection");

  // (l) protectedHeaders are AUTHENTICATED: an INVALID signature (a tampered signed inner part) or an
  // unauthenticated (AES-CBC) decrypt must NOT surface the inner fields as protected.
  var innerTampered = Buffer.from(utf8Hp); var mi = innerTampered.indexOf(Buffer.from("the message body")); innerTampered[mi] ^= 0x20;
  var itv = await pki.smime.verify(innerTampered);
  check("97g. a tampered signed HP part -> valid:false AND protectedHeaders null (not the altered values)", itv.valid === false && itv.protectedHeaders === null && itv.headerProtection.present === false);
  var cbcHp = await pki.smime.encrypt(HB, [{ cert: rcpt.cert }], { protectHeaders: true, headers: { Subject: "S" }, contentEncryptionAlgorithm: "aes-256-cbc" });
  var cbcD = await pki.smime.decrypt(cbcHp, { key: rcpt.key, cert: rcpt.cert });
  check("97g. an unauthenticated (AES-CBC) HP decrypt does NOT surface protectedHeaders", cbcD.authenticated === false && cbcD.protectedHeaders === null);

  // (m) a duplicate Content-Type with an hp claim is a malformed wrap -> fail closed, not a silent downgrade.
  var dupCt = await pki.smime.sign(Buffer.from("Content-Type: text/plain\r\nContent-Type: text/plain; hp=\"clear\"\r\n\r\nbody\n"), signers, { entity: true });
  check("97h. a duplicate Content-Type with an hp claim -> smime/bad-header-protection", (await codeOf(function () { return pki.smime.verify(dupCt); })) === "smime/bad-header-protection");

  // (n) a DUPLICATE outer From (an attacker appends a second, forged one after the matching original) is
  // flagged fromMismatch -- header() returns only the first, so every occurrence must be inspected.
  var dupFrom = Buffer.from(hpSigned.toString("latin1").replace("From: a@ex.example\r\n", "From: a@ex.example\r\nFrom: mallory@evil.example\r\n"), "latin1");
  var dfv = await pki.smime.verify(dupFrom);
  check("97i. a duplicate outer From is flagged fromMismatch (not silently the first)", dfv.valid === true && dfv.headerProtection.fromMismatch === true);
  // a REMOVED outer From (a transport/attacker strips it, leaving the protected inner From) is a mismatch too.
  var noOuterFrom = Buffer.from(hpSigned.toString("latin1").replace("From: a@ex.example\r\n", ""), "latin1");
  var nofv = await pki.smime.verify(noOuterFrom);
  check("97i. a missing outer From (with a protected inner From) is flagged fromMismatch", nofv.valid === true && nofv.headerProtection.fromMismatch === true);

  // (o) a duplicate hp parameter is ambiguous (a parser could honor either) -> fail closed.
  var dupHp = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp=\"cipher\"; hp=\"clear\"\r\n\r\nbody\n"), signers, { entity: true });
  check("97j. a duplicate hp parameter -> smime/bad-header-protection", (await codeOf(function () { return pki.smime.verify(dupHp); })) === "smime/bad-header-protection");
  // (p) a duplicate INNER protected From is ambiguous (last-wins overwrite hides the first) -> fail closed.
  var dupInnerFrom = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp=\"clear\"\r\nFrom: attacker@ex.example\r\nFrom: victim@ex.example\r\n\r\nbody\n"), signers, { entity: true });
  check("97k. a duplicate inner protected From -> smime/bad-header-protection", (await codeOf(function () { return pki.smime.verify(dupInnerFrom); })) === "smime/bad-header-protection");
  // (q) a Non-Structural header whose name collides with an Object.prototype key is NOT treated as Structural.
  var ctorHp = await pki.smime.sign(HB, signers, { protectHeaders: true, headers: { Constructor: "custom" } });
  check("97l. a header named Constructor is protected + surfaced (not falsely Structural)", (await pki.smime.verify(ctorHp)).protectedHeaders.Constructor === "custom");

  // (r) a quoted "hp=" inside the caller's Content-Type is NOT a duplicate hp parameter (quote-aware) --
  // sign and verify must agree (the library never rejects a message it emits).
  var quotedHp = await pki.smime.sign(HB, signers, { protectHeaders: true, contentType: "text/plain; charset=\"a; hp=fake\"", headers: { Subject: "ok" } });
  check("97m. a quoted hp= in the caller Content-Type is not a duplicate hp param", (await pki.smime.verify(quotedHp)).protectedHeaders.Subject === "ok");
  // (s) a repeated protected field NAME is rejected by the PRODUCER (an unsupported shape it cannot re-consume).
  check("97n. duplicate opts.headers field names -> smime/bad-input (producer rejects)", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: [{ name: "Received", value: "a" }, { name: "Received", value: "b" }] }); })) === "smime/bad-input");
  // (t) a CRLF in opts.contentType is rejected on the NON-HP path too (the header-injection guard is universal).
  check("97o. a CRLF-injected opts.contentType (non-HP) -> smime/bad-header", (await codeOf(function () { return pki.smime.sign(HB, signers, { contentType: "text/plain\r\nBcc: mallory@evil.example" }); })) === "smime/bad-header");
  check("97o. a CRLF-injected opts.contentType on encrypt (non-HP) -> smime/bad-header", (await codeOf(function () { return pki.smime.encrypt(HB, [{ cert: rcpt.cert }], { contentType: "text/plain\r\nBcc: x" }); })) === "smime/bad-header");
  // (u) a caller-supplied hp parameter in opts.contentType conflicts with the one HP sets -> reject at sign.
  check("97p. a caller hp= in opts.contentType with protectHeaders -> smime/bad-input", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, contentType: "text/plain; hp=\"cipher\"", headers: { Subject: "x" } }); })) === "smime/bad-input");
  // (v) whitespace before the Content-Type colon (which mime.parse trims) is detected as HP, not downgraded.
  var wspColon = await pki.smime.sign(Buffer.from("Content-Type : text/plain; hp=\"clear\"\r\nSubject: WSP subject\r\n\r\nbody\n"), signers, { entity: true });
  check("97q. a Content-Type with whitespace before the colon is still detected as HP (no downgrade)", (await pki.smime.verify(wspColon)).protectedHeaders.Subject === "WSP subject");

  // protectHeaders with no/empty headers (an hp marker + no protected fields) + null header values.
  var emptyHp = await pki.smime.sign(HB, signers, { protectHeaders: true });
  check("98. protectHeaders with no opts.headers still emits hp + verifies", /hp="clear"/.test(emptyHp.toString("latin1")) && (await pki.smime.verify(emptyHp)).headerProtection.present === true);
  check("98. an object header with a null value is emitted empty", (await pki.smime.verify(await pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "X-Empty": null } }))).protectedHeaders["X-Empty"] === "");
  check("98. an array header with a null value is emitted empty", (await pki.smime.verify(await pki.smime.sign(HB, signers, { protectHeaders: true, headers: [{ name: "X-Empty", value: null }] }))).protectedHeaders["X-Empty"] === "");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
