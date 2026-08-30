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

// The @opts names each pki.smime.<verb> documents, read out of the source comment blocks the wiki is
// generated from. Derived rather than restated, so this cannot agree with a stale copy of itself.
function docOptsOf(file) {
  var src = require("fs").readFileSync(file, "utf8");
  var out = {}, verb = null;
  src.split(/\r?\n/).forEach(function (line) {
    var p = /^\s*\*\s*@primitive\s+pki\.smime\.(\w+)\s*$/.exec(line);
    if (p) { verb = p[1]; out[verb] = out[verb] || []; return; }
    if (/^\s*\*\s*@(primitive|module)\b/.test(line)) { verb = null; return; }
    var o = /^\s*\*\s*@opts\s+(\w+)\b/.exec(line);
    if (o && verb) out[verb].push(o[1]);
  });
  return out;
}

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
  // This verb is pki.cms.verify's verdict plus the MIME surface, so the trust seam that verb offers
  // has to reach it: a caller naming anchors here must have them applied, and one who names none
  // must be told the signer was not anchored rather than left to read `valid` as though it were.
  check("6a. an unanchored signer is reported untrusted, not merely valid", v.trusted === false);
  var smimeAnchored = await pki.smime.verify(mp, { trustAnchors: [rsa.cert] });
  check("6b. anchors named here reach the CMS verify beneath, rather than being dropped",
    smimeAnchored.valid === true && typeof smimeAnchored.trusted === "boolean");
  // Trusted FOR THIS PURPOSE. A chain alone does not make a signer right for email -- a certificate
  // restricted to serverAuth chains to its root perfectly well and is still the wrong key to have
  // signed a message -- so this verb asks for emailProtection (RFC 8551 sec. 4.4.4). The signer here
  // carries no emailProtection EKU, so the purpose-neutral answer and the S/MIME one differ, which
  // is what makes this vector discriminate rather than echo the chain result.
  var purposeBound = await pki.smime.verify(mp, { trustAnchors: [rsa.cert], requiredEku: ["serverAuth"] });
  check("6c. a purpose the signer does not carry is not reported trusted",
    purposeBound.trusted === false);

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
  check("96. a null opts.headers array entry -> smime/bad-input", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: [null] }); })) === "smime/bad-input");
  check("96. a non-object opts.headers -> smime/bad-input", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: 42 }); })) === "smime/bad-input");
  check("96. a non-string opts.hcp -> smime/bad-input", (await codeOf(function () { return pki.smime.encrypt(HB, [{ cert: rcpt.cert }], { protectHeaders: true, headers: { Subject: "x" }, hcp: 5 }); })) === "smime/bad-input");
  check("96. a Structural header in opts.headers -> smime/bad-input (only Non-Structural fields protected)", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "Content-Type": "text/html" } }); })) === "smime/bad-input");
  check("96. MIME-Version in opts.headers -> smime/bad-input", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "MIME-Version": "1.0" } }); })) === "smime/bad-input");
  // RFC 9787 sec. 1.1.1: a Structural field is MIME-Version OR any name beginning with "Content-" -- the prefix
  // rule catches EVERY Content-* field (Content-ID / -Description / -Language / ...), not just an enumerated subset.
  check("96. Content-Language (a Content-* field) in opts.headers -> smime/bad-input (Structural prefix rule)", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "Content-Language": "en" } }); })) === "smime/bad-input");
  check("96. Content-ID / Content-Description are Structural (begin with Content-) -> smime/bad-input", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "Content-Description": "d" } }); })) === "smime/bad-input" && (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "Content-ID": "<x>" } }); })) === "smime/bad-input");
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
  // (w) a quoted-pair-escaped "hp=" inside opts.contentType is not mistaken for a caller hp parameter (quoted-pair aware).
  var escHp = await pki.smime.sign(HB, signers, { protectHeaders: true, contentType: "text/plain; charset=\"a\\\"; hp=fake\"", headers: { Subject: "esc ok" } });
  check("97r. a quoted-pair-escaped hp= in opts.contentType is not a caller hp param (sign succeeds)", (await pki.smime.verify(escHp)).protectedHeaders.Subject === "esc ok");
  // (x) leading whitespace before Content-Type (which mime.parse trims) is still detected as HP (no downgrade).
  var leadWsp = await pki.smime.sign(Buffer.from(" Content-Type: text/plain; hp=\"clear\"\r\nSubject: lead ws\r\n\r\nbody\n"), signers, { entity: true });
  check("97s. leading whitespace before Content-Type is still detected as HP (no downgrade)", (await pki.smime.verify(leadWsp)).protectedHeaders.Subject === "lead ws");
  // (u) an over-998-octet protected header line is rejected at sign -- a relay re-fold would change the signed bytes (RFC 5322 sec. 2.1.1).
  check("97t. an over-length protected header line is rejected at sign (RFC 5322 998-octet cap)", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { Subject: new Array(1000).join("x") } }); })) === "smime/bad-header");
  // (v) a transport that rewrites the CRLF fold before a folded hp param to a bare CR keeps the signature valid
  // (the canonicalizer maps bare CR -> CRLF) -- the hp signal must survive too (no attacker-strippable downgrade).
  var signedFold = await pki.smime.sign(Buffer.from("Content-Type: text/plain;\r\n hp=\"clear\"\r\nSubject: folded hp\r\n\r\nbody\n"), signers, { entity: true });
  var tamperedFold = Buffer.from(signedFold.toString("latin1").replace("\r\n hp=", "\r hp="), "latin1");
  var rf = await pki.smime.verify(tamperedFold);
  check("97u. a bare-CR fold before hp still verifies AND still surfaces header protection (no signal strip)", rf.valid === true && rf.protectedHeaders != null && rf.protectedHeaders.Subject === "folded hp");
  // (w) a transport that rewrites the payload's header/body separator (CRLFCRLF) to bare CRs still verifies
  // (the canonicalizer repairs it) -- HP detection AND parsing run on that same canonical form, so a valid
  // message surfaces its authenticated headers rather than false-rejecting as an unparseable block.
  var signedSep = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp=\"clear\"\r\nSubject: sep test\r\n\r\nbody\n"), signers, { entity: true });
  var tamperedSep = Buffer.from(signedSep.toString("latin1").replace("sep test\r\n\r\nbody", "sep test\r\rbody"), "latin1");
  var rs = await pki.smime.verify(tamperedSep).then(function (r) { return r; }, function (e) { return { err: e.code }; });
  check("97v. a bare-CR header/body separator still verifies AND surfaces HP (parse the canonical entity)", rs.valid === true && rs.protectedHeaders != null && rs.protectedHeaders.Subject === "sep test");
  // (x) an hp= inside a MIME comment in the Content-Type is NOT the hp parameter (comment-aware probe + parse):
  // an ordinary commented Content-Type must not opt a valid signature into HP processing / false-reject.
  var commented = await pki.smime.sign(Buffer.from("Content-Type: text/plain; charset=us-ascii (note; hp=fake)\r\nSubject: c\r\n\r\nbody\n"), signers, { entity: true });
  var rcm = await pki.smime.verify(commented).then(function (r) { return r; }, function (e) { return { err: e.code }; });
  check("97w. an hp= inside a MIME comment does not opt into HP (valid signature returned, not false-rejected)", rcm.valid === true && rcm.protectedHeaders === null);
  // (y) a signed entity with NO Content-Type field is not header-protected (the probe finds no Content-Type line).
  var noCt = await pki.smime.sign(Buffer.from("Subject: no ct\r\n\r\nbody\n"), signers, { entity: true });
  check("97x. a signed entity without a Content-Type is not treated as header-protected", (await pki.smime.verify(noCt)).protectedHeaders === null);
  // (z) a MIME comment BETWEEN Content-Type parameters is CFWS -- the real hp parameter is still detected (no downgrade).
  var cfws = await pki.smime.sign(Buffer.from("Content-Type: text/plain; (note) hp=\"clear\"\r\nSubject: cfws\r\n\r\nbody\n"), signers, { entity: true });
  check("97y. a comment between Content-Type parameters does not hide hp (no downgrade)", (await pki.smime.verify(cfws)).protectedHeaders != null && (await pki.smime.verify(cfws)).protectedHeaders.Subject === "cfws");
  // (aa) opts.headers is snapshotted ONCE: an accessor/Proxy returning a different value on each read cannot make the
  // signed inner header diverge from the displayed outer copy (the authenticated value must be the one displayed).
  var reads = 0, proxyHeaders = { get Subject() { reads++; return "S" + reads; } };
  var signedProxy = await pki.smime.sign(HB, signers, { protectHeaders: true, headers: proxyHeaders });
  var vp = await pki.smime.verify(signedProxy);
  check("97z. an accessor-valued protected header is read once (signed inner == displayed outer)", signedProxy.toString("latin1").split("Subject: " + vp.protectedHeaders.Subject).length - 1 === 2);
  // (bb) the hp keyword is case-insensitive (RFC 2045 sec. 5.1): a peer that emits hp="CLEAR" is still recognized.
  var upperHp = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp=\"CLEAR\"\r\nSubject: upper hp\r\n\r\nbody\n"), signers, { entity: true });
  var vUpper = await pki.smime.verify(upperHp).then(function (r) { return r; }, function (e) { return { err: e.code }; });
  check("97aa. an uppercase hp value is recognized as header protection (case-insensitive keyword)", vUpper.protectedHeaders != null && vUpper.protectedHeaders.Subject === "upper hp");
  // (cc) a bare hp attribute with no value is a malformed HP declaration -- fail closed, never a silent downgrade.
  var bareHp = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp\r\nSubject: bare\r\n\r\nbody\n"), signers, { entity: true });
  var vBare = await pki.smime.verify(bareHp).then(function (r) { return r; }, function (e) { return { err: e.code }; });
  check("97bb. a bare hp parameter (no value) fails closed (smime/bad-header-protection), not a silent downgrade", vBare.err === "smime/bad-header-protection");
  // (dd) a bare hp attribute in opts.contentType is rejected at the producer (would else emit "hp; hp=\"clear\"").
  check("97cc. a bare hp attribute in opts.contentType is rejected (producer)", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, contentType: "text/plain; hp", headers: { Subject: "x" } }); })) === "smime/bad-input");
  // (ee) a bare+valued hp duplicate ("hp; hp=\"clear\"") is an ambiguous duplicate -- the verifier fails closed.
  var bvDupHp = await pki.smime.sign(Buffer.from("Content-Type: text/plain; hp; hp=\"clear\"\r\nSubject: d\r\n\r\nbody\n"), signers, { entity: true });
  var vDup = await pki.smime.verify(bvDupHp).then(function (r) { return r; }, function (e) { return { err: e.code }; });
  check("97dd. a bare+valued hp duplicate fails closed (verifier)", vDup.err === "smime/bad-header-protection");
  // (ff) the protected-From mismatch is compared BYTE-EXACT: a legacy-8bit signed From (octet 0x80) and an
  // attacker-modified outer From (octet 0x81) both lossy-decode to the same replacement char, so a lossy
  // compare would miss the tamper -- the byte-preserving compare trips fromMismatch.
  var b80 = String.fromCharCode(0x80), b81 = String.fromCharCode(0x81);
  var innerFromEnt = "Content-Type: text/plain; hp=\"clear\"\r\nFrom: " + b80 + "@e.example\r\nSubject: s\r\n\r\nbody\n";
  var signedFromMsg = await pki.smime.sign(Buffer.from(innerFromEnt, "latin1"), signers, { entity: true });
  var sfs = signedFromMsg.toString("latin1"), sep = sfs.indexOf("\r\n\r\n");
  var tamperedFrom = Buffer.from(sfs.slice(0, sep) + "\r\nFrom: " + b81 + "@e.example" + sfs.slice(sep), "latin1");
  var vFrom = await pki.smime.verify(tamperedFrom).then(function (r) { return r; }, function (e) { return { err: e.code }; });
  check("97ee. a one-octet-different invalid-UTF8 outer From trips fromMismatch (byte-exact compare)", vFrom.valid === true && vFrom.headerProtection != null && vFrom.headerProtection.fromMismatch === true);

  // (gg) RFC 9788 sec. 2.2: an ENCRYPTED header-protected payload embeds HP-Outer records for each Non-Structural
  // field left visible in the outer section (exact outer value), and NONE for a field the HCP removed. decrypt
  // consumes them: they never surface as a protected header, and per sec. 4.3.1 the confidential set is the fields
  // NOT copied verbatim to the outer (obscured or removed).
  var hoEnc = await pki.smime.encrypt(Buffer.from("secret\n"), [{ cert: eRsa.cert }], { protectHeaders: true, hcp: "hcp_baseline", headers: { Subject: "Real subject", From: "Bob <bob@e.example>", To: "Alice <alice@e.example>", Keywords: "Contract" } });
  var hoDec = await pki.smime.decrypt(hoEnc, { key: eRsa.key, cert: eRsa.cert });
  var hoPayload = hoDec.content.toString("latin1");
  check("97ff. an encrypted HP payload carries HP-Outer for exposed fields and none for HCP-removed ones (RFC 9788 sec. 2.2)", /^HP-Outer: From: Bob <bob@e.example>$/m.test(hoPayload) && /^HP-Outer: To: Alice <alice@e.example>$/m.test(hoPayload) && /^HP-Outer: Subject: \[\.\.\.\]$/m.test(hoPayload) && /^HP-Outer: Keywords:/m.test(hoPayload) === false);
  check("97gg. decrypt never surfaces HP-Outer as a protected header, and surfaces the real fields", ("HP-Outer" in hoDec.protectedHeaders) === false && hoDec.protectedHeaders.Subject === "Real subject" && hoDec.protectedHeaders.Keywords === "Contract");
  check("97hh. the confidential set (sec. 4.3.1) is the obscured/removed fields, not the verbatim ones", hoDec.headerProtection.confidential.indexOf("Subject") >= 0 && hoDec.headerProtection.confidential.indexOf("Keywords") >= 0 && hoDec.headerProtection.confidential.indexOf("From") < 0 && hoDec.headerProtection.confidential.indexOf("To") < 0);
  // (hh) a conformant encrypted message carrying MULTIPLE HP-Outer records decrypts cleanly (not false-rejected
  // as a duplicate field), and a signed-only (clear) payload carries no HP-Outer.
  var multiHoEntity = "Content-Type: text/plain; charset=utf-8; hp=\"cipher\"\r\nFrom: bob@e.example\r\nSubject: Real\r\nHP-Outer: From: bob@e.example\r\nHP-Outer: Subject: [...]\r\nHP-Outer: malformed-no-inner-colon\r\n\r\nbody\n";
  var multiHoEnc = await pki.smime.encrypt(Buffer.from(multiHoEntity, "latin1"), [{ cert: eRsa.cert }], { entity: true });
  var multiHoDec = await pki.smime.decrypt(multiHoEnc, { key: eRsa.key, cert: eRsa.cert }).then(function (r) { return r; }, function (e) { return { err: e.code }; });
  check("97ii. a multi-HP-Outer conformant message decrypts cleanly (not a false duplicate reject)", multiHoDec.err === undefined && multiHoDec.headerProtection.present === true && ("HP-Outer" in multiHoDec.protectedHeaders) === false && multiHoDec.headerProtection.confidential.indexOf("Subject") >= 0 && multiHoDec.headerProtection.confidential.indexOf("From") < 0);
  check("97jj. a signed-only (clear) header-protected message carries no HP-Outer (RFC 9788 sec. 2.2)", /HP-Outer:/i.test((await pki.smime.sign(HB, signers, { protectHeaders: true, headers: { Subject: "S" } })).toString("latin1")) === false);
  // (ii) a protected header value's leading/trailing whitespace is preserved (mime.parse trims value, rawValue does not).
  var wsHp = await pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "X-Token": "  spaced  " } });
  check("97kk. a protected header value's surrounding whitespace round-trips exactly", (await pki.smime.verify(wsHp)).protectedHeaders["X-Token"] === "  spaced  ");
  // (jj) HP-Outer is reserved for the library; a caller cannot supply it in opts.headers.
  check("97ll. a caller-supplied HP-Outer in opts.headers is rejected (reserved field)", (await codeOf(function () { return pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "HP-Outer": "From: x" } }); })) === "smime/bad-input");
  // (kk) the confidential determination is OCTET-EXACT: a protected field whose only difference from its HP-Outer
  // value is an invalid-UTF8 octet (0x80 vs 0x81) was obscured, so it must be confidential -- a lossy decode would
  // collapse both to the replacement char and wrongly mark it exposed (a reply/forward leak). Reuse b80/b81.
  var confEntity = "Content-Type: text/plain; charset=utf-8; hp=\"cipher\"\r\nX-Sec: " + b80 + "@x\r\nHP-Outer: X-Sec: " + b81 + "@x\r\n\r\nbody\n";
  var confEnc = await pki.smime.encrypt(Buffer.from(confEntity, "latin1"), [{ cert: eRsa.cert }], { entity: true });
  var confDec = await pki.smime.decrypt(confEnc, { key: eRsa.key, cert: eRsa.cert });
  check("97mm. a field obscured by only an invalid-UTF8 octet is confidential (octet-exact HP-Outer compare)", confDec.headerProtection.confidential.indexOf("X-Sec") >= 0);

  // protectHeaders with no/empty headers (an hp marker + no protected fields) + null header values.
  var emptyHp = await pki.smime.sign(HB, signers, { protectHeaders: true });
  check("98. protectHeaders with no opts.headers still emits hp + verifies", /hp="clear"/.test(emptyHp.toString("latin1")) && (await pki.smime.verify(emptyHp)).headerProtection.present === true);
  check("98. an object header with a null value is emitted empty", (await pki.smime.verify(await pki.smime.sign(HB, signers, { protectHeaders: true, headers: { "X-Empty": null } }))).protectedHeaders["X-Empty"] === "");
  check("98. an array header with a null value is emitted empty", (await pki.smime.verify(await pki.smime.sign(HB, signers, { protectHeaders: true, headers: [{ name: "X-Empty", value: null }] }))).protectedHeaders["X-Empty"] === "");

  // ==== INBOUND LEGACY RFC8551HP DETECTION (RFC 9788 sec. 4.10) ===================================
  // A legacy RFC 8551 header-protected message wraps the real message as a message/rfc822 Cryptographic
  // Payload with NO hp= parameter anywhere. sec. 4.10.1 identifies it by four conjunctive conditions;
  // sec. 4.10.2 surfaces part D's (the inner message's) headers with the mode inferred from the envelope.
  // Detect-ONLY, opt-in (opts.legacyHeaderProtection). CRUCIAL SAFETY PROPERTY: a legacy RFC8551HP message is
  // structurally INDISTINGUISHABLE from an ordinary signed/forwarded message/rfc822, so the inference is NEVER
  // placed in protectedHeaders and NEVER sets present:true -- it is surfaced ONLY under headerProtection.legacy
  // (its own { headers, mode, fromMismatch, confidential } object). A caller keying trust off present /
  // protectedHeaders can never mistake the opt-in heuristic for this message's authenticated headers.
  var LEG_ON = { legacyHeaderProtection: true };
  // headerProtection.legacy.headers is an ORDERED array of { name, value } (retains legally-repeated fields);
  // look a value up (first occurrence) / count occurrences by name.
  var legVal = function (r, n) { var l = r.headerProtection.legacy; if (!l) return undefined; for (var i = 0; i < l.headers.length; i++) if (l.headers[i].name === n) return l.headers[i].value; return undefined; };
  var legCount = function (r, n) { var l = r.headerProtection.legacy; if (!l) return 0; var c = 0; for (var i = 0; i < l.headers.length; i++) if (l.headers[i].name === n) c++; return c; };
  // part D: an ordinary RFC 5322 message -- Non-Structural From/To/Subject/Date + its own Structural Content-Type.
  var partD = "From: alice@in.example\r\nTo: bob@in.example\r\nSubject: smime-one-part-complex-rfc8551hp\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nThe real body.\r\n";
  // part C: the message/rfc822 Cryptographic Payload wrapping part D.
  var partC = Buffer.from("Content-Type: message/rfc822\r\n\r\n" + partD, "latin1");
  var legSignedRaw = await pki.smime.sign(partC, signers, { entity: true, form: "pkcs7-mime" });
  // Prepend the visible outer display header section (part A) with a From matching part D's -- a real received
  // legacy message carries the outer headers; a matching outer From must NOT flag fromMismatch.
  var legSigned = Buffer.from("From: alice@in.example\r\nTo: bob@in.example\r\nSubject: [obscured]\r\n" + legSignedRaw.toString("latin1"), "latin1");
  var lv = await pki.smime.verify(legSigned, LEG_ON);
  check("99. a legacy pkcs7-mime message/rfc822 wrap verifies valid", lv.valid === true);
  // SAFE-BY-DEFAULT: the inferred set is NOT in protectedHeaders and present stays false (a naive consumer is never misled).
  check("99. a legacy inference never populates protectedHeaders and never sets present:true", lv.protectedHeaders === null && lv.headerProtection.present === false);
  check("99. the inferred inner Subject is surfaced under headerProtection.legacy.headers", lv.headerProtection.legacy != null && legVal(lv, "Subject") === "smime-one-part-complex-rfc8551hp");
  check("99. legacy.headers surfaces the inner From + To + Date", legVal(lv, "From") === "alice@in.example" && legVal(lv, "To") === "bob@in.example" && legVal(lv, "Date") === "Mon, 1 Jan 2024 00:00:00 +0000");
  check("99. the mode is inferred clear (signed-only)", lv.headerProtection.legacy.mode === "clear");
  check("99. a signed-only legacy inference has no confidential fields", lv.headerProtection.legacy.confidential.length === 0);
  check("99. a matching outer From is not a mismatch", lv.headerProtection.legacy.fromMismatch === false);
  check("99. part D's Structural Content-Type is not surfaced as a legacy header", legVal(lv, "Content-Type") === undefined);

  // default-OFF tripwire: without the opt, the legacy-shaped message stays fully unprotected (legacy:null),
  // and the standard HP surface reports legacy:null.
  var lvOff = await pki.smime.verify(legSigned);
  check("100. legacy detection is OFF by default: protectedHeaders null, present false, legacy null", lvOff.protectedHeaders === null && lvOff.headerProtection.present === false && lvOff.headerProtection.legacy === null);
  check("100. the standard HP surface reports legacy:null", hv.headerProtection.legacy === null);

  // (V2) a legacy multipart/signed wrap: part C = the first body part.
  var legMpRaw = await pki.smime.sign(partC, signers, { entity: true, form: "multipart" });
  var legMp = Buffer.from("From: alice@in.example\r\n" + legMpRaw.toString("latin1"), "latin1");
  var lmv = await pki.smime.verify(legMp, LEG_ON);
  check("101. a legacy multipart/signed message/rfc822 wrap surfaces the inner headers under legacy (mode clear, present false)", lmv.valid === true && lmv.protectedHeaders === null && lmv.headerProtection.present === false && lmv.headerProtection.legacy != null && legVal(lmv, "Subject") === "smime-one-part-complex-rfc8551hp" && lmv.headerProtection.legacy.mode === "clear");

  // (V4/C3) part D that is ITSELF a Cryptographic Layer is not legacy (a genuinely nested signed/encrypted .eml).
  var mkLeg = function (pd) { return pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\n\r\n" + pd, "latin1"), signers, { entity: true, form: "pkcs7-mime" }); };
  var fpPkcs7 = await pki.smime.verify(await mkLeg("From: a@in.example\r\nSubject: fwd\r\nContent-Type: application/pkcs7-mime; smime-type=signed-data\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n"), LEG_ON);
  check("102. part D that is application/pkcs7-mime is NOT mis-detected as legacy (C3)", fpPkcs7.valid === true && fpPkcs7.protectedHeaders === null && fpPkcs7.headerProtection.legacy === null);
  var fpMpSigned = await pki.smime.verify(await mkLeg("Subject: fwd\r\nContent-Type: multipart/signed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n"), LEG_ON);
  check("102. part D that is multipart/signed is NOT mis-detected as legacy (C3)", fpMpSigned.protectedHeaders === null && fpMpSigned.headerProtection.legacy === null);
  var fpMpEnc = await pki.smime.verify(await mkLeg("Subject: fwd\r\nContent-Type: multipart/encrypted; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n"), LEG_ON);
  check("102. part D that is multipart/encrypted is NOT mis-detected as legacy (C3)", fpMpEnc.protectedHeaders === null && fpMpEnc.headerProtection.legacy === null);

  // (V5/C4) an hp= on part D means the message is NOT legacy (sec. 4.1: ignore hp outside the payload root).
  var hpDv = await pki.smime.verify(await mkLeg("From: a@in.example\r\nSubject: x\r\nContent-Type: text/plain; hp=\"clear\"\r\n\r\nbody\r\n"), LEG_ON);
  check("103. hp= on part D -> not legacy (C4): legacy null", hpDv.protectedHeaders === null && hpDv.headerProtection.legacy === null);

  // (V6/C2) a non-message/rfc822 payload is not legacy even with the opt on.
  var lvPlain = await pki.smime.verify(plain, LEG_ON);
  check("104. a non-message/rfc822 payload with the opt on -> legacy null (C2)", lvPlain.protectedHeaders === null && lvPlain.headerProtection.legacy === null);

  // (V7) a legacy candidate whose inner part D is UNPARSEABLE fails SOFT to null (no throw) -- swallow on its own line.
  var legBadD = await pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\n\r\nthis-inner-header-line-has-no-colon\r\n\r\nbody\r\n", "latin1"), signers, { entity: true, form: "pkcs7-mime" });
  check("105. a legacy candidate whose inner part D is unparseable -> legacy null (fail-soft, no throw)", (await pki.smime.verify(legBadD, LEG_ON)).headerProtection.legacy === null);

  // (dup singleton) a legacy wrap whose part D duplicates a SINGLETON field (RFC 5322 sec. 3.6 max-1: Subject,
  // From, To, Date, Message-ID, ...) is ambiguous -> fail SOFT to null (the legacy path never throws).
  var legDupD = await pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\n\r\nFrom: a@in.example\r\nSubject: one\r\nSubject: two\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1"), signers, { entity: true, form: "pkcs7-mime" });
  check("105b. a legacy part D with a duplicate SINGLETON field (Subject) -> legacy null (fail-soft, no throw)", (await pki.smime.verify(legDupD, LEG_ON)).headerProtection.legacy === null);
  // Return-Path is the envelope sender: RFC 5321 sec. 4.4 restricts a delivered message to a single one, so a
  // duplicate is as ambiguous as a duplicate From (a consumer could pick a different envelope sender) -> null.
  var legDupRP = await pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\n\r\nFrom: a@in.example\r\nSubject: x\r\nReturn-Path: <a@in.example>\r\nReturn-Path: <b@evil.example>\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1"), signers, { entity: true, form: "pkcs7-mime" });
  check("105h. a legacy part D with two Return-Path fields (ambiguous envelope sender) -> legacy null", (await pki.smime.verify(legDupRP, LEG_ON)).headerProtection.legacy === null);
  // A legally REPEATABLE field (RFC 5322 sec. 3.6 -- Received and other trace fields, Resent-*, Comments,
  // Keywords, optional/X-*) occurs many times in a real delivered message; its repetition must NOT reject the
  // inference (every received message carries multiple Received headers), or legacy detection would fail on
  // essentially all real-world mail. The singleton fields still surface; the repeated field does not reject.
  var legRepeatOK = await pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\n\r\nReceived: from mx1 by mx2\r\nReceived: from src by mx1\r\nFrom: alice@in.example\r\nSubject: repeated-received\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1"), signers, { entity: true, form: "pkcs7-mime" });
  var repv = await pki.smime.verify(legRepeatOK, LEG_ON);
  check("105f. a legacy part D with a legally repeated field (Received) is still surfaced, not rejected", repv.headerProtection.legacy != null && legVal(repv, "Subject") === "repeated-received" && legVal(repv, "From") === "alice@in.example");
  check("105f. BOTH Received occurrences are preserved in legacy.headers (not last-wins)", legCount(repv, "Received") === 2 && repv.headerProtection.legacy.headers[0].name === "Received" && repv.headerProtection.legacy.headers[0].value === "from mx1 by mx2");
  // a repeated field whose name collides with an Object.prototype member (Constructor / __proto__) must NOT be
  // mistaken for a singleton via a prototype-chain lookup -- it is a repeatable optional field, still surfaced.
  var legProto = await pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\n\r\nFrom: alice@in.example\r\nSubject: proto\r\nConstructor: a\r\nConstructor: b\r\n__proto__: x\r\n__proto__: y\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1"), signers, { entity: true, form: "pkcs7-mime" });
  var protov = await pki.smime.verify(legProto, LEG_ON);
  check("105g. a repeated field colliding with an Object.prototype name (Constructor/__proto__) is not a false singleton", protov.headerProtection.legacy != null && legVal(protov, "Subject") === "proto" && legCount(protov, "Constructor") === 2 && legCount(protov, "__proto__") === 2);

  // (dup Content-Type) the C2-C4 classification reads only the FIRST Content-Type (mime.parse surfaces the
  // first field), so a part with TWO Content-Type fields is ambiguous: a later one could carry hp= or a crypto
  // media type the first-field checks miss. A duplicate Content-Type on part C OR part D -> fail SOFT to null,
  // matching the standard path's duplicate-Content-Type reject, so the classification cannot depend on which
  // field a parser happens to read.
  var legDupCtHpD = await pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\n\r\nFrom: a@in.example\r\nSubject: x\r\nContent-Type: text/plain\r\nContent-Type: text/plain; hp=\"clear\"\r\n\r\nbody\r\n", "latin1"), signers, { entity: true, form: "pkcs7-mime" });
  check("105c. part D with a duplicate Content-Type whose LATER field carries hp= -> legacy null (not first-field legacy)", (await pki.smime.verify(legDupCtHpD, LEG_ON)).headerProtection.legacy === null);
  var legDupCtCryptoD = await pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\n\r\nFrom: a@in.example\r\nSubject: x\r\nContent-Type: text/plain\r\nContent-Type: application/pkcs7-mime; smime-type=signed-data\r\n\r\nbody\r\n", "latin1"), signers, { entity: true, form: "pkcs7-mime" });
  check("105d. part D with a duplicate Content-Type whose LATER field is a crypto layer -> legacy null (C3 cannot be evaded)", (await pki.smime.verify(legDupCtCryptoD, LEG_ON)).headerProtection.legacy === null);
  var legDupCtC = await pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\nContent-Type: text/plain\r\n\r\nFrom: a@in.example\r\nSubject: x\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1"), signers, { entity: true, form: "pkcs7-mime" });
  check("105e. part C with a duplicate Content-Type -> legacy null (C2 cannot depend on the first field)", (await pki.smime.verify(legDupCtC, LEG_ON)).headerProtection.legacy === null);

  // (empty) a legacy wrap whose part D carries no Non-Structural fields has nothing to surface -> null.
  var legEmpty = await pki.smime.sign(Buffer.from("Content-Type: message/rfc822\r\n\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\njust a body\r\n", "latin1"), signers, { entity: true, form: "pkcs7-mime" });
  check("106. a legacy wrap whose part D has no Non-Structural fields -> legacy null", (await pki.smime.verify(legEmpty, LEG_ON)).headerProtection.legacy === null);

  // (V8) fromMismatch: an outer From differing from (or missing against) part D's inner From is flagged on the
  // legacy sub-object (a forwarded .eml's inner sender differs from the actual outer sender -> the caller is warned).
  var mmv = await pki.smime.verify(Buffer.from("From: mallory@evil.example\r\n" + legSignedRaw.toString("latin1"), "latin1"), LEG_ON);
  check("107. a legacy outer From differing from the inner From is flagged legacy.fromMismatch (inner From unchanged)", mmv.headerProtection.legacy != null && mmv.headerProtection.legacy.fromMismatch === true && legVal(mmv, "From") === "alice@in.example");
  var legNoFrom = await pki.smime.verify(legSignedRaw, LEG_ON);
  check("107. a legacy message with no outer From (an inferred inner From) is flagged legacy.fromMismatch", legNoFrom.headerProtection.legacy != null && legNoFrom.headerProtection.legacy.fromMismatch === true);

  // (V9) cipher: decrypt legacy-detects an ENCRYPTED message/rfc822 wrap (authEnveloped -> authenticated). The
  // confidential set is derived from part A (the visible outer section): a field copied verbatim outside is
  // exposed; an obscured/removed one is confidential (sec. 4.3.1, applied to the actual outer headers).
  var legEncRaw = await pki.smime.encrypt(partC, [{ cert: rcpt.cert }], { entity: true });
  var legEnc = Buffer.from("From: alice@in.example\r\nSubject: [obscured]\r\n" + legEncRaw.toString("latin1"), "latin1");
  var lev = await pki.smime.decrypt(legEnc, { key: rcpt.key, cert: rcpt.cert }, LEG_ON);
  check("108. decrypt legacy-detects an encrypted message/rfc822 wrap under legacy (mode cipher, present false)", lev.headerProtection.present === false && lev.protectedHeaders === null && lev.headerProtection.legacy != null && lev.headerProtection.legacy.mode === "cipher" && legVal(lev, "Subject") === "smime-one-part-complex-rfc8551hp");
  check("108. the legacy confidential set names the obscured Subject, not the exposed (verbatim outer) From", lev.headerProtection.legacy.confidential.indexOf("Subject") >= 0 && lev.headerProtection.legacy.confidential.indexOf("From") < 0);
  // (confidentiality of a REPEATED field) an encrypted legacy message repeats a legal field with one obscured
  // and one exposed value (Keywords: secret / Keywords: public); the outer section exposes ONLY "public". A
  // last-wins map would keep only "public" and wrongly report Keywords non-confidential -- leaking "secret" if a
  // caller replies/forwards. The per-occurrence (multiset) match reports Keywords confidential (secret is hidden).
  var partCkw = Buffer.from("Content-Type: message/rfc822\r\n\r\nFrom: alice@in.example\r\nSubject: kw-test\r\nKeywords: secret\r\nKeywords: public\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1");
  var kwEncRaw = await pki.smime.encrypt(partCkw, [{ cert: rcpt.cert }], { entity: true });
  var kwEnc = Buffer.from("From: alice@in.example\r\nKeywords: public\r\n" + kwEncRaw.toString("latin1"), "latin1");
  var kwv = await pki.smime.decrypt(kwEnc, { key: rcpt.key, cert: rcpt.cert }, LEG_ON);
  check("108b. a repeated field with one obscured occurrence is confidential even when another occurrence is exposed", kwv.headerProtection.legacy != null && kwv.headerProtection.legacy.confidential.indexOf("Keywords") >= 0 && legCount(kwv, "Keywords") === 2);
  // ...and a repeated field whose occurrences are ALL exposed verbatim outside is not confidential.
  var partCkw2 = Buffer.from("Content-Type: message/rfc822\r\n\r\nFrom: alice@in.example\r\nSubject: [obscured]\r\nKeywords: a\r\nKeywords: b\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1");
  var kw2EncRaw = await pki.smime.encrypt(partCkw2, [{ cert: rcpt.cert }], { entity: true });
  var kw2Enc = Buffer.from("From: alice@in.example\r\nKeywords: a\r\nKeywords: b\r\n" + kw2EncRaw.toString("latin1"), "latin1");
  var kw2v = await pki.smime.decrypt(kw2Enc, { key: rcpt.key, cert: rcpt.cert }, LEG_ON);
  check("108c. a repeated field with every occurrence exposed verbatim outside is not confidential", kw2v.headerProtection.legacy.confidential.indexOf("Keywords") < 0 && kw2v.headerProtection.legacy.confidential.indexOf("Subject") >= 0);
  // multiset COUNTING (not set membership): 3 identical inner Keywords, only 2 exposed outside -> the third is
  // confidential (each outer occurrence accounts for at most one inner). This also exercises the O(N+M) index path.
  var partCkw3 = Buffer.from("Content-Type: message/rfc822\r\n\r\nFrom: alice@in.example\r\nSubject: [obscured]\r\nKeywords: x\r\nKeywords: x\r\nKeywords: x\r\nContent-Type: text/plain\r\n\r\nbody\r\n", "latin1");
  var kw3EncRaw = await pki.smime.encrypt(partCkw3, [{ cert: rcpt.cert }], { entity: true });
  var kw3Enc = Buffer.from("From: alice@in.example\r\nKeywords: x\r\nKeywords: x\r\n" + kw3EncRaw.toString("latin1"), "latin1");
  var kw3v = await pki.smime.decrypt(kw3Enc, { key: rcpt.key, cert: rcpt.cert }, LEG_ON);
  check("108d. multiset counting: 3 identical inner occurrences with only 2 exposed outside -> confidential", kw3v.headerProtection.legacy.confidential.indexOf("Keywords") >= 0 && legCount(kw3v, "Keywords") === 3);

  // (V10) the signed-and-encrypted (C.3.17) form: the non-recursive decrypt yields a signed-data blob, not a
  // message/rfc822 -> the documented deferral holds (legacy stays null rather than a mis-labeled inference).
  var signedInner = await pki.smime.sign(partC, signers, { entity: true, form: "pkcs7-mime" });
  var encOfSigned = await pki.smime.encrypt(signedInner, [{ cert: rcpt.cert }], { entity: true });
  var c317 = await pki.smime.decrypt(encOfSigned, { key: rcpt.key, cert: rcpt.cert }, LEG_ON);
  check("109. a signed-then-encrypted (C.3.17) wrap: decrypt yields a signed-data blob, not message/rfc822 -> deferral holds (legacy null)", c317.protectedHeaders === null && c317.headerProtection.legacy === null);

  // ---- the option surface each verb accepts ----
  // A misspelled option reads as an omission: nothing is out of range and nothing fails to parse, so
  // the caller who asked for something stricter gets the looser default and is told nothing.
  //
  // The accepted set is checked against the DOCUMENTED one rather than against a list repeated here,
  // and it is checked through the verb: every key the @opts block names is passed (with an undefined
  // value, which is a present key to the guard and a default to the verb) and must not be refused as
  // unknown. A name in the docs that the guard does not carry fails here, which is the drift worth
  // catching -- an operator reading the documentation and getting an error.
  // Read OFF the documentation blocks rather than repeated here: a list copied into the test drifts
  // from the one an operator reads, which is the drift this is for.
  var DOCUMENTED = docOptsOf(require("path").join(__dirname, "..", "..", "lib", "smime.js"));
  check("110a. the documented option surface was recovered for all seven verbs",
    Object.keys(DOCUMENTED).length === 7 && Object.keys(DOCUMENTED).every(function (v) { return DOCUMENTED[v].length > 0; }));
  var enc1 = await pki.smime.encrypt(MSG, [{ cert: rcpt.cert }]);
  var z1 = await pki.smime.compress(MSG);
  var drive = {
    sign: function (o) { return pki.smime.sign(MSG, signers, o); },
    verify: function (o) { return pki.smime.verify(mp, o); },
    encrypt: function (o) { return pki.smime.encrypt(MSG, [{ cert: rcpt.cert }], o); },
    decrypt: function (o) { return pki.smime.decrypt(enc1, { key: rcpt.key, cert: rcpt.cert }, o); },
    compress: function (o) { return pki.smime.compress(MSG, o); },
    decompress: function (o) { return pki.smime.decompress(z1, o); },
    buildCertsOnly: function (o) { return pki.smime.buildCertsOnly([rcpt.cert], o); },
  };
  for (var verb of Object.keys(DOCUMENTED)) {
    var accepted = true, rejectedName = null;
    for (var k of DOCUMENTED[verb]) {
      var o = {};
      o[k] = undefined;
      var code = await codeOf(function () { return drive[verb](o); });
      // Some keys reach real validation with an undefined value; only the unknown-option refusal is
      // the failure this vector is about, and its message names the key.
      if (code === "smime/bad-input") {
        var msg = await (async function () { try { await drive[verb](o); return ""; } catch (e) { return e.message; } })();
        if (msg.indexOf("unknown option") === 0) { accepted = false; rejectedName = k; }
      }
    }
    check("110. every documented pki.smime." + verb + " option is accepted" +
      (rejectedName ? " (refused: " + rejectedName + ")" : ""), accepted === true);
    var bad = {};
    bad[DOCUMENTED[verb][0] + "Z"] = 1;
    check("111. pki.smime." + verb + " refuses an unknown option",
      (await codeOf(function () { return drive[verb](bad); })) === "smime/bad-input");
  }
  // The near-miss that motivates it: a misspelling of the option that turns a check ON is otherwise
  // indistinguishable from not asking for the check at all.
  check("112. a misspelled strictMicalg is refused, not silently ignored",
    (await codeOf(function () { return pki.smime.verify(mp, { strictMicalgo: true }); })) === "smime/bad-input");
  check("113. ...and the verb still accepts the correctly-spelled one",
    (await codeOf(function () { return pki.smime.verify(mp, { strictMicalg: true }); })) === "NO-THROW");
  // The tables are per verb: sign's `form` means nothing to encrypt, and a merged table would accept
  // it there -- the same silence in a wider form.
  check("114. an option belonging to another verb is refused",
    (await codeOf(function () { return pki.smime.encrypt(MSG, [{ cert: rcpt.cert }], { form: "multipart" }); })) === "smime/bad-input");

  // ---- the signer is bound to a sender identity, and the verdict says whether anyone asked ----
  // A signature proves a key signed; it does not prove the message came from the mailbox the
  // reader sees. Without this the relying party's only sender signal was fromMismatch, which
  // was hard-false on every message without header protection -- i.e. essentially all mail --
  // so `valid && !fromMismatch` read as a verified sender over an unverified one.
  var idPair = await pki.key.generate("Ed25519");
  var idKey = await pki.key.export(idPair.privateKey);
  var idCert = await pki.x509.sign({
    subject: "Alice", subjectPublicKey: await pki.key.export(idPair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { subjectAltName: [{ rfc822Name: "alice@corp.example" }] },
  }, { key: idKey });
  var idMsg = await pki.smime.sign(MSG, [{ cert: idCert, key: idKey }]);
  // sender.match requires a TRUSTED signer, so every fixture below names its own
  // self-signed certificate as the anchor. Without one nothing is trusted and the binding
  // question is unanswered -- which is vector 136 below, on purpose.
  async function senderOf(o) {
    return (await pki.smime.verify(idMsg, Object.assign({ trustAnchors: [idCert] }, o))).sender;
  }
  async function senderOfOuter(hdrs, o) {
    return (await pki.smime.verify(withOuter(idMsg, hdrs),
      Object.assign({ trustAnchors: [idCert] }, o))).sender;
  }

  var sMatch = await senderOf({ expectedSender: "alice@corp.example" });
  check("115. expectedSender matching the certificate's rfc822Name binds the signer",
    sMatch.match === true && sMatch.checked === true && sMatch.source === "expectedSender");
  check("116. the identities the certificate asserts are surfaced",
    sMatch.identities.length === 1 && sMatch.identities[0] === "alice@corp.example");
  check("117. a different mailbox does not bind",
    (await senderOf({ expectedSender: "bob@victim.example" })).match === false);
  // RFC 5280 sec. 7.5: host-part case-insensitive, local-part exact. Folding the local-part
  // too would let one mailbox answer for another at the same domain.
  check("118. the host-part compares case-insensitively",
    (await senderOf({ expectedSender: "alice@CORP.EXAMPLE" })).match === true);
  check("119. the local-part compares case-sensitively",
    (await senderOf({ expectedSender: "Alice@corp.example" })).match === false);
  // The field that distinguishes "checked and agreed" from "nobody asked".
  var sNone = await senderOf({});
  check("120. with no expectedSender and no outer From, the binding is unchecked, never false",
    sNone.checked === false && sNone.match === null);
  // A signer whose certificate asserts no email identity cannot answer the question either --
  // and that must not read as a clean no-match.
  var plainMsg = await pki.smime.sign(MSG, signers);
  var sNoId = (await pki.smime.verify(plainMsg, { trustAnchors: [rsa.cert], expectedSender: "alice@corp.example" })).sender;
  check("121. a certificate asserting no email identity reports undecidable, not no-match",
    sNoId.checked === true && sNoId.match === null && sNoId.identities.length === 0);

  // The advisory branch. pki.smime.sign emits only the MIME framing -- a real MUA prepends the
  // RFC 5322 envelope -- so the outer From is prepended here the way a mail agent would.
  function withOuter(msgBytes, hdrs) {
    return Buffer.concat([Buffer.from(hdrs.join("\r\n") + "\r\n", "latin1"), msgBytes]);
  }
  var fromOk = await senderOfOuter(["From: alice@corp.example"]);
  check("123. a single outer From is used when no expectedSender is given, and reports itself advisory",
    fromOk.checked === true && fromOk.source === "from" && fromOk.match === true);
  var fromSpoof = await senderOfOuter(["From: bob@victim.example"]);
  check("124. an outer From the signer's certificate does not assert does not bind",
    fromSpoof.match === false && fromSpoof.source === "from");
  // A display-name form is the common real-world shape; the addr-spec inside is what compares.
  var fromDisplay = await senderOfOuter(["From: Alice <alice@corp.example>"]);
  check("125. a display-name From compares on the addr-spec inside the angle brackets",
    fromDisplay.match === true);
  // Two From headers give no unambiguous sender, so the question stays unanswered.
  var fromTwo = await senderOfOuter(["From: alice@corp.example", "From: bob@victim.example"]);
  check("126. an ambiguous (repeated) From is not compared at all",
    fromTwo.checked === false && fromTwo.match === null);
  // expectedSender is authoritative: a hostile outer From must not override it.
  var bothGiven = await senderOfOuter(["From: bob@victim.example"],
    { expectedSender: "alice@corp.example" });
  check("127. expectedSender wins over the outer From",
    bothGiven.source === "expectedSender" && bothGiven.match === true);

  // A mistyped expectedSender is a caller bug, refused at the door. Coercing it with
  // String() would accept any object carrying a toString, so a value that is not the
  // address the caller thinks it is could still drive sender.match to true.
  check("128. a non-string expectedSender is refused, never coerced",
    (await codeOf(function () {
      return pki.smime.verify(idMsg, { expectedSender: { toString: function () { return "alice@corp.example"; } } });
    })) === "smime/bad-input");
  check("129. a numeric expectedSender is refused",
    (await codeOf(function () { return pki.smime.verify(idMsg, { expectedSender: 42 }); })) === "smime/bad-input");

  // fromMismatch is tri-state: null when no protected From existed to compare against.
  // One From field can still name two mailboxes. Taking the angle address and ignoring what
  // follows would report a single compared sender over a field that named more than one.
  var fromTrailing = await senderOfOuter(["From: Alice <alice@corp.example>, mallory@victim.example"]);
  check("129c. a From with an address after the angle address is not compared",
    fromTrailing.checked === false && fromTrailing.match === null);

  // A signer whose signature did NOT verify must contribute no identity. cms.verify reports
  // every matched signer including failures (ok:false), so harvesting their subjectAltName
  // would let a tampered message read valid:false alongside sender.match:true -- and
  // sender.match === true is exactly what this verb tells a caller to enforce.
  var tamperedId = Buffer.from(idMsg);
  var textAt = tamperedId.indexOf(Buffer.from("Hello S/MIME"));
  check("129b. the signed text is locatable for the tamper vector", textAt > 0);
  tamperedId[textAt] = tamperedId[textAt] === 0x48 ? 0x68 : 0x48;   // H <-> h
  var tamperedRes = await pki.smime.verify(tamperedId, { expectedSender: "alice@corp.example" });
  check("130. tampering makes the signature invalid", tamperedRes.valid === false);
  check("131. ...and an unverified signer contributes no identity, so the binding is not true",
    tamperedRes.sender.match !== true);

  // RFC 8550 sec. 3: the address SHOULD be in subjectAltName, but a receiving agent "MUST
  // recognize email addresses in the distinguished name field in the PKCS #9 emailAddress
  // attribute". Reading only the extension leaves every certificate of that legacy shape
  // permanently undecidable, which makes expectedSender unusable for that whole class.
  var legacyPair = await pki.key.generate("Ed25519");
  var legacyKey = await pki.key.export(legacyPair.privateKey);
  var legacyCert = await pki.x509.sign({
    subject: [{ emailAddress: "legacy@corp.example" }],
    subjectPublicKey: await pki.key.export(legacyPair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
  }, { key: legacyKey });
  var legacyMsg = await pki.smime.sign(MSG, [{ cert: legacyCert, key: legacyKey }]);
  var legacyOk = (await pki.smime.verify(legacyMsg, { trustAnchors: [legacyCert], expectedSender: "legacy@corp.example" })).sender;
  check("132. an email identity carried only in the subject DN is recognized",
    legacyOk.match === true && legacyOk.identities.indexOf("legacy@corp.example") !== -1);
  check("133. ...and still answers false for a different mailbox",
    (await pki.smime.verify(legacyMsg, { trustAnchors: [legacyCert], expectedSender: "other@corp.example" })).sender.match === false);

  // When both carriers are present and disagree, the extension is authoritative (RFC 8550
  // sec. 3: SHOULD be in subjectAltName, SHOULD NOT be in the subject). Merging them would
  // let the weaker of two conflicting identities satisfy expectedSender.
  var bothPair = await pki.key.generate("Ed25519");
  var bothKey = await pki.key.export(bothPair.privateKey);
  var bothCert = await pki.x509.sign({
    subject: [{ emailAddress: "stale@old.example" }],
    subjectPublicKey: await pki.key.export(bothPair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { subjectAltName: [{ rfc822Name: "current@corp.example" }] },
  }, { key: bothKey });
  var bothMsg = await pki.smime.sign(MSG, [{ cert: bothCert, key: bothKey }]);
  check("134. the SAN address wins when the subject DN disagrees",
    (await pki.smime.verify(bothMsg, { trustAnchors: [bothCert], expectedSender: "current@corp.example" })).sender.match === true);
  check("135. ...and the conflicting subject DN address does not bind",
    (await pki.smime.verify(bothMsg, { trustAnchors: [bothCert], expectedSender: "stale@old.example" })).sender.match === false);

  // The trust gate. A signature verifying under the certificate that carries it proves
  // nothing about who sent the message: anyone can self-sign a certificate naming the
  // victim's address. With no anchor named, nothing is trusted, so the binding question is
  // unanswered rather than answered from an unvetted certificate.
  check("136. with no trustAnchors, a self-signed signer yields no positive binding",
    (await pki.smime.verify(idMsg, { expectedSender: "alice@corp.example" })).sender.match === null);
  // Two A-labels are the same encoding and need no IDNA transform to compare.
  check("137. two addresses already in A-label form compare normally",
    require("../../lib/guard-name").emailEqual("u@xn--bcher-kva.example", "u@XN--BCHER-KVA.EXAMPLE") === "match");
  // The question is existential, so an unrelated identity the comparison cannot read must
  // not erase an exact match that already answered it.
  check("138. an uncomparable second identity does not erase an exact match",
    (function () {
      var g = require("../../lib/guard-name");
      return g.emailEqual("alice@corp.example", "alice@corp.example") === "match" &&
        g.emailEqual("x@" + String.fromCharCode(0x43f) + ".example", "alice@corp.example") === "not-comparable";
    })());

  // An SmtpUTF8Mailbox SAN (RFC 8398 sec. 3) is an authoritative email identity this
  // comparison cannot read. It must therefore make the answer UNDECIDABLE, never let a
  // legacy subject-DN value speak for the certificate instead -- a stale subject address
  // would otherwise satisfy expectedSender while the SAN named a different mailbox.
  var i18nPair = await pki.key.generate("Ed25519");
  var i18nKey = await pki.key.export(i18nPair.privateKey);
  var i18nCert = await pki.x509.sign({
    subject: [{ emailAddress: "stale@old.example" }],
    subjectPublicKey: await pki.key.export(i18nPair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { subjectAltName: [{ otherName: { typeId: "1.3.6.1.5.5.7.8.9", value: pki.asn1.build.utf8("i18n@corp.example") } }] },
  }, { key: i18nKey });
  var i18nMsg = await pki.smime.sign(MSG, [{ cert: i18nCert, key: i18nKey }]);
  check("139. an SmtpUTF8Mailbox SAN does not let a stale subject-DN address bind the sender",
    (await pki.smime.verify(i18nMsg, { trustAnchors: [i18nCert], expectedSender: "stale@old.example" })).sender.match === null);

  // An UNRELATED otherName is routine (a Microsoft UPN). It says nothing about the email
  // question, so it must not drag a perfectly matching rfc822Name to undecidable.
  var upnPair = await pki.key.generate("Ed25519");
  var upnKey = await pki.key.export(upnPair.privateKey);
  var await0Spki = await pki.key.export(upnPair.publicKey);
  var upnCert = await pki.x509.sign({
    subject: "UPN Holder",
    subjectPublicKey: await pki.key.export(upnPair.publicKey),
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { subjectAltName: [
      { rfc822Name: "carol@corp.example" },
      { otherName: { typeId: "1.3.6.1.4.1.311.20.2.3", value: pki.asn1.build.utf8("carol@corp.local") } },
    ] },
  }, { key: upnKey });
  var upnMsg = await pki.smime.sign(MSG, [{ cert: upnCert, key: upnKey }]);
  check("140. an unrelated otherName does not erase a matching rfc822Name",
    (await pki.smime.verify(upnMsg, { trustAnchors: [upnCert], expectedSender: "carol@corp.example" })).sender.match === true);
  // The one that pins the TYPE-ID READ itself. With no match to fall back on, a UPN that
  // was wrongly counted as an unreadable email identity turns a clean "no" into "unknown".
  // Reading the type-id off the wrong level of the decoded GeneralName produces exactly
  // that, and every other vector here survives it.
  check("141. an unrelated otherName still yields a definite NO for a different mailbox",
    (await pki.smime.verify(upnMsg, { trustAnchors: [upnCert], expectedSender: "dave@corp.example" })).sender.match === false);

  // A shared builder reports in the CALLER's namespace. A malformed type-id must not leak
  // the codec's own oid/* code out of a module the caller never named.
  check("142. a malformed otherName type-id reports as x509/bad-input, not the codec's code",
    (await codeOf(function () {
      return pki.x509.sign({
        subject: "S", subjectPublicKey: await0Spki,
        notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
        extensions: { subjectAltName: [{ otherName: { typeId: "1.40.1", value: pki.asn1.build.utf8("x") } }] },
      }, { key: upnKey });
    })) === "x509/bad-input");
  // The value is spliced in raw and then SIGNED, so "one complete DER element" is decoded,
  // not taken on the caller's word. Two concatenated TLVs inside a [0] EXPLICIT wrapper
  // whose contract says exactly one would otherwise ship under a real signature.
  check("144. two concatenated DER elements are refused as an otherName value",
    (await codeOf(function () {
      return pki.x509.sign({
        subject: "S", subjectPublicKey: await0Spki,
        notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
        extensions: { subjectAltName: [{ otherName: { typeId: "1.3.6.1.5.5.7.8.9",
          value: Buffer.concat([pki.asn1.build.utf8("x"), pki.asn1.build.utf8("y")]) } }] },
      }, { key: upnKey });
    })) === "x509/bad-input");
  check("145. bytes that are not DER at all are refused as an otherName value",
    (await codeOf(function () {
      return pki.x509.sign({
        subject: "S", subjectPublicKey: await0Spki,
        notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
        extensions: { subjectAltName: [{ otherName: { typeId: "1.3.6.1.5.5.7.8.9",
          value: Buffer.from([0xff]) } }] },
      }, { key: upnKey });
    })) === "x509/bad-input");
  // Already covered by the shared empty-value guard, kept so the contract is pinned where a
  // reader looks for it.
  check("143. a null otherName reports as x509/bad-input",
    (await codeOf(function () {
      return pki.x509.sign({
        subject: "S", subjectPublicKey: await0Spki,
        notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
        extensions: { subjectAltName: [{ otherName: null }] },
      }, { key: upnKey });
    })) === "x509/bad-input");

  check("122. an unprotected message reports fromMismatch null, never a passed comparison",
    v.headerProtection.present === false && v.headerProtection.fromMismatch === null);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
