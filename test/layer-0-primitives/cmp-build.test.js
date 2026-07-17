// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for pki.cmp.build -- the RFC 9810 CMP PKIMessage producing side. Every vector drives
// the shipped consumer pki.cmp.build(message, opts) and asserts through pki.schema.cmp.parse (the round-trip
// GREEN oracle) or err.code. The #1 fragile area is that RFC 9810 App. A is DEFINITIONS EXPLICIT TAGS: every
// PKIHeader [0..8] optional, every PKIBody [n] arm, protection [0], extraCerts [1] is an EXPLICIT wrapper (a
// CONSTRUCTED context tag), the exact inverse of the CRMF interior -- each has a re-parse vector asserting the
// identifier octet. The co-fragile heart is the ProtectedPart byte-exactness (protection covers the exact DER
// of SEQUENCE { header, body } reconstructed from the parser-surfaced headerBytes/bodyBytes).

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;
var asn1 = pki.asn1;
var nodeCrypto = require("node:crypto");

async function codeOf(promise) {
  try { await promise; return null; }
  catch (e) { return e && e.code; }
}
function parse(der) { return pki.schema.cmp.parse(der); }
function bodyTagOctet(der) {
  // the outer PKIMessage SEQUENCE: children[1] is the body arm TLV; return its identifier octet.
  return asn1.decode(der).children[1].bytes[0];
}
function reconProtectedPart(m) {
  return asn1.build.sequence([asn1.build.raw(m.headerBytes), asn1.build.raw(m.bodyBytes)]);
}
function verifySig(spkiDer, preimage, sig, hash) {
  var pub = nodeCrypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
  return nodeCrypto.verify(hash || null, preimage, pub, sig);
}

async function run() {
  var s = makeSigner("ec-p256");
  var HDR = { sender: { directoryName: "CN=client" }, recipient: { directoryName: "CN=CA" }, transactionID: Buffer.alloc(16, 7) };
  var SIG = { key: s.key, cert: s.cert };
  async function csrDer() { return pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: s.spki }, s.key); }

  // ---- round-trip + byte-stability ----
  var irMsg = { header: HDR, body: { ir: { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: s.spki } } } };
  var irDer = await pki.cmp.build(irMsg, SIG);
  var mi = parse(irDer);
  check("1a. ir round-trips: sender/recipient/pvno/transactionID recovered", mi.header.pvno === 2 && Buffer.isBuffer(mi.header.transactionID) && mi.body.arm === "ir");
  check("1b. the inner CertReqMessages decodes via the CRMF walk", !!mi.body.decoded);

  // 2. ProtectedPart exactness (THE load-bearing vector).
  var recon = reconProtectedPart(mi);
  check("2a. reconstructed ProtectedPart == SEQUENCE(headerBytes, bodyBytes)", Buffer.isBuffer(recon) && recon.length > 8);
  check("2b. the protection signature verifies over the reconstructed ProtectedPart", verifySig(s.spki, recon, mi.protection.bytes, "sha256"));
  var flipped = Buffer.from(recon); flipped[flipped.length - 1] ^= 0xff;
  check("2c. a flipped ProtectedPart byte fails verification", !verifySig(s.spki, flipped, mi.protection.bytes, "sha256"));

  // 3. PEM output.
  var pem = await pki.cmp.build(irMsg, Object.assign({ pem: true }, SIG));
  check("3. opts.pem -> a CMP PEM block that decodes + round-trips", typeof pem === "string" && /-----BEGIN CMP-----/.test(pem) && parse(pki.schema.cmp.pemDecode(pem)).body.arm === "ir");

  // ---- pvno + protection<=>protectionAlg agreement ----
  check("4a. a protected build carries BOTH protectionAlg and protection", mi.header.protectionAlg && mi.header.protectionAlg.name === "ecdsaWithSHA256" && Buffer.isBuffer(mi.protection.bytes));
  check("4b. supplying both {key,cert} and {mac} -> cmp/bad-input", await codeOf(pki.cmp.build(irMsg, { key: s.key, cert: s.cert, mac: { secret: "x" } })) === "cmp/bad-input");
  check("4c. supplying neither protection selector -> cmp/bad-input", await codeOf(pki.cmp.build(irMsg, {})) === "cmp/bad-input");

  var ccBump = { header: HDR, body: { certConf: [{ certHash: Buffer.alloc(32, 1), certReqId: -1, hashAlg: "sha256" }] } };
  check("5a. a certConf hashAlg auto-bumps pvno to cmp2021(3)", parse(await pki.cmp.build(ccBump, SIG)).header.pvno === 3);
  check("5b. a plain message defaults to pvno===2", mi.header.pvno === 2);
  check("5c. an explicit out-of-range pvno:99 -> cmp/bad-version on re-parse", await codeOf(pki.cmp.build({ header: Object.assign({ pvno: 99 }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-version");

  // ---- EXPLICIT tag boundary (one assertion per emitted context tag) ----
  check("6a. ir body arm identifier octet is 0xA0 (EXPLICIT [0])", bodyTagOctet(irDer) === 0xa0);
  check("6b. p10cr body arm octet is 0xA4 ([4])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { p10cr: await csrDer() } }, SIG)) === 0xa4);
  check("6c. cr body arm octet is 0xA2 ([2])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { cr: irMsg.body.ir } }, SIG)) === 0xa2);
  check("6d. kur body arm octet is 0xA7 ([7])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { kur: irMsg.body.ir } }, SIG)) === 0xa7);
  check("6e. rr body arm octet is 0xAB ([11], NOT [15]/0xAF)", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n } }] } }, SIG)) === 0xab);
  check("6f. genm body arm octet is 0xB5 ([21])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { genm: [{ infoType: "caCerts" }] } }, SIG)) === 0xb5);
  check("6g. certConf body arm octet is 0xB8 ([24])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { certConf: [{ certHash: Buffer.alloc(32, 1), certReqId: 0 }] } }, SIG)) === 0xb8);
  check("6h. pollReq body arm octet is 0xB9 ([25])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { pollReq: [{ certReqId: 0 }] } }, SIG)) === 0xb9);

  // 7. envelope EXPLICIT tags: protection [0], extraCerts [1], header messageTime [0] / protectionAlg [1].
  var msgChildren = asn1.decode(irDer).children;
  check("7a. protection is [0] EXPLICIT (0xA0) wrapping a BIT STRING", msgChildren[2].bytes[0] === 0xa0 && asn1.decode(msgChildren[2].bytes).children[0].tagNumber === asn1.TAGS.BIT_STRING);
  check("7b. extraCerts is [1] EXPLICIT (0xA1) wrapping a non-empty SEQUENCE", msgChildren[3].bytes[0] === 0xa1 && asn1.decode(msgChildren[3].bytes).children[0].children.length >= 1);
  var withTime = await pki.cmp.build({ header: Object.assign({ messageTime: new Date("2001-02-03T04:05:06Z") }, HDR), body: irMsg.body }, SIG);
  var hdrKids = asn1.decode(asn1.decode(withTime).children[0].bytes).children;
  check("7c. header messageTime is [0] EXPLICIT (0xA0)", hdrKids[3].bytes[0] === 0xa0);
  check("7d. header protectionAlg is [1] EXPLICIT (0xA1)", hdrKids.some(function (k) { return k.bytes[0] === 0xa1; }));

  // 8. header optional order: ascending, at most once.
  var full = await pki.cmp.build({ header: Object.assign({ senderNonce: Buffer.alloc(16, 5), recipNonce: Buffer.alloc(16, 6) }, HDR), body: irMsg.body }, SIG);
  var mf = parse(full);
  check("8. header optionals decode ascending (transactionID/senderNonce/recipNonce recovered)", Buffer.isBuffer(mf.header.transactionID) && Buffer.isBuffer(mf.header.senderNonce) && Buffer.isBuffer(mf.header.recipNonce));

  // ---- body arm content round-trips ----
  check("9. ir inner CertReqMessages re-decodes (>=1 message)", mi.body.decoded && mi.body.decoded.messages.length >= 1);
  // the CRMF proof of possession uses the REQUESTED key (via body.ir.key), distinct from the protection key.
  var reqK = makeSigner("ec-p256");
  var distinctPop = await pki.cmp.build({ header: HDR, body: { ir: { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: reqK.spki }, key: reqK.key } } }, SIG);
  check("9b. ir with a distinct requested-key POP round-trips (POP key != protection key)", parse(distinctPop).body.arm === "ir" && !!parse(distinctPop).body.decoded);
  var p10 = await pki.cmp.build({ header: HDR, body: { p10cr: await csrDer() } }, SIG);
  var mp = parse(p10);
  check("10a. p10cr arm; body.bytes re-parses via csr.parse (subject matches)", mp.body.arm === "p10cr" && pki.schema.csr.parse(mp.body.bytes).subject.dn.indexOf("c") !== -1);
  check("10b. a non-CSR DER p10cr -> a typed cmp/* or csr/*", /^(cmp|csr)\//.test(await codeOf(pki.cmp.build({ header: HDR, body: { p10cr: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]) } }, SIG))));
  check("11a. certConf round-trips (empty CertConfirmContent legal)", parse(await pki.cmp.build({ header: HDR, body: { certConf: [] } }, SIG)).body.arm === "certConf");
  check("11b. certConf with a rejection statusInfo round-trips", parse(await pki.cmp.build({ header: HDR, body: { certConf: [{ certHash: Buffer.alloc(32, 1), certReqId: 0, statusInfo: { status: 2, statusString: ["rejected"] } }] } }, SIG)).body.arm === "certConf");
  // statusInfo.failInfo (a PKIFailureInfo NamedBitList) round-trips -- the parser validates minimal bits, so a
  // successful re-parse cross-checks the bit positions against the parser's own failInfo decoder.
  check("11c. certConf statusInfo with failInfo bits round-trips (minimal NamedBitList)", parse(await pki.cmp.build({ header: HDR, body: { certConf: [{ certHash: Buffer.alloc(32, 1), certReqId: 0, statusInfo: { status: 2, failInfo: ["badPOP", "badCertId"] } }] } }, SIG)).body.arm === "certConf");
  check("11d. an unknown failInfo bit name -> cmp/bad-cert-status", await codeOf(pki.cmp.build({ header: HDR, body: { certConf: [{ certHash: Buffer.alloc(32, 1), certReqId: 0, statusInfo: { status: 2, failInfo: ["notabit"] } }] } }, SIG)) === "cmp/bad-cert-status");
  check("12. pollReq round-trips with certReqId -1", parse(await pki.cmp.build({ header: HDR, body: { pollReq: [{ certReqId: -1 }] } }, SIG)).body.arm === "pollReq");
  // certReqId is an unbounded INTEGER: a bigint beyond 2^53 is accepted (not rejected as a non-safe-integer).
  var bigId = 12345678901234567890n;
  check("12b. a bigint pollReq certReqId (unbounded) round-trips", parse(await pki.cmp.build({ header: HDR, body: { pollReq: [{ certReqId: bigId }] } }, SIG)).body.arm === "pollReq");
  check("12c. a non-integer pollReq certReqId (2.5) -> cmp/bad-poll-req", await codeOf(pki.cmp.build({ header: HDR, body: { pollReq: [{ certReqId: 2.5 }] } }, SIG)) === "cmp/bad-poll-req");
  check("12d. a bigint certConf certReqId (unbounded) round-trips", parse(await pki.cmp.build({ header: HDR, body: { certConf: [{ certHash: Buffer.alloc(32, 1), certReqId: bigId }] } }, SIG)).body.arm === "certConf");
  check("13a. genm round-trips a bare id-it query", parse(await pki.cmp.build({ header: HDR, body: { genm: [{ infoType: "caCerts" }] } }, SIG)).body.arm === "genm");
  check("13b. a mis-typed fixed-syntax id-it value -> cmp/bad-info-value", await codeOf(pki.cmp.build({ header: HDR, body: { genm: [{ infoType: "implicitConfirm", infoValue: new Date() }] } }, SIG)) === "cmp/bad-info-value");
  // generalInfo [8] carrying the three fixed-syntax id-it values (implicitConfirm NULL, confirmWaitTime GT,
  // certProfile SEQ OF UTF8) plus a genm bare-query round-trip.
  var gi = { header: Object.assign({ generalInfo: [{ infoType: "implicitConfirm" }, { infoType: "confirmWaitTime", infoValue: new Date("2026-06-01T00:00:00Z") }, { infoType: "certProfile", infoValue: ["profile-A"] }] }, HDR), body: { p10cr: await csrDer() } };
  check("13c. header.generalInfo with implicitConfirm / confirmWaitTime / certProfile round-trips", parse(await pki.cmp.build(gi, SIG)).header.generalInfo.length === 3);
  check("13d. genm carrying a confirmWaitTime value round-trips", parse(await pki.cmp.build({ header: HDR, body: { genm: [{ infoType: "confirmWaitTime", infoValue: new Date("2026-06-01T00:00:00Z") }] } }, SIG)).body.arm === "genm");
  // opts.pem as an explicit label + opts.extraCerts.
  check("13e. opts.pem string label emits that PEM block", typeof (await pki.cmp.build(irMsg, Object.assign({ pem: "CMP" }, SIG))) === "string");
  check("13f. opts.extraCerts adds certificates to extraCerts [1]", parse(await pki.cmp.build(irMsg, Object.assign({ extraCerts: [s.cert] }, SIG))).extraCerts.length === 2);
  check("13g. a non-array opts.extraCerts -> cmp/bad-extra-certs", await codeOf(pki.cmp.build(irMsg, Object.assign({ extraCerts: "x" }, SIG))) === "cmp/bad-extra-certs");
  check("14. rr round-trips; certDetails re-decodes via the CertTemplate walk", parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n } }] } }, SIG)).body.arm === "rr");
  var tplDer = pki.crmf.buildCertTemplate({ serialNumber: 42n, issuer: "CN=CA" });
  check("14b. pki.crmf.buildCertTemplate produces a CertTemplate DER usable as rr certDetails", pki.asn1.decode(tplDer).tagNumber === asn1.TAGS.SEQUENCE && parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: tplDer }] } }, SIG)).body.arm === "rr");
  // header key-identifier optionals + a genm id-it carrying a pre-encoded infoValue + full cr/kur round-trips.
  var kids = await pki.cmp.build({ header: Object.assign({ senderKID: Buffer.alloc(8, 1), recipKID: Buffer.alloc(8, 2), messageTime: new Date("2026-01-01T00:00:00Z"), freeText: ["hello"] }, HDR), body: irMsg.body }, SIG);
  var mk = parse(kids);
  check("14c. header senderKID / recipKID / freeText round-trip", Buffer.isBuffer(mk.header.senderKID) && Buffer.isBuffer(mk.header.recipKID) && mk.header.freeText.length === 1);
  check("14d. a genm id-it with a pre-encoded infoValue round-trips", parse(await pki.cmp.build({ header: HDR, body: { genm: [{ infoType: "caCerts", infoValue: asn1.build.sequence([]) }] } }, SIG)).body.arm === "genm");
  check("14e. cr body re-decodes its inner CertReqMessages", !!parse(await pki.cmp.build({ header: HDR, body: { cr: irMsg.body.ir } }, SIG)).body.decoded);
  check("14f. kur body re-decodes its inner CertReqMessages", !!parse(await pki.cmp.build({ header: HDR, body: { kur: irMsg.body.ir } }, SIG)).body.decoded);
  // the sign-error factory: an unsupported protection key surfaces a typed cmp/*.
  check("14g. an unsupported protection cert -> a typed cmp/*", /^cmp\//.test(await codeOf(pki.cmp.build({ header: HDR, body: irMsg.body }, { key: s.key, cert: Buffer.from([0x30, 0x00]) }))));

  // 15. messageTime is GeneralizedTime-ONLY even in the UTCTime window.
  var mt = asn1.decode(asn1.decode(withTime).children[0].bytes).children[3];   // messageTime [0]
  check("15. messageTime wraps a GeneralizedTime (0x18), never UTCTime (0x17)", asn1.decode(mt.bytes).children[0].tagNumber === asn1.TAGS.GENERALIZED_TIME);

  // ---- signature protection: every algorithm arm ----
  var arms = ["rsa", "ec-p384", "ec-p521", "ed25519", "ml-dsa-65", "slh-dsa-sha2-128f"];
  for (var ai = 0; ai < arms.length; ai++) {
    var sa = makeSigner(arms[ai]);
    var d = await pki.cmp.build({ header: HDR, body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: sa.spki }, sa.key) } }, { key: sa.key, cert: sa.cert });
    var ma = parse(d);
    var reconA = reconProtectedPart(ma);
    var algName = ma.header.protectionAlg.name || "";
    // derive the digest from the resolved protectionAlg (the sign-scheme pairs every ECDSA/RSA arm with
    // SHA-256 by default); EdDSA / ML-DSA / SLH-DSA are one-shot (null).
    var hash = /sha384/i.test(algName) ? "sha384" : /sha512/i.test(algName) ? "sha512" : /sha256/i.test(algName) ? "sha256" : null;
    check("16." + ai + " " + arms[ai] + " signature protection builds + verifies over the ProtectedPart", verifySig(sa.spki, reconA, ma.protection.bytes, hash) && !!algName);
  }
  var comp = makeCompositeSigner ? makeCompositeSigner("id-MLDSA65-Ed25519-SHA512") : null;
  if (comp) {
    var cd = await pki.cmp.build({ header: HDR, body: { p10cr: await pki.csr.sign({ subject: [{ commonName: "c" }], subjectPublicKey: comp.spki }, comp.key) } }, { key: comp.key, cert: comp.cert });
    check("17. a composite protectionAlg builds + round-trips (both components carried)", !!parse(cd).header.protectionAlg);
  }

  // ---- PBMAC1 ----
  var macMsg = { header: HDR, body: { p10cr: await csrDer() } };
  var macDer = await pki.cmp.build(macMsg, { mac: { secret: "hunter2", salt: Buffer.alloc(16, 9), iterationCount: 2048 } });
  var mm = parse(macDer);
  var reconM = reconProtectedPart(mm);
  var derivedKey = nodeCrypto.pbkdf2Sync(Buffer.from("hunter2", "utf8"), Buffer.alloc(16, 9), 2048, 32, "sha256");
  var recomputed = nodeCrypto.createHmac("sha256", derivedKey).update(reconM).digest();
  check("18a. PBMAC1 protectionAlg is pbmac1, octet-aligned (0 unused bits)", mm.header.protectionAlg.name === "pbmac1" && mm.protection.unusedBits === 0);
  check("18b. the PBMAC1 protection recomputes byte-identically (PBKDF2 + HMAC-SHA256)", recomputed.equals(mm.protection.bytes));
  // the PBMAC1 HMAC AlgorithmIdentifiers carry NULL parameters (RFC 8018 App. B.1.1): the messageAuthScheme
  // (the 2nd child of PBMAC1-params) is a 2-element SEQUENCE { OID, NULL }.
  var pbmac1Params = asn1.decode(mm.header.protectionAlg.parameters);
  var messageAuthScheme = pbmac1Params.children[1];
  check("18c. the PBMAC1 messageAuthScheme HMAC algId has NULL parameters", messageAuthScheme.children.length === 2 && messageAuthScheme.children[1].tagNumber === asn1.TAGS.NULL);
  check("19a. a wrong-secret recompute does NOT match the emitted MAC", !nodeCrypto.createHmac("sha256", nodeCrypto.pbkdf2Sync(Buffer.from("wrong"), Buffer.alloc(16, 9), 2048, 32, "sha256")).update(reconM).digest().equals(mm.protection.bytes));
  check("19b. an empty mac.secret -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "" } })) === "cmp/bad-input");
  check("19c. a non-object mac -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: 5 })) === "cmp/bad-input");
  check("19d. an unknown mac field -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", bogus: 1 } })) === "cmp/bad-input");
  check("19e. an unsupported mac.algorithm -> cmp/unsupported-algorithm", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", algorithm: "passwordBasedMac" } })) === "cmp/unsupported-algorithm");
  check("19f. a bad mac.prf -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", prf: "MD5" } })) === "cmp/bad-input");
  check("19g. a non-integer mac.iterationCount -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", iterationCount: 1.5 } })) === "cmp/bad-input");
  check("19h. a non-integer mac.keyLength -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", keyLength: 0 } })) === "cmp/bad-input");
  // work factors are bounded BEFORE deriving -- a huge iterationCount / keyLength / salt fails closed.
  check("19j. an over-cap mac.iterationCount -> cmp/bad-input (PBKDF2 DoS bound)", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", iterationCount: 10000001 } })) === "cmp/bad-input");
  check("19k. an over-cap mac.keyLength -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", keyLength: 4096 } })) === "cmp/bad-input");
  check("19l. an over-cap mac.salt -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", salt: Buffer.alloc(2048) } })) === "cmp/bad-input");
  check("19i. a Buffer mac.secret + SHA-384 prf round-trips", parse(await pki.cmp.build(macMsg, { mac: { secret: Buffer.from("k"), salt: Buffer.alloc(16, 1), iterationCount: 1000, prf: "SHA-384" } })).header.protectionAlg.name === "pbmac1");

  // ---- protection self-check (the sender proof) ----
  var sB = makeSigner("ec-p256");
  check("20a. cert = signer A but key = signer B -> cmp/bad-input (protection self-verify fails)", await codeOf(pki.cmp.build({ header: HDR, body: { p10cr: await csrDer() } }, { key: sB.key, cert: s.cert })) === "cmp/bad-input");

  // ---- fail-closed misuse ----
  check("21a. a non-object message -> cmp/bad-input", await codeOf(pki.cmp.build(5, SIG)) === "cmp/bad-input");
  check("21b. an unknown top-level message field -> cmp/bad-input", await codeOf(pki.cmp.build({ header: HDR, body: irMsg.body, extra: 1 }, SIG)) === "cmp/bad-input");
  check("21c. an unknown header field -> cmp/bad-input", await codeOf(pki.cmp.build({ header: Object.assign({ bogus: 1 }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-input");
  check("21d. a multi-key body object -> cmp/bad-input", await codeOf(pki.cmp.build({ header: HDR, body: { ir: irMsg.body.ir, cr: irMsg.body.ir } }, SIG)) === "cmp/bad-input");
  check("21e. an empty body object -> cmp/bad-input", await codeOf(pki.cmp.build({ header: HDR, body: {} }, SIG)) === "cmp/bad-input");
  check("21f. a missing sender -> cmp/bad-input", await codeOf(pki.cmp.build({ header: { recipient: HDR.recipient }, body: irMsg.body }, SIG)) === "cmp/bad-input");
  check("21g. an unknown body arm -> cmp/bad-input", await codeOf(pki.cmp.build({ header: HDR, body: { nope: 1 } }, SIG)) === "cmp/bad-input");
  check("21h. a malformed inner ir/crmf spec surfaces a typed crmf/*", /^crmf\//.test(await codeOf(pki.cmp.build({ header: HDR, body: { ir: { certTemplate: { publicKey: Buffer.from([0x00]) } } } }, SIG))));
  check("21i. an unknown opts field -> cmp/bad-input", await codeOf(pki.cmp.build(irMsg, Object.assign({ bogus: 1 }, SIG))) === "cmp/bad-input");
  check("21j. a missing recipient -> cmp/bad-input", await codeOf(pki.cmp.build({ header: { sender: HDR.sender }, body: irMsg.body }, SIG)) === "cmp/bad-input");
  check("21k. signature protection missing cert -> cmp/bad-input", await codeOf(pki.cmp.build(irMsg, { key: s.key })) === "cmp/bad-input");
  check("21l. a non-integer pvno -> cmp/bad-input", await codeOf(pki.cmp.build({ header: Object.assign({ pvno: 1.5 }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-input");
  check("21m. a non-string opts.pem -> cmp/bad-input", await codeOf(pki.cmp.build(irMsg, Object.assign({ pem: 5 }, SIG))) === "cmp/bad-input");
  check("21n. a non-string messageTime -> cmp/bad-input", await codeOf(pki.cmp.build({ header: Object.assign({ messageTime: "now" }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-input");
  check("21o. an empty freeText array -> cmp/bad-freetext", await codeOf(pki.cmp.build({ header: Object.assign({ freeText: [] }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-freetext");
  check("21p. a non-string freeText entry -> cmp/bad-freetext", await codeOf(pki.cmp.build({ header: Object.assign({ freeText: [5] }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-freetext");
  check("21q. an unknown generalInfo infoType -> cmp/bad-name", await codeOf(pki.cmp.build({ header: Object.assign({ generalInfo: [{ infoType: "not-a-real-oid-name" }] }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-name");
  check("21r. a confirmWaitTime non-Date value -> cmp/bad-info-value", await codeOf(pki.cmp.build({ header: Object.assign({ generalInfo: [{ infoType: "confirmWaitTime", infoValue: "soon" }] }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-info-value");
  check("21s. a certConf non-array -> cmp/bad-cert-status", await codeOf(pki.cmp.build({ header: HDR, body: { certConf: 5 } }, SIG)) === "cmp/bad-cert-status");
  check("21t. an unknown certConf hashAlg -> cmp/bad-name", await codeOf(pki.cmp.build({ header: HDR, body: { certConf: [{ certHash: Buffer.alloc(32, 1), certReqId: 0, hashAlg: "nope" }] } }, SIG)) === "cmp/bad-name");
  check("21t3. a non-hash OID certConf hashAlg -> cmp/bad-name (must be a hash algorithm)", await codeOf(pki.cmp.build({ header: HDR, body: { certConf: [{ certHash: Buffer.alloc(32, 1), certReqId: 0, hashAlg: "rsaEncryption" }] } }, SIG)) === "cmp/bad-name");
  check("21t4. a valid hash certConf hashAlg (sha384) bumps pvno + round-trips", parse(await pki.cmp.build({ header: HDR, body: { certConf: [{ certHash: Buffer.alloc(48, 1), certReqId: 0, hashAlg: "sha384" }] } }, SIG)).header.pvno === 3);
  check("21t2. a non-integer certConf certReqId -> cmp/bad-cert-status", await codeOf(pki.cmp.build({ header: HDR, body: { certConf: [{ certHash: Buffer.alloc(32, 1), certReqId: 1.5 }] } }, SIG)) === "cmp/bad-cert-status");
  check("21u. a pollReq entry without certReqId -> cmp/bad-poll-req", await codeOf(pki.cmp.build({ header: HDR, body: { pollReq: [{}] } }, SIG)) === "cmp/bad-poll-req");
  check("21u2. a non-integer pollReq certReqId -> cmp/bad-poll-req", await codeOf(pki.cmp.build({ header: HDR, body: { pollReq: [{ certReqId: 2.5 }] } }, SIG)) === "cmp/bad-poll-req");
  check("21v. an rr without certDetails -> cmp/bad-rev-req", await codeOf(pki.cmp.build({ header: HDR, body: { rr: [{}] } }, SIG)) === "cmp/bad-rev-req");
  check("21w. an empty rr array -> cmp/bad-rev-req", await codeOf(pki.cmp.build({ header: HDR, body: { rr: [] } }, SIG)) === "cmp/bad-rev-req");
  check("21w2. an rr certDetails without issuer/serialNumber -> cmp/bad-rev-req", await codeOf(pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { subject: [{ commonName: "x" }] } }] } }, SIG)) === "cmp/bad-rev-req");
  check("21x. a genm non-array -> cmp/bad-info-type-and-value", await codeOf(pki.cmp.build({ header: HDR, body: { genm: 5 } }, SIG)) === "cmp/bad-info-type-and-value");
  check("21y. a missing message.header -> cmp/bad-input", await codeOf(pki.cmp.build({ body: irMsg.body }, SIG)) === "cmp/bad-input");
  check("21z. a missing message.body -> cmp/bad-input", await codeOf(pki.cmp.build({ header: HDR }, SIG)) === "cmp/bad-input");
  check("21aa. build without opts -> cmp/bad-input (protection required)", await codeOf(pki.cmp.build(irMsg)) === "cmp/bad-input");
  // an rr carrying crlEntryDetails (a pre-encoded Extensions DER) + a random-salt PBMAC1 (no salt supplied).
  var crlExts = asn1.build.sequence([asn1.build.sequence([asn1.build.oid("2.5.29.21"), asn1.build.octetString(Buffer.from("0a0101", "hex"))])]);   // Extensions { reasonCode keyCompromise }
  check("21bb. rr with crlEntryDetails round-trips", parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n }, crlEntryDetails: crlExts }] } }, SIG)).body.arm === "rr");
  check("21cc. PBMAC1 with a random (unsupplied) salt round-trips", parse(await pki.cmp.build(macMsg, { mac: { secret: "pw", iterationCount: 1000 } })).header.protectionAlg.name === "pbmac1");

  // ---- orchestrator dispatch ----
  check("22. pki.schema.parse detect-routes the built DER to cmp", pki.schema.parse(irDer).body.arm === "ir");

  console.log("CHECKS " + helpers.getChecks());
}

run().then(function () { }, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
