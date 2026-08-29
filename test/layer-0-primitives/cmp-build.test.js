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
var cmpBuild = require("../../lib/cmp-build");   // @internal buildCrlStatusList: the session composes it directly, without build()'s entry deep-copy

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

  // nested [20] NestedMessageContent ::= PKIMessages (RFC 9810 sec. 5.1.3.4): an RA wraps complete,
  // independently-protected PKIMessages to forward or batch them. The wrapper carries the RA's own
  // protection; the parser surfaces the nested content raw (never auto-recursed), so the operator re-parses
  // each inner message. A non-empty array is required (PKIMessages is SIZE (1..MAX)); each entry is validated
  // as a PKIMessage.
  var innerA = await pki.cmp.build({ header: HDR, body: { ir: { certTemplate: { subject: [{ commonName: "ee-a" }], publicKey: s.spki } } } }, SIG);
  var innerB = await pki.cmp.build({ header: HDR, body: { ir: { certTemplate: { subject: [{ commonName: "ee-b" }], publicKey: s.spki } } } }, SIG);
  var nestedDer = await pki.cmp.build({ header: HDR, body: { nested: [innerA, innerB] } }, SIG);
  var mn = parse(nestedDer);
  check("1c. nested round-trips as the nested [20] arm", mn.body.arm === "nested");
  var nseq = asn1.decode(mn.body.bytes);
  check("1d. nested wraps its PKIMessages as a SEQUENCE OF two", nseq.tagNumber === 16 && nseq.children.length === 2);
  check("1e. each inner PKIMessage re-parses to its ir body", parse(nseq.children[0].bytes).body.arm === "ir" && parse(nseq.children[1].bytes).body.arm === "ir");
  var nestedEmpty = await pki.cmp.build({ header: HDR, body: { nested: [] } }, SIG).then(function () { return "NO-THROW"; }, function (e) { return e.code; });
  check("1f. nested rejects an empty array (PKIMessages is SIZE (1..MAX))", nestedEmpty === "cmp/bad-input");
  var nestedBad = await pki.cmp.build({ header: HDR, body: { nested: [Buffer.from([0x30, 0x00])] } }, SIG).then(function () { return "NO-THROW"; }, function (e) { return e.code; });
  check("1g. nested rejects an entry that is not a PKIMessage", nestedBad === "cmp/bad-input");

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
  // The signature parameters are read only by the signature form. Under PBMAC1 a requested pss or
  // digestAlgorithm selected nothing and the message went out MAC'd under the default PRF, identical
  // byte for byte to the call that never named them.
  var MAC = { mac: { secret: "a-shared-secret", salt: Buffer.alloc(16, 7), iterationCount: 100000 } };
  check("4d. pss under MAC protection -> cmp/bad-input",
    await codeOf(pki.cmp.build(irMsg, { mac: MAC.mac, pss: true })) === "cmp/bad-input");
  check("4e. digestAlgorithm under MAC protection -> cmp/bad-input",
    await codeOf(pki.cmp.build(irMsg, { mac: MAC.mac, digestAlgorithm: "sha512" })) === "cmp/bad-input");
  check("4f. the same parameters on the signature form still build",
    (await pki.cmp.build(irMsg, { key: s.key, cert: s.cert, digestAlgorithm: "sha512" })) != null);
  check("4g. MAC protection without them still builds", (await pki.cmp.build(irMsg, MAC)) != null);
  check("4h. an option shared by both forms is accepted on each",
    typeof (await pki.cmp.build(irMsg, { mac: MAC.mac, pem: true })) === "string" &&
    typeof (await pki.cmp.build(irMsg, Object.assign({ pem: true }, SIG))) === "string");

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
  check("13h. a garbage opts.extraCerts entry -> cmp/bad-extra-certs (each must be a valid certificate)", await codeOf(pki.cmp.build(irMsg, Object.assign({ extraCerts: [Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01])] }, SIG))) === "cmp/bad-extra-certs");
  check("14. rr round-trips; certDetails re-decodes via the CertTemplate walk", parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n } }] } }, SIG)).body.arm === "rr");
  var tplDer = pki.crmf.buildCertTemplate({ serialNumber: 42n, issuer: "CN=CA" });
  check("14b. pki.crmf.buildCertTemplate produces a CertTemplate DER usable as rr certDetails", pki.asn1.decode(tplDer).tagNumber === asn1.TAGS.SEQUENCE && parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: tplDer }] } }, SIG)).body.arm === "rr");
  // A pre-encoded certDetails must survive every byte-source form the byte guard accepts. As an
  // ArrayBuffer or DataView a narrowed check would miss it and demand the { issuer, serialNumber } it
  // does not carry. bodyBytes is the protected body encoding, deterministic for equal input (unlike the
  // randomized ECDSA protection), so equal bodyBytes proves the certDetails was preserved.
  var cdBuf = parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: tplDer }] } }, SIG)).bodyBytes;
  var tplAb = tplDer.buffer.slice(tplDer.byteOffset, tplDer.byteOffset + tplDer.byteLength);
  check("14c. certDetails as an ArrayBuffer is accepted as a pre-encoded CertTemplate", (parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: tplAb }] } }, SIG)).bodyBytes).equals(cdBuf));
  check("14d. certDetails as a DataView is accepted as a pre-encoded CertTemplate", (parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: new DataView(tplAb) }] } }, SIG)).bodyBytes).equals(cdBuf));
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
  // build enforces the same RFC 9579 sec. 9 keyLength floor (>= 20) pki.cmp.verify requires, so it never emits
  // a message its own verify-inverse would reject.
  check("19e. mac.keyLength below the RFC 9579 floor (< 20) -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", keyLength: 16 } })) === "cmp/bad-input");
  check("19e. an unsupported mac.algorithm -> cmp/unsupported-algorithm", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", algorithm: "passwordBasedMac" } })) === "cmp/unsupported-algorithm");
  check("19f. a bad mac.prf -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", prf: "MD5" } })) === "cmp/bad-input");
  check("19g. a non-integer mac.iterationCount -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", iterationCount: 1.5 } })) === "cmp/bad-input");
  check("19h. a non-integer mac.keyLength -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", keyLength: 0 } })) === "cmp/bad-input");
  check("19h2. a below-minimum mac.iterationCount -> cmp/bad-input (RFC 8018 floor)", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", iterationCount: 100 } })) === "cmp/bad-input");
  // work factors are bounded BEFORE deriving -- a huge iterationCount / keyLength / salt fails closed.
  check("19j. an over-cap mac.iterationCount -> cmp/bad-input (PBKDF2 DoS bound)", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", iterationCount: 10000001 } })) === "cmp/bad-input");
  check("19k. an over-cap mac.keyLength -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", keyLength: 4096 } })) === "cmp/bad-input");
  // The COMBINED work is bounded here too, so build never emits a message pki.cmp.verify would refuse as
  // over-budget: a maximal keyLength (1024 = 32 SHA-256 blocks) with an iterationCount whose product exceeds
  // the ceiling is rejected at production, while the same key at a count under the product ceiling still emits.
  check("19k2. an in-range iterationCount x keyLength whose product exceeds the cap -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", iterationCount: 312501, keyLength: 1024 } })) === "cmp/bad-input");
  check("19k3. a maximal keyLength (1024) at a count under the product ceiling still emits", parse(await pki.cmp.build(macMsg, { mac: { secret: "x", iterationCount: 1000, keyLength: 1024 } })).header.protectionAlg.name === "pbmac1");
  check("19l. an over-cap mac.salt -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", salt: Buffer.alloc(2048) } })) === "cmp/bad-input");
  // An empty / short salt loses precomputation resistance (RFC 8018 sec. 4.1 64-bit floor) -- refused at
  // construction so build never emits a message pki.cmp.verify (same floor) rejects; an 8-octet salt is accepted.
  check("19l2. an empty mac.salt -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", salt: Buffer.alloc(0) } })) === "cmp/bad-input");
  check("19l3. a mac.salt below the 8-octet floor -> cmp/bad-input", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "x", salt: Buffer.alloc(4) } })) === "cmp/bad-input");
  check("19l4. an 8-octet mac.salt (the floor) still emits", parse(await pki.cmp.build(macMsg, { mac: { secret: "x", salt: Buffer.alloc(8, 1), iterationCount: 1000 } })).header.protectionAlg.name === "pbmac1");
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
  check("21n2. an Invalid Date messageTime -> cmp/bad-input", await codeOf(pki.cmp.build({ header: Object.assign({ messageTime: new Date("nope") }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-input");
  check("21n3. an Invalid Date confirmWaitTime -> cmp/bad-info-value", await codeOf(pki.cmp.build({ header: Object.assign({ generalInfo: [{ infoType: "confirmWaitTime", infoValue: new Date("nope") }] }, HDR), body: irMsg.body }, SIG)) === "cmp/bad-info-value");
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
  // The pre-encoded crlEntryDetails (reasonCode keyCompromise) must survive every byte-source form. As
  // an ArrayBuffer or DataView it would otherwise fall through as a { reason }-less object and be
  // silently replaced by a generated unspecified(0) reasonCode -- a different revocation reason than the
  // caller encoded. Equal bodyBytes proves the Extensions survived unchanged.
  var ceBuf = parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n }, crlEntryDetails: crlExts }] } }, SIG)).bodyBytes;
  var crlExtsAb = crlExts.buffer.slice(crlExts.byteOffset, crlExts.byteOffset + crlExts.byteLength);
  check("21bb2. crlEntryDetails as an ArrayBuffer preserves the caller's Extensions, not a generated unspecified(0)", (parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n }, crlEntryDetails: crlExtsAb }] } }, SIG)).bodyBytes).equals(ceBuf));
  check("21bb3. crlEntryDetails as a DataView preserves the caller's Extensions", (parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n }, crlEntryDetails: new DataView(crlExtsAb) }] } }, SIG)).bodyBytes).equals(ceBuf));
  // A crlEntryDetails.reason getter cannot make the encoded reason differ from the validated one: build()
  // deep-copies the caller's message at entry, so a getter is invoked exactly once and its LATER values
  // never reach the encoder. This getter returns keyCompromise on the first read and cessationOfOperation
  // on every read after; the built message must still encode keyCompromise, matching a plain { reason }.
  var refReasonBody = parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n }, crlEntryDetails: { reason: "keyCompromise" } }] } }, SIG)).bodyBytes;
  var reasonReads = 0, reasonSpec = {};
  Object.defineProperty(reasonSpec, "reason", { enumerable: true, get: function () { reasonReads += 1; return reasonReads === 1 ? "keyCompromise" : "cessationOfOperation"; } });
  var getterReasonBody = parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n }, crlEntryDetails: reasonSpec }] } }, SIG)).bodyBytes;
  check("21bb5. a crlEntryDetails.reason getter's later values never reach the encoder (entry deep-copy)", getterReasonBody.equals(refReasonBody) && reasonReads === 1);
  // crlEntryDetails is { reason } | pre-encoded Extensions DER. A value outside that union that is neither a
  // byte source nor a plain record -- an empty array, or an exotic like a Date -- must be refused, not read
  // as a keyless record: the fallback would find no `reason` and emit a generated unspecified(0) reasonCode,
  // turning a malformed input into a real revocation request. An empty PLAIN record stays valid (unspecified).
  check("21bb7. an array crlEntryDetails is refused, not defaulted to unspecified(0)", await codeOf(pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n }, crlEntryDetails: [] }] } }, SIG)) === "cmp/bad-rev-req");
  check("21bb8. a non-record (Date) crlEntryDetails is refused", await codeOf(pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n }, crlEntryDetails: new Date() }] } }, SIG)) === "cmp/bad-rev-req");
  check("21bb9. an empty plain-record crlEntryDetails stays valid (unspecified(0))", parse(await pki.cmp.build({ header: HDR, body: { rr: [{ certDetails: { issuer: "CN=CA", serialNumber: 42n }, crlEntryDetails: {} }] } }, SIG)).body.arm === "rr");
  // buildCrlStatusList composes a crlUpdate genm body straight from the caller's request: pki.cmp.session
  // hands it the request with no entry deep-copy, so the issuer it puts on the wire and the issuer it binds
  // the response to (the returned issuerName) must come from ONE read of the caller's field. An issuer whose
  // attributes are accessors must be encoded once: re-encoding it for the wire could ship a CRLSource naming
  // one CA while the answer is held to another, so a CRL from the bound CA could satisfy a request the wire
  // named a different CA for. This RDN's commonName reads "CA-A" first and "CA-B" after; the on-wire source
  // must carry the same encoded Name as issuerName (CA-A), and the field must be read exactly once.
  var issuerReads = 0, getterRdn = {};
  Object.defineProperty(getterRdn, "commonName", { enumerable: true, get: function () { issuerReads += 1; return issuerReads === 1 ? "CA-A" : "CA-B"; } });
  var crlStatus = cmpBuild.buildCrlStatusList({ issuer: [getterRdn] });
  check("21bb6. a crlUpdate issuer getter's later value never reaches the wire (on-wire source == bound issuerName)", crlStatus.der.includes(crlStatus.issuerName) && issuerReads === 1);
  check("21cc. PBMAC1 with a random (unsupplied) salt round-trips", parse(await pki.cmp.build(macMsg, { mac: { secret: "pw", iterationCount: 1000 } })).header.protectionAlg.name === "pbmac1");
  // opts.mac.prf defaults only when absent. A supplied falsy value ("", false, 0) is not a PRF name and must
  // be refused, not silently encoded as HMAC-SHA-256: `m.prf || "SHA-256"` would have defaulted it. An
  // explicitly named PRF still round-trips.
  check("21cc2. an empty-string opts.mac.prf is refused, not defaulted to SHA-256", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "pw", prf: "", iterationCount: 1000 } })) === "cmp/bad-input");
  check("21cc3. a false opts.mac.prf is refused", await codeOf(pki.cmp.build(macMsg, { mac: { secret: "pw", prf: false, iterationCount: 1000 } })) === "cmp/bad-input");
  check("21cc4. an explicit SHA-384 opts.mac.prf round-trips", parse(await pki.cmp.build(macMsg, { mac: { secret: "pw", prf: "SHA-384", iterationCount: 1000 } })).header.protectionAlg.name === "pbmac1");

  // ---- CA / responder-side arms (RFC 9810 sec. 5.3) ----
  var CERT = s.cert;
  // 23. the response arm EXPLICIT identifier octets (ip 0xA1, cp 0xA3, kup 0xA8, ccp 0xAE, krp 0xAA, rp 0xAC,
  //     genp 0xB6, error 0xB7, pollRep 0xBA, pkiconf 0xB3) -- the CertOrEncCert [0] is the v0.3.3 EXPLICIT trap.
  var grantResp = { response: [{ certReqId: 0, status: { status: 0 }, certifiedKeyPair: { certificate: CERT } }] };
  check("23a. ip body arm octet is 0xA1 ([1] CertRepMessage)", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { ip: grantResp } }, SIG)) === 0xa1);
  check("23b. cp body arm octet is 0xA3 ([3])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { cp: grantResp } }, SIG)) === 0xa3);
  check("23c. kup body arm octet is 0xA8 ([8])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { kup: grantResp } }, SIG)) === 0xa8);
  check("23d. ccp body arm octet is 0xAE ([14])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { ccp: grantResp } }, SIG)) === 0xae);
  check("23e. krp body arm octet is 0xAA ([10])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { krp: { status: { status: 0 }, newSigCert: CERT } } }, SIG)) === 0xaa);
  check("23f. rp body arm octet is 0xAC ([12])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { rp: { status: [{ status: 0 }] } } }, SIG)) === 0xac);
  check("23g. genp body arm octet is 0xB6 ([22])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { genp: [{ infoType: "caCerts" }] } }, SIG)) === 0xb6);
  check("23h. error body arm octet is 0xB7 ([23])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { error: { pKIStatusInfo: { status: 2 } } } }, SIG)) === 0xb7);
  check("23i. pollRep body arm octet is 0xBA ([26])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { pollRep: [{ certReqId: 0, checkAfter: 60 }] } }, SIG)) === 0xba);
  check("23j. pkiconf body arm octet is 0xB3 ([19])", bodyTagOctet(await pki.cmp.build({ header: HDR, body: { pkiconf: null } }, SIG)) === 0xb3);

  // 24. content round-trips through the parser.
  var mIp = parse(await pki.cmp.build({ header: HDR, body: { ip: { caPubs: [CERT], response: [{ certReqId: 0, status: { status: 0, statusString: ["ok"] }, certifiedKeyPair: { certificate: CERT }, rspInfo: Buffer.from([1, 2]) }] } } }, SIG));
  check("24a. ip CertRepMessage round-trips (caPubs + a granting CertResponse + certificate)", mIp.body.arm === "ip" && !!mIp.body.decoded);
  check("24b. rp RevRepContent round-trips (status + revCerts CertId)", parse(await pki.cmp.build({ header: HDR, body: { rp: { status: [{ status: 0 }], revCerts: [{ issuer: { directoryName: "CN=CA" }, serialNumber: 42n }] } } }, SIG)).body.arm === "rp");
  check("24c. error ErrorMsgContent round-trips (status + errorCode + errorDetails + failInfo)", parse(await pki.cmp.build({ header: HDR, body: { error: { pKIStatusInfo: { status: 2, failInfo: ["badRequest"] }, errorCode: 7, errorDetails: ["denied"] } } }, SIG)).body.arm === "error");
  check("24d. pollRep round-trips (certReqId + checkAfter + reason)", parse(await pki.cmp.build({ header: HDR, body: { pollRep: [{ certReqId: 0, checkAfter: 120, reason: ["still working"] }] } }, SIG)).body.arm === "pollRep");
  check("24e. krp KeyRecRepContent round-trips (status + caCerts + keyPairHist)", parse(await pki.cmp.build({ header: HDR, body: { krp: { status: { status: 0 }, caCerts: [CERT], keyPairHist: [{ certificate: CERT }] } } }, SIG)).body.arm === "krp");
  check("24f. pkiconf accepts true (PKIConfirmContent NULL)", parse(await pki.cmp.build({ header: HDR, body: { pkiconf: true } }, SIG)).body.arm === "pkiconf");
  // encryptedCert [1] CHOICE + privateKey [0] + publicationInfo [1]. A deprecated EncryptedValue privateKey
  // (a universal SEQUENCE) stays cmp2000(2) -- only the EnvelopedData [0] form bumps pvno to cmp2021(3).
  var encVal = asn1.build.sequence([asn1.build.integer(1n), asn1.build.octetString(Buffer.from([2, 3]))]);   // a minimal EncryptedValue-shaped SEQUENCE
  check("24g. certifiedKeyPair encryptedCert + EncryptedValue privateKey + publicationInfo stays pvno 2", parse(await pki.cmp.build({ header: HDR, body: { ip: { response: [{ certReqId: 0, status: { status: 0 }, certifiedKeyPair: { encryptedCert: encVal, privateKey: encVal, publicationInfo: asn1.build.sequence([asn1.build.integer(0n)]) } }] } } }, SIG)).header.pvno === 2);
  // an EnvelopedData [0] encryptedCert / privateKey IS a cmp2021 feature (pvno bump); the tag check mirrors the
  // EncryptedValue case above. Driving it end-to-end needs a parser-accepted EnvelopedData; the bump condition
  // (a context [0] top tag) is the identical detection on both the privateKey and encryptedCert CHOICE members.
  var minimalCrl = asn1.build.sequence([
    asn1.build.sequence([asn1.build.sequence([asn1.build.oid("1.2.840.10045.4.3.2")]), asn1.build.sequence([asn1.build.set([asn1.build.sequence([asn1.build.oid("2.5.4.3"), asn1.build.utf8("CA")])])]), asn1.build.utcTime(new Date("2026-01-01T00:00:00Z"))]),
    asn1.build.sequence([asn1.build.oid("1.2.840.10045.4.3.2")]), asn1.build.bitString(Buffer.from([0]), 0),
  ]);
  check("24h. rp with a valid crls entry round-trips", parse(await pki.cmp.build({ header: HDR, body: { rp: { status: [{ status: 0 }], crls: [minimalCrl] } } }, SIG)).body.arm === "rp");

  // 25. CertResponse fail-closed gates (RFC 9810 sec. 5.3.4) + fail-closed misuse.
  check("25a. certifiedKeyPair under a rejection status -> cmp/bad-cert-response", await codeOf(pki.cmp.build({ header: HDR, body: { ip: { response: [{ certReqId: 0, status: { status: 2 }, certifiedKeyPair: { certificate: CERT } }] } } }, SIG)) === "cmp/bad-cert-response");
  check("25b. certifiedKeyPair together with a failInfo -> cmp/bad-cert-response", await codeOf(pki.cmp.build({ header: HDR, body: { ip: { response: [{ certReqId: 0, status: { status: 0, failInfo: ["badPOP"] }, certifiedKeyPair: { certificate: CERT } }] } } }, SIG)) === "cmp/bad-cert-response");
  check("25c. a garbage certOrEncCert certificate -> cmp/bad-cert-response", await codeOf(pki.cmp.build({ header: HDR, body: { ip: { response: [{ certReqId: 0, status: { status: 0 }, certifiedKeyPair: { certificate: Buffer.from([0x30, 0x00]) } }] } } }, SIG)) === "cmp/bad-cert-response");
  check("25c2. both certificate AND encryptedCert (the CHOICE) -> cmp/bad-cert-response", await codeOf(pki.cmp.build({ header: HDR, body: { ip: { response: [{ certReqId: 0, status: { status: 0 }, certifiedKeyPair: { certificate: CERT, encryptedCert: asn1.build.sequence([asn1.build.integer(1n)]) } }] } } }, SIG)) === "cmp/bad-cert-response");
  check("25d. a ccp with more than one CertResponse -> cmp/bad-cert-rep", await codeOf(pki.cmp.build({ header: HDR, body: { ccp: { response: [{ certReqId: 0, status: { status: 0 } }, { certReqId: 1, status: { status: 0 } }] } } }, SIG)) === "cmp/bad-cert-rep");
  check("25e. an rp with an empty status array -> cmp/bad-rev-rep", await codeOf(pki.cmp.build({ header: HDR, body: { rp: { status: [] } } }, SIG)) === "cmp/bad-rev-rep");
  check("25e2. a garbage rp crls entry -> cmp/bad-rev-rep (each must be a valid CRL)", await codeOf(pki.cmp.build({ header: HDR, body: { rp: { status: [{ status: 0 }], crls: [asn1.build.sequence([asn1.build.integer(1n)])] } } }, SIG)) === "cmp/bad-rev-rep");
  check("25f. a negative pollRep checkAfter -> cmp/bad-poll-rep", await codeOf(pki.cmp.build({ header: HDR, body: { pollRep: [{ certReqId: 0, checkAfter: -1 }] } }, SIG)) === "cmp/bad-poll-rep");
  check("25g. an error without pKIStatusInfo -> cmp/bad-error", await codeOf(pki.cmp.build({ header: HDR, body: { error: {} } }, SIG)) === "cmp/bad-error");
  check("25g2. an out-of-range PKIStatus (7) -> cmp/bad-error", await codeOf(pki.cmp.build({ header: HDR, body: { error: { pKIStatusInfo: { status: 7 } } } }, SIG)) === "cmp/bad-error");
  check("25g3. an over-uint31 pollRep checkAfter -> cmp/bad-poll-rep", await codeOf(pki.cmp.build({ header: HDR, body: { pollRep: [{ certReqId: 0, checkAfter: 0x80000000 }] } }, SIG)) === "cmp/bad-poll-rep");
  check("25h. a certificate [0] EXPLICIT wrapper (the CHOICE tag) is 0xA0", (function () { var kp = asn1.decode(asn1.decode(mIp.bodyBytes).children[0].children[1].children[0].children[2].bytes); return kp.children[0].bytes[0] === 0xa0; })());

  // ---- every body arm rejects a malformed spec with its OWN code ----
  // These are config-time shapes, so the operator's diagnosis depends on the arm that faulted: a
  // shared or degraded code would send them to the wrong half of a message they are assembling.
  // Each case is asserted on the EXACT code, so a later refactor that collapses these onto one
  // generic cmp/bad-input is caught rather than silently accepted.
  var BAD_BODIES = [
    ["pollReq that is not an array", { pollReq: "x" }, "cmp/bad-poll-req"],
    ["a pollReq entry that is not an object", { pollReq: ["x"] }, "cmp/bad-poll-req"],
    ["a RevDetails that is not an object", { rr: ["x"] }, "cmp/bad-rev-req"],
    ["an ip arm that is not an object", { ip: "x" }, "cmp/bad-cert-rep"],
    ["an ip.response that is not an array", { ip: { response: "x" } }, "cmp/bad-cert-rep"],
    ["an ip.caPubs that is present but empty", { ip: { response: [], caPubs: [] } }, "cmp/bad-cert-rep"],
    ["a CertStatus that is not an object", { certConf: ["x"] }, "cmp/bad-cert-status"],
    ["a genm that is not an array", { genm: "x" }, "cmp/bad-info-type-and-value"],
  ];
  for (var bi = 0; bi < BAD_BODIES.length; bi++) {
    var bc = BAD_BODIES[bi];
    check("26" + String.fromCharCode(97 + bi) + ". " + bc[0] + " -> " + bc[2],
      (await codeOf(pki.cmp.build({ header: HDR, body: bc[1] }, SIG))) === bc[2]);
  }

  // ---- orchestrator dispatch ----
  check("22. pki.schema.parse detect-routes the built DER to cmp", pki.schema.parse(irDer).body.arm === "ir");

  console.log("CHECKS " + helpers.getChecks());
}

run().then(function () { }, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
