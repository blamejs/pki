// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the RFC 3161 TSP request/response wrappers and the token verifier that complete
 * the pki.tsp surface (sign + token parsing already ship). Drives the shipped consumer path
 * pki.tsp.request / parseRequest / response / parseResponse / verify. This file covers the
 * request/response layer (build + parse round-trips + the DER DEFAULT-FALSE and status<->token
 * coupling rules); the token-verifier vectors (signature, imprint match, the out-of-path TSA-cert
 * validation, the ESSCertID binding, the critical single-timeStamping EKU, the nonce, and the
 * read-from-verified-eContent desync proof) are exercised alongside real cert-chain fixtures.
 *
 * RED baseline: pki.tsp.request / parseRequest / response / parseResponse are undefined until the
 * module lands, so every vector throws.
 */

var crypto = require("node:crypto");
var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var b = pki.asn1.build;

var DATA = Buffer.from("the document the timestamp request covers");
function imprint(hashAlgorithm) {
  return { hashAlgorithm: hashAlgorithm, hashedMessage: crypto.createHash(hashAlgorithm).update(DATA).digest() };
}

// ---- A1: request round-trip with every optional present ----
function testRequestRoundTrip() {
  var mi = imprint("sha256");
  var der = pki.tsp.request(mi, { reqPolicy: "1.2.3.4.1", nonce: 0x0102030405060708n, certReq: true });
  check("request returns a DER Buffer", Buffer.isBuffer(der));
  var req = pki.tsp.parseRequest(der);
  check("A1 version is 1", req.version === 1);
  check("A1 messageImprint hash round-trips", Buffer.compare(req.messageImprint.hashedMessage, mi.hashedMessage) === 0);
  check("A1 reqPolicy round-trips", req.reqPolicy === "1.2.3.4.1");
  check("A1 nonce lossless (BigInt + hex)", req.nonce === 0x0102030405060708n && req.nonceHex === "0102030405060708");
  check("A1 certReq true round-trips", req.certReq === true);
  // the schema-namespace parser (pki.schema.tsp.parseRequest) is the same decoder the pki.tsp
  // delegate wraps -- exercise it directly so both public paths are covered.
  var schemaReq = pki.schema.tsp.parseRequest(der);
  check("A1 pki.schema.tsp.parseRequest agrees", schemaReq.nonce === req.nonce && schemaReq.certReq === true);
  // the built DER is byte-stable (a second build of the same inputs is identical).
  check("A1 request DER is byte-stable", Buffer.compare(pki.tsp.request(mi, { reqPolicy: "1.2.3.4.1", nonce: 0x0102030405060708n, certReq: true }), der) === 0);
}

// ---- A2: minimal request -- DEFAULT FALSE certReq is OMITTED, optionals absent ----
function testRequestMinimal() {
  var der = pki.tsp.request(imprint("sha256"));
  var req = pki.tsp.parseRequest(der);
  check("A2 certReq defaults false", req.certReq === false);
  check("A2 nonce absent -> null", req.nonce === null);
  check("A2 reqPolicy absent -> null", req.reqPolicy === null);
  // certReq DEFAULT FALSE must not be encoded: no BOOLEAN (tag 0x01) in the request body.
  check("A2 DEFAULT-FALSE certReq omitted from the DER", der.indexOf(0x01, 2) === -1 || der.indexOf(Buffer.from([0x01, 0x01, 0x00])) === -1);
}

// ---- A3: response round-trip (granted) wraps a real token ----
async function testResponseGranted() {
  var token = await pki.tsp.sign(imprint("sha256"), makeSigner("ec-p256"), { policy: "1.2.3", serialNumber: 1, genTime: new Date("2027-01-01T00:00:00Z") });
  var der = pki.tsp.response(token, {});
  check("response returns a DER Buffer", Buffer.isBuffer(der));
  var resp = pki.tsp.parseResponse(der);
  check("A3 status granted (0)", resp.status === 0);
  check("A3 timeStampToken present + decoded", resp.timeStampToken && resp.timeStampToken.tstInfo.genTime instanceof Date);
  check("A3 token genTime round-trips", resp.timeStampToken.tstInfo.genTime.toISOString() === "2027-01-01T00:00:00.000Z");
}

// ---- A4: response rejection carries a PKIStatusInfo, no token ----
function testResponseRejection() {
  var der = pki.tsp.response(null, { status: 2, failInfo: ["badAlg"] });
  var resp = pki.tsp.parseResponse(der);
  check("A4 status rejection (2)", resp.status === 2);
  check("A4 failInfo decoded", resp.failInfo && resp.failInfo.bits.indexOf("badAlg") !== -1);
  check("A4 no token on rejection", resp.timeStampToken === null);
}

// ---- R2: a request encoding an explicit certReq FALSE is non-DER (DEFAULT must be omitted) ----
function testCertReqExplicitFalseRejected() {
  // hand-build a TimeStampReq whose certReq BOOLEAN FALSE is explicitly present.
  var mi = imprint("sha256");
  var reqDer = b.sequence([
    b.integer(1n),
    b.sequence([b.sequence([b.oid(pki.oid.byName("sha256")), b.nullValue()]), b.octetString(mi.hashedMessage)]),
    b.boolean(false),   // certReq DEFAULT FALSE encoded explicitly -- non-canonical
  ]);
  rejectsSync("R2 explicit certReq FALSE", function () { return pki.tsp.parseRequest(reqDer); }, "tsp/bad-request");
}

// ---- R11: strict DER -- a non-minimal / trailing-byte request is refused ----
function testStrictDer() {
  var mi = imprint("sha256");
  var good = pki.tsp.request(mi);
  var trailing = Buffer.concat([good, Buffer.from([0x00])]);
  rejectsSync("R11 trailing byte after TimeStampReq", function () { return pki.tsp.parseRequest(trailing); }, "tsp/bad-der");
}

// ---- R13: the response orchestrator still routes a TimeStampResp to schema.tsp ----
async function testOrchestratorRouting() {
  var token = await pki.tsp.sign(imprint("sha256"), makeSigner("ec-p256"), { policy: "1.2.3", serialNumber: 2 });
  var der = pki.tsp.response(token, {});
  // pki.schema.parse detects + routes; a TimeStampResp yields the tsp result (a tsp-specific
  // timeStampToken shape), proving it routed to schema.tsp and was not mis-detected.
  var routed = pki.schema.parse(der);
  check("R13 TimeStampResp routes to the tsp parser", routed && routed.status === 0 && routed.timeStampToken && routed.timeStampToken.tstInfo.genTime instanceof Date);
}

function rejectsSync(label, fn, code) {
  var e = null;
  try { fn(); } catch (err) { e = err; }
  check(label + " throws", e !== null);
  check(label + " code=" + code, e && e.code === code);
}
async function rejects(label, fn, code) {
  var e = null;
  try { await fn(); } catch (err) { e = err; }
  check(label + " throws", e !== null);
  check(label + " code=" + code, e && e.code === code);
}

// ---- verifier fixtures: a REAL self-signed TSA cert (makeSigner's dummy signature would not
// pass path.validate). Modeled on path-validate.test.js's cert builders, self-contained here. ----
var TS_EKU = pki.oid.byName("timeStamping");
var CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";   // a non-timeStamping purpose (dotted is fine in a test)
function extDer(oidStr, critical, valueDer) {
  var ch = [b.oid(oidStr)];
  if (critical) ch.push(b.boolean(true));
  ch.push(b.octetString(valueDer));
  return b.sequence(ch);
}
function ekuExt(purposeOids, critical) { return extDer(pki.oid.byName("extKeyUsage"), critical, b.sequence(purposeOids.map(function (o) { return b.oid(o); }))); }
function certName(cn) { return b.sequence([b.set([b.sequence([b.oid("2.5.4.3"), b.utf8(cn)])])]); }

// makeTsa(ext, opts) -> { cert (DER), key (PKCS#8 DER), anchor } for a self-signed TSA with a REAL
// signature. `ext` is a single Extension DER or an array of them. opts: keyType ("ec"|"ed25519"),
// notBefore/notAfter (Date), name, serial.
function makeTsa(ext, opts) {
  opts = opts || {};
  var kp, algId, signFn;
  if (opts.keyType === "ed25519") {
    kp = crypto.generateKeyPairSync("ed25519");
    algId = b.sequence([b.oid(pki.oid.byName("Ed25519"))]);
    signFn = function (tbs) { return crypto.sign(null, tbs, kp.privateKey); };
  } else {
    kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    algId = b.sequence([b.oid(pki.oid.byName("ecdsaWithSHA256"))]);
    signFn = function (tbs) { return crypto.sign("sha256", tbs, { key: kp.privateKey, dsaEncoding: "der" }); };
  }
  var name = opts.name || "TSA";
  var tbsCh = [
    b.contextConstructed(0, b.integer(2n)),   // version [0] EXPLICIT v3
    b.integer(BigInt(opts.serial == null ? 1 : opts.serial)),
    algId,
    certName(name),
    b.sequence([b.utcTime(opts.notBefore || new Date("2020-01-01T00:00:00Z")), b.utcTime(opts.notAfter || new Date("2035-01-01T00:00:00Z"))]),
    certName(name),
    b.raw(kp.publicKey.export({ format: "der", type: "spki" })),
  ];
  var extList = Array.isArray(ext) ? ext : (ext ? [ext] : []);
  if (extList.length) tbsCh.push(b.contextConstructed(3, b.sequence(extList)));
  var tbs = b.sequence(tbsCh);
  var cert = b.sequence([tbs, algId, b.bitString(signFn(tbs), 0)]);
  var parsed = pki.schema.x509.parse(cert);
  return {
    cert: cert, key: kp.privateKey.export({ format: "der", type: "pkcs8" }),
    anchor: { name: parsed.subject, publicKey: parsed.subjectPublicKeyInfo.bytes, algorithm: parsed.signatureAlgorithm.oid },
  };
}

var GENTIME = new Date("2027-01-01T00:00:00Z");
function signToken(tsa, extra) {
  return pki.tsp.sign(imprint("sha256"), { cert: tsa.cert, key: tsa.key }, Object.assign({ policy: "1.2.3.4.1", serialNumber: 7, genTime: GENTIME }, extra || {}));
}

// ---- A5/A6/A7: accept with anchor, accept without anchor, precomputed imprint ----
async function testVerifyAccept() {
  var tsa = makeTsa(ekuExt([TS_EKU], true));   // critical, exclusive id-kp-timeStamping
  var token = await signToken(tsa);
  var res = await pki.tsp.verify(token, DATA, { trustAnchor: tsa.anchor });
  check("A5 valid with trust anchor", res.valid === true);
  check("A5 genTime from verified eContent", res.genTime instanceof Date && res.genTime.toISOString() === "2027-01-01T00:00:00.000Z");
  check("A5 serialNumber surfaced (lossless)", res.serialNumber === 7n);
  check("A5 policy surfaced", res.policy === "1.2.3.4.1");
  var res6 = await pki.tsp.verify(token, DATA, {});
  check("A6 valid without anchor; TSA cert surfaced for the caller to anchor", res6.valid === true && res6.signer && Buffer.isBuffer(res6.signer.cert));
  var res7 = await pki.tsp.verify(token, imprint("sha256"), {});
  check("A7 precomputed imprint matches", res7.valid === true);
}

// ---- A8: nonce echoed and required ----
async function testVerifyNonce() {
  var tsa = makeTsa(ekuExt([TS_EKU], true));
  var withNonce = await signToken(tsa, { nonce: 0x0102030405060708n });
  check("A8 nonce match -> valid", (await pki.tsp.verify(withNonce, DATA, { nonce: 0x0102030405060708n })).valid === true);
  var r7 = await pki.tsp.verify(withNonce, DATA, { nonce: 0xdeadbeefn });
  check("R7 nonce mismatch -> tsp/nonce-mismatch", r7.valid === false && r7.code === "tsp/nonce-mismatch");
  var noNonce = await signToken(tsa);
  var r7b = await pki.tsp.verify(noNonce, DATA, { nonce: 1n });
  check("R7 nonce required but absent -> tsp/nonce-mismatch", r7b.valid === false && r7b.code === "tsp/nonce-mismatch");
}

// ---- A9: algorithm-agnostic signer (the CMS layer carries any signer) ----
async function testVerifyAlgAgnostic() {
  var edTsa = makeTsa(ekuExt([TS_EKU], true), { keyType: "ed25519" });
  var token = await signToken(edTsa);
  check("A9 Ed25519 TSA verifies", (await pki.tsp.verify(token, DATA, { trustAnchor: edTsa.anchor })).valid === true);
}

// ---- R1: message-imprint mismatch ----
async function testVerifyImprintMismatch() {
  var tsa = makeTsa(ekuExt([TS_EKU], true));
  var token = await signToken(tsa);
  var r1 = await pki.tsp.verify(token, Buffer.from("a different document"), {});
  check("R1 imprint mismatch -> tsp/imprint-mismatch", r1.valid === false && r1.code === "tsp/imprint-mismatch");
}

// ---- R3: a CMS SignedData whose eContentType != id-ct-TSTInfo is not a token (throws) ----
async function testVerifyWrongEContentType() {
  var tsa = makeTsa(ekuExt([TS_EKU], true));
  var notAToken = await pki.cms.sign(Buffer.from("plain content"), { cert: tsa.cert, key: tsa.key });   // eContentType id-data
  await rejects("R3 wrong eContentType", function () { return pki.tsp.verify(notAToken, DATA, {}); }, "tsp/wrong-econtent-type");
}

// ---- R4/R5/R5b: the RFC 3161 sec. 2.3 critical single-timeStamping EKU gate ----
async function testVerifyEkuGate() {
  var nonCrit = makeTsa(ekuExt([TS_EKU], false));   // present but NOT critical
  var r4 = await pki.tsp.verify(await signToken(nonCrit), DATA, {});
  check("R4 non-critical EKU -> tsp/eku-not-critical", r4.valid === false && r4.code === "tsp/eku-not-critical");
  var extra = makeTsa(ekuExt([TS_EKU, CLIENT_AUTH], true));   // timeStamping + clientAuth
  var r5 = await pki.tsp.verify(await signToken(extra), DATA, {});
  check("R5 extra EKU purpose -> tsp/eku-not-exclusive", r5.valid === false && r5.code === "tsp/eku-not-exclusive");
  var anyEku = makeTsa(ekuExt([pki.oid.byName("anyExtendedKeyUsage")], true));
  var r5any = await pki.tsp.verify(await signToken(anyEku), DATA, {});
  check("R5 anyExtendedKeyUsage -> tsp/eku-not-exclusive", r5any.valid === false && r5any.code === "tsp/eku-not-exclusive");
  var noEku = makeTsa(null);   // extKeyUsage absent
  var r5b = await pki.tsp.verify(await signToken(noEku), DATA, {});
  check("R5b absent EKU -> tsp/bad-eku (RFC 3161 sec. 2.3 requires it present+critical)", r5b.valid === false && r5b.code === "tsp/bad-eku");
}

// ---- R6: genTime outside the TSA cert validity window (path.validate at time=genTime) ----
async function testVerifyExpired() {
  var expired = makeTsa(ekuExt([TS_EKU], true), { notBefore: new Date("2018-01-01T00:00:00Z"), notAfter: new Date("2019-01-01T00:00:00Z") });
  var token = await signToken(expired);   // genTime 2027 is outside 2018..2019
  var r6 = await pki.tsp.verify(token, DATA, { trustAnchor: expired.anchor });
  check("R6 expired TSA at genTime -> tsp/untrusted-tsa", r6.valid === false && r6.code === "tsp/untrusted-tsa");
}

// ---- R8: ESSCertID(V2) binding mismatch (a signed but WRONG certHash) ----
async function testVerifyBinding() {
  var tsa = makeTsa(ekuExt([TS_EKU], true));
  var mi = imprint("sha256");
  var tstInfo = b.sequence([b.integer(1n), b.oid("1.2.3.4.1"),
    b.sequence([b.sequence([b.oid(pki.oid.byName("sha256")), b.nullValue()]), b.octetString(mi.hashedMessage)]),
    b.integer(9n), b.generalizedTime(GENTIME)]);
  // a SigningCertificateV2 binding to a bogus (all-zeroes sha256) certHash, signed over the attrs.
  var bogusScv2 = b.sequence([b.sequence([b.sequence([b.octetString(Buffer.alloc(32))])])]);
  var badToken = await pki.cms.sign(tstInfo, { cert: tsa.cert, key: tsa.key },
    { eContentType: "tSTInfo", additionalSignedAttributes: [{ type: "signingCertificateV2", values: [bogusScv2] }] });
  var r8 = await pki.tsp.verify(badToken, DATA, {});
  check("R8 ESSCertID binding mismatch -> tsp/cert-binding-mismatch", r8.valid === false && r8.code === "tsp/cert-binding-mismatch");
}

// ---- R9: a well-formed, correctly-bound token whose TSA cert does not chain to the anchor ----
async function testVerifyUntrusted() {
  var tsa = makeTsa(ekuExt([TS_EKU], true));
  var other = makeTsa(ekuExt([TS_EKU], true), { name: "OtherRoot" });   // a different key
  var token = await signToken(tsa);
  var r9 = await pki.tsp.verify(token, DATA, { trustAnchor: other.anchor });
  check("R9 TSA does not chain to the anchor -> tsp/untrusted-tsa", r9.valid === false && r9.code === "tsp/untrusted-tsa");
}

// ---- R10 (desync): verify reads from the authenticated eContent, ignoring a mutated parsed object ----
async function testVerifyDesync() {
  var tsa = makeTsa(ekuExt([TS_EKU], true));
  var token = await signToken(tsa, { nonce: 0x11223344n });
  var parsed = pki.schema.tsp.parseToken(token);
  parsed.tstInfo.messageImprint.hashedMessage = Buffer.alloc(32);   // mutate the parsed object
  parsed.tstInfo.nonce = 0x99n;
  // verify takes the TOKEN BYTES and re-decodes TSTInfo from the authenticated eContent, so the
  // mutation to the separate parsed object has no effect on the verdict.
  var res = await pki.tsp.verify(token, DATA, { trustAnchor: tsa.anchor, nonce: 0x11223344n });
  check("R10 verify ignores a mutated parsed object (reads verified eContent)", res.valid === true);
}

// ---- branch coverage: the reachable edges of request/response/verify not hit above ----
async function testTspCoverage() {
  var tsa = makeTsa(ekuExt([TS_EKU], true));
  var token = await signToken(tsa);
  // _tokenDer: a PEM-string token (verify path), a Uint8Array token (response path), and the throw.
  var pemTok = pki.schema.tsp.pemEncode(token, "TIMESTAMP TOKEN");
  check("verify accepts a PEM token", (await pki.tsp.verify(pemTok, DATA, {})).valid !== undefined);
  check("response accepts a Uint8Array token", Buffer.isBuffer(pki.tsp.response(new Uint8Array(token), {})));
  rejectsSync("response with a non-DER/PEM token -> tsp/bad-input", function () { return pki.tsp.response(12345, {}); }, "tsp/bad-input");
  // request extensions ([0] IMPLICIT Extensions).
  var reqExt = pki.tsp.request(imprint("sha256"), { extensions: [extDer("1.2.3.4.5", false, Buffer.from([0x05, 0x00]))] });
  check("request with extensions parses", pki.tsp.parseRequest(reqExt).extensions !== null);
  // response statusString (PKIFreeText).
  var rej = pki.tsp.response(null, { status: 2, statusString: "policy not supported", failInfo: ["unacceptedPolicy"] });
  check("response statusString round-trips", pki.tsp.parseResponse(rej).statusString[0] === "policy not supported");
  // verify data config error -> throw tsp/bad-input.
  await rejects("verify with a non-Buffer/imprint data", function () { return pki.tsp.verify(token, 12345, {}); }, "tsp/bad-input");
  // verify reqPolicy match + mismatch (M15).
  check("verify reqPolicy match", (await pki.tsp.verify(token, DATA, { trustAnchor: tsa.anchor, reqPolicy: "1.2.3.4.1" })).valid === true);
  var pm = await pki.tsp.verify(token, DATA, { reqPolicy: "9.9.9" });
  check("verify reqPolicy mismatch -> tsp/policy-mismatch", pm.valid === false && pm.code === "tsp/policy-mismatch");
  // verify with no opts arg (opts defaults) + a bad opts type.
  check("verify with no opts arg completes", (await pki.tsp.verify(token, DATA)).valid !== undefined);
  await rejects("verify bad opts type -> tsp/bad-input", function () { return pki.tsp.verify(token, DATA, Buffer.from([1])); }, "tsp/bad-input");
  // a tampered signature -> cms.verify fails -> tsp/bad-signature verdict.
  var tampered = Buffer.from(token); tampered[tampered.length - 4] ^= 0xff;
  var ts = await pki.tsp.verify(tampered, DATA, {});
  check("tampered signature -> tsp/bad-signature", ts.valid === false && ts.code === "tsp/bad-signature");
  // reqPolicy as a registered OID NAME (the name-resolution arm of the policy comparison).
  var namedTok = await pki.tsp.sign(imprint("sha256"), { cert: tsa.cert, key: tsa.key }, { policy: "sha256", serialNumber: 3, genTime: GENTIME });
  check("verify reqPolicy by name", (await pki.tsp.verify(namedTok, DATA, { reqPolicy: "sha256" })).valid === true);
  // Q2: an unknown imprint hash OID cannot be recomputed -> fail closed, never an assumed match.
  var scv2 = b.sequence([b.sequence([b.sequence([b.octetString(crypto.createHash("sha256").update(tsa.cert).digest())])])]);
  var weirdTst = b.sequence([b.integer(1n), b.oid("1.2.3.4.1"),
    b.sequence([b.sequence([b.oid("1.2.3.99")]), b.octetString(Buffer.alloc(32))]), b.integer(4n), b.generalizedTime(GENTIME)]);
  var weirdTok = await pki.cms.sign(weirdTst, { cert: tsa.cert, key: tsa.key },
    { eContentType: "tSTInfo", additionalSignedAttributes: [{ type: "signingCertificateV2", values: [scv2] }] });
  var wr = await pki.tsp.verify(weirdTok, DATA, {});
  check("unknown imprint hash -> tsp/unsupported-algorithm (fail closed)", wr.valid === false && wr.code === "tsp/unsupported-algorithm");
  // a precomputed imprint under a DIFFERENT algorithm than the token's -> mismatch.
  var altImprint = { hashAlgorithm: "sha512", hashedMessage: crypto.createHash("sha512").update(DATA).digest() };
  var im2 = await pki.tsp.verify(token, altImprint, {});
  check("precomputed imprint under a different algorithm -> tsp/imprint-mismatch", im2.valid === false && im2.code === "tsp/imprint-mismatch");
  // a critical extKeyUsage whose value is not a decodable SEQUENCE OF KeyPurposeId -> fail closed.
  var badEkuTsa = makeTsa(extDer(pki.oid.byName("extKeyUsage"), true, Buffer.from([0xff, 0x01, 0x00])));
  var be = await pki.tsp.verify(await signToken(badEkuTsa), DATA, {});
  check("malformed critical EKU value -> tsp/bad-eku", be.valid === false && be.code === "tsp/bad-eku");
  // an ESSCertID(V2) using an unsupported hash algorithm cannot be recomputed -> fail closed.
  var goodImprint = b.sequence([b.sequence([b.oid(pki.oid.byName("sha256")), b.nullValue()]), b.octetString(imprint("sha256").hashedMessage)]);
  var tst371 = b.sequence([b.integer(1n), b.oid("1.2.3.4.1"), goodImprint, b.integer(5n), b.generalizedTime(GENTIME)]);
  var badHashScv2 = b.sequence([b.sequence([b.sequence([b.sequence([b.oid("1.2.3.99")]), b.octetString(Buffer.alloc(32))])])]);
  var tok371 = await pki.cms.sign(tst371, { cert: tsa.cert, key: tsa.key }, { eContentType: "tSTInfo", additionalSignedAttributes: [{ type: "signingCertificateV2", values: [badHashScv2] }] });
  var r371 = await pki.tsp.verify(tok371, DATA, {});
  check("unsupported ESSCertID hash -> tsp/unsupported-algorithm", r371.valid === false && r371.code === "tsp/unsupported-algorithm");
  // response: failInfo on a non-rejection status, and an unknown PKIFailureInfo name, fail closed.
  rejectsSync("response failInfo on status!=2 -> tsp/unexpected-failinfo", function () { return pki.tsp.response(null, { status: 3, failInfo: ["badAlg"] }); }, "tsp/unexpected-failinfo");
  rejectsSync("response unknown failInfo name -> tsp/bad-input", function () { return pki.tsp.response(null, { status: 2, failInfo: ["notARealBit"] }); }, "tsp/bad-input");
  // verify accepts raw data as a Uint8Array (hashed under the imprint algorithm).
  check("verify hashes Uint8Array data", (await pki.tsp.verify(token, new Uint8Array(DATA), {})).valid !== undefined);
}

// ---- builder + input-validation branch coverage: reachable config-time throws, output forms,
// and the fail-closed binding rejects (a signed-but-malformed / empty ESS SigningCertificateV2) ----
async function testBuilderCoverage() {
  var mi = imprint("sha256");
  var tsa = makeTsa(ekuExt([TS_EKU], true));
  var token = await pki.tsp.sign(mi, makeSigner("ec-p256"), { policy: "1.2.3", serialNumber: 10 });
  // request: PEM output + the config-time input validations.
  check("request pem:true -> PEM string", typeof pki.tsp.request(mi, { pem: true }) === "string");
  rejectsSync("request bad opts type -> tsp/bad-input", function () { return pki.tsp.request(mi, Buffer.from([1])); }, "tsp/bad-input");
  rejectsSync("request with no messageImprint -> tsp/unsupported-algorithm", function () { return pki.tsp.request(); }, "tsp/unsupported-algorithm");
  rejectsSync("request certReq non-boolean -> tsp/bad-input", function () { return pki.tsp.request(mi, { certReq: "yes" }); }, "tsp/bad-input");
  rejectsSync("request extensions not an array -> tsp/bad-input", function () { return pki.tsp.request(mi, { extensions: "x" }); }, "tsp/bad-input");
  rejectsSync("request extensions with a non-buffer element -> tsp/bad-input", function () { return pki.tsp.request(mi, { extensions: [123] }); }, "tsp/bad-input");
  rejectsSync("request bad imprint hash -> tsp/unsupported-algorithm", function () { return pki.tsp.request({ hashAlgorithm: "md5", hashedMessage: Buffer.alloc(16) }); }, "tsp/unsupported-algorithm");
  rejectsSync("request non-Buffer hashedMessage -> tsp/bad-input", function () { return pki.tsp.request({ hashAlgorithm: "sha256", hashedMessage: "x" }); }, "tsp/bad-input");
  rejectsSync("request imprint length mismatch -> tsp/bad-input", function () { return pki.tsp.request({ hashAlgorithm: "sha256", hashedMessage: Buffer.alloc(31) }); }, "tsp/bad-input");
  var extBuf = b.sequence([b.oid("1.2.3.4"), b.octetString(Buffer.from([0x05, 0x00]))]);
  check("request with a valid extension buffer round-trips", pki.tsp.parseRequest(pki.tsp.request(mi, { extensions: [extBuf] })).extensions !== null);
  // response: PEM output, statusString as an ARRAY, and the _tokenDer coercion forms.
  rejectsSync("response bad opts type -> tsp/bad-input", function () { return pki.tsp.response(token, Buffer.from([1])); }, "tsp/bad-input");
  check("response with no opts arg builds a granted response", Buffer.isBuffer(pki.tsp.response(token)));
  check("response pem:true -> PEM string", typeof pki.tsp.response(token, { pem: true }) === "string");
  check("response statusString array round-trips", pki.tsp.parseResponse(pki.tsp.response(null, { status: 2, statusString: ["a", "b"], failInfo: ["badAlg"] })).statusString.length === 2);
  rejectsSync("response empty statusString array -> tsp/bad-input (PKIFreeText SIZE 1..MAX)", function () { return pki.tsp.response(null, { status: 2, statusString: [], failInfo: ["badAlg"] }); }, "tsp/bad-input");
  check("response accepts a Uint8Array token", Buffer.isBuffer(pki.tsp.response(new Uint8Array(token), {})));
  var pemToken = await pki.tsp.sign(mi, makeSigner("ec-p256"), { policy: "1.2.3", serialNumber: 11, pem: true });
  check("response accepts a PEM-string token", Buffer.isBuffer(pki.tsp.response(pemToken, {})));
  rejectsSync("response bad token type -> tsp/bad-input", function () { return pki.tsp.response(12345, {}); }, "tsp/bad-input");
  // response status + status<->token coupling throws (RFC 3161 sec. 2.4.2).
  rejectsSync("response status out of 0..5 -> tsp/bad-input", function () { return pki.tsp.response(null, { status: 9 }); }, "tsp/bad-input");
  rejectsSync("response granted with no token -> tsp/missing-token", function () { return pki.tsp.response(null, {}); }, "tsp/missing-token");
  rejectsSync("response non-granted with a token -> tsp/unexpected-token", function () { return pki.tsp.response(token, { status: 2 }); }, "tsp/unexpected-token");
  // _failInfoBits: non-array, empty array, and a high multi-byte bit (systemFailure = bit 25).
  rejectsSync("response non-array failInfo -> tsp/bad-input", function () { return pki.tsp.response(null, { status: 2, failInfo: "badAlg" }); }, "tsp/bad-input");
  check("response empty failInfo array builds", Buffer.isBuffer(pki.tsp.response(null, { status: 2, failInfo: [] })));
  check("response multi-byte failInfo (systemFailure) round-trips", pki.tsp.parseResponse(pki.tsp.response(null, { status: 2, failInfo: ["systemFailure"] })).failInfo.bits.indexOf("systemFailure") !== -1);
  // verify: a precomputed imprint whose hashedMessage is a Uint8Array (not a Buffer).
  var tsTok = await signToken(tsa);
  check("verify precomputed Uint8Array imprint matches", (await pki.tsp.verify(tsTok, { hashAlgorithm: "sha256", hashedMessage: new Uint8Array(imprint("sha256").hashedMessage) }, {})).valid === true);
  // verify binding: a signed-but-malformed ESS value, and an empty ESS certs list, both fail closed.
  var tstB = b.sequence([b.integer(1n), b.oid("1.2.3.4.1"), b.sequence([b.sequence([b.oid(pki.oid.byName("sha256")), b.nullValue()]), b.octetString(mi.hashedMessage)]), b.integer(20n), b.generalizedTime(GENTIME)]);
  function mkTok(scv2) { return pki.cms.sign(tstB, { cert: tsa.cert, key: tsa.key }, { eContentType: "tSTInfo", additionalSignedAttributes: [{ type: "signingCertificateV2", values: [scv2] }] }); }
  var rMal = await pki.tsp.verify(await mkTok(b.integer(1n)), DATA, {});
  check("malformed ESS signingCertificate value -> tsp/bad-signing-certificate", rMal.valid === false && rMal.code === "tsp/bad-signing-certificate");
  var rEmpty = await pki.tsp.verify(await mkTok(b.sequence([b.sequence([])])), DATA, {});
  check("empty ESS certs list -> tsp/bad-signing-certificate", rEmpty.valid === false && rEmpty.code === "tsp/bad-signing-certificate");
  // verify: a malformed trustAnchor makes path.validate fault -> caught fail-closed as tsp/untrusted-tsa.
  var ba = await pki.tsp.verify(tsTok, DATA, { trustAnchor: { name: "x", publicKey: Buffer.from([1, 2, 3]), algorithm: "1.2.840.10045.4.3.2" } });
  check("malformed trustAnchor -> tsp/untrusted-tsa", ba.valid === false && ba.code === "tsp/untrusted-tsa");
  // M11 keyUsage (RFC 5280 sec. 4.2.1.3): a TSA cert whose keyUsage forbids signing (keyEncipherment
  // only, no digitalSignature / nonRepudiation) cannot mint a token, even with a correct EKU.
  var keyEncOnly = extDer(pki.oid.byName("keyUsage"), true, b.bitString(Buffer.from([0x20]), 5));   // keyEncipherment (bit 2) only
  var noSignTsa = makeTsa([ekuExt([TS_EKU], true), keyEncOnly]);
  var kur = await pki.tsp.verify(await signToken(noSignTsa), DATA, {});
  check("TSA keyUsage without a signing bit -> tsp/bad-key-usage", kur.valid === false && kur.code === "tsp/bad-key-usage");
  // the accept arm: a keyUsage asserting digitalSignature (bit 0) passes the signing-permitted gate.
  var signTsa = makeTsa([ekuExt([TS_EKU], true), extDer(pki.oid.byName("keyUsage"), true, b.bitString(Buffer.from([0x80]), 7))]);
  check("TSA keyUsage with digitalSignature verifies", (await pki.tsp.verify(await signToken(signTsa), DATA, {})).valid === true);
  // nonRepudiation (bit 1) alone also permits signing -> accept.
  var nrTsa = makeTsa([ekuExt([TS_EKU], true), extDer(pki.oid.byName("keyUsage"), true, b.bitString(Buffer.from([0x40]), 6))]);
  check("TSA keyUsage with nonRepudiation verifies", (await pki.tsp.verify(await signToken(nrTsa), DATA, {})).valid === true);
  // an empty keyUsage (no bits) permits nothing -> reject.
  var emptyKuTsa = makeTsa([ekuExt([TS_EKU], true), extDer(pki.oid.byName("keyUsage"), true, b.bitString(Buffer.alloc(0), 0))]);
  check("TSA empty keyUsage -> tsp/bad-key-usage", (await pki.tsp.verify(await signToken(emptyKuTsa), DATA, {})).code === "tsp/bad-key-usage");
  // a keyUsage value that is not a BIT STRING fails closed via the decode catch.
  var badKuTsa = makeTsa([ekuExt([TS_EKU], true), extDer(pki.oid.byName("keyUsage"), true, b.integer(5n))]);
  check("TSA malformed keyUsage value -> tsp/bad-key-usage", (await pki.tsp.verify(await signToken(badKuTsa), DATA, {})).code === "tsp/bad-key-usage");
}

// An issuer-signed EC (P-256 / ecdsa-SHA256) certificate, for a multi-level chain.
function signedCert(subjectCN, issuerCN, subjectKp, issuerKp, exts) {
  var algId = b.sequence([b.oid(pki.oid.byName("ecdsaWithSHA256"))]);
  var tbsCh = [
    b.contextConstructed(0, b.integer(2n)),
    b.integer(BigInt(1 + Math.floor(Math.random() * 1e12))),
    algId, certName(issuerCN),
    b.sequence([b.utcTime(new Date("2020-01-01T00:00:00Z")), b.utcTime(new Date("2035-01-01T00:00:00Z"))]),
    certName(subjectCN),
    b.raw(subjectKp.publicKey.export({ format: "der", type: "spki" })),
  ];
  if (exts && exts.length) tbsCh.push(b.contextConstructed(3, b.sequence(exts)));
  var tbs = b.sequence(tbsCh);
  return b.sequence([tbs, algId, b.bitString(crypto.sign("sha256", tbs, { key: issuerKp.privateKey, dsaEncoding: "der" }), 0)]);
}
// Add an (unsigned) certificate to a token's SignedData certificates [0] SET -- the set is outside
// the signed content, so the signature stays valid; a verifier reads the fuller embedded chain.
function spliceCert(tokenDer, extraCertDer) {
  var ci = pki.asn1.decode(tokenDer);
  var sd = ci.children[1].children[0];   // [0] EXPLICIT -> SignedData
  var ch = sd.children, idx = -1;
  for (var i = 0; i < ch.length; i++) { if (ch[i].tagClass === "context" && ch[i].tagNumber === 0) { idx = i; break; } }
  var certs = ch[idx].children.map(function (c) { return c.bytes; });
  certs.push(extraCertDer); certs.sort(Buffer.compare);
  var newSd = b.sequence(ch.map(function (c, i) { return b.raw(i === idx ? b.contextConstructed(0, Buffer.concat(certs)) : c.bytes); }));
  return b.sequence([b.raw(ci.children[0].bytes), b.explicit(0, newSd)]);
}

// ---- Codex-round hardening: embedded-chain path validation, EKU-wrapper strictness, and the
// ESSCertID(V2) issuerSerial binding. ----
async function testChainAndBindings() {
  var bcCA = extDer(pki.oid.byName("basicConstraints"), true, b.sequence([b.boolean(true)]));
  var rootKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var interKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var leafKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var rootCert = signedCert("ChainRoot", "ChainRoot", rootKp, rootKp, [bcCA]);
  var interCert = signedCert("ChainInter", "ChainRoot", interKp, rootKp, [bcCA]);
  var leafCert = signedCert("ChainLeaf", "ChainInter", leafKp, interKp, [ekuExt([TS_EKU], true)]);
  var rootP = pki.schema.x509.parse(rootCert);
  var anchor = { name: rootP.subject, publicKey: rootP.subjectPublicKeyInfo.bytes, algorithm: rootP.signatureAlgorithm.oid };
  var chainTok = await pki.tsp.sign(imprint("sha256"), { cert: leafCert, key: leafKp.privateKey.export({ format: "der", type: "pkcs8" }) }, { policy: "1.2.3.4.1", serialNumber: 1, genTime: GENTIME });
  // #1: a TSA under an intermediate -- without the intermediate embedded, it cannot chain to the root.
  var noInter = await pki.tsp.verify(chainTok, DATA, { trustAnchor: anchor });
  check("TSA under an intermediate, chain NOT embedded -> tsp/untrusted-tsa", noInter.valid === false && noInter.code === "tsp/untrusted-tsa");
  // ...with the intermediate embedded, verify orders [leaf, inter] and validates to the root.
  var withInter = await pki.tsp.verify(spliceCert(chainTok, interCert), DATA, { trustAnchor: anchor });
  check("TSA under an intermediate, chain embedded -> valid", withInter.valid === true);

  // #2: the extKeyUsage extnValue MUST be a SEQUENCE OF -- a SET wrapper with the same OID child
  // must not slip through the children walk.
  var setEkuTsa = makeTsa(extDer(pki.oid.byName("extKeyUsage"), true, b.set([b.oid(TS_EKU)])));
  check("EKU wrapped in a SET (not SEQUENCE) -> tsp/bad-eku", (await pki.tsp.verify(await signToken(setEkuTsa), DATA, {})).code === "tsp/bad-eku");
  // ...and an EKU SEQUENCE whose element is not a KeyPurposeId OID fails the OID read -> tsp/bad-eku.
  var nonOidEkuTsa = makeTsa(extDer(pki.oid.byName("extKeyUsage"), true, b.sequence([b.integer(5n)])));
  check("EKU SEQUENCE with a non-OID element -> tsp/bad-eku", (await pki.tsp.verify(await signToken(nonOidEkuTsa), DATA, {})).code === "tsp/bad-eku");

  // #3: the ESSCertID(V2) issuerSerial, when present, MUST match the signer cert's serialNumber.
  var essTsa = makeTsa(ekuExt([TS_EKU], true));   // self-signed, serial 1, subject/issuer "TSA"
  var certHash = crypto.createHash("sha256").update(essTsa.cert).digest();
  function scv2(serial) {
    var is = b.sequence([b.sequence([b.contextConstructed(4, certName("TSA"))]), b.integer(BigInt(serial))]);
    return b.sequence([b.sequence([b.sequence([b.octetString(certHash), is])])]);
  }
  function essTok(serial) {
    var tst = b.sequence([b.integer(1n), b.oid("1.2.3.4.1"),
      b.sequence([b.sequence([b.oid(pki.oid.byName("sha256")), b.nullValue()]), b.octetString(imprint("sha256").hashedMessage)]),
      b.integer(50n), b.generalizedTime(GENTIME)]);
    return pki.cms.sign(tst, { cert: essTsa.cert, key: essTsa.key }, { eContentType: "tSTInfo", additionalSignedAttributes: [{ type: "signingCertificateV2", values: [scv2(serial)] }] });
  }
  check("ESSCertID issuerSerial wrong serial -> tsp/cert-binding-mismatch", (await pki.tsp.verify(await essTok(999), DATA, {})).code === "tsp/cert-binding-mismatch");
  check("ESSCertID issuerSerial correct serial verifies", (await pki.tsp.verify(await essTok(1), DATA, {})).valid === true);
}

async function run() {
  testRequestRoundTrip();
  testRequestMinimal();
  await testResponseGranted();
  testResponseRejection();
  testCertReqExplicitFalseRejected();
  testStrictDer();
  await testOrchestratorRouting();
  await testVerifyAccept();
  await testVerifyNonce();
  await testVerifyAlgAgnostic();
  await testVerifyImprintMismatch();
  await testVerifyWrongEContentType();
  await testVerifyEkuGate();
  await testVerifyExpired();
  await testVerifyBinding();
  await testVerifyUntrusted();
  await testVerifyDesync();
  await testTspCoverage();
  await testBuilderCoverage();
  await testChainAndBindings();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
