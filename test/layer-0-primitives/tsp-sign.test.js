// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.tsp.sign (RFC 3161 timestamp token creation, the producing side of
 * pki.schema.tsp.parseToken). A TimeStampToken is a CMS SignedData over a TSTInfo, so the
 * output is asserted through BOTH the independent CMS verifier (pki.cms.verify -- the signature)
 * AND the TSP parser (pki.schema.tsp.parseToken -- the TSTInfo shape + the round-tripped
 * imprint, policy, serial, genTime, nonce, accuracy). Config-time misuse fails closed with a
 * typed tsp/* error.
 *
 * RED baseline: pki.tsp.sign is undefined until the module lands, so every vector throws.
 */

var crypto = require("node:crypto");
var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;

var DATA = Buffer.from("the document being timestamped");
function imprint(hashAlgorithm) {
  var hashedMessage = crypto.createHash(hashAlgorithm).update(DATA).digest();
  return { hashAlgorithm: hashAlgorithm, hashedMessage: hashedMessage };
}

async function rejects(label, fn, code) {
  var e = null;
  try { await fn(); } catch (err) { e = err; }
  check(label + " throws", e !== null);
  check(label + " code=" + code, e && e.code === code);
}

// ---- round-trip: a full-featured token verifies and decodes ----
async function testRoundTrip() {
  var tsa = makeSigner("ec-p256");
  var mi = imprint("sha256");
  var token = await pki.tsp.sign(mi, tsa, {
    policy: "1.2.3.4.1", serialNumber: 42, genTime: new Date("2026-07-13T12:00:00Z"),
    nonce: 0xdeadbeefn, accuracy: { seconds: 1, millis: 500 }, ordering: true,
  });
  var v = await pki.cms.verify(token);
  check("timestamp token -> cms.verify valid", v.valid === true);
  var parsed = pki.schema.tsp.parseToken(token);
  var tst = parsed.tstInfo;
  check("token content is a TSTInfo v1", tst.version === 1);
  check("policy round-trips", tst.policy === "1.2.3.4.1");
  check("serialNumber round-trips", tst.serialNumber === 42n);
  check("messageImprint hash round-trips", Buffer.compare(tst.messageImprint.hashedMessage, mi.hashedMessage) === 0);
  check("genTime round-trips", tst.genTime instanceof Date && tst.genTime.toISOString() === "2026-07-13T12:00:00.000Z");
  check("nonce round-trips", tst.nonce === 0xdeadbeefn);
  check("accuracy round-trips", tst.accuracy && tst.accuracy.seconds === 1n && tst.accuracy.millis === 500);
  // the signing-certificate attribute (RFC 3161 sec. 2.4.2) binds the token to the TSA cert.
  var si = pki.schema.cms.parse(token).signerInfos[0];
  var hasSignCert = si.signedAttrs.some(function (a) { return a.type === pki.oid.byName("signingCertificateV2"); });
  check("signing-certificate attribute present", hasSignCert);
}

// ---- imprint hash algorithms + TSA key algorithms ----
async function testAlgorithms() {
  for (var h of ["sha256", "sha384", "sha512"]) {
    var t = await pki.tsp.sign(imprint(h), makeSigner("ec-p256"), { policy: "1.2.3", serialNumber: 1 });
    check("imprint " + h + " -> verifies", (await pki.cms.verify(t)).valid === true);
  }
  for (var alg of ["rsa", "ec-p384", "ed25519"]) {
    var t2 = await pki.tsp.sign(imprint("sha256"), makeSigner(alg), { policy: "1.2.3", serialNumber: 2 });
    check("TSA key " + alg + " -> verifies", (await pki.cms.verify(t2)).valid === true);
  }
  // a non-sha256 ESSCertIDv2 hash algorithm (carries an explicit hashAlgorithm).
  var t3 = await pki.tsp.sign(imprint("sha256"), makeSigner("ec-p256"), { policy: "1.2.3", serialNumber: 3, certHashAlgorithm: "sha512" });
  check("certHashAlgorithm sha512 -> verifies", (await pki.cms.verify(t3)).valid === true);
}

// ---- output passthrough: policy by name, PEM, sid ----
async function testPassthrough() {
  // policy as a registered OID name.
  var byName = await pki.tsp.sign(imprint("sha256"), makeSigner("ec-p256"), { policy: "sha256", serialNumber: 5 });
  check("policy by OID name -> verifies", (await pki.cms.verify(byName)).valid === true);
  // PEM output + a ski signer identifier passed through to cms.sign.
  var pem = await pki.tsp.sign(imprint("sha256"), makeSigner("ec-p256", { ski: true }), { policy: "1.2.3", serialNumber: 6, pem: true, sid: "ski" });
  check("pem:true -> a CMS PEM string", typeof pem === "string" && pem.indexOf("-----BEGIN CMS-----") === 0);
  check("PEM token verifies + ski sid", (await pki.cms.verify(pem)).signers[0].sid.subjectKeyIdentifier != null);

  // the TSA certificate supplied as a PEM string and as a Uint8Array.
  var tsa = makeSigner("ec-p256");
  var certPem = pki.schema.x509.pemEncode(tsa.cert, "CERTIFICATE");
  check("TSA cert as PEM -> verifies", (await pki.cms.verify(await pki.tsp.sign(imprint("sha256"), { cert: certPem, key: tsa.key }, { policy: "1.2.3", serialNumber: 7 }))).valid === true);
  check("TSA cert as Uint8Array -> verifies", (await pki.cms.verify(await pki.tsp.sign(imprint("sha256"), { cert: new Uint8Array(tsa.cert), key: tsa.key }, { policy: "1.2.3", serialNumber: 8 }))).valid === true);
  check("TSA cert as a PEM Buffer -> verifies", (await pki.cms.verify(await pki.tsp.sign(imprint("sha256"), { cert: Buffer.from(certPem), key: tsa.key }, { policy: "1.2.3", serialNumber: 9 }))).valid === true);
}

// ---- config-time misuse fails closed with a typed tsp/* error ----
async function testBadInput() {
  var tsa = makeSigner("ec-p256");
  await rejects("options not an object", function () { return pki.tsp.sign(imprint("sha256"), tsa, "nope"); }, "tsp/bad-input");
  await rejects("imprint without a hashAlgorithm", function () { return pki.tsp.sign({ hashedMessage: Buffer.alloc(32) }, tsa, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/unsupported-algorithm");
  await rejects("imprint with an unsupported hash", function () { return pki.tsp.sign({ hashAlgorithm: "md5", hashedMessage: Buffer.alloc(16) }, tsa, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/unsupported-algorithm");
  await rejects("imprint hashedMessage not a Buffer", function () { return pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: "x" }, tsa, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("no policy", function () { return pki.tsp.sign(imprint("sha256"), tsa, { serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("policy not a string", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: 123, serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("no serialNumber", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3" }); }, "tsp/bad-input");
  await rejects("no TSA certificate", function () { return pki.tsp.sign(imprint("sha256"), { key: tsa.key }, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("TSA cert a bad type", function () { return pki.tsp.sign(imprint("sha256"), { cert: 123, key: tsa.key }, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("TSA cert a non-CERTIFICATE PEM", function () { return pki.tsp.sign(imprint("sha256"), { cert: "-----BEGIN X-----\nAA\n-----END X-----", key: tsa.key }, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/bad-input");
  await rejects("unsupported certHashAlgorithm", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, certHashAlgorithm: "md5" }); }, "tsp/unsupported-algorithm");
  await rejects("Accuracy micros out of range", function () { return pki.tsp.sign(imprint("sha256"), tsa, { policy: "1.2.3", serialNumber: 1, accuracy: { micros: -1 } }); }, "tsp/bad-input");
  await rejects("no options at all", function () { return pki.tsp.sign(imprint("sha256"), tsa); }, "tsp/bad-input");
  await rejects("a null messageImprint", function () { return pki.tsp.sign(null, tsa, { policy: "1.2.3", serialNumber: 1 }); }, "tsp/unsupported-algorithm");
}

async function run() {
  await testRoundTrip();
  await testAlgorithms();
  await testPassthrough();
  await testBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack || e)); process.exit(1); }
  );
}
