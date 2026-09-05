// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- every verdict a public verify verb returns is built by guard.verdict.of, so it owns
 * the fields it reports and ends the prototype lookup for `then` on itself.
 *
 * Resolving a promise reads `then` off the value it settles with. A verdict that does not own one
 * hands that lookup to Object.prototype, where an accessor runs with the verdict as its receiver
 * and can rewrite the decision on its way to the caller. Each vector below drives the shipped verb,
 * installs such an accessor while the verification is pending, and asserts the caller receives the
 * object the verb built, still reporting what it computed.
 *
 * This states the rule once for the whole closed set. A verb added without the guard fails here,
 * not in the suite of whichever module happens to notice.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = require("../helpers/signing").makeSigner;

var hasOwn = Object.prototype.hasOwnProperty;

// Install a `then` getter that rewrites the decision, resolve the pending verdict through it, and
// report whether the caller got the verb's own object back unchanged.
async function survives(label, pending, field, expected) {
  var held, sameShape;
  Object.defineProperty(Object.prototype, "then", {
    configurable: true,
    get: function () {
      try { this[field] = !expected; } catch (_e) { /* a frozen verdict refuses the write */ }
      return undefined;
    },
  });
  try {
    var v = await pending;
    sameShape = hasOwn.call(v, "then") && v.then === undefined;
    held = sameShape && v[field] === expected;
  } finally { delete Object.prototype.then; }
  check(label + ": the verdict owns then and still reports " + field + " === " + expected, held);
}

async function testCsr() {
  var s = makeSigner("ed25519");
  var der = await pki.csr.sign({ subject: "shield.example", subjectPublicKey: s.spki }, { key: s.key });
  await survives("pki.csr.verify", pki.csr.verify(der), "valid", true);
}

async function testCrl() {
  var s = makeSigner("ed25519");
  var crl = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"), crlNumber: 1n },
    { name: "Shield CRL Issuer", publicKey: s.spki, key: s.key });
  await survives("pki.crl.verify", pki.crl.verify(crl, { publicKey: s.spki }), "valid", true);
}

async function testCms() {
  var s = makeSigner("ed25519");
  var signed = await pki.cms.sign(Buffer.from("shield"), { cert: s.cert, key: s.key });
  await survives("pki.cms.verify", pki.cms.verify(signed), "valid", true);
}

async function testCrmf() {
  var s = makeSigner("ed25519");
  var req = await pki.crmf.build({ certReqId: 1n, certTemplate: { subject: "shield.example", publicKey: s.spki } }, { key: s.key });
  await survives("pki.crmf.verifyPop", pki.crmf.verifyPop(req), "valid", true);
}

async function testPkcs12() {
  var s = makeSigner("ed25519");
  var pfx = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "shield" });
  await survives("pki.pkcs12.verifyMac", pki.pkcs12.verifyMac(pfx, "shield"), "valid", true);
  await survives("pki.pkcs12.open", pki.pkcs12.open(pfx, "shield"), "valid", true);
}

async function testPath() {
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2028-01-01T00:00:00Z");
  var at = new Date("2027-01-01T00:00:00Z");
  var rootKey = makeSigner("ed25519");
  var rootDer = await pki.x509.sign({
    serialNumber: 1n, subject: "Shield Path Root", subjectPublicKey: rootKey.spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true },
  }, { key: rootKey.key });
  var anchor = pki.path.anchorFromCert(rootDer);
  var leafKey = makeSigner("ed25519");
  var leaf = await pki.x509.sign({
    serialNumber: 42n, subject: "leaf.shield.example", subjectPublicKey: leafKey.spki, notBefore: NB, notAfter: NA,
  }, { key: rootKey.key, cert: rootDer });
  await survives("pki.path.validate", pki.path.validate([leaf], { time: at, trustAnchors: anchor }), "valid", true);
  await survives("pki.path.build", pki.path.build(leaf, { time: at, trustAnchors: [anchor] }), "valid", true);
}

async function testAttrcert() {
  var aa = makeSigner("ed25519");
  var ac = await pki.attrcert.sign({
    holder: { entityName: { directoryName: "CN=Shield Holder" } },
    notBeforeTime: new Date("2026-01-01T00:00:00Z"),
    notAfterTime: new Date("2027-01-01T00:00:00Z"),
    attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:shield" } } },
  }, { name: "CN=Shield AA", publicKey: aa.spki, key: aa.key });
  await survives("pki.attrcert.verify",
    pki.attrcert.verify(ac, { name: "CN=Shield AA", publicKey: aa.spki },
      { time: new Date("2026-06-01T00:00:00Z"), revocationStatus: "notRevoked" }),
    "valid", true);
}

async function testCmp() {
  var s = makeSigner("ed25519");
  var csr = await pki.csr.sign({ subject: [{ commonName: "shield" }], subjectPublicKey: s.spki }, { key: s.key });
  var msg = await pki.cmp.build({
    header: { sender: { directoryName: [{ commonName: "Test Signer" }] }, recipient: { directoryName: "CN=Shield CA" },
      transactionID: Buffer.alloc(16, 1), senderNonce: Buffer.alloc(16, 2) },
    body: { p10cr: csr },
  }, { key: s.key, cert: s.cert });
  await survives("pki.cmp.verify", pki.cmp.verify(msg, { signerCert: s.cert }), "valid", true);
}

async function run() {
  await testCsr();
  await testCrl();
  await testCms();
  await testCrmf();
  await testPkcs12();
  await testPath();
  await testAttrcert();
  await testCmp();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  run().then(null, function (e) { console.error((e && e.stack) || e); process.exit(1); });
}
