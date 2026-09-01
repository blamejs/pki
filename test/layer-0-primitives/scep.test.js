// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- pki.scep pkiMessage codec (RFC 8894). The SCEP client's enrollment surface: build a
// PKCSReq / RenewalReq request (inner EnvelopedData over the PKCS#10, outer SignedData under the
// transaction attributes) and parse any pkiMessage (verify the outer signature, read the attributes
// BOUND to the verified signer, decrypt the pkcsPKIEnvelope). Every vector drives the SHIPPED verb
// (pki.scep.build / pki.scep.parse). CertRep fixtures are assembled inline from the CMS verbs to
// exercise the response-reading paths. The security property under test is that the transaction
// attributes are surfaced only from a signature that verified -- a tampered message is refused, never
// returned with a false verdict.

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var cmsSign = require("../../lib/cms-sign");
var cmsEncrypt = require("../../lib/cms-encrypt");
var fakeTransport = require("../helpers/fake-transport").fakeTransport;
var nodeCrypto = require("node:crypto");
var O = function (n) { return pki.oid.byName(n); };

var ID_SIGNED_DATA = "1.2.840.113549.1.7.2", ID_DATA = "1.2.840.113549.1.7.1";

// A degenerate certs-only SignedData (RFC 5272 sec. 4.1): no eContent, EMPTY signerInfos, the
// certificates in the [0] field DER-sorted. This is the messageData a CertRep SUCCESS carries.
function certsOnly(certs) {
  var sd = [b.integer(1n), b.set([]), b.sequence([b.oid(ID_DATA)])];
  if (certs && certs.length) sd.push(b.contextConstructed(0, Buffer.concat(certs.slice().sort(Buffer.compare))));
  sd.push(b.set([]));
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence(sd))]);
}

// A degenerate SignedData carrying CRLs in the [1] field (and optionally certs in [0]) -- the shape a
// SUCCESS CertRep answering GetCRL carries.
function certsOnlyBag(certs, crls) {
  var sd = [b.integer(1n), b.set([]), b.sequence([b.oid(ID_DATA)])];
  if (certs && certs.length) sd.push(b.contextConstructed(0, Buffer.concat(certs.slice().sort(Buffer.compare))));
  if (crls && crls.length) sd.push(b.contextConstructed(1, Buffer.concat(crls.slice())));
  sd.push(b.set([]));
  return b.sequence([b.oid(ID_SIGNED_DATA), b.explicit(0, b.sequence(sd))]);
}

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }

var F = {};
async function setup() {
  var caKp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  F.caKey = await pki.key.export(caKp.privateKey);
  F.caCert = await pki.x509.sign({ subject: "SCEP CA", subjectPublicKey: await pki.key.export(caKp.publicKey), notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "keyEncipherment", "digitalSignature", "cRLSign"] } }, { key: F.caKey });
  var clientKp = await pki.key.generate("Ed25519");
  F.clientKey = await pki.key.export(clientKp.privateKey);
  F.clientCert = await pki.x509.sign({ subject: "SCEP Client", subjectPublicKey: await pki.key.export(clientKp.publicKey), notBefore: new Date("2026-01-01"), notAfter: new Date("2028-01-01"), extensions: { keyUsage: ["digitalSignature"] } }, { key: F.clientKey });
  var reqKp = await pki.key.generate("Ed25519");
  F.csr = await pki.csr.sign({ subject: "device.example", subjectPublicKey: await pki.key.export(reqKp.publicKey), challengePassword: "s3cret" }, { key: await pki.key.export(reqKp.privateKey) });
  var issuedKp = await pki.key.generate("Ed25519");
  F.issuedCert = await pki.x509.sign({ subject: "device.example", subjectPublicKey: await pki.key.export(issuedKp.publicKey), notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01") }, { key: F.caKey, cert: F.caCert });
  F.signer = { cert: F.clientCert, key: F.clientKey };
}

// Assemble a CertRep fixture from the CMS verbs (the response direction, issued by a CA in the field).
async function buildCertRep(opts) {
  var attrs = [
    { type: O("scepMessageType"), values: [b.printable("3")] },
    { type: O("scepTransactionId"), values: [b.printable(opts.transactionId || "txn")] },
    { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] },
    { type: O("scepPkiStatus"), values: [b.printable(opts.statusCode)] },
  ];
  if (!opts.omitRecipientNonce) attrs.push({ type: O("scepRecipientNonce"), values: [b.octetString(opts.recipientNonce || nodeCrypto.randomBytes(16))] });
  if (opts.failCode != null) attrs.push({ type: O("scepFailInfo"), values: [b.printable(opts.failCode)] });
  if (opts.failText != null) attrs.push({ type: O("scepFailInfoText"), values: [b.utf8(opts.failText)] });
  // A conforming FAILURE / PENDING CertRep omits the pkcsPKIEnvelope: sign detached with no content
  // when the caller gives none. A SUCCESS response passes its certs-only envelope as content.
  var signOpts = { additionalSignedAttributes: attrs }, content = opts.content;
  if (content == null) { content = Buffer.alloc(0); signOpts.detached = true; }
  return cmsSign.sign(content, opts.signer || { cert: F.caCert, key: F.caKey }, signOpts);
}

// Sign an arbitrary content with the client under a caller-chosen attribute list (for missing /
// malformed-attribute vectors that cms.sign would not let build() emit).
function signWith(content, attrs) {
  return cmsSign.sign(content, F.signer, { additionalSignedAttributes: attrs });
}

async function testPkcsReqRoundTrip() {
  var msg = await pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "txn-0001" });
  var v = await pki.scep.parse(msg, { recipientKey: { cert: F.caCert, key: F.caKey } });
  check("PKCSReq: signatureValid", v.signatureValid === true);
  check("PKCSReq: messageType", v.messageType === "PKCSReq");
  check("PKCSReq: transactionId echoed", v.transactionId === "txn-0001");
  check("PKCSReq: senderNonce is 16 bytes", Buffer.isBuffer(v.senderNonce) && v.senderNonce.length === 16);
  check("PKCSReq: messageData is the exact CSR", Buffer.compare(v.messageData, F.csr) === 0);
  check("PKCSReq: recovered CSR subject", pki.schema.csr.parse(v.messageData).subject.dn === "CN=device.example");
}

async function testRenewalReqRoundTrip() {
  var msg = await pki.scep.build({ messageType: "RenewalReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "renew-1", senderNonce: nodeCrypto.randomBytes(16) });
  var v = await pki.scep.parse(msg, { recipientKey: { cert: F.caCert, key: F.caKey } });
  check("RenewalReq: messageType", v.messageType === "RenewalReq");
  check("RenewalReq: messageData recovered", Buffer.compare(v.messageData, F.csr) === 0);
}

async function testNoKeyParse() {
  var msg = await pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "t" });
  var v = await pki.scep.parse(msg);
  check("no recipientKey: signature still verified", v.signatureValid === true);
  check("no recipientKey: messageData not decrypted", v.messageData === null);
  check("no recipientKey: attributes still read", v.transactionId === "t");
}

async function testNonceEcho() {
  var sent = nodeCrypto.randomBytes(16);
  var rep = await buildCertRep({ statusCode: "0", transactionId: "t", recipientNonce: sent, content: await cmsEncrypt.encrypt(certsOnly([F.issuedCert]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" }) });
  var ok = await pki.scep.parse(rep, { expectedSenderNonce: sent });
  check("nonce echo: matching recipientNonce accepted", ok.pkiStatus === "SUCCESS");
  check("nonce echo: mismatch refused", (await codeOf(pki.scep.parse(rep, { expectedSenderNonce: nodeCrypto.randomBytes(16) }))) === "scep/nonce-mismatch");
}

async function testCertRepSuccessParse() {
  var recipNonce = nodeCrypto.randomBytes(16);
  var env = await cmsEncrypt.encrypt(certsOnly([F.issuedCert]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var rep = await buildCertRep({ statusCode: "0", transactionId: "s-1", recipientNonce: recipNonce, content: env });
  var v = await pki.scep.parse(rep, { recipientKey: { cert: F.caCert, key: F.caKey } });
  check("CertRep SUCCESS: messageType", v.messageType === "CertRep");
  check("CertRep SUCCESS: pkiStatus", v.pkiStatus === "SUCCESS");
  check("CertRep SUCCESS: recipientNonce 16 bytes", v.recipientNonce.length === 16);
  check("CertRep SUCCESS: messageData decrypts to the certs-only bag", Buffer.compare(v.messageData, certsOnly([F.issuedCert])) === 0);
  check("CertRep SUCCESS: issued certificate surfaced", v.certificates.length === 1 && Buffer.compare(v.certificates[0], F.issuedCert) === 0);
}

async function testRequestPayloadValidated() {
  // A decrypted request's messageData must be a PKCS#10 (RFC 8894 sec. 3.3.1). Build a PKCSReq whose
  // envelope encrypts non-CSR bytes (bypassing build's own check) and confirm parse refuses it.
  var env = await cmsEncrypt.encrypt(Buffer.from("not a certification request"), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var msg = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }]);
  check("decrypted request messageData that is not a PKCS#10 refused", (await codeOf(pki.scep.parse(msg, { recipientKey: { cert: F.caCert, key: F.caKey } }))) === "scep/bad-request-payload");
}

async function testCertRepCrlOnly() {
  // A SUCCESS CertRep answering GetCRL carries a CRL and no certificate (RFC 8894 sec. 3.3.4); the CRL
  // is surfaced in crls and certificates is empty, rather than rejected for having no certificate.
  var crl = await pki.crl.sign({ thisUpdate: new Date("2026-06-01"), nextUpdate: new Date("2026-07-01"), revoked: [] }, { key: F.caKey, cert: F.caCert });
  var env = await cmsEncrypt.encrypt(certsOnlyBag(null, [crl]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var rep = await buildCertRep({ statusCode: "0", transactionId: "crl", content: env });
  var v = await pki.scep.parse(rep, { recipientKey: { cert: F.caCert, key: F.caKey } });
  check("CRL-only SUCCESS CertRep: CRL surfaced, no certificates", v.crls.length === 1 && Buffer.compare(v.crls[0], crl) === 0 && v.certificates.length === 0);
  // A SUCCESS CertRep whose payload carries neither a certificate nor a CRL is refused.
  var empty = await cmsEncrypt.encrypt(certsOnlyBag(null, null), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var emptyRep = await buildCertRep({ statusCode: "0", transactionId: "e", content: empty });
  check("SUCCESS CertRep with an empty bag refused", (await codeOf(pki.scep.parse(emptyRep, { recipientKey: { cert: F.caCert, key: F.caKey } }))) === "scep/empty-response");
}

async function testCertRepSuccessValidatesPayload() {
  // A SUCCESS CertRep's decrypted messageData MUST be a certs-only CMS SignedData (RFC 8894 sec. 3.3.2);
  // decrypted bytes that are not are refused rather than surfaced as a successful issuance.
  var notCms = await cmsEncrypt.encrypt(Buffer.from("not a CMS certs-only message"), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var rep = await buildCertRep({ statusCode: "0", transactionId: "s", content: notCms });
  check("SUCCESS CertRep with a non-certs-only payload refused", (await codeOf(pki.scep.parse(rep, { recipientKey: { cert: F.caCert, key: F.caKey } }))) === "scep/bad-response");
  // A degenerate bag whose certificates field holds a non-certificate (here a PKCS#10) is refused: each
  // entry is validated as a plain X.509 certificate, not surfaced raw.
  var badCert = await cmsEncrypt.encrypt(certsOnly([F.csr]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var badCertRep = await buildCertRep({ statusCode: "0", transactionId: "bc", content: badCert });
  check("SUCCESS CertRep with a non-certificate in certificates refused", (await codeOf(pki.scep.parse(badCertRep, { recipientKey: { cert: F.caCert, key: F.caKey } }))) === "scep/bad-certificate");
}

async function testCertRepFailureParse() {
  var rep = await buildCertRep({ statusCode: "2", failCode: "2", failText: "policy rejected the request", transactionId: "f-1" });
  var v = await pki.scep.parse(rep);
  check("CertRep FAILURE: pkiStatus", v.pkiStatus === "FAILURE");
  check("CertRep FAILURE: failInfo mapped", v.failInfo === "badRequest");
  check("CertRep FAILURE: failInfoText surfaced", v.failInfoText === "policy rejected the request");
}

async function testCertRepPendingParse() {
  var rep = await buildCertRep({ statusCode: "3", transactionId: "p-1" });
  var v = await pki.scep.parse(rep);
  check("CertRep PENDING: pkiStatus", v.pkiStatus === "PENDING");
  check("CertRep PENDING: no failInfo", v.failInfo === null);
}

async function testMissingMandatoryAttributes() {
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var noType = await signWith(env, [{ type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }]);
  check("missing messageType refused", (await codeOf(pki.scep.parse(noType))) === "scep/missing-attribute");
  var noTxn = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }]);
  check("missing transactionID refused", (await codeOf(pki.scep.parse(noTxn))) === "scep/missing-attribute");
  var noNonce = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }]);
  check("missing senderNonce refused", (await codeOf(pki.scep.parse(noNonce))) === "scep/missing-attribute");
}

async function testUnknownEnumerants() {
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var base = [{ type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }];
  var badType = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("99")] }].concat(base));
  check("unknown messageType enumerant refused", (await codeOf(pki.scep.parse(badType))) === "scep/bad-message-type");
  var badStatus = await buildCertRep({ statusCode: "7", transactionId: "t", content: certsOnly([]) });
  check("unknown pkiStatus enumerant refused", (await codeOf(pki.scep.parse(badStatus))) === "scep/bad-pki-status");
  var badFail = await buildCertRep({ statusCode: "2", failCode: "9", transactionId: "t", content: certsOnly([]) });
  check("unknown failInfo enumerant refused", (await codeOf(pki.scep.parse(badFail))) === "scep/bad-fail-info");
}

async function testCertRepMissingStatusAndFail() {
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var noStatus = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("3")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }]);
  check("CertRep without pkiStatus refused", (await codeOf(pki.scep.parse(noStatus))) === "scep/missing-attribute");
  // Carries a recipientNonce (so it passes that gate) but omits failInfo, so the failInfo gate is what refuses it.
  var failNoInfo = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("3")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }, { type: O("scepRecipientNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }, { type: O("scepPkiStatus"), values: [b.printable("2")] }]);
  check("FAILURE without failInfo refused", (await codeOf(pki.scep.parse(failNoInfo))) === "scep/missing-attribute");
}

async function testNonSuccessCertRepWithRecipientKey() {
  // A FAILURE / PENDING CertRep carries no pkcsPKIEnvelope; passing recipientKey must still return the
  // authenticated status rather than a decrypt failure over content that is not an EnvelopedData.
  var fail = await buildCertRep({ statusCode: "2", failCode: "2", transactionId: "f" });
  var vf = await pki.scep.parse(fail, { recipientKey: { cert: F.caCert, key: F.caKey } });
  check("FAILURE CertRep + recipientKey: status returned, not a decrypt error", vf.pkiStatus === "FAILURE" && vf.failInfo === "badRequest" && vf.messageData === null);
  var pend = await buildCertRep({ statusCode: "3", transactionId: "p" });
  var vp = await pki.scep.parse(pend, { recipientKey: { cert: F.caCert, key: F.caKey } });
  check("PENDING CertRep + recipientKey: status returned, not a decrypt error", vp.pkiStatus === "PENDING" && vp.messageData === null);
}

async function testSignerAuthentication() {
  // A valid signature is not an authenticated signer: opts.signerCert must match the CA that signed
  // the CertRep, or the message is refused; without it the verdict is crypto-only (P1).
  var env = await cmsEncrypt.encrypt(certsOnly([F.issuedCert]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var rep = await buildCertRep({ statusCode: "0", transactionId: "auth-1", recipientNonce: nodeCrypto.randomBytes(16), content: env });
  var vOk = await pki.scep.parse(rep, { signerCert: F.caCert });
  check("signerCert match: signerAuthenticated true", vOk.signerAuthenticated === true && vOk.pkiStatus === "SUCCESS");
  check("signerCert mismatch refused (forged-response defense)", (await codeOf(pki.scep.parse(rep, { signerCert: F.clientCert }))) === "scep/untrusted-signer");
  var vNo = await pki.scep.parse(rep);
  check("no signerCert: crypto-only verdict, signerAuthenticated false", vNo.signerAuthenticated === false && vNo.signatureValid === true);
}

async function testEnvelopeRequiresCiphertext() {
  // A request or SUCCESS CertRep whose EnvelopedData omits encryptedContent has no messageData to
  // recover; it is refused structurally, without a recipient key (RFC 8894 sec. 3.2).
  var ds = require("../helpers/der-surgery");
  var realEnv = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  function reqAttrs() { return [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }]; }
  var noCt = ds.patch(realEnv, function (n) { return (n.tagClass === "context" && n.tagNumber === 0 && !n.constructed) ? Buffer.alloc(0) : undefined; });
  check("pkcsPKIEnvelope with absent ciphertext refused (no recipientKey)", (await codeOf(pki.scep.parse(await signWith(noCt, reqAttrs())))) === "scep/missing-envelope");
  // A present but zero-length [0] OCTET STRING also carries no ciphertext.
  var emptyCt = ds.patch(realEnv, function (n) { return (n.tagClass === "context" && n.tagNumber === 0 && !n.constructed) ? Buffer.from([0x80, 0x00]) : undefined; });
  check("pkcsPKIEnvelope with empty ciphertext refused (no recipientKey)", (await codeOf(pki.scep.parse(await signWith(emptyCt, reqAttrs())))) === "scep/missing-envelope");
}

async function testPinnedSignerKeyUsage() {
  // The pinned opts.signerCert must itself be authorized to sign: a same-key digitalSignature cert
  // embedded in the message cannot authenticate a pinned encryption-only cert (RFC 8894 sec. 2.3).
  var kp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var key = await pki.key.export(kp.privateKey), spki = await pki.key.export(kp.publicKey);
  var sigCert = await pki.x509.sign({ subject: "dual", subjectPublicKey: spki, notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), extensions: { keyUsage: ["digitalSignature"] } }, { key: key });
  var encCert = await pki.x509.sign({ subject: "dual", subjectPublicKey: spki, notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), extensions: { keyUsage: ["keyEncipherment"] } }, { key: key });
  var env = await cmsEncrypt.encrypt(certsOnly([F.issuedCert]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var rep = await cmsSign.sign(env, { cert: sigCert, key: key }, { additionalSignedAttributes: [{ type: O("scepMessageType"), values: [b.printable("3")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }, { type: O("scepPkiStatus"), values: [b.printable("0")] }, { type: O("scepRecipientNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }] });
  check("pinned encryption-only signerCert refused despite same-key signing cert", (await codeOf(pki.scep.parse(rep, { signerCert: encCert }))) === "scep/bad-signer-usage");
}

async function testSignerKeyUsage() {
  // A SCEP signer's certificate must be authorized to sign (RFC 8894 sec. 2.3): an encryption-only
  // certificate (keyUsage keyEncipherment, no digitalSignature) is refused for both build and parse.
  var encKp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var encKey = await pki.key.export(encKp.privateKey);
  var encCert = await pki.x509.sign({ subject: "enc only", subjectPublicKey: await pki.key.export(encKp.publicKey), notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), extensions: { keyUsage: ["keyEncipherment"] } }, { key: encKey });
  check("build with an encryption-only signer refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: { cert: encCert, key: encKey }, transactionId: "t" }))) === "scep/bad-signer-usage");
  // RFC 8894 sec. 2.3 requires digitalSignature specifically; a contentCommitment-only cert is refused.
  var ncCert = await pki.x509.sign({ subject: "nonrepud only", subjectPublicKey: await pki.key.export(encKp.publicKey), notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), extensions: { keyUsage: ["contentCommitment"] } }, { key: encKey });
  check("build with a contentCommitment-only signer refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: { cert: ncCert, key: encKey }, transactionId: "t" }))) === "scep/bad-signer-usage");
  var env = await cmsEncrypt.encrypt(certsOnly([F.issuedCert]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var rep = await cmsSign.sign(env, { cert: encCert, key: encKey }, { additionalSignedAttributes: [{ type: O("scepMessageType"), values: [b.printable("3")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }, { type: O("scepPkiStatus"), values: [b.printable("0")] }, { type: O("scepRecipientNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }] });
  check("parse of a CertRep signed by an encryption-only cert refused", (await codeOf(pki.scep.parse(rep))) === "scep/bad-signer-usage");
}

async function testBuildValidatesCsr() {
  // build's messageData must be a PKCS#10 with a valid proof-of-possession (P2): non-CSR bytes or a
  // request whose self-signature does not verify is refused before enveloping, not left to the CA.
  check("non-CSR messageData refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: Buffer.from("not a certification request"), recipient: F.caCert, signer: F.signer, transactionId: "t" }))) === "scep/bad-input");
  var badPop = Buffer.from(F.csr);
  badPop[badPop.length - 4] ^= 0x40;   // flip a signature byte: structure intact, proof-of-possession broken
  check("PKCS#10 with a broken proof-of-possession refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: badPop, recipient: F.caCert, signer: F.signer, transactionId: "t" }))) === "scep/bad-popo");
}

async function testCertRepRequiresRecipientNonce() {
  // A CertRep MUST echo the request's senderNonce in a recipientNonce (RFC 8894 sec. 3.1), regardless
  // of whether the caller passes expectedSenderNonce.
  var env = await cmsEncrypt.encrypt(certsOnly([F.issuedCert]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var noRecip = await buildCertRep({ statusCode: "0", transactionId: "s", omitRecipientNonce: true, content: env });
  check("CertRep without recipientNonce refused", (await codeOf(pki.scep.parse(noRecip))) === "scep/missing-attribute");
}

async function testEnvelopeMandatory() {
  // A request and a SUCCESS CertRep MUST carry a pkcsPKIEnvelope (RFC 8894 sec. 3.2). A signed message
  // of those types whose content is not an EnvelopedData is refused before any recipient-key decryption.
  var reqAttrs = [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }];
  var fakeReq = await signWith(certsOnly([]), reqAttrs);
  check("request with non-envelope content refused (no recipientKey)", (await codeOf(pki.scep.parse(fakeReq))) === "scep/missing-envelope");
  // An OID-only "envelope" (ContentInfo carrying the envelopedData OID but no [0] content) is not a
  // valid EnvelopedData and is refused, not accepted as a message with a null messageData.
  var oidOnly = await signWith(b.sequence([b.oid(O("envelopedData"))]), reqAttrs);
  check("OID-only pseudo-envelope refused", (await codeOf(pki.scep.parse(oidOnly))) === "scep/missing-envelope");
  var emptyContent = await signWith(b.sequence([b.oid(O("envelopedData")), b.contextConstructed(0, Buffer.alloc(0))]), reqAttrs);
  check("envelopedData OID with an empty [0] content refused", (await codeOf(pki.scep.parse(emptyContent))) === "scep/missing-envelope");
  var fakeSuccess = await buildCertRep({ statusCode: "0", transactionId: "s", content: certsOnly([]) });
  check("SUCCESS CertRep with non-envelope content refused", (await codeOf(pki.scep.parse(fakeSuccess))) === "scep/missing-envelope");
  // A FAILURE / PENDING CertRep MUST omit the pkcsPKIEnvelope; carrying signed content is off-profile.
  var failWithContent = await buildCertRep({ statusCode: "2", failCode: "2", transactionId: "f", content: certsOnly([F.issuedCert]) });
  check("FAILURE CertRep carrying signed content refused", (await codeOf(pki.scep.parse(failWithContent))) === "scep/unexpected-envelope");
  var pendWithContent = await buildCertRep({ statusCode: "3", transactionId: "p", content: certsOnly([F.issuedCert]) });
  check("PENDING CertRep carrying signed content refused", (await codeOf(pki.scep.parse(pendWithContent))) === "scep/unexpected-envelope");
  // The envelope must be OMITTED (a null eContent), so even an attached zero-length OCTET STRING is refused.
  var attachedEmpty = await buildCertRep({ statusCode: "2", failCode: "2", transactionId: "f", content: Buffer.alloc(0) });
  check("FAILURE CertRep with an attached empty eContent refused", (await codeOf(pki.scep.parse(attachedEmpty))) === "scep/unexpected-envelope");
}

async function testOuterContentTypeMustBeData() {
  // RFC 8894 sec. 3.2: the SignedData eContentType MUST be id-data. A message that verifies as CMS but
  // names another eContentType is not a valid SCEP pkiMessage.
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var attrs = [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }];
  var wrongType = await cmsSign.sign(env, F.signer, { eContentType: "signedData", additionalSignedAttributes: attrs });
  check("non-data eContentType refused", (await codeOf(pki.scep.parse(wrongType))) === "scep/bad-content-type");
}

async function testFailInfoOnlyOnFailure() {
  // failInfo / failInfoText are FAILURE-only (RFC 8894 sec. 3.2.1.4): a SUCCESS or PENDING CertRep
  // carrying them asserts a contradictory authenticated status and is refused.
  var env = await cmsEncrypt.encrypt(certsOnly([F.issuedCert]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var successWithFail = await buildCertRep({ statusCode: "0", transactionId: "s", failCode: "2", content: env });
  check("SUCCESS CertRep carrying failInfo refused", (await codeOf(pki.scep.parse(successWithFail))) === "scep/unexpected-attribute");
  var pendWithText = await buildCertRep({ statusCode: "3", transactionId: "p", failText: "should not be here" });
  check("PENDING CertRep carrying failInfoText refused", (await codeOf(pki.scep.parse(pendWithText))) === "scep/unexpected-attribute");
}

async function testUnsupportedMessageTypes() {
  // CertPoll (20), GetCert (21), GetCRL (22) are client queries this release's parser does not read.
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var codes = ["20", "21", "22"], i;
  for (i = 0; i < codes.length; i++) {
    var msg = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable(codes[i])] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }]);
    check("messageType " + codes[i] + " (query) refused", (await codeOf(pki.scep.parse(msg))) === "scep/unsupported-message-type");
  }
}

async function testRequestRejectsResponseAttrs() {
  // A request (PKCSReq / RenewalReq) carrying a CertRep response attribute is off-profile (RFC 8894 sec. 3.2.1).
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var base = [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }];
  var withStatus = await signWith(env, base.concat([{ type: O("scepPkiStatus"), values: [b.printable("0")] }]));
  check("PKCSReq carrying pkiStatus refused", (await codeOf(pki.scep.parse(withStatus))) === "scep/unexpected-attribute");
  var withRecipNonce = await signWith(env, base.concat([{ type: O("scepRecipientNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }]));
  check("PKCSReq carrying recipientNonce refused", (await codeOf(pki.scep.parse(withRecipNonce))) === "scep/unexpected-attribute");
}

async function testEnvelopeContentTypeMustBeData() {
  // The pkcsPKIEnvelope's encrypted content type MUST be id-data (RFC 8894 sec. 3.2.2); an off-profile
  // envelope naming another type is refused even though its plaintext would parse as a request.
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc", contentType: "signedData" });
  var msg = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }]);
  // The content type is a structural field, so it is refused with or without a recipient key.
  check("non-data pkcsPKIEnvelope content type refused (no recipientKey)", (await codeOf(pki.scep.parse(msg))) === "scep/bad-envelope-content-type");
  check("non-data pkcsPKIEnvelope content type refused (with recipientKey)", (await codeOf(pki.scep.parse(msg, { recipientKey: { cert: F.caCert, key: F.caKey } }))) === "scep/bad-envelope-content-type");
}

async function testWrongStringType() {
  // RFC 8894 sec. 3.2 pins messageType / transactionID / pkiStatus / failInfo as PrintableString and
  // failInfoText as UTF8String; an off-profile string type (or nonce type) is refused.
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var base = [{ type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }];
  var utf8Type = await signWith(env, [{ type: O("scepMessageType"), values: [b.utf8("19")] }].concat(base));
  check("messageType as UTF8String (not PrintableString) refused", (await codeOf(pki.scep.parse(utf8Type))) === "scep/bad-attribute");
  var strNonce = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.printable("not-octets")] }]);
  check("senderNonce as PrintableString (not OCTET STRING) refused", (await codeOf(pki.scep.parse(strNonce))) === "scep/bad-nonce");
}

async function testMalformedInputsCoverage() {
  // build fail-closed paths: a missing signer, a recipient without keyEncipherment, and a bad signer key.
  check("build without signer refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, transactionId: "t" }))) === "scep/bad-input");
  check("build with a non-RSA recipient refused (RSAES-OAEP profile)", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.clientCert, signer: F.signer, transactionId: "t" }))) === "scep/bad-recipient");
  var rsaNoEncKp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var rsaNoEncCert = await pki.x509.sign({ subject: "no-enc", subjectPublicKey: await pki.key.export(rsaNoEncKp.publicKey), notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), extensions: { keyUsage: ["digitalSignature"] } }, { key: await pki.key.export(rsaNoEncKp.privateKey) });
  check("build with an RSA recipient lacking keyEncipherment refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: rsaNoEncCert, signer: F.signer, transactionId: "t" }))) === "scep/bad-input");
  check("build with a bad signer key refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: { cert: F.clientCert, key: Buffer.from("bad-key") }, transactionId: "t" }))) === "scep/bad-input");

  var msg = await pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "t" });
  check("parse with the wrong recipient key -> decrypt-failed", (await codeOf(pki.scep.parse(msg, { recipientKey: { cert: F.clientCert, key: F.clientKey } }))) === "scep/decrypt-failed");
  check("parse with a malformed signerCert refused", (await codeOf(pki.scep.parse(msg, { signerCert: Buffer.from("not a certificate") }))) === "scep/bad-input");

  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var badNonce = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(8))] }]);
  check("parse with a wrong-width senderNonce refused", (await codeOf(pki.scep.parse(badNonce))) === "scep/bad-nonce");
}

async function testBuildSnapshotsMessageData() {
  // build snapshots messageData synchronously before its awaited proof-of-possession verify, so a caller
  // that mutates the Buffer after calling build (but before awaiting it) cannot desync the enveloped
  // request from the verified one: the message carries the original bytes.
  var csrCopy = Buffer.from(F.csr);
  var p = pki.scep.build({ messageType: "PKCSReq", messageData: csrCopy, recipient: F.caCert, signer: F.signer, transactionId: "toctou" });
  csrCopy[csrCopy.length - 4] ^= 0x40;   // mutate after the synchronous snapshot, before the awaited encrypt
  var msg = await p;
  var v = await pki.scep.parse(msg, { recipientKey: { cert: F.caCert, key: F.caKey } });
  check("build snapshots messageData: enveloped request is the original, PoP intact",
    Buffer.compare(v.messageData, F.csr) === 0 && (await pki.csr.verify(v.messageData)).verified === true);
}

async function testParseSnapshotsBytes() {
  // parse snapshots the message bytes at its door and uses that copy for both verification attempts (a
  // detached FAILURE / PENDING is re-verified against an empty payload), so a caller overwriting the
  // Buffer between the two attempts cannot swap which message's attributes are returned.
  var failMsg = Buffer.from(await buildCertRep({ statusCode: "2", failCode: "2", transactionId: "f" }));   // conforming detached FAILURE
  var p = pki.scep.parse(failMsg);   // door snapshots failMsg
  failMsg.fill(0);                    // overwrite the caller's Buffer after the door
  var v = await p;
  check("parse snapshots message bytes: parsed from the door-time bytes", v.pkiStatus === "FAILURE" && v.failInfo === "badRequest");
}

async function testParseSnapshotsSignerCert() {
  // parse captures opts.signerCert at its synchronous door, so a caller swapping it during the awaited
  // verification cannot change which certificate the response is authenticated against.
  var env = await cmsEncrypt.encrypt(certsOnly([F.issuedCert]), [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var rep = await buildCertRep({ statusCode: "0", transactionId: "auth", recipientNonce: nodeCrypto.randomBytes(16), content: env });
  var o = { signerCert: F.caCert, recipientKey: { cert: F.caCert, key: F.caKey } };
  var p = pki.scep.parse(rep, o);   // door snapshots F.caCert
  o.signerCert = F.clientCert;       // swap to a different certificate after the door
  var v = await p;
  check("parse snapshots signerCert: authenticated against the door-time cert", v.signerAuthenticated === true && v.pkiStatus === "SUCCESS");
}

async function testBuildSnapshotsRecipient() {
  // build captures the recipient at its synchronous door, so a caller swapping spec.recipient during the
  // awaited verify cannot redirect the envelope to a substituted CA.
  var otherKp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var otherCa = await pki.x509.sign({ subject: "other CA", subjectPublicKey: await pki.key.export(otherKp.publicKey), notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), extensions: { keyUsage: ["keyEncipherment"] } }, { key: await pki.key.export(otherKp.privateKey) });
  var spec = { messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "r" };
  var p = pki.scep.build(spec);   // door snapshots F.caCert as the recipient
  spec.recipient = otherCa;        // swap to a different CA after the door
  var msg = await p;
  var v = await pki.scep.parse(msg, { recipientKey: { cert: F.caCert, key: F.caKey } });
  check("build snapshots recipient: enveloped to the door-time CA", Buffer.compare(v.messageData, F.csr) === 0);
}

async function testMultiValuedAttribute() {
  // A single-typed attribute whose value SET holds more than one value passes the CMS parser (which
  // rejects only a repeated attribute TYPE), so the single-value refusal is SCEP's own (P2).
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var base = [{ type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }];
  var multi = await signWith(env, [{ type: O("scepMessageType"), values: [b.printable("19"), b.printable("17")] }].concat(base));
  check("multi-valued transaction attribute refused", (await codeOf(pki.scep.parse(multi))) === "scep/bad-attribute");
}

async function testMultipleSigners() {
  var env = await cmsEncrypt.encrypt(F.csr, [{ cert: F.caCert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
  var two = await cmsSign.sign(env, [F.signer, { cert: F.caCert, key: F.caKey }], { additionalSignedAttributes: [{ type: O("scepMessageType"), values: [b.printable("19")] }, { type: O("scepTransactionId"), values: [b.printable("t")] }, { type: O("scepSenderNonce"), values: [b.octetString(nodeCrypto.randomBytes(16))] }] });
  check("two SignerInfos refused", (await codeOf(pki.scep.parse(two))) === "scep/bad-signer");
}

async function testTamperFailsClosed() {
  var msg = await pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "t" });
  // The client signs Ed25519, so the 64-byte signature is the trailing OCTET STRING. Flip a byte
  // inside it: the DER stays well-formed and the outer signature no longer verifies.
  var tampered = Buffer.from(msg);
  tampered[tampered.length - 4] ^= 0x40;
  var code = await codeOf(pki.scep.parse(tampered));
  check("tampered signature is refused (fail-closed), never a false verdict", code === "scep/bad-signature");
}

async function testInputGuards() {
  check("unknown build option refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "t", bogus: 1 }))) === "scep/bad-input");
  check("unknown parse option refused", (await codeOf(pki.scep.parse(await pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "t" }), { nope: 1 }))) === "scep/bad-input");
  check("unknown messageType refused", (await codeOf(pki.scep.build({ messageType: "Nope", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "t" }))) === "scep/bad-message-type");
  check("CertRep not built by this release", (await codeOf(pki.scep.build({ messageType: "CertRep", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "t" }))) === "scep/bad-message-type");
  check("empty transactionId refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "" }))) === "scep/bad-input");
  var long = new Array(300).join("x");
  check("over-long transactionId refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: long }))) === "scep/bad-input");
  check("bad senderNonce width refused", (await codeOf(pki.scep.build({ messageType: "PKCSReq", messageData: F.csr, recipient: F.caCert, signer: F.signer, transactionId: "t", senderNonce: nodeCrypto.randomBytes(8) }))) === "scep/bad-nonce");
  check("non-object build spec refused", (await codeOf(pki.scep.build(42))) === "scep/bad-input");
}

// ---- HTTP client verbs (RFC 8894 sec. 4), driven over an injected fake transport ----------------------

// A self-signed RSA client (key-transport capable): the PKCSReq signer whose key the CA encrypts the
// response to; the requested certificate carries this same key, so findIssuedCert selects it.
async function rsaClient() {
  var kp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var key = await pki.key.export(kp.privateKey), pub = await pki.key.export(kp.publicKey);
  var cert = await pki.x509.sign({ subject: "device.example", subjectPublicKey: pub, notBefore: new Date("2026-01-01"), notAfter: new Date("2028-01-01"), extensions: { keyUsage: ["digitalSignature", "keyEncipherment"] } }, { key: key });
  return { key: key, pub: pub, cert: cert };
}

// A CA transport double: decrypt the POSTed request to echo its senderNonce, encrypt the payload to the
// client, and sign the CertRep as the CA (exactly what a real CA does on the wire).
function caTransport(build) {
  return fakeTransport(async function (req) {
    var reqParsed = await pki.scep.parse(req.body, { recipientKey: { cert: F.caCert, key: F.caKey } });
    var rep = await build(reqParsed);
    return { status: 200, headers: { "content-type": "application/x-pki-message" }, body: rep };
  });
}

async function testGetCACaps() {
  var pc = pki.scep.parseCapabilities("aes\nSHA-256\nBogus\r\n");   // LF/CRLF mix, case-fold, unknown ignored
  check("parseCapabilities: folds case and ignores unknown keywords", pc.AES === true && pc["SHA-256"] === true && pc.Bogus === undefined);
  var t = fakeTransport({ status: 200, headers: { "content-type": "text/plain" }, body: "AES\r\nSHA-256\r\nPOSTPKIOperation\r\nSCEPStandard\r\n" });
  var caps = await pki.scep.getCACaps("http://ca.example/scep", { transport: t });
  check("getCACaps: SCEPStandard implies the mandatory set", caps.SCEPStandard === true && caps.AES === true && caps["SHA-256"] === true && caps.POSTPKIOperation === true);
  check("getCACaps: GET ?operation=GetCACaps", t.calls[0].method === "GET" && t.calls[0].url.indexOf("operation=GetCACaps") !== -1);
  var none = await pki.scep.getCACaps("http://ca.example/scep", { transport: fakeTransport({ status: 404, headers: {}, body: "" }) });
  check("getCACaps: 404 means none supported", Object.keys(none).length === 0);
  var notImpl = await pki.scep.getCACaps("http://ca.example/scep", { transport: fakeTransport({ status: 501, headers: {}, body: "" }) });
  check("getCACaps: 501 Not Implemented means none supported (RFC 8894 sec. 3.5.1)", Object.keys(notImpl).length === 0);
  var notAllowed = await pki.scep.getCACaps("http://ca.example/scep", { transport: fakeTransport({ status: 405, headers: {}, body: "" }) });
  check("getCACaps: 405 Method Not Allowed means none supported", Object.keys(notAllowed).length === 0);
  check("getCACaps: a 502 is a transient error, not none-supported", (await codeOf(pki.scep.getCACaps("http://ca.example/scep", { transport: fakeTransport({ status: 502, headers: {}, body: "" }) }))) === "scep/http-error");
  var weak = fakeTransport({ status: 200, headers: { "content-type": "text/plain" }, body: "SHA-1\r\nDES3\r\n" });
  check("getCACaps: expectSCEPStandard fails closed when absent", (await codeOf(pki.scep.getCACaps("http://ca.example/scep", { transport: weak, expectSCEPStandard: true }))) === "scep/weak-profile");
  var proxyHtml = fakeTransport({ status: 200, headers: { "content-type": "text/html" }, body: "<html>gateway error</html>" });
  check("getCACaps: a 200 non-text/plain response is refused, not read as no capabilities", (await codeOf(pki.scep.getCACaps("http://ca.example/scep", { transport: proxyHtml }))) === "scep/bad-content-type");
  // the strong-profile policy is captured at the door: a caller cannot relax its own downgrade guard by
  // mutating opts while the GET is in flight.
  var relaxOpts = { expectSCEPStandard: true };
  relaxOpts.transport = fakeTransport(function () { relaxOpts.expectSCEPStandard = false; return Promise.resolve({ status: 200, headers: { "content-type": "text/plain" }, body: "SHA-1\r\n" }); });
  check("getCACaps: a mid-flight relax of expectSCEPStandard is ignored", (await codeOf(pki.scep.getCACaps("http://ca.example/scep", relaxOpts))) === "scep/weak-profile");
}

async function testGetCACert() {
  var r = await pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: F.caCert }) });
  check("getCACert: single certificate returned", Buffer.compare(r.caCertificate, F.caCert) === 0);
  // an injected transport may hand back a BufferSource (Uint8Array) rather than a Node Buffer: its raw bytes
  // must be normalized, not String()-coerced into "48,1,..." and fed to the certificate parser.
  var r8 = await pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: new Uint8Array(F.caCert) }) });
  check("getCACert: a Uint8Array response body is normalized, not string-coerced", Buffer.compare(r8.caCertificate, F.caCert) === 0);
  // a raw ArrayBuffer is a BufferSource too: the size check must accept the same forms the body decode does.
  var rab = await pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: new Uint8Array(F.caCert).buffer }) });
  check("getCACert: an ArrayBuffer response body is size-checked and read consistently (source, not view)", Buffer.compare(rab.caCertificate, F.caCert) === 0);
  var fp = nodeCrypto.createHash("sha256").update(F.caCert).digest("hex");
  var okFp = await pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: F.caCert }), expectedFingerprint: fp });
  check("getCACert: matching fingerprint accepted", Buffer.compare(okFp.caCertificate, F.caCert) === 0);
  check("getCACert: an unavailable fingerprintAlgorithm is a typed bad-input", (await codeOf(pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: F.caCert }), expectedFingerprint: fp, fingerprintAlgorithm: "not-a-real-hash" }))) === "scep/bad-input");
  var mismatch = "00" + fp.slice(2);
  check("getCACert: fingerprint mismatch refused", (await codeOf(pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: F.caCert }), expectedFingerprint: mismatch }))) === "scep/fingerprint-mismatch");
  var rc = await pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-ra-cert" }, body: certsOnly([F.caCert, F.issuedCert]) }) });
  check("getCACert: unpinned chain returns all certificates", rc.certificates.length === 2);
  check("getCACert: unpinned chain does not guess the CA certificate by position", rc.caCertificate === null);
  var chainFp = nodeCrypto.createHash("sha256").update(F.caCert).digest("hex");
  var pinnedChain = await pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-ra-cert" }, body: certsOnly([F.issuedCert, F.caCert]) }), expectedFingerprint: chainFp });
  check("getCACert: a fingerprint identifies the CA in a chain regardless of order", Buffer.compare(pinnedChain.caCertificate, F.caCert) === 0);
  check("getCACert: chain response carrying no certificate refused", (await codeOf(pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-ra-cert" }, body: certsOnly([]) }) }))) === "scep/no-certificates");
  check("getCACert: wrong content-type refused", (await codeOf(pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "text/html" }, body: F.caCert }) }))) === "scep/bad-content-type");
  check("getCACert: HTTP error refused", (await codeOf(pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 500, headers: {}, body: "oops" }) }))) === "scep/http-error");
  // the fingerprint is captured at the entry point: a caller mutating expectedFingerprint while the GET is
  // in flight cannot repoint the pin away from the value it supplied at the call.
  var fpOrig = nodeCrypto.createHash("sha256").update(F.caCert).digest("hex");
  var gcOpts = { expectedFingerprint: fpOrig };
  gcOpts.transport = fakeTransport(function () { gcOpts.expectedFingerprint = "00" + fpOrig.slice(2); return Promise.resolve({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: F.caCert }); });
  var gcOut = await pki.scep.getCACert("http://ca.example/scep", gcOpts);
  check("getCACert: a mid-GET fingerprint swap cannot repoint the pin", Buffer.compare(gcOut.caCertificate, F.caCert) === 0);
}

async function testGetNextCACert() {
  // The RFC 8894 sec. 4.7.1 rollover response: an outer SignedData signed by the CURRENT CA key whose
  // content is a degenerate certs-only SignedData carrying the next CA certificate. Constructed offline
  // from the CMS verbs (no live SCEP CA in the stack), the same way the CertRep fixtures are.
  var nextKp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var nextCaCert = await pki.x509.sign({ subject: "SCEP CA (next)", subjectPublicKey: await pki.key.export(nextKp.publicKey), notBefore: new Date("2029-06-01"), notAfter: new Date("2035-01-01"), extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: await pki.key.export(nextKp.privateKey) });
  var inner = await pki.cms.certsOnly([nextCaCert]);
  var outer = await cmsSign.sign(inner, { cert: F.caCert, key: F.caKey }, {});
  var NEXT_CT = { "content-type": "application/x-x509-next-ca-cert" };

  // 1. Happy path: the current CA signs, the next CA is returned byte-identical.
  var r = await pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, transport: fakeTransport({ status: 200, headers: NEXT_CT, body: outer }) });
  check("getNextCACert: the next CA certificate is returned", r.certificates.length === 1 && Buffer.compare(r.certificates[0], nextCaCert) === 0);

  // 2. The security MUST (sec. 4.7.1): a response signed by any key other than the current CA is refused,
  // even though the CMS is internally self-consistent under its embedded (attacker) certificate.
  var atkKp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var atkKey = await pki.key.export(atkKp.privateKey);
  var atkCert = await pki.x509.sign({ subject: "Rogue CA", subjectPublicKey: await pki.key.export(atkKp.publicKey), notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "digitalSignature"] } }, { key: atkKey });
  var rogue = await cmsSign.sign(inner, { cert: atkCert, key: atkKey }, {});
  check("getNextCACert: a response not signed by the current CA is refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, transport: fakeTransport({ status: 200, headers: NEXT_CT, body: rogue }) }))) === "scep/untrusted-signer");

  // 3. A tampered outer signature (well-formed DER, invalid signature) is refused. The RSA-2048 signature
  // is the trailing OCTET STRING; a byte flipped well inside it keeps the DER well-formed.
  var tampered = Buffer.from(outer);
  tampered[tampered.length - 20] ^= 0x40;
  check("getNextCACert: a tampered outer signature is refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, transport: fakeTransport({ status: 200, headers: NEXT_CT, body: tampered }) }))) === "scep/bad-signature");

  // 4. The wrong content-type is refused (sec. 4.7.1 names application/x-x509-next-ca-cert).
  check("getNextCACert: wrong content-type refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: outer }) }))) === "scep/bad-content-type");

  // 5. The current CA certificate is required: an unauthenticated rollover certificate becomes a future
  // trust anchor, so it is refused at the synchronous door, before any GET.
  check("getNextCACert: a missing caCertificate is refused before the GET", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: NEXT_CT, body: outer }) }))) === "scep/bad-input");

  // 6. An empty inner certs-only bag is refused, never an empty success.
  var emptyOuter = await cmsSign.sign(certsOnly([]), { cert: F.caCert, key: F.caKey }, {});
  check("getNextCACert: an empty certificate bag is refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, transport: fakeTransport({ status: 200, headers: NEXT_CT, body: emptyOuter }) }))) === "scep/no-certificates");

  // 7. A detached outer (no content) is refused: the rollover certificates ARE the content.
  var detached = await cmsSign.sign(inner, { cert: F.caCert, key: F.caKey }, { detached: true });
  check("getNextCACert: a detached outer (no content) is refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, transport: fakeTransport({ status: 200, headers: NEXT_CT, body: detached }) }))) === "scep/bad-response");

  // 8. An HTTP error is surfaced, not swallowed.
  check("getNextCACert: HTTP error refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, transport: fakeTransport({ status: 500, headers: {}, body: "oops" }) }))) === "scep/http-error");

  // 9. An unknown option is refused.
  check("getNextCACert: unknown option refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, bogus: 1, transport: fakeTransport({ status: 200, headers: NEXT_CT, body: outer }) }))) === "scep/bad-input");

  // 10. The caCertificate is captured at the synchronous door: a caller swapping it while the GET is in
  // flight cannot repoint the authentication away from the value supplied at the call.
  var gnOpts = { caCertificate: F.caCert };
  gnOpts.transport = fakeTransport(function () { gnOpts.caCertificate = atkCert; return Promise.resolve({ status: 200, headers: NEXT_CT, body: outer }); });
  var gnOut = await pki.scep.getNextCACert("http://ca.example/scep", gnOpts);
  check("getNextCACert: a mid-GET caCertificate swap cannot repoint the authentication", gnOut.certificates.length === 1 && Buffer.compare(gnOut.certificates[0], nextCaCert) === 0);

  // 11. A current CA whose keyUsage omits digitalSignature cannot authenticate a signature, so it is
  // refused at the door (RFC 8894 sec. 2.3), before the GET.
  var noSignKp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var noSignCa = await pki.x509.sign({ subject: "SCEP CA (no sign)", subjectPublicKey: await pki.key.export(noSignKp.publicKey), notBefore: new Date("2026-01-01"), notAfter: new Date("2030-01-01"), extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } }, { key: await pki.key.export(noSignKp.privateKey) });
  check("getNextCACert: a current CA that cannot sign is refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: noSignCa, transport: fakeTransport({ status: 200, headers: NEXT_CT, body: outer }) }))) === "scep/bad-signer-usage");

  // 12. A response body that is not a CMS SignedData at all is refused as a bad response.
  check("getNextCACert: a non-CMS response body is refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, transport: fakeTransport({ status: 200, headers: NEXT_CT, body: Buffer.from("not a CMS message") }) }))) === "scep/bad-response");

  // 13. A response carrying more than one signer is refused, even when one signer IS the current CA. A
  // GetNextCACert response is signed by the current CA alone (sec. 4.7.1); requiring exactly one signer
  // binds the signature-verified check and the current-CA key pin to the same SignerInfo, so a second
  // signer's valid signature cannot stand in for a current-CA identity whose own signature does not verify.
  var twoSigner = await cmsSign.sign(inner, [{ cert: F.caCert, key: F.caKey }, { cert: atkCert, key: atkKey }], {});
  check("getNextCACert: a multi-signer response is refused", (await codeOf(pki.scep.getNextCACert("http://ca.example/scep", { caCertificate: F.caCert, transport: fakeTransport({ status: 200, headers: NEXT_CT, body: twoSigner }) }))) === "scep/bad-signer");
}

async function testEnrollSuccess() {
  var cl = await rsaClient();
  var csr = await pki.csr.sign({ subject: "device.example", subjectPublicKey: cl.pub, challengePassword: "s3cret" }, { key: cl.key });
  var issued = await pki.x509.sign({ subject: "device.example", subjectPublicKey: cl.pub, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01") }, { key: F.caKey, cert: F.caCert });
  var t = caTransport(async function (p) {
    var env = await cmsEncrypt.encrypt(certsOnly([issued]), [{ cert: cl.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
    return buildCertRep({ statusCode: "0", transactionId: p.transactionId, recipientNonce: p.senderNonce, content: env });
  });
  var out = await pki.scep.enroll("http://ca.example/scep", { csr: csr, caCert: F.caCert, signer: { cert: cl.cert, key: cl.key }, recipientKey: { cert: cl.cert, key: cl.key }, transport: t });
  check("enroll: SUCCESS status", out.status === "SUCCESS");
  check("enroll: issued certificate selected by SPKI", Buffer.compare(out.certificate, issued) === 0);
  check("enroll: POSTed a pkiMessage to PKIOperation", t.calls[0].method === "POST" && t.calls[0].url.indexOf("operation=PKIOperation") !== -1 && Buffer.isBuffer(t.calls[0].body));
  check("enroll: request carried the pkiMessage content-type", t.calls[0].headers["content-type"] === "application/x-pki-message");
}

async function testEnrollTransactionIdUnique() {
  var cl = await rsaClient();
  var csr = await pki.csr.sign({ subject: "device.example", subjectPublicKey: cl.pub }, { key: cl.key });
  var issued = await pki.x509.sign({ subject: "device.example", subjectPublicKey: cl.pub, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01") }, { key: F.caKey, cert: F.caCert });
  var base = { csr: csr, caCert: F.caCert, signer: { cert: cl.cert, key: cl.key }, recipientKey: { cert: cl.cert, key: cl.key } };
  function okT() {
    return caTransport(async function (p) {
      var env = await cmsEncrypt.encrypt(certsOnly([issued]), [{ cert: cl.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
      return buildCertRep({ statusCode: "0", transactionId: p.transactionId, recipientNonce: p.senderNonce, content: env });
    });
  }
  var out1 = await pki.scep.enroll("http://ca.example/scep", Object.assign({ transport: okT() }, base));
  var out2 = await pki.scep.enroll("http://ca.example/scep", Object.assign({ transport: okT() }, base));
  // The default transaction ID is unique per operation (RFC 8894 sec. 3.2.1.1): two enrollments of the same
  // key must not collide, or a CA cannot tell a renewal from the original request (a caller wanting a stable
  // per-device ID passes an explicit transactionId).
  check("enroll: two enrollments of the same key get distinct transaction IDs (RFC 8894 sec. 3.2.1.1)", typeof out1.transactionId === "string" && out1.transactionId !== out2.transactionId);
}

async function testEnrollFailureAndPending() {
  var cl = await rsaClient();
  var csr = await pki.csr.sign({ subject: "device.example", subjectPublicKey: cl.pub }, { key: cl.key });
  var base = { csr: csr, caCert: F.caCert, signer: { cert: cl.cert, key: cl.key }, recipientKey: { cert: cl.cert, key: cl.key } };
  var fT = caTransport(function (p) { return buildCertRep({ statusCode: "2", failCode: "2", failText: "bad request", transactionId: p.transactionId, recipientNonce: p.senderNonce }); });
  var failErr = null;
  try { await pki.scep.enroll("http://ca.example/scep", Object.assign({ transport: fT }, base)); } catch (e) { failErr = e; }
  check("enroll: a FAILURE CertRep throws scep/enrollment-failed", failErr && failErr.code === "scep/enrollment-failed");
  check("enroll: the failure error carries the structured failInfo and failInfoText", failErr && failErr.failInfo === "badRequest" && failErr.failInfoText === "bad request");
  var pT = caTransport(function (p) { return buildCertRep({ statusCode: "3", transactionId: p.transactionId, recipientNonce: p.senderNonce }); });
  var pend = await pki.scep.enroll("http://ca.example/scep", Object.assign({ transport: pT }, base));
  check("enroll: a PENDING CertRep returns the pending status", pend.status === "PENDING" && typeof pend.transactionId === "string");
}

async function testRenew() {
  var cl = await rsaClient();
  var csr = await pki.csr.sign({ subject: "device.example", subjectPublicKey: cl.pub }, { key: cl.key });
  var issued = await pki.x509.sign({ subject: "device.example", subjectPublicKey: cl.pub, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01") }, { key: F.caKey, cert: F.caCert });
  var t = caTransport(async function (p) {
    check("renew: request is a RenewalReq", p.messageType === "RenewalReq");
    var env = await cmsEncrypt.encrypt(certsOnly([issued]), [{ cert: cl.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
    return buildCertRep({ statusCode: "0", transactionId: p.transactionId, recipientNonce: p.senderNonce, content: env });
  });
  var out = await pki.scep.renew("http://ca.example/scep", { csr: csr, caCert: F.caCert, signer: { cert: cl.cert, key: cl.key }, recipientKey: { cert: cl.cert, key: cl.key }, transport: t });
  check("renew: SUCCESS returns the renewed certificate", out.status === "SUCCESS" && Buffer.compare(out.certificate, issued) === 0);
}

async function testClientTransportEdges() {
  var seq = fakeTransport([
    { status: 302, headers: { location: "http://ca.example/scep2" } },
    { status: 200, headers: { "content-type": "text/plain" }, body: "AES\n" },
  ]);
  var caps = await pki.scep.getCACaps("http://ca.example/scep", { transport: seq });
  check("client: follows a same-origin redirect", caps.AES === true && seq.calls.length === 2);
  check("client: an https->http redirect is refused", (await codeOf(pki.scep.getCACaps("https://ca.example/scep", { transport: fakeTransport([{ status: 302, headers: { location: "http://ca.example/scep2" } }]) }))) === "scep/insecure-redirect");
  // the mTLS client identity is sent to the initial origin only; a cross-origin redirect hop drops it.
  var xorigin = fakeTransport([
    { status: 302, headers: { location: "https://other.example/scep" } },
    { status: 200, headers: { "content-type": "text/plain" }, body: "AES\n" },
  ]);
  await pki.scep.getCACaps("https://ca.example/scep", { transport: xorigin, tls: { cert: Buffer.from("CLIENT-CERT"), key: Buffer.from("CLIENT-KEY"), anchors: [] } });
  check("client: mTLS credential reaches the initial origin", Buffer.isBuffer(xorigin.calls[0].tls.cert) && Buffer.isBuffer(xorigin.calls[0].tls.key));
  // Explicitly null, not absent: a deleted field falls back to a transport's own tls defaults, so the
  // cross-origin hop must OVERRIDE cert/key/servername to suppress a configured default credential.
  check("client: mTLS credential is overridden (not just omitted) on a cross-origin hop", xorigin.calls[1].tls.cert === null && xorigin.calls[1].tls.key === null && xorigin.calls[1].tls.servername === null);
  // a discovery GET snapshots its tls at the start: a same-origin redirect hop uses the identity the first
  // hop did, even if opts.tls is replaced while the request is in flight.
  var redirOpts = { tls: { cert: Buffer.from("ORIG-CERT"), anchors: [] } };
  var hopN = 0;
  redirOpts.transport = fakeTransport(function () {
    hopN += 1;
    if (hopN === 1) { redirOpts.tls = { cert: Buffer.from("SWAPPED-CERT"), anchors: [] }; return { status: 302, headers: { location: "http://ca.example/scep2" } }; }
    return { status: 200, headers: { "content-type": "text/plain" }, body: "AES\n" };
  });
  await pki.scep.getCACaps("http://ca.example/scep", redirOpts);
  check("getCACaps: a redirect hop uses the tls captured at the start, not a mid-flight replacement", redirOpts.transport.calls[1].tls.cert.equals(Buffer.from("ORIG-CERT")));
  // even when the call carries no request-level tls, a cross-origin hop must emit explicit null overrides:
  // the transport may hold default client credentials that an omitted field would fall through to.
  var xoBare = fakeTransport([{ status: 302, headers: { location: "https://other.example/scep" } }, { status: 200, headers: { "content-type": "text/plain" }, body: "AES\n" }]);
  await pki.scep.getCACaps("https://ca.example/scep", { transport: xoBare });
  check("client: a cross-origin hop overrides tls credentials even when the call sets none", xoBare.calls[1].tls.cert === null && xoBare.calls[1].tls.key === null && xoBare.calls[1].tls.servername === null);
  check("client: a redirect to a non-HTTP scheme is refused", (await codeOf(pki.scep.getCACaps("http://ca.example/scep", { transport: fakeTransport([{ status: 302, headers: { location: "ftp://evil.example/x" } }]) }))) === "scep/bad-url");
  check("client: the redirect cap is enforced", (await codeOf(pki.scep.getCACaps("http://ca.example/scep", { transport: fakeTransport({ status: 302, headers: { location: "http://ca.example/next" } }), maxRedirects: 1 }))) === "scep/too-many-redirects");
  check("client: a redirect without a Location is refused", (await codeOf(pki.scep.getCACaps("http://ca.example/scep", { transport: fakeTransport({ status: 302, headers: {}, body: "" }) }))) === "scep/bad-response");
  check("client: a non-HTTP base URL is refused even with an injected transport", (await codeOf(pki.scep.getCACaps("ftp://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "text/plain" }, body: "AES\n" }) }))) === "scep/bad-url");
  check("client: a file URL is refused", (await codeOf(pki.scep.getCACaps("file:///etc/passwd", { transport: fakeTransport({ status: 200, headers: { "content-type": "text/plain" }, body: "AES\n" }) }))) === "scep/bad-url");
  check("getCACaps: a 500 is an error, not none-supported", (await codeOf(pki.scep.getCACaps("http://ca.example/scep", { transport: fakeTransport({ status: 500, headers: {}, body: "" }) }))) === "scep/http-error");
  check("client: a response over the byte cap is refused", (await codeOf(pki.scep.getCACaps("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "text/plain" }, body: Buffer.alloc(4096, 0x41) }), maxResponseBytes: 16 }))) === "scep/response-too-large");
  var fpColon = nodeCrypto.createHash("sha256").update(F.caCert).digest("hex").replace(/(..)(?!$)/g, "$1:");
  var okc = await pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: F.caCert }), expectedFingerprint: fpColon });
  check("getCACert: a colon-separated fingerprint is accepted", Buffer.compare(okc.caCertificate, F.caCert) === 0);
  check("getCACert: a non-hex fingerprint is refused", (await codeOf(pki.scep.getCACert("http://ca.example/scep", { transport: fakeTransport({ status: 200, headers: { "content-type": "application/x-x509-ca-cert" }, body: F.caCert }), expectedFingerprint: "zz" }))) === "scep/bad-input");
}

async function testEnrollSecurity() {
  var cl = await rsaClient();
  var csr = await pki.csr.sign({ subject: "device.example", subjectPublicKey: cl.pub }, { key: cl.key });
  var base = { csr: csr, caCert: F.caCert, signer: { cert: cl.cert, key: cl.key }, recipientKey: { cert: cl.cert, key: cl.key } };
  var other = await rsaClient();
  var wrongCert = await pki.x509.sign({ subject: "device.example", subjectPublicKey: other.pub, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01") }, { key: F.caKey, cert: F.caCert });
  var wrongT = caTransport(async function (p) {
    var env = await cmsEncrypt.encrypt(certsOnly([wrongCert]), [{ cert: cl.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
    return buildCertRep({ statusCode: "0", transactionId: p.transactionId, recipientNonce: p.senderNonce, content: env });
  });
  check("enroll: a SUCCESS lacking the requested key is refused", (await codeOf(pki.scep.enroll("http://ca.example/scep", Object.assign({ transport: wrongT }, base)))) === "scep/no-issued-cert");
  // a CertRep signed by a rogue (non-CA) certificate is refused: enroll authenticates the responder.
  var rogue = await rsaClient();
  var rogueT = fakeTransport(async function (req) {
    var p = await pki.scep.parse(req.body, { recipientKey: { cert: F.caCert, key: F.caKey } });
    var env = await cmsEncrypt.encrypt(certsOnly([wrongCert]), [{ cert: cl.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
    var rep = await buildCertRep({ statusCode: "0", transactionId: p.transactionId, recipientNonce: p.senderNonce, content: env, signer: { cert: rogue.cert, key: rogue.key } });
    return { status: 200, headers: { "content-type": "application/x-pki-message" }, body: rep };
  });
  check("enroll: a response signed by a rogue certificate is refused", (await codeOf(pki.scep.enroll("http://ca.example/scep", Object.assign({ transport: rogueT }, base)))) === "scep/untrusted-signer");
  // a CertRep whose transactionID does not echo the request is refused even with a matching nonce + signer.
  var wrongTxn = caTransport(function (p) { return buildCertRep({ statusCode: "3", transactionId: "a-different-transaction", recipientNonce: p.senderNonce }); });
  check("enroll: a mismatched CertRep transactionID is refused", (await codeOf(pki.scep.enroll("http://ca.example/scep", Object.assign({ transport: wrongTxn }, base)))) === "scep/transaction-id-mismatch");
  // a mid-flight mutation of caCert must not change the trusted response signer: the response-security
  // inputs are snapshotted at the synchronous entry point, so the response is authenticated against the
  // caCert the request was built with, not one the caller swaps in while the POST is in flight.
  var swapIssued = await pki.x509.sign({ subject: "device.example", subjectPublicKey: cl.pub, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01") }, { key: F.caKey, cert: F.caCert });
  var swapOpts = Object.assign({}, base);
  swapOpts.transport = fakeTransport(async function (req) {
    swapOpts.caCert = F.issuedCert;   // swap the trusted signer after build, before the response is parsed
    var p = await pki.scep.parse(req.body, { recipientKey: { cert: F.caCert, key: F.caKey } });
    var env = await cmsEncrypt.encrypt(certsOnly([swapIssued]), [{ cert: cl.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
    return { status: 200, headers: { "content-type": "application/x-pki-message" }, body: await buildCertRep({ statusCode: "0", transactionId: p.transactionId, recipientNonce: p.senderNonce, content: env }) };
  });
  var swapOut = await pki.scep.enroll("http://ca.example/scep", swapOpts);
  check("enroll: a mid-flight caCert swap cannot change the trusted response signer", swapOut.status === "SUCCESS" && Buffer.compare(swapOut.certificate, swapIssued) === 0);
  // the recipient key FIELDS are snapshotted at the entry point too: replacing opts.recipientKey.key while
  // the POST is in flight must not switch the credential the response is decrypted with.
  var rkSwapOpts = Object.assign({}, base);
  rkSwapOpts.recipientKey = { cert: cl.cert, key: cl.key };
  rkSwapOpts.transport = fakeTransport(async function (req) {
    rkSwapOpts.recipientKey.key = other.key;   // replace the recipient private key field after build, before parse decrypts
    var p = await pki.scep.parse(req.body, { recipientKey: { cert: F.caCert, key: F.caKey } });
    var env = await cmsEncrypt.encrypt(certsOnly([swapIssued]), [{ cert: cl.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
    return { status: 200, headers: { "content-type": "application/x-pki-message" }, body: await buildCertRep({ statusCode: "0", transactionId: p.transactionId, recipientNonce: p.senderNonce, content: env }) };
  });
  var rkOut = await pki.scep.enroll("http://ca.example/scep", rkSwapOpts);
  check("enroll: a mid-flight recipientKey field swap cannot change the decryption credential", rkOut.status === "SUCCESS" && Buffer.compare(rkOut.certificate, swapIssued) === 0);
  // the transport options are snapshotted at the door too: replacing opts.transport or opts.tls.cert
  // immediately after the call must not reroute the in-flight request or change the mTLS identity it presents.
  var okBuild = async function (p) {
    var env = await cmsEncrypt.encrypt(certsOnly([swapIssued]), [{ cert: cl.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
    return buildCertRep({ statusCode: "0", transactionId: p.transactionId, recipientNonce: p.senderNonce, content: env });
  };
  var T1 = caTransport(okBuild), T2 = caTransport(okBuild);
  var swapTOpts = Object.assign({ transport: T1, tls: { cert: Buffer.from("CLIENT-CERT-A"), anchors: [] } }, base);
  var pSwap = pki.scep.enroll("http://ca.example/scep", swapTOpts);
  swapTOpts.transport = T2;                          // reroute attempt
  swapTOpts.tls.cert = Buffer.from("CLIENT-CERT-B"); // mTLS identity-swap attempt
  await pSwap;
  check("enroll: a transport swap immediately after the call cannot reroute the in-flight request", T1.calls.length === 1 && T2.calls.length === 0);
  check("enroll: a tls.cert swap immediately after the call cannot change the presented mTLS identity", T1.calls.length === 1 && T1.calls[0].tls.cert.equals(Buffer.from("CLIENT-CERT-A")));
  // the request URL is resolved at the door: a baseUrl object whose toString() changes after the call must
  // not redirect the in-flight POST to another host.
  var urlTarget = "http://ca.example/scep";
  var mutBaseUrl = { toString: function () { return urlTarget; } };
  var urlT = caTransport(okBuild);
  var pUrl = pki.scep.enroll(mutBaseUrl, Object.assign({ transport: urlT }, base));
  urlTarget = "http://evil.example/scep";   // repoint the URL while the request is being built
  await pUrl;
  check("enroll: a mutable baseUrl toString cannot redirect the in-flight POST", urlT.calls[0].url.indexOf("ca.example") !== -1 && urlT.calls[0].url.indexOf("evil.example") === -1);
  // two returned certificates carrying the requested public key (a same-key renewal, a duplicate) are
  // ambiguous: a CMS CertificateSet states no issuance order, so the issued certificate cannot be chosen.
  var issuedA = await pki.x509.sign({ subject: "device.example", subjectPublicKey: cl.pub, notBefore: new Date("2026-01-01"), notAfter: new Date("2027-01-01") }, { key: F.caKey, cert: F.caCert });
  var issuedB = await pki.x509.sign({ subject: "device.example", subjectPublicKey: cl.pub, notBefore: new Date("2026-02-01"), notAfter: new Date("2028-01-01") }, { key: F.caKey, cert: F.caCert });
  var ambigT = caTransport(async function (p) {
    var env = await cmsEncrypt.encrypt(certsOnly([issuedA, issuedB]), [{ cert: cl.cert }], { contentEncryptionAlgorithm: "aes-128-cbc" });
    return buildCertRep({ statusCode: "0", transactionId: p.transactionId, recipientNonce: p.senderNonce, content: env });
  });
  check("enroll: two certificates carrying the requested key are refused as ambiguous", (await codeOf(pki.scep.enroll("http://ca.example/scep", Object.assign({ transport: ambigT }, base)))) === "scep/ambiguous-issued-cert");
}

async function testClientInputGuards() {
  var okT = fakeTransport({ status: 200, headers: { "content-type": "text/plain" }, body: "" });
  check("getCACaps: unknown option refused", (await codeOf(pki.scep.getCACaps("http://ca/scep", { transport: okT, bogus: 1 }))) === "scep/bad-input");
  check("enroll: missing csr refused before any request", (await codeOf(pki.scep.enroll("http://ca/scep", { caCert: F.caCert, signer: F.signer, recipientKey: F.signer, transport: okT }))) === "scep/bad-input");
  check("enroll: missing recipientKey refused", (await codeOf(pki.scep.enroll("http://ca/scep", { csr: F.csr, caCert: F.caCert, signer: F.signer, transport: okT }))) === "scep/bad-input");
  check("client: an unparseable base URL is refused", (await codeOf(pki.scep.getCACaps("not a url", { transport: okT }))) === "scep/bad-url");
}

async function main() {
  await setup();
  await testPkcsReqRoundTrip();
  await testRenewalReqRoundTrip();
  await testNoKeyParse();
  await testNonceEcho();
  await testCertRepSuccessParse();
  await testCertRepCrlOnly();
  await testRequestPayloadValidated();
  await testCertRepSuccessValidatesPayload();
  await testCertRepFailureParse();
  await testCertRepPendingParse();
  await testMissingMandatoryAttributes();
  await testUnknownEnumerants();
  await testCertRepMissingStatusAndFail();
  await testNonSuccessCertRepWithRecipientKey();
  await testSignerAuthentication();
  await testSignerKeyUsage();
  await testEnvelopeRequiresCiphertext();
  await testPinnedSignerKeyUsage();
  await testBuildValidatesCsr();
  await testCertRepRequiresRecipientNonce();
  await testEnvelopeMandatory();
  await testOuterContentTypeMustBeData();
  await testFailInfoOnlyOnFailure();
  await testMalformedInputsCoverage();
  await testBuildSnapshotsMessageData();
  await testParseSnapshotsBytes();
  await testParseSnapshotsSignerCert();
  await testBuildSnapshotsRecipient();
  await testUnsupportedMessageTypes();
  await testRequestRejectsResponseAttrs();
  await testEnvelopeContentTypeMustBeData();
  await testWrongStringType();
  await testMultiValuedAttribute();
  await testMultipleSigners();
  await testTamperFailsClosed();
  await testInputGuards();
  await testGetCACaps();
  await testGetCACert();
  await testGetNextCACert();
  await testEnrollSuccess();
  await testEnrollTransactionIdUnique();
  await testEnrollFailureAndPending();
  await testRenew();
  await testClientTransportEdges();
  await testEnrollSecurity();
  await testClientInputGuards();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
