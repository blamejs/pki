// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- SCEP pkiMessage (pki.scep.build) cross-implementation interop.
 *
 * A SCEP request pkiMessage (RFC 8894 sec. 3) is two nested CMS layers: an outer SignedData over the
 * transaction attributes, and an inner EnvelopedData (the pkcsPKIEnvelope) that encrypts the PKCS#10.
 * OpenSSL has no SCEP verb, but it is the INDEPENDENT ORACLE for the two CMS layers the toolkit emits,
 * so a pkiMessage we build is validated end to end by something other than our own decoder:
 *
 *   Gate A (structural) -- `openssl cms -cmsout` parses the whole pkiMessage as a well-formed CMS
 *     SignedData, so the SCEP transaction attributes never produce malformed DER.
 *   Gate B (outer signature) -- `openssl cms -verify -noverify` verifies the outer signature under the
 *     embedded signer certificate and extracts the pkcsPKIEnvelope, confirming the signed layer is
 *     independently verifiable.
 *   Gate C (inner decryption) -- `openssl cms -decrypt` recovers the messageData from the extracted
 *     EnvelopedData with the recipient CA key, confirming the encrypted layer is independently readable.
 *   Gate D (round-trip) -- the recovered messageData is byte-identical to the PKCS#10 we encrypted, and
 *     `openssl req` parses it back to its subject.
 *   Negative -- a pkiMessage whose outer signature byte is flipped is REJECTED by `openssl cms -verify`.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");

function pemFromDer(bytes, opensslArgs, ext) {
  var pem = ctx.runOpenssl(opensslArgs.concat(["-in", ctx.tmpFile(bytes, ext + ".der")]));
  return ctx.tmpFile(Buffer.from(pem, "utf8"), ext + ".pem");
}

async function run() {
  var ca = signing.makeRecipient("rsa");            // the SCEP CA: a keyEncipherment RSA recipient
  var client = signing.makeSigner("rsa");           // the client: the outer SignedData signer
  var reqKp = await pki.key.generate("Ed25519");
  var csr = await pki.csr.sign(
    { subject: "device.example", subjectPublicKey: await pki.key.export(reqKp.publicKey) },
    { key: await pki.key.export(reqKp.privateKey) });

  var msg = await pki.scep.build({
    messageType: "PKCSReq", messageData: csr, recipient: ca.cert,
    signer: { cert: client.cert, key: client.key }, transactionId: "txn-interop" });

  var msgPath = ctx.tmpFile(msg, "scep-msg.der");
  var caPemPath = pemFromDer(ca.cert, ["x509", "-inform", "DER"], "ca");
  var caKeyPath = pemFromDer(ca.key, ["pkey", "-inform", "DER"], "cakey");
  var envPath = ctx.tmpFile(Buffer.alloc(0), "env.der");
  var recPath = ctx.tmpFile(Buffer.alloc(0), "recovered.bin");

  // Gate A: openssl parses the whole pkiMessage as a CMS structure.
  var printed = ctx.runOpenssl(["cms", "-cmsout", "-noout", "-print", "-inform", "DER", "-in", msgPath], { allowNonZero: true });
  check("Gate A: openssl parses our SCEP pkiMessage as CMS SignedData", printed.code === 0);

  // Gate B: openssl verifies the outer signature and extracts the pkcsPKIEnvelope. `-binary` keeps the
  // extracted DER byte-exact: without it openssl applies S/MIME CRLF canonicalization to the content.
  var vres = ctx.runOpenssl(["cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", msgPath, "-out", envPath, "-outform", "DER"], { allowNonZero: true });
  check("Gate B: openssl verifies the outer SignedData signature", vres.code === 0);

  // Gate C: openssl decrypts the extracted EnvelopedData with the CA key. `-binary` preserves the
  // recovered PKCS#10 DER exactly, so a CSR byte that looks like a line ending is not rewritten.
  var dres = ctx.runOpenssl(["cms", "-decrypt", "-binary", "-inform", "DER", "-in", envPath, "-recip", caPemPath, "-inkey", caKeyPath, "-out", recPath], { allowNonZero: true });
  check("Gate C: openssl decrypts the pkcsPKIEnvelope with the recipient CA key", dres.code === 0);

  // Gate D: the recovered messageData is the exact PKCS#10 we encrypted, and openssl parses it.
  var recovered = ctx.fs.readFileSync(recPath);
  check("Gate D: recovered messageData is byte-identical to the PKCS#10", Buffer.compare(recovered, csr) === 0);
  var subj = ctx.runOpenssl(["req", "-inform", "DER", "-in", recPath, "-noout", "-subject"], { allowNonZero: true });
  check("Gate D: openssl parses the recovered PKCS#10 request", subj.code === 0);

  // Negative: a pkiMessage with a flipped outer-signature byte is rejected by openssl.
  var tampered = Buffer.from(msg);
  tampered[tampered.length - 4] ^= 0x40;
  var tPath = ctx.tmpFile(tampered, "tampered.der");
  var tOut = ctx.tmpFile(Buffer.alloc(0), "tampered-out.der");
  var tres = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", tPath, "-out", tOut, "-outform", "DER"], { allowNonZero: true });
  check("Negative: openssl rejects a pkiMessage with a tampered outer signature", tres.code !== 0);

  [msgPath, caPemPath, caKeyPath, envPath, recPath, tPath, tOut].forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } });
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
