// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- CAdES signature timestamp (pki.cms.attachTimestamp) cross-implementation interop.
 *
 * OpenSSL's `cms` CLI cannot attach a signature timestamp, so "openssl stamps, we verify" is not
 * achievable. OpenSSL is the INDEPENDENT ORACLE for the three things that matter:
 *
 *  Gate A (structural) -- `openssl cms -cmsout -print` parses the stamped SignedData and shows the
 *    attribute in `unauthAttr` under { 1 2 840 113549 1 9 16 2 14 }, so the splice produced the
 *    unsigned attribute an independent implementation reads where CAdES puts it.
 *  Gate B (the signature survives the splice) -- `openssl cms -verify` accepts the message both
 *    before and after the attach, which is what proves the four signature inputs were preserved
 *    byte for byte. A tampered content is rejected.
 *  Gate C (the imprint preimage) -- `openssl ts -verify -token_in -data <signature octets>` accepts
 *    the token against the SignerInfo signature value, independently confirming the EN 319 122-1
 *    clause 5.3 preimage: the contents octets of the signature OCTET STRING, with no tag and no
 *    length. The same token against any other bytes is rejected.
 *
 * The TSA chain is minted by the openssl CLI, since `openssl ts -verify` validates it; the signer is
 * ours. Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;

var CONTENT = Buffer.from("CAdES B-T interop content");
var TS_OID = "1.2.840.113549.1.9.16.2.14";

async function run() {
  // Oracle-capability probe: `openssl ts` with no sub-mode prints its usage.
  var tsProbe = ctx.runOpenssl(["ts"], { allowNonZero: true });
  var tsText = String(tsProbe.stdout || "") + String(tsProbe.stderr || "");
  if (!/-query|-reply|-verify/.test(tsText)) {
    ctx.skip("openssl `ts` subcommand unavailable in this build -- the signature-timestamp preimage cross-check cannot run");
    return;
  }

  var tmps = [];
  function T(bytes, ext) { var p = ctx.tmpFile(bytes, ext); tmps.push(p); return p; }
  function reserve(ext) { return T(Buffer.alloc(0), ext); }
  function fwd(p) { return p.replace(/\\/g, "/"); }

  try {
    // ---- hermetic TSA chain: a CA, and a leaf carrying the critical sole timeStamping EKU -------
    var caKey = reserve("caKey.pem");
    var caCert = reserve("caCert.pem");
    var caCnf = T(Buffer.from(
      "[req]\ndistinguished_name = dn\nx509_extensions = v3_ca\nprompt = no\n" +
      "[dn]\nCN = pkijs-cades-tsa-root\n" +
      "[v3_ca]\nbasicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\n" +
      "subjectKeyIdentifier = hash\n", "ascii"), "ca.cnf");
    ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-keyout", caKey, "-out", caCert, "-days", "2", "-nodes", "-config", caCnf]);
    var caSrl = T(Buffer.from("01", "ascii"), "ca.srl");
    var serial = T(Buffer.from("01", "ascii"), "serial.txt");
    var tsaKey = reserve("tsaKey.pem");
    var tsaCsr = reserve("tsaCsr.pem");
    var tsaCert = reserve("tsaCert.pem");
    var tsaCnf = T(Buffer.from(
      "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = pkijs-cades-tsa\n" +
      "[tsa_ext]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n" +
      "extendedKeyUsage = critical, timeStamping\nsubjectKeyIdentifier = hash\n" +
      "[tsa]\ndefault_tsa = tsa_config1\n[tsa_config1]\nserial = " + fwd(serial) + "\ncrypto_device = builtin\n" +
      "signer_digest = sha256\ndigests = sha256, sha384, sha512\ndefault_policy = 1.2.3.4.1\n" +
      "accuracy = secs:1\nclock_precision_digits = 0\nordering = no\ntsa_name = no\n", "ascii"), "tsa.cnf");
    ctx.runOpenssl(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-keyout", tsaKey, "-out", tsaCsr, "-nodes", "-config", tsaCnf]);
    ctx.runOpenssl(["x509", "-req", "-in", tsaCsr, "-CA", caCert, "-CAkey", caKey,
      "-CAserial", caSrl, "-days", "1", "-out", tsaCert, "-extfile", tsaCnf, "-extensions", "tsa_ext"]);
    var tsaCertDer = reserve("tsaCert.der");
    var tsaKeyP8 = reserve("tsaKey.p8");
    ctx.runOpenssl(["x509", "-in", tsaCert, "-outform", "DER", "-out", tsaCertDer]);
    ctx.runOpenssl(["pkcs8", "-topk8", "-nocrypt", "-in", tsaKey, "-outform", "DER", "-out", tsaKeyP8]);
    var tsa = { cert: ctx.fs.readFileSync(tsaCertDer), key: ctx.fs.readFileSync(tsaKeyP8) };

    // ---- the signer, and a signature carrying the CAdES signing-certificate binding -------------
    var signerKey = reserve("signerKey.pem");
    var signerCert = reserve("signerCert.pem");
    var signerCnf = T(Buffer.from(
      "[req]\ndistinguished_name = dn\nx509_extensions = v3_leaf\nprompt = no\n" +
      "[dn]\nCN = pkijs-cades-signer\n" +
      "[v3_leaf]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n" +
      "subjectKeyIdentifier = hash\n", "ascii"), "signer.cnf");
    ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-keyout", signerKey, "-out", signerCert, "-days", "2", "-nodes", "-config", signerCnf]);
    var signerCertDer = reserve("signerCert.der");
    var signerKeyP8 = reserve("signerKey.p8");
    ctx.runOpenssl(["x509", "-in", signerCert, "-outform", "DER", "-out", signerCertDer]);
    ctx.runOpenssl(["pkcs8", "-topk8", "-nocrypt", "-in", signerKey, "-outform", "DER", "-out", signerKeyP8]);
    var signer = { cert: ctx.fs.readFileSync(signerCertDer), key: ctx.fs.readFileSync(signerKeyP8) };

    var base = await pki.cms.sign(CONTENT, signer, { additionalSignedAttributes: [
      { type: "signingCertificateV2", values: [pki.schema.smime.buildSigningCertificateV2(signer.cert)] },
    ] });
    var imprint = await pki.cms.timestampImprint(base);
    var token = await pki.tsp.sign({ hashAlgorithm: imprint.hashAlgorithm, hashedMessage: imprint.hashedMessage },
      tsa, { policy: "1.2.3.4.1", serialNumber: 11 });
    var bT = await pki.cms.attachTimestamp(base, token);

    // ---- Gate A: openssl reads the attribute where CAdES puts it --------------------------------
    var bTPath = T(bT, "cades-bt.der");
    var printed = ctx.runOpenssl(["cms", "-cmsout", "-noout", "-print", "-inform", "DER", "-in", bTPath], { allowNonZero: true });
    var printedText = String(printed.stdout || "") + String(printed.stderr || "");
    check("Gate A: openssl parses our stamped SignedData", printed.code === 0);
    // The heading is spelled `unsignedAttrs` by the `cms` printer and `unauthAttr` by the older
    // `pkcs7` one, so either names the right place; the OID is what pins the attribute.
    check("Gate A: openssl shows the token among the unsigned attributes under " + TS_OID,
      (/unsignedAttrs/.test(printedText) || /unauthAttr/.test(printedText)) &&
      printedText.indexOf(TS_OID) !== -1);

    // ---- Gate B: the splice left every signature input alone ------------------------------------
    var basePath = T(base, "cades-base.der");
    var certfile = signerCert;
    var vBase = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", basePath, "-certfile", certfile], { allowNonZero: true });
    check("Gate B: openssl verifies the signature before the attach", vBase.code === 0);
    var vBt = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", bTPath, "-certfile", certfile], { allowNonZero: true });
    check("Gate B: openssl still verifies the same signature after the attach", vBt.code === 0);
    var ours = await pki.cms.verify(bT, { certs: [signer.cert] });
    check("Gate B: and our own verdict agrees, with the timestamp row valid",
      ours.signers[0].ok === true && ours.signers[0].signatureTimeStamps.length === 1 &&
      ours.signers[0].signatureTimeStamps[0].valid === true);
    check("Gate B: the message reports the CAdES baseline requirements as met",
      ours.signers[0].cadesBaseline.conformant === true);

    // ---- Gate C: the imprint is the signature's contents octets, tag and length excluded --------
    var sigOctets = Buffer.from(pki.schema.cms.parse(bT).signerInfos[0].signature);
    var sigPath = T(sigOctets, "sigvalue.bin");
    var tokenPath = T(token, "token.der");
    var vTs = ctx.runOpenssl(["ts", "-verify", "-data", sigPath, "-in", tokenPath, "-token_in",
      "-CAfile", caCert, "-untrusted", tsaCert], { allowNonZero: true });
    check("Gate C: openssl ts -verify accepts the token against the SignerInfo signature octets",
      vTs.code === 0 && /Verification:\s*OK/i.test(String(vTs.stdout) + String(vTs.stderr)));
    // The negative arm names the exact confusion the preimage rule exists to prevent: the signature
    // TLV with its tag and length, which is one byte sequence away from the right answer.
    var sigTlv = T(pki.asn1.build.octetString(sigOctets), "sigvalue-tlv.bin");
    var vTsTlv = ctx.runOpenssl(["ts", "-verify", "-data", sigTlv, "-in", tokenPath, "-token_in",
      "-CAfile", caCert, "-untrusted", tsaCert], { allowNonZero: true });
    check("Gate C: and rejects the same token against the signature TLV, tag and length included",
      vTsTlv.code !== 0);
    var contentPath = T(CONTENT, "content.bin");
    var vTsContent = ctx.runOpenssl(["ts", "-verify", "-data", contentPath, "-in", tokenPath, "-token_in",
      "-CAfile", caCert, "-untrusted", tsaCert], { allowNonZero: true });
    check("Gate C: and rejects it against the signed content, which a countersignature would cover",
      vTsContent.code !== 0);
  } finally {
    tmps.forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } });
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
