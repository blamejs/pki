// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- RFC 6211 CMSAlgorithmProtection cross-implementation interop.
 *
 * OpenSSL registers the attribute's object identifier (`pkcs9 52 : id-aa-CMSAlgorithmProtection` in
 * `crypto/objects/objects.txt`) but its `cms` CLI neither emits nor compares the attribute, so
 * "openssl writes it, we check it" is not achievable. OpenSSL is the INDEPENDENT ORACLE for the two
 * things that decide whether emitting it is safe:
 *
 *  Gate A (structural) -- `openssl cms -cmsout -print` parses a SignedData carrying the attribute
 *    and names it by the identifier it registered, which is what says the identifier this build
 *    emits is the one deployed code reads. The same gate over the IANA registry spelling shows the
 *    raw OID instead, which is the interop split draft-ietf-lamps-rfc6211-update sec. 1 records.
 *  Gate B (the signature still verifies) -- `openssl cms -verify` accepts the message, so adding the
 *    attribute to signedAttrs did not disturb the RFC 5652 sec. 5.4 preimage. A verifier that does
 *    not know the attribute must be unaffected by it, which is the whole basis of the SHOULD in
 *    RFC 8933 sec. 4.1.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;

var CONTENT = Buffer.from("RFC 6211 algorithm protection interop content");
var OID_PKCS9 = "1.2.840.113549.1.9.52";
var OID_REGISTRY = "1.2.840.113549.1.9.16.2.52";

async function run() {
  var tmps = [];
  function T(bytes, ext) { var p = ctx.tmpFile(bytes, ext); tmps.push(p); return p; }
  function reserve(ext) { return T(Buffer.alloc(0), ext); }

  try {
    var key = reserve("signer.key");
    var cert = reserve("signer.pem");
    var cnf = T(Buffer.from(
      "[req]\ndistinguished_name = dn\nx509_extensions = v3\nprompt = no\n" +
      "[dn]\nCN = pkijs-rfc6211-signer\n" +
      "[v3]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n" +
      "subjectKeyIdentifier = hash\n", "ascii"), "signer.cnf");
    ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-keyout", key, "-out", cert, "-days", "2", "-nodes", "-config", cnf]);
    var certDer = reserve("signer.der");
    var keyP8 = reserve("signer.p8");
    ctx.runOpenssl(["x509", "-in", cert, "-outform", "DER", "-out", certDer]);
    ctx.runOpenssl(["pkcs8", "-topk8", "-nocrypt", "-in", key, "-outform", "DER", "-out", keyP8]);
    var signer = { cert: ctx.fs.readFileSync(certDer), key: ctx.fs.readFileSync(keyP8) };

    var protectedDer = await pki.cms.sign(CONTENT, signer, { algorithmProtection: true });
    var registryDer = await pki.cms.sign(CONTENT, signer, { algorithmProtection: "registry" });

    // ---- Gate A: openssl reads the attribute, and names the identifier it registered ------------
    var protPath = T(protectedDer, "protected.der");
    var printed = ctx.runOpenssl(["cms", "-cmsout", "-noout", "-print", "-inform", "DER", "-in", protPath], { allowNonZero: true });
    var printedText = String(printed.stdout || "") + String(printed.stderr || "");
    check("Gate A: openssl parses our SignedData carrying the attribute", printed.code === 0);
    check("Gate A: and shows it under " + OID_PKCS9,
      printedText.indexOf(OID_PKCS9) !== -1);
    var regPath = T(registryDer, "registry.der");
    var printedReg = ctx.runOpenssl(["cms", "-cmsout", "-noout", "-print", "-inform", "DER", "-in", regPath], { allowNonZero: true });
    var regText = String(printedReg.stdout || "") + String(printedReg.stderr || "");
    check("Gate A: the IANA registry spelling parses too, and shows under " + OID_REGISTRY,
      printedReg.code === 0 && regText.indexOf(OID_REGISTRY) !== -1);
    /** Whether the binary maps the identifier to a NAME is a capability of its object table, not a
     *  property of the bytes: the registration arrived after OpenSSL 3.0, so a build that prints the
     *  raw OID is reading the same structure by a table that does not list it. Asserted where the
     *  capability is present and recorded as a skip where it is not, rather than failing the gate on
     *  the oracle's vintage. */
    if (/CMSAlgorithmProtection/i.test(printedText)) {
      check("Gate A: this build names the RFC 6211 identifier, and does NOT name the registry one, " +
        "which is the interop split the update draft records",
      !/CMSAlgorithmProtection/i.test(regText));
    } else {
      ctx.skip("this openssl build does not map 1.2.840.113549.1.9.52 to a name (the object-table " +
        "registration postdates 3.0), so the name half of the identifier split cannot be observed");
    }

    // ---- Gate B: a verifier that does not know the attribute is unaffected by it ---------------
    var vProt = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", protPath, "-certfile", cert], { allowNonZero: true });
    check("Gate B: openssl verifies the signature over signedAttrs carrying the attribute",
      vProt.code === 0);
    var plainPath = T(await pki.cms.sign(CONTENT, signer), "plain.der");
    var vPlain = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", plainPath, "-certfile", cert], { allowNonZero: true });
    check("Gate B CONTROL: and the same message without it, so the gate is not vacuous",
      vPlain.code === 0);
    var vReg = ctx.runOpenssl(["cms", "-verify", "-noverify", "-inform", "DER", "-in", regPath, "-certfile", cert], { allowNonZero: true });
    check("Gate B: the registry spelling verifies as well, an unknown attribute being just an " +
      "attribute to a verifier that does not read it", vReg.code === 0);

    // ---- and our own verdict agrees on the message openssl just accepted -----------------------
    var ours = await pki.cms.verify(protectedDer, { certs: [signer.cert] });
    check("our verdict compares both identifiers on the message openssl accepted",
      ours.signers[0].ok === true &&
      ours.signers[0].algorithmProtection.oid === OID_PKCS9 &&
      ours.signers[0].algorithmProtection.compared.length === 2);
  } finally {
    tmps.forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } });
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
