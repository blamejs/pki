// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- RFC 5272 CMC message issuance (pki.cmc.build) cross-implementation interop.
 *
 * No toolchain PROCESSES CMC: there is no `openssl cmc` verb, and NSS ships no PKIData /
 * PKIResponse generator. But that is not the same as having no independent reader, and the
 * oracle here is the same two-part one the other formats without a full implementation use:
 *  (a) STRUCTURE -- `openssl asn1parse -inform DER` (an independent DER decoder, unrelated to
 *      the toolkit's) accepts the emitted Full PKI Request, and its dump NAMES the content type
 *      `id-cct-PKIData` and the control OIDs from its own OID table -- so a second implementation
 *      agrees about what these bytes are, not merely that they are well-formed DER. Across a
 *      classical arm (RSA, ECDSA, EdDSA) and, on OpenSSL >= 3.5, the post-quantum ML-DSA arm;
 *  (b) SIGNATURE -- verified OUTSIDE the toolkit's own CMS verifier: the signed attributes are
 *      re-tagged to the SET OF form RFC 5652 sec. 5.4 signs and checked with node:crypto under
 *      the signer's public key, so a passing check does not depend on pki.cms.verify agreeing
 *      with pki.cms.sign. A flipped signature byte fails it.
 *
 * WHAT THIS DOES NOT PROVE, because the distinction matters more than the checks:
 * `asn1parse` without `-item` is a generic DER dumper plus an OID table. It establishes that the
 * bytes are well-formed DER and that OpenSSL recognizes the OIDs in them. It does NOT drive a CMC
 * template, so it does not validate the schema, CHOICE-arm resolution on TaggedRequest, IMPLICIT
 * tagging, or OPTIONAL field ordering -- a structurally plausible message with the wrong arm would
 * pass here. Treat it as a real but WEAK oracle: it is the strongest one available without a second
 * package, not a conformance check. A format-aware oracle (Bouncy Castle's asn1.cmc, which resolves
 * the arms and can also PRODUCE a PKIResponse) belongs beside it, not replaced by it.
 *
 * The OID table is the same story: it names RFC 5272's original id-cmc controls (statusInfo,
 * transactionId, senderNonce, recipientNonce, popLinkRandom) and both id-cct content types, but
 * NONE of RFC 6402's later additions (the 30..37 range, which includes identityProofV2). So this
 * is silent about the V2 controls -- not evidence either way about those.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var nodeCrypto = require("node:crypto");

// The SignerInfo signature, verified WITHOUT the toolkit's CMS verifier. RFC 5652 sec. 5.4: what
// is signed is the signedAttrs re-tagged from its [0] IMPLICIT wire form to a universal SET OF.
function signedAttrsVerify(der, spki, keyType) {
  var si = pki.schema.cms.parse(der).signerInfos[0];
  var attrs = si.signedAttrsBytes;
  var region = Buffer.concat([Buffer.from([0x31]), attrs.subarray(1)]);   // [0] IMPLICIT -> SET
  var pub = nodeCrypto.createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
  var sig = Buffer.from(si.signature);
  if (keyType === "rsa" || keyType === "rsa-pss") return nodeCrypto.verify("sha256", region, pub, sig);
  if (keyType === "ec-p256") return nodeCrypto.verify("sha256", region, pub, sig);
  return nodeCrypto.verify(null, region, pub, sig);   // EdDSA / ML-DSA are one-shot
}

// OpenSSL's dump of the CARRIER, plus its dump of the encapsulated CMC content.
//
// The second half is the point. asn1parse shows the eContent as an opaque hex blob, so a
// top-level dump proves only that the CMS envelope is well-formed -- the PKIData inside it
// would go unread. `-strparse <offset>` makes OpenSSL descend into that octet string and walk
// the PKIData itself: the four sequences, the tagged request, the embedded PKCS#10. The offset
// is taken from OpenSSL's OWN dump rather than from the toolkit's parser, so the toolkit never
// tells the oracle where to look.
function opensslDump(p) {
  var top = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p], { allowNonZero: true });
  var out = String(top.stdout || "");
  var lines = out.split(/\r?\n/);
  var inner = "", innerCode = null;
  for (var i = 0; i < lines.length; i++) {
    if (!/id-cct-PKI(Data|Response)/.test(lines[i])) continue;
    for (var j = i + 1; j < lines.length && j < i + 4; j++) {
      var m = /^\s*(\d+):.*OCTET STRING/.exec(lines[j]);
      if (!m) continue;
      var t2 = ctx.runOpenssl(["asn1parse", "-inform", "DER", "-in", p, "-strparse", m[1]],
        { allowNonZero: true });
      innerCode = t2.code;
      inner = String(t2.stdout || "");
      break;
    }
    break;
  }
  return { code: top.code, out: out, innerCode: innerCode, inner: inner };
}

async function run() {
  var arms = ["rsa", "ec-p256", "ed25519"];
  if (ctx.opensslSupports("ML-DSA")) arms.push("ml-dsa-65");

  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var s = signing.makeSigner(alg);
    var csr = await pki.csr.sign(
      { subject: alg + ".device.example", subjectPublicKey: s.spki }, { key: s.key });

    // A request carrying the controls OpenSSL's OID table knows, so the dump can be checked for
    // them by name rather than by offset.
    var der = await pki.cmc.build({
      requests: [{ tcr: csr }],
      transactionId: 1000 + i,
      senderNonce: Buffer.alloc(16, 0x5a),
    }, { cert: s.cert, key: s.key });

    ctx.withTmp(Buffer.from(der), "cmc-req-" + alg + ".der", function (p) {
      var d = opensslDump(p);
      check("openssl asn1parse structurally accepts the toolkit-issued " + alg + " Full PKI Request",
        d.code === 0);
      // The content type, named by OpenSSL's table -- an independent implementation agreeing
      // these bytes are a CMC PKIData, not merely that they parse.
      check("openssl names the encapsulated content type id-cct-PKIData (" + alg + ")",
        /id-cct-PKIData/.test(d.out));
      // The CMS carrier itself is a shape OpenSSL fully understands.
      check("openssl names the CMS SignedData carrier (" + alg + ")",
        /pkcs7-signedData/.test(d.out));
      // ...and it walks the PKIData INSIDE the envelope, not just around it.
      check("openssl parses the encapsulated PKIData itself (" + alg + ")", d.innerCode === 0);
      check("openssl names the Transaction Identifier control inside it (" + alg + ")",
        /id-cmc-transactionId/.test(d.inner));
      check("openssl names the Sender Nonce control inside it (" + alg + ")",
        /id-cmc-senderNonce/.test(d.inner));
      // The embedded PKCS#10 is read by the same independent decoder, through two
      // layers of encapsulation -- the strongest structural claim available here.
      check("openssl reads the embedded certification request's subject (" + alg + ")",
        /commonName/.test(d.inner) && new RegExp(alg + "\\.device\\.example").test(d.inner));
    });

    check(alg + " Full PKI Request round-trips through the strict parser",
      pki.schema.cmc.parse(der).kind === "pkiData");
    check(alg + " SignerInfo signature verifies under node:crypto, outside the toolkit's verifier",
      signedAttrsVerify(der, s.spki, alg) === true);
  }

  // The response direction: a PKIResponse the toolkit signs is read the same way.
  var r = signing.makeSigner("ec-p256");
  var b = pki.asn1.build;
  var body = b.sequence([b.sequence([]), b.sequence([]), b.sequence([])]);
  var respDer = await pki.cms.sign(body, { cert: r.cert, key: r.key },
    { eContentType: "id-cct-PKIResponse" });
  ctx.withTmp(Buffer.from(respDer), "cmc-resp.der", function (p) {
    var d = opensslDump(p);
    check("openssl asn1parse structurally accepts a toolkit-issued Full PKI Response", d.code === 0);
    check("openssl names the encapsulated content type id-cct-PKIResponse",
      /id-cct-PKIResponse/.test(d.out));
    check("openssl parses the encapsulated PKIResponse itself", d.innerCode === 0);
  });
  check("the Full PKI Response round-trips through the strict parser",
    pki.schema.cmc.parse(respDer).kind === "pkiResponse");
  check("its SignerInfo signature verifies under node:crypto",
    signedAttrsVerify(respDer, r.spki, "ec-p256") === true);

  // A flipped signature byte fails the independent verify -- which is what makes the passing
  // checks above mean something.
  var t = signing.makeSigner("ec-p256");
  var tcsr = await pki.csr.sign({ subject: "tamper.example", subjectPublicKey: t.spki }, { key: t.key });
  var good = await pki.cmc.build({ requests: [{ tcr: tcsr }] }, { cert: t.cert, key: t.key });
  check("the untampered Full PKI Request signature verifies",
    signedAttrsVerify(good, t.spki, "ec-p256") === true);
  var bad = Buffer.from(good);
  bad[bad.length - 1] ^= 0xff;
  check("a flipped signature byte fails the independent verify",
    signedAttrsVerify(bad, t.spki, "ec-p256") === false);

  // The other carrier RFC 5272 sec. 3.2 gives a Full PKI Request: an AuthenticatedData keyed by a
  // shared secret. OpenSSL has no CMC template either, but it does fully understand this CMS shape,
  // so the oracle here is stronger than the asn1parse dump above: `openssl cms -cmsout` accepts the
  // message as a CMS structure it recognizes, and the dump names the recipient kind sec. 3.2(a)
  // requires from OpenSSL's own OID table rather than from ours.
  var m = signing.makeSigner("ec-p256");
  var mcsr = await pki.csr.sign({ subject: "shared-secret.example", subjectPublicKey: m.spki }, { key: m.key });
  var macDer = await pki.cmc.build({ requests: [{ tcr: mcsr }] },
    { mac: { identifier: "cmc-client-17", secret: "a-shared-secret-at-least-16-chars" } });
  ctx.withTmp(Buffer.from(macDer), "cmc-req-authdata.der", function (p) {
    var d = opensslDump(p);
    check("openssl asn1parse structurally accepts the shared-secret Full PKI Request", d.code === 0);
    check("openssl names the AuthenticatedData carrier from its own table",
      /id-smime-ct-authData/.test(d.out));
    check("openssl names the encapsulated content type id-cct-PKIData on that carrier",
      /id-cct-PKIData/.test(d.out));
    // RFC 5272 sec. 3.2(a): the Password Recipient Info option, which OpenSSL names by its
    // key-encryption algorithm id-alg-PWRI-KEK.
    check("openssl names the password recipient's key-encryption algorithm",
      /id-alg-PWRI-KEK/.test(d.out) && /PBKDF2/.test(d.out));
    // The stronger half: a CMS-aware verb, not a generic DER dumper, reads the whole message.
    var cmsout = ctx.runOpenssl(["cms", "-cmsout", "-inform", "DER", "-in", p, "-noout"],
      { allowNonZero: true });
    check("openssl cms reads the shared-secret request as a CMS message", cmsout.code === 0);
  });
  check("the shared-secret Full PKI Request round-trips through the strict parser",
    pki.schema.cmc.parse(macDer).kind === "pkiData");

  // A request answering a challenge-response proof of possession (RFC 5272 sec. 6.7). The oracle here
  // is weaker than for the controls above and the difference is worth stating: OpenSSL's OID table
  // carries RFC 5272's original controls but NOT id-cmc-decryptedPOP, so it accepts and walks the
  // message without naming this control. What that establishes is that the message is well-formed CMS
  // carrying a well-formed PKIData, not that a second implementation agrees what the control is.
  var p = signing.makeSigner("ec-p256");
  var ppcsr = await pki.csr.sign({ subject: "pop.example", subjectPublicKey: p.spki }, { key: p.key });
  var proofValue = Buffer.alloc(48, 0x21);
  var envelope = await pki.cms.encrypt(proofValue, [{ cert: p.cert }],
    { contentEncryptionAlgorithm: "aes-256-cbc" });
  var challengeDer = pki.asn1.build.sequence([
    pki.asn1.build.contextConstructed(0,
      Buffer.concat([pki.asn1.build.integer(11n), ppcsr])),
    envelope,
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("hmacWithSHA256"))]),
    pki.asn1.build.sequence([pki.asn1.build.oid(pki.oid.byName("sha256"))]),
    pki.asn1.build.octetString(nodeCrypto.createHash("sha256").update(proofValue).digest()),
  ]);
  var popDer = await pki.cmc.build({ requests: [{ tcr: ppcsr }],
    popChallenge: { challenge: challengeDer, recipient: { key: p.key, cert: p.cert } } },
  { cert: p.cert, key: p.key });
  ctx.withTmp(Buffer.from(popDer), "cmc-req-pop.der", function (path2) {
    var d = opensslDump(path2);
    check("openssl asn1parse structurally accepts a request answering a POP challenge", d.code === 0);
    check("openssl names the encapsulated content type on that request too",
      /id-cct-PKIData/.test(d.out));
    check("openssl parses the encapsulated PKIData carrying the answer", d.innerCode === 0);
    var cmsout = ctx.runOpenssl(["cms", "-cmsout", "-inform", "DER", "-in", path2, "-noout"],
      { allowNonZero: true });
    check("openssl cms reads the answering request as a CMS message", cmsout.code === 0);
  });
  check("the answering request round-trips through the strict parser, control and all",
    pki.schema.cmc.parse(popDer).controls.some(function (c) { return !!c.decryptedPOP; }));
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
