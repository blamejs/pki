// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- CMS countersignature (pki.cms.countersign) cross-implementation interop.
 *
 * OpenSSL's `cms` CLI has NO countersign operation (`-sign` / `-verify` / `-resign` only; `-resign`
 * adds a PEER SignerInfo, not an RFC 5652 sec. 11.4 countersignature), so "openssl countersigns, we
 * verify" is not achievable. Instead OpenSSL is the INDEPENDENT ORACLE for the two things that matter:
 *
 *  Gate A (structural) -- a SignedData we sign then countersign is a well-formed CMS structure OpenSSL
 *    parses (`openssl cms -cmsout -noout -print`), so the splice never produces malformed DER.
 *  Gate B (the sec. 11.4 preimage) -- the countersignature's OWN signature verifies under OpenSSL
 *    (`openssl dgst -verify` for RSA/ECDSA, `openssl pkeyutl -verify -rawin` for EdDSA) over the EXACT
 *    sec. 11.4 preimage (the countersigned signature octets directly when attr-less, or the re-tagged
 *    SignedAttributes SET OF when signed-attrs present). This independently confirms the #1 fragile
 *    area -- that a countersignature signs the countersigned SIGNATURE VALUE, not the content. A
 *    tampered preimage is REJECTED.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var signing = require("../helpers/signing");
var schemaCms = require("../../lib/schema-cms");

var CONTENT = Buffer.from("CMS countersignature interop content");
function O(n) { return pki.oid.byName(n); }

// The primary signature octets + the (single) countersignature SignerInfo of a countersigned output.
function extract(outDer) {
  var si = pki.schema.cms.parse(outDer).signerInfos[0];
  var attr = (si.unsignedAttrs || []).filter(function (a) { return a.type === O("countersignature"); })[0];
  var csDer = Buffer.from(attr.values[0].bytes || attr.values[0]);
  var csSi = schemaCms.walkCountersignature(pki.asn1.decode(csDer));
  return { primarySig: Buffer.from(si.signature), csSi: csSi };
}

// The exact sec. 11.4 preimage the countersignature covers.
function preimageOf(csSi, primarySig) {
  if (!csSi.signedAttrsBytes) return primarySig;         // attr-less: the countersigned signature octets
  var reTagged = Buffer.from(csSi.signedAttrsBytes);
  reTagged[0] = 0x31;                                    // [0] IMPLICIT -> universal SET OF
  return reTagged;
}

// Verify a countersignature's signature under OpenSSL over `preimage`, returning { code, stdout }.
function opensslVerify(alg, spkiDer, preimage, sig, digestName) {
  var pubPem = ctx.runOpenssl(["pkey", "-pubin", "-inform", "DER", "-in", ctx.tmpFile(spkiDer, "cspub.der")]);
  var pubPath = ctx.tmpFile(Buffer.from(pubPem, "utf8"), "cspub.pem");
  var prePath = ctx.tmpFile(preimage, "preimage.bin");
  var sigPath = ctx.tmpFile(sig, "cssig.bin");
  try {
    if (alg === "ed25519" || alg === "ed448") {
      return ctx.runOpenssl(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pubPath, "-sigfile", sigPath, "-in", prePath], { allowNonZero: true });
    }
    return ctx.runOpenssl(["dgst", "-" + digestName, "-verify", pubPath, "-signature", sigPath, prePath], { allowNonZero: true });
  } finally {
    [pubPath, prePath, sigPath].forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } });
  }
}

async function run() {
  var base = signing.makeSigner("ec-p256");
  var baseSigner = { cert: base.cert, key: base.key };

  // Gate A (structural): a countersigned SignedData is a well-formed CMS structure OpenSSL parses.
  var g = await pki.cms.countersign(await pki.cms.sign(CONTENT, baseSigner, {}), { cert: base.cert, key: base.key }, {});
  var gPath = ctx.tmpFile(g, "countersigned.der");
  try {
    var printed = ctx.runOpenssl(["cms", "-cmsout", "-noout", "-print", "-inform", "DER", "-in", gPath], { allowNonZero: true });
    check("Gate A: openssl parses our countersigned SignedData", printed.code === 0);
  } finally { try { ctx.fs.unlinkSync(gPath); } catch (_e) { /* best-effort */ } }

  // Gate B: the countersignature's OWN signature verifies under OpenSSL over the exact sec. 11.4 preimage.
  var arms = ["rsa", "ec-p256", "ec-p384", "ed25519"];
  for (var i = 0; i < arms.length; i++) {
    var alg = arms[i];
    var cs = signing.makeSigner(alg);
    var signer = { cert: cs.cert, key: cs.key };

    // attr-less: the signature is over the countersigned signature octets DIRECTLY.
    var base1 = await pki.cms.sign(CONTENT, baseSigner, {});
    var outNo = await pki.cms.countersign(base1, signer, { signedAttributes: false });
    var e1 = extract(outNo);
    var pre1 = preimageOf(e1.csSi, e1.primarySig);
    var r1 = opensslVerify(alg, cs.spki, pre1, e1.csSi.signature, e1.csSi.digestAlgorithm.name);
    check("Gate B " + alg + " (attr-less): openssl verifies the countersignature over the primary signature octets", r1.code === 0 && (/Verified OK|Signature Verified Successfully/.test(r1.stdout) || alg.indexOf("ed") === 0));

    // signed-attrs: the signature is over the re-tagged SignedAttributes SET OF.
    var base2 = await pki.cms.sign(CONTENT, baseSigner, {});
    var outAttr = await pki.cms.countersign(base2, signer, {});
    var e2 = extract(outAttr);
    var pre2 = preimageOf(e2.csSi, e2.primarySig);
    var r2 = opensslVerify(alg, cs.spki, pre2, e2.csSi.signature, e2.csSi.digestAlgorithm.name);
    check("Gate B " + alg + " (signed-attrs): openssl verifies the countersignature over the SignedAttributes preimage", r2.code === 0 && (/Verified OK|Signature Verified Successfully/.test(r2.stdout) || alg.indexOf("ed") === 0));

    // negative: a countersignature over the WRONG preimage (the eContent) is REJECTED by openssl.
    var rBad = opensslVerify(alg, cs.spki, CONTENT, e1.csSi.signature, e1.csSi.digestAlgorithm.name);
    check("Gate B " + alg + ": openssl rejects the countersignature over the wrong bytes (the content)", rBad.code !== 0);
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
