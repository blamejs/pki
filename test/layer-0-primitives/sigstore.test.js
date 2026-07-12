// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.sigstore: Sigstore bundle (npm --provenance) verification.
 * Oracle: a REAL npm provenance bundle -- the toolkit's own @blamejs/pki@0.2.2
 * publish (npm registry attestations API) -- verified against the authoritative
 * public-good sigstore trust root (Fulcio CA chain + Rekor log key). This is a
 * dogfood end-to-end known-answer: the toolkit verifies its own supply chain.
 * The five legs (DSSE PAE + signature, Fulcio chain as-of log time, identity,
 * Rekor inclusion + signed root, in-toto subject) each pin a RED vector.
 */

var pki = require("../../index.js");
var helpers = require("../helpers");
var check = helpers.check;
var fs = require("fs");
var path = require("path");

var FX = path.join(__dirname, "..", "fixtures", "sigstore");
var BUNDLE = JSON.parse(fs.readFileSync(path.join(FX, "npm-provenance-bundle.json"), "utf8"));
var TRUST = JSON.parse(fs.readFileSync(path.join(FX, "trusted-root.json"), "utf8"));

// Extract the caller trust material from the public-good trusted_root.json: the
// Fulcio CA cert chains (DER) and the Rekor log public keys (SPKI DER + keyId).
function trustMaterial() {
  var fulcioRoots = [];
  (TRUST.certificateAuthorities || []).forEach(function (ca) {
    ((ca.certChain && ca.certChain.certificates) || []).forEach(function (c) {
      fulcioRoots.push(Buffer.from(c.rawBytes, "base64"));
    });
  });
  var rekorKeys = (TRUST.tlogs || []).map(function (t) {
    var vf = t.publicKey && t.publicKey.validFor;
    return {
      keyId: Buffer.from((t.logId && t.logId.keyId) || "", "base64"),
      spki: Buffer.from((t.publicKey && t.publicKey.rawBytes) || "", "base64"),
      keyDetails: t.publicKey && t.publicKey.keyDetails,
      validFor: vf ? { start: vf.start ? Date.parse(vf.start) : null, end: vf.end ? Date.parse(vf.end) : null } : undefined,
    };
  });
  return { fulcioRoots: fulcioRoots, rekorKeys: rekorKeys };
}

function codeOf(p) { return p.then(function () { return "NO-THROW"; }, function (e) { return e.code || e.message; }); }

async function run() {
  var TM = trustMaterial();

  // --- PAE exactness (the highest-value unit; a LEN-over-base64 or missing-SP
  // bug is a silent verify bypass). Hand-computed against the DSSE spec example. ---
  var pae = pki.sigstore.pae("http://example.com/HelloWorld", Buffer.from("hello world"));
  var expected = Buffer.concat([
    Buffer.from("DSSEv1 29 http://example.com/HelloWorld 11 ", "ascii"),
    Buffer.from("hello world", "ascii"),
  ]);
  check("PAE byte-exact (DSSE protocol.md worked example)", Buffer.isBuffer(pae) && pae.equals(expected));

  // --- parseBundle: accept the real bundle; reject malformed / oversize / bad version ---
  var parsed = pki.sigstore.parseBundle(BUNDLE);
  check("parseBundle accepts the real v0.3 bundle", parsed && parsed.mediaType.indexOf("v0.3") >= 0 && !!parsed.dsseEnvelope);
  check("parseBundle rejects a non-object", await codeOf(Promise.resolve().then(function () { return pki.sigstore.parseBundle("not json"); })) === "sigstore/bad-bundle" || (function () { try { pki.sigstore.parseBundle(42); return false; } catch (e) { return e.code === "sigstore/bad-bundle"; } })());
  check("parseBundle rejects an unknown media type", (function () { var b = JSON.parse(JSON.stringify(BUNDLE)); b.mediaType = "application/x.bogus"; try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-bundle-version"; } })());
  // An unsupported bundle version (a v0.x we do not actually verify) must reject,
  // recognize-and-defer, not be accepted by an over-broad media-type match.
  check("parseBundle rejects an unsupported bundle version", (function () { var b = JSON.parse(JSON.stringify(BUNDLE)); b.mediaType = "application/vnd.dev.sigstore.bundle.v0.9+json"; try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-bundle-version"; } })());

  // --- Full verify against the real trust root -> a structured verified verdict ---
  var v = await pki.sigstore.verifyBundle(BUNDLE, TM);
  check("verifyBundle: the real bundle verifies (all legs)", v && v.verified === true);
  check("verifyBundle surfaces the in-toto subject digest", v && v.subjects && v.subjects.length >= 1 && /^[0-9a-f]{64,128}$/.test(v.subjects[0].digest.sha512 || v.subjects[0].digest.sha256 || ""));
  check("verifyBundle surfaces the SLSA predicateType", v && v.predicateType === "https://slsa.dev/provenance/v1");
  // The verified payload bytes are surfaced RAW (never a re-serialization).
  check("verified payload bytes equal the decoded envelope payload", v && Buffer.isBuffer(v.payload) && v.payload.equals(Buffer.from(BUNDLE.dsseEnvelope.payload, "base64")));

  // --- DSSE reject: a flipped signature byte must not verify ---
  var flipped = JSON.parse(JSON.stringify(BUNDLE));
  var sig = Buffer.from(flipped.dsseEnvelope.signatures[0].sig, "base64"); sig[10] ^= 1;
  flipped.dsseEnvelope.signatures[0].sig = sig.toString("base64");
  check("DSSE flipped signature -> sigstore/dsse-verify-failed", await codeOf(pki.sigstore.verifyBundle(flipped, TM)) === "sigstore/dsse-verify-failed");

  // --- Rekor inclusion reject: a flipped proof hash must not reconstruct the root ---
  var badRekor = JSON.parse(JSON.stringify(BUNDLE));
  var h = Buffer.from(badRekor.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0], "base64"); h[0] ^= 1;
  badRekor.verificationMaterial.tlogEntries[0].inclusionProof.hashes[0] = h.toString("base64");
  check("Rekor flipped proof hash -> sigstore/inclusion-proof-mismatch", await codeOf(pki.sigstore.verifyBundle(badRekor, TM)) === "sigstore/inclusion-proof-mismatch");

  // --- Ephemeral-cert-as-of-log-time: the Fulcio cert (10-min validity) is valid
  // at integratedTime but expired at a far-future "now" -> reject with an override. ---
  check("Fulcio cert rejected when checked far after the log time", (await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({}, TM, { time: new Date("2030-01-01T00:00:00Z") })))).indexOf("sigstore/") === 0);

  // --- Identity: the SAN + Fulcio issuer/source surface; a policy match accepts,
  // a mismatch rejects (the core of Sigstore identity verification). ---
  check("identity surfaces the SAN URI + OIDC issuer + source repo", v && v.identity.san.type === "uri" &&
    /github\.com\/blamejs\/pki/.test(v.identity.san.value) &&
    v.identity.extensions.issuer === "https://token.actions.githubusercontent.com" &&
    v.identity.extensions.sourceRepositoryURI === "https://github.com/blamejs/pki");
  var goodPolicy = { san: v.identity.san.value, issuer: "https://token.actions.githubusercontent.com" };
  var vp = await pki.sigstore.verifyBundle(BUNDLE, Object.assign({ identity: goodPolicy }, TM));
  check("identity policy match -> verified", vp && vp.verified === true);
  check("identity policy mismatch -> sigstore/identity-mismatch",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({ identity: { san: "https://evil.example/attacker" } }, TM))) === "sigstore/identity-mismatch");

  // --- Unsigned-root: corrupt the checkpoint signature AND drop the SET -> the
  // reconstructed root is not attested by the Rekor key (an attacker-computed root
  // is not trust). ---
  var noRoot = JSON.parse(JSON.stringify(BUNDLE));
  var ipn = noRoot.verificationMaterial.tlogEntries[0];
  ipn.inclusionProof.checkpoint.envelope = ipn.inclusionProof.checkpoint.envelope.replace(/wNI9aj/, "wNI9ZZ");
  delete ipn.inclusionPromise;
  check("unsigned tree root -> sigstore/unsigned-root", await codeOf(pki.sigstore.verifyBundle(noRoot, TM)) === "sigstore/unsigned-root");

  // --- Attested time: the integratedTime that dates the ephemeral Fulcio cert is
  // signed by the SET, never by the checkpoint (which signs only the tree root).
  // A bundle with a valid checkpoint but no verifiable SET cannot establish a
  // Rekor-attested time and must reject (the RFC 3161 alternative is deferred). ---
  var noSet = JSON.parse(JSON.stringify(BUNDLE));
  delete noSet.verificationMaterial.tlogEntries[0].inclusionPromise;
  check("checkpoint-only, no SET -> sigstore/unattested-time", await codeOf(pki.sigstore.verifyBundle(noSet, TM)) === "sigstore/unattested-time");

  // --- Entry-binds-this-signature: tamper the Rekor entry's embedded signature so
  // it no longer matches the envelope -> reject (a valid inclusion proof for a
  // DIFFERENT entry is not evidence for this signature). ---
  var mism = JSON.parse(JSON.stringify(BUNDLE));
  var te = mism.verificationMaterial.tlogEntries[0];
  var body = JSON.parse(Buffer.from(te.canonicalizedBody, "base64").toString("utf8"));
  var s = Buffer.from(body.spec.signatures[0].signature, "base64"); s[5] ^= 1;
  body.spec.signatures[0].signature = s.toString("base64");
  te.canonicalizedBody = Buffer.from(JSON.stringify(body)).toString("base64");
  check("tlog entry not binding this signature -> sigstore/entry-mismatch", await codeOf(pki.sigstore.verifyBundle(mism, TM)) === "sigstore/entry-mismatch");

  // --- Trust-anchor bypass: a bundle that supplies its OWN full certificate
  // chain must NOT be verifiable against an empty caller trust set. The anchor
  // must come from opts.fulcioRoots, never from a bundle-supplied cert (else an
  // attacker ships a self-signed chain and verifies against their own root). ---
  var selfAnchored = JSON.parse(JSON.stringify(BUNDLE));
  var leafB64 = selfAnchored.verificationMaterial.certificate.rawBytes;
  var caChain = TM.fulcioRoots.map(function (d) { return { rawBytes: d.toString("base64") }; });
  delete selfAnchored.verificationMaterial.certificate;
  selfAnchored.verificationMaterial.x509CertificateChain = { certificates: [{ rawBytes: leafB64 }].concat(caChain) };
  check("bundle-supplied chain + empty caller trust -> rejected",
    (await codeOf(pki.sigstore.verifyBundle(selfAnchored, { fulcioRoots: [], rekorKeys: TM.rekorKeys }))).indexOf("sigstore/") === 0);

  // --- The Rekor entry must be bound to THIS leaf cert: a valid inclusion proof
  // whose embedded verifier certificate is a DIFFERENT cert must reject. ---
  var wrongVerifier = JSON.parse(JSON.stringify(BUNDLE));
  var wte = wrongVerifier.verificationMaterial.tlogEntries[0];
  var wbody = JSON.parse(Buffer.from(wte.canonicalizedBody, "base64").toString("utf8"));
  var otherPem = "-----BEGIN CERTIFICATE-----\n" + TM.fulcioRoots[0].toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----\n";
  wbody.spec.signatures[0].verifier = Buffer.from(otherPem).toString("base64");
  wte.canonicalizedBody = Buffer.from(JSON.stringify(wbody)).toString("base64");
  check("Rekor entry verifier != leaf cert -> sigstore/entry-mismatch", await codeOf(pki.sigstore.verifyBundle(wrongVerifier, TM)) === "sigstore/entry-mismatch");

  // --- Trust-root validity windows: a Rekor key whose validFor window does not
  // contain the entry's integratedTime must not be used (a rotated-out key). ---
  var narrowKeys = TM.rekorKeys.map(function (k) { return Object.assign({}, k, { validFor: { start: 0, end: 1 } }); });
  check("Rekor key outside its validFor window -> rejected", (await codeOf(pki.sigstore.verifyBundle(BUNDLE, { fulcioRoots: TM.fulcioRoots, rekorKeys: narrowKeys }))).indexOf("sigstore/") === 0);

  // --- A message_signature content arm (non-DSSE) is a recognize-and-defer. ---
  check("message_signature arm -> sigstore/unsupported-content", (function () { var b = JSON.parse(JSON.stringify(BUNDLE)); delete b.dsseEnvelope; b.messageSignature = { messageDigest: { algorithm: "SHA2_256", digest: "" }, signature: "" }; try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/unsupported-content"; } })());

  // --- Malformed-but-structurally-shaped fields must fail closed with a typed
  // sigstore/* error, never a raw TypeError escaping the contract (a null array
  // element or a non-object JSON value where an object is required). ---
  check("dsseEnvelope.signatures[null] -> sigstore/bad-dsse", (function () { var b = JSON.parse(JSON.stringify(BUNDLE)); b.dsseEnvelope.signatures = [null]; try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-dsse"; } })());
  var nullCert = JSON.parse(JSON.stringify(BUNDLE));
  delete nullCert.verificationMaterial.certificate;
  nullCert.verificationMaterial.x509CertificateChain = { certificates: [null] };
  check("x509CertificateChain.certificates[null] -> sigstore/bad-bundle", await codeOf(pki.sigstore.verifyBundle(nullCert, TM)) === "sigstore/bad-bundle");
  var nullBody = JSON.parse(JSON.stringify(BUNDLE));
  nullBody.verificationMaterial.tlogEntries[0].canonicalizedBody = Buffer.from("null").toString("base64");
  check("canonicalizedBody = null -> sigstore/bad-tlog-entry", await codeOf(pki.sigstore.verifyBundle(nullBody, TM)) === "sigstore/bad-tlog-entry");
  var nullEntry = JSON.parse(JSON.stringify(BUNDLE));
  nullEntry.verificationMaterial.tlogEntries = [null];
  check("tlogEntries[null] -> typed sigstore error", (await codeOf(pki.sigstore.verifyBundle(nullEntry, TM))).indexOf("sigstore/") === 0);
  // A tampered integratedTime is caught by the SET, which signs it -- the rebuilt
  // canonical JSON no longer matches Rekor's signature (never a leaked constants error).
  var badTime = JSON.parse(JSON.stringify(BUNDLE));
  badTime.verificationMaterial.tlogEntries[0].integratedTime = {};
  check("tampered integratedTime -> rejected via the SET (sigstore/*, not a raw/leaked error)", (await codeOf(pki.sigstore.verifyBundle(badTime, TM))).indexOf("sigstore/") === 0);

  // --- Input coercion: a non-object bundle is a config-time TypeError ---
  check("verifyBundle(non-object) -> TypeError", await (pki.sigstore.verifyBundle(42, TM).then(function () { return "NO"; }, function (e) { return e instanceof TypeError ? "TypeError" : (e.code || "other"); })) === "TypeError");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
