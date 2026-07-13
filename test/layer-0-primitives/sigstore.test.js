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
var crypto = require("crypto");
var merkle = require("../../lib/merkle");

var FX = path.join(__dirname, "..", "fixtures", "sigstore");
var BUNDLE = JSON.parse(fs.readFileSync(path.join(FX, "npm-provenance-bundle.json"), "utf8"));
var TRUST = JSON.parse(fs.readFileSync(path.join(FX, "trusted-root.json"), "utf8"));

// Extract the caller trust material from the public-good trusted_root.json: the
// Fulcio CA cert chains (DER) and the Rekor log public keys (SPKI DER + keyId).
function trustMaterial() {
  // Pass the trusted_root validFor windows through VERBATIM (ISO-8601 strings) --
  // the toolkit must parse them; a caller pins trust material as it comes.
  var fulcioRoots = [];
  (TRUST.certificateAuthorities || []).forEach(function (ca) {
    ((ca.certChain && ca.certChain.certificates) || []).forEach(function (c) {
      fulcioRoots.push({ der: Buffer.from(c.rawBytes, "base64"), validFor: ca.validFor });
    });
  });
  var rekorKeys = (TRUST.tlogs || []).map(function (t) {
    return {
      keyId: Buffer.from((t.logId && t.logId.keyId) || "", "base64"),
      spki: Buffer.from((t.publicKey && t.publicKey.rawBytes) || "", "base64"),
      keyDetails: t.publicKey && t.publicKey.keyDetails,
      validFor: t.publicKey && t.publicKey.validFor,
    };
  });
  return { fulcioRoots: fulcioRoots, rekorKeys: rekorKeys };
}

function codeOf(p) { return p.then(function () { return "NO-THROW"; }, function (e) { return e.code || e.message; }); }

// ---------------------------------------------------------------------------
// A fully-synthetic Sigstore bundle: a self-issued Fulcio CA + a caller-held
// Rekor log key + a single-leaf Merkle tree. Every signature is real (node
// crypto over the exact bytes each leg hashes), so verifyBundle runs all five
// legs genuinely. The real dogfood bundle's leaf certificate and DSSE payload
// are cryptographically pinned by the Rekor entry/checkpoint/SET, so the
// Fulcio-identity and in-toto-statement legs can only be exercised on a bundle
// whose Fulcio CA and Rekor key the test holds. The builder takes the SAN
// GeneralNames, the DSSE payloadType, and the in-toto payload so each identity
// / statement branch can be driven through the shipped verifyBundle entry point.
// ---------------------------------------------------------------------------
var B = pki.asn1.build;
function synOid(name) { return B.oid(pki.oid.byName(name)); }
function synAtv(name, val) { return B.sequence([synOid(name), B.utf8(val)]); }
function synName(cn) { return B.sequence([B.set([synAtv("commonName", cn)])]); }
function synExt(name, critical, valueDer) {
  var ch = [synOid(name)];
  if (critical) ch.push(B.boolean(true));
  ch.push(B.octetString(valueDer));
  return B.sequence(ch);
}
function synKuVal(bits) {
  var maxBit = Math.max.apply(null, bits);
  var buf = Buffer.alloc((maxBit >> 3) + 1);
  bits.forEach(function (p) { buf[p >> 3] |= (0x80 >> (p & 7)); });
  return B.bitString(buf, 7 - (maxBit & 7));
}
function gnUriDer(text) { return B.contextPrimitive(6, Buffer.from(text, "ascii")); }
var SYN_ALGID = B.sequence([synOid("ecdsaWithSHA256")]);
function synCert(o) {
  var spkiDer = o.subjectKey.export({ format: "der", type: "spki" });
  var tbsChildren = [B.explicit(0, B.integer(2n)), B.integer(o.serial), SYN_ALGID, synName(o.issuer),
    B.sequence([B.utcTime(o.notBefore), B.utcTime(o.notAfter)]), synName(o.subject), B.raw(spkiDer)];
  if (o.extensions && o.extensions.length) tbsChildren.push(B.explicit(3, B.sequence(o.extensions)));
  var tbs = B.sequence(tbsChildren);
  var sig = crypto.sign("sha256", tbs, { key: o.signerKey, dsaEncoding: "der" });
  return B.sequence([tbs, SYN_ALGID, B.bitString(sig, 0)]);
}
function synPem(der) { return "-----BEGIN CERTIFICATE-----\n" + der.toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "") + "\n-----END CERTIFICATE-----\n"; }
function buildSynBundle(opts) {
  opts = opts || {};
  var rootKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var leafKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var rekorKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2030-01-01T00:00:00Z");
  var integratedTime = Math.floor(new Date("2027-06-01T00:00:00Z").getTime() / 1000);
  var rootDer = synCert({ serial: 1n, issuer: "syn-root", subject: "syn-root", notBefore: NB, notAfter: NA,
    subjectKey: rootKp.publicKey, signerKey: rootKp.privateKey, extensions: [synExt("basicConstraints", true, B.sequence([B.boolean(true)])), synExt("keyUsage", true, synKuVal([5, 6]))] });
  var san = opts.san || [gnUriDer("https://github.com/synthetic/repo")];
  var leafDer = synCert({ serial: 2n, issuer: opts.leafIssuer || "syn-root", subject: "syn-leaf", notBefore: NB, notAfter: NA,
    subjectKey: leafKp.publicKey, signerKey: rootKp.privateKey,
    extensions: [synExt("keyUsage", true, synKuVal([0])), synExt("extKeyUsage", false, B.sequence([synOid("codeSigning")])), synExt("subjectAltName", false, B.sequence(san))] });
  var payloadType = opts.payloadType || "application/vnd.in-toto+json";
  var payloadObj = opts.payload !== undefined ? opts.payload
    : { _type: "https://in-toto.io/Statement/v1", predicateType: "https://slsa.dev/provenance/v1", subject: [{ name: "pkg", digest: { sha512: "ab".repeat(64) } }], predicate: {} };
  var payload = Buffer.from(JSON.stringify(payloadObj));
  var derSig = crypto.sign("sha256", pki.sigstore.pae(payloadType, payload), { key: leafKp.privateKey, dsaEncoding: "der" });
  var env = { payload: payload.toString("base64"), payloadType: payloadType, signatures: [{ sig: derSig.toString("base64") }] };
  var body = { apiVersion: "0.0.1", kind: "dsse", spec: { signatures: [{ signature: derSig.toString("base64"), verifier: Buffer.from(synPem(leafDer)).toString("base64") }],
    payloadHash: { algorithm: "sha256", value: crypto.createHash("sha256").update(payload).digest("hex") } } };
  var canonBuf = Buffer.from(JSON.stringify(body));
  var rootHash = merkle.leafHash(canonBuf);          // single-leaf tree: root == leaf hash
  var rekorSpki = rekorKp.publicKey.export({ format: "der", type: "spki" });
  var keyId = crypto.createHash("sha256").update(rekorSpki).digest();
  var logIndex = 1234;
  var cpBody = Buffer.from("rekor.local\n1\n" + rootHash.toString("base64") + "\n", "utf8");
  var cpSig = crypto.sign("sha256", cpBody, { key: rekorKp.privateKey, dsaEncoding: "der" });
  var cpBlob = Buffer.concat([keyId.subarray(0, 4), cpSig]);
  var cpEnvelope = cpBody.toString("utf8") + "\n" + String.fromCharCode(0x2014) + " rekor.local " + cpBlob.toString("base64") + "\n";
  var setCanon = JSON.stringify({ body: canonBuf.toString("base64"), integratedTime: integratedTime, logID: keyId.toString("hex"), logIndex: logIndex });
  var setSig = crypto.sign("sha256", Buffer.from(setCanon, "utf8"), { key: rekorKp.privateKey, dsaEncoding: "der" });
  var te = { logId: { keyId: keyId.toString("base64") }, integratedTime: integratedTime, logIndex: logIndex,
    inclusionPromise: { signedEntryTimestamp: setSig.toString("base64") },
    inclusionProof: { logIndex: 0, treeSize: 1, hashes: [], rootHash: rootHash.toString("base64"), checkpoint: { envelope: cpEnvelope } },
    canonicalizedBody: canonBuf.toString("base64") };
  // extraChain rides in the bundle x509CertificateChain (path steps only, never a
  // terminal anchor) so the chain-building walk can be driven with a cyclic or an
  // over-deep DN graph -- the leaf stays cert[0].
  var vmat = { tlogEntries: [te] };
  if (opts.extraChain && opts.extraChain.length) {
    vmat.x509CertificateChain = { certificates: [{ rawBytes: leafDer.toString("base64") }].concat(opts.extraChain.map(function (d) { return { rawBytes: d.toString("base64") }; })) };
  } else {
    vmat.certificate = { rawBytes: leafDer.toString("base64") };
  }
  var bundle = { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", verificationMaterial: vmat, dsseEnvelope: env };
  return { bundle: bundle, trust: { fulcioRoots: [{ der: rootDer }], rekorKeys: [{ keyId: keyId, spki: rekorSpki }] } };
}

// A structurally-parseable intermediate with the given subject/issuer DNs (a
// throwaway self-key; the chain-building walk inspects only DN linkage, never the
// signature, for these cases). Used to build cyclic / over-deep DN graphs.
function synChainCert(subject, issuer) {
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return synCert({ serial: 9n, issuer: issuer, subject: subject, notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2030-01-01T00:00:00Z"),
    subjectKey: kp.publicKey, signerKey: kp.privateKey, extensions: [synExt("basicConstraints", true, B.sequence([B.boolean(true)]))] });
}

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
  // The inclusion-proof root MUST be checkpoint-signed: a valid SET alone does not
  // attest the root the proof reconstructs, so a corrupted checkpoint rejects even
  // with a valid SET (the reconstructed root would otherwise be attacker-supplied).
  var noCheckpoint = JSON.parse(JSON.stringify(BUNDLE));
  noCheckpoint.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope =
    noCheckpoint.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope.replace(/wNI9aj/, "wNI9ZZ");
  check("valid SET but unsigned checkpoint root -> sigstore/unsigned-root", await codeOf(pki.sigstore.verifyBundle(noCheckpoint, TM)) === "sigstore/unsigned-root");

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
  var caChain = TM.fulcioRoots.map(function (d) { return { rawBytes: d.der.toString("base64") }; });
  delete selfAnchored.verificationMaterial.certificate;
  selfAnchored.verificationMaterial.x509CertificateChain = { certificates: [{ rawBytes: leafB64 }].concat(caChain) };
  check("bundle-supplied chain + empty caller trust -> rejected",
    (await codeOf(pki.sigstore.verifyBundle(selfAnchored, { fulcioRoots: [], rekorKeys: TM.rekorKeys }))).indexOf("sigstore/") === 0);

  // --- The Rekor entry must be bound to THIS leaf cert: a valid inclusion proof
  // whose embedded verifier certificate is a DIFFERENT cert must reject. ---
  var wrongVerifier = JSON.parse(JSON.stringify(BUNDLE));
  var wte = wrongVerifier.verificationMaterial.tlogEntries[0];
  var wbody = JSON.parse(Buffer.from(wte.canonicalizedBody, "base64").toString("utf8"));
  var otherPem = "-----BEGIN CERTIFICATE-----\n" + TM.fulcioRoots[0].der.toString("base64").replace(/(.{64})/g, "$1\n") + "\n-----END CERTIFICATE-----\n";
  wbody.spec.signatures[0].verifier = Buffer.from(otherPem).toString("base64");
  wte.canonicalizedBody = Buffer.from(JSON.stringify(wbody)).toString("base64");
  check("Rekor entry verifier != leaf cert -> sigstore/entry-mismatch", await codeOf(pki.sigstore.verifyBundle(wrongVerifier, TM)) === "sigstore/entry-mismatch");

  // --- Trust-root validity windows: a Rekor key whose validFor window does not
  // contain the entry's integratedTime must not be used (a rotated-out key). ---
  var narrowKeys = TM.rekorKeys.map(function (k) { return Object.assign({}, k, { validFor: { start: 0, end: 1 } }); });
  check("Rekor key outside its validFor window -> rejected", (await codeOf(pki.sigstore.verifyBundle(BUNDLE, { fulcioRoots: TM.fulcioRoots, rekorKeys: narrowKeys }))).indexOf("sigstore/") === 0);

  // --- A malformed leaf certificate fails closed as a typed sigstore/*, never a
  // raw certificate/* leak from the X.509 parser boundary. ---
  var badLeaf = JSON.parse(JSON.stringify(BUNDLE));
  badLeaf.verificationMaterial.certificate.rawBytes = Buffer.from("not a certificate").toString("base64");
  check("malformed leaf certificate -> sigstore/bad-certificate", await codeOf(pki.sigstore.verifyBundle(badLeaf, TM)) === "sigstore/bad-certificate");

  // --- Multiple transparency-log entries: a leading malformed / non-binding entry
  // must not sink the verify when a later entry fully verifies. ---
  var multiEntry = JSON.parse(JSON.stringify(BUNDLE));
  multiEntry.verificationMaterial.tlogEntries = [{ notAnEntry: true }].concat(multiEntry.verificationMaterial.tlogEntries);
  var me = await pki.sigstore.verifyBundle(multiEntry, TM);
  check("verify succeeds via a later tlog entry when the first is malformed", me && me.verified === true);

  // --- Fulcio CA validFor: an anchor whose trust-root validity window does not
  // contain the log time must not be used (a rotated-out CA). ---
  var expiredCA = TM.fulcioRoots.map(function (r) { return { der: r.der, validFor: { start: 0, end: 1 } }; });
  check("Fulcio anchor outside its validFor window -> sigstore/chain-incomplete", await codeOf(pki.sigstore.verifyBundle(BUNDLE, { fulcioRoots: expiredCA, rekorKeys: TM.rekorKeys })) === "sigstore/chain-incomplete");

  // --- Multiple caller anchors sharing a subject DN (the trusted_root carries
  // several Fulcio CA rotations) must all be tried, not just the last stored. ---
  var dupAnchors = TM.fulcioRoots.concat(TM.fulcioRoots);
  var dup = await pki.sigstore.verifyBundle(BUNDLE, { fulcioRoots: dupAnchors, rekorKeys: TM.rekorKeys });
  check("duplicate same-DN anchors still verify (all candidates tried)", dup && dup.verified === true);

  // --- Predicate pinning: opts.predicateType enforces the attestation kind, so a
  // non-SLSA in-toto statement is not accepted as the expected provenance. ---
  var vpred = await pki.sigstore.verifyBundle(BUNDLE, Object.assign({ predicateType: "https://slsa.dev/provenance/v1" }, TM));
  check("matching predicateType pin -> verified", vpred && vpred.verified === true);
  check("wrong predicateType pin -> sigstore/predicate-mismatch", await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({ predicateType: "https://example/sbom" }, TM))) === "sigstore/predicate-mismatch");

  // --- The Rekor dsse entry MUST carry its verifier certificate (bound to the
  // leaf); an entry with the verifier stripped is rejected, not accepted on the
  // signature match alone. ---
  var noVerifier = JSON.parse(JSON.stringify(BUNDLE));
  var nvte = noVerifier.verificationMaterial.tlogEntries[0];
  var nvbody = JSON.parse(Buffer.from(nvte.canonicalizedBody, "base64").toString("utf8"));
  delete nvbody.spec.signatures[0].verifier;
  nvte.canonicalizedBody = Buffer.from(JSON.stringify(nvbody)).toString("base64");
  check("Rekor entry without a verifier cert -> sigstore/bad-tlog-entry", await codeOf(pki.sigstore.verifyBundle(noVerifier, TM)) === "sigstore/bad-tlog-entry");

  // --- A caller may pin only the Fulcio ROOT while the intermediate rides in the
  // bundle chain: the caller cert anchors and the bundle intermediate is a path
  // link. Identify the root (self-issued) and intermediate among the trust certs. ---
  var parsedRoots = TM.fulcioRoots.map(function (r) { return { der: r.der, cert: pki.schema.x509.parse(r.der) }; });
  var leafCert = pki.schema.x509.parse(Buffer.from(BUNDLE.verificationMaterial.certificate.rawBytes, "base64"));
  var interCert = parsedRoots.filter(function (p) { return p.cert.subject.dn === leafCert.issuer.dn; })[0];
  // The trust set carries multiple self-signed roots sharing a DN (CA rotations);
  // pin all of them so the verifier picks the one that actually signed the chain.
  var rootCerts = parsedRoots.filter(function (p) { return p.cert.subject.dn === p.cert.issuer.dn; });
  if (interCert && rootCerts.length) {
    var rootOnly = JSON.parse(JSON.stringify(BUNDLE));
    var lb = rootOnly.verificationMaterial.certificate.rawBytes;
    delete rootOnly.verificationMaterial.certificate;
    rootOnly.verificationMaterial.x509CertificateChain = { certificates: [{ rawBytes: lb }, { rawBytes: interCert.der.toString("base64") }] };
    var ro = await pki.sigstore.verifyBundle(rootOnly, { fulcioRoots: rootCerts.map(function (p) { return { der: p.der }; }), rekorKeys: TM.rekorKeys });
    check("caller pins only the roots + bundle carries the intermediate -> verifies", ro && ro.verified === true);
  }

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

  // ===========================================================================
  // Adversarial edge / malformed-input coverage: every reject below drives the
  // shipped consumer path (parseBundle / verifyBundle / pae) with a hostile or
  // structurally-degenerate input and pins the exact fail-closed typed verdict.
  // ===========================================================================
  var cl = function () { return JSON.parse(JSON.stringify(BUNDLE)); };

  // --- parseBundle input-shape rejects (each is a distinct fail-closed arm) ---
  check("parseBundle(42) -> sigstore/bad-bundle", (function () { try { pki.sigstore.parseBundle(42); return false; } catch (e) { return e.code === "sigstore/bad-bundle"; } })());
  check("parseBundle(null) -> sigstore/bad-bundle", (function () { try { pki.sigstore.parseBundle(null); return false; } catch (e) { return e.code === "sigstore/bad-bundle"; } })());
  check("parseBundle([]) (array) -> sigstore/bad-bundle", (function () { try { pki.sigstore.parseBundle([]); return false; } catch (e) { return e.code === "sigstore/bad-bundle"; } })());
  check("parseBundle without mediaType -> sigstore/bad-bundle-version (none)", (function () { var b = cl(); delete b.mediaType; try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-bundle-version"; } })());
  check("parseBundle missing verificationMaterial -> sigstore/bad-bundle", (function () { var b = cl(); delete b.verificationMaterial; try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-bundle"; } })());
  check("parseBundle missing dsseEnvelope (no messageSignature) -> sigstore/bad-bundle", (function () { var b = cl(); delete b.dsseEnvelope; try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-bundle"; } })());

  // --- pae: a non-string payloadType is a config-time TypeError; a string /
  // null body coerces (LEN is always over the decoded body byte length). ---
  check("pae(non-string type) -> TypeError", (function () { try { pki.sigstore.pae(123, Buffer.from("x")); return false; } catch (e) { return e instanceof TypeError; } })());
  check("pae coerces a string body (LEN over decoded bytes)", pki.sigstore.pae("t", "hi").equals(Buffer.from("DSSEv1 1 t 2 hi", "ascii")));
  check("pae coerces a null body to empty", pki.sigstore.pae("t", null).equals(Buffer.from("DSSEv1 1 t 0 ", "ascii")));

  // --- base64 canonicality: a non-canonical re-encoding is an encoding-
  // malleability reject; a URL-safe (base64url) encoding of the SAME bytes is
  // accepted and still verifies end-to-end. ---
  var nonCanon = cl(); nonCanon.verificationMaterial.certificate.rawBytes = "QR==";
  check("non-canonical base64 leaf -> sigstore/bad-bundle", await codeOf(pki.sigstore.verifyBundle(nonCanon, TM)) === "sigstore/bad-bundle");
  var urlLeaf = cl();
  urlLeaf.verificationMaterial.certificate.rawBytes = urlLeaf.verificationMaterial.certificate.rawBytes.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  var uv = await pki.sigstore.verifyBundle(urlLeaf, TM);
  check("URL-safe base64 leaf (identical bytes) still verifies", uv && uv.verified === true);

  // --- Rekor SET selection: a non-string logId.keyId is a malformed bundle; a
  // well-formed keyId that matches no caller Rekor key leaves the log time
  // unattested (the SET, not the checkpoint, signs integratedTime). ---
  var kidNum = cl(); kidNum.verificationMaterial.tlogEntries[0].logId.keyId = 123;
  check("non-string logId.keyId -> sigstore/bad-bundle", await codeOf(pki.sigstore.verifyBundle(kidNum, TM)) === "sigstore/bad-bundle");
  var kidBad = cl(); kidBad.verificationMaterial.tlogEntries[0].logId.keyId = Buffer.alloc(32, 7).toString("base64");
  check("logId.keyId matching no Rekor key -> sigstore/unattested-time", await codeOf(pki.sigstore.verifyBundle(kidBad, TM)) === "sigstore/unattested-time");
  var setNum = cl(); setNum.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp = 123;
  check("non-string signedEntryTimestamp -> sigstore/unattested-time", await codeOf(pki.sigstore.verifyBundle(setNum, TM)) === "sigstore/unattested-time");

  // --- Checkpoint (C2SP signed note) parse: no separator, a root line that
  // disagrees with the inclusion-proof root, and a too-short signature blob that
  // is skipped while the real signature still verifies. ---
  var noSep = cl(); noSep.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = "no-separator-here";
  check("checkpoint with no note/signature separator -> sigstore/bad-checkpoint", await codeOf(pki.sigstore.verifyBundle(noSep, TM)) === "sigstore/bad-checkpoint");
  var cpRoot = cl();
  var cpip = cpRoot.verificationMaterial.tlogEntries[0].inclusionProof;
  var cplines = cpip.checkpoint.envelope.split("\n"); cplines[2] = Buffer.alloc(32).toString("base64"); cpip.checkpoint.envelope = cplines.join("\n");
  check("checkpoint root != inclusion-proof root -> sigstore/inclusion-proof-mismatch", await codeOf(pki.sigstore.verifyBundle(cpRoot, TM)) === "sigstore/inclusion-proof-mismatch");
  var shortSig = cl();
  var ssip = shortSig.verificationMaterial.tlogEntries[0].inclusionProof;
  ssip.checkpoint.envelope = ssip.checkpoint.envelope.replace("\n\n", "\n\n" + String.fromCharCode(0x2014) + " x AAAA\n");
  var ssv = await pki.sigstore.verifyBundle(shortSig, TM);
  check("a too-short checkpoint signature line is skipped, the real one verifies", ssv && ssv.verified === true);

  // --- Rekor entry binding (_bindEntry): a non-dsse kind, a missing payloadHash,
  // a payloadHash that disagrees with the envelope payload, and a verifier field
  // that is not a decodable certificate each fail closed. ---
  var kindBad = cl();
  (function () { var te = kindBad.verificationMaterial.tlogEntries[0]; var bo = JSON.parse(Buffer.from(te.canonicalizedBody, "base64").toString("utf8")); bo.kind = "hashedrekord"; te.canonicalizedBody = Buffer.from(JSON.stringify(bo)).toString("base64"); })();
  check("non-dsse Rekor entry kind -> sigstore/unsupported-content", await codeOf(pki.sigstore.verifyBundle(kindBad, TM)) === "sigstore/unsupported-content");
  var phMiss = cl();
  (function () { var te = phMiss.verificationMaterial.tlogEntries[0]; var bo = JSON.parse(Buffer.from(te.canonicalizedBody, "base64").toString("utf8")); delete bo.spec.payloadHash; te.canonicalizedBody = Buffer.from(JSON.stringify(bo)).toString("base64"); })();
  check("Rekor dsse entry missing payloadHash -> sigstore/bad-tlog-entry", await codeOf(pki.sigstore.verifyBundle(phMiss, TM)) === "sigstore/bad-tlog-entry");
  var phBad = cl();
  (function () { var te = phBad.verificationMaterial.tlogEntries[0]; var bo = JSON.parse(Buffer.from(te.canonicalizedBody, "base64").toString("utf8")); bo.spec.payloadHash.value = "00"; te.canonicalizedBody = Buffer.from(JSON.stringify(bo)).toString("base64"); })();
  check("Rekor entry payloadHash != envelope payload -> sigstore/entry-mismatch", await codeOf(pki.sigstore.verifyBundle(phBad, TM)) === "sigstore/entry-mismatch");
  var vg = cl();
  (function () { var te = vg.verificationMaterial.tlogEntries[0]; var bo = JSON.parse(Buffer.from(te.canonicalizedBody, "base64").toString("utf8")); bo.spec.signatures[0].verifier = Buffer.from("not a pem cert").toString("base64"); te.canonicalizedBody = Buffer.from(JSON.stringify(bo)).toString("base64"); })();
  check("Rekor entry verifier not a decodable certificate -> sigstore/bad-tlog-entry", await codeOf(pki.sigstore.verifyBundle(vg, TM)) === "sigstore/bad-tlog-entry");

  // --- Inclusion-proof fold: a non-numeric logIndex makes the Merkle fold throw;
  // the fault is re-typed to a sigstore/* verdict, never a raw leak. ---
  var mli = cl(); mli.verificationMaterial.tlogEntries[0].inclusionProof.logIndex = "not-a-number";
  check("non-numeric inclusionProof.logIndex -> sigstore/bad-inclusion-proof", await codeOf(pki.sigstore.verifyBundle(mli, TM)) === "sigstore/bad-inclusion-proof");

  // --- fulcioRoots normalization: an element that is neither a Buffer nor a
  // { der | rawBytes } object is a config-time bad-input; a bare DER Buffer
  // (no wrapper) is accepted and verifies. ---
  check("fulcioRoots element without der/rawBytes -> sigstore/bad-input", await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: [{ foo: 1 }], rekorKeys: TM.rekorKeys })) === "sigstore/bad-input");
  var rawRoots = await pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots.map(function (r) { return r.der; }), rekorKeys: TM.rekorKeys });
  check("bare DER Buffer fulcioRoots (no wrapper) still verify", rawRoots && rawRoots.verified === true);

  // --- Missing material: no Fulcio certificate at all, no transparency-log
  // entries, and a non-array tlogEntries each fail closed. ---
  var noCert = cl(); delete noCert.verificationMaterial.certificate;
  check("bundle with no Fulcio certificate -> sigstore/bad-bundle", await codeOf(pki.sigstore.verifyBundle(noCert, TM)) === "sigstore/bad-bundle");
  var noTlog = cl(); delete noTlog.verificationMaterial.tlogEntries;
  check("keyless bundle without tlogEntries -> sigstore/bad-bundle", await codeOf(pki.sigstore.verifyBundle(noTlog, TM)) === "sigstore/bad-bundle");
  var badTlog = cl(); badTlog.verificationMaterial.tlogEntries = "nope";
  check("non-array tlogEntries -> sigstore/bad-bundle", await codeOf(pki.sigstore.verifyBundle(badTlog, TM)) === "sigstore/bad-bundle");

  // --- verifyBundle with no opts falls back to empty trust material and fails
  // closed (never accepts on missing trust). ---
  check("verifyBundle without opts fails closed (empty trust)", (await codeOf(pki.sigstore.verifyBundle(cl()))).indexOf("sigstore/") === 0);

  // --- Identity policy: the OIDC issuer and the source-repository URI each gate
  // independently; a mismatch rejects, the correct source URI accepts. ---
  check("identity issuer mismatch -> sigstore/identity-mismatch", await codeOf(pki.sigstore.verifyBundle(cl(), Object.assign({ identity: { issuer: "https://evil.example" } }, TM))) === "sigstore/identity-mismatch");
  check("identity sourceRepositoryURI mismatch -> sigstore/identity-mismatch", await codeOf(pki.sigstore.verifyBundle(cl(), Object.assign({ identity: { sourceRepositoryURI: "https://evil.example" } }, TM))) === "sigstore/identity-mismatch");
  var srcOk = await pki.sigstore.verifyBundle(cl(), Object.assign({ identity: { sourceRepositoryURI: "https://github.com/blamejs/pki" } }, TM));
  check("identity sourceRepositoryURI match -> verified", srcOk && srcOk.verified === true);

  // --- Trust-material faults: a Rekor key with an unparseable SPKI is a typed
  // bad-key; the leaf cert pinned as the sole anchor yields no path. ---
  check("malformed Rekor key SPKI -> sigstore/bad-key", await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots, rekorKeys: TM.rekorKeys.map(function (k) { return Object.assign({}, k, { spki: Buffer.from("garbage") }); }) })) === "sigstore/bad-key");
  var leafDerX = Buffer.from(BUNDLE.verificationMaterial.certificate.rawBytes, "base64");
  check("leaf cert pinned as the only anchor (no path) -> sigstore/chain-incomplete", await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: [{ der: leafDerX }], rekorKeys: TM.rekorKeys })) === "sigstore/chain-incomplete");

  // --- validFor bound parsing (_toMs): a present-but-unparseable window bound
  // (NaN / non-ISO string / object / invalid Date) fails closed rather than
  // silently disabling the window; a valid Date-instance window is honored. ---
  var keyWin = function (vf) { return TM.rekorKeys.map(function (k) { return Object.assign({}, k, { validFor: vf }); }); };
  check("Rekor key validFor start=NaN fails closed", (await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots, rekorKeys: keyWin({ start: NaN }) }))).indexOf("sigstore/") === 0);
  check("Rekor key validFor start=non-ISO string fails closed", (await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots, rekorKeys: keyWin({ start: "not-a-date" }) }))).indexOf("sigstore/") === 0);
  check("Rekor key validFor start=object fails closed", (await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots, rekorKeys: keyWin({ start: {} }) }))).indexOf("sigstore/") === 0);
  check("Rekor key validFor start=invalid Date fails closed", (await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots, rekorKeys: keyWin({ start: new Date("nope") }) }))).indexOf("sigstore/") === 0);
  var dateWin = await pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots, rekorKeys: keyWin({ start: new Date(0), end: new Date("2100-01-01T00:00:00Z") }) });
  check("Rekor key validFor as Date instances (in window) verifies", dateWin && dateWin.verified === true);

  // ===========================================================================
  // _rawVerify algorithm dispatch, SET keyId absence, and the path-validation
  // throw arm -- driven on the REAL bundle with crafted trust material.
  // ===========================================================================

  // A Rekor key selected for the checkpoint (its keyId's first four bytes equal
  // the checkpoint keyhint) but of a key TYPE/curve other than the log's drives
  // the _rawVerify hash / EdDSA dispatch; the signature cannot verify, so the
  // reconstructed tree root is unattested and the bundle fails closed.
  var logIdBuf = Buffer.from(BUNDLE.verificationMaterial.tlogEntries[0].logId.keyId, "base64");
  function spkiOf(kind, opt) { return crypto.generateKeyPairSync(kind, opt).publicKey.export({ format: "der", type: "spki" }); }
  function injectRekorKey(spkiDer) { return { keyId: logIdBuf, spki: spkiDer }; }
  check("Ed25519 Rekor key dispatch (checkpoint) -> sigstore/unsigned-root",
    await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots, rekorKeys: [injectRekorKey(spkiOf("ed25519"))].concat(TM.rekorKeys) })) === "sigstore/unsigned-root");
  check("secp384r1 Rekor key dispatch (SHA-384) -> sigstore/unsigned-root",
    await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots, rekorKeys: [injectRekorKey(spkiOf("ec", { namedCurve: "secp384r1" }))].concat(TM.rekorKeys) })) === "sigstore/unsigned-root");
  check("secp521r1 Rekor key dispatch (SHA-512) -> sigstore/unsigned-root",
    await codeOf(pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots, rekorKeys: [injectRekorKey(spkiOf("ec", { namedCurve: "secp521r1" }))].concat(TM.rekorKeys) })) === "sigstore/unsigned-root");

  // A tlog entry with no logId leaves the SET selector with a null keyId. The SET
  // (not the checkpoint) signs integratedTime, so no SET verifies -> the log time
  // is unattested and cannot date the ephemeral Fulcio certificate.
  var noLogId = cl(); delete noLogId.verificationMaterial.tlogEntries[0].logId;
  check("tlog entry without logId (SET keyId null) -> sigstore/unattested-time",
    await codeOf(pki.sigstore.verifyBundle(noLogId, TM)) === "sigstore/unattested-time");

  // A bundle intermediate whose embedded ECDSA signature is not a DER SEQUENCE
  // makes the path validator THROW; the fault is caught and re-typed to
  // sigstore/chain-invalid rather than leaking a raw path/* error.
  var ptv = TM.fulcioRoots.map(function (r) { return { der: r.der, cert: pki.schema.x509.parse(r.der) }; });
  var lp = pki.schema.x509.parse(Buffer.from(BUNDLE.verificationMaterial.certificate.rawBytes, "base64"));
  var interP = ptv.filter(function (p) { return p.cert.subject.dn === lp.issuer.dn && p.cert.subject.dn !== p.cert.issuer.dn; })[0];
  var selfRoots = ptv.filter(function (p) { return p.cert.subject.dn === p.cert.issuer.dn; });
  if (interP && selfRoots.length) {
    var interDer = Buffer.from(interP.der);
    var sigBs = pki.asn1.decode(interDer).children[2];      // signatureValue BIT STRING
    interDer[sigBs.contentStart + 1] = 0x00;                // clobber the inner ECDSA SEQUENCE tag (after the unused-bits octet)
    var badChain = cl();
    var leafRaw = badChain.verificationMaterial.certificate.rawBytes;
    delete badChain.verificationMaterial.certificate;
    badChain.verificationMaterial.x509CertificateChain = { certificates: [{ rawBytes: leafRaw }, { rawBytes: interDer.toString("base64") }] };
    check("bundle intermediate with a non-DER signature -> sigstore/chain-invalid",
      await codeOf(pki.sigstore.verifyBundle(badChain, { fulcioRoots: selfRoots.map(function (p) { return { der: p.der }; }), rekorKeys: TM.rekorKeys })) === "sigstore/chain-invalid");
  }

  // ===========================================================================
  // Synthetic-bundle legs: Fulcio identity + in-toto statement. These run only
  // after the crypto legs pass, so they are exercised on a bundle whose Fulcio CA
  // and Rekor key the test holds (buildSynBundle above).
  // ===========================================================================
  var synGood = buildSynBundle({});
  var sv = await pki.sigstore.verifyBundle(synGood.bundle, synGood.trust);
  check("synthetic bundle (self-issued trust) fully verifies", sv && sv.verified === true && sv.identity.san.type === "uri");

  // A Fulcio machine identity carried as an otherName SAN ([0] { type-id, [0]
  // EXPLICIT value }) is decoded and surfaced with its type-id.
  var synOther = buildSynBundle({ san: [B.contextConstructed(0, Buffer.concat([B.oid("1.3.6.1.4.1.57264.1.7"), B.explicit(0, B.utf8("https://machine/id"))]))] });
  var svo = await pki.sigstore.verifyBundle(synOther.bundle, synOther.trust);
  check("synthetic otherName SAN -> identity.san.type === otherName",
    svo && svo.identity.san && svo.identity.san.type === "otherName" && svo.identity.san.value === "https://machine/id");

  // A Fulcio certificate binds exactly one identity: two SAN entries fail closed
  // (a mis-issued cert cannot smuggle a second identity past a caller policy).
  var synMulti = buildSynBundle({ san: [gnUriDer("https://a/1"), gnUriDer("https://a/2")] });
  check("synthetic multi-identity SAN -> sigstore/bad-certificate",
    await codeOf(pki.sigstore.verifyBundle(synMulti.bundle, synMulti.trust)) === "sigstore/bad-certificate");

  // A SAN carrying only a directoryName (no rfc822/dNS/URI machine identity)
  // surfaces a null SAN rather than throwing; a caller identity policy still
  // gates against the null value.
  var synDir = buildSynBundle({ san: [B.contextConstructed(4, B.sequence([B.set([B.sequence([synOid("commonName"), B.utf8("dir")])])]))] });
  var svd = await pki.sigstore.verifyBundle(synDir.bundle, synDir.trust);
  check("synthetic directoryName-only SAN -> identity.san is null", svd && svd.verified === true && svd.identity.san === null);

  // in-toto statement leg: a non-in-toto payloadType, a wrong statement _type, and
  // an empty subject each fail closed with sigstore/bad-statement.
  var synBadPt = buildSynBundle({ payloadType: "application/x.other" });
  check("synthetic non-in-toto payloadType -> sigstore/bad-statement",
    await codeOf(pki.sigstore.verifyBundle(synBadPt.bundle, synBadPt.trust)) === "sigstore/bad-statement");
  var synBadType = buildSynBundle({ payload: { _type: "https://in-toto.io/Statement/v0.9", subject: [{ name: "x" }] } });
  check("synthetic wrong statement _type -> sigstore/bad-statement",
    await codeOf(pki.sigstore.verifyBundle(synBadType.bundle, synBadType.trust)) === "sigstore/bad-statement");
  var synNoSubj = buildSynBundle({ payload: { _type: "https://in-toto.io/Statement/v1", predicateType: "x", subject: [] } });
  check("synthetic empty statement subject -> sigstore/bad-statement",
    await codeOf(pki.sigstore.verifyBundle(synNoSubj.bundle, synNoSubj.trust)) === "sigstore/bad-statement");

  // Chain-building termination: a bundle intermediate whose issuer cycles back to
  // its own (already-visited) subject must not loop; the walk finds no anchor path
  // and the chain is incomplete rather than hanging.
  var synCycle = buildSynBundle({ leafIssuer: "cycle-ca", extraChain: [synChainCert("cycle-ca", "cycle-ca")] });
  check("synthetic cyclic intermediate graph -> sigstore/chain-incomplete",
    await codeOf(pki.sigstore.verifyBundle(synCycle.bundle, synCycle.trust)) === "sigstore/chain-incomplete");

  // Chain-building depth cap: a linear DN chain longer than the walk's step bound
  // that never reaches a caller anchor is abandoned (no path), not walked forever.
  var deep = [];
  for (var di = 1; di <= 17; di++) { deep.push(synChainCert("depth-" + di, "depth-" + (di + 1))); }
  var synDeep = buildSynBundle({ leafIssuer: "depth-1", extraChain: deep });
  check("synthetic over-deep DN chain -> sigstore/chain-incomplete",
    await codeOf(pki.sigstore.verifyBundle(synDeep.bundle, synDeep.trust)) === "sigstore/chain-incomplete");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
