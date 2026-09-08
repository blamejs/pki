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

// The certificate-transparency logs the same document pins, in the shape verifyBundle takes for the
// Rekor keys: an operator builds both from the one trusted_root.json.
function ctLogMaterial() {
  return (TRUST.ctlogs || []).map(function (l) {
    return {
      keyId: Buffer.from((l.logId && l.logId.keyId) || "", "base64"),
      spki: Buffer.from((l.publicKey && l.publicKey.rawBytes) || "", "base64"),
      validFor: l.publicKey && l.publicKey.validFor,
    };
  });
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
  var integratedTime = opts.integratedTime !== undefined ? opts.integratedTime : Math.floor(new Date("2027-06-01T00:00:00Z").getTime() / 1000);
  var rootDer = synCert({ serial: 1n, issuer: "syn-root", subject: "syn-root", notBefore: NB, notAfter: NA,
    subjectKey: rootKp.publicKey, signerKey: rootKp.privateKey, extensions: [synExt("basicConstraints", true, B.sequence([B.boolean(true)])), synExt("keyUsage", true, synKuVal([5, 6]))] });
  var san = opts.san || [gnUriDer("https://github.com/synthetic/repo")];
  var leafDer = synCert({ serial: 2n, issuer: opts.leafIssuer || "syn-root", subject: "syn-leaf", notBefore: NB, notAfter: NA,
    subjectKey: opts.leafSubjectKey || leafKp.publicKey, signerKey: rootKp.privateKey,
    extensions: [synExt("keyUsage", true, synKuVal([0])), synExt("extKeyUsage", false, B.sequence([synOid("codeSigning")])), synExt("subjectAltName", false, B.sequence(san))].concat(opts.extraLeafExtensions || []) });
  // The message_signature arm, built with the same held keys. `signOver` lets the signature cover
  // bytes other than the artifact, which is how the digest-as-message construction and a plain
  // forgery are driven: the log entry still records the signature the bundle carries, so those
  // reach the signature check rather than being turned away by the entry binding.
  var env, body, derSig;
  var payloadType = opts.payloadType || "application/vnd.in-toto+json";
  if (opts.messageArtifact !== undefined) {
    var art = opts.messageArtifact;
    var hashAlg = opts.messageHashAlgorithm || "sha256";
    derSig = crypto.sign(opts.signHash || "sha256", opts.signOver !== undefined ? opts.signOver : art,
      { key: leafKp.privateKey, dsaEncoding: "der" });
    var ms = { signature: derSig.toString("base64") };
    if (!opts.omitMessageDigest) {
      ms.messageDigest = { algorithm: opts.messageDigestAlgorithm || "SHA2_256",
        digest: crypto.createHash(hashAlg).update(art).digest().toString("base64") };
    }
    env = null;
    body = { apiVersion: "0.0.1", kind: "hashedrekord", spec: {
      signature: { content: derSig.toString("base64"), publicKey: { content: Buffer.from(synPem(leafDer)).toString("base64") } },
      data: { hash: { algorithm: hashAlg, value: crypto.createHash(hashAlg).update(art).digest("hex") } } } };
    opts._ms = ms;
  } else {
    var payloadObj = opts.payload !== undefined ? opts.payload
      : { _type: "https://in-toto.io/Statement/v1", predicateType: "https://slsa.dev/provenance/v1", subject: [{ name: "pkg", digest: { sha512: "ab".repeat(64) } }], predicate: {} };
    var payload = Buffer.from(JSON.stringify(payloadObj));
    derSig = crypto.sign("sha256", pki.sigstore.pae(payloadType, payload), { key: leafKp.privateKey, dsaEncoding: "der" });
    env = { payload: payload.toString("base64"), payloadType: payloadType, signatures: [{ sig: derSig.toString("base64") }] };
    body = { apiVersion: "0.0.1", kind: "dsse", spec: { signatures: [{ signature: derSig.toString("base64"), verifier: Buffer.from(synPem(leafDer)).toString("base64") }],
      payloadHash: { algorithm: "sha256", value: crypto.createHash("sha256").update(payload).digest("hex") } } };
  }
  var canonBuf = Buffer.from(JSON.stringify(body));
  var rootHash = merkle.leafHash(canonBuf);          // single-leaf tree: root == leaf hash
  var rekorSpki = rekorKp.publicKey.export({ format: "der", type: "spki" });
  var keyId = crypto.createHash("sha256").update(rekorSpki).digest();
  var logIndex = 1234;
  var cpBody = Buffer.from("rekor.local\n1\n" + rootHash.toString("base64") + "\n", "utf8");
  var cpSig = crypto.sign("sha256", cpBody, { key: rekorKp.privateKey, dsaEncoding: "der" });
  var cpBlob = Buffer.concat([keyId.subarray(0, 4), cpSig]);
  var cpEnvelope = cpBody.toString("utf8") + "\n" + String.fromCharCode(0x2014) + " rekor.local " + cpBlob.toString("base64") + "\n";
  // Number() as the verifier applies it, so a non-numeric integratedTime is signed in the same form
  // the verifier canonicalizes it into and the SET still attests it.
  var setCanon = JSON.stringify({ body: canonBuf.toString("base64"), integratedTime: Number(integratedTime), logID: keyId.toString("hex"), logIndex: logIndex });
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
  var bundle = { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", verificationMaterial: vmat };
  if (env === null) bundle.messageSignature = opts._ms; else bundle.dsseEnvelope = env;
  return {
    bundle: bundle,
    trust: { fulcioRoots: [{ der: rootDer }], rekorKeys: [{ keyId: keyId, spki: rekorSpki }] },
    // The held keys, so a vector can construct material this bundle's own signer could have made
    // but never logged, which is the difference a transparency log exists to state.
    keys: { leafPrivate: leafKp.privateKey, leafDer: leafDer, leafPem: synPem(leafDer) },
  };
}

// A synthetic bundle whose leaf is issued by an INTERMEDIATE the bundle carries, with a real embedded
// certificate-transparency receipt over that leaf. The caller pins only the root, so the certificate
// that issued the leaf is a link in the chain rather than the anchor, which is the shape the receipt's
// issuer-key hash is computed from. The receipt is signed with a log key the test holds, so both the
// accepting and the refusing case are decidable here rather than against the public log.
async function buildSctChainBundle(o) {
  o = o || {};
  var rootKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var interKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var leafKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var rekorKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var logKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2030-01-01T00:00:00Z");
  var integratedTime = Math.floor(new Date("2027-06-01T00:00:00Z").getTime() / 1000);
  var caExts = [synExt("basicConstraints", true, B.sequence([B.boolean(true)])), synExt("keyUsage", true, synKuVal([5, 6]))];
  var rootDer = synCert({ serial: 1n, issuer: "syn-root", subject: "syn-root", notBefore: NB, notAfter: NA,
    subjectKey: rootKp.publicKey, signerKey: rootKp.privateKey, extensions: caExts });
  var interDer = synCert({ serial: 2n, issuer: "syn-root", subject: "syn-inter", notBefore: NB, notAfter: NA,
    subjectKey: interKp.publicKey, signerKey: rootKp.privateKey, extensions: caExts });

  // The receipt covers the certificate as it stood before the receipt was added, so the leaf is built
  // twice: once without the extension, to sign over, and once with it, to ship (RFC 6962 sec. 3.2).
  var leafExts = [synExt("keyUsage", true, synKuVal([0])), synExt("extKeyUsage", false, B.sequence([synOid("codeSigning")])),
    synExt("subjectAltName", false, B.sequence([gnUriDer("https://github.com/synthetic/repo")]))];
  function mkLeaf(exts) {
    return synCert({ serial: 3n, issuer: "syn-inter", subject: "syn-leaf", notBefore: NB, notAfter: NA,
      subjectKey: leafKp.publicKey, signerKey: interKp.privateKey, extensions: exts });
  }
  var preLeaf = pki.schema.x509.parse(mkLeaf(leafExts));
  var interSpki = interKp.publicKey.export({ format: "der", type: "spki" });
  var entry = { entryType: 1, tbsCertificate: Buffer.from(preLeaf.tbsBytes),
    issuerKeyHash: crypto.createHash("sha256").update(interSpki).digest() };
  var sct = await pki.ct.signSct(entry, logKp.privateKey.export({ format: "der", type: "pkcs8" }),
    { timestamp: o.sctTimestamp !== undefined ? o.sctTimestamp : new Date("2027-01-01T00:00:00Z").getTime() });
  var leafDer = mkLeaf(leafExts.concat([synExt("signedCertificateTimestampList", false, pki.ct.encodeSctList([sct]))]));

  var payloadType = "application/vnd.in-toto+json";
  var payload = Buffer.from(JSON.stringify({ _type: "https://in-toto.io/Statement/v1",
    predicateType: "https://slsa.dev/provenance/v1", subject: [{ name: "pkg", digest: { sha512: "ab".repeat(64) } }], predicate: {} }));
  var derSig = crypto.sign("sha256", pki.sigstore.pae(payloadType, payload), { key: leafKp.privateKey, dsaEncoding: "der" });
  var env = { payload: payload.toString("base64"), payloadType: payloadType, signatures: [{ sig: derSig.toString("base64") }] };
  var body = { apiVersion: "0.0.1", kind: "dsse", spec: { signatures: [{ signature: derSig.toString("base64"), verifier: Buffer.from(synPem(leafDer)).toString("base64") }],
    payloadHash: { algorithm: "sha256", value: crypto.createHash("sha256").update(payload).digest("hex") } } };
  var canonBuf = Buffer.from(JSON.stringify(body));
  var rootHash = merkle.leafHash(canonBuf);
  var rekorSpki = rekorKp.publicKey.export({ format: "der", type: "spki" });
  var keyId = crypto.createHash("sha256").update(rekorSpki).digest();
  var cpBody = Buffer.from("rekor.local\n1\n" + rootHash.toString("base64") + "\n", "utf8");
  var cpSig = crypto.sign("sha256", cpBody, { key: rekorKp.privateKey, dsaEncoding: "der" });
  var cpEnvelope = cpBody.toString("utf8") + "\n" + String.fromCharCode(0x2014) + " rekor.local " +
    Buffer.concat([keyId.subarray(0, 4), cpSig]).toString("base64") + "\n";
  var setCanon = JSON.stringify({ body: canonBuf.toString("base64"), integratedTime: integratedTime, logID: keyId.toString("hex"), logIndex: 1234 });
  var setSig = crypto.sign("sha256", Buffer.from(setCanon, "utf8"), { key: rekorKp.privateKey, dsaEncoding: "der" });
  var te = { logId: { keyId: keyId.toString("base64") }, integratedTime: integratedTime, logIndex: 1234,
    inclusionPromise: { signedEntryTimestamp: setSig.toString("base64") },
    inclusionProof: { logIndex: 0, treeSize: 1, hashes: [], rootHash: rootHash.toString("base64"), checkpoint: { envelope: cpEnvelope } },
    canonicalizedBody: canonBuf.toString("base64") };
  var bundle = { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { tlogEntries: [te],
      x509CertificateChain: { certificates: [{ rawBytes: leafDer.toString("base64") }, { rawBytes: interDer.toString("base64") }] } },
    dsseEnvelope: env };
  return {
    bundle: bundle,
    trust: { fulcioRoots: [{ der: rootDer }], rekorKeys: [{ keyId: keyId, spki: rekorSpki }] },
    ctLogs: [{ keyId: Buffer.from(sct.logId), spki: logKp.publicKey.export({ format: "der", type: "spki" }) }],
  };
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
  check("#78 valid aliases verified on the sigstore verdict", v.valid === true && v.valid === v.verified);
  // The verdict ends the prototype lookup for `then` on itself, so resolving it does not hand an
  // inherited accessor the verdict as a receiver. verdict-shield.test.js drives that behavior.
  check("the sigstore verdict owns then", Object.prototype.hasOwnProperty.call(v, "then") && v.then === undefined);
  check("verifyBundle surfaces the in-toto subject digest", v && v.subjects && v.subjects.length >= 1 && /^[0-9a-f]{64,128}$/.test(v.subjects[0].digest.sha512 || v.subjects[0].digest.sha256 || ""));

  // --- Embedded certificate-transparency SCTs (RFC 6962 sec. 3.2) -----------------------------
  // Fulcio logs every certificate it issues and embeds the log's receipt in the certificate. Checking
  // it is what says the signing certificate was public when it was issued, rather than handed out
  // quietly. It is opt-in, so a caller that pins no log is unaffected.
  check("SCT-1 with no ctLogs the bundle still verifies and says the receipt was not checked",
    v.sctChecked === false && v.validScts === 0);

  var CT = ctLogMaterial();
  var vSct = await pki.sigstore.verifyBundle(BUNDLE, Object.assign({}, TM, { ctLogs: CT }));
  check("SCT-2 the embedded receipt verifies against the logs the same trusted root pins",
    vSct.verified === true && vSct.sctChecked === true && vSct.validScts >= 1);

  // A pinned log set that does not include the log that issued the receipt is a refusal, not a pass:
  // an unverifiable receipt must not read as a verified one.
  var otherLog = CT.filter(function (l) { return l.keyId.toString("base64") !== "3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4="; });
  check("SCT-3 a log set that does not cover the receipt is refused",
    (await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({}, TM, { ctLogs: otherLog })))) === "sigstore/sct-unverified");

  // A tampered receipt signature must not verify. The extension bytes sit inside the certificate the
  // Fulcio chain leg authenticates, so this is checked on the certificate the bundle actually carries.
  var badSctTrust = CT.map(function (l) {
    var spki = Buffer.from(l.spki);
    spki[spki.length - 1] ^= 0x01;
    return { keyId: l.keyId, spki: spki, validFor: l.validFor };
  });
  check("SCT-4 a receipt that does not verify under the pinned log key is refused",
    (await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({}, TM, { ctLogs: badSctTrust })))) === "sigstore/sct-unverified");

  // An operator pins the Fulcio ROOT and the bundle carries the intermediate, which is the shape
  // cosign produces. The receipt is bound to the key that issued the certificate, so the check has to
  // read that issuer off the chain it just validated rather than off the anchor at the top of it.
  var sctChain = await buildSctChainBundle();
  var vChain = await pki.sigstore.verifyBundle(sctChain.bundle, Object.assign({}, sctChain.trust, { ctLogs: sctChain.ctLogs }));
  check("SCT-4b a receipt verifies when the intermediate that issued the leaf is not the pinned anchor",
    vChain.verified === true && vChain.sctChecked === true && vChain.validScts === 1);
  check("SCT-4c the same bundle without ctLogs verifies and reports the receipt unchecked",
    (await pki.sigstore.verifyBundle(sctChain.bundle, sctChain.trust)).sctChecked === false);

  check("SCT-5 an empty ctLogs array is refused rather than read as no policy",
    (await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({}, TM, { ctLogs: [] })))) === "sigstore/bad-input");
  check("SCT-6 a ctLogs entry missing its key is refused",
    (await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({}, TM, { ctLogs: [{ keyId: CT[0].keyId }] })))) === "sigstore/bad-input");
  check("SCT-6b ctLogs that is not an array is refused",
    (await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({}, TM, { ctLogs: { keyId: CT[0].keyId } })))) === "sigstore/bad-input");
  check("SCT-6c a ctLogs entry that is not an object is refused",
    (await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({}, TM, { ctLogs: ["not a log"] })))) === "sigstore/bad-input");
  check("SCT-6d a ctLogs entry whose keyId is not a Buffer is refused",
    (await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({}, TM, { ctLogs: [{ keyId: "3T0was", spki: CT[0].spki }] })))) === "sigstore/bad-input");

  // A certificate carrying no receipt at all, when the caller asked for the check, is its own refusal:
  // the absence must not read as a receipt that passed. The synthetic builder makes a leaf without one.
  var noSct = buildSynBundle({});
  check("SCT-7 a certificate carrying no receipt is refused when ctLogs was supplied",
    (await codeOf(pki.sigstore.verifyBundle(noSct.bundle, Object.assign({}, noSct.trust, { ctLogs: CT })))) === "sigstore/sct-missing");
  check("SCT-7b the same bundle verifies when no logs are pinned",
    (await pki.sigstore.verifyBundle(noSct.bundle, noSct.trust)).verified === true);

  // A receipt dated after the time being validated at is one the log could not have issued yet, so it
  // is not counted (RFC 6962 sec. 5.2). Checking the chain at a time before the receipt leaves nothing
  // that verifies, which is a refusal rather than a pass.
  check("SCT-8 a receipt dated after the caller's validation instant is not counted",
    (await codeOf(pki.sigstore.verifyBundle(sctChain.bundle,
      Object.assign({}, sctChain.trust, { ctLogs: sctChain.ctLogs, time: new Date("2026-06-01T00:00:00Z") })))) === "sigstore/sct-unverified");
  // The reference is the caller's own instant, never the Rekor entry time: that records whole seconds
  // while a receipt carries milliseconds, so a certificate logged in the same second as its entry would
  // otherwise read as dated after it. The published bundle is exactly that case, 64 ms apart.
  check("SCT-8b the published bundle's receipt is 64 ms after its Rekor entry and still counts",
    vSct.sctChecked === true && vSct.validScts >= 1);

  // A log key's window says when that key was the log's, so the receipt is held to the window as it
  // stood when the receipt was SIGNED. The synthetic receipt is dated 2027-01-01 and its artifact was
  // logged on 2027-06-01, so a window that opens between the two covers the logging but not the signing.
  check("SCT-9 a log whose key window opens after the receipt was signed does not count",
    (await codeOf(pki.sigstore.verifyBundle(sctChain.bundle, Object.assign({}, sctChain.trust, {
      ctLogs: sctChain.ctLogs.map(function (l) { return { keyId: l.keyId, spki: l.spki, validFor: { start: "2027-03-01T00:00:00Z" } }; }),
    })))) === "sigstore/sct-unverified");
  check("SCT-9b a log whose key window closes after the receipt was signed still counts",
    (await pki.sigstore.verifyBundle(sctChain.bundle, Object.assign({}, sctChain.trust, {
      ctLogs: sctChain.ctLogs.map(function (l) { return { keyId: l.keyId, spki: l.spki, validFor: { start: "2026-01-01T00:00:00Z", end: "2027-03-01T00:00:00Z" } }; }),
    }))).validScts === 1);

  // With no caller instant the bound is the authenticated log-entry time, whose whole second counts.
  // A receipt dated after that second is not accepted just because no instant was pinned.
  var future = await buildSctChainBundle({ sctTimestamp: new Date("2028-01-01T00:00:00Z").getTime() });
  check("SCT-10 a receipt dated after the log entry is refused even with no validation instant",
    (await codeOf(pki.sigstore.verifyBundle(future.bundle,
      Object.assign({}, future.trust, { ctLogs: future.ctLogs })))) === "sigstore/sct-unverified");
  var sameSecond = await buildSctChainBundle({ sctTimestamp: new Date("2027-06-01T00:00:00Z").getTime() + 640 });
  check("SCT-10b a receipt in the same second as the log entry counts, which is the granularity case",
    (await pki.sigstore.verifyBundle(sameSecond.bundle,
      Object.assign({}, sameSecond.trust, { ctLogs: sameSecond.ctLogs }))).validScts === 1);
  check("verifyBundle surfaces the SLSA predicateType", v && v.predicateType === "https://slsa.dev/provenance/v1");
  check("#78 predicateTypeChecked is false when no predicateType is pinned", v.predicateTypeChecked === false);
  check("#78 the verdict identifies the attested Rekor entry (logIndex + logId)",
    typeof v.logIndex === "number" && v.logIndex >= 0 && typeof v.logId === "string" && v.logId.length > 0);
  var vPin78 = await pki.sigstore.verifyBundle(BUNDLE, Object.assign({ predicateType: "https://slsa.dev/provenance/v1" }, TM));
  check("#78 predicateTypeChecked is true when a matching predicateType is pinned", vPin78.valid === true && vPin78.predicateTypeChecked === true);
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

  // The same far-future override, wearing a `getTime` that answers with the log time
  // instead. `time` is accepted by its internal slot, so a subclass from any realm gets
  // in; reading the instant back off the value asked the caller what time it was, and the
  // ephemeral Fulcio certificate was then checked inside its ten-minute window no matter
  // when the caller said to check it.
  var LogTimeDate = class extends Date {
    getTime() { return v.integratedTime * 1000; }
  };
  var answersItsOwnQuestion = new LogTimeDate("2030-01-01T00:00:00Z");
  check("the fixture holds the far-future instant and reports the log time",
    Date.prototype.getTime.call(answersItsOwnQuestion) === Date.parse("2030-01-01T00:00:00Z") &&
    answersItsOwnQuestion.getTime() === v.integratedTime * 1000);
  check("a caller Date cannot answer the instant the Fulcio chain is checked at",
    (await codeOf(pki.sigstore.verifyBundle(BUNDLE,
      Object.assign({}, TM, { time: answersItsOwnQuestion })))).indexOf("sigstore/") === 0);

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

  // A bundle verifies its own signature and log inclusion whoever signed it -- Fulcio issues to
  // anyone who can complete an OIDC flow. So `verified: true` says the artifact was signed and
  // logged, NOT that it was signed by someone the caller trusts, and only an identity policy
  // makes it the latter. The verdict has to distinguish the two, or a caller reading `verified`
  // cannot tell a checked signer from an unchecked one.
  check("with no identity policy the verdict reports that no signer check ran",
    v.identityChecked !== undefined && v.identityChecked.san === false &&
    v.identityChecked.issuer === false && v.identityChecked.sourceRepositoryURI === false);
  check("...and a policy that matched reports WHICH fields it checked",
    vp.identityChecked.san === true && vp.identityChecked.issuer === true &&
    vp.identityChecked.sourceRepositoryURI === false);
  // An empty policy object asks for nothing. Read as "an identity policy is in force" it is the
  // most dangerous input on this surface: every guard inside is falsy, so it passes everything
  // while looking like it constrains something. That is a caller's configuration mistake, so it
  // is refused at the boundary rather than answered.
  check("an identity policy that constrains nothing is refused, not silently satisfied",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({ identity: {} }, TM))) === "sigstore/bad-input");
  // cosign spells this `certificateIdentity`. Swallowed, it checks nothing under a name the
  // operator believes is pinning the signer.
  // A named field carrying a value that cannot be compared is the same defect wearing a policy:
  // the field is named, so it reads as pinned, but the comparison is skipped and the signer goes
  // unchecked. Deciding "was this asked for" and deciding "was this compared" must be one test.
  check("an identity field named with an empty value is refused, not reported as checked",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({ identity: { san: "" } }, TM))) === "sigstore/bad-input");
  check("...and a null value likewise",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE, Object.assign({ identity: { issuer: null } }, TM))) === "sigstore/bad-input");
  check("an unknown identity-policy key is refused rather than ignored",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE,
      Object.assign({ identity: { certificateIdentity: v.identity.san.value } }, TM))) === "sigstore/bad-input");
  // The same door at the TOP level, where the same slip loses the same pin. Closing it one level
  // down only caught a caller who already knew to write `identity`; a caller reaching for cosign's
  // flag name writes it here, and got `verified: true` with the signer entirely unpinned.
  check("cosign's certificateIdentity spelling at the top level is refused, not ignored",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE,
      Object.assign({ certificateIdentity: v.identity.san.value }, TM))) === "sigstore/bad-input");
  check("a misspelled certificateOidcIssuer is refused, not ignored",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE,
      Object.assign({ certificateOidcIssuer: "https://token.actions.githubusercontent.com" }, TM))) === "sigstore/bad-input");
  // predicateType has no identityChecked-style field, so a swallowed spelling left NOTHING in the
  // verdict to reveal that the SLSA-predicate pin never ran.
  check("a misspelled predicateType is refused, not silently unpinned",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE,
      Object.assign({ predicate_type: "https://slsa.dev/provenance/v1" }, TM))) === "sigstore/bad-input");
  check("the documented options are all still accepted",
    (await pki.sigstore.verifyBundle(BUNDLE, Object.assign({ identity: goodPolicy, predicateType: v.predicateType }, TM))).verified === true);

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

  // --- A message_signature content arm parses on its own shape. An empty signature is not a
  // signature, and the digest is held to the algorithm it names rather than to the arm being absent.
  check("message_signature arm with an empty signature -> sigstore/bad-message-signature", (function () { var b = JSON.parse(JSON.stringify(BUNDLE)); delete b.dsseEnvelope; b.messageSignature = { messageDigest: { algorithm: "SHA2_256", digest: "" }, signature: "" }; try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-message-signature"; } })());
  // Let a throw surface rather than catching it: a failure here should name what parseBundle refused.
  var msArmOk = (function () {
    var b = JSON.parse(JSON.stringify(BUNDLE));
    delete b.dsseEnvelope;
    b.messageSignature = { messageDigest: { algorithm: "SHA2_256", digest: Buffer.alloc(32).toString("base64") }, signature: Buffer.alloc(64).toString("base64") };
    return b;
  }());
  // An object is returned as the validated copy the checks ran on, not as the object handed over, so
  // what a caller reads back is what was actually checked.
  var msArmParsed = pki.sigstore.parseBundle(msArmOk);
  check("a well-formed message_signature arm parses",
    msArmParsed !== null && msArmParsed.messageSignature.signature === msArmOk.messageSignature.signature);
  check("and what comes back is the checked copy rather than the object handed over",
    msArmParsed !== msArmOk);
  // The same rule the verifying verb applies reaches this one: a bundle owning two content arms is
  // refused even when reading one of them removes the other, and an accessor is refused rather than
  // called. Both verbs decide on the same copy, so they cannot answer differently.
  var pbMutating = {};
  pbMutating.mediaType = BUNDLE.mediaType;
  pbMutating.verificationMaterial = BUNDLE.verificationMaterial;
  Object.defineProperty(pbMutating, "messageSignature", {
    enumerable: true, configurable: true,
    get: function () { delete pbMutating.dsseEnvelope; return { signature: "AA==" }; },
  });
  pbMutating.dsseEnvelope = BUNDLE.dsseEnvelope;
  check("the parse-side mutating object really owns both arms first",
    Object.prototype.hasOwnProperty.call(pbMutating, "messageSignature") &&
    Object.prototype.hasOwnProperty.call(pbMutating, "dsseEnvelope"));
  check("parseBundle refuses an accessor-backed arm rather than calling it", (function () {
    try { pki.sigstore.parseBundle(pbMutating); return false; }
    catch (e) { return e.code === "sigstore/bad-bundle"; }
  }()));

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

  // The bundle content is a oneof. A bundle setting both arms is malformed, and verifying the
  // envelope while passing over the other arm returns a verdict that says nothing about content the
  // bundle carries, so it is refused rather than read as the arm this build supports.
  var bothArms = JSON.parse(JSON.stringify(BUNDLE));
  bothArms.messageSignature = { messageDigest: { algorithm: "SHA2_256", digest: "AAAA" }, signature: "AAAA" };
  check("a bundle carrying both content arms is refused, not verified on the envelope alone",
    await codeOf(pki.sigstore.verifyBundle(bothArms, TM)) === "sigstore/bad-bundle");

  // The verification material's certificate is a oneof of the same kind. Both arms set would draw the
  // leaf from one and the chain through which it is validated from the other.
  var bothVm = JSON.parse(JSON.stringify(BUNDLE));
  var vmArm = bothVm.verificationMaterial;
  if (vmArm.x509CertificateChain) {
    vmArm.certificate = vmArm.x509CertificateChain.certificates[0];
  } else {
    vmArm.x509CertificateChain = { certificates: [vmArm.certificate] };
  }
  check("verificationMaterial carrying both certificate arms is refused",
    await codeOf(pki.sigstore.verifyBundle(bothVm, TM)) === "sigstore/bad-bundle");

  // The oneof has a third arm. A publicKey beside a certificate names a second signer identity, and
  // reading the certificate while passing over it reports a verdict about only one of the two.
  var vmPlusKey = JSON.parse(JSON.stringify(BUNDLE));
  vmPlusKey.verificationMaterial.publicKey = { hint: "AAAA" };
  check("verificationMaterial carrying a publicKey beside a certificate arm is refused",
    await codeOf(pki.sigstore.verifyBundle(vmPlusKey, TM)) === "sigstore/bad-bundle");

  // A bundle that SETS an arm to false or to an empty string has set it. Reading presence as
  // truthiness lets a second arm sit beside the one being read, which is the state the rule refuses.
  var falseyArms = [
    ["a publicKey set to false", function (b) { b.verificationMaterial.publicKey = false; }],
    ["an x509CertificateChain set to an empty string", function (b) { b.verificationMaterial.x509CertificateChain = ""; }],
    ["a messageSignature set to false", function (b) { b.messageSignature = false; }],
    ["a messageSignature set to an empty string", function (b) { b.messageSignature = ""; }],
  ];
  for (var fa = 0; fa < falseyArms.length; fa++) {
    var fb = JSON.parse(JSON.stringify(BUNDLE));
    falseyArms[fa][1](fb);
    check("a bundle carrying " + falseyArms[fa][0] + " beside a real arm is refused",
      await codeOf(pki.sigstore.verifyBundle(fb, TM)) === "sigstore/bad-bundle");
  }
  // An arm that is absent, or explicitly null, is not set.
  var nulledArm = JSON.parse(JSON.stringify(BUNDLE));
  nulledArm.verificationMaterial.publicKey = null;
  check("a verificationMaterial arm explicitly null is not a second arm",
    (await pki.sigstore.verifyBundle(nulledArm, TM)).verified === true);
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

  // A low-order (all-zeroes) Ed25519 Fulcio leaf key verifies a FORGED EdDSA signature; node imports it
  // without complaint, so the shared Edwards-point full-order gate must reject it at key-parse (before the
  // DSSE verify), exactly as the webauthn / path-validation EdDSA paths do. Without the gate the bundle
  // reaches the verify step (a different, later error); with it, sigstore/bad-key fires first.
  var lowOrderEd25519 = crypto.createPublicKey({ key: Buffer.from("302a300506032b6570032100" + "00".repeat(32), "hex"), format: "der", type: "spki" });
  var synLowOrder = buildSynBundle({ leafSubjectKey: lowOrderEd25519 });
  check("a low-order Ed25519 Fulcio leaf key -> sigstore/bad-key before verify",
    (await codeOf(pki.sigstore.verifyBundle(synLowOrder.bundle, synLowOrder.trust))) === "sigstore/bad-key");

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

  // A transparency-log entry whose integratedTime is attested by the SET (the
  // synthetic SET is re-signed over it) but is non-finite is rejected: the log
  // time must be a valid date to bound the ephemeral Fulcio certificate. A
  // negative finite time cannot reach this arm -- the C.TIME.seconds scale guard
  // rejects it first -- so a non-finite value is the reachable malformed-time form.
  // Written as a string rather than as NaN, since JSON carries no NaN and a bundle
  // reaches the verifier through its reader either way.
  var synBadTime = buildSynBundle({ integratedTime: "not-a-time" });
  check("synthetic SET-attested non-finite integratedTime -> sigstore/bad-tlog-entry",
    await codeOf(pki.sigstore.verifyBundle(synBadTime.bundle, synBadTime.trust)) === "sigstore/bad-tlog-entry");

  // A Fulcio arc extension (.1.8 issuer; non-critical, so the RFC 5280 chain leg
  // ignores it) whose value is well-formed DER but not a string is first decoded
  // in the identity leg. The raw asn1/* decode fault is re-typed at the _identity
  // boundary to a typed sigstore/bad-certificate rather than leaking an asn1/* code.
  var synBadFulcio = buildSynBundle({ extraLeafExtensions: [B.sequence([B.oid("1.3.6.1.4.1.57264.1.8"), B.octetString(B.integer(5n))])] });
  check("synthetic malformed Fulcio .8 extension value -> sigstore/bad-certificate",
    await codeOf(pki.sigstore.verifyBundle(synBadFulcio.bundle, synBadFulcio.trust)) === "sigstore/bad-certificate");

  // An otherName SAN whose [0] EXPLICIT value is a non-string (INTEGER) clears the
  // chain leg's otherName gate (which checks the [0] shape but not the inner type)
  // and reaches _sanValue: read.string throws, so the value surfaces as null. The
  // identity is still surfaced as an otherName type, and with no identity pinned the
  // bundle verifies. A null value cannot equal a pinned san, so it stays un-matchable.
  var synOtherInt = buildSynBundle({ san: [B.contextConstructed(0, Buffer.concat([B.oid("1.3.6.1.4.1.57264.1.7"), B.explicit(0, B.integer(5n))]))] });
  var svOtherInt = await pki.sigstore.verifyBundle(synOtherInt.bundle, synOtherInt.trust);
  check("synthetic otherName SAN with a non-string value -> otherName identity, null value (verified)",
    svOtherInt && svOtherInt.verified === true && svOtherInt.identity.san && svOtherInt.identity.san.type === "otherName" && svOtherInt.identity.san.value === null);
  // A non-string otherName value whose raw content bytes spell a pinned identity must
  // not satisfy the san pin: read.string rejects the non-string type, the value is
  // null, and the pin fails closed rather than matching the fabricated bytes.
  var SAN_SPOOF = "https://github.com/blamejs/pki";
  var synOtherSpoof = buildSynBundle({ san: [B.contextConstructed(0, Buffer.concat([B.oid("1.3.6.1.4.1.57264.1.7"), B.explicit(0, B.octetString(Buffer.from(SAN_SPOOF, "ascii")))]))] });
  check("a non-string otherName value spelling a pinned san is refused, not matched",
    await codeOf(pki.sigstore.verifyBundle(synOtherSpoof.bundle, Object.assign({ identity: { san: SAN_SPOOF } }, synOtherSpoof.trust))) === "sigstore/identity-mismatch");

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

  await runMessageSignature(TM);
}

// ---------------------------------------------------------------------------
// The message_signature content arm (Sigstore bundle protobuf, sigstore_common
// MessageSignature). The three fixtures are the conformance suite's own vectors over one
// 109-byte artifact, so the accepting cases are an independent implementation's output rather
// than this suite's.
// ---------------------------------------------------------------------------
async function runMessageSignature(TM) {
  var CFX = path.join(FX, "conformance");
  var ARTIFACT = fs.readFileSync(path.join(CFX, "a.txt"));
  var ARTIFACT_SHA256 = "a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf";
  function msBundle(v) {
    return JSON.parse(fs.readFileSync(path.join(CFX, "happy-path-" + v + ".sigstore.json"), "utf8"));
  }
  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  var trust = { fulcioRoots: TM.fulcioRoots, rekorKeys: TM.rekorKeys };

  check("the artifact fixture is the 109 bytes the bundles were signed over",
    ARTIFACT.length === 109 &&
    crypto.createHash("sha256").update(ARTIFACT).digest("hex") === ARTIFACT_SHA256);

  // Accept. Each vintage carries a different verificationMaterial arm and a different log time,
  // so all three run rather than one standing in for the others.
  var v3 = await pki.sigstore.verifyBundle(msBundle("v0.3"), { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT });
  check("a message_signature bundle over the artifact verifies",
    v3.valid === true && v3.verified === true && v3.contentType === "messageSignature");
  check("the verdict reports the log entry it was bound to", v3.integratedTime === 1710869186);
  check("the verdict reports the digest it COMPUTED, in the algorithm the entry names",
    v3.artifactDigest === ARTIFACT_SHA256 && v3.digestAlgorithm === "sha256");
  check("the unauthenticated messageDigest was checked and agreed", v3.messageDigestChecked === true);
  check("the statement fields the other arm carries are present and null, not absent",
    "payload" in v3 && v3.payload === null && v3.statement === null && v3.subjects === null &&
    v3.predicateType === null && v3.predicate === null && v3.predicateTypeChecked === false);

  var v1 = await pki.sigstore.verifyBundle(msBundle("v0.1"), { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT });
  check("the v0.1 media type and its x509CertificateChain arm verify on this content arm",
    v1.verified === true && v1.integratedTime === 1689177396);
  var v2 = await pki.sigstore.verifyBundle(msBundle("v0.2"), { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT });
  check("the v0.2 media type verifies on this content arm", v2.verified === true);

  // The DSSE arm keeps its shape, with the artifact fields present and null.
  var dsse = await pki.sigstore.verifyBundle(BUNDLE, trust);
  // The sentinel differs by what the field reports, and the two kinds are pinned separately so the
  // documented contract and the verdict cannot drift apart: a field carrying a VALUE the arm has
  // none of reads null, and a field reporting whether a CHECK RAN stays boolean.
  check("a dsse bundle reports the artifact values as null rather than omitting them",
    "artifactDigest" in dsse && dsse.artifactDigest === null &&
    "digestAlgorithm" in dsse && dsse.digestAlgorithm === null && dsse.contentType === "dsseEnvelope");
  check("a dsse bundle reports messageDigestChecked as false, not null",
    dsse.messageDigestChecked === false);
  check("and a message_signature reports predicateTypeChecked as false, not null, the same way",
    v3.predicateTypeChecked === false && v3.messageDigestChecked === true);

  // The artifact door. There is no shape in which a caller hands over a digest instead of bytes.
  check("a message_signature bundle with no artifact is refused, never verified from the digest",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.3"), trust)) === "sigstore/artifact-required");
  check("the same refusal on each vintage",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.1"), trust)) === "sigstore/artifact-required" &&
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.2"), trust)) === "sigstore/artifact-required");
  check("an artifact given as the hex digest is refused at the door, before any hashing",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.3"),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT_SHA256 })) === "sigstore/bad-input");
  check("an artifact given as the raw digest BYTES fails the entry hash, not the signature",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.3"),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys,
        artifact: crypto.createHash("sha256").update(ARTIFACT).digest() })) === "sigstore/artifact-mismatch");
  check("opts.artifact alongside a dsse bundle is refused rather than ignored",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE,
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/bad-input");
  check("opts.predicateType alongside a message_signature bundle is refused rather than ignored",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.3"),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT,
        predicateType: "https://slsa.dev/provenance/v1" })) === "sigstore/bad-input");

  // A wrong artifact, in each shape that could be mistaken for the right one.
  var oneOff = Buffer.from(ARTIFACT); oneOff[50] = oneOff[50] ^ 0x01;
  check("an artifact of the same length differing in one byte is refused",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.3"),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: oneOff })) === "sigstore/artifact-mismatch");
  check("a truncated artifact is refused",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.3"),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT.subarray(0, 108) })) === "sigstore/artifact-mismatch");
  check("an empty artifact is digested and compared rather than short-circuited",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.3"),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: Buffer.alloc(0) })) === "sigstore/artifact-mismatch");

  // The arm's own shape.
  var noSig = clone(msBundle("v0.3")); delete noSig.messageSignature.signature;
  check("a message_signature with no signature is refused",
    await codeOf(pki.sigstore.verifyBundle(noSig, trust)) === "sigstore/bad-message-signature");
  var emptyArm = clone(msBundle("v0.3")); emptyArm.messageSignature = {};
  check("an empty message_signature arm is refused",
    await codeOf(pki.sigstore.verifyBundle(emptyArm, trust)) === "sigstore/bad-message-signature");
  var unspecAlg = clone(msBundle("v0.3")); unspecAlg.messageSignature.messageDigest.algorithm = "HASH_ALGORITHM_UNSPECIFIED";
  check("a messageDigest naming the unspecified hash algorithm is refused",
    await codeOf(pki.sigstore.verifyBundle(unspecAlg, trust)) === "sigstore/bad-message-signature");
  // The enum carries two SHA-3 members. They are marked deprecated, which says a producer should not
  // choose them, not that a bundle carrying one is malformed; the digest is identification only and
  // names its own algorithm independently of the one the log entry records, so a bundle stating one
  // is verified rather than turned away before its signature is ever read.
  var sha3Names = [["SHA3_256", "sha3-256"], ["SHA3_384", "sha3-384"]];
  for (var s3 = 0; s3 < sha3Names.length; s3++) {
    var okSha3 = clone(msBundle("v0.3"));
    okSha3.messageSignature.messageDigest = { algorithm: sha3Names[s3][0],
      digest: crypto.createHash(sha3Names[s3][1]).update(ARTIFACT).digest().toString("base64") };
    var sha3Out = await pki.sigstore.verifyBundle(okSha3,
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT });
    check("a messageDigest stated under " + sha3Names[s3][0] + " is checked and the bundle verifies",
      sha3Out.verified === true && sha3Out.messageDigestChecked === true &&
      sha3Out.digestAlgorithm === "sha256" && sha3Out.artifactDigest === ARTIFACT_SHA256);
    var badSha3 = clone(msBundle("v0.3"));
    badSha3.messageSignature.messageDigest = { algorithm: sha3Names[s3][0],
      digest: crypto.createHash(sha3Names[s3][1]).update("other").digest().toString("base64") };
    check("and a " + sha3Names[s3][0] + " digest that disagrees with the artifact is refused",
      await codeOf(pki.sigstore.verifyBundle(badSha3,
        { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/artifact-mismatch");
  }
  // A member outside the enum entirely is still refused, so the rule is the enum rather than a
  // reader that takes any name it can hash under.
  var notInEnum = clone(msBundle("v0.3")); notInEnum.messageSignature.messageDigest.algorithm = "SHA2_224";
  check("a messageDigest naming a member outside the enum is refused",
    await codeOf(pki.sigstore.verifyBundle(notInEnum, trust)) === "sigstore/bad-message-signature");

  // The JSON mapping states that a parser accepts both enum names and integer values, so a bundle
  // writing the member's number is one a conforming producer may write and it names the same
  // algorithm. Every member is driven, not the one a vector happened to pick.
  var enumNumbers = [[1, "sha256"], [2, "sha384"], [3, "sha512"], [4, "sha3-256"], [5, "sha3-384"]];
  for (var en = 0; en < enumNumbers.length; en++) {
    var numB = clone(msBundle("v0.3"));
    numB.messageSignature.messageDigest = { algorithm: enumNumbers[en][0],
      digest: crypto.createHash(enumNumbers[en][1]).update(ARTIFACT).digest().toString("base64") };
    var numOut = await pki.sigstore.verifyBundle(numB,
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT });
    check("a messageDigest algorithm written as the number " + enumNumbers[en][0] + " is read as " + enumNumbers[en][1],
      numOut.verified === true && numOut.messageDigestChecked === true);
  }
  // The numbers outside the members are refused the same way their names are, and zero is the
  // unspecified member, which names no algorithm.
  var numBad = [0, 6, -1, 1.5];
  for (var nb = 0; nb < numBad.length; nb++) {
    var nbB = clone(msBundle("v0.3"));
    nbB.messageSignature.messageDigest.algorithm = numBad[nb];
    check("a messageDigest algorithm written as " + numBad[nb] + " is refused",
      await codeOf(pki.sigstore.verifyBundle(nbB, trust)) === "sigstore/bad-message-signature");
  }
  // The digest is still held to the length the number's algorithm produces, so the numeric form is
  // read as that member rather than admitted without its own rule.
  var numWrongLen = clone(msBundle("v0.3"));
  numWrongLen.messageSignature.messageDigest = { algorithm: 3, digest: Buffer.alloc(32).toString("base64") };
  check("a numeric algorithm whose digest is the wrong length for it is refused",
    await codeOf(pki.sigstore.verifyBundle(numWrongLen, trust)) === "sigstore/bad-message-signature");
  var wrongLen = clone(msBundle("v0.3"));
  wrongLen.messageSignature.messageDigest.digest = Buffer.alloc(48).toString("base64");
  check("a messageDigest whose length disagrees with its own algorithm is refused",
    await codeOf(pki.sigstore.verifyBundle(wrongLen, trust)) === "sigstore/bad-message-signature");
  var noDigest = clone(msBundle("v0.3")); delete noDigest.messageSignature.messageDigest;
  var ndOut = await pki.sigstore.verifyBundle(noDigest,
    { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT });
  check("a message_signature carrying no messageDigest still verifies, and says it checked none",
    ndOut.verified === true && ndOut.messageDigestChecked === false &&
    ndOut.artifactDigest === ARTIFACT_SHA256);

  // The digest the bundle claims is unauthenticated, so it is compared against the one computed
  // here and never reported in its place.
  var badDigest = clone(msBundle("v0.3"));
  badDigest.messageSignature.messageDigest.digest = crypto.createHash("sha256").update("other").digest().toString("base64");
  check("a messageDigest disagreeing with the artifact is refused",
    await codeOf(pki.sigstore.verifyBundle(badDigest,
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/artifact-mismatch");

  // The log entry is the authority on what was signed. Editing the hash it carries breaks the
  // signed body before any comparison of digests happens, which is what makes that hash the one
  // worth binding to.
  var editedEntry = clone(msBundle("v0.3"));
  var body = JSON.parse(Buffer.from(editedEntry.verificationMaterial.tlogEntries[0].canonicalizedBody, "base64").toString("utf8"));
  body.spec.data.hash.value = crypto.createHash("sha256").update("other").digest("hex");
  editedEntry.verificationMaterial.tlogEntries[0].canonicalizedBody =
    Buffer.from(JSON.stringify(body), "utf8").toString("base64");
  check("editing the entry's own artifact hash breaks the inclusion proof, before any digest compare",
    await codeOf(pki.sigstore.verifyBundle(editedEntry,
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/inclusion-proof-mismatch");

  // The entry kind and version come from the body the inclusion proof covers, not from the
  // kindVersion beside it, which no signature reaches. The v0.0.1 field names are not the v0.0.2
  // ones, so a version this build does not read is refused rather than parsed for names it may not
  // carry, and that refusal happens before the proof so it names the version rather than the proof.
  function withBody(bundle, edit) {
    var b = clone(bundle);
    var te = b.verificationMaterial.tlogEntries[0];
    var body = JSON.parse(Buffer.from(te.canonicalizedBody, "base64").toString("utf8"));
    edit(body);
    te.canonicalizedBody = Buffer.from(JSON.stringify(body), "utf8").toString("base64");
    return b;
  }
  check("a hashedrekord entry of an unsupported version is refused, never partly parsed",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.apiVersion = "0.0.2"; }),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/unsupported-content");
  check("an entry of a kind this build does not read is refused",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.kind = "intoto"; }),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/unsupported-content");
  // The entry kind and the content arm must describe the same signature: a dsse entry says nothing
  // about a message signature, and the bundle carrying one alongside the other is refused.
  check("a dsse entry beside a message_signature arm is refused",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.kind = "dsse"; }),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/unsupported-content");
  // The entry's signature and certificate are bound to the bundle's own, so an entry recording a
  // different signature is refused before anything is verified with it.
  check("an entry recording a different signature is refused",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.spec.signature.content = Buffer.alloc(70, 7).toString("base64"); }),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/entry-mismatch");
  check("an entry naming a hash algorithm outside the schema's three is refused",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.spec.data.hash.algorithm = "md5"; }),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/bad-tlog-entry");
  // The entry's algorithm comes from the hashedrekord schema's own enum, which is exactly sha256,
  // sha384 and sha512. The digest the bundle states is a different field under a different enum, so
  // admitting the SHA-3 members there does not admit them here.
  check("an entry naming a SHA-3 algorithm is refused, since its schema enumerates three",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.spec.data.hash.algorithm = "sha3-256"; }),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/bad-tlog-entry");
  check("an entry whose artifact hash is not lowercase hex of its own algorithm is refused",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.spec.data.hash.value = bd.spec.data.hash.value.toUpperCase(); }),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/bad-tlog-entry");

  // Every field the entry row reads is held to being there and being what it claims, since the
  // entry is what binds the signature and the certificate to the artifact.
  var withArtifact = { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT };
  var entryShapes = [
    ["no signature object", function (bd) { delete bd.spec.signature; }, "sigstore/bad-tlog-entry"],
    ["a signature with no content", function (bd) { bd.spec.signature = {}; }, "sigstore/bad-tlog-entry"],
    ["no verifier public key", function (bd) { delete bd.spec.signature.publicKey; }, "sigstore/bad-tlog-entry"],
    ["a verifier that is not a certificate", function (bd) { bd.spec.signature.publicKey = { content: Buffer.from("not a pem").toString("base64") }; }, "sigstore/bad-tlog-entry"],
    ["no data hash", function (bd) { delete bd.spec.data; }, "sigstore/bad-tlog-entry"],
    ["a data hash that is not an object", function (bd) { bd.spec.data = { hash: "sha256:x" }; }, "sigstore/bad-tlog-entry"],
    ["no hash algorithm at all", function (bd) { delete bd.spec.data.hash.algorithm; }, "sigstore/bad-tlog-entry"],
    ["a hash value of the wrong length for its algorithm", function (bd) { bd.spec.data.hash.value = "abcd"; }, "sigstore/bad-tlog-entry"],
  ];
  for (var es = 0; es < entryShapes.length; es++) {
    check("an entry with " + entryShapes[es][0] + " is refused",
      await codeOf(pki.sigstore.verifyBundle(
        withBody(msBundle("v0.3"), entryShapes[es][1]), withArtifact)) === entryShapes[es][2]);
  }
  // The verifier certificate the entry names has to be the bundle's own leaf.
  var otherLeaf = JSON.parse(JSON.stringify(BUNDLE)).verificationMaterial.certificate.rawBytes;
  check("an entry naming a different verifier certificate is refused",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) {
        bd.spec.signature.publicKey = { content: Buffer.from(
          "-----BEGIN CERTIFICATE-----\n" + otherLeaf.replace(/(.{64})/g, "$1\n").replace(/\n$/, "") + "\n-----END CERTIFICATE-----\n"
        ).toString("base64") };
      }), withArtifact)) === "sigstore/entry-mismatch");

  // The bundle may state its digest under an algorithm the entry does not use. Both are then
  // computed from the artifact and both must agree, rather than one standing in for the other.
  var sha512Claim = clone(msBundle("v0.3"));
  sha512Claim.messageSignature.messageDigest = {
    algorithm: "SHA2_512",
    digest: crypto.createHash("sha512").update(ARTIFACT).digest().toString("base64"),
  };
  var s5 = await pki.sigstore.verifyBundle(sha512Claim, withArtifact);
  check("a messageDigest under a different algorithm than the entry's is computed and agreed",
    s5.verified === true && s5.messageDigestChecked === true &&
    s5.digestAlgorithm === "sha256" && s5.artifactDigest === ARTIFACT_SHA256);
  var sha512Wrong = clone(msBundle("v0.3"));
  sha512Wrong.messageSignature.messageDigest = {
    algorithm: "SHA2_512",
    digest: crypto.createHash("sha512").update("other").digest().toString("base64"),
  };
  check("a messageDigest under a different algorithm that disagrees is refused",
    await codeOf(pki.sigstore.verifyBundle(sha512Wrong, withArtifact)) === "sigstore/artifact-mismatch");

  // Editing a real bundle cannot reach the signature check: the log entry records the signature, so
  // a forged one breaks the inclusion proof first. These are built under keys the test holds, where
  // the entry agrees with a signature that still does not verify over the artifact.
  var SYN_ART = Buffer.from("synthetic artifact bytes");
  var synMs = buildSynBundle({ messageArtifact: SYN_ART });
  var synOut = await pki.sigstore.verifyBundle(synMs.bundle,
    { fulcioRoots: synMs.trust.fulcioRoots, rekorKeys: synMs.trust.rekorKeys, artifact: SYN_ART });
  check("a synthetic message_signature bundle verifies, so the refusals below are about the signature",
    synOut.verified === true && synOut.contentType === "messageSignature" &&
    synOut.artifactDigest === crypto.createHash("sha256").update(SYN_ART).digest("hex"));

  // The construction the arm's own definition forbids: signing the DIGEST as if it were the
  // message. The entry records the artifact's hash, so this reaches the signature check and fails
  // there rather than being accepted as a second valid form.
  var synPrehash = buildSynBundle({ messageArtifact: SYN_ART,
    signOver: crypto.createHash("sha256").update(SYN_ART).digest() });
  check("a signature made over the digest rather than the artifact is refused",
    await codeOf(pki.sigstore.verifyBundle(synPrehash.bundle,
      { fulcioRoots: synPrehash.trust.fulcioRoots, rekorKeys: synPrehash.trust.rekorKeys, artifact: SYN_ART })) === "sigstore/signature-verify-failed");

  var synForged = buildSynBundle({ messageArtifact: SYN_ART, signOver: Buffer.from("other bytes entirely") });
  check("a message signature over other bytes is refused at the signature, not earlier",
    await codeOf(pki.sigstore.verifyBundle(synForged.bundle,
      { fulcioRoots: synForged.trust.fulcioRoots, rekorKeys: synForged.trust.rekorKeys, artifact: SYN_ART })) === "sigstore/signature-verify-failed");

  // A zero-length artifact is a real input shape: one actually signed over no bytes verifies, which
  // is the acceptance half of the empty-artifact refusal above.
  var synEmpty = buildSynBundle({ messageArtifact: Buffer.alloc(0) });
  var emptyOut = await pki.sigstore.verifyBundle(synEmpty.bundle,
    { fulcioRoots: synEmpty.trust.fulcioRoots, rekorKeys: synEmpty.trust.rekorKeys, artifact: Buffer.alloc(0) });
  check("a bundle signed over zero bytes verifies against a zero-length artifact",
    emptyOut.verified === true &&
    emptyOut.artifactDigest === crypto.createHash("sha256").update(Buffer.alloc(0)).digest("hex"));

  // The entry may record the artifact under sha384 or sha512, which the schema allows, and the
  // digest is then computed under that algorithm rather than under a fixed one.
  var syn384 = buildSynBundle({ messageArtifact: SYN_ART, messageHashAlgorithm: "sha384", omitMessageDigest: true });
  var out384 = await pki.sigstore.verifyBundle(syn384.bundle,
    { fulcioRoots: syn384.trust.fulcioRoots, rekorKeys: syn384.trust.rekorKeys, artifact: SYN_ART });
  check("an entry recording the artifact under sha384 is digested under sha384",
    out384.verified === true && out384.digestAlgorithm === "sha384" &&
    out384.artifactDigest === crypto.createHash("sha384").update(SYN_ART).digest("hex"));
  var syn512 = buildSynBundle({ messageArtifact: SYN_ART, messageHashAlgorithm: "sha512", omitMessageDigest: true });
  var out512 = await pki.sigstore.verifyBundle(syn512.bundle,
    { fulcioRoots: syn512.trust.fulcioRoots, rekorKeys: syn512.trust.rekorKeys, artifact: SYN_ART });
  check("an entry recording the artifact under sha512 is digested under sha512",
    out512.verified === true && out512.digestAlgorithm === "sha512");

  // The artifact is taken in every byte-source form, and read once: a view whose backing store is
  // rewritten after the call began is verified as the bytes that were there when it was taken.
  var u8 = new Uint8Array(SYN_ART);
  var viewOut = await pki.sigstore.verifyBundle(synMs.bundle,
    { fulcioRoots: synMs.trust.fulcioRoots, rekorKeys: synMs.trust.rekorKeys, artifact: u8 });
  check("an artifact given as a Uint8Array verifies to the same digest",
    viewOut.artifactDigest === synOut.artifactDigest);
  var backing = new ArrayBuffer(SYN_ART.length);
  new Uint8Array(backing).set(SYN_ART);
  var abOut = await pki.sigstore.verifyBundle(synMs.bundle,
    { fulcioRoots: synMs.trust.fulcioRoots, rekorKeys: synMs.trust.rekorKeys, artifact: backing });
  check("an artifact given as an ArrayBuffer verifies to the same digest",
    abOut.artifactDigest === synOut.artifactDigest);
  var dvOut = await pki.sigstore.verifyBundle(synMs.bundle,
    { fulcioRoots: synMs.trust.fulcioRoots, rekorKeys: synMs.trust.rekorKeys, artifact: new DataView(backing) });
  check("an artifact given as a DataView verifies to the same digest",
    dvOut.artifactDigest === synOut.artifactDigest);

  // A field that names a registry row is read for being a STRING before it is used as a key. A
  // value whose own conversion throws would otherwise escape as an untyped error from a verb whose
  // whole contract is that malformed input is refused with a typed one.
  var hostileKey = { toString: null };
  var algObj = clone(msBundle("v0.3")); algObj.messageSignature.messageDigest.algorithm = hostileKey;
  check("a messageDigest algorithm that is not a string is refused with a typed error",
    await codeOf(pki.sigstore.verifyBundle(algObj, withArtifact)) === "sigstore/bad-message-signature");
  check("and parseBundle refuses it the same way rather than throwing an untyped error",
    (function () {
      var b2 = clone(msBundle("v0.3"));
      b2.messageSignature.messageDigest.algorithm = hostileKey;
      try { pki.sigstore.parseBundle(b2); return false; }
      catch (e) { return e instanceof pki.errors.PkiError && e.code === "sigstore/bad-message-signature"; }
    }()));
  check("an entry kind that is not a string is refused with a typed error",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.kind = hostileKey; }), withArtifact)) === "sigstore/unsupported-content");
  check("an entry apiVersion that is not a string is refused with a typed error",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.apiVersion = hostileKey; }), withArtifact)) === "sigstore/unsupported-content");
  check("an entry hash algorithm that is not a string is refused with a typed error",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.spec.data.hash.algorithm = hostileKey; }), withArtifact)) === "sigstore/bad-tlog-entry");

  // A bundle handed over as an object carries the caller's own properties, so a field can answer
  // differently each time it is read. It is taken as a snapshot at the door, so every check runs on
  // the same answer: a later one cannot become the verified one, and the field is read once.
  var lying = clone(msBundle("v0.3"));
  var realArm = lying.messageSignature;
  var reads = 0;
  Object.defineProperty(lying, "messageSignature", {
    enumerable: true, configurable: true,
    get: function () {
      reads++;
      return reads === 1 ? realArm : { signature: Buffer.alloc(70, 9).toString("base64") };
    },
  });
  // A bundle is data. Its values are taken from each property's descriptor, which does not call an
  // accessor, and a field that computes its value is refused rather than called. Nothing the caller
  // wrote runs during the copy, so a field cannot answer differently on a later read and a getter
  // cannot change the object while it is being walked.
  check("a content arm reached through an accessor is refused rather than called",
    await codeOf(pki.sigstore.verifyBundle(lying, withArtifact)) === "sigstore/bad-bundle");
  check("and the accessor was never called", reads === 0);
  var countedBody = clone(msBundle("v0.3"));
  var cbTe = countedBody.verificationMaterial.tlogEntries[0];
  var cbReal = cbTe.canonicalizedBody, cbReads = 0;
  Object.defineProperty(cbTe, "canonicalizedBody", {
    enumerable: true, configurable: true, get: function () { cbReads++; return cbReal; },
  });
  check("a log entry field reached through an accessor is refused too, however consistent it is",
    await codeOf(pki.sigstore.verifyBundle(countedBody, withArtifact)) === "sigstore/bad-bundle");
  check("and that accessor was never called either", cbReads === 0);

  // The shape that made this necessary: a getter on one property deleting another. Both content arms
  // are listed when the object is enumerated, and reading the first would remove the second, leaving
  // a bundle that carried two arms copied as one.
  var mutating = {};
  var msrc = clone(msBundle("v0.3"));
  Object.defineProperty(mutating, "trigger", {
    enumerable: true, configurable: true,
    get: function () { delete mutating.messageSignature; return 1; },
  });
  mutating.mediaType = msrc.mediaType;
  mutating.verificationMaterial = msrc.verificationMaterial;
  mutating.dsseEnvelope = { payload: "e30=", payloadType: "application/vnd.in-toto+json", signatures: [{ sig: "AA==" }] };
  mutating.messageSignature = msrc.messageSignature;
  check("the object really does list both content arms before anything reads it",
    Object.keys(mutating).indexOf("messageSignature") >= 0 &&
    Object.keys(mutating).indexOf("dsseEnvelope") >= 0);
  check("a getter that deletes a content arm while the object is walked is refused",
    await codeOf(pki.sigstore.verifyBundle(mutating, withArtifact)) === "sigstore/bad-bundle");

  // An array element is a property too, so the same rule reaches it: an indexed accessor is refused
  // rather than called, and it can do exactly what a named one can.
  var arrMutating = {};
  var asrc = clone(msBundle("v0.3"));
  var trap = [];
  Object.defineProperty(trap, "0", {
    enumerable: true, configurable: true,
    get: function () { delete arrMutating.messageSignature; return 1; },
  });
  arrMutating.first = trap;
  arrMutating.mediaType = asrc.mediaType;
  arrMutating.verificationMaterial = asrc.verificationMaterial;
  arrMutating.dsseEnvelope = { payload: "e30=", payloadType: "application/vnd.in-toto+json", signatures: [{ sig: "AA==" }] };
  arrMutating.messageSignature = asrc.messageSignature;
  check("the array-trap object really does list both content arms first",
    Object.keys(arrMutating).indexOf("messageSignature") >= 0 &&
    Object.keys(arrMutating).indexOf("dsseEnvelope") >= 0);
  check("an array element reached through an accessor is refused rather than called",
    await codeOf(pki.sigstore.verifyBundle(arrMutating, withArtifact)) === "sigstore/bad-bundle");
  // The copy enumerates every own string-keyed property, not only the enumerable ones, because that
  // is what the presence test reads. A non-enumerable second content arm would otherwise be counted
  // as present where the bundle is parsed and dropped where it is copied.
  var hidden = clone(msBundle("v0.3"));
  Object.defineProperty(hidden, "dsseEnvelope", {
    enumerable: false, configurable: true,
    value: { payload: "e30=", payloadType: "application/vnd.in-toto+json", signatures: [{ sig: "AA==" }] },
  });
  check("the hidden-arm object really does own both arms",
    Object.prototype.hasOwnProperty.call(hidden, "dsseEnvelope") &&
    Object.prototype.hasOwnProperty.call(hidden, "messageSignature") &&
    Object.keys(hidden).indexOf("dsseEnvelope") === -1);
  check("a second content arm held as a non-enumerable property is refused, not dropped",
    await codeOf(pki.sigstore.verifyBundle(hidden, withArtifact)) === "sigstore/bad-bundle");
  var hiddenVm = clone(msBundle("v0.3"));
  Object.defineProperty(hiddenVm.verificationMaterial, "publicKey", {
    enumerable: false, configurable: true, value: { rawBytes: "AA==" },
  });
  check("a second verificationMaterial arm held the same way is refused too",
    await codeOf(pki.sigstore.verifyBundle(hiddenVm, withArtifact)) === "sigstore/bad-bundle");

  // Read the other way: an ordinary array of values still copies, so the rule is the accessor.
  var plainArray = clone(msBundle("v0.3"));
  plainArray.extras = [1, "two", null, { three: 3 }];
  var plainArrOut = await pki.sigstore.verifyBundle(plainArray, withArtifact);
  check("an ordinary array of values is copied and the bundle verifies",
    plainArrOut.verified === true && plainArrOut.artifactDigest === ARTIFACT_SHA256);
  // The rule is the accessor, not what it answers: one that would answer consistently is refused
  // alike, since whether it answers consistently is only knowable by calling it.
  var steady = clone(msBundle("v0.3"));
  var steadyArm = steady.messageSignature;
  var steadyCalls = 0;
  Object.defineProperty(steady, "messageSignature", {
    enumerable: true, configurable: true, get: function () { steadyCalls++; return steadyArm; },
  });
  check("an arm reached through an accessor that would answer consistently is refused alike",
    await codeOf(pki.sigstore.verifyBundle(steady, withArtifact)) === "sigstore/bad-bundle");
  check("and it too was never called", steadyCalls === 0);
  // Read the other way: the same bundle holding the same arm as a plain value verifies, so the rule
  // is how the field is held rather than anything about the arm.
  var plainArm = clone(msBundle("v0.3"));
  var plainOut = await pki.sigstore.verifyBundle(plainArm, withArtifact);
  check("the same arm held as a plain value verifies",
    plainOut.verified === true && plainOut.artifactDigest === ARTIFACT_SHA256);

  // A bundle is JSON data. A value JSON does not carry is refused rather than skipped, because
  // skipping one turns a bundle setting two content arms into one setting a single arm: a refusal
  // sanitized into an accept. The rule is stated over the whole structure rather than over the arms,
  // so there is no field where the reasoning has to be repeated.
  var notJson = [
    ["a second content arm held as a function", function (b) { b.dsseEnvelope = function () {}; }],
    ["a second content arm held as a symbol", function (b) { b.dsseEnvelope = Symbol("x"); }],
    ["a second verificationMaterial arm held as a function", function (b) { b.verificationMaterial.publicKey = function () {}; }],
    ["an unrelated property held as a function", function (b) { b.someUnrelatedField = function () {}; }],
    ["a value nested inside an array held as a function", function (b) { b.verificationMaterial.tlogEntries.push(function () {}); }],
    ["a number JSON cannot represent", function (b) { b.someNumber = Infinity; }],
    ["a bigint", function (b) { b.someBig = 1n; }],
  ];
  for (var nj = 0; nj < notJson.length; nj++) {
    var njB = clone(msBundle("v0.3"));
    notJson[nj][1](njB);
    check("a bundle carrying " + notJson[nj][0] + " is refused rather than having it dropped",
      await codeOf(pki.sigstore.verifyBundle(njB, withArtifact)) === "sigstore/bad-bundle");
  }
  // A field explicitly set to undefined is what an absent field means, and is skipped rather than
  // refused, which is how the presence test already reads it.
  var undefArm = clone(msBundle("v0.3"));
  undefArm.dsseEnvelope = undefined;
  var undefOut = await pki.sigstore.verifyBundle(undefArm, withArtifact);
  check("a field explicitly set to undefined reads as absent rather than as a second arm",
    undefOut.verified === true && undefOut.contentType === "messageSignature");
  // Sharing one sub-object between two properties doubles the values a copy visits per level, so a
  // structure of a few hundred bytes expands past anything a depth cap bounds: twenty-eight levels
  // of { a: previous, b: previous } is 268 million values. The count of values visited is bounded on
  // the way, so the refusal costs what the bound allows rather than what the structure expands to.
  var bomb = clone(msBundle("v0.3"));
  var shared = { x: 1 };
  for (var bz = 0; bz < 28; bz++) shared = { a: shared, b: shared };
  bomb.bomb = shared;
  var bombStart = Date.now();
  var bombErr = null;
  try { await pki.sigstore.verifyBundle(bomb, withArtifact); } catch (e) { bombErr = e; }
  check("a bundle sharing sub-objects to expand exponentially is refused on its size",
    bombErr !== null && bombErr.code === "sigstore/bad-bundle" &&
    bombErr.message.indexOf("larger than") !== -1);
  check("and that refusal is bounded rather than proportional to what the structure expands to",
    (Date.now() - bombStart) < 10000);

  // The other shape the same bound covers: a handful of values holding tens of megabytes. The size
  // is charged as the copy is built, so the refusal comes before the allocation rather than after.
  var fatStrings = clone(msBundle("v0.3"));
  fatStrings.fat = new Array(2048).fill("a".repeat(32768));
  var fatStart = Date.now();
  var fatErr = null;
  try { await pki.sigstore.verifyBundle(fatStrings, withArtifact); } catch (e) { fatErr = e; }
  check("a bundle whose values hold far more than the size limit is refused on its size",
    fatErr !== null && fatErr.code === "sigstore/bad-bundle" &&
    fatErr.message.indexOf("larger than") !== -1);
  check("and that refusal happens without building the whole of it",
    (Date.now() - fatStart) < 10000);

  // A property is charged for by the name it is enumerated under, before its value is read, so a
  // structure made of properties the copy would skip is bounded like any other rather than walked
  // for free.
  var manyUndef = clone(msBundle("v0.3"));
  for (var mu = 0; mu < 40000; mu++) manyUndef["k".repeat(64) + mu] = undefined;
  var muStart = Date.now();
  check("a bundle of many properties the copy skips is still refused on its size",
    await codeOf(pki.sigstore.verifyBundle(manyUndef, withArtifact)) === "sigstore/bad-bundle");
  check("and that refusal is bounded", (Date.now() - muStart) < 10000);

  // Reading a caller's object runs the caller's own accessors, and one that throws must surface as
  // this module's refusal rather than as whatever it threw: the contract is that a bundle this
  // cannot read is refused with a typed error.
  var throwing = clone(msBundle("v0.3"));
  Object.defineProperty(throwing, "someField", {
    enumerable: true, configurable: true,
    get: function () { throw new RangeError("from the caller's own accessor"); },
  });
  var thrownErr = null;
  try { await pki.sigstore.verifyBundle(throwing, withArtifact); } catch (e) { thrownErr = e; }
  check("an accessor that throws is reported as a typed refusal, not as what it threw",
    thrownErr !== null && thrownErr instanceof pki.errors.PkiError &&
    thrownErr.code === "sigstore/bad-bundle");

  // A structure nesting past the reader's depth cap is refused rather than walked.
  var deep = clone(msBundle("v0.3"));
  var cur = deep;
  for (var dz = 0; dz < 40; dz++) { cur.nest = {}; cur = cur.nest; }
  check("a bundle nesting past the depth cap is refused",
    await codeOf(pki.sigstore.verifyBundle(deep, withArtifact)) === "sigstore/bad-bundle");

  // The same bundle as JSON text and as bytes reaches the same verdict: text is already fixed and
  // is read as it came, so the snapshot is what an object input is brought to rather than a
  // different route to a different answer.
  var asText = await pki.sigstore.verifyBundle(JSON.stringify(msBundle("v0.3")), withArtifact);
  check("a bundle given as a JSON string verifies to the same digest",
    asText.verified === true && asText.artifactDigest === ARTIFACT_SHA256);
  var asBytes = await pki.sigstore.verifyBundle(Buffer.from(JSON.stringify(msBundle("v0.3")), "utf8"), withArtifact);
  check("a bundle given as bytes verifies to the same digest",
    asBytes.verified === true && asBytes.artifactDigest === ARTIFACT_SHA256);

  // A structure that cannot be serialized is not a bundle, and is refused at the door rather than
  // part-way through a check that reads it.
  var circular = clone(msBundle("v0.3"));
  circular.self = circular;
  check("a bundle object that cannot be serialized is refused",
    await codeOf(pki.sigstore.verifyBundle(circular, withArtifact)) === "sigstore/bad-bundle");
  check("a bundle object that serializes to nothing is refused",
    await codeOf(pki.sigstore.verifyBundle({ toJSON: function () { return undefined; } }, withArtifact)) === "sigstore/bad-bundle");

  // The same rule reaches the log entry, where getting it wrong is worse: an entry that answers with
  // one body while it is bound and another while it is proven would let a signature over bytes the
  // log never recorded be attested by an authentic entry for something else. The body is read once
  // and the binding, the inclusion proof and the signed entry timestamp all run on that copy.
  // The signer holds a legitimately issued certificate, so it can sign anything; what the log adds
  // is that the signature was publicly recorded. The attack pairs an UNLOGGED body, which binds the
  // signature and names the artifact, with the authentic body whose inclusion proof and signed
  // timestamp actually verify. Both name the same leaf, so the binding accepts the first.
  var LOGGED = Buffer.from("the artifact that was logged");
  var UNLOGGED = Buffer.from("an artifact that never was");
  var swapBuilt = buildSynBundle({ messageArtifact: LOGGED });
  var unloggedSig = crypto.sign("sha256", UNLOGGED, { key: swapBuilt.keys.leafPrivate, dsaEncoding: "der" });
  var unloggedBody = Buffer.from(JSON.stringify({
    apiVersion: "0.0.1", kind: "hashedrekord",
    spec: {
      signature: { content: unloggedSig.toString("base64"),
        publicKey: { content: Buffer.from(swapBuilt.keys.leafPem).toString("base64") } },
      data: { hash: { algorithm: "sha256", value: crypto.createHash("sha256").update(UNLOGGED).digest("hex") } },
    },
  }), "utf8").toString("base64");
  var swapped = JSON.parse(JSON.stringify(swapBuilt.bundle));
  swapped.messageSignature = { signature: unloggedSig.toString("base64") };
  var authenticBody = swapped.verificationMaterial.tlogEntries[0].canonicalizedBody;
  var bodyReads = 0;
  Object.defineProperty(swapped.verificationMaterial.tlogEntries[0], "canonicalizedBody", {
    enumerable: true, configurable: true,
    get: function () { bodyReads++; return bodyReads === 1 ? unloggedBody : authenticBody; },
  });
  check("a log entry whose body could change between the binding and the proof is refused",
    await codeOf(pki.sigstore.verifyBundle(swapped,
      { fulcioRoots: swapBuilt.trust.fulcioRoots, rekorKeys: swapBuilt.trust.rekorKeys, artifact: UNLOGGED })) === "sigstore/bad-bundle");
  check("and the body it would have answered with was never asked for", bodyReads === 0);
  // The same attack with the unlogged body held as a plain value, so the entry it binds is the one
  // it proves. It is refused where the proof is folded rather than where the copy is taken, which is
  // what says the log entry is bound to the body it was proven from.
  var swappedPlain = JSON.parse(JSON.stringify(swapBuilt.bundle));
  swappedPlain.messageSignature = { signature: unloggedSig.toString("base64") };
  swappedPlain.verificationMaterial.tlogEntries[0].canonicalizedBody = unloggedBody;
  check("an unlogged body carrying the signature and the leaf is refused at the inclusion proof",
    await codeOf(pki.sigstore.verifyBundle(swappedPlain,
      { fulcioRoots: swapBuilt.trust.fulcioRoots, rekorKeys: swapBuilt.trust.rekorKeys, artifact: UNLOGGED })) === "sigstore/inclusion-proof-mismatch");

  // The DSSE arm reads the same entry through the same function, so the rule holds there too.
  var dsseSwap = buildSynBundle({});
  var dsseAuthentic = dsseSwap.bundle.verificationMaterial.tlogEntries[0].canonicalizedBody;
  var dsseOther = Buffer.from(JSON.stringify({
    apiVersion: "0.0.1", kind: "dsse",
    spec: { signatures: [{ signature: "AA==", verifier: Buffer.from(dsseSwap.keys.leafPem).toString("base64") }],
      payloadHash: { algorithm: "sha256", value: "00".repeat(32) } },
  }), "utf8").toString("base64");
  var dsseReads = 0;
  Object.defineProperty(dsseSwap.bundle.verificationMaterial.tlogEntries[0], "canonicalizedBody", {
    enumerable: true, configurable: true,
    get: function () { dsseReads++; return dsseReads === 1 ? dsseOther : dsseAuthentic; },
  });
  check("a dsse entry whose body could change between the binding and the proof is refused",
    await codeOf(pki.sigstore.verifyBundle(dsseSwap.bundle, dsseSwap.trust)) === "sigstore/bad-bundle");
  check("and that dsse entry's body was never asked for either", dsseReads === 0);

  // The DSSE entry row is held to its own shape the same way, and that check runs before the
  // inclusion proof so it names the entry rather than the proof.
  var synDsse = buildSynBundle({});
  function withSynBody(built, edit) {
    var b = JSON.parse(JSON.stringify(built.bundle));
    var te2 = b.verificationMaterial.tlogEntries[0];
    var bd = JSON.parse(Buffer.from(te2.canonicalizedBody, "base64").toString("utf8"));
    edit(bd);
    te2.canonicalizedBody = Buffer.from(JSON.stringify(bd), "utf8").toString("base64");
    return b;
  }
  check("a dsse entry with an empty signatures array is refused as a malformed entry",
    await codeOf(pki.sigstore.verifyBundle(
      withSynBody(synDsse, function (bd) { bd.spec.signatures = []; }), synDsse.trust)) === "sigstore/bad-tlog-entry");
  check("a dsse entry whose signature is not a string is refused as a malformed entry",
    await codeOf(pki.sigstore.verifyBundle(
      withSynBody(synDsse, function (bd) { bd.spec.signatures = [{ signature: 7 }]; }), synDsse.trust)) === "sigstore/bad-tlog-entry");

  // An identity policy has to be an object naming fields. An array names none of them while reading
  // as a policy in force.
  check("an identity policy given as an array is refused",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.3"),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT,
        identity: ["https://github.com/x"] })) === "sigstore/bad-input");

  // opts.identity and opts.ctLogs run on this arm too.
  var idOut = await pki.sigstore.verifyBundle(msBundle("v0.3"), {
    fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT,
    ctLogs: ctLogMaterial(),
  });
  check("the certificate-transparency receipt is checked on this arm",
    idOut.sctChecked === true && idOut.validScts >= 1);
  check("the signer identity is surfaced on this arm",
    idOut.identity !== null && typeof idOut.identity === "object");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
