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
  var rekorSpki = rekorKp.publicKey.export({ format: "der", type: "spki" });
  var keyId = crypto.createHash("sha256").update(rekorSpki).digest();
  var logIndex = 1234;
  // One entry, built the way the log builds one. A vector asking for a second gets one that binds
  // just as hard, with its own proof and signed entry timestamp, differing only in what it records.
  function makeEntry(bodyObj, atTime) {
    var entryTime = atTime === undefined ? integratedTime : atTime;
    var canonBuf = Buffer.from(JSON.stringify(bodyObj));
    var rootHash = merkle.leafHash(canonBuf);        // single-leaf tree: root == leaf hash
    var cpBody = Buffer.from("rekor.local\n1\n" + rootHash.toString("base64") + "\n", "utf8");
    var cpSig = crypto.sign("sha256", cpBody, { key: rekorKp.privateKey, dsaEncoding: "der" });
    var cpBlob = Buffer.concat([keyId.subarray(0, 4), cpSig]);
    var cpEnvelope = cpBody.toString("utf8") + "\n" + String.fromCharCode(0x2014) + " rekor.local " + cpBlob.toString("base64") + "\n";
    // Number() as the verifier applies it, so a non-numeric integratedTime is signed in the same form
    // the verifier canonicalizes it into and the SET still attests it.
    var setCanon = JSON.stringify({ body: canonBuf.toString("base64"), integratedTime: Number(entryTime), logID: keyId.toString("hex"), logIndex: logIndex });
    var setSig = crypto.sign("sha256", Buffer.from(setCanon, "utf8"), { key: rekorKp.privateKey, dsaEncoding: "der" });
    return { logId: { keyId: keyId.toString("base64") }, integratedTime: entryTime, logIndex: logIndex,
      inclusionPromise: { signedEntryTimestamp: setSig.toString("base64") },
      inclusionProof: { logIndex: 0, treeSize: 1, hashes: [], rootHash: rootHash.toString("base64"), checkpoint: { envelope: cpEnvelope } },
      canonicalizedBody: canonBuf.toString("base64") };
  }
  var te = makeEntry(body);
  // extraChain rides in the bundle x509CertificateChain (path steps only, never a
  // terminal anchor) so the chain-building walk can be driven with a cyclic or an
  // over-deep DN graph -- the leaf stays cert[0].
  // An entry that binds exactly as hard as the real one, carrying the same signature and the same
  // certificate, and naming a different artifact. A log can hold several entries for one signer.
  var entries = [te];
  if (opts.decoyArtifact !== undefined) {
    var decoyBody = JSON.parse(JSON.stringify(body));
    decoyBody.spec.data.hash.value = crypto.createHash(hashAlg).update(opts.decoyArtifact).digest("hex");
    entries = [makeEntry(decoyBody), te];
  } else if (opts.decoyIntegratedTime !== undefined) {
    // The same body, authentically logged, attesting an instant the leaf certificate does not cover.
    entries = [makeEntry(body, opts.decoyIntegratedTime), te];
  }
  var vmat = { tlogEntries: entries };
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
    // but never logged, which is the difference a transparency log exists to state. The log's own
    // key rides along so a vector can mint a checkpoint a DIFFERENT log would have signed, which is
    // what distinguishes "a signed tree root" from "this log's signed tree root".
    keys: { leafPrivate: leafKp.privateKey, leafDer: leafDer, leafPem: synPem(leafDer),
      rekorPrivate: rekorKp.privateKey, rekorSpki: rekorSpki, rekorKeyId: keyId },
  };
}

// A synthetic Rekor v2 bundle. No public-good v2 bundle exists to borrow: the npm attestations are
// v1, so this is built the way rekor-tiles CLIENTS.md describes one.
//
// Rekor v2 supports no DSSE entry type, so a DSSE signature is logged as a `hashedrekord` v0.0.2 over
// the hash of its PAE preimage. It issues no signed entry timestamp and writes integratedTime as 0,
// so the instant comes from an RFC 3161 token over the SIGNATURE bytes, which is what dates the
// ephemeral certificate that made them.
async function buildV2Bundle(opts) {
  opts = opts || {};
  var rootKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var leafKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var logKp = crypto.generateKeyPairSync("ed25519");           // a v2 log signs with Ed25519
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2030-01-01T00:00:00Z");
  var genTime = opts.genTime || new Date("2027-06-01T00:00:00Z");

  var rootDer = synCert({ serial: 1n, issuer: "v2-root", subject: "v2-root", notBefore: NB, notAfter: NA,
    subjectKey: rootKp.publicKey, signerKey: rootKp.privateKey,
    extensions: [synExt("basicConstraints", true, B.sequence([B.boolean(true)])), synExt("keyUsage", true, synKuVal([5, 6]))] });
  var leafDer = synCert({ serial: 2n, issuer: "v2-root", subject: "v2-leaf", notBefore: NB, notAfter: NA,
    subjectKey: leafKp.publicKey, signerKey: rootKp.privateKey,
    extensions: [synExt("keyUsage", true, synKuVal([0])), synExt("extKeyUsage", false, B.sequence([synOid("codeSigning")])),
      synExt("subjectAltName", false, B.sequence([gnUriDer("https://github.com/synthetic/v2")]))] });

  // Either content arm. A v2 log holds a DSSE signature as a hashedrekord over
  // the hash of its signing preimage, and a message signature as one over the
  // artifact's own digest, so the digest the entry records differs by arm.
  var isMsg = opts.messageArtifact !== undefined;
  var payloadType = "application/vnd.in-toto+json";
  var payload, paeBytes, derSig, env = null, ms = null, coveredDigest;
  if (isMsg) {
    var art = opts.messageArtifact;
    derSig = crypto.sign("sha256", art, { key: leafKp.privateKey, dsaEncoding: "der" });
    ms = { signature: derSig.toString("base64"),
      messageDigest: { algorithm: "SHA2_256", digest: crypto.createHash("sha256").update(art).digest().toString("base64") } };
    coveredDigest = crypto.createHash("sha256").update(art).digest();
  } else {
    var payloadObj = { _type: "https://in-toto.io/Statement/v1", predicateType: "https://slsa.dev/provenance/v1",
      subject: [{ name: "pkg", digest: { sha512: "cd".repeat(64) } }], predicate: {} };
    payload = Buffer.from(JSON.stringify(payloadObj));
    paeBytes = pki.sigstore.pae(payloadType, payload);
    derSig = crypto.sign("sha256", paeBytes, { key: leafKp.privateKey, dsaEncoding: "der" });
    env = { payload: payload.toString("base64"), payloadType: payloadType, signatures: [{ sig: derSig.toString("base64") }] };
    coveredDigest = crypto.createHash("sha256").update(paeBytes).digest();
  }

  // The v0.0.2 entry body: the signature, the raw certificate that made it, and
  // the digest of the PAE preimage.
  var body = {
    apiVersion: opts.apiVersion || "0.0.2",
    kind: opts.kind || "hashedrekord",
    spec: { hashedRekordV002: {
      signature: {
        content: derSig.toString("base64"),
        verifier: { x509Certificate: { rawBytes: leafDer.toString("base64") },
          keyDetails: opts.keyDetails === null ? undefined : (opts.keyDetails || "PKIX_ECDSA_P256_SHA_256") },
      },
      data: { algorithm: opts.digestAlgorithm || "SHA2_256",
        digest: (opts.digest || coveredDigest).toString("base64") },
    } },
  };
  if (opts.editBody) opts.editBody(body);
  var canonBuf = Buffer.from(JSON.stringify(body));

  // A single-leaf tree, so the root is the leaf hash and the proof is empty.
  var rootHash = merkle.leafHash(canonBuf);
  var logSpki = logKp.publicKey.export({ format: "der", type: "spki" });
  var logRaw = pki.asn1.decode(logSpki).children[1].content.subarray(1);
  var origin = opts.origin || "log2025-1.rekor.example";
  var cpBody = origin + "\n1\n" + rootHash.toString("base64") + "\n";
  var cpSig = crypto.sign(null, Buffer.from(cpBody, "utf8"), logKp.privateKey);
  var cpKeyId = pki.tlog.keyId(origin, logRaw);
  var cpEnvelope = cpBody + "\n" + String.fromCharCode(0x2014) + " " + origin + " " +
    Buffer.concat([cpKeyId, cpSig]).toString("base64") + "\n";
  // logId.keyId is the NON-truncated checkpoint key ID for a v2 log.
  var logIdFull = crypto.createHash("sha256")
    .update(Buffer.from(origin, "utf8")).update(Buffer.from([0x0a, 0x01])).update(logRaw).digest();

  // The timestamp authority, self-signed with the critical exclusive timeStamping EKU RFC 3161 asks
  // for, and a token over the SIGNATURE bytes.
  var tsaKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  // The authority outlives the ephemeral signing certificate, which is what lets a token be VERIFIABLE
  // and still date the signing outside the leaf's life. With one window for both, such a token cannot be
  // built and a vector about timestamp ordering would pass without exercising it.
  var tsaDer = synCert({ serial: 3n, issuer: "v2-tsa", subject: "v2-tsa", notBefore: NB,
    notAfter: new Date("2040-01-01T00:00:00Z"),
    subjectKey: tsaKp.publicKey, signerKey: tsaKp.privateKey,
    extensions: [synExt("extKeyUsage", true, B.sequence([synOid("timeStamping")]))] });
  async function mintToken(at, serial) {
    return pki.tsp.sign(
      { hashAlgorithm: "sha256", hashedMessage: crypto.createHash("sha256").update(opts.tsaOver || derSig).digest() },
      { cert: tsaDer, key: tsaKp.privateKey.export({ format: "der", type: "pkcs8" }) },
      { policy: "1.2.3", serialNumber: serial, genTime: at });
  }
  var token = await mintToken(genTime, 7);
  // Further tokens from the SAME authority over the SAME signature, at other instants. A bundle really
  // does carry these: a signature is re-timestamped while it is archived, so the token listed first need
  // not be the one made at signing.
  var extraTokens = [];
  var extraTimes = opts.extraGenTimes || [];
  for (var xt = 0; xt < extraTimes.length; xt++) {
    extraTokens.push({ signedTimestamp: (await mintToken(extraTimes[xt], 8 + xt)).toString("base64") });
  }

  var te = {
    logId: { keyId: logIdFull.toString("base64") },
    integratedTime: 0,                       // always zero on a v2 entry, and ignored
    logIndex: opts.logIndex === undefined ? 4242 : opts.logIndex,
    inclusionProof: {
      logIndex: opts.proofLogIndex === undefined ? 0 : opts.proofLogIndex,
      treeSize: 1, hashes: [], rootHash: rootHash.toString("base64"),
      checkpoint: { envelope: cpEnvelope } },
    canonicalizedBody: canonBuf.toString("base64"),
  };
  var bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: {
      certificate: { rawBytes: leafDer.toString("base64") },
      tlogEntries: [te],
      timestampVerificationData: opts.omitTimestamps === true ? undefined
        : { rfc3161Timestamps: opts.timestamps ||
            extraTokens.concat([{ signedTimestamp: token.toString("base64") }]) },
    },
  };
  if (isMsg) bundle.messageSignature = ms; else bundle.dsseEnvelope = env;
  return {
    bundle: bundle, origin: origin, genTime: genTime, artifact: opts.messageArtifact,
    trust: { fulcioRoots: [{ der: rootDer }], rekorKeys: [{ keyId: logIdFull, spki: logSpki }],
      tsaRoots: [{ der: tsaDer }], identity: { san: "https://github.com/synthetic/v2" } },
    keys: { leafPrivate: leafKp.privateKey, leafDer: leafDer, tsaDer: tsaDer, derSig: derSig, paeBytes: paeBytes },
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
  // `decoyInter` prepends an intermediate carrying the SAME subject and the SAME issuer as the real one but
  // a different key, so it did not sign the leaf. It is what a CA key rotation leaves in a bundle, and it
  // assembles by NAME while failing validation: the real sibling behind it must still be reached.
  var chainCerts = [{ rawBytes: leafDer.toString("base64") }];
  // `cyclicDecoys` prepends N intermediates whose subject AND issuer are both the real one's subject, so
  // every one of them is a candidate at every depth of the walk. They are what exhausts a step budget, and
  // they sit BEFORE the real intermediate so the search must still reach it.
  for (var cd = 0; cd < (o.cyclicDecoys || 0); cd += 1) {
    var cycKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    chainCerts.push({ rawBytes: synCert({ serial: BigInt(200 + cd), issuer: "syn-inter", subject: "syn-inter",
      notBefore: NB, notAfter: NA, subjectKey: cycKp.publicKey, signerKey: cycKp.privateKey,
      extensions: caExts }).toString("base64") });
  }
  if (o.decoyInter === true) {
    var decoyKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    var decoyDer = synCert({ serial: 22n, issuer: "syn-root", subject: "syn-inter", notBefore: NB, notAfter: NA,
      subjectKey: decoyKp.publicKey, signerKey: rootKp.privateKey, extensions: caExts });
    chainCerts.push({ rawBytes: decoyDer.toString("base64") });
  }
  chainCerts.push({ rawBytes: interDer.toString("base64") });
  var bundle = { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { tlogEntries: [te],
      x509CertificateChain: { certificates: chainCerts } },
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

  // The pinned trust lists are byte options, and the set the door admits has to be the set it handles.
  // `guard.bytes.isByteSource` admits a DataView and an ArrayBuffer; the snapshot that copies these keys
  // took neither, so a caller holding a key as the ArrayBuffer `Response.arrayBuffer()` returned had the
  // bundle refused for its container rather than its content. This runs on the REAL bundle, so the
  // narrow operation is actually reached: a probe on a malformed bundle never gets this far and its
  // silence says nothing.
  async function verifyWithKeyAs(convert) {
    var tm = trustMaterial();
    tm.rekorKeys = tm.rekorKeys.map(function (k) {
      return { keyId: convert(k.keyId), spki: convert(k.spki), validFor: k.validFor };
    });
    try {
      var r = await pki.sigstore.verifyBundle(BUNDLE, tm);
      return r && r.verified === true ? "verified" : "unverified";
    } catch (e) { return (e && e.isPkiError === true) ? "throw:" + e.code : "UNTYPED:" + ((e && e.message) || e); }
  }
  function asBuffer(b) { return Buffer.from(b); }
  function asUint8(b) { return new Uint8Array(Buffer.from(b)); }
  function asDataView(b) { var u = new Uint8Array(Buffer.from(b)); return new DataView(u.buffer); }
  function asArrayBuffer(b) { return new Uint8Array(Buffer.from(b)).buffer; }
  var repOutcomes = [];
  repOutcomes.push(["Buffer", await verifyWithKeyAs(asBuffer)]);
  repOutcomes.push(["Uint8Array", await verifyWithKeyAs(asUint8)]);
  repOutcomes.push(["DataView", await verifyWithKeyAs(asDataView)]);
  repOutcomes.push(["ArrayBuffer", await verifyWithKeyAs(asArrayBuffer)]);
  var repBase = repOutcomes[0][1];
  var repBad = repOutcomes.slice(1).filter(function (r) { return r[1] !== repBase; });
  check("BS1: a pinned rekor key verifies the same whichever byte representation holds it (" +
    repBase + (repBad.length ? "; diverged: " + repBad.map(function (r) { return r[0] + " -> " + r[1]; }).join(" | ") : "") + ")",
    repBase === "verified" && repBad.length === 0);

  // An entry is tried until one passes every entry-dependent check, and those include a path
  // validation. The count is bounded so a bundle that fits the byte budget cannot multiply that
  // work. At the ceiling the bundle still verifies; one past it is refused before any entry is
  // touched, which is why the over-ceiling bundle here carries entries that are not even objects:
  // reaching the loop would report THAT instead.
  var C_LIMITS = require("../../lib/constants.js").LIMITS;
  function withTlogCount(n, filler) {
    var b = JSON.parse(JSON.stringify(BUNDLE));
    var one = b.verificationMaterial.tlogEntries[0];
    var list = [one];
    for (var i = 1; i < n; i++) list.push(filler === undefined ? JSON.parse(JSON.stringify(one)) : filler);
    b.verificationMaterial.tlogEntries = list;
    return b;
  }
  check("a bundle AT the transparency-log entry ceiling still verifies",
    (await pki.sigstore.verifyBundle(withTlogCount(C_LIMITS.TLOG_MAX_COUNT), TM)).verified === true);
  check("a bundle one PAST the ceiling -> sigstore/bad-bundle",
    await codeOf(pki.sigstore.verifyBundle(withTlogCount(C_LIMITS.TLOG_MAX_COUNT + 1), TM)) === "sigstore/bad-bundle");
  var junkOverMsg = await pki.sigstore.verifyBundle(withTlogCount(C_LIMITS.TLOG_MAX_COUNT + 1, 7), TM)
    .then(function () { return "NO-THROW"; }, function (e) { return e.message; });
  check("the count refusal fires BEFORE any per-entry work, so non-object entries never report",
    junkOverMsg.indexOf("at most " + C_LIMITS.TLOG_MAX_COUNT) !== -1);
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

  // A path that assembles by NAME can still fail validation, and the sibling that would have validated must
  // not be lost because a same-named one was tried first. The decoy here carries the real intermediate's
  // subject AND issuer with a different key, so it did not sign the leaf: assembling stops at it, validation
  // rejects it, and the search has to resume rather than move on to the next anchor.
  var decoyChain = await buildSctChainBundle({ decoyInter: true });
  var vDecoy = await pki.sigstore.verifyBundle(decoyChain.bundle,
    Object.assign({}, decoyChain.trust, { ctLogs: decoyChain.ctLogs }));
  check("SCT-4d an intermediate that assembles by name but fails validation does not hide the one that validates",
    vDecoy.verified === true && vDecoy.sctChecked === true && vDecoy.validScts === 1);

  // And the search's own bound must not become the denial. Eight intermediates sharing the real one's
  // subject AND issuer are candidates at every depth, which is what exhausts a step budget, and they sit
  // ahead of the real one. A bundle a rotated CA produced is not required to list its certificates in any
  // helpful order, so the verdict must not depend on it.
  var cyc = await buildSctChainBundle({ cyclicDecoys: 8 });
  var tCyc = Date.now();
  var vCyc = await pki.sigstore.verifyBundle(cyc.bundle, Object.assign({}, cyc.trust, { ctLogs: cyc.ctLogs }));
  check("SCT-4e eight same-subject intermediates ahead of the real one do not exhaust the search (" +
    (Date.now() - tCyc) + "ms)", vCyc.verified === true && vCyc.validScts === 1);

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
  // A SET that is present and well formed but signed by nothing the caller pinned:
  // every key the entry's identifier selects is tried and none verifies, which is
  // the exhausted-candidates path rather than the missing-field one above.
  var badSet = JSON.parse(JSON.stringify(BUNDLE));
  var setBuf = Buffer.from(badSet.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp, "base64");
  setBuf[setBuf.length - 1] ^= 0x01;
  badSet.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp = setBuf.toString("base64");
  check("a well-formed SET that no pinned key verifies -> sigstore/unattested-time",
    await codeOf(pki.sigstore.verifyBundle(badSet, TM)) === "sigstore/unattested-time");
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

  // The bundle protobuf states the rule on the producer and again on the verifier: a bundle's DSSE
  // envelope carries exactly one signature, and a verifier rejects an envelope whose signature
  // count is not one. Only signatures[0] is ever read, so a second signature would otherwise ride
  // through a verification that never looked at it.
  check("dsseEnvelope.signatures with TWO entries -> sigstore/bad-dsse", (function () {
    var b = JSON.parse(JSON.stringify(BUNDLE));
    b.dsseEnvelope.signatures = [b.dsseEnvelope.signatures[0], JSON.parse(JSON.stringify(b.dsseEnvelope.signatures[0]))];
    try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-dsse"; }
  })());
  check("a SECOND signature is refused even when it is structurally junk, so the count is what decides", (function () {
    var b = JSON.parse(JSON.stringify(BUNDLE));
    b.dsseEnvelope.signatures = [b.dsseEnvelope.signatures[0], { sig: "AA==" }];
    try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-dsse"; }
  })());
  check("dsseEnvelope.signatures with exactly ONE still parses", (function () {
    var b = JSON.parse(JSON.stringify(BUNDLE));
    return b.dsseEnvelope.signatures.length === 1 && !!pki.sigstore.parseBundle(b);
  })());
  check("an EMPTY dsseEnvelope.signatures keeps its own refusal", (function () {
    var b = JSON.parse(JSON.stringify(BUNDLE)); b.dsseEnvelope.signatures = [];
    try { pki.sigstore.parseBundle(b); return false; } catch (e) { return e.code === "sigstore/bad-dsse"; }
  })());
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

  // --- Rekor log selection: a non-string logId.keyId is a malformed bundle; a
  // well-formed keyId that matches no caller Rekor key names a log nobody pinned.
  // The entry's own logId.keyId is what the checkpoint is bound to, so that leg is
  // the first thing such an entry cannot establish: the root it folds to is not
  // attested by the log the entry claims. The SET leg would fail too, and did
  // report first before the checkpoint was bound to the named log. ---
  var kidNum = cl(); kidNum.verificationMaterial.tlogEntries[0].logId.keyId = 123;
  check("non-string logId.keyId -> sigstore/bad-bundle", await codeOf(pki.sigstore.verifyBundle(kidNum, TM)) === "sigstore/bad-bundle");
  var kidBad = cl(); kidBad.verificationMaterial.tlogEntries[0].logId.keyId = Buffer.alloc(32, 7).toString("base64");
  check("logId.keyId matching no Rekor key -> sigstore/unsigned-root", await codeOf(pki.sigstore.verifyBundle(kidBad, TM)) === "sigstore/unsigned-root");
  var setNum = cl(); setNum.verificationMaterial.tlogEntries[0].inclusionPromise.signedEntryTimestamp = 123;
  check("non-string signedEntryTimestamp -> sigstore/unattested-time", await codeOf(pki.sigstore.verifyBundle(setNum, TM)) === "sigstore/unattested-time");

  // --- Checkpoint (C2SP signed note) parse: no separator, a root line that
  // disagrees with the inclusion-proof root, and a too-short signature blob that
  // is skipped while the real signature still verifies. ---
  var noSep = cl(); noSep.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = "no-separator-here";
  check("checkpoint with no note/signature separator -> sigstore/bad-checkpoint", await codeOf(pki.sigstore.verifyBundle(noSep, TM)) === "sigstore/bad-checkpoint");
  // The root line sits inside the text the log signed, so rewriting it breaks the
  // checkpoint's own signature. That is the fault, and it is what is reported: the
  // root is unattested. Comparing a rewritten root against the proof BEFORE
  // checking the signature would have named the mismatch instead, which reads as
  // "these two roots differ" for what is really a tampered checkpoint.
  var cpRoot = cl();
  var cpip = cpRoot.verificationMaterial.tlogEntries[0].inclusionProof;
  var cplines = cpip.checkpoint.envelope.split("\n"); cplines[2] = Buffer.alloc(32).toString("base64"); cpip.checkpoint.envelope = cplines.join("\n");
  check("a rewritten checkpoint root breaks its signature -> sigstore/unsigned-root", await codeOf(pki.sigstore.verifyBundle(cpRoot, TM)) === "sigstore/unsigned-root");
  // And the case that vector was reaching for, reached properly: the unsigned
  // inclusionProof.rootHash disagrees with the VERIFIED checkpoint root. The fold
  // uses the attested one, so the bundle's own unsigned copy carries no weight.
  var ipRoot = cl();
  ipRoot.verificationMaterial.tlogEntries[0].inclusionProof.rootHash = Buffer.alloc(32, 9).toString("base64");
  var ipRootV = await pki.sigstore.verifyBundle(ipRoot, TM);
  check("the unsigned inclusionProof.rootHash is not what the fold trusts", ipRootV && ipRootV.verified === true);
  // "Signatures are the base64 encoding of 4+n bytes", so a three-byte blob is not
  // a signature line and the note does not conform. It is refused rather than
  // passed over: a verifier that skips whatever it cannot read decides how much of
  // a note it is willing to ignore, and a malformed line is not the same thing as
  // the unknown-key line a verifier is told to ignore.
  var shortSig = cl();
  var ssip = shortSig.verificationMaterial.tlogEntries[0].inclusionProof;
  ssip.checkpoint.envelope = ssip.checkpoint.envelope.replace("\n\n", "\n\n" + String.fromCharCode(0x2014) + " x AAAA\n");
  check("a malformed checkpoint signature line refuses the note -> sigstore/bad-checkpoint",
    await codeOf(pki.sigstore.verifyBundle(shortSig, TM)) === "sigstore/bad-checkpoint");
  // A WELL-FORMED line from a key the caller did not pin is the case a verifier
  // must ignore, and it is ignored: this is the witness-cosignature shape.
  var cosigned = cl();
  var cip = cosigned.verificationMaterial.tlogEntries[0].inclusionProof;
  var cosigLine = String.fromCharCode(0x2014) + " witness.example " +
    Buffer.concat([Buffer.from([1, 2, 3, 4]), Buffer.alloc(72)]).toString("base64") + "\n";
  cip.checkpoint.envelope = cip.checkpoint.envelope + cosigLine;
  var cosV = await pki.sigstore.verifyBundle(cosigned, TM);
  check("a cosignature from an unpinned key is ignored, and the log's own line still verifies",
    cosV && cosV.verified === true);

  // --- Which log signed the root. The entry names its log in logId.keyId, and
  // the checkpoint that attests the root must be that log's. A valid signature
  // from a second pinned log over the same tree root is not evidence about this
  // log's tree, and with more than one log pinned that is the whole difference.
  await runCheckpointIsThisLogs();

  // --- The checkpoint body's own shape, which the signed-note and
  // tlog-checkpoint specifications fix and which a verifier must hold it to
  // before reading a root out of it. ---
  await runCheckpointShape();

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
  // Each of these pins a key of the WRONG type or curve whose keyId collides with
  // the log's, alongside the real key. The identifier a signed note carries is
  // derived from the key material, so such a key derives a different identifier,
  // is not a candidate for the line, and never reaches a verify; the real key is
  // still found and the bundle verifies.
  //
  // These three previously expected unsigned-root, because the resolver stopped at
  // the FIRST key whose four-byte hint matched and reported that key's failure even
  // though a later pinned key would have verified. A caller holding a stale or an
  // unrelated log key could therefore deny verification of a sound bundle.
  var WRONG_KEYS = [["Ed25519", spkiOf("ed25519")],
    ["secp384r1", spkiOf("ec", { namedCurve: "secp384r1" })],
    ["secp521r1", spkiOf("ec", { namedCurve: "secp521r1" })]];
  for (var wk = 0; wk < WRONG_KEYS.length; wk++) {
    var wv = await pki.sigstore.verifyBundle(cl(), { fulcioRoots: TM.fulcioRoots,
      rekorKeys: [injectRekorKey(WRONG_KEYS[wk][1])].concat(TM.rekorKeys) });
    check("a pinned " + WRONG_KEYS[wk][0] + " Rekor key with a colliding keyId is not a candidate, " +
      "and the real key still verifies", wv && wv.verified === true);
  }

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

  /* An in-toto predicate is ARBITRARY JSON by specification, so a fractional number in it is conforming
     and a bundle carrying one must verify. Holding every number in the document to denoting an integer
     refuses such an attestation, which no fixture can reveal, because the predicate's shape is open by
     specification rather than by convention: the rule is named onto the members that are read as
     integers, `logIndex`, `integratedTime` and `treeSize`, and nothing else is constrained.
     Both arms are needed. The accepting one proves the predicate is unconstrained; the refusing one
     proves the named members still are, so the narrowing did not simply remove the rule. */
  var fracPredicate = buildSynBundle({
    payload: { _type: "https://in-toto.io/Statement/v1", predicateType: "https://slsa.dev/provenance/v1",
      subject: [{ name: "pkg", digest: { sha512: "ab".repeat(64) } }],
      // Values that survive serialization as written. A precision-losing spelling cannot be expressed as
      // a source literal, because it collapses before `JSON.stringify` ever sees it, which is the same
      // reason the refusing arm below injects its token as text.
      //
      // `integratedTime` and `logIndex` are here DELIBERATELY. They are the names the bundle reads as
      // integers, and a predicate field is conforming whatever it is called: a rule that followed the
      // NAME rather than the document would refuse this attestation for a field that merely shares a
      // name with log metadata, which is the same failure as a document-wide rule wearing a disguise.
      predicate: { score: 0.5, confidence: 0.001, integratedTime: 0.5, logIndex: 1.25,
        nested: { ratio: 2.25, treeSize: 0.75 } } },
  });
  var fracVerdict = null, fracCode = null;
  try { fracVerdict = await pki.sigstore.verifyBundle(fracPredicate.bundle, fracPredicate.trust); }
  catch (e) { fracCode = (e && e.code) || "NO-CODE"; }
  check("a bundle whose in-toto predicate carries fractional numbers still verifies" +
    (fracCode ? " (refused " + fracCode + ")" : ""),
    fracVerdict !== null && fracVerdict.verified === true);
  /* And the named members are still held to the rule, on the bundle's own log metadata. The token is
     injected as TEXT, because the value would collapse to an integer before reaching the parser. */
  var intBundleText = JSON.stringify(synGood.bundle)
    .replace(/"logIndex":"?(\d+)"?/, "\"logIndex\":1.0000000000000001");
  var intCode = "NO-THROW";
  if (intBundleText.indexOf("1.0000000000000001") !== -1) {
    try { await pki.sigstore.verifyBundle(intBundleText, synGood.trust); }
    catch (e) { intCode = (e && e.code) || "NO-CODE"; }
  }
  check("a logIndex spelled 1.0000000000000001 is still refused, so naming the members kept the rule (" +
    intCode + ")",
    intBundleText.indexOf("1.0000000000000001") !== -1 && intCode !== "NO-THROW");

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

  // The one-identity rule has to count every GeneralName the SAN carries, not only the forms this
  // reader turns into an identity string. A SAN pairing a recognized form with an unrecognized one
  // binds two identities as surely as two URIs do, and a caller policy that matches the recognized
  // one never sees the other.
  var synMixed = buildSynBundle({ san: [gnUriDer("https://a/1"), B.contextPrimitive(7, Buffer.from([10, 0, 0, 1]))] });
  check("synthetic SAN pairing a URI with an iPAddress -> sigstore/bad-certificate",
    await codeOf(pki.sigstore.verifyBundle(synMixed.bundle, synMixed.trust)) === "sigstore/bad-certificate");
  var synMixedDir = buildSynBundle({ san: [gnUriDer("https://a/1"),
    B.contextConstructed(4, B.sequence([B.set([B.sequence([synOid("commonName"), B.utf8("dir")])])]))] });
  check("synthetic SAN pairing a URI with a directoryName -> sigstore/bad-certificate",
    await codeOf(pki.sigstore.verifyBundle(synMixedDir.bundle, synMixedDir.trust)) === "sigstore/bad-certificate");

  // A SAN this toolkit refuses elsewhere does not verify here either. The refusal comes from the
  // CHAIN leg rather than from the identity leg: pki.path.validate reads the certificate under the
  // RFC 5280 sec. 4.2.1.6 rules and stops on a dNSName carrying a control byte (CVE-2009-2408
  // class), an empty GeneralNames, or a zero-length name, so the identity leg is never reached.
  // Pinned as the code it actually answers with rather than the one the identity leg would use:
  // the property is that the bundle fails closed, and naming the wrong leg would hide it moving.
  var NUL = String.fromCharCode(0);
  var synNul = buildSynBundle({ san: [B.contextPrimitive(2, Buffer.from("a" + NUL + "b.example", "latin1"))] });
  check("synthetic SAN dNSName carrying a NUL byte does not verify",
    await codeOf(pki.sigstore.verifyBundle(synNul.bundle, synNul.trust)) === "sigstore/chain-invalid");
  var synCr = buildSynBundle({ san: [B.contextPrimitive(2, Buffer.from("a" + String.fromCharCode(13) + "b.example", "latin1"))] });
  check("synthetic SAN dNSName carrying a CR does not verify",
    await codeOf(pki.sigstore.verifyBundle(synCr.bundle, synCr.trust)) === "sigstore/chain-invalid");
  var synEmptyDns = buildSynBundle({ san: [B.contextPrimitive(2, Buffer.alloc(0))] });
  check("synthetic SAN carrying a zero-length dNSName does not verify",
    await codeOf(pki.sigstore.verifyBundle(synEmptyDns.bundle, synEmptyDns.trust)) === "sigstore/chain-invalid");
  var synEmptySan = buildSynBundle({ san: [] });
  check("synthetic empty SAN does not verify",
    await codeOf(pki.sigstore.verifyBundle(synEmptySan.bundle, synEmptySan.trust)) === "sigstore/chain-invalid");

  // CONTROL: the shapes this reader is meant to take still verify, so the rules above are the
  // shared reader's and not a refusal of everything.
  var synDnsOk = buildSynBundle({ san: [B.contextPrimitive(2, Buffer.from("build.example", "latin1"))] });
  var svDns = await pki.sigstore.verifyBundle(synDnsOk.bundle, synDnsOk.trust);
  check("CONTROL: a single well-formed dNSName still verifies and surfaces as the identity",
    svDns && svDns.verified === true && svDns.identity.san.type === "dNSName" &&
    svDns.identity.san.value === "build.example");

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

  // Two intermediates can share a subject DN, which is what a rotated CA looks like, and only one of them
  // leads to the anchor. Taking the first match by name and stopping loses a path that exists, so the walk
  // BACKTRACKS. The observable is which failure comes back: `chain-incomplete` means no path was assembled
  // at all, `chain-invalid` means one was and then did not validate. These synthetic intermediates are
  // self-signed, so no assembled path can validate; the point is that one is FOUND.
  var decoyFirst = buildSynBundle({ leafIssuer: "mid-ca", extraChain: [
    synChainCert("mid-ca", "nowhere-root"),   // same subject, issuer leads nowhere: tried first
    synChainCert("mid-ca", "syn-root"),       // same subject, issuer IS the anchor: the real one
  ] });
  var decoyCode = await codeOf(pki.sigstore.verifyBundle(decoyFirst.bundle, decoyFirst.trust));
  check("PATH-BACKTRACK a decoy intermediate sharing the real one's subject does not hide the path (" +
    decoyCode + ")", decoyCode === "sigstore/chain-invalid");
  // The control: with ONLY the real intermediate the verdict is the same, so the decoy case now behaves as
  // though the decoy were not there, which is the property. Without this the check above would also pass
  // for a walk that assembled some other wrong path.
  var realOnly = buildSynBundle({ leafIssuer: "mid-ca", extraChain: [synChainCert("mid-ca", "syn-root")] });
  check("PATH-BACKTRACK control: the same bundle without the decoy reaches the same verdict",
    (await codeOf(pki.sigstore.verifyBundle(realOnly.bundle, realOnly.trust))) === decoyCode);
  // And the decoy alone still finds nothing, so `chain-invalid` above came from the real intermediate.
  var decoyOnly = buildSynBundle({ leafIssuer: "mid-ca", extraChain: [synChainCert("mid-ca", "nowhere-root")] });
  check("PATH-BACKTRACK control: the decoy alone assembles no path",
    (await codeOf(pki.sigstore.verifyBundle(decoyOnly.bundle, decoyOnly.trust))) === "sigstore/chain-incomplete");

  // Backtracking needs a STEP bound or a bundle of same-subject decoys makes the search combinatorial,
  // which is a parser-DoS rather than a longer search. One large input, timed: a chain of decoys that
  // reaches no anchor must be abandoned promptly rather than explored.
  // Each decoy carries the SAME subject AND issuer, so every one of them is a candidate at every depth and
  // the branch factor stays at 40 all the way down. The visited check does not help: they are 40 distinct
  // certificates, not one revisited. Decoys that merely dead-end would be a linear walk and would prove
  // nothing, which is what a first version of this vector did.
  var manyDecoys = [];
  for (var dd = 0; dd < 40; dd += 1) manyDecoys.push(synChainCert("fan-ca", "fan-ca"));
  var fanOut = buildSynBundle({ leafIssuer: "fan-ca", extraChain: manyDecoys });
  var t0 = Date.now();
  var fanCode = await codeOf(pki.sigstore.verifyBundle(fanOut.bundle, fanOut.trust));
  var elapsed = Date.now() - t0;
  check("PATH-BACKTRACK 40 same-subject decoys are abandoned, not explored (" + fanCode + ", " +
    elapsed + "ms)", fanCode === "sigstore/chain-incomplete" && elapsed < 5000);

  await runMessageSignature(TM);
  await runRekorV2();
}

// ---------------------------------------------------------------------------
// The message_signature content arm (Sigstore bundle protobuf, sigstore_common
// MessageSignature). The three fixtures are the conformance suite's own vectors over one
// 109-byte artifact, so the accepting cases are an independent implementation's output rather
// than this suite's.
// ---------------------------------------------------------------------------
/** Mint a checkpoint over `rootHash` under a caller-chosen key, name and origin. This is what a
 *  DIFFERENT log's signed tree root looks like: well formed, correctly signed, and about a tree the
 *  entry never claimed. */
function mintCheckpoint(o) {
  var body = Buffer.from(o.origin + "\n" + o.size + "\n" + o.rootHash.toString("base64") + "\n", "utf8");
  var sig = crypto.sign("sha256", body, { key: o.privateKey, dsaEncoding: "der" });
  var blob = Buffer.concat([o.keyIdPrefix, sig]);
  return body.toString("utf8") + "\n" + String.fromCharCode(0x2014) + " " + o.keyName + " " +
    blob.toString("base64") + "\n";
}

async function runCheckpointIsThisLogs() {
  var syn = buildSynBundle({});
  var te0 = syn.bundle.verificationMaterial.tlogEntries[0];
  var rootHash = Buffer.from(te0.inclusionProof.rootHash, "base64");

  // A second log, whose key the caller also pins. Its key ID is the ECDSA
  // derivation the signed-note specification fixes: the SPKI alone.
  var otherKp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var otherSpki = otherKp.publicKey.export({ format: "der", type: "spki" });
  var otherKeyId = crypto.createHash("sha256").update(otherSpki).digest();
  var twoLogs = {
    fulcioRoots: syn.trust.fulcioRoots,
    rekorKeys: [syn.trust.rekorKeys[0], { keyId: otherKeyId, spki: otherSpki }],
  };

  // Control: the bundle still verifies with two logs pinned, so the refusals
  // below are about which log signed and not about pinning a second one.
  var ctl = await pki.sigstore.verifyBundle(syn.bundle, twoLogs);
  check("CP1: pinning a second Rekor log does not disturb a good bundle", ctl && ctl.verified === true);

  // The attack: swap in a checkpoint the OTHER pinned log signed, over the same
  // root. The entry still names the first log in logId.keyId.
  var swapped = JSON.parse(JSON.stringify(syn.bundle));
  swapped.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = mintCheckpoint({
    origin: "other.log", size: 1, rootHash: rootHash, privateKey: otherKp.privateKey,
    keyName: "other.log", keyIdPrefix: otherKeyId.subarray(0, 4),
  });
  var cp2 = await codeOf(pki.sigstore.verifyBundle(swapped, twoLogs));
  check("CP2: a checkpoint signed by a DIFFERENT pinned log does not attest this entry's root (got " +
    cp2 + ")", cp2 === "sigstore/unsigned-root");

  // The same swap where the other log even reuses this log's origin string: the
  // binding is to the key the entry names, not to a string in the note.
  var swappedSameOrigin = JSON.parse(JSON.stringify(syn.bundle));
  swappedSameOrigin.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = mintCheckpoint({
    origin: "rekor.local", size: 1, rootHash: rootHash, privateKey: otherKp.privateKey,
    keyName: "rekor.local", keyIdPrefix: otherKeyId.subarray(0, 4),
  });
  check("CP3: nor when that log copies this log's origin and key name",
    await codeOf(pki.sigstore.verifyBundle(swappedSameOrigin, twoLogs)) === "sigstore/unsigned-root");

  // Two signature lines naming the SAME key. The candidate list is built from the
  // distinct names the note carries, so a repeated name contributes one entry and
  // the duplicate does not multiply the keys tried.
  var repeated = JSON.parse(JSON.stringify(syn.bundle));
  var goodEnvelope = mintCheckpoint({
    origin: "rekor.local", size: 1, rootHash: rootHash, privateKey: syn.keys.rekorPrivate,
    keyName: "rekor.local", keyIdPrefix: syn.keys.rekorKeyId.subarray(0, 4),
  });
  var lastLine = goodEnvelope.slice(goodEnvelope.indexOf(String.fromCharCode(0x2014)));
  repeated.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = goodEnvelope + lastLine;
  var repV = await pki.sigstore.verifyBundle(repeated, twoLogs);
  check("CP3b: a checkpoint repeating one signer's line still verifies once", repV && repV.verified === true);

  // A pinned key carrying the RIGHT keyId but the wrong key material: it is the
  // only key the entry's identifier selects, its derived note identifier does not
  // match the signature line, so nothing matches and the root is unattested. This
  // is the verified-false path, distinct from a matched key that fails.
  var wrongMaterial = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var onlyWrong = { fulcioRoots: syn.trust.fulcioRoots, rekorKeys: [{
    keyId: syn.keys.rekorKeyId,
    spki: wrongMaterial.publicKey.export({ format: "der", type: "spki" }),
  }] };
  check("CP3c: a pinned key with the right identifier but the wrong material attests nothing",
    await codeOf(pki.sigstore.verifyBundle(syn.bundle, onlyWrong)) === "sigstore/unsigned-root");

  // And the honest re-sign: this log's own key over the same root still verifies,
  // so CP2 and CP3 are about the signer and not about the minting helper.
  var reminted = JSON.parse(JSON.stringify(syn.bundle));
  reminted.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = mintCheckpoint({
    origin: "rekor.local", size: 1, rootHash: rootHash, privateKey: syn.keys.rekorPrivate,
    keyName: "rekor.local", keyIdPrefix: syn.keys.rekorKeyId.subarray(0, 4),
  });
  var rev = await pki.sigstore.verifyBundle(reminted, twoLogs);
  check("CP4: a checkpoint re-minted under this log's own key verifies", rev && rev.verified === true);
}

async function runCheckpointShape() {
  var syn = buildSynBundle({});
  var TRUST = syn.trust;
  var rootHash = Buffer.from(syn.bundle.verificationMaterial.tlogEntries[0].inclusionProof.rootHash, "base64");
  function withEnvelope(env) {
    var b = JSON.parse(JSON.stringify(syn.bundle));
    b.verificationMaterial.tlogEntries[0].inclusionProof.checkpoint.envelope = env;
    return b;
  }
  function signedBody(text) {
    var sig = crypto.sign("sha256", Buffer.from(text, "utf8"), { key: syn.keys.rekorPrivate, dsaEncoding: "der" });
    return text + "\n" + String.fromCharCode(0x2014) + " rekor.local " +
      Buffer.concat([syn.keys.rekorKeyId.subarray(0, 4), sig]).toString("base64") + "\n";
  }
  // Control: a body minted here and signed here verifies, so each refusal below
  // is about the shape and not about the minting.
  var ok = await pki.sigstore.verifyBundle(
    withEnvelope(signedBody("rekor.local\n1\n" + rootHash.toString("base64") + "\n")), TRUST);
  check("CS1: a checkpoint body minted in this vector verifies", ok && ok.verified === true);

  // "The note text is a sequence of at least three non-empty lines."
  check("CS2: a checkpoint body of two lines is refused rather than read past its end",
    await codeOf(pki.sigstore.verifyBundle(withEnvelope(signedBody("rekor.local\n1\n")), TRUST)) === "sigstore/bad-checkpoint");
  check("CS3: an empty origin line is refused",
    await codeOf(pki.sigstore.verifyBundle(withEnvelope(signedBody("\n1\n" + rootHash.toString("base64") + "\n")), TRUST)) === "sigstore/bad-checkpoint");
  // "the ASCII decimal representation ... with no leading zeroes"
  check("CS4: a tree size with a leading zero is refused",
    await codeOf(pki.sigstore.verifyBundle(withEnvelope(signedBody("rekor.local\n01\n" + rootHash.toString("base64") + "\n")), TRUST)) === "sigstore/bad-checkpoint");
  // A root that is not 32 bytes cannot be a SHA-256 tree head.
  check("CS5: a root hash that is not 32 bytes is refused",
    await codeOf(pki.sigstore.verifyBundle(withEnvelope(signedBody("rekor.local\n1\n" + Buffer.alloc(31).toString("base64") + "\n")), TRUST)) === "sigstore/bad-checkpoint");
  // "MUST NOT contain any ASCII control characters (those below U+0020) other than newline"
  check("CS6: a control byte in the note is refused",
    await codeOf(pki.sigstore.verifyBundle(
      withEnvelope(signedBody("rekor" + String.fromCharCode(7) + ".local\n1\n" + rootHash.toString("base64") + "\n")), TRUST)) === "sigstore/bad-checkpoint");
  // "Verifiers SHOULD apply a maximum limit to the number of signatures."
  var many = signedBody("rekor.local\n1\n" + rootHash.toString("base64") + "\n");
  var pad = "";
  for (var i = 0; i < 200; i++) pad += String.fromCharCode(0x2014) + " pad" + i + " AAAAAAAA\n";
  check("CS7: a checkpoint carrying more signature lines than the cap is refused",
    await codeOf(pki.sigstore.verifyBundle(withEnvelope(many + pad), TRUST)) === "sigstore/bad-checkpoint");
  // The tree size the fold uses comes from the VERIFIED note, so a checkpoint
  // whose size disagrees with the proof geometry is refused there rather than
  // folding against a caller-supplied number.
  var cs8 = await codeOf(pki.sigstore.verifyBundle(
    withEnvelope(signedBody("rekor.local\n99\n" + rootHash.toString("base64") + "\n")), TRUST));
  check("CS8: a tree size the proof geometry cannot match is refused (got " + cs8 + ")",
    cs8 === "sigstore/bad-inclusion-proof");
}

// ---------------------------------------------------------------------------
// The Rekor v2 arm: a hashedrekord v0.0.2 entry over a DSSE signature, dated by
// an RFC 3161 token because the log issues no signed entry timestamp.
// ---------------------------------------------------------------------------
async function runRekorV2() {
  var v2 = await buildV2Bundle({});
  var ok = await pki.sigstore.verifyBundle(v2.bundle, v2.trust);
  check("V1: a Rekor v2 bundle verifies", ok && ok.verified === true);
  check("V2: and the verdict reports what the verified checkpoint said",
    ok.logOrigin === v2.origin && ok.treeSize === 1n && typeof ok.checkpointKeyId === "string" &&
    ok.checkpointKeyId.length === 8);
  check("V3: the instant is the timestamp token's, not the entry's zero",
    ok.timestampSource === "rfc3161" && ok.integratedTime === null);

  // The reported index is the one the INCLUSION PROOF established, not the one the bundle wrote beside
  // it. A v1 entry's signed entry timestamp covers `logIndex`, so there it is attested; a v2 entry has
  // no such signature, and the only index anything authenticates is the leaf index the proof folds
  // against the checkpoint-attested root. The fixture writes 4242 in the entry and proves index 0, so
  // the two disagree and a verdict reporting 4242 is reporting a number nothing signed.
  //
  // THEY ARE TWO DIFFERENT QUANTITIES AND MUST NOT BE COMPARED. The entry's index is the log's own
  // counter; the proof's is the leaf index folded against the checkpoint root. Requiring them to agree
  // refuses the v1 fixtures below, whose signed entry timestamp covers 1234 while the proof establishes
  // 0, and would refuse sound bundles in the same shape. What differs between the paths is which of the
  // two is SIGNED, not which is correct.
  check("V3a: CONTROL the fixture's entry index and proof index really do differ",
    v2.bundle.verificationMaterial.tlogEntries[0].logIndex === 4242 &&
    v2.bundle.verificationMaterial.tlogEntries[0].inclusionProof.logIndex === 0);
  check("V3b: the verdict reports the index the inclusion proof established", ok.logIndex === 0);

  // And a forged entry index cannot reach the verdict at all. These are values no proof could have
  // established, so a verdict carrying one would be attesting to the bundle's own claim.
  var forgeries = [-20, "1.5", 99999, null];
  var forged = [];
  for (var fi = 0; fi < forgeries.length; fi++) {
    var bad = await buildV2Bundle({ logIndex: forgeries[fi] });
    var r = await pki.sigstore.verifyBundle(bad.bundle, bad.trust);
    forged.push(r && r.verified === true && r.logIndex === 0);
  }
  check("V3c: a forged entry index never becomes the reported index",
    forged.length === forgeries.length && forged.every(function (x) { return x === true; }));

  // The reported index comes from the reading the PROOF used, not from a second look at the field, and
  // these two conversions do not agree on every shape. `BigInt` reads a single-element array through its
  // string form, so `["1"]` folds as leaf 1 and the proof verifies, while the numeric conversion the
  // verdict used type-guards arrays to NaN and said the entry had no index at all. One conversion, bound
  // once, or a verified proof can be reported as unverified metadata.
  check("V3d: CONTROL the two conversions really disagree on this shape",
    BigInt(["1"]) === 1n && typeof ["1"] === "object");
  var arrIdx = await buildV2Bundle({ proofLogIndex: ["0"] });
  var arrRes = await pki.sigstore.verifyBundle(arrIdx.bundle, arrIdx.trust);
  check("V3e: a proof index the fold accepted is reported as the number it folded",
    arrRes && arrRes.verified === true && arrRes.logIndex === 0);

  // A signature that is re-timestamped while it is archived carries more than one token, and the one a
  // bundle lists first need not be the one made at signing. The leaf here expires 2030-01-01, so a 2035
  // token dates the signing outside the certificate's life while the 2027 token proves it inside. Taking
  // only the first refused a bundle another token verifies, which denies a sound bundle rather than
  // enforcing anything.
  var laterFirst = await buildV2Bundle({ extraGenTimes: [new Date("2035-06-01T00:00:00Z")] });
  check("V3a: the bundle offers both tokens, the out-of-validity one first",
    laterFirst.bundle.verificationMaterial.timestampVerificationData.rfc3161Timestamps.length === 2);
  var lf = await pki.sigstore.verifyBundle(laterFirst.bundle, laterFirst.trust);
  check("V3b: a later timestamp listed first does not refuse a bundle an earlier one dates inside the certificate",
    lf && lf.verified === true && lf.timestampSource === "rfc3161");
  // The control: with ONLY the out-of-validity token the bundle must still be refused, so V3b is the
  // ordering being tolerated and not the validity check being skipped.
  var onlyLater = await buildV2Bundle({ genTime: new Date("2035-06-01T00:00:00Z") });
  var onlyLaterCode = await codeOf(pki.sigstore.verifyBundle(onlyLater.bundle, onlyLater.trust));
  check("V3c: control -- a bundle whose only token is the out-of-validity one is refused (" + onlyLaterCode + ")",
    onlyLaterCode !== "NO-THROW");

  // The pinned Rekor keys are copied before the first await, so a caller mutating its own trust material
  // while verification is in flight cannot have the checkpoint and the signed entry timestamp checked
  // under different key material filed under one identifier. Observed from the benign side: a valid
  // bundle still verifies although the caller replaces the key mid-flight.
  var mutating = await buildV2Bundle({});
  var record = mutating.trust.rekorKeys[0];
  var verdictPromise = pki.sigstore.verifyBundle(mutating.bundle, mutating.trust);
  Promise.resolve().then(function () {
    record.spki = Buffer.alloc(record.spki.length, 0x09);
    record.keyId = Buffer.alloc(record.keyId.length, 0x09);
    mutating.trust.rekorKeys[0] = { keyId: Buffer.alloc(8, 1), spki: Buffer.alloc(8, 1) };
  });
  var mutated = await verdictPromise;
  check("V3d: replacing a pinned Rekor key while verification is in flight does not change what it runs on",
    mutated && mutated.verified === true);

  // The anchors are read from the caller before the first await too. Starting with NO anchor and adding
  // the real ones while verification is pending must not decide the chain: the call was made without an
  // anchor for it. The list grows in a microtask, which is inside the window the timestamp check opens.
  var growing = await buildV2Bundle({});
  var realRoots = growing.trust.fulcioRoots;
  var emptyTrust = _assignTrust(growing.trust, { fulcioRoots: [] });
  var growingPromise = pki.sigstore.verifyBundle(growing.bundle, emptyTrust);
  Promise.resolve().then(function () { emptyTrust.fulcioRoots.push(realRoots[0]); });
  var grownCode = await codeOf(growingPromise);
  check("V3f: anchors added while verification is pending do not decide the chain (" + grownCode + ")",
    grownCode === "sigstore/chain-incomplete");
  // The control: the same anchor pinned from the start does verify, so V3f is the late addition being
  // ignored and not the anchor being unusable.
  var pinnedFromStart = await pki.sigstore.verifyBundle(growing.bundle, _assignTrust(growing.trust, { fulcioRoots: realRoots }));
  check("V3g: control -- the same anchor pinned before the call verifies", pinnedFromStart.verified === true);

  // And measured rather than inferred: each field of a pinned key record is read from the caller's object
  // exactly once, so there is no second read for a mutation to answer differently. The checkpoint and the
  // signed entry timestamp sit on either side of an await, so two reads would be two answers.
  var counted = await buildV2Bundle({});
  var src = counted.trust.rekorKeys[0];
  var reads = { keyId: 0, spki: 0, validFor: 0 };
  var probed = {};
  ["keyId", "spki", "validFor"].forEach(function (f) {
    var v = src[f];
    Object.defineProperty(probed, f, { enumerable: true, get: function () { reads[f] += 1; return v; } });
  });
  var countedTrust = _assignTrust(counted.trust, { rekorKeys: [probed] });
  var countedOk = await pki.sigstore.verifyBundle(counted.bundle, countedTrust);
  check("V3e: each pinned Rekor key field is read from the caller exactly once (keyId " + reads.keyId +
    ", spki " + reads.spki + ", validFor " + reads.validFor + ")",
    countedOk && countedOk.verified === true &&
    reads.keyId === 1 && reads.spki === 1 && reads.validFor === 1);

  // The bounds INSIDE a validity window are one read each too. Normalizing a bound takes a presence test,
  // a conversion and an assignment, which is three reads of the same member: a bound that answers the
  // first reads and then reports absent would be discarded after it had already been parsed, and the
  // window it states would impose nothing.
  var win = await buildV2Bundle({});
  var winSrc = win.trust.rekorKeys[0];
  var endReads = 0;
  var lyingWindow = {};
  Object.defineProperty(lyingWindow, "end", {
    enumerable: true,
    get: function () { endReads += 1; return endReads <= 2 ? 1 : null; },
  });
  var windowTrust = _assignTrust(win.trust, {
    rekorKeys: [{ keyId: winSrc.keyId, spki: winSrc.spki, validFor: lyingWindow }],
  });
  var windowCode = await codeOf(pki.sigstore.verifyBundle(win.bundle, windowTrust));
  check("V3h: a validity bound that reports absent on a later read is not discarded (" + windowCode +
    ", " + endReads + " read(s))", windowCode !== "NO-THROW" && endReads === 1);
  // The control: a fixed `end` of 1 refuses the same bundle, so V3h is the accessor being read once and
  // not the window being ignored altogether.
  var fixedEndCode = await codeOf(pki.sigstore.verifyBundle(win.bundle,
    _assignTrust(win.trust, { rekorKeys: [{ keyId: winSrc.keyId, spki: winSrc.spki, validFor: { end: 1 } }] })));
  check("V3i: control -- a fixed end bound of 1 refuses the bundle too (" + fixedEndCode + ")",
    fixedEndCode === windowCode);

  /* The three binding legs. Dropping any one leaves inclusion proving nothing
     about this bundle, so each is its own vector. */
  var sigSwap = await buildV2Bundle({ editBody: function (bd) {
    bd.spec.hashedRekordV002.signature.content = Buffer.alloc(70, 9).toString("base64");
  } });
  check("V4: an entry signature that is not the bundle's is refused",
    await codeOf(pki.sigstore.verifyBundle(sigSwap.bundle, sigSwap.trust)) === "sigstore/entry-mismatch");
  var otherLeaf = await buildV2Bundle({});
  var certSwap = await buildV2Bundle({ editBody: function (bd) {
    bd.spec.hashedRekordV002.signature.verifier.x509Certificate.rawBytes = otherLeaf.keys.leafDer.toString("base64");
  } });
  check("V5: an entry verifier certificate that is not the bundle leaf is refused",
    await codeOf(pki.sigstore.verifyBundle(certSwap.bundle, certSwap.trust)) === "sigstore/entry-mismatch");
  var digestSwap = await buildV2Bundle({ digest: Buffer.alloc(32, 3) });
  check("V6: a digest that is not the hash of this envelope's signing preimage is refused",
    await codeOf(pki.sigstore.verifyBundle(digestSwap.bundle, digestSwap.trust)) === "sigstore/entry-mismatch");

  /* The entry's statement about the key is held to the key. */
  var keyLie = await buildV2Bundle({ keyDetails: "PKIX_ED25519" });
  check("V7: an entry naming a key algorithm the leaf key is not is refused",
    await codeOf(pki.sigstore.verifyBundle(keyLie.bundle, keyLie.trust)) === "sigstore/entry-mismatch");
  var keyUnknown = await buildV2Bundle({ keyDetails: "PKIX_SOMETHING_NEW" });
  check("V8: an entry naming a key algorithm this build does not read is refused",
    await codeOf(pki.sigstore.verifyBundle(keyUnknown.bundle, keyUnknown.trust)) === "sigstore/bad-tlog-entry");
  var noDetails = await buildV2Bundle({ keyDetails: null });
  check("V9: an entry omitting keyDetails still verifies, since it states nothing to hold",
    (await pki.sigstore.verifyBundle(noDetails.bundle, noDetails.trust)).verified === true);

  /* A keyDetails name states more than a key FAMILY: it names the curve for an ECDSA key and the
     modulus size for an RSA one. Comparing only the SubjectPublicKeyInfo algorithm OID holds none of
     that, because every NIST curve shares the ecPublicKey OID and every RSA size shares rsaEncryption.
     So an entry could claim P-384 with SHA-384 over a P-256 key signing with SHA-256 and the statement
     the entry makes about the key would go unchecked. */
  var curveLie = await buildV2Bundle({ keyDetails: "PKIX_ECDSA_P384_SHA_384" });
  check("V9a: an entry naming P-384 over a P-256 leaf key is refused",
    await codeOf(pki.sigstore.verifyBundle(curveLie.bundle, curveLie.trust)) === "sigstore/entry-mismatch");
  var curveLie2 = await buildV2Bundle({ keyDetails: "PKIX_ECDSA_P521_SHA_512" });
  check("V9b: and so is one naming P-521 over the same key",
    await codeOf(pki.sigstore.verifyBundle(curveLie2.bundle, curveLie2.trust)) === "sigstore/entry-mismatch");
  var rsaSizeLie = await buildV2Bundle({ keyDetails: "PKIX_RSA_PKCS1V15_4096_SHA256" });
  check("V9c: an entry naming a 4096-bit RSA key over a key that is not RSA at all is refused",
    await codeOf(pki.sigstore.verifyBundle(rsaSizeLie.bundle, rsaSizeLie.trust)) === "sigstore/entry-mismatch");
  /* CONTROL: the name that DOES describe this leaf key still verifies, so the refusals above are about
     the mismatch rather than about the check rejecting every name. */
  var trueDetails = await buildV2Bundle({ keyDetails: "PKIX_ECDSA_P256_SHA_256" });
  check("V9d: CONTROL the entry naming the leaf key's actual curve verifies",
    (await pki.sigstore.verifyBundle(trueDetails.bundle, trueDetails.trust)).verified === true);

  /* A keyDetails name also states a SIGNATURE SCHEME, and a name whose scheme this build does not verify
     under must be refused rather than checked under a different one. RSA-PSS and Ed25519ph are the two:
     signatures here are verified with RSA PKCS#1 v1.5 and ordinary Ed25519, so an entry declaring either
     would have had its signature checked under the wrong scheme, accepting a PKCS#1 v1.5 signature for a
     declared PSS one and an ordinary Ed25519 signature for a declared Ed25519ph one. They are refused as
     a declaration this build does not read, which is a different verdict from a name whose key family
     merely does not match the leaf, and it is reached before that comparison. */
  var pssDecl = await buildV2Bundle({ keyDetails: "PKIX_RSA_PSS_2048_SHA256" });
  check("V9e: an entry declaring RSA-PSS is refused as a scheme this build does not verify under",
    await codeOf(pki.sigstore.verifyBundle(pssDecl.bundle, pssDecl.trust)) === "sigstore/bad-tlog-entry");
  var phDecl = await buildV2Bundle({ keyDetails: "PKIX_ED25519_PH" });
  check("V9f: and so is one declaring Ed25519ph",
    await codeOf(pki.sigstore.verifyBundle(phDecl.bundle, phDecl.trust)) === "sigstore/bad-tlog-entry");
  /* CONTROL: the RSA PKCS#1 v1.5 and plain Ed25519 names are read, so the refusals above are about the
     scheme and not about every RSA or Ed25519 name. Over this EC leaf they report a family mismatch,
     which is the verdict for a name the build reads but the key is not. */
  var rsaPkcs1 = await buildV2Bundle({ keyDetails: "PKIX_RSA_PKCS1V15_2048_SHA256" });
  check("V9g: CONTROL an RSA PKCS#1 v1.5 name is read, and mismatches this EC leaf",
    await codeOf(pki.sigstore.verifyBundle(rsaPkcs1.bundle, rsaPkcs1.trust)) === "sigstore/entry-mismatch");
  var edPlain = await buildV2Bundle({ keyDetails: "PKIX_ED25519" });
  check("V9h: CONTROL a plain Ed25519 name is read, and mismatches this EC leaf",
    await codeOf(pki.sigstore.verifyBundle(edPlain.bundle, edPlain.trust)) === "sigstore/entry-mismatch");

  /* A keyDetails that is PRESENT but not a string skipped every check above, because the block was entered
     only for a string: the entry then stated an algorithm and nothing held it to the key. Protobuf JSON
     permits an enum as its numeric value, so a number is a shape a real producer can emit, and an object
     is simply malformed. Either way a present declaration has to be read or refused, never passed over:
     an unknown STRING is already refused, so passing over a number is the looser of the two readings of
     the same field. */
  var numericDetails = await buildV2Bundle({ keyDetails: 999 });
  check("V9i: a numeric keyDetails is not passed over as though absent",
    await codeOf(pki.sigstore.verifyBundle(numericDetails.bundle, numericDetails.trust)) === "sigstore/bad-tlog-entry");
  var objectDetails = await buildV2Bundle({ keyDetails: {} });
  check("V9j: and neither is an object",
    await codeOf(pki.sigstore.verifyBundle(objectDetails.bundle, objectDetails.trust)) === "sigstore/bad-tlog-entry");
  /* CONTROL: an ABSENT keyDetails still verifies, since a declaration that was never made states nothing
     to hold. That is the case the two above must stay distinct from. */
  check("V9k: CONTROL an omitted keyDetails still verifies, stating nothing to hold",
    (await pki.sigstore.verifyBundle(noDetails.bundle, noDetails.trust)).verified === true);

  /* The time leg. */
  var noTsa = await buildV2Bundle({});
  check("V10: with no timestamp anchor pinned there is no attested instant",
    await codeOf(pki.sigstore.verifyBundle(noTsa.bundle,
      { fulcioRoots: noTsa.trust.fulcioRoots, rekorKeys: noTsa.trust.rekorKeys,
        identity: noTsa.trust.identity })) === "sigstore/no-attested-time");
  var callerTime = await buildV2Bundle({});
  var ctv = await pki.sigstore.verifyBundle(callerTime.bundle,
    { fulcioRoots: callerTime.trust.fulcioRoots, rekorKeys: callerTime.trust.rekorKeys,
      identity: callerTime.trust.identity, time: callerTime.genTime });
  check("V11: a caller instant dates the bundle without a timestamp anchor, and says so",
    ctv.verified === true && ctv.timestampSource === "caller");
  /* A token over the wrong bytes dates the wrong thing. */
  var wrongCover = await buildV2Bundle({ tsaOver: Buffer.from("not the signature") });
  check("V12: a timestamp token over bytes other than the signature does not date it",
    await codeOf(pki.sigstore.verifyBundle(wrongCover.bundle, wrongCover.trust)) === "sigstore/no-attested-time");
  /* A token whose TSA chains to no pinned anchor. */
  var otherTsa = await buildV2Bundle({});
  var foreignAnchor = await buildV2Bundle({});
  check("V13: a timestamp token whose authority chains to no pinned anchor does not date it",
    await codeOf(pki.sigstore.verifyBundle(otherTsa.bundle,
      { fulcioRoots: otherTsa.trust.fulcioRoots, rekorKeys: otherTsa.trust.rekorKeys,
        identity: otherTsa.trust.identity,
        tsaRoots: [{ der: foreignAnchor.keys.tsaDer }] })) === "sigstore/no-attested-time");
  check("V14: an empty tsaRoots list is refused rather than read as a policy that checks nothing",
    await codeOf(pki.sigstore.verifyBundle(otherTsa.bundle,
      { fulcioRoots: otherTsa.trust.fulcioRoots, rekorKeys: otherTsa.trust.rekorKeys,
        identity: otherTsa.trust.identity, tsaRoots: [] })) === "sigstore/bad-input");

  /* integratedTime is ignored, not used as a fallback: a plausible non-zero value
     must not date the bundle. */
  var fakeTime = await buildV2Bundle({});
  fakeTime.bundle.verificationMaterial.tlogEntries[0].integratedTime =
    Math.floor(fakeTime.genTime.getTime() / 1000);
  check("V15: a v2 entry's integratedTime is ignored even when it looks plausible",
    await codeOf(pki.sigstore.verifyBundle(fakeTime.bundle,
      { fulcioRoots: fakeTime.trust.fulcioRoots, rekorKeys: fakeTime.trust.rekorKeys,
        identity: fakeTime.trust.identity })) === "sigstore/no-attested-time");

  /* The unsigned inclusionProof fields are not read on this arm either. */
  var ipLies = await buildV2Bundle({});
  ipLies.bundle.verificationMaterial.tlogEntries[0].inclusionProof.rootHash = Buffer.alloc(32, 8).toString("base64");
  ipLies.bundle.verificationMaterial.tlogEntries[0].inclusionProof.treeSize = 9999;
  check("V16: the unsigned inclusionProof root and size are not what the fold trusts",
    (await pki.sigstore.verifyBundle(ipLies.bundle, ipLies.trust)).verified === true);

  /* And the v1 arm is untouched, which is the regression half. */
  var v1 = buildSynBundle({});
  var v1v = await pki.sigstore.verifyBundle(v1.bundle, v1.trust);
  check("V17: a v1 dsse bundle still verifies and still reports its SET-derived time",
    v1v.verified === true && v1v.timestampSource === "set" && typeof v1v.integratedTime === "number");

  /* The OTHER content arm. A v2 log holds a message signature as a hashedrekord
     over the artifact's own digest, so this drives the half of the binding the
     DSSE vectors above never reach. */
  var ART = Buffer.from("the artifact a v2 log recorded");
  var v2msg = await buildV2Bundle({ messageArtifact: ART });
  var mv = await pki.sigstore.verifyBundle(v2msg.bundle,
    _assignTrust(v2msg.trust, { artifact: ART }));
  check("V18: a Rekor v2 bundle on the message-signature arm verifies",
    mv.verified === true && mv.timestampSource === "rfc3161" && mv.contentType === "messageSignature");
  check("V19: and the artifact is held to the digest the v2 entry records",
    await codeOf(pki.sigstore.verifyBundle(v2msg.bundle,
      _assignTrust(v2msg.trust, { artifact: Buffer.from("a different artifact") }))) === "sigstore/artifact-mismatch");
  var v2msgShort = await buildV2Bundle({ messageArtifact: ART, digest: Buffer.alloc(31, 1) });
  check("V20: a v2 digest whose length is not its algorithm's is refused",
    await codeOf(pki.sigstore.verifyBundle(v2msgShort.bundle,
      _assignTrust(v2msgShort.trust, { artifact: ART }))) === "sigstore/bad-tlog-entry");

  /* Every field the binding reads, missing or of the wrong type. A shape guard
     that never runs is a guard nobody has checked. */
  var SHAPES = [
    ["no spec", function (bd) { delete bd.spec; }],
    ["no hashedRekordV002", function (bd) { bd.spec = {}; }],
    ["no signature object", function (bd) { delete bd.spec.hashedRekordV002.signature; }],
    ["a non-string signature content", function (bd) { bd.spec.hashedRekordV002.signature.content = 7; }],
    ["no verifier", function (bd) { delete bd.spec.hashedRekordV002.signature.verifier; }],
    ["no x509Certificate", function (bd) { delete bd.spec.hashedRekordV002.signature.verifier.x509Certificate; }],
    ["non-string rawBytes", function (bd) { bd.spec.hashedRekordV002.signature.verifier.x509Certificate.rawBytes = []; }],
    ["no data", function (bd) { delete bd.spec.hashedRekordV002.data; }],
    ["a non-string digest", function (bd) { bd.spec.hashedRekordV002.data.digest = 1; }],
    ["a digest algorithm outside the schema", function (bd) { bd.spec.hashedRekordV002.data.algorithm = "MD5"; }],
    ["no digest algorithm", function (bd) { delete bd.spec.hashedRekordV002.data.algorithm; }],
  ];
  var shapeOk = 0;
  for (var si = 0; si < SHAPES.length; si++) {
    var sb = await buildV2Bundle({ editBody: SHAPES[si][1] });
    if (await codeOf(pki.sigstore.verifyBundle(sb.bundle, sb.trust)) === "sigstore/bad-tlog-entry") shapeOk++;
    else console.log("    shape not refused as bad-tlog-entry: " + SHAPES[si][0]);
  }
  check("V21: every malformed v0.0.2 entry shape is refused as a bad entry (" + shapeOk + "/" +
    SHAPES.length + ")", shapeOk === SHAPES.length);

  /* The digest algorithm may also be the integer the JSON mapping allows. */
  var numAlg = await buildV2Bundle({ editBody: function (bd) { bd.spec.hashedRekordV002.data.algorithm = 1; } });
  check("V22: a digest algorithm given as the enum's integer is read as the name it stands for",
    (await pki.sigstore.verifyBundle(numAlg.bundle, numAlg.trust)).verified === true);

  /* The timestamp material's own shapes. */
  var noTvd = await buildV2Bundle({ omitTimestamps: true });
  check("V23: a bundle carrying no timestamp data has no instant to offer",
    await codeOf(pki.sigstore.verifyBundle(noTvd.bundle, noTvd.trust)) === "sigstore/no-attested-time");
  var nonString = await buildV2Bundle({ timestamps: [{ signedTimestamp: 9 }] });
  check("V24: a non-string signedTimestamp is passed over rather than read",
    await codeOf(pki.sigstore.verifyBundle(nonString.bundle, nonString.trust)) === "sigstore/no-attested-time");
  var notArray = await buildV2Bundle({});
  notArray.bundle.verificationMaterial.timestampVerificationData.rfc3161Timestamps = "nope";
  check("V25: a timestamp list that is not a list offers nothing",
    await codeOf(pki.sigstore.verifyBundle(notArray.bundle, notArray.trust)) === "sigstore/no-attested-time");
  var tooMany = await buildV2Bundle({});
  var many = [];
  var LIM = require("../../lib/constants.js").LIMITS;
  for (var mi = 0; mi < LIM.TLOG_MAX_COUNT + 1; mi++) many.push({ signedTimestamp: "AAAA" });
  tooMany.bundle.verificationMaterial.timestampVerificationData.rfc3161Timestamps = many;
  check("V26: more timestamps than the cap is refused rather than walked",
    await codeOf(pki.sigstore.verifyBundle(tooMany.bundle, tooMany.trust)) === "sigstore/bad-bundle");

  /* tsaRoots accepts the shapes the other trust material accepts. */
  var single = await buildV2Bundle({});
  var sv2 = await pki.sigstore.verifyBundle(single.bundle,
    _assignTrust(single.trust, { tsaRoots: single.keys.tsaDer }));
  check("V27: a single anchor outside a list is accepted, as a raw DER Buffer", sv2.verified === true);
  var rawShape = await buildV2Bundle({});
  var rv2 = await pki.sigstore.verifyBundle(rawShape.bundle,
    _assignTrust(rawShape.trust, { tsaRoots: [{ rawBytes: rawShape.keys.tsaDer }] }));
  check("V28: and the { rawBytes } spelling the bundle format uses", rv2.verified === true);
  var badShape = await buildV2Bundle({});
  check("V29: an anchor that is neither a Buffer nor { der } is refused at the door",
    await codeOf(pki.sigstore.verifyBundle(badShape.bundle,
      _assignTrust(badShape.trust, { tsaRoots: [{ nope: 1 }] }))) === "sigstore/bad-input");
}

/** Copy a trust bundle with overrides, so a vector changes one pinned thing. */
function _assignTrust(trust, over) {
  var out = {};
  Object.keys(trust).forEach(function (k) { out[k] = trust[k]; });
  Object.keys(over).forEach(function (k) { out[k] = over[k]; });
  return out;
}

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

  // An option is read the way the option gate reads it, so one supplied on the options object's
  // prototype is the same option. Reading these as own properties made an inherited artifact look
  // missing, let an inherited one pass unread on the arm that does not take it, and let an inherited
  // predicateType through the refusal and then report predicateTypeChecked for a statement that does
  // not exist.
  function inherited(extra) {
    var o = Object.create(extra);
    o.fulcioRoots = trust.fulcioRoots; o.rekorKeys = trust.rekorKeys;
    return o;
  }
  var inhArtifact = await pki.sigstore.verifyBundle(msBundle("v0.3"), inherited({ artifact: ARTIFACT }));
  check("an artifact supplied on the options prototype is read as the artifact",
    inhArtifact.verified === true && inhArtifact.artifactDigest === ARTIFACT_SHA256);
  check("an inherited predicateType is refused on a message_signature, not silently counted",
    await codeOf(pki.sigstore.verifyBundle(msBundle("v0.3"),
      (function () { var o = inherited({ predicateType: "https://slsa.dev/provenance/v1" }); o.artifact = ARTIFACT; return o; }()))) === "sigstore/bad-input");
  check("an inherited artifact is refused on a dsse bundle rather than ignored",
    await codeOf(pki.sigstore.verifyBundle(BUNDLE, inherited({ artifact: ARTIFACT }))) === "sigstore/bad-input");

  // Each option is read once and every use reads that one answer, so an option reached through an
  // accessor cannot pass a refusal with one answer and be reported by the verdict with another.
  // The counter lives outside the options object: a bookkeeping property on it is an unknown option
  // and is refused before any option is read.
  var optReads = 0;
  function accessorOpt(name, first, later) {
    var o = { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT };
    Object.defineProperty(o, name, {
      enumerable: true, configurable: true,
      get: function () { optReads++; return optReads === 1 ? first : later; },
    });
    return o;
  }
  optReads = 0;
  var ptOpt = accessorOpt("predicateType", undefined, "https://slsa.dev/provenance/v1");
  var ptErr = null, ptOut = null;
  try { ptOut = await pki.sigstore.verifyBundle(msBundle("v0.3"), ptOpt); } catch (e) { ptErr = e; }
  check("an accessor-backed predicateType cannot pass the arm refusal and then be reported as checked",
    ptErr !== null || (ptOut !== null && ptOut.predicateTypeChecked === false));
  check("and that option was read exactly once", optReads === 1);
  optReads = 0;
  var tmOpt = accessorOpt("time", new Date("2024-03-19T17:30:00Z"), undefined);
  var tmOut = null, tmErr = null;
  try { tmOut = await pki.sigstore.verifyBundle(msBundle("v0.3"), tmOpt); } catch (e) { tmErr = e; }
  check("an accessor-backed time is read exactly once", optReads === 1);
  check("and the verify reaches a verdict on that one answer",
    tmErr !== null || (tmOut !== null && tmOut.verified === true));

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

  // A log may hold more than one entry for the same signature and certificate. Choosing among them
  // asks which entry records THIS artifact, so an earlier entry that binds and names a different one
  // is passed over rather than taken and then failed. Taking the first that bound refused a bundle
  // whose later entry recorded the artifact the caller supplied.
  // The bundle's own messageDigest is omitted, so the entry's recorded hash is the ONLY thing
  // binding the artifact here. With it present, that second comparison raises the same code and
  // would answer for a log-entry comparison that had stopped running.
  var decoyBuilt = buildSynBundle({ messageArtifact: ARTIFACT, omitMessageDigest: true,
    decoyArtifact: Buffer.from("a different artifact entirely") });
  check("a decoy entry is present and is first",
    decoyBuilt.bundle.verificationMaterial.tlogEntries.length === 2);
  var decoyOut = null, decoyErr = null;
  try {
    decoyOut = await pki.sigstore.verifyBundle(decoyBuilt.bundle, {
      fulcioRoots: decoyBuilt.trust.fulcioRoots, rekorKeys: decoyBuilt.trust.rekorKeys, artifact: ARTIFACT });
  } catch (e) { decoyErr = e; }
  check("an earlier binding entry naming another artifact does not sink the verify",
    decoyErr === null && decoyOut !== null && decoyOut.verified === true);
  check("and the verdict reports the digest the matching entry recorded",
    decoyOut !== null && decoyOut.artifactDigest === crypto.createHash("sha256").update(ARTIFACT).digest("hex"));
  // The artifact still has to be recorded by SOME entry: with neither naming it, the refusal stands.
  check("with no entry naming the artifact the bundle is still refused",
    await codeOf(pki.sigstore.verifyBundle(decoyBuilt.bundle, {
      fulcioRoots: decoyBuilt.trust.fulcioRoots, rekorKeys: decoyBuilt.trust.rekorKeys,
      artifact: Buffer.from("neither of them") })) === "sigstore/artifact-mismatch");

  // The instant an entry attests decides whether the certificate covers it, so that check belongs to
  // choosing the entry too. An earlier entry attesting a moment after the leaf expired is passed
  // over for a later one the certificate does cover, rather than sinking the bundle.
  var lateBuilt = buildSynBundle({ messageArtifact: ARTIFACT, omitMessageDigest: true,
    decoyIntegratedTime: Math.floor(new Date("2035-01-01T00:00:00Z").getTime() / 1000) });
  check("a decoy entry attesting a later instant is present and first",
    lateBuilt.bundle.verificationMaterial.tlogEntries.length === 2 &&
    lateBuilt.bundle.verificationMaterial.tlogEntries[0].integratedTime >
      lateBuilt.bundle.verificationMaterial.tlogEntries[1].integratedTime);
  var lateOut = null, lateErr = null;
  try {
    lateOut = await pki.sigstore.verifyBundle(lateBuilt.bundle, {
      fulcioRoots: lateBuilt.trust.fulcioRoots, rekorKeys: lateBuilt.trust.rekorKeys, artifact: ARTIFACT });
  } catch (e) { lateErr = e; }
  check("an entry attesting an instant the certificate does not cover does not sink the verify",
    lateErr === null && lateOut !== null && lateOut.verified === true);

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
  // A v0.0.1 body relabelled 0.0.2 is not read with v0.0.1 field names. The
  // version is part of the dispatch key, so the v0.0.2 reader looks for the
  // v0.0.2 shape and refuses a body that does not carry it. This vector
  // previously expected unsupported-content, which was true only while 0.0.2 was
  // unread; what it was pinning is that a version bump is never partly parsed,
  // and that is what it pins now.
  check("a hashedrekord body relabelled 0.0.2 is not read with v0.0.1 field names",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.apiVersion = "0.0.2"; }),
      { fulcioRoots: trust.fulcioRoots, rekorKeys: trust.rekorKeys, artifact: ARTIFACT })) === "sigstore/bad-tlog-entry");
  check("a hashedrekord entry of a version this build does not read is refused",
    await codeOf(pki.sigstore.verifyBundle(
      withBody(msBundle("v0.3"), function (bd) { bd.apiVersion = "0.0.3"; }),
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
  // The Rekor field is "the public key that can verify the signature; this can also be an X509 code
  // signing certificate that contains the raw public key information", so an entry naming the key
  // itself is conforming and binds when that key is the leaf's. A different key does not bind.
  var SYN_ART_PK = Buffer.from("artifact for the public-key verifier form");
  var pubBuilt = buildSynBundle({ messageArtifact: SYN_ART_PK });
  var pubLeaf = pki.schema.x509.parse(pubBuilt.keys.leafDer);
  function pemOf(der, label) {
    return "-----BEGIN " + label + "-----\n" +
      Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "") +
      "\n-----END " + label + "-----\n";
  }
  function withSynEntryKey(built, pem) {
    var b = JSON.parse(JSON.stringify(built.bundle));
    var te2 = b.verificationMaterial.tlogEntries[0];
    var bd = JSON.parse(Buffer.from(te2.canonicalizedBody, "base64").toString("utf8"));
    bd.spec.signature.publicKey = { content: Buffer.from(pem).toString("base64") };
    te2.canonicalizedBody = Buffer.from(JSON.stringify(bd), "utf8").toString("base64");
    return b;
  }
  var pubTrust = { fulcioRoots: pubBuilt.trust.fulcioRoots, rekorKeys: pubBuilt.trust.rekorKeys, artifact: SYN_ART_PK };
  check("an entry naming the leaf's own public key rather than its certificate binds",
    await codeOf(pki.sigstore.verifyBundle(
      withSynEntryKey(pubBuilt, pemOf(pubLeaf.subjectPublicKeyInfo.bytes, "PUBLIC KEY")), pubTrust)) === "sigstore/inclusion-proof-mismatch");
  var otherKey = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  check("an entry naming a different public key does not bind",
    await codeOf(pki.sigstore.verifyBundle(
      withSynEntryKey(pubBuilt, pemOf(otherKey.publicKey.export({ format: "der", type: "spki" }), "PUBLIC KEY")), pubTrust)) === "sigstore/entry-mismatch");

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
  // JSON omits a property whose value is not written, so the document these describe is the bundle
  // itself and it is judged as that. Charging the names would refuse a bundle the text form admits.
  // The walk they cost is bounded by its own count rather than by the size.
  var muOut = await pki.sigstore.verifyBundle(manyUndef, withArtifact);
  check("a bundle of many properties the copy skips is judged as the document they describe",
    muOut.verified === true && muOut.artifactDigest === ARTIFACT_SHA256);
  check("and walking them is bounded", (Date.now() - muStart) < 10000);
  check("the same document as text is judged the same way",
    (await pki.sigstore.verifyBundle(JSON.stringify(manyUndef), withArtifact)).verified === true);

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

  // Nothing between the copy and the checks belongs to anybody else. A serializer replaced after this
  // module loaded is read when it is called, so converting the copy to text and reading it back would
  // let a replacement hand the checks a bundle carrying one content arm where the copy holds two. The
  // copy is the snapshot, so there is no such step to replace.
  var bothArms = clone(msBundle("v0.3"));
  bothArms.dsseEnvelope = { payload: "e30=", payloadType: "application/vnd.in-toto+json", signatures: [{ sig: "AA==" }] };
  var realStringify = JSON.stringify;
  var tamperCalls = 0;
  JSON.stringify = function (v) {
    tamperCalls++;
    if (v && typeof v === "object" && v.messageSignature && v.dsseEnvelope) {
      var c = Object.assign({}, v);
      delete c.messageSignature;
      return realStringify(c);
    }
    return realStringify.apply(JSON, arguments);
  };
  var tamperedCode;
  try {
    tamperedCode = await codeOf(pki.sigstore.verifyBundle(bothArms, withArtifact));
  } finally { JSON.stringify = realStringify; }
  check("a serializer replaced after load cannot drop a content arm from the copy",
    tamperedCode === "sigstore/bad-bundle");
  check("and the copy was never handed to a serializer at all", tamperCalls === 0);

  // The operations the copy decides with are taken at load, so replacing one afterwards does not
  // change what it copies. Driven through parseBundle, which is the copy and the structural rules and
  // nothing else: verifying reaches modules whose own operations are a separate question. Each is
  // swapped separately, since capturing some and reading others is the same hole with fewer
  // entrances, and each replacement is one that would change the answer if it were read.
  var realCreateForSwap = Object.create;
  var swaps = [
    ["Object.getOwnPropertyNames", Object, "getOwnPropertyNames", function () { return []; }],
    ["Object.getOwnPropertyDescriptor", Object, "getOwnPropertyDescriptor", function () { return undefined; }],
    ["Array.isArray", Array, "isArray", function () { return false; }],
    // The object the copy is built into is decided by this one, so a replacement returning something
    // that discards what is written to it drops a field the copy holds.
    ["Object.create", Object, "create", function (p) {
      var o = realCreateForSwap(p);
      return new Proxy(o, { set: function (t, k, v) { if (k === "messageSignature") return true; t[k] = v; return true; } });
    }],
    // A number is charged the digits it takes, so the conversion that counts them decides whether a
    // padded bundle passes the size limit.
    ["String", globalThis, "String", function () { return ""; }],
    // Every field the copy holds is defined with this one, so a replacement that drops the write
    // leaves the copy empty.
    ["Object.defineProperty", Object, "defineProperty", function (o) { return o; }],
    // The oneof rules are written on this question, so a replacement answering no for one arm hides
    // it and a bundle setting two arms reads as setting one.
    ["Object.prototype.hasOwnProperty", Object.prototype, "hasOwnProperty", function () { return false; }],
    // These decide which route a bundle takes and whether a value is the kind the rule is about.
    ["Buffer.isBuffer", Buffer, "isBuffer", function () { return false; }],
    ["Number.isFinite", Number, "isFinite", function () { return false; }],
    ["Number.isSafeInteger", Number, "isSafeInteger", function () { return false; }],
  ];
  for (var sw = 0; sw < swaps.length; sw++) {
    var holder = swaps[sw][1], swapName = swaps[sw][2], original = holder[swapName];
    var swappedOut = null, swappedErr = null;
    try {
      holder[swapName] = swaps[sw][3];
      swappedOut = pki.sigstore.parseBundle(clone(msBundle("v0.3")));
    } catch (e) { swappedErr = e; } finally { holder[swapName] = original; }
    check("replacing " + swaps[sw][0] + " after load does not change what the copy holds",
      swappedErr === null && swappedOut !== null &&
      swappedOut.mediaType === msBundle("v0.3").mediaType &&
      typeof swappedOut.messageSignature.signature === "string" &&
      _isArrayLike(swappedOut.verificationMaterial.tlogEntries));
  }
  function _isArrayLike(v) { return !!v && typeof v === "object" && typeof v.length === "number" && v.length > 0; }

  // The operations the VERIFY path decides with are taken at load as well. Each replacement below
  // would, read live, either break a valid bundle (an emptied split leaves no checkpoint lines, an
  // emptied filter leaves no candidate root, a NaN parse leaves no validity window) or admit a
  // tampered one (an equals answering yes binds any entry to any signature). The valid fixture must
  // still verify and the tampered entry must still be refused with this module's own code. Only the
  // operations this module reaches through its captures are listed: a replacement a neighbor module
  // reads live (the buffer text and slice operations the certificate parser uses, the array map the
  // chain builder's neighbors use) fails inside that neighbor and is that module's question.
  var tamperedEntry = JSON.parse(JSON.stringify(BUNDLE));
  (function () {
    var t = tamperedEntry.verificationMaterial.tlogEntries[0];
    var b = JSON.parse(Buffer.from(t.canonicalizedBody, "base64").toString("utf8"));
    var sig = Buffer.from(b.spec.signatures[0].signature, "base64"); sig[5] ^= 1;
    b.spec.signatures[0].signature = sig.toString("base64");
    t.canonicalizedBody = Buffer.from(JSON.stringify(b)).toString("base64");
  })();
  var verifySwaps = [
    ["Buffer.prototype.equals", Buffer.prototype, "equals", function () { return true; }],
    ["String.prototype.split", String.prototype, "split", function () { return []; }],
    ["String.prototype.indexOf", String.prototype, "indexOf", function () { return -1; }],
    ["Array.prototype.filter", Array.prototype, "filter", function () { return []; }],
    ["Array.prototype.forEach", Array.prototype, "forEach", function () {}],
    ["Date.parse", Date, "parse", function () { return NaN; }],
  ];
  // The valid bundle is verified under an identity policy naming its own SAN and issuer, so the
  // identity extraction (a prefix test on each extension OID) and the policy walk (a forEach over
  // the fields asked for) decide something a replacement could move: with either read live, the
  // policy fails to match and the verdict is identity-mismatch.
  var baselineIdentity = (await pki.sigstore.verifyBundle(BUNDLE, TM)).identity;
  var identityPolicy = { san: baselineIdentity.san.value, issuer: baselineIdentity.extensions.issuer };
  var TM_ID = Object.assign({}, TM, { identity: identityPolicy });
  for (var vs = 0; vs < verifySwaps.length; vs++) {
    var vHolder = verifySwaps[vs][1], vName = verifySwaps[vs][2], vOriginal = vHolder[vName];
    var validUnderSwap, tamperedUnderSwap;
    try {
      vHolder[vName] = verifySwaps[vs][3];
      validUnderSwap = await codeOf(pki.sigstore.verifyBundle(BUNDLE, TM_ID).then(function (v) {
        if (v.verified !== true || v.identityChecked.san !== true || v.identityChecked.issuer !== true) throw new Error("not verified under the identity policy");
      }));
      tamperedUnderSwap = await codeOf(pki.sigstore.verifyBundle(tamperedEntry, TM_ID));
    } finally { vHolder[vName] = vOriginal; }
    check("replacing " + verifySwaps[vs][0] + " after load neither breaks a valid bundle under an identity policy nor admits a tampered entry",
      validUnderSwap === "NO-THROW" && tamperedUnderSwap === "sigstore/entry-mismatch");
  }

  // A property named __proto__ is copied as a field of that name, never as a prototype. Assigning it
  // onto an ordinary object would run the inherited setter instead, which promotes whatever it holds
  // into the bundle's own fields: an object owning nothing but __proto__ would read as the bundle
  // nested inside it, while the same document as JSON text is refused for having no media type. The
  // reader this module parses text with states the same rule.
  var protoOnly = {};
  Object.defineProperty(protoOnly, "__proto__", {
    enumerable: true, configurable: true, writable: true, value: clone(msBundle("v0.3")),
  });
  check("the proto-only object really owns just that one property",
    Object.getOwnPropertyNames(protoOnly).length === 1 &&
    Object.getOwnPropertyNames(protoOnly)[0] === "__proto__");
  check("an object owning only __proto__ is refused, not read as what it holds",
    await codeOf(pki.sigstore.verifyBundle(protoOnly, withArtifact)) === "sigstore/bad-bundle-version");
  // And a bundle carrying __proto__ beside its real fields keeps it as a field, so the copy holds it
  // rather than adopting it.
  var protoBeside = clone(msBundle("v0.3"));
  Object.defineProperty(protoBeside, "__proto__", {
    enumerable: true, configurable: true, writable: true, value: { messageSignature: { signature: "AA==" } },
  });
  var protoOut = pki.sigstore.parseBundle(protoBeside);
  check("a __proto__ field is copied as a field of that name",
    Object.prototype.hasOwnProperty.call(protoOut, "__proto__") &&
    Object.getPrototypeOf(protoOut) === null);
  check("and the bundle beside it still verifies as itself",
    (await pki.sigstore.verifyBundle(protoBeside, withArtifact)).artifactDigest === ARTIFACT_SHA256);

  // The copy writes its fields as its own, never through a setter something else installed. An
  // inherited index setter on the array prototype would otherwise see every element the copy writes
  // and could hand back a different one, so a malformed element arrives valid and the checks read
  // something the caller never sent.
  var trapDesc = Object.getOwnPropertyDescriptor(Array.prototype, "0");
  var elementSeen = 0;
  var trapped = clone(msBundle("v0.3"));
  trapped.dsseEnvelope = { payload: "e30=", payloadType: "application/vnd.in-toto+json", signatures: [{ sig: 7 }] };
  delete trapped.messageSignature;
  var trappedOut = null, trappedErr = null;
  try {
    Object.defineProperty(Array.prototype, "0", {
      configurable: true,
      get: function () { return undefined; },
      set: function (v) {
        elementSeen++;
        Object.defineProperty(this, "0", {
          value: (v && typeof v === "object" && "sig" in v) ? { sig: "AA==" } : v,
          writable: true, enumerable: true, configurable: true,
        });
      },
    });
    trappedOut = pki.sigstore.parseBundle(trapped);
  } catch (e) { trappedErr = e; } finally {
    if (trapDesc) Object.defineProperty(Array.prototype, "0", trapDesc); else delete Array.prototype["0"];
  }
  check("an inherited index setter never sees what the copy writes", elementSeen === 0);
  check("and the malformed element it would have replaced is still refused",
    trappedErr !== null && trappedErr.code === "sigstore/bad-dsse" && trappedOut === null);

  // The size an object is charged is the size the same document costs as text, so one bundle is not
  // admitted one way and refused the other. A string's cost is what JSON writes it as: an escape
  // costs the characters it takes, a character outside ASCII costs its own bytes, and an unpaired
  // surrogate costs the six a \u escape takes. Counting the string's own length counts UTF-16 units,
  // which is fewer.
  var escapeHeavy = clone(msBundle("v0.3"));
  escapeHeavy.pad = "\ud800".repeat(200000);
  var asTextLength = JSON.stringify(escapeHeavy).length;
  check("the escape-heavy fixture really is over the limit as text, and under it by length",
    asTextLength > 1048576 && escapeHeavy.pad.length < 1048576);
  check("a bundle over the size limit once escaped is refused as an object too",
    await codeOf(pki.sigstore.verifyBundle(escapeHeavy, withArtifact)) === "sigstore/bad-bundle");
  check("and the same document as text is refused alike",
    await codeOf(pki.sigstore.verifyBundle(JSON.stringify(escapeHeavy), withArtifact)) !== "NO-THROW");

  // The size charged is what the document costs as text, for every kind of value rather than for
  // strings alone. These two shapes decide it in opposite directions: numbers written in exponent
  // form are long and were counted as one byte each, and array elements were counted twice, so one
  // document was admitted over the limit and another refused under it.
  var sizeCases = [
    ["numbers written in exponent form", function (b) { b.pad = new Array(200000).fill(1e100); }],
    ["empty strings in an array", function (b) { b.pad = new Array(270000).fill(""); }],
    ["nulls in an array", function (b) { b.pad = new Array(260000).fill(null); }],
    ["booleans in an array", function (b) { b.pad = new Array(200000).fill(true); }],
  ];
  for (var sc = 0; sc < sizeCases.length; sc++) {
    var sb = clone(msBundle("v0.3"));
    sizeCases[sc][1](sb);
    var asObject = await codeOf(pki.sigstore.verifyBundle(sb, withArtifact));
    var asTextCode = await codeOf(pki.sigstore.verifyBundle(JSON.stringify(sb), withArtifact));
    var overCap = Buffer.byteLength(JSON.stringify(sb), "utf8") > 1048576;
    check("a bundle padded with " + sizeCases[sc][0] + " is judged the same way as an object and as text",
      (asObject === "sigstore/bad-bundle") === overCap &&
      (asObject === "sigstore/bad-bundle") === (asTextCode === "sigstore/bad-bundle"));
  }
  // Read the other way, and across every kind of character the count prices separately: a bundle
  // carrying them verifies while what they cost stays under the limit, so the rule is the size rather
  // than the alphabet. Each string exercises one arm of the count.
  var priced = [
    ["plain ASCII", "an ordinary note"],
    ["a quote and a backslash", "a \" and a \\ inside"],
    ["the short escapes", "tab\there\nnewline\rreturn\bback\fform"],
    ["a control character with no short escape", "before" + String.fromCharCode(1) + "after"],
    ["two-byte characters", "e".repeat(8) + String.fromCharCode(0xe9).repeat(64)],
    ["three-byte characters", String.fromCharCode(0x4e2d).repeat(64)],
    ["a surrogate pair", String.fromCharCode(0xd83d, 0xde00).repeat(64)],
    ["a lone leading surrogate", "x" + String.fromCharCode(0xd800) + "y"],
    ["a lone trailing surrogate", "x" + String.fromCharCode(0xdc00) + "y"],
    ["a leading surrogate at the very end", "x" + String.fromCharCode(0xd800)],
    ["a property name that is not ASCII", null],
  ];
  for (var pz = 0; pz < priced.length; pz++) {
    var pb = clone(msBundle("v0.3"));
    if (priced[pz][1] === null) pb[String.fromCharCode(0x4e2d) + "key"] = "value";
    else pb.note = priced[pz][1];
    var pOut = await pki.sigstore.verifyBundle(pb, withArtifact);
    check("a bundle carrying " + priced[pz][0] + " verifies, its cost counted",
      pOut.verified === true && pOut.artifactDigest === ARTIFACT_SHA256);
  }

  // One depth limit governs both representations, so a bundle is not admitted one way and refused
  // the other for how deeply something unrelated to it nests. Both sides of the limit are driven.
  var depthCases = [["within the limit", 40, false], ["past it", 80, true]];
  for (var dc = 0; dc < depthCases.length; dc++) {
    var deep = clone(msBundle("v0.3"));
    var cur = deep;
    for (var dz = 0; dz < depthCases[dc][1]; dz++) { cur.nest = {}; cur = cur.nest; }
    var deepObject = await codeOf(pki.sigstore.verifyBundle(deep, withArtifact));
    var deepText = await codeOf(pki.sigstore.verifyBundle(JSON.stringify(deep), withArtifact));
    check("a bundle nesting " + depthCases[dc][0] + " is judged the same way as an object and as text",
      (deepObject === "sigstore/bad-bundle") === depthCases[dc][2] &&
      (deepObject === "sigstore/bad-bundle") === (deepText === "sigstore/bad-bundle"));
  }

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
