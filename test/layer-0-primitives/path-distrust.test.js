// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- `distrustedKeys` on pki.path.validate, pki.path.build, the OCSP responder checks and
 * pki.trust.spkiDigest.
 *
 * An entry is the SHA-256 digest of a certificate's DER SubjectPublicKeyInfo. A key is refused
 * wherever it appears: as the trust anchor, as an intermediate, as the target, and as a delegated
 * OCSP responder. Keying on the public key rather than on one certificate covers every certificate
 * that carries the key, which is what a cross-signed intermediate is: two certificates, one key.
 *
 * The chains are real-signed, and the algorithms span EC P-384 (the curve of the keys this option
 * exists to refuse), Ed25519 and RSA, because the digest is over the encoded key and an encoding
 * difference between algorithms is exactly where a digest of the wrong bytes would hide.
 */

var crypto = require("crypto");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var signing = require("../helpers/signing");
var world = require("../helpers/ocsp-world");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2030-01-01T00:00:00Z");
var AT = new Date("2027-01-01T00:00:00Z");

function sha(spki) { return crypto.createHash("sha256").update(spki).digest("hex"); }
async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return e.code || "UNTYPED"; } }
function codeOfSync(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || "UNTYPED"; } }
function rows(res) {
  var out = [];
  res.results.forEach(function (r) { r.checks.forEach(function (c) { out.push({ index: r.index, name: c.name, ok: c.ok, code: c.code }); }); });
  return out;
}
function rowAt(res, index, name) {
  return rows(res).filter(function (r) { return r.index === index && r.name === name; })[0] || null;
}

var CA_EXTS = { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] };

async function mintChain(alg) {
  var root = signing.makeSigner(alg);
  var root2 = signing.makeSigner(alg);
  var inter = signing.makeSigner(alg);
  var leaf = signing.makeSigner(alg);
  var rootDer = await pki.x509.sign({ subject: "Distrust Root " + alg, subjectPublicKey: root.spki, serialNumber: 1n,
    notBefore: NB, notAfter: NA, extensions: CA_EXTS }, { key: root.key });
  var root2Der = await pki.x509.sign({ subject: "Distrust Second Root " + alg, subjectPublicKey: root2.spki, serialNumber: 2n,
    notBefore: NB, notAfter: NA, extensions: CA_EXTS }, { key: root2.key });
  var interDer = await pki.x509.sign({ subject: "Distrust Intermediate " + alg, subjectPublicKey: inter.spki, serialNumber: 3n,
    notBefore: NB, notAfter: NA, extensions: CA_EXTS }, { cert: rootDer, key: root.key });
  // The same intermediate key and name, certified by the second root: a cross-sign.
  var crossDer = await pki.x509.sign({ subject: "Distrust Intermediate " + alg, subjectPublicKey: inter.spki, serialNumber: 4n,
    notBefore: NB, notAfter: NA, extensions: CA_EXTS }, { cert: root2Der, key: root2.key });
  var leafDer = await pki.x509.sign({ subject: "leaf.example", subjectPublicKey: leaf.spki, serialNumber: 5n,
    notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] } }, { cert: interDer, key: inter.key });
  return { alg: alg, root: root, root2: root2, inter: inter, leaf: leaf,
    rootDer: rootDer, root2Der: root2Der, interDer: interDer, crossDer: crossDer, leafDer: leafDer };
}

function validate(w, extra) {
  return pki.path.validate([w.interDer, w.leafDer], Object.assign({ time: AT, trustAnchors: [w.rootDer] }, extra || {}));
}

async function testValidate(w) {
  var tag = " [" + w.alg + "]";
  var control = await validate(w);
  check("CONTROL the chain validates with no list" + tag, control.valid === true && control.distrustedKeysApplied === false);
  var unrelated = await validate(w, { distrustedKeys: [sha(signing.makeSigner("ed25519").spki)] });
  check("CONTROL an unrelated listed key leaves the chain valid, and the list is reported applied" + tag,
    unrelated.valid === true && unrelated.distrustedKeysApplied === true);

  var inter = await validate(w, { distrustedKeys: [sha(w.inter.spki)] });
  var interRow = rowAt(inter, 0, "distrustedKey");
  check("a distrusted intermediate key fails the path with path/distrusted-key on that certificate" + tag,
    inter.valid === false && interRow && interRow.ok === false && interRow.code === "path/distrusted-key");
  check("the leaf under it carries no distrustedKey row of its own" + tag, rowAt(inter, 1, "distrustedKey") === null);

  var leaf = await validate(w, { distrustedKeys: [sha(w.leaf.spki)] });
  check("a distrusted target key fails the path on the target" + tag,
    leaf.valid === false && rowAt(leaf, 1, "distrustedKey") !== null && rowAt(leaf, 1, "distrustedKey").code === "path/distrusted-key");

  var anchor = await validate(w, { distrustedKeys: [sha(w.root.spki)] });
  var anchorRow = rowAt(anchor, 0, "distrustedIssuerKey");
  check("a distrusted trust anchor key fails the path, reported on the certificate the anchor issued" + tag,
    anchor.valid === false && anchorRow && anchorRow.code === "path/distrusted-key");

  var asBytes = await validate(w, { distrustedKeys: [crypto.createHash("sha256").update(w.inter.spki).digest()] });
  check("the 32-byte spelling refuses the same key" + tag, asBytes.valid === false && rowAt(asBytes, 0, "distrustedKey") !== null);
  var upper = await validate(w, { distrustedKeys: [sha(w.inter.spki).toUpperCase()] });
  check("the upper-case hex spelling refuses the same key" + tag, upper.valid === false);
  var viaHelper = await validate(w, { distrustedKeys: [pki.trust.spkiDigest(w.interDer)] });
  check("pki.trust.spkiDigest of the certificate names the key the option refuses" + tag, viaHelper.valid === false);
  check("pki.trust.spkiDigest of the certificate is the digest of its SubjectPublicKeyInfo" + tag,
    pki.trust.spkiDigest(w.interDer) === sha(w.inter.spki) &&
    pki.trust.spkiDigest(pki.schema.x509.parse(w.interDer)) === sha(w.inter.spki) &&
    pki.trust.spkiDigest(pki.schema.x509.pemEncode(w.interDer, "CERTIFICATE")) === sha(w.inter.spki));

  // The cross-sign carries the intermediate's key, so listing the key refuses it too, under the
  // other root.
  var cross = await pki.path.validate([w.crossDer, w.leafDer], { time: AT, trustAnchors: [w.root2Der], distrustedKeys: [sha(w.inter.spki)] });
  check("the key is refused under the cross-signing root as well" + tag, cross.valid === false && rowAt(cross, 0, "distrustedKey") !== null);
  var crossOk = await pki.path.validate([w.crossDer, w.leafDer], { time: AT, trustAnchors: [w.root2Der] });
  check("CONTROL the cross-signed path validates with no list" + tag, crossOk.valid === true);

  if (w.alg === "ec-p384") {
    // A cross-certificate carrying the intermediate's key as a compressed point. The digest
    // spkiDigest computes from it names the key, so the ordinary uncompressed certificate is refused,
    // and the other way round.
    var b = pki.asn1.build;
    var point = pki.asn1.read.bitString(pki.asn1.decode(w.inter.spki).children[1]).bytes;
    var compressed = b.sequence([b.raw(pki.asn1.decode(w.inter.spki).children[0].bytes),
      b.bitString(crypto.ECDH.convertKey(point, "secp384r1", undefined, undefined, "compressed"), 0)]);
    var compressedCross = await pki.x509.sign({ subject: "Distrust Intermediate " + w.alg, subjectPublicKey: compressed, serialNumber: 6n,
      notBefore: NB, notAfter: NA, extensions: CA_EXTS }, { cert: w.root2Der, key: w.root2.key });
    check("spkiDigest names the key, not the encoding" + tag, pki.trust.spkiDigest(compressedCross) === pki.trust.spkiDigest(w.interDer));
    var viaCompressed = await validate(w, { distrustedKeys: [pki.trust.spkiDigest(compressedCross)] });
    check("an entry computed from a compressed-point cross-certificate refuses the uncompressed intermediate" + tag,
      viaCompressed.valid === false && rowAt(viaCompressed, 0, "distrustedKey") !== null);
    var compressedPath = await pki.path.validate([compressedCross, w.leafDer], { time: AT, trustAnchors: [w.root2Der], distrustedKeys: [sha(w.inter.spki)] });
    check("an entry computed from the uncompressed key refuses the compressed-point cross-certificate" + tag,
      compressedPath.valid === false && rowAt(compressedPath, 0, "distrustedKey") !== null);
  }
}

async function testValidateInput(w) {
  check("a non-array distrustedKeys is path/bad-input",
    (await codeOf(validate(w, { distrustedKeys: sha(w.inter.spki) }))) === "path/bad-input");
  check("a malformed entry is path/bad-input", (await codeOf(validate(w, { distrustedKeys: ["nope"] }))) === "path/bad-input");
  check("a 20-byte (SHA-1) entry is path/bad-input",
    (await codeOf(validate(w, { distrustedKeys: [crypto.createHash("sha1").update(w.inter.spki).digest()] }))) === "path/bad-input");
  var nullList = await validate(w, { distrustedKeys: null });
  check("distrustedKeys: null reads as omitted", nullList.valid === true && nullList.distrustedKeysApplied === false);
  var emptyList = await validate(w, { distrustedKeys: [] });
  check("distrustedKeys: [] refuses nothing", emptyList.valid === true);

  // The list is read once at the door. A caller that swaps the entry while a revocation checker is
  // awaited cannot change what the later certificates are checked against.
  var list = [sha(signing.makeSigner("ed25519").spki)];
  var swapper = { check: async function () { list[0] = "00".repeat(32); return { status: "good" }; } };
  var swapped = await validate(w, { distrustedKeys: list, revocationChecker: swapper });
  check("the list is snapshotted at the door, not re-read across awaits", swapped.valid === true);
  var listed = [sha(w.leaf.spki)];
  var clearer = { check: async function () { listed.length = 0; return { status: "good" }; } };
  var cleared = await validate(w, { distrustedKeys: listed, revocationChecker: clearer });
  check("emptying the caller's array mid-validation does not clear the refusal", cleared.valid === false && rowAt(cleared, 1, "distrustedKey") !== null);
}

async function testRevocationNotAsked(w) {
  var asked = 0;
  var checker = { check: async function () { asked += 1; return { status: "good" }; } };
  var res = await validate(w, { distrustedKeys: [sha(w.root.spki)], revocationChecker: checker });
  check("no revocation status is asked for under a distrusted anchor", asked === 0 && res.valid === false);
  asked = 0;
  var res2 = await validate(w, { distrustedKeys: [sha(w.inter.spki)], revocationChecker: checker });
  check("no revocation status is asked for at or below a distrusted intermediate", asked === 0 && res2.valid === false);
  asked = 0;
  var res3 = await validate(w, { distrustedKeys: [sha(w.leaf.spki)], revocationChecker: checker });
  check("the intermediate above a distrusted target is still asked about", asked === 1 && res3.valid === false);
  asked = 0;
  await validate(w, { revocationChecker: checker });
  check("CONTROL with no list both certificates are asked about", asked === 2);
}

async function testBuild(w) {
  var tag = " [" + w.alg + "]";
  var base = { time: AT, candidates: [w.interDer, w.crossDer], trustAnchors: [w.rootDer, w.root2Der] };
  var ok = await pki.path.build(w.leafDer, base);
  check("CONTROL build finds a path with no list" + tag, ok.valid === true);
  var viaRoot2 = await pki.path.build(w.leafDer, Object.assign({}, base, { distrustedKeys: [sha(w.root.spki)] }));
  check("build routes around a distrusted root through the cross-sign" + tag,
    viaRoot2.valid === true && pki.trust.spkiDigest(viaRoot2.path[0]) === sha(w.inter.spki) &&
    Buffer.compare(viaRoot2.trustAnchor.publicKey, w.root2.spki) === 0);
  var noWay = await pki.path.build(w.leafDer, Object.assign({}, base, { distrustedKeys: [sha(w.inter.spki)] }));
  check("build finds no valid path when the shared intermediate key is distrusted" + tag,
    noWay.valid === false && rowAt(noWay.result, 0, "distrustedKey") !== null);
  check("build refuses distrustedKeys with validate: false",
    (await codeOf(pki.path.build(w.leafDer, Object.assign({}, base, { validate: false, distrustedKeys: [sha(w.inter.spki)] })))) === "path/bad-input");
  check("build types the list at its door even when no path assembles",
    (await codeOf(pki.path.build(w.leafDer, { time: AT, candidates: [], trustAnchors: [w.rootDer], distrustedKeys: ["nope"] }))) === "path/bad-input");
  // The leaf key is listed, so the first path tried fails on the leaf after its intermediate was
  // asked about, and the checker empties the caller's array then. A build that re-read the array
  // would accept the second (cross-signed) path.
  var listed = [sha(w.leaf.spki)];
  var res = await pki.path.build(w.leafDer, { time: AT, candidates: [w.interDer, w.crossDer], trustAnchors: [w.rootDer, w.root2Der],
    distrustedKeys: listed, revocationChecker: { check: async function () { listed.length = 0; return { status: "good" }; } } });
  check("build hands every validate the list it read at its door" + tag, listed.length === 0 && res.valid === false);
}

async function testOcspDelegate() {
  var w = await world.makeOcspWorld("ec-p384");
  var TU = new Date("2026-06-01T00:00:00Z"), NU = new Date("2028-06-01T00:00:00Z");
  var resp = await pki.ocsp.sign({ responderID: "byName", responses: [
    { cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] },
    { cert: w.responderCertDer, key: w.responderKeyPkcs8 }, { embedCert: true });
  var delegateKey = pki.trust.spkiDigest(w.responderCertDer);
  var base = { time: AT, trustAnchors: [w.issuerCertDer], revocationChecker: pki.path.ocspChecker([resp]) };
  var ok = await pki.path.validate([w.targetCertDer], base);
  check("CONTROL the delegated responder answers good", ok.valid === true && ok.revocationChecked === "determined");
  var refused = await pki.path.validate([w.targetCertDer], Object.assign({}, base, { distrustedKeys: [delegateKey] }));
  check("a delegated responder whose key is distrusted is not an authorized responder",
    refused.valid === false && refused.revocationChecked === "undetermined");

  var standaloneOk = await pki.path.verifyOcspResponse(resp, w.targetCertDer, w.issuerCertDer, AT);
  check("CONTROL verifyOcspResponse accepts the delegate", standaloneOk.status === "good");
  var standalone = await pki.path.verifyOcspResponse(resp, w.targetCertDer, w.issuerCertDer, AT, { distrustedKeys: [delegateKey] });
  check("verifyOcspResponse does not take a distrusted delegate's answer",
    standalone.status === "unknown" && standalone.responderAuthorized === false);
  var issuerKey = pki.trust.spkiDigest(w.issuerCertDer);
  var direct = await pki.ocsp.sign({ responderID: "byName", responses: [
    { cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] },
    { cert: w.issuerCertDer, key: w.issuerKeyPkcs8 });
  check("CONTROL the issuing CA answers directly", (await pki.path.verifyOcspResponse(direct, w.targetCertDer, w.issuerCertDer, AT)).status === "good");
  var directRefused = await pki.path.verifyOcspResponse(direct, w.targetCertDer, w.issuerCertDer, AT, { distrustedKeys: [issuerKey] });
  check("verifyOcspResponse does not take an answer signed by a distrusted issuing CA", directRefused.status === "unknown");
  check("verifyOcspResponse types the list",
    (await codeOf(pki.path.verifyOcspResponse(resp, w.targetCertDer, w.issuerCertDer, AT, { distrustedKeys: ["x"] }))) === "path/bad-input");
  var viaOcspVerify = await pki.ocsp.verify(resp, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: AT, distrustedKeys: [delegateKey] });
  check("pki.ocsp.verify does not take a distrusted delegate's answer", viaOcspVerify.status === "unknown");
  check("CONTROL pki.ocsp.verify takes the delegate's answer with no list",
    (await pki.ocsp.verify(resp, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: AT })).status === "good");
}

/* A listed issuing CA is refused on every route a revocation answer can arrive by: an answer it signs
 * directly, an answer from a delegate it certified, and a CRL it signs, through the checkers called
 * standalone as well as from validate. Holding the listed key is enough to mint a delegate, so a
 * delegate the listed key certified is no more an answer than the key's own signature. */
async function testListedIssuerRoutes() {
  var w = await world.makeOcspWorld("ec-p256");
  var TU = new Date("2026-06-01T00:00:00Z"), NU = new Date("2028-06-01T00:00:00Z");
  var issuerKey = pki.trust.spkiDigest(w.issuerCertDer);
  var viaDelegate = await pki.ocsp.sign({ responderID: "byName", responses: [
    { cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] },
    { cert: w.responderCertDer, key: w.responderKeyPkcs8 }, { embedCert: true });
  check("L1 CONTROL the delegate's answer is good with no list",
    (await pki.path.verifyOcspResponse(viaDelegate, w.targetCertDer, w.issuerCertDer, AT)).status === "good");
  var l1 = await pki.path.verifyOcspResponse(viaDelegate, w.targetCertDer, w.issuerCertDer, AT, { distrustedKeys: [issuerKey] });
  check("L1b verifyOcspResponse refuses a delegate certified by a listed issuing CA", l1.status === "unknown" && l1.responderAuthorized === false);
  check("L1c pki.ocsp.verify refuses it too",
    (await pki.ocsp.verify(viaDelegate, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: AT, distrustedKeys: [issuerKey] })).status === "unknown");
  var issuerParsed = pki.schema.x509.parse(w.issuerCertDer);
  var issuerCtx = { workingPublicKey: issuerParsed.subjectPublicKeyInfo.bytes, workingIssuerName: issuerParsed.subject, issuerCert: issuerParsed };
  var target = pki.schema.x509.parse(w.targetCertDer);
  var standaloneOcsp = await pki.path.ocspChecker([viaDelegate]).check(target, issuerCtx, { time: AT, distrustedKeys: [issuerKey] });
  check("L1d ocspChecker called standalone refuses it too", standaloneOcsp.status === "unknown");

  var crl = await pki.crl.sign({ thisUpdate: TU, nextUpdate: NU, crlNumber: 1n, revoked: [] },
    { cert: w.issuerCertDer, key: w.issuerKeyPkcs8 });
  var crlCheck = pki.path.crlChecker([crl]);
  check("L2 CONTROL crlChecker answers good from the issuer's CRL with no list",
    (await crlCheck.check(target, issuerCtx, { time: AT })).status === "good");
  check("L2b crlChecker called standalone does not take a CRL signed by a listed key",
    (await crlCheck.check(target, issuerCtx, { time: AT, distrustedKeys: [issuerKey] })).status === "unknown");

  var fetchCheck = pki.path.fetchingChecker({ transport: function () { return Promise.reject(new Error("not reached")); } });
  check("L3 fetchingChecker types ctx.distrustedKeys before it decodes or fetches anything",
    (await codeOf(fetchCheck.check(target, issuerCtx, { time: AT, distrustedKeys: ["nope"] }))) === "path/bad-input");
  check("L3b fetchingChecker types opts.tls.distrustedKeys when it is built",
    codeOfSync(function () {
      pki.path.fetchingChecker({ transport: function () { return Promise.reject(new Error("x")); }, tls: { distrustedKeys: ["nope"] } });
    }) === "path/bad-input");
  check("L3c fetchingChecker refuses a misspelled key in opts.tls when it is built",
    codeOfSync(function () {
      pki.path.fetchingChecker({ transport: function () { return Promise.reject(new Error("x")); }, tls: { distrustKeys: [issuerKey] } });
    }) === "path/bad-input");
  check("L4 path.build refuses a misspelled key in the AIA tls bag",
    (await codeOf(pki.path.build(w.targetCertDer, { time: AT, trustAnchors: [w.issuerCertDer], fetchAia: true,
      tls: { distrustKeys: [issuerKey] } }))) === "path/bad-input");
  check("L4b path.build types the AIA tls.distrustedKeys at its door",
    (await codeOf(pki.path.build(w.targetCertDer, { time: AT, trustAnchors: [w.issuerCertDer], fetchAia: true,
      tls: { distrustedKeys: ["nope"] } }))) === "path/bad-input");

  // A tls bag whose settings are inherited reaches the transport with them, as it did before the
  // bag was copied at the door: the copy takes each setting by value whether the bag holds it or
  // inherits it.
  var inherited = Object.create({ useSystemStore: true, distrustedKeys: [issuerKey] });
  inherited.minVersion = "TLSv1.2";
  var seenTls = [];
  function recording(req) { seenTls.push(req.tls); return Promise.reject(new Error("no network in this vector")); }
  recording.blocksPrivateAddresses = true;
  var caKp = signing.makeSigner("ec-p256");
  var aiaCa = await pki.x509.sign({ subject: "AIA Test CA", subjectPublicKey: caKp.spki, notBefore: NB, notAfter: NA, extensions: CA_EXTS },
    { key: caKp.key });
  var aiaLeafKp = signing.makeSigner("ec-p256");
  var aiaLeaf = await pki.x509.sign({ subject: "aia-leaf.example", subjectPublicKey: aiaLeafKp.spki, notBefore: NB, notAfter: NA,
    extensions: { authorityInfoAccess: [{ accessMethod: "ocsp", accessLocation: "https://93.184.216.34/ocsp" },
      { accessMethod: "caIssuers", accessLocation: "https://93.184.216.34/ca.crt" }] } }, { cert: aiaCa, key: caKp.key });
  var aiaCaParsed = pki.schema.x509.parse(aiaCa);
  await pki.path.fetchingChecker({ transport: recording, tls: inherited, allowPlaintextHttp: false })
    .check(pki.schema.x509.parse(aiaLeaf), { workingPublicKey: aiaCaParsed.subjectPublicKeyInfo.bytes, workingIssuerName: aiaCaParsed.subject, issuerCert: aiaCaParsed }, { time: AT });
  check("L5 fetchingChecker forwards the tls settings the bag inherits",
    seenTls.length >= 1 && seenTls[0].useSystemStore === true && Array.isArray(seenTls[0].distrustedKeys) &&
    seenTls[0].distrustedKeys[0] === issuerKey && seenTls[0].minVersion === "TLSv1.2");
  seenTls = [];
  var otherRoot = signing.makeSigner("ec-p256");
  var otherRootDer = await pki.x509.sign({ subject: "AIA Other Root", subjectPublicKey: otherRoot.spki, notBefore: NB, notAfter: NA, extensions: CA_EXTS },
    { key: otherRoot.key });
  await pki.path.build(aiaLeaf, { time: AT, trustAnchors: [otherRootDer], fetchAia: true, transport: recording, tls: inherited })
    .then(function () {}, function () {});
  check("L5b path.build forwards the AIA tls settings the bag inherits",
    seenTls.length >= 1 && seenTls[0].useSystemStore === true && Array.isArray(seenTls[0].distrustedKeys) &&
    seenTls[0].distrustedKeys[0] === issuerKey);
}

/* An elliptic curve certificate may omit its parameters and inherit them from its issuer (RFC 5280
 * sec. 6.1.4), and the validator verifies under the key with them spliced in. The key on its own
 * names no curve, so the check reads the key the way the validator uses it. */
async function testInheritedParameters() {
  var b = pki.asn1.build;
  var root = signing.makeSigner("ec-p256"), inter = signing.makeSigner("ec-p256"), leaf = signing.makeSigner("ec-p256");
  var rootDer = await pki.x509.sign({ subject: "Inherit Root", subjectPublicKey: root.spki, notBefore: NB, notAfter: NA, extensions: CA_EXTS }, { key: root.key });
  var absent = b.sequence([b.sequence([b.oid(pki.oid.byName("ecPublicKey"))]), b.raw(pki.asn1.decode(inter.spki).children[1].bytes)]);
  var interDer = await pki.x509.sign({ subject: "Inherit Inter", subjectPublicKey: absent, notBefore: NB, notAfter: NA, extensions: CA_EXTS },
    { cert: rootDer, key: root.key });
  var leafDer = await pki.x509.sign({ subject: "inherit.example", subjectPublicKey: leaf.spki, notBefore: NB, notAfter: NA },
    { key: inter.key, name: "Inherit Inter", publicKey: inter.spki });
  var ok = await pki.path.validate([interDer, leafDer], { time: AT, trustAnchors: [rootDer] });
  check("I1 CONTROL an intermediate that inherits its curve validates", ok.valid === true);
  var listed = await pki.path.validate([interDer, leafDer], { time: AT, trustAnchors: [rootDer], distrustedKeys: [sha(inter.spki)] });
  check("I1b an intermediate that inherits its curve is refused when its key is listed",
    listed.valid === false && rowAt(listed, 0, "distrustedKey") !== null);

  // The same key as a delegated OCSP responder under the EC CA.
  var target = await pki.x509.sign({ subject: "inherit-target.example", subjectPublicKey: signing.makeSigner("ec-p256").spki,
    notBefore: NB, notAfter: NA, serialNumber: 77n }, { cert: rootDer, key: root.key });
  var delegateOpts = { subject: "Inherit Responder", notBefore: NB, notAfter: NA,
    extensions: { extendedKeyUsage: ["ocspSigning"], ocspNoCheck: true } };
  var delegate = await pki.x509.sign(Object.assign({ subjectPublicKey: absent }, delegateOpts), { cert: rootDer, key: root.key });
  var namedDelegate = await pki.x509.sign(Object.assign({ subjectPublicKey: inter.spki }, delegateOpts), { cert: rootDer, key: root.key });
  var TU = new Date("2026-06-01T00:00:00Z"), NU = new Date("2028-06-01T00:00:00Z");
  // pki.ocsp.sign refuses a signer whose key omits its curve, so the response is signed with the
  // ordinary certificate for the same key and the embedded certificate is then swapped. The
  // signature covers tbsResponseData only, so it still verifies.
  var signed = await pki.ocsp.sign({ responderID: "byName", responses: [
    { cert: target, issuer: rootDer, status: "good", thisUpdate: TU, nextUpdate: NU }] },
    { cert: namedDelegate, key: inter.key }, { embedCert: true });
  var top = pki.asn1.decode(signed);
  var rbSeq = pki.asn1.decode(top.children[1].bytes).children[0];
  var basicDer = pki.asn1.read.octetString(rbSeq.children[1]);
  var bnode = pki.asn1.decode(basicDer);
  var rebuiltBasic = b.sequence([b.raw(bnode.children[0].bytes), b.raw(bnode.children[1].bytes), b.raw(bnode.children[2].bytes),
    b.explicit(0, b.sequence([b.raw(delegate)]))]);
  var resp = b.sequence([b.raw(top.children[0].bytes),
    b.explicit(0, b.sequence([b.raw(rbSeq.children[0].bytes), b.octetString(rebuiltBasic)]))]);
  check("I2 CONTROL a delegate that inherits its curve answers good",
    (await pki.path.verifyOcspResponse(resp, target, rootDer, AT)).status === "good");
  check("I2b a delegate that inherits its curve is not authorized when its key is listed",
    (await pki.path.verifyOcspResponse(resp, target, rootDer, AT, { distrustedKeys: [sha(inter.spki)] })).status === "unknown");
}

function testSpkiDigestInput() {
  check("pki.trust.spkiDigest refuses a non-certificate", codeOfSync(function () { pki.trust.spkiDigest(Buffer.from("nope")); }) !== "NO-THROW");
  check("pki.trust.spkiDigest refuses a missing argument", codeOfSync(function () { pki.trust.spkiDigest(); }) === "trust/bad-input");
  check("pki.trust.spkiDigest refuses an object that is not a parsed certificate",
    codeOfSync(function () { pki.trust.spkiDigest({ subjectPublicKeyInfo: { bytes: "not bytes" } }); }) === "trust/bad-input");
  check("pki.trust.spkiDigest refuses a number", codeOfSync(function () { pki.trust.spkiDigest(5); }) === "trust/bad-input");
}

async function run() {
  var algs = ["ec-p384", "ed25519", "rsa"];
  for (var i = 0; i < algs.length; i++) {
    var w = await mintChain(algs[i]);
    await testValidate(w);
    await testBuild(w);
    if (i === 0) { await testValidateInput(w); await testRevocationNotAsked(w); }
  }
  await testOcspDelegate();
  await testListedIssuerRoutes();
  await testInheritedParameters();
  testSpkiDigestInput();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("path-distrust: OK, CHECKS " + helpers.getChecks()); },
    function (e) { console.error(e && e.stack || e); process.exit(1); });
}
