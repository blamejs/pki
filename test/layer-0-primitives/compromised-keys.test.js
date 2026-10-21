// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- keys whose private key is public, refused by default with no option to turn it off.
 *
 * A key is compromised when it is on the built-in list (`pki.trust.knownCompromisedKeys()`) or when
 * it is an elliptic curve key whose private key is an integer below 256. The known answer is "EM DV
 * TLS CA - G3B", a CA certificate trusted through two roots whose P-384 private key is 156: the
 * vectors below sign with that recovered key, so the chain they validate is one a holder of the key
 * could really present.
 *
 *   G1-G6   the guard: the built-in list in each encoding, the small-scalar test, the list copy
 *   P1-P6   pki.path.validate, pki.path.build and pki.cms.verify: anchor, intermediate, target, no
 *           list given
 *   R1-R3   the revocation checkers and a delegated OCSP responder
 *   S1-S6   pki.x509.sign, pki.csr.sign and pki.crmf.build refuse to certify, sign with or request one
 *   A1-A2   pki.trust.systemAnchors skips one with trust/compromised-key
 *   L1-L2   the lint row for a listed key
 *   T1-T6   pki.transport.https refuses one on the chain and in the caller's and the proxy's anchors
 */

var crypto = require("crypto");
var https = require("node:https");
var fs = require("fs");
var os = require("os");
var path = require("path");
var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var signing = require("../helpers/signing");
var world = require("../helpers/ocsp-world");

var EM_DV_TLS_CA_G3B = [
  "-----BEGIN CERTIFICATE-----",
  "MIIDaDCCAu6gAwIBAgIQAKSu5njyM2K0wORgt3LyFDAKBggqhkjOPQQDAzBWMQsw",
  "CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl",
  "ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTU1",
  "NDA4WhcNNDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11",
  "ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNCMHYwEAYHKoZIzj0C",
  "AQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/J",
  "hZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p",
  "1E+R4VYGtjzO2rRoo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L",
  "WUIgkFQwHQYDVR0OBBYEFOIeL+ccGTkOVUtiwSAkVzUkiiUUMB0GA1UdJQQWMBQG",
  "CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow",
  "KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB",
  "BAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY",
  "aHR0cDovL29jc3AtYi5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw",
  "b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQi5wN2MwNwYDVR0f",
  "BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j",
  "cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E",
  "AwMDaAAwZQIwLmsGXi6oFMJ2klkcEMXMug6gvxQWZWkewiDWVzQyl2L6z6DuQfPO",
  "Ibh1grvdULDCAjEAxZvLlxUavG69J6wnSjC8XBbqNIQsJ6CE2QdNOe84Ptxb6VG8",
  "gt2TlfJbHii+KNvK",
  "-----END CERTIFICATE-----",
  "",
].join("\n");
// The Superfish root, installed with one private key on Lenovo laptops; the key was published in
// 2015. An RSA key, so it is refused by the list alone.
var SUPERFISH = [
  "-----BEGIN CERTIFICATE-----",
  "MIIC9TCCAl6gAwIBAgIJANL8E4epRNznMA0GCSqGSIb3DQEBBQUAMFsxGDAWBgNV",
  "BAoTD1N1cGVyZmlzaCwgSW5jLjELMAkGA1UEBxMCU0YxCzAJBgNVBAgTAkNBMQsw",
  "CQYDVQQGEwJVUzEYMBYGA1UEAxMPU3VwZXJmaXNoLCBJbmMuMB4XDTE0MDUxMjE2",
  "MjUyNloXDTM0MDUwNzE2MjUyNlowWzEYMBYGA1UEChMPU3VwZXJmaXNoLCBJbmMu",
  "MQswCQYDVQQHEwJTRjELMAkGA1UECBMCQ0ExCzAJBgNVBAYTAlVTMRgwFgYDVQQD",
  "Ew9TdXBlcmZpc2gsIEluYy4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOjz",
  "Shh2Xxk/sc9Y6X9DBwmVgDXFD/5xMSeBmRImIKXfj2r8QlU57gk4idngNsSsAYJb",
  "1Tnm+Y8HiN/+7vahFM6pdEXY/fAXVyqC4XouEpNarIrXFWPRt5tVgA9YvBxJ7SBi",
  "3bZMpTrrHD2g/3pxptMQeDOuS8Ic/ZJKocPnQaQtAgMBAAGjgcAwgb0wDAYDVR0T",
  "BAUwAwEB/zAdBgNVHQ4EFgQU+5izU38URC7o7tUJml4OVoaoNYgwgY0GA1UdIwSB",
  "hTCBgoAU+5izU38URC7o7tUJml4OVoaoNYihX6RdMFsxGDAWBgNVBAoTD1N1cGVy",
  "ZmlzaCwgSW5jLjELMAkGA1UEBxMCU0YxCzAJBgNVBAgTAkNBMQswCQYDVQQGEwJV",
  "UzEYMBYGA1UEAxMPU3VwZXJmaXNoLCBJbmMuggkA0vwTh6lE3OcwDQYJKoZIhvcN",
  "AQEFBQADgYEApHyg7ApKx3DEcWjzOyLi3JyN0JL+c35yK1VEmxu0Qusfr76645Oj",
  "1IsYwpTws6a9ZTRMzST4GQvFFQra81eLqYbPbMPuhC+FCxkUF5i0DNSWi+kczJXJ",
  "TtCqSwGl9t9JEoFqvtW+znZ9TqyLiOMw7TGEUI+88VAqW0qmXnwPcfo=",
  "-----END CERTIFICATE-----",
  "",
].join("\n");
var SUPERFISH_DIGEST = "4bb8f35ba1e126f8dde1b0c420625ed86dce61a7bddadbdea9aba578ff13145e";
var EM_DIGEST = "ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105";
var EMUDHRA_DIGESTS = [
  EM_DIGEST,
  "43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b",
  "e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41",
  "49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f",
  "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8",
  "5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0",
  "ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6",
  "92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30",
];
var ORDER_P384 = BigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");

var NB = new Date("2026-01-01T00:00:00Z");
var NA = new Date("2030-01-01T00:00:00Z");
var AT = new Date("2027-01-01T00:00:00Z");
var CA_EXTS = { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] };

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return e.code || ("RAW:" + e.message); } }
async function messageOf(p) { try { await p; return ""; } catch (e) { return String(e.message); } }
function rowAt(res, index, name) {
  var r = res.results.filter(function (x) { return x.index === index; })[0];
  return r ? r.checks.filter(function (c) { return c.name === name; })[0] || null : null;
}
function spkiOf(der) { return pki.schema.x509.parse(der).subjectPublicKeyInfo.bytes; }

/** The real certificate's key, rebuilt from its private key 156. */
function emudhraKey() {
  var k = signing.smallScalarKey("secp384r1", 156n);
  if (!k.spki.equals(Buffer.from(spkiOf(pki.schema.x509.pemDecode(EM_DV_TLS_CA_G3B, "CERTIFICATE"))))) throw new Error("the recovered key is not the certificate's");
  return k;
}

async function testGuard() {
  var g = require("../../lib/guard-all").distrust;
  var emDer = pki.schema.x509.pemDecode(EM_DV_TLS_CA_G3B, "CERTIFICATE");
  var emSpki = spkiOf(emDer);
  var why = g.compromised(emSpki);
  check("G1. the real certificate's key is compromised, and the reason names the listed certificate",
    typeof why === "string" && why.indexOf("EM DV TLS CA - G3B") !== -1);
  var b = pki.asn1.build;
  var point = pki.asn1.read.bitString(pki.asn1.decode(emSpki).children[1]).bytes;
  var compressed = b.sequence([b.raw(pki.asn1.decode(emSpki).children[0].bytes),
    b.bitString(crypto.ECDH.convertKey(point, "secp384r1", undefined, undefined, "compressed"), 0)]);
  var whyCompressed = g.compromised(compressed);
  check("G1b. the same key as a compressed point is matched against the list too",
    typeof whyCompressed === "string" && whyCompressed.indexOf("EM DV TLS CA - G3B") !== -1);
  var ecdh = b.sequence([b.sequence([b.oid(pki.oid.byName("ecDH")), b.oid(pki.oid.byName("secp384r1"))]), b.bitString(point, 0)]);
  check("G1c. the same key under id-ecDH is matched too", typeof g.compromised(ecdh) === "string");

  var sfSpki = spkiOf(pki.schema.x509.pemDecode(SUPERFISH, "CERTIFICATE"));
  var whySf = g.compromised(sfSpki);
  check("G1d. the Superfish RSA key is compromised by the list alone, and the reason names it",
    typeof whySf === "string" && whySf.indexOf("Superfish, Inc.") !== -1 && g.smallEcScalar(sfSpki) === null);
  check("G1e. its spkiDigest is the listed digest", pki.trust.spkiDigest(SUPERFISH) === SUPERFISH_DIGEST);
  var sfBits = pki.asn1.decode(sfSpki).children[1].bytes;
  var sfPss = b.sequence([b.sequence([b.oid(pki.oid.byName("rsassaPss"))]), b.raw(sfBits)]);
  check("G1f. the same RSA key under id-RSASSA-PSS is matched against the list", typeof g.compromised(sfPss) === "string");
  var sfNoNull = b.sequence([b.sequence([b.oid(pki.oid.byName("rsaEncryption"))]), b.raw(sfBits)]);
  check("G1g. the same RSA key with absent parameters instead of NULL is matched", typeof g.compromised(sfNoNull) === "string");

  var small = signing.smallScalarKey("prime256v1", 3n);
  var whySmall = g.compromised(small.spki);
  check("G2. an unlisted P-256 key whose private key is 3 is compromised by the small-scalar test",
    typeof whySmall === "string" && whySmall.indexOf("prime256v1") !== -1 && whySmall.indexOf("below 256") !== -1);
  check("G2b. smallEcScalar names the curve", g.smallEcScalar(small.spki) === "prime256v1");
  check("G2c. a private key of n-5 shares an x-coordinate with 5 and is compromised",
    g.compromised(signing.smallScalarKey("secp384r1", ORDER_P384 - 5n).spki) !== null);
  check("G2d. a private key of 256 is outside the bound", g.compromised(signing.smallScalarKey("prime256v1", 256n).spki) === null);

  var random = signing.makeSigner("ec-p384");
  check("G3. CONTROL a randomly generated key is not compromised", g.compromised(random.spki) === null);
  check("G3b. CONTROL an Ed25519 key is not compromised", g.compromised(signing.makeSigner("ed25519").spki) === null);
  check("G3c. no key is not compromised", g.compromised(null) === null && g.compromised(undefined) === null);

  check("G4. has() refuses a compromised key with no list", g.has(null, small.spki) === true && g.has([], small.spki) === true);
  check("G4b. CONTROL has() admits an unlisted key with no list", g.has(null, random.spki) === false);
  check("G4c. refusal() says a compromised key is compromised, even when the list names it too",
    g.refusal([pki.trust.spkiDigest(emDer)], emSpki, "opts.distrustedKeys").indexOf("is a compromised key") === 0);
  check("G4d. refusal() says a listed key is listed",
    g.refusal([crypto.createHash("sha256").update(random.spki).digest("hex")], random.spki, "opts.distrustedKeys") === "is listed in opts.distrustedKeys");
  check("G4e. refusal() is null for a key neither listed nor compromised", g.refusal(null, random.spki, "x") === null);

  var listed = pki.trust.knownCompromisedKeys();
  check("G5. the list holds every eMudhra key",
    EMUDHRA_DIGESTS.every(function (d) { return listed.some(function (e) { return e.spkiSha256 === d; }); }));
  check("G5b. each record carries a digest, a name, a reason and https sources",
    listed.every(function (e) {
      return /^[0-9a-f]{64}$/.test(e.spkiSha256) && typeof e.name === "string" && e.name.length > 0 &&
        typeof e.reason === "string" && e.reason.length > 0 && Array.isArray(e.sources) && e.sources.length > 0 &&
        e.sources.every(function (s) { return typeof s === "string" && s.indexOf("https://") === 0; });
    }));
  check("G5c. no digest is listed twice", new Set(listed.map(function (e) { return e.spkiSha256; })).size === listed.length);
  check("G5d. the real certificate's spkiDigest is the listed digest", pki.trust.spkiDigest(EM_DV_TLS_CA_G3B) === EM_DIGEST);
  check("G6. each record is frozen", listed.every(function (e) { return Object.isFrozen(e) && Object.isFrozen(e.sources); }));
  var n = listed.length;
  listed.length = 0;
  listed.push({ spkiSha256: "00" });
  check("G6b. the array is the caller's own: emptying it leaves the list intact", pki.trust.knownCompromisedKeys().length === n);
}

async function chainUnder(intermediateKey, opts) {
  opts = opts || {};
  var root = signing.makeSigner("ed25519");
  var rootDer = await pki.x509.sign({ subject: "Compromise Test Root", subjectPublicKey: root.spki, serialNumber: 1n,
    notBefore: NB, notAfter: NA, extensions: CA_EXTS }, { key: root.key });
  var interDer = signing.rawSignedCert({ subject: "Compromise Test Intermediate", issuerName: "Compromise Test Root",
    spki: intermediateKey.spki, issuerKey: root.keyObject, serial: 2, ca: true, notBefore: NB, notAfter: NA });
  var leafKey = opts.leafKey || signing.makeSigner("ec-p256");
  var leafDer = signing.rawSignedCert({ subject: "leaf.example", issuerName: "Compromise Test Intermediate",
    spki: leafKey.spki, issuerKey: intermediateKey.keyObject, serial: 3, notBefore: NB, notAfter: NA, san: opts.san });
  return { root: root, rootDer: rootDer, interDer: interDer, leafDer: leafDer, leafKey: leafKey };
}

async function testPath() {
  var clean = await chainUnder(signing.smallScalarKey("secp384r1", 1000n));
  var control = await pki.path.validate([clean.interDer, clean.leafDer], { time: AT, trustAnchors: [clean.rootDer] });
  check("P1. CONTROL a chain built the same way with an ordinary intermediate key validates", control.valid === true);

  var w = await chainUnder(signing.smallScalarKey("secp384r1", 7n));
  var res = await pki.path.validate([w.interDer, w.leafDer], { time: AT, trustAnchors: [w.rootDer] });
  var row = rowAt(res, 0, "compromisedKey");
  check("P2. an intermediate whose P-384 private key is 7 fails the path with no list given",
    res.valid === false && row !== null && row.ok === false && row.code === "path/compromised-key");
  check("P2b. ...the list is not reported applied, since none was given", res.distrustedKeysApplied === false);
  check("P2c. ...and the leaf under it carries no compromisedKey row of its own", rowAt(res, 1, "compromisedKey") === null);

  var leafSmall = await chainUnder(signing.smallScalarKey("secp384r1", 1001n), { leafKey: signing.smallScalarKey("prime256v1", 2n) });
  var leafRes = await pki.path.validate([leafSmall.interDer, leafSmall.leafDer], { time: AT, trustAnchors: [leafSmall.rootDer] });
  check("P3. a target whose private key is 2 fails on the target",
    leafRes.valid === false && rowAt(leafRes, 1, "compromisedKey") !== null && rowAt(leafRes, 1, "compromisedKey").code === "path/compromised-key");

  // The real certificate as the trust anchor, and a leaf signed with its recovered private key.
  var em = emudhraKey();
  var emDer = pki.schema.x509.pemDecode(EM_DV_TLS_CA_G3B, "CERTIFICATE");
  var emLeafKey = signing.makeSigner("ec-p256");
  var emLeaf = signing.rawSignedCert({ subject: "victim.example", issuerName: pki.schema.x509.parse(emDer).subject.bytes,
    spki: emLeafKey.spki, issuerKey: em.keyObject, serial: 9, notBefore: NB, notAfter: NA });
  var emRes = await pki.path.validate([emLeaf], { time: AT, trustAnchors: [emDer] });
  var emRow = rowAt(emRes, 0, "compromisedIssuerKey");
  check("P4. a leaf signed with the recovered key of the real eMudhra CA fails with that CA as the trust anchor",
    emRes.valid === false && emRow !== null && emRow.code === "path/compromised-key");
  check("P4b. ...and the signature itself verified, so the refusal is the compromised key alone",
    rowAt(emRes, 0, "signature") !== null && rowAt(emRes, 0, "signature").ok === true);

  // The Superfish root as the trust anchor. Its private key is not shipped here, so the certificate
  // under it carries a signature that does not verify; the anchor's key row is reported either way.
  var sfDer = pki.schema.x509.pemDecode(SUPERFISH, "CERTIFICATE");
  var underSf = signing.rawSignedCert({ subject: "victim.example", issuerName: pki.schema.x509.parse(sfDer).subject.bytes,
    spki: emLeafKey.spki, issuerKey: signing.makeSigner("ec-p256").keyObject, serial: 10, notBefore: NB, notAfter: NA });
  var sfRes = await pki.path.validate([underSf], { time: AT, trustAnchors: [sfDer] });
  check("P4c. the listed Superfish RSA root as the trust anchor fails the path with path/compromised-key",
    sfRes.valid === false && rowAt(sfRes, 0, "compromisedIssuerKey") !== null && rowAt(sfRes, 0, "compromisedIssuerKey").code === "path/compromised-key");

  var listedToo = await pki.path.validate([w.interDer, w.leafDer], { time: AT, trustAnchors: [w.rootDer],
    distrustedKeys: [pki.trust.spkiDigest(w.interDer)] });
  check("P5. a compromised key the caller also listed is reported as compromised",
    rowAt(listedToo, 0, "compromisedKey") !== null && rowAt(listedToo, 0, "distrustedKey") === null);

  // A verb built on path validation: a CMS signature by a leaf under the compromised intermediate.
  var content = Buffer.from("signed content");
  var cleanSigned = await pki.cms.sign(content, { cert: clean.leafDer, key: clean.leafKey.key });
  var cleanVerdict = await pki.cms.verify(cleanSigned, { trustAnchors: [clean.rootDer], certs: [clean.interDer], time: AT });
  check("P5b. CONTROL pki.cms.verify trusts a signer under an ordinary intermediate", cleanVerdict.valid === true && cleanVerdict.trusted === true);
  var badSigned = await pki.cms.sign(content, { cert: w.leafDer, key: w.leafKey.key });
  var badVerdict = await pki.cms.verify(badSigned, { trustAnchors: [w.rootDer], certs: [w.interDer], time: AT });
  check("P5c. pki.cms.verify leaves the signature valid and the signer untrusted under a compromised intermediate, with no list given",
    badVerdict.valid === true && badVerdict.trusted === false && badVerdict.signers[0].trusted === false);

  var built = await pki.path.build(w.leafDer, { time: AT, trustAnchors: [w.rootDer], intermediates: [w.interDer] });
  check("P6. pki.path.build finds no valid path through the compromised intermediate", built.valid !== true);
  var builtClean = await pki.path.build(clean.leafDer, { time: AT, trustAnchors: [clean.rootDer], intermediates: [clean.interDer] });
  check("P6b. CONTROL pki.path.build finds the ordinary path", builtClean.valid === true);
}

async function testRevocation() {
  var small = signing.smallScalarKey("secp384r1", 11n);
  var w = await chainUnder(small);
  var leaf = pki.schema.x509.parse(w.leafDer);
  var crlRes = await pki.path.crlChecker([]).check(leaf, { workingPublicKey: small.spki }, { time: AT });
  check("R1. the CRL checker answers unknown for a compromised issuer and says why",
    crlRes.status === "unknown" && String(crlRes.reason).indexOf("is a compromised key") !== -1);
  var fetchRes = await pki.path.fetchingChecker({ transport: function () { throw new Error("no fetch expected"); } })
    .check(leaf, { workingPublicKey: small.spki }, { time: AT });
  check("R2. the fetching checker answers unknown for a compromised issuer without fetching",
    fetchRes.status === "unknown" && String(fetchRes.reason).indexOf("is a compromised key") !== -1);

  // A delegated OCSP responder whose P-256 private key is 37, certified by an ordinary CA.
  var w2 = await world.makeOcspWorld("ec-p256");
  var TU = new Date("2026-06-01T00:00:00Z"), NU = new Date("2028-06-01T00:00:00Z");
  var respKey = signing.smallScalarKey("prime256v1", 37n);
  var plainKey = signing.smallScalarKey("prime256v1", 37n + (1n << 200n));
  async function answerBy(key) {
    var cert = await w2.delegate({ spki: key.spki });
    return pki.ocsp.sign({ responderID: "byName", responses: [
      { cert: w2.targetCertDer, issuer: w2.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] },
      { cert: cert, key: key.key }, { embedCert: true });
  }
  check("R3. CONTROL a delegate built the same way with an ordinary key answers good",
    (await pki.path.verifyOcspResponse(await answerBy(plainKey), w2.targetCertDer, w2.issuerCertDer, AT)).status === "good");
  var viaSmall = await pki.path.verifyOcspResponse(await answerBy(respKey), w2.targetCertDer, w2.issuerCertDer, AT);
  check("R3b. a delegate whose key is compromised is not an authorized responder, with no list given",
    viaSmall.status === "unknown" && viaSmall.responderAuthorized === false);
}

async function testSigning() {
  var small = signing.smallScalarKey("secp384r1", 13n);
  var ca = signing.makeSigner("ed25519");
  var caDer = await pki.x509.sign({ subject: "Signing Test CA", subjectPublicKey: ca.spki, notBefore: NB, notAfter: NA, extensions: CA_EXTS }, { key: ca.key });
  check("S1. pki.x509.sign refuses to certify a compromised key",
    (await codeOf(pki.x509.sign({ subject: "victim", subjectPublicKey: small.spki, notBefore: NB, notAfter: NA }, { cert: caDer, key: ca.key }))) === "x509/compromised-key");
  check("S1b. ...and the message names the field",
    (await messageOf(pki.x509.sign({ subject: "victim", subjectPublicKey: small.spki, notBefore: NB, notAfter: NA }, { cert: caDer, key: ca.key }))).indexOf("spec.subjectPublicKey is a compromised key") === 0);
  check("S2. pki.x509.sign refuses a self-signed certificate for a compromised key",
    (await codeOf(pki.x509.sign({ subject: "self", subjectPublicKey: small.spki, notBefore: NB, notAfter: NA, extensions: CA_EXTS }, { key: small.key }))) === "x509/compromised-key");
  var em = emudhraKey();
  var leaf = signing.makeSigner("ec-p256");
  check("S3. pki.x509.sign refuses to issue under the real eMudhra CA with its recovered key",
    (await codeOf(pki.x509.sign({ subject: "victim.example", subjectPublicKey: leaf.spki, notBefore: NB, notAfter: NA },
      { cert: EM_DV_TLS_CA_G3B, key: em.key }))) === "x509/compromised-key");
  check("S3b. pki.x509.sign refuses an explicit issuer whose public key is compromised",
    (await codeOf(pki.x509.sign({ subject: "victim.example", subjectPublicKey: leaf.spki, notBefore: NB, notAfter: NA },
      { key: em.key, name: "EM DV TLS CA - G3B", publicKey: em.spki }))) === "x509/compromised-key");
  check("S3c. pki.x509.sign refuses to certify the listed Superfish RSA key",
    (await codeOf(pki.x509.sign({ subject: "victim", subjectPublicKey: spkiOf(pki.schema.x509.pemDecode(SUPERFISH, "CERTIFICATE")), notBefore: NB, notAfter: NA },
      { cert: caDer, key: ca.key }))) === "x509/compromised-key");
  check("S4. CONTROL pki.x509.sign certifies an ordinary key",
    Buffer.isBuffer(await pki.x509.sign({ subject: "ok.example", subjectPublicKey: leaf.spki, notBefore: NB, notAfter: NA }, { cert: caDer, key: ca.key })));
  check("S5. pki.csr.sign refuses to request a certificate for a compromised key",
    (await codeOf(pki.csr.sign({ subject: "victim.example", subjectPublicKey: small.spki }, { key: small.key }))) === "csr/compromised-key");
  check("S5b. CONTROL pki.csr.sign signs a request for an ordinary key",
    Buffer.isBuffer(await pki.csr.sign({ subject: "ok.example", subjectPublicKey: leaf.spki }, { key: leaf.key })));
  check("S6. pki.crmf.build refuses a request whose template carries a compromised key",
    (await codeOf(pki.crmf.build({ certReqId: 0, certTemplate: { subject: "victim", publicKey: small.spki } }, { key: small.key }))) === "crmf/compromised-key");
  check("S6b. CONTROL pki.crmf.build builds a request for an ordinary key",
    Buffer.isBuffer(await pki.crmf.build({ certReqId: 0, certTemplate: { subject: "ok", publicKey: leaf.spki } }, { key: leaf.key })));
}

function testSystemAnchors() {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pki-compromised-"));
  var root = signing.makeSigner("ed25519");
  var small = signing.smallScalarKey("secp384r1", 17n);
  var compromisedRoot = signing.rawSignedCert({ subject: "Compromised Root", spki: small.spki, issuerKey: small.keyObject, ca: true, notBefore: NB, notAfter: NA });
  var cleanRoot = signing.rawSignedCert({ subject: "Clean Root", spki: root.spki, issuerKey: root.keyObject, ca: true, notBefore: NB, notAfter: NA });
  var p = path.join(dir, "bundle.pem");
  fs.writeFileSync(p, pki.schema.x509.pemEncode(cleanRoot, "CERTIFICATE") + pki.schema.x509.pemEncode(compromisedRoot, "CERTIFICATE") +
    EM_DV_TLS_CA_G3B + SUPERFISH);
  var res = pki.trust.systemAnchors({ path: p });
  check("A1. systemAnchors keeps the ordinary root and skips the compromised ones", res.anchors.length === 1);
  check("A1b. each skipped entry is reported with trust/compromised-key",
    res.skipped.length === 3 && res.skipped.every(function (s) { return s.reason.indexOf("trust/compromised-key: ") === 0; }));
  check("A1c. the listed Superfish root is skipped, and the reason names it",
    res.skipped.some(function (s) { return s.reason.indexOf("Superfish, Inc.") !== -1; }));
  check("A2. a compromised intermediate is not offered as a chain-building candidate either", res.intermediates.length === 0);
}

function testLint() {
  var report = pki.lint.certificate(EM_DV_TLS_CA_G3B);
  var row = report.findings.filter(function (f) { return f.id === "lint/key-compromise/known-compromised-key"; })[0];
  check("L1. the lint reports the real certificate as a listed key, naming the listed certificate",
    !!row && row.severity === "error" && row.context && row.context.name === "EM DV TLS CA - G3B" && row.context.spkiSha256 === EM_DIGEST);
  var randomReport = pki.lint.certificate(signing.makeSigner("ed25519").cert);
  check("L2. CONTROL an ordinary key is not reported",
    !randomReport.findings.some(function (f) { return f.id === "lint/key-compromise/known-compromised-key"; }));
}

async function testTransport() {
  var small = signing.smallScalarKey("secp384r1", 19n);
  var w = await chainUnder(small, { san: [{ dNSName: "localhost" }, { iPAddress: "127.0.0.1" }] });
  var rootPem = pki.schema.x509.pemEncode(w.rootDer, "CERTIFICATE");
  var requests = 0;
  var srv = https.createServer({
    cert: pki.schema.x509.pemEncode(w.leafDer, "CERTIFICATE") + pki.schema.x509.pemEncode(w.interDer, "CERTIFICATE"),
    key: pki.schema.pkcs8.pemEncode(w.leafKey.key, "PRIVATE KEY"),
  }, function (req, res) { requests += 1; res.end("ok"); });
  srv.on("clientError", function () {});
  var port = await new Promise(function (res) { srv.listen(0, "127.0.0.1", function () { res(srv.address().port); }); });
  var clean = await chainUnder(signing.smallScalarKey("secp384r1", 1002n), { san: [{ dNSName: "localhost" }, { iPAddress: "127.0.0.1" }] });
  var cleanSrv = https.createServer({
    cert: pki.schema.x509.pemEncode(clean.leafDer, "CERTIFICATE") + pki.schema.x509.pemEncode(clean.interDer, "CERTIFICATE"),
    key: pki.schema.pkcs8.pemEncode(clean.leafKey.key, "PRIVATE KEY"),
  }, function (req, res) { res.end("ok"); });
  cleanSrv.on("clientError", function () {});
  var cleanPort = await new Promise(function (res) { cleanSrv.listen(0, "127.0.0.1", function () { res(cleanSrv.address().port); }); });
  try {
    var t = pki.transport.https({});
    check("T1. CONTROL a server whose intermediate key is ordinary is reached",
      (await t({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/", tls: { anchors: [pki.schema.x509.pemEncode(clean.rootDer, "CERTIFICATE")] } })).status === 200);
    var msg = "";
    var code = await t({ method: "GET", url: "https://127.0.0.1:" + port + "/", tls: { anchors: [rootPem] } })
      .then(function () { return "NO-THROW"; }, function (e) { msg = String(e.message) + " " + String(e.cause && e.cause.message); return e.code; });
    check("T2. a server whose chain carries a compromised intermediate is refused with no list given (" + code + ")",
      code === "transport/server-key-compromised");
    check("T2b. the refusal says why the key is compromised", msg.indexOf("below 256") !== -1);
    check("T2c. the refused request never reached the application", requests === 0);
    var listed = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + port + "/",
      tls: { anchors: [rootPem], distrustedKeys: [pki.trust.spkiDigest(signing.makeSigner("ed25519").cert)] } }));
    check("T3. with a list given, the compromised key is still reported as compromised (" + listed + ")", listed === "transport/server-key-compromised");
    var anchorCode = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/", tls: { anchors: [EM_DV_TLS_CA_G3B] } }));
    check("T4. a caller anchor with a compromised key is refused before any connection (" + anchorCode + ")", anchorCode === "transport/bad-input");
    var defaultsCode = await codeOf(pki.transport.https({ tls: { anchors: [EM_DV_TLS_CA_G3B] } })({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/" }));
    check("T5. ...and so is one set as a transport default (" + defaultsCode + ")", defaultsCode === "transport/bad-input");
    var sfCode = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/", tls: { anchors: [SUPERFISH] } }));
    check("T5b. the listed Superfish root as a caller anchor is refused (" + sfCode + ")", sfCode === "transport/bad-input");
    var bundleCode = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/",
      tls: { anchors: [pki.schema.x509.pemEncode(clean.rootDer, "CERTIFICATE") + SUPERFISH] } }));
    check("T5c. a compromised root inside a multi-certificate PEM anchor is refused (" + bundleCode + ")", bundleCode === "transport/bad-input");
    var proxyCode = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/",
      tls: { anchors: [pki.schema.x509.pemEncode(clean.rootDer, "CERTIFICATE")] },
      proxy: { url: "https://127.0.0.1:1", tls: { anchors: [EM_DV_TLS_CA_G3B] } } }));
    check("T6. a proxy anchor with a compromised key is refused before any connection (" + proxyCode + ")", proxyCode === "transport/bad-proxy");

    // A caller's identity hook runs after the check reads the chain, so it cannot hide the chain by
    // changing the certificate object node hands it, and a hook that throws is a refusal.
    var erased = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + port + "/", tls: { anchors: [rootPem],
      checkServerIdentity: function (host, cert) { cert.raw = undefined; cert.issuerCertificate = undefined; return undefined; } } }));
    check("T7. a caller hook that erases the chain from the certificate object does not hide the compromised key (" + erased + ")",
      erased === "transport/server-key-compromised");
    var threw = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/",
      tls: { anchors: [pki.schema.x509.pemEncode(clean.rootDer, "CERTIFICATE")], checkServerIdentity: function () { throw new Error("hook failed"); } } }));
    check("T8. a caller hook that throws refuses the server with a typed code instead of escaping (" + threw + ")",
      threw === "transport/server-auth-failed");
    // A hook that installs throwing setters for the properties the refusal carries. The refusal is
    // built after the hook returns, so it defines those properties rather than assigning them.
    var polluted = ["pkiCompromisedKey", "pkiDistrustedKey", "cause"];
    var setterCode;
    try {
      setterCode = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + port + "/", tls: { anchors: [rootPem],
        checkServerIdentity: function () {
          polluted.forEach(function (k) {
            Object.defineProperty(Object.prototype, k, { configurable: true, set: function () { throw new Error("setter " + k); } });
          });
          return undefined;
        } } }));
    } finally {
      polluted.forEach(function (k) { delete Object.prototype[k]; });
    }
    check("T8b. a hook that installs throwing setters cannot make the refusal throw out of the identity check (" + setterCode + ")",
      setterCode === "transport/server-key-compromised");
    var getCode;
    try {
      getCode = await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/",
        tls: { anchors: [pki.schema.x509.pemEncode(clean.rootDer, "CERTIFICATE")], checkServerIdentity: function () {
          Object.defineProperty(Object.prototype, "get", { configurable: true, writable: true, value: function () { return undefined; } });
          // eslint-disable-next-line no-throw-literal -- the vector is a hook that throws a non-Error value
          throw 0;
        } } }));
    } finally { delete Object.prototype.get; }
    check("T8c. a hook that installs Object.prototype.get and throws a non-Error is still a typed refusal (" + getCode + ")",
      getCode === "transport/server-auth-failed");
    // Pollution left by an earlier hook is in place when a later connection builds its refusal. A
    // listed key's refusal reads a field its record does not carry, so the inherited getter runs. The
    // later request carries no tls bag of its own: its settings are the transport defaults, read when
    // the transport was built, before the pollution.
    var laterCode;
    var listing = pki.transport.https({ tls: { anchors: [pki.schema.x509.pemEncode(clean.rootDer, "CERTIFICATE")],
      distrustedKeys: [pki.trust.spkiDigest(clean.leafDer)] } });
    try {
      await codeOf(t({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/",
        tls: { anchors: [pki.schema.x509.pemEncode(clean.rootDer, "CERTIFICATE")], checkServerIdentity: function () {
          Object.defineProperty(Object.prototype, "unchecked", { configurable: true, get: function () { throw new Error("getter unchecked"); } });
          return undefined;
        } } }));
      laterCode = await codeOf(listing({ method: "GET", url: "https://127.0.0.1:" + cleanPort + "/" }));
    } finally { delete Object.prototype.unchecked; }
    check("T8d. a refusal built under pollution an earlier hook left is still a typed refusal (" + laterCode + ")",
      laterCode === "transport/server-key-distrusted" || laterCode === "transport/server-auth-failed");
  } finally {
    srv.close(); cleanSrv.close();
  }

  // A served chain longer than the check reads. The leaf is issued by the anchor, which OpenSSL
  // verifies directly; the server also sends a certificate carrying the anchor's name issued by a
  // run of 101 decoys, so the chain node reports runs past the cap before it ends.
  var anchor = signing.makeSigner("ed25519");
  var anchorDer = signing.rawSignedCert({ subject: "Long Walk Root", spki: anchor.spki, issuerKey: anchor.keyObject, ca: true });
  var longLeaf = signing.makeSigner("ec-p256");
  var longLeafDer = signing.rawSignedCert({ subject: "localhost", issuerName: "Long Walk Root", spki: longLeaf.spki,
    issuerKey: anchor.keyObject, serial: 2, san: [{ dNSName: "localhost" }, { iPAddress: "127.0.0.1" }] });
  var served = [longLeafDer];
  var decoyKey = signing.makeSigner("ed25519");
  served.push(signing.rawSignedCert({ subject: "Long Walk Root", issuerName: "Decoy 0", spki: decoyKey.spki, issuerKey: decoyKey.keyObject, serial: 3, ca: true }));
  for (var d = 0; d < 101; d++) {
    served.push(signing.rawSignedCert({ subject: "Decoy " + d, issuerName: "Decoy " + (d + 1), spki: decoyKey.spki,
      issuerKey: decoyKey.keyObject, serial: 4 + d, ca: true }));
  }
  var longSrv = https.createServer({
    cert: served.map(function (c) { return pki.schema.x509.pemEncode(c, "CERTIFICATE"); }).join(""),
    key: pki.schema.pkcs8.pemEncode(longLeaf.key, "PRIVATE KEY"),
  }, function (req, res) { res.end("ok"); });
  longSrv.on("clientError", function () {});
  var longPort = await new Promise(function (res) { longSrv.listen(0, "127.0.0.1", function () { res(longSrv.address().port); }); });
  try {
    var walkLen = await new Promise(function (resolve) {
      var tlsSock = require("tls").connect({ host: "127.0.0.1", port: longPort, servername: "localhost",
        ca: [pki.schema.x509.pemEncode(anchorDer, "CERTIFICATE")] }, function () {
        var n = 0, c = tlsSock.getPeerCertificate(true);
        while (c && c.raw && n < 200) { n++; if (c.issuerCertificate === c) break; c = c.issuerCertificate; }
        tlsSock.destroy(); resolve(tlsSock.authorized ? n : -1);
      });
      tlsSock.on("error", function () { resolve(-2); });
    });
    check("T9 CONTROL OpenSSL verifies the session while node reports a chain longer than 100 (" + walkLen + ")", walkLen > 100);
    var longCode = await codeOf(pki.transport.https({})({ method: "GET", url: "https://127.0.0.1:" + longPort + "/",
      tls: { anchors: [pki.schema.x509.pemEncode(anchorDer, "CERTIFICATE")] } }));
    check("T9. a reported chain longer than the check reads is refused rather than read in part (" + longCode + ")",
      longCode === "transport/server-key-compromised");
  } finally {
    longSrv.close();
  }
}

async function run() {
  await testGuard();
  await testPath();
  await testRevocation();
  await testSigning();
  testSystemAnchors();
  testLint();
  await testTransport();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () {}, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
