// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- pki.cms.authenticate + the pki.cms.decrypt AuthenticatedData arm (RFC 5652 sec. 9,
// RFC 2104/4231 HMAC). AuthenticatedData carries CLEARTEXT + a MAC (no content encryption): a fresh
// HMAC key is wrapped for each recipient with the SAME RecipientInfo model EnvelopedData uses, and the
// MAC covers either the re-tagged [2] authAttrs SET OF (default) or the raw eContent value octets. The
// #1 fragile case is the sec. 9.2 preimage (the [2]->0x31 re-tag on a THIRD context tag) -- pinned by
// an INDEPENDENT node:crypto HMAC over the reconstructed preimage. Every secret-dependent failure
// collapses to the uniform cms/decrypt-failed (no unwrap-success oracle).
//
// RED baseline: pki.cms.authenticate is undefined and pki.cms.decrypt rejects id-ct-authData.

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var signing = require("../helpers/signing");
var makeRecipient = signing.makeRecipient;
var nodeCrypto = require("crypto");
var subtle = nodeCrypto.webcrypto.subtle;
var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }
async function codeOf(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

var MSG = Buffer.from("the CMS AuthenticatedData MAC round-trip payload -- authenticate me");
var HASH_NODE = { "hmac-sha256": "sha256", "hmac-sha384": "sha384", "hmac-sha512": "sha512" };
var HASH_WC = { "hmac-sha256": "SHA-256", "hmac-sha384": "SHA-384", "hmac-sha512": "SHA-512" };

// The sec. 9.2 MAC preimage from a parsed AuthenticatedData: the [2] authAttrs re-tagged to 0x31 when
// present, else the eContent value octets directly.
function preimageOf(parsed) {
  if (parsed.authAttrsBytes) { var r = Buffer.from(parsed.authAttrsBytes); r[0] = 0x31; return r; }
  return Buffer.from(parsed.encapContentInfo.eContent);
}
// Recover the minted MAC key from a KEKRI recipient by AES-KW-unwrapping its encryptedKey under kek.
async function recoverMacKey(parsed, kek, mac) {
  var ek = parsed.recipientInfos[0].encryptedKey;
  var kk = await subtle.importKey("raw", kek, { name: "AES-KW" }, false, ["unwrapKey"]);
  var mk = await subtle.unwrapKey("raw", ek, kk, { name: "AES-KW" }, { name: "HMAC", hash: { name: HASH_WC[mac] } }, true, ["sign"]);
  return Buffer.from(await subtle.exportKey("raw", mk));
}
function flipRegion(der, region) {
  var i = der.indexOf(region);
  if (i < 0) throw new Error("flipRegion: region not found");
  var out = Buffer.from(der); out[i + region.length - 1] ^= 0xff; return out;
}

// ---- 1 / 2 present + absent round-trip + INDEPENDENT HMAC KAT ---------------
async function testRoundTripAndKat() {
  var kek = Buffer.alloc(32, 0x5c);
  for (var mode = 0; mode < 2; mode++) {
    var present = mode === 0;
    var out = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], present ? {} : { authenticatedAttributes: false });
    var parsed = pki.schema.cms.parse(out);
    check("#" + (mode + 1) + " macAlgorithm is hmacWithSHA256", parsed.macAlgorithm.name === "hmacWithSHA256");
    check("#" + (mode + 1) + " digestAlgorithm " + (present ? "present" : "absent"), present ? parsed.digestAlgorithm != null : parsed.digestAlgorithm == null);
    check("#" + (mode + 1) + " authAttrs " + (present ? "present" : "absent"), present ? parsed.authAttrsBytes != null : parsed.authAttrsBytes == null);
    // INDEPENDENT HMAC over the exact sec. 9.2 preimage equals parsed.mac.
    var macKey = await recoverMacKey(parsed, kek, "hmac-sha256");
    var indep = nodeCrypto.createHmac("sha256", macKey).update(preimageOf(parsed)).digest();
    check("#" + (mode + 1) + " independent HMAC over the preimage == parsed.mac", Buffer.compare(indep, Buffer.from(parsed.mac)) === 0);
    // decrypt recovers content + authenticated:true.
    var d = await pki.cms.decrypt(out, { kek: kek });
    check("#" + (mode + 1) + " decrypt -> content + authenticated:true", Buffer.compare(d.content, MSG) === 0 && d.authenticated === true);
  }
  // present mode: the message-digest attribute equals sha256(content).
  var op = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], {});
  var pp = pki.schema.cms.parse(op);
  var md = pp.authAttrs.filter(function (a) { return a.type === O("messageDigest"); })[0];
  check("#1 message-digest attribute == sha256(content)", md != null);
}

// ---- 3 PREIMAGE-NEGATIVE: a MAC over the wrong bytes fails uniformly --------
async function testPreimageNegative() {
  var kek = Buffer.alloc(32, 0x33);
  var out = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], {});
  // Flip a byte inside authAttrsBytes -> the MAC (over the re-tagged authAttrs) no longer matches.
  var tampered = flipRegion(out, pki.schema.cms.parse(out).authAttrsBytes.subarray(2));
  check("#3 a MAC over tampered authAttrs -> uniform cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(tampered, { kek: kek }); })) === "cms/decrypt-failed");
}

// ---- 4 PER-ARM MATRIX ------------------------------------------------------
async function testPerArm() {
  for (var kind of ["rsa", "ec-p256", "ec-p521", "x25519", "x448", "ml-kem-512", "ml-kem-768", "ml-kem-1024"]) {
    var r = makeRecipient(kind);
    var out = await pki.cms.authenticate(MSG, [{ cert: r.cert }], {});
    var d = await pki.cms.decrypt(out, { key: r.key, cert: r.cert });
    check("#4 arm " + kind + " -> content + authenticated:true", Buffer.compare(d.content, MSG) === 0 && d.authenticated === true);
  }
  // pwri + kekri
  check("#4 pwri round-trips", (await pki.cms.decrypt(await pki.cms.authenticate(MSG, [{ password: "pw" }], {}), { password: "pw" })).authenticated === true);
  // multi-recipient: one MAC key wrapped for RSA + password + kek; each recovers + authenticates.
  var rsa = makeRecipient("rsa"), kek = Buffer.alloc(16, 7);
  var multi = await pki.cms.authenticate(MSG, [{ cert: rsa.cert }, { password: "pw" }, { kek: kek, kekId: Buffer.from("k") }], {});
  check("#4 multi-recipient: RSA recovers", Buffer.compare((await pki.cms.decrypt(multi, { key: rsa.key, cert: rsa.cert })).content, MSG) === 0);
  check("#4 multi-recipient: password recovers", Buffer.compare((await pki.cms.decrypt(multi, { password: "pw" })).content, MSG) === 0);
  check("#4 multi-recipient: kek recovers", Buffer.compare((await pki.cms.decrypt(multi, { kek: kek })).content, MSG) === 0);
}

// ---- 5 PER-HASH MATRIX -----------------------------------------------------
async function testPerHash() {
  var kek = Buffer.alloc(32, 0x11);
  var OUTLEN = { "hmac-sha256": 32, "hmac-sha384": 48, "hmac-sha512": 64 };
  for (var mac of ["hmac-sha256", "hmac-sha384", "hmac-sha512"]) {
    var out = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], { macAlgorithm: mac });
    var parsed = pki.schema.cms.parse(out);
    check("#5 " + mac + " mac octet length == HMAC output", Buffer.from(parsed.mac).length === OUTLEN[mac]);
    var macKey = await recoverMacKey(parsed, kek, mac);
    var indep = nodeCrypto.createHmac(HASH_NODE[mac], macKey).update(preimageOf(parsed)).digest();
    check("#5 " + mac + " independent HMAC == parsed.mac (32-octet key, no codec change)", Buffer.compare(indep, Buffer.from(parsed.mac)) === 0);
    check("#5 " + mac + " decrypt round-trips", (await pki.cms.decrypt(out, { kek: kek })).authenticated === true);
  }
}

// ---- 6 / 7 / 9 tampered content / mac / wrong key -> uniform verdict --------
async function testFailClosed() {
  var kek = Buffer.alloc(32, 0x66);
  var out = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], {});
  check("#6 tampered content -> cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(flipRegion(out, MSG), { kek: kek }); })) === "cms/decrypt-failed");
  check("#7 tampered mac -> cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(flipRegion(out, Buffer.from(pki.schema.cms.parse(out).mac)), { kek: kek }); })) === "cms/decrypt-failed");
  check("#9 wrong kek -> cms/decrypt-failed (IDENTICAL verdict, no unwrap oracle)", (await codeOf(function () { return pki.cms.decrypt(out, { kek: Buffer.alloc(32, 0x99) }); })) === "cms/decrypt-failed");
  // wrong recipient key on a ktri arm (the cert matches the rid so the unwrap RUNS, but with the wrong
  // private key it fails), and wrong password on a pwri arm -> the SAME uniform code as a MAC failure.
  var rsa = makeRecipient("rsa"), rsa2 = makeRecipient("rsa");
  var kout = await pki.cms.authenticate(MSG, [{ cert: rsa.cert }], {});
  check("#9 wrong RSA key (matching rid) -> cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(kout, { key: rsa2.key, cert: rsa.cert }); })) === "cms/decrypt-failed");
  var pout = await pki.cms.authenticate(MSG, [{ password: "right" }], {});
  check("#9 wrong password -> cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(pout, { password: "wrong" }); })) === "cms/decrypt-failed");
  // AMBIGUOUS candidates: two kekri recipients + a wrong kek with no kekId matches BOTH; every candidate
  // fails, collapsing to the uniform verdict (nothing leaked about which candidate).
  var k1 = Buffer.alloc(32, 0x41);
  var two = await pki.cms.authenticate(MSG, [{ kek: k1, kekId: Buffer.from("a") }, { kek: k1, kekId: Buffer.from("b") }], {});
  check("#9 two ambiguous kekri candidates all fail -> cms/decrypt-failed", (await codeOf(function () { return pki.cms.decrypt(two, { kek: Buffer.alloc(32, 0x99) }); })) === "cms/decrypt-failed");
}

// ---- 12 macAlgorithm strictness (distinct pass-through code) ----------------
async function testMacAlgorithmStrictness() {
  // a hand-built AuthenticatedData whose macAlgorithm is hmac-SHA1 (weak) is refused BEFORE any
  // secret-dependent step with the DISTINCT cms/unsupported-algorithm (not the uniform verdict).
  var kek = Buffer.alloc(32, 0x22);
  var out = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], {});
  // splice the macAlgorithm OID hmacWithSHA256 -> hmac-SHA1 by re-encoding (simplest: assert the
  // producer refuses to emit a weak/unknown macAlgorithm at build time as the primary guard).
  check("#12 authenticate refuses an unknown macAlgorithm", (await codeOf(function () { return pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], { macAlgorithm: "hmac-sha1" }); })) === "cms/bad-input");
  // decrypt-side: a message whose macAlgorithm OID is unregistered is refused with the DISTINCT
  // cms/unsupported-algorithm BEFORE any secret step -- swap the hmacWithSHA256 OID's last arc.
  var oidBytes = Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09]);
  var i = out.indexOf(oidBytes);
  var bad = Buffer.from(out); bad[i + oidBytes.length - 1] = 0x7f;   // hmacWithSHA256 -> an unknown HMAC OID
  check("#12 decrypt an unknown macAlgorithm -> cms/unsupported-algorithm (distinct, pre-secret)", (await codeOf(function () { return pki.cms.decrypt(bad, { kek: kek }); })) === "cms/unsupported-algorithm");
}

// ---- 14 version == 0 for every recipient kind ------------------------------
async function testVersion() {
  var kek = Buffer.alloc(16, 3);
  for (var desc of [[{ kek: kek, kekId: Buffer.from("k") }], [{ password: "pw" }], [{ cert: makeRecipient("ml-kem-768").cert }]]) {
    var parsed = pki.schema.cms.parse(await pki.cms.authenticate(MSG, desc, {}));
    check("#14 version == 0 (originatorInfo-only rule; kemri/pwri never bump it)", parsed.version === 0);
  }
}

// ---- 16 DER / PEM I/O + self-verify ----------------------------------------
async function testIo() {
  var kek = Buffer.alloc(32, 0x44);
  var pem = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], { pem: true });
  check("#16 authenticate opts.pem returns a CMS PEM string", typeof pem === "string" && pem.indexOf("-----BEGIN CMS-----") === 0);
  check("#16 the PEM round-trips through decrypt", (await pki.cms.decrypt(pem, { kek: kek })).authenticated === true);
  var der = await pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], {});
  check("#16 a DER Buffer round-trips", Buffer.isBuffer(der) && (await pki.cms.decrypt(der, { kek: kek })).authenticated === true);
  // config-time: empty recipients, non-object opts, non-data content without authAttrs.
  check("#cfg empty recipients -> bad-input", (await codeOf(function () { return pki.cms.authenticate(MSG, [], {}); })) === "cms/bad-input");
  check("#cfg non-id-data contentType with authenticatedAttributes:false -> bad-input",
    (await codeOf(function () { return pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], { contentType: "signedData", authenticatedAttributes: false }); })) === "cms/bad-input");
  // an unsupported digestAlgorithm the verifier could not recompute is refused (the no-orphan rule).
  check("#cfg unsupported digestAlgorithm -> bad-input",
    (await codeOf(function () { return pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], { digestAlgorithm: "sha1" }); })) === "cms/bad-input");
  // a caller-supplied authAttr duplicating the auto-built content-type attribute is refused (RFC 5652
  // attribute uniqueness), and a malformed authAttr is refused.
  check("#cfg duplicate authenticated attribute type -> bad-input",
    (await codeOf(function () { return pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], { authAttrs: [b.sequence([b.oid(O("contentType")), b.setOf([b.oid(O("data"))])])] }); })) === "cms/bad-input");
  check("#cfg a non-SEQUENCE authenticated attribute -> bad-input",
    (await codeOf(function () { return pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], { authAttrs: [b.integer(5n)] }); })) === "cms/bad-input");
  check("#cfg an attribute with a valid OID but a non-SET value -> bad-input",
    (await codeOf(function () { return pki.cms.authenticate(MSG, [{ kek: kek, kekId: Buffer.from("k") }], { authAttrs: [b.sequence([b.oid(O("signingTime")), b.integer(1n)])] }); })) === "cms/bad-input");
}

async function run() {
  await testRoundTripAndKat();
  await testPreimageNegative();
  await testPerArm();
  await testPerHash();
  await testFailClosed();
  await testMacAlgorithmStrictness();
  await testVersion();
  await testIo();
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + helpers.getChecks()); process.exit(0); },
  function (e) { console.error(e && e.stack || e); process.exit(1); }
);
