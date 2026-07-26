// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for pki.pkcs12.open -- the PKCS#12 (.p12/.pfx) reading + decryption side (RFC 7292 sec.
// 5.1, RFC 9579, RFC 8018). Every vector drives the shipped consumer and asserts the recovered bytes against
// the originals, the MAC-verify-BEFORE-decrypt ordering, the fail-closed policies (MAC-less, public-key,
// legacy PBE), and the uniform decrypt verdict. Cross-implementation open (OpenSSL/NSS-produced stores) lives
// in test/integration/pkcs12-build-openssl-interop.test.js.
//
// MAC-before-decrypt (RFC 7292 sec. 5.1): a store whose password MAC fails returns NOTHING -- the wrong-password
// verdict is the MAC gate (pkcs12/mac-mismatch), never a per-bag decrypt error. The PBES2 bag password is UTF-8
// (the pinned interop convention), the classic MAC password BMPString+NULL.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var legacyFixtures = require("../helpers/pkcs12-legacy-fixtures");

async function codeOf(promise) { try { await promise; return null; } catch (e) { return e && e.code; } }

var SIGNER = null;
function signer() { if (!SIGNER) SIGNER = makeSigner("rsa"); return SIGNER; }

// ---- #1 / #4 / #5 / #13 build -> open round-trip (classic HMAC) -------------
async function testClassicRoundTrip() {
  var s = signer();
  var crl = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"), revoked: [] }, { cert: pki.schema.x509.parse(s.cert), key: s.key });
  var lki = Buffer.from([0xaa, 0xbb]);
  var p12 = await pki.pkcs12.build({ safeContents: [
    { encrypt: { password: "1234" }, bags: [{ type: "cert", cert: s.cert, friendlyName: "my cert", localKeyId: lki }] },   // #4 encrypted cert safe
    { bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234" }, localKeyId: lki }, { type: "crl", crl: crl }] } ] },
    { password: "1234", mac: { algorithm: "hmac", hash: "sha256" } });
  var o = await pki.pkcs12.open(p12, "1234");
  check("#1 macVerified is true", o.macVerified === true);
  check("#1 integrityMode is password", o.integrityMode === "password");
  check("#1 recovers one key + one cert + one crl", o.keys.length === 1 && o.certs.length === 1 && o.crls.length === 1);
  check("#5 shrouded key decrypts to the exact PrivateKeyInfo DER", Buffer.compare(o.keys[0].pkcs8, s.key) === 0);
  check("#5 the recovered key re-parses as PKCS#8", pki.schema.pkcs8.parse(o.keys[0].pkcs8) != null);
  check("#1 keys[0].encrypted is true", o.keys[0].encrypted === true);
  check("#4 the cert is recovered from the encrypted safe", Buffer.compare(o.certs[0].cert, s.cert) === 0);
  check("#1 the crl is recovered", Buffer.compare(o.crls[0].crl, crl) === 0);
  check("#13 friendlyName round-trips (BMPString)", o.certs[0].friendlyName === "my cert");
  check("#13 localKeyId pairs the key and cert", Buffer.isBuffer(o.keys[0].localKeyId) && o.keys[0].localKeyId.equals(o.certs[0].localKeyId));
}

// ---- #2 PBMAC1 round-trip; a plaintext keyBag surfaces raw DER -------------
async function testPbmac1AndPlainKey() {
  var s = signer();
  var pb = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }, { type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] },
    { password: "1234", mac: { algorithm: "pbmac1", hash: "sha256" } });
  var ob = await pki.pkcs12.open(pb, "1234");
  check("#2 PBMAC1 store opens (MAC gate verified) + key round-trips", ob.macVerified === true && Buffer.compare(ob.keys[0].pkcs8, s.key) === 0);
  // a plaintext keyBag returns the raw PrivateKeyInfo DER with encrypted:false.
  var pk = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "key", key: s.key }] }] }, { password: "1234" });
  var ok = await pki.pkcs12.open(pk, "1234");
  check("a plaintext keyBag surfaces the raw PrivateKeyInfo DER (encrypted:false)", ok.keys[0].encrypted === false && Buffer.compare(ok.keys[0].pkcs8, s.key) === 0);
}

// ---- #3 wrong password fails at the MAC gate before any decrypt -----------
async function testWrongPassword() {
  var s = signer();
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] }, { password: "1234" });
  check("#3 wrong password -> pkcs12/mac-mismatch (MAC gate, no partial bundle)", (await codeOf(pki.pkcs12.open(p12, "wrong"))) === "pkcs12/mac-mismatch");
}

// ---- #6 post-MAC bag decrypt failure -> uniform pkcs12/decrypt-failed ------
async function testUniformDecryptFail() {
  var s = signer();
  // the shrouded key is encrypted under a DIFFERENT password than the MAC -> the MAC (macpw) verifies, then
  // the bag decrypt with macpw fails (the bag is under bagpw): a UNIFORM pkcs12/decrypt-failed, no oracle.
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "bagpw" } }] }] }, { password: "macpw" });
  check("#6 a post-MAC shrouded-key decrypt failure -> uniform pkcs12/decrypt-failed", (await codeOf(pki.pkcs12.open(p12, "macpw"))) === "pkcs12/decrypt-failed");
  // an encrypted SAFE under a different password than the MAC: the walkSafeContents re-parse failure is
  // collapsed to the SAME uniform verdict (no distinguishable structural code -- no padding oracle).
  var p12safe = await pki.pkcs12.build({ safeContents: [{ encrypt: { password: "safepw" }, bags: [{ type: "cert", cert: s.cert }] }] }, { password: "macpw" });
  check("#6 an encrypted safe under a differing password -> uniform pkcs12/decrypt-failed", (await codeOf(pki.pkcs12.open(p12safe, "macpw"))) === "pkcs12/decrypt-failed");
}

// ---- #7 MAC-less store: refuse by default, opt-in allowed ------------------
async function testMacLessPolicy() {
  var s = signer();
  var pn = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { mac: false });
  check("#7 a MAC-less store -> pkcs12/no-integrity by default", (await codeOf(pki.pkcs12.open(pn, "1234"))) === "pkcs12/no-integrity");
  var on = await pki.pkcs12.open(pn, "1234", { allowUnauthenticated: true });
  check("#7 allowUnauthenticated opens it with macVerified:false", on.macVerified === false && on.integrityMode === "none" && on.certs.length === 1);
}

// ---- #10 attacker-controlled bag KDF iteration cap ------------------------
async function testBagDosCap() {
  var s = signer();
  // MAC iterations 500 (cheap), the PBES2 bag at 4096; open with maxIterations 1000 -> the MAC passes the cap
  // but the bag KDF exceeds it, refused BEFORE deriving.
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234", iterations: 4096 } }] }] },
    { password: "1234", mac: { algorithm: "hmac", hash: "sha256", iterations: 500 } });
  check("#10 a bag KDF over opts.maxIterations -> pkcs12/iteration-limit", (await codeOf(pki.pkcs12.open(p12, "1234", { maxIterations: 1000 }))) === "pkcs12/iteration-limit");
  check("#10 a non-integer maxIterations -> pkcs12/bad-input", (await codeOf(pki.pkcs12.open(p12, "1234", { maxIterations: NaN }))) === "pkcs12/bad-input");
}

// ---- #14 keys:"crypto" imports; ambiguous RSA/EC fails closed -------------
async function testKeysCrypto() {
  var ed = await pki.key.generate("Ed25519");
  var pe = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: await pki.key.export(ed.privateKey), encrypt: { password: "1234" } }] }] }, { password: "1234" });
  var oe = await pki.pkcs12.open(pe, "1234", { keys: "crypto" });
  check("#14 keys:crypto imports an unambiguous key to a CryptoKey", oe.keys[0].key && oe.keys[0].key.type === "private" && oe.keys[0].key.algorithm.name === "Ed25519");
  // an RSA key without importAlgorithm fails closed (the key.import ambiguity).
  var s = signer();
  var pr = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] }, { password: "1234" });
  check("#14 keys:crypto with an ambiguous RSA key + no importAlgorithm -> fail closed", typeof (await codeOf(pki.pkcs12.open(pr, "1234", { keys: "crypto" }))) === "string");
  var or = await pki.pkcs12.open(pr, "1234", { keys: "crypto", importAlgorithm: { name: "RSA-PSS", hash: "SHA-256" } });
  check("#14 keys:crypto with importAlgorithm imports the RSA key", or.keys[0].key.type === "private");
}

// ---- #15 nested safeContentsBag recursion + input polymorphism ------------
async function testNestedAndInputs() {
  var s = signer();
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "safeContents", nested: [{ type: "cert", cert: s.cert }, { type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] }] }, { password: "1234" });
  var o = await pki.pkcs12.open(p12, "1234");
  check("#15 a nested safeContentsBag's bags are recovered", o.certs.length === 1 && o.keys.length === 1 && Buffer.compare(o.certs[0].cert, s.cert) === 0);
  // a secret bag round-trips through open.
  var ps = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "secret", secretTypeId: "data", secretValue: pki.asn1.build.octetString(Buffer.from("shh")) }] }] }, { password: "1234" });
  var os = await pki.pkcs12.open(ps, "1234");
  check("a secret bag is recovered by open", os.secrets.length === 1 && os.secrets[0].secretTypeName === "data" && Buffer.isBuffer(os.secrets[0].secretValue));
  // open accepts DER, PEM, and a pre-parsed result.
  var pem = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234", pem: true });
  check("open accepts a PEM string", (await pki.pkcs12.open(pem, "1234")).certs.length === 1);
  check("open accepts a parse-result object", (await pki.pkcs12.open(pki.schema.pkcs12.parse(await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234" })), "1234")).certs.length === 1);
}

// RFC 7292 App. C legacy-PBE: read an `openssl pkcs12 -legacy` store (committed KAT fixtures) via the App. B
// multi-block KDF (BMPString password) + 3DES / in-tree RC2. The schemes were all REFUSED before this feature.
async function testLegacyPbe() {
  var F = legacyFixtures, b = function (s) { return Buffer.from(s, "base64"); };
  // A -legacy 3DES store (both bags): the 24-byte 3-key-3DES key is the first consumer of the App. B.2 c=2
  // multi-block KDF block -- opening it (recovering a valid PKCS#8) IS that multi-block known-answer test.
  var r = await pki.pkcs12.open(b(F.triple3des), "test123");
  check("#L1 a -legacy 3DES store opens (key + cert), MAC verified", r.keys.length === 1 && r.certs.length === 1 && r.macVerified === true);
  check("#L1 the 3DES-decrypted key is valid PKCS#8 (App. B.2 c=2 multi-block KDF KAT)", !!pki.schema.pkcs8.parse(r.keys[0].pkcs8));
  check("#L1 the 3DES-decrypted cert is a valid X.509", !!pki.schema.x509.parse(r.certs[0].cert));
  // The default -legacy store: a 40-bit RC2 cert bag decrypts via the in-tree RFC 2268 RC2 (node has no RC2).
  var r40 = await pki.pkcs12.open(b(F.rc2_40), "test123");
  check("#L2 a default -legacy store (40-bit RC2 cert) opens", r40.certs.length === 1 && !!pki.schema.x509.parse(r40.certs[0].cert));
  // A 128-bit RC2 cert bag (the c=... RC2 key-expansion path with effective-bits 128).
  check("#L3 a 128-bit RC2 cert store opens", (await pki.pkcs12.open(b(F.rc2_128), "test123")).certs.length === 1);
  // RC4 is deferred with a written re-open condition -> a typed, actionable refusal, never a silent failure.
  check("#L4 an RC4 legacy scheme -> pkcs12/unsupported-algorithm", (await codeOf(pki.pkcs12.open(b(F.rc4_128), "test123"))) === "pkcs12/unsupported-algorithm");
  // A wrong password fails at the MAC gate (RFC 7292 sec. 5.1) -- never a per-bag legacy decrypt error.
  check("#L5 a wrong password on a -legacy store -> pkcs12/mac-mismatch (MAC gate first)", (await codeOf(pki.pkcs12.open(b(F.triple3des), "wrong"))) === "pkcs12/mac-mismatch");
  // opts.maxIterations caps the synchronous App. B KDF work (here the MAC's own iteration count hits the cap first).
  check("#L6 opts.maxIterations caps a -legacy store -> pkcs12/iteration-limit", (await codeOf(pki.pkcs12.open(b(F.triple3des), "test123", { maxIterations: 10 }))) === "pkcs12/iteration-limit");
  // A MAC-less -legacy store (opts.allowUnauthenticated) exercises the legacy BAG decrypt path directly (no MAC
  // gate in front): a wrong password is the uniform pkcs12/decrypt-failed (a 3DES unpad failure, no oracle),
  // and opts.maxIterations caps the bag's own App. B KDF work.
  check("#L7 a MAC-less -legacy store opens under allowUnauthenticated", (await pki.pkcs12.open(b(F.nomac3des), "test123", { allowUnauthenticated: true })).keys.length === 1);
  check("#L8 a MAC-less -legacy store + wrong password -> uniform pkcs12/decrypt-failed", (await codeOf(pki.pkcs12.open(b(F.nomac3des), "wrongpw", { allowUnauthenticated: true }))) === "pkcs12/decrypt-failed");
  check("#L9 a MAC-less -legacy store + low maxIterations -> pkcs12/iteration-limit (bag KDF cap)", (await codeOf(pki.pkcs12.open(b(F.nomac3des), "test123", { allowUnauthenticated: true, maxIterations: 10 }))) === "pkcs12/iteration-limit");
  // Malformed legacy bags via single-byte surgery on the MAC-less fixture (no length change, so the outer DER
  // stays valid): an unregistered PBE OID and a corrupt pkcs-12PbeParams both fail closed pre-derivation.
  var nm = b(F.nomac3des), oidOff = nm.indexOf(Buffer.from("060a2a864886f70d010c0103", "hex"));   // the pbeWithSHAAnd3-KeyTripleDES-CBC OID DER
  var s653 = Buffer.from(nm); s653[oidOff + 11] = 0x63;   // last arc 3 -> 99: an unregistered PBE OID
  check("#L10 an unregistered legacy PBE OID -> pkcs12/unsupported-algorithm", (await codeOf(pki.pkcs12.open(s653, "test123", { allowUnauthenticated: true }))) === "pkcs12/unsupported-algorithm");
  var s656 = Buffer.from(nm); s656[oidOff + 12] = 0x2f;   // corrupt the params SEQUENCE tag -> the store parser rejects it
  check("#L11 a store with a corrupt params tag is rejected by the parser -> pkcs12/bad-der", (await codeOf(pki.pkcs12.open(s656, "test123", { allowUnauthenticated: true }))) === "pkcs12/bad-der");
  // Dispatch is by the IMMUTABLE OID, not the display name: renaming the built-in 3DES OID via the public oid
  // registry must NOT break a valid store (a name-keyed dispatch would refuse it). Restore for test isolation.
  var oid3des = pki.oid.byName("pbeWithSHAAnd3-KeyTripleDES-CBC");
  pki.oid.register(oid3des, "z-renamed-3des");
  var openedAfterRename;
  try {
    openedAfterRename = await pki.pkcs12.open(b(F.triple3des), "test123").then(function (r) { return r.keys.length === 1; }, function () { return false; });
  } finally {
    pki.oid.register(oid3des, "pbeWithSHAAnd3-KeyTripleDES-CBC");   // restore for test isolation, even if the open rejected
  }
  check("#L12 a -legacy store opens after its OID is renamed (dispatch by immutable OID, not display name)", openedAfterRename === true);
  // PKCS#12 content is normatively BER (RFC 7292 sec. 4.1): a conforming legacy store may encode
  // pkcs-12PbeParams with a constructed OCTET STRING salt. It must DECODE (and reach the decrypt -- here a
  // garbage ciphertext then fails as the uniform pkcs12/decrypt-failed), not be rejected by a strict-DER params
  // decode. Built with the asn1 builders (a raw BER params child), MAC-less so the bag decrypt path runs.
  var Bld = pki.asn1.build;
  var berSalt = Buffer.concat([Buffer.from([0x24, 0x0a, 0x04, 0x08]), Buffer.from("0011223344556677", "hex")]);   // constructed OCTET STRING salt
  var berParams = Buffer.concat([Buffer.from([0x30, 0x10]), berSalt, Buffer.from([0x02, 0x02, 0x08, 0x00])]);      // SEQUENCE { <constructed salt>, INTEGER 2048 }
  var encAlg = Bld.sequence([Bld.oid(pki.oid.byName("pbeWithSHAAnd3-KeyTripleDES-CBC")), Bld.raw(berParams)]);
  var epki = Bld.sequence([Bld.raw(encAlg), Bld.octetString(Buffer.alloc(16, 7))]);   // garbage ciphertext, valid 3DES length
  var safeBag = Bld.sequence([Bld.oid(pki.oid.byName("pkcs8ShroudedKeyBag")), Bld.explicit(0, Bld.raw(epki))]);
  var certSafe = Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(safeBag)])))]);
  var berStore = Bld.sequence([Bld.integer(3), Bld.raw(Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(certSafe)])))]))]);
  check("#L13 a conforming BER legacy store (constructed OCTET STRING salt) decodes + decrypts (RFC 7292 sec. 4.1)", (await codeOf(pki.pkcs12.open(berStore, "test123", { allowUnauthenticated: true }))) === "pkcs12/decrypt-failed");
  // The legacy KDF work is bounded by an AGGREGATE budget across the whole open(), not just a per-bag cap: a
  // 3DES bag at 350k iterations passes the 1e6 per-bag cap but its 3 * 350k = 1.05M SHA-1 rounds exceed the
  // aggregate budget -- so it fails closed BEFORE the KDF runs (a hostile many-bag store cannot reset the cap).
  var hiParams = Bld.sequence([Bld.octetString(Buffer.from("0011223344556677", "hex")), Bld.integer(350000)]);
  var hiEncAlg = Bld.sequence([Bld.oid(pki.oid.byName("pbeWithSHAAnd3-KeyTripleDES-CBC")), Bld.raw(hiParams)]);
  var hiEpki = Bld.sequence([Bld.raw(hiEncAlg), Bld.octetString(Buffer.alloc(16, 7))]);
  var hiBag = Bld.sequence([Bld.oid(pki.oid.byName("pkcs8ShroudedKeyBag")), Bld.explicit(0, Bld.raw(hiEpki))]);
  var hiSafe = Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(hiBag)])))]);
  var hiStore = Bld.sequence([Bld.integer(3), Bld.raw(Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(hiSafe)])))]))]);
  check("#L14 legacy KDF work over the aggregate budget -> pkcs12/iteration-limit (not the per-bag cap)", (await codeOf(pki.pkcs12.open(hiStore, "test123", { allowUnauthenticated: true }))) === "pkcs12/iteration-limit");
  // No CBC padding oracle: an RC2 bag whose decrypt fails on an invalid pad must give the SAME opaque error
  // MESSAGE (not just code) as a valid-pad-wrong-content failure, so the message cannot distinguish pad validity.
  var rc2Params = Bld.sequence([Bld.octetString(Buffer.from("0011223344556677", "hex")), Bld.integer(2048)]);
  var rc2EncAlg = Bld.sequence([Bld.oid(pki.oid.byName("pbeWithSHAAnd40BitRC2-CBC")), Bld.raw(rc2Params)]);
  var rc2Epki = Bld.sequence([Bld.raw(rc2EncAlg), Bld.octetString(Buffer.alloc(16, 7))]);   // garbage ct -> an RC2 pad failure
  var rc2Bag = Bld.sequence([Bld.oid(pki.oid.byName("pkcs8ShroudedKeyBag")), Bld.explicit(0, Bld.raw(rc2Epki))]);
  var rc2Safe = Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(rc2Bag)])))]);
  var rc2Store = Bld.sequence([Bld.integer(3), Bld.raw(Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(rc2Safe)])))]))]);
  var rc2Msg = await pki.pkcs12.open(rc2Store, "test123", { allowUnauthenticated: true }).then(function () { return "OPENED"; }, function (e) { return e.message; });
  check("#L15 an RC2 decrypt failure gives the uniform opaque message (no CBC padding oracle)", rc2Msg === "decryption failed");
  // A legacy AlgorithmIdentifier that OMITS its parameters must be a typed pkcs12 fault, not a leaked asn1/*
  // error (asn1.decode of the absent parameters would otherwise throw asn1/not-buffer straight to the caller).
  var noParamsEncAlg = Bld.sequence([Bld.oid(pki.oid.byName("pbeWithSHAAnd3-KeyTripleDES-CBC"))]);   // no params child
  var npEpki = Bld.sequence([Bld.raw(noParamsEncAlg), Bld.octetString(Buffer.alloc(16, 7))]);
  var npBag = Bld.sequence([Bld.oid(pki.oid.byName("pkcs8ShroudedKeyBag")), Bld.explicit(0, Bld.raw(npEpki))]);
  var npSafe = Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(npBag)])))]);
  var npStore = Bld.sequence([Bld.integer(3), Bld.raw(Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(npSafe)])))]))]);
  check("#L16 a legacy bag with no parameters -> pkcs12/bad-algorithm-parameters (not a leaked asn1/* error)", (await codeOf(pki.pkcs12.open(npStore, "test123", { allowUnauthenticated: true }))) === "pkcs12/bad-algorithm-parameters");
  // A well-formed but non-SEQUENCE params (an INTEGER the store parser accepts as ANY) fails the pkcs-12PbeParams
  // shape check -> the same typed pkcs12/bad-algorithm-parameters.
  var wrongEncAlg = Bld.sequence([Bld.oid(pki.oid.byName("pbeWithSHAAnd3-KeyTripleDES-CBC")), Bld.integer(5)]);   // params is an INTEGER, not the SEQUENCE
  var wpEpki = Bld.sequence([Bld.raw(wrongEncAlg), Bld.octetString(Buffer.alloc(16, 7))]);
  var wpBag = Bld.sequence([Bld.oid(pki.oid.byName("pkcs8ShroudedKeyBag")), Bld.explicit(0, Bld.raw(wpEpki))]);
  var wpSafe = Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(wpBag)])))]);
  var wpStore = Bld.sequence([Bld.integer(3), Bld.raw(Bld.sequence([Bld.oid(pki.oid.byName("data")), Bld.explicit(0, Bld.octetString(Bld.sequence([Bld.raw(wpSafe)])))]))]);
  check("#L17 a non-SEQUENCE pkcs-12PbeParams -> pkcs12/bad-algorithm-parameters", (await codeOf(pki.pkcs12.open(wpStore, "test123", { allowUnauthenticated: true }))) === "pkcs12/bad-algorithm-parameters");
}

async function main() {
  await testClassicRoundTrip();
  await testPbmac1AndPlainKey();
  await testWrongPassword();
  await testUniformDecryptFail();
  await testMacLessPolicy();
  await testBagDosCap();
  await testKeysCrypto();
  await testNestedAndInputs();
  await testLegacyPbe();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
