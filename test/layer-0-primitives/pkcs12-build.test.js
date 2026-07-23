// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Conformance vectors for pki.pkcs12.build / verifyMac -- the PKCS#12 (.p12 / .pfx) producing side (RFC 7292,
// RFC 9579). Every vector drives the shipped consumer and asserts through pki.schema.pkcs12.parse (the strict
// round-trip oracle), a captured MAC byte range, or verifyMac's boolean verdict. Keys/certs come from the
// makeSigner helper. Cross-implementation validation (ours <-> OpenSSL, classic + PBMAC1 + PBES2 bags) lives
// in test/integration/pkcs12-build-openssl-interop.test.js.
//
// Password encoding (the interop wart, pinned against OpenSSL): the classic Appendix B MAC KDF consumes the
// BMPString+NULL password; the PBES2 bag ciphers and the PBMAC1 MAC consume the UTF-8 password. RFC 9579's
// published A.1-A.5 examples encode a non-canonical DEFAULT MacData.iterations=1 (BER) that the strict parser
// fail-closed rejects (Hard rule 3); OpenSSL emits canonical iterations, so the OpenSSL interop covers the
// same code paths.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var asn1 = pki.asn1;
var b = asn1.build;
function byName(n) { return pki.oid.byName(n); }

async function boolOf(promise) { try { return await promise; } catch (e) { return "THREW:" + (e && e.code); } }
async function codeOf(promise) { try { await promise; return null; } catch (e) { return e && e.code; } }

var SIGNER = null;
function signer() { if (!SIGNER) SIGNER = makeSigner("rsa"); return SIGNER; }

// ---- #1 classic HMAC-SHA256 password-integrity round-trip ------------------
async function testClassicRoundTrip() {
  var s = signer();
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [
    { type: "cert", cert: s.cert },
    { type: "shroudedKey", key: s.key, encrypt: { password: "1234" } } ] }] },
    { password: "1234", mac: { algorithm: "hmac", hash: "sha256", iterations: 2048 } });
  var m = pki.schema.pkcs12.parse(p12);
  check("#1 version is 3", m.version === 3);
  check("#1 integrityMode is password", m.integrityMode === "password");
  check("#1 mac.kind is hmac", m.mac.kind === "hmac");
  check("#1 mac.hashName is sha256", m.mac.hashName === "sha256");
  check("#1 mac.iterations is 2048", m.mac.iterations === 2048);
  check("#1 safeBags carry a certBag + a pkcs8ShroudedKeyBag", m.safeBags.map(function (x) { return x.type; }).sort().join(",") === "certBag,pkcs8ShroudedKeyBag");
  check("#1 verifyMac accepts the correct password", (await pki.pkcs12.verifyMac(p12, "1234")) === true);
  check("#1 verifyMac rejects a wrong password", (await pki.pkcs12.verifyMac(p12, "wrong")) === false);
  // PEM round-trip
  var pem = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234", pem: true });
  check("#1 pem output carries the PKCS12 armor", /-----BEGIN PKCS12-----/.test(pem));
  check("#1 verifyMac accepts a PEM store", (await pki.pkcs12.verifyMac(pem, "1234")) === true);
}

// ---- #2 PBMAC1-SHA256 round-trip -------------------------------------------
async function testPbmac1RoundTrip() {
  var s = signer();
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] },
    { password: "1234", mac: { algorithm: "pbmac1", hash: "sha256" } });
  var m = pki.schema.pkcs12.parse(p12);
  check("#2 mac.kind is pbmac1", m.mac.kind === "pbmac1");
  check("#2 PBMAC1 keyLength is 32", m.mac.pbmac1.kdf.keyLength === 32);
  check("#2 PBMAC1 prfName is hmacWithSHA256", m.mac.pbmac1.kdf.prfName === "hmacWithSHA256");
  check("#2 PBMAC1 schemeName is hmacWithSHA256", m.mac.pbmac1.schemeName === "hmacWithSHA256");
  check("#2 verifyMac accepts the correct password", (await pki.pkcs12.verifyMac(p12, "1234")) === true);
  check("#2 verifyMac rejects a wrong password", (await pki.pkcs12.verifyMac(p12, "nope")) === false);
  // PBMAC1 over SHA-384 / SHA-512
  var p384 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234", mac: { algorithm: "pbmac1", hash: "sha384" } });
  check("#2 PBMAC1-SHA384 keyLength is 48 + verifies", pki.schema.pkcs12.parse(p384).mac.pbmac1.kdf.keyLength === 48 && (await pki.pkcs12.verifyMac(p384, "1234")) === true);
}

// ---- #7 macedBytes exactness (off-by-the-TLV-header) -----------------------
async function testMacedBytesExactness() {
  var s = signer();
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234" });
  var m = pki.schema.pkcs12.parse(p12);
  // macedBytes is the AuthenticatedSafe value octets -- the OCTET STRING content, strictly shorter than its TLV.
  var authSafeOctet = asn1.decode(p12).children[1].children[1].children[0];   // PFX -> authSafe ContentInfo -> [0] -> OCTET STRING
  check("#7 macedBytes is strictly shorter than the authSafe OCTET STRING TLV", m.macedBytes.length < authSafeOctet.bytes.length);
  check("#7 macedBytes equals the OCTET STRING content (no header)", m.macedBytes.equals(authSafeOctet.content));
}

// ---- #8 the classic MAC KDF consumes the BMPString password, not UTF-8 -----
async function testClassicBmpStringPassword() {
  var s = signer();
  var pw = String.fromCharCode(0x63, 0x61, 0x66, 0xe9);   // "cafe" + U+00E9  (non-ASCII, built at runtime)
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: pw, mac: { algorithm: "hmac", hash: "sha256" } });
  check("#8 verifyMac with the string (BMPString-encoded) passes", (await pki.pkcs12.verifyMac(p12, pw)) === true);
  // Passing the raw UTF-8 BYTES as a Buffer is a DIFFERENT key than the BMPString the classic KDF derives.
  check("#8 verifyMac with the raw UTF-8 bytes fails (proves BMPString, not UTF-8)", (await pki.pkcs12.verifyMac(p12, Buffer.from(pw, "utf8"))) === false);
}

// ---- #9 / #10 PBES2 hosts round-trip through the parser --------------------
async function testPbes2Hosts() {
  var s = signer();
  // #9 shrouded key bag = a bare EncryptedPrivateKeyInfo (RFC 5958 sec. 3), NOT a CMS EncryptedData.
  var p9 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234", cipher: "aes-256-cbc" } }] }] }, { password: "1234" });
  var m9 = pki.schema.pkcs12.parse(p9);
  var sk = m9.safeBags.filter(function (x) { return x.type === "pkcs8ShroudedKeyBag"; })[0];
  check("#9 shrouded key bag is present", sk != null);
  check("#9 shrouded key encryptionAlgorithm is PBES2", sk.encrypted.encryptionAlgorithm.oid === byName("pbes2"));
  // #10 encrypted cert safe = an id-encryptedData ContentInfo over the SafeContents.
  var p10 = await pki.pkcs12.build({ safeContents: [{ encrypt: { password: "1234", cipher: "aes-256-cbc" }, bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234" });
  var m10 = pki.schema.pkcs12.parse(p10);
  check("#10 an encryptedData safe is present", m10.encryptedSafes.length === 1 && m10.encryptedSafes[0].type === "encryptedData");
  check("#10 verifyMac still holds over the encrypted safe", (await pki.pkcs12.verifyMac(p10, "1234")) === true);
}

// ---- #12 no-MAC store + verifyMac fail-closed ------------------------------
async function testNoMac() {
  var s = signer();
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { mac: false });
  var m = pki.schema.pkcs12.parse(p12);
  check("#12 integrityMode is none", m.integrityMode === "none");
  check("#12 mac is null", m.mac === null);
  check("#12 verifyMac on a MAC-less store throws (never a falsy verdict)", (await boolOf(pki.pkcs12.verifyMac(p12, "1234"))) === "THREW:pkcs12/bad-input");
}

// ---- #13 / #14 MacData.iterations DEFAULT-1 + SHA-1 PBMAC1 floor -----------
async function testMacFailClosed() {
  var s = signer();
  var spec = { safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] };
  // #13 a DEFAULT-1 MacData iterations cannot be DER-encoded -- reject up front.
  check("#13 mac.iterations = 1 -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { iterations: 1 } }))) === "pkcs12/bad-input");
  check("#13 mac.iterations non-integer -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { iterations: 1.5 } }))) === "pkcs12/bad-input");
  check("#13 mac.iterations over the cap -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { iterations: pki.constants.LIMITS.PBKDF2_MAX_ITERATIONS + 1 } }))) === "pkcs12/bad-input");
  // #14 SHA-1 is forbidden in PBMAC1 (RFC 9579 sec. 5/7).
  check("#14 PBMAC1 with sha1 -> pkcs12/unsupported-algorithm", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { algorithm: "pbmac1", hash: "sha1" } }))) === "pkcs12/unsupported-algorithm");
  check("#14 PBMAC1 keyLength over the cap -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { algorithm: "pbmac1", keyLength: 2000 } }))) === "pkcs12/bad-input");
  // classic HMAC with SHA-1 IS allowed (legacy interop), so this must NOT throw.
  check("#14 classic HMAC with sha1 is allowed", typeof (await pki.pkcs12.build(spec, { password: "1234", mac: { algorithm: "hmac", hash: "sha1" } })) === "object");
}

// ---- #15 friendlyName / localKeyId attributes -----------------------------
async function testAttributes() {
  var s = signer();
  var lki = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert, friendlyName: "my cert", localKeyId: lki }] }] }, { password: "1234" });
  var bag = pki.schema.pkcs12.parse(p12).safeBags[0];
  check("#15 friendlyName round-trips as a BMPString value", bag.friendlyName === "my cert");
  check("#15 localKeyId round-trips as the exact OCTET STRING", Buffer.isBuffer(bag.localKeyId) && bag.localKeyId.equals(lki));
}

// ---- #11 public-key integrity is refused (deferred) + fail-closed inputs ---
async function testFailClosedInputs() {
  var s = signer();
  check("#11 public-key integrity -> pkcs12/unsupported-algorithm (deferred)", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { integrity: { mode: "public-key" }, password: "1234" }))) === "pkcs12/unsupported-algorithm");
  check("an unknown bag type -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "bogus" }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a keyBag with non-key bytes -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "key", key: Buffer.from([1, 2, 3]) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a shroudedKey with non-key bytes -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: Buffer.from([1, 2, 3]) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a null bag -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [null] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  // a shroudedKey with no encrypt block inherits opts.password + the default cipher (the bag.encrypt || {} arm).
  var pdef = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key }] }] }, { password: "1234" });
  check("a shroudedKey with no encrypt block uses opts.password + defaults", (await pki.pkcs12.verifyMac(pdef, "1234")) === true);
  check("a certBag with non-cert bytes -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: Buffer.from([1, 2, 3]) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("an empty store -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a bad spec -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({}, { password: "1234" }))) === "pkcs12/bad-input");
  check("a secret bag with no secretValue -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "secret", secretTypeId: "data" }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a secret value with trailing bytes -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "secret", secretTypeId: "data", secretValue: Buffer.concat([b.octetString(Buffer.from("x")), Buffer.from([0])]) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("bags that are not an array -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: "nope" }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("localKeyId 'ski' auto-derive -> pkcs12/bad-input (deferred)", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert, localKeyId: "ski" }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  // a safeContents bag with no nested list (the bag.nested || [] arm).
  var pnn = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }, { type: "safeContents" }] }] }, { password: "1234" });
  check("a safeContents bag with no nested list is tolerated", (await pki.pkcs12.verifyMac(pnn, "1234")) === true);
  check("a secret bag with no secretTypeId -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "secret", secretValue: b.octetString(Buffer.from("x")) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  // a shroudedKey whose encrypt omits its own password inherits opts.password.
  var pski = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { cipher: "aes-256-cbc" } }] }] }, { password: "1234" });
  check("a shroudedKey encrypt inherits opts.password", (await pki.pkcs12.verifyMac(pski, "1234")) === true);
  // nesting past the depth cap fails closed.
  var deep = { type: "cert", cert: s.cert };
  for (var d = 0; d < 18; d++) deep = { type: "safeContents", nested: [deep] };
  check("safeContents nesting past the depth cap -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [deep] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  // Documented residuals (branch report): the _reqDer trailing-bytes check (asn1.decode rejects trailing
  // first, so it is defensive), the SafeContents element cap (a 1024+-bag store, not worth building), the
  // build self-check catch (a build bug that cannot re-parse), and verifyMac's unsupported classic-hash /
  // PBMAC1-prf guards (reachable only from a hand-crafted store our builder never emits) stay verified-defensive.
  check("an unknown mac.algorithm -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234", mac: { algorithm: "bogus" } }))) === "pkcs12/bad-input");
  check("an unsupported bag cipher -> pkcs12/bad-input (not a silent default)", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234", cipher: "des-cbc" } }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  // AES-128/192 bag ciphers + an explicit salt/iterations exercise the PBES2 encrypt arms.
  var p128 = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234", cipher: "aes-128-cbc", salt: Buffer.alloc(8, 9), iterations: 4096 } }] }] }, { password: "1234" });
  check("aes-128-cbc bag with explicit salt + iterations round-trips", (await pki.pkcs12.verifyMac(p128, "1234")) === true);
}

// ---- bag-type coverage: keyBag, crl, secret, nested safeContents ----------
async function testBagTypes() {
  var s = signer();
  var crlDer = await pki.crl.sign({ thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"), revoked: [] },
    { cert: pki.schema.x509.parse(s.cert), key: s.key });
  var p12 = await pki.pkcs12.build({ safeContents: [{ bags: [
    { type: "key", key: s.key },
    { type: "crl", crl: crlDer },
    { type: "secret", secretTypeId: "data", secretValue: b.octetString(Buffer.from("shh")) },
    { type: "safeContents", nested: [{ type: "cert", cert: s.cert }] } ] }] }, { password: "1234" });
  var m = pki.schema.pkcs12.parse(p12);
  var types = m.safeBags.map(function (x) { return x.type; });
  check("bag types: keyBag present", types.indexOf("keyBag") !== -1);
  check("bag types: crlBag present", types.indexOf("crlBag") !== -1);
  check("bag types: secretBag present", types.indexOf("secretBag") !== -1);
  check("bag types: safeContentsBag present", types.indexOf("safeContentsBag") !== -1);
  check("nested safeContents + verifyMac holds", (await pki.pkcs12.verifyMac(p12, "1234")) === true);
  // convenience (OpenSSL-style) form
  var conv = await pki.pkcs12.build({ key: s.key, cert: s.cert, friendlyName: "k" }, { password: "1234" });
  check("convenience form { key, cert } builds + verifies", (await pki.pkcs12.verifyMac(conv, "1234")) === true);
}

// ---- option/verifyMac reachable edges --------------------------------------
async function testEdges() {
  var s = signer();
  var spec = { safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] };
  // an unsupported classic MAC hash.
  check("classic MAC with an unknown hash -> pkcs12/unsupported-algorithm", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { hash: "md5" } }))) === "pkcs12/unsupported-algorithm");
  // PBMAC1 with an explicit iteration count + keyLength, and a too-short keyLength.
  var pex = await pki.pkcs12.build(spec, { password: "1234", mac: { algorithm: "pbmac1", hash: "sha256", iterations: 3000, keyLength: 32 } });
  check("PBMAC1 with explicit iterations + keyLength round-trips", (await pki.pkcs12.verifyMac(pex, "1234")) === true);
  check("PBMAC1 with keyLength < 20 -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { algorithm: "pbmac1", keyLength: 10 } }))) === "pkcs12/bad-input");
  // build with NO opts (an empty password, MAC present) + verifyMac with the empty password.
  var pnoopts = await pki.pkcs12.build(spec);
  check("build with no opts uses an empty password + still MACs", pki.schema.pkcs12.parse(pnoopts).integrityMode === "password");
  check("verifyMac with the empty password accepts it", (await pki.pkcs12.verifyMac(pnoopts, "")) === true);
  // verifyMac accepts a pre-parsed pki.schema.pkcs12.parse result (not only DER/PEM).
  var p12 = await pki.pkcs12.build(spec, { password: "1234" });
  check("verifyMac accepts a parse-result object", (await pki.pkcs12.verifyMac(pki.schema.pkcs12.parse(p12), "1234")) === true);
  // a safeContents element with no bags (the sc.bags || [] arm) alongside a real one.
  var pempty = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }, {}] }, { password: "1234" });
  check("an empty safeContents element is tolerated", (await pki.pkcs12.verifyMac(pempty, "1234")) === true);
  // an encrypted safe that omits its own password falls back to opts.password.
  var pshared = await pki.pkcs12.build({ safeContents: [{ encrypt: { cipher: "aes-256-cbc" }, bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234" });
  check("an encrypted safe inherits opts.password", (await pki.pkcs12.verifyMac(pshared, "1234")) === true);
  // a MAC-specific password (mac.password) overrides the shared password; an explicit MAC salt is honored.
  var pmacpw = await pki.pkcs12.build(spec, { password: "privpw", mac: { password: "macpw", salt: Buffer.alloc(8, 2) } });
  check("mac.password overrides the shared password", (await pki.pkcs12.verifyMac(pmacpw, "macpw")) === true && (await pki.pkcs12.verifyMac(pmacpw, "privpw")) === false);
  // an empty MAC salt is rejected.
  check("an empty MAC salt -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { salt: Buffer.alloc(0) } }))) === "pkcs12/bad-input");
}

// ---- verifyMac DoS bound + independent PBMAC1 messageAuthScheme -----------
async function testVerifyHardening() {
  var nc = require("node:crypto");
  var pbes2 = require("../../lib/pbes2");
  var s = signer();
  var spec = { safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] };

  // A hostile store's iteration count must be bounded BEFORE deriving. opts.maxIterations lowers the cap.
  var p = await pki.pkcs12.build(spec, { password: "1234", mac: { algorithm: "pbmac1", hash: "sha256", iterations: 2048 } });
  check("verifyMac with maxIterations below the count -> pkcs12/iteration-limit", (await codeOf(pki.pkcs12.verifyMac(p, "1234", { maxIterations: 1000 }))) === "pkcs12/iteration-limit");
  check("verifyMac without a cap still verifies", (await pki.pkcs12.verifyMac(p, "1234")) === true);

  // Craft a store around a real AuthenticatedSafe: an over-the-hard-cap PBMAC1 iteration count is rejected
  // before any derivation (a hostile store cannot force a multi-second CPU burn).
  var noMac = await pki.pkcs12.build(spec, { mac: false });
  var authSafeCI = asn1.decode(noMac).children[1];
  var macedBytes = pki.schema.pkcs12.parse(noMac).macedBytes;
  function craft(salt, iter, keyLen, prfName, macName, macBytes) {
    var di = b.sequence([pbes2.pbmac1AlgId({ salt: salt, iterationCount: iter, keyLength: keyLen, prfName: prfName, macName: macName }), b.octetString(macBytes)]);
    return b.sequence([b.integer(3n), authSafeCI.bytes, b.sequence([di, b.octetString(salt), b.integer(BigInt(iter))])]);
  }
  var salt = Buffer.alloc(8, 5);
  var overCap = craft(salt, pki.constants.LIMITS.PBKDF2_MAX_ITERATIONS + 1, 32, "hmacWithSHA256", "hmacWithSHA256", Buffer.alloc(32));
  check("verifyMac rejects an over-hard-cap iteration count -> pkcs12/iteration-limit", (await codeOf(pki.pkcs12.verifyMac(overCap, "1234"))) === "pkcs12/iteration-limit");
  // an over-cap salt and an over-cap PBMAC1 keyLength are rejected before derivation.
  var bigSalt = craft(Buffer.alloc(pki.constants.LIMITS.PBKDF2_MAX_SALT + 1, 1), 2048, 32, "hmacWithSHA256", "hmacWithSHA256", Buffer.alloc(32));
  check("verifyMac rejects an over-cap salt -> pkcs12/bad-input", (await codeOf(pki.pkcs12.verifyMac(bigSalt, "1234"))) === "pkcs12/bad-input");
  var bigKeyLen = craft(salt, 2048, 4096, "hmacWithSHA256", "hmacWithSHA256", Buffer.alloc(32));
  check("verifyMac rejects an over-cap PBMAC1 keyLength -> pkcs12/bad-input", (await codeOf(pki.pkcs12.verifyMac(bigKeyLen, "1234"))) === "pkcs12/bad-input");
  check("verifyMac with an invalid maxIterations -> pkcs12/bad-input", (await codeOf(pki.pkcs12.verifyMac(p, "1234", { maxIterations: NaN }))) === "pkcs12/bad-input");

  // RFC 9579 A.2 shape: a SHA-512 PBKDF2 prf with a SHA-256 HMAC messageAuthScheme. verifyMac must key the
  // HMAC by the messageAuthScheme, not the prf -- so it must compute HMAC-SHA256(PBKDF2-SHA512(pw), maced).
  var iter = 2048, keyLen = 32, pw = Buffer.from("1234", "utf8");
  var dk = nc.pbkdf2Sync(pw, salt, iter, keyLen, "sha512");
  var mac = nc.createHmac("sha256", dk).update(macedBytes).digest();
  var differing = craft(salt, iter, keyLen, "hmacWithSHA512", "hmacWithSHA256", mac);
  check("verifyMac honors a differing PBMAC1 prf / messageAuthScheme (SHA-512 PRF + SHA-256 HMAC)", (await pki.pkcs12.verifyMac(differing, "1234")) === true);
  // the same store with the wrong password still fails.
  check("the differing-scheme store fails on a wrong password", (await pki.pkcs12.verifyMac(differing, "nope")) === false);
  // a downgraded SHA-1 PBMAC1 store is refused on verify (RFC 9579 sec. 5/7 forbids a <= 160-bit digest).
  var sha1Store = craft(salt, iter, keyLen, "hmacWithSHA1", "hmacWithSHA1", Buffer.alloc(20));
  check("verifyMac refuses a SHA-1 PBMAC1 -> pkcs12/unsupported-algorithm", (await codeOf(pki.pkcs12.verifyMac(sha1Store, "1234"))) === "pkcs12/unsupported-algorithm");
}

async function main() {
  await testVerifyHardening();
  await testEdges();
  await testClassicRoundTrip();
  await testPbmac1RoundTrip();
  await testMacedBytesExactness();
  await testClassicBmpStringPassword();
  await testPbes2Hosts();
  await testNoMac();
  await testMacFailClosed();
  await testAttributes();
  await testFailClosedInputs();
  await testBagTypes();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
