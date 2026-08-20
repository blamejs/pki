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

// ---- unknown keys on the spec and the options -------------------------------
// A store that silently omits the certificate or the key a caller asked for looks well formed and
// opens cleanly; the omission surfaces wherever it is later imported. `certificates` is the shape
// that caused it -- a plausible plural for the shorthand form's `cert`.
async function testUnknownBuildKeys() {
  var s = signer();
  var spec = { safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] };

  check("an unknown spec field -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build({ safeContents: spec.safeContents, certificates: [s.cert] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("an unknown build option -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build(spec, { password: "1234", nonsenseOption: 1 }))) === "pkcs12/bad-input");
  // verifyMac and open have disjoint option sets; build must not admit theirs.
  check("an option belonging to pkcs12.open -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build(spec, { password: "1234", signerCerts: [s.cert] }))) === "pkcs12/bad-input");
  // A safeContents entry carries the PRIVACY directive for everything inside it, and the entry is
  // where the worst misspelling lands. A present-but-falsy `encrypt` already fails closed, but a
  // MISSPELLED one is neither present nor falsy: it slipped past that guard, no privacy was
  // selected, and the safe went out as plaintext id-data -- an unshrouded keyBag in the clear,
  // inside a PFX whose MAC still verified and which opens without complaint. Refuse before the
  // dispatch, and assert the STORE IS NOT EMITTED rather than only the code.
  async function emittedOf(promise) {
    try { return { out: await promise, code: null }; } catch (e) { return { out: null, code: e && e.code }; }
  }
  function keyBagSafe(privacyKey) {
    var sc = { bags: [{ type: "key", key: s.key }] };
    sc[privacyKey] = { password: "1234" };
    return { safeContents: [sc] };
  }
  var typo = await emittedOf(pki.pkcs12.build(keyBagSafe("encrpyt"), { password: "1234" }));
  check("a misspelled safeContents privacy directive -> pkcs12/bad-input", typo.code === "pkcs12/bad-input");
  check("...and NO store is emitted", typo.out === null);
  // The control that gives the vector its stakes: spelled correctly, the private key does not
  // appear in the emitted bytes. Without the door the misspelled call above emitted it verbatim.
  var priv = await pki.pkcs12.build(keyBagSafe("encrypt"), { password: "1234" });
  check("encrypt spelled correctly -> the private key is not in the emitted store",
    Buffer.from(priv).indexOf(Buffer.from(s.key)) === -1);
  // The spec has two mutually exclusive FORMS. _normalizeSpec returns spec.safeContents the moment
  // it is an array and never reads the shorthand fields, so a union built a store with the key
  // silently absent -- the same omission the door exists to refuse, reached by mixing forms.
  var mixedForm = await emittedOf(pki.pkcs12.build(
    { safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }], key: s.key }, { password: "1234" }));
  check("the full form mixed with a shorthand field -> pkcs12/bad-input", mixedForm.code === "pkcs12/bad-input");
  check("...and NO store is emitted", mixedForm.out === null);
  check("each form on its own still builds",
    (await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234" })) != null &&
    (await pki.pkcs12.build({ key: s.key, cert: s.cert }, { password: "1234" })) != null);

  // opts answers to the same two forms. recipientCerts is read only where _normalizeSpec assembles
  // the safes itself, so under the full form it selected nothing: a plaintext key bag was emitted as
  // an id-data safe while the caller had asked for recipient-enveloped privacy. Artifact asserted absent.
  var rcpt = signing.makeRecipient("rsa");
  var fullRecip = await emittedOf(pki.pkcs12.build(
    { safeContents: [{ bags: [{ type: "key", key: s.key }] }] },
    { password: "1234", recipientCerts: [rcpt.cert] }));
  check("recipientCerts under the safeContents form -> pkcs12/bad-input", fullRecip.code === "pkcs12/bad-input");
  check("...and NO store is emitted", fullRecip.out === null);
  check("the shorthand form still reads recipientCerts",
    (await pki.pkcs12.build({ key: s.key, cert: s.cert }, { password: "1234", recipientCerts: [rcpt.cert] })) != null);
  check("the full form carries privacy per entry instead",
    (await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "key", key: s.key }], recipients: [{ cert: rcpt.cert }] }] },
      { password: "1234" })) != null);

  // Which form a spec is gets decided ONCE and the door and the builder both act on that decision.
  // Decided separately the two spellings drift, and the door then checks a form the builder will
  // not assemble. (A spec supplying the field through an accessor is refused before either looks.)
  var accessorSpec = {};
  Object.defineProperty(accessorSpec, "safeContents", {
    enumerable: true, get: function () { return [{ bags: [{ type: "cert", cert: s.cert }] }]; },
  });
  check("an accessor-backed spec field is refused outright",
    (await codeOf(pki.pkcs12.build(accessorSpec, { password: "1234" }))) === "pkcs12/bad-input");
  // A safeContents that is present but not a list is not the full form. It is named as the field
  // that is wrong, rather than switching the door to a form the builder will not assemble.
  // The MAC descriptor is checked against the algorithm it selects. The classic Appendix B key
  // derivation produces a key at the hash's own output length, so a keyLength there was an explicit
  // security parameter that emitted the same MAC as the call that never named it.
  check("keyLength on a classic HMAC MAC -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] },
      { password: "1234", mac: { algorithm: "hmac", keyLength: 64 } }))) === "pkcs12/bad-input");
  check("...and on the default algorithm, which is the classic one",
    (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] },
      { password: "1234", mac: { keyLength: 64 } }))) === "pkcs12/bad-input");
  check("keyLength on a PBMAC1 MAC is still read",
    (await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] },
      { password: "1234", mac: { algorithm: "pbmac1", hash: "sha256", keyLength: 32 } })) != null);
  check("an unrecognized algorithm is still named by _buildMacData",
    (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] },
      { password: "1234", mac: { algorithm: "hmc", keyLength: 64 } }))) === "pkcs12/bad-input");

  var notAList = null;
  try { await pki.pkcs12.build({ safeContents: { bags: [] }, key: s.key, cert: s.cert }, { password: "1234" }); }
  catch (e) { notAList = e; }
  check("a non-list safeContents -> pkcs12/bad-input naming safeContents",
    notAList != null && notAList.code === "pkcs12/bad-input" && /field "safeContents"/.test(notAList.message));

  // A safeContents entry is checked against the privacy branch it selects. contentEncryptionAlgorithm
  // is the public-key branch's cipher and is read by nothing on a password safe, whose cipher comes
  // from encrypt.cipher -- so an explicit request was accepted and the default used anyway.
  check("a public-key cipher field on a password safe -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }],
      encrypt: { password: "1234" }, contentEncryptionAlgorithm: "aes-128-cbc" }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("the cipher a password safe DOES read still builds",
    (await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }],
      encrypt: { password: "1234", cipher: "aes-128-cbc" } }] }, { password: "1234" })) != null);
  check("an encrypt field on a plaintext safe is still the directive, not an unknown key",
    (await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234" })) != null);

  check("an unknown safeContents field -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }], recipient: [] }] },
      { password: "1234" }))) === "pkcs12/bad-input");

  // Same rule one level down: the bag, and the encrypt descriptor it carries. A misspelled bag
  // attribute is dropped from the emitted bag; a misspelled PBE parameter silently reverts to the
  // default, so a caller who asked for a stronger KDF gets the built-in one and nothing says so.
  check("an unknown bag field -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert, freindlyName: "x" }] }] },
      { password: "1234" }))) === "pkcs12/bad-input");
  // Per TYPE, not one union: `encrypt` is real on a shroudedKey bag and read by nothing on a plain
  // key bag, so a union table accepted it and emitted the private key as a plaintext keyBag while
  // the caller had supplied an explicit encryption directive. The artifact is asserted absent.
  var wrongArm = await emittedOf(pki.pkcs12.build(
    { safeContents: [{ bags: [{ type: "key", key: s.key, encrypt: { password: "1234" } }] }] },
    { password: "1234" }));
  check("encrypt on a plaintext key bag -> pkcs12/bad-input", wrongArm.code === "pkcs12/bad-input");
  check("...and NO store is emitted", wrongArm.out === null);
  check("the same field on a shroudedKey bag still builds",
    (await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key, encrypt: { password: "1234" } }] }] },
      { password: "1234" })) != null);
  check("a cert field on a key bag -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "key", key: s.key, cert: s.cert }] }] },
      { password: "1234" }))) === "pkcs12/bad-input");
  check("an unknown encrypt-descriptor field -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key,
      encrypt: { password: "1234", iteration: 4096 } }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  // Every real field at both levels still builds.
  check("the documented bag and encrypt fields still build",
    (await pki.pkcs12.build({ safeContents: [{ bags: [
      { type: "shroudedKey", key: s.key, encrypt: { password: "1234", cipher: "aes-128-cbc", iterations: 4096 },
        friendlyName: "k", localKeyId: Buffer.from([1, 2]) },
      { type: "cert", cert: s.cert, friendlyName: "c" },
    ] }] }, { password: "1234" })) != null);

  // opts.mac is the third descriptor this verb reads, and every one of its fields has a default,
  // so a misspelled `iterations` produced a store MAC'd at the shipped iteration count while the
  // caller believed they had raised it.
  check("an unknown mac-descriptor field -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { algorithm: "hmac", iteration: 4096 } }))) === "pkcs12/bad-input");
  // An array satisfies typeof "object" and carries no name any table lists, so it slipped through
  // as an empty descriptor and produced the DEFAULT MAC. opts.integrity already excluded arrays.
  check("an array opts.mac -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: [] }))) === "pkcs12/bad-input");
  check("a non-empty array opts.mac -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: [1, 2] }))) === "pkcs12/bad-input");
  check("opts.mac false still omits the MAC",
    (await pki.pkcs12.build(spec, { password: "1234", mac: false })) != null);
  check("the documented mac fields still build",
    (await pki.pkcs12.build(spec, { password: "1234", mac: { algorithm: "hmac", hash: "sha256", iterations: 4096 } })) != null);

  // The two READING verbs take their own disjoint option sets. `maxIterations` caps the work a
  // hostile store can demand, so a misspelling restored the built-in ceiling and the tighter bound
  // the caller set was never applied.
  var p12 = await pki.pkcs12.build(spec, { password: "1234" });
  check("pki.pkcs12.open, a misspelled maxIterations -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.open(p12, "1234", { maxIteration: 1000 }))) === "pkcs12/bad-input");
  check("pki.pkcs12.open, a build option -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.open(p12, "1234", { mac: { iterations: 2048 } }))) === "pkcs12/bad-input");
  check("pki.pkcs12.verifyMac, a misspelled maxIterations -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.verifyMac(p12, "1234", { maxIteration: 1000 }))) === "pkcs12/bad-input");
  check("the documented open options are still accepted",
    (await pki.pkcs12.open(p12, "1234", { maxIterations: 200000 })) != null);
  // recipientIndex is read by cms-decrypt, which open hands this whole options object to. A table
  // built from this module's own reads would refuse it and break selecting a recipient by index.
  check("an option open forwards to the CMS layer is still accepted",
    (await pki.pkcs12.open(p12, "1234", { recipientIndex: 0 })) != null);
  check("the documented verifyMac option is still accepted",
    (await pki.pkcs12.verifyMac(p12, "1234", { maxIterations: 200000 })) === true);

  // The shorthand form and every real build option still work.
  check("the { key, cert } shorthand still builds",
    (await pki.pkcs12.build({ key: s.key, cert: s.cert }, { password: "1234" })) != null);
  check("pem is still accepted",
    typeof (await pki.pkcs12.build(spec, { password: "1234", pem: true })) === "string");
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

// ---- #11 public-key integrity config-time rejects + fail-closed inputs ------
// (the public-key integrity round-trip surface lives in pkcs12-public-key.test.js)
async function testFailClosedInputs() {
  var s = signer();
  check("#11 public-key integrity with no signer -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { integrity: { mode: "public-key" }, password: "1234" }))) === "pkcs12/bad-input");
  // The integrity signers are authoring input for this store, so they answer to the same rule as
  // every other field written here. Every field beyond the identity has a default, so a misspelled
  // signature parameter signed the store under PKCS#1 with SHA-256 while the caller asked for PSS,
  // and the store records only what was used.
  var spec11 = { safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] };
  check("a misspelled signature parameter on an integrity signer -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build(spec11, { password: "1234",
      integrity: { mode: "public-key", signer: { cert: s.cert, key: s.key, ps: true } } }))) === "pkcs12/bad-input");
  check("a key-only field on a certificate signer -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build(spec11, { password: "1234",
      integrity: { mode: "public-key", signers: [{ cert: s.cert, key: s.key, keyIdentifier: Buffer.alloc(20) }] } }))) === "pkcs12/bad-input");
  check("the parameters spelled correctly still sign the store",
    (await pki.pkcs12.build(spec11, { password: "1234",
      integrity: { mode: "public-key", signer: { cert: s.cert, key: s.key, pss: true, digestAlgorithm: "sha384" } } })) != null);
  check("an unknown bag type -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "bogus" }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a keyBag with non-key bytes -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "key", key: Buffer.from([1, 2, 3]) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a shroudedKey with non-key bytes -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: Buffer.from([1, 2, 3]) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a null bag -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [null] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a null safeContents entry -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [null] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a non-object safeContents entry -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: ["nope"] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("spec.ca that is not an array -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ key: s.key, cert: s.cert, ca: "nope" }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a non-object opts.mac -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234", mac: "yes" }))) === "pkcs12/bad-input");
  // a shroudedKey with no encrypt block inherits opts.password + the default cipher (the bag.encrypt || {} arm).
  var pdef = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "shroudedKey", key: s.key }] }] }, { password: "1234" });
  check("a shroudedKey with no encrypt block uses opts.password + defaults", (await pki.pkcs12.verifyMac(pdef, "1234")) === true);
  check("a certBag with non-cert bytes -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: Buffer.from([1, 2, 3]) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a crlBag with non-CRL bytes -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "crl", crl: Buffer.from([1, 2, 3]) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a secret bag with a garbage secretTypeId -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "secret", secretTypeId: "not an oid", secretValue: b.octetString(Buffer.from("x")) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
  check("a non-string secretTypeId -> pkcs12/bad-input (domain-wrapped, not oid/*)", (await codeOf(pki.pkcs12.build({ safeContents: [{ bags: [{ type: "secret", secretTypeId: 42, secretValue: b.octetString(Buffer.from("x")) }] }] }, { password: "1234" }))) === "pkcs12/bad-input");
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
  // an arbitrary (unregistered) dotted-decimal secretTypeId OID is preserved verbatim.
  var pdotted = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "secret", secretTypeId: "1.2.3.4.5", secretValue: b.octetString(Buffer.from("s")) }] }] }, { password: "1234" });
  check("a secret bag with an arbitrary OID secretTypeId round-trips", (await pki.pkcs12.verifyMac(pdotted, "1234")) === true && pki.schema.pkcs12.parse(pdotted).safeBags[0].secretTypeId === "1.2.3.4.5");
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
  // An OMITTED password is refused rather than silently encoded as the empty one. Without this a
  // caller who misspells the option -- or threads it through a layer that drops it -- gets a store
  // whose contents are protected by nothing, and nothing anywhere says so.
  check("build with no opts -> pkcs12/bad-input, not an empty-password store",
    (await codeOf(pki.pkcs12.build(spec))) === "pkcs12/bad-input");
  check("build with a misspelled password option -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build(spec, { passwrod: "s3cr3t" }))) === "pkcs12/bad-input");
  // The empty password remains available -- it just has to be asked for.
  var pEmptyPw = await pki.pkcs12.build(spec, { password: "" });
  check("an explicit empty password still builds a MACed store", pki.schema.pkcs12.parse(pEmptyPw).integrityMode === "password");
  check("verifyMac with the empty password accepts it", (await pki.pkcs12.verifyMac(pEmptyPw, "")) === true);
  // The integrity mode is validated against the permitted value, not compared to one literal: any
  // other spelling silently selected password integrity and dropped the signer with it.
  check("integrity.mode 'publicKey' -> pkcs12/bad-integrity-mode, not a silent password MAC",
    (await codeOf(pki.pkcs12.build(spec, { password: "1234", integrity: { mode: "publicKey", signer: { cert: s.cert, key: s.key } } }))) === "pkcs12/bad-integrity-mode");
  check("an unknown opts.integrity option -> pkcs12/bad-input",
    (await codeOf(pki.pkcs12.build(spec, { password: "1234", integrity: { mode: "public-key", signers: [{ cert: s.cert, key: s.key }], signerz: 1 } }))) === "pkcs12/bad-input");
  // An integrity verb reads two things that must have come from one place: the MACed byte range,
  // and the bags handed back as verified. On a parsed store they are separate properties, so a
  // REBUILT object can pair one store's macedBytes with another's contents -- verify this, return
  // that. The parser marks what it returns and the door asks for the mark, so the documented parsed
  // form keeps working and only a rebuilt one is refused.
  var p12 = await pki.pkcs12.build(spec, { password: "1234" });
  check("the parser's own result is still accepted", (await pki.pkcs12.verifyMac(pki.schema.pkcs12.parse(p12), "1234")) === true);
  check("...by open too", (await pki.pkcs12.open(pki.schema.pkcs12.parse(p12), "1234")).macVerified === true);
  check("bytes and PEM are unchanged", (await pki.pkcs12.verifyMac(p12, "1234")) === true);
  // Object.assign and spread copy own ENUMERABLE properties, which is exactly how the mixed object
  // is built -- and exactly what the mark does not survive.
  check("an Object.assign copy is refused: it is no longer the store the parser produced",
    await codeOf(pki.pkcs12.verifyMac(Object.assign({}, pki.schema.pkcs12.parse(p12)), "1234")) === "pkcs12/bad-input");
  check("...and a spread copy likewise", await codeOf(pki.pkcs12.open({ ...pki.schema.pkcs12.parse(p12) }, "1234")) === "pkcs12/bad-input");
  check("a hand-built object naming any store field is refused, not read as bad bytes",
    await codeOf(pki.pkcs12.verifyMac({ macedBytes: Buffer.alloc(0) }, "1234")) === "pkcs12/bad-input");
  // A mark that only said "this came from the parser" would survive both of these, which is why the
  // record carries the BYTES and the door re-derives from them. Editing the object in place leaves
  // any flag intact while the fields describe something else; Object.create inherits every symbol
  // through the prototype chain while letting each field be shadowed.
  var mutated = pki.schema.pkcs12.parse(p12);
  mutated.macedBytes = Buffer.alloc(8, 9);
  check("editing a parsed store in place does not change the verdict: it is re-derived",
    (await pki.pkcs12.verifyMac(mutated, "1234")) === true);
  var shadowed = Object.create(pki.schema.pkcs12.parse(p12));
  shadowed.macedBytes = Buffer.alloc(8, 9);
  check("an Object.create shadow does not inherit provenance it did not earn",
    await codeOf(pki.pkcs12.verifyMac(shadowed, "1234")) === "pkcs12/bad-input");
  var openedMutated = pki.schema.pkcs12.parse(p12);
  openedMutated.safeBags = [];
  check("open returns the bags of the store the MAC was checked over, not the edited list",
    (await pki.pkcs12.open(openedMutated, "1234")).certs.length === 1);
  // a safeContents element with no bags (the sc.bags || [] arm) alongside a real one.
  var pempty = await pki.pkcs12.build({ safeContents: [{ bags: [{ type: "cert", cert: s.cert }] }, {}] }, { password: "1234" });
  check("an empty safeContents element is tolerated", (await pki.pkcs12.verifyMac(pempty, "1234")) === true);
  // an encrypted safe that omits its own password falls back to opts.password.
  var pshared = await pki.pkcs12.build({ safeContents: [{ encrypt: { cipher: "aes-256-cbc" }, bags: [{ type: "cert", cert: s.cert }] }] }, { password: "1234" });
  check("an encrypted safe inherits opts.password", (await pki.pkcs12.verifyMac(pshared, "1234")) === true);
  // a MAC-specific password (mac.password) overrides the shared password; an explicit MAC salt is honored.
  var pmacpw = await pki.pkcs12.build(spec, { password: "privpw", mac: { password: "macpw", salt: Buffer.alloc(8, 2) } });
  check("mac.password overrides the shared password", (await pki.pkcs12.verifyMac(pmacpw, "macpw")) === true && (await pki.pkcs12.verifyMac(pmacpw, "privpw")) === false);
  // an empty or over-cap MAC salt is rejected on build.
  check("an empty MAC salt -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { salt: Buffer.alloc(0) } }))) === "pkcs12/bad-input");
  check("an over-cap MAC salt -> pkcs12/bad-input", (await codeOf(pki.pkcs12.build(spec, { password: "1234", mac: { salt: Buffer.alloc(pki.constants.LIMITS.PBKDF2_MAX_SALT + 1) } }))) === "pkcs12/bad-input");
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
  check("verifyMac rejects an over-hard-cap PBMAC1 iteration count -> pkcs12/iteration-limit", (await codeOf(pki.pkcs12.verifyMac(overCap, "1234"))) === "pkcs12/iteration-limit");
  // the classic App B MAC (a synchronous KDF loop) has a far lower iteration cap than PBMAC1's native PBKDF2.
  var classicOver = await pki.pkcs12.build(spec, { password: "1234", mac: { algorithm: "hmac", hash: "sha256", iterations: 2000001 } }).then(function () { return "NO-THROW"; }, function (e) { return e.code; });
  check("build rejects a classic MAC iteration count over its lower cap -> pkcs12/bad-input", classicOver === "pkcs12/bad-input");
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
  // a below-floor PBMAC1 keyLength is refused on verify too (RFC 9579 sec. 9).
  var shortKl = craft(salt, iter, 10, "hmacWithSHA256", "hmacWithSHA256", Buffer.alloc(32));
  check("verifyMac refuses a below-floor PBMAC1 keyLength -> pkcs12/bad-input", (await codeOf(pki.pkcs12.verifyMac(shortKl, "1234"))) === "pkcs12/bad-input");
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
  await testUnknownBuildKeys();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
