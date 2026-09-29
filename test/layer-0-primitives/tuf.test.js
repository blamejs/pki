// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.tuf: The Update Framework metadata verification.
 *
 * The signing preimage here is a RE-SERIALIZATION, which is the one place this toolkit does that on
 * purpose: TUF signs the canonical JSON form of the `signed` object, so there is no raw byte range to
 * surface and the encoder IS the wire format. Every asymmetry between reading the transport bytes and
 * writing the canonical ones is therefore a signature bypass, which is why the encoder gets
 * known-answer vectors built from the rules rather than from the implementation.
 *
 * Canonical JSON, from the encoder the reference implementation ships:
 *   - object keys lexically sorted, compared by code point
 *   - no whitespace anywhere; `,` between members and `:` between key and value
 *   - in a string, ONLY `\` and `"` are escaped, each with a single backslash; a literal control
 *     character is emitted as itself
 *   - true / false / null as those literals, integers in decimal
 *   - a float is refused, not rounded
 *
 * A KEYID is "a hexdigest of the SHA-256 hash of the canonical form of the key", and the
 * specification says clients MUST calculate each one to verify it is correct for its key, so a
 * metadata file cannot list a key under an identifier that is not its own.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
async function codeAsync(p) { try { await p; return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
function cj(v) { return pki.tuf.canonicalJson(v).toString("utf8"); }

// ---------------------------------------------------------------------------
// Canonical JSON, against answers written from the rules
// ---------------------------------------------------------------------------
function runCanonical() {
  var CASES = [
    ["an empty object", {}, "{}"],
    ["an empty array", [], "[]"],
    ["members in order", { a: 1, b: 2 }, '{"a":1,"b":2}'],
    ["members out of order are sorted", { b: 2, a: 1 }, '{"a":1,"b":2}'],
    ["nested objects are sorted at every level", { a: { c: 1, b: 2 } }, '{"a":{"b":2,"c":1}}'],
    ["arrays keep their order", [3, 1, 2], "[3,1,2]"],
    ["the three literals", [true, false, null], "[true,false,null]"],
    ["a negative integer", { v: -7 }, '{"v":-7}'],
    ["zero", { v: 0 }, '{"v":0}'],
    ["a quote is escaped", { a: 'x"y' }, '{"a":"x\\"y"}'],
    ["a backslash is escaped", { a: "x\\y" }, '{"a":"x\\\\y"}'],
    ["an empty string", { a: "" }, '{"a":""}'],
    ["no whitespace is emitted", { a: [1, { b: 2 }] }, '{"a":[1,{"b":2}]}'],
  ];
  CASES.forEach(function (c) {
    check("J: " + c[0], cj(c[1]) === c[2]);
  });

  /* Only backslash and quote are escaped. A literal control character is emitted
     as itself, which is what makes this encoding NOT JSON.stringify: that would
     write \n and the signature would be over different bytes. */
  var withLf = cj({ a: "one\ntwo" });
  check("J: a literal newline in a string is emitted raw, not as an escape",
    withLf === '{"a":"one\ntwo"}' && withLf.indexOf("\\n") === -1);
  check("J: and that is where JSON.stringify would differ",
    JSON.stringify({ a: "one\ntwo" }).indexOf("\\n") !== -1);
  var withTab = cj({ a: "one\ttwo" });
  check("J: a literal tab is emitted raw too", withTab === '{"a":"one\ttwo"}');

  /* Non-ASCII is emitted as UTF-8, never as a \u escape. */
  var utf8 = pki.tuf.canonicalJson({ a: "é" });
  check("J: a non-ASCII character is emitted as UTF-8 bytes",
    utf8.length === 10 && utf8[6] === 0xc3 && utf8[7] === 0xa9);

  /* Keys are compared by code point, which is not what a default sort does for a
     character outside the basic plane: a surrogate pair sorts below U+FFFF under
     UTF-16 code-unit comparison and above it by code point. */
  var astral = "\u{1F600}";        // U+1F600, a surrogate pair in UTF-16
  var bmpHigh = "�";          // U+FFFD, one code unit
  var sorted = cj((function () { var o = {}; o[astral] = 1; o[bmpHigh] = 2; return o; })());
  check("J: keys sort by code point, so an astral key follows a high BMP key",
    sorted.indexOf(bmpHigh) < sorted.indexOf(astral));
  check("J: and a default UTF-16 sort would have put them the other way",
    [astral, bmpHigh].sort()[0] === astral);

  /* A float is refused rather than rounded: the reference encoder cannot write
     one, so metadata a conforming signer produced never contains one. */
  check("J: a float is refused", code(function () { pki.tuf.canonicalJson({ a: 1.5 }); }) === "tuf/bad-input");
  check("J: a number past the exact-integer range is refused",
    code(function () { pki.tuf.canonicalJson({ a: Math.pow(2, 53) }); }) === "tuf/bad-input");
  check("J: NaN and Infinity are refused",
    code(function () { pki.tuf.canonicalJson({ a: NaN }); }) === "tuf/bad-input" &&
    code(function () { pki.tuf.canonicalJson({ a: Infinity }); }) === "tuf/bad-input");
  check("J: undefined is refused, since it has no encoding",
    code(function () { pki.tuf.canonicalJson({ a: undefined }); }) === "tuf/bad-input");
  check("J: a function is refused", code(function () { pki.tuf.canonicalJson({ a: function () {} }); }) === "tuf/bad-input");
  /* Depth is bounded, so a nested document cannot drive the recursion. */
  var deep = {}, cur = deep;
  for (var i = 0; i < 200; i++) { cur.a = {}; cur = cur.a; }
  check("J: a document deeper than the cap is refused",
    code(function () { pki.tuf.canonicalJson(deep); }) === "tuf/too-deep");
}

// ---------------------------------------------------------------------------
// Keys and key identifiers
// ---------------------------------------------------------------------------
function makeEd25519Key() {
  var kp = crypto.generateKeyPairSync("ed25519");
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  var raw = pki.asn1.decode(spki).children[1].content.subarray(1);
  var key = { keytype: "ed25519", scheme: "ed25519", keyval: { public: raw.toString("hex") } };
  return { kp: kp, key: key, keyId: pki.tuf.keyId(key) };
}
function makeEcdsaKey() {
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var pem = kp.publicKey.export({ format: "pem", type: "spki" });
  var key = { keytype: "ecdsa", scheme: "ecdsa-sha2-nistp256", keyval: { public: pem } };
  return { kp: kp, key: key, keyId: pki.tuf.keyId(key) };
}

function runKeyIds() {
  var ed = makeEd25519Key();
  /* The identifier is the hex SHA-256 of the key's own canonical form, computed
     here independently of the library. */
  var want = crypto.createHash("sha256").update(pki.tuf.canonicalJson(ed.key)).digest("hex");
  check("K: a key identifier is the hex SHA-256 of the key's canonical form", ed.keyId === want);
  check("K: and it is 64 hex characters", ed.keyId.length === 64);
  /* A change anywhere in the key object changes the identifier, which is what
     makes listing a key under someone else's identifier detectable. */
  var altered = JSON.parse(JSON.stringify(ed.key));
  altered.scheme = "ed25519 ";
  check("K: altering any field changes the identifier", pki.tuf.keyId(altered) !== ed.keyId);
  check("K: a key missing keytype, scheme or keyval is refused",
    code(function () { pki.tuf.keyId({ scheme: "ed25519", keyval: { public: "00" } }); }) === "tuf/bad-key" &&
    code(function () { pki.tuf.keyId({ keytype: "ed25519", keyval: { public: "00" } }); }) === "tuf/bad-key" &&
    code(function () { pki.tuf.keyId({ keytype: "ed25519", scheme: "ed25519" }); }) === "tuf/bad-key");
}

// ---------------------------------------------------------------------------
// Metadata parsing and threshold verification
// ---------------------------------------------------------------------------
var EXPIRES = "2030-01-01T00:00:00Z";
var NOW = new Date("2027-01-01T00:00:00Z");

function signWith(signer, signedObj) {
  var preimage = pki.tuf.canonicalJson(signedObj);
  if (signer.key.keytype === "ed25519") {
    return crypto.sign(null, preimage, signer.kp.privateKey).toString("hex");
  }
  return crypto.sign("sha256", preimage, { key: signer.kp.privateKey, dsaEncoding: "der" }).toString("hex");
}
function metadataFor(signedObj, signers) {
  return Buffer.from(JSON.stringify({
    signatures: signers.map(function (s) { return { keyid: s.keyId, sig: signWith(s, signedObj) }; }),
    signed: signedObj,
  }));
}
function rootSigned(o) {
  o = o || {};
  var keys = {};
  (o.signers || []).forEach(function (s) { keys[s.keyId] = s.key; });
  return {
    _type: "root", spec_version: "1.0.31",
    version: o.version === undefined ? 1 : o.version,
    expires: o.expires || EXPIRES,
    consistent_snapshot: true,
    keys: keys,
    roles: o.roles || { root: { keyids: (o.signers || []).map(function (s) { return s.keyId; }),
      threshold: o.threshold === undefined ? 1 : o.threshold } },
  };
}

async function runVerify() {
  var a = makeEd25519Key(), b = makeEd25519Key(), c = makeEcdsaKey();

  var signed = rootSigned({ signers: [a] });
  var meta = pki.tuf.parseMetadata(metadataFor(signed, [a]));
  check("M1: metadata parses into its signed body and its signatures",
    meta.type === "root" && meta.version === 1 && meta.signatures.length === 1);
  check("M2: and the signed bytes are the canonical form of the signed body",
    Buffer.compare(meta.signedBytes, pki.tuf.canonicalJson(signed)) === 0);

  var v = await pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys, role: signed.roles.root });
  check("M3: a single signature meets a threshold of one", v.verified === true && v.keyIds.length === 1);

  /* An ECDSA key and an Ed25519 key in one role, both counted. */
  var two = rootSigned({ signers: [a, c], threshold: 2 });
  var vt = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(metadataFor(two, [a, c])),
    keys: two.keys, role: two.roles.root });
  check("M4: an Ed25519 and an ECDSA signature both count toward one threshold",
    vt.verified === true && vt.keyIds.length === 2);

  /* "each SIGNATURE which is counted towards the THRESHOLD MUST have a unique
     KEYID. Even if a KEYID is listed more than once ... a client MUST NOT count
     more than one verified SIGNATURE from that KEYID." */
  var dupSigned = rootSigned({ signers: [a, b], threshold: 2 });
  var dupBytes = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: signWith(a, dupSigned) }, { keyid: a.keyId, sig: signWith(a, dupSigned) }],
    signed: dupSigned,
  }));
  var dv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(dupBytes),
    keys: dupSigned.keys, role: dupSigned.roles.root });
  check("M5: one key signing twice counts once, so a threshold of two is not met",
    dv.verified === false && dv.keyIds.length === 1);

  /* A signature from a key the role does not list contributes nothing. */
  var outsider = makeEd25519Key();
  var oneSigner = rootSigned({ signers: [a] });
  var withOutsider = Buffer.from(JSON.stringify({
    signatures: [{ keyid: outsider.keyId, sig: signWith(outsider, oneSigner) }],
    signed: oneSigner,
  }));
  var ov = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(withOutsider),
    keys: oneSigner.keys, role: oneSigner.roles.root });
  check("M6: a signature from a key the role does not list counts for nothing",
    ov.verified === false && ov.keyIds.length === 0);

  /* A signature that does not verify counts for nothing, and does not throw:
     whether a threshold was met is a verdict about the metadata. */
  var badSig = Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: "00".repeat(64) }], signed: oneSigner,
  }));
  var bv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(badSig),
    keys: oneSigner.keys, role: oneSigner.roles.root });
  check("M7: a signature that does not verify counts for nothing", bv.verified === false);

  /* The signature is over the canonical form, so altering the body anywhere
     breaks it -- including in a way that leaves the transport JSON valid. */
  var tampered = JSON.parse(metadataFor(oneSigner, [a]).toString("utf8"));
  tampered.signed.version = 2;
  var tv = await pki.tuf.verifySignatures({ metadata: pki.tuf.parseMetadata(Buffer.from(JSON.stringify(tampered))),
    keys: tampered.signed.keys, role: tampered.signed.roles.root });
  check("M8: altering the signed body breaks the signature", tv.verified === false);

  /* A key listed under an identifier that is not its own is refused: the
     specification says a client MUST calculate each identifier. */
  var mislabeled = JSON.parse(JSON.stringify(oneSigner));
  mislabeled.keys = {}; mislabeled.keys[b.keyId] = a.key;
  mislabeled.roles.root.keyids = [b.keyId];
  check("M9: a key listed under an identifier that is not its own is refused",
    await codeAsync(pki.tuf.verifySignatures({
      metadata: pki.tuf.parseMetadata(metadataFor(mislabeled, [a])),
      keys: mislabeled.keys, role: mislabeled.roles.root,
    })) === "tuf/bad-key");

  /* Shape refusals on the wrapper. */
  check("M10: a document with no signatures array is refused",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signed: oneSigner }))); }) === "tuf/bad-metadata");
  check("M11: a document with no signed body is refused",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [] }))); }) === "tuf/bad-metadata");
  check("M12: a signed body with no _type is refused",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [], signed: { version: 1, expires: EXPIRES } }))); }) === "tuf/bad-metadata");
  check("M13: a version that is not a positive integer is refused",
    code(function () { pki.tuf.parseMetadata(metadataFor(rootSigned({ signers: [a], version: 0 }), [a])); }) === "tuf/bad-metadata");
  check("M14: an expires that is not a date-time is refused",
    code(function () { pki.tuf.parseMetadata(metadataFor(rootSigned({ signers: [a], expires: "soon" }), [a])); }) === "tuf/bad-metadata");
  check("M15: a duplicate JSON member is refused before anything is read",
    code(function () { pki.tuf.parseMetadata(Buffer.from('{"signed":{},"signed":{}}')); }) === "tuf/duplicate-member");
  check("M16: a threshold that is not a positive integer is refused",
    await codeAsync(pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys,
      role: { keyids: [a.keyId], threshold: 0 } })) === "tuf/bad-input");

  /* Expiry is a separate question from signatures, asked against a caller instant. */
  check("M17: metadata within its expiry passes the expiry check",
    pki.tuf.checkExpiry(meta, NOW) === true);
  var stale = pki.tuf.parseMetadata(metadataFor(rootSigned({ signers: [a], expires: "2026-01-01T00:00:00Z" }), [a]));
  check("M18: metadata past its expiry is refused, which is the freeze-attack check",
    code(function () { pki.tuf.checkExpiry(stale, NOW); }) === "tuf/expired");
}

// ---------------------------------------------------------------------------
// Root rotation: the chain walk
// ---------------------------------------------------------------------------
async function runRootChain() {
  var k1 = makeEd25519Key(), k2 = makeEd25519Key(), k3 = makeEd25519Key();

  var r1 = rootSigned({ signers: [k1], version: 1 });
  var r1Bytes = metadataFor(r1, [k1]);

  /* "Version N+1 of the root metadata file MUST have been signed by: (1) a
     THRESHOLD of keys specified in the trusted root metadata file (version N),
     and (2) a THRESHOLD of keys specified in the new root metadata file." */
  var r2 = rootSigned({ signers: [k2], version: 2 });
  var r2BothBytes = metadataFor(r2, [k1, k2]);      // old key and new key
  var updated = await pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r2BothBytes], now: NOW });
  check("T1: a root signed by both the old and the new keys is adopted",
    updated.version === 2 && updated.updated === true);

  var r2OldOnly = metadataFor(r2, [k1]);
  check("T2: a root signed only by the OLD keys is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r2OldOnly], now: NOW })) === "tuf/root-unsigned");
  var r2NewOnly = metadataFor(r2, [k2]);
  check("T3: a root signed only by the NEW keys is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r2NewOnly], now: NOW })) === "tuf/root-unsigned");

  /* "The version number of the new root metadata (version N+1) MUST be exactly
     the version in the trusted root metadata (version N) incremented by one." */
  var r3 = rootSigned({ signers: [k3], version: 3 });
  var r3Bytes = metadataFor(r3, [k2, k3]);
  check("T4: a root that skips a version is refused, so no intermediate is passed over",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r3Bytes], now: NOW })) === "tuf/bad-root-version");
  /* The full chain, walked in order. */
  var walked = await pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [r2BothBytes, r3Bytes], now: NOW });
  check("T5: the chain is walked to the latest root, each link verified against the one before",
    walked.version === 3 && walked.updated === true);
  check("T6: and the adopted root's keys are the LAST root's, not the first",
    Object.keys(walked.root.keys).indexOf(k3.keyId) !== -1 &&
    Object.keys(walked.root.keys).indexOf(k1.keyId) === -1);

  /* A candidate whose version goes backwards is a rollback attempt. */
  var r1Again = metadataFor(rootSigned({ signers: [k1], version: 1 }), [k1]);
  check("T7: a candidate at the version already trusted is refused as a rollback",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: r2BothBytes, candidates: [r1Again], now: NOW })) === "tuf/bad-root-version");

  /* With no candidates the trusted root stands, and says it was not updated. */
  var none = await pki.tuf.updateRoot({ trustedRoot: r1Bytes, candidates: [], now: NOW });
  check("T8: with no candidate the trusted root stands and reports no update",
    none.version === 1 && none.updated === false);

  /* An expired root is refused even when the signatures are good. */
  var expiredRoot = metadataFor(rootSigned({ signers: [k1], version: 1, expires: "2026-01-01T00:00:00Z" }), [k1]);
  check("T9: an expired trusted root is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: expiredRoot, candidates: [], now: NOW })) === "tuf/expired");

  /* A root whose own role threshold it does not meet is refused, which is the
     both-thresholds rule applied to the very first root a caller pins. */
  var underThreshold = rootSigned({ signers: [k1, k2], version: 1, threshold: 2 });
  var onlyOne = metadataFor(underThreshold, [k1]);
  check("T10: a trusted root that does not meet its own threshold is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: onlyOne, candidates: [], now: NOW })) === "tuf/root-unsigned");

  /* A root whose _type is not root is not a root. */
  var wrongType = rootSigned({ signers: [k1], version: 1 });
  wrongType._type = "targets";
  check("T11: a document whose _type is not root is refused as a root",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(wrongType, [k1]), candidates: [], now: NOW })) === "tuf/bad-metadata");
  /* A root with no root role cannot state who may sign it. */
  var noRole = rootSigned({ signers: [k1], version: 1 });
  delete noRole.roles.root;
  check("T12: a root that names no root role is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(noRole, [k1]), candidates: [], now: NOW })) === "tuf/bad-metadata");
}

// Every input guard, and the RSA key arm. A guard that never runs is a guard
// nobody has checked.
async function runGuards() {
  var a = makeEd25519Key();
  var signed = rootSigned({ signers: [a] });
  var meta = pki.tuf.parseMetadata(metadataFor(signed, [a]));

  /* An RSA key with the scheme the specification pairs with it. */
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaKey = { keytype: "rsa", scheme: "rsassa-pss-sha256",
    keyval: { public: rsa.publicKey.export({ format: "pem", type: "spki" }) } };
  var rsaId = pki.tuf.keyId(rsaKey);
  var rsaKeys = {}; rsaKeys[rsaId] = rsaKey;
  var rsaSigned = { _type: "root", spec_version: "1.0.31", version: 1, expires: EXPIRES,
    keys: rsaKeys, roles: { root: { keyids: [rsaId], threshold: 1 } } };
  var rsaSig = crypto.sign("sha256", pki.tuf.canonicalJson(rsaSigned), {
    key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  }).toString("hex");
  var rsaMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: rsaId, sig: rsaSig }], signed: rsaSigned })));
  var rv = await pki.tuf.verifySignatures({ metadata: rsaMeta, keys: rsaKeys, role: rsaSigned.roles.root });
  check("G1: an RSA key signing under RSASSA-PSS over SHA-256 verifies", rv.verified === true);
  /* The padding is not read from the document: a PKCS#1 v1.5 signature under the
     same key does not verify, since the scheme the specification pairs with an
     rsa key is PSS. */
  var v15 = crypto.sign("sha256", pki.tuf.canonicalJson(rsaSigned), rsa.privateKey).toString("hex");
  var v15Meta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: rsaId, sig: v15 }], signed: rsaSigned })));
  check("G2: a PKCS#1 v1.5 signature under the same RSA key does not verify",
    (await pki.tuf.verifySignatures({ metadata: v15Meta, keys: rsaKeys, role: rsaSigned.roles.root })).verified === false);
  /* An unreadable PEM, and a key type this build does not read. */
  var badPem = { keytype: "ecdsa", scheme: "ecdsa-sha2-nistp256", keyval: { public: "not a pem" } };
  var bpId = pki.tuf.keyId(badPem); var bpKeys = {}; bpKeys[bpId] = badPem;
  var bpSigned = { _type: "root", version: 1, expires: EXPIRES, keys: bpKeys,
    roles: { root: { keyids: [bpId], threshold: 1 } } };
  var bpMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: bpId, sig: "00" }], signed: bpSigned })));
  check("G3: a public key that is not a readable PEM is refused",
    await codeAsync(pki.tuf.verifySignatures({ metadata: bpMeta, keys: bpKeys, role: bpSigned.roles.root })) === "tuf/bad-key");
  var alien = { keytype: "dilithium", scheme: "dilithium", keyval: { public: "00" } };
  var alId = pki.tuf.keyId(alien); var alKeys = {}; alKeys[alId] = alien;
  var alSigned = { _type: "root", version: 1, expires: EXPIRES, keys: alKeys,
    roles: { root: { keyids: [alId], threshold: 1 } } };
  var alMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: alId, sig: "00" }], signed: alSigned })));
  check("G4: a key type this build does not read is refused, not skipped",
    await codeAsync(pki.tuf.verifySignatures({ metadata: alMeta, keys: alKeys, role: alSigned.roles.root })) === "tuf/unsupported-key");
  /* An ed25519 key of the wrong length, and one that is not a full-order point. */
  var shortEd = { keytype: "ed25519", scheme: "ed25519", keyval: { public: "00".repeat(31) } };
  var seId = pki.tuf.keyId(shortEd); var seKeys = {}; seKeys[seId] = shortEd;
  var seSigned = { _type: "root", version: 1, expires: EXPIRES, keys: seKeys,
    roles: { root: { keyids: [seId], threshold: 1 } } };
  var seMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: seId, sig: "00".repeat(64) }], signed: seSigned })));
  check("G5: an ed25519 key that is not 32 bytes is refused",
    await codeAsync(pki.tuf.verifySignatures({ metadata: seMeta, keys: seKeys, role: seSigned.roles.root })) === "tuf/bad-key");
  var lowOrder = { keytype: "ed25519", scheme: "ed25519", keyval: { public: "00".repeat(32) } };
  var loId = pki.tuf.keyId(lowOrder); var loKeys = {}; loKeys[loId] = lowOrder;
  var loSigned = { _type: "root", version: 1, expires: EXPIRES, keys: loKeys,
    roles: { root: { keyids: [loId], threshold: 1 } } };
  var loMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: loId, sig: "00".repeat(64) }], signed: loSigned })));
  check("G6: an ed25519 key that is not a full-order point is refused before any verify",
    await codeAsync(pki.tuf.verifySignatures({ metadata: loMeta, keys: loKeys, role: loSigned.roles.root })) === "tuf/bad-key");
  /* A signature that is not hex counts for nothing rather than throwing: it is a
     statement this build cannot read, and the metadata may carry another that it
     can. */
  var badHexMeta = pki.tuf.parseMetadata(Buffer.from(JSON.stringify({
    signatures: [{ keyid: a.keyId, sig: "zz" }], signed: signed })));
  check("G7: a signature that is not hex counts for nothing",
    (await pki.tuf.verifySignatures({ metadata: badHexMeta, keys: signed.keys, role: signed.roles.root })).verified === false);

  /* The input guards on each verb. */
  check("G8: keyId refuses a non-object", code(function () { pki.tuf.keyId("x"); }) === "tuf/bad-key" &&
    code(function () { pki.tuf.keyId([]); }) === "tuf/bad-key");
  check("G9: parseMetadata refuses a document that is not an object",
    code(function () { pki.tuf.parseMetadata(Buffer.from("[]")); }) === "tuf/bad-metadata");
  check("G10: parseMetadata refuses a signature entry missing keyid or sig",
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [{ keyid: "a" }], signed: signed }))); }) === "tuf/bad-metadata" &&
    code(function () { pki.tuf.parseMetadata(Buffer.from(JSON.stringify({ signatures: [7], signed: signed }))); }) === "tuf/bad-metadata");
  check("G11: checkExpiry refuses something that is not parsed metadata",
    code(function () { pki.tuf.checkExpiry({}, NOW); }) === "tuf/bad-input");
  check("G12: checkExpiry refuses an instant that is not a Date",
    code(function () { pki.tuf.checkExpiry(meta, "2027-01-01"); }) === "tuf/bad-input");
  check("G13: verifySignatures refuses a keys map that is not an object",
    await codeAsync(pki.tuf.verifySignatures({ metadata: meta, keys: [], role: signed.roles.root })) === "tuf/bad-input");
  check("G14: verifySignatures refuses a keyid that is not 64 characters",
    await codeAsync(pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys,
      role: { keyids: ["short"], threshold: 1 } })) === "tuf/bad-metadata");
  check("G15: verifySignatures refuses a role naming a key the map does not carry",
    await codeAsync(pki.tuf.verifySignatures({ metadata: meta, keys: signed.keys,
      role: { keyids: ["ab".repeat(32)], threshold: 1 } })) === "tuf/bad-metadata");
  check("G16: verifySignatures refuses something that is not parsed metadata",
    await codeAsync(pki.tuf.verifySignatures({ metadata: {}, keys: signed.keys, role: signed.roles.root })) === "tuf/bad-input");

  /* updateRoot's own guards. */
  var rootBytes = metadataFor(rootSigned({ signers: [a], version: 1 }), [a]);
  check("G17: updateRoot refuses candidates that are not an array",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: rootBytes, candidates: "x", now: NOW })) === "tuf/bad-input");
  check("G18: updateRoot refuses an instant that is not a Date",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: rootBytes, candidates: [], now: 1 })) === "tuf/bad-input");
  check("G19: updateRoot omits candidates entirely and the trusted root stands",
    (await pki.tuf.updateRoot({ trustedRoot: rootBytes, now: NOW })).updated === false);
  check("G20: updateRoot refuses a chain past the cap", await (async function () {
    var many = []; for (var i = 0; i < 1100; i++) many.push(rootBytes);
    return await codeAsync(pki.tuf.updateRoot({ trustedRoot: rootBytes, candidates: many, now: NOW }));
  })() === "tuf/bad-input");
  var k2 = makeEd25519Key();
  var dupVersion = metadataFor(rootSigned({ signers: [k2], version: 2 }), [a, k2]);
  check("G21: two candidates stating one version are refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: rootBytes, candidates: [dupVersion, dupVersion], now: NOW })) === "tuf/bad-root-version");
  var noKeys = rootSigned({ signers: [a], version: 1 });
  delete noKeys.keys;
  check("G22: a root carrying no keys map is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(noKeys, [a]), candidates: [], now: NOW })) === "tuf/bad-metadata");
  var noRoles = rootSigned({ signers: [a], version: 1 });
  delete noRoles.roles;
  check("G23: a root carrying no roles map is refused",
    await codeAsync(pki.tuf.updateRoot({ trustedRoot: metadataFor(noRoles, [a]), candidates: [], now: NOW })) === "tuf/bad-metadata");

  /* The code-point comparison's own equal-prefix arm. */
  check("G24: a key that is a prefix of another sorts before it",
    cj((function () { var o = {}; o.ab = 1; o.a = 2; return o; })()) === '{"a":2,"ab":1}');
  check("G25: and two equal keys cannot both exist, so the comparison's equal arm is the same key",
    cj({ a: 1 }) === '{"a":1}');
}

function testSurface() {
  ["canonicalJson", "keyId", "parseMetadata", "verifySignatures", "checkExpiry", "updateRoot"].forEach(function (n) {
    check("pki.tuf." + n + " is exposed", typeof pki.tuf[n] === "function");
  });
}

async function run() {
  testSurface();
  runCanonical();
  runKeyIds();
  await runVerify();
  await runRootChain();
  await runGuards();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
