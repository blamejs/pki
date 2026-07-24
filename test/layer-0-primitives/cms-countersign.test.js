// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// Layer 0 -- pki.cms.countersign + the unsigned-attribute surface (RFC 5652 sec. 5.3 unsignedAttrs,
// sec. 11.4 id-countersignature). Drives the shipped consumer path sign -> countersign -> verify and
// asserts through pki.schema.cms.parse and err.code. A countersignature signs over the CONTENTS of the
// countersigned SignerInfo's signature OCTET STRING (sec. 11.4) -- NOT the eContent -- so the #1 fragile
// case is the preimage: a countersignature bound to the wrong bytes fails closed. Unsigned attributes
// are outside the top-level signature (tag [1], 0xA1) -- surfaced but NEVER reported authenticated.
// Cross-implementation verification (OpenSSL over the sec. 11.4 preimage, a real RFC 3161 token) lives
// in test/integration/cms-countersign-openssl-interop.test.js.
//
// RED baseline: pki.cms.countersign is undefined and verify does not yet surface
// countersignatures/unsignedAttrs, so every vector fails until the extension lands.

var helpers = require("../helpers");
var signing = require("../helpers/signing");
var pki = helpers.pki;
var check = helpers.check;
var makeSigner = signing.makeSigner;
var makeCompositeSigner = signing.makeCompositeSigner;
var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }

var CONTENT = Buffer.from("hello CMS countersignature");

async function rejects(label, fn, code) {
  var e = null;
  try { await fn(); } catch (err) { e = err; }
  check(label + " throws", e !== null);
  check(label + " code=" + code, e && e.code === code);
}
async function codeOf(promise) { try { await promise; return null; } catch (e) { return e && e.code; } }

// A base SignedData signed by a primary signer of `alg` (attached, embedded cert).
async function signBase(alg, opts) {
  var s = makeSigner(alg || "ec-p256", opts);
  var cms = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key }, {});
  return { cms: cms, signer: s };
}
function parse(der) { return pki.schema.cms.parse(der); }

// The countersignature attribute (id-countersignature) on a parsed SignerInfo, or null.
function csAttr(si) {
  var t = O("countersignature");
  return (si.unsignedAttrs || []).filter(function (a) { return a.type === t; })[0] || null;
}
// The raw signature-value octets of a countersignature value (a SignerInfo DER): the last child.
function sigOctetsOf(siDer) {
  var node = pki.asn1.decode(siDer);
  var last = node.children[node.children.length - 1];   // OCTET STRING signature (last field)
  return pki.asn1.read.octetString(last);
}
// Flip the last byte of `region` wherever it occurs in `der` (a targeted, offset-free tamper).
function flipRegion(der, region) {
  var i = der.indexOf(region);
  if (i < 0) throw new Error("flipRegion: region not found");
  var out = Buffer.from(der);
  out[i + region.length - 1] ^= 0xff;
  return out;
}

// ---- 1 / 7 PREIMAGE-POSITIVE + per-algorithm matrix ------------------------
async function testPreimagePositiveAndMatrix() {
  var base = await signBase("ec-p256");
  var cs = makeSigner("rsa");
  var out = await pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key }, {});
  var res = await pki.cms.verify(out);
  check("#1 primary still valid after countersign", res.valid === true && res.signers[0].ok === true);
  check("#1 one countersignature, ok", res.signers[0].countersignatures.length === 1 && res.signers[0].countersignatures[0].ok === true);
  check("#1 countersigner cert surfaced", Buffer.isBuffer(res.signers[0].countersignatures[0].cert));

  // #7 per-algorithm: each countersigner arm over a fixed ECDSA primary.
  var arms = ["rsa", "rsa-pss", "ec-p256", "ec-p384", "ec-p521", "ed25519", "ed448", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128s"];
  for (var i = 0; i < arms.length; i++) {
    var b0 = await signBase("ec-p256");
    var ck = makeSigner(arms[i]);
    var o = await pki.cms.countersign(b0.cms, { cert: ck.cert, key: ck.key }, {});
    var r = await pki.cms.verify(o);
    check("#7 countersign arm " + arms[i] + " -> ok", r.signers[0].countersignatures[0].ok === true);
  }
  // composite ML-DSA countersigner
  var bc = await signBase("ec-p256");
  var comp = makeCompositeSigner("id-MLDSA65-ECDSA-P256-SHA512");
  var oc = await pki.cms.countersign(bc.cms, { cert: comp.cert, key: comp.key }, {});
  var rc = await pki.cms.verify(oc);
  check("#7 composite ML-DSA countersigner -> ok", rc.signers[0].countersignatures[0].ok === true);
}

// ---- 2 PREIMAGE-NEGATIVE (wrong bytes -> message-digest-mismatch) ----------
async function testPreimageNegative() {
  var base = await signBase("ec-p256");
  var cs = makeSigner("ec-p256");
  var out = await pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key }, {});
  // Tamper the PRIMARY signature octets: the countersignature's message-digest was bound to the
  // ORIGINAL primary signature (sec. 11.4), so it no longer equals digest(the tampered signature).
  var primarySig = parse(out).signerInfos[0].signature;
  var tampered = flipRegion(out, primarySig);
  var res = await pki.cms.verify(tampered);
  check("#2 tampered primary -> primary invalid", res.signers[0].ok === false);
  check("#2 countersignature bound to the primary signature -> message-digest-mismatch",
    res.signers[0].countersignatures[0].ok === false && res.signers[0].countersignatures[0].code === "cms/message-digest-mismatch");
}

// ---- 3 FORBIDDEN-CONTENT-TYPE-REJECTED -------------------------------------
async function testForbiddenContentType() {
  var base = await signBase("ec-p256");
  var cs = makeSigner("ec-p256");
  // countersign must REFUSE to produce a countersignature carrying a content-type signed attribute.
  check("#3 countersign rejects a content-type additional signed attr",
    (await codeOf(pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key }, {
      additionalSignedAttributes: [{ type: "contentType", values: [b.oid(O("data"))] }],
    }))) === "cms/bad-input");
}

// ---- 4 UNSIGNED-ATTR-SURFACED-NOT-AUTHENTICATED ----------------------------
async function testUnsignedAttrNotAuthenticated() {
  var s = makeSigner("ec-p256");
  var opaque = b.sequence([b.oid(O("data")), b.octetString(Buffer.from("ts"))]);   // a stand-in unsigned attr value
  var out = await pki.cms.sign(CONTENT, { cert: s.cert, key: s.key }, {
    unsignedAttributes: [{ type: "timeStampToken", values: [opaque] }],
  });
  var res = await pki.cms.verify(out);
  check("#4 primary valid with an unsigned attribute attached", res.valid === true && res.signers[0].ok === true);
  var ua = (res.signers[0].unsignedAttrs || []).filter(function (a) { return a.type === O("timeStampToken"); })[0];
  check("#4 unsigned attribute surfaced decoded", ua != null && ua.values.length === 1);
  check("#4 unsigned attribute typeName resolved", ua && ua.typeName === "timeStampToken");
  // Mutating the unsigned attribute does NOT change the top-level verdict (it is not signed).
  var mutated = flipRegion(out, Buffer.from("ts"));
  var res2 = await pki.cms.verify(mutated);
  check("#4 mutating an unsigned attribute leaves res.valid unchanged", res2.valid === true && res2.signers[0].ok === true);
}

// ---- 5 RECURSIVE-COUNTERSIGNATURE ------------------------------------------
async function testRecursive() {
  var base = await signBase("ec-p256");
  var cs1 = makeSigner("ec-p256");
  var out1 = await pki.cms.countersign(base.cms, { cert: cs1.cert, key: cs1.key }, {});
  // countersign the countersignature itself (a countersignature of a countersignature).
  var cs2 = makeSigner("rsa");
  var out2 = await pki.cms.countersign(out1, { cert: cs2.cert, key: cs2.key }, { countersignatureOf: 0 });
  var res = await pki.cms.verify(out2);
  var cnode = res.signers[0].countersignatures[0];
  check("#5 outer countersignature ok", cnode.ok === true);
  check("#5 nested countersignature-of-countersignature ok",
    cnode.countersignatures && cnode.countersignatures[0] && cnode.countersignatures[0].ok === true);
}

// ---- 6 VALID-REGARDLESS (present-but-invalid cs does not flip res.valid) ---
async function testValidRegardless() {
  var base = await signBase("ec-p256");
  var cs = makeSigner("ec-p256");
  var out = await pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key }, {});
  // Flip the countersignature's OWN signature -> its crypto verdict fails; the primary stays valid.
  var csDer = csAttr(parse(out).signerInfos[0]).values[0];
  var flipped = flipRegion(out, sigOctetsOf(csDer));
  var res = await pki.cms.verify(flipped);
  check("#6 primary stays valid despite a broken countersignature", res.valid === true && res.signers[0].ok === true);
  check("#6 broken countersignature surfaced ok:false", res.signers[0].countersignatures[0].ok === false);

  // A countersigner cert not embedded and not supplied -> cert-not-found, primary still valid. The
  // countersigner needs a UNIQUE issuer+serial so no embedded cert matches its signer identifier.
  var cs2 = makeSigner("ec-p256", { serial: 0x5c2, cn: "Countersigner NotEmbedded" });
  var out2 = await pki.cms.countersign(base.cms, { cert: cs2.cert, key: cs2.key }, { certificates: false });
  var res2 = await pki.cms.verify(out2);
  check("#6 missing countersigner cert -> ok:false + signer-cert-not-found, primary valid",
    res2.valid === true && res2.signers[0].countersignatures[0].ok === false && res2.signers[0].countersignatures[0].code === "cms/signer-cert-not-found");

  // a MALFORMED countersignature value (an INTEGER, not a SignerInfo) in a hand-supplied parse result
  // -> the value fails to walk, surfaced ok:false with a typed code; the primary stays valid.
  var good = await pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key }, {});
  var parsed = parse(good);
  parsed.signerInfos[0].unsignedAttrs.filter(function (a) { return a.type === O("countersignature"); })[0].values[0] = b.integer(5n);
  var res3 = await pki.cms.verify(parsed);
  check("#6 a malformed countersignature value -> ok:false + typed code, primary valid",
    res3.valid === true && res3.signers[0].countersignatures[0].ok === false && typeof res3.signers[0].countersignatures[0].code === "string");
}

// ---- 8 NO-SIGNED-ATTRS COUNTERSIGNATURE ------------------------------------
async function testNoSignedAttrs() {
  var base = await signBase("ec-p256");
  var cs = makeSigner("ec-p256");
  var out = await pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key }, { signedAttributes: false });
  var res = await pki.cms.verify(out);
  check("#8 no-signedAttrs countersignature (signs the primary sig octets directly) -> ok",
    res.signers[0].countersignatures[0].ok === true);
  // Tamper the primary sig -> the direct-preimage countersignature fails (crypto false, no md attr).
  var tampered = flipRegion(out, parse(out).signerInfos[0].signature);
  var res2 = await pki.cms.verify(tampered);
  check("#8 tampered primary -> no-attrs countersignature ok:false", res2.signers[0].countersignatures[0].ok === false);
}

// ---- 9 MULTI-SIGNER TARGET -------------------------------------------------
async function testMultiSignerTarget() {
  var s0 = makeSigner("ec-p256"), s1 = makeSigner("rsa");
  var cms = await pki.cms.sign(CONTENT, [{ cert: s0.cert, key: s0.key }, { cert: s1.cert, key: s1.key }], {});
  var before = parse(cms).signerInfos;
  var cs = makeSigner("ec-p256");
  var out = await pki.cms.countersign(cms, { cert: cs.cert, key: cs.key }, { signerIndex: 1 });
  var after = parse(out).signerInfos;
  // Signer 0 (untargeted) is byte-identical; signer 1 gains the countersignature.
  check("#9 untargeted signer 0 unchanged", Buffer.compare(before[0].signature, after[0].signature) === 0 && csAttr(after[0]) === null);
  check("#9 targeted signer 1 gains a countersignature", csAttr(after[1]) != null);
  var res = await pki.cms.verify(out);
  check("#9 both primaries valid + signer 1 countersignature ok",
    res.valid === true && res.signers[1].countersignatures[0].ok === true && res.signers[0].countersignatures.length === 0);
}

// ---- 10 MULTIPLE COUNTERSIGNATURES = ONE ATTRIBUTE -------------------------
async function testMultipleCountersignatures() {
  var base = await signBase("ec-p256");
  var a = makeSigner("ec-p256"), c = makeSigner("rsa");
  var out1 = await pki.cms.countersign(base.cms, { cert: a.cert, key: a.key }, {});
  var out2 = await pki.cms.countersign(out1, { cert: c.cert, key: c.key }, {});
  var attr = csAttr(parse(out2).signerInfos[0]);
  check("#10 two countersignatures land as two VALUES in ONE id-countersignature attribute",
    attr != null && attr.values.length === 2);
  var res = await pki.cms.verify(out2);
  check("#10 both countersignatures verify", res.signers[0].countersignatures.length === 2 && res.signers[0].countersignatures.every(function (x) { return x.ok === true; }));
}

// ---- 11 BYTE-PRESERVATION --------------------------------------------------
async function testBytePreservation() {
  var base = await signBase("ec-p256");
  var before = parse(base.cms).signerInfos[0];
  var cs = makeSigner("ec-p256");
  var out = await pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key }, {});
  var after = parse(out).signerInfos[0];
  check("#11 targeted primary signedAttrsBytes preserved byte-for-byte", Buffer.compare(before.signedAttrsBytes, after.signedAttrsBytes) === 0);
  check("#11 targeted primary signature preserved byte-for-byte", Buffer.compare(before.signature, after.signature) === 0);
  var res = await pki.cms.verify(out);
  check("#11 primary still verifies after the splice", res.signers[0].ok === true);
}

// ---- 12 TIMESTAMP-TOKEN ROUND-TRIP (real RFC 3161 token) -------------------
async function testTimestampToken() {
  var base = await signBase("ec-p256");
  var primarySig = parse(base.cms).signerInfos[0].signature;
  var digest = require("crypto").createHash("sha256").update(primarySig).digest();
  var tsa = makeSigner("ec-p256");
  var token = await pki.tsp.sign({ hashAlgorithm: "sha256", hashedMessage: digest }, tsa, { policy: "1.2.3.4.1", serialNumber: 7 });
  // Attach the token as an id-aa-timeStampToken unsigned attribute on the primary signer.
  var out = await pki.cms.sign(CONTENT, { cert: base.signer.cert, key: base.signer.key }, {
    unsignedAttributes: [{ type: "timeStampToken", values: [token] }],
  });
  var res = await pki.cms.verify(out);
  var ua = (res.signers[0].unsignedAttrs || []).filter(function (x) { return x.type === O("timeStampToken"); })[0];
  check("#12 RFC 3161 timestamp token round-trips as an unsigned attribute", ua != null && Buffer.compare(Buffer.from(ua.values[0].bytes || ua.values[0]), token) === 0);
  check("#12 the surfaced token independently verifies", (await pki.cms.verify(token)).valid === true);
}

// ---- 13 UNSIGNED-ATTR PLACEMENT REJECT -------------------------------------
async function testPlacementReject() {
  var s = makeSigner("ec-p256");
  var forbidden = ["contentType", "messageDigest", "signingTime"];
  for (var i = 0; i < forbidden.length; i++) {
    var t = forbidden[i];
    check("#13 " + t + " forbidden as an unsigned attribute", (await codeOf(pki.cms.sign(CONTENT, { cert: s.cert, key: s.key }, {
      unsignedAttributes: [{ type: t, values: [b.octetString(Buffer.from("x"))] }],
    }))) === "cms/bad-input");
  }
  // A duplicate unsigned-attribute type is rejected.
  check("#13 duplicate unsigned-attribute type rejected", (await codeOf(pki.cms.sign(CONTENT, { cert: s.cert, key: s.key }, {
    unsignedAttributes: [{ type: "timeStampToken", values: [b.octetString(Buffer.from("a"))] }, { type: "timeStampToken", values: [b.octetString(Buffer.from("b"))] }],
  }))) === "cms/bad-input");
}

// ---- 14 DIGEST-ALGORITHM INDEPENDENCE --------------------------------------
async function testDigestIndependence() {
  var base = await signBase("ec-p256");   // primary digest defaults to sha256
  var cs = makeSigner("ec-p384");
  var out = await pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key, digestAlgorithm: "sha512" }, {});
  var res = await pki.cms.verify(out);
  check("#14 countersignature under a different digest (sha512) verifies", res.signers[0].countersignatures[0].ok === true);
  check("#14 countersignature digestAlgorithm surfaced", res.signers[0].countersignatures[0].digestAlgorithm === "sha512");
  // The countersignature's digestAlgorithm is NOT added to SignedData.digestAlgorithms.
  var parsed = parse(out);
  check("#14 SignedData.digestAlgorithms unchanged (countersig digest not added)",
    parsed.digestAlgorithms.filter(function (d) { return d.name === "sha512"; }).length === 0);
}

// ---- 15 INPUT POLYMORPHISM: DER Buffer / Uint8Array / PEM (byte-preserving) --
async function testInputPolymorphism() {
  var base = await signBase("ec-p256");
  var cs = makeSigner("ec-p256");
  // a Uint8Array view of the DER (countersign preserves the wire bytes, so it takes DER/PEM).
  var out1 = await pki.cms.countersign(new Uint8Array(base.cms), { cert: cs.cert, key: cs.key }, {});
  check("#15 countersign accepts a Uint8Array DER", (await pki.cms.verify(out1)).signers[0].countersignatures[0].ok === true);
  // PEM input + PEM output
  var pem = await pki.cms.sign(CONTENT, { cert: base.signer.cert, key: base.signer.key }, { pem: true });
  var out2 = await pki.cms.countersign(pem, { cert: cs.cert, key: cs.key }, { pem: true });
  check("#15 countersign accepts a PEM string and returns PEM", typeof out2 === "string" && out2.indexOf("-----BEGIN CMS-----") === 0);
  check("#15 the PEM countersigned output round-trips through verify", (await pki.cms.verify(out2)).signers[0].countersignatures[0].ok === true);
}

// ---- config-time fail-closed surface ---------------------------------------
async function testConfigTime() {
  var base = await signBase("ec-p256");
  var cs = makeSigner("ec-p256");
  await rejects("#cfg options not an object", function () { return pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key }, 7); }, "cms/bad-input");
  await rejects("#cfg empty signers", function () { return pki.cms.countersign(base.cms, [], {}); }, "cms/bad-input");
  await rejects("#cfg signerIndex out of range", function () { return pki.cms.countersign(base.cms, { cert: cs.cert, key: cs.key }, { signerIndex: 9 }); }, "cms/bad-input");
  await rejects("#cfg signer without a cert", function () { return pki.cms.countersign(base.cms, { key: cs.key }, {}); }, "cms/bad-input");
}

// ---- signerIndex modes + edge branches -------------------------------------
async function testSignerIndexAndEdges() {
  var s0 = makeSigner("ec-p256"), s1 = makeSigner("rsa", { serial: 0x201, cn: "Signer One" });
  var cms2 = await pki.cms.sign(CONTENT, [{ cert: s0.cert, key: s0.key }, { cert: s1.cert, key: s1.key }], {});
  var csk = makeSigner("ec-p256", { serial: 0x301, cn: "Countersigner" });
  var signer = { cert: csk.cert, key: csk.key };
  var base = await pki.cms.sign(CONTENT, { cert: s0.cert, key: s0.key }, {});

  var rAll = await pki.cms.verify(await pki.cms.countersign(cms2, signer, { signerIndex: "all" }));
  check("signerIndex 'all' countersigns every signer", rAll.signers[0].countersignatures[0].ok === true && rAll.signers[1].countersignatures[0].ok === true);
  var rArr = await pki.cms.verify(await pki.cms.countersign(cms2, signer, { signerIndex: [0, 1] }));
  check("signerIndex array countersigns the listed signers", rArr.signers[0].countersignatures.length === 1 && rArr.signers[1].countersignatures.length === 1);
  await rejects("signerIndex []", function () { return pki.cms.countersign(cms2, signer, { signerIndex: [] }); }, "cms/bad-input");
  await rejects("a null countersigner", function () { return pki.cms.countersign(base, null, {}); }, "cms/bad-input");

  // a pre-existing non-countersignature unsigned attribute is preserved when the signer is countersigned.
  var withTs = await pki.cms.sign(CONTENT, { cert: s0.cert, key: s0.key }, { unsignedAttributes: [{ type: "timeStampToken", values: [b.sequence([b.oid(O("data")), b.octetString(Buffer.from("t"))])] }] });
  var rTs = await pki.cms.verify(await pki.cms.countersign(withTs, signer, {}));
  check("countersign preserves a pre-existing non-countersignature unsigned attribute",
    rTs.signers[0].unsignedAttrs.some(function (a) { return a.type === O("timeStampToken"); }) && rTs.signers[0].countersignatures[0].ok === true);

  // countersignatureOf on a signer with no countersignature (none at all, and one that has other
  // unsigned attrs but no countersignature), and out of range, are rejected.
  await rejects("countersignatureOf a signer with no countersignature", function () { return pki.cms.countersign(base, signer, { countersignatureOf: 0 }); }, "cms/bad-input");
  await rejects("countersignatureOf a signer with unsigned attrs but no countersignature", function () { return pki.cms.countersign(withTs, signer, { countersignatureOf: 0 }); }, "cms/bad-input");
  var one = await pki.cms.countersign(base, signer, {});
  await rejects("countersignatureOf out of range", function () { return pki.cms.countersign(one, signer, { countersignatureOf: 5 }); }, "cms/bad-input");
  // nested-countersign a signer that ALSO carries a sibling non-countersignature unsigned attribute
  // (the splice skips the sibling attribute and merges into the countersignature).
  var tsThenCs = await pki.cms.countersign(withTs, signer, {});
  var rNested = await pki.cms.verify(await pki.cms.countersign(tsThenCs, signer, { countersignatureOf: 0 }));
  check("nested countersign preserves a sibling non-countersignature unsigned attribute",
    rNested.signers[0].unsignedAttrs.some(function (a) { return a.type === O("timeStampToken"); }) && rNested.signers[0].countersignatures[0].countersignatures[0].ok === true);

  // nested-countersign ONE of MULTIPLE countersignatures: the splice preserves the sibling countersignature.
  var twoCs = await pki.cms.countersign(await pki.cms.countersign(base, signer, {}), { cert: s1.cert, key: s1.key }, {});
  var rTwo = await pki.cms.verify(await pki.cms.countersign(twoCs, signer, { countersignatureOf: 0 }));
  check("nested-countersign one of two countersignatures preserves the sibling",
    rTwo.signers[0].countersignatures.length === 2 && rTwo.signers[0].countersignatures.filter(function (c) { return c.countersignatures.length > 0; }).length === 1);

  // a malformed input throws the parser's own typed cms/* error (like verify); a structurally-valid
  // non-SignedData CMS (an EnvelopedData) has no signerInfos array and is a cms/bad-input.
  for (var mi = 0; mi < 2; mi++) {
    var bad = [[0x30, 0x03, 0x02, 0x01, 0x01], [0x30, 0x05, 0x02]][mi];
    var e = null;
    try { await pki.cms.countersign(Buffer.from(bad), signer, {}); } catch (err) { e = err; }
    check("countersign a malformed input -> typed cms/* error", e && typeof e.code === "string" && e.code.indexOf("cms/") === 0);
  }
  var env = await pki.cms.encrypt(CONTENT, [{ cert: signing.makeRecipient("rsa").cert }], {});
  await rejects("countersign a non-SignedData CMS (EnvelopedData)", function () { return pki.cms.countersign(env, signer, {}); }, "cms/bad-input");
  await rejects("countersign with an invalid signingTime", function () { return pki.cms.countersign(base, signer, { signingTime: new Date("invalid") }); }, "cms/bad-input");
  check("countersign with a signingTime verifies", (await pki.cms.verify(await pki.cms.countersign(base, signer, { signingTime: new Date("2027-01-01T00:00:00Z") }))).signers[0].countersignatures[0].ok === true);
}

async function main() {
  await testSignerIndexAndEdges();
  await testPreimagePositiveAndMatrix();
  await testPreimageNegative();
  await testForbiddenContentType();
  await testUnsignedAttrNotAuthenticated();
  await testRecursive();
  await testValidRegardless();
  await testNoSignedAttrs();
  await testMultiSignerTarget();
  await testMultipleCountersignatures();
  await testBytePreservation();
  await testTimestampToken();
  await testPlacementReject();
  await testDigestIndependence();
  await testInputPolymorphism();
  await testConfigTime();
  console.log("CHECKS " + helpers.getChecks());
}

main().then(function () { process.exit(0); }, function (e) { console.error(e && e.stack || e); process.exit(1); });
