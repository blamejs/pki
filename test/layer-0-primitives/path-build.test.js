// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.path.build: certification path BUILDING (RFC 4158 / RFC 5280 sec. 6).
 *
 * build discovers the ordered leaf->anchor path validate consumes, from an untrusted pool of
 * candidate CAs and a trust store, then hands it to the SHIPPED pki.path.validate for the
 * authoritative verdict. These vectors drive the SHIPPED consumer path pki.path.build(...) and
 * assert through pki.path.validate and/or err.code:
 *  - a pool builds + validates (the round-trip GREEN oracle);
 *  - a decoy same-name issuer is skipped by backtracking through validate (name chaining alone
 *    is insufficient -- signature drives selection);
 *  - a cross-cert cycle + a combinatorial blow-up TERMINATE within the DoS bound (never hang);
 *  - no-chain-to-any-anchor fails closed (path/no-path); bad opts throw path/bad-input;
 *  - self-issued key rollover does not consume a path-length unit;
 *  - AKI/SKI is a SORT hint, never a filter (a mismatched/absent KID still validates);
 *  - the pure-builder escape hatch (opts.validate:false) yields an order validate accepts.
 *
 * Certificates are REAL-signed (the issuer key signs the exact tbs), so chain verification through
 * validate genuinely runs. Each entity gets its OWN keypair (freshKeys), so a decoy sharing a
 * subject DN has a DISTINCT key that did NOT sign the child.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;
var subtle = require("../../lib/webcrypto").webcrypto.subtle;

async function codeOf(promise) {
  try { await promise; return "NO-THROW"; }
  catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); }
}

// ---- signature plumbing: Ed25519 workhorse + a P-256 arm; each entity a FRESH keypair ----
var ALG = {
  ed25519: { gen: { name: "Ed25519" }, sign: { name: "Ed25519" }, sigOid: "1.3.101.112", params: "omit" },
  p256: { gen: { name: "ECDSA", namedCurve: "P-256" }, sign: { name: "ECDSA", hash: "SHA-256" }, sigOid: "1.2.840.10045.4.3.2", params: "omit", p1363: 32 },
};
async function freshKeys(algName) {
  var a = ALG[algName || "ed25519"];
  var kp = await subtle.generateKey(a.gen, true, ["sign", "verify"]);
  var spki = Buffer.from(await subtle.exportKey("spki", kp.publicKey));
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, spki: spki, alg: a };
}
function algIdDer(a) {
  if (a.params === "null") return b.sequence([b.oid(a.sigOid), b.nullValue()]);
  return b.sequence([b.oid(a.sigOid)]);
}
function p1363ToDer(sig, width) {
  var r = BigInt("0x" + Buffer.from(sig.slice(0, width)).toString("hex"));
  var s = BigInt("0x" + Buffer.from(sig.slice(width)).toString("hex"));
  return b.sequence([b.integer(r), b.integer(s)]);
}

// ---- DER fixture builders ----
function atv(typeOid, value) { return b.sequence([b.oid(typeOid), b.utf8(value)]); }
function nameDer(cn) { return b.sequence([b.set([atv("2.5.4.3", cn)])]); }
function validityDer(nb, na) { return b.sequence([b.utcTime(nb), b.utcTime(na)]); }
function ext(oidStr, critical, valueDer) {
  var kids = [b.oid(oidStr)];
  if (critical) kids.push(b.boolean(true));
  kids.push(b.octetString(valueDer));
  return b.sequence(kids);
}
function bcExt(cA) { return ext("2.5.29.19", true, b.sequence(cA ? [b.boolean(true)] : [])); }
function kuExt(bits) {
  var maxBit = Math.max.apply(null, bits), n = (maxBit >> 3) + 1, buf = Buffer.alloc(n);
  bits.forEach(function (p) { buf[p >> 3] |= (0x80 >> (p & 7)); });
  return ext("2.5.29.15", true, b.bitString(buf, 7 - (maxBit & 7)));
}
function skiExt(keyId) { return ext("2.5.29.14", false, b.octetString(keyId)); }
function akiExt(keyId) { return ext("2.5.29.35", false, b.sequence([b.contextPrimitive(0, keyId)])); }
function sanExt(names) { return ext("2.5.29.17", false, b.sequence(names.map(function (nm) { return b.contextPrimitive(2, Buffer.from(nm, "ascii")); }))); }
var KU_KEY_CERT_SIGN = 5;
var T = new Date("2027-06-01T00:00:00Z");
var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2030-01-01T00:00:00Z");

var SERIAL = 0n;
// A REAL signed certificate. o.signer = the ISSUER keypair; o.subjectKp = the SUBJECT keypair.
async function mkCert(o) {
  var signer = o.signer, a = signer.alg;
  var tbsChildren = [
    b.explicit(0, b.integer(2n)),
    b.integer(o.serial !== undefined ? o.serial : (SERIAL += 1n)),
    algIdDer(a),
    nameDer(o.issuerName),
    validityDer(o.notBefore || NB, o.notAfter || NA),
    nameDer(o.subjectName),
    b.raw(o.subjectKp.spki),
  ];
  if (o.extensions && o.extensions.length) tbsChildren.push(b.explicit(3, b.sequence(o.extensions)));
  var tbs = b.sequence(tbsChildren);
  var sig = Buffer.from(await subtle.sign(a.sign, signer.privateKey, tbs));
  if (a.p1363) sig = p1363ToDer(sig, a.p1363);
  return b.sequence([tbs, algIdDer(a), b.bitString(sig, 0)]);
}
function caExts(extra) { return [bcExt(true), kuExt([KU_KEY_CERT_SIGN])].concat(extra || []); }

async function run() {
  // ---- V-BUILD-1: a three-cert pool builds + validates ----
  var anchorKp = await freshKeys(), interAKp = await freshKeys(), interBKp = await freshKeys(), leafKp = await freshKeys();
  var anchorCert = await mkCert({ signer: anchorKp, subjectKp: anchorKp, issuerName: "Anchor", subjectName: "Anchor", extensions: caExts() });
  var interA = await mkCert({ signer: anchorKp, subjectKp: interAKp, issuerName: "Anchor", subjectName: "Inter", extensions: caExts() });
  var interBDecoySubj = await mkCert({ signer: anchorKp, subjectKp: interBKp, issuerName: "Anchor", subjectName: "Unrelated", extensions: caExts() });
  var leaf = await mkCert({ signer: interAKp, subjectKp: leafKp, issuerName: "Inter", subjectName: "Leaf" });

  var r1 = await pki.path.build(leaf, { candidates: [interBDecoySubj, interA], trustAnchors: [anchorCert], time: T });
  check("V-BUILD-1 build returns valid:true for a buildable pool", r1.valid === true);
  check("V-BUILD-1 path is [interA, leaf] (anchor-proximal first, leaf last, anchor excluded)",
    r1.path.length === 2 && r1.path[1].subject.rdns && Buffer.from(r1.path[0].subjectPublicKeyInfo.bytes).equals(interAKp.spki));
  // GREEN oracle: the built path validates through the SHIPPED validate.
  var green = await pki.path.validate(r1.path, { time: T, trustAnchor: r1.trustAnchor });
  check("V-BUILD-1 the built path validates through pki.path.validate (round-trip GREEN oracle)", green.valid === true);

  // ---- V-BUILD-2: decoy same-name issuer -> backtrack past it via validate ----
  // interReal + interDecoy share subject DN "Inter" but have DIFFERENT keys; only interReal signed the leaf.
  var realKp = await freshKeys(), decoyKp = await freshKeys(), leaf2Kp = await freshKeys();
  var interReal = await mkCert({ signer: anchorKp, subjectKp: realKp, issuerName: "Anchor", subjectName: "Inter", extensions: caExts() });
  var interDecoy = await mkCert({ signer: anchorKp, subjectKp: decoyKp, issuerName: "Anchor", subjectName: "Inter", extensions: caExts() });
  var leaf2 = await mkCert({ signer: realKp, subjectKp: leaf2Kp, issuerName: "Inter", subjectName: "Leaf2" });
  var r2 = await pki.path.build(leaf2, { candidates: [interDecoy, interReal], trustAnchors: [anchorCert], time: T });
  check("V-BUILD-2 decoy same-name issuer: build backtracks and validates", r2.valid === true);
  check("V-BUILD-2 the selected issuer is the REAL signer (not the decoy)",
    Buffer.from(r2.path[0].subjectPublicKeyInfo.bytes).equals(realKp.spki));

  // ---- V-BUILD-3: cross-cert cycle terminates within the bound, no anchor reachable ----
  var cycAKp = await freshKeys(), cycBKp = await freshKeys(), leaf3Kp = await freshKeys();
  var cycA = await mkCert({ signer: cycBKp, subjectKp: cycAKp, issuerName: "B", subjectName: "A", extensions: caExts() });
  var cycB = await mkCert({ signer: cycAKp, subjectKp: cycBKp, issuerName: "A", subjectName: "B", extensions: caExts() });
  var leaf3 = await mkCert({ signer: cycAKp, subjectKp: leaf3Kp, issuerName: "A", subjectName: "Leaf3" });
  var t3 = Date.now();
  var code3 = await codeOf(pki.path.build(leaf3, { candidates: [cycA, cycB], trustAnchors: [anchorCert], time: T }));
  check("V-BUILD-3 a cross-cert cycle terminates with a typed path/* verdict (no hang)",
    code3 === "path/no-path" || code3 === "path/build-limit");
  check("V-BUILD-3 the cycle search completed bounded (well under a wall-clock ceiling)", (Date.now() - t3) < 5000);

  // ---- V-BUILD-4: no chain to any anchor -> path/no-path ----
  var otherAnchorKp = await freshKeys();
  var otherAnchorCert = await mkCert({ signer: otherAnchorKp, subjectKp: otherAnchorKp, issuerName: "OtherAnchor", subjectName: "OtherAnchor", extensions: caExts() });
  var code4 = await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [otherAnchorCert], time: T }));
  check("V-BUILD-4 a pool that never reaches an anchor throws path/no-path", code4 === "path/no-path");

  // ---- V-BUILD-5: self-issued key rollover does not consume path length ----
  var rollOldKp = await freshKeys(), rollNewKp = await freshKeys(), leaf5Kp = await freshKeys();
  var interOld = await mkCert({ signer: anchorKp, subjectKp: rollOldKp, issuerName: "Anchor", subjectName: "Roll", extensions: caExts() });
  // interNew: self-issued (subject == issuer == "Roll"), signed by the OLD key, carrying the NEW key.
  var interNew = await mkCert({ signer: rollOldKp, subjectKp: rollNewKp, issuerName: "Roll", subjectName: "Roll", extensions: caExts() });
  var leaf5 = await mkCert({ signer: rollNewKp, subjectKp: leaf5Kp, issuerName: "Roll", subjectName: "Leaf5" });
  var r5 = await pki.path.build(leaf5, { candidates: [interOld, interNew], trustAnchors: [anchorCert], time: T });
  check("V-BUILD-5 self-issued rollover chain builds + validates", r5.valid === true);

  // ---- V-BUILD-6: backtrack on a VALIDATION failure (a higher-priority candidate that validate rejects) ----
  // interKidBad carries an SKI matching leaf6's AKI, so it is prioritized FIRST -- but its key did NOT
  // sign leaf6, so validate rejects it. interGood6 (no KID hint, lower priority) DID sign leaf6. build
  // must try the KID-matched candidate first, see validate fail, and BACKTRACK to the real signer.
  var badKp = await freshKeys(), goodKp = await freshKeys(), leaf6Kp = await freshKeys();
  var kidX = Buffer.alloc(20, 0x66);
  var interKidBad = await mkCert({ signer: anchorKp, subjectKp: badKp, issuerName: "Anchor", subjectName: "Inter6", extensions: caExts([skiExt(kidX)]) });
  var interGood6 = await mkCert({ signer: anchorKp, subjectKp: goodKp, issuerName: "Anchor", subjectName: "Inter6", extensions: caExts() });
  var leaf6 = await mkCert({ signer: goodKp, subjectKp: leaf6Kp, issuerName: "Inter6", subjectName: "Leaf6", extensions: [akiExt(kidX)] });
  var r6 = await pki.path.build(leaf6, { candidates: [interGood6, interKidBad], trustAnchors: [anchorCert], time: T });
  check("V-BUILD-6 backtracks off a higher-priority (KID-matched) candidate that validate rejects, to the real signer",
    r6.valid === true && Buffer.from(r6.path[0].subjectPublicKeyInfo.bytes).equals(goodKp.spki));

  // ---- V-BUILD-7: AKI/SKI prioritization + the fail-closed inversion (no SKI still validates) ----
  var kidReal = Buffer.alloc(20, 0xA1), kidDecoy = Buffer.alloc(20, 0xB2);
  var interKidReal = await mkCert({ signer: anchorKp, subjectKp: realKp, issuerName: "Anchor", subjectName: "Inter7", extensions: caExts([skiExt(kidReal)]) });
  var interKidDecoy = await mkCert({ signer: anchorKp, subjectKp: decoyKp, issuerName: "Anchor", subjectName: "Inter7", extensions: caExts([skiExt(kidDecoy)]) });
  var leaf7Kp = await freshKeys();
  var leaf7 = await mkCert({ signer: realKp, subjectKp: leaf7Kp, issuerName: "Inter7", subjectName: "Leaf7", extensions: [akiExt(kidReal)] });
  var r7 = await pki.path.build(leaf7, { candidates: [interKidDecoy, interKidReal], trustAnchors: [anchorCert], time: T });
  check("V-BUILD-7 an SKI/AKI match selects + validates the right issuer", r7.valid === true &&
    Buffer.from(r7.path[0].subjectPublicKeyInfo.bytes).equals(realKp.spki));
  // Fail-closed inversion: the real issuer has NO SKI (or a mismatched one) -- build must STILL validate.
  var leaf7b = await mkCert({ signer: realKp, subjectKp: leaf7Kp, issuerName: "Inter", subjectName: "Leaf7b", extensions: [akiExt(Buffer.alloc(20, 0xCC))] });
  var r7b = await pki.path.build(leaf7b, { candidates: [interDecoy, interReal], trustAnchors: [anchorCert], time: T });
  check("V-BUILD-7 a mismatched/absent KID still validates (KID is a hint, never a filter)", r7b.valid === true);

  // ---- V-BUILD-8: the DoS bound is a deterministic throw ----
  // Many same-name decoys with a low maxCandidatesConsidered -> path/build-limit.
  var decoys = [];
  for (var i = 0; i < 8; i++) { var dk = await freshKeys(); decoys.push(await mkCert({ signer: anchorKp, subjectKp: dk, issuerName: "Anchor", subjectName: "Inter", extensions: caExts() })); }
  var code8 = await codeOf(pki.path.build(leaf2, { candidates: decoys, trustAnchors: [anchorCert], time: T, maxCandidatesConsidered: 3 }));
  check("V-BUILD-8 a low candidate ceiling throws path/build-limit (the DoS terminator)", code8 === "path/build-limit");
  // A depth cap below the required chain length -> path/no-path (depth exhausted before an anchor).
  var midKp = await freshKeys(), leaf8Kp = await freshKeys();
  var interMid = await mkCert({ signer: interAKp, subjectKp: midKp, issuerName: "Inter", subjectName: "Mid", extensions: caExts() });
  var leaf8 = await mkCert({ signer: midKp, subjectKp: leaf8Kp, issuerName: "Mid", subjectName: "Leaf8" });
  var code8b = await codeOf(pki.path.build(leaf8, { candidates: [interA, interMid], trustAnchors: [anchorCert], time: T, maxDepth: 1 }));
  check("V-BUILD-8 a maxDepth below the required chain length throws path/no-path", code8b === "path/no-path");

  // ---- V-BUILD-9: entry-point bad input ----
  check("V-BUILD-9 non-array candidates -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: "nope", trustAnchors: [anchorCert], time: T })) === "path/bad-input");
  check("V-BUILD-9 a malformed trustAnchors entry -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [{ not: "an anchor" }], time: T })) === "path/bad-input");
  check("V-BUILD-9 missing/invalid time -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [anchorCert], time: new Date("nope") })) === "path/bad-input");
  check("V-BUILD-9 a fractional maxDepth -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [anchorCert], time: T, maxDepth: 1.5 })) === "path/bad-input");
  check("V-BUILD-9 an empty trustAnchors array -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [], time: T })) === "path/bad-input");

  // ---- V-BUILD-10: build-only mode round-trip (the explicit GREEN oracle) ----
  var r10 = await pki.path.build(leaf, { candidates: [interA], trustAnchors: [anchorCert], time: T, validate: false });
  check("V-BUILD-10 build-only returns a path + trustAnchor without a validate result", r10.path.length === 2 && !!r10.trustAnchor && r10.result === undefined);
  var green10 = await pki.path.validate(r10.path, { time: T, trustAnchor: r10.trustAnchor });
  check("V-BUILD-10 the build-only order validates through pki.path.validate", green10.valid === true);

  // ---- V-BUILD-11: multiple anchors selects the correct terminal ----
  var r11 = await pki.path.build(leaf, { candidates: [interA], trustAnchors: [otherAnchorCert, anchorCert], time: T });
  check("V-BUILD-11 with multiple anchors, the correct terminal anchor is selected", r11.valid === true &&
    Buffer.from(r11.trustAnchor.publicKey).equals(anchorKp.spki));

  // ---- V-BUILD-12: degenerate leaf directly under the anchor (empty pool) ----
  var directKp = await freshKeys();
  var direct = await mkCert({ signer: anchorKp, subjectKp: directKp, issuerName: "Anchor", subjectName: "Direct" });
  var r12 = await pki.path.build(direct, { candidates: [], trustAnchors: [anchorCert], time: T });
  check("V-BUILD-12 a leaf directly under the anchor builds path == [leaf]", r12.valid === true && r12.path.length === 1);

  // ---- V-BUILD-13: a raw self-signed root as a store entry (already the default above) + tuple form ----
  var anchorParsed = pki.schema.x509.parse(anchorCert);
  var anchorTuple = { name: anchorParsed.subject, publicKey: anchorParsed.subjectPublicKeyInfo.bytes, algorithm: anchorParsed.subjectPublicKeyInfo.algorithm.oid, parameters: anchorParsed.subjectPublicKeyInfo.algorithm.parameters };
  var r13 = await pki.path.build(leaf, { candidates: [interA], trustAnchors: [anchorTuple], time: T });
  check("V-BUILD-13 a pre-extracted anchor tuple also builds + validates", r13.valid === true);

  // ---- V-BUILD-14: a self-signed pool cert is NOT trusted as an anchor ----
  // anchorCert sits in the POOL, not the store; the store has an unrelated anchor -> no path.
  var code14 = await codeOf(pki.path.build(leaf, { candidates: [interA, anchorCert], trustAnchors: [otherAnchorCert], time: T }));
  check("V-BUILD-14 a self-signed pool cert (not in trustAnchors) never terminates a path", code14 === "path/no-path");

  // ---- V-BUILD-15: cross-cert same-DN disambiguation (distinct keys, not pruned as a loop) ----
  // Two DISTINCT certs share subject DN "Inter" (interReal + interDecoy from V-BUILD-2); the (name,SAN,key)
  // visited-set must treat them as distinct so the real signer is reachable even with the decoy present.
  var r15 = await pki.path.build(leaf2, { candidates: [interReal, interDecoy, interDecoy], trustAnchors: [anchorCert], time: T });
  check("V-BUILD-15 cross-cert same-DN candidates are distinct (real signer selected, none wrongly pruned)",
    r15.valid === true && Buffer.from(r15.path[0].subjectPublicKeyInfo.bytes).equals(realKp.spki));

  // ---- input coercion + entry-point branch coverage ----
  var rParsed = await pki.path.build(pki.schema.x509.parse(leaf),
    { candidates: [pki.schema.x509.parse(interA)], trustAnchors: [pki.schema.x509.parse(anchorCert)], time: T });
  check("build accepts already-parsed leaf/candidate/anchor inputs", rParsed.valid === true);
  var rAlias = await pki.path.build(leaf, { intermediates: [interA], trustAnchors: [anchorCert], time: T });
  check("opts.intermediates is an alias for opts.candidates", rAlias.valid === true);
  var rNoPool = await pki.path.build(direct, { trustAnchors: [anchorCert], time: T });
  check("opts.candidates may be omitted (a leaf directly under the anchor)", rNoPool.valid === true);
  check("build with no opts -> path/bad-input", await codeOf(pki.path.build(leaf)) === "path/bad-input");
  check("non-object opts -> path/bad-input", await codeOf(pki.path.build(leaf, "nope")) === "path/bad-input");
  check("an unparseable leaf -> path/bad-input",
    await codeOf(pki.path.build(Buffer.from([1, 2, 3]), { candidates: [], trustAnchors: [anchorCert], time: T })) === "path/bad-input");
  check("an unparseable candidate -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [Buffer.from([1, 2, 3])], trustAnchors: [anchorCert], time: T })) === "path/bad-input");
  check("a tuple anchor whose name lacks .rdns -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [{ name: {}, publicKey: anchorKp.spki, algorithm: "1.3.101.112" }], time: T })) === "path/bad-input");
  check("an oversized candidate pool -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: new Array(pki.C.LIMITS.PATH_BUILD_MAX_CANDIDATES + 1).fill(interA), trustAnchors: [anchorCert], time: T })) === "path/bad-input");

  // The soft verdict: chains assemble to an anchor but none validate -> { valid:false } (not a throw),
  // carrying the failing validate result -- parity with validate. The sole issuer is EXPIRED at T.
  var soleExpKp = await freshKeys(), leafSoleKp = await freshKeys();
  var interSoleExpired = await mkCert({ signer: anchorKp, subjectKp: soleExpKp, issuerName: "Anchor", subjectName: "Sole", notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z"), extensions: caExts() });
  var leafSole = await mkCert({ signer: soleExpKp, subjectKp: leafSoleKp, issuerName: "Sole", subjectName: "LeafSole" });
  var rSoft = await pki.path.build(leafSole, { candidates: [interSoleExpired], trustAnchors: [anchorCert], time: T });
  check("chains assemble but none validate -> { valid:false } with the failing result (not a throw)",
    rSoft.valid === false && !!rSoft.result && rSoft.result.valid === false);

  // Soft-degradation coverage: a SAN-bearing chain (identityKey's SAN arm), a decoy with a MALFORMED
  // keyUsage (softDecode degrades to no sort hint), and a decoy with a control-byte subject DN
  // (nameMatchSoft fails it closed to "not an issuer") -- the real path still builds through all three.
  var sanKp = await freshKeys(), leafSanKp = await freshKeys(), badKuKp = await freshKeys(), ctrlKp = await freshKeys();
  var interSan = await mkCert({ signer: anchorKp, subjectKp: sanKp, issuerName: "Anchor", subjectName: "InterSan", extensions: caExts([sanExt(["host.example"])]) });
  var interBadKu = await mkCert({ signer: anchorKp, subjectKp: badKuKp, issuerName: "Anchor", subjectName: "InterSan", extensions: [bcExt(true), ext("2.5.29.15", true, b.integer(5n))] });
  var interCtrl = await mkCert({ signer: anchorKp, subjectKp: ctrlKp, issuerName: "Anchor", subjectName: "Inter" + String.fromCharCode(1) + "San", extensions: caExts() });
  var leafSan = await mkCert({ signer: sanKp, subjectKp: leafSanKp, issuerName: "InterSan", subjectName: "LeafSan", extensions: [sanExt(["leaf.example"])] });
  var rDegrade = await pki.path.build(leafSan, { candidates: [interBadKu, interCtrl, interSan], trustAnchors: [anchorCert], time: T });
  check("a SAN-bearing cert + a malformed-keyUsage decoy + a control-byte-DN decoy: the real path still builds",
    rDegrade.valid === true && Buffer.from(rDegrade.path[0].subjectPublicKeyInfo.bytes).equals(sanKp.spki));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run().then(function () {}, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
