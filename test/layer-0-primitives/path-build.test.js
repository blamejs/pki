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
// authorityInfoAccess (RFC 5280 sec. 4.2.2.1): SEQUENCE OF AccessDescription { accessMethod, accessLocation }.
// Each entry is [methodOid, GeneralName]; a URI accessLocation is [6] IA5String. Non-critical (MUST).
function aiaExt(entries) {
  return ext("1.3.6.1.5.5.7.1.1", false, b.sequence(entries.map(function (e) {
    var gn = e.tag === 6 ? b.contextPrimitive(6, Buffer.from(e.value, "latin1"))
      : e.tag === 1 ? b.contextPrimitive(1, Buffer.from(e.value, "latin1"))
      : b.contextPrimitive(e.tag, Buffer.from(e.value, "latin1"));
    return b.sequence([b.oid(e.method || pki.oid.byName("caIssuers")), gn]);
  })));
}
function aiaCaIssuersUri(url) { return aiaExt([{ method: pki.oid.byName("caIssuers"), tag: 6, value: url }]); }
// A call-counting injectable transport. `handler(url) -> {status,headers,body}` or a thrown/rejected error.
// t.calls records every url requested (the SSRF/dedupe assertions read the count).
function mkTransport(handler) {
  var calls = [];
  var t = function (req) { calls.push(req.url); return Promise.resolve().then(function () { return handler(req.url, req); }); };
  t.calls = calls;
  return t;
}
function cert200(der, contentType) { return { status: 200, headers: { "content-type": contentType || "application/pkix-cert" }, body: der }; }
// A degenerate certs-only SignedData (RFC 5272 sec. 4.1): version 1, empty digestAlgorithms, id-data
// eContentInfo (no eContent), the [0] certificates field (DER-sorted, mirroring the SET-OF ordering), empty
// signerInfos -- the same shape the EST test builds, so pki.schema.cms.parseCertsOnly accepts it.
function certsOnlyCms(certDers) {
  var sd = [b.integer(1n), b.set([]), b.sequence([b.oid(pki.oid.byName("data"))])];
  if (certDers.length) sd.push(b.contextConstructed(0, Buffer.concat(certDers.slice().sort(Buffer.compare))));
  sd.push(b.set([]));
  return b.sequence([b.oid(pki.oid.byName("signedData")), b.explicit(0, b.sequence(sd))]);
}

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
  // A forwarded maxPathCerts bounds the chain length build hands to validate: the 2-intermediate
  // chain (path length 3) under maxPathCerts:2 must fail closed as path/no-path (build never
  // assembles an over-length path), NOT leak validate's path/bad-input.
  var code8c = await codeOf(pki.path.build(leaf8, { candidates: [interA, interMid], trustAnchors: [anchorCert], time: T, maxPathCerts: 2 }));
  check("V-BUILD-8 a chain longer than maxPathCerts fails as path/no-path (not validate's path/bad-input)", code8c === "path/no-path");

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
  // A claimed-parsed object (truthy tbsBytes) must carry the COMPLETE parsed-certificate shape
  // build produces and hands to validate; ANY missing/mistyped field fails closed as a typed
  // path/bad-input, never a raw TypeError in the search or inside validate. `full` is the minimal
  // valid shape; each badShapes entry breaks exactly one field so that field's check is exercised.
  var Z = Buffer.alloc(0);
  var full = {
    tbsBytes: Z, serialNumberHex: "01", signatureAlgorithm: { oid: "1.2" }, signatureValue: { bytes: Z },
    validity: { notBefore: NB, notAfter: NA }, issuer: { rdns: [] }, subject: { rdns: [], bytes: Z },
    subjectPublicKeyInfo: { bytes: Z, algorithm: { oid: "1.2" }, publicKey: { bytes: Z, unusedBits: 0 } }, extensions: [],
  };
  function bad(over) { return Object.assign({}, full, over); }
  var badShapes = [
    bad({ tbsBytes: "x" }),                                             // tbsBytes not a Buffer
    bad({ serialNumberHex: 5 }),                                        // serialNumberHex not a string
    bad({ signatureAlgorithm: null }),                                 // missing signatureAlgorithm
    bad({ signatureAlgorithm: {} }),                                   // signatureAlgorithm.oid not a string
    bad({ signatureValue: null }),                                     // missing signatureValue
    bad({ signatureValue: {} }),                                       // signatureValue.bytes not a Buffer
    bad({ validity: null }),                                           // missing validity
    bad({ validity: { notAfter: NA } }),                               // validity.notBefore not a Date
    bad({ validity: { notBefore: NB } }),                              // validity.notAfter not a Date
    bad({ issuer: null }),                                             // missing issuer
    bad({ issuer: {} }),                                               // issuer.rdns not an array
    bad({ subject: null }),                                            // missing subject
    bad({ subject: { bytes: Z } }),                                    // subject.rdns not an array
    bad({ subject: { rdns: [] } }),                                    // subject.bytes not a Buffer
    bad({ subjectPublicKeyInfo: null }),                               // missing subjectPublicKeyInfo
    bad({ subjectPublicKeyInfo: {} }),                                 // spki.bytes not a Buffer
    bad({ subjectPublicKeyInfo: { bytes: Z } }),                       // missing spki.algorithm
    bad({ subjectPublicKeyInfo: { bytes: Z, algorithm: {} } }),        // spki.algorithm.oid not a string
    bad({ subjectPublicKeyInfo: { bytes: Z, algorithm: { oid: "1.2" } } }),                          // missing spki.publicKey
    bad({ subjectPublicKeyInfo: { bytes: Z, algorithm: { oid: "1.2" }, publicKey: {} } }),           // spki.publicKey.bytes not a Buffer
    bad({ subjectPublicKeyInfo: { bytes: Z, algorithm: { oid: "1.2" }, publicKey: { bytes: Z } } }), // spki.publicKey.unusedBits not a number
    bad({ extensions: "x" }),                                          // extensions not an array
    bad({ extensions: [null] }),                                       // extension entry not an object
    bad({ extensions: [{ value: Z }] }),                               // extension entry missing .oid
    bad({ extensions: [{ oid: "1.2" }] }),                             // extension entry missing a Buffer .value
  ];
  for (var bi = 0; bi < badShapes.length; bi++) {
    check("a claimed-parsed leaf with a malformed field (#" + bi + ") -> path/bad-input",
      await codeOf(pki.path.build(badShapes[bi], { candidates: [], trustAnchors: [anchorCert], time: T })) === "path/bad-input");
  }
  check("a malformed claimed-parsed candidate -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [bad({ subject: null })], trustAnchors: [anchorCert], time: T })) === "path/bad-input");
  check("a malformed certificate-form anchor -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [bad({ subject: null })], time: T })) === "path/bad-input");

  // A ready anchor TUPLE is a caller option: a malformed tuple (bad name.rdns / publicKey / algorithm
  // types) fails closed at entry as path/bad-input, not a downstream no-path or soft valid:false.
  check("an anchor tuple with a non-array name.rdns -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [{ name: { rdns: "bad" }, publicKey: Z, algorithm: "1.2" }], time: T })) === "path/bad-input");
  check("an anchor tuple with a non-Buffer publicKey -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [{ name: { rdns: [] }, publicKey: "x", algorithm: "1.2" }], time: T })) === "path/bad-input");
  check("an anchor tuple with a non-string algorithm -> path/bad-input",
    await codeOf(pki.path.build(leaf, { candidates: [interA], trustAnchors: [{ name: { rdns: [] }, publicKey: Z, algorithm: 5 }], time: T })) === "path/bad-input");

  // maxPathCerts:1 permits exactly a leaf directly under an anchor (a zero-hop search): the bound
  // must not throw before the anchor is checked, whether maxDepth is omitted or explicitly 0.
  check("maxPathCerts:1 permits a leaf directly under the anchor (zero-hop)",
    (await pki.path.build(direct, { candidates: [], trustAnchors: [anchorCert], time: T, maxPathCerts: 1 })).valid === true);
  check("maxPathCerts:1 with an explicit maxDepth:0 also permits the zero-hop path",
    (await pki.path.build(direct, { candidates: [], trustAnchors: [anchorCert], time: T, maxPathCerts: 1, maxDepth: 0 })).valid === true);
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

  // ==== AIA caIssuers network fetching (RFC 5280 sec. 4.2.2.1, opt-in over an INJECTED offline transport) ====
  var aRootKp = await freshKeys(), aInterKp = await freshKeys(), aLeafKp = await freshKeys();
  var aRoot = await mkCert({ signer: aRootKp, subjectKp: aRootKp, issuerName: "AiaRoot", subjectName: "AiaRoot", extensions: caExts() });
  var aInter = await mkCert({ signer: aRootKp, subjectKp: aInterKp, issuerName: "AiaRoot", subjectName: "AiaInter", extensions: caExts() });
  var AIA_URL = "https://ca.example/inter.der";
  var aLeaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaCaIssuersUri(AIA_URL)] });
  var aBase = { candidates: [], trustAnchors: [aRoot], time: T, fetchAia: true };

  // B1 DISCOVERY: an EMPTY pool builds via the AIA-fetched intermediate; it is accepted THROUGH validate.
  var b1t = mkTransport(function () { return cert200(aInter); });
  var b1 = await pki.path.build(aLeaf, Object.assign({}, aBase, { transport: b1t }));
  check("AIA B1: an empty pool builds via an AIA-fetched intermediate (valid:true, path length 2)", b1.valid === true && b1.path.length === 2);
  check("AIA B1: the fetched intermediate is on the built path (accepted through validate, not a raw insert)", Buffer.from(b1.path[0].subjectPublicKeyInfo.bytes).equals(aInterKp.spki));
  check("AIA B1: aiaFetches counts the single GET and only the caIssuers URL was fetched", b1.aiaFetches === 1 && b1t.calls.length === 1 && b1t.calls[0] === AIA_URL);
  check("AIA B1: WITHOUT fetchAia the same empty-pool build fails path/no-path (the fetch is load-bearing)", (await codeOf(pki.path.build(aLeaf, { candidates: [], trustAnchors: [aRoot], time: T }))) === "path/no-path");
  // B2 CERTS-ONLY CMS response supplies the intermediate.
  var b2t = mkTransport(function () { return { status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: certsOnlyCms([aInter]) }; });
  check("AIA B2: a certs-only CMS response supplies the intermediate (valid:true)", (await pki.path.build(aLeaf, Object.assign({}, aBase, { transport: b2t }))).valid === true);
  // B3 CONTENT-TYPE IS A HINT (RFC 5280 sec. 4.2.2.1): a mislabeled body still parses by structure, both ways.
  var b3a = mkTransport(function () { return { status: 200, headers: { "content-type": "application/pkix-cert" }, body: certsOnlyCms([aInter]) }; });
  check("AIA B3: a certs-only body mislabeled application/pkix-cert still parses (structure-sniff)", (await pki.path.build(aLeaf, Object.assign({}, aBase, { transport: b3a }))).valid === true);
  var b3b = mkTransport(function () { return { status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: aInter }; });
  check("AIA B3: a single DER cert mislabeled application/pkcs7-mime still parses", (await pki.path.build(aLeaf, Object.assign({}, aBase, { transport: b3b }))).valid === true);

  // C1 SSRF SCHEME GATE: a non-https caIssuers URL is NEVER fetched (no socket); the verdict is the no-AIA case.
  var cHttpLeaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaExt([{ tag: 6, value: "http://internal.example/inter.der" }, { tag: 6, value: "ldap://ca.example/cn=x" }, { tag: 6, value: "file:///etc/passwd" }])] });
  var c1t = mkTransport(function () { return cert200(aInter); });
  check("AIA C1: http/ldap/file caIssuers URLs are never fetched -> path/no-path, transport uncalled (no socket)", (await codeOf(pki.path.build(cHttpLeaf, Object.assign({}, aBase, { transport: c1t })))) === "path/no-path" && c1t.calls.length === 0);
  // C2 an id-ad-ocsp accessMethod is never fetched (only caIssuers).
  var cOcspLeaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaExt([{ method: pki.oid.byName("ocsp"), tag: 6, value: "https://ocsp.example/x" }])] });
  var c2t = mkTransport(function () { return cert200(aInter); });
  check("AIA C2: an id-ad-ocsp accessMethod is never fetched (only id-ad-caIssuers)", (await codeOf(pki.path.build(cOcspLeaf, Object.assign({}, aBase, { transport: c2t })))) === "path/no-path" && c2t.calls.length === 0);
  // C3 an unparseable caIssuers URI (valid IA5String but not a WHATWG URL, e.g. no scheme) is skipped before any socket.
  var cBadUrlLeaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaExt([{ tag: 6, value: "notaurl-no-scheme" }])] });
  var c3t = mkTransport(function () { return cert200(aInter); });
  check("AIA C3: an unparseable caIssuers URI is skipped -> path/no-path, transport uncalled", (await codeOf(pki.path.build(cBadUrlLeaf, Object.assign({}, aBase, { transport: c3t })))) === "path/no-path" && c3t.calls.length === 0);
  // C4 SSRF PRIVATE-ADDRESS BLOCK: an https caIssuers URL to a loopback / link-local / RFC1918 IP LITERAL is
  // never fetched (an untrusted cert must not drive an authenticated GET to an internal service / cloud metadata).
  var privHosts = ["127.0.0.1", "169.254.169.254", "10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1", "198.18.0.1", "192.0.2.1", "203.0.113.1", "[::1]", "[::]", "[fc00::1]", "[fe80::1]", "[fec0::1]", "[ff02::1]", "[2001:db8::1]", "[::ffff:127.0.0.1]"];
  var cPrivLeaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaExt(privHosts.map(function (h) { return { tag: 6, value: "https://" + h + "/i" }; }))] });
  var c4t = mkTransport(function () { return cert200(aInter); });
  check("AIA C4: private/loopback/link-local/reserved IP-literal caIssuers URLs (v4 + v6) are never fetched (SSRF, transport uncalled)", (await codeOf(pki.path.build(cPrivLeaf, Object.assign({}, aBase, { transport: c4t, maxAiaPerCert: 20 })))) === "path/no-path" && c4t.calls.length === 0);
  // C5 PUBLIC IP-literal destinations (v4 AND v6) ARE fetchable (the block is private-only) -- the guard is a scalpel.
  var cPubLeaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaCaIssuersUri("https://8.8.8.8/i.der")] });
  var c5t = mkTransport(function () { return cert200(aInter); });
  check("AIA C5: a public IPv4-literal caIssuers URL IS fetched (block is private-only) -> valid", (await pki.path.build(cPubLeaf, Object.assign({}, aBase, { transport: c5t }))).valid === true && c5t.calls.length === 1);
  var cPub6Leaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaCaIssuersUri("https://[2606:4700::1]/i.der")] });
  var c6t = mkTransport(function () { return cert200(aInter); });
  check("AIA C6: a global-unicast IPv6-literal caIssuers URL IS fetched (block is non-global-only) -> valid", (await pki.path.build(cPub6Leaf, Object.assign({}, aBase, { transport: c6t }))).valid === true && c6t.calls.length === 1);

  // D1 BUDGET is a SILENT CAP, not a throw: a chain needing more fetches than maxAiaFetches stops fetching at
  // the budget (never a throw that denies a buildable path). Here no path exists within a 1-fetch budget, so the
  // verdict is path/no-path and the transport is called at most maxAiaFetches times (bounded).
  var dRootKp = await freshKeys(), dBKp = await freshKeys(), dAKp = await freshKeys(), dLeafKp = await freshKeys();
  var dRoot = await mkCert({ signer: dRootKp, subjectKp: dRootKp, issuerName: "DRoot", subjectName: "DRoot", extensions: caExts() });
  var dB = await mkCert({ signer: dRootKp, subjectKp: dBKp, issuerName: "DRoot", subjectName: "DInterB", extensions: caExts() });
  var dA = await mkCert({ signer: dBKp, subjectKp: dAKp, issuerName: "DInterB", subjectName: "DInterA", extensions: caExts([aiaCaIssuersUri("https://ca.example/B.der")]) });
  var dLeaf = await mkCert({ signer: dAKp, subjectKp: dLeafKp, issuerName: "DInterA", subjectName: "DLeaf", extensions: [aiaCaIssuersUri("https://ca.example/A.der")] });
  var dt = mkTransport(function (url) { if (url.indexOf("A.der") >= 0) return cert200(dA); if (url.indexOf("B.der") >= 0) return cert200(dB); throw new Error("unknown"); });
  check("AIA D1: the total fetch budget is a SILENT cap -> path/no-path (never aborts a build), transport <= budget", (await codeOf(pki.path.build(dLeaf, { candidates: [], trustAnchors: [dRoot], time: T, fetchAia: true, transport: dt, maxAiaFetches: 1 }))) === "path/no-path" && dt.calls.length <= 1);
  // D0 LOCAL-BEFORE-REMOTE IS GLOBAL, NOT PER-BRANCH: a leaf with a valid pool path whose issuer also has many
  // same-DN decoys (each anchor-adjacent but unable to sign, each advertising a dead AIA URL) must build via the
  // static pool with ZERO fetches. Every decoy dead-ends locally, but its AIA fallback is DEFERRED until the whole
  // local search is exhausted -- and the valid static issuer (aInter) is found during that local search, so the
  // decoys' fallbacks never run. A fetch ahead of a still-unexplored static sibling would break the guarantee.
  var d0Decoys = [];
  for (var d0i = 0; d0i < 15; d0i++) { var d0kp = await freshKeys(); d0Decoys.push(await mkCert({ signer: aRootKp, subjectKp: d0kp, issuerName: "AiaRoot", subjectName: "AiaInter", extensions: caExts([aiaCaIssuersUri("https://ca.example/decoy" + d0i)]) })); }
  var d0Pool = [aInter].concat(d0Decoys);
  var d0t = mkTransport(function () { return { status: 404, headers: {}, body: Buffer.alloc(0) }; });
  var d0Offline = await pki.path.build(aLeaf, { candidates: d0Pool, trustAnchors: [aRoot], time: T });
  var d0Fetch = await pki.path.build(aLeaf, { candidates: d0Pool, trustAnchors: [aRoot], time: T, fetchAia: true, transport: d0t });
  check("AIA D0: fetchAia does NOT deny a valid static path amid budget-burning decoys (valid:true both ways)", d0Offline.valid === true && d0Fetch.valid === true);
  check("AIA D0: a pool-completable build makes ZERO fetches -- a dead-ending decoy never fetches ahead of the valid static sibling (local-before-remote is global)", d0t.calls.length === 0);
  // D7 STALE-POOL-CERT FALLBACK (RFC 4158 sec. 7.2 local-before-remote is LAZY, not skip-if-any-local-match): the
  // pool holds a DECOY whose subject == the leaf's issuer DN but with a different key -- it name-chains to the
  // anchor yet cannot sign the leaf. The local decoy branch is explored FIRST and dead-ends in validation; only
  // then is the leaf's AIA fetched as a fallback, and the real intermediate completes the path. A same-DN pool
  // cert must never STARVE the fetch (the pre-fix `scored.length === 0` gate did exactly that).
  var d7DecoyKp = await freshKeys();
  var d7Decoy = await mkCert({ signer: aRootKp, subjectKp: d7DecoyKp, issuerName: "AiaRoot", subjectName: "AiaInter", extensions: caExts() });
  var d7t = mkTransport(function () { return cert200(aInter); });
  var d7 = await pki.path.build(aLeaf, { candidates: [d7Decoy], trustAnchors: [aRoot], time: T, fetchAia: true, transport: d7t });
  check("AIA D7: a stale same-DN pool cert that fails validation no longer starves AIA fallback (valid via the fetched issuer)", d7.valid === true && d7.aiaFetches === 1 && Buffer.from(d7.path[0].subjectPublicKeyInfo.bytes).equals(aInterKp.spki));
  check("AIA D7: the local decoy branch is explored BEFORE the network fetch (one GET, local-before-remote)", d7t.calls.length === 1);
  // D8 ZERO PER-CERT CAP: maxAiaPerCert:0 (explicitly accepted by the option guard) must DISABLE per-certificate
  // fetching -- not fetch the first eligible URI and only then notice the cap. transport uncalled -> path/no-path.
  var d8t = mkTransport(function () { return cert200(aInter); });
  check("AIA D8: maxAiaPerCert:0 collects no URL -> no fetch at all (transport uncalled)", (await codeOf(pki.path.build(aLeaf, Object.assign({}, aBase, { transport: d8t, maxAiaPerCert: 0 })))) === "path/no-path" && d8t.calls.length === 0);
  // D9 CA-KEY-ROLLOVER FALLBACK (the fallback is gated on `success` being unset, NOT on the issuer name failing to
  // match an anchor): the leaf's issuer DN matches the anchor, but the anchor's NEW key does not validate the leaf
  // (the leaf was signed by the OLD key). The missing self-issued rollover intermediate -- same DN, the OLD key,
  // itself signed by the NEW (anchor) key -- is reachable only via AIA. Direct validation fails; the fallback then
  // fetches the rollover cert and the chain validates. A name match to an anchor must NOT suppress the fallback.
  var d9NewKp = await freshKeys(), d9OldKp = await freshKeys(), d9LeafKp = await freshKeys();
  var d9Anchor = await mkCert({ signer: d9NewKp, subjectKp: d9NewKp, issuerName: "RollRoot", subjectName: "RollRoot", extensions: caExts() });
  var d9Inter = await mkCert({ signer: d9NewKp, subjectKp: d9OldKp, issuerName: "RollRoot", subjectName: "RollRoot", extensions: caExts() });   // self-issued, OLD key, signed by NEW
  var d9Leaf = await mkCert({ signer: d9OldKp, subjectKp: d9LeafKp, issuerName: "RollRoot", subjectName: "RollLeaf", extensions: [aiaCaIssuersUri("https://ca.example/rollover.der")] });
  var d9t = mkTransport(function () { return cert200(d9Inter); });
  var d9 = await pki.path.build(d9Leaf, { candidates: [], trustAnchors: [d9Anchor], time: T, fetchAia: true, transport: d9t });
  check("AIA D9: a name match to an anchor whose key fails direct validation still falls back to AIA (rollover chain validates)", d9.valid === true && d9.aiaFetches === 1 && d9.path.length === 2);
  check("AIA D9: the fetched rollover intermediate carries the old key and is on the built path", Buffer.from(d9.path[0].subjectPublicKeyInfo.bytes).equals(d9OldKp.spki));
  // D10 DEEPEST-FIRST DRAIN: the pool supplies the leaf's DIRECT issuer (I1) but the higher intermediate (I2) is
  // missing. A FIFO drain would spend the only fetch re-retrieving the already-supplied I1 via the leaf's AIA and
  // exhaust the budget; deepest-first drains I1's fallback (the actual dead end) first, fetching the MISSING I2.
  var d10RootKp = await freshKeys(), d10I2Kp = await freshKeys(), d10I1Kp = await freshKeys(), d10LeafKp = await freshKeys();
  var d10Root = await mkCert({ signer: d10RootKp, subjectKp: d10RootKp, issuerName: "D10Root", subjectName: "D10Root", extensions: caExts() });
  var d10I2 = await mkCert({ signer: d10RootKp, subjectKp: d10I2Kp, issuerName: "D10Root", subjectName: "D10I2", extensions: caExts() });
  var d10I1 = await mkCert({ signer: d10I2Kp, subjectKp: d10I1Kp, issuerName: "D10I2", subjectName: "D10I1", extensions: caExts([aiaCaIssuersUri("https://ca.example/d10-i2.der")]) });
  var d10Leaf = await mkCert({ signer: d10I1Kp, subjectKp: d10LeafKp, issuerName: "D10I1", subjectName: "D10Leaf", extensions: [aiaCaIssuersUri("https://ca.example/d10-i1.der")] });
  var d10t = mkTransport(function (url) { if (url.indexOf("d10-i2") >= 0) return cert200(d10I2); if (url.indexOf("d10-i1") >= 0) return cert200(d10I1); throw new Error("unknown"); });
  var d10 = await pki.path.build(d10Leaf, { candidates: [d10I1], trustAnchors: [d10Root], time: T, fetchAia: true, transport: d10t, maxAiaFetches: 1 });
  check("AIA D10: deepest-first spends the single fetch on the MISSING higher hop, not the pool-supplied issuer (valid within budget 1)", d10.valid === true && d10.aiaFetches === 1);
  check("AIA D10: the fetch targeted the missing intermediate's AIA, not the leaf's already-supplied issuer", d10t.calls.length === 1 && d10t.calls[0].indexOf("d10-i2") >= 0);
  // D11 CONFIG-TIME AIA OPTION VALIDATION: a caller typo is a path/bad-input THROW (tier 1), not a swallowed fetch
  // fault that degrades to path/no-path (or, for an injected transport, an unvalidated timeout).
  check("AIA D11: a non-function opts.transport is rejected at config time (path/bad-input)", (await codeOf(pki.path.build(aLeaf, { candidates: [], trustAnchors: [aRoot], time: T, fetchAia: true, transport: true }))) === "path/bad-input");
  check("AIA D11: a negative opts.aiaTimeout is rejected at config time (path/bad-input)", (await codeOf(pki.path.build(aLeaf, { candidates: [], trustAnchors: [aRoot], time: T, fetchAia: true, transport: b1t, aiaTimeout: -5 }))) === "path/bad-input");
  check("AIA D11: a NaN opts.aiaTimeout is rejected at config time (path/bad-input)", (await codeOf(pki.path.build(aLeaf, { candidates: [], trustAnchors: [aRoot], time: T, fetchAia: true, transport: b1t, aiaTimeout: NaN }))) === "path/bad-input");
  // D12 SHARED-POOL RECHECK ON DRAIN: two deferred branches share the same missing issuer (X) reachable at ONE
  // (deduped) caIssuers URL. The lower-priority branch drains first, fetches X into the SHARED pool, but fails
  // validation; the second branch's URL is then deduped and returns nothing, so it must reconsider X from the
  // shared pool rather than only its own (empty) fetch. leaf has two same-DN issuers both issued by X: Mid_good
  // (signs leaf) and Mid_bad (expired, a different key, so it scores lower -> drains first -> does the fetch).
  var d12RootKp = await freshKeys(), d12XKp = await freshKeys(), d12GoodKp = await freshKeys(), d12BadKp = await freshKeys(), d12LeafKp = await freshKeys();
  var d12Root = await mkCert({ signer: d12RootKp, subjectKp: d12RootKp, issuerName: "D12Root", subjectName: "D12Root", extensions: caExts() });
  var d12X = await mkCert({ signer: d12RootKp, subjectKp: d12XKp, issuerName: "D12Root", subjectName: "D12X", extensions: caExts() });
  var d12Good = await mkCert({ signer: d12XKp, subjectKp: d12GoodKp, issuerName: "D12X", subjectName: "D12Mid", extensions: caExts([aiaCaIssuersUri("https://ca.example/d12-x.der")]) });
  var d12Bad = await mkCert({ signer: d12XKp, subjectKp: d12BadKp, issuerName: "D12X", subjectName: "D12Mid", notBefore: new Date("1999-01-01T00:00:00Z"), notAfter: new Date("2000-01-01T00:00:00Z"), extensions: caExts([aiaCaIssuersUri("https://ca.example/d12-x.der")]) });
  var d12Leaf = await mkCert({ signer: d12GoodKp, subjectKp: d12LeafKp, issuerName: "D12Mid", subjectName: "D12Leaf" });
  var d12t = mkTransport(function (url) { if (url.indexOf("d12-x") >= 0) return cert200(d12X); throw new Error("unknown"); });
  var d12 = await pki.path.build(d12Leaf, { candidates: [d12Good, d12Bad], trustAnchors: [d12Root], time: T, fetchAia: true, transport: d12t });
  check("AIA D12: a sibling-fetched issuer in the shared pool is reconsidered when a deduped URL returns nothing (valid)", d12.valid === true && d12.aiaFetches === 1);
  check("AIA D12: the shared caIssuers URL was fetched exactly once (deduped across both branches)", d12t.calls.length === 1);
  // D2 PER-CERT URL CAP: a leaf advertising 5 caIssuers URLs (all failing) fetches at most maxAiaPerCert.
  var d2Leaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaExt([1, 2, 3, 4, 5].map(function (i) { return { tag: 6, value: "https://ca.example/u" + i }; }))] });
  var d2t = mkTransport(function () { throw new Error("all fail"); });
  await codeOf(pki.path.build(d2Leaf, Object.assign({}, aBase, { transport: d2t, maxAiaPerCert: 2 })));
  check("AIA D2: the per-cert URL cap (maxAiaPerCert) bounds GETs for one certificate", d2t.calls.length === 2);
  // D3 URL DEDUPE + NORMALIZATION: byte-identical AND normalization-equivalent (leading/trailing whitespace)
  // caIssuers URLs collapse to a SINGLE fetch, and the transport receives the NORMALIZED url it was validated against.
  var d3Leaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaExt([{ tag: 6, value: "https://ca.example/same" }, { tag: 6, value: " https://ca.example/same " }, { tag: 6, value: "https://ca.example/same" }])] });
  var d3t = mkTransport(function () { throw new Error("fail"); });
  await codeOf(pki.path.build(d3Leaf, Object.assign({}, aBase, { transport: d3t })));
  check("AIA D3: byte-identical + whitespace-variant caIssuers URLs collapse to one fetch of the normalized URL", d3t.calls.length === 1 && d3t.calls[0] === "https://ca.example/same");
  // D4 CERTIFICATE-COUNT CAP: a huge certs-only bundle is bounded by COUNT (not only bytes) -- it still builds
  // via the capped fetched certs (a hostile TLS-trusted server cannot force O(bundle) certificate parses).
  var d4t = mkTransport(function () { return { status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: certsOnlyCms(new Array(400).fill(aInter)) }; });
  check("AIA D4: a huge certs-only bundle still builds via the count-capped fetched certs (bounded parse work)", (await pki.path.build(aLeaf, Object.assign({}, aBase, { transport: d4t }))).valid === true);
  // D5 DEDUPE BEFORE THE PER-CERT CAP: a duplicate-flood must not crowd out a usable LATER URL (the cap counts
  // DISTINCT urls). [dup x3, real] with maxAiaPerCert:3 -> the real URL is still tried -> valid.
  var d5Leaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaExt([{ tag: 6, value: "https://ca.example/dup" }, { tag: 6, value: "https://ca.example/dup" }, { tag: 6, value: "https://ca.example/dup" }, { tag: 6, value: "https://ca.example/real" }])] });
  var d5t = mkTransport(function (url) { return url.indexOf("real") >= 0 ? cert200(aInter) : { status: 404, headers: {}, body: Buffer.alloc(0) }; });
  check("AIA D5: a duplicate-flood does not crowd out a usable later URL (per-cert cap counts distinct urls) -> valid", (await pki.path.build(d5Leaf, Object.assign({}, aBase, { transport: d5t, maxAiaPerCert: 3 }))).valid === true);
  // D6 FRAGMENT DEDUPE: fragment-only variants (never sent on the wire) collapse to ONE fetch of the fragment-free URL.
  var d6Leaf = await mkCert({ signer: aInterKp, subjectKp: aLeafKp, issuerName: "AiaInter", subjectName: "AiaLeaf", extensions: [aiaExt([{ tag: 6, value: "https://ca.example/i#one" }, { tag: 6, value: "https://ca.example/i#two" }])] });
  var d6t = mkTransport(function () { throw new Error("fail"); });
  await codeOf(pki.path.build(d6Leaf, Object.assign({}, aBase, { transport: d6t })));
  check("AIA D6: fragment-only URL variants collapse to a single fetch of the fragment-free URL", d6t.calls.length === 1 && d6t.calls[0] === "https://ca.example/i");

  // E FAIL-CLOSED SKIP: every fetch fault is a skip (the DFS continues), never a spurious/raw throw.
  check("AIA E1: a transport rejection is a skip -> path/no-path (never a raw throw)", (await codeOf(pki.path.build(aLeaf, Object.assign({}, aBase, { transport: mkTransport(function () { throw new Error("network down"); }) })))) === "path/no-path");
  check("AIA E2: a non-200 status is a skip", (await codeOf(pki.path.build(aLeaf, Object.assign({}, aBase, { transport: mkTransport(function () { return { status: 404, headers: {}, body: aInter }; }) })))) === "path/no-path");
  check("AIA E3: an over-cap response body is a skip", (await codeOf(pki.path.build(aLeaf, Object.assign({}, aBase, { transport: mkTransport(function () { return { status: 200, headers: {}, body: Buffer.alloc(100) }; }), maxResponseBytes: 10 })))) === "path/no-path");
  check("AIA E4: a non-certificate body (neither DER cert nor certs-only CMS) is a skip", (await codeOf(pki.path.build(aLeaf, Object.assign({}, aBase, { transport: mkTransport(function () { return { status: 200, headers: {}, body: Buffer.from("not a certificate at all") }; }) })))) === "path/no-path");
  check("AIA E5: a certs-only CMS carrying no certificate is a skip", (await codeOf(pki.path.build(aLeaf, Object.assign({}, aBase, { transport: mkTransport(function () { return { status: 200, headers: { "content-type": "application/pkcs7-mime" }, body: certsOnlyCms([]) }; }) })))) === "path/no-path");

  // F NO TRUST BYPASS: a fetched cert is untrusted pool material -- it must pass validate, and is never an anchor.
  var fDecoyKp = await freshKeys();
  var fDecoyInter = await mkCert({ signer: aRootKp, subjectKp: fDecoyKp, issuerName: "AiaRoot", subjectName: "AiaInter", extensions: caExts() });   // same DN as the real inter, WRONG key (did not sign the leaf)
  var f1 = await pki.path.build(aLeaf, Object.assign({}, aBase, { transport: mkTransport(function () { return cert200(fDecoyInter); }) }));
  check("AIA F1: a fetched cert that fails validate is NOT accepted (valid:false via validate, not a raw insert)", f1.valid === false);

  // G OPT-OUT + TLS TRUST.
  var g1t = mkTransport(function () { throw new Error("MUST NOT be called when fetchAia is off"); });
  var g1 = await pki.path.build(aLeaf, { candidates: [aInter], trustAnchors: [aRoot], time: T, transport: g1t });   // fetchAia ABSENT
  check("AIA G1: fetchAia absent -> transport NEVER called, aiaFetches 0 (opt-out is byte-identical offline)", g1.valid === true && g1t.calls.length === 0 && g1.aiaFetches === 0);
  check("AIA G2: fetchAia:true with the DEFAULT transport + no tls trust -> fetch fails closed (no-trust-anchors), skipped", (await codeOf(pki.path.build(aLeaf, { candidates: [], trustAnchors: [aRoot], time: T, fetchAia: true }))) === "path/no-path");
  var g3t = mkTransport(function () { return cert200(aInter); });
  check("AIA G3: at the depth cap (maxDepth 0) no fetch is attempted (transport uncalled)", (await codeOf(pki.path.build(aLeaf, Object.assign({}, aBase, { transport: g3t, maxDepth: 0 })))) === "path/no-path" && g3t.calls.length === 0);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run().then(function () {}, function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : e); process.exit(1); });
