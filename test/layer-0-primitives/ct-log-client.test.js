// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the RFC 6962 sec. 4 log client: the eight HTTP messages a log serves, of which this
 * reads seven. Every vector runs offline through the shared routing fixture transport, so no socket
 * is opened and the wire shape is asserted from what crossed the seam.
 *
 * The load-bearing property is that NOTHING UNVERIFIED IS RETURNED where a signature exists to check.
 * A signed tree head carries a signature over a fixed 50-byte preimage, so `getSth` verifies it under
 * the caller-pinned log key and refuses rather than handing back an STH nobody vouched for; an SCT
 * returned by add-chain is a promise the log made, so it is verified against the chain it was issued
 * for. Where the specification provides no signature -- get-entries, get-roots -- the verbs say so
 * and the vectors assert the absence rather than implying a check that does not exist.
 *
 * The STH preimage is quoted from RFC 6962 sec. 3.5:
 *
 *   digitally-signed struct {
 *       Version version;
 *       SignatureType signature_type = tree_hash;
 *       uint64 timestamp;
 *       uint64 tree_size;
 *       opaque sha256_root_hash[32];
 *   } TreeHeadSignature;
 *
 * with `v1(0)` and `tree_hash(1)` from sec. 3.2, so the preimage is 1 + 1 + 8 + 8 + 32 = 50 bytes.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var crypto = require("crypto");
var ctx = require("../helpers/ct-fetch-transport");
var resp = ctx.resp, routeByUrl = ctx.routeByUrl;
var C = pki.constants;

async function code(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

var BASE = "https://ct.example/";
function u(path) { return BASE + "ct/v1/" + path; }

// A log whose key the caller pins, and an STH it signs. The preimage is built HERE from the RFC's
// own struct rather than by the library, so a vector compares against the specification and not
// against the implementation's idea of it.
function makeLog() {
  var kp = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  var spki = kp.publicKey.export({ format: "der", type: "spki" });
  return { kp: kp, spki: spki, logId: crypto.createHash("sha256").update(spki).digest() };
}
function sthPreimage(timestamp, treeSize, rootHash) {
  var b = Buffer.alloc(50);
  b[0] = 0;                                    // Version v1(0)
  b[1] = 1;                                    // SignatureType tree_hash(1)
  b.writeBigUInt64BE(BigInt(timestamp), 2);
  b.writeBigUInt64BE(BigInt(treeSize), 10);
  rootHash.copy(b, 18);
  return b;
}
// The digitally-signed wire form: hash(1) || sig alg(1) || uint16 length || DER signature.
function digitallySigned(der) {
  var head = Buffer.from([4, 3, (der.length >> 8) & 0xff, der.length & 0xff]);   // sha256(4), ecdsa(3)
  return Buffer.concat([head, der]);
}
function signSth(log, timestamp, treeSize, rootHash) {
  var der = crypto.sign("sha256", sthPreimage(timestamp, treeSize, rootHash), { key: log.kp.privateKey, dsaEncoding: "der" });
  return digitallySigned(der);
}

var TS = 1800000000000;
function sthBody(log, treeSize, rootHash, over) {
  var o = {
    tree_size: treeSize, timestamp: TS,
    sha256_root_hash: rootHash.toString("base64"),
    tree_head_signature: signSth(log, TS, treeSize, rootHash).toString("base64"),
  };
  Object.keys(over || {}).forEach(function (k) { o[k] = over[k]; });
  return JSON.stringify(o);
}

// A three-leaf tree, so a proof has real nodes and the audit path is not empty.
function tree(n) {
  var leaves = [];
  for (var i = 0; i < n; i++) leaves.push(pki.merkle.leafHash(Buffer.from([i])));
  return { leaves: leaves, root: pki.merkle.root(leaves) };
}

function opts(log, routes, extra) {
  var transport = routeByUrl(routes);
  var o = { url: BASE, logKey: log.spki, transport: transport };
  Object.keys(extra || {}).forEach(function (k) { o[k] = extra[k]; });
  return { o: o, transport: transport };
}

// ---------------------------------------------------------------------------
// get-sth, and the preimage it is verified over
// ---------------------------------------------------------------------------
async function runGetSth() {
  var log = makeLog(), t = tree(3);

  check("S1: the STH preimage is the 50 bytes RFC 6962 sec. 3.5 fixes",
    pki.ct.sthSignedData({ timestamp: TS, treeSize: 3n, rootHash: t.root }).toString("hex") ===
    sthPreimage(TS, 3, t.root).toString("hex"));
  check("S1b: and its version and signature_type bytes are v1(0) and tree_hash(1)",
    pki.ct.sthSignedData({ timestamp: TS, treeSize: 3n, rootHash: t.root })[0] === 0 &&
    pki.ct.sthSignedData({ timestamp: TS, treeSize: 3n, rootHash: t.root })[1] === 1);

  var f = opts(log, { [u("get-sth")]: resp(200, sthBody(log, 3, t.root), "application/json") });
  var sth = await pki.ct.getSth(f.o);
  check("S2: a signed tree head is fetched and read",
    sth.treeSize === 3n && sth.timestamp === BigInt(TS) &&
    Buffer.compare(sth.rootHash, t.root) === 0);
  check("S3: the request crossed the seam as a GET to the sec. 4.3 path",
    f.transport.calls.length === 1 && f.transport.calls[0].method === "GET" &&
    f.transport.calls[0].url === u("get-sth"));

  /* The pinned key is READ ONCE. `opts.logKey` was read twice, by the presence check and then by the
     copy the signature is verified under, and an accessor answers each read separately: presenting the
     key the caller means to pin to the check and a DIFFERENT one to the copy made getSth verify an
     attacker-signed tree head under the attacker's own key and return it as a result. The vector below
     is that exact sequence. The log that signs the response is NOT the one the first read names, so a
     verdict of "fetched" means the second read decided which log was trusted. */
  async function sthUnderTwoFacedKey() {
    var genuine = log, attacker = makeLog();
    var reads = [];
    var h = opts(attacker, { [u("get-sth")]: resp(200, sthBody(attacker, 3, t.root), "application/json") });
    var keys = [genuine.spki, attacker.spki];
    Object.defineProperty(h.o, "logKey", {
      configurable: true, enumerable: true,
      get: function () { var i = reads.length; reads.push(i); return keys[i] || attacker.spki; },
    });
    var outcome;
    try {
      var s = await pki.ct.getSth(h.o);
      outcome = s.treeSize === 3n ? "ACCEPTED an attacker-signed tree head" : "returned something else";
    } catch (e) { outcome = (e && e.isPkiError === true) ? e.code : "UNTYPED"; }
    return { outcome: outcome, reads: reads.length };
  }
  var twoFaced = await sthUnderTwoFacedKey();
  /* The refusal moved earlier and got stronger. Reading the option once was enough to stop the second
     answer deciding anything, and the client's door now declines the whole bag instead: an options
     object whose properties are not plain values is a shape no set of checks can answer for, which is
     the rule `signSct` in this module already applied. So the outcome is a refusal at the door rather
     than a fetch that ends in `ct/sth-untrusted`, and the option is never read at all. */
  check("S3b: a two-faced opts.logKey cannot hand one key to the check and another to the verification (" +
    twoFaced.outcome + ", " + twoFaced.reads + " read(s))", twoFaced.outcome === "ct/bad-input");
  check("S3c: and it is refused before the option is read, so there is no answer to give at all",
    twoFaced.reads === 0);
  /* The control, which is what makes the two above mean something: the attacker's key really does
     verify the attacker's tree head. So the second read was not harmless -- had the copy taken it, the
     call would have returned a result instead of refusing, which is the acceptance S3b now denies. */
  var attackerAccepts = await (async function () {
    var attacker = makeLog();
    var h = opts(attacker, { [u("get-sth")]: resp(200, sthBody(attacker, 3, t.root), "application/json") });
    // No catch: the control's whole point is that this fetch SUCCEEDS, so a throw here is the
    // diagnostic rather than a quiet false that would make the control look merely unmet.
    var s = await pki.ct.getSth(h.o);
    return s.treeSize === 3n;
  })();
  check("S3d: CONTROL the key the second read would have supplied does verify that tree head",
    attackerAccepts === true);

  /* `opts.logKey` is documented "BufferSource, // the log's SubjectPublicKeyInfo, pinned by the caller",
     and the copy that takes it accepted a Buffer and a Uint8Array only. So the ArrayBuffer that
     `crypto.subtle.exportKey("spki", ...)` returns, which is how a caller holding a WebCrypto key has it,
     was refused with `ct/bad-input` before the transport ran, while a Buffer of the identical bytes
     fetched and verified. The property is that the pinned key verifies the same whichever container holds
     it, run on a fetch that SUCCEEDS so the copy is actually reached. */
  async function sthWithKeyAs(convert) {
    var h = opts(log, { [u("get-sth")]: resp(200, sthBody(log, 3, t.root), "application/json") });
    h.o.logKey = convert(h.o.logKey);
    try {
      var s = await pki.ct.getSth(h.o);
      return s.treeSize === 3n ? "fetched" : "wrong-tree";
    } catch (e) { return (e && e.isPkiError === true) ? "throw:" + e.code : "UNTYPED:" + ((e && e.message) || e); }
  }
  var keyReps = [
    ["Buffer", await sthWithKeyAs(function (k) { return Buffer.from(k); })],
    ["Uint8Array", await sthWithKeyAs(function (k) { return new Uint8Array(Buffer.from(k)); })],
    ["DataView", await sthWithKeyAs(function (k) { var x = new Uint8Array(Buffer.from(k)); return new DataView(x.buffer); })],
    ["ArrayBuffer", await sthWithKeyAs(function (k) { return new Uint8Array(Buffer.from(k)).buffer; })],
  ];
  var keyBase = keyReps[0][1];
  var keyBad = keyReps.slice(1).filter(function (r) { return r[1] !== keyBase; });
  check("S1c: the pinned log key verifies the same whichever byte container holds it (" + keyBase +
    (keyBad.length ? "; diverged: " + keyBad.map(function (r) { return r[0] + " -> " + r[1]; }).join(" | ") : "") + ")",
    keyBase === "fetched" && keyBad.length === 0);

  /* The signature is the whole point: an STH nobody vouched for is not returned. */
  var other = makeLog();
  var g = opts(other, { [u("get-sth")]: resp(200, sthBody(log, 3, t.root), "application/json") });
  check("S4: an STH signed by a key other than the pinned one is refused",
    await code(function () { return pki.ct.getSth(g.o); }) === "ct/sth-untrusted");
  var flipped = opts(log, { [u("get-sth")]: resp(200, sthBody(log, 3, t.root, {
    sha256_root_hash: Buffer.alloc(32, 7).toString("base64"),
  }), "application/json") });
  check("S5: an STH whose root was altered after signing is refused",
    await code(function () { return pki.ct.getSth(flipped.o); }) === "ct/sth-untrusted");
  var resized = opts(log, { [u("get-sth")]: resp(200, sthBody(log, 3, t.root, { tree_size: 4 }), "application/json") });
  check("S6: an STH whose tree size was altered after signing is refused",
    await code(function () { return pki.ct.getSth(resized.o); }) === "ct/sth-untrusted");
  var retimed = opts(log, { [u("get-sth")]: resp(200, sthBody(log, 3, t.root, { timestamp: TS + 1 }), "application/json") });
  check("S7: an STH whose timestamp was altered after signing is refused",
    await code(function () { return pki.ct.getSth(retimed.o); }) === "ct/sth-untrusted");

  /* The key the STH is verified under is the key PINNED AT THE CALL, not whatever `opts.logKey` holds
     when the fetch returns. The key was read after the await, so a caller that reuses that buffer during
     the request has the tree head checked against the replacement: the log it pinned is not the log that
     answered. The route function below is the mutation point, which is exactly where a real caller's
     buffer reuse would land. */
  var pinned = makeLog(), substitute = makeLog();
  var liveKey = Buffer.from(pinned.spki);
  check("S7a: the two log keys are the same length, so one can overwrite the other in place",
    pinned.spki.length === substitute.spki.length);
  var swapRoutes = {};
  swapRoutes[u("get-sth")] = function () {
    substitute.spki.copy(liveKey);                  // the pinned key becomes the other log's key
    return { status: 200, headers: { "content-type": "application/json" },
      body: sthBody(substitute, 3, t.root) };       // and the STH is signed by that other log
  };
  var swapT = routeByUrl(swapRoutes);
  var swapCode = await code(function () {
    return pki.ct.getSth({ url: BASE, logKey: liveKey, transport: swapT });
  });
  check("S7b: an STH signed by a log substituted into the key buffer mid-fetch is refused (" + swapCode + ")",
    swapCode === "ct/sth-untrusted");
  /* CONTROLS: the other log's STH verifies when that log is the one actually pinned, and the pinned
     log's own STH verifies. So S7b is about the substitution and not about either key being unusable. */
  var c1 = opts(substitute, { [u("get-sth")]: resp(200, sthBody(substitute, 3, t.root), "application/json") });
  check("S7c: CONTROL the substitute log's STH verifies when that log is the one pinned",
    (await pki.ct.getSth(c1.o)).treeSize === 3n);
  var c2 = opts(pinned, { [u("get-sth")]: resp(200, sthBody(pinned, 3, t.root), "application/json") });
  check("S7d: CONTROL the pinned log's own STH verifies",
    (await pki.ct.getSth(c2.o)).treeSize === 3n);

  /* What getSth RETURNS is what sthSignedData TAKES. A client that fetches a tree head and then wants the
     50 bytes the log signed, to fold a proof against or to re-verify, has to be able to hand one verb's
     result to the other. The returned record carries a `raw` field that the preimage builder's allowlist
     refused, so the obvious next call threw instead of producing the preimage. */
  var c3 = opts(log, { [u("get-sth")]: resp(200, sthBody(log, 3, t.root), "application/json") });
  var fetched = await pki.ct.getSth(c3.o);
  var preimageCode = "NO-THROW";
  var preimage = null;
  try { preimage = pki.ct.sthSignedData(fetched); } catch (e) { preimageCode = e.code || e.message; }
  check("S8: the record getSth returns is one sthSignedData accepts (" + preimageCode + ")",
    preimage !== null && preimage.length === 50);
  check("S8a: and it is the same preimage the log signed over those values",
    preimage !== null && Buffer.compare(preimage,
      pki.ct.sthSignedData({ timestamp: fetched.timestamp, treeSize: fetched.treeSize,
        rootHash: fetched.rootHash })) === 0);

  /* Shape refusals: each field is required and each is held to its type. */
  // Each shape names the code it must report, so a refusal for the wrong reason
  // is a failure rather than a pass.
  /* Two layers refuse a bad number, and which one speaks says where the fault is. A token that does not
     DENOTE an integer is a malformed document for a format that reads it as one, and the JSON reader
     refuses it while it is still text: `ct/bad-json`. A token that denotes an integer the field cannot
     take is a bad STH: `ct/bad-sth`, which is why `-1` still reports that. The split is deliberate. */
  var SHAPES = [
    ["no tree_size", { tree_size: undefined }, "ct/bad-sth"],
    ["a non-integer tree_size", { tree_size: 1.5 }, "ct/bad-json"],
    ["a negative tree_size", { tree_size: -1 }, "ct/bad-sth"],
    ["no timestamp", { timestamp: undefined }, "ct/bad-sth"],
    ["no root hash", { sha256_root_hash: undefined }, "ct/bad-sth"],
    ["a root hash that is not 32 bytes", { sha256_root_hash: Buffer.alloc(31).toString("base64") }, "ct/bad-sth"],
    ["no signature", { tree_head_signature: undefined }, "ct/bad-sth"],
    ["a signature shorter than a digitally-signed header", { tree_head_signature: "AAEC" }, "ct/bad-signature"],
    ["a signature whose stated length disagrees with its bytes", { tree_head_signature: Buffer.from([4, 3, 0, 99, 1, 2]).toString("base64") }, "ct/bad-signature"],
  ];
  var shapeOk = 0;
  for (var i = 0; i < SHAPES.length; i++) {
    var body = JSON.parse(sthBody(log, 3, t.root));
    Object.keys(SHAPES[i][1]).forEach(function (k) {
      if (SHAPES[i][1][k] === undefined) delete body[k]; else body[k] = SHAPES[i][1][k];
    });
    var fx = opts(log, { [u("get-sth")]: resp(200, JSON.stringify(body), "application/json") });
    var c = await code(function () { return pki.ct.getSth(fx.o); });
    if (c === SHAPES[i][2]) shapeOk++;
    else console.log("    STH shape " + SHAPES[i][0] + ": expected " + SHAPES[i][2] + ", got " + c);
  }
  check("S8: every malformed STH shape is refused with its own reason (" + shapeOk + "/" +
    SHAPES.length + ")", shapeOk === SHAPES.length);

  /* S8a. The spelling that no check made AFTER conversion can see. `1.0000000000000001` converts to the
     Number 1, so a tree size written that way passed the integer check as 1 and was folded into the
     reconstructed binary preimage the tree-head signature is verified over: the rounded spelling
     verified, and the size the caller was handed was not the one the log sent. It has to be refused on
     the TOKEN, which is where it still differs from 1.
     The body is built as TEXT, because `JSON.parse` would already have collapsed it to 1 and the fixture
     would be testing nothing. */
  var exactBody = JSON.parse(sthBody(log, 3, t.root));
  var exactText = JSON.stringify(exactBody).replace("\"tree_size\":3", "\"tree_size\":1.0000000000000001");
  if (exactText.indexOf("1.0000000000000001") === -1) {
    exactText = JSON.stringify(exactBody).replace(/"tree_size":\s*3/, "\"tree_size\":1.0000000000000001");
  }
  var fxExact = opts(log, { [u("get-sth")]: resp(200, exactText, "application/json") });
  var exactCode = await code(function () { return pki.ct.getSth(fxExact.o); });
  check("S8a: a tree_size spelled 1.0000000000000001 is refused on the token, not read as 1 (" +
    exactCode + ")",
    Number("1.0000000000000001") === 1 && exactCode === "ct/bad-json");
  /* CONTROL: exponent form is LEGAL in an RFC 6962 response and still accepted, which is why the policy
     is "the value must be exactly its own integer" and not "no exponents". A tree size of 3 written
     `3e0` is the same tree size. */
  var expText = JSON.stringify(exactBody).replace("\"tree_size\":3", "\"tree_size\":3e0");
  var fxExp = opts(log, { [u("get-sth")]: resp(200, expText, "application/json") });
  var expSth = null, expCode = null;
  try { expSth = await pki.ct.getSth(fxExp.o); } catch (e) { expCode = (e && e.code) || "NO-CODE"; }
  check("S8b: CONTROL a tree_size written in exponent form is still accepted and reads as that integer" +
    (expCode ? " (refused " + expCode + ")" : ""),
    expSth !== null && expSth.treeSize === 3n);

  /* The log key is required: there is no baked-in key and no unverified mode. */
  var noKey = opts(log, { [u("get-sth")]: resp(200, sthBody(log, 3, t.root), "application/json") });
  delete noKey.o.logKey;
  check("S9: opts.logKey is required, since an unverified STH is not a result",
    await code(function () { return pki.ct.getSth(noKey.o); }) === "ct/bad-input");
  check("S10: and the gate runs before the wire", noKey.transport.calls.length === 0);

  /* Offline verification of an STH a caller already holds. */
  var held = JSON.parse(sthBody(log, 3, t.root));
  check("S11: an STH held offline verifies under the log key",
    await pki.ct.verifySth({ treeSize: 3n, timestamp: BigInt(TS), rootHash: t.root,
      signature: Buffer.from(held.tree_head_signature, "base64") }, log.spki) === true);
  check("S12: and returns false, not a throw, when it is another log's",
    await pki.ct.verifySth({ treeSize: 3n, timestamp: BigInt(TS), rootHash: t.root,
      signature: Buffer.from(held.tree_head_signature, "base64") }, other.spki) === false);
  /* The two operations a signature check runs are captured at load. Held as an object whose METHODS are
     fetched per call, a replacement installed on the SubtleCrypto prototype afterwards decided the
     verdict: a `verify` answering true accepts a tree head no log signed. The same replacement reaches
     every signature gate in this module, so this one vector stands for all of them. */
  var subtleProto = Object.getPrototypeOf(pki.webcrypto.subtle);
  var realVerify = subtleProto.verify;
  var wrongLog;
  try {
    Object.defineProperty(subtleProto, "verify", {
      configurable: true, writable: true,
      value: async function () { return true; },
    });
    wrongLog = await pki.ct.verifySth({ treeSize: 3n, timestamp: BigInt(TS), rootHash: t.root,
      signature: Buffer.from(held.tree_head_signature, "base64") }, other.spki);
  } finally {
    Object.defineProperty(subtleProto, "verify", {
      configurable: true, writable: true, value: realVerify,
    });
  }
  check("S12a: a verify installed on the SubtleCrypto prototype after load does not decide the " +
    "verdict (" + wrongLog + ")", wrongLog === false);
  /* CONTROL: the replacement is restored, so the suite below is not running against it, and the
     genuine signature still verifies. */
  check("S12b: CONTROL the real operation is back and the log's own STH still verifies",
    subtleProto.verify === realVerify &&
    await pki.ct.verifySth({ treeSize: 3n, timestamp: BigInt(TS), rootHash: t.root,
      signature: Buffer.from(held.tree_head_signature, "base64") }, log.spki) === true);

  // The verdict is about the signature supplied at entry. Verification imports the log key with an await,
  // so a signature held as a VIEW onto the caller's buffer could be overwritten in that window and the
  // bytes verified would not be the bytes handed in. The caller's buffer is filled with the real
  // signature immediately after the call returns its promise; the verdict must still be false.
  // The log here signs with RSA, because that is the arm where the window exists: an ECDSA signature is
  // converted from DER to P1363 before the key import, and the conversion already makes a copy. One byte
  // inside the signature is flipped rather than the buffer zeroed, so the header and length still parse;
  // a value refused before the import never reaches the window this is about.
  var rsaKp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaLog = { kp: rsaKp, spki: rsaKp.publicKey.export({ format: "der", type: "spki" }) };
  var rsaSth = { treeSize: 3n, timestamp: BigInt(TS), rootHash: t.root };
  var rsaRaw = crypto.sign("sha256", sthPreimage(TS, 3, t.root), rsaKp.privateKey);
  var good = Buffer.concat([Buffer.from([4, 1, (rsaRaw.length >> 8) & 0xff, rsaRaw.length & 0xff]), rsaRaw]);
  var mutable = Buffer.from(good);
  mutable[mutable.length - 1] ^= 0xff;
  var mutatingSth = { treeSize: rsaSth.treeSize, timestamp: rsaSth.timestamp, rootHash: rsaSth.rootHash, signature: mutable };
  var verdict = pki.ct.verifySth(mutatingSth, rsaLog.spki);
  good.copy(mutable);
  check("S13: an RSA tree-head signature overwritten while verification is in flight does not change the verdict",
    (await verdict) === false);
  // Two controls, so S13 is the mutation being ignored rather than this arm failing for another reason:
  // the correct signature verifies, and the corrupted one on its own does not.
  check("S13a: control -- the same RSA signature supplied at entry verifies",
    await pki.ct.verifySth({ treeSize: 3n, timestamp: BigInt(TS), rootHash: t.root,
      signature: Buffer.from(good) }, rsaLog.spki) === true);
  var stillBad = Buffer.from(good); stillBad[stillBad.length - 1] ^= 0xff;
  check("S13b: control -- the corrupted RSA signature alone does not verify",
    await pki.ct.verifySth({ treeSize: 3n, timestamp: BigInt(TS), rootHash: t.root,
      signature: stillBad }, rsaLog.spki) === false);
}

// ---------------------------------------------------------------------------
// get-proof-by-hash, folded against the STH it was requested at
// ---------------------------------------------------------------------------
async function runGetProof() {
  var log = makeLog(), t = tree(3);
  var sth = { treeSize: 3n, timestamp: BigInt(TS), rootHash: t.root };
  var proof = pki.merkle.inclusionProof({ leafHashes: t.leaves, leafIndex: 1 });
  var proofBody = JSON.stringify({ leaf_index: 1, audit_path: proof.map(function (p) { return p.toString("base64"); }) });

  var f = opts(log, { [u("get-proof-by-hash") + "?hash=" + encodeURIComponent(t.leaves[1].toString("base64")) + "&tree_size=3"]: resp(200, proofBody, "application/json") });
  var got = await pki.ct.getProofByHash(Object.assign(f.o, { leafHash: t.leaves[1], sth: sth }));
  check("P1: an audit proof is fetched and folds to the STH root",
    got.leafIndex === 1n && got.auditPath.length === proof.length && got.verified === true);
  check("P2: the tree size in the query came from the STH, not a second argument",
    f.transport.calls[0].url.indexOf("tree_size=3") !== -1);

  /* A proof that does not fold is refused, not returned with a false flag. */
  var badPath = proof.map(function (p) { var q = Buffer.from(p); q[0] ^= 1; return q.toString("base64"); });
  var g = opts(log, { [u("get-proof-by-hash") + "?hash=" + encodeURIComponent(t.leaves[1].toString("base64")) + "&tree_size=3"]:
    resp(200, JSON.stringify({ leaf_index: 1, audit_path: badPath }), "application/json") });
  check("P3: a proof that does not fold to the STH root is refused",
    await code(function () { return pki.ct.getProofByHash(Object.assign(g.o, { leafHash: t.leaves[1], sth: sth })); }) === "ct/proof-mismatch");
  /* A leaf index the log states that the proof does not support. */
  var h = opts(log, { [u("get-proof-by-hash") + "?hash=" + encodeURIComponent(t.leaves[1].toString("base64")) + "&tree_size=3"]:
    resp(200, JSON.stringify({ leaf_index: 0, audit_path: proof.map(function (p) { return p.toString("base64"); }) }), "application/json") });
  check("P4: a leaf index the proof does not support is refused",
    await code(function () { return pki.ct.getProofByHash(Object.assign(h.o, { leafHash: t.leaves[1], sth: sth })); }) === "ct/proof-mismatch");
  /* The STH is required: a proof against nothing proves nothing. */
  var noSth = opts(log, {});
  check("P5: opts.sth is required, since a proof is verified against a tree head",
    await code(function () { return pki.ct.getProofByHash(Object.assign(noSth.o, { leafHash: t.leaves[1] })); }) === "ct/bad-input");
  check("P6: and the gate runs before the wire", noSth.transport.calls.length === 0);

  /* The proof is folded against the tree head supplied at ENTRY, even when the caller's buffers change
     while the fetch is in flight. The STH root hash and the leaf hash are held across a network await, so
     a caller that reuses either buffer would otherwise have the fold run against the replacement: an
     empty proof folds a one-leaf tree to its own leaf hash, so overwriting the root with a leaf hash makes
     an empty proof for that leaf "verify" against a tree head nobody supplied. */
  var one = tree(1);
  var otherLeaf = Buffer.alloc(32, 0x5b);
  var liveRoot = Buffer.from(one.root);
  var liveLeaf = Buffer.from(otherLeaf);
  var emptyProof = JSON.stringify({ leaf_index: 0, audit_path: [] });
  var raceRoutes = {};
  raceRoutes[u("get-proof-by-hash") + "?hash=" + encodeURIComponent(otherLeaf.toString("base64")) + "&tree_size=1"] =
    resp(200, emptyProof, "application/json");
  raceRoutes[u("get-proof-by-hash") + "?hash=" + encodeURIComponent(one.root.toString("base64")) + "&tree_size=1"] =
    resp(200, emptyProof, "application/json");
  var r = opts(log, raceRoutes);
  var pending = pki.ct.getProofByHash(Object.assign(r.o, {
    leafHash: liveLeaf, sth: { treeSize: 1n, timestamp: BigInt(TS), rootHash: liveRoot },
  }));
  otherLeaf.copy(liveRoot);              // the trusted root becomes the leaf hash, mid-fetch
  var racedProof = null, racedCode = null;
  try { racedProof = await pending; } catch (e) { racedCode = e.code || e.message; }
  check("P7: a trusted root overwritten during the fetch cannot make an empty proof verify" +
    (racedCode ? " (refused with " + racedCode + ")" : ""),
    racedProof === null || racedProof.verified !== true);

  /* CONTROL: the same empty proof DOES verify when the root legitimately is that leaf hash, so P7's
     refusal is about the swap and not about empty proofs or one-leaf trees. */
  var c1 = opts(log, raceRoutes);
  var legit = await pki.ct.getProofByHash(Object.assign(c1.o, {
    leafHash: otherLeaf, sth: { treeSize: 1n, timestamp: BigInt(TS), rootHash: otherLeaf },
  }));
  check("P8: CONTROL an empty proof folds a one-leaf tree to its own leaf hash", legit.verified === true);
}

// ---------------------------------------------------------------------------
// get-sth-consistency, folded against both tree heads
// ---------------------------------------------------------------------------
async function runGetConsistency() {
  var log = makeLog(), t5 = tree(5);
  var oldSth = { treeSize: 3n, timestamp: BigInt(TS), rootHash: pki.merkle.root(t5.leaves.slice(0, 3)) };
  var newSth = { treeSize: 5n, timestamp: BigInt(TS + 1), rootHash: t5.root };
  var cons = pki.merkle.consistencyProof({ leafHashes: t5.leaves, oldSize: 3 });
  var body = JSON.stringify({ consistency: cons.map(function (p) { return p.toString("base64"); }) });

  var f = opts(log, { [u("get-sth-consistency") + "?first=3&second=5"]: resp(200, body, "application/json") });
  var got = await pki.ct.getSthConsistency(Object.assign(f.o, { oldSth: oldSth, newSth: newSth }));
  check("C1: a consistency proof is fetched and folds both roots", got.verified === true && got.consistency.length === cons.length);
  check("C2: both sizes in the query came from the two tree heads",
    f.transport.calls[0].url.indexOf("first=3&second=5") !== -1);
  var bad = cons.map(function (p) { var q = Buffer.from(p); q[0] ^= 1; return q.toString("base64"); });
  var g = opts(log, { [u("get-sth-consistency") + "?first=3&second=5"]: resp(200, JSON.stringify({ consistency: bad }), "application/json") });
  check("C3: a consistency proof that does not fold is refused, which is the append-only check",
    await code(function () { return pki.ct.getSthConsistency(Object.assign(g.o, { oldSth: oldSth, newSth: newSth })); }) === "ct/consistency-mismatch");
}

// ---------------------------------------------------------------------------
// get-entries and get-roots: the two the specification leaves unsigned
// ---------------------------------------------------------------------------
async function runGetEntriesRoots() {
  var log = makeLog();
  var e = [{ leaf_input: Buffer.from("leaf0").toString("base64"), extra_data: Buffer.from("x0").toString("base64") },
    { leaf_input: Buffer.from("leaf1").toString("base64"), extra_data: "" }];
  var f = opts(log, { [u("get-entries") + "?start=0&end=1"]: resp(200, JSON.stringify({ entries: e }), "application/json") });
  var got = await pki.ct.getEntries(Object.assign(f.o, { start: 0, end: 1 }));
  check("E1: entries are fetched and decoded", got.entries.length === 2 &&
    got.entries[0].leafInput.toString("utf8") === "leaf0" && got.entries[1].extraData.length === 0);

  /* "Logs MAY restrict the number of entries that can be retrieved per get-entries
     request... the log SHALL return the maximum number of entries permissible."
     So a short answer is normal and is reported rather than treated as an error. */
  var short = opts(log, { [u("get-entries") + "?start=0&end=9"]: resp(200, JSON.stringify({ entries: [e[0]] }), "application/json") });
  var sgot = await pki.ct.getEntries(Object.assign(short.o, { start: 0, end: 9 }));
  check("E2: a log returning fewer entries than asked is reported, not refused",
    sgot.entries.length === 1 && sgot.requested === 10 && sgot.truncated === true);
  check("E3: and a full answer is not reported as truncated", got.truncated === false && got.requested === 2);
  /* More entries than asked for is the other direction and IS a fault. */
  var over = opts(log, { [u("get-entries") + "?start=0&end=0"]: resp(200, JSON.stringify({ entries: e }), "application/json") });
  check("E4: a log returning MORE entries than asked is refused",
    await code(function () { return pki.ct.getEntries(Object.assign(over.o, { start: 0, end: 0 })); }) === "ct/bad-entries");
  var inverted = opts(log, {});
  check("E5: an inverted range is refused before the wire",
    await code(function () { return pki.ct.getEntries(Object.assign(inverted.o, { start: 5, end: 1 })); }) === "ct/bad-input" &&
    inverted.transport.calls.length === 0);

  var roots = [Buffer.from("root-a"), Buffer.from("root-b")];
  var r = opts(log, { [u("get-roots")]: resp(200, JSON.stringify({ certificates: roots.map(function (x) { return x.toString("base64"); }) }), "application/json") });
  var rgot = await pki.ct.getRoots(r.o);
  check("E6: the accepted roots are fetched and decoded",
    rgot.certificates.length === 2 && rgot.certificates[0].toString("utf8") === "root-a");

  /* The element COUNT is capped, which it was not: the cap in the shared base64-array reader was keyed on
     the proof entries' fixed 32-byte width, so the roots path, whose entries have no fixed width, had
     none. A configured log is trusted for its own signatures and not for its resource use, and a response
     well under the 4 MiB body cap carries about a million empty strings, each of which became its own
     Buffer (CWE-770). Measured below by count rather than by heap, since the count is what the cap decides
     and a heap figure on a 64-bit runtime is noise. */
  var many = [];
  for (var mi = 0; mi < C.LIMITS.CT_MAX_ROOTS + 1; mi++) many.push("");
  var overRoots = opts(log, { [u("get-roots")]: resp(200, JSON.stringify({ certificates: many }), "application/json") });
  check("E6a: a roots response carrying more entries than the cap is refused",
    await code(function () { return pki.ct.getRoots(overRoots.o); }) === "ct/bad-roots");
  var atCap = [];
  for (var ai = 0; ai < C.LIMITS.CT_MAX_ROOTS; ai++) atCap.push(Buffer.from("r" + ai).toString("base64"));
  var ok = opts(log, { [u("get-roots")]: resp(200, JSON.stringify({ certificates: atCap }), "application/json") });
  check("E6b: CONTROL a response exactly at the cap is accepted, so the bound is the count and not the shape",
    (await pki.ct.getRoots(ok.o)).certificates.length === C.LIMITS.CT_MAX_ROOTS);
}

// ---------------------------------------------------------------------------
// add-chain / add-pre-chain: the SCT the log returns is a promise, so it is checked
// ---------------------------------------------------------------------------
async function runAddChain() {
  var log = makeLog();
  var leaf = Buffer.from("a certificate the log accepted");
  var sct = { version: 0, logId: log.logId, timestamp: BigInt(TS), extensions: Buffer.alloc(0) };
  var signedData = pki.ct.reconstructSignedData({ entryType: 0, leafCert: leaf }, sct);
  var der = crypto.sign("sha256", signedData, { key: log.kp.privateKey, dsaEncoding: "der" });
  var body = JSON.stringify({ sct_version: 0, id: log.logId.toString("base64"),
    timestamp: TS, extensions: "", signature: digitallySigned(der).toString("base64") });

  var f = opts(log, { [u("add-chain")]: resp(200, body, "application/json") });
  var got = await pki.ct.addChain(Object.assign(f.o, { chain: [leaf] }));
  check("A1: add-chain returns an SCT verified against the chain it was issued for",
    got.verified === true && got.sct.timestamp === BigInt(TS) &&
    Buffer.compare(got.sct.logId, log.logId) === 0);
  check("A2: the request crossed the seam as a POST of a base64 chain to the sec. 4.1 path",
    f.transport.calls[0].method === "POST" && f.transport.calls[0].url === u("add-chain") &&
    JSON.parse(f.transport.calls[0].body).chain[0] === leaf.toString("base64"));

  // The certificate submitted and the certificate the returned SCT is verified over are one read of the
  // caller's array. An indexed accessor answering with a second certificate on its second read would have
  // the log receipt for one certificate accepted as a receipt for another. Here the SCT is genuinely
  // signed over `other`, so a second read of `other` would make the verification pass while `leaf` was
  // what went out; with one read the receipt does not match what was submitted and is refused.
  var swappedIn = Buffer.from("a DIFFERENT certificate the log never saw");
  var otherSigned = pki.ct.reconstructSignedData({ entryType: 0, leafCert: swappedIn }, sct);
  var otherDer = crypto.sign("sha256", otherSigned, { key: log.kp.privateKey, dsaEncoding: "der" });
  var otherBody = JSON.stringify({ sct_version: 0, id: log.logId.toString("base64"),
    timestamp: TS, extensions: "", signature: digitallySigned(otherDer).toString("base64") });
  var swap = opts(log, { [u("add-chain")]: resp(200, otherBody, "application/json") });
  var reads = 0;
  var twoFaced = [];
  Object.defineProperty(twoFaced, "0", { enumerable: true, get: function () { reads += 1; return reads === 1 ? leaf : swappedIn; } });
  Object.defineProperty(twoFaced, "length", { value: 1 });
  var swapCode = await code(function () { return pki.ct.addChain(Object.assign(swap.o, { chain: twoFaced })); });
  check("A2a: a chain element read twice cannot submit one certificate and be verified against another (" +
    swapCode + ", " + reads + " read(s))", swapCode === "ct/sct-untrusted" && reads === 1);
  check("A2b: and the certificate that went out is the one read first",
    JSON.parse(swap.transport.calls[0].body).chain[0] === leaf.toString("base64"));

  /* The receipt is in the SCT shape the rest of the module reads. A receipt is only useful if it can be
     embedded and re-verified, and both of those go through verbs that take the parsed shape `parseSctList`
     and `signSct` produce: the algorithm bytes decoded into `signatureAlgorithm`, and `signature` the raw
     signature rather than the whole TLS digitally-signed structure. Returning the wire structure instead
     made the receipt unusable by every verb that consumes one. */
  check("A2a: the receipt carries its decoded signature algorithm",
    got.sct.signatureAlgorithm != null && got.sct.signatureAlgorithm.hashName === "sha256" &&
    got.sct.signatureAlgorithm.signatureName === "ecdsa");
  check("A2b: and `signature` is the raw signature, not the digitally-signed wrapper",
    Buffer.compare(got.sct.signature, der) === 0);
  check("A2c: so the receipt re-verifies through pki.ct.verifySct",
    (await pki.ct.verifySct({ entryType: 0, leafCert: leaf }, got.sct, log.spki)) === true);
  check("A2d: and encodes into an SCT list for embedding",
    Buffer.isBuffer(pki.ct.encodeSctList([got.sct])));
  check("A2e: which parses back to the same receipt",
    pki.ct.parseSctList(pki.ct.encodeSctList([got.sct])).scts[0].timestamp === BigInt(TS));
  // The receipt is the shape this module's OTHER consumers read, and the log-list verbs key a log by
  // `logIdHex` rather than by the raw bytes. Omitting it made a receipt that verified here unusable
  // there: `verifySctWithLogList` refused it outright and `verifySctList` dropped it and reported a
  // policy failure, both for a receipt the log had genuinely signed.
  check("A2f: the receipt carries logIdHex, the field the log-list verbs key a log by",
    got.sct.logIdHex === log.logId.toString("hex"));
  // CONTROL: the shape parseSctList produces carries it too, which is the claim the receipt has to meet.
  check("A2g: CONTROL parseSctList produces that same field",
    pki.ct.parseSctList(pki.ct.encodeSctList([got.sct])).scts[0].logIdHex === log.logId.toString("hex"));

  /* An SCT the log returns that does not verify is not a receipt. */
  var badDer = Buffer.from(der); badDer[badDer.length - 1] ^= 1;
  var g = opts(log, { [u("add-chain")]: resp(200, JSON.stringify({ sct_version: 0,
    id: log.logId.toString("base64"), timestamp: TS, extensions: "",
    signature: digitallySigned(badDer).toString("base64") }), "application/json") });
  check("A3: an SCT whose signature does not verify is refused, not returned",
    await code(function () { return pki.ct.addChain(Object.assign(g.o, { chain: [leaf] })); }) === "ct/sct-untrusted");
  /* An SCT naming a different log is not this log's receipt. */
  var other = makeLog();
  var h = opts(log, { [u("add-chain")]: resp(200, JSON.stringify({ sct_version: 0,
    id: other.logId.toString("base64"), timestamp: TS, extensions: "",
    signature: digitallySigned(der).toString("base64") }), "application/json") });
  check("A4: an SCT naming a log other than the pinned one is refused",
    await code(function () { return pki.ct.addChain(Object.assign(h.o, { chain: [leaf] })); }) === "ct/sct-untrusted");
  var e2 = opts(log, {});
  check("A5: an empty chain is refused before the wire",
    await code(function () { return pki.ct.addChain(Object.assign(e2.o, { chain: [] })); }) === "ct/bad-input" &&
    e2.transport.calls.length === 0);

  /* add-pre-chain differs in the path and in the entry type the SCT covers. */
  var tbs = Buffer.from("the tbsCertificate of a precertificate");
  var ikh = crypto.createHash("sha256").update(Buffer.from("issuer spki")).digest();
  var preSigned = pki.ct.reconstructSignedData({ entryType: 1, tbsCertificate: tbs, issuerKeyHash: ikh }, sct);
  var preDer = crypto.sign("sha256", preSigned, { key: log.kp.privateKey, dsaEncoding: "der" });
  var p = opts(log, { [u("add-pre-chain")]: resp(200, JSON.stringify({ sct_version: 0,
    id: log.logId.toString("base64"), timestamp: TS, extensions: "",
    signature: digitallySigned(preDer).toString("base64") }), "application/json") });
  var pgot = await pki.ct.addPreChain(Object.assign(p.o, { chain: [Buffer.from("precert")],
    tbsCertificate: tbs, issuerKeyHash: ikh }));
  check("A6: add-pre-chain verifies its SCT over the precert entry type",
    pgot.verified === true && p.transport.calls[0].url === u("add-pre-chain"));
}

// ---------------------------------------------------------------------------
// The shape every verb shares
// ---------------------------------------------------------------------------
async function runShared() {
  var log = makeLog(), t = tree(1);
  check("X1: an http URL is refused; a log is reached over TLS",
    await code(function () {
      return pki.ct.getSth({ url: "http://ct.example/", logKey: log.spki, transport: routeByUrl({}) });
    }) === "ct/insecure-url");
  check("X2: a 404 from the log is an http error, not an empty result",
    await code(function () {
      return pki.ct.getSth({ url: BASE, logKey: log.spki, transport: routeByUrl({ [u("get-sth")]: resp(404, "nope") }) });
    }) === "ct/http-error");
  check("X3: a body that is not JSON is refused",
    await code(function () {
      return pki.ct.getSth({ url: BASE, logKey: log.spki, transport: routeByUrl({ [u("get-sth")]: resp(200, "{not json", "application/json") }) });
    }) === "ct/bad-json");
  check("X4: an unknown option is refused rather than ignored",
    await code(function () {
      return pki.ct.getSth({ url: BASE, logKey: log.spki, transport: routeByUrl({}), nope: 1 });
    }) === "ct/bad-input");
  check("X5: a response past the cap is refused",
    await code(function () {
      return pki.ct.getSth({ url: BASE, logKey: log.spki, maxResponseBytes: 8,
        transport: routeByUrl({ [u("get-sth")]: resp(200, sthBody(log, 1, t.root), "application/json") }) });
    }) === "ct/response-too-large");
  check("X6: with no transport and no pinned TLS anchor the client refuses rather than trusting the system store",
    await code(function () { return pki.ct.getSth({ url: BASE, logKey: log.spki }); }) === "ct/no-trust-anchors");
  /* A base URL that already names the ct/v1 prefix is not doubled. */
  var f = opts(log, { [u("get-sth")]: resp(200, sthBody(log, 1, t.root), "application/json") });
  f.o.url = BASE + "ct/v1/";
  var sth = await pki.ct.getSth(f.o);
  check("X7: a base URL already carrying the ct/v1 prefix reaches the same path",
    sth.treeSize === 1n && f.transport.calls[0].url === u("get-sth"));

  /* The option the client CHECKED has to be the option it then USES. `opts.url` was read once for the
     presence check and again to build the endpoint, so an accessor answered the two separately: the
     check saw a URL the caller meant and the request went to another host entirely. The caller's bag
     is the caller's, and an object that answers differently on a second read is a value this code has
     no business trusting twice, so every declared option is taken once into a plain record and read
     from there. The assertion is on what crossed the seam, because that is the server contacted. */
  var EVIL = "https://attacker.example/";
  function readsDifferently(name, first, rest, base) {
    var n = 0, o = {};
    Object.keys(base).forEach(function (k) { o[k] = base[k]; });
    Object.defineProperty(o, name, {
      get: function () { n += 1; return n === 1 ? first : rest; },
      enumerable: true, configurable: true,
    });
    return o;
  }
  var divert = routeByUrl({ [u("get-sth")]: resp(200, sthBody(log, 1, t.root), "application/json") });
  var oDivert = readsDifferently("url", BASE, EVIL, { logKey: log.spki, transport: divert });
  var divertCode = await code(function () { return pki.ct.getSth(oDivert); });
  var contacted = divert.calls.map(function (c) { return c.url; });
  check("X8: an options bag whose url answers a second read differently is refused at the door " +
    "(outcome " + divertCode + ")", divertCode === "ct/bad-input");
  check("X8b: and the refusal happens before the wire, so no request is sent anywhere (contacted " +
    JSON.stringify(contacted) + ")", divert.calls.length === 0);

  /* The same door covers every option, so the anchor pin cannot be approved on one object and the
     socket opened under another. */
  var tlsT = routeByUrl({});
  var oTls = { url: BASE, logKey: log.spki, transport: tlsT };
  Object.defineProperty(oTls, "tls", {
    get: function () { return { anchors: [Buffer.alloc(1)] }; },
    enumerable: true, configurable: true,
  });
  check("X9: an accessor-backed tls is refused rather than read twice",
    (await code(function () { return pki.ct.getSth(oTls); })) === "ct/bad-input");
  check("X9b: and nothing was fetched under it", tlsT.calls.length === 0);

  /* A bag that gains or loses an option while the door reads it cannot be checked at all. */
  var shifty = { url: BASE, logKey: log.spki, transport: routeByUrl({}) };
  var hits = 0;
  Object.defineProperty(shifty, "timeout", {
    get: function () { hits += 1; if (hits === 1) { delete shifty.logKey; } return 1000; },
    enumerable: true, configurable: true,
  });
  check("X10: a bag that changes which options it carries while they are read is refused",
    (await code(function () { return pki.ct.getSth(shifty); })) === "ct/bad-input");

  /* Refusing an accessor ON THE BAG is not the whole rule, because the door is handed the caller's own
     object: a getter nested in one of the VALUES is never inspected by it, and a header name whose
     getter rewrote `url` as a side effect moved the request after the presence check had approved the
     original. The door copies the options it accepts, so nothing the caller does afterwards is visible.
     The control matters here: a plain header must still reach the URL the caller named, or the vector
     would pass for the wrong reason. */
  var plainT = routeByUrl({ [u("get-sth")]: resp(200, sthBody(log, 1, t.root), "application/json") });
  await code(function () {
    return pki.ct.getSth({ url: BASE, logKey: log.spki, transport: plainT, headers: { "x-a": "1" } });
  });
  check("X11 CONTROL: a plain header still reaches the URL the caller named",
    plainT.calls.length === 1 && plainT.calls[0].url === u("get-sth"));

  var nestedT = routeByUrl({ [u("get-sth")]: resp(200, sthBody(log, 1, t.root), "application/json") });
  var liveBag = { logKey: log.spki, transport: nestedT };
  liveBag.url = BASE;
  var trap = {};
  Object.defineProperty(trap, "x-trigger", {
    enumerable: true, configurable: true,
    get: function () { liveBag.url = EVIL; return "1"; },
  });
  liveBag.headers = trap;
  await code(function () { return pki.ct.getSth(liveBag); });
  var nestedHits = nestedT.calls.map(function (c) { return c.url; });
  check("X11: a getter nested in opts.headers cannot move the request off the checked URL by " +
    "rewriting the caller's bag mid-request (contacted " + JSON.stringify(nestedHits) + ")",
    nestedHits.every(function (hit) { return hit.indexOf("attacker.example") === -1; }));

  /* The trust anchors are the sharper case. `opts.tls` is the caller's object and its members were read
     later than the check that approves them, so a header getter emptied the pinned anchor list and
     rewrote the servername after the check had passed: the anchors checked were not the anchors the
     connection used. The settings are flattened once, with the anchor LIST copied, before any caller
     getter can run. The transport records what it was handed, because that is what a socket would use. */
  function tlsRecorder(seen) {
    return function (req) {
      var tls = req.tls || {};
      seen.push({ anchors: Array.isArray(tls.anchors) ? tls.anchors.length : null,
        servername: tls.servername });
      return Promise.resolve({ status: 500, headers: { "content-type": "application/json" }, body: Buffer.from("{}") });
    };
  }

  var pinOk = [];
  await code(function () {
    return pki.ct.getSth({ url: BASE, logKey: log.spki, transport: tlsRecorder(pinOk),
      tls: { anchors: [Buffer.alloc(1)], servername: "ct.example" }, headers: { "x-a": "1" } });
  });
  check("X12 CONTROL: a plain bag hands the connection the anchors the caller pinned (" +
    JSON.stringify(pinOk) + ")",
    pinOk.length === 1 && pinOk[0].anchors === 1 && pinOk[0].servername === "ct.example");

  var pinSeen = [];
  var sharedTls = { anchors: [Buffer.alloc(1)], servername: "ct.example" };
  var pinTrap = {};
  Object.defineProperty(pinTrap, "x-trigger", {
    enumerable: true, configurable: true,
    get: function () { sharedTls.anchors.length = 0; sharedTls.servername = EVIL; return "1"; },
  });
  await code(function () {
    return pki.ct.getSth({ url: BASE, logKey: log.spki, transport: tlsRecorder(pinSeen),
      tls: sharedTls, headers: pinTrap });
  });
  check("X12: a header getter cannot empty the pinned anchor list or rewrite the servername after " +
    "the trust-anchor check approved them (" + JSON.stringify(pinSeen) + ")",
    pinSeen.length === 1 && pinSeen[0].anchors === 1 && pinSeen[0].servername === "ct.example");

  /* An option supplied through a caller's defaults object is reached along the prototype chain, and the
     door has always accepted that. It is worth a vector because the obvious way to make the repeated
     reads safe, copying the bag, cannot reproduce it: the enumeration a copy would use omits an
     inherited FUNCTION member, since that is how `Object.prototype.toString` is kept from counting as an
     option. Copying therefore dropped an inherited `transport` and fell through to opening a real
     connection, which is the opposite of what the caller asked for. */
  var inheritedCalls = [];
  var inheritedBag = Object.create({
    url: BASE,
    transport: function (req) {
      inheritedCalls.push(String(req.url));
      return Promise.resolve({ status: 500, headers: { "content-type": "application/json" }, body: Buffer.from("{}") });
    },
  });
  inheritedBag.logKey = log.spki;
  await code(function () { return pki.ct.getRoots(inheritedBag); });
  check("X13: options supplied through a caller's defaults object are still used, the transport " +
    "among them, rather than being dropped in favor of a real connection (contacted " +
    JSON.stringify(inheritedCalls) + ")",
    inheritedCalls.length === 1 && inheritedCalls[0] === u("get-roots"));

  /* Holding the url VALUE is not enough when the value is an object, because the text form is what
     names the host and converting asks the object for it. A header getter that rewrote an
     object-valued url's `href` moved the request just as a second read would have: the conversion is
     the last reader, so it happens where the value is taken. */
  var convCalls = [];
  var urlObj = { href: BASE, toString: function () { return this.href; } };
  var convTrap = {};
  Object.defineProperty(convTrap, "x-trigger", {
    enumerable: true, configurable: true,
    get: function () { urlObj.href = EVIL; return "1"; },
  });
  await code(function () {
    return pki.ct.getSth({ url: urlObj, logKey: log.spki, headers: convTrap,
      transport: function (req) {
        convCalls.push(String(req.url));
        return Promise.resolve({ status: 500, headers: { "content-type": "application/json" }, body: Buffer.from("{}") });
      } });
  });
  check("X14: an object-valued url is converted where it is taken, so a header getter cannot change " +
    "the host by rewriting it later (contacted " + JSON.stringify(convCalls) + ")",
    convCalls.every(function (hit) { return hit.indexOf("attacker.example") === -1; }));
}

// Every refusal the shared readers make, and the RSA log-key arm. A guard that
// never runs is a guard nobody has checked.
async function runReaders() {
  var log = makeLog(), t = tree(3);
  var sth = { treeSize: 3n, timestamp: BigInt(TS), rootHash: t.root };

  /* An RSA log key, which RFC 6962 sec. 2.1.4 allows beside ECDSA. */
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaSpki = rsa.publicKey.export({ format: "der", type: "spki" });
  var rsaSig = crypto.sign("sha256", sthPreimage(TS, 3, t.root), rsa.privateKey);
  var rsaBody = JSON.stringify({ tree_size: 3, timestamp: TS, sha256_root_hash: t.root.toString("base64"),
    tree_head_signature: Buffer.concat([Buffer.from([4, 1, (rsaSig.length >> 8) & 0xff, rsaSig.length & 0xff]), rsaSig]).toString("base64") });
  var r = { url: BASE, logKey: rsaSpki, transport: routeByUrl({ [u("get-sth")]: resp(200, rsaBody, "application/json") }) };
  check("R1: a tree head signed by an RSA log key verifies",
    (await pki.ct.getSth(r)).treeSize === 3n);
  /* An algorithm the structure names that the key is not. */
  var mixed = { url: BASE, logKey: log.spki, transport: routeByUrl({ [u("get-sth")]: resp(200, rsaBody, "application/json") }) };
  check("R2: a structure declaring RSA against an EC log key is refused",
    await code(function () { return pki.ct.getSth(mixed); }) === "ct/bad-input");
  /* A hash algorithm outside the one the specification mandates. */
  var badHash = Buffer.concat([Buffer.from([2, 3, 0, 4]), Buffer.from([1, 2, 3, 4])]);
  var bh = { url: BASE, logKey: log.spki, transport: routeByUrl({ [u("get-sth")]: resp(200,
    JSON.stringify({ tree_size: 3, timestamp: TS, sha256_root_hash: t.root.toString("base64"),
      tree_head_signature: badHash.toString("base64") }), "application/json") }) };
  check("R3: a hash algorithm outside sha256 is refused",
    await code(function () { return pki.ct.getSth(bh); }) === "ct/unsupported-algorithm");
  /* A signature algorithm neither ecdsa nor rsa. */
  var anon = Buffer.concat([Buffer.from([4, 0, 0, 4]), Buffer.from([1, 2, 3, 4])]);
  var an = { url: BASE, logKey: log.spki, transport: routeByUrl({ [u("get-sth")]: resp(200,
    JSON.stringify({ tree_size: 3, timestamp: TS, sha256_root_hash: t.root.toString("base64"),
      tree_head_signature: anon.toString("base64") }), "application/json") }) };
  check("R4: a signature algorithm outside ecdsa and rsa is refused",
    await code(function () { return pki.ct.getSth(an); }) === "ct/unsupported-algorithm");

  /* A tree size stated as a decimal string, which protojson-style encoders emit. */
  var strSize = JSON.parse(sthBody(log, 3, t.root)); strSize.tree_size = "3";
  var ss = opts(log, { [u("get-sth")]: resp(200, JSON.stringify(strSize), "application/json") });
  check("R5: a tree size stated as a decimal string is read", (await pki.ct.getSth(ss.o)).treeSize === 3n);
  var badStr = JSON.parse(sthBody(log, 3, t.root)); badStr.tree_size = "03";
  var bs = opts(log, { [u("get-sth")]: resp(200, JSON.stringify(badStr), "application/json") });
  check("R6: a decimal string carrying a leading zero is refused",
    await code(function () { return pki.ct.getSth(bs.o); }) === "ct/bad-sth");

  /* A JSON body that is an array rather than an object. */
  var arr = opts(log, { [u("get-sth")]: resp(200, "[1,2]", "application/json") });
  check("R7: a response that is a JSON array is refused",
    await code(function () { return pki.ct.getSth(arr.o); }) === "ct/bad-json");

  /* A base URL with no trailing slash reaches the same path. */
  var noSlash = opts(log, { [u("get-sth")]: resp(200, sthBody(log, 3, t.root), "application/json") });
  noSlash.o.url = "https://ct.example";
  check("R8: a base URL without a trailing slash reaches the same path",
    (await pki.ct.getSth(noSlash.o)).treeSize === 3n &&
    noSlash.transport.calls[0].url === u("get-sth"));

  /* The proof and consistency readers' own refusals. */
  var shortHash = opts(log, {});
  check("R9: a leaf hash that is not 32 bytes is refused before the wire",
    await code(function () { return pki.ct.getProofByHash(Object.assign(shortHash.o, { leafHash: Buffer.alloc(31), sth: sth })); }) === "ct/bad-input" &&
    shortHash.transport.calls.length === 0);
  var shortRoot = opts(log, {});
  check("R10: a tree head whose root is not 32 bytes is refused",
    await code(function () { return pki.ct.getProofByHash(Object.assign(shortRoot.o, { leafHash: t.leaves[0], sth: { treeSize: 3n, rootHash: Buffer.alloc(31) } })); }) === "ct/bad-input");
  var pathNotArray = opts(log, { [u("get-proof-by-hash") + "?hash=" + encodeURIComponent(t.leaves[1].toString("base64")) + "&tree_size=3"]:
    resp(200, JSON.stringify({ leaf_index: 1, audit_path: "nope" }), "application/json") });
  check("R11: an audit path that is not an array is refused",
    await code(function () { return pki.ct.getProofByHash(Object.assign(pathNotArray.o, { leafHash: t.leaves[1], sth: sth })); }) === "ct/bad-proof");
  var pathBadNode = opts(log, { [u("get-proof-by-hash") + "?hash=" + encodeURIComponent(t.leaves[1].toString("base64")) + "&tree_size=3"]:
    resp(200, JSON.stringify({ leaf_index: 1, audit_path: [Buffer.alloc(31).toString("base64")] }), "application/json") });
  check("R12: an audit-path node that is not 32 bytes is refused",
    await code(function () { return pki.ct.getProofByHash(Object.assign(pathBadNode.o, { leafHash: t.leaves[1], sth: sth })); }) === "ct/bad-proof");
  var pathNonString = opts(log, { [u("get-proof-by-hash") + "?hash=" + encodeURIComponent(t.leaves[1].toString("base64")) + "&tree_size=3"]:
    resp(200, JSON.stringify({ leaf_index: 1, audit_path: [7] }), "application/json") });
  check("R13: an audit-path member that is not a string is refused",
    await code(function () { return pki.ct.getProofByHash(Object.assign(pathNonString.o, { leafHash: t.leaves[1], sth: sth })); }) === "ct/bad-proof");
  var tooManyNodes = [];
  for (var i = 0; i < 70; i++) tooManyNodes.push(Buffer.alloc(32).toString("base64"));
  var manyNodes = opts(log, { [u("get-proof-by-hash") + "?hash=" + encodeURIComponent(t.leaves[1].toString("base64")) + "&tree_size=3"]:
    resp(200, JSON.stringify({ leaf_index: 1, audit_path: tooManyNodes }), "application/json") });
  check("R14: an audit path longer than the proof-node cap is refused",
    await code(function () { return pki.ct.getProofByHash(Object.assign(manyNodes.o, { leafHash: t.leaves[1], sth: sth })); }) === "ct/bad-proof");
  var inverted = opts(log, {});
  check("R15: an older tree head larger than the newer is refused before the wire",
    await code(function () { return pki.ct.getSthConsistency(Object.assign(inverted.o, {
      oldSth: { treeSize: 5n, rootHash: t.root }, newSth: { treeSize: 3n, rootHash: t.root } })); }) === "ct/bad-input" &&
    inverted.transport.calls.length === 0);

  /* The entry reader's own refusals. */
  var notArr = opts(log, { [u("get-entries") + "?start=0&end=0"]: resp(200, JSON.stringify({ entries: "x" }), "application/json") });
  check("R16: an entries field that is not an array is refused",
    await code(function () { return pki.ct.getEntries(Object.assign(notArr.o, { start: 0, end: 0 })); }) === "ct/bad-entries");
  var notObj = opts(log, { [u("get-entries") + "?start=0&end=0"]: resp(200, JSON.stringify({ entries: [7] }), "application/json") });
  check("R17: an entry that is not an object is refused",
    await code(function () { return pki.ct.getEntries(Object.assign(notObj.o, { start: 0, end: 0 })); }) === "ct/bad-entries");
  var missing = opts(log, { [u("get-entries") + "?start=0&end=0"]: resp(200, JSON.stringify({ entries: [{ leaf_input: "AA" }] }), "application/json") });
  check("R18: an entry missing extra_data is refused",
    await code(function () { return pki.ct.getEntries(Object.assign(missing.o, { start: 0, end: 0 })); }) === "ct/bad-entries");
  var hugeRange = opts(log, {});
  check("R19: a range past the request cap is refused before the wire",
    await code(function () { return pki.ct.getEntries(Object.assign(hugeRange.o, { start: 0, end: 99999 })); }) === "ct/bad-input" &&
    hugeRange.transport.calls.length === 0);

  /* add-chain's own refusals. */
  var v2 = opts(log, { [u("add-chain")]: resp(200, JSON.stringify({ sct_version: 1 }), "application/json") });
  check("R20: an SCT of a version this build does not read is refused",
    await code(function () { return pki.ct.addChain(Object.assign(v2.o, { chain: [Buffer.from("c")] })); }) === "ct/bad-sct");
}

function testSurface() {
  ["sthSignedData", "verifySth", "getSth", "getProofByHash", "getSthConsistency", "getEntries",
    "getRoots", "addChain", "addPreChain"].forEach(function (n) {
    check("pki.ct." + n + " is exposed", typeof pki.ct[n] === "function");
  });
}

async function run() {
  testSurface();
  await runGetSth();
  await runGetProof();
  await runGetConsistency();
  await runGetEntriesRoots();
  await runAddChain();
  await runShared();
  await runReaders();
  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(helpers.formatErr(e)); process.exit(1); });
}
