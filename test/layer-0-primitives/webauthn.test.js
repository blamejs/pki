// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.webauthn: WebAuthn / passkey attestation trust evaluation.
 * KAT oracle: real attestation objects captured from duo-labs/py_webauthn (a
 * zero-external-dependency fixture -- test/fixtures/webauthn/py-webauthn-kat.json).
 * These drive the SHIPPED consumer path (pki.webauthn.parseAttestationObject /
 * .verify); the attestation CBOR is decoded by the strict pki.cbor codec, the
 * signature/chain by pki.webcrypto + pki.path.
 */

var pki = require("../../index.js");
var helpers = require("../helpers");
var check = helpers.check;
var crypto = require("crypto");
var fs = require("fs");
var path = require("path");

var KAT = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "webauthn", "py-webauthn-kat.json"), "utf8"));
function b64u(s) { var b = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (b.length % 4) b += "="; return Buffer.from(b, "base64"); }
function attObj(fmt) { return b64u(KAT.formats[fmt].attestationObject); }
function clientHash(fmt) { return crypto.createHash("sha256").update(b64u(KAT.formats[fmt].clientDataJSON)).digest(); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
async function codeOfAsync(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

// ---- minimal deterministic (canonical) CBOR encoder, for forging malformed
// attestation objects the strict pki.cbor decoder still accepts as well-formed ----
function cHead(major, n) {
  n = Number(n);
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) { var b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  var b4 = Buffer.alloc(5); b4[0] = (major << 5) | 26; b4.writeUInt32BE(n >>> 0, 1); return b4;
}
function cInt(n) { return n < 0 ? cHead(1, -1 - n) : cHead(0, n); }
function cBytes(buf) { return Buffer.concat([cHead(2, buf.length), buf]); }
function cText(s) { var x = Buffer.from(s, "utf8"); return Buffer.concat([cHead(3, x.length), x]); }
function cArr(items) { return Buffer.concat([cHead(4, items.length)].concat(items)); }
function cMap(pairs) {  // canonical: entries sorted by encoded-key bytes (RFC 8949 sec. 4.2.1)
  var e = pairs.slice().sort(function (a, b) { return Buffer.compare(a[0], b[0]); });
  var out = [cHead(5, pairs.length)];
  e.forEach(function (p) { out.push(p[0], p[1]); });
  return Buffer.concat(out);
}
// A COSE_Key EC2 map (kty 2) from a chosen set of entries -- callers build the exact
// (possibly malformed) key a vector needs; `cKV(label, valueBuf)` is one entry.
function cKV(label, valueBuf) { return [cInt(label), valueBuf]; }
function coseKey(entries) { return cMap(entries); }
// authenticatorData with a chosen flag set + attestedCredentialData (RFC WebAuthn 6.1).
function buildAuthData(o) {
  o = o || {};
  var flags = (o.at === false ? 0 : 0x40) | (o.ed ? 0x80 : 0) | 0x01;   // UP always
  var parts = [Buffer.concat([Buffer.alloc(32, 1), Buffer.from([flags]), Buffer.alloc(4)])];
  if (o.at !== false) {
    var credId = o.credId || Buffer.alloc(16, 3);
    var clen = Buffer.alloc(2); clen.writeUInt16BE(credId.length);
    parts.push(o.aaguid || Buffer.alloc(16, 2), clen, credId, o.coseKey);
  }
  if (o.trailing) parts.push(o.trailing);
  return Buffer.concat(parts);
}
function attObjOf(fmt, attStmtPairs, authData) {
  return cMap([[cText("fmt"), cText(fmt)], [cText("attStmt"), cMap(attStmtPairs)], [cText("authData"), cBytes(authData)]]);
}

async function run() {
  // --- parseAttestationObject: the structural entry over strict pki.cbor ---
  var p = pki.webauthn.parseAttestationObject(attObj("packed"));
  check("parse: fmt is 'packed'", p.fmt === "packed");
  check("parse: authData rpIdHash is 32 bytes", Buffer.isBuffer(p.authData.rpIdHash) && p.authData.rpIdHash.length === 32);
  check("parse: authData flags decoded (AT set for a registration)", p.authData.flags.at === true && typeof p.authData.flags.up === "boolean");
  check("parse: signCount is a number", typeof p.authData.signCount === "number");
  check("parse: attestedCredentialData present (aaguid 16 + credentialId + COSE key)",
    Buffer.isBuffer(p.authData.aaguid) && p.authData.aaguid.length === 16 &&
    Buffer.isBuffer(p.authData.credentialId) && p.authData.credentialPublicKey && typeof p.authData.credentialPublicKey === "object");
  check("parse: authDataBytes surfaced RAW (byte-identical, for the signed message)", Buffer.isBuffer(p.authDataBytes));

  // Every KAT format parses to its own fmt id.
  check("parse: tpm fmt", pki.webauthn.parseAttestationObject(attObj("tpm")).fmt === "tpm");
  check("parse: apple fmt", pki.webauthn.parseAttestationObject(attObj("apple")).fmt === "apple");
  check("parse: fido-u2f fmt", pki.webauthn.parseAttestationObject(attObj("fido_u2f")).fmt === "fido-u2f");
  check("parse: android-key fmt", pki.webauthn.parseAttestationObject(attObj("android_key")).fmt === "android-key");

  // COSE_Key: the credentialPublicKey decodes to a usable key (kty/alg/curve).
  check("parse: EC2 COSE key surfaces kty/alg/crv/x/y", (function () {
    var k = p.authData.credentialPublicKey;
    return k.kty != null && k.alg != null && (k.crv != null || k.n != null);
  })());

  // --- verify: the packed x5c attestation signature verifies over the KAT ---
  var v = await pki.webauthn.verify(attObj("packed"), clientHash("packed"), {});
  check("verify: packed KAT verifies (verified true)", v.verified === true);
  check("verify: packed reports fmt + attestation type + trust path", v.fmt === "packed" && typeof v.attestationType === "string" && Array.isArray(v.trustPath));
  check("verify: packed surfaces the aaguid + credentialPublicKey", Buffer.isBuffer(v.aaguid) && v.credentialPublicKey);

  // Every defined attestation format verifies structurally + cryptographically
  // over its real KAT: the signature (or nonce/name binding) + the public-key ==
  // credentialPublicKey checks all hold against captured authenticator output.
  for (var fmt of ["tpm", "apple", "fido_u2f", "android_key"]) {
    var res = await pki.webauthn.verify(attObj(fmt), clientHash(fmt), {});
    check("verify: " + fmt + " KAT verifies (verified true)", res.verified === true);
    check("verify: " + fmt + " reports its attestation type", typeof res.attestationType === "string" && res.attestationType.length > 0);
    check("verify: " + fmt + " surfaces a non-empty trust path", Array.isArray(res.trustPath) && res.trustPath.length >= 1);
  }

  // A tampered clientDataHash breaks every format's binding (signature or nonce).
  for (var bfmt of ["tpm", "apple", "fido_u2f", "android_key"]) {
    check("verify: " + bfmt + " with a wrong clientDataHash fails closed (typed webauthn/*)",
      /^webauthn\//.test(await codeOfAsync((function (f) { return function () { return pki.webauthn.verify(attObj(f), Buffer.alloc(32), {}); }; })(bfmt))));
  }

  // --- fail-closed negatives ---
  check("verify: a wrong clientDataHash fails the signature (typed, not a raw throw)",
    /^webauthn\//.test(await codeOfAsync(function () { return pki.webauthn.verify(attObj("packed"), Buffer.alloc(32), {}); })));
  check("parse: non-CBOR bytes -> webauthn/bad-attestation-object",
    codeOf(function () { pki.webauthn.parseAttestationObject(Buffer.from("not cbor")); }) === "webauthn/bad-attestation-object");
  check("parse: a truncated authData -> typed webauthn/* error", /^webauthn\//.test(codeOf(function () {
    // a valid attestation-object map whose authData is 10 bytes (< the 37-byte minimum)
    var b = pki.asn1; // reuse for nothing; build minimal CBOR by hand
    var cbor = Buffer.concat([
      Buffer.from("a3", "hex"),                                  // map(3)
      Buffer.from("63666d74", "hex"), Buffer.from("64", "hex"), Buffer.from("none", "latin1"),   // "fmt":"none"
      Buffer.from("67617474537461746d74", "hex"), Buffer.from("a0", "hex"),                        // "attStmt":{}
      Buffer.from("6861757468446174614a", "hex"), Buffer.alloc(10),                                // "authData":bytes(10)
    ]);
    void b; pki.webauthn.parseAttestationObject(cbor);
  })));

  // --- adversarial-audit conformance vectors (each RED on the pre-fix tree) ---
  // Real KAT material reused: the packed leaf (v3, non-CA, OU=Authenticator
  // Attestation), a CA certificate (tpm chain root, cA=true), the apple leaf
  // (OU != Authenticator Attestation), and a real registration authData.
  function x5cDer(fmt, idx) {
    var att = pki.webauthn.parseAttestationObject(attObj(fmt));
    var x5cN = null;
    for (var i = 0; i < att.attStmt.children.length; i++) { var k = att.attStmt.children[i][0]; if (k.majorType === 3 && pki.cbor.read.textString(k) === "x5c") x5cN = att.attStmt.children[i][1]; }
    return pki.cbor.read.byteString(x5cN.children[idx]);
  }
  var packedLeaf = x5cDer("packed", 0), caCert = x5cDer("tpm", 1), appleLeaf = x5cDer("apple", 0);
  var realAuthData = pki.webauthn.parseAttestationObject(attObj("packed")).authDataBytes;
  var credKey = pki.webauthn.parseAttestationObject(attObj("packed")).authData.credentialPublicKey;
  var packedHash = clientHash("packed");
  function packedWith(x5cList, sig, authData) {
    return attObjOf("packed", [[cText("alg"), cInt(-7)], [cText("sig"), cBytes(sig)], [cText("x5c"), cArr(x5cList.map(cBytes))]], authData);
  }

  // §8.2.1 -- a CA certificate MUST NOT be repurposed as the packed attestation leaf.
  check("verify: packed x5c leaf that is a CA cert -> webauthn/bad-att-cert",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([caCert], Buffer.alloc(8), realAuthData), packedHash); })) === "webauthn/bad-att-cert");
  // §8.2.1 -- the packed leaf subject OU MUST be "Authenticator Attestation".
  check("verify: packed x5c leaf missing OU=Authenticator Attestation -> webauthn/bad-att-cert",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([appleLeaf], Buffer.alloc(8), realAuthData), packedHash); })) === "webauthn/bad-att-cert");
  // A malformed DER ECDSA signature (constructed r/s) must fail typed, not raw-throw.
  check("verify: packed with a constructed-child ECDSA sig -> webauthn/bad-signature",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([packedLeaf], Buffer.from("3004300030 00".replace(/ /g, ""), "hex"), realAuthData), packedHash); })) === "webauthn/bad-signature");
  // §6.1 -- an AT-clear authenticatorData (no attestedCredentialData) must fail closed typed.
  check("verify: AT-clear authData -> webauthn/bad-auth-data",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("none", [], buildAuthData({ at: false })), packedHash); })) === "webauthn/bad-auth-data");
  // §6.1 -- trailing bytes after attestedCredentialData with the ED flag clear.
  check("parse: authData trailing bytes with ED clear -> webauthn/bad-auth-data",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], Buffer.concat([realAuthData, Buffer.from([0x00])]))); }) === "webauthn/bad-auth-data");
  // §6.5.1 / COSE sec. 7 -- the credential COSE key MUST carry alg (label 3).
  var ec2NoAlg = coseKey([cKV(1, cInt(2)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y))]);
  check("parse: COSE credential key missing alg (label 3) -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ec2NoAlg }))); }) === "webauthn/bad-cose-key");
  // §6.5.1 -- an incomplete EC2 key (alg present, y omitted) is rejected at decode.
  var ec2NoY = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x))]);
  check("parse: incomplete EC2 COSE key (no y) -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ec2NoY }))); }) === "webauthn/bad-cose-key");
  // §6.5.1 -- an unknown kty is rejected at decode, not surfaced as a materialess key.
  var unknownKty = coseKey([cKV(1, cInt(9)), cKV(3, cInt(-7))]);
  check("parse: unknown COSE key kty -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: unknownKty }))); }) === "webauthn/bad-cose-key");
  // §8.7 -- the none format verifies with no statement (attestationType "None").
  var noneRes = await pki.webauthn.verify(attObjOf("none", [], realAuthData), packedHash);
  check("verify: none attestation verifies (attestationType None, empty trust path)",
    noneRes.verified === true && noneRes.attestationType === "None" && noneRes.trustPath.length === 0);
  // §8.7 -- a non-empty none attStmt is rejected.
  check("verify: none attestation with a non-empty attStmt -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("none", [[cText("x"), cInt(1)]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  // §8.7 -- a none attStmt that is not a map at all (here a uint) is rejected.
  check("verify: none attestation with a non-map attStmt -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(cMap([[cText("fmt"), cText("none")], [cText("attStmt"), cInt(5)], [cText("authData"), cBytes(realAuthData)]]), packedHash); })) === "webauthn/bad-att-stmt");
  // A DER-negative ECDSA signature integer is not a valid coordinate.
  check("verify: packed with a negative ECDSA signature integer -> webauthn/bad-signature",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([packedLeaf], Buffer.from("3006020180020101", "hex"), realAuthData), packedHash); })) === "webauthn/bad-signature");
  // §8.6 -- fido-u2f x5c MUST contain exactly one certificate.
  check("verify: fido-u2f x5c with two certificates -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("fido-u2f", [[cText("sig"), cBytes(Buffer.alloc(8))], [cText("x5c"), cArr([packedLeaf, appleLeaf].map(cBytes))]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  // §8.2 self-attestation -- the statement alg MUST match the credential key's alg.
  check("verify: packed self-attestation alg != credential key alg -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("packed", [[cText("alg"), cInt(-35)], [cText("sig"), cBytes(Buffer.alloc(8))]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
