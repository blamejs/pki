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
// The W3C WebAuthn Level 3 official test-vector suite (spec sec. Test Vectors): every
// defined format + algorithm, incl. ES384/ES512, Ed25519 (-8) and Ed448 (fully-specified
// -53). clientDataHash = SHA-256(clientDataJSON).
var SPEC = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "webauthn", "webauthn-l3-spec-kat.json"), "utf8"));
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
  var flags = (o.at === false ? 0 : 0x40) | (o.ed ? 0x80 : 0) | (o.bs ? 0x10 : 0) | (o.be ? 0x08 : 0) | (o.rfu ? 0x02 : 0) | 0x01;   // UP always
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
  // trustPath is in pki.path.validate order (anchor-adjacent first, leaf last): the
  // tpm x5c is [AIK(empty subject), root], so the reversed trustPath ends with the
  // empty-subject AIK leaf.
  var tpmRes = await pki.webauthn.verify(attObj("tpm"), clientHash("tpm"), {});
  check("verify: tpm trustPath is anchor->leaf ordered (leaf/AIK last)",
    tpmRes.trustPath.length === 2 && tpmRes.trustPath[tpmRes.trustPath.length - 1].subject.rdns.length === 0 && tpmRes.trustPath[0].subject.rdns.length > 0);

  // A tpm attestation signed under a fully-specified ECDSA alg (RFC 9864 ESP256 = -9) must
  // reach the certInfo.extraData digest step: -9 needs a COSE_ALG_HASH mapping, or it is
  // wrongly rejected as webauthn/unsupported-algorithm before the signature is evaluated.
  // Rebuild the tpm KAT with alg -9 (its sig/certInfo no longer correspond, so it fails at
  // extraData -- but NOT as unsupported-algorithm, which is the regression this pins).
  var tpmDec = pki.cbor.decode(attObj("tpm"));
  var _ck = function (node, key) { for (var i = 0; i < node.children.length; i++) { var k = node.children[i][0]; if (k.majorType === 3 && pki.cbor.read.textString(k) === key) return node.children[i][1]; } return null; };
  var tpmAs = _ck(tpmDec, "attStmt");
  var tpmAlg9 = attObjOf("tpm", [
    [cText("ver"), cText("2.0")],
    [cText("alg"), cInt(-9)],
    [cText("sig"), cBytes(pki.cbor.read.byteString(_ck(tpmAs, "sig")))],
    [cText("certInfo"), cBytes(pki.cbor.read.byteString(_ck(tpmAs, "certInfo")))],
    [cText("pubArea"), cBytes(pki.cbor.read.byteString(_ck(tpmAs, "pubArea")))],
    [cText("x5c"), cArr(_ck(tpmAs, "x5c").children.map(function (c) { return cBytes(pki.cbor.read.byteString(c)); }))],
  ], pki.cbor.read.byteString(_ck(tpmDec, "authData")));
  var tpmCode9 = await codeOfAsync(function () { return pki.webauthn.verify(tpmAlg9, clientHash("tpm"), {}); });
  check("verify: a fully-specified ECDSA alg (-9) in a tpm attestation reaches the extraData step (not unsupported-algorithm)",
    tpmCode9 !== "webauthn/unsupported-algorithm" && /^webauthn\//.test(tpmCode9));

  // --- W3C WebAuthn Level 3 official test vectors ---------------------------------
  // Every spec-published vector verifies to its expected format + attestation type +
  // credential-key algorithm. This is the authoritative cross-implementation oracle:
  // it proves the full ES256/ES384/ES512/RS256/Ed25519 set AND Ed448 (fully-specified
  // COSE alg -53, the only WebAuthn path to Ed448) verify end-to-end over a real signature.
  for (var sv of SPEC.pass) {
    var cdh = crypto.createHash("sha256").update(Buffer.from(sv.clientDataJSON, "hex")).digest();
    var sr = await pki.webauthn.verify(Buffer.from(sv.attestationObject, "hex"), cdh, {});
    check("spec KAT: " + sv.name + " verifies (" + sv.expect.fmt + "/" + sv.expect.attestationType + "/alg " + sv.expect.alg + ")",
      sr.verified === true && sr.fmt === sv.expect.fmt && sr.attestationType === sv.expect.attestationType &&
      sr.credentialPublicKey.alg === sv.expect.alg);
  }
  // The spec's android-key vector carries EMPTY authorization lists, so it does not
  // satisfy WebAuthn 8.4.1's origin==GENERATED / purpose==SIGN MUSTs: a structural /
  // signature vector, correctly rejected by the full verifier (fail-closed, typed).
  for (var nv of SPEC.negative) {
    check("spec KAT (negative): " + nv.name + " -> " + nv.expectCode,
      (await codeOfAsync((function (o, c) { return function () { return pki.webauthn.verify(Buffer.from(o, "hex"), Buffer.from(c, "hex").length ? crypto.createHash("sha256").update(Buffer.from(c, "hex")).digest() : Buffer.alloc(32), {}); }; })(nv.attestationObject, nv.clientDataJSON))) === nv.expectCode);
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
  var packedLeaf = x5cDer("packed", 0), caCert = x5cDer("tpm", 1), appleLeaf = x5cDer("apple", 0), androidLeaf = x5cDer("android_key", 0), tpmAik = x5cDer("tpm", 0);
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
  // §8.2.1 -- the packed leaf MUST carry a basicConstraints extension (the android
  // leaf omits it), so an attestation leaf without one is rejected.
  check("verify: packed x5c leaf with no basicConstraints -> webauthn/bad-att-cert",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([androidLeaf], Buffer.alloc(8), realAuthData), packedHash); })) === "webauthn/bad-att-cert");
  // An all-zeroes Ed25519 attestation-cert key MUST NOT pass statement-signature
  // verification: node/OpenSSL imports it and verifies a trivial (all-zero) signature, so a
  // packed Ed attestation could otherwise pass without the attestation private key. The OKP
  // point is validated (RFC 8032 decode + cofactor) before verify, for the CERT key too.
  var _B = pki.asn1.build;
  function _atv(o, v) { return _B.set([_B.sequence([_B.oid(pki.oid.byName(o)), _B.utf8(v)])]); }
  function _dn(cn) { return _B.sequence([_atv("countryName", "US"), _atv("organizationName", "WA Test"), _atv("organizationalUnitName", "Authenticator Attestation"), _atv("commonName", cn)]); }
  var edZeroCert = _B.sequence([
    _B.sequence([_B.explicit(0, _B.integer(2n)), _B.integer(0x1234n), _B.sequence([_B.oid(pki.oid.byName("Ed25519"))]), _dn("I"),
      _B.sequence([_B.utcTime(new Date("2024-01-01T00:00:00Z")), _B.utcTime(new Date("2030-01-01T00:00:00Z"))]), _dn("L"),
      _B.sequence([_B.sequence([_B.oid(pki.oid.byName("Ed25519"))]), _B.bitString(Buffer.alloc(32))]),
      _B.explicit(3, _B.sequence([_B.sequence([_B.oid(pki.oid.byName("basicConstraints")), _B.boolean(true), _B.octetString(_B.sequence([]))])]))]),
    _B.sequence([_B.oid(pki.oid.byName("Ed25519"))]), _B.bitString(Buffer.alloc(64)),
  ]);
  var edZeroAtt = attObjOf("packed", [[cText("alg"), cInt(-8)], [cText("sig"), cBytes(Buffer.alloc(64))], [cText("x5c"), cArr([edZeroCert].map(cBytes))]], realAuthData);
  check("verify: packed x5c with an all-zeroes Ed25519 attestation-cert key -> webauthn/bad-signature",
    (await codeOfAsync(function () { return pki.webauthn.verify(edZeroAtt, packedHash); })) === "webauthn/bad-signature");
  // WebAuthn 8.6 -- a fido-u2f credential public key MUST be alg -7 (ES256); an ESP256 (-9)
  // key, though the same P-256 curve, is not a valid fido-u2f credential.
  var u2fEsp256 = attObjOf("fido-u2f", [[cText("sig"), cBytes(Buffer.alloc(8))], [cText("x5c"), cArr([x5cDer("fido_u2f", 0)].map(cBytes))]],
    buildAuthData({ coseKey: coseKey([cKV(1, cInt(2)), cKV(3, cInt(-9)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y))]) }));
  check("verify: fido-u2f with an ESP256 (-9) credential key -> webauthn/bad-att-stmt (must be -7)",
    (await codeOfAsync(function () { return pki.webauthn.verify(u2fEsp256, Buffer.alloc(32)); })) === "webauthn/bad-att-stmt");
  // §8.2.1 -- the packed leaf subject MUST set C/O/OU/CN (the tpm AIK is v3 + non-CA
  // but has an empty subject), so a leaf missing those fields is rejected.
  check("verify: packed x5c leaf with an empty subject (no C/O/CN) -> webauthn/bad-att-cert",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([tpmAik], Buffer.alloc(8), realAuthData), packedHash); })) === "webauthn/bad-att-cert");
  // §8.2 -- a packed attStmt carrying a field outside its canonical {alg,sig,x5c} set is rejected.
  check("verify: packed attStmt with an unexpected field -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("packed", [[cText("alg"), cInt(-7)], [cText("sig"), cBytes(Buffer.alloc(8))], [cText("x5c"), cArr([packedLeaf].map(cBytes))], [cText("zz"), cInt(1)]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  // §8.2 -- an attStmt with a non-text-string field key is rejected (not silently skipped).
  check("verify: packed attStmt with an integer key -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("packed", [[cInt(5), cInt(1)], [cText("alg"), cInt(-7)], [cText("sig"), cBytes(Buffer.alloc(8))], [cText("x5c"), cArr([packedLeaf].map(cBytes))]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  // A malformed DER ECDSA signature (constructed r/s) must fail typed, not raw-throw.
  check("verify: packed with a constructed-child ECDSA sig -> webauthn/bad-signature",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([packedLeaf], Buffer.from("3004300030 00".replace(/ /g, ""), "hex"), realAuthData), packedHash); })) === "webauthn/bad-signature");
  // §6.1 -- an AT-clear authenticatorData (no attestedCredentialData) must fail closed typed.
  check("verify: AT-clear authData -> webauthn/bad-auth-data",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("none", [], buildAuthData({ at: false })), packedHash); })) === "webauthn/bad-auth-data");
  // §6.1 -- trailing bytes after attestedCredentialData with the ED flag clear.
  check("parse: authData trailing bytes with ED clear -> webauthn/bad-auth-data",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], Buffer.concat([realAuthData, Buffer.from([0x00])]))); }) === "webauthn/bad-auth-data");
  // §6.1 -- Backup State (BS) set without Backup Eligibility (BE) is an invalid flag combination.
  check("parse: authData BS set without BE -> webauthn/bad-auth-data",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ bs: true, be: false, coseKey: coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y))]) }))); }) === "webauthn/bad-auth-data");
  // §6.1 -- a set reserved (RFU) flag bit is rejected.
  check("parse: authData with a reserved flag bit set -> webauthn/bad-auth-data",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ rfu: true, coseKey: coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y))]) }))); }) === "webauthn/bad-auth-data");
  // §6.1 -- the ED flag set with no (or malformed) extensions map is rejected.
  check("parse: ED flag set with no extensions map -> webauthn/bad-auth-data",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ ed: true, coseKey: coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y))]) }))); }) === "webauthn/bad-auth-data");
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
  // §6.5.1 -- a wrong-typed COSE label (x as an integer, kty as text) is a typed
  // webauthn/bad-cose-key, not a leaked cbor/* codec fault.
  var ec2IntX = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cInt(99)), cKV(-3, cBytes(credKey.y))]);
  check("parse: EC2 key with x as an integer -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ec2IntX }))); }) === "webauthn/bad-cose-key");
  var ktyText = coseKey([cKV(1, cText("two")), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y))]);
  check("parse: COSE key with a non-integer kty -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ktyText }))); }) === "webauthn/bad-cose-key");
  // WebAuthn alg identifier / RFC 9864 -- Ed448 is the fully-specified alg -53 (OKP crv 7,
  // 57-byte x); it is the ONLY WebAuthn path to Ed448 (-8 is Ed25519 only). A real Ed448
  // point is required: the OKP on-curve + full-order check rejects a bogus 57-byte string.
  var realEd448X = Buffer.from(crypto.generateKeyPairSync("ed448").publicKey.export({ format: "jwk" }).x, "base64url");
  var ed448 = coseKey([cKV(1, cInt(1)), cKV(3, cInt(-53)), cKV(-1, cInt(7)), cKV(-2, cBytes(realEd448X))]);
  var ed448Parsed = pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ed448 })));
  check("parse: Ed448 (fully-specified alg -53, OKP crv 7, real point) credential key accepted",
    ed448Parsed.authData.credentialPublicKey.kty === 1 && ed448Parsed.authData.credentialPublicKey.crv === 7 && ed448Parsed.authData.credentialPublicKey.alg === -53);
  // OKP ON-CURVE: an OKP credential key whose point is not a valid, full-order Edwards point
  // (e.g. the all-zeroes low-order point, which node/OpenSSL imports and would even verify a
  // trivial signature) is rejected -- RFC 8032 decode + the cofactor check.
  var okpZero25519 = coseKey([cKV(1, cInt(1)), cKV(3, cInt(-8)), cKV(-1, cInt(6)), cKV(-2, cBytes(Buffer.alloc(32)))]);
  check("parse: all-zeroes Ed25519 OKP credential key -> webauthn/bad-cose-key (low-order point)",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: okpZero25519 }))); }) === "webauthn/bad-cose-key");
  var okpZero448 = coseKey([cKV(1, cInt(1)), cKV(3, cInt(-53)), cKV(-1, cInt(7)), cKV(-2, cBytes(Buffer.alloc(57)))]);
  check("parse: all-zeroes Ed448 OKP credential key -> webauthn/bad-cose-key (off-curve/low-order)",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: okpZero448 }))); }) === "webauthn/bad-cose-key");
  // an OKP key whose x length does not match its curve is rejected.
  var ed448Bad = coseKey([cKV(1, cInt(1)), cKV(3, cInt(-53)), cKV(-1, cInt(7)), cKV(-2, cBytes(Buffer.alloc(32, 7)))]);
  check("parse: OKP crv 7 with a 32-byte x -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ed448Bad }))); }) === "webauthn/bad-cose-key");
  // WebAuthn alg identifier -- alg -8 (EdDSA) MUST specify crv 6 (Ed25519); an -8 key
  // claiming crv 7 (Ed448) is a profile violation (Ed448 must use -53).
  var eddsaCrv7 = coseKey([cKV(1, cInt(1)), cKV(3, cInt(-8)), cKV(-1, cInt(7)), cKV(-2, cBytes(Buffer.alloc(57, 7)))]);
  check("parse: alg -8 with crv 7 (Ed448) -> webauthn/bad-cose-key (must be Ed25519)",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: eddsaCrv7 }))); }) === "webauthn/bad-cose-key");
  // ON-CURVE (WebAuthn sec. alg identifier) -- an EC2 credential key whose point is not
  // on its curve is rejected: the SPKI fails to import (OpenSSL validates the point).
  var offY = Buffer.from(credKey.y); offY[10] = offY[10] ^ 0xff;
  var ec2OffCurve = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(offY))]);
  check("parse: off-curve EC2 credential key -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ec2OffCurve }))); }) === "webauthn/bad-cose-key");
  // COMPRESSED (WebAuthn sec. alg identifier) -- an EC2 key with a boolean (sign-bit) y is
  // the compressed point form, forbidden for WebAuthn credential keys (CBOR true = 0xf5).
  var ec2Compressed = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, Buffer.from([0xf5]))]);
  check("parse: EC2 credential key with a compressed (boolean) y -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ec2Compressed }))); }) === "webauthn/bad-cose-key");
  // §6.5.1 -- a credential key with an extra (non-canonical) parameter is rejected.
  var ec2Extra = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y)), cKV(4, cInt(1))]);
  check("parse: EC2 key with an extra parameter -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ec2Extra }))); }) === "webauthn/bad-cose-key");
  // §6.5.1 -- the COSE profile: an EC2 key declaring an EdDSA alg is inconsistent.
  var ec2WrongAlg = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-8)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y))]);
  check("parse: EC2 key with an EdDSA alg (profile mismatch) -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ec2WrongAlg }))); }) === "webauthn/bad-cose-key");
  // A malformed attStmt field (alg not an integer) is a webauthn/bad-att-stmt, not a leaked cbor/*.
  check("verify: packed attStmt alg not an integer -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("packed", [[cText("alg"), cText("nope")], [cText("sig"), cBytes(Buffer.alloc(8))], [cText("x5c"), cArr([packedLeaf].map(cBytes))]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  // §6.5.1 -- an EC2 P-256 (crv 1) key whose x/y are not 32 bytes is malformed.
  var ec2ShortX = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(Buffer.alloc(5))), cKV(-3, cBytes(credKey.y))]);
  check("parse: EC2 P-256 key with a wrong-length x -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: ec2ShortX }))); }) === "webauthn/bad-cose-key");
  // §8.3 -- a tpm certInfo with trailing bytes past the attested structure is rejected.
  check("verify: tpm certInfo with trailing bytes -> webauthn/bad-tpm", (await codeOfAsync(function () {
    var att = pki.webauthn.parseAttestationObject(attObj("tpm"));
    function fld(k) { for (var i = 0; i < att.attStmt.children.length; i++) { var kv = att.attStmt.children[i]; if (pki.cbor.read.textString(kv[0]) === k) return kv[1]; } return null; }
    var x5c = fld("x5c").children.map(function (c) { return pki.cbor.read.byteString(c); });
    var attStmt = [
      [cText("ver"), cText(pki.cbor.read.textString(fld("ver")))],
      [cText("alg"), cInt(Number(pki.cbor.read.int(fld("alg"))))],
      [cText("sig"), cBytes(pki.cbor.read.byteString(fld("sig")))],
      [cText("certInfo"), cBytes(Buffer.concat([pki.cbor.read.byteString(fld("certInfo")), Buffer.from([0x00])]))],
      [cText("pubArea"), cBytes(pki.cbor.read.byteString(fld("pubArea")))],
      [cText("x5c"), cArr(x5c.map(cBytes))],
    ];
    return pki.webauthn.verify(attObjOf("tpm", attStmt, att.authDataBytes), clientHash("tpm"));
  })) === "webauthn/bad-tpm");
  // A zero-valued ECDSA signature integer is not a positive coordinate.
  check("verify: packed with a zero ECDSA signature integer -> webauthn/bad-signature",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([packedLeaf], Buffer.from("3006020100020101", "hex"), realAuthData), packedHash); })) === "webauthn/bad-signature");
  // §8.3 -- a tpm pubArea with trailing bytes past the unique field is rejected.
  check("verify: tpm pubArea with trailing bytes -> webauthn/bad-tpm", (await codeOfAsync(function () {
    var att = pki.webauthn.parseAttestationObject(attObj("tpm"));
    function fld(k) { for (var i = 0; i < att.attStmt.children.length; i++) { var kv = att.attStmt.children[i]; if (pki.cbor.read.textString(kv[0]) === k) return kv[1]; } return null; }
    var x5c = fld("x5c").children.map(function (c) { return pki.cbor.read.byteString(c); });
    var attStmt = [
      [cText("ver"), cText(pki.cbor.read.textString(fld("ver")))],
      [cText("alg"), cInt(Number(pki.cbor.read.int(fld("alg"))))],
      [cText("sig"), cBytes(pki.cbor.read.byteString(fld("sig")))],
      [cText("certInfo"), cBytes(pki.cbor.read.byteString(fld("certInfo")))],
      [cText("pubArea"), cBytes(Buffer.concat([pki.cbor.read.byteString(fld("pubArea")), Buffer.from([0x00])]))],
      [cText("x5c"), cArr(x5c.map(cBytes))],
    ];
    return pki.webauthn.verify(attObjOf("tpm", attStmt, att.authDataBytes), clientHash("tpm"));
  })) === "webauthn/bad-tpm");
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
  // §6.5.4 -- an attestation object with an extra top-level key (non-canonical envelope) is rejected.
  check("parse: attestation object with an extra top-level key -> webauthn/bad-attestation-object",
    codeOf(function () { pki.webauthn.parseAttestationObject(cMap([[cText("fmt"), cText("none")], [cText("attStmt"), cMap([])], [cText("authData"), cBytes(realAuthData)], [cText("zextra"), cInt(1)]])); }) === "webauthn/bad-attestation-object");
  // A DER-negative ECDSA signature integer is not a valid coordinate.
  check("verify: packed with a negative ECDSA signature integer -> webauthn/bad-signature",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([packedLeaf], Buffer.from("3006020180020101", "hex"), realAuthData), packedHash); })) === "webauthn/bad-signature");
  // §8.6 -- fido-u2f x5c MUST contain exactly one certificate.
  check("verify: fido-u2f x5c with two certificates -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("fido-u2f", [[cText("sig"), cBytes(Buffer.alloc(8))], [cText("x5c"), cArr([packedLeaf, appleLeaf].map(cBytes))]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  // §8.2 self-attestation -- the statement alg MUST match the credential key's alg.
  check("verify: packed self-attestation alg != credential key alg -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("packed", [[cText("alg"), cInt(-35)], [cText("sig"), cBytes(Buffer.alloc(8))]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");

  // ---- entry-point + envelope edge cases (verify / parseAttestationObject) --------
  // verify: clientDataHash MUST be a 32-byte SHA-256 digest (config-time reject).
  check("verify: a clientDataHash that is not 32 bytes -> webauthn/bad-input",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObj("packed"), Buffer.alloc(31)); })) === "webauthn/bad-input");
  check("verify: a clientDataHash that is not a Buffer -> webauthn/bad-input",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObj("packed"), "not-a-buffer"); })) === "webauthn/bad-input");
  // verify: a malformed attestationObject surfaces the parse error as a rejection.
  check("verify: a non-CBOR attestationObject -> webauthn/bad-attestation-object",
    (await codeOfAsync(function () { return pki.webauthn.verify(Buffer.from("not cbor"), Buffer.alloc(32)); })) === "webauthn/bad-attestation-object");
  // verify: an unknown fmt with valid attestedCredentialData -> unsupported-format.
  check("verify: an unsupported attestation format -> webauthn/unsupported-format",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("no-such-fmt", [], realAuthData), packedHash); })) === "webauthn/unsupported-format");
  // sec. 6.5.4 -- the attestation object MUST be a CBOR map.
  check("parse: an attestation object that is not a CBOR map -> webauthn/bad-attestation-object",
    codeOf(function () { pki.webauthn.parseAttestationObject(cInt(5)); }) === "webauthn/bad-attestation-object");
  // sec. 6.5.4 -- fmt MUST be a text string; authData MUST be a byte string.
  check("parse: attestation object fmt that is not a text string -> webauthn/bad-attestation-object",
    codeOf(function () { pki.webauthn.parseAttestationObject(cMap([[cText("fmt"), cInt(5)], [cText("attStmt"), cMap([])], [cText("authData"), cBytes(realAuthData)]])); }) === "webauthn/bad-attestation-object");
  check("parse: attestation object authData that is not a byte string -> webauthn/bad-attestation-object",
    codeOf(function () { pki.webauthn.parseAttestationObject(cMap([[cText("fmt"), cText("none")], [cText("attStmt"), cMap([])], [cText("authData"), cInt(5)]])); }) === "webauthn/bad-attestation-object");

  // ---- authenticatorData bounded reader (WebAuthn sec. 6.1) ----------------------
  // AT flag set but the buffer ends before the aaguid + credentialId length.
  check("parse: AT-set authData truncated before the credentialId length -> webauthn/bad-auth-data",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], Buffer.concat([Buffer.alloc(32, 1), Buffer.from([0x41]), Buffer.alloc(4)]))); }) === "webauthn/bad-auth-data");
  // credentialIdLength MUST be 1..1023 (a zero length is rejected).
  check("parse: attestedCredentialData with a zero credentialId length -> webauthn/bad-credential-id",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], Buffer.concat([Buffer.alloc(32, 1), Buffer.from([0x41]), Buffer.alloc(4), Buffer.alloc(16, 2), Buffer.from([0, 0])]))); }) === "webauthn/bad-credential-id");
  // a credentialId length that runs past the end of authenticatorData.
  var _clen100 = Buffer.alloc(2); _clen100.writeUInt16BE(100);
  check("parse: credentialId length overruns authenticatorData -> webauthn/bad-auth-data",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], Buffer.concat([Buffer.alloc(32, 1), Buffer.from([0x41]), Buffer.alloc(4), Buffer.alloc(16, 2), _clen100, Buffer.alloc(3)]))); }) === "webauthn/bad-auth-data");
  // the credentialPublicKey slice is not well-formed CBOR.
  check("parse: a malformed COSE credential public key -> webauthn/bad-cose-key",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ coseKey: Buffer.from([0x9f]) }))); }) === "webauthn/bad-cose-key");
  // with the ED flag set the extensions remainder MUST be a single CBOR map (not a uint).
  var _validEc2 = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y))]);
  check("parse: ED flag set with a non-map extensions item -> webauthn/bad-auth-data",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ ed: true, coseKey: _validEc2, trailing: Buffer.from([0x05]) }))); }) === "webauthn/bad-auth-data");

  // ---- attStmt shape + x5c reader --------------------------------------------------
  function packedAlg(alg, sig, x5cList) { return attObjOf("packed", [[cText("alg"), cInt(alg)], [cText("sig"), cBytes(sig)], [cText("x5c"), cArr(x5cList.map(cBytes))]], realAuthData); }
  // an attStmt that is not a CBOR map fails the canonical-shape check, not silently.
  check("verify: packed attStmt that is not a CBOR map -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(cMap([[cText("fmt"), cText("packed")], [cText("attStmt"), cInt(5)], [cText("authData"), cBytes(realAuthData)]]), packedHash); })) === "webauthn/bad-att-stmt");
  // x5c MUST be a non-empty array of byte-string certificates.
  check("verify: packed x5c that is an empty array -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("packed", [[cText("alg"), cInt(-7)], [cText("sig"), cBytes(Buffer.alloc(8))], [cText("x5c"), cArr([])]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  check("verify: packed x5c entry that is not a byte string -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("packed", [[cText("alg"), cInt(-7)], [cText("sig"), cBytes(Buffer.alloc(8))], [cText("x5c"), cArr([cInt(5)])]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  check("verify: packed x5c entry that is not a well-formed certificate -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedWith([Buffer.from([1, 2, 3])], Buffer.alloc(8), realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  // an alg outside the COSE registry is refused before any signature is evaluated.
  check("verify: an unsupported COSE algorithm in a packed x5c statement -> webauthn/unsupported-algorithm",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedAlg(-999, Buffer.alloc(8), [packedLeaf]), packedHash); })) === "webauthn/unsupported-algorithm");
  // alg -8 (EdDSA) with a non-EdDSA (EC) leaf key: the SPKI curve OID is not an OKP curve.
  check("verify: packed alg -8 with a non-EdDSA (EC) x5c leaf -> webauthn/unsupported-algorithm",
    (await codeOfAsync(function () { return pki.webauthn.verify(packedAlg(-8, Buffer.alloc(64), [packedLeaf]), packedHash); })) === "webauthn/unsupported-algorithm");
  // packed self-attestation whose signature does not verify under the credential key.
  check("verify: packed self-attestation with a non-verifying signature -> webauthn/verify-failed",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("packed", [[cText("alg"), cInt(-7)], [cText("sig"), cBytes(_B.sequence([_B.integer(1n), _B.integer(1n)]))]], realAuthData), packedHash); })) === "webauthn/verify-failed");

  // ---- tpm statement (WebAuthn 8.3) -----------------------------------------------
  // Rebuild the real tpm KAT with a single overridden field (ver / alg / sig).
  function tpmField(k) { var att = pki.webauthn.parseAttestationObject(attObj("tpm")); for (var i = 0; i < att.attStmt.children.length; i++) { var kv = att.attStmt.children[i]; if (pki.cbor.read.textString(kv[0]) === k) return kv[1]; } return null; }
  function tpmRebuild(over) {
    over = over || {};
    var att = pki.webauthn.parseAttestationObject(attObj("tpm"));
    var x5c = tpmField("x5c").children.map(function (c) { return pki.cbor.read.byteString(c); });
    return attObjOf("tpm", [
      [cText("ver"), cText(over.ver != null ? over.ver : "2.0")],
      [cText("alg"), cInt(over.alg != null ? over.alg : Number(pki.cbor.read.int(tpmField("alg"))))],
      [cText("sig"), cBytes(over.sig != null ? over.sig : pki.cbor.read.byteString(tpmField("sig")))],
      [cText("certInfo"), cBytes(pki.cbor.read.byteString(tpmField("certInfo")))],
      [cText("pubArea"), cBytes(pki.cbor.read.byteString(tpmField("pubArea")))],
      [cText("x5c"), cArr(x5c.map(cBytes))],
    ], att.authDataBytes);
  }
  // tpm 'ver' MUST be "2.0".
  check("verify: tpm attestation with ver != 2.0 -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(tpmRebuild({ ver: "1.0" }), clientHash("tpm")); })) === "webauthn/bad-att-stmt");
  // a TPM AIK never signs with EdDSA: alg -8 has no certInfo.extraData hash mapping, so
  // the extraData step refuses it as unsupported-algorithm (fail-closed, before the sig).
  check("verify: tpm attestation under an EdDSA alg (-8, no TPM hash) -> webauthn/unsupported-algorithm",
    (await codeOfAsync(function () { return pki.webauthn.verify(tpmRebuild({ alg: -8 }), clientHash("tpm")); })) === "webauthn/unsupported-algorithm");
  // the extraData + Name bindings still hold (real certInfo/pubArea) but the AIK signature
  // is replaced with zeroes: the statement fails at the signature, a false verdict.
  check("verify: tpm attestation with a non-verifying certInfo signature -> webauthn/verify-failed",
    (await codeOfAsync(function () { return pki.webauthn.verify(tpmRebuild({ sig: Buffer.alloc(pki.cbor.read.byteString(tpmField("sig")).length, 0) }), clientHash("tpm")); })) === "webauthn/verify-failed");

  // ---- apple statement: extension decode + certificate-key == credential-key -------
  // A v3 leaf carrying (or omitting) the apple anonymous-attestation extension. The nonce
  // is embedded correctly so the flow reaches the certificate-key comparison; the SPKI is
  // varied to drive each key-mismatch arm (WebAuthn 8.8 item 30).
  var _oidName = pki.oid.byName;
  function ecSpki(algInner, pt) { return _B.sequence([algInner, _B.bitString(pt)]); }
  function ecP256Spki(pt) { return ecSpki(_B.sequence([_B.oid(_oidName("ecPublicKey")), _B.oid(_oidName("prime256v1"))]), pt); }
  function appleCert(spkiNode, extValue) {
    var tail = extValue == null ? [] : [_B.explicit(3, _B.sequence([_B.sequence([_B.oid(_oidName("appleAnonymousAttestation")), _B.octetString(extValue)])]))];
    return _B.sequence([
      _B.sequence([_B.explicit(0, _B.integer(2n)), _B.integer(0x1234n), _B.sequence([_B.oid(_oidName("ecdsaWithSHA256"))]), _dn("I"),
        _B.sequence([_B.utcTime(new Date("2024-01-01T00:00:00Z")), _B.utcTime(new Date("2030-01-01T00:00:00Z"))]), _dn("L"),
        spkiNode].concat(tail)),
      _B.sequence([_B.oid(_oidName("ecdsaWithSHA256"))]), _B.bitString(Buffer.alloc(64))]);
  }
  function appleAtt(cert, authData) { return attObjOf("apple", [[cText("x5c"), cArr([cert].map(cBytes))]], authData); }
  function nonceExtFor(authData, cdh) { return _B.sequence([_B.explicit(1, _B.octetString(crypto.createHash("sha256").update(Buffer.concat([authData, cdh])).digest()))]); }
  var appleNonceExt = nonceExtFor(realAuthData, packedHash);
  var goodEcPoint = Buffer.concat([Buffer.from([0x04]), credKey.x, credKey.y]);
  // no anonymous-attestation extension (present-but-wrong leaf vs a no-extension leaf).
  check("verify: apple leaf missing the anonymous-attestation extension -> webauthn/bad-att-cert",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(packedLeaf, realAuthData), packedHash); })) === "webauthn/bad-att-cert");
  check("verify: apple v3 leaf with no extensions -> webauthn/bad-att-cert",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(ecP256Spki(goodEcPoint), null), realAuthData), packedHash); })) === "webauthn/bad-att-cert");
  // the anonymous-attestation extension value must decode to SEQUENCE {[1] OCTET STRING}.
  check("verify: apple attestation extension that is not decodable -> webauthn/bad-att-cert",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(ecP256Spki(goodEcPoint), Buffer.from([0x01])), realAuthData), packedHash); })) === "webauthn/bad-att-cert");
  check("verify: apple attestation extension not SEQUENCE {[1] ...} -> webauthn/bad-att-cert",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(ecP256Spki(goodEcPoint), _B.sequence([_B.integer(1n)])), realAuthData), packedHash); })) === "webauthn/bad-att-cert");
  check("verify: apple attestation nonce that is not an OCTET STRING -> webauthn/bad-att-cert",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(ecP256Spki(goodEcPoint), _B.sequence([_B.explicit(1, _B.integer(1n))])), realAuthData), packedHash); })) === "webauthn/bad-att-cert");
  // the certificate EC key must equal the credential key: curve params present + valid,
  // the declared curve equal, the point uncompressed, and X/Y equal (WebAuthn 8.8 item 30).
  check("verify: apple leaf EC key with no named-curve parameters -> webauthn/key-mismatch",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(ecSpki(_B.sequence([_B.oid(_oidName("ecPublicKey"))]), goodEcPoint), appleNonceExt), realAuthData), packedHash); })) === "webauthn/key-mismatch");
  check("verify: apple leaf EC key whose curve parameters are not an OID -> webauthn/key-mismatch",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(ecSpki(_B.sequence([_B.oid(_oidName("ecPublicKey")), _B.integer(5n)]), goodEcPoint), appleNonceExt), realAuthData), packedHash); })) === "webauthn/key-mismatch");
  check("verify: apple leaf EC key on a different curve than the credential key -> webauthn/key-mismatch",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(ecSpki(_B.sequence([_B.oid(_oidName("ecPublicKey")), _B.oid(_oidName("secp384r1"))]), goodEcPoint), appleNonceExt), realAuthData), packedHash); })) === "webauthn/key-mismatch");
  check("verify: apple leaf EC key that is not an uncompressed point -> webauthn/key-mismatch",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(ecP256Spki(Buffer.concat([Buffer.from([0x02]), credKey.x])), appleNonceExt), realAuthData), packedHash); })) === "webauthn/key-mismatch");
  check("verify: apple leaf EC coordinates differ from the credential key -> webauthn/key-mismatch",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(ecP256Spki(Buffer.concat([Buffer.from([0x04]), Buffer.alloc(32, 7), Buffer.alloc(32, 8)])), appleNonceExt), realAuthData), packedHash); })) === "webauthn/key-mismatch");
  // The certificate-key == credential-key comparison also covers RSA credential keys: an
  // apple leaf whose RSA SPKI equals the RSA credential key verifies; a different modulus
  // is a key-mismatch. (Forge the nonce for the RSA authData so the flow reaches item 30.)
  var _rsa1 = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var _rsa1Jwk = _rsa1.publicKey.export({ format: "jwk" });
  var rsaCose = coseKey([cKV(1, cInt(3)), cKV(3, cInt(-257)), cKV(-1, cBytes(Buffer.from(_rsa1Jwk.n, "base64url"))), cKV(-2, cBytes(Buffer.from(_rsa1Jwk.e, "base64url")))]);
  var rsaAuthData = buildAuthData({ coseKey: rsaCose });
  var rsaNonceExt = nonceExtFor(rsaAuthData, packedHash);
  var rsaMatchCert = appleCert(_B.raw(_rsa1.publicKey.export({ format: "der", type: "spki" })), rsaNonceExt);
  var rsaMatchRes = await pki.webauthn.verify(appleAtt(rsaMatchCert, rsaAuthData), packedHash);
  check("verify: apple leaf RSA key equal to an RSA credential key verifies (AnonCA)",
    rsaMatchRes.verified === true && rsaMatchRes.fmt === "apple" && rsaMatchRes.attestationType === "AnonCA");
  var _rsa2Spki = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "der", type: "spki" });
  check("verify: apple leaf RSA key different from the RSA credential key -> webauthn/key-mismatch",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(_B.raw(_rsa2Spki), rsaNonceExt), rsaAuthData), packedHash); })) === "webauthn/key-mismatch");

  // ---- OKP self-attestation (valid Edwards point through the on-curve gate) --------
  // A valid Ed25519 self-attestation: the credential OKP point passes the full-order check
  // and the real signature verifies -- the attestation-type is "Self" (WebAuthn 8.2).
  var _ed = crypto.generateKeyPairSync("ed25519");
  var _edX = Buffer.from(_ed.publicKey.export({ format: "jwk" }).x, "base64url");
  var _edAuthData = buildAuthData({ coseKey: coseKey([cKV(1, cInt(1)), cKV(3, cInt(-8)), cKV(-1, cInt(6)), cKV(-2, cBytes(_edX))]) });
  var _edAtt = attObjOf("packed", [[cText("alg"), cInt(-8)], [cText("sig"), cBytes(crypto.sign(null, Buffer.concat([_edAuthData, packedHash]), _ed.privateKey))]], _edAuthData);
  var edRes = await pki.webauthn.verify(_edAtt, packedHash);
  check("verify: a valid Ed25519 self-attestation verifies (Self)",
    edRes.verified === true && edRes.fmt === "packed" && edRes.attestationType === "Self");
  // A valid Ed448 self-attestation (fully-specified alg -53) verifies the same way.
  var _ed4 = crypto.generateKeyPairSync("ed448");
  var _ed4X = Buffer.from(_ed4.publicKey.export({ format: "jwk" }).x, "base64url");
  var _ed4AuthData = buildAuthData({ coseKey: coseKey([cKV(1, cInt(1)), cKV(3, cInt(-53)), cKV(-1, cInt(7)), cKV(-2, cBytes(_ed4X))]) });
  var _ed4Att = attObjOf("packed", [[cText("alg"), cInt(-53)], [cText("sig"), cBytes(crypto.sign(null, Buffer.concat([_ed4AuthData, packedHash]), _ed4.privateKey))]], _ed4AuthData);
  var ed4Res = await pki.webauthn.verify(_ed4Att, packedHash);
  check("verify: a valid Ed448 self-attestation verifies (Self)",
    ed4Res.verified === true && ed4Res.fmt === "packed" && ed4Res.attestationType === "Self");

  // ---- authenticatorData bounded reader: the sub-37-byte + ED-happy paths -----------
  // sec. 6.1 -- a well-formed attestation object whose authData byte string is under the
  // 37-byte minimum is rejected by the bounded reader's length gate (a valid CBOR envelope,
  // so the length check -- not the CBOR decode -- is the rejecting step).
  check("parse: a <37-byte authData -> webauthn/bad-auth-data (minimum-length gate)",
    codeOf(function () { pki.webauthn.parseAttestationObject(attObjOf("none", [], Buffer.alloc(10))); }) === "webauthn/bad-auth-data");
  // sec. 6.1 -- with the ED flag set and the remainder a single well-formed CBOR map,
  // authenticatorData parses and surfaces the raw extensions bytes (an empty map 0xa0 is a
  // valid extensions block). This is the ED-set happy path (the reject arms are pinned above).
  var _edFlagCose = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)), cKV(-2, cBytes(credKey.x)), cKV(-3, cBytes(credKey.y))]);
  var _edFlagParsed = pki.webauthn.parseAttestationObject(attObjOf("none", [], buildAuthData({ ed: true, coseKey: _edFlagCose, trailing: Buffer.from([0xa0]) })));
  check("parse: ED flag set with a valid CBOR-map extensions block surfaces the raw extensions",
    _edFlagParsed.authData.flags.ed === true && Buffer.isBuffer(_edFlagParsed.authData.extensions));

  // ---- apple leaf certificate-key comparison: RSA + OKP arms (WebAuthn 8.8 item 30) --
  // An RSA credential key + an apple leaf whose SPKI carries a MALFORMED RSAPublicKey drives
  // the RSA arm of the certificate-key == credential-key check: the leaf key material is
  // decoded (an undecodable body; a non-{INTEGER,INTEGER} SEQUENCE) and, either way, cannot
  // equal the credential key -> webauthn/key-mismatch (fail-closed, never a raw throw).
  var _rsaKp = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var _rsaJwk = _rsaKp.publicKey.export({ format: "jwk" });
  var _rsaCose = coseKey([cKV(1, cInt(3)), cKV(3, cInt(-257)), cKV(-1, cBytes(Buffer.from(_rsaJwk.n, "base64url"))), cKV(-2, cBytes(Buffer.from(_rsaJwk.e, "base64url")))]);
  var _rsaAuth = buildAuthData({ coseKey: _rsaCose });
  var _rsaNonce = nonceExtFor(_rsaAuth, packedHash);
  function _rsaSpki(bodyNode) { return _B.sequence([_B.sequence([_B.oid(_oidName("rsaEncryption")), _B.nullValue()]), _B.bitString(bodyNode)]); }
  check("verify: apple leaf RSA key with an undecodable key body -> webauthn/key-mismatch",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(_rsaSpki(Buffer.from([0x01])), _rsaNonce), _rsaAuth), packedHash); })) === "webauthn/key-mismatch");
  check("verify: apple leaf RSA key that is not SEQUENCE{modulus, exponent} -> webauthn/key-mismatch",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(_rsaSpki(_B.sequence([_B.integer(5n)])), _rsaNonce), _rsaAuth), packedHash); })) === "webauthn/key-mismatch");
  // An OKP (Ed25519) credential key + an apple leaf carrying the SAME Ed25519 SPKI verifies
  // (AnonCA); a DIFFERENT Ed25519 leaf key is a key-mismatch. Drives the kty===1 (OKP) arm of
  // the certificate-key == credential-key comparison (a fixed-width byte-exact compare).
  var _okpKp = crypto.generateKeyPairSync("ed25519");
  var _okpX = Buffer.from(_okpKp.publicKey.export({ format: "jwk" }).x, "base64url");
  var _okpCose = coseKey([cKV(1, cInt(1)), cKV(3, cInt(-8)), cKV(-1, cInt(6)), cKV(-2, cBytes(_okpX))]);
  var _okpAuth = buildAuthData({ coseKey: _okpCose });
  var _okpNonce = nonceExtFor(_okpAuth, packedHash);
  var _okpMatch = await pki.webauthn.verify(appleAtt(appleCert(_B.raw(_okpKp.publicKey.export({ format: "der", type: "spki" })), _okpNonce), _okpAuth), packedHash);
  check("verify: apple leaf OKP key equal to the OKP credential key verifies (AnonCA)",
    _okpMatch.verified === true && _okpMatch.fmt === "apple" && _okpMatch.attestationType === "AnonCA");
  var _okpOtherSpki = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" });
  check("verify: apple leaf OKP key different from the OKP credential key -> webauthn/key-mismatch",
    (await codeOfAsync(function () { return pki.webauthn.verify(appleAtt(appleCert(_B.raw(_okpOtherSpki), _okpNonce), _okpAuth), packedHash); })) === "webauthn/key-mismatch");

  // ---- tpm pubArea nameAlg + the TPM Name binding (WebAuthn 8.3) ---------------------
  // Rebuild the real tpm KAT with ONLY the pubArea bytes altered. The AIK signs certInfo, not
  // pubArea, and the key material lives in `unique` (the pubArea tail), so these edits keep
  // the pubArea-key == credential-key binding and fail at the Name step instead.
  function _tpmWithPubArea(newPub) {
    var att = pki.webauthn.parseAttestationObject(attObj("tpm"));
    var x5c = tpmField("x5c").children.map(function (c) { return pki.cbor.read.byteString(c); });
    return attObjOf("tpm", [
      [cText("ver"), cText("2.0")],
      [cText("alg"), cInt(Number(pki.cbor.read.int(tpmField("alg"))))],
      [cText("sig"), cBytes(pki.cbor.read.byteString(tpmField("sig")))],
      [cText("certInfo"), cBytes(pki.cbor.read.byteString(tpmField("certInfo")))],
      [cText("pubArea"), cBytes(newPub)],
      [cText("x5c"), cArr(x5c.map(cBytes))],
    ], att.authDataBytes);
  }
  var _realPub = pki.cbor.read.byteString(tpmField("pubArea"));
  // pubArea nameAlg (bytes 2..4) set to TPM_ALG_NULL (0x0010), which carries no digest
  // mapping: the TPM Name step refuses it before hashing pubArea (WebAuthn 8.3).
  var _pubBadNameAlg = Buffer.from(_realPub); _pubBadNameAlg.writeUInt16BE(0x0010, 2);
  check("verify: tpm pubArea with an unsupported nameAlg -> webauthn/bad-tpm",
    (await codeOfAsync(function () { return pki.webauthn.verify(_tpmWithPubArea(_pubBadNameAlg), clientHash("tpm")); })) === "webauthn/bad-tpm");
  // Flip an objectAttributes byte: the key material (in `unique`) is unchanged so the pubArea
  // still binds to the credential key AND the certInfo.extraData check still holds, but
  // H(pubArea) changes, so the certInfo attested Name no longer equals nameAlg || H(pubArea)
  // (WebAuthn 8.3) -> webauthn/verify-failed.
  var _pubPerturbed = Buffer.from(_realPub); _pubPerturbed[4] = _pubPerturbed[4] ^ 0x01;
  check("verify: tpm certInfo attested Name != nameAlg||H(pubArea) -> webauthn/verify-failed",
    (await codeOfAsync(function () { return pki.webauthn.verify(_tpmWithPubArea(_pubPerturbed), clientHash("tpm")); })) === "webauthn/verify-failed");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
