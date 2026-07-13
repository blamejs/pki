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
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
