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

// ---- fixtures for the ceremony / assertion vectors --------------------------------------------
var nodeCrypto = require("crypto");
function _sha256(b) { return nodeCrypto.createHash("sha256").update(b).digest(); }
function _u16(n) { var b = Buffer.alloc(2); b.writeUInt16BE(n); return b; }
function _u32(n) { var b = Buffer.alloc(4); b.writeUInt32BE(n); return b; }
function _b64url(b) { return Buffer.from(b).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"); }
// One real P-256 keypair, and the COSE_Key that names its public half -- so an assertion vector
// signs with the key the credential declares rather than asserting over a fixture nobody can check.
var _EC_KP = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
var _EC_JWK = _EC_KP.publicKey.export({ format: "jwk" });
var _EC_COSE = coseKey([cKV(1, cInt(2)), cKV(3, cInt(-7)), cKV(-1, cInt(1)),
  cKV(-2, cBytes(Buffer.from(_EC_JWK.x, "base64url"))), cKV(-3, cBytes(Buffer.from(_EC_JWK.y, "base64url")))]);
// A bare authenticatorData, the shape an ASSERTION returns: no attestedCredentialData, so the AT
// flag is clear and the buffer is exactly the 37-byte header.
function _assertAuthData(o) {
  o = o || {};
  var flags = (o.up === false ? 0 : 0x01) | (o.uv ? 0x04 : 0) | (o.ed ? 0x80 : 0);
  return Buffer.concat([_sha256(Buffer.from(o.rpId || "example.com", "utf8")),
    Buffer.from([flags]), _u32(o.signCount === undefined ? 9 : o.signCount)]);
}
function _clientDataJson(o) {
  o = o || {};
  var doc = { type: o.type || "webauthn.get", challenge: _b64url(o.challenge || Buffer.alloc(16, 4)),
    origin: o.origin || "https://example.com" };
  if (o.crossOrigin !== undefined) doc.crossOrigin = o.crossOrigin;
  return Buffer.from(JSON.stringify(doc), "utf8");
}
function _assertSig(authData, clientDataJSON) {
  return nodeCrypto.sign("sha256", Buffer.concat([authData, _sha256(clientDataJSON)]),
    { key: _EC_KP.privateKey, dsaEncoding: "der" });
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
  check("verify: packed KAT verifies (verified true)", v.attestationVerified === true);
  check("verify: packed reports fmt + attestation type + trust path", v.fmt === "packed" && typeof v.attestationType === "string" && Array.isArray(v.trustPath));
  check("verify: packed surfaces the aaguid + credentialPublicKey", Buffer.isBuffer(v.aaguid) && v.credentialPublicKey);

  // Every defined attestation format verifies structurally + cryptographically
  // over its real KAT: the signature (or nonce/name binding) + the public-key ==
  // credentialPublicKey checks all hold against captured authenticator output.
  for (var fmt of ["tpm", "apple", "fido_u2f", "android_key"]) {
    var res = await pki.webauthn.verify(attObj(fmt), clientHash(fmt), {});
    check("verify: " + fmt + " KAT verifies (verified true)", res.attestationVerified === true);
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
      sr.attestationVerified === true && sr.fmt === sv.expect.fmt && sr.attestationType === sv.expect.attestationType &&
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

  // --- non-map attStmt: the attestation statement MUST be a CBOR map (WebAuthn 6.5.4) ---
  // A non-map attStmt is a structural malformation of the attestation OBJECT, rejected at
  // parse -- it must NEVER reach a format verifier. A CBOR array attStmt in particular has a
  // `children` array whose entries are single nodes, not {key,value} pairs: iterating them as
  // pairs read kv[0] as undefined and threw a raw TypeError, leaking a non-PkiError.
  var nmAuthData = pki.webauthn.parseAttestationObject(attObj("packed")).authDataBytes;
  function attObjRaw(fmt, attStmtBuf, authData) {
    return cMap([[cText("fmt"), cText(fmt)], [cText("attStmt"), attStmtBuf], [cText("authData"), cBytes(authData)]]);
  }
  // Every non-map CBOR type for attStmt is rejected at parse with the structural code.
  [["array", cArr([cInt(1), cInt(2)])], ["integer", cInt(7)], ["byte string", cBytes(Buffer.alloc(3))], ["text string", cText("x")]].forEach(function (t) {
    check("parse: a " + t[0] + " attStmt -> webauthn/bad-attestation-object (not a raw throw)",
      codeOf(function () { pki.webauthn.parseAttestationObject(attObjRaw("packed", t[1], nmAuthData)); }) === "webauthn/bad-attestation-object");
  });
  // verify() runs the same structural parse first: an ARRAY attStmt (the fuzz-found crash
  // input) in EVERY format fails closed with the typed structural error, never a raw throw.
  for (var nmFmt of ["packed", "apple", "fido-u2f", "android-key", "tpm", "none"]) {
    check("verify: an array attStmt (" + nmFmt + ") fails closed as webauthn/bad-attestation-object",
      (await codeOfAsync((function (f) { return function () { return pki.webauthn.verify(attObjRaw(f, cArr([cInt(1), cInt(2)]), nmAuthData), Buffer.alloc(32), {}); }; })(nmFmt))) === "webauthn/bad-attestation-object");
  }

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
    noneRes.attestationVerified === true && noneRes.attestationType === "None" && noneRes.trustPath.length === 0);
  // §8.7 -- a non-empty none attStmt is rejected.
  check("verify: none attestation with a non-empty attStmt -> webauthn/bad-att-stmt",
    (await codeOfAsync(function () { return pki.webauthn.verify(attObjOf("none", [[cText("x"), cInt(1)]], realAuthData), packedHash); })) === "webauthn/bad-att-stmt");
  // §6.5.4 -- a none attStmt that is not a map at all (here a uint) is a structural
  // malformation of the attestation OBJECT, rejected at parse before format dispatch.
  check("verify: none attestation with a non-map attStmt -> webauthn/bad-attestation-object",
    (await codeOfAsync(function () { return pki.webauthn.verify(cMap([[cText("fmt"), cText("none")], [cText("attStmt"), cInt(5)], [cText("authData"), cBytes(realAuthData)]]), packedHash); })) === "webauthn/bad-attestation-object");
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
  // an attStmt that is not a CBOR map is a structural malformation of the attestation
  // OBJECT, rejected at parse before format dispatch, not silently.
  check("verify: packed attStmt that is not a CBOR map -> webauthn/bad-attestation-object",
    (await codeOfAsync(function () { return pki.webauthn.verify(cMap([[cText("fmt"), cText("packed")], [cText("attStmt"), cInt(5)], [cText("authData"), cBytes(realAuthData)]]), packedHash); })) === "webauthn/bad-attestation-object");
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
  // AppleAnonymousAttestation ::= SEQUENCE { nonce [1] EXPLICIT OCTET STRING } is a
  // one-field SEQUENCE wrapping exactly one value. Reading the first child and ignoring
  // the rest accepts a certificate carrying a second, unchecked value beside the nonce --
  // and the whole point of this extension is that its content is what the attestation
  // binds to. Arity is part of the declared shape, so it is enforced rather than skipped.
  var realNonce = crypto.createHash("sha256").update(Buffer.concat([realAuthData, packedHash])).digest();
  check("verify: apple extension with a trailing field beside the nonce is refused",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(appleAtt(appleCert(ecP256Spki(goodEcPoint),
        _B.sequence([_B.explicit(1, _B.octetString(realNonce)), _B.integer(7n)])), realAuthData), packedHash);
    })) === "webauthn/bad-att-cert");
  check("verify: apple extension whose [1] wrapper holds a second value is refused",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(appleAtt(appleCert(ecP256Spki(goodEcPoint),
        _B.sequence([_B.contextConstructed(1, Buffer.concat([_B.octetString(realNonce), _B.octetString(Buffer.alloc(4))]))])), realAuthData), packedHash);
    })) === "webauthn/bad-att-cert");
  check("verify: apple extension whose outer value is not a universal SEQUENCE is refused",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(appleAtt(appleCert(ecP256Spki(goodEcPoint),
        _B.set([_B.explicit(1, _B.octetString(realNonce))])), realAuthData), packedHash);
    })) === "webauthn/bad-att-cert");
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
    rsaMatchRes.attestationVerified === true && rsaMatchRes.fmt === "apple" && rsaMatchRes.attestationType === "AnonCA");
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
    edRes.attestationVerified === true && edRes.fmt === "packed" && edRes.attestationType === "Self");
  // A valid Ed448 self-attestation (fully-specified alg -53) verifies the same way.
  var _ed4 = crypto.generateKeyPairSync("ed448");
  var _ed4X = Buffer.from(_ed4.publicKey.export({ format: "jwk" }).x, "base64url");
  var _ed4AuthData = buildAuthData({ coseKey: coseKey([cKV(1, cInt(1)), cKV(3, cInt(-53)), cKV(-1, cInt(7)), cKV(-2, cBytes(_ed4X))]) });
  var _ed4Att = attObjOf("packed", [[cText("alg"), cInt(-53)], [cText("sig"), cBytes(crypto.sign(null, Buffer.concat([_ed4AuthData, packedHash]), _ed4.privateKey))]], _ed4AuthData);
  var ed4Res = await pki.webauthn.verify(_ed4Att, packedHash);
  check("verify: a valid Ed448 self-attestation verifies (Self)",
    ed4Res.attestationVerified === true && ed4Res.fmt === "packed" && ed4Res.attestationType === "Self");

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
    _okpMatch.attestationVerified === true && _okpMatch.fmt === "apple" && _okpMatch.attestationType === "AnonCA");
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

  await testAndroidSafetyNet();
  await testCompoundAttestation();
  await testTpmObjectAttributePolicy();
  await testCeremonyBinding();
  await testClientData();
  await testAssertion();
  await testCallerAnchors();
}

// ---- caller-supplied attestation anchors (WebAuthn sec. 7.1 step 22-23) -----------------------
// The metadata route resolves an authenticator's roots from the catalogue that registered it, which
// is the stronger source -- but it reaches only the models the catalogue lists. Apple does not
// publish its authenticators to the FIDO Metadata Service and the Google hardware-attestation roots
// come from Google, so for those formats the catalogue resolves nothing and a trust path would come
// back unchecked with no parameter to pin it.
async function testCallerAnchors() {
  var u2f = await require("../helpers/mds-blob").mintU2fAttestation();
  var other = await require("../helpers/mds-blob").mintU2fAttestation();
  var T = new Date("2026-06-01T00:00:00Z");

  var unanchored = await pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash, { time: T });
  check("anchors: with neither route asked for, the verdict SAYS the path was not anchored",
    unanchored.attestationVerified === true && unanchored.anchoredTo === null);

  var pinned = await pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
    { rootCertificates: [u2f.rootDer], time: T });
  check("anchors: a trust path that validates to a caller-supplied root is anchored, and says so",
    pinned.attestationVerified === true && pinned.anchoredTo === "rootCertificates");

  check("anchors: a root the path does not chain to is refused, not ignored",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
        { rootCertificates: [other.rootDer], time: T });
    })) !== "NO-THROW");

  // The pinned roots are read AFTER the attestation verifier resolves, so they stay
  // caller-owned across a promise turn. Both the array and each DER buffer are copied
  // synchronously at entry: without that, a caller recycling the array or overwriting a
  // certificate's bytes in the gap has the attestation anchored against the REPLACEMENT
  // roots while the verdict still reports anchoredTo: "rootCertificates". Mutate both,
  // the way a pooled buffer would, and the verdict must still describe the pin as given.
  var mutableRootBytes = Buffer.from(u2f.rootDer);
  var mutableRootArray = [mutableRootBytes];
  var racedPromise = pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
    { rootCertificates: mutableRootArray, time: T });
  mutableRootArray[0] = other.rootDer;          // swap the array slot
  mutableRootArray.push(other.rootDer);         // and grow the array
  mutableRootBytes.fill(0);                     // and destroy the bytes it pointed at
  var raced = await racedPromise;
  check("anchors: pinned roots mutated after the call still anchor to what was passed (TOCTOU)",
    raced.attestationVerified === true && raced.anchoredTo === "rootCertificates");

  // The documented parsed-certificate form is caller-owned too, and the anchor comparison reads its
  // nested subject / subjectPublicKeyInfo buffers. Copying only the array would leave those aliased,
  // so rewriting the parsed object's key bytes after the call must not change what it anchors to.
  // Parsed from a PRIVATE copy of the root: the parser surfaces byte ranges as views into its
  // input, so mutating them below would otherwise corrupt the shared fixture for every later check.
  var parsedRoot = pki.schema.x509.parse(Buffer.from(u2f.rootDer));
  var parsedPromise = pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
    { rootCertificates: [parsedRoot], time: T });
  if (parsedRoot.subjectPublicKeyInfo && Buffer.isBuffer(parsedRoot.subjectPublicKeyInfo.bytes)) {
    parsedRoot.subjectPublicKeyInfo.bytes.fill(0);
  }
  if (Buffer.isBuffer(parsedRoot.tbsBytes)) parsedRoot.tbsBytes.fill(0);
  var parsedRaced = await parsedPromise;
  check("anchors: a parsed root mutated after the call still anchors to what was passed (TOCTOU)",
    parsedRaced.attestationVerified === true && parsedRaced.anchoredTo === "rootCertificates");

  // The reverse direction: a pin that should NOT chain cannot be rescued by swapping in a
  // good root after the call, either.
  var swapToGood = [Buffer.from(other.rootDer)];
  var badPromise = pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
    { rootCertificates: swapToGood, time: T });
  swapToGood[0] = u2f.rootDer;
  check("anchors: swapping in a chaining root after the call does not rescue a bad pin",
    (await (async function () { try { await badPromise; return "NO-THROW"; } catch (e) { return e.code; } })()) !== "NO-THROW");

  // `none` and self-attestation carry no certificates. A caller who asked for anchoring is told it
  // could not be applied rather than handed a pass that reads as though it had been.
  // The KAT's own authenticatorData, so the `none` attestation is otherwise valid and
  // the verdict under test is the anchoring one rather than a key-decode failure.
  var realAuth = pki.webauthn.parseAttestationObject(attObj("packed")).authDataBytes;
  check("anchors: an attestation with no trust path reports that anchoring could not be applied",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(attObjOf("none", [], realAuth), clientHash("packed"),
        { rootCertificates: [u2f.rootDer] });
    })) === "webauthn/anchor-not-applicable");

  // Both routes together is the ordinary configuration for a relying party that accepts MDS-listed
  // authenticators AND Apple. The precedence is stated: metadata governs when it is present.
  var meta = await require("../helpers/mds-blob").mint({ aaguid: null,
    anchors: [u2f.rootDer.toString("base64")],
    keyIdentifiers: [require("../../lib/webauthn-mds").certKeyIdentifier(unanchored.trustPath[unanchored.trustPath.length - 1])] });
  var verifiedMeta = await pki.webauthn.verifyMetadataBlob(meta.blob, { rootCertificates: [meta.rootDer], time: T });
  var both = await pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
    { metadata: verifiedMeta, rootCertificates: [other.rootDer], time: T });
  check("anchors: metadata governs when both routes are supplied, and the verdict names which ran",
    both.anchoredTo === "metadata" && !!both.metadata);

  // A compound element carrying no certificates makes no attestation claim, so it is
  // not a reason to refuse the statement -- but `anchoredTo` alone would then read as
  // "the whole statement is anchored" when one element was never covered. The
  // coverage is reported rather than left to be assumed.
  check("anchors: a single-format attestation reports 1 of 1 elements anchored",
    pinned.anchoredElements.total === 1 && pinned.anchoredElements.anchored === 1);

  // ...and the combined configuration has to WORK for the models it was added to
  // reach. Apple is in no catalogue, so a metadata MISS falling through to the
  // pinned roots is the whole point of supplying both.
  var otherMeta = await require("../helpers/mds-blob").mint({ aaguid: null,
    anchors: [other.rootDer.toString("base64")], keyIdentifiers: ["00".repeat(20)] });
  var verifiedOther = await pki.webauthn.verifyMetadataBlob(otherMeta.blob,
    { rootCertificates: [otherMeta.rootDer], time: T });
  var missed = await pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
    { metadata: verifiedOther, rootCertificates: [u2f.rootDer], time: T });
  check("anchors: a model the catalogue does not list falls through to the pinned roots",
    missed.attestationVerified === true && missed.anchoredTo === "rootCertificates");

  check("anchors: ...but a catalogue MISS with no pinned roots is still a refusal",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
        { metadata: verifiedOther, time: T });
    })) === "webauthn/metadata-not-found");

  // A catalogue DENIAL is not a miss. If the model IS listed and its entry
  // disqualifies it, a static pin must not overrule the stronger source -- otherwise
  // supplying roots would quietly downgrade every revoked model to trusted.
  var revoked = await require("../helpers/mds-blob").mint({ aaguid: null,
    anchors: [u2f.rootDer.toString("base64")],
    keyIdentifiers: [require("../../lib/webauthn-mds").certKeyIdentifier(unanchored.trustPath[unanchored.trustPath.length - 1])],
    statusReports: [{ status: "REVOKED", effectiveDate: "2026-01-01" }] });
  var verifiedRevoked = await pki.webauthn.verifyMetadataBlob(revoked.blob,
    { rootCertificates: [revoked.rootDer], time: T });
  check("anchors: a LISTED but disqualified model does not fall through to pinned roots",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(u2f.attestationObject, u2f.clientDataHash,
        { metadata: verifiedRevoked, rootCertificates: [u2f.rootDer], time: T });
    })) === "webauthn/metadata-status");
}

// ---- the ceremony boundary (WebAuthn sec. 7.1) ------------------------------------------------
// An attestation statement being SOUND is not the same claim as a registration being ACCEPTABLE:
// the statement says nothing about which relying party asked for it, or whether a user was there.
// The verdict has to make that distinguishable, or a caller reading one boolean ships a passkey
// verifier with no phishing resistance at all.
async function testCeremonyBinding() {
  // The reported case: an attestation naming ANOTHER relying party, with User Present and User
  // Verified both clear. The statement is sound and the field says exactly that -- and no more.
  var otherRp = _sha256(Buffer.from("attacker.example", "utf8"));
  var hostile = Buffer.concat([otherRp, Buffer.from([0x40]), Buffer.alloc(4),
    Buffer.alloc(16, 2), _u16(16), Buffer.alloc(16, 3), _EC_COSE]);
  var hostileObj = attObjOf("none", [], hostile);
  var unbound = await pki.webauthn.verify(hostileObj, clientHash("packed"), {});
  check("binding: the verdict field is attestationVerified, never a bare `verified`",
    unbound.attestationVerified === true && unbound.verified === undefined);
  check("binding: with nothing asked for, every binding reports NOT checked",
    unbound.bindingChecked.rpId === false && unbound.bindingChecked.userPresence === false &&
    unbound.bindingChecked.userVerification === false && unbound.bindingChecked.algorithm === false);

  check("binding: expectedRpId refuses an attestation made for another relying party",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(hostileObj, clientHash("packed"), { expectedRpId: "example.com" });
    })) === "webauthn/rp-id-mismatch");
  check("binding: requireUserPresence refuses a UP-clear response",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(hostileObj, clientHash("packed"), { requireUserPresence: true });
    })) === "webauthn/user-presence-required");
  check("binding: requireUserVerification refuses a UV-clear response",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(hostileObj, clientHash("packed"), { requireUserVerification: true });
    })) === "webauthn/user-verification-required");
  // COSE alg -65535 is RSASSA-PKCS1-v1_5 with SHA-1. Which algorithms are acceptable is the relying
  // party's own pubKeyCredParams policy, and nothing in the response says what was offered -- so it
  // is checked when the caller states the list, and reported when it was.
  check("binding: allowedAlgorithms refuses a credential key outside the list",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(hostileObj, clientHash("packed"), { allowedAlgorithms: [-8] });
    })) === "webauthn/algorithm-not-allowed");

  // The matching relying party, with the flags the caller demanded actually set.
  var good = Buffer.concat([_sha256(Buffer.from("example.com", "utf8")), Buffer.from([0x01 | 0x04 | 0x40]),
    Buffer.from([0, 0, 0, 5]), Buffer.alloc(16, 2), _u16(16), Buffer.alloc(16, 3), _EC_COSE]);
  var okRes = await pki.webauthn.verify(attObjOf("none", [], good), clientHash("packed"),
    { expectedRpId: "example.com", requireUserPresence: true, requireUserVerification: true, allowedAlgorithms: [-7] });
  check("binding: the bindings that ran are the ones reported",
    okRes.bindingChecked.rpId === true && okRes.bindingChecked.userPresence === true &&
    okRes.bindingChecked.userVerification === true && okRes.bindingChecked.algorithm === true);
  // Everything a relying party must STORE to run a later login comes back from the call that
  // verified the registration -- without them a login cannot be checked at all, and the caller
  // would have to parse the attestation object a second time for values already decoded here.
  check("binding: the verdict carries the credentialId, key and signCount a login needs",
    Buffer.isBuffer(okRes.credentialId) && okRes.credentialId.length === 16 &&
    okRes.signCount === 5 && okRes.flags.up === true && !!okRes.credentialPublicKey);
}

// ---- TPM object-attribute policy (TPM 2.0 Part 2 sec. 8.3, NOT WebAuthn sec. 8.3) ------------
// WebAuthn sec. 8.3 constrains only pubArea's `parameters` and `unique` fields -- `objectAttributes`
// and `authPolicy` appear nowhere in it. They are therefore SURFACED for relying-party policy and
// gated only when a caller asks by name. Every vector drives opts rather than a forged fixture:
// pubArea is hashed into certInfo.attested.name, so a mutated pubArea fails the Name check long
// before any policy code runs, and re-deriving certInfo would need the AIK private key.
async function testTpmObjectAttributePolicy() {
  var ATT = attObj("tpm"), CDH = clientHash("tpm");
  function withPolicy(p) { return pki.webauthn.verify(ATT, CDH, { tpmPolicy: p }); }
  async function codeFor(p) { try { await withPolicy(p); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }

  // Default off: with no tpmPolicy the verdict is what it was before this existed.
  var plain = await pki.webauthn.verify(ATT, CDH, {});
  check("tpm policy: absent, the attestation verifies exactly as before", plain.attestationVerified === true && plain.attestationType === "AttCA");
  // Surfacing is the load-bearing half -- an RP cannot apply policy to a field it never sees.
  check("tpm policy: the object attributes are surfaced as named booleans",
    plain.tpm.attributes.fixedTPM === true && plain.tpm.attributes.sign === true && plain.tpm.attributes.restricted === false);
  check("tpm policy: the raw objectAttributes word and authPolicy digest are surfaced",
    typeof plain.tpm.objectAttributes === "number" && Buffer.isBuffer(plain.tpm.authPolicy));

  // The one defined preset holds on real hardware -- that is why those six bits are the preset.
  check("tpm policy: the hardware-bound profile accepts a genuine attestation",
    (await withPolicy({ profile: "hardware-bound" })).attestationVerified === true);
  // A demanded bit the key does not have is refused, in both directions.
  check("tpm policy: a required-SET attribute the key lacks is refused",
    (await codeFor({ objectAttributes: { restricted: true } })) === "webauthn/tpm-policy");
  check("tpm policy: a required-CLEAR attribute the key sets is refused",
    (await codeFor({ objectAttributes: { decrypt: false } })) === "webauthn/tpm-policy");
  // An explicit map layers over the preset, so one bit can be overridden without losing the rest.
  check("tpm policy: an explicit attribute overrides the profile",
    (await codeFor({ profile: "hardware-bound", objectAttributes: { sign: false } })) === "webauthn/tpm-policy");

  // The trap: userWithAuth CLEAR is the STRICTER setting (Table 33 bit 6 -- CLEAR means only a
  // policy session may approve USER-role use). This statement has it SET, so demanding it CLEAR
  // must refuse; a caller who writes `userWithAuth: true` believing it hardens anything has it
  // backwards, and the vector records which direction is which.
  check("tpm policy: demanding userWithAuth CLEAR refuses a key that sets it",
    (await codeFor({ objectAttributes: { userWithAuth: false } })) === "webauthn/tpm-policy");

  // Config-time faults: a typo must never silently disable the check the caller thinks they set.
  check("tpm policy: a non-object policy is a config-time fault", (await codeFor("hardware-bound")) === "webauthn/bad-input");
  check("tpm policy: an unknown top-level key is a config-time fault",
    (await codeFor({ objectAttribute: {} })) === "webauthn/bad-input");
  check("tpm policy: an unknown profile is a config-time fault",
    (await codeFor({ profile: "maximum-security" })) === "webauthn/bad-input");
  check("tpm policy: an unknown attribute name is a config-time fault",
    (await codeFor({ objectAttributes: { fixedTpm: true } })) === "webauthn/bad-input");
  check("tpm policy: a non-boolean attribute value is a config-time fault",
    (await codeFor({ objectAttributes: { fixedTPM: "yes" } })) === "webauthn/bad-input");
  // sec. 8.3.3.5 NOTE 1: sensitiveDataOrigin asserts the TPM generated the key only when fixedTPM
  // is also SET. Demanding it alone asserts nothing, so it is refused at config time rather than
  // giving the caller a check that quietly means less than they think.
  check("tpm policy: sensitiveDataOrigin without fixedTPM is refused as meaningless",
    (await codeFor({ objectAttributes: { sensitiveDataOrigin: true } })) === "webauthn/bad-input");

  // Structural opt-ins, both satisfied by genuine hardware.
  check("tpm policy: the reserved-bit check passes on a genuine attestation",
    (await withPolicy({ reservedBitsClear: true })).attestationVerified === true);
  check("tpm policy: the consistency check passes on a genuine attestation",
    (await withPolicy({ consistency: true })).attestationVerified === true);

  // authPolicy: this statement carries a real 32-octet digest.
  check("tpm policy: requiring a non-Empty authPolicy passes when one is present",
    (await withPolicy({ authPolicy: { present: true } })).attestationVerified === true);
  check("tpm policy: an authPolicy allow-list containing the key's digest passes",
    (await withPolicy({ authPolicy: { allow: [plain.tpm.authPolicy] } })).attestationVerified === true);
  check("tpm policy: an allow-list the digest is absent from is refused",
    (await codeFor({ authPolicy: { allow: [Buffer.alloc(32, 7)] } })) === "webauthn/tpm-policy");
  check("tpm policy: an allow-list entry may be a hex string",
    (await withPolicy({ authPolicy: { allow: [plain.tpm.authPolicy.toString("hex")] } })).attestationVerified === true);
  check("tpm policy: a non-array allow-list is a config-time fault",
    (await codeFor({ authPolicy: { allow: "deadbeef" } })) === "webauthn/bad-input");
  // A misspelled NESTED key would leave the allow-list unset and the policy silently doing
  // nothing -- the same failure the top-level enumeration prevents, one level down.
  check("tpm policy: a misspelled authPolicy key is a config-time fault",
    (await codeFor({ authPolicy: { alow: [Buffer.alloc(32, 1)] } })) === "webauthn/bad-input");
  // Every one of these tables is indexed by a caller-supplied name. An inherited Object member
  // resolves to a truthy non-value, which in a "is this name known?" lookup reads as "known" and
  // leaves the policy applying nothing -- a fail-open, and the worst kind, because the caller
  // believes they selected a policy. All three tables are null-prototype; all three are pinned.
  var inherited = ["constructor", "toString", "__proto__", "valueOf", "hasOwnProperty"];
  var profileRefused = true, keyRefused = true, attrRefused = true;
  for (var pi = 0; pi < inherited.length; pi++) {
    // Built through JSON so `__proto__` is a real own property rather than a prototype assignment
    // -- which is exactly how a policy read from a config file or a request body arrives.
    var named = JSON.stringify(inherited[pi]);
    if ((await codeFor({ profile: inherited[pi] })) !== "webauthn/bad-input") profileRefused = false;
    if ((await codeFor(JSON.parse("{" + named + ": true}"))) !== "webauthn/bad-input") keyRefused = false;
    if ((await codeFor({ objectAttributes: JSON.parse("{" + named + ": true}") })) !== "webauthn/bad-input") attrRefused = false;
  }
  check("tpm policy: an inherited Object name is not a valid profile", profileRefused);
  check("tpm policy: an inherited Object name is not a valid policy key", keyRefused);
  check("tpm policy: an inherited Object name is not a valid attribute name", attrRefused);

  // The policy is checked inside the tpm arm, so an attestation in any other format would never
  // reach it. A caller who demanded a TPM-bound key must not therefore accept a `none` or `packed`
  // attestation that carries no TPM public area at all -- the requirement is refused at dispatch.
  var otherFormats = ["packed", "apple", "android_key", "fido_u2f"];
  var bypassRefused = true;
  for (var oi = 0; oi < otherFormats.length; oi++) {
    var got = await codeOfAsync((function (fmt) {
      return function () { return pki.webauthn.verify(attObj(fmt), clientHash(fmt), { tpmPolicy: { profile: "hardware-bound" } }); };
    })(otherFormats[oi]));
    if (got !== "webauthn/tpm-policy") bypassRefused = false;
  }
  // `none` is the sharpest case -- it always verifies and carries no key properties at all -- and
  // has no KAT fixture, so it is assembled from the packed statement's authenticatorData.
  var noneAuth = (function () {
    var m = pki.cbor.read.map(pki.cbor.decode(attObj("packed")));
    for (var i = 0; i < m.length; i++) if (pki.cbor.read.textString(m[i][0]) === "authData") return m[i][1].content;
    throw new Error("no authData in the KAT");
  })();
  if ((await codeOfAsync(function () {
    return pki.webauthn.verify(attObjOf("none", [], noneAuth), clientHash("packed"), { tpmPolicy: { profile: "hardware-bound" } });
  })) !== "webauthn/tpm-policy") bypassRefused = false;
  // ... and that same `none` attestation still verifies when no TPM policy was asked for.
  check("tpm policy: a none attestation still verifies when no policy is requested",
    (await pki.webauthn.verify(attObjOf("none", [], noneAuth), clientHash("packed"), {})).attestationVerified === true);
  check("tpm policy: a non-TPM attestation cannot silently ignore a requested TPM policy", bypassRefused);
  // ... and the same policy on a genuine TPM attestation still verifies, so the dispatch gate
  // refuses the formats that cannot satisfy it without blocking the one that can.
  check("tpm policy: the gate does not block the format that can satisfy it",
    (await withPolicy({ profile: "hardware-bound" })).attestationVerified === true);
  // Node's hex decoder stops at the first non-hex character and yields an empty buffer for a
  // non-string, so an unvalidated entry could decode into a digest the policy meant to exclude --
  // including the Empty Policy. Each entry is type- and shape-checked before it is decoded.
  var badEntries = [null, 42, {}, "", "abc", "zz", plain.tpm.authPolicy.toString("hex") + "zz"];
  var allRefused = true;
  for (var bi = 0; bi < badEntries.length; bi++) {
    if ((await codeFor({ authPolicy: { allow: [badEntries[bi]] } })) !== "webauthn/bad-input") allRefused = false;
  }
  check("tpm policy: an allow-list entry that is not a Buffer or canonical hex is refused", allRefused);
  // The specific danger: a digest followed by junk must not silently truncate back to that digest
  // and authorize the very key the caller wrote the allow-list to exclude.
  check("tpm policy: a hex entry with trailing junk does not truncate into a match",
    (await codeFor({ authPolicy: { allow: [plain.tpm.authPolicy.toString("hex") + "zz"] } })) === "webauthn/bad-input");
}

// ---- compound attestation (WebAuthn sec. 8.9) --------------------------------
// The attStmt is an ARRAY of nested statements, each verified over the SAME authenticatorData and
// clientDataHash. Built here from the real KAT statements, so each element is a genuine attestation
// rather than a shape that merely parses.
async function testCompoundAttestation() {
  // Lift the { fmt, attStmt } of a real KAT attestation, and its authData, so a compound can be
  // assembled from statements that actually verify.
  function partsOf(fmt) {
    var m = pki.cbor.read.map(pki.cbor.decode(attObj(fmt)));
    var out = {};
    m.forEach(function (kv) { out[pki.cbor.read.textString(kv[0])] = kv[1]; });
    return out;
  }
  var packed = partsOf("packed");
  var AUTH_DATA = packed.authData.content;
  // The local cText/cMap/cArr builders emit raw CBOR bytes, and a lifted KAT node's own bytes are
  // at .bytes -- one builder family throughout, so an element is byte-identical to the statement
  // it was lifted from.
  function el(fmtText, attStmtBytes) { return cMap([[cText("fmt"), cText(fmtText)], [cText("attStmt"), attStmtBytes]]); }
  function compoundOf(elements, authData) {
    return cMap([[cText("fmt"), cText("compound")], [cText("attStmt"), cArr(elements)],
      [cText("authData"), cBytes(authData || AUTH_DATA)]]);
  }
  var NONE = el("none", cMap([]));
  var PACKED = el("packed", packed.attStmt.bytes);

  // sec. 8.9 bullet 2: a compound whose elements all verify returns a combined result.
  var okRes = await pki.webauthn.verify(compoundOf([PACKED, NONE]), clientHash("packed"), {});
  check("compound: a statement whose elements all verify returns a combined result",
    okRes.attestationVerified === true && okRes.fmt === "compound" && okRes.attestationType === "Compound");
  check("compound: each element's own verdict is surfaced in order",
    okRes.compound.length === 2 && okRes.compound[0].fmt === "packed" &&
    okRes.compound[0].attestationType === "Basic" && okRes.compound[1].fmt === "none");
  // Two independent chains cannot form one ordered path, so the top-level trust path is empty and
  // each element carries its own.
  check("compound: the trust path is per-element, not merged",
    okRes.trustPath.length === 0 && okRes.compound[0].trustPath.length > 0);
  // The credential binding comes from the shared authenticatorData, as for every other format.
  check("compound: the credential binding comes from the shared authenticatorData",
    Buffer.isBuffer(okRes.aaguid) && !!okRes.credentialPublicKey);

  // Metadata enforcement reads the ELEMENTS' paths. The top-level path is empty by design here, so
  // treating that as "nothing to anchor" would refuse every compound attestation out of hand --
  // including ones whose certificate-bearing elements do chain to the model's registered roots.
  // The elements here chain to a vendor root this project does not hold, so the reachable
  // assertion is that the verdict is a real lookup outcome and NOT the not-applicable short circuit.
  var mdsHelper = require("../helpers/mds-blob");
  var mdsFixture = await mdsHelper.mint({});
  var compoundMd = await pki.webauthn.verifyMetadataBlob(mdsFixture.blob,
    { rootCertificates: [mdsFixture.rootDer], time: new Date("2026-06-01T00:00:00Z") });
  var compoundVerdict = await codeOfAsync(function () {
    return pki.webauthn.verify(compoundOf([PACKED, NONE]), clientHash("packed"),
      { metadata: compoundMd, time: new Date("2026-06-01T00:00:00Z") });
  });
  check("compound: metadata is applied to the elements' paths, not refused as not applicable",
    compoundVerdict !== "webauthn/metadata-not-applicable" && /^webauthn\/metadata-/.test(compoundVerdict));
  // Which identifier may name an element's entry is decided by THAT element's format, not by the
  // statement as a whole. A mixed compound holding a fido-u2f element (whose AAGUID is unsigned)
  // alongside a packed element (whose AAGUID is signed) must not force the packed element down the
  // certificate-identifier path -- a conforming entry indexed only by its AAGUID would not be found
  // there. The packed element here is the one whose lookup is observable: the catalogue lists the
  // authenticator's AAGUID, so an AAGUID-keyed lookup reaches an entry and the verdict is about its
  // anchors, whereas a certificate-keyed lookup could only ever report the model as unlisted.
  var MIXED_AAGUID = "11111111-1111-1111-1111-111111111111";
  var mixed = await mdsHelper.mintMixedCompound(MIXED_AAGUID);
  var mixedVerified = await pki.webauthn.verify(mixed.attestationObject, mixed.clientDataHash, {});
  check("compound: the mixed fixture verifies, with a path on each element",
    mixedVerified.attestationVerified === true && mixedVerified.compound.length === 2 &&
    mixedVerified.compound[0].trustPath.length > 0 && mixedVerified.compound[1].trustPath.length > 0);
  // The catalogue lists the packed element's model by AAGUID and the u2f element's certificate by
  // key identifier -- each element under the identifier its own format actually signs. Both must
  // resolve, which only happens when the choice is made per element.
  var u2fKeyId = require("../../lib/webauthn-mds.js").certKeyIdentifier(pki.schema.x509.parse(mixed.u2fCertDer));
  var mixedBlob = await mdsHelper.mint({ entries: [
    { aaguid: MIXED_AAGUID, statusReports: [{ status: "FIDO_CERTIFIED_L2" }],
      metadataStatement: { attestationRootCertificates: [mixed.rootDer.toString("base64")] } },
    { attestationCertificateKeyIdentifiers: [u2fKeyId], statusReports: [{ status: "FIDO_CERTIFIED_L2" }],
      metadataStatement: { attestationRootCertificates: [mixed.rootDer.toString("base64")] } },
  ] });
  var mixedMd = await pki.webauthn.verifyMetadataBlob(mixedBlob.blob,
    { rootCertificates: [mixedBlob.rootDer], time: new Date("2026-06-01T00:00:00Z") });
  var mixedBound = await pki.webauthn.verify(mixed.attestationObject, mixed.clientDataHash,
    { metadata: mixedMd, time: new Date("2026-06-01T00:00:00Z") });
  check("compound: each element is looked up by the identifier its own format signs",
    mixedBound.attestationVerified === true && mixedBound.metadata.entries.length === 2 &&
    mixedBound.metadata.entries[0].aaguid === MIXED_AAGUID &&
    mixedBound.metadata.entries[1].keyIdentifiers.indexOf(u2fKeyId) !== -1);

  // An UNLISTED element must not launder a REVOKED sibling. The two governance failures are not
  // equal: `metadata-not-found` is the one a caller may fall back to pinned roots on, and that
  // fallback covers the whole statement. So if governance stopped at the first failing element, an
  // element the catalogue does not list could raise the fallback error before a listed-but-revoked
  // sibling is ever consulted -- and a compound's element order is not signed, so an attacker picks
  // it. The denial must win from EITHER position, and it must win even when pinned roots that would
  // otherwise accept the statement are supplied.
  var pinnedFallback = { rootCertificates: [mixed.rootDer], time: new Date("2026-06-01T00:00:00Z") };
  var revokedU2fOnly = await mdsHelper.mint({ entries: [
    // the packed element's AAGUID is absent -> that element MISSES the catalogue
    { attestationCertificateKeyIdentifiers: [u2fKeyId], statusReports: [{ status: "REVOKED", effectiveDate: "2026-02-01" }],
      metadataStatement: { attestationRootCertificates: [mixed.rootDer.toString("base64")] } },
  ] });
  var revokedMd = await pki.webauthn.verifyMetadataBlob(revokedU2fOnly.blob,
    { rootCertificates: [revokedU2fOnly.rootDer], time: new Date("2026-06-01T00:00:00Z") });
  check("compound: an unlisted element cannot launder a revoked sibling into a pinned-root pass",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(mixed.attestationObject, mixed.clientDataHash,
        Object.assign({ metadata: revokedMd }, pinnedFallback));
    })) === "webauthn/metadata-status");
  // The same catalogue without the pinned-root fallback: still the denial, never the miss.
  check("compound: the denial outranks the miss with no fallback offered either",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(mixed.attestationObject, mixed.clientDataHash,
        { metadata: revokedMd, time: new Date("2026-06-01T00:00:00Z") });
    })) === "webauthn/metadata-status");
  // Resolving an entry is only half of governance; the path must also VALIDATE to the roots that
  // entry registers. Here the u2f element IS listed and healthy, but its entry registers a root its
  // path does not reach, while the caller's pinned roots would accept it. If the miss on the packed
  // element were reported before that chain check ran, the listed element would ride out on the
  // fallback without ever satisfying its own catalogue anchors -- the same bypass one phase later.
  var wrongAnchor = await mdsHelper.mint({ entries: [
    { attestationCertificateKeyIdentifiers: [u2fKeyId], statusReports: [{ status: "FIDO_CERTIFIED_L2" }],
      metadataStatement: { attestationRootCertificates: [mdsFixture.rootDer.toString("base64")] } },
  ] });
  var wrongAnchorMd = await pki.webauthn.verifyMetadataBlob(wrongAnchor.blob,
    { rootCertificates: [wrongAnchor.rootDer], time: new Date("2026-06-01T00:00:00Z") });
  check("compound: a listed element must reach ITS OWN registered roots before a sibling's miss falls back",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(mixed.attestationObject, mixed.clientDataHash,
        Object.assign({ metadata: wrongAnchorMd }, pinnedFallback));
    })) !== "NO-THROW");

  // And a compound where EVERY element misses still reports the miss, so the documented
  // pinned-roots fallback for models the catalogue does not cover keeps working.
  var listsNeither = await mdsHelper.mint({ entries: [
    { aaguid: "99999999-9999-9999-9999-999999999999", statusReports: [{ status: "FIDO_CERTIFIED_L2" }],
      metadataStatement: { attestationRootCertificates: [] } },
  ] });
  var neitherMd = await pki.webauthn.verifyMetadataBlob(listsNeither.blob,
    { rootCertificates: [listsNeither.rootDer], time: new Date("2026-06-01T00:00:00Z") });
  var allMissed = await pki.webauthn.verify(mixed.attestationObject, mixed.clientDataHash,
    Object.assign({ metadata: neitherMd }, pinnedFallback));
  check("compound: when no element is listed at all, the pinned-roots fallback still applies",
    allMissed.attestationVerified === true && allMissed.anchoredTo === "rootCertificates");

  // A compound whose elements carry no certificate at all genuinely has nothing to anchor, and
  // that IS the not-applicable case -- so the distinction is drawn on the elements, not on the
  // (always empty) top-level path.
  check("compound: a compound with no certificate-bearing element is not applicable",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(compoundOf([NONE, el("none", cMap([]))]), clientHash("packed"),
        { metadata: compoundMd, time: new Date("2026-06-01T00:00:00Z") });
    })) === "webauthn/metadata-not-applicable");

  // Fail-closed policy: sec. 8.9 leaves the threshold to the relying party, and this toolkit
  // requires every element. A compound must not launder a failed element behind a passing one.
  var badPacked = el("packed", partsOf("packed").attStmt.bytes);
  check("compound: one failing element fails the whole statement", (await codeOfAsync(function () {
    // the packed element verified against the WRONG clientDataHash cannot verify
    return pki.webauthn.verify(compoundOf([badPacked, NONE]), clientHash("tpm"), {});
  })) === "webauthn/compound-element-failed");
  // Most format arms do their structural checks SYNCHRONOUSLY, so an element that fails before the
  // first await must be reported with the same element context as one that fails after it -- a
  // `none` element carrying a non-empty statement throws on the spot.
  var syncFail = el("none", cMap([[cText("x"), cText("y")]]));
  check("compound: an element that fails synchronously carries the same element context",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(compoundOf([syncFail, NONE]), clientHash("packed"), {});
    })) === "webauthn/compound-element-failed");

  // sec. 8.9 syntax: 2* elements, each exactly { fmt, attStmt }, and none of them compound.
  check("compound: fewer than two elements is refused",
    (await codeOfAsync(function () { return pki.webauthn.verify(compoundOf([NONE]), clientHash("packed"), {}); })) === "webauthn/bad-att-stmt");
  check("compound: a nested compound is refused (the syntax forbids it)",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(compoundOf([el("compound", cArr([NONE, NONE])), NONE]), clientHash("packed"), {});
    })) === "webauthn/bad-att-stmt");
  check("compound: an element carrying an unexpected field is refused",
    (await codeOfAsync(function () {
      var extra = cMap([[cText("fmt"), cText("none")], [cText("attStmt"), cMap([])], [cText("x"), cText("y")]]);
      return pki.webauthn.verify(compoundOf([extra, NONE]), clientHash("packed"), {});
    })) === "webauthn/bad-att-stmt");
  check("compound: an element with an unknown format is refused",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(compoundOf([el("not-a-format", cMap([])), NONE]), clientHash("packed"), {});
    })) === "webauthn/unsupported-format");
  // sec. 8.1: identifiers match case-sensitively, so "None" is not "none".
  check("compound: a format identifier is matched case-sensitively",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(compoundOf([el("None", cMap([])), NONE]), clientHash("packed"), {});
    })) === "webauthn/unsupported-format");
  // An element whose attStmt has the wrong CBOR shape for its format never reaches the walk.
  check("compound: an element whose attStmt is the wrong CBOR shape is refused",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(compoundOf([el("none", cArr([])), NONE]), clientHash("packed"), {});
    })) === "webauthn/bad-att-stmt");
  // Not a spec rule -- a resource bound. Each element costs a verify and possibly a path validation.
  var many = [];
  for (var i = 0; i < 17; i++) many.push(NONE);
  check("compound: more nested statements than the verify bound is refused",
    (await codeOfAsync(function () { return pki.webauthn.verify(compoundOf(many), clientHash("packed"), {}); })) === "webauthn/bad-att-stmt");

  // The envelope is registry-driven: an array attStmt is legal ONLY for compound, and a map
  // attStmt is still refused for compound. Neither format's contract leaks into the other.
  // The map-shaped `none` must still parse -- called directly, so a regression surfaces as its own
  // throw rather than as a bare false.
  pki.webauthn.parseAttestationObject(attObjOf("none", [], AUTH_DATA));
  check("compound: a non-compound format still refuses an array attStmt", (function () {
    var arrayNone = cMap([[cText("fmt"), cText("none")], [cText("attStmt"), cArr([])],
      [cText("authData"), cBytes(AUTH_DATA)]]);
    return codeOf(function () { return pki.webauthn.parseAttestationObject(arrayNone); }) === "webauthn/bad-attestation-object";
  })());
  check("compound: a compound with a map attStmt is refused",
    codeOf(function () {
      return pki.webauthn.parseAttestationObject(attObjOf("compound", [], packed.authData.content));
    }) === "webauthn/bad-attestation-object");
}

// ---- android-safetynet (WebAuthn sec. 8.5) ----------------------------------
// Google retired the SafetyNet Attestation API, so there is no live producer to capture a vector
// from and none will exist again -- the surviving use is a relying party re-checking attestations it
// stored years ago. The statements below are therefore minted here: this toolkit's own issuer builds
// the chain and signs the JWS, which exercises every sec. 8.5 bind on the SHIPPED consumer path.
async function testAndroidSafetyNet() {
  var SN_TIME = new Date("2026-06-01T00:00:00Z");
  function b64uEnc(buf) { return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }

  // One builder serves the accept vector and every reject vector, each breaking exactly one bind.
  async function mint(o) {
    o = o || {};
    var NB = o.notBefore || new Date("2026-01-01T00:00:00Z"), NA = o.notAfter || new Date("2027-01-01T00:00:00Z");
    var rsa = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
    var rootKp = await pki.webcrypto.subtle.generateKey(rsa, true, ["sign", "verify"]);
    var leafKp = await pki.webcrypto.subtle.generateKey(rsa, true, ["sign", "verify"]);
    var rootSpki = Buffer.from(await pki.webcrypto.subtle.exportKey("spki", rootKp.publicKey));
    var leafSpki = Buffer.from(await pki.webcrypto.subtle.exportKey("spki", leafKp.publicKey));
    var rootName = [{ commonName: "Test Google Internet Authority" }];
    var rootDer = await pki.x509.sign({
      subject: rootName, subjectPublicKey: rootSpki, serialNumber: Buffer.from([1]), notBefore: NB, notAfter: NA,
      extensions: { basicConstraints: { critical: true, cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
    }, { key: rootKp.privateKey, name: rootName, publicKey: rootSpki });
    var host = o.hostname || "attest.android.com";
    var leafExts = { keyUsage: ["digitalSignature"] };
    if (!o.noSan) leafExts.subjectAltName = [{ dNSName: host }];
    var leafDer = await pki.x509.sign({
      subject: [{ commonName: host }], subjectPublicKey: leafSpki, serialNumber: Buffer.from([2]), notBefore: NB, notAfter: NA,
      extensions: leafExts,
    }, { key: rootKp.privateKey, name: rootName, publicKey: rootSpki });

    var authData = (function () {
      var m = pki.cbor.read.map(pki.cbor.decode(attObj("packed")));
      for (var i = 0; i < m.length; i++) if (pki.cbor.read.textString(m[i][0]) === "authData") return m[i][1].content;
      throw new Error("no authData in the KAT");
    })();
    var cdh = clientHash("packed");
    // sec. 8.5 bullet 3: the nonce is STANDARD base64 (not base64url) of SHA-256(authData||cdh).
    var nonce = o.nonce !== undefined ? o.nonce
      : crypto.createHash("sha256").update(Buffer.concat([authData, cdh])).digest().toString("base64");
    var header = { alg: o.alg || "RS256",
      x5c: o.x5cRaw || (o.x5c || [leafDer, rootDer]).map(function (d) { return d.toString("base64"); }) };
    var payload = Object.assign({ nonce: nonce, timestampMs: 1767225600000, ctsProfileMatch: true, basicIntegrity: true }, o.payloadExtra || {});
    (o.payloadOmit || []).forEach(function (k) { delete payload[k]; });
    var h64 = b64uEnc(Buffer.from(JSON.stringify(header), "utf8"));
    var p64 = b64uEnc(Buffer.from(JSON.stringify(payload), "utf8"));
    var sig = Buffer.from(await pki.webcrypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" },
      (o.signWithRoot ? rootKp : leafKp).privateKey, Buffer.from(h64 + "." + p64, "ascii")));
    var jws = h64 + "." + p64 + "." + b64uEnc(o.badSig ? Buffer.alloc(sig.length, 9) : sig);
    var pairs = o.attStmtPairs || [[cText("ver"), cText("214516005")], [cText("response"), cBytes(Buffer.from(jws, "utf8"))]];
    return { attObj: attObjOf("android-safetynet", pairs, authData), cdh: cdh, rootDer: rootDer };
  }
  async function codeFor(mintOpts, optsOverride) {
    var f = await mint(mintOpts || {});
    var opts = Object.assign({ verifySafetyNetJws: true, safetyNetRoots: [f.rootDer], time: SN_TIME }, optsOverride || {});
    try { return await pki.webauthn.verify(f.attObj, f.cdh, opts); } catch (e) { return e.code || e.constructor.name; }
  }

  // The format is OFF unless the caller opts in, so the verdict for a caller who has not is
  // byte-identical to the one this format gave before the arm existed.
  var offCase = await mint({});
  check("safetynet: with the opt off the format is still unsupported",
    (await codeOfAsync(function () { return pki.webauthn.verify(offCase.attObj, offCase.cdh, {}); })) === "webauthn/unsupported-format");
  check("safetynet: opting in without a root is refused (no bundled root, no TOFU)",
    (await codeOfAsync(function () { return pki.webauthn.verify(offCase.attObj, offCase.cdh, { verifySafetyNetJws: true, time: SN_TIME }); })) === "webauthn/safetynet-no-root");
  check("safetynet: an empty root list is refused", (await codeFor({}, { safetyNetRoots: [] })) === "webauthn/safetynet-no-root");
  check("safetynet: a non-boolean opt is a config-time fault", (await codeFor({}, { verifySafetyNetJws: "yes" })) === "webauthn/bad-input");

  // sec. 8.5 bullet 5: a statement that satisfies every bind returns Basic with the x5c trust path.
  var okRes = await codeFor({});
  check("safetynet: a well-formed statement verifies as Basic with the x5c trust path",
    okRes && okRes.attestationVerified === true && okRes.fmt === "android-safetynet" &&
    okRes.attestationType === "Basic" && okRes.trustPath.length === 2);

  // A stored response's service chain has usually expired by the time the registration is examined,
  // which is why the format judges it at the signed timestamp rather than the current clock. A
  // later check of that SAME path -- the metadata anchor check -- has to use the same instant, or it
  // refuses the very registration the format verifier just accepted.
  // The chain here is genuinely expired now and valid only at the signed timestamp, so the vector
  // discriminates: an anchor check that reset the instant to the current clock would refuse it.
  var snStored = await mint({
    notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z"),
    payloadExtra: { timestampMs: Date.UTC(2020, 5, 1) },
  });
  var snRes = await pki.webauthn.verify(snStored.attObj, snStored.cdh,
    { verifySafetyNetJws: true, safetyNetRoots: [snStored.rootDer] });
  check("safetynet: the instant the chain was judged at is surfaced",
    snRes.chainValidatedAt instanceof Date && snRes.chainValidatedAt.getTime() === Date.UTC(2020, 5, 1));
  // android-safetynet binds the whole authenticatorData (the nonce is its digest), so the AAGUID is
  // signed and the entry is keyed by it.
  var snAaguid = snRes.aaguid.toString("hex").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
  var snBlob = await require("../helpers/mds-blob").mint({ aaguid: snAaguid,
    anchors: [snStored.rootDer.toString("base64")] });
  var snMd = await pki.webauthn.verifyMetadataBlob(snBlob.blob,
    { rootCertificates: [snBlob.rootDer], time: new Date("2026-06-01T00:00:00Z") });
  // No opts.time is given, so the anchor check must fall back to the instant the format established
  // from signed data rather than to "now" -- against which this chain expired years ago.
  check("safetynet: metadata binds a stored response at the instant its own format judged it",
    (await pki.webauthn.verify(snStored.attObj, snStored.cdh,
      { verifySafetyNetJws: true, safetyNetRoots: [snStored.rootDer], metadata: snMd })).attestationVerified === true);

  // Each bind, broken one at a time.
  check("safetynet: a nonce not bound to this registration is refused (bullet 3)",
    (await codeFor({ nonce: Buffer.alloc(32, 7).toString("base64") })) === "webauthn/safetynet-nonce-mismatch");
  check("safetynet: the nonce is standard base64, not base64url (bullet 3)",
    (await codeFor({ nonce: "not-the-right-nonce" })) === "webauthn/safetynet-nonce-mismatch");
  // A suffix of the expected name must not pass -- the match is exact, never a suffix or wildcard.
  check("safetynet: a leaf issued to another hostname is refused (bullet 4)",
    (await codeFor({ hostname: "attest.android.com.evil.test" })) === "webauthn/safetynet-bad-hostname");
  check("safetynet: a signature that does not verify is refused (bullet 4)",
    (await codeFor({ badSig: true })) === "webauthn/verify-failed");
  check("safetynet: a signature by a key other than the x5c leaf is refused (bullet 4)",
    (await codeFor({ signWithRoot: true })) === "webauthn/verify-failed");
  // The alg is pinned rather than read from the token -- the JWS algorithm-confusion class.
  check("safetynet: a JWS alg other than RS256 is refused",
    (await codeFor({ alg: "HS256" })) === "webauthn/unsupported-algorithm");
  check("safetynet: a header with no x5c chain is refused",
    (await codeFor({ x5c: [] })) === "webauthn/bad-att-stmt");
  // The hostname alone proves nothing: the chain must reach the root the CALLER supplied.
  var unrelated = await mint({});
  var subject = await mint({});
  check("safetynet: a chain that does not reach the supplied root is refused (bullet 4)",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(subject.attObj, subject.cdh,
        { verifySafetyNetJws: true, safetyNetRoots: [unrelated.rootDer], time: SN_TIME });
    })) === "webauthn/safetynet-cert-untrusted");
  check("safetynet: a chain outside its validity window is refused",
    (await codeFor({}, { time: new Date("2030-01-01T00:00:00Z") })) === "webauthn/safetynet-cert-untrusted");
  check("safetynet: a supplied root that is not a certificate is a config-time fault",
    (await codeFor({}, { safetyNetRoots: [Buffer.from([1, 2, 3])] })) === "webauthn/bad-input");
  // sec. 8.5 syntax: attStmt is exactly {ver, response} -- an extra field is a non-canonical
  // statement, refused before any field is trusted.
  check("safetynet: an attStmt carrying an unexpected field is refused",
    (await codeFor({ attStmtPairs: [[cText("ver"), cText("1")], [cText("response"), cBytes(Buffer.from("a.b.c", "utf8"))], [cText("extra"), cText("x")]] })) === "webauthn/bad-att-stmt");

  // ---- the certificate chain is bounded by COUNT, not only by entry size ----
  // Capping each entry's bytes does not bound how many there are, and each one costs a DER parse
  // and, downstream, a path validation. A chain longer than any real attestation is refused.
  var many = [];
  for (var mc = 0; mc < 11; mc++) many.push("AA==");
  check("safetynet: an x5c chain longer than the parse bound is refused",
    (await codeFor({ x5cRaw: many })) === "webauthn/bad-att-stmt");

  // ---- a JWS segment must be a JSON OBJECT ----
  // null, a number, a string and an array are all valid JSON, so the parse succeeds and any later
  // field read would escape this module's typed contract as a raw TypeError.
  function rawJws(headerJson, payloadJson) {
    var h = b64uEnc(Buffer.from(headerJson, "utf8")), p = b64uEnc(Buffer.from(payloadJson, "utf8"));
    return { attStmtPairs: [[cText("ver"), cText("1")],
      [cText("response"), cBytes(Buffer.from(h + "." + p + "." + b64uEnc(Buffer.alloc(8)), "utf8"))]] };
  }
  var nonObject = ["null", "42", "\"text\"", "[1,2]"];
  for (var nj = 0; nj < nonObject.length; nj++) {
    var asHeader = await codeFor(rawJws(nonObject[nj], "{}"));
    var asPayload = await codeFor(rawJws(JSON.stringify({ alg: "RS256", x5c: ["AA=="] }), nonObject[nj]));
    check("safetynet: a JWS header that is JSON " + nonObject[nj] + " is refused typed",
      asHeader === "webauthn/bad-att-stmt");
    check("safetynet: a JWS payload that is JSON " + nonObject[nj] + " is refused typed",
      asPayload === "webauthn/bad-att-stmt" || asPayload === "webauthn/bad-att-cert");
  }

  // ---- when the chain is judged ----
  // These attestations are historical, so a leaf valid at signing time is routinely expired now.
  // The signed timestamp in the response is what the chain is judged against by default, and an
  // explicit opts.time overrides it.
  var past = await mint({
    notBefore: new Date("2020-01-01T00:00:00Z"), notAfter: new Date("2021-01-01T00:00:00Z"),
    payloadExtra: { timestampMs: Date.UTC(2020, 5, 1) },
  });
  var histRes = await pki.webauthn.verify(past.attObj, past.cdh,
    { verifySafetyNetJws: true, safetyNetRoots: [past.rootDer] });
  check("safetynet: a stored attestation whose chain has since expired still verifies at its signed time",
    histRes.attestationVerified === true);
  check("safetynet: an explicit opts.time overrides the signed timestamp and refuses out of window",
    (await codeOfAsync(function () {
      return pki.webauthn.verify(past.attObj, past.cdh,
        { verifySafetyNetJws: true, safetyNetRoots: [past.rootDer], time: new Date("2026-06-01T00:00:00Z") });
    })) === "webauthn/safetynet-cert-untrusted");

  // ---- device-integrity signals: surfaced, and enforced only on request ----
  // The sec. 8.5 verification procedure never mentions these, so the attestation verdict does not
  // turn on them -- but a relying party cannot apply its own policy to a signal it never sees, so
  // they are surfaced, and a caller that asks for enforcement gets it.
  var failedCts = await codeFor({ payloadExtra: { ctsProfileMatch: false, basicIntegrity: false } });
  check("safetynet: a device that failed the compatibility suite still verifies per sec. 8.5",
    failedCts && failedCts.attestationVerified === true);
  check("safetynet: ... and the failing signals are surfaced for relying-party policy",
    failedCts.safetyNet.ctsProfileMatch === false && failedCts.safetyNet.basicIntegrity === false);
  check("safetynet: a passing device surfaces its signals too",
    (await codeFor({})).safetyNet.ctsProfileMatch === true);
  check("safetynet: opts.requireCtsProfileMatch refuses a device that failed",
    (await codeFor({ payloadExtra: { ctsProfileMatch: false } }, { requireCtsProfileMatch: true })) === "webauthn/safetynet-cts-profile");
  check("safetynet: opts.requireCtsProfileMatch refuses a response that omits the signal",
    (await codeFor({ payloadOmit: ["ctsProfileMatch"] }, { requireCtsProfileMatch: true })) === "webauthn/safetynet-cts-profile");
  check("safetynet: opts.requireCtsProfileMatch accepts a device that passed",
    (await codeFor({}, { requireCtsProfileMatch: true })).attestationVerified === true);
  check("safetynet: a non-boolean requireCtsProfileMatch is a config-time fault",
    (await codeFor({}, { requireCtsProfileMatch: "yes" })) === "webauthn/bad-input");

  // ---- the remaining x5c / anchor shapes ----
  // An x5c entry is standard base64 of one DER certificate; neither half may be assumed.
  check("safetynet: an x5c entry that is not canonical base64 is refused",
    (await codeFor({ x5cRaw: ["not!base64!"] })) === "webauthn/bad-att-stmt");
  check("safetynet: an x5c entry that is not a certificate is refused",
    (await codeFor({ x5cRaw: [Buffer.from([1, 2, 3, 4]).toString("base64")] })) === "webauthn/bad-att-cert");
  check("safetynet: an x5c entry that is not a string is refused",
    (await codeFor({ x5cRaw: [42] })) === "webauthn/bad-att-stmt");
  // The response must be a three-part JWS compact serialization (RFC 7515 sec. 3.1) before any
  // field inside it is read -- an empty, mis-segmented, or undecodable response never reaches the
  // signature or the nonce.
  function rawResponse(text) {
    return { attStmtPairs: [[cText("ver"), cText("1")], [cText("response"), cBytes(Buffer.from(text, "utf8"))]] };
  }
  check("safetynet: an empty response is refused", (await codeFor(rawResponse(""))) === "webauthn/bad-att-stmt");
  check("safetynet: a response that is not three segments is refused",
    (await codeFor(rawResponse("only.two"))) === "webauthn/bad-att-stmt");
  check("safetynet: a response whose segments do not decode is refused",
    (await codeFor(rawResponse("!!!.@@@.###"))) === "webauthn/bad-att-stmt");
  // A leaf with no subjectAltName at all falls back to the commonName, the way hostname matching
  // has been specified since RFC 6125 -- and it still has to be the right name.
  // When a SAN is present it is authoritative and the commonName is not consulted: a leaf naming the
  // host ONLY in its SAN must verify, and one naming it only in a commonName it contradicts must not.
  var sanOnly = await codeFor({ cn: "wrong.example" });
  check("safetynet: a leaf naming the host in its SAN verifies even when the commonName differs",
    sanOnly && sanOnly.attestationVerified === true);
  check("safetynet: a SAN that names another host is refused even when the commonName is right",
    (await codeFor({ hostname: "other.example", cn: "attest.android.com" })) === "webauthn/safetynet-bad-hostname");
  var noSanOk = await codeFor({ noSan: true });
  check("safetynet: a leaf naming the host only in its commonName verifies",
    noSanOk && noSanOk.attestationVerified === true && noSanOk.attestationType === "Basic");
  check("safetynet: a leaf whose commonName is another host is refused",
    (await codeFor({ noSan: true, hostname: "other.example" })) === "webauthn/safetynet-bad-hostname");
  // opts.time is optional; omitted, the chain is checked against now rather than the check being
  // skipped. The refusal side of the same branch is pinned by the explicit-time vector above ("a
  // chain outside its validity window is refused"), so an absent time cannot mean "do not check".
  var noTime = await mint({});
  var noTimeRes = await pki.webauthn.verify(noTime.attObj, noTime.cdh,
    { verifySafetyNetJws: true, safetyNetRoots: [noTime.rootDer] });
  check("safetynet: with no opts.time a currently-valid chain verifies", noTimeRes.attestationVerified === true);
  // A root may be handed over already parsed, not only as DER.
  var parsedRoot = await mint({});
  var parsedRes = await pki.webauthn.verify(parsedRoot.attObj, parsedRoot.cdh,
    { verifySafetyNetJws: true, safetyNetRoots: [pki.schema.x509.parse(parsedRoot.rootDer)], time: SN_TIME });
  check("safetynet: a root supplied as a parsed certificate is accepted", parsedRes.attestationVerified === true);
  check("safetynet: a root that is neither DER nor a certificate is a config-time fault",
    (await codeFor({}, { safetyNetRoots: [{}] })) === "webauthn/bad-input");
  // Several anchors are tried in turn, so a caller holding a rotation set is not forced to guess
  // which one applies -- and the first that validates ends the search.
  var multi = await mint({});
  var spare = await mint({});
  var firstOk = await pki.webauthn.verify(multi.attObj, multi.cdh,
    { verifySafetyNetJws: true, safetyNetRoots: [multi.rootDer, spare.rootDer], time: SN_TIME });
  check("safetynet: the first matching root of several ends the search", firstOk.attestationVerified === true);
  var secondOk = await pki.webauthn.verify(multi.attObj, multi.cdh,
    { verifySafetyNetJws: true, safetyNetRoots: [spare.rootDer, multi.rootDer], time: SN_TIME });
  check("safetynet: a later root in the list still anchors the chain", secondOk.attestationVerified === true);
}

// ---- clientDataJSON (WebAuthn sec. 5.8.1 / 7.1 / 7.2) -----------------------------------------
// The half of a response the signature covers by DIGEST and no signature check ever looks inside.
// These are attacker-chosen bytes, so the parse is fail-closed; the comparisons are the relying
// party's own state, so they run when the caller supplies it and say so when they did.
async function testClientData() {
  var cd = _clientDataJson({});
  var parsed = pki.webauthn.parseClientData(cd);
  check("clientData: type / origin / crossOrigin come back as they were",
    parsed.type === "webauthn.get" && parsed.origin === "https://example.com" && parsed.crossOrigin === false);
  check("clientData: the challenge comes back DECODED, so a caller compares bytes not spellings",
    Buffer.isBuffer(parsed.challenge) && parsed.challenge.equals(Buffer.alloc(16, 4)));
  check("clientData: with nothing to compare against, no comparison claims to have run",
    parsed.checked.type === false && parsed.checked.challenge === false && parsed.checked.origin === false);

  var bound = pki.webauthn.parseClientData(cd, { expectedType: "webauthn.get",
    expectedChallenge: Buffer.alloc(16, 4), expectedOrigin: "https://example.com" });
  check("clientData: the comparisons that ran are the ones reported",
    bound.checked.type === true && bound.checked.challenge === true && bound.checked.origin === true);
  check("clientData: an array of acceptable origins is accepted",
    pki.webauthn.parseClientData(cd, { expectedOrigin: ["https://other.example", "https://example.com"] })
      .checked.origin === true);

  // A registration response replayed into a login. Which ceremony a response belongs to is fixed by
  // the spec, not negotiated, so this is a refusal rather than a policy knob.
  check("clientData: a webauthn.create response is refused where a login was expected",
    codeOf(function () { return pki.webauthn.parseClientData(_clientDataJson({ type: "webauthn.create" }), { expectedType: "webauthn.get" }); })
      === "webauthn/client-data-mismatch");
  check("clientData: a challenge that is not the one issued is refused",
    codeOf(function () { return pki.webauthn.parseClientData(cd, { expectedChallenge: Buffer.alloc(16, 5) }); })
      === "webauthn/client-data-mismatch");
  // The origin is compared WHOLE. A prefix or suffix test is how a look-alike host passes.
  check("clientData: a look-alike origin does not match by prefix",
    codeOf(function () { return pki.webauthn.parseClientData(_clientDataJson({ origin: "https://example.com.attacker.tld" }), { expectedOrigin: "https://example.com" }); })
      === "webauthn/client-data-mismatch");
  check("clientData: an unknown ceremony type is refused outright",
    codeOf(function () { return pki.webauthn.parseClientData(Buffer.from(JSON.stringify({ type: "webauthn.sign", challenge: "AQID", origin: "https://example.com" }), "utf8")); })
      === "webauthn/bad-client-data");
  check("clientData: a challenge that is not base64url is refused",
    codeOf(function () { return pki.webauthn.parseClientData(Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: "not base64!", origin: "https://example.com" }), "utf8")); })
      === "webauthn/bad-client-data");
  check("clientData: malformed JSON is refused, not guessed at",
    codeOf(function () { return pki.webauthn.parseClientData(Buffer.from("{\"type\":", "utf8")); }) === "webauthn/bad-client-data");
  // A present-but-malformed member must not arrive looking like an absent one: a
  // caller making a cross-origin policy decision on topOrigin would read "the sender
  // wrote something that is not an origin" as "the sender said nothing".
  check("clientData: a topOrigin that is not a string is refused, not reported as absent",
    codeOf(function () { return pki.webauthn.parseClientData(Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: "AQID", origin: "https://example.com", topOrigin: 7 }), "utf8")); })
      === "webauthn/bad-client-data");
  check("clientData: a real topOrigin comes back",
    pki.webauthn.parseClientData(Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: "AQID", origin: "https://inner.example", topOrigin: "https://example.com" }), "utf8")).topOrigin === "https://example.com");

  check("clientData: a parsed object is refused -- the RAW bytes are what the digest covers",
    codeOf(function () { return pki.webauthn.parseClientData({ type: "webauthn.get" }); }) === "webauthn/bad-input");
}

// ---- assertion verification (WebAuthn sec. 7.2) -----------------------------------------------
// The half of WebAuthn every login runs. The authenticator signs authenticatorData ||
// SHA-256(clientDataJSON) as RAW bytes -- no COSE_Sign1 wrapper -- with an ES256 signature in
// ASN.1 DER, so a COSE message verifier is the wrong tool and fails on structure first.
async function testAssertion() {
  var ad = _assertAuthData({ uv: true });
  var cd = _clientDataJson({});
  var sig = _assertSig(ad, cd);
  var stored = pki.webauthn.parseAuthenticatorData(
    Buffer.concat([_sha256(Buffer.from("example.com", "utf8")), Buffer.from([0x41]), _u32(5),
      Buffer.alloc(16, 2), _u16(16), Buffer.alloc(16, 3), _EC_COSE])).credentialPublicKey;

  check("assertion: a bare authenticatorData parses without an attestation-object wrapper",
    pki.webauthn.parseAuthenticatorData(ad).signCount === 9 &&
    pki.webauthn.parseAuthenticatorData(ad).flags.at === false);

  var res = await pki.webauthn.verifyAssertion({ authenticatorData: ad, clientDataJSON: cd,
    signature: sig, credentialPublicKey: stored });
  check("assertion: a genuine signature over authenticatorData || SHA-256(clientDataJSON) verifies",
    res.signatureVerified === true && res.signCount === 9);
  check("assertion: the field is signatureVerified, never a bare `verified`", res.verified === undefined);
  check("assertion: the ceremony type is checked whenever the JSON is supplied",
    res.clientData.checked.type === true && res.clientData.type === "webauthn.get");
  check("assertion: a counter not compared says so rather than implying it passed",
    res.signCountChecked === false);

  check("assertion: a signature over other bytes does not verify",
    (await codeOfAsync(function () {
      return pki.webauthn.verifyAssertion({ authenticatorData: _assertAuthData({ signCount: 10 }),
        clientDataJSON: cd, signature: sig, credentialPublicKey: stored });
    })) === "webauthn/bad-signature");

  // sec. 7.2 step 21: a counter that fails to advance is the signal of a cloned authenticator.
  check("assertion: previousSignCount refuses a counter that does not advance",
    (await codeOfAsync(function () {
      return pki.webauthn.verifyAssertion({ authenticatorData: ad, clientDataJSON: cd, signature: sig,
        credentialPublicKey: stored, previousSignCount: 9 });
    })) === "webauthn/sign-count-not-advanced");
  // ... and only from an AUTHENTIC assertion. A counter that fails to advance means
  // two authenticators hold one credential -- an alarm a relying party acts on. If it
  // were judged before the signature, anyone could raise that alarm with arbitrary
  // bytes and have a credential revoked.
  check("assertion: a bad signature is reported as such, never as a cloned authenticator",
    (await codeOfAsync(function () {
      return pki.webauthn.verifyAssertion({ authenticatorData: ad, clientDataJSON: cd,
        signature: Buffer.alloc(sig.length, 0x41), credentialPublicKey: stored, previousSignCount: 99 });
    })) === "webauthn/bad-signature");

  check("assertion: a counter that advances is accepted and reported as checked",
    (await pki.webauthn.verifyAssertion({ authenticatorData: ad, clientDataJSON: cd, signature: sig,
      credentialPublicKey: stored, previousSignCount: 8 })).signCountChecked === true);
  // An authenticator that implements no counter reports 0 forever, which the spec permits.
  var zeroAd = _assertAuthData({ signCount: 0 });
  var zeroCd = _clientDataJson({});
  check("assertion: the 0/0 case an authenticator without a counter reports is accepted",
    (await pki.webauthn.verifyAssertion({ authenticatorData: zeroAd, clientDataJSON: zeroCd,
      signature: _assertSig(zeroAd, zeroCd), credentialPublicKey: stored, previousSignCount: 0 })).signCount === 0);

  check("assertion: expectedRpId refuses a response produced for another relying party",
    (await codeOfAsync(function () {
      var other = _assertAuthData({ rpId: "attacker.example" });
      return pki.webauthn.verifyAssertion({ authenticatorData: other, clientDataJSON: cd,
        signature: _assertSig(other, cd), credentialPublicKey: stored, expectedRpId: "example.com" });
    })) === "webauthn/rp-id-mismatch");
  check("assertion: requireUserVerification refuses a UV-clear response",
    (await codeOfAsync(function () {
      var noUv = _assertAuthData({});
      return pki.webauthn.verifyAssertion({ authenticatorData: noUv, clientDataJSON: cd,
        signature: _assertSig(noUv, cd), credentialPublicKey: stored, requireUserVerification: true });
    })) === "webauthn/user-verification-required");

  // A registration response replayed as a login, driven through the shipped verb.
  check("assertion: a webauthn.create clientData is refused as a login response",
    (await codeOfAsync(function () {
      var regCd = _clientDataJson({ type: "webauthn.create" });
      return pki.webauthn.verifyAssertion({ authenticatorData: ad, clientDataJSON: regCd,
        signature: _assertSig(ad, regCd), credentialPublicKey: stored });
    })) === "webauthn/client-data-mismatch");

  // The digest form stays available for a caller that computed it -- but the checks that read the
  // JSON cannot be claimed over bytes this call never saw.
  check("assertion: the clientDataHash form still verifies",
    (await pki.webauthn.verifyAssertion({ authenticatorData: ad, clientDataHash: _sha256(cd),
      signature: sig, credentialPublicKey: stored })).signatureVerified === true);
  check("assertion: expectedChallenge without the JSON is refused rather than silently skipped",
    (await codeOfAsync(function () {
      return pki.webauthn.verifyAssertion({ authenticatorData: ad, clientDataHash: _sha256(cd),
        signature: sig, credentialPublicKey: stored, expectedChallenge: Buffer.alloc(16, 4) });
    })) === "webauthn/bad-input");
  check("assertion: supplying BOTH clientDataJSON and clientDataHash is refused as ambiguous",
    (await codeOfAsync(function () {
      return pki.webauthn.verifyAssertion({ authenticatorData: ad, clientDataJSON: cd,
        clientDataHash: _sha256(cd), signature: sig, credentialPublicKey: stored });
    })) === "webauthn/bad-input");
  // The descriptor and its buffers are the CALLER's memory, and verification runs a
  // microtask later. A caller that reuses or zeroizes them on the next line would
  // otherwise have the verification read what it wrote -- so an assertion that did
  // not verify could be swapped for one that does, after the call was made.
  var liveAd = Buffer.from(ad), liveCd = Buffer.from(cd), liveSig = Buffer.from(sig);
  var live = { authenticatorData: liveAd, clientDataJSON: liveCd, signature: liveSig,
    credentialPublicKey: stored };
  var livePromise = pki.webauthn.verifyAssertion(live);
  liveAd.fill(0); liveCd.fill(0); liveSig.fill(0);          // zeroized on the very next line
  live.credentialPublicKey = {};
  var liveRes = null, liveErr = null;
  try { liveRes = await livePromise; } catch (e) { liveErr = e; }
  check("assertion: buffers zeroized after the call do not change what was verified",
    liveErr === null && liveRes.signatureVerified === true && liveRes.signCount === 9);

  // ...and the same in the direction that matters: a FAILING assertion cannot be
  // rescued by writing a good one into the caller's buffers after the call.
  var badSig = Buffer.alloc(sig.length, 0x41);
  var swap = { authenticatorData: Buffer.from(ad), clientDataJSON: Buffer.from(cd),
    signature: badSig, credentialPublicKey: stored };
  var swapPromise = pki.webauthn.verifyAssertion(swap);
  sig.copy(badSig);                                         // the good signature, too late
  check("assertion: a good signature written in after the call does not rescue a bad one",
    (await codeOfAsync(function () { return swapPromise; })) === "webauthn/bad-signature");

  check("assertion: an unknown input key is refused rather than silently ignored",
    (await codeOfAsync(function () {
      return pki.webauthn.verifyAssertion({ authenticatorData: ad, clientDataJSON: cd, signature: sig,
        credentialPublicKey: stored, requireUserPrescence: true });
    })) === "webauthn/bad-input");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
