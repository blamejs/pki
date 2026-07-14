// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- validator-cose (@internal): the COSE_Key conformance gate a WebAuthn
 * credential key routes through (RFC 9052 sec. 7 + WebAuthn sec. 6.5.1 + CTAP2
 * canonical form + on-curve). The `@enforced-by behavioral` contract is that the
 * MUST-reject vectors ARE the guard, so this drives credentialKey() directly with a
 * crafted COSE_Key for each rejection, exactly as the tpm/sig validators are pinned.
 */

var crypto = require("crypto");
var cose = require("../../lib/validator-cose");
var pkicbor = require("../../lib/cbor-det");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError", { withCause: true });
function E(code, message, cause) { return new TestError(code, message, cause); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

// Minimal canonical-CBOR builders (mirroring the webauthn test's).
function cHead(major, n) {
  n = Number(n);
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  var b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b;
}
function cInt(n) { return n < 0 ? cHead(1, -1 - n) : cHead(0, n); }
function cBytes(buf) { return Buffer.concat([cHead(2, buf.length), buf]); }
function cMap(pairs) {
  var e = pairs.slice().sort(function (a, b) { return Buffer.compare(a[0], b[0]); });
  var out = [cHead(5, pairs.length)];
  e.forEach(function (p) { out.push(p[0], p[1]); });
  return Buffer.concat(out);
}
function kv(label, v) { return [cInt(label), v]; }
function decode(buf) { return pkicbor.decode(buf); }
function credKey(pairs) { return cose.credentialKey(decode(cMap(pairs)), E, "cose/bad"); }

// A real P-256 point for the valid-key + accept path.
var jwk = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
var P256_X = Buffer.from(jwk.x, "base64url"), P256_Y = Buffer.from(jwk.y, "base64url");
// Real OKP (Ed25519/Ed448) + RSA public keys for the valid-key + toSpki self-sufficiency
// paths -- generated the same way webauthn.test.js builds its KAT keys, so this file
// exercises the OKP/RSA credentialKey + toSpki forms without webauthn's attestation flow.
var ED25519_X = Buffer.from(crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x, "base64url");
var ED448_X = Buffer.from(crypto.generateKeyPairSync("ed448").publicKey.export({ format: "jwk" }).x, "base64url");
var rsaJwk = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" });
var RSA_N = Buffer.from(rsaJwk.n, "base64url"), RSA_E = Buffer.from(rsaJwk.e, "base64url");

function run() {
  // Accept path: a canonical ES256 (alg -7) EC2 key decodes + validates + on-curve.
  check("credentialKey accepts a canonical ES256 EC2 key",
    code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-7)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]); }) === "NO-THROW");

  // Self-sufficiency happy paths: a valid key of each accepted kty resolves to the expected
  // key AND builds an importable SPKI. The OKP/RSA validate + toSpki forms are otherwise
  // reached only through webauthn.test.js's KATs; pinning them here keeps this module's own
  // branch coverage standalone.
  var ec2Key = credKey([kv(1, cInt(2)), kv(3, cInt(-7)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]);
  check("credentialKey resolves a canonical ES256 EC2 key",
    ec2Key.kty === 2 && ec2Key.crv === 1 && ec2Key.x.length === 32 && ec2Key.y.length === 32);
  check("toSpki builds an importable EC2 SPKI",
    code(function () { crypto.createPublicKey({ key: cose.toSpki(ec2Key, E, "cose/bad"), format: "der", type: "spki" }); }) === "NO-THROW");

  var ed25519Key = credKey([kv(1, cInt(1)), kv(3, cInt(-8)), kv(-1, cInt(6)), kv(-2, cBytes(ED25519_X))]);
  check("credentialKey resolves a canonical Ed25519 OKP key",
    ed25519Key.kty === 1 && ed25519Key.crv === 6 && ed25519Key.x.length === 32);
  check("toSpki builds an importable Ed25519 SPKI",
    code(function () { crypto.createPublicKey({ key: cose.toSpki(ed25519Key, E, "cose/bad"), format: "der", type: "spki" }); }) === "NO-THROW");

  var ed448Key = credKey([kv(1, cInt(1)), kv(3, cInt(-53)), kv(-1, cInt(7)), kv(-2, cBytes(ED448_X))]);
  check("credentialKey resolves a canonical Ed448 OKP key",
    ed448Key.kty === 1 && ed448Key.crv === 7 && ed448Key.x.length === 57);
  check("toSpki builds an importable Ed448 SPKI",
    code(function () { crypto.createPublicKey({ key: cose.toSpki(ed448Key, E, "cose/bad"), format: "der", type: "spki" }); }) === "NO-THROW");

  var rsaKey = credKey([kv(1, cInt(3)), kv(3, cInt(-257)), kv(-1, cBytes(RSA_N)), kv(-2, cBytes(RSA_E))]);
  check("credentialKey resolves a canonical RS256 RSA key",
    rsaKey.kty === 3 && rsaKey.n.length > 0 && rsaKey.e.length > 0);
  check("toSpki builds an importable RSA SPKI",
    code(function () { crypto.createPublicKey({ key: cose.toSpki(rsaKey, E, "cose/bad"), format: "der", type: "spki" }); }) === "NO-THROW");

  // A non-map COSE_Key is rejected.
  check("a non-map COSE_Key is rejected", code(function () { cose.credentialKey(decode(cInt(5)), E, "cose/bad"); }) === "cose/bad");
  // Missing kty (label 1) / alg (label 3).
  check("a COSE_Key missing kty is rejected", code(function () { credKey([kv(3, cInt(-7)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]); }) === "cose/bad");
  check("a COSE_Key missing alg is rejected", code(function () { credKey([kv(1, cInt(2)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]); }) === "cose/bad");
  // A wrong-typed parameter (crv as a byte string, not an integer).
  check("a wrong-typed COSE parameter is rejected", code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-7)), kv(-1, cBytes(Buffer.from([1]))), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]); }) === "cose/bad");
  // A compressed EC point (y as a CBOR bool, major 7) is rejected.
  check("a compressed EC2 point (y sign-bit) is rejected", code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-7)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, Buffer.from([0xf5]))]); }) === "cose/bad");
  // An EC2 x/y whose length disagrees with the curve.
  check("an EC2 x/y length inconsistent with the curve is rejected", code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-7)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X.subarray(0, 16))), kv(-3, cBytes(P256_Y))]); }) === "cose/bad");
  // An RSA (kty 3) key missing n or e.
  check("an RSA COSE_Key missing e is rejected", code(function () { credKey([kv(1, cInt(3)), kv(3, cInt(-257)), kv(-1, cBytes(Buffer.alloc(256, 1)))]); }) === "cose/bad");
  // A non-canonical key: an extra parameter beyond the type's canonical set.
  check("a COSE_Key with a parameter beyond the canonical set is rejected", code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-7)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y)), kv(-4, cInt(0))]); }) === "cose/bad");
  // An unsupported algorithm, and an alg/key-type / alg/curve mismatch.
  check("an unsupported credential-key algorithm is rejected", code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-999)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]); }) === "cose/bad");
  check("an EC2 key whose alg demands a different key type is rejected", code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-257)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]); }) === "cose/bad");
  check("an EC2 key whose alg demands a different curve is rejected", code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-35)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]); }) === "cose/bad");
  // An unsupported kty entirely.
  check("an unsupported COSE_Key kty is rejected", code(function () { credKey([kv(1, cInt(9)), kv(3, cInt(-7)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X))]); }) === "cose/bad");
  // An EC2 (kty 2) key that carries x/y but omits crv (-1): rejected before the on-curve gate.
  check("an EC2 COSE_Key missing crv (-1) is rejected",
    code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-7)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]); }) === "cose/bad");
  // An OKP (kty 1) key that carries x but omits crv (-1): OKP_CRV[null] is undefined, rejected.
  check("an OKP COSE_Key missing crv (-1) is rejected",
    code(function () { credKey([kv(1, cInt(1)), kv(3, cInt(-8)), kv(-2, cBytes(Buffer.alloc(32)))]); }) === "cose/bad");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
