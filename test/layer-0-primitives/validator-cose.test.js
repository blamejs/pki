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

function run() {
  // Accept path: a canonical ES256 (alg -7) EC2 key decodes + validates + on-curve.
  check("credentialKey accepts a canonical ES256 EC2 key",
    code(function () { credKey([kv(1, cInt(2)), kv(3, cInt(-7)), kv(-1, cInt(1)), kv(-2, cBytes(P256_X)), kv(-3, cBytes(P256_Y))]); }) === "NO-THROW");

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

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
