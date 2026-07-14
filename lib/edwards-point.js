// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// @internal -- no operator-facing namespace. Composed by validator-cose to validate an
// OKP (Ed25519 / Ed448) credential public-key point.
//
// edwards-point -- point validation for the Edwards curves EdDSA uses. node:crypto imports
// an RFC 8410 OKP SubjectPublicKeyInfo WITHOUT checking the point is a valid, full-order
// Edwards point (an all-zeroes Ed25519/Ed448 key parses, and an all-zeroes key with an
// all-zeroes signature even verifies TRUE -- a trivial forgery), so an OKP credential key
// needs an explicit check. This decodes the compressed point per RFC 8032 sec. 5.1.3
// (Ed25519) / sec. 5.2.3 (Ed448) -- which fails closed on an off-curve or non-canonical
// encoding -- and rejects a low-order point via the cofactor check [8]P == identity (an
// all-zeroes key is a low-order point ON the curve, so the decode alone does not catch it).
// A conformant authenticator never emits a low-order credential key.
//
// Pure BigInt modular arithmetic (constant-time is not a goal here: the input is a public
// key, and the verdict is a public validity bit, not a secret).

var asn1 = require("./asn1-der");

// ---- field parameters ------------------------------------------------------
var P25519 = (1n << 255n) - 19n;
// d = -121665 / 121666 (mod p); sqrt(-1) = 2^((p-1)/4) (mod p).
var D25519 = _mul(P25519 - 121665n, _inv(121666n, P25519), P25519);
var SQRTM1 = _pow(2n, (P25519 - 1n) / 4n, P25519);
var P448 = (1n << 448n) - (1n << 224n) - 1n;
var D448 = P448 - 39081n;   // d = -39081 (mod p)

var CURVE = {
  6: { p: P25519, d: D25519, a: P25519 - 1n, len: 32, signBit: 255n },   // Ed25519, a = -1
  7: { p: P448, d: D448, a: 1n, len: 57, signBit: 455n },                // Ed448, a = 1
};

function _mul(x, y, p) { return (x % p) * (y % p) % p; }
function _pow(b, e, p) { var r = 1n; b %= p; while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; } return r; }
function _inv(a, p) { return _pow(((a % p) + p) % p, p - 2n, p); }   // Fermat inverse (p prime)
// A fixed 32/57-byte little-endian public key -> BigInt in one shot (big-endian hex of the
// reversed bytes), never a per-byte shift-accumulate (the quadratic-BigInt antipattern).
function _leToBig(buf) { return BigInt("0x" + Buffer.from(buf).reverse().toString("hex")); }

// Decode a compressed Edwards point (RFC 8032) -> { x, y } or null (off-curve / non-canonical).
function _decode(raw, c) {
  var num = _leToBig(raw);
  var sign = (num >> c.signBit) & 1n;
  var y = num & ((1n << c.signBit) - 1n);
  if (y >= c.p) return null;   // non-canonical y
  var p = c.p, y2 = y * y % p, x;
  var u = ((y2 - 1n) % p + p) % p;
  if (c.a === 1n) {
    // Ed448: v = d*y^2 - 1; x = u^3 v (u^5 v^3)^((p-3)/4); require v*x^2 == u.
    var v = ((c.d * y2 % p - 1n) % p + p) % p;
    x = _mul(_mul(_pow(u, 3n, p), v, p), _pow(_mul(_pow(u, 5n, p), _pow(v, 3n, p), p), (p - 3n) / 4n, p), p);
    if (_mul(v, x * x % p, p) !== u) return null;
  } else {
    // Ed25519: v = d*y^2 + 1; x = u v^3 (u v^7)^((p-5)/8); v*x^2 == u, or == -u then x *= sqrt(-1).
    var v25 = (c.d * y2 % p + 1n) % p;
    x = _mul(_mul(u, _pow(v25, 3n, p), p), _pow(_mul(u, _pow(v25, 7n, p), p), (p - 5n) / 8n, p), p);
    var vxx = _mul(v25, x * x % p, p);
    if (vxx === u) { /* x is a root */ }
    else if (vxx === (p - u) % p) { x = x * SQRTM1 % p; }
    else return null;
  }
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = (p - x) % p;
  return { x: x, y: y };
}

// Affine doubling on a*x^2 + y^2 = 1 + d*x^2*y^2: x3 = 2xy/(a x^2 + y^2),
// y3 = (y^2 - a x^2)/(2 - a x^2 - y^2).
function _double(P, c) {
  var p = c.p, x2 = P.x * P.x % p, y2 = P.y * P.y % p, ax2 = c.a * x2 % p;
  var nx = 2n * P.x % p * P.y % p, dx = (ax2 + y2) % p;
  var ny = ((y2 - ax2) % p + p) % p, dy = ((2n - ax2 - y2) % p + 2n * p) % p;
  return { x: _mul(nx, _inv(dx, p), p), y: _mul(ny, _inv(dy, p), p) };
}

// validate(raw, crv) -> true iff `raw` is a canonical, on-curve, full-order Edwards point for
// the OKP curve (6 = Ed25519, 7 = Ed448). Off-curve, non-canonical, wrong-length, and
// low-order (cofactor) points all return false.
function validate(raw, crv) {
  var c = CURVE[crv];
  if (!c || !Buffer.isBuffer(raw) || raw.length !== c.len) return false;
  var pt = _decode(raw, c);
  if (!pt) return false;
  // Low-order iff [8]P is the identity (0, 1). One double per cofactor bit (8 = 2^3).
  var q = _double(_double(_double(pt, c), c), c);
  if (q.x === 0n && q.y === 1n) return false;
  return true;
}

// validateSpki(spkiBytes, crv, E, code) -> throws new E(code, ...) unless the
// SubjectPublicKeyInfo's subjectPublicKey (its BIT STRING body, past the unused-bits octet) is a
// canonical, on-curve, full-order Edwards point for the OKP curve (6 = Ed25519, 7 = Ed448). This
// is the one home every EdDSA verify path routes an SPKI through before importKey/verify -- node
// imports a low-order (e.g. all-zeroes) OKP SPKI without complaint and such a key verifies a
// forged signature. Error-parameterized like the guard family: the caller passes its own typed
// error CONSTRUCTOR `E` and domain `code`, so the shared gate keeps no error domain of its own.
function validateSpki(spkiBytes, crv, E, code) {
  var point;
  try {
    point = asn1.decode(spkiBytes).children[1].content.subarray(1);
  } catch (e) { throw new E(code, "the EdDSA public key is not a well-formed SubjectPublicKeyInfo", e); }
  if (!validate(point, crv)) {
    throw new E(code, "the EdDSA public key is not a valid, full-order Edwards point");
  }
}

module.exports = { validate: validate, validateSpki: validateSpki };
