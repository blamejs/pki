// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

var asn1 = require("./asn1-der");

var P25519 = (1n << 255n) - 19n;
var D25519 = _mul(P25519 - 121665n, _inv(121666n, P25519), P25519);
var SQRTM1 = _pow(2n, (P25519 - 1n) / 4n, P25519);
var P448 = (1n << 448n) - (1n << 224n) - 1n;
var D448 = P448 - 39081n;

var CURVE = {
  6: { p: P25519, d: D25519, a: P25519 - 1n, len: 32, signBit: 255n },
  7: { p: P448, d: D448, a: 1n, len: 57, signBit: 455n },
};

function _mul(x, y, p) { return (x % p) * (y % p) % p; }
function _pow(b, e, p) { var r = 1n; b %= p; while (e > 0n) { if (e & 1n) r = r * b % p; b = b * b % p; e >>= 1n; } return r; }
function _inv(a, p) { return _pow(((a % p) + p) % p, p - 2n, p); }
function _leToBig(buf) { return BigInt("0x" + Buffer.from(buf).reverse().toString("hex")); }

function _decode(raw, c) {
  var num = _leToBig(raw);
  var sign = (num >> c.signBit) & 1n;
  var y = num & ((1n << c.signBit) - 1n);
  if (y >= c.p) return null;
  var p = c.p, y2 = y * y % p, x;
  var u = ((y2 - 1n) % p + p) % p;
  if (c.a === 1n) {
    var v = ((c.d * y2 % p - 1n) % p + p) % p;
    x = _mul(_mul(_pow(u, 3n, p), v, p), _pow(_mul(_pow(u, 5n, p), _pow(v, 3n, p), p), (p - 3n) / 4n, p), p);
    if (_mul(v, x * x % p, p) !== u) return null;
  } else {
    var v25 = (c.d * y2 % p + 1n) % p;
    x = _mul(_mul(u, _pow(v25, 3n, p), p), _pow(_mul(u, _pow(v25, 7n, p), p), (p - 5n) / 8n, p), p);
    var vxx = _mul(v25, x * x % p, p);
    if (vxx !== u) {
      if (vxx === (p - u) % p) { x = x * SQRTM1 % p; }
      else return null;
    }
  }
  if (x === 0n && sign === 1n) return null;
  if ((x & 1n) !== sign) x = (p - x) % p;
  return { x: x, y: y };
}

function _double(P, c) {
  var p = c.p, x2 = P.x * P.x % p, y2 = P.y * P.y % p, ax2 = c.a * x2 % p;
  var nx = 2n * P.x % p * P.y % p, dx = (ax2 + y2) % p;
  var ny = ((y2 - ax2) % p + p) % p, dy = ((2n - ax2 - y2) % p + 2n * p) % p;
  return { x: _mul(nx, _inv(dx, p), p), y: _mul(ny, _inv(dy, p), p) };
}

function validate(raw, crv) {
  var c = CURVE[crv];
  if (!c || !Buffer.isBuffer(raw) || raw.length !== c.len) return false;
  var pt = _decode(raw, c);
  if (!pt) return false;
  var q = _double(_double(_double(pt, c), c), c);
  if (q.x === 0n && q.y === 1n) return false;
  return true;
}

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
