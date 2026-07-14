// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- edwards-point (@internal): validation of an Ed25519 / Ed448 public-key point
 * (RFC 8032 decode + cofactor low-order rejection). Oracle: real keys from node:crypto MUST
 * validate; the degenerate points node/OpenSSL accepts on import but that are invalid or
 * low-order (the all-zeroes key, the identity, a non-canonical y, an off-curve encoding)
 * MUST be rejected -- an OKP credential key node would otherwise register and even verify a
 * trivial signature.
 */

var ep = require("../../lib/edwards-point");
var crypto = require("crypto");
var helpers = require("../helpers");
var check = helpers.check;

function rawOf(kp) { return Buffer.from(kp.publicKey.export({ format: "jwk" }).x, "base64url"); }

function run() {
  // Real keys from an independent generator: every one is a valid, full-order point.
  var f25 = 0, f48 = 0;
  for (var i = 0; i < 200; i++) {
    if (!ep.validate(rawOf(crypto.generateKeyPairSync("ed25519")), 6)) f25++;
    if (!ep.validate(rawOf(crypto.generateKeyPairSync("ed448")), 7)) f48++;
  }
  check("real Ed25519 keys all validate", f25 === 0);
  check("real Ed448 keys all validate", f48 === 0);

  // Low-order / degenerate points (on-curve but weak) are rejected.
  check("all-zeroes Ed25519 (low-order) rejected", ep.validate(Buffer.alloc(32), 6) === false);
  check("all-zeroes Ed448 (off-curve) rejected", ep.validate(Buffer.alloc(57), 7) === false);
  check("identity Ed25519 (y=1) rejected", ep.validate(Buffer.concat([Buffer.from([1]), Buffer.alloc(31)]), 6) === false);
  // The order-2 point y = -1 (encoded p-1): 0xec..ff..7f is a known small-order Ed25519 point.
  check("order-2 Ed25519 point rejected", ep.validate(Buffer.concat([Buffer.from([0xec]), Buffer.alloc(30, 0xff), Buffer.from([0x7f])]), 6) === false);

  // Non-canonical y (>= p): p encoded little-endian (p = 2^255-19 -> 0xed,0xff*30,0x7f) is >= p.
  check("non-canonical Ed25519 y (= p) rejected", ep.validate(Buffer.concat([Buffer.from([0xed]), Buffer.alloc(30, 0xff), Buffer.from([0x7f])]), 6) === false);

  // Wrong length / unknown curve.
  check("wrong-length Ed25519 rejected", ep.validate(Buffer.alloc(31), 6) === false);
  check("wrong-length Ed448 rejected", ep.validate(Buffer.alloc(32), 7) === false);
  check("unknown curve rejected", ep.validate(Buffer.alloc(32), 4) === false);
  check("non-buffer rejected", ep.validate("not a buffer", 6) === false);

  // An off-curve encoding (tampered real key that lands off-curve) fails closed -- run a batch
  // so at least one tamper is genuinely off-curve (not every tamper leaves the curve).
  var anyOff = false;
  for (var k = 0; k < 40 && !anyOff; k++) {
    var r = rawOf(crypto.generateKeyPairSync("ed25519")); r[4] ^= 0xff; r[9] ^= 0xa5;
    if (ep.validate(r, 6) === false) anyOff = true;
  }
  check("a tampered/off-curve Ed25519 encoding is rejected", anyOff);
  // Ed448 off-curve: a tampered real Ed448 point that lands off the curve fails the on-curve
  // solve (the a=1 branch), exactly as the Ed25519 case -- run a batch so at least one tamper
  // is genuinely off-curve rather than a non-canonical y caught earlier.
  var anyOff48 = false;
  for (var m = 0; m < 60 && !anyOff48; m++) {
    var r48 = rawOf(crypto.generateKeyPairSync("ed448")); r48[4] ^= 0xff; r48[9] ^= 0xa5;
    if (ep.validate(r48, 7) === false) anyOff48 = true;
  }
  check("a tampered/off-curve Ed448 encoding is rejected", anyOff48);
  // x == 0 with the sign bit set is the one encoding RFC 8032 sec. 5.1.3 forbids (x=0 forces a
  // clear sign): y = 1 (the identity's y) with the high sign bit set decodes x = 0, sign = 1.
  check("x==0 with sign bit set rejected", ep.validate(Buffer.concat([Buffer.from([1]), Buffer.alloc(30), Buffer.from([0x80])]), 6) === false);

  // validateSpki -- the SPKI-input, error-parameterized gate the CMS / composite / path verify
  // paths share. A real SPKI passes silently; a low-order point and a malformed SPKI both throw
  // the caller's typed error/code (never a bare false leaking past the verify boundary).
  function E(code, msg, cause) { this.code = code; this.message = msg; this.cause = cause; }
  var goodSpki = crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" });
  var okThrew = false; try { ep.validateSpki(goodSpki, 6, E, "x/bad"); } catch (_e) { okThrew = true; }
  check("validateSpki accepts a real Ed25519 SPKI", okThrew === false);
  var good448 = crypto.generateKeyPairSync("ed448").publicKey.export({ format: "der", type: "spki" });
  var ok448 = false; try { ep.validateSpki(good448, 7, E, "x/bad"); } catch (_e) { ok448 = true; }
  check("validateSpki accepts a real Ed448 SPKI", ok448 === false);
  // low-order point: zero the 32-byte Ed25519 point in an otherwise well-formed SPKI.
  var lowSpki = Buffer.from(goodSpki); lowSpki.fill(0, lowSpki.length - 32);
  var lowErr = null; try { ep.validateSpki(lowSpki, 6, E, "x/bad-point"); } catch (e) { lowErr = e; }
  check("validateSpki rejects a low-order SPKI with the caller code", lowErr !== null && lowErr.code === "x/bad-point");
  // malformed SPKI (a SEQUENCE with no subjectPublicKey child) -> the decode-catch throws.
  var badErr = null; try { ep.validateSpki(Buffer.from([0x30, 0x01, 0x00]), 6, E, "x/bad-spki"); } catch (e) { badErr = e; }
  check("validateSpki rejects a malformed SPKI via the decode-catch", badErr !== null && badErr.code === "x/bad-spki");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
