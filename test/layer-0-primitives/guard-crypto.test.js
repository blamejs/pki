// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard.crypto: the comparison and the digest a security decision rests on, taken through
 * operations captured at load. Pins the guard's own contract: constantTimeEqual answers false for
 * operands of different lengths rather than throwing out of the platform primitive, and digest()
 * computes the platform's own value while a replaced hash prototype cannot change what it covers or
 * what it returns.
 */

var crypto = require("node:crypto");
var helpers = require("../helpers");
var check = helpers.check;
var guard = require("../../lib/guard-all").crypto;

function threw(fn) { try { fn(); return null; } catch (e) { return (e && (e.code || e.name)) || "throw"; } }

function run() {
  // ---- constantTimeEqual ----
  check("equal bytes compare equal",
    guard.constantTimeEqual(Buffer.from("abc"), Buffer.from("abc")) === true);
  check("different bytes of the same length compare unequal",
    guard.constantTimeEqual(Buffer.from("abc"), Buffer.from("abd")) === false);
  /* The platform primitive THROWS on a length mismatch, which is the common case for a comparison
     against untrusted bytes, so the length is answered before it is reached. A caller comparing a
     decoded value against an expected one gets a verdict rather than an untyped error. */
  check("a length mismatch is false rather than a throw out of the platform primitive",
    guard.constantTimeEqual(Buffer.from("abc"), Buffer.from("abcd")) === false &&
    guard.constantTimeEqual(Buffer.from(""), Buffer.from("a")) === false);
  check("CONTROL the platform primitive does throw on that pair, which is what the guard absorbs",
    threw(function () { crypto.timingSafeEqual(Buffer.from("abc"), Buffer.from("abcd")); }) !== null);

  // ---- digest ----
  var MSG = Buffer.from("the message");
  check("a digest is the platform's own value for the same name and bytes",
    guard.digest("sha256", MSG).equals(crypto.createHash("sha256").update(MSG).digest()) &&
    guard.digest("sha512", MSG).equals(crypto.createHash("sha512").update(MSG).digest()));

  /* `update` and `digest` are ordinary writable properties of the hash prototype, so a chained
     `createHash(name).update(b).digest()` lets a replacement decide what the digest is OVER. A digest
     in this toolkit names a key, binds a certificate, or is the value a signature covers, so the
     operations are captured at load and a later replacement reaches nothing. */
  var expected = crypto.createHash("sha256").update(MSG).digest();
  var hashProto = Object.getPrototypeOf(crypto.createHash("sha256"));
  var realUpdate = hashProto.update, realDigest = hashProto.digest;
  var underReplacedUpdate, underReplacedDigest, updateLive, digestLive;
  try {
    Object.defineProperty(hashProto, "update", {
      value: function () { return realUpdate.call(this, Buffer.from("other bytes entirely")); },
      writable: true, configurable: true,
    });
    // CONTROL, inside the window: the replacement is installed, so the check below exercises it.
    updateLive = !crypto.createHash("sha256").update(MSG).digest().equals(expected);
    underReplacedUpdate = guard.digest("sha256", MSG).equals(expected);
  } finally {
    Object.defineProperty(hashProto, "update", { value: realUpdate, writable: true, configurable: true });
  }
  check("CONTROL the replaced update is live, so the next check exercises it", updateLive === true);
  check("a replaced hash update cannot change what a digest covers", underReplacedUpdate === true);

  try {
    Object.defineProperty(hashProto, "digest", {
      value: function () { return Buffer.alloc(32, 0x7a); },
      writable: true, configurable: true,
    });
    digestLive = crypto.createHash("sha256").update(MSG).digest()[0] === 0x7a;
    underReplacedDigest = guard.digest("sha256", MSG).equals(expected);
  } finally {
    Object.defineProperty(hashProto, "digest", { value: realDigest, writable: true, configurable: true });
  }
  check("CONTROL the replaced digest is live too", digestLive === true);
  check("and a replaced digest cannot change the value returned", underReplacedDigest === true);

  /* An algorithm this platform does not have is the caller's error at the point of the call, not a
     value: nothing is returned in its place. */
  check("an unknown algorithm name throws rather than answering",
    threw(function () { guard.digest("sha-not-a-real-one", MSG); }) !== null);

  // ---- octet alignment ----
  check("a BIT STRING with no unused bits is octet-aligned",
    guard.isOctetAligned({ unusedBits: 0 }) === true &&
    guard.isOctetAligned({ unusedBits: 3 }) === false &&
    guard.isOctetAligned(null) === false);
  function E(code, message) { var e = new Error(message); e.code = code; return e; }
  check("asserting alignment returns the value and refuses an unaligned one through the caller's factory",
    guard.assertOctetAligned({ unusedBits: 0, bytes: Buffer.from("x") }, E, "x/bad", "sig").unusedBits === 0 &&
    threw(function () { guard.assertOctetAligned({ unusedBits: 1 }, E, "x/bad", "sig"); }) === "x/bad");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack) || e); process.exit(1); }
  );
}
