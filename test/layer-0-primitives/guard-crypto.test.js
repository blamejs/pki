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

  /* The comparison is the operation a MAC verdict rests on, and `crypto.timingSafeEqual` is an ordinary
     writable property of the module object, so a replacement answering `true` accepted any
     equal-length wrong MAC. It is captured at load. */
  var realEqual = crypto.timingSafeEqual;
  var underReplacedEqual, equalLive;
  try {
    crypto.timingSafeEqual = function () { return true; };
    equalLive = crypto.timingSafeEqual(Buffer.from("abc"), Buffer.from("abd")) === true;
    underReplacedEqual = guard.constantTimeEqual(Buffer.from("abc"), Buffer.from("abd"));
  } finally { crypto.timingSafeEqual = realEqual; }
  check("CONTROL the replaced comparison is live, so the next check exercises it", equalLive === true);
  check("a replaced crypto.timingSafeEqual cannot turn unequal bytes into a match",
    underReplacedEqual === false);

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

  // ---- xof ----
  /* A single-stage KDF squeezes an extendable-output function for key material, so a replaced `update`
     chooses what the derivation covers and a replaced `digest` chooses the key bytes. */
  var xofExpected = crypto.createHash("shake128", { outputLength: 32 }).update(MSG).digest();
  check("an XOF is the platform's own value for the same name, bytes and length",
    guard.xof("shake128", MSG, 32).equals(xofExpected) &&
    guard.xof("shake256", MSG, 64).length === 64);
  var underReplacedXof, xofLive;
  try {
    Object.defineProperty(hashProto, "update", {
      value: function () { return this; }, writable: true, configurable: true,
    });
    xofLive = crypto.createHash("shake128", { outputLength: 32 }).update(MSG).digest()
      .equals(crypto.createHash("shake128", { outputLength: 32 }).update(Buffer.from("other")).digest());
    underReplacedXof = guard.xof("shake128", MSG, 32).equals(xofExpected);
  } finally {
    Object.defineProperty(hashProto, "update", { value: realUpdate, writable: true, configurable: true });
  }
  check("CONTROL under the replacement the chained XOF form derives the same bytes from different input",
    xofLive === true);
  check("a replaced hash update cannot change what an XOF covers", underReplacedXof === true);

  // ---- hmac ----
  /* HKDF-Extract and every HKDF-Expand round are MACs, so a replacement here decides the pseudo-random
     key a whole key schedule hangs off. The Hmac prototype is its own object, not the Hash one. */
  var MAC_KEY = Buffer.alloc(32, 0x5c);
  var macExpected = crypto.createHmac("sha256", MAC_KEY).update(MSG).digest();
  check("a MAC is the platform's own value for the same name, key and bytes",
    guard.hmac("sha256", MAC_KEY, MSG).equals(macExpected));
  var macProto = Object.getPrototypeOf(crypto.createHmac("sha256", MAC_KEY));
  var realMacUpdate = macProto.update, realMacDigest = macProto.digest;
  var underReplacedMac, macLive, underReplacedMacDigest, macDigestLive;
  try {
    Object.defineProperty(macProto, "update", {
      value: function () { return this; }, writable: true, configurable: true,
    });
    macLive = crypto.createHmac("sha256", MAC_KEY).update(MSG).digest()
      .equals(crypto.createHmac("sha256", MAC_KEY).update(Buffer.from("other")).digest());
    underReplacedMac = guard.hmac("sha256", MAC_KEY, MSG).equals(macExpected);
  } finally {
    Object.defineProperty(macProto, "update", { value: realMacUpdate, writable: true, configurable: true });
  }
  check("CONTROL under the replacement the chained MAC form answers the same for different input",
    macLive === true);
  check("a replaced MAC update cannot change what a MAC covers", underReplacedMac === true);

  try {
    Object.defineProperty(macProto, "digest", {
      value: function () { return Buffer.alloc(32, 0x7a); }, writable: true, configurable: true,
    });
    macDigestLive = crypto.createHmac("sha256", MAC_KEY).update(MSG).digest()[0] === 0x7a;
    underReplacedMacDigest = guard.hmac("sha256", MAC_KEY, MSG).equals(macExpected);
  } finally {
    Object.defineProperty(macProto, "digest", { value: realMacDigest, writable: true, configurable: true });
  }
  check("CONTROL the replaced MAC digest is live too", macDigestLive === true);
  check("and a replaced MAC digest cannot change the value returned", underReplacedMacDigest === true);

  // ---- verify and sign ----
  /* `crypto.verify` and `crypto.sign` are ordinary writable properties of the module object, and they
     were read once per signature at every call site in `lib/`, so a replacement installed after the
     package loaded decided the verdict. Captured at load, a later replacement reaches nothing. */
  var pair = crypto.generateKeyPairSync("ed25519");
  var msg = Buffer.from("the signed bytes", "utf8");
  var good = guard.sign(null, msg, pair.privateKey);
  check("a signature made through the guard verifies through it",
    guard.verify(null, msg, pair.publicKey, good) === true);
  check("and a signature over other bytes does not",
    guard.verify(null, Buffer.from("other", "utf8"), pair.publicKey, good) === false);

  var realVerify = crypto.verify, realSign = crypto.sign;
  var zero = Buffer.alloc(64, 0);
  var underReplacedVerify, verifyLive, underReplacedSign, signLive;
  try {
    crypto.verify = function () { return true; };
    verifyLive = crypto.verify(null, msg, pair.publicKey, zero) === true;
    underReplacedVerify = guard.verify(null, msg, pair.publicKey, zero);
  } finally { crypto.verify = realVerify; }
  check("CONTROL the replaced verifier is live, so the next check exercises it", verifyLive === true);
  check("a replaced crypto.verify cannot turn an all-zero signature into a verdict",
    underReplacedVerify === false);

  try {
    crypto.sign = function () { return Buffer.alloc(64, 0x7a); };
    signLive = crypto.sign(null, msg, pair.privateKey)[0] === 0x7a;
    underReplacedSign = guard.sign(null, msg, pair.privateKey);
  } finally { crypto.sign = realSign; }
  check("CONTROL the replaced signer is live too", signLive === true);
  check("and a replaced crypto.sign cannot decide the signature bytes",
    Buffer.compare(underReplacedSign, good) === 0 &&
    guard.verify(null, msg, pair.publicKey, underReplacedSign) === true);

  // ---- octet alignment ----
  check("a BIT STRING with no unused bits is octet-aligned",
    guard.isOctetAligned({ unusedBits: 0 }) === true &&
    guard.isOctetAligned({ unusedBits: 3 }) === false &&
    guard.isOctetAligned(null) === false);
  function E(code, message) { var e = new Error(message); e.code = code; return e; }
  check("asserting alignment returns the value and refuses an unaligned one through the caller's factory",
    guard.assertOctetAligned({ unusedBits: 0, bytes: Buffer.from("x") }, E, "x/bad", "sig").unusedBits === 0 &&
    threw(function () { guard.assertOctetAligned({ unusedBits: 1 }, E, "x/bad", "sig"); }) === "x/bad");

  testLoadGeneratesOnlyApprovedKeys();
}

// The module captures the three KeyObject `export` methods by making a sample key pair at load, which
// makes the generation part of `require`. An algorithm outside the FIPS 140-3 boundary therefore makes
// the WHOLE package unloadable under `crypto.setFips(1)`: OpenSSL's FIPS provider carries no Ed25519,
// so the generation raises ERR_OSSL_EVP_UNSUPPORTED before any export is reached, and a caller needing
// only approved RSA or EC operations cannot require the package at all. The prototypes do not depend
// on the algorithm (measured: the ed25519, P-256 and RSA pairs all yield the same two prototypes), so
// the sample is an approved algorithm and one pair serves both.
//
// Driven in a CHILD process: the module is already loaded here, and the property is about what its
// load does, so reloading it in-process would leave every other module holding the first instance.
function testLoadGeneratesOnlyApprovedKeys() {
  var spawnSync = require("node:child_process").spawnSync;
  var probe =
    "var c = require('node:crypto');" +
    "var calls = [];" +
    "var real = c.generateKeyPairSync;" +
    "c.generateKeyPairSync = function (alg) { calls.push(String(alg)); return real.apply(c, arguments); };" +
    "require('./lib/guard-crypto.js');" +
    "process.stdout.write(JSON.stringify(calls));";
  var rv = spawnSync(process.execPath, ["-e", probe], { encoding: "utf8", cwd: process.cwd() });
  check("the load probe ran", rv.status === 0);
  var calls;
  try { calls = JSON.parse(rv.stdout || "[]"); } catch (_e) { calls = ["UNPARSEABLE:" + rv.stdout]; }

  // Everything OpenSSL's FIPS provider does not carry. A sample key drawn from one of these is what
  // turns a load into a failure for a FIPS deployment.
  var OUTSIDE_FIPS = ["ed25519", "ed448", "x25519", "x448"];
  var offending = calls.filter(function (alg) { return OUTSIDE_FIPS.indexOf(alg) !== -1; });
  check("requiring guard-crypto generates no key outside the FIPS boundary",
    offending.length === 0);
  check("and it generates at most one sample pair, since both prototypes come from one",
    calls.length <= 1);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr ? helpers.formatErr(e) : (e && e.stack) || e); process.exit(1); }
  );
}
