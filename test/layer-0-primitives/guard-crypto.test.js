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
  testEveryCapturedOperationIsImmuneToReplacement();
  testTheSeamCoversEveryOperationThisGuardCaptures();
  return testEveryTransformMethodIsImmuneToReplacement();
}

/* The seam at test/helpers/crypto-tap.js exists because this module's captures make a wrapper
   installed afterwards invisible. That only holds if the seam wraps the SAME operations: an operation
   this guard captures and the seam does not is one a vector can still wrap, with the wrapper never
   consulted, the counter left at zero and the check reading as a passing fix. DERIVED from this
   module's own source, so adding a capture here and not there fails the gate rather than quietly
   deleting a suite's coverage. */
function testTheSeamCoversEveryOperationThisGuardCaptures() {
  var fs = require("node:fs");
  var path = require("node:path");
  var root = path.join(__dirname, "..", "..");
  var guardSrc = fs.readFileSync(path.join(root, "lib", "guard-crypto.js"), "utf8");
  var seamSrc = fs.readFileSync(path.join(root, "test", "helpers", "crypto-tap.js"), "utf8");

  var captured = [], re = /nodeCrypto\.([A-Za-z_$][\w$]*)/g, m;
  while ((m = re.exec(guardSrc)) !== null) {
    if (captured.indexOf(m[1]) === -1) captured.push(m[1]);
  }
  check("the capture list was read off the guard (" + captured.length + " name(s))", captured.length > 20);

  /* `constants` is the one name on that list with nothing to wrap, and the reason is measured rather
     than assumed: it is a non-writable, non-configurable property of the module, and each value on it
     is non-writable too, so an assignment silently fails and `defineProperty` throws. */
  var d = Object.getOwnPropertyDescriptor(crypto, "constants");
  check("CONTROL crypto.constants is non-writable and non-configurable, so it is not wrappable",
    d !== undefined && d.writable === false && d.configurable === false);

  var notWrappable = ["constants"];
  var uncovered = captured.filter(function (name) {
    if (notWrappable.indexOf(name) !== -1) return false;
    // A module property appears in the seam's OPS list; a constructor or a namespace the guard reads
    // THROUGH appears as a wrapProto holder instead.
    return seamSrc.indexOf("\"" + name + "\"") === -1 && seamSrc.indexOf("nodeCrypto." + name) === -1;
  });
  check("every operation this guard captures is one the test seam also wraps" +
    (uncovered.length ? " (uncovered: " + uncovered.join(", ") + ")" : ""), uncovered.length === 0);
}

// Capturing the CONSTRUCTION closes only half of it: the object a construction returns carries its
// methods as ordinary prototype properties, and a static sits on a constructor the module exports, so
// each is still a live read from the caller's side. Every arm replaces one of those and drives the
// verb that owns it. The replacement target differs per arm, which is why these are not rows in the
// module-property table above.
async function testEveryTransformMethodIsImmuneToReplacement() {
  var marked = Buffer.alloc(16, 0x5a);
  var key = Buffer.alloc(32, 11);
  var iv = Buffer.alloc(12, 13);
  var cipherProto = Object.getPrototypeOf(crypto.createCipheriv("aes-256-gcm", key, iv));
  var decipherProto = Object.getPrototypeOf(crypto.createDecipheriv("aes-256-gcm", key, iv));
  var ecdhProto = Object.getPrototypeOf(crypto.createECDH("prime256v1"));
  var realSetAuthTag = decipherProto.setAuthTag;
  var ecSample = crypto.createECDH("prime256v1");
  ecSample.generateKeys();
  var scalar = ecSample.getPrivateKey();
  var wantPoint = ecSample.getPublicKey(null, "uncompressed");
  var compressed = ecSample.getPublicKey(null, "compressed");
  var aesKeyObj = crypto.generateKeyPairSync("ed25519").publicKey;
  // A CryptoKey belonging to NODE's WebCrypto, which is the case `nodeExportKey` exists for, and the
  // bytes it exports with nothing replaced.
  var nodeCryptoKey = (await crypto.webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])).publicKey;
  var nodeKeyWant = Buffer.from(await crypto.webcrypto.subtle.exportKey("spki", nodeCryptoKey));
  function bytesEqualLocal(a, b) { return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b); }
  function strictEqualLocal(a, b) { return a === b; }

  // A sealed message to open, made before any replacement is installed.
  function seal(aad) {
    var c = guard.cipher("aes-256-gcm", key, iv, { authTagLength: 16 });
    if (aad) guard.transformSetAAD(c, aad);
    var body = Buffer.concat([guard.transformUpdate(c, Buffer.from("the plaintext")), guard.transformFinal(c)]);
    return { body: body, tag: guard.cipherAuthTag(c) };
  }
  var sealed = seal(null);
  var sealedWithAad = seal(Buffer.from("the aad"));

  function openUnder(tag, aad) {
    var d = guard.decipher("aes-256-gcm", key, iv, { authTagLength: 16 });
    if (aad) guard.transformSetAAD(d, aad);
    guard.decipherSetAuthTag(d, tag);
    return Buffer.concat([guard.transformUpdate(d, sealedWithAad.body), guard.transformFinal(d)]).toString();
  }
  // The same message opened the way a lib file used to, through the receiver. This is the control
  // side of the tag arm: it must refuse the genuine message that the verb still opens.
  function openLive(tag, aad) {
    var d = crypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
    if (aad) d.setAAD(aad);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(sealedWithAad.body), d.final()]).toString();
  }

  var ARMS = [
    { what: "Cipheriv.prototype.setAAD", holder: cipherProto, prop: "setAAD",
      fake: function () { return this; },
      verb: function () { return seal(Buffer.from("the aad")).tag; },
      want: function () { return sealedWithAad.tag; }, same: bytesEqualLocal },
    { what: "Cipheriv.prototype.getAuthTag", holder: cipherProto, prop: "getAuthTag",
      fake: function () { return marked; },
      verb: function () { return seal(null).tag; },
      want: function () { return sealed.tag; }, same: bytesEqualLocal },
    // The one that fails OPEN rather than wrong: a decryptor with no tag set authenticates against
    // nothing, so the message opens whatever its tag says.
    /* The tag is what says an AEAD message is genuine, and MEASURED, the exposure is not that a
       replacement opens a forged message: a decryptor whose tag was never set refuses anyway, because
       node requires the state. What a replacement does is decide WHICH tag the ciphertext is checked
       against, so the verdict stops being a function of the message. The fake substitutes a tag of its
       own, and under it the receiver-side call refuses a GENUINE message while the verb still opens
       it. */
    { what: "Decipheriv.prototype.setAuthTag", holder: decipherProto, prop: "setAuthTag",
      fake: function () { return realSetAuthTag.call(this, Buffer.alloc(16, 0xff)); },
      verb: function () { return openUnder(sealedWithAad.tag, Buffer.from("the aad")); },
      liveAnswer: function () { return openLive(sealedWithAad.tag, Buffer.from("the aad")); },
      want: function () { return "the plaintext"; }, same: strictEqualLocal },
    { what: "Decipheriv.prototype.setAutoPadding", holder: decipherProto, prop: "setAutoPadding",
      fake: function () { return this; },
      verb: function () {
        var d = guard.decipher("aes-256-cbc", key, Buffer.alloc(16, 3));
        guard.transformNoPadding(d);
        var c = guard.cipher("aes-256-cbc", key, Buffer.alloc(16, 3));
        guard.transformNoPadding(c);
        var ct = Buffer.concat([guard.transformUpdate(c, Buffer.alloc(32, 7)), guard.transformFinal(c)]);
        return Buffer.concat([guard.transformUpdate(d, ct), guard.transformFinal(d)]).length;
      },
      want: function () { return 32; }, same: strictEqualLocal },
    { what: "Cipheriv.prototype.update", holder: cipherProto, prop: "update",
      fake: function () { return marked; },
      verb: function () { return seal(null).body; },
      want: function () { return sealed.body; }, same: bytesEqualLocal },
    { what: "Cipheriv.prototype.final", holder: cipherProto, prop: "final",
      fake: function () { return marked; },
      verb: function () { return seal(null).body; },
      want: function () { return sealed.body; }, same: bytesEqualLocal },
    { what: "ECDH.prototype.setPrivateKey", holder: ecdhProto, prop: "setPrivateKey",
      fake: function () { return this; },
      verb: function () { return guard.ecPointFromScalar("prime256v1", scalar); },
      want: function () { return wantPoint; }, same: bytesEqualLocal },
    { what: "ECDH.prototype.getPublicKey", holder: ecdhProto, prop: "getPublicKey",
      fake: function () { return Buffer.alloc(65, 0x04); },
      verb: function () { return guard.ecPointFromScalar("prime256v1", scalar); },
      want: function () { return wantPoint; }, same: bytesEqualLocal },
    { what: "ECDH.convertKey (a static on the constructor)", holder: crypto.ECDH, prop: "convertKey",
      fake: function () { return Buffer.alloc(65, 0x04); },
      verb: function () { return guard.ecConvertPoint(compressed, "prime256v1", "uncompressed"); },
      want: function () { return wantPoint; }, same: bytesEqualLocal },
    { what: "crypto.webcrypto.subtle.exportKey", holder: crypto.webcrypto.subtle, prop: "exportKey",
      fake: function () { return Promise.resolve(marked.buffer); },
      verb: null,   // settled below: it is the one arm whose verb returns a promise
      want: function () { return nodeKeyWant; }, same: bytesEqualLocal },
    // `instanceof` reads the constructor and then asks its `Symbol.hasInstance`, so the holder here is
    // the well-known symbol rather than a named property.
    { what: "crypto.KeyObject[Symbol.hasInstance]", holder: crypto.KeyObject, prop: Symbol.hasInstance,
      fake: function () { return false; },
      verb: function () { return guard.isKeyObject(aesKeyObj); },
      want: function () { return true; }, same: strictEqualLocal },
  ];

  var immune = 0, controls = 0, exercised = 0;

  ARMS.forEach(function (arm) {
    if (arm.verb === null) return;   // handled after the loop; counted there too
    exercised += 1;
    var had = Object.prototype.hasOwnProperty.call(arm.holder, arm.prop);
    var real = arm.holder[arm.prop];
    var under, verbThrew = null, live, liveThrew = null;
    var want = arm.want();
    try {
      Object.defineProperty(arm.holder, arm.prop, { value: arm.fake, writable: true, configurable: true });
      try { under = arm.verb(); } catch (e) { verbThrew = (e && e.message) || "throw"; }
      // CONTROL: the replacement must be reachable through the receiver, which is how a lib file
      // would have reached it. Without this an arm whose verb simply refused would read as immune.
      try { live = arm.holder[arm.prop] === arm.fake; } catch (e2) { liveThrew = e2; }
      // The stronger control, where the arm carries one: the SAME replacement must change the answer
      // on the receiver-side call. An arm without it rests on the method merely being reachable.
      if (arm.liveAnswer !== undefined) {
        var liveAnswer;
        try { liveAnswer = arm.liveAnswer(); } catch (e3) { liveAnswer = "threw:" + ((e3 && e3.code) || "throw"); }
        check("CONTROL " + arm.what + ": the same replacement DOES change the receiver-side answer (" +
          liveAnswer + ")", !arm.same(liveAnswer, want));
      }
    } finally {
      if (had) Object.defineProperty(arm.holder, arm.prop, { value: real, writable: true, configurable: true });
      else delete arm.holder[arm.prop];
    }
    // Every arm compares a value, including the setAuthTag one: its verb RETURNS the refusal code
    // rather than throwing, so a replacement that opened the message would show as a different value.
    var held = verbThrew === null && arm.same(under, want);
    if (held) immune += 1;
    if (live === true && liveThrew === null) controls += 1;
    check("guard.crypto owns " + arm.what + ": a replacement does not change the verb's answer" +
      (verbThrew === null ? "" : " (verb threw \"" + verbThrew + "\")"), held);
    check("CONTROL " + arm.what + ": the replacement was installed and reachable through the receiver",
      live === true && liveThrew === null);
  });
  /* The one arm whose verb returns a promise, run apart from the synchronous loop. Node's own
     WebCrypto export is the fallback for a CryptoKey from another implementation, and it hands back
     key material, so a replacement decides those bytes. */
  var exportArm = ARMS.filter(function (a) { return a.prop === "exportKey"; })[0];
  var realExport = crypto.webcrypto.subtle.exportKey;
  var exportUnder = null, exportThrew = null, exportLive;
  try {
    Object.defineProperty(crypto.webcrypto.subtle, "exportKey",
      { value: exportArm.fake, writable: true, configurable: true });
    exportLive = crypto.webcrypto.subtle.exportKey === exportArm.fake;
    try { exportUnder = Buffer.from(await guard.nodeExportKey("spki", nodeCryptoKey)); }
    catch (e) { exportThrew = (e && e.message) || "throw"; }
  } finally {
    Object.defineProperty(crypto.webcrypto.subtle, "exportKey",
      { value: realExport, writable: true, configurable: true });
  }
  var exportHeld = exportThrew === null && bytesEqualLocal(exportUnder, nodeKeyWant);
  exercised += 1;
  if (exportHeld) immune += 1;
  if (exportLive) controls += 1;
  check("guard.crypto owns " + exportArm.what + ": a replacement does not change the bytes exported" +
    (exportThrew === null ? "" : " (threw \"" + exportThrew + "\")"), exportHeld);
  check("CONTROL " + exportArm.what + ": the replacement was installed and reachable through the receiver",
    exportLive);

  check("every transform method and static was exercised (" + immune + "/" + ARMS.length + " immune, " +
    controls + "/" + ARMS.length + " controls fired)",
  exercised === ARMS.length && immune === ARMS.length && controls === ARMS.length);
}

// Every operation the guard exposes is one node:crypto carries as an ordinary writable property, so a
// replacement installed after this module loaded decides what the operation returns. Each case below
// replaces one and drives the guard verb that owns it, asserting the verb's answer is NOT the value
// the replacement chose. The CONTROL in the same arm reads the operation off the module handle the way
// a lib file used to, proving the replacement was installed and reachable: without it, a verb that
// happened to refuse would read as immune.
function testEveryCapturedOperationIsImmuneToReplacement() {
  var MARK = "replacement-chose-this";
  var marked = Buffer.alloc(32, 0x5a);
  var rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var x1 = crypto.generateKeyPairSync("x25519");
  var x2 = crypto.generateKeyPairSync("x25519");
  var mlkem = crypto.generateKeyPairSync("ml-kem-768");
  var aesKey = Buffer.alloc(32, 7);
  var iv = Buffer.alloc(16, 9);
  var mlkemCt = guard.encapsulate(mlkem.publicKey).ciphertext;
  var markedSecretKey = guard.secretKey(marked);
  var ecSample = crypto.createECDH("prime256v1");
  ecSample.generateKeys();
  var ecScalar = ecSample.getPrivateKey();

  var oaepCt = guard.publicEncrypt({ key: rsa.publicKey, padding: guard.padding.RSA_PKCS1_OAEP, oaepHash: "sha256" }, Buffer.alloc(16, 3));
  var x1Pkcs8 = guard.exportKey(x1.privateKey, { format: "der", type: "pkcs8" });
  var hex = function (v) { return Buffer.isBuffer(v) ? v.toString("hex") : String(v); };
  var isMarkedBytes = function (v) { return hex(v) === marked.toString("hex"); };
  var bytesEqual = function (a, b) { return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b); };
  var strictEqual = function (a, b) { return a === b; };
  // A replacement that THROWS cannot plant a value, so its arm is immune when the verb completes and
  // the control fires when the module-handle read raises the marked error.
  var threwIsFake = function () { return false; };

  var CASES = [
    { op: "randomBytes", fake: function () { return marked; },
      verb: function () { return guard.randomBytes(32); },
      live: function () { return crypto.randomBytes(32); },
      isFake: isMarkedBytes },
    { op: "randomFillSync", fake: function (b) { marked.copy(b); return b; },
      verb: function () { return guard.randomFill(Buffer.alloc(32)); },
      live: function () { return crypto.randomFillSync(Buffer.alloc(32)); },
      isFake: isMarkedBytes },
    { op: "randomUUID", fake: function () { return MARK; },
      verb: function () { return guard.randomUUID(); },
      live: function () { return crypto.randomUUID(); },
      isFake: function (v) { return v === MARK; } },
    { op: "createHash", fake: function () { throw new Error(MARK); },
      verb: function () { return guard.digest("sha256", Buffer.from("abc")).toString("hex"); },
      live: function () { return crypto.createHash("sha256").update("abc").digest("hex"); },
      isFake: threwIsFake, deterministic: true, same: strictEqual },
    { op: "createHmac", fake: function () { throw new Error(MARK); },
      verb: function () { return guard.hmac("sha256", aesKey, Buffer.from("abc")).toString("hex"); },
      live: function () { return crypto.createHmac("sha256", aesKey).update("abc").digest("hex"); },
      isFake: threwIsFake, deterministic: true, same: strictEqual },
    { op: "pbkdf2Sync", fake: function () { return marked; },
      verb: function () { return guard.pbkdf2("pw", Buffer.alloc(8, 1), 10, 32, "sha256"); },
      live: function () { return crypto.pbkdf2Sync("pw", Buffer.alloc(8, 1), 10, 32, "sha256"); },
      isFake: isMarkedBytes, deterministic: true, same: bytesEqual },
    { op: "hkdfSync", fake: function () { return marked.buffer; },
      verb: function () { return Buffer.from(guard.hkdf("sha256", aesKey, Buffer.alloc(8), Buffer.alloc(0), 32)); },
      live: function () { return Buffer.from(crypto.hkdfSync("sha256", aesKey, Buffer.alloc(8), Buffer.alloc(0), 32)); },
      isFake: isMarkedBytes, deterministic: true, same: bytesEqual },
    { op: "diffieHellman", fake: function () { return marked; },
      verb: function () { return guard.diffieHellman({ privateKey: x1.privateKey, publicKey: x2.publicKey }); },
      live: function () { return crypto.diffieHellman({ privateKey: x1.privateKey, publicKey: x2.publicKey }); },
      isFake: isMarkedBytes, deterministic: true, same: bytesEqual },
    { op: "encapsulate", fake: function () { return { sharedKey: marked, ciphertext: marked }; },
      verb: function () { return guard.encapsulate(mlkem.publicKey).sharedKey; },
      live: function () { return crypto.encapsulate(mlkem.publicKey).sharedKey; },
      isFake: isMarkedBytes },
    { op: "decapsulate", fake: function () { return marked; },
      verb: function () { return guard.decapsulate(mlkem.privateKey, mlkemCt); },
      live: function () { return crypto.decapsulate(mlkem.privateKey, mlkemCt); },
      isFake: isMarkedBytes, deterministic: true, same: bytesEqual },
    { op: "generateKeyPairSync", fake: function () { throw new Error(MARK); },
      verb: function () { return guard.generateKeyPair("x25519").publicKey.asymmetricKeyType; },
      live: function () { return crypto.generateKeyPairSync("x25519").publicKey.asymmetricKeyType; },
      isFake: threwIsFake, deterministic: true, same: strictEqual },
    { op: "createPublicKey", fake: function () { return rsa.publicKey; },
      verb: function () { return guard.publicKey(x1.privateKey).asymmetricKeyType; },
      live: function () { return crypto.createPublicKey(x1.privateKey).asymmetricKeyType; },
      isFake: function (v) { return v === "rsa"; }, deterministic: true, same: strictEqual },
    { op: "createPrivateKey", fake: function () { return rsa.privateKey; },
      verb: function () { return guard.privateKey({ key: x1Pkcs8, format: "der", type: "pkcs8" }).asymmetricKeyType; },
      live: function () { return crypto.createPrivateKey({ key: x1Pkcs8, format: "der", type: "pkcs8" }).asymmetricKeyType; },
      isFake: function (v) { return v === "rsa"; }, deterministic: true, same: strictEqual },
    // The fixture is built BEFORE the replacement is installed: a fake that called the operation it
    // replaces would recurse into itself, and the control would read as a throw rather than a hit.
    { op: "createSecretKey", fake: function () { return markedSecretKey; },
      verb: function () { return guard.exportKey(guard.secretKey(aesKey)); },
      live: function () { return guard.exportKey(crypto.createSecretKey(aesKey)); },
      isFake: isMarkedBytes, deterministic: true, same: bytesEqual },
    { op: "createCipheriv", fake: function () { throw new Error(MARK); },
      verb: function () { var c = guard.cipher("aes-256-cbc", aesKey, iv); return Buffer.concat([c.update(Buffer.alloc(16)), c.final()]).toString("hex"); },
      live: function () { var c = crypto.createCipheriv("aes-256-cbc", aesKey, iv); return Buffer.concat([c.update(Buffer.alloc(16)), c.final()]).toString("hex"); },
      isFake: threwIsFake, deterministic: true, same: strictEqual },
    { op: "createDecipheriv", fake: function () { throw new Error(MARK); },
      verb: function () { var d = guard.decipher("aes-256-cbc", aesKey, iv); d.setAutoPadding(false); return Buffer.concat([d.update(Buffer.alloc(16)), d.final()]).toString("hex"); },
      live: function () { var d = crypto.createDecipheriv("aes-256-cbc", aesKey, iv); d.setAutoPadding(false); return Buffer.concat([d.update(Buffer.alloc(16)), d.final()]).toString("hex"); },
      isFake: threwIsFake, deterministic: true, same: strictEqual },
    { op: "createECDH", fake: function () { throw new Error(MARK); },
      verb: function () { return guard.ecPointFromScalar("prime256v1", ecScalar); },
      live: function () { var e = crypto.createECDH("prime256v1"); e.setPrivateKey(ecScalar); return e.getPublicKey(null, "uncompressed"); },
      isFake: threwIsFake, deterministic: true, same: bytesEqual },
    { op: "publicEncrypt", fake: function () { return marked; },
      verb: function () { return guard.publicEncrypt({ key: rsa.publicKey, padding: guard.padding.RSA_PKCS1_OAEP, oaepHash: "sha256" }, Buffer.alloc(16, 3)); },
      live: function () { return crypto.publicEncrypt({ key: rsa.publicKey, padding: guard.padding.RSA_PKCS1_OAEP, oaepHash: "sha256" }, Buffer.alloc(16, 3)); },
      isFake: isMarkedBytes },
    { op: "privateDecrypt", fake: function () { return marked; },
      verb: function () { return guard.privateDecrypt({ key: rsa.privateKey, padding: guard.padding.RSA_PKCS1_OAEP, oaepHash: "sha256" }, oaepCt); },
      live: function () { return crypto.privateDecrypt({ key: rsa.privateKey, padding: guard.padding.RSA_PKCS1_OAEP, oaepHash: "sha256" }, oaepCt); },
      isFake: isMarkedBytes, deterministic: true, same: bytesEqual },
  ];

  /* A random operation returns a different value every call, so "the answer did not change" cannot be
     the test for one: the signal is that the answer is not the value the REPLACEMENT chose. A
     replacement that throws is read the same way, by whether the verb completed. Where the operation
     IS deterministic the case says so, and the answer is compared against the unreplaced one too. */
  var immune = 0, controlsFired = 0;
  CASES.forEach(function (c) {
    var want = c.verb();              // the answer with nothing replaced
    var real = crypto[c.op];
    var under, verbThrew = null, live, liveThrew = null;
    try {
      crypto[c.op] = c.fake;
      try { under = c.verb(); } catch (e) { verbThrew = e.message; }
      try { live = c.live(); } catch (e2) { liveThrew = e2.message; }
    } finally { crypto[c.op] = real; }
    var held = verbThrew === null && !c.isFake(under) &&
      (c.deterministic !== true || c.same(under, want));
    // The control must show the replacement WAS reachable: either the module-handle read returned
    // the replacement's value, or it threw the replacement's error. Without it, a verb that happened
    // to refuse for its own reasons would read as immune.
    var controlShowed = liveThrew !== null ? liveThrew.indexOf(MARK) >= 0 : c.isFake(live);
    if (held) immune += 1;
    if (controlShowed) controlsFired += 1;
    check("guard.crypto owns " + c.op + ": a replacement after load does not change the verb's answer" +
      (verbThrew === null ? "" : " (verb threw \"" + verbThrew + "\")"), held);
    check("CONTROL " + c.op + ": the same replacement DOES reach a module-handle read" +
      (liveThrew === null ? "" : " (threw)"), controlShowed);
  });
  check("every captured operation was exercised (" + immune + "/" + CASES.length + " immune, " +
    controlsFired + "/" + CASES.length + " controls fired)",
  immune === CASES.length && controlsFired === CASES.length);
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
