// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The seam a vector needs to observe or steer a node:crypto operation from outside lib/.
 *
 * lib/guard-crypto.js captures every node:crypto operation it uses at the moment it LOADS, so a
 * wrapper a vector assigns onto the module afterwards is a property nothing in lib/ reads any more:
 * the assignment succeeds, the vector's counter stays at zero, and the check reads as a passing fix.
 * This module installs a wrapper over each captured operation and MUST be required before pki, which
 * is what makes the capture the package takes be these wrappers. Each wrapper stays installed for the
 * life of the process and delegates to the real operation; `on()` decides whether a hook sees a call.
 *
 * A hook is called as `hook(real, args)` and owns the call: it may count and delegate
 * (`real.apply(null, args)`), observe the result, substitute one, or throw. `on()` returns the
 * restore function, which MUST run in a finally, or a later vector in the same process inherits the
 * hook.
 */
var nodeCrypto = require("node:crypto");

/** Every operation lib/guard-crypto.js captures at load. A name node's version does not carry is
 *  skipped rather than refused, so this list can name an operation a newer Node adds. */
var OPS = ["createHash", "createHmac", "sign", "verify", "timingSafeEqual",
  "createPublicKey", "createPrivateKey", "createSecretKey",
  "diffieHellman", "generateKeyPairSync", "encapsulate", "decapsulate",
  "createCipheriv", "createDecipheriv", "createECDH",
  "randomBytes", "randomFillSync", "randomUUID",
  "pbkdf2", "pbkdf2Sync", "hkdfSync", "publicEncrypt", "privateDecrypt"];

var real = Object.create(null);
var hooks = Object.create(null);

OPS.forEach(function (name) {
  var fn = nodeCrypto[name];
  if (typeof fn !== "function") return;
  real[name] = fn;
  nodeCrypto[name] = function () {
    var hook = hooks[name];
    if (hook === undefined) return fn.apply(this, arguments);
    return hook.call(this, fn, arguments);
  };
});

/* The transform prototypes' methods, wrapped at load for a second reason on top of the one above:
   lib/guard-crypto.js UNCURRIES them, so it holds each function itself rather than reaching it
   through a receiver, and a wrapper assigned onto an INSTANCE is never consulted at all. A vector
   that needs to see the bytes a digest covers, or the plaintext a decryptor produced before its tag
   was checked, has to be here. node:crypto exports no Hash or Hmac constructor, so each prototype is
   read off an instance. These are named "<Kind>.<method>" in `on()`, and the hook's `this` is the
   transform. */
function wrapProto(label, proto, methods) {
  methods.forEach(function (method) {
    var name = label + "." + method;
    var realFn = proto[method];
    if (typeof realFn !== "function") return;
    real[name] = realFn;
    Object.defineProperty(proto, method, {
      value: function () {
        var hook = hooks[name];
        if (hook === undefined) return realFn.apply(this, arguments);
        return hook.call(this, realFn, arguments);
      },
      writable: true, configurable: true,
    });
  });
}
var _sampleKey = Buffer.alloc(32);
var _sampleIv = Buffer.alloc(12);
wrapProto("Hash", Object.getPrototypeOf(nodeCrypto.createHash("sha256")), ["update", "digest"]);
wrapProto("Hmac", Object.getPrototypeOf(nodeCrypto.createHmac("sha256", "k")), ["update", "digest"]);
wrapProto("Cipheriv", Object.getPrototypeOf(nodeCrypto.createCipheriv("aes-256-gcm", _sampleKey, _sampleIv)),
  ["update", "final", "setAAD", "getAuthTag", "setAutoPadding"]);
wrapProto("Decipheriv", Object.getPrototypeOf(nodeCrypto.createDecipheriv("aes-256-gcm", _sampleKey, _sampleIv)),
  ["update", "final", "setAAD", "setAuthTag", "setAutoPadding"]);
wrapProto("ECDH", Object.getPrototypeOf(nodeCrypto.createECDH("prime256v1")),
  ["setPrivateKey", "getPublicKey", "generateKeys", "computeSecret"]);
// The three KeyObject `export` methods. node:crypto exports no constructor carrying them, so each
// prototype is read off a sample key, the same way lib/guard-crypto.js reads them.
var _samplePair = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
wrapProto("PublicKeyObject", Object.getPrototypeOf(_samplePair.publicKey), ["export"]);
wrapProto("PrivateKeyObject", Object.getPrototypeOf(_samplePair.privateKey), ["export"]);
wrapProto("SecretKeyObject", Object.getPrototypeOf(nodeCrypto.createSecretKey(Buffer.alloc(32))), ["export"]);
// The two operations the guard reaches through something other than a module property: a static on a
// constructor, and a method three property reads deep on node's own WebCrypto.
wrapProto("ECDH", nodeCrypto.ECDH, ["convertKey"]);
wrapProto("NodeSubtle", nodeCrypto.webcrypto.subtle, ["exportKey"]);

/** Installs `hook` for `name` and returns the function that removes it. An operation this Node does
 *  not carry, or a name not in OPS, throws rather than silently never firing. */
function on(name, hook) {
  if (real[name] === undefined) {
    throw new Error("crypto-tap: " + name + " is not a wrapped node:crypto operation");
  }
  if (typeof hook !== "function") throw new TypeError("crypto-tap: on(" + name + ") needs a function");
  var had = Object.prototype.hasOwnProperty.call(hooks, name);
  var prev = hooks[name];
  hooks[name] = hook;
  return function restore() {
    if (had) hooks[name] = prev; else delete hooks[name];
  };
}

/** Installs several hooks at once, as {name: hook}, and returns one restore function for the set. */
function onAll(spec) {
  var undo = Object.keys(spec).map(function (name) { return on(name, spec[name]); });
  return function restore() { for (var i = undo.length - 1; i >= 0; i--) undo[i](); };
}

/** Counts calls to `name` while `fn` runs, keyed by the first argument, and returns the counts. */
function count(name, fn) {
  var counts = Object.create(null);
  var restore = on(name, function (realFn, args) {
    var key = String(args[0]);
    counts[key] = (counts[key] || 0) + 1;
    return realFn.apply(null, args);
  });
  try { return { counts: counts, value: fn() }; } finally { restore(); }
}

module.exports = { on: on, onAll: onAll, count: count, real: real, ops: OPS.slice() };
