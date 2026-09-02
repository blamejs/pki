// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the coercion-safe option contract, shared across every public build/sign/enrollment
 * verb: a caller option of an unexpected type (a BigInt, an Object.create(null), or an object whose
 * Symbol.toPrimitive throws) must be refused with the module's typed PkiError (a domain/reason code),
 * never a native TypeError/RangeError leaking from a JSON.stringify, a String()/`+` coercion, a
 * property-key lookup, a new Date(), or a Number() on the value. Drives the SHIPPED consumer paths.
 * The rendering (guard.text.showValue), lookup-key (guard.text.keyOf), and Date (guard.time.toDate)
 * primitives are contract-pinned in guard-text.test.js / guard-time.test.js; this file proves they
 * are WIRED at each verb.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;

// A caller value with no primitive form (property-key coercion / Number() / String() throw on it).
function nullProto() { return Object.create(null); }
// A caller value whose Symbol.toPrimitive throws when anything coerces it.
function poison() {
  var o = {};
  Object.defineProperty(o, Symbol.toPrimitive, { value: function () { throw new RangeError("poison"); } });
  return o;
}
// The class invariant: a typed PkiError carries a "domain/reason" code; a native throw does not.
function isTyped(e) { return !!(e && typeof e.code === "string" && e.code.indexOf("/") > 0); }
async function typed(fn) {
  try { await fn(); return "NO-THROW"; }
  catch (e) { return isTyped(e) ? true : ("NATIVE:" + (e && e.constructor && e.constructor.name)); }
}

async function run() {
  var buf32 = Buffer.alloc(32);
  var sct = { logId: buf32, timestamp: 0n, signature: buf32, hashAlg: "sha256", sigAlg: "ecdsa" };

  // ---- property-key coercion -> guard.text.keyOf ----
  check("tsp.request hashAlgorithm=Object.create(null) -> typed", (await typed(function () { return pki.tsp.request({ hashAlgorithm: nullProto(), hashedMessage: buf32 }, {}); })) === true);
  check("ocsp.buildErrorResponse(Object.create(null)) -> typed", (await typed(function () { return pki.ocsp.buildErrorResponse(nullProto()); })) === true);
  check("ocsp.buildErrorResponse(poison) -> typed", (await typed(function () { return pki.ocsp.buildErrorResponse(poison()); })) === true);
  check("scep.build messageType=Object.create(null) -> typed", (await typed(function () { return pki.scep.build({ messageType: nullProto() }); })) === true);
  check("acme.assertTransition(Object.create(null),..) -> typed", (await typed(function () { return pki.acme.assertTransition(nullProto(), "pending", "valid"); })) === true);
  check("acme.assertTransition('order',Object.create(null),..) -> typed", (await typed(function () { return pki.acme.assertTransition("order", nullProto(), "valid"); })) === true);
  check("acme.validate(Object.create(null),{}) -> typed", (await typed(function () { return pki.acme.validate(nullProto(), {}); })) === true);
  check("pkcs12.build pbmac1 hash=Object.create(null) -> typed", (await typed(function () { return pki.pkcs12.build({ safeContents: [{ bags: [] }] }, { password: "x", mac: { algorithm: "pbmac1", hash: nullProto() } }); })) === true);
  check("hpke.setupS kem=Object.create(null) -> typed", (await typed(function () { return pki.hpke.setupS({ kem: nullProto(), kdf: 1, aead: 1 }, buf32, {}); })) === true);
  check("hpke.setupS kdf=Object.create(null) -> typed", (await typed(function () { return pki.hpke.setupS({ kem: 0x0010, kdf: nullProto(), aead: 1 }, buf32, {}); })) === true);
  check("hpke.setupS aead=Object.create(null) -> typed", (await typed(function () { return pki.hpke.setupS({ kem: 0x0010, kdf: 0x0001, aead: nullProto() }, buf32, {}); })) === true);
  check("hpke.setupS kem=poison -> typed", (await typed(function () { return pki.hpke.setupS({ kem: poison(), kdf: 1, aead: 1 }, buf32, {}); })) === true);

  // ---- diagnostic rendering -> guard.text.showValue ----
  check("scep.getCACaps(Object.create(null)) -> typed", (await typed(function () { return pki.scep.getCACaps(nullProto()); })) === true);
  check("scep.getCACaps(poison) -> typed", (await typed(function () { return pki.scep.getCACaps(poison()); })) === true);
  check("cmp.wellKnownUrl(Object.create(null)) -> typed", (await typed(function () { return pki.cmp.wellKnownUrl(nullProto()); })) === true);
  check("cmp.wellKnownUrl(poison) -> typed", (await typed(function () { return pki.cmp.wellKnownUrl(poison()); })) === true);
  check("est.cacerts(Object.create(null)) -> typed", (await typed(function () { return pki.est.cacerts(nullProto()); })) === true);
  check("est.cacerts(poison) -> typed", (await typed(function () { return pki.est.cacerts(poison()); })) === true);
  check("acme.assertTransition(1n,..) -> typed", (await typed(function () { return pki.acme.assertTransition(1n, "pending", "valid"); })) === true);
  check("acme.assertTransition(..,1n) -> typed", (await typed(function () { return pki.acme.assertTransition("order", "pending", 1n); })) === true);
  check("acme.validate(1n,{}) -> typed", (await typed(function () { return pki.acme.validate(1n, {}); })) === true);
  check("ct.reconstructSignedData entryType=Symbol -> typed", (await typed(function () { return pki.ct.reconstructSignedData({ entryType: Symbol("x") }, sct); })) === true);
  check("ct.reconstructSignedData entryType=Object.create(null) -> typed", (await typed(function () { return pki.ct.reconstructSignedData({ entryType: nullProto() }, sct); })) === true);
  check("sigstore.parseBundle mediaType=Symbol -> typed", (await typed(function () { return pki.sigstore.parseBundle({ mediaType: Symbol("m") }); })) === true);
  check("sigstore.parseBundle mediaType=poison -> typed", (await typed(function () { return pki.sigstore.parseBundle({ mediaType: poison() }); })) === true);

  // ---- string-method / concat precheck -> typeof-guard ----
  check("smime.sign contentType=Symbol (protectHeaders) -> typed", (await typed(function () { return pki.smime.sign(Buffer.from("x"), [], { protectHeaders: true, contentType: Symbol("ct") }); })) === true);
  check("smime.sign contentType=poison (protectHeaders) -> typed", (await typed(function () { return pki.smime.sign(Buffer.from("x"), [], { protectHeaders: true, contentType: poison() }); })) === true);

  // ---- Number() drop -> Number.isInteger typed rejection ----
  check("tsp.response status=Symbol -> typed", (await typed(function () { return pki.tsp.response(null, { status: Symbol("s") }); })) === true);
  check("tsp.response status=poison -> typed", (await typed(function () { return pki.tsp.response(null, { status: poison() }); })) === true);

  // ---- an inherited property name must miss the lookup, not resolve to Object.prototype ----
  // The lookup tables are null-proto, so "toString" / "constructor" / "__proto__" are unknown keys.
  check("ocsp.buildErrorResponse('toString') -> typed", (await typed(function () { return pki.ocsp.buildErrorResponse("toString"); })) === true);
  check("ocsp.buildErrorResponse('__proto__') -> typed", (await typed(function () { return pki.ocsp.buildErrorResponse("__proto__"); })) === true);
  check("hpke.setupS kem='constructor' -> typed", (await typed(function () { return pki.hpke.setupS({ kem: "constructor", kdf: 1, aead: 1 }, buf32, {}); })) === true);
  check("tsp.response failInfo=['toString'] -> typed", (await typed(function () { return pki.tsp.response(null, { status: 2, failInfo: ["toString"] }); })) === true);
  check("scep.build messageType='__proto__' -> typed", (await typed(function () { return pki.scep.build({ messageType: "__proto__" }); })) === true);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
