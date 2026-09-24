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

// The same option written two ways: enumerable (the control) and non-enumerable.
function visible(k, v) { var o = {}; o[k] = v; return o; }
function hidden(k, v) {
  var o = {};
  Object.defineProperty(o, k, { value: v, enumerable: false, configurable: true, writable: true });
  return o;
}
async function settled(fn) {
  try { return "ok:" + JSON.stringify(await fn()); }
  catch (e) { return "throw:" + (e && e.code ? e.code : e && e.name) + ":" + String(e && e.message).slice(0, 60); }
}
async function agrees(label, run, k, v) {
  var a = await settled(function () { return run(visible(k, v)); });
  var b = await settled(function () { return run(hidden(k, v)); });
  // The enumerable call is the control, and it has to REACH the read under test. A spec field this
  // verb refuses at its door fails both calls the same way, and the comparison below then passes
  // whatever the read does, which is a vector that asserts nothing.
  check(label + ": the enumerable control reaches the read (" + a + ")", a.indexOf("ok:") === 0);
  check(label + " reads a non-enumerable own option the same as an enumerable one" +
    (a === b ? "" : " (enumerable " + a + " / non-enumerable " + b + ")"), a === b);
}

async function runOwnPropertyOptionVectors() {
  var kp = await pki.key.generate("Ed25519");
  var priv = await pki.key.export(kp.privateKey);
  var pub = await pki.key.export(kp.publicKey);
  var aa = await pki.x509.sign({
    subject: "CN=AA", subjectPublicKey: pub,
    notBefore: new Date("2020-01-01Z"), notAfter: new Date("2040-01-01Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: priv });
  var signer = { cert: aa, key: priv };
  function acSpec(over) {
    var s = { holder: { entityName: { directoryName: "CN=H" } }, serialNumber: 1n,
      notBeforeTime: new Date("2021-01-01Z"), notAfterTime: new Date("2031-01-01Z"),
      attributes: { role: { roleName: { uniformResourceIdentifier: "urn:x" } } } };
    Object.keys(over).forEach(function (k) { s[k] = over[k]; });
    return s;
  }

  // An extension the caller asked for reaches the signed certificate.
  await agrees("attrcert.sign extensions", function (o) {
    return pki.attrcert.sign(acSpec({ extensions: o }), signer).then(function (der) {
      return (pki.schema.attrcert.parse(der).extensions || []).map(function (e) { return e.extnID; });
    });
  }, "noRevAvail", true);

  // An attribute the caller asked for reaches the signed certificate.
  await agrees("attrcert.sign attributes", function (o) {
    return pki.attrcert.sign(acSpec({ attributes: o }), signer).then(function (der) {
      return pki.schema.attrcert.parse(der).attributes.length;
    });
  }, "role", { roleName: { uniformResourceIdentifier: "urn:y" } });

  // The holder form the caller named is the one that is found.
  await agrees("attrcert.sign holder", function (o) {
    return pki.attrcert.sign(acSpec({ holder: o }), signer).then(function (der) { return der.length > 0; });
  }, "entityName", { directoryName: "CN=H" });

  // A control the caller asked for reaches the request.
  await agrees("crmf.build controls", function (o) {
    return pki.crmf.build({ certTemplate: { subject: "CN=x", publicKey: pub }, controls: o }, priv, {})
      .then(function (der) { return (pki.schema.crmf.parse(der).messages[0].controls || []).length; });
  }, "authenticator", "hunter2");

  // The enrollment arm and the support operation the caller named are the ones that get sent. The
  // transport answers so the call reaches the arm read rather than stopping at the network.
  function sessionWith(seen) {
    return pki.cmp.session({ url: "http://cmp.invalid/x", mac: { secret: Buffer.from("s") },
      recipient: { directoryName: "CN=R" }, sender: { directoryName: "CN=S" },
      transport: function () {
        seen.sent = true;
        return Promise.reject(new Error("the request was built; the response is not what this pins"));
      } });
  }
  await agrees("cmp.session enroll", function (o) {
    var seen = {};
    return sessionWith(seen).enroll(o).then(
      function () { return seen.sent === true; },
      function (e) { if (seen.sent === true) return true; throw e; });
  }, "ir", { certTemplate: { subject: "CN=x", publicKey: pub }, key: priv });

  await agrees("cmp.session info", function (o) {
    var seen = {};
    return sessionWith(seen).info(o).then(
      function () { return seen.sent === true; },
      function (e) { if (seen.sent === true) return true; throw e; });
  }, "caCerts", true);

  // A distribution point the caller named is read as a distribution point, not as a bare name.
  await agrees("crl.sign freshestCRL", function (o) {
    return pki.crl.sign({ thisUpdate: new Date("2021-01-01Z"),
      nextUpdate: new Date("2031-01-01Z"), revoked: [],
      extensions: { freshestCRL: [o] } }, { cert: aa, key: priv })
      .then(function (der) { return der.length > 0; });
  }, "fullName", [{ uniformResourceIdentifier: "http://crl.example/d.crl" }]);

  // The message arm the caller named is the one that is encoded.
  await agrees("cmp.build body arm", function (o) {
    return pki.cmp.build({ header: { sender: { directoryName: "CN=S" }, recipient: { directoryName: "CN=R" } },
      body: o }, { mac: { secret: Buffer.from("s") } }).then(function (der) { return der.length > 0; });
  }, "genm", []);

  // An attribute the caller named in an RDN reaches the encoded name.
  await agrees("x509.sign subject RDN", function (o) {
    return pki.x509.sign({ subject: [o], subjectPublicKey: pub,
      notBefore: new Date("2021-01-01Z"), notAfter: new Date("2031-01-01Z") }, { cert: aa, key: priv })
      .then(function (der) { return pki.schema.x509.parse(der).subject.rdns.length; });
  }, "commonName", "leaf.example");

  // Every parsed record is built by the schema engine writing the field names a schema declares.
  // An accessor planted on Object.prototype under one of those names must not take the write: a
  // getter-only slot would throw out of an ordinary parse, and a setter would swallow the decoded
  // value and leave the caller reading the attacker's.
  var hijacked = [];
  ["signatureAlgorithm", "signatureValue", "tbsBytes", "version", "serialNumber",
    "issuer", "subject", "validity", "extensions"].forEach(function (n) {
    Object.defineProperty(Object.prototype, n, { get: function () { return "HIJACKED"; }, configurable: true });
    try {
      var parsed = pki.schema.x509.parse(aa);
      if (!Object.prototype.hasOwnProperty.call(parsed, n) || parsed[n] === "HIJACKED") hijacked.push(n);
    } catch (e) { hijacked.push(n + ":" + e.name); }
    delete Object.prototype[n];
  });
  check("a certificate parses to own fields with an accessor planted on Object.prototype" +
    (hijacked.length ? " (" + hijacked.join(", ") + ")" : ""), hijacked.length === 0);

  // A trust-anchor constraint never widens what the caller asked for: the caller's own option
  // stays in force whatever its descriptor, so adding a constraint cannot turn a refusal into an
  // acceptance (RFC 5937 sec. 3.2).
  var aaAnchor = pki.path.anchorFromCert(pki.schema.x509.parse(aa));
  var leafNoPolicy = await pki.x509.sign({
    subject: "CN=leaf.example", subjectPublicKey: pub,
    notBefore: new Date("2021-01-01Z"), notAfter: new Date("2031-01-01Z"),
    extensions: { basicConstraints: { cA: false } },
  }, { cert: aa, key: priv });
  await agrees("path.validate opts", function (o) {
    o.trustAnchors = [aaAnchor];
    o.time = new Date("2025-01-01Z");
    return pki.path.validate([leafNoPolicy], o).then(function (r) { return r.valid; });
  }, "initialExplicitPolicy", true);
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

  // ---- an option is an own property, whatever its descriptor says ----
  // Every door reads a bag with Reflect.ownKeys, which reports a non-enumerable own property, so
  // such an option is accepted. A read that enumerates the same bag with Object.keys skips it, and
  // the caller is told nothing: the extension they asked for is left out of what gets signed, or
  // the check they asked for never runs. Each case is the same option written both ways, and the
  // two must agree.
  await runOwnPropertyOptionVectors();

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
