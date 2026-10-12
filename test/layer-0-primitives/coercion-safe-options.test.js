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
    subject: "AA", subjectPublicKey: pub,
    notBefore: new Date("2020-01-01Z"), notAfter: new Date("2040-01-01Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] },
  }, { key: priv });
  var signer = { cert: aa, key: priv };
  function acSpec(over) {
    var s = { holder: { entityName: { directoryName: "H" } }, serialNumber: 1n,
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
  }, "entityName", { directoryName: "H" });

  // A control the caller asked for reaches the request.
  await agrees("crmf.build controls", function (o) {
    return pki.crmf.build({ certTemplate: { subject: "x", publicKey: pub }, controls: o }, priv, {})
      .then(function (der) { return (pki.schema.crmf.parse(der).messages[0].controls || []).length; });
  }, "authenticator", "hunter2");

  // The enrollment arm and the support operation the caller named are the ones that get sent. The
  // transport answers so the call reaches the arm read rather than stopping at the network.
  function sessionWith(seen) {
    return pki.cmp.session({ url: "http://cmp.invalid/x", mac: { secret: Buffer.from("s") },
      recipient: { directoryName: "R" }, sender: { directoryName: "S" },
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
  }, "ir", { certTemplate: { subject: "x", publicKey: pub }, key: priv });

  await agrees("cmp.session info", function (o) {
    var seen = {};
    return sessionWith(seen).info(o).then(
      function () { return seen.sent === true; },
      function (e) { if (seen.sent === true) return true; throw e; });
  }, "caCerts", true);

  // A distribution point the caller named is read as a distribution point, not as a bare name.
  await agrees("crl.sign freshestCRL", function (o) {
    return pki.crl.sign({ thisUpdate: new Date("2021-01-01Z"),
      nextUpdate: new Date("2031-01-01Z"), crlNumber: 1n, revoked: [],
      extensions: { freshestCRL: [o] } }, { cert: aa, key: priv })
      .then(function (der) { return der.length > 0; });
  }, "fullName", [{ uniformResourceIdentifier: "http://crl.example/d.crl" }]);

  // The message arm the caller named is the one that is encoded.
  await agrees("cmp.build body arm", function (o) {
    return pki.cmp.build({ header: { sender: { directoryName: "S" }, recipient: { directoryName: "R" } },
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
    subject: "leaf.example", subjectPublicKey: pub,
    notBefore: new Date("2021-01-01Z"), notAfter: new Date("2031-01-01Z"),
    extensions: { basicConstraints: { cA: false } },
  }, { cert: aa, key: priv });
  await agrees("path.validate opts", function (o) {
    o.trustAnchors = [aaAnchor];
    o.time = new Date("2025-01-01Z");
    return pki.path.validate([leafNoPolicy], o).then(function (r) { return r.valid; });
  }, "initialExplicitPolicy", true);
}

/* The options DOOR is what makes a multi-read of an option harmless, so it is pinned behaviorally
   rather than reasoned about. `pki.cms.verify` reads `opts.content`, `opts.time` and `opts.requiredEku`
   more than once each, and an accessor on any of them could answer differently across those reads: a
   `content` reporting the embedded value to the agreement check and something else afterwards would
   have the verdict describe a check that ran on a value the caller never supplied. None of them is
   reachable, because the door refuses an accessor-backed option before the first read. Asserted with a
   COUNTING getter, so a door that stopped refusing would show as a read rather than as a silent pass. */
async function runOptionAccessorDoor() {
  var names = ["content", "time", "requiredEku", "certs", "trustAnchors"];
  var leaked = [], accepted = [];
  for (var i = 0; i < names.length; i++) {
    var reads = 0;
    var bag = {};
    (function (n) {
      Object.defineProperty(bag, n, {
        enumerable: true, configurable: true,
        get: function () { reads++; return Buffer.from("x"); },
      });
    })(names[i]);
    var code = "NO-THROW";
    try { await pki.cms.verify(Buffer.alloc(4), bag); }
    catch (e) { code = e.code || e.constructor.name; }
    if (code !== "cms/bad-input") accepted.push(names[i] + " -> " + code);
    if (reads !== 0) leaked.push(names[i] + " read " + reads + " time(s)");
  }
  check("pki.cms.verify refuses an accessor-backed option before reading it (" +
    (accepted.length ? accepted.join(", ") : names.length + " refused") +
    (leaked.length ? "; " + leaked.join(", ") : "; 0 reads") + ")",
  accepted.length === 0 && leaked.length === 0);
  /* CONTROL: the same options carried as plain values reach the verb and fail for the document, not
     for the option, so the refusal above is about the accessor. */
  var plainCode = "NO-THROW";
  try { await pki.cms.verify(Buffer.alloc(4), { content: Buffer.from("x") }); }
  catch (e2) { plainCode = e2.code || e2.constructor.name; }
  check("CONTROL the same option as a plain value is read and the document is what fails (" +
    plainCode + ")", plainCode !== "cms/bad-input");
}

async function run() {
  var buf32 = Buffer.alloc(32);
  var sct = { logId: buf32, timestamp: 0n, signature: buf32, hashAlg: "sha256", sigAlg: "ecdsa" };
  await runOptionAccessorDoor();

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

  // ---- a switch option is the boolean it documents, typed at the verb's door ----
  // A switch read with `!== false`, `=== true` or a truthiness test answers for every value, so a
  // boolean that arrived as a string or a number selects a state the caller did not ask for and the
  // call succeeds without saying so. Each door below accepts true, false and absence, and refuses
  // everything else with its own typed code.
  await runSwitchDoorVectors();

  // ---- a null option reads as an omitted one ----
  // A presence test written against `undefined` alone takes a `null` as a value the caller
  // stated, so an option left out as null was validated as if it were content and refused,
  // or forwarded as a value nobody set. Each pair below drives the same verb twice and the
  // two outcomes have to agree.
  await runNullIsAbsenceVectors();

  console.log("CHECKS " + helpers.getChecks());
}

// `null` and an omitted option must reach the same outcome. Comparing the two is the whole
// assertion: either both are accepted or both are refused the same way, and a difference is
// the option being read as content on one path and absence on the other.
async function agreesWithOmitted(label, run) {
  var a = await settled(function () { return run({}); });
  var b = await settled(function () { return run(null); });
  check(label + ": omitted reaches the verb (" + a.slice(0, 70) + ")", a.indexOf("throw:") !== 0);
  check(label + ": null reads as omitted" + (a === b ? "" : " (omitted " + a.slice(0, 60) +
    " / null " + b.slice(0, 60) + ")"), a === b);
}

async function runNullIsAbsenceVectors() {
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2036-01-01T00:00:00Z");
  var kp = await pki.key.generate("Ed25519");
  var key = await pki.key.export(kp.privateKey);
  var spki = await pki.key.export(kp.publicKey);
  var cert = await pki.x509.sign({ subject: "null-abs", subjectPublicKey: spki,
    notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] } }, { key: key });
  var data = Buffer.from("payload");

  // An option whose absence selects a default: the default has to be what null selects.
  await agreesWithOmitted("cms.digest opts.digestAlgorithm", function (o) {
    return pki.cms.digest(data, { digestAlgorithm: o === null ? null : undefined })
      .then(function (der) { return pki.schema.cms.parse(der).digestAlgorithm.name; });
  });
  await agreesWithOmitted("cms.digest opts.contentType", function (o) {
    return pki.cms.digest(data, { contentType: o === null ? null : undefined })
      .then(function (der) { return pki.schema.cms.parse(der).encapContentInfo.eContentType; });
  });
  await agreesWithOmitted("cms.compress opts.level", function (o) {
    return pki.cms.compress(data, { level: o === null ? null : undefined })
      .then(function (der) { return der.length > 0; });
  });
  // The possession statement is what reads `includeCertificate`, so the vector has to carry
  // one: varying any other option leaves the defaulting this pins unexercised. The observable
  // is whether the statement put the certificate on the wire, which is what the flag decides.
  var possCert = await pki.x509.sign({ subject: "poss signer", subjectPublicKey: spki,
    notBefore: NB, notAfter: NA, extensions: { keyUsage: ["digitalSignature"] } }, { key: key });
  var possParsed = pki.schema.x509.parse(possCert);
  var possIssuer = possParsed.issuer.bytes;
  var possSerial = possParsed.serialNumber;
  function possessionCsr(flag) {
    var statement = { signer: { issuer: possIssuer, serialNumber: possSerial }, certificate: possCert };
    if (flag !== undefined) statement.includeCertificate = flag;
    return pki.csr.sign({ subject: "r", subjectPublicKey: spki,
      privateKeyPossessionStatement: statement }, key);
  }
  // The arrival control: `false` leaves the certificate off the wire, so it MUST encode shorter
  // than an omitted flag. Without this the null-equals-omitted check below would pass even if
  // nothing read the flag at all.
  var possOmitted = (await possessionCsr(undefined)).length;
  var possFalse = (await possessionCsr(false)).length;
  check("csr.sign includeCertificate: false emits the compact statement (omitted " + possOmitted +
    "B, false " + possFalse + "B)", possFalse < possOmitted);
  await agreesWithOmitted("csr.sign privateKeyPossessionStatement.includeCertificate", function (o) {
    return possessionCsr(o === null ? null : undefined).then(function (der) { return "csr=" + der.length; });
  });
  await agreesWithOmitted("x509.extension opts.critical", function (o) {
    return Promise.resolve(pki.x509.extension("certificatePolicies", ["domain-validated"],
      { critical: o === null ? null : undefined })).then(function (der) {
      return pki.asn1.decode(der).children.length;
    });
  });
  await agreesWithOmitted("cms.sign opts.signingTime", function (o) {
    return pki.cms.sign(data, [{ cert: cert, key: key }],
      { eContentType: "data", detached: false, signingTime: o === null ? null : undefined })
      .then(function (der) {
        var si = pki.schema.cms.parse(der).signerInfos[0];
        return (si.signedAttrs || []).length;
      });
  });
  await agreesWithOmitted("path.crlChecker opts.useDeltas", function (o) {
    return Promise.resolve(typeof pki.path.crlChecker([],
      { useDeltas: o === null ? null : undefined }).check);
  });

  // ---- the two options where `null` is a VALUE, not absence ----
  // `expectedTopOrigin: null` states that the ceremony must be unframed (WebAuthn sec. 5.8.1),
  // so it is a check the caller asked for and not an option they left out. Read as absence the
  // check silently stopped running, which is the regression this pins.
  check("webauthn.verify expectedTopOrigin: null is a stated expectation, not an omission",
    (function () {
      var src = require("node:fs").readFileSync(
        require("node:path").join(__dirname, "..", "..", "lib", "webauthn.js"), "utf8");
      return src.indexOf("opts.expectedTopOrigin !== undefined") !== -1;
    })());

  // A trust anchor's members RESTRICT what it may certify, so a `null` is a malformed spec
  // rather than an omission: reading it as absent would build a wider anchor than described.
  var anchorNulls = [
    ["certPath", { taInfo: { pubKey: spki, keyId: Buffer.from([1]), certPath: null } }],
    ["policyFlags", { taInfo: { pubKey: spki, keyId: Buffer.from([1]),
      certPath: { taName: "TA", policyFlags: null } } }],
  ];
  for (var ai = 0; ai < anchorNulls.length; ai++) {
    var verdict = await settled(function () {
      return pki.trustanchor.build({ anchors: [anchorNulls[ai][1]] });
    });
    check("trustanchor.build a null " + anchorNulls[ai][0] + " is refused, not read as absent (" +
      verdict.slice(0, 60) + ")", verdict.indexOf("throw:trustanchor/bad-input") === 0);
  }
}

// A value standing for "the option was not passed at all", which is one of the accepted forms.
var OMIT = { omitted: true };

// A transport that answers, so a client verb reaches the option read instead of stopping at the
// network. The status it reports is not what these vectors pin.
function stubTransport() {
  return Promise.resolve({ status: 503, headers: {}, body: Buffer.alloc(0) });
}

async function doorVerdict(run, v) {
  try { await run(v); return { refused: false, code: "", msg: "" }; }
  catch (e) {
    return { refused: true, code: (e && e.code) || (e && e.name) || "throw",
      msg: String((e && e.message) || "") };
  }
}

// The verdict under test is "this door refused THIS option", which is the typed code plus the
// option's own name in the message. A fixture that fails for another reason raises a different
// code, or the same code about something else, and does not pass as the door's answer. Naming the
// option is itself part of the contract: a caller told only "bad input" cannot find the typo.
function refusedOption(r, code, option) {
  return r.refused && r.code === code && r.msg.indexOf(option) !== -1;
}

// `run(v)` drives the shipped verb with the switch set to `v`, or omitted when `v` is OMIT.
// `controls` narrows the accepted-value control set for a verb where one boolean is refused on its
// own merits, which is a different and correct refusal.
async function switchDoor(label, run, code, option, controls) {
  // The control. Both booleans and the two absence forms must get PAST this door, or the refusals
  // below would be the fixture failing rather than the switch being typed.
  var ctl = controls ||
    [["true", true], ["false", false], ["an omitted option", OMIT], ["null", null]];
  for (var c = 0; c < ctl.length; c++) {
    var got = await doorVerdict(run, ctl[c][1]);
    check(label + " accepts " + ctl[c][0] + (refusedOption(got, code, option) ? " (refused " + got.msg.slice(0, 90) + ")" : ""),
      !refusedOption(got, code, option));
  }
  // `null` is the absent form, so it has to reach the same verdict the omitted option reaches.
  // Accepting both is not enough: a consumer that tests presence with `!== undefined` takes a
  // `null` as a value the caller stated and reads it as the off state, which is a different answer
  // from the default an omitted option selects. Only comparing the two outcomes sees that.
  var nullVerdict = await doorVerdict(run, null);
  var omitVerdict = await doorVerdict(run, OMIT);
  check(label + ": null reads as the omitted option does (null -> " +
    (nullVerdict.refused ? nullVerdict.code : "accepted") + ", omitted -> " +
    (omitVerdict.refused ? omitVerdict.code : "accepted") + ")",
    nullVerdict.refused === omitVerdict.refused && nullVerdict.code === omitVerdict.code);
  var bad = ["false", "true", "no", 0, 1, "", "0"];
  for (var i = 0; i < bad.length; i++) {
    var r = await doorVerdict(run, bad[i]);
    check(label + " refuses " + JSON.stringify(bad[i]) + " with " + code + " naming the option" +
      (refusedOption(r, code, option) ? "" : " (got " + (r.refused ? r.code + ": " + r.msg.slice(0, 70) : "NO-THROW") + ")"),
      refusedOption(r, code, option));
  }
}

async function runSwitchDoorVectors() {
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2036-01-01T00:00:00Z");
  var kp = await pki.key.generate("Ed25519");
  var key = await pki.key.export(kp.privateKey);
  var spki = await pki.key.export(kp.publicKey);
  var caDer = await pki.x509.sign({
    subject: "Switch CA", subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"], subjectKeyIdentifier: true },
  }, { key: key });
  var signerDer = await pki.x509.sign({
    subject: "switch signer", subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"] },
  }, { cert: caDer, key: key });
  var leafDer = await pki.x509.sign({
    subject: "leaf.switch", subjectPublicKey: spki, notBefore: NB, notAfter: NA,
  }, { cert: caDer, key: key });
  var tsaDer = await pki.x509.sign({
    subject: "Switch TSA", subjectPublicKey: spki, notBefore: NB, notAfter: NA,
    extensions: { keyUsage: ["digitalSignature"], extendedKeyUsage: ["timeStamping"], extendedKeyUsageCritical: true },
  }, { key: key });
  var signers = [{ cert: signerDer, key: key }];
  var data = Buffer.from("payload");
  var imprint = { hashAlgorithm: "sha256",
    hashedMessage: Buffer.from(await pki.webcrypto.subtle.digest("SHA-256", data)) };

  // The switch written into an options bag, or left out of it when the value is OMIT.
  function withSwitch(base, k, v) {
    var o = {};
    Object.keys(base).forEach(function (bk) { o[bk] = base[bk]; });
    if (v !== OMIT) o[k] = v;
    return o;
  }

  // ---- CMS ----
  await switchDoor("cms.sign opts.certificates", function (v) {
    return pki.cms.sign(data, signers, withSwitch({ eContentType: "data", detached: false }, "certificates", v));
  }, "cms/bad-input", "certificates");

  await switchDoor("cms.sign opts.signedAttributes", function (v) {
    return pki.cms.sign(data, signers, withSwitch({ eContentType: "data", detached: false }, "signedAttributes", v));
  }, "cms/bad-input", "signedAttributes");

  // Read two ways in one module (`!== true` for the shape, `!opts.detached` for the content), so
  // `detached: "false"` took the attached branch and then omitted the content from it.
  await switchDoor("cms.sign opts.detached", function (v) {
    return pki.cms.sign(data, signers, withSwitch({ eContentType: "data" }, "detached", v));
  }, "cms/bad-input", "detached");

  await switchDoor("cms.digest opts.detached", function (v) {
    return pki.cms.digest(data, withSwitch({}, "detached", v));
  }, "cms/bad-input", "detached");

  var baseCms = await pki.cms.sign(data, signers, { eContentType: "data", detached: false });
  await switchDoor("cms.countersign opts.certificates", function (v) {
    return pki.cms.countersign(baseCms, signers, withSwitch({ signerIndex: 0 }, "certificates", v));
  }, "cms/bad-input", "certificates");

  await switchDoor("cms.authenticate opts.authenticatedAttributes", function (v) {
    return pki.cms.authenticate(data, [{ kek: Buffer.alloc(32, 7), kekId: Buffer.from("k") }],
      withSwitch({ macAlgorithm: "hmac-sha256" }, "authenticatedAttributes", v));
  }, "cms/bad-input", "authenticatedAttributes");

  // ---- OCSP ----
  var respData = { responderID: "byName", responses: [{ cert: leafDer, issuer: caDer, status: "good" }] };
  await switchDoor("ocsp.sign opts.embedCert", function (v) {
    return pki.ocsp.sign(respData, { cert: caDer, key: key }, withSwitch({}, "embedCert", v));
  }, "ocsp/bad-input", "embedCert");

  await switchDoor("ocsp.sign opts.extendedRevoke", function (v) {
    return pki.ocsp.sign(respData, { cert: caDer, key: key }, withSwitch({}, "extendedRevoke", v));
  }, "ocsp/bad-input", "extendedRevoke");

  // ---- TSP ----
  await switchDoor("tsp.sign opts.ordering", function (v) {
    return pki.tsp.sign(imprint, { cert: tsaDer, key: key },
      withSwitch({ policy: "1.3.6.1.4.1.1", serialNumber: 1 }, "ordering", v));
  }, "tsp/bad-input", "ordering");

  // ---- S/MIME: the header-protection control. Read by coercion, `protectHeaders: "true"` left
  // RFC 9788 header protection off and the message went out unprotected.
  await switchDoor("smime.sign opts.protectHeaders", function (v) {
    return pki.smime.sign(data, signers, withSwitch({ headers: { Subject: "s" } }, "protectHeaders", v));
  }, "smime/bad-input", "protectHeaders");

  await switchDoor("smime.encrypt opts.protectHeaders", function (v) {
    return pki.smime.encrypt(data, [signerDer], withSwitch({ headers: { Subject: "s" } }, "protectHeaders", v));
  }, "smime/bad-input", "protectHeaders");

  // ---- PKCS#12 public-key integrity ----
  await switchDoor("pkcs12.build opts.integrity.certificates", function (v) {
    return pki.pkcs12.build({ key: key, cert: signerDer }, {
      integrity: withSwitch({ mode: "public-key", signer: { cert: signerDer, key: key } }, "certificates", v),
      mac: false, password: "pw",
    });
  }, "pkcs12/bad-input", "certificates");

  // ---- revocation: the delta-CRL merge. One line below it, `nonce` was already read this way.
  await switchDoor("path.crlChecker opts.useDeltas", function (v) {
    return pki.path.crlChecker([], withSwitch({}, "useDeltas", v));
  }, "path/bad-input", "useDeltas");

  await switchDoor("path.fetchingChecker opts.useDeltas", function (v) {
    return pki.path.fetchingChecker(withSwitch({ transport: stubTransport }, "useDeltas", v));
  }, "path/bad-input", "useDeltas");

  // ---- the extension criticality flags. The rule was written for basicConstraints.critical and
  // the six sibling flags were left coerced, so `keyUsageCritical: "false"` emitted it critical.
  var CRITICALITY = ["keyUsageCritical", "extendedKeyUsageCritical", "certificatePoliciesCritical",
    "policyMappingsCritical", "qcStatementsCritical", "tlsFeatureCritical"];
  // Each flag is paired with a value its own extension accepts: RFC 5280 sec. 4.2.1.5 refuses a
  // policy mapping to or from anyPolicy, and a qcStatements entry is { statementId, info }.
  var CRIT_VALUE = {
    keyUsageCritical: { keyUsage: ["digitalSignature"] },
    extendedKeyUsageCritical: { extendedKeyUsage: ["clientAuth"] },
    certificatePoliciesCritical: { certificatePolicies: ["domain-validated"] },
    policyMappingsCritical: { certificatePolicies: ["domain-validated"],
      policyMappings: [{ issuerDomainPolicy: "domain-validated", subjectDomainPolicy: "organization-validated" }] },
    qcStatementsCritical: { qcStatements: [{ statementId: "1.3.6.1.4.1.99999.9" }] },
    tlsFeatureCritical: { tlsFeature: ["status_request"] },
  };
  var CRIT_VERBS = [
    ["x509.sign", "x509/bad-input", function (ext) {
      return pki.x509.sign({ subject: "crit", subjectPublicKey: spki, notBefore: NB, notAfter: NA,
        extensions: ext }, { key: key });
    }],
    // The csr spec carries the requested v3 extensions as `extensionRequest`.
    ["csr.sign", "csr/bad-input", function (ext) {
      return pki.csr.sign({ subject: "crit", subjectPublicKey: spki, extensionRequest: ext }, key);
    }],
  ];
  for (var ci = 0; ci < CRITICALITY.length; ci++) {
    for (var vi = 0; vi < CRIT_VERBS.length; vi++) {
      await switchDoor(CRIT_VERBS[vi][0] + " extensions." + CRITICALITY[ci],
        (function (flag, drive) {
          return function (v) { return drive(withSwitch(CRIT_VALUE[flag], flag, v)); };
        })(CRITICALITY[ci], CRIT_VERBS[vi][2]), CRIT_VERBS[vi][1], CRITICALITY[ci]);
    }
  }

  // ---- the enrollment clients' cross-origin redirect switch. It WEAKENS a check, and read by
  // truthiness `allowCrossOriginRedirect: "false"` allowed the redirect it was meant to refuse.
  // The transport answers so the call reaches the read rather than stopping at the network; what
  // it answers does not matter, because the verdict under test is this door's own refusal.
  await switchDoor("est.cacerts opts.allowCrossOriginRedirect", function (v) {
    return pki.est.cacerts("https://est.invalid",
      withSwitch({ transport: stubTransport }, "allowCrossOriginRedirect", v));
  }, "est/bad-input", "allowCrossOriginRedirect");

  await switchDoor("scep.getCACert opts.allowCrossOriginRedirect", function (v) {
    return pki.scep.getCACert("http://scep.invalid/scep",
      withSwitch({ transport: stubTransport }, "allowCrossOriginRedirect", v));
  }, "scep/bad-input", "allowCrossOriginRedirect");

  // This CSR advertises no key-encryption attribute, so `requestedEncryption: true` contradicts it
  // and is refused on its own merits (RFC 7030 sec. 4.4.1). The control set is the three values
  // this request can carry; what the vectors below pin is that a non-boolean is refused for being
  // one, rather than passing the door and being read as whichever state its truthiness matched.
  var csrDer = await pki.csr.sign({ subject: "switch requester", subjectPublicKey: spki }, key);
  await switchDoor("est.serverkeygen opts.requestedEncryption", function (v) {
    return pki.est.serverkeygen("https://est.invalid", csrDer,
      withSwitch({ transport: stubTransport }, "requestedEncryption", v));
  }, "est/bad-input", "requestedEncryption",
  [["false", false], ["an omitted option", OMIT], ["null", null]]);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
