// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-identifier (@internal): fail-closed canonicalization of the
 * structured-identifier strings the toolkit compares and encodes.
 * Oracle: X.660 -- a canonical dotted-decimal OID has two or more arcs, no
 * leading-zero component, the root arc 0..2, and the second arc 0..39 under roots
 * 0 and 1. The string-OID contract is the shared primitive pki.oid name/arc
 * resolution, pki.asn1 build.oid, and pki.path.validate EKU / policy key checking
 * compose -- exercised end-to-end there; these pin its contract directly.
 */

var identifier = require("../../lib/guard-identifier");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError");
function E(code, message) { return new TestError(code, message); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
// The thrown error itself, so a vector can assert the REASON (the operator-facing message,
// the error type) and not only the code -- a code-only assertion passes against a check that
// happens to reject for some other reason entirely.
function errOf(fn) { try { fn(); return { code: "NO-THROW", message: "NO-THROW" }; } catch (e) { return e; } }

function testAcceptsCanonical() {
  check("a plain OID is returned unchanged", identifier.assertCanonicalOid("1.2.840.113549", E, "x/bad", "oid") === "1.2.840.113549");
  check("a two-arc OID is accepted", identifier.assertCanonicalOid("2.5", E, "x/bad", "oid") === "2.5");
  check("a zero arc is canonical (no leading zero)", identifier.assertCanonicalOid("2.5.29.0", E, "x/bad", "oid") === "2.5.29.0");
  check("root 2 lifts the second-arc bound", identifier.assertCanonicalOid("2.999.1", E, "x/bad", "oid", "x/bounds") === "2.999.1");
  // A UUID-based arc exceeds 2^53 -- it must survive as a BigInt without precision loss.
  check("a huge arc beyond 2^53 is accepted", identifier.assertCanonicalOid("2.25.329800735698586629295641978511506172918", E, "x/bad", "oid") === "2.25.329800735698586629295641978511506172918");
}

function testSyntaxRejects() {
  check("a leading-zero arc throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("2.05.29.15", E, "x/bad", "oid"); }) === "x/bad");
  check("a single arc throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("2", E, "x/bad", "oid"); }) === "x/bad");
  check("a non-string throws the syntax code", codeOf(function () { identifier.assertCanonicalOid(1.2, E, "x/bad", "oid"); }) === "x/bad");
  check("a trailing dot throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("1.2.", E, "x/bad", "oid"); }) === "x/bad");
  check("a non-numeric arc throws the syntax code", codeOf(function () { identifier.assertCanonicalOid("1.2.x", E, "x/bad", "oid"); }) === "x/bad");
}

function testBoundsRejects() {
  // The X.660 arc bounds throw the SEPARATE boundsCode when one is supplied.
  check("root arc above 2 throws the bounds code", codeOf(function () { identifier.assertCanonicalOid("9.9.9", E, "x/bad", "oid", "x/bounds"); }) === "x/bounds");
  check("second arc 40 under root 1 throws the bounds code", codeOf(function () { identifier.assertCanonicalOid("1.40.1", E, "x/bad", "oid", "x/bounds"); }) === "x/bounds");
  // With no boundsCode, an out-of-range arc falls back to the syntax code.
  check("bounds fault falls back to the syntax code by default", codeOf(function () { identifier.assertCanonicalOid("9.9.9", E, "x/bad", "oid"); }) === "x/bad");
}

function testBoundsWaived() {
  // boundsCode === null waives the arc-bound check (a LOOKUP key): a well-formed
  // but non-encodable OID passes syntax so the caller can treat it as a miss.
  check("boundsCode null accepts an out-of-bounds well-formed OID", identifier.assertCanonicalOid("9.9.9", E, "x/bad", "oid", null) === "9.9.9");
  // Syntax is still enforced even when bounds are waived.
  check("boundsCode null still rejects a leading-zero arc", codeOf(function () { identifier.assertCanonicalOid("2.05.1", E, "x/bad", "oid", null); }) === "x/bad");
}

// assertKnownKeys -- every own key of a caller-supplied options object must be one the
// caller recognizes. Oracle: the failure this prevents is fail-OPEN. A misspelled option
// key is silently absent, so the default applies and a caller who asked for a stricter
// check quietly gets the looser behavior with no error anywhere. The consumers compose
// this at their config-time boundary (x509.sign extensions, csr.sign spec, crl.sign
// issuingDistributionPoint, cmp.build opts, webauthn opts.tpmPolicy); these pin the
// contract directly, including the two ways a hand-rolled walk gets it wrong.
function testKnownKeys() {
  var KNOWN = { alpha: 1, beta: 1 };
  check("every known key is accepted", identifier.assertKnownKeys({ alpha: 1, beta: 2 }, KNOWN, E, "x/bad", "unknown ") === undefined);
  check("an empty object is accepted", identifier.assertKnownKeys({}, KNOWN, E, "x/bad", "unknown ") === undefined);
  var err = errOf(function () { identifier.assertKnownKeys({ alpha: 1, gamma: 3 }, KNOWN, E, "x/bad", "unknown option "); });
  check("an unknown key throws the caller's code", err.code === "x/bad");
  check("the message is the caller's wording plus the quoted key", err.message === 'unknown option "gamma"');

  // A table consulted with a truthiness test rather than hasOwnProperty accepts every
  // inherited Object member as a recognized key -- "constructor" resolves to a function,
  // which is truthy, so a caller passing { constructor: ... } sails through a hand-rolled
  // walk. The guard reads own properties only, so an inherited name is still unknown.
  check("an inherited Object member is not a known key", errOf(function () {
    identifier.assertKnownKeys({ constructor: 1 }, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");
  check("toString is not a known key", errOf(function () {
    identifier.assertKnownKeys({ toString: 1 }, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");

  // An options object built by JSON.parse can carry an OWN "__proto__" key. Object.keys
  // enumerates it (unlike a `for..in` walk over a literal, where it is the prototype
  // slot), so it must be inspected and rejected rather than skipped.
  var fromJson = JSON.parse('{"__proto__": {"alpha": 1}}');
  check("an own __proto__ key from JSON is rejected", errOf(function () {
    identifier.assertKnownKeys(fromJson, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");

  // The message may be a builder, for the callers that name the key mid-sentence and
  // follow it with the hint saying what to pass instead.
  var built = errOf(function () {
    identifier.assertKnownKeys({ gamma: 1 }, KNOWN, E, "x/bad", function (k) {
      return "unknown extension " + JSON.stringify(k) + "; pass a pre-encoded DER via the array form";
    });
  });
  check("a function message builds the whole sentence", built.message === 'unknown extension "gamma"; pass a pre-encoded DER via the array form');

  // The guard rejects through a (code, message) FACTORY, never `new` on a class -- a
  // caller holding a class adapts at the call site so the guard keeps one convention.
  var adapted = errOf(function () {
    identifier.assertKnownKeys({ gamma: 1 }, KNOWN, function (c, m) { return new TestError(c, m); }, "x/adapted", "unknown ");
  });
  check("a class adapted to a factory still throws the typed error", adapted.code === "x/adapted" && adapted instanceof TestError);

  // What counts as a method, which is the one thing the property walk skips. The distinction has
  // to hold on both sides of guard.bytes.snapshotDeep. That copy carries every readable name onto
  // the copy and keeps the prototype, so the same method is inherited before it and own after it.
  function Bag() { this.alpha = 1; }
  Bag.prototype.describe = function () { return "bag"; };
  check("an instance whose class defines a method is accepted",
        identifier.assertKnownKeys(new Bag(), KNOWN, E, "x/bad", "unknown ") === undefined);
  // The same instance after a snapshot: `describe` and `constructor` are now own properties.
  var copied = Object.create(Bag.prototype);
  copied.alpha = 1;
  copied.describe = Bag.prototype.describe;
  copied.constructor = Bag;
  check("a snapshot copy carrying its methods as own properties is accepted",
        identifier.assertKnownKeys(copied, KNOWN, E, "x/bad", "unknown ") === undefined);
  // A function value is not a free pass. It is a method only where the chain above supplies the
  // same function under that name. An unrelated function under an unknown name is still unknown.
  check("an own function under an unknown name is still reported", errOf(function () {
    identifier.assertKnownKeys({ gamma: function () {} }, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");
  // An own property shadowing a method with another function is a value the caller supplied.
  var shadow = Object.create(Bag.prototype);
  shadow.describe = function () { return "mine"; };
  check("an own property shadowing a method with another function is reported",
        errOf(function () { identifier.assertKnownKeys(shadow, KNOWN, E, "x/bad", "unknown "); }).code === "x/bad");
  // An accessor is never a method. A getter exists to answer with a value, which is what an
  // option is, including one whose value happens to be a function.
  var accessor = {};
  Object.defineProperty(accessor, "gamma", { get: function () { return function () {}; }, enumerable: false });
  check("an inherited-style accessor is reported however its value reads",
        errOf(function () { identifier.assertKnownKeys(accessor, KNOWN, E, "x/bad", "unknown "); }).code === "x/bad");

  // A name added to Object.prototype after this module loaded reaches an empty object. `{}.gamma`
  // answers while the object itself holds nothing. The built-ins are skipped by identity against
  // a snapshot taken at load, so the planted name is still reported.
  Object.defineProperty(Object.prototype, "gamma", { value: 3, writable: true, configurable: true, enumerable: false });
  var pollutedCode, restored;
  try {
    pollutedCode = errOf(function () { identifier.assertKnownKeys({}, KNOWN, E, "x/bad", "unknown "); }).code;
  } finally {
    restored = delete Object.prototype.gamma;
  }
  check("a name planted on Object.prototype is reported on an empty object", pollutedCode === "x/bad");
  check("the pollution vector leaves Object.prototype as it found it",
        restored === true && !("gamma" in Object.prototype));
  check("an empty object is accepted again once the pollution is gone",
        identifier.assertKnownKeys({}, KNOWN, E, "x/bad", "unknown ") === undefined);

  // A prototype chain is finite only while it is acyclic. A Proxy whose `getPrototypeOf` trap
  // returns the proxy itself makes a cycle, which the engine permits while the target stays
  // extensible. A walk with no cycle test never returns, and the verb hangs before it has read a
  // single option. The names are still complete, since a second lap yields nothing new.
  var cyclicTarget = { alpha: 1, gamma: 3 };
  var cyclic = new Proxy(cyclicTarget, { getPrototypeOf: function () { return cyclic; } });
  check("the fixture really is a cycle", Object.getPrototypeOf(cyclic) === cyclic);
  var cyclicNames = identifier.readableNames(cyclic);
  check("a cyclic prototype chain terminates and reports every own name",
        cyclicNames.length === 2 && cyclicNames.indexOf("alpha") >= 0 && cyclicNames.indexOf("gamma") >= 0);
  check("the unknown key on a cyclic chain is still refused", errOf(function () {
    identifier.assertKnownKeys(cyclic, KNOWN, E, "x/bad", "unknown ");
  }).code === "x/bad");
}

// Every config-time boundary that composes assertKnownKeys must still raise its OWN typed error.
//
// This is the behavioral guard for routing those checks through one home. The failure it catches is
// invisible from the happy path: a caller that hands the guard an error CLASS where it expects a
// (code, message) FACTORY raises "class constructor cannot be invoked without new" instead of the
// verdict -- and only when the check actually fires, which is the branch a valid-input test never
// takes. So each boundary is driven through the SHIPPED verb with an unrecognized key.
async function testConsumersFailClosed() {
  var pki = require("../../index.js");
  var BAD = { nope___: 1 };
  // The issuance verbs check for a signing key BEFORE they walk the spec, so a case built without
  // one never reaches the check under test and passes on an unrelated fault. A real key is cheaper
  // than reordering the verb's gates, which would weaken a check to suit a test.
  var kp = await pki.webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  var keySpki = Buffer.from(await pki.webcrypto.subtle.exportKey("spki", kp.publicKey));
  var ISSUER = { key: kp.privateKey, name: [{ commonName: "Test Issuer" }], publicKey: keySpki };
  var NB = new Date("2026-01-01T00:00:00Z"), NA = new Date("2027-01-01T00:00:00Z");
  function cert(over) {
    return Object.assign({ subject: [{ commonName: "x" }], subjectPublicKey: keySpki,
      serialNumber: Buffer.from([1]), notBefore: NB, notAfter: NA }, over);
  }
  function crl(over) {
    return Object.assign({ issuer: [{ commonName: "x" }], thisUpdate: NB, nextUpdate: NA }, over);
  }
  function ac(over) {
    return Object.assign({ holder: { entityName: [{ dNSName: "holder.test" }] }, serialNumber: Buffer.from([1]),
      notBeforeTime: NB, notAfterTime: NA, attributes: { role: { roleName: { uniformResourceIdentifier: "urn:role:test" } } } }, over);
  }
  var CASES = [
    ["x509.sign extensions", "x509/bad-input", function () { return pki.x509.sign(cert({ extensions: BAD }), ISSUER); }],
    ["csr.sign spec", "csr/bad-input", function () { return pki.csr.sign(Object.assign({ subject: [{ commonName: "x" }] }, BAD), null); }],
    ["crl.sign extensions", "crl/bad-input", function () { return pki.crl.sign(crl({ extensions: BAD }), ISSUER); }],
    ["crl.sign issuingDistributionPoint", "crl/bad-idp", function () { return pki.crl.sign(crl({ extensions: { issuingDistributionPoint: BAD } }), ISSUER); }],
    ["attrcert.sign spec", "attrcert/bad-input", function () { return pki.attrcert.sign(ac(BAD), ISSUER); }],
    ["attrcert.sign holder", "attrcert/bad-input", function () { return pki.attrcert.sign(ac({ holder: BAD }), ISSUER); }],
    ["attrcert.sign attributes", "attrcert/bad-input", function () { return pki.attrcert.sign(ac({ attributes: BAD }), ISSUER); }],
    ["attrcert.sign extensions", "attrcert/bad-input", function () { return pki.attrcert.sign(ac({ extensions: BAD }), ISSUER); }],
    ["crmf.build spec", "crmf/bad-input", function () { return pki.crmf.build(Object.assign({ certTemplate: {} }, BAD), {}); }],
    ["crmf.build certTemplate", "crmf/bad-input", function () { return pki.crmf.build({ certTemplate: BAD }, {}); }],
    ["crmf.build controls", "crmf/bad-input", function () { return pki.crmf.build({ certTemplate: {}, controls: BAD }, {}); }],
    ["cmp.build message", "cmp/bad-input", function () { return pki.cmp.build(Object.assign({ header: {}, body: {} }, BAD), {}); }],
    ["cmp.build opts", "cmp/bad-input", function () { return pki.cmp.build({ header: {}, body: {} }, BAD); }],
    ["cmp.wellKnownUrl opts", "cmp/bad-input", function () { return pki.cmp.wellKnownUrl("https://a.test", BAD); }],
    ["cmp.session opts", "cmp/bad-input", function () { return pki.cmp.session(BAD); }],
    ["cmp.verify opts", "cmp/bad-input", function () { return pki.cmp.verify(Buffer.alloc(4), BAD); }],
    ["ct.fetchLogList opts", "ct/bad-input", function () { return pki.ct.fetchLogList(BAD); }],
    ["webauthn.verifyMetadataBlob opts", "webauthn/bad-input", function () { return pki.webauthn.verifyMetadataBlob("a.b.c", BAD); }],
  ];
  // The assertion is on the code AND on the message naming the offending key. Asserting the code
  // alone is worthless here: every one of these verbs has other config-time faults that raise the
  // same generic code, so a vector whose spec is incomplete passes while never reaching the walk at
  // all -- which is exactly what happened to the first draft of this list.
  for (var i = 0; i < CASES.length; i++) {
    var c = CASES[i], got;
    try { await c[2](); got = "NO-THROW"; }
    catch (e) {
      got = !(e instanceof pki.errors.PkiError) ? "RAW " + e.constructor.name
        : e.message.indexOf("nope___") === -1 ? "reached a different gate: " + e.message.slice(0, 60)
          : e.code;
    }
    check("unknown key at " + c[0] + " -> " + c[1], got === c[1]);
  }
}

async function run() {
  testAcceptsCanonical();
  testSyntaxRejects();
  testBoundsRejects();
  testBoundsWaived();
  testKnownKeys();
  await testConsumersFailClosed();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
