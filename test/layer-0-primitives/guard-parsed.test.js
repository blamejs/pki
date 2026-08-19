// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// guard-parsed's own contract. The doors that compose it are covered by their own
// behavioral vectors (crl-sign, path-build, path-validate, ocsp, cmp); what is
// pinned here is what the guard itself promises, so a change to the shape rules
// fails against the rule rather than only against whichever consumer noticed.
var guard = require("../../lib/guard-parsed");
var vm = require("vm");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var signing = require("../helpers/signing");
var vectors = require("../helpers/vectors");
var pki = helpers.pki;
var check = helpers.check;

var TestError = errors.defineClass("TestError");
function E(code, message) { return new TestError(code, message); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e && e.code; } }

var Z = Buffer.alloc(0);
var ALG = { oid: "1.2", name: null, parameters: null };
var NAME = { rdns: [], bytes: Z, dn: "" };
var CERT = {
  tbsBytes: Z, version: 3, serialNumber: 1n, serialNumberHex: "01",
  signatureAlgorithm: ALG, tbsSignatureAlgorithm: ALG, signatureValue: { bytes: Z, unusedBits: 0 },
  validity: { notBefore: new Date(0), notAfter: new Date(1) },
  issuer: NAME, subject: NAME,
  subjectPublicKeyInfo: { bytes: Z, algorithm: ALG, publicKey: { bytes: Z, unusedBits: 0 } },
  extensions: [],
};
var CRL = {
  tbsBytes: Z, version: 2, signatureAlgorithm: ALG, signatureValue: { bytes: Z, unusedBits: 0 },
  issuer: NAME, thisUpdate: new Date(0), nextUpdate: new Date(1),
  crlExtensions: [], revokedCertificates: [],
};
var ENTRY = { serialNumber: 1n, serialNumberHex: "01", revocationDate: new Date(0), crlEntryExtensions: [] };
function cert(over) { return Object.assign({}, CERT, over); }
function crl(over) { return Object.assign({}, CRL, over); }
function entry(over) { return Object.assign({}, ENTRY, over); }
function keysOf(o) { return Object.keys(o).sort().join(","); }

async function run() {
  // ---- the shapes are the PARSERS' output, not a consumer's dereference set ----
  // The fixtures above are hand-written, and a hand-written shape is exactly what
  // drifts: this guard first shipped derived from the path validator's reads, and
  // three fields the other doors depend on were absent from it. So the fixtures are
  // pinned to the real parsers here. A field added to either parser fails this pair
  // until the shape and the fixture carry it, which is what stops the shape from
  // going stale in the direction that matters -- silently accepting less.
  var realCert = pki.schema.x509.parse(vectors.CERT_EC_PEM);
  check("real parsed certificate satisfies the shape", guard.isCert(realCert) === true);
  check("the certificate fixture carries exactly the parser's fields",
    keysOf(realCert) === keysOf(CERT));
  check("...and so do its issuer and subject", keysOf(realCert.issuer) === keysOf(NAME) &&
    keysOf(realCert.subject) === keysOf(NAME));
  check("...and its signatureAlgorithm", keysOf(realCert.signatureAlgorithm) === keysOf(ALG));

  // The contract stated directly, over the parser's own output: EVERY field it
  // assigns is one the shape requires. Derived rather than listed, so a field added
  // to a parser fails here until the shape covers it -- which is the drift the first
  // version of this guard shipped with, and the reason it is checked this way.
  function eachFieldRequired(label, shape, real, describe) {
    Object.keys(real).forEach(function (k) {
      var partial = Object.assign({}, real);
      delete partial[k];
      check(label + " requires " + (describe ? describe + "." : "") + k, shape(partial) === false);
    });
  }
  eachFieldRequired("the certificate shape", guard.isCert, realCert);
  Object.keys(realCert.extensions[0]).forEach(function (k) {
    var x = Object.assign({}, realCert.extensions[0]);
    delete x[k];
    check("the certificate shape requires an extension's " + k,
      guard.isCert(Object.assign({}, realCert, { extensions: [x] })) === false);
  });
  // The DN walk goes to the attributes, so the shape does too: dnEqual compares each
  // attribute's type and canonicalizes its value, and the WebAuthn subject-CN lookup
  // reads its name -- none of which an "rdns is an array" test says anything about.
  var realAtv = realCert.subject.rdns[0][0];
  Object.keys(realAtv).forEach(function (k) {
    var a = Object.assign({}, realAtv);
    delete a[k];
    check("the certificate shape requires a DN attribute's " + k,
      guard.isCert(Object.assign({}, realCert, { subject: Object.assign({}, realCert.subject, { rdns: [[a]] }) })) === false);
  });
  check("an RDN that is not an array of attributes is refused",
    guard.isCert(Object.assign({}, realCert, { subject: Object.assign({}, realCert.subject, { rdns: [realAtv] }) })) === false);
  check("an empty RDN is refused (RelativeDistinguishedName ::= SET SIZE (1..MAX))",
    guard.isCert(Object.assign({}, realCert, { subject: Object.assign({}, realCert.subject, { rdns: [[]] }) })) === false);
  check("a multi-valued RDN is accepted", guard.isCert(Object.assign({}, realCert,
    { subject: Object.assign({}, realCert.subject, { rdns: [[realAtv, realAtv]] }) })) === true);
  check("an empty subject DN is accepted (a certificate may carry one)",
    guard.isCert(Object.assign({}, realCert, { subject: Object.assign({}, realCert.subject, { rdns: [] }) })) === true);
  check("an attribute value that is not a string is refused",
    guard.isCert(Object.assign({}, realCert, { subject: Object.assign({}, realCert.subject,
      { rdns: [[Object.assign({}, realAtv, { value: Buffer.from("US") })]] }) })) === false);
  check("an unregistered attribute type (name: null) is accepted",
    guard.isCert(Object.assign({}, realCert, { subject: Object.assign({}, realCert.subject,
      { rdns: [[{ type: "1.2.3.4.5.6.7", name: null, value: "x" }]] }) })) === true);

  ["issuer", "subject", "validity", "subjectPublicKeyInfo", "signatureAlgorithm", "signatureValue"].forEach(function (sub) {
    Object.keys(realCert[sub]).forEach(function (k) {
      var inner = Object.assign({}, realCert[sub]);
      delete inner[k];
      var partial = Object.assign({}, realCert);
      partial[sub] = inner;
      check("the certificate shape requires " + sub + "." + k, guard.isCert(partial) === false);
    });
  });

  var s = signing.makeSigner("ec-p256");
  var realCrl = pki.schema.crl.parse(await pki.crl.sign({
    thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"),
    crlNumber: 1n, revoked: [{ serialNumber: 5n, revocationDate: new Date("2026-01-15T00:00:00Z") }],
  }, { name: "Guard Shape CRL Issuer", publicKey: s.spki, key: s.key }));
  check("real parsed CRL satisfies the shape", guard.isCrl(realCrl) === true);
  check("the CRL fixture carries exactly the parser's fields", keysOf(realCrl) === keysOf(CRL));
  check("the revoked-entry fixture carries exactly the parser's fields",
    keysOf(realCrl.revokedCertificates[0]) === keysOf(ENTRY));
  eachFieldRequired("the CRL shape", guard.isCrl, realCrl);
  Object.keys(realCrl.revokedCertificates[0]).forEach(function (k) {
    var e = Object.assign({}, realCrl.revokedCertificates[0]);
    delete e[k];
    var partial = Object.assign({}, realCrl, { revokedCertificates: [e] });
    check("the CRL shape requires a revoked entry's " + k, guard.isCrl(partial) === false);
  });
  Object.keys(realCrl.crlExtensions[0]).forEach(function (k) {
    var x = Object.assign({}, realCrl.crlExtensions[0]);
    delete x[k];
    var partial = Object.assign({}, realCrl, { crlExtensions: [x] });
    check("the CRL shape requires a crlExtension's " + k, guard.isCrl(partial) === false);
  });

  // ---- the two shapes accept what the parsers produce, in their minimal form ----
  check("the minimal complete certificate shape is a certificate", guard.isCert(CERT) === true);
  check("the minimal complete CRL shape is a CRL", guard.isCrl(CRL) === true);

  // ---- the fields the first shape omitted --------------------------------------
  // Each of these is read by a door other than the one the shape was derived from:
  // pki.ocsp.buildRequest encodes `serialNumber` into the CertID, the OCSP
  // responder-identity comparison reads `issuer.bytes`, and the path validator gates
  // on an extension's `critical`. Absent, the first two reach the consumer as a
  // foreign fault and the third reads as non-critical -- so an unknown critical
  // extension passes unhandled, which is the fail-open direction.
  check("a certificate without serialNumber is not a certificate",
    guard.isCert(cert({ serialNumber: undefined })) === false);
  check("a certificate whose serialNumber is a Number is not one either",
    guard.isCert(cert({ serialNumber: 1 })) === false);
  check("a certificate without version is not a certificate",
    guard.isCert(cert({ version: undefined })) === false);
  check("a certificate without tbsSignatureAlgorithm is not a certificate",
    guard.isCert(cert({ tbsSignatureAlgorithm: undefined })) === false);
  check("a certificate whose issuer has no bytes is not a certificate",
    guard.isCert(cert({ issuer: { rdns: [], dn: "" } })) === false);
  check("a certificate whose issuer has no dn is not a certificate",
    guard.isCert(cert({ issuer: { rdns: [], bytes: Z } })) === false);
  check("an extension entry with no critical flag is refused",
    guard.isCert(cert({ extensions: [{ oid: "2.5.29.15", name: "keyUsage", value: Z }] })) === false);
  check("...while one carrying critical: false is accepted",
    guard.isCert(cert({ extensions: [{ oid: "2.5.29.15", name: "keyUsage", critical: false, value: Z }] })) === true);
  check("a CRL without version is not a CRL", guard.isCrl(crl({ version: undefined })) === false);
  check("a revoked entry without serialNumber is not a CRL",
    guard.isCrl(crl({ revokedCertificates: [entry({ serialNumber: undefined })] })) === false);
  check("a CRL extension entry with no critical flag is refused",
    guard.isCrl(crl({ crlExtensions: [{ oid: "2.5.29.20", name: "cRLNumber", value: 5n }] })) === false);

  // An algorithm identifier's `name` is the registry lookup and is null for an OID
  // the registry does not carry, so both forms are the parser's own output.
  check("an unregistered algorithm OID (name: null) is accepted",
    guard.isCert(cert({ signatureAlgorithm: { oid: "1.2.3.4", name: null, parameters: null } })) === true);
  check("an algorithm identifier with no name property at all is refused",
    guard.isCert(cert({ signatureAlgorithm: { oid: "1.2.3.4", parameters: null } })) === false);
  check("an algorithm identifier with no parameters property is refused",
    guard.isCert(cert({ signatureAlgorithm: { oid: "1.2.3.4", name: null } })) === false);

  // ---- a missing LIST is not an empty one -------------------------------------
  // The distinction the guard exists for: every scope and extension check in the
  // toolkit reads a list as `(list || [])`, so an absent property and an empty array
  // are the same value to the check and opposite claims about the structure.
  check("a certificate without an extensions property is not a certificate",
    guard.isCert(cert({ extensions: undefined })) === false);
  check("...while an EMPTY extensions array is one", guard.isCert(cert({ extensions: [] })) === true);
  check("a CRL without a crlExtensions property is not a CRL",
    guard.isCrl(crl({ crlExtensions: undefined })) === false);
  check("...while an EMPTY crlExtensions array is one", guard.isCrl(crl({ crlExtensions: [] })) === true);
  check("a revoked entry without crlEntryExtensions is not a CRL",
    guard.isCrl(crl({ revokedCertificates: [entry({ crlEntryExtensions: undefined })] })) === false);
  check("...while an entry with an empty one is",
    guard.isCrl(crl({ revokedCertificates: [entry({})] })) === true);

  // ---- an extension entry is dispatched on .oid -------------------------------
  // An entry with a readable .name but no .oid reads as present to a human and is
  // invisible to every OID-keyed lookup in the toolkit.
  check("a certificate extension entry with a name but no oid is refused",
    guard.isCert(cert({ extensions: [{ name: "keyUsage", critical: false, value: Z }] })) === false);
  check("a certificate extension entry with no Buffer value is refused",
    guard.isCert(cert({ extensions: [{ oid: "2.5.29.15", name: "keyUsage", critical: false }] })) === false);
  // A CRL's known extension values are DECODED by its parser (cRLNumber is a BigInt,
  // reasonCode a Number), so only presence can be asserted there -- but the dispatch
  // key is the same and it is the part that decides anything.
  check("a CRL extension entry carrying a decoded value is accepted",
    guard.isCrl(crl({ crlExtensions: [{ oid: "2.5.29.20", name: "cRLNumber", critical: false, value: 5n }] })) === true);
  check("a CRL extension entry with no oid is refused",
    guard.isCrl(crl({ crlExtensions: [{ name: "cRLNumber", critical: false, value: 5n }] })) === false);
  check("a CRL extension entry with no value at all is refused",
    guard.isCrl(crl({ crlExtensions: [{ oid: "2.5.29.20", name: "cRLNumber", critical: false }] })) === false);

  // ---- accept(): the three input classes --------------------------------------
  var parseCalls = 0;
  function parse(b) { parseCalls++; return Object.assign({ parsedFrom: b }, CERT); }
  // Every container the verbs document as "bytes" reaches the parser. A narrower test (Buffer or
  // Uint8Array only) does not merely miss one form: the others fall through to the parsed-object
  // branch and are refused as REBUILT structures, so a caller who happened to hold a DataView reads
  // "your certificate was rebuilt" about bytes they never touched.
  var derBytes = pki.schema.x509.pemDecode(vectors.CERT_EC_PEM);
  var derAb = derBytes.buffer.slice(derBytes.byteOffset, derBytes.byteOffset + derBytes.length);
  // A realm is one of the ways a container varies, so the class the door claims to accept has to
  // be tested across it. A buffer built in a `vm` context holds bytes and inherits from that
  // context, so a test keyed on this realm's prototypes calls it no byte container at all and
  // sends it down the rebuilt-object branch, while the module that finally reads the bytes takes
  // it. The two doors then answer differently about one argument.
  var foreignAb = vm.runInNewContext("new ArrayBuffer(" + derBytes.length + ")");
  new Uint8Array(foreignAb).set(derBytes);
  var foreignU8 = vm.runInNewContext("new Uint8Array(" + derBytes.length + ")");
  foreignU8.set(derBytes);
  var containers = {
    Buffer: derBytes,
    Uint8Array: new Uint8Array(derAb),
    "a non-Uint8Array view": new Int8Array(derAb),
    DataView: new DataView(derAb),
    ArrayBuffer: derAb,
    "an ArrayBuffer from another realm": foreignAb,
    "a Uint8Array from another realm": foreignU8,
    "a PEM string": vectors.CERT_EC_PEM,
  };
  Object.keys(containers).forEach(function (name) {
    var got;
    try { got = guard.acceptDerived(containers[name], "certificate", pki.schema.x509.parse, E, "x/bad", "root"); }
    catch (_e) {
      got = null;   // refused: the assertion below names which container was not recognized
    }
    check("a certificate given as " + name + " is parsed, not read as a rebuilt object",
      !!got && got.subject.dn === realCert.subject.dn);
  });

  check("a Buffer is parsed", guard.accept(Buffer.from([0x30]), "certificate", parse, E, "x/bad", "arg").parsedFrom !== undefined);
  check("a Uint8Array is parsed", guard.accept(new Uint8Array([0x30]), "certificate", parse, E, "x/bad", "arg").parsedFrom !== undefined);
  check("a PEM string is parsed", guard.accept("-----BEGIN", "certificate", parse, E, "x/bad", "arg").parsedFrom !== undefined);
  check("three byte forms, three parse calls", parseCalls === 3);
  check("a complete parsed object is passed through without parsing",
    guard.accept(CERT, "certificate", parse, E, "x/bad", "arg") === CERT && parseCalls === 3);

  // A claim is made by carrying tbsBytes AT ALL, including a null one: an object
  // saying "I am parsed" and failing must be told that, not handed to a byte parser
  // that would report something unrelated about its type.
  check("a partial claimed-parsed object is a typed fault",
    codeOf(function () { guard.accept(cert({ subject: undefined }), "certificate", parse, E, "x/bad", "arg"); }) === "x/bad");
  check("tbsBytes: null is a CLAIM that fails, not a non-claim",
    codeOf(function () { guard.accept({ tbsBytes: null }, "certificate", parse, E, "x/bad", "arg"); }) === "x/bad");
  check("an object claiming nothing is a typed fault naming what is accepted",
    codeOf(function () { guard.accept({ nope: 1 }, "certificate", parse, E, "x/bad", "arg"); }) === "x/bad");
  check("null is a typed fault", codeOf(function () { guard.accept(null, "certificate", parse, E, "x/bad", "arg"); }) === "x/bad");
  check("a number is a typed fault", codeOf(function () { guard.accept(5, "certificate", parse, E, "x/bad", "arg"); }) === "x/bad");

  // ---- the walk cannot be turned into a raw fault -----------------------------
  // A caller-supplied object can define an accessor that throws on read. The verb's
  // contract is that every failure is its own typed error, so a property that cannot
  // be read is simply not one the parser produced.
  var trap = cert({});
  Object.defineProperty(trap, "extensions", { get: function () { throw new RangeError("unreadable"); } });
  check("an accessor that throws is refused as a typed fault, not propagated",
    codeOf(function () { guard.accept(trap, "certificate", parse, E, "x/bad", "arg"); }) === "x/bad");
  // Including the CLAIM property itself, which is read before the walk begins: a
  // throwing tbsBytes would otherwise escape from outside the guarded region.
  var claimTrapCert = {};
  Object.defineProperty(claimTrapCert, "tbsBytes", { enumerable: true, get: function () { throw new RangeError("unreadable"); } });
  check("a throwing tbsBytes accessor is a typed fault, not a raw one",
    codeOf(function () { guard.accept(claimTrapCert, "certificate", parse, E, "x/bad", "arg"); }) === "x/bad");
  check("...and the same object through the CRL door",
    codeOf(function () { guard.accept(claimTrapCert, "crl", parse, E, "x/bad", "arg"); }) === "x/bad");
  check("...and the predicate answers false rather than throwing", guard.isCert(trap) === false);
  var crlTrap = crl({});
  Object.defineProperty(crlTrap, "revokedCertificates", { get: function () { throw new RangeError("unreadable"); } });
  check("the CRL predicate answers false rather than throwing too", guard.isCrl(crlTrap) === false);

  // ---- fromTrustedSource ------------------------------------------------------
  // An integrity verb reads two or three fields that must have come from one place, so it asks the
  // parser for the bytes it read rather than trusting the object. An object claiming to be parser
  // output without that record has been rebuilt, and is refused.
  var recording = guard.recordingParser("thing", function (b) { return { parsedFrom: b, tag: "real" }; },
    TestError, "x/bad", "a thing");
  var real = recording(Buffer.from([1, 2, 3]));
  function door(v) {
    return guard.fromTrustedSource(v, "thing", ["responseStatus"], function (b) { return { reparsed: b }; },
      E, "x/bad", "rebuilt");
  }
  check("bytes go to the parser", Buffer.isBuffer(door(Buffer.from([9])).reparsed));
  check("the parser's own result is re-derived from what it recorded",
    Buffer.compare(door(real).reparsed, Buffer.from([1, 2, 3])) === 0);
  check("a rebuilt copy claiming to be one is refused",
    codeOf(function () { door(Object.assign({}, real, { responseStatus: 1 })); }) === "x/bad");
  // The claim field can itself be an accessor that throws. A guard answers; it does not relay --
  // an object whose claim cannot even be read is certainly not the parser's own result.
  var claimTrap = {};
  Object.defineProperty(claimTrap, "responseStatus", { enumerable: true, get: function () { throw new RangeError("unreadable"); } });
  check("a throwing claim accessor is a typed fault, not a raw one",
    codeOf(function () { door(claimTrap); }) === "x/bad");
  // The record is keyed by IDENTITY, so a Proxy answering for any key cannot claim it.
  var proxied = new Proxy(real, { get: function (t, k) { return Reflect.get(t, k); } });
  check("a Proxy over a real result does not inherit its record",
    codeOf(function () { door(Object.assign(proxied, { responseStatus: 1 })); }) === "x/bad");

  // ---- the kind is a programming error, not an input fault --------------------
  // A misspelled kind is a bug in the composing module and must not read as a
  // malformed input from the operator.
  check("an unknown kind is a TypeError, not the caller's input code", (function () {
    try { guard.accept(CERT, "nope", parse, E, "x/bad", "arg"); return "NO-THROW"; }
    catch (e) { return e instanceof TypeError ? "TypeError" : (e && e.code); }
  })() === "TypeError");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
