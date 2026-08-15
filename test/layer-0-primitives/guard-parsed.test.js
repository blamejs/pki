// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// guard-parsed's own contract. The doors that compose it are covered by their own
// behavioural vectors (crl-sign, path-build, path-validate, ocsp, cmp); what is
// pinned here is what the guard itself promises, so a change to the shape rules
// fails against the rule rather than only against whichever consumer noticed.
var guard = require("../../lib/guard-parsed");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError");
function E(code, message) { return new TestError(code, message); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e && e.code; } }

var Z = Buffer.alloc(0);
var CERT = {
  tbsBytes: Z, serialNumberHex: "01", signatureAlgorithm: { oid: "1.2" }, signatureValue: { bytes: Z },
  validity: { notBefore: new Date(0), notAfter: new Date(1) },
  issuer: { rdns: [] }, subject: { rdns: [], bytes: Z },
  subjectPublicKeyInfo: { bytes: Z, algorithm: { oid: "1.2" }, publicKey: { bytes: Z, unusedBits: 0 } },
  extensions: [],
};
var CRL = {
  tbsBytes: Z, signatureAlgorithm: { oid: "1.2" }, signatureValue: { bytes: Z },
  issuer: { rdns: [] }, thisUpdate: new Date(0), nextUpdate: new Date(1),
  crlExtensions: [], revokedCertificates: [],
};
function cert(over) { return Object.assign({}, CERT, over); }
function crl(over) { return Object.assign({}, CRL, over); }

function run() {
  // ---- the two shapes accept what the parsers produce, in their minimal form ----
  check("the minimal complete certificate shape is a certificate", guard.isCert(CERT) === true);
  check("the minimal complete CRL shape is a CRL", guard.isCrl(CRL) === true);

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
    guard.isCrl(crl({ revokedCertificates: [{ serialNumberHex: "01", revocationDate: new Date(0) }] })) === false);
  check("...while an entry with an empty one is",
    guard.isCrl(crl({ revokedCertificates: [{ serialNumberHex: "01", revocationDate: new Date(0), crlEntryExtensions: [] }] })) === true);

  // ---- an extension entry is dispatched on .oid -------------------------------
  // An entry with a readable .name but no .oid reads as present to a human and is
  // invisible to every OID-keyed lookup in the toolkit.
  check("a certificate extension entry with a name but no oid is refused",
    guard.isCert(cert({ extensions: [{ name: "keyUsage", value: Z }] })) === false);
  check("a certificate extension entry with no Buffer value is refused",
    guard.isCert(cert({ extensions: [{ oid: "2.5.29.15" }] })) === false);
  // A CRL's known extension values are DECODED by its parser (cRLNumber is a BigInt,
  // reasonCode a Number), so only presence can be asserted there -- but the dispatch
  // key is the same and it is the part that decides anything.
  check("a CRL extension entry carrying a decoded value is accepted",
    guard.isCrl(crl({ crlExtensions: [{ oid: "2.5.29.20", name: "cRLNumber", value: 5n }] })) === true);
  check("a CRL extension entry with no oid is refused",
    guard.isCrl(crl({ crlExtensions: [{ name: "cRLNumber", value: 5n }] })) === false);
  check("a CRL extension entry with no value at all is refused",
    guard.isCrl(crl({ crlExtensions: [{ oid: "2.5.29.20" }] })) === false);

  // ---- accept(): the three input classes --------------------------------------
  var parseCalls = 0;
  function parse(b) { parseCalls++; return Object.assign({ parsedFrom: b }, CERT); }
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
