// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — pki.errors (PkiError taxonomy + defineClass factory).
 * Oracle: the documented error shape { name, code, isPkiError, permanent }.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

function testBase() {
  var e = new pki.errors.PkiError("boom", "test/boom");
  check("PkiError extends Error", e instanceof Error);
  check("PkiError name", e.name === "PkiError");
  check("PkiError code", e.code === "test/boom");
  check("PkiError isPkiError flag", e.isPkiError === true);
  check("PkiError permanent default", e.permanent === true);
  check("PkiError default code", new pki.errors.PkiError("x").code === "pki/invalid");
}

function testDefineClass() {
  var MyError = pki.errors.defineClass("MyError");
  var e = new MyError("my/bad", "explanation");
  check("generated extends PkiError", e instanceof pki.errors.PkiError);
  check("generated name is set", e.name === "MyError");
  check("generated flag isMyError", e.isMyError === true);
  check("generated code", e.code === "my/bad");
  check("constructor name defined", MyError.name === "MyError");
  check("factory builds instances", MyError.factory("my/x", "y") instanceof MyError);

  var Caused = pki.errors.defineClass("Caused", { withCause: true });
  var inner = new Error("inner");
  check("withCause attaches cause", new Caused("c/x", "y", inner).cause === inner);

  var threw = false;
  try { pki.errors.defineClass(""); } catch (_e) { threw = true; }
  check("defineClass rejects empty name", threw);
}

function testCodeShapeGuard() {
  // The base class takes (message, code); every defineClass subclass takes
  // (code, message). A call in the wrong convention lands prose in `code` —
  // caught at construction because a code must be a domain/reason string.
  var swappedBase = null;
  try { new pki.errors.PkiError("my/code", "an explanation of the fault"); }
  catch (e) { swappedBase = e; }
  check("PkiError with swapped (code, message) args throws at construction", swappedBase instanceof TypeError);
  var swappedSub = null;
  try { new pki.errors.Asn1Error("the DER length is non-minimal", "asn1/non-minimal-length"); }
  catch (e) { swappedSub = e; }
  check("subclass with swapped (message, code) args throws at construction", swappedSub instanceof TypeError);
  // A third argument to a non-withCause class would previously be discarded
  // silently — a cause the caller meant to thread must not vanish. ConstantsError
  // is a config-time authoring error with no cause to thread.
  var extraArg = null;
  try { new pki.errors.ConstantsError("constants/bad-scale", "msg", new Error("cause")); }
  catch (e) { extraArg = e; }
  check("non-withCause class rejects a third argument", extraArg instanceof TypeError);
  // Controls: both documented conventions still construct.
  check("control: PkiError (message, code) constructs", new pki.errors.PkiError("boom", "test/boom").code === "test/boom");
  check("control: subclass (code, message) constructs", new pki.errors.Asn1Error("asn1/truncated", "boom").code === "asn1/truncated");
  check("control: omitted code still defaults to pki/invalid", new pki.errors.PkiError("x").code === "pki/invalid");
  check("control: withCause class still threads a third argument", new pki.errors.CtError("ct/bad-der", "m", swappedBase).cause === swappedBase);
}

function testPerDomain() {
  ["ConstantsError", "Asn1Error", "OidError", "PemError", "CertificateError"].forEach(function (n) {
    check(n + " exported", typeof pki.errors[n] === "function");
    var inst = new pki.errors[n]("dom/x", "msg");
    check(n + " instanceof PkiError", inst instanceof pki.errors.PkiError);
    check(n + " sets its flag", inst["is" + n] === true);
  });
}

function run() {
  testBase();
  testDefineClass();
  testCodeShapeGuard();
  testPerDomain();
  testTransientCodes();
}

// `permanent` is documented as "the same input will never parse on retry", which is true of a
// verdict on bytes in hand and false of a network timeout. Every error was stamped permanent
// unconditionally, so a caller could not tell a deterministic refusal from one worth retrying
// and each client hand-rolled its own retry policy instead of reading the error.
function testTransientCodes() {
  var TransportError = pki.errors.TransportError;
  // CONTROL: a verdict on bytes stays permanent, which is the overwhelming majority.
  check("a parse verdict is permanent", new pki.errors.Asn1Error("asn1/indefinite-length", "x").permanent === true);
  check("a transport verdict that IS deterministic stays permanent",
    new TransportError("transport/insecure-url", "x").permanent === true);
  check("a policy refusal stays permanent",
    new TransportError("transport/blocked-address", "x").permanent === true);

  check("a timeout is not permanent", new TransportError("transport/timeout", "x").permanent === false);
  // The reason is read without its domain, because the HTTP transport re-prefixes the same
  // failure for each protocol client. A table of exact codes would have left the great
  // majority of real network errors marked permanent.
  check("a timeout under a protocol client's own prefix is not permanent either",
    new pki.errors.AcmeError("acme/timeout", "x").permanent === false &&
    new pki.errors.EstError("est/timeout", "x").permanent === false);
  // A proxy that answers CONNECT with 403 has refused deterministically, so the shared
  // connect-failure code stays permanent rather than inviting a retry of a refusal.
  check("a failed proxy connect stays permanent",
    new TransportError("transport/proxy-connect-failed", "x").permanent === true);
  // The flag stays on the documented shape either way.
  check("permanent is always a boolean",
    typeof new TransportError("transport/timeout", "x").permanent === "boolean");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
