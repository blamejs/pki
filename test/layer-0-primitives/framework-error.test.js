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
  testPerDomain();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
