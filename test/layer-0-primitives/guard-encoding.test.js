// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- guard-encoding (@internal): strict canonical decode of untrusted
 * base64 / base64url / hex. Oracle: RFC 4648 sec. 3.5 / sec. 5 canonicality (the
 * unique encoding of a byte string) + the allocate-before-cap rule. The consumers
 * (pki.jose base64url, pki.schema PEM bodies, pki.webcrypto JWK key material) are
 * exercised end-to-end in their own suites; these pin the guard's contract.
 */

var encoding = require("../../lib/guard-encoding");
var errors = require("../../lib/framework-error");
var helpers = require("../helpers");
var check = helpers.check;

var TestError = errors.defineClass("TestError");
function E(code, message) { return new TestError(code, message); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }
function hexOf(buf) { return buf.toString("hex"); }

function testBase64url() {
  var canon = Buffer.from([1, 2, 3]).toString("base64url");   // "AQID"
  check("base64url: canonical decodes", hexOf(encoding.base64url(canon, null, E, "x/enc", "v")) === "010203");
  check("base64url: unpadded empty ok", encoding.base64url("", null, E, "x/enc", "v").length === 0);
  check("base64url: padding rejected", codeOf(function () { encoding.base64url("AQID=", null, E, "x/enc", "v"); }) === "x/enc");
  check("base64url: non-alphabet (+/) rejected", codeOf(function () { encoding.base64url("a+/b", null, E, "x/enc", "v"); }) === "x/enc");
  check("base64url: impossible length rejected", codeOf(function () { encoding.base64url("AQIDA", null, E, "x/enc", "v"); }) === "x/enc");
  check("base64url: non-canonical trailing bits rejected", codeOf(function () { encoding.base64url("QR", null, E, "x/enc", "v"); }) === "x/enc");
  check("base64url: non-string rejected", codeOf(function () { encoding.base64url(undefined, null, E, "x/enc", "v"); }) === "x/enc");
  check("base64url: over-cap rejected before copy", codeOf(function () { encoding.base64url("AAAAAAAA", 3, E, "x/enc", "v"); }) === "x/enc");
  check("base64url: within cap ok", encoding.base64url("AAAAAAAA", 6, E, "x/enc", "v").length === 6);
}

function testBase64() {
  var canon = Buffer.from([255, 0, 128]).toString("base64");   // padded
  check("base64: canonical (padded) decodes", hexOf(encoding.base64(canon, null, E, "x/enc", "v")) === "ff0080");
  check("base64: non-4-group rejected", codeOf(function () { encoding.base64("AQI", null, E, "x/enc", "v"); }) === "x/enc");
  check("base64: non-canonical padding rejected", codeOf(function () { encoding.base64("QQ=A", null, E, "x/enc", "v"); }) === "x/enc");
  check("base64: base64url alphabet (-_) rejected", codeOf(function () { encoding.base64("a-_b", null, E, "x/enc", "v"); }) === "x/enc");
}

function testHex() {
  check("hex: canonical (lower) decodes", hexOf(encoding.hex("0aff", null, E, "x/enc", "v")) === "0aff");
  check("hex: upper-case accepted (canonical bytes)", hexOf(encoding.hex("0AFF", null, E, "x/enc", "v")) === "0aff");
  check("hex: odd length rejected", codeOf(function () { encoding.hex("abc", null, E, "x/enc", "v"); }) === "x/enc");
  check("hex: non-hex rejected", codeOf(function () { encoding.hex("zz", null, E, "x/enc", "v"); }) === "x/enc");
  check("hex: over-cap rejected before copy", codeOf(function () { encoding.hex("00112233", 3, E, "x/enc", "v"); }) === "x/enc");
}

function testAuthoringBounds() {
  // maxBytes is an authoring input with a DOCUMENTED null/undefined = uncapped
  // mode; anything else non-integer (NaN, fractional, negative) silently
  // disables the cap-before-copy comparison -- reject with a config-time
  // TypeError instead.
  function typeErr(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e instanceof TypeError ? "TYPE" : (e.code || "OTHER"); } }
  check("null maxBytes stays uncapped (documented)", encoding.base64("QUJD", null, E, "x/enc", "v").length === 3);
  check("NaN maxBytes throws TypeError", typeErr(function () { encoding.base64("QUJD", NaN, E, "x/enc", "v"); }) === "TYPE");
  check("fractional maxBytes throws TypeError", typeErr(function () { encoding.base64url("AQID", 2.5, E, "x/enc", "v"); }) === "TYPE");
  check("negative maxBytes throws TypeError", typeErr(function () { encoding.hex("00ff", -1, E, "x/enc", "v"); }) === "TYPE");
}

function run() {
  testBase64url();
  testBase64();
  testHex();
  testAuthoringBounds();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
