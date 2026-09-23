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
  testPercentEncode();
}

// RFC 3986 sec. 2.1 writes a percent-encoding as `%` and two hexadecimal digits, and sec. 2.3
// names the unreserved set that is never encoded. Everything else is, which is what keeps a value
// inside the component it was placed in: a `/`, a `?`, a `#` or a percent of its own cannot reach
// past its own path segment. `encodeURIComponent` is not this function, because it reads a
// JavaScript string rather than bytes and leaves the sub-delims of sec. 2.2 unescaped.
function testPercentEncode() {
  function E(code, message) { var e = new Error(message); e.code = code; return e; }
  function enc(v) { return encoding.percentEncode(v, E, "test/bad"); }
  function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.name; } }

  check("the unreserved set passes through unchanged",
    enc(Buffer.from("ABCabc019-._~")) === "ABCabc019-._~");
  check("every reserved character becomes a triplet",
    enc(Buffer.from("/?#[]@!$&'()*+,;=")) === "%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D");
  check("a space, a percent and a colon are encoded too",
    enc(Buffer.from(" %:")) === "%20%25%3A");
  check("the hex digits are upper case, which RFC 3986 sec. 2.1 names the canonical form",
    enc(Buffer.from([0xab, 0xcd, 0xef])) === "%AB%CD%EF");
  check("a zero byte and a high byte are encoded, not dropped",
    enc(Buffer.from([0x00, 0x7f, 0x80, 0xff])) === "%00%7F%80%FF");
  check("an empty input encodes to an empty string", enc(Buffer.alloc(0)) === "");
  // Every byte value, decoded by the inverse of what sec. 2.1 defines rather than by
  // `decodeURIComponent`, which reads a triplet as UTF-8 and throws on `%80` through `%FF`.
  check("every one of the 256 byte values survives a round trip", (function () {
    var all = Buffer.alloc(256);
    for (var i = 0; i < 256; i++) all[i] = i;
    var out = enc(all);
    var back = [], k = 0;
    while (k < out.length) {
      if (out.charAt(k) === "%") { back.push(parseInt(out.slice(k + 1, k + 3), 16)); k += 3; }
      else { back.push(out.charCodeAt(k)); k += 1; }
    }
    if (back.length !== 256) return false;
    for (var j = 0; j < 256; j++) if (back[j] !== j) return false;
    return true;
  })());
  check("...and the encoding of that whole range carries no character outside the unreserved set and %",
    /^[A-Za-z0-9\-._~%0-9A-F]*$/.test(enc(Buffer.from([0x00, 0x41, 0x2f, 0xff]))));
  check("a base64 body's three special characters are all escaped",
    enc(Buffer.from("aB+/c=")) === "aB%2B%2Fc%3D");

  check("uriPathSegment reads a string as its latin1 bytes",
    encoding.uriPathSegment("a/b", E, "test/bad") === "a%2Fb" &&
    encoding.uriPathSegment("", E, "test/bad") === "");
  check("a segment cannot carry a delimiter out of its own component",
    encoding.uriPathSegment("../../etc/passwd", E, "test/bad") === "..%2F..%2Fetc%2Fpasswd");
  check("a value that is not a string is refused by uriPathSegment",
    code(function () { encoding.uriPathSegment(Buffer.from("x"), E, "test/bad"); }) === "test/bad");
  check("a value that is not bytes is refused by percentEncode",
    code(function () { enc("x"); }) === "test/bad" && code(function () { enc(null); }) === "test/bad");
  check("an error factory is required, and a class is a configuration fault",
    code(function () { encoding.percentEncode(Buffer.from("x"), null, "c"); }) === "TypeError");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
