// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- lib/mime.js, the MIME entity framer + canonicalizer under pki.smime. The load-bearing
 * contract is canonicalization: line endings normalized to CRLF over the exact bytes (never a header
 * re-serialization), so the signer and verifier compute one digest. The multipart splitter returns
 * each part's exact bytes -- the CRLF (or bare LF) that precedes a boundary is the delimiter's, not
 * the part's -- and fails closed on a missing / unterminated boundary.
 */

var helpers = require("../helpers");
var check = helpers.check;
var mime = require("../../lib/mime.js");

function E(code, message) { this.code = code; this.message = message; }
E.prototype = Object.create(Error.prototype);
function fault(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.constructor && e.constructor.name)); } }

function run() {
  // ---- parse ----
  var ent = mime.parse(Buffer.from("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nBODY"), E, "m/bad");
  check("1. parses the media type + params", ent.contentType.type === "text/plain" && ent.contentType.params.charset === "utf-8");
  check("2. parses the transfer encoding", ent.cte === "base64");
  check("3. surfaces the exact body bytes", ent.body.toString() === "BODY");
  check("4. header() is case-insensitive", ent.header("CONTENT-TYPE") != null && ent.header("nope") === null);
  // folded header (a continuation line joins the previous)
  var folded = mime.parse(Buffer.from("Content-Type: multipart/signed;\r\n boundary=\"XX\"\r\n\r\nb"), E, "m/bad");
  check("5. unfolds a continued header", folded.contentType.type === "multipart/signed" && folded.contentType.params.boundary === "XX");
  // no blank-line separator: the whole input is headers, empty body (mime.js:36 _splitPoint -> null)
  var noSep = mime.parse(Buffer.from("Content-Type: text/plain"), E, "m/bad");
  check("6. a header block with no blank-line separator parses with an empty body", noSep.body.length === 0 && noSep.contentType.type === "text/plain");
  check("7. absent Content-Type defaults to text/plain", mime.parse(Buffer.from("X-Other: y\r\n\r\nb"), E, "m/bad").contentType.type === "text/plain");
  check("8. a header line with no colon -> typed fault", fault(function () { mime.parse(Buffer.from("no colon here\r\n\r\nb"), E, "m/bad"); }) === "m/bad");
  check("9. a non-Buffer input -> typed fault", fault(function () { mime.parse(42, E, "m/bad"); }) === "m/bad");
  // a bare LF-LF header/body separator (Unix line endings)
  check("9a. a LF-LF header/body separator parses", mime.parse(Buffer.from("Content-Type: text/plain\n\nunix body"), E, "m/bad").body.toString() === "unix body");
  // a Content-Type parameter with no '=' is skipped
  check("9b. a parameter with no '=' is ignored", Object.keys(mime.parse(Buffer.from("Content-Type: text/plain; junk\r\n\r\nb"), E, "m/bad").contentType.params).length === 0);

  // ---- canonicalizeText / canonicalize: every line ending -> CRLF ----
  check("10. bare LF -> CRLF", mime.canonicalizeText(Buffer.from("a\nb\nc")).toString() === "a\r\nb\r\nc");
  check("11. bare CR -> CRLF", mime.canonicalizeText(Buffer.from("a\rb")).toString() === "a\r\nb");
  check("12. existing CRLF is preserved", mime.canonicalizeText(Buffer.from("a\r\nb")).toString() === "a\r\nb");
  check("13. canonicalize is a pure line-ending normalizer (no header rebuild)", mime.canonicalize(Buffer.from("Content-Type: text/plain\n\nx\ny"), E, "m/bad").toString() === "Content-Type: text/plain\r\n\r\nx\r\ny");

  // ---- splitMultipart: exact part bytes, CRLF and bare-LF delimiters, preamble, close ----
  var mp = "preamble\r\n--BND\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--BND\r\nContent-Type: application/pkcs7-signature\r\n\r\nSECOND\r\n--BND--\r\n";
  var parts = mime.splitMultipart(Buffer.from(mp), "BND", E, "m/bad");
  check("14. splits into the two parts (skipping the preamble)", parts.length === 2);
  check("15. part 0 is exact (no trailing CRLF before the boundary)", parts[0].toString() === "Content-Type: text/plain\r\n\r\nfirst");
  check("16. part 1 is exact", parts[1].toString() === "Content-Type: application/pkcs7-signature\r\n\r\nSECOND");
  // a bare-LF delimiter (mime.js:145): the part ends at the bare LF preceding the boundary
  var lfMp = "--B\nfirst part\n--B\nsecond part\n--B--\n";
  var lfParts = mime.splitMultipart(Buffer.from(lfMp), "B", E, "m/bad");
  check("17. a bare-LF boundary delimiter splits correctly", lfParts.length === 2 && lfParts[0].toString() === "first part");
  check("18. a missing boundary delimiter -> typed fault", fault(function () { mime.splitMultipart(Buffer.from("no boundary here"), "B", E, "m/bad"); }) === "m/bad");
  check("19. a null boundary -> typed fault", fault(function () { mime.splitMultipart(Buffer.from("x"), null, E, "m/bad"); }) === "m/bad");
  check("20. an unterminated part (no closing boundary) -> typed fault", fault(function () { mime.splitMultipart(Buffer.from("--B\r\ncontent with no close\r\n"), "B", E, "m/bad"); }) === "m/bad");
  // an opening boundary line that is never terminated (mime.js:158)
  check("21. an unterminated boundary line -> typed fault", fault(function () { mime.splitMultipart(Buffer.from("--B"), "B", E, "m/bad"); }) === "m/bad");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(null, function (e) { console.error(e && e.stack || e); process.exit(1); });
}
